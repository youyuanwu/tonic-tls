use super::{backend::TestBackend, certs::roots};
use crate::{
    helloworld::{self, HelloReply, HelloRequest},
    tests::create_listener_server,
};
use futures::Stream;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use std::{
    net::TcpStream,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tonic::{
    Request, Response, Status,
    transport::{
        Channel, Endpoint,
        server::{TcpConnectInfo, TcpIncoming},
    },
};
use tonic_tls_xds::CertificateProvider;

pub(in crate::xds_tests) struct TestIncoming {
    pub inner: TcpIncoming,
    pub first_connection: Option<oneshot::Sender<TcpStream>>,
}

impl Stream for TestIncoming {
    type Item = Result<tokio::net::TcpStream, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let next = std::task::ready!(Pin::new(&mut self.inner).poll_next(cx));
        Poll::Ready(next.map(|stream| {
            let stream = stream?;
            let Some(sender) = self.first_connection.take() else {
                return Ok(stream);
            };
            // Both handles refer to the same socket, allowing a test-triggered shutdown.
            let stream = stream.into_std()?;
            sender
                .send(stream.try_clone()?)
                .expect("test must receive the first accepted connection");
            tokio::net::TcpStream::from_std(stream)
        }))
    }
}

impl tonic_tls::Incoming for TestIncoming {
    type Io = tokio::net::TcpStream;
    type Error = std::io::Error;
}

struct PeerGreeter {
    clients: Vec<CertificateDer<'static>>,
}

#[tonic::async_trait]
impl helloworld::greeter_server::Greeter for PeerGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        let certs = request
            .extensions()
            .get::<tonic_tls::rustls::SslConnectInfo<TcpConnectInfo>>()
            .and_then(|info| info.peer_certs())
            .ok_or_else(|| Status::unauthenticated("missing client certificate"))?;
        // Report the expected-cert index of the actual TLS peer's leaf certificate.
        // With [first, second], "0" means original and "1" means rotated.
        let index = self
            .clients
            .iter()
            .position(|cert| Some(cert) == certs.first())
            .ok_or_else(|| Status::unauthenticated("unexpected client certificate"))?;
        Ok(Response::new(HelloReply {
            message: index.to_string(),
        }))
    }
}

pub(in crate::xds_tests) async fn start_server(
    cert: &rcgen::Certificate,
    key: &rcgen::KeyPair,
    clients: &[&rcgen::Certificate],
    first_connection: Option<oneshot::Sender<TcpStream>>,
) -> (Endpoint, CancellationToken, tokio::task::JoinHandle<()>) {
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots(clients)), crypto.clone())
            .build()
            .unwrap();
    let mut config = ServerConfig::builder_with_provider(crypto)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap();
    config.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];
    let greeter = PeerGreeter {
        clients: clients.iter().map(|cert| cert.der().clone()).collect(),
    };
    let (listener, addr) = create_listener_server().await;
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let task = tokio::spawn(async move {
        let incoming = tonic_tls::rustls::TlsIncoming::new(
            TestIncoming {
                inner: TcpIncoming::from(listener),
                first_connection,
            },
            Arc::new(config),
        );
        tonic::transport::Server::builder()
            .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
            .serve_with_incoming_shutdown(incoming, signal.cancelled_owned())
            .await
            .unwrap();
    });
    let endpoint = Endpoint::from_shared(format!("https://{addr}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5));
    (endpoint, shutdown, task)
}

pub(in crate::xds_tests) fn connector<B: TestBackend>(
    endpoint: &Endpoint,
    factory: B::Factory,
    provider: Arc<dyn CertificateProvider>,
) -> tonic_tls_xds::ReloadableTlsConnector<tokio::net::TcpStream, B::Connector> {
    tonic_tls_xds::ReloadableTlsConnector::new(
        tonic_tls::TcpTransport::from_endpoint(endpoint),
        provider,
        factory,
    )
    .unwrap()
}

pub(in crate::xds_tests) async fn peer_identity(
    client: &mut helloworld::greeter_client::GreeterClient<Channel>,
) -> Result<String, Status> {
    Ok(client
        .say_hello(HelloRequest {
            name: "rotation".into(),
        })
        .await?
        .into_inner()
        .message)
}

pub(in crate::xds_tests) async fn await_peer_identity(
    client: &mut helloworld::greeter_client::GreeterClient<Channel>,
    expected: &str,
) {
    let mut attempts = 0;
    let mut last_error = None;
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            attempts += 1;
            match peer_identity(client).await {
                Ok(peer) => {
                    assert_eq!(peer, expected);
                    break;
                }
                Err(status) => {
                    // The first RPC can race with tonic noticing the closed connection.
                    assert!(
                        status.code() == tonic::Code::Unavailable
                            || (matches!(
                                status.code(),
                                tonic::Code::Unknown | tonic::Code::Cancelled
                            ) && std::error::Error::source(&status).is_some()),
                        "unexpected reconnect error: {status:?}",
                    );
                    last_error = Some(status);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "same channel did not reconnect with identity {expected} after {attempts} attempts; last error: {last_error:?}",
    );
}
