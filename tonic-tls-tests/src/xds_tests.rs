use std::sync::Arc;

use crate::{
    helloworld::{self, HelloReply, HelloRequest},
    tests::{create_listener_server, make_test_cert},
};
use arc_swap::ArcSwap;
use futures::Stream;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use std::{
    net::{Shutdown, TcpStream},
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tonic::transport::{Endpoint, server::TcpConnectInfo};
use tonic::{
    Request, Response, Status,
    transport::{Channel, server::TcpIncoming},
};
use tonic_tls_xds::{CertificateData, CertificateProvider, Identity};

struct TestProvider {
    data: ArcSwap<CertificateData>,
    fail: AtomicBool,
}

impl TestProvider {
    fn new(data: CertificateData) -> Arc<Self> {
        Arc::new(Self {
            data: ArcSwap::from_pointee(data),
            fail: AtomicBool::new(false),
        })
    }
}

impl CertificateProvider for TestProvider {
    fn snapshot(&self) -> Result<Arc<CertificateData>, tonic_tls::Error> {
        if self.fail.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("certificate provider unavailable").into());
        }
        Ok(self.data.load_full())
    }
}

struct TestIncoming {
    inner: TcpIncoming,
    first_connection: Option<oneshot::Sender<TcpStream>>,
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

fn identity(cert: &rcgen::Certificate, key: &rcgen::KeyPair) -> Identity {
    Identity::from_pem(cert.pem(), key.serialize_pem())
}

async fn wait_for_snapshot(
    provider: &dyn CertificateProvider,
    description: &str,
    predicate: impl Fn(&CertificateData) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !predicate(&provider.snapshot().unwrap()) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("file watcher did not publish {description}"));
}

fn roots(certs: &[&rcgen::Certificate]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert.der().clone()).unwrap();
    }
    roots
}

fn base_config(certs: &[&rcgen::Certificate]) -> ClientConfig {
    let mut config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots(certs))
            .with_no_client_auth();
    config.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];
    config
}

async fn start_server(
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

fn connector(
    endpoint: &Endpoint,
    base: ClientConfig,
    provider: Arc<dyn CertificateProvider>,
) -> tonic_tls_xds::ReloadableTlsConnector<tokio::net::TcpStream, tonic_tls_xds::rustls::TlsConnector>
{
    tonic_tls_xds::ReloadableTlsConnector::new(
        tonic_tls::TcpTransport::from_endpoint(endpoint),
        provider,
        tonic_tls_xds::rustls::TlsConnectorFactory::new(
            Arc::new(base),
            "localhost".try_into().unwrap(),
        ),
    )
    .unwrap()
}

async fn peer_identity(
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

async fn await_peer_identity(
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

#[tokio::test]
async fn rustls_client_identity_rotates_on_channel_reconnect() {
    let (server, server_key) = make_test_cert(vec!["localhost".into()]);
    let (first, first_key) = make_test_cert(vec!["client-1".into()]);
    let (second, second_key) = make_test_cert(vec!["client-2".into()]);
    let (first_connection_tx, first_connection_rx) = oneshot::channel();
    let (endpoint, shutdown, task) = start_server(
        &server,
        &server_key,
        &[&first, &second],
        Some(first_connection_tx),
    )
    .await;
    let provider = TestProvider::new(
        CertificateData::new(None, Some(identity(&first, &first_key)), None).unwrap(),
    );
    let connector = connector(&endpoint, base_config(&[&server]), provider.clone());
    let channel = endpoint.connect_with_connector(connector).await.unwrap();
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    let first_connection = first_connection_rx.await.unwrap();

    provider.data.store(Arc::new(
        CertificateData::new(None, Some(identity(&second, &second_key)), None).unwrap(),
    ));

    // Close only the authenticated first connection after publishing the update.
    // Reuse the original channel; replacement connections are never aged out.
    first_connection.shutdown(Shutdown::Both).unwrap();
    drop(first_connection);
    await_peer_identity(&mut client, "1").await;
    drop(client);
    shutdown.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn rustls_client_file_watcher_rotates_identity() {
    let (server, server_key) = make_test_cert(vec!["localhost".into()]);
    let (first, first_key) = make_test_cert(vec!["client-1".into()]);
    let (second, second_key) = make_test_cert(vec!["client-2".into()]);
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");
    std::fs::write(&cert_path, b"").unwrap();
    std::fs::write(&key_path, first_key.serialize_pem()).unwrap();
    let (endpoint, shutdown, task) =
        start_server(&server, &server_key, &[&first, &second], None).await;
    let factory = tonic_tls_xds::rustls::TlsConnectorFactory::new(
        Arc::new(base_config(&[&server])),
        "localhost".try_into().unwrap(),
    );
    let provider = Arc::new(
        tonic_tls_xds::FileWatcherProvider::new(tonic_tls_xds::FileWatcherConfig {
            certificate_file: Some(cert_path.clone()),
            private_key_file: Some(key_path.clone()),
            refresh_interval: Duration::from_millis(20),
            ..Default::default()
        })
        .await
        .unwrap(),
    );

    // The watcher accepts readable bytes; connector construction rejects the empty chain.
    let error = tonic_tls_xds::ReloadableTlsConnector::new(
        tonic_tls::TcpTransport::from_endpoint(&endpoint),
        provider.clone(),
        factory.clone(),
    )
    .err()
    .expect("connector construction must reject an empty identity chain");
    assert!(matches!(
        error.downcast_ref::<rustls::Error>(),
        Some(rustls::Error::NoCertificatesPresented),
    ));

    std::fs::write(&cert_path, first.pem()).unwrap();
    let expected = identity(&first, &first_key);
    wait_for_snapshot(provider.as_ref(), "the initial identity", |data| {
        data.identity() == Some(&expected)
    })
    .await;
    let connector = tonic_tls_xds::ReloadableTlsConnector::new(
        tonic_tls::TcpTransport::from_endpoint(&endpoint),
        provider.clone(),
        factory,
    )
    .unwrap();
    let channel = endpoint
        .connect_with_connector(connector.clone())
        .await
        .unwrap();
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");

    // A half-applied update is published, but cannot fall back to the cached pair.
    std::fs::write(&cert_path, second.pem()).unwrap();
    let expected = identity(&second, &first_key);
    wait_for_snapshot(provider.as_ref(), "the half-updated identity", |data| {
        data.identity() == Some(&expected)
    })
    .await;
    assert!(
        endpoint
            .connect_with_connector(connector.clone())
            .await
            .is_err()
    );
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    drop(client);

    // Wait for both files, then confirm the actual peer identity after recovery.
    std::fs::write(&key_path, second_key.serialize_pem()).unwrap();
    let expected = identity(&second, &second_key);
    wait_for_snapshot(provider.as_ref(), "the rotated identity", |data| {
        data.identity() == Some(&expected)
    })
    .await;
    let channel = endpoint.connect_with_connector(connector).await.unwrap();
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut client).await.unwrap(), "1");
    drop(client);
    drop(provider);
    shutdown.cancel();
    task.await.unwrap();
}

// Trust must switch servers without changing the client's mTLS identity.
#[tokio::test]
async fn rustls_client_provider_rotates_roots_and_preserves_base_identity() {
    let (server1, server1_key) = make_test_cert(vec!["localhost".into()]);
    let (server2, server2_key) = make_test_cert(vec!["localhost".into()]);
    let (client_cert, client_key) = make_test_cert(vec!["client".into()]);
    let (endpoint1, shutdown1, task1) =
        start_server(&server1, &server1_key, &[&client_cert], None).await;
    let (endpoint2, shutdown2, task2) =
        start_server(&server2, &server2_key, &[&client_cert], None).await;
    let mut base = base_config(&[]);
    let key = rustls::sign::CertifiedKey::from_der(
        vec![client_cert.der().clone()],
        PrivateKeyDer::from_pem_slice(client_key.serialize_pem().as_bytes()).unwrap(),
        base.crypto_provider(),
    )
    .unwrap();
    base.client_auth_cert_resolver = Arc::new(rustls::sign::SingleCertAndKey::from(key));
    let provider = TestProvider::new(
        CertificateData::new(Some(server1.pem().into_bytes()), None, None).unwrap(),
    );
    let connector = connector(&endpoint1, base, provider.clone());

    let channel = endpoint1
        .connect_with_connector(connector.clone())
        .await
        .unwrap();
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    drop(client);
    assert!(
        endpoint2
            .connect_with_connector(connector.clone())
            .await
            .is_err()
    );

    provider.data.store(Arc::new(
        CertificateData::new(Some(server2.pem().into_bytes()), None, None).unwrap(),
    ));
    let channel = endpoint2
        .connect_with_connector(connector.clone())
        .await
        .unwrap();
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    assert!(endpoint1.connect_with_connector(connector).await.is_err());
    drop(client);
    shutdown1.cancel();
    shutdown2.cancel();
    task1.await.unwrap();
    task2.await.unwrap();
}

// Prime the cache, reject unavailable/invalid snapshots, then verify recovery.
#[tokio::test]
async fn rustls_client_provider_errors_do_not_fall_back_to_cached_credentials() {
    let (server, server_key) = make_test_cert(vec!["localhost".into()]);
    let (client_cert, client_key) = make_test_cert(vec!["client".into()]);
    let (endpoint, shutdown, task) =
        start_server(&server, &server_key, &[&client_cert], None).await;
    let provider = TestProvider::new(
        CertificateData::new(
            Some(server.pem().into_bytes()),
            Some(identity(&client_cert, &client_key)),
            None,
        )
        .unwrap(),
    );
    let good = provider.data.load_full();
    let connector = connector(&endpoint, base_config(&[&server]), provider.clone());
    let channel = endpoint
        .connect_with_connector(connector.clone())
        .await
        .unwrap();
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    drop(client);

    provider.fail.store(true, Ordering::Relaxed);
    assert!(
        endpoint
            .connect_with_connector(connector.clone())
            .await
            .is_err()
    );
    provider.fail.store(false, Ordering::Relaxed);

    provider.data.store(Arc::new(
        CertificateData::new(
            None,
            Some(Identity::from_pem(client_cert.pem(), b"not a key")),
            None,
        )
        .unwrap(),
    ));
    assert!(
        endpoint
            .connect_with_connector(connector.clone())
            .await
            .is_err(),
        "invalid snapshot should fail, not reuse the cached configuration",
    );
    provider.data.store(good);
    let channel = endpoint
        .connect_with_connector(connector)
        .await
        .expect("a valid snapshot should recover after an error");
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    drop(client);
    shutdown.cancel();
    task.await.unwrap();
}

// Construction checks parsing and key pairing without opening sockets.
#[test]
fn rustls_client_connector_rejects_invalid_material_at_construction() {
    let (cert, key) = make_test_cert(vec!["client".into()]);
    let wrong_key = rcgen::KeyPair::generate().unwrap();
    let endpoint = Endpoint::from_static("https://localhost");
    let factory = tonic_tls_xds::rustls::TlsConnectorFactory::new(
        Arc::new(base_config(&[])),
        "localhost".try_into().unwrap(),
    );

    for (name, data) in [
        (
            "empty certificate chain",
            CertificateData::new(
                None,
                Some(Identity::from_pem(b"", key.serialize_pem())),
                None,
            )
            .unwrap(),
        ),
        (
            "mismatched certificate and key",
            CertificateData::new(None, Some(identity(&cert, &wrong_key)), None).unwrap(),
        ),
        (
            "malformed certificate",
            CertificateData::new(
                None,
                Some(Identity::from_pem(
                    b"not a certificate",
                    key.serialize_pem(),
                )),
                None,
            )
            .unwrap(),
        ),
        (
            "malformed private key",
            CertificateData::new(
                None,
                Some(Identity::from_pem(cert.pem(), b"not a key")),
                None,
            )
            .unwrap(),
        ),
        (
            "empty roots",
            CertificateData::new(Some(Vec::new()), None, None).unwrap(),
        ),
        (
            "malformed roots",
            CertificateData::new(Some(b"not a CA certificate".to_vec()), None, None).unwrap(),
        ),
    ] {
        let result = tonic_tls_xds::ReloadableTlsConnector::new(
            tonic_tls::TcpTransport::from_endpoint(&endpoint),
            TestProvider::new(data),
            factory.clone(),
        );
        assert!(result.is_err(), "{name} should be rejected at construction");
    }
}

#[test]
fn rustls_client_factory_rejects_empty_chain_with_unknown_key_consistency() {
    #[derive(Debug)]
    struct SigningKey(Arc<dyn rustls::sign::SigningKey>);

    impl rustls::sign::SigningKey for SigningKey {
        fn choose_scheme(
            &self,
            offered: &[rustls::SignatureScheme],
        ) -> Option<Box<dyn rustls::sign::Signer>> {
            self.0.choose_scheme(offered)
        }

        fn algorithm(&self) -> rustls::SignatureAlgorithm {
            self.0.algorithm()
        }
    }

    #[derive(Debug)]
    struct KeyProvider;

    impl rustls::crypto::KeyProvider for KeyProvider {
        fn load_private_key(
            &self,
            key: PrivateKeyDer<'static>,
        ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
            let key = rustls::crypto::ring::default_provider()
                .key_provider
                .load_private_key(key)?;
            Ok(Arc::new(SigningKey(key)))
        }
    }

    // The wrapper deliberately omits public_key(), making rustls skip key matching.
    let mut crypto = rustls::crypto::ring::default_provider();
    crypto.key_provider = &KeyProvider;
    let base = ClientConfig::builder_with_provider(Arc::new(crypto))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let factory = tonic_tls_xds::rustls::TlsConnectorFactory::new(
        Arc::new(base),
        "localhost".try_into().unwrap(),
    );
    let key = rcgen::KeyPair::generate().unwrap();
    let data = CertificateData::new(
        None,
        Some(Identity::from_pem(b"", key.serialize_pem())),
        None,
    )
    .unwrap();
    let error = tonic_tls_xds::TlsConnectorFactory::<tokio::io::DuplexStream>::build_connector(
        &factory, &data,
    )
    .err()
    .expect("an empty chain must be rejected even without key matching");
    assert!(matches!(
        error.downcast_ref::<rustls::Error>(),
        Some(rustls::Error::NoCertificatesPresented),
    ));
}

mod crl_tests;
