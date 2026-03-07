use std::{net::SocketAddr, sync::Arc};

use crate::helloworld::{self, HelloReply, HelloRequest};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use tokio_util::sync::CancellationToken;
use tonic::{
    Request, Response, Status,
    transport::{
        Channel,
        server::{TcpConnectInfo, TcpIncoming},
    },
};

pub struct RustlsGreeter {}

#[tonic::async_trait]
impl helloworld::greeter_server::Greeter for RustlsGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        let conn_info = request
            .extensions()
            .get::<tonic_tls::rustls::SslConnectInfo<TcpConnectInfo>>();
        let remote_addr = conn_info.as_ref().and_then(|i| i.get_ref().remote_addr());
        let peer_certs = conn_info.and_then(|i| i.peer_certs());
        println!(
            "Got a request from {remote_addr:?} with certs: {}",
            peer_certs.is_some()
        );

        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}

async fn connect_rustls_tonic_channel(
    cert: &CertificateDer<'static>,
    addr: SocketAddr,
) -> Result<Channel, tonic_tls::Error> {
    use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};

    let url = format!("https://{addr}");
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add(cert.clone()).unwrap();
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];

    let dnsname = ServerName::try_from("localhost").unwrap();

    let ep = tonic::transport::Endpoint::from_shared(url).unwrap();
    let transport = tonic_tls::TcpTransport::from_endpoint(&ep);
    ep.connect_with_connector(tonic_tls::rustls::TlsConnector::new(
        transport,
        Arc::new(config),
        dnsname,
    ))
    .await
    .map_err(tonic_tls::Error::from)
}

fn make_test_cert_rustls(
    subject_alt_names: Vec<String>,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let (cert, key_pair) = crate::tests::make_test_cert(subject_alt_names);
    let cert = CertificateDer::from(cert);
    use rustls::pki_types::pem::PemObject;
    let key = PrivateKeyDer::from_pem(
        rustls::pki_types::pem::SectionKind::PrivateKey,
        key_pair.serialize_der(),
    )
    .unwrap();
    (cert, key)
}

pub fn create_rustls_acceptor(
    cert: &CertificateDer<'static>,
    key: &PrivateKeyDer<'static>,
) -> Arc<tokio_rustls::rustls::ServerConfig> {
    let mut config = tokio_rustls::rustls::ServerConfig::builder_with_provider(
        tokio_rustls::rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key.clone_key())
    .unwrap();
    config.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];
    Arc::new(config)
}

// Run the tonic server on the current thread until token is cancelled.
async fn run_rustls_tonic_server(
    token: CancellationToken,
    tcp_s: TcpIncoming,
    tls_acceptor: Arc<tokio_rustls::rustls::ServerConfig>,
) {
    let incoming = tonic_tls::rustls::TlsIncoming::new(tcp_s, tls_acceptor);

    let greeter = RustlsGreeter {};
    tonic::transport::Server::builder()
        .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
        .serve_with_incoming_shutdown(incoming, async move { token.cancelled().await })
        .await
        .unwrap();
}

#[tokio::test]
async fn rustls_test() {
    // Generate a certificate that's valid for "localhost" and "hello.world.example"
    let (cert, key) = make_test_cert_rustls(vec![
        "hello.world.example".to_string(),
        "localhost".to_string(),
    ]);
    let (cert2, _) = make_test_cert_rustls(vec![
        "hello.world.example2".to_string(),
        "localhost2".to_string(),
    ]);

    // get a random port on localhost from os
    let (listener, addr) = crate::tests::create_listener_server().await;

    let sv_token = CancellationToken::new();
    let sv_token_cp = sv_token.clone();

    let acceptor = create_rustls_acceptor(&cert, &key);
    // start server in background
    let sv_h = tokio::spawn(async move {
        run_rustls_tonic_server(sv_token_cp, TcpIncoming::from(listener), acceptor).await
    });

    println!("running server on {addr}");

    // wait a bit for server to boot up.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // send a request with a wrong cert and verify it fails
    {
        let e = connect_rustls_tonic_channel(&cert2, addr)
            .await
            .expect_err("unexpected success");
        // there is a double wrappring of the error of ssl Error
        let src = e.source().unwrap().source().unwrap();
        // println!("debug error: {src:?}");
        let ssl_e = src.downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(ssl_e.kind(), std::io::ErrorKind::InvalidData);
        let ssl_e = ssl_e
            .get_ref()
            .unwrap()
            .downcast_ref::<rustls::Error>()
            .unwrap();
        // check cert is invalid
        assert!(matches!(ssl_e, rustls::Error::InvalidCertificate(_)));
    }

    // get client and send request
    let ch = connect_rustls_tonic_channel(&cert, addr)
        .await
        .expect("cannot connect");
    let mut client = helloworld::greeter_client::GreeterClient::new(ch);
    let request = tonic::Request::new(helloworld::HelloRequest {
        name: "Tonic".into(),
    });
    let resp = client.say_hello(request).await.unwrap();
    println!("RESPONSE={resp:?}");

    // stop server
    sv_token.cancel();
    sv_h.await.unwrap();
}
