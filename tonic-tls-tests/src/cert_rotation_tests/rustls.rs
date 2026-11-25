use super::{RotationGreeter, assert_hello};
use crate::helloworld;
use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tonic::transport::{Channel, server::TcpIncoming};

/// A dynamic cert resolver that can be swapped at runtime.
#[derive(Debug)]
struct ReloadableResolver {
    certified_key: ArcSwap<CertifiedKey>,
}

impl ReloadableResolver {
    fn new(certified_key: Arc<CertifiedKey>) -> Self {
        Self {
            certified_key: ArcSwap::new(certified_key),
        }
    }

    fn update(&self, new_key: Arc<CertifiedKey>) {
        self.certified_key.store(new_key);
    }
}

impl ResolvesServerCert for ReloadableResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key.load_full())
    }
}

fn make_test_cert(
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

fn make_certified_key(
    cert: &CertificateDer<'static>,
    key: &PrivateKeyDer<'static>,
) -> Arc<CertifiedKey> {
    let signing_key = rustls::crypto::ring::sign::any_supported_type(key).unwrap();
    Arc::new(CertifiedKey::new(vec![cert.clone()], signing_key))
}

fn create_reloadable_acceptor(
    resolver: Arc<ReloadableResolver>,
) -> Arc<tokio_rustls::rustls::ServerConfig> {
    let mut config = tokio_rustls::rustls::ServerConfig::builder_with_provider(
        tokio_rustls::rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(resolver);
    config.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];
    Arc::new(config)
}

async fn connect_rustls_channel(
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

    let ep = tonic::transport::Endpoint::from_shared(url)
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5));
    let transport = tonic_tls::TcpTransport::from_endpoint(&ep);
    ep.connect_with_connector(tonic_tls::rustls::TlsConnector::new(
        transport,
        Arc::new(config),
        dnsname,
    ))
    .await
    .map_err(tonic_tls::Error::from)
}

async fn run_server(
    token: CancellationToken,
    tcp_s: TcpIncoming,
    tls_acceptor: Arc<tokio_rustls::rustls::ServerConfig>,
) {
    let incoming = tonic_tls::rustls::TlsIncoming::new(tcp_s, tls_acceptor);
    let greeter = RotationGreeter {};
    tonic::transport::Server::builder()
        .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
        .serve_with_incoming_shutdown(incoming, async move { token.cancelled().await })
        .await
        .unwrap();
}

/// Test cert rotation with rustls using a dynamic cert resolver.
///
/// 1. Server starts with cert1.
/// 2. Client trusting cert1 connects successfully.
/// 3. Server rotates to cert2 via the resolver.
/// 4. Client trusting cert1 fails to connect (cert mismatch).
/// 5. Client trusting cert2 connects successfully.
#[tokio::test]
async fn rustls_cert_rotation() {
    // Generate two different self-signed certs
    let (cert1, key1) = make_test_cert(vec!["localhost".to_string()]);
    let (cert2, key2) = make_test_cert(vec!["localhost".to_string()]);

    let ck1 = make_certified_key(&cert1, &key1);
    let ck2 = make_certified_key(&cert2, &key2);

    // Create reloadable resolver starting with cert1
    let resolver = Arc::new(ReloadableResolver::new(ck1));
    let acceptor = create_reloadable_acceptor(resolver.clone());

    let (listener, addr) = crate::tests::create_listener_server().await;

    let sv_token = CancellationToken::new();
    let sv_token_cp = sv_token.clone();
    let sv_h = tokio::spawn(async move {
        run_server(sv_token_cp, TcpIncoming::from(listener), acceptor).await
    });

    // Step 1: Client trusting cert1 should succeed
    let channel = connect_rustls_channel(&cert1, addr)
        .await
        .expect("cert1 client should connect");
    assert_hello(channel, "before rotation").await;

    // Step 2: Rotate server cert to cert2
    resolver.update(ck2);
    println!("Server cert rotated to cert2");

    // Step 3: Client trusting cert1 should fail (server now presents cert2)
    {
        let result = connect_rustls_channel(&cert1, addr).await;
        assert!(result.is_err(), "cert1 client should fail after rotation");
        println!("cert1 client correctly rejected after rotation");
    }

    // Step 4: Client trusting cert2 should succeed
    let channel = connect_rustls_channel(&cert2, addr)
        .await
        .expect("cert2 client should connect after rotation");
    assert_hello(channel, "after rotation").await;

    sv_token.cancel();
    sv_h.await.unwrap();
}
