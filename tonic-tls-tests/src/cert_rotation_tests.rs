use std::{net::SocketAddr, sync::Arc};

use crate::helloworld::{self, HelloReply, HelloRequest};
use tokio_util::sync::CancellationToken;
use tonic::{
    Request, Response, Status,
    transport::{Channel, server::TcpIncoming},
};

pub struct RotationGreeter {}

#[tonic::async_trait]
impl helloworld::greeter_server::Greeter for RotationGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}

// ============================================================
// Rustls cert rotation test using ResolvesServerCert
// ============================================================

mod rustls_rotation {
    use super::*;
    use arc_swap::ArcSwap;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::ResolvesServerCert;
    use rustls::sign::CertifiedKey;

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
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<CertifiedKey>> {
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

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        // Step 1: Client trusting cert1 should succeed
        {
            let ch = connect_rustls_channel(&cert1, addr)
                .await
                .expect("cert1 client should connect");
            let mut client = helloworld::greeter_client::GreeterClient::new(ch);
            let resp = client
                .say_hello(Request::new(HelloRequest {
                    name: "before rotation".into(),
                }))
                .await
                .unwrap();
            println!("Before rotation: {resp:?}");
        }

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
        {
            let ch = connect_rustls_channel(&cert2, addr)
                .await
                .expect("cert2 client should connect after rotation");
            let mut client = helloworld::greeter_client::GreeterClient::new(ch);
            let resp = client
                .say_hello(Request::new(HelloRequest {
                    name: "after rotation".into(),
                }))
                .await
                .unwrap();
            println!("After rotation: {resp:?}");
        }

        sv_token.cancel();
        sv_h.await.unwrap();
    }
}

// ============================================================
// OpenSSL cert rotation test using set_client_hello_callback.
// Unlike the SNI callback, the client hello callback fires on
// every handshake regardless of whether the client sends SNI.
// ============================================================

mod openssl_rotation {
    use super::*;
    use arc_swap::ArcSwap;

    struct CertKeyPair {
        cert: openssl::x509::X509,
        key: openssl::pkey::PKey<openssl::pkey::Private>,
    }

    /// Handle to update the cert/key used by the server.
    struct CertReloadHandle {
        certs: Arc<ArcSwap<CertKeyPair>>,
    }

    impl CertReloadHandle {
        fn reload(
            &self,
            cert: openssl::x509::X509,
            key: openssl::pkey::PKey<openssl::pkey::Private>,
        ) {
            self.certs.store(Arc::new(CertKeyPair { cert, key }));
        }
    }

    /// Build an SslAcceptor with a client hello callback that dynamically
    /// loads the current cert/key from shared state on every handshake.
    /// The acceptor is built once and never reconstructed.
    fn create_reloadable_openssl_acceptor(
        cert: &openssl::x509::X509,
        key: &openssl::pkey::PKey<openssl::pkey::Private>,
    ) -> (openssl::ssl::SslAcceptor, CertReloadHandle) {
        let certs = Arc::new(ArcSwap::new(Arc::new(CertKeyPair {
            cert: cert.clone(),
            key: key.clone(),
        })));
        let cb_certs = certs.clone();

        let mut acceptor =
            openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls())
                .unwrap();
        acceptor.set_alpn_select_callback(|_ssl, alpn| {
            openssl::ssl::select_next_proto(tonic_tls::openssl::ALPN_H2_WIRE, alpn)
                .ok_or(openssl::ssl::AlpnError::NOACK)
        });

        // Client hello callback: fires on every handshake, sets cert/key
        // from shared state. No unsafe FFI needed.
        acceptor.set_client_hello_callback(move |ssl, _alert| {
            let current = cb_certs.load();
            ssl.set_certificate(&current.cert)
                .map_err(|_| openssl::error::ErrorStack::get())?;
            ssl.set_private_key(&current.key)
                .map_err(|_| openssl::error::ErrorStack::get())?;
            Ok(openssl::ssl::ClientHelloResponse::SUCCESS)
        });

        let handle = CertReloadHandle { certs };
        (acceptor.build(), handle)
    }

    async fn connect_openssl_channel(
        cert: &openssl::x509::X509,
        addr: SocketAddr,
    ) -> Result<Channel, tonic_tls::Error> {
        let mut connector =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()).unwrap();
        connector.cert_store_mut().add_cert(cert.clone()).unwrap();
        connector.set_verify_callback(openssl::ssl::SslVerifyMode::PEER, |ok, ctx| {
            if !ok {
                let e = ctx.error();
                println!("verify failed: {e}");
            }
            ok
        });
        connector
            .set_alpn_protos(tonic_tls::openssl::ALPN_H2_WIRE)
            .unwrap();
        let connector = connector.build();

        let url = format!("https://localhost:{}", addr.port());
        let dnsname = "localhost".to_string();
        let ep = tonic::transport::Endpoint::from_shared(url).unwrap();
        let transport = tonic_tls::TcpTransport::from_endpoint(&ep);
        ep.connect_with_connector(tonic_tls::openssl::TlsConnector::new(
            transport, connector, dnsname,
        ))
        .await
        .map_err(tonic_tls::Error::from)
    }

    /// Test cert rotation with openssl using set_client_hello_callback.
    /// The acceptor is built once; cert/key are swapped via ArcSwap
    /// and picked up by the client hello callback on every handshake.
    ///
    /// 1. Server starts with cert1.
    /// 2. Client trusting cert1 connects successfully.
    /// 3. Cert/key are swapped to cert2 via the reload handle.
    /// 4. Client trusting cert1 fails to connect (cert mismatch).
    /// 5. Client trusting cert2 connects successfully.
    #[tokio::test]
    async fn openssl_cert_rotation() {
        // Generate two different self-signed certs
        let (cert1, key1) = crate::tests::make_test_cert2(vec!["localhost".to_string()]);
        let (cert2, key2) = crate::tests::make_test_cert2(vec!["localhost".to_string()]);

        // Create acceptor with client hello callback; built once, never reconstructed
        let (acceptor, reload_handle) = create_reloadable_openssl_acceptor(&cert1, &key1);

        let (listener, addr) = crate::tests::create_listener_server().await;

        let sv_token = CancellationToken::new();
        let sv_token_cp = sv_token.clone();

        // Use standard TlsIncoming — no custom TlsAcceptor impl needed
        let sv_h = tokio::spawn(async move {
            let incoming =
                tonic_tls::openssl::TlsIncoming::new(TcpIncoming::from(listener), acceptor);
            let greeter = RotationGreeter {};
            tonic::transport::Server::builder()
                .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
                .serve_with_incoming_shutdown(
                    incoming,
                    async move { sv_token_cp.cancelled().await },
                )
                .await
                .unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        // Step 1: Client trusting cert1 should succeed
        {
            let ch = connect_openssl_channel(&cert1, addr)
                .await
                .expect("cert1 client should connect");
            let mut client = helloworld::greeter_client::GreeterClient::new(ch);
            let resp = client
                .say_hello(Request::new(HelloRequest {
                    name: "before rotation".into(),
                }))
                .await
                .unwrap();
            println!("Before rotation: {resp:?}");
        }

        // Step 2: Rotate cert/key — no acceptor reconstruction
        reload_handle.reload(cert2.clone(), key2);
        println!("Server cert rotated to cert2");

        // Step 3: Client trusting cert1 should fail (server now presents cert2)
        {
            let result = connect_openssl_channel(&cert1, addr).await;
            assert!(result.is_err(), "cert1 client should fail after rotation");
            println!("cert1 client correctly rejected after rotation");
        }

        // Step 4: Client trusting cert2 should succeed
        {
            let ch = connect_openssl_channel(&cert2, addr)
                .await
                .expect("cert2 client should connect after rotation");
            let mut client = helloworld::greeter_client::GreeterClient::new(ch);
            let resp = client
                .say_hello(Request::new(HelloRequest {
                    name: "after rotation".into(),
                }))
                .await
                .unwrap();
            println!("After rotation: {resp:?}");
        }

        sv_token.cancel();
        sv_h.await.unwrap();
    }
}
