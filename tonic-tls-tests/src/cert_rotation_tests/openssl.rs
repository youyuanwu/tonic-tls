use super::{RotationGreeter, assert_hello};
use crate::helloworld;
use arc_swap::ArcSwap;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tonic::transport::{Channel, server::TcpIncoming};

struct CertKeyPair {
    cert: openssl::x509::X509,
    key: openssl::pkey::PKey<openssl::pkey::Private>,
}

/// Handle to update the cert/key used by the server.
struct CertReloadHandle {
    certs: Arc<ArcSwap<CertKeyPair>>,
}

impl CertReloadHandle {
    fn reload(&self, cert: openssl::x509::X509, key: openssl::pkey::PKey<openssl::pkey::Private>) {
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
        openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls()).unwrap();
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
    let ep = tonic::transport::Endpoint::from_shared(url)
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5));
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
        let incoming = tonic_tls::openssl::TlsIncoming::new(TcpIncoming::from(listener), acceptor);
        let greeter = RotationGreeter {};
        tonic::transport::Server::builder()
            .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
            .serve_with_incoming_shutdown(incoming, async move { sv_token_cp.cancelled().await })
            .await
            .unwrap();
    });

    // Step 1: Client trusting cert1 should succeed
    let channel = connect_openssl_channel(&cert1, addr)
        .await
        .expect("cert1 client should connect");
    assert_hello(channel, "before rotation").await;

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
    let channel = connect_openssl_channel(&cert2, addr)
        .await
        .expect("cert2 client should connect after rotation");
    assert_hello(channel, "after rotation").await;

    sv_token.cancel();
    sv_h.await.unwrap();
}
