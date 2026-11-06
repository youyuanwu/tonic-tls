use super::{TestProvider, base_config, identity, roots, wait_for_snapshot};
use crate::tests::{create_listener_server, make_test_cert};
use rustls::{
    ClientConfig, ServerConfig,
    pki_types::{PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector, client::TlsStream as ClientStream, server::TlsStream as ServerStream,
};
use tonic_tls_xds::{
    CertificateData, CertificateProvider, FileWatcherConfig, FileWatcherProvider,
    rustls::build_client_config,
};

const ALPN: &[u8] = b"raw-tcp-test";
const TIMEOUT: Duration = Duration::from_secs(5);

fn server_config(
    cert: &rcgen::Certificate,
    key: &rcgen::KeyPair,
    clients: &[&rcgen::Certificate],
) -> Arc<ServerConfig> {
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
    config.alpn_protocols = vec![ALPN.to_vec()];
    Arc::new(config)
}

async fn connect_pair(
    listener: &TcpListener,
    client_config: ClientConfig,
    server_config: Arc<ServerConfig>,
) -> std::io::Result<(ClientStream<TcpStream>, ServerStream<TcpStream>)> {
    let address = listener.local_addr()?;
    let client = async {
        let tcp = TcpStream::connect(address).await?;
        TlsConnector::from(Arc::new(client_config))
            .connect("localhost".try_into().unwrap(), tcp)
            .await
    };
    let server = async {
        let (tcp, _) = listener.accept().await?;
        TlsAcceptor::from(server_config).accept(tcp).await
    };
    let (client, server) = tokio::time::timeout(TIMEOUT, async { tokio::join!(client, server) })
        .await
        .expect("raw TCP/TLS handshake stalled");
    Ok((client?, server?))
}

async fn assert_exchange(
    client: &mut ClientStream<TcpStream>,
    server: &mut ServerStream<TcpStream>,
) {
    assert_eq!(client.get_ref().1.alpn_protocol(), Some(ALPN));
    assert_eq!(server.get_ref().1.alpn_protocol(), Some(ALPN));
    tokio::time::timeout(TIMEOUT, async {
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut request = [0; 4];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");

        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        let mut response = [0; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
    })
    .await
    .expect("raw TCP/TLS exchange stalled");
}

fn assert_untrusted_server(error: &std::io::Error) {
    // Self-signed certificates with the same issuer name can fail by signature instead.
    assert!(
        matches!(
            error
                .get_ref()
                .and_then(|error| error.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer | rustls::CertificateError::BadSignature,
            )),
        ),
        "expected an untrusted server certificate, got {error:?}",
    );
}

#[tokio::test]
async fn raw_tcp_manual_snapshots_rotate_client_identity() {
    let (server_cert, server_key) = make_test_cert(vec!["localhost".into()]);
    let (first_cert, first_key) = make_test_cert(vec!["client-1".into()]);
    let (second_cert, second_key) = make_test_cert(vec!["client-2".into()]);
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");
    std::fs::write(&cert_path, first_cert.pem()).unwrap();
    std::fs::write(&key_path, first_key.serialize_pem()).unwrap();
    let provider = FileWatcherProvider::new(
        FileWatcherConfig::default()
            .with_identity_files(&cert_path, &key_path)
            .with_refresh_interval(Duration::from_millis(20)),
    )
    .await
    .unwrap();
    let base = base_config(&[&server_cert]);
    let server = server_config(&server_cert, &server_key, &[&first_cert, &second_cert]);
    let (listener, _) = create_listener_server().await;

    let first_snapshot = provider.snapshot().unwrap();
    assert!(Arc::ptr_eq(&first_snapshot, &provider.snapshot().unwrap(),));
    let mut config = build_client_config(&base, &first_snapshot).unwrap();
    config.alpn_protocols = vec![ALPN.to_vec()];
    let (mut first_client, mut first_server) = connect_pair(&listener, config, server.clone())
        .await
        .unwrap();
    assert_eq!(
        first_server
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first(),
        Some(first_cert.der()),
    );
    assert_eq!(
        first_client
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first(),
        Some(server_cert.der()),
    );
    assert_exchange(&mut first_client, &mut first_server).await;

    std::fs::write(&cert_path, second_cert.pem()).unwrap();
    std::fs::write(&key_path, second_key.serialize_pem()).unwrap();
    let second_identity = identity(&second_cert, &second_key);
    wait_for_snapshot(&provider, "the raw TCP client identity", |data| {
        data.identity() == Some(&second_identity)
    })
    .await;

    let second_snapshot = provider.snapshot().unwrap();
    assert!(!Arc::ptr_eq(&first_snapshot, &second_snapshot));
    assert_eq!(
        first_snapshot.identity(),
        Some(&identity(&first_cert, &first_key)),
    );
    let mut config = build_client_config(&base, &second_snapshot).unwrap();
    config.alpn_protocols = vec![ALPN.to_vec()];
    let (mut second_client, mut second_server) =
        connect_pair(&listener, config, server).await.unwrap();
    assert_eq!(
        second_server
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first(),
        Some(second_cert.der()),
    );
    assert_exchange(&mut second_client, &mut second_server).await;

    assert_eq!(
        first_server
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first(),
        Some(first_cert.der()),
    );
    assert_exchange(&mut first_client, &mut first_server).await;
    assert!(!base.client_auth_cert_resolver.has_certs());
    assert_ne!(base.alpn_protocols, vec![ALPN.to_vec()]);
}

#[tokio::test]
async fn raw_tcp_manual_snapshots_rotate_roots_and_recover_after_invalid_update() {
    let (first_cert, first_key) = make_test_cert(vec!["localhost".into()]);
    let (second_cert, second_key) = make_test_cert(vec!["localhost".into()]);
    let (client_cert, client_key) = make_test_cert(vec!["client".into()]);
    let provider = TestProvider::new(
        CertificateData::new(Some(first_cert.pem().into_bytes()), None, None).unwrap(),
    );
    let client_identity =
        CertificateData::new(None, Some(identity(&client_cert, &client_key)), None).unwrap();
    let mut base = build_client_config(&base_config(&[]), &client_identity).unwrap();
    base.alpn_protocols = vec![ALPN.to_vec()];
    let first_server_config = server_config(&first_cert, &first_key, &[&client_cert]);
    let second_server_config = server_config(&second_cert, &second_key, &[&client_cert]);
    let (listener, _) = create_listener_server().await;

    let first_snapshot = provider.snapshot().unwrap();
    let config = build_client_config(&base, &first_snapshot).unwrap();
    let (mut first_client, mut first_server) =
        connect_pair(&listener, config, first_server_config.clone())
            .await
            .unwrap();
    assert_exchange(&mut first_client, &mut first_server).await;

    let config = build_client_config(&base, &first_snapshot).unwrap();
    let error = connect_pair(&listener, config, second_server_config.clone())
        .await
        .expect_err("the initial snapshot must not trust the second server");
    assert_untrusted_server(&error);

    provider.data.store(Arc::new(
        CertificateData::new(Some(b"not a CA certificate".to_vec()), None, None).unwrap(),
    ));
    let invalid_snapshot = provider.snapshot().unwrap();
    assert!(build_client_config(&base, &invalid_snapshot).is_err());
    assert_exchange(&mut first_client, &mut first_server).await;

    provider.data.store(Arc::new(
        CertificateData::new(Some(second_cert.pem().into_bytes()), None, None).unwrap(),
    ));
    let second_snapshot = provider.snapshot().unwrap();
    assert!(!Arc::ptr_eq(&first_snapshot, &second_snapshot));
    assert_eq!(first_snapshot.roots(), Some(first_cert.pem().as_bytes()),);

    let config = build_client_config(&base, &second_snapshot).unwrap();
    let error = connect_pair(&listener, config, first_server_config)
        .await
        .expect_err("the rotated snapshot must stop trusting the first server");
    assert_untrusted_server(&error);

    let config = build_client_config(&base, &second_snapshot).unwrap();
    let (mut second_client, mut second_server) =
        connect_pair(&listener, config, second_server_config)
            .await
            .unwrap();
    assert_eq!(
        second_client
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first(),
        Some(second_cert.der()),
    );
    assert_eq!(
        second_server
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first(),
        Some(client_cert.der()),
    );
    assert_exchange(&mut second_client, &mut second_server).await;
    assert_exchange(&mut first_client, &mut first_server).await;
}
