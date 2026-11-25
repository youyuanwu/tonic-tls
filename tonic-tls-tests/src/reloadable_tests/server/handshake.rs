use super::super::support::{
    TestProvider,
    backend::{TestServerBackend, VerificationFailure},
};
use super::{acceptor, chain_identity, client_config};
use crate::{
    test_support::certs::{base_config, ca, ca_params, crl, identity, roots, server_cert},
    tests::make_test_cert,
};
use rcgen::{CertifiedIssuer, KeyPair};
use rustls::{
    ClientConfig, ServerConfig,
    pki_types::{PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tonic_tls::TlsAcceptor;
use tonic_tls_xds::{CertificateData, ClientAuth, ServerConfig as ManagedConfig};

fn crypto() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

async fn handshake<A: TlsAcceptor<DuplexStream>>(
    acceptor: &A,
    config: Arc<ClientConfig>,
) -> (
    Result<tokio_rustls::client::TlsStream<DuplexStream>, std::io::Error>,
    Result<A::TlsStream, tonic_tls::Error>,
) {
    let connector = tokio_rustls::TlsConnector::from(config);
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            connector.connect("localhost".try_into().unwrap(), client_io),
            acceptor.accept(server_io),
        )
    })
    .await
    .expect("client/server handshake stalled")
}

async fn exchange<C, S>(client: &mut C, server: &mut S)
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(Duration::from_secs(5), async {
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut bytes = [0; 4];
        server.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ping");
        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"pong");
    })
    .await
    .expect("TLS exchange stalled");
}

pub(super) async fn identities_and_client_roots_are_complete_overlays_on_original_base<
    B: TestServerBackend,
>() {
    let root = ca("server root");
    let intermediate = CertifiedIssuer::signed_by(
        ca_params("server intermediate", 2),
        KeyPair::generate().unwrap(),
        &root,
    )
    .unwrap();
    let (server, server_key) = server_cert(&intermediate);
    let client_ca1 = ca("client CA 1");
    let client_ca2 = ca("client CA 2");
    let (client1, key1) = server_cert(&client_ca1);
    let (client2, key2) = server_cert(&client_ca2);
    let base_identity = chain_identity(&[&server, intermediate.as_ref()], &server_key);
    let base = ManagedConfig::default()
        .with_identity(base_identity.clone())
        .with_ca_certificates(client_ca1.pem())
        .with_client_auth(ClientAuth::Required);
    let provider = TestProvider::new(
        CertificateData::new(Some(client_ca2.pem().into_bytes()), None, None).unwrap(),
    );
    let (acceptor, builds) = acceptor::<B, _>(provider.clone(), base);
    let first_config = client_config(&[root.as_ref()], &[&client2], &key2);
    let (client_result, server_result) = handshake(&acceptor, first_config.clone()).await;
    let mut old_client = client_result.unwrap();
    let mut old_server = server_result.unwrap();
    assert_eq!(
        old_client.get_ref().1.peer_certificates().unwrap(),
        &[server.der().clone(), intermediate.der().clone()]
    );
    let (_, rejected) = handshake(
        &acceptor,
        client_config(&[root.as_ref()], &[&client1], &key1),
    )
    .await;
    B::assert_invalid_certificate(&rejected.err().unwrap());

    // OpenSSL 3.0 cannot decode ring's PKCS#8 v2 Ed25519 encoding.
    let new_key = openssl::pkey::PKey::generate_ed25519()
        .unwrap()
        .private_key_to_pem_pkcs8()
        .unwrap();
    let new_key = KeyPair::from_pem(std::str::from_utf8(&new_key).unwrap()).unwrap();
    let new_server = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&new_key)
        .unwrap();
    provider.data.store(Arc::new(
        CertificateData::new(None, Some(identity(&new_server, &new_key)), None).unwrap(),
    ));
    let (client_result, server_result) =
        handshake(&acceptor, client_config(&[&new_server], &[&client1], &key1)).await;
    let mut new_stream = server_result.unwrap();
    let mut new_client = client_result.unwrap();
    assert_eq!(
        new_client.get_ref().1.peer_certificates().unwrap(),
        &[new_server.der().clone()]
    );
    exchange(&mut new_client, &mut new_stream).await;
    let (_, rejected) =
        handshake(&acceptor, client_config(&[&new_server], &[&client2], &key2)).await;
    B::assert_invalid_certificate(&rejected.err().unwrap());
    let (rejected, _) = handshake(
        &acceptor,
        client_config(&[root.as_ref()], &[&client1], &key1),
    )
    .await;
    assert!(
        rejected.is_err(),
        "new identity must not retain the old chain"
    );
    assert_eq!(builds.load(Ordering::Relaxed), 2);
    exchange(&mut old_client, &mut old_server).await;
    drop(acceptor);
    drop(provider);
    exchange(&mut old_client, &mut old_server).await;
}

pub(super) async fn client_crl_rotation_rejects_revocation_and_recovers<B: TestServerBackend>() {
    let root = ca("client root");
    let intermediate = CertifiedIssuer::signed_by(
        ca_params("client intermediate", 2),
        KeyPair::generate().unwrap(),
        &root,
    )
    .unwrap();
    let (client, client_key) = server_cert(&intermediate);
    let (server, server_key) = make_test_cert(vec!["localhost".into()]);
    let base = ManagedConfig::default()
        .with_identity(identity(&server, &server_key))
        .with_client_auth(ClientAuth::Required);
    let client_config = client_config(&[&server], &[&client, intermediate.as_ref()], &client_key);
    let data =
        |crls| CertificateData::new(Some(root.pem().into_bytes()), None, Some(crls)).unwrap();
    let provider = TestProvider::new(data(vec![crl(&root, &[]), crl(&intermediate, &[])]));
    let (acceptor, builds) = acceptor::<B, _>(provider.clone(), base);
    let (client, server) = handshake(&acceptor, client_config.clone()).await;
    exchange(&mut client.unwrap(), &mut server.unwrap()).await;
    for (crls, expected) in [
        (
            vec![crl(&root, &[]), crl(&intermediate, &[3])],
            VerificationFailure::Revoked,
        ),
        (
            vec![crl(&root, &[2]), crl(&intermediate, &[])],
            VerificationFailure::Revoked,
        ),
        (
            vec![crl(&root, &[])],
            VerificationFailure::UnknownRevocationStatus,
        ),
    ] {
        provider.data.store(Arc::new(data(crls)));
        let (_, rejected) = handshake(&acceptor, client_config.clone()).await;
        B::assert_verification_error(&rejected.err().unwrap(), expected);
    }

    provider.data.store(Arc::new(
        CertificateData::new(Some(root.pem().into_bytes()), None, None).unwrap(),
    ));
    let (client, server) = handshake(&acceptor, client_config).await;
    exchange(&mut client.unwrap(), &mut server.unwrap()).await;
    assert_eq!(builds.load(Ordering::Relaxed), 5);
}

#[derive(Clone)]
struct NativeAcceptor(tokio_rustls::TlsAcceptor);

impl TlsAcceptor<DuplexStream> for NativeAcceptor {
    type TlsStream = tonic_tls::rustls::TlsStream<DuplexStream>;

    async fn accept(&self, io: DuplexStream) -> Result<Self::TlsStream, tonic_tls::Error> {
        Ok(tonic_tls::rustls::TlsStream::new(self.0.accept(io).await?))
    }
}

pub(super) async fn full_handshakes_before_and_after_rotation<B: TestServerBackend>() {
    let (server, key) = make_test_cert(vec!["localhost".into()]);
    let (rotated_server, rotated_key) = make_test_cert(vec!["localhost".into()]);
    let client_ca = ca("client CA");
    let (client_cert, client_key) = server_cert(&client_ca);
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots(&[client_ca.as_ref()])),
            crypto(),
        )
        .build()
        .unwrap();
        let native = ServerConfig::builder_with_provider(crypto())
            .with_protocol_versions(&[version])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server.der().clone()],
                PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap(),
            )
            .unwrap();
        let native = NativeAcceptor(tokio_rustls::TlsAcceptor::from(Arc::new(native)));
        let mut config = ClientConfig::builder_with_provider(crypto())
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots(&[&server, &rotated_server]))
            .with_client_auth_cert(
                vec![client_cert.der().clone()],
                PrivateKeyDer::from_pem_slice(client_key.serialize_pem().as_bytes()).unwrap(),
            )
            .unwrap();
        config.alpn_protocols = vec![];
        let config = Arc::new(config);
        for expected in [rustls::HandshakeKind::Full, rustls::HandshakeKind::Resumed] {
            let (client, server) = handshake(&native, config.clone()).await;
            let mut client = client.unwrap();
            let mut server = server.unwrap();
            exchange(&mut client, &mut server).await;
            assert_eq!(client.get_ref().1.handshake_kind(), Some(expected));
        }
        // The client now has a valid resumable session from the positive control.
        let data = |identity, revoked: &[u64]| {
            CertificateData::new(
                Some(client_ca.pem().into_bytes()),
                Some(identity),
                Some(vec![crl(&client_ca, revoked)]),
            )
            .unwrap()
        };
        let good = data(identity(&server, &key), &[]);
        let provider = TestProvider::new(good.clone());
        let (acceptor, builds) = acceptor::<B, _>(
            provider.clone(),
            ManagedConfig::default().with_client_auth(ClientAuth::Required),
        );
        for rotation in 0..3 {
            if rotation == 2 {
                provider
                    .data
                    .store(Arc::new(data(identity(&rotated_server, &rotated_key), &[])));
            }
            let (client, server_stream) = handshake(&acceptor, config.clone()).await;
            let mut client = client.unwrap();
            exchange(&mut client, &mut server_stream.unwrap()).await;
            assert_eq!(client.get_ref().1.protocol_version(), Some(version.version));
            assert_eq!(
                client.get_ref().1.handshake_kind(),
                Some(rustls::HandshakeKind::Full)
            );
            let expected = if rotation == 2 {
                &rotated_server
            } else {
                &server
            };
            assert_eq!(
                client.get_ref().1.peer_certificates().unwrap().first(),
                Some(expected.der())
            );
        }
        assert_eq!(builds.load(Ordering::Relaxed), 2);
        provider.data.store(Arc::new(data(
            identity(&rotated_server, &rotated_key),
            &[3],
        )));
        let (_, rejected) = handshake(&acceptor, config.clone()).await;
        B::assert_verification_error(&rejected.err().unwrap(), VerificationFailure::Revoked);
        assert_eq!(builds.load(Ordering::Relaxed), 3);
    }
}

pub(super) async fn client_ca_hints_follow_selected_snapshot_and_original_base<
    B: TestServerBackend,
>() {
    #[derive(Debug)]
    struct RecordingResolver {
        key: Arc<rustls::sign::CertifiedKey>,
        hints: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl rustls::client::ResolvesClientCert for RecordingResolver {
        fn resolve(
            &self,
            hints: &[&[u8]],
            _: &[rustls::SignatureScheme],
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            *self.hints.lock().unwrap() = hints.iter().map(|name| name.to_vec()).collect();
            Some(self.key.clone())
        }

        fn has_certs(&self) -> bool {
            true
        }
    }

    let (server, key) = make_test_cert(vec!["localhost".into()]);
    let first = ca("client CA 1");
    let second = ca("client CA 2");
    let (client, client_key) = server_cert(&first);
    let resolver = Arc::new(RecordingResolver {
        key: Arc::new(
            rustls::sign::CertifiedKey::from_der(
                vec![client.der().clone()],
                PrivateKeyDer::from_pem_slice(client_key.serialize_pem().as_bytes()).unwrap(),
                &crypto(),
            )
            .unwrap(),
        ),
        hints: std::sync::Mutex::new(vec![]),
    });
    let mut config = base_config(&[&server]);
    config.client_auth_cert_resolver = resolver.clone();
    let config = Arc::new(config);
    let provider = TestProvider::new(
        CertificateData::new(Some(first.pem().into_bytes()), None, None).unwrap(),
    );
    let base = ManagedConfig::default()
        .with_identity(identity(&server, &key))
        .with_client_auth(ClientAuth::Required)
        .with_ca_certificates(first.pem());
    let (acceptor, _) = acceptor::<B, _>(provider.clone(), base);
    for (pem, expected) in [
        (Some(first.pem()), roots(&[first.as_ref()]).subjects()),
        (
            Some([first.pem(), second.pem()].concat()),
            roots(&[first.as_ref(), second.as_ref()]).subjects(),
        ),
        (None, roots(&[first.as_ref()]).subjects()),
    ] {
        provider.data.store(Arc::new(
            CertificateData::new(
                pem.map(String::into_bytes),
                Some(identity(&server, &key)),
                None,
            )
            .unwrap(),
        ));
        let (client, server) = handshake(&acceptor, config.clone()).await;
        exchange(&mut client.unwrap(), &mut server.unwrap()).await;
        assert_eq!(
            *resolver.hints.lock().unwrap(),
            expected
                .iter()
                .map(|name| name.as_ref().to_vec())
                .collect::<Vec<_>>()
        );
    }
}
