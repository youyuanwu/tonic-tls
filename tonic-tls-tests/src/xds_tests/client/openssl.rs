use super::super::support::{
    backend::assert_openssl_verification_error as assert_verification_error,
    certs::{ca, ca_params, crl, identity, roots, server_cert, server_config, snapshot},
};
use crate::tests::make_test_cert;
use openssl::{
    ssl::{Ssl, SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::X509,
};
use rcgen::{CertifiedIssuer, KeyPair};
use std::{pin::Pin, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tonic_tls_xds::{
    CertificateData, Identity,
    openssl::{ClientConfig, TlsConnector},
};

fn base_config(certs: &[&rcgen::Certificate]) -> ClientConfig {
    let pem = certs.iter().map(|cert| cert.pem()).collect::<String>();
    ClientConfig::default().with_ca_certificates(pem)
}

fn build(data: &CertificateData) -> TlsConnector {
    TlsConnector::new(&ClientConfig::default(), data).unwrap()
}

type ClientStream = tokio_openssl::SslStream<tokio::io::DuplexStream>;
type ServerStream = tokio_rustls::server::TlsStream<tokio::io::DuplexStream>;

async fn connect_pair(
    connector: &TlsConnector,
    server: Arc<rustls::ServerConfig>,
    domain: &str,
) -> Result<(ClientStream, ServerStream), tonic_tls::Error> {
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let acceptor = tokio_rustls::TlsAcceptor::from(server);
    let (client, server) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            connector.connect(domain, client_io),
            acceptor.accept(server_io)
        )
    })
    .await
    .expect("TLS handshake stalled");
    let client = client?;
    assert!(!client.ssl().session_reused());
    Ok((
        client,
        server.expect("server must accept a successful client handshake"),
    ))
}

async fn assert_exchange(client: &mut ClientStream, server: &mut ServerStream) {
    tokio::time::timeout(Duration::from_secs(5), async {
        client.write_all(b"ping").await.unwrap();
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
    .expect("TLS data exchange stalled");
}

async fn handshake(
    connector: &TlsConnector,
    server: Arc<rustls::ServerConfig>,
    domain: &str,
) -> Result<(), tonic_tls::Error> {
    let (mut client, mut server) = connect_pair(connector, server, domain).await?;
    assert_exchange(&mut client, &mut server).await;
    Ok(())
}

#[test]
fn configuration_validates_effective_material_and_alpn_limits() {
    let (cert, key) = make_test_cert(vec!["client".into()]);
    let roots_only = CertificateData::new(Some(cert.pem().into_bytes()), None, None).unwrap();
    let identity_only = CertificateData::new(None, Some(identity(&cert, &key)), None).unwrap();
    for roots in [Vec::new(), b"invalid".to_vec()] {
        let config = ClientConfig::default().with_ca_certificates(roots);
        assert!(TlsConnector::new(&config, &identity_only).is_err());
        assert!(
            TlsConnector::new(&config, &roots_only).is_ok(),
            "snapshot replaces invalid unused base roots"
        );
    }
    let config =
        base_config(&[&cert]).with_identity(Identity::from_pem(cert.pem(), b"secret-invalid-key"));
    assert!(TlsConnector::new(&config, &roots_only).is_err());
    assert!(
        TlsConnector::new(&config, &identity_only).is_ok(),
        "snapshot replaces unused base identity"
    );
    assert!(!format!("{config:?}").contains("secret-invalid-key"));
    for (protocols, valid) in [
        (Vec::new(), true),
        (vec![Vec::new()], false),
        (vec![vec![b'a'; 255]], true),
        (vec![vec![b'a'; 256]], false),
        (
            [vec![vec![b'a'; 255]; 255], vec![vec![b'b'; 254]]].concat(),
            true,
        ),
        (vec![vec![b'a'; 255]; 256], false),
    ] {
        let config = ClientConfig::default().with_alpn_protocols(protocols);
        assert_eq!(TlsConnector::new(&config, &roots_only).is_ok(), valid);
    }
}

#[tokio::test]
async fn alpn_uses_configured_protocols_or_can_be_disabled() {
    let (cert, key) = make_test_cert(vec!["localhost".into()]);
    let data = CertificateData::new(Some(cert.pem().into_bytes()), None, None).unwrap();
    let mut server = (*server_config(&[&cert], &key)).clone();
    server.alpn_protocols = vec![b"h2".to_vec(), b"raw-test".to_vec()];
    let server = Arc::new(server);
    for (config, expected) in [
        (ClientConfig::default(), Some(b"h2".as_slice())),
        (
            ClientConfig::default().with_alpn_protocols(vec![b"raw-test".to_vec()]),
            Some(b"raw-test".as_slice()),
        ),
        (
            ClientConfig::default().with_alpn_protocols(Vec::new()),
            None,
        ),
    ] {
        let connector = TlsConnector::new(&config, &data).unwrap();
        let (client, peer) = connect_pair(&connector, server.clone(), "localhost")
            .await
            .unwrap();
        assert_eq!(client.ssl().selected_alpn_protocol(), expected);
        assert_eq!(peer.get_ref().1.alpn_protocol(), expected);
    }
}

#[test]
fn encrypted_private_keys_are_rejected_without_prompting() {
    let (cert, key) = crate::tests::make_test_cert2(vec!["client".into()]);
    let rsa = key.rsa().unwrap();
    let mut encrypted = Vec::new();
    for password in [b"test-password".as_slice(), b"".as_slice()] {
        encrypted.push(
            key.private_key_to_pem_pkcs8_passphrase(openssl::symm::Cipher::aes_256_cbc(), password)
                .unwrap(),
        );
        encrypted.push(
            rsa.private_key_to_pem_passphrase(openssl::symm::Cipher::aes_256_cbc(), password)
                .unwrap(),
        );
    }
    let cert = cert.to_pem().unwrap();
    let (ec_cert, ec_key) = make_test_cert(vec!["client".into()]);
    let ec_key = openssl::pkey::PKey::private_key_from_der(&ec_key.serialize_der()).unwrap();
    let plaintext = [
        (cert.clone(), key.private_key_to_pem_pkcs8().unwrap()),
        (cert.clone(), rsa.private_key_to_pem().unwrap()),
        (
            ec_cert.pem().into_bytes(),
            ec_key.ec_key().unwrap().private_key_to_pem().unwrap(),
        ),
    ];
    let (tx, rx) = std::sync::mpsc::channel();
    // A Tokio timeout cannot interrupt a synchronous password prompt.
    let worker = std::thread::spawn(move || {
        let base = ClientConfig::default().with_ca_certificates(cert.clone());
        let roots_only = CertificateData::new(Some(cert.clone()), None, None).unwrap();
        for pem in encrypted {
            let identity = Identity::from_pem(cert.clone(), pem);
            let identity_only = CertificateData::new(None, Some(identity.clone()), None).unwrap();
            for result in [
                TlsConnector::new(&base, &identity_only),
                TlsConnector::new(&base.clone().with_identity(identity), &roots_only),
            ] {
                let error = result
                    .err()
                    .expect("encrypted keys must be rejected, even with an empty password");
                assert!(
                    error
                        .downcast_ref::<rustls::pki_types::pem::Error>()
                        .is_some(),
                    "encrypted PEM must fail before entering OpenSSL's key parser: {error}",
                );
            }
        }
        for (cert, pem) in plaintext {
            let identity = Identity::from_pem(cert, pem);
            let identity_only = CertificateData::new(None, Some(identity.clone()), None).unwrap();
            TlsConnector::new(&base, &identity_only).unwrap();
            TlsConnector::new(&base.clone().with_identity(identity), &roots_only).unwrap();
        }
        tx.send(()).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("key parsing must finish without waiting for a password");
    worker.join().unwrap();
}

#[tokio::test]
async fn snapshot_identity_replaces_base_key_algorithm_and_entire_chain() {
    let (server, server_key) = make_test_cert(vec!["localhost".into()]);
    let root = ca("client root");
    let intermediate = CertifiedIssuer::signed_by(
        ca_params("client intermediate", 2),
        KeyPair::generate().unwrap(),
        &root,
    )
    .unwrap();
    let (client, client_key) = server_cert(&intermediate);
    let (old_cert, old_key) = crate::tests::make_test_cert2(vec!["old-client".into()]);
    let old_pem = old_cert.to_pem().unwrap();
    let base = base_config(&[&server, root.as_ref()]).with_identity(Identity::from_pem(
        [old_pem.clone(), old_pem].concat(),
        old_key.private_key_to_pem_pkcs8().unwrap(),
    ));
    let data = CertificateData::new(
        None,
        Some(Identity::from_pem(
            [client.pem(), intermediate.pem()].concat(),
            client_key.serialize_pem(),
        )),
        None,
    )
    .unwrap();
    let (direct, direct_key) = server_cert(&root);
    let direct_data =
        CertificateData::new(None, Some(identity(&direct, &direct_key)), None).unwrap();
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots(&[root.as_ref()])),
        crypto.clone(),
    )
    .build()
    .unwrap();
    let server = Arc::new(
        rustls::ServerConfig::builder_with_provider(crypto)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
            )
            .unwrap(),
    );
    for (snapshot, expected) in [
        (
            &data,
            vec![client.der().clone(), intermediate.der().clone()],
        ),
        (&direct_data, vec![direct.der().clone()]),
    ] {
        let connector = TlsConnector::new(&base, snapshot).unwrap();
        let (_, stream) = connect_pair(&connector, server.clone(), "localhost")
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.peer_certificates().unwrap(), expected);
    }
}

fn dated_crl(issuer: &rcgen::Issuer<'_, KeyPair>, start: i32, end: i32) -> Vec<u8> {
    rcgen::CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(start, 1, 1),
        next_update: rcgen::date_time_ymd(end, 1, 1),
        crl_number: 1u64.into(),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(issuer)
    .unwrap()
    .pem()
    .unwrap()
    .into_bytes()
}

#[tokio::test]
async fn crl_validity_and_hostname_are_checked() {
    let root = ca("root");
    let (cert, key) = server_cert(&root);
    let server = server_config(&[&cert], &key);
    let clear = crl(&root, &[]);
    for first in [dated_crl(&root, 2020, 2021), dated_crl(&root, 2098, 2099)] {
        let connector = build(&snapshot(&root, vec![first, clear.clone()]));
        assert_verification_error(
            &handshake(&connector, server.clone(), "localhost")
                .await
                .unwrap_err(),
        );
    }
    let connector = build(&snapshot(&root, vec![clear]));
    handshake(&connector, server.clone(), "localhost")
        .await
        .unwrap();
    assert_verification_error(
        &handshake(&connector, server, "wrong.example")
            .await
            .unwrap_err(),
    );
}

#[tokio::test]
async fn snapshot_identity_cannot_fall_back_to_old_rsa_credentials() {
    let (old_cert, old_key) = crate::tests::make_test_cert2(vec!["localhost".into()]);
    let (new_cert, new_key) = make_test_cert(vec!["new-client".into()]);
    let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    server.set_certificate(&old_cert).unwrap();
    server.set_private_key(&old_key).unwrap();
    server.cert_store_mut().add_cert(old_cert.clone()).unwrap();
    server
        .cert_store_mut()
        .add_cert(X509::from_der(new_cert.der()).unwrap())
        .unwrap();
    server.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    server.set_sigalgs_list("rsa_pss_rsae_sha256").unwrap();
    let server = server.build();
    let base = ClientConfig::default()
        .with_ca_certificates(old_cert.to_pem().unwrap())
        .with_identity(Identity::from_pem(
            old_cert.to_pem().unwrap(),
            old_key.private_key_to_pem_pkcs8().unwrap(),
        ));
    let data = CertificateData::new(None, Some(identity(&new_cert, &new_key)), None).unwrap();
    let roots_only = CertificateData::new(Some(old_cert.to_pem().unwrap()), None, None).unwrap();
    for (data, succeeds) in [(&roots_only, true), (&data, false)] {
        let connector = TlsConnector::new(&base, data).unwrap();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let mut stream =
            tokio_openssl::SslStream::new(Ssl::new(server.context()).unwrap(), server_io).unwrap();
        let (client, result) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                connector.connect("localhost", client_io),
                Pin::new(&mut stream).accept()
            )
        })
        .await
        .unwrap();
        if succeeds {
            client.unwrap();
            result.unwrap();
            assert_eq!(
                stream.ssl().peer_certificate().unwrap().to_der().unwrap(),
                old_cert.to_der().unwrap()
            );
        } else {
            assert_eq!(result.unwrap_err().code(), openssl::ssl::ErrorCode::SSL);
            assert!(
                stream.ssl().peer_certificate().is_none(),
                "must not present the old RSA identity"
            );
        }
    }
}

#[tokio::test]
async fn raw_connections_cache_contexts_preserve_snapshots_and_never_resume() {
    let (first, first_key) = make_test_cert(vec!["localhost".into()]);
    let (second, second_key) = make_test_cert(vec!["localhost".into()]);
    let (client, client_key) = make_test_cert(vec!["client".into()]);
    let mut server1 = (*server_config(&[&first], &first_key)).clone();
    server1.alpn_protocols = vec![b"raw-test".to_vec()];
    server1.send_tls13_tickets = 1;
    let server1 = Arc::new(server1);
    let server2 = server_config(&[&second], &second_key);
    let base = base_config(&[&first]).with_alpn_protocols(vec![b"raw-test".to_vec()]);
    let identity_only =
        CertificateData::new(None, Some(identity(&client, &client_key)), None).unwrap();
    let original = TlsConnector::new(&base, &identity_only).unwrap();
    let (mut live_client, mut live_server) = connect_pair(&original, server1.clone(), "localhost")
        .await
        .unwrap();
    assert_exchange(&mut live_client, &mut live_server).await;
    assert_eq!(
        live_client.ssl().selected_alpn_protocol(),
        Some(b"raw-test".as_slice())
    );
    assert_eq!(
        live_server.get_ref().1.alpn_protocol(),
        Some(b"raw-test".as_slice())
    );
    let (mut next, mut peer) = connect_pair(&original.clone(), server1.clone(), "localhost")
        .await
        .unwrap();
    assert!(std::ptr::eq(
        next.ssl().ssl_context(),
        live_client.ssl().ssl_context()
    ));
    assert_exchange(&mut next, &mut peer).await;
    assert!(!next.ssl().session_reused());
    assert_eq!(
        peer.get_ref().1.handshake_kind(),
        Some(rustls::HandshakeKind::Full)
    );
    let roots_only = CertificateData::new(Some(second.pem().into_bytes()), None, None).unwrap();
    let rotated = TlsConnector::new(&base, &roots_only).unwrap();
    let (new_client, _) = connect_pair(&rotated, server2.clone(), "localhost")
        .await
        .unwrap();
    assert!(!std::ptr::eq(
        new_client.ssl().ssl_context(),
        live_client.ssl().ssl_context()
    ));
    assert_verification_error(
        &handshake(&rotated, server1.clone(), "localhost")
            .await
            .unwrap_err(),
    );
    assert_verification_error(
        &handshake(&original, server2, "localhost")
            .await
            .unwrap_err(),
    );
    let restored = TlsConnector::new(&base, &identity_only).unwrap();
    handshake(&restored, server1, "localhost").await.unwrap();
    drop(original);
    drop(rotated);
    drop(base);
    assert_exchange(&mut live_client, &mut live_server).await;
}

#[tokio::test]
async fn certificate_less_psk_is_not_offered() {
    const KEY: &[u8] = &[0x42; 32];
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
        server.set_min_proto_version(Some(version)).unwrap();
        server.set_max_proto_version(Some(version)).unwrap();
        server.set_cipher_list("PSK-AES128-GCM-SHA256").unwrap();
        server.set_ciphersuites("TLS_AES_128_GCM_SHA256").unwrap();
        server.set_psk_server_callback(|_, _, psk| {
            psk[..KEY.len()].copy_from_slice(KEY);
            Ok(KEY.len())
        });
        let server = server.build();
        let mut control = SslConnector::builder(SslMethod::tls_client()).unwrap();
        control.set_min_proto_version(Some(version)).unwrap();
        control.set_max_proto_version(Some(version)).unwrap();
        control.set_cipher_list("PSK-AES128-GCM-SHA256").unwrap();
        control.set_ciphersuites("TLS_AES_128_GCM_SHA256").unwrap();
        control.set_psk_client_callback(|_, _, identity, psk| {
            identity[..5].copy_from_slice(b"test\0");
            psk[..KEY.len()].copy_from_slice(KEY);
            Ok(KEY.len())
        });
        let control = control.build();
        let root = ca("root");
        let connector = build(&snapshot(&root, vec![crl(&root, &[])]));
        for control_case in [true, false] {
            let (client_io, server_io) = tokio::io::duplex(16 * 1024);
            let mut peer =
                tokio_openssl::SslStream::new(Ssl::new(server.context()).unwrap(), server_io)
                    .unwrap();
            let connect = async {
                if control_case {
                    let mut stream = tokio_openssl::SslStream::new(
                        control.configure()?.into_ssl("localhost")?,
                        client_io,
                    )?;
                    Pin::new(&mut stream).connect().await?;
                    Ok::<_, tonic_tls::Error>(stream)
                } else {
                    connector.connect("localhost", client_io).await
                }
            };
            let (client, result) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(connect, Pin::new(&mut peer).accept())
            })
            .await
            .unwrap();
            if control_case {
                assert!(client.unwrap().ssl().peer_certificate().is_none());
                result.unwrap();
            } else {
                assert!(
                    client.is_err() && result.is_err(),
                    "PSK-only authentication must fail"
                );
            }
        }
    }
}
