use super::*;
use rcgen::{CertificateParams, CertifiedIssuer, Issuer, KeyPair};
use rustls::{CertificateError, pki_types::UnixTime};
use std::sync::atomic::{AtomicU64, AtomicUsize};
use tonic_tls_xds::{CrlSelection, CrlSource, FileWatcherConfig, FileWatcherProvider};

fn ca_params(name: &str, serial: u64) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.serial_number = Some(serial.into());
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params
}

fn ca(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    CertifiedIssuer::self_signed(ca_params(name, 1), KeyPair::generate().unwrap()).unwrap()
}

fn server_cert(issuer: &Issuer<'_, KeyPair>) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.serial_number = Some(3.into());
    let key = KeyPair::generate().unwrap();
    (params.signed_by(&key, issuer).unwrap(), key)
}

fn crl(issuer: &Issuer<'_, KeyPair>, revoked: &[u64]) -> Vec<u8> {
    rcgen::CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2025, 1, 1),
        next_update: rcgen::date_time_ymd(2030, 1, 1),
        crl_number: (revoked.len() as u64 + 1).into(),
        issuing_distribution_point: None,
        revoked_certs: revoked
            .iter()
            .map(|serial| rcgen::RevokedCertParams {
                serial_number: (*serial).into(),
                revocation_time: rcgen::date_time_ymd(2025, 1, 1),
                reason_code: None,
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(issuer)
    .unwrap()
    .pem()
    .unwrap()
    .into_bytes()
}

#[derive(Debug)]
struct Clock(AtomicU64);

impl Clock {
    fn new() -> Arc<Self> {
        let clock = Arc::new(Self(AtomicU64::new(0)));
        clock.set_year(2026);
        clock
    }

    fn set_year(&self, year: i32) {
        self.0.store(
            rcgen::date_time_ymd(year, 1, 1)
                .unix_timestamp()
                .try_into()
                .unwrap(),
            Ordering::Relaxed,
        );
    }
}

impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            self.0.load(Ordering::Relaxed),
        )))
    }
}

fn config(clock: Arc<Clock>) -> ClientConfig {
    let mut config = base_config(&[]);
    config.time_provider = clock;
    config
}

fn snapshot(issuer: &CertifiedIssuer<'_, KeyPair>, crls: Vec<Vec<u8>>) -> CertificateData {
    CertificateData::new(Some(issuer.pem().into_bytes()), None, Some(crls)).unwrap()
}

fn build(data: &CertificateData, clock: Arc<Clock>) -> tonic_tls_xds::rustls::TlsConnector {
    let factory = tonic_tls_xds::rustls::TlsConnectorFactory::new(
        Arc::new(config(clock)),
        "localhost".try_into().unwrap(),
    );
    tonic_tls_xds::TlsConnectorFactory::<tokio::io::DuplexStream>::build_connector(&factory, data)
        .unwrap()
        .0
}

struct CrlErrorEvents(Arc<AtomicUsize>);

impl tracing::Subscriber for CrlErrorEvents {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "tonic_tls_xds::rustls" && *metadata.level() == tracing::Level::ERROR
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        if self.enabled(event.metadata()) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

fn build_with_error_count(data: &CertificateData) -> (tonic_tls_xds::rustls::TlsConnector, usize) {
    let errors = Arc::new(AtomicUsize::new(0));
    let connector = tracing::subscriber::with_default(CrlErrorEvents(errors.clone()), || {
        build(data, Clock::new())
    });
    (connector, errors.load(Ordering::Relaxed))
}

fn server_config(chain: &[&rcgen::Certificate], key: &KeyPair) -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                chain.iter().map(|cert| cert.der().clone()).collect(),
                PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap(),
            )
            .unwrap(),
    )
}

async fn handshake(
    connector: &tonic_tls_xds::rustls::TlsConnector,
    server: Arc<ServerConfig>,
) -> Result<(), tonic_tls::Error> {
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let acceptor = tokio_rustls::TlsAcceptor::from(server);
    let (client, server) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            tonic_tls::TlsConnector::connect(connector, "localhost".try_into().unwrap(), client_io),
            acceptor.accept(server_io),
        )
    })
    .await
    .expect("TLS handshake stalled");
    let _stream = client?;
    server.expect("server handshake must succeed when the client accepts it");
    Ok(())
}

fn tls_error(error: &tonic_tls::Error) -> &rustls::Error {
    error
        .downcast_ref::<std::io::Error>()
        .unwrap()
        .get_ref()
        .unwrap()
        .downcast_ref::<rustls::Error>()
        .unwrap()
}

fn certificate_error(error: &tonic_tls::Error) -> &CertificateError {
    let error = tls_error(error);
    let rustls::Error::InvalidCertificate(error) = error else {
        panic!("expected certificate verification error, got {error:?}");
    };
    error
}

#[test]
fn rustls_crls_reject_invalid_material_at_construction() {
    let issuer = ca("root");
    let good = crl(&issuer, &[]);
    let malformed = b"-----BEGIN X509 CRL-----\n!\n-----END X509 CRL-----\n".to_vec();
    let endpoint = Endpoint::from_static("https://localhost");
    let factory = tonic_tls_xds::rustls::TlsConnectorFactory::new(
        Arc::new(config(Clock::new())),
        "localhost".try_into().unwrap(),
    );
    for (name, crls) in [
        ("empty collection", Vec::new()),
        ("empty file", vec![Vec::new()]),
        ("wrong PEM type", vec![issuer.pem().into_bytes()]),
        ("non-PEM file", vec![b"not a CRL".to_vec()]),
        ("malformed PEM", vec![malformed.clone()]),
        (
            "invalid DER",
            vec![b"-----BEGIN X509 CRL-----\nAAE=\n-----END X509 CRL-----\n".to_vec()],
        ),
        ("empty second file", vec![good.clone(), Vec::new()]),
        (
            "malformed second file",
            vec![good.clone(), malformed.clone()],
        ),
        (
            "malformed second CRL in bundle",
            vec![[good, malformed].concat()],
        ),
    ] {
        let result = tonic_tls_xds::ReloadableTlsConnector::new(
            tonic_tls::TcpTransport::from_endpoint(&endpoint),
            TestProvider::new(snapshot(&issuer, crls)),
            factory.clone(),
        );
        assert!(
            result.is_err(),
            "{name} must not disable revocation checking"
        );
    }
}

#[tokio::test]
async fn rustls_crls_check_leaf_and_intermediate_with_separate_files_or_bundle() {
    let root = ca("root");
    let intermediate = CertifiedIssuer::signed_by(
        ca_params("intermediate", 2),
        KeyPair::generate().unwrap(),
        &root,
    )
    .unwrap();
    let (cert, key) = server_cert(&intermediate);
    let server = server_config(&[&cert, intermediate.as_ref()], &key);
    let root_crl = crl(&root, &[]);
    let intermediate_crl = crl(&intermediate, &[]);
    for (name, crls, expected) in [
        (
            "separate files",
            vec![root_crl.clone(), intermediate_crl.clone()],
            None,
        ),
        (
            "PEM bundle",
            vec![[root_crl.clone(), intermediate_crl.clone()].concat()],
            None,
        ),
        (
            "revoked leaf",
            vec![root_crl.clone(), crl(&intermediate, &[3])],
            Some(CertificateError::Revoked),
        ),
        (
            "revoked intermediate",
            vec![crl(&root, &[2]), intermediate_crl.clone()],
            Some(CertificateError::Revoked),
        ),
        (
            "missing leaf issuer CRL",
            vec![root_crl],
            Some(CertificateError::UnknownRevocationStatus),
        ),
        (
            "missing intermediate issuer CRL",
            vec![intermediate_crl.clone()],
            Some(CertificateError::UnknownRevocationStatus),
        ),
        (
            "trust anchor excluded",
            vec![crl(&root, &[1]), intermediate_crl],
            None,
        ),
    ] {
        let connector = build(&snapshot(&root, crls), Clock::new());
        match expected {
            None => handshake(&connector, server.clone()).await.unwrap(),
            Some(expected) => {
                let error = handshake(&connector, server.clone()).await.unwrap_err();
                assert_eq!(certificate_error(&error), &expected, "{name}: {error}");
            }
        }
    }
}

#[tokio::test]
async fn rustls_static_crls_keep_first_per_issuer_and_log_duplicates() {
    let issuer = ca("root");
    let other = ca("other root");
    let (cert, key) = server_cert(&issuer);
    let server = server_config(&[&cert], &key);
    let clear = crl(&issuer, &[]);
    let revoked = crl(&issuer, &[3]);
    let unrelated = crl(&other, &[]);
    let (_, errors) =
        build_with_error_count(&snapshot(&issuer, vec![clear.clone(), unrelated.clone()]));
    assert_eq!(errors, 0);
    for (first, last, expected_revoked) in [(&clear, &revoked, false), (&revoked, &clear, true)] {
        for bundles in [
            vec![first.clone(), unrelated.clone(), last.clone()],
            vec![[first.as_slice(), unrelated.as_slice(), last.as_slice()].concat()],
        ] {
            let data = snapshot(&issuer, bundles);
            assert_eq!(data.crl_selection(), CrlSelection::FirstPerIssuer);
            let (connector, errors) = build_with_error_count(&data);
            assert_eq!(errors, 1, "static duplicates must emit an ERROR");
            let result = handshake(&connector, server.clone()).await;
            if expected_revoked {
                assert_eq!(
                    certificate_error(&result.unwrap_err()),
                    &CertificateError::Revoked
                );
            } else {
                result.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn rustls_duplicate_crls_do_not_fall_back_after_signature_failure() {
    let issuer = ca("root");
    let impostor = ca("root");
    let (cert, key) = server_cert(&issuer);
    let (connector, errors) = build_with_error_count(&snapshot(
        &issuer,
        vec![crl(&impostor, &[]), crl(&issuer, &[])],
    ));
    assert_eq!(
        errors, 1,
        "selection must use issuer, not signing-key identity"
    );
    let error = handshake(&connector, server_config(&[&cert], &key))
        .await
        .unwrap_err();
    assert_eq!(
        tls_error(&error),
        &rustls::Error::InvalidCertRevocationList(rustls::CertRevocationListError::BadSignature),
    );
}

#[tokio::test]
async fn rustls_crls_reject_wrong_signing_key() {
    let issuer = ca("root");
    let impostor = ca("root");
    let (cert, key) = server_cert(&issuer);
    let connector = build(&snapshot(&issuer, vec![crl(&impostor, &[])]), Clock::new());
    let error = handshake(&connector, server_config(&[&cert], &key))
        .await
        .unwrap_err();
    assert_eq!(
        tls_error(&error),
        &rustls::Error::InvalidCertRevocationList(rustls::CertRevocationListError::BadSignature),
    );
}

#[tokio::test]
async fn rustls_crl_expiry_is_checked_without_rebuilding_connector() {
    let issuer = ca("root");
    let (cert, key) = server_cert(&issuer);
    let server = server_config(&[&cert], &key);
    let clock = Clock::new();
    let connector = build(&snapshot(&issuer, vec![crl(&issuer, &[])]), clock.clone());
    handshake(&connector, server.clone()).await.unwrap();
    clock.set_year(2031);
    let error = handshake(&connector, server).await.unwrap_err();
    assert!(
        matches!(
            certificate_error(&error),
            CertificateError::ExpiredRevocationListContext { .. },
        ),
        "{error}"
    );
}

struct CountingProvider {
    inner: FileWatcherProvider,
    snapshots: AtomicUsize,
}

impl CertificateProvider for CountingProvider {
    fn snapshot(&self) -> Result<Arc<CertificateData>, tonic_tls::Error> {
        self.snapshots.fetch_add(1, Ordering::Relaxed);
        self.inner.snapshot()
    }
}

enum CrlSourceKind {
    File,
    Directory,
}

async fn duplicate_crl_reload(source: CrlSourceKind) {
    let issuer = ca("root");
    let (cert, key) = server_cert(&issuer);
    let server = server_config(&[&cert], &key);
    let clear = crl(&issuer, &[]);
    let revoked = crl(&issuer, &[3]);
    let dir = tempfile::tempdir().unwrap();
    let roots = dir.path().join("roots.pem");
    let directory = dir.path().join("crls");
    let bundle = dir.path().join("bundle.pem");
    std::fs::write(&roots, issuer.pem()).unwrap();
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("01.pem"), &clear).unwrap();
    std::fs::write(directory.join("02.pem"), &revoked).unwrap();
    std::fs::write(&bundle, [clear.as_slice(), revoked.as_slice()].concat()).unwrap();
    let (crl_source, selection, error_count) = match source {
        CrlSourceKind::File => (
            CrlSource::File(bundle.clone()),
            CrlSelection::FirstPerIssuer,
            1,
        ),
        CrlSourceKind::Directory => (
            CrlSource::Directory(directory.clone()),
            CrlSelection::LastPerIssuer,
            0,
        ),
    };
    let provider = FileWatcherProvider::new(
        FileWatcherConfig::default()
            .with_ca_certificate_file(roots)
            .with_crl_source(crl_source)
            .with_refresh_interval(Duration::from_millis(20)),
    )
    .await
    .unwrap();
    for (first, last) in [(&clear, &revoked), (&revoked, &clear)] {
        let expected = match source {
            CrlSourceKind::File => {
                let bytes = [first.as_slice(), last.as_slice()].concat();
                std::fs::write(&bundle, &bytes).unwrap();
                vec![bytes]
            }
            CrlSourceKind::Directory => {
                std::fs::write(directory.join("01.pem"), first).unwrap();
                std::fs::write(directory.join("02.pem"), last).unwrap();
                vec![first.clone(), last.clone()]
            }
        };
        wait_for_snapshot(&provider, "the reordered duplicate CRLs", |data| {
            data.crls() == Some(expected.as_slice())
        })
        .await;
        let data = provider.snapshot().unwrap();
        assert_eq!(data.crl_selection(), selection);
        let (connector, errors) = build_with_error_count(&data);
        assert_eq!(errors, error_count);
        let expected_revoked = match source {
            CrlSourceKind::File => first == &revoked,
            CrlSourceKind::Directory => last == &revoked,
        };
        let result = handshake(&connector, server.clone()).await;
        if expected_revoked {
            assert_eq!(
                certificate_error(&result.unwrap_err()),
                &CertificateError::Revoked
            );
        } else {
            result.unwrap();
        }
    }

    if matches!(source, CrlSourceKind::Directory) {
        // Remove the later, non-revoking CRL; the remaining earlier CRL must now apply.
        std::fs::remove_file(directory.join("02.pem")).unwrap();
        wait_for_snapshot(&provider, "the remaining revoking CRL", |data| {
            data.crls() == Some(std::slice::from_ref(&revoked))
        })
        .await;
        let connector = build(&provider.snapshot().unwrap(), Clock::new());
        let error = handshake(&connector, server.clone()).await.unwrap_err();
        assert_eq!(certificate_error(&error), &CertificateError::Revoked);

        for (first, last) in [(&clear, &revoked), (&revoked, &clear)] {
            let bytes = [first.as_slice(), last.as_slice()].concat();
            std::fs::write(directory.join("01.pem"), &bytes).unwrap();
            wait_for_snapshot(&provider, "the directory CRL bundle", |data| {
                data.crls() == Some(std::slice::from_ref(&bytes))
            })
            .await;
            let (connector, errors) = build_with_error_count(&provider.snapshot().unwrap());
            assert_eq!(errors, 0);
            let result = handshake(&connector, server.clone()).await;
            if last == &revoked {
                assert_eq!(
                    certificate_error(&result.unwrap_err()),
                    &CertificateError::Revoked
                );
            } else {
                result.unwrap();
            }
        }

        let malformed = b"-----BEGIN X509 CRL-----\nAAE=\n-----END X509 CRL-----\n".to_vec();
        std::fs::write(directory.join("01.pem"), &malformed).unwrap();
        std::fs::write(directory.join("02.pem"), &clear).unwrap();
        wait_for_snapshot(&provider, "the malformed earlier CRL file", |data| {
            data.crls() == Some(&[malformed.clone(), clear.clone()])
        })
        .await;
        let factory = tonic_tls_xds::rustls::TlsConnectorFactory::new(
            Arc::new(config(Clock::new())),
            "localhost".try_into().unwrap(),
        );
        assert!(
            tonic_tls_xds::TlsConnectorFactory::<tokio::io::DuplexStream>::build_connector(
                &factory,
                &provider.snapshot().unwrap(),
            )
            .is_err(),
            "a malformed earlier CRL must fail construction, not be hidden by last-wins selection",
        );
    }
}

#[tokio::test]
async fn rustls_crl_file_duplicates_keep_first_on_reload() {
    duplicate_crl_reload(CrlSourceKind::File).await;
}

#[tokio::test]
async fn rustls_crl_directory_duplicates_keep_last_on_reload() {
    duplicate_crl_reload(CrlSourceKind::Directory).await;
}

enum IdentitySource {
    Provider,
    BaseConfig,
}

async fn crl_rotation_on_channel_reconnect(source: CrlSourceKind, identity_source: IdentitySource) {
    let issuer = ca("root");
    let (server, server_key) = server_cert(&issuer);
    let (client_cert, client_key) = make_test_cert(vec!["client".into()]);
    let good = crl(&issuer, &[]);
    let revoked = crl(&issuer, &[3]);
    let dir = tempfile::tempdir().unwrap();
    let roots = dir.path().join("ca.pem");
    let cert = dir.path().join("client.pem");
    let key = dir.path().join("client.key");
    let crls = dir.path().join("crls");
    let path = crls.join("issuer.pem");
    std::fs::create_dir(&crls).unwrap();
    std::fs::write(&roots, issuer.pem()).unwrap();
    std::fs::write(&cert, client_cert.pem()).unwrap();
    std::fs::write(&key, client_key.serialize_pem()).unwrap();
    std::fs::write(&path, &good).unwrap();
    let mut base = config(Clock::new());
    let mut watcher_config = FileWatcherConfig::default()
        .with_ca_certificate_file(roots)
        .with_crl_source(match source {
            CrlSourceKind::File => CrlSource::File(path.clone()),
            CrlSourceKind::Directory => CrlSource::Directory(crls),
        })
        .with_refresh_interval(Duration::from_millis(20));
    match identity_source {
        IdentitySource::Provider => {
            watcher_config = watcher_config.with_identity_files(cert, key);
        }
        IdentitySource::BaseConfig => {
            let key = rustls::sign::CertifiedKey::from_der(
                vec![client_cert.der().clone()],
                PrivateKeyDer::from_pem_slice(client_key.serialize_pem().as_bytes()).unwrap(),
                base.crypto_provider(),
            )
            .unwrap();
            base.client_auth_cert_resolver = Arc::new(rustls::sign::SingleCertAndKey::from(key));
        }
    }
    let provider = Arc::new(CountingProvider {
        inner: FileWatcherProvider::new(watcher_config).await.unwrap(),
        snapshots: AtomicUsize::new(0),
    });
    let (first_tx, first_rx) = oneshot::channel();
    let (endpoint, shutdown, task) =
        start_server(&server, &server_key, &[&client_cert], Some(first_tx)).await;
    let connector = connector(&endpoint, base, provider.clone());
    let channel = endpoint
        .connect_with_connector(connector.clone())
        .await
        .unwrap();
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    let first_connection = first_rx.await.unwrap();

    std::fs::write(&path, &revoked).unwrap();
    wait_for_snapshot(provider.as_ref(), "the revoked CRL", |data| {
        data.crls() == Some(std::slice::from_ref(&revoked))
    })
    .await;
    assert!(
        endpoint
            .connect_with_connector(connector.clone())
            .await
            .is_err()
    );
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    let snapshots = provider.snapshots.load(Ordering::Relaxed);
    first_connection.shutdown(Shutdown::Both).unwrap();
    drop(first_connection);
    // Require an actual reconnect snapshot, not just an error from closing the old socket.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(peer_identity(&mut client).await.is_err());
            if provider.snapshots.load(Ordering::Relaxed) > snapshots {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("channel did not attempt a reconnect with the revoked snapshot");

    let malformed = b"not a CRL".to_vec();
    std::fs::write(&path, &malformed).unwrap();
    wait_for_snapshot(provider.as_ref(), "the malformed CRL", |data| {
        data.crls() == Some(std::slice::from_ref(&malformed))
    })
    .await;
    assert!(
        endpoint
            .connect_with_connector(connector.clone())
            .await
            .is_err()
    );
    match source {
        CrlSourceKind::Directory => {
            std::fs::remove_file(&path).unwrap();
            wait_for_snapshot(provider.as_ref(), "the empty CRL directory", |data| {
                data.crls() == Some(&[])
            })
            .await;
        }
        CrlSourceKind::File => {
            std::fs::write(&path, b"").unwrap();
            wait_for_snapshot(provider.as_ref(), "the empty CRL file", |data| {
                data.crls() == Some(&[Vec::new()])
            })
            .await;
        }
    }
    assert!(endpoint.connect_with_connector(connector).await.is_err());

    std::fs::write(&path, &good).unwrap();
    wait_for_snapshot(provider.as_ref(), "the restored CRL", |data| {
        data.crls() == Some(std::slice::from_ref(&good))
    })
    .await;
    await_peer_identity(&mut client, "0").await;
    drop(client);
    drop(provider);
    shutdown.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn rustls_crl_file_rotation_with_provider_identity() {
    crl_rotation_on_channel_reconnect(CrlSourceKind::File, IdentitySource::Provider).await;
}

#[tokio::test]
async fn rustls_crl_directory_rotation_preserves_base_identity() {
    crl_rotation_on_channel_reconnect(CrlSourceKind::Directory, IdentitySource::BaseConfig).await;
}
