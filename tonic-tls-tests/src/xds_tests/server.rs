use super::support::{
    TestProvider,
    backend::{OpenSsl, Rustls, TestServerBackend, VerificationFailure},
    certs::{base_config, ca, ca_params, crl, identity, roots, server_cert},
    grpc::{TestIncoming, await_peer_identity, peer_identity},
    wait_for_snapshot,
};
use crate::{
    helloworld::{self, HelloReply, HelloRequest},
    tests::{create_listener_server, make_test_cert},
};
use rcgen::{CertifiedIssuer, KeyPair};
use rustls::{
    ClientConfig, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use std::{
    net::{Shutdown, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tonic::{
    Request, Response, Status,
    transport::{Channel, Endpoint, server::TcpIncoming},
};
use tonic_tls::TlsAcceptor;
use tonic_tls_xds::{
    CertificateData, CertificateProvider, ClientAuth, FileWatcherConfig, FileWatcherProvider,
    Identity, ReloadableTlsAcceptor, ServerConfig as ManagedConfig, TlsAcceptorFactory,
};

#[derive(Clone)]
struct CountingServerFactory<F> {
    inner: F,
    builds: Arc<AtomicUsize>,
}

impl<IO, F> TlsAcceptorFactory<IO> for CountingServerFactory<F>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: TlsAcceptorFactory<IO>,
{
    type Acceptor = F::Acceptor;

    fn build_acceptor(&self, data: &CertificateData) -> Result<Self::Acceptor, tonic_tls::Error> {
        self.builds.fetch_add(1, Ordering::Relaxed);
        self.inner.build_acceptor(data)
    }
}

fn crypto() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn acceptor<B, IO>(
    provider: Arc<dyn CertificateProvider>,
    base: ManagedConfig,
) -> (
    ReloadableTlsAcceptor<IO, CountingServerFactory<B::ServerFactory>>,
    Arc<AtomicUsize>,
)
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    B: TestServerBackend,
    B::ServerFactory: TlsAcceptorFactory<IO, Acceptor = B::Acceptor>,
{
    let builds = Arc::new(AtomicUsize::new(0));
    let factory = CountingServerFactory {
        inner: B::server_factory(base),
        builds: builds.clone(),
    };
    (
        ReloadableTlsAcceptor::new(provider, factory).unwrap(),
        builds,
    )
}

fn chain_identity(chain: &[&rcgen::Certificate], key: &KeyPair) -> Identity {
    Identity::from_pem(
        chain.iter().map(|cert| cert.pem()).collect::<String>(),
        key.serialize_pem(),
    )
}

fn client_config(
    roots: &[&rcgen::Certificate],
    chain: &[&rcgen::Certificate],
    key: &KeyPair,
) -> Arc<ClientConfig> {
    Arc::new(
        tonic_tls_xds::rustls::build_client_config(
            &base_config(roots),
            &CertificateData::new(None, Some(chain_identity(chain, key)), None).unwrap(),
        )
        .unwrap(),
    )
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

async fn identities_and_client_roots_are_complete_overlays_on_original_base<
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

async fn client_crl_rotation_rejects_revocation_and_recovers<B: TestServerBackend>() {
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

struct ServerPeerGreeter<B> {
    clients: Vec<CertificateDer<'static>>,
    backend: std::marker::PhantomData<B>,
}

#[tonic::async_trait]
impl<B: TestServerBackend> helloworld::greeter_server::Greeter for ServerPeerGreeter<B> {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        let leaf = B::peer_leaf(&request)?;
        let index = self
            .clients
            .iter()
            .position(|cert| cert == &leaf)
            .ok_or_else(|| Status::unauthenticated("unexpected client certificate"))?;
        Ok(Response::new(HelloReply {
            message: index.to_string(),
        }))
    }
}

async fn start_reloadable_server<B: TestServerBackend>(
    provider: Arc<dyn CertificateProvider>,
    base: ManagedConfig,
    clients: &[&rcgen::Certificate],
    first_connection: Option<oneshot::Sender<TcpStream>>,
) -> (
    Endpoint,
    CancellationToken,
    tokio::task::JoinHandle<()>,
    Arc<AtomicUsize>,
) {
    let (listener, addr) = create_listener_server().await;
    let (acceptor, builds) = acceptor::<B, _>(provider, base);
    let incoming = acceptor.incoming(TestIncoming {
        inner: TcpIncoming::from(listener),
        first_connection,
    });
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let greeter = ServerPeerGreeter::<B> {
        clients: clients.iter().map(|cert| cert.der().clone()).collect(),
        backend: std::marker::PhantomData,
    };
    let task = tokio::spawn(async move {
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
    (endpoint, shutdown, task, builds)
}

async fn connect(
    endpoint: &Endpoint,
    config: Arc<ClientConfig>,
) -> Result<helloworld::greeter_client::GreeterClient<Channel>, tonic_tls::Error> {
    let transport = tonic_tls::TcpTransport::from_endpoint(endpoint);
    let connector =
        tonic_tls::rustls::TlsConnector::new(transport, config, "localhost".try_into().unwrap());
    let channel = endpoint.connect_with_connector(connector).await?;
    Ok(helloworld::greeter_client::GreeterClient::new(channel))
}

async fn stop_server(shutdown: CancellationToken, task: tokio::task::JoinHandle<()>) {
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("server did not stop")
        .unwrap();
}

async fn tonic_incoming_rotates_recovers_and_preserves_peer_info_on_reconnect<
    B: TestServerBackend,
>() {
    let (first, key1) = make_test_cert(vec!["localhost".into()]);
    let (second, key2) = make_test_cert(vec!["localhost".into()]);
    let (client, client_key) = make_test_cert(vec!["client".into()]);
    let provider = TestProvider::new(
        CertificateData::new(
            Some(client.pem().into_bytes()),
            Some(identity(&first, &key1)),
            None,
        )
        .unwrap(),
    );
    let base = ManagedConfig::default().with_client_auth(ClientAuth::Required);
    let (first_tx, first_rx) = oneshot::channel();
    let (endpoint, shutdown, task, builds) =
        start_reloadable_server::<B>(provider.clone(), base, &[&client], Some(first_tx)).await;
    let config = client_config(&[&first, &second], &[&client], &client_key);
    let mut existing = connect(&endpoint, config.clone()).await.unwrap();
    assert_eq!(peer_identity(&mut existing).await.unwrap(), "0");
    let socket = tokio::time::timeout(Duration::from_secs(5), first_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(builds.load(Ordering::Relaxed), 1);

    provider.data.store(Arc::new(
        CertificateData::new(
            Some(client.pem().into_bytes()),
            Some(identity(&second, &key2)),
            None,
        )
        .unwrap(),
    ));
    assert_eq!(peer_identity(&mut existing).await.unwrap(), "0");
    let mut fresh = connect(
        &endpoint,
        client_config(&[&second], &[&client], &client_key),
    )
    .await
    .unwrap();
    assert_eq!(peer_identity(&mut fresh).await.unwrap(), "0");
    assert!(
        connect(&endpoint, client_config(&[&first], &[&client], &client_key))
            .await
            .is_err()
    );
    assert_eq!(builds.load(Ordering::Relaxed), 2);

    socket.shutdown(Shutdown::Both).unwrap();
    await_peer_identity(&mut existing, "0").await;
    for data in [
        CertificateData::new(
            Some(client.pem().into_bytes()),
            Some(Identity::from_pem(b"invalid cert", b"invalid key")),
            None,
        )
        .unwrap(),
        CertificateData::new(
            Some(client.pem().into_bytes()),
            Some(identity(&second, &key2)),
            Some(vec![b"bad CRL".to_vec()]),
        )
        .unwrap(),
    ] {
        provider.data.store(Arc::new(data));
        assert!(connect(&endpoint, config.clone()).await.is_err());
        assert_eq!(peer_identity(&mut existing).await.unwrap(), "0");
    }
    provider.fail.store(true, Ordering::Relaxed);
    assert!(connect(&endpoint, config.clone()).await.is_err());
    provider.fail.store(false, Ordering::Relaxed);
    provider.data.store(Arc::new(
        CertificateData::new(
            Some(client.pem().into_bytes()),
            Some(identity(&second, &key2)),
            None,
        )
        .unwrap(),
    ));
    let mut recovered = connect(&endpoint, config).await.unwrap();
    assert_eq!(peer_identity(&mut recovered).await.unwrap(), "0");
    drop((existing, fresh, recovered));
    stop_server(shutdown, task).await;
}

async fn file_watcher_rotates_server_identity_without_restarting_listener<B: TestServerBackend>() {
    let (first, key1) = make_test_cert(vec!["localhost".into()]);
    let (second, key2) = make_test_cert(vec!["localhost".into()]);
    let (client, client_key) = make_test_cert(vec!["client".into()]);
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("server.pem");
    let key_path = dir.path().join("server.key");
    tokio::fs::write(&cert_path, first.pem()).await.unwrap();
    tokio::fs::write(&key_path, key1.serialize_pem())
        .await
        .unwrap();
    let provider = Arc::new(
        FileWatcherProvider::new(
            FileWatcherConfig::default()
                .with_identity_files(&cert_path, &key_path)
                .with_refresh_interval(Duration::from_millis(10)),
        )
        .await
        .unwrap(),
    );
    let base = ManagedConfig::default()
        .with_ca_certificates(client.pem())
        .with_client_auth(ClientAuth::Required);
    let (endpoint, shutdown, task, builds) =
        start_reloadable_server::<B>(provider.clone(), base, &[&client], None).await;
    let mut existing = connect(&endpoint, client_config(&[&first], &[&client], &client_key))
        .await
        .unwrap();
    assert_eq!(peer_identity(&mut existing).await.unwrap(), "0");
    tokio::fs::write(&cert_path, second.pem()).await.unwrap();
    tokio::fs::write(&key_path, key2.serialize_pem())
        .await
        .unwrap();
    wait_for_snapshot(provider.as_ref(), "new server identity", |data| {
        data.identity().is_some_and(|identity| {
            identity.cert_chain() == second.pem().as_bytes()
                && identity.key() == key2.serialize_pem().as_bytes()
        })
    })
    .await;
    let mut fresh = connect(
        &endpoint,
        client_config(&[&second], &[&client], &client_key),
    )
    .await
    .unwrap();
    assert_eq!(peer_identity(&mut fresh).await.unwrap(), "0");
    assert_eq!(peer_identity(&mut existing).await.unwrap(), "0");
    assert_eq!(builds.load(Ordering::Relaxed), 2);
    drop((existing, fresh));
    stop_server(shutdown, task).await;
}

#[derive(Clone)]
struct NativeAcceptor(tokio_rustls::TlsAcceptor);

impl TlsAcceptor<DuplexStream> for NativeAcceptor {
    type TlsStream = tonic_tls::rustls::TlsStream<DuplexStream>;

    async fn accept(&self, io: DuplexStream) -> Result<Self::TlsStream, tonic_tls::Error> {
        Ok(tonic_tls::rustls::TlsStream::new(self.0.accept(io).await?))
    }
}

async fn tls12_and_tls13_full_handshakes_are_enforced_before_and_after_rotation<
    B: TestServerBackend,
>() {
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

async fn client_ca_hints_follow_selected_snapshot_and_original_base<B: TestServerBackend>() {
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

macro_rules! server_rotation_tests {
    ($module:ident, $backend:ty) => {
        mod $module {
            use super::*;

            #[tokio::test]
            async fn identity_and_client_roots_rotate() {
                identities_and_client_roots_are_complete_overlays_on_original_base::<$backend>()
                    .await;
            }

            #[tokio::test]
            async fn client_crls_rotate_and_recover() {
                client_crl_rotation_rejects_revocation_and_recovers::<$backend>().await;
            }

            #[tokio::test]
            async fn tonic_reconnect_and_failure_recovery() {
                tonic_incoming_rotates_recovers_and_preserves_peer_info_on_reconnect::<$backend>()
                    .await;
            }

            #[tokio::test]
            async fn file_watcher_rotates_identity() {
                file_watcher_rotates_server_identity_without_restarting_listener::<$backend>()
                    .await;
            }

            #[tokio::test]
            async fn full_handshakes_before_and_after_rotation() {
                tls12_and_tls13_full_handshakes_are_enforced_before_and_after_rotation::<$backend>(
                )
                .await;
            }

            #[tokio::test]
            async fn client_ca_hints_rotate() {
                client_ca_hints_follow_selected_snapshot_and_original_base::<$backend>().await;
            }
        }
    };
}

server_rotation_tests!(rustls_servers, Rustls);
server_rotation_tests!(openssl_servers, OpenSsl);
