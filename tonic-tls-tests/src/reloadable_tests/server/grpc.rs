use super::super::support::{
    TestProvider,
    backend::TestServerBackend,
    grpc::{await_peer_identity, peer_identity},
    wait_for_snapshot,
};
use super::{acceptor, client_config};
use crate::{
    helloworld::{self, HelloReply, HelloRequest},
    test_support::{certs::identity, grpc::TestIncoming},
    tests::{create_listener_server, make_test_cert},
};
use rustls::{ClientConfig, pki_types::CertificateDer};
use std::{
    net::{Shutdown, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tonic::{
    Request, Response, Status,
    transport::{Channel, Endpoint, server::TcpIncoming},
};
use tonic_tls_xds::{
    CertificateData, CertificateProvider, ClientAuth, FileWatcherConfig, FileWatcherProvider,
    Identity, ServerConfig as ManagedConfig,
};

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

pub(super) async fn tonic_incoming_rotates_recovers_and_preserves_peer_info_on_reconnect<
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

pub(super) async fn file_watcher_rotates_server_identity_without_restarting_listener<
    B: TestServerBackend,
>() {
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
