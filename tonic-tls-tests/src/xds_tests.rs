//! Interop tests between [`tonic_xds`] and `tonic-tls`.
//!
//! `tonic-xds` has two places where an application can supply its own
//! transport, and these tests check that a `tonic-tls` connector fits both:
//!
//! * the **control plane** — the ADS connection to the xDS management server,
//!   supplied through [`XdsChannelBuilder::with_control_plane_connector`].
//! * the **data plane** — the connections to the endpoints discovered through
//!   EDS, supplied through [`XdsChannelBuilder::build_transport_channel`] with
//!   a custom [`MakeConnector`].
//!
//! Every scenario is written once against the [`TlsBackend`] trait and then run
//! for each tls backend, in the `rustls` and `openssl` modules at the bottom of
//! this file. `tonic-xds` itself is built without its tls features: all tls, on
//! both the server and the client side, comes from `tonic-tls`.
//!
//! # Uri scheme
//!
//! All endpoint uris here use the `http` scheme even though every connection is
//! tls, because the connector, not tonic, terminates tls. When tonic itself is
//! built with a tls feature (which `tonic-xds` turns on with its `tls-ring` /
//! `tls-aws-lc` features) tonic rejects an `https` uri that has no
//! `ClientTlsConfig` on the endpoint, regardless of the custom connector. Using
//! `http` keeps these tests working in both configurations.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::Stream;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tonic::body::Body as TonicBody;
use tonic::transport::server::{Connected, Router, TcpIncoming};
use tonic::transport::{Channel, Endpoint, Uri};
use tonic_xds::{
    BootstrapConfig, BoxFuture, ClusterConfig, Connector, EndpointAddress, EndpointChannel,
    MakeConnector, SharedBody, XdsChannelBuilder, XdsChannelConfig, XdsChannelGrpc, XdsUri,
};
use tower::{BoxError, Service};
use xds_test_util::{XdsTestControlPlaneService, config};

use crate::helloworld::{
    self, HelloReply, HelloRequest, greeter_client::GreeterClient, greeter_server::GreeterServer,
};

/// A `tonic-tls` backend under test: how to make a certificate, how to accept
/// connections with it, and how to connect to them.
///
/// Every scenario below is generic over this trait, so each one runs unchanged
/// on every backend.
trait TlsBackend: Send + Sync + 'static {
    /// A certificate and its key, used both as the server identity and as the
    /// trust anchor a client validates it against.
    type Cert: Send + Sync + 'static;
    /// The accepted tls stream.
    type Io: AsyncRead
        + AsyncWrite
        + Connected<ConnectInfo: Clone + Send + Sync + 'static>
        + Unpin
        + Send
        + 'static;
    /// The `tonic-tls` incoming stream, e.g. [`tonic_tls::rustls::TlsIncoming`].
    type Incoming: Stream<Item = Result<Self::Io, tonic_tls::Error>> + Send + 'static;
    /// The `tonic-tls` connector, e.g. [`tonic_tls::rustls::TlsConnector`].
    type Connector: Service<
            Uri,
            Response: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
            Error = tonic_tls::Error,
            Future: Send + 'static,
        > + Clone
        + Send
        + Sync
        + 'static;

    /// Generates a self signed certificate valid for `subject_alt_names`.
    fn make_cert(subject_alt_names: &[&str]) -> Self::Cert;

    /// Wraps a tcp listener into a tls incoming stream serving `cert`.
    fn incoming(listener: TcpIncoming, cert: &Self::Cert) -> Self::Incoming;

    /// Builds a connector for `endpoint` that trusts `cert` and validates the
    /// server name `localhost`.
    fn connector(cert: &Self::Cert, endpoint: &Endpoint) -> Self::Connector;
}

/// A greeter that tags its replies with its own name, so a test can tell which
/// backend served a request.
struct NamedGreeter {
    name: String,
}

#[tonic::async_trait]
impl helloworld::greeter_server::Greeter for NamedGreeter {
    async fn say_hello(
        &self,
        request: tonic::Request<HelloRequest>,
    ) -> Result<tonic::Response<HelloReply>, tonic::Status> {
        Ok(tonic::Response::new(HelloReply {
            message: format!("{}: {}", self.name, request.into_inner().name),
        }))
    }
}

/// A server running in a background task, stopped when this handle is dropped.
struct BackgroundServer {
    addr: SocketAddr,
    token: CancellationToken,
}

impl Drop for BackgroundServer {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

/// Serves `router` on `incoming` until the returned handle is dropped.
fn spawn_server<I, IO>(router: Router, incoming: I, addr: SocketAddr) -> BackgroundServer
where
    I: Stream<Item = Result<IO, tonic_tls::Error>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static,
    IO::ConnectInfo: Clone + Send + Sync + 'static,
{
    let token = CancellationToken::new();
    let token_cp = token.clone();
    tokio::spawn(async move {
        router
            .serve_with_incoming_shutdown(incoming, async move { token_cp.cancelled().await })
            .await
            .unwrap();
    });
    BackgroundServer { addr, token }
}

fn greeter_router(name: &str) -> Router {
    let greeter = NamedGreeter {
        name: name.to_string(),
    };
    tonic::transport::Server::builder().add_service(GreeterServer::new(greeter))
}

/// Serves a [`NamedGreeter`] behind a `tonic-tls` acceptor.
async fn spawn_tls_greeter<B: TlsBackend>(name: &str, cert: &B::Cert) -> BackgroundServer {
    let (listener, addr) = crate::tests::create_listener_server().await;
    spawn_server(
        greeter_router(name),
        B::incoming(TcpIncoming::from(listener), cert),
        addr,
    )
}

/// Serves a [`NamedGreeter`] over plaintext.
async fn spawn_plaintext_greeter(name: &str) -> BackgroundServer {
    let (listener, addr) = crate::tests::create_listener_server().await;
    let incoming =
        futures::TryStreamExt::map_err(TcpIncoming::from(listener), tonic_tls::Error::from);
    spawn_server(greeter_router(name), incoming, addr)
}

/// Serves the fake ADS control plane behind a `tonic-tls` acceptor.
///
/// [`XdsTestControlPlaneService::start`] only serves plaintext, so the service
/// is registered on a tonic server of our own here.
async fn spawn_tls_control_plane<B: TlsBackend>(
    cert: &B::Cert,
) -> (XdsTestControlPlaneService, BackgroundServer) {
    use envoy_types::pb::envoy::service::discovery::v3::aggregated_discovery_service_server::AggregatedDiscoveryServiceServer;

    let service = XdsTestControlPlaneService::new();
    let (listener, addr) = crate::tests::create_listener_server().await;
    let router = tonic::transport::Server::builder()
        .add_service(AggregatedDiscoveryServiceServer::new(service.clone()));
    let server = spawn_server(router, B::incoming(TcpIncoming::from(listener), cert), addr);
    (service, server)
}

/// Points `listener` at a single cluster holding `endpoints`, through
/// LDS (with an inline route) -> CDS -> EDS.
fn set_xds_config(
    control_plane: &XdsTestControlPlaneService,
    listener: &str,
    cluster: &str,
    endpoints: &[SocketAddr],
) {
    control_plane.set_xds_config(
        &config::AdsTypeUrl::Lds,
        HashMap::from([(
            listener.to_string(),
            config::build_inline_listener(listener, cluster),
        )]),
    );
    control_plane.set_xds_config(
        &config::AdsTypeUrl::Cds,
        HashMap::from([(cluster.to_string(), config::build_cluster(cluster))]),
    );
    let endpoints = endpoints
        .iter()
        .map(|addr| (addr.ip().to_string(), addr.port()))
        .collect::<Vec<_>>();
    control_plane.set_xds_config(
        &config::AdsTypeUrl::Eds,
        HashMap::from([(cluster.to_string(), config::build_cla(cluster, &endpoints))]),
    );
}

/// A bootstrap document pointing at a control plane on `host:port`. `host` lets
/// a test use the dns name the control plane certificate is issued for.
fn bootstrap_json(host: &str, port: u16) -> String {
    format!(r#"{{"xds_servers":[{{"server_uri":"http://{host}:{port}"}}],"node":{{"id":"test"}}}}"#)
}

fn channel_builder(bootstrap_json: &str, listener: &str) -> XdsChannelBuilder {
    let bootstrap = BootstrapConfig::from_json(bootstrap_json).expect("parse bootstrap");
    let target = XdsUri::parse(&format!("xds:///{listener}")).expect("parse target");
    XdsChannelBuilder::new(XdsChannelConfig::new(target).with_bootstrap(bootstrap))
}

/// Builds the `tonic-tls` connector used for the ads stream to the control
/// plane. The certificates are issued for "localhost", so the uri uses that
/// name rather than the loopback ip.
fn control_plane_connector<B: TlsBackend>(cert: &B::Cert, port: u16) -> B::Connector {
    let endpoint =
        Endpoint::from_shared(format!("http://localhost:{port}")).expect("control plane endpoint");
    B::connector(cert, &endpoint)
}

/// xDS resolution is asynchronous, so retry until a reply from the expected
/// backend shows up.
async fn say_hello_until_prefix(
    client: &mut GreeterClient<XdsChannelGrpc>,
    prefix: &str,
) -> String {
    let mut last = None;
    for _ in 0..100 {
        match say_hello(client).await {
            Ok(message) => {
                if message.starts_with(prefix) {
                    return message;
                }
                last = Some(Ok(message));
            }
            Err(status) => last = Some(Err(status)),
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("no reply starting with {prefix:?}; last seen: {last:?}");
}

async fn say_hello(client: &mut GreeterClient<XdsChannelGrpc>) -> Result<String, tonic::Status> {
    let request = HelloRequest {
        name: "Tonic".to_string(),
    };
    // An xds channel can block until the first config arrives, so do not let a
    // misconfigured test hang the suite.
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), client.say_hello(request))
        .await
        .map_err(|_| tonic::Status::deadline_exceeded("say_hello timed out"))??;
    Ok(resp.into_inner().message)
}

/// A single xDS endpoint, dialed through a `tonic-tls` connector.
///
/// `tonic-xds` hands endpoint services the retry buffered [`SharedBody`], so the
/// request body is rewrapped into a [`TonicBody`] before it reaches the tonic
/// [`Channel`], exactly like the built in grpc endpoint does.
#[derive(Clone)]
struct TlsEndpoint {
    channel: Channel,
}

impl Service<http::Request<SharedBody<TonicBody>>> for TlsEndpoint {
    type Response = http::Response<TonicBody>;
    type Error = <Channel as Service<http::Request<TonicBody>>>::Error;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Service::<http::Request<TonicBody>>::poll_ready(&mut self.channel, cx)
    }

    fn call(&mut self, req: http::Request<SharedBody<TonicBody>>) -> Self::Future {
        Box::pin(self.channel.call(req.map(TonicBody::new)))
    }
}

/// Connects every endpoint of a cluster through a `tonic-tls` connector.
struct TonicTlsConnector<B: TlsBackend> {
    cert: Arc<B::Cert>,
}

impl<B: TlsBackend> Connector for TonicTlsConnector<B> {
    type Service = EndpointChannel<TlsEndpoint>;

    fn connect(&self, addr: &EndpointAddress) -> BoxFuture<Self::Service> {
        // `EndpointAddress` displays as `host:port`, so this is always a valid uri.
        let endpoint = Endpoint::from_shared(format!("http://{addr}")).unwrap();
        let connector = B::connector(&self.cert, &endpoint);
        // Connect lazily: `Connector::connect` has no way to report a failure,
        // and the built in connector is lazy for the same reason.
        let channel = endpoint.connect_with_connector_lazy(connector);
        let svc = EndpointChannel::new(TlsEndpoint { channel });
        Box::pin(async move { svc })
    }
}

/// A [`MakeConnector`] that puts every cluster behind `tonic-tls`, using a fixed
/// certificate supplied by the test.
struct TonicTlsMakeConnector<B: TlsBackend> {
    cert: Arc<B::Cert>,
}

impl<B: TlsBackend> MakeConnector for TonicTlsMakeConnector<B> {
    type Service = EndpointChannel<TlsEndpoint>;

    fn make_connector(
        &self,
        _cluster: ClusterConfig<'_>,
    ) -> Result<Arc<dyn Connector<Service = Self::Service> + Send + Sync>, BoxError> {
        Ok(Arc::new(TonicTlsConnector::<B> {
            cert: self.cert.clone(),
        }))
    }
}

fn make_connector<B: TlsBackend>(cert: &Arc<B::Cert>) -> TonicTlsMakeConnector<B> {
    TonicTlsMakeConnector { cert: cert.clone() }
}

/// The ads stream to the control plane runs over a `tonic-tls` connector, and
/// the discovered plaintext backend is reachable through the resulting channel.
async fn control_plane_over_tonic_tls<B: TlsBackend>() {
    let cert = B::make_cert(&["localhost"]);
    let backend = spawn_plaintext_greeter("backend").await;
    let (control_plane, cp_server) = spawn_tls_control_plane::<B>(&cert).await;
    set_xds_config(&control_plane, "my-service", "my-cluster", &[backend.addr]);

    let bootstrap = bootstrap_json("localhost", cp_server.addr.port());
    let channel = channel_builder(&bootstrap, "my-service")
        .with_control_plane_connector(control_plane_connector::<B>(&cert, cp_server.addr.port()))
        .build_grpc_channel()
        .expect("build xds channel");

    let mut client = GreeterClient::new(channel);
    assert_eq!(
        say_hello_until_prefix(&mut client, "backend:").await,
        "backend: Tonic"
    );

    // The client really did reach the control plane over tls.
    let counts = control_plane.get_subscriber_counts();
    assert_eq!(counts.get(&config::AdsTypeUrl::Lds), Some(&1));
    assert_eq!(counts.get(&config::AdsTypeUrl::Cds), Some(&1));
    assert_eq!(counts.get(&config::AdsTypeUrl::Eds), Some(&1));
}

/// The connections to the discovered endpoints are made by a `tonic-tls`
/// connector plugged in as a custom [`MakeConnector`].
async fn data_plane_over_tonic_tls<B: TlsBackend>() {
    let cert = Arc::new(B::make_cert(&["localhost"]));
    let backend = spawn_tls_greeter::<B>("backend", &cert).await;
    let control_plane = XdsTestControlPlaneService::new()
        .start()
        .await
        .expect("start control plane");
    set_xds_config(
        control_plane.get_service(),
        "my-service",
        "my-cluster",
        &[backend.addr],
    );

    let bootstrap = bootstrap_json(
        &control_plane.addr().ip().to_string(),
        control_plane.addr().port(),
    );
    let channel = channel_builder(&bootstrap, "my-service")
        .build_transport_channel(make_connector::<B>(&cert))
        .expect("build xds transport channel");

    let mut client = GreeterClient::new(channel);
    assert_eq!(
        say_hello_until_prefix(&mut client, "backend:").await,
        "backend: Tonic"
    );
}

/// Load balancing still works when the endpoints are `tonic-tls` connections:
/// with several tls backends in one cluster, requests spread over all of them.
async fn data_plane_over_tonic_tls_load_balances<B: TlsBackend>() {
    const BACKENDS: usize = 3;
    const REQUESTS: usize = 60;

    let cert = Arc::new(B::make_cert(&["localhost"]));
    let mut backends = Vec::new();
    for i in 0..BACKENDS {
        backends.push(spawn_tls_greeter::<B>(&format!("backend-{i}"), &cert).await);
    }
    let addrs = backends.iter().map(|b| b.addr).collect::<Vec<_>>();

    let control_plane = XdsTestControlPlaneService::new()
        .start()
        .await
        .expect("start control plane");
    set_xds_config(
        control_plane.get_service(),
        "my-service",
        "my-cluster",
        &addrs,
    );

    let bootstrap = bootstrap_json(
        &control_plane.addr().ip().to_string(),
        control_plane.addr().port(),
    );
    let channel = channel_builder(&bootstrap, "my-service")
        .build_transport_channel(make_connector::<B>(&cert))
        .expect("build xds transport channel");

    let mut client = GreeterClient::new(channel);
    say_hello_until_prefix(&mut client, "backend-").await;

    let mut seen: HashMap<String, usize> = HashMap::new();
    for _ in 0..REQUESTS {
        let message = say_hello(&mut client).await.expect("say_hello");
        let backend = message.split(':').next().unwrap().to_string();
        *seen.entry(backend).or_default() += 1;
    }
    assert_eq!(
        seen.len(),
        BACKENDS,
        "expected every tls backend to serve traffic, got {seen:?}"
    );
}

/// Both planes over `tonic-tls` at once, and traffic follows a route update the
/// control plane pushes down the tls ads stream.
async fn both_planes_over_tonic_tls_follow_route_update<B: TlsBackend>() {
    let cert = Arc::new(B::make_cert(&["localhost"]));
    let backend_a = spawn_tls_greeter::<B>("backend-a", &cert).await;
    let backend_b = spawn_tls_greeter::<B>("backend-b", &cert).await;
    let (control_plane, cp_server) = spawn_tls_control_plane::<B>(&cert).await;
    set_xds_config(&control_plane, "my-service", "cluster-a", &[backend_a.addr]);

    let bootstrap = bootstrap_json("localhost", cp_server.addr.port());
    let channel = channel_builder(&bootstrap, "my-service")
        .with_control_plane_connector(control_plane_connector::<B>(&cert, cp_server.addr.port()))
        .build_transport_channel(make_connector::<B>(&cert))
        .expect("build xds transport channel");

    let mut client = GreeterClient::new(channel);
    assert_eq!(
        say_hello_until_prefix(&mut client, "backend-a:").await,
        "backend-a: Tonic"
    );

    // Move the listener to a second cluster and check traffic follows.
    set_xds_config(&control_plane, "my-service", "cluster-b", &[backend_b.addr]);
    assert_eq!(
        say_hello_until_prefix(&mut client, "backend-b:").await,
        "backend-b: Tonic"
    );
}

/// A backend whose certificate the connector does not trust is rejected during
/// the `tonic-tls` handshake, so the failure surfaces as an rpc error rather
/// than as a successful call.
async fn data_plane_rejects_untrusted_backend<B: TlsBackend>() {
    let trusted = Arc::new(B::make_cert(&["localhost"]));
    let untrusted = B::make_cert(&["localhost"]);
    let backend = spawn_tls_greeter::<B>("backend", &untrusted).await;
    let control_plane = XdsTestControlPlaneService::new()
        .start()
        .await
        .expect("start control plane");
    set_xds_config(
        control_plane.get_service(),
        "my-service",
        "my-cluster",
        &[backend.addr],
    );

    let bootstrap = bootstrap_json(
        &control_plane.addr().ip().to_string(),
        control_plane.addr().port(),
    );
    let channel = channel_builder(&bootstrap, "my-service")
        .build_transport_channel(make_connector::<B>(&trusted))
        .expect("build xds transport channel");

    let mut client = GreeterClient::new(channel);
    let mut last = None;
    for _ in 0..50 {
        let status = say_hello(&mut client)
            .await
            .expect_err("a handshake against an untrusted backend must not succeed");
        // Before xds resolution completes the call fails for other reasons, so
        // only the terminal state is asserted on.
        if status.message().contains("certificate") {
            return;
        }
        last = Some(status);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("never observed a certificate validation failure; last seen: {last:?}");
}

/// Runs every scenario above against one tls backend.
macro_rules! xds_backend_tests {
    ($backend:ty) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn xds_control_plane_over_tonic_tls() {
            super::control_plane_over_tonic_tls::<$backend>().await
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn xds_data_plane_over_tonic_tls() {
            super::data_plane_over_tonic_tls::<$backend>().await
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn xds_data_plane_over_tonic_tls_load_balances() {
            super::data_plane_over_tonic_tls_load_balances::<$backend>().await
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn xds_both_planes_over_tonic_tls_follow_route_update() {
            super::both_planes_over_tonic_tls_follow_route_update::<$backend>().await
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn xds_data_plane_rejects_untrusted_backend() {
            super::data_plane_rejects_untrusted_backend::<$backend>().await
        }
    };
}

mod rustls_backend {
    use super::TlsBackend;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use std::sync::Arc;
    use tonic::transport::Endpoint;
    use tonic::transport::server::TcpIncoming;

    pub(super) struct RustlsCert {
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    }

    impl RustlsCert {
        /// Client side tls config trusting this certificate as a root.
        fn client_config(&self) -> Arc<rustls::ClientConfig> {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(self.cert.clone()).unwrap();
            // Pin the ring provider so the tests do not depend on a process
            // wide default crypto provider being installed.
            let mut config = rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            config.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];
            Arc::new(config)
        }
    }

    struct Rustls;

    impl TlsBackend for Rustls {
        type Cert = RustlsCert;
        type Io = tonic_tls::rustls::TlsStream<tokio::net::TcpStream>;
        type Incoming = tonic_tls::rustls::TlsIncoming<tokio::net::TcpStream>;
        type Connector = tonic_tls::rustls::TlsConnector<tokio::net::TcpStream>;

        fn make_cert(subject_alt_names: &[&str]) -> Self::Cert {
            let (cert, key) = crate::tests::make_test_cert(
                subject_alt_names.iter().map(|s| s.to_string()).collect(),
            );
            RustlsCert {
                cert: CertificateDer::from_pem_slice(cert.pem().as_bytes()).unwrap(),
                key: PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap(),
            }
        }

        fn incoming(listener: TcpIncoming, cert: &Self::Cert) -> Self::Incoming {
            let acceptor = crate::rustls_tests::create_rustls_acceptor(&cert.cert, &cert.key);
            tonic_tls::rustls::TlsIncoming::new(listener, acceptor)
        }

        fn connector(cert: &Self::Cert, endpoint: &Endpoint) -> Self::Connector {
            tonic_tls::rustls::TlsConnector::new(
                tonic_tls::TcpTransport::from_endpoint(endpoint),
                cert.client_config(),
                ServerName::try_from("localhost").unwrap(),
            )
        }
    }

    xds_backend_tests!(Rustls);
}

mod openssl_backend {
    use super::TlsBackend;
    use openssl::pkey::{PKey, Private};
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use openssl::x509::X509;
    use tonic::transport::Endpoint;
    use tonic::transport::server::TcpIncoming;

    pub(super) struct OpensslCert {
        cert: X509,
        key: PKey<Private>,
    }

    struct Openssl;

    impl TlsBackend for Openssl {
        type Cert = OpensslCert;
        type Io = tonic_tls::openssl::SslStream<tokio::net::TcpStream>;
        type Incoming = tonic_tls::openssl::TlsIncoming<tokio::net::TcpStream>;
        type Connector = tonic_tls::openssl::TlsConnector<tokio::net::TcpStream>;

        fn make_cert(subject_alt_names: &[&str]) -> Self::Cert {
            let (cert, key) = crate::tests::make_test_cert2(
                subject_alt_names.iter().map(|s| s.to_string()).collect(),
            );
            OpensslCert { cert, key }
        }

        fn incoming(listener: TcpIncoming, cert: &Self::Cert) -> Self::Incoming {
            let acceptor = crate::openssl_tests::create_openssl_acceptor(&cert.cert, &cert.key);
            tonic_tls::openssl::TlsIncoming::new(listener, acceptor)
        }

        fn connector(cert: &Self::Cert, endpoint: &Endpoint) -> Self::Connector {
            let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
            connector
                .cert_store_mut()
                .add_cert(cert.cert.clone())
                .unwrap();
            connector.set_verify(SslVerifyMode::PEER);
            connector
                .set_alpn_protos(tonic_tls::openssl::ALPN_H2_WIRE)
                .unwrap();
            tonic_tls::openssl::TlsConnector::new(
                tonic_tls::TcpTransport::from_endpoint(endpoint),
                connector.build(),
                "localhost".to_string(),
            )
        }
    }

    xds_backend_tests!(Openssl);
}
