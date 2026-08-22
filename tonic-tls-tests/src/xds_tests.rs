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

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_util::sync::CancellationToken;
use tonic::body::Body as TonicBody;
use tonic::transport::{Channel, Endpoint, server::TcpIncoming};
use tonic_xds::{
    BootstrapConfig, BoxFuture, ClusterConfig, Connector, EndpointAddress, EndpointChannel,
    MakeConnector, SharedBody, XdsChannelBuilder, XdsChannelConfig, XdsChannelGrpc, XdsUri,
};
use tower::{BoxError, Service};
use xds_test_util::{XdsTestControlPlaneService, config};

use crate::helloworld::{
    self, HelloReply, HelloRequest, greeter_client::GreeterClient, greeter_server::GreeterServer,
};

/// A self signed certificate, used both as a server identity and as the trust
/// anchor that validates it.
struct TestCert {
    cert_pem: String,
    key_pem: String,
}

impl TestCert {
    fn new(subject_alt_names: &[&str]) -> Self {
        let (cert, key) =
            crate::tests::make_test_cert(subject_alt_names.iter().map(|s| s.to_string()).collect());
        Self {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    fn cert_der(&self) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(self.cert_pem.as_bytes()).unwrap()
    }

    fn key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_slice(self.key_pem.as_bytes()).unwrap()
    }

    /// Server side tls config, with the `h2` alpn tonic needs.
    fn server_config(&self) -> Arc<rustls::ServerConfig> {
        crate::rustls_tests::create_rustls_acceptor(&self.cert_der(), &self.key_der())
    }

    /// Client side tls config trusting this certificate as a root.
    fn client_config(&self) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.cert_der()).unwrap();
        // Pin the ring provider so the tests do not depend on a process wide
        // default crypto provider being installed.
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

/// Serves a [`NamedGreeter`] behind a tonic-tls rustls acceptor.
async fn spawn_tls_greeter(name: &str, cert: &TestCert) -> BackgroundServer {
    let (listener, addr) = crate::tests::create_listener_server().await;
    let token = CancellationToken::new();
    let token_cp = token.clone();
    let incoming =
        tonic_tls::rustls::TlsIncoming::new(TcpIncoming::from(listener), cert.server_config());
    let greeter = NamedGreeter {
        name: name.to_string(),
    };
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(GreeterServer::new(greeter))
            .serve_with_incoming_shutdown(incoming, async move { token_cp.cancelled().await })
            .await
            .unwrap();
    });
    BackgroundServer { addr, token }
}

/// Serves a [`NamedGreeter`] over plaintext.
async fn spawn_plaintext_greeter(name: &str) -> BackgroundServer {
    let (listener, addr) = crate::tests::create_listener_server().await;
    let token = CancellationToken::new();
    let token_cp = token.clone();
    let greeter = NamedGreeter {
        name: name.to_string(),
    };
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(GreeterServer::new(greeter))
            .serve_with_incoming_shutdown(TcpIncoming::from(listener), async move {
                token_cp.cancelled().await
            })
            .await
            .unwrap();
    });
    BackgroundServer { addr, token }
}

/// Serves the fake ADS control plane behind a tonic-tls rustls acceptor.
///
/// [`XdsTestControlPlaneService::start`] only serves plaintext, so the service
/// is registered on a tonic server of our own here.
async fn spawn_tls_control_plane(
    cert: &TestCert,
) -> (XdsTestControlPlaneService, BackgroundServer) {
    use envoy_types::pb::envoy::service::discovery::v3::aggregated_discovery_service_server::AggregatedDiscoveryServiceServer;

    let service = XdsTestControlPlaneService::new();
    let (listener, addr) = crate::tests::create_listener_server().await;
    let token = CancellationToken::new();
    let token_cp = token.clone();
    let incoming =
        tonic_tls::rustls::TlsIncoming::new(TcpIncoming::from(listener), cert.server_config());
    let service_cp = service.clone();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(AggregatedDiscoveryServiceServer::new(service_cp))
            .serve_with_incoming_shutdown(incoming, async move { token_cp.cancelled().await })
            .await
            .unwrap();
    });
    (service, BackgroundServer { addr, token })
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

/// A bootstrap document pointing at a control plane on `addr`. `host` lets a
/// test use the dns name the control plane certificate is issued for.
fn bootstrap_json(host: &str, port: u16) -> String {
    format!(r#"{{"xds_servers":[{{"server_uri":"http://{host}:{port}"}}],"node":{{"id":"test"}}}}"#)
}

fn channel_builder(bootstrap_json: &str, listener: &str) -> XdsChannelBuilder {
    let bootstrap = BootstrapConfig::from_json(bootstrap_json).expect("parse bootstrap");
    let target = XdsUri::parse(&format!("xds:///{listener}")).expect("parse target");
    XdsChannelBuilder::new(XdsChannelConfig::new(target).with_bootstrap(bootstrap))
}

/// Builds the tonic-tls connector used for the ads stream to the control plane.
fn control_plane_connector(
    cert: &TestCert,
    port: u16,
) -> tonic_tls::rustls::TlsConnector<tokio::net::TcpStream> {
    let endpoint =
        Endpoint::from_shared(format!("http://localhost:{port}")).expect("control plane endpoint");
    tonic_tls::rustls::TlsConnector::new(
        tonic_tls::TcpTransport::from_endpoint(&endpoint),
        cert.client_config(),
        ServerName::try_from("localhost").unwrap(),
    )
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

/// A single xDS endpoint, dialed through a tonic-tls connector.
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

/// Connects every endpoint of a cluster through a tonic-tls rustls connector.
struct TonicTlsConnector {
    client_config: Arc<rustls::ClientConfig>,
    domain: ServerName<'static>,
}

impl Connector for TonicTlsConnector {
    type Service = EndpointChannel<TlsEndpoint>;

    fn connect(&self, addr: &EndpointAddress) -> BoxFuture<Self::Service> {
        // `EndpointAddress` displays as `host:port`, so this is always a valid uri.
        let endpoint = Endpoint::from_shared(format!("http://{addr}")).unwrap();
        let connector = tonic_tls::rustls::TlsConnector::new(
            tonic_tls::TcpTransport::from_endpoint(&endpoint),
            self.client_config.clone(),
            self.domain.clone(),
        );
        // Connect lazily: `Connector::connect` has no way to report a failure,
        // and the built in connector is lazy for the same reason.
        let channel = endpoint.connect_with_connector_lazy(connector);
        let svc = EndpointChannel::new(TlsEndpoint { channel });
        Box::pin(async move { svc })
    }
}

/// A [`MakeConnector`] that puts every cluster behind tonic-tls, using a fixed
/// client config supplied by the test.
struct TonicTlsMakeConnector {
    client_config: Arc<rustls::ClientConfig>,
    domain: ServerName<'static>,
}

impl TonicTlsMakeConnector {
    fn new(cert: &TestCert) -> Self {
        Self {
            client_config: cert.client_config(),
            domain: ServerName::try_from("localhost").unwrap(),
        }
    }
}

impl MakeConnector for TonicTlsMakeConnector {
    type Service = EndpointChannel<TlsEndpoint>;

    fn make_connector(
        &self,
        _cluster: ClusterConfig<'_>,
    ) -> Result<Arc<dyn Connector<Service = Self::Service> + Send + Sync>, BoxError> {
        Ok(Arc::new(TonicTlsConnector {
            client_config: self.client_config.clone(),
            domain: self.domain.clone(),
        }))
    }
}

/// The ads stream to the control plane runs over a tonic-tls connector, and the
/// discovered plaintext backend is reachable through the resulting channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xds_control_plane_over_tonic_tls() {
    let cert = TestCert::new(&["localhost"]);
    let backend = spawn_plaintext_greeter("backend").await;
    let (control_plane, cp_server) = spawn_tls_control_plane(&cert).await;
    set_xds_config(&control_plane, "my-service", "my-cluster", &[backend.addr]);

    // The control plane certificate is issued for "localhost", so the bootstrap
    // uri uses that name rather than the loopback ip.
    let bootstrap = bootstrap_json("localhost", cp_server.addr.port());
    let channel = channel_builder(&bootstrap, "my-service")
        .with_control_plane_connector(control_plane_connector(&cert, cp_server.addr.port()))
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

/// The connections to the discovered endpoints are made by a tonic-tls
/// connector plugged in as a custom [`MakeConnector`].
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xds_data_plane_over_tonic_tls() {
    let cert = TestCert::new(&["localhost"]);
    let backend = spawn_tls_greeter("backend", &cert).await;
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
        .build_transport_channel(TonicTlsMakeConnector::new(&cert))
        .expect("build xds transport channel");

    let mut client = GreeterClient::new(channel);
    assert_eq!(
        say_hello_until_prefix(&mut client, "backend:").await,
        "backend: Tonic"
    );
}

/// Load balancing still works when the endpoints are tonic-tls connections:
/// with several tls backends in one cluster, requests spread over all of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xds_data_plane_over_tonic_tls_load_balances() {
    const BACKENDS: usize = 3;
    const REQUESTS: usize = 60;

    let cert = TestCert::new(&["localhost"]);
    let mut backends = Vec::new();
    for i in 0..BACKENDS {
        backends.push(spawn_tls_greeter(&format!("backend-{i}"), &cert).await);
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
        .build_transport_channel(TonicTlsMakeConnector::new(&cert))
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

/// Both planes over tonic-tls at once, and traffic follows a route update the
/// control plane pushes down the tls ads stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xds_both_planes_over_tonic_tls_follow_route_update() {
    let cert = TestCert::new(&["localhost"]);
    let backend_a = spawn_tls_greeter("backend-a", &cert).await;
    let backend_b = spawn_tls_greeter("backend-b", &cert).await;
    let (control_plane, cp_server) = spawn_tls_control_plane(&cert).await;
    set_xds_config(&control_plane, "my-service", "cluster-a", &[backend_a.addr]);

    let bootstrap = bootstrap_json("localhost", cp_server.addr.port());
    let channel = channel_builder(&bootstrap, "my-service")
        .with_control_plane_connector(control_plane_connector(&cert, cp_server.addr.port()))
        .build_transport_channel(TonicTlsMakeConnector::new(&cert))
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
/// the tonic-tls handshake, so the failure surfaces as an rpc error rather than
/// as a successful call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xds_data_plane_rejects_untrusted_backend() {
    let trusted = TestCert::new(&["localhost"]);
    let untrusted = TestCert::new(&["localhost"]);
    let backend = spawn_tls_greeter("backend", &untrusted).await;
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
        .build_transport_channel(TonicTlsMakeConnector::new(&trusted))
        .expect("build xds transport channel");

    let mut client = GreeterClient::new(channel);
    for _ in 0..50 {
        let status = say_hello(&mut client)
            .await
            .expect_err("a handshake against an untrusted backend must not succeed");
        // Before xds resolution completes the call fails for other reasons, so
        // only the terminal state is asserted on.
        if status.message().contains("certificate") {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("never observed a certificate validation failure");
}
