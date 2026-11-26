use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::net::TcpStream;
use tonic::transport::{Endpoint, Uri};
use tonic_tls::{TcpTransport, Transport};
use tonic_tls_xds::xds::ConfiguredMakeConnector;
use tonic_xds::XdsChannelGrpc;

use super::support::{
    ads::{CLUSTER, start_control_plane},
    backend::{OpenSsl, Rustls, TestBackend},
};
use crate::{
    helloworld::{HelloRequest, greeter_client::GreeterClient},
    test_support::grpc::{start_named_server, start_server_for},
    tests::make_test_cert,
};

#[derive(Clone)]
struct CountingTransport {
    inner: TcpTransport,
    attempts: Arc<AtomicUsize>,
}

impl Transport for CountingTransport {
    type Io = TcpStream;
    type Error = std::io::Error;

    async fn connect(&self, uri: &Uri) -> Result<Self::Io, Self::Error> {
        assert_eq!(uri.scheme_str(), Some("http"));
        self.attempts.fetch_add(1, Ordering::Relaxed);
        self.inner.connect(uri).await
    }
}

type Client = GreeterClient<XdsChannelGrpc>;

async fn peer(client: &mut Client) -> Result<String, tonic::Status> {
    let mut request = tonic::Request::new(HelloRequest {
        name: "xds-connector".into(),
    });
    request.set_timeout(Duration::from_secs(5));
    Ok(client.say_hello(request).await?.into_inner().message)
}

async fn uses_configured_tls_connector<B: TestBackend>() {
    let (server, server_key) = make_test_cert(vec!["localhost".into()]);
    let (client_cert, client_key) = make_test_cert(vec!["client".into()]);
    let (endpoint, shutdown, server_task) =
        start_server_for::<B>(&server, &server_key, &[&client_cert], None).await;
    let address: SocketAddr = endpoint
        .uri()
        .authority()
        .unwrap()
        .as_str()
        .parse()
        .unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let factory = ConfiguredMakeConnector::new(
        CLUSTER,
        B::connector(
            CountingTransport {
                inner: TcpTransport::from_endpoint(&endpoint),
                attempts: attempts.clone(),
            },
            &[&server],
            Some((&client_cert, &client_key)),
        ),
    );
    let (builder, _updates, ads_shutdown, ads_task) = start_control_plane::<B>(address).await;
    let mut client = Client::new(builder.build_grpc_channel_with_connector(factory).unwrap());
    assert_eq!(peer(&mut client).await.unwrap(), "0");
    assert_eq!(attempts.load(Ordering::Relaxed), 1);

    drop(client);
    shutdown.cancel();
    ads_shutdown.cancel();
    server_task.await.unwrap();
    ads_task.await.unwrap();
}

async fn switches_endpoints_after_eds_update<B: TestBackend>() {
    let (server, server_key) = make_test_cert(vec!["localhost".into()]);
    let (client_cert, client_key) = make_test_cert(vec!["client".into()]);
    let (endpoint_a, shutdown_a, task_a) =
        start_named_server::<B>(&server, &server_key, &[&client_cert], "A").await;
    let (endpoint_b, shutdown_b, task_b) =
        start_named_server::<B>(&server, &server_key, &[&client_cert], "B").await;
    let [address_a, address_b] = [&endpoint_a, &endpoint_b].map(|endpoint| {
        endpoint
            .uri()
            .authority()
            .unwrap()
            .as_str()
            .parse::<SocketAddr>()
            .unwrap()
    });
    let attempts = Arc::new(AtomicUsize::new(0));
    let connector = B::connector(
        CountingTransport {
            inner: TcpTransport::from_endpoint(&endpoint_a),
            attempts: attempts.clone(),
        },
        &[&server],
        Some((&client_cert, &client_key)),
    );
    let (builder, updates, ads_shutdown, ads_task) = start_control_plane::<B>(address_a).await;
    let mut client = Client::new(
        builder
            .build_grpc_channel_with_connector(ConfiguredMakeConnector::new(
                CLUSTER,
                connector.clone(),
            ))
            .unwrap(),
    );
    assert_eq!(peer(&mut client).await.unwrap(), "A");
    assert_eq!(attempts.load(Ordering::Relaxed), 1);

    updates.update_endpoints([address_b]);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match peer(&mut client)
                .await
                .expect("RPC failed during EDS update")
                .as_str()
            {
                "B" => break,
                "A" => tokio::task::yield_now().await,
                reply => panic!("unexpected server reply: {reply}"),
            }
        }
    })
    .await
    .expect("the same xDS channel must switch from A to B after the EDS update");
    for _ in 0..5 {
        assert_eq!(peer(&mut client).await.unwrap(), "B");
    }
    assert_eq!(attempts.load(Ordering::Relaxed), 2);

    // A remains responsive; the switch must be caused by EDS, not an outage.
    let direct = Endpoint::from_shared(format!("http://{address_a}"))
        .unwrap()
        .origin(endpoint_a.uri().clone())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .connect_with_connector(connector)
        .await
        .unwrap();
    let mut direct_a = GreeterClient::new(direct);
    assert_eq!(
        direct_a
            .say_hello(HelloRequest {
                name: "health".into()
            })
            .await
            .unwrap()
            .into_inner()
            .message,
        "A",
    );

    drop(direct_a);
    drop(client);
    shutdown_a.cancel();
    shutdown_b.cancel();
    ads_shutdown.cancel();
    task_a.await.unwrap();
    task_b.await.unwrap();
    ads_task.await.unwrap();
}

async fn rejects_unregistered_clusters_before_connecting<B: TestBackend>() {
    use tonic_xds::{ClusterConfig, Connector, EndpointChannel, MakeConnector};

    struct ObserveRejection {
        factory: ConfiguredMakeConnector,
        errors: tokio::sync::mpsc::UnboundedSender<String>,
    }

    impl MakeConnector for ObserveRejection {
        type Service = EndpointChannel<tonic::transport::Channel>;

        fn make_connector(
            &self,
            cluster: ClusterConfig<'_>,
        ) -> Result<Arc<dyn Connector<Service = Self::Service> + Send + Sync>, tower::BoxError>
        {
            let result = self.factory.make_connector(cluster);
            if let Err(error) = &result {
                assert_eq!(
                    error.downcast_ref::<std::io::Error>().unwrap().kind(),
                    std::io::ErrorKind::InvalidInput,
                );
                self.errors.send(error.to_string()).unwrap();
            }
            result
        }
    }

    let (_listener, address) = crate::tests::create_listener_server().await;
    let endpoint = Endpoint::from_shared(format!("http://{address}")).unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let connector = B::connector(
        CountingTransport {
            inner: TcpTransport::from_endpoint(&endpoint),
            attempts: attempts.clone(),
        },
        &[],
        None,
    );
    let (builder, _updates, shutdown, task) = start_control_plane::<B>(address).await;
    let (errors_tx, mut errors_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut client = Client::new(
        builder
            .build_grpc_channel_with_connector(ObserveRejection {
                factory: ConfiguredMakeConnector::new("other-cluster", connector),
                errors: errors_tx,
            })
            .unwrap(),
    );
    let error = {
        let request = peer(&mut client);
        tokio::pin!(request);
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::select! {
                biased;
                error = errors_rx.recv() => error.expect("expected a cluster selection error"),
                result = &mut request => panic!("request completed before cluster rejection: {result:?}"),
            }
        })
        .await
        .expect("the factory must reject the discovered, unregistered cluster")
    };
    assert_eq!(
        error,
        format!("no configured connector for cluster '{CLUSTER}'")
    );
    assert_eq!(attempts.load(Ordering::Relaxed), 0);
    drop(client);
    shutdown.cancel();
    task.await.unwrap();
}

macro_rules! xds_tests {
    ($module:ident, $backend:ty) => {
        mod $module {
            use super::*;

            #[tokio::test]
            async fn uses_configured_tls_connector() {
                super::uses_configured_tls_connector::<$backend>().await;
            }

            #[tokio::test]
            async fn switches_endpoints_after_eds_update() {
                super::switches_endpoints_after_eds_update::<$backend>().await;
            }

            #[tokio::test]
            async fn rejects_unregistered_clusters_before_connecting() {
                super::rejects_unregistered_clusters_before_connecting::<$backend>().await;
            }
        }
    };
}

xds_tests!(rustls_xds, Rustls);
xds_tests!(openssl_xds, OpenSsl);
