use std::{collections::HashMap, net::SocketAddr, pin::Pin};

use super::backend::TestBackend;
use crate::tests::make_test_cert;
use envoy_types::pb::{
    envoy::{
        config::{
            cluster::v3::{
                Cluster,
                cluster::{ClusterDiscoveryType, DiscoveryType},
            },
            core::v3::{
                Address, SocketAddress, address::Address as AddressKind,
                socket_address::PortSpecifier,
            },
            endpoint::v3::{
                ClusterLoadAssignment, Endpoint, LbEndpoint, LocalityLbEndpoints,
                lb_endpoint::HostIdentifier,
            },
            listener::v3::{ApiListener, Listener},
            route::v3::{
                Route, RouteAction, RouteConfiguration, RouteMatch, VirtualHost, route::Action,
                route_action::ClusterSpecifier, route_match::PathSpecifier,
            },
        },
        extensions::filters::network::http_connection_manager::v3::{
            HttpConnectionManager, http_connection_manager::RouteSpecifier,
        },
        service::discovery::v3::{
            DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
            aggregated_discovery_service_server::{
                AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
            },
        },
    },
    google::protobuf::Any,
};
use futures::Stream;
use prost::{Message, Name};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tonic::{
    Request, Response, Status,
    transport::{Endpoint as TonicEndpoint, server::TcpIncoming},
};
use tonic_tls::TcpTransport;
use tonic_tls_xds::xds::ConfiguredControlPlaneConnector;
use tonic_xds::{
    BootstrapConfig, ChannelCredentialType, XdsChannelBuilder, XdsChannelConfig, XdsUri,
};

pub(in crate::xds_tests) const CLUSTER: &str = "explicit-tls";
const LISTENER: &str = "connector-test";

struct Ads {
    resources: HashMap<String, Any>,
    endpoints: watch::Sender<EndpointSnapshot>,
}

struct EndpointSnapshot {
    version: u64,
    resource: Any,
}

pub(in crate::xds_tests) struct EndpointUpdates(watch::Sender<EndpointSnapshot>);

impl EndpointUpdates {
    pub fn update_endpoints(&self, addresses: impl IntoIterator<Item = SocketAddr>) {
        let resource = endpoint_resource(addresses);
        self.0.send_modify(|snapshot| {
            snapshot.version += 1;
            snapshot.resource = resource;
        });
    }
}

fn resource<T: Message + Name>(message: T) -> Any {
    Any {
        type_url: T::type_url(),
        value: message.encode_to_vec(),
    }
}

fn endpoint_resource(addresses: impl IntoIterator<Item = SocketAddr>) -> Any {
    resource(ClusterLoadAssignment {
        cluster_name: CLUSTER.into(),
        endpoints: vec![LocalityLbEndpoints {
            lb_endpoints: addresses
                .into_iter()
                .map(|address| LbEndpoint {
                    host_identifier: Some(HostIdentifier::Endpoint(Endpoint {
                        address: Some(Address {
                            address: Some(AddressKind::SocketAddress(SocketAddress {
                                address: address.ip().to_string(),
                                port_specifier: Some(PortSpecifier::PortValue(
                                    address.port().into(),
                                )),
                                ..Default::default()
                            })),
                        }),
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }],
        ..Default::default()
    })
}

fn discovery_response(resource: Any, version: u64) -> DiscoveryResponse {
    DiscoveryResponse {
        version_info: version.to_string(),
        type_url: resource.type_url.clone(),
        resources: vec![resource],
        ..Default::default()
    }
}

impl Ads {
    fn new(address: SocketAddr) -> Self {
        let manager = HttpConnectionManager {
            route_specifier: Some(RouteSpecifier::RouteConfig(RouteConfiguration {
                name: "routes".into(),
                virtual_hosts: vec![VirtualHost {
                    name: "service".into(),
                    domains: vec!["*".into()],
                    routes: vec![Route {
                        r#match: Some(RouteMatch {
                            path_specifier: Some(PathSpecifier::Prefix("/".into())),
                            ..Default::default()
                        }),
                        action: Some(Action::Route(RouteAction {
                            cluster_specifier: Some(ClusterSpecifier::Cluster(CLUSTER.into())),
                            ..Default::default()
                        })),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            })),
            ..Default::default()
        };
        let listener = Listener {
            name: LISTENER.into(),
            api_listener: Some(ApiListener {
                api_listener: Some(resource(manager)),
            }),
            ..Default::default()
        };
        let cluster = Cluster {
            name: CLUSTER.into(),
            cluster_discovery_type: Some(ClusterDiscoveryType::Type(DiscoveryType::Eds as i32)),
            ..Default::default()
        };
        let (endpoints, _) = watch::channel(EndpointSnapshot {
            version: 1,
            resource: endpoint_resource([address]),
        });
        Self {
            resources: [resource(listener), resource(cluster)]
                .into_iter()
                .map(|resource| (resource.type_url.clone(), resource))
                .collect(),
            endpoints,
        }
    }
}

#[tonic::async_trait]
impl AggregatedDiscoveryService for Ads {
    type StreamAggregatedResourcesStream =
        Pin<Box<dyn Stream<Item = Result<DiscoveryResponse, Status>> + Send>>;

    async fn stream_aggregated_resources(
        &self,
        request: Request<tonic::Streaming<DiscoveryRequest>>,
    ) -> Result<Response<Self::StreamAggregatedResourcesStream>, Status> {
        let mut requests = request.into_inner();
        let resources = self.resources.clone();
        let mut endpoints = self.endpoints.subscribe();
        Ok(Response::new(Box::pin(async_stream::try_stream! {
            let endpoint_type = ClusterLoadAssignment::type_url();
            let mut subscribed = false;
            let mut nonce = 0_u64;
            enum Event {
                Request(Option<Box<DiscoveryRequest>>),
                EndpointsChanged,
            }
            loop {
                let event = tokio::select! {
                    request = requests.message() => request
                        .map(|request| Event::Request(request.map(Box::new))),
                    changed = endpoints.changed(), if subscribed => changed
                        .map(|()| Event::EndpointsChanged)
                        .map_err(|_| Status::unavailable("endpoint update source closed")),
                }?;
                let mut response = match event {
                    Event::Request(Some(request)) => {
                        if let Some(error) = request.error_detail {
                            Err(Status::invalid_argument(format!("xDS NACK: {error:?}")))?;
                        }
                        if request.type_url == endpoint_type {
                            if request.resource_names.is_empty() {
                                subscribed = false;
                                continue;
                            }
                            if request.resource_names.iter().any(|name| name != CLUSTER) {
                                Err(Status::invalid_argument("unexpected EDS resource name"))?;
                            }
                            let was_subscribed = subscribed;
                            subscribed = true;
                            if was_subscribed && !request.response_nonce.is_empty() {
                                continue;
                            }
                            let snapshot = endpoints.borrow_and_update();
                            discovery_response(snapshot.resource.clone(), snapshot.version)
                        } else {
                            if !request.response_nonce.is_empty() {
                                continue;
                            }
                            let resource = resources.get(&request.type_url)
                                .ok_or_else(|| Status::invalid_argument("unexpected resource subscription"))?;
                            discovery_response(resource.clone(), 1)
                        }
                    }
                    Event::Request(None) => break,
                    Event::EndpointsChanged => {
                        let snapshot = endpoints.borrow_and_update();
                        discovery_response(snapshot.resource.clone(), snapshot.version)
                    }
                };
                nonce += 1;
                response.nonce = nonce.to_string();
                yield response;
            }
        })))
    }

    type DeltaAggregatedResourcesStream =
        Pin<Box<dyn Stream<Item = Result<DeltaDiscoveryResponse, Status>> + Send>>;

    async fn delta_aggregated_resources(
        &self,
        _: Request<tonic::Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
        Err(Status::unimplemented(
            "test control plane supports SotW only",
        ))
    }
}

pub(in crate::xds_tests) async fn start_control_plane<B: TestBackend>(
    endpoint: SocketAddr,
) -> (
    XdsChannelBuilder,
    EndpointUpdates,
    CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    let (listener, address) = crate::tests::create_listener_server().await;
    let (cert, key) = make_test_cert(vec!["localhost".into()]);
    let incoming = B::incoming(TcpIncoming::from(listener), &cert, &key, None);
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let ads = Ads::new(endpoint);
    let updates = EndpointUpdates(ads.endpoints.clone());
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(AggregatedDiscoveryServiceServer::new(ads))
            .serve_with_incoming_shutdown(incoming, signal.cancelled_owned())
            .await
            .unwrap();
    });
    let bootstrap = BootstrapConfig::builder(format!("https://{address}"))
        .channel_creds([ChannelCredentialType::Tls])
        .node_id("connector-test")
        .build()
        .unwrap();
    let config = XdsChannelConfig::new(XdsUri::parse(&format!("xds:///{LISTENER}")).unwrap())
        .with_bootstrap(bootstrap);
    let template = TonicEndpoint::from_shared(format!("http://{address}")).unwrap();
    let connector = ConfiguredControlPlaneConnector::new(B::connector(
        TcpTransport::from_endpoint(&template),
        &[&cert],
        None,
    ));
    let builder = XdsChannelBuilder::new(config).with_control_plane_connector(connector);
    (builder, updates, shutdown, task)
}
