use std::{sync::Arc, time::Duration};

use tonic::transport::{Channel, Endpoint, Uri};
use tonic_xds::{ClusterConfig, Connector, EndpointChannel, MakeConnector, XdsEndpoint};
use tower::Service;

/// An upstream-compatible gRPC factory using an explicitly configured TLS connector.
///
/// Registers one cluster and implements [`MakeConnector`] without interpreting
/// CDS security policy. Other cluster names return an error. The endpoint service
/// is upstream's `EndpointChannel<Channel>`; use this factory with
/// [`tonic_xds::XdsChannelBuilder::build_grpc_channel_with_connector`].
///
/// The URI service must already perform TLS. The factory adds neither another
/// TLS layer nor a plaintext fallback. It connects to the endpoint's primary
/// address, matching upstream's default connector; alternate addresses and the
/// endpoint hostname are not used. Configure SNI and peer verification in the
/// supplied connector.
#[derive(Clone)]
pub struct ConfiguredMakeConnector {
    cluster: String,
    connector: Arc<dyn Connector<Service = EndpointChannel<Channel>> + Send + Sync>,
}

impl ConfiguredMakeConnector {
    /// Registers an already configured TLS URI service for one cluster.
    ///
    /// This does not open a connection or validate credentials. Construct and
    /// validate a [`crate::ReloadableTlsConnector`] before passing it here.
    /// Cloning the factory shares its connector; each endpoint channel gets a
    /// clone of the URI service, preserving that service's own sharing semantics.
    ///
    /// Endpoint channels connect lazily with upstream's liveness defaults:
    /// a 10-second connection timeout, 30-second HTTP/2 keepalive interval,
    /// 10-second keepalive timeout, and keepalive while idle. The internal
    /// connection URI is `http`, with an `https` request origin, so the URI service
    /// performs TLS exactly once even when tonic TLS features are also enabled.
    pub fn new<C>(cluster: impl Into<String>, connector: C) -> Self
    where
        C: Service<Uri> + Clone + Send + Sync + 'static,
        C::Response: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
        C::Future: Send + 'static,
        tonic_tls::Error: From<C::Error>,
    {
        Self {
            cluster: cluster.into(),
            connector: Arc::new(ConfiguredConnector(connector)),
        }
    }
}

impl MakeConnector for ConfiguredMakeConnector {
    type Service = EndpointChannel<Channel>;

    fn make_connector(
        &self,
        cluster: ClusterConfig<'_>,
    ) -> Result<Arc<dyn Connector<Service = Self::Service> + Send + Sync>, tonic_tls::Error> {
        if cluster.name() != self.cluster {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("no configured connector for cluster '{}'", cluster.name()),
            )
            .into());
        }
        Ok(self.connector.clone())
    }
}

struct ConfiguredConnector<C>(C);

impl<C> Connector for ConfiguredConnector<C>
where
    C: Service<Uri> + Clone + Send + Sync + 'static,
    C::Response: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    C::Future: Send + 'static,
    tonic_tls::Error: From<C::Error>,
{
    type Service = EndpointChannel<Channel>;

    fn connect(&self, endpoint: &XdsEndpoint) -> tonic_xds::BoxFuture<Self::Service> {
        let address = endpoint.address();
        // TODO: Return connection errors for malformed EDS addresses instead of
        // panicking discovery; test recovery after a corrected EDS update.
        let endpoint = Endpoint::from_shared(format!("http://{address}"))
            .expect("validated xDS address")
            .origin(
                format!("https://{address}")
                    .parse()
                    .expect("validated xDS address"),
            )
            .connect_timeout(Duration::from_secs(10))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
            .keep_alive_while_idle(true);
        let channel = endpoint.connect_with_connector_lazy(self.0.clone());
        Box::pin(async move { EndpointChannel::new(channel) })
    }
}
