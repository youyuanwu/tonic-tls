//! Configured TLS connectors for upstream `tonic-xds`.
//!
//! Pass a `tonic-tls` connector or [`crate::ReloadableTlsConnector`] to
//! [`ConfiguredMakeConnector::new`], then use
//! [`tonic_xds::XdsChannelBuilder::build_grpc_channel_with_connector`]. This
//! returns upstream's standard gRPC channel and preserves its gRPC behavior.
//! Applications do not need to implement upstream connector traits.
//!
//! The application must explicitly configure TLS and select certificate
//! providers for the registered cluster. This module does not interpret CDS
//! security policy or enable upstream TLS. Keep ADS bootstrap credentials
//! `insecure`; control-plane TLS is outside this integration.
//!
//! # Explicit rustls policy
//!
//! Build and validate the reloadable connector during application setup, before
//! passing it to the factory. Clones retain its cache,
//! so tonic reconnects use current credentials without another CDS update.
//! The policy in this example is application-owned; it does not interpret or
//! enforce security settings advertised in CDS.
//!
//! ```no_run
//! # #[cfg(feature = "rustls")]
//! # fn channel(
//! #     ads_server: &str,
//! #     provider: std::sync::Arc<dyn tonic_tls_xds::CertificateProvider>,
//! #     mut tls: tokio_rustls::rustls::ClientConfig,
//! # ) -> Result<tonic_xds::XdsChannelGrpc, tonic_tls::Error> {
//! use std::sync::Arc;
//! use tonic::transport::Endpoint;
//! use tonic_tls::TcpTransport;
//! use tonic_tls_xds::{ReloadableTlsConnector, xds::ConfiguredMakeConnector};
//! use tonic_xds::{
//!     BootstrapConfig, ChannelCredentialType, XdsChannelBuilder, XdsChannelConfig, XdsUri,
//! };
//!
//! tls.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];
//! let template = Endpoint::from_static("http://service.example:443");
//! let connector = ReloadableTlsConnector::new(
//!     TcpTransport::from_endpoint(&template),
//!     provider,
//!     tonic_tls_xds::rustls::TlsConnectorFactory::new(
//!         Arc::new(tls), "service.example".try_into()?,
//!     ),
//! )?;
//! let bootstrap = BootstrapConfig::builder(ads_server)
//!     .channel_creds([ChannelCredentialType::Insecure])
//!     .node_id("my-node")
//!     .build()?;
//! let config = XdsChannelConfig::new(XdsUri::parse("xds:///my-service")?)
//!     .with_bootstrap(bootstrap);
//! let factory = ConfiguredMakeConnector::new("my-cluster", connector);
//! let channel = XdsChannelBuilder::new(config)
//!     .build_grpc_channel_with_connector(factory)?;
//! // Pass `channel` to your generated tonic client.
//! # Ok(channel)
//! # }
//! ```

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
