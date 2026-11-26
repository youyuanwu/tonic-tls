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
//! security policy or enable upstream TLS. Use [`ConfiguredControlPlaneConnector`]
//! for independently configured control-plane TLS. Without that override, keep
//! ADS bootstrap credentials `insecure` to use upstream's plaintext transport.
//!
//! # Explicit rustls policies
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
//! #     ads_provider: std::sync::Arc<dyn tonic_tls_xds::CertificateProvider>,
//! #     mut ads_tls: tokio_rustls::rustls::ClientConfig,
//! # ) -> Result<tonic_xds::XdsChannelGrpc, tonic_tls::Error> {
//! use std::sync::Arc;
//! use tonic::transport::Endpoint;
//! use tonic_tls::TcpTransport;
//! use tonic_tls_xds::{
//!     ReloadableTlsConnector,
//!     xds::{ConfiguredControlPlaneConnector, ConfiguredMakeConnector},
//! };
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
//! ads_tls.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];
//! let ads_template = Endpoint::from_static("http://ads.example:443");
//! let ads_connector = ReloadableTlsConnector::new(
//!     TcpTransport::from_endpoint(&ads_template),
//!     ads_provider,
//!     tonic_tls_xds::rustls::TlsConnectorFactory::new(
//!         Arc::new(ads_tls), "ads.example".try_into()?,
//!     ),
//! )?;
//! let bootstrap = BootstrapConfig::builder(ads_server)
//!     .channel_creds([ChannelCredentialType::Tls])
//!     .node_id("my-node")
//!     .build()?;
//! let config = XdsChannelConfig::new(XdsUri::parse("xds:///my-service")?)
//!     .with_bootstrap(bootstrap);
//! let factory = ConfiguredMakeConnector::new("my-cluster", connector);
//! let channel = XdsChannelBuilder::new(config)
//!     .with_control_plane_connector(ConfiguredControlPlaneConnector::new(ads_connector))
//!     .build_grpc_channel_with_connector(factory)?;
//! // Pass `channel` to your generated tonic client.
//! # Ok(channel)
//! # }
//! ```

mod control_plane;
mod data_plane;

pub use control_plane::ConfiguredControlPlaneConnector;
pub use data_plane::ConfiguredMakeConnector;
