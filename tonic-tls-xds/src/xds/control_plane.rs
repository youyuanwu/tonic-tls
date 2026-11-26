use std::time::Duration;

use tonic::transport::{Channel, Endpoint, Uri};
use tonic_xds::{BoxFuture, ControlPlaneConfig, ControlPlaneConnector, XdsError};
use tower::Service;

/// Connects upstream ADS using an independently configured TLS URI service.
///
/// Register this with [`tonic_xds::XdsChannelBuilder::with_control_plane_connector`]
/// or [`tonic_xds::XdsClientPoolBuilder::with_control_plane_connector`]. Data-plane
/// connectors are unaffected. No upstream TLS feature is required.
///
/// The supplied service must authenticate the management server and provide
/// confidentiality and integrity on every connection, without plaintext
/// fallback. Configure roots, client identity, SNI, and ALPN in that service.
/// Bootstrap must select TLS and use an HTTPS or scheme-less server address;
/// bootstrap certificate-file settings are not translated into TLS policy.
///
/// The data-plane factory and control-plane connector can use different
/// backends, credentials, and server names. The [`crate::xds`] module example
/// shows independently configured services.
#[derive(Clone)]
pub struct ConfiguredControlPlaneConnector<C> {
    connector: C,
}

impl<C> ConfiguredControlPlaneConnector<C>
where
    C: Service<Uri> + Clone + Send + Sync + 'static,
    C::Response: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    C::Future: Send + 'static,
    tonic_tls::Error: From<C::Error>,
{
    /// Wraps an already configured TLS URI service without connecting or
    /// validating credentials. Construct a fallible reloadable connector first.
    ///
    /// Connections use upstream ADS defaults: a 10-second connection timeout,
    /// 5-minute HTTP/2 keepalive interval, 20-second acknowledgement timeout,
    /// and keepalives while idle. Explicit keepalive overrides are honored,
    /// including disabling PINGs. Socket options belong to the supplied service.
    pub fn new(connector: C) -> Self {
        Self { connector }
    }
}

impl<C> ControlPlaneConnector for ConfiguredControlPlaneConnector<C>
where
    C: Service<Uri> + Clone + Send + Sync + 'static,
    C::Response: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    C::Future: Send + 'static,
    tonic_tls::Error: From<C::Error>,
{
    fn is_secure(&self) -> bool {
        true
    }

    fn connect(&self, config: ControlPlaneConfig<'_>) -> BoxFuture<Result<Channel, XdsError>> {
        let endpoint = ads_endpoint(config.server().uri(), config.keep_alive());
        let connector = self.connector.clone();
        Box::pin(async move {
            endpoint?
                .connect_with_connector(connector)
                .await
                .map_err(|error| XdsError::Connection(error.to_string()))
        })
    }
}

fn ads_endpoint(
    server_uri: &str,
    keep_alive: Option<(Option<Duration>, Duration)>,
) -> Result<Endpoint, XdsError> {
    let uri: Uri = server_uri
        .parse()
        .map_err(|error| XdsError::Connection(format!("invalid management-server URI: {error}")))?;
    let origin = match uri.scheme_str() {
        Some("https") => uri,
        None => format!("https://{server_uri}").parse().map_err(|error| {
            XdsError::Connection(format!("invalid management-server address: {error}"))
        })?,
        Some(scheme) => {
            return Err(XdsError::Connection(format!(
                "configured control-plane TLS requires HTTPS or a scheme-less address, not '{scheme}'"
            )));
        }
    };
    let authority = origin
        .authority()
        .ok_or_else(|| XdsError::Connection("management-server URI has no authority".into()))?;
    let connection_uri = if authority.port_u16().is_some() {
        format!("http://{authority}")
    } else {
        format!("http://{authority}:443")
    };
    let mut endpoint = Endpoint::from_shared(connection_uri)
        .map_err(|error| XdsError::Connection(format!("invalid management-server URI: {error}")))?
        .origin(origin)
        .connect_timeout(Duration::from_secs(10));
    let (interval, timeout) =
        keep_alive.unwrap_or((Some(Duration::from_secs(5 * 60)), Duration::from_secs(20)));
    endpoint = endpoint.keep_alive_timeout(timeout);
    if let Some(interval) = interval {
        endpoint = endpoint
            .http2_keep_alive_interval(interval)
            .keep_alive_while_idle(true);
    }
    Ok(endpoint)
}
