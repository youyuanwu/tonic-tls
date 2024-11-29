use std::sync::Arc;

use tokio::net::TcpStream;
use tonic::transport::Uri;
use tower::Service;

/// Internal implementation of connector wrapper.
#[derive(Clone)]
struct RustlsConnector(tokio_rustls::TlsConnector);

impl crate::TlsConnector<TcpStream> for RustlsConnector {
    type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;
    type Domain = tokio_rustls::rustls::pki_types::ServerName<'static>;

    async fn connect(
        &self,
        domain: Self::Domain,
        stream: TcpStream,
    ) -> Result<Self::TlsStream, crate::Error> {
        self.0
            .connect(domain, stream)
            .await
            .map_err(crate::Error::from)
    }
}

/// tonic client connector to connect to https endpoint at addr using
/// rustls.
/// domain is the server name to validate.
/// Disabling validation is not supported.
/// See [connect](tokio_rustls::TlsConnector::connect) for details.
/// # Examples
/// ```
/// async fn connect_tonic_channel(ssl_conn: std::sync::Arc<tokio_rustls::rustls::ClientConfig>) -> tonic::transport::Channel {
///     let dnsname = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
///     tonic_tls::new_endpoint()
///         .connect_with_connector(tonic_tls::rustls::connector(
///             "https:://localhost:12345".parse().unwrap(),
///             ssl_conn,
///             dnsname,
///         ))
///         .await.unwrap()
/// }
/// ```
pub fn connector(
    uri: Uri,
    ssl_conn: Arc<tokio_rustls::rustls::ClientConfig>,
    domain: tokio_rustls::rustls::pki_types::ServerName<'static>,
) -> impl Service<
    Uri,
    Response = impl hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    Future = impl Send + 'static,
    Error = crate::Error,
> {
    let ssl_conn = RustlsConnector(tokio_rustls::TlsConnector::from(ssl_conn));
    crate::connector_inner(uri, ssl_conn, domain)
}
