use tokio::net::TcpStream;

use tonic::transport::Uri;
use tower::Service;

/// Internal implementation of connector wrapper.
#[derive(Clone)]
struct NativeConnector(tokio_native_tls::TlsConnector);

impl crate::TlsConnector<TcpStream> for NativeConnector {
    type TlsStream = tokio_native_tls::TlsStream<TcpStream>;
    type Arg = String;

    async fn connect(
        &self,
        domain: Self::Arg,
        stream: TcpStream,
    ) -> Result<Self::TlsStream, crate::Error> {
        self.0
            .connect(domain.as_str(), stream)
            .await
            .map_err(crate::Error::from)
    }
}

/// tonic client connector to connect to https endpoint at addr using
/// native tls.
/// domain is the server name to validate, and if none.
/// Disabling validation is not supported.
/// See [connect](tokio_native_tls::native_tls::TlsConnector::connect) for details.
/// # Examples
/// ```
/// async fn connect_tonic_channel(ssl_conn: tokio_native_tls::native_tls::TlsConnector) -> tonic::transport::Channel {
///     tonic_tls::new_endpoint()
///         .connect_with_connector(tonic_tls::native::connector(
///             "https:://localhost:12345".parse().unwrap(),
///             ssl_conn,
///             "localhost".to_string(),
///         ))
///         .await.unwrap()
/// }
/// ```
pub fn connector(
    uri: Uri,
    ssl_conn: tokio_native_tls::native_tls::TlsConnector,
    domain: String,
) -> impl Service<
    Uri,
    Response = impl hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    Future = impl Send + 'static,
    Error = crate::Error,
> {
    let ssl_conn = NativeConnector(tokio_native_tls::TlsConnector::from(ssl_conn));
    crate::connector_inner(uri, ssl_conn, domain)
}
