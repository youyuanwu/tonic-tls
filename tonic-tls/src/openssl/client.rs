use tokio::net::TcpStream;

use tonic::transport::Uri;
use tower::Service;

/// Internal implementation of connector wrapper.
#[derive(Clone)]
struct OpensslConnector(openssl::ssl::SslConnector);

impl crate::TlsConnector<TcpStream> for OpensslConnector {
    type TlsStream = tokio_openssl::SslStream<TcpStream>;
    type Domain = String;

    async fn connect(
        &self,
        domain: Self::Domain,
        stream: TcpStream,
    ) -> Result<Self::TlsStream, crate::Error> {
        let ssl_config = self.0.configure()?;
        // configure server name check.
        let ssl = ssl_config.into_ssl(&domain)?;

        let mut stream = tokio_openssl::SslStream::new(ssl, stream)?;
        std::pin::Pin::new(&mut stream).connect().await?;
        Ok(stream)
    }
}

/// tonic client connector to connect to https endpoint at addr using
/// openssl settings in ssl.
/// domain is the server name to validate.
/// See [connect](openssl::ssl::SslConnector::connect) for details.
/// # Examples
/// ```
/// async fn connect_tonic_channel(ssl_conn: openssl::ssl::SslConnector){
///     let ch: tonic::transport::Channel = tonic_tls::new_endpoint()
///         .connect_with_connector(tonic_tls::openssl::connector(
///             "https:://localhost:12345".parse().unwrap(),
///             ssl_conn,
///            "localhost".to_string(),
///         ))
///         .await.unwrap();
/// }
/// ```
pub fn connector(
    uri: Uri,
    ssl_conn: openssl::ssl::SslConnector,
    domain: String,
) -> impl Service<
    Uri,
    Response = impl hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    Future = impl Send + 'static,
    Error = crate::Error,
> {
    let ssl_conn = OpensslConnector(ssl_conn);
    crate::connector_inner(uri, ssl_conn, domain)
}
