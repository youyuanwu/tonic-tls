use tokio::net::TcpStream;

use tonic::transport::Uri;
use tower::Service;

/// Internal implementation of connector wrapper.
#[derive(Clone)]
struct OpensslConnector(openssl::ssl::SslConnector);

impl crate::TlsConnector<TcpStream> for OpensslConnector {
    type TlsStream = tokio_openssl::SslStream<TcpStream>;
    type Arg = String;

    async fn connect(
        &self,
        domain: Self::Arg,
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

fn connector(
    uri: Uri,
    ssl_conn: openssl::ssl::SslConnector,
    domain: String,
) -> impl Service<
    Uri,
    Response = hyper_util::rt::TokioIo<tokio_openssl::SslStream<TcpStream>>,
    Future = impl Send + 'static,
    Error = crate::Error,
> {
    let ssl_conn = OpensslConnector(ssl_conn);
    crate::connector_inner(uri, ssl_conn, domain)
}

/// tonic client connector to connect to https endpoint at addr using
/// openssl settings in ssl.
pub struct TlsConnector {
    inner: crate::client::ConnectorWrapper<tokio_openssl::SslStream<TcpStream>>,
}

impl TlsConnector {
    /// domain is the server name to validate.
    /// See [connect](openssl::ssl::SslConnector::connect) for details.
    /// # Examples
    /// ```
    /// async fn connect_tonic_channel(ssl_conn: openssl::ssl::SslConnector){
    ///     let ch: tonic::transport::Channel = tonic_tls::new_endpoint()
    ///         .connect_with_connector(tonic_tls::openssl::TlsConnector::new(
    ///             "https:://localhost:12345".parse().unwrap(),
    ///             ssl_conn,
    ///            "localhost".to_string(),
    ///         ))
    ///         .await.unwrap();
    /// }
    /// ```
    pub fn new(uri: Uri, ssl_conn: openssl::ssl::SslConnector, domain: String) -> Self {
        Self {
            inner: crate::client::ConnectorWrapper::new(connector(uri, ssl_conn, domain)),
        }
    }
}

impl Service<Uri> for TlsConnector {
    type Response = hyper_util::rt::TokioIo<tokio_openssl::SslStream<TcpStream>>;

    type Error = crate::Error;

    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        self.inner.inner.call(req)
    }
}
