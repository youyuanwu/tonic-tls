use tokio::net::TcpStream;

use tonic::transport::Uri;
use tower::Service;

/// Internal implementation of connector wrapper.
#[derive(Clone)]
struct OpensslKtlsConnector(openssl::ssl::SslConnector);

impl crate::TlsConnector<TcpStream> for OpensslKtlsConnector {
    type TlsStream = openssl_ktls::TokioSslStream;
    type Arg = String;

    async fn connect(
        &self,
        domain: Self::Arg,
        stream: TcpStream,
    ) -> Result<Self::TlsStream, crate::Error> {
        let ssl_config = self.0.configure()?;
        // configure server name check.
        let ssl = ssl_config.into_ssl(&domain)?;

        let mut stream = openssl_ktls::TokioSslStream::new(stream, ssl)?;
        std::pin::Pin::new(&mut stream).connect().await?;
        Ok(stream)
    }
}

/// tonic client connector to connect to https endpoint at addr using
/// openssl settings in ssl.
pub struct TlsConnector {
    inner: crate::client::TlsBoxedService<openssl_ktls::TokioSslStream>,
}

impl TlsConnector {
    /// domain is the server name to validate.
    /// See [connect](openssl::ssl::SslConnector::connect) for details.
    /// # Examples
    /// ```
    /// async fn connect_tonic_channel(
    ///     endpoint: tonic::transport::Endpoint,
    ///     ssl_conn: openssl::ssl::SslConnector
    /// ) -> tonic::transport::Channel {
    ///     endpoint.connect_with_connector(tonic_tls::openssl_ktls::TlsConnector::new(
    ///         &endpoint,
    ///         ssl_conn,
    ///        "localhost".to_string(),
    ///     )).await.unwrap()
    /// }
    /// ```
    pub fn new(
        endpoint: &tonic::transport::Endpoint,
        ssl_conn: openssl::ssl::SslConnector,
        domain: String,
    ) -> Self {
        Self {
            inner: crate::connector_inner(endpoint, OpensslKtlsConnector(ssl_conn), domain),
        }
    }
}

impl Service<Uri> for TlsConnector {
    type Response = hyper_util::rt::TokioIo<openssl_ktls::TokioSslStream>;

    type Error = crate::Error;

    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        self.inner.call(req)
    }
}
