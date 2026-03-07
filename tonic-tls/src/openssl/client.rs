use tokio::io::{AsyncRead, AsyncWrite};

use tonic::transport::Uri;
use tower::Service;

/// Internal implementation of connector wrapper.
#[derive(Clone)]
struct OpensslConnector(openssl::ssl::SslConnector);

impl<S> crate::TlsConnector<S> for OpensslConnector
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type TlsStream = tokio_openssl::SslStream<S>;
    type Arg = String;

    async fn connect(&self, domain: Self::Arg, stream: S) -> Result<Self::TlsStream, crate::Error> {
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
pub struct TlsConnector<IO> {
    inner: crate::client::TlsBoxedService<tokio_openssl::SslStream<IO>>,
}

impl<IO: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static> TlsConnector<IO> {
    /// domain is the server name to validate.
    /// See [connect](openssl::ssl::SslConnector::connect) for details.
    /// # Examples
    /// ```
    /// async fn connect_tonic_channel(
    ///     endpoint: tonic::transport::Endpoint,
    ///     ssl_conn: openssl::ssl::SslConnector
    /// ) -> tonic::transport::Channel {
    ///     let transport = tonic_tls::TcpTransport::from_endpoint(&endpoint);
    ///     endpoint.connect_with_connector(tonic_tls::openssl::TlsConnector::new(
    ///         transport,
    ///         ssl_conn,
    ///        "localhost".to_string(),
    ///     )).await.unwrap()
    /// }
    /// ```
    pub fn new(
        transport: impl crate::Transport<Io = IO>,
        ssl_conn: openssl::ssl::SslConnector,
        domain: String,
    ) -> Self {
        Self {
            inner: crate::connector_inner(transport, OpensslConnector(ssl_conn), domain),
        }
    }
}

impl<IO: Send + 'static> Service<Uri> for TlsConnector<IO> {
    type Response = hyper_util::rt::TokioIo<tokio_openssl::SslStream<IO>>;

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
