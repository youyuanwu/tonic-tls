use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tonic::transport::Uri;
use tower::Service;

pub type TlsStream<IO> = tokio_rustls::client::TlsStream<IO>;

/// Internal implementation of connector wrapper.
#[derive(Clone)]
struct RustlsConnector(tokio_rustls::TlsConnector);

impl<S> crate::TlsConnector<S> for RustlsConnector
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type TlsStream = TlsStream<S>;
    type Arg = tokio_rustls::rustls::pki_types::ServerName<'static>;

    async fn connect(&self, domain: Self::Arg, stream: S) -> Result<Self::TlsStream, crate::Error> {
        self.0
            .connect(domain, stream)
            .await
            .map_err(crate::Error::from)
    }
}

/// tonic client connector to connect to https endpoint at addr using
/// rustls.
pub struct TlsConnector<IO> {
    inner: crate::client::TlsBoxedService<TlsStream<IO>>,
}

impl<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> TlsConnector<IO> {
    /// domain is the server name to validate.
    /// Disabling validation is not supported.
    /// See [connect](tokio_rustls::TlsConnector::connect) for details.
    /// # Examples
    /// ```
    /// async fn connect_tonic_channel(
    ///     endpoint: tonic::transport::Endpoint,
    ///     ssl_conn: std::sync::Arc<tokio_rustls::rustls::ClientConfig>)
    /// -> tonic::transport::Channel {    
    ///     let dnsname = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
    ///     let transport = tonic_tls::TcpTransport::from_endpoint(&endpoint);
    ///     endpoint.connect_with_connector(tonic_tls::rustls::TlsConnector::new(
    ///         transport,
    ///         ssl_conn,
    ///         dnsname,
    ///     )).await.unwrap()
    /// }
    /// ```
    pub fn new(
        transport: impl crate::Transport<Io = IO>,
        ssl_conn: Arc<tokio_rustls::rustls::ClientConfig>,
        domain: tokio_rustls::rustls::pki_types::ServerName<'static>,
    ) -> Self {
        Self {
            inner: crate::connector_inner(
                transport,
                RustlsConnector(tokio_rustls::TlsConnector::from(ssl_conn)),
                domain,
            ),
        }
    }
}

impl<IO: Send + 'static> Service<Uri> for TlsConnector<IO> {
    type Response = hyper_util::rt::TokioIo<TlsStream<IO>>;

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
