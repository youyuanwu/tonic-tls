use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tonic::transport::Uri;
use tower::Service;

pub type TlsStream<IO> = tokio_schannel::TlsStream<IO>;

/// Internal implementation of connector wrapper.
#[derive(Clone)]
struct SchannelConnector {
    inner: Arc<tokio::sync::Mutex<tokio_schannel::TlsConnector>>,
}

impl<S> crate::TlsConnector<S> for SchannelConnector
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type TlsStream = TlsStream<S>;
    type Arg = schannel::schannel_cred::SchannelCred;

    async fn connect(
        &self,
        cred: schannel::schannel_cred::SchannelCred,
        stream: S,
    ) -> Result<Self::TlsStream, crate::Error> {
        // lock is needed because schannel inner is mutable
        self.inner
            .lock()
            .await
            .connect(cred, stream)
            .await
            .map_err(crate::Error::from)
    }
}

/// tonic client connector to connect to https endpoint at addr using
/// schannel.
pub struct TlsConnector<IO> {
    inner: crate::client::TlsBoxedService<TlsStream<IO>>,
}

impl<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> TlsConnector<IO> {
    /// See [connect](schannel::tls_stream::Builder::connect) for details.
    /// # Examples
    /// ```
    /// async fn connect_tonic_channel(
    ///     endpoint: tonic::transport::Endpoint,
    ///     builder: schannel::tls_stream::Builder,
    ///     cred: schannel::schannel_cred::SchannelCred)
    /// -> tonic::transport::Channel {
    ///     let transport = tonic_tls::TcpTransport::from_endpoint(&endpoint);
    ///     endpoint.connect_with_connector(tonic_tls::schannel::TlsConnector::new(
    ///         transport,
    ///         builder,
    ///         cred,
    ///     )).await.unwrap()
    /// }
    /// ```
    pub fn new(
        transport: impl crate::Transport<Io = IO>,
        builder: schannel::tls_stream::Builder,
        cred: schannel::schannel_cred::SchannelCred,
    ) -> Self {
        let ssl_conn = SchannelConnector {
            inner: Arc::new(tokio::sync::Mutex::new(tokio_schannel::TlsConnector::new(
                builder,
            ))),
        };
        Self {
            inner: crate::connector_inner(transport, ssl_conn, cred),
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
