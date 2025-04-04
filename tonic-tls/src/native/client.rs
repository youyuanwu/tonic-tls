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

fn connector(
    uri: Uri,
    ssl_conn: tokio_native_tls::native_tls::TlsConnector,
    domain: String,
) -> impl Service<
    Uri,
    Response = hyper_util::rt::TokioIo<tokio_native_tls::TlsStream<TcpStream>>,
    Future = impl Send + 'static,
    Error = crate::Error,
> {
    let ssl_conn = NativeConnector(tokio_native_tls::TlsConnector::from(ssl_conn));
    crate::connector_inner(uri, ssl_conn, domain)
}

/// tonic client connector to connect to https endpoint at addr using
/// native tls.
pub struct TlsConnector {
    inner: crate::client::ConnectorWrapper<tokio_native_tls::TlsStream<TcpStream>>,
}

impl TlsConnector {
    /// domain is the server name to validate, and if none.
    /// Disabling validation is not supported.
    /// See [connect](tokio_native_tls::native_tls::TlsConnector::connect) for details.
    /// # Examples
    /// ```
    /// async fn connect_tonic_channel(ssl_conn: tokio_native_tls::native_tls::TlsConnector) -> tonic::transport::Channel {
    ///     tonic_tls::new_endpoint()
    ///         .connect_with_connector(tonic_tls::native::TlsConnector::new(
    ///             "https:://localhost:12345".parse().unwrap(),
    ///             ssl_conn,
    ///             "localhost".to_string(),
    ///         ))
    ///         .await.unwrap()
    /// }
    /// ```
    pub fn new(
        uri: Uri,
        ssl_conn: tokio_native_tls::native_tls::TlsConnector,
        domain: String,
    ) -> Self {
        Self {
            inner: crate::client::ConnectorWrapper::new(connector(uri, ssl_conn, domain)),
        }
    }
}

impl Service<Uri> for TlsConnector {
    type Response = hyper_util::rt::TokioIo<tokio_native_tls::TlsStream<TcpStream>>;

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
