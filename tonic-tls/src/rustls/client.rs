use std::sync::Arc;

use tokio::net::TcpStream;
use tonic::transport::Uri;
use tower::Service;

pub type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// Internal implementation of connector wrapper.
#[derive(Clone)]
struct RustlsConnector(tokio_rustls::TlsConnector);

impl crate::TlsConnector<TcpStream> for RustlsConnector {
    type TlsStream = TlsStream;
    type Arg = tokio_rustls::rustls::pki_types::ServerName<'static>;

    async fn connect(
        &self,
        domain: Self::Arg,
        stream: TcpStream,
    ) -> Result<Self::TlsStream, crate::Error> {
        self.0
            .connect(domain, stream)
            .await
            .map_err(crate::Error::from)
    }
}

fn connector(
    uri: Uri,
    ssl_conn: Arc<tokio_rustls::rustls::ClientConfig>,
    domain: tokio_rustls::rustls::pki_types::ServerName<'static>,
) -> impl Service<
    Uri,
    Response = hyper_util::rt::TokioIo<TlsStream>,
    Future = impl Send + 'static,
    Error = crate::Error,
> {
    let ssl_conn = RustlsConnector(tokio_rustls::TlsConnector::from(ssl_conn));
    crate::connector_inner(uri, ssl_conn, domain)
}

/// tonic client connector to connect to https endpoint at addr using
/// rustls.
pub struct TlsConnector {
    inner: crate::client::ConnectorWrapper<TlsStream>,
}

impl TlsConnector {
    /// domain is the server name to validate.
    /// Disabling validation is not supported.
    /// See [connect](tokio_rustls::TlsConnector::connect) for details.
    /// # Examples
    /// ```
    /// async fn connect_tonic_channel(ssl_conn: std::sync::Arc<tokio_rustls::rustls::ClientConfig>) -> tonic::transport::Channel {
    ///     let dnsname = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
    ///     tonic_tls::new_endpoint()
    ///         .connect_with_connector(tonic_tls::rustls::TlsConnector::new(
    ///             "https:://localhost:12345".parse().unwrap(),
    ///             ssl_conn,
    ///             dnsname,
    ///         ))
    ///         .await.unwrap()
    /// }
    /// ```
    pub fn new(
        uri: Uri,
        ssl_conn: Arc<tokio_rustls::rustls::ClientConfig>,
        domain: tokio_rustls::rustls::pki_types::ServerName<'static>,
    ) -> Self {
        Self {
            inner: crate::client::ConnectorWrapper::new(connector(uri, ssl_conn, domain)),
        }
    }
}

impl Service<Uri> for TlsConnector {
    type Response = hyper_util::rt::TokioIo<TlsStream>;

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
