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

/// tonic client connector to connect to https endpoint at addr using
/// rustls.
pub struct TlsConnector {
    inner: crate::client::TlsBoxedService<TlsStream>,
}

impl TlsConnector {
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
    ///     endpoint.connect_with_connector(tonic_tls::rustls::TlsConnector::new(
    ///         &endpoint,
    ///         ssl_conn,
    ///         dnsname,
    ///     )).await.unwrap()
    /// }
    /// ```
    pub fn new(
        endpoint: &tonic::transport::Endpoint,
        ssl_conn: Arc<tokio_rustls::rustls::ClientConfig>,
        domain: tokio_rustls::rustls::pki_types::ServerName<'static>,
    ) -> Self {
        Self {
            inner: crate::connector_inner(
                endpoint,
                RustlsConnector(tokio_rustls::TlsConnector::from(ssl_conn)),
                domain,
            ),
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
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        self.inner.call(req)
    }
}
