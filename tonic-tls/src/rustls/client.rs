use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::Uri;
use tower::Service;

#[derive(Clone)]
pub struct RustlsConnector(tokio_rustls::TlsConnector);

impl crate::TlsConnector<TcpStream> for RustlsConnector {
    type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;
    type Domain = tokio_rustls::rustls::pki_types::ServerName<'static>;

    async fn connect(
        &self,
        domain: Self::Domain,
        stream: TcpStream,
    ) -> Result<Self::TlsStream, crate::Error> {
        self.0
            .connect(domain, stream)
            .await
            .map_err(crate::Error::from)
    }
}

pub fn connector(
    uri: Uri,
    ssl_conn: TlsConnector,
    domain: tokio_rustls::rustls::pki_types::ServerName<'static>,
) -> impl Service<
    Uri,
    Response = impl hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    Future = impl Send + 'static,
    Error = crate::Error,
> {
    let ssl_conn = RustlsConnector(ssl_conn);
    crate::connector_inner(uri, ssl_conn, domain)
}
