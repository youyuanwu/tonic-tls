use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::{Endpoint, Uri};
use tower::Service;

/// Creates an endpoint with and local uri that is never used.
/// Use `connector` to make connections.
pub fn new_endpoint() -> Endpoint {
    tonic::transport::Endpoint::from_static("http://[::]:50051")
}

#[derive(Clone)]
pub struct RustlsConnector(tokio_rustls::TlsConnector);

impl tonic_tls::TlsConnector<TcpStream> for RustlsConnector {
    type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;
    type Domain = rustls::pki_types::ServerName<'static>;

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
    domain: rustls::pki_types::ServerName<'static>,
) -> impl Service<
    Uri,
    Response = impl hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    Future = impl Send + 'static,
    Error = crate::Error,
> {
    let ssl_conn = RustlsConnector(ssl_conn);
    tonic_tls::connector_inner(uri, ssl_conn, domain)
}
