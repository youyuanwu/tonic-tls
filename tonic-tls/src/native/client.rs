use tokio::net::TcpStream;

use tonic::transport::Uri;
use tower::Service;

#[derive(Clone)]
pub struct NativeConnector(tokio_native_tls::TlsConnector);

impl crate::TlsConnector<TcpStream> for NativeConnector {
    type TlsStream = tokio_native_tls::TlsStream<TcpStream>;
    type Domain = String;

    async fn connect(
        &self,
        domain: Self::Domain,
        stream: TcpStream,
    ) -> Result<Self::TlsStream, crate::Error> {
        self.0
            .connect(domain.as_str(), stream)
            .await
            .map_err(crate::Error::from)
    }
}

pub fn connector(
    uri: Uri,
    ssl_conn: tokio_native_tls::TlsConnector,
    domain: String,
) -> impl Service<
    Uri,
    Response = impl hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    Future = impl Send + 'static,
    Error = crate::Error,
> {
    let ssl_conn = NativeConnector(ssl_conn);
    crate::connector_inner(uri, ssl_conn, domain)
}
