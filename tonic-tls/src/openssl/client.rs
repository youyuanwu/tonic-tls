use tokio::net::TcpStream;

use tonic::transport::Uri;
use tower::Service;

#[derive(Clone)]
struct OpensslConnector(openssl::ssl::SslConnector);

impl crate::TlsConnector<TcpStream> for OpensslConnector {
    type TlsStream = tokio_openssl::SslStream<TcpStream>;
    type Domain = String;

    async fn connect(
        &self,
        domain: Self::Domain,
        stream: TcpStream,
    ) -> Result<Self::TlsStream, crate::Error> {
        let ssl_config = self.0.configure()?;
        // configure server name check.
        let ssl = ssl_config.into_ssl(&domain)?;

        let mut stream = tokio_openssl::SslStream::new(ssl, stream)?;
        std::pin::Pin::new(&mut stream).connect().await?;
        Ok(stream)
    }
}

pub fn connector(
    uri: Uri,
    ssl_conn: openssl::ssl::SslConnector,
    domain: String,
) -> impl Service<
    Uri,
    Response = impl hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    Future = impl Send + 'static,
    Error = crate::Error,
> {
    let ssl_conn = OpensslConnector(ssl_conn);
    crate::connector_inner(uri, ssl_conn, domain)
}
