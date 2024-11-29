use std::sync::Arc;

use tokio::net::TcpStream;
use tonic::transport::Uri;
use tower::Service;

#[derive(Clone)]
struct SchannelConnector {
    inner: Arc<tokio::sync::Mutex<tokio_schannel::TlsConnector>>,
}

impl crate::TlsConnector<TcpStream> for SchannelConnector {
    type TlsStream = tokio_schannel::TlsStream<TcpStream>;
    type Domain = schannel::schannel_cred::SchannelCred;

    async fn connect(
        &self,
        domain: schannel::schannel_cred::SchannelCred,
        stream: TcpStream,
    ) -> Result<Self::TlsStream, crate::Error> {
        // lock is needed because schannel inner is mutable
        self.inner
            .lock()
            .await
            .connect(domain, stream)
            .await
            .map_err(crate::Error::from)
    }
}

pub fn connector(
    uri: Uri,
    ssl_conn: tokio_schannel::TlsConnector,
    cred: schannel::schannel_cred::SchannelCred,
) -> impl Service<
    Uri,
    Response = impl hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    Future = impl Send + 'static,
    Error = crate::Error,
> {
    let ssl_conn = SchannelConnector {
        inner: Arc::new(tokio::sync::Mutex::new(ssl_conn)),
    };
    crate::connector_inner(uri, ssl_conn, cred)
}
