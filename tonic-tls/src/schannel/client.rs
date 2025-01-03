use std::sync::Arc;

use tokio::net::TcpStream;
use tonic::transport::Uri;
use tower::Service;

/// Internal implementation of connector wrapper.
#[derive(Clone)]
struct SchannelConnector {
    inner: Arc<tokio::sync::Mutex<tokio_schannel::TlsConnector>>,
}

impl crate::TlsConnector<TcpStream> for SchannelConnector {
    type TlsStream = tokio_schannel::TlsStream<TcpStream>;
    type Arg = schannel::schannel_cred::SchannelCred;

    async fn connect(
        &self,
        cred: schannel::schannel_cred::SchannelCred,
        stream: TcpStream,
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
/// See [connect](schannel::tls_stream::Builder::connect) for details.
/// # Examples
/// ```
/// async fn connect_tonic_channel(builder: schannel::tls_stream::Builder,
///         cred: schannel::schannel_cred::SchannelCred)
/// -> tonic::transport::Channel {
///     tonic_tls::new_endpoint()
///         .connect_with_connector(tonic_tls::schannel::connector(
///             "https:://localhost:12345".parse().unwrap(),
///             builder,
///             cred,
///         ))
///         .await.unwrap()
/// }
/// ```
pub fn connector(
    uri: Uri,
    builder: schannel::tls_stream::Builder,
    cred: schannel::schannel_cred::SchannelCred,
) -> impl Service<
    Uri,
    Response = impl hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    Future = impl Send + 'static,
    Error = crate::Error,
> {
    let ssl_conn = SchannelConnector {
        inner: Arc::new(tokio::sync::Mutex::new(tokio_schannel::TlsConnector::new(
            builder,
        ))),
    };
    crate::connector_inner(uri, ssl_conn, cred)
}
