use std::net::SocketAddr;

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use tonic::transport::Uri;
use tower::Service;

/// Creates an endpoint with and local uri that is never used.
/// Use connector like [connector](super::openssl::connector) to make connections.
pub fn new_endpoint() -> tonic::transport::Endpoint {
    tonic::transport::Endpoint::from_static("http://[::]:50051")
}

/// Not intended to be used by applications directly.
/// To add a new tls backend, implment this and pass it into [connector_inner].
pub trait TlsConnector<S>: Clone + Send + 'static
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type TlsStream;
    /// Argument for connect.
    type Arg: Clone + Send;
    fn connect(
        &self,
        arg: Self::Arg,
        stream: S,
    ) -> impl std::future::Future<Output = Result<Self::TlsStream, crate::Error>> + Send;
}

/// Not intended to be used by applications directly.
/// Applications should use the tls backend api, for example [super::openssl::connector]
pub fn connector_inner<C, TS>(
    uri: Uri,
    ssl_conn: C,
    arg: C::Arg,
) -> impl Service<
    Uri,
    Response = impl hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    Future = impl Send + 'static,
    Error = crate::Error,
>
where
    C: TlsConnector<TcpStream, TlsStream = TS>,
    TS: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    tower::service_fn(move |_: Uri| {
        let uri = uri.clone();
        let ssl_conn = ssl_conn.clone();
        let arg = arg.clone();
        async move {
            let addrs = dns_resolve(&uri).await?;
            // Connect and get ssl stream
            let stream = connect_tcp(addrs).await?;
            let ssl_s = ssl_conn.connect(arg, stream).await?;
            Ok::<_, crate::Error>(hyper_util::rt::TokioIo::new(ssl_s))
        }
    })
}

/// Use the host:port portion of the uri and resolve to an sockaddr.
/// If uri host portion is an ip string, then directly use the ip addr without
/// dns lookup.
async fn dns_resolve(uri: &Uri) -> std::io::Result<Vec<SocketAddr>> {
    let host_port = uri
        .authority()
        .ok_or(std::io::Error::from(std::io::ErrorKind::InvalidInput))?
        .as_str();
    match host_port.parse::<SocketAddr>() {
        Ok(addr) => Ok(vec![addr]),
        Err(_) => {
            // uri is using a dns name. try resolve it and return the first.
            tokio::net::lookup_host(host_port)
                .await
                .map(|a| a.collect::<Vec<_>>())
        }
    }
}

/// Connect to the target addr (from the same dns). The first success SockAddr connection
/// stream is returned. This is needed because sometimes ipv4 or ipv6 addrs are returned
/// by dns resolution, and only 1 of them works, especially in docker. This is the
/// same logic in hyper client.
async fn connect_tcp(addrs: Vec<SocketAddr>) -> std::io::Result<TcpStream> {
    let mut conn_err = std::io::Error::from(std::io::ErrorKind::AddrNotAvailable);
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => conn_err = e,
        }
    }
    Err(conn_err)
}
