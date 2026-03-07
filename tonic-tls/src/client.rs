use std::net::SocketAddr;
use std::sync::Arc;

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use tonic::transport::Uri;

use crate::endpoint::TcpOpt;

/// Not intended to be used by applications directly.
/// To add a new tls backend, implement this and pass it into [connector_inner].
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

/// Trait for abstracting the transport connection step.
/// Implement this for custom transports (e.g. Unix sockets, VSOCK).
pub trait Transport: Clone + Send + 'static {
    /// The connection type produced by this transport.
    type Io: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static;
    /// The error type returned by connect.
    type Error: Into<crate::Error>;

    fn connect(
        &self,
        uri: &Uri,
    ) -> impl std::future::Future<Output = Result<Self::Io, Self::Error>> + Send;
}

/// Default TCP transport. Handles DNS resolution, TCP connect,
/// and applies TCP options (keepalive, nodelay).
#[derive(Clone)]
pub struct TcpTransport {
    tcp_opt: Arc<TcpOpt>,
}

impl TcpTransport {
    pub fn from_endpoint(ep: &tonic::transport::Endpoint) -> Self {
        Self {
            tcp_opt: Arc::new(TcpOpt::from_ep(ep)),
        }
    }
}

impl Transport for TcpTransport {
    type Io = TcpStream;
    type Error = std::io::Error;

    async fn connect(&self, uri: &Uri) -> Result<Self::Io, Self::Error> {
        let addrs = dns_resolve(uri).await?;
        let stream = connect_tcp(addrs).await?;
        self.tcp_opt.apply_opt(&stream)?;
        Ok(stream)
    }
}

pub(crate) type TlsBoxedService<TS> =
    tower::util::BoxService<Uri, hyper_util::rt::TokioIo<TS>, crate::Error>;

/// Not intended to be used by applications directly.
/// Applications should use the tls backend api, for example [super::openssl::TlsConnector]
pub fn connector_inner<T, C, TS>(transport: T, ssl_conn: C, arg: C::Arg) -> TlsBoxedService<TS>
where
    T: Transport,
    C: TlsConnector<T::Io, TlsStream = TS>,
    TS: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let svc = tower::service_fn(move |uri: Uri| {
        let transport = transport.clone();
        let ssl_conn = ssl_conn.clone();
        let arg = arg.clone();
        async move {
            let stream = transport.connect(&uri).await.map_err(Into::into)?;
            let ssl_s = ssl_conn.connect(arg, stream).await?;
            Ok::<_, crate::Error>(hyper_util::rt::TokioIo::new(ssl_s))
        }
    });
    tower::util::BoxService::new(svc)
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
