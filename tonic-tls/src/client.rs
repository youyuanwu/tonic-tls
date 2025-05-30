use std::{net::SocketAddr, sync::Arc};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use tonic::transport::Uri;
use tower::Service;

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

/// Not intended to be used by applications directly.
/// Applications should use the tls backend api, for example [super::openssl::connector]
pub fn connector_inner<C, TS>(
    endpoint: &tonic::transport::Endpoint,
    ssl_conn: C,
    arg: C::Arg,
) -> impl Service<
    Uri,
    Response = hyper_util::rt::TokioIo<TS>,
    Future = impl Send + 'static,
    Error = crate::Error,
>
where
    C: TlsConnector<TcpStream, TlsStream = TS>,
    TS: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let tcp_opt = Arc::new(TcpOpt::from_ep(endpoint));
    tower::service_fn(move |_: Uri| {
        let tcp_opt = tcp_opt.clone();
        let ssl_conn = ssl_conn.clone();
        let arg = arg.clone();
        async move {
            let addrs = dns_resolve(&tcp_opt.uri).await?;
            // Connect and get ssl stream
            let stream = connect_tcp(addrs).await?;

            // Apply tcp options to stream.
            tcp_opt.apply_opt(&stream)?;

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

/// Pass through wrapper for converting a tower service connector impl into a struct.
pub(crate) struct ConnectorWrapper<T> {
    pub inner: tower::util::BoxService<Uri, hyper_util::rt::TokioIo<T>, crate::Error>,
}

impl<T> ConnectorWrapper<T> {
    pub fn new(
        inner: impl Service<
                Uri,
                Response = hyper_util::rt::TokioIo<T>,
                Future = impl Send + 'static,
                Error = crate::Error,
            > + Send
            + 'static,
    ) -> Self {
        Self {
            inner: tower::util::BoxService::new(inner),
        }
    }
}
