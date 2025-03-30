use super::TlsStreamWrapper;
use futures::Stream;
use tokio_native_tls::native_tls::TlsAcceptor;

use super::incoming;

/// The same as the [incoming] returned stream,
/// but wrapped in a struct.
pub struct TlsIncoming {
    inner: crate::TlsIncoming<TlsStreamWrapper<tokio::net::TcpStream>>,
}

impl TlsIncoming {
    /// The same arguments as [incoming] function.
    pub fn new(tcp_incoming: tonic::transport::server::TcpIncoming, acceptor: TlsAcceptor) -> Self {
        let inner = incoming(tcp_incoming, acceptor);
        Self {
            inner: crate::TlsIncoming::new(inner),
        }
    }
}

impl Stream for TlsIncoming {
    type Item = Result<TlsStreamWrapper<tokio::net::TcpStream>, crate::Error>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use futures::StreamExt;
        self.inner.poll_next_unpin(cx)
    }
}
