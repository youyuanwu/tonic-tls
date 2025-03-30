use super::SslStream;
use futures::Stream;
use openssl::ssl::SslAcceptor;

use super::incoming;

/// The same as the [incoming] returned stream,
/// but wrapped in a struct.
pub struct TlsIncoming {
    inner: crate::TlsIncoming<SslStream<tokio::net::TcpStream>>,
}

impl TlsIncoming {
    /// The same arguments as [incoming] function.
    pub fn new(tcp_incoming: tonic::transport::server::TcpIncoming, acceptor: SslAcceptor) -> Self {
        let inner = incoming(tcp_incoming, acceptor);
        Self {
            inner: crate::TlsIncoming::new(inner),
        }
    }
}

impl Stream for TlsIncoming {
    type Item = Result<SslStream<tokio::net::TcpStream>, crate::Error>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use futures::StreamExt;
        self.inner.poll_next_unpin(cx)
    }
}
