use super::TlsStream;
use futures::Stream;

use super::incoming;

/// The same as the [incoming] returned stream,
/// but wrapped in a struct.
pub struct TlsIncoming {
    inner: crate::TlsIncoming<TlsStream<tokio::net::TcpStream>>,
}

impl TlsIncoming {
    /// The same arguments as [incoming] function.
    pub fn new(
        tcp_incoming: tonic::transport::server::TcpIncoming,
        builder: schannel::tls_stream::Builder,
        cred: schannel::schannel_cred::SchannelCred,
    ) -> Self {
        let inner = incoming(tcp_incoming, builder, cred);
        Self {
            inner: crate::TlsIncoming::new(inner),
        }
    }
}

impl Stream for TlsIncoming {
    type Item = Result<TlsStream<tokio::net::TcpStream>, crate::Error>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use futures::StreamExt;
        self.inner.poll_next_unpin(cx)
    }
}
