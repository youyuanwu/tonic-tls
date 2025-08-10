use std::sync::Arc;

use super::TlsStream;
use futures::Stream;
use tokio::io::{AsyncRead, AsyncWrite};

/// Internal implementation of acceptor wrapper.
#[derive(Clone)]
struct SchannelAcceptor {
    inner: Arc<tokio::sync::Mutex<tokio_schannel::TlsAcceptor>>,
    cred: schannel::schannel_cred::SchannelCred,
}

impl SchannelAcceptor {
    fn new(
        inner: tokio_schannel::TlsAcceptor,
        cred: schannel::schannel_cred::SchannelCred,
    ) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(inner)),
            cred,
        }
    }
}

impl<S> crate::server::TlsAcceptor<S> for SchannelAcceptor
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type TlsStream = TlsStream<S>;
    async fn accept(&self, stream: S) -> Result<TlsStream<S>, crate::Error> {
        // lock is needed here because schannel accept call is mutable.
        self.inner
            .lock()
            .await
            .accept(self.cred.clone(), stream)
            .await
            .map(|s| TlsStream::new(s))
            .map_err(crate::Error::from)
    }
}

/// The same as the [incoming] returned stream,
/// but wrapped in a struct.
pub struct TlsIncoming {
    inner: crate::server::TlsIncoming<TlsStream<tokio::net::TcpStream>>,
}

impl TlsIncoming {
    /// Creates a tls incoming stream on top of a tcp incoming stream
    /// # Examples
    /// ```no_run
    /// # use tower::Service;
    /// # use hyper::{Request, Response};
    /// # use tonic::{body::Body, server::NamedService, transport::{Server, server::TcpIncoming}};
    /// # use core::convert::Infallible;
    /// # use std::error::Error;
    /// use schannel::tls_stream::Builder;
    /// use schannel::schannel_cred::SchannelCred;
    /// use tonic_tls::schannel::TlsIncoming;
    /// # fn main() { }  // Cannot have type parameters, hence instead define:
    /// # fn run<S>(some_service: S, builder: schannel::tls_stream::Builder,
    ///     cred: schannel::schannel_cred::SchannelCred,) -> Result<(), Box<dyn Error + Send + Sync>>
    /// # where
    /// #   S: Service<Request<Body>, Response = Response<Body>, Error = Infallible> + NamedService + Clone + Send + Sync + 'static,
    /// #   S::Future: Send + 'static,
    /// # {
    /// let addr = "127.0.0.1:1322".parse().unwrap();
    /// let inc = TlsIncoming::new(TcpIncoming::bind(addr).unwrap(), builder, cred);
    /// Server::builder()
    ///    .add_service(some_service)
    ///    .serve_with_incoming(inc);
    /// # Ok(())
    /// # }
    pub fn new(
        tcp_incoming: tonic::transport::server::TcpIncoming,
        builder: schannel::tls_stream::Builder,
        cred: schannel::schannel_cred::SchannelCred,
    ) -> Self {
        let acceptor = SchannelAcceptor::new(tokio_schannel::TlsAcceptor::new(builder), cred);
        Self {
            inner: crate::server::incoming_inner(tcp_incoming, acceptor),
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
