use std::sync::Arc;

use super::TlsStream;
use futures::Stream;

use super::incoming;

/// The same as the [incoming] returned stream,
/// but wrapped in a struct.
pub struct TlsIncoming {
    inner: crate::TlsIncoming<TlsStream<tokio::net::TcpStream>>,
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
    /// # use std::sync::Arc;
    /// use tokio_rustls::rustls::ServerConfig;
    /// use tonic_tls::rustls::TlsIncoming;
    /// # fn main() { }  // Cannot have type parameters, hence instead define:
    /// # fn run<S>(some_service: S, server_config: Arc<tokio_rustls::rustls::ServerConfig>) -> Result<(), Box<dyn Error + Send + Sync>>
    /// # where
    /// #   S: Service<Request<Body>, Response = Response<Body>, Error = Infallible> + NamedService + Clone + Send + Sync + 'static,
    /// #   S::Future: Send + 'static,
    /// # {
    /// let addr = "127.0.0.1:1322".parse().unwrap();
    /// let inc = TlsIncoming::new(TcpIncoming::bind(addr).unwrap(), server_config);
    /// Server::builder()
    ///    .add_service(some_service)
    ///    .serve_with_incoming(inc);
    /// # Ok(())
    /// # }
    pub fn new(
        tcp_incoming: tonic::transport::server::TcpIncoming,
        server_config: Arc<tokio_rustls::rustls::ServerConfig>,
    ) -> Self {
        let inner = incoming(tcp_incoming, server_config);
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
