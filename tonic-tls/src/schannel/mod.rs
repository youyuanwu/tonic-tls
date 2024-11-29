use futures::Stream;
use schannel::cert_context::CertContext;
use std::{
    fmt::Debug,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::Connected;

mod client;
pub use client::connector;

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

impl<S> crate::TlsAcceptor<S> for SchannelAcceptor
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
            .map(|s| TlsStream { inner: s })
            .map_err(crate::Error::from)
    }
}

/// Wraps the incoming (tcp) stream into a schannel stream, which
/// can be used to run tonic server.
/// Example:
/// ```ignore
/// async fn run_openssl_tonic_server(
///  tcp_s: TcpListenerStream,
///  builder: schannel::tls_stream::Builder,
///  cred: schannel::schannel_cred::SchannelCred,
/// ) {
/// let incoming = tonic_tls::schannel::incoming(tcp_s, builder, cred);
/// let greeter = Greeter {};
/// tonic::transport::Server::builder()
///     .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
///     .serve_with_incoming(incoming)
///     .await
///     .unwrap();
/// }
/// ```
pub fn incoming<IO, IE>(
    incoming: impl Stream<Item = Result<IO, IE>>,
    builder: schannel::tls_stream::Builder,
    cred: schannel::schannel_cred::SchannelCred,
) -> impl Stream<Item = Result<TlsStream<IO>, crate::Error>>
where
    IO: AsyncRead + AsyncWrite + Send + Sync + Debug + Unpin + 'static,
    IE: Into<crate::Error>,
{
    let acceptor = SchannelAcceptor::new(tokio_schannel::TlsAcceptor::new(builder), cred);
    crate::incoming_inner::<IO, IE, SchannelAcceptor, TlsStream<IO>>(incoming, acceptor)
}

/// A `TlsStream` wrapper type that implements tokio's io traits
/// and tonic's `Connected` trait.
#[derive(Debug)]
pub struct TlsStream<S> {
    inner: tokio_schannel::TlsStream<S>,
}

impl<S: Connected + AsyncRead + AsyncWrite> Connected for TlsStream<S> {
    type ConnectInfo = SslConnectInfo<S::ConnectInfo>;

    fn connect_info(&self) -> Self::ConnectInfo {
        let inner = self.inner.get_ref();
        let conn = inner.get_ref().get_ref().connect_info();
        let certs = inner.peer_certificate().ok().map(Arc::new);
        SslConnectInfo { inner: conn, certs }
    }
}

impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Connection info for SSL streams.
///
/// This type will be accessible through [request extensions](tonic::Request::extensions).
///
/// See [`Connected`] for more details.
#[derive(Debug, Clone)]
pub struct SslConnectInfo<T> {
    inner: T,
    certs: Option<Arc<CertContext>>,
}

impl<T> SslConnectInfo<T> {
    /// Get a reference to the underlying connection info.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the underlying connection info.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Return the set of connected peer SSL certificates.
    pub fn peer_certs(&self) -> Option<Arc<CertContext>> {
        self.certs.clone()
    }
}
