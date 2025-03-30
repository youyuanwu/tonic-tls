use futures::Stream;
use std::{
    fmt::Debug,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::pki_types::CertificateDer;
use tonic::transport::server::Connected;

mod client;
pub use client::connector;
mod server;
pub use server::TlsIncoming;

/// Internal implementation of acceptor wrapper.
#[derive(Clone)]
struct RustlsAcceptor(tokio_rustls::TlsAcceptor);

impl RustlsAcceptor {
    fn new(inner: tokio_rustls::TlsAcceptor) -> Self {
        Self(inner)
    }
}

impl<S> crate::TlsAcceptor<S> for RustlsAcceptor
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type TlsStream = TlsStream<S>;
    async fn accept(&self, stream: S) -> Result<TlsStream<S>, crate::Error> {
        self.0
            .accept(stream)
            .await
            .map(|s| TlsStream { inner: s })
            .map_err(crate::Error::from)
    }
}

/// Wraps the incoming (tcp) stream into a rustls stream, which
/// can be used to run tonic server.
/// Example:
/// ```ignore
/// async fn run_openssl_tonic_server(
///     tcp_s: tonic::transport::server::TcpIncoming,
///     server_config: std::sync::Arc<tokio_rustls::rustls::ServerConfig>,
/// ) {
///     let incoming = tonic_tls::rustls::incoming(tcp_s, server_config);
///     let greeter = Greeter {};
///     tonic::transport::Server::builder()
///         .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
///         .serve_with_incoming(incoming)
///         .await
///         .unwrap();
/// }
/// ```
pub fn incoming<IO, IE>(
    incoming: impl Stream<Item = Result<IO, IE>>,
    server_config: Arc<tokio_rustls::rustls::ServerConfig>,
) -> impl Stream<Item = Result<TlsStream<IO>, crate::Error>>
where
    IO: AsyncRead + AsyncWrite + Send + Sync + Debug + Unpin + 'static,
    IE: Into<crate::Error>,
{
    let acceptor = RustlsAcceptor::new(tokio_rustls::TlsAcceptor::from(server_config));
    crate::incoming_inner::<IO, IE, RustlsAcceptor, TlsStream<IO>>(incoming, acceptor)
}

/// A `TlsStream` wrapper type that implements tokio's io traits
/// and tonic's `Connected` trait.
#[derive(Debug)]
pub struct TlsStream<S> {
    inner: tokio_rustls::server::TlsStream<S>,
}

impl<S: Connected> Connected for TlsStream<S> {
    type ConnectInfo = SslConnectInfo<S::ConnectInfo>;

    fn connect_info(&self) -> Self::ConnectInfo {
        let (inner, conn) = self.inner.get_ref();
        // inner stream info
        let inner = inner.connect_info();
        let certs = conn
            .peer_certificates()
            .map(|certs| certs.to_owned().into());
        SslConnectInfo { inner, certs }
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
    certs: Option<Arc<Vec<CertificateDer<'static>>>>,
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
    pub fn peer_certs(&self) -> Option<Arc<Vec<CertificateDer<'static>>>> {
        self.certs.clone()
    }
}
