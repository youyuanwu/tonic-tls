use futures::Stream;
use std::{
    error::Error as StdError,
    fmt::Debug,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_native_tls::{TlsAcceptor, TlsStream};

mod client;
pub use client::connector;

pub type Error = Box<dyn StdError + Send + Sync + 'static>;

#[derive(Clone)]
struct NativeTlsAcceptor(TlsAcceptor);

impl NativeTlsAcceptor {
    fn new(inner: TlsAcceptor) -> Self {
        Self(inner)
    }
}

impl<S> tonic_tls::TlsAcceptor<S> for NativeTlsAcceptor
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type TlsStream = TlsStreamWrapper<S>;
    async fn accept(&self, stream: S) -> Result<TlsStreamWrapper<S>, tonic_tls::Error> {
        self.0
            .accept(stream)
            .await
            .map(|s| TlsStreamWrapper(s))
            .map_err(tonic_tls::Error::from)
    }
}

pub fn incoming<IO, IE>(
    incoming: impl Stream<Item = Result<IO, IE>>,
    acceptor: TlsAcceptor,
) -> impl Stream<Item = Result<TlsStreamWrapper<IO>, Error>>
where
    IO: AsyncRead + AsyncWrite + Send + Sync + Debug + Unpin + 'static,
    IE: Into<crate::Error>,
{
    let acceptor = NativeTlsAcceptor::new(acceptor);
    tonic_tls::incoming_inner::<IO, IE, NativeTlsAcceptor, TlsStreamWrapper<IO>>(incoming, acceptor)
}

#[derive(Debug)]
pub struct TlsStreamWrapper<S>(TlsStream<S>);

impl<S> tonic::transport::server::Connected for TlsStreamWrapper<S>
where
    S: tonic::transport::server::Connected + AsyncRead + AsyncWrite + Unpin,
{
    type ConnectInfo = SslConnectInfo<S::ConnectInfo>;

    fn connect_info(&self) -> Self::ConnectInfo {
        let inner = self.0.get_ref();
        let cert = inner.peer_certificate().ok().and_then(|opt| opt);
        let inner = inner.get_ref().get_ref().connect_info();
        Self::ConnectInfo {
            inner,
            certs: cert.map(Arc::new),
        }
    }
}

/// Connection info for SSL streams.
///
/// This type will be accessible through [request extensions](tonic::Request::extensions).
///
/// See [`Connected`](tonic::transport::server::Connected) for more details.
#[derive(Clone)]
pub struct SslConnectInfo<T> {
    inner: T,
    certs: Option<Arc<tokio_native_tls::native_tls::Certificate>>,
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
    pub fn peer_certs(&self) -> Option<Arc<tokio_native_tls::native_tls::Certificate>> {
        self.certs.clone()
    }
}

impl<S> AsyncRead for TlsStreamWrapper<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for TlsStreamWrapper<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
