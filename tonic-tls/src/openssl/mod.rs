use futures::Stream;
use openssl::{ssl::SslAcceptor, x509::X509};
use std::fmt::Debug;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::Connected;

mod client;
pub use client::connector;

/// A const that contains the on the wire `h2` alpn
/// value that can be passed directly to OpenSSL.
pub const ALPN_H2_WIRE: &[u8] = b"\x02h2";

#[derive(Clone)]
struct OpensslTlsAcceptor(SslAcceptor);

impl OpensslTlsAcceptor {
    fn new(inner: SslAcceptor) -> Self {
        Self(inner)
    }
}

impl<S> crate::TlsAcceptor<S> for OpensslTlsAcceptor
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type TlsStream = SslStream<S>;
    async fn accept(&self, stream: S) -> Result<SslStream<S>, crate::Error> {
        let ssl = openssl::ssl::Ssl::new(self.0.context())?;
        let mut tls = tokio_openssl::SslStream::new(ssl, stream)?;
        Pin::new(&mut tls).accept().await?;
        Ok(SslStream { inner: tls })
    }
}

pub fn incoming<IO, IE>(
    incoming: impl Stream<Item = Result<IO, IE>>,
    acceptor: SslAcceptor,
) -> impl Stream<Item = Result<SslStream<IO>, crate::Error>>
where
    IO: AsyncRead + AsyncWrite + Send + Sync + Debug + Unpin + 'static,
    IE: Into<crate::Error>,
{
    let acceptor = OpensslTlsAcceptor::new(acceptor);
    crate::incoming_inner::<IO, IE, OpensslTlsAcceptor, SslStream<IO>>(incoming, acceptor)
}

/// A `SslStream` wrapper type that implements tokio's io traits
/// and tonic's `Connected` trait.
#[derive(Debug)]
pub struct SslStream<S> {
    inner: tokio_openssl::SslStream<S>,
}

impl<S: Connected> Connected for SslStream<S> {
    type ConnectInfo = SslConnectInfo<S::ConnectInfo>;

    fn connect_info(&self) -> Self::ConnectInfo {
        let inner = self.inner.get_ref().connect_info();

        // Currently openssl rust does not support clone of objects
        // So we need to reparse the X509 certs.
        // See: https://github.com/sfackler/rust-openssl/issues/1112
        let ssl = self.inner.ssl();
        let certs = ssl
            .verified_chain()
            .map(|certs| {
                certs
                    .iter()
                    .filter_map(|c| c.to_pem().ok())
                    .filter_map(|p| X509::from_pem(&p).ok())
                    .collect()
            })
            .map(Arc::new);

        SslConnectInfo { inner, certs }
    }
}

impl<S> AsyncRead for SslStream<S>
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

impl<S> AsyncWrite for SslStream<S>
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
/// See [`Connected`](tonic::transport::server::Connected) for more details.
#[derive(Debug, Clone)]
pub struct SslConnectInfo<T> {
    inner: T,
    certs: Option<Arc<Vec<X509>>>,
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
    pub fn peer_certs(&self) -> Option<Arc<Vec<X509>>> {
        self.certs.clone()
    }
}
