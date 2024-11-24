use futures::Stream;
use std::{
    error::Error as StdError,
    fmt::Debug,
    pin::Pin,
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
    type ConnectInfo = <S as tonic::transport::server::Connected>::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.0.get_ref().get_ref().get_ref().connect_info()
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
