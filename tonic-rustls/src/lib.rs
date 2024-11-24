use futures::{Stream, TryStreamExt};
use rustls::pki_types::CertificateDer;
use std::{
    fmt::Debug,
    io,
    ops::ControlFlow,
    pin::{pin, Pin},
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::Connected;

mod client;
pub use client::{connector, new_endpoint};

/// Wrapper error type.
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

pub fn incoming<IO, IE>(
    incoming: impl Stream<Item = Result<IO, IE>>,
    acceptor: tokio_rustls::TlsAcceptor,
) -> impl Stream<Item = Result<TlsStream<IO>, Error>>
where
    IO: AsyncRead + AsyncWrite + Send + Sync + Debug + Unpin + 'static,
    IE: Into<crate::Error>,
{
    async_stream::try_stream! {
        let mut incoming = pin!(incoming);

        let mut tasks = tokio::task::JoinSet::new();

        loop {
            match select(&mut incoming, &mut tasks).await {
                SelectOutput::Incoming(stream) => {
                        let tls = acceptor.clone();
                        tasks.spawn(async move {
                            let io = tls.accept(stream).await?;
                            Ok(TlsStream{inner: io})
                        });
                }

                SelectOutput::Io(io) => {
                    yield io;
                }

                SelectOutput::TcpErr(e) => match handle_tcp_accept_error(e) {
                    ControlFlow::Continue(()) => continue,
                    ControlFlow::Break(e) => Err(e)?,
                }

                SelectOutput::TlsErr(e) => {
                    tracing::debug!(error = %e, "tls accept error");
                    continue;
                }

                SelectOutput::Done => {
                    break;
                }
            }
        }
    }
}

async fn select<IO: 'static, IE>(
    incoming: &mut (impl Stream<Item = Result<IO, IE>> + Unpin),
    tasks: &mut tokio::task::JoinSet<Result<TlsStream<IO>, crate::Error>>,
) -> SelectOutput<IO>
where
    IE: Into<crate::Error>,
{
    let incoming_stream_future = async {
        match incoming.try_next().await {
            Ok(Some(stream)) => SelectOutput::Incoming(stream),
            Ok(None) => SelectOutput::Done,
            Err(e) => SelectOutput::TcpErr(e.into()),
        }
    };

    if tasks.is_empty() {
        return incoming_stream_future.await;
    }

    tokio::select! {
        stream = incoming_stream_future => stream,
        accept = tasks.join_next() => {
            match accept.expect("JoinSet should never end") {
                Ok(Ok(io)) => SelectOutput::Io(io),
                Ok(Err(e)) => SelectOutput::TlsErr(e),
                Err(e) => SelectOutput::TlsErr(e.into()),
            }
        }
    }
}

fn handle_tcp_accept_error(e: impl Into<crate::Error>) -> ControlFlow<crate::Error> {
    let e = e.into();
    tracing::debug!(error = %e, "accept loop error");
    if let Some(e) = e.downcast_ref::<io::Error>() {
        if matches!(
            e.kind(),
            io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::Interrupted
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
        ) {
            return ControlFlow::Continue(());
        }
    }

    ControlFlow::Break(e)
}

#[allow(clippy::large_enum_variant)]
enum SelectOutput<A> {
    Incoming(A),
    Io(TlsStream<A>),
    TcpErr(crate::Error),
    TlsErr(crate::Error),
    Done,
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
/// See [`Connected`](tonic::transport::server::Connected) for more details.
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
