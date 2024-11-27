use futures::TryStreamExt;
use std::fmt::Debug;
use std::io;
use std::{ops::ControlFlow, pin::pin};

use futures::Stream;
use tokio::io::{AsyncRead, AsyncWrite};
mod client;
pub use client::{connector_inner, new_endpoint, TlsConnector};

#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "rustls")]
pub mod rustls;

#[cfg(feature = "openssl")]
pub mod openssl;

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

pub trait TlsAcceptor<S>: Clone + Send + 'static
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type TlsStream;
    fn accept(
        &self,
        stream: S,
    ) -> impl std::future::Future<Output = Result<Self::TlsStream, Error>> + Send;
}

/// A is acceptor, TS is the tls stream type.
pub fn incoming_inner<IO, IE, A, TS>(
    incoming: impl Stream<Item = Result<IO, IE>>,
    acceptor: A,
) -> impl Stream<Item = Result<TS, Error>>
where
    IO: AsyncRead + AsyncWrite + Send + Sync + Debug + Unpin + 'static,
    IE: Into<crate::Error>,
    A: TlsAcceptor<IO, TlsStream = TS>,
    TS: Send + 'static,
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
                            Ok(io)
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

async fn select<IO: 'static, IE, TS: 'static>(
    incoming: &mut (impl Stream<Item = Result<IO, IE>> + Unpin),
    tasks: &mut tokio::task::JoinSet<Result<TS, crate::Error>>,
) -> SelectOutput<IO, TS>
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
enum SelectOutput<A, TS> {
    Incoming(A),
    Io(TS),
    TcpErr(crate::Error),
    TlsErr(crate::Error),
    Done,
}
