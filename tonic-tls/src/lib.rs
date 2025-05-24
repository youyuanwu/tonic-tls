//! A tls adaptor for `tonic`.
//!
//! Supports various tls backend:
//! * [native_tls](tokio_native_tls::native_tls) in mod [native].
//! * [openssl](tokio_openssl) in mod [openssl].
//! * [rustls](tokio_rustls::rustls) in mod [rustls].
//! * [schannel](tokio_schannel) in mod [schannel].
//!
//! For full examples see [examples](https://github.com/youyuanwu/tonic-tls/tree/main/tonic-tls-tests/examples).
//! Server example for openssl:
//! # Examples
//! Server example:
//! ```no_run
//! # use tower::Service;
//! # use hyper::{Request, Response};
//! # use tonic::{body::Body, server::NamedService, transport::{Server, server::TcpIncoming}};
//! # use core::convert::Infallible;
//! # use std::error::Error;
//! use openssl::ssl::SslAcceptor;
//! use tonic_tls::openssl::TlsIncoming;
//! # fn main() { }  // Cannot have type parameters, hence instead define:
//! # fn run<S>(some_service: S, acceptor: SslAcceptor) -> Result<(), Box<dyn Error + Send + Sync>>
//! # where
//! #   S: Service<Request<Body>, Response = Response<Body>, Error = Infallible> + NamedService + Clone + Send + Sync + 'static,
//! #   S::Future: Send + 'static,
//! # {
//! let addr = "127.0.0.1:1322".parse().unwrap();
//! let inc = TlsIncoming::new(TcpIncoming::bind(addr).unwrap(), acceptor);
//! Server::builder()
//!    .add_service(some_service)
//!    .serve_with_incoming(inc);
//! # Ok(())
//! # }
//! ```
//! Client example:
//! ```
//! async fn connect_tonic_channel(
//!     endpoint: tonic::transport::Endpoint,
//!     ssl_conn: openssl::ssl::SslConnector
//! ) -> tonic::transport::Channel {
//!     endpoint.connect_with_connector(tonic_tls::openssl::TlsConnector::new(
//!         &endpoint,
//!         ssl_conn,
//!        "localhost".to_string(),
//!     )).await.unwrap()
//! }
//! ```
#![doc(html_root_url = "https://docs.rs/tonic-tls/latest/tonic_tls/")]

use futures::TryStreamExt;
use std::fmt::Debug;
use std::io;
use std::{ops::ControlFlow, pin::pin};

use futures::Stream;
use tokio::io::{AsyncRead, AsyncWrite};
mod client;
pub use client::{connector_inner, TlsConnector};
mod server;
use server::TlsIncoming;
mod endpoint;

#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "rustls")]
pub mod rustls;

#[cfg(feature = "openssl")]
pub mod openssl;

#[cfg(all(feature = "schannel", target_os = "windows"))]
pub mod schannel;

/// A const that contains the on the wire `h2` alpn value
/// to pass to tls backends.
pub const ALPN_H2: &[u8] = b"h2";

/// Common boxed error.
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Trait for abstracting tls backend's stream accept impl. Not intended to be used directly
/// by applications.
/// To add a new tls backend, this trait needs to be implemented, and the
/// implementation needs to be passed to [incoming_inner].
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

/// Wraps the incoming stream into a tls stream.
/// Use this only when implementing tls backends.
/// For applications, use a tls backend instead. For example [incomming](openssl::incoming).
///
/// IO is the input io type, IE is the input error type.
/// A is acceptor, TS is the output tls stream type.
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
