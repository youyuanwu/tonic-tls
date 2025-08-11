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

mod client;
pub use client::{TlsConnector, connector_inner};
mod endpoint;
mod server;
pub use server::{TlsAcceptor, incoming_inner};

#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "rustls")]
pub mod rustls;

#[cfg(feature = "openssl")]
pub mod openssl;

#[cfg(all(feature = "openssl-ktls", target_os = "linux"))]
pub mod openssl_ktls;

#[cfg(all(feature = "schannel", target_os = "windows"))]
pub mod schannel;

/// A const that contains the on the wire `h2` alpn value
/// to pass to tls backends.
pub const ALPN_H2: &[u8] = b"h2";

/// Common boxed error.
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
