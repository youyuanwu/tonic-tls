//! Certificate providers and reloadable TLS connectors/acceptors built on `tonic-tls`.
//!
//! [`CertificateProvider`] supplies backend-neutral certificate and CRL PEM snapshots.
//! [`ReloadableTlsConnector`] validates and caches connector/argument pairs using
//! a [`TlsConnectorFactory`], refreshing them for new TLS handshakes.
//! [`ReloadableTlsAcceptor`] does the same for servers using a [`TlsAcceptorFactory`].
//! [`FileWatcherProvider`] polls PEM files and publishes changed snapshots without
//! validating their certificate contents.
//!
//! Enable the `rustls` feature for the built-in `rustls::TlsConnectorFactory`.
//! It also provides `rustls::TlsAcceptorFactory` for server identity, client CA,
//! and client-certificate CRL rotation with [`ServerConfig`].
//! Enable `openssl` for `openssl::TlsConnectorFactory` and
//! `openssl::TlsAcceptorFactory` (OpenSSL 1.1.1 or newer). Both server backends
//! use the same [`ServerConfig`] and provider snapshots.
//! Providers and generic connector/acceptor APIs require no TLS backend feature.
//! This crate does not implement the xDS discovery protocol.

mod client;
mod provider;
mod server;

pub use client::{ConnectorPair, ReloadableTlsConnector, TlsConnectorFactory};
pub use provider::{
    CertificateData, CertificateProvider, CrlSelection, CrlSource, FileWatcherConfig,
    FileWatcherProvider, Identity,
};
pub use server::{ClientAuth, ReloadableTlsAcceptor, ServerConfig, TlsAcceptorFactory};

#[cfg(feature = "rustls")]
pub mod rustls;

#[cfg(feature = "openssl")]
pub mod openssl;

#[cfg(any(feature = "rustls", feature = "openssl"))]
pub(crate) fn invalid_input(message: &str) -> tonic_tls::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into()
}
