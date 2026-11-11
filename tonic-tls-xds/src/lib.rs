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

mod cert_provider;
pub use cert_provider::{CertificateData, CertificateProvider, CrlSelection, Identity};
mod file_watcher;
pub use file_watcher::{CrlSource, FileWatcherConfig, FileWatcherProvider};
mod reloadable_tls_connector;
pub use reloadable_tls_connector::{ConnectorPair, ReloadableTlsConnector, TlsConnectorFactory};
mod server_config;
pub use server_config::{ClientAuth, ServerConfig};
mod reloadable_tls_acceptor;
pub use reloadable_tls_acceptor::{ReloadableTlsAcceptor, TlsAcceptorFactory};

#[cfg(feature = "rustls")]
pub mod rustls;

#[cfg(feature = "openssl")]
pub mod openssl;
