//! Certificate providers and reloadable TLS connectors built on `tonic-tls`.
//!
//! [`CertificateProvider`] supplies backend-neutral PEM snapshots.
//! [`ReloadableTlsConnector`] validates and caches connector/argument pairs using
//! a [`TlsConnectorFactory`], refreshing them for new TLS handshakes.
//! [`FileWatcherProvider`] polls PEM files and publishes changed snapshots without
//! validating their certificate contents.
//!
//! Enable the `rustls` feature for the built-in `rustls::TlsConnectorFactory`.
//! The provider, file watcher, and generic connector require no TLS backend feature.
//! This crate does not implement the xDS discovery protocol.

mod cert_provider;
pub use cert_provider::{CertificateData, CertificateProvider, Identity};
mod file_watcher;
pub use file_watcher::{FileWatcherConfig, FileWatcherProvider};
mod reloadable_tls_connector;
pub use reloadable_tls_connector::{ConnectorPair, ReloadableTlsConnector, TlsConnectorFactory};

#[cfg(feature = "rustls")]
pub mod rustls;
