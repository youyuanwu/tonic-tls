//! OpenSSL adapters for provider-driven TLS connections and accepts.

mod client;
mod common;
mod server;

pub use client::{ClientConfig, TlsConnector, TlsConnectorFactory};
pub use server::{TlsAcceptor, TlsAcceptorFactory};
