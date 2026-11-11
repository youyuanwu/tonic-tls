//! Rustls adapters for provider-driven TLS connections and accepts.

mod client;
mod common;
mod server;

pub use client::{TlsConnector, TlsConnectorFactory, build_client_config};
pub use server::{TlsAcceptor, TlsAcceptorFactory};
