mod client;
pub use client::TlsConnector;
mod server;
pub use server::TlsIncoming;
mod stream;
pub use stream::{SslConnectInfo, SslStream};

/// A const that contains the on the wire `h2` alpn
/// value that can be passed directly to OpenSSL.
pub const ALPN_H2_WIRE: &[u8] = b"\x02h2";
