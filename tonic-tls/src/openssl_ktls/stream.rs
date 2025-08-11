use openssl::x509::X509;
use std::fmt::Debug;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::{Connected, TcpConnectInfo};

/// A `SslStream` wrapper type that implements tokio's io traits
/// and tonic's [Connected] trait.
#[derive(Debug)]
pub struct SslStream {
    inner: openssl_ktls::TokioSslStream,
}

impl SslStream {
    pub fn new(inner: openssl_ktls::TokioSslStream) -> Self {
        Self { inner }
    }
}

impl Connected for SslStream {
    type ConnectInfo = SslConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        let inner = self.inner.get_ref();
        let info = TcpConnectInfo {
            local_addr: inner.local_addr().ok(),
            remote_addr: inner.peer_addr().ok(),
        };

        // Currently openssl rust does not support clone of objects
        // So we need to reparse the X509 certs.
        // See: https://github.com/sfackler/rust-openssl/issues/1112
        let ssl = self.inner.ssl();
        let certs = ssl
            .verified_chain()
            .map(|certs| {
                certs
                    .iter()
                    .filter_map(|c| c.to_pem().ok())
                    .filter_map(|p| X509::from_pem(&p).ok())
                    .collect()
            })
            .map(Arc::new);

        SslConnectInfo { inner: info, certs }
    }
}

impl AsyncRead for SslStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SslStream {
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
/// See [`Connected`] for more details.
#[derive(Debug, Clone)]
pub struct SslConnectInfo {
    inner: TcpConnectInfo,
    certs: Option<Arc<Vec<X509>>>,
}

impl SslConnectInfo {
    /// Get a reference to the underlying connection info.
    pub fn get_ref(&self) -> &TcpConnectInfo {
        &self.inner
    }

    /// Get a mutable reference to the underlying connection info.
    pub fn get_mut(&mut self) -> &mut TcpConnectInfo {
        &mut self.inner
    }

    /// Return the set of connected peer SSL certificates.
    pub fn peer_certs(&self) -> Option<Arc<Vec<X509>>> {
        self.certs.clone()
    }
}
