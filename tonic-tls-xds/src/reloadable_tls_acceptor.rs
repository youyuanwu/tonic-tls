use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{CertificateData, CertificateProvider};

/// Builds an immutable server TLS acceptor from one certificate snapshot.
///
/// Implementations must apply or reject every supplied component, validate the
/// effective server identity, and enforce their client authentication policy.
/// CRLs must follow [`CertificateData::crls`]. Session resumption must not bypass
/// current identity, trust, or revocation checks. Custom factories are responsible
/// for preserving these guarantees.
pub trait TlsAcceptorFactory<IO>: Send + Sync + 'static
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Acceptor: tonic_tls::TlsAcceptor<IO>;

    /// Validates and applies a snapshot without starting a TLS handshake.
    fn build_acceptor(&self, data: &CertificateData) -> Result<Self::Acceptor, tonic_tls::Error>;
}

/// A provider-backed TLS acceptor for tonic incoming streams or raw Tokio IO.
///
/// Clones share a provider, factory, and cache keyed by snapshot `Arc` identity.
/// Selection and construction are serialized; the mutex is released before
/// starting a handshake. In-flight handshakes and established connections keep
/// their selected configuration. Rotation does not reauthenticate existing RPCs.
///
/// Provider or build errors fail the accept, without using an older cached
/// acceptor or allowing anonymous TLS. Later valid snapshots allow recovery.
/// This adapter does not poll files, limit concurrent handshakes, impose timeouts,
/// or retire old connections.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "rustls")]
/// # fn incoming(
/// #     provider: std::sync::Arc<dyn tonic_tls_xds::CertificateProvider>,
/// #     tcp_incoming: tonic::transport::server::TcpIncoming,
/// #     crypto: std::sync::Arc<tokio_rustls::rustls::crypto::CryptoProvider>,
/// # ) -> Result<(), tonic_tls::Error> {
/// use tonic_tls_xds::{ClientAuth, ReloadableTlsAcceptor, ServerConfig};
///
/// // The provider must supply the server identity and client trust roots.
/// let config = ServerConfig::default().with_client_auth(ClientAuth::Required);
/// let factory = tonic_tls_xds::rustls::TlsAcceptorFactory::new(config, crypto);
/// let acceptor = ReloadableTlsAcceptor::new(provider, factory)?;
/// let incoming = acceptor.incoming(tcp_incoming);
/// // Pass incoming to tonic::transport::Server::serve_with_incoming.
/// # let _ = incoming;
/// # Ok(())
/// # }
/// ```
///
/// For raw IO, import [`tonic_tls::TlsAcceptor`] and call `acceptor.accept(io)`.
pub struct ReloadableTlsAcceptor<IO, F>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: TlsAcceptorFactory<IO>,
{
    state: Arc<ProviderState<IO, F>>,
}

struct ProviderState<IO, F>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: TlsAcceptorFactory<IO>,
{
    provider: Arc<dyn CertificateProvider>,
    factory: F,
    cached: Mutex<Option<CachedAcceptor<F::Acceptor>>>,
}

struct CachedAcceptor<A> {
    data: Arc<CertificateData>,
    acceptor: A,
}

impl<IO, F> Clone for ReloadableTlsAcceptor<IO, F>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: TlsAcceptorFactory<IO>,
{
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<IO, F> ReloadableTlsAcceptor<IO, F>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: TlsAcceptorFactory<IO>,
{
    /// Validates the initial snapshot and primes the cache without accepting IO.
    ///
    /// The provider must already have material available. On each accept, it is
    /// sampled again when the accept future starts executing, not when the TCP
    /// socket is accepted. Unchanged snapshot `Arc`s reuse the parsed acceptor.
    pub fn new(
        provider: Arc<dyn CertificateProvider>,
        factory: F,
    ) -> Result<Self, tonic_tls::Error> {
        let acceptor = Self {
            state: Arc::new(ProviderState {
                provider,
                factory,
                cached: Mutex::new(None),
            }),
        };
        acceptor.current_acceptor()?;
        Ok(acceptor)
    }

    /// Wraps an incoming transport stream using the core concurrent accept loop.
    ///
    /// Individual provider, build, and TLS failures are logged and drop only that
    /// connection. Incoming transport errors retain the core loop's behavior.
    /// Backend stream wrappers preserve tonic's peer-certificate connection info.
    pub fn incoming(
        self,
        incoming: impl tonic_tls::Incoming<Io = IO>,
    ) -> futures::stream::BoxStream<
        'static,
        Result<<F::Acceptor as tonic_tls::TlsAcceptor<IO>>::TlsStream, tonic_tls::Error>,
    >
    where
        <F::Acceptor as tonic_tls::TlsAcceptor<IO>>::TlsStream: Send + 'static,
    {
        tonic_tls::incoming_inner(incoming, self)
    }

    fn current_acceptor(&self) -> Result<F::Acceptor, tonic_tls::Error> {
        let mut cached = self.state.cached.lock().map_err(|_| {
            std::io::Error::other("certificate provider acceptor cache lock poisoned")
        })?;
        // Sample under the lock so an older selection cannot replace a newer one.
        let data = match self.state.provider.snapshot() {
            Ok(data) => data,
            Err(error) => {
                drop(cached);
                tracing::debug!(
                    error = %error,
                    stage = "snapshot",
                    "certificate snapshot retrieval failed",
                );
                return Err(error);
            }
        };
        if let Some(cached) = cached.as_ref()
            && Arc::ptr_eq(&cached.data, &data)
        {
            return Ok(cached.acceptor.clone());
        }
        let acceptor = match self.state.factory.build_acceptor(&data) {
            Ok(acceptor) => acceptor,
            Err(error) => {
                drop(cached);
                tracing::debug!(
                    error = %error,
                    stage = "build_acceptor",
                    "TLS acceptor build failed",
                );
                return Err(error);
            }
        };
        let replaced = cached.is_some();
        *cached = Some(CachedAcceptor {
            data,
            acceptor: acceptor.clone(),
        });
        drop(cached);
        tracing::debug!(replaced, "TLS acceptor rebuilt from certificate snapshot");
        Ok(acceptor)
    }
}

impl<IO, F> tonic_tls::TlsAcceptor<IO> for ReloadableTlsAcceptor<IO, F>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: TlsAcceptorFactory<IO>,
{
    type TlsStream = <F::Acceptor as tonic_tls::TlsAcceptor<IO>>::TlsStream;

    async fn accept(&self, stream: IO) -> Result<Self::TlsStream, tonic_tls::Error> {
        self.current_acceptor()?.accept(stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tonic_tls::TlsAcceptor;

    struct TestProvider {
        data: Mutex<Result<Arc<CertificateData>, &'static str>>,
        calls: AtomicUsize,
    }

    impl TestProvider {
        fn new(data: Arc<CertificateData>) -> Arc<Self> {
            Arc::new(Self {
                data: Mutex::new(Ok(data)),
                calls: AtomicUsize::new(0),
            })
        }
    }

    impl CertificateProvider for TestProvider {
        fn snapshot(&self) -> Result<Arc<CertificateData>, tonic_tls::Error> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            match self.data.lock().unwrap().as_ref() {
                Ok(data) => Ok(data.clone()),
                Err(message) => Err(std::io::Error::other(*message).into()),
            }
        }
    }

    #[derive(Clone, Debug)]
    struct TestAcceptor(u8);

    impl TlsAcceptor<DuplexStream> for TestAcceptor {
        type TlsStream = DuplexStream;

        async fn accept(&self, mut stream: DuplexStream) -> Result<DuplexStream, tonic_tls::Error> {
            stream.write_all(&[self.0]).await?;
            stream.read_u8().await?;
            Ok(stream)
        }
    }

    struct TestFactory(Arc<AtomicUsize>);

    impl TlsAcceptorFactory<DuplexStream> for TestFactory {
        type Acceptor = TestAcceptor;

        fn build_acceptor(&self, data: &CertificateData) -> Result<TestAcceptor, tonic_tls::Error> {
            self.0.fetch_add(1, Ordering::Relaxed);
            let version = data.roots().unwrap()[0];
            if version == 0 {
                return Err(std::io::Error::other("invalid server identity").into());
            }
            Ok(TestAcceptor(version))
        }
    }

    fn snapshot(version: u8) -> Arc<CertificateData> {
        Arc::new(CertificateData::new(Some(vec![version]), None, None).unwrap())
    }

    #[test]
    fn published_errors_fail_accepts_without_using_cached_credentials() {
        let good = snapshot(1);
        let provider = TestProvider::new(good.clone());
        let builds = Arc::new(AtomicUsize::new(0));
        let acceptor =
            ReloadableTlsAcceptor::new(provider.clone(), TestFactory(builds.clone())).unwrap();
        assert_eq!(builds.load(Ordering::Relaxed), 1);

        for (failure, message) in [
            (Err("provider unavailable"), "provider unavailable"),
            (Ok(snapshot(0)), "invalid server identity"),
        ] {
            *provider.data.lock().unwrap() = failure;
            for _ in 0..2 {
                let (stream, mut peer) = tokio::io::duplex(16);
                let error = acceptor.accept(stream).now_or_never().unwrap().unwrap_err();
                assert_eq!(error.to_string(), message);
                assert!(error.downcast_ref::<std::io::Error>().is_some());
                assert_eq!(
                    peer.read_u8().now_or_never().unwrap().unwrap_err().kind(),
                    std::io::ErrorKind::UnexpectedEof
                );
            }
            *provider.data.lock().unwrap() = Ok(good.clone());
            assert_eq!(acceptor.current_acceptor().unwrap().0, 1);
        }
        // A bad published snapshot is retried, but restoring the original Arc reuses it.
        assert_eq!(builds.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn clones_share_cache_and_selection_happens_when_polled() {
        let provider = TestProvider::new(snapshot(1));
        let builds = Arc::new(AtomicUsize::new(0));
        let acceptor =
            ReloadableTlsAcceptor::new(provider.clone(), TestFactory(builds.clone())).unwrap();
        let cloned = acceptor.clone();
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
        for version in 1..=3 {
            let (stream, mut peer) = tokio::io::duplex(16);
            let future = cloned.accept(stream);
            if version > 1 {
                *provider.data.lock().unwrap() = Ok(snapshot(version));
            }
            peer.write_all(&[1]).now_or_never().unwrap().unwrap();
            let _stream = future.now_or_never().unwrap().unwrap();
            assert_eq!(peer.read_u8().now_or_never().unwrap().unwrap(), version);
            assert_eq!(acceptor.current_acceptor().unwrap().0, version);
            assert_eq!(builds.load(Ordering::Relaxed), usize::from(version));
        }
    }

    #[tokio::test]
    async fn pending_handshake_keeps_snapshot_and_does_not_hold_selection_lock() {
        let provider = TestProvider::new(snapshot(1));
        let builds = Arc::new(AtomicUsize::new(0));
        let acceptor =
            ReloadableTlsAcceptor::new(provider.clone(), TestFactory(builds.clone())).unwrap();
        let (stream, mut peer) = tokio::io::duplex(16);
        let cloned = acceptor.clone();
        let pending = tokio::spawn(async move { cloned.accept(stream).await.unwrap() });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            assert_eq!(peer.read_u8().await.unwrap(), 1);
            *provider.data.lock().unwrap() = Ok(snapshot(2));
            let (new_stream, mut new_peer) = tokio::io::duplex(16);
            new_peer.write_all(&[1]).await.unwrap();
            let _new_stream = acceptor.accept(new_stream).await.unwrap();
            assert_eq!(new_peer.read_u8().await.unwrap(), 2);
            assert_eq!(builds.load(Ordering::Relaxed), 2);
            drop(acceptor);
            drop(provider);
            peer.write_all(&[1]).await.unwrap();
            let mut established = pending.await.unwrap();
            peer.write_all(b"alive").await.unwrap();
            let mut bytes = [0; 5];
            established.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"alive");
        })
        .await
        .expect("handshake held the selection lock or lost its snapshot");
    }

    #[test]
    fn snapshot_sampling_is_serialized_with_cache_replacement() {
        use std::{sync::mpsc, time::Duration};

        struct BlockingProvider {
            data: Mutex<Arc<CertificateData>>,
            calls: AtomicUsize,
            entered: mpsc::Sender<()>,
            release: Mutex<mpsc::Receiver<()>>,
        }
        impl CertificateProvider for BlockingProvider {
            fn snapshot(&self) -> Result<Arc<CertificateData>, tonic_tls::Error> {
                let data = self.data.lock().unwrap().clone();
                if self.calls.fetch_add(1, Ordering::Relaxed) == 1 {
                    self.entered.send(()).unwrap();
                    self.release
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap();
                }
                Ok(data)
            }
        }
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let provider = Arc::new(BlockingProvider {
            data: Mutex::new(snapshot(1)),
            calls: AtomicUsize::new(0),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        });
        let builds = Arc::new(AtomicUsize::new(0));
        let acceptor = ReloadableTlsAcceptor::<DuplexStream, _>::new(
            provider.clone(),
            TestFactory(builds.clone()),
        )
        .unwrap();
        std::thread::scope(|scope| {
            let older = scope.spawn(|| acceptor.current_acceptor().unwrap().0);
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(acceptor.state.cached.try_lock().is_err());
            *provider.data.lock().unwrap() = snapshot(2);
            let newer = scope.spawn(|| acceptor.current_acceptor().unwrap().0);
            release_tx.send(()).unwrap();
            assert_eq!(older.join().unwrap(), 1);
            assert_eq!(newer.join().unwrap(), 2);
        });
        assert_eq!(acceptor.current_acceptor().unwrap().0, 2);
        assert_eq!(builds.load(Ordering::Relaxed), 2);
    }
}
