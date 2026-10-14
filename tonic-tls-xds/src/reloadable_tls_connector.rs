use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncWrite};
use tonic::transport::Uri;
use tower::Service;

use crate::{CertificateData, CertificateProvider};

/// A TLS connector paired with its backend-specific connection argument.
pub type ConnectorPair<IO, C> = (C, <C as tonic_tls::TlsConnector<IO>>::Arg);

/// Builds a backend connector and its connection argument from a PEM snapshot.
///
/// Used by [`ReloadableTlsConnector`] on a cache miss. Implementations retain their
/// base configuration and any stable connection settings. They must validate
/// the supplied material and apply backend policies such as session resumption
/// before returning a usable pair. Build errors fail construction or the
/// connection attempt.
pub trait TlsConnectorFactory<IO>: Send + Sync + 'static
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// The TLS backend, including its associated argument and stream types.
    type Connector: tonic_tls::TlsConnector<IO>;

    /// Validates and applies a snapshot, returning a connector/argument pair.
    fn build_connector(
        &self,
        data: &CertificateData,
    ) -> Result<ConnectorPair<IO, Self::Connector>, tonic_tls::Error>;
}

/// A tonic-compatible connector with provider-driven TLS credentials.
///
/// `C` selects the backend by implementing [`tonic_tls::TlsConnector<IO>`]. Its
/// associated `Arg` determines the connection argument type; arguments do not
/// need to uniquely identify a backend.
///
/// The [`TlsConnectorFactory`] returns a connector and its argument together. Both
/// are cached against the certificate snapshot and replaced together on rotation.
/// This supports backends whose rotating credentials live in the argument rather
/// than the connector. Clones share the provider, factory, and cache.
///
/// Provider and factory errors fail construction or the connection without falling back to a
/// cached pair. Existing connections are unaffected. The factory is responsible
/// for certificate validation and backend policies such as session resumption.
///
/// # Example
///
/// With the `rustls` feature:
///
/// ```no_run
/// # #[cfg(feature = "rustls")]
/// # async fn connect(
/// #     endpoint: tonic::transport::Endpoint,
/// #     config: std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
/// #     provider: std::sync::Arc<dyn tonic_tls_xds::CertificateProvider>,
/// # ) -> Result<tonic::transport::Channel, tonic_tls::Error> {
/// use tonic_tls::TcpTransport;
/// use tonic_tls_xds::ReloadableTlsConnector;
///
/// let domain = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost")?;
/// let transport = TcpTransport::from_endpoint(&endpoint);
/// let factory = tonic_tls_xds::rustls::TlsConnectorFactory::new(config, domain);
/// let connector = ReloadableTlsConnector::new(transport, provider, factory)?;
/// let channel = endpoint.connect_with_connector(connector).await?;
/// # Ok(channel)
/// # }
/// ```
pub struct ReloadableTlsConnector<IO, C>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    C: tonic_tls::TlsConnector<IO>,
{
    inner: tower::util::BoxCloneSyncService<
        Uri,
        hyper_util::rt::TokioIo<C::TlsStream>,
        tonic_tls::Error,
    >,
}

impl<IO, C> Clone for ReloadableTlsConnector<IO, C>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    C: tonic_tls::TlsConnector<IO>,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<IO, C> ReloadableTlsConnector<IO, C>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    C: tonic_tls::TlsConnector<IO>,
    C::TlsStream: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Creates a provider-backed URI service for a transport and TLS backend.
    ///
    /// Requests and validates the initial snapshot, caching the connector and
    /// argument without opening a connection. The provider must have a snapshot
    /// ready. Provider and factory errors are returned to the caller.
    ///
    /// The factory runs again when the current snapshot differs from the cached
    /// one. Return the same `Arc<CertificateData>` from the
    /// provider while material is unchanged to reuse the cached connector and
    /// argument. The cache lock is released before the TLS handshake.
    ///
    /// A snapshot is also requested before each TLS handshake, including tonic
    /// channel reconnects, so updates after construction are not missed.
    /// This connector does not start background tasks or watch files.
    pub fn new(
        transport: impl tonic_tls::Transport<Io = IO>,
        provider: Arc<dyn CertificateProvider>,
        factory: impl TlsConnectorFactory<IO, Connector = C>,
    ) -> Result<Self, tonic_tls::Error> {
        let connector = ProviderTlsConnector::new(provider, factory);
        connector.connector_pair()?;
        Ok(Self {
            inner: tonic_tls::connector_inner(transport, connector, ()),
        })
    }
}

impl<IO, C> Service<Uri> for ReloadableTlsConnector<IO, C>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    C: tonic_tls::TlsConnector<IO>,
    C::TlsStream: Send + 'static,
{
    type Response = hyper_util::rt::TokioIo<C::TlsStream>;
    type Error = tonic_tls::Error;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        self.inner.call(uri)
    }
}

struct ProviderTlsConnector<IO, F>(Arc<ProviderState<IO, F>>)
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: TlsConnectorFactory<IO>;

impl<IO, F> Clone for ProviderTlsConnector<IO, F>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: TlsConnectorFactory<IO>,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

struct ProviderState<IO, F>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: TlsConnectorFactory<IO>,
{
    provider: Arc<dyn CertificateProvider>,
    factory: F,
    cached: Mutex<Option<CachedConnectorPair<IO, F::Connector>>>,
}

struct CachedConnectorPair<IO, C>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    C: tonic_tls::TlsConnector<IO>,
{
    data: Arc<CertificateData>,
    connector_pair: ConnectorPair<IO, C>,
}

impl<IO, F> ProviderTlsConnector<IO, F>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: TlsConnectorFactory<IO>,
{
    fn new(provider: Arc<dyn CertificateProvider>, factory: F) -> Self {
        Self(Arc::new(ProviderState {
            provider,
            factory,
            cached: Mutex::new(None),
        }))
    }

    // Retrieves or builds the connector/argument pair; does not open a transport
    // or perform a TLS handshake. Custom providers/factories may do their own IO.
    fn connector_pair(&self) -> Result<ConnectorPair<IO, F::Connector>, tonic_tls::Error> {
        let data = self.0.provider.snapshot().inspect_err(|error| {
            tracing::debug!(
                error = %error,
                stage = "snapshot",
                "certificate snapshot retrieval failed",
            );
        })?;
        let mut cached = self
            .0
            .cached
            .lock()
            .map_err(|_| std::io::Error::other("certificate provider cache lock poisoned"))?;
        if let Some(cached) = cached.as_ref()
            && Arc::ptr_eq(&cached.data, &data)
        {
            return Ok(cached.connector_pair.clone());
        }

        let connector_pair = match self.0.factory.build_connector(&data) {
            Ok(connector_pair) => connector_pair,
            Err(error) => {
                drop(cached);
                tracing::debug!(
                    error = %error,
                    stage = "build_connector",
                    "TLS connector build failed",
                );
                return Err(error);
            }
        };
        let replaced = cached.is_some();
        *cached = Some(CachedConnectorPair {
            data,
            connector_pair: connector_pair.clone(),
        });
        drop(cached);
        tracing::debug!(replaced, "TLS connector rebuilt from certificate snapshot",);
        Ok(connector_pair)
    }
}

impl<IO, F> tonic_tls::TlsConnector<IO> for ProviderTlsConnector<IO, F>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: TlsConnectorFactory<IO>,
{
    type TlsStream = <F::Connector as tonic_tls::TlsConnector<IO>>::TlsStream;
    type Arg = ();

    async fn connect(
        &self,
        (): Self::Arg,
        stream: IO,
    ) -> Result<Self::TlsStream, tonic_tls::Error> {
        let (connector, arg) = self.connector_pair()?;
        connector.connect(arg, stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    struct TestProvider {
        data: Mutex<Result<Arc<CertificateData>, &'static str>>,
        snapshot_calls: AtomicUsize,
    }

    impl TestProvider {
        fn new(data: Arc<CertificateData>) -> Arc<Self> {
            Arc::new(Self {
                data: Mutex::new(Ok(data)),
                snapshot_calls: AtomicUsize::new(0),
            })
        }
    }

    impl CertificateProvider for TestProvider {
        fn snapshot(&self) -> Result<Arc<CertificateData>, tonic_tls::Error> {
            self.snapshot_calls.fetch_add(1, Ordering::Relaxed);
            match self.data.lock().unwrap().as_ref() {
                Ok(data) => Ok(data.clone()),
                Err(message) => Err(std::io::Error::other(*message).into()),
            }
        }
    }

    #[derive(Clone, Debug)]
    struct TestConnector(u8);

    impl tonic_tls::TlsConnector<DuplexStream> for TestConnector {
        type TlsStream = DuplexStream;
        type Arg = u8;

        async fn connect(
            &self,
            arg: u8,
            mut stream: DuplexStream,
        ) -> Result<Self::TlsStream, tonic_tls::Error> {
            if arg == 0 {
                return Err(std::io::Error::other("handshake failed").into());
            }
            stream.write_all(&[self.0, arg]).await?;
            Ok(stream)
        }
    }

    #[derive(Clone)]
    struct TestTransport(mpsc::Sender<DuplexStream>);

    impl tonic_tls::Transport for TestTransport {
        type Io = DuplexStream;
        type Error = std::io::Error;

        async fn connect(&self, _: &Uri) -> Result<Self::Io, Self::Error> {
            let (stream, peer) = tokio::io::duplex(16);
            self.0
                .send(peer)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
            Ok(stream)
        }
    }

    // Fake certificate bytes encode the [version, argument] echoed by the handshake.
    // Version 0 rejects the build; argument 0 rejects the handshake.
    fn snapshot(version: u8, arg: u8) -> Arc<CertificateData> {
        Arc::new(CertificateData::RootsOnly {
            roots: vec![version, arg],
        })
    }

    struct TestFactory(Arc<AtomicUsize>);

    impl TlsConnectorFactory<DuplexStream> for TestFactory {
        type Connector = TestConnector;

        fn build_connector(
            &self,
            data: &CertificateData,
        ) -> Result<(TestConnector, u8), tonic_tls::Error> {
            self.0.fetch_add(1, Ordering::Relaxed);
            let version = data.roots().unwrap()[0];
            if version == 0 {
                return Err(std::io::Error::other("invalid certificate data").into());
            }
            Ok((TestConnector(version), data.roots().unwrap()[1]))
        }
    }

    #[test]
    fn errors_do_not_fall_back_or_replace_cached_pair() {
        let good = snapshot(1, 41);
        let provider = TestProvider::new(good.clone());
        let builds = Arc::new(AtomicUsize::new(0));
        let connector = ProviderTlsConnector::new(provider.clone(), TestFactory(builds.clone()));
        let (backend, arg) = connector.connector_pair().unwrap();
        assert_eq!((backend.0, arg), (1, 41));

        *provider.data.lock().unwrap() = Err("provider unavailable");
        assert_eq!(
            connector.connector_pair().unwrap_err().to_string(),
            "provider unavailable",
        );
        assert_eq!(builds.load(Ordering::Relaxed), 1);

        *provider.data.lock().unwrap() = Ok(snapshot(0, 99));
        assert_eq!(
            connector.connector_pair().unwrap_err().to_string(),
            "invalid certificate data",
        );
        assert_eq!(builds.load(Ordering::Relaxed), 2);

        // Restoring the original Arc must reuse the cached pair without rebuilding.
        *provider.data.lock().unwrap() = Ok(good);
        let (backend, arg) = connector.connector_pair().unwrap();
        assert_eq!((backend.0, arg), (1, 41));
        assert_eq!(builds.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn construction_rejects_provider_and_factory_errors_without_connecting() {
        for (data, message, expected_builds) in [
            (Err("provider unavailable"), "provider unavailable", 0),
            (Ok(snapshot(0, 99)), "invalid certificate data", 1),
        ] {
            let provider = TestProvider::new(snapshot(1, 41));
            *provider.data.lock().unwrap() = data;
            let builds = Arc::new(AtomicUsize::new(0));
            let (tx, rx) = mpsc::channel();
            let error = ReloadableTlsConnector::new(
                TestTransport(tx),
                provider.clone(),
                TestFactory(builds.clone()),
            )
            .err()
            .expect("construction should reject an unavailable or invalid snapshot");

            assert_eq!(error.to_string(), message);
            assert_eq!(provider.snapshot_calls.load(Ordering::Relaxed), 1);
            assert_eq!(builds.load(Ordering::Relaxed), expected_builds);
            assert!(rx.try_recv().is_err());
        }
    }

    // Buffered in-memory IO completes immediately, so no Tokio runtime is needed.
    #[test]
    fn public_service_caches_and_rotates_pairs_across_clones() {
        let provider = TestProvider::new(snapshot(1, 41));
        let builds = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel();
        let mut connector = ReloadableTlsConnector::new(
            TestTransport(tx),
            provider.clone(),
            TestFactory(builds.clone()),
        )
        .unwrap();
        let mut cloned = connector.clone();
        // Construction primes the shared cache without transport IO; cloning is lazy.
        assert_eq!(provider.snapshot_calls.load(Ordering::Relaxed), 1);
        assert_eq!(builds.load(Ordering::Relaxed), 1);
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        let uri = Uri::from_static("https://localhost");
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            connector.poll_ready(&mut cx),
            std::task::Poll::Ready(Ok(()))
        ));
        // Reuse the initial Arc, then rotate the argument alone and both values.
        // Each round adds two provider reads but builds only for new snapshots.
        for (round, (version, arg)) in [(1, 41), (1, 42), (2, 43)].into_iter().enumerate() {
            if round > 0 {
                *provider.data.lock().unwrap() = Ok(snapshot(version, arg));
            }
            for service in [&mut connector, &mut cloned] {
                let mut stream = service
                    .call(uri.clone())
                    .now_or_never()
                    .unwrap()
                    .unwrap()
                    .into_inner();
                let mut peer = rx.try_recv().unwrap();
                let mut header = [0; 2];
                peer.read_exact(&mut header)
                    .now_or_never()
                    .unwrap()
                    .unwrap();
                assert_eq!(header, [version, arg]);
                peer.write_all(b"hello").now_or_never().unwrap().unwrap();
                let mut bytes = [0; 5];
                stream
                    .read_exact(&mut bytes)
                    .now_or_never()
                    .unwrap()
                    .unwrap();
                assert_eq!(&bytes, b"hello");
            }
            assert_eq!(builds.load(Ordering::Relaxed), round + 1);
            assert_eq!(
                provider.snapshot_calls.load(Ordering::Relaxed),
                1 + 2 * (round + 1)
            );
        }

        *provider.data.lock().unwrap() = Ok(snapshot(3, 0));
        assert_eq!(
            connector
                .call(uri)
                .now_or_never()
                .unwrap()
                .unwrap_err()
                .to_string(),
            "handshake failed",
        );
        assert_eq!(builds.load(Ordering::Relaxed), 4);
        assert_eq!(provider.snapshot_calls.load(Ordering::Relaxed), 8);
    }
}
