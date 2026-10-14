use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{CertificateData, CertificateProvider, Identity};

/// PEM file paths and polling interval for [`FileWatcherProvider`].
///
/// Configure roots, an identity, or both. Certificate and private-key paths must
/// be supplied together. The default interval is 600 seconds.
#[derive(Clone, Debug)]
pub struct FileWatcherConfig {
    /// PEM trust bundle used to validate peers.
    pub ca_certificate_file: Option<PathBuf>,
    /// PEM identity certificate chain, leaf first.
    pub certificate_file: Option<PathBuf>,
    /// PEM private key for the identity.
    pub private_key_file: Option<PathBuf>,
    /// Nonzero polling interval; defaults to 600 seconds.
    pub refresh_interval: Duration,
}

impl Default for FileWatcherConfig {
    fn default() -> Self {
        Self {
            ca_certificate_file: None,
            certificate_file: None,
            private_key_file: None,
            refresh_interval: Duration::from_secs(600),
        }
    }
}

impl FileWatcherConfig {
    fn validate(&self) -> Result<(), tonic_tls::Error> {
        let message = if self.certificate_file.is_some() != self.private_key_file.is_some() {
            Some("certificate_file and private_key_file must be supplied together")
        } else if self.ca_certificate_file.is_none() && self.certificate_file.is_none() {
            Some("at least one CA certificate file or identity must be configured")
        } else if self.refresh_interval.is_zero() {
            Some("refresh_interval must be greater than zero")
        } else if tokio::time::Instant::now()
            .checked_add(self.refresh_interval)
            .is_none()
        {
            Some("refresh_interval is too large")
        } else {
            None
        };
        match message {
            Some(message) => {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into())
            }
            None => Ok(()),
        }
    }

    async fn read(&self) -> Result<CertificateData, tonic_tls::Error> {
        let roots = match &self.ca_certificate_file {
            Some(path) => Some(read_file(path).await?),
            None => None,
        };
        let identity = match (&self.certificate_file, &self.private_key_file) {
            (Some(cert), Some(key)) => Some(Identity::from_pem(
                read_file(cert).await?,
                read_file(key).await?,
            )),
            (None, None) => None,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "certificate_file and private_key_file must be supplied together",
                )
                .into());
            }
        };
        match (roots, identity) {
            (Some(roots), Some(identity)) => Ok(CertificateData::Both { roots, identity }),
            (Some(roots), None) => Ok(CertificateData::RootsOnly { roots }),
            (None, Some(identity)) => Ok(CertificateData::IdentityOnly { identity }),
            (None, None) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "at least one CA certificate file or identity must be configured",
            )
            .into()),
        }
    }
}

async fn read_file(path: &Path) -> Result<Vec<u8>, tonic_tls::Error> {
    tokio::fs::read(path).await.map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "failed to read certificate file '{}': {error}",
                path.display()
            ),
        )
        .into()
    })
}

/// A backend-neutral certificate provider that polls PEM files.
///
/// Files are published as raw PEM bytes without certificate validation. Read
/// failures during refresh are logged at `WARN`; the last successfully read
/// snapshot stays available. Unchanged bytes retain the same `Arc`, avoiding
/// connector rebuilds. [`crate::ReloadableTlsConnector`] validates snapshots
/// through its TLS factory before use. Readable but invalid updates therefore
/// fail new connection attempts rather than retaining older credentials.
///
/// Share the provider using `Arc`. Dropping it aborts the polling task using
/// Tokio's standard task cancellation.
///
/// # Example
///
/// Load PEM files and let the rustls connector factory validate them:
///
/// ```no_run
/// # #[cfg(feature = "rustls")]
/// # async fn connect(
/// #     endpoint: tonic::transport::Endpoint,
/// #     config: std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
/// # ) -> Result<tonic::transport::Channel, tonic_tls::Error> {
/// use std::sync::Arc;
/// use tonic_tls_xds::{FileWatcherConfig, FileWatcherProvider, ReloadableTlsConnector};
///
/// let domain = "localhost".try_into()?;
/// let factory = tonic_tls_xds::rustls::TlsConnectorFactory::new(config, domain);
/// let provider = Arc::new(FileWatcherProvider::new(FileWatcherConfig {
///     certificate_file: Some("client.pem".into()),
///     private_key_file: Some("client.key".into()),
///     ..Default::default()
/// }).await?);
/// let transport = tonic_tls::TcpTransport::from_endpoint(&endpoint);
/// let connector = ReloadableTlsConnector::new(transport, provider, factory)?;
/// let channel = endpoint.connect_with_connector(connector).await?;
/// # Ok(channel)
/// # }
/// ```
pub struct FileWatcherProvider {
    state: Arc<WatcherState>,
    refresh_task: tokio::task::JoinHandle<()>,
}

impl FileWatcherProvider {
    /// Reads and caches the initial files asynchronously, then starts polling.
    ///
    /// Must be called inside a Tokio runtime with time enabled. Invalid config,
    /// such as unpaired identity paths, and file-read errors are returned without
    /// starting a task. The first refresh occurs after the configured interval.
    ///
    /// File reads use `tokio::fs`. Certificate contents are not validated here;
    /// [`crate::ReloadableTlsConnector::new`] validates the initial snapshot.
    pub async fn new(config: FileWatcherConfig) -> Result<Self, tonic_tls::Error> {
        config.validate()?;
        let runtime = tokio::runtime::Handle::try_current()?;
        let data = config.read().await?;
        let start = tokio::time::Instant::now()
            .checked_add(config.refresh_interval)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "refresh_interval is too large",
                )
            })?;
        let mut interval = tokio::time::interval_at(start, config.refresh_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let state = Arc::new(WatcherState {
            config,
            cached: Mutex::new(Arc::new(data)),
        });
        let refresh_task = runtime.spawn(refresh_loop(state.clone(), interval));
        Ok(Self {
            state,
            refresh_task,
        })
    }
}

impl CertificateProvider for FileWatcherProvider {
    fn snapshot(&self) -> Result<Arc<CertificateData>, tonic_tls::Error> {
        self.state.snapshot()
    }
}

impl Drop for FileWatcherProvider {
    fn drop(&mut self) {
        self.refresh_task.abort();
    }
}

struct WatcherState {
    config: FileWatcherConfig,
    cached: Mutex<Arc<CertificateData>>,
}

impl WatcherState {
    fn snapshot(&self) -> Result<Arc<CertificateData>, tonic_tls::Error> {
        self.cached
            .lock()
            .map(|cached| cached.clone())
            .map_err(|_| std::io::Error::other("file watcher cache lock poisoned").into())
    }

    async fn refresh(&self) -> Result<bool, tonic_tls::Error> {
        let data = self.config.read().await?;
        if self.snapshot()?.as_ref() == &data {
            return Ok(false);
        }
        *self
            .cached
            .lock()
            .map_err(|_| std::io::Error::other("file watcher cache lock poisoned"))? =
            Arc::new(data);
        Ok(true)
    }
}

async fn refresh_loop(state: Arc<WatcherState>, mut interval: tokio::time::Interval) {
    loop {
        interval.tick().await;
        match state.refresh().await {
            Ok(true) => tracing::debug!("certificate files refreshed"),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                error = %error,
                "certificate file refresh failed; keeping last successfully read snapshot",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;

    fn roots_config(path: &Path) -> FileWatcherConfig {
        FileWatcherConfig {
            ca_certificate_file: Some(path.into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn invalid_configuration_is_rejected() {
        let roots = roots_config(Path::new("roots.pem"));
        for (config, message) in [
            (FileWatcherConfig::default(), "at least one"),
            (
                FileWatcherConfig {
                    certificate_file: Some("cert.pem".into()),
                    ..roots.clone()
                },
                "supplied together",
            ),
            (
                FileWatcherConfig {
                    private_key_file: Some("key.pem".into()),
                    ..roots.clone()
                },
                "supplied together",
            ),
            (
                FileWatcherConfig {
                    refresh_interval: Duration::ZERO,
                    ..roots.clone()
                },
                "greater than zero",
            ),
            (
                FileWatcherConfig {
                    refresh_interval: Duration::MAX,
                    ..roots
                },
                "too large",
            ),
        ] {
            let error = FileWatcherProvider::new(config).await.err().unwrap();
            assert!(error.to_string().contains(message), "{error}");
        }
    }

    #[test]
    fn construction_requires_a_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roots.pem");
        std::fs::write(&path, b"roots").unwrap();
        let error = FileWatcherProvider::new(roots_config(&path))
            .now_or_never()
            .expect("missing runtime must be rejected before reading files")
            .err()
            .unwrap();
        assert!(error.is::<tokio::runtime::TryCurrentError>());
    }

    // The watcher preserves bytes; certificate validation belongs to the TLS factory.
    #[tokio::test]
    async fn initial_load_supports_roots_identity_and_both() {
        let dir = tempfile::tempdir().unwrap();
        let root_path = dir.path().join("roots.pem");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&root_path, b"roots").unwrap();
        std::fs::write(&cert_path, b"certificate").unwrap();
        std::fs::write(&key_path, b"key").unwrap();
        let identity = Identity::from_pem(b"certificate", b"key");
        for expected in [
            CertificateData::RootsOnly {
                roots: b"roots".to_vec(),
            },
            CertificateData::IdentityOnly {
                identity: identity.clone(),
            },
            CertificateData::Both {
                roots: b"roots".to_vec(),
                identity,
            },
        ] {
            let config = FileWatcherConfig {
                ca_certificate_file: expected.roots().map(|_| root_path.clone()),
                certificate_file: expected.identity().map(|_| cert_path.clone()),
                private_key_file: expected.identity().map(|_| key_path.clone()),
                ..Default::default()
            };
            let provider = FileWatcherProvider::new(config).await.unwrap();
            let data = provider.snapshot().unwrap();
            assert_eq!(data.as_ref(), &expected);
            assert!(Arc::ptr_eq(&data, &provider.snapshot().unwrap()));
        }
    }

    #[tokio::test]
    async fn initial_read_errors_are_returned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roots.pem");
        let error = FileWatcherProvider::new(roots_config(&path))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains(path.to_str().unwrap()));
    }

    #[tokio::test]
    async fn refresh_retains_snapshot_only_on_read_errors() {
        let dir = tempfile::tempdir().unwrap();
        let root_path = dir.path().join("roots.pem");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&root_path, b"root-1").unwrap();
        std::fs::write(&cert_path, b"identity-1").unwrap();
        std::fs::write(&key_path, b"identity-1").unwrap();
        let provider = FileWatcherProvider::new(FileWatcherConfig {
            ca_certificate_file: Some(root_path.clone()),
            certificate_file: Some(cert_path.clone()),
            private_key_file: Some(key_path.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        let initial = provider.snapshot().unwrap();
        assert!(!provider.state.refresh().await.unwrap());
        assert!(Arc::ptr_eq(&initial, &provider.snapshot().unwrap()));

        std::fs::remove_file(&cert_path).unwrap();
        std::fs::write(&root_path, b"root-2").unwrap();
        assert!(provider.state.refresh().await.is_err());
        assert!(Arc::ptr_eq(&initial, &provider.snapshot().unwrap()));

        // Readable updates are published even if the key is stale or roots are empty.
        std::fs::write(&cert_path, b"identity-2").unwrap();
        assert!(provider.state.refresh().await.unwrap());
        assert_eq!(
            provider.snapshot().unwrap().as_ref(),
            &CertificateData::Both {
                roots: b"root-2".to_vec(),
                identity: Identity::from_pem(b"identity-2", b"identity-1"),
            },
        );
        std::fs::write(&key_path, b"identity-2").unwrap();
        std::fs::write(&root_path, b"").unwrap();
        assert!(provider.state.refresh().await.unwrap());
        assert_eq!(
            provider.snapshot().unwrap().as_ref(),
            &CertificateData::Both {
                roots: Vec::new(),
                identity: Identity::from_pem(b"identity-2", b"identity-2"),
            },
        );

        std::fs::write(&root_path, b"root-2").unwrap();
        assert!(provider.state.refresh().await.unwrap());
        let updated = provider.snapshot().unwrap();
        assert!(!Arc::ptr_eq(&initial, &updated));
        assert_eq!(
            updated.as_ref(),
            &CertificateData::Both {
                roots: b"root-2".to_vec(),
                identity: Identity::from_pem(b"identity-2", b"identity-2"),
            },
        );
        assert!(!provider.state.refresh().await.unwrap());
        assert!(Arc::ptr_eq(&updated, &provider.snapshot().unwrap()));
    }

    // tokio::fs needs executor time even while the polling clock is paused.
    async fn wait_until(mut ready: impl FnMut() -> bool) {
        let start = std::time::Instant::now();
        while !ready() {
            assert!(start.elapsed() < Duration::from_secs(5), "watcher stalled");
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn polling_waits_for_interval_and_stops_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roots.pem");
        std::fs::write(&path, b"root-1").unwrap();
        let provider = Arc::new(
            FileWatcherProvider::new(FileWatcherConfig {
                refresh_interval: Duration::from_secs(10),
                ..roots_config(&path)
            })
            .await
            .unwrap(),
        );
        let initial = provider.snapshot().unwrap();
        let remaining = provider.clone();
        let abort = provider.refresh_task.abort_handle();
        let state = Arc::downgrade(&provider.state);
        std::fs::write(&path, b"").unwrap();
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(Arc::ptr_eq(&initial, &provider.snapshot().unwrap()));
        tokio::time::advance(Duration::from_secs(1)).await;
        wait_until(|| !Arc::ptr_eq(&initial, &provider.snapshot().unwrap())).await;
        let updated = provider.snapshot().unwrap();
        assert!(updated.roots().unwrap().is_empty());

        drop(provider);
        assert!(!abort.is_finished());
        std::fs::write(&path, b"root-2").unwrap();
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(Arc::ptr_eq(&updated, &remaining.snapshot().unwrap()));
        tokio::time::advance(Duration::from_secs(1)).await;
        wait_until(|| !Arc::ptr_eq(&updated, &remaining.snapshot().unwrap())).await;
        assert_eq!(remaining.snapshot().unwrap().roots().unwrap(), b"root-2");

        drop(remaining);
        wait_until(|| abort.is_finished() && state.upgrade().is_none()).await;
    }
}
