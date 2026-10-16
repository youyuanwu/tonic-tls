use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{
    CertificateData, CertificateProvider, CrlSelection, Identity, cert_provider::PemBytes,
};

/// A source of raw PEM CRL bundles for [`FileWatcherProvider`].
#[derive(Clone, Debug)]
pub enum CrlSource {
    /// A file containing one or more PEM CRLs. The first CRL per issuer wins,
    /// with duplicates logged at `ERROR` by the TLS factory.
    File(PathBuf),
    /// A directory of PEM CRL files, read in filename order without recursion.
    ///
    /// All regular files are read, regardless of extension. Symlinks to files
    /// are followed; subdirectories are ignored. Other file types and broken
    /// symlinks cause a read error. An empty directory publishes an empty CRL
    /// collection, which the TLS factory must reject.
    /// The last CRL per issuer wins in filename/PEM-block order, not issuance order.
    Directory(PathBuf),
}

impl CrlSource {
    async fn read(&self) -> Result<Vec<PemBytes>, tonic_tls::Error> {
        let paths = match self {
            Self::File(path) => vec![path.clone()],
            Self::Directory(directory) => async {
                let mut entries = tokio::fs::read_dir(directory).await?;
                let mut paths = Vec::new();
                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    let metadata = tokio::fs::metadata(&path).await?;
                    if metadata.is_dir() {
                        continue;
                    }
                    if !metadata.is_file() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("CRL path '{}' is not a regular file", path.display()),
                        ));
                    }
                    paths.push(path);
                }
                paths.sort();
                Ok::<_, std::io::Error>(paths)
            }
            .await
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "failed to read CRL directory '{}': {error}",
                        directory.display()
                    ),
                )
            })?,
        };
        let mut crls = Vec::with_capacity(paths.len());
        for path in paths {
            crls.push(read_file(&path).await?);
        }
        Ok(crls)
    }
}

/// PEM file paths and polling interval for [`FileWatcherProvider`].
///
/// Configure roots, an identity, or both. Certificate and private-key paths must
/// be supplied together. CRLs require a CA certificate file. The default interval
/// is 600 seconds.
///
/// Fluent methods can be called in any order and only assign fields. Validation
/// and file reads happen in [`FileWatcherProvider::new`]. Struct literals remain
/// supported.
///
/// ```
/// use std::time::Duration;
/// use tonic_tls_xds::{CrlSource, FileWatcherConfig};
///
/// let config = FileWatcherConfig::default()
///     .with_ca_certificate_file("ca.pem")
///     .with_identity_files("client.pem", "client.key")
///     .with_crl_source(CrlSource::Directory("crls".into()))
///     .with_refresh_interval(Duration::from_secs(60));
/// ```
#[derive(Clone, Debug)]
pub struct FileWatcherConfig {
    /// PEM trust bundle used to validate peers.
    pub ca_certificate_file: Option<PathBuf>,
    /// PEM identity certificate chain, leaf first.
    pub certificate_file: Option<PathBuf>,
    /// PEM private key for the identity.
    pub private_key_file: Option<PathBuf>,
    /// Optional CRL file or directory; requires `ca_certificate_file`.
    pub crl_source: Option<CrlSource>,
    /// Nonzero polling interval; defaults to 600 seconds.
    pub refresh_interval: Duration,
}

impl Default for FileWatcherConfig {
    fn default() -> Self {
        Self {
            ca_certificate_file: None,
            certificate_file: None,
            private_key_file: None,
            crl_source: None,
            refresh_interval: Duration::from_secs(600),
        }
    }
}

impl FileWatcherConfig {
    /// Sets the PEM trust bundle path.
    #[must_use]
    pub fn with_ca_certificate_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_certificate_file = Some(path.into());
        self
    }

    /// Sets the PEM identity certificate chain and private-key paths together.
    #[must_use]
    pub fn with_identity_files(
        mut self,
        certificate_file: impl Into<PathBuf>,
        private_key_file: impl Into<PathBuf>,
    ) -> Self {
        self.certificate_file = Some(certificate_file.into());
        self.private_key_file = Some(private_key_file.into());
        self
    }

    /// Sets the CRL file or directory. A CA certificate file is also required.
    #[must_use]
    pub fn with_crl_source(mut self, source: CrlSource) -> Self {
        self.crl_source = Some(source);
        self
    }

    /// Sets the polling interval, validated by [`FileWatcherProvider::new`].
    #[must_use]
    pub fn with_refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval;
        self
    }

    fn validate(&self) -> Result<(), tonic_tls::Error> {
        let message = if self.certificate_file.is_some() != self.private_key_file.is_some() {
            Some("certificate_file and private_key_file must be supplied together")
        } else if self.crl_source.is_some() && self.ca_certificate_file.is_none() {
            Some("crl_source requires ca_certificate_file")
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
        let crls = match &self.crl_source {
            Some(source) => Some(source.read().await?),
            None => None,
        };
        let mut data = CertificateData::new(roots, identity, crls)?;
        if matches!(&self.crl_source, Some(CrlSource::Directory(_))) {
            data.crl_selection = CrlSelection::LastPerIssuer;
        }
        Ok(data)
    }
}

async fn read_file(path: &Path) -> Result<PemBytes, tonic_tls::Error> {
    tokio::fs::read(path).await.map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("failed to read PEM file '{}': {error}", path.display()),
        )
        .into()
    })
}

/// A backend-neutral certificate provider that polls PEM certificate and CRL files.
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
/// let watcher_config = FileWatcherConfig::default()
///     .with_identity_files("client.pem", "client.key");
/// let provider = Arc::new(FileWatcherProvider::new(watcher_config).await?);
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
        FileWatcherConfig::default().with_ca_certificate_file(path)
    }

    #[test]
    fn fluent_configuration_preserves_defaults_and_replaces_settings() {
        let config =
            FileWatcherConfig::default().with_crl_source(CrlSource::Directory("crls".into()));
        assert!(config.ca_certificate_file.is_none());
        assert!(config.certificate_file.is_none());
        assert!(config.private_key_file.is_none());
        assert_eq!(config.refresh_interval, Duration::from_secs(600));

        let config = config
            .with_ca_certificate_file("ca.pem")
            .with_identity_files(Path::new("client.pem"), String::from("client.key"))
            .with_refresh_interval(Duration::from_secs(60));
        assert_eq!(
            config.ca_certificate_file.as_deref(),
            Some(Path::new("ca.pem"))
        );
        assert_eq!(
            config.certificate_file.as_deref(),
            Some(Path::new("client.pem"))
        );
        assert_eq!(
            config.private_key_file.as_deref(),
            Some(Path::new("client.key"))
        );
        assert!(matches!(
            &config.crl_source,
            Some(CrlSource::Directory(path)) if path == Path::new("crls"),
        ));
        assert_eq!(config.refresh_interval, Duration::from_secs(60));
        config.validate().unwrap();

        let config = config
            .with_ca_certificate_file(PathBuf::from("new-ca.pem"))
            .with_identity_files(String::from("new-client.pem"), Path::new("new-client.key"))
            .with_crl_source(CrlSource::File("crl.pem".into()))
            .with_refresh_interval(Duration::from_secs(30));
        assert_eq!(
            config.ca_certificate_file.as_deref(),
            Some(Path::new("new-ca.pem"))
        );
        assert_eq!(
            config.certificate_file.as_deref(),
            Some(Path::new("new-client.pem"))
        );
        assert_eq!(
            config.private_key_file.as_deref(),
            Some(Path::new("new-client.key"))
        );
        assert!(matches!(
            &config.crl_source,
            Some(CrlSource::File(path)) if path == Path::new("crl.pem"),
        ));
        assert_eq!(config.refresh_interval, Duration::from_secs(30));
        config.validate().unwrap();
    }

    #[tokio::test]
    async fn invalid_configuration_is_rejected() {
        let roots = roots_config(Path::new("roots.pem"));
        for (config, message) in [
            (FileWatcherConfig::default(), "at least one"),
            (
                FileWatcherConfig::default().with_crl_source(CrlSource::File("crl.pem".into())),
                "crl_source requires ca_certificate_file",
            ),
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
                roots.clone().with_refresh_interval(Duration::ZERO),
                "greater than zero",
            ),
            (roots.with_refresh_interval(Duration::MAX), "too large"),
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
            CertificateData::new(Some(b"roots".to_vec()), None, None).unwrap(),
            CertificateData::new(None, Some(identity.clone()), None).unwrap(),
            CertificateData::new(Some(b"roots".to_vec()), Some(identity), None).unwrap(),
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
    async fn crl_file_refresh_publishes_raw_bytes_and_retains_on_read_failure() {
        let dir = tempfile::tempdir().unwrap();
        let roots = dir.path().join("roots.pem");
        let crl = dir.path().join("crl.pem");
        std::fs::write(&roots, b"roots").unwrap();
        let config = FileWatcherConfig {
            crl_source: Some(CrlSource::File(crl.clone())),
            ..roots_config(&roots)
        };
        assert!(FileWatcherProvider::new(config.clone()).await.is_err());
        std::fs::write(&crl, b"crl-1").unwrap();
        let provider = FileWatcherProvider::new(config).await.unwrap();
        let initial = provider.snapshot().unwrap();
        assert_eq!(initial.crls().unwrap(), &[b"crl-1".to_vec()]);
        assert_eq!(initial.crl_selection(), CrlSelection::FirstPerIssuer);
        assert!(!provider.state.refresh().await.unwrap());
        assert!(Arc::ptr_eq(&initial, &provider.snapshot().unwrap()));

        std::fs::remove_file(&crl).unwrap();
        assert!(provider.state.refresh().await.is_err());
        assert!(Arc::ptr_eq(&initial, &provider.snapshot().unwrap()));
        for bytes in [b"crl-2".as_slice(), b""] {
            std::fs::write(&crl, bytes).unwrap();
            assert!(provider.state.refresh().await.unwrap());
            assert_eq!(
                provider.snapshot().unwrap().crls().unwrap(),
                &[bytes.to_vec()]
            );
        }
    }

    #[tokio::test]
    async fn crl_directory_tracks_additions_removals_and_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let roots = dir.path().join("roots.pem");
        let cert = dir.path().join("client.pem");
        let key = dir.path().join("client.key");
        let crls = dir.path().join("crls");
        std::fs::write(&roots, b"roots").unwrap();
        std::fs::write(&cert, b"cert").unwrap();
        std::fs::write(&key, b"key").unwrap();
        let config = roots_config(&roots)
            .with_identity_files(cert, key)
            .with_crl_source(CrlSource::Directory(crls.clone()));
        assert!(FileWatcherProvider::new(config.clone()).await.is_err());
        std::fs::create_dir(&crls).unwrap();
        // Deliberately create in reverse filename order; extensions are not filtered.
        std::fs::write(crls.join("b.crl"), b"b").unwrap();
        std::fs::write(crls.join("a"), b"a").unwrap();
        std::fs::create_dir(crls.join("nested")).unwrap();
        std::fs::write(crls.join("nested/ignored.pem"), b"ignored").unwrap();
        let provider = FileWatcherProvider::new(config).await.unwrap();
        let initial = provider.snapshot().unwrap();
        assert_eq!(initial.crls().unwrap(), &[b"a".to_vec(), b"b".to_vec()]);
        assert_eq!(initial.crl_selection(), CrlSelection::LastPerIssuer);
        assert_eq!(
            initial.identity(),
            Some(&Identity::from_pem(b"cert", b"key"))
        );
        assert!(!provider.state.refresh().await.unwrap());
        assert!(Arc::ptr_eq(&initial, &provider.snapshot().unwrap()));

        std::fs::write(crls.join("c.pem"), b"c").unwrap();
        assert!(provider.state.refresh().await.unwrap());
        assert_eq!(
            provider.snapshot().unwrap().crls().unwrap(),
            &[b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
        );
        std::fs::remove_file(crls.join("b.crl")).unwrap();
        assert!(provider.state.refresh().await.unwrap());
        assert_eq!(
            provider.snapshot().unwrap().crls().unwrap(),
            &[b"a".to_vec(), b"c".to_vec()]
        );
        std::fs::remove_file(crls.join("a")).unwrap();
        std::fs::remove_file(crls.join("c.pem")).unwrap();
        assert!(provider.state.refresh().await.unwrap());
        assert!(provider.snapshot().unwrap().crls().unwrap().is_empty());
        let empty = provider.snapshot().unwrap();

        let moved = dir.path().join("moved");
        std::fs::rename(&crls, &moved).unwrap();
        assert!(provider.state.refresh().await.is_err());
        assert!(Arc::ptr_eq(&empty, &provider.snapshot().unwrap()));
        std::fs::rename(&moved, &crls).unwrap();
        std::fs::write(crls.join("a"), b"restored").unwrap();
        assert!(provider.state.refresh().await.unwrap());
        assert_eq!(
            provider.snapshot().unwrap().crls().unwrap(),
            &[b"restored".to_vec()]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn crl_directory_follows_file_symlinks_and_rejects_broken_links() {
        let dir = tempfile::tempdir().unwrap();
        let roots = dir.path().join("roots.pem");
        let crl = dir.path().join("crl.pem");
        let crls = dir.path().join("crls");
        std::fs::write(&roots, b"roots").unwrap();
        std::fs::write(&crl, b"crl").unwrap();
        std::fs::create_dir(&crls).unwrap();
        std::os::unix::fs::symlink(&crl, crls.join("link")).unwrap();
        let provider = FileWatcherProvider::new(FileWatcherConfig {
            crl_source: Some(CrlSource::Directory(crls)),
            ..roots_config(&roots)
        })
        .await
        .unwrap();
        let initial = provider.snapshot().unwrap();
        assert_eq!(initial.crls().unwrap(), &[b"crl".to_vec()]);
        std::fs::remove_file(&crl).unwrap();
        assert!(provider.state.refresh().await.is_err());
        assert!(Arc::ptr_eq(&initial, &provider.snapshot().unwrap()));
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
            &CertificateData::new(
                Some(b"root-2".to_vec()),
                Some(Identity::from_pem(b"identity-2", b"identity-1")),
                None,
            )
            .unwrap(),
        );
        std::fs::write(&key_path, b"identity-2").unwrap();
        std::fs::write(&root_path, b"").unwrap();
        assert!(provider.state.refresh().await.unwrap());
        assert_eq!(
            provider.snapshot().unwrap().as_ref(),
            &CertificateData::new(
                Some(Vec::new()),
                Some(Identity::from_pem(b"identity-2", b"identity-2")),
                None,
            )
            .unwrap(),
        );

        std::fs::write(&root_path, b"root-2").unwrap();
        assert!(provider.state.refresh().await.unwrap());
        let updated = provider.snapshot().unwrap();
        assert!(!Arc::ptr_eq(&initial, &updated));
        assert_eq!(
            updated.as_ref(),
            &CertificateData::new(
                Some(b"root-2".to_vec()),
                Some(Identity::from_pem(b"identity-2", b"identity-2")),
                None,
            )
            .unwrap(),
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
