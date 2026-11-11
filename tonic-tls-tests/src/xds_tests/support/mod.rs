use arc_swap::ArcSwap;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tonic_tls_xds::{CertificateData, CertificateProvider};

pub(super) mod backend;
pub(super) mod certs;
pub(super) mod grpc;

pub(super) struct TestProvider {
    pub data: ArcSwap<CertificateData>,
    pub fail: AtomicBool,
}

impl TestProvider {
    pub fn new(data: CertificateData) -> Arc<Self> {
        Arc::new(Self {
            data: ArcSwap::from_pointee(data),
            fail: AtomicBool::new(false),
        })
    }
}

impl CertificateProvider for TestProvider {
    fn snapshot(&self) -> Result<Arc<CertificateData>, tonic_tls::Error> {
        if self.fail.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("certificate provider unavailable").into());
        }
        Ok(self.data.load_full())
    }
}

pub(super) async fn wait_for_snapshot(
    provider: &dyn CertificateProvider,
    description: &str,
    predicate: impl Fn(&CertificateData) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !predicate(&provider.snapshot().unwrap()) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("file watcher did not publish {description}"));
}

pub(super) struct CrlErrorEvents(pub Arc<AtomicUsize>, pub &'static str);

impl tracing::Subscriber for CrlErrorEvents {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == self.1 && *metadata.level() == tracing::Level::ERROR
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        if self.enabled(event.metadata()) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}
