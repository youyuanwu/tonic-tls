use super::support::backend::{OpenSsl, Rustls, TestServerBackend};
use crate::test_support::certs::base_config;
use rcgen::KeyPair;
use rustls::ClientConfig;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tonic_tls_xds::{
    CertificateData, CertificateProvider, Identity, ReloadableTlsAcceptor,
    ServerConfig as ManagedConfig, TlsAcceptorFactory,
};

mod grpc;
mod handshake;

#[derive(Clone)]
struct CountingServerFactory<F> {
    inner: F,
    builds: Arc<AtomicUsize>,
}

impl<IO, F> TlsAcceptorFactory<IO> for CountingServerFactory<F>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: TlsAcceptorFactory<IO>,
{
    type Acceptor = F::Acceptor;

    fn build_acceptor(&self, data: &CertificateData) -> Result<Self::Acceptor, tonic_tls::Error> {
        self.builds.fetch_add(1, Ordering::Relaxed);
        self.inner.build_acceptor(data)
    }
}

fn acceptor<B, IO>(
    provider: Arc<dyn CertificateProvider>,
    base: ManagedConfig,
) -> (
    ReloadableTlsAcceptor<IO, CountingServerFactory<B::ServerFactory>>,
    Arc<AtomicUsize>,
)
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    B: TestServerBackend,
    B::ServerFactory: TlsAcceptorFactory<IO, Acceptor = B::Acceptor>,
{
    let builds = Arc::new(AtomicUsize::new(0));
    let factory = CountingServerFactory {
        inner: B::server_factory(base),
        builds: builds.clone(),
    };
    (
        ReloadableTlsAcceptor::new(provider, factory).unwrap(),
        builds,
    )
}

fn chain_identity(chain: &[&rcgen::Certificate], key: &KeyPair) -> Identity {
    Identity::from_pem(
        chain.iter().map(|cert| cert.pem()).collect::<String>(),
        key.serialize_pem(),
    )
}

fn client_config(
    roots: &[&rcgen::Certificate],
    chain: &[&rcgen::Certificate],
    key: &KeyPair,
) -> Arc<ClientConfig> {
    Arc::new(
        tonic_tls_xds::rustls::build_client_config(
            &base_config(roots),
            &CertificateData::new(None, Some(chain_identity(chain, key)), None).unwrap(),
        )
        .unwrap(),
    )
}

macro_rules! server_rotation_tests {
    ($module:ident, $backend:ty) => {
        mod $module {
            use super::*;

            #[tokio::test]
            async fn identity_and_client_roots_rotate() {
                handshake::identities_and_client_roots_are_complete_overlays_on_original_base::<
                    $backend,
                >()
                .await;
            }

            #[tokio::test]
            async fn client_crls_rotate_and_recover() {
                handshake::client_crl_rotation_rejects_revocation_and_recovers::<$backend>().await;
            }

            #[tokio::test]
            async fn tonic_reconnect_and_failure_recovery() {
                grpc::tonic_incoming_rotates_recovers_and_preserves_peer_info_on_reconnect::<
                    $backend,
                >()
                .await;
            }

            #[tokio::test]
            async fn file_watcher_rotates_identity() {
                grpc::file_watcher_rotates_server_identity_without_restarting_listener::<$backend>(
                )
                .await;
            }

            #[tokio::test]
            async fn full_handshakes_before_and_after_rotation() {
                handshake::full_handshakes_before_and_after_rotation::<$backend>().await;
            }

            #[tokio::test]
            async fn client_ca_hints_rotate() {
                handshake::client_ca_hints_follow_selected_snapshot_and_original_base::<$backend>()
                    .await;
            }
        }
    };
}

server_rotation_tests!(rustls_servers, Rustls);
server_rotation_tests!(openssl_servers, OpenSsl);
