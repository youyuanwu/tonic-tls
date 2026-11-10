use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{
    RootCertStore, ServerConfig as RustlsServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, pem::PemObject},
    server::{NoServerSessionStorage, WebPkiClientVerifier},
};

use super::{certified_key, select_crls};
use crate::{CertificateData, ClientAuth, ServerConfig, server_config::invalid_input};

/// An immutable rustls server acceptor built from one certificate snapshot.
///
/// Clones share a configuration. Every accept performs a full handshake, and
/// the resulting core stream wrapper exposes peer certificates to tonic.
#[derive(Clone)]
pub struct TlsAcceptor(tokio_rustls::TlsAcceptor);

impl TlsAcceptor {
    /// Builds a fresh server configuration from original settings and a snapshot.
    ///
    /// Requires an effective identity. Snapshot identity and roots replace base
    /// material; omissions use the original base. Client authentication requires
    /// explicit roots and uses standard client-chain/EKU verification, without
    /// hostname checks. Disabled client authentication rejects roots and CRLs.
    ///
    /// Supplied CRLs check the full client chain except its trust anchor.
    /// Unknown status and expired CRLs fail verification at each handshake.
    /// Parsing and duplicate selection match the rustls client backend.
    /// No CRLs means no revocation checking, not reuse of an earlier snapshot.
    ///
    /// ALPN follows server preference. Session resumption and early data are
    /// disabled. Arbitrary native server configurations are not accepted.
    pub fn new(
        base: &ServerConfig,
        data: &CertificateData,
        crypto: Arc<CryptoProvider>,
    ) -> Result<Self, tonic_tls::Error> {
        let config = build_server_config(base, data, crypto)?;
        Ok(Self(tokio_rustls::TlsAcceptor::from(Arc::new(config))))
    }
}

fn build_server_config(
    base: &ServerConfig,
    data: &CertificateData,
    crypto: Arc<CryptoProvider>,
) -> Result<RustlsServerConfig, tonic_tls::Error> {
    base.validate(data)?;
    let builder = RustlsServerConfig::builder_with_provider(crypto.clone())
        .with_safe_default_protocol_versions()?;
    let builder = match base.client_auth {
        ClientAuth::Disabled => builder.with_no_client_auth(),
        ClientAuth::Optional | ClientAuth::Required => {
            let roots = data.roots().or(base.roots.as_deref()).ok_or_else(|| {
                invalid_input("client authentication requires explicit client roots")
            })?;
            let mut store = RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(roots) {
                store.add(cert?)?;
            }
            let mut verifier =
                WebPkiClientVerifier::builder_with_provider(Arc::new(store), crypto.clone());
            if let Some(bundles) = data.crls() {
                verifier = verifier
                    .with_crls(select_crls(bundles, data.crl_selection())?)
                    .enforce_revocation_expiration();
            }
            if base.client_auth == ClientAuth::Optional {
                verifier = verifier.allow_unauthenticated();
            }
            builder.with_client_cert_verifier(verifier.build()?)
        }
    };
    let identity = data
        .identity()
        .or(base.identity.as_ref())
        .ok_or_else(|| invalid_input("server identity is required"))?;
    let key = certified_key(identity, &crypto)?;
    let mut config = builder.with_cert_resolver(Arc::new(
        tokio_rustls::rustls::sign::SingleCertAndKey::from(key),
    ));
    config.alpn_protocols = base.alpn_protocols.clone();
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(config)
}

impl<IO> tonic_tls::TlsAcceptor<IO> for TlsAcceptor
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type TlsStream = tonic_tls::rustls::TlsStream<IO>;

    async fn accept(&self, stream: IO) -> Result<Self::TlsStream, tonic_tls::Error> {
        Ok(tonic_tls::rustls::TlsStream::new(
            self.0.accept(stream).await?,
        ))
    }
}

/// A rustls factory for [`crate::ReloadableTlsAcceptor`].
///
/// Owns the original server settings and an explicit crypto provider. Snapshot
/// construction never installs a process-wide default crypto provider.
#[derive(Clone, Debug)]
pub struct TlsAcceptorFactory {
    config: ServerConfig,
    crypto: Arc<CryptoProvider>,
}

impl TlsAcceptorFactory {
    /// Records original server settings. Validation happens when an acceptor is built.
    pub fn new(config: ServerConfig, crypto: Arc<CryptoProvider>) -> Self {
        Self { config, crypto }
    }
}

impl<IO> crate::TlsAcceptorFactory<IO> for TlsAcceptorFactory
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Acceptor = TlsAcceptor;

    fn build_acceptor(&self, data: &CertificateData) -> Result<Self::Acceptor, tonic_tls::Error> {
        TlsAcceptor::new(&self.config, data, self.crypto.clone())
    }
}
