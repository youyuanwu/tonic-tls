use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{
    ClientConfig, RootCertStore,
    client::{Resumption, WebPkiServerVerifier},
    pki_types::{CertificateDer, ServerName, pem::PemObject},
    sign::SingleCertAndKey,
};

use super::common::{certified_key, select_crls};
use crate::CertificateData;

/// A rustls handshake connector produced by [`TlsConnectorFactory`].
#[derive(Clone)]
pub struct TlsConnector(tokio_rustls::TlsConnector);

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(config: Arc<ClientConfig>) -> Self {
        Self(tokio_rustls::TlsConnector::from(config))
    }
}

impl<IO> tonic_tls::TlsConnector<IO> for TlsConnector
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type TlsStream = tokio_rustls::client::TlsStream<IO>;
    type Arg = ServerName<'static>;

    async fn connect(
        &self,
        domain: Self::Arg,
        stream: IO,
    ) -> Result<Self::TlsStream, tonic_tls::Error> {
        self.0
            .connect(domain, stream)
            .await
            .map_err(tonic_tls::Error::from)
    }
}

/// Applies a PEM snapshot to a clone of the base rustls configuration.
///
/// Supplied roots replace the base server verifier with rustls's
/// standard certificate-chain and hostname verifier. Supplied identity replaces
/// its client certificate resolver. Omitted material retains the base settings,
/// not the previous snapshot's settings. Always pass the original base
/// configuration when building successive snapshots.
///
/// Supplied CRLs enable revocation checking for the full peer chain, excluding
/// the trust anchor. Unknown status and expired CRLs are rejected. Every supplied
/// buffer must contain at least one PEM CRL; empty collections are also rejected.
/// Parsing happens at build time; signature, applicability, revocation, and expiry
/// checks happen during handshakes. No CRLs are downloaded from distribution points.
/// One CRL per DER-encoded issuer is selected using [`CertificateData::crl_selection`].
/// All supplied CRLs are parsed, including duplicates; there is no newest-CRL
/// selection or fallback if the selected CRL fails verification.
///
/// Other settings, including ALPN, are preserved, except that session resumption
/// is disabled so new connections authenticate with current credentials and trust.
///
/// Returns errors for invalid PEM, unusable roots, or invalid certificate/key
/// pairs. No fallback credentials are substituted, and the base is not modified.
///
/// The returned configuration is owned so a custom [`crate::TlsConnectorFactory`]
/// can adjust backend-specific settings before wrapping it in [`TlsConnector`].
/// Replacing its verifier or re-enabling resumption can undo the validation and
/// rotation guarantees above; custom factories are responsible for preserving them.
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
/// use tokio_rustls::rustls::{ClientConfig, pki_types::ServerName};
/// use tonic_tls_xds::{CertificateData, rustls::{build_client_config, TlsConnector}};
///
/// fn build_custom_connector(
///     base: &ClientConfig,
///     data: &CertificateData,
///     server_name: ServerName<'static>,
/// ) -> Result<(TlsConnector, ServerName<'static>), tonic_tls::Error> {
///     let mut config = build_client_config(base, data)?;
///     config.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];
///     Ok((TlsConnector::from(Arc::new(config)), server_name))
/// }
/// ```
pub fn build_client_config(
    base: &ClientConfig,
    data: &CertificateData,
) -> Result<ClientConfig, tonic_tls::Error> {
    let mut config = base.clone();
    if let Some(roots) = data.roots() {
        let mut store = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(roots) {
            store.add(cert?)?;
        }
        let mut verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(store),
            config.crypto_provider().clone(),
        );
        if let Some(bundles) = data.crls() {
            verifier = verifier
                .with_crls(select_crls(bundles, data.crl_selection())?)
                .enforce_revocation_expiration();
        }
        config
            .dangerous()
            .set_certificate_verifier(verifier.build()?);
    }
    if let Some(identity) = data.identity() {
        let certified_key = certified_key(identity, config.crypto_provider())?;
        config.client_auth_cert_resolver = Arc::new(SingleCertAndKey::from(certified_key));
    }
    // Resumed sessions can retain an old authenticated identity or trust
    // decision without exchanging certificates again.
    config.resumption = Resumption::disabled();

    Ok(config)
}

/// A rustls implementation of [`crate::TlsConnectorFactory`].
///
/// Use with [`crate::ReloadableTlsConnector`] to apply snapshots to the original
/// base configuration using [`build_client_config`], then create a handshake
/// connector paired with the configured server name.
///
/// For post-snapshot customization, use [`build_client_config`] in a custom
/// factory instead.
#[derive(Clone, Debug)]
pub struct TlsConnectorFactory {
    config: Arc<ClientConfig>,
    domain: ServerName<'static>,
}

impl TlsConnectorFactory {
    /// Creates a factory using the base TLS configuration and server name.
    ///
    /// The base configuration should include the desired ALPN protocols.
    /// This does not request or validate a snapshot; that happens when constructing
    /// [`crate::ReloadableTlsConnector`] and on connection attempts after rotation.
    pub fn new(config: Arc<ClientConfig>, domain: ServerName<'static>) -> Self {
        Self { config, domain }
    }
}

impl<IO> crate::TlsConnectorFactory<IO> for TlsConnectorFactory
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Connector = TlsConnector;

    fn build_connector(
        &self,
        data: &CertificateData,
    ) -> Result<(Self::Connector, ServerName<'static>), tonic_tls::Error> {
        let config = build_client_config(&self.config, data)?;
        Ok((TlsConnector::from(Arc::new(config)), self.domain.clone()))
    }
}
