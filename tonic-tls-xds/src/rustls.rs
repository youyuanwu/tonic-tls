//! Rustls adapter for provider-driven TLS connections.

use std::{
    collections::{BTreeMap, btree_map::Entry},
    sync::Arc,
};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{
    ClientConfig, RootCertStore,
    client::{Resumption, WebPkiServerVerifier},
    pki_types::{
        CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, pem::PemObject,
    },
    sign::{CertifiedKey, SingleCertAndKey},
};

use crate::{CertificateData, CrlSelection};

/// A rustls handshake connector produced by [`TlsConnectorFactory`].
#[derive(Clone)]
pub struct TlsConnector(tokio_rustls::TlsConnector);

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

/// A rustls implementation of [`crate::TlsConnectorFactory`].
///
/// Use with [`crate::ReloadableTlsConnector`] to apply PEM snapshots to a base
/// configuration. Supplied roots replace its server verifier with rustls's
/// standard certificate-chain and hostname verifier. Supplied identity replaces
/// its client certificate resolver. Omitted material retains the base settings,
/// not the previous snapshot's settings.
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
/// Factory builds return errors for invalid PEM, unusable roots, or invalid
/// certificate/key pairs. No fallback credentials are substituted.
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
        let mut config = self.config.as_ref().clone();
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
            let certs = CertificateDer::pem_slice_iter(identity.cert_chain())
                .collect::<Result<Vec<_>, _>>()?;
            if certs.is_empty() {
                return Err(tokio_rustls::rustls::Error::NoCertificatesPresented.into());
            }
            let key = PrivateKeyDer::from_pem_slice(identity.key())?;
            let certified_key = CertifiedKey::from_der(certs, key, config.crypto_provider())?;
            config.client_auth_cert_resolver = Arc::new(SingleCertAndKey::from(certified_key));
        }
        // Resumed sessions can retain an old authenticated identity or trust
        // decision without exchanging certificates again.
        config.resumption = Resumption::disabled();

        Ok((
            TlsConnector(tokio_rustls::TlsConnector::from(Arc::new(config))),
            self.domain.clone(),
        ))
    }
}

fn select_crls(
    bundles: &[Vec<u8>],
    selection: CrlSelection,
) -> Result<Vec<CertificateRevocationListDer<'static>>, tonic_tls::Error> {
    if bundles.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "CRL collection must not be empty",
        )
        .into());
    }
    let mut by_issuer = BTreeMap::new();
    for (bundle_index, bundle) in bundles.iter().enumerate() {
        let crls =
            CertificateRevocationListDer::pem_slice_iter(bundle).collect::<Result<Vec<_>, _>>()?;
        if crls.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("CRL bundle {bundle_index} must contain at least one PEM CRL"),
            )
            .into());
        }
        for (crl_index, crl) in crls.into_iter().enumerate() {
            // Parse entries too, so a malformed duplicate cannot be silently discarded.
            let parsed =
                webpki::CertRevocationList::from(webpki::OwnedCertRevocationList::from_der(&crl)?);
            match by_issuer.entry(parsed.issuer().to_vec()) {
                Entry::Vacant(entry) => {
                    entry.insert(crl);
                }
                Entry::Occupied(mut entry) => match selection {
                    CrlSelection::FirstPerIssuer => tracing::error!(
                        bundle_index,
                        crl_index,
                        "multiple CRLs with the same issuer; keeping the first CRL",
                    ),
                    CrlSelection::LastPerIssuer => {
                        entry.insert(crl);
                    }
                },
            }
        }
    }
    Ok(by_issuer.into_values().collect())
}
