//! Rustls adapter for provider-driven TLS connections.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{
    ClientConfig, RootCertStore,
    client::{Resumption, WebPkiServerVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    sign::{CertifiedKey, SingleCertAndKey},
};

use crate::CertificateData;

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
            let verifier = WebPkiServerVerifier::builder_with_provider(
                Arc::new(store),
                config.crypto_provider().clone(),
            )
            .build()?;
            config.dangerous().set_certificate_verifier(verifier);
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
