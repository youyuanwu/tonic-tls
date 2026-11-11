use std::pin::Pin;

use openssl::{
    ssl::{
        SslConnector, SslMethod, SslMode, SslOptions, SslSessionCacheMode, SslVerifyMode,
        SslVersion,
    },
    x509::verify::X509VerifyFlags,
};
use tokio::io::{AsyncRead, AsyncWrite};

use super::common::{configure_identity, configure_roots};
use crate::{CertificateData, Identity, invalid_input};

/// Settings for crate-managed OpenSSL client contexts.
///
/// Defaults to OpenSSL's system trust paths, no client identity, and HTTP/2 ALPN.
/// Snapshots override the base roots and identity when supplied. Omitted material
/// uses these original settings, never the previous snapshot.
///
/// Only base CA PEM, identity, and ALPN are configurable. The crate owns context
/// creation, TLS 1.2-or-newer negotiation, certificate/hostname verification,
/// CRL checking, and disabled session resumption. Arbitrary OpenSSL contexts,
/// builders, callbacks, PSK authentication, and verification flags are not accepted.
/// This prevents inherited hooks from bypassing verification or restoring an old
/// identity during rotation.
///
/// Fluent methods only assign settings. Effective PEM and ALPN are validated by
/// [`TlsConnector::new`] or [`crate::ReloadableTlsConnector::new`].
///
/// ```compile_fail
/// use openssl::ssl::{SslConnector, SslMethod};
/// use tonic_tls_xds::openssl::TlsConnectorFactory;
///
/// let builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
/// let factory = TlsConnectorFactory::new(builder, "localhost".to_owned());
/// ```
///
/// ```compile_fail
/// use openssl::ssl::{SslConnector, SslMethod};
/// use tonic_tls_xds::openssl::TlsConnector;
///
/// let connector = SslConnector::builder(SslMethod::tls_client()).unwrap().build();
/// let connector = TlsConnector::from(connector);
/// ```
#[derive(Clone, Debug)]
pub struct ClientConfig {
    roots: Option<Vec<u8>>,
    identity: Option<Identity>,
    alpn_protocols: Vec<Vec<u8>>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            roots: None,
            identity: None,
            alpn_protocols: vec![tonic_tls::ALPN_H2.to_vec()],
        }
    }
}

impl ClientConfig {
    /// Sets the base PEM CA bundle, replacing system roots when used.
    ///
    /// A snapshot's roots replace this bundle. An empty or invalid effective
    /// bundle is an error, not a request to use system roots.
    #[must_use]
    pub fn with_ca_certificates(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.roots = Some(pem.into());
        self
    }

    /// Sets the base client identity, used when a snapshot omits identity.
    ///
    /// The private key must be unencrypted. Password-protected PEM is rejected.
    #[must_use]
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Sets ALPN protocol names in preference order, replacing the default `h2`.
    ///
    /// Names must contain 1 to 255 bytes and the length-prefixed list must fit
    /// in 65535 bytes. An empty list disables ALPN.
    #[must_use]
    pub fn with_alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }
}

/// A reusable OpenSSL connector built for one certificate snapshot.
///
/// The context is private and immutable after construction. Clones share it;
/// every connection creates a new `SSL` and performs a full handshake.
#[derive(Clone)]
pub struct TlsConnector(SslConnector);

impl TlsConnector {
    /// Builds a fresh context from the original settings and a complete snapshot.
    ///
    /// Supplied roots replace base roots, and supplied identity replaces the
    /// entire base certificate chain and key, even across key algorithms.
    /// No old context, callbacks, identities, or CRLs are inherited.
    /// Explicitly trusted intermediate CAs may terminate the verified chain.
    ///
    /// # Revocation policy
    ///
    /// CRLs check the leaf and intermediates, excluding the trust anchor, as in
    /// rustls. The anchor is the locally trusted CA where the verified chain ends.
    /// Its CRLs still check certificates it issued; remove it from trusted roots
    /// to withdraw trust. OpenSSL checks the anchor with `CRL_CHECK_ALL`, so a
    /// callback exempts only anchor CRL errors, not other verification failures.
    ///
    /// Every supplied buffer must contain at least one PEM CRL with `nextUpdate`;
    /// an empty collection is invalid. All CRLs are parsed, including duplicates.
    /// Selection uses [`CertificateData::crl_selection`], with no fallback to
    /// another CRL, newest-CRL selection, or network retrieval.
    /// Missing applicable CRLs, revoked certificates, invalid signatures, and
    /// expired or not-yet-valid CRLs reject the handshake.
    ///
    /// No CRLs in a snapshot means no CRL checking, not reuse of an earlier
    /// snapshot's CRLs. Certificate validation and CRL applicability, signatures,
    /// revocation and times are checked at each handshake.
    ///
    /// # Errors
    ///
    /// Invalid effective PEM, encrypted keys, empty roots/identity, mismatched keys, invalid ALPN,
    /// or OpenSSL setup errors fail construction without a usable fallback.
    /// This does not open a connection or watch for later snapshots.
    pub fn new(base: &ClientConfig, data: &CertificateData) -> Result<Self, tonic_tls::Error> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_verify(SslVerifyMode::PEER);
        builder
            .verify_param_mut()
            .set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
        builder.set_session_cache_mode(SslSessionCacheMode::OFF);
        builder.set_options(SslOptions::NO_TICKET);
        builder.set_mode(SslMode::NO_AUTO_CHAIN);

        if let Some(roots) = data.roots().or(base.roots.as_deref()) {
            configure_roots(&mut builder, roots, data, SslVerifyMode::PEER)?;
        }
        if let Some(identity) = data.identity().or(base.identity.as_ref()) {
            configure_identity(&mut builder, identity)?;
        }
        let mut alpn = Vec::new();
        for protocol in &base.alpn_protocols {
            let len = u8::try_from(protocol.len())
                .map_err(|_| invalid_input("ALPN protocol names must contain 1 to 255 bytes"))?;
            if len == 0 {
                return Err(invalid_input(
                    "ALPN protocol names must contain 1 to 255 bytes",
                ));
            }
            if alpn.len() + 1 + protocol.len() > usize::from(u16::MAX) {
                return Err(invalid_input(
                    "ALPN protocol list must not exceed 65535 bytes",
                ));
            }
            alpn.push(len);
            alpn.extend_from_slice(protocol);
        }
        builder.set_alpn_protos(&alpn)?;
        Ok(Self(builder.build()))
    }

    /// Performs a full TLS handshake over an existing stream.
    ///
    /// The domain is used for SNI and hostname verification. No saved session is
    /// installed. This connector keeps its original snapshot; obtain and build
    /// the current snapshot before connecting when using a provider manually.
    ///
    /// ```no_run
    /// # async fn connect(provider: &dyn tonic_tls_xds::CertificateProvider, tcp: tokio::net::TcpStream) -> Result<(), tonic_tls::Error> {
    /// use tonic_tls_xds::openssl::{ClientConfig, TlsConnector};
    ///
    /// let config = ClientConfig::default().with_alpn_protocols(vec![b"my-protocol".to_vec()]);
    /// let snapshot = provider.snapshot()?;
    /// let connector = TlsConnector::new(&config, &snapshot)?;
    /// let stream = connector.connect("localhost", tcp).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect<IO>(
        &self,
        domain: &str,
        stream: IO,
    ) -> Result<tokio_openssl::SslStream<IO>, tonic_tls::Error>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let ssl = self.0.configure()?.into_ssl(domain)?;
        let mut stream = tokio_openssl::SslStream::new(ssl, stream)?;
        Pin::new(&mut stream).connect().await?;
        Ok(stream)
    }
}

impl<IO> tonic_tls::TlsConnector<IO> for TlsConnector
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type TlsStream = tokio_openssl::SslStream<IO>;
    type Arg = String;

    async fn connect(
        &self,
        domain: String,
        stream: IO,
    ) -> Result<Self::TlsStream, tonic_tls::Error> {
        self.connect(&domain, stream).await
    }
}

/// An OpenSSL implementation of [`crate::TlsConnectorFactory`].
///
/// With [`crate::ReloadableTlsConnector`], builds and caches a fresh context at
/// construction and when the snapshot changes, including CRL-only updates.
/// Unchanged snapshots reuse that context. Existing connections are unaffected.
///
/// ```
/// use tonic_tls_xds::openssl::{ClientConfig, TlsConnectorFactory};
///
/// let factory = TlsConnectorFactory::new(ClientConfig::default(), "localhost".to_owned());
/// ```
#[derive(Clone, Debug)]
pub struct TlsConnectorFactory {
    config: ClientConfig,
    domain: String,
}

impl TlsConnectorFactory {
    /// Stores the original settings and server name without requesting a snapshot.
    pub fn new(config: ClientConfig, domain: String) -> Self {
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
    ) -> Result<(Self::Connector, String), tonic_tls::Error> {
        Ok((TlsConnector::new(&self.config, data)?, self.domain.clone()))
    }
}
