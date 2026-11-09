//! OpenSSL adapter for provider-driven TLS connections.

use std::{
    collections::{BTreeMap, btree_map::Entry},
    pin::Pin,
};

use foreign_types::ForeignType;
use openssl::{
    error::ErrorStack,
    pkey::PKey,
    ssl::{
        SslConnector, SslMethod, SslMode, SslOptions, SslSessionCacheMode, SslVerifyMode,
        SslVersion,
    },
    x509::{
        X509, X509Crl, X509StoreContextRef, X509VerifyResult, store::X509StoreBuilder,
        verify::X509VerifyFlags,
    },
};
use pki_types::{CertificateRevocationListDer, PrivateKeyDer, pem::PemObject};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{CertificateData, CrlSelection, Identity};

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
            let roots = X509::stack_from_pem(roots)?;
            if roots.is_empty() {
                return Err(invalid_input(
                    "root bundle must contain at least one PEM certificate",
                ));
            }
            let mut store = X509StoreBuilder::new()?;
            for root in roots {
                store.add_cert(root)?;
            }
            if let Some(bundles) = data.crls() {
                for crl in select_crls(bundles, data.crl_selection())? {
                    // The store retains a reference; both arguments are live for the call.
                    if unsafe { native::X509_STORE_add_crl(store.as_ptr(), crl.as_ptr()) } != 1 {
                        return Err(ErrorStack::get().into());
                    }
                }
                builder
                    .verify_param_mut()
                    .set_flags(X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL)?;
                builder.set_verify_callback(SslVerifyMode::PEER, verify_except_anchor_crl);
            }
            builder.set_cert_store(store.build());
        }
        if let Some(identity) = data.identity().or(base.identity.as_ref()) {
            let mut certs = X509::stack_from_pem(identity.cert_chain())?.into_iter();
            let cert = certs.next().ok_or_else(|| {
                invalid_input("identity must contain at least one PEM certificate")
            })?;
            // Decode only unencrypted PEM formats; OpenSSL's PEM reader can prompt.
            let key_der = PrivateKeyDer::from_pem_slice(identity.key())?;
            let key = PKey::private_key_from_der(key_der.secret_der())?;
            builder.set_certificate(&cert)?;
            builder.set_private_key(&key)?;
            builder.check_private_key()?;
            for cert in certs {
                builder.add_extra_chain_cert(cert)?;
            }
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

fn invalid_input(message: &str) -> tonic_tls::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into()
}

fn select_crls(
    bundles: &[Vec<u8>],
    selection: CrlSelection,
) -> Result<Vec<X509Crl>, tonic_tls::Error> {
    if bundles.is_empty() {
        return Err(invalid_input("CRL collection must not be empty"));
    }
    let mut by_issuer = BTreeMap::new();
    for (bundle_index, bundle) in bundles.iter().enumerate() {
        let mut count = 0;
        for (crl_index, der) in CertificateRevocationListDer::pem_slice_iter(bundle).enumerate() {
            let crl = X509Crl::from_der(&der?)?;
            if crl.next_update().is_none() {
                return Err(invalid_input("CRL must contain nextUpdate"));
            }
            match by_issuer.entry(crl.issuer_name().to_der()?) {
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
            count += 1;
        }
        if count == 0 {
            return Err(invalid_input(&format!(
                "CRL bundle {bundle_index} must contain at least one PEM CRL"
            )));
        }
    }
    Ok(by_issuer.into_values().collect())
}

// CRL_CHECK_ALL includes the terminal trust anchor, unlike the provider contract.
// Preserve every other OpenSSL verification failure, including non-CRL anchor errors.
fn verify_except_anchor_crl(ok: bool, context: &mut X509StoreContextRef) -> bool {
    use openssl_sys::*;
    let anchor = context
        .chain()
        .is_some_and(|chain| context.error_depth() as usize + 1 == chain.len());
    let crl_error = matches!(
        context.error().as_raw(),
        X509_V_ERR_UNABLE_TO_GET_CRL
            | X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE
            | X509_V_ERR_CRL_SIGNATURE_FAILURE
            | X509_V_ERR_CRL_NOT_YET_VALID
            | X509_V_ERR_CRL_HAS_EXPIRED
            | X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD
            | X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD
            | X509_V_ERR_CERT_REVOKED
            | X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER
            | X509_V_ERR_KEYUSAGE_NO_CRL_SIGN
            | X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION
            | X509_V_ERR_DIFFERENT_CRL_SCOPE
            | X509_V_ERR_CRL_PATH_VALIDATION_ERROR
    );
    if !ok && anchor && crl_error {
        context.set_error(X509VerifyResult::OK);
        return true;
    }
    ok
}

mod native {
    // The safe OpenSSL bindings only expose CRL loading from files.
    unsafe extern "C" {
        pub fn X509_STORE_add_crl(
            store: *mut openssl_sys::X509_STORE,
            crl: *mut openssl_sys::X509_CRL,
        ) -> std::ffi::c_int;
    }
}
