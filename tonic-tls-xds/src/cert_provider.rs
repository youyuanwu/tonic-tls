use std::sync::Arc;

/// Raw, unvalidated bytes intended to contain PEM-encoded TLS material.
pub(crate) type PemBytes = Vec<u8>;

/// Selection of CRLs with the same DER-encoded issuer, matching gRPC C++ providers.
///
/// Neither policy selects by CRL number or issuance time. Issuing distribution
/// points and signing-key identifiers are not part of the selection key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlSelection {
    /// Keep the first CRL for each issuer and log duplicates at `ERROR`.
    FirstPerIssuer,
    /// Keep the last encountered CRL for each issuer.
    LastPerIssuer,
}

/// A PEM-encoded certificate chain and its private key.
///
/// Construction does not validate the material. TLS backends validate it before
/// use. Publish the certificate and key together to avoid half-applied updates.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    cert_chain: PemBytes,
    key: PemBytes,
}

impl Identity {
    pub fn from_pem(cert_chain: impl Into<Vec<u8>>, key: impl Into<Vec<u8>>) -> Self {
        Self {
            cert_chain: cert_chain.into(),
            key: key.into(),
        }
    }

    /// PEM-encoded certificate chain, leaf certificate first.
    pub fn cert_chain(&self) -> &[u8] {
        &self.cert_chain
    }

    /// PEM-encoded private key.
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("cert_chain_bytes", &self.cert_chain.len())
            .field("key", &"<redacted>")
            .finish()
    }
}

/// A backend-neutral snapshot of certificate material.
///
/// Each snapshot supplies roots, an identity, or both. Material not supplied
/// by the snapshot retains the connector's original configuration; snapshots
/// are not incremental updates to the previous snapshot.
/// CRLs are supplied together with the roots used to verify the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateData {
    roots: Option<PemBytes>,
    identity: Option<Identity>,
    crls: Option<Vec<PemBytes>>,
    pub(crate) crl_selection: CrlSelection,
}

impl CertificateData {
    /// Creates a snapshot, validating only which material is supplied.
    ///
    /// At least roots or an identity must be supplied, and CRLs require roots.
    /// Contents are not parsed or validated here; TLS factories do that before
    /// use. In particular, `Some(Vec::new())` for CRLs is preserved as invalid
    /// input, not converted to `None` (which requests no CRL override).
    /// CRLs use [`CrlSelection::FirstPerIssuer`], in buffer and PEM-block order.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error if neither roots nor identity is supplied,
    /// or if CRLs are supplied without roots.
    ///
    /// ```
    /// use tonic_tls_xds::{CertificateData, Identity};
    ///
    /// let data = CertificateData::new(
    ///     None,
    ///     Some(Identity::from_pem(b"certificate PEM", b"private key PEM")),
    ///     None,
    /// )?;
    /// assert!(data.identity().is_some());
    /// assert!(data.roots().is_none());
    /// # Ok::<(), tonic_tls::Error>(())
    /// ```
    pub fn new(
        roots: Option<Vec<u8>>,
        identity: Option<Identity>,
        crls: Option<Vec<Vec<u8>>>,
    ) -> Result<Self, tonic_tls::Error> {
        if crls.is_some() && roots.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "CRLs require roots in the same snapshot",
            )
            .into());
        }
        if roots.is_none() && identity.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "at least roots or an identity must be supplied",
            )
            .into());
        }
        Ok(Self {
            roots,
            identity,
            crls,
            crl_selection: CrlSelection::FirstPerIssuer,
        })
    }

    /// PEM-encoded CA trust bundle, if supplied.
    pub fn roots(&self) -> Option<&[u8]> {
        self.roots.as_deref()
    }

    /// Local certificate chain and private key, if supplied.
    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// Raw PEM CRL bundles, if revocation checking is requested.
    ///
    /// Each buffer must contain one or more PEM CRLs. Empty inputs are invalid,
    /// not a request to disable checking. Backends must reject revoked, unknown,
    /// and expired revocation status for the peer's chain, excluding the trust
    /// anchor. `None` requests no CRL override.
    /// Backends must select one CRL per issuer using [`Self::crl_selection`].
    pub fn crls(&self) -> Option<&[Vec<u8>]> {
        self.crls.as_deref()
    }

    /// Duplicate-issuer selection policy for this snapshot.
    ///
    /// [`Self::new`] and single-file sources use first-wins. Directory snapshots
    /// from [`crate::FileWatcherProvider`] use last-wins in filename/PEM-block
    /// order. Selection is part of snapshot equality and applies before handshake
    /// verification; there is no fallback to other CRLs if the selected one fails.
    pub fn crl_selection(&self) -> CrlSelection {
        self.crl_selection
    }
}

/// Supplies the current certificate material for new TLS connections.
///
/// Implementations should refresh outside the connection path and return a
/// cached, immutable snapshot promptly. Return the same [`Arc`] while the
/// material is unchanged and publish a new one when it changes, so adapters can
/// cache parsed credentials. This interface does not require a TLS feature.
///
/// Snapshot retrieval and validation errors fail connector construction or the
/// connection attempt; adapters must not silently fall back to older credentials
/// or unauthenticated TLS. A provider
/// may retain its last valid snapshot after a refresh failure, but should
/// report that failure through the application's logging or monitoring.
pub trait CertificateProvider: Send + Sync {
    /// Returns the current cached certificate snapshot.
    fn snapshot(&self) -> Result<Arc<CertificateData>, tonic_tls::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_debug_redacts_private_key() {
        let identity = Identity::from_pem(b"certificate", b"secret-key");
        assert_eq!(identity.cert_chain(), b"certificate");
        assert_eq!(identity.key(), b"secret-key");
        let debug = format!(
            "{:?}",
            CertificateData::new(None, Some(identity), None).unwrap()
        );
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-key"));
    }

    #[test]
    fn crl_snapshot_exposes_raw_material_and_redacts_identity() {
        let data = CertificateData::new(
            Some(b"roots".to_vec()),
            Some(Identity::from_pem(b"cert", b"secret-key")),
            Some(vec![b"crl-1".to_vec(), b"crl-2".to_vec()]),
        )
        .unwrap();
        assert_eq!(data.roots(), Some(b"roots".as_slice()));
        assert_eq!(
            data.crls().unwrap(),
            &[b"crl-1".to_vec(), b"crl-2".to_vec()]
        );
        assert_eq!(data.identity().unwrap().key(), b"secret-key");
        assert!(!format!("{data:?}").contains("secret-key"));
    }

    #[test]
    fn constructor_validates_material_combinations() {
        for roots in [None, Some(b"roots".to_vec())] {
            for identity in [None, Some(Identity::from_pem(b"cert", b"key"))] {
                for crls in [None, Some(vec![b"crl".to_vec()])] {
                    let result =
                        CertificateData::new(roots.clone(), identity.clone(), crls.clone());
                    let message = if crls.is_some() && roots.is_none() {
                        Some("CRLs require roots in the same snapshot")
                    } else if roots.is_none() && identity.is_none() {
                        Some("at least roots or an identity must be supplied")
                    } else {
                        None
                    };
                    if let Some(message) = message {
                        let error = result.unwrap_err();
                        assert_eq!(
                            error.downcast_ref::<std::io::Error>().unwrap().kind(),
                            std::io::ErrorKind::InvalidInput,
                        );
                        assert_eq!(error.to_string(), message);
                    } else {
                        let data = result.unwrap();
                        assert_eq!(data.roots(), roots.as_deref());
                        assert_eq!(data.identity(), identity.as_ref());
                        assert_eq!(data.crls(), crls.as_deref());
                    }
                }
            }
        }
    }

    #[test]
    fn constructor_preserves_empty_and_invalid_contents_for_backend_validation() {
        let no_crls = CertificateData::new(Some(Vec::new()), None, None).unwrap();
        assert_eq!(no_crls.roots(), Some(b"".as_slice()));
        assert!(no_crls.crls().is_none());
        for crls in [Vec::new(), vec![Vec::new()], vec![b"not a CRL".to_vec()]] {
            let data = CertificateData::new(Some(Vec::new()), None, Some(crls.clone())).unwrap();
            assert_eq!(data.crls(), Some(crls.as_slice()));
            assert_ne!(data, no_crls);
        }
        let identity = Identity::from_pem(b"", b"not a key");
        let data = CertificateData::new(None, Some(identity.clone()), None).unwrap();
        assert_eq!(data.identity(), Some(&identity));
    }

    #[test]
    fn crl_selection_is_part_of_snapshot_equality() {
        let first =
            CertificateData::new(Some(b"roots".to_vec()), None, Some(vec![b"crl".to_vec()]))
                .unwrap();
        assert_eq!(first.crl_selection(), CrlSelection::FirstPerIssuer);
        let mut last = first.clone();
        last.crl_selection = CrlSelection::LastPerIssuer;
        assert_ne!(first, last);
        assert_eq!(last.crls(), first.crls());
    }
}
