use std::sync::Arc;

/// A PEM-encoded certificate chain and its private key.
///
/// Construction does not validate the material. TLS backends validate it before
/// use. Publish the certificate and key together to avoid half-applied updates.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    cert_chain: Vec<u8>,
    key: Vec<u8>,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateData {
    /// Replace the trusted CA certificates.
    RootsOnly { roots: Vec<u8> },
    /// Replace the local certificate chain and private key.
    IdentityOnly { identity: Identity },
    /// Replace both the trusted CA certificates and local identity.
    Both { roots: Vec<u8>, identity: Identity },
}

impl CertificateData {
    /// PEM-encoded CA trust bundle, if supplied.
    pub fn roots(&self) -> Option<&[u8]> {
        match self {
            Self::RootsOnly { roots } | Self::Both { roots, .. } => Some(roots),
            Self::IdentityOnly { .. } => None,
        }
    }

    /// Local certificate chain and private key, if supplied.
    pub fn identity(&self) -> Option<&Identity> {
        match self {
            Self::IdentityOnly { identity } | Self::Both { identity, .. } => Some(identity),
            Self::RootsOnly { .. } => None,
        }
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
        let debug = format!("{:?}", CertificateData::IdentityOnly { identity });
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-key"));
    }
}
