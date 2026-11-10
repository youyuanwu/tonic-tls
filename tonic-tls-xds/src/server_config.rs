#[cfg(feature = "rustls")]
use crate::CertificateData;
use crate::Identity;

/// Whether a server requests and requires a verified client certificate.
///
/// Certificate validation authenticates the peer. Applications still need to
/// authorize its identity for each RPC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClientAuth {
    /// Do not request client certificates. Configured client roots/CRLs are errors.
    #[default]
    Disabled,
    /// Validate presented certificates, but allow clients to remain anonymous.
    Optional,
    /// Require and validate a client certificate on every connection.
    Required,
}

/// Settings for crate-managed server TLS configurations.
///
/// Snapshots replace the base identity and client CA bundle when supplied.
/// Omitted material uses the original base, never a previous snapshot.
/// An effective server identity is always required. Client authentication
/// requires explicit nonempty roots; system trust is never used implicitly.
///
/// Defaults to no base identity or roots, [`ClientAuth::Disabled`], and HTTP/2
/// ALPN. Fluent setters assign settings; acceptor construction validates them.
/// Built-in backends disable session resumption and early data so every new
/// connection authenticates using its selected snapshot.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub(crate) roots: Option<Vec<u8>>,
    pub(crate) identity: Option<Identity>,
    pub(crate) client_auth: ClientAuth,
    pub(crate) alpn_protocols: Vec<Vec<u8>>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            roots: None,
            identity: None,
            client_auth: ClientAuth::Disabled,
            alpn_protocols: vec![tonic_tls::ALPN_H2.to_vec()],
        }
    }
}

impl ServerConfig {
    /// Sets the original server certificate chain and unencrypted private key.
    ///
    /// A snapshot identity replaces the entire chain and key.
    #[must_use]
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Sets the original PEM bundle of CAs trusted to authenticate clients.
    ///
    /// Snapshot roots replace, rather than extend, this bundle. Roots are invalid
    /// with [`ClientAuth::Disabled`]; empty effective roots are always invalid.
    #[must_use]
    pub fn with_ca_certificates(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.roots = Some(pem.into());
        self
    }

    /// Sets client authentication policy, independently of rotating material.
    ///
    /// [`ClientAuth::Optional`] allows anonymous clients. Use
    /// [`ClientAuth::Required`] when all peers must authenticate.
    #[must_use]
    pub fn with_client_auth(mut self, policy: ClientAuth) -> Self {
        self.client_auth = policy;
        self
    }

    /// Sets ALPN protocols in server preference order.
    ///
    /// Each name must contain 1 to 255 bytes and the length-prefixed list must
    /// fit in 65535 bytes. An empty list disables ALPN. With a nonempty list,
    /// an offered list without overlap fails negotiation; omission is allowed.
    #[must_use]
    pub fn with_alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    #[cfg(feature = "rustls")]
    pub(crate) fn validate(&self, data: &CertificateData) -> Result<(), tonic_tls::Error> {
        let roots = data.roots().or(self.roots.as_deref());
        match self.client_auth {
            ClientAuth::Disabled if roots.is_some() || data.crls().is_some() => {
                return Err(invalid_input(
                    "client roots and CRLs require client authentication",
                ));
            }
            ClientAuth::Optional | ClientAuth::Required if roots.is_none() => {
                return Err(invalid_input(
                    "client authentication requires explicit client roots",
                ));
            }
            _ => {}
        }
        if data.identity().or(self.identity.as_ref()).is_none() {
            return Err(invalid_input("server identity is required"));
        }
        let mut total = 0;
        for protocol in &self.alpn_protocols {
            if protocol.is_empty() || protocol.len() > usize::from(u8::MAX) {
                return Err(invalid_input(
                    "ALPN protocol names must contain 1 to 255 bytes",
                ));
            }
            total += 1 + protocol.len();
            if total > usize::from(u16::MAX) {
                return Err(invalid_input("ALPN protocol list must fit in 65535 bytes"));
            }
        }
        Ok(())
    }
}

#[cfg(feature = "rustls")]
pub(crate) fn invalid_input(message: &str) -> tonic_tls::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into()
}
