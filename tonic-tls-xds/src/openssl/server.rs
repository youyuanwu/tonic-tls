use std::pin::Pin;

use openssl::{
    ssl::{
        AlpnError, Ssl, SslAcceptor, SslMethod, SslMode, SslOptions, SslSessionCacheMode,
        SslVerifyMode, SslVersion,
    },
    stack::Stack,
    x509::verify::X509VerifyFlags,
};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{configure_identity, configure_roots};
use crate::{CertificateData, ClientAuth, ServerConfig, server_config::invalid_input};

/// An immutable OpenSSL server acceptor built from one certificate snapshot.
///
/// Clones share a context. Each accept creates a new `SSL` and performs a full
/// handshake; the core stream wrapper exposes peer certificates to tonic.
#[derive(Clone)]
pub struct TlsAcceptor(SslAcceptor);

impl TlsAcceptor {
    /// Builds a fresh crate-owned server context from original settings and a snapshot.
    ///
    /// Snapshot identity and roots replace base material; omissions use the original
    /// base, never a previous snapshot. An effective identity is required. Client
    /// authentication requires explicit client roots and performs standard chain
    /// and client-authentication usage validation, without hostname checks.
    /// Disabled client authentication rejects roots and CRLs.
    ///
    /// Supplied CRLs follow the OpenSSL client backend's strict verification and
    /// duplicate-selection policy, checking client leaves and intermediates but
    /// excluding the trust anchor. No supplied CRLs means no revocation checking.
    ///
    /// TLS 1.2 or newer, exact supplied identity chains, server-preference ALPN,
    /// and disabled session resumption/early data are enforced. Native builders,
    /// contexts, authentication callbacks, and PSK hooks are not accepted.
    pub fn new(base: &ServerConfig, data: &CertificateData) -> Result<Self, tonic_tls::Error> {
        base.validate(data)?;
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_mode(SslMode::NO_AUTO_CHAIN);
        builder.set_session_cache_mode(SslSessionCacheMode::OFF);
        builder.set_options(SslOptions::NO_TICKET);
        builder.set_num_tickets(0)?;
        builder.set_max_early_data(0)?;

        let mode = match base.client_auth {
            ClientAuth::Disabled => SslVerifyMode::NONE,
            ClientAuth::Optional => SslVerifyMode::PEER,
            ClientAuth::Required => SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        };
        builder.set_verify(mode);
        builder
            .verify_param_mut()
            .set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
        if let Some(roots) = data.roots().or(base.roots.as_deref()) {
            let roots = configure_roots(&mut builder, roots, data, mode)?;
            let mut names = Stack::new()?;
            for root in roots {
                names.push(root.subject_name().to_owned()?)?;
            }
            builder.set_client_ca_list(names);
        }
        let identity = data
            .identity()
            .or(base.identity.as_ref())
            .ok_or_else(|| invalid_input("server identity is required"))?;
        configure_identity(&mut builder, identity)?;
        if !base.alpn_protocols.is_empty() {
            let protocols = base.alpn_protocols.clone();
            // Return a slice of the client's buffer, not the captured server list.
            builder.set_alpn_select_callback(move |_, offered| {
                for protocol in &protocols {
                    let mut remaining = offered;
                    while let Some((&len, rest)) = remaining.split_first() {
                        let len = usize::from(len);
                        if len == 0 || rest.len() < len {
                            return Err(AlpnError::ALERT_FATAL);
                        }
                        let (name, rest) = rest.split_at(len);
                        if name == protocol {
                            return Ok(name);
                        }
                        remaining = rest;
                    }
                }
                Err(AlpnError::ALERT_FATAL)
            });
        }
        Ok(Self(builder.build()))
    }
}

impl<IO> tonic_tls::TlsAcceptor<IO> for TlsAcceptor
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type TlsStream = tonic_tls::openssl::SslStream<IO>;

    async fn accept(&self, stream: IO) -> Result<Self::TlsStream, tonic_tls::Error> {
        let ssl = Ssl::new(self.0.context())?;
        let mut stream = tokio_openssl::SslStream::new(ssl, stream)?;
        Pin::new(&mut stream).accept().await?;
        Ok(tonic_tls::openssl::SslStream::new(stream))
    }
}

/// An OpenSSL factory for [`crate::ReloadableTlsAcceptor`].
///
/// Creates a fresh server context for each changed snapshot, including CRL-only
/// updates. Established connections keep their selected context.
///
/// ```no_run
/// # fn incoming(
/// #     provider: std::sync::Arc<dyn tonic_tls_xds::CertificateProvider>,
/// #     tcp_incoming: tonic::transport::server::TcpIncoming,
/// # ) -> Result<(), tonic_tls::Error> {
/// use tonic_tls_xds::{ClientAuth, ReloadableTlsAcceptor, ServerConfig};
///
/// // The provider supplies the server identity and client trust bundle.
/// let config = ServerConfig::default().with_client_auth(ClientAuth::Required);
/// let factory = tonic_tls_xds::openssl::TlsAcceptorFactory::new(config);
/// let acceptor = ReloadableTlsAcceptor::new(provider, factory)?;
/// let incoming = acceptor.incoming(tcp_incoming);
/// // Pass incoming to tonic::transport::Server::serve_with_incoming.
/// # let _ = incoming;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct TlsAcceptorFactory {
    config: ServerConfig,
}

impl TlsAcceptorFactory {
    /// Records original server settings; validation happens when an acceptor is built.
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }
}

impl<IO> crate::TlsAcceptorFactory<IO> for TlsAcceptorFactory
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Acceptor = TlsAcceptor;

    fn build_acceptor(&self, data: &CertificateData) -> Result<Self::Acceptor, tonic_tls::Error> {
        TlsAcceptor::new(&self.config, data)
    }
}
