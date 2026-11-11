use super::{CertificateData, Identity, base_config};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream},
    net::TcpStream,
};
use tonic_tls_xds::{ConnectorPair, TlsConnectorFactory};

pub(super) enum VerificationFailure {
    Revoked,
    UnknownRevocationStatus,
    CrlSignature,
}

pub(super) trait TestBackend {
    type TcpStream: AsyncRead + AsyncWrite + Send + Unpin + 'static;
    type DuplexStream: AsyncRead + AsyncWrite + Send + Unpin + 'static;
    type Connector: tonic_tls::TlsConnector<TcpStream, TlsStream = Self::TcpStream>
        + tonic_tls::TlsConnector<DuplexStream, TlsStream = Self::DuplexStream>;
    type Factory: TlsConnectorFactory<TcpStream, Connector = Self::Connector>
        + TlsConnectorFactory<DuplexStream, Connector = Self::Connector>
        + Clone;

    const LOG_TARGET: &'static str;

    fn factory(roots: &[&rcgen::Certificate], identity: Option<Identity>) -> Self::Factory;
    fn assert_empty_identity(error: &tonic_tls::Error);
    fn assert_verification_error(error: &tonic_tls::Error, expected: VerificationFailure);
}

pub(super) struct Rustls;

impl TestBackend for Rustls {
    type TcpStream = tokio_rustls::client::TlsStream<TcpStream>;
    type DuplexStream = tokio_rustls::client::TlsStream<DuplexStream>;
    type Connector = tonic_tls_xds::rustls::TlsConnector;
    type Factory = tonic_tls_xds::rustls::TlsConnectorFactory;
    const LOG_TARGET: &'static str = "tonic_tls_xds::rustls";

    fn factory(roots: &[&rcgen::Certificate], identity: Option<Identity>) -> Self::Factory {
        let mut config = base_config(roots);
        if let Some(identity) = identity {
            config = tonic_tls_xds::rustls::build_client_config(
                &config,
                &CertificateData::new(None, Some(identity), None).unwrap(),
            )
            .unwrap();
        }
        Self::Factory::new(Arc::new(config), "localhost".try_into().unwrap())
    }

    fn assert_empty_identity(error: &tonic_tls::Error) {
        assert!(matches!(
            error.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::NoCertificatesPresented)
        ));
    }

    fn assert_verification_error(error: &tonic_tls::Error, expected: VerificationFailure) {
        let error = error
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .get_ref()
            .unwrap()
            .downcast_ref::<rustls::Error>()
            .unwrap();
        let expected = match expected {
            VerificationFailure::Revoked => {
                rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked)
            }
            VerificationFailure::UnknownRevocationStatus => {
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownRevocationStatus)
            }
            VerificationFailure::CrlSignature => rustls::Error::InvalidCertRevocationList(
                rustls::CertRevocationListError::BadSignature,
            ),
        };
        assert_eq!(error, &expected);
    }
}

pub(super) struct OpenSsl;

impl TestBackend for OpenSsl {
    type TcpStream = tokio_openssl::SslStream<TcpStream>;
    type DuplexStream = tokio_openssl::SslStream<DuplexStream>;
    type Connector = tonic_tls_xds::openssl::TlsConnector;
    type Factory = tonic_tls_xds::openssl::TlsConnectorFactory;
    const LOG_TARGET: &'static str = "tonic_tls_xds::openssl";

    fn factory(roots: &[&rcgen::Certificate], identity: Option<Identity>) -> Self::Factory {
        let pem = roots.iter().map(|cert| cert.pem()).collect::<String>();
        let mut config = tonic_tls_xds::openssl::ClientConfig::default().with_ca_certificates(pem);
        if let Some(identity) = identity {
            config = config.with_identity(identity);
        }
        Self::Factory::new(config, "localhost".into())
    }

    fn assert_empty_identity(error: &tonic_tls::Error) {
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            error.to_string(),
            "identity must contain at least one PEM certificate"
        );
    }

    fn assert_verification_error(error: &tonic_tls::Error, _: VerificationFailure) {
        // The adapter returns OpenSSL's SSL error stack, not its X509 verify result.
        super::openssl_tests::assert_verification_error(error);
    }
}

pub(super) trait TestServerBackend: TestBackend + Send + Sync + 'static {
    type ServerTcpStream: AsyncRead
        + AsyncWrite
        + tonic::transport::server::Connected
        + Send
        + Unpin
        + 'static;
    type ServerDuplexStream: AsyncRead + AsyncWrite + Send + Unpin + 'static;
    type Acceptor: tonic_tls::TlsAcceptor<TcpStream, TlsStream = Self::ServerTcpStream>
        + tonic_tls::TlsAcceptor<DuplexStream, TlsStream = Self::ServerDuplexStream>;
    type ServerFactory: tonic_tls_xds::TlsAcceptorFactory<TcpStream, Acceptor = Self::Acceptor>
        + tonic_tls_xds::TlsAcceptorFactory<DuplexStream, Acceptor = Self::Acceptor>;

    fn server_factory(config: tonic_tls_xds::ServerConfig) -> Self::ServerFactory;
    fn peer_leaf(
        request: &tonic::Request<super::HelloRequest>,
    ) -> Result<rustls::pki_types::CertificateDer<'static>, tonic::Status>;
    fn assert_invalid_certificate(error: &tonic_tls::Error);
}

impl TestServerBackend for Rustls {
    type ServerTcpStream = tonic_tls::rustls::TlsStream<TcpStream>;
    type ServerDuplexStream = tonic_tls::rustls::TlsStream<DuplexStream>;
    type Acceptor = tonic_tls_xds::rustls::TlsAcceptor;
    type ServerFactory = tonic_tls_xds::rustls::TlsAcceptorFactory;

    fn server_factory(config: tonic_tls_xds::ServerConfig) -> Self::ServerFactory {
        Self::ServerFactory::new(config, Arc::new(rustls::crypto::ring::default_provider()))
    }

    fn peer_leaf(
        request: &tonic::Request<super::HelloRequest>,
    ) -> Result<rustls::pki_types::CertificateDer<'static>, tonic::Status> {
        request
            .extensions()
            .get::<tonic_tls::rustls::SslConnectInfo<super::TcpConnectInfo>>()
            .and_then(|info| info.peer_certs())
            .and_then(|certs| certs.first().cloned())
            .ok_or_else(|| tonic::Status::unauthenticated("missing client certificate"))
    }

    fn assert_invalid_certificate(error: &tonic_tls::Error) {
        let error = error
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .get_ref()
            .unwrap()
            .downcast_ref::<rustls::Error>()
            .unwrap();
        assert!(matches!(error, rustls::Error::InvalidCertificate(_)));
    }
}

impl TestServerBackend for OpenSsl {
    type ServerTcpStream = tonic_tls::openssl::SslStream<TcpStream>;
    type ServerDuplexStream = tonic_tls::openssl::SslStream<DuplexStream>;
    type Acceptor = tonic_tls_xds::openssl::TlsAcceptor;
    type ServerFactory = tonic_tls_xds::openssl::TlsAcceptorFactory;

    fn server_factory(config: tonic_tls_xds::ServerConfig) -> Self::ServerFactory {
        Self::ServerFactory::new(config)
    }

    fn peer_leaf(
        request: &tonic::Request<super::HelloRequest>,
    ) -> Result<rustls::pki_types::CertificateDer<'static>, tonic::Status> {
        let certs = request
            .extensions()
            .get::<tonic_tls::openssl::SslConnectInfo<super::TcpConnectInfo>>()
            .and_then(|info| info.peer_certs())
            .ok_or_else(|| tonic::Status::unauthenticated("missing client certificate"))?;
        let leaf = certs
            .first()
            .ok_or_else(|| tonic::Status::unauthenticated("missing client certificate"))?;
        leaf.to_der()
            .map(rustls::pki_types::CertificateDer::from)
            .map_err(|error| {
                tonic::Status::internal(format!("client certificate encoding failed: {error}"))
            })
    }

    fn assert_invalid_certificate(error: &tonic_tls::Error) {
        super::openssl_tests::assert_verification_error(error);
    }
}

#[derive(Clone)]
pub(super) struct CountingFactory<F> {
    pub inner: F,
    pub builds: Arc<AtomicUsize>,
}

impl<IO, F> TlsConnectorFactory<IO> for CountingFactory<F>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: TlsConnectorFactory<IO>,
{
    type Connector = F::Connector;

    fn build_connector(
        &self,
        data: &CertificateData,
    ) -> Result<ConnectorPair<IO, Self::Connector>, tonic_tls::Error> {
        self.builds.fetch_add(1, Ordering::Relaxed);
        self.inner.build_connector(data)
    }
}
