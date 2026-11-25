use crate::test_support::certs::roots;
use openssl::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use rustls::{
    ClientConfig,
    pki_types::{PrivateKeyDer, pem::PemObject},
};
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tonic::transport::Uri;
use tonic_tls::Transport;
use tower::util::BoxCloneSyncService;

pub(in crate::xds_tests) type Connector<S> =
    BoxCloneSyncService<Uri, hyper_util::rt::TokioIo<S>, tonic_tls::Error>;

pub(in crate::xds_tests) trait TestBackend {
    type TlsStream: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    fn connector(
        transport: impl Transport<Io = TcpStream>,
        trusted: &[&rcgen::Certificate],
        identity: Option<(&rcgen::Certificate, &rcgen::KeyPair)>,
    ) -> Connector<Self::TlsStream>;
}

pub(in crate::xds_tests) struct Rustls;

impl TestBackend for Rustls {
    type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

    fn connector(
        transport: impl Transport<Io = TcpStream>,
        trusted: &[&rcgen::Certificate],
        identity: Option<(&rcgen::Certificate, &rcgen::KeyPair)>,
    ) -> Connector<Self::TlsStream> {
        let builder =
            ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots(trusted));
        let mut config = match identity {
            Some((cert, key)) => builder
                .with_client_auth_cert(
                    vec![cert.der().clone()],
                    PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap(),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];
        BoxCloneSyncService::new(tonic_tls::rustls::TlsConnector::new(
            transport,
            Arc::new(config),
            "localhost".try_into().unwrap(),
        ))
    }
}

pub(in crate::xds_tests) struct OpenSsl;

impl TestBackend for OpenSsl {
    type TlsStream = tokio_openssl::SslStream<TcpStream>;

    fn connector(
        transport: impl Transport<Io = TcpStream>,
        trusted: &[&rcgen::Certificate],
        identity: Option<(&rcgen::Certificate, &rcgen::KeyPair)>,
    ) -> Connector<Self::TlsStream> {
        let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
        builder.set_verify(SslVerifyMode::PEER);
        for cert in trusted {
            builder
                .cert_store_mut()
                .add_cert(X509::from_der(cert.der()).unwrap())
                .unwrap();
        }
        if let Some((cert, key)) = identity {
            builder
                .set_certificate(&X509::from_der(cert.der()).unwrap())
                .unwrap();
            builder
                .set_private_key(
                    &PKey::private_key_from_pem(key.serialize_pem().as_bytes()).unwrap(),
                )
                .unwrap();
            builder.check_private_key().unwrap();
        }
        builder
            .set_alpn_protos(tonic_tls::openssl::ALPN_H2_WIRE)
            .unwrap();
        BoxCloneSyncService::new(tonic_tls::openssl::TlsConnector::new(
            transport,
            builder.build(),
            "localhost".into(),
        ))
    }
}
