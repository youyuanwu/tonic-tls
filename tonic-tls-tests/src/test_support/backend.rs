use super::certs::roots;
use crate::helloworld::HelloRequest;
use futures::Stream;
use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod, SslVerifyMode},
    x509::X509,
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tonic::{
    Request, Status,
    transport::server::{Connected, TcpConnectInfo},
};

pub(crate) trait ServerBackend: Send + Sync + 'static {
    type ServerStream: AsyncRead + AsyncWrite + Connected + Send + Unpin + 'static;
    type Incoming: Stream<Item = Result<Self::ServerStream, tonic_tls::Error>> + Send + 'static;

    fn incoming(
        incoming: impl tonic_tls::Incoming<Io = TcpStream>,
        cert: &rcgen::Certificate,
        key: &rcgen::KeyPair,
        clients: Option<&[&rcgen::Certificate]>,
    ) -> Self::Incoming;

    fn peer_leaf(request: &Request<HelloRequest>) -> Result<CertificateDer<'static>, Status>;
}

pub(crate) struct Rustls;

impl ServerBackend for Rustls {
    type ServerStream = tonic_tls::rustls::TlsStream<TcpStream>;
    type Incoming = tonic_tls::rustls::TlsIncoming<TcpStream>;

    fn incoming(
        incoming: impl tonic_tls::Incoming<Io = TcpStream>,
        cert: &rcgen::Certificate,
        key: &rcgen::KeyPair,
        clients: Option<&[&rcgen::Certificate]>,
    ) -> Self::Incoming {
        let crypto = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ServerConfig::builder_with_provider(crypto.clone())
            .with_safe_default_protocol_versions()
            .unwrap();
        let builder = match clients {
            Some(clients) => {
                let verifier =
                    WebPkiClientVerifier::builder_with_provider(Arc::new(roots(clients)), crypto)
                        .build()
                        .unwrap();
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };
        let mut config = builder
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap(),
            )
            .unwrap();
        config.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];
        tonic_tls::rustls::TlsIncoming::new(incoming, Arc::new(config))
    }

    fn peer_leaf(request: &Request<HelloRequest>) -> Result<CertificateDer<'static>, Status> {
        request
            .extensions()
            .get::<tonic_tls::rustls::SslConnectInfo<TcpConnectInfo>>()
            .and_then(|info| info.peer_certs())
            .and_then(|certs| certs.first().cloned())
            .ok_or_else(|| Status::unauthenticated("missing client certificate"))
    }
}

pub(crate) struct OpenSsl;

impl ServerBackend for OpenSsl {
    type ServerStream = tonic_tls::openssl::SslStream<TcpStream>;
    type Incoming = tonic_tls::openssl::TlsIncoming<TcpStream>;

    fn incoming(
        incoming: impl tonic_tls::Incoming<Io = TcpStream>,
        cert: &rcgen::Certificate,
        key: &rcgen::KeyPair,
        clients: Option<&[&rcgen::Certificate]>,
    ) -> Self::Incoming {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        builder
            .set_certificate(&X509::from_der(cert.der()).unwrap())
            .unwrap();
        builder
            .set_private_key(&PKey::private_key_from_pem(key.serialize_pem().as_bytes()).unwrap())
            .unwrap();
        builder.check_private_key().unwrap();
        builder.set_alpn_select_callback(|_, protocols| {
            openssl::ssl::select_next_proto(tonic_tls::openssl::ALPN_H2_WIRE, protocols)
                .ok_or(openssl::ssl::AlpnError::NOACK)
        });
        match clients {
            Some(clients) => {
                assert!(!clients.is_empty(), "mTLS server requires client roots");
                for client in clients {
                    builder
                        .cert_store_mut()
                        .add_cert(X509::from_der(client.der()).unwrap())
                        .unwrap();
                }
                builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            }
            None => builder.set_verify(SslVerifyMode::NONE),
        }
        tonic_tls::openssl::TlsIncoming::new(incoming, builder.build())
    }

    fn peer_leaf(request: &Request<HelloRequest>) -> Result<CertificateDer<'static>, Status> {
        let certs = request
            .extensions()
            .get::<tonic_tls::openssl::SslConnectInfo<TcpConnectInfo>>()
            .and_then(|info| info.peer_certs())
            .ok_or_else(|| Status::unauthenticated("missing client certificate"))?;
        let leaf = certs
            .first()
            .ok_or_else(|| Status::unauthenticated("missing client certificate"))?;
        leaf.to_der().map(CertificateDer::from).map_err(|error| {
            Status::internal(format!("client certificate encoding failed: {error}"))
        })
    }
}
