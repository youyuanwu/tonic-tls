use rustls::{ClientConfig, RootCertStore, pki_types::PrivateKeyDer};
use std::sync::Arc;
use tonic_tls_xds::{CertificateData, Identity};

#[test]
fn rustls_client_factory_rejects_empty_chain_with_unknown_key_consistency() {
    #[derive(Debug)]
    struct SigningKey(Arc<dyn rustls::sign::SigningKey>);

    impl rustls::sign::SigningKey for SigningKey {
        fn choose_scheme(
            &self,
            offered: &[rustls::SignatureScheme],
        ) -> Option<Box<dyn rustls::sign::Signer>> {
            self.0.choose_scheme(offered)
        }

        fn algorithm(&self) -> rustls::SignatureAlgorithm {
            self.0.algorithm()
        }
    }

    #[derive(Debug)]
    struct KeyProvider;

    impl rustls::crypto::KeyProvider for KeyProvider {
        fn load_private_key(
            &self,
            key: PrivateKeyDer<'static>,
        ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
            let key = rustls::crypto::ring::default_provider()
                .key_provider
                .load_private_key(key)?;
            Ok(Arc::new(SigningKey(key)))
        }
    }

    // The wrapper deliberately omits public_key(), making rustls skip key matching.
    let mut crypto = rustls::crypto::ring::default_provider();
    crypto.key_provider = &KeyProvider;
    let base = ClientConfig::builder_with_provider(Arc::new(crypto))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let factory = tonic_tls_xds::rustls::TlsConnectorFactory::new(
        Arc::new(base),
        "localhost".try_into().unwrap(),
    );
    let key = rcgen::KeyPair::generate().unwrap();
    let data = CertificateData::new(
        None,
        Some(Identity::from_pem(b"", key.serialize_pem())),
        None,
    )
    .unwrap();
    let error = tonic_tls_xds::TlsConnectorFactory::<tokio::io::DuplexStream>::build_connector(
        &factory, &data,
    )
    .err()
    .expect("an empty chain must be rejected even without key matching");
    assert!(matches!(
        error.downcast_ref::<rustls::Error>(),
        Some(rustls::Error::NoCertificatesPresented),
    ));
}
