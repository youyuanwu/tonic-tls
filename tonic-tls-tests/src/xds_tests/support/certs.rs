use rcgen::{CertificateParams, CertifiedIssuer, Issuer, KeyPair};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{PrivateKeyDer, pem::PemObject},
};
use std::sync::Arc;
use tonic_tls_xds::{CertificateData, Identity};

pub(in crate::xds_tests) fn identity(cert: &rcgen::Certificate, key: &KeyPair) -> Identity {
    Identity::from_pem(cert.pem(), key.serialize_pem())
}

pub(in crate::xds_tests) fn roots(certs: &[&rcgen::Certificate]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert.der().clone()).unwrap();
    }
    roots
}

pub(in crate::xds_tests) fn base_config(certs: &[&rcgen::Certificate]) -> ClientConfig {
    let mut config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots(certs))
            .with_no_client_auth();
    config.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];
    config
}

pub(in crate::xds_tests) fn ca_params(name: &str, serial: u64) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.serial_number = Some(serial.into());
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params
}

pub(in crate::xds_tests) fn ca(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    CertifiedIssuer::self_signed(ca_params(name, 1), KeyPair::generate().unwrap()).unwrap()
}

pub(in crate::xds_tests) fn server_cert(
    issuer: &Issuer<'_, KeyPair>,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.serial_number = Some(3.into());
    let key = KeyPair::generate().unwrap();
    (params.signed_by(&key, issuer).unwrap(), key)
}

pub(in crate::xds_tests) fn crl(issuer: &Issuer<'_, KeyPair>, revoked: &[u64]) -> Vec<u8> {
    rcgen::CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2025, 1, 1),
        next_update: rcgen::date_time_ymd(2030, 1, 1),
        crl_number: (revoked.len() as u64 + 1).into(),
        issuing_distribution_point: None,
        revoked_certs: revoked
            .iter()
            .map(|serial| rcgen::RevokedCertParams {
                serial_number: (*serial).into(),
                revocation_time: rcgen::date_time_ymd(2025, 1, 1),
                reason_code: None,
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(issuer)
    .unwrap()
    .pem()
    .unwrap()
    .into_bytes()
}

pub(in crate::xds_tests) fn snapshot(
    issuer: &CertifiedIssuer<'_, KeyPair>,
    crls: Vec<Vec<u8>>,
) -> CertificateData {
    CertificateData::new(Some(issuer.pem().into_bytes()), None, Some(crls)).unwrap()
}

pub(in crate::xds_tests) fn server_config(
    chain: &[&rcgen::Certificate],
    key: &KeyPair,
) -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                chain.iter().map(|cert| cert.der().clone()).collect(),
                PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap(),
            )
            .unwrap(),
    )
}
