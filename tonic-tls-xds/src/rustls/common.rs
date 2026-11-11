use std::collections::{BTreeMap, btree_map::Entry};

use tokio_rustls::rustls::{
    crypto::CryptoProvider,
    pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, pem::PemObject},
    sign::CertifiedKey,
};

use crate::{CrlSelection, Identity};

pub(super) fn certified_key(
    identity: &Identity,
    crypto: &CryptoProvider,
) -> Result<CertifiedKey, tonic_tls::Error> {
    let certs =
        CertificateDer::pem_slice_iter(identity.cert_chain()).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(tokio_rustls::rustls::Error::NoCertificatesPresented.into());
    }
    let key = PrivateKeyDer::from_pem_slice(identity.key())?;
    Ok(CertifiedKey::from_der(certs, key, crypto)?)
}

pub(super) fn select_crls(
    bundles: &[Vec<u8>],
    selection: CrlSelection,
) -> Result<Vec<CertificateRevocationListDer<'static>>, tonic_tls::Error> {
    if bundles.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "CRL collection must not be empty",
        )
        .into());
    }
    let mut by_issuer = BTreeMap::new();
    for (bundle_index, bundle) in bundles.iter().enumerate() {
        let crls =
            CertificateRevocationListDer::pem_slice_iter(bundle).collect::<Result<Vec<_>, _>>()?;
        if crls.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("CRL bundle {bundle_index} must contain at least one PEM CRL"),
            )
            .into());
        }
        for (crl_index, crl) in crls.into_iter().enumerate() {
            // Parse entries too, so a malformed duplicate cannot be silently discarded.
            let parsed =
                webpki::CertRevocationList::from(webpki::OwnedCertRevocationList::from_der(&crl)?);
            match by_issuer.entry(parsed.issuer().to_vec()) {
                Entry::Vacant(entry) => {
                    entry.insert(crl);
                }
                Entry::Occupied(mut entry) => match selection {
                    CrlSelection::FirstPerIssuer => tracing::error!(
                        target: "tonic_tls_xds::rustls",
                        bundle_index,
                        crl_index,
                        "multiple CRLs with the same issuer; keeping the first CRL",
                    ),
                    CrlSelection::LastPerIssuer => {
                        entry.insert(crl);
                    }
                },
            }
        }
    }
    Ok(by_issuer.into_values().collect())
}
