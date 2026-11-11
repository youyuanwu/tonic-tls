use std::collections::{BTreeMap, btree_map::Entry};

use foreign_types::ForeignType;
use openssl::{
    error::ErrorStack,
    pkey::PKey,
    ssl::{SslContextBuilder, SslVerifyMode},
    x509::{
        X509, X509Crl, X509StoreContextRef, X509VerifyResult, store::X509StoreBuilder,
        verify::X509VerifyFlags,
    },
};
use pki_types::{CertificateRevocationListDer, PrivateKeyDer, pem::PemObject};

use crate::{CertificateData, CrlSelection, Identity, invalid_input};

pub(super) fn configure_roots(
    builder: &mut SslContextBuilder,
    pem: &[u8],
    data: &CertificateData,
    mode: SslVerifyMode,
) -> Result<Vec<X509>, tonic_tls::Error> {
    let roots = X509::stack_from_pem(pem)?;
    if roots.is_empty() {
        return Err(invalid_input(
            "root bundle must contain at least one PEM certificate",
        ));
    }
    let mut store = X509StoreBuilder::new()?;
    for root in &roots {
        store.add_cert(root.clone())?;
    }
    if let Some(bundles) = data.crls() {
        for crl in select_crls(bundles, data.crl_selection())? {
            // The store retains a reference; both arguments are live for the call.
            if unsafe { native::X509_STORE_add_crl(store.as_ptr(), crl.as_ptr()) } != 1 {
                return Err(ErrorStack::get().into());
            }
        }
        builder
            .verify_param_mut()
            .set_flags(X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL)?;
        builder.set_verify_callback(mode, verify_except_anchor_crl);
    }
    builder.set_cert_store(store.build());
    Ok(roots)
}

pub(super) fn configure_identity(
    builder: &mut SslContextBuilder,
    identity: &Identity,
) -> Result<(), tonic_tls::Error> {
    let mut certs = X509::stack_from_pem(identity.cert_chain())?.into_iter();
    let cert = certs
        .next()
        .ok_or_else(|| invalid_input("identity must contain at least one PEM certificate"))?;
    // Decode only unencrypted PEM formats; OpenSSL's PEM reader can prompt.
    let key_der = PrivateKeyDer::from_pem_slice(identity.key())?;
    let key = PKey::private_key_from_der(key_der.secret_der())?;
    builder.set_certificate(&cert)?;
    builder.set_private_key(&key)?;
    builder.check_private_key()?;
    for cert in certs {
        builder.add_extra_chain_cert(cert)?;
    }
    Ok(())
}

fn select_crls(
    bundles: &[Vec<u8>],
    selection: CrlSelection,
) -> Result<Vec<X509Crl>, tonic_tls::Error> {
    if bundles.is_empty() {
        return Err(invalid_input("CRL collection must not be empty"));
    }
    let mut by_issuer = BTreeMap::new();
    for (bundle_index, bundle) in bundles.iter().enumerate() {
        let mut count = 0;
        for (crl_index, der) in CertificateRevocationListDer::pem_slice_iter(bundle).enumerate() {
            let crl = X509Crl::from_der(&der?)?;
            if crl.next_update().is_none() {
                return Err(invalid_input("CRL must contain nextUpdate"));
            }
            match by_issuer.entry(crl.issuer_name().to_der()?) {
                Entry::Vacant(entry) => {
                    entry.insert(crl);
                }
                Entry::Occupied(mut entry) => match selection {
                    CrlSelection::FirstPerIssuer => tracing::error!(
                        target: "tonic_tls_xds::openssl",
                        bundle_index,
                        crl_index,
                        "multiple CRLs with the same issuer; keeping the first CRL",
                    ),
                    CrlSelection::LastPerIssuer => {
                        entry.insert(crl);
                    }
                },
            }
            count += 1;
        }
        if count == 0 {
            return Err(invalid_input(&format!(
                "CRL bundle {bundle_index} must contain at least one PEM CRL"
            )));
        }
    }
    Ok(by_issuer.into_values().collect())
}

// CRL_CHECK_ALL includes the terminal trust anchor, unlike the provider contract.
// Preserve every other OpenSSL verification failure, including non-CRL anchor errors.
fn verify_except_anchor_crl(ok: bool, context: &mut X509StoreContextRef) -> bool {
    use openssl_sys::*;
    let anchor = context
        .chain()
        .is_some_and(|chain| context.error_depth() as usize + 1 == chain.len());
    let crl_error = matches!(
        context.error().as_raw(),
        X509_V_ERR_UNABLE_TO_GET_CRL
            | X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE
            | X509_V_ERR_CRL_SIGNATURE_FAILURE
            | X509_V_ERR_CRL_NOT_YET_VALID
            | X509_V_ERR_CRL_HAS_EXPIRED
            | X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD
            | X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD
            | X509_V_ERR_CERT_REVOKED
            | X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER
            | X509_V_ERR_KEYUSAGE_NO_CRL_SIGN
            | X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION
            | X509_V_ERR_DIFFERENT_CRL_SCOPE
            | X509_V_ERR_CRL_PATH_VALIDATION_ERROR
    );
    if !ok && anchor && crl_error {
        context.set_error(X509VerifyResult::OK);
        return true;
    }
    ok
}

mod native {
    // The safe OpenSSL bindings only expose CRL loading from files.
    unsafe extern "C" {
        pub fn X509_STORE_add_crl(
            store: *mut openssl_sys::X509_STORE,
            crl: *mut openssl_sys::X509_CRL,
        ) -> std::ffi::c_int;
    }
}
