//! The HTTP client used for every request to a log.

use std::sync::Arc;

/// `aws-lc-rs` rather than the default `ring`: Microsec's logs chain to a P-521
/// root, and `ring` cannot verify `ecdsa-with-SHA512` certificate signatures.
pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A client builder with TLS configured. Use this for every client.
pub fn client_builder() -> reqwest::ClientBuilder {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("provider supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    reqwest::Client::builder().use_preconfigured_tls(tls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_verifies_ecdsa_sha512_chains() {
        let p = provider();
        assert!(p
            .signature_verification_algorithms
            .all
            .iter()
            .any(|a| a.signature_alg_id() == rustls::pki_types::alg_id::ECDSA_SHA512));
    }
}
