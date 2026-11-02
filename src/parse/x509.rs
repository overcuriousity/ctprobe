use super::ParseError;
use crate::types::{ParsedCert, RawEntry};
use x509_parser::certificate::TbsCertificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

fn sig_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.5" => "rsa-sha1",
        "1.2.840.113549.1.1.11" => "rsa-sha256",
        "1.2.840.113549.1.1.12" => "rsa-sha384",
        "1.2.840.113549.1.1.13" => "rsa-sha512",
        "1.2.840.113549.1.1.10" => "rsa-pss",
        "1.2.840.10045.4.3.2" => "ecdsa-sha256",
        "1.2.840.10045.4.3.3" => "ecdsa-sha384",
        "1.2.840.10045.4.3.4" => "ecdsa-sha512",
        "1.3.101.112" => "ed25519",
        other => other,
    }
    .to_string()
}

fn from_tbs(tbs: &TbsCertificate<'_>) -> Result<ParsedCert, ParseError> {
    let (key_type, key_bits) = match tbs.subject_pki.parsed() {
        Ok(PublicKey::RSA(k)) => ("rsa".to_string(), k.key_size() as u32),
        Ok(PublicKey::EC(k)) => ("ecdsa".to_string(), k.key_size() as u32),
        _ => (tbs.subject_pki.algorithm.algorithm.to_id_string(), 0),
    };
    let subject_cn = tbs
        .subject
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(str::to_string);
    let mut names: Vec<String> = Vec::new();
    let mut san_count = 0u32;
    let san = tbs.subject_alternative_name().map_err(|e| ParseError::X509(e.to_string()))?;
    if let Some(san) = san {
        for gn in &san.value.general_names {
            san_count += 1;
            if let GeneralName::DNSName(n) = gn {
                names.push(n.to_string());
            }
        }
    }
    if let Some(cn) = &subject_cn {
        names.push(cn.clone());
    }
    let mut names: Vec<String> =
        names.iter().filter_map(|n| crate::names::normalize(n)).collect();
    names.sort_unstable();
    names.dedup();
    Ok(ParsedCert {
        issuer_cn: tbs
            .issuer
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .unwrap_or_default()
            .to_string(),
        issuer_org: tbs
            .issuer
            .iter_organization()
            .next()
            .and_then(|a| a.as_str().ok())
            .unwrap_or_default()
            .to_string(),
        issuer_der: tbs.issuer.as_raw().to_vec(),
        serial_hex: {
            // DER adds a leading zero to keep the integer positive.
            let raw = tbs.raw_serial();
            let raw = raw.strip_prefix(&[0u8]).filter(|r| !r.is_empty()).unwrap_or(raw);
            raw.iter().map(|b| format!("{b:02x}")).collect()
        },
        subject_cn,
        names,
        san_count,
        key_type,
        key_bits,
        sig_type: sig_name(&tbs.signature.algorithm.to_id_string()),
        not_before_ms: tbs.validity.not_before.timestamp().saturating_mul(1000),
        not_after_ms: tbs.validity.not_after.timestamp().saturating_mul(1000),
    })
}

pub fn extract(e: &RawEntry) -> Result<ParsedCert, ParseError> {
    let bad = |err: String| ParseError::X509(err);
    if e.is_precert {
        let (_, tbs) = TbsCertificate::from_der(&e.tbs_or_cert).map_err(|x| bad(x.to_string()))?;
        from_tbs(&tbs)
    } else {
        let (_, c) = X509Certificate::from_der(&e.tbs_or_cert).map_err(|x| bad(x.to_string()))?;
        from_tbs(&c.tbs_certificate)
    }
}
