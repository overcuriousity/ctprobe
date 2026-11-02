use bytes::Bytes;

pub type LogId = u16;

/// One log entry before X.509 parsing. `tbs_or_cert` is a TBSCertificate for
/// precertificates and a full certificate otherwise.
#[derive(Debug, Clone)]
pub struct RawEntry {
    pub log: LogId,
    pub index: u64,
    pub timestamp_ms: u64,
    pub is_precert: bool,
    pub tbs_or_cert: Bytes,
    pub der_size: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ParsedCert {
    pub issuer_cn: String,
    pub issuer_org: String,
    /// Raw DER of the issuer name; part of the dedup key.
    #[serde(skip)]
    pub issuer_der: Vec<u8>,
    pub serial_hex: String,
    pub subject_cn: Option<String>,
    pub names: Vec<String>,
    pub san_count: u32,
    pub key_type: String,
    pub key_bits: u32,
    pub sig_type: String,
    pub not_before_ms: i64,
    pub not_after_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalClass {
    Exact,
    Name,
    New,
}

impl RenewalClass {
    pub fn as_str(self) -> &'static str {
        match self {
            RenewalClass::Exact => "exact",
            RenewalClass::Name => "name",
            RenewalClass::New => "new",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertRow {
    pub parsed: ParsedCert,
    pub reg_domains: Vec<String>,
    pub primary_domain: Option<String>,
    pub is_wildcard: bool,
    pub is_precert: bool,
    pub renewal: RenewalClass,
    pub days_since_seen: Option<u32>,
    pub new_names: u32,
    pub new_domains: u32,
    pub log: LogId,
    pub index: u64,
    pub der_size: u32,
    pub seen_at_ms: i64,
    pub sct_lag_ms: i64,
    pub not_before_lag_ms: i64,
    pub cert_hash: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sighting {
    pub cert_hash: u64,
    pub log: LogId,
    pub seen_at_ms: i64,
}
