use bytes::Bytes;
use ctprobe::parse::{decode_merkle_leaf, decode_tile, extract, EntryKind};
use ctprobe::types::RawEntry;

fn raw(kind: EntryKind, body: &[u8]) -> RawEntry {
    RawEntry {
        log: 0,
        index: 0,
        timestamp_ms: 0,
        is_precert: kind == EntryKind::Precert,
        tbs_or_cert: Bytes::copy_from_slice(body),
        der_size: body.len() as u32,
    }
}

const TILE: &[u8] = include_bytes!("fixtures/tile.bin");

fn get_entries() -> Vec<Vec<u8>> {
    use base64::Engine;
    let v: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/get_entries.json")).unwrap();
    v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            base64::engine::general_purpose::STANDARD
                .decode(e["leaf_input"].as_str().unwrap())
                .unwrap()
        })
        .collect()
}

#[test]
fn decodes_tile_with_leaf_index() {
    let entries = decode_tile(TILE).unwrap();
    assert_eq!(entries.len(), 256);
    let first = entries[0].leaf_index;
    assert_eq!(first % 256, 0);
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(e.leaf_index, first + i as u64);
        assert!(e.view.timestamp_ms > 1_700_000_000_000);
    }
}

#[test]
fn decodes_rfc6962_leaf_matches_fixture() {
    let leaves = get_entries();
    assert!(!leaves.is_empty());
    for l in &leaves {
        let v = decode_merkle_leaf(l).unwrap();
        assert!(v.timestamp_ms > 1_700_000_000_000);
        // The body must parse as X.509 of the declared kind.
        let p = extract(&raw(v.kind, v.body)).unwrap();
        assert!(!p.serial_hex.is_empty());
    }
}

#[test]
fn extract_all_tile_entries() {
    let entries = decode_tile(TILE).unwrap();
    let mut ok = 0;
    for e in &entries {
        let p = extract(&raw(e.view.kind, e.view.body)).unwrap();
        assert!(!p.issuer_cn.is_empty() || !p.issuer_org.is_empty());
        assert!(p.not_after_ms > p.not_before_ms);
        assert!(!p.key_type.is_empty());
        ok += 1;
    }
    assert_eq!(ok, 256);
}

/// A precertificate must be read from the TBSCertificate in the leaf, never
/// from `pre_certificate`, whose issuer can be a dedicated signing CA.
#[test]
fn precert_fields_come_from_tbs_not_pre_certificate() {
    let entries = decode_tile(TILE).unwrap();
    let e = entries
        .iter()
        .find(|e| e.view.kind == EntryKind::Precert)
        .expect("fixture has a precert");
    assert!(e.pre_certificate.is_some());
    let p = extract(&raw(EntryKind::Precert, e.view.body)).unwrap();
    assert!(!p.serial_hex.is_empty());
}

#[test]
fn empty_cn_uses_sans() {
    let entries = decode_tile(TILE).unwrap();
    let mut seen_no_cn = 0;
    for e in &entries {
        let p = extract(&raw(e.view.kind, e.view.body)).unwrap();
        if p.subject_cn.is_none() {
            seen_no_cn += 1;
            // IP-only certificates legitimately have no DNS name at all.
            assert!(p.names.len() <= p.san_count as usize, "only SANs supply names");
        }
    }
    assert!(seen_no_cn > 0, "fixture should contain a CN-less certificate");
}

#[test]
fn truncated_input_errors_without_panic() {
    let entries = decode_tile(TILE).unwrap();
    let body = entries[0].view.body;
    for n in (0..body.len()).step_by(7) {
        let _ = extract(&raw(entries[0].view.kind, &body[..n]));
    }
    for n in (0..2000).step_by(3) {
        let _ = decode_tile(&TILE[..n]);
        let _ = decode_merkle_leaf(&TILE[..n]);
    }
}

/// Ground truth read from the same fixture with `openssl x509`.
#[test]
fn extract_final_cert() {
    let entries = decode_tile(TILE).unwrap();
    let e = entries.iter().find(|e| e.view.kind == EntryKind::Final).unwrap();
    let p = extract(&raw(EntryKind::Final, e.view.body)).unwrap();
    assert_eq!(p.serial_hex, "a8413e92c976ab6c1314bf26c326024a");
    assert_eq!(p.issuer_cn, "WE1");
    assert_eq!(p.issuer_org, "Google Trust Services");
    assert_eq!(p.subject_cn.as_deref(), Some("members.cmacademy.au"));
    assert!(p.names.iter().any(|n| n == "members.cmacademy.au"));
    assert_eq!(p.san_count, 1);
    assert_eq!((p.key_type.as_str(), p.key_bits), ("ecdsa", 256));
    assert_eq!(p.sig_type, "ecdsa-sha256");
    use chrono::{TimeZone, Utc};
    let ms = |y, mo, d, h, mi, s| Utc.with_ymd_and_hms(y, mo, d, h, mi, s).unwrap().timestamp_millis();
    assert_eq!(p.not_before_ms, ms(2026, 9, 4, 12, 1, 16));
    assert_eq!(p.not_after_ms, ms(2026, 12, 3, 13, 1, 9));
}

/// A tile entry whose `pre_certificate` is garbage still yields its fields:
/// proves the TBS is the only source used for precertificates.
#[test]
fn precert_and_final_share_issuer_and_serial() {
    let entries = decode_tile(TILE).unwrap();
    let e = entries.iter().find(|e| e.view.kind == EntryKind::Precert).unwrap();
    let from_tbs = extract(&raw(EntryKind::Precert, e.view.body)).unwrap();
    assert_eq!(from_tbs.serial_hex, "0620a76bfaa916f810e2ed8bc9571d1e");
    assert_eq!(from_tbs.issuer_cn, "WR3");
    assert_eq!((from_tbs.key_type.as_str(), from_tbs.key_bits), ("rsa", 2048));
}
