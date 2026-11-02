use ctprobe::tracker::{EntryMeta, Tracker};
use ctprobe::types::{ParsedCert, RenewalClass};

fn cert(serial: &str, names: &[&str]) -> ParsedCert {
    let mut names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    names.sort();
    ParsedCert {
        issuer_cn: "CA".into(),
        issuer_der: b"issuer".to_vec(),
        serial_hex: serial.into(),
        subject_cn: names.first().cloned(),
        san_count: names.len() as u32,
        names,
        ..Default::default()
    }
}

fn meta(log: u16) -> EntryMeta {
    EntryMeta { log, index: 1, is_precert: false, der_size: 100, timestamp_ms: 1000, seen_at_ms: 5000 }
}

fn tracker(d: &tempfile::TempDir) -> Tracker {
    Tracker::open(d.path(), 1 << 30, 0).unwrap()
}

#[test]
fn first_sighting_only_yields_row() {
    let d = tempfile::tempdir().unwrap();
    let mut t = tracker(&d);
    let c = cert("01", &["a.example.com"]);
    let first = t.observe(meta(0), &c, 100);
    assert!(first.row.is_some());
    let second = t.observe(meta(1), &c, 100);
    assert!(second.row.is_none());
    assert_eq!(second.sighting.log, 1);
    assert_eq!(second.sighting.cert_hash, first.sighting.cert_hash);
}

#[test]
fn precert_then_final_dedupes() {
    let d = tempfile::tempdir().unwrap();
    let mut t = tracker(&d);
    let c = cert("02", &["a.example.com"]);
    let mut m = meta(0);
    m.is_precert = true;
    assert!(t.observe(m, &c, 100).row.is_some());
    assert!(t.observe(meta(0), &c, 100).row.is_none());
}

#[test]
fn different_issuer_same_serial_is_distinct() {
    let d = tempfile::tempdir().unwrap();
    let mut t = tracker(&d);
    let a = cert("03", &["a.example.com"]);
    let mut b = a.clone();
    b.issuer_der = b"other".to_vec();
    assert!(t.observe(meta(0), &a, 100).row.is_some());
    assert!(t.observe(meta(0), &b, 100).row.is_some());
}

#[test]
fn renewal_exact_vs_name_vs_new() {
    let d = tempfile::tempdir().unwrap();
    let mut t = tracker(&d);
    let r = t.observe(meta(0), &cert("10", &["a.example.com", "b.example.com"]), 100).row.unwrap();
    assert_eq!(r.renewal, RenewalClass::New);
    assert_eq!(r.days_since_seen, None);
    assert_eq!((r.new_names, r.new_domains), (2, 1));
    let r = t.observe(meta(0), &cert("11", &["a.example.com", "b.example.com"]), 160).row.unwrap();
    assert_eq!(r.renewal, RenewalClass::Exact);
    assert_eq!(r.days_since_seen, Some(60));
    assert_eq!((r.new_names, r.new_domains), (0, 0));
    let r = t.observe(meta(0), &cert("12", &["a.example.com", "c.example.com"]), 170).row.unwrap();
    assert_eq!(r.renewal, RenewalClass::Name);
    assert_eq!(r.new_names, 1);
    let r = t.observe(meta(0), &cert("13", &["z.other.org"]), 170).row.unwrap();
    assert_eq!(r.renewal, RenewalClass::New);
}

#[test]
fn san_match_counts_when_cn_differs() {
    let d = tempfile::tempdir().unwrap();
    let mut t = tracker(&d);
    t.observe(meta(0), &cert("20", &["san.example.com", "x.example.com"]), 100);
    let mut c = cert("21", &["other.example.com", "san.example.com"]);
    c.subject_cn = Some("other.example.com".into());
    let r = t.observe(meta(0), &c, 101).row.unwrap();
    assert_eq!(r.renewal, RenewalClass::Name);
}

#[test]
fn days_since_seen_smallest_gap() {
    let d = tempfile::tempdir().unwrap();
    let mut t = tracker(&d);
    t.observe(meta(0), &cert("30", &["a.example.com"]), 100);
    t.observe(meta(0), &cert("31", &["b.example.com"]), 150);
    let r = t.observe(meta(0), &cert("32", &["a.example.com", "b.example.com"]), 160).row.unwrap();
    assert_eq!(r.days_since_seen, Some(10));
}

#[test]
fn dedup_expires_after_7_days() {
    let d = tempfile::tempdir().unwrap();
    let mut t = tracker(&d);
    let c = cert("40", &["a.example.com"]);
    t.observe(meta(0), &c, 100);
    assert!(t.observe(meta(1), &c, 107).row.is_none());
    assert!(t.observe(meta(1), &c, 108).row.is_some());
}

#[test]
fn certificate_without_names_is_new_and_stored() {
    let d = tempfile::tempdir().unwrap();
    let mut t = tracker(&d);
    let r = t.observe(meta(0), &cert("41", &[]), 100).row.unwrap();
    assert_eq!(r.renewal, RenewalClass::New);
    assert_eq!(r.primary_domain, None);
    let r = t.observe(meta(0), &cert("42", &[]), 100).row.unwrap();
    assert_eq!(r.renewal, RenewalClass::New, "no names must not match an empty set");
}

#[test]
fn row_fields_derived() {
    let d = tempfile::tempdir().unwrap();
    let mut t = tracker(&d);
    let mut c = cert("43", &["*.foo.example.co.uk", "bar.test.org"]);
    c.subject_cn = Some("bar.test.org".into());
    c.not_before_ms = 2000;
    let r = t.observe(meta(0), &c, 100).row.unwrap();
    assert!(r.is_wildcard);
    assert_eq!(r.primary_domain.as_deref(), Some("test.org"));
    assert_eq!(r.reg_domains, ["example.co.uk", "test.org"]);
    assert_eq!((r.sct_lag_ms, r.not_before_lag_ms), (4000, 3000));
}

#[test]
fn wal_recovers_committed_only() {
    let d = tempfile::tempdir().unwrap();
    {
        let mut t = tracker(&d);
        t.observe(meta(0), &cert("50", &["kept.example.com"]), 100);
        t.commit_wal(1).unwrap();
        t.observe(meta(0), &cert("51", &["lost.example.com"]), 100);
        // Dropped without commit: simulated crash.
    }
    let mut t = Tracker::open(d.path(), 1 << 30, 1).unwrap();
    assert!(t.observe(meta(0), &cert("50", &["kept.example.com"]), 100).row.is_none());
    let r = t.observe(meta(0), &cert("51", &["lost.example.com"]), 100).row.unwrap();
    assert_eq!(r.renewal, RenewalClass::New);
}

#[test]
fn wal_frames_newer_than_committed_epoch_are_discarded() {
    let d = tempfile::tempdir().unwrap();
    {
        let mut t = tracker(&d);
        t.observe(meta(0), &cert("52", &["a.example.com"]), 100);
        t.commit_wal(1).unwrap();
        t.observe(meta(0), &cert("53", &["b.example.com"]), 100);
        t.commit_wal(2).unwrap(); // Crash before positions recorded epoch 2.
    }
    let mut t = Tracker::open(d.path(), 1 << 30, 1).unwrap();
    assert!(t.observe(meta(0), &cert("52", &["a.example.com"]), 100).row.is_none());
    assert!(t.observe(meta(0), &cert("53", &["b.example.com"]), 100).row.is_some());
    t.commit_wal(2).unwrap();
    drop(t);
    let mut t = Tracker::open(d.path(), 1 << 30, 2).unwrap();
    assert!(t.observe(meta(0), &cert("53", &["b.example.com"]), 100).row.is_none());
}

#[test]
fn torn_wal_tail_is_ignored() {
    let d = tempfile::tempdir().unwrap();
    {
        let mut t = tracker(&d);
        t.observe(meta(0), &cert("54", &["a.example.com"]), 100);
        t.commit_wal(1).unwrap();
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(d.path().join("tracker.wal")).unwrap();
    f.write_all(&[1, 2, 3]).unwrap();
    drop(f);
    let mut t = Tracker::open(d.path(), 1 << 30, 1).unwrap();
    assert!(t.observe(meta(0), &cert("54", &["a.example.com"]), 100).row.is_none());
}

#[test]
fn snapshot_then_reopen() {
    let d = tempfile::tempdir().unwrap();
    {
        let mut t = tracker(&d);
        t.observe(meta(0), &cert("55", &["a.example.com"]), 100);
        t.commit_wal(1).unwrap();
        t.snapshot(1).unwrap();
        t.observe(meta(0), &cert("56", &["b.example.com"]), 100);
        t.commit_wal(2).unwrap();
    }
    assert!(std::fs::metadata(d.path().join("tracker.snap")).unwrap().len() > 0);
    let mut t = Tracker::open(d.path(), 1 << 30, 2).unwrap();
    assert!(t.observe(meta(0), &cert("55", &["a.example.com"]), 100).row.is_none());
    assert!(t.observe(meta(0), &cert("56", &["b.example.com"]), 100).row.is_none());
}

#[test]
fn eviction_respects_cap() {
    let d = tempfile::tempdir().unwrap();
    let cap = 600 << 10; // Dedup is never evicted, so the cap must exceed it.
    let mut t = Tracker::open(d.path(), cap, 0).unwrap();
    for i in 0..20_000u32 {
        let name = format!("n{i}.example.com");
        t.observe(meta(0), &cert(&format!("{i:x}"), &[&name]), 100 + (i / 1000) as u16);
    }
    t.commit_wal(1).unwrap();
    assert!(t.bytes_used() <= cap, "{} > {cap}", t.bytes_used());
    // Newest name survives, oldest is gone.
    let r = t.observe(meta(0), &cert("f1", &["n19999.example.com"]), 130).row.unwrap();
    assert_ne!(r.renewal, RenewalClass::New);
    let r = t.observe(meta(0), &cert("f2", &["n0.example.com"]), 130).row.unwrap();
    assert_eq!(r.renewal, RenewalClass::New);
}

#[test]
fn table_growth_stays_under_cap_without_commits() {
    let d = tempfile::tempdir().unwrap();
    let cap = 3 << 20;
    let mut t = Tracker::open(d.path(), cap, 0).unwrap();
    for i in 0..100_000u32 {
        let name = format!("n{i}.example.com");
        t.observe(meta(0), &cert(&format!("{i:x}"), &[&name]), 100 + (i / 5000) as u16);
        assert!(t.bytes_used() <= cap, "at {i}: {} > {cap}", t.bytes_used());
    }
    // The newest names survive eviction.
    let r = t.observe(meta(0), &cert("ff1", &["n99999.example.com"]), 130).row.unwrap();
    assert_ne!(r.renewal, RenewalClass::New);
}
