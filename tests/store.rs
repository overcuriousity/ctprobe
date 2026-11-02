use arrow::array::{Array, AsArray, RecordBatch};
use arrow::datatypes::{Int32Type, UInt64Type};
use ctprobe::store::{list_parts, Writer, MINUTE_GLOBAL_LOG};
use ctprobe::store::RollupMinuteRow;
use ctprobe::types::{CertRow, ParsedCert, RenewalClass, Sighting};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::Path;

const DAY_MS: i64 = 86_400_000;
const D1: i64 = 20_000 * DAY_MS; // 2024-10-04

fn row(serial: &str, seen: i64) -> CertRow {
    CertRow {
        parsed: ParsedCert {
            issuer_cn: "CA".into(),
            issuer_org: "Org".into(),
            issuer_der: vec![],
            serial_hex: serial.into(),
            subject_cn: Some("a.example.co.uk".into()),
            names: vec!["*.example.co.uk".into(), "a.b.example.co.uk".into()],
            san_count: 2,
            key_type: "ecdsa".into(),
            key_bits: 256,
            sig_type: "ecdsa-sha256".into(),
            not_before_ms: seen - 1000,
            not_after_ms: seen + 90 * DAY_MS,
        },
        reg_domains: vec!["example.co.uk".into()],
        primary_domain: Some("example.co.uk".into()),
        is_wildcard: true,
        is_precert: true,
        renewal: RenewalClass::Name,
        days_since_seen: Some(60),
        new_names: 1,
        new_domains: 0,
        log: 7,
        index: 42,
        der_size: 900,
        seen_at_ms: seen,
        sct_lag_ms: 5,
        not_before_lag_ms: 1000,
        cert_hash: 0xdead_beef_dead_beef,
    }
}

fn read(path: &Path) -> Vec<RecordBatch> {
    let f = std::fs::File::open(path).unwrap();
    ParquetRecordBatchReaderBuilder::try_new(f).unwrap().build().unwrap().map(|b| b.unwrap()).collect()
}

#[test]
fn flush_writes_readable_parquet() {
    let d = tempfile::tempdir().unwrap();
    let mut w = Writer::open(d.path(), 0).unwrap();
    w.push_cert(row("aa", D1));
    w.push_sighting(Sighting { cert_hash: 9, log: 3, seen_at_ms: D1 });
    w.flush(1).unwrap();
    w.publish(1).unwrap();
    let parts = list_parts(d.path(), "certs");
    assert_eq!(parts.len(), 1);
    let b = &read(&parts[0])[0];
    assert_eq!(b.num_rows(), 1);
    let col = |n: &str| b.column_by_name(n).unwrap();
    assert_eq!(col("serial").as_string::<i32>().value(0), "aa");
    assert_eq!(col("tld").as_string::<i32>().value(0), "co.uk");
    assert_eq!(col("depth").as_primitive::<Int32Type>().value(0), 2);
    assert_eq!(col("renewal").as_string::<i32>().value(0), "name");
    assert_eq!(col("days_since_seen").as_primitive::<Int32Type>().value(0), 60);
    assert_eq!(col("cert_hash").as_primitive::<UInt64Type>().value(0), 0xdead_beef_dead_beef);
    assert_eq!(col("names").as_list::<i32>().value(0).len(), 2);
    assert_eq!(list_parts(d.path(), "sightings").len(), 1);
    assert_eq!(list_parts(d.path(), "domains").len(), 1);
}

#[test]
fn flush_splits_at_utc_midnight() {
    let d = tempfile::tempdir().unwrap();
    let mut w = Writer::open(d.path(), 0).unwrap();
    w.push_cert(row("aa", D1 + DAY_MS - 1));
    w.push_cert(row("bb", D1 + DAY_MS));
    w.flush(1).unwrap();
    w.publish(1).unwrap();
    let parts = list_parts(d.path(), "certs");
    let days: Vec<String> = parts
        .iter()
        .map(|p| p.parent().unwrap().file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(days, ["day=2024-10-04", "day=2024-10-05"]);
}

#[test]
fn unpublished_parts_are_invisible_and_resolved_on_open() {
    let d = tempfile::tempdir().unwrap();
    {
        let mut w = Writer::open(d.path(), 0).unwrap();
        w.push_cert(row("aa", D1));
        w.flush(1).unwrap(); // Not published.
        assert!(list_parts(d.path(), "certs").is_empty());
    }
    // Epoch 1 was recorded: the part must appear.
    {
        let _w = Writer::open(d.path(), 1).unwrap();
        assert_eq!(list_parts(d.path(), "certs").len(), 1);
        let mut w = _w;
        w.push_cert(row("bb", D1));
        w.flush(2).unwrap();
    }
    // Epoch 2 was not recorded: the part must vanish.
    let _w = Writer::open(d.path(), 1).unwrap();
    assert_eq!(list_parts(d.path(), "certs").len(), 1);
    assert!(walk(d.path()).iter().all(|p| !p.ends_with(".pending")));
}

fn walk(p: &Path) -> Vec<String> {
    let mut out = vec![];
    for e in std::fs::read_dir(p).unwrap() {
        let e = e.unwrap().path();
        if e.is_dir() {
            out.extend(walk(&e));
        } else {
            out.push(e.to_string_lossy().into_owned());
        }
    }
    out
}

#[test]
fn tmp_files_removed_on_open() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("certs/day=2024-10-04");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("x.parquet.tmp"), b"junk").unwrap();
    Writer::open(d.path(), 0).unwrap();
    assert!(!dir.join("x.parquet.tmp").exists());
}

#[test]
fn domains_delta_aggregates_per_flush() {
    let d = tempfile::tempdir().unwrap();
    let mut w = Writer::open(d.path(), 0).unwrap();
    w.push_cert(row("aa", D1));
    w.push_cert(row("bb", D1 + 5));
    w.flush(1).unwrap();
    w.publish(1).unwrap();
    let b = &read(&list_parts(d.path(), "domains")[0])[0];
    assert_eq!(b.num_rows(), 1);
    assert_eq!(b.column_by_name("cert_count").unwrap().as_primitive::<arrow::datatypes::Int64Type>().value(0), 2);
    assert!(b.column_by_name("skeleton").unwrap().null_count() == 0);
}

#[test]
fn rollup_minute_global_row_keeps_process_columns() {
    let d = tempfile::tempdir().unwrap();
    let mut w = Writer::open(d.path(), 0).unwrap();
    w.push_rollup(RollupMinuteRow { minute_ms: D1, log: MINUTE_GLOBAL_LOG, entries: 5, tracker_names: Some(77), ..Default::default() });
    w.push_rollup(RollupMinuteRow { minute_ms: D1, log: 1, entries: 3, ..Default::default() });
    w.flush(1).unwrap();
    w.publish(1).unwrap();
    let b = &read(&list_parts(d.path(), "rollup_minute")[0])[0];
    assert_eq!(b.num_rows(), 2);
    assert_eq!(b.column_by_name("tracker_names").unwrap().null_count(), 1);
}
