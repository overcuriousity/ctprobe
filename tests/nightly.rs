use arrow::array::{AsArray, RecordBatch};
use arrow::datatypes::{Float64Type, Int64Type};
use chrono::NaiveDate;
use ctprobe::config::Config;
use ctprobe::nightly::{self, expire};
use ctprobe::store::{list_parts, Writer};
use ctprobe::types::{CertRow, ParsedCert, RenewalClass, Sighting};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::Path;

const DAY_MS: i64 = 86_400_000;
const D: i64 = 20_000 * DAY_MS; // 2024-10-04

fn day() -> NaiveDate {
    NaiveDate::from_ymd_opt(2024, 10, 4).unwrap()
}

fn cfg(dir: &Path) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.to_path_buf(),
        disk_budget_bytes: 1 << 30,
        tracker_max_bytes: 1 << 20,
        include_logs: vec![],
        exclude_logs: vec![],
        log_list_url: String::new(),
        extra_log_lists: vec![],
        include_test_logs: false,
        coverage_target: 95.0,
        dns: Default::default(),
    }
}

fn row(serial: &str, domain: &str, seen: i64, issuer: &str, days: i64, renewal: RenewalClass) -> CertRow {
    CertRow {
        parsed: ParsedCert {
            issuer_cn: issuer.into(),
            issuer_org: "Org".into(),
            issuer_der: vec![],
            serial_hex: serial.into(),
            subject_cn: Some(domain.into()),
            names: vec![domain.into(), format!("www.{domain}")],
            san_count: 2,
            key_type: "ecdsa".into(),
            key_bits: 256,
            sig_type: "ecdsa-sha256".into(),
            not_before_ms: seen,
            not_after_ms: seen + days * DAY_MS,
        },
        reg_domains: vec![domain.into()],
        primary_domain: Some(domain.into()),
        is_wildcard: false,
        is_precert: false,
        renewal,
        days_since_seen: None,
        new_names: 2,
        new_domains: 1,
        log: 0,
        index: 1,
        der_size: 100,
        seen_at_ms: seen,
        sct_lag_ms: 1,
        not_before_lag_ms: 1,
        cert_hash: 0,
    }
}

fn seed(dir: &Path) {
    let mut w = Writer::open(dir, 0).unwrap();
    w.push_cert(row("1", "zeta.com", D, "LE", 90, RenewalClass::New));
    w.push_cert(row("2", "alpha.org", D + 1, "LE", 6, RenewalClass::Exact));
    w.flush(1).unwrap();
    w.publish(1).unwrap();
    w.push_cert(row("3", "alpha.org", D + 2, "GTS", 90, RenewalClass::Name));
    // Logs: 0 sees {1,2,3}, 1 sees {3,4}, 2 sees {1}.
    for (h, l) in [(1, 0), (2, 0), (3, 0), (3, 1), (4, 1), (1, 2)] {
        w.push_sighting(Sighting { cert_hash: h, log: l, seen_at_ms: D });
    }
    w.flush(2).unwrap();
    w.publish(2).unwrap();
}

fn read(dir: &Path, table: &str) -> Vec<RecordBatch> {
    let mut out = vec![];
    for p in list_parts(dir, table) {
        let f = std::fs::File::open(p).unwrap();
        out.extend(ParquetRecordBatchReaderBuilder::try_new(f).unwrap().build().unwrap().map(|b| b.unwrap()));
    }
    out
}

fn sum_col(b: &[RecordBatch], c: &str) -> i64 {
    b.iter()
        .map(|x| x.column_by_name(c).unwrap().as_primitive::<Int64Type>().iter().flatten().sum::<i64>())
        .sum()
}

#[tokio::test(flavor = "multi_thread")]
async fn rollup_sums_match_certs() {
    let d = tempfile::tempdir().unwrap();
    seed(d.path());
    nightly::run_nightly(&cfg(d.path()), day()).await.unwrap();
    let r = read(d.path(), "rollup_daily");
    assert_eq!(sum_col(&r, "certs"), 3);
    assert_eq!(sum_col(&r, "sans"), 6);
    let f = read(d.path(), "daily_stages");
    assert_eq!(sum_col(&f, "raw_entries"), 6);
    assert_eq!(sum_col(&f, "unique_certs"), 3);
    assert_eq!(sum_col(&f, "names"), 6);
    assert_eq!(sum_col(&f, "new_domains"), 3);
    let buckets: Vec<String> = r
        .iter()
        .flat_map(|b| b.column_by_name("validity_bucket").unwrap().as_string::<i32>().iter().flatten().map(str::to_string).collect::<Vec<_>>())
        .collect();
    assert!(buckets.contains(&"<=7d".to_string()));
    assert!(buckets.contains(&"<=100d".to_string()));
}

#[tokio::test(flavor = "multi_thread")]
async fn daily_top_ranks_by_count() {
    let d = tempfile::tempdir().unwrap();
    seed(d.path());
    nightly::run_nightly(&cfg(d.path()), day()).await.unwrap();
    let t = read(d.path(), "daily_top");
    let b = arrow::compute::concat_batches(&t[0].schema(), &t).unwrap();
    let keys: Vec<_> = b.column_by_name("key").unwrap().as_string::<i32>().iter().flatten().collect();
    assert_eq!(keys[0], "alpha.org");
    assert!(keys.contains(&"LE"));
    assert!(b.column_by_name("day_total").unwrap().as_primitive::<Int64Type>().iter().flatten().all(|v| v == 3));
}

#[tokio::test(flavor = "multi_thread")]
async fn coverage_greedy_order() {
    let d = tempfile::tempdir().unwrap();
    seed(d.path());
    nightly::run_nightly(&cfg(d.path()), day()).await.unwrap();
    let c = read(d.path(), "daily_coverage");
    let b = arrow::compute::concat_batches(&c[0].schema(), &c).unwrap();
    let logs: Vec<i32> = b.column_by_name("log_id").unwrap().as_primitive::<arrow::datatypes::Int32Type>().iter().flatten().collect();
    assert_eq!(logs, [0, 1]); // Log 2 adds nothing and is not listed.
    let pct: Vec<f64> = b.column_by_name("cumulative_pct").unwrap().as_primitive::<Float64Type>().iter().flatten().collect();
    assert_eq!(pct, [75.0, 100.0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn compaction_sorted_with_bloom() {
    let d = tempfile::tempdir().unwrap();
    seed(d.path());
    nightly::run_nightly(&cfg(d.path()), day()).await.unwrap();
    let parts = list_parts(d.path(), "certs");
    assert_eq!(parts.len(), 1);
    assert!(parts[0].ends_with("day=2024-10-04/daily.parquet"));
    let f = std::fs::File::open(&parts[0]).unwrap();
    let rb = ParquetRecordBatchReaderBuilder::try_new(f).unwrap();
    let col = rb.parquet_schema().columns().iter().position(|c| c.name() == "primary_domain").unwrap();
    assert!(rb.metadata().row_group(0).column(col).bloom_filter_offset().is_some());
    let b = rb.build().unwrap().next().unwrap().unwrap();
    let v: Vec<_> = b.column_by_name("primary_domain").unwrap().as_string::<i32>().iter().flatten().collect();
    assert_eq!(v, ["alpha.org", "alpha.org", "zeta.com"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn crash_after_rename_does_not_double_count() {
    let d = tempfile::tempdir().unwrap();
    seed(d.path());
    let dir = d.path().join("certs/day=2024-10-04");
    let parts: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    nightly::run_nightly(&cfg(d.path()), day()).await.unwrap();
    // Parts reappear, as if the crash came before their deletion.
    let daily = std::fs::read(dir.join("daily.parquet")).unwrap();
    for p in &parts {
        std::fs::write(p, &daily).unwrap();
    }
    assert_eq!(list_parts(d.path(), "certs").len(), 1);
    nightly::cleanup(d.path()).unwrap();
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn domains_merge_updates_first_last_count() {
    let d = tempfile::tempdir().unwrap();
    seed(d.path());
    nightly::run_nightly(&cfg(d.path()), day()).await.unwrap();
    let mut w = Writer::open(d.path(), 2).unwrap();
    w.push_cert(row("9", "alpha.org", D + DAY_MS, "LE", 90, RenewalClass::Exact));
    w.push_cert(row("10", "beta.net", D + DAY_MS, "LE", 90, RenewalClass::New));
    w.flush(3).unwrap();
    w.publish(3).unwrap();
    nightly::run_nightly(&cfg(d.path()), day().succ_opt().unwrap()).await.unwrap();
    let snaps = list_parts(d.path(), "domains");
    assert_eq!(snaps.len(), 1, "{snaps:?}");
    let t = read(d.path(), "domains");
    let b = &t[0];
    let names: Vec<_> = b.column_by_name("domain").unwrap().as_string::<i32>().iter().flatten().collect();
    assert_eq!(names, ["alpha.org", "beta.net", "zeta.com"]);
    let counts: Vec<i64> = b.column_by_name("cert_count").unwrap().as_primitive::<Int64Type>().iter().flatten().collect();
    assert_eq!(counts, [3, 1, 1]);
    assert!(d.path().join("search/domains.fst").exists());
    assert!(d.path().join("search/skeleton.fst").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn rerun_is_idempotent() {
    let d = tempfile::tempdir().unwrap();
    seed(d.path());
    nightly::run_nightly(&cfg(d.path()), day()).await.unwrap();
    nightly::run_nightly(&cfg(d.path()), day()).await.unwrap();
    assert_eq!(sum_col(&read(d.path(), "rollup_daily"), "certs"), 3);
    assert_eq!(read(d.path(), "certs").iter().map(|b| b.num_rows()).sum::<usize>(), 3);
    assert_eq!(sum_col(&read(d.path(), "domains"), "cert_count"), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_day_succeeds() {
    let d = tempfile::tempdir().unwrap();
    nightly::run_nightly(&cfg(d.path()), day()).await.unwrap();
}

#[test]
fn expiry_keeps_budget_and_permanent_tables() {
    let d = tempfile::tempdir().unwrap();
    let mk = |t: &str, day: &str, n: usize| {
        let p = d.path().join(t).join(format!("day={day}"));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("daily.parquet"), vec![0u8; n]).unwrap();
    };
    mk("certs", "2026-01-01", 1000);
    mk("certs", "2026-01-02", 1000);
    mk("certs", "2026-01-03", 1000);
    mk("sightings", "2026-01-01", 10);
    mk("sightings", "2026-01-20", 10);
    mk("rollup_daily", "2026-01-01", 10);
    let today = NaiveDate::from_ymd_opt(2026, 1, 25).unwrap();
    let r = expire::enforce(d.path(), 2300, today).unwrap();
    assert_eq!(r, None);
    assert!(!d.path().join("sightings/day=2026-01-01").exists(), "past 14 days");
    assert!(d.path().join("sightings/day=2026-01-20").exists());
    assert!(!d.path().join("certs/day=2026-01-01").exists(), "oldest first");
    assert!(d.path().join("certs/day=2026-01-02").exists());
    assert!(d.path().join("rollup_daily/day=2026-01-01").exists());
    // A budget the permanent tables alone exceed reports a reason.
    let r = expire::enforce(d.path(), 5, today).unwrap();
    assert!(r.is_some());
}

#[test]
fn expiry_spares_days_nightly_has_not_finished() {
    let d = tempfile::tempdir().unwrap();
    let mk = |day: &str, n: usize| {
        let p = d.path().join("certs").join(format!("day={day}"));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("part-1.parquet"), vec![0u8; n]).unwrap();
    };
    mk("2026-01-01", 1000); // Oldest, nightly failed.
    mk("2026-01-02", 1000); // Finished.
    mk("2026-01-03", 1000); // Finished.
    let done = d.path().join("nightly");
    std::fs::create_dir_all(&done).unwrap();
    std::fs::write(done.join("2026-01-02.domains"), b"").unwrap();
    std::fs::write(done.join("2026-01-03.domains"), b"").unwrap();
    let today = NaiveDate::from_ymd_opt(2026, 1, 25).unwrap();
    assert_eq!(expire::enforce(d.path(), 2300, today).unwrap(), None);
    assert!(d.path().join("certs/day=2026-01-01").exists(), "not rolled up yet");
    assert!(!d.path().join("certs/day=2026-01-02").exists());
    // Over the hard budget even so, it goes too.
    expire::enforce(d.path(), 500, today).unwrap();
    assert!(!d.path().join("certs/day=2026-01-01").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_day_compacts_sorted_by_domain_and_still_answers_lookups() {
    use ctprobe::dns::outcome::{Lookup, Status};
    use ctprobe::dns::queue::Kind;
    use ctprobe::dns::DnsRow;
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path());
    let probe = |name: &str, domain: &str, hash: u64, at: i64| DnsRow {
        probed_at_ms: at,
        name: name.into(),
        kind: Kind::Name,
        reg_domain: Some(domain.into()),
        cert_hash: hash,
        cert_seen_at_ms: at,
        attempt: 0,
        renewal: "new",
        lookup: Lookup { status: Status::Resolved, v4: vec!["192.0.2.1".parse().unwrap()], v6: vec![], cnames: vec![], ttl: Some(60) },
        latency_ms: 5,
        last_miss_ms: None,
        prev: None,
    };
    let mut w = Writer::open(dir.path(), 2).unwrap();
    w.push_dns(probe("www.zeta.com", "zeta.com", u64::MAX, D + 5));
    w.push_dns(probe("alpha.org", "alpha.org", 7, D + 3));
    w.flush(3).unwrap();
    w.publish(3).unwrap();
    w.push_dns(probe("www.alpha.org", "alpha.org", 8, D + 4));
    w.flush(4).unwrap();
    w.publish(4).unwrap();
    nightly::run_nightly(&cfg(dir.path()), day()).await.unwrap();

    let parts = list_parts(dir.path(), "dns");
    assert_eq!(parts.len(), 1, "{parts:?}");
    assert!(parts[0].ends_with("daily.parquet"));
    let domains: Vec<String> = read(dir.path(), "dns")
        .iter()
        .flat_map(|b| b.column_by_name("reg_domain").unwrap().as_string::<i32>().iter().map(|d| d.unwrap().to_string()).collect::<Vec<_>>())
        .collect();
    assert_eq!(domains, ["alpha.org", "alpha.org", "zeta.com"]);

    let engine = ctprobe::query::QueryEngine::open(dir.path()).unwrap();
    let r = engine
        .internal(format!("SELECT name FROM dns WHERE cert_hash = CAST('{}' AS BIGINT UNSIGNED)", u64::MAX), 10, None, None)
        .await
        .unwrap();
    assert_eq!(r.rows, vec![vec![serde_json::json!("www.zeta.com")]]);
}
