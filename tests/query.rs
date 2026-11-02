use ctprobe::config::Config;
use ctprobe::nightly;
use ctprobe::query::{CertFilter, Mode, QueryEngine, QueryError};
use ctprobe::store::Writer;
use ctprobe::types::{CertRow, ParsedCert, RenewalClass};
use std::path::Path;

const DAY_MS: i64 = 86_400_000;
const D: i64 = 20_000 * DAY_MS;

fn row(serial: &str, names: &[&str], seen: i64) -> CertRow {
    let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    let mut reg: Vec<String> = names.iter().filter_map(|n| ctprobe::names::registered_domain(n)).collect();
    reg.sort();
    reg.dedup();
    CertRow {
        parsed: ParsedCert {
            issuer_cn: "CA".into(),
            issuer_org: "Org".into(),
            issuer_der: vec![],
            serial_hex: serial.into(),
            subject_cn: names.first().cloned(),
            san_count: names.len() as u32,
            names,
            key_type: "ecdsa".into(),
            key_bits: 256,
            sig_type: "ecdsa-sha256".into(),
            not_before_ms: seen,
            not_after_ms: seen + 90 * DAY_MS,
        },
        primary_domain: reg.first().cloned(),
        reg_domains: reg,
        is_wildcard: false,
        is_precert: false,
        renewal: RenewalClass::New,
        days_since_seen: None,
        new_names: 1,
        new_domains: 1,
        log: 3,
        index: 9,
        der_size: 1,
        seen_at_ms: seen,
        sct_lag_ms: 1,
        not_before_lag_ms: 1,
        cert_hash: 1,
    }
}

async fn seed(dir: &Path) -> QueryEngine {
    let mut w = Writer::open(dir, 0).unwrap();
    let domains = ["paypal.com", "paypa1.com", "paypal-login.com", "xn--pypal-4ve.com", "payapl.net", "example.com"];
    for (i, n) in domains.iter().enumerate() {
        w.push_cert(row(&format!("s{i}"), &[n], D));
    }
    w.push_cert(row("sub", &["a.example.com", "example.org"], D));
    w.push_cert(row("sub2", &["notexample.com"], D));
    w.flush(1).unwrap();
    w.publish(1).unwrap();
    let cfg = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.to_path_buf(),
        disk_budget_bytes: 1 << 30,
        tracker_max_bytes: 1,
        include_logs: vec![],
        exclude_logs: vec![],
        log_list_url: String::new(),
        extra_log_lists: vec![],
        include_test_logs: false,
        coverage_target: 95.0,
    };
    nightly::run_nightly(&cfg, chrono::NaiveDate::from_ymd_opt(2024, 10, 4).unwrap()).await.unwrap();
    w.push_cert(row("today", &["paypai.org"], D + DAY_MS));
    w.flush(2).unwrap();
    w.publish(2).unwrap();
    QueryEngine::open(dir).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn sql_rejects_ddl_and_copy() {
    let d = tempfile::tempdir().unwrap();
    let e = seed(d.path()).await;
    let out = d.path().join("evil.parquet");
    for q in [
        format!("COPY certs TO '{}'", out.display()),
        "CREATE EXTERNAL TABLE x STORED AS CSV LOCATION '/etc/passwd'".to_string(),
        "INSERT INTO certs VALUES (1)".to_string(),
        "DROP TABLE certs".to_string(),
        "SET datafusion.execution.batch_size = 1".to_string(),
        "SELECT 1; SELECT 2".to_string(),
    ] {
        assert!(matches!(e.sql(&q, 10).await, Err(QueryError::NotAllowed(_))), "{q}");
    }
    assert!(!out.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn sql_cannot_read_files() {
    let d = tempfile::tempdir().unwrap();
    let e = seed(d.path()).await;
    assert!(e.sql("SELECT * FROM '/etc/passwd'", 10).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn sql_returns_rows_and_marks_truncation() {
    let d = tempfile::tempdir().unwrap();
    let e = seed(d.path()).await;
    let r = e.sql("SELECT primary_domain, san_count FROM certs ORDER BY 1, 2", 3).await.unwrap();
    assert_eq!(r.columns, ["primary_domain", "san_count"]);
    assert_eq!(r.rows.len(), 3);
    assert!(r.truncated);
    assert_eq!(r.rows[0][0], serde_json::json!("example.com"));
    let r = e.sql("SELECT COUNT(*) AS n FROM certs", 3).await.unwrap();
    assert_eq!(r.rows[0][0], serde_json::json!(9));
    assert!(!r.truncated);
}

#[tokio::test(flavor = "multi_thread")]
async fn sql_timeout_applies() {
    let d = tempfile::tempdir().unwrap();
    let mut e = seed(d.path()).await;
    e.set_timeout(std::time::Duration::from_millis(1));
    let q = "SELECT COUNT(*) FROM generate_series(1, 2000000000) a, generate_series(1, 1000) b";
    assert!(matches!(e.sql(q, 10).await, Err(QueryError::Timeout)));
}

#[tokio::test(flavor = "multi_thread")]
async fn levenshtein_ranks_closest_first() {
    let d = tempfile::tempdir().unwrap();
    let e = seed(d.path()).await;
    let hits = e.search_domains("paypal.com", Mode::Levenshtein(1), 10).await.unwrap();
    let names: Vec<_> = hits.iter().map(|h| h.domain.as_str()).collect();
    assert_eq!(names[0], "paypal.com");
    assert!(names.contains(&"paypa1.com"));
    assert!(!names.contains(&"paypal-login.com"));
}

#[tokio::test(flavor = "multi_thread")]
async fn bare_label_matches_any_tld() {
    let d = tempfile::tempdir().unwrap();
    let e = seed(d.path()).await;
    let hits = e.search_domains("paypal", Mode::Levenshtein(2), 10).await.unwrap();
    let names: Vec<_> = hits.iter().map(|h| h.domain.as_str()).collect();
    assert!(names.contains(&"payapl.net"), "{names:?}");
    assert!(names.contains(&"paypai.org"), "today's delta: {names:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn homoglyph_finds_cyrillic() {
    let d = tempfile::tempdir().unwrap();
    let e = seed(d.path()).await;
    let hits = e.search_domains("paypal.com", Mode::Homoglyph, 10).await.unwrap();
    let names: Vec<_> = hits.iter().map(|h| h.domain.as_str()).collect();
    assert!(names.contains(&"xn--pypal-4ve.com"), "{names:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn contains_finds_substring_in_domain() {
    let d = tempfile::tempdir().unwrap();
    let e = seed(d.path()).await;
    let hits = e.search_domains("login", Mode::Contains, 10).await.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].domain, "paypal-login.com");
    assert_eq!(hits[0].cert_count, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn todays_delta_is_searchable() {
    let d = tempfile::tempdir().unwrap();
    let e = seed(d.path()).await;
    let hits = e.search_domains("paypai.org", Mode::Exact, 10).await.unwrap();
    assert_eq!(hits.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn wildcard_returns_subdomains_only() {
    let d = tempfile::tempdir().unwrap();
    let e = seed(d.path()).await;
    let r = e.search_names("%.example.com", CertFilter { limit: 10, ..Default::default() }).await.unwrap();
    let serial = r.columns.iter().position(|c| c == "serial").unwrap();
    let got: Vec<_> = r.rows.iter().map(|x| x[serial].as_str().unwrap().to_string()).collect();
    assert_eq!(got, ["sub"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn certs_for_domain_quotes_safely() {
    let d = tempfile::tempdir().unwrap();
    let e = seed(d.path()).await;
    let r = e.certs_for(&["x' OR '1'='1".to_string()], CertFilter { limit: 10, ..Default::default() }).await.unwrap();
    assert!(r.rows.is_empty());
    let r = e.certs_for(&["paypal.com".to_string()], CertFilter { limit: 10, ..Default::default() }).await.unwrap();
    assert_eq!(r.rows.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn random_n_returns_n_distinct_matching_rows() {
    let d = tempfile::tempdir().unwrap();
    let e = seed(d.path()).await;
    let f = CertFilter { random_n: Some(3), limit: 100, ..Default::default() };
    let all = ["paypal.com", "paypa1.com", "paypal-login.com", "payapl.net", "example.com"].map(String::from);
    let r = e.certs_for(&all, f).await.unwrap();
    assert_eq!(r.rows.len(), 3);
    let serial = r.columns.iter().position(|c| c == "serial").unwrap();
    let mut s: Vec<_> = r.rows.iter().map(|x| x[serial].to_string()).collect();
    s.sort();
    s.dedup();
    assert_eq!(s.len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn date_filter_limits_days() {
    let d = tempfile::tempdir().unwrap();
    let e = seed(d.path()).await;
    let f = CertFilter { from_ms: Some(D + DAY_MS), limit: 100, ..Default::default() };
    let r = e.certs_for(&["paypai.org".to_string(), "paypal.com".to_string()], f).await.unwrap();
    assert_eq!(r.rows.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_store_works() {
    let d = tempfile::tempdir().unwrap();
    let e = QueryEngine::open(d.path()).unwrap();
    assert!(e.search_domains("x.com", Mode::Exact, 10).await.unwrap().is_empty());
    let r = e.sql("SELECT COUNT(*) FROM certs", 10).await.unwrap();
    assert_eq!(r.rows[0][0], serde_json::json!(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn search_scans_honour_the_timeout() {
    let d = tempfile::tempdir().unwrap();
    let mut e = seed(d.path()).await;
    e.set_timeout(std::time::Duration::ZERO);
    let r = e.search_domains("pay", Mode::Contains, 10).await;
    assert!(matches!(r, Err(QueryError::Timeout)), "{r:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn minute_files_from_before_the_backlog_columns_still_read() {
    use arrow::array::{Int32Array, Int64Array, RecordBatch, TimestampMillisecondArray};
    use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
    use std::sync::Arc;
    let d = tempfile::tempdir().unwrap();
    let schema = Arc::new(Schema::new(vec![
        Field::new("minute", DataType::Timestamp(TimeUnit::Millisecond, None), false),
        Field::new("log_id", DataType::Int32, false),
        Field::new("entries", DataType::Int64, false),
    ]));
    let b = RecordBatch::try_new(schema, vec![
        Arc::new(TimestampMillisecondArray::from(vec![D])),
        Arc::new(Int32Array::from(vec![1])),
        Arc::new(Int64Array::from(vec![5])),
    ]).unwrap();
    let f = d.path().join("rollup_minute/day=2024-10-04/part-old.parquet");
    ctprobe::store::write_batch(&f, &b, None).unwrap();
    let e = QueryEngine::open(d.path()).unwrap();
    let r = e.sql("SELECT entries, backlog FROM rollup_minute", 10).await.unwrap();
    assert_eq!(r.rows[0], [serde_json::json!(5), serde_json::Value::Null]);
}
