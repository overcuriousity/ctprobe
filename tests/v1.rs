use chrono::NaiveDate;
use ctprobe::config::Config;
use ctprobe::dns::outcome::{Lookup, Status};
use ctprobe::dns::queue::Kind;
use ctprobe::dns::DnsRow;
use ctprobe::fetch::FetchOpts;
use ctprobe::mocklog::{MockLog, MockOpts};
use ctprobe::pipeline::{Pipeline, PipelineOpts};
use ctprobe::query::QueryEngine;
use ctprobe::registry::{LogKind, LogSpec};
use ctprobe::store::Writer;
use ctprobe::types::{CertRow, ParsedCert, RenewalClass};
use ctprobe::{names, nightly, web};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

struct App {
    base: String,
    state: web::AppState,
    _pipe: Pipeline,
    _log: MockLog,
    _dir: tempfile::TempDir,
}

/// Certificates written before the app starts, days to archive first, and
/// the query time limit.
#[derive(Default)]
struct Setup {
    certs: Vec<CertRow>,
    dns: Vec<DnsRow>,
    archive: Vec<i64>,
    timeout: Option<Duration>,
}

async fn app() -> App {
    app_with(Setup::default()).await
}

async fn app_with(setup: Setup) -> App {
    let log = MockLog::start(MockOpts::rfc6962(0)).await;
    let dir = tempfile::tempdir().unwrap();
    if !setup.certs.is_empty() || !setup.dns.is_empty() {
        let mut w = Writer::open(dir.path(), 0).unwrap();
        for r in setup.certs {
            w.push_cert(r);
        }
        for r in setup.dns {
            w.push_dns(r);
        }
        w.flush(1).unwrap();
        w.publish(1).unwrap();
    }
    let cfg = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.path().to_path_buf(),
        disk_budget_bytes: 1 << 33,
        tracker_max_bytes: 1 << 26,
        include_logs: vec![],
        exclude_logs: vec![],
        log_list_url: String::new(),
        extra_log_lists: vec![],
        include_test_logs: false,
        coverage_target: 95.0,
        dns: Default::default(),
        hot_days: None,
        dns_days: None,
        archive_budget_bytes: None,
    };
    for ms in setup.archive {
        let mut c = cfg.clone();
        c.archive_budget_bytes = Some(1 << 40);
        let day = chrono::DateTime::from_timestamp_millis(ms).unwrap().date_naive();
        nightly::run_nightly(&c, day).await.unwrap();
    }
    let opts = PipelineOpts {
        logs: Some(vec![LogSpec {
            name: "mock".into(),
            log_id_b64: "bW9jaw==".into(),
            kind: LogKind::Rfc6962 { url: log.url() },
            state: "usable".into(),
            operator: String::new(),
            source: String::new(),
        }]),
        commit_interval: Duration::from_millis(100),
        start_at_zero: true,
        fetch: FetchOpts {
            poll: Duration::from_millis(20),
            backoff_min: Duration::from_millis(10),
            backoff_max: Duration::from_millis(50),
            partial_after: Duration::ZERO,
            batch: 256,
            tile_parallel: 1,
        },
        minute: Duration::from_millis(100),
        nightly: false,
        snapshot_every: Duration::from_secs(86400),
        coverage_every: Duration::from_millis(100),
        dns: ctprobe::dns::DnsOpts { minute: Duration::from_millis(100), ..Default::default() },
    };
    let pipe = Pipeline::start(cfg, opts).await.unwrap();
    let mut engine = QueryEngine::open(dir.path()).unwrap();
    if let Some(t) = setup.timeout {
        engine.set_timeout(t);
    }
    let engine = Arc::new(engine);
    let state = web::AppState::new(engine, pipe.handle.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(web::serve(listener, state.clone()));
    App { base, state, _pipe: pipe, _log: log, _dir: dir }
}

async fn get(a: &App, path: &str) -> (u16, reqwest::header::HeaderMap, Value) {
    let r = reqwest::get(format!("{}{path}", a.base)).await.unwrap();
    let status = r.status().as_u16();
    let headers = r.headers().clone();
    let body = r.json().await.unwrap_or(Value::Null);
    (status, headers, body)
}

fn code(v: &Value) -> &str {
    assert!(v["error"]["message"].is_string(), "{v}");
    v["error"]["code"].as_str().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_path_is_json_404() {
    let a = app().await;
    let (s, _, b) = get(&a, "/api/v1/nope").await;
    assert_eq!(s, 404);
    assert_eq!(code(&b), "not_found");
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_param_is_400() {
    let a = app().await;
    let (s, _, b) = get(&a, "/api/v1/search?q=a&bogus=1").await;
    assert_eq!(s, 400);
    assert_eq!(code(&b), "bad_request");
}

#[tokio::test(flavor = "multi_thread")]
async fn search_modes_work() {
    let a = app().await;
    for m in ["exact", "contains", "levenshtein", "homoglyph"] {
        let (s, _, b) = get(&a, &format!("/api/v1/search?q=example.com&mode={m}")).await;
        assert_eq!(s, 200, "{m}: {b}");
        assert!(b["hits"].is_array(), "{m}: {b}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_inputs_are_400() {
    let a = app().await;
    for p in [
        "/api/v1/search?q=a&mode=x",
        "/api/v1/search?q=a&mode=levenshtein&distance=3",
        "/api/v1/search?q=a&limit=0",
        "/api/v1/search?q=a&limit=1001",
        "/api/v1/search?q=",
        "/api/v1/search?q=%20%20",
        "/api/v1/search",
    ]
    .into_iter()
    .map(String::from)
    .chain([format!("/api/v1/search?q={}", "a".repeat(254))])
    {
        let p = p.as_str();
        let (s, _, b) = get(&a, p).await;
        assert_eq!(s, 400, "{p}: {b}");
        assert_eq!(code(&b), "bad_request", "{p}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn busy_is_429_with_retry_after() {
    let a = app().await;
    let _p1 = a.state.v1.enter(false).unwrap();
    let _p2 = a.state.v1.enter(false).unwrap();
    let (s, h, b) = get(&a, "/api/v1/search?q=a").await;
    assert_eq!(s, 429);
    assert_eq!(code(&b), "busy");
    assert_eq!(h["retry-after"], "1");
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_api_unaffected_when_busy() {
    let a = app().await;
    let _p1 = a.state.v1.enter(false).unwrap();
    let _p2 = a.state.v1.enter(false).unwrap();
    let (s, _, _) = get(&a, "/api/search?q=a").await;
    assert_eq!(s, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_method_and_bare_prefix_are_json_404() {
    let a = app().await;
    let r = reqwest::Client::new().post(format!("{}/api/v1/search?q=a", a.base)).send().await.unwrap();
    assert_eq!(r.status(), 404);
    assert_eq!(code(&r.json().await.unwrap()), "not_found");
    let (s, _, b) = get(&a, "/api/v1").await;
    assert_eq!(s, 404);
    assert_eq!(code(&b), "not_found");
}

const DAY_MS: i64 = 86_400_000;
const D: i64 = 20_000 * DAY_MS; // 2024-10-04

fn day_dir(a: &App, ms: i64) -> std::path::PathBuf {
    let day = chrono::DateTime::from_timestamp_millis(ms).unwrap().date_naive();
    assert!(day < NaiveDate::from_ymd_opt(2026, 1, 1).unwrap());
    a._dir.path().join("certs").join(format!("day={}", day.format("%Y-%m-%d")))
}

/// A certificate; registered domains and the primary come from its names.
fn cert(index: u64, names: &[&str], seen: i64) -> CertRow {
    let mut regs: Vec<String> = names.iter().filter_map(|n| names::registered_domain(n)).collect();
    regs.sort();
    regs.dedup();
    CertRow {
        parsed: ParsedCert {
            issuer_cn: "LE".into(),
            issuer_org: "Org".into(),
            issuer_der: vec![],
            serial_hex: format!("{index:x}"),
            subject_cn: Some(names[0].into()),
            names: names.iter().map(|s| s.to_string()).collect(),
            san_count: names.len() as u32,
            key_type: "ecdsa".into(),
            key_bits: 256,
            sig_type: "ecdsa-sha256".into(),
            not_before_ms: seen,
            not_after_ms: seen + 90 * DAY_MS,
        },
        primary_domain: names::registered_domain(names[0]),
        reg_domains: regs,
        is_wildcard: names.iter().any(|n| n.starts_with("*.")),
        is_precert: false,
        renewal: RenewalClass::New,
        days_since_seen: None,
        new_names: 1,
        new_domains: 1,
        log: 0,
        index,
        der_size: 100,
        seen_at_ms: seen,
        sct_lag_ms: 1,
        not_before_lag_ms: 1,
        cert_hash: index,
    }
}

async fn page(a: &App, path: &str) -> Value {
    let (s, _, b) = get(a, path).await;
    assert_eq!(s, 200, "{path}: {b}");
    b
}

async fn rows(a: &App, path: &str) -> Vec<Value> {
    page(a, path).await["rows"].as_array().unwrap().clone()
}

type Key = (i64, i64, String);

fn key(r: &Value) -> Key {
    (r["log_id"].as_i64().unwrap(), r["entry_index"].as_i64().unwrap(), r["reg_domain"].as_str().unwrap().to_string())
}

fn indexes(rs: &[Value]) -> Vec<i64> {
    let mut v: Vec<i64> = rs.iter().map(|r| r["entry_index"].as_i64().unwrap()).collect();
    v.sort();
    v
}

/// The row without the parts that depend on the hot tier.
fn without_tier(r: &Value) -> Value {
    let mut r = r.clone();
    let o = r.as_object_mut().unwrap();
    o.remove("tier");
    o.remove("detail");
    r
}

fn two_domain_cert() -> CertRow {
    cert(1, &["a.one.com", "*.one.com", "b.two.org"], D + 1000)
}

#[tokio::test(flavor = "multi_thread")]
async fn matches_a_non_primary_domain() {
    for archive in [vec![], vec![D]] {
        let a = app_with(Setup { certs: vec![two_domain_cert()], archive: archive.clone(), ..Default::default() }).await;
        let rs = rows(&a, "/api/v1/certs?domain=two.org").await;
        assert_eq!(rs.len(), 1, "archive {archive:?}: {rs:?}");
        assert_eq!(rs[0]["reg_domain"], "two.org");
        assert_eq!(rs[0]["names"], serde_json::json!(["b.two.org"]));
        let legacy = page(&a, "/api/certs?domain=two.org").await;
        assert_eq!(legacy["rows"].as_array().unwrap().len(), 0, "{legacy}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rows_dropped_in_rust_are_refilled() {
    // Only the oldest lists a.one.com; the two newer ones are wildcards that
    // do not cover it.
    let certs = vec![
        cert(1, &["a.one.com"], D + 1),
        cert(2, &["*.b.one.com", "b.one.com"], D + 2),
        cert(3, &["*.c.one.com", "c.one.com"], D + 3),
    ];
    let a = app_with(Setup { certs, ..Default::default() }).await;
    let p = page(&a, "/api/v1/certs?domain=a.one.com&limit=1").await;
    assert_eq!(indexes(p["rows"].as_array().unwrap()), vec![1], "{p}");
    assert!(p["next_cursor"].is_null(), "{p}");
    // The scan cannot push `wildcard=false` into SQL, so the two newest rows
    // are dropped in Rust and the day is read again.
    let p = page(&a, "/api/v1/certs?domain=one.com&wildcard=false&limit=1").await;
    assert_eq!(indexes(p["rows"].as_array().unwrap()), vec![1], "{p}");
    assert!(p["next_cursor"].is_null(), "{p}");
}

#[tokio::test(flavor = "multi_thread")]
async fn tier_marks_follow_the_hot_dir() {
    let a = app_with(Setup { certs: vec![two_domain_cert()], archive: vec![D], ..Default::default() }).await;
    let hot = rows(&a, "/api/v1/certs?domain=one.com").await;
    assert_eq!(hot.len(), 1, "{hot:?}");
    assert_eq!(hot[0]["tier"], "hot");
    assert_eq!(hot[0]["names"], serde_json::json!(["*.one.com", "a.one.com"]));
    for k in ["key_type", "renewal", "san_count"] {
        assert!(hot[0]["detail"].get(k).is_some(), "{k}: {}", hot[0]);
    }
    assert_eq!(hot[0]["detail"]["san_count"], 3);
    std::fs::remove_dir_all(day_dir(&a, D)).unwrap();
    let cold = rows(&a, "/api/v1/certs?domain=one.com").await;
    assert_eq!(cold.len(), 1, "{cold:?}");
    assert_eq!(cold[0]["tier"], "archive");
    assert!(cold[0].get("detail").is_none(), "{}", cold[0]);
    assert_eq!(without_tier(&cold[0]), without_tier(&hot[0]));
}

#[tokio::test(flavor = "multi_thread")]
async fn archive_file_of_any_name_is_read() {
    let a = app_with(Setup { certs: vec![two_domain_cert()], archive: vec![D], ..Default::default() }).await;
    let dir = a._dir.path().join("archive").join("certs");
    std::fs::rename(dir.join("2024-10-04.parquet"), dir.join("merged.parquet")).unwrap();
    std::fs::remove_dir_all(day_dir(&a, D)).unwrap();
    let rs = rows(&a, "/api/v1/certs?domain=two.org").await;
    assert_eq!(rs.len(), 1, "{rs:?}");
    assert_eq!(rs[0]["tier"], "archive");
}

#[tokio::test(flavor = "multi_thread")]
async fn unarchived_day_is_scanned() {
    let archived = app_with(Setup { certs: vec![two_domain_cert()], archive: vec![D], ..Default::default() }).await;
    let scanned = app_with(Setup { certs: vec![two_domain_cert()], ..Default::default() }).await;
    for d in ["one.com", "two.org"] {
        let path = format!("/api/v1/certs?domain={d}");
        let s = rows(&scanned, &path).await;
        assert_eq!(s.len(), 1, "{s:?}");
        assert_eq!(s[0]["tier"], "hot");
        assert_eq!(s, rows(&archived, &path).await, "{d}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn deeper_name_filters_rows() {
    let certs = vec![
        cert(1, &["a.one.com"], D + 1),
        cert(2, &["*.one.com"], D + 2),
        cert(3, &["b.one.com"], D + 3),
        cert(4, &["x.a.one.com", "one.com"], D + 4),
    ];
    for archive in [vec![], vec![D]] {
        let a = app_with(Setup { certs: certs.clone(), archive, ..Default::default() }).await;
        assert_eq!(indexes(&rows(&a, "/api/v1/certs?domain=a.one.com").await), vec![1, 2]);
        assert_eq!(indexes(&rows(&a, "/api/v1/certs?domain=*.a.one.com").await), vec![1, 2]);
        assert_eq!(indexes(&rows(&a, "/api/v1/certs?domain=one.com").await), vec![1, 2, 3, 4]);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn filters_apply_in_both_tiers() {
    let mut c1 = cert(1, &["one.com", "www.one.com"], D + 1000);
    c1.parsed.not_after_ms = D + 90 * DAY_MS;
    let mut c2 = cert(2, &["*.one.com"], D + 2000);
    c2.parsed.issuer_cn = "Sectigo RSA".into();
    c2.parsed.not_after_ms = D + 30 * DAY_MS;
    let mut c3 = cert(3, &["a.one.com"], D + DAY_MS + 3000);
    c3.parsed.issuer_cn = "R3 Encrypt".into();
    c3.parsed.not_after_ms = D + 365 * DAY_MS;
    let a = app_with(Setup { certs: vec![c1, c2, c3], archive: vec![D, D + DAY_MS], ..Default::default() }).await;
    let cases: Vec<(String, Vec<i64>)> = vec![
        (format!("from={}", D + 1500), vec![2, 3]),
        (format!("to={}", D + 1500), vec![1]),
        ("from=2024-10-05".into(), vec![3]),
        ("to=2024-10-04".into(), vec![1, 2]),
        (format!("expires_from={}", D + 60 * DAY_MS), vec![1, 3]),
        (format!("expires_to={}", D + 60 * DAY_MS), vec![2]),
        ("issuer=LE".into(), vec![1]),
        ("issuer_contains=encrypt".into(), vec![3]),
        ("issuer_contains=SECTIGO".into(), vec![2]),
        ("tld=com".into(), vec![1, 2, 3]),
        ("tld=org".into(), vec![]),
        ("wildcard=true".into(), vec![2]),
        ("wildcard=false".into(), vec![1, 3]),
    ];
    let mut before = Vec::new();
    for (q, want) in &cases {
        let rs = rows(&a, &format!("/api/v1/certs?domain=one.com&{q}")).await;
        assert_eq!(&indexes(&rs), want, "{q}");
        assert!(rs.iter().all(|r| r["tier"] == "hot"), "{q}: {rs:?}");
        before.push(rs.iter().map(without_tier).collect::<Vec<_>>());
    }
    std::fs::remove_dir_all(day_dir(&a, D)).unwrap();
    std::fs::remove_dir_all(day_dir(&a, D + DAY_MS)).unwrap();
    for ((q, _), b) in cases.iter().zip(before) {
        let rs = rows(&a, &format!("/api/v1/certs?domain=one.com&{q}")).await;
        assert!(rs.iter().all(|r| r["tier"] == "archive"), "{q}: {rs:?}");
        assert_eq!(rs.iter().map(without_tier).collect::<Vec<_>>(), b, "{q}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tld_and_wildcard_are_per_row() {
    for archive in [vec![], vec![D]] {
        let a = app_with(Setup { certs: vec![two_domain_cert()], archive, ..Default::default() }).await;
        let n = |q: &'static str| {
            let a = &a;
            async move { rows(a, &format!("/api/v1/certs?domain=two.org&{q}")).await.len() }
        };
        assert_eq!(n("tld=org").await, 1);
        assert_eq!(n("tld=com").await, 0);
        assert_eq!(n("wildcard=true").await, 0);
        assert_eq!(n("wildcard=false").await, 1);
        assert_eq!(rows(&a, "/api/v1/certs?domain=one.com&wildcard=true").await.len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn paging_returns_every_row_once() {
    // Day D is archived and still hot, day D+1 is only hot. Within a day all
    // certificates share a time; one of them covers both domains.
    let s1 = D + 5;
    let s2 = D + DAY_MS + 5;
    let mut late = cert(6, &["c.one.com"], s2);
    late.log = 1;
    let certs = vec![
        cert(1, &["a.one.com"], s1),
        cert(2, &["a.bone.com"], s1),
        cert(3, &["b.one.com", "b.bone.com"], s1),
        cert(4, &["d.one.com"], s2),
        cert(5, &["e.bone.com"], s2),
        late,
    ];
    let a = app_with(Setup { certs, archive: vec![D], ..Default::default() }).await;
    let mut seen: Vec<Key> = Vec::new();
    let mut all = Vec::new();
    let mut path = "/api/v1/certs?q=one.com&mode=contains&limit=3".to_string();
    let mut pages = 0;
    loop {
        let p = page(&a, &path).await;
        pages += 1;
        let rs = p["rows"].as_array().unwrap();
        seen.extend(rs.iter().map(key));
        all.extend(rs.iter().cloned());
        match p["next_cursor"].as_str() {
            Some(c) => path = format!("/api/v1/certs?q=one.com&mode=contains&limit=3&cursor={c}"),
            None => break,
        }
        assert!(pages < 10, "no end");
    }
    assert_eq!(pages, 3, "{all:?}");
    assert_eq!(seen.len(), 7, "{seen:?}");
    assert_eq!(seen.iter().collect::<HashSet<_>>().len(), 7, "{seen:?}");
    let order: Vec<(i64, i64, i64)> =
        all.iter().map(|r| (r["seen_at"].as_i64().unwrap(), r["log_id"].as_i64().unwrap(), r["entry_index"].as_i64().unwrap())).collect();
    let mut sorted = order.clone();
    sorted.sort_by(|x, y| y.cmp(x));
    assert_eq!(order, sorted);
    // The certificate covering both domains: bone.com before one.com.
    let three: Vec<&str> = all.iter().filter(|r| r["entry_index"] == 3).map(|r| r["reg_domain"].as_str().unwrap()).collect();
    assert_eq!(three, vec!["bone.com", "one.com"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn fuzzy_scope_looks_up_hits() {
    let a = app_with(Setup { certs: vec![cert(1, &["www.example.com"], D)], ..Default::default() }).await;
    let rs = rows(&a, "/api/v1/certs?q=exampel.com&mode=levenshtein").await;
    assert_eq!(rs.len(), 1, "{rs:?}");
    assert_eq!(rs[0]["reg_domain"], "example.com");
    assert!(rows(&a, "/api/v1/certs?q=nothing-like-it.net").await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn scope_errors() {
    let a = app().await;
    let long = format!("/api/v1/certs?q={}", "a".repeat(254));
    for p in [
        "/api/v1/certs",
        "/api/v1/certs?domain=a.com&q=a.com",
        "/api/v1/certs?domain=a.com&cursor=garbage",
        "/api/v1/certs?domain=1.2.3.4",
        "/api/v1/certs?domain=a.com&from=yesterday",
        "/api/v1/certs?domain=a.com&limit=0",
        "/api/v1/certs?domain=a.com&wildcard=maybe",
        "/api/v1/certs?domain=a.com&mode=contains",
        "/api/v1/certs?q=a.com&mode=x",
        "/api/v1/certs?q=%20",
        long.as_str(),
    ] {
        let (s, _, b) = get(&a, p).await;
        assert_eq!(s, 400, "{p}: {b}");
        assert_eq!(code(&b), "bad_request", "{p}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn timeout_without_rows_is_504() {
    let a = app_with(Setup { certs: vec![two_domain_cert()], timeout: Some(Duration::ZERO), ..Default::default() }).await;
    let (s, _, b) = get(&a, "/api/v1/certs?domain=one.com").await;
    assert_eq!(s, 504, "{b}");
    assert_eq!(code(&b), "timeout");
}

#[tokio::test(flavor = "multi_thread")]
async fn certs_takes_the_archive_permit_when_there_is_an_archive() {
    let a = app_with(Setup { certs: vec![two_domain_cert()], archive: vec![D], ..Default::default() }).await;
    let _held = a.state.v1.enter(true).unwrap();
    let (s, _, b) = get(&a, "/api/v1/certs?domain=one.com").await;
    assert_eq!(s, 429, "{b}");
    let (s, _, _) = get(&a, "/api/v1/search?q=one.com").await;
    assert_eq!(s, 200);
}

/// A first-attempt probe of `name`, `at` ms into day `D`.
fn probe(name: &str, at: i64, v4: &[&str]) -> DnsRow {
    let lookup = Lookup {
        status: Status::Resolved,
        v4: v4.iter().map(|a| a.parse().unwrap()).collect(),
        v6: vec![],
        cnames: vec![],
        ttl: Some(60),
    };
    DnsRow {
        probed_at_ms: at,
        name: name.into(),
        kind: Kind::Name,
        reg_domain: names::registered_domain(name),
        cert_hash: 1,
        cert_seen_at_ms: D,
        attempt: 0,
        renewal: "new",
        lookup,
        latency_ms: 5,
        last_miss_ms: None,
        prev: None,
    }
}

/// Three probes of one name, the last with a new address: two rows remain.
fn changing_name() -> Vec<DnsRow> {
    vec![
        probe("www.example.com", D + 1000, &["1.1.1.1"]),
        probe("www.example.com", D + 2000, &["1.1.1.1"]),
        probe("www.example.com", D + 3000, &["2.2.2.2"]),
    ]
}

fn dns_dir(a: &App, ms: i64) -> std::path::PathBuf {
    let day = chrono::DateTime::from_timestamp_millis(ms).unwrap().date_naive();
    a._dir.path().join("dns").join(format!("day={}", day.format("%Y-%m-%d")))
}

fn dns_rows(p: &Value) -> Vec<Value> {
    p["dns"]["rows"].as_array().unwrap().clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn domain_summary_from_the_index() {
    let certs = vec![cert(1, &["a.example.com"], D + 10), cert(2, &["b.example.com"], D + 5000)];
    let a = app_with(Setup { certs, dns: changing_name(), ..Default::default() }).await;
    let hits = page(&a, "/api/search?q=example.com&mode=exact").await;
    let hit = &hits[0];
    assert_eq!(hit["domain"], "example.com");
    let p = page(&a, "/api/v1/domain/example.com").await;
    assert_eq!(p["domain"], "example.com");
    assert_eq!(p["first_seen"], hit["first_seen_ms"]);
    assert_eq!(p["last_seen"], hit["last_seen_ms"]);
    assert_eq!(p["cert_count"], hit["cert_count"]);
    assert_eq!(p["cert_count"], 2);
    assert!(p["first_seen"].is_i64() && p["last_seen"].is_i64(), "{p}");
    assert_eq!(dns_rows(&p).len(), 2, "{p}");
}

#[tokio::test(flavor = "multi_thread")]
async fn deeper_name_is_reduced() {
    let a = app_with(Setup { certs: vec![cert(1, &["www.example.com"], D + 10)], ..Default::default() }).await;
    let p = page(&a, "/api/v1/domain/www.example.com").await;
    assert_eq!(p["domain"], "example.com");
    assert_eq!(p["cert_count"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_domain_is_404() {
    let a = app().await;
    let (s, _, b) = get(&a, "/api/v1/domain/never-seen.com").await;
    assert_eq!(s, 404, "{b}");
    assert_eq!(code(&b), "not_found");
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_only_domain_has_null_summary() {
    let a = app_with(Setup { dns: changing_name(), ..Default::default() }).await;
    let p = page(&a, "/api/v1/domain/example.com").await;
    for k in ["first_seen", "last_seen", "cert_count"] {
        assert!(p[k].is_null(), "{k}: {p}");
    }
    assert_eq!(dns_rows(&p).len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_rows_same_before_and_after_archiving() {
    let a = app_with(Setup { dns: changing_name(), archive: vec![D], ..Default::default() }).await;
    let hot = dns_rows(&page(&a, "/api/v1/domain/example.com").await);
    assert_eq!(hot.len(), 2, "{hot:?}");
    assert!(hot.iter().all(|r| r["tier"] == "hot"), "{hot:?}");
    assert_eq!(hot[0]["probed_at"], D + 3000);
    assert_eq!(hot[0]["v4"], serde_json::json!(["2.2.2.2"]));
    assert_eq!(hot[1]["probed_at"], D + 1000);
    assert_eq!(hot[0]["name"], "www.example.com");
    assert_eq!(hot[0]["status"], "resolved");
    assert_eq!(hot[0]["v6"], serde_json::json!([]));
    std::fs::remove_dir_all(dns_dir(&a, D)).unwrap();
    let cold = dns_rows(&page(&a, "/api/v1/domain/example.com").await);
    assert_eq!(cold.len(), 2, "{cold:?}");
    assert!(cold.iter().all(|r| r["tier"] == "archive"), "{cold:?}");
    let plain = |v: &[Value]| -> Vec<Value> { v.iter().map(without_tier).collect() };
    assert_eq!(plain(&cold), plain(&hot));
}

#[tokio::test(flavor = "multi_thread")]
async fn unarchived_dns_day_matches_the_archive() {
    let archived = app_with(Setup { dns: changing_name(), archive: vec![D], ..Default::default() }).await;
    let scanned = app_with(Setup { dns: changing_name(), ..Default::default() }).await;
    let p = "/api/v1/domain/example.com";
    assert_eq!(dns_rows(&page(&scanned, p).await), dns_rows(&page(&archived, p).await));
}

#[tokio::test(flavor = "multi_thread")]
async fn archived_day_is_read_from_archive_only() {
    let a = app_with(Setup { dns: changing_name(), archive: vec![D], ..Default::default() }).await;
    // The hot files are still there: reading both would give four rows.
    assert!(dns_dir(&a, D).exists());
    let rs = dns_rows(&page(&a, "/api/v1/domain/example.com").await);
    assert_eq!(rs.len(), 2, "{rs:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn other_domains_names_are_not_mixed_in() {
    let mut dns = changing_name();
    dns.push(probe("www.other.org", D + 1500, &["9.9.9.9"]));
    let a = app_with(Setup { dns, archive: vec![D], ..Default::default() }).await;
    let rs = dns_rows(&page(&a, "/api/v1/domain/example.com").await);
    assert!(rs.iter().all(|r| r["name"] == "www.example.com"), "{rs:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_paging_returns_every_row_once() {
    let n = |s: &str| format!("{s}.example.com");
    let mut dns = vec![];
    // Day D (archived): ties on probed_at, ordered by name.
    for s in ["c", "a", "b"] {
        dns.push(probe(&n(s), D + 500, &["1.1.1.1"]));
    }
    dns.push(probe(&n("a"), D + 900, &["1.1.1.2"]));
    // Day D+1 (hot only).
    dns.push(probe(&n("a"), D + DAY_MS + 100, &["1.1.1.3"]));
    dns.push(probe(&n("d"), D + DAY_MS + 100, &["1.1.1.4"]));
    let a = app_with(Setup { dns, archive: vec![D], ..Default::default() }).await;
    let all = dns_rows(&page(&a, "/api/v1/domain/example.com?limit=100").await);
    assert_eq!(all.len(), 6, "{all:?}");
    let order: Vec<(i64, String)> = all.iter().map(|r| (r["probed_at"].as_i64().unwrap(), r["name"].as_str().unwrap().into())).collect();
    let mut sorted = order.clone();
    sorted.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)));
    assert_eq!(order, sorted);
    assert_eq!(all[0]["tier"], "hot");
    for limit in [1, 2, 4] {
        let mut got = vec![];
        let mut path = format!("/api/v1/domain/example.com?limit={limit}");
        for _ in 0..20 {
            let p = page(&a, &path).await;
            got.extend(dns_rows(&p));
            match p["dns"]["next_cursor"].as_str() {
                Some(c) => path = format!("/api/v1/domain/example.com?limit={limit}&cursor={c}"),
                None => break,
            }
        }
        assert_eq!(got, all, "limit {limit}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn domain_inputs_are_checked() {
    let a = app().await;
    for p in [
        "/api/v1/domain/not%20a%20name",
        "/api/v1/domain/example.com?limit=0",
        "/api/v1/domain/example.com?cursor=garbage",
        "/api/v1/domain/example.com?bogus=1",
    ] {
        let (s, _, b) = get(&a, p).await;
        assert_eq!(s, 400, "{p}: {b}");
        assert_eq!(code(&b), "bad_request", "{p}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn domain_timeout_before_the_summary_is_504() {
    let a = app_with(Setup { dns: changing_name(), timeout: Some(Duration::ZERO), ..Default::default() }).await;
    let (s, _, b) = get(&a, "/api/v1/domain/example.com").await;
    assert_eq!(s, 504, "{b}");
    assert_eq!(code(&b), "timeout");
}

#[tokio::test(flavor = "multi_thread")]
async fn domain_takes_the_archive_permit_when_there_is_a_dns_archive() {
    let a = app_with(Setup { dns: changing_name(), archive: vec![D], ..Default::default() }).await;
    let _held = a.state.v1.enter(true).unwrap();
    let (s, _, b) = get(&a, "/api/v1/domain/example.com").await;
    assert_eq!(s, 429, "{b}");
}
