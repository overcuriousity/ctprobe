use ctprobe::config::Config;
use ctprobe::fetch::FetchOpts;
use ctprobe::mocklog::{MockEntry, MockLog, MockOpts, TestCa};
use ctprobe::pipeline::{Pipeline, PipelineOpts};
use ctprobe::query::{QueryEngine, QueryResult};
use ctprobe::registry::{LogKind, LogSpec};
use ctprobe::web;
use futures::StreamExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

struct App {
    base: String,
    pipe: Pipeline,
    log: MockLog,
    _dir: tempfile::TempDir,
}

async fn app(entries: Vec<MockEntry>, hold: bool) -> App {
    let log = MockLog::start(MockOpts::rfc6962(0).with_entries(entries)).await;
    if hold {
        log.set_tree_size(0);
    }
    app_on(log).await
}

async fn app_on(log: MockLog) -> App {
    let dir = tempfile::tempdir().unwrap();
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
    };
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
    };
    let pipe = Pipeline::start(cfg, opts).await.unwrap();
    let engine = Arc::new(QueryEngine::open(dir.path()).unwrap());
    let state = web::AppState::new(engine, pipe.handle.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(web::serve(listener, state));
    App { base, pipe, log, _dir: dir }
}

fn certs(names: &[&str]) -> Vec<MockEntry> {
    let ca = TestCa::default();
    names.iter().enumerate().map(|(i, n)| ca.final_cert(i as u64 + 1, &[n])).collect()
}

/// Reads SSE until `pred` holds for an accumulated body.
async fn read_sse(url: &str, secs: u64, pred: impl Fn(&str) -> bool) -> String {
    let resp = reqwest::get(url).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers()["content-type"].to_str().unwrap().starts_with("text/event-stream"));
    let mut s = resp.bytes_stream();
    let mut text = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(secs), async {
        while let Some(Ok(b)) = s.next().await {
            text.push_str(&String::from_utf8_lossy(&b));
            if pred(&text) {
                return;
            }
        }
    })
    .await;
    text
}

#[test]
fn csv_neutralises_formulas() {
    let r = QueryResult {
        columns: vec!["a".into(), "b".into(), "c".into()],
        rows: vec![vec![
            serde_json::json!("=cmd()"),
            serde_json::json!("x,\"y\""),
            serde_json::json!(["p.com", "q.com"]),
        ]],
        truncated: false,
    };
    assert_eq!(web::csv::to_csv(&r), "a,b,c\n'=cmd(),\"x,\"\"y\"\"\",p.com q.com\n");
    for bad in ["+1", "-1", "@x", "\tx", "\rx"] {
        let r = QueryResult {
            columns: vec!["a".into()],
            rows: vec![vec![serde_json::json!(bad)]],
            truncated: false,
        };
        assert!(web::csv::to_csv(&r).contains(&format!("'{}", bad.trim_end())) || bad == "\rx");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn healthz_ok() {
    let a = app(vec![], false).await;
    let r = reqwest::get(format!("{}/healthz", a.base)).await.unwrap();
    assert_eq!(r.status(), 200);
    let live: serde_json::Value = reqwest::get(format!("{}/api/live", a.base)).await.unwrap().json().await.unwrap();
    assert_eq!(live["logs"][0]["name"], "mock");
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_sends_snapshot_within_2s() {
    let a = app(vec![], false).await;
    let t = read_sse(&format!("{}/api/stream", a.base), 3, |t| t.contains("event: snapshot")).await;
    assert!(t.contains("event: snapshot"), "{t}");
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn sse_filter_applies() {
    let a = app(certs(&["needle.example.com", "hay.example.org"]), true).await;
    let url = format!("{}/api/stream?q=needle", a.base);
    let log = &a.log;
    let reader = read_sse(&url, 4, |t| t.contains("event: cert"));
    let open = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        log.set_tree_size(2);
    };
    let (t, _) = tokio::join!(reader, open);
    assert!(t.contains("needle.example.com"), "{t}");
    assert!(!t.contains("hay.example.org"), "{t}");
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_sse_client_does_not_block() {
    let names: Vec<String> = (0..3000).map(|i| format!("h{i}.example.com")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let a = app(certs(&refs), true).await;
    // Connected and never read.
    let _stalled = reqwest::get(format!("{}/api/stream", a.base)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    a.log.set_tree_size(3000);
    tokio::time::timeout(Duration::from_secs(20), async {
        while a.pipe.handle.live.snapshot().raw_total < 3000 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("ingest stalled behind a slow client");
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn sse_client_cap_returns_503() {
    let a = app(vec![], false).await;
    let mut held = vec![];
    for _ in 0..web::MAX_SSE_CLIENTS {
        held.push(reqwest::get(format!("{}/api/stream", a.base)).await.unwrap());
    }
    let r = reqwest::get(format!("{}/api/stream", a.base)).await.unwrap();
    assert_eq!(r.status(), 503);
    drop(held);
    a.pipe.shutdown().await.unwrap();
}

#[test]
fn feed_item_with_html_is_inert() {
    for f in std::fs::read_dir(Path::new("assets")).unwrap() {
        let p = f.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("uplot") || !(name.ends_with(".js") || name.ends_with(".html")) {
            continue;
        }
        let t = std::fs::read_to_string(&p).unwrap();
        assert!(!t.contains("innerHTML"), "{name}");
        assert!(!t.contains("insertAdjacentHTML"), "{name}");
        assert!(!t.contains("document.write"), "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pages_have_csp_and_render() {
    let a = app(vec![], false).await;
    let r = reqwest::get(format!("{}/", a.base)).await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.headers()["content-security-policy"].to_str().unwrap().contains("default-src 'self'"));
    assert!(r.text().await.unwrap().contains("ctprobe"));
    let r = reqwest::get(format!("{}/assets/uplot.min.js", a.base)).await.unwrap();
    assert_eq!(r.status(), 200);
    a.pipe.shutdown().await.unwrap();
}

async fn wait_rows(a: &App, n: u64) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while a.pipe.handle.live.snapshot().raw_total < n {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("entries did not arrive");
    tokio::time::sleep(Duration::from_millis(400)).await; // Let a commit land.
}

#[tokio::test(flavor = "multi_thread")]
async fn every_metric_has_a_valid_query() {
    let a = app(certs(&["a.example.com", "b.example.org", "c.example.net"]), false).await;
    wait_rows(&a, 3).await;
    for m in web::trends::METRICS {
        for bucket in ["minute", "hour", "day"] {
            let u = format!("{}/api/trends/{m}?bucket={bucket}", a.base);
            let r = reqwest::get(&u).await.unwrap();
            let code = r.status();
            assert_eq!(code, 200, "{m} {bucket}: {}", r.text().await.unwrap());
        }
    }
    let v: serde_json::Value = reqwest::get(format!("{}/api/trends/issuers", a.base)).await.unwrap().json().await.unwrap();
    assert_eq!(v["rows"][0][0], "Test CA");
    assert_eq!(v["rows"][0][1], 3);
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_metric_is_404() {
    let a = app(vec![], false).await;
    let r = reqwest::get(format!("{}/api/trends/nope", a.base)).await.unwrap();
    assert_eq!(r.status(), 404);
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn search_page_flow() {
    let a = app(certs(&["needle.example.com"]), false).await;
    wait_rows(&a, 1).await;
    let hits: serde_json::Value = reqwest::get(format!("{}/api/search?q=example.com&mode=levenshtein&distance=1", a.base)).await.unwrap().json().await.unwrap();
    assert_eq!(hits[0]["domain"], "example.com");
    let c: serde_json::Value = reqwest::get(format!("{}/api/certs?domain=example.com", a.base)).await.unwrap().json().await.unwrap();
    assert_eq!(c["rows"].as_array().unwrap().len(), 1);
    let csv = reqwest::get(format!("{}/api/certs?domain=example.com&format=csv", a.base)).await.unwrap().text().await.unwrap();
    assert!(csv.starts_with("seen_at,cn,"), "{csv}");
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn cert_detail_fetches_from_mock_log() {
    let a = app(certs(&["needle.example.com"]), false).await;
    wait_rows(&a, 1).await;
    let c: serde_json::Value = reqwest::get(format!("{}/api/cert/0/0", a.base)).await.unwrap().json().await.unwrap();
    assert_eq!(c["parsed"]["subject_cn"], "needle.example.com");
    assert!(c["pem"].as_str().unwrap().starts_with("-----BEGIN CERTIFICATE-----"));
    let r = reqwest::get(format!("{}/api/cert/0/99", a.base)).await.unwrap();
    assert_eq!(r.status(), 404);
    let r = reqwest::get(format!("{}/api/cert/7/0", a.base)).await.unwrap();
    assert_eq!(r.status(), 404);
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_store_renders() {
    let a = app(vec![], false).await;
    for p in ["/", "/trends", "/search", "/sql", "/sizing", "/domain?d=example.com", "/cert?log=0&index=0", "/api/schema"] {
        assert_eq!(reqwest::get(format!("{}{p}", a.base)).await.unwrap().status(), 200, "{p}");
    }
    for m in web::trends::METRICS {
        let r = reqwest::get(format!("{}/api/trends/{m}", a.base)).await.unwrap();
        let code = r.status();
        assert_eq!(code, 200, "{m}: {}", r.text().await.unwrap());
    }
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn trend_range_is_validated() {
    let a = app(vec![], false).await;
    let r = reqwest::get(format!("{}/api/trends/volume?bucket=week;drop", a.base)).await.unwrap();
    assert_eq!(r.status(), 400);
    a.pipe.shutdown().await.unwrap();
}

async fn get_json(u: String) -> serde_json::Value {
    reqwest::get(u).await.unwrap().json().await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn cert_filters_apply() {
    let a = app(certs(&["a.example.com", "b.example.com"]), false).await;
    wait_rows(&a, 2).await;
    let n = |q: &'static str| {
        let base = a.base.clone();
        async move {
            let v = get_json(format!("{base}/api/certs?domain=example.com&{q}")).await;
            v["rows"].as_array().map(|r| r.len()).unwrap_or(usize::MAX)
        }
    };
    assert_eq!(n("").await, 2);
    assert_eq!(n("issuer=Test%20CA").await, 2);
    assert_eq!(n("issuer=Nobody").await, 0);
    assert_eq!(n("issuer=x%27%20OR%20%271%27=%271").await, 0);
    assert_eq!(n("renewal=exact").await, 0);
    assert_eq!(n("renewal=new").await, 2);
    assert_eq!(n("wildcard=true").await, 0);
    assert_eq!(n("wildcard=false").await, 2);
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn domain_overview_lists_issuers_and_subdomains() {
    let a = app(certs(&["a.example.com", "b.example.com", "b.example.com"]), false).await;
    wait_rows(&a, 3).await;
    let v = get_json(format!("{}/api/domain?d=Example.com", a.base)).await;
    assert_eq!(v["domain"], "example.com");
    assert_eq!(v["issuers"]["rows"][0], serde_json::json!(["Test CA", 3]));
    assert_eq!(v["names"]["rows"][0], serde_json::json!(["b.example.com", 2]));
    assert_eq!(v["days"]["rows"].as_array().unwrap().len(), 1);
    assert!(v["similar"].is_array());
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn minute_rollup_records_backlog() {
    let a = app(certs(&["a.example.com"]), false).await;
    wait_rows(&a, 1).await;
    let q = "SELECT raw_entries, backlog, limited_backlog, healthy_logs FROM rollup_minute WHERE log_id = 65535 ORDER BY raw_entries DESC";
    let u = format!("{}/api/sql?q={}", a.base, q.replace(' ', "%20").replace('=', "%3D"));
    let v = get_json(u).await;
    assert_eq!(v["rows"][0], serde_json::json!([1, 0, 0, 1]), "{v}");
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_gives_start_time_and_steady_rates() {
    let a = app(certs(&["a.example.com", "b.example.com"]), false).await;
    wait_rows(&a, 2).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let v = get_json(format!("{}/api/live", a.base)).await;
    assert!(v["started_at_ms"].as_i64().unwrap() > 1_000_000_000_000, "{v}");
    assert!(v["raw_per_sec"].as_f64().unwrap() > 0.0, "the batch stays in the window: {v}");
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn history_endpoint_works_on_empty_and_after_entries() {
    let a = app(certs(&["a.example.com", "b.example.com"]), true).await;
    let v = get_json(format!("{}/api/history?minutes=5", a.base)).await;
    assert_eq!(v["totals"]["raw"], 0, "{v}");
    assert!(v["t"].is_array() && v["raw"].is_array());
    a.log.set_tree_size(2);
    wait_rows(&a, 2).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let v = get_json(format!("{}/api/history?minutes=5", a.base)).await;
    assert_eq!(v["totals"]["raw"], 2, "{v}");
    assert_eq!(v["totals"]["unique"], 2, "{v}");
    let r = reqwest::get(format!("{}/api/history?minutes=99999", a.base)).await.unwrap();
    assert_eq!(r.status(), 200);
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_endpoint_reports_state_and_problems() {
    let a = app(certs(&["a.example.com"]), false).await;
    wait_rows(&a, 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let v = get_json(format!("{}/api/logs", a.base)).await;
    let l = &v["logs"][0];
    assert_eq!(l["name"], "mock", "{v}");
    assert_eq!(l["state"], "measuring");
    assert_eq!(l["behind"], 0);
    assert_eq!(l["problems"], 0);
    assert_eq!(v["verdict"]["status"], "measuring");
    assert_eq!(v["coverage_target"], 95.0);
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn delay_is_null_before_data() {
    let a = app(vec![], true).await;
    let v = get_json(format!("{}/api/logs", a.base)).await;
    assert!(v["logs"][0]["delay_p50_ms"].is_null(), "{v}");
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_tree_size_is_null_not_zero() {
    let log = MockLog::start(MockOpts::rfc6962(10)).await;
    log.fail_next(1_000_000, 500);
    let a = app_on(log).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let v = get_json(format!("{}/api/logs", a.base)).await;
            if v["logs"][0]["last_error"].is_string() {
                assert!(v["logs"][0]["behind"].is_null(), "{v}");
                assert!(v["logs"][0]["last_error"].as_str().unwrap().contains("500"), "{v}");
                assert!(v["logs"][0]["last_error_ms"].as_i64().unwrap() > 0);
                assert!(v["logs"][0]["problems"].as_u64().is_some());
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("no error reported");
    let live = get_json(format!("{}/api/live", a.base)).await;
    assert!(live["behind_total"].is_null(), "{live}");
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn sse_snapshot_has_totals_but_no_logs() {
    let a = app(certs(&["a.example.com"]), false).await;
    let got = read_sse(&format!("{}/api/stream", a.base), 3, |t| t.contains("\"log_count\"")).await;
    assert!(got.contains("\"log_count\":1"), "{got}");
    assert!(got.contains("\"logs\":[]"), "{got}");
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn catchup_trend_has_published_rate() {
    let a = app(certs(&["a.example.com"]), false).await;
    wait_rows(&a, 1).await;
    let v = get_json(format!("{}/api/trends/catchup?hours=1&bucket=minute", a.base)).await;
    let cols: Vec<_> = v["columns"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
    assert_eq!(cols, ["log_id", "fetched_per_sec", "published_per_sec", "backlog_change", "problems"]);
    assert_eq!(v["rows"].as_array().unwrap().len(), 1, "{v}");
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn coverage_appears_in_logs_api() {
    let names: Vec<String> = (0..40).map(|i| format!("h{i}.example.com")).collect();
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    let a = app(certs(&refs), false).await;
    wait_rows(&a, 40).await;
    let v = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let v = get_json(format!("{}/api/logs", a.base)).await;
            if !v["coverage"].is_null() {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("coverage never appeared");
    let l = &v["logs"][0];
    assert_eq!(l["share_pct"], 100.0, "{v}");
    assert_eq!(l["alone_pct"], 100.0, "{v}");
    assert_eq!(l["rank"], 1, "{v}");
    assert_eq!(l["undercounted"], false, "{v}");
    assert!(v["coverage"]["sampled_certs"].as_u64().unwrap() > 0);
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn coverage_is_null_on_an_empty_store() {
    let a = app(vec![], true).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let v = get_json(format!("{}/api/logs", a.base)).await;
    assert!(v["coverage"].is_null(), "{v}");
    assert!(v["logs"][0]["share_pct"].is_null(), "{v}");
    a.pipe.shutdown().await.unwrap();
}

fn enc(s: &str) -> String {
    url_escape(s)
}

fn url_escape(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

fn hour_ago_ms() -> i64 {
    chrono::Utc::now().timestamp_millis() - 3_600_000
}

#[tokio::test(flavor = "multi_thread")]
async fn filter_without_domain_returns_rows() {
    let a = app(certs(&["a.example.com", "b.example.org"]), false).await;
    wait_rows(&a, 2).await;
    let v = get_json(format!("{}/api/certs?tld=org", a.base)).await;
    assert_eq!(v["rows"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(v["count"], 1);
    assert!(v["from_ms"].as_i64().unwrap() > 0, "defaults to the last day: {v}");
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn no_scope_and_no_filter_is_400() {
    let a = app(vec![], true).await;
    let r = reqwest::get(format!("{}/api/certs", a.base)).await.unwrap();
    assert_eq!(r.status(), 400);
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn each_new_filter_applies() {
    let a = app(certs(&["a.example.com", "b.example.com"]), false).await;
    wait_rows(&a, 2).await;
    let n = |q: String| {
        let base = a.base.clone();
        async move { get_json(format!("{base}/api/certs?domain=example.com&{q}")).await["rows"].as_array().unwrap().len() }
    };
    assert_eq!(n("tld=com".into()).await, 2);
    assert_eq!(n("tld=org".into()).await, 0);
    assert_eq!(n("issuer_contains=test".into()).await, 2);
    assert_eq!(n("issuer_contains=nope".into()).await, 0);
    assert_eq!(n("precert=true".into()).await, 0);
    assert_eq!(n("precert=false".into()).await, 2);
    assert_eq!(n("san=1".into()).await, 2);
    assert_eq!(n("san=2".into()).await, 0);
    assert_eq!(n("size=%3E%3D16%20KiB".into()).await, 0);
    assert_eq!(n("key_type=none".into()).await, 0);
    assert_eq!(n("validity=nope".into()).await, 0);
    assert_eq!(n(format!("expires_to={}", 1)).await, 0);
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn sort_orders_across_all_rows_not_a_page() {
    let a = app(certs(&["e.example.com", "c.example.com", "a.example.com", "d.example.com", "b.example.com"]), false).await;
    wait_rows(&a, 5).await;
    let cn = |q: &'static str| {
        let base = a.base.clone();
        async move {
            let v = get_json(format!("{base}/api/certs?domain=example.com&sort=cn&dir=asc&limit=2&{q}")).await;
            let i = v["columns"].as_array().unwrap().iter().position(|c| c == "cn").unwrap();
            (v["rows"].as_array().unwrap().iter().map(|r| r[i].as_str().unwrap().to_string()).collect::<Vec<_>>(), v["truncated"].as_bool().unwrap(), v["count"].clone())
        }
    };
    let (rows, more, count) = cn("offset=0").await;
    assert_eq!(rows, ["a.example.com", "b.example.com"]);
    assert!(more);
    assert_eq!(count, 5);
    let (rows, ..) = cn("offset=2").await;
    assert_eq!(rows, ["c.example.com", "d.example.com"]);
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn newest_first_pages_cleanly() {
    let a = app(certs(&["a.example.com", "b.example.com", "c.example.com"]), false).await;
    wait_rows(&a, 3).await;
    let v = get_json(format!("{}/api/certs?domain=example.com&limit=2", a.base)).await;
    assert_eq!(v["rows"].as_array().unwrap().len(), 2);
    assert_eq!(v["truncated"], true);
    assert_eq!(v["count"], 3);
    let v = get_json(format!("{}/api/certs?domain=example.com&limit=2&offset=2", a.base)).await;
    assert_eq!(v["rows"].as_array().unwrap().len(), 1);
    assert_eq!(v["truncated"], false);
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_sort_is_400() {
    let a = app(vec![], true).await;
    for q in ["sort=names", "sort=cn;DROP", "sort=cn&dir=sideways", "offset=10001", "from=soon"] {
        let r = reqwest::get(format!("{}/api/certs?domain=x.com&{q}", a.base)).await.unwrap();
        assert_eq!(r.status(), 400, "{q}");
    }
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn apostrophe_and_percent_in_filter_are_literal() {
    let a = app(certs(&["a.example.com"]), false).await;
    wait_rows(&a, 1).await;
    for bad in ["x' OR '1'='1", "%", "_"] {
        let v = get_json(format!("{}/api/certs?domain=example.com&issuer_contains={}", a.base, enc(bad))).await;
        assert_eq!(v["rows"].as_array().unwrap().len(), 0, "{bad}: {v}");
    }
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn from_accepts_milliseconds_and_dates() {
    let a = app(certs(&["a.example.com"]), false).await;
    wait_rows(&a, 1).await;
    let future = chrono::Utc::now().timestamp_millis() + 86_400_000;
    let rows = |q: String| {
        let base = a.base.clone();
        async move { get_json(format!("{base}/api/certs?domain=example.com&{q}")).await["rows"].as_array().unwrap().len() }
    };
    assert_eq!(rows(format!("from={}", hour_ago_ms())).await, 1);
    assert_eq!(rows(format!("from={future}")).await, 0);
    assert_eq!(rows("to=2000-01-01".into()).await, 0);
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn csv_follows_filters() {
    let a = app(certs(&["a.example.com", "b.example.org"]), false).await;
    wait_rows(&a, 2).await;
    let t = reqwest::get(format!("{}/api/certs?tld=org&format=csv", a.base)).await.unwrap().text().await.unwrap();
    assert!(t.contains("b.example.org") && !t.contains("a.example.com"), "{t}");
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn trends_click_path_finds_the_bar_rows() {
    let a = app(certs(&["a.example.com", "b.example.org", "c.example.org"]), false).await;
    wait_rows(&a, 3).await;
    for (metric, param) in [("issuers", "issuer"), ("tlds", "tld"), ("keys", "key_type"), ("validity", "validity"), ("san_dist", "san"), ("der_size", "size")] {
        let v = get_json(format!("{}/api/trends/{metric}?hours=6&bucket=minute", a.base)).await;
        for row in v["rows"].as_array().unwrap() {
            let (key, bar) = (row[0].as_str().unwrap(), row[1].as_u64().unwrap());
            let u = format!("{}/api/certs?{param}={}&from={}", a.base, enc(key), hour_ago_ms());
            let got = get_json(u).await;
            assert_eq!(got["count"].as_u64(), Some(bar), "{metric} {key}: {got}");
        }
    }
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn short_range_bars_exclude_rows_before_the_range() {
    let a = app(certs(&["a.example.com"]), false).await;
    wait_rows(&a, 1).await;
    let v = get_json(format!("{}/api/trends/issuers?hours=1&bucket=minute", a.base)).await;
    assert_eq!(v["rows"][0][1], 1, "{v}");
    a.pipe.shutdown().await.unwrap();
}

#[test]
fn composition_under_a_day_reads_only_certs() {
    let q = web::trends::trend_query("issuers", 1000, 2000, "minute", 1500, 6).unwrap();
    assert!(!q.contains("rollup_daily"), "{q}");
    assert!(q.contains(">= 1000"), "{q}");
}

#[test]
fn composition_over_a_day_keeps_rollups() {
    let q = web::trends::trend_query("issuers", 1000, 2000, "hour", 1500, 48).unwrap();
    assert!(q.contains("rollup_daily"), "{q}");
}

#[test]
fn distributions_honour_the_range() {
    for m in ["san_dist", "der_size"] {
        assert!(web::trends::trend_query(m, 1000, 2000, "hour", 1500, 48).unwrap().contains(">= 1000"), "{m}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pages_have_their_new_sections() {
    let a = app(vec![], true).await;
    let page = |p: &'static str| {
        let base = a.base.clone();
        async move { reqwest::get(format!("{base}{p}")).await.unwrap().text().await.unwrap() }
    };
    let live = page("/").await;
    for id in ["id=\"timeframe\"", "id=\"keeping\"", "id=\"stages\"", "id=\"logs-card\""] {
        assert!(live.contains(id), "{id}");
    }
    let sizing = page("/sizing").await;
    assert!(sizing.contains("id=\"keeping\"") && sizing.contains("id=\"coverage\""));
    let js = page("/assets/app.js").await;
    for f in ["function sortTable", "function fmtCount", "function logTable", "function keepingCard", "function coverageSummary"] {
        assert!(js.contains(f), "{f}");
    }
    a.pipe.shutdown().await.unwrap();
}

async fn page_ids(a: &App, q: &str, pages: usize) -> Vec<(u64, u64)> {
    let mut seen = Vec::new();
    for p in 0..pages {
        let v = get_json(format!("{}/api/certs?domain=example.com&limit=100&offset={}&{q}", a.base, p * 100)).await;
        let col = |n: &str| v["columns"].as_array().unwrap().iter().position(|c| c == n).unwrap();
        let (l, e) = (col("log_id"), col("entry_index"));
        for r in v["rows"].as_array().unwrap() {
            seen.push((r[l].as_u64().unwrap(), r[e].as_u64().unwrap()));
        }
    }
    seen
}

#[tokio::test(flavor = "multi_thread")]
async fn paging_shows_every_row_once() {
    let names: Vec<String> = (0..300).map(|i| format!("h{i}.example.com")).collect();
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    let a = app(certs(&refs), false).await;
    wait_rows(&a, 300).await;
    for q in ["", "sort=issuer_cn&dir=asc", "sort=san_count"] {
        let mut ids = page_ids(&a, q, 3).await;
        assert_eq!(ids.len(), 300, "{q}");
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 300, "repeated rows with {q}");
    }
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_complete_page_is_not_cut_short() {
    let a = app(certs(&["a.example.com"]), false).await;
    wait_rows(&a, 1).await;
    let v = get_json(format!("{}/api/certs?domain=example.com", a.base)).await;
    assert_eq!(v["cut_short"], false, "{v}");
    a.pipe.shutdown().await.unwrap();
}
