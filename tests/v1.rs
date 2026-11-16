use ctprobe::config::Config;
use ctprobe::fetch::FetchOpts;
use ctprobe::mocklog::{MockLog, MockOpts};
use ctprobe::pipeline::{Pipeline, PipelineOpts};
use ctprobe::query::QueryEngine;
use ctprobe::registry::{LogKind, LogSpec};
use ctprobe::web;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

struct App {
    base: String,
    state: web::AppState,
    _pipe: Pipeline,
    _log: MockLog,
    _dir: tempfile::TempDir,
}

async fn app() -> App {
    let log = MockLog::start(MockOpts::rfc6962(0)).await;
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
        dns: Default::default(),
        hot_days: None,
        dns_days: None,
        archive_budget_bytes: None,
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
        dns: ctprobe::dns::DnsOpts { minute: Duration::from_millis(100), ..Default::default() },
    };
    let pipe = Pipeline::start(cfg, opts).await.unwrap();
    let engine = Arc::new(QueryEngine::open(dir.path()).unwrap());
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
