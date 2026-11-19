use ctprobe::config::Config;
use ctprobe::fetch::FetchOpts;
use ctprobe::mocklog::{MockEntry, MockLog, MockOpts, TestCa};
use ctprobe::pipeline::{Pipeline, PipelineOpts};
use ctprobe::query::QueryEngine;
use ctprobe::registry::{LogKind, LogSpec};
use ctprobe::web;
use futures::StreamExt;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

struct App {
    base: String,
    pipe: Pipeline,
    engine: Arc<QueryEngine>,
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
    app_with(log, Default::default()).await
}

async fn app_with(log: MockLog, dns: ctprobe::config::DnsConfig) -> App {
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
        dns,
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
    let state = web::AppState::new(engine.clone(), pipe.handle.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(web::serve(listener, state));
    App { base, pipe, engine, log, _dir: dir }
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

/// Runs a query on the engine and gives the result as the JSON it serialises to.
async fn sql(a: &App, q: &str) -> serde_json::Value {
    serde_json::to_value(a.engine.sql(q, 1000).await.unwrap()).unwrap()
}

/// Waits until `n` entries are readable, not merely received: commits run on a
/// timer, and a loaded machine can take far longer than any fixed sleep.
async fn wait_rows(a: &App, n: u64) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let v = sql(a, "SELECT COUNT(*) AS n FROM sightings").await;
            if v["rows"][0][0].as_u64().is_some_and(|c| c >= n) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("entries did not become readable");
}

async fn get_json(u: String) -> Value {
    reqwest::get(u).await.unwrap().json().await.unwrap()
}

/// Replaces every scalar by its type name, keeps object keys, and reduces an
/// array to the shape of its first element (`[]` when it is empty).
fn shape(v: &Value) -> Value {
    match v {
        Value::Null => json!("null"),
        Value::Bool(_) => json!("bool"),
        Value::Number(_) => json!("number"),
        Value::String(_) => json!("string"),
        Value::Array(a) => Value::Array(a.first().map(|x| vec![shape(x)]).unwrap_or_default()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), shape(x))).collect()),
    }
}

/// For a field that is inherently variable (null or a number depending on
/// timing): checks that it is one of `allowed` and replaces it, or each of its
/// elements when it is an array, by a sample of the first allowed type, so
/// `shape` sees one fixed value whichever case occurred.
fn variable(v: &mut Value, ptr: &str, allowed: &[&str]) {
    let ty = |x: &Value| match shape(x) {
        Value::String(s) => s,
        _ => "container".to_string(),
    };
    let sample = match allowed[0] {
        "number" => json!(0),
        "string" => json!(""),
        "bool" => json!(false),
        _ => Value::Null,
    };
    let slot = v.pointer_mut(ptr).unwrap_or_else(|| panic!("missing {ptr}"));
    if let Value::Array(a) = slot {
        for x in a.iter() {
            assert!(allowed.contains(&ty(x).as_str()), "{ptr}: {x}");
        }
        *slot = json!([sample]);
    } else {
        assert!(allowed.contains(&ty(slot).as_str()), "{ptr}: {slot}");
        *slot = sample;
    }
}

/// The shape of each element of an array: `shape` keeps only the first, which
/// would leave a row's cells unpinned.
fn cells(row: &Value) -> Value {
    Value::Array(row.as_array().unwrap().iter().map(shape).collect())
}

/// Fetches `path`, asserts the status and `content-type` prefix, and returns the body.
async fn fetch(a: &App, path: &str, status: u16, content_type: &str) -> Value {
    let r = reqwest::get(format!("{}{path}", a.base)).await.unwrap();
    assert_eq!(r.status(), status, "{path}");
    let ct = r.headers()["content-type"].to_str().unwrap().to_string();
    assert!(ct.starts_with(content_type), "{path}: {ct}");
    let text = r.text().await.unwrap();
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}: {text}"))
}

/// A 200 JSON response whose shape is `want`.
async fn ok(a: &App, path: &str, want: Value) {
    let v = fetch(a, path, 200, "application/json").await;
    assert_eq!(shape(&v), want, "{path}: {v}");
}

/// A 200 CSV response: asserts the content type and returns the first line.
async fn csv_header(a: &App, path: &str) -> String {
    let r = reqwest::get(format!("{}{path}", a.base)).await.unwrap();
    assert_eq!(r.status(), 200, "{path}");
    assert_eq!(r.headers()["content-type"], "text/csv; charset=utf-8", "{path}");
    r.text().await.unwrap().lines().next().unwrap().to_string()
}

/// A JSON error response: `{"error": "string"}` with the given status.
async fn err(a: &App, path: &str, status: u16) {
    let v = fetch(a, path, status, "application/json").await;
    assert_eq!(shape(&v), json!({"error": "string"}), "{path}: {v}");
}

fn table() -> Value {
    json!({"columns": ["string"], "rows": [], "truncated": "bool"})
}

fn hit() -> Value {
    json!({"cert_count": "number", "domain": "string", "first_seen_ms": "number", "last_seen_ms": "number", "score": "number"})
}

/// The cells of one certificate row of `/api/certs`, in column order.
fn cert_row() -> Value {
    json!([
        "string",
        "string",
        "string",
        "string",
        "string",
        "string",
        "string",
        "number",
        ["string"],
        "string",
        "number",
        "string",
        "bool",
        "string",
        // days_since_seen is null for a certificate that is new when it is seen.
        "null",
        "number",
        "number",
        "string",
        "number",
        "string",
        "bool"
    ])
}

fn certs_page(from_ms: Value) -> Value {
    json!({
        "columns": ["string"], "count": "number", "count_capped": "bool", "cut_short": "bool",
        "desc": "bool", "from_ms": from_ms, "offset": "number", "rows": [["string"]],
        "sort": "string", "truncated": "bool"
    })
}

/// A 200 `/api/certs` page: the envelope, and every cell of the first row.
async fn certs_ok(a: &App, path: &str, from_ms: &str) {
    let v = fetch(a, path, 200, "application/json").await;
    assert_eq!(shape(&v), certs_page(json!(from_ms)), "{path}: {v}");
    assert_eq!(cells(&v["rows"][0]), cert_row(), "{path}: {v}");
}

async fn app_with_rows(names: &[&str]) -> App {
    let a = app(certs(names), false).await;
    wait_rows(&a, names.len() as u64).await;
    a
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_live() {
    let a = app_with_rows(&["a.example.com", "b.example.com"]).await;
    let mut v = fetch(&a, "/api/live", 200, "application/json").await;
    // Whether the log has published a lag figure yet depends on timing.
    variable(&mut v, "/logs/0/sct_lag_p50_ms", &["number", "null"]);
    assert_eq!(
        shape(&v),
        json!({
            "behind_total": "number", "disk_bytes": "number", "log_count": "number",
            "logs": [{
                "behind": "number", "bytes": "number", "entries": "number", "errors": "number",
                "http_429": "number", "id": "number", "kind": "string", "malformed": "number",
                "name": "string", "per_sec": "number", "position": "number",
                "sct_lag_p50_ms": "number", "state": "string", "tree_size": "number"
            }],
            "names_per_sec": "number", "names_total": "number", "new_domains_per_sec": "number",
            "new_domains_total": "number", "new_names_per_sec": "number", "new_names_total": "number",
            // Null while nothing is paused.
            "paused_reason": "null",
            "raw_per_sec": "number", "raw_total": "number", "renew_exact_total": "number",
            "renew_name_total": "number", "renew_new_total": "number", "rss_bytes": "number",
            "started_at_ms": "number", "tracker_bytes": "number", "tracker_names": "number",
            "ts_ms": "number", "unique_per_sec": "number", "unique_total": "number"
        }),
        "{v}"
    );
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_history() {
    let want = json!({
        // Buckets without data are null, so which are numbers depends on timing.
        "new_domains": ["number"], "new_names": ["number"], "raw": ["number"],
        "unique": ["number"], "step_s": "number", "t": ["number"],
        "totals": {
            "dns_probed": "number", "dns_resolved": "number", "names": "number", "new_domains": "number",
            "new_names": "number", "raw": "number", "seconds": "number", "unique": "number"
        }
    });
    let check = |mut v: Value| {
        for k in ["new_domains", "new_names", "raw", "unique"] {
            variable(&mut v, &format!("/{k}"), &["number", "null"]);
        }
        assert_eq!(shape(&v), want, "{v}");
    };
    let a = app(certs(&["a.example.com"]), true).await;
    check(fetch(&a, "/api/history?minutes=5", 200, "application/json").await);
    a.log.set_tree_size(1);
    wait_rows(&a, 1).await;
    check(fetch(&a, "/api/history?minutes=5", 200, "application/json").await);
    a.pipe.shutdown().await.unwrap();
}

fn log_shape(variable_fields: Value) -> Value {
    let mut l = json!({
        "alone_pct": "number", "behind": "number", "behind_change": "number", "fetched_per_sec": "number",
        "http_failures": "number", "id": "number", "kind": "string", "last_error": "null",
        "last_error_ms": "null", "list_state": "string", "name": "string", "operator": "string",
        "problems": "number", "published_per_sec": "number", "rank": "number", "rate_limited": "number",
        "share_pct": "number", "source": "string", "state": "string", "undecodable": "number",
        "undercounted": "bool", "window_fetched_per_sec": "number"
    });
    l.as_object_mut().unwrap().extend(variable_fields.as_object().unwrap().clone());
    l
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_logs() {
    // Before any data: no coverage figure, and no share or rank for the log.
    let a = app(vec![], true).await;
    let mut v = fetch(&a, "/api/logs", 200, "application/json").await;
    variable(&mut v, "/logs/0/behind", &["number", "null"]);
    let mut empty = log_shape(json!({"delay_p50_ms": "null", "eta_secs": "null"}));
    // The tree size can still be unknown when the first request comes.
    for k in ["alone_pct", "rank", "share_pct"] {
        empty[k] = json!("null");
    }
    let verdict = |eta: &str| {
        json!({
            "backlog": "number", "backlog_change": "number", "bottlenecks": [], "cause_unclear": "bool",
            "ctprobe_limit": "bool", "eta_secs": eta, "fetched_per_sec": "number", "limited_backlog": "number",
            "pipeline_busy_pct": "number", "published_per_sec": "number", "queue_full_pct": "number",
            "seconds": "number", "status": "string"
        })
    };
    assert_eq!(
        shape(&v),
        json!({"coverage": "null", "coverage_target": "number", "logs": [empty], "now_ms": "number", "verdict": verdict("null")}),
        "{v}"
    );
    a.pipe.shutdown().await.unwrap();

    // With enough certificates the coverage figure appears.
    let names: Vec<String> = (0..40).map(|i| format!("h{i}.example.com")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let a = app_with_rows(&refs).await;
    let mut v = tokio::time::timeout(Duration::from_secs(10), async {
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
    // The delay and the time to catch up depend on what has been published so far.
    variable(&mut v, "/logs/0/delay_p50_ms", &["number", "null"]);
    variable(&mut v, "/logs/0/eta_secs", &["number", "null"]);
    variable(&mut v, "/verdict/eta_secs", &["number", "null"]);
    let step = json!({"added_pct": "number", "cumulative_pct": "number", "key": "string"});
    let mut l = log_shape(json!({"delay_p50_ms": "number", "eta_secs": "number"}));
    l["behind"] = json!("number");
    assert_eq!(
        shape(&v),
        json!({
            "coverage": {"computed_ms": "number", "operators": [step], "order": [step], "sampled_certs": "number"},
            "coverage_target": "number", "logs": [l], "now_ms": "number", "verdict": verdict("number")
        }),
        "{v}"
    );
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_schema() {
    let a = app(vec![], true).await;
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn sql_is_not_served() {
    let a = app(vec![], true).await;
    for path in ["/sql", "/api/sql?q=SELECT%201", "/api/schema"] {
        let r = reqwest::get(format!("{}{path}", a.base)).await.unwrap();
        assert_eq!(r.status(), 404, "{path}");
    }
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_search() {
    let a = app_with_rows(&["a.example.com", "b.example.com"]).await;
    for mode in ["exact", "contains", "levenshtein", "homoglyph"] {
        let q = if mode == "contains" { "example" } else { "example.com" };
        let v = fetch(&a, &format!("/api/search?q={q}&mode={mode}"), 200, "application/json").await;
        assert_eq!(shape(&v), json!([hit()]), "{mode}: {v}");
    }
    err(&a, "/api/search?q=example.com&mode=nope", 400).await;
    err(&a, "/api/search?q=", 400).await;
    err(&a, "/api/search?q=%20%20", 400).await;
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_certs() {
    let a = app_with_rows(&["a.example.com", "b.example.com"]).await;
    // A domain or pattern scope has no default time window, so from_ms is null.
    certs_ok(&a, "/api/certs?domain=example.com", "null").await;
    certs_ok(&a, "/api/certs?pattern=%25example.com", "null").await;
    // A filter alone reads the last day.
    certs_ok(&a, "/api/certs?tld=com", "number").await;
    for q in [
        "domain=example.com&pattern=a.com",
        "",
        "domain=example.com&sort=names",
        "domain=example.com&dir=up",
        "domain=example.com&dns=x",
        "domain=example.com&offset=10001",
        "domain=example.com&from=x",
    ] {
        err(&a, &format!("/api/certs?{q}"), 400).await;
    }
    let r = reqwest::get(format!("{}/api/certs?domain=example.com&format=csv", a.base)).await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "text/csv; charset=utf-8");
    let text = r.text().await.unwrap();
    assert_eq!(
        text.lines().next().unwrap(),
        "seen_at,cn,primary_domain,issuer_cn,issuer_org,not_before,not_after,san_count,names,key_type,key_bits,sig_type,is_precert,renewal,days_since_seen,log_id,entry_index,serial,der_size,tld,is_wildcard"
    );
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_domain() {
    let a = app_with_rows(&["a.example.com", "b.example.com"]).await;
    let v = fetch(&a, "/api/domain?d=example.com", 200, "application/json").await;
    assert_eq!(
        shape(&v),
        json!({
            "days": {"columns": ["string"], "rows": [["number"]], "truncated": "bool"},
            // DNS probing is off, so these tables are empty and there is no error.
            "dns_changes": table(), "dns_enabled": "bool", "dns_error": "null", "dns_names": table(),
            "domain": "string", "hit": hit(),
            "issuers": {"columns": ["string"], "rows": [["string"]], "truncated": "bool"},
            "names": {"columns": ["string"], "rows": [["string"]], "truncated": "bool"},
            // No lookalike domain is stored, so the list is empty.
            "similar": []
        }),
        "{v}"
    );
    err(&a, "/api/domain?d=", 400).await;
    err(&a, "/api/domain?d=%20", 400).await;
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_dns() {
    let a = app(vec![], true).await;
    ok(&a, "/api/dns", json!({"enabled": "bool"})).await;
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_cert_dns() {
    let a = app(vec![], true).await;
    let v = fetch(&a, "/api/dns/cert?hash=1&at=0", 200, "application/json").await;
    // With no names asked for, there is no latest-answer table.
    assert_eq!(shape(&v), json!({"enabled": "bool", "latest": "null", "probes": table()}), "{v}");
    err(&a, "/api/dns/cert?hash=x&at=0", 400).await;
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_cert() {
    let a = app_with_rows(&["a.example.com"]).await;
    ok(
        &a,
        "/api/cert/0/0",
        json!({
            "cert_hash": "string", "index": "number", "is_precert": "bool", "log": "string",
            "parsed": {
                "issuer_cn": "string", "issuer_org": "string", "key_bits": "number", "key_type": "string",
                "names": ["string"], "not_after_ms": "number", "not_before_ms": "number", "san_count": "number",
                "serial_hex": "string", "sig_type": "string", "subject_cn": "string"
            },
            "pem": "string", "timestamp_ms": "number"
        }),
    )
    .await;
    err(&a, "/api/cert/7/0", 404).await;
    err(&a, "/api/cert/0/99", 404).await;
    a.pipe.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_trends() {
    let a = app_with_rows(&["a.example.com", "b.example.com"]).await;
    let v = fetch(&a, "/api/trends/issuers", 200, "application/json").await;
    assert_eq!(shape(&v), json!({"columns": ["string"], "rows": [["string"]], "truncated": "bool"}), "{v}");
    assert_eq!(cells(&v["rows"][0]), json!(["string", "number"]), "{v}");
    assert_eq!(csv_header(&a, "/api/trends/issuers?format=csv").await, "k,certs");
    err(&a, "/api/trends/nope", 404).await;
    err(&a, "/api/trends/issuers?bucket=week", 400).await;
    a.pipe.shutdown().await.unwrap();
}

/// Splits an event stream into (event name, data) pairs.
fn sse_events(text: &str) -> Vec<(String, Value)> {
    text.split("\n\n")
        .filter_map(|block| {
            let name = block.lines().find_map(|l| l.strip_prefix("event: "))?;
            let data = block.lines().find_map(|l| l.strip_prefix("data: "))?;
            Some((name.to_string(), serde_json::from_str(data).ok()?))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_stream() {
    let a = app(certs(&["a.example.com"]), true).await;
    let url = format!("{}/api/stream", a.base);
    let log = &a.log;
    let reader = read_sse(&url, 10, |t| t.contains("event: cert") && t.contains("event: snapshot"));
    let release = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        log.set_tree_size(1);
    };
    let (text, _) = tokio::join!(reader, release);
    let events = sse_events(&text);
    let first = |name: &str| {
        events
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d.clone())
            .unwrap_or_else(|| panic!("no {name} event in {text}"))
    };
    // The first snapshot can come before the log's tree size is known.
    let mut snapshot = first("snapshot");
    variable(&mut snapshot, "/behind_total", &["number", "null"]);
    // The stream sends the snapshot without its per-log table.
    assert_eq!(
        shape(&snapshot),
        json!({
            "behind_total": "number", "disk_bytes": "number", "log_count": "number", "logs": [],
            "names_per_sec": "number", "names_total": "number", "new_domains_per_sec": "number",
            "new_domains_total": "number", "new_names_per_sec": "number", "new_names_total": "number",
            "paused_reason": "null", "raw_per_sec": "number", "raw_total": "number",
            "renew_exact_total": "number", "renew_name_total": "number", "renew_new_total": "number",
            "rss_bytes": "number", "started_at_ms": "number", "tracker_bytes": "number",
            "tracker_names": "number", "ts_ms": "number", "unique_per_sec": "number", "unique_total": "number"
        })
    );
    assert_eq!(
        shape(&first("cert")),
        json!({"cn": "string", "index": "number", "issuer_cn": "string", "log": "number", "primary_domain": "string", "renewal": "string", "seen_at_ms": "number"}),
        "{text}"
    );
    for (n, _) in &events {
        assert!(n == "snapshot" || n == "cert", "unexpected event {n}");
    }
    a.pipe.shutdown().await.unwrap();
}
