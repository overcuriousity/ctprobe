use chrono::{TimeZone, Utc};
use ctprobe::config::Config;
use ctprobe::positions::{open_db, Positions};
use ctprobe::registry::{merge_specs, parse_log_list, LogKind, LogSpec, Registry};
use std::path::PathBuf;

fn cfg() -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: PathBuf::from("."),
        disk_budget_bytes: 1,
        tracker_max_bytes: 1,
        include_logs: vec![],
        exclude_logs: vec![],
        log_list_url: String::new(),
        extra_log_lists: vec![],
        include_test_logs: false,
        coverage_target: 95.0,
        dns: Default::default(),
    }
}

const LIST: &str = r#"{"operators":[{"name":"op","logs":[
 {"description":"Old","log_id":"AA==","url":"https://old/","state":{"usable":{}},
  "temporal_interval":{"start_inclusive":"2025-01-01T00:00:00Z","end_exclusive":"2026-01-01T00:00:00Z"}},
 {"description":"Now","log_id":"AB==","url":"https://now/","state":{"usable":{}},
  "temporal_interval":{"start_inclusive":"2026-07-01T00:00:00Z","end_exclusive":"2027-01-01T00:00:00Z"}},
 {"description":"Ro","log_id":"AC==","url":"https://ro/","state":{"readonly":{}}},
 {"description":"Dead","log_id":"AD==","url":"https://dead/","state":{"retired":{}}}
],"tiled_logs":[
 {"description":"Tile","log_id":"AE==","submission_url":"https://s/","monitoring_url":"https://m/","state":{"qualified":{}}}
]}]}"#;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 2, 0, 0, 0).unwrap()
}

#[test]
fn selects_usable_and_qualified_in_interval() {
    let got = parse_log_list(LIST.as_bytes(), now(), &cfg(), "g", false).unwrap();
    let names: Vec<_> = got.iter().map(|l| l.name.as_str()).collect();
    assert_eq!(names, ["Now", "Tile"]);
    assert!(matches!(&got[1].kind, LogKind::Tiled { monitoring_url } if monitoring_url == "https://m/"));
    assert!(matches!(&got[0].kind, LogKind::Rfc6962 { url } if url == "https://now/"));
}

#[test]
fn real_log_list_parses() {
    let got = parse_log_list(include_bytes!("fixtures/log_list.json"), now(), &cfg(), "g", false).unwrap();
    assert!(got.iter().any(|l| matches!(l.kind, LogKind::Tiled { .. })));
    assert!(got.iter().any(|l| matches!(l.kind, LogKind::Rfc6962 { .. })));
}

#[test]
fn exclude_list_wins() {
    let mut c = cfg();
    c.include_logs = vec!["Now".into(), "Tile".into()];
    c.exclude_logs = vec!["Tile".into()];
    let got = parse_log_list(LIST.as_bytes(), now(), &c, "g", false).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].name, "Now");
}

fn spec(name: &str, id: &str) -> LogSpec {
    LogSpec {
        name: name.into(),
        log_id_b64: id.into(),
        kind: LogKind::Rfc6962 { url: format!("https://{name}/") },
        state: "usable".into(),
        operator: String::new(),
        source: String::new(),
    }
}

#[test]
fn log_ids_stable_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("state.redb");
    let (a, b);
    {
        let db = open_db(&p).unwrap();
        let r = Registry::open(db).unwrap();
        let added = r.ingest(vec![spec("a", "1"), spec("b", "2")]).unwrap();
        assert_eq!(added.len(), 2);
        a = r.logs().iter().find(|l| l.name == "a").unwrap().id;
        b = r.logs().iter().find(|l| l.name == "b").unwrap().id;
        assert_ne!(a, b);
    }
    let db = open_db(&p).unwrap();
    let r = Registry::open(db).unwrap();
    // New order, new log, one log gone from the list.
    let added = r.ingest(vec![spec("c", "3"), spec("b", "2")]).unwrap();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].name, "c");
    let logs = r.logs();
    assert_eq!(logs.iter().find(|l| l.name == "b").unwrap().id, b);
    let gone = logs.iter().find(|l| l.name == "a").unwrap();
    assert_eq!(gone.id, a);
    assert_eq!(gone.state, "retired");
}

#[test]
fn positions_commit_is_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("state.redb");
    {
        let pos = Positions::new(open_db(&p).unwrap());
        assert_eq!(pos.get(1).unwrap(), None);
        pos.commit(&[(1, 10), (2, 20)]).unwrap();
        pos.commit(&[(1, 11)]).unwrap();
    }
    let pos = Positions::new(open_db(&p).unwrap());
    assert_eq!(pos.get(1).unwrap(), Some(11));
    assert_eq!(pos.get(2).unwrap(), Some(20));
}

#[test]
fn empty_refresh_keeps_following_known_logs() {
    let dir = tempfile::tempdir().unwrap();
    let r = Registry::open(open_db(&dir.path().join("s.redb")).unwrap()).unwrap();
    r.ingest(vec![spec("a", "1")]).unwrap();
    assert!(r.merge_refresh(vec![], &[]).is_err());
    assert_eq!(r.logs()[0].state, "usable");
}

fn sourced(name: &str, id: &str, source: &str) -> LogSpec {
    LogSpec { source: source.into(), ..spec(name, id) }
}

#[test]
fn duplicate_log_id_keeps_primary_entry() {
    let merged = merge_specs(vec![vec![sourced("google", "1", "g")], vec![sourced("apple", "1", "a")]]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].name, "google");
    assert_eq!(merged[0].source, "g");
}

#[test]
fn extra_only_log_is_selected() {
    let merged = merge_specs(vec![vec![sourced("x", "1", "g")], vec![sourced("y", "2", "a")]]);
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[1].source, "a");
}

#[test]
fn failed_source_does_not_retire_its_logs() {
    let dir = tempfile::tempdir().unwrap();
    let r = Registry::open(open_db(&dir.path().join("s.redb")).unwrap()).unwrap();
    r.ingest(vec![sourced("g", "1", "g"), sourced("a", "2", "a")]).unwrap();
    r.ingest_keeping(vec![sourced("g", "1", "g")], &["a".to_string()]).unwrap();
    assert_eq!(r.logs().iter().find(|l| l.name == "a").unwrap().state, "usable");
    r.ingest_keeping(vec![sourced("g", "1", "g")], &[]).unwrap();
    assert_eq!(r.logs().iter().find(|l| l.name == "a").unwrap().state, "retired");
}

#[test]
fn old_stored_log_records_load() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_db(&dir.path().join("s.redb")).unwrap();
    let t: redb::TableDefinition<u16, &str> = redb::TableDefinition::new("logs");
    let tx = db.begin_write().unwrap();
    {
        let mut table = tx.open_table(t).unwrap();
        let old = r#"{"id":7,"name":"old","log_id_b64":"AA==","kind":{"Rfc6962":{"url":"https://o/"}},"state":"usable"}"#;
        table.insert(7, old).unwrap();
    }
    tx.commit().unwrap();
    let r = Registry::open(db).unwrap();
    let l = &r.logs()[0];
    assert_eq!((l.id, l.operator.as_str(), l.source.as_str()), (7, "", ""));
}

#[test]
fn refresh_fills_in_operator_and_source() {
    let dir = tempfile::tempdir().unwrap();
    let r = Registry::open(open_db(&dir.path().join("s.redb")).unwrap()).unwrap();
    r.ingest(vec![spec("a", "1")]).unwrap();
    r.ingest(vec![LogSpec { operator: "Op".into(), ..sourced("a", "1", "g") }]).unwrap();
    assert_eq!((r.logs()[0].operator.as_str(), r.logs()[0].source.as_str()), ("Op", "g"));
}

const WIDE: &str = r#"{"operators":[{"name":"Cloudflare","logs":[
 {"description":"Rejected","log_id":"BA==","url":"https://r/","state":{"rejected":{}}},
 {"description":"Fine","log_id":"BB==","url":"https://f/","state":{"usable":{}}},
 {"description":"Stateless","log_id":"BC==","url":"https://t/"}
],"tiled_logs":[
 {"description":"Raio2027h1a","log_id":"BD==","submission_url":"https://s/","monitoring_url":"https://m/","state":{"usable":{}}}
]}]}"#;

#[test]
fn test_logs_only_when_asked() {
    let names = |test| -> Vec<String> {
        parse_log_list(WIDE.as_bytes(), now(), &cfg(), "g", test).unwrap().into_iter().map(|l| l.name).collect()
    };
    assert_eq!(names(false), ["Fine", "Raio2027h1a"]);
    assert_eq!(names(true), ["Stateless"]);
    let got = parse_log_list(WIDE.as_bytes(), now(), &cfg(), "g", true).unwrap();
    assert_eq!(got[0].state, "test");
}

#[test]
fn raio_style_tiled_entry_parses() {
    let got = parse_log_list(WIDE.as_bytes(), now(), &cfg(), "apple", false).unwrap();
    let raio = got.iter().find(|l| l.name == "Raio2027h1a").unwrap();
    assert!(matches!(&raio.kind, LogKind::Tiled { monitoring_url } if monitoring_url == "https://m/"));
    assert_eq!((raio.operator.as_str(), raio.source.as_str()), ("Cloudflare", "apple"));
}
