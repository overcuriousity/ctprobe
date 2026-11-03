use arrow::array::RecordBatch;
use ctprobe::mocklog::{MockEntry, MockLog, MockOpts, TestCa};
use ctprobe::pipeline::{Pipeline, PipelineOpts};
use ctprobe::config::Config;
use ctprobe::fetch::FetchOpts;
use ctprobe::registry::{LogKind, LogSpec};
use ctprobe::store::list_parts;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::Path;
use std::time::Duration;

fn cfg(dir: &Path) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.to_path_buf(),
        disk_budget_bytes: 1 << 34,
        tracker_max_bytes: 1 << 28,
        include_logs: vec![],
        exclude_logs: vec![],
        log_list_url: String::new(),
        extra_log_lists: vec![],
        include_test_logs: false,
        coverage_target: 95.0,
        dns: Default::default(),
    }
}

fn spec(name: &str, url: String, tiled: bool) -> LogSpec {
    LogSpec {
        name: name.into(),
        log_id_b64: name.into(),
        kind: if tiled { LogKind::Tiled { monitoring_url: url } } else { LogKind::Rfc6962 { url } },
        state: "usable".into(),
        operator: String::new(),
        source: String::new(),
    }
}

fn opts(logs: Vec<LogSpec>, commit: Duration) -> PipelineOpts {
    PipelineOpts {
        logs: Some(logs),
        commit_interval: commit,
        start_at_zero: true,
        fetch: FetchOpts {
            poll: Duration::from_millis(20),
            backoff_min: Duration::from_millis(10),
            backoff_max: Duration::from_millis(50),
            partial_after: Duration::ZERO,
            batch: 256,
            tile_parallel: 4,
        },
        minute: Duration::from_secs(60),
        nightly: false,
        snapshot_every: Duration::from_secs(86400),
        coverage_every: Duration::from_secs(86400),
        dns: Default::default(),
    }
}

fn rows(dir: &Path, table: &str) -> usize {
    list_parts(dir, table)
        .iter()
        .map(|p| {
            let f = std::fs::File::open(p).unwrap();
            let b: Vec<RecordBatch> = ParquetRecordBatchReaderBuilder::try_new(f)
                .unwrap()
                .build()
                .unwrap()
                .map(|b| b.unwrap())
                .collect();
            b.iter().map(|x| x.num_rows()).sum::<usize>()
        })
        .sum()
}

async fn two_logs() -> (MockLog, MockLog) {
    let ca = TestCa::default();
    let names = |i: u64| format!("h{i}.example.com");
    let a: Vec<MockEntry> = (0..200).map(|i| ca.final_cert(i + 1, &[&names(i)])).collect();
    let b: Vec<MockEntry> = (100..300).map(|i| ca.precert(i + 1, &[&names(i)])).collect();
    (
        MockLog::start(MockOpts::rfc6962(0).with_entries(a)).await,
        MockLog::start(MockOpts::tiled(0).with_entries(b)).await,
    )
}

async fn wait_positions(p: &Pipeline, total: u64) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if p.handle.live.snapshot().raw_total >= total {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("entries did not arrive");
}

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_counts() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = two_logs().await;
    let logs = vec![spec("a", a.url(), false), spec("b", b.url(), true)];
    let p = Pipeline::start(cfg(d.path()), opts(logs, Duration::from_secs(600))).await.unwrap();
    wait_positions(&p, 400).await;
    let live = p.handle.live.snapshot();
    assert_eq!(live.unique_total, 300);
    assert_eq!(live.names_total, 300);
    assert_eq!(live.new_names_total, 300);
    assert_eq!(live.new_domains_total, 1);
    p.shutdown().await.unwrap();
    assert_eq!(rows(d.path(), "certs"), 300);
    assert_eq!(rows(d.path(), "sightings"), 400);
    assert!(rows(d.path(), "rollup_minute") >= 3, "per-log and global rows on shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn crash_replay_counts_once() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = two_logs().await;
    let logs = vec![spec("a", a.url(), false), spec("b", b.url(), true)];
    let p = Pipeline::start(cfg(d.path()), opts(logs.clone(), Duration::from_secs(600))).await.unwrap();
    wait_positions(&p, 400).await;
    p.kill().await; // No commit happened.
    assert_eq!(rows(d.path(), "certs"), 0);
    let p = Pipeline::start(cfg(d.path()), opts(logs, Duration::from_secs(600))).await.unwrap();
    wait_positions(&p, 400).await;
    p.shutdown().await.unwrap();
    assert_eq!(rows(d.path(), "certs"), 300);
    assert_eq!(rows(d.path(), "sightings"), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn commit_then_kill_resumes_at_position() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = two_logs().await;
    let logs = vec![spec("a", a.url(), false), spec("b", b.url(), true)];
    let p = Pipeline::start(cfg(d.path()), opts(logs.clone(), Duration::from_millis(100))).await.unwrap();
    wait_positions(&p, 400).await;
    tokio::time::sleep(Duration::from_millis(400)).await; // Let a commit land.
    p.kill().await;
    assert_eq!(rows(d.path(), "certs"), 300);
    let p = Pipeline::start(cfg(d.path()), opts(logs, Duration::from_millis(100))).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(p.handle.live.snapshot().raw_total, 0, "resumed past everything");
    p.shutdown().await.unwrap();
    assert_eq!(rows(d.path(), "certs"), 300);
    assert_eq!(rows(d.path(), "sightings"), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn commit_after_kill_during_flush_window_never_duplicates() {
    // Epoch written but not recorded: everything is replayed exactly once.
    let d = tempfile::tempdir().unwrap();
    let (a, b) = two_logs().await;
    let logs = vec![spec("a", a.url(), false), spec("b", b.url(), true)];
    let p = Pipeline::start(cfg(d.path()), opts(logs.clone(), Duration::from_secs(600))).await.unwrap();
    wait_positions(&p, 400).await;
    p.kill_mid_commit().await;
    let p = Pipeline::start(cfg(d.path()), opts(logs, Duration::from_secs(600))).await.unwrap();
    wait_positions(&p, 400).await;
    p.shutdown().await.unwrap();
    assert_eq!(rows(d.path(), "certs"), 300);
    assert_eq!(rows(d.path(), "sightings"), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_certificate_counted_and_skipped() {
    let d = tempfile::tempdir().unwrap();
    let ca = TestCa::default();
    let mut es = vec![ca.final_cert(1, &["a.example.com"])];
    es.push(MockEntry { precert: false, body: vec![1, 2, 3], timestamp_ms: 1, corrupt: false });
    es.push(ca.final_cert(3, &["b.example.com"]));
    let m = MockLog::start(MockOpts::rfc6962(0).with_entries(es)).await;
    let p = Pipeline::start(cfg(d.path()), opts(vec![spec("a", m.url(), false)], Duration::from_secs(600))).await.unwrap();
    wait_positions(&p, 2).await;
    let s = p.handle.live.snapshot();
    assert_eq!(s.logs[0].malformed, 1);
    p.shutdown().await.unwrap();
    assert_eq!(rows(d.path(), "certs"), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn exhausted_disk_budget_pauses_ingest() {
    let d = tempfile::tempdir().unwrap();
    let ca = TestCa::default();
    let es: Vec<MockEntry> = (0..100).map(|i| ca.final_cert(i + 1, &["a.example.com"])).collect();
    let m = MockLog::start(MockOpts::rfc6962(0).with_entries(es)).await;
    let mut c = cfg(d.path());
    c.disk_budget_bytes = 1;
    let mut o = opts(vec![spec("a", m.url(), false)], Duration::from_millis(50));
    o.minute = Duration::from_millis(50);
    let p = Pipeline::start(c, o).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while p.handle.live.snapshot().paused_reason.is_none() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("should pause");
    let before = p.handle.live.snapshot().raw_total;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(p.handle.live.snapshot().raw_total, before, "no ingest while paused");
    p.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn tracker_snapshot_does_not_need_the_nightly_job() {
    let d = tempfile::tempdir().unwrap();
    let (a, _b) = two_logs().await;
    let mut o = opts(vec![spec("a", a.url(), false)], Duration::from_millis(50));
    o.snapshot_every = Duration::from_millis(100);
    let p = Pipeline::start(cfg(d.path()), o).await.unwrap();
    wait_positions(&p, 200).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    p.shutdown().await.unwrap();
    assert!(d.path().join("tracker/tracker.snap").exists());
}
