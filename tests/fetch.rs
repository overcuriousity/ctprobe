use ctprobe::fetch::{self, tile_path, Batch, FetchOpts, LogBackend, LogStats, Rfc6962Backend, TiledBackend};
use ctprobe::mocklog::{MockLog, MockOpts};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

fn opts() -> FetchOpts {
    FetchOpts {
        poll: Duration::from_millis(20),
        backoff_min: Duration::from_millis(10),
        backoff_max: Duration::from_millis(50),
        partial_after: Duration::ZERO,
        batch: 256,
        tile_parallel: 4,
    }
}

async fn collect<B: LogBackend + 'static>(
    b: B,
    start: Option<u64>,
    want: usize,
    stats: Arc<LogStats>,
) -> Vec<u64> {
    let (tx, mut rx) = mpsc::channel::<Batch>(8);
    let (_stop_tx, stop) = watch::channel(false);
    let task = tokio::spawn(fetch::run_fetcher(b, start, tx, stats, opts(), stop));
    let mut got = Vec::new();
    while got.len() < want {
        let batch = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for entries")
            .expect("fetcher ended");
        got.extend(batch.entries.iter().map(|e| e.index));
    }
    task.abort();
    got
}

#[test]
fn tile_path_encoding() {
    assert_eq!(tile_path(1234067), "x001/x234/067");
    assert_eq!(tile_path(67), "067");
    assert_eq!(tile_path(1000), "x001/000");
    assert_eq!(tile_path(0), "000");
}

#[tokio::test]
async fn rfc6962_short_batches_lose_nothing() {
    let m = MockLog::start(MockOpts { max_batch: 32, ..MockOpts::rfc6962(1000) }).await;
    let got = collect(Rfc6962Backend::new(0, &m.url(), reqwest::Client::new()), Some(0), 1000, Default::default()).await;
    assert_eq!(got, (0..1000).collect::<Vec<u64>>());
}

#[tokio::test]
async fn tiled_follows_to_partial_then_full() {
    let m = MockLog::start(MockOpts::tiled(300)).await;
    let b = TiledBackend::new(0, &m.url(), reqwest::Client::new(), Duration::ZERO, 4);
    let (tx, mut rx) = mpsc::channel::<Batch>(8);
    let (_s, stop) = watch::channel(false);
    let task = tokio::spawn(fetch::run_fetcher(b, Some(0), tx, Default::default(), opts(), stop));
    let mut got = Vec::new();
    while got.len() < 300 {
        let b = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        got.extend(b.entries.iter().map(|e| e.index));
    }
    m.set_tree_size(700);
    while got.len() < 700 {
        let b = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        got.extend(b.entries.iter().map(|e| e.index));
    }
    task.abort();
    assert_eq!(got, (0..700).collect::<Vec<u64>>());
}

#[tokio::test]
async fn tile_404_retries_without_advancing() {
    let m = MockLog::start(MockOpts::tiled(512)).await;
    m.fail_next(2, 404);
    let stats: Arc<LogStats> = Default::default();
    let b = TiledBackend::new(0, &m.url(), reqwest::Client::new(), Duration::ZERO, 1);
    let got = collect(b, Some(0), 512, stats).await;
    assert_eq!(got, (0..512).collect::<Vec<u64>>());
}

#[tokio::test]
async fn http_429_backs_off_and_counts() {
    let m = MockLog::start(MockOpts::rfc6962(100)).await;
    m.fail_next(3, 429);
    let stats: Arc<LogStats> = Default::default();
    let b = Rfc6962Backend::new(0, &m.url(), reqwest::Client::new());
    let got = collect(b, Some(0), 100, stats.clone()).await;
    assert_eq!(got, (0..100).collect::<Vec<u64>>());
    assert_eq!(stats.http_429.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn gzip_tile_is_decoded() {
    let m = MockLog::start(MockOpts { gzip: true, ..MockOpts::tiled(256) }).await;
    let b = TiledBackend::new(0, &m.url(), reqwest::Client::new(), Duration::ZERO, 4);
    let got = collect(b, Some(0), 256, Default::default()).await;
    assert_eq!(got, (0..256).collect::<Vec<u64>>());
}

#[tokio::test]
async fn starts_at_head_when_no_position() {
    let m = MockLog::start(MockOpts::rfc6962(50)).await;
    let (tx, mut rx) = mpsc::channel::<Batch>(8);
    let (_s, stop) = watch::channel(false);
    let b = Rfc6962Backend::new(0, &m.url(), reqwest::Client::new());
    let task = tokio::spawn(fetch::run_fetcher(b, None, tx, Default::default(), opts(), stop));
    tokio::time::sleep(Duration::from_millis(100)).await;
    m.set_tree_size(60);
    let first = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
    task.abort();
    assert_eq!(first.entries[0].index, 50);
}

#[tokio::test]
async fn malformed_leaf_is_counted_and_skipped() {
    let m = MockLog::start(MockOpts::rfc6962(20)).await;
    m.corrupt(5);
    let stats: Arc<LogStats> = Default::default();
    let b = Rfc6962Backend::new(0, &m.url(), reqwest::Client::new());
    let got = collect(b, Some(0), 19, stats.clone()).await;
    assert!(!got.contains(&5));
    assert_eq!(got.len(), 19);
    assert_eq!(stats.malformed.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn rfc6962_parallel_requests_stay_in_order() {
    let m = MockLog::start(MockOpts { max_batch: 32, ..MockOpts::rfc6962(5000) }).await;
    let b = Rfc6962Backend::new(0, &m.url(), reqwest::Client::new()).with_parallel(4);
    let got = collect(b, Some(0), 5000, Default::default()).await;
    assert_eq!(got, (0..5000).collect::<Vec<u64>>());
}

#[tokio::test]
async fn rfc6962_parallel_failure_keeps_contiguous_prefix() {
    let m = MockLog::start(MockOpts { max_batch: 32, ..MockOpts::rfc6962(2000) }).await;
    let b = Rfc6962Backend::new(0, &m.url(), reqwest::Client::new()).with_parallel(4);
    let (tx, mut rx) = mpsc::channel::<Batch>(8);
    let (_s, stop) = watch::channel(false);
    let task = tokio::spawn(fetch::run_fetcher(b, Some(0), tx, Default::default(), opts(), stop));
    let mut got = Vec::new();
    let mut injected = false;
    while got.len() < 2000 {
        let batch = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        got.extend(batch.entries.iter().map(|e| e.index));
        if !injected {
            m.fail_next(2, 500);
            injected = true;
        }
    }
    task.abort();
    assert_eq!(got, (0..2000).collect::<Vec<u64>>());
}

#[tokio::test]
async fn html_tile_is_retried_not_counted_malformed() {
    let m = MockLog::start(MockOpts::tiled(256)).await;
    m.junk_next(2);
    let stats: Arc<LogStats> = Default::default();
    let b = TiledBackend::new(0, &m.url(), reqwest::Client::new(), Duration::ZERO, 1);
    let got = collect(b, Some(0), 256, stats.clone()).await;
    assert_eq!(got, (0..256).collect::<Vec<u64>>());
    assert_eq!(stats.malformed.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn permanently_bad_tile_is_skipped_after_retries() {
    let m = MockLog::start(MockOpts::tiled(512)).await;
    m.junk_next(1000);
    let stats: Arc<LogStats> = Default::default();
    let b = TiledBackend::new(0, &m.url(), reqwest::Client::new(), Duration::ZERO, 1);
    let (tx, mut rx) = mpsc::channel::<Batch>(8);
    let (_s, stop) = watch::channel(false);
    let task = tokio::spawn(fetch::run_fetcher(b, Some(0), tx, stats.clone(), opts(), stop));
    tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
    task.abort();
    assert_eq!(stats.malformed.load(Ordering::Relaxed), 256);
}

#[tokio::test]
async fn rate_limit_inside_a_parallel_batch_is_counted() {
    let m = MockLog::start(MockOpts::tiled(4096)).await;
    let stats: Arc<LogStats> = Default::default();
    let b = TiledBackend::new(0, &m.url(), reqwest::Client::new(), Duration::ZERO, 4);
    m.fail_next(3, 429);
    let got = collect(b, Some(0), 4096, stats.clone()).await;
    assert_eq!(got, (0..4096).collect::<Vec<u64>>());
    assert_eq!(stats.http_429.load(Ordering::Relaxed), 3);
}

/// Runs a fetcher from entry 0 until `until` holds.
async fn watch_stats(b: Rfc6962Backend, stats: Arc<LogStats>, until: impl Fn(&LogStats) -> bool) {
    let (tx, _rx) = mpsc::channel::<Batch>(8);
    let (_s, stop) = watch::channel(false);
    let task = tokio::spawn(fetch::run_fetcher(b, Some(0), tx, stats.clone(), opts(), stop));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !until(&stats) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("condition never held");
    task.abort();
}

#[tokio::test]
async fn failing_data_requests_record_text_and_time() {
    let m = MockLog::start(MockOpts::rfc6962(1000)).await;
    m.fail_data(500);
    let stats: Arc<LogStats> = Default::default();
    let b = Rfc6962Backend::new(0, &m.url(), reqwest::Client::new());
    watch_stats(b, stats.clone(), |s| s.errors.load(Ordering::Relaxed) > 0).await;
    let (at, text) = stats.last_error.lock().unwrap().clone().expect("error text");
    assert!(at > 0);
    assert!(text.contains("500"), "{text}");
    assert!(stats.data_fail_since_ms.load(Ordering::Relaxed) > 0);
    assert!(stats.last_contact_ms.load(Ordering::Relaxed) > 0, "the tree head answered");
}

#[tokio::test]
async fn delivery_clears_a_data_failure() {
    let m = MockLog::start(MockOpts::rfc6962(1000)).await;
    m.fail_data(500);
    let stats: Arc<LogStats> = Default::default();
    let b = Rfc6962Backend::new(0, &m.url(), reqwest::Client::new());
    let (tx, mut rx) = mpsc::channel::<Batch>(8);
    let (_s, stop) = watch::channel(false);
    let task = tokio::spawn(fetch::run_fetcher(b, Some(0), tx, stats.clone(), opts(), stop));
    while stats.data_fail_since_ms.load(Ordering::Relaxed) == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    m.clear_data_failure();
    tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
    task.abort();
    assert_eq!(stats.data_fail_since_ms.load(Ordering::Relaxed), 0);
    assert!(stats.last_delivery_ms.load(Ordering::Relaxed) > 0);
}

#[tokio::test]
async fn rate_limited_tree_head_counts_as_contact() {
    let m = MockLog::start(MockOpts::rfc6962(1000)).await;
    m.fail_next(10_000, 429);
    let stats: Arc<LogStats> = Default::default();
    let b = Rfc6962Backend::new(0, &m.url(), reqwest::Client::new());
    watch_stats(b, stats.clone(), |s| s.http_429.load(Ordering::Relaxed) > 0).await;
    assert!(stats.last_contact_ms.load(Ordering::Relaxed) > 0);
    assert_eq!(stats.data_fail_since_ms.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn failing_tree_head_is_no_contact_and_keeps_its_text() {
    let m = MockLog::start(MockOpts::rfc6962(1000)).await;
    m.fail_next(10_000, 500);
    let stats: Arc<LogStats> = Default::default();
    let b = Rfc6962Backend::new(0, &m.url(), reqwest::Client::new());
    watch_stats(b, stats.clone(), |s| s.errors.load(Ordering::Relaxed) > 0).await;
    assert_eq!(stats.last_contact_ms.load(Ordering::Relaxed), 0);
    assert!(stats.last_error.lock().unwrap().is_some());
}

#[tokio::test]
async fn missing_tree_head_keeps_its_text() {
    let m = MockLog::start(MockOpts::rfc6962(1000)).await;
    m.fail_next(10_000, 404);
    let stats: Arc<LogStats> = Default::default();
    let b = Rfc6962Backend::new(0, &m.url(), reqwest::Client::new());
    watch_stats(b, stats.clone(), |s| s.last_error.lock().unwrap().is_some()).await;
    assert_eq!(stats.last_contact_ms.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn data_404_while_behind_records_an_error_after_partial_wait() {
    let m = MockLog::start(MockOpts::rfc6962(1000)).await;
    m.fail_data(404);
    let stats: Arc<LogStats> = Default::default();
    let b = Rfc6962Backend::new(0, &m.url(), reqwest::Client::new());
    watch_stats(b, stats.clone(), |s| s.data_fail_since_ms.load(Ordering::Relaxed) > 0).await;
    assert!(stats.last_error.lock().unwrap().is_some());
}

#[tokio::test]
async fn tree_change_time_is_recorded() {
    let m = MockLog::start(MockOpts::rfc6962(10)).await;
    let stats: Arc<LogStats> = Default::default();
    let b = Rfc6962Backend::new(0, &m.url(), reqwest::Client::new());
    watch_stats(b, stats.clone(), |s| s.tree_changed_ms.load(Ordering::Relaxed) > 0).await;
}

#[tokio::test]
async fn rate_limit_ends_a_run_of_data_failures() {
    let m = MockLog::start(MockOpts::rfc6962(1000)).await;
    m.fail_data(500);
    let stats: Arc<LogStats> = Default::default();
    let b = Rfc6962Backend::new(0, &m.url(), reqwest::Client::new());
    let (tx, _rx) = mpsc::channel::<Batch>(8);
    let (_s, stop) = watch::channel(false);
    let task = tokio::spawn(fetch::run_fetcher(b, Some(0), tx, stats.clone(), opts(), stop));
    while stats.data_fail_since_ms.load(Ordering::Relaxed) == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    m.fail_data(429);
    tokio::time::timeout(Duration::from_secs(5), async {
        while stats.data_fail_since_ms.load(Ordering::Relaxed) != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("failure run never ended");
    task.abort();
}
