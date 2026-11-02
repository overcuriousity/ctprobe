//! Per-log fetch loop and the two backends.

mod rfc6962;
mod tiled;

pub use rfc6962::Rfc6962Backend;
pub use tiled::{tile_path, TiledBackend};

use crate::registry::{LogInfo, LogKind};
use crate::types::{LogId, RawEntry};
use std::future::Future;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Entries from one or more contiguous requests. `next` is the index after the
/// last entry examined; malformed entries are absent but counted in `malformed`.
#[derive(Debug, Default)]
pub struct Batch {
    pub log: LogId,
    pub entries: Vec<RawEntry>,
    pub next: u64,
    pub malformed: u64,
    pub bytes: u64,
    pub busy_ms: u64,
    /// Requests refused with 429 while fetching this batch.
    pub rate_limited: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("rate limited")]
    RateLimited(Option<Duration>),
    #[error("not ready")]
    NotReady,
    #[error("{0}")]
    Other(String),
}

impl From<reqwest::Error> for FetchError {
    fn from(e: reqwest::Error) -> Self {
        FetchError::Other(e.to_string())
    }
}

/// Maps an HTTP status onto a `FetchError`, returning the response if it is OK.
pub(crate) fn check(resp: reqwest::Response) -> Result<reqwest::Response, FetchError> {
    let s = resp.status();
    if s.is_success() {
        return Ok(resp);
    }
    if s.as_u16() == 429 {
        let after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| parse_retry_after(v, chrono::Utc::now()));
        return Err(FetchError::RateLimited(after));
    }
    if s.as_u16() == 404 {
        return Err(FetchError::NotReady);
    }
    Err(FetchError::Other(format!("HTTP {s}")))
}

pub trait LogBackend: Send + Sync {
    fn tree_size(&self) -> impl Future<Output = Result<u64, FetchError>> + Send;
    /// Fetches entries from `start`, at most `limit`, below `tree_size`.
    fn fetch(
        &self,
        start: u64,
        limit: u64,
        tree_size: u64,
    ) -> impl Future<Output = Result<Batch, FetchError>> + Send;
}

#[derive(Debug, Default)]
pub struct LogStats {
    pub entries: AtomicU64,
    pub bytes: AtomicU64,
    pub errors: AtomicU64,
    pub malformed: AtomicU64,
    pub http_429: AtomicU64,
    pub busy_ms: AtomicU64,
    pub tree_size: AtomicU64,
    pub position: AtomicU64,
    /// Where a log with no stored position began following.
    pub head_start: AtomicU64,
    /// When the log last answered a tree head request, even with a 429. 0 if never.
    pub last_contact_ms: AtomicI64,
    /// When the tree size was first read or last changed. 0 if never read.
    pub tree_changed_ms: AtomicI64,
    pub last_delivery_ms: AtomicI64,
    /// Start of the current run of failed data requests. 0 if none.
    pub data_fail_since_ms: AtomicI64,
    pub last_error: Mutex<Option<(i64, String)>>,
}

impl LogStats {
    fn note_error(&self, text: impl ToString) {
        *self.last_error.lock().unwrap() = Some((now_ms(), text.to_string()));
    }

    fn note_data_failure(&self) {
        let _ = self.data_fail_since_ms.compare_exchange(0, now_ms(), Ordering::Relaxed, Ordering::Relaxed);
    }

    fn note_contact(&self) {
        self.last_contact_ms.store(now_ms(), Ordering::Relaxed);
    }

    fn note_tree(&self, size: u64) {
        let old = self.tree_size.swap(size, Ordering::Relaxed);
        if old != size || self.tree_changed_ms.load(Ordering::Relaxed) == 0 {
            self.tree_changed_ms.store(now_ms(), Ordering::Relaxed);
        }
    }

    fn note_delivery(&self) {
        self.last_delivery_ms.store(now_ms(), Ordering::Relaxed);
        self.data_fail_since_ms.store(0, Ordering::Relaxed);
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Below a tile, so backends send one request at a time.
const CAUTIOUS_LIMIT: u64 = 128;
/// Behind by a full tile, so an empty answer cannot be a tile still filling.
const SURELY_AVAILABLE: u64 = 256;
const PACE_MIN: Duration = Duration::from_millis(200);
const PACE_MAX: Duration = Duration::from_secs(10);

/// Time between requests after a 429. Doubles on each refusal and decays on
/// success, so a log settles just under the rate it accepts from this client.
#[derive(Default)]
struct Pace(Duration);

impl Pace {
    fn refused(&mut self) {
        self.0 = (self.0 * 2).clamp(PACE_MIN, PACE_MAX);
    }
    fn accepted(&mut self) {
        self.0 = self.0 * 19 / 20;
        if self.0 < Duration::from_millis(20) {
            self.0 = Duration::ZERO;
        }
    }
}

#[derive(Debug, Clone)]
pub struct FetchOpts {
    pub poll: Duration,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    pub partial_after: Duration,
    pub batch: u64,
    pub tile_parallel: usize,
}

impl Default for FetchOpts {
    fn default() -> Self {
        FetchOpts {
            poll: Duration::from_secs(10),
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(300),
            partial_after: Duration::from_secs(30),
            batch: 1024,
            tile_parallel: 4,
        }
    }
}

/// Sleeps unless shutdown arrives. Returns true if shutting down.
async fn pause(d: Duration, stop: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => *stop.borrow(),
        _ = stop.changed() => true,
    }
}

/// Follows one log until shutdown. With no `start`, begins at the current head.
/// The bounded channel provides backpressure: a slow pipeline slows the fetcher.
pub async fn run_fetcher<B: LogBackend>(
    backend: B,
    start: Option<u64>,
    tx: mpsc::Sender<Batch>,
    stats: Arc<LogStats>,
    opts: FetchOpts,
    mut stop: watch::Receiver<bool>,
) {
    let mut pos = start;
    if let Some(p) = pos {
        stats.position.store(p, Ordering::Relaxed);
    }
    let mut backoff = opts.backoff_min;
    let mut pace = Pace::default();
    let mut empty_since: Option<tokio::time::Instant> = None;
    loop {
        if *stop.borrow() {
            return;
        }
        if !pace.0.is_zero() && pause(pace.0, &mut stop).await {
            return;
        }
        let limit = if pace.0.is_zero() { opts.batch } else { CAUTIOUS_LIMIT };
        let step = async {
            let pos = &mut pos;
            let size = match backend.tree_size().await {
                Ok(size) => size,
                Err(e) => {
                    match &e {
                        FetchError::RateLimited(_) => stats.note_contact(),
                        FetchError::NotReady => stats.note_error("no tree head: HTTP 404"),
                        FetchError::Other(_) => {}
                    }
                    return Err(e);
                }
            };
            stats.note_contact();
            stats.note_tree(size);
            let p = match *pos {
                Some(p) => p,
                None => {
                    *pos = Some(size);
                    stats.head_start.store(size, Ordering::Relaxed);
                    stats.position.store(size, Ordering::Relaxed);
                    size
                }
            };
            if p >= size {
                return Err(FetchError::NotReady);
            }
            let got = backend.fetch(p, limit, size).await;
            match &got {
                Err(FetchError::Other(_)) => stats.note_data_failure(),
                Err(FetchError::NotReady) if size - p >= SURELY_AVAILABLE => {
                    let since = *empty_since.get_or_insert_with(tokio::time::Instant::now);
                    if since.elapsed() >= opts.partial_after {
                        stats.note_data_failure();
                        stats.note_error("log does not serve entries below its tree head");
                    }
                }
                // Refusals are rate limiting, not failure, so they end a failing run.
                Err(FetchError::RateLimited(_)) => stats.data_fail_since_ms.store(0, Ordering::Relaxed),
                Ok(_) => empty_since = None,
                _ => {}
            }
            got
        };
        match step.await {
            Ok(batch) => {
                backoff = opts.backoff_min;
                stats.http_429.fetch_add(batch.rate_limited, Ordering::Relaxed);
                if batch.rate_limited > 0 {
                    pace.refused();
                } else {
                    pace.accepted();
                }
                if batch.next == pos.unwrap_or(batch.next) && batch.malformed == 0 {
                    continue; // Refused outright; nothing to deliver.
                }
                pos = Some(batch.next);
                stats.position.store(batch.next, Ordering::Relaxed);
                stats.entries.fetch_add(batch.entries.len() as u64, Ordering::Relaxed);
                stats.malformed.fetch_add(batch.malformed, Ordering::Relaxed);
                stats.bytes.fetch_add(batch.bytes, Ordering::Relaxed);
                stats.note_delivery();
                stats.busy_ms.fetch_add(batch.busy_ms, Ordering::Relaxed);
                tokio::select! {
                    r = tx.send(batch) => if r.is_err() { return },
                    _ = stop.changed() => return,
                }
            }
            Err(FetchError::NotReady) => {
                backoff = opts.backoff_min;
                if pause(opts.poll, &mut stop).await {
                    return;
                }
            }
            Err(FetchError::RateLimited(after)) => {
                stats.http_429.fetch_add(1, Ordering::Relaxed);
                pace.refused();
                let wait = after.unwrap_or(backoff).max(backoff);
                backoff = (backoff * 2).min(opts.backoff_max);
                if pause(wait, &mut stop).await {
                    return;
                }
            }
            Err(FetchError::Other(e)) => {
                tracing::debug!("fetch error: {e}");
                stats.note_error(&e);
                stats.errors.fetch_add(1, Ordering::Relaxed);
                let wait = backoff;
                backoff = (backoff * 2).min(opts.backoff_max);
                if pause(wait, &mut stop).await {
                    return;
                }
            }
        }
    }
}

/// Spawns the right backend for a log.
pub fn spawn_fetcher(
    log: &LogInfo,
    client: reqwest::Client,
    start: Option<u64>,
    tx: mpsc::Sender<Batch>,
    stats: Arc<LogStats>,
    opts: FetchOpts,
    stop: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    match &log.kind {
        LogKind::Rfc6962 { url } => {
            let b = Rfc6962Backend::new(log.id, url, client).with_parallel(opts.tile_parallel);
            tokio::spawn(run_fetcher(b, start, tx, stats, opts, stop))
        }
        LogKind::Tiled { monitoring_url } => {
            let b = TiledBackend::new(
                log.id,
                monitoring_url,
                client,
                opts.partial_after,
                opts.tile_parallel,
            );
            tokio::spawn(run_fetcher(b, start, tx, stats, opts, stop))
        }
    }
}

/// Fetches one entry again, for the certificate detail page.
pub async fn fetch_entry(
    log: &LogInfo,
    client: reqwest::Client,
    index: u64,
) -> Result<RawEntry, FetchError> {
    async fn one<B: LogBackend>(b: B, index: u64) -> Result<RawEntry, FetchError> {
        let size = b.tree_size().await?;
        if index >= size {
            return Err(FetchError::NotReady);
        }
        let batch = b.fetch(index, 1, size).await?;
        batch.entries.into_iter().find(|e| e.index == index).ok_or(FetchError::NotReady)
    }
    match &log.kind {
        LogKind::Rfc6962 { url } => one(Rfc6962Backend::new(log.id, url, client), index).await,
        LogKind::Tiled { monitoring_url } => {
            let b = TiledBackend::new(log.id, monitoring_url, client, Duration::ZERO, 1);
            one(b, index).await
        }
    }
}

/// A `Retry-After` value, in seconds or as a date. Logs use both, and not always
/// the `GMT` spelling of the HTTP date format.
fn parse_retry_after(v: &str, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    if let Ok(secs) = v.trim().parse() {
        return Some(Duration::from_secs(secs));
    }
    let bare = v.trim().trim_end_matches("UTC").trim_end_matches("GMT").trim();
    let at = chrono::NaiveDateTime::parse_from_str(bare, "%a, %d %b %Y %H:%M:%S").ok()?.and_utc();
    Some((at - now).to_std().unwrap_or(Duration::ZERO))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn retry_after_forms() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 11, 2, 15, 26, 0).unwrap();
        let d = |s| parse_retry_after(s, now);
        assert_eq!(d("7"), Some(Duration::from_secs(7)));
        assert_eq!(d("Mon, 02 Nov 2026 15:26:33 UTC"), Some(Duration::from_secs(33)));
        assert_eq!(d("Mon, 02 Nov 2026 15:26:33 GMT"), Some(Duration::from_secs(33)));
        assert_eq!(d("Mon, 02 Nov 2026 15:25:00 GMT"), Some(Duration::ZERO));
        assert_eq!(d("soon"), None);
    }
}
