use super::{check, Batch, FetchError, LogBackend};
use crate::parse::{decode_merkle_leaf, EntryKind};
use crate::types::{LogId, RawEntry};
use base64::Engine;
use bytes::Bytes;
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub struct Rfc6962Backend {
    log: LogId,
    base: String,
    client: reqwest::Client,
    parallel: u64,
    page: AtomicU64,
}

impl Rfc6962Backend {
    pub fn new(log: LogId, url: &str, client: reqwest::Client) -> Self {
        Rfc6962Backend {
            log,
            base: url.trim_end_matches('/').to_string(),
            client,
            parallel: 1,
            page: AtomicU64::new(0),
        }
    }

    /// Allows up to `n` concurrent requests while behind.
    pub fn with_parallel(mut self, n: usize) -> Self {
        self.parallel = n.max(1) as u64;
        self
    }
}

#[derive(Deserialize)]
struct Sth {
    tree_size: u64,
}

#[derive(Deserialize)]
struct Entries {
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    leaf_input: String,
}

struct Range {
    entries: Vec<RawEntry>,
    count: u64,
    malformed: u64,
    bytes: u64,
}

impl Rfc6962Backend {
    /// Fetches `start..=end`, which the log may answer only in part.
    async fn get_range(&self, start: u64, end: u64) -> Result<Range, FetchError> {
        let url = format!("{}/ct/v1/get-entries?start={start}&end={end}", self.base);
        let resp = check(self.client.get(url).send().await?)?;
        let body = resp.bytes().await?;
        let parsed: Entries =
            serde_json::from_slice(&body).map_err(|e| FetchError::Other(e.to_string()))?;
        let mut out = Range {
            entries: Vec::with_capacity(parsed.entries.len()),
            count: parsed.entries.len() as u64,
            malformed: 0,
            bytes: body.len() as u64,
        };
        let b64 = base64::engine::general_purpose::STANDARD;
        for (i, e) in parsed.entries.iter().enumerate() {
            let leaf = b64.decode(&e.leaf_input).ok();
            match leaf.as_deref().and_then(|l| decode_merkle_leaf(l).ok()) {
                Some(v) => out.entries.push(RawEntry {
                    log: self.log,
                    index: start + i as u64,
                    timestamp_ms: v.timestamp_ms,
                    is_precert: v.kind == EntryKind::Precert,
                    tbs_or_cert: Bytes::copy_from_slice(v.body),
                    der_size: v.body.len() as u32,
                }),
                None => out.malformed += 1,
            }
        }
        Ok(out)
    }
}

impl LogBackend for Rfc6962Backend {
    async fn tree_size(&self) -> Result<u64, FetchError> {
        let url = format!("{}/ct/v1/get-sth", self.base);
        let resp = check(self.client.get(url).send().await?)?;
        Ok(resp.json::<Sth>().await?.tree_size)
    }

    async fn fetch(&self, start: u64, limit: u64, tree_size: u64) -> Result<Batch, FetchError> {
        let t0 = Instant::now();
        // Logs cap responses at their own page size, learned from the replies.
        // Until it is known, or when nearly caught up, one request is enough.
        let step = self.page.load(Ordering::Relaxed);
        let behind = tree_size - start;
        let n = if step == 0 || behind <= step || limit < 256 {
            1
        } else {
            (behind.div_ceil(step)).min(self.parallel) as usize
        };
        let span = if n == 1 { limit } else { step };
        let reqs = (0..n as u64).map(|i| {
            let s = start + i * span;
            self.get_range(s, (s + span).min(tree_size) - 1)
        });
        let results = futures::future::join_all(reqs).await;
        let mut b = Batch { log: self.log, next: start, ..Batch::default() };
        let mut gap = false;
        for (i, r) in results.into_iter().enumerate() {
            let want = span.min(tree_size.saturating_sub(b.next));
            match r {
                Ok(_) if gap => {} // After a gap, keep only the count of refusals.
                Ok(range) => {
                    if range.count == 0 {
                        if i == 0 {
                            return Err(FetchError::NotReady);
                        }
                        gap = true;
                        continue;
                    }
                    self.page.fetch_max(range.count.min(limit), Ordering::Relaxed);
                    let short = range.count < want;
                    b.entries.extend(range.entries);
                    b.malformed += range.malformed;
                    b.bytes += range.bytes;
                    b.next += range.count;
                    gap = short; // Later replies would leave a hole.
                }
                Err(FetchError::RateLimited(_)) if n > 1 => {
                    b.rate_limited += 1;
                    gap = true;
                }
                // Later ranges are fetched again next time.
                Err(_) if i > 0 => gap = true,
                Err(e) => return Err(e),
            }
        }
        b.busy_ms = t0.elapsed().as_millis() as u64;
        Ok(b)
    }
}
