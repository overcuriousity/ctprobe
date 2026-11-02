use super::{check, Batch, FetchError, LogBackend};
use crate::parse::{decode_tile, EntryKind};
use crate::types::{LogId, RawEntry};
use bytes::Bytes;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const TILE_WIDTH: u64 = 256;
const MAX_BAD_TILE: u32 = 5;

/// `1234067` → `x001/x234/067`.
pub fn tile_path(n: u64) -> String {
    let mut groups = vec![n % 1000];
    let mut rest = n / 1000;
    while rest > 0 {
        groups.push(rest % 1000);
        rest /= 1000;
    }
    let last = groups.len() - 1;
    groups
        .iter()
        .rev()
        .enumerate()
        .map(|(i, g)| if i == last { format!("{g:03}") } else { format!("x{g:03}") })
        .collect::<Vec<_>>()
        .join("/")
}

pub struct TiledBackend {
    log: LogId,
    base: String,
    client: reqwest::Client,
    partial_after: Duration,
    parallel: usize,
    /// Last tree size seen and when it last changed.
    last: Mutex<Option<(u64, Instant)>>,
    /// Consecutive failures of one tile that returned a body but did not decode.
    bad: Mutex<(u64, u32)>,
}

impl TiledBackend {
    pub fn new(
        log: LogId,
        url: &str,
        client: reqwest::Client,
        partial_after: Duration,
        parallel: usize,
    ) -> Self {
        TiledBackend {
            log,
            base: url.trim_end_matches('/').to_string(),
            client,
            partial_after,
            parallel: parallel.max(1),
            last: Mutex::new(None),
            bad: Mutex::new((u64::MAX, 0)),
        }
    }

    /// True if the tree has been still long enough to read a partial tile.
    fn partial_allowed(&self) -> bool {
        self.last.lock().unwrap().is_some_and(|(_, t)| t.elapsed() >= self.partial_after)
    }

    async fn get_tile(&self, n: u64, width: Option<u64>) -> Result<Bytes, FetchError> {
        let mut url = format!("{}/tile/data/{}", self.base, tile_path(n));
        if let Some(w) = width {
            url.push_str(&format!(".p/{w}"));
        }
        let resp = self
            .client
            .get(url)
            .header("accept-encoding", "gzip, identity")
            .send()
            .await?;
        Ok(check(resp)?.bytes().await?)
    }

    /// Appends one tile's entries at or above `start`. A tile that does not
    /// decode to its full width is usually a proxy's error page, so it is retried;
    /// only one that keeps failing is counted malformed, so it cannot wedge a log.
    fn absorb(
        &self,
        b: &mut Batch,
        tile: u64,
        width: u64,
        data: &[u8],
        start: u64,
    ) -> Result<(), FetchError> {
        b.bytes += data.len() as u64;
        let first = tile * TILE_WIDTH;
        let end = first + width;
        let lo = start.max(first);
        match decode_tile(data).ok().filter(|e| e.len() as u64 == width) {
            Some(entries) => {
                *self.bad.lock().unwrap() = (u64::MAX, 0);
                for e in entries {
                    if e.leaf_index < lo {
                        continue;
                    }
                    b.entries.push(RawEntry {
                        log: self.log,
                        index: e.leaf_index,
                        timestamp_ms: e.view.timestamp_ms,
                        is_precert: e.view.kind == EntryKind::Precert,
                        tbs_or_cert: Bytes::copy_from_slice(e.view.body),
                        der_size: e.view.body.len() as u32,
                    });
                }
            }
            None => {
                let mut bad = self.bad.lock().unwrap();
                *bad = if bad.0 == tile { (tile, bad.1 + 1) } else { (tile, 1) };
                if bad.1 < MAX_BAD_TILE {
                    return Err(FetchError::Other(format!("undecodable tile {tile}")));
                }
                b.malformed += end - lo;
            }
        }
        b.next = end;
        Ok(())
    }
}

impl LogBackend for TiledBackend {
    async fn tree_size(&self) -> Result<u64, FetchError> {
        let url = format!("{}/checkpoint", self.base);
        let text = check(self.client.get(url).send().await?)?.text().await?;
        let size: u64 = text
            .lines()
            .nth(1)
            .and_then(|l| l.trim().parse().ok())
            .ok_or_else(|| FetchError::Other("bad checkpoint".into()))?;
        let mut last = self.last.lock().unwrap();
        if last.is_none_or(|(s, _)| s != size) {
            *last = Some((size, Instant::now()));
        }
        Ok(size)
    }

    async fn fetch(&self, start: u64, limit: u64, tree_size: u64) -> Result<Batch, FetchError> {
        let t0 = Instant::now();
        let first = start / TILE_WIDTH;
        let full_tiles = tree_size / TILE_WIDTH;
        let mut b = Batch { log: self.log, next: start, ..Batch::default() };

        if first >= full_tiles {
            if !self.partial_allowed() {
                return Err(FetchError::NotReady);
            }
            let width = tree_size % TILE_WIDTH;
            let data = self.get_tile(first, Some(width)).await?;
            self.absorb(&mut b, first, width, &data, start)?;
            b.busy_ms = t0.elapsed().as_millis() as u64;
            return Ok(b);
        }

        let parallel = if limit < TILE_WIDTH { 1 } else { self.parallel as u64 };
        let last = (first + parallel).min(full_tiles);
        let reqs = (first..last).map(|n| self.get_tile(n, None));
        let results = futures::future::join_all(reqs).await;
        let mut gap = false;
        for (i, r) in results.into_iter().enumerate() {
            match r {
                Ok(_) if gap => {}
                Ok(data) => match self.absorb(&mut b, first + i as u64, TILE_WIDTH, &data, start) {
                    Ok(()) => {}
                    Err(e) if i == 0 => return Err(e),
                    Err(_) => gap = true,
                },
                Err(FetchError::RateLimited(_)) if parallel > 1 => {
                    b.rate_limited += 1;
                    gap = true;
                }
                // Later tiles are retried on the next call; keep what is contiguous.
                Err(_) if i > 0 => gap = true,
                Err(e) => return Err(e),
            }
        }
        b.busy_ms = t0.elapsed().as_millis() as u64;
        Ok(b)
    }
}
