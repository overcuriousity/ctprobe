use super::sql::QueryError;
use super::QueryEngine;
use crate::names;
use crate::store::{list_parts, unpack_domain};
use anyhow::Result;
use arrow::array::AsArray;
use arrow::datatypes::{Int64Type, TimestampMillisecondType};
use fst::automaton::Levenshtein;
use fst::{IntoStreamer, Map, Set, Streamer};
use memmap2::Mmap;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

const MS_PER_DAY: i64 = 86_400_000;
const SCAN_CAP: usize = 100_000;
const CHECK_EVERY: u64 = 1 << 16;

/// Stops long scans at the query deadline.
struct Clock {
    until: Instant,
    seen: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("search timed out")]
struct TimedOut;

impl Clock {
    fn tick(&mut self) -> Result<()> {
        if self.seen % CHECK_EVERY == 0 && Instant::now() >= self.until {
            return Err(TimedOut.into());
        }
        self.seen += 1;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Exact,
    Contains,
    /// Maximum edit distance, 1 or 2.
    Levenshtein(u8),
    Homoglyph,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainHit {
    pub domain: String,
    /// Higher is closer. Exact matches score 1.
    pub score: f64,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub cert_count: u64,
}

pub(super) struct SearchIndex {
    domains: Map<Mmap>,
    skeletons: Set<Mmap>,
    stamp: SystemTime,
}

fn mmap(p: &Path) -> Result<Mmap> {
    // Files are replaced by rename, never modified in place.
    Ok(unsafe { Mmap::map(&std::fs::File::open(p)?)? })
}

fn load(data: &Path) -> Result<Option<SearchIndex>> {
    let dp = data.join("search/domains.fst");
    let sp = data.join("search/skeleton.fst");
    if !dp.exists() || !sp.exists() {
        return Ok(None);
    }
    let stamp = std::fs::metadata(&dp)?.modified()?;
    Ok(Some(SearchIndex { domains: Map::new(mmap(&dp)?)?, skeletons: Set::new(mmap(&sp)?)?, stamp }))
}

/// How a query is compared with a domain.
#[derive(Clone)]
struct Matcher {
    mode: Mode,
    q: String,
    skel: String,
    bare: bool,
}

impl Matcher {
    fn new(q: &str, mode: Mode) -> Matcher {
        let q = names::normalize(q).unwrap_or_else(|| q.trim().to_lowercase());
        Matcher { mode, skel: names::skeleton(&q), bare: !q.contains('.'), q }
    }

    fn label(s: &str) -> &str {
        s.split('.').next().unwrap_or(s)
    }

    /// Damerau distance scaled to a score; Jaro-Winkler breaks ties.
    fn close(a: &str, b: &str, max: usize) -> Option<f64> {
        let d = strsim::damerau_levenshtein(a, b);
        (d <= max).then(|| 1.0 / (1.0 + d as f64) + strsim::jaro_winkler(a, b) / 100.0)
    }

    /// The score of a domain, or `None` if it does not match.
    fn score(&self, domain: &str, skeleton: &str) -> Option<f64> {
        match self.mode {
            Mode::Exact => (domain == self.q).then_some(1.0),
            Mode::Contains => domain.contains(&self.q).then(|| {
                self.q.len() as f64 / domain.len().max(1) as f64
            }),
            Mode::Levenshtein(d) => {
                let target = if self.bare { Self::label(domain) } else { domain };
                Self::close(target, &self.q, d as usize)
            }
            Mode::Homoglyph => {
                let target = if self.bare { Self::label(skeleton) } else { skeleton };
                if target == self.skel {
                    Some(1.0)
                } else {
                    Self::close(target, &self.skel, 1)
                }
            }
        }
    }
}

fn hit(domain: String, score: f64, packed: u64) -> DomainHit {
    let (first, last, count) = unpack_domain(packed);
    DomainHit {
        domain,
        score,
        first_seen_ms: first as i64 * MS_PER_DAY,
        last_seen_ms: last as i64 * MS_PER_DAY,
        cert_count: count as u64,
    }
}

fn from_index(
    ix: &SearchIndex,
    m: &Matcher,
    out: &mut HashMap<String, DomainHit>,
    clock: &mut Clock,
) -> Result<()> {
    let add = |d: &str, skel: &str, v: u64, out: &mut HashMap<String, DomainHit>| {
        if let Some(s) = m.score(d, skel) {
            out.insert(d.to_string(), hit(d.to_string(), s, v));
        }
    };
    match m.mode {
        Mode::Exact => {
            if let Some(v) = ix.domains.get(&m.q) {
                add(&m.q, "", v, out);
            }
        }
        Mode::Levenshtein(d) if !m.bare => {
            let aut = Levenshtein::new(&m.q, d as u32)?;
            let mut s = ix.domains.search(aut).into_stream();
            while let Some((k, v)) = s.next() {
                add(std::str::from_utf8(k)?, "", v, out);
            }
        }
        Mode::Homoglyph if !m.bare => {
            // Candidates share a skeleton, or lie one edit from it.
            let mut lower = m.skel.clone().into_bytes();
            lower.push(0);
            let mut upper = m.skel.clone().into_bytes();
            upper.push(1);
            let mut s = ix.skeletons.range().ge(&lower).lt(&upper).into_stream();
            let mut found: Vec<Vec<u8>> = Vec::new();
            while let Some(k) = s.next() {
                found.push(k.to_vec());
            }
            if found.is_empty() {
                let aut = Levenshtein::new(&m.skel, 1)?;
                let mut s = ix.skeletons.search(fst::Automaton::starts_with(aut)).into_stream();
                while let Some(k) = s.next() {
                    found.push(k.to_vec());
                    if found.len() >= SCAN_CAP {
                        break;
                    }
                }
            }
            for k in found {
                let Some(i) = k.iter().position(|b| *b == 0) else { continue };
                let (skel, domain) = (std::str::from_utf8(&k[..i])?, std::str::from_utf8(&k[i + 1..])?);
                if let Some(v) = ix.domains.get(domain) {
                    add(domain, skel, v, out);
                }
            }
        }
        Mode::Homoglyph => {
            let mut s = ix.skeletons.stream();
            while let Some(k) = s.next() {
                clock.tick()?;
                let Some(i) = k.iter().position(|b| *b == 0) else { continue };
                let (skel, domain) = (std::str::from_utf8(&k[..i])?, std::str::from_utf8(&k[i + 1..])?);
                if m.score(domain, skel).is_some() {
                    if let Some(v) = ix.domains.get(domain) {
                        add(domain, skel, v, out);
                    }
                }
            }
        }
        Mode::Contains | Mode::Levenshtein(_) => {
            let mut s = ix.domains.stream();
            while let Some((k, v)) = s.next() {
                clock.tick()?;
                add(std::str::from_utf8(k)?, "", v, out);
            }
        }
    }
    Ok(())
}

/// Adds domains from delta files, which the FSTs do not cover yet.
fn from_deltas(
    data: &Path,
    m: &Matcher,
    out: &mut HashMap<String, DomainHit>,
    clock: &mut Clock,
) -> Result<()> {
    for f in list_parts(data, "domains") {
        if f.file_name().is_some_and(|n| n.to_string_lossy().starts_with("snapshot-")) {
            continue;
        }
        let r = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(f)?)?.build()?;
        for b in r {
            let b = b?;
            let dom = b.column(0).as_string::<i32>();
            let skel = b.column(1).as_string::<i32>();
            let first = b.column(2).as_primitive::<TimestampMillisecondType>();
            let last = b.column(3).as_primitive::<TimestampMillisecondType>();
            let count = b.column(4).as_primitive::<Int64Type>();
            for i in 0..b.num_rows() {
                clock.tick()?;
                let Some(s) = m.score(dom.value(i), skel.value(i)) else { continue };
                let e = out.entry(dom.value(i).to_string()).or_insert_with(|| DomainHit {
                    domain: dom.value(i).to_string(),
                    score: s,
                    first_seen_ms: first.value(i),
                    last_seen_ms: last.value(i),
                    cert_count: 0,
                });
                e.first_seen_ms = e.first_seen_ms.min(first.value(i));
                e.last_seen_ms = e.last_seen_ms.max(last.value(i));
                e.cert_count += count.value(i) as u64;
            }
        }
    }
    Ok(())
}

impl QueryEngine {
    fn refresh_index(&self) -> Result<()> {
        let path = self.data.join("search/domains.fst");
        let stamp = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        let current = self.index.read().unwrap().as_ref().map(|i| i.stamp);
        if stamp != current {
            *self.index.write().unwrap() = load(&self.data)?;
        }
        Ok(())
    }

    /// Domains matching `q`, best first.
    pub async fn search_domains(
        &self,
        q: &str,
        mode: Mode,
        limit: usize,
    ) -> Result<Vec<DomainHit>, QueryError> {
        let _permit = self.limiter.acquire().await.map_err(|e| QueryError::Failed(e.to_string()))?;
        let m = Matcher::new(q, mode);
        let mut out = HashMap::new();
        let until = Instant::now() + self.timeout;
        let timed = |e: anyhow::Error| match e.is::<TimedOut>() {
            true => QueryError::Timeout,
            false => QueryError::from(e),
        };
        // Scans can take seconds; keep them off the async workers fetchers use.
        tokio::task::block_in_place(|| -> Result<()> {
            self.refresh_index()?;
            if let Some(ix) = self.index.read().unwrap().as_ref() {
                from_index(ix, &m, &mut out, &mut Clock { until, seen: 0 })?;
            }
            Ok(())
        })
        .map_err(timed)?;
        let data = self.data.clone();
        let m2 = m.clone();
        let out = Arc::new(std::sync::Mutex::new(out));
        let o2 = out.clone();
        tokio::task::spawn_blocking(move || {
            from_deltas(&data, &m2, &mut o2.lock().unwrap(), &mut Clock { until, seen: 0 })
        })
        .await
        .map_err(|e| QueryError::Failed(e.to_string()))?
        .map_err(timed)?;
        let out = std::mem::take(&mut *out.lock().unwrap());
        let mut hits: Vec<DomainHit> = out.into_values().collect();
        hits.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.domain.cmp(&b.domain)));
        hits.truncate(limit);
        Ok(hits)
    }
}
