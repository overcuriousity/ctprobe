//! The walk both tiers share: days newest first, each day read by a fetcher,
//! rows strictly after the request's cursor, one deadline for the whole walk.

use super::TierPage;
use crate::nightly::days_done;
use crate::query::sql::{days_of, MS_PER_DAY};
use crate::query::{DomainHit, QueryEngine, QueryError};
use crate::store::archive_days;
use chrono::NaiveDate;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

/// The first and last millisecond of a day.
pub(super) fn day_bounds(day: i64) -> (i64, i64) {
    (day * MS_PER_DAY, day * MS_PER_DAY + MS_PER_DAY - 1)
}

/// The time remaining, or `None` once the deadline has passed.
pub(super) type Left<'a> = &'a mut (dyn FnMut() -> Option<Duration> + Send);

/// The days a walk may skip, judged by the permanent domain index. The index
/// covers exactly the days with the `domains` marker, so a day without it is
/// always read; a day with it only inside one of `ranges` (inclusive days
/// since the epoch).
#[derive(Clone, Debug, PartialEq)]
pub struct Bound {
    ranges: Vec<(i64, i64)>,
}

impl Bound {
    /// Certificates: from the first to the last day each hit was seen.
    pub fn certs(hits: &[DomainHit]) -> Bound {
        let day = |ms: i64| ms.div_euclid(MS_PER_DAY);
        Bound { ranges: hits.iter().map(|h| (day(h.first_seen_ms), day(h.last_seen_ms))).collect() }
    }

    /// Addresses: from the day the domain was first seen on, since probes can
    /// follow its last certificate by weeks.
    pub fn dns(hit: Option<&DomainHit>) -> Bound {
        Bound { ranges: hit.map(|h| (h.first_seen_ms.div_euclid(MS_PER_DAY), i64::MAX)).into_iter().collect() }
    }

    /// Whether a walk reads `day`; `marked` when the index covers it.
    pub(super) fn allows(&self, day: i64, marked: bool) -> bool {
        !marked || self.ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&day))
    }
}

/// What one query of a day gave: rows in page order, how many rows SQL
/// returned, and where the next query of the day starts. `cut` means the
/// deadline passed while the rows were being completed.
pub(super) struct Got<C> {
    pub(super) rows: Vec<Value>,
    pub(super) returned: usize,
    pub(super) next: Option<C>,
    pub(super) cut: bool,
}

/// What differs between the walks: the cursor, the per-day reads and the
/// tests applied to the rows they return.
pub(super) trait DayFetch: Sync {
    /// Where a page ended.
    type Cursor: Clone + Send + Sync;
    /// Where a day's query starts.
    type Start: Send + Sync;

    fn cursor_of(row: &Value) -> Self::Cursor;
    fn encode(c: &Self::Cursor) -> String;
    fn day(c: &Self::Cursor) -> i64;
    /// A position after every row of `day` and before every row of the day
    /// before it: where a walk cut short after finishing `day` continues.
    fn after_day(day: i64) -> Self::Cursor;
    /// The request's cursor, on its own day.
    fn first(c: Self::Cursor) -> Self::Start;
    /// After the last row a query of the day returned.
    fn resume(c: Self::Cursor) -> Self::Start;
    /// Tests SQL could not make exact: row order against the request's
    /// cursor and anything else the walk filters in Rust.
    fn keep(&self, row: &Value, after: Option<&Self::Cursor>) -> bool;
    /// One query of a day. `files` are its archive files, if it has any.
    fn day_rows(
        &self,
        day: i64,
        files: Option<&[PathBuf]>,
        start: Option<&Self::Start>,
        n: usize,
        t: Duration,
        left: Left<'_>,
    ) -> impl Future<Output = Result<Got<Self::Cursor>, QueryError>> + Send;
}

/// Which days a walk lists: the days of `table` inside `from..=to` that
/// `bound` allows, and nothing when `skip` is set.
pub(super) struct Days<'a> {
    pub(super) table: &'static str,
    pub(super) ts: &'static str,
    pub(super) from: Option<i64>,
    pub(super) to: Option<i64>,
    pub(super) bound: &'a Bound,
    pub(super) skip: bool,
}

/// What a walk learns from the disk before its first query.
#[derive(Default)]
pub(super) struct Listing {
    /// Archive files by the days they hold.
    pub(super) archive: BTreeMap<i64, Vec<PathBuf>>,
    /// Days with hot files inside the range.
    pub(super) hot: Vec<i64>,
    /// Days the domain index covers.
    pub(super) marked: HashSet<i64>,
}

fn epoch_day(d: NaiveDate) -> i64 {
    d.signed_duration_since(NaiveDate::default()).num_days()
}

impl QueryEngine {
    /// Directory listings and footers for a walk of `table`: blocking reads,
    /// kept off the web workers and bounded by `t`.
    pub(super) async fn list_days(
        &self,
        table: &'static str,
        ts: &'static str,
        from: Option<i64>,
        to: Option<i64>,
        t: Duration,
    ) -> Result<Listing, QueryError> {
        let data = self.data.clone();
        let job = self.rt.spawn_blocking(move || Listing {
            archive: archive_days(&data, table, ts),
            hot: days_of(&data, table, from, to),
            marked: days_done(&data, "domains").into_iter().map(epoch_day).collect(),
        });
        tokio::time::timeout(t, job)
            .await
            .map_err(|_| QueryError::Timeout)?
            .map_err(|e| QueryError::Failed(e.to_string()))
    }

    /// One page of `limit` rows after `after`. A day with archive files is
    /// read from them, any other day from the hot tier; that is the
    /// fetcher's business. When the deadline ends the walk, the rows found
    /// come back `cut_short` with a cursor after the last row of the day being
    /// read, or else after the last day read to its end, so that a page with
    /// no rows still makes progress. Only a walk that finished no day and
    /// found no row is `Timeout`.
    pub(super) async fn walk_days<F: DayFetch>(
        &self,
        fetch: &F,
        days: Days<'_>,
        limit: usize,
        after: Option<F::Cursor>,
        left: Left<'_>,
    ) -> Result<TierPage, QueryError> {
        let want = limit + 1;
        let mut out: Vec<Value> = Vec::new();
        let mut cut_short = false;
        let listing = if days.skip {
            Listing::default()
        } else {
            let t = left().ok_or(QueryError::Timeout)?;
            self.list_days(days.table, days.ts, days.from, days.to, t).await?
        };
        let in_range = |d: &i64| {
            days.from.is_none_or(|t| *d >= t.div_euclid(MS_PER_DAY)) && days.to.is_none_or(|t| *d <= t.div_euclid(MS_PER_DAY))
        };
        let mut list: Vec<i64> = listing
            .hot
            .iter()
            .copied()
            .chain(listing.archive.keys().copied().filter(in_range))
            .filter(|d| days.bound.allows(*d, listing.marked.contains(d)))
            .filter(|d| after.as_ref().is_none_or(|c| *d <= F::day(c)))
            .collect();
        list.sort_unstable_by(|a, b| b.cmp(a));
        list.dedup();
        // The day being read, and the oldest day read to its end.
        let (mut current, mut done) = (None, None);
        'days: for day in list {
            current = Some(day);
            let mut start = after.clone().filter(|c| F::day(c) == day).map(F::first);
            let mut seen = HashSet::new();
            loop {
                let Some(t) = left() else {
                    cut_short = true;
                    break 'days;
                };
                let n = want - out.len();
                let files = listing.archive.get(&day).map(Vec::as_slice);
                let got = match fetch.day_rows(day, files, start.as_ref(), n, t, &mut *left).await {
                    Ok(g) => g,
                    Err(QueryError::Timeout) => {
                        cut_short = true;
                        break 'days;
                    }
                    Err(e) => return Err(e),
                };
                out.extend(
                    got.rows
                        .into_iter()
                        .filter(|r| fetch.keep(r, after.as_ref()) && seen.insert(F::encode(&F::cursor_of(r)))),
                );
                if got.cut {
                    cut_short = true;
                    break 'days;
                }
                if out.len() >= want {
                    break 'days;
                }
                match got.next {
                    Some(c) if got.returned >= n => start = Some(F::resume(c)),
                    _ => break,
                }
            }
            done = Some(day);
        }
        let full = out.len() > limit;
        out.truncate(limit);
        let last = out.last().map(F::cursor_of);
        let next = if full || (cut_short && last.as_ref().is_some_and(|c| Some(F::day(c)) == current)) {
            last
        } else if cut_short {
            done.map(F::after_day).or(last)
        } else {
            None
        };
        if cut_short && next.is_none() {
            return Err(QueryError::Timeout);
        }
        Ok(TierPage { rows: out, next_cursor: next.as_ref().map(F::encode), cut_short })
    }
}

/// A fetcher that records the days it is asked to read.
#[cfg(test)]
pub(super) struct Counting<F> {
    pub(super) inner: F,
    pub(super) days: std::sync::Mutex<Vec<i64>>,
}

#[cfg(test)]
impl<F> Counting<F> {
    pub(super) fn new(inner: F) -> Counting<F> {
        Counting { inner, days: Default::default() }
    }

    /// The days read since the last call.
    pub(super) fn take(&self) -> Vec<i64> {
        std::mem::take(&mut *self.days.lock().unwrap())
    }
}

#[cfg(test)]
impl<F: DayFetch> DayFetch for Counting<F> {
    type Cursor = F::Cursor;
    type Start = F::Start;

    fn cursor_of(row: &Value) -> F::Cursor {
        F::cursor_of(row)
    }

    fn encode(c: &F::Cursor) -> String {
        F::encode(c)
    }

    fn day(c: &F::Cursor) -> i64 {
        F::day(c)
    }

    fn after_day(day: i64) -> F::Cursor {
        F::after_day(day)
    }

    fn first(c: F::Cursor) -> F::Start {
        F::first(c)
    }

    fn resume(c: F::Cursor) -> F::Start {
        F::resume(c)
    }

    fn keep(&self, row: &Value, after: Option<&F::Cursor>) -> bool {
        self.inner.keep(row, after)
    }

    async fn day_rows(
        &self,
        day: i64,
        files: Option<&[PathBuf]>,
        start: Option<&F::Start>,
        n: usize,
        t: Duration,
        left: Left<'_>,
    ) -> Result<Got<F::Cursor>, QueryError> {
        self.days.lock().unwrap().push(day);
        self.inner.day_rows(day, files, start, n, t, left).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(first_day: i64, last_day: i64) -> DomainHit {
        DomainHit {
            domain: "one.com".into(),
            score: 1.0,
            first_seen_ms: first_day * MS_PER_DAY + 5,
            last_seen_ms: last_day * MS_PER_DAY + 7,
            cert_count: 1,
        }
    }

    #[test]
    fn unmarked_days_are_always_read() {
        for b in [Bound::certs(&[]), Bound::dns(None), Bound::certs(&[hit(10, 12)]), Bound::dns(Some(&hit(10, 12)))] {
            for day in [0, 9, 11, 13, 20_000] {
                assert!(b.allows(day, false), "{b:?} {day}");
            }
        }
    }

    #[test]
    fn no_hit_reads_only_unmarked_days() {
        for b in [Bound::certs(&[]), Bound::dns(None)] {
            for day in [0, 11, 20_000] {
                assert!(!b.allows(day, true), "{b:?} {day}");
            }
        }
    }

    #[test]
    fn certs_read_each_hit_from_first_to_last_day() {
        let b = Bound::certs(&[hit(10, 12), hit(20, 20)]);
        let read: Vec<i64> = (0..30).filter(|d| b.allows(*d, true)).collect();
        assert_eq!(read, vec![10, 11, 12, 20]);
    }

    #[test]
    fn dns_reads_from_the_first_day_on() {
        let b = Bound::dns(Some(&hit(10, 12)));
        assert!(!b.allows(9, true));
        assert!(b.allows(10, true) && b.allows(13, true) && b.allows(20_000, true));
    }
}
