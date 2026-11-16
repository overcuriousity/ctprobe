//! The walk both tiers share: days newest first, each day read by a fetcher,
//! rows strictly after the request's cursor, one deadline for the whole walk.

use super::TierPage;
use crate::query::sql::{days_of, MS_PER_DAY};
use crate::query::{QueryEngine, QueryError};
use crate::store::archive_days;
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

/// Which days a walk lists: the days of `table` inside `from..=to`, and
/// nothing when `skip` is set.
pub(super) struct Days {
    pub(super) table: &'static str,
    pub(super) ts: &'static str,
    pub(super) from: Option<i64>,
    pub(super) to: Option<i64>,
    pub(super) skip: bool,
}

impl QueryEngine {
    /// The archive's files by day, and the days with hot files, of `table`.
    /// Directory listings and footers: blocking reads, kept off the web
    /// workers and bounded by `t`.
    pub(super) async fn list_days(
        &self,
        table: &'static str,
        ts: &'static str,
        from: Option<i64>,
        to: Option<i64>,
        t: Duration,
    ) -> Result<(BTreeMap<i64, Vec<PathBuf>>, Vec<i64>), QueryError> {
        let data = self.data.clone();
        let job = self.rt.spawn_blocking(move || (archive_days(&data, table, ts), days_of(&data, table, from, to)));
        tokio::time::timeout(t, job)
            .await
            .map_err(|_| QueryError::Timeout)?
            .map_err(|e| QueryError::Failed(e.to_string()))
    }

    /// One page of `limit` rows after `after`. A day with archive files is
    /// read from them, any other day from the hot tier; that is the
    /// fetcher's business. Zero rows at the deadline is `Timeout`; rows in
    /// hand come back `cut_short`.
    pub(super) async fn walk_days<F: DayFetch>(
        &self,
        fetch: &F,
        days: Days,
        limit: usize,
        after: Option<F::Cursor>,
        left: Left<'_>,
    ) -> Result<TierPage, QueryError> {
        let want = limit + 1;
        let mut out: Vec<Value> = Vec::new();
        let mut cut_short = false;
        let (archive, mut list) = if days.skip {
            (BTreeMap::new(), vec![])
        } else {
            let t = left().ok_or(QueryError::Timeout)?;
            self.list_days(days.table, days.ts, days.from, days.to, t).await?
        };
        let in_range = |d: &i64| {
            days.from.is_none_or(|t| *d >= t.div_euclid(MS_PER_DAY)) && days.to.is_none_or(|t| *d <= t.div_euclid(MS_PER_DAY))
        };
        list.extend(archive.keys().copied().filter(in_range));
        list.retain(|d| after.as_ref().is_none_or(|c| *d <= F::day(c)));
        list.sort_unstable_by(|a, b| b.cmp(a));
        list.dedup();
        'days: for day in list {
            let mut start = after.clone().filter(|c| F::day(c) == day).map(F::first);
            let mut seen = HashSet::new();
            loop {
                let Some(t) = left() else {
                    cut_short = true;
                    break 'days;
                };
                let n = want - out.len();
                let files = archive.get(&day).map(Vec::as_slice);
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
        }
        if cut_short && out.is_empty() {
            return Err(QueryError::Timeout);
        }
        let more = out.len() > limit || cut_short;
        out.truncate(limit);
        let next_cursor = out.last().filter(|_| more).map(|r| F::encode(&F::cursor_of(r)));
        Ok(TierPage { rows: out, next_cursor, cut_short })
    }
}
