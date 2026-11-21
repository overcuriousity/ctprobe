//! The certificate feed: every certificate with a name ctprobe had not seen,
//! in the order ctprobe stored them, from a position a client keeps.
//!
//! A page walks forward in short time windows, one day directory at a time,
//! and stops once it is full. A window reads only the files of its day and,
//! through the `seen_at` statistics, only the parts it overlaps, so a page
//! costs about one window however far behind the client is.

use super::sql::MS_PER_DAY;
use super::{QueryEngine, QueryError};
use crate::store::{certs_schema, list_parts, register_files, session};
use arrow::array::{Array, AsArray, ListArray, RecordBatch};
use arrow::compute::cast;
use arrow::datatypes::{DataType, Field, Int32Type, Int64Type, UInt64Type};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Certificate time the first query of a page covers within a day of parts.
/// It doubles after each window that does not fill the page, so a quiet
/// stretch costs a few queries, not one per window.
const WINDOW_MS: i64 = 15 * 60 * 1000;
/// A page that is not full by then ends early with `more`, well inside the
/// request timeout.
const PAGE_BUDGET: Duration = Duration::from_secs(10);
/// Memory one feed query may use before it spills.
const MEMORY: usize = 512 << 20;
const PARTITIONS: usize = 2;

/// A position in the feed: after every certificate up to this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeedCursor {
    pub seen_at_ms: i64,
    pub log_id: i32,
    pub entry_index: i64,
}

impl FeedCursor {
    /// After every certificate seen at or before `ms`.
    pub fn end_of(ms: i64) -> FeedCursor {
        FeedCursor { seen_at_ms: ms, log_id: i32::MAX, entry_index: i64::MAX }
    }

    /// `<seen_at_ms>.<log_id>.<entry_index>`.
    pub fn parse(s: &str) -> Option<FeedCursor> {
        let mut it = s.trim().split('.');
        let c = FeedCursor {
            seen_at_ms: it.next()?.parse().ok()?,
            log_id: it.next()?.parse().ok()?,
            entry_index: it.next()?.parse().ok()?,
        };
        (it.next().is_none() && c.seen_at_ms >= 0).then_some(c)
    }

    /// The day of the first certificate that can come after this position.
    /// The end of a day's last millisecond belongs to the next day.
    fn day(&self) -> i64 {
        let at_end = self.log_id == i32::MAX && self.entry_index == i64::MAX;
        (self.seen_at_ms + i64::from(at_end)).div_euclid(MS_PER_DAY)
    }
}

impl std::fmt::Display for FeedCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.seen_at_ms, self.log_id, self.entry_index)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FeedRow {
    pub seen_at: i64,
    pub log_id: i32,
    pub entry_index: i64,
    pub issuer_cn: String,
    pub san_count: i32,
    pub new_names: i32,
    pub names: Vec<String>,
    pub reg_domains: Vec<String>,
    pub new_domains: i32,
    /// The names that were new; `None` for a certificate stored before ctprobe
    /// kept them.
    pub new_name_list: Option<Vec<String>>,
    /// The registered domains that were new; `None` as for `new_name_list`.
    pub new_reg_domains: Option<Vec<String>>,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer_org: String,
    pub renewal: String,
    pub days_since_seen: Option<i32>,
    pub is_wildcard: bool,
    /// 16 lowercase hex digits: a u64 does not survive a JSON number.
    pub cert_hash: String,
}

impl FeedRow {
    fn cursor(&self) -> FeedCursor {
        FeedCursor { seen_at_ms: self.seen_at, log_id: self.log_id, entry_index: self.entry_index }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FeedPage {
    pub rows: Vec<FeedRow>,
    /// Where the next page starts. Past `final_through` when `more` is false,
    /// so a quiet stretch moves the client forward too.
    pub next_cursor: String,
    /// More certificates up to `final_through` are waiting: ask again at once.
    pub more: bool,
    pub final_through: i64,
}

impl QueryEngine {
    /// Up to `limit` feed rows after `after` and at or before `final_through`.
    pub async fn feed(&self, after: FeedCursor, limit: usize, final_through: i64) -> Result<FeedPage, QueryError> {
        let data = self.data.clone();
        let timeout = self.timeout;
        let task = self.rt.spawn(async move {
            tokio::time::timeout(timeout, page(&data, after, limit, final_through))
                .await
                .map_err(|_| QueryError::Timeout)?
        });
        task.await.map_err(|e| QueryError::Failed(e.to_string()))?
    }
}

async fn page(data: &Path, after: FeedCursor, limit: usize, final_through: i64) -> Result<FeedPage, QueryError> {
    let end = FeedCursor::end_of(final_through);
    let started = Instant::now();
    let mut rows: Vec<FeedRow> = Vec::new();
    let days = by_day(data);
    let mut at = after;
    let mut span = WINDOW_MS;
    while at < end && rows.len() < limit {
        if started.elapsed() >= PAGE_BUDGET {
            break;
        }
        // The first day at or after the cursor that holds files.
        let Some((&day, files)) = days.range(at.day()..).next() else {
            at = end;
            break;
        };
        if day > at.day() {
            at = FeedCursor::end_of(day * MS_PER_DAY - 1).min(end);
            continue;
        }
        let day_end = (day + 1) * MS_PER_DAY - 1;
        // A compacted day is sorted by domain, so a window would read it
        // whole anyway: take the rest of the day at once.
        let compacted = files.iter().any(|p| p.ends_with("daily.parquet"));
        let hi = if compacted { day_end } else { at.seen_at_ms.saturating_add(span).min(day_end) };
        let hi = hi.min(final_through);
        rows.extend(window(data, files, at, hi, limit - rows.len()).await?);
        span = span.saturating_mul(2).min(MS_PER_DAY);
        at = match rows.last() {
            Some(r) if rows.len() >= limit => r.cursor(),
            _ => FeedCursor::end_of(hi),
        };
    }
    let more = at < end;
    Ok(FeedPage { rows, next_cursor: at.to_string(), more, final_through })
}

/// The `certs` files readers use, by day since the epoch.
fn by_day(data: &Path) -> BTreeMap<i64, Vec<PathBuf>> {
    let mut out: BTreeMap<i64, Vec<PathBuf>> = BTreeMap::new();
    for p in list_parts(data, "certs") {
        let day = p
            .parent()
            .and_then(|d| d.file_name())
            .and_then(|d| d.to_str()?.strip_prefix("day=").map(str::to_string))
            .and_then(|d| chrono::NaiveDate::parse_from_str(&d, "%Y-%m-%d").ok())
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|d| d.and_utc().timestamp_millis().div_euclid(MS_PER_DAY));
        if let Some(day) = day {
            out.entry(day).or_default().push(p);
        }
    }
    out
}

async fn window(
    data: &Path,
    files: &[PathBuf],
    after: FeedCursor,
    hi: i64,
    limit: usize,
) -> Result<Vec<FeedRow>, QueryError> {
    let ctx = session(data, MEMORY, PARTITIONS)?;
    register_files(&ctx, "certs", certs_schema(), files).await?;
    let FeedCursor { seen_at_ms: t, log_id: l, entry_index: i } = after;
    // Bare comparisons on `seen_at` so the Parquet statistics prune parts.
    let sql = format!(
        "SELECT CAST(seen_at AS BIGINT) AS seen_ms, log_id, entry_index, issuer_cn, san_count, new_names, names, \
                reg_domains, new_domains, new_name_list, new_reg_domains, \
                CAST(not_before AS BIGINT) AS not_before_ms, CAST(not_after AS BIGINT) AS not_after_ms, \
                issuer_org, renewal, days_since_seen, is_wildcard, cert_hash \
         FROM certs \
         WHERE new_names > 0 \
           AND seen_at <= to_timestamp_millis({hi}) \
           AND (seen_at > to_timestamp_millis({t}) \
                OR (seen_at = to_timestamp_millis({t}) \
                    AND (log_id > {l} OR (log_id = {l} AND entry_index > {i})))) \
         ORDER BY seen_at, log_id, entry_index \
         LIMIT {limit}"
    );
    let batches = ctx.sql(&sql).await?.collect().await?;
    let mut out = Vec::with_capacity(batches.iter().map(RecordBatch::num_rows).sum());
    for b in &batches {
        rows_of(b, &mut out)?;
    }
    Ok(out)
}

fn rows_of(b: &RecordBatch, out: &mut Vec<FeedRow>) -> Result<(), QueryError> {
    let col = |i: usize, t: &DataType| cast(b.column(i), t).map_err(|e| QueryError::Failed(e.to_string()));
    let list_type = DataType::List(Arc::new(Field::new_list_field(DataType::Utf8, true)));
    let seen = col(0, &DataType::Int64)?;
    let log = col(1, &DataType::Int32)?;
    let index = col(2, &DataType::Int64)?;
    let issuer = col(3, &DataType::Utf8)?;
    let sans = col(4, &DataType::Int32)?;
    let new = col(5, &DataType::Int32)?;
    let names = col(6, &list_type)?;
    let regs = col(7, &list_type)?;
    let new_domains = col(8, &DataType::Int32)?;
    let new_list = col(9, &list_type)?;
    let new_regs = col(10, &list_type)?;
    let not_before = col(11, &DataType::Int64)?;
    let not_after = col(12, &DataType::Int64)?;
    let org = col(13, &DataType::Utf8)?;
    let renewal = col(14, &DataType::Utf8)?;
    let since = col(15, &DataType::Int32)?;
    let wildcard = col(16, &DataType::Boolean)?;
    let hash = col(17, &DataType::UInt64)?;
    let (seen, log, index) =
        (seen.as_primitive::<Int64Type>(), log.as_primitive::<Int32Type>(), index.as_primitive::<Int64Type>());
    let (sans, new, issuer) =
        (sans.as_primitive::<Int32Type>(), new.as_primitive::<Int32Type>(), issuer.as_string::<i32>());
    let (names, regs, new_list, new_regs) =
        (names.as_list::<i32>(), regs.as_list::<i32>(), new_list.as_list::<i32>(), new_regs.as_list::<i32>());
    let (new_domains, not_before, not_after) = (
        new_domains.as_primitive::<Int32Type>(),
        not_before.as_primitive::<Int64Type>(),
        not_after.as_primitive::<Int64Type>(),
    );
    let (org, renewal, since, wildcard, hash) = (
        org.as_string::<i32>(),
        renewal.as_string::<i32>(),
        since.as_primitive::<Int32Type>(),
        wildcard.as_boolean(),
        hash.as_primitive::<UInt64Type>(),
    );
    for r in 0..b.num_rows() {
        out.push(FeedRow {
            seen_at: seen.value(r),
            log_id: log.value(r),
            entry_index: index.value(r),
            issuer_cn: issuer.value(r).to_string(),
            san_count: sans.value(r),
            new_names: new.value(r),
            names: strings(names, r).unwrap_or_default(),
            reg_domains: strings(regs, r).unwrap_or_default(),
            new_domains: new_domains.value(r),
            new_name_list: strings(new_list, r),
            new_reg_domains: strings(new_regs, r),
            not_before: not_before.value(r),
            not_after: not_after.value(r),
            issuer_org: org.value(r).to_string(),
            renewal: renewal.value(r).to_string(),
            days_since_seen: since.is_valid(r).then(|| since.value(r)),
            is_wildcard: wildcard.value(r),
            cert_hash: format!("{:016x}", hash.value(r)),
        });
    }
    Ok(())
}

/// The strings of list `r`, or `None` when the list itself is null.
fn strings(l: &ListArray, r: usize) -> Option<Vec<String>> {
    if l.is_null(r) {
        return None;
    }
    let v = l.value(r);
    let v = v.as_string::<i32>();
    Some((0..v.len()).filter(|&j| v.is_valid(j)).map(|j| v.value(j).to_string()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trips() {
        let c = FeedCursor { seen_at_ms: 1_763_600_000_123, log_id: 7, entry_index: 42 };
        assert_eq!(FeedCursor::parse(&c.to_string()), Some(c));
        assert_eq!(FeedCursor::parse(" 5.1.2 "), Some(FeedCursor { seen_at_ms: 5, log_id: 1, entry_index: 2 }));
    }

    #[test]
    fn cursor_rejects_malformed() {
        for s in ["", "5", "5.1", "5.1.2.3", "a.1.2", "-1.0.0", "5.1.x"] {
            assert_eq!(FeedCursor::parse(s), None, "{s:?}");
        }
    }

    #[test]
    fn the_end_of_a_day_belongs_to_the_next_day() {
        let last = MS_PER_DAY - 1;
        assert_eq!(FeedCursor::end_of(last).day(), 1);
        assert_eq!(FeedCursor { seen_at_ms: last, log_id: 3, entry_index: 9 }.day(), 0);
        assert_eq!(FeedCursor::end_of(last - 1).day(), 0);
        assert_eq!(FeedCursor::end_of(MS_PER_DAY * 5).day(), 5);
    }

    #[test]
    fn end_of_sorts_after_every_entry_at_that_time() {
        let e = FeedCursor::end_of(10);
        assert!(FeedCursor { seen_at_ms: 10, log_id: i32::MAX, entry_index: i64::MAX - 1 } < e);
        assert!(e < FeedCursor { seen_at_ms: 11, log_id: 0, entry_index: 0 });
        assert_eq!(FeedCursor::parse(&e.to_string()), Some(e));
    }
}
