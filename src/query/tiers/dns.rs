//! Address history of a registered domain across both tiers, walked day by
//! day from the newest. A day with an archive file is read from it; a day
//! without one is reduced from the hot rows by the archive's own rule, so a
//! day's rows do not change when it is archived.

use super::days::{columns, objects};
use super::walk::{day_bounds, Bound, DayFetch, Days, Got, Left};
use super::{TierPage, BASE64};
use crate::nightly::archive::DNS_CHANGES_SQL;
use crate::query::sql::{quote, MS_PER_DAY};
use crate::query::{QueryEngine, QueryError};
use crate::store::{archive_dns_schema, has_archive};
use base64::Engine;
use serde_json::{Map, Value};
use std::cmp::Reverse;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const NEWEST: &str = "CAST(probed_at AS BIGINT) DESC, name ASC, status ASC";

/// The last row of a page.
#[derive(Clone, PartialEq, Debug)]
pub struct DnsCursor {
    pub probed_at_ms: i64,
    pub name: String,
}

impl DnsCursor {
    pub fn encode(&self) -> String {
        BASE64.encode(serde_json::to_vec(&(self.probed_at_ms, &self.name)).unwrap_or_default())
    }

    pub fn decode(s: &str) -> Option<DnsCursor> {
        let (probed_at_ms, name) = serde_json::from_slice(&BASE64.decode(s).ok()?).ok()?;
        Some(DnsCursor { probed_at_ms, name })
    }

    /// A cursor before every row: a page that starts here starts at the newest.
    pub fn start() -> DnsCursor {
        DnsCursor { probed_at_ms: i64::MAX, name: String::new() }
    }

    /// A position after every row of `day` and before every row of the day
    /// before: its last millisecond, before every name.
    fn after_day(day: i64) -> DnsCursor {
        DnsCursor { probed_at_ms: day * MS_PER_DAY - 1, name: String::new() }
    }

    fn of(r: &Value) -> DnsCursor {
        DnsCursor {
            probed_at_ms: r["probed_at"].as_i64().unwrap_or_default(),
            name: r["name"].as_str().unwrap_or_default().to_string(),
        }
    }

    fn rank(&self) -> (Reverse<i64>, &str) {
        (Reverse(self.probed_at_ms), &self.name)
    }

    fn day(&self) -> i64 {
        self.probed_at_ms.div_euclid(MS_PER_DAY)
    }

    /// Rows after this one in page order.
    fn sql(&self) -> String {
        let (t, n) = (self.probed_at_ms, quote(&self.name));
        format!("(CAST(probed_at AS BIGINT) < {t} OR (CAST(probed_at AS BIGINT) = {t} AND name > {n}))")
    }
}

fn rank(r: &Value) -> (Reverse<i64>, &str) {
    (Reverse(r["probed_at"].as_i64().unwrap_or_default()), r["name"].as_str().unwrap_or_default())
}

/// A page row: the day's columns without `reg_domain`, and its tier.
fn row(tier: &str, mut o: Map<String, Value>) -> Value {
    o.remove("reg_domain");
    let mut out = Map::new();
    out.insert("tier".into(), tier.into());
    out.extend(o);
    Value::Object(out)
}

/// The address walk's per-day reads.
struct DnsFetch<'a> {
    engine: &'a QueryEngine,
    reg: &'a str,
}

impl DayFetch for DnsFetch<'_> {
    type Cursor = DnsCursor;
    type Start = DnsCursor;

    fn cursor_of(row: &Value) -> DnsCursor {
        DnsCursor::of(row)
    }

    fn encode(c: &DnsCursor) -> String {
        c.encode()
    }

    fn day(c: &DnsCursor) -> i64 {
        c.day()
    }

    fn after_day(day: i64) -> DnsCursor {
        DnsCursor::after_day(day)
    }

    fn first(c: DnsCursor) -> DnsCursor {
        c
    }

    fn resume(c: DnsCursor) -> DnsCursor {
        c
    }

    fn keep(&self, row: &Value, after: Option<&DnsCursor>) -> bool {
        after.is_none_or(|c| rank(row) > c.rank())
    }

    async fn day_rows(
        &self,
        day: i64,
        files: Option<&[PathBuf]>,
        hot: bool,
        start: Option<&DnsCursor>,
        n: usize,
        t: Duration,
        _left: Left<'_>,
    ) -> Result<Got<DnsCursor>, QueryError> {
        let rows = match files {
            Some(files) => self.engine.archive_dns_day(self.reg, day, files, hot, start, n, t).await?,
            None => self.engine.hot_dns_day(self.reg, day, start, n, t).await?,
        };
        let next = rows.last().map(DnsCursor::of);
        Ok(Got { returned: rows.len(), rows, next, cut: false })
    }
}

impl QueryEngine {
    /// True when the DNS archive holds a file.
    pub fn has_dns_archive(&self) -> bool {
        has_archive(&self.data, "dns")
    }

    /// One page of address history for `reg_domain`, newest first, after
    /// `after`, on the days `bound` allows.
    pub async fn tier_dns(
        &self,
        reg_domain: &str,
        limit: usize,
        after: Option<DnsCursor>,
        bound: &Bound,
        deadline: Instant,
    ) -> Result<TierPage, QueryError> {
        let mut left = || deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero());
        self.walk_dns(&DnsFetch { engine: self, reg: reg_domain }, limit, after, bound, &mut left).await
    }

    /// The walk behind `tier_dns`. `left` gives the time remaining, or `None`
    /// once the deadline has passed.
    async fn walk_dns<F: DayFetch>(
        &self,
        fetch: &F,
        limit: usize,
        after: Option<F::Cursor>,
        bound: &Bound,
        left: Left<'_>,
    ) -> Result<TierPage, QueryError> {
        let days = Days { table: "dns", ts: "probed_at", from: None, to: None, bound, skip: false };
        self.walk_days(fetch, days, limit, after, left).await
    }

    /// One day from its archive file, outside the limiter. The day is `hot`
    /// while its hot files remain, as the walk's listing found.
    #[allow(clippy::too_many_arguments)]
    async fn archive_dns_day(
        &self,
        reg: &str,
        day: i64,
        files: &[PathBuf],
        hot: bool,
        start: Option<&DnsCursor>,
        n: usize,
        t: Duration,
    ) -> Result<Vec<Value>, QueryError> {
        let (lo, hi) = day_bounds(day);
        let mut conds =
            vec![format!("reg_domain = {}", quote(reg)), format!("CAST(probed_at AS BIGINT) BETWEEN {lo} AND {hi}")];
        conds.extend(start.map(DnsCursor::sql));
        let sql = format!(
            "SELECT {} FROM a WHERE {} ORDER BY {NEWEST} LIMIT {n}",
            columns(archive_dns_schema()),
            conds.join(" AND ")
        );
        let found = objects(self.run_archive(files.to_vec(), archive_dns_schema(), sql, n, t).await?);
        let tier = if hot { "hot" } else { "archive" };
        Ok(found.into_iter().map(|o| row(tier, o)).collect())
    }

    /// One day with no archive file: the hot rows of the domain, reduced as
    /// the archive reduces them. The reduction is per name and a name has one
    /// registered domain, so narrowing the input first gives the same rows.
    async fn hot_dns_day(
        &self,
        reg: &str,
        day: i64,
        start: Option<&DnsCursor>,
        n: usize,
        t: Duration,
    ) -> Result<Vec<Value>, QueryError> {
        let (lo, hi) = day_bounds(day);
        let after = start.map(|c| format!(" WHERE {}", c.sql())).unwrap_or_default();
        let sql = format!(
            "WITH t AS (SELECT * FROM dns WHERE reg_domain = {}) SELECT {} FROM ({DNS_CHANGES_SQL}) c{after} ORDER BY {NEWEST} LIMIT {n}",
            quote(reg),
            columns(archive_dns_schema()),
        );
        let found = objects(self.run_within(sql, n, Some(lo), Some(hi), t).await?);
        Ok(found.into_iter().map(|o| row("hot", o)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::outcome::{Lookup, Status};
    use crate::dns::queue::Kind;
    use crate::dns::DnsRow;
    use crate::query::tiers::walk::Counting;
    use crate::store::Writer;

    #[test]
    fn cursor_round_trips() {
        let c = DnsCursor { probed_at_ms: 1_700_000_000_123, name: "o'ne.com".into() };
        let s = c.encode();
        assert!(s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'), "{s}");
        assert_eq!(DnsCursor::decode(&s), Some(c));
    }

    #[test]
    fn cursor_rejects_garbage() {
        for s in [
            "",
            "garbage",
            "!!!",
            "W10",
            &BASE64.encode("[1]"),
            &BASE64.encode(r#"[1,2,3]"#),
            &BASE64.encode(r#"["a",1]"#),
        ] {
            assert_eq!(DnsCursor::decode(s), None, "{s:?}");
        }
    }

    fn probe(at: i64, ip: &str) -> DnsRow {
        let lookup =
            Lookup { status: Status::Resolved, v4: vec![ip.parse().unwrap()], v6: vec![], cnames: vec![], ttl: None };
        DnsRow {
            probed_at_ms: at,
            name: "www.one.com".into(),
            kind: Kind::Name,
            reg_domain: Some("one.com".into()),
            cert_hash: 1,
            cert_seen_at_ms: at,
            attempt: 0,
            renewal: "new",
            lookup,
            latency_ms: 1,
            last_miss_ms: None,
            prev: None,
        }
    }

    /// The start cursor reads like no cursor, and its day arithmetic holds.
    #[tokio::test(flavor = "multi_thread")]
    async fn start_cursor_is_before_every_row() {
        let dir = tempfile::tempdir().unwrap();
        let d = 20_000 * MS_PER_DAY;
        let mut w = Writer::open(dir.path(), 0).unwrap();
        w.push_dns(probe(d + 5, "1.1.1.1"));
        w.push_dns(probe(d + MS_PER_DAY + 5, "2.2.2.2"));
        w.flush(1).unwrap();
        w.publish(1).unwrap();
        let e = QueryEngine::open(dir.path()).unwrap();
        let far = Instant::now() + Duration::from_secs(30);
        let plain = e.tier_dns("one.com", 10, None, &none(), far).await.unwrap();
        let start = DnsCursor::decode(&DnsCursor::start().encode()).unwrap();
        let from_start = e.tier_dns("one.com", 10, Some(start), &none(), far).await.unwrap();
        assert_eq!(plain.rows.len(), 2);
        assert_eq!(plain.rows, from_start.rows);
    }

    fn none() -> Bound {
        Bound::dns(None)
    }

    /// One page of `one.com` on a scripted clock, and the days it read.
    async fn walk(
        e: &QueryEngine,
        after: Option<DnsCursor>,
        bound: &Bound,
        left: Left<'_>,
    ) -> (Result<TierPage, QueryError>, Vec<i64>) {
        let fetch = Counting::new(DnsFetch { engine: e, reg: "one.com" });
        let page = e.walk_dns(&fetch, 10, after, bound, left).await;
        (page, fetch.take())
    }

    /// A clock with time for the first `n` asks and none after.
    fn clock(n: usize) -> impl FnMut() -> Option<Duration> + Send {
        let mut calls = 0;
        move || {
            calls += 1;
            (calls <= n).then_some(Duration::from_secs(30))
        }
    }

    /// The deadline passes after the first day's query (asks: the listing,
    /// then the query): that day's rows come back cut short, and the cursor
    /// reaches the next day. No time for the first query is a timeout.
    #[tokio::test(flavor = "multi_thread")]
    async fn deadline_after_first_day_is_cut_short() {
        let dir = tempfile::tempdir().unwrap();
        let d = 20_000 * MS_PER_DAY;
        let mut w = Writer::open(dir.path(), 0).unwrap();
        w.push_dns(probe(d + 5, "1.1.1.1"));
        w.push_dns(probe(d + MS_PER_DAY + 5, "2.2.2.2"));
        w.flush(1).unwrap();
        w.publish(1).unwrap();
        let e = QueryEngine::open(dir.path()).unwrap();
        let p = walk(&e, None, &none(), &mut clock(2)).await.0.unwrap();
        assert!(p.cut_short);
        assert_eq!(p.rows.len(), 1);
        assert_eq!(p.rows[0]["v4"], serde_json::json!(["2.2.2.2"]));
        let c = DnsCursor::decode(p.next_cursor.as_deref().unwrap()).unwrap();
        let far = Instant::now() + Duration::from_secs(30);
        let rest = e.tier_dns("one.com", 10, Some(c), &none(), far).await.unwrap();
        assert!(!rest.cut_short && rest.next_cursor.is_none());
        assert_eq!(rest.rows.len(), 1);
        assert_eq!(rest.rows[0]["v4"], serde_json::json!(["1.1.1.1"]));

        assert!(matches!(walk(&e, None, &none(), &mut clock(0)).await.0, Err(QueryError::Timeout)));
        assert!(matches!(walk(&e, None, &none(), &mut clock(1)).await.0, Err(QueryError::Timeout)));
    }

    /// Days with probes of other domains only, then one with the domain: an
    /// empty page cut short continues after the last day it finished.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_cut_short_page_without_rows_makes_progress() {
        let dir = tempfile::tempdir().unwrap();
        let d = 20_000;
        let mut w = Writer::open(dir.path(), 0).unwrap();
        w.push_dns(probe(d * MS_PER_DAY + 5, "1.1.1.1"));
        for i in 1..=3 {
            let mut p = probe((d + i) * MS_PER_DAY + 5, "2.2.2.2");
            p.name = "www.other.com".into();
            p.reg_domain = Some("other.com".into());
            w.push_dns(p);
        }
        w.flush(1).unwrap();
        w.publish(1).unwrap();
        let e = QueryEngine::open(dir.path()).unwrap();
        let (p, read) = walk(&e, None, &none(), &mut clock(3)).await;
        let p = p.unwrap();
        assert!(p.rows.is_empty() && p.cut_short);
        assert_eq!(read, vec![d + 3, d + 2]);
        let c = DnsCursor::decode(p.next_cursor.as_deref().unwrap()).unwrap();
        assert_ne!(c, DnsCursor::start());
        let (p, rest) = walk(&e, Some(c), &none(), &mut clock(100)).await;
        let p = p.unwrap();
        assert_eq!(rest, vec![d + 1, d]);
        assert_eq!(p.rows.len(), 1);
        assert!(!p.cut_short && p.next_cursor.is_none());
    }

    /// Days the index covers are read from the domain's first day on; days
    /// before it only when the index does not cover them.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_first_seen_day_bounds_the_walk_from_below() {
        let dir = tempfile::tempdir().unwrap();
        let d = 20_000;
        let mut w = Writer::open(dir.path(), 0).unwrap();
        for i in 0..4 {
            w.push_dns(probe((d + i) * MS_PER_DAY + 5, "1.1.1.1"));
        }
        w.flush(1).unwrap();
        w.publish(1).unwrap();
        std::fs::create_dir_all(dir.path().join("nightly")).unwrap();
        for i in 0..3 {
            let name = crate::store::day_string((d + i) * MS_PER_DAY);
            std::fs::write(dir.path().join("nightly").join(format!("{name}.domains")), b"").unwrap();
        }
        let e = QueryEngine::open(dir.path()).unwrap();
        let hit = crate::query::DomainHit {
            domain: "one.com".into(),
            score: 1.0,
            first_seen_ms: (d + 1) * MS_PER_DAY,
            last_seen_ms: (d + 1) * MS_PER_DAY,
            cert_count: 1,
        };
        let (p, read) = walk(&e, None, &Bound::dns(Some(&hit)), &mut clock(100)).await;
        assert_eq!(read, vec![d + 3, d + 2, d + 1]);
        assert_eq!(p.unwrap().rows.len(), 3);
        let (p, read) = walk(&e, None, &Bound::dns(None), &mut clock(100)).await;
        assert_eq!(read, vec![d + 3], "only the day the index does not cover");
        assert_eq!(p.unwrap().rows.len(), 1);
    }
}
