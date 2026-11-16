//! Address history of a registered domain across both tiers, walked day by
//! day from the newest. A day with an archive file is read from it; a day
//! without one is reduced from the hot rows by the archive's own rule, so a
//! day's rows do not change when it is archived.

use super::days::{columns, objects};
use super::{TierPage, BASE64};
use crate::nightly::archive::DNS_CHANGES_SQL;
use crate::query::sql::{quote, MS_PER_DAY};
use crate::query::{QueryEngine, QueryError};
use crate::store::{archive_dns_schema, day_string, list_archive, list_day};
use base64::Engine;
use serde_json::{Map, Value};
use std::cmp::Reverse;
use std::collections::HashSet;
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

impl QueryEngine {
    /// True when the DNS archive holds a file.
    pub fn has_dns_archive(&self) -> bool {
        !list_archive(&self.data, "dns").is_empty()
    }

    /// One page of address history for `reg_domain`, newest first, after
    /// `after`.
    pub async fn tier_dns(
        &self,
        reg_domain: &str,
        limit: usize,
        after: Option<DnsCursor>,
        deadline: Instant,
    ) -> Result<TierPage, QueryError> {
        let mut left = || deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero());
        self.walk_dns(reg_domain, limit, after, &mut left).await
    }

    /// The walk behind `tier_dns`. `left` gives the time remaining, or `None`
    /// once the deadline has passed.
    async fn walk_dns(
        &self,
        reg: &str,
        limit: usize,
        after: Option<DnsCursor>,
        left: &mut (dyn FnMut() -> Option<Duration> + Send),
    ) -> Result<TierPage, QueryError> {
        let want = limit + 1;
        let mut out: Vec<Value> = Vec::new();
        let mut cut_short = false;
        let t = left().ok_or(QueryError::Timeout)?;
        let (archive, mut days) = self.list_days("dns", "probed_at", None, None, t).await?;
        days.extend(archive.keys().copied());
        days.retain(|d| after.as_ref().is_none_or(|c| *d <= c.day()));
        days.sort_unstable_by(|a, b| b.cmp(a));
        days.dedup();
        'days: for day in days {
            let mut start = after.clone().filter(|c| c.day() == day);
            // A (probed_at, name) pair is one position, whatever else differs.
            let mut seen = HashSet::new();
            loop {
                let Some(t) = left() else {
                    cut_short = true;
                    break 'days;
                };
                let n = want - out.len();
                let got = match archive.get(&day) {
                    Some(files) => self.archive_dns_day(reg, day, files, start.as_ref(), n, t).await,
                    None => self.hot_dns_day(reg, day, start.as_ref(), n, t).await,
                };
                let got = match got {
                    Ok(g) => g,
                    Err(QueryError::Timeout) => {
                        cut_short = true;
                        break 'days;
                    }
                    Err(e) => return Err(e),
                };
                let returned = got.len();
                let last = got.last().map(DnsCursor::of);
                out.extend(got.into_iter().filter(|r| {
                    after.as_ref().is_none_or(|c| rank(r) > c.rank()) && seen.insert(DnsCursor::of(r).encode())
                }));
                if out.len() >= want {
                    break 'days;
                }
                match last {
                    Some(c) if returned >= n => start = Some(c),
                    _ => break,
                }
            }
        }
        if cut_short && out.is_empty() {
            return Err(QueryError::Timeout);
        }
        let more = out.len() > limit || cut_short;
        out.truncate(limit);
        let next_cursor = out.last().filter(|_| more).map(|r| DnsCursor::of(r).encode());
        Ok(TierPage { rows: out, next_cursor, cut_short })
    }

    /// One day from its archive file, outside the limiter. The day is `hot`
    /// while its hot files remain.
    async fn archive_dns_day(
        &self,
        reg: &str,
        day: i64,
        files: &[PathBuf],
        start: Option<&DnsCursor>,
        n: usize,
        t: Duration,
    ) -> Result<Vec<Value>, QueryError> {
        let (lo, hi) = (day * MS_PER_DAY, day * MS_PER_DAY + MS_PER_DAY - 1);
        let mut conds = vec![format!("reg_domain = {}", quote(reg)), format!("CAST(probed_at AS BIGINT) BETWEEN {lo} AND {hi}")];
        conds.extend(start.map(DnsCursor::sql));
        let sql = format!(
            "SELECT {} FROM a WHERE {} ORDER BY {NEWEST} LIMIT {n}",
            columns(archive_dns_schema()),
            conds.join(" AND ")
        );
        let found = objects(self.run_archive(files.to_vec(), archive_dns_schema(), sql, n, t).await?);
        let tier = if list_day(&self.data, "dns", &day_string(lo)).is_empty() { "archive" } else { "hot" };
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
        let (lo, hi) = (day * MS_PER_DAY, day * MS_PER_DAY + MS_PER_DAY - 1);
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
        for s in ["", "garbage", "!!!", "W10", &BASE64.encode("[1]"), &BASE64.encode(r#"[1,2,3]"#), &BASE64.encode(r#"["a",1]"#)] {
            assert_eq!(DnsCursor::decode(s), None, "{s:?}");
        }
    }

    fn probe(at: i64, ip: &str) -> DnsRow {
        let lookup = Lookup { status: Status::Resolved, v4: vec![ip.parse().unwrap()], v6: vec![], cnames: vec![], ttl: None };
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
        let p = e.walk_dns("one.com", 10, None, &mut clock(2)).await.unwrap();
        assert!(p.cut_short);
        assert_eq!(p.rows.len(), 1);
        assert_eq!(p.rows[0]["v4"], serde_json::json!(["2.2.2.2"]));
        let c = DnsCursor::decode(p.next_cursor.as_deref().unwrap()).unwrap();
        let far = Instant::now() + Duration::from_secs(30);
        let rest = e.tier_dns("one.com", 10, Some(c), far).await.unwrap();
        assert!(!rest.cut_short && rest.next_cursor.is_none());
        assert_eq!(rest.rows.len(), 1);
        assert_eq!(rest.rows[0]["v4"], serde_json::json!(["1.1.1.1"]));

        assert!(matches!(e.walk_dns("one.com", 10, None, &mut clock(0)).await, Err(QueryError::Timeout)));
        assert!(matches!(e.walk_dns("one.com", 10, None, &mut clock(1)).await, Err(QueryError::Timeout)));
    }
}
