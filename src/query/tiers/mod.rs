//! Certificates across both tiers, one row per (certificate, registered
//! domain), walked day by day from the newest. A day with an archive file is
//! read from it; a day without one is scanned in the hot tier and split there.

mod days;

use super::sql::{days_of, quote, MS_PER_DAY};
use super::{QueryEngine, QueryError};
use crate::store::{archive_days, list_archive};
use base64::Engine;
use days::Start;
use serde::Serialize;
use serde_json::Value;
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
const WILDCARD_RE: &str = r"'(^| )\*\.'";

#[derive(Default, Clone)]
pub struct TierFilter {
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub expires_from_ms: Option<i64>,
    pub expires_to_ms: Option<i64>,
    pub issuer: Option<String>,
    pub issuer_contains: Option<String>,
    pub tld: Option<String>,
    pub wildcard: Option<bool>,
}

/// The last row of a page.
#[derive(Clone, PartialEq, Debug)]
pub struct CertCursor {
    pub seen_at_ms: i64,
    pub log_id: i32,
    pub entry_index: i64,
    pub reg_domain: String,
}

type Rank<'a> = (Reverse<i64>, Reverse<i64>, Reverse<i64>, &'a str);

impl CertCursor {
    pub fn encode(&self) -> String {
        let t = (self.seen_at_ms, self.log_id, self.entry_index, &self.reg_domain);
        BASE64.encode(serde_json::to_vec(&t).unwrap_or_default())
    }

    pub fn decode(s: &str) -> Option<CertCursor> {
        let (seen_at_ms, log_id, entry_index, reg_domain) = serde_json::from_slice(&BASE64.decode(s).ok()?).ok()?;
        Some(CertCursor { seen_at_ms, log_id, entry_index, reg_domain })
    }

    fn of(r: &Value) -> CertCursor {
        let n = |k: &str| r[k].as_i64().unwrap_or_default();
        CertCursor {
            seen_at_ms: n("seen_at"),
            log_id: n("log_id") as i32,
            entry_index: n("entry_index"),
            reg_domain: r["reg_domain"].as_str().unwrap_or_default().to_string(),
        }
    }

    fn rank(&self) -> Rank<'_> {
        (Reverse(self.seen_at_ms), Reverse(self.log_id as i64), Reverse(self.entry_index), &self.reg_domain)
    }

    fn day(&self) -> i64 {
        self.seen_at_ms.div_euclid(MS_PER_DAY)
    }

    /// Rows after this one in page order. `tail` decides rows of the same
    /// certificate.
    fn sql(&self, tail: &str) -> String {
        let (s, l, i) = (self.seen_at_ms, self.log_id, self.entry_index);
        format!(
            "(CAST(seen_at AS BIGINT) < {s} OR (CAST(seen_at AS BIGINT) = {s} AND (log_id < {l} OR \
             (log_id = {l} AND (entry_index < {i} OR (entry_index = {i} AND {tail}))))))"
        )
    }
}

fn rank(r: &Value) -> Rank<'_> {
    let n = |k: &str| Reverse(r[k].as_i64().unwrap_or_default());
    (n("seen_at"), n("log_id"), n("entry_index"), r["reg_domain"].as_str().unwrap_or_default())
}

#[derive(Serialize)]
pub struct TierPage {
    pub rows: Vec<Value>,
    pub next_cursor: Option<String>,
    pub cut_short: bool,
}

/// The request, with the domain list narrowed by `tld`.
struct Scope<'a> {
    domains: Vec<String>,
    exact: Option<(&'a str, String)>,
    f: &'a TierFilter,
}

impl Scope<'_> {
    fn list(&self) -> String {
        self.domains.iter().map(|d| quote(d)).collect::<Vec<_>>().join(", ")
    }

    /// Conditions both tiers can answer. With `per_row`, `names` holds one
    /// domain's names, so the wildcard test is exact.
    fn conditions(&self, day: i64, base: String, per_row: bool) -> Vec<String> {
        let f = self.f;
        let lo = f.from_ms.map_or(day * MS_PER_DAY, |t| t.max(day * MS_PER_DAY));
        let hi = f.to_ms.map_or(day * MS_PER_DAY + MS_PER_DAY - 1, |t| t.min(day * MS_PER_DAY + MS_PER_DAY - 1));
        let mut c = vec![base, format!("CAST(seen_at AS BIGINT) BETWEEN {lo} AND {hi}")];
        if let Some(t) = f.expires_from_ms {
            c.push(format!("CAST(not_after AS BIGINT) >= {t}"));
        }
        if let Some(t) = f.expires_to_ms {
            c.push(format!("CAST(not_after AS BIGINT) <= {t}"));
        }
        if let Some(i) = &f.issuer {
            c.push(format!("issuer_cn = {}", quote(i)));
        }
        if let Some(i) = &f.issuer_contains {
            c.push(format!("strpos(lower(issuer_cn), lower({})) > 0", quote(i)));
        }
        if let Some((name, wild)) = &self.exact {
            c.push(format!("array_has_any(names, make_array({}, {}))", quote(name), quote(wild)));
        }
        match f.wildcard {
            Some(true) => c.push(format!("regexp_like(array_to_string(names, ' '), {WILDCARD_RE})")),
            Some(false) if per_row => c.push(format!("NOT regexp_like(array_to_string(names, ' '), {WILDCARD_RE})")),
            _ => {}
        }
        c
    }

    /// The tests SQL could not make exact for a split hot certificate.
    fn keeps(&self, r: &Value) -> bool {
        let names: Vec<&str> = r["names"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        let exact = self.exact.as_ref().is_none_or(|(n, w)| names.iter().any(|x| x == n || x == w));
        let wild = self.f.wildcard.is_none_or(|w| names.iter().any(|n| n.starts_with("*.")) == w);
        exact && wild
    }
}

impl QueryEngine {
    /// True when either archive directory holds a file.
    pub fn has_archive(&self) -> bool {
        !list_archive(&self.data, "certs").is_empty() || !list_archive(&self.data, "dns").is_empty()
    }

    /// One page of rows for `domains`, newest first, after `after`. With
    /// `exact_name`, only rows listing that name or the wildcard covering it.
    pub async fn tier_certs(
        &self,
        domains: &[String],
        exact_name: Option<&str>,
        f: &TierFilter,
        limit: usize,
        after: Option<CertCursor>,
    ) -> Result<TierPage, QueryError> {
        let deadline = Instant::now() + self.timeout;
        let mut left = || deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero());
        self.walk(domains, exact_name, f, limit, after, &mut left).await
    }

    /// The walk behind `tier_certs`. `left` gives the time remaining, or
    /// `None` once the deadline has passed.
    async fn walk(
        &self,
        domains: &[String],
        exact_name: Option<&str>,
        f: &TierFilter,
        limit: usize,
        after: Option<CertCursor>,
        left: &mut (dyn FnMut() -> Option<Duration> + Send),
    ) -> Result<TierPage, QueryError> {
        let scope = Scope {
            domains: domains
                .iter()
                .filter(|d| f.tld.as_deref().is_none_or(|t| psl::suffix_str(d) == Some(t)))
                .cloned()
                .collect(),
            exact: exact_name.map(|n| (n, format!("*.{}", n.split_once('.').map_or(n, |(_, p)| p)))),
            f,
        };
        let want = limit + 1;
        let mut out: Vec<Value> = Vec::new();
        let mut cut_short = false;
        let archive = if scope.domains.is_empty() { BTreeMap::new() } else { archive_days(&self.data, "certs", "seen_at") };
        let mut days = if scope.domains.is_empty() { vec![] } else { days_of(&self.data, "certs", f.from_ms, f.to_ms) };
        let in_range = |d: &i64| {
            f.from_ms.is_none_or(|t| *d >= t.div_euclid(MS_PER_DAY)) && f.to_ms.is_none_or(|t| *d <= t.div_euclid(MS_PER_DAY))
        };
        days.extend(archive.keys().copied().filter(in_range));
        days.retain(|d| after.as_ref().is_none_or(|c| *d <= c.day()));
        days.sort_unstable_by(|a, b| b.cmp(a));
        days.dedup();
        'days: for day in days {
            let mut start = after.clone().filter(|c| c.day() == day).map(Start::Cursor);
            let mut seen = HashSet::new();
            loop {
                let Some(t) = left() else {
                    cut_short = true;
                    break 'days;
                };
                let n = want - out.len();
                let got = match archive.get(&day) {
                    Some(files) => self.archive_day(&scope, day, files, start.as_ref(), n, t).await,
                    None => self.hot_day(&scope, day, start.as_ref(), n, t).await,
                };
                let got = match got {
                    Ok(g) => g,
                    Err(QueryError::Timeout) => {
                        cut_short = true;
                        break 'days;
                    }
                    Err(e) => return Err(e),
                };
                out.extend(got.rows.into_iter().filter(|r| {
                    scope.keeps(r)
                        && after.as_ref().is_none_or(|c| rank(r) > c.rank())
                        && seen.insert(CertCursor::of(r).encode())
                }));
                if out.len() >= want {
                    break 'days;
                }
                match got.next {
                    Some(c) if got.returned >= n => start = Some(Start::After(c)),
                    _ => break,
                }
            }
        }
        if cut_short && out.is_empty() {
            return Err(QueryError::Timeout);
        }
        let more = out.len() > limit || cut_short;
        out.truncate(limit);
        let next_cursor = out.last().filter(|_| more).map(|r| CertCursor::of(r).encode());
        Ok(TierPage { rows: out, next_cursor, cut_short })
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Writer;
    use crate::types::{CertRow, ParsedCert, RenewalClass};

    #[test]
    fn cursor_round_trips() {
        let c = CertCursor { seen_at_ms: 1_700_000_000_123, log_id: 7, entry_index: 42, reg_domain: "o'ne.com".into() };
        let s = c.encode();
        assert!(s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'), "{s}");
        assert_eq!(CertCursor::decode(&s), Some(c));
    }

    #[test]
    fn cursor_rejects_garbage() {
        for s in ["", "garbage", "!!!", "W10", &BASE64.encode("[1,2,3]"), &BASE64.encode(r#"[1,2,3,4]"#)] {
            assert_eq!(CertCursor::decode(s), None, "{s:?}");
        }
    }

    fn cert(index: u64, seen: i64) -> CertRow {
        CertRow {
            parsed: ParsedCert {
                issuer_cn: "LE".into(),
                names: vec!["a.one.com".into()],
                not_before_ms: seen,
                not_after_ms: seen + MS_PER_DAY,
                ..Default::default()
            },
            reg_domains: vec!["one.com".into()],
            primary_domain: Some("one.com".into()),
            is_wildcard: false,
            is_precert: false,
            renewal: RenewalClass::New,
            days_since_seen: None,
            new_names: 0,
            new_domains: 0,
            log: 0,
            index,
            der_size: 1,
            seen_at_ms: seen,
            sct_lag_ms: 0,
            not_before_lag_ms: 0,
            cert_hash: index,
        }
    }

    /// The deadline passes after the first day's query: the rows of that day
    /// come back cut short, and the cursor reaches the next day.
    #[tokio::test(flavor = "multi_thread")]
    async fn deadline_after_first_day_is_cut_short() {
        let dir = tempfile::tempdir().unwrap();
        let d = 20_000 * MS_PER_DAY;
        let mut w = Writer::open(dir.path(), 0).unwrap();
        w.push_cert(cert(1, d + 5));
        w.push_cert(cert(2, d + MS_PER_DAY + 5));
        w.flush(1).unwrap();
        w.publish(1).unwrap();
        let e = QueryEngine::open(dir.path()).unwrap();
        let domains = ["one.com".to_string()];
        let f = TierFilter::default();
        let mut calls = 0;
        let mut left = || {
            calls += 1;
            (calls == 1).then_some(Duration::from_secs(30))
        };
        let p = e.walk(&domains, None, &f, 10, None, &mut left).await.unwrap();
        assert!(p.cut_short);
        assert_eq!(p.rows.len(), 1);
        assert_eq!(p.rows[0]["entry_index"], 2);
        let c = CertCursor::decode(p.next_cursor.as_deref().unwrap()).unwrap();
        let rest = e.tier_certs(&domains, None, &f, 10, Some(c)).await.unwrap();
        assert!(!rest.cut_short && rest.next_cursor.is_none());
        assert_eq!(rest.rows.len(), 1);
        assert_eq!(rest.rows[0]["entry_index"], 1);

        let mut never = || None;
        assert!(matches!(e.walk(&domains, None, &f, 10, None, &mut never).await, Err(QueryError::Timeout)));
    }
}
