//! Certificates across both tiers, one row per (certificate, registered
//! domain), walked day by day from the newest. A day with an archive file is
//! read from it; a day without one is scanned in the hot tier and split there.

mod days;
mod dns;
mod walk;

use super::sql::{quote, MS_PER_DAY};
use super::{QueryEngine, QueryError};
use crate::store::has_archive;
use base64::Engine;
use days::Start;
pub use dns::DnsCursor;
use serde::Serialize;
use serde_json::Value;
use std::cmp::Reverse;
use std::path::PathBuf;
use std::time::{Duration, Instant};
pub use walk::Bound;
#[cfg(test)]
use walk::Counting;
use walk::{DayFetch, Days, Got, Left};

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

    /// A position after every row of `day` and before every row of the day
    /// before: its last millisecond with the highest log and index.
    fn after_day(day: i64) -> CertCursor {
        CertCursor {
            seen_at_ms: day * MS_PER_DAY - 1,
            log_id: i32::MAX,
            entry_index: i64::MAX,
            reg_domain: String::new(),
        }
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
    /// True when the certificate archive holds a file.
    pub fn has_cert_archive(&self) -> bool {
        has_archive(&self.data, "certs")
    }

    /// One page of rows for `domains`, newest first, after `after`, on the
    /// days `bound` allows. With `exact_name`, only rows listing that name or
    /// the wildcard covering it.
    #[allow(clippy::too_many_arguments)]
    pub async fn tier_certs(
        &self,
        domains: &[String],
        exact_name: Option<&str>,
        f: &TierFilter,
        limit: usize,
        after: Option<CertCursor>,
        bound: &Bound,
        deadline: Instant,
    ) -> Result<TierPage, QueryError> {
        let mut left = || deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero());
        let scope = Scope::new(domains, exact_name, f);
        self.walk_days(&CertFetch { engine: self, scope: &scope }, scope.days(bound), limit, after, &mut left).await
    }
}

impl<'a> Scope<'a> {
    fn new(domains: &[String], exact_name: Option<&'a str>, f: &'a TierFilter) -> Scope<'a> {
        Scope {
            domains: domains
                .iter()
                .filter(|d| f.tld.as_deref().is_none_or(|t| psl::suffix_str(d) == Some(t)))
                .cloned()
                .collect(),
            exact: exact_name.map(|n| (n, format!("*.{}", n.split_once('.').map_or(n, |(_, p)| p)))),
            f,
        }
    }

    /// The days the certificate walk lists.
    fn days<'b>(&self, bound: &'b Bound) -> Days<'b> {
        Days {
            table: "certs",
            ts: "seen_at",
            from: self.f.from_ms,
            to: self.f.to_ms,
            bound,
            skip: self.domains.is_empty(),
        }
    }
}

/// The certificate walk's per-day reads.
struct CertFetch<'a> {
    engine: &'a QueryEngine,
    scope: &'a Scope<'a>,
}

impl DayFetch for CertFetch<'_> {
    type Cursor = CertCursor;
    type Start = Start;

    fn cursor_of(row: &Value) -> CertCursor {
        CertCursor::of(row)
    }

    fn encode(c: &CertCursor) -> String {
        c.encode()
    }

    fn day(c: &CertCursor) -> i64 {
        c.day()
    }

    fn after_day(day: i64) -> CertCursor {
        CertCursor::after_day(day)
    }

    fn first(c: CertCursor) -> Start {
        Start::Cursor(c)
    }

    fn resume(c: CertCursor) -> Start {
        Start::After(c)
    }

    fn keep(&self, row: &Value, after: Option<&CertCursor>) -> bool {
        self.scope.keeps(row) && after.is_none_or(|c| rank(row) > c.rank())
    }

    async fn day_rows(
        &self,
        day: i64,
        files: Option<&[PathBuf]>,
        hot: bool,
        start: Option<&Start>,
        n: usize,
        t: Duration,
        left: Left<'_>,
    ) -> Result<Got<CertCursor>, QueryError> {
        match files {
            Some(files) => self.engine.archive_day(self.scope, day, files, hot, start, n, t, left).await,
            None => self.engine.hot_day(self.scope, day, start, n, t).await,
        }
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
            new_name_list: vec![],
            new_reg_domains: vec![],
            log: 0,
            index,
            der_size: 1,
            seen_at_ms: seen,
            sct_lag_ms: 0,
            not_before_lag_ms: 0,
            cert_hash: index,
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

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn none() -> Bound {
        Bound::certs(&[])
    }

    /// One page as `tier_certs` gives it, on a scripted clock, and the days
    /// it read.
    async fn walk(
        e: &QueryEngine,
        domains: &[String],
        f: &TierFilter,
        after: Option<CertCursor>,
        bound: &Bound,
        left: &mut (dyn FnMut() -> Option<Duration> + Send),
    ) -> (Result<TierPage, QueryError>, Vec<i64>) {
        let scope = Scope::new(domains, None, f);
        let fetch = Counting::new(CertFetch { engine: e, scope: &scope });
        let page = e.walk_days(&fetch, scope.days(bound), 10, after, left).await;
        (page, fetch.take())
    }

    /// The deadline passes after the first day's query (asks: the listing,
    /// then the query): the rows of that day come back cut short, and the
    /// cursor reaches the next day.
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
        let p = walk(&e, &domains, &f, None, &none(), &mut clock(2)).await.0.unwrap();
        assert!(p.cut_short);
        assert_eq!(p.rows.len(), 1);
        assert_eq!(p.rows[0]["entry_index"], 2);
        let c = CertCursor::decode(p.next_cursor.as_deref().unwrap()).unwrap();
        let rest = e.tier_certs(&domains, None, &f, 10, Some(c), &none(), far()).await.unwrap();
        assert!(!rest.cut_short && rest.next_cursor.is_none());
        assert_eq!(rest.rows.len(), 1);
        assert_eq!(rest.rows[0]["entry_index"], 1);

        assert!(matches!(walk(&e, &domains, &f, None, &none(), &mut clock(0)).await.0, Err(QueryError::Timeout)));
        assert!(matches!(walk(&e, &domains, &f, None, &none(), &mut clock(1)).await.0, Err(QueryError::Timeout)));
    }

    /// The deadline passes before the hot detail of an archived, still hot day
    /// is fetched (asks: the listing, the archive query, the detail): the
    /// rows found are kept, `hot` without `detail`, and the page is cut short.
    #[tokio::test(flavor = "multi_thread")]
    async fn detail_timeout_keeps_rows() {
        let dir = tempfile::tempdir().unwrap();
        let d = 20_000 * MS_PER_DAY;
        let mut w = Writer::open(dir.path(), 0).unwrap();
        w.push_cert(cert(1, d + 5));
        w.push_cert(cert(2, d + 6));
        w.flush(1).unwrap();
        w.publish(1).unwrap();
        crate::nightly::archive::certs(dir.path(), "2024-10-04", u64::MAX).await.unwrap();
        let e = QueryEngine::open(dir.path()).unwrap();
        let domains = ["one.com".to_string()];
        let f = TierFilter::default();
        let p = walk(&e, &domains, &f, None, &none(), &mut clock(2)).await.0.unwrap();
        assert!(p.cut_short);
        assert_eq!(p.rows.len(), 2);
        assert!(p.rows.iter().all(|r| r["tier"] == "hot" && r.get("detail").is_none()), "{:?}", p.rows);
        let c = CertCursor::decode(p.next_cursor.as_deref().unwrap()).unwrap();
        assert_eq!(c.entry_index, 1);
        let rest = e.tier_certs(&domains, None, &f, 10, Some(c), &none(), far()).await.unwrap();
        assert!(rest.rows.is_empty() && !rest.cut_short && rest.next_cursor.is_none());

        let full = walk(&e, &domains, &f, None, &none(), &mut clock(3)).await.0.unwrap();
        assert!(!full.cut_short);
        assert!(full.rows.iter().all(|r| r["tier"] == "hot" && r["detail"]["key_type"].is_string()), "{:?}", full.rows);
    }

    fn other(index: u64, seen: i64) -> CertRow {
        let mut c = cert(index, seen);
        c.parsed.names = vec!["a.other.com".into()];
        c.reg_domains = vec!["other.com".into()];
        c.primary_domain = Some("other.com".into());
        c
    }

    /// Three days without a row for the domain, then one with it. A page cut
    /// short before the row is empty but continues after the last day it
    /// finished, and no day is read twice.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_cut_short_page_without_rows_makes_progress() {
        let dir = tempfile::tempdir().unwrap();
        let d = 20_000;
        let mut w = Writer::open(dir.path(), 0).unwrap();
        w.push_cert(cert(1, d * MS_PER_DAY + 5));
        for i in 1..=3 {
            w.push_cert(other(10 + i as u64, (d + i) * MS_PER_DAY + 5));
        }
        w.flush(1).unwrap();
        w.publish(1).unwrap();
        let e = QueryEngine::open(dir.path()).unwrap();
        let domains = ["one.com".to_string()];
        let f = TierFilter::default();
        // Asks: the listing, then two days.
        let (p, read) = walk(&e, &domains, &f, None, &none(), &mut clock(3)).await;
        let p = p.unwrap();
        assert!(p.rows.is_empty() && p.cut_short, "{:?}", p.rows);
        assert_eq!(read, vec![d + 3, d + 2]);
        let c1 = CertCursor::decode(p.next_cursor.as_deref().unwrap()).unwrap();
        // From that cursor, with time for one day: empty again, further on.
        let (p, again) = walk(&e, &domains, &f, Some(c1.clone()), &none(), &mut clock(2)).await;
        let p = p.unwrap();
        assert!(p.rows.is_empty() && p.cut_short);
        assert_eq!(again, vec![d + 1]);
        let c2 = CertCursor::decode(p.next_cursor.as_deref().unwrap()).unwrap();
        assert_ne!(c2, c1, "an empty page must not hand back the request's cursor");
        let (p, rest) = walk(&e, &domains, &f, Some(c2), &none(), &mut clock(100)).await;
        let p = p.unwrap();
        assert_eq!(rest, vec![d]);
        assert!(!p.cut_short && p.next_cursor.is_none());
        assert_eq!(p.rows.len(), 1);
        assert_eq!(p.rows[0]["entry_index"], 1);
        // Time for no day at all from a cursor is still a timeout.
        let c = CertCursor::decode(&CertCursor::after_day(d + 1).encode()).unwrap();
        assert!(matches!(walk(&e, &domains, &f, Some(c), &none(), &mut clock(1)).await.0, Err(QueryError::Timeout)));
    }

    /// The position after a day lies after each of its rows and before each
    /// row of the day before, in SQL and in Rust.
    #[tokio::test(flavor = "multi_thread")]
    async fn after_day_lies_between_days() {
        let dir = tempfile::tempdir().unwrap();
        let d = 20_000;
        let mut w = Writer::open(dir.path(), 0).unwrap();
        for (i, t) in [d * MS_PER_DAY, (d + 1) * MS_PER_DAY - 1, (d + 1) * MS_PER_DAY, (d + 2) * MS_PER_DAY - 1]
            .into_iter()
            .enumerate()
        {
            w.push_cert(cert(i as u64, t));
        }
        w.flush(1).unwrap();
        w.publish(1).unwrap();
        crate::nightly::archive::certs(dir.path(), "2024-10-04", u64::MAX).await.unwrap();
        let e = QueryEngine::open(dir.path()).unwrap();
        let domains = ["one.com".to_string()];
        let f = TierFilter::default();
        let c = CertCursor::after_day(d + 1);
        assert_eq!(c.day(), d);
        let p = e.tier_certs(&domains, None, &f, 10, Some(c), &none(), far()).await.unwrap();
        let mut got: Vec<i64> = p.rows.iter().map(|r| r["entry_index"].as_i64().unwrap()).collect();
        got.sort();
        assert_eq!(got, vec![0, 1], "{:?}", p.rows);
        // Day d+1 is only hot: the scan's SQL places the position the same way.
        let p = e.tier_certs(&domains, None, &f, 10, Some(CertCursor::after_day(d + 2)), &none(), far()).await.unwrap();
        let got: Vec<i64> = p.rows.iter().map(|r| r["entry_index"].as_i64().unwrap()).collect();
        assert_eq!(got, vec![3, 2, 1, 0], "{:?}", p.rows);
    }

    fn cfg(dir: &std::path::Path) -> crate::config::Config {
        crate::config::Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: dir.to_path_buf(),
            disk_budget_bytes: 1 << 40,
            tracker_max_bytes: 1 << 20,
            include_logs: vec![],
            exclude_logs: vec![],
            log_list_url: String::new(),
            extra_log_lists: vec![],
            include_test_logs: false,
            coverage_target: 95.0,
            dns: Default::default(),
            hot_days: None,
            dns_days: None,
            archive_budget_bytes: Some(1 << 40),
        }
    }

    fn day_name(day: i64) -> String {
        crate::store::day_string(day * MS_PER_DAY)
    }

    /// Years of archived days the index covers, as files no reader could
    /// open: reading one fails the walk.
    fn junk_archive(dir: &std::path::Path, days: std::ops::Range<i64>) {
        let a = dir.join("archive/certs");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(dir.join("nightly")).unwrap();
        for day in days {
            std::fs::write(a.join(format!("{}.parquet", day_name(day))), b"junk").unwrap();
            std::fs::write(dir.join("nightly").join(format!("{}.domains", day_name(day))), b"").unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_domain_the_index_never_saw_reads_no_archive_day() {
        let dir = tempfile::tempdir().unwrap();
        junk_archive(dir.path(), 18_000..19_100);
        let e = QueryEngine::open(dir.path()).unwrap();
        let domains = ["never-seen.com".to_string()];
        let f = TierFilter::default();
        let (p, read) = walk(&e, &domains, &f, None, &Bound::certs(&[]), &mut clock(100)).await;
        let p = p.unwrap();
        assert!(read.is_empty(), "{read:?}");
        assert!(p.rows.is_empty() && !p.cut_short && p.next_cursor.is_none());
    }

    /// One old archived day holds the domain; around it, years of other
    /// archived days and one day the nightly job has not finished.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_domain_seen_on_one_day_reads_that_day_and_unfinished_days() {
        let dir = tempfile::tempdir().unwrap();
        let d = 20_000;
        let mut w = Writer::open(dir.path(), 0).unwrap();
        w.push_cert(cert(1, d * MS_PER_DAY + 5));
        w.flush(1).unwrap();
        w.publish(1).unwrap();
        crate::nightly::run_nightly(&cfg(dir.path()), chrono::NaiveDate::from_ymd_opt(2024, 10, 4).unwrap())
            .await
            .unwrap();
        junk_archive(dir.path(), d - 800..d);
        junk_archive(dir.path(), d + 1..d + 30);
        let mut w = Writer::open(dir.path(), 0).unwrap();
        w.push_cert(other(2, (d + 40) * MS_PER_DAY + 5));
        w.flush(1).unwrap();
        w.publish(1).unwrap();
        let e = QueryEngine::open(dir.path()).unwrap();
        let hits = e.search_domains("one.com", crate::query::Mode::Exact, 1).await.unwrap();
        assert_eq!(hits.len(), 1);
        let domains = ["one.com".to_string()];
        let f = TierFilter::default();
        let (p, read) = walk(&e, &domains, &f, None, &Bound::certs(&hits), &mut clock(100)).await;
        let p = p.unwrap();
        assert_eq!(read, vec![d + 40, d]);
        assert_eq!(p.rows.len(), 1, "{:?}", p.rows);
        assert_eq!(p.rows[0]["entry_index"], 1);
        assert!(!p.cut_short && p.next_cursor.is_none());
    }
}
