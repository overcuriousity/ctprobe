//! Certificates across both tiers, one row per (certificate, registered
//! domain), walked day by day from the newest. A day with an archive file is
//! read from it; a day without one is scanned in the hot tier and split here.

use super::sql::{days_of, quote, to_result, QueryResult, MEMORY, MS_PER_DAY, PARTITIONS};
use super::{QueryEngine, QueryError};
use crate::nightly::archive::names_of;
use crate::store::{archive_certs_schema, certs_schema, day_string, list_archive, list_day, register_files, session};
use arrow::datatypes::{DataType, SchemaRef};
use base64::Engine;
use chrono::NaiveDate;
use parquet::file::metadata::ParquetMetaDataReader;
use parquet::file::statistics::Statistics;
use serde::Serialize;
use serde_json::{Map, Value};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
/// Keys of a row besides `tier` and `detail`.
const TOP: [&str; 9] =
    ["reg_domain", "names", "seen_at", "not_before", "not_after", "issuer_cn", "issuer_org", "log_id", "entry_index"];
const NEWEST: &str = "seen_at DESC, log_id DESC, entry_index DESC";
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

/// Where a day's next query starts.
enum Start {
    /// The request's cursor: in the hot tier its certificate is read again,
    /// since later domains of it may follow.
    Cursor(CertCursor),
    /// After the last row a query returned.
    After(CertCursor),
}

/// What one query of a day gave: rows in page order, how many rows SQL
/// returned, and where the next query of the day starts.
struct Got {
    rows: Vec<Value>,
    returned: usize,
    next: Option<CertCursor>,
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

/// Columns of a schema, with timestamps as milliseconds.
fn columns(schema: SchemaRef) -> String {
    schema
        .fields()
        .iter()
        .map(|f| match f.data_type() {
            DataType::Timestamp(..) => format!("CAST({0} AS BIGINT) AS {0}", f.name()),
            _ => f.name().to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn objects(r: QueryResult) -> Vec<Map<String, Value>> {
    r.rows.into_iter().map(|row| r.columns.iter().cloned().zip(row).collect()).collect()
}

/// A row from the top-level values of `src`.
fn row(tier: &str, reg: &str, names: Vec<Value>, src: &Map<String, Value>, detail: Option<Map<String, Value>>) -> Value {
    let mut o = Map::new();
    o.insert("tier".into(), tier.into());
    o.insert("reg_domain".into(), reg.into());
    o.insert("names".into(), Value::Array(names));
    for k in &TOP[2..] {
        o.insert(k.to_string(), src.get(*k).cloned().unwrap_or(Value::Null));
    }
    if let Some(d) = detail {
        o.insert("detail".into(), Value::Object(d));
    }
    Value::Object(o)
}

/// A hot row's columns that are not top-level keys.
fn detail(mut hot: Map<String, Value>) -> Map<String, Value> {
    for k in TOP {
        hot.remove(k);
    }
    hot
}

fn key(o: &Map<String, Value>) -> (i64, i64) {
    let n = |k: &str| o.get(k).and_then(Value::as_i64).unwrap_or_default();
    (n("log_id"), n("entry_index"))
}

fn epoch_day(d: NaiveDate) -> i64 {
    d.signed_duration_since(NaiveDate::default()).num_days()
}

/// The `seen_at` range in a Parquet footer, in milliseconds.
fn seen_range(p: &Path) -> Option<(i64, i64)> {
    let meta = ParquetMetaDataReader::new().parse_and_finish(&std::fs::File::open(p).ok()?).ok()?;
    let col = meta.file_metadata().schema_descr().columns().iter().position(|c| c.name() == "seen_at")?;
    let mut range: Option<(i64, i64)> = None;
    for rg in meta.row_groups() {
        let Some(Statistics::Int64(s)) = rg.column(col).statistics() else { return None };
        let (lo, hi) = (*s.min_opt()?, *s.max_opt()?);
        range = Some(range.map_or((lo, hi), |(a, b)| (a.min(lo), b.max(hi))));
    }
    range
}

/// Archive files by the days they hold. `<YYYY-MM-DD>.parquet` holds that
/// day; a file of any other name is placed by the `seen_at` range in its footer.
fn archive_days(data: &Path) -> BTreeMap<i64, Vec<PathBuf>> {
    let mut out: BTreeMap<i64, Vec<PathBuf>> = BTreeMap::new();
    for p in list_archive(data, "certs") {
        let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let days = match NaiveDate::parse_from_str(&stem, "%Y-%m-%d") {
            Ok(d) => epoch_day(d)..=epoch_day(d),
            Err(_) => match seen_range(&p) {
                Some((lo, hi)) => lo.div_euclid(MS_PER_DAY)..=hi.div_euclid(MS_PER_DAY),
                None => continue,
            },
        };
        for d in days {
            out.entry(d).or_default().push(p.clone());
        }
    }
    out
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
        let archive = if scope.domains.is_empty() { BTreeMap::new() } else { archive_days(&self.data) };
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

    /// One day from its archive files, with hot detail while the day is hot.
    async fn archive_day(
        &self,
        scope: &Scope<'_>,
        day: i64,
        files: &[PathBuf],
        start: Option<&Start>,
        n: usize,
        t: Duration,
    ) -> Result<Got, QueryError> {
        let until = Instant::now() + t;
        let mut conds = scope.conditions(day, format!("reg_domain IN ({})", scope.list()), true);
        if let Some(Start::Cursor(c) | Start::After(c)) = start {
            conds.push(c.sql(&format!("reg_domain > {}", quote(&c.reg_domain))));
        }
        let sql = format!(
            "SELECT {} FROM a WHERE {} ORDER BY {NEWEST}, reg_domain ASC LIMIT {n}",
            columns(archive_certs_schema()),
            conds.join(" AND ")
        );
        let found = objects(self.run_archive(files.to_vec(), sql, n, t).await?);
        let mut hot = HashMap::new();
        let (lo, hi) = (day * MS_PER_DAY, day * MS_PER_DAY + MS_PER_DAY - 1);
        if !found.is_empty() && !list_day(&self.data, "certs", &day_string(lo)).is_empty() {
            let list = |v: BTreeSet<String>| v.into_iter().collect::<Vec<_>>().join(", ");
            let primary = |o: &Map<String, Value>| {
                o.get("primary_domain").and_then(Value::as_str).or(o.get("reg_domain").and_then(Value::as_str)).map(quote)
            };
            let sql = format!(
                "SELECT {} FROM certs WHERE primary_domain IN ({}) AND log_id IN ({}) AND entry_index IN ({})",
                columns(certs_schema()),
                list(found.iter().filter_map(primary).collect()),
                list(found.iter().map(|o| key(o).0.to_string()).collect()),
                list(found.iter().map(|o| key(o).1.to_string()).collect()),
            );
            let cap = 4 * found.len() + 100;
            let r = self.run_for(sql, cap, Some(lo), Some(hi), until.saturating_duration_since(Instant::now())).await?;
            hot = objects(r).into_iter().map(|o| (key(&o), o)).collect();
        }
        let returned = found.len();
        let rows: Vec<Value> = found
            .iter()
            .map(|o| {
                let reg = o.get("reg_domain").and_then(Value::as_str).unwrap_or_default();
                let names = o.get("names").and_then(Value::as_array).cloned().unwrap_or_default();
                match hot.get(&key(o)) {
                    Some(h) => row("hot", reg, names, o, Some(detail(h.clone()))),
                    None => row("archive", reg, names, o, None),
                }
            })
            .collect();
        let next = rows.last().map(CertCursor::of);
        Ok(Got { rows, returned, next })
    }

    /// One day scanned in the hot tier, each certificate split by domain.
    async fn hot_day(
        &self,
        scope: &Scope<'_>,
        day: i64,
        start: Option<&Start>,
        n: usize,
        t: Duration,
    ) -> Result<Got, QueryError> {
        let mut conds = scope.conditions(day, format!("array_has_any(reg_domains, make_array({}))", scope.list()), false);
        match start {
            Some(Start::Cursor(c)) => conds.push(c.sql("TRUE")),
            Some(Start::After(c)) => conds.push(c.sql("FALSE")),
            None => {}
        }
        let sql = format!(
            "SELECT {} FROM certs WHERE {} ORDER BY {NEWEST} LIMIT {n}",
            columns(certs_schema()),
            conds.join(" AND ")
        );
        let (lo, hi) = (day * MS_PER_DAY, day * MS_PER_DAY + MS_PER_DAY - 1);
        let found = objects(self.run_for(sql, n, Some(lo), Some(hi), t).await?);
        let wanted: HashSet<&str> = scope.domains.iter().map(String::as_str).collect();
        let strs = |o: &Map<String, Value>, k: &str| -> Vec<String> {
            o.get(k).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect()
        };
        let mut rows = Vec::new();
        for o in &found {
            let names = strs(o, "names");
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            let mut regs = strs(o, "reg_domains");
            regs.sort();
            regs.dedup();
            for reg in regs.iter().filter(|r| wanted.contains(r.as_str())) {
                let mine = names_of(&names, reg).into_iter().map(Value::from).collect();
                rows.push(row("hot", reg, mine, o, Some(detail(o.clone()))));
            }
        }
        let next = found.last().map(|o| {
            let n = |k: &str| o.get(k).and_then(Value::as_i64).unwrap_or_default();
            CertCursor { seen_at_ms: n("seen_at"), log_id: n("log_id") as i32, entry_index: n("entry_index"), reg_domain: String::new() }
        });
        Ok(Got { rows, returned: found.len(), next })
    }

    /// A query over archive files on the query runtime, bounded by `t` but
    /// outside the limiter, so it cannot queue in front of other endpoints.
    async fn run_archive(&self, files: Vec<PathBuf>, sql: String, limit: usize, t: Duration) -> Result<QueryResult, QueryError> {
        let data = self.data.clone();
        let task = self.rt.spawn(async move {
            let work = async {
                let ctx = session(&data, MEMORY, PARTITIONS)?;
                register_files(&ctx, "a", archive_certs_schema(), &files).await?;
                let df = ctx.sql(&sql).await?;
                let schema = SchemaRef::new(df.schema().as_arrow().clone());
                let batches = df.collect().await?;
                Ok::<_, QueryError>(to_result(&batches, schema, limit)?)
            };
            tokio::time::timeout(t, work).await.map_err(|_| QueryError::Timeout)?
        });
        task.await.map_err(|e| QueryError::Failed(e.to_string()))?
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
