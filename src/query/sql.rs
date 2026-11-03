use super::buckets::{san_case, size_case, validity_case};
use super::QueryEngine;
use crate::store::{
    certs_schema, daily_coverage_schema, daily_stages_schema, daily_top_schema, day_string,
    dns_minute_schema, dns_schema, domains_schema, list_parts, register_files, rollup_daily_schema, rollup_minute_schema, session,
    sightings_schema,
};
use anyhow::Result;
use arrow::array::RecordBatch;
use arrow::datatypes::SchemaRef;
use datafusion::prelude::SessionContext;
use serde::Serialize;
use sqlparser::ast::Statement;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MS_PER_DAY: i64 = 86_400_000;
const MEMORY: usize = 1 << 30;
const PARTITIONS: usize = 2;
const CERT_COLUMNS: &str = "seen_at, cn, primary_domain, issuer_cn, issuer_org, not_before, \
    not_after, san_count, names, key_type, key_bits, sig_type, is_precert, renewal, \
    days_since_seen, log_id, entry_index, serial, der_size, tld, is_wildcard";

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("only a single SELECT is allowed: {0}")]
    NotAllowed(String),
    #[error("query timed out")]
    Timeout,
    #[error("{0}")]
    Failed(String),
}

impl From<anyhow::Error> for QueryError {
    fn from(e: anyhow::Error) -> Self {
        QueryError::Failed(format!("{e:#}"))
    }
}

impl From<datafusion::error::DataFusionError> for QueryError {
    fn from(e: datafusion::error::DataFusionError) -> Self {
        QueryError::Failed(e.to_string())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub truncated: bool,
}

/// Columns certificate results can sort on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortKey {
    #[default]
    SeenAt,
    NotBefore,
    NotAfter,
    Cn,
    IssuerCn,
    SanCount,
    Renewal,
    DaysSinceSeen,
    DerSize,
    KeyType,
}

impl SortKey {
    const ALL: [(SortKey, &'static str); 10] = [
        (SortKey::SeenAt, "seen_at"),
        (SortKey::NotBefore, "not_before"),
        (SortKey::NotAfter, "not_after"),
        (SortKey::Cn, "cn"),
        (SortKey::IssuerCn, "issuer_cn"),
        (SortKey::SanCount, "san_count"),
        (SortKey::Renewal, "renewal"),
        (SortKey::DaysSinceSeen, "days_since_seen"),
        (SortKey::DerSize, "der_size"),
        (SortKey::KeyType, "key_type"),
    ];

    pub fn parse(s: &str) -> Option<SortKey> {
        Self::ALL.iter().find(|(_, n)| *n == s).map(|(k, _)| *k)
    }

    pub fn column(self) -> &'static str {
        Self::ALL.iter().find(|(k, _)| *k == self).map_or("seen_at", |(_, n)| n)
    }
}

#[derive(Debug, Clone, Default)]
pub struct CertFilter {
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub random_n: Option<usize>,
    pub limit: usize,
    pub issuer: Option<String>,
    pub renewal: Option<String>,
    pub wildcard: Option<bool>,
    pub tld: Option<String>,
    pub key_type: Option<String>,
    pub validity: Option<String>,
    pub san: Option<String>,
    pub size: Option<String>,
    pub issuer_contains: Option<String>,
    pub expires_from_ms: Option<i64>,
    pub expires_to_ms: Option<i64>,
    pub precert: Option<bool>,
    pub sort: SortKey,
    /// Ascending when set; newest or largest first otherwise.
    pub asc: bool,
    pub offset: usize,
}

impl CertFilter {
    /// True if anything narrows the results besides a domain or pattern.
    pub fn narrows(&self) -> bool {
        self.from_ms.is_some()
            || self.to_ms.is_some()
            || self.issuer.is_some()
            || self.renewal.is_some()
            || self.wildcard.is_some()
            || self.tld.is_some()
            || self.key_type.is_some()
            || self.validity.is_some()
            || self.san.is_some()
            || self.size.is_some()
            || self.issuer_contains.is_some()
            || self.expires_from_ms.is_some()
            || self.expires_to_ms.is_some()
            || self.precert.is_some()
    }
}

#[derive(Debug, Clone)]
pub enum CertScope {
    Domain(String),
    Pattern(String),
    All,
}

/// One page of certificates. `count` is `None` when counting ran out of time.
#[derive(Debug, Clone, Serialize)]
pub struct CertPage {
    #[serde(flatten)]
    pub result: QueryResult,
    pub count: Option<u64>,
    pub count_capped: bool,
    /// The time limit ended the scan, so later rows may exist unseen.
    pub cut_short: bool,
    pub sort: &'static str,
    pub desc: bool,
    pub offset: usize,
    pub from_ms: Option<i64>,
}

/// Deepest page reachable, and where the count stops.
pub const MAX_OFFSET: usize = 10_000;
const COUNT_TIMEOUT: Duration = Duration::from_secs(5);
/// Certificates of one batch share a time, so pages need a unique last sort key
/// or rows repeat and go missing between pages.
const NEWEST: &str = "seen_at DESC, log_id DESC, entry_index DESC";

/// Accepts exactly one read-only query. DataFusion's own SQL also plans DDL,
/// `COPY` and `SET`, so the check happens on the parsed statement.
pub fn check_sql(q: &str) -> Result<(), QueryError> {
    let stmts = Parser::parse_sql(&GenericDialect {}, q)
        .map_err(|e| QueryError::NotAllowed(e.to_string()))?;
    match stmts.as_slice() {
        [Statement::Query(_)] => Ok(()),
        _ => Err(QueryError::NotAllowed("not a single query".into())),
    }
}

fn to_result(batches: &[RecordBatch], schema: SchemaRef, limit: usize) -> Result<QueryResult> {
    let columns: Vec<String> = schema.fields().iter().map(|f| f.name().clone()).collect();
    let mut w = arrow::json::ArrayWriter::new(Vec::new());
    for b in batches {
        w.write(b)?;
    }
    w.finish()?;
    let buf = w.into_inner();
    let objects: Vec<serde_json::Map<String, serde_json::Value>> =
        if buf.is_empty() { vec![] } else { serde_json::from_slice(&buf)? };
    let truncated = objects.len() > limit;
    let rows = objects
        .into_iter()
        .take(limit)
        .map(|mut o| {
            columns.iter().map(|c| o.remove(c).unwrap_or(serde_json::Value::Null)).collect()
        })
        .collect();
    Ok(QueryResult { columns, rows, truncated })
}

/// Files of a day-partitioned table inside an optional time range.
fn in_range(data: &Path, table: &str, from: Option<i64>, to: Option<i64>) -> Vec<PathBuf> {
    let lo = from.map(day_string);
    let hi = to.map(day_string);
    list_parts(data, table)
        .into_iter()
        .filter(|p| {
            let d = p
                .parent()
                .and_then(|d| d.file_name())
                .map(|d| d.to_string_lossy().trim_start_matches("day=").to_string())
                .unwrap_or_default();
            lo.as_ref().is_none_or(|l| &d >= l) && hi.as_ref().is_none_or(|h| &d <= h)
        })
        .collect()
}

/// Days holding `table` files within the range, newest first, as days since the epoch.
fn days_of(data: &Path, table: &str, from: Option<i64>, to: Option<i64>) -> Vec<i64> {
    let mut days: Vec<i64> = in_range(data, table, from, to)
        .iter()
        .filter_map(|p| {
            let name = p.parent()?.file_name()?.to_string_lossy().into_owned();
            let d = chrono::NaiveDate::parse_from_str(name.strip_prefix("day=")?, "%Y-%m-%d").ok()?;
            Some(d.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis() / MS_PER_DAY)
        })
        .collect();
    days.sort_unstable_by(|a, b| b.cmp(a));
    days.dedup();
    days
}

async fn context(data: &Path, from: Option<i64>, to: Option<i64>) -> Result<SessionContext> {
    let ctx = session(data, MEMORY, PARTITIONS)?;
    let ranged = in_range(data, "certs", from, to);
    register_files(&ctx, "certs", certs_schema(), &ranged).await?;
    register_files(&ctx, "dns", dns_schema(), &in_range(data, "dns", from, to)).await?;
    let tables: [(&str, SchemaRef); 7] = [
        ("dns_minute", dns_minute_schema()),
        ("sightings", sightings_schema()),
        ("rollup_minute", rollup_minute_schema()),
        ("rollup_daily", rollup_daily_schema()),
        ("daily_stages", daily_stages_schema()),
        ("daily_top", daily_top_schema()),
        ("daily_coverage", daily_coverage_schema()),
    ];
    for (name, schema) in tables {
        register_files(&ctx, name, schema, &list_parts(data, name)).await?;
    }
    register_files(&ctx, "domains_raw", domains_schema(), &list_parts(data, "domains")).await?;
    let view = ctx
        .sql(
            "SELECT domain, MAX(skeleton) AS skeleton, MIN(first_seen) AS first_seen, \
             MAX(last_seen) AS last_seen, CAST(SUM(cert_count) AS BIGINT) AS cert_count \
             FROM domains_raw GROUP BY domain",
        )
        .await?;
    ctx.register_table("domains", view.into_view())?;
    Ok(ctx)
}

/// A SQL string literal.
pub fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Translates a SQL LIKE pattern into a regex over space-joined names.
fn name_regex(pattern: &str) -> String {
    let mut re = String::from("(^| )");
    for c in pattern.chars() {
        match c {
            '%' => re.push_str("[^ ]*"),
            '_' => re.push_str("[^ ]"),
            c if c.is_ascii_alphanumeric() || c == '-' => re.push(c),
            c => {
                re.push('\\');
                re.push(c);
            }
        }
    }
    re.push_str("( |$)");
    re
}

impl QueryEngine {
    /// Runs one query on the query runtime, bounded by the concurrency limit
    /// and the timeout.
    async fn run(
        &self,
        sql: String,
        limit: usize,
        from: Option<i64>,
        to: Option<i64>,
    ) -> Result<QueryResult, QueryError> {
        self.run_for(sql, limit, from, to, self.timeout).await
    }

    async fn run_for(
        &self,
        sql: String,
        limit: usize,
        from: Option<i64>,
        to: Option<i64>,
        timeout: Duration,
    ) -> Result<QueryResult, QueryError> {
        let data = self.data.clone();
        let limiter = self.limiter.clone();
        let task = self.rt.spawn(async move {
            let _permit = limiter.acquire_owned().await.map_err(|e| QueryError::Failed(e.to_string()))?;
            let work = async {
                let ctx = context(&data, from, to).await?;
                let df = ctx.sql(&sql).await?;
                let schema = SchemaRef::new(df.schema().as_arrow().clone());
                let batches = df.limit(0, Some(limit + 1))?.collect().await?;
                Ok::<_, QueryError>(to_result(&batches, schema, limit)?)
            };
            tokio::time::timeout(timeout, work).await.map_err(|_| QueryError::Timeout)?
        });
        task.await.map_err(|e| QueryError::Failed(e.to_string()))?
    }

    /// User-supplied SQL, limited to a single read-only query.
    pub async fn sql(&self, q: &str, limit: usize) -> Result<QueryResult, QueryError> {
        check_sql(q)?;
        self.run(q.to_string(), limit, None, None).await
    }

    /// Fixed internal SQL with a certificate time range.
    pub async fn internal(
        &self,
        q: String,
        limit: usize,
        from: Option<i64>,
        to: Option<i64>,
    ) -> Result<QueryResult, QueryError> {
        self.run(q, limit, from, to).await
    }

    fn cert_conditions(where_: &str, f: &CertFilter) -> String {
        let mut conds = vec![where_.to_string()];
        let ms = |conds: &mut Vec<String>, col: &str, op: &str, t: Option<i64>| {
            if let Some(t) = t {
                conds.push(format!("CAST({col} AS BIGINT) {op} {t}"));
            }
        };
        ms(&mut conds, "seen_at", ">=", f.from_ms);
        ms(&mut conds, "seen_at", "<=", f.to_ms);
        ms(&mut conds, "not_after", ">=", f.expires_from_ms);
        ms(&mut conds, "not_after", "<=", f.expires_to_ms);
        let eq = |conds: &mut Vec<String>, expr: &str, v: &Option<String>| {
            if let Some(v) = v {
                conds.push(format!("{expr} = {}", quote(v)));
            }
        };
        eq(&mut conds, "issuer_cn", &f.issuer);
        eq(&mut conds, "renewal", &f.renewal);
        eq(&mut conds, "tld", &f.tld);
        eq(&mut conds, "key_type", &f.key_type);
        eq(&mut conds, &format!("({})", validity_case()), &f.validity);
        eq(&mut conds, &format!("({})", san_case()), &f.san);
        eq(&mut conds, &format!("({})", size_case()), &f.size);
        if let Some(i) = &f.issuer_contains {
            conds.push(format!("strpos(lower(issuer_cn), lower({})) > 0", quote(i)));
        }
        if let Some(w) = f.wildcard {
            conds.push(format!("is_wildcard = {w}"));
        }
        if let Some(p) = f.precert {
            conds.push(format!("is_precert = {p}"));
        }
        conds.join(" AND ")
    }

    fn cert_query(where_: &str, f: &CertFilter) -> String {
        let order = match f.random_n {
            Some(n) => format!("ORDER BY random() LIMIT {n}"),
            None => "ORDER BY seen_at DESC".to_string(),
        };
        format!("SELECT {CERT_COLUMNS} FROM certs WHERE {} {order}", Self::cert_conditions(where_, f))
    }

    /// Newest first, one day at a time from the newest, stopping when the page
    /// is full. A filter cannot skip rows inside a day's file, so this is what
    /// keeps a click on a long range answerable. On a timeout, what was found
    /// so far is returned, marked as truncated.
    async fn newest_first(&self, conds: &str, f: &CertFilter) -> Result<(QueryResult, bool), QueryError> {
        let want = f.offset + f.limit + 1;
        let deadline = Instant::now() + self.timeout;
        let mut out = QueryResult { columns: vec![], rows: vec![], truncated: false };
        let mut cut_short = false;
        for day in days_of(&self.data, "certs", f.from_ms, f.to_ms) {
            let need = want - out.rows.len();
            let q = format!("SELECT {CERT_COLUMNS} FROM certs WHERE {conds} ORDER BY {NEWEST} LIMIT {need}");
            let (lo, hi) = (day * MS_PER_DAY, day * MS_PER_DAY + MS_PER_DAY - 1);
            let left = deadline.saturating_duration_since(Instant::now());
            match self.run_for(q, need, Some(lo), Some(hi), left).await {
                Ok(r) => {
                    out.columns = r.columns;
                    out.rows.extend(r.rows);
                }
                Err(QueryError::Timeout) if !out.rows.is_empty() => {
                    cut_short = true;
                    break;
                }
                Err(e) => return Err(e),
            }
            if out.rows.len() >= want {
                break;
            }
        }
        out.truncated = out.rows.len() > f.offset + f.limit;
        out.rows = out.rows.into_iter().skip(f.offset).take(f.limit).collect();
        Ok((out, cut_short))
    }

    /// A page of certificates, filtered, sorted and offset on the server.
    pub async fn certs_page(&self, scope: CertScope, f: CertFilter) -> Result<CertPage, QueryError> {
        let base = match &scope {
            CertScope::Domain(d) => format!("primary_domain = {}", quote(d)),
            CertScope::Pattern(p) => {
                format!("regexp_like(array_to_string(names, ' '), {})", quote(&name_regex(&p.to_lowercase())))
            }
            CertScope::All => "TRUE".to_string(),
        };
        let conds = Self::cert_conditions(&base, &f);
        let (result, cut_short) = if let Some(n) = f.random_n {
            let q = format!("SELECT {CERT_COLUMNS} FROM certs WHERE {conds} ORDER BY random() LIMIT {n}");
            (self.run(q, f.limit, f.from_ms, f.to_ms).await?, false)
        } else if f.sort == SortKey::SeenAt && !f.asc {
            self.newest_first(&conds, &f).await?
        } else {
            let dir = if f.asc { "ASC" } else { "DESC" };
            let (col, limit, offset) = (f.sort.column(), f.limit + 1, f.offset);
            let q = format!(
                "SELECT {CERT_COLUMNS} FROM certs WHERE {conds} \
                 ORDER BY {col} {dir} NULLS LAST, {NEWEST} LIMIT {limit} OFFSET {offset}"
            );
            (self.run(q, f.limit, f.from_ms, f.to_ms).await?, false)
        };
        let (count, count_capped) = if f.random_n.is_some() {
            (Some(result.rows.len() as u64), false)
        } else if !result.truncated && !cut_short {
            (Some((f.offset + result.rows.len()) as u64), false)
        } else {
            self.count_certs(&conds, &f).await
        };
        Ok(CertPage {
            result,
            count,
            count_capped,
            cut_short,
            sort: f.sort.column(),
            desc: !f.asc,
            offset: f.offset,
            from_ms: f.from_ms,
        })
    }

    /// A count capped at `MAX_OFFSET`. Failing only loses the count, not the results.
    async fn count_certs(&self, conds: &str, f: &CertFilter) -> (Option<u64>, bool) {
        let cap = MAX_OFFSET + 1;
        let q = format!("SELECT COUNT(*) AS n FROM (SELECT 1 AS x FROM certs WHERE {conds} LIMIT {cap})");
        let got = self.run_for(q, 1, f.from_ms, f.to_ms, COUNT_TIMEOUT.min(self.timeout)).await;
        match got.ok().and_then(|r| r.rows.first()?.first()?.as_u64()) {
            Some(n) if n as usize >= cap => (Some(MAX_OFFSET as u64), true),
            Some(n) => (Some(n), false),
            None => (None, false),
        }
    }

    /// Certificates whose primary registered domain is one of `domains`.
    pub async fn certs_for(&self, domains: &[String], f: CertFilter) -> Result<QueryResult, QueryError> {
        if domains.is_empty() {
            return Ok(QueryResult { columns: vec![], rows: vec![], truncated: false });
        }
        let list = domains.iter().map(|d| quote(d)).collect::<Vec<_>>().join(", ");
        let q = Self::cert_query(&format!("primary_domain IN ({list})"), &f);
        self.run(q, f.limit, f.from_ms, f.to_ms).await
    }

    /// Certificates with any name matching a LIKE pattern. Scans all rows.
    pub async fn search_names(&self, pattern: &str, f: CertFilter) -> Result<QueryResult, QueryError> {
        let re = quote(&name_regex(&pattern.to_lowercase()));
        let q = Self::cert_query(&format!("regexp_like(array_to_string(names, ' '), {re})"), &f);
        self.run(q, f.limit, f.from_ms, f.to_ms).await
    }
}
