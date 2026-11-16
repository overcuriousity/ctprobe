//! The per-tier readers of one day, and the rows they build.

use super::{CertCursor, Scope};
use crate::nightly::archive::names_of;
use crate::query::sql::{quote, to_result, QueryResult, MEMORY, MS_PER_DAY, PARTITIONS};
use crate::query::{QueryEngine, QueryError};
use crate::store::{archive_certs_schema, certs_schema, day_string, list_day, register_files, session};
use arrow::datatypes::{DataType, SchemaRef};
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Keys of a row besides `tier` and `detail`.
const TOP: [&str; 9] =
    ["reg_domain", "names", "seen_at", "not_before", "not_after", "issuer_cn", "issuer_org", "log_id", "entry_index"];
const NEWEST: &str = "seen_at DESC, log_id DESC, entry_index DESC";

/// Where a day's next query starts.
pub(super) enum Start {
    /// The request's cursor: in the hot tier its certificate is read again,
    /// since later domains of it may follow.
    Cursor(CertCursor),
    /// After the last row a query returned.
    After(CertCursor),
}

/// What one query of a day gave: rows in page order, how many rows SQL
/// returned, and where the next query of the day starts.
pub(super) struct Got {
    pub(super) rows: Vec<Value>,
    pub(super) returned: usize,
    pub(super) next: Option<CertCursor>,
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

impl QueryEngine {    /// One day from its archive files, with hot detail while the day is hot.
    pub(super) async fn archive_day(
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
    pub(super) async fn hot_day(
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
