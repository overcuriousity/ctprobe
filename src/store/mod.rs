//! Parquet layout. Tables live in `<data>/<table>/day=YYYY-MM-DD/`, except
//! `domains`, which has one flat directory of deltas and snapshots.

mod schema;
mod writer;

pub use schema::*;
pub use writer::{write_batch, RollupMinuteRow, Writer, MINUTE_GLOBAL_LOG};

use anyhow::Result;
use arrow::datatypes::SchemaRef;
use chrono::{DateTime, Utc};
use datafusion::datasource::empty::EmptyTable;
use datafusion::execution::runtime_env::RuntimeEnvBuilder;
use datafusion::prelude::{ParquetReadOptions, SessionConfig, SessionContext};
use parquet::file::metadata::ParquetMetaDataReader;
use parquet::file::statistics::Statistics;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub fn day_string(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms).unwrap_or_default().format("%Y-%m-%d").to_string()
}

fn domain_file_day(name: &str, prefix: &str) -> Option<String> {
    name.strip_prefix(prefix)?.get(..10).map(str::to_string)
}

/// Files readers should use. A `daily.parquet` hides the parts beside it, so a
/// crash between compaction and part deletion cannot double count. For
/// `domains`, the newest snapshot hides deltas it already absorbed.
pub fn list_parts(data: &Path, table: &str) -> Vec<PathBuf> {
    let mut all = Vec::new();
    let mut stack = vec![data.join(table)];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "parquet") {
                all.push(p);
            }
        }
    }
    all.sort();
    if table == "domains" {
        let name = |p: &PathBuf| p.file_name().unwrap().to_string_lossy().into_owned();
        let snap = all.iter().filter(|p| name(p).starts_with("snapshot-")).max().cloned();
        let snap_day = snap.as_ref().and_then(|p| domain_file_day(&name(p), "snapshot-"));
        let mut out: Vec<PathBuf> = snap.into_iter().collect();
        out.extend(
            all.iter()
                .filter(|p| domain_file_day(&name(p), "delta-").is_some_and(|d| Some(&d) > snap_day.as_ref()))
                .cloned(),
        );
        return out;
    }
    let dailies: std::collections::HashSet<PathBuf> =
        all.iter().filter(|p| p.ends_with("daily.parquet")).filter_map(|p| p.parent().map(Path::to_path_buf)).collect();
    all.retain(|p| p.ends_with("daily.parquet") || !p.parent().is_some_and(|d| dailies.contains(d)));
    all
}

/// Published files of one table and day.
pub fn list_day(data: &Path, table: &str, day: &str) -> Vec<PathBuf> {
    let dir = format!("day={day}");
    list_parts(data, table)
        .into_iter()
        .filter(|p| p.parent().and_then(|d| d.file_name()).is_some_and(|d| d.to_string_lossy() == dir))
        .collect()
}

/// Where the archive keeps one day of `table`.
pub fn archive_file(data: &Path, table: &str, day: &str) -> PathBuf {
    data.join("archive").join(table).join(format!("{day}.parquet"))
}

/// Every Parquet file in the archive directory of `table`, whatever its name.
pub fn list_archive(data: &Path, table: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(data.join("archive").join(table))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "parquet"))
        .collect();
    out.sort();
    out
}

/// Whether the archive directory of `table` holds a Parquet file; stops at
/// the first.
pub fn has_archive(data: &Path, table: &str) -> bool {
    std::fs::read_dir(data.join("archive").join(table))
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| e.path().extension().is_some_and(|x| x == "parquet"))
}

fn epoch_day(d: chrono::NaiveDate) -> i64 {
    d.signed_duration_since(chrono::NaiveDate::default()).num_days()
}

/// The range of a millisecond timestamp column in a Parquet footer.
fn footer_range(p: &Path, column: &str) -> Option<(i64, i64)> {
    let meta = ParquetMetaDataReader::new().parse_and_finish(&std::fs::File::open(p).ok()?).ok()?;
    let col = meta.file_metadata().schema_descr().columns().iter().position(|c| c.name() == column)?;
    let mut range: Option<(i64, i64)> = None;
    for rg in meta.row_groups() {
        let Some(Statistics::Int64(s)) = rg.column(col).statistics() else { return None };
        let (lo, hi) = (*s.min_opt()?, *s.max_opt()?);
        range = Some(range.map_or((lo, hi), |(a, b)| (a.min(lo), b.max(hi))));
    }
    range
}

/// Archive files of `table` by the days (since the epoch) they hold.
/// `<YYYY-MM-DD>.parquet` holds that day; a file of any other name is placed
/// by the range of the timestamp column `ts` in its footer.
pub fn archive_days(data: &Path, table: &str, ts: &str) -> BTreeMap<i64, Vec<PathBuf>> {
    const MS_PER_DAY: i64 = 86_400_000;
    let mut out: BTreeMap<i64, Vec<PathBuf>> = BTreeMap::new();
    for p in list_archive(data, table) {
        let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let days = match chrono::NaiveDate::parse_from_str(&stem, "%Y-%m-%d") {
            Ok(d) => epoch_day(d)..=epoch_day(d),
            Err(_) => match footer_range(&p, ts) {
                Some((lo, hi)) => lo.div_euclid(MS_PER_DAY)..=hi.div_euclid(MS_PER_DAY),
                None => {
                    tracing::warn!("skipping archive file {}: no readable {ts} range in its footer", p.display());
                    continue;
                }
            },
        };
        for d in days {
            out.entry(d).or_default().push(p.clone());
        }
    }
    out
}

/// First and last seen day (since the epoch) and count in one FST value.
pub fn pack_domain(first_ms: i64, last_ms: i64, count: i64) -> u64 {
    let day = |ms: i64| (ms / 86_400_000).clamp(0, u16::MAX as i64) as u64;
    (day(first_ms) << 48) | (day(last_ms) << 32) | count.clamp(0, u32::MAX as i64) as u64
}

/// Inverse of `pack_domain`: first day, last day, count.
pub fn unpack_domain(v: u64) -> (u16, u16, u32) {
    ((v >> 48) as u16, (v >> 32) as u16, v as u32)
}

/// DataFusion session with spilling and a memory ceiling.
pub fn session(data: &Path, memory: usize, partitions: usize) -> Result<SessionContext> {
    let tmp = data.join("tmp");
    std::fs::create_dir_all(&tmp)?;
    let rt = RuntimeEnvBuilder::new().with_memory_limit(memory, 1.0).with_temp_file_path(tmp).build_arc()?;
    // Filters run while decoding, so a lookup on an unsorted column reads that
    // column alone and not every row in full.
    let cfg = SessionConfig::new()
        .with_target_partitions(partitions.max(1))
        .set_bool("datafusion.execution.parquet.pushdown_filters", true)
        .set_bool("datafusion.execution.parquet.reorder_filters", true);
    Ok(SessionContext::new_with_config_rt(cfg, rt))
}

/// Registers `files` as a table, or an empty table if there are none.
pub async fn register_files(ctx: &SessionContext, name: &str, schema: SchemaRef, files: &[PathBuf]) -> Result<()> {
    if files.is_empty() {
        ctx.register_table(name, Arc::new(EmptyTable::new(schema)))?;
        return Ok(());
    }
    let paths: Vec<String> =
        files.iter().map(|p| Ok(std::path::absolute(p)?.to_string_lossy().into_owned())).collect::<Result<_>>()?;
    let df = ctx.read_parquet(paths, ParquetReadOptions::default().schema(&schema)).await?;
    ctx.register_table(name, df.into_view())?;
    Ok(())
}
