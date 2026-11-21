//! Long-term archive: one narrow, sorted Parquet file per finished day, with a
//! row per (certificate, registered domain). Files are never deleted here.

use super::compact::{props, BLOOM_NDV};
use super::{MEMORY, PARTITIONS};
use crate::metrics::dir_size;
use crate::names::registered_domain;
use crate::store::{
    archive_certs_schema, archive_dns_schema, archive_file, dns_schema, list_archive, list_day, register_files, session,
};
use anyhow::{Context, Result};
use arrow::array::{
    Array, ArrayRef, AsArray, Int32Builder, Int64Builder, ListBuilder, RecordBatch, StringBuilder,
    TimestampMillisecondBuilder,
};
use arrow::datatypes::SchemaRef;
use arrow::datatypes::{Int32Type, Int64Type, TimestampMillisecondType};
use futures::StreamExt;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::{ArrowWriter, ProjectionMask};
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::metadata::ParquetMetaDataReader;
use parquet::file::properties::WriterProperties;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Written { rows: u64, bytes: u64 },
    Empty,
    BudgetFull,
}

const COLUMNS: [&str; 10] = [
    "seen_at",
    "not_before",
    "not_after",
    "issuer_cn",
    "issuer_org",
    "names",
    "reg_domains",
    "primary_domain",
    "log_id",
    "entry_index",
];
const BATCH_ROWS: usize = 50_000;

pub fn archive_size(data: &Path) -> u64 {
    dir_size(&data.join("archive"))
}

/// Whole days of growth the budget still has room for, judged by the newest
/// 30 days: each day's cert and dns files together.
pub fn days_left(data: &Path, budget: u64, total: u64) -> u64 {
    let mut per_day: BTreeMap<String, u64> = BTreeMap::new();
    for p in list_archive(data, "certs").into_iter().chain(list_archive(data, "dns")) {
        let Some(day) = p.file_stem().map(|s| s.to_string_lossy().into_owned()) else { continue };
        // Daily files only; a file of any other name holds no one day.
        if chrono::NaiveDate::parse_from_str(&day, "%Y-%m-%d").is_err() {
            continue;
        }
        *per_day.entry(day).or_default() += std::fs::metadata(&p).map_or(0, |m| m.len());
    }
    let newest: Vec<u64> = per_day.into_values().rev().take(30).collect();
    let mean = newest.iter().sum::<u64>() / newest.len().max(1) as u64;
    budget.saturating_sub(total) / mean.max(1)
}

#[derive(Default)]
struct Builders {
    reg: StringBuilder,
    names: ListBuilder<StringBuilder>,
    seen: TimestampMillisecondBuilder,
    nb: TimestampMillisecondBuilder,
    na: TimestampMillisecondBuilder,
    cn: StringBuilder,
    org: StringBuilder,
    log: Int32Builder,
    idx: Int64Builder,
    primary: StringBuilder,
    rows: usize,
}

impl Builders {
    fn finish(&mut self) -> Result<RecordBatch> {
        self.rows = 0;
        let cols: Vec<ArrayRef> = vec![
            Arc::new(self.reg.finish()),
            Arc::new(self.names.finish()),
            Arc::new(self.seen.finish()),
            Arc::new(self.nb.finish()),
            Arc::new(self.na.finish()),
            Arc::new(self.cn.finish()),
            Arc::new(self.org.finish()),
            Arc::new(self.log.finish()),
            Arc::new(self.idx.finish()),
            Arc::new(self.primary.finish()),
        ];
        Ok(RecordBatch::try_new(archive_certs_schema(), cols)?)
    }
}

/// The names of a certificate that belong to one of its registered domains,
/// sorted ascending.
pub(crate) fn names_of<'a>(names: &[&'a str], reg: &str) -> Vec<&'a str> {
    let mut mine: Vec<&str> = names.iter().copied().filter(|n| registered_domain(n).as_deref() == Some(reg)).collect();
    mine.sort_unstable();
    mine
}

/// Pass 1: one unsorted row per (cert, registered domain). The file counts
/// against the disk budget while it exists, so it is compressed, cheaply.
fn expand(files: &[std::path::PathBuf], out: &Path) -> Result<u64> {
    let schema = archive_certs_schema();
    let fast = WriterProperties::builder().set_compression(Compression::ZSTD(ZstdLevel::try_new(1)?)).build();
    let mut w = ArrowWriter::try_new(std::fs::File::create(out)?, schema, Some(fast))?;
    let mut b = Builders::default();
    let mut total = 0u64;
    for f in files {
        let rb = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(f)?)?;
        let mask = ProjectionMask::columns(rb.parquet_schema(), COLUMNS);
        for batch in rb.with_projection(mask).build()? {
            let batch = batch?;
            let col = |n: &str| batch.column_by_name(n).with_context(|| format!("column {n}"));
            let seen = col("seen_at")?.as_primitive::<TimestampMillisecondType>();
            let nb = col("not_before")?.as_primitive::<TimestampMillisecondType>();
            let na = col("not_after")?.as_primitive::<TimestampMillisecondType>();
            let cn = col("issuer_cn")?.as_string::<i32>();
            let org = col("issuer_org")?.as_string::<i32>();
            let names = col("names")?.as_list::<i32>();
            let regs = col("reg_domains")?.as_list::<i32>();
            let primary = col("primary_domain")?.as_string::<i32>();
            let log = col("log_id")?.as_primitive::<Int32Type>();
            let idx = col("entry_index")?.as_primitive::<Int64Type>();
            for i in 0..batch.num_rows() {
                let all = names.value(i);
                let all: Vec<&str> = all.as_string::<i32>().iter().flatten().collect();
                let r = regs.value(i);
                for reg in r.as_string::<i32>().iter().flatten() {
                    b.reg.append_value(reg);
                    for n in names_of(&all, reg) {
                        b.names.values().append_value(n);
                    }
                    b.names.append(true);
                    b.seen.append_value(seen.value(i));
                    b.nb.append_value(nb.value(i));
                    b.na.append_value(na.value(i));
                    b.cn.append_value(cn.value(i));
                    b.org.append_value(org.value(i));
                    b.log.append_value(log.value(i));
                    b.idx.append_value(idx.value(i));
                    // Null on the primary domain's own row.
                    match primary.is_valid(i).then(|| primary.value(i)) {
                        Some(p) if p != reg => b.primary.append_value(p),
                        _ => b.primary.append_null(),
                    }
                    b.rows += 1;
                    total += 1;
                    if b.rows >= BATCH_ROWS {
                        w.write(&b.finish()?)?;
                    }
                }
            }
        }
    }
    if b.rows > 0 {
        w.write(&b.finish()?)?;
    }
    w.into_inner()?.sync_all()?;
    Ok(total)
}

/// The rename makes a file at the final path complete, so the day is done.
fn finished(dest: &Path) -> Result<Option<Outcome>> {
    if !dest.exists() {
        return Ok(None);
    }
    let meta = ParquetMetaDataReader::new().parse_and_finish(&std::fs::File::open(dest)?)?;
    let rows = meta.file_metadata().num_rows() as u64;
    Ok(Some(Outcome::Written { rows, bytes: std::fs::metadata(dest)?.len() }))
}

/// Streams the query result into `dest` through `<dest>.tmp`, sorted data
/// with a bloom filter on `reg_domain`. Returns the rows written; with none,
/// no file is left behind.
async fn write_query(
    ctx: &datafusion::prelude::SessionContext,
    sql: &str,
    schema: SchemaRef,
    dest: &Path,
) -> Result<u64> {
    std::fs::create_dir_all(dest.parent().unwrap())?;
    let tmp = dest.with_extension("parquet.tmp");
    let mut stream = ctx.sql(sql).await?.execute_stream().await?;
    let mut w =
        ArrowWriter::try_new(std::fs::File::create(&tmp)?, schema.clone(), Some(props(&[("reg_domain", BLOOM_NDV)])))?;
    let mut rows = 0u64;
    while let Some(b) = stream.next().await {
        let b = b.context("archive query")?;
        rows += b.num_rows() as u64;
        w.write(&RecordBatch::try_new(schema.clone(), b.columns().to_vec())?)?;
    }
    if rows == 0 {
        drop(w);
        std::fs::remove_file(&tmp)?;
        return Ok(0);
    }
    w.into_inner()?.sync_all()?;
    std::fs::rename(&tmp, dest)?;
    Ok(rows)
}

/// Per name, the first answer of the day and every later one whose status or
/// address sets differ from the answer before it. Reads a table `t` shaped
/// like `dns`; the reduction is per name over all of `t`, so an outer filter
/// on `reg_domain` is safe.
pub const DNS_CHANGES_SQL: &str = "SELECT reg_domain, name, probed_at, status, v4, v6 FROM (
  SELECT *, ROW_NUMBER() OVER w AS rn,
         LAG(status || '|' || array_to_string(array_sort(v4), ',') || '|' || array_to_string(array_sort(v6), ','))
           OVER w AS prev,
         status || '|' || array_to_string(array_sort(v4), ',') || '|' || array_to_string(array_sort(v6), ',') AS cur
  FROM t WHERE kind = 'name' AND reg_domain IS NOT NULL
  WINDOW w AS (PARTITION BY name ORDER BY probed_at, attempt)
) WHERE rn = 1 OR cur IS DISTINCT FROM prev
ORDER BY reg_domain, name, probed_at, attempt";

pub async fn dns(data: &Path, day: &str, budget: u64) -> Result<Outcome> {
    let dest = archive_file(data, "dns", day);
    if let Some(done) = finished(&dest)? {
        return Ok(done);
    }
    // Nothing to archive is done whatever the budget.
    let files = list_day(data, "dns", day);
    if files.is_empty() {
        return Ok(Outcome::Empty);
    }
    if archive_size(data) >= budget {
        return Ok(Outcome::BudgetFull);
    }
    let ctx = session(data, MEMORY, PARTITIONS)?;
    register_files(&ctx, "t", dns_schema(), &files).await?;
    match write_query(&ctx, DNS_CHANGES_SQL, archive_dns_schema(), &dest).await? {
        0 => Ok(Outcome::Empty),
        rows => Ok(Outcome::Written { rows, bytes: std::fs::metadata(&dest)?.len() }),
    }
}

pub async fn certs(data: &Path, day: &str, budget: u64) -> Result<Outcome> {
    let dest = archive_file(data, "certs", day);
    if let Some(done) = finished(&dest)? {
        return Ok(done);
    }
    // Nothing to archive is done whatever the budget.
    let files = list_day(data, "certs", day);
    if files.is_empty() {
        return Ok(Outcome::Empty);
    }
    if archive_size(data) >= budget {
        return Ok(Outcome::BudgetFull);
    }
    let tmp_dir = data.join("tmp");
    std::fs::create_dir_all(&tmp_dir)?;
    let unsorted = tmp_dir.join(format!("archive-{day}.parquet"));
    let rows = expand(&files, &unsorted)?;
    if rows == 0 {
        std::fs::remove_file(&unsorted)?;
        return Ok(Outcome::Empty);
    }

    let schema = archive_certs_schema();
    let ctx = session(data, MEMORY, PARTITIONS)?;
    register_files(&ctx, "t", schema.clone(), std::slice::from_ref(&unsorted)).await?;
    write_query(&ctx, "SELECT * FROM t ORDER BY reg_domain, seen_at", schema, &dest).await?;
    std::fs::remove_file(&unsorted)?;
    Ok(Outcome::Written { rows, bytes: std::fs::metadata(&dest)?.len() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Writer;
    use crate::types::{CertRow, ParsedCert, RenewalClass};

    /// The unsorted pass-1 file counts against the disk budget, so it is
    /// compressed too.
    #[test]
    fn pass_one_file_is_compressed() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = Writer::open(dir.path(), 0).unwrap();
        w.push_cert(CertRow {
            parsed: ParsedCert { names: vec!["a.one.com".into()], ..Default::default() },
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
            index: 1,
            der_size: 1,
            seen_at_ms: 20_000 * 86_400_000,
            sct_lag_ms: 0,
            not_before_lag_ms: 0,
            cert_hash: 1,
        });
        w.flush(1).unwrap();
        w.publish(1).unwrap();
        let out = dir.path().join("unsorted.parquet");
        assert_eq!(expand(&list_day(dir.path(), "certs", "2024-10-04"), &out).unwrap(), 1);
        let meta = ParquetMetaDataReader::new().parse_and_finish(&std::fs::File::open(&out).unwrap()).unwrap();
        for c in meta.row_group(0).columns() {
            assert!(matches!(c.compression(), Compression::ZSTD(_)), "{}: {:?}", c.column_path(), c.compression());
        }
    }
}
