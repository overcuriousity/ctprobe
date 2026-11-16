//! Long-term archive: one narrow, sorted Parquet file per finished day, with a
//! row per (certificate, registered domain). Files are never deleted here.

use super::compact::{props, BLOOM_NDV};
use super::{MEMORY, PARTITIONS};
use crate::metrics::dir_size;
use crate::names::registered_domain;
use crate::store::{archive_certs_schema, archive_file, list_archive, list_day, register_files, session};
use anyhow::{Context, Result};
use arrow::array::{
    Array, ArrayRef, AsArray, Int32Builder, Int64Builder, ListBuilder, RecordBatch, StringBuilder,
    TimestampMillisecondBuilder,
};
use arrow::datatypes::{Int32Type, Int64Type, TimestampMillisecondType};
use futures::StreamExt;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::file::metadata::ParquetMetaDataReader;
use parquet::arrow::{ArrowWriter, ProjectionMask};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Written { rows: u64, bytes: u64 },
    Empty,
    BudgetFull,
}

const COLUMNS: [&str; 10] = [
    "seen_at", "not_before", "not_after", "issuer_cn", "issuer_org", "names", "reg_domains",
    "primary_domain", "log_id", "entry_index",
];
const BATCH_ROWS: usize = 50_000;

pub fn archive_size(data: &Path) -> u64 {
    dir_size(&data.join("archive"))
}

/// Whole days of growth the budget still has room for, judged by the newest
/// 30 files.
pub fn days_left(data: &Path, budget: u64, total: u64) -> u64 {
    let mut sizes: Vec<u64> = list_archive(data, "certs")
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.len()))
        .collect();
    let n = sizes.len().min(30);
    sizes = sizes.split_off(sizes.len() - n);
    let mean = sizes.iter().sum::<u64>() / n.max(1) as u64;
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

/// Pass 1: one unsorted row per (cert, registered domain).
fn expand(files: &[std::path::PathBuf], out: &Path) -> Result<u64> {
    let schema = archive_certs_schema();
    let mut w = ArrowWriter::try_new(std::fs::File::create(out)?, schema, None)?;
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
                    let mut mine: Vec<&str> =
                        all.iter().copied().filter(|n| registered_domain(n).as_deref() == Some(reg)).collect();
                    mine.sort_unstable();
                    b.reg.append_value(reg);
                    for n in mine {
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

pub async fn certs(data: &Path, day: &str, budget: u64) -> Result<Outcome> {
    // The rename makes a file at the final path complete, so the day is done.
    let dest = archive_file(data, "certs", day);
    if dest.exists() {
        let meta = ParquetMetaDataReader::new().parse_and_finish(&std::fs::File::open(&dest)?)?;
        let rows = meta.file_metadata().num_rows() as u64;
        return Ok(Outcome::Written { rows, bytes: std::fs::metadata(&dest)?.len() });
    }
    if archive_size(data) >= budget {
        return Ok(Outcome::BudgetFull);
    }
    let files = list_day(data, "certs", day);
    if files.is_empty() {
        return Ok(Outcome::Empty);
    }
    let tmp_dir = data.join("tmp");
    std::fs::create_dir_all(&tmp_dir)?;
    let unsorted = tmp_dir.join(format!("archive-{day}.parquet"));
    let rows = expand(&files, &unsorted)?;
    if rows == 0 {
        std::fs::remove_file(&unsorted)?;
        return Ok(Outcome::Empty);
    }

    std::fs::create_dir_all(dest.parent().unwrap())?;
    let tmp = dest.with_extension("parquet.tmp");
    let schema = archive_certs_schema();
    let ctx = session(data, MEMORY, PARTITIONS)?;
    register_files(&ctx, "t", schema.clone(), std::slice::from_ref(&unsorted)).await?;
    let mut stream =
        ctx.sql("SELECT * FROM t ORDER BY reg_domain, seen_at").await?.execute_stream().await?;
    let mut w = ArrowWriter::try_new(
        std::fs::File::create(&tmp)?,
        schema.clone(),
        Some(props(&[("reg_domain", BLOOM_NDV)])),
    )?;
    while let Some(b) = stream.next().await {
        let b = b.context("archive query")?;
        w.write(&RecordBatch::try_new(schema.clone(), b.columns().to_vec())?)?;
    }
    w.into_inner()?.sync_all()?;
    std::fs::rename(&tmp, &dest)?;
    std::fs::remove_file(&unsorted)?;
    Ok(Outcome::Written { rows, bytes: std::fs::metadata(&dest)?.len() })
}
