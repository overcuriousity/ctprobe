use super::{MEMORY, PARTITIONS};
use crate::store::{
    certs_schema, daily_coverage_schema, daily_stages_schema, daily_top_schema, list_day,
    register_files, rollup_daily_schema, session, sightings_schema, write_batch,
};
use anyhow::{Context, Result};
use arrow::array::{
    ArrayRef, AsArray, Date32Array, Float64Array, Int32Array, Int64Array, RecordBatch,
    StringArray,
};
use arrow::datatypes::{DataType, Int32Type, Int64Type, SchemaRef, UInt64Type};
use chrono::{Datelike, NaiveDate};
use datafusion::prelude::SessionContext;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

const TOP_N: usize = 1000;
const MAX_LOGS: usize = 256;

fn output(data: &Path, table: &str, day: &str) -> std::path::PathBuf {
    data.join(table).join(format!("day={day}")).join("daily.parquet")
}

async fn collect(ctx: &SessionContext, sql: &str) -> Result<Vec<RecordBatch>> {
    Ok(ctx.sql(sql).await?.collect().await?)
}

/// Rebuilds query output under the table's declared schema.
fn conform(schema: &SchemaRef, batches: &[RecordBatch]) -> Result<Option<RecordBatch>> {
    let mut parts = Vec::new();
    for b in batches.iter().filter(|b| b.num_rows() > 0) {
        parts.push(RecordBatch::try_new(schema.clone(), b.columns().to_vec()).context("conforming rollup")?);
    }
    if parts.is_empty() {
        return Ok(None);
    }
    Ok(Some(arrow::compute::concat_batches(schema, &parts)?))
}

pub async fn run(data: &Path, day: &str) -> Result<()> {
    let ctx = session(data, MEMORY, PARTITIONS)?;
    register_files(&ctx, "certs", certs_schema(), &list_day(data, "certs", day)).await?;
    register_files(&ctx, "sightings", sightings_schema(), &list_day(data, "sightings", day)).await?;

    let date = format!("CAST('{day}' AS DATE)");
    let span = "(CAST(not_after AS BIGINT) - CAST(not_before AS BIGINT)) / 86400000.0";
    let sql = format!(
        "SELECT {date} AS day, issuer_cn, issuer_org, tld, key_type, \
           CASE WHEN {span} <= 7 THEN '<=7d' WHEN {span} <= 47 THEN '<=47d' \
                WHEN {span} <= 100 THEN '<=100d' WHEN {span} <= 200 THEN '<=200d' \
                ELSE '>200d' END AS validity_bucket, \
           renewal, COUNT(*) AS certs, CAST(SUM(san_count) AS BIGINT) AS sans, \
           CAST(SUM(new_names) AS BIGINT) AS new_names, \
           CAST(SUM(new_domains) AS BIGINT) AS new_domains \
         FROM certs GROUP BY 2, 3, 4, 5, 6, 7"
    );
    if let Some(b) = conform(&rollup_daily_schema(), &collect(&ctx, &sql).await?)? {
        write_batch(&output(data, "rollup_daily", day), &b, None)?;
    }

    let sql = format!(
        "SELECT {date} AS day, (SELECT COUNT(*) FROM sightings) AS raw_entries, COUNT(*) AS unique_certs, \
           CAST(COALESCE(SUM(array_length(names)), 0) AS BIGINT) AS names, \
           CAST(COALESCE(SUM(new_names), 0) AS BIGINT) AS new_names, \
           CAST(COALESCE(SUM(new_domains), 0) AS BIGINT) AS new_domains FROM certs"
    );
    if let Some(b) = conform(&daily_stages_schema(), &collect(&ctx, &sql).await?)? {
        write_batch(&output(data, "daily_stages", day), &b, None)?;
    }

    let total = {
        let b = collect(&ctx, "SELECT COUNT(*) FROM certs").await?;
        b[0].column(0).as_primitive::<Int64Type>().value(0)
    };
    let date_days = NaiveDate::parse_from_str(day, "%Y-%m-%d")?.num_days_from_ce() - 719_163;
    let mut rows: Vec<(&str, i32, String, i64)> = Vec::new();
    for (kind, col) in [("domain", "primary_domain"), ("issuer", "issuer_cn")] {
        let sql = format!(
            "SELECT {col} AS key, COUNT(*) AS c FROM certs WHERE {col} IS NOT NULL \
             GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT {TOP_N}"
        );
        let mut rank = 0;
        for b in collect(&ctx, &sql).await? {
            let keys = arrow::compute::cast(b.column(0), &DataType::Utf8)?;
            let keys = keys.as_string::<i32>();
            let counts = b.column(1).as_primitive::<Int64Type>();
            for i in 0..b.num_rows() {
                rank += 1;
                rows.push((kind, rank, keys.value(i).to_string(), counts.value(i)));
            }
        }
    }
    if !rows.is_empty() {
        let n = rows.len();
        let cols: Vec<ArrayRef> = vec![
            Arc::new(Date32Array::from(vec![date_days; n])),
            Arc::new(StringArray::from_iter_values(rows.iter().map(|r| r.0))),
            Arc::new(Int32Array::from_iter_values(rows.iter().map(|r| r.1))),
            Arc::new(StringArray::from_iter_values(rows.iter().map(|r| r.2.as_str()))),
            Arc::new(Int64Array::from_iter_values(rows.iter().map(|r| r.3))),
            Arc::new(Int64Array::from(vec![total; n])),
        ];
        let b = RecordBatch::try_new(daily_top_schema(), cols)?;
        write_batch(&output(data, "daily_top", day), &b, None)?;
    }

    coverage(data, day, date_days)
}

/// Greedy best-N log selection over the day's sightings.
fn coverage(data: &Path, day: &str, date_days: i32) -> Result<()> {
    let mut dense: HashMap<i32, usize> = HashMap::new();
    let mut ids: Vec<i32> = Vec::new();
    let mut certs: HashMap<u64, [u64; 4]> = HashMap::new();
    for f in list_day(data, "sightings", day) {
        let r = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(f)?)?.build()?;
        for b in r {
            let b = b?;
            let hashes = b.column(0).as_primitive::<UInt64Type>();
            let logs = b.column(1).as_primitive::<Int32Type>();
            for i in 0..b.num_rows() {
                let log = logs.value(i);
                let bit = *dense.entry(log).or_insert_with(|| {
                    ids.push(log);
                    ids.len() - 1
                });
                if bit >= MAX_LOGS {
                    continue;
                }
                certs.entry(hashes.value(i)).or_default()[bit / 64] |= 1 << (bit % 64);
            }
        }
    }
    let total = certs.len() as i64;
    if total == 0 {
        return Ok(());
    }
    let mut groups: HashMap<[u64; 4], u64> = HashMap::new();
    for mask in certs.values() {
        *groups.entry(*mask).or_default() += 1;
    }
    let keys = ids.len().min(MAX_LOGS);
    let order = crate::coverage::greedy_by(groups.into_iter().collect(), keys, |i| ids[i]);
    let mut rows: Vec<(i32, i32, i64, i64, f64)> = Vec::new();
    let mut covered = 0i64;
    for (bit, added) in order {
        covered += added as i64;
        rows.push((
            rows.len() as i32 + 1,
            ids[bit],
            added as i64,
            covered,
            covered as f64 * 100.0 / total as f64,
        ));
    }
    let n = rows.len();
    let cols: Vec<ArrayRef> = vec![
        Arc::new(Date32Array::from(vec![date_days; n])),
        Arc::new(Int32Array::from_iter_values(rows.iter().map(|r| r.0))),
        Arc::new(Int32Array::from_iter_values(rows.iter().map(|r| r.1))),
        Arc::new(Int64Array::from_iter_values(rows.iter().map(|r| r.2))),
        Arc::new(Int64Array::from_iter_values(rows.iter().map(|r| r.3))),
        Arc::new(Float64Array::from_iter_values(rows.iter().map(|r| r.4))),
    ];
    let b = RecordBatch::try_new(daily_coverage_schema(), cols)?;
    write_batch(&output(data, "daily_coverage", day), &b, None)
}
