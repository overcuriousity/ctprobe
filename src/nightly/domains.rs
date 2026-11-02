use super::{MEMORY, PARTITIONS};
use crate::store::{domains_schema, pack_domain, register_files, session};
use anyhow::Result;
use futures::StreamExt;
use arrow::array::{ArrayRef, AsArray, Int64Builder, RecordBatch, StringBuilder, TimestampMillisecondBuilder};
use arrow::datatypes::{Int64Type, TimestampMillisecondType};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const OUT_BATCH: usize = 100_000;

fn cast_utf8(a: &ArrayRef) -> Result<ArrayRef> {
    Ok(arrow::compute::cast(a, &arrow::datatypes::DataType::Utf8)?)
}

#[derive(Clone, Debug)]
struct Rec {
    domain: String,
    skeleton: String,
    first: i64,
    last: i64,
    count: i64,
}

fn recs(b: &RecordBatch) -> Vec<Rec> {
    let d = b.column(0).as_string::<i32>();
    let s = b.column(1).as_string::<i32>();
    let f = b.column(2).as_primitive::<TimestampMillisecondType>();
    let l = b.column(3).as_primitive::<TimestampMillisecondType>();
    let c = b.column(4).as_primitive::<Int64Type>();
    (0..b.num_rows())
        .map(|i| Rec {
            domain: d.value(i).to_string(),
            skeleton: s.value(i).to_string(),
            first: f.value(i),
            last: l.value(i),
            count: c.value(i),
        })
        .collect()
}

/// Streams a sorted snapshot, or nothing.
fn snapshot_iter(path: Option<PathBuf>) -> Result<Box<dyn Iterator<Item = Result<Rec>>>> {
    let Some(path) = path else { return Ok(Box::new(std::iter::empty())) };
    let r = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path)?)?.build()?;
    Ok(Box::new(r.flat_map(|b| match b {
        Ok(b) => recs(&b).into_iter().map(Ok).collect::<Vec<_>>(),
        Err(e) => vec![Err(e.into())],
    })))
}

struct Out {
    writer: ArrowWriter<std::fs::File>,
    fst: fst::MapBuilder<BufWriter<std::fs::File>>,
    buf: Vec<Rec>,
}

impl Out {
    fn push(&mut self, r: Rec) -> Result<()> {
        self.fst.insert(&r.domain, pack_domain(r.first, r.last, r.count))?;
        self.buf.push(r);
        if self.buf.len() >= OUT_BATCH {
            self.drain()?;
        }
        Ok(())
    }

    fn drain(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let mut d = StringBuilder::new();
        let mut s = StringBuilder::new();
        let mut f = TimestampMillisecondBuilder::new();
        let mut l = TimestampMillisecondBuilder::new();
        let mut c = Int64Builder::new();
        for r in self.buf.drain(..) {
            d.append_value(&r.domain);
            s.append_value(&r.skeleton);
            f.append_value(r.first);
            l.append_value(r.last);
            c.append_value(r.count);
        }
        let cols: Vec<ArrayRef> = vec![
            Arc::new(d.finish()),
            Arc::new(s.finish()),
            Arc::new(f.finish()),
            Arc::new(l.finish()),
            Arc::new(c.finish()),
        ];
        self.writer.write(&RecordBatch::try_new(domains_schema(), cols)?)?;
        Ok(())
    }
}

/// Writes the sorted union of a snapshot and new records.
fn merge(base: Option<PathBuf>, new: Vec<Rec>, out: &mut Out) -> Result<()> {
    let mut old = snapshot_iter(base)?.peekable();
    let mut fresh = new.into_iter().peekable();
    loop {
        let take_old = match (old.peek(), fresh.peek()) {
            (None, None) => break,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (Some(Err(_)), _) => true,
            (Some(Ok(a)), Some(b)) => a.domain <= b.domain,
        };
        let mut rec = if take_old { old.next().unwrap()? } else { fresh.next().unwrap() };
        if take_old && fresh.peek().is_some_and(|f| f.domain == rec.domain) {
            let f = fresh.next().unwrap();
            rec.first = rec.first.min(f.first);
            rec.last = rec.last.max(f.last);
            rec.count += f.count;
        }
        out.push(rec)?;
    }
    Ok(())
}

/// Merges deltas up to `day` into a new snapshot and rebuilds the FSTs.
pub async fn run(data: &Path, day: &str) -> Result<()> {
    let dir = data.join("domains");
    std::fs::create_dir_all(&dir)?;
    let mut base = None;
    let mut deltas = Vec::new();
    for e in std::fs::read_dir(&dir)?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".parquet") {
            continue;
        }
        if let Some(d) = name.strip_prefix("snapshot-").and_then(|n| n.get(..10)) {
            if d < day && base.as_ref().is_none_or(|(b, _): &(String, PathBuf)| b.as_str() < d) {
                base = Some((d.to_string(), e.path()));
            }
        } else if name.strip_prefix("delta-").and_then(|n| n.get(..10)).is_some_and(|d| d <= day) {
            deltas.push(e.path());
        }
    }
    if deltas.is_empty() {
        return Ok(());
    }
    deltas.sort();

    let ctx = session(data, MEMORY, PARTITIONS)?;
    register_files(&ctx, "d", domains_schema(), &deltas).await?;
    let sql = "SELECT domain, MAX(skeleton) AS skeleton, MIN(first_seen) AS first_seen, \
               MAX(last_seen) AS last_seen, CAST(SUM(cert_count) AS BIGINT) AS cert_count \
               FROM d GROUP BY domain ORDER BY domain";
    let batches = ctx.sql(sql).await?.collect().await?;
    let new: Vec<Rec> = batches.iter().flat_map(recs).collect();

    let search = data.join("search");
    std::fs::create_dir_all(&search)?;
    let tmp = dir.join(format!("snapshot-{day}.parquet.tmp"));
    let fst_tmp = search.join("domains.fst.tmp");
    let skel_tmp = search.join("skeleton.fst.tmp");
    let mut out = Out {
        writer: ArrowWriter::try_new(std::fs::File::create(&tmp)?, domains_schema(), None)?,
        fst: fst::MapBuilder::new(BufWriter::new(std::fs::File::create(&fst_tmp)?))?,
        buf: Vec::new(),
    };

    merge(base.map(|b| b.1), new, &mut out)?;
    out.drain()?;
    let Out { writer, fst, .. } = out;
    writer.into_inner()?.sync_all()?;
    fst.finish()?;

    // The table is permanent and only grows, so this sort must be able to spill.
    let snapshot = dir.join(format!("snapshot-{day}.parquet"));
    std::fs::rename(tmp, &snapshot)?;
    let ctx = session(data, MEMORY, PARTITIONS)?;
    register_files(&ctx, "s", domains_schema(), &[snapshot]).await?;
    let mut sorted = ctx
        .sql("SELECT skeleton, domain FROM s ORDER BY skeleton, domain")
        .await?
        .execute_stream()
        .await?;
    let mut set = fst::SetBuilder::new(BufWriter::new(std::fs::File::create(&skel_tmp)?))?;
    let mut key = Vec::new();
    let mut last = Vec::new();
    while let Some(b) = sorted.next().await {
        let b = b?;
        let (skel, domain) = (cast_utf8(b.column(0))?, cast_utf8(b.column(1))?);
        let (skel, domain) = (skel.as_string::<i32>(), domain.as_string::<i32>());
        for i in 0..b.num_rows() {
            key.clear();
            key.extend_from_slice(skel.value(i).as_bytes());
            key.push(0);
            key.extend_from_slice(domain.value(i).as_bytes());
            if key != last {
                set.insert(&key)?;
                std::mem::swap(&mut key, &mut last);
            }
        }
    }
    set.finish()?;

    std::fs::rename(fst_tmp, search.join("domains.fst"))?;
    std::fs::rename(skel_tmp, search.join("skeleton.fst"))?;
    Ok(())
}
