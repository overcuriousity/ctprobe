use super::{certs_schema, day_string, domains_schema, rollup_minute_schema, sightings_schema};
use crate::names;
use crate::types::{CertRow, LogId, Sighting};
use anyhow::{Context, Result};
use arrow::array::{
    ArrayRef, BooleanBuilder, Int32Builder, Int64Builder, ListBuilder, RecordBatch, StringBuilder,
    TimestampMillisecondBuilder, UInt64Builder,
};
use arrow::datatypes::SchemaRef;
use chrono::Utc;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// `rollup_minute.log_id` of the row holding process-wide figures.
pub const MINUTE_GLOBAL_LOG: LogId = u16::MAX;

#[derive(Debug, Clone, Default)]
pub struct RollupMinuteRow {
    pub minute_ms: i64,
    pub log: LogId,
    pub entries: i64,
    pub bytes: i64,
    pub errors: i64,
    pub malformed: i64,
    pub http_429: i64,
    pub busy_ms: i64,
    pub peak_per_sec: i64,
    pub sct_lag_p50_ms: Option<i64>,
    pub sct_lag_p99_ms: Option<i64>,
    pub nb_lag_p50_ms: Option<i64>,
    pub nb_lag_p99_ms: Option<i64>,
    pub tracker_names: Option<i64>,
    pub tracker_bytes: Option<i64>,
    pub rss_bytes: Option<i64>,
    pub cpu_ms: Option<i64>,
    pub disk_bytes: Option<i64>,
    /// Raw entries across all logs this minute.
    pub raw_entries: Option<i64>,
    /// Entries behind on logs that are not rate-limiting us.
    pub backlog: Option<i64>,
    /// Entries behind on logs that sent a 429 in the last hour.
    pub limited_backlog: Option<i64>,
    /// Logs that fetched without errors this minute.
    pub healthy_logs: Option<i64>,
}

fn props() -> WriterProperties {
    WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(3).expect("valid level")))
        .set_max_row_group_size(1_000_000)
        .build()
}

/// Writes a batch to `path` via a synced temp file and rename.
pub fn write_batch(path: &Path, batch: &RecordBatch, props_override: Option<WriterProperties>) -> Result<()> {
    fs::create_dir_all(path.parent().context("no parent")?)?;
    let tmp = path.with_extension("parquet.tmp");
    let file = File::create(&tmp)?;
    let mut w = ArrowWriter::try_new(file, batch.schema(), Some(props_override.unwrap_or_else(props)))?;
    w.write(batch)?;
    w.into_inner()?.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Default)]
struct DomainDelta {
    first: i64,
    last: i64,
    count: i64,
}

/// Buffers rows and writes them as pending files. `publish` makes an epoch's
/// files visible; `open` resolves leftovers against the committed epoch.
pub struct Writer {
    dir: PathBuf,
    certs: Vec<CertRow>,
    sightings: Vec<Sighting>,
    rollups: Vec<RollupMinuteRow>,
    domains: HashMap<String, DomainDelta>,
    pending: Vec<(PathBuf, PathBuf)>,
}

fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk_files(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// `part-e12.parquet.pending` → epoch 12 and its published path.
fn pending_target(p: &Path) -> Option<(u64, PathBuf)> {
    let name = p.file_name()?.to_str()?;
    let stem = name.strip_suffix(".pending")?;
    let digits = stem.strip_suffix(".parquet")?.rsplit("-e").next()?;
    Some((digits.parse().ok()?, p.with_file_name(stem)))
}

impl Writer {
    pub fn open(dir: &Path, committed_epoch: u64) -> Result<Writer> {
        fs::create_dir_all(dir)?;
        let mut files = Vec::new();
        walk_files(dir, &mut files);
        for f in files {
            let s = f.to_string_lossy();
            if s.ends_with(".tmp") {
                fs::remove_file(&f)?;
            } else if s.ends_with(".pending") {
                match pending_target(&f) {
                    Some((e, target)) if e <= committed_epoch => fs::rename(&f, target)?,
                    _ => fs::remove_file(&f)?,
                }
            }
        }
        Ok(Writer {
            dir: dir.to_path_buf(),
            certs: Vec::new(),
            sightings: Vec::new(),
            rollups: Vec::new(),
            domains: HashMap::new(),
            pending: Vec::new(),
        })
    }

    pub fn push_cert(&mut self, row: CertRow) {
        for d in &row.reg_domains {
            let e = self.domains.entry(d.clone()).or_insert(DomainDelta {
                first: row.seen_at_ms,
                last: row.seen_at_ms,
                count: 0,
            });
            e.first = e.first.min(row.seen_at_ms);
            e.last = e.last.max(row.seen_at_ms);
            e.count += 1;
        }
        self.certs.push(row);
    }

    pub fn push_sighting(&mut self, s: Sighting) {
        self.sightings.push(s);
    }

    pub fn push_rollup(&mut self, r: RollupMinuteRow) {
        self.rollups.push(r);
    }

    pub fn buffered_certs(&self) -> usize {
        self.certs.len()
    }

    fn pending_path(&mut self, final_path: PathBuf, epoch_written: bool) -> PathBuf {
        let name = format!("{}.pending", final_path.file_name().unwrap().to_string_lossy());
        let pending = final_path.with_file_name(name);
        if epoch_written {
            self.pending.push((pending.clone(), final_path));
        }
        pending
    }

    fn write(&mut self, table: &str, day: &str, stamp: &str, batch: RecordBatch) -> Result<()> {
        let path = self.dir.join(table).join(format!("day={day}")).join(format!("part-{stamp}.parquet"));
        let pending = self.pending_path(path, true);
        write_pending(&pending, &batch)
    }

    /// Writes all buffered rows as pending files for `epoch`.
    pub fn flush(&mut self, epoch: u64) -> Result<()> {
        let stamp = format!("{}-e{epoch}", Utc::now().format("%H%M%S"));

        let mut by_day: BTreeMap<String, Vec<CertRow>> = BTreeMap::new();
        for r in self.certs.drain(..) {
            by_day.entry(day_string(r.seen_at_ms)).or_default().push(r);
        }
        for (day, rows) in by_day {
            let b = certs_batch(&rows)?;
            self.write("certs", &day, &stamp, b)?;
        }

        let mut by_day: BTreeMap<String, Vec<Sighting>> = BTreeMap::new();
        for s in self.sightings.drain(..) {
            by_day.entry(day_string(s.seen_at_ms)).or_default().push(s);
        }
        for (day, rows) in by_day {
            let b = sightings_batch(&rows)?;
            self.write("sightings", &day, &stamp, b)?;
        }

        let mut by_day: BTreeMap<String, Vec<RollupMinuteRow>> = BTreeMap::new();
        for r in self.rollups.drain(..) {
            by_day.entry(day_string(r.minute_ms)).or_default().push(r);
        }
        for (day, rows) in by_day {
            let b = rollup_batch(&rows)?;
            self.write("rollup_minute", &day, &stamp, b)?;
        }

        if !self.domains.is_empty() {
            let map = std::mem::take(&mut self.domains);
            let day = map.values().map(|d| d.first).min().map(day_string).unwrap_or_default();
            let mut rows: Vec<_> = map.into_iter().collect();
            rows.sort_by(|a, b| a.0.cmp(&b.0));
            let b = domains_batch(&rows)?;
            let path = self.dir.join("domains").join(format!("delta-{day}-{stamp}.parquet"));
            let pending = self.pending_path(path, true);
            write_pending(&pending, &b)?;
        }
        Ok(())
    }

    /// Makes the files of the last `flush` visible.
    pub fn publish(&mut self, _epoch: u64) -> Result<()> {
        for (from, to) in self.pending.drain(..) {
            fs::rename(from, to)?;
        }
        Ok(())
    }
}

fn write_pending(path: &Path, batch: &RecordBatch) -> Result<()> {
    fs::create_dir_all(path.parent().context("no parent")?)?;
    let file = File::create(path)?;
    let mut w = ArrowWriter::try_new(file, batch.schema(), Some(props()))?;
    w.write(batch)?;
    w.into_inner()?.sync_all()?;
    Ok(())
}

fn batch(schema: SchemaRef, cols: Vec<ArrayRef>) -> Result<RecordBatch> {
    Ok(RecordBatch::try_new(schema, cols)?)
}

fn certs_batch(rows: &[CertRow]) -> Result<RecordBatch> {
    let ts = |f: &dyn Fn(&CertRow) -> i64| -> ArrayRef {
        let mut b = TimestampMillisecondBuilder::with_capacity(rows.len());
        rows.iter().for_each(|r| b.append_value(f(r)));
        Arc::new(b.finish())
    };
    let s = |f: &dyn Fn(&CertRow) -> Option<String>| -> ArrayRef {
        let mut b = StringBuilder::new();
        rows.iter().for_each(|r| b.append_option(f(r)));
        Arc::new(b.finish())
    };
    let i32c = |f: &dyn Fn(&CertRow) -> Option<i32>| -> ArrayRef {
        let mut b = Int32Builder::with_capacity(rows.len());
        rows.iter().for_each(|r| b.append_option(f(r)));
        Arc::new(b.finish())
    };
    let i64c = |f: &dyn Fn(&CertRow) -> i64| -> ArrayRef {
        let mut b = Int64Builder::with_capacity(rows.len());
        rows.iter().for_each(|r| b.append_value(f(r)));
        Arc::new(b.finish())
    };
    let boolc = |f: &dyn Fn(&CertRow) -> bool| -> ArrayRef {
        let mut b = BooleanBuilder::with_capacity(rows.len());
        rows.iter().for_each(|r| b.append_value(f(r)));
        Arc::new(b.finish())
    };
    let listc = |f: &dyn Fn(&CertRow) -> &Vec<String>| -> ArrayRef {
        let mut b = ListBuilder::new(StringBuilder::new());
        for r in rows {
            for v in f(r) {
                b.values().append_value(v);
            }
            b.append(true);
        }
        Arc::new(b.finish())
    };
    let mut hash = UInt64Builder::with_capacity(rows.len());
    rows.iter().for_each(|r| hash.append_value(r.cert_hash));
    batch(
        certs_schema(),
        vec![
            ts(&|r| r.seen_at_ms),
            ts(&|r| r.parsed.not_before_ms),
            ts(&|r| r.parsed.not_after_ms),
            s(&|r| Some(r.parsed.issuer_cn.clone())),
            s(&|r| Some(r.parsed.issuer_org.clone())),
            s(&|r| Some(r.parsed.serial_hex.clone())),
            s(&|r| r.parsed.subject_cn.clone()),
            listc(&|r| &r.parsed.names),
            listc(&|r| &r.reg_domains),
            s(&|r| r.primary_domain.clone()),
            s(&|r| {
                r.primary_domain.as_deref().and_then(psl::suffix_str).map(str::to_string)
            }),
            i32c(&|r| Some(r.parsed.san_count as i32)),
            i32c(&|r| {
                Some(r.parsed.names.iter().map(|n| names::depth(n)).max().unwrap_or(0) as i32)
            }),
            s(&|r| Some(r.parsed.key_type.clone())),
            i32c(&|r| Some(r.parsed.key_bits as i32)),
            s(&|r| Some(r.parsed.sig_type.clone())),
            boolc(&|r| r.is_precert),
            boolc(&|r| r.is_wildcard),
            s(&|r| Some(r.renewal.as_str().to_string())),
            i32c(&|r| r.days_since_seen.map(|d| d as i32)),
            i32c(&|r| Some(r.new_names as i32)),
            i32c(&|r| Some(r.new_domains as i32)),
            i32c(&|r| Some(r.log as i32)),
            i64c(&|r| r.index as i64),
            i32c(&|r| Some(r.der_size as i32)),
            i64c(&|r| r.sct_lag_ms),
            i64c(&|r| r.not_before_lag_ms),
            Arc::new(hash.finish()),
        ],
    )
}

fn sightings_batch(rows: &[Sighting]) -> Result<RecordBatch> {
    let mut h = UInt64Builder::with_capacity(rows.len());
    let mut l = Int32Builder::with_capacity(rows.len());
    let mut t = TimestampMillisecondBuilder::with_capacity(rows.len());
    for r in rows {
        h.append_value(r.cert_hash);
        l.append_value(r.log as i32);
        t.append_value(r.seen_at_ms);
    }
    batch(sightings_schema(), vec![Arc::new(h.finish()), Arc::new(l.finish()), Arc::new(t.finish())])
}

fn rollup_batch(rows: &[RollupMinuteRow]) -> Result<RecordBatch> {
    let opt = |f: &dyn Fn(&RollupMinuteRow) -> Option<i64>| -> ArrayRef {
        let mut b = Int64Builder::with_capacity(rows.len());
        rows.iter().for_each(|r| b.append_option(f(r)));
        Arc::new(b.finish())
    };
    let mut t = TimestampMillisecondBuilder::with_capacity(rows.len());
    let mut l = Int32Builder::with_capacity(rows.len());
    for r in rows {
        t.append_value(r.minute_ms);
        l.append_value(r.log as i32);
    }
    batch(
        rollup_minute_schema(),
        vec![
            Arc::new(t.finish()),
            Arc::new(l.finish()),
            opt(&|r| Some(r.entries)),
            opt(&|r| Some(r.bytes)),
            opt(&|r| Some(r.errors)),
            opt(&|r| Some(r.malformed)),
            opt(&|r| Some(r.http_429)),
            opt(&|r| Some(r.busy_ms)),
            opt(&|r| Some(r.peak_per_sec)),
            opt(&|r| r.sct_lag_p50_ms),
            opt(&|r| r.sct_lag_p99_ms),
            opt(&|r| r.nb_lag_p50_ms),
            opt(&|r| r.nb_lag_p99_ms),
            opt(&|r| r.tracker_names),
            opt(&|r| r.tracker_bytes),
            opt(&|r| r.rss_bytes),
            opt(&|r| r.cpu_ms),
            opt(&|r| r.disk_bytes),
            opt(&|r| r.raw_entries),
            opt(&|r| r.backlog),
            opt(&|r| r.limited_backlog),
            opt(&|r| r.healthy_logs),
        ],
    )
}

fn domains_batch(rows: &[(String, DomainDelta)]) -> Result<RecordBatch> {
    let mut d = StringBuilder::new();
    let mut s = StringBuilder::new();
    let mut f = TimestampMillisecondBuilder::with_capacity(rows.len());
    let mut l = TimestampMillisecondBuilder::with_capacity(rows.len());
    let mut c = Int64Builder::with_capacity(rows.len());
    for (name, e) in rows {
        d.append_value(name);
        s.append_value(names::skeleton(name));
        f.append_value(e.first);
        l.append_value(e.last);
        c.append_value(e.count);
    }
    batch(
        domains_schema(),
        vec![
            Arc::new(d.finish()),
            Arc::new(s.finish()),
            Arc::new(f.finish()),
            Arc::new(l.finish()),
            Arc::new(c.finish()),
        ],
    )
}

