//! Which logs a coverage target needs, read from recent sightings. It reads the
//! Parquet files directly: grouping every sighting by certificate is more than
//! the SQL memory pool can hold.

use crate::store::{day_string, list_parts};
use crate::types::LogId;
use anyhow::{bail, Result};
use arrow::array::AsArray;
use arrow::datatypes::{Int32Type, TimestampMillisecondType, UInt64Type};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub type Mask = [u64; 4];

const MAX_KEYS: usize = 256;
/// One certificate in this many is kept, chosen by hash.
const SAMPLE: u64 = 8;
/// With the sample, this covers about 32 million certificates a day.
const MAX_CERTS: usize = 4_000_000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogCoverage {
    pub id: LogId,
    pub share_pct: f64,
    pub alone_pct: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Step {
    pub key: String,
    pub added_pct: f64,
    pub cumulative_pct: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageReport {
    pub computed_ms: i64,
    pub window_ms: i64,
    pub sampled_certs: u64,
    pub logs: Vec<LogCoverage>,
    /// Logs, best first. Keys are log IDs.
    pub order: Vec<Step>,
    /// Operators, best first. Keys are operator names.
    pub operators: Vec<Step>,
}

fn bits(m: &Mask) -> impl Iterator<Item = usize> + '_ {
    m.iter().enumerate().flat_map(|(w, word)| {
        (0..64).filter(move |b| word & (1 << b) != 0).map(move |b| w * 64 + b)
    })
}

/// Best order of keys as (bit, certificates added), lowest `tie` first on equal counts.
pub fn greedy_by<T: Ord + Copy>(
    mut sets: Vec<(Mask, u64)>,
    keys: usize,
    tie: impl Fn(usize) -> T,
) -> Vec<(usize, u64)> {
    let mut out = Vec::new();
    loop {
        let mut counts = vec![0u64; keys.min(MAX_KEYS)];
        for (mask, n) in &sets {
            bits(mask).for_each(|b| counts[b] += n);
        }
        let best = (0..counts.len()).max_by_key(|i| (counts[*i], std::cmp::Reverse(tie(*i))));
        let Some(best) = best.filter(|b| counts[*b] > 0) else { break };
        out.push((best, counts[best]));
        sets.retain(|(m, _)| m[best / 64] & (1 << (best % 64)) == 0);
    }
    out
}

pub fn greedy(sets: Vec<(Mask, u64)>, keys: usize) -> Vec<(usize, u64)> {
    greedy_by(sets, keys, |i| i)
}

/// How many steps reach `target`, or all of them if it cannot be reached.
pub fn needed_for(steps: &[Step], target: f64) -> usize {
    steps.iter().position(|s| s.cumulative_pct >= target).map_or(steps.len(), |i| i + 1)
}

/// Which keys hold each certificate, bounded so a huge day cannot exhaust memory.
pub struct Collector {
    cap: usize,
    pub certs: HashMap<u64, Mask>,
}

impl Collector {
    pub fn new(cap: usize) -> Collector {
        Collector { cap, certs: HashMap::new() }
    }

    pub fn add(&mut self, hash: u64, bit: usize) {
        let len = self.certs.len();
        if let Some(m) = self.certs.get_mut(&hash) {
            m[bit / 64] |= 1 << (bit % 64);
        } else if len < self.cap {
            let mut m = [0u64; 4];
            m[bit / 64] |= 1 << (bit % 64);
            self.certs.insert(hash, m);
        }
    }

    /// Certificates grouped by the logs that hold them, which is far smaller.
    pub fn grouped(&self) -> HashMap<Mask, u64> {
        let mut out: HashMap<Mask, u64> = HashMap::new();
        for m in self.certs.values() {
            *out.entry(*m).or_default() += 1;
        }
        out
    }
}

fn files_since(data: &Path, since_ms: i64) -> Vec<PathBuf> {
    let first = format!("day={}", day_string(since_ms));
    list_parts(data, "sightings")
        .into_iter()
        .filter(|p| {
            p.parent().and_then(|d| d.file_name()).is_some_and(|d| d.to_string_lossy().as_ref() >= first.as_str())
        })
        .collect()
}

fn read_file(
    path: &Path,
    since_ms: i64,
    dense: &HashMap<i32, usize>,
    c: &mut Collector,
    stop: &impl Fn() -> bool,
) -> Result<()> {
    let r = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path)?)?.build()?;
    for b in r {
        if stop() {
            bail!("stopped");
        }
        let b = b?;
        let hashes = b.column(0).as_primitive::<UInt64Type>();
        let logs = b.column(1).as_primitive::<Int32Type>();
        let seen = b.column(2).as_primitive::<TimestampMillisecondType>();
        for i in 0..b.num_rows() {
            let h = hashes.value(i);
            if h % SAMPLE != 0 || seen.value(i) < since_ms {
                continue;
            }
            if let Some(bit) = dense.get(&logs.value(i)) {
                c.add(h, *bit);
            }
        }
    }
    Ok(())
}

fn steps(order: Vec<(usize, u64)>, total: u64, key: impl Fn(usize) -> String) -> Vec<Step> {
    let mut covered = 0;
    order
        .into_iter()
        .map(|(bit, added)| {
            covered += added;
            Step {
                key: key(bit),
                added_pct: 100.0 * added as f64 / total as f64,
                cumulative_pct: 100.0 * covered as f64 / total as f64,
            }
        })
        .collect()
}

/// Assesses sightings since `since_ms`. `logs` holds each log's ID, operator and
/// whether it counts. A file that vanishes mid-run, as compaction and expiry do
/// to files, is skipped. Fails if `stop` turns true.
pub fn assess(
    data: &Path,
    since_ms: i64,
    logs: &[(LogId, String, bool)],
    stop: impl Fn() -> bool,
) -> Result<CoverageReport> {
    let included: Vec<_> = logs.iter().filter(|l| l.2).take(MAX_KEYS).collect();
    let dense: HashMap<i32, usize> = included.iter().enumerate().map(|(i, l)| (l.0 as i32, i)).collect();
    let mut c = Collector::new(MAX_CERTS);
    for f in files_since(data, since_ms) {
        if let Err(e) = read_file(&f, since_ms, &dense, &mut c, &stop) {
            if stop() {
                bail!("stopped");
            }
            tracing::debug!("skipping {}: {e:#}", f.display());
        }
    }
    let total = c.certs.len() as u64;
    let now = chrono::Utc::now().timestamp_millis();
    let mut report = CoverageReport { computed_ms: now, window_ms: now - since_ms, sampled_certs: total, ..Default::default() };
    if total == 0 {
        return Ok(report);
    }
    let groups = c.grouped();
    let mut held = vec![0u64; included.len()];
    let mut alone = vec![0u64; included.len()];
    for (m, n) in &groups {
        let on: Vec<usize> = bits(m).collect();
        on.iter().for_each(|b| held[*b] += n);
        if let [only] = on[..] {
            alone[only] += n;
        }
    }
    let pct = |n: u64| 100.0 * n as f64 / total as f64;
    report.logs = included
        .iter()
        .enumerate()
        .map(|(i, l)| LogCoverage { id: l.0, share_pct: pct(held[i]), alone_pct: pct(alone[i]) })
        .collect();
    let sets: Vec<(Mask, u64)> = groups.iter().map(|(m, n)| (*m, *n)).collect();
    report.order = steps(greedy(sets.clone(), included.len()), total, |b| included[b].0.to_string());

    let mut names: Vec<&str> = included.iter().map(|l| l.1.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    let op_bit: Vec<usize> = included
        .iter()
        .map(|l| names.iter().position(|n| *n == l.1).unwrap_or(0))
        .collect();
    let mut by_op: HashMap<Mask, u64> = HashMap::new();
    for (m, n) in sets {
        let mut o = [0u64; 4];
        bits(&m).map(|b| op_bit[b]).for_each(|b| o[b / 64] |= 1 << (b % 64));
        *by_op.entry(o).or_default() += n;
    }
    report.operators = steps(greedy(by_op.into_iter().collect(), names.len()), total, |b| names[b].to_string());
    Ok(report)
}

pub fn save(report: &CoverageReport, path: &Path) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(report)?)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

pub fn load(path: &Path) -> Option<CoverageReport> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{sightings_schema, write_batch};
    use arrow::array::{ArrayRef, Int32Array, RecordBatch, TimestampMillisecondArray, UInt64Array};
    use std::sync::Arc;

    const T0: i64 = 1_793_600_000_000;

    fn write(dir: &Path, name: &str, rows: &[(u64, i32, i64)]) {
        let cols: Vec<ArrayRef> = vec![
            Arc::new(UInt64Array::from_iter_values(rows.iter().map(|r| r.0))),
            Arc::new(Int32Array::from_iter_values(rows.iter().map(|r| r.1))),
            Arc::new(TimestampMillisecondArray::from_iter_values(rows.iter().map(|r| r.2))),
        ];
        let b = RecordBatch::try_new(sightings_schema(), cols).unwrap();
        let day = crate::store::day_string(T0);
        let p = dir.join("sightings").join(format!("day={day}")).join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        write_batch(&p, &b, None).unwrap();
    }

    fn logs(ops: &[&str]) -> Vec<(LogId, String, bool)> {
        ops.iter().enumerate().map(|(i, o)| (i as LogId, o.to_string(), true)).collect()
    }

    fn mask(bits: &[usize]) -> Mask {
        let mut m = [0u64; 4];
        for b in bits {
            m[b / 64] |= 1 << (b % 64);
        }
        m
    }

    #[test]
    fn greedy_prefers_largest_then_lowest_id() {
        let sets = vec![(mask(&[1]), 5), (mask(&[2]), 5), (mask(&[0, 3]), 9)];
        let order = greedy(sets, 4);
        assert_eq!(order, vec![(0, 9), (1, 5), (2, 5)]);
    }

    #[test]
    fn greedy_counts_only_what_a_log_adds() {
        let order = greedy(vec![(mask(&[0, 1]), 10), (mask(&[1]), 1)], 2);
        assert_eq!(order, vec![(1, 11)]);
    }

    #[test]
    fn sample_keeps_one_hash_in_eight() {
        let dir = tempfile::tempdir().unwrap();
        let rows: Vec<_> = (0..80u64).map(|h| (h, 0, T0)).collect();
        write(dir.path(), "a.parquet", &rows);
        let r = assess(dir.path(), T0 - 1, &logs(&["A"]), || false).unwrap();
        assert_eq!(r.sampled_certs, 10);
    }

    #[test]
    fn shares_and_alone_are_percentages() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.parquet", &[(0, 0, T0), (8, 0, T0), (8, 1, T0), (16, 1, T0)]);
        let r = assess(dir.path(), T0 - 1, &logs(&["A", "B"]), || false).unwrap();
        let l0 = r.logs.iter().find(|l| l.id == 0).unwrap();
        assert!((l0.share_pct - 200.0 / 3.0).abs() < 0.01);
        assert!((l0.alone_pct - 100.0 / 3.0).abs() < 0.01);
        assert_eq!(r.order.last().unwrap().cumulative_pct, 100.0);
    }

    #[test]
    fn operator_order_merges_a_operators_logs() {
        let dir = tempfile::tempdir().unwrap();
        let rows = [(0, 0, T0), (8, 1, T0), (16, 2, T0)];
        write(dir.path(), "a.parquet", &rows);
        let r = assess(dir.path(), T0 - 1, &logs(&["A", "A", "B"]), || false).unwrap();
        assert_eq!(r.operators[0].key, "A");
        assert_eq!(r.operators.len(), 2);
        assert_eq!(r.order[0].key, "0");
    }

    #[test]
    fn needed_for_stops_at_target() {
        let s = |c| Step { key: "x".into(), added_pct: 0.0, cumulative_pct: c };
        assert_eq!(needed_for(&[s(60.0), s(95.0), s(99.0)], 95.0), 2);
        assert_eq!(needed_for(&[s(60.0)], 95.0), 1);
        assert_eq!(needed_for(&[], 95.0), 0);
    }

    #[test]
    fn missing_file_during_read_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.parquet", &[(0, 0, T0)]);
        let day = crate::store::day_string(T0);
        std::fs::write(dir.path().join("sightings").join(format!("day={day}")).join("b.parquet"), b"junk").unwrap();
        let r = assess(dir.path(), T0 - 1, &logs(&["A"]), || false).unwrap();
        assert_eq!(r.sampled_certs, 1);
    }

    #[test]
    fn certificate_cap_bounds_memory() {
        let mut c = Collector::new(2);
        c.add(8, 0);
        c.add(16, 0);
        c.add(24, 0);
        c.add(8, 1);
        assert_eq!(c.certs.len(), 2);
        assert_eq!(c.certs[&8], mask(&[0, 1]));
    }

    #[test]
    fn test_logs_are_left_out() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.parquet", &[(0, 0, T0), (8, 1, T0)]);
        let list = vec![(0, "A".to_string(), true), (1, "T".to_string(), false)];
        let r = assess(dir.path(), T0 - 1, &list, || false).unwrap();
        assert_eq!(r.sampled_certs, 1);
        assert!(r.logs.iter().all(|l| l.id == 0));
    }

    #[test]
    fn rows_before_the_window_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.parquet", &[(0, 0, T0 - 5000), (8, 0, T0)]);
        let r = assess(dir.path(), T0 - 1, &logs(&["A"]), || false).unwrap();
        assert_eq!(r.sampled_certs, 1);
    }

    #[test]
    fn empty_store_gives_an_empty_report() {
        let dir = tempfile::tempdir().unwrap();
        let r = assess(dir.path(), T0, &logs(&["A"]), || false).unwrap();
        assert_eq!(r.sampled_certs, 0);
        assert!(r.order.is_empty());
    }

    #[test]
    fn stopping_abandons_the_run() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.parquet", &[(0, 0, T0)]);
        assert!(assess(dir.path(), T0 - 1, &logs(&["A"]), || true).is_err());
    }

    #[test]
    fn report_round_trips_through_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("coverage.json");
        assert!(load(&p).is_none());
        let r = CoverageReport { computed_ms: 5, ..Default::default() };
        save(&r, &p).unwrap();
        assert_eq!(load(&p).unwrap().computed_ms, 5);
        std::fs::write(&p, b"junk").unwrap();
        assert!(load(&p).is_none());
    }
}
