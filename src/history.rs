//! Rate history of the last 24 hours, kept by the server so that a reload or a
//! restart does not lose it.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

const BUCKET_S: i64 = 10;
const BUCKETS: usize = 8640;
/// Buckets in the 60-second window behind each charted rate.
const RATE_BUCKETS: i64 = 6;
pub const MAX_POINTS: usize = 360;

/// What happened during one bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    pub raw: u32,
    pub unique: u32,
    pub names: u32,
    pub new_names: u32,
    pub new_domains: u32,
    /// First DNS probes of certificate names, and those that found an address.
    /// Absent from files written before DNS probing.
    #[serde(default)]
    pub dns_probed: u32,
    #[serde(default)]
    pub dns_resolved: u32,
}

impl Counts {
    fn add(&mut self, o: &Counts) {
        self.raw = self.raw.saturating_add(o.raw);
        self.unique = self.unique.saturating_add(o.unique);
        self.names = self.names.saturating_add(o.names);
        self.new_names = self.new_names.saturating_add(o.new_names);
        self.new_domains = self.new_domains.saturating_add(o.new_domains);
        self.dns_probed = self.dns_probed.saturating_add(o.dns_probed);
        self.dns_resolved = self.dns_resolved.saturating_add(o.dns_resolved);
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Totals {
    pub raw: u64,
    pub unique: u64,
    pub names: u64,
    pub new_names: u64,
    pub new_domains: u64,
    pub dns_probed: u64,
    pub dns_resolved: u64,
    /// Seconds of the frame with data, so averages ignore downtime.
    pub seconds: u64,
}

/// A time frame as 60-second rates. `None` marks time without data.
#[derive(Debug, Default, Clone, Serialize)]
pub struct HistoryView {
    pub step_s: u32,
    pub t: Vec<i64>,
    pub raw: Vec<Option<f64>>,
    pub unique: Vec<Option<f64>>,
    pub new_names: Vec<Option<f64>>,
    pub new_domains: Vec<Option<f64>>,
    pub totals: Totals,
}

/// A ring of 10-second buckets. Each slot knows its time, so stale slots from an
/// earlier day never read as current.
#[derive(Clone)]
pub struct History {
    slots: Vec<Option<(i64, Counts)>>,
}

impl Default for History {
    fn default() -> Self {
        History::new()
    }
}

fn slot(t: i64) -> usize {
    (t / BUCKET_S).rem_euclid(BUCKETS as i64) as usize
}

impl History {
    pub fn new() -> History {
        History { slots: vec![None; BUCKETS] }
    }

    pub fn add(&mut self, now_s: i64, c: Counts) {
        let t = now_s - now_s.rem_euclid(BUCKET_S);
        match &mut self.slots[slot(t)] {
            Some((at, have)) if *at == t => have.add(&c),
            s => *s = Some((t, c)),
        }
    }

    fn get(&self, t: i64) -> Option<&Counts> {
        self.slots[slot(t)].as_ref().filter(|(at, _)| *at == t).map(|(_, c)| c)
    }

    /// The 60-second rates at bucket `t`, from the buckets that exist.
    fn rates_at(&self, t: i64) -> Option<[f64; 4]> {
        self.get(t)?;
        let mut sum = Counts::default();
        let mut n = 0;
        for i in 0..RATE_BUCKETS {
            if let Some(c) = self.get(t - i * BUCKET_S) {
                sum.add(c);
                n += 1;
            }
        }
        let secs = (n * BUCKET_S) as f64;
        Some([sum.raw, sum.unique, sum.new_names, sum.new_domains].map(|v| v as f64 / secs))
    }

    pub fn view(&self, minutes: u32, now_s: i64) -> HistoryView {
        let n = minutes.clamp(1, (BUCKETS / 6) as u32) as i64 * 6;
        let end = now_s - now_s.rem_euclid(BUCKET_S);
        let start = end - (n - 1) * BUCKET_S;
        let mut v = HistoryView::default();
        for t in (start..=end).step_by(BUCKET_S as usize) {
            if let Some(c) = self.get(t) {
                v.totals.raw += c.raw as u64;
                v.totals.unique += c.unique as u64;
                v.totals.names += c.names as u64;
                v.totals.new_names += c.new_names as u64;
                v.totals.new_domains += c.new_domains as u64;
                v.totals.dns_probed += c.dns_probed as u64;
                v.totals.dns_resolved += c.dns_resolved as u64;
                v.totals.seconds += BUCKET_S as u64;
            }
        }
        let per_point = (n as usize).div_ceil(MAX_POINTS) as i64;
        let step = per_point * BUCKET_S;
        let points = n / per_point;
        // Aligned to the step, so old points keep their values as time moves on.
        let last = end - end.rem_euclid(step);
        for p in 0..points {
            let from = last - (points - 1 - p) * step;
            let mut sum = [0.0; 4];
            let mut got = 0;
            for i in 0..per_point {
                let t = from + i * BUCKET_S;
                // The current bucket is still filling, and would read low.
                if t < end {
                    if let Some(r) = self.rates_at(t) {
                        (0..4).for_each(|k| sum[k] += r[k]);
                        got += 1;
                    }
                }
            }
            let mean = |k: usize| (got > 0).then(|| sum[k] / got as f64);
            v.t.push(from);
            v.raw.push(mean(0));
            v.unique.push(mean(1));
            v.new_names.push(mean(2));
            v.new_domains.push(mean(3));
        }
        v.step_s = step as u32;
        v
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let rows: Vec<&(i64, Counts)> = self.slots.iter().flatten().collect();
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(&rows)?)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    /// Starts empty if the file is missing or unreadable: history is a
    /// convenience and must never stop collection.
    pub fn load(path: &Path, now_s: i64) -> History {
        let mut h = History::new();
        let rows: Vec<(i64, Counts)> = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                tracing::warn!("ignoring rate history {}: {e}", path.display());
                Vec::new()
            }),
            Err(_) => Vec::new(),
        };
        for (t, c) in rows {
            if now_s - t < (BUCKETS as i64) * BUCKET_S {
                h.slots[slot(t)] = Some((t, c));
            }
        }
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_793_650_000;

    fn raw(n: u32) -> Counts {
        Counts { raw: n, ..Counts::default() }
    }

    fn last_some(v: &[Option<f64>]) -> f64 {
        v.iter().rev().flatten().next().copied().unwrap()
    }

    #[test]
    fn buckets_are_ten_seconds_and_ring_holds_a_day() {
        let mut h = History::new();
        h.add(T, raw(5));
        assert_eq!(h.view(1440, T + 5).totals.raw, 5);
        h.add(T + 86_401, raw(7));
        assert_eq!(h.view(1440, T + 86_401).totals.raw, 7);
    }

    #[test]
    fn same_bucket_accumulates() {
        let mut h = History::new();
        h.add(T - T % 10, raw(5));
        h.add(T - T % 10 + 3, raw(5));
        assert_eq!(h.view(5, T).totals.raw, 10);
    }

    #[test]
    fn view_gives_60s_rates() {
        let mut h = History::new();
        let t0 = T - T % 10;
        for i in 0..6 {
            h.add(t0 + i * 10, raw(60));
        }
        let v = h.view(5, t0 + 60);
        assert_eq!(last_some(&v.raw), 6.0);
    }

    #[test]
    fn unfinished_bucket_does_not_drag_the_newest_point_down() {
        let mut h = History::new();
        let t0 = T - T % 10;
        for i in 0..7 {
            h.add(t0 + i * 10, raw(60));
        }
        h.add(t0 + 70, raw(1)); // One second into this bucket.
        let v = h.view(5, t0 + 71);
        assert_eq!(last_some(&v.raw), 6.0, "{:?}", v.raw);
    }

    #[test]
    fn view_marks_gaps_as_none() {
        let mut h = History::new();
        let t0 = T - T % 10;
        h.add(t0, raw(10));
        h.add(t0 + 600, raw(10));
        let v = h.view(30, t0 + 610);
        let some = v.raw.iter().flatten().count();
        assert!(some >= 2 && some < v.raw.len(), "{:?}", v.raw);
        let first = v.raw.iter().position(|x| x.is_some()).unwrap();
        let last = v.raw.iter().rposition(|x| x.is_some()).unwrap();
        assert!(v.raw[first..last].iter().any(|x| x.is_none()));
    }

    #[test]
    fn view_is_capped_at_360_points() {
        let mut h = History::new();
        for i in 0..8640 {
            h.add(T + i * 10, raw(1));
        }
        let v = h.view(1440, T + 86_390);
        assert!(v.t.len() <= MAX_POINTS, "{}", v.t.len());
        assert_eq!(v.t.len(), v.raw.len());
        assert_eq!(v.t.len(), v.new_domains.len());
        assert_eq!(v.step_s, 240);
    }

    #[test]
    fn totals_sum_the_frame() {
        let mut h = History::new();
        let t0 = T - T % 10;
        h.add(t0, Counts { unique: 100, ..Counts::default() });
        h.add(t0 + 3000, Counts { unique: 7, ..Counts::default() });
        let v = h.view(5, t0 + 3000);
        assert_eq!(v.totals.unique, 7);
        assert_eq!(v.totals.seconds, 10);
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.json");
        let mut h = History::new();
        h.add(T, raw(42));
        h.save(&p).unwrap();
        let back = History::load(&p, T + 5);
        assert_eq!(back.view(5, T + 5).totals.raw, 42);
    }

    #[test]
    fn missing_file_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::load(&dir.path().join("none"), T);
        assert_eq!(h.view(5, T).totals.raw, 0);
    }

    #[test]
    fn corrupt_file_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.json");
        std::fs::write(&p, b"\x00junk").unwrap();
        let h = History::load(&p, T);
        assert_eq!(h.view(5, T).totals.raw, 0);
    }

    #[test]
    fn restart_after_two_days_shows_only_gaps() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.json");
        let mut h = History::new();
        h.add(T, raw(42));
        h.save(&p).unwrap();
        let later = T + 2 * 86_400;
        let v = History::load(&p, later).view(1440, later);
        assert_eq!(v.totals.raw, 0);
        assert!(v.raw.iter().all(|x| x.is_none()));
    }

    #[test]
    fn clock_going_backwards_does_not_panic() {
        let mut h = History::new();
        h.add(T, raw(1));
        h.add(T - 3600, raw(1));
        let v = h.view(5, T - 3600);
        assert_eq!(v.t.len(), v.raw.len());
    }

    #[test]
    fn empty_view_is_valid() {
        let v = History::new().view(5, T);
        assert_eq!(v.totals.raw, 0);
        assert_eq!(v.t.len(), v.raw.len());
    }
}
