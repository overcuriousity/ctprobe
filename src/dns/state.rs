//! The last conclusive answer per name, kept to tell whether DNS changed
//! between certificates. Held in memory under a cap and saved as a snapshot;
//! a crash loses what changed since the last one, which then reads as unknown.

use super::outcome::Fingerprint;
use anyhow::{bail, Result};
use hashbrown::HashMap;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"CTPDNS01";
const RECORD: usize = 22; // key, exact, network, day
/// Key, value and control byte of one table slot.
const SLOT_BYTES: u64 = std::mem::size_of::<(u64, Last)>() as u64 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Last {
    pub fp: Fingerprint,
    /// Days since the Unix epoch.
    pub day: u16,
}

pub struct LastAnswers {
    path: PathBuf,
    map: HashMap<u64, Last>,
    max_len: usize,
}

/// Entries that fit in `max_bytes` without the table growing past it.
fn max_len(max_bytes: u64) -> usize {
    let slots = (max_bytes / SLOT_BYTES).max(16);
    let buckets = 1u64 << (63 - slots.leading_zeros());
    (buckets / 8 * 7) as usize
}

impl LastAnswers {
    /// Loads `path` if it exists. An unreadable snapshot is set aside, not fatal.
    pub fn open(path: &Path, max_bytes: u64) -> LastAnswers {
        let mut s = LastAnswers { path: path.to_path_buf(), map: HashMap::new(), max_len: max_len(max_bytes) };
        if path.exists() {
            if let Err(e) = s.load() {
                tracing::warn!("ignoring DNS state {}: {e:#}", path.display());
                s.map.clear();
            }
        }
        while s.map.len() > s.max_len {
            s.evict_half();
        }
        s
    }

    fn load(&mut self) -> Result<()> {
        let mut r = BufReader::with_capacity(1 << 20, File::open(&self.path)?);
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            bail!("bad magic");
        }
        let mut n = [0u8; 8];
        r.read_exact(&mut n)?;
        let count = u64::from_le_bytes(n) as usize;
        self.map.reserve(count.min(self.max_len));
        let mut rec = [0u8; RECORD];
        for _ in 0..count {
            r.read_exact(&mut rec)?;
            let key = u64::from_le_bytes(rec[..8].try_into().unwrap());
            let exact = u64::from_le_bytes(rec[8..16].try_into().unwrap());
            let network = u32::from_le_bytes(rec[16..20].try_into().unwrap());
            let day = u16::from_le_bytes(rec[20..22].try_into().unwrap());
            self.map.insert(key, Last { fp: Fingerprint { exact, network }, day });
        }
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        let tmp = self.path.with_extension("snap.tmp");
        let mut w = BufWriter::with_capacity(1 << 20, File::create(&tmp)?);
        w.write_all(MAGIC)?;
        w.write_all(&(self.map.len() as u64).to_le_bytes())?;
        for (k, v) in &self.map {
            w.write_all(&k.to_le_bytes())?;
            w.write_all(&v.fp.exact.to_le_bytes())?;
            w.write_all(&v.fp.network.to_le_bytes())?;
            w.write_all(&v.day.to_le_bytes())?;
        }
        w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn get(&self, name_hash: u64) -> Option<Last> {
        self.map.get(&name_hash).copied()
    }

    pub fn put(&mut self, name_hash: u64, last: Last) {
        if self.map.len() >= self.max_len && !self.map.contains_key(&name_hash) {
            self.evict_half();
        }
        self.map.insert(name_hash, last);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn bytes_used(&self) -> u64 {
        self.map.allocation_size() as u64
    }

    /// Forgets the oldest half by day; within one day, an arbitrary half.
    fn evict_half(&mut self) {
        let mut days: BTreeMap<u16, usize> = BTreeMap::new();
        for v in self.map.values() {
            *days.entry(v.day).or_default() += 1;
        }
        let target = self.map.len() / 2;
        let (mut removed, mut cutoff) = (0, 0);
        for (d, n) in days {
            removed += n;
            cutoff = d;
            if removed >= target {
                break;
            }
        }
        let by_day = removed < self.map.len();
        // Rebuilt rather than filtered in place: tombstones would count as
        // occupied and make the next insert double the table.
        let mut kept = HashMap::with_capacity(self.max_len);
        kept.extend(self.map.drain().filter(|(k, v)| if by_day { v.day > cutoff } else { k & 1 == 0 }));
        self.map = kept;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn last(exact: u64, day: u16) -> Last {
        Last { fp: Fingerprint { exact, network: exact as u32 }, day }
    }

    #[test]
    fn saves_and_loads() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("dns_state.snap");
        let mut s = LastAnswers::open(&p, 1 << 20);
        s.put(1, last(10, 100));
        s.put(2, last(20, 101));
        s.save().unwrap();
        let s = LastAnswers::open(&p, 1 << 20);
        assert_eq!(s.len(), 2);
        assert_eq!(s.get(2), Some(last(20, 101)));
        std::fs::write(&p, b"garbage").unwrap();
        assert!(LastAnswers::open(&p, 1 << 20).is_empty());
    }

    #[test]
    fn stays_under_cap_by_forgetting_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = LastAnswers::open(&dir.path().join("s"), 64 * 1024);
        let cap = s.max_len;
        for i in 0..(cap as u64 * 3) {
            s.put(i, last(i, (i / 100) as u16));
        }
        assert!(s.len() <= cap);
        assert!(s.bytes_used() <= 64 * 1024, "{}", s.bytes_used());
        assert!(s.get(cap as u64 * 3 - 1).is_some(), "newest kept");
        assert!(s.get(0).is_none(), "oldest forgotten");
    }
}
