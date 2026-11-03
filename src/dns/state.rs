//! The last conclusive answer per name, kept to tell whether DNS changed
//! between certificates. It holds the first few addresses themselves and
//! hashes of the full sets, so changes are exact even where not every address
//! fits. Held in memory under a cap and saved as a snapshot; a crash loses
//! what changed since the last one, which then reads as unknown.

use super::outcome::{Lookup, Status};
use anyhow::{bail, Result};
use hashbrown::HashMap;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use xxhash_rust::xxh3::xxh3_64;

pub const KEEP_V4: usize = 4;
pub const KEEP_V6: usize = 2;
const MAGIC: &[u8; 8] = b"CTPDNS02";
const RECORD: usize = 8 + 8 + 16 + 2 + 3 + 4 * KEEP_V4 + 16 * KEEP_V6;
/// Key, value and control byte of one table slot.
const SLOT_BYTES: u64 = std::mem::size_of::<(u64, Last)>() as u64 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Last {
    /// Hash of the whole answer.
    pub exact: u64,
    pub v4_set: u32,
    pub v6_set: u32,
    /// Hash of the CNAME chain; 0 without one.
    pub cname: u32,
    /// The CNAME chain where there is one, the /24 and /48 prefixes otherwise.
    pub network: u32,
    /// Days since the Unix epoch.
    pub day: u16,
    pub status: u8,
    /// Address counts, which may exceed what is kept.
    pub n4: u8,
    pub n6: u8,
    pub v4: [[u8; 4]; KEEP_V4],
    pub v6: [[u8; 16]; KEEP_V6],
}

fn h32(s: &str) -> u32 {
    xxh3_64(s.as_bytes()) as u32
}

impl Last {
    pub fn of(l: &Lookup, day: u16) -> Last {
        let list = |v: &[String]| v.join(",");
        let v4: Vec<String> = l.v4.iter().map(|a| a.to_string()).collect();
        let v6: Vec<String> = l.v6.iter().map(|a| a.to_string()).collect();
        let chain = l.cnames.join(",");
        let net = if l.cnames.is_empty() {
            let mut p4: Vec<[u8; 3]> = l.v4.iter().map(|a| { let o = a.octets(); [o[0], o[1], o[2]] }).collect();
            p4.dedup();
            let mut p6: Vec<[u16; 3]> = l.v6.iter().map(|a| { let s = a.segments(); [s[0], s[1], s[2]] }).collect();
            p6.dedup();
            format!("{p4:?}|{p6:?}")
        } else {
            chain.clone()
        };
        let mut out = Last {
            exact: xxh3_64(format!("{}|{chain}|{}|{}", l.status.as_str(), list(&v4), list(&v6)).as_bytes()),
            v4_set: h32(&list(&v4)),
            v6_set: h32(&list(&v6)),
            cname: if chain.is_empty() { 0 } else { h32(&chain).max(1) },
            network: h32(&format!("{}|{net}", l.status.as_str())),
            day,
            status: l.status.code(),
            n4: l.v4.len().min(255) as u8,
            n6: l.v6.len().min(255) as u8,
            v4: [[0; 4]; KEEP_V4],
            v6: [[0; 16]; KEEP_V6],
        };
        for (s, a) in out.v4.iter_mut().zip(&l.v4) {
            *s = a.octets();
        }
        for (s, a) in out.v6.iter_mut().zip(&l.v6) {
            *s = a.octets();
        }
        out
    }

    pub fn status(&self) -> Option<Status> {
        Status::from_code(self.status)
    }

    pub fn v4(&self) -> Vec<Ipv4Addr> {
        self.v4[..(self.n4 as usize).min(KEEP_V4)].iter().map(|o| Ipv4Addr::from(*o)).collect()
    }

    pub fn v6(&self) -> Vec<Ipv6Addr> {
        self.v6[..(self.n6 as usize).min(KEEP_V6)].iter().map(|o| Ipv6Addr::from(*o)).collect()
    }

    /// Whether every address is kept, not only the first few.
    pub fn complete(&self) -> bool {
        self.n4 as usize <= KEEP_V4 && self.n6 as usize <= KEEP_V6
    }
}

/// One address family, where both answers had addresses of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyDiff {
    pub changed: bool,
    /// No address in common. `None` when the earlier addresses are not all known.
    pub replaced: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Diff {
    pub days: u16,
    pub changed: bool,
    pub status_changed: bool,
    pub cname_changed: bool,
    pub network_changed: bool,
    /// The IPv4 set differs, gained or lost included.
    pub v4_changed: bool,
    pub v6_changed: bool,
    pub v4: Option<FamilyDiff>,
    pub v6: Option<FamilyDiff>,
}

/// How `cur`, seen `today`, differs from the earlier answer `prev`.
pub fn diff(prev: &Last, cur: &Last, l: &Lookup, today: u16) -> Diff {
    let family = |both: bool, changed: bool, complete: bool, overlap: bool| {
        both.then_some(FamilyDiff { changed, replaced: complete.then_some(!overlap) })
    };
    let v4_changed = (prev.n4, prev.v4_set) != (cur.n4, cur.v4_set);
    let v6_changed = (prev.n6, prev.v6_set) != (cur.n6, cur.v6_set);
    let old4 = prev.v4();
    let old6 = prev.v6();
    Diff {
        days: today.saturating_sub(prev.day),
        changed: prev.exact != cur.exact,
        status_changed: prev.status != cur.status,
        cname_changed: prev.cname != cur.cname,
        network_changed: prev.network != cur.network,
        v4_changed,
        v6_changed,
        v4: family(
            prev.n4 > 0 && cur.n4 > 0,
            v4_changed,
            prev.n4 as usize <= KEEP_V4,
            l.v4.iter().any(|a| old4.contains(a)),
        ),
        v6: family(
            prev.n6 > 0 && cur.n6 > 0,
            v6_changed,
            prev.n6 as usize <= KEEP_V6,
            l.v6.iter().any(|a| old6.contains(a)),
        ),
    }
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
            let mut at = 0;
            let mut take = |n: usize| {
                let s = &rec[at..at + n];
                at += n;
                s.to_vec()
            };
            let u64_ = |b: Vec<u8>| u64::from_le_bytes(b.try_into().unwrap());
            let u32_ = |b: Vec<u8>| u32::from_le_bytes(b.try_into().unwrap());
            let key = u64_(take(8));
            let mut l = Last {
                exact: u64_(take(8)),
                v4_set: u32_(take(4)),
                v6_set: u32_(take(4)),
                cname: u32_(take(4)),
                network: u32_(take(4)),
                day: u16::from_le_bytes(take(2).try_into().unwrap()),
                status: take(1)[0],
                n4: take(1)[0],
                n6: take(1)[0],
                v4: [[0; 4]; KEEP_V4],
                v6: [[0; 16]; KEEP_V6],
            };
            for s in l.v4.iter_mut() {
                s.copy_from_slice(&take(4));
            }
            for s in l.v6.iter_mut() {
                s.copy_from_slice(&take(16));
            }
            self.map.insert(key, l);
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
            w.write_all(&v.exact.to_le_bytes())?;
            for x in [v.v4_set, v.v6_set, v.cname, v.network] {
                w.write_all(&x.to_le_bytes())?;
            }
            w.write_all(&v.day.to_le_bytes())?;
            w.write_all(&[v.status, v.n4, v.n6])?;
            for a in &v.v4 {
                w.write_all(a)?;
            }
            for a in &v.v6 {
                w.write_all(a)?;
            }
        }
        w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn get(&self, key: u64) -> Option<Last> {
        self.map.get(&key).copied()
    }

    pub fn put(&mut self, key: u64, last: Last) {
        if self.map.len() >= self.max_len && !self.map.contains_key(&key) {
            self.evict_half();
        }
        self.map.insert(key, last);
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

    fn lookup(v4: &[&str], v6: &[&str], cnames: &[&str]) -> Lookup {
        Lookup {
            status: if v4.is_empty() && v6.is_empty() { Status::NxDomain } else { Status::Resolved },
            v4: v4.iter().map(|a| a.parse().unwrap()).collect(),
            v6: v6.iter().map(|a| a.parse().unwrap()).collect(),
            cnames: cnames.iter().map(|c| c.to_string()).collect(),
            ttl: None,
        }
    }

    fn change(a: &Lookup, b: &Lookup) -> Diff {
        diff(&Last::of(a, 10), &Last::of(b, 40), b, 40)
    }

    #[test]
    fn tells_address_changes_apart() {
        let a = lookup(&["192.0.2.1", "192.0.2.2"], &["2001:db8::1"], &[]);
        let same = change(&a, &a);
        assert!(!same.changed && !same.v4_changed && !same.network_changed);
        assert_eq!(same.days, 30);
        let partly = change(&a, &lookup(&["192.0.2.2", "192.0.2.3"], &["2001:db8::1"], &[]));
        assert!(partly.changed && partly.v4_changed && !partly.v6_changed && !partly.network_changed);
        assert_eq!(partly.v4, Some(FamilyDiff { changed: true, replaced: Some(false) }));
        let moved = change(&a, &lookup(&["203.0.113.9"], &["2001:db8::1"], &[]));
        assert_eq!(moved.v4, Some(FamilyDiff { changed: true, replaced: Some(true) }));
        assert!(moved.network_changed);
        let lost6 = change(&a, &lookup(&["192.0.2.1", "192.0.2.2"], &[], &[]));
        assert!(lost6.v6_changed && lost6.v6.is_none());
        let gone = change(&a, &lookup(&[], &[], &[]));
        assert!(gone.status_changed && gone.v4.is_none());
    }

    #[test]
    fn rotation_behind_a_cname_is_no_network_change() {
        let a = lookup(&["192.0.2.1"], &[], &["x.cdn.example"]);
        let b = lookup(&["198.51.100.7"], &[], &["x.cdn.example"]);
        let d = change(&a, &b);
        assert!(d.v4_changed && !d.cname_changed && !d.network_changed);
        let c = lookup(&["198.51.100.7"], &[], &["y.othercdn.example"]);
        assert!(change(&a, &c).cname_changed);
    }

    #[test]
    fn many_addresses_change_exactly_but_replacement_is_unknown() {
        let many: Vec<String> = (1..=8).map(|i| format!("192.0.2.{i}")).collect();
        let more: Vec<String> = (1..=9).map(|i| format!("192.0.2.{i}")).collect();
        let r = |v: &Vec<String>| lookup(&v.iter().map(String::as_str).collect::<Vec<_>>(), &[], &[]);
        let d = change(&r(&many), &r(&more));
        assert!(d.v4_changed);
        assert_eq!(d.v4.unwrap().replaced, None);
        assert!(!Last::of(&r(&many), 1).complete());
        assert_eq!(Last::of(&r(&many), 1).v4().len(), KEEP_V4);
    }

    #[test]
    fn saves_and_loads() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("dns_state.snap");
        let mut s = LastAnswers::open(&p, 1 << 20);
        let l = Last::of(&lookup(&["192.0.2.1"], &["2001:db8::1"], &["a.example"]), 100);
        s.put(1, l);
        s.save().unwrap();
        let s = LastAnswers::open(&p, 1 << 20);
        assert_eq!(s.len(), 1);
        assert_eq!(s.get(1), Some(l));
        assert_eq!(s.get(1).unwrap().v6(), vec!["2001:db8::1".parse::<Ipv6Addr>().unwrap()]);
        std::fs::write(&p, b"garbage").unwrap();
        assert!(LastAnswers::open(&p, 1 << 20).is_empty());
    }

    #[test]
    fn stays_under_cap_by_forgetting_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = LastAnswers::open(&dir.path().join("s"), 128 * 1024);
        let cap = s.max_len;
        let l = Last::of(&lookup(&["192.0.2.1"], &[], &[]), 0);
        for i in 0..(cap as u64 * 3) {
            s.put(i, Last { day: (i / 100) as u16, ..l });
        }
        assert!(s.len() <= cap);
        assert!(s.bytes_used() <= 128 * 1024, "{}", s.bytes_used());
        assert!(s.get(cap as u64 * 3 - 1).is_some(), "newest kept");
        assert!(s.get(0).is_none(), "oldest forgotten");
    }
}
