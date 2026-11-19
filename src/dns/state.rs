//! The last conclusive answer per name, kept to tell whether DNS changed
//! between certificates. It holds the first few addresses themselves and
//! hashes of the full sets, so changes are exact even where not every address
//! fits. Kept in the key-value store under a cap on its size; a crash loses
//! the last moments of answers, which then read as unknown.

use super::outcome::{Lookup, Status};
use crate::kv::{keyspace, u64_of, Db};
use anyhow::Result;
use fjall::Keyspace;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use xxhash_rust::xxh3::xxh3_64;

pub const KEEP_V4: usize = 4;
pub const KEEP_V6: usize = 2;
const RECORD: usize = 8 + 16 + 2 + 3 + 4 * KEEP_V4 + 16 * KEEP_V6;
/// Disk space of one answer with its key, as measured on 15 to 50 million.
const ENTRY_BYTES: u64 = 110;
/// Number of answers, saved now and then.
const LEN: &[u8] = b"dns_last_len";

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
            let mut p4: Vec<[u8; 3]> =
                l.v4.iter()
                    .map(|a| {
                        let o = a.octets();
                        [o[0], o[1], o[2]]
                    })
                    .collect();
            p4.dedup();
            let mut p6: Vec<[u16; 3]> =
                l.v6.iter()
                    .map(|a| {
                        let s = a.segments();
                        [s[0], s[1], s[2]]
                    })
                    .collect();
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
    table: Keyspace,
    meta: Keyspace,
    len: Arc<AtomicU64>,
    max_len: u64,
    evicting: Option<JoinHandle<()>>,
}

fn encode(v: &Last) -> [u8; RECORD] {
    let mut b = [0u8; RECORD];
    b[0..8].copy_from_slice(&v.exact.to_le_bytes());
    for (i, x) in [v.v4_set, v.v6_set, v.cname, v.network].into_iter().enumerate() {
        b[8 + i * 4..12 + i * 4].copy_from_slice(&x.to_le_bytes());
    }
    b[24..26].copy_from_slice(&v.day.to_le_bytes());
    b[26..29].copy_from_slice(&[v.status, v.n4, v.n6]);
    let mut at = 29;
    for a in &v.v4 {
        b[at..at + 4].copy_from_slice(a);
        at += 4;
    }
    for a in &v.v6 {
        b[at..at + 16].copy_from_slice(a);
        at += 16;
    }
    b
}

fn decode(b: &[u8]) -> Option<Last> {
    if b.len() != RECORD {
        return None;
    }
    let u32_ = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
    let mut l = Last {
        exact: u64::from_le_bytes(b[0..8].try_into().unwrap()),
        v4_set: u32_(8),
        v6_set: u32_(12),
        cname: u32_(16),
        network: u32_(20),
        day: day_of(b),
        status: b[26],
        n4: b[27],
        n6: b[28],
        v4: [[0; 4]; KEEP_V4],
        v6: [[0; 16]; KEEP_V6],
    };
    let mut at = 29;
    for s in l.v4.iter_mut() {
        s.copy_from_slice(&b[at..at + 4]);
        at += 4;
    }
    for s in l.v6.iter_mut() {
        s.copy_from_slice(&b[at..at + 16]);
        at += 16;
    }
    Some(l)
}

fn day_of(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[24], b[25]])
}

impl LastAnswers {
    /// Opens the answers in `db`, keeping at most what fits in `max_bytes` on disk.
    pub fn open(db: &Db, max_bytes: u64) -> Result<LastAnswers> {
        let table = keyspace(db, "dns_last")?;
        let meta = keyspace(db, "meta")?;
        // The count is saved now and then; after a crash it is a little off,
        // which only moves the moment of the next eviction.
        let len = match meta.get(LEN)?.and_then(|v| u64_of(&v)) {
            Some(n) => n,
            None => table.len()? as u64,
        };
        let max_len = (max_bytes / ENTRY_BYTES).max(16);
        Ok(LastAnswers { table, meta, len: Arc::new(AtomicU64::new(len)), max_len, evicting: None })
    }

    /// Writes the count. The answers themselves are written as they change.
    pub fn save(&self) -> Result<()> {
        self.meta.insert(LEN, self.len.load(Ordering::Relaxed).to_be_bytes())?;
        Ok(())
    }

    pub fn get(&self, key: u64) -> Option<Last> {
        match self.table.get(key.to_be_bytes()) {
            Ok(v) => v.and_then(|v| decode(&v)),
            Err(e) => {
                tracing::warn!("reading DNS state: {e}");
                None
            }
        }
    }

    pub fn put(&mut self, key: u64, last: Last) {
        let k = key.to_be_bytes();
        let known = self.table.contains_key(k).unwrap_or(false);
        if let Err(e) = self.table.insert(k, encode(&last)) {
            return tracing::warn!("writing DNS state: {e}");
        }
        if !known && self.len.fetch_add(1, Ordering::Relaxed) + 1 > self.max_len {
            self.evict();
        }
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn bytes_used(&self) -> u64 {
        self.table.disk_space()
    }

    /// Starts forgetting the oldest half, unless that is already running. It
    /// runs beside probing: scanning tens of millions of answers takes a while.
    fn evict(&mut self) {
        if self.evicting.as_ref().is_some_and(|h| !h.is_finished()) {
            return;
        }
        let (table, len) = (self.table.clone(), self.len.clone());
        let spawned = std::thread::Builder::new().name("ctprobe-dns-evict".into()).spawn(move || {
            if let Err(e) = evict_half(&table, &len) {
                tracing::warn!("evicting DNS state: {e:#}");
            }
        });
        match spawned {
            Ok(h) => self.evicting = Some(h),
            Err(e) => tracing::warn!("evicting DNS state: {e}"),
        }
    }

    /// Waits for a running eviction.
    pub fn settle(&mut self) {
        if let Some(h) = self.evicting.take() {
            let _ = h.join();
        }
    }
}

/// Forgets the oldest half: whole days, oldest first, then as many of the
/// cutoff day as are still needed. An answer rewritten while this runs may be
/// forgotten with its old day; it then reads as unknown once.
fn evict_half(table: &Keyspace, len: &AtomicU64) -> Result<()> {
    let before = len.load(Ordering::Relaxed);
    let mut days: BTreeMap<u16, usize> = BTreeMap::new();
    let mut count = 0u64;
    for row in table.iter() {
        let v = row.value()?;
        if v.len() == RECORD {
            *days.entry(day_of(&v)).or_default() += 1;
        }
        count += 1;
    }
    let (cutoff, mut need) = cutoff_day(days, (count / 2) as usize);
    let mut removed = 0u64;
    for row in table.iter() {
        let (k, v) = row.into_inner()?;
        let go = v.len() != RECORD
            || match day_of(&v).cmp(&cutoff) {
                std::cmp::Ordering::Less => true,
                std::cmp::Ordering::Greater => false,
                std::cmp::Ordering::Equal if need > 0 => {
                    need -= 1;
                    true
                }
                std::cmp::Ordering::Equal => false,
            };
        if go {
            table.remove(k)?;
            removed += 1;
        }
    }
    // Also corrects a count that drifted after a crash.
    let now = len.load(Ordering::Relaxed);
    len.store((count + now.saturating_sub(before)).saturating_sub(removed), Ordering::Relaxed);
    tracing::info!("DNS state at its cap: forgot the {removed} oldest answers of {count}");
    Ok(())
}

/// The day up to which entries go, and how many of that day go, so that at
/// least `target` are removed oldest first: every earlier day goes whole.
pub(crate) fn cutoff_day(days: BTreeMap<u16, usize>, target: usize) -> (u16, usize) {
    let mut removed = 0;
    for (day, n) in days {
        if removed + n >= target {
            return (day, target - removed);
        }
        removed += n;
    }
    (u16::MAX, 0)
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

    fn open(dir: &tempfile::TempDir, max_bytes: u64) -> LastAnswers {
        LastAnswers::open(&crate::kv::open_db(&dir.path().join("kv")).unwrap(), max_bytes).unwrap()
    }

    /// A put that waits for the eviction it may start.
    fn put(s: &mut LastAnswers, key: u64, l: Last) {
        s.put(key, l);
        s.settle();
    }

    #[test]
    fn survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&dir, 1 << 20);
        let l = Last::of(&lookup(&["192.0.2.1"], &["2001:db8::1"], &["a.example"]), 100);
        s.put(1, l);
        s.put(1, l);
        s.save().unwrap();
        drop(s);
        let s = open(&dir, 1 << 20);
        assert_eq!(s.len(), 1);
        assert_eq!(s.get(1), Some(l));
        assert_eq!(s.get(1).unwrap().v6(), vec!["2001:db8::1".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(s.get(2), None);
    }

    #[test]
    fn stays_under_cap_by_forgetting_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&dir, 128 * 1024);
        let cap = s.max_len;
        let l = Last::of(&lookup(&["192.0.2.1"], &[], &[]), 0);
        for i in 0..(cap * 3) {
            put(&mut s, i, Last { day: (i / 100) as u16, ..l });
        }
        assert!(s.len() as u64 <= cap);
        assert_eq!(s.len(), s.table.len().unwrap(), "the count follows evictions");
        assert!(s.get(cap * 3 - 1).is_some(), "newest kept");
        assert!(s.get(0).is_none(), "oldest forgotten");
    }

    #[test]
    fn eviction_within_one_day_halves() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&dir, 128 * 1024);
        let cap = s.max_len;
        let l = Last::of(&lookup(&["192.0.2.1"], &[], &[]), 7);
        for i in 0..cap {
            put(&mut s, i * 2, l);
        }
        assert_eq!(s.len() as u64, cap);
        put(&mut s, cap * 2 + 2, l);
        assert!(s.len() as u64 <= cap / 2 + 1, "{} of {cap} left", s.len());
    }

    #[test]
    fn eviction_drops_older_days_before_any_of_the_newest() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&dir, 128 * 1024);
        let cap = s.max_len;
        let l = Last::of(&lookup(&["192.0.2.1"], &[], &[]), 0);
        // A tenth of the names from day 1, the rest from day 2.
        for i in 0..cap {
            put(&mut s, i * 2, Last { day: if i < cap / 10 { 1 } else { 2 }, ..l });
        }
        put(&mut s, cap * 2 + 2, Last { day: 2, ..l });
        assert!(s.len() as u64 <= cap / 2 + 1, "{} of {cap} left", s.len());
        assert!(s.get(0).is_none(), "an answer of the older day is forgotten first");
    }
}
