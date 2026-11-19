//! Names waiting for a later probe. A schedule that runs for 30 days must
//! survive restarts and can hold tens of millions of names, so it lives in
//! the key-value store, in a keyspace ordered by when each name is due. A crash loses at most
//! the names taken out for probing but not yet probed. A second keyspace orders
//! the names by sighting, so a queue over its cap drops the oldest names.

use crate::kv::{durable, keyspace, u64_of, Db};
use crate::types::RenewalClass;
use anyhow::Result;
use fjall::Keyspace;

/// Number of waiting names, written with every batch.
const LEN: &[u8] = b"dns_queue_len";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A name from the certificate.
    Name,
    /// A wildcard name, asked as written: it answers if a wildcard record exists.
    Wildcard,
    /// The name a wildcard covers, when the certificate does not list it.
    Base,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Name => "name",
            Kind::Wildcard => "wildcard",
            Kind::Base => "base",
        }
    }

    fn code(self) -> u8 {
        match self {
            Kind::Name => 0,
            Kind::Wildcard => 1,
            Kind::Base => 2,
        }
    }

    fn from_code(c: u8) -> Option<Kind> {
        Some(match c {
            0 => Kind::Name,
            1 => Kind::Wildcard,
            2 => Kind::Base,
            _ => return None,
        })
    }
}

fn renewal_code(r: RenewalClass) -> u8 {
    match r {
        RenewalClass::New => 0,
        RenewalClass::Name => 1,
        RenewalClass::Exact => 2,
    }
}

fn renewal_from(c: u8) -> RenewalClass {
    match c {
        1 => RenewalClass::Name,
        2 => RenewalClass::Exact,
        _ => RenewalClass::New,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub name: String,
    /// Identifies the name and kind in the queue and the answer store.
    pub key: u64,
    pub kind: Kind,
    pub cert_hash: u64,
    pub seen_at_ms: i64,
    pub renewal: RenewalClass,
    /// The probe this is waiting for; 0 is the first.
    pub attempt: u8,
    /// When the probe before this one ran.
    pub last_ms: Option<i64>,
}

const HEADER: usize = 1 + 1 + 1 + 8 + 8 + 8 + 8;

impl Pending {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER + self.name.len());
        v.extend_from_slice(&[self.kind.code(), renewal_code(self.renewal), self.attempt]);
        v.extend_from_slice(&self.key.to_le_bytes());
        v.extend_from_slice(&self.cert_hash.to_le_bytes());
        v.extend_from_slice(&self.seen_at_ms.to_le_bytes());
        v.extend_from_slice(&self.last_ms.unwrap_or(i64::MIN).to_le_bytes());
        v.extend_from_slice(self.name.as_bytes());
        v
    }

    fn decode(b: &[u8]) -> Option<Pending> {
        if b.len() < HEADER {
            return None;
        }
        let n = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let last = n(27) as i64;
        Some(Pending {
            kind: Kind::from_code(b[0])?,
            renewal: renewal_from(b[1]),
            attempt: b[2],
            key: n(3),
            cert_hash: n(11),
            seen_at_ms: n(19) as i64,
            last_ms: (last != i64::MIN).then_some(last),
            name: String::from_utf8(b[HEADER..].to_vec()).ok()?,
        })
    }
}

pub struct Queue {
    db: Db,
    waiting: Keyspace,
    by_seen: Keyspace,
    meta: Keyspace,
    adds: Vec<(u64, Pending)>,
    len: u64,
    /// No waiting name is due before this, and none was seen before `seen_from`.
    /// Scans start here: taken names leave tombstones at the head of both
    /// orders, and a scan from the very start would walk all of them each time.
    due_from: u128,
    seen_from: u128,
}

fn pair(a: u64, b: u64) -> u128 {
    (a as u128) << 64 | b as u128
}

fn split(k: &[u8]) -> Option<(u64, u64)> {
    let k = u128::from_be_bytes(k.try_into().ok()?);
    Some(((k >> 64) as u64, k as u64))
}

impl Queue {
    pub fn open(db: &Db) -> Result<Queue> {
        let waiting = keyspace(db, "dns_waiting")?;
        let by_seen = keyspace(db, "dns_by_seen")?;
        let meta = keyspace(db, "meta")?;
        let len = match meta.get(LEN)?.and_then(|v| u64_of(&v)) {
            Some(n) => n,
            None => waiting.len()? as u64,
        };
        Ok(Queue { db: db.clone(), waiting, by_seen, meta, adds: Vec::new(), len, due_from: 0, seen_from: 0 })
    }

    /// Keys of every waiting name, to rebuild the set of names in progress.
    pub fn keys(&self) -> Result<Vec<u64>> {
        let mut out = Vec::with_capacity(self.len as usize);
        for row in self.waiting.iter() {
            if let Some((_, key)) = split(&row.key()?) {
                out.push(key);
            }
        }
        Ok(out)
    }

    /// Queues `p` for `due_ms`; written by the next `sync`.
    pub fn push(&mut self, due_ms: i64, p: Pending) {
        self.adds.push((due_ms.max(0) as u64, p));
        self.len += 1;
    }

    /// Waiting names, including those not yet written.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Writes queued names and takes out up to `max` that are due by `now_ms`,
    /// earliest first, in one batch. Returns them with their due time.
    pub fn sync(&mut self, now_ms: i64, max: usize) -> Result<Vec<(i64, Pending)>> {
        if self.adds.is_empty() && max == 0 {
            return Ok(Vec::new());
        }
        let mut batch = durable(&self.db);
        // Candidates: the head of what is stored, and new names already due.
        // A new name that is taken at once is never written.
        let mut due: Vec<(u128, Option<Pending>, bool)> = Vec::new();
        // Sightings of stored names that could not be read.
        let mut raw = std::collections::HashMap::new();
        let mut later = Vec::new();
        let take = max > 0 && now_ms >= 0;
        let until = pair(now_ms.max(0) as u64, u64::MAX);
        if take {
            for row in self.waiting.range(self.due_from.to_be_bytes()..=until.to_be_bytes()).take(max) {
                let (k, v) = row.into_inner()?;
                if let Ok(k) = k.as_ref().try_into() {
                    let (k, p) = (u128::from_be_bytes(k), Pending::decode(&v));
                    if p.is_none() {
                        raw.insert(k, seen_of(&v));
                    }
                    due.push((k, p, true));
                }
            }
        }
        for (at, p) in self.adds.drain(..) {
            let k = pair(at, p.key);
            if take && k <= until {
                due.push((k, Some(p), false));
            } else {
                later.push((k, at, p));
            }
        }
        due.sort_by_key(|d| d.0);
        let mut len = self.len;
        let (mut due_from, mut seen_from) = (self.due_from, self.seen_from);
        let mut out = Vec::new();
        for (i, (k, p, stored)) in due.into_iter().enumerate() {
            let at = (k >> 64) as u64;
            if i >= max {
                // Only new names can be left over: at most `max` were read.
                if let (Some(p), false) = (p, stored) {
                    later.push((k, at, p));
                }
                continue;
            }
            if stored {
                batch.remove(&self.waiting, k.to_be_bytes());
                // Also for a name that could not be read, where its sighting
                // still can, so that no sighting row is left behind.
                if let Some(seen) = p.as_ref().map(seen_key).or_else(|| raw.get(&k).copied().flatten()) {
                    batch.remove(&self.by_seen, pair(seen, k as u64).to_be_bytes());
                }
                // Stored names are taken in order, so none is left before this one.
                due_from = due_from.max(k.saturating_add(1));
            }
            len = len.saturating_sub(1);
            if let Some(p) = p {
                out.push((at as i64, p));
            }
        }
        for (k, at, p) in later {
            batch.insert(&self.waiting, k.to_be_bytes(), p.encode());
            batch.insert(&self.by_seen, pair(seen_key(&p), p.key).to_be_bytes(), at.to_be_bytes());
            due_from = due_from.min(k);
            seen_from = seen_from.min(pair(seen_key(&p), p.key));
        }
        batch.insert(&self.meta, LEN, len.to_be_bytes());
        batch.commit()?;
        self.len = len;
        self.due_from = due_from;
        self.seen_from = seen_from;
        Ok(out)
    }

    /// Drops the names seen longest ago until at most `max` wait, and returns
    /// their keys. Their later probes are the ones least likely to find a change.
    pub fn trim(&mut self, max: u64) -> Result<Vec<u64>> {
        if self.len <= max {
            return Ok(Vec::new());
        }
        self.sync(0, 0)?;
        let excess = self.len.saturating_sub(max) as usize;
        let mut batch = durable(&self.db);
        let mut dropped = Vec::new();
        let mut last = None;
        for row in self.by_seen.range(self.seen_from.to_be_bytes()..) {
            if dropped.len() >= excess {
                break;
            }
            let (k, v) = row.into_inner()?;
            let (Some((seen, key)), Some(due)) = (split(&k), u64_of(&v)) else { continue };
            let at = pair(due, key).to_be_bytes();
            last = Some(pair(seen, key));
            batch.remove(&self.by_seen, k);
            // A name whose stored form could not be read may have left this
            // row behind when it was taken; it is not waiting and not counted.
            if !self.waiting.contains_key(at)? {
                continue;
            }
            batch.remove(&self.waiting, at);
            dropped.push(key);
        }
        let len = self.len - dropped.len() as u64;
        batch.insert(&self.meta, LEN, len.to_be_bytes());
        batch.commit()?;
        self.len = len;
        if let Some(last) = last {
            self.seen_from = last.saturating_add(1);
        }
        Ok(dropped)
    }
}

fn seen_key(p: &Pending) -> u64 {
    p.seen_at_ms.max(0) as u64
}

/// The sighting of a stored name that does not decode, where its header is whole.
fn seen_of(b: &[u8]) -> Option<u64> {
    let v = i64::from_le_bytes(b.get(19..27)?.try_into().ok()?);
    Some(v.max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::open_db;

    fn p(name: &str, key: u64, attempt: u8) -> Pending {
        Pending {
            name: name.into(),
            key,
            kind: Kind::Base,
            cert_hash: 7,
            seen_at_ms: 1_000,
            renewal: RenewalClass::Name,
            attempt,
            last_ms: Some(1_500),
        }
    }

    #[test]
    fn takes_due_names_in_order_and_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kv");
        let mut q = Queue::open(&open_db(&path).unwrap()).unwrap();
        q.push(3_000, p("c.example", 3, 2));
        q.push(1_000, p("a.example", 1, 1));
        q.push(2_000, p("b.example", 2, 1));
        assert_eq!(q.sync(0, 0).unwrap(), vec![]);
        drop(q);
        let mut q = Queue::open(&open_db(&path).unwrap()).unwrap();
        assert_eq!(q.len(), 3);
        let mut keys = q.keys().unwrap();
        keys.sort();
        assert_eq!(keys, vec![1, 2, 3]);
        let got = q.sync(2_500, 10).unwrap();
        assert_eq!(got, vec![(1_000, p("a.example", 1, 1)), (2_000, p("b.example", 2, 1))]);
        assert_eq!(q.len(), 1);
        assert_eq!(q.sync(10_000, 10).unwrap().len(), 1);
        assert!(q.is_empty());
        let mut none = p("x", 9, 0);
        none.last_ms = None;
        assert_eq!(Pending::decode(&none.encode()), Some(none));
    }

    fn seen(name: &str, key: u64, seen_at_ms: i64) -> Pending {
        Pending { seen_at_ms, ..p(name, key, 3) }
    }

    #[test]
    fn trim_drops_the_names_seen_longest_ago() {
        let dir = tempfile::tempdir().unwrap();
        let mut q = Queue::open(&open_db(&dir.path().join("kv")).unwrap()).unwrap();
        // Due order differs from sighting order: trimming must follow the sighting.
        q.push(5_000, seen("old.example", 1, 100));
        q.push(1_000, seen("new.example", 2, 900));
        q.push(9_000, seen("older.example", 3, 50));
        q.push(2_000, seen("mid.example", 4, 500));
        let mut dropped = q.trim(2).unwrap();
        dropped.sort();
        assert_eq!(dropped, vec![1, 3]);
        assert_eq!(q.len(), 2);
        let left: Vec<u64> = q.sync(10_000, 10).unwrap().into_iter().map(|(_, p)| p.key).collect();
        assert_eq!(left, vec![2, 4]);
    }

    #[test]
    fn trim_keeps_a_queue_under_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let mut q = Queue::open(&open_db(&dir.path().join("kv")).unwrap()).unwrap();
        q.push(1_000, seen("a.example", 1, 100));
        assert_eq!(q.trim(5).unwrap(), Vec::<u64>::new());
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn names_taken_for_probing_are_not_trimmed_later() {
        let dir = tempfile::tempdir().unwrap();
        let mut q = Queue::open(&open_db(&dir.path().join("kv")).unwrap()).unwrap();
        q.push(1_000, seen("a.example", 1, 100));
        q.push(9_000, seen("b.example", 2, 200));
        assert_eq!(q.sync(5_000, 10).unwrap().len(), 1);
        assert_eq!(q.trim(0).unwrap(), vec![2]);
        assert!(q.is_empty());
    }

    #[test]
    fn trim_does_not_count_a_sighting_row_without_a_waiting_name() {
        let dir = tempfile::tempdir().unwrap();
        let mut q = Queue::open(&open_db(&dir.path().join("kv")).unwrap()).unwrap();
        q.push(1_000, seen("a.example", 1, 100));
        q.push(2_000, seen("b.example", 2, 200));
        q.sync(0, 0).unwrap();
        // Left behind by a name that was taken but could not be read.
        q.by_seen.insert(pair(50, 9).to_be_bytes(), 500u64.to_be_bytes()).unwrap();
        assert_eq!(q.trim(1).unwrap(), vec![1]);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn taking_a_name_that_does_not_read_also_removes_its_sighting() {
        let dir = tempfile::tempdir().unwrap();
        let mut q = Queue::open(&open_db(&dir.path().join("kv")).unwrap()).unwrap();
        q.push(1_000, seen("a.example", 1, 100));
        q.sync(0, 0).unwrap();
        // An unknown kind, so the name does not decode.
        let at = pair(1_000, 1).to_be_bytes();
        let mut v = q.waiting.get(at).unwrap().unwrap().to_vec();
        v[0] = 9;
        q.waiting.insert(at, v).unwrap();
        assert_eq!(q.sync(5_000, 10).unwrap(), vec![]);
        assert_eq!(q.len(), 0);
        assert_eq!(q.by_seen.len().unwrap(), 0);
    }
}
