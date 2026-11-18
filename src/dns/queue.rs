//! Names waiting for a later probe. A schedule that runs for 30 days must
//! survive restarts and can hold tens of millions of names, so it lives in
//! its own redb file, ordered by when each name is due. A crash loses at most
//! the names taken out for probing but not yet probed. A second table orders
//! the names by sighting, so a queue over its cap drops the oldest names.

use crate::types::RenewalClass;
use anyhow::{Context, Result};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::path::Path;

/// (due ms, name key) → encoded `Pending`.
const WAITING: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("waiting");
/// (seen ms, name key) → due ms, for every name in `WAITING`.
const BY_SEEN: TableDefinition<(u64, u64), u64> = TableDefinition::new("by_seen");

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
    db: Database,
    adds: Vec<(u64, Pending)>,
    len: u64,
}

impl Queue {
    pub fn open(path: &Path) -> Result<Queue> {
        let db = Database::create(path).with_context(|| format!("opening {}", path.display()))?;
        let tx = db.begin_write()?;
        let len = {
            let waiting = tx.open_table(WAITING)?;
            let mut by_seen = tx.open_table(BY_SEEN)?;
            // A queue written before the sighting index has none; build it once.
            if by_seen.len()? != waiting.len()? {
                by_seen.retain(|_, _| false)?;
                for row in waiting.iter()? {
                    let (k, v) = row?;
                    let (due, key) = k.value();
                    if let Some(p) = Pending::decode(v.value()) {
                        by_seen.insert((seen_key(&p), key), due)?;
                    }
                }
            }
            waiting.len()?
        };
        tx.commit()?;
        Ok(Queue { db, adds: Vec::new(), len })
    }

    /// Keys of every waiting name, to rebuild the set of names in progress.
    pub fn keys(&self) -> Result<Vec<u64>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(WAITING)?;
        let mut out = Vec::with_capacity(t.len()? as usize);
        for row in t.iter()? {
            out.push(row?.0.value().1);
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
    /// earliest first, in one transaction. Returns them with their due time.
    pub fn sync(&mut self, now_ms: i64, max: usize) -> Result<Vec<(i64, Pending)>> {
        if self.adds.is_empty() && max == 0 {
            return Ok(Vec::new());
        }
        let tx = self.db.begin_write()?;
        let mut out = Vec::new();
        {
            let mut t = tx.open_table(WAITING)?;
            let mut by_seen = tx.open_table(BY_SEEN)?;
            self.write_adds(&mut t, &mut by_seen)?;
            if max > 0 && now_ms >= 0 {
                let mut keys = Vec::new();
                for row in t.range((0u64, 0u64)..=(now_ms as u64, u64::MAX))?.take(max) {
                    let (k, v) = row?;
                    let p = Pending::decode(v.value());
                    keys.push((k.value(), p.as_ref().map(seen_key)));
                    if let Some(p) = p {
                        out.push((k.value().0 as i64, p));
                    }
                }
                for (k, seen) in &keys {
                    t.remove(k)?;
                    if let Some(seen) = seen {
                        by_seen.remove((*seen, k.1))?;
                    }
                }
                self.len = t.len()?;
            }
        }
        tx.commit()?;
        Ok(out)
    }

    /// Drops the names seen longest ago until at most `max` wait, and returns
    /// their keys. Their later probes are the ones least likely to find a change.
    pub fn trim(&mut self, max: u64) -> Result<Vec<u64>> {
        if self.len <= max {
            return Ok(Vec::new());
        }
        let tx = self.db.begin_write()?;
        let mut dropped = Vec::new();
        {
            let mut t = tx.open_table(WAITING)?;
            let mut by_seen = tx.open_table(BY_SEEN)?;
            self.write_adds(&mut t, &mut by_seen)?;
            let excess = t.len()?.saturating_sub(max) as usize;
            let mut oldest = Vec::with_capacity(excess);
            for row in by_seen.iter()?.take(excess) {
                let (k, due) = row?;
                oldest.push((k.value(), due.value()));
            }
            for ((seen, key), due) in oldest {
                by_seen.remove((seen, key))?;
                if t.remove((due, key))?.is_some() {
                    dropped.push(key);
                }
            }
            self.len = t.len()?;
        }
        tx.commit()?;
        Ok(dropped)
    }

    fn write_adds(
        &mut self,
        t: &mut redb::Table<(u64, u64), &[u8]>,
        by_seen: &mut redb::Table<(u64, u64), u64>,
    ) -> Result<()> {
        for (due, p) in self.adds.drain(..) {
            t.insert((due, p.key), p.encode().as_slice())?;
            by_seen.insert((seen_key(&p), p.key), due)?;
        }
        Ok(())
    }
}

fn seen_key(p: &Pending) -> u64 {
    p.seen_at_ms.max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let path = dir.path().join("q.redb");
        let mut q = Queue::open(&path).unwrap();
        q.push(3_000, p("c.example", 3, 2));
        q.push(1_000, p("a.example", 1, 1));
        q.push(2_000, p("b.example", 2, 1));
        assert_eq!(q.sync(0, 0).unwrap(), vec![]);
        drop(q);
        let mut q = Queue::open(&path).unwrap();
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
        let mut q = Queue::open(&dir.path().join("q.redb")).unwrap();
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
        let mut q = Queue::open(&dir.path().join("q.redb")).unwrap();
        q.push(1_000, seen("a.example", 1, 100));
        assert_eq!(q.trim(5).unwrap(), Vec::<u64>::new());
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn names_taken_for_probing_are_not_trimmed_later() {
        let dir = tempfile::tempdir().unwrap();
        let mut q = Queue::open(&dir.path().join("q.redb")).unwrap();
        q.push(1_000, seen("a.example", 1, 100));
        q.push(9_000, seen("b.example", 2, 200));
        assert_eq!(q.sync(5_000, 10).unwrap().len(), 1);
        assert_eq!(q.trim(0).unwrap(), vec![2]);
        assert!(q.is_empty());
    }

    #[test]
    fn indexes_a_queue_written_before_the_sighting_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("q.redb");
        {
            let db = Database::create(&path).unwrap();
            let tx = db.begin_write().unwrap();
            {
                let mut t = tx.open_table(WAITING).unwrap();
                t.insert((5_000, 1), seen("old.example", 1, 100).encode().as_slice()).unwrap();
                t.insert((1_000, 2), seen("new.example", 2, 900).encode().as_slice()).unwrap();
            }
            tx.commit().unwrap();
        }
        let mut q = Queue::open(&path).unwrap();
        assert_eq!(q.trim(1).unwrap(), vec![1]);
        assert_eq!(q.len(), 1);
    }
}
