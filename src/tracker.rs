//! Deduplication and renewal state: hashes in memory, a daily snapshot and a
//! write-ahead log framed by commit epoch.

use crate::names;
use crate::types::{CertRow, LogId, ParsedCert, RenewalClass, Sighting};
use anyhow::{bail, Context, Result};
use hashbrown::HashMap;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasherDefault, Hasher};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use xxhash_rust::xxh3::xxh3_64;

const DEDUP_DAYS: u16 = 7;
const RECORD: usize = 11; // table + hash + day
const FRAME_HEADER: usize = 16; // epoch + record count
const SNAP_MAGIC: &[u8; 8] = b"CTPSNAP1";
const SLOT_BYTES: u64 = 11; // key + value + control byte

/// The keys are already hashes, so the table hasher passes them through.
#[derive(Default)]
struct PassThrough(u64);

impl Hasher for PassThrough {
    fn write(&mut self, bytes: &[u8]) {
        if let Ok(b) = bytes.try_into() {
            self.0 = u64::from_le_bytes(b);
        }
    }
    fn write_usize(&mut self, _: usize) {}
    fn finish(&self) -> u64 {
        self.0
    }
}

/// Byte arrays keep each slot at 10 bytes; `(u64, u16)` would pad to 16.
type Table = HashMap<[u8; 8], [u8; 2], BuildHasherDefault<PassThrough>>;

#[derive(Debug, Clone, Copy)]
pub struct EntryMeta {
    pub log: LogId,
    pub index: u64,
    pub is_precert: bool,
    pub der_size: u32,
    pub timestamp_ms: u64,
    pub seen_at_ms: i64,
}

#[derive(Debug)]
pub struct Observation {
    pub sighting: Sighting,
    pub row: Option<CertRow>,
}

pub struct Tracker {
    dir: PathBuf,
    max_bytes: u64,
    tables: [Table; 3], // dedup, names, name sets
    pending: Vec<u8>,
    pending_records: u64,
    wal: File,
}

const DEDUP: u8 = 0;
const NAMES: u8 = 1;
const SETS: u8 = 2;

fn replay_wal(path: &Path, tables: &mut [Table; 3], committed: u64) -> Result<u64> {
    let mut f = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(path)?;
    let len = f.metadata()?.len();
    let mut r = BufReader::new(&mut f);
    let mut good = 0u64;
    loop {
        let mut head = [0u8; FRAME_HEADER];
        if r.read_exact(&mut head).is_err() {
            break;
        }
        let epoch = u64::from_le_bytes(head[..8].try_into().unwrap());
        let count = u64::from_le_bytes(head[8..].try_into().unwrap());
        let body_len = count.saturating_mul(RECORD as u64);
        if epoch > committed || good + FRAME_HEADER as u64 + body_len > len {
            break;
        }
        let mut rec = [0u8; RECORD];
        for _ in 0..count {
            r.read_exact(&mut rec)?;
            let t = rec[0] as usize;
            if t > 2 {
                bail!("corrupt tracker WAL");
            }
            tables[t].insert(rec[1..9].try_into().unwrap(), rec[9..11].try_into().unwrap());
        }
        good += FRAME_HEADER as u64 + body_len;
    }
    drop(r);
    f.set_len(good)?;
    Ok(good)
}

/// Identifies a certificate across logs and its precertificate: issuer and serial.
pub fn cert_hash(p: &ParsedCert) -> u64 {
    let mut k = p.issuer_der.clone();
    k.extend_from_slice(p.serial_hex.as_bytes());
    xxh3_64(&k)
}

impl Tracker {
    /// Loads the snapshot and replays WAL frames up to `committed_epoch`.
    /// Later frames belong to a commit that never completed and are dropped.
    pub fn open(dir: &Path, max_bytes: u64, committed_epoch: u64) -> Result<Tracker> {
        fs::create_dir_all(dir)?;
        let mut tables: [Table; 3] = Default::default();
        let snap = dir.join("tracker.snap");
        if snap.exists() {
            let mut r = BufReader::with_capacity(1 << 20, File::open(&snap)?);
            let mut magic = [0u8; 8];
            r.read_exact(&mut magic)?;
            if &magic != SNAP_MAGIC {
                bail!("bad tracker snapshot");
            }
            let mut n = [0u8; 8];
            r.read_exact(&mut n)?; // snapshot epoch, informational
            for t in tables.iter_mut() {
                r.read_exact(&mut n)?;
                let count = u64::from_le_bytes(n);
                t.reserve(count as usize);
                let mut rec = [0u8; 10];
                for _ in 0..count {
                    r.read_exact(&mut rec)?;
                    t.insert(rec[..8].try_into().unwrap(), rec[8..].try_into().unwrap());
                }
            }
        }
        let wal_path = dir.join("tracker.wal");
        replay_wal(&wal_path, &mut tables, committed_epoch).context("replaying tracker WAL")?;
        let mut wal = OpenOptions::new().read(true).write(true).open(&wal_path)?;
        wal.seek(SeekFrom::End(0))?;
        let mut t = Tracker {
            dir: dir.to_path_buf(),
            max_bytes,
            tables,
            pending: Vec::new(),
            pending_records: 0,
            wal,
        };
        t.evict();
        Ok(t)
    }

    /// Keeps a table from doubling past the cap. A resize holds both the old and
    /// new allocation, so the check counts them together and must run before
    /// the insert that would trigger it. Dedup is exempt: it expires by itself.
    fn make_room(&mut self, table: u8) {
        let t = &self.tables[table as usize];
        let alloc = t.allocation_size() as u64;
        let buckets = alloc / SLOT_BYTES;
        if buckets < 64 || (t.len() as u64) < buckets / 8 * 7 {
            return;
        }
        if self.bytes_used() + alloc * 2 > self.max_bytes {
            self.evict_half(table);
        }
    }

    /// Forgets the oldest half of a table, keeping its size.
    fn evict_half(&mut self, table: u8) {
        let t = &mut self.tables[table as usize];
        let mut days: BTreeMap<u16, u64> = BTreeMap::new();
        for d in t.values() {
            *days.entry(u16::from_le_bytes(*d)).or_default() += 1;
        }
        let target = t.len() as u64 / 2;
        let (mut removed, mut cutoff) = (0, 0);
        for (d, n) in days {
            removed += n;
            cutoff = d;
            if removed >= target {
                break;
            }
        }
        let by_day = removed < t.len() as u64;
        // Rebuilt, not filtered in place: tombstones would count as occupied and
        // force the very doubling this avoids.
        let capacity = t.capacity() - 1;
        let mut kept = Table::with_capacity_and_hasher(capacity, Default::default());
        kept.extend(t.drain().filter(|(k, d)| {
            // All of one day means nothing is older, so an arbitrary half goes.
            if by_day { u16::from_le_bytes(*d) > cutoff } else { k[0] & 1 == 0 }
        }));
        *t = kept;
    }

    fn put(&mut self, table: u8, hash: u64, day: u16) {
        if table != DEDUP {
            self.make_room(table);
        }
        let key = hash.to_le_bytes();
        let val = day.to_le_bytes();
        self.tables[table as usize].insert(key, val);
        self.pending.push(table);
        self.pending.extend_from_slice(&key);
        self.pending.extend_from_slice(&val);
        self.pending_records += 1;
    }

    fn get(&self, table: u8, hash: u64) -> Option<u16> {
        self.tables[table as usize].get(&hash.to_le_bytes()).map(|v| u16::from_le_bytes(*v))
    }

    /// Records one entry. `today` is days since the Unix epoch.
    pub fn observe(&mut self, m: EntryMeta, p: &ParsedCert, today: u16) -> Observation {
        let cert_hash = cert_hash(p);
        let sighting = Sighting { cert_hash, log: m.log, seen_at_ms: m.seen_at_ms };
        if let Some(day) = self.get(DEDUP, cert_hash) {
            if today.saturating_sub(day) <= DEDUP_DAYS {
                return Observation { sighting, row: None };
            }
        }
        self.put(DEDUP, cert_hash, today);

        let mut hit = false;
        let mut smallest_gap: Option<u32> = None;
        let mut new_names = 0;
        for n in &p.names {
            let h = xxh3_64(n.as_bytes());
            match self.get(NAMES, h) {
                Some(d) => {
                    hit = true;
                    let gap = today.saturating_sub(d) as u32;
                    smallest_gap = Some(smallest_gap.map_or(gap, |g| g.min(gap)));
                    if d != today {
                        self.put(NAMES, h, today);
                    }
                }
                None => {
                    new_names += 1;
                    self.put(NAMES, h, today);
                }
            }
        }

        let mut set_hit = None;
        if !p.names.is_empty() {
            let h = xxh3_64(p.names.join("\n").as_bytes());
            set_hit = self.get(SETS, h);
            self.put(SETS, h, today);
        }

        let mut reg_domains: Vec<String> =
            p.names.iter().filter_map(|n| names::registered_domain(n)).collect();
        reg_domains.sort_unstable();
        reg_domains.dedup();
        let mut new_domains = 0;
        for d in &reg_domains {
            let h = xxh3_64(format!("d:{d}").as_bytes());
            match self.get(NAMES, h) {
                Some(day) if day == today => {}
                Some(_) => self.put(NAMES, h, today),
                None => {
                    new_domains += 1;
                    self.put(NAMES, h, today);
                }
            }
        }

        let primary_domain = p
            .subject_cn
            .as_deref()
            .and_then(names::normalize)
            .and_then(|cn| names::registered_domain(&cn))
            .or_else(|| reg_domains.first().cloned());
        let renewal = match (set_hit, hit) {
            (Some(_), _) => RenewalClass::Exact,
            (None, true) => RenewalClass::Name,
            (None, false) => RenewalClass::New,
        };
        let row = CertRow {
            parsed: p.clone(),
            reg_domains,
            primary_domain,
            is_wildcard: p.names.iter().any(|n| n.starts_with("*.")),
            is_precert: m.is_precert,
            renewal,
            days_since_seen: smallest_gap,
            new_names,
            new_domains,
            log: m.log,
            index: m.index,
            der_size: m.der_size,
            seen_at_ms: m.seen_at_ms,
            sct_lag_ms: m.seen_at_ms - m.timestamp_ms as i64,
            not_before_lag_ms: m.seen_at_ms - p.not_before_ms,
            cert_hash,
        };
        Observation { sighting, row: Some(row) }
    }

    /// Durably appends everything since the last commit as one frame.
    pub fn commit_wal(&mut self, epoch: u64) -> Result<()> {
        let mut w = BufWriter::with_capacity(1 << 20, &self.wal);
        w.write_all(&epoch.to_le_bytes())?;
        w.write_all(&self.pending_records.to_le_bytes())?;
        w.write_all(&self.pending)?;
        w.flush()?;
        drop(w);
        self.wal.sync_data()?;
        self.pending.clear();
        self.pending_records = 0;
        self.evict();
        Ok(())
    }

    /// Writes a full snapshot and empties the WAL. Call right after a
    /// `commit_wal` whose epoch has been recorded.
    pub fn snapshot(&mut self, epoch: u64) -> Result<()> {
        let tmp = self.dir.join("tracker.snap.tmp");
        let mut w = BufWriter::with_capacity(1 << 20, File::create(&tmp)?);
        w.write_all(SNAP_MAGIC)?;
        w.write_all(&epoch.to_le_bytes())?;
        for t in &self.tables {
            w.write_all(&(t.len() as u64).to_le_bytes())?;
            for (k, v) in t {
                w.write_all(k)?;
                w.write_all(v)?;
            }
        }
        let f = w.into_inner().map_err(|e| e.into_error())?;
        f.sync_all()?;
        fs::rename(&tmp, self.dir.join("tracker.snap"))?;
        self.wal.set_len(0)?;
        self.wal.seek(SeekFrom::Start(0))?;
        self.wal.sync_all()?;
        Ok(())
    }

    /// Drops expired dedup entries. Run daily.
    pub fn expire_dedup(&mut self, today: u16) {
        self.tables[DEDUP as usize]
            .retain(|_, d| today.saturating_sub(u16::from_le_bytes(*d)) <= DEDUP_DAYS);
        self.tables[DEDUP as usize].shrink_to_fit();
    }

    pub fn name_count(&self) -> u64 {
        self.tables[NAMES as usize].len() as u64
    }

    pub fn bytes_used(&self) -> u64 {
        self.tables.iter().map(|t| t.allocation_size() as u64).sum()
    }

    /// Removes the oldest names and name sets until usage is under the cap.
    /// Dedup entries are exempt: they expire on their own after 7 days.
    fn evict(&mut self) {
        let mut guard = 0;
        while self.bytes_used() > self.max_bytes && guard < 64 {
            guard += 1;
            let oldest = [NAMES, SETS]
                .iter()
                .flat_map(|t| self.tables[*t as usize].values())
                .map(|d| u16::from_le_bytes(*d))
                .min();
            let Some(oldest) = oldest else { break };
            for t in [NAMES, SETS] {
                let table = &mut self.tables[t as usize];
                table.retain(|_, d| u16::from_le_bytes(*d) != oldest);
                table.shrink_to_fit();
            }
        }
    }
}
