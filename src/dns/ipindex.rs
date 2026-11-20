//! Which registered domains resolved to an address, and on which days first
//! and last. The Parquet files are sorted by domain, so finding an address in
//! them means reading every day; this index answers it with one range read.
//! Key: the address as 16 bytes, then the domain. Value: first and last day.

use crate::kv::{keyspace, Db};
use anyhow::Result;
use chrono::NaiveDate;
use fjall::Keyspace;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Mutex;

/// Held for each read-then-write of an entry, so that expiry cannot remove an
/// entry that probing has just renewed.
static WRITE: Mutex<()> = Mutex::new(());

#[derive(Clone)]
pub struct IpIndex {
    table: Keyspace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpHit {
    pub domain: String,
    /// Days since the Unix epoch.
    pub first_day: u16,
    pub last_day: u16,
}

fn prefix(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
        IpAddr::V6(a) => a.octets(),
    }
}

fn days(v: &[u8]) -> Option<(u16, u16)> {
    let v: [u8; 4] = v.try_into().ok()?;
    Some((u16::from_be_bytes([v[0], v[1]]), u16::from_be_bytes([v[2], v[3]])))
}

impl IpIndex {
    pub fn open(db: &Db) -> Result<IpIndex> {
        Ok(IpIndex { table: keyspace(db, "ip_domains")? })
    }

    /// Notes that names of `domain` resolved to these addresses on `day`.
    pub fn record(&self, v4: &[Ipv4Addr], v6: &[Ipv6Addr], domain: &str, day: u16) -> Result<()> {
        let ips = v4.iter().map(|a| IpAddr::V4(*a)).chain(v6.iter().map(|a| IpAddr::V6(*a)));
        for ip in ips {
            let mut key = prefix(ip).to_vec();
            key.extend_from_slice(domain.as_bytes());
            let _held = WRITE.lock().unwrap_or_else(|e| e.into_inner());
            let (first, last) = match self.table.get(&key)?.and_then(|v| days(&v)) {
                Some((first, last)) if (first..=last).contains(&day) => continue,
                Some((first, last)) => (first.min(day), last.max(day)),
                None => (day, day),
            };
            let mut v = [0u8; 4];
            v[..2].copy_from_slice(&first.to_be_bytes());
            v[2..].copy_from_slice(&last.to_be_bytes());
            self.table.insert(key, v)?;
        }
        Ok(())
    }

    /// Up to `limit` domains of `ip` in name order, after the domain `after`.
    pub fn lookup(&self, ip: IpAddr, after: Option<&str>, limit: usize) -> Result<Vec<IpHit>> {
        let p = prefix(ip);
        let mut from = p.to_vec();
        if let Some(a) = after {
            from.extend_from_slice(a.as_bytes());
            // The smallest key after `after` itself.
            from.push(0);
        }
        let mut out = Vec::new();
        for row in self.table.range(from..) {
            let (k, v) = row.into_inner()?;
            if out.len() >= limit || !k.starts_with(&p) {
                break;
            }
            let (Ok(domain), Some((first_day, last_day))) = (std::str::from_utf8(&k[16..]), days(&v)) else { continue };
            out.push(IpHit { domain: domain.to_string(), first_day, last_day });
        }
        Ok(out)
    }

    /// Forgets what was last seen before `day`. Returns how many entries went.
    pub fn expire(&self, day: u16) -> Result<u64> {
        let mut removed = 0;
        for row in self.table.iter() {
            let (k, v) = row.into_inner()?;
            let old = |v: &[u8]| days(v).is_none_or(|(_, last)| last < day);
            if !old(&v) {
                continue;
            }
            // The scan reads a view from its start; the entry may be newer by now.
            let _held = WRITE.lock().unwrap_or_else(|e| e.into_inner());
            if self.table.get(&k)?.is_some_and(|v| old(&v)) {
                self.table.remove(k)?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// The oldest day that still has DNS rows, hot or archived.
pub fn oldest_dns_day(data: &Path) -> Option<u16> {
    let names = |dir: std::path::PathBuf| {
        std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.file_name().to_string_lossy().into_owned())
    };
    let hot = names(data.join("dns")).filter_map(|n| n.strip_prefix("day=").map(str::to_string));
    let cold = names(data.join("archive").join("dns")).filter_map(|n| n.strip_suffix(".parquet").map(str::to_string));
    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1)?;
    hot.chain(cold)
        .filter_map(|d| NaiveDate::parse_from_str(&d, "%Y-%m-%d").ok())
        .min()
        .map(|d| (d - epoch).num_days().clamp(0, u16::MAX as i64) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_domains_of_an_address_and_pages_through_them() {
        let dir = tempfile::tempdir().unwrap();
        let ix = IpIndex::open(&crate::kv::open_db(&dir.path().join("kv")).unwrap()).unwrap();
        let a: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let b: Ipv4Addr = "192.0.2.2".parse().unwrap();
        let six: Ipv6Addr = "2001:db8::1".parse().unwrap();
        ix.record(&[a, b], &[six], "b.example", 10).unwrap();
        ix.record(&[a], &[], "a.example", 12).unwrap();
        ix.record(&[a], &[], "b.example", 15).unwrap();
        ix.record(&[a], &[], "b.example", 12).unwrap();
        let hit = |d: &str, f, l| IpHit { domain: d.into(), first_day: f, last_day: l };
        assert_eq!(ix.lookup(a.into(), None, 10).unwrap(), vec![hit("a.example", 12, 12), hit("b.example", 10, 15)]);
        assert_eq!(ix.lookup(a.into(), None, 1).unwrap(), vec![hit("a.example", 12, 12)]);
        assert_eq!(ix.lookup(a.into(), Some("a.example"), 10).unwrap(), vec![hit("b.example", 10, 15)]);
        assert_eq!(ix.lookup(b.into(), None, 10).unwrap(), vec![hit("b.example", 10, 10)]);
        assert_eq!(ix.lookup(six.into(), None, 10).unwrap(), vec![hit("b.example", 10, 10)]);
        assert_eq!(ix.lookup("192.0.2.3".parse().unwrap(), None, 10).unwrap(), vec![]);
        assert_eq!(ix.expire(12).unwrap(), 2);
        assert_eq!(ix.lookup(b.into(), None, 10).unwrap(), vec![]);
        assert_eq!(ix.lookup(a.into(), None, 10).unwrap().len(), 2);
    }
}
