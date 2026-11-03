//! What one probe found: per resolver, then across resolvers by quorum.

use super::client::Reply;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use xxhash_rust::xxh3::xxh3_64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// At least one A or AAAA record.
    Resolved,
    /// The name exists but has no address.
    NoData,
    NxDomain,
    /// SERVFAIL, REFUSED, timeouts and the like.
    Failed,
    /// No outcome reached the quorum.
    Split,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Resolved => "resolved",
            Status::NoData => "nodata",
            Status::NxDomain => "nxdomain",
            Status::Failed => "failed",
            Status::Split => "split",
        }
    }

    /// An answer the name's owner chose, as opposed to a failure to get one.
    pub fn conclusive(self) -> bool {
        matches!(self, Status::Resolved | Status::NoData | Status::NxDomain)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    pub status: Status,
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
    pub cnames: Vec<String>,
    pub ttl: Option<u32>,
}

impl Lookup {
    fn empty(status: Status) -> Lookup {
        Lookup { status, v4: Vec::new(), v6: Vec::new(), cnames: Vec::new(), ttl: None }
    }

    fn add(&mut self, addrs: &[IpAddr]) {
        for a in addrs {
            match a {
                IpAddr::V4(a) => self.v4.push(*a),
                IpAddr::V6(a) => self.v6.push(*a),
            }
        }
        self.v4.sort_unstable();
        self.v4.dedup();
        self.v6.sort_unstable();
        self.v6.dedup();
    }
}

/// One resolver's view from its A and AAAA replies. Any address wins; then a
/// nonexistent name; then two clean empty answers; anything else failed.
pub fn combine(a: &Reply, aaaa: &Reply) -> Lookup {
    let answers = [a, aaaa];
    let mut out = Lookup::empty(Status::Failed);
    let mut clean = 0;
    for r in answers {
        if let Reply::Answer { addrs, cnames, ttl } = r {
            clean += 1;
            out.add(addrs);
            if out.cnames.is_empty() {
                out.cnames = cnames.clone();
            }
            if let Some(t) = ttl {
                out.ttl = Some(out.ttl.map_or(*t, |o| o.min(*t)));
            }
        }
    }
    out.status = if !out.v4.is_empty() || !out.v6.is_empty() {
        Status::Resolved
    } else if answers.iter().any(|r| matches!(r, Reply::NxDomain)) {
        Status::NxDomain
    } else if clean == 2 {
        Status::NoData
    } else {
        Status::Failed
    };
    if out.status != Status::Resolved && out.status != Status::NoData {
        out.cnames.clear();
        out.ttl = None;
    }
    out
}

/// The first outcome, in order of preference, that `quorum` resolvers share.
/// Addresses of agreeing resolvers are merged. Also returns how many agreed.
pub fn decide(per: &[Lookup], quorum: usize) -> (Lookup, usize) {
    for status in [Status::Resolved, Status::NxDomain, Status::NoData, Status::Failed] {
        let agree: Vec<&Lookup> = per.iter().filter(|l| l.status == status).collect();
        if !agree.is_empty() && agree.len() >= quorum {
            let mut out = Lookup::empty(status);
            for l in &agree {
                out.add(&l.v4.iter().map(|a| IpAddr::V4(*a)).collect::<Vec<_>>());
                out.add(&l.v6.iter().map(|a| IpAddr::V6(*a)).collect::<Vec<_>>());
                if out.cnames.is_empty() {
                    out.cnames = l.cnames.clone();
                }
                if let Some(t) = l.ttl {
                    out.ttl = Some(out.ttl.map_or(t, |o| o.min(t)));
                }
            }
            return (out, agree.len());
        }
    }
    let most = [Status::Resolved, Status::NxDomain, Status::NoData, Status::Failed]
        .iter()
        .map(|s| per.iter().filter(|l| l.status == *s).count())
        .max()
        .unwrap_or(0);
    (Lookup::empty(Status::Split), most)
}

/// Two fingerprints of an answer. `exact` changes with any address. `network`
/// follows the CNAME chain where there is one, since CDNs rotate addresses
/// behind a stable alias, and the /24 and /48 prefixes otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    pub exact: u64,
    pub network: u32,
}

pub fn fingerprint(l: &Lookup) -> Fingerprint {
    let mut exact = format!("{}|{}|", l.status.as_str(), l.cnames.join(","));
    for a in &l.v4 {
        exact.push_str(&a.to_string());
        exact.push(',');
    }
    exact.push('|');
    for a in &l.v6 {
        exact.push_str(&a.to_string());
        exact.push(',');
    }
    let mut network = format!("{}|{}|", l.status.as_str(), l.cnames.join(","));
    if l.cnames.is_empty() {
        let mut v4: Vec<[u8; 3]> = l.v4.iter().map(|a| {
            let o = a.octets();
            [o[0], o[1], o[2]]
        }).collect();
        v4.dedup();
        let mut v6: Vec<[u16; 3]> = l.v6.iter().map(|a| {
            let s = a.segments();
            [s[0], s[1], s[2]]
        }).collect();
        v6.dedup();
        network.push_str(&format!("{v4:?}|{v6:?}"));
    }
    Fingerprint { exact: xxh3_64(exact.as_bytes()), network: xxh3_64(network.as_bytes()) as u32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ans(addrs: &[&str], cnames: &[&str], ttl: u32) -> Reply {
        Reply::Answer {
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
            cnames: cnames.iter().map(|c| c.to_string()).collect(),
            ttl: Some(ttl),
        }
    }

    #[test]
    fn combines_a_and_aaaa() {
        let l = combine(&ans(&["192.0.2.1"], &[], 300), &ans(&["2001:db8::1"], &[], 60));
        assert_eq!(l.status, Status::Resolved);
        assert_eq!(l.v4.len(), 1);
        assert_eq!(l.v6.len(), 1);
        assert_eq!(l.ttl, Some(60));
        // An address on one side is enough even if the other failed.
        assert_eq!(combine(&ans(&["192.0.2.1"], &[], 1), &Reply::Timeout).status, Status::Resolved);
        assert_eq!(combine(&ans(&[], &[], 1), &ans(&[], &[], 1)).status, Status::NoData);
        assert_eq!(combine(&Reply::NxDomain, &Reply::NxDomain).status, Status::NxDomain);
        assert_eq!(combine(&ans(&[], &[], 1), &Reply::Rcode(2)).status, Status::Failed);
        assert_eq!(combine(&Reply::Timeout, &Reply::Timeout).status, Status::Failed);
    }

    #[test]
    fn quorum_prefers_answers_then_nxdomain() {
        let ok = combine(&ans(&["192.0.2.1"], &[], 1), &ans(&[], &[], 1));
        let ok2 = combine(&ans(&["192.0.2.2"], &[], 1), &ans(&[], &[], 1));
        let nx = combine(&Reply::NxDomain, &Reply::NxDomain);
        let fail = combine(&Reply::Timeout, &Reply::Timeout);
        let (d, n) = decide(&[ok.clone(), nx.clone(), nx.clone()], 2);
        assert_eq!((d.status, n), (Status::NxDomain, 2));
        let (d, n) = decide(&[ok.clone(), ok2, nx.clone()], 2);
        assert_eq!((d.status, n, d.v4.len()), (Status::Resolved, 2, 2));
        let (d, _) = decide(&[ok.clone(), nx.clone(), fail.clone()], 1);
        assert_eq!(d.status, Status::Resolved);
        let (d, n) = decide(&[ok, nx, fail], 2);
        assert_eq!((d.status, n), (Status::Split, 1));
    }

    #[test]
    fn network_fingerprint_ignores_rotation_behind_a_cname() {
        let a = combine(&ans(&["192.0.2.1"], &["x.cdn.example"], 1), &ans(&[], &["x.cdn.example"], 1));
        let b = combine(&ans(&["198.51.100.7"], &["x.cdn.example"], 1), &ans(&[], &["x.cdn.example"], 1));
        assert_ne!(fingerprint(&a).exact, fingerprint(&b).exact);
        assert_eq!(fingerprint(&a).network, fingerprint(&b).network);
        let c = combine(&ans(&["192.0.2.1"], &[], 1), &ans(&[], &[], 1));
        let d = combine(&ans(&["192.0.2.99"], &[], 1), &ans(&[], &[], 1));
        let e = combine(&ans(&["203.0.113.1"], &[], 1), &ans(&[], &[], 1));
        assert_eq!(fingerprint(&c).network, fingerprint(&d).network, "same /24");
        assert_ne!(fingerprint(&c).network, fingerprint(&e).network);
    }
}
