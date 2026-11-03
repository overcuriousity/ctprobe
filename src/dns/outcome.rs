//! What one probe found, from the A and AAAA replies of the resolver.

use super::client::Reply;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// At least one A or AAAA record.
    Resolved,
    /// The name exists but has no address.
    NoData,
    NxDomain,
    /// SERVFAIL, REFUSED, timeouts and the like.
    Failed,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Resolved => "resolved",
            Status::NoData => "nodata",
            Status::NxDomain => "nxdomain",
            Status::Failed => "failed",
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Status::Resolved => 1,
            Status::NoData => 2,
            Status::NxDomain => 3,
            Status::Failed => 4,
        }
    }

    pub fn from_code(c: u8) -> Option<Status> {
        Some(match c {
            1 => Status::Resolved,
            2 => Status::NoData,
            3 => Status::NxDomain,
            4 => Status::Failed,
            _ => return None,
        })
    }

    /// An answer the name's owner chose, as opposed to a failure to get one.
    pub fn conclusive(self) -> bool {
        self != Status::Failed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    pub status: Status,
    /// Sorted and without duplicates, as is `v6`.
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
    pub cnames: Vec<String>,
    pub ttl: Option<u32>,
}

/// The resolver's view from its A and AAAA replies. Any address wins; then a
/// nonexistent name; then two clean empty answers; anything else failed.
pub fn combine(a: &Reply, aaaa: &Reply) -> Lookup {
    let answers = [a, aaaa];
    let mut out = Lookup { status: Status::Failed, v4: Vec::new(), v6: Vec::new(), cnames: Vec::new(), ttl: None };
    let mut clean = 0;
    for r in answers {
        if let Reply::Answer { addrs, cnames, ttl } = r {
            clean += 1;
            for a in addrs {
                match a {
                    IpAddr::V4(a) => out.v4.push(*a),
                    IpAddr::V6(a) => out.v6.push(*a),
                }
            }
            if out.cnames.is_empty() {
                out.cnames = cnames.clone();
            }
            if let Some(t) = ttl {
                out.ttl = Some(out.ttl.map_or(*t, |o| o.min(*t)));
            }
        }
    }
    out.v4.sort_unstable();
    out.v4.dedup();
    out.v6.sort_unstable();
    out.v6.dedup();
    out.status = if !out.v4.is_empty() || !out.v6.is_empty() {
        Status::Resolved
    } else if answers.iter().any(|r| matches!(r, Reply::NxDomain)) {
        Status::NxDomain
    } else if clean == 2 {
        Status::NoData
    } else {
        Status::Failed
    };
    if !matches!(out.status, Status::Resolved | Status::NoData) {
        out.cnames.clear();
        out.ttl = None;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ans(addrs: &[&str], ttl: u32) -> Reply {
        Reply::Answer { addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(), cnames: vec![], ttl: Some(ttl) }
    }

    #[test]
    fn combines_a_and_aaaa() {
        let l = combine(&ans(&["192.0.2.1"], 300), &ans(&["2001:db8::1"], 60));
        assert_eq!(l.status, Status::Resolved);
        assert_eq!((l.v4.len(), l.v6.len(), l.ttl), (1, 1, Some(60)));
        // An address on one side is enough even if the other failed.
        assert_eq!(combine(&ans(&["192.0.2.1"], 1), &Reply::Timeout).status, Status::Resolved);
        assert_eq!(combine(&ans(&[], 1), &ans(&[], 1)).status, Status::NoData);
        assert_eq!(combine(&Reply::NxDomain, &Reply::NxDomain).status, Status::NxDomain);
        assert_eq!(combine(&ans(&[], 1), &Reply::Rcode(2)).status, Status::Failed);
        assert_eq!(combine(&Reply::Timeout, &Reply::Timeout).status, Status::Failed);
        for s in [Status::Resolved, Status::NoData, Status::NxDomain, Status::Failed] {
            assert_eq!(Status::from_code(s.code()), Some(s));
        }
    }
}
