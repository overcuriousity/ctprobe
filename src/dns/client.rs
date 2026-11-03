//! One DNS query to one resolver: UDP, then TCP when the answer is truncated.

use hickory_proto::op::{Edns, Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Fits an unfragmented UDP datagram on any path (DNS flag day 2020).
const EDNS_PAYLOAD: u16 = 1232;
const MAX_UDP: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// NOERROR, with the records of the asked type and the CNAMEs on the way.
    Answer { addrs: Vec<IpAddr>, cnames: Vec<String>, ttl: Option<u32> },
    NxDomain,
    /// Any other response code, such as SERVFAIL or REFUSED.
    Rcode(u16),
    Timeout,
    /// The resolver could not be reached or sent something unreadable.
    Error,
}

/// A query name as hickory wants it, or `None` for something that is not one.
pub fn query_name(host: &str) -> Option<Name> {
    let mut n = Name::from_ascii(host).ok()?;
    n.set_fqdn(true);
    Some(n)
}

fn request(name: &Name, rtype: RecordType) -> Message {
    let mut m = Message::query();
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(name.clone(), rtype));
    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_PAYLOAD);
    m.set_edns(edns);
    m
}

fn host(n: &Name) -> String {
    n.to_ascii().trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `resp` answers `req`: same id, a response, the same question.
fn matches(req: &Message, resp: &Message) -> bool {
    resp.metadata.id == req.metadata.id
        && resp.metadata.message_type == MessageType::Response
        && match (req.queries.first(), resp.queries.first()) {
            (Some(a), Some(b)) => {
                a.query_type() == b.query_type() && host(a.name()) == host(b.name())
            }
            _ => false,
        }
}

/// Reads what a resolver said. Only records of the asked type count as
/// addresses; CNAMEs are kept in the order given.
pub fn interpret(resp: &Message, rtype: RecordType) -> Reply {
    match resp.metadata.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => return Reply::NxDomain,
        other => return Reply::Rcode(u16::from(other)),
    }
    let mut addrs = Vec::new();
    let mut cnames = Vec::new();
    let mut ttl: Option<u32> = None;
    for r in &resp.answers {
        let addr = match (&r.data, rtype) {
            (RData::A(a), RecordType::A) => Some(IpAddr::V4(a.0)),
            (RData::AAAA(a), RecordType::AAAA) => Some(IpAddr::V6(a.0)),
            (RData::CNAME(c), _) => {
                cnames.push(host(&c.0));
                None
            }
            _ => continue,
        };
        ttl = Some(ttl.map_or(r.ttl, |t| t.min(r.ttl)));
        addrs.extend(addr);
    }
    Reply::Answer { addrs, cnames, ttl }
}

fn local_for(server: SocketAddr) -> SocketAddr {
    match server {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

enum Try {
    Done(Message),
    Truncated,
    Timeout,
    Error,
}

/// A fresh socket per query gives each one its own random source port.
async fn over_udp(server: SocketAddr, req: &Message, bytes: &[u8], deadline: Instant) -> Try {
    let Ok(sock) = UdpSocket::bind(local_for(server)).await else { return Try::Error };
    if sock.connect(server).await.is_err() || sock.send(bytes).await.is_err() {
        return Try::Error;
    }
    let mut buf = vec![0u8; MAX_UDP];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, sock.recv(&mut buf)).await {
            Err(_) => return Try::Timeout,
            Ok(Err(_)) => return Try::Error,
            Ok(Ok(n)) => {
                // Anything that does not answer this question is ignored, not trusted.
                let Ok(resp) = Message::from_vec(&buf[..n]) else { continue };
                if !matches(req, &resp) {
                    continue;
                }
                return if resp.metadata.truncation { Try::Truncated } else { Try::Done(resp) };
            }
        }
    }
}

async fn over_tcp(server: SocketAddr, req: &Message, bytes: &[u8], deadline: Instant) -> Try {
    let left = deadline.saturating_duration_since(Instant::now());
    let work = async {
        let mut s = TcpStream::connect(server).await.ok()?;
        let len = u16::try_from(bytes.len()).ok()?;
        let mut out = len.to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        s.write_all(&out).await.ok()?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.ok()?;
        let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut body).await.ok()?;
        let resp = Message::from_vec(&body).ok()?;
        matches(req, &resp).then_some(resp)
    };
    match tokio::time::timeout(left, work).await {
        Err(_) => Try::Timeout,
        Ok(None) => Try::Error,
        Ok(Some(m)) => Try::Done(m),
    }
}

/// Asks `server` once per try, each try with its own id, port and `timeout`.
/// Returns the reply and the time taken by the try that produced it.
pub async fn query(
    server: SocketAddr,
    name: &Name,
    rtype: RecordType,
    timeout: Duration,
    tries: u32,
) -> (Reply, Duration) {
    let mut last = (Reply::Timeout, timeout);
    for _ in 0..tries.max(1) {
        let req = request(name, rtype);
        let Ok(bytes) = req.to_vec() else { return (Reply::Error, Duration::ZERO) };
        let start = Instant::now();
        let deadline = start + timeout;
        let mut got = over_udp(server, &req, &bytes, deadline).await;
        if matches!(got, Try::Truncated) {
            got = over_tcp(server, &req, &bytes, deadline).await;
        }
        let took = start.elapsed();
        match got {
            Try::Done(m) => return (interpret(&m, rtype), took),
            Try::Timeout => last = (Reply::Timeout, took),
            Try::Error | Try::Truncated => last = (Reply::Error, took),
        }
    }
    last
}
