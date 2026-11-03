//! A scripted DNS resolver on localhost, over UDP and TCP, for tests.

use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Debug, Clone)]
pub enum MockAnswer {
    /// Addresses, optionally behind one CNAME.
    Addrs { cname: Option<String>, addrs: Vec<IpAddr> },
    NxDomain,
    ServFail,
    /// Never answers.
    Silent,
}

impl MockAnswer {
    pub fn addrs(addrs: &[&str]) -> MockAnswer {
        MockAnswer::Addrs { cname: None, addrs: addrs.iter().map(|a| a.parse().unwrap()).collect() }
    }
}

#[derive(Default)]
struct Shared {
    zone: Mutex<HashMap<String, MockAnswer>>,
    queries: AtomicU64,
    tcp_queries: AtomicU64,
    truncate_udp: AtomicBool,
}

pub struct MockDns {
    addr: SocketAddr,
    shared: Arc<Shared>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for MockDns {
    fn drop(&mut self) {
        self.tasks.iter().for_each(|t| t.abort());
    }
}

/// The reply to `req`, or `None` to stay silent. Unknown names do not exist.
fn answer(shared: &Shared, req: &Message, udp: bool) -> Option<Message> {
    let q = req.queries.first()?.clone();
    let host = q.name().to_ascii().trim_end_matches('.').to_ascii_lowercase();
    let entry = shared.zone.lock().unwrap().get(&host).cloned().unwrap_or(MockAnswer::NxDomain);
    let mut resp = Message::response(req.metadata.id, OpCode::Query);
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.add_query(q.clone());
    if udp && shared.truncate_udp.load(Ordering::Relaxed) {
        resp.metadata.truncation = true;
        return Some(resp);
    }
    match entry {
        MockAnswer::Silent => return None,
        MockAnswer::NxDomain => resp.metadata.response_code = ResponseCode::NXDomain,
        MockAnswer::ServFail => resp.metadata.response_code = ResponseCode::ServFail,
        MockAnswer::Addrs { cname, addrs } => {
            let mut owner = q.name().clone();
            if let Some(c) = cname {
                let target = Name::from_ascii(format!("{c}.")).unwrap();
                resp.add_answer(Record::from_rdata(owner, 300, RData::CNAME(CNAME(target.clone()))));
                owner = target;
            }
            for a in addrs {
                let rdata = match (a, q.query_type()) {
                    (IpAddr::V4(a), RecordType::A) => RData::A(A(a)),
                    (IpAddr::V6(a), RecordType::AAAA) => RData::AAAA(AAAA(a)),
                    _ => continue,
                };
                resp.add_answer(Record::from_rdata(owner.clone(), 60, rdata));
            }
        }
    }
    Some(resp)
}

impl MockDns {
    pub async fn start() -> MockDns {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(addr).await.unwrap();
        let shared = Arc::new(Shared::default());
        let s = shared.clone();
        let u = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else { continue };
                let Ok(req) = Message::from_vec(&buf[..n]) else { continue };
                s.queries.fetch_add(1, Ordering::Relaxed);
                if let Some(bytes) = answer(&s, &req, true).and_then(|m| m.to_vec().ok()) {
                    let _ = udp.send_to(&bytes, from).await;
                }
            }
        });
        let s = shared.clone();
        let t = tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = tcp.accept().await else { continue };
                let s = s.clone();
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if c.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
                    if c.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let Ok(req) = Message::from_vec(&body) else { return };
                    s.queries.fetch_add(1, Ordering::Relaxed);
                    s.tcp_queries.fetch_add(1, Ordering::Relaxed);
                    if let Some(bytes) = answer(&s, &req, false).and_then(|m| m.to_vec().ok()) {
                        let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
                        out.extend_from_slice(&bytes);
                        let _ = c.write_all(&out).await;
                    }
                });
            }
        });
        MockDns { addr, shared, tasks: vec![u, t] }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn set(&self, name: &str, a: MockAnswer) {
        self.shared.zone.lock().unwrap().insert(name.to_string(), a);
    }

    /// Queries received over both transports.
    pub fn queries(&self) -> u64 {
        self.shared.queries.load(Ordering::Relaxed)
    }

    pub fn tcp_queries(&self) -> u64 {
        self.shared.tcp_queries.load(Ordering::Relaxed)
    }

    /// Answers UDP with only the truncation bit, forcing a retry over TCP.
    pub fn truncate_udp(&self, on: bool) {
        self.shared.truncate_udp.store(on, Ordering::Relaxed);
    }
}
