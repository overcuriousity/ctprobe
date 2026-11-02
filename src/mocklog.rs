//! An in-process CT log speaking RFC 6962 and static-ct-api, for tests.

use base64::Engine;
use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Mutex};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

#[derive(Clone)]
pub struct MockEntry {
    pub precert: bool,
    /// Certificate DER, or TBSCertificate DER for a precertificate.
    pub body: Vec<u8>,
    pub timestamp_ms: u64,
    pub corrupt: bool,
}

#[derive(Clone)]
pub struct MockOpts {
    pub tiled: bool,
    pub tree_size: u64,
    pub max_batch: u64,
    pub gzip: bool,
    pub entries: Vec<MockEntry>,
}

impl MockOpts {
    pub fn rfc6962(tree_size: u64) -> Self {
        MockOpts { tiled: false, tree_size, max_batch: 256, gzip: false, entries: vec![] }
    }
    pub fn tiled(tree_size: u64) -> Self {
        MockOpts { tiled: true, ..Self::rfc6962(tree_size) }
    }
    pub fn with_entries(mut self, entries: Vec<MockEntry>) -> Self {
        self.tree_size = entries.len() as u64;
        self.entries = entries;
        self
    }
}

struct State {
    opts: MockOpts,
    entries: Vec<MockEntry>,
    tree_size: u64,
    failures: VecDeque<u16>,
    junk: usize,
    /// Answers every entry or tile request with this status.
    data_status: Option<u16>,
}

impl State {
    fn entry(&self, i: u64) -> MockEntry {
        self.entries.get(i as usize).cloned().unwrap_or(MockEntry {
            precert: false,
            body: i.to_be_bytes().to_vec(),
            timestamp_ms: 1_800_000_000_000 + i,
            corrupt: false,
        })
    }
}

pub struct MockLog {
    server: MockServer,
    state: Arc<Mutex<State>>,
}

fn u24(n: usize) -> [u8; 3] {
    [(n >> 16) as u8, (n >> 8) as u8, n as u8]
}

fn timestamped(e: &MockEntry, ext: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(e.body.len() + 64);
    o.extend(e.timestamp_ms.to_be_bytes());
    o.extend((e.precert as u16).to_be_bytes());
    if e.precert {
        o.extend([0u8; 32]);
    }
    o.extend(u24(e.body.len()));
    o.extend(&e.body);
    o.extend((ext.len() as u16).to_be_bytes());
    o.extend(ext);
    o
}

/// RFC 6962 `MerkleTreeLeaf`.
pub fn merkle_leaf(e: &MockEntry) -> Vec<u8> {
    let mut o = vec![0u8, 0u8];
    o.extend(timestamped(e, &[]));
    o
}

/// static-ct-api `TileLeaf` with its `leaf_index` extension.
pub fn tile_leaf(e: &MockEntry, index: u64) -> Vec<u8> {
    let idx = index.to_be_bytes();
    let mut ext = vec![0u8, 0, 5];
    ext.extend(&idx[3..]);
    let mut o = timestamped(e, &ext);
    if e.precert {
        o.extend(u24(0));
    }
    o.extend(0u16.to_be_bytes());
    o
}

fn parse_tile_number(p: &str) -> u64 {
    p.split('/').map(|g| g.trim_start_matches('x')).collect::<String>().parse().unwrap()
}

fn respond(st: &Mutex<State>, req: &Request) -> ResponseTemplate {
    let mut st = st.lock().unwrap();
    if let Some(code) = st.failures.pop_front() {
        return ResponseTemplate::new(code);
    }
    let path = req.url.path().to_string();
    let size = st.tree_size;
    if let Some(code) = st.data_status {
        if path == "/ct/v1/get-entries" || path.starts_with("/tile/") {
            return ResponseTemplate::new(code);
        }
    }
    if path == "/ct/v1/get-sth" {
        return ResponseTemplate::new(200).set_body_json(serde_json::json!({ "tree_size": size }));
    }
    if path == "/ct/v1/get-entries" {
        let q: std::collections::HashMap<_, _> = req.url.query_pairs().into_owned().collect();
        let start: u64 = q["start"].parse().unwrap();
        let end: u64 = q["end"].parse().unwrap();
        let end = end.min(size.saturating_sub(1)).min(start + st.opts.max_batch - 1);
        let b64 = base64::engine::general_purpose::STANDARD;
        let items: Vec<_> = (start..=end)
            .map(|i| {
                let e = st.entry(i);
                let leaf = if e.corrupt { vec![9u8; 4] } else { merkle_leaf(&e) };
                serde_json::json!({ "leaf_input": b64.encode(leaf), "extra_data": "" })
            })
            .collect();
        return ResponseTemplate::new(200).set_body_json(serde_json::json!({ "entries": items }));
    }
    if path == "/checkpoint" {
        return ResponseTemplate::new(200).set_body_string(format!("mock\n{size}\nAAAA=\n\n"));
    }
    if let Some(rest) = path.strip_prefix("/tile/data/") {
        let (n, width) = match rest.split_once(".p/") {
            Some((n, w)) => (parse_tile_number(n), w.parse::<u64>().unwrap()),
            None => (parse_tile_number(rest), 256),
        };
        let first = n * 256;
        if first + width > size {
            return ResponseTemplate::new(404);
        }
        if st.junk > 0 {
            st.junk -= 1;
            return ResponseTemplate::new(200).set_body_string("<html>try later</html>");
        }
        let mut body = Vec::new();
        for i in first..first + width {
            body.extend(tile_leaf(&st.entry(i), i));
        }
        if st.opts.gzip {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            gz.write_all(&body).unwrap();
            return ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .set_body_bytes(gz.finish().unwrap());
        }
        return ResponseTemplate::new(200).set_body_bytes(body);
    }
    ResponseTemplate::new(404)
}

impl MockLog {
    pub async fn start(opts: MockOpts) -> MockLog {
        let server = MockServer::start().await;
        let state = Arc::new(Mutex::new(State {
            tree_size: opts.tree_size,
            entries: opts.entries.clone(),
            opts,
            failures: VecDeque::new(),
            junk: 0,
            data_status: None,
        }));
        let st = state.clone();
        Mock::given(any())
            .respond_with(move |r: &Request| respond(&st, r))
            .mount(&server)
            .await;
        MockLog { server, state }
    }

    pub fn url(&self) -> String {
        format!("{}/", self.server.uri())
    }

    pub fn set_tree_size(&self, n: u64) {
        self.state.lock().unwrap().tree_size = n;
    }

    pub fn fail_next(&self, n: usize, status: u16) {
        self.state.lock().unwrap().failures.extend(std::iter::repeat_n(status, n));
    }

    /// Answers the next `n` tile requests with 200 and an HTML body.
    pub fn fail_data(&self, status: u16) {
        self.state.lock().unwrap().data_status = Some(status);
    }

    pub fn clear_data_failure(&self) {
        self.state.lock().unwrap().data_status = None;
    }

    pub fn junk_next(&self, n: usize) {
        self.state.lock().unwrap().junk = n;
    }

    /// Makes entry `i` undecodable.
    pub fn corrupt(&self, i: u64) {
        let mut st = self.state.lock().unwrap();
        let mut e = st.entry(i);
        e.corrupt = true;
        let needed = i as usize + 1;
        while st.entries.len() < needed {
            let k = st.entries.len() as u64;
            let f = st.entry(k);
            st.entries.push(f);
        }
        st.entries[i as usize] = e;
    }
}

/// Issues real certificates from one test CA.
pub struct TestCa {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl Default for TestCa {
    fn default() -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name.push(rcgen::DnType::CommonName, "Test CA");
        p.distinguished_name.push(rcgen::DnType::OrganizationName, "Test Org");
        TestCa { cert: p.self_signed(&key).unwrap(), key }
    }
}

impl TestCa {
    pub fn final_cert(&self, serial: u64, names: &[&str]) -> MockEntry {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(
            names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        p.serial_number = Some(rcgen::SerialNumber::from(serial.max(1)));
        if let Some(n) = names.first() {
            p.distinguished_name.push(rcgen::DnType::CommonName, *n);
        }
        let der = p.signed_by(&key, &self.cert, &self.key).unwrap().der().to_vec();
        MockEntry { precert: false, body: der, timestamp_ms: 1_800_000_000_000, corrupt: false }
    }

    /// The same certificate as a precertificate: its TBSCertificate alone.
    pub fn precert(&self, serial: u64, names: &[&str]) -> MockEntry {
        let mut e = self.final_cert(serial, names);
        e.precert = true;
        let tbs = first_inner_sequence(&e.body);
        e.body = tbs;
        e
    }
}

fn first_inner_sequence(der: &[u8]) -> Vec<u8> {
    fn header(b: &[u8]) -> (usize, usize) {
        let l = b[1] as usize;
        if l < 0x80 {
            (2, l)
        } else {
            let n = l & 0x7f;
            (2 + n, b[2..2 + n].iter().fold(0usize, |a, x| (a << 8) | *x as usize))
        }
    }
    let (h, _) = header(der);
    let inner = &der[h..];
    let (h2, l2) = header(inner);
    inner[..h2 + l2].to_vec()
}
