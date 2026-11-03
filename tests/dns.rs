use ctprobe::config::DnsConfig;
use ctprobe::dns::client::{query, query_name, Reply};
use ctprobe::dns::mock::{MockAnswer, MockDns};
use ctprobe::dns::outcome::{Lookup, Status};
use ctprobe::dns::queue::Kind;
use ctprobe::dns::state::{Last, LastAnswers};
use ctprobe::dns::{self, DnsLink, DnsOpts, DnsOut, DnsReport, DnsRow, STATE_FILE};
use ctprobe::types::{CertRow, ParsedCert, RenewalClass};
use hickory_proto::rr::RecordType;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::watch;

const T: Duration = Duration::from_millis(300);

fn cert(hash: u64, names: &[&str], renewal: RenewalClass) -> CertRow {
    let mut names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    names.sort();
    CertRow {
        parsed: ParsedCert { names, ..Default::default() },
        reg_domains: vec![],
        primary_domain: None,
        is_wildcard: false,
        is_precert: false,
        renewal,
        days_since_seen: None,
        new_names: 0,
        new_domains: 0,
        log: 0,
        index: hash,
        der_size: 0,
        seen_at_ms: chrono::Utc::now().timestamp_millis(),
        sct_lag_ms: 0,
        not_before_lag_ms: 0,
        cert_hash: hash,
    }
}

fn cfg(resolver: SocketAddr) -> DnsConfig {
    DnsConfig { resolver: Some(resolver), max_qps: 10_000, sample_pct: 100.0, state_max_bytes: 1 << 20 }
}

fn opts(schedule_ms: &[u64]) -> DnsOpts {
    DnsOpts {
        schedule: schedule_ms.iter().map(|m| Duration::from_millis(*m)).collect(),
        timeout: T,
        stale_after: Duration::from_secs(5),
        snapshot_every: Duration::from_secs(3600),
        minute: Duration::from_millis(200),
    }
}

struct Run {
    link: DnsLink,
    stop: watch::Sender<bool>,
    thread: std::thread::JoinHandle<()>,
    rows: Vec<DnsRow>,
    minutes: i64,
}

impl Run {
    fn start(c: DnsConfig, o: DnsOpts, dir: &Path) -> Run {
        let (stop, rx) = watch::channel(false);
        let (link, thread) = dns::start(c, o, dir, rx).unwrap();
        Run { link, stop, thread, rows: Vec::new(), minutes: 0 }
    }

    fn drain(&mut self) {
        while let Ok(o) = self.link.out.try_recv() {
            match o {
                DnsOut::Row(r) => self.rows.push(r),
                DnsOut::Minute(m) => self.minutes += m.first_probes,
            }
        }
    }

    /// Waits until `pred` holds for the published report and the rows so far.
    async fn until(&mut self, what: &str, pred: impl Fn(&DnsReport, &[DnsRow]) -> bool) -> DnsReport {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            self.drain();
            let r = self.link.stats.report();
            if pred(&r, &self.rows) {
                return r;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}: {r:#?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn row(&self, name: &str, attempt: u8) -> &DnsRow {
        self.rows.iter().find(|r| r.name == name && r.attempt == attempt).unwrap()
    }

    fn stop(self) {
        let _ = self.stop.send(true);
        self.thread.join().unwrap();
    }
}

#[tokio::test]
async fn client_reads_answers_and_failures() {
    let m = MockDns::start().await;
    m.set("www.example.com", MockAnswer::Addrs { cname: Some("edge.cdn.example".into()), addrs: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()] });
    m.set("broken.example.com", MockAnswer::ServFail);
    m.set("slow.example.com", MockAnswer::Silent);
    let n = |s: &str| query_name(s).unwrap();
    let (a, _) = query(m.addr(), &n("www.example.com"), RecordType::A, T, 1).await;
    assert_eq!(a, Reply::Answer { addrs: vec!["192.0.2.1".parse().unwrap()], cnames: vec!["edge.cdn.example".into()], ttl: Some(60) });
    let (aaaa, _) = query(m.addr(), &n("www.example.com"), RecordType::AAAA, T, 1).await;
    assert!(matches!(aaaa, Reply::Answer { ref addrs, .. } if addrs.len() == 1 && addrs[0].is_ipv6()));
    assert_eq!(query(m.addr(), &n("nothing.example.com"), RecordType::A, T, 1).await.0, Reply::NxDomain);
    assert_eq!(query(m.addr(), &n("broken.example.com"), RecordType::A, T, 1).await.0, Reply::Rcode(2));
    let before = m.queries();
    assert_eq!(query(m.addr(), &n("slow.example.com"), RecordType::A, T, 2).await.0, Reply::Timeout);
    assert_eq!(m.queries() - before, 2, "a timeout is tried again");
    assert!(query_name("bad name.example").is_none());
}

#[tokio::test]
async fn client_falls_back_to_tcp_when_truncated() {
    let m = MockDns::start().await;
    m.set("big.example.com", MockAnswer::addrs(&["192.0.2.7"]));
    m.truncate_udp(true);
    let (r, _) = query(m.addr(), &query_name("big.example.com").unwrap(), RecordType::A, T, 1).await;
    assert_eq!(r, Reply::Answer { addrs: vec!["192.0.2.7".parse().unwrap()], cnames: vec![], ttl: Some(60) });
    assert_eq!(m.tcp_queries(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn probes_names_and_retries_until_they_resolve() {
    let m = MockDns::start().await;
    m.set("a.example.com", MockAnswer::addrs(&["192.0.2.1", "2001:db8::1"]));
    m.set("v4.example.com", MockAnswer::addrs(&["192.0.2.2"]));
    let dir = tempfile::tempdir().unwrap();
    let mut run = Run::start(cfg(m.addr()), opts(&[0, 1000, 2000, 3000]), dir.path());
    run.link.submit(&cert(1, &["a.example.com", "late.example.com", "v4.example.com"], RenewalClass::New));
    let r = run.until("first probes", |r, _| r.names.first.probes == 3).await;
    let f = &r.names.first;
    assert_eq!((f.resolved, f.v4, f.v6, f.both, f.nxdomain), (2, 2, 1, 1, 1));
    assert_eq!(r.names.first_new.probes, 3);
    // The missing name appears between the second and third probe.
    run.until("second probe", |_, rows| rows.iter().any(|r| r.name == "late.example.com" && r.attempt == 1)).await;
    m.set("late.example.com", MockAnswer::addrs(&["192.0.2.9"]));
    let r = run.until("late name", |r, _| r.names.resolved_later == 1).await;
    assert_eq!(r.names.later_by_attempt, vec![0, 0, 1, 0]);
    let (hi, lo) = (r.names.time_to_dns.clone().unwrap(), r.names.time_to_dns_lower.clone().unwrap());
    assert!(lo.p50_ms >= 1000.0 && hi.p50_ms >= 2000.0 && hi.p50_ms < 4000.0, "{lo:?} {hi:?}");
    let late = run.row("late.example.com", 2);
    assert_eq!(late.lookup.status, Status::Resolved);
    assert_eq!(late.last_miss_ms, Some(run.row("late.example.com", 1).probed_at_ms));
    assert!(run.rows.iter().all(|r| r.cert_hash == 1 && r.renewal == "new" && r.kind == Kind::Name));
    // A name still pending is not probed twice for another certificate.
    run.link.submit(&cert(2, &["never.example.com"], RenewalClass::New));
    run.link.submit(&cert(3, &["never.example.com"], RenewalClass::Name));
    let r = run.until("never", |r, _| r.names.never == 1).await;
    assert_eq!(r.already_pending, 1);
    assert_eq!(r.resolver.queries, 2 * r.probes);
    assert!(r.retry_late.is_some());
    assert!(run.minutes > 0, "minute rows count first probes");
    run.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn wildcards_are_asked_as_written_and_for_the_name_they_cover() {
    let m = MockDns::start().await;
    m.set("*.example.com", MockAnswer::addrs(&["192.0.2.1"]));
    m.set("example.org", MockAnswer::addrs(&["192.0.2.2"]));
    let dir = tempfile::tempdir().unwrap();
    let mut run = Run::start(cfg(m.addr()), opts(&[0]), dir.path());
    run.link.submit(&cert(1, &["*.example.com"], RenewalClass::New));
    // The covered name is listed, so it is probed once, as a name.
    run.link.submit(&cert(2, &["*.example.org", "example.org"], RenewalClass::New));
    let r = run.until("probes", |r, _| r.probes == 4).await;
    assert_eq!((r.wildcards.first.probes, r.wildcards.first.resolved), (2, 1));
    assert_eq!((r.bases.first.probes, r.bases.first.nxdomain), (1, 1));
    assert_eq!((r.names.first.probes, r.names.first.resolved), (1, 1));
    assert_eq!(run.row("example.com", 0).kind, Kind::Base);
    assert_eq!(run.row("*.example.com", 0).kind, Kind::Wildcard);
    run.stop();
}

fn resolved(v4: &[&str]) -> Lookup {
    Lookup { status: Status::Resolved, v4: v4.iter().map(|a| a.parse().unwrap()).collect(), v6: vec![], cnames: vec![], ttl: None }
}

#[tokio::test(flavor = "multi_thread")]
async fn reports_ip_changes_and_keeps_answers_across_restarts() {
    let m = MockDns::start().await;
    m.set("moved.example.com", MockAnswer::addrs(&["203.0.113.5"]));
    m.set("same.example.com", MockAnswer::addrs(&["192.0.2.5"]));
    let dir = tempfile::tempdir().unwrap();
    let today = (chrono::Utc::now().timestamp_millis() / 86_400_000) as u16;
    // Thirty days ago, before a renewal, `moved` pointed elsewhere.
    let mut last = LastAnswers::open(&dir.path().join(STATE_FILE), 1 << 20);
    let h = xxhash_rust::xxh3::xxh3_64(b"moved.example.com");
    last.put(h, Last::of(&resolved(&["192.0.2.1", "192.0.2.2"]), today - 30));
    last.save().unwrap();

    let mut run = Run::start(cfg(m.addr()), opts(&[0]), dir.path());
    run.link.submit(&cert(1, &["moved.example.com", "same.example.com"], RenewalClass::Name));
    let r = run.until("first", |r, _| r.names.first.probes == 2).await;
    let e = &r.names.earlier_day;
    assert_eq!((e.compared, e.changed, e.v4_compared, e.v4_changed, e.v4_replaced, e.v4_replaced_known), (1, 1, 1, 1, 1, 1));
    let moved = run.row("moved.example.com", 0);
    let (old, change) = moved.prev.unwrap();
    assert_eq!((change.days, change.v4_changed), (30, true));
    assert_eq!(old.v4(), vec!["192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap(), "192.0.2.2".parse().unwrap()]);
    assert!(run.row("same.example.com", 0).prev.is_none());
    assert_eq!(r.names.first_renewed.probes, 2);
    run.stop();

    // After a restart the answers are still known. `same` moved within its /24.
    m.set("same.example.com", MockAnswer::addrs(&["192.0.2.6"]));
    let mut run = Run::start(cfg(m.addr()), opts(&[0]), dir.path());
    run.link.submit(&cert(2, &["moved.example.com", "same.example.com"], RenewalClass::Exact));
    let r = run.until("second", |r, _| r.names.first.probes == 2).await;
    let s = &r.names.same_day;
    assert_eq!((s.compared, s.changed, s.v4_changed, s.v4_replaced, s.network_changed), (2, 1, 1, 1, 0));
    let (_, change) = run.row("same.example.com", 0).prev.unwrap();
    assert!(change.v4_changed && !change.network_changed && change.days == 0);
    run.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn waiting_names_survive_a_restart() {
    let m = MockDns::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut run = Run::start(cfg(m.addr()), opts(&[0, 1500]), dir.path());
    run.link.submit(&cert(1, &["soon.example.com"], RenewalClass::New));
    run.until("first probe", |r, _| r.names.first.probes == 1).await;
    run.stop();
    m.set("soon.example.com", MockAnswer::addrs(&["192.0.2.3"]));
    let mut run = Run::start(cfg(m.addr()), opts(&[0, 1500]), dir.path());
    let r = run.until("second probe", |r, _| r.names.resolved_later == 1).await;
    assert_eq!(r.waiting, 0);
    let row = run.row("soon.example.com", 1);
    assert_eq!((row.cert_hash, row.lookup.status), (1, Status::Resolved));
    run.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn stays_within_the_query_budget() {
    let m = MockDns::start().await;
    let dir = tempfile::tempdir().unwrap();
    // 20 queries per second is 10 probes per second; names wait at most 500 ms.
    let c = DnsConfig { max_qps: 20, ..cfg(m.addr()) };
    let o = DnsOpts { stale_after: Duration::from_millis(500), ..opts(&[0]) };
    let mut run = Run::start(c, o, dir.path());
    let names: Vec<String> = (0..200).map(|i| format!("n{i}.example.com")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let start = Instant::now();
    run.link.submit(&cert(1, &refs, RenewalClass::New));
    let r = run.until("skips", |r, _| r.queued == 0 && r.in_flight == 0 && r.accepted > 0 && r.probes > 0).await;
    let secs = start.elapsed().as_secs_f64();
    assert!(r.probes as f64 <= 10.0 * secs + 3.0, "{} probes in {secs:.2}s", r.probes);
    assert_eq!(r.probes + r.skipped_busy + r.skipped_stale, 200, "{r:#?}");
    assert!(r.skipped_busy + r.skipped_stale > 150);
    run.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn samples_by_name() {
    let m = MockDns::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut run = Run::start(DnsConfig { sample_pct: 50.0, ..cfg(m.addr()) }, opts(&[0]), dir.path());
    let names: Vec<String> = (0..400).map(|i| format!("s{i}.example.com")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    run.link.submit(&cert(1, &refs, RenewalClass::New));
    let r = run.until("probes", |r, _| r.probes + r.not_sampled == 400).await;
    assert!((150..250).contains(&r.not_sampled), "{}", r.not_sampled);
    run.stop();
}
