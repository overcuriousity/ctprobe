use ctprobe::config::DnsConfig;
use ctprobe::dns::client::{query, query_name, Reply};
use ctprobe::dns::mock::{MockAnswer, MockDns};
use ctprobe::dns::outcome::{Fingerprint, Status};
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
    CertRow {
        parsed: ParsedCert { names: names.iter().map(|n| n.to_string()).collect(), ..Default::default() },
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

fn cfg(resolvers: Vec<SocketAddr>, quorum: usize) -> DnsConfig {
    DnsConfig { resolvers, quorum, max_qps: 10_000, state_max_bytes: 1 << 20 }
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

    /// Waits until `pred` holds for the published report.
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
    let mut run = Run::start(cfg(vec![m.addr()], 1), opts(&[0, 300, 900, 1500]), dir.path());
    run.link.submit(&cert(1, &["*.example.com", "a.example.com", "late.example.com", "v4.example.com"], RenewalClass::New));
    let r = run.until("first probes", |r, _| r.first.probes == 3).await;
    assert_eq!((r.wildcards, r.names), (1, 3));
    assert_eq!((r.first.resolved, r.first.v4, r.first.v6, r.first.both, r.first.nxdomain), (2, 2, 1, 1, 1));
    assert_eq!(r.first_new.probes, 3);
    // The missing name appears between the second and third probe.
    run.until("second probe", |_, rows| rows.iter().any(|r| r.name == "late.example.com" && r.attempt == 1)).await;
    m.set("late.example.com", MockAnswer::addrs(&["192.0.2.9"]));
    let r = run.until("late name", |r, _| r.resolved_later == 1).await;
    assert_eq!(r.later_by_attempt, vec![0, 0, 1, 0]);
    let ttd = r.time_to_dns.clone().unwrap();
    assert!(ttd.p50_ms >= 800.0 && ttd.p50_ms < 3000.0, "{ttd:?}");
    let late: Vec<_> = run.rows.iter().filter(|r| r.name == "late.example.com").collect();
    assert_eq!(late.iter().map(|r| (r.attempt, r.lookup.status)).collect::<Vec<_>>(),
        vec![(0, Status::NxDomain), (1, Status::NxDomain), (2, Status::Resolved)]);
    assert!(late.iter().all(|r| r.cert_hash == 1 && r.renewal == "new"));
    // A name still pending is not probed twice for another certificate.
    m.set("never.example.com", MockAnswer::NxDomain);
    run.link.submit(&cert(2, &["never.example.com"], RenewalClass::New));
    run.link.submit(&cert(3, &["never.example.com"], RenewalClass::Name));
    let r = run.until("never", |r, _| r.never == 1).await;
    assert_eq!(r.already_pending, 1);
    assert_eq!(r.resolvers[0].queries, 2 * r.probes);
    assert!(run.minutes > 0, "minute rows count first probes");
    run.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn compares_with_last_answer_and_keeps_it_across_restarts() {
    let m = MockDns::start().await;
    m.set("moved.example.com", MockAnswer::addrs(&["192.0.2.1"]));
    m.set("same.example.com", MockAnswer::addrs(&["192.0.2.5"]));
    let dir = tempfile::tempdir().unwrap();
    let today = (chrono::Utc::now().timestamp_millis() / 86_400_000) as u16;
    // Thirty days ago, before a renewal, `moved` pointed elsewhere.
    let mut last = LastAnswers::open(&dir.path().join(STATE_FILE), 1 << 20);
    let h = xxhash_rust::xxh3::xxh3_64(b"moved.example.com");
    last.put(h, Last { fp: Fingerprint { exact: 1, network: 1 }, day: today - 30 });
    last.save().unwrap();

    let mut run = Run::start(cfg(vec![m.addr()], 1), opts(&[0]), dir.path());
    run.link.submit(&cert(1, &["moved.example.com", "same.example.com"], RenewalClass::Name));
    let r = run.until("first", |r, _| r.first.probes == 2).await;
    assert_eq!((r.earlier_day.compared, r.earlier_day.changed, r.earlier_day.network_changed), (1, 1, 1));
    let moved = run.rows.iter().find(|r| r.name == "moved.example.com").unwrap();
    assert_eq!((moved.changed, moved.prev_days), (Some(true), Some(30)));
    assert_eq!(run.rows.iter().find(|r| r.name == "same.example.com").unwrap().changed, None);
    assert_eq!(r.first_renewed.probes, 2);
    run.stop();

    // After a restart the answers are still known; only `same` changed, and
    // only its addresses within the same /24.
    m.set("same.example.com", MockAnswer::addrs(&["192.0.2.6"]));
    let mut run = Run::start(cfg(vec![m.addr()], 1), opts(&[0]), dir.path());
    run.link.submit(&cert(2, &["moved.example.com", "same.example.com"], RenewalClass::Exact));
    let r = run.until("second", |r, _| r.first.probes == 2).await;
    assert_eq!((r.same_day.compared, r.same_day.changed, r.same_day.network_changed), (2, 1, 0));
    let same = run.rows.iter().find(|r| r.name == "same.example.com").unwrap();
    assert_eq!((same.changed, same.network_changed, same.prev_days), (Some(true), Some(false), Some(0)));
    run.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn quorum_decides_and_counts_disagreement() {
    let good = MockDns::start().await;
    let good2 = MockDns::start().await;
    let filtering = MockDns::start().await;
    for m in [&good, &good2] {
        m.set("blocked.example.com", MockAnswer::addrs(&["192.0.2.1"]));
    }
    filtering.set("blocked.example.com", MockAnswer::NxDomain);
    let dir = tempfile::tempdir().unwrap();
    let mut run = Run::start(cfg(vec![good.addr(), good2.addr(), filtering.addr()], 2), opts(&[0]), dir.path());
    run.link.submit(&cert(1, &["blocked.example.com"], RenewalClass::New));
    let r = run.until("probe", |r, _| r.first.probes == 1).await;
    assert_eq!(r.first.resolved, 1);
    assert_eq!(r.resolvers.iter().map(|x| x.disagreed).collect::<Vec<_>>(), vec![0, 0, 1]);
    assert_eq!(run.rows[0].agree, 2);
    run.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn stays_within_the_query_budget() {
    let m = MockDns::start().await;
    let dir = tempfile::tempdir().unwrap();
    // 20 queries per second is 10 probes per second; names wait at most 500 ms.
    let c = DnsConfig { max_qps: 20, ..cfg(vec![m.addr()], 1) };
    let o = DnsOpts { stale_after: Duration::from_millis(500), ..opts(&[0]) };
    let mut run = Run::start(c, o, dir.path());
    let names: Vec<String> = (0..200).map(|i| format!("n{i}.example.com")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let start = Instant::now();
    run.link.submit(&cert(1, &refs, RenewalClass::New));
    let r = run.until("skips", |r, _| r.queued == 0 && r.in_flight == 0 && r.names > 0 && r.probes > 0).await;
    let secs = start.elapsed().as_secs_f64();
    assert!(r.probes as f64 <= 10.0 * secs + 3.0, "{} probes in {secs:.2}s", r.probes);
    assert_eq!(r.probes + r.skipped_busy + r.skipped_stale, 200, "{r:#?}");
    assert!(r.skipped_busy + r.skipped_stale > 150);
    run.stop();
}
