//! DNS probing of certificate names. Every unique certificate, renewals
//! included, sends its names here. Each name is probed for A and AAAA right
//! away and, while it has no address, again on a fixed schedule, which bounds
//! the time it took to appear. A name's first probe is compared with the last
//! answer seen for it, so changes between certificates show.
//!
//! It runs on its own thread with its own runtime and a query budget per
//! resolver, so it can neither slow ingest nor exceed the rate it was given.
//! Names that do not fit the budget are skipped and counted, never queued
//! without bound.

pub mod client;
#[cfg(feature = "mock")]
pub mod mock;
pub mod outcome;
pub mod state;

use crate::config::DnsConfig;
use crate::names;
use crate::rates::RateWindow;
use crate::types::{CertRow, RenewalClass};
use client::{query, query_name, Reply};
use hdrhistogram::Histogram;
use hickory_proto::rr::RecordType;
use outcome::{combine, decide, fingerprint, Lookup, Status};
use serde::Serialize;
use state::{Last, LastAnswers};
use std::cmp::{Ordering as Cmp, Reverse};
use std::collections::{BinaryHeap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use xxhash_rust::xxh3::xxh3_64;

const MS_PER_DAY: i64 = 86_400_000;
/// Certificates waiting for the scheduler.
const JOB_QUEUE: usize = 65_536;
/// Rows waiting for the writer, which drains them every 100 ms.
const OUT_QUEUE: usize = 262_144;
const MAX_IN_FLIGHT: usize = 4096;
/// Names waiting for a later probe. Over it, a name gets no further probes.
const MAX_WAITING: usize = 1_000_000;
/// Each query is tried twice before it counts as timed out.
const TRIES: u32 = 2;
pub const STATE_FILE: &str = "dns_state.snap";
const TICK: Duration = Duration::from_millis(10);
const PUBLISH: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct DnsOpts {
    /// When each probe of a name happens, counted from when its certificate
    /// was seen. Probing stops once the name resolves.
    pub schedule: Vec<Duration>,
    /// Per try of one query.
    pub timeout: Duration,
    /// A name whose first probe cannot start this soon is skipped, so first
    /// probes always measure the same moment.
    pub stale_after: Duration,
    pub snapshot_every: Duration,
    /// Interval of `dns_minute` rows.
    pub minute: Duration,
}

impl Default for DnsOpts {
    fn default() -> Self {
        let m = |n: u64| Duration::from_secs(60 * n);
        DnsOpts {
            schedule: vec![Duration::ZERO, m(2), m(15), m(60), m(360), m(1440)],
            timeout: Duration::from_secs(2),
            stale_after: Duration::from_secs(60),
            snapshot_every: Duration::from_secs(6 * 3600),
            minute: Duration::from_secs(60),
        }
    }
}

pub struct Job {
    pub names: Vec<String>,
    pub cert_hash: u64,
    pub seen_at_ms: i64,
    pub renewal: RenewalClass,
}

/// One probe of one name.
#[derive(Debug, Clone)]
pub struct DnsRow {
    pub probed_at_ms: i64,
    pub name: String,
    pub reg_domain: Option<String>,
    pub cert_hash: u64,
    pub cert_seen_at_ms: i64,
    /// 0 for the first probe.
    pub attempt: u8,
    pub renewal: &'static str,
    pub lookup: Lookup,
    /// Slowest resolver's slower query.
    pub latency_ms: u32,
    /// Resolvers that reported the decided outcome.
    pub agree: u8,
    /// First probes only: whether the answer differs from the last one held.
    pub changed: Option<bool>,
    pub network_changed: Option<bool>,
    /// Days since that last answer.
    pub prev_days: Option<u16>,
}

/// Per-minute totals, for trends over long ranges.
#[derive(Debug, Clone, Default)]
pub struct DnsMinuteRow {
    pub minute_ms: i64,
    pub probes: i64,
    pub first_probes: i64,
    pub first_resolved: i64,
    pub first_v4: i64,
    pub first_v6: i64,
    pub first_nodata: i64,
    pub first_nxdomain: i64,
    /// Failures and splits.
    pub first_failed: i64,
    pub resolved_later: i64,
    pub never: i64,
    /// First probes compared with an answer from an earlier day.
    pub compared: i64,
    pub changed: i64,
    pub network_changed: i64,
    /// Names not probed for lack of capacity.
    pub skipped: i64,
    pub ttd_p50_ms: Option<i64>,
    pub ttd_p90_ms: Option<i64>,
}

pub enum DnsOut {
    Row(DnsRow),
    Minute(DnsMinuteRow),
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Outcomes {
    pub probes: u64,
    pub resolved: u64,
    pub v4: u64,
    pub v6: u64,
    pub both: u64,
    pub nodata: u64,
    pub nxdomain: u64,
    pub failed: u64,
    pub split: u64,
}

impl Outcomes {
    fn add(&mut self, l: &Lookup) {
        self.probes += 1;
        match l.status {
            Status::Resolved => self.resolved += 1,
            Status::NoData => self.nodata += 1,
            Status::NxDomain => self.nxdomain += 1,
            Status::Failed => self.failed += 1,
            Status::Split => self.split += 1,
        }
        let (v4, v6) = (!l.v4.is_empty(), !l.v6.is_empty());
        self.v4 += v4 as u64;
        self.v6 += v6 as u64;
        self.both += (v4 && v6) as u64;
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Changes {
    pub compared: u64,
    pub changed: u64,
    pub network_changed: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Quantiles {
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

/// Quantiles of `h`, whose values are `per_ms` to the millisecond.
fn quantiles(h: &Histogram<u64>, per_ms: f64) -> Option<Quantiles> {
    let q = |v: u64| v as f64 / per_ms;
    (!h.is_empty()).then(|| Quantiles {
        p50_ms: q(h.value_at_quantile(0.5)),
        p90_ms: q(h.value_at_quantile(0.9)),
        p99_ms: q(h.value_at_quantile(0.99)),
        max_ms: q(h.max()),
    })
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ResolverReport {
    pub addr: String,
    pub queries: u64,
    pub answers: u64,
    pub nxdomain: u64,
    pub timeouts: u64,
    /// SERVFAIL, REFUSED and other codes, or unreachable.
    pub errors: u64,
    /// Probes where this resolver's outcome differed from the decision.
    pub disagreed: u64,
    pub latency: Option<Quantiles>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsReport {
    pub enabled: bool,
    pub since_ms: i64,
    pub quorum: usize,
    pub max_qps: u32,
    /// Seconds after the certificate was seen of each scheduled probe.
    pub schedule_secs: Vec<u64>,
    pub certs: u64,
    /// Names accepted for probing.
    pub names: u64,
    pub wildcards: u64,
    pub invalid: u64,
    /// Names already being probed for an earlier certificate.
    pub already_pending: u64,
    /// Names skipped because the query budget was used up.
    pub skipped_busy: u64,
    pub skipped_stale: u64,
    pub skipped_queue: u64,
    /// Names that got no further probes because too many were waiting.
    pub retries_dropped: u64,
    pub rows_dropped: u64,
    pub probes: u64,
    pub probes_per_sec: f64,
    pub queued: u64,
    pub waiting: u64,
    pub in_flight: u64,
    pub first: Outcomes,
    /// First probes of names the tracker had never seen.
    pub first_new: Outcomes,
    /// First probes of names seen in an earlier certificate.
    pub first_renewed: Outcomes,
    pub resolved_first: u64,
    pub resolved_later: u64,
    /// Names still without an address after the last probe.
    pub never: u64,
    /// Names resolved at each probe after the first, by probe number.
    pub later_by_attempt: Vec<u64>,
    /// From the certificate sighting to the probe that first found an address.
    pub time_to_dns: Option<Quantiles>,
    /// Compared with an answer from the same day, such as a second CA's certificate.
    pub same_day: Changes,
    /// Compared with an answer from an earlier day, such as before a renewal.
    pub earlier_day: Changes,
    pub resolvers: Vec<ResolverReport>,
    pub tracked_names: u64,
    pub tracked_bytes: u64,
}

/// What the web layer reads. The scheduler republishes it four times a second.
pub struct DnsStats {
    /// Names lost because the certificate queue was full; counted by ingest.
    pub jobs_dropped: AtomicU64,
    report: Mutex<DnsReport>,
}

impl DnsStats {
    pub fn report(&self) -> DnsReport {
        let mut r = self.report.lock().unwrap().clone();
        r.skipped_queue = self.jobs_dropped.load(Ordering::Relaxed);
        r
    }
}

/// The pipeline's side: where certificates go and rows come back.
pub struct DnsLink {
    jobs: mpsc::Sender<Job>,
    pub out: std_mpsc::Receiver<DnsOut>,
    pub stats: Arc<DnsStats>,
}

impl DnsLink {
    /// Hands a certificate's names over without ever waiting.
    pub fn submit(&self, row: &CertRow) {
        if row.parsed.names.is_empty() {
            return;
        }
        let job = Job {
            names: row.parsed.names.clone(),
            cert_hash: row.cert_hash,
            seen_at_ms: row.seen_at_ms,
            renewal: row.renewal,
        };
        if let Err(e) = self.jobs.try_send(job) {
            let n = match e {
                mpsc::error::TrySendError::Full(j) | mpsc::error::TrySendError::Closed(j) => j.names.len(),
            };
            self.stats.jobs_dropped.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
}

/// Starts the prober thread. It stops when `stop` turns true or the link is dropped.
pub fn start(
    cfg: DnsConfig,
    opts: DnsOpts,
    data: &Path,
    stop: watch::Receiver<bool>,
) -> anyhow::Result<(DnsLink, std::thread::JoinHandle<()>)> {
    anyhow::ensure!(!opts.schedule.is_empty(), "empty DNS schedule");
    let (jobs_tx, jobs_rx) = mpsc::channel(JOB_QUEUE);
    let (out_tx, out_rx) = std_mpsc::sync_channel(OUT_QUEUE);
    let stats = Arc::new(DnsStats { jobs_dropped: AtomicU64::new(0), report: Mutex::new(DnsReport::default()) });
    let last = LastAnswers::open(&data.join(STATE_FILE), cfg.state_max_bytes);
    let sched = Scheduler::new(cfg, opts, last, out_tx, stats.clone());
    let thread = std::thread::Builder::new().name("ctprobe-dns".into()).spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => return tracing::error!("DNS runtime: {e}"),
        };
        rt.block_on(sched.run(jobs_rx, stop));
    })?;
    Ok((DnsLink { jobs: jobs_tx, out: out_rx, stats }, thread))
}

struct Pending {
    name: String,
    hash: u64,
    cert_hash: u64,
    seen_at_ms: i64,
    seen: Instant,
    renewal: RenewalClass,
    attempt: u8,
}

struct Waiting {
    due: Instant,
    seq: u64,
    p: Pending,
}

impl PartialEq for Waiting {
    fn eq(&self, o: &Self) -> bool {
        (self.due, self.seq) == (o.due, o.seq)
    }
}
impl Eq for Waiting {}
impl PartialOrd for Waiting {
    fn partial_cmp(&self, o: &Self) -> Option<Cmp> {
        Some(self.cmp(o))
    }
}
impl Ord for Waiting {
    fn cmp(&self, o: &Self) -> Cmp {
        (self.due, self.seq).cmp(&(o.due, o.seq))
    }
}

type Replies = ((Reply, Duration), (Reply, Duration));

struct Done {
    p: Pending,
    per: Vec<Replies>,
}

struct ResolverAgg {
    r: ResolverReport,
    /// Microseconds.
    latency: Histogram<u64>,
}

fn histogram() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 1 << 42, 2).expect("valid bounds")
}

struct Scheduler {
    cfg: DnsConfig,
    opts: DnsOpts,
    resolvers: Arc<Vec<SocketAddr>>,
    last: LastAnswers,
    out: std_mpsc::SyncSender<DnsOut>,
    stats: Arc<DnsStats>,
    fresh: VecDeque<Pending>,
    fresh_max: usize,
    waiting: BinaryHeap<Reverse<Waiting>>,
    seq: u64,
    /// Names being probed or waiting for their next probe.
    active: HashSet<u64>,
    in_flight: usize,
    rate: f64,
    tokens: f64,
    refilled: Instant,
    report: DnsReport,
    agg: Vec<ResolverAgg>,
    ttd: Histogram<u64>,
    per_sec: RateWindow,
    started: Instant,
    minute: DnsMinuteRow,
    minute_ttd: Histogram<u64>,
    /// Skips counted into earlier minute rows.
    skipped_seen: u64,
}

impl Scheduler {
    fn new(
        cfg: DnsConfig,
        opts: DnsOpts,
        last: LastAnswers,
        out: std_mpsc::SyncSender<DnsOut>,
        stats: Arc<DnsStats>,
    ) -> Scheduler {
        // Every probe sends an A and an AAAA query to each resolver.
        let rate = cfg.max_qps as f64 / 2.0;
        let report = DnsReport {
            enabled: true,
            since_ms: chrono::Utc::now().timestamp_millis(),
            quorum: cfg.quorum,
            max_qps: cfg.max_qps,
            schedule_secs: opts.schedule.iter().map(|d| d.as_secs()).collect(),
            later_by_attempt: vec![0; opts.schedule.len()],
            ..Default::default()
        };
        let agg = cfg
            .resolvers
            .iter()
            .map(|a| ResolverAgg { r: ResolverReport { addr: a.to_string(), ..Default::default() }, latency: histogram() })
            .collect();
        Scheduler {
            resolvers: Arc::new(cfg.resolvers.clone()),
            fresh_max: ((rate * opts.stale_after.as_secs_f64()).ceil() as usize).max(64),
            cfg,
            opts,
            last,
            out,
            stats,
            fresh: VecDeque::new(),
            waiting: BinaryHeap::new(),
            seq: 0,
            active: HashSet::new(),
            in_flight: 0,
            rate,
            tokens: 1.0,
            refilled: Instant::now(),
            report,
            agg,
            ttd: histogram(),
            per_sec: RateWindow::new(60),
            started: Instant::now(),
            minute: DnsMinuteRow::default(),
            minute_ttd: histogram(),
            skipped_seen: 0,
        }
    }

    async fn run(mut self, mut jobs: mpsc::Receiver<Job>, mut stop: watch::Receiver<bool>) {
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<Done>();
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let (mut last_sec, mut last_min, mut last_snap) = (Instant::now(), Instant::now(), Instant::now());
        self.publish();
        loop {
            if *stop.borrow() {
                break;
            }
            tokio::select! {
                r = stop.changed() => if r.is_err() { break },
                Some(d) = done_rx.recv() => self.finish(d),
                j = jobs.recv() => match j {
                    Some(j) => self.accept(j),
                    None => break,
                },
                _ = tick.tick() => {}
            }
            self.dispatch(&done_tx);
            if last_sec.elapsed() >= PUBLISH {
                self.publish();
                last_sec = Instant::now();
            }
            if last_min.elapsed() >= self.opts.minute {
                self.emit_minute();
                last_min = Instant::now();
            }
            if last_snap.elapsed() >= self.opts.snapshot_every {
                self.save();
                last_snap = Instant::now();
            }
        }
        self.emit_minute();
        self.save();
    }

    fn save(&self) {
        if let Err(e) = self.last.save() {
            tracing::warn!("saving DNS state: {e:#}");
        }
    }

    fn accept(&mut self, job: Job) {
        self.report.certs += 1;
        for name in job.names {
            if name.starts_with("*.") {
                self.report.wildcards += 1;
                continue;
            }
            let hash = xxh3_64(name.as_bytes());
            if self.active.contains(&hash) {
                self.report.already_pending += 1;
                continue;
            }
            if self.fresh.len() >= self.fresh_max {
                self.report.skipped_busy += 1;
                continue;
            }
            if query_name(&name).is_none() {
                self.report.invalid += 1;
                continue;
            }
            self.active.insert(hash);
            self.report.names += 1;
            self.fresh.push_back(Pending {
                name,
                hash,
                cert_hash: job.cert_hash,
                seen_at_ms: job.seen_at_ms,
                seen: Instant::now(),
                renewal: job.renewal,
                attempt: 0,
            });
        }
    }

    /// The oldest name due for its first probe, skipping those gone stale.
    fn next_fresh(&mut self, now: Instant) -> Option<Pending> {
        loop {
            let due = self.fresh.front()?.seen + self.opts.schedule[0];
            if due > now {
                return None;
            }
            let p = self.fresh.pop_front()?;
            if now.duration_since(due) <= self.opts.stale_after {
                return Some(p);
            }
            self.report.skipped_stale += 1;
            self.active.remove(&p.hash);
        }
    }

    /// Starts probes while the budget allows. Later probes go first, since
    /// their timing is what bounds the time to DNS.
    fn dispatch(&mut self, done: &mpsc::UnboundedSender<Done>) {
        let now = Instant::now();
        let burst = (self.rate / 10.0).max(1.0);
        self.tokens = (self.tokens + now.duration_since(self.refilled).as_secs_f64() * self.rate).min(burst);
        self.refilled = now;
        while self.tokens >= 1.0 && self.in_flight < MAX_IN_FLIGHT {
            let p = match self.waiting.peek() {
                Some(Reverse(w)) if w.due <= now => self.waiting.pop().expect("peeked").0.p,
                _ => match self.next_fresh(now) {
                    Some(p) => p,
                    None => break,
                },
            };
            let Some(qn) = query_name(&p.name) else {
                self.active.remove(&p.hash);
                continue;
            };
            self.tokens -= 1.0;
            self.in_flight += 1;
            let (resolvers, timeout, done) = (self.resolvers.clone(), self.opts.timeout, done.clone());
            tokio::spawn(async move {
                let per = futures::future::join_all(resolvers.iter().map(|r| {
                    let qn = &qn;
                    async move {
                        tokio::join!(
                            query(*r, qn, RecordType::A, timeout, TRIES),
                            query(*r, qn, RecordType::AAAA, timeout, TRIES)
                        )
                    }
                }))
                .await;
                let _ = done.send(Done { p, per });
            });
        }
    }

    fn finish(&mut self, d: Done) {
        self.in_flight -= 1;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let today = (now_ms / MS_PER_DAY) as u16;
        let per: Vec<Lookup> = d.per.iter().map(|((a, _), (b, _))| combine(a, b)).collect();
        let (decided, agree) = decide(&per, self.cfg.quorum);
        let mut latency = Duration::ZERO;
        for (i, ((a, ta), (b, tb))) in d.per.iter().enumerate() {
            let agg = &mut self.agg[i];
            for (r, t) in [(a, ta), (b, tb)] {
                agg.r.queries += 1;
                match r {
                    Reply::Answer { .. } => agg.r.answers += 1,
                    Reply::NxDomain => agg.r.nxdomain += 1,
                    Reply::Timeout => agg.r.timeouts += 1,
                    Reply::Rcode(_) | Reply::Error => agg.r.errors += 1,
                }
                if !matches!(r, Reply::Timeout) {
                    agg.latency.saturating_record(t.as_micros().max(1) as u64);
                }
                latency = latency.max(*t);
            }
            agg.r.disagreed += (per[i].status != decided.status) as u64;
        }

        let p = d.p;
        let first = p.attempt == 0;
        let (mut changed, mut network_changed, mut prev_days) = (None, None, None);
        if decided.status.conclusive() {
            let fp = fingerprint(&decided);
            if let (true, Some(prev)) = (first, self.last.get(p.hash)) {
                let days = today.saturating_sub(prev.day);
                let (c, n) = (prev.fp.exact != fp.exact, prev.fp.network != fp.network);
                let bucket = if days == 0 { &mut self.report.same_day } else { &mut self.report.earlier_day };
                bucket.compared += 1;
                bucket.changed += c as u64;
                bucket.network_changed += n as u64;
                if days > 0 {
                    self.minute.compared += 1;
                    self.minute.changed += c as i64;
                    self.minute.network_changed += n as i64;
                }
                (changed, network_changed, prev_days) = (Some(c), Some(n), Some(days));
            }
            self.last.put(p.hash, Last { fp, day: today });
        }

        self.report.probes += 1;
        self.minute.probes += 1;
        if first {
            self.report.first.add(&decided);
            match p.renewal {
                RenewalClass::New => self.report.first_new.add(&decided),
                _ => self.report.first_renewed.add(&decided),
            }
            let m = &mut self.minute;
            m.first_probes += 1;
            m.first_v4 += !decided.v4.is_empty() as i64;
            m.first_v6 += !decided.v6.is_empty() as i64;
            match decided.status {
                Status::Resolved => m.first_resolved += 1,
                Status::NoData => m.first_nodata += 1,
                Status::NxDomain => m.first_nxdomain += 1,
                Status::Failed | Status::Split => m.first_failed += 1,
            }
        }

        let row = DnsRow {
            probed_at_ms: now_ms,
            reg_domain: names::registered_domain(&p.name),
            name: p.name.clone(),
            cert_hash: p.cert_hash,
            cert_seen_at_ms: p.seen_at_ms,
            attempt: p.attempt,
            renewal: p.renewal.as_str(),
            lookup: decided,
            latency_ms: latency.as_millis().min(u32::MAX as u128) as u32,
            agree: agree.min(u8::MAX as usize) as u8,
            changed,
            network_changed,
            prev_days,
        };
        let resolved = row.lookup.status == Status::Resolved;
        if self.out.try_send(DnsOut::Row(row)).is_err() {
            self.report.rows_dropped += 1;
        }

        let next = p.attempt as usize + 1;
        if resolved {
            if first {
                self.report.resolved_first += 1;
            } else {
                self.report.resolved_later += 1;
                self.report.later_by_attempt[p.attempt as usize] += 1;
                let ttd = (now_ms - p.seen_at_ms).max(1) as u64;
                self.ttd.saturating_record(ttd);
                self.minute_ttd.saturating_record(ttd);
                self.minute.resolved_later += 1;
            }
            self.active.remove(&p.hash);
        } else if next >= self.opts.schedule.len() {
            self.report.never += 1;
            self.minute.never += 1;
            self.active.remove(&p.hash);
        } else if self.waiting.len() >= MAX_WAITING {
            self.report.retries_dropped += 1;
            self.active.remove(&p.hash);
        } else {
            self.seq += 1;
            let due = p.seen + self.opts.schedule[next];
            self.waiting.push(Reverse(Waiting { due, seq: self.seq, p: Pending { attempt: next as u8, ..p } }));
        }
    }

    fn skipped_total(&self) -> u64 {
        self.report.skipped_busy
            + self.report.skipped_stale
            + self.report.retries_dropped
            + self.stats.jobs_dropped.load(Ordering::Relaxed)
    }

    fn emit_minute(&mut self) {
        let now = chrono::Utc::now().timestamp_millis();
        let skipped = self.skipped_total();
        let mut m = std::mem::take(&mut self.minute);
        m.minute_ms = now - now.rem_euclid(60_000);
        m.skipped = (skipped - self.skipped_seen) as i64;
        self.skipped_seen = skipped;
        if !self.minute_ttd.is_empty() {
            m.ttd_p50_ms = Some(self.minute_ttd.value_at_quantile(0.5) as i64);
            m.ttd_p90_ms = Some(self.minute_ttd.value_at_quantile(0.9) as i64);
        }
        self.minute_ttd.reset();
        if m.probes > 0 || m.skipped > 0 {
            let _ = self.out.try_send(DnsOut::Minute(m));
        }
    }

    fn publish(&mut self) {
        self.per_sec.push(self.started.elapsed().as_millis() as i64, self.report.probes);
        let r = &mut self.report;
        r.probes_per_sec = self.per_sec.rate();
        r.queued = self.fresh.len() as u64;
        r.waiting = self.waiting.len() as u64;
        r.in_flight = self.in_flight as u64;
        r.time_to_dns = quantiles(&self.ttd, 1.0);
        r.resolvers = self
            .agg
            .iter()
            .map(|a| ResolverReport { latency: quantiles(&a.latency, 1000.0), ..a.r.clone() })
            .collect();
        r.tracked_names = self.last.len() as u64;
        r.tracked_bytes = self.last.bytes_used();
        *self.stats.report.lock().unwrap() = r.clone();
    }
}
