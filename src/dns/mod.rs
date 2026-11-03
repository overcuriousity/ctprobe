//! DNS probing of certificate names. Every unique certificate, renewals
//! included, sends its names here. Each name is probed for A and AAAA right
//! away and, while it has no address, again on a schedule of up to 30 days,
//! which bounds the time it took to appear. A name's first probe is compared
//! with the last answer held for it, so changes between certificates show.
//!
//! Wildcards are asked as written, which answers whether a wildcard record
//! exists, and for the name they cover when the certificate does not list it.
//!
//! It runs on its own thread with its own runtime and a query budget, so it
//! can neither slow ingest nor exceed the rate it was given. Names are sampled
//! by a hash of the name, so the same names are probed on every certificate
//! and comparisons across renewals stay complete. Names that do not fit the
//! budget in a burst are skipped and counted; later probes wait and run late.

pub mod client;
#[cfg(feature = "mock")]
pub mod mock;
pub mod outcome;
pub mod queue;
pub mod state;

use crate::config::DnsConfig;
use crate::names;
use crate::rates::RateWindow;
use crate::types::{CertRow, RenewalClass};
use client::{query, query_name, Reply};
use hdrhistogram::Histogram;
use hickory_proto::rr::RecordType;
use outcome::{combine, Lookup, Status};
use queue::{Kind, Pending, Queue};
use serde::Serialize;
use state::{diff, Diff, Last, LastAnswers};
use std::collections::{HashSet, VecDeque};
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
/// Each query is tried twice before it counts as timed out.
const TRIES: u32 = 2;
pub const STATE_FILE: &str = "dns_state.snap";
pub const QUEUE_FILE: &str = "dns_queue.redb";
const TICK: Duration = Duration::from_millis(10);
const PUBLISH: Duration = Duration::from_millis(250);
/// How often waiting names are written and due ones taken out.
const SYNC: Duration = Duration::from_millis(500);

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

/// From the sighting: finer steps first, then daily, up to 30 days.
pub fn default_schedule() -> Vec<Duration> {
    let m = |n: u64| Duration::from_secs(60 * n);
    let h = |n: u64| m(60 * n);
    let d = |n: u64| h(24 * n);
    vec![
        Duration::ZERO, m(1), m(2), m(5), m(10), m(15), m(30), h(1), h(2), h(3), h(6), h(12),
        d(1), h(36), d(2), d(3), d(4), d(5), d(7), d(10), d(14), d(21), d(30),
    ]
}

impl Default for DnsOpts {
    fn default() -> Self {
        DnsOpts {
            schedule: default_schedule(),
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
    pub kind: Kind,
    pub reg_domain: Option<String>,
    pub cert_hash: u64,
    pub cert_seen_at_ms: i64,
    /// 0 for the first probe.
    pub attempt: u8,
    pub renewal: &'static str,
    pub lookup: Lookup,
    /// The slower of the two queries.
    pub latency_ms: u32,
    /// When the probe before this one found no address.
    pub last_miss_ms: Option<i64>,
    /// First probes only: the last answer held for the name, and how this one differs.
    pub prev: Option<(Last, Diff)>,
}

/// Per-minute totals of certificate names (not wildcards), for long trends.
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
    pub first_failed: i64,
    pub resolved_later: i64,
    pub never: i64,
    /// First probes compared with an answer from an earlier day.
    pub compared: i64,
    pub changed: i64,
    pub v4_compared: i64,
    pub v4_changed: i64,
    pub v6_compared: i64,
    pub v6_changed: i64,
    pub network_changed: i64,
    /// Names not probed for lack of capacity.
    pub skipped: i64,
    pub ttd_p50_ms: Option<i64>,
    pub ttd_p90_ms: Option<i64>,
    /// Names found later, by when the probe that found them ran after the sighting.
    pub found_15m: i64,
    pub found_1h: i64,
    pub found_1d: i64,
    pub found_later: i64,
    /// Queries sent, for every kind of name.
    pub queries: i64,
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
}

impl Outcomes {
    fn add(&mut self, l: &Lookup) {
        self.probes += 1;
        match l.status {
            Status::Resolved => self.resolved += 1,
            Status::NoData => self.nodata += 1,
            Status::NxDomain => self.nxdomain += 1,
            Status::Failed => self.failed += 1,
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
    /// Any difference: addresses, aliases or outcome.
    pub changed: u64,
    pub status_changed: u64,
    /// Names whose IPv4 or IPv6 addresses differ, gained or lost included.
    pub ip_changed: u64,
    pub cname_changed: u64,
    pub network_changed: u64,
    /// Compared answers that both had IPv4 addresses.
    pub v4_compared: u64,
    pub v4_changed: u64,
    /// No IPv4 address in common, of those whose earlier addresses are all known.
    pub v4_replaced: u64,
    pub v4_replaced_known: u64,
    pub v6_compared: u64,
    pub v6_changed: u64,
    pub v6_replaced: u64,
    pub v6_replaced_known: u64,
}

impl Changes {
    fn add(&mut self, d: &Diff) {
        self.compared += 1;
        self.changed += d.changed as u64;
        self.status_changed += d.status_changed as u64;
        self.ip_changed += (d.v4_changed || d.v6_changed) as u64;
        self.cname_changed += d.cname_changed as u64;
        self.network_changed += d.network_changed as u64;
        if let Some(f) = d.v4 {
            self.v4_compared += 1;
            self.v4_changed += f.changed as u64;
            if let Some(r) = f.replaced {
                self.v4_replaced_known += 1;
                self.v4_replaced += r as u64;
            }
        }
        if let Some(f) = d.v6 {
            self.v6_compared += 1;
            self.v6_changed += f.changed as u64;
            if let Some(r) = f.replaced {
                self.v6_replaced_known += 1;
                self.v6_replaced += r as u64;
            }
        }
    }
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

/// Figures for one kind of name.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Group {
    pub first: Outcomes,
    /// First probes of names the tracker had never seen.
    pub first_new: Outcomes,
    /// First probes of names seen in an earlier certificate.
    pub first_renewed: Outcomes,
    pub resolved_first: u64,
    pub resolved_later: u64,
    /// Names still without an address after the last probe.
    pub never: u64,
    /// Names resolved at each probe, by probe number.
    pub later_by_attempt: Vec<u64>,
    /// From the sighting to the probe that first found an address: an upper bound.
    pub time_to_dns: Option<Quantiles>,
    /// From the sighting to the probe before it, which found none: a lower bound.
    pub time_to_dns_lower: Option<Quantiles>,
    /// Compared with an answer from the same day, such as a second CA's certificate.
    pub same_day: Changes,
    /// Compared with an answer from an earlier day, such as before a renewal.
    pub earlier_day: Changes,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ResolverReport {
    pub addr: String,
    pub queries: u64,
    pub answers: u64,
    pub nxdomain: u64,
    pub timeouts: u64,
    /// All of the four below.
    pub errors: u64,
    pub servfail: u64,
    pub refused: u64,
    /// Other response codes.
    pub other_rcode: u64,
    /// Nothing listening, or an unreadable reply.
    pub unreachable: u64,
    pub latency: Option<Quantiles>,
}

/// The last few minutes, for telling whether probing works right now.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Recent {
    pub secs: f64,
    pub queries: u64,
    pub answers: u64,
    pub nxdomain: u64,
    pub timeouts: u64,
    pub errors: u64,
    pub servfail: u64,
    pub refused: u64,
    pub unreachable: u64,
    /// Names skipped for lack of capacity.
    pub skipped: u64,
}

/// Span of `Recent`.
const RECENT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsReport {
    pub enabled: bool,
    pub since_ms: i64,
    pub max_qps: u32,
    pub sample_pct: f64,
    /// Seconds after the sighting of each scheduled probe.
    pub schedule_secs: Vec<u64>,
    pub certs: u64,
    /// Names, wildcards and covered names queued for probing.
    pub accepted: u64,
    pub not_sampled: u64,
    pub invalid: u64,
    /// Names already being probed for an earlier certificate.
    pub already_pending: u64,
    /// Names skipped because the query budget was used up.
    pub skipped_busy: u64,
    pub skipped_stale: u64,
    pub skipped_queue: u64,
    pub rows_dropped: u64,
    pub probes: u64,
    pub probes_per_sec: f64,
    pub queued: u64,
    pub waiting: u64,
    pub in_flight: u64,
    /// How late later probes ran against their schedule.
    pub retry_late: Option<Quantiles>,
    pub names: Group,
    pub wildcards: Group,
    pub bases: Group,
    pub resolver: ResolverReport,
    pub tracked_names: u64,
    pub tracked_bytes: u64,
    /// The last error of the retry queue, if any.
    pub queue_error: Option<String>,
    pub recent: Recent,
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
    let resolver = cfg.resolver.ok_or_else(|| anyhow::anyhow!("no DNS resolver configured"))?;
    let (jobs_tx, jobs_rx) = mpsc::channel(JOB_QUEUE);
    let (out_tx, out_rx) = std_mpsc::sync_channel(OUT_QUEUE);
    let stats = Arc::new(DnsStats { jobs_dropped: AtomicU64::new(0), report: Mutex::new(DnsReport::default()) });
    let last = LastAnswers::open(&data.join(STATE_FILE), cfg.state_max_bytes);
    let queue = Queue::open(&data.join(QUEUE_FILE))?;
    let active: HashSet<u64> = queue.keys()?.into_iter().collect();
    let sched = Scheduler::new(cfg, resolver, opts, last, queue, active, out_tx, stats.clone());
    let thread = std::thread::Builder::new().name("ctprobe-dns".into()).spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => return tracing::error!("DNS runtime: {e}"),
        };
        rt.block_on(sched.run(jobs_rx, stop));
    })?;
    Ok((DnsLink { jobs: jobs_tx, out: out_rx, stats }, thread))
}

/// Whether a name is in the sample: the same answer on every certificate.
fn sampled(name: &str, pct: f64) -> bool {
    pct >= 100.0 || ((xxh3_64(name.as_bytes()) >> 11) as f64 / (1u64 << 53) as f64) * 100.0 < pct
}

fn key_of(name: &str, kind: Kind) -> u64 {
    match kind {
        Kind::Base => xxh3_64(format!("base:{name}").as_bytes()),
        _ => xxh3_64(name.as_bytes()),
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

type Replies = ((Reply, Duration), (Reply, Duration));

struct Done {
    p: Pending,
    replies: Replies,
}

fn histogram() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 1 << 42, 2).expect("valid bounds")
}

/// Running figures of one kind; the histograms are kept apart from `Group`.
struct GroupAgg {
    g: Group,
    upper: Histogram<u64>,
    lower: Histogram<u64>,
}

impl GroupAgg {
    fn new(probes: usize) -> GroupAgg {
        GroupAgg { g: Group { later_by_attempt: vec![0; probes], ..Default::default() }, upper: histogram(), lower: histogram() }
    }

    fn report(&self) -> Group {
        Group { time_to_dns: quantiles(&self.upper, 1.0), time_to_dns_lower: quantiles(&self.lower, 1.0), ..self.g.clone() }
    }
}

struct Scheduler {
    cfg: DnsConfig,
    opts: DnsOpts,
    resolver: SocketAddr,
    last: LastAnswers,
    queue: Queue,
    out: std_mpsc::SyncSender<DnsOut>,
    stats: Arc<DnsStats>,
    /// Names waiting for their first probe.
    fresh: VecDeque<Pending>,
    fresh_max: usize,
    /// Later probes taken from the queue, with their due time.
    due: VecDeque<(i64, Pending)>,
    /// Names being probed or waiting for their next probe.
    active: HashSet<u64>,
    in_flight: usize,
    rate: f64,
    tokens: f64,
    refilled: Instant,
    report: DnsReport,
    groups: [GroupAgg; 3],
    latency: Histogram<u64>,
    late: Histogram<u64>,
    per_sec: RateWindow,
    started: Instant,
    minute: DnsMinuteRow,
    minute_ttd: Histogram<u64>,
    /// Skips counted into earlier minute rows.
    skipped_seen: u64,
    /// Counters as published, oldest first, for `Recent`.
    history: VecDeque<(Instant, Recent)>,
}

fn group_index(k: Kind) -> usize {
    match k {
        Kind::Name => 0,
        Kind::Wildcard => 1,
        Kind::Base => 2,
    }
}

impl Scheduler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        cfg: DnsConfig,
        resolver: SocketAddr,
        opts: DnsOpts,
        last: LastAnswers,
        queue: Queue,
        active: HashSet<u64>,
        out: std_mpsc::SyncSender<DnsOut>,
        stats: Arc<DnsStats>,
    ) -> Scheduler {
        // Every probe sends an A and an AAAA query.
        let rate = cfg.max_qps as f64 / 2.0;
        let n = opts.schedule.len();
        let report = DnsReport {
            enabled: true,
            since_ms: now_ms(),
            max_qps: cfg.max_qps,
            sample_pct: cfg.sample_pct,
            schedule_secs: opts.schedule.iter().map(|d| d.as_secs()).collect(),
            resolver: ResolverReport { addr: resolver.to_string(), ..Default::default() },
            ..Default::default()
        };
        Scheduler {
            fresh_max: ((rate * opts.stale_after.as_secs_f64()).ceil() as usize).max(64),
            cfg,
            opts,
            resolver,
            last,
            queue,
            out,
            stats,
            fresh: VecDeque::new(),
            due: VecDeque::new(),
            active,
            in_flight: 0,
            rate,
            tokens: 1.0,
            refilled: Instant::now(),
            report,
            groups: [GroupAgg::new(n), GroupAgg::new(n), GroupAgg::new(n)],
            latency: histogram(),
            late: histogram(),
            per_sec: RateWindow::new(60),
            started: Instant::now(),
            minute: DnsMinuteRow::default(),
            minute_ttd: histogram(),
            skipped_seen: 0,
            history: VecDeque::new(),
        }
    }

    async fn run(mut self, mut jobs: mpsc::Receiver<Job>, mut stop: watch::Receiver<bool>) {
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<Done>();
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_pub = Instant::now();
        let mut last_min = Instant::now();
        let mut last_snap = Instant::now();
        let mut last_sync = Instant::now() - SYNC;
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
            if last_sync.elapsed() >= SYNC {
                self.sync();
                last_sync = Instant::now();
            }
            self.dispatch(&done_tx);
            if last_pub.elapsed() >= PUBLISH {
                self.publish();
                last_pub = Instant::now();
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
        // Names taken out but not probed go back, so a restart misses none.
        for (due, p) in std::mem::take(&mut self.due) {
            self.queue.push(due, p);
        }
        if let Err(e) = self.queue.sync(0, 0) {
            tracing::warn!("saving DNS queue: {e:#}");
        }
        self.emit_minute();
        self.save();
    }

    fn save(&self) {
        if let Err(e) = self.last.save() {
            tracing::warn!("saving DNS state: {e:#}");
        }
    }

    /// Writes new waiting names and tops up the due ones for the next second.
    fn sync(&mut self) {
        let want = ((self.rate * 2.0) as usize).max(16).saturating_sub(self.due.len());
        match self.queue.sync(now_ms(), want) {
            Ok(got) => {
                self.due.extend(got);
                self.report.queue_error = None;
            }
            Err(e) => {
                tracing::warn!("DNS queue: {e:#}");
                self.report.queue_error = Some(format!("{e:#}"));
            }
        }
    }

    fn accept(&mut self, job: Job) {
        self.report.certs += 1;
        for name in &job.names {
            if !sampled(name, self.cfg.sample_pct) {
                self.report.not_sampled += 1;
                continue;
            }
            match name.strip_prefix("*.") {
                Some(base) => {
                    self.enqueue(&job, name.clone(), Kind::Wildcard);
                    if job.names.binary_search_by(|n| n.as_str().cmp(base)).is_err() {
                        self.enqueue(&job, base.to_string(), Kind::Base);
                    }
                }
                None => self.enqueue(&job, name.clone(), Kind::Name),
            }
        }
    }

    fn enqueue(&mut self, job: &Job, name: String, kind: Kind) {
        let key = key_of(&name, kind);
        if self.active.contains(&key) {
            self.report.already_pending += 1;
            return;
        }
        if self.fresh.len() >= self.fresh_max {
            self.report.skipped_busy += 1;
            return;
        }
        if query_name(&name).is_none() {
            self.report.invalid += 1;
            return;
        }
        self.active.insert(key);
        self.report.accepted += 1;
        self.fresh.push_back(Pending {
            name,
            key,
            kind,
            cert_hash: job.cert_hash,
            seen_at_ms: job.seen_at_ms,
            renewal: job.renewal,
            attempt: 0,
            last_ms: None,
        });
    }

    /// The oldest name due for its first probe, skipping those gone stale.
    fn next_fresh(&mut self, now: i64) -> Option<Pending> {
        let first = self.opts.schedule[0].as_millis() as i64;
        let stale = self.opts.stale_after.as_millis() as i64;
        loop {
            let due = self.fresh.front()?.seen_at_ms + first;
            if due > now {
                return None;
            }
            let p = self.fresh.pop_front()?;
            if now - due <= stale {
                return Some(p);
            }
            self.report.skipped_stale += 1;
            self.active.remove(&p.key);
        }
    }

    /// Starts probes while the budget allows. First probes go first: they
    /// must run at the sighting, while a later probe that runs late still
    /// bounds the time to DNS correctly, if more loosely.
    fn dispatch(&mut self, done: &mpsc::UnboundedSender<Done>) {
        let now = Instant::now();
        let burst = (self.rate / 10.0).max(1.0);
        self.tokens = (self.tokens + now.duration_since(self.refilled).as_secs_f64() * self.rate).min(burst);
        self.refilled = now;
        let wall = now_ms();
        while self.tokens >= 1.0 && self.in_flight < MAX_IN_FLIGHT {
            let p = match self.next_fresh(wall) {
                Some(p) => p,
                None => match self.due.pop_front() {
                    Some((due, p)) => {
                        self.late.saturating_record((wall - due).max(1) as u64);
                        p
                    }
                    None => break,
                },
            };
            let Some(qn) = query_name(&p.name) else {
                self.active.remove(&p.key);
                continue;
            };
            self.tokens -= 1.0;
            self.in_flight += 1;
            let (server, timeout, done) = (self.resolver, self.opts.timeout, done.clone());
            tokio::spawn(async move {
                let replies = tokio::join!(
                    query(server, &qn, RecordType::A, timeout, TRIES),
                    query(server, &qn, RecordType::AAAA, timeout, TRIES)
                );
                let _ = done.send(Done { p, replies });
            });
        }
    }

    fn finish(&mut self, d: Done) {
        self.in_flight -= 1;
        let now = now_ms();
        let today = (now / MS_PER_DAY) as u16;
        let ((a, ta), (b, tb)) = &d.replies;
        let lookup = combine(a, b);
        for (r, t) in [(a, ta), (b, tb)] {
            let s = &mut self.report.resolver;
            s.queries += 1;
            match r {
                Reply::Answer { .. } => s.answers += 1,
                Reply::NxDomain => s.nxdomain += 1,
                Reply::Timeout => s.timeouts += 1,
                Reply::Rcode(2) => s.servfail += 1,
                Reply::Rcode(5) => s.refused += 1,
                Reply::Rcode(_) => s.other_rcode += 1,
                Reply::Error => s.unreachable += 1,
            }
            s.errors = s.servfail + s.refused + s.other_rcode + s.unreachable;
            self.minute.queries += 1;
            if !matches!(r, Reply::Timeout) {
                self.latency.saturating_record(t.as_micros().max(1) as u64);
            }
        }

        let p = d.p;
        let first = p.attempt == 0;
        let is_name = p.kind == Kind::Name;
        let mut prev = None;
        if lookup.status.conclusive() {
            let cur = Last::of(&lookup, today);
            if let (true, Some(old)) = (first, self.last.get(p.key)) {
                let change = diff(&old, &cur, &lookup, today);
                let g = &mut self.groups[group_index(p.kind)].g;
                if change.days == 0 { g.same_day.add(&change) } else { g.earlier_day.add(&change) }
                if is_name && change.days > 0 {
                    let m = &mut self.minute;
                    m.compared += 1;
                    m.changed += change.changed as i64;
                    m.network_changed += change.network_changed as i64;
                    if let Some(f) = change.v4 {
                        m.v4_compared += 1;
                        m.v4_changed += f.changed as i64;
                    }
                    if let Some(f) = change.v6 {
                        m.v6_compared += 1;
                        m.v6_changed += f.changed as i64;
                    }
                }
                prev = Some((old, change));
            }
            self.last.put(p.key, cur);
        }

        self.report.probes += 1;
        if is_name {
            self.minute.probes += 1;
        }
        let g = &mut self.groups[group_index(p.kind)];
        if first {
            g.g.first.add(&lookup);
            match p.renewal {
                RenewalClass::New => g.g.first_new.add(&lookup),
                _ => g.g.first_renewed.add(&lookup),
            }
            if is_name {
                let m = &mut self.minute;
                m.first_probes += 1;
                m.first_v4 += !lookup.v4.is_empty() as i64;
                m.first_v6 += !lookup.v6.is_empty() as i64;
                match lookup.status {
                    Status::Resolved => m.first_resolved += 1,
                    Status::NoData => m.first_nodata += 1,
                    Status::NxDomain => m.first_nxdomain += 1,
                    Status::Failed => m.first_failed += 1,
                }
            }
        }

        let resolved = lookup.status == Status::Resolved;
        let next = p.attempt as usize + 1;
        if resolved {
            if first {
                g.g.resolved_first += 1;
            } else {
                g.g.resolved_later += 1;
                g.g.later_by_attempt[p.attempt as usize] += 1;
                let upper = (now - p.seen_at_ms).max(1) as u64;
                g.upper.saturating_record(upper);
                if let Some(l) = p.last_ms {
                    g.lower.saturating_record((l - p.seen_at_ms).max(1) as u64);
                }
                if is_name {
                    self.minute_ttd.saturating_record(upper);
                    let m = &mut self.minute;
                    m.resolved_later += 1;
                    const MIN: u64 = 60_000;
                    match upper {
                        u if u <= 15 * MIN => m.found_15m += 1,
                        u if u <= 60 * MIN => m.found_1h += 1,
                        u if u <= 1440 * MIN => m.found_1d += 1,
                        _ => m.found_later += 1,
                    }
                }
            }
        } else if next >= self.opts.schedule.len() {
            g.g.never += 1;
            if is_name {
                self.minute.never += 1;
            }
        }

        let row = DnsRow {
            probed_at_ms: now,
            reg_domain: names::registered_domain(&p.name),
            name: p.name.clone(),
            kind: p.kind,
            cert_hash: p.cert_hash,
            cert_seen_at_ms: p.seen_at_ms,
            attempt: p.attempt,
            renewal: p.renewal.as_str(),
            lookup,
            latency_ms: ta.max(tb).as_millis().min(u32::MAX as u128) as u32,
            last_miss_ms: p.last_ms,
            prev,
        };
        if self.out.try_send(DnsOut::Row(row)).is_err() {
            self.report.rows_dropped += 1;
        }

        if resolved || next >= self.opts.schedule.len() {
            self.active.remove(&p.key);
        } else {
            let due = p.seen_at_ms + self.opts.schedule[next].as_millis() as i64;
            self.queue.push(due, Pending { attempt: next as u8, last_ms: Some(now), ..p });
        }
    }

    fn skipped_total(&self) -> u64 {
        self.report.skipped_busy + self.report.skipped_stale + self.stats.jobs_dropped.load(Ordering::Relaxed)
    }

    fn emit_minute(&mut self) {
        let now = now_ms();
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
        if m.probes > 0 || m.skipped > 0 || m.queries > 0 {
            let _ = self.out.try_send(DnsOut::Minute(m));
        }
    }

    fn publish(&mut self) {
        self.per_sec.push(self.started.elapsed().as_millis() as i64, self.report.probes);
        let r = &mut self.report;
        r.probes_per_sec = self.per_sec.rate();
        r.queued = self.fresh.len() as u64;
        r.waiting = self.queue.len() + self.due.len() as u64;
        r.in_flight = self.in_flight as u64;
        r.retry_late = quantiles(&self.late, 1.0);
        r.names = self.groups[0].report();
        r.wildcards = self.groups[1].report();
        r.bases = self.groups[2].report();
        r.resolver.latency = quantiles(&self.latency, 1000.0);
        r.tracked_names = self.last.len() as u64;
        r.tracked_bytes = self.last.bytes_used();
        let s = &r.resolver;
        let now = Recent {
            secs: 0.0,
            queries: s.queries,
            answers: s.answers,
            nxdomain: s.nxdomain,
            timeouts: s.timeouts,
            errors: s.errors,
            servfail: s.servfail,
            refused: s.refused,
            unreachable: s.unreachable,
            skipped: r.skipped_busy + r.skipped_stale + self.stats.jobs_dropped.load(Ordering::Relaxed),
        };
        let at = Instant::now();
        while self.history.front().is_some_and(|(t, _)| at.duration_since(*t) > RECENT) {
            self.history.pop_front();
        }
        r.recent = match self.history.front() {
            Some((t, old)) => Recent {
                secs: at.duration_since(*t).as_secs_f64(),
                queries: now.queries - old.queries,
                answers: now.answers - old.answers,
                nxdomain: now.nxdomain - old.nxdomain,
                timeouts: now.timeouts - old.timeouts,
                errors: now.errors - old.errors,
                servfail: now.servfail - old.servfail,
                refused: now.refused - old.refused,
                unreachable: now.unreachable - old.unreachable,
                skipped: now.skipped - old.skipped,
            },
            None => Recent::default(),
        };
        self.history.push_back((at, now));
        *self.stats.report.lock().unwrap() = r.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampling_is_stable_and_near_the_rate() {
        let names: Vec<String> = (0..20_000).map(|i| format!("h{i}.example.com")).collect();
        let n = names.iter().filter(|n| sampled(n, 25.0)).count();
        assert!((4_500..5_500).contains(&n), "{n}");
        assert!(names.iter().all(|n| sampled(n, 100.0)));
        // A lower rate keeps a subset, so lowering it never breaks a name's history.
        assert!(names.iter().filter(|n| sampled(n, 10.0)).all(|n| sampled(n, 25.0)));
    }

    #[test]
    fn schedule_runs_thirty_days() {
        let s = default_schedule();
        assert_eq!(s[0], Duration::ZERO);
        assert!(s.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(*s.last().unwrap(), Duration::from_secs(30 * 86400));
    }
}
