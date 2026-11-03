//! Fetchers feed one ordered processing thread, which parses each batch on the
//! rayon pool and then owns the tracker, the writer and the commit protocol.
//!
//! A commit is: write pending Parquet, append the tracker WAL frame, record
//! positions and epoch atomically, publish. Startup discards anything newer
//! than the recorded epoch, so a crash at any step counts nothing twice.

use crate::config::Config;
use crate::coverage;
use crate::dns::outcome::Status;
use crate::dns::queue::Kind;
use crate::dns::{self, DnsLink, DnsOpts, DnsOut, DnsStats};
use crate::fetch::{spawn_fetcher, Batch, FetchOpts, LogStats};
use crate::history::{Counts, History};
use crate::loghealth::{LogSample, LogWindow};
use crate::metrics::{dir_size, proc_stats, FeedItem, LiveState, PipelineLoad};
use crate::nightly;
use crate::parse::extract;
use crate::positions::{open_db, Positions};
use crate::rates::RateWindow;
use crate::registry::{load_specs, LogInfo, LogSpec, Registry};
use crate::store::{RollupMinuteRow, Writer, MINUTE_GLOBAL_LOG};
use crate::tracker::{EntryMeta, Tracker};
use crate::types::{LogId, RenewalClass};
use anyhow::{anyhow, Result};
use hdrhistogram::Histogram;
use rayon::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;

const CHANNEL_BATCHES: usize = 128;
const FEED_PER_SEC: u32 = 200;
const REFRESH_LOGS: Duration = Duration::from_secs(3600);
const MS_PER_DAY: i64 = 86_400_000;
const WATCHDOG_PING: Duration = Duration::from_secs(15);
/// A log counts as rate-limiting us for this long after a 429.
const LIMITED_FOR: Duration = Duration::from_secs(3600);
/// Span of every displayed rate.
const RATE_SECS: u32 = 60;
const HISTORY_FILE: &str = "rate_history.json";
const COVERAGE_FILE: &str = "coverage.json";
/// A fresh install shows coverage this soon, ahead of the regular interval.
const COVERAGE_FIRST: Duration = Duration::from_secs(300);
const COVERAGE_WINDOW_MS: i64 = MS_PER_DAY;
/// How often each log's health window takes a sample.
const SAMPLE_MS: i64 = 10_000;
/// Samples in the 15-minute health window.
const LOAD_SAMPLES: usize = 90;
const STRAINED_PCT: f64 = 80.0;

#[derive(Clone)]
pub struct PipelineOpts {
    /// Fixed log selection; `None` downloads and refreshes the log list.
    pub logs: Option<Vec<LogSpec>>,
    pub commit_interval: Duration,
    /// Unknown logs start at entry 0, not the head. For tests.
    pub start_at_zero: bool,
    pub fetch: FetchOpts,
    /// Interval of rollup rows and disk checks.
    pub minute: Duration,
    /// Runs the nightly job at 00:30 UTC. Off in tests that drive it directly.
    pub nightly: bool,
    /// Interval of full tracker snapshots.
    pub snapshot_every: Duration,
    /// Interval of the coverage assessment.
    pub coverage_every: Duration,
    pub dns: DnsOpts,
}

impl Default for PipelineOpts {
    fn default() -> Self {
        PipelineOpts {
            logs: None,
            commit_interval: Duration::from_secs(300),
            start_at_zero: false,
            fetch: FetchOpts::default(),
            minute: Duration::from_secs(60),
            nightly: true,
            snapshot_every: Duration::from_secs(86400),
            coverage_every: Duration::from_secs(900),
            dns: DnsOpts::default(),
        }
    }
}

#[derive(Clone)]
pub struct PipelineHandle {
    pub live: Arc<LiveState>,
    pub feed: broadcast::Sender<Arc<FeedItem>>,
    pub registry: Arc<Registry>,
    /// Present while DNS probing is configured.
    pub dns: Option<Arc<DnsStats>>,
}

const RUN: u8 = 0;
const KILL: u8 = 1;
const KILL_MID_COMMIT: u8 = 2;

pub struct Pipeline {
    pub handle: PipelineHandle,
    stop: watch::Sender<bool>,
    mode: Arc<AtomicU8>,
    thread: Option<std::thread::JoinHandle<Result<()>>>,
    coverage_thread: Option<std::thread::JoinHandle<()>>,
    dns_thread: Option<std::thread::JoinHandle<()>>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

struct Fleet {
    client: reqwest::Client,
    tx: mpsc::Sender<Batch>,
    stop: watch::Receiver<bool>,
    fetch: FetchOpts,
    live: Arc<LiveState>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    running: Mutex<HashMap<LogId, JoinHandle<()>>>,
    start_at_zero: bool,
}

impl Fleet {
    /// Registers a log's stats and starts its fetcher, once.
    fn launch(&self, log: &LogInfo, start: Option<u64>) {
        let stats = Arc::new(LogStats::default());
        self.live.logs.write().unwrap().push((log.clone(), stats.clone()));
        let start = start.or(self.start_at_zero.then_some(0));
        let h = spawn_fetcher(
            log,
            self.client.clone(),
            start,
            self.tx.clone(),
            stats,
            self.fetch.clone(),
            self.stop.clone(),
        );
        self.running.lock().unwrap().insert(log.id, h);
    }

    /// Reconciles running fetchers with the registry after a refresh.
    fn reconcile(&self, reg: &Registry) {
        let logs = reg.logs();
        let mut live = self.live.logs.write().unwrap();
        for (l, _) in live.iter_mut() {
            if let Some(n) = logs.iter().find(|x| x.id == l.id) {
                l.state = n.state.clone();
            }
        }
        drop(live);
        for l in logs.iter().filter(|l| l.state == "retired") {
            if let Some(h) = self.running.lock().unwrap().remove(&l.id) {
                h.abort();
            }
        }
    }
}

/// Assesses coverage on its own thread, so it never touches ingest.
fn coverage_loop(live: Arc<LiveState>, data: PathBuf, every: Duration, stop: watch::Receiver<bool>) {
    let path = data.join(COVERAGE_FILE);
    if let Some(r) = coverage::load(&path) {
        *live.coverage.write().unwrap() = Some(Arc::new(r));
    }
    let stopped = || *stop.borrow();
    let mut wait = every.min(COVERAGE_FIRST);
    loop {
        let until = Instant::now() + wait;
        while Instant::now() < until {
            if stopped() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50).min(wait));
        }
        wait = every;
        let logs: Vec<_> = live
            .logs
            .read()
            .unwrap()
            .iter()
            .map(|(l, _)| (l.id, l.operator.clone(), l.state != "test" && l.state != "retired"))
            .collect();
        let since = chrono::Utc::now().timestamp_millis() - COVERAGE_WINDOW_MS;
        match coverage::assess(&data, since, &logs, stopped) {
            Ok(r) => {
                if let Err(e) = coverage::save(&r, &path) {
                    tracing::warn!("saving coverage: {e:#}");
                }
                *live.coverage.write().unwrap() = Some(Arc::new(r));
            }
            Err(_) if stopped() => return,
            Err(e) => tracing::warn!("coverage assessment failed: {e:#}"),
        }
    }
}

impl Pipeline {
    pub async fn start(cfg: Config, opts: PipelineOpts) -> Result<Pipeline> {
        std::fs::create_dir_all(&cfg.data_dir)?;
        let db = open_db(&cfg.data_dir.join("state.redb"))?;
        let positions = Positions::new(db.clone());
        let epoch = positions.epoch()?;
        let registry = Arc::new(Registry::open(db)?);
        nightly::cleanup(&cfg.data_dir)?;
        let _ = std::fs::remove_dir_all(cfg.data_dir.join("tmp"));
        let writer = Writer::open(&cfg.data_dir, epoch)?;
        let tracker = Tracker::open(&cfg.data_dir.join("tracker"), cfg.tracker_max_bytes, epoch)?;

        let client = crate::http::client_builder()
            .user_agent(concat!("ctprobe/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(8)
            .build()?;

        let (specs, failed) = match &opts.logs {
            Some(l) => (l.clone(), Vec::new()),
            None => load_specs(&client, &cfg, chrono::Utc::now()).await?,
        };
        registry.ingest_keeping(specs, &failed)?;

        let live = Arc::new(LiveState::default());
        live.started_at_ms.store(chrono::Utc::now().timestamp_millis(), Ordering::Relaxed);
        *live.coverage_target.write().unwrap() = cfg.coverage_target;
        *live.history.lock().unwrap() =
            History::load(&cfg.data_dir.join(HISTORY_FILE), chrono::Utc::now().timestamp());
        let (feed, _) = broadcast::channel(1024);
        let (tx, rx) = mpsc::channel::<Batch>(CHANNEL_BATCHES);
        let (stop, stop_rx) = watch::channel(false);
        let tasks = Arc::new(Mutex::new(Vec::new()));
        let (dns_link, dns_thread) = if cfg.dns.enabled() {
            let (l, t) = dns::start(cfg.dns.clone(), opts.dns.clone(), &cfg.data_dir, stop.subscribe())?;
            tracing::info!("probing names via the DNS resolver at {}", cfg.dns.resolver.map(|r| r.to_string()).unwrap_or_default());
            (Some(l), Some(t))
        } else {
            (None, None)
        };
        let dns_stats = dns_link.as_ref().map(|l| l.stats.clone());
        let fleet = Arc::new(Fleet {
            client: client.clone(),
            tx,
            stop: stop_rx,
            fetch: opts.fetch.clone(),
            live: live.clone(),
            tasks: tasks.clone(),
            running: Mutex::new(HashMap::new()),
            start_at_zero: opts.start_at_zero,
        });

        for l in registry.logs().iter().filter(|l| l.state != "retired") {
            fleet.launch(l, positions.get(l.id)?);
        }

        if opts.logs.is_none() {
            let (f, reg, cfg2) = (fleet.clone(), registry.clone(), cfg.clone());
            let t = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(REFRESH_LOGS).await;
                    match reg.refresh(&f.client, &cfg2).await {
                        Ok(added) => {
                            for l in added {
                                f.launch(&l, None);
                            }
                            f.reconcile(&reg);
                        }
                        Err(e) => tracing::warn!("log list refresh failed: {e:#}"),
                    }
                }
            });
            fleet.tasks.lock().unwrap().push(t);
        }

        if opts.nightly {
            let cfg2 = cfg.clone();
            let t = tokio::spawn(async move {
                loop {
                    let today = chrono::Utc::now().date_naive();
                    for day in nightly::pending_days(&cfg2.data_dir, today) {
                        tracing::info!("nightly job for {day}");
                        if let Err(e) = nightly::run_nightly(&cfg2, day).await {
                            tracing::error!("nightly job for {day} failed: {e:#}");
                        }
                    }
                    tokio::time::sleep(until_next_nightly(chrono::Utc::now())).await;
                }
            });
            tasks.lock().unwrap().push(t);
        }

        let coverage_thread = {
            let (l, d, every, s) = (live.clone(), cfg.data_dir.clone(), opts.coverage_every, stop.subscribe());
            std::thread::Builder::new()
                .name("ctprobe-coverage".into())
                .spawn(move || coverage_loop(l, d, every, s))?
        };

        let mode = Arc::new(AtomicU8::new(RUN));
        let ctx = Worker {
            rx,
            positions,
            tracker,
            writer,
            live: live.clone(),
            feed: feed.clone(),
            cfg,
            epoch,
            commit_interval: opts.commit_interval,
            minute: opts.minute,
            snapshot_every: opts.snapshot_every,
            stop: stop.subscribe(),
            mode: mode.clone(),
            rt: Handle::current(),
            done: HashMap::new(),
            agg: HashMap::new(),
            global: GlobalAgg::default(),
            started: Instant::now(),
            last_sample_ms: -SAMPLE_MS,
            busy: Duration::ZERO,
            queue_sum: 0.0,
            queue_ticks: 0,
            load: VecDeque::new(),
            dns: dns_link,
            _fleet: fleet,
        };
        let thread = std::thread::Builder::new()
            .name("ctprobe-pipeline".into())
            .spawn(move || ctx.run())?;

        Ok(Pipeline {
            handle: PipelineHandle { live, feed, registry, dns: dns_stats },
            stop,
            mode,
            thread: Some(thread),
            coverage_thread: Some(coverage_thread),
            dns_thread,
            tasks,
        })
    }

    async fn finish(mut self, mode: u8) -> Result<()> {
        self.mode.store(mode, Ordering::SeqCst);
        let _ = self.stop.send(true);
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
        let coverage = self.coverage_thread.take();
        let dns = self.dns_thread.take();
        let thread = self.thread.take().ok_or_else(|| anyhow!("already stopped"))?;
        tokio::task::spawn_blocking(move || {
            for t in [coverage, dns].into_iter().flatten() {
                let _ = t.join();
            }
            thread.join()
        })
        .await?
        .map_err(|_| anyhow!("pipeline thread panicked"))?
    }

    /// Stops cleanly with a final commit.
    pub async fn shutdown(self) -> Result<()> {
        self.finish(RUN).await
    }

    /// Stops as a crash would: everything since the last commit is lost.
    pub async fn kill(self) {
        let _ = self.finish(KILL).await;
    }

    /// As `kill`, but after writing a commit's files and before recording it.
    pub async fn kill_mid_commit(self) {
        let _ = self.finish(KILL_MID_COMMIT).await;
    }

    /// Resolves when the pipeline thread ends, normally only on a fatal error.
    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(|t| t.is_finished())
    }
}

/// Time from `now` until the next 00:30 UTC.
fn until_next_nightly(now: chrono::DateTime<chrono::Utc>) -> Duration {
    let ms = now.timestamp_millis();
    let at = 30 * 60_000;
    let rem = ms.rem_euclid(MS_PER_DAY);
    let wait = if rem < at { at - rem } else { MS_PER_DAY - rem + at };
    Duration::from_millis(wait as u64)
}

/// Counters start at zero with the pipeline, so work before the first tick counts.
fn rate_window() -> RateWindow {
    let mut w = RateWindow::new(RATE_SECS);
    w.push(0, 0);
    w
}

struct LogAgg {
    entries: u64,
    bytes: u64,
    errors: u64,
    malformed: u64,
    http_429: u64,
    busy_ms: u64,
    sec_entries: u64,
    peak: u64,
    per_sec: RateWindow,
    window: LogWindow,
    limited_at: Option<Instant>,
    sct: Histogram<u64>,
    nb: Histogram<u64>,
}

impl Default for LogAgg {
    fn default() -> Self {
        let h = || Histogram::new_with_bounds(1, 1 << 42, 2).expect("valid bounds");
        LogAgg {
            entries: 0,
            bytes: 0,
            errors: 0,
            malformed: 0,
            http_429: 0,
            busy_ms: 0,
            sec_entries: 0,
            peak: 0,
            per_sec: rate_window(),
            window: LogWindow::new(),
            limited_at: None,
            sct: h(),
            nb: h(),
        }
    }
}

struct GlobalAgg {
    unique: u64,
    sec_unique: u64,
    peak: u64,
    cpu_ms: u64,
    raw_rate: RateWindow,
    unique_rate: RateWindow,
    names_rate: RateWindow,
    new_names_rate: RateWindow,
    new_domains_rate: RateWindow,
    /// Counters at the last tick, for the history's deltas.
    seen: [u64; 7],
}

impl Default for GlobalAgg {
    fn default() -> Self {
        let w = rate_window;
        GlobalAgg {
            unique: 0,
            sec_unique: 0,
            peak: 0,
            cpu_ms: 0,
            raw_rate: w(),
            unique_rate: w(),
            names_rate: w(),
            new_names_rate: w(),
            new_domains_rate: w(),
            seen: [0; 7],
        }
    }
}

struct Worker {
    rx: mpsc::Receiver<Batch>,
    positions: Positions,
    tracker: Tracker,
    writer: Writer,
    live: Arc<LiveState>,
    feed: broadcast::Sender<Arc<FeedItem>>,
    cfg: Config,
    epoch: u64,
    commit_interval: Duration,
    minute: Duration,
    snapshot_every: Duration,
    stop: watch::Receiver<bool>,
    mode: Arc<AtomicU8>,
    rt: Handle,
    /// Position per log after everything processed so far.
    done: HashMap<LogId, u64>,
    agg: HashMap<LogId, LogAgg>,
    global: GlobalAgg,
    started: Instant,
    last_sample_ms: i64,
    /// Time spent processing since the last sample.
    busy: Duration,
    queue_sum: f64,
    queue_ticks: u32,
    /// Busy and queue percentages of recent samples.
    load: VecDeque<(f64, f64)>,
    dns: Option<DnsLink>,
    _fleet: Arc<Fleet>,
}

impl Worker {
    fn run(mut self) -> Result<()> {
        let mut last_sec = Instant::now();
        let mut last_min = Instant::now();
        let mut last_commit = Instant::now();
        let mut last_ping = Instant::now();
        let mut last_snapshot = Instant::now();
        let mut feed_budget = FEED_PER_SEC;
        loop {
            if *self.stop.borrow() {
                break;
            }
            let wait = Duration::from_millis(100);
            if self.live.paused.read().unwrap().is_some() {
                // The bounded channel fills and fetchers stop on their own.
                std::thread::sleep(wait);
            } else {
                let rx = &mut self.rx;
                let got = self.rt.block_on(async { tokio::time::timeout(wait, rx.recv()).await });
                match got {
                    Ok(Some(batch)) => {
                        let t = Instant::now();
                        self.process(batch, &mut feed_budget);
                        self.busy += t.elapsed();
                    }
                    Ok(None) => std::thread::sleep(wait),
                    Err(_) => {}
                }
            }
            self.drain_dns();
            if last_ping.elapsed() >= WATCHDOG_PING {
                // From this loop, so a hung pipeline stops pinging and is restarted.
                let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
                last_ping = Instant::now();
            }
            if last_sec.elapsed() >= Duration::from_secs(1) {
                self.tick_second();
                last_sec = Instant::now();
                feed_budget = FEED_PER_SEC;
            }
            if last_min.elapsed() >= self.minute {
                self.emit_minute();
                self.check_disk()?;
                last_min = Instant::now();
            }
            if last_commit.elapsed() >= self.commit_interval {
                self.commit()?;
                last_commit = Instant::now();
                // Not tied to the nightly job: its failure must not grow the WAL.
                if last_snapshot.elapsed() >= self.snapshot_every {
                    let today = (chrono::Utc::now().timestamp_millis() / MS_PER_DAY) as u16;
                    self.tracker.expire_dedup(today);
                    self.tracker.snapshot(self.epoch)?;
                    last_snapshot = Instant::now();
                }
            }
        }
        match self.mode.load(Ordering::SeqCst) {
            KILL => Ok(()),
            KILL_MID_COMMIT => {
                self.epoch += 1;
                self.writer.flush(self.epoch)?;
                self.tracker.commit_wal(self.epoch)
            }
            _ => {
                self.drain_dns();
                self.emit_minute();
                self.commit()
            }
        }
    }

    fn process(&mut self, batch: Batch, feed_budget: &mut u32) {
        let now = chrono::Utc::now().timestamp_millis();
        let today = (now / MS_PER_DAY) as u16;
        let parsed: Vec<_> = batch.entries.par_iter().map(extract).collect();
        let mut bad = 0u64;
        for (e, p) in batch.entries.iter().zip(parsed) {
            let agg = self.agg.entry(e.log).or_default();
            agg.sct.saturating_record((now - e.timestamp_ms as i64).max(1) as u64);
            let Ok(p) = p else {
                bad += 1;
                continue;
            };
            agg.nb.saturating_record((now - p.not_before_ms).max(1) as u64);
            let meta = EntryMeta {
                log: e.log,
                index: e.index,
                is_precert: e.is_precert,
                der_size: e.der_size,
                timestamp_ms: e.timestamp_ms,
                seen_at_ms: now,
            };
            let o = self.tracker.observe(meta, &p, today);
            self.writer.push_sighting(o.sighting);
            self.live.raw.fetch_add(1, Ordering::Relaxed);
            let Some(row) = o.row else { continue };
            let l = &self.live;
            l.unique.fetch_add(1, Ordering::Relaxed);
            l.names.fetch_add(row.parsed.names.len() as u64, Ordering::Relaxed);
            l.new_names.fetch_add(row.new_names as u64, Ordering::Relaxed);
            l.new_domains.fetch_add(row.new_domains as u64, Ordering::Relaxed);
            match row.renewal {
                RenewalClass::Exact => l.renew_exact.fetch_add(1, Ordering::Relaxed),
                RenewalClass::Name => l.renew_name.fetch_add(1, Ordering::Relaxed),
                RenewalClass::New => l.renew_new.fetch_add(1, Ordering::Relaxed),
            };
            self.global.sec_unique += 1;
            if *feed_budget > 0 && self.feed.receiver_count() > 0 {
                *feed_budget -= 1;
                let _ = self.feed.send(Arc::new(FeedItem::from_row(&row)));
            }
            if let Some(d) = &self.dns {
                d.submit(&row);
            }
            self.writer.push_cert(row);
        }
        if bad > 0 {
            if let Some((_, st)) =
                self.live.logs.read().unwrap().iter().find(|(l, _)| l.id == batch.log)
            {
                st.malformed.fetch_add(bad, Ordering::Relaxed);
            }
        }
        self.done.insert(batch.log, batch.next);
    }

    /// Moves finished probes into the writer, so they commit with the rest.
    fn drain_dns(&mut self) {
        let Some(d) = &self.dns else { return };
        while let Ok(o) = d.out.try_recv() {
            match o {
                DnsOut::Row(r) => {
                    if r.kind == Kind::Name && r.attempt == 0 {
                        self.live.dns_probed.fetch_add(1, Ordering::Relaxed);
                        if r.lookup.status == Status::Resolved {
                            self.live.dns_resolved.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    self.writer.push_dns(r)
                }
                DnsOut::Minute(m) => self.writer.push_dns_minute(m),
            }
        }
    }

    fn tick_second(&mut self) {
        let now_ms = self.started.elapsed().as_millis() as i64;
        let g = |a: &std::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
        let mut rates = crate::metrics::Rates::default();
        let live = &self.live;
        let global = &mut self.global;
        global.raw_rate.push(now_ms, g(&live.raw));
        global.unique_rate.push(now_ms, g(&live.unique));
        global.names_rate.push(now_ms, g(&live.names));
        global.new_names_rate.push(now_ms, g(&live.new_names));
        global.new_domains_rate.push(now_ms, g(&live.new_domains));
        rates.raw = global.raw_rate.rate();
        rates.unique = global.unique_rate.rate();
        rates.names = global.names_rate.rate();
        rates.new_names = global.new_names_rate.rate();
        rates.new_domains = global.new_domains_rate.rate();
        let now = [
            g(&live.raw),
            g(&live.unique),
            g(&live.names),
            g(&live.new_names),
            g(&live.new_domains),
            g(&live.dns_probed),
            g(&live.dns_resolved),
        ];
        let [raw, unique, names, new_names, new_domains, dns_probed, dns_resolved] =
            std::array::from_fn(|i| (now[i] - global.seen[i]) as u32);
        global.seen = now;
        let counts = Counts { raw, unique, names, new_names, new_domains, dns_probed, dns_resolved };
        live.history.lock().unwrap().add(chrono::Utc::now().timestamp(), counts);
        self.global.peak = self.global.peak.max(self.global.sec_unique);
        self.global.unique += self.global.sec_unique;
        self.global.sec_unique = 0;
        let sample = now_ms - self.last_sample_ms >= SAMPLE_MS;
        let mut health = HashMap::new();
        for (l, s) in self.live.logs.read().unwrap().iter() {
            let a = self.agg.entry(l.id).or_default();
            let e = s.entries.load(Ordering::Relaxed);
            let delta = e - a.sec_entries;
            a.sec_entries = e;
            a.peak = a.peak.max(delta);
            a.per_sec.push(now_ms, e);
            rates.per_log.insert(l.id, a.per_sec.rate());
            if sample {
                a.window.push(LogSample {
                    t_ms: now_ms,
                    position: s.position.load(Ordering::Relaxed),
                    tree_size: s.tree_size.load(Ordering::Relaxed),
                    fetched: e,
                    http_429: s.http_429.load(Ordering::Relaxed),
                    errors: s.errors.load(Ordering::Relaxed),
                    malformed: s.malformed.load(Ordering::Relaxed),
                });
                health.insert(l.id, a.window.summary());
            }
            if !a.sct.is_empty() {
                rates.lag_p50.insert(l.id, a.sct.value_at_quantile(0.5));
            }
        }
        let room = self._fleet.tx.capacity() as f64 / CHANNEL_BATCHES as f64;
        self.queue_sum += 100.0 * (1.0 - room);
        self.queue_ticks += 1;
        if sample {
            let span = (now_ms - self.last_sample_ms).max(1) as f64;
            let busy_pct = (100.0 * self.busy.as_millis() as f64 / span).min(100.0);
            let queue_pct = self.queue_sum / self.queue_ticks.max(1) as f64;
            self.busy = Duration::ZERO;
            self.queue_sum = 0.0;
            self.queue_ticks = 0;
            self.load.push_back((busy_pct, queue_pct));
            while self.load.len() > LOAD_SAMPLES {
                self.load.pop_front();
            }
            let n = self.load.len() as f64;
            *self.live.load.write().unwrap() = PipelineLoad {
                busy_pct: self.load.iter().map(|l| l.0).sum::<f64>() / n,
                queue_full_pct: self.load.iter().map(|l| l.1).sum::<f64>() / n,
                strained_pct: 100.0 * self.load.iter().filter(|l| l.0.max(l.1) > STRAINED_PCT).count() as f64 / n,
            };
            self.last_sample_ms = now_ms;
            *self.live.health.write().unwrap() = health;
        }
        *self.live.rates.write().unwrap() = rates;
        self.live.tracker_names.store(self.tracker.name_count(), Ordering::Relaxed);
        self.live.tracker_bytes.store(self.tracker.bytes_used(), Ordering::Relaxed);
        self.live.rss_bytes.store(proc_stats().1, Ordering::Relaxed);
    }

    fn emit_minute(&mut self) {
        self.tick_second();
        let now = chrono::Utc::now().timestamp_millis();
        let minute_ms = now - now % 60_000;
        let logs: Vec<(LogId, Arc<LogStats>)> =
            self.live.logs.read().unwrap().iter().map(|(l, s)| (l.id, s.clone())).collect();
        let (mut raw, mut backlog, mut limited, mut healthy) = (0i64, 0i64, 0i64, 0i64);
        for (id, s) in logs {
            let a = self.agg.entry(id).or_default();
            let behind = s
                .tree_size
                .load(Ordering::Relaxed)
                .saturating_sub(s.position.load(Ordering::Relaxed)) as i64;
            if s.http_429.load(Ordering::Relaxed) > a.http_429 {
                a.limited_at = Some(Instant::now());
            }
            if a.limited_at.is_some_and(|t| t.elapsed() < LIMITED_FOR) {
                limited += behind;
            } else {
                backlog += behind;
            }
            if s.errors.load(Ordering::Relaxed) == a.errors {
                healthy += 1;
            }
            let take = |prev: &mut u64, cur: &std::sync::atomic::AtomicU64| {
                let c = cur.load(Ordering::Relaxed);
                let d = c - *prev;
                *prev = c;
                d as i64
            };
            let q = |h: &Histogram<u64>, v: f64| {
                (!h.is_empty()).then(|| h.value_at_quantile(v) as i64)
            };
            let row = RollupMinuteRow {
                minute_ms,
                log: id,
                entries: take(&mut a.entries, &s.entries),
                bytes: take(&mut a.bytes, &s.bytes),
                errors: take(&mut a.errors, &s.errors),
                malformed: take(&mut a.malformed, &s.malformed),
                http_429: take(&mut a.http_429, &s.http_429),
                busy_ms: take(&mut a.busy_ms, &s.busy_ms),
                peak_per_sec: a.peak as i64,
                sct_lag_p50_ms: q(&a.sct, 0.5),
                sct_lag_p99_ms: q(&a.sct, 0.99),
                nb_lag_p50_ms: q(&a.nb, 0.5),
                nb_lag_p99_ms: q(&a.nb, 0.99),
                backlog: Some(behind),
                ..Default::default()
            };
            raw += row.entries;
            a.peak = 0;
            a.sct.reset();
            a.nb.reset();
            self.writer.push_rollup(row);
        }
        let (cpu, rss) = proc_stats();
        let disk = dir_size(&self.cfg.data_dir);
        self.live.disk_bytes.store(disk, Ordering::Relaxed);
        let row = RollupMinuteRow {
            minute_ms,
            log: MINUTE_GLOBAL_LOG,
            entries: self.global.unique as i64,
            peak_per_sec: self.global.peak as i64,
            tracker_names: Some(self.tracker.name_count() as i64),
            tracker_bytes: Some(self.tracker.bytes_used() as i64),
            rss_bytes: Some(rss as i64),
            cpu_ms: Some((cpu - self.global.cpu_ms) as i64),
            disk_bytes: Some(disk as i64),
            raw_entries: Some(raw),
            backlog: Some(backlog),
            limited_backlog: Some(limited),
            healthy_logs: Some(healthy),
            ..Default::default()
        };
        let snap = self.live.snapshot();
        let behind = snap.behind_total.unwrap_or(0);
        let errors: u64 = snap.logs.iter().map(|l| l.errors + l.http_429).sum();
        tracing::info!(
            unique_min = self.global.unique,
            peak_per_sec = self.global.peak,
            raw_total = snap.raw_total,
            unique_total = snap.unique_total,
            behind,
            errors,
            rss_mib = rss >> 20,
            disk_mib = disk >> 20,
            "minute"
        );
        self.global.cpu_ms = cpu;
        self.global.unique = 0;
        self.global.peak = 0;
        self.writer.push_rollup(row);
    }

    /// Enforces the disk budget; pauses ingest while it cannot be met.
    fn check_disk(&mut self) -> Result<()> {
        let size = self.live.disk_bytes.load(Ordering::Relaxed);
        let budget = self.cfg.disk_budget_bytes;
        let reason = if size > budget {
            let today = chrono::Utc::now().date_naive();
            nightly::expire::enforce(&self.cfg.data_dir, budget, today)?
        } else {
            None
        };
        if let Some(r) = &reason {
            tracing::warn!("ingest paused: {r}");
        }
        *self.live.paused.write().unwrap() = reason;
        Ok(())
    }

    /// Positions to record: what was processed, or the fetcher's head start
    /// for a log that has delivered nothing yet.
    fn commit_positions(&self) -> Vec<(LogId, u64)> {
        let mut out: Vec<(LogId, u64)> = self.done.iter().map(|(k, v)| (*k, *v)).collect();
        for (l, s) in self.live.logs.read().unwrap().iter() {
            if !self.done.contains_key(&l.id) {
                let head = s.head_start.load(Ordering::Relaxed);
                if head > 0 {
                    out.push((l.id, head));
                }
            }
        }
        out
    }

    fn save_history(&self) {
        let history = self.live.history.lock().unwrap().clone();
        if let Err(e) = history.save(&self.cfg.data_dir.join(HISTORY_FILE)) {
            tracing::warn!("saving rate history: {e:#}");
        }
    }

    fn commit(&mut self) -> Result<()> {
        let epoch = self.epoch + 1;
        self.writer.flush(epoch)?;
        self.tracker.commit_wal(epoch)?;
        self.positions.commit_epoch(&self.commit_positions(), epoch)?;
        self.writer.publish(epoch)?;
        self.epoch = epoch;
        self.save_history();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn nightly_waits_for_next_0030() {
        let at = |h, m| chrono::Utc.with_ymd_and_hms(2026, 1, 1, h, m, 0).unwrap();
        assert_eq!(until_next_nightly(at(0, 0)), Duration::from_secs(1800));
        assert_eq!(until_next_nightly(at(0, 30)), Duration::from_secs(86400));
        assert_eq!(until_next_nightly(at(23, 30)), Duration::from_secs(3600));
    }
}
