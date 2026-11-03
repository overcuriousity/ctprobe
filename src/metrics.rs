//! Live counters shared between the pipeline and the web server.

use crate::coverage::{CoverageReport, Step};
use crate::fetch::LogStats;
use crate::history::History;
use crate::loghealth::{
    behind_of, classify, verdict, HealthInput, LogState, Verdict, VerdictInput, WindowSummary,
};
use crate::registry::LogInfo;
use crate::types::{CertRow, LogId};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

#[derive(Debug, Clone, Serialize)]
pub struct FeedItem {
    pub seen_at_ms: i64,
    pub cn: Option<String>,
    pub primary_domain: Option<String>,
    pub issuer_cn: String,
    pub renewal: &'static str,
    pub log: LogId,
    pub index: u64,
}

impl FeedItem {
    pub fn from_row(r: &CertRow) -> FeedItem {
        FeedItem {
            seen_at_ms: r.seen_at_ms,
            cn: r.parsed.subject_cn.clone(),
            primary_domain: r.primary_domain.clone(),
            issuer_cn: r.parsed.issuer_cn.clone(),
            renewal: r.renewal.as_str(),
            log: r.log,
            index: r.index,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LogSnap {
    pub id: LogId,
    pub name: String,
    pub state: String,
    pub kind: &'static str,
    pub position: u64,
    pub tree_size: u64,
    /// `None` while the tree size has never been read.
    pub behind: Option<u64>,
    pub entries: u64,
    pub per_sec: f64,
    pub bytes: u64,
    pub errors: u64,
    pub malformed: u64,
    pub http_429: u64,
    pub sct_lag_p50_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LiveSnapshot {
    pub ts_ms: i64,
    pub started_at_ms: i64,
    /// `None` until a log has told us its tree size.
    pub behind_total: Option<u64>,
    pub log_count: u64,
    pub raw_total: u64,
    pub unique_total: u64,
    pub names_total: u64,
    pub new_names_total: u64,
    pub new_domains_total: u64,
    pub renew_exact_total: u64,
    pub renew_name_total: u64,
    pub renew_new_total: u64,
    pub raw_per_sec: f64,
    pub unique_per_sec: f64,
    pub names_per_sec: f64,
    pub new_names_per_sec: f64,
    pub new_domains_per_sec: f64,
    pub tracker_names: u64,
    pub tracker_bytes: u64,
    pub rss_bytes: u64,
    pub disk_bytes: u64,
    pub paused_reason: Option<String>,
    pub logs: Vec<LogSnap>,
}

#[derive(Default)]
pub struct Rates {
    pub raw: f64,
    pub unique: f64,
    pub names: f64,
    pub new_names: f64,
    pub new_domains: f64,
    pub per_log: HashMap<LogId, f64>,
    pub lag_p50: HashMap<LogId, u64>,
}

#[derive(Default)]
pub struct LiveState {
    pub started_at_ms: AtomicI64,
    pub raw: AtomicU64,
    pub unique: AtomicU64,
    pub names: AtomicU64,
    pub new_names: AtomicU64,
    pub new_domains: AtomicU64,
    pub renew_exact: AtomicU64,
    pub renew_name: AtomicU64,
    pub renew_new: AtomicU64,
    /// First DNS probes of certificate names, and those that found an address.
    pub dns_probed: AtomicU64,
    pub dns_resolved: AtomicU64,
    pub tracker_names: AtomicU64,
    pub tracker_bytes: AtomicU64,
    pub rss_bytes: AtomicU64,
    pub disk_bytes: AtomicU64,
    pub rates: RwLock<Rates>,
    pub paused: RwLock<Option<String>>,
    pub logs: RwLock<Vec<(LogInfo, Arc<LogStats>)>>,
    pub history: Mutex<History>,
    /// Each log's last 15 minutes, refreshed every 10 seconds.
    pub health: RwLock<HashMap<LogId, WindowSummary>>,
    pub load: RwLock<PipelineLoad>,
    pub coverage_target: RwLock<f64>,
    pub coverage: RwLock<Option<Arc<CoverageReport>>>,
}

/// How hard the pipeline works, averaged over the health window.
#[derive(Debug, Clone, Copy, Default)]
pub struct PipelineLoad {
    pub busy_pct: f64,
    pub queue_full_pct: f64,
    /// Percent of the window with the pipeline or its queue over 80%.
    pub strained_pct: f64,
}

impl LiveState {
    pub fn snapshot(&self) -> LiveSnapshot {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let rates = self.rates.read().unwrap();
        let logs = self
            .logs
            .read()
            .unwrap()
            .iter()
            .map(|(l, s)| {
                let position = g(&s.position);
                let tree_size = g(&s.tree_size);
                LogSnap {
                    id: l.id,
                    name: l.name.clone(),
                    state: l.state.clone(),
                    kind: kind_name(l),
                    position,
                    tree_size,
                    behind: behind_of(position, tree_size, s.tree_changed_ms.load(Ordering::Relaxed)),
                    entries: g(&s.entries),
                    per_sec: rates.per_log.get(&l.id).copied().unwrap_or(0.0),
                    bytes: g(&s.bytes),
                    errors: g(&s.errors),
                    malformed: g(&s.malformed),
                    http_429: g(&s.http_429),
                    sct_lag_p50_ms: rates.lag_p50.get(&l.id).copied().unwrap_or(0),
                }
            })
            .collect::<Vec<LogSnap>>();
        LiveSnapshot {
            ts_ms: chrono::Utc::now().timestamp_millis(),
            started_at_ms: self.started_at_ms.load(Ordering::Relaxed),
            behind_total: logs.iter().flat_map(|l| l.behind).reduce(|a, b| a + b),
            log_count: logs.len() as u64,
            raw_total: g(&self.raw),
            unique_total: g(&self.unique),
            names_total: g(&self.names),
            new_names_total: g(&self.new_names),
            new_domains_total: g(&self.new_domains),
            renew_exact_total: g(&self.renew_exact),
            renew_name_total: g(&self.renew_name),
            renew_new_total: g(&self.renew_new),
            raw_per_sec: rates.raw,
            unique_per_sec: rates.unique,
            names_per_sec: rates.names,
            new_names_per_sec: rates.new_names,
            new_domains_per_sec: rates.new_domains,
            tracker_names: g(&self.tracker_names),
            tracker_bytes: g(&self.tracker_bytes),
            rss_bytes: g(&self.rss_bytes),
            disk_bytes: g(&self.disk_bytes),
            paused_reason: self.paused.read().unwrap().clone(),
            logs,
        }
    }
}

/// One row of the log table.
#[derive(Debug, Clone, Serialize)]
pub struct LogRow {
    pub id: LogId,
    pub name: String,
    pub operator: String,
    pub kind: &'static str,
    pub state: LogState,
    pub list_state: String,
    pub source: String,
    pub fetched_per_sec: f64,
    pub published_per_sec: f64,
    pub behind: Option<u64>,
    pub behind_change: i64,
    pub delay_p50_ms: Option<u64>,
    pub problems: u64,
    pub http_failures: u64,
    pub rate_limited: u64,
    pub undecodable: u64,
    pub last_error: Option<String>,
    pub last_error_ms: Option<i64>,
    pub window_fetched_per_sec: f64,
    pub eta_secs: Option<u64>,
    pub share_pct: Option<f64>,
    pub alone_pct: Option<f64>,
    /// Position in the best order of logs, from 1.
    pub rank: Option<u32>,
    /// A log we cannot read fully cannot show all it would contribute.
    pub undercounted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageOut {
    pub computed_ms: i64,
    pub sampled_certs: u64,
    pub order: Vec<Step>,
    pub operators: Vec<Step>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogsReport {
    pub now_ms: i64,
    pub logs: Vec<LogRow>,
    pub verdict: Verdict,
    pub coverage_target: f64,
    pub coverage: Option<CoverageOut>,
}

impl LiveState {
    /// The log table and the verdict on the whole fleet.
    pub fn logs_report(&self) -> LogsReport {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let g_i = |a: &AtomicI64| a.load(Ordering::Relaxed);
        let now_ms = chrono::Utc::now().timestamp_millis();
        let started_ms = g_i(&self.started_at_ms);
        let paused = self.paused.read().unwrap().is_some();
        let rates = self.rates.read().unwrap();
        let health = self.health.read().unwrap();
        let load = *self.load.read().unwrap();
        let cov = self.coverage.read().unwrap().clone();
        let cov_of = |id: LogId| cov.as_ref().and_then(|c| c.logs.iter().find(|l| l.id == id));
        let rank_of = |id: LogId| {
            let key = id.to_string();
            cov.as_ref().and_then(|c| c.order.iter().position(|s| s.key == key)).map(|i| i as u32 + 1)
        };
        let mut rows = Vec::new();
        let mut input = VerdictInput {
            pipeline_busy_pct: load.busy_pct,
            queue_full_pct: load.queue_full_pct,
            strained_pct: load.strained_pct,
            ..VerdictInput::default()
        };
        for (l, s) in self.logs.read().unwrap().iter().filter(|(l, _)| l.state != "retired") {
            let window = health.get(&l.id).copied().unwrap_or_default();
            let tree_changed_ms = g_i(&s.tree_changed_ms);
            let behind = behind_of(g(&s.position), g(&s.tree_size), tree_changed_ms);
            let state = classify(&HealthInput {
                now_ms,
                started_ms,
                paused,
                behind,
                last_contact_ms: g_i(&s.last_contact_ms),
                tree_changed_ms,
                data_fail_since_ms: g_i(&s.data_fail_since_ms),
                window,
            });
            let gain = window.fetched_per_sec - window.published_per_sec;
            input.seconds = input.seconds.max(window.seconds);
            input.published_per_sec += window.published_per_sec;
            input.fetched_per_sec += window.fetched_per_sec;
            input.backlog += behind.unwrap_or(0);
            input.backlog_change += window.behind_change;
            if state == LogState::RateLimited {
                input.limited_backlog += behind.unwrap_or(0);
            }
            input.logs.push((l.name.clone(), state, -gain));
            let last_error = s.last_error.lock().unwrap().clone();
            rows.push(LogRow {
                id: l.id,
                name: l.name.clone(),
                operator: l.operator.clone(),
                kind: kind_name(l),
                state,
                list_state: l.state.clone(),
                source: l.source.clone(),
                fetched_per_sec: rates.per_log.get(&l.id).copied().unwrap_or(0.0),
                published_per_sec: window.published_per_sec,
                behind,
                behind_change: window.behind_change,
                delay_p50_ms: rates.lag_p50.get(&l.id).copied(),
                problems: window.http_429 + window.errors + window.malformed,
                http_failures: window.errors,
                rate_limited: window.http_429,
                undecodable: window.malformed,
                last_error_ms: last_error.as_ref().map(|e| e.0),
                last_error: last_error.map(|e| e.1),
                window_fetched_per_sec: window.fetched_per_sec,
                eta_secs: (state == LogState::CatchingUp && gain > 0.0)
                    .then(|| (behind.unwrap_or(0) as f64 / gain) as u64),
                share_pct: cov_of(l.id).map(|c| c.share_pct),
                alone_pct: cov_of(l.id).map(|c| c.alone_pct),
                rank: rank_of(l.id),
                undercounted: matches!(state, LogState::Failing | LogState::RateLimited | LogState::FallingBehind),
            });
        }
        LogsReport {
            now_ms,
            logs: rows,
            verdict: verdict(&input),
            coverage_target: *self.coverage_target.read().unwrap(),
            coverage: cov.as_ref().filter(|c| c.sampled_certs > 0).map(|c| CoverageOut {
                computed_ms: c.computed_ms,
                sampled_certs: c.sampled_certs,
                order: c.order.clone(),
                operators: c.operators.clone(),
            }),
        }
    }
}

fn kind_name(l: &LogInfo) -> &'static str {
    match l.kind {
        crate::registry::LogKind::Rfc6962 { .. } => "rfc6962",
        crate::registry::LogKind::Tiled { .. } => "tiled",
    }
}

/// Process CPU time in milliseconds and resident bytes, from `/proc`.
pub fn proc_stats() -> (u64, u64) {
    let clk = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    // Fields after the parenthesised name: utime and stime are 12th and 13th.
    let rest = stat.rsplit(')').next().unwrap_or("");
    let f: Vec<&str> = rest.split_whitespace().collect();
    let tick = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let cpu_ms = (tick(11) + tick(12)) * 1000 / clk;
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let rss = statm.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    (cpu_ms, rss * page)
}

pub fn dir_size(dir: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            match e.metadata() {
                Ok(m) if m.is_dir() => stack.push(e.path()),
                Ok(m) => total += m.len(),
                Err(_) => {}
            }
        }
    }
    total
}
