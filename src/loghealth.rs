//! How well each log is doing, judged over 15 minutes because logs publish and
//! we fetch in bursts.

use serde::Serialize;
use std::collections::VecDeque;

const WINDOW_MS: i64 = 15 * 60_000;
const FAILING_AFTER_MS: i64 = 5 * 60_000;
const MEASURING_MS: i64 = 5 * 60_000;
const NOT_ADVANCING_MS: i64 = 30 * 60_000;
/// Behind by less than this is normal between polls, however quiet the log.
const MIN_BEHIND: f64 = 1000.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogState {
    Paused,
    Measuring,
    Failing,
    RateLimited,
    FallingBehind,
    CatchingUp,
    NotAdvancing,
    Healthy,
}

/// Cumulative counters of one log at one moment.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogSample {
    pub t_ms: i64,
    pub position: u64,
    pub tree_size: u64,
    pub fetched: u64,
    pub http_429: u64,
    pub errors: u64,
    pub malformed: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct WindowSummary {
    pub seconds: f64,
    pub fetched_per_sec: f64,
    pub published_per_sec: f64,
    pub behind_change: i64,
    pub http_429: u64,
    pub errors: u64,
    pub malformed: u64,
}

#[derive(Default)]
pub struct LogWindow {
    samples: VecDeque<LogSample>,
}

impl LogWindow {
    pub fn new() -> LogWindow {
        LogWindow::default()
    }

    pub fn push(&mut self, sample: LogSample) {
        self.samples.push_back(sample);
        while self.samples.front().is_some_and(|s| sample.t_ms - s.t_ms > WINDOW_MS) {
            self.samples.pop_front();
        }
    }

    /// Rates start at the first sample with a known tree, because the jump from
    /// nothing to the tree's size is not publishing. Problems count from the start.
    pub fn summary(&self) -> WindowSummary {
        let (Some(first), Some(last)) = (self.samples.front(), self.samples.back()) else {
            return WindowSummary::default();
        };
        let mut s = WindowSummary {
            http_429: last.http_429.saturating_sub(first.http_429),
            errors: last.errors.saturating_sub(first.errors),
            malformed: last.malformed.saturating_sub(first.malformed),
            ..WindowSummary::default()
        };
        let Some(base) = self.samples.iter().find(|x| x.tree_size > 0) else {
            return s;
        };
        s.seconds = (last.t_ms - base.t_ms) as f64 / 1000.0;
        if s.seconds <= 0.0 {
            s.seconds = 0.0;
            return s;
        }
        let behind = |x: &LogSample| x.tree_size.saturating_sub(x.position) as i64;
        let fetched = last.fetched.saturating_sub(base.fetched) as f64;
        s.behind_change = behind(last) - behind(base);
        s.fetched_per_sec = fetched / s.seconds;
        s.published_per_sec = ((fetched + s.behind_change as f64) / s.seconds).max(0.0);
        s
    }
}

/// Entries behind the tree head, or `None` while the tree size has never been read.
pub fn behind_of(position: u64, tree_size: u64, tree_changed_ms: i64) -> Option<u64> {
    (tree_changed_ms > 0).then(|| tree_size.saturating_sub(position))
}

pub fn is_behind(behind: u64, published_per_sec: f64) -> bool {
    behind as f64 > MIN_BEHIND.max(60.0 * published_per_sec)
}

#[derive(Debug, Clone)]
pub struct HealthInput {
    pub now_ms: i64,
    pub started_ms: i64,
    pub paused: bool,
    pub behind: Option<u64>,
    /// 0 if the log has never answered.
    pub last_contact_ms: i64,
    pub tree_changed_ms: i64,
    /// 0 unless data requests are failing.
    pub data_fail_since_ms: i64,
    pub window: WindowSummary,
}

pub fn classify(i: &HealthInput) -> LogState {
    let w = &i.window;
    if i.paused {
        return LogState::Paused;
    }
    if i.now_ms - i.started_ms < MEASURING_MS {
        return LogState::Measuring;
    }
    let behind = i.behind.is_some_and(|b| is_behind(b, w.published_per_sec));
    // Backoff after a 429 can leave minutes between requests. Silence then is ours.
    let silent = i.now_ms - i.last_contact_ms >= FAILING_AFTER_MS && w.http_429 == 0;
    let no_contact = i.last_contact_ms == 0 || silent;
    let data_down = i.data_fail_since_ms > 0 && i.now_ms - i.data_fail_since_ms >= FAILING_AFTER_MS;
    if no_contact || (behind && data_down) {
        return LogState::Failing;
    }
    if w.http_429 > 0 && (behind || i.behind.is_none()) {
        return LogState::RateLimited;
    }
    if behind {
        return if w.fetched_per_sec > w.published_per_sec {
            LogState::CatchingUp
        } else {
            LogState::FallingBehind
        };
    }
    if i.tree_changed_ms > 0 && i.now_ms - i.tree_changed_ms >= NOT_ADVANCING_MS {
        return LogState::NotAdvancing;
    }
    LogState::Healthy
}

/// The whole fleet over the health window.
#[derive(Debug, Clone, Default)]
pub struct VerdictInput {
    pub seconds: f64,
    pub published_per_sec: f64,
    pub fetched_per_sec: f64,
    pub backlog: u64,
    pub backlog_change: i64,
    pub limited_backlog: u64,
    pub pipeline_busy_pct: f64,
    pub queue_full_pct: f64,
    /// Percent of the window with the pipeline or its queue over 80%.
    pub strained_pct: f64,
    /// Name, state and shortfall per second of each log.
    pub logs: Vec<(String, LogState, f64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Keeping {
    Measuring,
    CatchingUp,
    HoldingSteady,
    FallingBehind,
}

#[derive(Debug, Clone, Serialize)]
pub struct Bottleneck {
    pub name: String,
    pub state: LogState,
    pub shortfall_per_sec: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub status: Keeping,
    pub bottlenecks: Vec<Bottleneck>,
    pub ctprobe_limit: bool,
    pub cause_unclear: bool,
    pub eta_secs: Option<u64>,
    pub seconds: f64,
    pub published_per_sec: f64,
    pub fetched_per_sec: f64,
    pub backlog: u64,
    pub backlog_change: i64,
    pub limited_backlog: u64,
    pub pipeline_busy_pct: f64,
    pub queue_full_pct: f64,
}

const MIN_VERDICT_SECS: f64 = 300.0;
const STEADY_SHARE: f64 = 0.05;
const STRAINED_MOST_OF_WINDOW: f64 = 50.0;
const TOP_BOTTLENECKS: usize = 3;

/// Says whether the fleet keeps up, and what holds it back when it does not.
pub fn verdict(i: &VerdictInput) -> Verdict {
    let (p, f) = (i.published_per_sec, i.fetched_per_sec);
    let near = (p - f).abs() <= STEADY_SHARE * p.max(f).max(1.0);
    let flat = (i.backlog_change.abs() as f64) < 60.0 * p;
    let status = if i.seconds < MIN_VERDICT_SECS {
        Keeping::Measuring
    } else if near || flat {
        Keeping::HoldingSteady
    } else if f > p {
        Keeping::CatchingUp
    } else {
        Keeping::FallingBehind
    };
    // Jitter leaves healthy logs a little short half the time; only a log in
    // trouble can be named as the cause.
    let troubled = |s: LogState| matches!(s, LogState::Failing | LogState::RateLimited | LogState::FallingBehind);
    let mut slow: Vec<_> = i.logs.iter().filter(|l| l.2 > 0.0 && troubled(l.1)).collect();
    slow.sort_by(|a, b| b.2.total_cmp(&a.2));
    let bottlenecks: Vec<_> = slow
        .into_iter()
        .take(TOP_BOTTLENECKS)
        .map(|l| Bottleneck { name: l.0.clone(), state: l.1, shortfall_per_sec: l.2 })
        .collect();
    let ctprobe_limit = i.strained_pct > STRAINED_MOST_OF_WINDOW;
    Verdict {
        status,
        cause_unclear: status == Keeping::FallingBehind && bottlenecks.is_empty() && !ctprobe_limit,
        ctprobe_limit,
        bottlenecks,
        eta_secs: (status == Keeping::CatchingUp).then(|| (i.backlog as f64 / (f - p)) as u64),
        seconds: i.seconds,
        published_per_sec: p,
        fetched_per_sec: f,
        backlog: i.backlog,
        backlog_change: i.backlog_change,
        limited_backlog: i.limited_backlog,
        pipeline_busy_pct: i.pipeline_busy_pct,
        queue_full_pct: i.queue_full_pct,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict_input() -> VerdictInput {
        VerdictInput {
            seconds: 900.0,
            published_per_sec: 100.0,
            fetched_per_sec: 100.0,
            backlog: 0,
            backlog_change: 0,
            limited_backlog: 0,
            pipeline_busy_pct: 1.0,
            queue_full_pct: 0.0,
            strained_pct: 0.0,
            logs: vec![],
        }
    }

    fn falling() -> VerdictInput {
        VerdictInput { published_per_sec: 1000.0, fetched_per_sec: 500.0, backlog: 500_000, backlog_change: 450_000, ..verdict_input() }
    }

    #[test]
    fn verdict_names_largest_shortfalls_first() {
        let logs = vec![
            ("a".to_string(), LogState::FallingBehind, 10.0),
            ("b".to_string(), LogState::RateLimited, 160.0),
            ("c".to_string(), LogState::Healthy, 0.0),
            ("d".to_string(), LogState::RateLimited, 90.0),
            ("e".to_string(), LogState::FallingBehind, 40.0),
        ];
        let v = verdict(&VerdictInput { logs, ..falling() });
        assert_eq!(v.status, Keeping::FallingBehind);
        let names: Vec<_> = v.bottlenecks.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["b", "d", "e"]);
        assert_eq!(v.bottlenecks[0].state, LogState::RateLimited);
        assert!(!v.cause_unclear);
    }

    #[test]
    fn healthy_logs_are_never_named_as_bottlenecks() {
        let logs = (0..100).map(|i| (format!("l{i}"), LogState::Healthy, 0.3)).collect();
        let v = verdict(&VerdictInput { logs, ..falling() });
        assert!(v.bottlenecks.is_empty());
        assert!(v.cause_unclear);
    }

    #[test]
    fn measuring_logs_are_never_named_as_bottlenecks() {
        let logs = vec![("a".to_string(), LogState::Measuring, 50.0)];
        assert!(verdict(&VerdictInput { logs, ..falling() }).bottlenecks.is_empty());
    }

    #[test]
    fn verdict_flags_ctprobe_when_queue_stays_full() {
        let v = verdict(&VerdictInput { strained_pct: 70.0, queue_full_pct: 85.0, ..falling() });
        assert!(v.ctprobe_limit);
        assert!(!v.cause_unclear);
        assert!(!verdict(&VerdictInput { strained_pct: 30.0, ..falling() }).ctprobe_limit);
    }

    #[test]
    fn verdict_says_unclear_when_nothing_explains_it() {
        assert!(verdict(&falling()).cause_unclear);
    }

    #[test]
    fn verdict_holding_steady_within_five_percent() {
        let v = verdict(&VerdictInput { fetched_per_sec: 96.0, backlog: 90_000, backlog_change: 90_000, ..verdict_input() });
        assert_eq!(v.status, Keeping::HoldingSteady);
    }

    #[test]
    fn verdict_holding_steady_when_backlog_barely_moves() {
        let v = verdict(&VerdictInput { published_per_sec: 100.0, fetched_per_sec: 50.0, backlog_change: 5999, ..verdict_input() });
        assert_eq!(v.status, Keeping::HoldingSteady);
    }

    #[test]
    fn verdict_eta_only_when_catching_up() {
        let up = verdict(&VerdictInput { fetched_per_sec: 200.0, backlog: 10_000, backlog_change: -90_000, ..verdict_input() });
        assert_eq!(up.status, Keeping::CatchingUp);
        assert_eq!(up.eta_secs, Some(100));
        assert_eq!(verdict(&falling()).eta_secs, None);
    }

    #[test]
    fn verdict_waits_for_five_minutes_of_data() {
        assert_eq!(verdict(&VerdictInput { seconds: 200.0, ..falling() }).status, Keeping::Measuring);
    }

    const NOW: i64 = 10_000_000;
    const MIN: i64 = 60_000;

    fn input() -> HealthInput {
        HealthInput {
            now_ms: NOW,
            started_ms: NOW - 60 * MIN,
            paused: false,
            behind: Some(0),
            last_contact_ms: NOW,
            tree_changed_ms: NOW,
            data_fail_since_ms: 0,
            window: WindowSummary { seconds: 900.0, fetched_per_sec: 10.0, published_per_sec: 10.0, ..Default::default() },
        }
    }

    fn behind() -> HealthInput {
        HealthInput { behind: Some(50_000), ..input() }
    }

    #[test]
    fn paused_wins() {
        let i = HealthInput { paused: true, last_contact_ms: 0, ..input() };
        assert_eq!(classify(&i), LogState::Paused);
    }

    #[test]
    fn measuring_in_first_five_minutes_even_if_failing() {
        let i = HealthInput { started_ms: NOW - 4 * MIN, last_contact_ms: 0, ..input() };
        assert_eq!(classify(&i), LogState::Measuring);
    }

    #[test]
    fn failing_after_five_minutes_without_contact() {
        let i = HealthInput { last_contact_ms: NOW - 5 * MIN, ..input() };
        assert_eq!(classify(&i), LogState::Failing);
    }

    #[test]
    fn failing_when_never_contacted() {
        let i = HealthInput { last_contact_ms: 0, behind: None, ..input() };
        assert_eq!(classify(&i), LogState::Failing);
    }

    #[test]
    fn failing_when_only_data_requests_fail_for_five_minutes() {
        let i = HealthInput { data_fail_since_ms: NOW - 5 * MIN, ..behind() };
        assert_eq!(classify(&i), LogState::Failing);
    }

    #[test]
    fn recent_data_failure_is_not_failing_yet() {
        let i = HealthInput { data_fail_since_ms: NOW - MIN, ..behind() };
        assert_ne!(classify(&i), LogState::Failing);
    }

    #[test]
    fn rate_limited_when_behind_with_recent_429() {
        let mut i = behind();
        i.window.http_429 = 3;
        i.window.fetched_per_sec = 50.0;
        assert_eq!(classify(&i), LogState::RateLimited);
    }

    #[test]
    fn backing_off_from_429s_is_not_an_outage() {
        let mut i = HealthInput { last_contact_ms: NOW - 6 * MIN, ..behind() };
        i.window.http_429 = 2;
        assert_eq!(classify(&i), LogState::RateLimited);
    }

    #[test]
    fn rate_limited_before_tree_size_is_known() {
        let mut i = HealthInput { behind: None, ..input() };
        i.window.http_429 = 1;
        assert_eq!(classify(&i), LogState::RateLimited);
    }

    #[test]
    fn falling_behind_without_429() {
        let mut i = behind();
        i.window.fetched_per_sec = 5.0;
        assert_eq!(classify(&i), LogState::FallingBehind);
    }

    #[test]
    fn no_progress_when_behind_is_falling_behind() {
        let mut i = behind();
        i.window.fetched_per_sec = 0.0;
        i.window.published_per_sec = 0.0;
        assert_eq!(classify(&i), LogState::FallingBehind);
    }

    #[test]
    fn catching_up_when_fetched_above_published() {
        let mut i = behind();
        i.window.fetched_per_sec = 50.0;
        assert_eq!(classify(&i), LogState::CatchingUp);
    }

    #[test]
    fn not_advancing_after_30_minutes() {
        let i = HealthInput { tree_changed_ms: NOW - 30 * MIN, ..input() };
        assert_eq!(classify(&i), LogState::NotAdvancing);
    }

    #[test]
    fn healthy_otherwise() {
        assert_eq!(classify(&input()), LogState::Healthy);
    }

    #[test]
    fn threshold_uses_60s_of_published_rate() {
        assert!(!is_behind(1000, 1.0));
        assert!(is_behind(1001, 1.0));
        assert!(!is_behind(5999, 100.0));
        assert!(is_behind(6001, 100.0));
    }

    fn sample(t_s: i64, position: u64, tree_size: u64, fetched: u64) -> LogSample {
        LogSample { t_ms: t_s * 1000, position, tree_size, fetched, http_429: 0, errors: 0, malformed: 0 }
    }

    #[test]
    fn summary_derives_published_from_fetched_and_backlog() {
        let mut w = LogWindow::new();
        w.push(sample(0, 100, 200, 0));
        w.push(sample(100, 600, 1200, 500));
        let s = w.summary();
        assert_eq!(s.seconds, 100.0);
        assert_eq!(s.fetched_per_sec, 5.0);
        assert_eq!(s.published_per_sec, 10.0);
        assert_eq!(s.behind_change, 500);
    }

    #[test]
    fn samples_older_than_15_minutes_leave() {
        let mut w = LogWindow::new();
        w.push(sample(0, 0, 0, 0));
        w.push(sample(10, 0, 1000, 0));
        for m in 1..=20 {
            w.push(sample(m * 60, 0, 1000, 0));
        }
        assert_eq!(w.summary().seconds, 900.0);
    }

    #[test]
    fn first_contact_does_not_read_as_publishing() {
        let mut w = LogWindow::new();
        w.push(sample(0, 0, 0, 0));
        w.push(sample(10, 5_000_000, 5_000_000, 0));
        w.push(sample(20, 5_000_100, 5_000_100, 100));
        let s = w.summary();
        assert_eq!(s.published_per_sec, 10.0);
        assert_eq!(s.seconds, 10.0);
    }

    #[test]
    fn problem_counts_cover_time_before_first_contact() {
        let mut w = LogWindow::new();
        w.push(LogSample { http_429: 1, ..sample(0, 0, 0, 0) });
        w.push(LogSample { http_429: 4, errors: 2, ..sample(10, 0, 0, 0) });
        let s = w.summary();
        assert_eq!((s.http_429, s.errors), (3, 2));
    }

    #[test]
    fn shrinking_tree_never_gives_negative_published() {
        let mut w = LogWindow::new();
        w.push(sample(0, 100, 5000, 0));
        w.push(sample(100, 100, 1000, 0));
        assert_eq!(w.summary().published_per_sec, 0.0);
    }

    #[test]
    fn position_above_tree_size_is_zero_behind() {
        assert_eq!(behind_of(500, 100, 1), Some(0));
        assert_eq!(behind_of(100, 500, 1), Some(400));
    }

    #[test]
    fn unknown_tree_size_is_unknown_behind() {
        assert_eq!(behind_of(7, 0, 0), None);
        assert_eq!(behind_of(0, 0, 5), Some(0));
    }
}
