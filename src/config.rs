use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub const DEFAULT_LOG_LIST: &str = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
pub const DEFAULT_APPLE_LIST: &str = "https://valid.apple.com/ct/log_list/current_log_list.json";
pub const DEFAULT_ALL_LOGS: &str = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json";
const DEFAULT_COVERAGE_TARGET: f64 = 95.0;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub disk_budget_bytes: u64,
    pub tracker_max_bytes: u64,
    pub include_logs: Vec<String>,
    pub exclude_logs: Vec<String>,
    pub log_list_url: String,
    /// Further lists; a log on any of them is followed.
    pub extra_log_lists: Vec<String>,
    pub include_test_logs: bool,
    /// Percent of certificates the coverage assessment aims for.
    pub coverage_target: f64,
    pub dns: DnsConfig,
}

/// DNS probing of certificate names. Off while `resolvers` is empty.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsConfig {
    pub resolvers: Vec<SocketAddr>,
    /// Resolvers that must report the same outcome for it to count.
    pub quorum: usize,
    /// Queries per second sent to each resolver; every probe sends two (A, AAAA).
    pub max_qps: u32,
    /// Memory cap for the last answer per name, used to detect changes.
    pub state_max_bytes: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig { resolvers: Vec::new(), quorum: 1, max_qps: DEFAULT_DNS_QPS, state_max_bytes: DEFAULT_DNS_STATE }
    }
}

impl DnsConfig {
    pub fn enabled(&self) -> bool {
        !self.resolvers.is_empty()
    }
}

const DEFAULT_DNS_QPS: u32 = 500;
const DEFAULT_DNS_STATE: u64 = 256 << 20;

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawDns {
    #[serde(default)]
    resolvers: Vec<String>,
    quorum: Option<usize>,
    max_qps: Option<u32>,
    state_max: Option<String>,
}

/// `1.2.3.4`, `1.2.3.4:5353`, `::1` or `[::1]:5353`; port 53 when absent.
fn parse_resolver(s: &str) -> Result<SocketAddr> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    let ip: std::net::IpAddr = s.parse().with_context(|| format!("bad resolver address {s:?}"))?;
    Ok(SocketAddr::new(ip, 53))
}

impl RawDns {
    fn build(self) -> Result<DnsConfig> {
        let resolvers = self.resolvers.iter().map(|r| parse_resolver(r)).collect::<Result<Vec<_>>>()?;
        let n = resolvers.len();
        let quorum = self.quorum.unwrap_or(n / 2 + 1);
        if n > 0 && !(1..=n).contains(&quorum) {
            bail!("dns.quorum {quorum} must be between 1 and the number of resolvers ({n})");
        }
        let max_qps = self.max_qps.unwrap_or(DEFAULT_DNS_QPS);
        if max_qps < 2 {
            bail!("dns.max_qps must be at least 2");
        }
        let state_max_bytes = match &self.state_max {
            Some(s) => parse_size(s)?,
            None => DEFAULT_DNS_STATE,
        };
        Ok(DnsConfig { resolvers, quorum: quorum.max(1), max_qps, state_max_bytes })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    bind: SocketAddr,
    data_dir: PathBuf,
    disk_budget: String,
    tracker_max: String,
    #[serde(default)]
    include_logs: Vec<String>,
    #[serde(default)]
    exclude_logs: Vec<String>,
    log_list_url: Option<String>,
    extra_log_lists: Option<Vec<String>>,
    #[serde(default)]
    include_test_logs: bool,
    coverage_target: Option<f64>,
    #[serde(default)]
    dns: RawDns,
}

fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix("GiB") {
        (n, 1u64 << 30)
    } else if let Some(n) = s.strip_suffix("MiB") {
        (n, 1u64 << 20)
    } else {
        bail!("size {s:?} must end in GiB or MiB");
    };
    let n: u64 = num.trim().parse().with_context(|| format!("bad size {s:?}"))?;
    n.checked_mul(mult).context("size overflow")
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let raw: RawConfig = toml::from_str(&text).context("parsing config")?;
        let coverage_target = raw.coverage_target.unwrap_or(DEFAULT_COVERAGE_TARGET);
        if !(coverage_target > 0.0 && coverage_target <= 100.0) {
            bail!("coverage_target {coverage_target} must be above 0 and at most 100");
        }
        Ok(Config {
            bind: raw.bind,
            data_dir: raw.data_dir,
            disk_budget_bytes: parse_size(&raw.disk_budget)?,
            tracker_max_bytes: parse_size(&raw.tracker_max)?,
            include_logs: raw.include_logs,
            exclude_logs: raw.exclude_logs,
            log_list_url: raw.log_list_url.unwrap_or_else(|| DEFAULT_LOG_LIST.to_string()),
            extra_log_lists: raw.extra_log_lists.unwrap_or_else(|| vec![DEFAULT_APPLE_LIST.to_string()]),
            include_test_logs: raw.include_test_logs,
            coverage_target,
            dns: raw.dns.build()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loads_example_config() {
        let c = Config::load(std::path::Path::new("ctprobe.example.toml")).unwrap();
        assert_eq!(c.bind.to_string(), "0.0.0.0:8080");
        assert_eq!(c.disk_budget_bytes, 4294967296);
        assert_eq!(c.tracker_max_bytes, 2147483648);
        assert_eq!(c.extra_log_lists, [DEFAULT_APPLE_LIST]);
        assert!(!c.include_test_logs);
        assert_eq!(c.coverage_target, 95.0);
        assert!(!c.dns.enabled());
    }

    #[test]
    fn parses_dns_section() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.toml");
        let base = "bind = \"0.0.0.0:1\"\ndata_dir = \"d\"\ndisk_budget = \"1GiB\"\ntracker_max = \"1GiB\"\n";
        let dns = "[dns]\nresolvers = [\"127.0.0.1\", \"[::1]:5353\", \"9.9.9.9:53\"]\nmax_qps = 100\nstate_max = \"64MiB\"\n";
        std::fs::write(&p, format!("{base}{dns}")).unwrap();
        let c = Config::load(&p).unwrap().dns;
        assert_eq!(c.resolvers[0].to_string(), "127.0.0.1:53");
        assert_eq!(c.resolvers[1].to_string(), "[::1]:5353");
        assert_eq!(c.quorum, 2, "majority by default");
        assert_eq!(c.max_qps, 100);
        assert_eq!(c.state_max_bytes, 64 << 20);
        std::fs::write(&p, format!("{base}[dns]\nresolvers = [\"127.0.0.1\"]\nquorum = 2\n")).unwrap();
        assert!(Config::load(&p).is_err());
        std::fs::write(&p, format!("{base}[dns]\nresolvers = [\"not an ip\"]\n")).unwrap();
        assert!(Config::load(&p).is_err());
    }

    #[test]
    fn rejects_coverage_target_out_of_range() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.toml");
        let base = "bind = \"0.0.0.0:1\"\ndata_dir = \"d\"\ndisk_budget = \"1GiB\"\ntracker_max = \"1GiB\"\n";
        for bad in ["0", "101", "-5"] {
            std::fs::write(&p, format!("{base}coverage_target = {bad}\n")).unwrap();
            assert!(Config::load(&p).is_err(), "{bad}");
        }
        std::fs::write(&p, format!("{base}coverage_target = 100\n")).unwrap();
        assert!(Config::load(&p).is_ok());
    }
}
