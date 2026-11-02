use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::config::Config;
use crate::types::LogId;

const LOGS: TableDefinition<u16, &str> = TableDefinition::new("logs");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogKind {
    Rfc6962 { url: String },
    Tiled { monitoring_url: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogSpec {
    pub name: String,
    pub log_id_b64: String,
    pub kind: LogKind,
    pub state: String,
    pub operator: String,
    /// URL of the list this entry came from.
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogInfo {
    pub id: LogId,
    pub name: String,
    pub log_id_b64: String,
    pub kind: LogKind,
    pub state: String,
    #[serde(default)]
    pub operator: String,
    /// Empty on records stored before sources existed, until the next refresh.
    #[serde(default)]
    pub source: String,
}

#[derive(Deserialize)]
struct ListFile {
    operators: Vec<ListOperator>,
}

#[derive(Deserialize)]
struct ListOperator {
    #[serde(default)]
    name: String,
    #[serde(default)]
    logs: Vec<ListLog>,
    #[serde(default)]
    tiled_logs: Vec<ListLog>,
}

#[derive(Deserialize)]
struct ListLog {
    description: String,
    log_id: String,
    url: Option<String>,
    monitoring_url: Option<String>,
    #[serde(default)]
    state: HashMap<String, serde_json::Value>,
    temporal_interval: Option<Interval>,
}

#[derive(Deserialize)]
struct Interval {
    end_exclusive: DateTime<Utc>,
}

/// Selects logs to follow: `usable` or `qualified`, interval not ended,
/// matching the include list (if any) and not the exclude list. With `test_logs`
/// it selects only logs with no state, which are test or staging logs.
pub fn parse_log_list(
    data: &[u8],
    now: DateTime<Utc>,
    cfg: &Config,
    source: &str,
    test_logs: bool,
) -> Result<Vec<LogSpec>> {
    let file: ListFile = serde_json::from_slice(data).context("parsing log list")?;
    let mut out = Vec::new();
    let wanted = |name: &str| {
        (cfg.include_logs.is_empty() || cfg.include_logs.iter().any(|p| name.contains(p.as_str())))
            && !cfg.exclude_logs.iter().any(|p| name.contains(p.as_str()))
    };
    for op in file.operators {
        let all = op.logs.into_iter().chain(op.tiled_logs);
        for log in all {
            let state = if test_logs {
                if !log.state.is_empty() {
                    continue;
                }
                "test"
            } else {
                let found = ["usable", "qualified"].iter().find(|s| log.state.contains_key(**s));
                let Some(found) = found else { continue };
                found
            };
            if log.temporal_interval.as_ref().is_some_and(|i| i.end_exclusive <= now) {
                continue;
            }
            if !wanted(&log.description) {
                continue;
            }
            let kind = match (log.monitoring_url, log.url) {
                (Some(monitoring_url), _) => LogKind::Tiled { monitoring_url },
                (None, Some(url)) => LogKind::Rfc6962 { url },
                (None, None) => continue,
            };
            out.push(LogSpec {
                name: log.description,
                log_id_b64: log.log_id,
                kind,
                state: state.to_string(),
                operator: op.name.clone(),
                source: source.to_string(),
            });
        }
    }
    Ok(out)
}

/// Joins selections, keeping the first entry for each log. Put the primary list first.
pub fn merge_specs(lists: Vec<Vec<LogSpec>>) -> Vec<LogSpec> {
    let mut seen = std::collections::HashSet::new();
    lists.into_iter().flatten().filter(|s| seen.insert(s.log_id_b64.clone())).collect()
}

async fn download(client: &reqwest::Client, url: &str) -> Result<bytes::Bytes> {
    Ok(client.get(url).send().await?.error_for_status()?.bytes().await?)
}

/// Downloads every configured list. Only the primary list is required; the
/// second value names the other sources that could not be read, whose logs
/// must not be retired for being absent.
pub async fn load_specs(
    client: &reqwest::Client,
    cfg: &Config,
    now: DateTime<Utc>,
) -> Result<(Vec<LogSpec>, Vec<String>)> {
    let body = download(client, &cfg.log_list_url).await?;
    let mut lists = vec![parse_log_list(&body, now, cfg, &cfg.log_list_url, false)?];
    let mut failed = Vec::new();
    let extras = cfg.extra_log_lists.iter().map(|u| (u.as_str(), false));
    let test = cfg.include_test_logs.then_some((crate::config::DEFAULT_ALL_LOGS, true));
    for (url, test_logs) in extras.chain(test) {
        let got = match download(client, url).await {
            Ok(b) => parse_log_list(&b, now, cfg, url, test_logs),
            Err(e) => Err(e),
        };
        match got {
            Ok(specs) => lists.push(specs),
            Err(e) => {
                tracing::warn!("log list {url} unavailable: {e:#}");
                failed.push(url.to_string());
            }
        }
    }
    Ok((merge_specs(lists), failed))
}

/// All logs ever followed, with `LogId`s that never change.
pub struct Registry {
    db: Arc<Database>,
    logs: RwLock<Vec<LogInfo>>,
}

impl Registry {
    pub fn open(db: Arc<Database>) -> Result<Registry> {
        let mut logs = Vec::new();
        {
            let tx = db.begin_read()?;
            match tx.open_table(LOGS) {
                Ok(t) => {
                    for row in t.iter()? {
                        let (_, v) = row?;
                        logs.push(serde_json::from_str(v.value())?);
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(Registry { db, logs: RwLock::new(logs) })
    }

    pub fn logs(&self) -> Vec<LogInfo> {
        self.logs.read().unwrap().clone()
    }

    pub fn get(&self, id: LogId) -> Option<LogInfo> {
        self.logs.read().unwrap().iter().find(|l| l.id == id).cloned()
    }

    /// Merges a fresh selection. Returns newly added logs; known logs absent
    /// from `specs` are marked retired.
    pub fn ingest(&self, specs: Vec<LogSpec>) -> Result<Vec<LogInfo>> {
        self.ingest_keeping(specs, &[])
    }

    /// As `ingest`, leaving alone the logs of sources that could not be read.
    pub fn ingest_keeping(&self, specs: Vec<LogSpec>, failed: &[String]) -> Result<Vec<LogInfo>> {
        let mut logs = self.logs.write().unwrap();
        let mut added = Vec::new();
        for log in logs.iter_mut() {
            let listed = specs.iter().any(|s| s.log_id_b64 == log.log_id_b64);
            if !listed && !failed.contains(&log.source) {
                log.state = "retired".into();
            }
        }
        for s in specs {
            if let Some(l) = logs.iter_mut().find(|l| l.log_id_b64 == s.log_id_b64) {
                l.state = s.state;
                l.kind = s.kind;
                l.operator = s.operator;
                l.source = s.source;
                continue;
            }
            let id = logs.iter().map(|l| l.id + 1).max().unwrap_or(0);
            let info = LogInfo {
                id,
                name: s.name,
                log_id_b64: s.log_id_b64,
                kind: s.kind,
                state: s.state,
                operator: s.operator,
                source: s.source,
            };
            logs.push(info.clone());
            added.push(info);
        }
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(LOGS)?;
            for l in logs.iter() {
                t.insert(l.id, serde_json::to_string(l)?.as_str())?;
            }
        }
        tx.commit()?;
        Ok(added)
    }

    /// As `ingest`, for a periodic refresh: an empty selection from a bad
    /// download must not retire every log and stop collection.
    pub fn merge_refresh(&self, specs: Vec<LogSpec>, failed: &[String]) -> Result<Vec<LogInfo>> {
        anyhow::ensure!(!specs.is_empty(), "log list selects no logs; keeping the current ones");
        self.ingest_keeping(specs, failed)
    }

    /// Downloads the log lists and merges them.
    pub async fn refresh(&self, client: &reqwest::Client, cfg: &Config) -> Result<Vec<LogInfo>> {
        let (specs, failed) = load_specs(client, cfg, Utc::now()).await?;
        self.merge_refresh(specs, &failed)
    }
}
