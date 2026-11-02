//! Daily maintenance. Each step is recorded by a marker file and writes its
//! output atomically, so a rerun after a crash repeats only unfinished work.

mod compact;
mod domains;
pub mod expire;
mod rollups;

use crate::config::Config;
use anyhow::Result;
use chrono::{NaiveDate, Utc};
use std::path::{Path, PathBuf};

const MEMORY: usize = 4 << 30;
const PARTITIONS: usize = 2;

fn marker(data: &Path, day: &str, step: &str) -> PathBuf {
    data.join("nightly").join(format!("{day}.{step}"))
}

fn step_done(data: &Path, day: &str, step: &str) -> bool {
    marker(data, day, step).exists()
}

fn mark(data: &Path, day: &str, step: &str) -> Result<()> {
    let p = marker(data, day, step);
    std::fs::create_dir_all(p.parent().unwrap())?;
    std::fs::write(p, b"")?;
    Ok(())
}

/// Runs all steps for a finished UTC day.
pub async fn run_nightly(cfg: &Config, day: NaiveDate) -> Result<()> {
    let data = &cfg.data_dir;
    let d = day.format("%Y-%m-%d").to_string();
    if !step_done(data, &d, "rollups") {
        rollups::run(data, &d).await?;
        mark(data, &d, "rollups")?;
    }
    if !step_done(data, &d, "compact") {
        compact::run(data, &d, cfg.disk_budget_bytes).await?;
        mark(data, &d, "compact")?;
    }
    if !step_done(data, &d, "domains") {
        domains::run(data, &d).await?;
        mark(data, &d, "domains")?;
    }
    cleanup(data)?;
    expire::enforce(data, cfg.disk_budget_bytes, Utc::now().date_naive())?;
    Ok(())
}

/// Removes what a crash may leave behind: parts hidden by a daily file and
/// domain files hidden by a newer snapshot.
pub fn cleanup(data: &Path) -> Result<()> {
    for table in ["certs", "sightings", "rollup_minute"] {
        let Ok(rd) = std::fs::read_dir(data.join(table)) else { continue };
        for dir in rd.flatten().map(|e| e.path()) {
            if !dir.join("daily.parquet").exists() {
                continue;
            }
            for f in std::fs::read_dir(&dir)?.flatten() {
                if f.file_name() != "daily.parquet" {
                    std::fs::remove_file(f.path())?;
                }
            }
        }
    }
    let visible = crate::store::list_parts(data, "domains");
    if visible.iter().any(|p| p.to_string_lossy().contains("snapshot-")) {
        if let Ok(rd) = std::fs::read_dir(data.join("domains")) {
            for f in rd.flatten() {
                let p = f.path();
                if p.extension().is_some_and(|x| x == "parquet") && !visible.contains(&p) {
                    std::fs::remove_file(p)?;
                }
            }
        }
    }
    Ok(())
}

/// Finished days present on disk that the nightly job has not completed.
pub fn pending_days(data: &Path, today: NaiveDate) -> Vec<NaiveDate> {
    let mut out: Vec<NaiveDate> = std::fs::read_dir(data.join("certs"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            NaiveDate::parse_from_str(n.strip_prefix("day=")?, "%Y-%m-%d").ok()
        })
        .filter(|d| *d < today && !step_done(data, &d.format("%Y-%m-%d").to_string(), "domains"))
        .collect();
    out.sort();
    out
}

