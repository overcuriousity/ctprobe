//! Daily maintenance. Each step is recorded by a marker file and writes its
//! output atomically, so a rerun after a crash repeats only unfinished work.

pub mod archive;
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

/// The days whose `step` is done, from one listing of the marker directory.
pub fn days_done(data: &Path, step: &str) -> Vec<NaiveDate> {
    let suffix = format!(".{step}");
    std::fs::read_dir(data.join("nightly"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            NaiveDate::parse_from_str(n.strip_suffix(&suffix)?, "%Y-%m-%d").ok()
        })
        .collect()
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
        compact::run(data, &d, &cfg.retention()).await?;
        mark(data, &d, "compact")?;
    }
    if !step_done(data, &d, "domains") {
        domains::run(data, &d).await?;
        mark(data, &d, "domains")?;
    }
    if let Some(budget) = cfg.archive_budget_bytes {
        for (step, table) in [("archive", "certs"), ("archive-dns", "dns")] {
            if step_done(data, &d, step) {
                continue;
            }
            let outcome = match table {
                "certs" => archive::certs(data, &d, budget).await?,
                _ => archive::dns(data, &d, budget).await?,
            };
            match outcome {
                archive::Outcome::Written { rows, bytes } => {
                    mark(data, &d, step)?;
                    let total = archive::archive_size(data);
                    tracing::info!(
                        "archive {total} bytes, {} bytes per row of {table} on {d}, {} days left",
                        bytes / rows.max(1),
                        archive::days_left(data, budget, total)
                    );
                }
                archive::Outcome::Empty => mark(data, &d, step)?,
                archive::Outcome::BudgetFull => {
                    tracing::warn!("archive budget is full, {table} of {d} is not archived");
                }
            }
        }
    }
    cleanup(data)?;
    expire::enforce(data, &cfg.retention(), Utc::now().date_naive())?;
    Ok(())
}

/// Removes what a crash may leave behind: parts hidden by a daily file and
/// domain files hidden by a newer snapshot.
pub fn cleanup(data: &Path) -> Result<()> {
    for table in ["certs", "sightings", "rollup_minute", "dns", "dns_minute"] {
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
/// With `archive`, days whose archive step is unfinished are pending too, and
/// a day that holds only `dns` counts, so that it is archived and can age out.
pub fn pending_days(data: &Path, today: NaiveDate, archive: bool) -> Vec<NaiveDate> {
    let tables: &[&str] = if archive { &["certs", "dns"] } else { &["certs"] };
    let mut out: Vec<NaiveDate> = tables
        .iter()
        .flat_map(|t| std::fs::read_dir(data.join(t)).into_iter().flatten().flatten())
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            NaiveDate::parse_from_str(n.strip_prefix("day=")?, "%Y-%m-%d").ok()
        })
        .filter(|d| {
            let s = d.format("%Y-%m-%d").to_string();
            *d < today
                && (!step_done(data, &s, "domains")
                    || (archive && !(step_done(data, &s, "archive") && step_done(data, &s, "archive-dns"))))
        })
        .collect();
    out.sort();
    out.dedup();
    out
}
