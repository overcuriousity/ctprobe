//! Disk budget enforcement. Only `sightings`, `certs` and `dns` ever lose data.

use crate::metrics::dir_size;
use anyhow::Result;
use chrono::NaiveDate;
use std::path::{Path, PathBuf};

const SIGHTINGS_DAYS: i64 = 14;

/// Day directories of a table, oldest first.
fn days(table_dir: &Path) -> Vec<(NaiveDate, PathBuf)> {
    let mut out: Vec<_> = std::fs::read_dir(table_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let d = NaiveDate::parse_from_str(name.strip_prefix("day=")?, "%Y-%m-%d").ok()?;
            Some((d, e.path()))
        })
        .collect();
    out.sort();
    out
}

/// Removes one day of `certs` and its `dns` probes, returning the bytes freed.
fn remove_day(data: &Path, day: NaiveDate) -> Result<u64> {
    let mut freed = 0;
    for table in ["certs", "dns"] {
        let p = data.join(table).join(format!("day={}", day.format("%Y-%m-%d")));
        if p.exists() {
            freed += dir_size(&p);
            std::fs::remove_dir_all(p)?;
        }
    }
    Ok(freed)
}

/// Deletes `sightings` past retention, then the oldest days of `certs` and
/// `dns` until total size is under 90% of budget. The current day is never
/// deleted. Returns a reason if the budget still cannot be met.
pub fn enforce(data: &Path, budget: u64, today: NaiveDate) -> Result<Option<String>> {
    for (d, p) in days(&data.join("sightings")) {
        if (today - d).num_days() > SIGHTINGS_DAYS {
            std::fs::remove_dir_all(p)?;
        }
    }
    let target = budget / 10 * 9;
    let mut size = dir_size(data);
    if size <= target {
        return Ok(None);
    }
    // Days the nightly job has not finished still owe their rollups, so they go
    // last, and only to stay under the hard budget.
    let finished = |d: &NaiveDate| {
        data.join("nightly").join(format!("{}.domains", d.format("%Y-%m-%d"))).exists()
    };
    let mut all: Vec<NaiveDate> = days(&data.join("certs"))
        .into_iter()
        .chain(days(&data.join("dns")))
        .map(|(d, _)| d)
        .filter(|d| *d < today)
        .collect();
    all.sort();
    all.dedup();
    let (done, pending): (Vec<_>, Vec<_>) = all.into_iter().partition(finished);
    for d in done {
        size = size.saturating_sub(remove_day(data, d)?);
        if size <= target {
            return Ok(None);
        }
    }
    for d in pending {
        if size <= budget {
            break;
        }
        size = size.saturating_sub(remove_day(data, d)?);
    }
    Ok((size > budget).then(|| {
        format!("disk budget of {budget} bytes cannot be met; data uses {size} bytes")
    }))
}
