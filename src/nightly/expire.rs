//! Disk budget enforcement. Only `sightings`, `certs` and `dns` ever lose data.

use super::step_done;
use crate::metrics::{dir_size, hot_size};
use anyhow::Result;
use chrono::NaiveDate;
use std::path::{Path, PathBuf};

const SIGHTINGS_DAYS: i64 = 14;

/// How long data is kept, resolved from the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    pub budget: u64,
    pub hot_days: Option<u32>,
    /// Explicit `dns_days`, else `hot_days` raised to at least a year.
    pub dns_days: Option<u32>,
    /// An archive budget is set.
    pub archive: bool,
}

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

/// Removes one table's directory of a day, returning the bytes freed.
fn remove_table(data: &Path, table: &str, day: NaiveDate) -> Result<u64> {
    let p = data.join(table).join(format!("day={}", day.format("%Y-%m-%d")));
    if !p.exists() {
        return Ok(0);
    }
    let freed = dir_size(&p);
    std::fs::remove_dir_all(p)?;
    Ok(freed)
}

/// Removes one day of `certs` and its `dns` probes, returning the bytes freed.
fn remove_day(data: &Path, day: NaiveDate) -> Result<u64> {
    Ok(remove_table(data, "certs", day)? + remove_table(data, "dns", day)?)
}

/// Removes the days of `table` older than `max_days`. With an archive, a day
/// goes only once `step` has marked it as archived; without one, once nightly
/// has finished it (`domains` reads `certs`).
fn expire_by_age(data: &Path, table: &str, step: &str, max_days: u32, archive: bool, today: NaiveDate) -> Result<()> {
    for (d, p) in days(&data.join(table)) {
        if d >= today || (today - d).num_days() <= i64::from(max_days) {
            continue;
        }
        let name = d.format("%Y-%m-%d").to_string();
        if !step_done(data, &name, if archive { step } else { "domains" }) {
            continue;
        }
        std::fs::remove_dir_all(p)?;
    }
    Ok(())
}

/// Deletes `sightings` past retention, then `certs` and `dns` days past their
/// age limit, then the oldest days of both until the hot data is under 90% of
/// budget. The archive does not count and is never touched. The current day is
/// never deleted. Returns a reason if the budget still cannot be met.
pub fn enforce(data: &Path, r: &Retention, today: NaiveDate) -> Result<Option<String>> {
    let budget = r.budget;
    for (d, p) in days(&data.join("sightings")) {
        if (today - d).num_days() > SIGHTINGS_DAYS {
            std::fs::remove_dir_all(p)?;
        }
    }
    if let Some(n) = r.hot_days {
        expire_by_age(data, "certs", "archive", n, r.archive, today)?;
    }
    if let Some(n) = r.dns_days {
        expire_by_age(data, "dns", "archive-dns", n, r.archive, today)?;
    }
    let target = budget / 10 * 9;
    let mut size = hot_size(data);
    if size <= target {
        return Ok(None);
    }
    // Days the nightly job has not finished still owe their rollups, so they go
    // last, and only to stay under the hard budget.
    let finished = |d: &NaiveDate| step_done(data, &d.format("%Y-%m-%d").to_string(), "domains");
    let mut all: Vec<NaiveDate> = days(&data.join("certs"))
        .into_iter()
        .chain(days(&data.join("dns")))
        .map(|(d, _)| d)
        .filter(|d| *d < today)
        .collect();
    all.sort();
    all.dedup();
    let (done, pending): (Vec<_>, Vec<_>) = all.into_iter().partition(finished);
    // With an archive, days it already holds go before days it does not.
    let (archived, unarchived): (Vec<_>, Vec<_>) = if r.archive {
        done.into_iter().partition(|d| {
            let name = d.format("%Y-%m-%d").to_string();
            let held = |table: &str, step: &str| {
                step_done(data, &name, step) || !data.join(table).join(format!("day={name}")).exists()
            };
            held("certs", "archive") && held("dns", "archive-dns")
        })
    } else {
        (done, vec![])
    };
    for d in archived {
        size = size.saturating_sub(remove_day(data, d)?);
        if size <= target {
            return Ok(None);
        }
    }
    // Days the archive does not hold yet go only to stay under the hard budget.
    for d in unarchived {
        if size <= budget {
            break;
        }
        tracing::error!("disk budget forces removing {d} before it is archived");
        size = size.saturating_sub(remove_day(data, d)?);
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
