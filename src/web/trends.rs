//! Fixed SQL behind the Trends page. Finished days come from the permanent
//! rollups; the current day comes from `certs`, so charts fill from the start.

use super::api::{error, query_error, respond};
use super::AppState;
use crate::query::buckets::{san_case, size_case, validity_case};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;

pub const METRICS: &[&str] = &[
    "volume", "stages", "renewals", "issuers", "tlds", "keys", "validity", "san_dist", "der_size",
    "peaks", "lag", "concentration", "coverage", "state_growth", "catchup", "cost", "resources",
    "settling", "quality", "sizing", "dns", "dns_changes", "dns_ttd", "dns_sizing",
];

const ROWS: usize = 20_000;
const GLOBAL: &str = "65535";
/// A minute is clean when the backlog of logs that accept our rate is under one
/// minute of volume, so its rates reflect issuance and not catch-up.
const CLEAN: &str = "backlog IS NOT NULL AND backlog <= GREATEST(raw_entries, 10000)";

const DAY_HOURS: i64 = 24;

/// Counts of a dimension over the range. Under a day it counts certificates seen
/// since `from`. Longer ranges use whole finished days from permanent rows plus
/// the current day, because rollups only know days.
fn composition(col: &str, today_expr: &str, from: i64, today: i64, hours: i64) -> String {
    let rows = if hours < DAY_HOURS {
        format!("SELECT {today_expr} AS k, 1 AS n FROM certs WHERE CAST(seen_at AS BIGINT) >= {from}")
    } else {
        format!(
            "SELECT {col} AS k, certs AS n FROM rollup_daily \
               WHERE CAST(day AS TIMESTAMP) >= to_timestamp_millis({from}) \
               UNION ALL \
             SELECT {today_expr} AS k, 1 AS n FROM certs \
               WHERE CAST(seen_at AS BIGINT) >= {today}"
        )
    };
    format!(
        "SELECT k, CAST(SUM(n) AS BIGINT) AS certs FROM ( {rows} ) \
         WHERE k IS NOT NULL GROUP BY k ORDER BY 2 DESC, 1 LIMIT 15"
    )
}

/// Trend SQL for a metric.
pub fn trend_query(metric: &str, from: i64, to: i64, bucket: &str, today: i64, hours: i64) -> Option<String> {
    let t = format!("CAST(date_trunc('{bucket}', minute) AS BIGINT) / 1000 AS t");
    let range = format!("CAST(minute AS BIGINT) BETWEEN {from} AND {to}");
    let secs = match bucket {
        "minute" => 60,
        "hour" => 3600,
        _ => 86400,
    };
    Some(match metric {
        "dns" => format!(
            "SELECT {t}, \
               100.0 * SUM(first_resolved) / NULLIF(SUM(first_probes), 0) AS resolved_pct, \
               100.0 * SUM(first_v4) / NULLIF(SUM(first_probes), 0) AS v4_pct, \
               100.0 * SUM(first_v6) / NULLIF(SUM(first_probes), 0) AS v6_pct, \
               100.0 * SUM(first_nxdomain) / NULLIF(SUM(first_probes), 0) AS nxdomain_pct \
             FROM dns_minute WHERE {range} GROUP BY 1 ORDER BY 1"
        ),
        "dns_changes" => format!(
            "SELECT {t}, \
               100.0 * SUM(v4_changed) / NULLIF(SUM(v4_compared), 0) AS v4_changed_pct, \
               100.0 * SUM(v6_changed) / NULLIF(SUM(v6_compared), 0) AS v6_changed_pct, \
               100.0 * SUM(network_changed) / NULLIF(SUM(compared), 0) AS network_changed_pct, \
               100.0 * SUM(changed) / NULLIF(SUM(compared), 0) AS changed_pct \
             FROM dns_minute WHERE {range} GROUP BY 1 ORDER BY 1"
        ),
        // Cumulative shares of names found on a later probe.
        "dns_ttd" => format!(
            "SELECT {t}, \
               100.0 * SUM(found_15m) / NULLIF(SUM(found_15m + found_1h + found_1d + found_later), 0) AS within_15_min_pct, \
               100.0 * SUM(found_15m + found_1h) / NULLIF(SUM(found_15m + found_1h + found_1d + found_later), 0) AS within_1_h_pct, \
               100.0 * SUM(found_15m + found_1h + found_1d) / NULLIF(SUM(found_15m + found_1h + found_1d + found_later), 0) AS within_1_day_pct \
             FROM dns_minute WHERE {range} AND found_15m IS NOT NULL GROUP BY 1 \
             HAVING SUM(found_15m + found_1h + found_1d + found_later) > 0 ORDER BY 1"
        ),
        "dns_sizing" => format!(
            "SELECT COUNT(*) AS minutes, \
               approx_percentile_cont(queries / 60.0, 0.5) AS queries_p50, \
               approx_percentile_cont(queries / 60.0, 0.99) AS queries_p99, \
               approx_percentile_cont(first_probes / 60.0, 0.5) AS names_p50, \
               100.0 * SUM(first_resolved) / NULLIF(SUM(first_probes), 0) AS resolved_pct, \
               100.0 * SUM(never) / NULLIF(SUM(resolved_later + never), 0) AS never_pct \
             FROM dns_minute WHERE {range} AND queries IS NOT NULL"
        ),
        "volume" => format!(
            "SELECT {t}, \
               CAST(SUM(CASE WHEN log_id <> {GLOBAL} THEN entries ELSE 0 END) AS DOUBLE) / {secs} AS raw_per_sec, \
               CAST(SUM(CASE WHEN log_id = {GLOBAL} THEN entries ELSE 0 END) AS DOUBLE) / {secs} AS unique_per_sec \
             FROM rollup_minute WHERE {range} GROUP BY 1 ORDER BY 1"
        ),
        "stages" => format!(
            "SELECT * FROM ( \
               SELECT CAST(day AS VARCHAR) AS day, raw_entries, unique_certs, names, new_names, new_domains \
                 FROM daily_stages WHERE CAST(day AS TIMESTAMP) >= to_timestamp_millis({from}) \
               UNION ALL \
               SELECT 'today' AS day, (SELECT COUNT(*) FROM sightings WHERE CAST(seen_at AS BIGINT) >= {today}) AS raw_entries, \
                 COUNT(*) AS unique_certs, CAST(COALESCE(SUM(array_length(names)), 0) AS BIGINT) AS names, \
                 CAST(COALESCE(SUM(new_names), 0) AS BIGINT) AS new_names, \
                 CAST(COALESCE(SUM(new_domains), 0) AS BIGINT) AS new_domains \
                 FROM certs WHERE CAST(seen_at AS BIGINT) >= {today} \
             ) ORDER BY day DESC"
        ),
        "renewals" => format!(
            "SELECT t, CAST(SUM(CASE WHEN r = 'new' THEN n ELSE 0 END) AS BIGINT) AS new, \
               CAST(SUM(CASE WHEN r = 'name' THEN n ELSE 0 END) AS BIGINT) AS name_match, \
               CAST(SUM(CASE WHEN r = 'exact' THEN n ELSE 0 END) AS BIGINT) AS exact_match FROM ( \
               SELECT CAST(CAST(day AS TIMESTAMP) AS BIGINT) / 1000000000 AS t, renewal AS r, certs AS n FROM rollup_daily \
                 WHERE CAST(day AS TIMESTAMP) >= to_timestamp_millis({from}) \
               UNION ALL \
               SELECT CAST(date_trunc('hour', seen_at) AS BIGINT) / 1000 AS t, renewal AS r, 1 AS n FROM certs \
                 WHERE CAST(seen_at AS BIGINT) >= {today} \
             ) GROUP BY t ORDER BY t"
        ),
        "issuers" => composition("issuer_cn", "issuer_cn", from, today, hours),
        "tlds" => composition("tld", "tld", from, today, hours),
        "keys" => composition("key_type", "key_type", from, today, hours),
        "validity" => composition("validity_bucket", &validity_case(), from, today, hours),
        "san_dist" => format!(
            "SELECT k, certs, sans FROM (SELECT {} AS k, COUNT(*) AS certs, \
               CAST(SUM(san_count) AS BIGINT) AS sans, MIN(san_count) AS o FROM certs \
               WHERE CAST(seen_at AS BIGINT) >= {from} GROUP BY 1) ORDER BY o",
            san_case()
        ),
        "der_size" => format!(
            "SELECT k, certs, bytes FROM (SELECT {} AS k, COUNT(*) AS certs, \
               CAST(SUM(der_size) AS BIGINT) AS bytes, MIN(der_size) AS o FROM certs \
               WHERE CAST(seen_at AS BIGINT) >= {from} GROUP BY 1) ORDER BY o",
            size_case()
        ),
        "peaks" => format!(
            "SELECT {t}, approx_percentile_cont(entries / 60.0, 0.5) AS p50_per_sec, \
               approx_percentile_cont(entries / 60.0, 0.99) AS p99_per_sec, \
               CAST(MAX(peak_per_sec) AS DOUBLE) AS max_per_sec \
             FROM rollup_minute WHERE log_id = {GLOBAL} AND {range} GROUP BY 1 ORDER BY 1"
        ),
        "lag" => format!(
            "SELECT log_id, AVG(sct_lag_p50_ms) AS sct_p50_ms, MAX(sct_lag_p99_ms) AS sct_p99_ms, \
               AVG(nb_lag_p50_ms) AS not_before_p50_ms, MAX(nb_lag_p99_ms) AS not_before_p99_ms \
             FROM rollup_minute WHERE log_id <> {GLOBAL} AND sct_lag_p50_ms IS NOT NULL AND {range} \
             GROUP BY 1 ORDER BY 2 DESC"
        ),
        "concentration" => format!(
            "SELECT CAST(CAST(day AS TIMESTAMP) AS BIGINT) / 1000000000 AS t, \
               100.0 * SUM(CASE WHEN rank <= 10 THEN certs ELSE 0 END) / MAX(day_total) AS top_10_pct, \
               100.0 * SUM(CASE WHEN rank <= 100 THEN certs ELSE 0 END) / MAX(day_total) AS top_100_pct, \
               100.0 * SUM(certs) / MAX(day_total) AS top_1000_pct \
             FROM daily_top WHERE kind = 'domain' AND CAST(day AS TIMESTAMP) >= to_timestamp_millis({from}) \
             GROUP BY 1 ORDER BY 1"
        ),
        "coverage" => "SELECT n, log_id, added_certs, cumulative_certs, cumulative_pct FROM daily_coverage \
              WHERE day = (SELECT MAX(day) FROM daily_coverage) ORDER BY n"
            .to_string(),
        "state_growth" => format!(
            "SELECT {t}, CAST(MAX(tracker_names) AS DOUBLE) AS names FROM rollup_minute \
             WHERE log_id = {GLOBAL} AND {range} GROUP BY 1 ORDER BY 1"
        ),
        "resources" => format!(
            "SELECT {t}, CAST(MAX(rss_bytes) AS DOUBLE) AS memory_bytes, \
               CAST(MAX(disk_bytes) AS DOUBLE) AS disk_bytes, CAST(MAX(tracker_bytes) AS DOUBLE) AS tracker_bytes \
             FROM rollup_minute WHERE log_id = {GLOBAL} AND {range} GROUP BY 1 ORDER BY 1"
        ),
        "catchup" => format!(
            "SELECT a.log_id, a.fetched_per_sec, \
               GREATEST((a.entries + COALESCE(b.backlog_change, 0)) * 1.0 / a.span_s, 0.0) AS published_per_sec, \
               COALESCE(b.backlog_change, 0) AS backlog_change, a.problems FROM ( \
               SELECT log_id, CAST(SUM(entries) AS BIGINT) AS entries, GREATEST(COUNT(*) * 60.0, 1.0) AS span_s, \
                 CAST(SUM(entries) AS DOUBLE) / GREATEST(COUNT(*) * 60.0, 1.0) AS fetched_per_sec, \
                 CAST(SUM(errors + http_429 + malformed) AS BIGINT) AS problems \
               FROM rollup_minute WHERE log_id <> {GLOBAL} AND {range} GROUP BY 1 \
             ) a LEFT JOIN ( \
               SELECT log_id, last_value(backlog ORDER BY minute) - first_value(backlog ORDER BY minute) AS backlog_change \
               FROM rollup_minute WHERE log_id <> {GLOBAL} AND backlog IS NOT NULL AND {range} GROUP BY 1 \
             ) b ON a.log_id = b.log_id ORDER BY 2 DESC"
        ),
        "cost" => format!(
            "SELECT CAST(SUM(cpu_ms) AS DOUBLE) / 1000.0 / GREATEST(SUM(entries), 1) * 1000000.0 AS cpu_seconds_per_million, \
               MAX(disk_bytes) * 1000000.0 / GREATEST(SUM(entries), 1) AS disk_bytes_per_million, \
               MAX(tracker_bytes) * 1.0 / GREATEST(MAX(tracker_names), 1) AS tracker_bytes_per_name, \
               CAST(SUM(entries) AS BIGINT) AS unique_certs \
             FROM rollup_minute WHERE log_id = {GLOBAL} AND {range}"
        ),
        "settling" => format!(
            "SELECT t, per_sec AS never_seen_domains_per_sec, names_per_sec AS never_seen_names_per_sec FROM ( \
               SELECT CAST(CAST(day AS TIMESTAMP) AS BIGINT) / 1000000000 AS t, \
                 new_domains / 86400.0 AS per_sec, new_names / 86400.0 AS names_per_sec FROM daily_stages \
                 WHERE CAST(day AS TIMESTAMP) >= to_timestamp_millis({from}) \
               UNION ALL \
               SELECT CAST(date_trunc('hour', seen_at) AS BIGINT) / 1000 AS t, \
                 SUM(new_domains) / 3600.0 AS per_sec, SUM(new_names) / 3600.0 AS names_per_sec FROM certs \
                 WHERE CAST(seen_at AS BIGINT) >= {today} \
                   AND date_trunc('hour', seen_at) < date_trunc('hour', to_timestamp_millis({to})) \
                 GROUP BY 1 \
             ) ORDER BY t"
        ),
        "quality" => format!(
            "SELECT {t}, CAST(MAX(backlog) AS DOUBLE) AS backlog, CAST(MAX(limited_backlog) AS DOUBLE) AS rate_limited_backlog \
             FROM rollup_minute WHERE log_id = {GLOBAL} AND {range} GROUP BY 1 ORDER BY 1"
        ),
        "sizing" => format!(
            "SELECT COUNT(*) AS minutes, CAST(SUM(CASE WHEN {CLEAN} THEN 1 ELSE 0 END) AS BIGINT) AS clean_minutes, \
               CAST(MIN(minute) AS BIGINT) AS first_ms, CAST(MAX(minute) AS BIGINT) AS last_ms, \
               approx_percentile_cont(CASE WHEN {CLEAN} THEN entries / 60.0 END, 0.5) AS unique_p50, \
               approx_percentile_cont(CASE WHEN {CLEAN} THEN entries / 60.0 END, 0.99) AS unique_p99, \
               MAX(CASE WHEN {CLEAN} THEN peak_per_sec END) AS unique_max, \
               approx_percentile_cont(CASE WHEN {CLEAN} THEN raw_entries / 60.0 END, 0.5) AS raw_p50, \
               approx_percentile_cont(entries / 60.0, 0.5) AS unique_p50_all, \
               approx_percentile_cont(raw_entries / 60.0, 0.5) AS raw_p50_all, \
               MAX(backlog) AS backlog_max, MAX(healthy_logs) AS healthy_logs \
             FROM rollup_minute WHERE log_id = {GLOBAL} AND {range}"
        ),
        _ => return None,
    })
}

#[derive(Deserialize)]
pub struct TrendParams {
    hours: Option<i64>,
    bucket: Option<String>,
    format: Option<String>,
}

pub async fn trends(
    State(s): State<AppState>,
    Path(metric): Path<String>,
    Query(q): Query<TrendParams>,
) -> Response {
    let bucket = q.bucket.as_deref().unwrap_or("hour");
    if !["minute", "hour", "day"].contains(&bucket) {
        return error(StatusCode::BAD_REQUEST, "bucket must be minute, hour or day");
    }
    let now = Utc::now();
    let hours = q.hours.unwrap_or(48).clamp(1, 24 * 3650);
    let from = now - Duration::hours(hours);
    let today = now.date_naive().and_hms_opt(0, 0, 0).expect("midnight").and_utc();
    let (from_ms, to_ms, today_ms) =
        (from.timestamp_millis(), now.timestamp_millis(), today.timestamp_millis());
    let Some(sql) = trend_query(&metric, from_ms, to_ms, bucket, today_ms, hours) else {
        return error(StatusCode::NOT_FOUND, "unknown metric");
    };
    // Certificates come from the range for distributions and short ranges;
    // longer compositions need only the current day beside their rollups.
    let in_range = hours < DAY_HOURS || matches!(metric.as_str(), "san_dist" | "der_size");
    let certs_from = if in_range { from_ms } else { today_ms };
    match s.engine.internal(sql, ROWS, Some(certs_from), None).await {
        Ok(r) => respond(r, q.format.as_deref()),
        Err(e) => query_error(e),
    }
}

/// Tables and columns for the SQL page.
pub async fn schema() -> Json<serde_json::Value> {
    use crate::store::*;
    let t = |name: &str, s: arrow::datatypes::SchemaRef| {
        json!({ "name": name, "columns": s.fields().iter().map(|f| f.name().clone()).collect::<Vec<_>>() })
    };
    Json(json!([
        t("certs", certs_schema()),
        t("domains", domains_schema()),
        t("sightings", sightings_schema()),
        t("rollup_minute", rollup_minute_schema()),
        t("rollup_daily", rollup_daily_schema()),
        t("daily_stages", daily_stages_schema()),
        t("daily_top", daily_top_schema()),
        t("daily_coverage", daily_coverage_schema()),
        t("dns", dns_schema()),
        t("dns_minute", dns_minute_schema()),
    ]))
}
