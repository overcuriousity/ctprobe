use super::{csv, AppState};
use crate::fetch::{fetch_entry, FetchError};
use crate::parse::extract;
use crate::query::{quote, CertFilter, CertScope, DnsFilter, Mode, QueryError, QueryResult, SortKey, MAX_OFFSET};
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use chrono::NaiveDate;
use serde::Deserialize;
use serde_json::json;

const DEFAULT_LIMIT: usize = 500;
/// Rows on one page of certificate results.
const PAGE: usize = 100;
const MAX_LIMIT: usize = 100_000;

pub fn error(code: StatusCode, msg: impl ToString) -> Response {
    (code, Json(json!({ "error": msg.to_string() }))).into_response()
}

pub fn query_error(e: QueryError) -> Response {
    let code = match e {
        QueryError::NotAllowed(_) => StatusCode::BAD_REQUEST,
        QueryError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        QueryError::Failed(_) => StatusCode::BAD_REQUEST,
    };
    error(code, e)
}

pub fn respond(r: QueryResult, format: Option<&str>) -> Response {
    if format == Some("csv") {
        return (
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"ctprobe.csv\""),
            ],
            csv::to_csv(&r),
        )
            .into_response();
    }
    Json(r).into_response()
}

fn limit(l: Option<usize>) -> usize {
    l.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

pub async fn live(State(s): State<AppState>) -> Response {
    Json(s.pipe.live.snapshot()).into_response()
}

/// DNS probing figures since start, or `enabled: false` when it is off.
pub async fn dns(State(s): State<AppState>) -> Response {
    match &s.pipe.dns {
        Some(d) => Json(d.report()).into_response(),
        None => Json(json!({ "enabled": false })).into_response(),
    }
}

pub async fn logs(State(s): State<AppState>) -> Response {
    Json(s.pipe.live.logs_report()).into_response()
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    minutes: Option<u32>,
}

pub async fn history(State(s): State<AppState>, Query(q): Query<HistoryQuery>) -> Response {
    let now = chrono::Utc::now().timestamp();
    let view = s.pipe.live.history.lock().unwrap().view(q.minutes.unwrap_or(15), now);
    Json(view).into_response()
}

#[derive(Deserialize)]
pub struct SqlQuery {
    q: String,
    limit: Option<usize>,
    format: Option<String>,
}

pub async fn sql(State(s): State<AppState>, Query(q): Query<SqlQuery>) -> Response {
    match s.engine.sql(&q.q, limit(q.limit)).await {
        Ok(r) => respond(r, q.format.as_deref()),
        Err(e) => query_error(e),
    }
}

#[derive(Deserialize)]
pub struct SearchQuery {
    q: String,
    mode: Option<String>,
    distance: Option<u8>,
    limit: Option<usize>,
}

pub async fn search(State(s): State<AppState>, Query(q): Query<SearchQuery>) -> Response {
    let mode = match q.mode.as_deref().unwrap_or("exact") {
        "exact" => Mode::Exact,
        "contains" => Mode::Contains,
        "levenshtein" => Mode::Levenshtein(q.distance.unwrap_or(1).clamp(1, 2)),
        "homoglyph" => Mode::Homoglyph,
        other => return error(StatusCode::BAD_REQUEST, format!("unknown mode {other}")),
    };
    if q.q.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "empty query");
    }
    match s.engine.search_domains(&q.q, mode, limit(q.limit).min(5000)).await {
        Ok(hits) => Json(hits).into_response(),
        Err(e) => query_error(e),
    }
}

#[derive(Deserialize)]
pub struct CertsQuery {
    domain: Option<String>,
    pattern: Option<String>,
    from: Option<String>,
    to: Option<String>,
    random: Option<usize>,
    limit: Option<usize>,
    format: Option<String>,
    issuer: Option<String>,
    renewal: Option<String>,
    wildcard: Option<bool>,
    tld: Option<String>,
    key_type: Option<String>,
    validity: Option<String>,
    san: Option<String>,
    size: Option<String>,
    issuer_contains: Option<String>,
    expires_from: Option<String>,
    expires_to: Option<String>,
    precert: Option<bool>,
    dns: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
    offset: Option<usize>,
}

/// A time given as a date or in milliseconds. A date as an end means its last moment.
fn parse_when(s: &str, end: bool) -> Option<i64> {
    if let Ok(ms) = s.parse::<i64>() {
        return Some(ms);
    }
    let d = NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
    let t = d.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis();
    Some(if end { t + 86_399_999 } else { t })
}

fn when(v: Option<String>, end: bool, name: &str) -> Result<Option<i64>, Response> {
    match v.filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => parse_when(&s, end)
            .map(Some)
            .ok_or_else(|| error(StatusCode::BAD_REQUEST, format!("{name} must be a date or milliseconds"))),
    }
}

pub async fn certs(State(s): State<AppState>, Query(q): Query<CertsQuery>) -> Response {
    let some = |v: Option<String>| v.filter(|s| !s.is_empty());
    let scope = match (some(q.domain), some(q.pattern)) {
        (Some(d), None) => CertScope::Domain(d.to_lowercase()),
        (None, Some(p)) => CertScope::Pattern(p),
        (None, None) => CertScope::All,
        _ => return error(StatusCode::BAD_REQUEST, "give at most one of domain or pattern"),
    };
    let sort = match q.sort.as_deref().filter(|s| !s.is_empty()) {
        None => SortKey::default(),
        Some(s) => match SortKey::parse(s) {
            Some(k) => k,
            None => return error(StatusCode::BAD_REQUEST, "unknown sort column"),
        },
    };
    let asc = match q.dir.as_deref() {
        None | Some("") | Some("desc") => false,
        Some("asc") => true,
        Some(_) => return error(StatusCode::BAD_REQUEST, "dir must be asc or desc"),
    };
    let dns = match q.dns.as_deref().filter(|s| !s.is_empty()) {
        None => None,
        Some(s) => match DnsFilter::parse(s) {
            Some(d) => Some(d),
            None => return error(StatusCode::BAD_REQUEST, "dns must be address, no_address or ip_changed"),
        },
    };
    let offset = q.offset.unwrap_or(0);
    if offset > MAX_OFFSET {
        return error(StatusCode::BAD_REQUEST, format!("offset cannot pass {MAX_OFFSET}"));
    }
    let csv = q.format.as_deref() == Some("csv");
    let parsed = (|| {
        Ok::<_, Response>((
            when(q.from, false, "from")?,
            when(q.to, true, "to")?,
            when(q.expires_from, false, "expires_from")?,
            when(q.expires_to, true, "expires_to")?,
        ))
    })();
    let (from_ms, to_ms, expires_from_ms, expires_to_ms) = match parsed {
        Ok(p) => p,
        Err(r) => return r,
    };
    let mut f = CertFilter {
        from_ms,
        to_ms,
        random_n: q.random.map(|n| n.clamp(1, MAX_LIMIT)),
        limit: if csv { limit(q.limit) } else { q.limit.unwrap_or(PAGE).clamp(1, MAX_LIMIT) },
        issuer: some(q.issuer),
        renewal: some(q.renewal),
        wildcard: q.wildcard,
        tld: some(q.tld),
        key_type: some(q.key_type),
        validity: some(q.validity),
        san: some(q.san),
        size: some(q.size),
        issuer_contains: some(q.issuer_contains),
        expires_from_ms,
        expires_to_ms,
        precert: q.precert,
        dns,
        sort,
        asc,
        offset,
    };
    if let CertScope::All = scope {
        if !f.narrows() {
            return error(StatusCode::BAD_REQUEST, "give a domain, a pattern or a filter");
        }
        // An unscoped search reads whole files, so it needs a bound.
        if f.from_ms.is_none() && f.to_ms.is_none() {
            f.from_ms = Some(chrono::Utc::now().timestamp_millis() - 86_400_000);
        }
    }
    match s.engine.certs_page(scope, f).await {
        Ok(p) if csv => respond(p.result, Some("csv")),
        Ok(p) => Json(p).into_response(),
        Err(e) => query_error(e),
    }
}

#[derive(Deserialize)]
pub struct DomainQuery {
    d: String,
}

/// Everything known about one registered domain.
pub async fn domain(State(s): State<AppState>, Query(q): Query<DomainQuery>) -> Response {
    let d = q.d.trim().to_lowercase();
    if d.is_empty() {
        return error(StatusCode::BAD_REQUEST, "empty domain");
    }
    let lit = quote(&d);
    let sqls = [
        format!(
            "SELECT issuer_cn, COUNT(*) AS certs FROM certs WHERE primary_domain = {lit} \
             GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 15"
        ),
        format!(
            "SELECT n, COUNT(*) AS certs FROM (SELECT unnest(names) AS n FROM certs \
             WHERE primary_domain = {lit}) GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 200"
        ),
        format!(
            "SELECT CAST(date_trunc('day', seen_at) AS BIGINT) / 1000 AS t, COUNT(*) AS certs \
             FROM certs WHERE primary_domain = {lit} GROUP BY 1 ORDER BY 1"
        ),
    ];
    let mut parts = Vec::new();
    for q in sqls {
        match s.engine.internal(q, 1000, None, None).await {
            Ok(r) => parts.push(r),
            Err(e) => return query_error(e),
        }
    }
    let hit = s.engine.search_domains(&d, Mode::Exact, 1).await.ok().and_then(|mut h| h.pop());
    // Lookalikes under any TLD, then visual ones. A scan past the timeout only
    // costs this section, so the rest of the page still renders.
    let label = d.split('.').next().unwrap_or(&d).to_string();
    let mut similar = s.engine.search_domains(&label, Mode::Levenshtein(1), 25).await.unwrap_or_default();
    similar.extend(s.engine.search_domains(&d, Mode::Homoglyph, 25).await.unwrap_or_default());
    similar.retain(|h| h.domain != d);
    similar.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.domain.cmp(&b.domain)));
    similar.dedup_by(|a, b| a.domain == b.domain);
    similar.truncate(25);
    let days = parts.pop();
    let names = parts.pop();
    let issuers = parts.pop();
    // DNS is optional here: a slow scan costs only this section.
    let dns_names = s.engine.internal(
        format!(
            "SELECT name, last_value(status ORDER BY probed_at) AS status, \
               last_value(v4 ORDER BY probed_at) AS v4, last_value(v6 ORDER BY probed_at) AS v6, \
               CAST(MIN(CASE WHEN status = 'resolved' THEN probed_at END) AS BIGINT) AS first_address_ms, \
               CAST(MAX(probed_at) AS BIGINT) AS last_probe_ms, \
               CAST(SUM(CASE WHEN attempt = 0 AND prev_days > 0 AND (v4_changed OR v6_changed) \
                 THEN 1 ELSE 0 END) AS BIGINT) AS ip_changes \
             FROM dns WHERE reg_domain = {lit} AND kind = 'name' GROUP BY name ORDER BY name LIMIT 500"
        ),
        500,
        None,
        None,
    );
    let dns_changes = s.engine.internal(
        format!(
            "SELECT CAST(probed_at AS BIGINT) AS t, name, prev_days, prev_status, status, \
               prev_v4, v4, prev_v6, v6 \
             FROM dns WHERE reg_domain = {lit} AND attempt = 0 AND changed \
             ORDER BY probed_at DESC LIMIT 100"
        ),
        100,
        None,
        None,
    );
    let (dns_names, dns_changes) = (dns_names.await, dns_changes.await);
    let dns_error = dns_names.as_ref().err().or(dns_changes.as_ref().err()).map(|e| e.to_string());
    Json(json!({
        "domain": d, "hit": hit, "issuers": issuers, "names": names, "days": days, "similar": similar,
        "dns_enabled": s.pipe.dns.is_some(),
        "dns_names": dns_names.ok(), "dns_changes": dns_changes.ok(), "dns_error": dns_error,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct CertDnsQuery {
    hash: String,
    /// When the certificate was logged, which bounds the days to read.
    at: i64,
    /// The certificate's names, for those probed for another certificate.
    names: Option<String>,
}

const MAX_CERT_NAMES: usize = 200;

/// DNS probes of one certificate's names: those made for it, and the latest
/// answer for names that were already being probed for another certificate.
pub async fn cert_dns(State(s): State<AppState>, Query(q): Query<CertDnsQuery>) -> Response {
    let Ok(hash) = q.hash.parse::<u64>() else {
        return error(StatusCode::BAD_REQUEST, "hash must be an unsigned 64-bit number");
    };
    const DAY: i64 = 86_400_000;
    // Probes start when the certificate is seen, which follows its log
    // timestamp within the log's merge delay, and run for 30 days. A
    // timestamp in the future cannot be right, so it counts as now.
    let at = q.at.min(chrono::Utc::now().timestamp_millis());
    let (from, to) = (at - 2 * DAY, at + 31 * DAY);
    let own = s.engine.internal(
        format!(
            "SELECT name, kind, attempt, status, v4, v6, cnames, CAST(probed_at AS BIGINT) AS probed_ms, \
               CAST(cert_seen_at AS BIGINT) AS seen_ms, prev_days, prev_status, prev_v4, prev_v6, \
               changed, v4_changed, v6_changed, network_changed \
             FROM dns WHERE cert_hash = CAST('{hash}' AS BIGINT UNSIGNED) ORDER BY name, kind, attempt"
        ),
        5000,
        Some(from),
        Some(to),
    );
    let names: Vec<String> = q
        .names
        .unwrap_or_default()
        .split(',')
        .map(|n| n.trim().to_lowercase())
        .filter(|n| !n.is_empty() && !n.starts_with("*."))
        .take(MAX_CERT_NAMES)
        .collect();
    let mut domains: Vec<String> = names.iter().filter_map(|n| crate::names::registered_domain(n)).collect();
    domains.sort();
    domains.dedup();
    let latest = if names.is_empty() || domains.is_empty() {
        None
    } else {
        let list = |v: &[String]| v.iter().map(|x| quote(x)).collect::<Vec<_>>().join(", ");
        // The registered domain first, so sorted and filtered files skip most rows.
        Some(s.engine.internal(
            format!(
                "SELECT name, last_value(status ORDER BY probed_at) AS status, \
                   last_value(v4 ORDER BY probed_at) AS v4, last_value(v6 ORDER BY probed_at) AS v6, \
                   CAST(MAX(probed_at) AS BIGINT) AS probed_ms \
                 FROM dns WHERE reg_domain IN ({}) AND name IN ({}) AND kind = 'name' GROUP BY name",
                list(&domains),
                list(&names)
            ),
            MAX_CERT_NAMES,
            Some(from),
            Some(to),
        ))
    };
    let own = match own.await {
        Ok(r) => r,
        Err(e) => return query_error(e),
    };
    let latest = match latest {
        Some(f) => f.await.ok(),
        None => None,
    };
    Json(json!({ "enabled": s.pipe.dns.is_some(), "probes": own, "latest": latest })).into_response()
}

pub async fn cert(State(s): State<AppState>, Path((log, index)): Path<(u16, u64)>) -> Response {
    let Some(info) = s.pipe.registry.get(log) else {
        return error(StatusCode::NOT_FOUND, "unknown log");
    };
    let entry = match fetch_entry(&info, s.client.clone(), index).await {
        Ok(e) => e,
        Err(FetchError::NotReady) => return error(StatusCode::NOT_FOUND, "entry not available"),
        Err(e) => return error(StatusCode::BAD_GATEWAY, e),
    };
    let parsed = match extract(&entry) {
        Ok(p) => p,
        Err(e) => return error(StatusCode::UNPROCESSABLE_ENTITY, e),
    };
    let label = if entry.is_precert { "TBS CERTIFICATE" } else { "CERTIFICATE" };
    let b64 = base64::engine::general_purpose::STANDARD.encode(&entry.tbs_or_cert);
    let body = b64.as_bytes().chunks(64).map(|c| String::from_utf8_lossy(c)).collect::<Vec<_>>().join("\n");
    Json(json!({
        "log": info.name,
        "index": index,
        // As a string: JavaScript numbers cannot hold every 64-bit value.
        "cert_hash": crate::tracker::cert_hash(&parsed).to_string(),
        "is_precert": entry.is_precert,
        "timestamp_ms": entry.timestamp_ms,
        "parsed": parsed,
        "pem": format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"),
    }))
    .into_response()
}
