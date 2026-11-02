use super::{csv, AppState};
use crate::fetch::{fetch_entry, FetchError};
use crate::parse::extract;
use crate::query::{quote, CertFilter, CertScope, Mode, QueryError, QueryResult, SortKey, MAX_OFFSET};
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
    Json(json!({
        "domain": d, "hit": hit, "issuers": issuers, "names": names, "days": days, "similar": similar,
    }))
    .into_response()
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
        "is_precert": entry.is_precert,
        "timestamp_ms": entry.timestamp_ms,
        "parsed": parsed,
        "pem": format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"),
    }))
    .into_response()
}
