//! `GET /api/v1/domain/{domain}`: a registered domain's summary from the
//! permanent index and its address history from both tiers.

use super::error::ApiError;
use super::input::{self, Params};
use crate::query::{DnsCursor, Mode, QueryError};
use crate::web::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Instant;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DomainParams {
    limit: Option<usize>,
    cursor: Option<String>,
}

pub(super) async fn domain(
    State(s): State<AppState>,
    Path(raw): Path<String>,
    Params(p): Params<DomainParams>,
) -> Result<Json<Value>, ApiError> {
    // One time limit for the whole request, summary included.
    let deadline = Instant::now() + s.engine.timeout();
    let (_, reg) = input::domain(&raw)?;
    let limit = input::limit(p.limit)?;
    let cursor = p.cursor.as_deref().map(str::trim).filter(|c| !c.is_empty());
    let after = match cursor {
        None => None,
        Some(c) => Some(DnsCursor::decode(c).ok_or_else(|| ApiError::BadRequest("malformed cursor".into()))?),
    };
    let _permits = s.v1.enter(s.engine.has_dns_archive())?;
    let hit = s.engine.search_domains_until(&reg, Mode::Exact, 1, deadline).await?.into_iter().find(|h| h.domain == reg);
    // With the summary in hand, a walk that finds nothing in time still answers.
    let (rows, next_cursor, cut_short) = match s.engine.tier_dns(&reg, limit, after.clone(), deadline).await {
        Ok(page) => (page.rows, page.next_cursor, page.cut_short),
        Err(QueryError::Timeout) if hit.is_some() => (vec![], cursor.map(str::to_string), true),
        Err(e) => return Err(e.into()),
    };
    if hit.is_none() && rows.is_empty() && after.is_none() {
        return Err(ApiError::NotFound(format!("no data for {reg}")));
    }
    Ok(Json(json!({
        "domain": reg,
        "first_seen": hit.as_ref().map(|h| h.first_seen_ms),
        "last_seen": hit.as_ref().map(|h| h.last_seen_ms),
        "cert_count": hit.as_ref().map(|h| h.cert_count),
        "dns": { "rows": rows, "next_cursor": next_cursor, "cut_short": cut_short },
    })))
}
