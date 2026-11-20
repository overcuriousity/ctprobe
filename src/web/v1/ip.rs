//! `GET /api/v1/ip/{ip}`: the registered domains whose names resolved to an
//! address, in name order, from the address index.

use super::error::ApiError;
use super::input::{self, Params, Segment};
use crate::web::AppState;
use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::IpAddr;

const MS_PER_DAY: i64 = 86_400_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IpParams {
    limit: Option<usize>,
    /// The last domain of the page before.
    cursor: Option<String>,
}

pub(super) async fn ip(
    State(s): State<AppState>,
    Segment(raw): Segment<String>,
    Params(p): Params<IpParams>,
) -> Result<Json<Value>, ApiError> {
    let ip: IpAddr = raw.trim().parse().map_err(|_| ApiError::BadRequest("not an IP address".into()))?;
    // An IPv4 address written as IPv6 is the same address.
    let ip = match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    let limit = input::limit(p.limit)?;
    let after = p.cursor.map(|c| c.trim().to_lowercase()).filter(|c| !c.is_empty());
    let _permits = s.v1.enter(false)?;
    let index = s.pipe.ips.clone();
    let mut hits = tokio::task::spawn_blocking(move || index.lookup(ip, after.as_deref(), limit + 1))
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|e| ApiError::Internal(format!("{e:#}")))?;
    let more = hits.len() > limit;
    hits.truncate(limit);
    let next_cursor = more.then(|| hits.last().map(|h| h.domain.clone())).flatten();
    let rows: Vec<Value> = hits
        .iter()
        .map(|h| {
            json!({
                "domain": h.domain,
                "first_seen": h.first_day as i64 * MS_PER_DAY,
                "last_seen": h.last_day as i64 * MS_PER_DAY,
            })
        })
        .collect();
    Ok(Json(json!({ "ip": ip.to_string(), "rows": rows, "next_cursor": next_cursor })))
}
