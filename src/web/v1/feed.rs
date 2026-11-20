//! `GET /api/v1/feed`: every certificate with at least one name ctprobe had
//! not seen, oldest first, from a position the client keeps.

use super::error::ApiError;
use super::input::Params;
use crate::query::{FeedCursor, FeedPage};
use crate::web::AppState;
use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use std::sync::atomic::Ordering;

const DEFAULT_LIMIT: usize = 1000;
const MAX_LIMIT: usize = 10_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FeedParams {
    /// `next_cursor` of the page before; without it the feed starts at
    /// `final_through`.
    after: Option<String>,
    limit: Option<usize>,
}

pub(super) async fn feed(State(s): State<AppState>, Params(p): Params<FeedParams>) -> Result<Json<FeedPage>, ApiError> {
    let limit = match p.limit {
        None => DEFAULT_LIMIT,
        Some(n) if (1..=MAX_LIMIT).contains(&n) => n,
        Some(_) => return Err(ApiError::BadRequest(format!("limit must be between 1 and {MAX_LIMIT}"))),
    };
    // Read before any file is listed: files published later only hold
    // certificates after this time.
    let final_through = s.pipe.live.final_through_ms.load(Ordering::Acquire);
    let after = match p.after.as_deref().map(str::trim).filter(|a| !a.is_empty()) {
        None => FeedCursor::end_of(final_through),
        Some(a) => FeedCursor::parse(a).ok_or_else(|| {
            ApiError::BadRequest("after must be <seen_at_ms>.<log_id>.<entry_index>, as next_cursor gives it".into())
        })?,
    };
    let _permit = s.v1.enter_feed()?;
    Ok(Json(s.engine.feed(after, limit, final_through).await?))
}
