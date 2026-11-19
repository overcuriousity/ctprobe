//! `/api/v1`: a stable JSON API with a uniform error body and load limits.

mod certs;
mod domain;
pub mod error;
pub mod input;
mod ip;

use super::AppState;
use axum::extract::State;
use axum::http::Uri;
use axum::routing::get;
use axum::{Json, Router};
use error::ApiError;
use input::Params;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Requests allowed in flight across all of v1.
const ALL_PERMITS: usize = 2;
/// Of those, requests that read the archive.
const ARCHIVE_PERMITS: usize = 1;

/// Admission control for v1. Requests that find no permit fail at once with
/// 429; they never queue.
pub struct Gate {
    all: Arc<Semaphore>,
    archive: Arc<Semaphore>,
}

/// Held for the life of a request; releases its permits on drop.
pub struct Permits {
    _all: OwnedSemaphorePermit,
    _archive: Option<OwnedSemaphorePermit>,
}

impl Gate {
    pub fn new() -> Gate {
        Gate { all: Arc::new(Semaphore::new(ALL_PERMITS)), archive: Arc::new(Semaphore::new(ARCHIVE_PERMITS)) }
    }

    pub fn enter(&self, archive: bool) -> Result<Permits, ApiError> {
        let all = self.all.clone().try_acquire_owned().map_err(|_| ApiError::Busy)?;
        let archive =
            if archive { Some(self.archive.clone().try_acquire_owned().map_err(|_| ApiError::Busy)?) } else { None };
        Ok(Permits { _all: all, _archive: archive })
    }
}

impl Default for Gate {
    fn default() -> Self {
        Gate::new()
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/search", get(search))
        .route("/certs", get(certs::certs))
        .route("/domain/{domain}", get(domain::domain))
        .route("/ip/{ip}", get(ip::ip))
        .method_not_allowed_fallback(not_found)
        .fallback(not_found)
}

async fn not_found(uri: Uri) -> ApiError {
    ApiError::NotFound(format!("no such endpoint: {}", uri.path()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchParams {
    q: Option<String>,
    mode: Option<String>,
    distance: Option<u8>,
    limit: Option<usize>,
}

async fn search(State(s): State<AppState>, Params(p): Params<SearchParams>) -> Result<Json<Value>, ApiError> {
    let q = input::q(p.q.as_deref())?;
    let mode = input::mode(p.mode.as_deref(), p.distance)?;
    let limit = input::limit(p.limit)?;
    // Search reads the permanent index, not the archive.
    let _permits = s.v1.enter(false)?;
    let hits = s.engine.search_domains(q, mode, limit).await?;
    Ok(Json(json!({ "hits": hits })))
}
