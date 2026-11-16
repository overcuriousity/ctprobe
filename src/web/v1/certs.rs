//! `GET /api/v1/certs`: certificates of a domain or of fuzzy search hits,
//! from both tiers.

use super::error::ApiError;
use super::input::{self, Params};
use crate::query::{Bound, CertCursor, Mode, TierFilter, TierPage};
use crate::web::AppState;
use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use std::time::Instant;

/// Domain hits a fuzzy scope looks up.
const MAX_HITS: usize = 100;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CertsParams {
    domain: Option<String>,
    q: Option<String>,
    mode: Option<String>,
    distance: Option<u8>,
    from: Option<String>,
    to: Option<String>,
    expires_from: Option<String>,
    expires_to: Option<String>,
    issuer: Option<String>,
    issuer_contains: Option<String>,
    tld: Option<String>,
    wildcard: Option<bool>,
    limit: Option<usize>,
    cursor: Option<String>,
}

enum Scope {
    /// A name and its registered domain.
    Domain(String, String),
    Fuzzy(String, Mode),
}

fn text(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub(super) async fn certs(State(s): State<AppState>, Params(p): Params<CertsParams>) -> Result<Json<TierPage>, ApiError> {
    // One time limit for the whole request, search included.
    let deadline = Instant::now() + s.engine.timeout();
    let scope = match (p.domain.as_deref(), p.q.as_deref()) {
        (Some(d), None) => {
            if p.mode.is_some() || p.distance.is_some() {
                return Err(ApiError::BadRequest("mode and distance apply to q only".into()));
            }
            let (name, reg) = input::domain(d)?;
            Scope::Domain(name, reg)
        }
        (None, Some(q)) => {
            let q = input::q(Some(q))?.to_string();
            Scope::Fuzzy(q, input::mode(p.mode.as_deref(), p.distance)?)
        }
        _ => return Err(ApiError::BadRequest("exactly one of domain or q is required".into())),
    };
    let f = TierFilter {
        from_ms: input::when(p.from.as_deref(), false, "from")?,
        to_ms: input::when(p.to.as_deref(), true, "to")?,
        expires_from_ms: input::when(p.expires_from.as_deref(), false, "expires_from")?,
        expires_to_ms: input::when(p.expires_to.as_deref(), true, "expires_to")?,
        issuer: text(p.issuer),
        issuer_contains: text(p.issuer_contains),
        tld: text(p.tld).map(|t| t.to_lowercase()),
        wildcard: p.wildcard,
    };
    let limit = input::limit(p.limit)?;
    let after = match text(p.cursor) {
        None => None,
        Some(c) => Some(CertCursor::decode(&c).ok_or_else(|| ApiError::BadRequest("malformed cursor".into()))?),
    };
    let _permits = s.v1.enter(s.engine.has_cert_archive())?;
    // The index's first and last sightings bound the days the walk reads.
    let (domains, exact, hits) = match scope {
        Scope::Domain(name, reg) => {
            let hits = s.engine.search_domains_until(&reg, Mode::Exact, 1, deadline).await?;
            let hits: Vec<_> = hits.into_iter().filter(|h| h.domain == reg).collect();
            let exact = (name != reg).then_some(name);
            (vec![reg], exact, hits)
        }
        Scope::Fuzzy(q, mode) => {
            let hits = s.engine.search_domains_until(&q, mode, MAX_HITS, deadline).await?;
            (hits.iter().map(|h| h.domain.clone()).collect(), None, hits)
        }
    };
    let bound = Bound::certs(&hits);
    Ok(Json(s.engine.tier_certs(&domains, exact.as_deref(), &f, limit, after, &bound, deadline).await?))
}
