//! Parsing and validation of `/api/v1` query parameters. Nothing is clamped:
//! a value out of range is a 400.

use super::error::ApiError;
use crate::names;
use crate::query::Mode;
use axum::extract::{FromRequestParts, Query};
use axum::http::request::Parts;
use chrono::{DateTime, NaiveDate};
use serde::de::DeserializeOwned;

const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

/// `Query<T>` whose rejection is an [`ApiError`].
pub struct Params<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for Params<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(t)| Params(t))
            .map_err(|e| ApiError::BadRequest(e.body_text()))
    }
}

/// A domain name and its registered domain, both normalised. A leading `*.` is dropped.
#[allow(dead_code)] // used by the certs endpoint
pub fn domain(raw: &str) -> Result<(String, String), ApiError> {
    let bad = || ApiError::BadRequest(format!("not a valid domain name: {raw:?}"));
    let name = names::normalize(raw).ok_or_else(bad)?;
    let name = name.strip_prefix("*.").unwrap_or(&name).to_string();
    let reg = names::registered_domain(&name).ok_or_else(bad)?;
    Ok((name, reg))
}

pub fn limit(v: Option<usize>) -> Result<usize, ApiError> {
    match v {
        None => Ok(DEFAULT_LIMIT),
        Some(n) if (1..=MAX_LIMIT).contains(&n) => Ok(n),
        Some(_) => Err(ApiError::BadRequest(format!("limit must be between 1 and {MAX_LIMIT}"))),
    }
}

/// A date (`YYYY-MM-DD`, UTC) or an RFC 3339 time as milliseconds since the
/// epoch. A bare date means its first millisecond, or with `end` its last.
#[allow(dead_code)] // used by the certs endpoint
pub fn when(v: Option<&str>, end: bool, name: &str) -> Result<Option<i64>, ApiError> {
    let Some(s) = v else { return Ok(None) };
    let bad = || ApiError::BadRequest(format!("{name} must be YYYY-MM-DD or an RFC 3339 time"));
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let start = d.and_hms_opt(0, 0, 0).ok_or_else(bad)?.and_utc().timestamp_millis();
        return Ok(Some(if end { start + 86_400_000 - 1 } else { start }));
    }
    DateTime::parse_from_rfc3339(s).map(|t| Some(t.timestamp_millis())).map_err(|_| bad())
}

pub fn mode(mode: Option<&str>, distance: Option<u8>) -> Result<Mode, ApiError> {
    let m = mode.unwrap_or("exact");
    if distance.is_some() && m != "levenshtein" {
        return Err(ApiError::BadRequest("distance applies to mode levenshtein only".into()));
    }
    match m {
        "exact" => Ok(Mode::Exact),
        "contains" => Ok(Mode::Contains),
        "homoglyph" => Ok(Mode::Homoglyph),
        "levenshtein" => match distance.unwrap_or(1) {
            d @ (1 | 2) => Ok(Mode::Levenshtein(d)),
            _ => Err(ApiError::BadRequest("distance must be 1 or 2".into())),
        },
        other => Err(ApiError::BadRequest(format!("unknown mode {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_normalises() {
        assert_eq!(domain("WWW.Example.COM.").unwrap(), ("www.example.com".into(), "example.com".into()));
        assert_eq!(domain("*.example.com").unwrap(), ("example.com".into(), "example.com".into()));
        assert_eq!(domain("bücher.de").unwrap(), ("xn--bcher-kva.de".into(), "xn--bcher-kva.de".into()));
    }

    #[test]
    fn domain_rejects() {
        let long = format!("{}.com", "a".repeat(296));
        for s in ["", "1.2.3.4", "a'b.com", "com", long.as_str()] {
            assert!(matches!(domain(s), Err(ApiError::BadRequest(_))), "{s:?}");
        }
    }

    #[test]
    fn limit_and_mode_and_when() {
        assert_eq!(limit(None).unwrap(), 100);
        assert!(limit(Some(0)).is_err() && limit(Some(1001)).is_err());
        assert!(limit(Some(1)).is_ok() && limit(Some(1000)).is_ok());
        assert!(matches!(mode(Some("levenshtein"), Some(2)), Ok(Mode::Levenshtein(2))));
        assert!(mode(Some("levenshtein"), Some(3)).is_err());
        assert!(mode(Some("exact"), Some(1)).is_err());
        assert!(mode(Some("x"), None).is_err());
        assert_eq!(when(Some("1970-01-02"), false, "from").unwrap(), Some(86_400_000));
        assert_eq!(when(Some("1970-01-01"), true, "to").unwrap(), Some(86_399_999));
        assert_eq!(when(Some("1970-01-01T00:00:01Z"), false, "from").unwrap(), Some(1000));
        assert!(when(Some("yesterday"), false, "from").is_err());
        assert_eq!(when(None, false, "from").unwrap(), None);
    }
}
