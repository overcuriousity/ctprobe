//! The uniform error body of `/api/v1`: `{"error":{"code","message"}}`.

use crate::query::QueryError;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    Busy,
    Timeout,
    Internal(String),
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m.clone()),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", m.clone()),
            ApiError::Busy => (StatusCode::TOO_MANY_REQUESTS, "busy", "too many requests in flight".into()),
            ApiError::Timeout => (StatusCode::GATEWAY_TIMEOUT, "timeout", "the query timed out".into()),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, "internal", m.clone()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = self.parts();
        let mut resp = (status, Json(json!({ "error": { "code": code, "message": message } }))).into_response();
        if matches!(self, ApiError::Busy) {
            resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        resp
    }
}

impl From<QueryError> for ApiError {
    fn from(e: QueryError) -> Self {
        match e {
            QueryError::Timeout => ApiError::Timeout,
            QueryError::NotAllowed(m) => ApiError::BadRequest(m),
            QueryError::Failed(m) => ApiError::Internal(m),
        }
    }
}
