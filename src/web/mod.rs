//! HTTP layer: pages are static shells, and all data arrives as JSON or SSE and
//! is rendered with `textContent`, so certificate fields cannot become markup.

pub mod api;
pub mod csv;
mod sse;
pub mod trends;
mod v1;

use crate::pipeline::PipelineHandle;
use crate::query::QueryEngine;
use axum::extract::{Path, RawQuery};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rust_embed::RustEmbed;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, OnceLock};
use tower_http::set_header::SetResponseHeaderLayer;

pub const MAX_SSE_CLIENTS: usize = 100;
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
                   font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

#[derive(RustEmbed)]
#[folder = "assets/"]
struct Assets;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<QueryEngine>,
    pub pipe: PipelineHandle,
    pub client: reqwest::Client,
    pub sse_clients: Arc<AtomicUsize>,
    pub v1: Arc<v1::Gate>,
}

impl AppState {
    pub fn new(engine: Arc<QueryEngine>, pipe: PipelineHandle) -> AppState {
        let client =
            crate::http::client_builder().timeout(std::time::Duration::from_secs(20)).build().expect("HTTP client");
        AppState { engine, pipe, client, sse_clients: Arc::new(AtomicUsize::new(0)), v1: Arc::new(v1::Gate::new()) }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Changes whenever any embedded file does, so versioned URLs can be cached for good.
fn assets_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        let mut all = Vec::new();
        for name in Assets::iter() {
            if let Some(f) = Assets::get(&name) {
                all.extend_from_slice(&f.metadata.sha256_hash());
            }
        }
        format!("{:016x}", xxhash_rust::xxh3::xxh3_64(&all))
    })
}

fn page(name: &str, title: &str) -> Response {
    let layout = Assets::get("layout.html").expect("embedded layout");
    let body = Assets::get(&format!("{name}.html")).expect("embedded page");
    let html = String::from_utf8_lossy(&layout.data)
        .replace("{{title}}", title)
        .replace("{{page}}", name)
        .replace("{{v}}", assets_version())
        .replace("{{body}}", &String::from_utf8_lossy(&body.data));
    ([(header::CACHE_CONTROL, "no-cache")], Html(html)).into_response()
}

async fn asset(Path(path): Path<String>, RawQuery(query): RawQuery, headers: HeaderMap) -> Response {
    let Some(f) = Assets::get(&path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let etag = format!("\"{}\"", hex(&f.metadata.sha256_hash()[..12]));
    // Only a URL that names the version may be kept without asking again.
    let versioned = query.is_some_and(|q| q == format!("v={}", assets_version()));
    let cache = if versioned { IMMUTABLE } else { "no-cache" };
    if headers.get(header::IF_NONE_MATCH).is_some_and(|v| v.as_bytes() == etag.as_bytes()) {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag), (header::CACHE_CONTROL, cache.into())])
            .into_response();
    }
    let mime = match path.rsplit('.').next() {
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    (
        [(header::CONTENT_TYPE, mime.to_string()), (header::ETAG, etag), (header::CACHE_CONTROL, cache.into())],
        f.data.into_owned(),
    )
        .into_response()
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { page("live", "Live") }))
        .route("/trends", get(|| async { page("trends", "Trends") }))
        .route("/search", get(|| async { page("search", "Search") }))
        .route("/cert", get(|| async { page("cert", "Certificate") }))
        .route("/sizing", get(|| async { page("sizing", "Sizing") }))
        .route("/domain", get(|| async { page("domain", "Domain") }))
        .route("/dns", get(|| async { page("dns", "DNS details") }))
        .route("/api/dns", get(api::dns))
        .route("/api/dns/cert", get(api::cert_dns))
        .route("/api/domain", get(api::domain))
        .route("/api/trends/{metric}", get(trends::trends))
        .route("/assets/{*path}", get(asset))
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/live", get(api::live))
        .route("/api/history", get(api::history))
        .route("/api/logs", get(api::logs))
        .route("/api/stream", get(sse::stream))
        .route("/api/search", get(api::search))
        .route("/api/certs", get(api::certs))
        .route("/api/cert/{log}/{index}", get(api::cert))
        .nest("/api/v1", v1::router())
        .with_state(state)
        .layer(SetResponseHeaderLayer::overriding(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP)))
        .layer(SetResponseHeaderLayer::overriding(header::REFERRER_POLICY, HeaderValue::from_static("same-origin")))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
}

pub async fn serve(listener: tokio::net::TcpListener, state: AppState) -> std::io::Result<()> {
    axum::serve(listener, router(state)).await
}
