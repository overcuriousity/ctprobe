//! HTTP layer: pages are static shells, and all data arrives as JSON or SSE and
//! is rendered with `textContent`, so certificate fields cannot become markup.

pub mod api;
pub mod csv;
mod sse;
pub mod trends;

use crate::pipeline::PipelineHandle;
use crate::query::QueryEngine;
use axum::extract::Path;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rust_embed::RustEmbed;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tower_http::set_header::SetResponseHeaderLayer;

pub const MAX_SSE_CLIENTS: usize = 100;
const CSP: &str = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
                   object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

#[derive(RustEmbed)]
#[folder = "assets/"]
struct Assets;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<QueryEngine>,
    pub pipe: PipelineHandle,
    pub client: reqwest::Client,
    pub sse_clients: Arc<AtomicUsize>,
}

impl AppState {
    pub fn new(engine: Arc<QueryEngine>, pipe: PipelineHandle) -> AppState {
        let client = crate::http::client_builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .expect("HTTP client");
        AppState { engine, pipe, client, sse_clients: Arc::new(AtomicUsize::new(0)) }
    }
}

fn page(name: &str, title: &str) -> Response {
    let layout = Assets::get("layout.html").expect("embedded layout");
    let body = Assets::get(&format!("{name}.html")).expect("embedded page");
    let html = String::from_utf8_lossy(&layout.data)
        .replace("{{title}}", title)
        .replace("{{page}}", name)
        .replace("{{body}}", &String::from_utf8_lossy(&body.data));
    Html(html).into_response()
}

async fn asset(Path(path): Path<String>) -> Response {
    let Some(f) = Assets::get(&path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mime = match path.rsplit('.').next() {
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        _ => "application/octet-stream",
    };
    ([(header::CONTENT_TYPE, mime)], f.data.into_owned()).into_response()
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { page("live", "Live") }))
        .route("/trends", get(|| async { page("trends", "Trends") }))
        .route("/search", get(|| async { page("search", "Search") }))
        .route("/cert", get(|| async { page("cert", "Certificate") }))
        .route("/sql", get(|| async { page("sql", "SQL") }))
        .route("/sizing", get(|| async { page("sizing", "Sizing") }))
        .route("/domain", get(|| async { page("domain", "Domain") }))
        .route("/dns", get(|| async { page("dns", "DNS details") }))
        .route("/api/dns", get(api::dns))
        .route("/api/dns/cert", get(api::cert_dns))
        .route("/api/domain", get(api::domain))
        .route("/api/trends/{metric}", get(trends::trends))
        .route("/api/schema", get(trends::schema))
        .route("/assets/{*path}", get(asset))
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/live", get(api::live))
        .route("/api/history", get(api::history))
        .route("/api/logs", get(api::logs))
        .route("/api/stream", get(sse::stream))
        .route("/api/sql", get(api::sql))
        .route("/api/search", get(api::search))
        .route("/api/certs", get(api::certs))
        .route("/api/cert/{log}/{index}", get(api::cert))
        .with_state(state)
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
}

pub async fn serve(listener: tokio::net::TcpListener, state: AppState) -> std::io::Result<()> {
    axum::serve(listener, router(state)).await
}

