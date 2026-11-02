use super::{AppState, MAX_SSE_CLIENTS};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::{BroadcastStream, IntervalStream};
use tokio_stream::StreamExt;

#[derive(Deserialize)]
pub struct StreamQuery {
    q: Option<String>,
}

struct ClientSlot(Arc<AtomicUsize>);

impl Drop for ClientSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One snapshot a second and a filtered certificate feed. The broadcast buffer
/// is dropped for a slow client (`Lagged`), so it can never hold up ingest.
pub async fn stream(State(s): State<AppState>, Query(q): Query<StreamQuery>) -> Response {
    if s.sse_clients.fetch_add(1, Ordering::SeqCst) >= MAX_SSE_CLIENTS {
        s.sse_clients.fetch_sub(1, Ordering::SeqCst);
        return (StatusCode::SERVICE_UNAVAILABLE, "too many live clients").into_response();
    }
    let slot = ClientSlot(s.sse_clients.clone());
    let live = s.pipe.live.clone();
    let ticks = IntervalStream::new(tokio::time::interval(Duration::from_secs(1))).map(move |_| {
        let mut snap = live.snapshot();
        snap.logs.clear(); // The log table polls /api/logs; this goes out every second.
        Event::default().event("snapshot").json_data(snap).unwrap_or_default()
    });
    let needle = q.q.map(|n| n.to_lowercase()).filter(|n| !n.is_empty());
    let feed = BroadcastStream::new(s.pipe.feed.subscribe()).filter_map(move |item| {
        let item = item.ok()?;
        if let Some(n) = &needle {
            let cn = item.cn.as_deref().unwrap_or("").to_lowercase();
            let dom = item.primary_domain.as_deref().unwrap_or("");
            if !cn.contains(n) && !dom.contains(n) {
                return None;
            }
        }
        Event::default().event("cert").json_data(&*item).ok()
    });
    let merged = ticks.merge(feed).map(move |e| {
        let _keep = &slot;
        Ok::<_, std::convert::Infallible>(e)
    });
    Sse::new(merged).keep_alive(KeepAlive::default()).into_response()
}
