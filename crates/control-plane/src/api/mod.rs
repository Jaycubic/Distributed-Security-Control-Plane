use crate::metrics::{get_metrics, render_prometheus_metrics};
use crate::storage::DurableEventSink;
use crate::stream::{EventStreamProducer, MemoryEventStream};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use futures::{sink::SinkExt, stream::StreamExt};
use security_control_plane_common::{validate_security_event, SecurityEvent};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub stream: Arc<MemoryEventStream>,
    pub durable_sink: Arc<dyn DurableEventSink>,
}

#[derive(Serialize)]
pub struct IngestionResponse {
    pub status: &'static str,
    pub accepted_count: usize,
    pub event_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum IngestionPayload {
    Single(Box<SecurityEvent>),
    Batch(Vec<SecurityEvent>),
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/telemetry", post(handle_telemetry))
        .route("/api/v1/health", get(handle_health))
        .route("/api/v1/metrics", get(handle_metrics))
        .route("/api/v1/events/recent", get(handle_recent_events))
        .route("/api/v1/ws/events", get(handle_ws_events))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn handle_health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "security-control-plane",
        "version": "0.1.0",
        "mode": "Mode A (Deterministic)",
    }))
}

async fn handle_metrics() -> impl IntoResponse {
    render_prometheus_metrics()
}

async fn handle_recent_events(State(state): State<AppState>) -> impl IntoResponse {
    match state.durable_sink.get_recent_events(50).await {
        Ok(events) => (StatusCode::OK, Json(serde_json::json!(events))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn handle_telemetry(
    State(state): State<AppState>,
    Json(payload): Json<IngestionPayload>,
) -> impl IntoResponse {
    let metrics = get_metrics();
    let timer = metrics.ingestion_latency_seconds.start_timer();

    let events = match payload {
        IngestionPayload::Single(ev) => vec![*ev],
        IngestionPayload::Batch(evs) => evs,
    };

    let mut valid_events = Vec::with_capacity(events.len());
    for ev in events {
        if let Err(err) = validate_security_event(&ev) {
            metrics.events_invalid.inc();
            warn!(error = %err, event_id = %ev.event_id, "Rejected malformed security event");
            continue;
        }
        valid_events.push(ev);
    }

    if valid_events.is_empty() {
        timer.observe_duration();
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "All submitted events failed validation".into(),
            }),
        )
            .into_response();
    }

    // Publish to the decoupled event stream
    match state.stream.publish_batch(&valid_events).await {
        Ok(ids) => {
            metrics.events_ingested.inc_by(ids.len() as f64);
            
            // Asynchronously dispatch to the selective durable sink
            let sink = Arc::clone(&state.durable_sink);
            let events_to_persist = valid_events;
            tokio::spawn(async move {
                if let Ok(count) = sink.save_batch(&events_to_persist).await {
                    get_metrics().events_persisted.inc_by(count as f64);
                }
            });

            timer.observe_duration();
            (
                StatusCode::ACCEPTED,
                Json(IngestionResponse {
                    status: "accepted",
                    accepted_count: ids.len(),
                    event_ids: ids,
                }),
            )
                .into_response()
        }
        Err(e) => {
            timer.observe_duration();
            error!(error = %e, "Failed publishing telemetry to event stream");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Stream ingestion error: {}", e),
                }),
            )
                .into_response()
        }
    }
}

async fn handle_ws_events(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let metrics = get_metrics();
    metrics.active_ws_clients.inc();
    info!("Dashboard client connected to telemetry WebSocket stream");

    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.stream.subscribe();

    // Spawn task to read client incoming pings or messages
    let mut read_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Close(_) = msg {
                break;
            }
        }
    });

    // Stream live events from the Event Stream to the WebSocket client
    let mut write_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if let Ok(json_str) = serde_json::to_string(&event) {
                if sender.send(Message::Text(json_str)).await.is_err() {
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = (&mut read_task) => write_task.abort(),
        _ = (&mut write_task) => read_task.abort(),
    };

    metrics.active_ws_clients.dec();
    info!("Dashboard client disconnected from telemetry stream");
}
