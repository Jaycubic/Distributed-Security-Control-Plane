use crate::metrics::{get_metrics, render_prometheus_metrics};
use crate::storage::DurableEventSink;
use crate::stream::{EventStreamProducer, MemoryEventStream};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use futures::{sink::SinkExt, stream::StreamExt};
use security_control_plane_common::{validate_security_event, SecurityEvent};
use security_control_plane_correlator::CorrelationEngine;
use security_control_plane_engine::{IncidentStatus, RuleEngine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub stream: Arc<MemoryEventStream>,
    pub durable_sink: Arc<dyn DurableEventSink>,
    pub engine: Arc<RuleEngine>,
    pub correlator: Arc<CorrelationEngine>,
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

#[derive(Deserialize)]
pub struct IncidentsQuery {
    pub status: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateIncidentStatusRequest {
    pub status: String,
}

#[derive(Deserialize)]
pub struct GraphQuery {
    pub entity_id: Option<String>,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/telemetry", post(handle_telemetry))
        .route("/api/v1/health", get(handle_health))
        .route("/api/v1/metrics", get(handle_metrics))
        .route("/api/v1/events/recent", get(handle_recent_events))
        .route("/api/v1/incidents", get(handle_get_incidents))
        .route("/api/v1/incidents/:id", get(handle_get_incident_by_id))
        .route("/api/v1/incidents/:id/status", post(handle_update_incident_status))
        .route("/api/v1/entities", get(handle_get_entities))
        .route("/api/v1/entities/:id", get(handle_get_entity_by_id))
        .route("/api/v1/correlation/graph", get(handle_get_correlation_graph))
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

async fn handle_get_incidents(
    State(state): State<AppState>,
    Query(query): Query<IncidentsQuery>,
) -> impl IntoResponse {
    let incidents = if let Some(ref s) = query.status {
        if s == "open" || s == "active" {
            state.engine.get_active_incidents().await
        } else {
            state.engine.get_all_incidents().await
        }
    } else {
        state.engine.get_all_incidents().await
    };

    (StatusCode::OK, Json(serde_json::json!(incidents)))
}

async fn handle_get_incident_by_id(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if let Some(inc) = state.engine.get_incident_by_id(id).await {
        (StatusCode::OK, Json(serde_json::json!(inc))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("Incident {} not found", id) })),
        )
            .into_response()
    }
}

async fn handle_update_incident_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateIncidentStatusRequest>,
) -> impl IntoResponse {
    let status = match payload.status.to_lowercase().as_str() {
        "open" => IncidentStatus::Open,
        "investigating" => IncidentStatus::Investigating,
        "contained" => IncidentStatus::Contained,
        "resolved" => IncidentStatus::Resolved,
        "false_positive" => IncidentStatus::FalsePositive,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("Invalid status '{}'", other) })),
            )
                .into_response();
        }
    };

    let updated = state.engine.update_incident_status(id, status).await;
    if updated {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "updated", "incident_id": id })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("Incident {} not found", id) })),
        )
            .into_response()
    }
}

async fn handle_get_entities(State(state): State<AppState>) -> impl IntoResponse {
    let resolver = state.correlator.identity_resolver();
    let lock = resolver.read().await;
    let entities = lock.list_entities();
    (StatusCode::OK, Json(serde_json::json!(entities))).into_response()
}

async fn handle_get_entity_by_id(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let resolver = state.correlator.identity_resolver();
    let lock = resolver.read().await;
    if let Some(entity) = lock.get(&id).or_else(|| lock.get_by_alias(&id)) {
        (StatusCode::OK, Json(serde_json::json!(entity))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("Entity '{}' not found", id) })),
        )
            .into_response()
    }
}

async fn handle_get_correlation_graph(
    State(state): State<AppState>,
    Query(query): Query<GraphQuery>,
) -> impl IntoResponse {
    let graph = state.correlator.context_graph();
    let lock = graph.read().await;
    let sub = if let Some(entity_id) = query.entity_id {
        lock.get_subgraph(&entity_id)
    } else {
        lock.get_full_graph()
    };
    (StatusCode::OK, Json(serde_json::json!(sub))).into_response()
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
    let mut rx_events = state.stream.subscribe();
    let mut rx_incidents = state.engine.subscribe_incidents();

    // Spawn task to read client incoming pings or close messages
    let mut read_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Close(_) = msg {
                break;
            }
        }
    });

    // Stream live events and incident notifications over the WebSocket
    let mut write_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Ok(event) = rx_events.recv() => {
                    if let Ok(json_str) = serde_json::to_string(&event) {
                        if sender.send(Message::Text(json_str)).await.is_err() {
                            break;
                        }
                    }
                }
                Ok(incident) = rx_incidents.recv() => {
                    if let Ok(json_str) = serde_json::to_string(&incident) {
                        if sender.send(Message::Text(json_str)).await.is_err() {
                            break;
                        }
                    }
                }
                else => break,
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
