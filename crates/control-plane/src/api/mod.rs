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
use security_control_plane_common::{
    validate_security_event, ContainmentActionType, PolicyBundle, SecurityEvent,
};
use security_control_plane_correlator::CorrelationEngine;
use security_control_plane_engine::{
    CapabilityPolicyEngine, ContainmentManager, IncidentStatus, RuleEngine,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};
use uuid::Uuid;

mod sensors;
use sensors::{handle_falco_ingest, handle_hubble_ingest, handle_tetragon_ingest};

#[derive(Clone)]
pub struct AppState {
    pub stream: Arc<MemoryEventStream>,
    pub durable_sink: Arc<dyn DurableEventSink>,
    pub engine: Arc<RuleEngine>,
    pub correlator: Arc<CorrelationEngine>,
    pub policy_engine: Arc<CapabilityPolicyEngine>,
    pub containment_mgr: Arc<ContainmentManager>,
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

#[derive(Deserialize)]
pub struct ContainmentQuery {
    pub active_only: Option<bool>,
}

#[derive(Deserialize)]
pub struct PolicyEvaluationRequest {
    pub app_id: String,
    pub who: Option<String>,
    pub actor_entity: Option<String>,
    pub capability: String,
    pub target_resource: String,
    pub evidence_event_ids: Option<Vec<Uuid>>,
}

#[derive(Deserialize)]
pub struct DispatchContainmentRequest {
    pub action: String,
    pub target_entity: String,
    pub capability: Option<String>,
    pub params: Option<HashMap<String, String>>,
    pub ttl_seconds: Option<u64>,
    pub evidence_incident_id: Option<Uuid>,
    pub rollback_recipe: Option<String>,
}

#[derive(Deserialize)]
pub struct RollbackContainmentRequest {
    pub reason: Option<String>,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Telemetry & Metrics
        .route("/api/v1/telemetry", get(handle_recent_events).post(handle_telemetry))
        .route("/api/v1/health", get(handle_health))
        .route("/api/v1/metrics", get(handle_metrics))
        .route("/api/v1/events/recent", get(handle_recent_events))
        // Incidents
        .route("/api/v1/incidents", get(handle_get_incidents))
        .route("/api/v1/incidents/:id", get(handle_get_incident_by_id))
        .route("/api/v1/incidents/:id/status", post(handle_update_incident_status))
        // Correlation & Identity
        .route("/api/v1/entities", get(handle_get_entities))
        .route("/api/v1/entities/:id", get(handle_get_entity_by_id))
        .route("/api/v1/correlation/graph", get(handle_get_correlation_graph))
        // Phase 4: Capability Policies
        .route("/api/v1/policies", get(handle_get_policies).post(handle_create_policy))
        .route("/api/v1/policies/:id", get(handle_get_policy_by_id).delete(handle_delete_policy))
        .route("/api/v1/policies/evaluate", post(handle_evaluate_policy))
        .route("/api/v1/policies/simulate", post(handle_simulate_policy))
        // Phase 4: Graduated Containment & Signed Commands
        .route("/api/v1/containment/commands", get(handle_get_containment_commands))
        .route("/api/v1/containment/dispatch", post(handle_dispatch_containment))
        .route("/api/v1/containment/:id/rollback", post(handle_rollback_containment))
        .route("/api/v1/containment/public-key", get(handle_get_containment_public_key))
        // Phase 5: Kernel & Runtime Sensor Telemetry
        .route("/api/v1/sensors/tetragon", post(handle_tetragon_ingest))
        .route("/api/v1/sensors/falco", post(handle_falco_ingest))
        .route("/api/v1/sensors/hubble", post(handle_hubble_ingest))
        // WebSocket Real-time Stream
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
        "phase": "Phase 5 - Kernel & Runtime Telemetry Adapters (Tetragon, Falco, Hubble)",
    }))
}

async fn handle_metrics() -> impl IntoResponse {
    render_prometheus_metrics()
}

async fn handle_recent_events(State(state): State<AppState>) -> impl IntoResponse {
    let events = state.stream.get_recent(50).await;
    (StatusCode::OK, Json(serde_json::json!(events))).into_response()
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

// ==========================================
// Phase 4: Policy Handlers
// ==========================================

async fn handle_get_policies(State(state): State<AppState>) -> impl IntoResponse {
    let bundles = state.policy_engine.get_bundles().await;
    (StatusCode::OK, Json(serde_json::json!(bundles))).into_response()
}

async fn handle_get_policy_by_id(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(bundle) = state.policy_engine.get_bundle(&id).await {
        (StatusCode::OK, Json(serde_json::json!(bundle))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("Policy bundle '{}' not found", id) })),
        )
            .into_response()
    }
}

async fn handle_create_policy(
    State(state): State<AppState>,
    Json(bundle): Json<PolicyBundle>,
) -> impl IntoResponse {
    let policy_id = bundle.policy_id.clone();
    state.policy_engine.add_bundle(bundle).await;
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "created", "policy_id": policy_id })),
    )
        .into_response()
}

async fn handle_delete_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.policy_engine.remove_bundle(&id).await {
        (StatusCode::OK, Json(serde_json::json!({ "status": "deleted", "policy_id": id }))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("Policy bundle '{}' not found", id) })),
        )
            .into_response()
    }
}

async fn handle_evaluate_policy(
    State(state): State<AppState>,
    Json(req): Json<PolicyEvaluationRequest>,
) -> impl IntoResponse {
    let who = req.who.unwrap_or_else(|| "anonymous".into());
    let actor_entity = req.actor_entity.unwrap_or_else(|| who.clone());
    let evidence = req.evidence_event_ids.unwrap_or_default();

    // Check if actor has active capability revocation
    if state.containment_mgr.is_capability_revoked(&actor_entity, &req.capability).await {
        let decision = security_control_plane_common::PolicyDecision {
            decision_id: Uuid::new_v4(),
            who,
            app_id: req.app_id,
            capability: req.capability,
            target_resource: req.target_resource,
            policy_id: "containment-active".into(),
            decision: security_control_plane_common::DecisionOutcome::Revoke,
            reason: "Capability revoked under active signed containment command".into(),
            matched_rule: Some("CONTAINMENT: REVOKE_CAPABILITY".into()),
            is_simulation: false,
            evidence_event_ids: evidence,
            timestamp: chrono::Utc::now(),
        };
        return (StatusCode::OK, Json(serde_json::json!(decision))).into_response();
    }

    let decision = state
        .policy_engine
        .evaluate(
            &req.app_id,
            &who,
            &actor_entity,
            &req.capability,
            &req.target_resource,
            evidence,
            false,
        )
        .await;

    (StatusCode::OK, Json(serde_json::json!(decision))).into_response()
}

async fn handle_simulate_policy(
    State(state): State<AppState>,
    Json(req): Json<PolicyEvaluationRequest>,
) -> impl IntoResponse {
    let who = req.who.unwrap_or_else(|| "simulation-user".into());
    let actor_entity = req.actor_entity.unwrap_or_else(|| who.clone());
    let evidence = req.evidence_event_ids.unwrap_or_default();

    let decision = state
        .policy_engine
        .evaluate(
            &req.app_id,
            &who,
            &actor_entity,
            &req.capability,
            &req.target_resource,
            evidence,
            true, // Mode C Simulation
        )
        .await;

    (StatusCode::OK, Json(serde_json::json!(decision))).into_response()
}

// ==========================================
// Phase 4: Containment Handlers
// ==========================================

async fn handle_get_containment_commands(
    State(state): State<AppState>,
    Query(query): Query<ContainmentQuery>,
) -> impl IntoResponse {
    let active_only = query.active_only.unwrap_or(false);
    let commands = state.containment_mgr.get_commands(active_only).await;
    (StatusCode::OK, Json(serde_json::json!(commands))).into_response()
}

async fn handle_dispatch_containment(
    State(state): State<AppState>,
    Json(req): Json<DispatchContainmentRequest>,
) -> impl IntoResponse {
    let action = ContainmentActionType::from_str_lossy(&req.action);
    let ttl = req.ttl_seconds.unwrap_or(300);
    let recipe = req.rollback_recipe.unwrap_or_else(|| "AUTOMATED_ROLLBACK".into());
    let params = req.params.unwrap_or_default();

    let cmd = state
        .containment_mgr
        .dispatch(
            action,
            req.target_entity,
            req.capability,
            params,
            ttl,
            req.evidence_incident_id,
            recipe,
        )
        .await;

    (StatusCode::CREATED, Json(serde_json::json!(cmd))).into_response()
}

async fn handle_rollback_containment(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<RollbackContainmentRequest>,
) -> impl IntoResponse {
    let reason = req.reason.unwrap_or_else(|| "Operator manual rollback".into());
    match state.containment_mgr.rollback(id, &reason).await {
        Ok(cmd) => (StatusCode::OK, Json(serde_json::json!(cmd))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn handle_get_containment_public_key(State(state): State<AppState>) -> impl IntoResponse {
    let pubkey = state.containment_mgr.public_key_hex();
    Json(serde_json::json!({
        "public_key": pubkey,
        "algorithm": "Ed25519",
        "key_length_bytes": 32,
        "format": "hex",
    }))
}

// ==========================================
// Ingestion & WebSocket Telemetry
// ==========================================

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

    match state.stream.publish_batch(&valid_events).await {
        Ok(ids) => {
            metrics.events_ingested.inc_by(ids.len() as f64);

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

    let mut read_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Close(_) = msg {
                break;
            }
        }
    });

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
