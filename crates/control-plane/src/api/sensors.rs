use crate::api::{AppState, ErrorResponse, IngestionResponse};
use crate::metrics::get_metrics;
use crate::stream::EventStreamProducer;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use security_control_plane_sensors::{FalcoAdapter, HubbleAdapter, TetragonAdapter};
use serde_json::Value;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Ingests raw Cilium Tetragon process_exec or process_kprobe events.
pub async fn handle_tetragon_ingest(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let metrics = get_metrics();
    let timer = metrics.ingestion_latency_seconds.start_timer();

    let raw_events = match payload {
        Value::Array(arr) => arr,
        obj @ Value::Object(_) => vec![obj],
        _ => {
            timer.observe_duration();
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid Tetragon payload: Expected JSON object or array".into(),
                }),
            )
                .into_response();
        }
    };

    let mut canonical_events = Vec::with_capacity(raw_events.len());
    for raw in raw_events {
        match TetragonAdapter::parse_event(&raw) {
            Ok(event) => canonical_events.push(event),
            Err(e) => {
                warn!(error = %e, "Failed to parse raw Tetragon event");
            }
        }
    }

    if canonical_events.is_empty() {
        timer.observe_duration();
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "No valid Tetragon events could be extracted".into(),
            }),
        )
            .into_response();
    }

    info!(count = canonical_events.len(), "Ingested Cilium Tetragon eBPF telemetry");

    match state.stream.publish_batch(&canonical_events).await {
        Ok(ids) => {
            metrics.events_ingested.inc_by(ids.len() as f64);
            let sink = Arc::clone(&state.durable_sink);
            let to_persist = canonical_events;
            tokio::spawn(async move {
                if let Ok(count) = sink.save_batch(&to_persist).await {
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
            error!(error = %e, "Failed to stream Tetragon events");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Stream error: {}", e),
                }),
            )
                .into_response()
        }
    }
}

/// Ingests raw Falco runtime security alert webhooks.
pub async fn handle_falco_ingest(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let metrics = get_metrics();
    let timer = metrics.ingestion_latency_seconds.start_timer();

    let raw_events = match payload {
        Value::Array(arr) => arr,
        obj @ Value::Object(_) => vec![obj],
        _ => {
            timer.observe_duration();
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid Falco payload: Expected JSON object or array".into(),
                }),
            )
                .into_response();
        }
    };

    let mut canonical_events = Vec::with_capacity(raw_events.len());
    for raw in raw_events {
        match FalcoAdapter::parse_event(&raw) {
            Ok(event) => canonical_events.push(event),
            Err(e) => {
                warn!(error = %e, "Failed to parse Falco alert");
            }
        }
    }

    if canonical_events.is_empty() {
        timer.observe_duration();
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "No valid Falco alerts could be extracted".into(),
            }),
        )
            .into_response();
    }

    info!(count = canonical_events.len(), "Ingested Falco runtime syscall alerts");

    match state.stream.publish_batch(&canonical_events).await {
        Ok(ids) => {
            metrics.events_ingested.inc_by(ids.len() as f64);
            let sink = Arc::clone(&state.durable_sink);
            let to_persist = canonical_events;
            tokio::spawn(async move {
                if let Ok(count) = sink.save_batch(&to_persist).await {
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
            error!(error = %e, "Failed to stream Falco alerts");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Stream error: {}", e),
                }),
            )
                .into_response()
        }
    }
}

/// Ingests raw Cilium Hubble L3/L4/L7 flow logs.
pub async fn handle_hubble_ingest(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let metrics = get_metrics();
    let timer = metrics.ingestion_latency_seconds.start_timer();

    let raw_events = match payload {
        Value::Array(arr) => arr,
        obj @ Value::Object(_) => vec![obj],
        _ => {
            timer.observe_duration();
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid Hubble payload: Expected JSON object or array".into(),
                }),
            )
                .into_response();
        }
    };

    let mut canonical_events = Vec::with_capacity(raw_events.len());
    for raw in raw_events {
        match HubbleAdapter::parse_event(&raw) {
            Ok(event) => canonical_events.push(event),
            Err(e) => {
                warn!(error = %e, "Failed to parse Hubble flow log");
            }
        }
    }

    if canonical_events.is_empty() {
        timer.observe_duration();
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "No valid Hubble flow events could be extracted".into(),
            }),
        )
            .into_response();
    }

    info!(count = canonical_events.len(), "Ingested Cilium Hubble network flow logs");

    match state.stream.publish_batch(&canonical_events).await {
        Ok(ids) => {
            metrics.events_ingested.inc_by(ids.len() as f64);
            let sink = Arc::clone(&state.durable_sink);
            let to_persist = canonical_events;
            tokio::spawn(async move {
                if let Ok(count) = sink.save_batch(&to_persist).await {
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
            error!(error = %e, "Failed to stream Hubble flow logs");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Stream error: {}", e),
                }),
            )
                .into_response()
        }
    }
}
