use crate::api::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use security_control_plane_common::{
    AdvisoryRecommendation, ControlPlaneMode,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct SetModeRequest {
    pub mode: String,
}

#[derive(Debug, Serialize)]
pub struct ModeResponse {
    pub mode: String,
    pub is_mode_b: bool,
    pub worker_url: String,
    pub description: &'static str,
}

/// GET /api/v1/mode: Returns the current Control Plane execution mode (Mode A or Mode B).
pub async fn handle_get_mode(State(state): State<AppState>) -> impl IntoResponse {
    let mode = state.advisory_mgr.get_mode().await;
    let worker_url = state.advisory_mgr.get_worker_url().await;

    let description = match mode {
        ControlPlaneMode::ModeA => {
            "Mode A (Deterministic): Baseline mode. LLM is completely off-path and disabled. All detection, policy, and containment run with sub-millisecond deterministic logic."
        }
        ControlPlaneMode::ModeB => {
            "Mode B (Intelligent / Advisory): Off-path LLM reasoning active for ambiguous incidents. All recommendations pass through the Deterministic Policy Gate."
        }
    };

    Json(ModeResponse {
        mode: mode.as_str().to_string(),
        is_mode_b: mode == ControlPlaneMode::ModeB,
        worker_url,
        description,
    })
}

/// POST /api/v1/mode: Toggles between Mode A (Deterministic) and Mode B (Advisory AI).
pub async fn handle_set_mode(
    State(state): State<AppState>,
    Json(payload): Json<SetModeRequest>,
) -> impl IntoResponse {
    let mode_str = payload.mode.trim().to_lowercase();
    let new_mode = if mode_str.contains('b') || mode_str.contains("advisory") || mode_str.contains("llm") {
        ControlPlaneMode::ModeB
    } else {
        ControlPlaneMode::ModeA
    };

    state.advisory_mgr.set_mode(new_mode).await;

    info!(
        mode = new_mode.as_str(),
        "Operator updated Control Plane execution mode"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "mode": new_mode.as_str(),
            "is_mode_b": new_mode == ControlPlaneMode::ModeB,
        })),
    )
}

/// POST /api/v1/advisory/analyze/:incident_id:
/// Triggers asynchronous, off-path advisory reasoning for an ambiguous incident.
/// If in Mode A, rejects or gracefully falls back.
/// If worker is unavailable, falls back gracefully to deterministic Mode A without error.
pub async fn handle_analyze_incident(
    State(state): State<AppState>,
    Path(incident_id): Path<Uuid>,
) -> impl IntoResponse {
    // 1. Verify incident exists
    let incident = match state.engine.get_incident_by_id(incident_id).await {
        Some(inc) => inc,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": format!("Incident {} not found", incident_id)
                })),
            )
                .into_response();
        }
    };

    // 2. Check if Mode B is active
    let is_mode_b = state.advisory_mgr.is_mode_b().await;
    if !is_mode_b {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Control plane is in Mode A (Deterministic). Mode B must be enabled to trigger advisory AI reasoning.",
                "mode": "Mode A (Deterministic)",
                "hint": "Set mode to 'mode_b' via POST /api/v1/mode to enable advisory reasoning."
            })),
        )
            .into_response();
    }

    // 3. Build structured incident context
    let policy_bundles = state.policy_engine.get_bundles().await;
    let policy_ids: Vec<String> = policy_bundles.into_iter().map(|b| b.policy_id).collect();
    let context = security_control_plane_engine::AdvisoryManager::build_incident_context(
        &incident,
        policy_ids,
    );

    // 4. Dispatch to Python Advisory Worker
    let worker_url = state.advisory_mgr.get_worker_url().await;
    let endpoint = format!("{}/analyze", worker_url.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(3000)) // strict 3 second timeout for off-path reasoning
        .build()
        .unwrap_or_default();

    let worker_response = client.post(&endpoint).json(&context).send().await;

    match worker_response {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<AdvisoryRecommendation>().await {
                Ok(rec) => {
                    info!(
                        incident_id = %incident_id,
                        classification = ?rec.classification,
                        confidence = rec.confidence,
                        action = rec.recommended_action.as_str(),
                        "Received structured recommendation from advisory worker"
                    );

                    // 5. Pass through Deterministic Policy Validation Gate (DENY > ALLOW)
                    let validation = state.advisory_mgr.validate_and_enact(rec.clone()).await;

                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "status": "completed",
                            "recommendation": rec,
                            "validation": validation,
                        })),
                    )
                        .into_response()
                }
                Err(err) => {
                    warn!(
                        incident_id = %incident_id,
                        error = %err,
                        "Advisory worker returned malformed recommendation JSON; falling back to deterministic Mode A"
                    );
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "status": "fallback",
                            "mode": "Mode A (Deterministic Fallback)",
                            "message": "Malformed advisory worker response. Incident remains governed by deterministic rules.",
                            "incident_id": incident_id,
                        })),
                    )
                        .into_response()
                }
            }
        }
        Ok(resp) => {
            warn!(
                incident_id = %incident_id,
                status = %resp.status(),
                "Advisory worker returned HTTP error; falling back to deterministic Mode A"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "fallback",
                    "mode": "Mode A (Deterministic Fallback)",
                    "message": format!("Advisory worker returned status {}. Retained deterministic state.", resp.status()),
                    "incident_id": incident_id,
                })),
            )
                .into_response()
        }
        Err(err) => {
            warn!(
                incident_id = %incident_id,
                endpoint = %endpoint,
                error = %err,
                "Advisory worker unreachable; gracefully falling back to deterministic Mode A"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "fallback",
                    "mode": "Mode A (Deterministic Fallback)",
                    "message": "Advisory worker unreachable. Incident remains safely handled by deterministic engine.",
                    "incident_id": incident_id,
                })),
            )
                .into_response()
        }
    }
}

/// POST /api/v1/advisory/recommendation:
/// Ingests an advisory recommendation directly (e.g. from an external worker script or simulation),
/// evaluating it through the Deterministic Policy Validation Gate.
pub async fn handle_submit_recommendation(
    State(state): State<AppState>,
    Json(rec): Json<AdvisoryRecommendation>,
) -> impl IntoResponse {
    info!(
        recommendation_id = %rec.recommendation_id,
        incident_id = %rec.incident_id,
        action = rec.recommended_action.as_str(),
        target = %rec.target_entity,
        "Ingesting advisory recommendation into Deterministic Policy Gate"
    );

    let validation = state.advisory_mgr.validate_and_enact(rec.clone()).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "evaluated",
            "recommendation": rec,
            "validation": validation,
        })),
    )
}

/// GET /api/v1/advisory/recommendations:
/// Returns historical advisory recommendations and their deterministic gate validation outcomes.
pub async fn handle_get_recommendations(State(state): State<AppState>) -> impl IntoResponse {
    let history = state.advisory_mgr.get_history().await;
    let formatted: Vec<serde_json::Value> = history
        .into_iter()
        .map(|(rec, val)| {
            serde_json::json!({
                "recommendation": rec,
                "validation": val,
            })
        })
        .collect();

    (StatusCode::OK, Json(serde_json::json!(formatted)))
}
