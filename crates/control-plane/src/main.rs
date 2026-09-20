use security_control_plane::{create_router, AppState, MemoryDurableSink, MemoryEventStream};
use security_control_plane_correlator::CorrelationEngine;
use security_control_plane_engine::{
    CapabilityPolicyEngine, ContainmentManager, HotStateStore, MemoryHotState, RedisHotState,
    RuleEngine,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "security_control_plane=debug,security_control_plane_engine=debug,security_control_plane_correlator=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Distributed Security Control Plane (Phase 5 - Kernel & Runtime Telemetry Adapters: Tetragon, Falco, Hubble)");

    // Initialize decoupled Event Stream
    let stream = Arc::new(MemoryEventStream::new(50_000));

    // Initialize Selective Durable Sink
    let durable_sink = Arc::new(MemoryDurableSink::new());

    // Initialize Hot State & Deterministic Rule Engine
    let hot_state: Arc<dyn HotStateStore> = match std::env::var("REDIS_URL") {
        Ok(url) if !url.is_empty() => {
            info!("Connecting to Redis Hot State store at {}", url);
            Arc::new(RedisHotState::new(&url)?)
        }
        _ => {
            info!("Initializing in-memory sub-microsecond Hot State store");
            Arc::new(MemoryHotState::new())
        }
    };
    let engine = Arc::new(RuleEngine::with_default_rules(hot_state));

    // Initialize Cross-Application Correlation Engine
    let correlator = Arc::new(CorrelationEngine::new());

    // Phase 4: Initialize Deno-inspired Capability Policy Engine with default production baseline
    let policy_engine = Arc::new(CapabilityPolicyEngine::with_default_policies());

    // Phase 4: Initialize Ed25519 Graduated Containment Manager
    let containment_mgr = Arc::new(ContainmentManager::with_random_keypair());
    info!(
        public_key = %containment_mgr.public_key_hex(),
        "Ed25519 Control Plane signing keypair active"
    );

    // Spawn periodic background TTL expiration sweeper (runs every 5 seconds)
    let sweeper_mgr = Arc::clone(&containment_mgr);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let expired = sweeper_mgr.sweep_expired().await;
            if !expired.is_empty() {
                info!(count = expired.len(), "Swept and expired containment commands past TTL");
            }
        }
    });

    // Spawn out-of-band asynchronous detection & correlation worker
    let engine_worker = Arc::clone(&engine);
    let correlator_worker = Arc::clone(&correlator);
    let mut detection_rx = stream.subscribe();
    tokio::spawn(async move {
        info!("Deterministic Detection & Correlation worker started (out-of-band streaming)");
        while let Ok(event) = detection_rx.recv().await {
            // 1. Process correlation, identity resolution, capability inference, and attack-chain detection
            let (canonical_id, cross_app_signal) = correlator_worker.process_event(&event).await;

            if let Some(signal) = cross_app_signal {
                info!(canonical_id = %canonical_id, "Cross-application attack sequence signal triggered");
                if let Err(err) = engine_worker.ingest_signal(signal, &event).await {
                    tracing::error!(error = %err, "Failed to ingest cross-app attack chain signal into incident engine");
                }
            }

            // 2. Evaluate deterministic rules
            if let Err(err) = engine_worker.evaluate_event(&event).await {
                tracing::error!(error = %err, "Detection engine event evaluation error");
            }
        }
    });

    let state = AppState {
        stream,
        durable_sink,
        engine,
        correlator,
        policy_engine,
        containment_mgr,
    };

    let app = create_router(state);

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse::<u16>()
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!("Security Control Plane Ingestion & Stream API listening on http://{}", addr);
    info!("WebSocket live feed (events + incidents) at ws://{}/api/v1/ws/events", addr);
    info!("Incidents REST API at http://{}/api/v1/incidents", addr);
    info!("Entities & Identity API at http://{}/api/v1/entities", addr);
    info!("Correlation Context Graph at http://{}/api/v1/correlation/graph", addr);
    info!("Capability Policies API at http://{}/api/v1/policies", addr);
    info!("Graduated Containment API at http://{}/api/v1/containment/commands", addr);
    info!("Kernel Telemetry (Cilium Tetragon) at http://{}/api/v1/sensors/tetragon", addr);
    info!("Runtime Telemetry (Falco Syscalls) at http://{}/api/v1/sensors/falco", addr);
    info!("Network Telemetry (Cilium Hubble Flows) at http://{}/api/v1/sensors/hubble", addr);
    info!("Prometheus metrics available at http://{}/api/v1/metrics", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
