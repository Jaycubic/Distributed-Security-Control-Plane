#[cfg(feature = "distributed")]
use security_control_plane::MemoryDurableSink;
#[cfg(feature = "standalone")]
use security_control_plane::SqliteDurableSink;
use security_control_plane::{
    config::{Config, RunMode},
    create_router, AppState, DurableEventSink, EventStreamProducer, MemoryEventStream,
};
use security_control_plane_correlator::CorrelationEngine;
use security_control_plane_enforcer::NativeEnforcer;
#[cfg(feature = "distributed")]
use security_control_plane_engine::RedisHotState;
use security_control_plane_engine::{
    AdvisoryManager, CapabilityPolicyEngine, ContainmentManager, HotStateStore, MemoryHotState,
    RuleEngine,
};
use security_control_plane_packet_inspector::PacketInspector;
use security_control_plane_port_guardian::PortGuardian;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_args()?;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| config.log_level.clone().into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!(mode = ?config.mode, "Starting Corvus security control plane");

    // Initialize decoupled Event Stream
    let stream = Arc::new(MemoryEventStream::new(50_000));

    // Initialize durable storage for standalone or distributed operation.
    let durable_sink: Arc<dyn DurableEventSink> = match &config.mode {
        RunMode::Standalone => {
            #[cfg(feature = "standalone")]
            {
                Arc::new(SqliteDurableSink::open(&config.storage.sqlite_path)?)
            }
            #[cfg(not(feature = "standalone"))]
            {
                return Err("standalone mode requires the `standalone` feature".into());
            }
        }
        RunMode::Distributed => {
            #[cfg(feature = "distributed")]
            {
                Arc::new(MemoryDurableSink::new())
            }
            #[cfg(not(feature = "distributed"))]
            {
                return Err("distributed mode requires the `distributed` feature".into());
            }
        }
    };

    // Initialize Hot State & Deterministic Rule Engine
    let hot_state: Arc<dyn HotStateStore> = match &config.mode {
        RunMode::Standalone => Arc::new(MemoryHotState::new()),
        RunMode::Distributed => {
            #[cfg(feature = "distributed")]
            {
                match config.storage.redis_url.as_deref() {
                    Some(url) if !url.is_empty() => {
                        info!(redis_url = %url, "Connecting to Redis Hot State store");
                        Arc::new(RedisHotState::new(url)?)
                    }
                    _ => {
                        info!("Redis URL absent; using in-memory hot state fallback");
                        Arc::new(MemoryHotState::new())
                    }
                }
            }
            #[cfg(not(feature = "distributed"))]
            {
                return Err("distributed mode requires the `distributed` feature".into());
            }
        }
    };
    let engine = Arc::new(RuleEngine::with_default_rules(Arc::clone(&hot_state)));
    let port_guardian = Arc::new(PortGuardian::new(hot_state));

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
    let native_enforcer = match std::env::var("NATIVE_ENFORCER").as_deref() {
        Ok("true") => {
            info!("Native OS containment enabled for explicit signed commands");
            Some(Arc::new(NativeEnforcer::system(
                containment_mgr.public_key_hex(),
            )))
        }
        _ => None,
    };

    // Phase 6: Initialize Advisory Manager and Deterministic Policy Gate (Mode A baseline default)
    let advisory_mgr = Arc::new(AdvisoryManager::with_defaults(
        Arc::clone(&policy_engine),
        Arc::clone(&containment_mgr),
    ));
    info!(
        mode = advisory_mgr.get_mode().await.as_str(),
        worker_url = %advisory_mgr.get_worker_url().await,
        "Advisory Off-Path Reasoning Controller initialized"
    );

    // Spawn periodic background TTL expiration sweeper (runs every 5 seconds)
    let sweeper_mgr = Arc::clone(&containment_mgr);
    let sweeper_sink = Arc::clone(&durable_sink);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let expired = sweeper_mgr.sweep_expired().await;
            if !expired.is_empty() {
                info!(
                    count = expired.len(),
                    "Swept and expired containment commands past TTL"
                );
                for command_id in expired {
                    if let Some(command) = sweeper_mgr.get_command(command_id).await {
                        if let Err(err) = sweeper_sink.save_containment_command(&command).await {
                            tracing::error!(error = %err, command_id = %command_id, "Failed to persist expired containment command");
                        }
                    }
                }
            }
        }
    });

    let incident_sink = Arc::clone(&durable_sink);
    let mut incident_rx = engine.subscribe_incidents();
    tokio::spawn(async move {
        loop {
            match incident_rx.recv().await {
                Ok(incident) => {
                    if let Err(err) = incident_sink.save_incident(&incident).await {
                        tracing::error!(error = %err, incident_id = %incident.incident_id, "Failed to persist incident");
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                    tracing::error!(
                        skipped = count,
                        "Incident persistence worker lagged; incident updates were lost"
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Spawn out-of-band asynchronous detection & correlation worker
    let engine_worker = Arc::clone(&engine);
    let port_guardian_worker = Arc::clone(&port_guardian);
    let correlator_worker = Arc::clone(&correlator);
    let mut detection_rx = stream.subscribe();
    tokio::spawn(async move {
        info!("Deterministic Detection & Correlation worker started (out-of-band streaming)");
        while let Ok(event) = detection_rx.recv().await {
            let event = match port_guardian_worker.process_event(&event).await {
                Ok(event) => event,
                Err(err) => {
                    tracing::error!(error = %err, event_id = %event.event_id, "Port Guardian event processing failed");
                    event
                }
            };

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

    // Phase 6: Start native eBPF sensor if enabled and running as root
    if config.sensor.native_enabled {
        let hostname = config
            .sensor
            .hostname
            .clone()
            .or_else(|| std::env::var("HOSTNAME").ok())
            .or_else(|| std::env::var("COMPUTERNAME").ok())
            .unwrap_or_else(|| "localhost".to_string());

        let loader = security_control_plane_sensor_native::NativeSensorLoader::new(hostname);

        match loader.start().await {
            Ok(mut rx) => {
                let stream_clone = Arc::clone(&stream);
                tokio::spawn(async move {
                    while let Some(event) = rx.recv().await {
                        if let Err(e) = stream_clone.publish(&event).await {
                            tracing::warn!(error = %e, "Native sensor event publish failed");
                        }
                    }
                });
                info!("Native eBPF sensor active — replacing Tetragon/Falco/Hubble");
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Native eBPF sensor failed to start — falling back to external sensors"
                );
            }
        }
    }

    let state = AppState {
        stream,
        durable_sink,
        engine,
        correlator,
        policy_engine,
        containment_mgr,
        advisory_mgr,
        port_guardian,
        native_enforcer,
        packet_inspector: Arc::new(PacketInspector::new("packet-inspector")),
    };

    let app = create_router(state);

    let addr: SocketAddr = config.bind_address.parse()?;

    info!(
        "Security Control Plane Ingestion & Stream API listening on http://{}",
        addr
    );
    info!(
        "WebSocket live feed (events + incidents) at ws://{}/api/v1/ws/events",
        addr
    );
    info!("Incidents REST API at http://{}/api/v1/incidents", addr);
    info!("Entities & Identity API at http://{}/api/v1/entities", addr);
    info!(
        "Correlation Context Graph at http://{}/api/v1/correlation/graph",
        addr
    );
    info!("Capability Policies API at http://{}/api/v1/policies", addr);
    info!(
        "Graduated Containment API at http://{}/api/v1/containment/commands",
        addr
    );
    info!(
        "Kernel Telemetry (Cilium Tetragon) at http://{}/api/v1/sensors/tetragon",
        addr
    );
    info!(
        "Runtime Telemetry (Falco Syscalls) at http://{}/api/v1/sensors/falco",
        addr
    );
    info!(
        "Network Telemetry (Cilium Hubble Flows) at http://{}/api/v1/sensors/hubble",
        addr
    );
    info!("Execution Mode API at http://{}/api/v1/mode", addr);
    info!(
        "Advisory AI Reasoning API at http://{}/api/v1/advisory/recommendations",
        addr
    );
    info!(
        "Prometheus metrics available at http://{}/api/v1/metrics",
        addr
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
