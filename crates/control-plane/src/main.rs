use security_control_plane::{create_router, AppState, MemoryDurableSink, MemoryEventStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "security_control_plane=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Distributed Security Control Plane (Phase 1 Slice)");

    // Initialize decoupled Event Stream
    let stream = Arc::new(MemoryEventStream::new(50_000));

    // Initialize Selective Durable Sink
    let durable_sink = Arc::new(MemoryDurableSink::new());

    let state = AppState {
        stream,
        durable_sink,
    };

    let app = create_router(state);

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse::<u16>()
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!("Security Control Plane Ingestion & Stream API listening on http://{}", addr);
    info!("WebSocket live feed available at ws://{}/api/v1/ws/events", addr);
    info!("Prometheus metrics available at http://{}/api/v1/metrics", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
