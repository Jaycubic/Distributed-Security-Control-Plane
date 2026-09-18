use prometheus::{
    register_counter, register_gauge, register_histogram, Counter, Encoder, Gauge, Histogram,
    TextEncoder,
};
use std::sync::OnceLock;

pub struct ControlPlaneMetrics {
    pub events_ingested: Counter,
    pub events_invalid: Counter,
    pub events_persisted: Counter,
    pub active_ws_clients: Gauge,
    pub ingestion_latency_seconds: Histogram,
}

static METRICS: OnceLock<ControlPlaneMetrics> = OnceLock::new();

pub fn get_metrics() -> &'static ControlPlaneMetrics {
    METRICS.get_or_init(|| {
        let events_ingested = register_counter!(
            "control_plane_events_ingested_total",
            "Total number of events accepted by the ingestion pipeline"
        )
        .expect("metric can be registered");

        let events_invalid = register_counter!(
            "control_plane_events_invalid_total",
            "Total number of events rejected due to schema or validation errors"
        )
        .expect("metric can be registered");

        let events_persisted = register_counter!(
            "control_plane_events_persisted_total",
            "Total number of security-significant events written to durable storage"
        )
        .expect("metric can be registered");

        let active_ws_clients = register_gauge!(
            "control_plane_active_ws_clients",
            "Number of active dashboard WebSocket subscribers"
        )
        .expect("metric can be registered");

        let ingestion_latency_seconds = register_histogram!(
            "control_plane_ingestion_latency_seconds",
            "Ingestion pipeline processing duration in seconds",
            vec![0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.005, 0.01]
        )
        .expect("metric can be registered");

        ControlPlaneMetrics {
            events_ingested,
            events_invalid,
            events_persisted,
            active_ws_clients,
            ingestion_latency_seconds,
        }
    })
}

pub fn render_prometheus_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap_or_default();
    String::from_utf8(buffer).unwrap_or_default()
}
