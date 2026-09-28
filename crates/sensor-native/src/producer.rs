use async_trait::async_trait;
use crate::error::SensorNativeError;

/// Lifecycle management trait for native sensor producers.
#[async_trait]
pub trait NativeSensorProducer: Send + Sync {
    async fn start(&self) -> Result<(), SensorNativeError>;
    async fn stop(&self) -> Result<(), SensorNativeError>;
}
