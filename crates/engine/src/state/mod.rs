use async_trait::async_trait;
use redis::AsyncCommands;
use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

#[derive(Debug, thiserror::Error)]
pub enum HotStateError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("Lock contention or poisoned lock")]
    LockPoisoned,
    #[error("Hot state internal error: {0}")]
    Internal(String),
}

/// Abstract contract for high-throughput, sub-millisecond hot state operations:
/// sliding window counters, distinct item sets, and entity risk scores.
#[async_trait]
pub trait HotStateStore: Send + Sync {
    /// Record an event occurrence at timestamp_ms for the given key and evict older than window_ms.
    /// Returns the total count of occurrences currently inside the sliding window.
    async fn record_hit(
        &self,
        key: &str,
        timestamp_ms: i64,
        window_ms: i64,
    ) -> Result<u64, HotStateError>;

    /// Count events within the sliding window [current_time_ms - window_ms, current_time_ms].
    async fn count_in_window(
        &self,
        key: &str,
        window_ms: i64,
        current_time_ms: i64,
    ) -> Result<u64, HotStateError>;

    /// Record a distinct item in a set (e.g. distinct endpoint URLs or user agents probed).
    /// Returns the updated distinct count.
    async fn record_distinct(
        &self,
        set_key: &str,
        item: &str,
        ttl_secs: u64,
    ) -> Result<u64, HotStateError>;

    /// Count distinct items recorded for a set key.
    async fn count_distinct(&self, set_key: &str) -> Result<u64, HotStateError>;

    /// Retrieve the current accumulated risk score for an entity.
    async fn get_entity_risk(&self, entity_id: &str) -> Result<u32, HotStateError>;

    /// Accumulate risk points for an entity with TTL eviction. Returns the new risk score.
    async fn add_entity_risk(
        &self,
        entity_id: &str,
        points: u32,
        ttl_secs: u64,
    ) -> Result<u32, HotStateError>;

    /// Clear or reset a specific key.
    async fn reset_key(&self, key: &str) -> Result<(), HotStateError>;
}

/// In-Memory thread-safe sliding window and risk state store.
/// Zero-dependency, deterministic, sub-microsecond latency.
#[derive(Default)]
pub struct MemoryHotState {
    sliding_windows: RwLock<HashMap<String, VecDeque<i64>>>,
    distinct_sets: RwLock<HashMap<String, HashMap<String, i64>>>,
    entity_risks: RwLock<HashMap<String, (u32, i64)>>,
}

impl MemoryHotState {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl HotStateStore for MemoryHotState {
    async fn record_hit(
        &self,
        key: &str,
        timestamp_ms: i64,
        window_ms: i64,
    ) -> Result<u64, HotStateError> {
        let mut map = self
            .sliding_windows
            .write()
            .map_err(|_| HotStateError::LockPoisoned)?;
        let deque = map.entry(key.to_string()).or_default();

        let cutoff = timestamp_ms.saturating_sub(window_ms);
        while let Some(&oldest) = deque.front() {
            if oldest < cutoff {
                deque.pop_front();
            } else {
                break;
            }
        }
        deque.push_back(timestamp_ms);
        Ok(deque.len() as u64)
    }

    async fn count_in_window(
        &self,
        key: &str,
        window_ms: i64,
        current_time_ms: i64,
    ) -> Result<u64, HotStateError> {
        let map = self
            .sliding_windows
            .read()
            .map_err(|_| HotStateError::LockPoisoned)?;
        if let Some(deque) = map.get(key) {
            let cutoff = current_time_ms.saturating_sub(window_ms);
            let count = deque
                .iter()
                .filter(|&&ts| ts >= cutoff && ts <= current_time_ms)
                .count();
            Ok(count as u64)
        } else {
            Ok(0)
        }
    }

    async fn record_distinct(
        &self,
        set_key: &str,
        item: &str,
        ttl_secs: u64,
    ) -> Result<u64, HotStateError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let expiry_ms = now_ms + (ttl_secs as i64 * 1000);

        let mut map = self
            .distinct_sets
            .write()
            .map_err(|_| HotStateError::LockPoisoned)?;
        let set = map.entry(set_key.to_string()).or_default();

        set.retain(|_, &mut exp| exp > now_ms);
        set.insert(item.to_string(), expiry_ms);
        Ok(set.len() as u64)
    }

    async fn count_distinct(&self, set_key: &str) -> Result<u64, HotStateError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let map = self
            .distinct_sets
            .read()
            .map_err(|_| HotStateError::LockPoisoned)?;
        if let Some(set) = map.get(set_key) {
            let count = set.values().filter(|&&exp| exp > now_ms).count();
            Ok(count as u64)
        } else {
            Ok(0)
        }
    }

    async fn get_entity_risk(&self, entity_id: &str) -> Result<u32, HotStateError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let map = self
            .entity_risks
            .read()
            .map_err(|_| HotStateError::LockPoisoned)?;
        if let Some(&(score, exp)) = map.get(entity_id) {
            if exp > now_ms {
                Ok(score)
            } else {
                Ok(0)
            }
        } else {
            Ok(0)
        }
    }

    async fn add_entity_risk(
        &self,
        entity_id: &str,
        points: u32,
        ttl_secs: u64,
    ) -> Result<u32, HotStateError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let expiry_ms = now_ms + (ttl_secs as i64 * 1000);

        let mut map = self
            .entity_risks
            .write()
            .map_err(|_| HotStateError::LockPoisoned)?;
        let entry = map
            .entry(entity_id.to_string())
            .or_insert((0, expiry_ms));

        if entry.1 <= now_ms {
            entry.0 = points;
        } else {
            entry.0 = entry.0.saturating_add(points);
        }
        entry.1 = expiry_ms;
        Ok(entry.0)
    }

    async fn reset_key(&self, key: &str) -> Result<(), HotStateError> {
        if let Ok(mut map) = self.sliding_windows.write() {
            map.remove(key);
        }
        if let Ok(mut map) = self.distinct_sets.write() {
            map.remove(key);
        }
        if let Ok(mut map) = self.entity_risks.write() {
            map.remove(key);
        }
        Ok(())
    }
}

/// Redis-backed Hot State implementation for multi-node distributed deployments.
pub struct RedisHotState {
    client: redis::Client,
}

impl RedisHotState {
    pub fn new(redis_url: &str) -> Result<Self, HotStateError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self { client })
    }
}

#[async_trait]
impl HotStateStore for RedisHotState {
    async fn record_hit(
        &self,
        key: &str,
        timestamp_ms: i64,
        window_ms: i64,
    ) -> Result<u64, HotStateError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let cutoff = timestamp_ms.saturating_sub(window_ms);
        let member = format!("{}:{}", timestamp_ms, uuid::Uuid::new_v4());
        let expire_secs = (window_ms / 1000 + 10).max(30);

        let _: () = conn.zrembyscore(key, "-inf", cutoff).await?;
        let _: () = conn.zadd(key, member, timestamp_ms).await?;
        let _: () = conn.expire(key, expire_secs).await?;
        let count: u64 = conn.zcard(key).await?;
        Ok(count)
    }

    async fn count_in_window(
        &self,
        key: &str,
        window_ms: i64,
        current_time_ms: i64,
    ) -> Result<u64, HotStateError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let cutoff = current_time_ms.saturating_sub(window_ms);
        let count: u64 = conn.zcount(key, cutoff, current_time_ms).await?;
        Ok(count)
    }

    async fn record_distinct(
        &self,
        set_key: &str,
        item: &str,
        ttl_secs: u64,
    ) -> Result<u64, HotStateError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let _: () = conn.sadd(set_key, item).await?;
        let _: () = conn.expire(set_key, ttl_secs as i64).await?;
        let count: u64 = conn.scard(set_key).await?;
        Ok(count)
    }

    async fn count_distinct(&self, set_key: &str) -> Result<u64, HotStateError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let count: u64 = conn.scard(set_key).await?;
        Ok(count)
    }

    async fn get_entity_risk(&self, entity_id: &str) -> Result<u32, HotStateError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("risk:{}", entity_id);
        let val: Option<u32> = conn.get(key).await?;
        Ok(val.unwrap_or(0))
    }

    async fn add_entity_risk(
        &self,
        entity_id: &str,
        points: u32,
        ttl_secs: u64,
    ) -> Result<u32, HotStateError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("risk:{}", entity_id);
        let new_score: u32 = conn.incr(&key, points).await?;
        let _: () = conn.expire(&key, ttl_secs as i64).await?;
        Ok(new_score)
    }

    async fn reset_key(&self, key: &str) -> Result<(), HotStateError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let _: () = conn.del(key).await?;
        let risk_key = format!("risk:{}", key);
        let _: () = conn.del(risk_key).await?;
        Ok(())
    }
}
