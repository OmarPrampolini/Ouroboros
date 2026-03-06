//! Dandelion Relay - Anti-correlation aggregation for WAN Assist
//!
//! Aggregates multiple requests into batches to prevent timing correlation attacks
//! where a compromised relay could deanonymize which client is talking to which peer.

use crate::protocol_assist_v5::AssistRequestV5;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Dandelion batch aggregation state
#[derive(Clone)]
pub struct DandelionAggregator {
    // Pending requests per batch tag
    batches: Arc<Mutex<HashMap<[u8; 8], Batch>>>,
}

struct Batch {
    requests: Vec<(AssistRequestV5, SocketAddr)>,
    deadline: Instant,
}

type SocketAddr = std::net::SocketAddr;

#[derive(Debug, Clone, Copy)]
pub struct DandelionPolicy {
    pub min_delay_secs: u64,
    pub max_delay_secs: u64,
    pub target_batch_size: usize,
    pub fluff_tick_ms: u64,
}

impl DandelionPolicy {
    fn jitter_delay_secs(&self) -> u64 {
        if cfg!(test) {
            return 1;
        }

        if self.max_delay_secs <= self.min_delay_secs {
            return self.min_delay_secs;
        }

        rand::thread_rng().gen_range(self.min_delay_secs..=self.max_delay_secs)
    }
}

impl DandelionAggregator {
    pub fn new() -> Self {
        Self {
            batches: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Backward-compatible helper: defaults to low-latency dandelion profile.
    pub async fn add_request(
        &self,
        tag: [u8; 8],
        request: AssistRequestV5,
        from: SocketAddr,
    ) -> bool {
        self.add_request_with_mode(tag, request, from, DandelionMode::LowLatency)
            .await
    }

    /// Add request to batch. Returns true if this was the first request in the batch (sets deadline).
    ///
    /// Mode controls delay window and batch size threshold.
    pub async fn add_request_with_mode(
        &self,
        tag: [u8; 8],
        request: AssistRequestV5,
        from: SocketAddr,
        mode: DandelionMode,
    ) -> bool {
        let mut batches = self.batches.lock().await;
        let policy = mode.effective_policy();

        let is_first = !batches.contains_key(&tag);

        let batch = batches.entry(tag).or_insert_with(|| Batch {
            requests: Vec::new(),
            deadline: Instant::now() + Duration::from_secs(policy.jitter_delay_secs()),
        });

        batch.requests.push((request, from));

        // Security mode prefers larger batches; low-latency mode flushes earlier.
        if batch.requests.len() >= policy.target_batch_size {
            batch.deadline = Instant::now();
        }

        is_first
    }

    /// Get all batches that are ready to be forwarded (deadline passed)
    pub async fn ready_batches(&self) -> Vec<(Vec<(AssistRequestV5, SocketAddr)>, [u8; 8])> {
        let mut batches = self.batches.lock().await;
        let now = Instant::now();

        let mut ready = Vec::new();
        let mut to_remove = Vec::new();

        for (tag, batch) in batches.iter() {
            if now >= batch.deadline {
                ready.push((batch.requests.clone(), *tag));
                to_remove.push(*tag);
            }
        }

        // Clean up sent batches
        for tag in to_remove {
            batches.remove(&tag);
        }

        ready
    }

    /// Get current batch size for a tag
    pub async fn batch_size(&self, tag: [u8; 8]) -> usize {
        let batches = self.batches.lock().await;
        batches.get(&tag).map(|b| b.requests.len()).unwrap_or(0)
    }
}

impl Default for DandelionAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic dandelion tag from request id + tag16 context.
pub fn derive_dandelion_tag(request_id: [u8; 8], tag16: u16) -> [u8; 8] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dandelion-tag/v1");
    hasher.update(&request_id);
    hasher.update(&tag16.to_be_bytes());
    let hash = hasher.finalize();
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&hash.as_bytes()[..8]);
    tag
}

/// Generate a dandelion tag from a request or use provided one
pub fn dandelion_tag_for_request(req: &AssistRequestV5) -> [u8; 8] {
    if let Some(tag) = req.dandelion_tag {
        return tag;
    }

    derive_dandelion_tag(req.request_id, 0)
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.parse::<u64>().ok()
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok()?.parse::<usize>().ok()
}

/// Configuration for Dandelion mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DandelionMode {
    Off,          // No aggregation, immediate forwarding
    LowLatency,   // short delay, small batches
    HighSecurity, // long delay, larger batches
}

impl DandelionMode {
    pub fn from_env() -> Self {
        match std::env::var("HANDSHACKE_DANDELION_MODE") {
            Ok(raw) => match raw.to_lowercase().as_str() {
                "high" | "highsecurity" | "high_security" => DandelionMode::HighSecurity,
                "low" | "lowlatency" | "low_latency" => DandelionMode::LowLatency,
                "off" | "0" | "false" => DandelionMode::Off,
                _ => DandelionMode::Off,
            },
            Err(_) => DandelionMode::Off,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DandelionMode::Off => "off",
            DandelionMode::LowLatency => "low_latency",
            DandelionMode::HighSecurity => "high_security",
        }
    }

    pub fn stem_enabled(self) -> bool {
        self != DandelionMode::Off
    }

    pub fn policy(self) -> DandelionPolicy {
        match self {
            DandelionMode::Off => DandelionPolicy {
                min_delay_secs: 0,
                max_delay_secs: 0,
                target_batch_size: 1,
                fluff_tick_ms: 100,
            },
            DandelionMode::LowLatency => DandelionPolicy {
                min_delay_secs: 1,
                max_delay_secs: 3,
                target_batch_size: 3,
                fluff_tick_ms: 150,
            },
            DandelionMode::HighSecurity => DandelionPolicy {
                min_delay_secs: 8,
                max_delay_secs: 16,
                target_batch_size: 12,
                fluff_tick_ms: 1000,
            },
        }
    }

    /// Effective policy with optional runtime tuning from env.
    ///
    /// Supported overrides:
    /// - HANDSHACKE_DANDELION_MIN_DELAY_S
    /// - HANDSHACKE_DANDELION_MAX_DELAY_S
    /// - HANDSHACKE_DANDELION_BATCH_SIZE
    /// - HANDSHACKE_DANDELION_TICK_MS
    pub fn effective_policy(self) -> DandelionPolicy {
        let mut p = self.policy();
        if self == DandelionMode::Off {
            return p;
        }

        if let Some(v) = env_u64("HANDSHACKE_DANDELION_MIN_DELAY_S") {
            p.min_delay_secs = v;
        }
        if let Some(v) = env_u64("HANDSHACKE_DANDELION_MAX_DELAY_S") {
            p.max_delay_secs = v;
        }
        if let Some(v) = env_usize("HANDSHACKE_DANDELION_BATCH_SIZE") {
            p.target_batch_size = v;
        }
        if let Some(v) = env_u64("HANDSHACKE_DANDELION_TICK_MS") {
            p.fluff_tick_ms = v;
        }

        p.min_delay_secs = p.min_delay_secs.clamp(0, 120);
        p.max_delay_secs = p.max_delay_secs.clamp(p.min_delay_secs, 180);
        p.target_batch_size = p.target_batch_size.clamp(1, 64);
        p.fluff_tick_ms = p.fluff_tick_ms.clamp(50, 5000);
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dandelion_batching() {
        let aggregator = DandelionAggregator::new();
        let tag = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];

        // Add multiple requests to same batch
        for i in 0..2 {
            let mut req = AssistRequestV5 {
                request_id: [i; 8],
                blinded_candidates: Default::default(),
                ttl_ms: 5000,
                dandelion_stem: true,
                dandelion_tag: Some(tag),
                mac: [0u8; 32],
            };

            // Compute dummy MAC
            let mut mac = [0u8; 32];
            mac[0] = i;
            req.mac = mac;

            let port = 1000u16 + i as u16;
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            aggregator
                .add_request_with_mode(tag, req, addr, DandelionMode::LowLatency)
                .await;
        }

        // Should be empty immediately (not ready)
        let ready = aggregator.ready_batches().await;
        assert!(ready.is_empty());

        // Wait for deadline
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Now should be ready
        let ready = aggregator.ready_batches().await;
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].0.len(), 2);
    }

    #[test]
    fn test_dandelion_mode_policies_are_different() {
        let low = DandelionMode::LowLatency.policy();
        let high = DandelionMode::HighSecurity.policy();

        assert!(low.max_delay_secs < high.min_delay_secs);
        assert!(low.target_batch_size < high.target_batch_size);
        assert!(low.fluff_tick_ms < high.fluff_tick_ms);
    }

    #[test]
    fn test_derive_dandelion_tag_is_deterministic() {
        let id = [7u8; 8];
        let a = derive_dandelion_tag(id, 0x1337);
        let b = derive_dandelion_tag(id, 0x1337);
        let c = derive_dandelion_tag(id, 0x4242);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
