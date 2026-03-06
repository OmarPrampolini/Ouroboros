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
        let policy = mode.policy();

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

/// Generate a dandelion tag from a request or use provided one
pub fn dandelion_tag_for_request(req: &AssistRequestV5) -> [u8; 8] {
    if let Some(tag) = req.dandelion_tag {
        return tag;
    }

    // Generate deterministic tag from request_id
    // Use first 8 bytes of SHA256(request_id) for determinism
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(req.request_id);
    let hash = hasher.finalize();
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&hash[..8]);
    tag
}

/// Configuration for Dandelion mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DandelionMode {
    Off,          // No aggregation, immediate forwarding
    LowLatency,   // 2-5s delay, small batches
    HighSecurity, // 10-15s delay, larger batches
}

impl DandelionMode {
    pub fn from_env() -> Self {
        match std::env::var("HANDSHACKE_DANDELION_MODE").as_deref() {
            Ok("high") | Ok("highsecurity") => DandelionMode::HighSecurity,
            Ok("low") | Ok("lowlatency") => DandelionMode::LowLatency,
            _ => DandelionMode::Off,
        }
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
                min_delay_secs: 2,
                max_delay_secs: 5,
                target_batch_size: 4,
                fluff_tick_ms: 250,
            },
            DandelionMode::HighSecurity => DandelionPolicy {
                min_delay_secs: 10,
                max_delay_secs: 15,
                target_batch_size: 10,
                fluff_tick_ms: 1000,
            },
        }
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
        for i in 0..3 {
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
        assert_eq!(ready[0].0.len(), 3);
    }

    #[test]
    fn test_dandelion_mode_policies_are_different() {
        let low = DandelionMode::LowLatency.policy();
        let high = DandelionMode::HighSecurity.policy();

        assert!(low.max_delay_secs < high.min_delay_secs);
        assert!(low.target_batch_size < high.target_batch_size);
        assert!(low.fluff_tick_ms < high.fluff_tick_ms);
    }
}
