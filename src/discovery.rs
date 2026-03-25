use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

use crate::config::Config;

#[cfg(feature = "dht")]
mod kad;

#[cfg(feature = "dht")]
pub use kad::KadDiscoveryProvider;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("invalid announce ttl: {0}")]
    InvalidTtl(u64),
    #[error("backend error: {0}")]
    Backend(String),
}

type Result<T> = std::result::Result<T, DiscoveryError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryRecord {
    pub endpoint: SocketAddr,
    pub observed_at_ms: u64,
    pub ttl_ms: u64,
}

/// Deterministic namespace key used by discovery backends.
///
/// Derived from rendezvous primitives so peers sharing the same secret material map
/// into the same discovery space.
pub fn space_hash_from_rendezvous(port: u16, tag16: u16, key_enc: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"hs/discovery-space/v1");
    h.update(&port.to_le_bytes());
    h.update(&tag16.to_le_bytes());
    h.update(key_enc);
    *h.finalize().as_bytes()
}

/// Parse configured bootstrap peers (`host:port`) while skipping invalid entries.
pub fn parse_bootstrap_peers(peers: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for entry in peers {
        if let Ok(addr) = entry.parse::<SocketAddr>() {
            if !out.contains(&addr) {
                out.push(addr);
            }
        } else {
            tracing::warn!("Ignoring invalid discovery bootstrap peer: {}", entry);
        }
    }
    out
}

/// Parse a bootstrap endpoint hint from either `host:port` or `scheme://host:port`.
pub fn parse_endpoint_hint(endpoint: &str) -> Option<SocketAddr> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Some(addr);
    }

    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    without_scheme.parse::<SocketAddr>().ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapEndpointPreference {
    Balanced,
    BridgeFirst,
    KeeperFirst,
    RelayFirst,
}

/// Abstraction layer for discovery backends (LAN cache, relay index, DHT/Kademlia).
#[async_trait::async_trait]
pub trait DiscoveryProvider: Send + Sync {
    async fn announce(&self, space_hash: [u8; 32], record: DiscoveryRecord) -> Result<()>;
    async fn discover(&self, space_hash: [u8; 32], limit: usize) -> Result<Vec<SocketAddr>>;
}

/// Federated provider that fans out announces/discovery across multiple backends.
///
/// This provides a bootstrap-like behavior for multi-node environments while keeping
/// discovery backend-agnostic (LAN cache, relay index, DHT).
#[derive(Clone, Default)]
pub struct FederatedDiscovery {
    backends: Vec<Arc<dyn DiscoveryProvider>>,
}

impl FederatedDiscovery {
    pub fn new(backends: Vec<Arc<dyn DiscoveryProvider>>) -> Self {
        Self { backends }
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for FederatedDiscovery {
    async fn announce(&self, space_hash: [u8; 32], record: DiscoveryRecord) -> Result<()> {
        for backend in &self.backends {
            backend
                .announce(space_hash, record.clone())
                .await
                .map_err(|e| DiscoveryError::Backend(e.to_string()))?;
        }
        Ok(())
    }

    async fn discover(&self, space_hash: [u8; 32], limit: usize) -> Result<Vec<SocketAddr>> {
        let mut out = Vec::new();
        for backend in &self.backends {
            let discovered = backend
                .discover(space_hash, limit)
                .await
                .map_err(|e| DiscoveryError::Backend(e.to_string()))?;
            for addr in discovered {
                if !out.contains(&addr) {
                    out.push(addr);
                }
                if out.len() >= limit {
                    return Ok(out);
                }
            }
        }
        Ok(out)
    }
}

/// Higher-level discovery API with bootstrap fallback.
#[derive(Clone)]
pub struct DiscoveryService<P: DiscoveryProvider> {
    provider: P,
    bootstrap_peers: Vec<SocketAddr>,
}

impl<P: DiscoveryProvider> DiscoveryService<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            bootstrap_peers: Vec::new(),
        }
    }

    pub fn with_bootstrap_peers(provider: P, bootstrap_peers: Vec<SocketAddr>) -> Self {
        Self {
            provider,
            bootstrap_peers,
        }
    }

    pub async fn announce_endpoint(
        &self,
        space_hash: [u8; 32],
        endpoint: SocketAddr,
        observed_at_ms: u64,
        ttl_ms: u64,
    ) -> Result<()> {
        self.provider
            .announce(
                space_hash,
                DiscoveryRecord {
                    endpoint,
                    observed_at_ms,
                    ttl_ms,
                },
            )
            .await
    }

    pub async fn discover_endpoints(
        &self,
        space_hash: [u8; 32],
        limit: usize,
    ) -> Result<Vec<SocketAddr>> {
        let mut out = self.provider.discover(space_hash, limit).await?;
        if out.len() < limit {
            for peer in &self.bootstrap_peers {
                if !out.contains(peer) {
                    out.push(*peer);
                }
                if out.len() >= limit {
                    break;
                }
            }
        }
        out.truncate(limit);
        Ok(out)
    }
}

/// In-memory discovery cache used as local baseline and test backend.
#[derive(Clone, Default)]
pub struct InMemoryDiscovery {
    entries: Arc<RwLock<HashMap<[u8; 32], Vec<DiscoveryRecord>>>>,
}

impl InMemoryDiscovery {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for InMemoryDiscovery {
    async fn announce(&self, space_hash: [u8; 32], record: DiscoveryRecord) -> Result<()> {
        if record.ttl_ms == 0 {
            return Err(DiscoveryError::InvalidTtl(record.ttl_ms));
        }
        let mut guard = self.entries.write().await;
        let entry = guard.entry(space_hash).or_default();
        entry.retain(|r| r.endpoint != record.endpoint);
        entry.push(record);
        Ok(())
    }

    async fn discover(&self, space_hash: [u8; 32], limit: usize) -> Result<Vec<SocketAddr>> {
        let guard = self.entries.read().await;
        let mut out: Vec<SocketAddr> = guard
            .get(&space_hash)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.endpoint)
            .collect();
        out.truncate(limit);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// ORP-backed discovery provider
// ---------------------------------------------------------------------------

/// Discovery provider backed by the EtherSync ORP route cache.
///
/// `announce` is a no-op — route announcements are published independently via
/// [`ethersync::EtherNode::publish_route_announcement`].
///
/// `discover` returns direct-UDP endpoints from fresh ORP announcements whose
/// `space_prefix` (first 8 bytes of `RouteKey`) matches the requested
/// `space_hash` prefix — no cross-space leakage.
pub struct OrpDiscoveryProvider {
    route_cache: Arc<Mutex<ethersync::routing::RouteCache>>,
}

impl OrpDiscoveryProvider {
    pub fn new(route_cache: Arc<Mutex<ethersync::routing::RouteCache>>) -> Self {
        Self { route_cache }
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for OrpDiscoveryProvider {
    async fn announce(&self, _space_hash: [u8; 32], _record: DiscoveryRecord) -> Result<()> {
        // ORP announcements are handled by EtherNode — nothing to do here.
        Ok(())
    }

    async fn discover(&self, space_hash: [u8; 32], limit: usize) -> Result<Vec<SocketAddr>> {
        use ethersync::routing::ANNOUNCE_SLOT_LOOKBACK;
        use ethersync::EtherCoordinate;

        let current_slot = EtherCoordinate::current_slot();
        let min_slot = current_slot.saturating_sub(ANNOUNCE_SLOT_LOOKBACK);

        // Filter by the first 8 bytes of space_hash (= space_prefix).
        let mut target_prefix = [0u8; 8];
        target_prefix.copy_from_slice(&space_hash[..8]);

        let cache = self.route_cache.lock().await;
        let addrs: Vec<SocketAddr> = cache
            .announcements
            .iter()
            .filter(|(key, ann)| {
                key.space_prefix == target_prefix
                    && ann.frame.slot >= min_slot
                    && ann.frame.capabilities.direct_udp
            })
            .flat_map(|(_, ann)| ann.frame.reachable_udp.iter().cloned())
            .take(limit)
            .collect();

        Ok(addrs)
    }
}

/// Discovery provider backed by a managed bootstrap bundle.
pub struct BootstrapDiscoveryProvider {
    endpoints: Vec<BootstrapEndpointRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootstrapEndpointClass {
    Relay,
    Bridge,
    Keeper,
}

#[derive(Clone, Debug)]
struct BootstrapEndpointRecord {
    addr: SocketAddr,
    class: BootstrapEndpointClass,
    operator_id_hint: String,
    region_hint: String,
}

impl BootstrapDiscoveryProvider {
    pub fn from_bundle(bundle: &crate::bootstrap_bundle::BootstrapBundle) -> Self {
        Self::from_bundle_with_preference(bundle, BootstrapEndpointPreference::Balanced)
    }

    pub fn from_bundle_with_preference(
        bundle: &crate::bootstrap_bundle::BootstrapBundle,
        preference: BootstrapEndpointPreference,
    ) -> Self {
        let cfg = Config::from_env();
        let mut endpoints = Vec::new();
        for relay in &bundle.relays {
            if let Some(addr) = parse_endpoint_hint(&relay.addr) {
                if !endpoints
                    .iter()
                    .any(|entry: &BootstrapEndpointRecord| entry.addr == addr)
                {
                    endpoints.push(BootstrapEndpointRecord {
                        addr,
                        class: BootstrapEndpointClass::Relay,
                        operator_id_hint: relay.operator_id.clone().unwrap_or_default(),
                        region_hint: relay.region.clone().unwrap_or_default(),
                    });
                }
            }
        }
        for bridge in &bundle.bridges {
            if let Some(addr) = parse_endpoint_hint(&bridge.endpoint) {
                if !endpoints
                    .iter()
                    .any(|entry: &BootstrapEndpointRecord| entry.addr == addr)
                {
                    endpoints.push(BootstrapEndpointRecord {
                        addr,
                        class: BootstrapEndpointClass::Bridge,
                        operator_id_hint: bridge.operator_id.clone().unwrap_or_default(),
                        region_hint: bridge.region.clone().unwrap_or_default(),
                    });
                }
            }
        }
        for keeper in &bundle.keepers {
            if let Some(addr) = parse_endpoint_hint(&keeper.endpoint) {
                if !endpoints
                    .iter()
                    .any(|entry: &BootstrapEndpointRecord| entry.addr == addr)
                {
                    endpoints.push(BootstrapEndpointRecord {
                        addr,
                        class: BootstrapEndpointClass::Keeper,
                        operator_id_hint: keeper.operator_id.clone().unwrap_or_default(),
                        region_hint: keeper.region.clone().unwrap_or_default(),
                    });
                }
            }
        }

        endpoints.sort_by(|a, b| {
            bootstrap_preference_rank(preference, a.class)
                .cmp(&bootstrap_preference_rank(preference, b.class))
                .then_with(|| {
                    bootstrap_operator_policy_rank(preference, &cfg, a)
                        .cmp(&bootstrap_operator_policy_rank(preference, &cfg, b))
                })
                .then_with(|| {
                    bootstrap_region_policy_rank(preference, &cfg, a)
                        .cmp(&bootstrap_region_policy_rank(preference, &cfg, b))
                })
                .then_with(|| bootstrap_hint_presence_rank(a).cmp(&bootstrap_hint_presence_rank(b)))
                .then_with(|| a.addr.to_string().cmp(&b.addr.to_string()))
        });

        Self { endpoints }
    }
}

fn bootstrap_preference_rank(
    preference: BootstrapEndpointPreference,
    class: BootstrapEndpointClass,
) -> u8 {
    match preference {
        BootstrapEndpointPreference::Balanced | BootstrapEndpointPreference::RelayFirst => {
            match class {
                BootstrapEndpointClass::Relay => 0,
                BootstrapEndpointClass::Bridge => 1,
                BootstrapEndpointClass::Keeper => 2,
            }
        }
        BootstrapEndpointPreference::BridgeFirst => match class {
            BootstrapEndpointClass::Bridge => 0,
            BootstrapEndpointClass::Relay => 1,
            BootstrapEndpointClass::Keeper => 2,
        },
        BootstrapEndpointPreference::KeeperFirst => match class {
            BootstrapEndpointClass::Keeper => 0,
            BootstrapEndpointClass::Bridge => 1,
            BootstrapEndpointClass::Relay => 2,
        },
    }
}

fn bootstrap_operator_policy_rank(
    preference: BootstrapEndpointPreference,
    cfg: &Config,
    entry: &BootstrapEndpointRecord,
) -> u8 {
    let operator = entry.operator_id_hint.trim();
    let is_local_operator =
        !operator.is_empty() && operator.eq_ignore_ascii_case(cfg.operator_id.trim());

    match preference {
        BootstrapEndpointPreference::BridgeFirst
            if entry.class == BootstrapEndpointClass::Bridge =>
        {
            if operator.is_empty() {
                1
            } else if is_local_operator {
                2
            } else {
                0
            }
        }
        BootstrapEndpointPreference::KeeperFirst
            if entry.class == BootstrapEndpointClass::Keeper =>
        {
            if operator.is_empty() {
                1
            } else if is_local_operator {
                2
            } else {
                0
            }
        }
        _ => {
            if operator.is_empty() {
                2
            } else if is_local_operator {
                1
            } else {
                0
            }
        }
    }
}

fn bootstrap_region_policy_rank(
    preference: BootstrapEndpointPreference,
    cfg: &Config,
    entry: &BootstrapEndpointRecord,
) -> u8 {
    let region = entry.region_hint.trim();
    let is_local_region =
        !region.is_empty() && region.eq_ignore_ascii_case(cfg.operator_region.trim());

    match preference {
        BootstrapEndpointPreference::BridgeFirst
            if entry.class == BootstrapEndpointClass::Bridge =>
        {
            if region.is_empty() {
                1
            } else if is_local_region {
                2
            } else {
                0
            }
        }
        BootstrapEndpointPreference::KeeperFirst
            if entry.class == BootstrapEndpointClass::Keeper =>
        {
            if region.is_empty() {
                1
            } else if is_local_region {
                2
            } else {
                0
            }
        }
        _ => {
            if region.is_empty() || is_local_region {
                1
            } else {
                0
            }
        }
    }
}

fn bootstrap_hint_presence_rank(entry: &BootstrapEndpointRecord) -> u8 {
    let operator_present = !entry.operator_id_hint.trim().is_empty();
    let region_present = !entry.region_hint.trim().is_empty();

    match (operator_present, region_present) {
        (true, true) => 0,
        (true, false) | (false, true) => 1,
        (false, false) => 2,
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for BootstrapDiscoveryProvider {
    async fn announce(&self, _space_hash: [u8; 32], _record: DiscoveryRecord) -> Result<()> {
        Ok(())
    }

    async fn discover(&self, _space_hash: [u8; 32], limit: usize) -> Result<Vec<SocketAddr>> {
        Ok(self
            .endpoints
            .iter()
            .map(|entry| entry.addr)
            .take(limit)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_discovery_roundtrip() {
        let discovery = InMemoryDiscovery::new();
        let space = [7u8; 32];
        let endpoint: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        discovery
            .announce(
                space,
                DiscoveryRecord {
                    endpoint,
                    observed_at_ms: 1,
                    ttl_ms: 30_000,
                },
            )
            .await
            .unwrap();

        let found = discovery.discover(space, 8).await.unwrap();
        assert_eq!(found, vec![endpoint]);
    }

    #[tokio::test]
    async fn announce_rejects_zero_ttl() {
        let discovery = InMemoryDiscovery::new();
        let res = discovery
            .announce(
                [1u8; 32],
                DiscoveryRecord {
                    endpoint: "127.0.0.1:9".parse().unwrap(),
                    observed_at_ms: 1,
                    ttl_ms: 0,
                },
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn federated_discovery_multinode_roundtrip() {
        let node_a = Arc::new(InMemoryDiscovery::new());
        let node_b = Arc::new(InMemoryDiscovery::new());
        let node_c = Arc::new(InMemoryDiscovery::new());

        let mesh = FederatedDiscovery::new(vec![node_a.clone(), node_b.clone(), node_c.clone()]);

        let space = [0x42u8; 32];
        let endpoint: SocketAddr = "10.10.10.10:4242".parse().unwrap();

        mesh.announce(
            space,
            DiscoveryRecord {
                endpoint,
                observed_at_ms: 10,
                ttl_ms: 30_000,
            },
        )
        .await
        .unwrap();

        let found_a = node_a.discover(space, 8).await.unwrap();
        let found_b = node_b.discover(space, 8).await.unwrap();
        let found_c = node_c.discover(space, 8).await.unwrap();

        assert_eq!(found_a, vec![endpoint]);
        assert_eq!(found_b, vec![endpoint]);
        assert_eq!(found_c, vec![endpoint]);

        let merged = mesh.discover(space, 8).await.unwrap();
        assert_eq!(merged, vec![endpoint]);
    }

    #[test]
    fn rendezvous_space_hash_is_deterministic() {
        let key = [3u8; 32];
        let a = space_hash_from_rendezvous(3333, 0x1337, &key);
        let b = space_hash_from_rendezvous(3333, 0x1337, &key);
        let c = space_hash_from_rendezvous(3334, 0x1337, &key);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[tokio::test]
    async fn discovery_service_uses_bootstrap_fallback() {
        let local = InMemoryDiscovery::new();
        let bootstrap: SocketAddr = "203.0.113.10:7700".parse().unwrap();
        let service = DiscoveryService::with_bootstrap_peers(local, vec![bootstrap]);

        let found = service.discover_endpoints([9u8; 32], 4).await.unwrap();
        assert_eq!(found, vec![bootstrap]);
    }

    #[test]
    fn parse_bootstrap_peers_skips_invalid_and_dedups() {
        let peers = vec![
            "127.0.0.1:7000".to_string(),
            "127.0.0.1:7000".to_string(),
            "not-a-peer".to_string(),
            "192.0.2.5:7001".to_string(),
        ];
        let parsed = parse_bootstrap_peers(&peers);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], "127.0.0.1:7000".parse::<SocketAddr>().unwrap());
        assert_eq!(parsed[1], "192.0.2.5:7001".parse::<SocketAddr>().unwrap());
    }
}
