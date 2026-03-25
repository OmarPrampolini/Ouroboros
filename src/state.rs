use crate::security::RateLimiter;
use base64::{engine::general_purpose, Engine as _};
use ethersync::coordinate::LOOKBACK_SLOTS;
use ethersync::{EtherCoordinate, EtherNode, NodeConfig};
use ouroboros_crypto::derive::canonicalize_passphrase;
use ouroboros_crypto::hash::blake3_hash;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;
use zeroize::Zeroize;

use crate::bootstrap_bundle::{BootstrapBundleSummary, BootstrapBundleValidationReport};
use crate::config::PrivacyProfile;

pub mod connection_manager;
pub mod metrics;

pub use connection_manager::{
    CircuitBreakerStatus, CircuitState, ConnectionCircuitBreaker, ConnectionFsmState,
    ConnectionManager,
};
pub use metrics::{ConnectionMetrics, CryptoTimer, DebugMetrics, MetricsCollector};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionState {
    pub status: ConnectionStatus,
    pub mode: Option<String>,
    pub port: Option<u16>,
    pub peer_address: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub privacy_profile: PrivacyProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PhraseStatus {
    Closed,
    Opening,
    Open,
    Connected,
    Error(String),
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            status: ConnectionStatus::Disconnected,
            mode: None,
            port: None,
            peer_address: None,
            bytes_sent: 0,
            bytes_received: 0,
            privacy_profile: PrivacyProfile::StandardPrivate,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Mutex<InnerState>>,
}

#[derive(Debug, Clone)]
pub struct EtherSyncStartConfig {
    pub bind_addr: String,
    pub bootstrap_peers: Vec<SocketAddr>,
    pub gossip_interval_secs: u64,
    pub sweep_interval_secs: u64,
    pub gossip_ttl: u8,
    pub enable_compression: bool,
    /// Enable ORP route discovery as a transport fallback before Tor.
    pub enable_orp: bool,
}

impl Default for EtherSyncStartConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".to_string(),
            bootstrap_peers: Vec::new(),
            gossip_interval_secs: 30,
            sweep_interval_secs: 10,
            gossip_ttl: 3,
            enable_compression: true,
            enable_orp: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EtherSyncStatus {
    pub running: bool,
    pub bind_addr: Option<String>,
    pub local_addr: Option<String>,
    pub peer_count: usize,
    pub subscription_count: usize,
    pub spaces: Vec<String>,
    /// Whether ORP is enabled for this runtime.
    pub orp_enabled: bool,
    /// Total number of route announcements currently in the route cache.
    pub route_cache_size: usize,
    /// Total number of route offers cached (across all lookup ids).
    pub route_offers_count: usize,
    /// UNIX timestamp (ms) of the most recently seen route announcement,
    /// or `None` if the cache is empty or the node is not running.
    pub last_orp_activity_ms: Option<u64>,
    /// Current retention tier exposed by the runtime.
    pub retention_tier: String,
    /// Number of slots scanned during local replay.
    pub replay_window_slots: usize,
    /// Whether keeper-backed encrypted replication is active.
    pub keeper_replication_enabled: bool,
    /// Configured replication factor for keeper-backed retention.
    pub keeper_replication_factor: usize,
    /// Count of bootstrap peers configured for the running EtherSync node.
    pub bootstrap_peer_count: usize,
    /// Count of discovery bootstrap peers configured for the main runtime.
    pub discovery_bootstrap_peer_count: usize,
    /// Whether a bridge bootstrap path is currently available.
    pub bridge_bootstrap_enabled: bool,
    /// Count of configured assist/bridge hints visible to the runtime.
    pub bridge_hint_count: usize,
    /// Whether the high-risk profile is available for activation.
    pub high_risk_available: bool,
    /// Blocking reasons preventing the high-risk profile from being enabled.
    pub high_risk_gate_reasons: Vec<String>,
    /// Number of high-risk circuits observed or locally prepared.
    pub high_risk_circuits_observed: usize,
    /// Number of high-risk circuits still considered active.
    pub high_risk_active_circuits: usize,
    /// Number of high-risk circuits explicitly closed or no longer active.
    pub high_risk_closed_circuits: usize,
    /// Number of high-risk control frames observed across tracked circuits.
    pub high_risk_control_frames_observed: usize,
    /// Number of high-risk cover packets observed across tracked circuits.
    pub high_risk_cover_packets_observed: usize,
    /// Most recent high-risk circuit activity timestamp across tracked circuits.
    pub high_risk_last_activity_ms: Option<u64>,
    /// Operator identity hint surfaced by the running node.
    pub operator_id_hint: String,
    /// Operator region hint surfaced by the running node.
    pub operator_region_hint: String,
    /// Whether a bootstrap bundle was successfully loaded.
    pub bootstrap_bundle_loaded: bool,
    /// Number of mirror endpoints in the loaded bootstrap bundle.
    pub bootstrap_bundle_mirrors: usize,
    /// Number of relay descriptors in the loaded bootstrap bundle.
    pub bootstrap_bundle_relays: usize,
    /// Number of bridge descriptors in the loaded bootstrap bundle.
    pub bootstrap_bundle_bridges: usize,
    /// Number of keeper descriptors in the loaded bootstrap bundle.
    pub bootstrap_bundle_keepers: usize,
    /// Whether the loaded bootstrap bundle is locally considered usable.
    pub bootstrap_bundle_usable: bool,
    /// Whether the loaded bootstrap bundle has structural warnings.
    pub bootstrap_bundle_structurally_weak: bool,
    /// Whether the loaded bootstrap bundle is locally considered stale.
    pub bootstrap_bundle_stale: bool,
    /// Number of bootstrap bundle validation warnings.
    pub bootstrap_bundle_warning_count: usize,
    /// Number of bootstrap bundle validation errors.
    pub bootstrap_bundle_error_count: usize,
    /// Count of locally queued keeper envelopes awaiting backfill/replication.
    pub pending_keeper_envelopes: usize,
    /// Number of spaces that currently have pending keeper envelopes.
    pub keeper_space_count: usize,
    /// Count of encrypted envelopes present in the keeper replica archive.
    pub archived_keeper_envelopes: usize,
    /// Number of spaces currently represented in the keeper replica archive.
    pub keeper_archive_space_count: usize,
    /// Number of spaces with a keeper manifest actively tracked by the runtime.
    pub keeper_manifest_space_count: usize,
    /// Number of managed spaces whose desired keeper targets exceed local candidate capacity.
    pub keeper_candidate_shortfall_space_count: usize,
    /// Number of managed spaces that have at least one keeper candidate available.
    pub managed_ready_space_count: usize,
    /// Most recent keeper-related local activity timestamp across all spaces.
    pub last_keeper_activity_ms: Option<u64>,
    /// Number of spaces whose policy enables managed keeper replication.
    pub managed_space_count: usize,
    /// Number of spaces whose route bias prefers bridge-capable paths.
    pub bridge_preferred_space_count: usize,
    /// Number of spaces whose route bias prefers keeper-capable paths.
    pub keeper_preferred_space_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EtherSyncJoinResult {
    pub space_id: String,
    pub retention_tier: String,
    pub replication_factor: usize,
    pub route_bias: String,
    pub keeper_manifest: KeeperSpaceManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpaceRouteBias {
    Balanced,
    BridgePreferred,
    KeeperPreferred,
    DirectPreferred,
}

impl SpaceRouteBias {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::BridgePreferred => "bridge-preferred",
            Self::KeeperPreferred => "keeper-preferred",
            Self::DirectPreferred => "direct-preferred",
        }
    }

    fn from_optional(raw: Option<&str>) -> Self {
        match raw.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
            "bridge" | "bridge-preferred" => Self::BridgePreferred,
            "keeper" | "keeper-preferred" => Self::KeeperPreferred,
            "direct" | "direct-preferred" => Self::DirectPreferred,
            _ => Self::Balanced,
        }
    }
}

#[derive(Debug, Clone)]
struct EtherSpacePolicy {
    retention_tier: String,
    replication_factor: usize,
    route_bias: SpaceRouteBias,
}

#[derive(Debug, Clone, Serialize)]
pub struct EtherSyncPublishResult {
    pub space_id: String,
    pub slot_id: u64,
    pub payload_len: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EtherSyncFilePublishResult {
    pub space_id: String,
    pub transfer_id: String,
    pub filename: String,
    pub total_bytes: usize,
    pub total_chunks: usize,
    pub published_chunks: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeeperBackfillResult {
    pub space_id: String,
    pub restored_messages: usize,
    pub remaining_pending: usize,
    pub keeper_manifest: KeeperSpaceManifest,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpacePolicySnapshot {
    pub space_key: String,
    pub retention_tier: String,
    pub replication_factor: usize,
    pub route_bias: String,
    pub pending_keeper_envelopes: usize,
    pub archived_keeper_envelopes: usize,
    pub keeper_manifest: KeeperSpaceManifest,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeeperSpaceManifest {
    pub managed: bool,
    pub keeper_route_intent: String,
    pub desired_replica_count: usize,
    pub available_keeper_candidates: usize,
    pub selected_keeper_targets: usize,
    pub candidate_shortfall: usize,
    pub replication_stage: String,
    pub last_local_activity_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EtherSyncFileChunkEnvelope {
    kind: String,
    transfer_id: String,
    filename: String,
    total_bytes: usize,
    chunk_index: usize,
    total_chunks: usize,
    chunk_b64: String,
}

#[derive(Debug, Serialize)]
struct EtherSyncEvent {
    kind: String,
    ts_ms: u64,
    space_id: Option<String>,
    slot_id: Option<u64>,
    payload_b64: Option<String>,
    text: Option<String>,
    info: Option<String>,
    error: Option<String>,
}

struct EtherSyncRuntime {
    node: Arc<EtherNode>,
    bind_addr: String,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    run_task: JoinHandle<()>,
    keeper_replication_task: Option<JoinHandle<()>>,
    subscriptions: HashMap<String, JoinHandle<()>>,
    events_tx: broadcast::Sender<String>,
    /// Whether ORP was enabled when this runtime was started.
    enable_orp: bool,
    bootstrap_peer_count: usize,
    retention_tier: String,
    keeper_replication_enabled: bool,
    keeper_replication_factor: usize,
    bridge_hint_count: usize,
    operator_id_hint: String,
    operator_region_hint: String,
    bootstrap_bundle: BootstrapBundleSummary,
    bootstrap_bundle_validation: Option<BootstrapBundleValidationReport>,
    keeper_envelopes: Arc<Mutex<HashMap<String, Vec<KeeperEnvelopeRecord>>>>,
    keeper_archive: Arc<Mutex<HashMap<String, Vec<KeeperEnvelopeRecord>>>>,
    keeper_last_activity: Arc<Mutex<HashMap<String, u64>>>,
    space_policies: Arc<Mutex<HashMap<String, EtherSpacePolicy>>>,
}

#[derive(Debug, Clone)]
struct KeeperEnvelopeRecord {
    slot_id: u64,
    message: ethersync::EtherMessage,
}

#[derive(Debug, Clone, Default)]
struct DiscoverySeedReport {
    discovered: usize,
    used_orp: bool,
    used_bootstrap_bundle: bool,
    used_static_bootstrap: bool,
    bundle_usable: bool,
    bundle_stale: bool,
    bundle_relay_candidates: usize,
    bundle_bridge_candidates: usize,
    bundle_keeper_candidates: usize,
    route_bias: String,
}

#[derive(Debug, Clone, Default)]
struct KeeperReplicationFlush {
    moved: usize,
    touched_spaces: usize,
}

const ETHERSYNC_FILE_CHUNK_DEFAULT: usize = 1024;
const ETHERSYNC_FILE_CHUNK_MIN: usize = 256;
const ETHERSYNC_FILE_CHUNK_MAX: usize = 12_288;

impl Default for AppState {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerState {
                connection_state: ConnectionState::default(),
                tx_out: None,
                key_enc: None,
                tag16: None,
                tag8: None,
                port: None,
                wan_keepalive_socket: None,
                stop_tx: None,
                api_rate_limiter: RateLimiter::new(10_000, 200, Duration::from_secs(4)),
                metrics: MetricsCollector::new(),
                phrase_status: PhraseStatus::Closed,
                phrase_onion: None,
                phrase_listener: None,
                phrase_accept_task: None,
                tor_session: None,
                ethersync: None,
            })),
        }
    }
}

struct InnerState {
    connection_state: ConnectionState,
    tx_out: Option<mpsc::Sender<Vec<u8>>>,
    #[allow(dead_code)]
    key_enc: Option<[u8; 32]>,
    tag16: Option<u16>,
    tag8: Option<u8>,
    #[allow(dead_code)]
    port: Option<u16>,
    wan_keepalive_socket: Option<Arc<UdpSocket>>,
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
    api_rate_limiter: RateLimiter,
    metrics: MetricsCollector, // In-memory metrics (zero persistence)
    phrase_status: PhraseStatus,
    phrase_onion: Option<String>,
    phrase_listener: Option<Arc<TcpListener>>,
    phrase_accept_task: Option<JoinHandle<()>>,
    tor_session: Option<Arc<tokio::sync::Mutex<crate::tor::managed::ManagedTor>>>,
    ethersync: Option<EtherSyncRuntime>,
}

impl Drop for InnerState {
    fn drop(&mut self) {
        // Zeroize sensitive data
        if let Some(mut key) = self.key_enc.take() {
            key.zeroize();
        }
    }
}

impl AppState {
    pub async fn set_connection_state(&self, state: ConnectionState) {
        let mut inner = self.inner.lock().await;
        inner.connection_state = state;
    }

    pub async fn get_connection_state(&self) -> ConnectionState {
        let inner = self.inner.lock().await;
        inner.connection_state.clone()
    }

    pub async fn update_stats(&self, sent: u64, received: u64) {
        let mut inner = self.inner.lock().await;
        inner.connection_state.bytes_sent += sent;
        inner.connection_state.bytes_received += received;
    }

    pub async fn set_tx_out(&self, tx: mpsc::Sender<Vec<u8>>) {
        let mut inner = self.inner.lock().await;
        inner.tx_out = Some(tx);
    }

    pub async fn get_tx_out(&self) -> Option<mpsc::Sender<Vec<u8>>> {
        let inner = self.inner.lock().await;
        inner.tx_out.clone()
    }

    pub async fn set_crypto_params(&self, key: [u8; 32], tag16: u16, tag8: u8) {
        let mut inner = self.inner.lock().await;
        inner.key_enc = Some(key);
        inner.tag16 = Some(tag16);
        inner.tag8 = Some(tag8);
    }

    pub async fn get_crypto_params(&self) -> Option<([u8; 32], u16, u8)> {
        let inner = self.inner.lock().await;
        Some((inner.key_enc?, inner.tag16?, inner.tag8?))
    }

    pub async fn clear_crypto_params(&self) {
        let mut inner = self.inner.lock().await;
        if let Some(mut k) = inner.key_enc.take() {
            use zeroize::Zeroize;
            k.zeroize();
        }
        inner.tag16 = None;
        inner.tag8 = None;
    }

    /// Get metrics collector (in-memory only)
    pub async fn get_metrics(&self) -> MetricsCollector {
        let inner = self.inner.lock().await;
        inner.metrics.clone()
    }

    pub async fn api_allow(&self, ip: IpAddr, cost: f64) -> bool {
        let limiter = {
            let inner = self.inner.lock().await;
            inner.api_rate_limiter.clone()
        };
        limiter.check_cost(SocketAddr::new(ip, 0), cost).await
    }

    /// Return the active EtherNode if ORP is enabled, for use with
    /// `establish_connection_with_orp`.
    pub async fn orp_node(&self) -> Option<Arc<EtherNode>> {
        let inner = self.inner.lock().await;
        let rt = inner.ethersync.as_ref()?;
        if rt.enable_orp {
            Some(rt.node.clone())
        } else {
            None
        }
    }

    pub async fn orp_space_route_bias(&self, passphrase: &str) -> Option<SpaceRouteBias> {
        let policies = {
            let inner = self.inner.lock().await;
            let rt = inner.ethersync.as_ref()?;
            rt.space_policies.clone()
        };
        let space_key = derive_space_key(passphrase);
        let route_bias = {
            let guard = policies.lock().await;
            guard
                .get(&space_key)
                .map(|policy| policy.route_bias.clone())
        };
        route_bias
    }

    pub async fn set_stop_tx(&self, tx: tokio::sync::watch::Sender<bool>) {
        let mut inner = self.inner.lock().await;
        inner.stop_tx = Some(tx);
    }

    pub async fn set_wan_keepalive_socket(&self, sock: Arc<UdpSocket>) {
        let mut inner = self.inner.lock().await;
        inner.wan_keepalive_socket = Some(sock);
    }

    pub async fn clear_wan_keepalive_socket(&self) {
        let mut inner = self.inner.lock().await;
        inner.wan_keepalive_socket = None;
    }

    pub async fn stop_all(&self) {
        let inner = self.inner.lock().await;
        if let Some(stop_tx) = &inner.stop_tx {
            let _ = stop_tx.send(true);
        }
    }

    pub async fn get_stop_rx(&self) -> Option<tokio::sync::watch::Receiver<bool>> {
        let inner = self.inner.lock().await;
        inner.stop_tx.as_ref().map(|tx| tx.subscribe())
    }

    pub async fn set_phrase_status(&self, status: PhraseStatus) {
        let mut inner = self.inner.lock().await;
        inner.phrase_status = status;
    }

    pub async fn get_phrase_status(&self) -> PhraseStatus {
        let inner = self.inner.lock().await;
        inner.phrase_status.clone()
    }

    pub async fn set_phrase_onion(&self, onion: Option<String>) {
        let mut inner = self.inner.lock().await;
        inner.phrase_onion = onion;
    }

    pub async fn get_phrase_onion(&self) -> Option<String> {
        let inner = self.inner.lock().await;
        inner.phrase_onion.clone()
    }

    pub async fn set_phrase_listener(&self, listener: Option<Arc<TcpListener>>) {
        let mut inner = self.inner.lock().await;
        inner.phrase_listener = listener;
    }

    pub async fn take_phrase_listener(&self) -> Option<Arc<TcpListener>> {
        let mut inner = self.inner.lock().await;
        inner.phrase_listener.take()
    }

    pub async fn set_phrase_accept_task(&self, task: Option<JoinHandle<()>>) {
        let mut inner = self.inner.lock().await;
        inner.phrase_accept_task = task;
    }

    pub async fn take_phrase_accept_task(&self) -> Option<JoinHandle<()>> {
        let mut inner = self.inner.lock().await;
        inner.phrase_accept_task.take()
    }

    pub async fn get_or_start_tor(
        &self,
        cfg: &crate::config::Config,
    ) -> anyhow::Result<Arc<tokio::sync::Mutex<crate::tor::managed::ManagedTor>>> {
        let existing = {
            let inner = self.inner.lock().await;
            inner.tor_session.clone()
        };
        if let Some(tor) = existing {
            return Ok(tor);
        }

        let tor = crate::tor::managed::ManagedTor::start(cfg.tor_bin_path.as_deref()).await?;
        let tor = Arc::new(tokio::sync::Mutex::new(tor));

        let mut inner = self.inner.lock().await;
        if let Some(existing) = &inner.tor_session {
            return Ok(existing.clone());
        }
        inner.tor_session = Some(tor.clone());
        Ok(tor)
    }

    pub async fn ethersync_start(
        &self,
        cfg: EtherSyncStartConfig,
    ) -> anyhow::Result<EtherSyncStatus> {
        {
            let inner = self.inner.lock().await;
            if inner.ethersync.is_some() {
                return Err(anyhow::anyhow!("ethersync already running"));
            }
        }

        let runtime_cfg = crate::config::Config::from_env();
        let bootstrap_bundle_validation =
            crate::bootstrap_bundle::validate_loaded_bootstrap_bundle(&runtime_cfg);
        let bootstrap_bundle = bootstrap_bundle_validation
            .as_ref()
            .map(|report| report.summary.clone())
            .unwrap_or_default();
        let resolved_bootstrap_peers =
            resolve_initial_bootstrap_peers(&runtime_cfg, &cfg.bootstrap_peers);
        let bootstrap_peer_count = resolved_bootstrap_peers.len();
        let node_cfg = NodeConfig {
            bind_addr: cfg.bind_addr.clone(),
            bootstrap_peers: resolved_bootstrap_peers,
            gossip_interval_secs: cfg.gossip_interval_secs.max(1),
            sweep_interval_secs: cfg.sweep_interval_secs.max(1),
            gossip_ttl: cfg.gossip_ttl.max(1),
            enable_compression: cfg.enable_compression,
            enable_orp: cfg.enable_orp,
            orp_can_relay: runtime_cfg.operator_can_relay,
            orp_wan_assist: !runtime_cfg.assist_relays.is_empty(),
            orp_tor_capable: runtime_cfg.wan_mode != crate::config::WanMode::Direct
                || runtime_cfg.tor_bin_path.is_some()
                || runtime_cfg.tor_onion_addr.is_some(),
            orp_bridge_capable: runtime_cfg.operator_bridge_capable,
            orp_keeper_capable: runtime_cfg.operator_keeper_capable,
            orp_operator_id_hint: runtime_cfg.operator_id.clone(),
            orp_region_hint: runtime_cfg.operator_region.clone(),
            ..NodeConfig::default()
        };

        let node = Arc::new(
            EtherNode::new(node_cfg)
                .await
                .map_err(|e| anyhow::anyhow!("failed to start ethersync node: {}", e))?,
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let node_for_task = node.clone();
        let run_task = tokio::spawn(async move {
            if let Err(e) = node_for_task.run(shutdown_rx).await {
                tracing::warn!("ethersync run loop ended with error: {}", e);
            }
        });
        let (events_tx, _) = broadcast::channel(512);
        let keeper_envelopes = Arc::new(Mutex::new(HashMap::new()));
        let keeper_archive = Arc::new(Mutex::new(HashMap::new()));
        let keeper_last_activity = Arc::new(Mutex::new(HashMap::new()));
        let space_policies = Arc::new(Mutex::new(HashMap::new()));
        let keeper_replication_task = if runtime_cfg.keeper_replication_enabled {
            Some(spawn_keeper_replication_task(
                shutdown_tx.subscribe(),
                events_tx.clone(),
                keeper_envelopes.clone(),
                keeper_archive.clone(),
            ))
        } else {
            None
        };
        emit_ethersync_event(
            &events_tx,
            EtherSyncEvent {
                kind: "started".to_string(),
                ts_ms: now_ms(),
                space_id: None,
                slot_id: None,
                payload_b64: None,
                text: None,
                info: Some(format!(
                    "ethersync node started (bootstrap peers={})",
                    bootstrap_peer_count
                )),
                error: None,
            },
        );

        let runtime = EtherSyncRuntime {
            node,
            bind_addr: cfg.bind_addr,
            shutdown_tx,
            run_task,
            keeper_replication_task,
            subscriptions: HashMap::new(),
            events_tx,
            enable_orp: cfg.enable_orp,
            bootstrap_peer_count,
            retention_tier: runtime_cfg.retention_tier.clone(),
            keeper_replication_enabled: runtime_cfg.keeper_replication_enabled,
            keeper_replication_factor: runtime_cfg.keeper_replication_factor,
            bridge_hint_count: runtime_cfg.bridge_bootstrap_hints.len(),
            operator_id_hint: runtime_cfg.operator_id.clone(),
            operator_region_hint: runtime_cfg.operator_region.clone(),
            bootstrap_bundle,
            bootstrap_bundle_validation,
            keeper_envelopes,
            keeper_archive,
            keeper_last_activity,
            space_policies,
        };

        let mut inner = self.inner.lock().await;
        if inner.ethersync.is_some() {
            return Err(anyhow::anyhow!("ethersync already running"));
        }
        inner.ethersync = Some(runtime);
        drop(inner);
        self.ethersync_status().await
    }

    pub async fn ethersync_stop(&self) -> anyhow::Result<EtherSyncStatus> {
        let runtime = {
            let mut inner = self.inner.lock().await;
            inner.ethersync.take()
        };
        let Some(mut runtime) = runtime else {
            return Ok(default_ethersync_status());
        };

        emit_ethersync_event(
            &runtime.events_tx,
            EtherSyncEvent {
                kind: "stopping".to_string(),
                ts_ms: now_ms(),
                space_id: None,
                slot_id: None,
                payload_b64: None,
                text: None,
                info: Some("ethersync node stopping".to_string()),
                error: None,
            },
        );

        let _ = runtime.shutdown_tx.send(true);
        for (_, handle) in runtime.subscriptions.drain() {
            handle.abort();
        }
        let _ = tokio::time::timeout(Duration::from_secs(3), async {
            let _ = runtime.run_task.await;
        })
        .await;
        if let Some(task) = runtime.keeper_replication_task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                let _ = task.await;
            })
            .await;
        }

        Ok(default_ethersync_status())
    }

    pub async fn ethersync_status(&self) -> anyhow::Result<EtherSyncStatus> {
        let (
            node,
            bind_addr,
            spaces,
            enable_orp,
            bootstrap_peer_count,
            retention_tier,
            keeper_replication_enabled,
            keeper_replication_factor,
            bridge_hint_count,
            operator_id_hint,
            operator_region_hint,
            bootstrap_bundle,
            bootstrap_bundle_validation,
            keeper_envelopes,
            keeper_archive,
            keeper_last_activity,
            space_policies,
        ) = {
            let inner = self.inner.lock().await;
            match inner.ethersync.as_ref() {
                Some(rt) => (
                    Some(rt.node.clone()),
                    Some(rt.bind_addr.clone()),
                    rt.subscriptions.keys().cloned().collect::<Vec<_>>(),
                    rt.enable_orp,
                    rt.bootstrap_peer_count,
                    rt.retention_tier.clone(),
                    rt.keeper_replication_enabled,
                    rt.keeper_replication_factor,
                    rt.bridge_hint_count,
                    rt.operator_id_hint.clone(),
                    rt.operator_region_hint.clone(),
                    rt.bootstrap_bundle.clone(),
                    rt.bootstrap_bundle_validation.clone(),
                    Some(rt.keeper_envelopes.clone()),
                    Some(rt.keeper_archive.clone()),
                    Some(rt.keeper_last_activity.clone()),
                    Some(rt.space_policies.clone()),
                ),
                None => (
                    None,
                    None,
                    Vec::new(),
                    false,
                    0,
                    "local-only".to_string(),
                    false,
                    0,
                    0,
                    "local-node".to_string(),
                    "unknown".to_string(),
                    BootstrapBundleSummary::default(),
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
            }
        };

        let Some(node) = node else {
            return Ok(default_ethersync_status());
        };

        let runtime_cfg = crate::config::Config::from_env();
        let high_risk_gate_reasons = default_high_risk_gate_reasons(
            enable_orp,
            keeper_replication_enabled,
            bootstrap_bundle.loaded,
            bridge_hint_count,
        );
        let (pending_keeper_envelopes, keeper_space_count) =
            if let Some(keeper_envelopes) = keeper_envelopes.as_ref() {
                let guard = keeper_envelopes.lock().await;
                let pending = guard.values().map(|items| items.len()).sum();
                let spaces = guard.values().filter(|items| !items.is_empty()).count();
                (pending, spaces)
            } else {
                (0, 0)
            };
        let (archived_keeper_envelopes, keeper_archive_space_count) =
            if let Some(keeper_archive) = keeper_archive.as_ref() {
                let guard = keeper_archive.lock().await;
                let archived = guard.values().map(|items| items.len()).sum();
                let spaces = guard.values().filter(|items| !items.is_empty()).count();
                (archived, spaces)
            } else {
                (0, 0)
            };
        let (
            managed_space_count,
            bridge_preferred_space_count,
            keeper_preferred_space_count,
            keeper_manifest_space_count,
            keeper_candidate_shortfall_space_count,
            managed_ready_space_count,
        ) = if let Some(space_policies) = space_policies {
            let guard = space_policies.lock().await;
            let pending_items = keeper_envelopes.as_ref().cloned();
            let pending_guard = if let Some(items) = pending_items.as_ref() {
                Some(items.lock().await)
            } else {
                None
            };
            let archived_items = keeper_archive.as_ref().cloned();
            let archived_guard = if let Some(items) = archived_items.as_ref() {
                Some(items.lock().await)
            } else {
                None
            };
            let activity_items = keeper_last_activity.as_ref().cloned();
            let activity_guard = if let Some(items) = activity_items.as_ref() {
                Some(items.lock().await)
            } else {
                None
            };
            let mut managed = 0usize;
            let mut bridge = 0usize;
            let mut keeper = 0usize;
            let mut manifest_spaces = 0usize;
            let mut shortfall_spaces = 0usize;
            let mut ready_spaces = 0usize;
            for (space_key, policy) in guard.iter() {
                if policy.replication_factor > 0 {
                    managed += 1;
                }
                if matches!(policy.route_bias, SpaceRouteBias::BridgePreferred) {
                    bridge += 1;
                }
                if matches!(policy.route_bias, SpaceRouteBias::KeeperPreferred) {
                    keeper += 1;
                }
                let pending = pending_guard
                    .as_ref()
                    .and_then(|items| items.get(space_key).map(|records| records.len()))
                    .unwrap_or(0);
                let archived = archived_guard
                    .as_ref()
                    .and_then(|items| items.get(space_key).map(|records| records.len()))
                    .unwrap_or(0);
                let last_activity_ms = activity_guard
                    .as_ref()
                    .and_then(|items| items.get(space_key).copied());
                let manifest = build_keeper_space_manifest(
                    policy,
                    pending,
                    archived,
                    &bootstrap_bundle,
                    last_activity_ms,
                );
                if manifest.managed || pending > 0 || archived > 0 {
                    manifest_spaces += 1;
                }
                if manifest.candidate_shortfall > 0 {
                    shortfall_spaces += 1;
                }
                if manifest.managed && manifest.available_keeper_candidates > 0 {
                    ready_spaces += 1;
                }
            }
            (
                managed,
                bridge,
                keeper,
                manifest_spaces,
                shortfall_spaces,
                ready_spaces,
            )
        } else {
            (0, 0, 0, 0, 0, 0)
        };
        let last_keeper_activity_ms = if let Some(keeper_last_activity) = keeper_last_activity {
            keeper_last_activity.lock().await.values().copied().max()
        } else {
            None
        };

        // Collect ORP diagnostics from the route cache.
        let (route_cache_size, route_offers_count, last_orp_activity_ms) = {
            let cache = node.route_cache().lock().await;
            let ann_size = cache.announcements.len();
            let offers_count: usize = cache.offers.values().map(|v| v.len()).sum();
            // Find the most recently observed announcement and convert its
            // elapsed Instant back to a UNIX-ms timestamp (best-effort).
            let last_ms = cache
                .announcements
                .values()
                .map(|a| a.last_seen.elapsed().as_millis() as u64)
                .min() // minimum elapsed = most recent
                .map(|elapsed_ms| now_ms().saturating_sub(elapsed_ms));
            (ann_size, offers_count, last_ms)
        };
        let high_risk_circuits = node.high_risk_circuit_stats().await;

        Ok(EtherSyncStatus {
            running: true,
            bind_addr,
            local_addr: Some(node.local_addr().to_string()),
            peer_count: node.peer_count().await,
            subscription_count: node.subscription_count().await,
            spaces,
            orp_enabled: enable_orp,
            route_cache_size,
            route_offers_count,
            last_orp_activity_ms,
            retention_tier,
            replay_window_slots: LOOKBACK_SLOTS,
            keeper_replication_enabled,
            keeper_replication_factor,
            bootstrap_peer_count,
            discovery_bootstrap_peer_count: runtime_cfg.discovery_bootstrap_peers.len(),
            bridge_bootstrap_enabled: bridge_hint_count > 0
                || bootstrap_bundle.bridges > 0
                || !runtime_cfg.assist_relays.is_empty(),
            bridge_hint_count,
            high_risk_available: high_risk_gate_reasons.is_empty(),
            high_risk_gate_reasons,
            high_risk_circuits_observed: high_risk_circuits.circuits_observed,
            high_risk_active_circuits: high_risk_circuits.active_circuits,
            high_risk_closed_circuits: high_risk_circuits.closed_circuits,
            high_risk_control_frames_observed: high_risk_circuits.control_frames_observed,
            high_risk_cover_packets_observed: high_risk_circuits.cover_packets_observed,
            high_risk_last_activity_ms: high_risk_circuits.last_activity_ms,
            operator_id_hint,
            operator_region_hint,
            bootstrap_bundle_loaded: bootstrap_bundle.loaded,
            bootstrap_bundle_mirrors: bootstrap_bundle.mirrors,
            bootstrap_bundle_relays: bootstrap_bundle.relays,
            bootstrap_bundle_bridges: bootstrap_bundle.bridges,
            bootstrap_bundle_keepers: bootstrap_bundle.keepers,
            bootstrap_bundle_usable: bootstrap_bundle_validation
                .as_ref()
                .map(|report| report.is_usable)
                .unwrap_or(false),
            bootstrap_bundle_structurally_weak: bootstrap_bundle_validation
                .as_ref()
                .map(|report| report.is_structurally_weak)
                .unwrap_or(false),
            bootstrap_bundle_stale: bootstrap_bundle_validation
                .as_ref()
                .map(|report| report.staleness.is_stale())
                .unwrap_or(false),
            bootstrap_bundle_warning_count: bootstrap_bundle_validation
                .as_ref()
                .map(|report| report.issue_counts.warning)
                .unwrap_or(0),
            bootstrap_bundle_error_count: bootstrap_bundle_validation
                .as_ref()
                .map(|report| report.issue_counts.error)
                .unwrap_or(0),
            pending_keeper_envelopes,
            keeper_space_count,
            archived_keeper_envelopes,
            keeper_archive_space_count,
            keeper_manifest_space_count,
            keeper_candidate_shortfall_space_count,
            managed_ready_space_count,
            last_keeper_activity_ms,
            managed_space_count,
            bridge_preferred_space_count,
            keeper_preferred_space_count,
        })
    }

    pub async fn ethersync_add_peer(&self, peer: SocketAddr) -> anyhow::Result<EtherSyncStatus> {
        let (node, events_tx) = {
            let inner = self.inner.lock().await;
            let Some(rt) = inner.ethersync.as_ref() else {
                return Err(anyhow::anyhow!("ethersync is not running"));
            };
            (rt.node.clone(), rt.events_tx.clone())
        };
        node.add_peer(peer).await;
        emit_ethersync_event(
            &events_tx,
            EtherSyncEvent {
                kind: "peer_added".to_string(),
                ts_ms: now_ms(),
                space_id: None,
                slot_id: None,
                payload_b64: None,
                text: None,
                info: Some(format!("peer {}", peer)),
                error: None,
            },
        );
        self.ethersync_status().await
    }

    pub async fn ethersync_join_space(
        &self,
        passphrase: String,
        label: Option<String>,
        retention_tier: Option<String>,
        replication_factor: Option<usize>,
        route_bias: Option<String>,
    ) -> anyhow::Result<EtherSyncJoinResult> {
        if passphrase.trim().is_empty() {
            return Err(anyhow::anyhow!("passphrase required"));
        }
        let space_id = derive_space_id(&passphrase, label.as_deref());
        let space_key = derive_space_key(&passphrase);
        let has_explicit_policy =
            retention_tier.is_some() || replication_factor.is_some() || route_bias.is_some();
        let requested_policy = build_space_policy(
            retention_tier.as_deref(),
            replication_factor,
            route_bias.as_deref(),
        );

        let (
            node,
            events_tx,
            already_subscribed,
            orp_enabled,
            keeper_envelopes,
            keeper_archive,
            keeper_last_activity,
            bootstrap_bundle,
            space_policies,
        ) = {
            let inner = self.inner.lock().await;
            let Some(rt) = inner.ethersync.as_ref() else {
                return Err(anyhow::anyhow!("ethersync is not running"));
            };
            (
                rt.node.clone(),
                rt.events_tx.clone(),
                rt.subscriptions.contains_key(&space_id),
                rt.enable_orp,
                rt.keeper_envelopes.clone(),
                rt.keeper_archive.clone(),
                rt.keeper_last_activity.clone(),
                rt.bootstrap_bundle.clone(),
                rt.space_policies.clone(),
            )
        };
        let applied_policy = upsert_space_policy(
            &space_policies,
            &space_key,
            requested_policy.clone(),
            has_explicit_policy,
        )
        .await;

        let discovery_report = seed_space_from_discovery(
            &node,
            &events_tx,
            &passphrase,
            &space_id,
            orp_enabled,
            &applied_policy,
        )
        .await;

        if already_subscribed {
            let replayed = replay_space_backlog(&node, &events_tx, &passphrase, &space_id).await;
            emit_keeper_pending_hint(&events_tx, &keeper_envelopes, &space_key, &space_id).await;
            emit_keeper_archive_hint(&events_tx, &keeper_archive, &space_key, &space_id).await;
            if policy_enables_keeper_replication(&applied_policy) {
                let _ = touch_keeper_activity(&keeper_last_activity, &space_key).await;
                emit_keeper_manifest_hint(
                    &events_tx,
                    &space_key,
                    &applied_policy,
                    &keeper_envelopes,
                    &keeper_archive,
                    &keeper_last_activity,
                    &bootstrap_bundle,
                )
                .await;
            }
            let last_local_activity_ms = keeper_last_activity.lock().await.get(&space_key).copied();
            let keeper_manifest = build_keeper_space_manifest(
                &applied_policy,
                keeper_envelopes
                    .lock()
                    .await
                    .get(&space_key)
                    .map(|items| items.len())
                    .unwrap_or(0),
                keeper_archive
                    .lock()
                    .await
                    .get(&space_key)
                    .map(|items| items.len())
                    .unwrap_or(0),
                &bootstrap_bundle,
                last_local_activity_ms,
            );
            tracing::info!(
                "ethersync join replayed {} message(s) for existing subscription {} (discovered {} endpoint(s))",
                replayed,
                space_id,
                discovery_report.discovered
            );
            return Ok(EtherSyncJoinResult {
                space_id,
                retention_tier: applied_policy.retention_tier,
                replication_factor: applied_policy.replication_factor,
                route_bias: applied_policy.route_bias.as_str().to_string(),
                keeper_manifest,
            });
        }

        let mut rx = node
            .subscribe(&passphrase)
            .await
            .map_err(|e| anyhow::anyhow!("failed to subscribe ethersync space: {}", e))?;

        if orp_enabled {
            node.start_orp_for_space(&passphrase).await;
        }

        let passphrase_for_task = passphrase.clone();
        let space_id_for_task = space_id.clone();
        let events_tx_for_task = events_tx.clone();
        let task = tokio::spawn(async move {
            loop {
                let Some(message) = rx.recv().await else {
                    emit_ethersync_event(
                        &events_tx_for_task,
                        EtherSyncEvent {
                            kind: "space_stream_closed".to_string(),
                            ts_ms: now_ms(),
                            space_id: Some(space_id_for_task.clone()),
                            slot_id: None,
                            payload_b64: None,
                            text: None,
                            info: Some("subscription stream closed".to_string()),
                            error: None,
                        },
                    );
                    break;
                };
                match message.decrypt(&passphrase_for_task) {
                    Ok(payload) => {
                        if let Ok(file_chunk) =
                            serde_json::from_slice::<EtherSyncFileChunkEnvelope>(&payload)
                        {
                            if file_chunk.kind == "file_chunk" {
                                emit_ethersync_event(
                                    &events_tx_for_task,
                                    EtherSyncEvent {
                                        kind: "space_file_chunk".to_string(),
                                        ts_ms: now_ms(),
                                        space_id: Some(space_id_for_task.clone()),
                                        slot_id: Some(message.header.slot_id),
                                        payload_b64: Some(
                                            general_purpose::STANDARD.encode(payload),
                                        ),
                                        text: None,
                                        info: Some(format!(
                                            "{} ({}/{})",
                                            file_chunk.filename,
                                            file_chunk.chunk_index + 1,
                                            file_chunk.total_chunks
                                        )),
                                        error: None,
                                    },
                                );
                                continue;
                            }
                        }
                        let preview = String::from_utf8(payload.clone()).ok();
                        emit_ethersync_event(
                            &events_tx_for_task,
                            EtherSyncEvent {
                                kind: "space_message".to_string(),
                                ts_ms: now_ms(),
                                space_id: Some(space_id_for_task.clone()),
                                slot_id: Some(message.header.slot_id),
                                payload_b64: Some(general_purpose::STANDARD.encode(payload)),
                                text: preview,
                                info: None,
                                error: None,
                            },
                        );
                    }
                    Err(e) => {
                        emit_ethersync_event(
                            &events_tx_for_task,
                            EtherSyncEvent {
                                kind: "space_message_error".to_string(),
                                ts_ms: now_ms(),
                                space_id: Some(space_id_for_task.clone()),
                                slot_id: Some(message.header.slot_id),
                                payload_b64: None,
                                text: None,
                                info: None,
                                error: Some(e.to_string()),
                            },
                        );
                    }
                }
            }
        });

        let mut inserted = false;
        let mut inner = self.inner.lock().await;
        if let Some(rt) = inner.ethersync.as_mut() {
            if rt.subscriptions.contains_key(&space_id) {
                task.abort();
            } else {
                rt.subscriptions.insert(space_id.clone(), task);
                emit_ethersync_event(
                    &rt.events_tx,
                    EtherSyncEvent {
                        kind: "space_joined".to_string(),
                        ts_ms: now_ms(),
                        space_id: Some(space_id.clone()),
                        slot_id: None,
                        payload_b64: None,
                        text: None,
                        info: Some("space subscription started".to_string()),
                        error: None,
                    },
                );
                inserted = true;
            }
        } else {
            task.abort();
            return Err(anyhow::anyhow!("ethersync was stopped"));
        }
        drop(inner);

        if inserted {
            let replayed = replay_space_backlog(&node, &events_tx, &passphrase, &space_id).await;
            emit_keeper_pending_hint(&events_tx, &keeper_envelopes, &space_key, &space_id).await;
            emit_keeper_archive_hint(&events_tx, &keeper_archive, &space_key, &space_id).await;
            if policy_enables_keeper_replication(&applied_policy) {
                let _ = touch_keeper_activity(&keeper_last_activity, &space_key).await;
                emit_keeper_manifest_hint(
                    &events_tx,
                    &space_key,
                    &applied_policy,
                    &keeper_envelopes,
                    &keeper_archive,
                    &keeper_last_activity,
                    &bootstrap_bundle,
                )
                .await;
            }
            tracing::info!(
                "ethersync join replayed {} message(s) for new subscription {} (discovered {} endpoint(s))",
                replayed,
                space_id,
                discovery_report.discovered
            );
        }

        let pending_keeper_envelopes = keeper_envelopes
            .lock()
            .await
            .get(&space_key)
            .map(|items| items.len())
            .unwrap_or(0);
        let archived_keeper_envelopes = keeper_archive
            .lock()
            .await
            .get(&space_key)
            .map(|items| items.len())
            .unwrap_or(0);
        let last_local_activity_ms = keeper_last_activity.lock().await.get(&space_key).copied();
        let keeper_manifest = build_keeper_space_manifest(
            &applied_policy,
            pending_keeper_envelopes,
            archived_keeper_envelopes,
            &bootstrap_bundle,
            last_local_activity_ms,
        );

        Ok(EtherSyncJoinResult {
            space_id,
            retention_tier: applied_policy.retention_tier,
            replication_factor: applied_policy.replication_factor,
            route_bias: applied_policy.route_bias.as_str().to_string(),
            keeper_manifest,
        })
    }

    pub async fn ethersync_publish(
        &self,
        passphrase: String,
        payload: Vec<u8>,
    ) -> anyhow::Result<EtherSyncPublishResult> {
        if passphrase.trim().is_empty() {
            return Err(anyhow::anyhow!("passphrase required"));
        }
        if payload.is_empty() {
            return Err(anyhow::anyhow!("payload is empty"));
        }
        let space_id = derive_space_key(&passphrase);
        let (
            node,
            events_tx,
            keeper_enabled_runtime,
            keeper_envelopes,
            keeper_archive,
            keeper_last_activity,
            bootstrap_bundle,
            space_policies,
        ) = {
            let inner = self.inner.lock().await;
            let Some(rt) = inner.ethersync.as_ref() else {
                return Err(anyhow::anyhow!("ethersync is not running"));
            };
            (
                rt.node.clone(),
                rt.events_tx.clone(),
                rt.keeper_replication_enabled,
                rt.keeper_envelopes.clone(),
                rt.keeper_archive.clone(),
                rt.keeper_last_activity.clone(),
                rt.bootstrap_bundle.clone(),
                rt.space_policies.clone(),
            )
        };
        let space_policy = space_policies
            .lock()
            .await
            .get(&space_id)
            .cloned()
            .unwrap_or_else(default_space_policy);
        let keeper_enabled =
            keeper_enabled_runtime && policy_enables_keeper_replication(&space_policy);

        let message = node
            .publish(&passphrase, &payload)
            .await
            .map_err(|e| anyhow::anyhow!("failed to publish ethersync payload: {}", e))?;

        if keeper_enabled {
            let pending = enqueue_keeper_envelope(
                &keeper_envelopes,
                &space_id,
                message.clone(),
                message.header.slot_id,
            )
            .await;
            let _ = touch_keeper_activity(&keeper_last_activity, &space_id).await;
            emit_ethersync_event(
                &events_tx,
                EtherSyncEvent {
                    kind: "space_keeper_enqueued".to_string(),
                    ts_ms: now_ms(),
                    space_id: Some(space_id.clone()),
                    slot_id: Some(message.header.slot_id),
                    payload_b64: None,
                    text: None,
                    info: Some(format!("pending keeper envelopes={}", pending)),
                    error: None,
                },
            );
            emit_keeper_manifest_hint(
                &events_tx,
                &space_id,
                &space_policy,
                &keeper_envelopes,
                &keeper_archive,
                &keeper_last_activity,
                &bootstrap_bundle,
            )
            .await;
        }

        emit_ethersync_event(
            &events_tx,
            EtherSyncEvent {
                kind: "space_published".to_string(),
                ts_ms: now_ms(),
                space_id: Some(space_id.clone()),
                slot_id: Some(message.header.slot_id),
                payload_b64: Some(general_purpose::STANDARD.encode(&payload)),
                text: String::from_utf8(payload.clone()).ok(),
                info: Some(format!("{} bytes", payload.len())),
                error: None,
            },
        );

        Ok(EtherSyncPublishResult {
            space_id,
            slot_id: message.header.slot_id,
            payload_len: payload.len(),
        })
    }

    pub async fn ethersync_publish_file(
        &self,
        passphrase: String,
        filename: String,
        file_bytes: Vec<u8>,
        chunk_size: Option<usize>,
    ) -> anyhow::Result<EtherSyncFilePublishResult> {
        if passphrase.trim().is_empty() {
            return Err(anyhow::anyhow!("passphrase required"));
        }
        let clean_filename = sanitize_filename(&filename);
        if clean_filename.is_empty() {
            return Err(anyhow::anyhow!("filename required"));
        }
        if file_bytes.is_empty() {
            return Err(anyhow::anyhow!("file is empty"));
        }

        let chunk_size = chunk_size
            .unwrap_or(ETHERSYNC_FILE_CHUNK_DEFAULT)
            .clamp(ETHERSYNC_FILE_CHUNK_MIN, ETHERSYNC_FILE_CHUNK_MAX);
        let total_chunks = file_bytes.len().div_ceil(chunk_size);
        let transfer_id = derive_transfer_id(&clean_filename, file_bytes.len(), now_ms());
        let space_id = derive_space_key(&passphrase);

        let (
            node,
            events_tx,
            keeper_enabled_runtime,
            keeper_envelopes,
            keeper_archive,
            keeper_last_activity,
            bootstrap_bundle,
            space_policies,
        ) = {
            let inner = self.inner.lock().await;
            let Some(rt) = inner.ethersync.as_ref() else {
                return Err(anyhow::anyhow!("ethersync is not running"));
            };
            (
                rt.node.clone(),
                rt.events_tx.clone(),
                rt.keeper_replication_enabled,
                rt.keeper_envelopes.clone(),
                rt.keeper_archive.clone(),
                rt.keeper_last_activity.clone(),
                rt.bootstrap_bundle.clone(),
                rt.space_policies.clone(),
            )
        };
        let space_policy = space_policies
            .lock()
            .await
            .get(&space_id)
            .cloned()
            .unwrap_or_else(default_space_policy);
        let keeper_enabled =
            keeper_enabled_runtime && policy_enables_keeper_replication(&space_policy);

        emit_ethersync_event(
            &events_tx,
            EtherSyncEvent {
                kind: "space_file_publish_started".to_string(),
                ts_ms: now_ms(),
                space_id: Some(space_id.clone()),
                slot_id: None,
                payload_b64: None,
                text: None,
                info: Some(format!(
                    "{} {} bytes in {} chunks",
                    clean_filename,
                    file_bytes.len(),
                    total_chunks
                )),
                error: None,
            },
        );

        let mut published_chunks = 0usize;
        for (idx, chunk) in file_bytes.chunks(chunk_size).enumerate() {
            let envelope = EtherSyncFileChunkEnvelope {
                kind: "file_chunk".to_string(),
                transfer_id: transfer_id.clone(),
                filename: clean_filename.clone(),
                total_bytes: file_bytes.len(),
                chunk_index: idx,
                total_chunks,
                chunk_b64: general_purpose::STANDARD.encode(chunk),
            };
            let payload = serde_json::to_vec(&envelope)
                .map_err(|e| anyhow::anyhow!("file envelope serialization failed: {}", e))?;
            let message = node.publish(&passphrase, &payload).await.map_err(|e| {
                anyhow::anyhow!(
                    "failed publishing file chunk {}/{}: {}",
                    idx + 1,
                    total_chunks,
                    e
                )
            })?;
            published_chunks += 1;

            if keeper_enabled {
                let _ = enqueue_keeper_envelope(
                    &keeper_envelopes,
                    &space_id,
                    message.clone(),
                    message.header.slot_id,
                )
                .await;
            }

            emit_ethersync_event(
                &events_tx,
                EtherSyncEvent {
                    kind: "space_file_chunk_published".to_string(),
                    ts_ms: now_ms(),
                    space_id: Some(space_id.clone()),
                    slot_id: Some(message.header.slot_id),
                    payload_b64: None,
                    text: None,
                    info: Some(format!("{} {}/{}", clean_filename, idx + 1, total_chunks)),
                    error: None,
                },
            );
        }

        emit_ethersync_event(
            &events_tx,
            EtherSyncEvent {
                kind: "space_file_publish_completed".to_string(),
                ts_ms: now_ms(),
                space_id: Some(space_id.clone()),
                slot_id: None,
                payload_b64: None,
                text: None,
                info: Some(format!(
                    "{} chunks={} bytes={}",
                    clean_filename,
                    published_chunks,
                    file_bytes.len()
                )),
                error: None,
            },
        );

        if keeper_enabled {
            let _ = touch_keeper_activity(&keeper_last_activity, &space_id).await;
            emit_keeper_manifest_hint(
                &events_tx,
                &space_id,
                &space_policy,
                &keeper_envelopes,
                &keeper_archive,
                &keeper_last_activity,
                &bootstrap_bundle,
            )
            .await;
        }

        Ok(EtherSyncFilePublishResult {
            space_id,
            transfer_id,
            filename: clean_filename,
            total_bytes: file_bytes.len(),
            total_chunks,
            published_chunks,
        })
    }

    pub async fn ethersync_subscribe_events(&self) -> anyhow::Result<broadcast::Receiver<String>> {
        let inner = self.inner.lock().await;
        let Some(rt) = inner.ethersync.as_ref() else {
            return Err(anyhow::anyhow!("ethersync is not running"));
        };
        Ok(rt.events_tx.subscribe())
    }

    pub async fn ethersync_keeper_backfill(
        &self,
        passphrase: String,
        max_messages: Option<usize>,
    ) -> anyhow::Result<KeeperBackfillResult> {
        if passphrase.trim().is_empty() {
            return Err(anyhow::anyhow!("passphrase required"));
        }
        let space_id = derive_space_key(&passphrase);
        let (
            node,
            events_tx,
            keeper_envelopes,
            keeper_archive,
            keeper_last_activity,
            bootstrap_bundle,
            space_policies,
        ) = {
            let inner = self.inner.lock().await;
            let Some(rt) = inner.ethersync.as_ref() else {
                return Err(anyhow::anyhow!("ethersync is not running"));
            };
            (
                rt.node.clone(),
                rt.events_tx.clone(),
                rt.keeper_envelopes.clone(),
                rt.keeper_archive.clone(),
                rt.keeper_last_activity.clone(),
                rt.bootstrap_bundle.clone(),
                rt.space_policies.clone(),
            )
        };

        let limit = max_messages.unwrap_or(256).clamp(1, 4096);
        let _ = flush_keeper_pending_envelopes(
            &keeper_envelopes,
            &keeper_archive,
            Some(space_id.as_str()),
        )
        .await;
        let archived = {
            let guard = keeper_archive.lock().await;
            guard
                .get(&space_id)
                .map(|items| items.iter().take(limit).cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        };

        let mut restored = 0usize;
        {
            let mut storage = node.storage().lock().await;
            for envelope in &archived {
                let hash = blake3_hash(&envelope.message.encrypted_payload);
                if storage
                    .store(envelope.slot_id, hash, envelope.message.clone())
                    .is_ok()
                {
                    restored = restored.saturating_add(1);
                }
            }
        }

        let remaining_pending = {
            let guard = keeper_envelopes.lock().await;
            guard.get(&space_id).map(|items| items.len()).unwrap_or(0)
        };
        let _ = touch_keeper_activity(&keeper_last_activity, &space_id).await;
        let applied_policy = space_policies
            .lock()
            .await
            .get(&space_id)
            .cloned()
            .unwrap_or_else(default_space_policy);
        emit_keeper_manifest_hint(
            &events_tx,
            &space_id,
            &applied_policy,
            &keeper_envelopes,
            &keeper_archive,
            &keeper_last_activity,
            &bootstrap_bundle,
        )
        .await;
        let archived_keeper_envelopes = {
            let guard = keeper_archive.lock().await;
            guard.get(&space_id).map(|items| items.len()).unwrap_or(0)
        };
        let last_local_activity_ms = keeper_last_activity.lock().await.get(&space_id).copied();
        let keeper_manifest = build_keeper_space_manifest(
            &applied_policy,
            remaining_pending,
            archived_keeper_envelopes,
            &bootstrap_bundle,
            last_local_activity_ms,
        );

        emit_ethersync_event(
            &events_tx,
            EtherSyncEvent {
                kind: "space_keeper_backfill_completed".to_string(),
                ts_ms: now_ms(),
                space_id: Some(space_id.clone()),
                slot_id: None,
                payload_b64: None,
                text: None,
                info: Some(format!(
                    "restored {} message(s), remaining pending={}, archived={}",
                    restored,
                    remaining_pending,
                    archived.len()
                )),
                error: None,
            },
        );

        Ok(KeeperBackfillResult {
            space_id,
            restored_messages: restored,
            remaining_pending,
            keeper_manifest,
        })
    }

    pub async fn ethersync_list_space_policies(&self) -> anyhow::Result<Vec<SpacePolicySnapshot>> {
        let (
            space_policies,
            keeper_envelopes,
            keeper_archive,
            keeper_last_activity,
            bootstrap_bundle,
        ) = {
            let inner = self.inner.lock().await;
            let Some(rt) = inner.ethersync.as_ref() else {
                return Err(anyhow::anyhow!("ethersync is not running"));
            };
            (
                rt.space_policies.clone(),
                rt.keeper_envelopes.clone(),
                rt.keeper_archive.clone(),
                rt.keeper_last_activity.clone(),
                rt.bootstrap_bundle.clone(),
            )
        };

        let policies = space_policies.lock().await;
        let pending = keeper_envelopes.lock().await;
        let archived = keeper_archive.lock().await;
        let activity = keeper_last_activity.lock().await;

        let mut items = Vec::new();
        for (space_key, policy) in policies.iter() {
            let pending_keeper_envelopes =
                pending.get(space_key).map(|items| items.len()).unwrap_or(0);
            let archived_keeper_envelopes = archived
                .get(space_key)
                .map(|items| items.len())
                .unwrap_or(0);
            let keeper_manifest = build_keeper_space_manifest(
                policy,
                pending_keeper_envelopes,
                archived_keeper_envelopes,
                &bootstrap_bundle,
                activity.get(space_key).copied(),
            );
            items.push(SpacePolicySnapshot {
                space_key: space_key.clone(),
                retention_tier: policy.retention_tier.clone(),
                replication_factor: policy.replication_factor,
                route_bias: policy.route_bias.as_str().to_string(),
                pending_keeper_envelopes,
                archived_keeper_envelopes,
                keeper_manifest,
            });
        }

        items.sort_by(|a, b| a.space_key.cmp(&b.space_key));
        Ok(items)
    }

    pub async fn ethersync_set_space_policy(
        &self,
        passphrase: String,
        retention_tier: Option<String>,
        replication_factor: Option<usize>,
        route_bias: Option<String>,
    ) -> anyhow::Result<SpacePolicySnapshot> {
        if passphrase.trim().is_empty() {
            return Err(anyhow::anyhow!("passphrase required"));
        }
        let space_key = derive_space_key(&passphrase);
        let requested_policy = build_space_policy(
            retention_tier.as_deref(),
            replication_factor,
            route_bias.as_deref(),
        );

        let (
            space_policies,
            keeper_envelopes,
            keeper_archive,
            keeper_last_activity,
            bootstrap_bundle,
            events_tx,
        ) = {
            let inner = self.inner.lock().await;
            let Some(rt) = inner.ethersync.as_ref() else {
                return Err(anyhow::anyhow!("ethersync is not running"));
            };
            (
                rt.space_policies.clone(),
                rt.keeper_envelopes.clone(),
                rt.keeper_archive.clone(),
                rt.keeper_last_activity.clone(),
                rt.bootstrap_bundle.clone(),
                rt.events_tx.clone(),
            )
        };

        let applied_policy =
            upsert_space_policy(&space_policies, &space_key, requested_policy, true).await;
        let pending_keeper_envelopes = {
            let guard = keeper_envelopes.lock().await;
            guard.get(&space_key).map(|items| items.len()).unwrap_or(0)
        };
        let archived_keeper_envelopes = {
            let guard = keeper_archive.lock().await;
            guard.get(&space_key).map(|items| items.len()).unwrap_or(0)
        };
        let _ = touch_keeper_activity(&keeper_last_activity, &space_key).await;
        emit_keeper_manifest_hint(
            &events_tx,
            &space_key,
            &applied_policy,
            &keeper_envelopes,
            &keeper_archive,
            &keeper_last_activity,
            &bootstrap_bundle,
        )
        .await;
        let last_local_activity_ms = keeper_last_activity.lock().await.get(&space_key).copied();
        let keeper_manifest = build_keeper_space_manifest(
            &applied_policy,
            pending_keeper_envelopes,
            archived_keeper_envelopes,
            &bootstrap_bundle,
            last_local_activity_ms,
        );

        emit_ethersync_event(
            &events_tx,
            EtherSyncEvent {
                kind: "space_policy_updated".to_string(),
                ts_ms: now_ms(),
                space_id: Some(space_key.clone()),
                slot_id: None,
                payload_b64: None,
                text: None,
                info: Some(format!(
                    "retention={} replication_factor={} route_bias={}",
                    applied_policy.retention_tier,
                    applied_policy.replication_factor,
                    applied_policy.route_bias.as_str()
                )),
                error: None,
            },
        );

        Ok(SpacePolicySnapshot {
            space_key,
            retention_tier: applied_policy.retention_tier,
            replication_factor: applied_policy.replication_factor,
            route_bias: applied_policy.route_bias.as_str().to_string(),
            pending_keeper_envelopes,
            archived_keeper_envelopes,
            keeper_manifest,
        })
    }
}

async fn replay_space_backlog(
    node: &Arc<EtherNode>,
    events_tx: &broadcast::Sender<String>,
    passphrase: &str,
    space_id: &str,
) -> usize {
    emit_ethersync_event(
        events_tx,
        EtherSyncEvent {
            kind: "space_replay_started".to_string(),
            ts_ms: now_ms(),
            space_id: Some(space_id.to_string()),
            slot_id: None,
            payload_b64: None,
            text: None,
            info: Some("replaying recent slot window".to_string()),
            error: None,
        },
    );

    let slots = EtherCoordinate::lookback_window(EtherCoordinate::current_slot());
    let mut backlog = Vec::new();

    {
        let storage = node.storage().lock().await;
        for slot in slots {
            if let Ok(messages) = storage.get_slot_messages(slot) {
                backlog.extend(messages);
            }
        }
    }

    backlog.sort_by_key(|m| (m.header.slot_id, m.header.fragment_index));

    let mut replayed = 0usize;
    let mut seen = HashSet::new();

    for message in backlog {
        let msg_hash = blake3_hash(&message.to_bytes());
        if !seen.insert(msg_hash) {
            continue;
        }

        match message.decrypt(passphrase) {
            Ok(payload) => {
                if let Ok(file_chunk) =
                    serde_json::from_slice::<EtherSyncFileChunkEnvelope>(&payload)
                {
                    if file_chunk.kind == "file_chunk" {
                        emit_ethersync_event(
                            events_tx,
                            EtherSyncEvent {
                                kind: "space_file_chunk".to_string(),
                                ts_ms: now_ms(),
                                space_id: Some(space_id.to_string()),
                                slot_id: Some(message.header.slot_id),
                                payload_b64: Some(general_purpose::STANDARD.encode(payload)),
                                text: None,
                                info: Some(format!(
                                    "replay {} ({}/{})",
                                    file_chunk.filename,
                                    file_chunk.chunk_index + 1,
                                    file_chunk.total_chunks
                                )),
                                error: None,
                            },
                        );
                        replayed = replayed.saturating_add(1);
                        continue;
                    }
                }

                emit_ethersync_event(
                    events_tx,
                    EtherSyncEvent {
                        kind: "space_message".to_string(),
                        ts_ms: now_ms(),
                        space_id: Some(space_id.to_string()),
                        slot_id: Some(message.header.slot_id),
                        payload_b64: Some(general_purpose::STANDARD.encode(&payload)),
                        text: String::from_utf8(payload).ok(),
                        info: Some("replay".to_string()),
                        error: None,
                    },
                );
                replayed = replayed.saturating_add(1);
            }
            Err(e) => {
                emit_ethersync_event(
                    events_tx,
                    EtherSyncEvent {
                        kind: "space_message_error".to_string(),
                        ts_ms: now_ms(),
                        space_id: Some(space_id.to_string()),
                        slot_id: Some(message.header.slot_id),
                        payload_b64: None,
                        text: None,
                        info: Some("replay".to_string()),
                        error: Some(e.to_string()),
                    },
                );
            }
        }
    }

    emit_ethersync_event(
        events_tx,
        EtherSyncEvent {
            kind: "space_replay_completed".to_string(),
            ts_ms: now_ms(),
            space_id: Some(space_id.to_string()),
            slot_id: None,
            payload_b64: None,
            text: None,
            info: Some(format!("replayed {} message(s)", replayed)),
            error: None,
        },
    );

    replayed
}

fn resolve_initial_bootstrap_peers(
    runtime_cfg: &crate::config::Config,
    requested: &[SocketAddr],
) -> Vec<SocketAddr> {
    let mut peers = requested.to_vec();

    for peer in crate::discovery::parse_bootstrap_peers(&runtime_cfg.discovery_bootstrap_peers) {
        push_unique_peer(&mut peers, peer);
    }

    for hint in &runtime_cfg.bridge_bootstrap_hints {
        if let Some(addr) = crate::discovery::parse_endpoint_hint(hint) {
            push_unique_peer(&mut peers, addr);
        }
    }

    if let Some(bundle) = crate::bootstrap_bundle::load_bootstrap_bundle(runtime_cfg) {
        let validation = bundle.validation_report();
        if validation.is_usable {
            for relay in &bundle.relays {
                if let Some(addr) = crate::discovery::parse_endpoint_hint(&relay.addr) {
                    push_unique_peer(&mut peers, addr);
                }
            }
            for bridge in &bundle.bridges {
                if let Some(addr) = crate::discovery::parse_endpoint_hint(&bridge.endpoint) {
                    push_unique_peer(&mut peers, addr);
                }
            }
            if runtime_cfg.keeper_replication_enabled && runtime_cfg.keeper_replication_factor > 0 {
                for keeper in &bundle.keepers {
                    if let Some(addr) = crate::discovery::parse_endpoint_hint(&keeper.endpoint) {
                        push_unique_peer(&mut peers, addr);
                    }
                }
            }
        } else {
            tracing::warn!(
                "ignoring unusable bootstrap bundle during initial peer resolution (warnings={}, errors={})",
                validation.issue_counts.warning,
                validation.issue_counts.error
            );
        }
    }

    peers
}

fn push_unique_peer(peers: &mut Vec<SocketAddr>, addr: SocketAddr) {
    if !peers.contains(&addr) {
        peers.push(addr);
    }
}

async fn seed_space_from_discovery(
    node: &Arc<EtherNode>,
    events_tx: &broadcast::Sender<String>,
    passphrase: &str,
    space_id: &str,
    orp_enabled: bool,
    policy: &EtherSpacePolicy,
) -> DiscoverySeedReport {
    let runtime_cfg = crate::config::Config::from_env();
    let static_bootstrap =
        crate::discovery::parse_bootstrap_peers(&runtime_cfg.discovery_bootstrap_peers);
    let mut backends: Vec<Arc<dyn crate::discovery::DiscoveryProvider>> = Vec::new();
    let mut report = DiscoverySeedReport {
        route_bias: policy.route_bias.as_str().to_string(),
        ..DiscoverySeedReport::default()
    };

    if orp_enabled {
        backends.push(Arc::new(crate::discovery::OrpDiscoveryProvider::new(
            node.route_cache().clone(),
        )));
        report.used_orp = true;
    }

    if let Some(bundle) = crate::bootstrap_bundle::load_bootstrap_bundle(&runtime_cfg) {
        report.bundle_relay_candidates = bundle.relays.len();
        report.bundle_bridge_candidates = bundle.bridges.len();
        report.bundle_keeper_candidates = bundle.keepers.len();
        let validation = bundle.validation_report();
        report.bundle_usable = validation.is_usable;
        report.bundle_stale = validation.staleness.is_stale();
        if validation.is_usable {
            let preference = match policy.route_bias {
                SpaceRouteBias::BridgePreferred => {
                    crate::discovery::BootstrapEndpointPreference::BridgeFirst
                }
                SpaceRouteBias::KeeperPreferred if policy_enables_keeper_replication(policy) => {
                    crate::discovery::BootstrapEndpointPreference::KeeperFirst
                }
                SpaceRouteBias::DirectPreferred => {
                    crate::discovery::BootstrapEndpointPreference::RelayFirst
                }
                SpaceRouteBias::Balanced => crate::discovery::BootstrapEndpointPreference::Balanced,
                _ => crate::discovery::BootstrapEndpointPreference::Balanced,
            };
            backends.push(Arc::new(
                crate::discovery::BootstrapDiscoveryProvider::from_bundle_with_preference(
                    &bundle, preference,
                ),
            ));
            report.used_bootstrap_bundle = true;
        } else {
            emit_ethersync_event(
                events_tx,
                EtherSyncEvent {
                    kind: "space_discovery_bundle_skipped".to_string(),
                    ts_ms: now_ms(),
                    space_id: Some(space_id.to_string()),
                    slot_id: None,
                    payload_b64: None,
                    text: None,
                    info: Some(
                        "bootstrap bundle skipped because it is locally unusable".to_string(),
                    ),
                    error: Some(format!(
                        "warnings={} errors={}",
                        validation.issue_counts.warning, validation.issue_counts.error
                    )),
                },
            );
        }
    }

    report.used_static_bootstrap = !static_bootstrap.is_empty();
    if backends.is_empty() && static_bootstrap.is_empty() {
        return report;
    }

    let canonical = canonicalize_passphrase(passphrase);
    let space_hash = blake3_hash(&canonical);
    let service = crate::discovery::DiscoveryService::with_bootstrap_peers(
        crate::discovery::FederatedDiscovery::new(backends),
        static_bootstrap,
    );

    let endpoints = match service.discover_endpoints(space_hash, 12).await {
        Ok(endpoints) => endpoints,
        Err(err) => {
            emit_ethersync_event(
                events_tx,
                EtherSyncEvent {
                    kind: "space_discovery_error".to_string(),
                    ts_ms: now_ms(),
                    space_id: Some(space_id.to_string()),
                    slot_id: None,
                    payload_b64: None,
                    text: None,
                    info: Some("federated discovery failed".to_string()),
                    error: Some(err.to_string()),
                },
            );
            return report;
        }
    };

    for endpoint in &endpoints {
        node.add_peer(*endpoint).await;
    }
    report.discovered = endpoints.len();

    if report.discovered > 0 {
        emit_ethersync_event(
            events_tx,
            EtherSyncEvent {
                kind: "space_discovery_seeded".to_string(),
                ts_ms: now_ms(),
                space_id: Some(space_id.to_string()),
                slot_id: None,
                payload_b64: None,
                text: None,
                info: Some(format!(
                    "discovered {} endpoint(s) via orp={} bundle={} static={} route_bias={} bundle_usable={} bundle_stale={} bundle(relays={}, bridges={}, keepers={})",
                    report.discovered,
                    report.used_orp,
                    report.used_bootstrap_bundle,
                    report.used_static_bootstrap,
                    report.route_bias,
                    report.bundle_usable,
                    report.bundle_stale,
                    report.bundle_relay_candidates,
                    report.bundle_bridge_candidates,
                    report.bundle_keeper_candidates
                )),
                error: None,
            },
        );
    }

    report
}

fn spawn_keeper_replication_task(
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    events_tx: broadcast::Sender<String>,
    keeper_envelopes: Arc<Mutex<HashMap<String, Vec<KeeperEnvelopeRecord>>>>,
    keeper_archive: Arc<Mutex<HashMap<String, Vec<KeeperEnvelopeRecord>>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(1500));

        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    let flush = flush_keeper_pending_envelopes(
                        &keeper_envelopes,
                        &keeper_archive,
                        None,
                    ).await;
                    if flush.moved > 0 {
                        emit_ethersync_event(
                            &events_tx,
                            EtherSyncEvent {
                                kind: "keeper_replication_flushed".to_string(),
                                ts_ms: now_ms(),
                                space_id: None,
                                slot_id: None,
                                payload_b64: None,
                                text: None,
                                info: Some(format!(
                                    "replicated {} envelope(s) across {} space(s)",
                                    flush.moved,
                                    flush.touched_spaces
                                )),
                                error: None,
                            },
                        );
                    }
                }
            }
        }

        let flush = flush_keeper_pending_envelopes(&keeper_envelopes, &keeper_archive, None).await;
        if flush.moved > 0 {
            emit_ethersync_event(
                &events_tx,
                EtherSyncEvent {
                    kind: "keeper_replication_flushed".to_string(),
                    ts_ms: now_ms(),
                    space_id: None,
                    slot_id: None,
                    payload_b64: None,
                    text: None,
                    info: Some(format!(
                        "replicated {} envelope(s) across {} space(s) during shutdown",
                        flush.moved, flush.touched_spaces
                    )),
                    error: None,
                },
            );
        }
    })
}

async fn flush_keeper_pending_envelopes(
    keeper_envelopes: &Arc<Mutex<HashMap<String, Vec<KeeperEnvelopeRecord>>>>,
    keeper_archive: &Arc<Mutex<HashMap<String, Vec<KeeperEnvelopeRecord>>>>,
    only_space: Option<&str>,
) -> KeeperReplicationFlush {
    let drained = {
        let mut guard = keeper_envelopes.lock().await;
        let mut drained = Vec::new();

        match only_space {
            Some(space_id) => {
                let drained_records = if let Some(entry) = guard.get_mut(space_id) {
                    std::mem::take(entry)
                } else {
                    Vec::new()
                };
                let should_remove = guard
                    .get(space_id)
                    .map(|items| items.is_empty())
                    .unwrap_or(false);
                if should_remove {
                    guard.remove(space_id);
                }
                if !drained_records.is_empty() {
                    drained.push((space_id.to_string(), drained_records));
                }
            }
            None => {
                let spaces = guard.keys().cloned().collect::<Vec<_>>();
                for space_id in spaces {
                    let drained_records = if let Some(entry) = guard.get_mut(&space_id) {
                        entry.drain(..).collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    };
                    let should_remove = guard
                        .get(&space_id)
                        .map(|items| items.is_empty())
                        .unwrap_or(false);
                    if should_remove {
                        guard.remove(&space_id);
                    }
                    if !drained_records.is_empty() {
                        drained.push((space_id, drained_records));
                    }
                }
            }
        }

        drained
    };

    if drained.is_empty() {
        return KeeperReplicationFlush::default();
    }

    let mut moved = 0usize;
    let touched_spaces = drained.len();
    let mut archive = keeper_archive.lock().await;

    for (space_id, records) in drained {
        let entry = archive.entry(space_id).or_default();
        for record in records {
            let exists = entry.iter().any(|existing| {
                existing.slot_id == record.slot_id
                    && existing.message.encrypted_payload == record.message.encrypted_payload
            });
            if !exists {
                entry.push(record);
                moved = moved.saturating_add(1);
            }
        }
        entry.sort_by_key(|record| record.slot_id);
    }

    KeeperReplicationFlush {
        moved,
        touched_spaces,
    }
}

async fn emit_keeper_pending_hint(
    events_tx: &broadcast::Sender<String>,
    keeper_envelopes: &Arc<Mutex<HashMap<String, Vec<KeeperEnvelopeRecord>>>>,
    space_key: &str,
    event_space_id: &str,
) {
    let pending = {
        let guard = keeper_envelopes.lock().await;
        guard.get(space_key).map(|items| items.len()).unwrap_or(0)
    };

    if pending == 0 {
        return;
    }

    emit_ethersync_event(
        events_tx,
        EtherSyncEvent {
            kind: "space_keeper_backfill_available".to_string(),
            ts_ms: now_ms(),
            space_id: Some(event_space_id.to_string()),
            slot_id: None,
            payload_b64: None,
            text: None,
            info: Some(format!(
                "{} pending keeper envelope(s) available for backfill",
                pending
            )),
            error: None,
        },
    );
}

async fn emit_keeper_archive_hint(
    events_tx: &broadcast::Sender<String>,
    keeper_archive: &Arc<Mutex<HashMap<String, Vec<KeeperEnvelopeRecord>>>>,
    space_key: &str,
    event_space_id: &str,
) {
    let archived = {
        let guard = keeper_archive.lock().await;
        guard.get(space_key).map(|items| items.len()).unwrap_or(0)
    };

    if archived == 0 {
        return;
    }

    emit_ethersync_event(
        events_tx,
        EtherSyncEvent {
            kind: "space_keeper_archive_available".to_string(),
            ts_ms: now_ms(),
            space_id: Some(event_space_id.to_string()),
            slot_id: None,
            payload_b64: None,
            text: None,
            info: Some(format!(
                "{} archived keeper envelope(s) available for backfill",
                archived
            )),
            error: None,
        },
    );
}

fn emit_ethersync_event(events_tx: &broadcast::Sender<String>, event: EtherSyncEvent) {
    if let Ok(json) = serde_json::to_string(&event) {
        let _ = events_tx.send(json);
    }
}

fn derive_space_id(passphrase: &str, label: Option<&str>) -> String {
    let base = derive_space_key(passphrase);
    let prefix = base.trim_start_matches("space-");
    if let Some(raw) = label {
        let clean = raw.trim();
        if !clean.is_empty() {
            return format!("{}:{}", clean, prefix);
        }
    }
    base
}

fn derive_space_key(passphrase: &str) -> String {
    let canonical = canonicalize_passphrase(passphrase);
    let hash = blake3_hash(&canonical);
    let prefix = hex::encode(&hash[..8]);
    format!("space-{}", prefix)
}

fn sanitize_filename(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' '))
        .collect::<String>()
        .trim()
        .to_string()
}

fn derive_transfer_id(filename: &str, total_bytes: usize, ts_ms: u64) -> String {
    let mut seed = Vec::with_capacity(filename.len() + 24);
    seed.extend_from_slice(filename.as_bytes());
    seed.extend_from_slice(&total_bytes.to_le_bytes());
    seed.extend_from_slice(&ts_ms.to_le_bytes());
    let hash = blake3_hash(&seed);
    hex::encode(&hash[..10])
}

async fn enqueue_keeper_envelope(
    keeper_envelopes: &Arc<Mutex<HashMap<String, Vec<KeeperEnvelopeRecord>>>>,
    space_id: &str,
    message: ethersync::EtherMessage,
    slot_id: u64,
) -> usize {
    let mut guard = keeper_envelopes.lock().await;
    let entry = guard.entry(space_id.to_string()).or_default();
    entry.push(KeeperEnvelopeRecord { slot_id, message });
    entry.len()
}

fn default_space_policy() -> EtherSpacePolicy {
    let runtime_cfg = crate::config::Config::from_env();
    EtherSpacePolicy {
        retention_tier: runtime_cfg.retention_tier,
        replication_factor: runtime_cfg.keeper_replication_factor,
        route_bias: if runtime_cfg.operator_bridge_capable
            && !runtime_cfg.bridge_bootstrap_hints.is_empty()
        {
            SpaceRouteBias::BridgePreferred
        } else if runtime_cfg.keeper_replication_enabled
            && runtime_cfg.keeper_replication_factor > 0
        {
            SpaceRouteBias::KeeperPreferred
        } else {
            SpaceRouteBias::Balanced
        },
    }
}

fn build_space_policy(
    retention_tier: Option<&str>,
    replication_factor: Option<usize>,
    route_bias: Option<&str>,
) -> EtherSpacePolicy {
    let mut policy = default_space_policy();

    if let Some(retention_tier) = retention_tier {
        let clean = retention_tier.trim();
        if !clean.is_empty() {
            policy.retention_tier = clean.to_string();
        }
    }

    if let Some(replication_factor) = replication_factor {
        policy.replication_factor = replication_factor.min(16);
    }

    if route_bias.is_some() {
        policy.route_bias = SpaceRouteBias::from_optional(route_bias);
    }

    if policy.retention_tier.eq_ignore_ascii_case("local-only") {
        policy.replication_factor = 0;
        if matches!(policy.route_bias, SpaceRouteBias::KeeperPreferred) {
            policy.route_bias = SpaceRouteBias::Balanced;
        }
    } else if policy.replication_factor == 0
        && !policy.retention_tier.eq_ignore_ascii_case("local-only")
    {
        policy.replication_factor = 1;
    }

    policy
}

async fn upsert_space_policy(
    policies: &Arc<Mutex<HashMap<String, EtherSpacePolicy>>>,
    space_id: &str,
    requested: EtherSpacePolicy,
    overwrite_existing: bool,
) -> EtherSpacePolicy {
    let mut guard = policies.lock().await;
    if !overwrite_existing {
        if let Some(existing) = guard.get(space_id) {
            return existing.clone();
        }
    }
    guard.insert(space_id.to_string(), requested.clone());
    requested
}

fn build_keeper_space_manifest(
    policy: &EtherSpacePolicy,
    pending_keeper_envelopes: usize,
    archived_keeper_envelopes: usize,
    bootstrap_bundle: &BootstrapBundleSummary,
    last_local_activity_ms: Option<u64>,
) -> KeeperSpaceManifest {
    let managed = policy_enables_keeper_replication(policy);
    let desired_replica_count = if managed {
        policy.replication_factor
    } else {
        0
    };
    let available_keeper_candidates = if managed { bootstrap_bundle.keepers } else { 0 };
    let selected_keeper_targets = desired_replica_count.min(available_keeper_candidates);
    let candidate_shortfall = desired_replica_count.saturating_sub(available_keeper_candidates);
    let replication_stage = if !managed {
        "local-only"
    } else if archived_keeper_envelopes > 0 && pending_keeper_envelopes > 0 {
        "staged-and-backfillable"
    } else if archived_keeper_envelopes > 0 {
        "backfillable"
    } else if pending_keeper_envelopes > 0 && available_keeper_candidates > 0 {
        "staging"
    } else if pending_keeper_envelopes > 0 {
        "awaiting-keeper-capacity"
    } else if available_keeper_candidates > 0 {
        "managed-ready"
    } else {
        "awaiting-network"
    };

    KeeperSpaceManifest {
        managed,
        keeper_route_intent: policy.route_bias.as_str().to_string(),
        desired_replica_count,
        available_keeper_candidates,
        selected_keeper_targets,
        candidate_shortfall,
        replication_stage: replication_stage.to_string(),
        last_local_activity_ms,
    }
}

async fn touch_keeper_activity(
    keeper_last_activity: &Arc<Mutex<HashMap<String, u64>>>,
    space_id: &str,
) -> u64 {
    let ts = now_ms();
    keeper_last_activity
        .lock()
        .await
        .insert(space_id.to_string(), ts);
    ts
}

async fn emit_keeper_manifest_hint(
    events_tx: &broadcast::Sender<String>,
    space_id: &str,
    policy: &EtherSpacePolicy,
    keeper_envelopes: &Arc<Mutex<HashMap<String, Vec<KeeperEnvelopeRecord>>>>,
    keeper_archive: &Arc<Mutex<HashMap<String, Vec<KeeperEnvelopeRecord>>>>,
    keeper_last_activity: &Arc<Mutex<HashMap<String, u64>>>,
    bootstrap_bundle: &BootstrapBundleSummary,
) {
    let pending_keeper_envelopes = keeper_envelopes
        .lock()
        .await
        .get(space_id)
        .map(|items| items.len())
        .unwrap_or(0);
    let archived_keeper_envelopes = keeper_archive
        .lock()
        .await
        .get(space_id)
        .map(|items| items.len())
        .unwrap_or(0);
    let last_local_activity_ms = keeper_last_activity.lock().await.get(space_id).copied();
    let manifest = build_keeper_space_manifest(
        policy,
        pending_keeper_envelopes,
        archived_keeper_envelopes,
        bootstrap_bundle,
        last_local_activity_ms,
    );

    emit_ethersync_event(
        events_tx,
        EtherSyncEvent {
            kind: "space_keeper_manifest_updated".to_string(),
            ts_ms: now_ms(),
            space_id: Some(space_id.to_string()),
            slot_id: None,
            payload_b64: None,
            text: None,
            info: Some(format!(
                "managed={} stage={} desired_targets={} selected_targets={} candidate_shortfall={} route_intent={}",
                manifest.managed,
                manifest.replication_stage,
                manifest.desired_replica_count,
                manifest.selected_keeper_targets,
                manifest.candidate_shortfall,
                manifest.keeper_route_intent
            )),
            error: None,
        },
    );
}

fn policy_enables_keeper_replication(policy: &EtherSpacePolicy) -> bool {
    policy.replication_factor > 0 && !policy.retention_tier.eq_ignore_ascii_case("local-only")
}

fn default_high_risk_gate_reasons(
    orp_enabled: bool,
    keeper_replication_enabled: bool,
    bootstrap_bundle_loaded: bool,
    bridge_hint_count: usize,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if !orp_enabled {
        reasons.push("ORP runtime is not enabled for this EtherSync node".to_string());
    }
    reasons.push(
        "ORP-HighRisk circuit planning is available, but the routed session data plane is not active yet"
            .to_string(),
    );
    if bridge_hint_count == 0 && !bootstrap_bundle_loaded {
        reasons.push("bridge bootstrap attestation is not available yet".to_string());
    }
    if !keeper_replication_enabled {
        reasons.push("keeper-backed replicated retention is not available yet".to_string());
    }
    reasons
}

fn default_ethersync_status() -> EtherSyncStatus {
    let runtime_cfg = crate::config::Config::from_env();
    let bootstrap_bundle_validation =
        crate::bootstrap_bundle::validate_loaded_bootstrap_bundle(&runtime_cfg);
    let bootstrap_bundle = bootstrap_bundle_validation
        .as_ref()
        .map(|report| report.summary.clone())
        .unwrap_or_default();
    let high_risk_gate_reasons = default_high_risk_gate_reasons(
        false,
        runtime_cfg.keeper_replication_enabled,
        bootstrap_bundle.loaded,
        runtime_cfg.bridge_bootstrap_hints.len(),
    );

    EtherSyncStatus {
        running: false,
        bind_addr: None,
        local_addr: None,
        peer_count: 0,
        subscription_count: 0,
        spaces: Vec::new(),
        orp_enabled: false,
        route_cache_size: 0,
        route_offers_count: 0,
        last_orp_activity_ms: None,
        retention_tier: runtime_cfg.retention_tier.clone(),
        replay_window_slots: LOOKBACK_SLOTS,
        keeper_replication_enabled: runtime_cfg.keeper_replication_enabled,
        keeper_replication_factor: runtime_cfg.keeper_replication_factor,
        bootstrap_peer_count: 0,
        discovery_bootstrap_peer_count: runtime_cfg.discovery_bootstrap_peers.len(),
        bridge_bootstrap_enabled: !runtime_cfg.bridge_bootstrap_hints.is_empty()
            || bootstrap_bundle.bridges > 0
            || !runtime_cfg.assist_relays.is_empty(),
        bridge_hint_count: runtime_cfg.bridge_bootstrap_hints.len(),
        high_risk_available: false,
        high_risk_gate_reasons,
        high_risk_circuits_observed: 0,
        high_risk_active_circuits: 0,
        high_risk_closed_circuits: 0,
        high_risk_control_frames_observed: 0,
        high_risk_cover_packets_observed: 0,
        high_risk_last_activity_ms: None,
        operator_id_hint: runtime_cfg.operator_id.clone(),
        operator_region_hint: runtime_cfg.operator_region.clone(),
        bootstrap_bundle_loaded: bootstrap_bundle.loaded,
        bootstrap_bundle_mirrors: bootstrap_bundle.mirrors,
        bootstrap_bundle_relays: bootstrap_bundle.relays,
        bootstrap_bundle_bridges: bootstrap_bundle.bridges,
        bootstrap_bundle_keepers: bootstrap_bundle.keepers,
        bootstrap_bundle_usable: bootstrap_bundle_validation
            .as_ref()
            .map(|report| report.is_usable)
            .unwrap_or(false),
        bootstrap_bundle_structurally_weak: bootstrap_bundle_validation
            .as_ref()
            .map(|report| report.is_structurally_weak)
            .unwrap_or(false),
        bootstrap_bundle_stale: bootstrap_bundle_validation
            .as_ref()
            .map(|report| report.staleness.is_stale())
            .unwrap_or(false),
        bootstrap_bundle_warning_count: bootstrap_bundle_validation
            .as_ref()
            .map(|report| report.issue_counts.warning)
            .unwrap_or(0),
        bootstrap_bundle_error_count: bootstrap_bundle_validation
            .as_ref()
            .map(|report| report.issue_counts.error)
            .unwrap_or(0),
        pending_keeper_envelopes: 0,
        keeper_space_count: 0,
        archived_keeper_envelopes: 0,
        keeper_archive_space_count: 0,
        keeper_manifest_space_count: 0,
        keeper_candidate_shortfall_space_count: 0,
        managed_ready_space_count: 0,
        last_keeper_activity_ms: None,
        managed_space_count: 0,
        bridge_preferred_space_count: 0,
        keeper_preferred_space_count: 0,
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
