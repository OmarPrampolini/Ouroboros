//! EtherNode - main interface for EtherSync
//!
//! Fully integrated node with storage, network, and gossip.

use crate::{
    coordinate::{EtherCoordinate, LOOKBACK_SLOTS},
    gossip::{GossipEngine, PeerManager},
    message::EtherMessage,
    network::EtherUdpSocket,
    onion::{
        decrypt_reply_layers, derive_onion_public_key, derive_onion_session_key,
        derive_rotating_onion_secret_key, encrypt_reply_layers, open_hop_capsule, seal_hop_capsule,
        HighRiskHopCapsule, HopHandshake, OnionCodec, OnionLayer,
    },
    routing::{
        encode_orp_frame, CircuitClose, CircuitExtend, CircuitOpen, CircuitReady, CoverPacket,
        DeliveryReceipt, ForwardDeliveryNotice, HighRiskCircuitHop, HighRiskCircuitPlan, HighRiskGateSnapshot,
        HighRiskRouteDescriptor, OrpFrame, RouteAnnouncement, RouteCache, RouteCapabilities,
        RouteClass, RouteDirection, RouteForward, RouteHop, RouteLookup, RouteOffer,
        SUBSPACE_CIRCUIT_CLOSE, SUBSPACE_CIRCUIT_EXTEND, SUBSPACE_CIRCUIT_OPEN,
        SUBSPACE_CIRCUIT_READY, SUBSPACE_COVER_TRAFFIC, SUBSPACE_DELIVERY_NOTICE,
        SUBSPACE_ROUTE_ANNOUNCE, SUBSPACE_ROUTE_FORWARD, SUBSPACE_ROUTE_LOOKUP,
        SUBSPACE_ROUTE_OFFER, SUBSPACE_USER,
    },
    storage::EtherStorage,
    EtherSyncError,
};
use ouroboros_crypto::derive::canonicalize_passphrase;
use ouroboros_crypto::hash::blake3_hash;
use ouroboros_crypto::random::fill_random;
use serde::Serialize;
use std::collections::{HashMap as StdHashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot, Mutex, Notify, RwLock};
use tokio::time::interval;
use tracing::{error, info, trace, warn};
use zeroize::{Zeroize, Zeroizing};

/// EtherNode configuration
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Bind address for UDP socket
    pub bind_addr: String,
    /// Max storage per slot
    pub max_storage_per_slot: usize,
    /// Bootstrap peers (static list)
    pub bootstrap_peers: Vec<SocketAddr>,
    /// Gossip interval in seconds
    pub gossip_interval_secs: u64,
    /// Slot sweep interval in seconds
    pub sweep_interval_secs: u64,
    /// Erasure coding: data fragments (k)
    pub erasure_data_fragments: usize,
    /// Erasure coding: parity fragments (m)
    pub erasure_parity_fragments: usize,
    /// Enable compression
    pub enable_compression: bool,
    /// Message TTL for gossip forwarding
    pub gossip_ttl: u8,
    /// Slot duration override (0 = use default)
    pub slot_duration_secs: u64,
    /// Enable ORP deterministic overlay routing
    pub enable_orp: bool,
    /// How often to publish ORP route announcements (seconds)
    pub orp_announce_interval_secs: u64,
    /// ORP role hints advertised in route announcements.
    pub orp_can_relay: bool,
    pub orp_wan_assist: bool,
    pub orp_tor_capable: bool,
    pub orp_bridge_capable: bool,
    pub orp_keeper_capable: bool,
    pub orp_operator_id_hint: String,
    pub orp_region_hint: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".to_string(),
            max_storage_per_slot: 1000,
            bootstrap_peers: Vec::new(),
            gossip_interval_secs: 30,
            sweep_interval_secs: 10,
            erasure_data_fragments: 4,
            erasure_parity_fragments: 2,
            enable_compression: true,
            gossip_ttl: 3,
            slot_duration_secs: 0,
            enable_orp: false,
            orp_announce_interval_secs: 60,
            orp_can_relay: false,
            orp_wan_assist: false,
            orp_tor_capable: false,
            orp_bridge_capable: false,
            orp_keeper_capable: false,
            orp_operator_id_hint: "local-node".to_string(),
            orp_region_hint: "unknown".to_string(),
        }
    }
}

/// Subscription state for a passphrase
#[derive(Debug)]
struct Subscription {
    /// Passphrase for this subscription
    _passphrase: String,
    /// Sender channel for incoming messages
    sender: mpsc::Sender<EtherMessage>,
    /// Space hash (derived from passphrase)
    _space_hash: [u8; 32],
    /// Last scanned slot
    _last_slot: RwLock<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HighRiskCircuitSnapshot {
    pub circuit_id: String,
    pub space_prefix: String,
    pub origin_id: Option<String>,
    pub active: bool,
    pub opened_at_slot: Option<u64>,
    pub expires_at_slot: Option<u64>,
    pub first_hop: Option<String>,
    pub last_hop: Option<String>,
    pub extend_count: usize,
    pub highest_hop_index: u8,
    pub cover_packets: usize,
    pub control_frames_seen: usize,
    pub close_reason: Option<u16>,
    pub last_updated_ms: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct HighRiskCircuitStats {
    pub circuits_observed: usize,
    pub active_circuits: usize,
    pub closed_circuits: usize,
    pub control_frames_observed: usize,
    pub cover_packets_observed: usize,
    pub last_activity_ms: Option<u64>,
    pub recent_circuits: Vec<HighRiskCircuitSnapshot>,
}

#[derive(Debug, Clone)]
struct ObservedHighRiskCircuit {
    circuit_id: [u8; 16],
    space_prefix: [u8; 8],
    origin_id: Option<[u8; 16]>,
    active: bool,
    opened_at_slot: Option<u64>,
    expires_at_slot: Option<u64>,
    first_hop: Option<String>,
    last_hop: Option<String>,
    extend_count: usize,
    highest_hop_index: u8,
    cover_packets: usize,
    control_frames_seen: usize,
    close_reason: Option<u16>,
    last_updated_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighRiskLocalRole {
    Origin,
    Entry,
    Middle,
    Exit,
}

#[derive(Debug)]
struct HighRiskRouteBinding {
    descriptor: HighRiskRouteDescriptor,
    local_role: HighRiskLocalRole,
    deliver_tx: Option<mpsc::Sender<Vec<u8>>>,
    hop_session_key: Option<[u8; 32]>,
    reply_session_key: Option<[u8; 32]>,
    onion_codec: Option<OnionCodec>,
    ready_state: Option<Arc<AtomicBool>>,
    ready_notify: Option<Arc<Notify>>,
    last_updated_ms: u64,
}

impl Drop for HighRiskRouteBinding {
    fn drop(&mut self) {
        if let Some(key) = self.hop_session_key.as_mut() {
            key.zeroize();
        }
        if let Some(key) = self.reply_session_key.as_mut() {
            key.zeroize();
        }
    }
}

#[derive(Debug)]
struct PendingHighRiskTransportSession {
    circuit_id: [u8; 16],
    descriptor: HighRiskRouteDescriptor,
    local_role: HighRiskLocalRole,
    receiver: mpsc::Receiver<Vec<u8>>,
    ready_state: Arc<AtomicBool>,
    ready_notify: Arc<Notify>,
}

#[derive(Debug)]
pub struct HighRiskTransportSession {
    pub circuit_id: [u8; 16],
    pub descriptor: HighRiskRouteDescriptor,
    pub local_role: HighRiskLocalRole,
    pub receiver: mpsc::Receiver<Vec<u8>>,
    ready_state: Arc<AtomicBool>,
    ready_notify: Arc<Notify>,
}

impl HighRiskTransportSession {
    /// Wait until the exit confirms that the circuit has been installed locally.
    pub async fn wait_ready(&self, timeout: Duration) -> Result<(), EtherSyncError> {
        if self.ready_state.load(Ordering::SeqCst) {
            return Ok(());
        }

        tokio::time::timeout(timeout, async {
            loop {
                let notified = self.ready_notify.notified();
                if self.ready_state.load(Ordering::SeqCst) {
                    return;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| EtherSyncError::NetworkError("circuit establishment timed out".to_string()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct HighRiskAckKey {
    circuit_id: [u8; 16],
    packet_id: [u8; 16],
    direction: RouteDirection,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
enum HighRiskPayloadFrame {
    Application(Vec<u8>),
    DeliveryReceipt(DeliveryReceipt),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Confirmed,
    Unconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct HighRiskForwardKey {
    circuit_id: [u8; 16],
    packet_id: [u8; 16],
    direction: RouteDirection,
    hop_index: u8,
}

/// EtherNode - main entry point for EtherSync protocol
#[derive(Debug)]
pub struct EtherNode {
    config: NodeConfig,
    /// Storage backend
    storage: Arc<Mutex<EtherStorage>>,
    /// UDP socket for networking
    socket: Arc<EtherUdpSocket>,
    /// Gossip engine (initialized in run())
    gossip_engine: Arc<RwLock<Option<GossipEngine>>>,
    /// Peer manager
    peers: Arc<PeerManager>,
    /// Active subscriptions
    subscriptions: Arc<RwLock<Vec<Subscription>>>,
    /// Recently forwarded messages (deduplication)
    seen_messages: Arc<RwLock<HashSet<[u8; 32]>>>,
    /// Max seen cache size
    max_seen_cache: usize,
    /// ORP route cache (shared across tasks)
    route_cache: Arc<Mutex<RouteCache>>,
    /// Ephemeral node id for the current session (random 16 bytes)
    node_id: [u8; 16],
    /// Static onion secret for per-hop DH session derivation.
    onion_secret_key: [u8; 32],
    /// Active ORP spaces: maps space_prefix (first 8 bytes of space_hash)
    /// to the passphrase that was used to join.  Only populated when
    /// `start_orp_for_space` is called.
    orp_spaces: Arc<RwLock<StdHashMap<[u8; 8], String>>>,
    /// Handles for ORP announce tasks keyed by space prefix, so duplicate joins
    /// do not spawn duplicate announcers and shutdown can abort them cleanly.
    orp_announce_tasks: Arc<Mutex<StdHashMap<[u8; 8], tokio::task::JoinHandle<()>>>>,
    /// Observed and locally prepared high-risk circuits.
    high_risk_circuits: Arc<Mutex<StdHashMap<[u8; 16], ObservedHighRiskCircuit>>>,
    /// High-risk route bindings for the local node's role within observed circuits.
    high_risk_routes: Arc<Mutex<StdHashMap<[u8; 16], HighRiskRouteBinding>>>,
    /// Pending inbound high-risk sessions for local acceptors, bucketed per space.
    pending_high_risk_accepts:
        Arc<Mutex<StdHashMap<[u8; 8], VecDeque<PendingHighRiskTransportSession>>>>,
    /// Pending end-to-end delivery acknowledgments for locally-originated packets.
    pending_high_risk_acks: Arc<Mutex<StdHashMap<HighRiskAckKey, oneshot::Sender<()>>>>,
    /// Notifier for inbound high-risk session availability.
    high_risk_accept_notify: Arc<Notify>,
    /// Deduplication cache for forwarded high-risk packets.
    high_risk_forward_seen: Arc<Mutex<StdHashMap<HighRiskForwardKey, u64>>>,
}

impl EtherNode {
    fn route_class_for_config(config: &NodeConfig) -> RouteClass {
        if config.orp_bridge_capable {
            RouteClass::Bridge
        } else if config.orp_keeper_capable {
            RouteClass::Keeper
        } else if config.orp_wan_assist || config.orp_can_relay {
            RouteClass::Assisted
        } else {
            RouteClass::Direct
        }
    }

    /// Create and initialize new EtherNode
    ///
    /// Binds UDP socket and initializes all components
    pub async fn new(config: NodeConfig) -> Result<Self, EtherSyncError> {
        // Bind UDP socket
        let socket = if config.bind_addr == "0.0.0.0:0" {
            EtherUdpSocket::bind_ephemeral().await?
        } else {
            let addr: SocketAddr = config.bind_addr.parse().map_err(|_| {
                EtherSyncError::NetworkError(format!("Invalid bind address: {}", config.bind_addr))
            })?;
            EtherUdpSocket::bind(addr).await?
        };

        let local_addr = socket.local_addr();
        info!("EtherNode UDP socket bound to {}", local_addr);

        // Wrap socket in Arc for sharing
        let socket = Arc::new(socket);

        // Initialize storage
        let storage = Arc::new(Mutex::new(EtherStorage::new()));

        // Initialize peer manager with bootstrap peers
        let peers = Arc::new(PeerManager::new(config.bootstrap_peers.clone()));

        // Initialize gossip engine (notifier added in run())
        let gossip_engine = Arc::new(RwLock::new(Some(GossipEngine::new(
            Arc::clone(&storage),
            Arc::clone(&peers),
            Arc::clone(&socket),
        ))));

        // Generate ephemeral node id for this session
        let mut node_id = [0u8; 16];
        fill_random(&mut node_id)
            .map_err(|_| EtherSyncError::NetworkError("failed to generate node id".to_string()))?;
        let mut onion_secret_key = [0u8; 32];
        fill_random(&mut onion_secret_key).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate onion secret key".to_string())
        })?;

        Ok(Self {
            config,
            storage,
            socket,
            gossip_engine,
            peers,
            subscriptions: Arc::new(RwLock::new(Vec::new())),
            seen_messages: Arc::new(RwLock::new(HashSet::new())),
            max_seen_cache: 10000,
            route_cache: Arc::new(Mutex::new(RouteCache::new())),
            node_id,
            onion_secret_key,
            orp_spaces: Arc::new(RwLock::new(StdHashMap::new())),
            orp_announce_tasks: Arc::new(Mutex::new(StdHashMap::new())),
            high_risk_circuits: Arc::new(Mutex::new(StdHashMap::new())),
            high_risk_routes: Arc::new(Mutex::new(StdHashMap::new())),
            pending_high_risk_accepts: Arc::new(Mutex::new(StdHashMap::new())),
            pending_high_risk_acks: Arc::new(Mutex::new(StdHashMap::new())),
            high_risk_accept_notify: Arc::new(Notify::new()),
            high_risk_forward_seen: Arc::new(Mutex::new(StdHashMap::new())),
        })
    }

    /// Create with persistent SQLite storage
    #[cfg(feature = "persistent-storage")]
    pub async fn new_persistent(config: NodeConfig, db_path: &str) -> Result<Self, EtherSyncError> {
        let mut node = Self::new(config).await?;
        node.storage = Arc::new(Mutex::new(EtherStorage::new_persistent(db_path)?));
        Ok(node)
    }

    /// Publish a message to the ether
    ///
    /// Creates message, stores locally, and gossips to peers
    pub async fn publish(
        &self,
        passphrase: &str,
        payload: &[u8],
    ) -> Result<EtherMessage, EtherSyncError> {
        let slot = EtherCoordinate::current_slot();

        // Create message
        let message = EtherMessage::new(passphrase, slot, payload, 0, 1)?;

        // Derive message hash for storage
        let hash = Self::message_hash(&message);

        // Store locally
        {
            let mut storage = self.storage.lock().await;
            storage.store(slot, hash, message.clone())?;
        }

        // Mark as seen (don't forward our own messages back to us)
        {
            let mut seen = self.seen_messages.write().await;
            seen.insert(hash);
            self.cleanup_seen_cache(&mut seen).await;
        }

        // Gossip to peers (with retry until engine is ready)
        let gossip_engine = self.gossip_engine.clone();
        let msg = message.clone();

        tokio::spawn(async move {
            // Wait up to 5 seconds for gossip engine to be initialized
            for _ in 0..50 {
                {
                    let engine_guard = gossip_engine.read().await;
                    if let Some(ref engine) = *engine_guard {
                        if let Err(e) = engine.publish(msg).await {
                            trace!("Failed to gossip message: {:?}", e);
                        }
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            trace!("Gossip engine not available after 5s, message not gossiped");
        });

        info!(
            "Published message to slot {} ({} bytes)",
            slot,
            payload.len()
        );
        Ok(message)
    }

    /// Subscribe to messages for a passphrase
    ///
    /// Returns a receiver channel that yields messages for this passphrase
    pub async fn subscribe(
        &self,
        passphrase: &str,
    ) -> Result<mpsc::Receiver<EtherMessage>, EtherSyncError> {
        let (tx, rx) = mpsc::channel(100);

        // Derive space hash from passphrase (use same canonicalization as message)
        let passphrase_bytes = canonicalize_passphrase(passphrase);
        let space_hash = blake3_hash(&passphrase_bytes);

        // Create subscription
        let subscription = Subscription {
            _passphrase: passphrase.to_string(),
            sender: tx,
            _space_hash: space_hash,
            _last_slot: RwLock::new(0),
        };

        // Add to subscriptions
        {
            let mut subs = self.subscriptions.write().await;
            subs.push(subscription);
        }

        info!(
            "Subscribed to space {} ({} active subscriptions)",
            hex::encode(&space_hash[..8]),
            self.subscriptions.read().await.len()
        );

        Ok(rx)
    }

    /// Sweep a slot for messages matching subscriptions
    ///
    /// Checks local storage and requests missing messages from peers
    async fn _sweep_slot(&self, slot: u64) -> Result<(), EtherSyncError> {
        let storage = self.storage.lock().await;
        let slot_messages = storage.get_slot_messages(slot)?;
        drop(storage);

        // Get subscriptions
        let subs = self.subscriptions.read().await;
        if subs.is_empty() {
            return Ok(());
        }

        // Check each message against subscriptions
        for message in slot_messages {
            for sub in subs.iter() {
                // Check if message belongs to this subscription's space
                if message.header.coordinate_hash == sub._space_hash {
                    // Try to send - ignore errors if channel closed
                    let _ = sub.sender.send(message.clone()).await;
                }
            }
        }

        // Request missing messages from peers
        // In full implementation, this would:
        // 1. Build digest of what we have
        // 2. Send digest to peers
        // 3. Request missing hashes

        Ok(())
    }

    /// Check if a message matches a subscription space
    fn _message_matches_space(&self, message: &EtherMessage, space_hash: &[u8; 32]) -> bool {
        &message.header.coordinate_hash == space_hash
    }

    /// Run the node with all background tasks
    ///
    /// This spawns:
    /// - Gossip engine (digest exchange, message forwarding)
    /// - Subscription router (routes received messages to subscribers)
    /// - Slot sweep task (scan for new messages)
    /// - Peer cleanup task
    pub async fn run(
        &self,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), EtherSyncError> {
        info!("EtherNode starting...");

        // Channel for gossip engine to notify new messages
        let (new_msg_tx, mut new_msg_rx) = mpsc::channel::<EtherMessage>(100);

        // Clone refs for subscription router
        let subscriptions = Arc::clone(&self.subscriptions);

        // Clone route_cache for the router task
        let route_cache_router = Arc::clone(&self.route_cache);

        // Clones needed for Lookup → Offer response generation
        let router_node_id = self.node_id;
        let router_socket = Arc::clone(&self.socket);
        let router_gossip = Arc::clone(&self.gossip_engine);
        let router_storage = Arc::clone(&self.storage);
        let router_seen = Arc::clone(&self.seen_messages);
        let router_max_seen = self.max_seen_cache;
        let router_enable_orp = self.config.enable_orp;
        let router_high_risk_circuits = Arc::clone(&self.high_risk_circuits);
        let router_high_risk_routes = Arc::clone(&self.high_risk_routes);
        let router_pending_high_risk_accepts = Arc::clone(&self.pending_high_risk_accepts);
        let router_pending_high_risk_acks = Arc::clone(&self.pending_high_risk_acks);
        let router_high_risk_accept_notify = Arc::clone(&self.high_risk_accept_notify);
        let router_high_risk_forward_seen = Arc::clone(&self.high_risk_forward_seen);
        let router_onion_secret_key = Zeroizing::new(self.onion_secret_key);

        // Spawn subscription router task
        let router_handle = tokio::spawn(async move {
            while let Some(msg) = new_msg_rx.recv().await {
                let subspace = msg.header.subspace;

                // Route message to matching subscriptions
                let subs = subscriptions.read().await;
                for sub in subs.iter() {
                    // Derive expected coordinate_hash for this subscription at the
                    // message's subspace so both user and ORP subspaces are matched.
                    let expected_hash = match EtherCoordinate::derive(
                        &sub._passphrase,
                        msg.header.slot_id,
                        subspace,
                    ) {
                        Ok(coord) => {
                            use ouroboros_crypto::hash::blake3_hash;
                            let mut encoded = Vec::with_capacity(32 + 8 + 8 + 16);
                            encoded.extend_from_slice(&coord.space_hash);
                            encoded.extend_from_slice(&coord.slot.to_be_bytes());
                            encoded.extend_from_slice(&coord.subspace.to_be_bytes());
                            encoded.extend_from_slice(&coord.entropy);
                            blake3_hash(&encoded)
                        }
                        Err(_) => continue,
                    };

                    if msg.header.coordinate_hash != expected_hash {
                        continue;
                    }

                    if subspace == SUBSPACE_USER {
                        // Regular user payload — deliver to subscriber channel.
                        let _ = sub.sender.send(msg.clone()).await;
                        continue;
                    }

                    // ORP control frame — decrypt and feed into route cache.
                    let plaintext = match msg.decrypt(&sub._passphrase) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let frame = match crate::routing::decode_orp_frame(&plaintext) {
                        Ok(f) => f,
                        Err(_) => continue,
                    };
                    let current_slot = EtherCoordinate::current_slot();
                    let passphrase_bytes =
                        ouroboros_crypto::derive::canonicalize_passphrase(&sub._passphrase);
                    let space_hash = ouroboros_crypto::hash::blake3_hash(&passphrase_bytes);
                    let mut space_prefix = [0u8; 8];
                    space_prefix.copy_from_slice(&space_hash[..8]);
                    let dummy_src: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();

                    let mut cache = route_cache_router.lock().await;
                    match frame {
                        OrpFrame::Announce(ann) => {
                            cache.insert_announcement(ann, dummy_src, current_slot, &space_hash);
                        }
                        OrpFrame::Offer(offer) => {
                            cache.insert_offer(offer);
                        }
                        OrpFrame::Forward(forward) => {
                            drop(cache);
                            handle_high_risk_forward(
                                &router_high_risk_routes,
                                &router_pending_high_risk_acks,
                                &router_high_risk_forward_seen,
                                &router_storage,
                                &router_seen,
                                router_max_seen,
                                &router_gossip,
                                &sub._passphrase,
                                current_slot,
                                forward,
                            )
                            .await;
                            continue;
                        }
                        OrpFrame::DeliveryNotice(notice) => {
                            drop(cache);
                            handle_high_risk_delivery_notice(
                                &router_high_risk_routes,
                                &router_storage,
                                &router_seen,
                                router_max_seen,
                                &router_gossip,
                                &sub._passphrase,
                                current_slot,
                                notice,
                            )
                            .await;
                            continue;
                        }
                        OrpFrame::CircuitOpen(open) => {
                            drop(cache);
                            record_high_risk_open(
                                &router_high_risk_circuits,
                                space_prefix,
                                msg.header.slot_id,
                                &open,
                            )
                            .await;
                            if let Some(ready) = install_high_risk_route_binding(
                                &router_high_risk_routes,
                                &router_pending_high_risk_accepts,
                                &router_high_risk_accept_notify,
                                &*router_onion_secret_key,
                                router_node_id,
                                open.circuit_id,
                                space_prefix,
                                &open.hop_payload,
                                current_slot,
                            )
                            .await
                            {
                                let _ = publish_orp_frame_router(
                                    &router_storage,
                                    &router_seen,
                                    router_max_seen,
                                    &router_gossip,
                                    &sub._passphrase,
                                    current_slot,
                                    OrpFrame::CircuitReady(ready),
                                    SUBSPACE_CIRCUIT_READY,
                                )
                                .await;
                            }
                            continue;
                        }
                        OrpFrame::CircuitExtend(extend) => {
                            drop(cache);
                            record_high_risk_extend(
                                &router_high_risk_circuits,
                                space_prefix,
                                msg.header.slot_id,
                                &extend,
                            )
                            .await;
                            if let Some(ready) = install_high_risk_route_binding(
                                &router_high_risk_routes,
                                &router_pending_high_risk_accepts,
                                &router_high_risk_accept_notify,
                                &*router_onion_secret_key,
                                router_node_id,
                                extend.circuit_id,
                                space_prefix,
                                &extend.hop_payload,
                                current_slot,
                            )
                            .await
                            {
                                let _ = publish_orp_frame_router(
                                    &router_storage,
                                    &router_seen,
                                    router_max_seen,
                                    &router_gossip,
                                    &sub._passphrase,
                                    current_slot,
                                    OrpFrame::CircuitReady(ready),
                                    SUBSPACE_CIRCUIT_READY,
                                )
                                .await;
                            }
                            continue;
                        }
                        OrpFrame::CircuitClose(close) => {
                            drop(cache);
                            let should_remove = {
                                let routes_guard = router_high_risk_routes.lock().await;
                                routes_guard
                                    .get(&close.circuit_id)
                                    .map(|binding| verify_high_risk_close(binding, &close))
                                    .unwrap_or(false)
                            };
                            if should_remove {
                                record_high_risk_close(
                                    &router_high_risk_circuits,
                                    space_prefix,
                                    msg.header.slot_id,
                                    &close,
                                )
                                .await;
                                remove_high_risk_route_binding(
                                    &router_high_risk_routes,
                                    &router_pending_high_risk_accepts,
                                    &router_pending_high_risk_acks,
                                    close.circuit_id,
                                )
                                .await;
                            }
                            continue;
                        }
                        OrpFrame::Cover(cover) => {
                            drop(cache);
                            record_high_risk_cover(
                                &router_high_risk_circuits,
                                space_prefix,
                                msg.header.slot_id,
                                &cover,
                            )
                            .await;
                            continue;
                        }
                        OrpFrame::CircuitReady(ready) => {
                            drop(cache);
                            handle_high_risk_circuit_ready(&router_high_risk_routes, ready).await;
                            continue;
                        }
                        OrpFrame::Lookup(lookup) if router_enable_orp => {
                            // Check if OUR assist_tag matches the lookup target_tag.
                            let mut our_tag = [0u8; 8];
                            let tag_hash = ouroboros_crypto::hash::blake3_hash(&router_node_id);
                            our_tag.copy_from_slice(&tag_hash[..8]);

                            if our_tag != lookup.target_tag {
                                // Not addressed to us — ignore.
                                continue;
                            }

                            let local_addr = router_socket.local_addr();
                            let hop = if !local_addr.ip().is_unspecified() {
                                RouteHop::Direct { addr: local_addr }
                            } else {
                                // Can't offer a route if we have no reachable addr.
                                continue;
                            };

                            let offer = RouteOffer {
                                version: 1,
                                lookup_id: lookup.lookup_id,
                                responder_id: router_node_id,
                                next_hop: hop,
                                score: 5000, // direct = highest base score
                            };
                            let offer_frame = OrpFrame::Offer(offer);
                            let offer_payload = match crate::routing::encode_orp_frame(&offer_frame)
                            {
                                Ok(p) => p,
                                Err(_) => continue,
                            };

                            let slot = EtherCoordinate::current_slot();
                            let offer_msg = match EtherMessage::new_control_message(
                                &sub._passphrase,
                                slot,
                                &offer_payload,
                                SUBSPACE_ROUTE_OFFER,
                            ) {
                                Ok(m) => m,
                                Err(_) => continue,
                            };

                            let hash =
                                ouroboros_crypto::hash::blake3_hash(&offer_msg.encrypted_payload);
                            {
                                let mut st = router_storage.lock().await;
                                let _ = st.store(slot, hash, offer_msg.clone());
                            }
                            {
                                let mut seen = router_seen.write().await;
                                seen.insert(hash);
                                if seen.len() > router_max_seen {
                                    let to_remove: Vec<_> =
                                        seen.iter().take(seen.len() / 2).cloned().collect();
                                    for h in to_remove {
                                        seen.remove(&h);
                                    }
                                }
                            }

                            // Gossip the offer
                            let ge = router_gossip.clone();
                            let m = offer_msg;
                            tokio::spawn(async move {
                                for _ in 0..50 {
                                    {
                                        let g = ge.read().await;
                                        if let Some(ref engine) = *g {
                                            let _ = engine.publish(m).await;
                                            return;
                                        }
                                    }
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                            });

                            trace!(
                                "ORP: responded to lookup {:?} with direct offer",
                                &lookup.lookup_id[..4]
                            );
                        }
                        _ => {} // Forward, Ack, Lookup when ORP disabled
                    }
                    drop(cache);
                }
            }
        });

        // Set notifier on existing gossip engine
        {
            let mut engine_guard = self.gossip_engine.write().await;
            if let Some(ref mut engine) = *engine_guard {
                engine.set_message_notifier(new_msg_tx);
            }
        }

        // Spawn slot sweep task
        let mut sweep_handle = self.spawn_sweep_task();

        // Spawn peer cleanup task
        let mut cleanup_handle = self.spawn_cleanup_task();

        info!("EtherNode running with gossip engine");

        // Run gossip engine (this blocks until error or shutdown)
        let engine = self.gossip_engine.read().await;
        if let Some(ref engine) = *engine {
            tokio::select! {
                result = engine.run() => {
                    if let Err(e) = result {
                        error!("Gossip engine error: {:?}", e);
                    }
                }
                _ = &mut sweep_handle => {}
                _ = &mut cleanup_handle => {}
                _ = shutdown_rx.changed() => {
                    info!("Shutdown signal received, stopping node...");
                }
            }
        }

        // Clean shutdown
        drop(engine);
        router_handle.abort();
        sweep_handle.abort();
        cleanup_handle.abort();
        self.abort_orp_announce_tasks().await;

        Ok(())
    }

    /// Spawn gossip background task
    fn _spawn_gossip_task(&self) -> tokio::task::JoinHandle<()> {
        let interval_secs = self.config.gossip_interval_secs;
        let _peers = Arc::clone(&self.peers);
        let _storage = Arc::clone(&self.storage);
        let _socket = Arc::clone(&self.socket);

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(interval_secs));

            loop {
                ticker.tick().await;

                // Build and send digests to peers
                trace!("Running gossip cycle");

                // In full implementation:
                // 1. Get current slot
                // 2. Build bloom filter digest of messages
                // 3. Send to random subset of peers
            }
        })
    }

    /// Spawn slot sweep background task
    fn spawn_sweep_task(&self) -> tokio::task::JoinHandle<()> {
        let interval_secs = self.config.sweep_interval_secs;
        let high_risk_routes = Arc::clone(&self.high_risk_routes);
        let pending_high_risk_accepts = Arc::clone(&self.pending_high_risk_accepts);
        let pending_high_risk_acks = Arc::clone(&self.pending_high_risk_acks);
        let high_risk_forward_seen = Arc::clone(&self.high_risk_forward_seen);

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(interval_secs));

            loop {
                ticker.tick().await;

                // Sweep lookback window
                let current_slot = EtherCoordinate::current_slot();
                let start_slot = current_slot.saturating_sub(LOOKBACK_SLOTS as u64);

                for slot in start_slot..=current_slot {
                    // Sweep slot - in full implementation would call self.sweep_slot
                    trace!("Sweeping slot {}", slot);
                }

                sweep_expired_high_risk_bindings(
                    &high_risk_routes,
                    &pending_high_risk_accepts,
                    &pending_high_risk_acks,
                    &high_risk_forward_seen,
                    current_slot,
                )
                .await;
            }
        })
    }

    /// Spawn receive task for incoming messages
    fn _spawn_receive_task(&self) -> tokio::task::JoinHandle<()> {
        let _socket = Arc::clone(&self.socket);
        let _storage = Arc::clone(&self.storage);
        let _peers = Arc::clone(&self.peers);
        let _seen = Arc::clone(&self.seen_messages);
        let _subscriptions = Arc::clone(&self.subscriptions);

        tokio::spawn(async move {
            loop {
                // In full implementation:
                // 1. Receive from socket
                // 2. Parse frame
                // 3. Handle based on type (digest/request/response)
                // 4. Store and forward if needed

                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
    }

    /// Spawn peer cleanup task
    fn spawn_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let peers = Arc::clone(&self.peers);

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(60));

            loop {
                ticker.tick().await;
                peers.cleanup().await;
                trace!("Cleaned up peers, {} remaining", peers.peer_count().await);
            }
        })
    }

    /// Get local socket address
    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr()
    }

    /// Get storage reference
    pub fn storage(&self) -> &Arc<Mutex<EtherStorage>> {
        &self.storage
    }

    /// Get socket reference
    pub fn socket(&self) -> &Arc<EtherUdpSocket> {
        &self.socket
    }

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        self.peers.peer_count().await
    }

    /// Add a peer to the peer manager
    pub async fn add_peer(&self, addr: SocketAddr) {
        self.peers.add_peer(addr).await;
    }

    /// Check if gossip engine is ready
    pub async fn is_gossip_ready(&self) -> bool {
        self.gossip_engine.read().await.is_some()
    }

    /// Wait for gossip engine to be ready
    pub async fn wait_for_gossip_ready(&self, timeout_secs: u64) -> Result<(), EtherSyncError> {
        for _ in 0..(timeout_secs * 10) {
            if self.is_gossip_ready().await {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(EtherSyncError::NetworkError(
            "Gossip engine not ready within timeout".to_string(),
        ))
    }

    /// Get subscription count
    pub async fn subscription_count(&self) -> usize {
        self.subscriptions.read().await.len()
    }

    /// Compute message hash for deduplication
    fn message_hash(message: &EtherMessage) -> [u8; 32] {
        blake3_hash(&message.encrypted_payload)
    }

    /// Cleanup seen message cache to prevent unbounded growth
    async fn cleanup_seen_cache(&self, seen: &mut HashSet<[u8; 32]>) {
        if seen.len() > self.max_seen_cache {
            // Simple strategy: clear half the cache
            // In production, use LRU or FIFO
            let to_remove: Vec<_> = seen.iter().take(seen.len() / 2).cloned().collect();
            for hash in to_remove {
                seen.remove(&hash);
            }
        }
    }

    async fn publish_orp_frame(
        &self,
        passphrase: &str,
        frame: OrpFrame,
        subspace: u64,
        slot: u64,
    ) -> Result<(), EtherSyncError> {
        let payload = encode_orp_frame(&frame)?;
        let msg = EtherMessage::new_control_message(passphrase, slot, &payload, subspace)?;

        let hash = Self::message_hash(&msg);
        {
            let mut storage = self.storage.lock().await;
            storage.store(slot, hash, msg.clone())?;
        }
        {
            let mut seen = self.seen_messages.write().await;
            seen.insert(hash);
            self.cleanup_seen_cache(&mut seen).await;
        }

        let gossip_engine = self.gossip_engine.clone();
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            for _ in 0..50 {
                {
                    let engine_guard = gossip_engine.read().await;
                    if let Some(ref engine) = *engine_guard {
                        if let Err(e) = engine.publish(msg_clone).await {
                            trace!("ORP control-frame gossip failed: {:?}", e);
                        }
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        Ok(())
    }

    // -----------------------------------------------------------------------
    // ORP — Ouroboros Routing Protocol
    // -----------------------------------------------------------------------

    /// Publish an ORP route announcement for the given passphrase space.
    ///
    /// The announcement is encrypted with the same passphrase on subspace 1
    /// and gossiped to all known peers, making this node discoverable by others
    /// in the same slot without relying on static bootstrap peers.
    pub async fn publish_route_announcement(&self, passphrase: &str) -> Result<(), EtherSyncError> {
        let slot = EtherCoordinate::current_slot();
        let local_addr = self.socket.local_addr();
        let (onion_pubkey, onion_salt) =
            derive_rotating_announcement_onion_key(&self.onion_secret_key, passphrase, slot)?;

        // Build assist_tag: first 8 bytes of blake3(node_id)
        let mut assist_tag = [0u8; 8];
        let tag_hash = blake3_hash(&self.node_id);
        assist_tag.copy_from_slice(&tag_hash[..8]);

        let announcement = RouteAnnouncement {
            version: 1,
            slot,
            node_id: self.node_id,
            onion_pubkey,
            onion_epoch_slot: slot,
            onion_salt,
            capabilities: RouteCapabilities {
                can_relay: self.config.orp_can_relay,
                direct_udp: !local_addr.ip().is_unspecified(),
                wan_assist: self.config.orp_wan_assist,
                tor_capable: self.config.orp_tor_capable,
                bridge_capable: self.config.orp_bridge_capable,
                keeper_capable: self.config.orp_keeper_capable,
            },
            reachable_udp: if local_addr.ip().is_unspecified() {
                vec![]
            } else {
                vec![local_addr]
            },
            assist_tag,
            route_class: Self::route_class_for_config(&self.config),
            operator_id_hint: self.config.orp_operator_id_hint.clone(),
            region_hint: self.config.orp_region_hint.clone(),
            measured_rtt_ms: None,
            expires_at_slot: slot + 4,
        };

        self.publish_orp_frame(
            passphrase,
            OrpFrame::Announce(announcement),
            SUBSPACE_ROUTE_ANNOUNCE,
            slot,
        )
        .await?;

        trace!("Published ORP route announcement for slot {}", slot);
        Ok(())
    }

    /// Broadcast a route lookup into the passphrase space and return the lookup id.
    ///
    /// Callers should wait briefly and then call `best_route` with the returned
    /// lookup id to retrieve the highest-scored offer received from peers.
    pub async fn lookup_route(
        &self,
        passphrase: &str,
        target_tag: [u8; 8],
    ) -> Result<[u8; 16], EtherSyncError> {
        let mut lookup_id = [0u8; 16];
        fill_random(&mut lookup_id).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate lookup id".to_string())
        })?;

        let lookup = RouteLookup {
            version: 1,
            lookup_id,
            target_tag,
            max_hops: 2,
            ttl: 3,
        };

        let slot = EtherCoordinate::current_slot();
        self.publish_orp_frame(
            passphrase,
            OrpFrame::Lookup(lookup),
            SUBSPACE_ROUTE_LOOKUP,
            slot,
        )
        .await?;

        trace!(
            "Published ORP route lookup {:?} for tag {:?}",
            lookup_id,
            target_tag
        );
        Ok(lookup_id)
    }

    pub async fn high_risk_gate_snapshot(
        &self,
        passphrase: &str,
    ) -> Result<HighRiskGateSnapshot, EtherSyncError> {
        let passphrase_bytes = canonicalize_passphrase(passphrase);
        let space_hash = blake3_hash(&passphrase_bytes);
        let mut space_prefix = [0u8; 8];
        space_prefix.copy_from_slice(&space_hash[..8]);
        let cache = self.route_cache.lock().await;
        Ok(cache.high_risk_gate_snapshot(&space_prefix, EtherCoordinate::current_slot()))
    }

    pub async fn plan_high_risk_circuit(
        &self,
        passphrase: &str,
        target_tag: [u8; 8],
    ) -> Result<HighRiskCircuitPlan, EtherSyncError> {
        let passphrase_bytes = canonicalize_passphrase(passphrase);
        let space_hash = blake3_hash(&passphrase_bytes);
        let mut space_prefix = [0u8; 8];
        space_prefix.copy_from_slice(&space_hash[..8]);
        let cache = self.route_cache.lock().await;
        cache
            .plan_high_risk_circuit(&space_prefix, &target_tag, EtherCoordinate::current_slot())
            .map_err(|err| EtherSyncError::NetworkError(err.reason))
    }

    pub async fn publish_high_risk_circuit_plan(
        &self,
        passphrase: &str,
        plan: &HighRiskCircuitPlan,
    ) -> Result<[u8; 16], EtherSyncError> {
        let slot = EtherCoordinate::current_slot();
        let mut circuit_id = [0u8; 16];
        fill_random(&mut circuit_id).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate high-risk circuit id".to_string())
        })?;
        let descriptor = self.build_high_risk_route_descriptor(plan, circuit_id, slot + 4);
        let _ = self
            .publish_high_risk_route_descriptor(passphrase, &descriptor, slot)
            .await?;
        Ok(circuit_id)
    }

    pub async fn open_high_risk_transport(
        &self,
        passphrase: &str,
        target_tag: [u8; 8],
    ) -> Result<
        (
            HighRiskGateSnapshot,
            HighRiskCircuitPlan,
            HighRiskTransportSession,
        ),
        EtherSyncError,
    > {
        let gate = self.high_risk_gate_snapshot(passphrase).await?;
        let plan = self.plan_high_risk_circuit(passphrase, target_tag).await?;
        let slot = EtherCoordinate::current_slot();
        let mut circuit_id = [0u8; 16];
        fill_random(&mut circuit_id).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate high-risk circuit id".to_string())
        })?;
        let descriptor = self.build_high_risk_route_descriptor(&plan, circuit_id, slot + 4);
        let (deliver_tx, receiver) = mpsc::channel(256);
        let ready_state = Arc::new(AtomicBool::new(false));
        let ready_notify = Arc::new(Notify::new());
        {
            let mut routes = self.high_risk_routes.lock().await;
            routes.insert(
                circuit_id,
                HighRiskRouteBinding {
                    descriptor: descriptor.clone(),
                    local_role: HighRiskLocalRole::Origin,
                    deliver_tx: Some(deliver_tx),
                    hop_session_key: None,
                    reply_session_key: None,
                    onion_codec: None,
                    ready_state: Some(Arc::clone(&ready_state)),
                    ready_notify: Some(Arc::clone(&ready_notify)),
                    last_updated_ms: now_ms(),
                },
            );
        }
        let (onion_codec, reply_session_key) = match self
            .publish_high_risk_route_descriptor(passphrase, &descriptor, slot)
            .await
        {
            Ok(material) => material,
            Err(err) => {
                remove_high_risk_route_binding(
                    &self.high_risk_routes,
                    &self.pending_high_risk_accepts,
                    &self.pending_high_risk_acks,
                    circuit_id,
                )
                .await;
                return Err(err);
            }
        };
        {
            let mut routes = self.high_risk_routes.lock().await;
            if let Some(binding) = routes.get_mut(&circuit_id) {
                binding.onion_codec = Some(onion_codec);
                binding.reply_session_key = Some(reply_session_key);
            }
        }
        Ok((
            gate,
            plan,
            HighRiskTransportSession {
                circuit_id,
                descriptor,
                local_role: HighRiskLocalRole::Origin,
                receiver,
                ready_state,
                ready_notify,
            },
        ))
    }

    pub async fn accept_high_risk_transport(
        &self,
        passphrase: &str,
        timeout: Duration,
    ) -> Result<HighRiskTransportSession, EtherSyncError> {
        let space_prefix = space_prefix_for_passphrase(passphrase);
        let started = tokio::time::Instant::now();
        loop {
            let notified = self.high_risk_accept_notify.notified();
            if let Some(session) = {
                let mut pending = self.pending_high_risk_accepts.lock().await;
                pending
                    .get_mut(&space_prefix)
                    .and_then(|queue| queue.pop_front())
                    .map(|session| HighRiskTransportSession {
                        circuit_id: session.circuit_id,
                        descriptor: session.descriptor,
                        local_role: session.local_role,
                        receiver: session.receiver,
                        ready_state: session.ready_state,
                        ready_notify: session.ready_notify,
                    })
            } {
                return Ok(session);
            }

            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Err(EtherSyncError::NetworkError(
                    "timed out waiting for an inbound high-risk circuit".to_string(),
                ));
            }
            let remaining = timeout.saturating_sub(elapsed);
            if tokio::time::timeout(remaining, notified).await.is_err() {
                return Err(EtherSyncError::NetworkError(
                    "timed out waiting for an inbound high-risk circuit".to_string(),
                ));
            }
        }
    }

    pub async fn send_high_risk_payload(
        &self,
        passphrase: &str,
        circuit_id: [u8; 16],
        direction: RouteDirection,
        payload: Vec<u8>,
    ) -> Result<(), EtherSyncError> {
        let mut packet_id = [0u8; 16];
        fill_random(&mut packet_id).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate high-risk packet id".to_string())
        })?;
        self.publish_high_risk_payload_frame(
            passphrase,
            circuit_id,
            packet_id,
            direction,
            HighRiskPayloadFrame::Application(payload),
        )
        .await
    }

    pub async fn send_high_risk_payload_reliable(
        &self,
        passphrase: &str,
        circuit_id: [u8; 16],
        direction: RouteDirection,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> Result<DeliveryOutcome, EtherSyncError> {
        let mut packet_id = [0u8; 16];
        fill_random(&mut packet_id).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate high-risk packet id".to_string())
        })?;
        let (tx, rx) = oneshot::channel();
        let ack_key = HighRiskAckKey {
            circuit_id,
            packet_id,
            direction,
        };
        self.pending_high_risk_acks.lock().await.insert(ack_key, tx);

        if let Err(err) = self
            .publish_high_risk_payload_frame(
                passphrase,
                circuit_id,
                packet_id,
                direction,
                HighRiskPayloadFrame::Application(payload),
            )
            .await
        {
            self.pending_high_risk_acks.lock().await.remove(&ack_key);
            return Err(err);
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(())) => Ok(DeliveryOutcome::Confirmed),
            _ => {
                self.pending_high_risk_acks.lock().await.remove(&ack_key);
                Ok(DeliveryOutcome::Unconfirmed)
            }
        }
    }

    async fn publish_high_risk_payload_frame(
        &self,
        passphrase: &str,
        circuit_id: [u8; 16],
        packet_id: [u8; 16],
        direction: RouteDirection,
        frame: HighRiskPayloadFrame,
    ) -> Result<(), EtherSyncError> {
        let payload_bytes = serialize_high_risk_payload_frame(&frame)?;
        let (payload, hop_index, remaining_hops) = {
            let routes = self.high_risk_routes.lock().await;
            let Some(binding) = routes.get(&circuit_id) else {
                return Err(EtherSyncError::NetworkError(
                    "high-risk circuit binding not found for outbound payload".to_string(),
                ));
            };
            let payload =
                encode_outbound_high_risk_payload(binding, direction, &packet_id, &payload_bytes)?;
            let (hop_index, remaining_hops) =
                outbound_high_risk_route_state(binding.local_role, direction)?;
            (payload, hop_index, remaining_hops)
        };

        let forward = RouteForward {
            version: 1,
            circuit_id,
            packet_id,
            direction,
            hop_index,
            remaining_hops,
            payload,
        };
        self.publish_orp_frame(
            passphrase,
            OrpFrame::Forward(forward),
            SUBSPACE_ROUTE_FORWARD,
            EtherCoordinate::current_slot(),
        )
        .await
    }

    pub async fn publish_high_risk_delivery_notice(
        &self,
        passphrase: &str,
        circuit_id: [u8; 16],
        packet_id: [u8; 16],
        direction: RouteDirection,
        delivered_hop: u8,
    ) -> Result<(), EtherSyncError> {
        let notice = ForwardDeliveryNotice {
            version: 1,
            packet_id,
            circuit_id,
            direction,
            delivered_hop,
        };
        self.publish_orp_frame(
            passphrase,
            OrpFrame::DeliveryNotice(notice),
            SUBSPACE_DELIVERY_NOTICE,
            EtherCoordinate::current_slot(),
        )
        .await
    }

    fn build_high_risk_route_descriptor(
        &self,
        plan: &HighRiskCircuitPlan,
        circuit_id: [u8; 16],
        expires_at_slot: u64,
    ) -> HighRiskRouteDescriptor {
        HighRiskRouteDescriptor {
            version: 1,
            circuit_id,
            origin_id: self.node_id,
            space_prefix: plan.space_prefix,
            target_tag: plan.target_tag,
            entry: plan.entry.clone(),
            middle: plan.middle.clone(),
            exit: plan.exit.clone(),
            expires_at_slot,
        }
    }

    async fn publish_high_risk_route_descriptor(
        &self,
        passphrase: &str,
        descriptor: &HighRiskRouteDescriptor,
        slot: u64,
    ) -> Result<(OnionCodec, [u8; 32]), EtherSyncError> {
        let mut entry_secret = Zeroizing::new([0u8; 32]);
        fill_random(&mut *entry_secret).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate entry onion secret".to_string())
        })?;
        let mut middle_secret = Zeroizing::new([0u8; 32]);
        fill_random(&mut *middle_secret).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate middle onion secret".to_string())
        })?;
        let mut exit_secret = Zeroizing::new([0u8; 32]);
        fill_random(&mut *exit_secret).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate exit onion secret".to_string())
        })?;
        let mut reply_entry_secret = Zeroizing::new([0u8; 32]);
        fill_random(&mut *reply_entry_secret).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate reply entry onion secret".to_string())
        })?;
        let mut reply_middle_secret = Zeroizing::new([0u8; 32]);
        fill_random(&mut *reply_middle_secret).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate reply middle onion secret".to_string())
        })?;
        let mut reply_exit_secret = Zeroizing::new([0u8; 32]);
        fill_random(&mut *reply_exit_secret).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate reply exit onion secret".to_string())
        })?;

        let entry_session_key = Zeroizing::new(
            derive_onion_session_key(
                &*entry_secret,
                &descriptor.entry.onion_pubkey,
                &descriptor.circuit_id,
            )
            .map_err(map_onion_error)?,
        );
        let middle_session_key = Zeroizing::new(
            derive_onion_session_key(
                &*middle_secret,
                &descriptor.middle.onion_pubkey,
                &descriptor.circuit_id,
            )
            .map_err(map_onion_error)?,
        );
        let exit_session_key = Zeroizing::new(
            derive_onion_session_key(
                &*exit_secret,
                &descriptor.exit.onion_pubkey,
                &descriptor.circuit_id,
            )
            .map_err(map_onion_error)?,
        );
        let reply_entry_session_key = Zeroizing::new(
            derive_onion_session_key(
                &*reply_entry_secret,
                &descriptor.entry.onion_pubkey,
                &descriptor.circuit_id,
            )
            .map_err(map_onion_error)?,
        );
        let reply_middle_session_key = Zeroizing::new(
            derive_onion_session_key(
                &*reply_middle_secret,
                &descriptor.middle.onion_pubkey,
                &descriptor.circuit_id,
            )
            .map_err(map_onion_error)?,
        );
        let reply_exit_session_key = Zeroizing::new(
            derive_onion_session_key(
                &*reply_exit_secret,
                &descriptor.exit.onion_pubkey,
                &descriptor.circuit_id,
            )
            .map_err(map_onion_error)?,
        );

        let entry_payload = serialize_hop_handshake(HopHandshake {
            origin_ephemeral_pubkey: derive_onion_public_key(&*entry_secret),
            onion_epoch_slot: descriptor.entry.onion_epoch_slot,
            onion_salt: descriptor.entry.onion_salt,
            sealed_capsule: seal_hop_capsule(
                &*entry_session_key,
                &descriptor.circuit_id,
                &HighRiskHopCapsule {
                    descriptor: build_minimal_high_risk_descriptor(
                        descriptor,
                        HighRiskLocalRole::Entry,
                    ),
                    local_role_code: high_risk_local_role_code(HighRiskLocalRole::Entry),
                    reply_origin_ephemeral_pubkey: derive_onion_public_key(&*reply_entry_secret),
                },
            )
            .map_err(map_onion_error)?,
            reply_layers_ciphertext: Vec::new(),
        })?;
        let middle_payload = serialize_hop_handshake(HopHandshake {
            origin_ephemeral_pubkey: derive_onion_public_key(&*middle_secret),
            onion_epoch_slot: descriptor.middle.onion_epoch_slot,
            onion_salt: descriptor.middle.onion_salt,
            sealed_capsule: seal_hop_capsule(
                &*middle_session_key,
                &descriptor.circuit_id,
                &HighRiskHopCapsule {
                    descriptor: build_minimal_high_risk_descriptor(
                        descriptor,
                        HighRiskLocalRole::Middle,
                    ),
                    local_role_code: high_risk_local_role_code(HighRiskLocalRole::Middle),
                    reply_origin_ephemeral_pubkey: derive_onion_public_key(&*reply_middle_secret),
                },
            )
            .map_err(map_onion_error)?,
            reply_layers_ciphertext: Vec::new(),
        })?;
        let mut reply_layers = [
            OnionLayer {
                session_key: *reply_middle_session_key,
                hop_index: 1,
            },
            OnionLayer {
                session_key: *reply_entry_session_key,
                hop_index: 0,
            },
            OnionLayer {
                session_key: *reply_exit_session_key,
                hop_index: 2,
            },
        ];
        let exit_payload = serialize_hop_handshake(HopHandshake {
            origin_ephemeral_pubkey: derive_onion_public_key(&*exit_secret),
            onion_epoch_slot: descriptor.exit.onion_epoch_slot,
            onion_salt: descriptor.exit.onion_salt,
            sealed_capsule: seal_hop_capsule(
                &*exit_session_key,
                &descriptor.circuit_id,
                &HighRiskHopCapsule {
                    descriptor: build_minimal_high_risk_descriptor(
                        descriptor,
                        HighRiskLocalRole::Exit,
                    ),
                    local_role_code: high_risk_local_role_code(HighRiskLocalRole::Exit),
                    reply_origin_ephemeral_pubkey: derive_onion_public_key(&*reply_exit_secret),
                },
            )
            .map_err(map_onion_error)?,
            reply_layers_ciphertext: encrypt_reply_layers(
                &*reply_exit_session_key,
                &descriptor.circuit_id,
                &reply_layers,
            )
            .map_err(map_onion_error)?,
        })?;
        for layer in &mut reply_layers {
            layer.session_key.zeroize();
        }

        let onion_codec = OnionCodec {
            layers: vec![
                OnionLayer {
                    session_key: *entry_session_key,
                    hop_index: 0,
                },
                OnionLayer {
                    session_key: *middle_session_key,
                    hop_index: 1,
                },
                OnionLayer {
                    session_key: *exit_session_key,
                    hop_index: 2,
                },
            ],
        };

        let open = CircuitOpen {
            version: 1,
            circuit_id: descriptor.circuit_id,
            hop_payload: entry_payload,
            expires_at_slot: descriptor.expires_at_slot,
        };
        self.publish_orp_frame(
            passphrase,
            OrpFrame::CircuitOpen(open.clone()),
            SUBSPACE_CIRCUIT_OPEN,
            slot,
        )
        .await?;
        record_high_risk_open_for_passphrase(&self.high_risk_circuits, passphrase, slot, &open)
            .await;

        let middle = CircuitExtend {
            version: 1,
            circuit_id: descriptor.circuit_id,
            current_hop: 1,
            hop_payload: middle_payload,
            expires_at_slot: descriptor.expires_at_slot,
        };
        self.publish_orp_frame(
            passphrase,
            OrpFrame::CircuitExtend(middle.clone()),
            SUBSPACE_CIRCUIT_EXTEND,
            slot,
        )
        .await?;
        record_high_risk_extend_for_passphrase(&self.high_risk_circuits, passphrase, slot, &middle)
            .await;

        let exit = CircuitExtend {
            version: 1,
            circuit_id: descriptor.circuit_id,
            current_hop: 2,
            hop_payload: exit_payload,
            expires_at_slot: descriptor.expires_at_slot,
        };
        self.publish_orp_frame(
            passphrase,
            OrpFrame::CircuitExtend(exit.clone()),
            SUBSPACE_CIRCUIT_EXTEND,
            slot,
        )
        .await?;
        record_high_risk_extend_for_passphrase(&self.high_risk_circuits, passphrase, slot, &exit)
            .await;

        let cover = CoverPacket {
            version: 1,
            stream_id: descriptor.circuit_id,
            cover_class: 1,
            payload: vec![0u8; 256],
        };
        self.publish_orp_frame(
            passphrase,
            OrpFrame::Cover(cover.clone()),
            SUBSPACE_COVER_TRAFFIC,
            slot,
        )
        .await?;
        record_high_risk_cover_for_passphrase(&self.high_risk_circuits, passphrase, slot, &cover)
            .await;
        Ok((onion_codec, *reply_exit_session_key))
    }

    pub async fn close_high_risk_circuit(
        &self,
        passphrase: &str,
        circuit_id: [u8; 16],
        reason_code: u16,
    ) -> Result<(), EtherSyncError> {
        let slot = EtherCoordinate::current_slot();
        let close_frames = {
            let routes = self.high_risk_routes.lock().await;
            routes
                .get(&circuit_id)
                .map(|binding| build_high_risk_close_frames(binding, circuit_id, reason_code))
                .unwrap_or_default()
        };
        for close in &close_frames {
            self.publish_orp_frame(
                passphrase,
                OrpFrame::CircuitClose(close.clone()),
                SUBSPACE_CIRCUIT_CLOSE,
                slot,
            )
            .await?;
            record_high_risk_close_for_passphrase(
                &self.high_risk_circuits,
                passphrase,
                slot,
                close,
            )
            .await;
        }
        remove_high_risk_route_binding(
            &self.high_risk_routes,
            &self.pending_high_risk_accepts,
            &self.pending_high_risk_acks,
            circuit_id,
        )
        .await;
        Ok(())
    }

    /// Return the best cached route offer for the given lookup id, if any.
    pub async fn best_route(
        &self,
        _passphrase: &str,
        lookup_id: [u8; 16],
    ) -> Result<Option<RouteOffer>, EtherSyncError> {
        let cache = self.route_cache.lock().await;
        Ok(cache
            .best_offer(&lookup_id, EtherCoordinate::current_slot())
            .map(|co| co.frame.clone()))
    }

    /// Return active ORP spaces with their passphrases.
    pub async fn active_orp_spaces(&self) -> Vec<([u8; 8], String)> {
        self.orp_spaces
            .read()
            .await
            .iter()
            .map(|(prefix, passphrase)| (*prefix, passphrase.clone()))
            .collect()
    }

    /// Activate ORP for a passphrase space.
    ///
    /// Registers the space prefix, starts periodic route announcements,
    /// and publishes an immediate first announcement.  Returns the space
    /// prefix so callers can track it.
    pub async fn start_orp_for_space(&self, passphrase: &str) -> [u8; 8] {
        let passphrase_bytes = canonicalize_passphrase(passphrase);
        let space_hash = blake3_hash(&passphrase_bytes);
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&space_hash[..8]);

        // Register the space once; repeated joins should not duplicate announcers.
        let already_active = {
            use std::collections::hash_map::Entry;

            let mut spaces = self.orp_spaces.write().await;
            match spaces.entry(prefix) {
                Entry::Occupied(_) => true,
                Entry::Vacant(entry) => {
                    entry.insert(passphrase.to_string());
                    false
                }
            }
        };

        if already_active {
            trace!("ORP: space {} already active", hex::encode(prefix));
            return prefix;
        }

        // Immediate first announcement
        {
            if let Err(e) = self.publish_route_announcement(passphrase).await {
                warn!("ORP: initial announcement failed: {:?}", e);
            }
        }

        // Start periodic announce task
        let handle = self.spawn_orp_announce_task(
            passphrase.to_string(),
            self.config.orp_announce_interval_secs,
        );
        let mut tasks = self.orp_announce_tasks.lock().await;
        tasks.insert(prefix, handle);

        info!(
            "ORP: activated for space {} (announce interval {}s)",
            hex::encode(prefix),
            self.config.orp_announce_interval_secs
        );
        prefix
    }

    /// Return all space prefixes that have ORP active.
    pub async fn orp_space_prefixes(&self) -> Vec<[u8; 8]> {
        self.orp_spaces.read().await.keys().cloned().collect()
    }

    pub async fn high_risk_circuit_stats(&self) -> HighRiskCircuitStats {
        let current_slot = EtherCoordinate::current_slot();
        let mut circuits = self.high_risk_circuits.lock().await;
        prune_high_risk_circuits(&mut circuits, current_slot);

        let circuits_observed = circuits.len();
        let active_circuits = circuits.values().filter(|record| record.active).count();
        let closed_circuits = circuits_observed.saturating_sub(active_circuits);
        let control_frames_observed = circuits
            .values()
            .map(|record| record.control_frames_seen)
            .sum();
        let cover_packets_observed = circuits.values().map(|record| record.cover_packets).sum();
        let last_activity_ms = circuits.values().map(|record| record.last_updated_ms).max();

        let mut recent_circuits = circuits
            .values()
            .cloned()
            .map(snapshot_high_risk_circuit)
            .collect::<Vec<_>>();
        recent_circuits.sort_by(|a, b| b.last_updated_ms.cmp(&a.last_updated_ms));
        recent_circuits.truncate(8);

        HighRiskCircuitStats {
            circuits_observed,
            active_circuits,
            closed_circuits,
            control_frames_observed,
            cover_packets_observed,
            last_activity_ms,
            recent_circuits,
        }
    }

    async fn abort_orp_announce_tasks(&self) {
        let handles = {
            let mut tasks = self.orp_announce_tasks.lock().await;
            tasks.drain().map(|(_, handle)| handle).collect::<Vec<_>>()
        };

        for handle in handles {
            handle.abort();
        }

        self.orp_spaces.write().await.clear();
        self.high_risk_circuits.lock().await.clear();
        self.high_risk_routes.lock().await.clear();
        self.pending_high_risk_accepts.lock().await.clear();
        self.pending_high_risk_acks.lock().await.clear();
        self.high_risk_forward_seen.lock().await.clear();
    }

    /// Spawn the ORP periodic announcement task.
    fn spawn_orp_announce_task(
        &self,
        passphrase: String,
        interval_secs: u64,
    ) -> tokio::task::JoinHandle<()> {
        let gossip_engine = Arc::clone(&self.gossip_engine);
        let storage = Arc::clone(&self.storage);
        let seen_messages = Arc::clone(&self.seen_messages);
        let route_cache = Arc::clone(&self.route_cache);
        let socket = Arc::clone(&self.socket);
        let node_id = self.node_id;
        let onion_secret_key = Zeroizing::new(self.onion_secret_key);
        let max_seen_cache = self.max_seen_cache;
        let orp_can_relay = self.config.orp_can_relay;
        let orp_wan_assist = self.config.orp_wan_assist;
        let orp_tor_capable = self.config.orp_tor_capable;
        let orp_bridge_capable = self.config.orp_bridge_capable;
        let orp_keeper_capable = self.config.orp_keeper_capable;
        let orp_operator_id_hint = self.config.orp_operator_id_hint.clone();
        let orp_region_hint = self.config.orp_region_hint.clone();
        let route_class = Self::route_class_for_config(&self.config);

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;

                let slot = EtherCoordinate::current_slot();
                let local_addr = socket.local_addr();
                let (onion_pubkey, onion_salt) = match derive_rotating_announcement_onion_key(
                    &onion_secret_key,
                    &passphrase,
                    slot,
                ) {
                    Ok(material) => material,
                    Err(err) => {
                        warn!(
                            "ORP onion announcement derive error in announce task: {:?}",
                            err
                        );
                        continue;
                    }
                };

                let mut assist_tag = [0u8; 8];
                let tag_hash = blake3_hash(&node_id);
                assist_tag.copy_from_slice(&tag_hash[..8]);

                let announcement = RouteAnnouncement {
                    version: 1,
                    slot,
                    node_id,
                    onion_pubkey,
                    onion_epoch_slot: slot,
                    onion_salt,
                    capabilities: RouteCapabilities {
                        can_relay: orp_can_relay,
                        direct_udp: !local_addr.ip().is_unspecified(),
                        wan_assist: orp_wan_assist,
                        tor_capable: orp_tor_capable,
                        bridge_capable: orp_bridge_capable,
                        keeper_capable: orp_keeper_capable,
                    },
                    reachable_udp: if local_addr.ip().is_unspecified() {
                        vec![]
                    } else {
                        vec![local_addr]
                    },
                    assist_tag,
                    route_class,
                    operator_id_hint: orp_operator_id_hint.clone(),
                    region_hint: orp_region_hint.clone(),
                    measured_rtt_ms: None,
                    expires_at_slot: slot + 4,
                };

                let frame = OrpFrame::Announce(announcement);
                let payload = match encode_orp_frame(&frame) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("ORP encode error in announce task: {:?}", e);
                        continue;
                    }
                };

                let msg = match EtherMessage::new_control_message(
                    &passphrase,
                    slot,
                    &payload,
                    SUBSPACE_ROUTE_ANNOUNCE,
                ) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("ORP message creation error: {:?}", e);
                        continue;
                    }
                };

                let hash = blake3_hash(&msg.encrypted_payload);
                {
                    let mut st = storage.lock().await;
                    let _ = st.store(slot, hash, msg.clone());
                }
                {
                    let mut seen = seen_messages.write().await;
                    seen.insert(hash);
                    if seen.len() > max_seen_cache {
                        let to_remove: Vec<_> = seen.iter().take(seen.len() / 2).cloned().collect();
                        for h in to_remove {
                            seen.remove(&h);
                        }
                    }
                }

                // Evict stale cache entries on each announce cycle
                {
                    let mut cache = route_cache.lock().await;
                    cache.evict_stale(slot, 600); // 10 minutes
                }

                let ge = gossip_engine.clone();
                let m = msg.clone();
                tokio::spawn(async move {
                    for _ in 0..50 {
                        {
                            let g = ge.read().await;
                            if let Some(ref engine) = *g {
                                let _ = engine.publish(m).await;
                                return;
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                });

                trace!("ORP periodic announcement published for slot {}", slot);
            }
        })
    }

    /// Get a reference to the ORP route cache.
    pub fn route_cache(&self) -> &Arc<Mutex<RouteCache>> {
        &self.route_cache
    }

    /// Return this node's ephemeral session id.
    pub fn node_id(&self) -> [u8; 16] {
        self.node_id
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn space_prefix_for_passphrase(passphrase: &str) -> [u8; 8] {
    let passphrase_bytes = canonicalize_passphrase(passphrase);
    let space_hash = blake3_hash(&passphrase_bytes);
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&space_hash[..8]);
    prefix
}

fn derive_rotating_announcement_onion_key(
    onion_root_secret_key: &[u8; 32],
    passphrase: &str,
    slot: u64,
) -> Result<([u8; 32], [u8; 16]), EtherSyncError> {
    let space_prefix = space_prefix_for_passphrase(passphrase);
    let mut onion_salt = [0u8; 16];
    fill_random(&mut onion_salt).map_err(|_| {
        EtherSyncError::NetworkError("failed to generate announcement onion salt".to_string())
    })?;
    let onion_secret_key =
        derive_rotating_onion_secret_key(onion_root_secret_key, &space_prefix, slot, &onion_salt)
            .map_err(map_onion_error)?;
    let onion_secret_key = Zeroizing::new(onion_secret_key);
    Ok((derive_onion_public_key(&onion_secret_key), onion_salt))
}

fn masked_high_risk_hop() -> HighRiskCircuitHop {
    HighRiskCircuitHop {
        node_id: [0u8; 16],
        onion_pubkey: [0u8; 32],
        onion_epoch_slot: 0,
        onion_salt: [0u8; 16],
        assist_tag: [0u8; 8],
        addr: SocketAddr::from(([0, 0, 0, 0], 0)),
        route_class: RouteClass::Direct,
        operator_id_hint: String::new(),
        region_hint: String::new(),
        can_relay: false,
        bridge_capable: false,
    }
}

fn build_minimal_high_risk_descriptor(
    descriptor: &HighRiskRouteDescriptor,
    local_role: HighRiskLocalRole,
) -> HighRiskRouteDescriptor {
    let mut minimal = HighRiskRouteDescriptor {
        version: descriptor.version,
        circuit_id: descriptor.circuit_id,
        origin_id: [0u8; 16],
        space_prefix: descriptor.space_prefix,
        target_tag: [0u8; 8],
        entry: masked_high_risk_hop(),
        middle: masked_high_risk_hop(),
        exit: masked_high_risk_hop(),
        expires_at_slot: descriptor.expires_at_slot,
    };

    match local_role {
        HighRiskLocalRole::Origin => {
            minimal.origin_id = descriptor.origin_id;
            minimal.target_tag = descriptor.target_tag;
            minimal.entry = descriptor.entry.clone();
            minimal.middle = descriptor.middle.clone();
            minimal.exit = descriptor.exit.clone();
        }
        HighRiskLocalRole::Entry => {
            minimal.entry = descriptor.entry.clone();
        }
        HighRiskLocalRole::Middle => {
            minimal.middle = descriptor.middle.clone();
        }
        HighRiskLocalRole::Exit => {
            minimal.target_tag = descriptor.target_tag;
            minimal.exit = descriptor.exit.clone();
        }
    }

    minimal
}

fn high_risk_local_role_code(local_role: HighRiskLocalRole) -> u8 {
    match local_role {
        HighRiskLocalRole::Origin => 0,
        HighRiskLocalRole::Entry => 1,
        HighRiskLocalRole::Middle => 2,
        HighRiskLocalRole::Exit => 3,
    }
}

fn high_risk_local_role_from_code(code: u8) -> Option<HighRiskLocalRole> {
    match code {
        1 => Some(HighRiskLocalRole::Entry),
        2 => Some(HighRiskLocalRole::Middle),
        3 => Some(HighRiskLocalRole::Exit),
        _ => None,
    }
}

fn high_risk_role_matches_descriptor(
    local_role: HighRiskLocalRole,
    node_id: [u8; 16],
    descriptor: &HighRiskRouteDescriptor,
) -> bool {
    match local_role {
        HighRiskLocalRole::Origin => descriptor.origin_id == node_id,
        HighRiskLocalRole::Entry => descriptor.entry.node_id == node_id,
        HighRiskLocalRole::Middle => descriptor.middle.node_id == node_id,
        HighRiskLocalRole::Exit => descriptor.exit.node_id == node_id,
    }
}

fn push_control_frame_label(record: &mut ObservedHighRiskCircuit, _label: &str) {
    record.control_frames_seen = record.control_frames_seen.saturating_add(1);
}

fn prune_high_risk_circuits(
    circuits: &mut StdHashMap<[u8; 16], ObservedHighRiskCircuit>,
    current_slot: u64,
) {
    let stale_before_ms = now_ms().saturating_sub(15 * 60 * 1000);
    circuits.retain(|_, record| {
        let slot_live = record
            .expires_at_slot
            .map(|expires_at_slot| expires_at_slot.saturating_add(2) >= current_slot)
            .unwrap_or(true);
        record.active || slot_live || record.last_updated_ms >= stale_before_ms
    });
}

fn snapshot_high_risk_circuit(record: ObservedHighRiskCircuit) -> HighRiskCircuitSnapshot {
    HighRiskCircuitSnapshot {
        circuit_id: hex::encode(record.circuit_id),
        space_prefix: hex::encode(record.space_prefix),
        origin_id: record.origin_id.map(hex::encode),
        active: record.active,
        opened_at_slot: record.opened_at_slot,
        expires_at_slot: record.expires_at_slot,
        first_hop: record.first_hop,
        last_hop: record.last_hop,
        extend_count: record.extend_count,
        highest_hop_index: record.highest_hop_index,
        cover_packets: record.cover_packets,
        control_frames_seen: record.control_frames_seen,
        close_reason: record.close_reason,
        last_updated_ms: record.last_updated_ms,
    }
}

async fn record_high_risk_open_for_passphrase(
    circuits: &Arc<Mutex<StdHashMap<[u8; 16], ObservedHighRiskCircuit>>>,
    passphrase: &str,
    slot: u64,
    frame: &CircuitOpen,
) {
    record_high_risk_open(
        circuits,
        space_prefix_for_passphrase(passphrase),
        slot,
        frame,
    )
    .await;
}

async fn record_high_risk_extend_for_passphrase(
    circuits: &Arc<Mutex<StdHashMap<[u8; 16], ObservedHighRiskCircuit>>>,
    passphrase: &str,
    slot: u64,
    frame: &CircuitExtend,
) {
    record_high_risk_extend(
        circuits,
        space_prefix_for_passphrase(passphrase),
        slot,
        frame,
    )
    .await;
}

async fn record_high_risk_close_for_passphrase(
    circuits: &Arc<Mutex<StdHashMap<[u8; 16], ObservedHighRiskCircuit>>>,
    passphrase: &str,
    slot: u64,
    frame: &CircuitClose,
) {
    record_high_risk_close(
        circuits,
        space_prefix_for_passphrase(passphrase),
        slot,
        frame,
    )
    .await;
}

async fn record_high_risk_cover_for_passphrase(
    circuits: &Arc<Mutex<StdHashMap<[u8; 16], ObservedHighRiskCircuit>>>,
    passphrase: &str,
    slot: u64,
    frame: &CoverPacket,
) {
    record_high_risk_cover(
        circuits,
        space_prefix_for_passphrase(passphrase),
        slot,
        frame,
    )
    .await;
}

async fn record_high_risk_open(
    circuits: &Arc<Mutex<StdHashMap<[u8; 16], ObservedHighRiskCircuit>>>,
    space_prefix: [u8; 8],
    slot: u64,
    frame: &CircuitOpen,
) {
    let mut circuits = circuits.lock().await;
    prune_high_risk_circuits(&mut circuits, slot);
    let record = circuits
        .entry(frame.circuit_id)
        .or_insert_with(|| ObservedHighRiskCircuit {
            circuit_id: frame.circuit_id,
            space_prefix,
            origin_id: None,
            active: true,
            opened_at_slot: Some(slot),
            expires_at_slot: Some(frame.expires_at_slot),
            first_hop: Some("sealed-capsule".to_string()),
            last_hop: Some("sealed-capsule".to_string()),
            extend_count: 0,
            highest_hop_index: 0,
            cover_packets: 0,
            control_frames_seen: 0,
            close_reason: None,
            last_updated_ms: now_ms(),
        });
    record.space_prefix = space_prefix;
    record.active = true;
    record.opened_at_slot.get_or_insert(slot);
    record.expires_at_slot = Some(
        record
            .expires_at_slot
            .unwrap_or(frame.expires_at_slot)
            .max(frame.expires_at_slot),
    );
    record.first_hop = Some("sealed-capsule".to_string());
    record
        .last_hop
        .get_or_insert_with(|| "sealed-capsule".to_string());
    record.close_reason = None;
    record.last_updated_ms = now_ms();
    push_control_frame_label(record, "CircuitOpen");
}

async fn record_high_risk_extend(
    circuits: &Arc<Mutex<StdHashMap<[u8; 16], ObservedHighRiskCircuit>>>,
    space_prefix: [u8; 8],
    slot: u64,
    frame: &CircuitExtend,
) {
    let mut circuits = circuits.lock().await;
    prune_high_risk_circuits(&mut circuits, slot);
    let record = circuits
        .entry(frame.circuit_id)
        .or_insert_with(|| ObservedHighRiskCircuit {
            circuit_id: frame.circuit_id,
            space_prefix,
            origin_id: None,
            active: true,
            opened_at_slot: Some(slot),
            expires_at_slot: Some(frame.expires_at_slot),
            first_hop: None,
            last_hop: Some("CircuitExtend".to_string()),
            extend_count: 0,
            highest_hop_index: frame.current_hop.saturating_add(1),
            cover_packets: 0,
            control_frames_seen: 0,
            close_reason: None,
            last_updated_ms: now_ms(),
        });
    record.space_prefix = space_prefix;
    record.active = true;
    record.opened_at_slot.get_or_insert(slot);
    record.expires_at_slot = Some(
        record
            .expires_at_slot
            .unwrap_or(frame.expires_at_slot)
            .max(frame.expires_at_slot),
    );
    record.extend_count = record.extend_count.saturating_add(1);
    record.highest_hop_index = record
        .highest_hop_index
        .max(frame.current_hop.saturating_add(1));
    record.last_hop = Some(format!("sealed-hop-{}", frame.current_hop));
    record.close_reason = None;
    record.last_updated_ms = now_ms();
    push_control_frame_label(record, "CircuitExtend");
}

async fn record_high_risk_close(
    circuits: &Arc<Mutex<StdHashMap<[u8; 16], ObservedHighRiskCircuit>>>,
    space_prefix: [u8; 8],
    slot: u64,
    frame: &CircuitClose,
) {
    let mut circuits = circuits.lock().await;
    prune_high_risk_circuits(&mut circuits, slot);
    let record = circuits
        .entry(frame.circuit_id)
        .or_insert_with(|| ObservedHighRiskCircuit {
            circuit_id: frame.circuit_id,
            space_prefix,
            origin_id: None,
            active: false,
            opened_at_slot: Some(slot),
            expires_at_slot: Some(slot),
            first_hop: None,
            last_hop: None,
            extend_count: 0,
            highest_hop_index: 0,
            cover_packets: 0,
            control_frames_seen: 0,
            close_reason: Some(frame.reason_code),
            last_updated_ms: now_ms(),
        });
    record.space_prefix = space_prefix;
    record.active = false;
    record.close_reason = Some(frame.reason_code);
    record.expires_at_slot = Some(record.expires_at_slot.unwrap_or(slot).max(slot));
    record.last_updated_ms = now_ms();
    push_control_frame_label(record, "CircuitClose");
}

async fn record_high_risk_cover(
    circuits: &Arc<Mutex<StdHashMap<[u8; 16], ObservedHighRiskCircuit>>>,
    space_prefix: [u8; 8],
    slot: u64,
    frame: &CoverPacket,
) {
    let mut circuits = circuits.lock().await;
    prune_high_risk_circuits(&mut circuits, slot);
    let record = circuits
        .entry(frame.stream_id)
        .or_insert_with(|| ObservedHighRiskCircuit {
            circuit_id: frame.stream_id,
            space_prefix,
            origin_id: None,
            active: true,
            opened_at_slot: Some(slot),
            expires_at_slot: Some(slot.saturating_add(2)),
            first_hop: None,
            last_hop: None,
            extend_count: 0,
            highest_hop_index: 0,
            cover_packets: 0,
            control_frames_seen: 0,
            close_reason: None,
            last_updated_ms: now_ms(),
        });
    record.space_prefix = space_prefix;
    record.active = record.close_reason.is_none();
    record.expires_at_slot = Some(
        record
            .expires_at_slot
            .unwrap_or(slot.saturating_add(2))
            .max(slot.saturating_add(2)),
    );
    record.cover_packets = record.cover_packets.saturating_add(1);
    record.last_updated_ms = now_ms();
    push_control_frame_label(record, "Cover");
}

async fn install_high_risk_route_binding(
    routes: &Arc<Mutex<StdHashMap<[u8; 16], HighRiskRouteBinding>>>,
    pending_accepts: &Arc<Mutex<StdHashMap<[u8; 8], VecDeque<PendingHighRiskTransportSession>>>>,
    accept_notify: &Arc<Notify>,
    onion_secret_key: &[u8; 32],
    node_id: [u8; 16],
    circuit_id: [u8; 16],
    space_prefix: [u8; 8],
    payload: &[u8],
    current_slot: u64,
) -> Option<CircuitReady> {
    let Some(handshake) = decode_high_risk_hop_handshake(payload) else {
        return None;
    };
    let local_onion_secret_key = Zeroizing::new(
        derive_rotating_onion_secret_key(
            onion_secret_key,
            &space_prefix,
            handshake.onion_epoch_slot,
            &handshake.onion_salt,
        )
        .ok()?,
    );
    let hop_session_key = Zeroizing::new(
        derive_onion_session_key(
            &local_onion_secret_key,
            &handshake.origin_ephemeral_pubkey,
            &circuit_id,
        )
        .ok()?,
    );
    let capsule =
        open_hop_capsule(&hop_session_key, &circuit_id, &handshake.sealed_capsule).ok()?;
    let descriptor = capsule.descriptor;
    if descriptor.circuit_id != circuit_id {
        return None;
    }
    if descriptor.space_prefix != space_prefix {
        return None;
    }
    if descriptor.expires_at_slot < current_slot {
        return None;
    }
    let Some(local_role) = high_risk_local_role_from_code(capsule.local_role_code) else {
        return None;
    };
    if !high_risk_role_matches_descriptor(local_role, node_id, &descriptor) {
        return None;
    }
    let hop_session_key = Some(*hop_session_key);
    let reply_session_key = Zeroizing::new(
        derive_onion_session_key(
            &local_onion_secret_key,
            &capsule.reply_origin_ephemeral_pubkey,
            &descriptor.circuit_id,
        )
        .ok()?,
    );

    let mut routes_guard = routes.lock().await;
    if let Some(existing) = routes_guard.get_mut(&descriptor.circuit_id) {
        existing.last_updated_ms = now_ms();
        return None;
    }

    if local_role == HighRiskLocalRole::Exit {
        let circuit_id = descriptor.circuit_id;
        let (deliver_tx, receiver) = mpsc::channel(256);
        let ready_state = Arc::new(AtomicBool::new(true));
        let ready_notify = Arc::new(Notify::new());
        let exit_onion_codec = if handshake.reply_layers_ciphertext.is_empty() {
            None
        } else {
            Some(OnionCodec {
                layers: decrypt_reply_layers(
                    &reply_session_key,
                    &descriptor.circuit_id,
                    &handshake.reply_layers_ciphertext,
                )
                .ok()?,
            })
        };
        routes_guard.insert(
            circuit_id,
            HighRiskRouteBinding {
                descriptor: descriptor.clone(),
                local_role,
                deliver_tx: Some(deliver_tx),
                hop_session_key,
                reply_session_key: Some(*reply_session_key),
                onion_codec: exit_onion_codec,
                ready_state: Some(Arc::clone(&ready_state)),
                ready_notify: Some(Arc::clone(&ready_notify)),
                last_updated_ms: now_ms(),
            },
        );
        drop(routes_guard);

        let mut pending = pending_accepts.lock().await;
        pending
            .entry(space_prefix)
            .or_default()
            .push_back(PendingHighRiskTransportSession {
                circuit_id,
                descriptor: descriptor.clone(),
                local_role,
                receiver,
                ready_state,
                ready_notify,
            });
        accept_notify.notify_waiters();
        return Some(CircuitReady {
            version: 1,
            circuit_id,
            established_at_slot: current_slot,
            ready_mac: compute_high_risk_ready_mac(
                &reply_session_key,
                &descriptor.circuit_id,
                current_slot,
            ),
        });
    }

    routes_guard.insert(
        descriptor.circuit_id,
        HighRiskRouteBinding {
            descriptor,
            local_role,
            deliver_tx: None,
            hop_session_key,
            reply_session_key: Some(*reply_session_key),
            onion_codec: None,
            ready_state: None,
            ready_notify: None,
            last_updated_ms: now_ms(),
        },
    );
    None
}

async fn remove_high_risk_route_binding(
    routes: &Arc<Mutex<StdHashMap<[u8; 16], HighRiskRouteBinding>>>,
    pending_accepts: &Arc<Mutex<StdHashMap<[u8; 8], VecDeque<PendingHighRiskTransportSession>>>>,
    pending_acks: &Arc<Mutex<StdHashMap<HighRiskAckKey, oneshot::Sender<()>>>>,
    circuit_id: [u8; 16],
) {
    routes.lock().await.remove(&circuit_id);
    let mut pending_guard = pending_accepts.lock().await;
    for queue in pending_guard.values_mut() {
        queue.retain(|session| session.circuit_id != circuit_id);
    }
    pending_guard.retain(|_, queue| !queue.is_empty());
    pending_acks
        .lock()
        .await
        .retain(|key, _| key.circuit_id != circuit_id);
}

async fn handle_high_risk_forward(
    routes: &Arc<Mutex<StdHashMap<[u8; 16], HighRiskRouteBinding>>>,
    pending_acks: &Arc<Mutex<StdHashMap<HighRiskAckKey, oneshot::Sender<()>>>>,
    forward_seen: &Arc<Mutex<StdHashMap<HighRiskForwardKey, u64>>>,
    storage: &Arc<Mutex<EtherStorage>>,
    seen_messages: &Arc<RwLock<HashSet<[u8; 32]>>>,
    max_seen_cache: usize,
    gossip_engine: &Arc<RwLock<Option<GossipEngine>>>,
    passphrase: &str,
    slot: u64,
    forward: RouteForward,
) {
    if !mark_high_risk_forward_seen(forward_seen, &forward).await {
        return;
    }

    enum ForwardAction {
        Relay(RouteForward),
        Deliver(mpsc::Sender<Vec<u8>>, Vec<u8>, Option<DeliveryReceipt>),
        ResolveReceipt(DeliveryReceipt),
        Ignore,
    }

    let action = {
        let mut routes_guard = routes.lock().await;
        let Some(binding) = routes_guard.get_mut(&forward.circuit_id) else {
            return;
        };
        binding.last_updated_ms = now_ms();
        let Some(expected_hop) = expected_high_risk_hop(binding.local_role, forward.direction)
        else {
            return;
        };
        if forward.hop_index != expected_hop {
            return;
        }

        let payload = match decode_inbound_high_risk_payload(binding, &forward) {
            Some(payload) => payload,
            None => return,
        };

        if is_terminal_high_risk_hop(binding.local_role, forward.direction) {
            match decode_high_risk_payload_frame(&payload) {
                Some(HighRiskPayloadFrame::DeliveryReceipt(receipt)) => {
                    if !verify_delivery_receipt(binding, &receipt) {
                        ForwardAction::Ignore
                    } else {
                        ForwardAction::ResolveReceipt(receipt)
                    }
                }
                Some(HighRiskPayloadFrame::Application(app_payload)) => {
                    match binding.deliver_tx.clone() {
                        Some(deliver_tx) => ForwardAction::Deliver(
                            deliver_tx,
                            app_payload,
                            build_delivery_receipt(binding, &forward),
                        ),
                        None => ForwardAction::Ignore,
                    }
                }
                None => match binding.deliver_tx.clone() {
                    Some(deliver_tx) => ForwardAction::Deliver(
                        deliver_tx,
                        payload,
                        build_delivery_receipt(binding, &forward),
                    ),
                    None => ForwardAction::Ignore,
                },
            }
        } else {
            ForwardAction::Relay(RouteForward {
                version: forward.version,
                packet_id: forward.packet_id,
                circuit_id: forward.circuit_id,
                direction: forward.direction,
                hop_index: forward.hop_index.saturating_add(1),
                remaining_hops: forward.remaining_hops.saturating_sub(1),
                payload,
            })
        }
    };

    match action {
        ForwardAction::Relay(next) => {
            let _ = publish_orp_frame_router(
                storage,
                seen_messages,
                max_seen_cache,
                gossip_engine,
                passphrase,
                slot,
                OrpFrame::Forward(next),
                SUBSPACE_ROUTE_FORWARD,
            )
            .await;
        }
        ForwardAction::Deliver(deliver_tx, payload, receipt) => {
            if deliver_tx.try_send(payload).is_ok() {
                if let Some(receipt) = receipt {
                    let _ = publish_high_risk_delivery_receipt_router(
                        routes,
                        storage,
                        seen_messages,
                        max_seen_cache,
                        gossip_engine,
                        passphrase,
                        receipt,
                    )
                    .await;
                }
            }
        }
        ForwardAction::ResolveReceipt(receipt) => {
            resolve_pending_high_risk_ack(pending_acks, receipt).await;
        }
        ForwardAction::Ignore => {}
    }
}

async fn handle_high_risk_delivery_notice(
    routes: &Arc<Mutex<StdHashMap<[u8; 16], HighRiskRouteBinding>>>,
    _storage: &Arc<Mutex<EtherStorage>>,
    _seen_messages: &Arc<RwLock<HashSet<[u8; 32]>>>,
    _max_seen_cache: usize,
    _gossip_engine: &Arc<RwLock<Option<GossipEngine>>>,
    _passphrase: &str,
    _slot: u64,
    notice: ForwardDeliveryNotice,
) {
    let mut routes_guard = routes.lock().await;
    if let Some(binding) = routes_guard.get_mut(&notice.circuit_id) {
        binding.last_updated_ms = now_ms();
    }
}

async fn publish_high_risk_delivery_receipt_router(
    routes: &Arc<Mutex<StdHashMap<[u8; 16], HighRiskRouteBinding>>>,
    storage: &Arc<Mutex<EtherStorage>>,
    seen_messages: &Arc<RwLock<HashSet<[u8; 32]>>>,
    max_seen_cache: usize,
    gossip_engine: &Arc<RwLock<Option<GossipEngine>>>,
    passphrase: &str,
    receipt: DeliveryReceipt,
) -> Result<(), EtherSyncError> {
    let direction = opposite_route_direction(receipt.direction);
    let mut packet_id = [0u8; 16];
    fill_random(&mut packet_id).map_err(|_| {
        EtherSyncError::NetworkError("failed to generate delivery receipt packet id".to_string())
    })?;
    let payload_bytes =
        serialize_high_risk_payload_frame(&HighRiskPayloadFrame::DeliveryReceipt(receipt.clone()))?;

    let (payload, hop_index, remaining_hops) = {
        let routes_guard = routes.lock().await;
        let Some(binding) = routes_guard.get(&receipt.circuit_id) else {
            return Ok(());
        };
        let payload =
            encode_outbound_high_risk_payload(binding, direction, &packet_id, &payload_bytes)?;
        let (hop_index, remaining_hops) =
            outbound_high_risk_route_state(binding.local_role, direction)?;
        (payload, hop_index, remaining_hops)
    };

    publish_orp_frame_router(
        storage,
        seen_messages,
        max_seen_cache,
        gossip_engine,
        passphrase,
        EtherCoordinate::current_slot(),
        OrpFrame::Forward(RouteForward {
            version: 1,
            circuit_id: receipt.circuit_id,
            packet_id,
            direction,
            hop_index,
            remaining_hops,
            payload,
        }),
        SUBSPACE_ROUTE_FORWARD,
    )
    .await
}

async fn resolve_pending_high_risk_ack(
    pending_acks: &Arc<Mutex<StdHashMap<HighRiskAckKey, oneshot::Sender<()>>>>,
    receipt: DeliveryReceipt,
) {
    let key = HighRiskAckKey {
        circuit_id: receipt.circuit_id,
        packet_id: receipt.packet_id,
        direction: receipt.direction,
    };
    if let Some(tx) = pending_acks.lock().await.remove(&key) {
        let _ = tx.send(());
    }
}

async fn handle_high_risk_circuit_ready(
    routes: &Arc<Mutex<StdHashMap<[u8; 16], HighRiskRouteBinding>>>,
    ready: CircuitReady,
) {
    let mut routes_guard = routes.lock().await;
    if let Some(binding) = routes_guard.get_mut(&ready.circuit_id) {
        if !verify_high_risk_ready(binding, &ready) {
            return;
        }
        binding.last_updated_ms = now_ms();
        if let Some(ready_state) = binding.ready_state.as_ref() {
            ready_state.store(true, Ordering::SeqCst);
        }
        if let Some(ready_notify) = binding.ready_notify.as_ref() {
            ready_notify.notify_waiters();
        }
    }
}

fn serialize_hop_handshake(handshake: HopHandshake) -> Result<Vec<u8>, EtherSyncError> {
    bincode::serialize(&handshake).map_err(|err| {
        EtherSyncError::NetworkError(format!(
            "failed to serialize high-risk hop handshake: {err}"
        ))
    })
}

fn decode_high_risk_hop_handshake(payload: &[u8]) -> Option<HopHandshake> {
    bincode::deserialize(payload).ok()
}

fn map_onion_error(err: crate::onion::OnionError) -> EtherSyncError {
    EtherSyncError::NetworkError(format!("high-risk onion error: {err}"))
}

fn expected_high_risk_hop(local_role: HighRiskLocalRole, direction: RouteDirection) -> Option<u8> {
    match (local_role, direction) {
        (HighRiskLocalRole::Entry, RouteDirection::OriginToTarget) => Some(0),
        (HighRiskLocalRole::Middle, RouteDirection::OriginToTarget) => Some(1),
        (HighRiskLocalRole::Exit, RouteDirection::OriginToTarget) => Some(2),
        (HighRiskLocalRole::Middle, RouteDirection::TargetToOrigin) => Some(0),
        (HighRiskLocalRole::Entry, RouteDirection::TargetToOrigin) => Some(1),
        (HighRiskLocalRole::Origin, RouteDirection::TargetToOrigin) => Some(2),
        _ => None,
    }
}

fn is_terminal_high_risk_hop(local_role: HighRiskLocalRole, direction: RouteDirection) -> bool {
    matches!(
        (local_role, direction),
        (HighRiskLocalRole::Exit, RouteDirection::OriginToTarget)
            | (HighRiskLocalRole::Origin, RouteDirection::TargetToOrigin)
    )
}

async fn mark_high_risk_forward_seen(
    forward_seen: &Arc<Mutex<StdHashMap<HighRiskForwardKey, u64>>>,
    forward: &RouteForward,
) -> bool {
    let now = now_ms();
    let mut seen = forward_seen.lock().await;
    seen.retain(|_, seen_at| now.saturating_sub(*seen_at) <= 15 * 60 * 1000);
    let key = HighRiskForwardKey {
        circuit_id: forward.circuit_id,
        packet_id: forward.packet_id,
        direction: forward.direction,
        hop_index: forward.hop_index,
    };
    if seen.contains_key(&key) {
        return false;
    }
    seen.insert(key, now);
    if seen.len() > 8192 {
        let cutoff = now.saturating_sub(5 * 60 * 1000);
        seen.retain(|_, seen_at| *seen_at >= cutoff);
    }
    true
}

async fn publish_orp_frame_router(
    storage: &Arc<Mutex<EtherStorage>>,
    seen_messages: &Arc<RwLock<HashSet<[u8; 32]>>>,
    max_seen_cache: usize,
    gossip_engine: &Arc<RwLock<Option<GossipEngine>>>,
    passphrase: &str,
    slot: u64,
    frame: OrpFrame,
    subspace: u64,
) -> Result<(), EtherSyncError> {
    let payload = encode_orp_frame(&frame)?;
    let msg = EtherMessage::new_control_message(passphrase, slot, &payload, subspace)?;
    let hash = blake3_hash(&msg.encrypted_payload);
    {
        let mut st = storage.lock().await;
        st.store(slot, hash, msg.clone())?;
    }
    {
        let mut seen = seen_messages.write().await;
        seen.insert(hash);
        if seen.len() > max_seen_cache {
            let to_remove: Vec<_> = seen.iter().take(seen.len() / 2).cloned().collect();
            for h in to_remove {
                seen.remove(&h);
            }
        }
    }

    let ge = gossip_engine.clone();
    tokio::spawn(async move {
        for _ in 0..50 {
            {
                let g = ge.read().await;
                if let Some(ref engine) = *g {
                    let _ = engine.publish(msg).await;
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    Ok(())
}

const HIGH_RISK_PAYLOAD_MAGIC: &[u8] = b"orbp1";

fn serialize_high_risk_payload_frame(
    frame: &HighRiskPayloadFrame,
) -> Result<Vec<u8>, EtherSyncError> {
    let mut encoded = HIGH_RISK_PAYLOAD_MAGIC.to_vec();
    let body = bincode::serialize(frame).map_err(|err| {
        EtherSyncError::NetworkError(format!(
            "failed to serialize high-risk payload frame: {err}"
        ))
    })?;
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

fn decode_high_risk_payload_frame(payload: &[u8]) -> Option<HighRiskPayloadFrame> {
    payload
        .strip_prefix(HIGH_RISK_PAYLOAD_MAGIC)
        .and_then(|body| bincode::deserialize(body).ok())
}

fn build_delivery_receipt(
    binding: &HighRiskRouteBinding,
    forward: &RouteForward,
) -> Option<DeliveryReceipt> {
    let session_key = receipt_session_key(binding)?;
    Some(DeliveryReceipt {
        version: 1,
        circuit_id: forward.circuit_id,
        packet_id: forward.packet_id,
        direction: forward.direction,
        receipt_mac: compute_delivery_receipt_mac(
            &session_key,
            &forward.circuit_id,
            &forward.packet_id,
            forward.direction,
        ),
    })
}

fn compute_high_risk_ready_mac(
    session_key: &[u8; 32],
    circuit_id: &[u8; 16],
    established_at_slot: u64,
) -> [u8; 16] {
    let mut input = Vec::with_capacity(16 + 8 + 18);
    input.extend_from_slice(b"orp/high-risk/ready");
    input.extend_from_slice(circuit_id);
    input.extend_from_slice(&established_at_slot.to_le_bytes());
    let digest = blake3::keyed_hash(session_key, &input);
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&digest.as_bytes()[..16]);
    mac
}

fn compute_high_risk_close_mac(
    session_key: &[u8; 32],
    circuit_id: &[u8; 16],
    reason_code: u16,
    target_role_code: u8,
) -> [u8; 16] {
    let mut input = Vec::with_capacity(16 + 2 + 1 + 18);
    input.extend_from_slice(b"orp/high-risk/close");
    input.extend_from_slice(circuit_id);
    input.extend_from_slice(&reason_code.to_le_bytes());
    input.push(target_role_code);
    let digest = blake3::keyed_hash(session_key, &input);
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&digest.as_bytes()[..16]);
    mac
}

fn verify_high_risk_ready(binding: &HighRiskRouteBinding, ready: &CircuitReady) -> bool {
    if binding.local_role != HighRiskLocalRole::Origin {
        return false;
    }
    let Some(session_key) = binding.reply_session_key else {
        return false;
    };
    compute_high_risk_ready_mac(&session_key, &ready.circuit_id, ready.established_at_slot)
        == ready.ready_mac
}

fn close_auth_key_for_binding(binding: &HighRiskRouteBinding) -> Option<[u8; 32]> {
    match binding.local_role {
        HighRiskLocalRole::Origin => binding.reply_session_key,
        HighRiskLocalRole::Entry | HighRiskLocalRole::Middle | HighRiskLocalRole::Exit => {
            binding.hop_session_key
        }
    }
}

fn verify_high_risk_close(binding: &HighRiskRouteBinding, close: &CircuitClose) -> bool {
    if high_risk_local_role_code(binding.local_role) != close.target_role_code {
        return false;
    }
    let Some(session_key) = close_auth_key_for_binding(binding) else {
        return false;
    };
    compute_high_risk_close_mac(
        &session_key,
        &close.circuit_id,
        close.reason_code,
        close.target_role_code,
    ) == close.control_mac
}

fn build_high_risk_close_frames(
    binding: &HighRiskRouteBinding,
    circuit_id: [u8; 16],
    reason_code: u16,
) -> Vec<CircuitClose> {
    match binding.local_role {
        HighRiskLocalRole::Origin => binding
            .onion_codec
            .as_ref()
            .map(|codec| {
                codec
                    .layers
                    .iter()
                    .enumerate()
                    .map(|(hop_index, layer)| {
                        let target_role_code = match hop_index {
                            0 => high_risk_local_role_code(HighRiskLocalRole::Entry),
                            1 => high_risk_local_role_code(HighRiskLocalRole::Middle),
                            _ => high_risk_local_role_code(HighRiskLocalRole::Exit),
                        };
                        CircuitClose {
                            version: 1,
                            circuit_id,
                            reason_code,
                            target_role_code,
                            control_mac: compute_high_risk_close_mac(
                                &layer.session_key,
                                &circuit_id,
                                reason_code,
                                target_role_code,
                            ),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default(),
        HighRiskLocalRole::Exit => binding
            .reply_session_key
            .map(|session_key| {
                vec![CircuitClose {
                    version: 1,
                    circuit_id,
                    reason_code,
                    target_role_code: high_risk_local_role_code(HighRiskLocalRole::Origin),
                    control_mac: compute_high_risk_close_mac(
                        &session_key,
                        &circuit_id,
                        reason_code,
                        high_risk_local_role_code(HighRiskLocalRole::Origin),
                    ),
                }]
            })
            .unwrap_or_default(),
        HighRiskLocalRole::Entry | HighRiskLocalRole::Middle => Vec::new(),
    }
}

fn verify_delivery_receipt(binding: &HighRiskRouteBinding, receipt: &DeliveryReceipt) -> bool {
    let Some(session_key) = receipt_session_key(binding) else {
        return false;
    };
    compute_delivery_receipt_mac(
        &session_key,
        &receipt.circuit_id,
        &receipt.packet_id,
        receipt.direction,
    ) == receipt.receipt_mac
}

fn receipt_session_key(binding: &HighRiskRouteBinding) -> Option<[u8; 32]> {
    match binding.local_role {
        HighRiskLocalRole::Exit | HighRiskLocalRole::Origin => binding.reply_session_key,
        HighRiskLocalRole::Entry | HighRiskLocalRole::Middle => None,
    }
}

fn compute_delivery_receipt_mac(
    session_key: &[u8; 32],
    circuit_id: &[u8; 16],
    packet_id: &[u8; 16],
    direction: RouteDirection,
) -> [u8; 16] {
    let mut input = Vec::with_capacity(33);
    input.extend_from_slice(circuit_id);
    input.extend_from_slice(packet_id);
    input.push(route_direction_code(direction));
    let digest = blake3::keyed_hash(session_key, &input);
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&digest.as_bytes()[..16]);
    mac
}

fn route_direction_code(direction: RouteDirection) -> u8 {
    match direction {
        RouteDirection::OriginToTarget => 1,
        RouteDirection::TargetToOrigin => 2,
    }
}

fn opposite_route_direction(direction: RouteDirection) -> RouteDirection {
    match direction {
        RouteDirection::OriginToTarget => RouteDirection::TargetToOrigin,
        RouteDirection::TargetToOrigin => RouteDirection::OriginToTarget,
    }
}

async fn sweep_expired_high_risk_bindings(
    routes: &Arc<Mutex<StdHashMap<[u8; 16], HighRiskRouteBinding>>>,
    pending_accepts: &Arc<Mutex<StdHashMap<[u8; 8], VecDeque<PendingHighRiskTransportSession>>>>,
    pending_acks: &Arc<Mutex<StdHashMap<HighRiskAckKey, oneshot::Sender<()>>>>,
    forward_seen: &Arc<Mutex<StdHashMap<HighRiskForwardKey, u64>>>,
    current_slot: u64,
) {
    let mut removed_circuit_ids = Vec::new();
    {
        let mut routes_guard = routes.lock().await;
        routes_guard.retain(|circuit_id, binding| {
            let keep = binding.descriptor.expires_at_slot >= current_slot;
            if !keep {
                removed_circuit_ids.push(*circuit_id);
            }
            keep
        });
    }

    {
        let mut pending_guard = pending_accepts.lock().await;
        for queue in pending_guard.values_mut() {
            queue.retain(|session| {
                let keep = session.descriptor.expires_at_slot >= current_slot;
                if !keep {
                    removed_circuit_ids.push(session.circuit_id);
                }
                keep
            });
        }
        pending_guard.retain(|_, queue| !queue.is_empty());
    }

    if !removed_circuit_ids.is_empty() {
        let removed = removed_circuit_ids
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        pending_acks
            .lock()
            .await
            .retain(|key, _| !removed.contains(&key.circuit_id));
    }

    {
        let cutoff = now_ms().saturating_sub(5 * 60_000);
        let mut forward_seen_guard = forward_seen.lock().await;
        forward_seen_guard.retain(|_, seen_at_ms| *seen_at_ms >= cutoff);
    }
}

fn outbound_high_risk_route_state(
    local_role: HighRiskLocalRole,
    direction: RouteDirection,
) -> Result<(u8, u8), EtherSyncError> {
    match (local_role, direction) {
        (HighRiskLocalRole::Origin, RouteDirection::OriginToTarget)
        | (HighRiskLocalRole::Exit, RouteDirection::TargetToOrigin) => Ok((0, 2)),
        _ => Err(EtherSyncError::NetworkError(
            "high-risk route direction is not valid for the local endpoint role".to_string(),
        )),
    }
}

fn encode_outbound_high_risk_payload(
    binding: &HighRiskRouteBinding,
    direction: RouteDirection,
    packet_id: &[u8; 16],
    payload_bytes: &[u8],
) -> Result<Vec<u8>, EtherSyncError> {
    match (binding.local_role, direction) {
        (HighRiskLocalRole::Origin, RouteDirection::OriginToTarget)
        | (HighRiskLocalRole::Exit, RouteDirection::TargetToOrigin) => {
            let Some(onion_codec) = binding.onion_codec.as_ref() else {
                return Err(EtherSyncError::NetworkError(
                    "high-risk onion codec is not installed for the outbound circuit direction"
                        .to_string(),
                ));
            };
            onion_codec
                .wrap(packet_id, payload_bytes)
                .map_err(map_onion_error)
        }
        _ => Ok(payload_bytes.to_vec()),
    }
}

fn decode_inbound_high_risk_payload(
    binding: &HighRiskRouteBinding,
    forward: &RouteForward,
) -> Option<Vec<u8>> {
    match (binding.local_role, forward.direction) {
        (
            HighRiskLocalRole::Entry | HighRiskLocalRole::Middle | HighRiskLocalRole::Exit,
            RouteDirection::OriginToTarget,
        ) => {
            let hop_session_key = binding.hop_session_key.as_ref()?;
            OnionCodec::peel(
                hop_session_key,
                forward.hop_index,
                &forward.packet_id,
                &forward.payload,
            )
            .ok()
        }
        (HighRiskLocalRole::Middle, RouteDirection::TargetToOrigin) => {
            let reply_session_key = binding.reply_session_key.as_ref()?;
            OnionCodec::peel(reply_session_key, 1, &forward.packet_id, &forward.payload).ok()
        }
        (HighRiskLocalRole::Entry, RouteDirection::TargetToOrigin) => {
            let reply_session_key = binding.reply_session_key.as_ref()?;
            OnionCodec::peel(reply_session_key, 0, &forward.packet_id, &forward.payload).ok()
        }
        (HighRiskLocalRole::Origin, RouteDirection::TargetToOrigin) => OnionCodec::peel(
            binding.reply_session_key.as_ref()?,
            2,
            &forward.packet_id,
            &forward.payload,
        )
        .ok(),
        _ => Some(forward.payload.clone()),
    }
}

impl Drop for EtherNode {
    fn drop(&mut self) {
        self.onion_secret_key.zeroize();
    }
}

#[cfg(feature = "handshake-fallback")]
pub mod handshake_stub {
    //! STUB for future handshacke integration
    pub struct HandshakeFallbackStub;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_creation() {
        let config = NodeConfig::default();
        let node = EtherNode::new(config).await.unwrap();

        assert!(node.local_addr().port() > 0);
        assert_eq!(node.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_publish_message() {
        let config = NodeConfig::default();
        let node = EtherNode::new(config).await.unwrap();

        let msg = node.publish("test-pass", b"hello world").await.unwrap();

        assert_eq!(msg.header.slot_id, EtherCoordinate::current_slot());
    }

    #[tokio::test]
    async fn test_subscribe() {
        let config = NodeConfig::default();
        let node = EtherNode::new(config).await.unwrap();

        let rx = node.subscribe("test-pass").await.unwrap();

        // Subscription should be active
        assert_eq!(node.subscription_count().await, 1);

        // Channel should be open (not closed)
        assert!(!rx.is_closed());
    }

    #[tokio::test]
    async fn test_message_hash_consistency() {
        let msg1 = EtherMessage::new("pass", 1, b"test", 0, 1).unwrap();
        let msg2 = EtherMessage::new("pass", 1, b"test", 0, 1).unwrap();

        // Different nonces = different encrypted payloads = different hashes
        let hash1 = EtherNode::message_hash(&msg1);
        let hash2 = EtherNode::message_hash(&msg2);

        // Hashes should be different due to random nonce
        assert_ne!(hash1, hash2);
    }

    #[tokio::test]
    async fn test_orp_disabled_no_spaces() {
        let config = NodeConfig {
            enable_orp: false,
            ..Default::default()
        };
        let node = EtherNode::new(config).await.unwrap();

        // With ORP disabled, no spaces should be registered
        let prefixes = node.orp_space_prefixes().await;
        assert!(prefixes.is_empty());

        // Route cache should be empty
        let cache = node.route_cache().lock().await;
        assert!(cache.announcements.is_empty());
        assert!(cache.offers.is_empty());
    }

    #[tokio::test]
    async fn test_start_orp_for_space_registers_prefix() {
        let config = NodeConfig {
            enable_orp: true,
            ..Default::default()
        };
        let node = EtherNode::new(config).await.unwrap();

        let prefix = node.start_orp_for_space("test-passphrase").await;

        // Prefix should be non-zero
        assert_ne!(prefix, [0u8; 8]);

        // Space should now appear in orp_space_prefixes
        let prefixes = node.orp_space_prefixes().await;
        assert_eq!(prefixes.len(), 1);
        assert!(prefixes.contains(&prefix));
    }

    #[tokio::test]
    async fn test_start_orp_produces_announcement_in_cache() {
        let config = NodeConfig {
            enable_orp: true,
            ..Default::default()
        };
        let node = EtherNode::new(config).await.unwrap();

        let _prefix = node.start_orp_for_space("announce-test").await;

        // The initial announcement should be stored in local storage
        // and the route cache gets populated when announcements are
        // received from gossip. Let's verify the announcement was at
        // least published by checking storage.
        let slot = crate::EtherCoordinate::current_slot();
        let storage = node.storage().lock().await;
        let msgs = storage.get_slot_messages(slot).unwrap_or_default();
        // Should have at least 1 message (the route announcement)
        assert!(
            !msgs.is_empty(),
            "ORP announcement should be stored locally"
        );
    }

    #[tokio::test]
    async fn test_orp_deterministic_prefix() {
        // Same passphrase must produce same prefix
        let config = NodeConfig {
            enable_orp: true,
            ..Default::default()
        };
        let node = EtherNode::new(config).await.unwrap();

        let prefix1 = node.start_orp_for_space("deterministic-test").await;
        let prefix2 = node.start_orp_for_space("deterministic-test").await;
        assert_eq!(
            prefix1, prefix2,
            "same passphrase must yield same space prefix"
        );

        // Different passphrase must produce different prefix
        let prefix3 = node.start_orp_for_space("other-passphrase").await;
        assert_ne!(
            prefix1, prefix3,
            "different passphrases must yield different prefixes"
        );
    }

    #[tokio::test]
    async fn test_orp_no_cross_space_in_space_prefixes() {
        let config = NodeConfig {
            enable_orp: true,
            ..Default::default()
        };
        let node = EtherNode::new(config).await.unwrap();

        let prefix_a = node.start_orp_for_space("space-alpha").await;
        let prefix_b = node.start_orp_for_space("space-beta").await;

        let prefixes = node.orp_space_prefixes().await;
        assert_eq!(prefixes.len(), 2);
        assert!(prefixes.contains(&prefix_a));
        assert!(prefixes.contains(&prefix_b));

        // Verify they're distinct
        assert_ne!(prefix_a, prefix_b);
    }
}
