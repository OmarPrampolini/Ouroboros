//! EtherNode - main interface for EtherSync
//!
//! Fully integrated node with storage, network, and gossip.

use crate::{
    coordinate::{EtherCoordinate, LOOKBACK_SLOTS},
    gossip::{GossipEngine, PeerManager},
    message::EtherMessage,
    network::EtherUdpSocket,
    routing::{
        decode_orp_frame, encode_orp_frame, OrpFrame, RouteAnnouncement, RouteCache,
        RouteCapabilities, RouteLookup, RouteOffer, SUBSPACE_ROUTE_ANNOUNCE,
        SUBSPACE_ROUTE_LOOKUP, SUBSPACE_ROUTE_OFFER, SUBSPACE_USER,
    },
    storage::EtherStorage,
    EtherSyncError,
};
use ouroboros_crypto::derive::canonicalize_passphrase;
use ouroboros_crypto::hash::blake3_hash;
use ouroboros_crypto::random::fill_random;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::interval;
use tracing::{error, info, trace, warn};

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
}

impl EtherNode {
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
        fill_random(&mut node_id).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate node id".to_string())
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
                    } else {
                        // ORP control frame — feed into route cache.
                        // We need a dummy source addr since routing is via gossip;
                        // Phase 2 will thread the real peer addr through the pipeline.
                        let dummy_src: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
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
                        let mut cache = route_cache_router.lock().await;
                        match frame {
                            OrpFrame::Announce(ann) => {
                                cache.insert_announcement(ann, dummy_src, current_slot, &space_hash);
                            }
                            OrpFrame::Offer(offer) => {
                                cache.insert_offer(offer);
                            }
                            _ => {}
                        }
                    }
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
        let sweep_handle = self.spawn_sweep_task();

        // Spawn peer cleanup task
        let cleanup_handle = self.spawn_cleanup_task();

        // ORP announce task is driven per-passphrase in Phase 2.
        // Nothing to spawn at node level yet.

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
                _ = sweep_handle => {}
                _ = cleanup_handle => {}
                _ = shutdown_rx.changed() => {
                    info!("Shutdown signal received, stopping node...");
                }
            }
        }

        // Clean shutdown
        drop(engine);
        router_handle.abort();

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
        let _node_self = Arc::new(Mutex::new(())); // Placeholder for self reference

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

    // -----------------------------------------------------------------------
    // ORP — Ouroboros Routing Protocol
    // -----------------------------------------------------------------------

    /// Publish an ORP route announcement for the given passphrase space.
    ///
    /// The announcement is encrypted with the same passphrase on subspace 1
    /// and gossiped to all known peers, making this node discoverable by others
    /// in the same slot without relying on static bootstrap peers.
    pub async fn publish_route_announcement(
        &self,
        passphrase: &str,
    ) -> Result<(), EtherSyncError> {
        let slot = EtherCoordinate::current_slot();
        let local_addr = self.socket.local_addr();

        // Build assist_tag: first 8 bytes of blake3(node_id)
        let mut assist_tag = [0u8; 8];
        let tag_hash = blake3_hash(&self.node_id);
        assist_tag.copy_from_slice(&tag_hash[..8]);

        let announcement = RouteAnnouncement {
            version: 1,
            slot,
            node_id: self.node_id,
            capabilities: RouteCapabilities {
                can_relay: false,
                direct_udp: !local_addr.ip().is_unspecified(),
                wan_assist: false,
                tor_capable: false,
            },
            reachable_udp: if local_addr.ip().is_unspecified() {
                vec![]
            } else {
                vec![local_addr]
            },
            assist_tag,
            expires_at_slot: slot + 4,
        };

        let frame = OrpFrame::Announce(announcement);
        let payload = encode_orp_frame(&frame)?;

        let msg = EtherMessage::new_control_message(passphrase, slot, &payload, SUBSPACE_ROUTE_ANNOUNCE)?;

        // Store locally and gossip
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
                            trace!("ORP announce gossip failed: {:?}", e);
                        }
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

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
        let slot = EtherCoordinate::current_slot();

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

        let frame = OrpFrame::Lookup(lookup);
        let payload = encode_orp_frame(&frame)?;

        let msg = EtherMessage::new_control_message(passphrase, slot, &payload, SUBSPACE_ROUTE_LOOKUP)?;

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
                            trace!("ORP lookup gossip failed: {:?}", e);
                        }
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        trace!("Published ORP route lookup {:?} for tag {:?}", lookup_id, target_tag);
        Ok(lookup_id)
    }

    /// Return the best cached route offer for the given lookup id, if any.
    pub async fn best_route(
        &self,
        _passphrase: &str,
        lookup_id: [u8; 16],
    ) -> Result<Option<RouteOffer>, EtherSyncError> {
        let cache = self.route_cache.lock().await;
        Ok(cache.best_offer(&lookup_id).map(|co| co.frame.clone()))
    }

    /// Feed a received ORP control message into the route cache.
    ///
    /// Called from the subscription router when a message arrives on a
    /// control subspace (1–4).
    async fn handle_orp_message(
        &self,
        msg: &EtherMessage,
        passphrase: &str,
        source_peer: SocketAddr,
    ) {
        let plaintext = match msg.decrypt(passphrase) {
            Ok(p) => p,
            Err(_) => return,
        };

        let frame = match decode_orp_frame(&plaintext) {
            Ok(f) => f,
            Err(e) => {
                trace!("ORP frame decode error: {:?}", e);
                return;
            }
        };

        let current_slot = EtherCoordinate::current_slot();
        let passphrase_bytes = canonicalize_passphrase(passphrase);
        let space_hash = blake3_hash(&passphrase_bytes);

        let mut cache = self.route_cache.lock().await;

        match frame {
            OrpFrame::Announce(ann) => {
                if !cache.insert_announcement(ann, source_peer, current_slot, &space_hash) {
                    trace!("ORP announcement rejected (stale or cache full)");
                }
            }
            OrpFrame::Offer(offer) => {
                cache.insert_offer(offer);
            }
            OrpFrame::Lookup(_) | OrpFrame::Forward(_) | OrpFrame::Ack(_) => {
                // Lookup and Forward handling will be added in Phase 2.
            }
        }
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
        let max_seen_cache = self.max_seen_cache;

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;

                let slot = EtherCoordinate::current_slot();
                let local_addr = socket.local_addr();

                let mut assist_tag = [0u8; 8];
                let tag_hash = blake3_hash(&node_id);
                assist_tag.copy_from_slice(&tag_hash[..8]);

                let announcement = RouteAnnouncement {
                    version: 1,
                    slot,
                    node_id,
                    capabilities: RouteCapabilities {
                        can_relay: false,
                        direct_udp: !local_addr.ip().is_unspecified(),
                        wan_assist: false,
                        tor_capable: false,
                    },
                    reachable_udp: if local_addr.ip().is_unspecified() {
                        vec![]
                    } else {
                        vec![local_addr]
                    },
                    assist_tag,
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
                        for h in to_remove { seen.remove(&h); }
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
}
