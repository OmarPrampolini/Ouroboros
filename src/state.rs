use crate::security::RateLimiter;
use base64::{engine::general_purpose, Engine as _};
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
}

#[derive(Debug, Clone, Serialize)]
pub struct EtherSyncJoinResult {
    pub space_id: String,
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
    subscriptions: HashMap<String, JoinHandle<()>>,
    events_tx: broadcast::Sender<String>,
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

        let node_cfg = NodeConfig {
            bind_addr: cfg.bind_addr.clone(),
            bootstrap_peers: cfg.bootstrap_peers,
            gossip_interval_secs: cfg.gossip_interval_secs.max(1),
            sweep_interval_secs: cfg.sweep_interval_secs.max(1),
            gossip_ttl: cfg.gossip_ttl.max(1),
            enable_compression: cfg.enable_compression,
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
        emit_ethersync_event(
            &events_tx,
            EtherSyncEvent {
                kind: "started".to_string(),
                ts_ms: now_ms(),
                space_id: None,
                slot_id: None,
                payload_b64: None,
                text: None,
                info: Some("ethersync node started".to_string()),
                error: None,
            },
        );

        let runtime = EtherSyncRuntime {
            node,
            bind_addr: cfg.bind_addr,
            shutdown_tx,
            run_task,
            subscriptions: HashMap::new(),
            events_tx,
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
            return Ok(EtherSyncStatus {
                running: false,
                bind_addr: None,
                local_addr: None,
                peer_count: 0,
                subscription_count: 0,
                spaces: Vec::new(),
            });
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

        Ok(EtherSyncStatus {
            running: false,
            bind_addr: None,
            local_addr: None,
            peer_count: 0,
            subscription_count: 0,
            spaces: Vec::new(),
        })
    }

    pub async fn ethersync_status(&self) -> anyhow::Result<EtherSyncStatus> {
        let (node, bind_addr, spaces) = {
            let inner = self.inner.lock().await;
            match inner.ethersync.as_ref() {
                Some(rt) => (
                    Some(rt.node.clone()),
                    Some(rt.bind_addr.clone()),
                    rt.subscriptions.keys().cloned().collect::<Vec<_>>(),
                ),
                None => (None, None, Vec::new()),
            }
        };

        let Some(node) = node else {
            return Ok(EtherSyncStatus {
                running: false,
                bind_addr: None,
                local_addr: None,
                peer_count: 0,
                subscription_count: 0,
                spaces: Vec::new(),
            });
        };

        Ok(EtherSyncStatus {
            running: true,
            bind_addr,
            local_addr: Some(node.local_addr().to_string()),
            peer_count: node.peer_count().await,
            subscription_count: node.subscription_count().await,
            spaces,
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
    ) -> anyhow::Result<EtherSyncJoinResult> {
        if passphrase.trim().is_empty() {
            return Err(anyhow::anyhow!("passphrase required"));
        }
        let space_id = derive_space_id(&passphrase, label.as_deref());

        let (node, events_tx, already_subscribed) = {
            let inner = self.inner.lock().await;
            let Some(rt) = inner.ethersync.as_ref() else {
                return Err(anyhow::anyhow!("ethersync is not running"));
            };
            (
                rt.node.clone(),
                rt.events_tx.clone(),
                rt.subscriptions.contains_key(&space_id),
            )
        };

        if already_subscribed {
            let replayed = replay_space_backlog(&node, &events_tx, &passphrase, &space_id).await;
            tracing::info!(
                "ethersync join replayed {} message(s) for existing subscription {}",
                replayed,
                space_id
            );
            return Ok(EtherSyncJoinResult { space_id });
        }

        let mut rx = node
            .subscribe(&passphrase)
            .await
            .map_err(|e| anyhow::anyhow!("failed to subscribe ethersync space: {}", e))?;

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
            tracing::info!(
                "ethersync join replayed {} message(s) for new subscription {}",
                replayed,
                space_id
            );
        }

        Ok(EtherSyncJoinResult { space_id })
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
        let space_id = derive_space_id(&passphrase, None);
        let (node, events_tx) = {
            let inner = self.inner.lock().await;
            let Some(rt) = inner.ethersync.as_ref() else {
                return Err(anyhow::anyhow!("ethersync is not running"));
            };
            (rt.node.clone(), rt.events_tx.clone())
        };

        let message = node
            .publish(&passphrase, &payload)
            .await
            .map_err(|e| anyhow::anyhow!("failed to publish ethersync payload: {}", e))?;

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
        let space_id = derive_space_id(&passphrase, None);

        let (node, events_tx) = {
            let inner = self.inner.lock().await;
            let Some(rt) = inner.ethersync.as_ref() else {
                return Err(anyhow::anyhow!("ethersync is not running"));
            };
            (rt.node.clone(), rt.events_tx.clone())
        };

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
fn emit_ethersync_event(events_tx: &broadcast::Sender<String>, event: EtherSyncEvent) {
    if let Ok(json) = serde_json::to_string(&event) {
        let _ = events_tx.send(json);
    }
}

fn derive_space_id(passphrase: &str, label: Option<&str>) -> String {
    let canonical = canonicalize_passphrase(passphrase);
    let hash = blake3_hash(&canonical);
    let prefix = hex::encode(&hash[..8]);
    if let Some(raw) = label {
        let clean = raw.trim();
        if !clean.is_empty() {
            return format!("{}:{}", clean, prefix);
        }
    }
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

