//! Multipath connection coordination for simultaneous transport
//!
//! Supports redundant and split mode for reliability and bandwidth aggregation

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::transport::Connection;

#[derive(Debug, Error)]
pub enum MultipathError {
    #[error("Path index {0} out of bounds")]
    PathIndexOutOfBounds(usize),
    #[error("No active paths")]
    NoActivePaths,
    #[error("All paths failed: {0}")]
    AllPathsFailed(String),
    #[error("Receive timeout on all paths")]
    ReceiveTimeoutAllPaths,
    #[error("I/O error on path {path_idx}: {message}")]
    Io { path_idx: usize, message: String },
    #[error("Buffer too small on path {path_idx}: got {got}, need {need}")]
    BufferTooSmall {
        path_idx: usize,
        got: usize,
        need: usize,
    },
    #[error("Invalid multipath frame: {0}")]
    InvalidFrame(String),
    #[error("Path id overflow for index {0}")]
    PathIdOverflow(usize),
}

type Result<T> = std::result::Result<T, MultipathError>;

const MULTIPATH_MAGIC: [u8; 4] = *b"MPTH";
const MULTIPATH_VERSION: u8 = 1;
const FLAG_DATA: u8 = 0x01;
const FLAG_ACK: u8 = 0x02;
const ACK_BITMAP_MAX_BYTES: usize = 32;
const REORDER_BUFFER_MAX: usize = 64;

/// Multipath packet header used for sequence/reordering.
#[derive(Debug, Clone)]
pub struct MultipathHeader {
    pub seq_num: u64,
    pub path_id: u8,
    pub timestamp: u64,
    pub flags: u8,
}

impl MultipathHeader {
    const ENCODED_LEN: usize = 28;

    fn encode(&self, payload_len: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN + payload_len as usize);
        out.extend_from_slice(&MULTIPATH_MAGIC);
        out.push(MULTIPATH_VERSION);
        out.push(self.flags);
        out.push(self.path_id);
        out.push(0); // reserved
        out.extend_from_slice(&self.seq_num.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out
    }

    fn decode(frame: &[u8]) -> Result<(Self, usize)> {
        if frame.len() < Self::ENCODED_LEN {
            return Err(MultipathError::InvalidFrame("frame too short".to_string()));
        }
        if frame[..4] != MULTIPATH_MAGIC {
            return Err(MultipathError::InvalidFrame("invalid magic".to_string()));
        }
        if frame[4] != MULTIPATH_VERSION {
            return Err(MultipathError::InvalidFrame(format!(
                "unsupported version {}",
                frame[4]
            )));
        }

        let flags = frame[5];
        let path_id = frame[6];
        let seq_num = u64::from_be_bytes(
            frame[8..16]
                .try_into()
                .map_err(|_| MultipathError::InvalidFrame("invalid sequence field".to_string()))?,
        );
        let timestamp =
            u64::from_be_bytes(frame[16..24].try_into().map_err(|_| {
                MultipathError::InvalidFrame("invalid timestamp field".to_string())
            })?);
        let payload_len = u32::from_be_bytes(
            frame[24..28]
                .try_into()
                .map_err(|_| MultipathError::InvalidFrame("invalid payload length".to_string()))?,
        ) as usize;

        let expected = Self::ENCODED_LEN + payload_len;
        if frame.len() < expected {
            return Err(MultipathError::InvalidFrame(
                "truncated frame payload".to_string(),
            ));
        }

        Ok((
            Self {
                seq_num,
                path_id,
                timestamp,
                flags,
            },
            expected,
        ))
    }
}

/// ACK frame with cumulative ack and optional SACK bitmap.
#[derive(Debug, Clone)]
pub struct AckFrame {
    pub acked_seq: u64,
    pub ack_bitmap: Vec<u8>,
    pub path_id: u8,
    pub receive_time: u64,
}

impl AckFrame {
    fn encode_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(18 + self.ack_bitmap.len());
        out.extend_from_slice(&self.acked_seq.to_be_bytes());
        out.extend_from_slice(&self.receive_time.to_be_bytes());
        let len = self.ack_bitmap.len().min(ACK_BITMAP_MAX_BYTES) as u16;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.ack_bitmap[..len as usize]);
        out
    }

    fn decode_payload(path_id: u8, payload: &[u8]) -> Result<Self> {
        if payload.len() < 18 {
            return Err(MultipathError::InvalidFrame(
                "ack payload too short".to_string(),
            ));
        }

        let acked_seq = u64::from_be_bytes(payload[0..8].try_into().map_err(|_| {
            MultipathError::InvalidFrame("ack payload seq decode failed".to_string())
        })?);
        let receive_time = u64::from_be_bytes(payload[8..16].try_into().map_err(|_| {
            MultipathError::InvalidFrame("ack payload time decode failed".to_string())
        })?);
        let bitmap_len = u16::from_be_bytes(payload[16..18].try_into().map_err(|_| {
            MultipathError::InvalidFrame("ack payload bitmap length decode failed".to_string())
        })?) as usize;

        if bitmap_len > ACK_BITMAP_MAX_BYTES {
            return Err(MultipathError::InvalidFrame(
                "ack bitmap exceeds max size".to_string(),
            ));
        }
        if payload.len() < 18 + bitmap_len {
            return Err(MultipathError::InvalidFrame(
                "ack bitmap truncated".to_string(),
            ));
        }

        Ok(Self {
            acked_seq,
            ack_bitmap: payload[18..18 + bitmap_len].to_vec(),
            path_id,
            receive_time,
        })
    }
}

/// Buffer for out-of-order frames.
#[derive(Debug)]
pub struct ReorderBuffer {
    next_seq: u64,
    buffer: BTreeMap<u64, Vec<u8>>,
    max_size: usize,
}

impl ReorderBuffer {
    pub fn new(max_size: usize) -> Self {
        Self {
            next_seq: 0,
            buffer: BTreeMap::new(),
            max_size: max_size.max(1),
        }
    }

    pub fn insert(&mut self, seq: u64, data: Vec<u8>) -> Vec<Vec<u8>> {
        if seq < self.next_seq {
            // Already delivered.
            return Vec::new();
        }

        let mut ready = Vec::new();
        if seq == self.next_seq {
            ready.push(data);
            self.next_seq = self.next_seq.saturating_add(1);
            while let Some(next) = self.buffer.remove(&self.next_seq) {
                ready.push(next);
                self.next_seq = self.next_seq.saturating_add(1);
            }
            return ready;
        }

        if self.buffer.len() < self.max_size {
            self.buffer.insert(seq, data);
        }

        ready
    }

    pub fn get_gaps(&self) -> Vec<(u64, u64)> {
        let mut gaps = Vec::new();
        let mut cursor = self.next_seq;
        for seq in self.buffer.keys() {
            if *seq > cursor {
                gaps.push((cursor, seq.saturating_sub(1)));
            }
            cursor = seq.saturating_add(1);
        }
        gaps
    }

    pub fn highest_contiguous_delivered(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }
}

#[derive(Debug, Clone)]
struct InflightPacket {
    _sent_at_ms: u64,
    _path_id: u8,
}

type InflightMap = Arc<Mutex<BTreeMap<u64, InflightPacket>>>;
type ReadyQueue = Arc<Mutex<VecDeque<(Vec<u8>, usize)>>>;

enum ParsedFrame {
    Data {
        header: MultipathHeader,
        payload: Vec<u8>,
    },
    Ack(AckFrame),
}

/// Multipath connection scheduler policy
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum SchedulerPolicy {
    /// Send identical data on all paths, receive from first
    #[default]
    Redundant,
    /// Split data 70/30 for bandwidth aggregation
    Split,
}

/// Path routing policy for data distribution
#[derive(Debug, Clone)]
pub enum RoutingPolicy {
    /// Send to primary path only
    Primary,
    /// Send to all active paths (redundant)
    All,
    /// Split based on ratio
    Split {
        primary_ratio: f32, // 0.0-1.0
    },
}

/// Path metadata and quality metrics
#[derive(Debug, Clone)]
pub struct PathMetadata {
    pub name: String,
    pub rtt_ms: u64,
    pub loss_rate: f32, // 0.0-1.0
    pub active: bool,
    pub created_at: std::time::Instant,
}

impl Default for PathMetadata {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            rtt_ms: 100,
            loss_rate: 0.0,
            active: true,
            created_at: std::time::Instant::now(),
        }
    }
}

impl PathMetadata {
    pub fn score(&self) -> f32 {
        if !self.active {
            return 0.0;
        }
        // Higher RTT and loss rate = lower score
        let rtt_penalty = 1.0 / (1.0 + (self.rtt_ms as f32 / 100.0));
        let loss_penalty = 1.0 - self.loss_rate.min(1.0);
        rtt_penalty * loss_penalty
    }
}

/// Handle for a single transport path
#[allow(dead_code)]
pub struct TransportHandle {
    transport: Connection,
    metadata: Arc<Mutex<PathMetadata>>,
}

impl TransportHandle {
    pub fn new(transport: Connection, metadata: PathMetadata) -> Self {
        Self {
            transport,
            metadata: Arc::new(Mutex::new(metadata)),
        }
    }

    pub async fn metadata(&self) -> PathMetadata {
        self.metadata.lock().await.clone()
    }

    pub async fn update_metadata<F>(&self, f: F)
    where
        F: FnOnce(&mut PathMetadata),
    {
        let mut meta = self.metadata.lock().await;
        f(&mut meta);
    }

    pub async fn probe_rtt(&self) -> Result<u64> {
        Ok(self.metadata().await.rtt_ms)
    }

    pub async fn probe_path_alive(&self, _timeout_ms: u64) -> Result<bool> {
        Ok(self.metadata().await.active)
    }
}

/// Multipath connection coordinator
#[allow(dead_code)]
pub struct MultipathConnection {
    paths: Vec<TransportHandle>,
    scheduler: SchedulerPolicy,
    primary_idx: usize,
    switch_threshold_ms: u64,
    seq_counter: AtomicU64,
    recv_compat_seq: AtomicU64,
    inflight: InflightMap,
    reorder: Arc<Mutex<ReorderBuffer>>,
    ready_queue: ReadyQueue,
}

impl MultipathConnection {
    /// Create new multipath connection
    pub fn new(scheduler: SchedulerPolicy, switch_threshold_ms: u64) -> Self {
        Self {
            paths: Vec::new(),
            scheduler,
            primary_idx: 0,
            switch_threshold_ms,
            seq_counter: AtomicU64::new(0),
            recv_compat_seq: AtomicU64::new(0),
            inflight: Arc::new(Mutex::new(BTreeMap::new())),
            reorder: Arc::new(Mutex::new(ReorderBuffer::new(REORDER_BUFFER_MAX))),
            ready_queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn next_seq(&self) -> u64 {
        self.seq_counter.fetch_add(1, Ordering::Relaxed)
    }

    fn path_id(path_idx: usize) -> Result<u8> {
        u8::try_from(path_idx).map_err(|_| MultipathError::PathIdOverflow(path_idx))
    }

    fn build_data_packet(seq_num: u64, path_idx: usize, data: &[u8]) -> Result<Vec<u8>> {
        let header = MultipathHeader {
            seq_num,
            path_id: Self::path_id(path_idx)?,
            timestamp: Self::now_ms(),
            flags: FLAG_DATA,
        };
        let mut packet = header.encode(data.len() as u32);
        packet.extend_from_slice(data);
        Ok(packet)
    }

    async fn send_raw_path(&self, path_idx: usize, data: &[u8]) -> Result<()> {
        if path_idx >= self.paths.len() {
            return Err(MultipathError::PathIndexOutOfBounds(path_idx));
        }

        let transport = &self.paths[path_idx].transport;
        match transport {
            Connection::Lan(sock, peer) | Connection::Wan(sock, peer) => {
                sock.send_to(data, *peer)
                    .await
                    .map_err(|e| MultipathError::Io {
                        path_idx,
                        message: e.to_string(),
                    })?;
            }
            Connection::WanTorStream { writer, .. } | Connection::WanTcpStream { writer, .. } => {
                let mut guard = writer.lock().await;
                crate::transport::framing::write_frame(&mut *guard, data)
                    .await
                    .map_err(|e| MultipathError::Io {
                        path_idx,
                        message: e.to_string(),
                    })?;
            }
            Connection::Quic(quic) => {
                quic.send(data).await.map_err(|e| MultipathError::Io {
                    path_idx,
                    message: e.to_string(),
                })?;
            }
            Connection::WebRtc(webrtc) => {
                webrtc.send(data).await.map_err(|e| MultipathError::Io {
                    path_idx,
                    message: e.to_string(),
                })?;
            }
        }
        Ok(())
    }

    async fn send_data_with_seq(&self, path_idx: usize, seq_num: u64, data: &[u8]) -> Result<()> {
        let packet = Self::build_data_packet(seq_num, path_idx, data)?;
        self.send_raw_path(path_idx, &packet).await?;

        let mut inflight = self.inflight.lock().await;
        inflight.insert(
            seq_num,
            InflightPacket {
                _sent_at_ms: Self::now_ms(),
                _path_id: Self::path_id(path_idx)?,
            },
        );
        Ok(())
    }

    async fn recv_raw_path(&self, path_idx: usize) -> Result<Vec<u8>> {
        if path_idx >= self.paths.len() {
            return Err(MultipathError::PathIndexOutOfBounds(path_idx));
        }

        let transport = &self.paths[path_idx].transport;
        let data = match transport {
            Connection::Lan(sock, _) | Connection::Wan(sock, _) => {
                let mut tmp = vec![0u8; 65_535];
                let (n, _) = sock
                    .recv_from(&mut tmp)
                    .await
                    .map_err(|e| MultipathError::Io {
                        path_idx,
                        message: e.to_string(),
                    })?;
                tmp.truncate(n);
                tmp
            }
            Connection::WanTorStream { reader, .. } | Connection::WanTcpStream { reader, .. } => {
                let mut guard = reader.lock().await;
                crate::transport::framing::read_frame(&mut *guard)
                    .await
                    .map_err(|e| MultipathError::Io {
                        path_idx,
                        message: e.to_string(),
                    })?
            }
            Connection::Quic(quic) => quic.recv().await.map_err(|e| MultipathError::Io {
                path_idx,
                message: e.to_string(),
            })?,
            Connection::WebRtc(webrtc) => webrtc.recv().await.map_err(|e| MultipathError::Io {
                path_idx,
                message: e.to_string(),
            })?,
        };

        Ok(data)
    }

    async fn recv_parsed_frame(&self, path_idx: usize) -> Result<ParsedFrame> {
        let data = self.recv_raw_path(path_idx).await?;

        if data.len() >= 4 && data[..4] == MULTIPATH_MAGIC {
            let (header, used) = MultipathHeader::decode(&data)?;
            let payload = data[MultipathHeader::ENCODED_LEN..used].to_vec();

            if (header.flags & FLAG_ACK) != 0 {
                return AckFrame::decode_payload(header.path_id, &payload).map(ParsedFrame::Ack);
            }

            if (header.flags & FLAG_DATA) == 0 {
                return Err(MultipathError::InvalidFrame(
                    "frame without DATA or ACK flag".to_string(),
                ));
            }

            return Ok(ParsedFrame::Data { header, payload });
        }

        // Backward compatibility for legacy raw packets.
        Ok(ParsedFrame::Data {
            header: MultipathHeader {
                seq_num: self.recv_compat_seq.fetch_add(1, Ordering::Relaxed),
                path_id: Self::path_id(path_idx)?,
                timestamp: Self::now_ms(),
                flags: FLAG_DATA,
            },
            payload: data,
        })
    }

    /// Add a new path to the connection
    pub fn add_path(&mut self, transport: Connection, metadata: PathMetadata) {
        let handle = TransportHandle::new(transport, metadata);
        self.paths.push(handle);

        // Set primary if this is the first path
        if self.paths.len() == 1 {
            self.primary_idx = 0;
        }
    }

    /// Update path quality metrics
    pub async fn update_path_quality(
        &mut self,
        path_idx: usize,
        rtt_ms: u64,
        loss_rate: f32,
    ) -> Result<()> {
        if path_idx >= self.paths.len() {
            return Err(MultipathError::PathIndexOutOfBounds(path_idx));
        }

        let handle = &self.paths[path_idx];
        handle
            .update_metadata(|meta| {
                meta.rtt_ms = rtt_ms;
                meta.loss_rate = loss_rate.clamp(0.0, 1.0);
            })
            .await;

        // Auto-switch to better path if needed
        if path_idx != self.primary_idx {
            let primary_meta = self.paths[self.primary_idx].metadata().await;
            let candidate_meta = self.paths[path_idx].metadata().await;
            let primary_score = primary_meta.score();
            let candidate_score = candidate_meta.score();
            let rtt_gain_ms = primary_meta.rtt_ms.saturating_sub(candidate_meta.rtt_ms);
            let loss_gain = (primary_meta.loss_rate - candidate_meta.loss_rate).max(0.0);

            // Switch when the candidate is objectively better and crosses
            // a configurable RTT/loss threshold.
            if candidate_score > primary_score
                && (rtt_gain_ms >= self.switch_threshold_ms || loss_gain >= 0.05)
            {
                tracing::info!(
                    "Switching primary path from {} to {}",
                    self.primary_idx,
                    path_idx
                );
                self.primary_idx = path_idx;
            }
        }

        Ok(())
    }

    /// Probe all paths and refresh quality metrics.
    pub async fn update_all_path_quality(&mut self) -> Result<()> {
        if self.paths.is_empty() {
            return Err(MultipathError::NoActivePaths);
        }

        let mut sampled = Vec::with_capacity(self.paths.len());
        for idx in 0..self.paths.len() {
            let current = self.paths[idx].metadata().await;
            let alive = self.paths[idx]
                .probe_path_alive(2_000)
                .await
                .unwrap_or(false);
            let rtt = if alive {
                self.paths[idx].probe_rtt().await.unwrap_or(current.rtt_ms)
            } else {
                current.rtt_ms.saturating_add(1_000)
            };
            let loss = if alive {
                (current.loss_rate * 0.9).clamp(0.0, 1.0)
            } else {
                1.0
            };
            sampled.push((idx, rtt, loss, alive));
        }

        for (idx, rtt, loss, alive) in sampled {
            self.update_path_quality(idx, rtt, loss).await?;
            self.paths[idx].update_metadata(|m| m.active = alive).await;
        }

        Ok(())
    }

    /// Background monitor that periodically updates path health.
    pub fn start_health_monitor(
        conn: Arc<Mutex<Self>>,
        interval_ms: u64,
    ) -> tokio::task::JoinHandle<()> {
        let interval = Duration::from_millis(interval_ms.max(100));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let mut guard = conn.lock().await;
                if let Err(err) = guard.update_all_path_quality().await {
                    tracing::debug!("health monitor update failed: {}", err);
                }
            }
        })
    }

    /// Send data with multipath framing and auto-incremented sequence.
    pub async fn send_sequenced(&self, path_idx: usize, data: &[u8]) -> Result<()> {
        let seq_num = self.next_seq();
        self.send_data_with_seq(path_idx, seq_num, data).await
    }

    /// Receive one data frame from a specific path.
    pub async fn recv_sequenced(&self, path_idx: usize) -> Result<(u64, Vec<u8>)> {
        for _ in 0..8 {
            match self.recv_parsed_frame(path_idx).await? {
                ParsedFrame::Data { header, payload } => {
                    return Ok((header.seq_num, payload));
                }
                ParsedFrame::Ack(ack) => {
                    self.process_ack(ack).await?;
                }
            }
        }

        Err(MultipathError::ReceiveTimeoutAllPaths)
    }

    /// Send ACK frame.
    pub async fn send_ack(&self, ack: AckFrame) -> Result<()> {
        let path_idx = ack.path_id as usize;
        if path_idx >= self.paths.len() {
            return Err(MultipathError::PathIndexOutOfBounds(path_idx));
        }

        let header = MultipathHeader {
            seq_num: self.next_seq(),
            path_id: ack.path_id,
            timestamp: Self::now_ms(),
            flags: FLAG_ACK,
        };
        let payload = ack.encode_payload();
        let mut frame = header.encode(payload.len() as u32);
        frame.extend_from_slice(&payload);
        self.send_raw_path(path_idx, &frame).await
    }

    /// Process cumulative + selective ACK.
    pub async fn process_ack(&self, ack: AckFrame) -> Result<()> {
        let mut inflight = self.inflight.lock().await;
        inflight.remove(&ack.acked_seq);

        for (byte_idx, byte) in ack.ack_bitmap.iter().enumerate() {
            for bit in 0..8u8 {
                if (byte & (1u8 << bit)) == 0 {
                    continue;
                }
                let offset = (byte_idx * 8 + bit as usize + 1) as u64;
                let seq = ack.acked_seq.saturating_sub(offset);
                inflight.remove(&seq);
            }
        }

        Ok(())
    }

    /// Generate ACK for received sequence.
    pub async fn generate_ack(&self, seq: u64) -> AckFrame {
        self.generate_ack_for_path(seq, self.primary_idx).await
    }

    async fn generate_ack_for_path(&self, seq: u64, path_idx: usize) -> AckFrame {
        let reorder = self.reorder.lock().await;
        let _gaps = reorder.get_gaps();
        AckFrame {
            acked_seq: seq,
            ack_bitmap: Vec::new(),
            path_id: Self::path_id(path_idx).unwrap_or(0),
            receive_time: Self::now_ms(),
        }
    }

    /// Send data using multipath coordination
    pub async fn send_multipath(&self, data: &[u8], routing: &RoutingPolicy) -> Result<()> {
        if self.paths.is_empty() {
            return Err(MultipathError::NoActivePaths);
        }

        // Single path optimization
        if self.paths.len() == 1 {
            return self.send_sequenced(0, data).await;
        }

        match self.scheduler {
            SchedulerPolicy::Redundant => match routing {
                RoutingPolicy::All => {
                    // Send same sequence on all active paths.
                    let seq_num = self.next_seq();
                    let mut futures = Vec::new();
                    for (idx, path) in self.paths.iter().enumerate() {
                        let meta = path.metadata().await;
                        if meta.active {
                            futures.push(self.send_data_with_seq(idx, seq_num, data));
                        }
                    }

                    let results = futures::future::join_all(futures).await;
                    if results.iter().any(|r| r.is_ok()) {
                        Ok(())
                    } else {
                        Err(MultipathError::AllPathsFailed(format!("{:?}", results)))
                    }
                }
                _ => {
                    // Default to primary
                    self.send_sequenced(self.primary_idx, data).await
                }
            },
            SchedulerPolicy::Split => self.send_split(data, routing).await,
        }
    }

    /// Split data using simple ratio distribution
    async fn send_split(&self, data: &[u8], routing: &RoutingPolicy) -> Result<()> {
        let primary_ratio = match routing {
            RoutingPolicy::Split { primary_ratio } => *primary_ratio,
            _ => 0.7, // Default 70/30 split
        };

        let primary_len = (data.len() as f32 * primary_ratio) as usize;
        let primary_chunk = &data[..primary_len.min(data.len())];
        let secondary_chunk = &data[primary_len.min(data.len())..];

        // Send primary chunk on primary path
        if !primary_chunk.is_empty() {
            self.send_sequenced(self.primary_idx, primary_chunk).await?;
        }

        // Send secondary chunk on best backup path
        if !secondary_chunk.is_empty() {
            if let Some(backup_idx) = self.find_best_backup_path().await {
                self.send_sequenced(backup_idx, secondary_chunk).await?;
            }
        }

        Ok(())
    }

    /// Find best backup path (lowest RTT, highest score)
    async fn find_best_backup_path(&self) -> Option<usize> {
        let mut best_idx = None;
        let mut best_score = 0.0;

        for (idx, path) in self.paths.iter().enumerate() {
            if idx == self.primary_idx {
                continue;
            }

            let meta = path.metadata().await;
            if !meta.active {
                continue;
            }

            let score = meta.score();
            if score > best_score {
                best_score = score;
                best_idx = Some(idx);
            }
        }

        best_idx
    }

    fn copy_payload_to_buf(path_idx: usize, payload: &[u8], buf: &mut [u8]) -> Result<usize> {
        if payload.len() > buf.len() {
            return Err(MultipathError::BufferTooSmall {
                path_idx,
                got: buf.len(),
                need: payload.len(),
            });
        }
        buf[..payload.len()].copy_from_slice(payload);
        Ok(payload.len())
    }

    /// Receive data from any path
    /// Receive data from any path
    pub async fn recv_multipath(&self, buf: &mut [u8]) -> Result<(usize, usize)> {
        // (bytes_received, path_index)
        if self.paths.is_empty() {
            return Err(MultipathError::NoActivePaths);
        }

        // Flush already re-ordered payload first.
        if let Some((payload, path_idx)) = self.ready_queue.lock().await.pop_front() {
            let n = Self::copy_payload_to_buf(path_idx, &payload, buf)?;
            return Ok((n, path_idx));
        }

        // Single path optimization
        if self.paths.len() == 1 {
            let (seq, payload) = self.recv_sequenced(0).await?;
            let ack = self.generate_ack_for_path(seq, 0).await;
            let _ = self.send_ack(ack).await;
            let n = Self::copy_payload_to_buf(0, &payload, buf)?;
            return Ok((n, 0));
        }

        // Try active paths in priority order. Repeat multiple rounds to allow
        // out-of-order frames to be buffered and then released when gaps close.
        let mut indices = (0..self.paths.len()).collect::<Vec<_>>();
        indices.sort_by_key(|idx| if *idx == self.primary_idx { 0 } else { 1 });

        for _round in 0..8 {
            for idx in indices.iter().copied() {
                let meta = self.paths[idx].metadata().await;
                if !meta.active {
                    continue;
                }

                let recv_result =
                    tokio::time::timeout(Duration::from_millis(500), self.recv_parsed_frame(idx))
                        .await;

                match recv_result {
                    Ok(Ok(ParsedFrame::Ack(ack))) => {
                        self.process_ack(ack).await?;
                        continue;
                    }
                    Ok(Ok(ParsedFrame::Data { header, payload })) => {
                        let ready = {
                            let mut reorder = self.reorder.lock().await;
                            reorder.insert(header.seq_num, payload)
                        };

                        let ack = self.generate_ack_for_path(header.seq_num, idx).await;
                        let _ = self.send_ack(ack).await;

                        if ready.is_empty() {
                            continue;
                        }

                        let mut iter = ready.into_iter();
                        if let Some(first) = iter.next() {
                            if iter.len() > 0 {
                                let mut queue = self.ready_queue.lock().await;
                                for chunk in iter {
                                    queue.push_back((chunk, idx));
                                }
                            }

                            let n = Self::copy_payload_to_buf(idx, &first, buf)?;
                            tracing::debug!(
                                "Received {} bytes from path {} seq {}",
                                n,
                                idx,
                                header.seq_num
                            );
                            return Ok((n, idx));
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("Receive failed on path {}: {}", idx, e);
                        continue;
                    }
                    Err(_) => {
                        tracing::debug!("Receive timeout on path {}", idx);
                        continue;
                    }
                }
            }

            if let Some((payload, path_idx)) = self.ready_queue.lock().await.pop_front() {
                let n = Self::copy_payload_to_buf(path_idx, &payload, buf)?;
                return Ok((n, path_idx));
            }
        }

        Err(MultipathError::ReceiveTimeoutAllPaths)
    }

    /// Graceful fallback: try multipath first then primary path only.
    pub async fn send_with_fallback(&self, data: &[u8]) -> Result<()> {
        let routing = match self.scheduler {
            SchedulerPolicy::Redundant => RoutingPolicy::All,
            SchedulerPolicy::Split => RoutingPolicy::Primary,
        };

        match self.send_multipath(data, &routing).await {
            Ok(()) => Ok(()),
            Err(err) => {
                tracing::warn!("multipath send failed, fallback to primary: {}", err);
                self.send_sequenced(self.primary_idx, data).await
            }
        }
    }

    /// Get number of active paths
    pub async fn active_paths(&self) -> usize {
        let mut count = 0;
        for path in &self.paths {
            let meta = path.metadata().await;
            if meta.active {
                count += 1;
            }
        }
        count
    }

    /// Get primary path index
    pub fn primary_path(&self) -> usize {
        self.primary_idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    #[test]
    fn test_scheduler_policy() {
        let policy = SchedulerPolicy::Redundant;
        assert_eq!(policy, SchedulerPolicy::Redundant);
    }

    #[test]
    fn test_header_roundtrip() {
        let h = MultipathHeader {
            seq_num: 42,
            path_id: 3,
            timestamp: 123_456,
            flags: FLAG_DATA,
        };
        let payload = b"hello";
        let mut frame = h.encode(payload.len() as u32);
        frame.extend_from_slice(payload);

        let (decoded, used) = MultipathHeader::decode(&frame).unwrap();
        assert_eq!(decoded.seq_num, 42);
        assert_eq!(decoded.path_id, 3);
        assert_eq!(decoded.flags, FLAG_DATA);
        assert_eq!(used, frame.len());
    }

    #[test]
    fn test_ack_roundtrip() {
        let ack = AckFrame {
            acked_seq: 88,
            ack_bitmap: vec![0b1010_0001, 0b0000_0011],
            path_id: 2,
            receive_time: 55,
        };
        let payload = ack.encode_payload();
        let decoded = AckFrame::decode_payload(2, &payload).unwrap();
        assert_eq!(decoded.acked_seq, 88);
        assert_eq!(decoded.path_id, 2);
        assert_eq!(decoded.ack_bitmap, ack.ack_bitmap);
    }

    #[test]
    fn test_reorder_buffer_orders_packets() {
        let mut reorder = ReorderBuffer::new(16);

        let ready = reorder.insert(2, b"c".to_vec());
        assert!(ready.is_empty());

        let ready = reorder.insert(0, b"a".to_vec());
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], b"a");

        let ready = reorder.insert(1, b"b".to_vec());
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0], b"b");
        assert_eq!(ready[1], b"c");
        assert_eq!(reorder.highest_contiguous_delivered(), 2);
    }

    #[tokio::test]
    async fn test_path_metadata_score() {
        let meta = PathMetadata {
            name: "test".to_string(),
            rtt_ms: 50,
            loss_rate: 0.0,
            active: true,
            created_at: std::time::Instant::now(),
        };

        let score = meta.score();
        assert!(score > 0.6); // Low RTT, no loss = high score
    }

    #[tokio::test]
    async fn test_multipath_basic() {
        let multi = MultipathConnection::new(SchedulerPolicy::Redundant, 50);
        assert_eq!(multi.active_paths().await, 0);
        assert_eq!(multi.primary_path(), 0);
    }

    #[tokio::test]
    async fn test_switch_primary_on_quality_improvement() {
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer_a: SocketAddr = sock_b.local_addr().unwrap();
        let peer_b: SocketAddr = sock_a.local_addr().unwrap();

        let mut multi = MultipathConnection::new(SchedulerPolicy::Redundant, 20);
        multi.add_path(
            Connection::Wan(sock_a, peer_a),
            PathMetadata {
                name: "primary".to_string(),
                rtt_ms: 120,
                loss_rate: 0.1,
                active: true,
                created_at: std::time::Instant::now(),
            },
        );
        multi.add_path(
            Connection::Wan(sock_b, peer_b),
            PathMetadata {
                name: "candidate".to_string(),
                rtt_ms: 110,
                loss_rate: 0.1,
                active: true,
                created_at: std::time::Instant::now(),
            },
        );

        assert_eq!(multi.primary_path(), 0);
        multi.update_path_quality(1, 70, 0.01).await.unwrap();
        assert_eq!(multi.primary_path(), 1);
    }

    #[tokio::test]
    async fn test_update_all_path_quality_keeps_best_primary() {
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer_a: SocketAddr = sock_b.local_addr().unwrap();
        let peer_b: SocketAddr = sock_a.local_addr().unwrap();

        let mut multi = MultipathConnection::new(SchedulerPolicy::Redundant, 20);
        multi.add_path(
            Connection::Wan(sock_a, peer_a),
            PathMetadata {
                name: "primary".to_string(),
                rtt_ms: 140,
                loss_rate: 0.2,
                active: true,
                created_at: std::time::Instant::now(),
            },
        );
        multi.add_path(
            Connection::Wan(sock_b, peer_b),
            PathMetadata {
                name: "candidate".to_string(),
                rtt_ms: 60,
                loss_rate: 0.01,
                active: true,
                created_at: std::time::Instant::now(),
            },
        );

        assert_eq!(multi.primary_path(), 0);
        multi.update_all_path_quality().await.unwrap();
        assert_eq!(multi.primary_path(), 1);
    }
    #[tokio::test]
    async fn test_send_recv_udp_path() {
        let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sender_addr = sender_sock.local_addr().unwrap();
        let receiver_addr = receiver_sock.local_addr().unwrap();

        let mut sender_multi = MultipathConnection::new(SchedulerPolicy::Redundant, 50);
        sender_multi.add_path(
            Connection::Wan(sender_sock, receiver_addr),
            PathMetadata::default(),
        );

        let mut receiver_multi = MultipathConnection::new(SchedulerPolicy::Redundant, 50);
        receiver_multi.add_path(
            Connection::Wan(receiver_sock, sender_addr),
            PathMetadata::default(),
        );

        sender_multi
            .send_multipath(b"hello-multipath", &RoutingPolicy::Primary)
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let (n, path_idx) = receiver_multi.recv_multipath(&mut buf).await.unwrap();

        assert_eq!(path_idx, 0);
        assert_eq!(&buf[..n], b"hello-multipath");
    }

    #[tokio::test]
    async fn test_sequence_increments() {
        let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver_addr = receiver_sock.local_addr().unwrap();

        let mut sender_multi = MultipathConnection::new(SchedulerPolicy::Redundant, 50);
        sender_multi.add_path(
            Connection::Wan(sender_sock, receiver_addr),
            PathMetadata::default(),
        );

        sender_multi.send_sequenced(0, b"one").await.unwrap();
        sender_multi.send_sequenced(0, b"two").await.unwrap();

        let inflight = sender_multi.inflight.lock().await;
        assert!(inflight.contains_key(&0));
        assert!(inflight.contains_key(&1));
    }
}
