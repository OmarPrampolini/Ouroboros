//! Pluggable Transports for DPI evasion
//!
//! Disguises P2P traffic as common protocols to bypass firewalls.

use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{info, warn};

use crate::config::PluggableTransportMode;

type AnyError = Box<dyn std::error::Error + Send + Sync + 'static>;
type Result<T> = std::result::Result<T, AnyError>;
const MAX_CHANNEL_FRAME_BYTES: usize = crate::crypto::MAX_CLEAR_PAYLOAD_BYTES;

fn any_error(msg: impl Into<String>) -> AnyError {
    std::io::Error::other(msg.into()).into()
}

fn validate_frame_len(len: usize, channel: &str) -> Result<()> {
    if len == 0 {
        return Err(any_error(format!("{} frame length is zero", channel)));
    }
    if len > MAX_CHANNEL_FRAME_BYTES {
        return Err(any_error(format!(
            "{} frame too large: {} > {}",
            channel, len, MAX_CHANNEL_FRAME_BYTES
        )));
    }
    Ok(())
}

pub mod http2_mimic;
pub mod mimicry;
pub mod quic_mimic;
pub mod real_tls;
pub mod ws_mimic;
pub use mimicry::{create_protocol, list_protocols, ProtocolMimicry};
pub use real_tls::{spki_hashes_base64_from_pem, spki_hashes_from_pem, RealTlsChannel};

/// DPI evasion modes
#[derive(Debug, Clone, PartialEq)]
pub enum DpiDisguise {
    None,            // Raw UDP
    HttpsLike,       // HTTPS-like TCP
    FtpData,         // FTP data channel
    DnsTunnel,       // DNS query tunnel
    RealTls(String), // Real TLS with domain
    WebSocket,       // WebSocket mimicry
    Quic,            // QUIC mimicry
}

impl From<PluggableTransportMode> for DpiDisguise {
    fn from(mode: PluggableTransportMode) -> Self {
        match mode {
            PluggableTransportMode::None => DpiDisguise::None,
            PluggableTransportMode::HttpsLike => DpiDisguise::HttpsLike,
            PluggableTransportMode::FtpData => DpiDisguise::FtpData,
            PluggableTransportMode::DnsTunnel => DpiDisguise::DnsTunnel,
            PluggableTransportMode::RealTls(d) => DpiDisguise::RealTls(d),
            PluggableTransportMode::WebSocket => DpiDisguise::WebSocket,
            PluggableTransportMode::Quic => DpiDisguise::Quic,
        }
    }
}

/// Wrapper Pluggable Transport
pub struct PluggableTransport {
    disguise: DpiDisguise,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl PluggableTransport {
    pub fn new(disguise: DpiDisguise, local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            disguise,
            local_addr: local,
            remote_addr: remote,
        }
    }

    pub async fn connect(&self) -> Result<Box<dyn TransportChannel>> {
        match &self.disguise {
            DpiDisguise::None => {
                let sock = UdpSocket::bind(self.local_addr).await?;
                sock.connect(self.remote_addr).await?;
                Ok(Box::new(UdpChannel { socket: sock }))
            }
            DpiDisguise::HttpsLike => {
                let conn = TcpStream::connect(self.remote_addr).await?;
                let mut channel = HttpsLikeChannel::new(conn)?;
                channel.perform_client_handshake().await?;
                info!("HTTPS-like connection");
                Ok(Box::new(channel))
            }
            DpiDisguise::FtpData => {
                let conn = TcpStream::connect(self.remote_addr).await?;
                let mut channel = FtpDataChannel::new(conn);
                channel.perform_client_handshake().await?;
                info!("FTP connection");
                Ok(Box::new(channel))
            }
            DpiDisguise::DnsTunnel => {
                let sock = UdpSocket::bind(self.local_addr).await?;
                sock.connect(self.remote_addr).await?;
                Ok(Box::new(DnsTunnelChannel::new(sock)))
            }
            DpiDisguise::RealTls(domain) => {
                let mut channel = RealTlsChannel::new(Arc::<str>::from(domain.as_str()));
                channel.establish(self.remote_addr.to_string()).await?;
                info!("Real TLS connection (SNI: {})", domain);
                Ok(Box::new(channel))
            }
            DpiDisguise::WebSocket => {
                let mut conn = TcpStream::connect(self.remote_addr).await?;
                let mut protocol = ws_mimic::WebSocketMimic::new();
                protocol.establish(&mut conn).await?;
                info!("WebSocket mimicry established");
                Ok(Box::new(ProtocolMimicChannel {
                    stream: conn,
                    protocol: Box::new(protocol),
                    buffer: Vec::new(),
                }))
            }
            DpiDisguise::Quic => {
                let mut conn = TcpStream::connect(self.remote_addr).await?;
                let mut protocol = quic_mimic::QuicMimic::new(quic_mimic::QuicVersion::Q050)?;
                protocol.establish(&mut conn).await?;
                info!("QUIC mimicry established");
                Ok(Box::new(ProtocolMimicChannel {
                    stream: conn,
                    protocol: Box::new(protocol),
                    buffer: Vec::new(),
                }))
            }
        }
    }

    /// Create with RealTls disguise using domain from config or random
    pub fn new_real_tls(
        cfg: &crate::config::Config,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Self {
        let domain = if let crate::config::PluggableTransportMode::RealTls(ref d) =
            cfg.pluggable_transport
        {
            d.clone()
        } else if !cfg.pluggable_tls_domains.is_empty() {
            use rand::seq::SliceRandom;
            cfg.pluggable_tls_domains
                .choose(&mut rand::thread_rng())
                .cloned()
                .unwrap_or_else(|| "www.cloudflare.com".to_string())
        } else {
            "www.cloudflare.com".to_string()
        };

        Self {
            disguise: DpiDisguise::RealTls(domain),
            local_addr: local,
            remote_addr: remote,
        }
    }

    /// Create with WebSocket mimicry
    pub fn new_websocket(local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            disguise: DpiDisguise::WebSocket,
            local_addr: local,
            remote_addr: remote,
        }
    }

    /// Create with QUIC mimicry
    pub fn new_quic(local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            disguise: DpiDisguise::Quic,
            local_addr: local,
            remote_addr: remote,
        }
    }

    /// Create based on config (detects WebSocket/Quic modes)
    pub fn from_config(cfg: &crate::config::Config, local: SocketAddr, remote: SocketAddr) -> Self {
        match cfg.pluggable_transport {
            crate::config::PluggableTransportMode::None => {
                Self::new(DpiDisguise::None, local, remote)
            }
            crate::config::PluggableTransportMode::HttpsLike => {
                Self::new(DpiDisguise::HttpsLike, local, remote)
            }
            crate::config::PluggableTransportMode::FtpData => {
                Self::new(DpiDisguise::FtpData, local, remote)
            }
            crate::config::PluggableTransportMode::DnsTunnel => {
                Self::new(DpiDisguise::DnsTunnel, local, remote)
            }
            crate::config::PluggableTransportMode::RealTls(ref d) => {
                Self::new(DpiDisguise::RealTls(d.clone()), local, remote)
            }
            crate::config::PluggableTransportMode::WebSocket => Self::new_websocket(local, remote),
            crate::config::PluggableTransportMode::Quic => Self::new_quic(local, remote),
        }
    }
}

/// Transport channel trait
/// Transport channel trait
#[async_trait::async_trait]
pub trait TransportChannel: Send + Sync {
    async fn read_message(&mut self) -> Result<Vec<u8>>;
    async fn write_message(&mut self, data: &[u8]) -> Result<()>;
}

// UDP raw channel
struct UdpChannel {
    socket: UdpSocket,
}

#[async_trait::async_trait]
impl TransportChannel for UdpChannel {
    async fn read_message(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 65536];
        let n = self.socket.recv(&mut buf).await?;
        Ok(buf[..n].to_vec())
    }

    async fn write_message(&mut self, data: &[u8]) -> Result<()> {
        self.socket.send(data).await?;
        Ok(())
    }
}

// HTTPS-like channel (TCP + fake TLS)

// Protocol mimicry channel (WebSocket, QUIC, etc.)
#[allow(dead_code)]
pub struct ProtocolMimicChannel {
    stream: TcpStream,
    protocol: Box<dyn crate::transport::pluggable::mimicry::ProtocolMimicry>,
    buffer: Vec<u8>,
}

#[async_trait::async_trait]
impl TransportChannel for ProtocolMimicChannel {
    async fn read_message(&mut self) -> Result<Vec<u8>> {
        if self.buffer.is_empty() {
            self.buffer.resize(64 * 1024, 0u8);
        }
        let n = self
            .protocol
            .recv(&mut self.stream, &mut self.buffer)
            .await?;
        Ok(self.buffer[..n].to_vec())
    }

    async fn write_message(&mut self, data: &[u8]) -> Result<()> {
        self.protocol.send(&mut self.stream, data).await?;
        Ok(())
    }
}

pub struct HttpsLikeChannel {
    stream: TcpStream,
}

impl HttpsLikeChannel {
    pub fn new(stream: TcpStream) -> Result<Self> {
        Ok(Self { stream })
    }

    pub async fn perform_client_handshake(&mut self) -> Result<()> {
        let fake_hello = build_fake_tls_client_hello();
        self.stream.write_all(&fake_hello).await?;

        let mut response = [0u8; 1024];
        let n = self.stream.read(&mut response).await?;
        if n < 100 {
            return Err(any_error("Invalid TLS response"));
        }
        Ok(())
    }

    pub async fn perform_server_handshake(&mut self) -> Result<()> {
        let mut buf = [0u8; 1024];
        let n = self.stream.read(&mut buf).await?;
        if n < 100 {
            return Err(any_error("Invalid TLS ClientHello"));
        }

        let fake_hello = build_fake_tls_server_hello();
        self.stream.write_all(&fake_hello).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl TransportChannel for HttpsLikeChannel {
    async fn read_message(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        validate_frame_len(len, "https_like")?;

        let mut msg = vec![0u8; len];
        self.stream.read_exact(&mut msg).await?;
        Ok(msg)
    }

    async fn write_message(&mut self, data: &[u8]) -> Result<()> {
        validate_frame_len(data.len(), "https_like")?;
        let len = data.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }
}

// FTP data channel
pub struct FtpDataChannel {
    stream: TcpStream,
}

impl FtpDataChannel {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    pub async fn perform_client_handshake(&mut self) -> Result<()> {
        self.stream.write_all(b"PASV\r\n").await?;
        Ok(())
    }

    pub async fn perform_server_handshake(&mut self) -> Result<()> {
        let mut buf = [0u8; 1024];
        let n = self.stream.read(&mut buf).await?;
        if &buf[..n] != b"PASV\r\n" {
            return Err(any_error("Invalid FTP handshake"));
        }

        let response = b"227 Entering Passive Mode (192,168,1,100,117,48)\r\n";
        self.stream.write_all(response).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl TransportChannel for FtpDataChannel {
    async fn read_message(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        validate_frame_len(len, "ftp_data")?;

        let mut msg = vec![0u8; len];
        self.stream.read_exact(&mut msg).await?;
        Ok(msg)
    }

    async fn write_message(&mut self, data: &[u8]) -> Result<()> {
        validate_frame_len(data.len(), "ftp_data")?;
        let len = data.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }
}

/// DNS Tunneling Constants for multi-label fragmentation
const CHUNK_HEADER_SIZE: usize = 3; // [total_chunks][chunk_index][crc8]
const MAX_LABEL_SIZE: usize = 63; // DNS single label limit
const MAX_CHUNK_PAYLOAD: usize = MAX_LABEL_SIZE - CHUNK_HEADER_SIZE; // 60 bytes

/// Fragmented message in reconstruction
#[derive(Debug)]
#[allow(dead_code)]
struct FragmentedMessage {
    total_chunks: u8,
    received_chunks: u8,
    data: Vec<u8>,
    last_update: Instant,
}

impl FragmentedMessage {
    fn new(total_chunks: u8) -> Self {
        Self {
            total_chunks,
            received_chunks: 0,
            data: vec![0u8; total_chunks as usize * MAX_CHUNK_PAYLOAD],
            last_update: Instant::now(),
        }
    }

    #[allow(dead_code)]
    fn is_complete(&self) -> bool {
        self.received_chunks == self.total_chunks
    }

    #[allow(dead_code)]
    fn trim_to_actual_size(&self) -> Vec<u8> {
        let total_len = self.data.len();
        let mut trimmed = self.data.clone();
        trimmed.truncate(total_len);
        trimmed
    }
}

/// Divide data into labeled chunks for DNS multi-label transmission
fn fragment_data(data: &[u8]) -> Vec<Vec<u8>> {
    let total_chunks = data.len().div_ceil(MAX_CHUNK_PAYLOAD) as u8;
    let mut chunks = Vec::new();

    for (i, chunk) in data.chunks(MAX_CHUNK_PAYLOAD).enumerate() {
        let mut labeled = Vec::with_capacity(CHUNK_HEADER_SIZE + chunk.len());
        labeled.push(total_chunks);
        labeled.push(i as u8);
        labeled.push(crc8(chunk));
        labeled.extend_from_slice(chunk);
        chunks.push(labeled);
    }

    chunks
}

/// Reconstruct data from DNS multi-label response
fn defragment_data(labels: &[&[u8]]) -> Result<Vec<u8>> {
    if labels.is_empty() {
        return Err(any_error("No data labels"));
    }

    // Read header from first label
    if labels[0].len() < CHUNK_HEADER_SIZE {
        return Err(any_error("Invalid label header"));
    }

    let total_chunks = labels[0][0];
    let mut chunks: Vec<Option<&[u8]>> = vec![None; total_chunks as usize];

    for label in labels {
        if label.len() < CHUNK_HEADER_SIZE + 1 {
            continue;
        }

        let chunk_total = label[0];
        let chunk_idx = label[1] as usize;
        let checksum = label[2];
        let payload = &label[CHUNK_HEADER_SIZE..];

        if chunk_total != total_chunks {
            return Err(any_error("Mismatched chunk total"));
        }

        if chunk_idx >= total_chunks as usize {
            continue;
        }

        // Verify checksum
        if crc8(payload) != checksum {
            warn!("DNS chunk {} failed checksum verification", chunk_idx);
            continue;
        }

        chunks[chunk_idx] = Some(payload);
    }

    // Check all chunks received
    let mut data = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        match chunk {
            Some(payload) => data.extend_from_slice(payload),
            None => return Err(any_error(format!("Missing chunk {}", i))),
        }
    }

    Ok(data)
}

/// Simple CRC8 for integrity checking
fn crc8(data: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &byte in data {
        crc = crc.wrapping_add(byte);
    }
    crc
}

// DNS tunneling channel
pub struct DnsTunnelChannel {
    socket: UdpSocket,
    query_id: u16,
    recv_buffer: HashMap<u16, FragmentedMessage>, // query_id -> partial message
}

impl DnsTunnelChannel {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            query_id: rand::random::<u16>(),
            recv_buffer: HashMap::new(),
        }
    }

    async fn cleanup_old_fragments(&mut self) {
        let now = Instant::now();
        self.recv_buffer
            .retain(|_, msg| now.duration_since(msg.last_update) < Duration::from_secs(30));
    }

    async fn store_fragment(&mut self, query_id: u16, labels: Vec<&[u8]>) -> Result<()> {
        if labels.is_empty() || labels[0].len() < CHUNK_HEADER_SIZE {
            return Ok(());
        }

        let total_chunks = labels[0][0];
        let chunk_idx = labels[0][1] as usize;
        let payload = &labels[0][CHUNK_HEADER_SIZE..];

        let entry = self
            .recv_buffer
            .entry(query_id)
            .or_insert_with(|| FragmentedMessage::new(total_chunks));

        // Copy chunk to correct position
        let offset = chunk_idx * MAX_CHUNK_PAYLOAD;
        if offset + payload.len() <= entry.data.len() {
            entry.data[offset..offset + payload.len()].copy_from_slice(payload);
            entry.received_chunks += 1;
            entry.last_update = Instant::now();
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl TransportChannel for DnsTunnelChannel {
    async fn read_message(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 512];

        // Read with timeout
        let n = match tokio::time::timeout(Duration::from_secs(5), self.socket.recv(&mut buf)).await
        {
            Ok(result) => result?,
            Err(_) => return Err(any_error("DNS response timeout")),
        };

        if n < 12 {
            return Err(any_error(format!("DNS packet too short ({} < 12)", n)));
        }

        // Parse DNS header
        let query_id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let questions = u16::from_be_bytes([buf[4], buf[5]]);

        // Verify it's a valid response
        if (flags & 0x8000) == 0 {
            return Err(any_error(format!(
                "Not a DNS response (flags={:#06x})",
                flags
            )));
        }
        if questions == 0 {
            return Err(any_error("No questions in DNS response"));
        }

        // Parse questions to extract labels (skip name compression for now)
        let mut offset = 12;
        let mut labels = Vec::new();

        while offset < buf.len() && buf[offset] != 0 {
            let label_len = buf[offset] as usize;
            offset += 1;

            if offset + label_len > buf.len() {
                return Err(any_error(format!(
                    "Invalid label length at offset {}",
                    offset
                )));
            }

            labels.push(&buf[offset..offset + label_len]);
            offset += label_len;
        }

        if labels.is_empty() {
            return Err(any_error("No labels found in DNS packet"));
        }

        // Attempt defragmentation
        match defragment_data(&labels) {
            Ok(data) => {
                self.cleanup_old_fragments().await;
                Ok(data)
            }
            Err(e) => {
                // Check if it's a partial message
                if e.to_string().contains("Missing chunk") {
                    self.store_fragment(query_id, labels).await?;
                    return Err(any_error(format!(
                        "Partial DNS message, waiting for more chunks: {}",
                        e
                    )));
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn write_message(&mut self, data: &[u8]) -> Result<()> {
        let chunks = fragment_data(data);

        if chunks.is_empty() {
            return Err(any_error("No data to send"));
        }

        for (i, labeled_chunk) in chunks.iter().enumerate() {
            let mut packet = Vec::with_capacity(12 + labeled_chunk.len() + 2);

            // DNS Header
            packet.extend_from_slice(&self.query_id.to_be_bytes());
            packet.extend_from_slice(&[0x01, 0x00]); // Flags: standard query
            packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
            packet.extend_from_slice(&[0x00, 0x00]); // Answers
            packet.extend_from_slice(&[0x00, 0x00]); // Authority
            packet.extend_from_slice(&[0x00, 0x00]); // Additional

            // Domain name: single label with chunk data
            packet.push(labeled_chunk.len() as u8);
            packet.extend_from_slice(labeled_chunk);

            // QTYPE = TXT (0x0010), QCLASS = IN (0x0001)
            packet.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]);

            self.socket.send(&packet).await?;

            // Increment query_id for each chunk
            self.query_id = self.query_id.wrapping_add(1);

            // Small delay between chunks to avoid overwhelming (optional)
            if i < chunks.len() - 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        Ok(())
    }
}

// Build fake TLS messages
fn build_fake_tls_handshake(handshake_type: u8, payload_len: usize) -> Vec<u8> {
    let record_payload_len = 4 + payload_len;
    let mut hello = Vec::with_capacity(5 + record_payload_len);
    hello.push(0x16);
    hello.push(0x03);
    hello.push(0x03);
    hello.extend_from_slice(&(record_payload_len as u16).to_be_bytes());
    hello.push(handshake_type);
    hello.push(((payload_len >> 16) & 0xff) as u8);
    hello.push(((payload_len >> 8) & 0xff) as u8);
    hello.push((payload_len & 0xff) as u8);

    let mut payload = vec![0u8; payload_len];
    rand::rngs::OsRng.fill_bytes(&mut payload);
    hello.extend_from_slice(&payload);
    hello
}

fn build_fake_tls_client_hello() -> Vec<u8> {
    build_fake_tls_handshake(0x01, 140)
}

fn build_fake_tls_server_hello() -> Vec<u8> {
    build_fake_tls_handshake(0x02, 140)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn test_https_handshake() {
        let client_hello = build_fake_tls_client_hello();
        assert!(client_hello.len() > 100);
        assert_eq!(client_hello[0], 0x16); // Handshake
    }

    #[tokio::test]
    async fn test_https_channel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let mut ch = HttpsLikeChannel::new(conn).unwrap();
            ch.perform_server_handshake().await.unwrap();
            ch
        });

        let client = tokio::spawn(async move {
            let conn = TcpStream::connect(addr).await.unwrap();
            let mut ch = HttpsLikeChannel::new(conn).unwrap();
            ch.perform_client_handshake().await.unwrap();
            ch
        });

        let (s, c) = tokio::join!(server, client);
        let mut server_ch = s.unwrap();
        let mut client_ch = c.unwrap();

        client_ch.write_message(b"test").await.unwrap();
        let msg = server_ch.read_message().await.unwrap();
        assert_eq!(msg, b"test");
    }
}
