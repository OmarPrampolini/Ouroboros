//! STUN client for public endpoint discovery and basic hole punching.
//!
//! RFC 5389 Binding Request/Response (XOR-MAPPED-ADDRESS).

use rand::RngCore;
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::network_telemetry;
use crate::transport::nat_detection::{NatDetector, NatType};

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const DEFAULT_TIMEOUT_MS: u64 = 3000;

#[derive(Debug, Error)]
pub enum StunError {
    #[error("address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("No STUN servers configured")]
    NoServersConfigured,
    #[error("STUN discovery failed: all servers exhausted")]
    DiscoveryFailedExhausted,
    #[error("hole punch recv failed: {0}")]
    HolePunchRecv(String),
    #[error("hole punch timeout")]
    HolePunchTimeout,
    #[error("STUN response too short")]
    ResponseTooShort,
    #[error("Not a STUN Binding Response")]
    NotBindingResponse,
    #[error("STUN response truncated")]
    ResponseTruncated,
    #[error("No XOR-MAPPED-ADDRESS found in STUN response")]
    NoXorMappedAddress,
}

type Result<T> = std::result::Result<T, StunError>;

#[derive(Debug, Clone, Copy, Default)]
struct StunServerStat {
    successes: u64,
    failures: u64,
    total_rtt_ms: u64,
    last_rtt_ms: u64,
    last_used_ms: u64,
}

impl StunServerStat {
    fn avg_rtt_ms(&self) -> u64 {
        if self.successes == 0 {
            self.last_rtt_ms
        } else {
            self.total_rtt_ms / self.successes
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StunServerScore {
    pub addr: String,
    pub success_count: u64,
    pub fail_count: u64,
    pub avg_rtt_ms: u64,
    pub last_rtt_ms: u64,
    pub last_used_ms: u64,
    pub score: i64,
}

type ServerStatsCache = Arc<Mutex<HashMap<SocketAddr, StunServerStat>>>;
static STUN_SERVER_STATS: OnceLock<ServerStatsCache> = OnceLock::new();

fn server_stats() -> ServerStatsCache {
    STUN_SERVER_STATS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

fn score_server(server: &SocketAddr, stats: &HashMap<SocketAddr, StunServerStat>) -> i64 {
    match stats.get(server) {
        Some(s) => {
            let success_bias = (s.successes as i64) * 25;
            let failure_penalty = (s.failures as i64) * 20;
            let rtt_penalty = (s.avg_rtt_ms().min(3000) as i64) / 25;
            let freshness_penalty = if s.last_used_ms == 0 {
                30
            } else {
                let age_ms = network_telemetry::now_ms().saturating_sub(s.last_used_ms);
                (age_ms.min(300_000) / 10_000) as i64
            };
            success_bias - failure_penalty - rtt_penalty - freshness_penalty
        }
        None => 0,
    }
}

pub async fn stun_server_scores_snapshot() -> Vec<StunServerScore> {
    let cache = server_stats();
    let stats = cache.lock().await;
    let mut out: Vec<StunServerScore> = stats
        .iter()
        .map(|(addr, s)| StunServerScore {
            addr: addr.to_string(),
            success_count: s.successes,
            fail_count: s.failures,
            avg_rtt_ms: s.avg_rtt_ms(),
            last_rtt_ms: s.last_rtt_ms,
            last_used_ms: s.last_used_ms,
            score: score_server(addr, &stats),
        })
        .collect();
    out.sort_by(|a, b| b.score.cmp(&a.score));
    out
}

pub struct StunClient {
    servers: Vec<SocketAddr>,
    timeout_ms: u64,
}

#[derive(Debug, Clone)]
pub struct StunDiscovery {
    pub public_addr: SocketAddr,
    pub nat_type: NatType,
    pub server_used: SocketAddr,
    pub socket: Arc<UdpSocket>,
}

impl StunClient {
    pub fn new(servers: Vec<String>) -> Result<Self> {
        let mut parsed = Vec::new();
        for s in servers {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            let addr: SocketAddr = s.parse()?;
            parsed.push(addr);
        }
        if parsed.is_empty() {
            return Err(StunError::NoServersConfigured);
        }
        Ok(Self {
            servers: parsed,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        })
    }

    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms.max(100);
        self
    }

    async fn ranked_servers(&self) -> Vec<SocketAddr> {
        let cache = server_stats();
        let stats = cache.lock().await;
        let mut ranked = self.servers.clone();
        ranked.sort_by(|a, b| {
            let sa = score_server(a, &stats);
            let sb = score_server(b, &stats);
            sb.cmp(&sa)
        });
        ranked
    }

    async fn mark_server_success(&self, server: SocketAddr, rtt_ms: u64) {
        let cache = server_stats();
        let mut stats = cache.lock().await;
        let entry = stats.entry(server).or_default();
        entry.successes = entry.successes.saturating_add(1);
        entry.total_rtt_ms = entry.total_rtt_ms.saturating_add(rtt_ms);
        entry.last_rtt_ms = rtt_ms;
        entry.last_used_ms = network_telemetry::now_ms();
    }

    async fn mark_server_failure(&self, server: SocketAddr) {
        let cache = server_stats();
        let mut stats = cache.lock().await;
        let entry = stats.entry(server).or_default();
        entry.failures = entry.failures.saturating_add(1);
        entry.last_used_ms = network_telemetry::now_ms();
    }

    pub async fn discover(&self, local_port: u16) -> Result<StunDiscovery> {
        let ranked_servers = self.ranked_servers().await;

        for server in ranked_servers {
            let bind_addr = if server.is_ipv6() {
                SocketAddr::from(([0u16; 8], local_port))
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_port)
            };
            let sock = match UdpSocket::bind(bind_addr).await {
                Ok(s) => s,
                Err(_) => UdpSocket::bind("0.0.0.0:0").await?,
            };
            let sock = Arc::new(sock);

            let tx_id = random_tx_id();
            let req = build_binding_request(tx_id);
            sock.send_to(&req, server).await?;

            let mut buf = vec![0u8; 512];
            let start = Instant::now();
            let (n, from) = match tokio::time::timeout(
                Duration::from_millis(self.timeout_ms),
                sock.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    self.mark_server_failure(server).await;
                    tracing::warn!("STUN recv error from {}: {}", server, e);
                    continue;
                }
                Err(_) => {
                    self.mark_server_failure(server).await;
                    tracing::warn!("STUN timeout for {}", server);
                    continue;
                }
            };

            if from != server {
                self.mark_server_failure(server).await;
                tracing::warn!("STUN response from unexpected server {}", from);
                continue;
            }

            let public_addr = match parse_xor_mapped_address(&buf[..n], &tx_id) {
                Ok(addr) => addr,
                Err(e) => {
                    self.mark_server_failure(server).await;
                    tracing::warn!("STUN parse error from {}: {}", server, e);
                    continue;
                }
            };

            self.mark_server_success(server, start.elapsed().as_millis() as u64)
                .await;

            let nat_type = if self.servers.len() >= 2 {
                let detector =
                    NatDetector::new(self.servers.iter().map(|s| s.to_string()).collect());
                detector
                    .detect_nat_profile()
                    .await
                    .map(|p| p.nat_type)
                    .unwrap_or(NatType::Unknown)
            } else {
                NatType::Unknown
            };

            return Ok(StunDiscovery {
                public_addr,
                nat_type,
                server_used: server,
                socket: sock,
            });
        }

        network_telemetry::record_fallback_event(
            "stun",
            "discovery_exhausted",
            Some("all servers failed".to_string()),
        );
        Err(StunError::DiscoveryFailedExhausted)
    }

    pub async fn hole_punch(
        &self,
        my_public: SocketAddr,
        peer_public: SocketAddr,
    ) -> Result<UdpSocket> {
        let sock = UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            my_public.port(),
        ))
        .await?;
        sock.connect(peer_public).await?;

        let burst = 5usize;
        for i in 0..burst {
            let payload = build_probe_payload();
            let _ = sock.send(&payload).await;
            if i + 1 < burst {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        let mut buf = vec![0u8; 1500];
        match tokio::time::timeout(Duration::from_millis(self.timeout_ms), sock.recv(&mut buf))
            .await
        {
            Ok(Ok(_n)) => Ok(sock),
            Ok(Err(e)) => Err(StunError::HolePunchRecv(e.to_string())),
            Err(_) => Err(StunError::HolePunchTimeout),
        }
    }

    pub async fn hole_punch_with_socket(
        &self,
        sock: Arc<UdpSocket>,
        peer_public: SocketAddr,
    ) -> Result<Arc<UdpSocket>> {
        sock.connect(peer_public).await?;

        let burst = 5usize;
        for i in 0..burst {
            let payload = build_probe_payload();
            let _ = sock.send(&payload).await;
            if i + 1 < burst {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        let mut buf = vec![0u8; 1500];
        match tokio::time::timeout(Duration::from_millis(self.timeout_ms), sock.recv(&mut buf))
            .await
        {
            Ok(Ok(_n)) => Ok(sock),
            Ok(Err(e)) => Err(StunError::HolePunchRecv(e.to_string())),
            Err(_) => Err(StunError::HolePunchTimeout),
        }
    }
}

fn random_tx_id() -> [u8; 12] {
    let mut tx_id = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut tx_id);
    tx_id
}

fn build_binding_request(tx_id: [u8; 12]) -> Vec<u8> {
    let mut req = vec![0u8; 20];
    // Message Type: Binding Request (0x0001)
    req[0] = 0x00;
    req[1] = 0x01;
    // Message Length: 0
    req[2] = 0x00;
    req[3] = 0x00;
    // Magic Cookie
    req[4] = 0x21;
    req[5] = 0x12;
    req[6] = 0xa4;
    req[7] = 0x42;
    // Transaction ID
    req[8..20].copy_from_slice(&tx_id);
    req
}

fn parse_xor_mapped_address(response: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr> {
    if response.len() < 20 {
        return Err(StunError::ResponseTooShort);
    }
    if response[0] != 0x01 || response[1] != 0x01 {
        return Err(StunError::NotBindingResponse);
    }

    let message_len = u16::from_be_bytes([response[2], response[3]]) as usize;
    if response.len() < 20 + message_len {
        return Err(StunError::ResponseTruncated);
    }

    let mut offset = 20;
    while offset + 4 <= response.len() {
        let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let attr_len = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
        let padded_len = attr_len.div_ceil(4) * 4;

        if (attr_type == 0x0020 || attr_type == 0x0001)
            && offset + 4 + attr_len <= response.len()
            && attr_len >= 8
        {
            let family = response[offset + 5];
            if family == 0x01 {
                let port = u16::from_be_bytes([response[offset + 6], response[offset + 7]]);
                let ip = Ipv4Addr::new(
                    response[offset + 8],
                    response[offset + 9],
                    response[offset + 10],
                    response[offset + 11],
                );

                let (port, ip) = if attr_type == 0x0020 {
                    let xored_port = port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                    let xored_ip = Ipv4Addr::new(
                        ip.octets()[0] ^ ((STUN_MAGIC_COOKIE >> 24) as u8),
                        ip.octets()[1] ^ ((STUN_MAGIC_COOKIE >> 16) as u8),
                        ip.octets()[2] ^ ((STUN_MAGIC_COOKIE >> 8) as u8),
                        ip.octets()[3] ^ (STUN_MAGIC_COOKIE as u8),
                    );
                    (xored_port, xored_ip)
                } else {
                    (port, ip)
                };

                return Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)));
            } else if family == 0x02 && attr_len >= 20 {
                let port = u16::from_be_bytes([response[offset + 6], response[offset + 7]]);
                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&response[offset + 8..offset + 24]);

                if attr_type == 0x0020 {
                    // XOR with magic cookie + transaction ID
                    let mut xor_bytes = [0u8; 16];
                    xor_bytes[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                    xor_bytes[4..].copy_from_slice(tx_id);
                    for i in 0..16 {
                        addr_bytes[i] ^= xor_bytes[i];
                    }
                }

                let port = if attr_type == 0x0020 {
                    port ^ ((STUN_MAGIC_COOKIE >> 16) as u16)
                } else {
                    port
                };

                let ip = std::net::Ipv6Addr::from(addr_bytes);
                return Ok(SocketAddr::new(IpAddr::V6(ip), port));
            }
        }

        offset += 4 + padded_len;
    }

    Err(StunError::NoXorMappedAddress)
}

fn build_probe_payload() -> Vec<u8> {
    let mut v = Vec::with_capacity(128);
    v.extend_from_slice(b"HS-STUN-PUNCH");
    v.resize(128, 0u8);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_score_prefers_success_and_low_rtt() {
        let a: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:3479".parse().unwrap();

        let mut stats = HashMap::new();
        stats.insert(
            a,
            StunServerStat {
                successes: 10,
                failures: 1,
                total_rtt_ms: 400,
                last_rtt_ms: 40,
                last_used_ms: 0,
            },
        );
        stats.insert(
            b,
            StunServerStat {
                successes: 1,
                failures: 6,
                total_rtt_ms: 500,
                last_rtt_ms: 500,
                last_used_ms: 0,
            },
        );

        assert!(score_server(&a, &stats) > score_server(&b, &stats));
    }
}
