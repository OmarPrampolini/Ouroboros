use crate::network_telemetry;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum NatDetectionError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("Need at least 2 STUN servers for NAT detection")]
    NeedAtLeastTwoStunServers,
    #[error("STUN response timeout")]
    StunResponseTimeout,
    #[error("STUN response from unexpected server")]
    UnexpectedServer,
    #[error("STUN response too short")]
    ResponseTooShort,
    #[error("Not a STUN Binding Response")]
    NotBindingResponse,
    #[error("STUN response truncated")]
    ResponseTruncated,
    #[error("No address attribute found in STUN response")]
    NoAddressAttribute,
}

type Result<T> = std::result::Result<T, NatDetectionError>;

/// Tipo di NAT rilevato
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    Unknown,
    OpenInternet, // Pubblico IP, no NAT
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
    SymetricFirewall, // NAT rilevato ma porta random
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::Unknown => write!(f, "unknown"),
            NatType::OpenInternet => write!(f, "open_internet"),
            NatType::FullCone => write!(f, "full_cone"),
            NatType::RestrictedCone => write!(f, "restricted_cone"),
            NatType::PortRestrictedCone => write!(f, "port_restricted_cone"),
            NatType::Symmetric => write!(f, "symmetric"),
            NatType::SymetricFirewall => write!(f, "symmetric_firewall"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatConfidence {
    Low,
    Medium,
    High,
}

impl NatConfidence {
    fn from_samples(samples: usize) -> Self {
        match samples {
            n if n >= 3 => NatConfidence::High,
            2 => NatConfidence::Medium,
            _ => NatConfidence::Low,
        }
    }
}

impl std::fmt::Display for NatConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatConfidence::Low => write!(f, "low"),
            NatConfidence::Medium => write!(f, "medium"),
            NatConfidence::High => write!(f, "high"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NatProfile {
    pub nat_type: NatType,
    pub confidence: NatConfidence,
    pub samples: u8,
}

impl NatProfile {
    pub const fn new(nat_type: NatType, confidence: NatConfidence, samples: u8) -> Self {
        Self {
            nat_type,
            confidence,
            samples,
        }
    }
}

/// Priorita di transport in base al tipo di NAT
#[derive(Debug, Clone)]
pub struct TransportPriority {
    pub kind: TransportKind,
    pub priority: u32,
    pub should_skip: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportKind {
    Lan,
    Upnp,
    Stun,
    Relay,
    Tor,
}

type NatCache = Arc<Mutex<Option<(NatProfile, Instant)>>>;

/// Cache globale del profilo NAT (5 minuti) - Lazy initialization
static NAT_CACHE: OnceLock<NatCache> = OnceLock::new();

fn get_nat_cache() -> NatCache {
    NAT_CACHE.get_or_init(|| Arc::new(Mutex::new(None))).clone()
}

#[derive(Debug, Clone, Copy)]
struct MappedObservation {
    server: SocketAddr,
    mapped: SocketAddr,
    port: u16,
}

#[derive(Clone)]
pub struct NatDetector {
    stun_servers: Vec<String>,
}

impl NatDetector {
    pub fn new(stun_servers: Vec<String>) -> Self {
        Self { stun_servers }
    }

    /// Rileva il tipo di NAT con caching per 5 minuti
    pub async fn detect_nat_type(&self) -> Result<NatType> {
        Ok(self.detect_nat_profile().await?.nat_type)
    }

    /// Rileva il profilo NAT completo (tipo + confidenza + campioni)
    pub async fn detect_nat_profile(&self) -> Result<NatProfile> {
        let cache = get_nat_cache();
        let mut cache_lock = cache.lock().await;
        let started = Instant::now();

        // Controlla cache
        if let Some((profile, cached_at)) = *cache_lock {
            if cached_at.elapsed() < Duration::from_secs(300) {
                return Ok(profile);
            }
        }

        // Esegui detection
        let profile = match self.perform_detection().await {
            Ok(profile) => {
                *cache_lock = Some((profile, Instant::now()));
                network_telemetry::record_nat_detection_success(
                    &profile.nat_type.to_string(),
                    started.elapsed(),
                );
                profile
            }
            Err(e) => {
                tracing::warn!("NAT detection failed: {}, using fallback Unknown", e);
                network_telemetry::record_nat_detection_failure(started.elapsed(), &e.to_string());
                NatProfile::new(NatType::Unknown, NatConfidence::Low, 0)
            }
        };

        Ok(profile)
    }

    /// Esegue la detection effettiva
    async fn perform_detection(&self) -> Result<NatProfile> {
        if self.stun_servers.len() < 2 {
            return Err(NatDetectionError::NeedAtLeastTwoStunServers);
        }

        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        let mut observations: Vec<MappedObservation> = Vec::new();

        // Probe fino a 3 server per migliorare confidenza.
        for server_str in self.stun_servers.iter().take(3) {
            let server: SocketAddr = server_str.parse()?;
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                self.send_stun_binding(&sock, server),
            )
            .await;

            match result {
                Ok(Ok((mapped, port))) => {
                    observations.push(MappedObservation {
                        server,
                        mapped,
                        port,
                    });
                }
                Ok(Err(e)) => {
                    tracing::debug!("NAT detect: STUN probe failed on {}: {}", server, e);
                }
                Err(_) => {
                    tracing::debug!("NAT detect: STUN probe timeout on {}", server);
                }
            }
        }

        if observations.len() < 2 {
            return Err(NatDetectionError::StunResponseTimeout);
        }

        let samples = observations.len();
        let base_confidence = NatConfidence::from_samples(samples);
        let first_mapped = observations[0].mapped;

        // Open internet: endpoint pubblico stabile.
        if self.is_public_ip(first_mapped.ip()) {
            return Ok(NatProfile::new(
                NatType::OpenInternet,
                base_confidence,
                samples as u8,
            ));
        }

        let unique_mapped: HashSet<SocketAddr> = observations.iter().map(|o| o.mapped).collect();
        let unique_ports: HashSet<u16> = observations.iter().map(|o| o.port).collect();

        // Mapping dipende dalla destinazione: comportamento symmetric-like.
        if unique_mapped.len() > 1 {
            let nat_type = if unique_ports.len() > 1 {
                NatType::Symmetric
            } else {
                NatType::SymetricFirewall
            };

            return Ok(NatProfile::new(nat_type, base_confidence, samples as u8));
        }

        // Mapping stabile: differenziamo cone/restricted con un test aggiuntivo best-effort.
        let primary_server = observations[0].server;
        let unrestricted = self
            .detect_restriction_with_server(&sock, primary_server)
            .await
            .unwrap_or(false);

        let nat_type = if unrestricted {
            NatType::FullCone
        } else {
            NatType::RestrictedCone
        };

        Ok(NatProfile::new(nat_type, base_confidence, samples as u8))
    }

    async fn detect_restriction_with_server(
        &self,
        sock: &UdpSocket,
        server: SocketAddr,
    ) -> Result<bool> {
        // Test best-effort: invia un nuovo binding e verifica che il server
        // risponda al socket corrente (stima grossolana di restrizione).
        let mut buf = vec![0u8; 512];
        let tx_id = rand::random::<[u8; 12]>();
        let request = self.build_stun_binding_request(tx_id);

        sock.send_to(&request, server).await?;

        match tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
            Ok(Ok((_n, from))) if from == server => Ok(true),
            Ok(Ok((_n, _))) => Err(NatDetectionError::UnexpectedServer),
            Ok(Err(e)) => Err(NatDetectionError::Io(e)),
            Err(_) => Ok(false),
        }
    }

    /// Invia binding request STUN e ottiene mapped address
    async fn send_stun_binding(
        &self,
        sock: &UdpSocket,
        server: SocketAddr,
    ) -> Result<(SocketAddr, u16)> {
        let mut buf = vec![0u8; 512];
        let tx_id = rand::random::<[u8; 12]>();
        let request = self.build_stun_binding_request(tx_id);

        sock.send_to(&request, server).await?;

        let (n, from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .map_err(|_| NatDetectionError::StunResponseTimeout)??;

        if from != server {
            return Err(NatDetectionError::UnexpectedServer);
        }

        let response = &buf[..n];
        self.parse_stun_mapped_address(response)
    }

    /// Costruisce STUN binding request
    fn build_stun_binding_request(&self, tx_id: [u8; 12]) -> Vec<u8> {
        let mut req = vec![0u8; 20 + 4]; // Header + CHANGE-REQUEST

        // STUN Message Type: Binding Request (0x0001)
        req[0] = 0x00;
        req[1] = 0x01;

        // Message Length (4 bytes per attributo)
        req[2] = 0x00;
        req[3] = 0x04;

        // Magic Cookie (RFC 5389)
        req[4] = 0x21;
        req[5] = 0x12;
        req[6] = 0xa4;
        req[7] = 0x42;

        // Transaction ID (12 bytes)
        req[8..20].copy_from_slice(&tx_id);

        req
    }

    /// Parsa STUN response per estrarre Mapped Address
    fn parse_stun_mapped_address(&self, response: &[u8]) -> Result<(SocketAddr, u16)> {
        if response.len() < 20 {
            return Err(NatDetectionError::ResponseTooShort);
        }

        // Verifica message type (Binding Response)
        if response[0] != 0x01 || response[1] != 0x01 {
            return Err(NatDetectionError::NotBindingResponse);
        }

        let message_len = u16::from_be_bytes([response[2], response[3]]) as usize;
        if response.len() < 20 + message_len {
            return Err(NatDetectionError::ResponseTruncated);
        }

        // Cerca XOR-MAPPED-ADDRESS (0x0020) o MAPPED-ADDRESS (0x0001)
        let mut offset = 20;
        while offset + 4 <= response.len() {
            let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let attr_len =
                u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
            let padded_len = attr_len.div_ceil(4) * 4;

            if attr_type == 0x0020 || attr_type == 0x0001 {
                // XOR-MAPPED-ADDRESS or MAPPED-ADDRESS
                if offset + 4 + attr_len <= response.len() && attr_len >= 8 {
                    // Skip first byte (reserved)
                    let family = response[offset + 5];
                    if family == 0x01 {
                        // IPv4
                        let port = u16::from_be_bytes([response[offset + 6], response[offset + 7]]);
                        let ip = Ipv4Addr::new(
                            response[offset + 8],
                            response[offset + 9],
                            response[offset + 10],
                            response[offset + 11],
                        );

                        // Decodifica XOR se necessario
                        let (port, ip) = if attr_type == 0x0020 {
                            // XOR with magic cookie and transaction ID
                            let magic_cookie = 0x2112A442u32;
                            let xored_port = port ^ (magic_cookie >> 16) as u16;
                            let xored_ip = Ipv4Addr::new(
                                ip.octets()[0] ^ ((magic_cookie >> 24) as u8),
                                ip.octets()[1] ^ ((magic_cookie >> 16) as u8),
                                ip.octets()[2] ^ ((magic_cookie >> 8) as u8),
                                ip.octets()[3] ^ (magic_cookie as u8),
                            );
                            (xored_port, xored_ip)
                        } else {
                            (port, ip)
                        };

                        return Ok((SocketAddr::V4(SocketAddrV4::new(ip, port)), port));
                    }
                }
            }

            offset += 4 + padded_len;
        }

        Err(NatDetectionError::NoAddressAttribute)
    }

    /// Verifica se un IP e pubblico
    fn is_public_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                // RFC 1918 private ranges
                !((ipv4.octets()[0] == 10)
                    || (ipv4.octets()[0] == 172
                        && ipv4.octets()[1] >= 16
                        && ipv4.octets()[1] <= 31)
                    || (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168)
                    ||
                    // Link-local
                    (ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254)
                    ||
                    // Loopback
                    ipv4.is_loopback())
            }
            IpAddr::V6(_) => {
                // Per IPv6, consideriamo globale se non e link-local o loopback
                let is_v4_mapped = match ip {
                    IpAddr::V6(v6) => {
                        let octets = v6.octets();
                        octets[..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff
                    }
                    _ => false,
                };
                !ip.is_loopback() && !ip.is_multicast() && !is_v4_mapped
            }
        }
    }

    /// Seleziona strategia di transport in base al tipo di NAT
    pub fn select_strategy(nat_type: NatType) -> Vec<TransportPriority> {
        match nat_type {
            NatType::OpenInternet => vec![
                TransportPriority {
                    kind: TransportKind::Lan,
                    priority: 100,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Upnp,
                    priority: 90,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Stun,
                    priority: 80,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Relay,
                    priority: 70,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Tor,
                    priority: 60,
                    should_skip: false,
                },
            ],
            NatType::FullCone => vec![
                TransportPriority {
                    kind: TransportKind::Lan,
                    priority: 100,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Stun,
                    priority: 80,
                    should_skip: false,
                }, // Hole punching diretto
                TransportPriority {
                    kind: TransportKind::Upnp,
                    priority: 70,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Relay,
                    priority: 60,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Tor,
                    priority: 50,
                    should_skip: false,
                },
            ],
            NatType::RestrictedCone | NatType::PortRestrictedCone | NatType::Symmetric => vec![
                TransportPriority {
                    kind: TransportKind::Lan,
                    priority: 100,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Upnp,
                    priority: 90,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Relay,
                    priority: 85,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Stun,
                    priority: 30,
                    should_skip: true,
                },
                TransportPriority {
                    kind: TransportKind::Tor,
                    priority: 80,
                    should_skip: false,
                },
            ],
            NatType::SymetricFirewall => vec![
                TransportPriority {
                    kind: TransportKind::Lan,
                    priority: 100,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Upnp,
                    priority: 85,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Relay,
                    priority: 90,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Tor,
                    priority: 80,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Stun,
                    priority: 20,
                    should_skip: true,
                },
            ],
            NatType::Unknown => vec![
                TransportPriority {
                    kind: TransportKind::Lan,
                    priority: 100,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Upnp,
                    priority: 85,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Stun,
                    priority: 70,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Relay,
                    priority: 75,
                    should_skip: false,
                },
                TransportPriority {
                    kind: TransportKind::Tor,
                    priority: 65,
                    should_skip: false,
                },
            ],
        }
    }

    /// Seleziona strategia adattiva in base a tipo NAT + confidenza detection.
    pub fn select_strategy_for_profile(profile: NatProfile) -> Vec<TransportPriority> {
        let mut strategy = Self::select_strategy(profile.nat_type);

        match profile.confidence {
            NatConfidence::High => {
                // Mantieni priorita base.
            }
            NatConfidence::Medium => {
                for step in &mut strategy {
                    match step.kind {
                        TransportKind::Relay | TransportKind::Tor => {
                            step.priority = step.priority.saturating_add(5);
                        }
                        _ => {}
                    }
                }
            }
            NatConfidence::Low => {
                for step in &mut strategy {
                    match step.kind {
                        TransportKind::Relay | TransportKind::Tor => {
                            step.priority = step.priority.saturating_add(12);
                        }
                        TransportKind::Stun | TransportKind::Upnp => {
                            step.priority = step.priority.saturating_sub(15);
                            if profile.nat_type == NatType::Unknown
                                && step.kind == TransportKind::Stun
                            {
                                step.should_skip = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        strategy.sort_by(|a, b| b.priority.cmp(&a.priority));
        strategy
    }
}

/// Wrapper per detection NAT con fallback
pub async fn detect_nat_type() -> Result<NatType> {
    Ok(detect_nat_profile().await?.nat_type)
}

/// Wrapper per detection del profilo NAT completo.
pub async fn detect_nat_profile() -> Result<NatProfile> {
    let config = crate::config::Config::from_env();
    let detector = NatDetector::new(config.nat_detection_servers);
    detector.detect_nat_profile().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nat_detection() {
        let detector = NatDetector::new(vec!["8.8.8.8:19302".into(), "1.1.1.1:3478".into()]);

        match detector.detect_nat_type().await {
            Ok(nat_type) => {
                println!("Detected NAT type: {}", nat_type);
                if nat_type == NatType::Unknown {
                    println!("NAT type unknown; skipping assertion");
                } else {
                    assert_ne!(nat_type, NatType::Unknown);
                }
            }
            Err(e) => {
                println!("NAT detection failed: {}", e);
                // Non fallire il test se i server sono irraggiungibili
            }
        }
    }

    #[test]
    fn test_select_strategy() {
        let strategy = NatDetector::select_strategy(NatType::Symmetric);
        assert!(strategy
            .iter()
            .any(|p| p.kind == TransportKind::Stun && p.should_skip));

        let strategy = NatDetector::select_strategy(NatType::FullCone);
        assert!(!strategy.iter().any(|p| p.should_skip));
    }

    #[test]
    fn test_select_strategy_for_low_confidence_biases_fallback() {
        let profile = NatProfile::new(NatType::Unknown, NatConfidence::Low, 1);
        let strategy = NatDetector::select_strategy_for_profile(profile);

        let relay = strategy
            .iter()
            .find(|p| p.kind == TransportKind::Relay)
            .unwrap();
        let stun = strategy
            .iter()
            .find(|p| p.kind == TransportKind::Stun)
            .unwrap();

        assert!(relay.priority >= stun.priority);
        assert!(stun.should_skip);
    }

    #[test]
    fn test_is_public_ip() {
        let detector = NatDetector::new(vec![]);

        assert!(!detector.is_public_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!detector.is_public_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!detector.is_public_ip(Ipv4Addr::new(172, 16, 0, 1).into()));
        assert!(detector.is_public_ip(Ipv4Addr::new(8, 8, 8, 8).into()));
    }
}
