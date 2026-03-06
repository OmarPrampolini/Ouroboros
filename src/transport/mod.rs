//! Transport layer: LAN -> WAN (Direct/Assist/Tor) with optional QUIC/WebRTC

pub mod assist_inbox;
pub mod dandelion;
pub mod framing;
pub mod guaranteed;
pub mod ice;
pub mod icmp_hole_punch;
pub mod io;
pub mod lan;
pub mod multipath;
pub mod nat_detection;
pub mod pluggable;
pub mod quic_rfc9000;
pub mod stealth;
pub mod stun;
pub mod tasks;
pub mod tcp_hole_punch;
pub mod wan;
pub mod wan_assist;
pub mod webrtc;

pub use icmp_hole_punch::IcmpHolePunch;
pub use tcp_hole_punch::TcpHolePunch;
pub use wan::wan_direct;
pub use wan::wan_tor;

use crate::config::{Config, WanMode, UDP_MAX_PACKET_SIZE, WAN_ASSIST_GLOBAL_TIMEOUT_SECS};
use crate::derive::RendezvousParams;
use crate::network_telemetry;
use crate::offer::{OfferPayload, RoleHint};
use crate::resume::ResumeParams;
use crate::security::early_drop_packet;
use crate::session_noise::NoiseRole;
use crate::transport::nat_detection::{
    detect_nat_profile, NatConfidence, NatDetector, NatProfile, NatType, TransportKind,
    TransportPriority,
};
use crate::transport::stun::StunClient;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::{sleep, timeout, Duration};

use wan::WanConnection;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

type TorStreamSplit = (
    Arc<TokioMutex<OwnedReadHalf>>,
    Arc<TokioMutex<OwnedWriteHalf>>,
);

fn strategy_metric_name(kind: &TransportKind) -> &'static str {
    match kind {
        TransportKind::Lan => "lan",
        TransportKind::Upnp => "upnp",
        TransportKind::Stun => "stun",
        TransportKind::Relay => "relay",
        TransportKind::Tor => "tor",
    }
}

fn apply_runtime_strategy_bias(strategy: &mut [TransportPriority]) {
    for step in strategy.iter_mut() {
        if step.should_skip {
            continue;
        }

        let name = strategy_metric_name(&step.kind);
        let delta = network_telemetry::strategy_priority_delta(name);
        if delta > 0 {
            step.priority = step.priority.saturating_add(delta as u32);
        } else if delta < 0 {
            step.priority = step.priority.saturating_sub((-delta) as u32);
        }
    }
}
/// Connection type established by transport layer
#[derive(Clone)]
pub enum Connection {
    /// LAN broadcast UDP
    Lan(Arc<UdpSocket>, SocketAddr),
    /// WAN Direct via UPnP/NAT-PMP
    Wan(Arc<UdpSocket>, SocketAddr),
    /// WAN via Tor stream (framed TCP)
    WanTorStream {
        reader: Arc<TokioMutex<OwnedReadHalf>>,
        writer: Arc<TokioMutex<OwnedWriteHalf>>,
    },
    /// WAN via direct TCP stream (framed)
    WanTcpStream {
        reader: Arc<TokioMutex<OwnedReadHalf>>,
        writer: Arc<TokioMutex<OwnedWriteHalf>>,
        peer: SocketAddr,
    },
    /// QUIC RFC9000 stream (framed)
    Quic(Arc<crate::transport::quic_rfc9000::QuinnTransport>),
    /// WebRTC DataChannel (message-based)
    WebRtc(Arc<crate::transport::webrtc::WebRtcTransport>),
    // Tun variant removed - Noise is now a session layer
}

impl Connection {
    /// Get UDP socket (only for UDP connections)
    pub fn get_socket(&self) -> Option<Arc<UdpSocket>> {
        match self {
            Connection::Lan(sock, _) => Some(sock.clone()),
            Connection::Wan(sock, _) => Some(sock.clone()),
            Connection::WanTcpStream { .. } => None,
            Connection::WanTorStream { .. } => None,
            Connection::Quic(_) => None,
            Connection::WebRtc(_) => None,
        }
    }

    /// Check if this is a Tor stream connection
    pub fn is_tor_stream(&self) -> bool {
        matches!(self, Connection::WanTorStream { .. })
    }

    /// Check if this is any stream-like transport
    pub fn is_stream(&self) -> bool {
        matches!(
            self,
            Connection::WanTorStream { .. }
                | Connection::WanTcpStream { .. }
                | Connection::Quic(_)
                | Connection::WebRtc(_)
        )
    }

    /// Get Tor stream (only for Tor connections)
    pub fn get_tor_stream(&self) -> Option<TorStreamSplit> {
        match self {
            Connection::WanTorStream { reader, writer } => Some((reader.clone(), writer.clone())),
            _ => None,
        }
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            Connection::Lan(_, addr) => Some(*addr),
            Connection::Wan(_, addr) => Some(*addr),
            Connection::WanTorStream { .. } => None,
            Connection::WanTcpStream { peer, .. } => Some(*peer),
            Connection::Quic(quic) => Some(quic.peer_addr()),
            Connection::WebRtc(_) => None,
        }
    }
}

/// Establish connection with cascade strategy: LAN → WAN → TUN
///
/// For WAN mode, uses config to determine Direct vs Tor transport.
pub async fn establish_connection(p: &RendezvousParams, cfg: &Config) -> Result<Connection> {
    // NAT strategy selection (uses cached detection when available).
    // NOTE: Requires STUN servers configured via config.nat_detection_servers.
    let nat_profile = match detect_nat_profile().await {
        Ok(profile) => profile,
        Err(e) => {
            tracing::warn!("NAT detection failed, using Unknown strategy: {}", e);
            network_telemetry::record_fallback_event(
                "connect",
                "nat_detection_failed",
                Some(e.to_string()),
            );
            NatProfile::new(NatType::Unknown, NatConfidence::Low, 0)
        }
    };
    let nat_type = nat_profile.nat_type;
    tracing::info!(
        "NAT profile detected: type={} confidence={} samples={}",
        nat_profile.nat_type,
        nat_profile.confidence,
        nat_profile.samples
    );

    let mut strategy = NatDetector::select_strategy_for_profile(nat_profile);
    // Fast-path: Symmetric NAT (or Symmetric+Firewall) should skip direct paths.
    if matches!(
        nat_type,
        crate::transport::nat_detection::NatType::Symmetric
            | crate::transport::nat_detection::NatType::SymetricFirewall
    ) {
        tracing::info!("nat=symmetric -> skipping direct transports (stun/upnp)");
        network_telemetry::record_fallback_event(
            "connect",
            "symmetric_nat_detected",
            Some(format!("nat_type={}", nat_type)),
        );
        for step in strategy.iter_mut() {
            match step.kind {
                TransportKind::Upnp | TransportKind::Stun => {
                    step.should_skip = true;
                }
                TransportKind::Relay => step.priority = step.priority.max(95),
                TransportKind::Tor => step.priority = step.priority.max(90),
                _ => {}
            }
        }
    }
    apply_runtime_strategy_bias(&mut strategy);
    strategy.sort_by(|a, b| b.priority.cmp(&a.priority));

    for step in strategy {
        if step.should_skip {
            tracing::debug!("Skipping transport {:?} due to NAT strategy", step.kind);
            network_telemetry::record_fallback_event(
                "connect",
                "strategy_skipped",
                Some(format!("kind={:?}", step.kind)),
            );
            continue;
        }

        match step.kind {
            TransportKind::Lan => match lan::try_lan_broadcast(p.port).await {
                Ok((sock, peer_addr)) => {
                    network_telemetry::record_strategy_result("lan", true);
                    tracing::info!("LAN mode active on port: {}", p.port);
                    return Ok(Connection::Lan(Arc::new(sock), peer_addr));
                }
                Err(e) => {
                    network_telemetry::record_strategy_result("lan", false);
                    network_telemetry::record_fallback_event(
                        "connect",
                        "lan_failed",
                        Some(e.to_string()),
                    );
                }
            },
            TransportKind::Upnp => {
                if cfg.wan_mode != WanMode::Tor {
                    match wan::wan_direct::try_direct_port_forward(p.port).await {
                        Ok((sock, ext_addr)) => {
                            network_telemetry::record_strategy_result("upnp", true);
                            tracing::info!(
                                "WAN Direct mode active. Port forwarded to {}",
                                ext_addr
                            );
                            return Ok(Connection::Wan(Arc::new(sock), ext_addr));
                        }
                        Err(e) => {
                            network_telemetry::record_strategy_result("upnp", false);
                            network_telemetry::record_fallback_event(
                                "connect",
                                "upnp_failed",
                                Some(e.to_string()),
                            );
                            tracing::warn!("WAN Direct failed: {}", e);
                        }
                    }
                }
            }
            TransportKind::Stun => {
                // Placeholder: direct STUN punching uses same WAN direct path for now.
                // Replace with real STUN-based hole punch when available.
                if cfg.wan_mode != WanMode::Tor {
                    match wan::wan_direct::try_direct_port_forward(p.port).await {
                        Ok((sock, ext_addr)) => {
                            network_telemetry::record_strategy_result("stun", true);
                            tracing::info!("STUN path active. Port forwarded to {}", ext_addr);
                            return Ok(Connection::Wan(Arc::new(sock), ext_addr));
                        }
                        Err(e) => {
                            network_telemetry::record_strategy_result("stun", false);
                            network_telemetry::record_fallback_event(
                                "connect",
                                "stun_path_failed",
                                Some(e.to_string()),
                            );
                            tracing::warn!("STUN path failed: {}", e);
                        }
                    }
                }
            }
            TransportKind::Relay => {
                if !cfg.assist_relays.is_empty() {
                    let assist_start = tokio::time::Instant::now();
                    let mut attempts = 0;

                    for relay in cfg.assist_relays.iter().take(2) {
                        if assist_start.elapsed()
                            > Duration::from_secs(WAN_ASSIST_GLOBAL_TIMEOUT_SECS)
                        {
                            tracing::warn!("WAN Assist: global timeout exceeded");
                            network_telemetry::record_fallback_event(
                                "connect",
                                "relay_global_timeout",
                                Some(format!("attempts={}", attempts)),
                            );
                            break;
                        }

                        attempts += 1;
                        match timeout(
                            Duration::from_secs(2),
                            wan_assist::try_assisted_punch(p, std::slice::from_ref(relay), cfg),
                        )
                        .await
                        {
                            Ok(Ok(conn)) => {
                                network_telemetry::record_strategy_result("relay", true);
                                tracing::info!("WAN Assist: success after {} attempts", attempts);
                                return Ok(conn);
                            }
                            Ok(Err(e)) => {
                                network_telemetry::record_strategy_result("relay", false);
                                network_telemetry::record_fallback_event(
                                    "connect",
                                    "relay_attempt_failed",
                                    Some(format!("relay={} err={}", relay, e)),
                                );
                                tracing::warn!("Relay {} failed: {}", relay, e)
                            }
                            Err(_) => {
                                network_telemetry::record_strategy_result("relay", false);
                                network_telemetry::record_fallback_event(
                                    "connect",
                                    "relay_attempt_timeout",
                                    Some(format!("relay={}", relay)),
                                );
                                tracing::warn!("Relay {} timeout", relay)
                            }
                        }
                    }
                    tracing::warn!("WAN Assist: all {} attempts failed, falling back", attempts);
                } else {
                    tracing::debug!("WAN Assist skipped: no relays configured");
                    network_telemetry::record_fallback_event(
                        "connect",
                        "relay_skipped_no_config",
                        None,
                    );
                }
            }
            TransportKind::Tor => match wan::try_tor_mode(cfg).await {
                Ok(wan_conn) => {
                    network_telemetry::record_strategy_result("tor", true);
                    return connection_from_wan(wan_conn).await;
                }
                Err(e) => {
                    network_telemetry::record_strategy_result("tor", false);
                    network_telemetry::record_fallback_event(
                        "connect",
                        "tor_failed",
                        Some(e.to_string()),
                    );
                    tracing::warn!("Tor failed: {}", e)
                }
            },
        }
    }

    network_telemetry::record_fallback_event(
        "connect",
        "strategy_exhausted",
        Some("no reachable transport found".to_string()),
    );
    Err(std::io::Error::other(
        "Connection failed: no reachable transport found (NAT strategy exhausted)",
    )
    .into())
}

async fn connection_from_wan(wan_conn: WanConnection) -> Result<Connection> {
    match wan_conn {
        WanConnection::Direct(sock, ext_addr) => {
            tracing::info!("WAN Direct mode active. Port forwarded to {}", ext_addr);
            Ok(Connection::Wan(Arc::new(sock), ext_addr))
        }
        WanConnection::TorClient(stream) => {
            tracing::info!("WAN Tor Client mode active");
            let (reader, writer) = stream.into_split();
            Ok(Connection::WanTorStream {
                reader: Arc::new(TokioMutex::new(reader)),
                writer: Arc::new(TokioMutex::new(writer)),
            })
        }
        WanConnection::TorHost(listener) => {
            tracing::info!("WAN Tor Host mode: waiting for connection...");
            let (stream, peer_addr) = listener.accept().await?;
            tracing::info!("Tor Host: accepted connection from {}", peer_addr);
            let (reader, writer) = stream.into_split();
            Ok(Connection::WanTorStream {
                reader: Arc::new(TokioMutex::new(reader)),
                writer: Arc::new(TokioMutex::new(writer)),
            })
        }
    }
}

/// Active dial to a specific target (WAN Direct or Tor).
pub async fn connect_to(
    target: &str,
    params: &RendezvousParams,
    cfg: &Config,
) -> Result<Connection> {
    if target.contains(".onion") {
        let stream = crate::transport::wan::wan_tor::try_tor_connect(
            &cfg.tor_socks_addr,
            target,
            None,
            Some(target),
        )
        .await?;
        let (reader, writer) = stream.into_split();
        return Ok(Connection::WanTorStream {
            reader: Arc::new(TokioMutex::new(reader)),
            writer: Arc::new(TokioMutex::new(writer)),
        });
    }

    let peer: SocketAddr = target.parse()?;
    let bind_addr = if peer.is_ipv6() {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    sock.connect(peer).await?;

    let probe = build_probe_packet(params.tag16);
    let burst = cfg.wan_probe_burst.clamp(1, 10); // Limit max burst to prevent amplification

    // Rate limiting: max 1 probe per 100ms per target to prevent amplification attacks
    let probe_interval = cfg.wan_probe_interval_ms.max(100);
    for i in 0..burst {
        sock.send(&probe).await?;
        if i + 1 < burst {
            sleep(Duration::from_millis(probe_interval)).await;
        }
    }

    let mut buf = vec![0u8; 1024];
    let timeout_ms = cfg.wan_connect_timeout_ms.clamp(1, 10000); // Cap timeout to prevent resource exhaustion

    let mut udp_blocked = false;
    match timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, from))) if from == peer && (8..=UDP_MAX_PACKET_SIZE).contains(&n) => {
            // Additional validation: ensure response is reasonable size
            if !early_drop_packet(&buf[..n], params.tag16, params.tag8) {
                tracing::debug!(
                    "UDP hole punching successful with {} bytes from {}",
                    n,
                    from
                );
                return Ok(Connection::Wan(Arc::new(sock), peer));
            }
        }
        Ok(Ok((n, from))) => {
            tracing::warn!(
                "Invalid UDP response: {} bytes from {} (expected {})",
                n,
                from,
                peer
            );
            network_telemetry::record_fallback_event(
                "connect_to",
                "udp_invalid_response",
                Some(format!("from={} bytes={}", from, n)),
            );
            udp_blocked = true;
        }
        Ok(Err(e)) => {
            tracing::debug!("UDP receive error: {}", e);
            network_telemetry::record_fallback_event(
                "connect_to",
                "udp_receive_error",
                Some(e.to_string()),
            );
            udp_blocked = true;
        }
        Err(_) => {
            tracing::debug!("UDP receive timeout");
            network_telemetry::record_fallback_event(
                "connect_to",
                "udp_timeout",
                Some(format!("target={}", target)),
            );
            udp_blocked = true;
        }
    }

    if udp_blocked {
        tracing::info!("udp_blocked -> trying adaptive TCP hole punch");
        network_telemetry::record_fallback_event(
            "connect_to",
            "udp_blocked_fallback_tcp",
            Some(format!("target={}", target)),
        );

        let tcp_plan = crate::transport::tcp_hole_punch::TcpPunchPlan {
            attempts: (cfg.wan_probe_burst as u8).saturating_add(2).clamp(3, 7),
            min_attempt_timeout_ms: cfg.wan_connect_timeout_ms.clamp(600, 3000),
            max_attempt_timeout_ms: cfg
                .wan_connect_timeout_ms
                .saturating_mul(2)
                .clamp(1500, 7000),
            base_interval_ms: cfg.wan_probe_interval_ms.clamp(80, 300),
            max_interval_ms: cfg.wan_probe_interval_ms.saturating_mul(3).clamp(200, 900),
            jitter_ms: 60,
        };

        let local = if peer.is_ipv6() {
            SocketAddr::from(([0u16; 8], params.port))
        } else {
            SocketAddr::from(([0, 0, 0, 0], params.port))
        };

        let tcp_result = match TcpHolePunch::punch_with_plan(local, peer, tcp_plan).await {
            Ok(stream) => Ok(stream),
            Err(e) => {
                tracing::warn!(
                    "TCP hole punch failed on fixed port {} ({}), retrying ephemeral port",
                    params.port,
                    e
                );
                network_telemetry::record_fallback_event(
                    "connect_to",
                    "tcp_fixed_port_failed",
                    Some(format!("port={} err={}", params.port, e)),
                );
                let local_ephemeral = if peer.is_ipv6() {
                    SocketAddr::from(([0u16; 8], 0))
                } else {
                    SocketAddr::from(([0, 0, 0, 0], 0))
                };
                let fallback_plan = crate::transport::tcp_hole_punch::TcpPunchPlan {
                    attempts: tcp_plan.attempts.saturating_sub(1).max(2),
                    ..tcp_plan
                };
                TcpHolePunch::punch_with_plan(local_ephemeral, peer, fallback_plan).await
            }
        };

        match tcp_result {
            Ok(stream) => {
                network_telemetry::record_strategy_result("tcp_hole_punch", true);
                let (reader, writer) = stream.into_split();
                return Ok(Connection::WanTcpStream {
                    reader: Arc::new(TokioMutex::new(reader)),
                    writer: Arc::new(TokioMutex::new(writer)),
                    peer,
                });
            }
            Err(e) => {
                network_telemetry::record_strategy_result("tcp_hole_punch", false);
                network_telemetry::record_fallback_event(
                    "connect_to",
                    "tcp_hole_punch_exhausted",
                    Some(e.to_string()),
                );
                tracing::warn!("tcp failed -> giving up ({})", e);
                tracing::warn!(
                    "Direct connect failed behind restrictive NAT/firewall. Suggested: use QR + Tor relay for reliable rendezvous."
                );
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Connection timeout to {}", target),
    )
    .into())
}

fn build_probe_packet(tag16: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(1400);
    v.extend_from_slice(&tag16.to_le_bytes());
    v.extend_from_slice(b"PROBE");

    // Pad to MTU for constant-size probe packets
    crate::crypto::pad_to_mtu(&mut v);
    v
}

pub struct OfferConnectResult {
    pub conn: Connection,
    pub session_key: [u8; 32],
    pub mode: String,
    pub peer: Option<String>,
    pub resume_used: Option<bool>,
}

pub async fn establish_connection_from_offer(
    offer: &OfferPayload,
    cfg: &Config,
    local_role: RoleHint,
) -> Result<OfferConnectResult> {
    establish_connection_from_offer_with_resume(offer, cfg, local_role, None).await
}

pub async fn establish_connection_from_offer_with_resume(
    offer: &OfferPayload,
    cfg: &Config,
    local_role: RoleHint,
    resume: Option<ResumeParams>,
) -> Result<OfferConnectResult> {
    let noise_role = match local_role {
        RoleHint::Host => NoiseRole::Responder,
        RoleHint::Client => NoiseRole::Initiator,
    };

    let offer_hash = crate::crypto::hash_offer(offer);
    let params = crate::derive::RendezvousParams {
        port: offer.rendezvous.port,
        key_enc: offer.rendezvous.key_enc,
        key_mac: [0u8; 32],
        tag16: offer.rendezvous.tag16,
        tag8: crate::derive::derive_tag8_from_key(&offer.rendezvous.key_enc)?,
        version: crate::offer::OFFER_VERSION,
    };

    // STUN hole punching (QR/offer aware). Requires peer public addr in offer.
    if let Some(peer_public) = offer.stun_public_addr {
        if let Ok(stun) = StunClient::new(cfg.nat_detection_servers.clone()) {
            match stun.discover(params.port).await {
                Ok(discovery) => {
                    tracing::info!(
                        "STUN discovery: public={} (via {}), nat_type={}",
                        discovery.public_addr,
                        discovery.server_used,
                        discovery.nat_type
                    );

                    // Coordinated rendezvous window using offer timestamp (best-effort sync)
                    let rendezvous_window_ms = 30_000u64;
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let adjusted_now = if let Some(offset) = offer.ntp_offset {
                        (now_ms as i64 + offset) as u64
                    } else {
                        now_ms
                    };
                    let rendezvous_at_ms = offer.timestamp.saturating_add(rendezvous_window_ms);
                    if rendezvous_at_ms > adjusted_now {
                        let sleep_ms = rendezvous_at_ms.saturating_sub(adjusted_now);
                        tracing::info!(
                            "STUN hole punch rendezvous at {} (in {}ms)",
                            rendezvous_at_ms,
                            sleep_ms
                        );
                        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                    }

                    if let Ok(sock) = stun
                        .hole_punch_with_socket(discovery.socket.clone(), peer_public)
                        .await
                    {
                        tracing::info!("STUN hole punch successful with {}", peer_public);
                        network_telemetry::record_strategy_result("stun_offer", true);
                        let conn = Connection::Wan(sock, peer_public);
                        let mode = "stun".to_string();
                        let peer = Some(peer_public.to_string());
                        let tag8 = crate::derive::derive_tag8_from_key(&offer.rendezvous.key_enc)?;
                        let (session_key, resume_used) = match resume {
                            Some(ref resume) => {
                                crate::session_noise::run_resume_or_noise(
                                    noise_role,
                                    &conn,
                                    &offer.rendezvous.key_enc,
                                    offer.rendezvous.tag16,
                                    tag8,
                                    resume,
                                )
                                .await?
                            }
                            None => (
                                crate::session_noise::run_noise_upgrade(
                                    noise_role,
                                    &conn,
                                    &offer.rendezvous.key_enc,
                                    offer.rendezvous.tag16,
                                    tag8,
                                )
                                .await?,
                                false,
                            ),
                        };

                        return Ok(OfferConnectResult {
                            conn,
                            session_key,
                            mode,
                            peer,
                            resume_used: resume.map(|_| resume_used),
                        });
                    } else {
                        network_telemetry::record_fallback_event(
                            "offer_connect",
                            "stun_hole_punch_failed",
                            Some(format!("peer_public={}", peer_public)),
                        );
                        tracing::warn!("STUN hole punch failed, falling back to ICE");
                    }
                }
                Err(e) => {
                    network_telemetry::record_fallback_event(
                        "offer_connect",
                        "stun_discovery_failed",
                        Some(e.to_string()),
                    );
                    tracing::warn!("STUN discovery failed: {}", e)
                }
            }
        }
    }

    // ICE module now validates the candidate by completing the resume/noise handshake.
    crate::transport::ice::multipath_race_connect_with_resume(
        offer,
        offer_hash,
        params,
        cfg.clone(),
        noise_role,
        resume,
    )
    .await
    .map_err(Into::into)
}
