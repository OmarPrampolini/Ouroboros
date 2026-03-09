use crate::protocol_assist_v5::CandidatePolicy;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

pub const UDP_MAX_PACKET_SIZE: usize = 65535;
pub const DEFAULT_CHANNEL_CAPACITY: usize = 1024;
pub const UDP_ROUTE_CHANNEL_CAPACITY: usize = 32;
pub const ASSIST_INBOX_CHANNEL_CAPACITY: usize = 128;
pub const WAN_ASSIST_GLOBAL_TIMEOUT_SECS: u64 = 5;
pub const ASSIST_INBOX_RETRY_SECS: u64 = 5;
pub const TOR_SOCKS_WAIT_SECS: u64 = 5;
pub const CONNECTION_BASE_TIMEOUT_SECS: u64 = 5;
pub const MIN_EPHEMERAL_PORT: u16 = 1024;
pub const MAX_PORT: u16 = 65535;

/// Product mode: Guaranteed (A) or Classic (B)
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ProductMode {
    Guaranteed,
    #[default]
    Classic,
}

/// Egress routing for Guaranteed mode (A)
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum GuaranteedEgress {
    #[default]
    Public,
    Tor,
}

/// WAN transport mode selection
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WanMode {
    #[default]
    Direct, // UPnP/NAT-PMP/PCP
    Tor,  // SOCKS5 via external Tor
    Auto, // Try Direct, fallback to Tor
}

/// Tor role in P2P connection
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TorRole {
    #[default]
    Client, // Connect to peer's onion
    Host, // Accept connections via onion service
}

/// Pluggable Transport mode for DPI evasion
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PluggableTransportMode {
    #[default]
    None, // Raw UDP (no disguise)
    HttpsLike,       // Disguise as HTTPS (fake)
    FtpData,         // Disguise as FTP
    DnsTunnel,       // DNS tunneling
    RealTls(String), // Real TLS with domain
    WebSocket,       // WebSocket mimicry
    Quic,            // QUIC mimicry
}

impl PluggableTransportMode {
    pub fn id(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HttpsLike => "httpslike",
            Self::FtpData => "ftpdata",
            Self::DnsTunnel => "dnstunnel",
            Self::RealTls(_) => "realtls",
            Self::WebSocket => "websocket",
            Self::Quic => "quic",
        }
    }
    pub fn class(&self) -> &'static str {
        match self {
            Self::None | Self::HttpsLike | Self::FtpData | Self::DnsTunnel => "stable",
            Self::RealTls(_) | Self::WebSocket | Self::Quic => "experimental",
        }
    }
    pub fn requires_external_infra(&self) -> bool {
        matches!(self, Self::RealTls(_) | Self::WebSocket)
    }
}
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PluggableProfile {
    #[default]
    Stable,
    Experimental,
}
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub api_bind: String, // "127.0.0.1:3000"
    pub rendezvous_timeout_ms: u64,
    pub keepalive_s: u64,
    pub max_chunk: usize, // es. 1200 bytes (fit in UDP MTU)
    pub discovery_enabled: bool,
    pub discovery_bootstrap_peers: Vec<String>,
    pub wan_probe_burst: usize,
    pub wan_probe_interval_ms: u64,
    pub wan_connect_timeout_ms: u64,
    pub wan_accept_timeout_ms: u64,
    pub assist_relays: Vec<String>,
    pub assist_obfuscation_v5: bool,
    pub assist_candidate_policy: CandidatePolicy,
    pub rate_limit_capacity: usize,
    pub rate_limit_max_requests: u32,
    pub rate_limit_time_window_s: u64,
    pub circuit_breaker_failure_threshold: u32,
    pub circuit_breaker_success_threshold: u32,
    pub offer_endpoint_delay_ms: u64,
    pub key_rotation_interval_s: u64,
    pub key_rotation_max_messages: u64,
    pub key_rotation_grace_s: u64,
    // Guaranteed transport settings
    pub guaranteed_relay_url: String,
    pub guaranteed_relay_wait_ms: u64,
    pub guaranteed_topic_window_ms: u64,
    pub tor_bin_path: Option<String>,
    // Tor transport settings
    pub wan_mode: WanMode,
    pub tor_role: TorRole,
    pub tor_socks_addr: String,         // "127.0.0.1:9050"
    pub tor_onion_addr: Option<String>, // target for Client mode
    pub tor_listen_addr: String,        // local addr for Host mode

    // NAT detection servers (STUN)
    pub nat_detection_servers: Vec<String>,

    // Pluggable Transport settings
    pub pluggable_profile: PluggableProfile,
    pub pluggable_transport: PluggableTransportMode,
    pub pluggable_tls_domains: Vec<String>, // Domains for RealTls mode
    pub pluggable_ws_host: String,          // Host header for WebSocket mimic
    pub realtls_mimic_pins: Vec<TlsMimicryConfig>,

    // Multipath settings
    pub multipath_policy: String, // "redundant" or "split"
    pub multipath_switch_threshold_ms: u64,
    pub multipath_split_ratio: (u8, u8), // (primary, secondary)

    // Capabilities for advanced features
    pub require_capabilities: bool, // true = require CAP_NET_RAW for ICMP
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsMimicryConfig {
    pub target_domain: String,
    pub issuer_spki_hashes: Vec<[u8; 32]>,
    pub enforce: bool, // true = reject if mismatch, false = warn only
}

impl Config {
    fn default() -> Self {
        Self {
            api_bind: "127.0.0.1:3000".into(),
            rendezvous_timeout_ms: 2000,
            keepalive_s: 30,
            max_chunk: 1200,
            discovery_enabled: false,
            discovery_bootstrap_peers: Vec::new(),
            wan_probe_burst: 5,
            wan_probe_interval_ms: 120,
            wan_connect_timeout_ms: 3000,
            wan_accept_timeout_ms: 30000,
            assist_relays: Vec::new(),
            assist_obfuscation_v5: false,
            assist_candidate_policy: CandidatePolicy::Any,
            rate_limit_capacity: 2048,
            rate_limit_max_requests: 300,
            rate_limit_time_window_s: 1,
            circuit_breaker_failure_threshold: 3,
            circuit_breaker_success_threshold: 2,
            offer_endpoint_delay_ms: 200,
            key_rotation_interval_s: 3600,
            key_rotation_max_messages: 1_000_000,
            key_rotation_grace_s: 60,
            guaranteed_relay_url: String::new(),
            guaranteed_relay_wait_ms: 10_000,
            guaranteed_topic_window_ms: 300_000,
            tor_bin_path: None,
            // Pluggable Transport default
            pluggable_profile: PluggableProfile::default(),
            pluggable_transport: PluggableTransportMode::default(),
            pluggable_tls_domains: vec!["www.cloudflare.com".into(), "api.google.com".into()],
            pluggable_ws_host: "www.cloudflare.com".into(),
            realtls_mimic_pins: Vec::new(),
            // Multipath defaults
            multipath_policy: "redundant".to_string(),
            multipath_switch_threshold_ms: 50,
            multipath_split_ratio: (70, 30),
            // Tor defaults
            wan_mode: WanMode::default(),
            tor_role: TorRole::default(),
            tor_socks_addr: "127.0.0.1:9050".into(),
            tor_onion_addr: None,
            tor_listen_addr: "127.0.0.1:9999".into(),
            nat_detection_servers: vec!["8.8.8.8:19302".into(), "1.1.1.1:3478".into()],
            require_capabilities: false,
        }
    }
}

impl Config {
    const MAX_ASSIST_RELAYS: usize = 5;
    const MAX_WAN_CONNECT_TIMEOUT_MS: u64 = 60000;

    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(bind) = std::env::var("HANDSHACKE_API_BIND") {
            config.api_bind = bind;
        }

        if let Ok(timeout) = std::env::var("HANDSHACKE_TIMEOUT_MS") {
            if let Ok(timeout) = timeout.parse() {
                config.rendezvous_timeout_ms = timeout;
            }
        }

        if let Ok(keepalive) = std::env::var("HANDSHACKE_KEEPALIVE_S") {
            if let Ok(keepalive) = keepalive.parse() {
                config.keepalive_s = keepalive;
            }
        }

        if let Ok(chunk_size) = std::env::var("HANDSHACKE_MAX_CHUNK") {
            if let Ok(chunk_size) = chunk_size.parse() {
                config.max_chunk = chunk_size;
            }
        }

        if let Ok(enabled) = std::env::var("HANDSHACKE_DISCOVERY_ENABLED") {
            config.discovery_enabled =
                matches!(enabled.to_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }

        if let Ok(peers) = std::env::var("HANDSHACKE_DISCOVERY_BOOTSTRAP_PEERS") {
            config.discovery_bootstrap_peers = peers
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .take(32)
                .collect();
        }

        if let Ok(burst) = std::env::var("HANDSHACKE_WAN_PROBE_BURST") {
            if let Ok(burst) = burst.parse() {
                config.wan_probe_burst = burst;
            }
        }

        if let Ok(interval) = std::env::var("HANDSHACKE_WAN_PROBE_INTERVAL_MS") {
            if let Ok(interval) = interval.parse() {
                config.wan_probe_interval_ms = interval;
            }
        }

        if let Ok(timeout) = std::env::var("HANDSHACKE_WAN_CONNECT_TIMEOUT_MS") {
            if let Ok(timeout) = timeout.parse::<u64>() {
                if timeout > 0 && timeout <= Self::MAX_WAN_CONNECT_TIMEOUT_MS {
                    config.wan_connect_timeout_ms = timeout;
                } else {
                    tracing::warn!(
                        "Invalid HANDSHACKE_WAN_CONNECT_TIMEOUT_MS {}, using default",
                        timeout
                    );
                }
            }
        }

        if let Ok(timeout) = std::env::var("HANDSHACKE_WAN_ACCEPT_TIMEOUT_MS") {
            if let Ok(timeout) = timeout.parse() {
                config.wan_accept_timeout_ms = timeout;
            }
        }

        if let Ok(relays) = std::env::var("HANDSHACKE_ASSIST_RELAYS") {
            let list = relays
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .take(Self::MAX_ASSIST_RELAYS)
                .collect::<Vec<_>>();
            config.assist_relays = list;
        }

        if let Ok(flag) = std::env::var("HANDSHACKE_ASSIST_OBFUSCATION_V5") {
            let flag = flag.to_lowercase();
            config.assist_obfuscation_v5 = matches!(flag.as_str(), "1" | "true" | "yes" | "on");
        }

        if let Ok(policy) = std::env::var("HANDSHACKE_ASSIST_CANDIDATE_POLICY") {
            config.assist_candidate_policy = match policy.to_lowercase().as_str() {
                "strict" | "strictwan" => CandidatePolicy::StrictWan,
                _ => CandidatePolicy::Any,
            };
        }

        if let Ok(delay_ms) = std::env::var("HANDSHACKE_OFFER_ENDPOINT_DELAY_MS") {
            if let Ok(delay_ms) = delay_ms.parse::<u64>() {
                config.offer_endpoint_delay_ms = delay_ms;
            }
        }

        if let Ok(relay_url) = std::env::var("HANDSHACKE_GUARANTEED_RELAY_URL") {
            config.guaranteed_relay_url = relay_url;
        }

        if let Ok(wait_ms) = std::env::var("HANDSHACKE_GUARANTEED_RELAY_WAIT_MS") {
            if let Ok(wait_ms) = wait_ms.parse::<u64>() {
                config.guaranteed_relay_wait_ms = wait_ms.max(100);
            }
        }

        if let Ok(window_ms) = std::env::var("HANDSHACKE_GUARANTEED_TOPIC_WINDOW_MS") {
            if let Ok(window_ms) = window_ms.parse::<u64>() {
                config.guaranteed_topic_window_ms = window_ms.max(60_000);
            }
        }

        if let Ok(tor_bin) = std::env::var("HANDSHACKE_TOR_BIN") {
            if !tor_bin.trim().is_empty() {
                config.tor_bin_path = Some(tor_bin);
            }
        }

        if let Ok(value) = std::env::var("HANDSHACKE_CB_FAILURE_THRESHOLD") {
            if let Ok(value) = value.parse::<u32>() {
                config.circuit_breaker_failure_threshold = value.max(1);
            }
        }

        if let Ok(value) = std::env::var("HANDSHACKE_CB_SUCCESS_THRESHOLD") {
            if let Ok(value) = value.parse::<u32>() {
                config.circuit_breaker_success_threshold = value.max(1);
            }
        }

        if let Ok(value) = std::env::var("HANDSHACKE_KEY_ROTATION_INTERVAL_S") {
            if let Ok(value) = value.parse::<u64>() {
                config.key_rotation_interval_s = value;
            }
        }

        if let Ok(value) = std::env::var("HANDSHACKE_KEY_ROTATION_MAX_MESSAGES") {
            if let Ok(value) = value.parse::<u64>() {
                config.key_rotation_max_messages = value;
            }
        }

        if let Ok(value) = std::env::var("HANDSHACKE_KEY_ROTATION_GRACE_S") {
            if let Ok(value) = value.parse::<u64>() {
                config.key_rotation_grace_s = value;
            }
        }
        // Pluggable Transport settings
        if let Ok(profile) = std::env::var("HANDSHACKE_PLUGGABLE_PROFILE") {
            config.pluggable_profile = match profile.to_lowercase().as_str() {
                "experimental" | "exp" => PluggableProfile::Experimental,
                _ => PluggableProfile::Stable,
            };
        }

        if let Ok(pt) = std::env::var("HANDSHACKE_PLUGGABLE_TRANSPORT") {
            config.pluggable_transport = match pt.to_lowercase().as_str() {
                "https" | "httpslike" => PluggableTransportMode::HttpsLike,
                "ftp" | "ftpdata" => PluggableTransportMode::FtpData,
                "dns" | "dnstunnel" => PluggableTransportMode::DnsTunnel,
                "websocket" | "ws" => PluggableTransportMode::WebSocket,
                "quic" => PluggableTransportMode::Quic,
                _ => PluggableTransportMode::None,
            };
        }

        // Parse RealTls domain if specified
        if let Ok(domain) = std::env::var("HANDSHACKE_REALTLS_DOMAIN") {
            if !domain.trim().is_empty() {
                config.pluggable_transport = PluggableTransportMode::RealTls(domain.clone());
                tracing::warn!(
                    "REALTLS WARNING: RealTls enabled with domain={}. You must operate a server endpoint with a valid certificate for this domain (or a compatible bridge). Without external infra, RealTls will not work.",
                    domain
                );
            }
        }

        if config.pluggable_profile == PluggableProfile::Stable
            && config.pluggable_transport.class() == "experimental"
        {
            tracing::warn!(
                "PLUGGABLE_PROFILE=stable blocks experimental transport {:?}. Falling back to none.",
                config.pluggable_transport
            );
            config.pluggable_transport = PluggableTransportMode::None;
        } else if config.pluggable_transport.class() == "experimental"
            && config.pluggable_transport != PluggableTransportMode::None
        {
            tracing::warn!(
                "PLUGGABLE_TRANSPORT WARNING: experimental feature enabled ({:?}) with profile={:?}. This may require external server-side infrastructure and can be fingerprintable if misconfigured.",
                config.pluggable_transport,
                config.pluggable_profile
            );
        }

        if let Ok(domains) = std::env::var("HANDSHACKE_REALTLS_DOMAINS") {
            config.pluggable_tls_domains = domains
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        if let Ok(host) = std::env::var("HANDSHACKE_WS_HOST") {
            if !host.trim().is_empty() {
                config.pluggable_ws_host = host;
            }
        }

        // RealTLS mimicry pinning (DPI evasion)
        // Format: "domain|enforce:BASE64,BASE64;domain|warn:BASE64"
        // Mode defaults to enforce if omitted.
        if let Ok(pins) = std::env::var("HANDSHACKE_REALTLS_MIMIC_PINS") {
            let mut parsed = Vec::new();
            for entry in pins.split(';') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                let (left, right) = match entry.split_once(':') {
                    Some(v) => v,
                    None => {
                        tracing::warn!("Invalid mimic pin entry (missing ':'): {}", entry);
                        continue;
                    }
                };
                let mut enforce = true;
                let mut domain = left.trim();
                if let Some((d, mode)) = left.split_once('|') {
                    domain = d.trim();
                    enforce = !matches!(mode.trim().to_lowercase().as_str(), "warn" | "soft");
                }
                if domain.is_empty() {
                    tracing::warn!("Invalid mimic pin entry (empty domain): {}", entry);
                    continue;
                }
                let mut hashes = Vec::new();
                for h in right.split(',') {
                    let h = h.trim();
                    if h.is_empty() {
                        continue;
                    }
                    let decoded = general_purpose::STANDARD
                        .decode(h)
                        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(h));
                    match decoded {
                        Ok(bytes) if bytes.len() == 32 => {
                            let mut out = [0u8; 32];
                            out.copy_from_slice(&bytes);
                            hashes.push(out);
                        }
                        Ok(_) => {
                            tracing::warn!("Invalid mimic pin hash length for domain {}", domain);
                        }
                        Err(_) => {
                            tracing::warn!("Invalid mimic pin base64 for domain {}", domain);
                        }
                    }
                }
                if hashes.is_empty() {
                    tracing::warn!("No valid mimic pin hashes for domain {}", domain);
                    continue;
                }
                parsed.push(TlsMimicryConfig {
                    target_domain: domain.to_string(),
                    issuer_spki_hashes: hashes,
                    enforce,
                });
            }
            config.realtls_mimic_pins = parsed;
        }

        // Multipath settings
        if let Ok(policy) = std::env::var("HANDSHACKE_MULTIPATH_POLICY") {
            config.multipath_policy = policy.to_lowercase();
        }

        if let Ok(threshold) = std::env::var("HANDSHACKE_MULTIPATH_THRESHOLD") {
            if let Ok(ms) = threshold.parse::<u64>() {
                config.multipath_switch_threshold_ms = ms;
            }
        }

        if let Ok(ratio) = std::env::var("HANDSHACKE_MULTIPATH_RATIO") {
            if let Some((primary, secondary)) = ratio.split_once(':') {
                if let (Ok(p), Ok(s)) = (primary.parse::<u8>(), secondary.parse::<u8>()) {
                    config.multipath_split_ratio = (p, s);
                }
            }
        }

        // Hole punching capabilities
        if let Ok(req) = std::env::var("HANDSHACKE_REQUIRE_CAPABILITIES") {
            config.require_capabilities =
                matches!(req.to_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }

        // Tor settings from env
        if let Ok(mode) = std::env::var("HANDSHACKE_WAN_MODE") {
            config.wan_mode = match mode.to_lowercase().as_str() {
                "tor" => WanMode::Tor,
                "auto" => WanMode::Auto,
                _ => WanMode::Direct,
            };
        }

        if let Ok(role) = std::env::var("HANDSHACKE_TOR_ROLE") {
            config.tor_role = match role.to_lowercase().as_str() {
                "host" => TorRole::Host,
                _ => TorRole::Client,
            };
        }

        if let Ok(socks) = std::env::var("HANDSHACKE_TOR_SOCKS") {
            config.tor_socks_addr = socks;
        }

        if let Ok(onion) = std::env::var("HANDSHACKE_TOR_ONION") {
            config.tor_onion_addr = Some(onion);
        }

        if let Ok(listen) = std::env::var("HANDSHACKE_TOR_LISTEN") {
            config.tor_listen_addr = listen;
        }

        if let Ok(servers) = std::env::var("HANDSHACKE_NAT_DETECTION_SERVERS") {
            config.nat_detection_servers = servers
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        config
    }

    pub fn key_rotation_policy(&self) -> crate::crypto::KeyRotationPolicy {
        crate::crypto::KeyRotationPolicy {
            interval_ms: self.key_rotation_interval_s.saturating_mul(1000),
            max_messages: self.key_rotation_max_messages,
        }
    }

    pub fn key_rotation_grace_ms(&self) -> u64 {
        self.key_rotation_grace_s.saturating_mul(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_product_mode_serde() {
        let v = serde_json::to_string(&ProductMode::Guaranteed).unwrap();
        assert_eq!(v, "\"guaranteed\"");
        let m: ProductMode = serde_json::from_str("\"classic\"").unwrap();
        assert_eq!(m, ProductMode::Classic);
    }

    #[test]
    fn test_guaranteed_egress_serde() {
        let v = serde_json::to_string(&GuaranteedEgress::Tor).unwrap();
        assert_eq!(v, "\"tor\"");
        let e: GuaranteedEgress = serde_json::from_str("\"public\"").unwrap();
        assert_eq!(e, GuaranteedEgress::Public);
    }
}
