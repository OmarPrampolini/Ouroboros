use axum::{
    extract::{ConnectInfo, Extension},
    response::Json,
};
use rand::RngCore;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::api::ApiError;
use crate::{
    config::{Config, MAX_PORT, MIN_EPHEMERAL_PORT},
    derive::{derive_from_passphrase_v2_stealth, derive_from_secret},
    offer::{
        derive_offer_key_v2, Endpoint, EndpointKind, OfferPayload, RendezvousInfo, RoleHint,
        DEFAULT_TTL_SECONDS,
    },
    resume::{
        caps_from_endpoints, HybridQrPayload, ResumeParams, DEFAULT_QR_TTL_MS,
        DEFAULT_RESUME_TTL_MS,
    },
    transport::stun::StunClient,
};

type OfferResult = Result<Json<OfferResponse>, ApiError>;

#[derive(Debug, Deserialize)]
pub struct OfferRequest {
    pub passphrase: Option<String>,
    pub ttl_s: Option<u64>,
    pub role_hint: Option<RoleHint>,
    pub include_tor: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct OfferResponse {
    pub offer: String,
    pub ver: u8,
    pub expires_at_ms: u64,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct HybridQrRequest {
    pub passphrase: Option<String>,
    pub ttl_s: Option<u64>,
    pub role_hint: Option<RoleHint>,
    pub include_tor: Option<bool>,
    pub resume_ttl_s: Option<u64>,
    pub qr_ttl_s: Option<u64>,
    pub relay_hints: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct HybridQrResponse {
    pub qr: String,
    pub offer: String,
    pub ver: u8,
    pub expires_at_ms: u64,
    pub resume_expires_at_ms: u64,
    pub endpoints: Vec<String>,
    pub relay_hints: Vec<String>,
}

pub async fn handle_offer_generate(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<crate::api::ApiState>>,
    Json(req): Json<OfferRequest>,
) -> OfferResult {
    if !state.app.api_allow(addr.ip(), 2.0).await {
        return Err(ApiError::bad_request("rate limit"));
    }
    let cfg = Config::from_env();
    let ttl_s = req.ttl_s.unwrap_or(DEFAULT_TTL_SECONDS);
    let role_hint = req.role_hint.unwrap_or(RoleHint::Host);

    // Check if stealth mode is requested via env var
    let stealth_mode = std::env::var("HANDSHACKE_STEALTH_PORT").is_ok();

    let (rendezvous, per_ephemeral_salt) = match req.passphrase {
        Some(pass) => {
            if stealth_mode {
                // Stealth mode: use random salt for port randomization
                let (params, salt) =
                    derive_from_passphrase_v2_stealth(&pass, &[0u8; 16]).map_err(|e| {
                        tracing::error!("Stealth derivation failed: {:?}", e);
                        ApiError::operation_failed()
                    })?;
                let info = RendezvousInfo {
                    port: params.port,
                    tag16: params.tag16,
                    key_enc: params.key_enc,
                };
                (info, Some(salt))
            } else {
                // Standard mode: deterministic derivation
                let secret = SecretString::from(pass);
                let params = derive_from_secret(&secret).map_err(|e| {
                    tracing::error!("Derivation failed: {:?}", e);
                    ApiError::operation_failed()
                })?;
                let info = RendezvousInfo {
                    port: params.port,
                    tag16: params.tag16,
                    key_enc: params.key_enc,
                };
                (info, None)
            }
        }
        None => {
            // Random params, no stealth needed
            let info = RendezvousInfo {
                port: random_port(),
                tag16: random_tag16(),
                key_enc: random_key(),
            };
            (info, None)
        }
    };

    let mut endpoints = Vec::new();
    let lan_eps = discover_lan_endpoints(rendezvous.port).map_err(|e| {
        tracing::error!("Offer LAN discovery failed: {:?}", e);
        ApiError::operation_failed()
    })?;
    endpoints.extend(lan_eps);

    if let Ok((wan_ep, keepalive_sock)) = discover_wan_endpoint(rendezvous.port).await {
        state.app.set_wan_keepalive_socket(keepalive_sock).await;
        endpoints.push(wan_ep);
    }

    let include_tor = req.include_tor.unwrap_or(false);
    let tor_onion_addr = if include_tor {
        cfg.tor_onion_addr.clone()
    } else {
        None
    };
    if let Some(onion) = &tor_onion_addr {
        if tracing::level_enabled!(tracing::Level::DEBUG) {
            tracing::debug!("Offer Tor endpoint (debug): {}", onion);
        }
    }
    if tor_onion_addr.is_some() {
        endpoints.push(Endpoint {
            kind: EndpointKind::Tor,
            addr: None,
            priority: 30,
            timeout_ms: 4000,
        });
    }

    if endpoints.is_empty() {
        return Err(ApiError::operation_failed());
    }

    let mut offer = OfferPayload::new(
        role_hint,
        endpoints.clone(),
        tor_onion_addr,
        rendezvous,
        ttl_s,
    )
    .map_err(|e| {
        tracing::error!("Offer build failed: {:?}", e);
        ApiError::operation_failed()
    })?;

    let mut needs_commit = false;
    // Set ephemeral salt if using stealth mode
    if let Some(salt) = per_ephemeral_salt {
        offer.per_ephemeral_salt = Some(salt);
        needs_commit = true;
    }

    // STUN discovery (best-effort) to enrich offer with public endpoint
    if let Ok(stun) = StunClient::new(cfg.nat_detection_servers.clone()) {
        match stun.discover(offer.rendezvous.port).await {
            Ok(discovery) => {
                tracing::info!(
                    "STUN discovery: public={} (via {}), nat_type={}",
                    discovery.public_addr,
                    discovery.server_used,
                    discovery.nat_type
                );
                offer.stun_public_addr = Some(discovery.public_addr);
                needs_commit = true;
            }
            Err(e) => tracing::warn!("STUN discovery failed: {}", e),
        }
    }

    if needs_commit {
        let k_offer = derive_offer_key_v2(&offer.rendezvous.key_enc, offer.rendezvous.tag16)?;
        offer.commit = OfferPayload::compute_commit(&offer, &k_offer)?;
    }
    let offer_str = offer.encode().map_err(|e| {
        tracing::error!("Offer encode failed: {:?}", e);
        ApiError::operation_failed()
    })?;

    let endpoints_display = endpoints
        .iter()
        .map(|e| match (&e.kind, &e.addr) {
            (EndpointKind::Tor, _) => "tor".to_string(),
            (_, Some(addr)) => format!("{:?} {}", e.kind, addr),
            _ => format!("{:?}", e.kind),
        })
        .collect();

    Ok(Json(OfferResponse {
        offer: offer_str,
        ver: offer.ver,
        expires_at_ms: offer.expires_at_ms(),
        endpoints: endpoints_display,
    }))
}

pub async fn handle_hybrid_qr_generate(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<crate::api::ApiState>>,
    Json(req): Json<HybridQrRequest>,
) -> Result<Json<HybridQrResponse>, ApiError> {
    if !state.app.api_allow(addr.ip(), 2.0).await {
        return Err(ApiError::bad_request("rate limit"));
    }
    let cfg = Config::from_env();
    let ttl_s = req.ttl_s.unwrap_or(DEFAULT_TTL_SECONDS);
    let role_hint = req.role_hint.unwrap_or(RoleHint::Host);
    let resume_ttl_ms = req
        .resume_ttl_s
        .map(|s| s.saturating_mul(1000))
        .unwrap_or(DEFAULT_RESUME_TTL_MS);
    let qr_ttl_ms = req
        .qr_ttl_s
        .map(|s| s.saturating_mul(1000))
        .unwrap_or(DEFAULT_QR_TTL_MS);

    let stealth_mode = std::env::var("HANDSHACKE_STEALTH_PORT").is_ok();

    let (rendezvous, per_ephemeral_salt) = match req.passphrase {
        Some(pass) => {
            if stealth_mode {
                let (params, salt) =
                    derive_from_passphrase_v2_stealth(&pass, &[0u8; 16]).map_err(|e| {
                        tracing::error!("Stealth derivation failed: {:?}", e);
                        ApiError::operation_failed()
                    })?;
                let info = RendezvousInfo {
                    port: params.port,
                    tag16: params.tag16,
                    key_enc: params.key_enc,
                };
                (info, Some(salt))
            } else {
                let secret = SecretString::from(pass);
                let params = derive_from_secret(&secret).map_err(|e| {
                    tracing::error!("Derivation failed: {:?}", e);
                    ApiError::operation_failed()
                })?;
                let info = RendezvousInfo {
                    port: params.port,
                    tag16: params.tag16,
                    key_enc: params.key_enc,
                };
                (info, None)
            }
        }
        None => {
            let info = RendezvousInfo {
                port: random_port(),
                tag16: random_tag16(),
                key_enc: random_key(),
            };
            (info, None)
        }
    };

    let mut endpoints = Vec::new();
    let lan_eps = discover_lan_endpoints(rendezvous.port).map_err(|e| {
        tracing::error!("Offer LAN discovery failed: {:?}", e);
        ApiError::operation_failed()
    })?;
    endpoints.extend(lan_eps);

    if let Ok((wan_ep, keepalive_sock)) = discover_wan_endpoint(rendezvous.port).await {
        state.app.set_wan_keepalive_socket(keepalive_sock).await;
        endpoints.push(wan_ep);
    }

    let include_tor = req.include_tor.unwrap_or(false);
    let tor_onion_addr = if include_tor {
        cfg.tor_onion_addr.clone()
    } else {
        None
    };
    if tor_onion_addr.is_some() {
        endpoints.push(Endpoint {
            kind: EndpointKind::Tor,
            addr: None,
            priority: 30,
            timeout_ms: 4000,
        });
    }

    if endpoints.is_empty() {
        return Err(ApiError::operation_failed());
    }

    let mut offer = OfferPayload::new(
        role_hint,
        endpoints.clone(),
        tor_onion_addr,
        rendezvous,
        ttl_s,
    )
    .map_err(|e| {
        tracing::error!("Offer build failed: {:?}", e);
        ApiError::operation_failed()
    })?;

    let mut needs_commit = false;
    if let Some(salt) = per_ephemeral_salt {
        offer.per_ephemeral_salt = Some(salt);
        needs_commit = true;
    }

    if let Ok(stun) = StunClient::new(cfg.nat_detection_servers.clone()) {
        match stun.discover(offer.rendezvous.port).await {
            Ok(discovery) => {
                tracing::info!(
                    "STUN discovery: public={} (via {}), nat_type={}",
                    discovery.public_addr,
                    discovery.server_used,
                    discovery.nat_type
                );
                offer.stun_public_addr = Some(discovery.public_addr);
                needs_commit = true;
            }
            Err(e) => tracing::warn!("STUN discovery failed: {}", e),
        }
    }

    if needs_commit {
        let k_offer = derive_offer_key_v2(&offer.rendezvous.key_enc, offer.rendezvous.tag16)?;
        offer.commit = OfferPayload::compute_commit(&offer, &k_offer)?;
    }

    let offer_str = offer.encode().map_err(|e| {
        tracing::error!("Offer encode failed: {:?}", e);
        ApiError::operation_failed()
    })?;

    let resume = ResumeParams::new(resume_ttl_ms);
    let qr_expires_at_ms = crate::crypto::now_ms().saturating_add(qr_ttl_ms);
    let offer_expires_at_ms = offer.expires_at_ms().min(qr_expires_at_ms);
    let caps = caps_from_endpoints(&endpoints);
    let relay_hints = req
        .relay_hints
        .clone()
        .unwrap_or_else(|| cfg.assist_relays.clone());
    let hybrid = HybridQrPayload::new(
        offer_str.clone(),
        offer_expires_at_ms,
        resume,
        caps,
        relay_hints.clone(),
    );
    let qr_str = hybrid.encode().map_err(|e| {
        tracing::error!("Hybrid QR encode failed: {:?}", e);
        ApiError::operation_failed()
    })?;

    let endpoints_display = endpoints
        .iter()
        .map(|e| match (&e.kind, &e.addr) {
            (EndpointKind::Tor, _) => "tor".to_string(),
            (_, Some(addr)) => format!("{:?} {}", e.kind, addr),
            _ => format!("{:?}", e.kind),
        })
        .collect();

    Ok(Json(HybridQrResponse {
        qr: qr_str,
        offer: offer_str,
        ver: offer.ver,
        expires_at_ms: offer_expires_at_ms,
        resume_expires_at_ms: hybrid.resume_expires_at_ms,
        endpoints: endpoints_display,
        relay_hints,
    }))
}

fn discover_lan_endpoints(port: u16) -> anyhow::Result<Vec<Endpoint>> {
    let local_addrs = crate::transport::lan::get_local_ip_addresses()?;
    let mut endpoints = Vec::new();

    for ip in local_addrs {
        let addr = SocketAddr::new(ip, port);
        endpoints.push(Endpoint {
            kind: EndpointKind::Lan,
            addr: Some(addr),
            priority: 10,
            timeout_ms: 1200,
        });
    }

    Ok(endpoints)
}

async fn discover_wan_endpoint(
    port: u16,
) -> anyhow::Result<(Endpoint, Arc<tokio::net::UdpSocket>)> {
    let (sock, ext_addr) = crate::transport::wan_direct::try_direct_port_forward(port).await?;
    let sock = Arc::new(sock);

    let endpoint = Endpoint {
        kind: EndpointKind::Wan,
        addr: Some(ext_addr),
        priority: 20,
        timeout_ms: 2000,
    };

    Ok((endpoint, sock))
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

fn random_tag16() -> u16 {
    let mut buf = [0u8; 2];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    u16::from_be_bytes(buf)
}

fn random_port() -> u16 {
    let mut buf = [0u8; 2];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    MIN_EPHEMERAL_PORT + (u16::from_be_bytes(buf) % (MAX_PORT - MIN_EPHEMERAL_PORT))
}
