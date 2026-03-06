use axum::http::StatusCode;
use axum::{
    extract::{ConnectInfo, Extension},
    Json,
};
use secrecy::SecretString;
use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, Mutex},
    time::sleep,
};

use super::connect_helpers;
use super::types::{ConnectionRequest, ConnectionResponse};
use super::{ApiError, ApiState, Streams};
use crate::transport::assist_inbox::{AssistInbox, AssistInboxRequest};
use crate::{
    config::{Config, ProductMode, TorRole, WanMode, DEFAULT_CHANNEL_CAPACITY},
    crypto::SessionKeyState,
    derive::{derive_from_secret, derive_tag8_from_key},
    offer::{OfferPayload, RoleHint},
    resume::HybridQrPayload,
    security::{RateLimiter, TimeValidator},
    transport::{self, Connection},
};

type ConnectResult = Result<Json<ConnectionResponse>, ApiError>;

fn connect_err(code: StatusCode, msg: &str) -> ApiError {
    ApiError {
        code: code.as_u16(),
        message: msg.to_string(),
    }
}

const CONNECT_RETRY_BUDGET: usize = 3;
const CONNECT_RETRY_BACKOFF_MS: u64 = 200;
const CONNECT_CIRCUIT_FAILURE_THRESHOLD: u32 = 6;
const CONNECT_CIRCUIT_COOLDOWN_SECS: u64 = 20;

#[derive(Debug, Default)]
struct ConnectCircuitBreaker {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

static CONNECT_CIRCUIT: OnceLock<Arc<Mutex<ConnectCircuitBreaker>>> = OnceLock::new();

fn connect_circuit() -> Arc<Mutex<ConnectCircuitBreaker>> {
    CONNECT_CIRCUIT
        .get_or_init(|| Arc::new(Mutex::new(ConnectCircuitBreaker::default())))
        .clone()
}

async fn ensure_connect_circuit_closed() -> Result<(), ApiError> {
    let circuit = connect_circuit();
    let guard = circuit.lock().await;
    if let Some(until) = guard.open_until {
        if Instant::now() < until {
            return Err(connect_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily unavailable, retry shortly",
            ));
        }
    }
    Ok(())
}

async fn record_connect_failure(context: &'static str) {
    let circuit = connect_circuit();
    let mut guard = circuit.lock().await;
    guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
    if guard.consecutive_failures >= CONNECT_CIRCUIT_FAILURE_THRESHOLD {
        guard.open_until =
            Some(Instant::now() + Duration::from_secs(CONNECT_CIRCUIT_COOLDOWN_SECS));
        tracing::warn!(
            "connect circuit opened for {}s after {} failures ({})",
            CONNECT_CIRCUIT_COOLDOWN_SECS,
            guard.consecutive_failures,
            context
        );
    } else {
        tracing::warn!(
            "connect failure #{} ({})",
            guard.consecutive_failures,
            context
        );
    }
}

async fn record_connect_success() {
    let circuit = connect_circuit();
    let mut guard = circuit.lock().await;
    guard.consecutive_failures = 0;
    guard.open_until = None;
}

pub(super) async fn get_connect_circuit_status() -> crate::state::CircuitBreakerStatus {
    let circuit = connect_circuit();
    let guard = circuit.lock().await;
    let now = Instant::now();

    let (state, next_attempt_in) = match guard.open_until {
        Some(until) if now < until => (
            crate::state::CircuitState::Open,
            Some(until.saturating_duration_since(now)),
        ),
        _ if guard.consecutive_failures > 0 => (crate::state::CircuitState::HalfOpen, None),
        _ => (crate::state::CircuitState::Closed, None),
    };

    crate::state::CircuitBreakerStatus {
        state,
        failure_count: guard.consecutive_failures,
        success_count: 0,
        next_attempt_in,
    }
}

async fn run_with_retry_budget<T, E, F, Fut>(
    op_name: &'static str,
    attempts: usize,
    base_backoff_ms: u64,
    mut op: F,
) -> std::result::Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<T, E>>,
    E: std::fmt::Display,
{
    let attempts = attempts.max(1);
    for attempt in 0..attempts {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt + 1 >= attempts {
                    return Err(e);
                }
                let backoff_ms = base_backoff_ms.saturating_mul(1u64 << (attempt as u32).min(5));
                tracing::warn!(
                    "{} attempt {}/{} failed: {}. retrying in {}ms",
                    op_name,
                    attempt + 1,
                    attempts,
                    e,
                    backoff_ms
                );
                sleep(Duration::from_millis(backoff_ms)).await;
            }
        }
    }
    unreachable!()
}
pub(crate) async fn handle_connect(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<ConnectionRequest>,
) -> ConnectResult {
    let app = state.app.clone();
    let streams = state.streams.clone();
    if !app.api_allow(addr.ip(), 5.0).await {
        return Err(connect_err(StatusCode::TOO_MANY_REQUESTS, "rate limit"));
    }
    if req.offer.is_some() && req.passphrase.is_some() {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "provide either passphrase or offer, not both",
        ));
    }
    if req.qr.is_some() && (req.offer.is_some() || req.passphrase.is_some()) {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "provide either qr or passphrase/offer, not both",
        ));
    }
    if req.offer.is_some() && req.target.is_some() {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "target not allowed with offer",
        ));
    }
    if req.qr.is_some() && req.target.is_some() {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "target not allowed with qr",
        ));
    }
    if req.target.is_some() && req.passphrase.is_none() {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "passphrase required for target connect",
        ));
    }

    let product_mode = req.product_mode;

    // Validate A/B request semantics
    if product_mode == ProductMode::Guaranteed && req.target_onion.is_some() {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "target_onion not allowed in guaranteed mode",
        ));
    }

    // Validate Tor config (Classic only)
    if product_mode == ProductMode::Classic
        && req.wan_mode == WanMode::Auto
        && req.tor_role == TorRole::Host
    {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "Auto mode is only valid with TorRole::Client",
        ));
    }
    if product_mode == ProductMode::Classic
        && (req.wan_mode == WanMode::Tor || req.wan_mode == WanMode::Auto)
        && req.tor_role == TorRole::Client
        && req.target_onion.is_none()
    {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "target_onion required for Tor Client mode",
        ));
    }

    // Validate target_onion format if provided (Classic only)
    if product_mode == ProductMode::Classic {
        if let Some(ref onion) = req.target_onion {
            if !onion.contains(':') || !onion.contains(".onion") {
                return Err(connect_err(
                    StatusCode::BAD_REQUEST,
                    "target_onion must be in format 'address.onion:PORT'",
                ));
            }
        }
    }

    ensure_connect_circuit_closed().await?;

    // Guaranteed mode: relay-backed transport with optional Tor egress.
    if product_mode == ProductMode::Guaranteed {
        if req.offer.is_some() || req.target.is_some() || req.target_onion.is_some() {
            return Err(connect_err(
                StatusCode::BAD_REQUEST,
                "offer/target not allowed in guaranteed mode",
            ));
        }
        if req.qr.is_some() {
            return Err(connect_err(
                StatusCode::BAD_REQUEST,
                "qr not allowed in guaranteed mode",
            ));
        }
        let passphrase = match req.passphrase {
            Some(p) => SecretString::from(p),
            None => return Err(connect_err(StatusCode::BAD_REQUEST, "passphrase required")),
        };
        let mut cfg = Config::from_env();
        if let Some(url) = req.guaranteed_relay_url.clone() {
            if !url.trim().is_empty() {
                cfg.guaranteed_relay_url = url;
            }
        }

        let params = derive_from_secret(&passphrase).map_err(|e| {
            tracing::error!("Derivation failed: {:?}", e);
            connect_err(StatusCode::INTERNAL_SERVER_ERROR, "operation failed")
        })?;
        let io = match crate::transport::guaranteed::establish_connection_guaranteed(
            &params,
            &cfg,
            req.guaranteed_egress,
        )
        .await
        {
            Ok(io) => io,
            Err(e) => {
                tracing::error!("Guaranteed connect failed: {:?}", e);
                record_connect_failure("guaranteed transport establish").await;
                return Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"));
            }
        };

        let noise_role = match req.local_role {
            Some(RoleHint::Host) => crate::session_noise::NoiseRole::Responder,
            Some(RoleHint::Client) => crate::session_noise::NoiseRole::Initiator,
            None => crate::session_noise::NoiseRole::Initiator,
        };

        let params_noise = match crate::session_noise::pq_noise_params() {
            Ok(p) => p,
            Err(_) => crate::session_noise::classic_noise_params()
                .map_err(|_| connect_err(StatusCode::BAD_GATEWAY, "operation failed"))?,
        };

        let session_key = match crate::session_noise::run_noise_upgrade_io(
            noise_role,
            {
                let io = io.clone();
                move |data: Vec<u8>| {
                    let io = io.clone();
                    async move { io.send(data).await }
                }
            },
            {
                let io = io.clone();
                move || {
                    let io = io.clone();
                    async move { io.recv().await }
                }
            },
            &params.key_enc,
            params.tag16,
            params.tag8,
            params_noise,
            io.max_packet_limit(),
        )
        .await
        {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("Guaranteed noise handshake failed: {:?}", e);
                record_connect_failure("guaranteed noise handshake").await;
                return Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"));
            }
        };

        let session_cipher = Arc::new(tokio::sync::RwLock::new(SessionKeyState::new(
            session_key,
            params.tag16,
            params.tag8,
            cfg.key_rotation_grace_ms(),
        )));
        let rotation_policy = cfg.key_rotation_policy();
        tracing::info!("Guaranteed noise upgrade completed");

        let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        app.set_tx_out(tx_out.clone()).await;

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        app.set_stop_tx(stop_tx).await;

        let updated_streams = Streams {
            tx: streams.tx,
            rx: streams.rx,
            tx_out,
        };

        let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
        let rl = RateLimiter::new(
            cfg.rate_limit_capacity,
            cfg.rate_limit_max_requests,
            rl_duration,
        );

        let stop_rx1 = stop_rx.clone();
        let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop_io(
            io.clone(),
            updated_streams.clone(),
            session_cipher.clone(),
            rl,
            stop_rx1,
        )
        .await;

        let stop_rx2 = stop_rx.clone();
        let metrics = app.get_metrics().await;
        let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop_io(
            io,
            rx_out,
            stop_rx2,
            metrics,
            session_cipher,
            rotation_policy,
            match noise_role {
                crate::session_noise::NoiseRole::Initiator => 0x01,
                crate::session_noise::NoiseRole::Responder => 0x02,
            },
        )
        .await;

        let mut s = app.get_connection_state().await;
        s.port = None;
        s.mode = Some("guaranteed".into());
        s.status = crate::state::ConnectionStatus::Connected;
        s.peer_address = None;
        app.set_connection_state(s).await;
        record_connect_success().await;

        return Ok(Json(ConnectionResponse {
            status: "connected".into(),
            port: None,
            mode: "guaranteed".into(),
            peer: None,
            resume_status: None,
        }));
    }

    let mut cfg = Config::from_env();
    cfg.wan_mode = req.wan_mode;
    cfg.tor_role = req.tor_role;
    if let Some(onion) = req.target_onion.clone() {
        cfg.tor_onion_addr = Some(onion);
    }

    if let Some(qr_str) = req.qr {
        let qr = match HybridQrPayload::decode(&qr_str) {
            Ok(q) => q,
            Err(e) => {
                tracing::warn!("Hybrid QR decode failed: {:?}", e);
                return Err(connect_err(StatusCode::BAD_REQUEST, "invalid request"));
            }
        };
        let offer_b64 = qr.offer.clone();
        let resume = qr.resume_params();
        let offer = match OfferPayload::decode(&offer_b64) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!("Offer decode failed: {:?}", e);
                return Err(connect_err(StatusCode::BAD_REQUEST, "invalid request"));
            }
        };
        let time_validator = TimeValidator::new();
        if let Err(e) = offer.verify(&time_validator) {
            tracing::warn!("Offer verify failed: {:?}", e);
            return Err(connect_err(StatusCode::BAD_REQUEST, "invalid request"));
        }

        let local_role = req.local_role.unwrap_or(match offer.role_hint {
            RoleHint::Host => RoleHint::Client,
            RoleHint::Client => RoleHint::Host,
        });

        let result = match transport::establish_connection_from_offer_with_resume(
            &offer,
            &cfg,
            local_role.clone(),
            Some(resume),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("QR connect failed: {:?}", e);
                record_connect_failure("offer+resume establish").await;
                return Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"));
            }
        };

        let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
        let rl = RateLimiter::new(
            cfg.rate_limit_capacity,
            cfg.rate_limit_max_requests,
            rl_duration,
        );

        let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        app.set_tx_out(tx_out.clone()).await;
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        app.set_stop_tx(stop_tx).await;

        let updated_streams = Streams {
            tx: streams.tx,
            rx: streams.rx,
            tx_out,
        };

        tracing::info!("Session upgrade completed, session key installed");

        let stop_rx1 = stop_rx.clone();
        let tag8 = derive_tag8_from_key(&offer.rendezvous.key_enc).map_err(|e| {
            tracing::error!("Tag8 derivation failed: {:?}", e);
            connect_err(StatusCode::INTERNAL_SERVER_ERROR, "operation failed")
        })?;
        let session_cipher = Arc::new(tokio::sync::RwLock::new(SessionKeyState::new(
            result.session_key,
            offer.rendezvous.tag16,
            tag8,
            cfg.key_rotation_grace_ms(),
        )));
        let rotation_policy = cfg.key_rotation_policy();
        let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop(
            result.conn.clone(),
            updated_streams.clone(),
            session_cipher.clone(),
            rl,
            stop_rx1,
        )
        .await;

        let stop_rx2 = stop_rx.clone();
        let metrics = app.get_metrics().await;
        let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop(
            result.conn,
            rx_out,
            stop_rx2,
            metrics,
            session_cipher,
            rotation_policy,
            match local_role {
                RoleHint::Host => 0x02,
                RoleHint::Client => 0x01,
            },
        )
        .await;

        let mode = result.mode.clone();
        let peer = result.peer.clone();
        let mut s = app.get_connection_state().await;
        s.port = Some(offer.rendezvous.port);
        s.mode = Some(mode.clone());
        s.status = crate::state::ConnectionStatus::Connected;
        s.peer_address = peer.clone();
        app.set_connection_state(s).await;

        let resume_status = match result.resume_used {
            Some(true) => Some("used".to_string()),
            Some(false) => Some("fallback".to_string()),
            None => None,
        };
        record_connect_success().await;
        return Ok(Json(ConnectionResponse {
            status: "connected".into(),
            port: Some(offer.rendezvous.port),
            mode,
            peer,
            resume_status,
        }));
    }

    if let Some(offer_b64) = req.offer {
        let offer = match OfferPayload::decode(&offer_b64) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!("Offer decode failed: {:?}", e);
                return Err(connect_err(StatusCode::BAD_REQUEST, "invalid request"));
            }
        };
        let time_validator = TimeValidator::new();
        if let Err(e) = offer.verify(&time_validator) {
            tracing::warn!("Offer verify failed: {:?}", e);
            return Err(connect_err(StatusCode::BAD_REQUEST, "invalid request"));
        }

        let local_role = req.local_role.unwrap_or(match offer.role_hint {
            RoleHint::Host => RoleHint::Client,
            RoleHint::Client => RoleHint::Host,
        });

        let result = match transport::establish_connection_from_offer(
            &offer,
            &cfg,
            local_role.clone(),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Offer connect failed: {:?}", e);
                record_connect_failure("offer establish").await;
                return Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"));
            }
        };

        let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
        let rl = RateLimiter::new(
            cfg.rate_limit_capacity,
            cfg.rate_limit_max_requests,
            rl_duration,
        );

        let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        app.set_tx_out(tx_out.clone()).await;
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        app.set_stop_tx(stop_tx).await;

        let updated_streams = Streams {
            tx: streams.tx,
            rx: streams.rx,
            tx_out,
        };

        tracing::info!("Noise upgrade completed, session key installed");

        let stop_rx1 = stop_rx.clone();
        let tag8 = derive_tag8_from_key(&offer.rendezvous.key_enc).map_err(|e| {
            tracing::error!("Tag8 derivation failed: {:?}", e);
            connect_err(StatusCode::INTERNAL_SERVER_ERROR, "operation failed")
        })?;
        let session_cipher = Arc::new(tokio::sync::RwLock::new(SessionKeyState::new(
            result.session_key,
            offer.rendezvous.tag16,
            tag8,
            cfg.key_rotation_grace_ms(),
        )));
        let rotation_policy = cfg.key_rotation_policy();
        let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop(
            result.conn.clone(),
            updated_streams.clone(),
            session_cipher.clone(),
            rl,
            stop_rx1,
        )
        .await;

        let stop_rx2 = stop_rx.clone();
        let metrics = app.get_metrics().await;
        let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop(
            result.conn,
            rx_out,
            stop_rx2,
            metrics,
            session_cipher,
            rotation_policy,
            match local_role {
                RoleHint::Host => 0x02,
                RoleHint::Client => 0x01,
            },
        )
        .await;

        let mode = result.mode.clone();
        let peer = result.peer.clone();
        let mut s = app.get_connection_state().await;
        s.port = Some(offer.rendezvous.port);
        s.mode = Some(mode.clone());
        s.status = crate::state::ConnectionStatus::Connected;
        s.peer_address = peer.clone();
        app.set_connection_state(s).await;
        record_connect_success().await;

        return Ok(Json(ConnectionResponse {
            status: "connected".into(),
            port: Some(offer.rendezvous.port),
            mode,
            peer,
            resume_status: None,
        }));
    }

    let passphrase = match req.passphrase {
        Some(p) => SecretString::from(p),
        None => {
            return Err(connect_err(StatusCode::BAD_REQUEST, "passphrase required"));
        }
    };

    let params = derive_from_secret(&passphrase).map_err(|e| {
        tracing::error!("Derivation failed: {:?}", e);
        connect_err(StatusCode::INTERNAL_SERVER_ERROR, "operation failed")
    })?;

    if !cfg.assist_relays.is_empty() {
        let is_host = match req.local_role {
            Some(RoleHint::Host) => true,
            Some(RoleHint::Client) => false,
            None => req.tor_role == TorRole::Host,
        };
        let state_snapshot = app.get_connection_state().await;
        if is_host && state_snapshot.status == crate::state::ConnectionStatus::Disconnected {
            for relay in cfg.assist_relays.clone() {
                let (inbox, mut rx) = AssistInbox::new(relay.clone(), params.clone());
                tokio::spawn(async move {
                    while let Some(req) = rx.recv().await {
                        match req {
                            AssistInboxRequest::V4(req) => {
                                tracing::info!("Assist request received: {:?}", req.request_id);
                            }
                            AssistInboxRequest::V5(req) => {
                                tracing::info!("Assist request v5 received: {:?}", req.request_id);
                            }
                        }
                    }
                });
                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    let _ = inbox.run(&cfg_clone).await;
                });
            }
        }
    }
    if let Some(target) = req.target.clone() {
        let conn = match run_with_retry_budget(
            "target_connect",
            CONNECT_RETRY_BUDGET,
            CONNECT_RETRY_BACKOFF_MS,
            || transport::connect_to(&target, &params, &cfg),
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Target connect failed: {:?}", e);
                record_connect_failure("target connect").await;
                return Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"));
            }
        };

        let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
        let rl = RateLimiter::new(
            cfg.rate_limit_capacity,
            cfg.rate_limit_max_requests,
            rl_duration,
        );

        let noise_role = match req.local_role {
            Some(RoleHint::Host) => crate::session_noise::NoiseRole::Responder,
            Some(RoleHint::Client) => crate::session_noise::NoiseRole::Initiator,
            None => crate::session_noise::NoiseRole::Initiator,
        };

        let session_key = match crate::session_noise::run_noise_upgrade(
            noise_role,
            &conn,
            &params.key_enc,
            params.tag16,
            params.tag8,
        )
        .await
        {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("Noise handshake failed: {:?}", e);
                record_connect_failure("target noise handshake").await;
                return Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"));
            }
        };

        let session_cipher = Arc::new(tokio::sync::RwLock::new(SessionKeyState::new(
            session_key,
            params.tag16,
            params.tag8,
            cfg.key_rotation_grace_ms(),
        )));
        let rotation_policy = cfg.key_rotation_policy();
        tracing::info!("Noise upgrade completed, session key installed");

        let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        app.set_tx_out(tx_out.clone()).await;

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        app.set_stop_tx(stop_tx).await;

        let updated_streams = Streams {
            tx: streams.tx,
            rx: streams.rx,
            tx_out,
        };

        let mode = match &conn {
            Connection::Lan(_, _) => "lan",
            Connection::Wan(_, _) => "wan",
            Connection::WanTorStream { .. } => "wan_tor",
            Connection::WanTcpStream { .. } => "wan_tcp",
            Connection::Quic(_) => "quic",
            Connection::WebRtc(_) => "webrtc",
        }
        .to_string();

        let stop_rx1 = stop_rx.clone();

        let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop(
            conn.clone(),
            updated_streams.clone(),
            session_cipher.clone(),
            rl,
            stop_rx1,
        )
        .await;

        let stop_rx2 = stop_rx.clone();

        let metrics = app.get_metrics().await;
        let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop(
            conn,
            rx_out,
            stop_rx2,
            metrics,
            session_cipher,
            rotation_policy,
            match noise_role {
                crate::session_noise::NoiseRole::Initiator => 0x01,
                crate::session_noise::NoiseRole::Responder => 0x02,
            },
        )
        .await;

        let peer = Some(target.clone());
        let mut s = app.get_connection_state().await;
        s.port = Some(params.port);
        s.mode = Some(mode.clone());
        s.status = crate::state::ConnectionStatus::Connected;
        s.peer_address = peer.clone();
        app.set_connection_state(s).await;
        record_connect_success().await;

        return Ok(Json(ConnectionResponse {
            status: "connected".into(),
            port: Some(params.port),
            mode,
            peer,
            resume_status: None,
        }));
    }

    match run_with_retry_budget(
        "establish_connection",
        CONNECT_RETRY_BUDGET,
        CONNECT_RETRY_BACKOFF_MS,
        || transport::establish_connection(&params, &cfg),
    )
    .await
    {
        Ok(conn) => {
            let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
            let rl = RateLimiter::new(
                cfg.rate_limit_capacity,
                cfg.rate_limit_max_requests,
                rl_duration,
            );

            // Determine Noise Role based on local role override or config
            let noise_role = match req.local_role {
                Some(RoleHint::Host) => crate::session_noise::NoiseRole::Responder,
                Some(RoleHint::Client) => crate::session_noise::NoiseRole::Initiator,
                None => {
                    if req.tor_role == TorRole::Host {
                        crate::session_noise::NoiseRole::Responder
                    } else {
                        crate::session_noise::NoiseRole::Initiator
                    }
                }
            };

            if let Connection::Wan(sock, _) = &conn {
                let state_snapshot = app.get_connection_state().await;
                if state_snapshot.status == crate::state::ConnectionStatus::Connecting
                    || state_snapshot.status == crate::state::ConnectionStatus::Connected
                {
                    let mode = state_snapshot.mode.clone().unwrap_or_else(|| "wan".into());
                    return Ok(Json(ConnectionResponse {
                        status: format!("{:?}", state_snapshot.status).to_lowercase(),
                        port: state_snapshot.port,
                        mode,
                        peer: state_snapshot.peer_address,
                        resume_status: None,
                    }));
                }

                let sock = sock.clone();
                let params_bg = params.clone();
                let cfg = cfg.clone();
                let state_bg = app.clone();
                let streams_bg = streams.clone();
                let noise_role = crate::session_noise::NoiseRole::Responder;
                tokio::spawn(async move {
                    if let Err(e) = connect_helpers::accept_wan_direct_and_spawn(
                        sock, params_bg, cfg, state_bg, streams_bg, noise_role,
                    )
                    .await
                    {
                        tracing::error!("WAN listen failed: {}", e);
                    }
                });

                let mut s = app.get_connection_state().await;
                s.port = Some(params.port);
                s.mode = Some("wan".into());
                s.status = crate::state::ConnectionStatus::Connecting;
                s.peer_address = None;
                app.set_connection_state(s).await;
                record_connect_success().await;

                return Ok(Json(ConnectionResponse {
                    status: "listening".into(),
                    port: Some(params.port),
                    mode: "wan".into(),
                    peer: None,
                    resume_status: None,
                }));
            }

            // Perform Noise Session Upgrade
            let session_key = match crate::session_noise::run_noise_upgrade(
                noise_role,
                &conn,
                &params.key_enc,
                params.tag16,
                params.tag8,
            )
            .await
            {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!("Noise handshake failed: {:?}", e);
                    record_connect_failure("direct noise handshake").await;
                    return Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"));
                }
            };

            let session_cipher = Arc::new(tokio::sync::RwLock::new(SessionKeyState::new(
                session_key,
                params.tag16,
                params.tag8,
                cfg.key_rotation_grace_ms(),
            )));
            let rotation_policy = cfg.key_rotation_policy();
            tracing::info!("Noise upgrade completed, session key installed");

            // Crea canale per sender task
            let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
            app.set_tx_out(tx_out.clone()).await;

            // Crea canale per shutdown
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            app.set_stop_tx(stop_tx).await;

            // Sostituisci il tx_out in streams con quello appena creato
            let updated_streams = Streams {
                tx: streams.tx,
                rx: streams.rx,
                tx_out,
            };

            let mode = match &conn {
                Connection::Lan(_, _) => "lan",
                Connection::Wan(_, _) => "wan",
                Connection::WanTorStream { .. } => "wan_tor",
                Connection::WanTcpStream { .. } => "wan_tcp",
                Connection::Quic(_) => "quic",
                Connection::WebRtc(_) => "webrtc",
            }
            .to_string();

            // Avvia tasks con controlli di sicurezza
            let stop_rx1 = stop_rx.clone();

            let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop(
                conn.clone(),
                updated_streams.clone(),
                session_cipher.clone(),
                rl,
                stop_rx1,
            )
            .await;

            let stop_rx2 = stop_rx.clone();

            let peer_addr = conn.peer_addr().map(|addr| addr.to_string());
            let metrics = app.get_metrics().await;
            let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop(
                conn,
                rx_out,
                stop_rx2,
                metrics,
                session_cipher,
                rotation_policy,
                match noise_role {
                    crate::session_noise::NoiseRole::Initiator => 0x01,
                    crate::session_noise::NoiseRole::Responder => 0x02,
                },
            )
            .await;

            // Aggiorna stato
            let mut s = app.get_connection_state().await;
            s.port = Some(params.port);
            s.mode = Some(mode.clone());
            s.status = crate::state::ConnectionStatus::Connected;
            s.peer_address = peer_addr.clone();
            app.set_connection_state(s).await;
            record_connect_success().await;

            Ok(Json(ConnectionResponse {
                status: "connected".into(),
                port: Some(params.port),
                mode,
                peer: peer_addr,
                resume_status: None,
            }))
        }
        Err(e) => {
            let mut s = app.get_connection_state().await;
            s.status = crate::state::ConnectionStatus::Error(e.to_string());
            app.set_connection_state(s).await;

            tracing::error!("Connect failed: {:?}", e);
            record_connect_failure("establish connection").await;
            Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"))
        }
    }
}
