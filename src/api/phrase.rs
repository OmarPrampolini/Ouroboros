use axum::{
    extract::{ConnectInfo, Extension},
    http::StatusCode,
    Json,
};
use secrecy::SecretString;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::mpsc;

use crate::config::{Config, PrivacyProfile};
use crate::derive::derive_from_secret;
use crate::onion::validate_onion_addr;
use crate::phrase::PhraseInvite;
use crate::security::RateLimiter;
use crate::state::PhraseStatus;
use crate::transport::Connection;
use crate::{crypto::SessionKeyState, session_noise::NoiseRole};

use super::types::{
    ConnectionResponse, PhraseJoinRequest, PhraseOpenRequest, PhraseOpenResponse,
    PhraseStatusResponse,
};
use super::{ApiState, Streams};

const PHRASE_VIRT_PORT: u16 = 443;

pub(crate) async fn handle_phrase_open(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<PhraseOpenRequest>,
) -> Result<Json<PhraseOpenResponse>, StatusCode> {
    let app = state.app.clone();
    let streams = state.streams.clone();
    if !app.api_allow(addr.ip(), 2.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if req.passphrase.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if app.get_phrase_status().await != PhraseStatus::Closed {
        return Err(StatusCode::CONFLICT);
    }
    app.set_phrase_status(PhraseStatus::Opening).await;

    let cfg = Config::from_env();
    let passphrase = req.passphrase;
    let secret = SecretString::from(passphrase);
    let params = derive_from_secret(&secret).map_err(|e| {
        tracing::error!("Derivation failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let local_port = listener
        .local_addr()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .port();
    let listener = Arc::new(listener);

    let tor = app
        .get_or_start_tor(&cfg)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let onion = {
        let tor = tor.lock().await;
        tor.add_onion_with_port(PHRASE_VIRT_PORT, local_port)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?
    };

    app.set_phrase_onion(Some(onion.clone())).await;
    app.set_phrase_listener(Some(listener.clone())).await;
    app.set_phrase_status(PhraseStatus::Open).await;

    let invite = PhraseInvite {
        ver: 1,
        product: "A".to_string(),
        policy: "tor".to_string(),
        onion: onion.clone(),
        virt_port: PHRASE_VIRT_PORT,
    };
    let invite_str = invite
        .encode()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let state_bg = app.clone();
    let streams_bg = streams.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            if state_bg.get_phrase_status().await == PhraseStatus::Closed {
                break;
            }
            let (stream, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("Phrase accept failed: {:?}", e);
                    continue;
                }
            };
            let (reader, writer) = stream.into_split();
            let conn = Connection::WanTorStream {
                reader: Arc::new(tokio::sync::Mutex::new(reader)),
                writer: Arc::new(tokio::sync::Mutex::new(writer)),
            };

            let noise_role = NoiseRole::Responder;
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
                    continue;
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

            let (tx_out, rx_out) = mpsc::channel(crate::config::DEFAULT_CHANNEL_CAPACITY);
            state_bg.set_tx_out(tx_out.clone()).await;

            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            state_bg.set_stop_tx(stop_tx).await;

            let updated_streams = Streams {
                tx: streams_bg.tx,
                rx: streams_bg.rx,
                tx_out,
            };

            let mode = "phrase_tor".to_string();
            let stop_rx1 = stop_rx.clone();
            let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
            let rl = RateLimiter::new(
                cfg.rate_limit_capacity,
                cfg.rate_limit_max_requests,
                rl_duration,
            );
            let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop(
                conn.clone(),
                updated_streams.clone(),
                session_cipher.clone(),
                rl,
                stop_rx1,
            )
            .await;

            let stop_rx2 = stop_rx.clone();
            let metrics = state_bg.get_metrics().await;
            let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop(
                conn,
                rx_out,
                stop_rx2,
                metrics,
                session_cipher,
                rotation_policy,
                match noise_role {
                    NoiseRole::Initiator => 0x01,
                    NoiseRole::Responder => 0x02,
                },
            )
            .await;

            let mut s = state_bg.get_connection_state().await;
            s.port = Some(local_port);
            s.mode = Some(mode);
            s.status = crate::state::ConnectionStatus::Connected;
            s.peer_address = None;
            s.privacy_profile = PrivacyProfile::StandardPrivate;
            state_bg.set_connection_state(s).await;

            state_bg.set_phrase_status(PhraseStatus::Connected).await;
            break;
        }
    });
    app.set_phrase_accept_task(Some(accept_task)).await;

    Ok(Json(PhraseOpenResponse {
        onion,
        virt_port: PHRASE_VIRT_PORT,
        invite: invite_str,
    }))
}

pub(crate) async fn handle_phrase_close(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<axum::http::StatusCode, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    if let Some(task) = state.app.take_phrase_accept_task().await {
        task.abort();
    }
    state.app.take_phrase_listener().await;
    state.app.stop_all().await;

    if let Some(onion) = state.app.get_phrase_onion().await {
        if let Ok(tor) = state.app.get_or_start_tor(&Config::from_env()).await {
            let tor = tor.lock().await;
            let _ = tor.del_onion(&onion).await;
        }
    }
    state.app.set_phrase_onion(None).await;
    state.app.set_phrase_status(PhraseStatus::Closed).await;
    let mut s = state.app.get_connection_state().await;
    s.status = crate::state::ConnectionStatus::Disconnected;
    s.privacy_profile = PrivacyProfile::StandardPrivate;
    state.app.set_connection_state(s).await;

    Ok(axum::http::StatusCode::OK)
}

pub(crate) async fn handle_phrase_join(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<PhraseJoinRequest>,
) -> Result<Json<ConnectionResponse>, StatusCode> {
    let app = state.app.clone();
    let streams = state.streams.clone();
    if !app.api_allow(addr.ip(), 2.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let invite = PhraseInvite::decode(&req.invite).map_err(|_| StatusCode::BAD_REQUEST)?;
    if invite.ver != 1 || invite.product != "A" || invite.policy != "tor" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let target = format!("{}:{}", invite.onion, invite.virt_port);
    if validate_onion_addr(&target).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.passphrase.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let cfg = Config::from_env();
    let tor = app
        .get_or_start_tor(&cfg)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let socks_addr = {
        let tor = tor.lock().await;
        tor.socks_addr()
    };

    let passphrase = req.passphrase;
    let secret = SecretString::from(passphrase);
    let params = derive_from_secret(&secret).map_err(|e| {
        tracing::error!("Derivation failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    app.set_phrase_status(PhraseStatus::Opening).await;
    let stream =
        crate::transport::wan_tor::try_tor_connect(&socks_addr, &target, None, Some(&target))
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let (reader, writer) = stream.into_split();
    let conn = Connection::WanTorStream {
        reader: Arc::new(tokio::sync::Mutex::new(reader)),
        writer: Arc::new(tokio::sync::Mutex::new(writer)),
    };

    let noise_role = NoiseRole::Initiator;
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
        Err(_) => {
            app.set_phrase_status(PhraseStatus::Error("handshake_failed".into()))
                .await;
            return Err(StatusCode::BAD_GATEWAY);
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

    let (tx_out, rx_out) = mpsc::channel(crate::config::DEFAULT_CHANNEL_CAPACITY);
    app.set_tx_out(tx_out.clone()).await;

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    app.set_stop_tx(stop_tx).await;

    let updated_streams = Streams {
        tx: streams.tx,
        rx: streams.rx,
        tx_out,
    };

    let mode = "phrase_tor".to_string();
    let stop_rx1 = stop_rx.clone();
    let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
    let rl = RateLimiter::new(
        cfg.rate_limit_capacity,
        cfg.rate_limit_max_requests,
        rl_duration,
    );
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
            NoiseRole::Initiator => 0x01,
            NoiseRole::Responder => 0x02,
        },
    )
    .await;

    let mut s = app.get_connection_state().await;
    s.port = Some(params.port);
    s.mode = Some(mode.clone());
    s.status = crate::state::ConnectionStatus::Connected;
    s.peer_address = Some(invite.onion);
    s.privacy_profile = PrivacyProfile::StandardPrivate;
    app.set_connection_state(s).await;

    app.set_phrase_status(PhraseStatus::Connected).await;

    Ok(Json(ConnectionResponse {
        status: "connected".into(),
        port: Some(params.port),
        mode,
        peer: None,
        resume_status: None,
        privacy_profile: PrivacyProfile::StandardPrivate,
    }))
}

pub(crate) async fn handle_phrase_status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<PhraseStatusResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let status = match state.app.get_phrase_status().await {
        PhraseStatus::Closed => "closed".to_string(),
        PhraseStatus::Opening => "opening".to_string(),
        PhraseStatus::Open => "open".to_string(),
        PhraseStatus::Connected => "connected".to_string(),
        PhraseStatus::Error(e) => format!("error:{e}"),
    };
    Ok(Json(PhraseStatusResponse {
        status,
        onion: state.app.get_phrase_onion().await,
    }))
}
