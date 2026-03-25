use axum::{
    extract::{ConnectInfo, Extension},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use secrecy::SecretString;
use std::{net::SocketAddr, sync::Arc};

use crate::config::PrivacyProfile;
use crate::crypto::{
    deserialize_cipher_packet_with_limit, now_ms, now_us, open, seal, serialize_cipher_packet,
    CipherPacket, ClearPayload, MAX_TCP_FRAME_BYTES,
};
use crate::derive::derive_from_secret;
use crate::state::CryptoTimer;

use super::types::{ConnectionResponse, OpenReq, OpenRes, SealReq, SealRes, SetPass, SetPassRes};
use super::ApiState;

pub(crate) async fn handle_set_passphrase(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<SetPass>,
) -> Result<Json<SetPassRes>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let secret = SecretString::from(req.passphrase);
    let params = derive_from_secret(&secret).map_err(|e| {
        tracing::error!("Derivation failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    state
        .app
        .set_crypto_params(params.key_enc, params.tag16, params.tag8)
        .await;
    Ok(Json(SetPassRes {
        status: "ok".to_string(),
        port: params.port,
        tag16: params.tag16,
    }))
}

pub(crate) async fn handle_seal(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<SealReq>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let (key_enc, tag16, tag8) = match state.app.get_crypto_params().await {
        Some(p) => p,
        None => return StatusCode::PRECONDITION_REQUIRED.into_response(),
    };

    let data = match general_purpose::STANDARD.decode(&req.data_b64) {
        Ok(d) => d,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let clear = ClearPayload {
        ts_ms: now_ms(),
        seq: now_us(),
        data,
    };

    // Utility endpoint: not for protocol frames. Uses random nonce.
    // Measure encrypt timing for metrics
    let timer = CryptoTimer::start();
    let pkt = match seal(&key_enc, tag16, tag8, &clear) {
        Ok(p) => {
            let metrics = state.app.get_metrics().await;
            metrics.record_encrypt_time(timer.elapsed()).await;
            p
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let packet_b64 = match serialize_cipher_packet(&pkt) {
        Ok(bytes) => general_purpose::STANDARD.encode(bytes),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    Json(SealRes { packet_b64 }).into_response()
}

pub(crate) async fn handle_open(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<OpenReq>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let (key_enc, tag16, tag8) = match state.app.get_crypto_params().await {
        Some(p) => p,
        None => return StatusCode::PRECONDITION_REQUIRED.into_response(),
    };

    let bytes = match general_purpose::STANDARD.decode(&req.packet_b64) {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let pkt: CipherPacket = match deserialize_cipher_packet_with_limit(&bytes, MAX_TCP_FRAME_BYTES)
    {
        Ok(p) => p,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let timer = CryptoTimer::start();
    if let Some(clear) = open(&key_enc, &pkt, tag16, tag8) {
        let metrics = state.app.get_metrics().await;
        metrics.record_decrypt_time(timer.elapsed()).await;
        Json(OpenRes {
            data_b64: general_purpose::STANDARD.encode(clear.data),
        })
        .into_response()
    } else {
        let metrics = state.app.get_metrics().await;
        metrics.record_connection_error().await;
        StatusCode::UNAUTHORIZED.into_response()
    }
}

pub(crate) async fn handle_disconnect(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<ConnectionResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    state.app.stop_all().await;
    state.app.clear_crypto_params().await;

    let mut current_state = state.app.get_connection_state().await;
    current_state.status = crate::state::ConnectionStatus::Disconnected;
    current_state.privacy_profile = PrivacyProfile::StandardPrivate;
    state.app.set_connection_state(current_state).await;

    Ok(Json(ConnectionResponse {
        status: "disconnected".into(),
        port: None,
        mode: "none".into(),
        peer: None,
        resume_status: None,
        privacy_profile: PrivacyProfile::StandardPrivate,
    }))
}
