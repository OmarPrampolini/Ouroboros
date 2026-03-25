use axum::{
    extract::{ConnectInfo, Extension},
    http::StatusCode,
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::broadcast;
use tokio::time::interval;

use super::types::{
    EtherSyncJoinRequest, EtherSyncPeerAddRequest, EtherSyncPublishFileRequest,
    EtherSyncPublishRequest, EtherSyncStartRequest, KeeperBackfillRequest,
};
use super::{ApiError, ApiState};
use crate::state::{EtherSyncStartConfig, EtherSyncStatus, KeeperBackfillResult};

type EtherSyncResult<T> = Result<Json<T>, ApiError>;

pub(crate) async fn handle_start(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<EtherSyncStartRequest>,
) -> EtherSyncResult<EtherSyncStatus> {
    if !state.app.api_allow(addr.ip(), 2.0).await {
        return Err(ApiError::bad_request("rate limit"));
    }

    let peers = parse_peers(req.bootstrap_peers.unwrap_or_default())?;
    let mut cfg = EtherSyncStartConfig::default();
    if let Some(bind) = req.bind_addr {
        cfg.bind_addr = bind;
    }
    cfg.bootstrap_peers = peers;
    if let Some(v) = req.gossip_interval_secs {
        cfg.gossip_interval_secs = v;
    }
    if let Some(v) = req.sweep_interval_secs {
        cfg.sweep_interval_secs = v;
    }
    if let Some(v) = req.gossip_ttl {
        cfg.gossip_ttl = v;
    }
    if let Some(v) = req.enable_compression {
        cfg.enable_compression = v;
    }
    if let Some(v) = req.enable_orp {
        cfg.enable_orp = v;
    }

    let status = state
        .app
        .ethersync_start(cfg)
        .await
        .map_err(|e| ApiError::bad_request(&e.to_string()))?;
    Ok(Json(status))
}

pub(crate) async fn handle_stop(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> EtherSyncResult<EtherSyncStatus> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(ApiError::bad_request("rate limit"));
    }
    let status = state
        .app
        .ethersync_stop()
        .await
        .map_err(|e| ApiError::bad_request(&e.to_string()))?;
    Ok(Json(status))
}

pub(crate) async fn handle_status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> EtherSyncResult<EtherSyncStatus> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(ApiError::bad_request("rate limit"));
    }
    let status = state
        .app
        .ethersync_status()
        .await
        .map_err(|e| ApiError::bad_request(&e.to_string()))?;
    Ok(Json(status))
}

pub(crate) async fn handle_peer_add(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<EtherSyncPeerAddRequest>,
) -> EtherSyncResult<EtherSyncStatus> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(ApiError::bad_request("rate limit"));
    }

    let peer = req
        .addr
        .parse::<SocketAddr>()
        .map_err(|_| ApiError::bad_request("invalid peer addr"))?;
    let status = state
        .app
        .ethersync_add_peer(peer)
        .await
        .map_err(|e| ApiError::bad_request(&e.to_string()))?;
    Ok(Json(status))
}

pub(crate) async fn handle_join_space(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<EtherSyncJoinRequest>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    match state
        .app
        .ethersync_join_space(
            req.passphrase,
            req.label,
            req.retention_tier,
            req.replication_factor,
            req.route_bias,
        )
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(&e.to_string())),
        )
            .into_response(),
    }
}

pub(crate) async fn handle_publish(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<EtherSyncPublishRequest>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let payload = if let Some(payload_b64) = req.payload_b64 {
        match general_purpose::STANDARD.decode(payload_b64) {
            Ok(bytes) => bytes,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ApiError::bad_request("invalid payload_b64")),
                )
                    .into_response();
            }
        }
    } else if let Some(message) = req.message {
        message.into_bytes()
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request("message or payload_b64 required")),
        )
            .into_response();
    };

    match state.app.ethersync_publish(req.passphrase, payload).await {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(&e.to_string())),
        )
            .into_response(),
    }
}

pub(crate) async fn handle_publish_file(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<EtherSyncPublishFileRequest>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let file_bytes = match general_purpose::STANDARD.decode(req.file_b64) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request("invalid file_b64")),
            )
                .into_response();
        }
    };

    match state
        .app
        .ethersync_publish_file(req.passphrase, req.filename, file_bytes, req.chunk_size)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(&e.to_string())),
        )
            .into_response(),
    }
}

pub(crate) async fn handle_events_sse(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let mut rx = match state.app.ethersync_subscribe_events().await {
        Ok(rx) => rx,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let mut ticker = interval(Duration::from_millis(5000));

    let stream = async_stream::stream! {
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Ok(json) => {
                            yield Ok::<Event, Infallible>(Event::default().data(json));
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = ticker.tick() => {
                    yield Ok::<Event, Infallible>(Event::default().event("keepalive").data("ok"));
                }
            }
        }
    };

    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::new())
        .into_response()
}

pub(crate) async fn handle_keeper_backfill(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<KeeperBackfillRequest>,
) -> EtherSyncResult<KeeperBackfillResult> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(ApiError::bad_request("rate limit"));
    }

    let result = state
        .app
        .ethersync_keeper_backfill(req.passphrase, req.max_messages)
        .await
        .map_err(|e| ApiError::bad_request(&e.to_string()))?;
    Ok(Json(result))
}

fn parse_peers(input: Vec<String>) -> Result<Vec<SocketAddr>, ApiError> {
    let mut out = Vec::new();
    for raw in input {
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }
        let parsed = value
            .parse::<SocketAddr>()
            .map_err(|_| ApiError::bad_request("invalid bootstrap peer"))?;
        if !out.contains(&parsed) {
            out.push(parsed);
        }
    }
    Ok(out)
}
