use axum::{
    extract::{ConnectInfo, Extension, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};

use crate::config::Config;
use crate::network_telemetry;
use crate::network_telemetry::{FallbackEvent, NatRuntimeMetrics};
use crate::state::{CircuitBreakerStatus, DebugMetrics};
use crate::transport::dandelion::DandelionMode;
use crate::transport::stun::StunServerScore;

use super::ApiState;

#[derive(Debug, Serialize)]
pub(crate) struct DandelionPolicySnapshot {
    pub min_delay_secs: u64,
    pub max_delay_secs: u64,
    pub target_batch_size: usize,
    pub fluff_tick_ms: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct NetworkCapabilities {
    pub runtime_connection_mode: Option<String>,
    pub configured_assist_relays: usize,
    pub assist_obfuscation_v5_enabled: bool,
    pub guaranteed_relay_configured: bool,
    pub nat_detection_servers: usize,
    pub multipath_policy: String,
    pub wan_mode: String,
    pub tor_role: String,
    pub pluggable_transport: String,
    pub dandelion_mode: String,
    pub dandelion_stem_outbound_enabled: bool,
    pub dandelion_policy: DandelionPolicySnapshot,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FallbackQuery {
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub(crate) struct FallbacksResponse {
    pub items: Vec<FallbackEvent>,
}

#[derive(Debug, Serialize)]
pub(crate) struct NatMetricsResponse {
    pub nat: NatRuntimeMetrics,
    pub stun_servers: Vec<StunServerScore>,
}

/// Handle /v1/metrics - In-memory debugging metrics (zero persistence)
pub(crate) async fn handle_metrics(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<DebugMetrics>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let metrics = state.app.get_metrics().await;
    let debug_metrics = DebugMetrics::from_collector(&metrics).await;

    Ok(Json(debug_metrics))
}

/// Handle /v1/circuit - Circuit breaker status for debugging
pub(crate) async fn handle_circuit_status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<CircuitBreakerStatus>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let status = super::connect::get_connect_circuit_status().await;
    Ok(Json(status))
}

/// Handle /v1/capabilities - Config/runtime capability matrix for networking diagnostics
pub(crate) async fn handle_capabilities(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<NetworkCapabilities>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let cfg = Config::from_env();
    let conn_state = state.app.get_connection_state().await;

    let dandelion_mode = DandelionMode::from_env();
    let dandelion_policy = dandelion_mode.effective_policy();

    let snapshot = NetworkCapabilities {
        runtime_connection_mode: conn_state.mode,
        configured_assist_relays: cfg.assist_relays.len(),
        assist_obfuscation_v5_enabled: cfg.assist_obfuscation_v5,
        guaranteed_relay_configured: !cfg.guaranteed_relay_url.trim().is_empty(),
        nat_detection_servers: cfg.nat_detection_servers.len(),
        multipath_policy: cfg.multipath_policy,
        wan_mode: format!("{:?}", cfg.wan_mode).to_lowercase(),
        tor_role: format!("{:?}", cfg.tor_role).to_lowercase(),
        pluggable_transport: format!("{:?}", cfg.pluggable_transport),
        dandelion_mode: dandelion_mode.as_str().to_string(),
        dandelion_stem_outbound_enabled: dandelion_mode.stem_enabled(),
        dandelion_policy: DandelionPolicySnapshot {
            min_delay_secs: dandelion_policy.min_delay_secs,
            max_delay_secs: dandelion_policy.max_delay_secs,
            target_batch_size: dandelion_policy.target_batch_size,
            fluff_tick_ms: dandelion_policy.fluff_tick_ms,
        },
    };

    Ok(Json(snapshot))
}

/// Handle /v1/connect/fallbacks - recent fallback reasons (ring buffer)
pub(crate) async fn handle_connect_fallbacks(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(query): Query<FallbackQuery>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<FallbacksResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let items = network_telemetry::recent_fallback_events(limit);
    Ok(Json(FallbacksResponse { items }))
}

/// Handle /v1/network/nat-metrics - NAT/STUN runtime metrics (in-memory)
pub(crate) async fn handle_nat_metrics(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<NatMetricsResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let nat = network_telemetry::nat_metrics_snapshot();
    let stun_servers = crate::transport::stun::stun_server_scores_snapshot().await;

    Ok(Json(NatMetricsResponse { nat, stun_servers }))
}
