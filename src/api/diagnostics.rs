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
    pub runtime_privacy_profile: String,
    pub configured_assist_relays: usize,
    pub assist_obfuscation_v5_enabled: bool,
    pub guaranteed_relay_configured: bool,
    pub nat_detection_servers: usize,
    pub multipath_policy: String,
    pub wan_mode: String,
    pub tor_role: String,
    pub pluggable_profile: String,
    pub pluggable_transport: String,
    pub pluggable_transport_class: String,
    pub dandelion_mode: String,
    pub dandelion_stem_outbound_enabled: bool,
    pub dandelion_policy: DandelionPolicySnapshot,
    pub quic: bool,
    pub webrtc: bool,
    pub pq_primitives: bool,
    pub orp_standard: bool,
    pub orp_highrisk: bool,
    pub keeper_replication: bool,
    pub bridge_bootstrap: bool,
    pub privacy_tiers: Vec<String>,
    pub api_version: String,
    pub wire_compatibility_window: String,
    pub deprecation_window: String,
    pub interop_matrix: String,
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

#[derive(Debug, Serialize)]
pub(crate) struct HighRiskGateStatus {
    pub available: bool,
    pub public_claim_unlocked: bool,
    pub relay_nodes_required: usize,
    pub relay_nodes_observed: Option<usize>,
    pub operator_identities_required: usize,
    pub operator_identities_observed: Option<usize>,
    pub region_buckets_required: usize,
    pub region_buckets_observed: Option<usize>,
    pub max_operator_share_allowed_pct: u8,
    pub max_operator_share_observed_pct: Option<u8>,
    pub requires_distinct_three_hop_path: bool,
    pub valid_three_hop_path_observed: Option<bool>,
    pub active_participants_required: usize,
    pub active_participants_observed: Option<usize>,
    pub gate_reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RouteStatusResponse {
    pub orp_enabled: bool,
    pub route_cache_size: usize,
    pub route_offers_count: usize,
    pub last_orp_activity_ms: Option<u64>,
    pub active_spaces: usize,
    pub route_classes: Vec<String>,
    pub standard_private_available: bool,
    pub high_risk: HighRiskGateStatus,
}

#[derive(Debug, Serialize)]
pub(crate) struct KeeperStatusResponse {
    pub retention_tier: String,
    pub replay_window_slots: usize,
    pub keeper_replication_enabled: bool,
    pub keeper_replication_factor: usize,
    pub operator_model: String,
    pub operator_enrollment: String,
    pub monetization_model: String,
    pub availability_slo_target: String,
    pub bootstrap_peer_count: usize,
    pub discovery_bootstrap_peer_count: usize,
    pub bridge_bootstrap_enabled: bool,
    pub bridge_hint_count: usize,
    pub notes: Vec<String>,
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
        runtime_privacy_profile: serde_json::to_string(&conn_state.privacy_profile)
            .unwrap_or_else(|_| "\"standard-private\"".to_string())
            .trim_matches('"')
            .to_string(),
        configured_assist_relays: cfg.assist_relays.len(),
        assist_obfuscation_v5_enabled: cfg.assist_obfuscation_v5,
        guaranteed_relay_configured: !cfg.guaranteed_relay_url.trim().is_empty(),
        nat_detection_servers: cfg.nat_detection_servers.len(),
        multipath_policy: cfg.multipath_policy,
        wan_mode: format!("{:?}", cfg.wan_mode).to_lowercase(),
        tor_role: format!("{:?}", cfg.tor_role).to_lowercase(),
        pluggable_profile: format!("{:?}", cfg.pluggable_profile).to_lowercase(),
        pluggable_transport: cfg.pluggable_transport.id().to_string(),
        pluggable_transport_class: cfg.pluggable_transport.class().to_string(),
        dandelion_mode: dandelion_mode.as_str().to_string(),
        dandelion_stem_outbound_enabled: dandelion_mode.stem_enabled(),
        dandelion_policy: DandelionPolicySnapshot {
            min_delay_secs: dandelion_policy.min_delay_secs,
            max_delay_secs: dandelion_policy.max_delay_secs,
            target_batch_size: dandelion_policy.target_batch_size,
            fluff_tick_ms: dandelion_policy.fluff_tick_ms,
        },
        quic: cfg!(feature = "quic"),
        webrtc: cfg!(feature = "webrtc"),
        pq_primitives: cfg!(feature = "pq"),
        orp_standard: true,
        orp_highrisk: false,
        keeper_replication: false,
        bridge_bootstrap: !cfg.assist_relays.is_empty(),
        privacy_tiers: vec!["standard-private".to_string(), "high-risk".to_string()],
        api_version: "/v1".to_string(),
        wire_compatibility_window: "CipherPacket V2 plus additive ORP frame extensions".to_string(),
        deprecation_window:
            "One additive minor line; breaking wire changes require explicit migration notes"
                .to_string(),
        interop_matrix: "docs/interop.md".to_string(),
    };

    Ok(Json(snapshot))
}

/// Handle /v1/routes/status - ORP control-plane diagnostics and high-risk gate status
pub(crate) async fn handle_routes_status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<RouteStatusResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let status = match state.app.ethersync_status().await {
        Ok(status) => status,
        Err(_) => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };

    let relay_nodes_observed = if let Some(node) = state.app.orp_node().await {
        let cache = node.route_cache().lock().await;
        Some(
            cache
                .announcements
                .values()
                .filter(|ann| ann.frame.capabilities.can_relay)
                .count(),
        )
    } else {
        None
    };

    let high_risk = HighRiskGateStatus {
        available: status.high_risk_available,
        public_claim_unlocked: false,
        relay_nodes_required: 64,
        relay_nodes_observed,
        operator_identities_required: 16,
        operator_identities_observed: None,
        region_buckets_required: 6,
        region_buckets_observed: None,
        max_operator_share_allowed_pct: 15,
        max_operator_share_observed_pct: None,
        requires_distinct_three_hop_path: true,
        valid_three_hop_path_observed: None,
        active_participants_required: 1024,
        active_participants_observed: Some(status.route_cache_size.max(status.peer_count)),
        gate_reasons: status.high_risk_gate_reasons.clone(),
    };

    Ok(Json(RouteStatusResponse {
        orp_enabled: status.orp_enabled,
        route_cache_size: status.route_cache_size,
        route_offers_count: status.route_offers_count,
        last_orp_activity_ms: status.last_orp_activity_ms,
        active_spaces: status.spaces.len(),
        route_classes: vec![
            "direct".to_string(),
            "assist".to_string(),
            "orp-standard".to_string(),
            "tor-fallback".to_string(),
        ],
        standard_private_available: true,
        high_risk,
    }))
}

/// Handle /v1/keepers/status - retention and managed-network scaffold status
pub(crate) async fn handle_keepers_status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<KeeperStatusResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let status = match state.app.ethersync_status().await {
        Ok(status) => status,
        Err(_) => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };

    Ok(Json(KeeperStatusResponse {
        retention_tier: status.retention_tier,
        replay_window_slots: status.replay_window_slots,
        keeper_replication_enabled: status.keeper_replication_enabled,
        keeper_replication_factor: status.keeper_replication_factor,
        operator_model: "managed-plus-open".to_string(),
        operator_enrollment: "first-party and partner-operated; third-party enrollment not open yet"
            .to_string(),
        monetization_model:
            "subscription, enterprise retention tiers, and managed network services".to_string(),
        availability_slo_target: "99.9% keeper-backed replay for managed tiers once enabled"
            .to_string(),
        bootstrap_peer_count: status.bootstrap_peer_count,
        discovery_bootstrap_peer_count: status.discovery_bootstrap_peer_count,
        bridge_bootstrap_enabled: status.bridge_bootstrap_enabled,
        bridge_hint_count: status.bridge_hint_count,
        notes: vec![
            "Current runtime is local-retention only; keeper replication is scaffolded but disabled"
                .to_string(),
            "Bootstrap remains hybrid: static discovery peers, assist relays, and future bridge bundles"
                .to_string(),
            "Keeper nodes are planned to store encrypted envelopes and minimal availability metadata"
                .to_string(),
        ],
    }))
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
