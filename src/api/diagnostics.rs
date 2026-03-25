use axum::{
    extract::{ConnectInfo, Extension, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

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
    pub operator_id_hint: String,
    pub operator_region_hint: String,
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
    pub bootstrap_bundle_loaded: bool,
    pub bootstrap_bundle_relays: usize,
    pub bootstrap_bundle_bridges: usize,
    pub bootstrap_bundle_keepers: usize,
    pub bootstrap_bundle_usable: bool,
    pub bootstrap_bundle_structurally_weak: bool,
    pub bootstrap_bundle_stale: bool,
    pub bootstrap_bundle_warning_count: usize,
    pub bootstrap_bundle_error_count: usize,
    pub api_version: String,
    pub wire_compatibility_window: String,
    pub deprecation_window: String,
    pub interop_matrix: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct InteropResponse {
    pub api_version: String,
    pub local_api_scope: String,
    pub cipher_packet_anchor: String,
    pub wire_compatibility_window: String,
    pub deprecation_window: String,
    pub interop_matrix: String,
    pub orp_frames: Vec<String>,
    pub reserved_highrisk_frames: Vec<String>,
    pub ethersync_subspaces: BTreeMap<String, u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FallbackQuery {
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RouteDiscoverQuery {
    pub passphrase: String,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RouteInspectQuery {
    pub passphrase: String,
    pub target_tag: String,
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
    pub high_risk_control_plane_active: bool,
    pub high_risk_circuits_observed: usize,
    pub high_risk_active_circuits: usize,
    pub high_risk_closed_circuits: usize,
    pub high_risk_control_frames_observed: usize,
    pub high_risk_cover_packets_observed: usize,
    pub high_risk_last_activity_ms: Option<u64>,
    pub high_risk_recent_circuits: Vec<ethersync::HighRiskCircuitSnapshot>,
    pub active_spaces: usize,
    pub route_classes: Vec<String>,
    pub route_class_counts: BTreeMap<String, usize>,
    pub standard_private_available: bool,
    pub relay_nodes_observed: Option<usize>,
    pub bridge_nodes_observed: Option<usize>,
    pub keeper_nodes_observed: Option<usize>,
    pub distinct_operator_hints_observed: usize,
    pub managed_space_count: usize,
    pub bridge_preferred_space_count: usize,
    pub keeper_preferred_space_count: usize,
    pub high_risk: HighRiskGateStatus,
}

#[derive(Debug, Serialize)]
pub(crate) struct KeeperStatusResponse {
    pub retention_tier: String,
    pub replay_window_slots: usize,
    pub keeper_replication_enabled: bool,
    pub keeper_replication_factor: usize,
    pub pending_keeper_envelopes: usize,
    pub keeper_space_count: usize,
    pub archived_keeper_envelopes: usize,
    pub keeper_archive_space_count: usize,
    pub keeper_manifest_space_count: usize,
    pub keeper_candidate_shortfall_space_count: usize,
    pub managed_ready_space_count: usize,
    pub last_keeper_activity_ms: Option<u64>,
    pub managed_space_count: usize,
    pub bridge_preferred_space_count: usize,
    pub keeper_preferred_space_count: usize,
    pub operator_model: String,
    pub operator_enrollment: String,
    pub monetization_model: String,
    pub availability_slo_target: String,
    pub bootstrap_peer_count: usize,
    pub discovery_bootstrap_peer_count: usize,
    pub bridge_bootstrap_enabled: bool,
    pub bridge_hint_count: usize,
    pub bootstrap_bundle_loaded: bool,
    pub bootstrap_bundle_mirrors: usize,
    pub bootstrap_bundle_relays: usize,
    pub bootstrap_bundle_bridges: usize,
    pub bootstrap_bundle_keepers: usize,
    pub bootstrap_bundle_usable: bool,
    pub bootstrap_bundle_structurally_weak: bool,
    pub bootstrap_bundle_stale: bool,
    pub bootstrap_bundle_warning_count: usize,
    pub bootstrap_bundle_error_count: usize,
    pub operator_id_hint: String,
    pub operator_region_hint: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RouteDiscoverResponse {
    pub space_prefix: String,
    pub candidates: Vec<String>,
    pub used_orp: bool,
    pub used_bootstrap_bundle: bool,
    pub used_static_bootstrap: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct RouteInspectResponse {
    pub space_prefix: String,
    pub target_tag: String,
    pub route_bias: Option<String>,
    pub candidate_count: usize,
    pub candidates: Vec<crate::transport::orp::OrpCandidateSnapshot>,
}

fn parse_target_tag(raw: &str) -> Option<[u8; 8]> {
    let candidate = raw.trim().strip_prefix("orp:").unwrap_or(raw.trim());
    if candidate.len() != 16 || !candidate.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }

    let bytes = hex::decode(candidate).ok()?;
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&bytes);
    Some(tag)
}

fn route_bias_label(bias: crate::state::SpaceRouteBias) -> String {
    match bias {
        crate::state::SpaceRouteBias::Balanced => "balanced",
        crate::state::SpaceRouteBias::BridgePreferred => "bridge-preferred",
        crate::state::SpaceRouteBias::KeeperPreferred => "keeper-preferred",
        crate::state::SpaceRouteBias::DirectPreferred => "direct-preferred",
    }
    .to_string()
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
    let ethersync_status = state.app.ethersync_status().await.ok();
    let bootstrap_bundle = crate::bootstrap_bundle::summarize_bootstrap_bundle(&cfg);

    let dandelion_mode = DandelionMode::from_env();
    let dandelion_policy = dandelion_mode.effective_policy();

    let snapshot = NetworkCapabilities {
        runtime_connection_mode: conn_state.mode,
        runtime_privacy_profile: serde_json::to_string(&conn_state.privacy_profile)
            .unwrap_or_else(|_| "\"standard-private\"".to_string())
            .trim_matches('"')
            .to_string(),
        operator_id_hint: ethersync_status
            .as_ref()
            .map(|s| s.operator_id_hint.clone())
            .unwrap_or_else(|| cfg.operator_id.clone()),
        operator_region_hint: ethersync_status
            .as_ref()
            .map(|s| s.operator_region_hint.clone())
            .unwrap_or_else(|| cfg.operator_region.clone()),
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
        keeper_replication: cfg.keeper_replication_enabled,
        bridge_bootstrap: !cfg.bridge_bootstrap_hints.is_empty() || !cfg.assist_relays.is_empty(),
        privacy_tiers: vec!["standard-private".to_string(), "high-risk".to_string()],
        bootstrap_bundle_loaded: ethersync_status
            .as_ref()
            .map(|s| s.bootstrap_bundle_loaded)
            .unwrap_or(bootstrap_bundle.loaded),
        bootstrap_bundle_relays: ethersync_status
            .as_ref()
            .map(|s| s.bootstrap_bundle_relays)
            .unwrap_or(bootstrap_bundle.relays),
        bootstrap_bundle_bridges: ethersync_status
            .as_ref()
            .map(|s| s.bootstrap_bundle_bridges)
            .unwrap_or(bootstrap_bundle.bridges),
        bootstrap_bundle_keepers: ethersync_status
            .as_ref()
            .map(|s| s.bootstrap_bundle_keepers)
            .unwrap_or(bootstrap_bundle.keepers),
        bootstrap_bundle_usable: ethersync_status
            .as_ref()
            .map(|s| s.bootstrap_bundle_usable)
            .unwrap_or(false),
        bootstrap_bundle_structurally_weak: ethersync_status
            .as_ref()
            .map(|s| s.bootstrap_bundle_structurally_weak)
            .unwrap_or(false),
        bootstrap_bundle_stale: ethersync_status
            .as_ref()
            .map(|s| s.bootstrap_bundle_stale)
            .unwrap_or(false),
        bootstrap_bundle_warning_count: ethersync_status
            .as_ref()
            .map(|s| s.bootstrap_bundle_warning_count)
            .unwrap_or(0),
        bootstrap_bundle_error_count: ethersync_status
            .as_ref()
            .map(|s| s.bootstrap_bundle_error_count)
            .unwrap_or(0),
        api_version: "/v1".to_string(),
        wire_compatibility_window: "CipherPacket V2 plus additive ORP frame extensions".to_string(),
        deprecation_window:
            "One additive minor line; breaking wire changes require explicit migration notes"
                .to_string(),
        interop_matrix: "docs/interop.md".to_string(),
    };

    Ok(Json(snapshot))
}

/// Handle /v1/interop - machine-readable local API and wire compatibility posture
pub(crate) async fn handle_interop(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<InteropResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let mut ethersync_subspaces = BTreeMap::new();
    ethersync_subspaces.insert("user".to_string(), ethersync::SUBSPACE_USER);
    ethersync_subspaces.insert(
        "route-announce".to_string(),
        ethersync::SUBSPACE_ROUTE_ANNOUNCE,
    );
    ethersync_subspaces.insert("route-lookup".to_string(), ethersync::SUBSPACE_ROUTE_LOOKUP);
    ethersync_subspaces.insert("route-offer".to_string(), ethersync::SUBSPACE_ROUTE_OFFER);
    ethersync_subspaces.insert("relay-beacon".to_string(), ethersync::SUBSPACE_RELAY_BEACON);
    ethersync_subspaces.insert("circuit-open".to_string(), ethersync::SUBSPACE_CIRCUIT_OPEN);
    ethersync_subspaces.insert(
        "circuit-extend".to_string(),
        ethersync::SUBSPACE_CIRCUIT_EXTEND,
    );
    ethersync_subspaces.insert(
        "circuit-close".to_string(),
        ethersync::SUBSPACE_CIRCUIT_CLOSE,
    );
    ethersync_subspaces.insert(
        "cover-traffic".to_string(),
        ethersync::SUBSPACE_COVER_TRAFFIC,
    );

    Ok(Json(InteropResponse {
        api_version: "/v1".to_string(),
        local_api_scope: "Authenticated local control plane with additive evolution inside /v1"
            .to_string(),
        cipher_packet_anchor: "CipherPacket V2".to_string(),
        wire_compatibility_window: "CipherPacket V2 plus additive ORP frame extensions".to_string(),
        deprecation_window:
            "One additive minor line; breaking wire changes require explicit migration notes"
                .to_string(),
        interop_matrix: "docs/interop.md".to_string(),
        orp_frames: vec![
            "Announce".to_string(),
            "Lookup".to_string(),
            "Offer".to_string(),
            "Forward".to_string(),
            "Ack".to_string(),
        ],
        reserved_highrisk_frames: vec![
            "CircuitOpen".to_string(),
            "CircuitExtend".to_string(),
            "CircuitClose".to_string(),
            "Cover".to_string(),
        ],
        ethersync_subspaces,
    }))
}

/// Handle /v1/routes/discover - resolve candidates from ORP, bundle, and static bootstrap
pub(crate) async fn handle_routes_discover(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(query): Query<RouteDiscoverQuery>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<RouteDiscoverResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if query.passphrase.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let cfg = Config::from_env();
    let limit = query.limit.unwrap_or(8).clamp(1, 64);
    let canonical = ouroboros_crypto::derive::canonicalize_passphrase(&query.passphrase);
    let space_hash = ouroboros_crypto::hash::blake3_hash(&canonical);
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&space_hash[..8]);

    let mut backends: Vec<Arc<dyn crate::discovery::DiscoveryProvider>> = Vec::new();
    let mut used_orp = false;
    if let Some(node) = state.app.orp_node().await {
        backends.push(Arc::new(crate::discovery::OrpDiscoveryProvider::new(
            node.route_cache().clone(),
        )));
        used_orp = true;
    }

    let mut used_bootstrap_bundle = false;
    if let Some(bundle) = crate::bootstrap_bundle::load_bootstrap_bundle(&cfg) {
        let validation = bundle.validation_report();
        if validation.is_usable {
            backends.push(Arc::new(
                crate::discovery::BootstrapDiscoveryProvider::from_bundle(&bundle),
            ));
            used_bootstrap_bundle = true;
        }
    }

    let service = crate::discovery::DiscoveryService::with_bootstrap_peers(
        crate::discovery::FederatedDiscovery::new(backends),
        crate::discovery::parse_bootstrap_peers(&cfg.discovery_bootstrap_peers),
    );
    let candidates = service
        .discover_endpoints(space_hash, limit)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    Ok(Json(RouteDiscoverResponse {
        space_prefix: hex::encode(prefix),
        candidates: candidates
            .into_iter()
            .map(|addr| addr.to_string())
            .collect(),
        used_orp,
        used_bootstrap_bundle,
        used_static_bootstrap: !cfg.discovery_bootstrap_peers.is_empty(),
    }))
}

/// Handle /v1/routes/inspect - inspect ranked ORP candidates for a specific assist tag
pub(crate) async fn handle_routes_inspect(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(query): Query<RouteInspectQuery>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<RouteInspectResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if query.passphrase.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let target_tag = parse_target_tag(&query.target_tag).ok_or(StatusCode::BAD_REQUEST)?;
    let limit = query.limit.unwrap_or(16).clamp(1, 64);
    let canonical = ouroboros_crypto::derive::canonicalize_passphrase(&query.passphrase);
    let space_hash = ouroboros_crypto::hash::blake3_hash(&canonical);
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&space_hash[..8]);

    let node = state
        .app
        .orp_node()
        .await
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let cfg = Config::from_env();
    let route_bias = state.app.orp_space_route_bias(&query.passphrase).await;
    let candidates = crate::transport::orp::inspect_orp_candidates(
        node.as_ref(),
        &cfg,
        Some(&query.passphrase),
        Some(target_tag),
        route_bias.clone(),
    )
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let candidate_count = candidates.len();
    let candidates = candidates.into_iter().take(limit).collect();

    Ok(Json(RouteInspectResponse {
        space_prefix: hex::encode(prefix),
        target_tag: hex::encode(target_tag),
        route_bias: route_bias.map(route_bias_label),
        candidate_count,
        candidates,
    }))
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

    let (
        relay_nodes_observed,
        bridge_nodes_observed,
        keeper_nodes_observed,
        distinct_operator_hints_observed,
        distinct_region_hints_observed,
        max_operator_share_observed_pct,
        valid_three_hop_path_observed,
        route_class_counts,
        high_risk_recent_circuits,
    ) = if let Some(node) = state.app.orp_node().await {
        let cache = node.route_cache().lock().await;
        let relay_nodes = cache
            .announcements
            .values()
            .filter(|ann| ann.frame.capabilities.can_relay)
            .count();
        let bridge_nodes = cache
            .announcements
            .values()
            .filter(|ann| ann.frame.capabilities.bridge_capable)
            .count();
        let keeper_nodes = cache
            .announcements
            .values()
            .filter(|ann| ann.frame.capabilities.keeper_capable)
            .count();
        let distinct_operators = cache
            .announcements
            .values()
            .filter(|ann| {
                ann.frame.capabilities.can_relay && !ann.frame.operator_id_hint.trim().is_empty()
            })
            .map(|ann| ann.frame.operator_id_hint.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let distinct_regions = cache
            .announcements
            .values()
            .filter(|ann| {
                ann.frame.capabilities.can_relay && !ann.frame.region_hint.trim().is_empty()
            })
            .map(|ann| ann.frame.region_hint.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .len();

        let mut relay_counts_by_operator = BTreeMap::new();
        for announcement in cache
            .announcements
            .values()
            .filter(|ann| ann.frame.capabilities.can_relay)
        {
            let operator = announcement.frame.operator_id_hint.trim();
            if !operator.is_empty() {
                *relay_counts_by_operator
                    .entry(operator.to_string())
                    .or_insert(0usize) += 1;
            }
        }
        let max_operator_share_observed_pct = if relay_nodes > 0 {
            relay_counts_by_operator
                .values()
                .max()
                .map(|count| (((*count as f64) / (relay_nodes as f64)) * 100.0).ceil() as u8)
        } else {
            None
        };
        let valid_three_hop_path_observed =
            if relay_nodes >= 3 && distinct_operators >= 3 && distinct_regions >= 3 {
                Some(true)
            } else if relay_nodes == 0 {
                None
            } else {
                Some(false)
            };

        let mut class_counts = BTreeMap::new();
        for announcement in cache.announcements.values() {
            let key = format!("{:?}", announcement.frame.route_class).to_lowercase();
            *class_counts.entry(key).or_insert(0) += 1;
        }
        drop(cache);
        let high_risk_circuit_stats = node.high_risk_circuit_stats().await;

        (
            Some(relay_nodes),
            Some(bridge_nodes),
            Some(keeper_nodes),
            distinct_operators,
            distinct_regions,
            max_operator_share_observed_pct,
            valid_three_hop_path_observed,
            class_counts,
            high_risk_circuit_stats.recent_circuits,
        )
    } else {
        (
            None,
            None,
            None,
            0,
            0,
            None,
            None,
            BTreeMap::new(),
            Vec::new(),
        )
    };

    let mut gate_reasons = status.high_risk_gate_reasons.clone();
    if relay_nodes_observed.unwrap_or_default() < 64 {
        gate_reasons.push(format!(
            "observed relay nodes below hard gate: {} / 64",
            relay_nodes_observed.unwrap_or_default()
        ));
    }
    if distinct_operator_hints_observed < 16 {
        gate_reasons.push(format!(
            "observed relay operators below hard gate: {} / 16",
            distinct_operator_hints_observed
        ));
    }
    if distinct_region_hints_observed < 6 {
        gate_reasons.push(format!(
            "observed relay region buckets below hard gate: {} / 6",
            distinct_region_hints_observed
        ));
    }
    if let Some(max_share) = max_operator_share_observed_pct {
        if max_share > 15 {
            gate_reasons.push(format!(
                "largest observed relay operator share exceeds hard gate: {}% / 15%",
                max_share
            ));
        }
    }
    if matches!(valid_three_hop_path_observed, Some(false)) {
        gate_reasons.push(
            "no distinct three-hop relay path observed across operator and region hints"
                .to_string(),
        );
    }

    let high_risk = HighRiskGateStatus {
        available: status.high_risk_available,
        public_claim_unlocked: false,
        relay_nodes_required: 64,
        relay_nodes_observed,
        operator_identities_required: 16,
        operator_identities_observed: Some(distinct_operator_hints_observed),
        region_buckets_required: 6,
        region_buckets_observed: Some(distinct_region_hints_observed),
        max_operator_share_allowed_pct: 15,
        max_operator_share_observed_pct,
        requires_distinct_three_hop_path: true,
        valid_three_hop_path_observed,
        active_participants_required: 1024,
        active_participants_observed: Some(status.route_cache_size.max(status.peer_count)),
        gate_reasons,
    };

    Ok(Json(RouteStatusResponse {
        orp_enabled: status.orp_enabled,
        route_cache_size: status.route_cache_size,
        route_offers_count: status.route_offers_count,
        last_orp_activity_ms: status.last_orp_activity_ms,
        high_risk_control_plane_active: status.high_risk_circuits_observed > 0
            || status.high_risk_control_frames_observed > 0,
        high_risk_circuits_observed: status.high_risk_circuits_observed,
        high_risk_active_circuits: status.high_risk_active_circuits,
        high_risk_closed_circuits: status.high_risk_closed_circuits,
        high_risk_control_frames_observed: status.high_risk_control_frames_observed,
        high_risk_cover_packets_observed: status.high_risk_cover_packets_observed,
        high_risk_last_activity_ms: status.high_risk_last_activity_ms,
        high_risk_recent_circuits,
        active_spaces: status.spaces.len(),
        route_classes: vec![
            "direct".to_string(),
            "assisted".to_string(),
            "bridge".to_string(),
            "keeper".to_string(),
            "orp-standard".to_string(),
            "tor-fallback".to_string(),
        ],
        route_class_counts,
        standard_private_available: true,
        relay_nodes_observed,
        bridge_nodes_observed,
        keeper_nodes_observed,
        distinct_operator_hints_observed,
        managed_space_count: status.managed_space_count,
        bridge_preferred_space_count: status.bridge_preferred_space_count,
        keeper_preferred_space_count: status.keeper_preferred_space_count,
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
        pending_keeper_envelopes: status.pending_keeper_envelopes,
        keeper_space_count: status.keeper_space_count,
        archived_keeper_envelopes: status.archived_keeper_envelopes,
        keeper_archive_space_count: status.keeper_archive_space_count,
        keeper_manifest_space_count: status.keeper_manifest_space_count,
        keeper_candidate_shortfall_space_count: status.keeper_candidate_shortfall_space_count,
        managed_ready_space_count: status.managed_ready_space_count,
        last_keeper_activity_ms: status.last_keeper_activity_ms,
        managed_space_count: status.managed_space_count,
        bridge_preferred_space_count: status.bridge_preferred_space_count,
        keeper_preferred_space_count: status.keeper_preferred_space_count,
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
        bootstrap_bundle_loaded: status.bootstrap_bundle_loaded,
        bootstrap_bundle_mirrors: status.bootstrap_bundle_mirrors,
        bootstrap_bundle_relays: status.bootstrap_bundle_relays,
        bootstrap_bundle_bridges: status.bootstrap_bundle_bridges,
        bootstrap_bundle_keepers: status.bootstrap_bundle_keepers,
        bootstrap_bundle_usable: status.bootstrap_bundle_usable,
        bootstrap_bundle_structurally_weak: status.bootstrap_bundle_structurally_weak,
        bootstrap_bundle_stale: status.bootstrap_bundle_stale,
        bootstrap_bundle_warning_count: status.bootstrap_bundle_warning_count,
        bootstrap_bundle_error_count: status.bootstrap_bundle_error_count,
        operator_id_hint: status.operator_id_hint,
        operator_region_hint: status.operator_region_hint,
        notes: vec![
            "Current runtime can stage encrypted envelopes and flush them into a keeper replica archive"
                .to_string(),
            "Retention and route posture can now be tuned per space at join time".to_string(),
            "Bootstrap remains hybrid: static discovery peers, assist relays, and future bridge bundles"
                .to_string(),
            "Keeper backfill currently restores archived encrypted envelopes into local replay storage"
                .to_string(),
            "Bootstrap bundle validation now exposes local usability, structural weakness, and advisory staleness"
                .to_string(),
            "Per-space keeper manifests now expose desired targets, local stage, and candidate shortfall"
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
