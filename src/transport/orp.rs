//! ORP transport adapter — bridges EtherSync route cache into connection attempts.
//!
//! Inserted into the transport fallback chain **between Relay and Tor**.
//! ORP only runs when the caller knows which peer it wants: we resolve a
//! specific `assist_tag` inside active ORP spaces, prefer fresh cached
//! announcements for that tag, then fall back to the lookup/offer flow.

use std::collections::HashMap;
use std::net::SocketAddr;

use ethersync::routing::{CachedAnnouncement, RouteClass, RouteHop, ANNOUNCE_SLOT_LOOKBACK};
use ethersync::{EtherCoordinate, EtherNode};
use ouroboros_crypto::derive::canonicalize_passphrase;
use ouroboros_crypto::hash::blake3_hash;
use serde::Serialize;
use tokio::time::{sleep, timeout, Duration};

use crate::config::Config;
use crate::derive::RendezvousParams;
use crate::network_telemetry;
use crate::transport::{connect_to, Connection};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[derive(Debug, Clone)]
struct RouteCandidate {
    addr: SocketAddr,
    score: u16,
    source: String,
    space_prefix: [u8; 8],
    route_class: Option<String>,
    operator_id_hint: String,
    region_hint: String,
    via_lookup: bool,
    preference_bucket: String,
    ranking_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrpCandidateSnapshot {
    pub addr: String,
    pub score: u16,
    pub source: String,
    pub space_prefix: String,
    pub route_class: Option<String>,
    pub operator_id_hint: String,
    pub region_hint: String,
    pub via_lookup: bool,
    pub preference_bucket: String,
    pub ranking_hints: Vec<String>,
}

#[derive(Debug, Clone)]
struct CandidatePosture {
    score: u16,
    preference_bucket: String,
    ranking_hints: Vec<String>,
}

fn trusted_bundle_for_runtime(cfg: &Config) -> Option<crate::bootstrap_bundle::BootstrapBundle> {
    let validation = crate::bootstrap_bundle::validate_loaded_bootstrap_bundle(cfg)?;
    if validation.is_usable && validation.trusted_for_runtime_high_risk() {
        crate::bootstrap_bundle::load_bootstrap_bundle(cfg)
    } else {
        None
    }
}

fn bundle_loaded_but_untrusted(cfg: &Config) -> bool {
    matches!(
        crate::bootstrap_bundle::validate_loaded_bootstrap_bundle(cfg),
        Some(report) if report.is_usable && !report.trusted_for_runtime_high_risk()
    )
}

fn score_with_bias(
    base_score: u16,
    cfg: &Config,
    announcement: &CachedAnnouncement,
    route_bias: Option<&crate::state::SpaceRouteBias>,
    bridge_heavy_space: bool,
) -> CandidatePosture {
    let mut bonus = 0i32;
    let mut ranking_hints = Vec::new();
    let trusted_bundle = trusted_bundle_for_runtime(cfg);
    let bundle_untrusted = bundle_loaded_but_untrusted(cfg);

    let operator = announcement.frame.operator_id_hint.trim();
    let region = announcement.frame.region_hint.trim();

    if !operator.is_empty() && operator != "local-node" {
        bonus += 80;
        ranking_hints.push("external-operator-hint".to_string());
    }
    if !region.is_empty() && region != "unknown" {
        if region.eq_ignore_ascii_case(&cfg.operator_region) {
            bonus += 20;
            ranking_hints.push("same-region-hint".to_string());
        } else {
            bonus += 180;
            ranking_hints.push("cross-region-hint".to_string());
        }
    }
    if !operator.is_empty() && operator.eq_ignore_ascii_case(&cfg.operator_id) {
        bonus -= 260;
        ranking_hints.push("local-operator-penalty".to_string());
    }

    match announcement.frame.route_class {
        RouteClass::Bridge
            if announcement.frame.capabilities.bridge_capable
                && (!cfg.bridge_bootstrap_hints.is_empty()
                    || trusted_bundle
                        .as_ref()
                        .map(|bundle| !bundle.bridges.is_empty())
                        .unwrap_or(false)) =>
        {
            bonus += 420;
            ranking_hints.push("bridge-capable-bundle-posture".to_string());
        }
        RouteClass::Keeper
            if announcement.frame.capabilities.keeper_capable
                && cfg.keeper_replication_enabled
                && cfg.keeper_replication_factor > 0 =>
        {
            bonus += 280 + (cfg.keeper_replication_factor.min(8) as i32 * 25);
            ranking_hints.push("keeper-capable-managed-posture".to_string());
        }
        RouteClass::Assisted if announcement.frame.capabilities.can_relay => {
            bonus += 140;
            ranking_hints.push("relay-capable".to_string());
        }
        RouteClass::Direct if announcement.frame.capabilities.direct_udp => {
            bonus += 60;
            ranking_hints.push("direct-udp".to_string());
        }
        _ => {}
    }

    if let Some(bundle) = trusted_bundle.as_ref() {
        ranking_hints.push("bundle-trust-verified".to_string());
        if bundle.relays.iter().any(|relay| {
            relay
                .operator_id
                .as_deref()
                .map(|value| value.eq_ignore_ascii_case(operator))
                .unwrap_or(false)
                || relay
                    .region
                    .as_deref()
                    .map(|value| value.eq_ignore_ascii_case(region))
                    .unwrap_or(false)
        }) {
            bonus += 140;
            ranking_hints.push("bundle-relay-match".to_string());
        }
        if bundle.bridges.iter().any(|bridge| {
            bridge
                .operator_id
                .as_deref()
                .map(|value| value.eq_ignore_ascii_case(operator))
                .unwrap_or(false)
                || bridge
                    .region
                    .as_deref()
                    .map(|value| value.eq_ignore_ascii_case(region))
                    .unwrap_or(false)
        }) {
            bonus += 180;
            ranking_hints.push("bundle-bridge-match".to_string());
        }
        if bundle.keepers.iter().any(|keeper| {
            keeper
                .operator_id
                .as_deref()
                .map(|value| value.eq_ignore_ascii_case(operator))
                .unwrap_or(false)
                || keeper
                    .region
                    .as_deref()
                    .map(|value| value.eq_ignore_ascii_case(region))
                    .unwrap_or(false)
        }) {
            bonus += 160;
            ranking_hints.push("bundle-keeper-match".to_string());
        }
    } else if bundle_untrusted {
        ranking_hints.push("bundle-untrusted-ignored".to_string());
    }

    if announcement.frame.capabilities.tor_capable && cfg.wan_mode != crate::config::WanMode::Direct
    {
        bonus += 40;
        ranking_hints.push("tor-capable".to_string());
    }

    if bridge_heavy_space
        && matches!(announcement.frame.route_class, RouteClass::Bridge)
        && announcement.frame.capabilities.bridge_capable
    {
        bonus += 140;
        ranking_hints.push("bridge-heavy-space".to_string());
    }

    match route_bias {
        Some(crate::state::SpaceRouteBias::BridgePreferred)
            if matches!(announcement.frame.route_class, RouteClass::Bridge) =>
        {
            bonus += 320;
            ranking_hints.push("bridge-preferred-policy".to_string());
        }
        Some(crate::state::SpaceRouteBias::BridgePreferred)
            if matches!(announcement.frame.route_class, RouteClass::Keeper) =>
        {
            bonus -= 120;
            ranking_hints.push("bridge-policy-keeper-penalty".to_string());
        }
        Some(crate::state::SpaceRouteBias::KeeperPreferred)
            if matches!(announcement.frame.route_class, RouteClass::Keeper) =>
        {
            bonus += 360;
            ranking_hints.push("keeper-preferred-policy".to_string());
        }
        Some(crate::state::SpaceRouteBias::KeeperPreferred)
            if matches!(announcement.frame.route_class, RouteClass::Direct) =>
        {
            bonus -= 80;
            ranking_hints.push("keeper-policy-direct-penalty".to_string());
        }
        Some(crate::state::SpaceRouteBias::DirectPreferred)
            if matches!(announcement.frame.route_class, RouteClass::Direct) =>
        {
            bonus += 280;
            ranking_hints.push("direct-preferred-policy".to_string());
        }
        Some(crate::state::SpaceRouteBias::DirectPreferred)
            if !matches!(announcement.frame.route_class, RouteClass::Direct) =>
        {
            bonus -= 160;
            ranking_hints.push("direct-policy-non-direct-penalty".to_string());
        }
        _ => {}
    }

    let score = if bonus >= 0 {
        base_score.saturating_add(bonus as u16)
    } else {
        base_score.saturating_sub((-bonus) as u16)
    };

    let preference_bucket = match route_bias {
        Some(crate::state::SpaceRouteBias::BridgePreferred)
            if matches!(announcement.frame.route_class, RouteClass::Bridge)
                && bridge_heavy_space =>
        {
            "bridge-heavy-preferred"
        }
        Some(crate::state::SpaceRouteBias::BridgePreferred)
            if matches!(announcement.frame.route_class, RouteClass::Bridge) =>
        {
            "bridge-preferred"
        }
        Some(crate::state::SpaceRouteBias::KeeperPreferred)
            if matches!(announcement.frame.route_class, RouteClass::Keeper) =>
        {
            "keeper-preferred"
        }
        Some(crate::state::SpaceRouteBias::DirectPreferred)
            if matches!(announcement.frame.route_class, RouteClass::Direct) =>
        {
            "direct-preferred"
        }
        _ if matches!(announcement.frame.route_class, RouteClass::Bridge) && bridge_heavy_space => {
            "bridge-heavy"
        }
        _ => "balanced",
    }
    .to_string();
    ranking_hints.push(format!("bucket={preference_bucket}"));

    CandidatePosture {
        score,
        preference_bucket,
        ranking_hints,
    }
}

fn push_candidate(out: &mut HashMap<SocketAddr, RouteCandidate>, candidate: RouteCandidate) {
    let candidate_addr = candidate.addr;
    let candidate_score = candidate.score;
    match out.get_mut(&candidate_addr) {
        Some(existing) if existing.score >= candidate_score => {}
        Some(existing) => {
            existing.score = candidate.score;
            existing.source = candidate.source;
            existing.space_prefix = candidate.space_prefix;
            existing.route_class = candidate.route_class;
            existing.operator_id_hint = candidate.operator_id_hint;
            existing.region_hint = candidate.region_hint;
            existing.via_lookup = candidate.via_lookup;
            existing.preference_bucket = candidate.preference_bucket;
            existing.ranking_hints = candidate.ranking_hints;
        }
        None => {
            out.insert(candidate_addr, candidate);
        }
    }
}

fn route_class_label(route_class: RouteClass) -> String {
    format!("{route_class:?}").to_lowercase()
}

fn sort_candidates(candidates: &mut [RouteCandidate]) {
    candidates.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.preference_bucket.cmp(&b.preference_bucket))
            .then_with(|| a.addr.to_string().cmp(&b.addr.to_string()))
    });
}

fn bridge_heavy_space(
    cache: &ethersync::routing::RouteCache,
    active_spaces: &[([u8; 8], String)],
    min_slot: u64,
) -> bool {
    let mut bridge_count = 0usize;
    let mut relay_count = 0usize;

    for (key, announcement) in &cache.announcements {
        if announcement.frame.slot < min_slot {
            continue;
        }
        if !active_spaces
            .iter()
            .any(|(space_prefix, _)| key.space_prefix == *space_prefix)
        {
            continue;
        }
        if announcement.frame.capabilities.bridge_capable {
            bridge_count += 1;
        }
        if announcement.frame.capabilities.can_relay {
            relay_count += 1;
        }
    }

    bridge_count >= 2 && bridge_count >= relay_count.saturating_sub(1)
}

async fn resolve_orp_candidates(
    node: &EtherNode,
    cfg: &Config,
    passphrase: Option<&str>,
    target_tag: Option<[u8; 8]>,
    route_bias: Option<crate::state::SpaceRouteBias>,
) -> Result<Vec<RouteCandidate>> {
    let Some(target_tag) = target_tag else {
        tracing::debug!("ORP: skipping route discovery without a target assist tag");
        network_telemetry::record_fallback_event("orp", "missing_target_tag", None);
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ORP: target assist tag required",
        )));
    };

    let requested_prefix = passphrase.map(|passphrase| {
        let passphrase_bytes = canonicalize_passphrase(passphrase);
        let space_hash = blake3_hash(&passphrase_bytes);
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&space_hash[..8]);
        prefix
    });

    let mut active_spaces = node.active_orp_spaces().await;
    if let Some(prefix) = requested_prefix {
        active_spaces.retain(|(space_prefix, _)| *space_prefix == prefix);
    }

    if active_spaces.is_empty() {
        tracing::debug!("ORP: no active ORP space matched the requested passphrase");
        network_telemetry::record_fallback_event("orp", "no_active_spaces", None);
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "ORP: no active ORP space for requested passphrase",
        )));
    }

    let current_slot = EtherCoordinate::current_slot();
    let min_slot = current_slot.saturating_sub(ANNOUNCE_SLOT_LOOKBACK);
    let local_node_id = node.node_id();
    let mut candidates = HashMap::new();

    {
        let cache = node.route_cache().lock().await;
        let bridge_heavy = bridge_heavy_space(&cache, &active_spaces, min_slot);
        for (space_prefix, _) in &active_spaces {
            if let Some(announcement) = cache.find_by_tag(space_prefix, &target_tag, current_slot) {
                if announcement.frame.slot < min_slot
                    || announcement.frame.node_id == local_node_id
                    || !announcement.frame.capabilities.direct_udp
                {
                    continue;
                }

                for addr in &announcement.frame.reachable_udp {
                    let posture = score_with_bias(
                        ethersync::score_announcement(announcement, current_slot),
                        cfg,
                        announcement,
                        route_bias.as_ref(),
                        bridge_heavy,
                    );
                    push_candidate(
                        &mut candidates,
                        RouteCandidate {
                            addr: *addr,
                            score: posture.score,
                            source: format!(
                                "space={} class={:?} operator={} region={} bucket={}",
                                hex::encode(space_prefix),
                                announcement.frame.route_class,
                                announcement.frame.operator_id_hint,
                                announcement.frame.region_hint,
                                posture.preference_bucket
                            ),
                            space_prefix: *space_prefix,
                            route_class: Some(route_class_label(announcement.frame.route_class)),
                            operator_id_hint: announcement.frame.operator_id_hint.clone(),
                            region_hint: announcement.frame.region_hint.clone(),
                            via_lookup: false,
                            preference_bucket: posture.preference_bucket,
                            ranking_hints: posture.ranking_hints,
                        },
                    );
                }
            }
        }
    }

    if candidates.is_empty() {
        let mut lookups = Vec::new();
        for (space_prefix, passphrase) in &active_spaces {
            match node.lookup_route(passphrase, target_tag).await {
                Ok(lookup_id) => lookups.push((*space_prefix, passphrase.clone(), lookup_id)),
                Err(err) => {
                    network_telemetry::record_fallback_event(
                        "orp",
                        "lookup_publish_failed",
                        Some(err.to_string()),
                    );
                    tracing::debug!("ORP: lookup publish failed: {}", err);
                }
            }
        }

        if lookups.is_empty() {
            network_telemetry::record_fallback_event("orp", "lookup_unavailable", None);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "ORP: could not publish any route lookup",
            )));
        }

        let lookup_wait_ms = cfg.wan_connect_timeout_ms.clamp(250, 1_500) / 2;
        sleep(Duration::from_millis(lookup_wait_ms.max(250))).await;

        for (space_prefix, passphrase, lookup_id) in lookups {
            match node.best_route(&passphrase, lookup_id).await {
                Ok(Some(offer)) => {
                    if let RouteHop::Direct { addr } = offer.next_hop {
                        let (
                            score,
                            source,
                            route_class,
                            operator_id_hint,
                            region_hint,
                            preference_bucket,
                            ranking_hints,
                        ) = {
                            let cache = node.route_cache().lock().await;
                            let bridge_heavy = bridge_heavy_space(&cache, &active_spaces, min_slot);
                            if let Some(announcement) = cache.announcement_for_node(
                                &space_prefix,
                                &offer.responder_id,
                                current_slot,
                            ) {
                                let posture = score_with_bias(
                                    offer.score,
                                    cfg,
                                    announcement,
                                    route_bias.as_ref(),
                                    bridge_heavy,
                                );
                                (
                                    posture.score,
                                    format!(
                                        "lookup={} class={:?} operator={} region={} bucket={}",
                                        hex::encode(lookup_id),
                                        announcement.frame.route_class,
                                        announcement.frame.operator_id_hint,
                                        announcement.frame.region_hint,
                                        posture.preference_bucket
                                    ),
                                    Some(route_class_label(announcement.frame.route_class)),
                                    announcement.frame.operator_id_hint.clone(),
                                    announcement.frame.region_hint.clone(),
                                    posture.preference_bucket,
                                    posture.ranking_hints,
                                )
                            } else {
                                (
                                    offer.score,
                                    format!("lookup={} direct-offer", hex::encode(lookup_id)),
                                    None,
                                    String::new(),
                                    String::new(),
                                    "lookup-direct-offer".to_string(),
                                    vec!["lookup-direct-offer".to_string()],
                                )
                            }
                        };
                        push_candidate(
                            &mut candidates,
                            RouteCandidate {
                                addr,
                                score,
                                source,
                                space_prefix,
                                route_class,
                                operator_id_hint,
                                region_hint,
                                via_lookup: true,
                                preference_bucket,
                                ranking_hints,
                            },
                        );
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    network_telemetry::record_fallback_event(
                        "orp",
                        "lookup_resolution_failed",
                        Some(err.to_string()),
                    );
                    tracing::debug!("ORP: lookup resolution failed: {}", err);
                }
            }
        }
    }

    if candidates.is_empty() {
        tracing::debug!(
            "ORP: no candidates resolved for assist_tag={} across {} active space(s)",
            hex::encode(target_tag),
            active_spaces.len()
        );
        network_telemetry::record_fallback_event(
            "orp",
            "no_candidates",
            Some(format!("assist_tag={}", hex::encode(target_tag))),
        );
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "ORP: no reachable candidates for target assist tag",
        )));
    }

    let mut candidates = candidates.into_values().collect::<Vec<_>>();
    sort_candidates(&mut candidates);
    tracing::debug!(
        "ORP: {} candidate(s) resolved for assist_tag={} across {} active space(s)",
        candidates.len(),
        hex::encode(target_tag),
        active_spaces.len()
    );
    Ok(candidates)
}

pub async fn inspect_orp_candidates(
    node: &EtherNode,
    cfg: &Config,
    passphrase: Option<&str>,
    target_tag: Option<[u8; 8]>,
    route_bias: Option<crate::state::SpaceRouteBias>,
) -> Result<Vec<OrpCandidateSnapshot>> {
    let candidates = resolve_orp_candidates(node, cfg, passphrase, target_tag, route_bias).await?;
    Ok(candidates
        .into_iter()
        .map(|candidate| OrpCandidateSnapshot {
            addr: candidate.addr.to_string(),
            score: candidate.score,
            source: candidate.source,
            space_prefix: hex::encode(candidate.space_prefix),
            route_class: candidate.route_class,
            operator_id_hint: candidate.operator_id_hint,
            region_hint: candidate.region_hint,
            via_lookup: candidate.via_lookup,
            preference_bucket: candidate.preference_bucket,
            ranking_hints: candidate.ranking_hints,
        })
        .collect())
}

/// Try to establish a connection via ORP for a specific assist tag.
pub async fn try_orp_route(
    node: &EtherNode,
    params: &RendezvousParams,
    cfg: &Config,
    passphrase: Option<&str>,
    target_tag: Option<[u8; 8]>,
    route_bias: Option<crate::state::SpaceRouteBias>,
) -> Result<Connection> {
    let candidates =
        resolve_orp_candidates(node, cfg, passphrase, target_tag, route_bias.clone()).await?;
    let target_tag = target_tag.expect("resolve_orp_candidates validates missing target tag");

    let dial_timeout = Duration::from_millis(cfg.wan_connect_timeout_ms.clamp(500, 5_000));
    for candidate in &candidates {
        let target = candidate.addr.to_string();
        tracing::debug!(
            "ORP: dialing resolved candidate {} score={} source={}",
            target,
            candidate.score,
            candidate.source
        );

        match timeout(dial_timeout, connect_to(&target, params, cfg)).await {
            Ok(Ok(conn)) => {
                tracing::info!(
                    "ORP: connection established via {} score={} source={}",
                    candidate.addr,
                    candidate.score,
                    candidate.source
                );
                network_telemetry::record_strategy_result("orp", true);
                return Ok(conn);
            }
            Ok(Err(e)) => {
                network_telemetry::record_fallback_event(
                    "orp",
                    "candidate_failed",
                    Some(format!(
                        "addr={} score={} source={} err={}",
                        candidate.addr, candidate.score, candidate.source, e
                    )),
                );
                tracing::debug!("ORP: {} unreachable: {}", candidate.addr, e);
            }
            Err(_) => {
                network_telemetry::record_fallback_event(
                    "orp",
                    "candidate_timeout",
                    Some(format!(
                        "addr={} score={} source={}",
                        candidate.addr, candidate.score, candidate.source
                    )),
                );
                tracing::debug!("ORP: {} timed out", candidate.addr);
            }
        }
    }

    network_telemetry::record_strategy_result("orp", false);
    Err(Box::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!(
            "ORP: all {} candidate(s) exhausted for assist_tag={}",
            candidates.len(),
            hex::encode(target_tag)
        ),
    )))
}
