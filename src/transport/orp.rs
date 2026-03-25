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
}

fn score_with_bias(
    base_score: u16,
    cfg: &Config,
    announcement: &CachedAnnouncement,
    route_bias: Option<&crate::state::SpaceRouteBias>,
) -> u16 {
    let mut bonus = 0i32;

    let operator = announcement.frame.operator_id_hint.trim();
    let region = announcement.frame.region_hint.trim();

    if !operator.is_empty() && operator != "local-node" {
        bonus += 80;
    }
    if !region.is_empty() && region != "unknown" {
        if region.eq_ignore_ascii_case(&cfg.operator_region) {
            bonus += 20;
        } else {
            bonus += 180;
        }
    }
    if !operator.is_empty() && operator.eq_ignore_ascii_case(&cfg.operator_id) {
        bonus -= 260;
    }

    match announcement.frame.route_class {
        RouteClass::Bridge
            if announcement.frame.capabilities.bridge_capable
                && (!cfg.bridge_bootstrap_hints.is_empty()
                    || crate::bootstrap_bundle::summarize_bootstrap_bundle(cfg).bridges > 0) =>
        {
            bonus += 420;
        }
        RouteClass::Keeper
            if announcement.frame.capabilities.keeper_capable
                && cfg.keeper_replication_enabled
                && cfg.keeper_replication_factor > 0 =>
        {
            bonus += 280 + (cfg.keeper_replication_factor.min(8) as i32 * 25);
        }
        RouteClass::Assisted if announcement.frame.capabilities.can_relay => {
            bonus += 140;
        }
        RouteClass::Direct if announcement.frame.capabilities.direct_udp => {
            bonus += 60;
        }
        _ => {}
    }

    if let Some(bundle) = crate::bootstrap_bundle::load_bootstrap_bundle(cfg) {
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
        }
    }

    if announcement.frame.capabilities.tor_capable && cfg.wan_mode != crate::config::WanMode::Direct
    {
        bonus += 40;
    }

    match route_bias {
        Some(crate::state::SpaceRouteBias::BridgePreferred)
            if matches!(announcement.frame.route_class, RouteClass::Bridge) =>
        {
            bonus += 320;
        }
        Some(crate::state::SpaceRouteBias::BridgePreferred)
            if matches!(announcement.frame.route_class, RouteClass::Keeper) =>
        {
            bonus -= 120;
        }
        Some(crate::state::SpaceRouteBias::KeeperPreferred)
            if matches!(announcement.frame.route_class, RouteClass::Keeper) =>
        {
            bonus += 360;
        }
        Some(crate::state::SpaceRouteBias::KeeperPreferred)
            if matches!(announcement.frame.route_class, RouteClass::Direct) =>
        {
            bonus -= 80;
        }
        Some(crate::state::SpaceRouteBias::DirectPreferred)
            if matches!(announcement.frame.route_class, RouteClass::Direct) =>
        {
            bonus += 280;
        }
        Some(crate::state::SpaceRouteBias::DirectPreferred)
            if !matches!(announcement.frame.route_class, RouteClass::Direct) =>
        {
            bonus -= 160;
        }
        _ => {}
    }

    if bonus >= 0 {
        base_score.saturating_add(bonus as u16)
    } else {
        base_score.saturating_sub((-bonus) as u16)
    }
}

fn push_candidate(
    out: &mut HashMap<SocketAddr, RouteCandidate>,
    addr: SocketAddr,
    score: u16,
    source: String,
) {
    match out.get_mut(&addr) {
        Some(existing) if existing.score >= score => {}
        Some(existing) => {
            existing.score = score;
            existing.source = source;
        }
        None => {
            out.insert(
                addr,
                RouteCandidate {
                    addr,
                    score,
                    source,
                },
            );
        }
    }
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
        for (space_prefix, _) in &active_spaces {
            if let Some(announcement) = cache.find_by_tag(space_prefix, &target_tag, current_slot) {
                if announcement.frame.slot < min_slot
                    || announcement.frame.node_id == local_node_id
                    || !announcement.frame.capabilities.direct_udp
                {
                    continue;
                }

                for addr in &announcement.frame.reachable_udp {
                    let score = score_with_bias(
                        ethersync::score_announcement(announcement, current_slot),
                        cfg,
                        announcement,
                        route_bias.as_ref(),
                    );
                    push_candidate(
                        &mut candidates,
                        *addr,
                        score,
                        format!(
                            "space={} class={:?} operator={} region={}",
                            hex::encode(space_prefix),
                            announcement.frame.route_class,
                            announcement.frame.operator_id_hint,
                            announcement.frame.region_hint
                        ),
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
                        let (score, source) = {
                            let cache = node.route_cache().lock().await;
                            if let Some(announcement) = cache.announcement_for_node(
                                &space_prefix,
                                &offer.responder_id,
                                current_slot,
                            ) {
                                (
                                    score_with_bias(
                                        offer.score,
                                        cfg,
                                        announcement,
                                        route_bias.as_ref(),
                                    ),
                                    format!(
                                        "lookup={} class={:?} operator={} region={}",
                                        hex::encode(lookup_id),
                                        announcement.frame.route_class,
                                        announcement.frame.operator_id_hint,
                                        announcement.frame.region_hint
                                    ),
                                )
                            } else {
                                (
                                    offer.score,
                                    format!("lookup={} direct-offer", hex::encode(lookup_id)),
                                )
                            }
                        };
                        push_candidate(&mut candidates, addr, score, source);
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
    candidates.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.addr.to_string().cmp(&b.addr.to_string()))
    });

    tracing::debug!(
        "ORP: {} candidate(s) resolved for assist_tag={} across {} active space(s)",
        candidates.len(),
        hex::encode(target_tag),
        active_spaces.len()
    );

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
