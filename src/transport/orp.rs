//! ORP transport adapter — bridges EtherSync route cache into connection attempts.
//!
//! Inserted into the transport fallback chain **between Relay and Tor**.
//! ORP only runs when the caller knows which peer it wants: we resolve a
//! specific `assist_tag` inside active ORP spaces, prefer fresh cached
//! announcements for that tag, then fall back to the lookup/offer flow.

use std::net::SocketAddr;

use ethersync::routing::{RouteHop, ANNOUNCE_SLOT_LOOKBACK};
use ethersync::{EtherCoordinate, EtherNode};
use ouroboros_crypto::derive::canonicalize_passphrase;
use ouroboros_crypto::hash::blake3_hash;
use tokio::time::{sleep, timeout, Duration};

use crate::config::Config;
use crate::derive::RendezvousParams;
use crate::network_telemetry;
use crate::transport::{connect_to, Connection};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

fn push_unique_addr(out: &mut Vec<SocketAddr>, addr: SocketAddr) {
    if !out.contains(&addr) {
        out.push(addr);
    }
}

/// Try to establish a connection via ORP for a specific assist tag.
pub async fn try_orp_route(
    node: &EtherNode,
    params: &RendezvousParams,
    cfg: &Config,
    passphrase: Option<&str>,
    target_tag: Option<[u8; 8]>,
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
    let mut candidates = Vec::new();

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
                    push_unique_addr(&mut candidates, *addr);
                }
            }
        }
    }

    if candidates.is_empty() {
        let mut lookups = Vec::new();
        for (_, passphrase) in &active_spaces {
            match node.lookup_route(passphrase, target_tag).await {
                Ok(lookup_id) => lookups.push((passphrase.clone(), lookup_id)),
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

        for (passphrase, lookup_id) in lookups {
            match node.best_route(&passphrase, lookup_id).await {
                Ok(Some(offer)) => {
                    if let RouteHop::Direct { addr } = offer.next_hop {
                        push_unique_addr(&mut candidates, addr);
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

    tracing::debug!(
        "ORP: {} candidate(s) resolved for assist_tag={} across {} active space(s)",
        candidates.len(),
        hex::encode(target_tag),
        active_spaces.len()
    );

    let dial_timeout = Duration::from_millis(cfg.wan_connect_timeout_ms.clamp(500, 5_000));
    for addr in &candidates {
        let target = addr.to_string();
        tracing::debug!("ORP: dialing resolved candidate {}", target);

        match timeout(dial_timeout, connect_to(&target, params, cfg)).await {
            Ok(Ok(conn)) => {
                tracing::info!("ORP: connection established via {}", addr);
                network_telemetry::record_strategy_result("orp", true);
                return Ok(conn);
            }
            Ok(Err(e)) => {
                network_telemetry::record_fallback_event(
                    "orp",
                    "candidate_failed",
                    Some(format!("addr={} err={}", addr, e)),
                );
                tracing::debug!("ORP: {} unreachable: {}", addr, e);
            }
            Err(_) => {
                network_telemetry::record_fallback_event(
                    "orp",
                    "candidate_timeout",
                    Some(format!("addr={}", addr)),
                );
                tracing::debug!("ORP: {} timed out", addr);
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
