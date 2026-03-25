//! ORP transport adapter — bridges EtherSync route cache into Connection attempts.
//!
//! Inserted into the transport fallback chain **between Relay and Tor**.
//! Scans the route cache for fresh announcements that advertise direct-UDP
//! reachability **within active ORP spaces only**, then dials each candidate
//! in order, returning the first successful `Connection`.

use std::net::SocketAddr;

use ethersync::routing::ANNOUNCE_SLOT_LOOKBACK;
use ethersync::{EtherCoordinate, EtherNode};
use tokio::time::{timeout, Duration};

use crate::config::Config;
use crate::derive::RendezvousParams;
use crate::network_telemetry;
use crate::transport::{connect_to, Connection};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

/// Try to establish a connection via the ORP route cache.
///
/// 1. Get the set of active ORP space prefixes from the node.
/// 2. Lock the route cache and collect fresh announcements whose
///    `direct_udp` capability is set **and** whose space prefix is in the
///    active set — no cross-space leakage.
/// 3. For each candidate, dial with `connect_to` bounded by
///    `cfg.wan_connect_timeout_ms`.
/// 4. Return the first successful `Connection`, or an error if all fail.
pub async fn try_orp_route(
    node: &EtherNode,
    params: &RendezvousParams,
    cfg: &Config,
) -> Result<Connection> {
    let current_slot = EtherCoordinate::current_slot();
    let min_slot = current_slot.saturating_sub(ANNOUNCE_SLOT_LOOKBACK);

    // Only consider announcements from spaces we actively participate in.
    let active_prefixes = node.orp_space_prefixes().await;
    if active_prefixes.is_empty() {
        tracing::debug!("ORP: no active ORP spaces registered");
        network_telemetry::record_fallback_event("orp", "no_active_spaces", None);
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "ORP: no active ORP spaces",
        )));
    }

    // Snapshot candidates under the lock, then release before dialling.
    let candidates: Vec<SocketAddr> = {
        let cache = node.route_cache().lock().await;
        cache
            .announcements
            .iter()
            .filter(|(key, ann)| {
                ann.frame.slot >= min_slot
                    && ann.frame.capabilities.direct_udp
                    && active_prefixes.contains(&key.space_prefix)
                    // Don't dial ourselves
                    && ann.frame.node_id != node.node_id()
            })
            .flat_map(|(_, ann)| ann.frame.reachable_udp.iter().cloned())
            .collect()
    };

    if candidates.is_empty() {
        tracing::debug!(
            "ORP: no direct-UDP candidates in {} active space(s) (slot={})",
            active_prefixes.len(),
            current_slot
        );
        network_telemetry::record_fallback_event("orp", "no_candidates", None);
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "ORP: no reachable candidates in active spaces",
        )));
    }

    tracing::debug!(
        "ORP: {} direct-UDP candidate(s) across {} space(s) for slot {}",
        candidates.len(),
        active_prefixes.len(),
        current_slot
    );

    let dial_timeout = Duration::from_millis(cfg.wan_connect_timeout_ms.clamp(500, 5_000));

    for addr in &candidates {
        let target = addr.to_string();
        tracing::debug!("ORP: dialling {}", target);

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
            Err(_elapsed) => {
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
        format!("ORP: all {} candidate(s) exhausted", candidates.len()),
    )))
}
