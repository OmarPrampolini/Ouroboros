//! ORP transport adapter — bridges EtherSync route cache into Connection attempts.
//!
//! Inserted into the transport fallback chain **between Relay and Tor**.
//! Scans the route cache for fresh announcements that advertise direct-UDP
//! reachability and dials each candidate in order, returning the first
//! successful `Connection`.
//!
//! ## Space-prefix filtering (Phase 3 TODO)
//! Currently all announcements in the cache are considered regardless of
//! passphrase space.  Precise per-space filtering requires threading the ORP
//! passphrase (or a derivation of it) into `RendezvousParams`; that mapping is
//! deferred to Phase 3.

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
/// 1. Lock the route cache and collect all fresh announcements whose
///    `direct_udp` capability flag is set.
/// 2. For each candidate UDP address, dial with `connect_to` (UDP first,
///    TCP hole-punch fallback) bounded by `cfg.wan_connect_timeout_ms`.
/// 3. Return the first successful `Connection`, or an error if all
///    candidates are unreachable.
pub async fn try_orp_route(
    node: &EtherNode,
    params: &RendezvousParams,
    cfg: &Config,
) -> Result<Connection> {
    let current_slot = EtherCoordinate::current_slot();
    let min_slot = current_slot.saturating_sub(ANNOUNCE_SLOT_LOOKBACK);

    // Snapshot candidates under the lock, then release before dialling.
    let candidates: Vec<SocketAddr> = {
        let cache = node.route_cache().lock().await;
        cache
            .announcements
            .values()
            .filter(|a| a.frame.slot >= min_slot && a.frame.capabilities.direct_udp)
            .flat_map(|a| a.frame.reachable_udp.iter().cloned())
            .collect()
    };

    if candidates.is_empty() {
        tracing::debug!("ORP: no direct-UDP candidates in route cache (slot={})", current_slot);
        network_telemetry::record_fallback_event("orp", "no_candidates", None);
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "ORP: route cache has no reachable candidates",
        )));
    }

    tracing::debug!(
        "ORP: {} direct-UDP candidate(s) for slot {}",
        candidates.len(),
        current_slot
    );

    // Clamp dial timeout: at least 500 ms, at most 5 s per candidate.
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
        format!(
            "ORP: all {} candidate(s) exhausted",
            candidates.len()
        ),
    )))
}
