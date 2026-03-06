use axum::{
    extract::{ConnectInfo, Extension},
    http::StatusCode,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::{sync::Mutex, time::sleep};

use crate::config::Config;
use crate::network_telemetry;
use crate::offer::OfferPayload;

use super::types::{SimultaneousOpenRequest, SimultaneousOpenResponse};
use super::ApiState;

const SYNC_RETRY_BUDGET: usize = 3;
const SYNC_RETRY_BACKOFF_MS: u64 = 150;
const SYNC_CIRCUIT_FAILURE_THRESHOLD: u32 = 8;
const SYNC_CIRCUIT_COOLDOWN_SECS: u64 = 15;

#[derive(Debug, Default)]
struct SyncCircuitBreaker {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

static SYNC_CIRCUIT: OnceLock<Arc<Mutex<SyncCircuitBreaker>>> = OnceLock::new();

fn sync_circuit() -> Arc<Mutex<SyncCircuitBreaker>> {
    SYNC_CIRCUIT
        .get_or_init(|| Arc::new(Mutex::new(SyncCircuitBreaker::default())))
        .clone()
}

async fn sync_circuit_is_open() -> bool {
    let circuit = sync_circuit();
    let guard = circuit.lock().await;
    matches!(guard.open_until, Some(until) if Instant::now() < until)
}

async fn record_sync_failure(context: &'static str) {
    let circuit = sync_circuit();
    let mut guard = circuit.lock().await;
    guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
    if guard.consecutive_failures >= SYNC_CIRCUIT_FAILURE_THRESHOLD {
        guard.open_until = Some(Instant::now() + Duration::from_secs(SYNC_CIRCUIT_COOLDOWN_SECS));
        tracing::warn!(
            "sync circuit opened for {}s after {} failures ({})",
            SYNC_CIRCUIT_COOLDOWN_SECS,
            guard.consecutive_failures,
            context
        );
    }
}

async fn record_sync_success() {
    let circuit = sync_circuit();
    let mut guard = circuit.lock().await;
    guard.consecutive_failures = 0;
    guard.open_until = None;
}

/// Handle /v1/rendezvous/sync - Coordinate simultaneous open via relay
pub(crate) async fn handle_connect_sync(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<SimultaneousOpenRequest>,
) -> Result<Json<SimultaneousOpenResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    if sync_circuit_is_open().await {
        network_telemetry::record_fallback_event(
            "sync",
            "circuit_open",
            Some("sync temporarily unavailable".to_string()),
        );
        return Ok(Json(SimultaneousOpenResponse {
            success: false,
            offset_ms: None,
            rendezvous_at: None,
            error: Some("sync temporarily unavailable, retry shortly".to_string()),
        }));
    }

    let cfg = Config::from_env();

    if !req.relay_onion.contains(':') || !req.relay_onion.contains(".onion") {
        return Ok(Json(SimultaneousOpenResponse {
            success: false,
            offset_ms: None,
            rendezvous_at: None,
            error: Some("Invalid relay_onion format".to_string()),
        }));
    }

    let offer_bytes = match general_purpose::STANDARD.decode(&req.my_offer) {
        Ok(b) => b,
        Err(e) => {
            return Ok(Json(SimultaneousOpenResponse {
                success: false,
                offset_ms: None,
                rendezvous_at: None,
                error: Some(format!("Invalid offer encoding: {}", e)),
            }));
        }
    };

    let my_offer: OfferPayload = match bincode::deserialize(&offer_bytes) {
        Ok(o) => o,
        Err(e) => {
            return Ok(Json(SimultaneousOpenResponse {
                success: false,
                offset_ms: None,
                rendezvous_at: None,
                error: Some(format!("Invalid offer: {}", e)),
            }));
        }
    };

    let their_hash = match general_purpose::STANDARD.decode(&req.their_hash) {
        Ok(h) if h.len() == 32 => {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&h);
            hash
        }
        _ => {
            return Ok(Json(SimultaneousOpenResponse {
                success: false,
                offset_ms: None,
                rendezvous_at: None,
                error: Some("Invalid hash: must be 32 bytes".to_string()),
            }));
        }
    };

    let mut last_error: Option<String> = None;
    for attempt in 0..SYNC_RETRY_BUDGET.max(1) {
        let result = crate::transport::wan_assist::coordination::try_simultaneous_or_sequential(
            &my_offer,
            their_hash,
            std::slice::from_ref(&req.relay_onion),
            &cfg,
        )
        .await;

        match result {
            Ok(_conn) => {
                record_sync_success().await;
                return Ok(Json(SimultaneousOpenResponse {
                    success: true,
                    offset_ms: my_offer.ntp_offset,
                    rendezvous_at: Some(my_offer.timestamp + 30000),
                    error: None,
                }));
            }
            Err(e) => {
                network_telemetry::record_fallback_event(
                    "sync",
                    "coordination_attempt_failed",
                    Some(format!("attempt={} err={}", attempt + 1, e)),
                );
                last_error = Some(e.to_string());
                let next_attempt = attempt + 1;
                if next_attempt < SYNC_RETRY_BUDGET {
                    let backoff_ms = SYNC_RETRY_BACKOFF_MS.saturating_mul(1u64 << (attempt as u32));
                    tracing::warn!(
                        "sync coordination attempt {}/{} failed: {}. retrying in {}ms",
                        next_attempt,
                        SYNC_RETRY_BUDGET,
                        e,
                        backoff_ms
                    );
                    sleep(Duration::from_millis(backoff_ms)).await;
                }
            }
        }
    }

    record_sync_failure("coordination attempts exhausted").await;
    Ok(Json(SimultaneousOpenResponse {
        success: false,
        offset_ms: my_offer.ntp_offset,
        rendezvous_at: None,
        error: last_error.or_else(|| Some("sync coordination failed".to_string())),
    }))
}
