use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_FALLBACK_EVENTS: usize = 500;

#[derive(Debug, Clone, Serialize)]
pub struct FallbackEvent {
    pub ts_ms: u64,
    pub phase: String,
    pub reason: String,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NatRuntimeMetrics {
    pub detection_successes: u64,
    pub detection_failures: u64,
    pub detection_success_rate: f64,
    pub avg_detection_time_ms: u64,
    pub classification_counts: BTreeMap<String, u64>,
    pub strategy_attempts: BTreeMap<String, u64>,
    pub strategy_successes: BTreeMap<String, u64>,
    pub strategy_success_rate: BTreeMap<String, f64>,
    pub strategy_priority_delta: BTreeMap<String, i32>,
}

#[derive(Default)]
struct TelemetryState {
    detection_successes: u64,
    detection_failures: u64,
    detection_total_time_ms: u64,
    classification_counts: BTreeMap<String, u64>,
    strategy_attempts: BTreeMap<String, u64>,
    strategy_successes: BTreeMap<String, u64>,
    fallback_events: VecDeque<FallbackEvent>,
}

static TELEMETRY: OnceLock<Mutex<TelemetryState>> = OnceLock::new();

fn telemetry() -> &'static Mutex<TelemetryState> {
    TELEMETRY.get_or_init(|| Mutex::new(TelemetryState::default()))
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn record_nat_detection_success(nat_type: &str, elapsed: Duration) {
    let mut state = telemetry().lock().expect("telemetry mutex poisoned");
    state.detection_successes = state.detection_successes.saturating_add(1);
    state.detection_total_time_ms = state
        .detection_total_time_ms
        .saturating_add(elapsed.as_millis().min(u64::MAX as u128) as u64);
    *state
        .classification_counts
        .entry(nat_type.to_string())
        .or_insert(0) += 1;
}

pub fn record_nat_detection_failure(elapsed: Duration, error: &str) {
    let mut state = telemetry().lock().expect("telemetry mutex poisoned");
    state.detection_failures = state.detection_failures.saturating_add(1);
    state.detection_total_time_ms = state
        .detection_total_time_ms
        .saturating_add(elapsed.as_millis().min(u64::MAX as u128) as u64);
    drop(state);
    record_fallback_event("nat_detection", "detection_failed", Some(error.to_string()));
}

pub fn record_strategy_result(strategy: &str, success: bool) {
    let mut state = telemetry().lock().expect("telemetry mutex poisoned");
    *state
        .strategy_attempts
        .entry(strategy.to_string())
        .or_insert(0) += 1;
    if success {
        *state
            .strategy_successes
            .entry(strategy.to_string())
            .or_insert(0) += 1;
    }
}

fn compute_strategy_priority_delta(attempts: u64, successes: u64) -> i32 {
    if attempts < 3 {
        return 0;
    }

    let rate = successes as f64 / attempts as f64;

    if attempts >= 10 {
        if rate >= 0.80 {
            8
        } else if rate >= 0.65 {
            4
        } else if rate <= 0.20 {
            -8
        } else if rate <= 0.35 {
            -4
        } else {
            0
        }
    } else if rate >= 0.75 {
        4
    } else if rate <= 0.25 {
        -4
    } else {
        0
    }
}

pub fn strategy_priority_delta(strategy: &str) -> i32 {
    let state = telemetry().lock().expect("telemetry mutex poisoned");
    let attempts = *state.strategy_attempts.get(strategy).unwrap_or(&0);
    let successes = *state.strategy_successes.get(strategy).unwrap_or(&0);
    compute_strategy_priority_delta(attempts, successes)
}

pub fn record_fallback_event(phase: &str, reason: &str, details: Option<String>) {
    let mut state = telemetry().lock().expect("telemetry mutex poisoned");
    if state.fallback_events.len() >= MAX_FALLBACK_EVENTS {
        state.fallback_events.pop_front();
    }
    state.fallback_events.push_back(FallbackEvent {
        ts_ms: now_ms(),
        phase: phase.to_string(),
        reason: reason.to_string(),
        details,
    });
}

pub fn nat_metrics_snapshot() -> NatRuntimeMetrics {
    let state = telemetry().lock().expect("telemetry mutex poisoned");
    let total_detection = state
        .detection_successes
        .saturating_add(state.detection_failures);
    let detection_success_rate = if total_detection == 0 {
        0.0
    } else {
        state.detection_successes as f64 / total_detection as f64
    };
    let avg_detection_time_ms = if total_detection == 0 {
        0
    } else {
        state.detection_total_time_ms / total_detection
    };

    let mut strategy_success_rate = BTreeMap::new();
    let mut strategy_priority_delta = BTreeMap::new();
    for (strategy, attempts) in &state.strategy_attempts {
        let successes = *state.strategy_successes.get(strategy).unwrap_or(&0);
        let rate = if *attempts == 0 {
            0.0
        } else {
            successes as f64 / *attempts as f64
        };
        strategy_success_rate.insert(strategy.clone(), rate);
        strategy_priority_delta.insert(
            strategy.clone(),
            compute_strategy_priority_delta(*attempts, successes),
        );
    }

    NatRuntimeMetrics {
        detection_successes: state.detection_successes,
        detection_failures: state.detection_failures,
        detection_success_rate,
        avg_detection_time_ms,
        classification_counts: state.classification_counts.clone(),
        strategy_attempts: state.strategy_attempts.clone(),
        strategy_successes: state.strategy_successes.clone(),
        strategy_success_rate,
        strategy_priority_delta,
    }
}

pub fn recent_fallback_events(limit: usize) -> Vec<FallbackEvent> {
    let state = telemetry().lock().expect("telemetry mutex poisoned");
    let take = limit.min(MAX_FALLBACK_EVENTS);
    state
        .fallback_events
        .iter()
        .rev()
        .take(take)
        .cloned()
        .collect()
}
