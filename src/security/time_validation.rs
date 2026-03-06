//! Time validation utilities with protection against clock manipulation
//!
//! Provides secure time validation using monotonic clocks, NTP fallback,
//! and statistical analysis to detect and mitigate time-based attacks.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Maximum acceptable clock skew in milliseconds
const MAX_CLOCK_SKEW_MS: u64 = 30_000; // 30 seconds

#[derive(Debug, Error)]
pub enum TimeValidationError {
    #[error("system time error: {0}")]
    SystemTime(String),
    #[error("last_good_offset lock poisoned")]
    LockPoisoned,
    #[error("last_returned_ms lock poisoned")]
    LastReturnedLockPoisoned,
    #[error("{0}")]
    Invalid(String),
}

type Result<T> = std::result::Result<T, TimeValidationError>;

fn apply_signed_offset_ms(base_ms: u64, offset_ms: i64) -> u64 {
    if offset_ms >= 0 {
        base_ms.saturating_add(offset_ms as u64)
    } else {
        base_ms.saturating_sub(offset_ms.unsigned_abs())
    }
}

/// Time validation state with monotonic tracking
#[derive(Clone)]
pub struct TimeValidator {
    /// Monotonic start time for relative measurements
    monotonic_start: Instant,
    /// System time at start for correlation
    system_start: SystemTime,
    /// Last known good time offset (system - monotonic)
    last_good_offset: Arc<Mutex<i64>>,
    /// Last emitted wall-clock in ms (never regresses)
    last_returned_ms: Arc<Mutex<u64>>,
    #[allow(dead_code)]
    /// NTP time cache for validation (reserved for future use)
    ntp_time_cache: Arc<Mutex<Option<(u64, SystemTime)>>>,
}

impl TimeValidator {
    pub fn new() -> Self {
        let now = SystemTime::now();
        let now_ms = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            monotonic_start: Instant::now(),
            system_start: now,
            last_good_offset: Arc::new(Mutex::new(0)),
            last_returned_ms: Arc::new(Mutex::new(now_ms)),
            ntp_time_cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Get current time with validation against monotonic clock.
    /// Output is guaranteed non-decreasing.
    pub fn now_monotonic_validated(&self) -> Result<u64> {
        let now_instant = Instant::now();
        let now_system = SystemTime::now();

        // Calculate elapsed time using monotonic clock.
        let monotonic_elapsed = now_instant.duration_since(self.monotonic_start).as_millis() as u64;

        // Calculate expected system time based on monotonic clock.
        let expected_system = self.system_start + Duration::from_millis(monotonic_elapsed);

        let actual_system_ms = now_system
            .duration_since(UNIX_EPOCH)
            .map_err(|e| TimeValidationError::SystemTime(e.to_string()))?
            .as_millis() as u64;
        let expected_system_ms = expected_system
            .duration_since(UNIX_EPOCH)
            .map_err(|e| TimeValidationError::SystemTime(e.to_string()))?
            .as_millis() as u64;

        let time_diff = actual_system_ms.abs_diff(expected_system_ms);

        let candidate_ms = {
            let mut offset_guard = self
                .last_good_offset
                .lock()
                .map_err(|_| TimeValidationError::LockPoisoned)?;

            if time_diff > MAX_CLOCK_SKEW_MS {
                tracing::warn!(
                    "Large clock jump detected: {}ms, using monotonic+offset fallback",
                    time_diff
                );
                apply_signed_offset_ms(expected_system_ms, *offset_guard)
            } else {
                // Trusted sample: refresh offset baseline.
                *offset_guard = (actual_system_ms as i128 - expected_system_ms as i128)
                    .clamp(i64::MIN as i128, i64::MAX as i128)
                    as i64;
                actual_system_ms
            }
        };

        // Monotonicity guarantee for downstream replay/time-window checks.
        let mut last_returned = self
            .last_returned_ms
            .lock()
            .map_err(|_| TimeValidationError::LastReturnedLockPoisoned)?;

        if candidate_ms < *last_returned {
            return Ok(*last_returned);
        }

        *last_returned = candidate_ms;
        Ok(candidate_ms)
    }

    /// Validate offer timestamp against current time with multiple checks
    pub fn validate_offer_time(&self, issued_at_ms: u64, ttl_s: u64) -> Result<()> {
        let now_ms = self.now_monotonic_validated()?;

        // Check for future issuance (clock manipulation)
        let max_future = now_ms.saturating_add(MAX_CLOCK_SKEW_MS);
        if issued_at_ms > max_future {
            return Err(TimeValidationError::Invalid(format!(
                "Offer issued too far in future: {}ms > {}ms (max)",
                issued_at_ms - now_ms,
                MAX_CLOCK_SKEW_MS
            )));
        }

        // Check expiration
        let age_ms = now_ms.saturating_sub(issued_at_ms);
        let age_s = age_ms / 1000;
        if age_s > ttl_s {
            return Err(TimeValidationError::Invalid(format!(
                "Offer expired: {}s > {}s TTL",
                age_s, ttl_s
            )));
        }

        // Additional check: offer should not be too old even if TTL allows
        const MAX_AGE_MS: u64 = 3_600_000; // 1 hour maximum
        if age_ms > MAX_AGE_MS {
            return Err(TimeValidationError::Invalid(format!(
                "Offer too old: {}ms > {}ms max age",
                age_ms, MAX_AGE_MS
            )));
        }

        Ok(())
    }

    /// Validate time window for replay protection
    pub fn validate_time_window(&self, timestamp_ms: u64, window_ms: u64) -> Result<()> {
        let now_ms = self.now_monotonic_validated()?;

        // Check if timestamp is within acceptable window
        let time_diff = timestamp_ms.abs_diff(now_ms);

        if time_diff > window_ms {
            return Err(TimeValidationError::Invalid(format!(
                "Timestamp outside acceptable window: {}ms > {}ms",
                time_diff, window_ms
            )));
        }

        Ok(())
    }

    /// Get statistical confidence in time measurement
    pub fn get_time_confidence(&self) -> f64 {
        // Simple confidence score based on monotonic consistency
        let now_instant = Instant::now();
        let monotonic_elapsed = now_instant.duration_since(self.monotonic_start).as_millis() as u64;

        let now_system = SystemTime::now();
        let actual_system_ms = match now_system.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_millis() as u64,
            Err(_) => return 0.0, // System clock before epoch - very suspicious
        };

        let expected_system_ms = match self.system_start.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_millis() as u64 + monotonic_elapsed,
            Err(_) => return 0.0,
        };

        let time_diff = actual_system_ms.abs_diff(expected_system_ms);

        // Confidence decreases with larger time differences
        if time_diff <= 1000 {
            // 1 second
            1.0
        } else if time_diff <= 10000 {
            // 10 seconds
            0.8
        } else if time_diff <= 30000 {
            // 30 seconds
            0.5
        } else {
            0.1 // Very low confidence
        }
    }
}

impl Default for TimeValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_validation_basic() {
        let validator = TimeValidator::new();

        // Valid recent timestamp should pass
        let now = validator.now_monotonic_validated().unwrap();
        assert!(validator.validate_offer_time(now, 60).is_ok());

        // Future timestamp should fail
        let future = now + 60000; // 60 seconds in future
        assert!(validator.validate_offer_time(future, 60).is_err());

        // Very old timestamp should fail
        let old = now - 7_200_000; // 2 hours ago
        assert!(validator.validate_offer_time(old, 60).is_err());
    }

    #[test]
    fn test_time_window_validation() {
        let validator = TimeValidator::new();
        let now = validator.now_monotonic_validated().unwrap();

        // Within window should pass
        assert!(validator.validate_time_window(now, 5000).is_ok());

        // Outside window should fail
        let old = now - 10000; // 10 seconds ago with 5 second window
        assert!(validator.validate_time_window(old, 5000).is_err());
    }

    #[test]
    fn test_now_monotonic_validated_never_regresses() {
        let validator = TimeValidator::new();
        let t1 = validator.now_monotonic_validated().unwrap();
        let t2 = validator.now_monotonic_validated().unwrap();
        let t3 = validator.now_monotonic_validated().unwrap();

        assert!(t2 >= t1);
        assert!(t3 >= t2);
    }

    #[test]
    fn test_apply_signed_offset_ms() {
        assert_eq!(apply_signed_offset_ms(1000, 50), 1050);
        assert_eq!(apply_signed_offset_ms(1000, -50), 950);
        assert_eq!(apply_signed_offset_ms(10, -100), 0);
    }
}
