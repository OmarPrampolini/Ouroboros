use std::collections::HashMap;
/// Advanced Rate Limiting for Production DoS Protection
///
/// Combina:
/// 1. Token Bucket per burst handling elegante
/// 2. Per-IP tracking (resistente a source-port hopping)
/// 3. Exponential backoff per repeat offenders
/// 4. Early-drop integration
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

/// Token Bucket Limiter - production-grade per peer DoS protection
#[derive(Clone)]
pub struct TokenBucketLimiter {
    buckets: Arc<RwLock<HashMap<IpAddr, TokenBucket>>>,
    default_capacity: f64,
    refill_rate: f64, // tokens per second
    cleanup_interval: Duration,
    last_cleanup: Arc<RwLock<Instant>>,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
    violations: u32,                // Track repeat offenders
    penalty_until: Option<Instant>, // Exponential backoff
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
            violations: 0,
            penalty_until: None,
        }
    }

    /// Refill tokens based on time elapsed
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }

    fn backoff_seconds(violations: u32) -> u64 {
        2_u64.pow(violations.min(8))
    }

    /// Try to consume one token
    fn try_consume(&mut self) -> bool {
        self.refill();
        let now = Instant::now();

        // Check if peer is in penalty timeout (exponential backoff)
        if let Some(penalty_end) = self.penalty_until {
            if now < penalty_end {
                // Hammering while already penalized extends the timeout.
                self.violations = self.violations.saturating_add(1);
                let backoff_secs = Self::backoff_seconds(self.violations);
                self.penalty_until = Some(now + Duration::from_secs(backoff_secs));
                return false;
            }
            self.penalty_until = None; // Timeout expired
        }

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            // Successful traffic gradually recovers reputation.
            self.violations = self.violations.saturating_sub(1);
            true
        } else {
            // Rate limit exceeded - apply exponential backoff
            self.violations = self.violations.saturating_add(1);
            let backoff_secs = Self::backoff_seconds(self.violations);
            self.penalty_until = Some(now + Duration::from_secs(backoff_secs));
            false
        }
    }
}

impl TokenBucketLimiter {
    pub fn new(capacity: f64, refill_rate: f64, cleanup_interval: Duration) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            default_capacity: capacity,
            refill_rate,
            cleanup_interval,
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Check if peer can send (token bucket + exponential backoff)
    pub async fn check(&self, addr: SocketAddr) -> bool {
        // Periodic cleanup of old entries
        self.maybe_cleanup().await;

        let mut buckets = self.buckets.write().await;
        let bucket = buckets
            .entry(addr.ip())
            .or_insert_with(|| TokenBucket::new(self.default_capacity, self.refill_rate));

        bucket.try_consume()
    }

    /// Get current metrics for monitoring
    pub async fn get_metrics(&self) -> RateLimiterMetrics {
        let buckets = self.buckets.read().await;
        let now = Instant::now();
        let active_ips = buckets.len();
        let total_violations = buckets.values().map(|b| b.violations as u64).sum();
        let penalized_ips = buckets
            .values()
            .filter(|b| b.penalty_until.is_some_and(|end| end > now))
            .count();

        RateLimiterMetrics {
            active_ips,
            total_violations,
            penalized_ips,
        }
    }

    /// Periodic cleanup of inactive IP entries
    async fn maybe_cleanup(&self) {
        let should_cleanup = {
            let last_cleanup = self.last_cleanup.read().await;
            last_cleanup.elapsed() > self.cleanup_interval
        };

        if should_cleanup {
            let mut buckets = self.buckets.write().await;
            let now = Instant::now();

            // Remove entries inactive for 10+ minutes
            buckets.retain(|_, bucket| {
                now.duration_since(bucket.last_refill) < Duration::from_secs(600)
            });

            *self.last_cleanup.write().await = now;
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimiterMetrics {
    pub active_ips: usize,
    pub total_violations: u64,
    pub penalized_ips: usize,
}

/// Combined DoS Protection Strategy
#[derive(Clone)]
pub struct DoSProtector {
    token_limiter: TokenBucketLimiter,
    tag_expected: u16,
    tag8_expected: u8,
}

impl DoSProtector {
    pub fn new(tag_expected: u16, tag8_expected: u8) -> Self {
        // Production-tuned parameters:
        // - 10 tokens capacity (burst of 10 packets)
        // - 5 tokens/second refill (sustainable rate)
        // - 60s cleanup interval
        let token_limiter = TokenBucketLimiter::new(10.0, 5.0, Duration::from_secs(60));

        Self {
            token_limiter,
            tag_expected,
            tag8_expected,
        }
    }

    /// Comprehensive DoS check: early-drop + rate limiting
    pub async fn should_process_packet(&self, packet: &[u8], source: SocketAddr) -> bool {
        // 1. FIRST: Early drop by tag (zero CPU cost for wrong tags)
        if crate::security::early_drop_packet(packet, self.tag_expected, self.tag8_expected) {
            return false;
        }

        // 2. SECOND: Token bucket rate limiting (only for correct tags)
        self.token_limiter.check(source).await
    }

    pub async fn get_metrics(&self) -> DoSMetrics {
        let limiter_metrics = self.token_limiter.get_metrics().await;

        DoSMetrics {
            rate_limiter: limiter_metrics,
            expected_tag: self.tag_expected,
            expected_tag8: self.tag8_expected,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DoSMetrics {
    pub rate_limiter: RateLimiterMetrics,
    pub expected_tag: u16,
    pub expected_tag8: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_token_bucket_basic() {
        let limiter = TokenBucketLimiter::new(3.0, 1.0, Duration::from_secs(60));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234);

        // Should allow 3 requests immediately (bucket capacity)
        assert!(limiter.check(addr).await);
        assert!(limiter.check(addr).await);
        assert!(limiter.check(addr).await);

        // 4th request should be denied (bucket empty)
        assert!(!limiter.check(addr).await);

        // Wait for refill (1 token per second)
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should allow 2 more requests (2 seconds = 2 tokens)
        assert!(limiter.check(addr).await);
        assert!(limiter.check(addr).await);
        assert!(!limiter.check(addr).await);
    }

    #[tokio::test]
    async fn test_exponential_backoff() {
        let limiter = TokenBucketLimiter::new(1.0, 0.1, Duration::from_secs(60)); // Very low rate
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234);

        // Exhaust tokens and trigger violations
        assert!(limiter.check(addr).await); // Use initial token
        assert!(!limiter.check(addr).await); // First violation (2s backoff)
        assert!(!limiter.check(addr).await); // Hammering escalates (4s backoff)

        // Should still be denied even after short wait
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!limiter.check(addr).await);
    }

    #[tokio::test]
    async fn test_dos_protector() {
        let protector = DoSProtector::new(0x1337, 0x42);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234);

        // Wrong tag should be dropped immediately
        let wrong_tag_packet = [0x42, 0x42, 0x01, 0x02];
        assert!(
            !protector
                .should_process_packet(&wrong_tag_packet, addr)
                .await
        );

        // Correct tag should pass (within rate limit)
        let good_packet = [0x37, 0x13, 0x01, 0x02];
        assert!(protector.should_process_packet(&good_packet, addr).await);
    }

    #[tokio::test]
    async fn test_same_ip_different_ports_share_bucket() {
        let limiter = TokenBucketLimiter::new(2.0, 0.0, Duration::from_secs(60));
        let addr_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 10000);
        let addr_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000);

        assert!(limiter.check(addr_a).await);
        assert!(limiter.check(addr_b).await);
        assert!(!limiter.check(addr_a).await);

        let metrics = limiter.get_metrics().await;
        assert_eq!(metrics.active_ips, 1);
    }

    #[tokio::test]
    async fn test_hammering_during_penalty_extends_timeout() {
        let limiter = TokenBucketLimiter::new(1.0, 0.0, Duration::from_secs(60));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 1234);

        assert!(limiter.check(addr).await);
        assert!(!limiter.check(addr).await);

        let first_penalty = {
            let buckets = limiter.buckets.read().await;
            buckets.get(&addr.ip()).unwrap().penalty_until.unwrap()
        };

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!limiter.check(addr).await);

        let second_penalty = {
            let buckets = limiter.buckets.read().await;
            buckets.get(&addr.ip()).unwrap().penalty_until.unwrap()
        };

        assert!(second_penalty > first_penalty);
    }
}
