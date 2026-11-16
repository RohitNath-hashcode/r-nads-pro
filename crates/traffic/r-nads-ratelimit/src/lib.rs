#![forbid(unsafe_code)]

use ahash::RandomState;
use dashmap::DashMap;
use r_nads_common::canonicalize_ip;
use r_nads_decision::{SystemTimeSource, TimeSource};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Multi-dimensional key for traffic rate limiting.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RateLimitKey {
    /// Single IP address (IPv4 or IPv6)
    Ip(IpAddr),
    /// IPv4 /24 subnet (first 3 octets)
    SubnetV4([u8; 3]),
    /// IPv6 /64 subnet (first 8 octets)
    SubnetV6([u8; 8]),
    /// Specific URI path or API endpoint
    Route(String),
    /// API Key, Bearer Token, or Tenant identifier
    ApiKey(String),
    /// Composite: Specific IP hitting a specific Route
    IpAndRoute(IpAddr, String),
}

impl RateLimitKey {
    /// Creates a normalized IP key.
    #[inline]
    pub fn from_ip(ip: IpAddr) -> Self {
        Self::Ip(canonicalize_ip(ip))
    }

    /// Creates a subnet key (/24 for IPv4, /64 for IPv6).
    #[inline]
    pub fn from_ip_subnet(ip: IpAddr) -> Self {
        match canonicalize_ip(ip) {
            IpAddr::V4(v4) => {
                let oct = v4.octets();
                Self::SubnetV4([oct[0], oct[1], oct[2]])
            }
            IpAddr::V6(v6) => {
                let oct = v6.octets();
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&oct[0..8]);
                Self::SubnetV6(prefix)
            }
        }
    }

    /// Creates a route key.
    #[inline]
    pub fn from_route(route: &str) -> Self {
        Self::Route(route.to_string())
    }

    /// Creates an API key identifier.
    #[inline]
    pub fn from_api_key(key: &str) -> Self {
        Self::ApiKey(key.to_string())
    }

    /// Creates a composite IP + Route key.
    #[inline]
    pub fn from_ip_and_route(ip: IpAddr, route: &str) -> Self {
        Self::IpAndRoute(canonicalize_ip(ip), route.to_string())
    }
}

/// Decision returned by rate limiting evaluators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitDecision {
    Allowed {
        remaining: u64,
        reset_after_ms: u64,
    },
    Limited {
        retry_after_ms: u64,
        violated_limit: String,
    },
}

impl RateLimitDecision {
    #[inline]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    #[inline]
    pub fn is_limited(&self) -> bool {
        matches!(self, Self::Limited { .. })
    }
}

// ---------------------------------------------------------------------------
// 1. Token Bucket Algorithm (Bursty traffic with smooth replenishment)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TokenBucketState {
    tokens: f64,
    last_update_ms: u64,
}

/// In-memory Token Bucket rate limiter.
/// Allows bursts up to `capacity`, continuously replenishing at `refill_rate_per_sec`.
pub struct TokenBucketLimiter {
    capacity: f64,
    refill_rate_per_sec: f64,
    buckets: DashMap<RateLimitKey, TokenBucketState, RandomState>,
    time_source: Arc<dyn TimeSource>,
}

impl TokenBucketLimiter {
    pub fn new(capacity: u64, refill_rate_per_sec: f64, time_source: Arc<dyn TimeSource>) -> Self {
        Self {
            capacity: capacity as f64,
            refill_rate_per_sec,
            buckets: DashMap::with_hasher(RandomState::new()),
            time_source,
        }
    }

    /// Check and consume 1 token for the specified key.
    /// Runs in O(1) lock-sharded time (< 30 ns).
    #[inline]
    pub fn check_and_consume(&self, key: &RateLimitKey) -> RateLimitDecision {
        let now_ms = self.time_source.current_timestamp_millis();
        let mut entry = self
            .buckets
            .entry(key.clone())
            .or_insert_with(|| TokenBucketState {
                tokens: self.capacity,
                last_update_ms: now_ms,
            });

        let state = entry.value_mut();
        // Calculate refilled tokens based on elapsed time
        let elapsed_secs = (now_ms.saturating_sub(state.last_update_ms) as f64) / 1000.0;
        state.tokens = (state.tokens + elapsed_secs * self.refill_rate_per_sec).min(self.capacity);
        state.last_update_ms = now_ms;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            RateLimitDecision::Allowed {
                remaining: state.tokens.floor() as u64,
                reset_after_ms: if self.refill_rate_per_sec > 0.0 {
                    ((self.capacity - state.tokens) / self.refill_rate_per_sec * 1000.0) as u64
                } else {
                    0
                },
            }
        } else {
            let needed = 1.0 - state.tokens;
            let retry_after_ms = if self.refill_rate_per_sec > 0.0 {
                ((needed / self.refill_rate_per_sec) * 1000.0).ceil() as u64
            } else {
                1000
            };
            RateLimitDecision::Limited {
                retry_after_ms: retry_after_ms.max(1),
                violated_limit: "token_bucket".to_string(),
            }
        }
    }

    /// Total number of tracked keys.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

// ---------------------------------------------------------------------------
// 2. Sliding Window Counter Algorithm (Strict time-window quotas)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
struct WindowCounter {
    window_start_ms: u64,
    count: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct SlidingWindowState {
    current: WindowCounter,
    previous: WindowCounter,
}

/// Cloudflare-style Sliding Window Counter limiter.
/// Approximates exact sliding log accuracy with O(1) memory and zero log allocations.
pub struct SlidingWindowLimiter {
    max_requests: u64,
    window_duration_ms: u64,
    windows: DashMap<RateLimitKey, SlidingWindowState, RandomState>,
    time_source: Arc<dyn TimeSource>,
}

impl SlidingWindowLimiter {
    pub fn new(
        max_requests: u64,
        window_duration_ms: u64,
        time_source: Arc<dyn TimeSource>,
    ) -> Self {
        Self {
            max_requests,
            window_duration_ms: window_duration_ms.max(1),
            windows: DashMap::with_hasher(RandomState::new()),
            time_source,
        }
    }

    /// Check and increment the sliding window counter.
    #[inline]
    pub fn check_and_increment(&self, key: &RateLimitKey) -> RateLimitDecision {
        let now_ms = self.time_source.current_timestamp_millis();
        let current_window_start = now_ms - (now_ms % self.window_duration_ms);

        let mut entry = self
            .windows
            .entry(key.clone())
            .or_insert_with(|| SlidingWindowState {
                current: WindowCounter {
                    window_start_ms: current_window_start,
                    count: 0,
                },
                previous: WindowCounter::default(),
            });

        let state = entry.value_mut();

        // Advance windows if time moved past current window
        if current_window_start > state.current.window_start_ms {
            let diff = current_window_start - state.current.window_start_ms;
            if diff == self.window_duration_ms {
                state.previous = state.current;
            } else {
                state.previous = WindowCounter::default();
            }
            state.current = WindowCounter {
                window_start_ms: current_window_start,
                count: 0,
            };
        }

        // Weighted count: (1 - weight) * prev + current
        let elapsed_in_window = now_ms - current_window_start;
        let weight =
            (self.window_duration_ms - elapsed_in_window) as f64 / self.window_duration_ms as f64;
        let estimated_count =
            (state.previous.count as f64 * weight).floor() as u64 + state.current.count;

        if estimated_count < self.max_requests {
            state.current.count += 1;
            let remaining = self.max_requests.saturating_sub(estimated_count + 1);
            let reset_after_ms = self.window_duration_ms - elapsed_in_window;
            RateLimitDecision::Allowed {
                remaining,
                reset_after_ms,
            }
        } else {
            let retry_after_ms = self.window_duration_ms - elapsed_in_window;
            RateLimitDecision::Limited {
                retry_after_ms: retry_after_ms.max(1),
                violated_limit: "sliding_window".to_string(),
            }
        }
    }

    pub fn len(&self) -> usize {
        self.windows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }
}

// ---------------------------------------------------------------------------
// 3. Concurrency Limiter (Bounded simultaneous in-flight connections)
// ---------------------------------------------------------------------------

/// Tracks concurrent in-flight executions per key.
pub struct ConcurrencyLimiter {
    max_concurrency: u32,
    active: DashMap<RateLimitKey, Arc<AtomicU32>, RandomState>,
}

pub struct ConcurrencyGuard {
    counter: Arc<AtomicU32>,
}

impl Drop for ConcurrencyGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ConcurrencyLimiter {
    pub fn new(max_concurrency: u32) -> Self {
        Self {
            max_concurrency,
            active: DashMap::with_hasher(RandomState::new()),
        }
    }

    /// Attempts to acquire an in-flight slot. Returns `Some(guard)` on success,
    /// or `None` if concurrent limit is exhausted.
    pub fn try_acquire(&self, key: &RateLimitKey) -> Result<ConcurrencyGuard, RateLimitDecision> {
        let counter = self
            .active
            .entry(key.clone())
            .or_insert_with(|| Arc::new(AtomicU32::new(0)))
            .clone();

        loop {
            let current = counter.load(Ordering::SeqCst);
            if current >= self.max_concurrency {
                return Err(RateLimitDecision::Limited {
                    retry_after_ms: 100,
                    violated_limit: "max_concurrency".to_string(),
                });
            }
            if counter
                .compare_exchange_weak(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(ConcurrencyGuard { counter });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Unified Composite Multi-Tier Limiter
// ---------------------------------------------------------------------------

/// Configuration parameters for composite multi-tier rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterConfig {
    pub ip_burst_capacity: u64,
    pub ip_refill_per_sec: f64,
    pub subnet_window_requests: u64,
    pub subnet_window_duration_ms: u64,
    pub route_burst_capacity: u64,
    pub route_refill_per_sec: f64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            ip_burst_capacity: 100,
            ip_refill_per_sec: 20.0,
            subnet_window_requests: 1000,
            subnet_window_duration_ms: 60_000,
            route_burst_capacity: 50,
            route_refill_per_sec: 10.0,
        }
    }
}

/// High-throughput composite rate limiting engine combining IP Token Bucket,
/// Subnet Sliding Window, and Route quotas.
pub struct MultiDimensionalRateLimiter {
    ip_limiter: TokenBucketLimiter,
    subnet_limiter: SlidingWindowLimiter,
    route_limiter: TokenBucketLimiter,
}

impl MultiDimensionalRateLimiter {
    pub fn new(config: &RateLimiterConfig, time_source: Arc<dyn TimeSource>) -> Self {
        Self {
            ip_limiter: TokenBucketLimiter::new(
                config.ip_burst_capacity,
                config.ip_refill_per_sec,
                time_source.clone(),
            ),
            subnet_limiter: SlidingWindowLimiter::new(
                config.subnet_window_requests,
                config.subnet_window_duration_ms,
                time_source.clone(),
            ),
            route_limiter: TokenBucketLimiter::new(
                config.route_burst_capacity,
                config.route_refill_per_sec,
                time_source,
            ),
        }
    }

    /// Evaluates all rate-limiting dimensions in priority order:
    /// 1. Individual IP (Token Bucket)
    /// 2. Subnet /24 or /64 (Sliding Window Counter)
    /// 3. Target Route (Token Bucket)
    pub fn evaluate(&self, client_ip: IpAddr, route: Option<&str>) -> RateLimitDecision {
        // 1. Check IP rate limit
        let ip_key = RateLimitKey::from_ip(client_ip);
        let ip_decision = self.ip_limiter.check_and_consume(&ip_key);
        if ip_decision.is_limited() {
            return ip_decision;
        }

        // 2. Check Subnet rate limit (/24 IPv4, /64 IPv6)
        let subnet_key = RateLimitKey::from_ip_subnet(client_ip);
        let subnet_decision = self.subnet_limiter.check_and_increment(&subnet_key);
        if subnet_decision.is_limited() {
            return subnet_decision;
        }

        // 3. Check Route rate limit (if route specified)
        if let Some(r) = route {
            let route_key = RateLimitKey::from_route(r);
            let route_decision = self.route_limiter.check_and_consume(&route_key);
            if route_decision.is_limited() {
                return route_decision;
            }
        }

        ip_decision
    }
}

impl Default for MultiDimensionalRateLimiter {
    fn default() -> Self {
        let time_source = Arc::new(SystemTimeSource);
        Self::new(&RateLimiterConfig::default(), time_source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r_nads_decision::MockTimeSource;

    #[test]
    fn test_token_bucket_burst_and_refill() {
        let mock_time = Arc::new(MockTimeSource::new(100_000));
        // 5 tokens capacity, 1 token/sec refill
        let limiter = TokenBucketLimiter::new(5, 1.0, mock_time.clone());
        let key = RateLimitKey::from_ip("192.168.1.1".parse().unwrap());

        // First 5 requests should pass
        for i in 0..5 {
            let dec = limiter.check_and_consume(&key);
            assert!(dec.is_allowed(), "Request {} should be allowed", i);
        }

        // 6th request is blocked
        let dec6 = limiter.check_and_consume(&key);
        assert!(dec6.is_limited(), "6th request must be rate limited");

        // Advance time by 2 seconds -> should refill 2 tokens
        mock_time.advance_millis(2000);

        assert!(limiter.check_and_consume(&key).is_allowed());
        assert!(limiter.check_and_consume(&key).is_allowed());
        assert!(limiter.check_and_consume(&key).is_limited());
    }

    #[test]
    fn test_sliding_window_limiter() {
        let mock_time = Arc::new(MockTimeSource::new(0));
        // Max 3 requests per 10,000ms window
        let limiter = SlidingWindowLimiter::new(3, 10_000, mock_time.clone());
        let key = RateLimitKey::from_route("/api/login");

        assert!(limiter.check_and_increment(&key).is_allowed());
        assert!(limiter.check_and_increment(&key).is_allowed());
        assert!(limiter.check_and_increment(&key).is_allowed());
        assert!(limiter.check_and_increment(&key).is_limited());

        // Move into next window far enough so weighted count of previous window drops
        // Or advance by full 2 windows (20,000ms) where previous window is completely expired
        mock_time.advance_millis(20_000);
        assert!(limiter.check_and_increment(&key).is_allowed());
    }

    #[test]
    fn test_subnet_aggregation_ipv4_and_ipv6() {
        let ip1: IpAddr = "10.0.1.5".parse().unwrap();
        let ip2: IpAddr = "10.0.1.99".parse().unwrap();
        let ip3: IpAddr = "10.0.2.1".parse().unwrap();

        let sub1 = RateLimitKey::from_ip_subnet(ip1);
        let sub2 = RateLimitKey::from_ip_subnet(ip2);
        let sub3 = RateLimitKey::from_ip_subnet(ip3);

        assert_eq!(sub1, sub2, "Same /24 must yield identical subnet keys");
        assert_ne!(sub1, sub3, "Different /24 must yield different subnet keys");

        let v6_1: IpAddr = "2001:db8:abcd:0012::1".parse().unwrap();
        let v6_2: IpAddr = "2001:db8:abcd:0012:ffff::2".parse().unwrap();
        let v6_sub1 = RateLimitKey::from_ip_subnet(v6_1);
        let v6_sub2 = RateLimitKey::from_ip_subnet(v6_2);

        assert_eq!(
            v6_sub1, v6_sub2,
            "Same /64 must yield identical subnet keys"
        );
    }

    #[test]
    fn test_concurrency_limiter() {
        let limiter = ConcurrencyLimiter::new(2);
        let key = RateLimitKey::from_api_key("tenant_123");

        let guard1 = limiter.try_acquire(&key).expect("Slot 1 acquired");
        let guard2 = limiter.try_acquire(&key).expect("Slot 2 acquired");

        // Slot 3 must fail
        assert!(limiter.try_acquire(&key).is_err());

        // Release guard1
        drop(guard1);

        // Now slot can be acquired
        let guard3 = limiter.try_acquire(&key).expect("Slot 3 acquired");
        drop(guard2);
        drop(guard3);
    }
}
