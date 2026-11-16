use criterion::{black_box, criterion_group, criterion_main, Criterion};
use r_nads_decision::SystemTimeSource;
use r_nads_ratelimit::{
    MultiDimensionalRateLimiter, RateLimitKey, RateLimiterConfig, TokenBucketLimiter,
};
use std::net::IpAddr;
use std::sync::Arc;

fn bench_token_bucket(c: &mut Criterion) {
    let time_source = Arc::new(SystemTimeSource);
    let limiter = TokenBucketLimiter::new(1_000_000, 1_000_000.0, time_source);
    let key = RateLimitKey::from_ip("192.168.1.100".parse::<IpAddr>().unwrap());

    c.bench_function("token_bucket_check_and_consume", |b| {
        b.iter(|| {
            let res = limiter.check_and_consume(black_box(&key));
            black_box(res);
        })
    });
}

fn bench_multidimensional_lookup(c: &mut Criterion) {
    let time_source = Arc::new(SystemTimeSource);
    let config = RateLimiterConfig {
        ip_burst_capacity: 100_000,
        ip_refill_per_sec: 100_000.0,
        subnet_window_requests: 500_000,
        subnet_window_duration_ms: 60_000,
        route_burst_capacity: 100_000,
        route_refill_per_sec: 100_000.0,
        max_tracked_entries: 500_000,
    };
    let limiter = Arc::new(MultiDimensionalRateLimiter::new(&config, time_source));
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let route = "/api/v1/auth/login";

    c.bench_function("multidimensional_rate_limiter_evaluate", |b| {
        b.iter(|| {
            let res = limiter.evaluate(black_box(ip), black_box(Some(route)));
            black_box(res);
        })
    });
}

criterion_group!(benches, bench_token_bucket, bench_multidimensional_lookup);
criterion_main!(benches);
