use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dashmap::DashMap;
use pingora_load_balancing::prelude::TcpHealthCheck;
use pingora_load_balancing::LoadBalancer;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};

use r_nads_bot_detection::BotDetectionEngine;
use r_nads_config::SystemConfig;
use r_nads_fingerprint::FingerprintEngine;
use r_nads_http::SecurityRequest;
use r_nads_proxy::{GatewayRequestContext, StandaloneGatewayProxy};
use r_nads_ratelimit::{MultiDimensionalRateLimiter, RateLimiterConfig};
use r_nads_waf::{WafConfig, WafEngine};

fn setup_gateway_environment() -> (
    Arc<StandaloneGatewayProxy>,
    SecurityRequest,
    GatewayRequestContext,
) {
    let blocklist = Arc::new(DashMap::new());
    let config = Arc::new(RwLock::new(SystemConfig {
        mode: "classify".to_string(),
        workers: 1,
        capacity: 100,
        database_path: "test.db".to_string(),
        log_path: "test.log".to_string(),
        block_list_ttl: 30,
        nginx_bind: "127.0.0.1:18090".to_string(),
        capture_source: "mock".to_string(),
        pps: 10,
        flows: 10,
        pcap_file: None,
        interface: None,
        training_samples: 10,
        mitigation_mode: "monitor".to_string(),
        model_path: "model.json".to_string(),
    }));
    let time_source = Arc::new(r_nads_decision::SystemTimeSource);
    let rate_limiter = Arc::new(MultiDimensionalRateLimiter::new(
        &RateLimiterConfig::default(),
        time_source,
    ));
    let waf_engine = Arc::new(WafEngine::new(WafConfig::default()));
    let fingerprint_engine = Arc::new(FingerprintEngine::with_default_key());
    let bot_engine = Arc::new(BotDetectionEngine::new());
    let packet_counter = Arc::new(AtomicU64::new(0));
    let latency_sum_us = Arc::new(AtomicU64::new(0));

    let mut lb = LoadBalancer::try_from_iter(["127.0.0.1:8080"]).unwrap();
    let hc = TcpHealthCheck::default();
    lb.set_health_check(Box::new(hc));

    let proxy = Arc::new(StandaloneGatewayProxy {
        load_balancer: Arc::new(lb),
        blocklist,
        config,
        rate_limiter,
        waf_engine,
        fingerprint_engine,
        bot_engine,
        packet_counter,
        latency_sum_us,
    });

    let ip: IpAddr = "192.0.2.10".parse().unwrap();
    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0".to_string(),
    );
    headers.insert("Accept-Language".to_string(), "en-US,en;q=0.9".to_string());
    headers.insert("Accept-Encoding".to_string(), "gzip, deflate".to_string());

    let sec_req = SecurityRequest::new(
        ip,
        "GET",
        "/api/v1/resource?id=1024",
        headers,
        None,
        128 * 1024,
    );

    let ctx = GatewayRequestContext::new(ip, "GET".to_string(), "/api/v1/resource".to_string());

    (proxy, sec_req, ctx)
}

fn bench_gateway_security_pipeline(c: &mut Criterion) {
    let (proxy, req, mut ctx) = setup_gateway_environment();

    c.bench_function("pingora_gateway_full_security_filter", |b| {
        b.iter(|| {
            // 1. Rate Limiting Check
            let rate_decision = proxy
                .rate_limiter
                .evaluate(req.client_ip, Some(&req.canonical_path));
            black_box(&rate_decision);

            // 2. Identity Fingerprinting
            let identity = proxy.fingerprint_engine.fingerprint(black_box(&req));
            black_box(&identity);

            // 3. Bot Classification
            let bot_class = proxy.bot_engine.classify(&identity, black_box(&req));
            black_box(&bot_class);

            // 4. Native WAF Inspection (Headers & URI)
            let violations = proxy.waf_engine.inspect(black_box(&req));
            black_box(&violations);

            // 5. Context state update
            ctx.client_identity = Some(identity);
            ctx.bot_classification = Some(bot_class);
            black_box(&ctx);
        });
    });
}

criterion_group!(benches, bench_gateway_security_pipeline);
criterion_main!(benches);
