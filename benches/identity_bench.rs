use criterion::{black_box, criterion_group, criterion_main, Criterion};
use r_nads_bot_detection::BotDetectionEngine;
use r_nads_fingerprint::FingerprintEngine;
use r_nads_http::SecurityRequest;
use std::collections::HashMap;
use std::net::IpAddr;

fn bench_fingerprint_generation(c: &mut Criterion) {
    let engine = FingerprintEngine::with_default_key();
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0".to_string(),
    );
    headers.insert("Accept-Language".to_string(), "en-US,en;q=0.9".to_string());
    headers.insert(
        "Accept-Encoding".to_string(),
        "gzip, deflate, br".to_string(),
    );

    let req = SecurityRequest::new(ip, "GET", "/api/v1/auth/login", headers, None, 1024);

    c.bench_function("fingerprint_generation", |b| {
        b.iter(|| {
            let res = engine.fingerprint(black_box(&req));
            black_box(res);
        })
    });
}

fn bench_bot_classification(c: &mut Criterion) {
    let fp_engine = FingerprintEngine::with_default_key();
    let bot_engine = BotDetectionEngine::new();
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0".to_string(),
    );
    headers.insert("Accept-Language".to_string(), "en-US,en;q=0.9".to_string());
    let req = SecurityRequest::new(ip, "GET", "/api/v1/auth/login", headers, None, 1024);
    let identity = fp_engine.fingerprint(&req);

    c.bench_function("bot_classification", |b| {
        b.iter(|| {
            let res = bot_engine.classify(black_box(&identity), black_box(&req));
            black_box(res);
        })
    });
}

criterion_group!(
    benches,
    bench_fingerprint_generation,
    bench_bot_classification
);
criterion_main!(benches);
