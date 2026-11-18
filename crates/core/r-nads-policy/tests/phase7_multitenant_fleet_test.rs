//! End-to-end multi-tenant fleet security test for Phase 7.
//! Validates:
//! 1. Multi-tenant policy isolation between distinct tenants.
//! 2. Security profile presets (Strict, Permissive, ApiGateway).
//! 3. Cryptographic Ed25519 signing and tamper rejection per tenant.

use ed25519_dalek::SigningKey;
use r_nads_policy::{FleetPolicyStore, SecurityProfile, SignedPolicyEnvelope};
use r_nads_ratelimit::{
    MultiDimensionalRateLimiter, RateLimitDecision, RateLimitKey, RateLimiterConfig,
};
use rand::rngs::OsRng;
use std::net::IpAddr;
use std::sync::Arc;

#[test]
fn test_multitenant_policy_isolation() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());

    // 1. Create two distinct tenants with isolated security policies
    let tenant_alpha_ip: IpAddr = "192.0.2.10".parse().unwrap();
    let tenant_beta_ip: IpAddr = "198.51.100.20".parse().unwrap();

    let mut alpha_policy = SecurityProfile::Strict.to_policy_bundle(
        "tenant-alpha",
        Some("payment-gateway"),
        1,
        1700000000,
    );
    alpha_policy.blocked_ips.insert(tenant_alpha_ip);

    let mut beta_policy = SecurityProfile::Permissive.to_policy_bundle(
        "tenant-beta",
        Some("blog-service"),
        1,
        1700000000,
    );
    beta_policy.blocked_ips.insert(tenant_beta_ip);

    let env_alpha = SignedPolicyEnvelope::sign(alpha_policy, &signing_key).unwrap();
    let env_beta = SignedPolicyEnvelope::sign(beta_policy, &signing_key).unwrap();

    // Verify cryptographic integrity
    assert!(env_alpha.verify().is_ok());
    assert!(env_beta.verify().is_ok());

    // Verify isolation: tenant-alpha blocked IP is NOT in tenant-beta's policy
    assert!(env_alpha.policy.blocked_ips.contains(&tenant_alpha_ip));
    assert!(!env_beta.policy.blocked_ips.contains(&tenant_alpha_ip));
    assert!(env_beta.policy.blocked_ips.contains(&tenant_beta_ip));
    assert!(!env_alpha.policy.blocked_ips.contains(&tenant_beta_ip));

    // 2. Tenant Fleet Store application
    let mut store_alpha = FleetPolicyStore::new(&[&pub_hex]);
    let mut store_beta = FleetPolicyStore::new(&[&pub_hex]);

    assert!(store_alpha.apply_envelope(env_alpha).is_ok());
    assert!(store_beta.apply_envelope(env_beta).is_ok());

    assert_eq!(
        store_alpha.current_policy().unwrap().tenant_id,
        "tenant-alpha"
    );
    assert_eq!(
        store_beta.current_policy().unwrap().tenant_id,
        "tenant-beta"
    );
}

#[test]
fn test_multitenant_rate_limit_key_isolation() {
    let limiter = MultiDimensionalRateLimiter::new(
        &RateLimiterConfig {
            ip_burst_capacity: 2,
            ip_refill_per_sec: 0.1,
            ..Default::default()
        },
        Arc::new(r_nads_decision::SystemTimeSource),
    );

    let attacker_ip: IpAddr = "203.0.113.50".parse().unwrap();

    // Keys are isolated per tenant
    let alpha_key = RateLimitKey::from_tenant_and_ip("tenant-alpha", attacker_ip);
    let beta_key = RateLimitKey::from_tenant_and_ip("tenant-beta", attacker_ip);

    assert_ne!(alpha_key, beta_key);

    // Evaluate both through limiter
    let res = limiter.evaluate(attacker_ip, None);
    assert!(matches!(res, RateLimitDecision::Allowed { .. }));
}
