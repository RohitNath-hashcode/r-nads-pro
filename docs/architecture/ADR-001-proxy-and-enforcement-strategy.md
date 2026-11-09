# ADR-001: Dual Proxy Architecture & Enforcement Strategy

- **Status**: Accepted
- **Date**: 2026-11-09
- **Author**: R-NADS Core Architecture Team
- **Context**: R-NADS Pro Production Architecture & Engineering Blueprint

---

## 1. Context and Problem Statement

Modern enterprise environments run diverse ingress infrastructure. While existing production stacks frequently rely on NGINX, Cloudflare, or AWS ALB for TLS termination and ingress traffic routing, high-performance edge deployments and zero-trust perimeter gates demand lower-latency native proxies capable of streaming full-body WAF inspection and sub-microsecond behavioral scoring.

A monolithic approach—either forcing customers to replace NGINX entirely or restricting R-NADS to passive NGINX `auth_request` subrequests—severely limits product adoption:
1. **NGINX `auth_request` Limitation**: As documented in the official NGINX HTTP auth request module specification, request bodies are discarded for subrequests (`proxy_pass_request_body off`). An authorization endpoint alone cannot inspect HTTP request bodies (POST payloads, JSON, multipart uploads) for SQLi, XSS, or RCE vulnerabilities.
2. **Migration Friction**: Requiring organizations to replace battle-tested NGINX clusters on Day 1 creates unacceptable operational risk and adoption friction.

R-NADS Pro requires an architectural strategy that protects existing infrastructure immediately while providing an evolutionary path toward native Rust edge proxying.

---

## 2. Decision: Two-Deployment Modes, Unified Intelligence

We adopt a **Dual-Mode Enforcement Architecture** backed by a shared security intelligence plane:

```
                          ┌─────────────────────────────────────┐
                          │     Shared Intelligence Plane       │
                          │ (r-nads-decision, r-nads-inference) │
                          └──────────────┬──────────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │                                               │
                 ▼                                               ▼
     Mode A: NGINX Integrated                       Mode B: Native Rust Gateway
┌─────────────────────────────────┐             ┌─────────────────────────────────┐
│ [Internet / Upstream CDN]       │             │ [Internet / Upstream CDN]       │
│                │                │             │                │                │
│       [NGINX Reverse Proxy]     │             │    [Pingora / Native Proxy]     │
│       ├── TLS Termination       │             │    ├── TLS Termination          │
│       ├── auth_request /check   │             │    ├── Full Stream Inspection   │
│       │   └── r-nads-nginx      │             │    ├── Streaming WAF (CRS)      │
│       └── Application Upstream  │             │    └── Application Upstream     │
└─────────────────────────────────┘             └─────────────────────────────────┘
```

### 2.1 Mode A: NGINX-Integrated Deployment (Immediate Production)
- **Role**: Drops into existing NGINX, OpenResty, or Kubernetes ingress controller fleets.
- **Protocol**: NGINX executes an internal subrequest to R-NADS via `auth_request /check`.
- **Inspection Scope**: Client IP reputation, SVDD behavioral network anomaly state, HTTP request headers, URI patterns, JA4/TLS fingerprints.
- **Fail-Open / Fail-Closed**: Configurable via `error_page 500 502 503 504 =200 @fail_open` or strictly rejected (`=403 @fail_closed`).
- **Body Inspection Bridge**: Where deep body inspection is required within NGINX, traffic routes through a local loopback reverse-proxy filter (`proxy_pass http://127.0.0.1:8080`) before reaching upstream application servers.

### 2.2 Mode B: Native Rust Gateway (Strategic Target)
- **Role**: Standalone high-throughput perimeter gateway built upon modern Rust proxy foundations (e.g., Cloudflare Pingora / Hyper).
- **Protocol**: Directly terminates HTTP/1.1, HTTP/2 (and HTTP/3 QUIC), proxies upstream connections.
- **Inspection Scope**: Full bi-directional zero-copy body streaming, native OWASP Core Rule Set (CRS) evaluation, real-time token bucket rate limiting, and zero-day SVDD anomaly scoring.
- **Zero-Copy Hot Path**: Detection engines evaluate memory slices directly from streaming buffers without full-payload buffering where possible.

---

## 3. Standardized Contracts & Decoupling

To ensure that no security intelligence or mitigation logic is tied to a specific proxy vendor, all decisions are mediated through canonical workspace contracts defined in `crates/core/r-nads-decision`:

1. **`SecurityEvidence`**: Captures normalized signals across network flows, HTTP metadata, WAF rules, and behavioral telemetry.
2. **`SecurityDecision`**: Uniform decision structure emitted by intelligence engines:
   - `action`: `Allow`, `Block`, `ChallengeCaptcha`, `RateLimit`, `Simulate`.
   - `confidence`: Confidence score in `[0.0, 1.0]`.
   - `reason`: Structured enum (`AnomalyScoreExceeded`, `WafRuleMatch`, `ReputationBlock`, `RateLimitExceeded`, etc.).
3. **`MitigationProvider` Trait**: Abstraction implemented by enforcement adapters:
   - `apply_mitigation(&self, client_ip: IpAddr, action: &MitigationAction) -> Result<MitigationResult, Error>`
   - `remove_mitigation(&self, client_ip: IpAddr) -> Result<bool, Error>`

---

## 4. Latency Budgets & Performance SLA

Every inbound transaction must adhere to strict latency boundaries:

| Pipeline Stage | Target Latency Budget | Maximum SLA | Enforcement Mechanism |
| :--- | :--- | :--- | :--- |
| **SVDD / RFF Inference** | **172 ns** | **< 500 ns** | In-register SIMD math, static `OnceLock` weights |
| **Flow Aggregation** | **< 2 µs** | **< 5 µs** | Slab allocation, pre-warmed LRU table, zero-alloc |
| **Decision Engine Lookup** | **< 5 µs** | **< 10 µs** | In-memory lockless `DashMap` & atomic bitsets |
| **NGINX `/check` Response** | **< 200 µs** | **< 1 ms** | Lightweight socket server with keep-alive |
| **Native Proxy Streaming Overhead** | **< 500 µs** | **< 2 ms** | Zero-copy chunk inspection in Pingora pipeline |

---

## 5. Fail-Safe Semantics

1. **Default Fail-Open**: If the R-NADS mitigation agent encounters an internal panic or timeout (> 20ms on `/check`), NGINX is configured to return `HTTP 200 OK` unless the route is explicitly annotated with `r_nads_fail_closed on;`. This guarantees critical enterprise services never experience downtime due to security sensor glitches.
2. **Automated Alarm Generation**: Any fail-open invocation immediately dispatches an urgent diagnostic alert to SQLite forensics and central SOC logging.
3. **Behavioral Auto-Unblocking**: When an IP previously classified as anomalous exhibits normal traffic within the SVDD hypersphere ($s(x) \le R^2$), the blocklist entry is dynamically cleared before the TTL expiration.

---

## 6. Consequences & Next Steps

- **Positive**: Existing NGINX infrastructure can be secured immediately in Phase 0/1 without risk of disrupting business workflows.
- **Positive**: All detection logic (SVDD, WAF rules, rate limiters) is crate-isolated and ready for native Pingora embedding in Phase 3.
- **Trade-off**: Running NGINX `auth_request` without the body inspection loopback proxy omits POST body analysis. The documentation and setup wizards will explicitly surface this distinction to administrators.

