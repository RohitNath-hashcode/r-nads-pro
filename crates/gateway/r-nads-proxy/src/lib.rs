#![forbid(unsafe_code)]

//! Native Pingora-powered reverse proxy gateway for R-NADS Pro.
//!
//! Provides zero-downtime, standalone reverse proxy capabilities, executing
//! inline multi-dimensional rate limiting, WAF heuristic inspection, salted
//! BLAKE3 identity fingerprinting, and behavioral bot classification.

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use pingora_core::prelude::*;
use pingora_error::{Error, ErrorSource, ErrorType};
use pingora_http::{ResponseHeader, StatusCode};
use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::LoadBalancer;
use pingora_proxy::{ProxyHttp, Session};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use r_nads_bot_detection::{BotClassification, BotDetectionEngine};
use r_nads_config::SystemConfig;
use r_nads_decision::{DecisionAction, DecisionReason, SecurityDecision};
use r_nads_fingerprint::{ClientIdentity, FingerprintEngine};
use r_nads_http::SecurityRequest;
use r_nads_ratelimit::MultiDimensionalRateLimiter;
use r_nads_waf::WafEngine;

/// Request-scoped context carrying telemetry, extracted identity, and partial body payload.
pub struct GatewayRequestContext {
    pub client_ip: IpAddr,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body_buffer: Vec<u8>,
    pub client_identity: Option<ClientIdentity>,
    pub bot_classification: Option<BotClassification>,
    pub decision: Option<SecurityDecision>,
    pub body_inspected: bool,
    pub start_time: Instant,
}

impl GatewayRequestContext {
    pub fn new(client_ip: IpAddr, method: String, path: String) -> Self {
        Self {
            client_ip,
            method,
            path,
            headers: HashMap::new(),
            body_buffer: Vec::new(),
            client_identity: None,
            bot_classification: None,
            decision: None,
            body_inspected: false,
            start_time: Instant::now(),
        }
    }
}

/// Standalone Gateway Reverse Proxy implementing Pingora's `ProxyHttp`.
pub struct StandaloneGatewayProxy {
    pub load_balancer: Arc<LoadBalancer<RoundRobin>>,
    pub blocklist: Arc<DashMap<IpAddr, Instant>>,
    pub config: Arc<std::sync::RwLock<SystemConfig>>,
    pub rate_limiter: Arc<MultiDimensionalRateLimiter>,
    pub waf_engine: Arc<WafEngine>,
    pub fingerprint_engine: Arc<FingerprintEngine>,
    pub bot_engine: Arc<BotDetectionEngine>,
    pub packet_counter: Arc<AtomicU64>,
    pub latency_sum_us: Arc<AtomicU64>,
}

impl StandaloneGatewayProxy {
    /// Maximum body inspection ceiling in bytes (128 KB standard).
    pub const MAX_BODY_INSPECTION_BYTES: usize = 128 * 1024;

    /// Builds a response header with security and telemetry headers.
    pub fn create_security_response(
        status: StatusCode,
        reason: &str,
        ctx: &GatewayRequestContext,
    ) -> Result<ResponseHeader, Box<Error>> {
        let mut resp = ResponseHeader::build(status, Some(4))?;
        resp.insert_header("Content-Type", "text/plain; charset=utf-8")?;
        resp.insert_header("Server", "R-NADS-Pro-Gateway/1.5")?;
        resp.insert_header("Connection", "close")?;

        if let Some(ref id) = ctx.client_identity {
            let _ = resp.insert_header(
                "X-RNADS-Client-Fingerprint",
                id.privacy_fingerprint.as_str(),
            );
        }
        if let Some(ref bot) = ctx.bot_classification {
            let _ = resp.insert_header("X-RNADS-Bot-Category", format!("{:?}", bot.category));
        }
        if let Some(ref dec) = ctx.decision {
            let _ = resp.insert_header("X-RNADS-Decision-ID", dec.decision_id.as_str());
            let _ = resp.insert_header("X-RNADS-Risk-Score", dec.risk_score.to_string());
        }
        let _ = resp.insert_header("X-RNADS-Block-Reason", reason);

        Ok(resp)
    }
}

#[async_trait]
impl ProxyHttp for StandaloneGatewayProxy {
    type CTX = GatewayRequestContext;

    fn new_ctx(&self) -> Self::CTX {
        GatewayRequestContext::new(
            "127.0.0.1".parse().unwrap(),
            "GET".to_string(),
            "/".to_string(),
        )
    }

    /// Fast-path filter executed immediately upon parsing request headers.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool, Box<Error>> {
        let req_header = session.req_header();

        // 1. Resolve client IP address
        let client_ip = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|inet| inet.ip())
            .unwrap_or_else(|| {
                req_header
                    .headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.split(',').next()?.trim().parse().ok())
                    .unwrap_or(IpAddr::from([127, 0, 0, 1]))
            });

        ctx.client_ip = client_ip;
        ctx.method = req_header.method.as_str().to_string();
        ctx.path = req_header.uri.path().to_string();

        // Collect request headers
        for (name, value) in &req_header.headers {
            if let Ok(v) = value.to_str() {
                ctx.headers.insert(name.as_str().to_string(), v.to_string());
            }
        }

        // 2. Check Local Memory Anomaly Blocklist
        let is_blocked = if let Some(expire) = self.blocklist.get(&client_ip) {
            if Instant::now() < *expire {
                true
            } else {
                drop(expire);
                self.blocklist.remove(&client_ip);
                false
            }
        } else {
            false
        };

        if is_blocked {
            let dec = SecurityDecision {
                decision_id: format!("ip_block_{}", client_ip),
                action: DecisionAction::Deny,
                reason: DecisionReason::BlocklistMatch,
                risk_score: 99,
                policy_version: 1,
                expires_at: None,
            };
            ctx.decision = Some(dec);
            let resp = Self::create_security_response(
                StatusCode::FORBIDDEN,
                "IP Temporarily Blocked by R-NADS Anomaly Protection",
                ctx,
            )?;
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(Bytes::from_static(b"403 Forbidden: Blocked")), true)
                .await?;
            return Ok(true); // Terminate request
        }

        // 3. Multi-Dimensional Rate Limiting
        let rate_status = self.rate_limiter.evaluate(client_ip, Some(&ctx.path));

        if let r_nads_ratelimit::RateLimitDecision::Limited {
            retry_after_ms,
            ref violated_limit,
        } = rate_status
        {
            let dec = SecurityDecision {
                decision_id: format!("ratelimit_{}", client_ip),
                action: DecisionAction::Deny,
                reason: DecisionReason::RateLimitExceeded,
                risk_score: 85,
                policy_version: 1,
                expires_at: None,
            };
            ctx.decision = Some(dec);
            let mut resp = Self::create_security_response(
                StatusCode::TOO_MANY_REQUESTS,
                "Rate Limit Exceeded",
                ctx,
            )?;
            let retry_secs = retry_after_ms.div_ceil(1000);
            let _ = resp.insert_header("Retry-After", retry_secs.to_string());
            let _ = resp.insert_header("X-RNADS-RateLimit-Violated", violated_limit.as_str());
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(
                    Some(Bytes::from_static(b"429 Too Many Requests: Rate Limited")),
                    true,
                )
                .await?;
            return Ok(true);
        }

        // 4. Construct SecurityRequest for Identity & WAF evaluation
        let sec_req = SecurityRequest::new(
            client_ip,
            &ctx.method,
            &ctx.path,
            ctx.headers.clone(),
            None,
            Self::MAX_BODY_INSPECTION_BYTES,
        );

        // 5. Identity Intelligence: Privacy Fingerprinting & Bot Classification
        let identity = self.fingerprint_engine.fingerprint(&sec_req);
        let bot_classification = self.bot_engine.classify(&identity, &sec_req);

        ctx.client_identity = Some(identity);

        if bot_classification.should_block || bot_classification.should_challenge {
            let dec = self.bot_engine.make_decision(&bot_classification, 1);
            let is_block = dec.action == DecisionAction::Deny;
            ctx.decision = Some(dec);
            ctx.bot_classification = Some(bot_classification);

            let status_code = if is_block {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::from_u16(428).unwrap_or(StatusCode::FORBIDDEN)
            };
            let resp = Self::create_security_response(status_code, "Bot Signature Detected", ctx)?;
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(
                    Some(Bytes::from_static(if is_block {
                        b"403 Forbidden: Malicious Bot Denied"
                    } else {
                        b"428 Precondition Required: Interactive Challenge Needed"
                    })),
                    true,
                )
                .await?;
            return Ok(true);
        }

        ctx.bot_classification = Some(bot_classification);

        // 6. Inspect HTTP URI, Query String, and Headers with WAF
        let waf_violations = self.waf_engine.inspect(&sec_req);
        if let Some(violation) = waf_violations.first() {
            let dec = SecurityDecision {
                decision_id: format!("waf_rule_{}", violation.pattern_name),
                action: DecisionAction::Deny,
                reason: DecisionReason::WafRuleViolation(violation.matched_sample.clone()),
                risk_score: 95,
                policy_version: 1,
                expires_at: None,
            };
            ctx.decision = Some(dec);
            let resp = Self::create_security_response(
                StatusCode::FORBIDDEN,
                "WAF Protocol / Rule Violation Detected in Headers/URI",
                ctx,
            )?;
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(
                    Some(Bytes::from_static(b"403 Forbidden: WAF Violation")),
                    true,
                )
                .await?;
            return Ok(true);
        }

        Ok(false) // Continue to body filter or upstream
    }

    /// Streams incoming request body chunks, accumulating up to MAX_BODY_INSPECTION_BYTES for inspection.
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        if let Some(chunk) = body {
            if ctx.body_buffer.len() < Self::MAX_BODY_INSPECTION_BYTES {
                let available = Self::MAX_BODY_INSPECTION_BYTES - ctx.body_buffer.len();
                let to_take = std::cmp::min(available, chunk.len());
                ctx.body_buffer.extend_from_slice(&chunk[..to_take]);
            }
        }

        // Run full payload inspection when stream finishes or buffer reaches inspection ceiling
        if (end_of_stream || ctx.body_buffer.len() >= Self::MAX_BODY_INSPECTION_BYTES)
            && !ctx.body_inspected
        {
            ctx.body_inspected = true;
            if !ctx.body_buffer.is_empty() {
                let sec_req = SecurityRequest::new(
                    ctx.client_ip,
                    &ctx.method,
                    &ctx.path,
                    ctx.headers.clone(),
                    Some(ctx.body_buffer.clone()),
                    Self::MAX_BODY_INSPECTION_BYTES,
                );

                let violations = self.waf_engine.inspect(&sec_req);
                if let Some(violation) = violations.first() {
                    let dec = SecurityDecision {
                        decision_id: format!("waf_body_{}", violation.pattern_name),
                        action: DecisionAction::Deny,
                        reason: DecisionReason::WafRuleViolation(violation.matched_sample.clone()),
                        risk_score: 98,
                        policy_version: 1,
                        expires_at: None,
                    };
                    ctx.decision = Some(dec);
                    let resp = Self::create_security_response(
                        StatusCode::FORBIDDEN,
                        "WAF Payload Violation Detected in Request Body",
                        ctx,
                    )?;
                    session.write_response_header(Box::new(resp), false).await?;
                    session
                        .write_response_body(
                            Some(Bytes::from_static(b"403 Forbidden: Malicious Payload")),
                            true,
                        )
                        .await?;
                    return Err(Error::create(
                        ErrorType::Custom("WafPayloadViolation"),
                        ErrorSource::Downstream,
                        None,
                        None,
                    ));
                }
            }
        }

        Ok(())
    }

    /// Selects upstream peer from configured round-robin load balancer.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<Error>> {
        let upstream = self
            .load_balancer
            .select(b"", 256)
            .ok_or_else(|| Error::new(ErrorType::InternalError))?;

        let peer = Box::new(HttpPeer::new(upstream, false, "".to_string()));
        Ok(peer)
    }

    /// Injects security and privacy headers on the response back to the client.
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        upstream_response.insert_header("Server", "R-NADS-Pro-Gateway/1.5")?;
        upstream_response
            .insert_header("X-Content-Type-Options", "nosniff")
            .ok();
        upstream_response
            .insert_header("X-Frame-Options", "DENY")
            .ok();

        if let Some(ref id) = ctx.client_identity {
            upstream_response
                .insert_header(
                    "X-RNADS-Client-Fingerprint",
                    id.privacy_fingerprint.as_str(),
                )
                .ok();
        }

        if let Some(ref bot) = ctx.bot_classification {
            upstream_response
                .insert_header("X-RNADS-Bot-Category", format!("{:?}", bot.category))
                .ok();
        }

        upstream_response
            .insert_header("X-RNADS-Detection-Status", "Allowed")
            .ok();

        // Record telemetry
        self.packet_counter.fetch_add(1, Ordering::Relaxed);
        let elapsed = ctx.start_time.elapsed().as_micros() as u64;
        self.latency_sum_us.fetch_add(elapsed, Ordering::Relaxed);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r_nads_bot_detection::ClientCategory;

    #[test]
    fn test_gateway_context_initialization() {
        let ctx = GatewayRequestContext::new(
            "192.0.2.1".parse().unwrap(),
            "POST".to_string(),
            "/api/login".to_string(),
        );

        assert_eq!(ctx.client_ip, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(ctx.method, "POST");
        assert_eq!(ctx.path, "/api/login");
        assert!(ctx.body_buffer.is_empty());
        assert!(!ctx.body_inspected);
    }

    #[test]
    fn test_security_response_header_construction() {
        let mut ctx = GatewayRequestContext::new(
            "192.0.2.1".parse().unwrap(),
            "GET".to_string(),
            "/".to_string(),
        );
        ctx.client_identity = Some(ClientIdentity {
            client_ip: "192.0.2.1".parse().unwrap(),
            user_agent: Some("TestAgent/1.0".to_string()),
            accept_language: None,
            accept_encoding: None,
            header_order_hash: "abcd1234efgh5678".to_string(),
            ja4_hint: None,
            privacy_fingerprint: "11223344556677889900aabbccddeeff".to_string(),
        });
        ctx.bot_classification = Some(BotClassification {
            category: ClientCategory::MaliciousScanner,
            confidence: 0.99,
            matched_signature: Some("scanner_pattern_sqlmap".to_string()),
            should_challenge: false,
            should_block: true,
        });

        let resp = StandaloneGatewayProxy::create_security_response(
            StatusCode::FORBIDDEN,
            "Scanner Detected",
            &ctx,
        )
        .unwrap();

        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers
                .get("X-RNADS-Client-Fingerprint")
                .unwrap()
                .to_str()
                .unwrap(),
            "11223344556677889900aabbccddeeff"
        );
        assert_eq!(
            resp.headers
                .get("X-RNADS-Bot-Category")
                .unwrap()
                .to_str()
                .unwrap(),
            "MaliciousScanner"
        );
    }
}
