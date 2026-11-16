#![forbid(unsafe_code)]

use aho_corasick::AhoCorasick;
use r_nads_decision::{DecisionAction, DecisionReason, SecurityDecision};
use r_nads_fingerprint::ClientIdentity;
use r_nads_http::SecurityRequest;
use serde::{Deserialize, Serialize};

/// High-level client classification categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientCategory {
    VerifiedBot,       // Googlebot, Bingbot, etc.
    HeadlessBrowser,   // Puppeteer, Playwright, Selenium, PhantomJS
    AutomatedTool,     // curl, python-requests, Go-http-client, Postman
    MaliciousScanner,  // sqlmap, nikto, masscan, nmap
    LegitimateBrowser, // Standard human interactive browser
    Unknown,
}

/// Detailed classification decision for incoming request identities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotClassification {
    pub category: ClientCategory,
    pub confidence: f32,
    pub matched_signature: Option<String>,
    pub should_challenge: bool,
    pub should_block: bool,
}

/// Fast behavioral and signature-based bot detection engine.
pub struct BotDetectionEngine {
    verified_bot_matcher: AhoCorasick,
    headless_matcher: AhoCorasick,
    automated_tool_matcher: AhoCorasick,
    malicious_scanner_matcher: AhoCorasick,
}

impl Default for BotDetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BotDetectionEngine {
    pub fn new() -> Self {
        let verified_bots = &[
            "googlebot",
            "bingbot",
            "duckduckbot",
            "yandexbot",
            "baiduspider",
        ];
        let headless_signatures = &[
            "headlesschrome",
            "phantomjs",
            "selenium",
            "webdriver",
            "puppeteer",
            "playwright",
        ];
        let automated_tools = &[
            "curl/",
            "python-requests",
            "go-http-client",
            "postmanruntime",
            "wget/",
            "httpclient",
            "aiohttp",
        ];
        let malicious_scanners = &[
            "sqlmap",
            "nikto",
            "masscan",
            "nmap",
            "zgrab",
            "dirbuster",
            "gobuster",
            "wpscan",
        ];

        Self {
            verified_bot_matcher: AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(verified_bots)
                .unwrap(),
            headless_matcher: AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(headless_signatures)
                .unwrap(),
            automated_tool_matcher: AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(automated_tools)
                .unwrap(),
            malicious_scanner_matcher: AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(malicious_scanners)
                .unwrap(),
        }
    }

    /// Evaluates the client identity against behavioral and user-agent heuristics.
    pub fn classify(&self, identity: &ClientIdentity, req: &SecurityRequest) -> BotClassification {
        let ua_str = identity.user_agent.as_deref().unwrap_or("");

        // 1. Check Malicious Scanners (Highest Priority Block)
        if let Some(m) = self.malicious_scanner_matcher.find(ua_str) {
            return BotClassification {
                category: ClientCategory::MaliciousScanner,
                confidence: 0.99,
                matched_signature: Some(format!("scanner_pattern_{:?}", m.pattern())),
                should_challenge: false,
                should_block: true,
            };
        }

        // 2. Check Headless Browsers
        if let Some(m) = self.headless_matcher.find(ua_str) {
            return BotClassification {
                category: ClientCategory::HeadlessBrowser,
                confidence: 0.95,
                matched_signature: Some(format!("headless_pattern_{:?}", m.pattern())),
                should_challenge: true,
                should_block: false,
            };
        }

        // 3. Check Automated HTTP Libraries (curl, requests, etc.)
        if let Some(m) = self.automated_tool_matcher.find(ua_str) {
            return BotClassification {
                category: ClientCategory::AutomatedTool,
                confidence: 0.90,
                matched_signature: Some(format!("tool_pattern_{:?}", m.pattern())),
                should_challenge: false,
                should_block: false, // By default allowed unless route requires interactive browser
            };
        }

        // 4. Check Search Engine Crawlers
        if let Some(m) = self.verified_bot_matcher.find(ua_str) {
            return BotClassification {
                category: ClientCategory::VerifiedBot,
                confidence: 0.85,
                matched_signature: Some(format!("crawler_pattern_{:?}", m.pattern())),
                should_challenge: false,
                should_block: false,
            };
        }

        // 5. Behavioral Browser Checks: Missing standard browser headers
        if ua_str.starts_with("Mozilla/") {
            // A legitimate browser typically sends Accept-Language and Accept-Encoding
            if identity.accept_language.is_none() && req.query_params.is_empty() {
                return BotClassification {
                    category: ClientCategory::HeadlessBrowser,
                    confidence: 0.75,
                    matched_signature: Some("anomalous_browser_missing_headers".to_string()),
                    should_challenge: true,
                    should_block: false,
                };
            }

            return BotClassification {
                category: ClientCategory::LegitimateBrowser,
                confidence: 0.95,
                matched_signature: None,
                should_challenge: false,
                should_block: false,
            };
        }

        BotClassification {
            category: ClientCategory::Unknown,
            confidence: 0.50,
            matched_signature: None,
            should_challenge: false,
            should_block: false,
        }
    }

    /// Converts bot classification into a SecurityDecision.
    pub fn make_decision(
        &self,
        classification: &BotClassification,
        policy_version: u64,
    ) -> SecurityDecision {
        if classification.should_block {
            SecurityDecision {
                decision_id: format!("bot_block_{:?}", classification.category),
                action: DecisionAction::Deny,
                reason: DecisionReason::WafRuleViolation(format!(
                    "Automated bot signature detected: {:?}",
                    classification.category
                )),
                risk_score: 95,
                policy_version,
                expires_at: None,
            }
        } else if classification.should_challenge {
            SecurityDecision {
                decision_id: format!("bot_chal_{:?}", classification.category),
                action: DecisionAction::Challenge,
                reason: DecisionReason::WafRuleViolation(format!(
                    "Headless browser detected, challenge required: {:?}",
                    classification.category
                )),
                risk_score: 70,
                policy_version,
                expires_at: None,
            }
        } else {
            SecurityDecision::allow(policy_version)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r_nads_fingerprint::FingerprintEngine;
    use std::collections::HashMap;

    #[test]
    fn test_scanner_detection_sqlmap() {
        let engine = BotDetectionEngine::new();
        let fp_engine = FingerprintEngine::with_default_key();
        let ip = "1.2.3.4".parse().unwrap();

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "sqlmap/1.6#stable".to_string());
        let req = SecurityRequest::new(ip, "GET", "/test", headers, None, 1024);

        let id = fp_engine.fingerprint(&req);
        let classification = engine.classify(&id, &req);

        assert_eq!(classification.category, ClientCategory::MaliciousScanner);
        assert!(classification.should_block);

        let dec = engine.make_decision(&classification, 1);
        assert_eq!(dec.action, DecisionAction::Deny);
    }

    #[test]
    fn test_headless_chrome_detection() {
        let engine = BotDetectionEngine::new();
        let fp_engine = FingerprintEngine::with_default_key();
        let ip = "1.2.3.4".parse().unwrap();

        let mut headers = HashMap::new();
        headers.insert(
            "User-Agent".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/108.0".to_string(),
        );
        let req = SecurityRequest::new(ip, "GET", "/test", headers, None, 1024);

        let id = fp_engine.fingerprint(&req);
        let classification = engine.classify(&id, &req);

        assert_eq!(classification.category, ClientCategory::HeadlessBrowser);
        assert!(classification.should_challenge);

        let dec = engine.make_decision(&classification, 1);
        assert_eq!(dec.action, DecisionAction::Challenge);
    }

    #[test]
    fn test_legitimate_browser() {
        let engine = BotDetectionEngine::new();
        let fp_engine = FingerprintEngine::with_default_key();
        let ip = "1.2.3.4".parse().unwrap();

        let mut headers = HashMap::new();
        headers.insert(
            "User-Agent".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0".to_string(),
        );
        headers.insert("Accept-Language".to_string(), "en-US,en;q=0.9".to_string());
        let req = SecurityRequest::new(ip, "GET", "/test", headers, None, 1024);

        let id = fp_engine.fingerprint(&req);
        let classification = engine.classify(&id, &req);

        assert_eq!(classification.category, ClientCategory::LegitimateBrowser);
        assert!(!classification.should_block);
        assert!(!classification.should_challenge);
    }
}
