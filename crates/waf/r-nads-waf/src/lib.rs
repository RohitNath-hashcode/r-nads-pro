#![forbid(unsafe_code)]

use aho_corasick::AhoCorasick;
use r_nads_decision::{
    DecisionAction, DecisionReason, EvidenceSource, SecurityDecision, SecurityEvidence, Severity,
    ThreatCategory,
};
use r_nads_http::SecurityRequest;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Categories of web application attacks detected by the native WAF engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WafAttackType {
    SqlInjection,
    CrossSiteScripting,
    CommandInjection,
    PathTraversal,
    SensitiveFileAccess,
}

impl WafAttackType {
    pub fn as_str(&self) -> &'static str {
        match self {
            WafAttackType::SqlInjection => "SQL_INJECTION",
            WafAttackType::CrossSiteScripting => "CROSS_SITE_SCRIPTING",
            WafAttackType::CommandInjection => "COMMAND_INJECTION",
            WafAttackType::PathTraversal => "PATH_TRAVERSAL",
            WafAttackType::SensitiveFileAccess => "SENSITIVE_FILE_ACCESS",
        }
    }
}

/// A specific matched violation found during request inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafViolation {
    pub attack_type: WafAttackType,
    pub pattern_name: String,
    pub matched_location: String,
    pub matched_sample: String,
    pub confidence: f32,
    pub severity: Severity,
}

/// Configuration options for the native WAF engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    pub enabled: bool,
    pub block_mode: bool, // true = Deny/Block, false = Monitor/Audit only
    pub max_inspected_body_bytes: usize,
    pub sqli_enabled: bool,
    pub xss_enabled: bool,
    pub cmdi_enabled: bool,
    pub lfi_enabled: bool,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_mode: true,
            max_inspected_body_bytes: 131_072, // 128 KB
            sqli_enabled: true,
            xss_enabled: true,
            cmdi_enabled: true,
            lfi_enabled: true,
        }
    }
}

/// Native Rust high-performance WAF inspection engine.
pub struct WafEngine {
    config: WafConfig,
    fast_sqli_matcher: AhoCorasick,
    fast_xss_matcher: AhoCorasick,
    fast_lfi_matcher: AhoCorasick,
    regex_sqli: Vec<(String, Regex)>,
    regex_xss: Vec<(String, Regex)>,
    regex_cmdi: Vec<(String, Regex)>,
}

impl WafEngine {
    /// Initializes the WAF engine with compiled Aho-Corasick matchers and Regex sets.
    pub fn new(config: WafConfig) -> Self {
        // 1. Fast substring filters (Aho-Corasick)
        let sqli_patterns = &[
            "' or '",
            "' or 1=1",
            "\" or \"",
            "\" or 1=1",
            "union select",
            "union all select",
            "sleep(",
            "benchmark(",
            "information_schema",
            "--",
            "/*",
        ];
        let fast_sqli_matcher = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(sqli_patterns)
            .expect("Failed to build SQLi AhoCorasick");

        let xss_patterns = &[
            "<script",
            "</script>",
            "javascript:",
            "vbscript:",
            "onload=",
            "onerror=",
            "onclick=",
            "onmouseover=",
            "<img src=",
            "<iframe",
        ];
        let fast_xss_matcher = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(xss_patterns)
            .expect("Failed to build XSS AhoCorasick");

        let lfi_patterns = &[
            "../",
            "..\\",
            "/etc/passwd",
            "/etc/shadow",
            "c:\\boot.ini",
            "c:\\windows\\system32",
            "/proc/self/environ",
        ];
        let fast_lfi_matcher = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(lfi_patterns)
            .expect("Failed to build LFI AhoCorasick");

        // 2. Deep heuristics Regex patterns
        let regex_sqli = vec![
            (
                "sqli_tautology".to_string(),
                Regex::new(r"(?i)(\bor\b|\band\b)\s+[\w'\x22]+\s*=\s*[\w'\x22]+").unwrap(),
            ),
            (
                "sqli_union".to_string(),
                Regex::new(r"(?i)\bUNION\b\s+(ALL\s+)?\bSELECT\b").unwrap(),
            ),
            (
                "sqli_blind".to_string(),
                Regex::new(r"(?i)\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY)\b").unwrap(),
            ),
        ];

        let regex_xss = vec![
            (
                "xss_script_tag".to_string(),
                Regex::new(r"(?i)<\s*script[^>]*>").unwrap(),
            ),
            (
                "xss_event_handler".to_string(),
                Regex::new(r"(?i)\bon\w+\s*=\s*[\x22']?[^>]+[\x22']?").unwrap(),
            ),
            (
                "xss_js_protocol".to_string(),
                Regex::new(r"(?i)javascript:\s*[^\s]+").unwrap(),
            ),
        ];

        let regex_cmdi = vec![
            (
                "cmdi_chained_commands".to_string(),
                Regex::new(r"([;|&`]\s*(cat|ls|id|whoami|uname|nc|bash|sh|cmd|powershell)\b)|(\$\([^)]+\))")
                    .unwrap(),
            ),
            (
                "cmdi_pipe_redirection".to_string(),
                Regex::new(r"(\|\s*/bin/)|(>\s*/dev/tcp/)").unwrap(),
            ),
        ];

        Self {
            config,
            fast_sqli_matcher,
            fast_xss_matcher,
            fast_lfi_matcher,
            regex_sqli,
            regex_xss,
            regex_cmdi,
        }
    }

    /// Evaluates an incoming canonical SecurityRequest, searching for injection and traversal signatures.
    pub fn inspect(&self, req: &SecurityRequest) -> Vec<WafViolation> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut violations = Vec::new();

        // 1. Inspect URI Path
        self.inspect_target("URI_PATH", &req.canonical_path, &mut violations);

        // 2. Inspect Query Parameters
        for (key, val) in &req.query_params {
            let loc_key = format!("QUERY_KEY[{}]", key);
            let loc_val = format!("QUERY_VAL[{}]", key);
            self.inspect_target(&loc_key, key, &mut violations);
            self.inspect_target(&loc_val, val, &mut violations);
        }

        // 3. Inspect Sensitive Headers
        for (name, val) in &req.headers {
            let n_lower = name.to_ascii_lowercase();
            // Inspect User-Agent, Cookie, Referer, and Authorization
            if n_lower == "user-agent"
                || n_lower == "cookie"
                || n_lower == "referer"
                || n_lower == "x-forwarded-for"
            {
                let loc = format!("HEADER[{}]", name);
                self.inspect_target(&loc, val, &mut violations);
            }
        }

        // 4. Inspect Request Body (if available, using lossy UTF-8 to prevent binary evasion)
        if let Some(ref body) = req.body_bytes {
            let body_str = String::from_utf8_lossy(body);
            self.inspect_target("REQUEST_BODY", &body_str, &mut violations);
        }

        violations
    }

    /// Converts WAF inspection results into an actionable SecurityDecision contract.
    pub fn make_decision(
        &self,
        violations: &[WafViolation],
        policy_version: u64,
    ) -> SecurityDecision {
        if violations.is_empty() {
            return SecurityDecision::allow(policy_version);
        }

        let top_violation = &violations[0];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if self.config.block_mode {
            SecurityDecision {
                decision_id: format!("waf_deny_{}", top_violation.pattern_name),
                action: DecisionAction::Deny,
                reason: DecisionReason::WafRuleViolation(format!(
                    "{}: {} at {}",
                    top_violation.attack_type.as_str(),
                    top_violation.pattern_name,
                    top_violation.matched_location
                )),
                risk_score: 95,
                policy_version,
                expires_at: Some(now + 300),
            }
        } else {
            SecurityDecision {
                decision_id: format!("waf_mon_{}", top_violation.pattern_name),
                action: DecisionAction::Monitor,
                reason: DecisionReason::WafRuleViolation(format!(
                    "{}: {} at {}",
                    top_violation.attack_type.as_str(),
                    top_violation.pattern_name,
                    top_violation.matched_location
                )),
                risk_score: 80,
                policy_version,
                expires_at: Some(now + 300),
            }
        }
    }

    /// Generates normalized security evidence events for alerting & forensics.
    pub fn generate_evidence(
        &self,
        req: &SecurityRequest,
        violation: &WafViolation,
    ) -> SecurityEvidence {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        SecurityEvidence {
            event_id: format!("ev_waf_{}", violation.pattern_name),
            tenant_id: "default".to_string(),
            application_id: "edge_gateway".to_string(),
            client_ip: req.client_ip,
            source: EvidenceSource::WafSignature,
            category: ThreatCategory::WafViolation,
            confidence: violation.confidence,
            severity: violation.severity,
            observed_at: now,
            expires_at: Some(now + 3600),
            model_version: Some("r-nads-waf-1.3".to_string()),
            rule_id: Some(violation.pattern_name.clone()),
        }
    }

    fn inspect_target(&self, location: &str, text: &str, violations: &mut Vec<WafViolation>) {
        // Fast Path 1: SQL Injection
        if self.config.sqli_enabled {
            if self.fast_sqli_matcher.find(text).is_some() {
                violations.push(WafViolation {
                    attack_type: WafAttackType::SqlInjection,
                    pattern_name: "fast_sqli_keyword".to_string(),
                    matched_location: location.to_string(),
                    matched_sample: text.chars().take(60).collect(),
                    confidence: 0.85,
                    severity: Severity::High,
                });
            } else {
                for (name, re) in &self.regex_sqli {
                    if re.is_match(text) {
                        violations.push(WafViolation {
                            attack_type: WafAttackType::SqlInjection,
                            pattern_name: name.clone(),
                            matched_location: location.to_string(),
                            matched_sample: text.chars().take(60).collect(),
                            confidence: 0.90,
                            severity: Severity::High,
                        });
                        break;
                    }
                }
            }
        }

        // Fast Path 2: Cross-Site Scripting (XSS)
        if self.config.xss_enabled {
            if self.fast_xss_matcher.find(text).is_some() {
                violations.push(WafViolation {
                    attack_type: WafAttackType::CrossSiteScripting,
                    pattern_name: "fast_xss_tag".to_string(),
                    matched_location: location.to_string(),
                    matched_sample: text.chars().take(60).collect(),
                    confidence: 0.85,
                    severity: Severity::High,
                });
            } else {
                for (name, re) in &self.regex_xss {
                    if re.is_match(text) {
                        violations.push(WafViolation {
                            attack_type: WafAttackType::CrossSiteScripting,
                            pattern_name: name.clone(),
                            matched_location: location.to_string(),
                            matched_sample: text.chars().take(60).collect(),
                            confidence: 0.90,
                            severity: Severity::High,
                        });
                        break;
                    }
                }
            }
        }

        // Fast Path 3: Local File Inclusion & Sensitive Path Traversal
        if self.config.lfi_enabled && self.fast_lfi_matcher.find(text).is_some() {
            violations.push(WafViolation {
                attack_type: WafAttackType::PathTraversal,
                pattern_name: "lfi_traversal_signature".to_string(),
                matched_location: location.to_string(),
                matched_sample: text.chars().take(60).collect(),
                confidence: 0.95,
                severity: Severity::Critical,
            });
        }

        // Fast Path 4: OS Command Injection
        if self.config.cmdi_enabled {
            for (name, re) in &self.regex_cmdi {
                if re.is_match(text) {
                    violations.push(WafViolation {
                        attack_type: WafAttackType::CommandInjection,
                        pattern_name: name.clone(),
                        matched_location: location.to_string(),
                        matched_sample: text.chars().take(60).collect(),
                        confidence: 0.95,
                        severity: Severity::Critical,
                    });
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r_nads_http::SecurityRequest;
    use std::collections::HashMap;

    #[test]
    fn test_sqli_detection_in_query() {
        let waf = WafEngine::new(WafConfig::default());
        let ip = "1.2.3.4".parse().unwrap();
        let req = SecurityRequest::new(
            ip,
            "GET",
            "/api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20admin--",
            HashMap::new(),
            None,
            1024,
        );

        let violations = waf.inspect(&req);
        assert!(!violations.is_empty(), "SQL injection must be detected");
        assert_eq!(violations[0].attack_type, WafAttackType::SqlInjection);

        let decision = waf.make_decision(&violations, 1);
        assert_eq!(decision.action, DecisionAction::Deny);
    }

    #[test]
    fn test_xss_detection_in_header() {
        let waf = WafEngine::new(WafConfig::default());
        let ip = "1.2.3.4".parse().unwrap();
        let mut headers = HashMap::new();
        headers.insert(
            "User-Agent".to_string(),
            "<script>alert(document.cookie)</script>".to_string(),
        );

        let req = SecurityRequest::new(ip, "GET", "/index.html", headers, None, 1024);

        let violations = waf.inspect(&req);
        assert!(!violations.is_empty(), "XSS in header must be detected");
        assert_eq!(violations[0].attack_type, WafAttackType::CrossSiteScripting);
    }

    #[test]
    fn test_cmdi_detection_in_body() {
        let waf = WafEngine::new(WafConfig::default());
        let ip = "1.2.3.4".parse().unwrap();
        let body = b"ip=127.0.0.1; whoami".to_vec();

        let req = SecurityRequest::new(ip, "POST", "/ping", HashMap::new(), Some(body), 1024);

        let violations = waf.inspect(&req);
        assert!(
            !violations.is_empty(),
            "Command injection in body must be detected"
        );
        assert_eq!(violations[0].attack_type, WafAttackType::CommandInjection);
    }

    #[test]
    fn test_path_traversal_detection() {
        let waf = WafEngine::new(WafConfig::default());
        let ip = "1.2.3.4".parse().unwrap();
        let req = SecurityRequest::new(
            ip,
            "GET",
            "/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            HashMap::new(),
            None,
            1024,
        );

        let violations = waf.inspect(&req);
        assert!(!violations.is_empty(), "Path traversal must be detected");
        assert_eq!(violations[0].attack_type, WafAttackType::PathTraversal);
    }
}
