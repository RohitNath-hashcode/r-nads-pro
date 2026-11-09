use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Source subsystem that generated the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceSource {
    NetworkAnomaly,
    RateLimiter,
    WafSignature,
    BehavioralDrift,
    ManualBlocklist,
}

/// Category of the threat detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatCategory {
    VolumetricDdos,
    PortScan,
    HandshakeAbuse,
    MalformedPacket,
    WafViolation,
    RateLimitExceeded,
    BotAnomaly,
}

/// Severity rating of the threat evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Normalized evidence emitted by any detection subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvidence {
    pub event_id: String,
    pub tenant_id: String,
    pub application_id: String,
    pub client_ip: IpAddr,
    pub source: EvidenceSource,
    pub category: ThreatCategory,
    pub confidence: f32,
    pub severity: Severity,
    pub observed_at: i64,
    pub expires_at: Option<i64>,
    pub model_version: Option<String>,
    pub rule_id: Option<String>,
}

/// Action to enforce on a connection or request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionAction {
    Allow,
    Monitor,
    Challenge,
    Throttle,
    Deny,
    Quarantine,
}

impl std::fmt::Display for DecisionAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "Allow"),
            Self::Monitor => write!(f, "Monitor"),
            Self::Challenge => write!(f, "Challenge"),
            Self::Throttle => write!(f, "Throttle"),
            Self::Deny => write!(f, "Deny"),
            Self::Quarantine => write!(f, "Quarantine"),
        }
    }
}

/// Explicit rationale for the decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionReason {
    NoPolicyMatch,
    BlocklistMatch,
    AnomalousDistanceSq(String),
    RateLimitExceeded,
    WafRuleViolation(String),
    BehavioralDrift,
    ManualAdminOverride,
}

/// Formal decision produced by the policy and decision engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDecision {
    pub decision_id: String,
    pub action: DecisionAction,
    pub reason: DecisionReason,
    pub risk_score: u32,
    pub policy_version: u64,
    pub expires_at: Option<i64>,
}

impl SecurityDecision {
    /// Creates an immediate 'Allow' decision.
    pub fn allow(policy_version: u64) -> Self {
        Self {
            decision_id: format!("dec_{}", uuid_fast()),
            action: DecisionAction::Allow,
            reason: DecisionReason::NoPolicyMatch,
            risk_score: 0,
            policy_version,
            expires_at: None,
        }
    }

    /// Creates an anomaly-triggered decision based on the active mitigation mode.
    pub fn from_anomaly(
        is_blocked: bool,
        mitigation_mode: &str,
        score: f64,
        ttl_secs: u64,
        policy_version: u64,
    ) -> Self {
        if !is_blocked {
            return Self::allow(policy_version);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if mitigation_mode.eq_ignore_ascii_case("mitigate") {
            Self {
                decision_id: format!("dec_{}", uuid_fast()),
                action: DecisionAction::Deny,
                reason: DecisionReason::AnomalousDistanceSq(format!("{:.4}", score)),
                risk_score: 95,
                policy_version,
                expires_at: Some(now + ttl_secs as i64),
            }
        } else {
            Self {
                decision_id: format!("dec_{}", uuid_fast()),
                action: DecisionAction::Monitor,
                reason: DecisionReason::AnomalousDistanceSq(format!("{:.4}", score)),
                risk_score: 95,
                policy_version,
                expires_at: Some(now + ttl_secs as i64),
            }
        }
    }
}

/// Fast pseudo-random identifier generator for zero-overhead decision tracing.
fn uuid_fast() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    now ^ COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Provider health status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHealth {
    pub is_healthy: bool,
    pub message: String,
}

/// Error type for mitigation provider implementations.
#[derive(Debug, thiserror::Error)]
pub enum MitigationError {
    #[error("Failed to apply firewall rule: {0}")]
    FirewallError(String),
    #[error("Provider timeout")]
    Timeout,
    #[error("Unknown error: {0}")]
    Other(String),
}

/// Generic mitigation action to apply at the network or edge layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationAction {
    pub action_id: String,
    pub target_ip: IpAddr,
    pub duration_secs: u64,
    pub reason: String,
}

/// Result of applying a mitigation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationResult {
    pub success: bool,
    pub provider_rule_id: String,
}

/// Abstract provider interface for OS firewall (nftables/iptables) or CDN upstream mitigation.
pub trait MitigationProvider: Send + Sync {
    fn apply(&self, action: &MitigationAction) -> Result<MitigationResult, MitigationError>;
    fn remove(&self, action_id: &str) -> Result<(), MitigationError>;
    fn health_check(&self) -> Result<ProviderHealth, MitigationError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_creation() {
        let allow_dec = SecurityDecision::allow(1);
        assert_eq!(allow_dec.action, DecisionAction::Allow);
        assert_eq!(allow_dec.risk_score, 0);

        let monitor_dec = SecurityDecision::from_anomaly(true, "monitor", 1.45, 30, 1);
        assert_eq!(monitor_dec.action, DecisionAction::Monitor);
        assert_eq!(monitor_dec.risk_score, 95);

        let mitigate_dec = SecurityDecision::from_anomaly(true, "mitigate", 1.45, 30, 1);
        assert_eq!(mitigate_dec.action, DecisionAction::Deny);
    }
}

