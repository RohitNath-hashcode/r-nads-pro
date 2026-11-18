#![forbid(unsafe_code)]

//! Fleet security policy definition, serialization, and Ed25519 signature validation.
//!
//! Enforces monotonic sequence numbers to guarantee anti-rollback protection and
//! provides autonomous disk caching for disconnected-mode resilience.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Cryptographic signature invalid")]
    InvalidSignature,
    #[error("Corrupted signature bytes: {0}")]
    MalformedSignature(String),
    #[error("Corrupted public key bytes: {0}")]
    MalformedKey(String),
    #[error(
        "Policy rollback rejected: incoming sequence {incoming} <= current sequence {current}"
    )]
    RollbackDetected { incoming: u64, current: u64 },
    #[error("I/O error during policy cache operation: {0}")]
    Io(#[from] std::io::Error),
}

/// Core security policy containing multi-tenant rules, rate limits, and blocklists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityPolicyBundle {
    pub tenant_id: String,
    pub policy_version: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: Option<u64>,
    pub blocked_ips: HashSet<IpAddr>,
    pub rate_limits: PolicyRateLimits,
    pub waf_rules: PolicyWafRules,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyRateLimits {
    pub ip_burst: u32,
    pub ip_refill_per_sec: f64,
    pub subnet_requests_per_min: u32,
    pub route_burst: u32,
    pub route_refill_per_sec: f64,
}

impl Default for PolicyRateLimits {
    fn default() -> Self {
        Self {
            ip_burst: 100,
            ip_refill_per_sec: 20.0,
            subnet_requests_per_min: 1000,
            route_burst: 50,
            route_refill_per_sec: 10.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyWafRules {
    pub enabled: bool,
    pub block_mode: bool,
    pub max_body_bytes: usize,
    pub custom_block_patterns: Vec<String>,
}

impl Default for PolicyWafRules {
    fn default() -> Self {
        Self {
            enabled: true,
            block_mode: true,
            max_body_bytes: 128 * 1024,
            custom_block_patterns: Vec::new(),
        }
    }
}

/// Signed policy bundle distributed by the central control plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedPolicyEnvelope {
    pub policy: SecurityPolicyBundle,
    pub signer_public_key_hex: String,
    pub signature_hex: String,
}

impl SignedPolicyEnvelope {
    /// Serializes and cryptographically signs a policy bundle with an Ed25519 signing key.
    pub fn sign(
        policy: SecurityPolicyBundle,
        signing_key: &SigningKey,
    ) -> Result<Self, PolicyError> {
        let serialized = serde_json::to_vec(&policy)?;
        let signature = signing_key.sign(&serialized);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            policy,
            signer_public_key_hex: hex::encode(verifying_key.to_bytes()),
            signature_hex: hex::encode(signature.to_bytes()),
        })
    }

    /// Verifies that the envelope payload matches the Ed25519 signature.
    pub fn verify(&self) -> Result<(), PolicyError> {
        let key_bytes = hex::decode(&self.signer_public_key_hex)
            .map_err(|e| PolicyError::MalformedKey(e.to_string()))?;
        if key_bytes.len() != 32 {
            return Err(PolicyError::MalformedKey(
                "Key must be 32 bytes".to_string(),
            ));
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        let verifying_key = VerifyingKey::from_bytes(&key_arr)
            .map_err(|e| PolicyError::MalformedKey(e.to_string()))?;

        let sig_bytes = hex::decode(&self.signature_hex)
            .map_err(|e| PolicyError::MalformedSignature(e.to_string()))?;
        if sig_bytes.len() != 64 {
            return Err(PolicyError::MalformedSignature(
                "Signature must be 64 bytes".to_string(),
            ));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        let serialized = serde_json::to_vec(&self.policy)?;
        verifying_key
            .verify(&serialized, &signature)
            .map_err(|_| PolicyError::InvalidSignature)?;

        Ok(())
    }

    /// Saves the signed policy envelope to disk atomically.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), PolicyError> {
        let serialized = serde_json::to_string_pretty(self)?;
        let temp_path = format!("{}.tmp", path.as_ref().display());
        std::fs::write(&temp_path, serialized)?;
        std::fs::rename(temp_path, path)?;
        Ok(())
    }

    /// Loads and verifies a signed policy envelope from disk.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, PolicyError> {
        let content = std::fs::read_to_string(path)?;
        let envelope: Self = serde_json::from_str(&content)?;
        envelope.verify()?;
        Ok(envelope)
    }
}

/// Agent-side policy manager enforcing anti-rollback monotonically.
pub struct FleetPolicyStore {
    current_policy: Option<SecurityPolicyBundle>,
    trusted_public_keys: HashSet<String>,
}

impl FleetPolicyStore {
    pub fn new(trusted_keys: &[&str]) -> Self {
        let mut trusted_public_keys = HashSet::new();
        for key in trusted_keys {
            trusted_public_keys.insert(key.to_lowercase());
        }
        Self {
            current_policy: None,
            trusted_public_keys,
        }
    }

    pub fn current_policy(&self) -> Option<&SecurityPolicyBundle> {
        self.current_policy.as_ref()
    }

    pub fn current_version(&self) -> u64 {
        self.current_policy
            .as_ref()
            .map(|p| p.policy_version)
            .unwrap_or(0)
    }

    /// Applies an incoming signed policy envelope with anti-rollback validation.
    pub fn apply_envelope(&mut self, envelope: SignedPolicyEnvelope) -> Result<(), PolicyError> {
        // 1. Verify cryptographic validity
        envelope.verify()?;

        // 2. Validate signer authenticity against trusted controller keys
        if !self.trusted_public_keys.is_empty()
            && !self
                .trusted_public_keys
                .contains(&envelope.signer_public_key_hex.to_lowercase())
        {
            return Err(PolicyError::InvalidSignature);
        }

        // 3. Enforce monotonic anti-rollback sequence check
        let incoming_version = envelope.policy.policy_version;
        let current_version = self.current_version();

        if incoming_version <= current_version {
            return Err(PolicyError::RollbackDetected {
                incoming: incoming_version,
                current: current_version,
            });
        }

        self.current_policy = Some(envelope.policy);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_policy_signing_and_verification() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let policy = SecurityPolicyBundle {
            tenant_id: "tenant_corp_global".to_string(),
            policy_version: 1,
            created_at_unix: 1700000000,
            expires_at_unix: None,
            blocked_ips: ["198.51.100.4".parse().unwrap()].into(),
            rate_limits: PolicyRateLimits::default(),
            waf_rules: PolicyWafRules::default(),
        };

        let envelope = SignedPolicyEnvelope::sign(policy.clone(), &signing_key).unwrap();
        assert!(envelope.verify().is_ok());

        // Tampering test: alter tenant ID
        let mut tampered = envelope.clone();
        tampered.policy.tenant_id = "tenant_attacker".to_string();
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn test_anti_rollback_protection() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let mut store = FleetPolicyStore::new(&[&pub_hex]);

        let policy_v1 = SecurityPolicyBundle {
            tenant_id: "corp".to_string(),
            policy_version: 1,
            created_at_unix: 1700000000,
            expires_at_unix: None,
            blocked_ips: HashSet::new(),
            rate_limits: PolicyRateLimits::default(),
            waf_rules: PolicyWafRules::default(),
        };

        let policy_v2 = SecurityPolicyBundle {
            tenant_id: "corp".to_string(),
            policy_version: 2,
            created_at_unix: 1700000010,
            expires_at_unix: None,
            blocked_ips: HashSet::new(),
            rate_limits: PolicyRateLimits::default(),
            waf_rules: PolicyWafRules::default(),
        };

        let env_v1 = SignedPolicyEnvelope::sign(policy_v1, &signing_key).unwrap();
        let env_v2 = SignedPolicyEnvelope::sign(policy_v2, &signing_key).unwrap();

        // Apply v1
        assert!(store.apply_envelope(env_v1.clone()).is_ok());
        assert_eq!(store.current_version(), 1);

        // Apply v2
        assert!(store.apply_envelope(env_v2).is_ok());
        assert_eq!(store.current_version(), 2);

        // Attempt rollback to v1 -> MUST FAIL
        let rollback_res = store.apply_envelope(env_v1);
        assert!(matches!(
            rollback_res,
            Err(PolicyError::RollbackDetected {
                incoming: 1,
                current: 2
            })
        ));
    }
}
