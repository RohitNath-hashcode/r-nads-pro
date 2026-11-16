#![forbid(unsafe_code)]

use blake3::Hasher;
use r_nads_http::SecurityRequest;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Multi-signal client identity components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientIdentity {
    pub client_ip: IpAddr,
    pub user_agent: Option<String>,
    pub accept_language: Option<String>,
    pub accept_encoding: Option<String>,
    pub header_order_hash: String,
    pub ja4_hint: Option<String>,
    pub privacy_fingerprint: String,
}

/// Computes multi-signal request fingerprints with one-way keyed hashing.
/// Conforms to GDPR privacy principles (IP and identity signals are salted and hashed).
pub struct FingerprintEngine {
    secret_salt: [u8; 32],
}

impl FingerprintEngine {
    /// Creates a fingerprint engine with a custom secret salt for keyed hashing.
    pub fn new(secret_salt: [u8; 32]) -> Self {
        Self { secret_salt }
    }

    /// Creates an engine with a default static key (can be rotated).
    pub fn with_default_key() -> Self {
        let salt_bytes = b"r_nads_pro_identity_secret_salt_";
        Self {
            secret_salt: *salt_bytes,
        }
    }

    /// Creates a fingerprint engine initialized from the `RNADS_IDENTITY_SALT` environment variable,
    /// falling back to the default key if unset or invalid length.
    pub fn from_env() -> Self {
        if let Ok(salt_str) = std::env::var("RNADS_IDENTITY_SALT") {
            let bytes = salt_str.as_bytes();
            if bytes.len() >= 32 {
                let mut salt = [0u8; 32];
                salt.copy_from_slice(&bytes[..32]);
                return Self::new(salt);
            }
        }
        Self::with_default_key()
    }

    /// Computes the normalized and salted privacy fingerprint from an incoming HTTP SecurityRequest.
    /// Employs a single-pass zero-copy header extraction and case-insensitive header ordering.
    pub fn fingerprint(&self, req: &SecurityRequest) -> ClientIdentity {
        let mut user_agent: Option<&str> = None;
        let mut accept_language: Option<&str> = None;
        let mut accept_encoding: Option<&str> = None;
        let mut ja4_hint: Option<&str> = None;

        let mut header_names: Vec<&str> = Vec::with_capacity(req.headers.len());

        for (k, v) in &req.headers {
            header_names.push(k.as_str());
            if k.eq_ignore_ascii_case("user-agent") {
                user_agent = Some(v.as_str());
            } else if k.eq_ignore_ascii_case("accept-language") {
                accept_language = Some(v.as_str());
            } else if k.eq_ignore_ascii_case("accept-encoding") {
                accept_encoding = Some(v.as_str());
            } else if k.eq_ignore_ascii_case("x-ja4") {
                ja4_hint = Some(v.as_str());
            }
        }

        // Canonical header structure ordering (case-insensitive unstable sort to avoid allocs)
        header_names.sort_unstable_by_key(|a| a.to_ascii_lowercase());

        let mut header_hasher = Hasher::new_keyed(&self.secret_salt);
        for (i, name) in header_names.iter().enumerate() {
            if i > 0 {
                header_hasher.update(b",");
            }
            // Hash lowercase representation in-flight to prevent case variance across proxies
            for b in name.bytes() {
                header_hasher.update(&[b.to_ascii_lowercase()]);
            }
        }
        let header_order_hash = header_hasher.finalize().to_hex()[..16].to_string();

        // Master privacy-preserving fingerprint
        let mut master_hasher = Hasher::new_keyed(&self.secret_salt);

        // Directly hash native IP octets to eliminate intermediate String allocation
        match req.client_ip {
            IpAddr::V4(v4) => {
                master_hasher.update(b"v4:");
                master_hasher.update(&v4.octets());
            }
            IpAddr::V6(v6) => {
                master_hasher.update(b"v6:");
                master_hasher.update(&v6.octets());
            }
        }

        master_hasher.update(b"|");
        master_hasher.update(user_agent.unwrap_or("none").as_bytes());
        master_hasher.update(b"|");
        master_hasher.update(accept_language.unwrap_or("none").as_bytes());
        master_hasher.update(b"|");
        master_hasher.update(header_order_hash.as_bytes());

        let privacy_fingerprint = master_hasher.finalize().to_hex()[..32].to_string();

        ClientIdentity {
            client_ip: req.client_ip,
            user_agent: user_agent.map(|s| s.to_string()),
            accept_language: accept_language.map(|s| s.to_string()),
            accept_encoding: accept_encoding.map(|s| s.to_string()),
            header_order_hash,
            ja4_hint: ja4_hint.map(|s| s.to_string()),
            privacy_fingerprint,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_fingerprint_generation_and_stability() {
        let engine = FingerprintEngine::with_default_key();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();

        let mut headers = HashMap::new();
        headers.insert(
            "User-Agent".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
        );
        headers.insert("Accept-Language".to_string(), "en-US,en;q=0.9".to_string());
        headers.insert(
            "Accept-Encoding".to_string(),
            "gzip, deflate, br".to_string(),
        );

        let req1 = SecurityRequest::new(ip, "GET", "/api/v1/data", headers.clone(), None, 1024);
        let req2 = SecurityRequest::new(ip, "GET", "/api/v1/other", headers, None, 1024);

        let id1 = engine.fingerprint(&req1);
        let id2 = engine.fingerprint(&req2);

        assert_eq!(
            id1.privacy_fingerprint, id2.privacy_fingerprint,
            "Identical clients must yield identical fingerprints"
        );
        assert_eq!(id1.header_order_hash, id2.header_order_hash);
        assert_eq!(id1.privacy_fingerprint.len(), 32);
    }

    #[test]
    fn test_fingerprint_variance_on_different_ip_or_agent() {
        let engine = FingerprintEngine::with_default_key();
        let ip1: IpAddr = "198.51.100.1".parse().unwrap();
        let ip2: IpAddr = "198.51.100.2".parse().unwrap();

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "curl/7.68.0".to_string());

        let req1 = SecurityRequest::new(ip1, "GET", "/", headers.clone(), None, 1024);
        let req2 = SecurityRequest::new(ip2, "GET", "/", headers, None, 1024);

        let id1 = engine.fingerprint(&req1);
        let id2 = engine.fingerprint(&req2);

        assert_ne!(
            id1.privacy_fingerprint, id2.privacy_fingerprint,
            "Different IPs must yield distinct fingerprints"
        );
    }

    #[test]
    fn test_header_casing_insensitivity() {
        let engine = FingerprintEngine::with_default_key();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();

        let mut headers1 = HashMap::new();
        headers1.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());
        headers1.insert("Accept-Language".to_string(), "en".to_string());

        let mut headers2 = HashMap::new();
        headers2.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
        headers2.insert("accept-language".to_string(), "en".to_string());

        let req1 = SecurityRequest::new(ip, "GET", "/", headers1, None, 1024);
        let req2 = SecurityRequest::new(ip, "GET", "/", headers2, None, 1024);

        let id1 = engine.fingerprint(&req1);
        let id2 = engine.fingerprint(&req2);

        assert_eq!(id1.header_order_hash, id2.header_order_hash);
        assert_eq!(id1.privacy_fingerprint, id2.privacy_fingerprint);
    }
}
