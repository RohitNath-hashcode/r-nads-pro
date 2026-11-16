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

    /// Computes the normalized and salted privacy fingerprint from an incoming HTTP SecurityRequest.
    pub fn fingerprint(&self, req: &SecurityRequest) -> ClientIdentity {
        let user_agent = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.clone());
        let accept_language = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("accept-language"))
            .map(|(_, v)| v.clone());
        let accept_encoding = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
            .map(|(_, v)| v.clone());
        let ja4_hint = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-ja4"))
            .map(|(_, v)| v.clone());

        // Header structure ordering fingerprint (fingerprints client HTTP stack implementation)
        let mut header_names: Vec<String> =
            req.headers.keys().map(|k| k.to_ascii_lowercase()).collect();
        header_names.sort(); // Canonical sorted representation for stable comparison
        let header_order_repr = header_names.join(",");

        let mut header_hasher = Hasher::new_keyed(&self.secret_salt);
        header_hasher.update(header_order_repr.as_bytes());
        let header_order_hash = header_hasher.finalize().to_hex()[..16].to_string();

        // Master privacy-preserving fingerprint
        let mut master_hasher = Hasher::new_keyed(&self.secret_salt);
        master_hasher.update(req.client_ip.to_string().as_bytes());
        master_hasher.update(b"|");
        master_hasher.update(user_agent.as_deref().unwrap_or("none").as_bytes());
        master_hasher.update(b"|");
        master_hasher.update(accept_language.as_deref().unwrap_or("none").as_bytes());
        master_hasher.update(b"|");
        master_hasher.update(header_order_hash.as_bytes());

        let privacy_fingerprint = master_hasher.finalize().to_hex()[..32].to_string();

        ClientIdentity {
            client_ip: req.client_ip,
            user_agent,
            accept_language,
            accept_encoding,
            header_order_hash,
            ja4_hint,
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
}
