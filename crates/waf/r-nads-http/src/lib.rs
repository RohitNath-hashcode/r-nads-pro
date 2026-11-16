#![forbid(unsafe_code)]

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use unicode_normalization::UnicodeNormalization;

/// HTTP Methods supported by the canonical request engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Connect,
    Trace,
    Other,
}

impl From<&str> for HttpMethod {
    fn from(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "DELETE" => HttpMethod::Delete,
            "PATCH" => HttpMethod::Patch,
            "HEAD" => HttpMethod::Head,
            "OPTIONS" => HttpMethod::Options,
            "CONNECT" => HttpMethod::Connect,
            "TRACE" => HttpMethod::Trace,
            _ => HttpMethod::Other,
        }
    }
}

/// Normalized and canonical representation of an incoming HTTP request for WAF and security evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRequest {
    pub client_ip: IpAddr,
    pub method: HttpMethod,
    pub raw_uri: String,
    pub canonical_path: String,
    pub query_string: Option<String>,
    pub query_params: Vec<(String, String)>,
    pub headers: HashMap<String, String>,
    pub body_bytes: Option<Vec<u8>>,
    pub body_truncated: bool,
}

impl SecurityRequest {
    /// Builds a canonical security request from raw HTTP elements, applying full path normalization.
    pub fn new(
        client_ip: IpAddr,
        method: &str,
        raw_uri: &str,
        headers: HashMap<String, String>,
        body: Option<Vec<u8>>,
        max_body_bytes: usize,
    ) -> Self {
        let (raw_path, query_str) = match raw_uri.split_once('?') {
            Some((p, q)) => (p, Some(q.to_string())),
            None => (raw_uri, None),
        };

        let canonical_path = normalize_path(raw_path);

        let query_params = if let Some(ref q) = query_str {
            parse_and_normalize_query(q)
        } else {
            Vec::new()
        };

        // Bounded body ingestion to prevent memory exhaustion
        let (body_bytes, body_truncated) = match body {
            Some(mut b) => {
                if b.len() > max_body_bytes {
                    b.truncate(max_body_bytes);
                    (Some(b), true)
                } else {
                    (Some(b), false)
                }
            }
            None => (None, false),
        };

        Self {
            client_ip,
            method: HttpMethod::from(method),
            raw_uri: raw_uri.to_string(),
            canonical_path,
            query_string: query_str,
            query_params,
            headers,
            body_bytes,
            body_truncated,
        }
    }
}

/// Recursively decodes percentage-encoded strings to defeat double-URL encoding attacks
/// (e.g., `%252e%252e%252f` -> `../`). Max recursion depth capped at 5 to prevent CPU exhaustion.
pub fn recursive_percent_decode(input: &str) -> String {
    let mut current = input.to_string();
    for _ in 0..5 {
        let decoded = match percent_decode_str(&current).decode_utf8() {
            Ok(s) => s.to_string(),
            Err(_) => return current,
        };
        if decoded == current {
            break;
        }
        current = decoded;
    }
    current
}

/// Performs comprehensive canonical path normalization:
/// 1. Strips null bytes (`\0`).
/// 2. Recursively URL-decodes percentage sequences.
/// 3. Normalizes Unicode representations using Unicode NFKC.
/// 4. Converts Windows backslashes `\` to standard forward slashes `/`.
/// 5. Resolves relative path traversals (`/./`, `/../`).
pub fn normalize_path(raw_path: &str) -> String {
    // 1. Strip null bytes
    let clean = raw_path.replace('\0', "");

    // 2. Recursive percent decode
    let decoded = recursive_percent_decode(&clean);

    // 3. Unicode NFKC normalization
    let normalized_unicode: String = decoded.nfkc().collect();

    // 4. Convert backslashes to forward slashes
    let forward_slashed = normalized_unicode.replace('\\', "/");

    // 5. Canonicalize path segments
    let mut segments: Vec<&str> = Vec::new();
    for seg in forward_slashed.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }

    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

/// Parses and normalizes URI query string into key-value pairs with recursive percent decoding.
pub fn parse_and_normalize_query(query: &str) -> Vec<(String, String)> {
    let mut params = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((key, val)) => (recursive_percent_decode(key), recursive_percent_decode(val)),
            None => (recursive_percent_decode(pair), String::new()),
        };
        params.push((k, v));
    }
    params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recursive_percent_decode_double_encoding() {
        // Double-encoded "../" -> %252e%252e%252f
        let attack = "%252e%252e%252fetc%252fpasswd";
        let decoded = recursive_percent_decode(attack);
        assert_eq!(decoded, "../etc/passwd");
    }

    #[test]
    fn test_path_normalization_traversal_and_backslashes() {
        assert_eq!(normalize_path("/api/v1/../../etc/passwd"), "/etc/passwd");
        assert_eq!(
            normalize_path("/static/..\\..\\windows\\system32"),
            "/windows/system32"
        );
        assert_eq!(normalize_path("/a/b/./c/../d/"), "/a/b/d");
        assert_eq!(
            normalize_path("///multiple///slashes//"),
            "/multiple/slashes"
        );
    }

    #[test]
    fn test_path_normalization_null_bytes_and_unicode() {
        let with_null = "/images/profile.jpg\0.php";
        assert_eq!(normalize_path(with_null), "/images/profile.jpg.php");
    }

    #[test]
    fn test_security_request_body_truncation() {
        let ip = "127.0.0.1".parse().unwrap();
        let large_body = vec![65u8; 1000]; // 1000 bytes
        let req = SecurityRequest::new(
            ip,
            "POST",
            "/api/upload?type=doc&ref=%252e%252e%252fsecret",
            HashMap::new(),
            Some(large_body),
            500, // max 500 bytes
        );

        assert_eq!(req.canonical_path, "/api/upload");
        assert!(req.body_truncated);
        assert_eq!(req.body_bytes.unwrap().len(), 500);
        assert_eq!(req.query_params[1].1, "../secret");
    }
}
