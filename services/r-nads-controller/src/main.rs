#![forbid(unsafe_code)]

//! Central Fleet Controller Service for R-NADS Pro.
//!
//! Manages edge agent heartbeats, tracks cluster inventory, and broadcasts
//! Ed25519-signed security policy envelopes with monotonic version sequencing.

use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Cursor;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Response, Server};

use r_nads_policy::{PolicyRateLimits, PolicyWafRules, SecurityPolicyBundle, SignedPolicyEnvelope};

/// Agent node metadata reported during registration or keepalive heartbeats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentNodeStatus {
    pub agent_id: String,
    pub hostname: String,
    pub ip_address: IpAddr,
    pub active_policy_version: u64,
    pub packets_processed: u64,
    pub uptime_secs: u64,
    pub last_heartbeat_unix: u64,
}

/// Central controller state.
pub struct FleetController {
    pub signing_key: SigningKey,
    pub active_envelope: Arc<RwLock<SignedPolicyEnvelope>>,
    pub agent_registry: Arc<DashMap<String, (AgentNodeStatus, Instant)>>,
    pub policy_version_seq: Arc<AtomicU64>,
}

impl FleetController {
    pub fn new(tenant_id: &str) -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let initial_policy = SecurityPolicyBundle {
            tenant_id: tenant_id.to_string(),
            policy_version: 1,
            created_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            expires_at_unix: None,
            blocked_ips: HashSet::new(),
            rate_limits: PolicyRateLimits::default(),
            waf_rules: PolicyWafRules::default(),
        };

        let initial_envelope = SignedPolicyEnvelope::sign(initial_policy, &signing_key)
            .expect("Initial policy signing failed");

        Self {
            signing_key,
            active_envelope: Arc::new(RwLock::new(initial_envelope)),
            agent_registry: Arc::new(DashMap::new()),
            policy_version_seq: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Issues an updated policy bundle signed with the controller key.
    pub fn publish_policy_update(
        &self,
        tenant_id: &str,
        blocked_ips: HashSet<IpAddr>,
        rate_limits: PolicyRateLimits,
        waf_rules: PolicyWafRules,
    ) -> SignedPolicyEnvelope {
        let next_version = self.policy_version_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let policy = SecurityPolicyBundle {
            tenant_id: tenant_id.to_string(),
            policy_version: next_version,
            created_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            expires_at_unix: None,
            blocked_ips,
            rate_limits,
            waf_rules,
        };

        let envelope = SignedPolicyEnvelope::sign(policy, &self.signing_key)
            .expect("Failed to sign updated policy bundle");

        *self.active_envelope.write().unwrap() = envelope.clone();
        envelope
    }

    /// Records an agent keepalive heartbeat.
    pub fn register_heartbeat(&self, status: AgentNodeStatus) {
        self.agent_registry
            .insert(status.agent_id.clone(), (status, Instant::now()));
    }

    /// Prunes agent nodes that have missed heartbeats past the timeout limit.
    pub fn prune_stale_agents(&self, timeout: Duration) -> usize {
        let now = Instant::now();
        let mut pruned = 0;
        self.agent_registry.retain(|_, (_, last_seen)| {
            if now.duration_since(*last_seen) > timeout {
                pruned += 1;
                false
            } else {
                true
            }
        });
        pruned
    }
}

/// Runs the HTTP control plane distribution server.
pub fn run_controller_server(
    bind_addr: &str,
    controller: Arc<FleetController>,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = Server::http(bind_addr).map_err(|e| e.to_string())?;

    while running.load(Ordering::Relaxed) {
        if let Ok(Some(mut request)) = server.recv_timeout(Duration::from_millis(200)) {
            let url = request.url().to_string();
            let method = request.method().clone();

            match (method, url.as_str()) {
                (Method::Get, "/api/v1/policy/current") => {
                    let envelope = controller.active_envelope.read().unwrap().clone();
                    let json = serde_json::to_string(&envelope).unwrap_or_default();
                    let response = Response::empty(200)
                        .with_header(
                            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                                .unwrap(),
                        )
                        .with_data(Cursor::new(json.into_bytes()), None);
                    let _ = request.respond(response);
                }
                (Method::Post, "/api/v1/agent/heartbeat") => {
                    let mut content = String::new();
                    if request.as_reader().read_to_string(&mut content).is_ok() {
                        if let Ok(status) = serde_json::from_str::<AgentNodeStatus>(&content) {
                            controller.register_heartbeat(status);
                            let response = Response::from_string("{\"status\":\"ok\"}")
                                .with_status_code(200)
                                .with_header(
                                    Header::from_bytes(
                                        &b"Content-Type"[..],
                                        &b"application/json"[..],
                                    )
                                    .unwrap(),
                                );
                            let _ = request.respond(response);
                            continue;
                        }
                    }
                    let response = Response::from_string("{\"error\":\"Invalid status payload\"}")
                        .with_status_code(400);
                    let _ = request.respond(response);
                }
                (Method::Get, "/api/v1/fleet/status") => {
                    let agents: Vec<AgentNodeStatus> = controller
                        .agent_registry
                        .iter()
                        .map(|entry| entry.value().0.clone())
                        .collect();
                    let json = serde_json::to_string(&agents).unwrap_or_default();
                    let response = Response::empty(200)
                        .with_header(
                            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                                .unwrap(),
                        )
                        .with_data(Cursor::new(json.into_bytes()), None);
                    let _ = request.respond(response);
                }
                _ => {
                    let response = Response::from_string("Not Found").with_status_code(404);
                    let _ = request.respond(response);
                }
            }
        }
    }

    Ok(())
}

fn main() {
    println!("R-NADS Central Fleet Controller Daemon starting...");
    let controller = Arc::new(FleetController::new("tenant_global_production"));
    let running = Arc::new(AtomicBool::new(true));

    let r_clone = running.clone();
    let _ = ctrlc::set_handler(move || {
        println!("Shutting down Fleet Controller...");
        r_clone.store(false, Ordering::SeqCst);
    });

    if let Err(e) = run_controller_server("0.0.0.0:8099", controller, running) {
        eprintln!("Controller error: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_controller_heartbeat_and_pruning() {
        let controller = FleetController::new("tenant_test");
        let ip: IpAddr = "10.0.0.5".parse().unwrap();

        let agent = AgentNodeStatus {
            agent_id: "edge-node-01".to_string(),
            hostname: "edge-us-east-1a".to_string(),
            ip_address: ip,
            active_policy_version: 1,
            packets_processed: 50000,
            uptime_secs: 3600,
            last_heartbeat_unix: 1700000000,
        };

        controller.register_heartbeat(agent);
        assert_eq!(controller.agent_registry.len(), 1);

        // Immediate pruning should not drop recently active agent
        let dropped = controller.prune_stale_agents(Duration::from_secs(60));
        assert_eq!(dropped, 0);
        assert_eq!(controller.agent_registry.len(), 1);

        // Zero-second timeout forces pruning
        let dropped = controller.prune_stale_agents(Duration::from_nanos(0));
        assert_eq!(dropped, 1);
        assert_eq!(controller.agent_registry.len(), 0);
    }

    #[test]
    fn test_controller_policy_broadcast_sequence() {
        let controller = FleetController::new("tenant_test");
        assert_eq!(
            controller
                .active_envelope
                .read()
                .unwrap()
                .policy
                .policy_version,
            1
        );

        let updated = controller.publish_policy_update(
            "tenant_test",
            ["192.0.2.1".parse().unwrap()].into(),
            PolicyRateLimits::default(),
            PolicyWafRules::default(),
        );

        assert_eq!(updated.policy.policy_version, 2);
        assert!(updated.verify().is_ok());
        assert_eq!(
            controller
                .active_envelope
                .read()
                .unwrap()
                .policy
                .policy_version,
            2
        );
    }
}
