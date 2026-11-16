#![forbid(unsafe_code)]

use ahash::RandomState;
use dashmap::DashMap;
use r_nads_common::canonicalize_ip;
use r_nads_decision::{
    MitigationAction, MitigationError, MitigationProvider, MitigationResult, ProviderHealth,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// 1. Safety Whitelist Engine (Protects CDNs, internal subnets, and gateways)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Cidr {
    pub network: u32,
    pub mask: u32,
}

impl Ipv4Cidr {
    pub fn new(ip: Ipv4Addr, prefix_len: u8) -> Self {
        let prefix = prefix_len.min(32);
        let mask = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        let network = u32::from(ip) & mask;
        Self { network, mask }
    }

    #[inline]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask) == self.network
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Cidr {
    pub network: u128,
    pub mask: u128,
}

impl Ipv6Cidr {
    pub fn new(ip: Ipv6Addr, prefix_len: u8) -> Self {
        let prefix = prefix_len.min(128);
        let mask = if prefix == 0 {
            0
        } else {
            !0u128 << (128 - prefix)
        };
        let network = u128::from(ip) & mask;
        Self { network, mask }
    }

    #[inline]
    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        (u128::from(ip) & self.mask) == self.network
    }
}

/// Safety whitelist engine to prevent self-inflicted Denial of Service
/// against critical infrastructure, local gateways, and upstream CDNs.
#[derive(Debug, Clone)]
pub struct SafetyWhitelist {
    v4_cidrs: Vec<Ipv4Cidr>,
    v6_cidrs: Vec<Ipv6Cidr>,
}

impl Default for SafetyWhitelist {
    fn default() -> Self {
        let mut wl = Self {
            v4_cidrs: Vec::new(),
            v6_cidrs: Vec::new(),
        };

        // 1. Loopback
        wl.add_v4_cidr("127.0.0.0", 8);
        wl.add_v6_cidr("::1", 128);

        // 2. RFC1918 Private Subnets
        wl.add_v4_cidr("10.0.0.0", 8);
        wl.add_v4_cidr("172.16.0.0", 12);
        wl.add_v4_cidr("192.168.0.0", 16);

        // 3. IPv6 Link-Local
        wl.add_v6_cidr("fe80::", 10);

        // 4. Cloudflare CDN Edge Ranges (IPv4)
        wl.add_v4_cidr("173.245.48.0", 20);
        wl.add_v4_cidr("103.21.244.0", 22);
        wl.add_v4_cidr("103.22.200.0", 22);
        wl.add_v4_cidr("103.31.4.0", 22);
        wl.add_v4_cidr("141.101.64.0", 18);
        wl.add_v4_cidr("108.162.192.0", 18);
        wl.add_v4_cidr("190.93.240.0", 20);
        wl.add_v4_cidr("188.114.96.0", 20);
        wl.add_v4_cidr("197.234.240.0", 22);
        wl.add_v4_cidr("198.41.128.0", 17);
        wl.add_v4_cidr("162.158.0.0", 15);
        wl.add_v4_cidr("104.16.0.0", 13);
        wl.add_v4_cidr("104.24.0.0", 14);
        wl.add_v4_cidr("172.64.0.0", 13);
        wl.add_v4_cidr("131.0.72.0", 22);

        // 5. Cloudflare CDN Edge Ranges (IPv6)
        wl.add_v6_cidr("2400:cb00::", 32);
        wl.add_v6_cidr("2606:4700::", 32);
        wl.add_v6_cidr("2803:f800::", 32);
        wl.add_v6_cidr("2405:b500::", 32);
        wl.add_v6_cidr("2405:8100::", 32);
        wl.add_v6_cidr("2a06:98c0::", 29);
        wl.add_v6_cidr("2c0f:f248::", 32);

        wl
    }
}

impl SafetyWhitelist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_v4_cidr(&mut self, ip_str: &str, prefix: u8) {
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            self.v4_cidrs.push(Ipv4Cidr::new(ip, prefix));
        }
    }

    pub fn add_v6_cidr(&mut self, ip_str: &str, prefix: u8) {
        if let Ok(ip) = ip_str.parse::<Ipv6Addr>() {
            self.v6_cidrs.push(Ipv6Cidr::new(ip, prefix));
        }
    }

    /// Checks if a client IP is protected by the safety whitelist.
    #[inline]
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        match canonicalize_ip(*ip) {
            IpAddr::V4(v4) => self.v4_cidrs.iter().any(|cidr| cidr.contains(v4)),
            IpAddr::V6(v6) => self.v6_cidrs.iter().any(|cidr| cidr.contains(v6)),
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Firewall Mitigation Provider (nftables / iptables / mock)
// ---------------------------------------------------------------------------

/// Mode of kernel firewall enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallMode {
    Nftables,
    Iptables,
    Mock,
}

/// Active ban record tracked for removal.
#[derive(Debug, Clone)]
pub struct ActiveBan {
    pub target_ip: IpAddr,
    pub rule_identifier: String,
    pub mode: FirewallMode,
}

/// Linux kernel firewall mitigation provider implementing `r_nads_decision::MitigationProvider`.
/// Zero command-injection risk: uses direct argument vectors with no shell interpolation.
pub struct KernelMitigationProvider {
    mode: FirewallMode,
    whitelist: SafetyWhitelist,
    active_bans: Arc<DashMap<String, ActiveBan, RandomState>>,
    table_family: String,
    table_name: String,
    set_name_v4: String,
    set_name_v6: String,
}

impl KernelMitigationProvider {
    pub fn new(mode: FirewallMode, whitelist: SafetyWhitelist) -> Self {
        let provider = Self {
            mode,
            whitelist,
            active_bans: Arc::new(DashMap::with_hasher(RandomState::new())),
            table_family: "inet".to_string(),
            table_name: "filter".to_string(),
            set_name_v4: "r_nads_block_v4".to_string(),
            set_name_v6: "r_nads_block_v6".to_string(),
        };

        // If in nftables mode on Linux, ensure both sets exist
        if mode == FirewallMode::Nftables && cfg!(target_os = "linux") {
            let _ = provider.init_nftables_table();
        }

        provider
    }

    /// Number of active kernel-level bans.
    pub fn active_bans_count(&self) -> usize {
        self.active_bans.len()
    }

    /// Gets active rule identifier for an action id.
    pub fn get_rule_id(&self, action_id: &str) -> Option<String> {
        self.active_bans
            .get(action_id)
            .map(|b| b.rule_identifier.clone())
    }

    /// Default constructor detecting host OS capabilities.
    pub fn auto_detect(whitelist: SafetyWhitelist) -> Self {
        if !cfg!(target_os = "linux") {
            return Self::new(FirewallMode::Mock, whitelist);
        }

        // Test if nft command is available
        if Command::new("nft").arg("--version").output().is_ok() {
            Self::new(FirewallMode::Nftables, whitelist)
        } else if Command::new("iptables").arg("--version").output().is_ok() {
            Self::new(FirewallMode::Iptables, whitelist)
        } else {
            Self::new(FirewallMode::Mock, whitelist)
        }
    }

    fn init_nftables_table(&self) -> Result<(), MitigationError> {
        // nft add set inet filter r_nads_block_v4 { type ipv4_addr; flags timeout; }
        let out_v4 = Command::new("nft")
            .args([
                "add",
                "set",
                &self.table_family,
                &self.table_name,
                &self.set_name_v4,
                "{",
                "type",
                "ipv4_addr;",
                "flags",
                "timeout;",
                "}",
            ])
            .output();

        if let Err(e) = out_v4 {
            return Err(MitigationError::FirewallError(e.to_string()));
        }

        // nft add set inet filter r_nads_block_v6 { type ipv6_addr; flags timeout; }
        let out_v6 = Command::new("nft")
            .args([
                "add",
                "set",
                &self.table_family,
                &self.table_name,
                &self.set_name_v6,
                "{",
                "type",
                "ipv6_addr;",
                "flags",
                "timeout;",
                "}",
            ])
            .output();

        match out_v6 {
            Ok(out) if out.status.success() => Ok(()),
            Ok(out) => Err(MitigationError::FirewallError(
                String::from_utf8_lossy(&out.stderr).to_string(),
            )),
            Err(e) => Err(MitigationError::FirewallError(e.to_string())),
        }
    }
}

impl MitigationProvider for KernelMitigationProvider {
    fn apply(&self, action: &MitigationAction) -> Result<MitigationResult, MitigationError> {
        // 1. Safety Whitelist Check
        if self.whitelist.is_whitelisted(&action.target_ip) {
            return Err(MitigationError::FirewallError(format!(
                "Refusing to ban IP {}: Address is protected by safety whitelist.",
                action.target_ip
            )));
        }

        // Avoid duplicate application if already banned
        if self.active_bans.contains_key(&action.action_id) {
            return Ok(MitigationResult {
                success: true,
                provider_rule_id: format!("fw-{}-{}", action.action_id, action.target_ip),
            });
        }

        let ip_str = action.target_ip.to_string();
        let duration_secs = action.duration_secs;

        // 2. Execute mitigation based on backend mode
        match self.mode {
            FirewallMode::Nftables => {
                let timeout_arg = format!("{}s", duration_secs);
                let set_target = if action.target_ip.is_ipv6() {
                    &self.set_name_v6
                } else {
                    &self.set_name_v4
                };
                // Parameterized invocation: zero shell injection risk
                let output = Command::new("nft")
                    .args([
                        "add",
                        "element",
                        "inet",
                        "filter",
                        set_target,
                        "{",
                        &ip_str,
                        "timeout",
                        &timeout_arg,
                        "}",
                    ])
                    .output()
                    .map_err(|e| MitigationError::FirewallError(e.to_string()))?;

                if !output.status.success() {
                    let err = String::from_utf8_lossy(&output.stderr);
                    return Err(MitigationError::FirewallError(err.to_string()));
                }
            }
            FirewallMode::Iptables => {
                let bin = if action.target_ip.is_ipv6() {
                    "ip6tables"
                } else {
                    "iptables"
                };

                // Parameterized invocation
                let output = Command::new(bin)
                    .args(["-I", "INPUT", "-s", &ip_str, "-j", "DROP"])
                    .output()
                    .map_err(|e| MitigationError::FirewallError(e.to_string()))?;

                if !output.status.success() {
                    let err = String::from_utf8_lossy(&output.stderr);
                    return Err(MitigationError::FirewallError(err.to_string()));
                }
            }
            FirewallMode::Mock => {
                // Mock mode successfully records in memory
            }
        }

        let rule_id = format!("fw-{}-{}", action.action_id, ip_str);

        self.active_bans.insert(
            action.action_id.clone(),
            ActiveBan {
                target_ip: action.target_ip,
                rule_identifier: rule_id.clone(),
                mode: self.mode,
            },
        );

        Ok(MitigationResult {
            success: true,
            provider_rule_id: rule_id,
        })
    }

    fn remove(&self, action_id: &str) -> Result<(), MitigationError> {
        let ban = self.active_bans.remove(action_id);

        if let Some((_, active)) = ban {
            let ip_str = active.target_ip.to_string();
            match active.mode {
                FirewallMode::Nftables => {
                    let set_target = if active.target_ip.is_ipv6() {
                        &self.set_name_v6
                    } else {
                        &self.set_name_v4
                    };
                    let output = Command::new("nft")
                        .args([
                            "delete", "element", "inet", "filter", set_target, "{", &ip_str, "}",
                        ])
                        .output()
                        .map_err(|e| MitigationError::FirewallError(e.to_string()))?;

                    if !output.status.success() {
                        let err = String::from_utf8_lossy(&output.stderr);
                        return Err(MitigationError::FirewallError(err.to_string()));
                    }
                }
                FirewallMode::Iptables => {
                    let bin = if active.target_ip.is_ipv6() {
                        "ip6tables"
                    } else {
                        "iptables"
                    };

                    let output = Command::new(bin)
                        .args(["-D", "INPUT", "-s", &ip_str, "-j", "DROP"])
                        .output()
                        .map_err(|e| MitigationError::FirewallError(e.to_string()))?;

                    if !output.status.success() {
                        let err = String::from_utf8_lossy(&output.stderr);
                        return Err(MitigationError::FirewallError(err.to_string()));
                    }
                }
                FirewallMode::Mock => {
                    // Removed from in-memory map
                }
            }
        }

        Ok(())
    }

    fn health_check(&self) -> Result<ProviderHealth, MitigationError> {
        let is_healthy = match self.mode {
            FirewallMode::Nftables => {
                if cfg!(target_os = "linux") {
                    Command::new("nft").arg("--version").output().is_ok()
                } else {
                    false
                }
            }
            FirewallMode::Iptables => {
                if cfg!(target_os = "linux") {
                    Command::new("iptables").arg("--version").output().is_ok()
                } else {
                    false
                }
            }
            FirewallMode::Mock => true,
        };

        Ok(ProviderHealth {
            is_healthy,
            message: format!("Mode: {:?}", self.mode),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_whitelist_rfc1918_and_loopback() {
        let wl = SafetyWhitelist::default();

        // Loopback
        assert!(wl.is_whitelisted(&"127.0.0.1".parse().unwrap()));
        assert!(wl.is_whitelisted(&"::1".parse().unwrap()));

        // RFC1918 Private ranges
        assert!(wl.is_whitelisted(&"10.0.1.50".parse().unwrap()));
        assert!(wl.is_whitelisted(&"172.16.5.10".parse().unwrap()));
        assert!(wl.is_whitelisted(&"192.168.1.1".parse().unwrap()));

        // Cloudflare IP
        assert!(wl.is_whitelisted(&"104.16.12.34".parse().unwrap()));
        assert!(wl.is_whitelisted(&"2606:4700::1".parse().unwrap()));

        // Public non-whitelisted IP
        assert!(!wl.is_whitelisted(&"203.0.113.195".parse().unwrap()));
        assert!(!wl.is_whitelisted(&"198.51.100.1".parse().unwrap()));
    }

    #[test]
    fn test_mock_mitigation_provider_apply_and_remove() {
        let wl = SafetyWhitelist::default();
        let provider = KernelMitigationProvider::new(FirewallMode::Mock, wl);

        let target_ip: IpAddr = "203.0.113.50".parse().unwrap();
        let action = MitigationAction {
            action_id: "act-001".to_string(),
            target_ip,
            duration_secs: 60,
            reason: "Volumetric SYN flood anomaly".to_string(),
        };

        // 1. Successful ban on public IP
        let res = provider
            .apply(&action)
            .expect("Should succeed in mock mode");
        assert!(res.success);
        assert!(res.provider_rule_id.contains("act-001"));

        // 2. Removal
        provider.remove("act-001").expect("Should remove cleanly");
    }

    #[test]
    fn test_refuse_ban_whitelisted_ip() {
        let wl = SafetyWhitelist::default();
        let provider = KernelMitigationProvider::new(FirewallMode::Mock, wl);

        // Attempt to ban Cloudflare IP
        let cloudflare_ip: IpAddr = "104.16.1.1".parse().unwrap();
        let action = MitigationAction {
            action_id: "act-bad".to_string(),
            target_ip: cloudflare_ip,
            duration_secs: 300,
            reason: "False positive".to_string(),
        };

        let result = provider.apply(&action);
        assert!(result.is_err(), "Must reject banning a whitelisted IP");
    }
}
