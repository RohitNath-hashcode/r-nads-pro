use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

/// Canonicalizes an IP address, converting IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`)
/// to their native IPv4 representation for uniform 128-bit / 32-bit symmetric comparison.
#[inline]
pub fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // IPv4-mapped IPv6 addresses have prefix 0..0 followed by 0xffff
            if octets[0..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
                IpAddr::V4(Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                ))
            } else {
                IpAddr::V6(v6)
            }
        }
    }
}

/// Direction of a packet in a flow relative to the flow initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Direction {
    #[default]
    Forward,
    Backward,
}

/// Bidirectional 5-tuple identifying a network flow across IPv4 and IPv6.
/// The fields are ordered symmetrically to ensure that traffic from A -> B and B -> A
/// maps to the exact same FlowKey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub ip_min: IpAddr,
    pub ip_max: IpAddr,
    pub port_min: u16,
    pub port_max: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// Creates a new symmetric FlowKey from packet properties,
    /// canonicalizing IPv4 and IPv6 addresses.
    #[inline]
    pub fn new(
        src_ip: IpAddr,
        src_port: u16,
        dest_ip: IpAddr,
        dest_port: u16,
        protocol: u8,
    ) -> Self {
        let src_c = canonicalize_ip(src_ip);
        let dest_c = canonicalize_ip(dest_ip);

        let (ip_min, port_min, ip_max, port_max) = if src_c < dest_c {
            (src_c, src_port, dest_c, dest_port)
        } else if src_c > dest_c {
            (dest_c, dest_port, src_c, src_port)
        } else if src_port <= dest_port {
            (src_c, src_port, dest_c, dest_port)
        } else {
            (dest_c, dest_port, src_c, src_port)
        };

        Self {
            ip_min,
            ip_max,
            port_min,
            port_max,
            protocol,
        }
    }

    /// Returns true if this flow is over IPv6.
    #[inline]
    pub fn is_ipv6(&self) -> bool {
        matches!(self.ip_min, IpAddr::V6(_)) || matches!(self.ip_max, IpAddr::V6(_))
    }
}

/// Extended diagnostic flags for parsed packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PacketFlags {
    /// True if the packet is an IP fragment (IPv4 fragment offset > 0 or MF flag; IPv6 fragment header)
    pub is_fragment: bool,
    /// True if the packet has malformed flags (NULL scan, XMAS scan, SYN+FIN, SYN+RST) or truncated headers
    pub is_malformed: bool,
}

/// A parsed packet event sent from Ingestion Engine (Producer) to Aggregators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEvent {
    pub timestamp: SystemTime,
    pub len: u32,
    pub src_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: u8,
    pub tcp_flags: Option<u8>,
    #[serde(default)]
    pub flags: PacketFlags,
}

impl PacketEvent {
    /// Helper to get the FlowKey for this packet.
    #[inline]
    pub fn flow_key(&self) -> FlowKey {
        FlowKey::new(
            self.src_ip,
            self.src_port,
            self.dest_ip,
            self.dest_port,
            self.protocol,
        )
    }

    /// Returns true if this packet is an IP fragment.
    #[inline]
    pub fn is_fragment(&self) -> bool {
        self.flags.is_fragment
    }

    /// Returns true if this packet was detected as malformed.
    #[inline]
    pub fn is_malformed(&self) -> bool {
        self.flags.is_malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_flow_key_ipv4() {
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        let key1 = FlowKey::new(ip_a, 1234, ip_b, 80, 6);
        let key2 = FlowKey::new(ip_b, 80, ip_a, 1234, 6);

        assert_eq!(key1, key2);
        assert_eq!(key1.ip_min, ip_a);
        assert_eq!(key1.ip_max, ip_b);
        assert_eq!(key1.port_min, 1234);
        assert_eq!(key1.port_max, 80);
        assert!(!key1.is_ipv6());
    }

    #[test]
    fn test_symmetric_flow_key_ipv6() {
        let ip_a: IpAddr = "2001:db8::1".parse().unwrap();
        let ip_b: IpAddr = "fe80::dead:beef".parse().unwrap();

        let key1 = FlowKey::new(ip_a, 443, ip_b, 54321, 6);
        let key2 = FlowKey::new(ip_b, 54321, ip_a, 443, 6);

        assert_eq!(key1, key2);
        assert!(key1.is_ipv6());
        assert_eq!(key1.protocol, 6);
    }

    #[test]
    fn test_ipv4_mapped_ipv6_canonicalization() {
        let ip_v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        // IPv4-mapped IPv6 ::ffff:192.0.2.1
        let ip_mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();

        assert_eq!(canonicalize_ip(ip_mapped), ip_v4);

        let key_v4 = FlowKey::new(ip_v4, 80, "10.0.0.1".parse().unwrap(), 12345, 6);
        let key_mapped = FlowKey::new(ip_mapped, 80, "10.0.0.1".parse().unwrap(), 12345, 6);

        assert_eq!(key_v4, key_mapped);
    }
}
