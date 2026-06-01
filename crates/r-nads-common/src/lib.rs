use std::net::IpAddr;
use std::time::SystemTime;
use serde::{Serialize, Deserialize};

/// Direction of a packet in a flow relative to the flow initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Forward,
    Backward,
}

/// Bidirectional 5-tuple identifying a network flow.
/// The fields are ordered symmetrically to ensure that traffic from A -> B and B -> A
/// maps to the same FlowKey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub ip_min: IpAddr,
    pub ip_max: IpAddr,
    pub port_min: u16,
    pub port_max: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// Creates a new symmetric FlowKey from packet properties.
    #[inline]
    pub fn new(src_ip: IpAddr, src_port: u16, dest_ip: IpAddr, dest_port: u16, protocol: u8) -> Self {
        // Order endpoints symmetrically based on IP, then port if IPs are equal
        let (ip_min, port_min, ip_max, port_max) = if src_ip < dest_ip {
            (src_ip, src_port, dest_ip, dest_port)
        } else if src_ip > dest_ip {
            (dest_ip, dest_port, src_ip, src_port)
        } else {
            // IPs are equal (e.g. loopback)
            if src_port <= dest_port {
                (src_ip, src_port, dest_ip, dest_port)
            } else {
                (dest_ip, dest_port, src_ip, src_port)
            }
        };

        Self {
            ip_min,
            ip_max,
            port_min,
            port_max,
            protocol,
        }
    }
}

/// A parsed packet event sent from the Ingestion Engine (Producer) to the Aggregators.
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
}

impl PacketEvent {
    /// Helper to get the FlowKey for this packet.
    #[inline]
    pub fn flow_key(&self) -> FlowKey {
        FlowKey::new(self.src_ip, self.src_port, self.dest_ip, self.dest_port, self.protocol)
    }
}

/// Alert details for a detected flow anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyAlert {
    pub key: FlowKey,
    pub timestamp: SystemTime,
    pub score: f64,
    pub threshold: f64,
    pub mean_len: f64,
    pub var_len: f64,
    pub packet_rate: f64,
    pub byte_rate: f64,
    pub fwd_bwd_ratio: f64,
    pub syn_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_symmetric_flow_key() {
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        let key1 = FlowKey::new(ip_a, 1234, ip_b, 80, 6);
        let key2 = FlowKey::new(ip_b, 80, ip_a, 1234, 6);

        assert_eq!(key1, key2);
        assert_eq!(key1.ip_min, ip_a);
        assert_eq!(key1.ip_max, ip_b);
        assert_eq!(key1.port_min, 1234);
        assert_eq!(key1.port_max, 80);
    }
}
