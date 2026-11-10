#![forbid(unsafe_code)]

use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use r_nads_common::{PacketEvent, PacketFlags};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Zero-copy network packet parser.
/// Parses ethernet, IPv4/IPv6, and TCP/UDP/ICMP headers from raw bytes,
/// detects IP fragmentation and malformed flags, and extracts a stateless `PacketEvent`.
#[inline]
pub fn parse_packet(packet_data: &[u8], timestamp: SystemTime) -> Option<PacketEvent> {
    let sliced = SlicedPacket::from_ethernet(packet_data).ok()?;

    let ip_slice = sliced.ip?;
    let mut is_fragment = false;

    let (src_ip, dest_ip, protocol) = match ip_slice {
        InternetSlice::Ipv4(ipv4_slice, _) => {
            is_fragment = ipv4_slice.more_fragments() || ipv4_slice.fragments_offset() > 0;
            (
                IpAddr::V4(ipv4_slice.source_addr()),
                IpAddr::V4(ipv4_slice.destination_addr()),
                ipv4_slice.protocol(),
            )
        }
        InternetSlice::Ipv6(ipv6_slice, _) => (
            IpAddr::V6(ipv6_slice.source_addr()),
            IpAddr::V6(ipv6_slice.destination_addr()),
            ipv6_slice.next_header(),
        ),
    };

    let mut is_malformed = false;

    let (src_port, dest_port, tcp_flags) = match sliced.transport {
        Some(TransportSlice::Tcp(tcp_slice)) => {
            let mut flags = 0u8;
            if tcp_slice.fin() {
                flags |= 0x01;
            }
            if tcp_slice.syn() {
                flags |= 0x02;
            }
            if tcp_slice.rst() {
                flags |= 0x04;
            }
            if tcp_slice.psh() {
                flags |= 0x08;
            }
            if tcp_slice.ack() {
                flags |= 0x10;
            }
            if tcp_slice.urg() {
                flags |= 0x20;
            }

            // Flag anomalies / stealth scan signatures:
            // 1. NULL scan: No flags set
            // 2. SYN-FIN: SYN and FIN both set
            // 3. SYN-RST: SYN and RST both set
            // 4. XMAS scan: FIN, PSH, and URG all set
            if flags == 0
                || (flags & 0x03) == 0x03
                || (flags & 0x06) == 0x06
                || (flags & 0x29) == 0x29
            {
                is_malformed = true;
            }

            (
                tcp_slice.source_port(),
                tcp_slice.destination_port(),
                Some(flags),
            )
        }
        Some(TransportSlice::Udp(udp_slice)) => {
            (udp_slice.source_port(), udp_slice.destination_port(), None)
        }
        Some(TransportSlice::Icmpv4(icmp_slice)) => {
            let type_u8 = icmp_slice.type_u8();
            let code_u8 = icmp_slice.code_u8();
            let port_encoded = ((type_u8 as u16) << 8) | (code_u8 as u16);
            (port_encoded, 0, None)
        }
        Some(TransportSlice::Icmpv6(icmp_slice)) => {
            let type_u8 = icmp_slice.type_u8();
            let code_u8 = icmp_slice.code_u8();
            let port_encoded = ((type_u8 as u16) << 8) | (code_u8 as u16);
            (port_encoded, 0, None)
        }
        _ => (0, 0, None),
    };

    Some(PacketEvent {
        timestamp,
        len: packet_data.len() as u32,
        src_ip,
        dest_ip,
        src_port,
        dest_port,
        protocol,
        tcp_flags,
        flags: PacketFlags {
            is_fragment,
            is_malformed,
        },
    })
}

/// Offline PCAP/PCAPNG file parser.
/// Reads packets from a file and pushes them into the sender channel.
pub fn run_pcap_file_capture(
    path: &str,
    tx: crossbeam_channel::Sender<PacketEvent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use pcap_file::pcap::PcapReader;
    use std::fs::File;

    let file = File::open(path)?;
    let mut reader = PcapReader::new(file)?;

    while let Some(packet) = reader.next_packet() {
        let packet = packet?;
        let timestamp = UNIX_EPOCH + packet.timestamp;
        if let Some(event) = parse_packet(&packet.data, timestamp) {
            if tx.send(event).is_err() {
                break;
            }
        }
    }
    Ok(())
}

/// Mock traffic generator.
/// Generates realistic synthetic network traffic (IPv4, IPv6, TCP, UDP, ICMP) to benchmark the pipeline.
#[allow(clippy::manual_is_multiple_of)]
pub fn run_mock_capture(
    tx: crossbeam_channel::Sender<PacketEvent>,
    packets_per_sec: u64,
    num_ips: u32,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::thread::sleep;
    use std::time::Duration;

    let mut count = 0u64;
    let base_ip = 0x0A000000; // 10.0.0.0

    let batch_size = if packets_per_sec > 10_000 { 1000 } else { 1 };
    let sleep_dur = Duration::from_nanos((1_000_000_000 * batch_size) / packets_per_sec);

    while running.load(Ordering::SeqCst) {
        let now = SystemTime::now();
        for _ in 0..batch_size {
            let src_offset = (count % num_ips as u64) as u32;
            let dest_offset = ((count / num_ips as u64) % num_ips as u64) as u32;

            // Generate mix of IPv4 (90%) and IPv6 (10%)
            let (src_ip, dest_ip) = if count % 10 == 0 {
                let s_v6: IpAddr = format!("2001:db8::{:x}", src_offset).parse().unwrap();
                let d_v6: IpAddr = format!("2001:db8::{:x}", dest_offset + 0x1000)
                    .parse()
                    .unwrap();
                (s_v6, d_v6)
            } else {
                let s_v4 = IpAddr::V4(std::net::Ipv4Addr::from(base_ip + src_offset));
                let d_v4 = IpAddr::V4(std::net::Ipv4Addr::from(base_ip + dest_offset + 1000));
                (s_v4, d_v4)
            };

            // Protocol distribution: TCP (70%), UDP (20%), ICMP (10%)
            let proto_selector = count % 10;
            let (protocol, src_port, dest_port, tcp_flags) = if proto_selector < 7 {
                // TCP
                let d_port = if count % 3 == 0 { 80 } else { 443 };
                let s_port = (1024 + (count % 50000)) as u16;
                let flags = if count % 10 == 0 {
                    Some(0x02) // SYN
                } else {
                    Some(0x10) // ACK
                };
                (6, s_port, d_port, flags)
            } else if proto_selector < 9 {
                // UDP (DNS / QUIC)
                let d_port = if count % 2 == 0 { 53 } else { 443 };
                let s_port = (1024 + (count % 50000)) as u16;
                (17, s_port, d_port, None)
            } else {
                // ICMP (Echo Request: Type 8, Code 0)
                let icmp_proto = if src_ip.is_ipv6() { 58 } else { 1 };
                (icmp_proto, 0x0800, 0, None)
            };

            let event = PacketEvent {
                timestamp: now,
                len: 64 + (count % 1400) as u32,
                src_ip,
                dest_ip,
                src_port,
                dest_port,
                protocol,
                tcp_flags,
                flags: PacketFlags::default(),
            };

            if tx.send(event).is_err() {
                return Ok(());
            }
            count += 1;
        }

        sleep(sleep_dur);
    }
    Ok(())
}

/// Live interface capture (compiled only on non-Windows targets).
#[cfg(not(target_os = "windows"))]
pub fn run_live_capture(
    interface: &str,
    tx: crossbeam_channel::Sender<PacketEvent>,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cap = pcap::Capture::from_device(interface)?
        .promisc(true)
        .snaplen(65535)
        .timeout(10)
        .open()?;

    let mut cap = cap;
    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                let timestamp = UNIX_EPOCH
                    + std::time::Duration::new(
                        packet.header.ts.tv_sec as u64,
                        packet.header.ts.tv_usec as u32 * 1000,
                    );
                if let Some(event) = parse_packet(packet.data, timestamp) {
                    if tx.send(event).is_err() {
                        break;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                continue;
            }
            Err(e) => {
                eprintln!("[Producer] Live capture error: {}", e);
                return Err(Box::new(e));
            }
        }
    }
    Ok(())
}

/// Live interface capture stub (compiled on Windows).
#[cfg(target_os = "windows")]
pub fn run_live_capture(
    _interface: &str,
    _tx: crossbeam_channel::Sender<PacketEvent>,
    _running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err(
        "Live capture is not supported on Windows. Use PCAP file reading or mock capture instead."
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_null_scan_packet() {
        use etherparse::PacketBuilder;

        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([192, 168, 1, 10], [192, 168, 1, 1], 64)
            .tcp(12345, 80, 1000, 100);

        let mut payload = Vec::new();
        builder.write(&mut payload, &[]).unwrap();

        // Null scan: zero out TCP flags byte (byte index 47 in ethernet+ipv4+tcp)
        // Find TCP header start: Ethernet(14) + IPv4(20) = 34. Flags are at offset 13 from TCP header = 47.
        payload[47] = 0;

        let event = parse_packet(&payload, SystemTime::now()).expect("Packet should parse");
        assert_eq!(event.src_port, 12345);
        assert_eq!(event.dest_port, 80);
        assert_eq!(event.tcp_flags, Some(0));
        assert!(event.is_malformed());
    }

    #[test]
    fn test_parse_udp_packet() {
        use etherparse::PacketBuilder;

        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
            .udp(5353, 53);

        let mut payload = Vec::new();
        builder.write(&mut payload, &[1, 2, 3, 4]).unwrap();

        let event = parse_packet(&payload, SystemTime::now()).expect("UDP packet should parse");
        assert_eq!(event.protocol, 17);
        assert_eq!(event.src_port, 5353);
        assert_eq!(event.dest_port, 53);
        assert_eq!(event.tcp_flags, None);
        assert!(!event.is_malformed());
    }
}
