use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use etherparse::{SlicedPacket, InternetSlice, TransportSlice};
use r_nads_common::PacketEvent;

/// Zero-copy network packet parser.
/// Parses the ethernet, IP, and TCP/UDP/ICMP headers from raw bytes and
/// extracts a stateless `PacketEvent`.
#[inline]
pub fn parse_packet(packet_data: &[u8], timestamp: SystemTime) -> Option<PacketEvent> {
    let sliced = SlicedPacket::from_ethernet(packet_data).ok()?;

    let ip_slice = sliced.ip?;
    let (src_ip, dest_ip, protocol) = match ip_slice {
        InternetSlice::Ipv4(ipv4_slice, _) => {
            (
                IpAddr::V4(ipv4_slice.source_addr()),
                IpAddr::V4(ipv4_slice.destination_addr()),
                ipv4_slice.protocol(),
            )
        }
        InternetSlice::Ipv6(ipv6_slice, _) => {
            (
                IpAddr::V6(ipv6_slice.source_addr()),
                IpAddr::V6(ipv6_slice.destination_addr()),
                ipv6_slice.next_header(),
            )
        }
    };

    let (src_port, dest_port, tcp_flags) = match sliced.transport {
        Some(TransportSlice::Tcp(tcp_slice)) => {
            let mut flags = 0u8;
            if tcp_slice.fin() { flags |= 0x01; }
            if tcp_slice.syn() { flags |= 0x02; }
            if tcp_slice.rst() { flags |= 0x04; }
            if tcp_slice.psh() { flags |= 0x08; }
            if tcp_slice.ack() { flags |= 0x10; }
            if tcp_slice.urg() { flags |= 0x20; }
            (tcp_slice.source_port(), tcp_slice.destination_port(), Some(flags))
        }
        Some(TransportSlice::Udp(udp_slice)) => {
            (udp_slice.source_port(), udp_slice.destination_port(), None)
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
    })
}

/// Offline PCAP/PCAPNG file parser.
/// Reads packets from a file and pushes them into the sender channel.
pub fn run_pcap_file_capture(
    path: &str,
    tx: crossbeam_channel::Sender<PacketEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use pcap_file::pcap::PcapReader;

    let file = File::open(path)?;
    let mut reader = PcapReader::new(file)?;

    while let Some(packet) = reader.next_packet() {
        let packet = packet?;
        let timestamp = UNIX_EPOCH + packet.timestamp;
        if let Some(event) = parse_packet(&packet.data, timestamp) {
            if tx.send(event).is_err() {
                break; // channel disconnected
            }
        }
    }
    Ok(())
}

/// Mock traffic generator.
/// Generates realistic synthetic network traffic to benchmark the pipeline.
pub fn run_mock_capture(
    tx: crossbeam_channel::Sender<PacketEvent>,
    packets_per_sec: u64,
    num_ips: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::thread::sleep;
    use std::time::Duration;

    let mut count = 0u64;
    let _start_time = SystemTime::now();

    // Create a set of mock IPs
    let base_ip = 0x0A000000; // 10.0.0.0
    
    // We compute sleep interval. To handle very high packets_per_sec (like millions),
    // we send packets in batches to avoid timer overhead from sleeping too frequently.
    let batch_size = if packets_per_sec > 10_000 { 1000 } else { 1 };
    let sleep_dur = Duration::from_nanos(
        (1_000_000_000 * batch_size) / packets_per_sec
    );

    loop {
        let now = SystemTime::now();
        for _ in 0..batch_size {
            // Generate a deterministic IP pair based on packet index
            let src_offset = (count % num_ips as u64) as u32;
            let dest_offset = ((count / num_ips as u64) % num_ips as u64) as u32;
            
            let src_ip = IpAddr::V4(std::net::Ipv4Addr::from(base_ip + src_offset));
            let dest_ip = IpAddr::V4(std::net::Ipv4Addr::from(base_ip + dest_offset + 1000));
            
            // Alternating TCP/UDP
            let protocol = if count % 2 == 0 { 6 } else { 17 }; // TCP or UDP
            
            let (src_port, dest_port, tcp_flags) = if protocol == 6 {
                // HTTP/HTTPS mock ports
                let dest_port = if count % 3 == 0 { 80 } else { 443 };
                let src_port = (1024 + (count % 50000)) as u16;
                // Periodic SYN scan behavior (10% of TCP traffic)
                let flags = if count % 10 == 0 { Some(0x02) } else { Some(0x10) }; // SYN or ACK
                (src_port, dest_port, flags)
            } else {
                (53, (1024 + (count % 50000)) as u16, None) // DNS mock
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
            };

            if tx.send(event).is_err() {
                return Ok(()); // channel disconnected
            }
            count += 1;
        }

        // Sleep to throttle throughput
        sleep(sleep_dur);
    }
}

/// Live interface capture (compiled only on non-Windows targets).
#[cfg(not(target_os = "windows"))]
pub fn run_live_capture(
    interface: &str,
    tx: crossbeam_channel::Sender<PacketEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cap = pcap::Capture::from_device(interface)?
        .promisc(true)
        .snaplen(65535)
        .timeout(10)
        .open()?;
    
    // Convert to a stateful loop reading packets
    let mut cap = cap;
    while let Ok(packet) = cap.next_packet() {
        let timestamp = UNIX_EPOCH + std::time::Duration::new(
            packet.header.ts.tv_sec as u64,
            packet.header.ts.tv_usec as u32 * 1000,
        );
        if let Some(event) = parse_packet(packet.data, timestamp) {
            if tx.send(event).is_err() {
                break; // channel disconnected
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
) -> Result<(), Box<dyn std::error::Error>> {
    Err("Live capture is not supported on Windows. Use PCAP file reading or mock capture instead.".into())
}
