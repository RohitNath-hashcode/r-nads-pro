#![forbid(unsafe_code)]

use etherparse::PacketBuilder;
use r_nads_producer::parse_packet;
use std::time::SystemTime;

#[test]
fn test_truncated_packets_zero_panics() {
    let now = SystemTime::now();

    // 0 bytes
    assert!(parse_packet(&[], now).is_none());

    // Sub-ethernet lengths (1 to 13 bytes)
    for len in 1..14 {
        let dummy = vec![0x42u8; len];
        assert!(parse_packet(&dummy, now).is_none());
    }

    // Ethernet header only (14 bytes)
    let eth_only = vec![0x00; 14];
    assert!(parse_packet(&eth_only, now).is_none());

    // Incomplete IP header (15 to 33 bytes)
    for len in 15..34 {
        let dummy = vec![0x45u8; len];
        let _ = parse_packet(&dummy, now); // must not panic
    }
}

#[test]
fn test_stealth_scan_anomalies_detected() {
    let now = SystemTime::now();

    // Helper to generate a packet and mutate TCP flags
    let make_packet = |flag_byte: u8| -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(12345, 80, 100, 100);

        let mut payload = Vec::new();
        builder.write(&mut payload, &[]).unwrap();
        // Ethernet(14) + IPv4(20) = 34. TCP flags byte is offset 13 from TCP header -> index 47.
        payload[47] = flag_byte;
        payload
    };

    // 1. NULL Scan (flags == 0x00)
    let null_pkt = make_packet(0x00);
    let event = parse_packet(&null_pkt, now).expect("Should parse");
    assert!(
        event.is_malformed(),
        "NULL scan must be flagged as malformed"
    );

    // 2. SYN+FIN Scan (flags == 0x03)
    let syn_fin_pkt = make_packet(0x03);
    let event = parse_packet(&syn_fin_pkt, now).expect("Should parse");
    assert!(
        event.is_malformed(),
        "SYN+FIN scan must be flagged as malformed"
    );

    // 3. SYN+RST Scan (flags == 0x06)
    let syn_rst_pkt = make_packet(0x06);
    let event = parse_packet(&syn_rst_pkt, now).expect("Should parse");
    assert!(
        event.is_malformed(),
        "SYN+RST scan must be flagged as malformed"
    );

    // 4. XMAS Scan (FIN+PSH+URG = 0x29)
    let xmas_pkt = make_packet(0x29);
    let event = parse_packet(&xmas_pkt, now).expect("Should parse");
    assert!(
        event.is_malformed(),
        "XMAS scan must be flagged as malformed"
    );

    // 5. Normal SYN (flags == 0x02)
    let syn_pkt = make_packet(0x02);
    let event = parse_packet(&syn_pkt, now).expect("Should parse");
    assert!(!event.is_malformed(), "Normal SYN must not be malformed");

    // 6. Normal ACK (flags == 0x10)
    let ack_pkt = make_packet(0x10);
    let event = parse_packet(&ack_pkt, now).expect("Should parse");
    assert!(!event.is_malformed(), "Normal ACK must not be malformed");
}

#[test]
fn test_ipv4_fragmentation_detection() {
    let now = SystemTime::now();

    // Create IPv4 packet with more_fragments bit set
    let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .udp(1234, 5678);

    let mut payload = Vec::new();
    builder.write(&mut payload, &[0xAA; 32]).unwrap();

    // Mutate IPv4 flags/fragment offset (offset 20: flags/offset high byte)
    // Flags are top 3 bits: 0x20 = More Fragments
    payload[20] |= 0x20;

    let event = parse_packet(&payload, now).expect("Fragment packet should parse");
    assert!(
        event.is_fragment(),
        "Packet with More Fragments flag must be detected as fragment"
    );
}

#[test]
fn test_pseudo_random_byte_fuzzing() {
    let now = SystemTime::now();

    // Deterministic LCG pseudo-random generator
    struct Lcg {
        state: u64,
    }
    impl Lcg {
        fn next_u8(&mut self) -> u8 {
            self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (self.state >> 33) as u8
        }
    }

    let mut rng = Lcg { state: 0xDEADBEEF };

    // Fuzz 1,000 iterations of random sizes up to 1500 bytes
    for i in 0..1000 {
        let size = (i % 1500) as usize;
        let mut data = vec![0u8; size];
        for b in &mut data {
            *b = rng.next_u8();
        }

        // Must NEVER panic on arbitrary byte inputs
        let _ = parse_packet(&data, now);
    }
}
