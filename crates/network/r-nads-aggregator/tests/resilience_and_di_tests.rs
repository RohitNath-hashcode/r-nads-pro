#![forbid(unsafe_code)]

use r_nads_aggregator::FlowTable;
use r_nads_common::{PacketEvent, PacketFlags};
use r_nads_decision::{MockTimeSource, TimeSource};
use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn test_mock_time_injection_in_flow_metrics() {
    let mock_time = MockTimeSource::new(1_000_000); // 1,000 seconds
    let mut table = FlowTable::new(100);

    let src_ip: IpAddr = "192.168.1.100".parse().unwrap();
    let dest_ip: IpAddr = "10.0.0.1".parse().unwrap();

    // Packet 1 at T = 1,000.000s
    let t1 = UNIX_EPOCH + Duration::from_millis(mock_time.current_timestamp_millis());
    let ev1 = PacketEvent {
        timestamp: t1,
        len: 100,
        src_ip,
        dest_ip,
        src_port: 4000,
        dest_port: 80,
        protocol: 6,
        tcp_flags: Some(0x02), // SYN
        flags: PacketFlags::default(),
    };
    table.process_packet(&ev1);

    // Advance mock time by 500ms
    mock_time.advance_millis(500);

    // Packet 2 at T = 1,000.500s
    let t2 = UNIX_EPOCH + Duration::from_millis(mock_time.current_timestamp_millis());
    let ev2 = PacketEvent {
        timestamp: t2,
        len: 200,
        src_ip,
        dest_ip,
        src_port: 4000,
        dest_port: 80,
        protocol: 6,
        tcp_flags: Some(0x10), // ACK
        flags: PacketFlags::default(),
    };
    let metrics = table.process_packet(&ev2);

    assert_eq!(metrics.packet_count, 2);
    assert!((metrics.mean_len - 150.0).abs() < 1e-4);
    // Interval between packets is exactly 500ms
    assert!((metrics.mean_interval - 500.0).abs() < 1e-4);
    // Packet rate: 2 packets over 0.5s = 4.0 packets/sec
    assert!((metrics.packet_rate - 4.0).abs() < 1e-4);
}

#[test]
fn test_volumetric_stress_and_strict_capacity_bounds() {
    let capacity = 500;
    let mut table = FlowTable::new(capacity);
    let now = UNIX_EPOCH + Duration::from_secs(100);

    // Ingest 50,000 packets across 2,500 distinct flows
    for i in 0..50_000 {
        let flow_id = (i % 2500) as u16;
        let event = PacketEvent {
            timestamp: now + Duration::from_millis(i as u64),
            len: 64 + (i % 500) as u32,
            src_ip: format!("10.0.{}.{}", flow_id / 256, flow_id % 256)
                .parse()
                .unwrap(),
            dest_ip: "192.168.1.1".parse().unwrap(),
            src_port: 1024 + flow_id,
            dest_port: 443,
            protocol: 6,
            tcp_flags: Some(0x10),
            flags: PacketFlags::default(),
        };

        table.process_packet(&event);

        // Assert memory constraint is NEVER violated at any iteration
        assert!(
            table.len() <= capacity,
            "Table length must never exceed capacity limit"
        );
    }

    assert_eq!(table.len(), capacity);
    assert!((table.load_factor() - 1.0).abs() < 1e-6);
    assert!(
        table.total_evictions > 0,
        "Total evictions must reflect LRU shedding"
    );
}

#[test]
fn test_stale_flow_eviction_and_emergency_shed() {
    let mut table = FlowTable::new(10);
    let base_time_ms = 1_000_000;

    // Insert 5 older flows at T = base_time_ms
    for i in 0..5 {
        let ev = PacketEvent {
            timestamp: UNIX_EPOCH + Duration::from_millis(base_time_ms),
            len: 64,
            src_ip: format!("10.0.0.{}", i + 1).parse().unwrap(),
            dest_ip: "192.168.1.1".parse().unwrap(),
            src_port: 1000 + i as u16,
            dest_port: 80,
            protocol: 6,
            tcp_flags: Some(0x02),
            flags: PacketFlags::default(),
        };
        table.process_packet(&ev);
    }

    // Insert 5 newer flows at T = base_time_ms + 10,000ms (10 seconds later)
    for i in 5..10 {
        let ev = PacketEvent {
            timestamp: UNIX_EPOCH + Duration::from_millis(base_time_ms + 10_000),
            len: 64,
            src_ip: format!("10.0.0.{}", i + 1).parse().unwrap(),
            dest_ip: "192.168.1.1".parse().unwrap(),
            src_port: 1000 + i as u16,
            dest_port: 80,
            protocol: 6,
            tcp_flags: Some(0x02),
            flags: PacketFlags::default(),
        };
        table.process_packet(&ev);
    }

    assert_eq!(table.len(), 10);

    // Shed flows older than 5,000ms at current time base_time_ms + 10,000ms
    let shed = table.shed_stale_flows(5_000, base_time_ms + 10_000);
    assert_eq!(shed, 5, "The 5 older flows must be shed");
    assert_eq!(table.len(), 5);

    // Emergency shed 3 more
    let em_shed = table.emergency_shed(3);
    assert_eq!(em_shed, 3);
    assert_eq!(table.len(), 2);
}
