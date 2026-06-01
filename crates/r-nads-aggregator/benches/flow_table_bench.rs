use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::SystemTime;
use std::net::IpAddr;
use r_nads_common::PacketEvent;
use r_nads_aggregator::FlowTable;

fn bench_process_packet(c: &mut Criterion) {
    let mut table = FlowTable::new(10000);
    
    let ip1 = "10.0.0.1".parse::<IpAddr>().unwrap();
    let ip2 = "192.168.1.100".parse::<IpAddr>().unwrap();
    
    let event = PacketEvent {
        timestamp: SystemTime::now(),
        len: 128,
        src_ip: ip1,
        dest_ip: ip2,
        src_port: 1234,
        dest_port: 80,
        protocol: 6,
        tcp_flags: Some(0x02),
    };
    
    // Warm up and insert
    table.process_packet(&event);

    c.bench_function("process_packet_existing_flow", |b| {
        b.iter(|| {
            table.process_packet(black_box(&event));
        })
    });
}

criterion_group!(benches, bench_process_packet);
criterion_main!(benches);
