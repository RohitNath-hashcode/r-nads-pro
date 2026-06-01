use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::net::IpAddr;
use std::time::SystemTime;

use r_nads::analysis::aggregator::{FlowKey, FlowMetrics, FlowTable, PacketEvent};
use r_nads::ml::svdd::{InferenceEngine, ModelConfig, MODEL_CONFIG};

fn setup_benchmark_model() {
    let _ = MODEL_CONFIG.set(ModelConfig {
        threshold: 1.5,
        means: [
            100.0, 10.0, 1000.0, 10000.0, 1.0, 0.1, 0.05, 0.05, 0.1, 0.8, 50.0, 10.0,
        ],
        stddevs: [
            10.0, 2.0, 100.0, 1000.0, 0.2, 0.05, 0.01, 0.01, 0.05, 0.1, 10.0, 5.0,
        ],
        centroid: [0.05; 256],
        b_vector: [0.1; 256],
        w_matrix: [[0.02; 12]; 256],
    });
}

fn bench_flow_table(c: &mut Criterion) {
    let mut table = FlowTable::new(65536);

    let src_ip = "192.168.1.1".parse::<IpAddr>().unwrap();
    let dest_ip = "10.0.0.1".parse::<IpAddr>().unwrap();

    let event = PacketEvent {
        timestamp: SystemTime::now(),
        len: 128,
        src_ip,
        dest_ip,
        src_port: 4567,
        dest_port: 80,
        protocol: 6,
        tcp_flags: Some(0x02), // SYN
    };

    // Pre-populate flow table slightly to warm up Slab/HashMap
    for i in 0..100 {
        let mut ev = event.clone();
        ev.src_port = 1000 + i;
        table.process_packet(&ev);
    }

    c.bench_function("flow_table_process_packet", |b| {
        let mut idx = 0u16;
        b.iter(|| {
            let mut ev = event.clone();
            // Alternate ports to hit existing/new flow entries
            ev.src_port = 1000 + (idx % 100);
            idx = idx.wrapping_add(1);
            table.process_packet(black_box(&ev));
        })
    });
}

fn bench_inference(c: &mut Criterion) {
    setup_benchmark_model();

    let metrics = FlowMetrics {
        src_ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
        dest_ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
        src_port: 4567,
        dest_port: 80,
        protocol: 6,
        key: FlowKey::new(
            "192.168.1.1".parse::<IpAddr>().unwrap(),
            4567,
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            80,
            6,
        ),
        packet_count: 50,
        mean_len: 250.0,
        var_len: 1500.0,
        packet_rate: 150.0,
        byte_rate: 37500.0,
        fwd_bwd_ratio: 1.5,
        syn_ratio: 0.1,
        rst_ratio: 0.05,
        fin_ratio: 0.02,
        psh_ratio: 0.2,
        ack_ratio: 0.8,
        mean_interval: 12.5,
        var_interval: 4.2,
    };

    c.bench_function("inference_predict", |b| {
        b.iter(|| InferenceEngine::predict(black_box(&metrics)))
    });
}

criterion_group!(benches, bench_flow_table, bench_inference);
criterion_main!(benches);
