use std::thread;
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use clap::Parser;
use crossbeam_channel::{bounded, unbounded};
use ahash::AHasher;
use std::hash::{Hash, Hasher};
use std::fs::File;

use r_nads_common::{PacketEvent, AnomalyAlert};
use r_nads_producer::{run_mock_capture, run_pcap_file_capture, run_live_capture};
use r_nads_aggregator::{FlowTable, FlowMetrics};
use r_nads_inference::{InferenceEngine, ModelConfig};

#[derive(Parser, Debug)]
#[command(name = "R-NADS")]
#[command(version = "0.1.0")]
#[command(about = "Rust-based Network Anomaly Detection System", long_about = None)]
struct Args {
    /// Operation mode: 'mock', 'pcap', 'live', or 'train'
    #[arg(short, long, default_value = "mock")]
    mode: String,

    /// Target packets per second (for mock/train mode)
    #[arg(long, default_value = "10000")]
    pps: u64,

    /// Number of mock active IPs (for mock/train mode)
    #[arg(long, default_value = "1000")]
    flows: u32,

    /// Path to input PCAP/PCAPNG file (for pcap or train-pcap mode)
    #[arg(short, long)]
    pcap_file: Option<String>,

    /// Network interface name (for live mode)
    #[arg(short, long)]
    interface: Option<String>,

    /// Number of aggregator threads
    #[arg(short, long, default_value = "4")]
    workers: usize,

    /// Total capacity of active flows across all tables
    #[arg(short, long, default_value = "65536")]
    capacity: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("=== R-NADS: Initializing Phases A, B & C ===");
    println!("Mode: {}", args.mode);
    println!("Aggregator Workers: {}", args.workers);
    println!("Flow Capacity Limit: {}", args.capacity);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\n[System] Shutdown signal received. Stopping threads...");
        r.store(false, Ordering::SeqCst);
    })?;

    // Performance counters
    let packet_counter = Arc::new(AtomicU64::new(0));
    let latency_sum_us = Arc::new(AtomicU64::new(0));

    // Create aggregator channels
    let mut worker_txs = Vec::new();
    let mut worker_threads = Vec::new();

    // Spawn Aggregator Threads (Phase B)
    let worker_capacity = args.capacity / args.workers;
    let (inference_tx, inference_rx) = unbounded::<FlowMetrics>();

    for i in 0..args.workers {
        let (tx, rx) = bounded::<PacketEvent>(10000);
        worker_txs.push(tx);

        let inf_tx = inference_tx.clone();
        let running_flag = running.clone();
        
        let thread_handle = thread::Builder::new()
            .name(format!("aggregator-{}", i))
            .spawn(move || {
                let mut flow_table = FlowTable::new(worker_capacity);
                println!("[Aggregator-{}] Thread started. Capacity: {}", i, worker_capacity);

                while running_flag.load(Ordering::SeqCst) {
                    if let Ok(event) = rx.recv_timeout(Duration::from_millis(50)) {
                        let metrics = flow_table.process_packet(&event);
                        let _ = inf_tx.send(metrics);
                    }
                }
                println!("[Aggregator-{}] Thread exiting. Final flow count: {}", i, flow_table.len());
            })?;
        
        worker_threads.push(thread_handle);
    }
    drop(inference_tx); // Drop original sender so channel closes when all workers exit

    // Spawn Ingestion/Producer Thread (Phase A)
    let (producer_tx, producer_rx) = bounded::<PacketEvent>(20000);
    
    // In training mode, we run PCAP capture if pcap_file is provided, otherwise fallback to mock capture
    let capture_mode = if args.mode == "train" {
        if args.pcap_file.is_some() { "pcap".to_string() } else { "mock".to_string() }
    } else {
        args.mode.clone()
    };

    let pps = args.pps;
    let flows = args.flows;
    let pcap_file = args.pcap_file.clone();
    let interface = args.interface.clone();
    let running_flag = running.clone();

    let producer_thread = thread::Builder::new()
        .name("producer".to_string())
        .spawn(move || {
            println!("[Producer] Ingestion thread started (Capture Mode: {}).", capture_mode);
            let result = match capture_mode.as_str() {
                "mock" => {
                    println!("[Producer] Running Mock Traffic: {} PPS, {} flows", pps, flows);
                    run_mock_capture(producer_tx, pps, flows)
                }
                "pcap" => {
                    if let Some(path) = pcap_file {
                        println!("[Producer] Reading from PCAP file: {}", path);
                        run_pcap_file_capture(&path, producer_tx)
                    } else {
                        Err("Error: PCAP file path must be specified with --pcap-file in pcap mode.".into())
                    }
                }
                "live" => {
                    if let Some(iface) = interface {
                        println!("[Producer] Capturing live traffic on interface: {}", iface);
                        run_live_capture(&iface, producer_tx)
                    } else {
                        Err("Error: Interface name must be specified with --interface in live mode.".into())
                    }
                }
                _ => Err(format!("Unknown capture mode: {}", capture_mode).into()),
            };

            if let Err(e) = result {
                eprintln!("[Producer] Ingestion stopped due to error: {}", e);
            }
            running_flag.store(false, Ordering::SeqCst);
            println!("[Producer] Thread exiting.");
        })?;

    // Spawn Router/Stats Thread (Orchestrator)
    let rx_c = producer_rx.clone();
    let tx_channels = worker_txs.clone();
    let num_workers = args.workers;
    let running_flag = running.clone();
    let pkt_count = packet_counter.clone();
    let lat_sum = latency_sum_us.clone();

    let router_thread = thread::Builder::new()
        .name("router".to_string())
        .spawn(move || {
            println!("[Router] Routing thread started.");
            while running_flag.load(Ordering::SeqCst) {
                if let Ok(event) = rx_c.recv_timeout(Duration::from_millis(50)) {
                    let start_route = Instant::now();
                    
                    // Route packets using symmetric hashing of FlowKey
                    let key = event.flow_key();
                    let mut hasher = AHasher::default();
                    key.hash(&mut hasher);
                    let hash = hasher.finish();
                    let worker_idx = (hash % num_workers as u64) as usize;

                    if tx_channels[worker_idx].send(event).is_ok() {
                        pkt_count.fetch_add(1, Ordering::Relaxed);
                        let elapsed_us = start_route.elapsed().as_micros() as u64;
                        lat_sum.fetch_add(elapsed_us, Ordering::Relaxed);
                    }
                }
            }
            println!("[Router] Thread exiting.");
        })?;

    // ----------------------------------------------------
    // Branch Execution: Training Mode vs. Normal Classifier Mode
    // ----------------------------------------------------
    if args.mode == "train" {
        // Collect 2000 normal traffic baseline metrics to train the model
        let target_samples = 2000;
        println!("[Trainer] Starting baseline collection. Gathering {} samples...", target_samples);
        let mut samples = Vec::with_capacity(target_samples);
        let collect_start = Instant::now();

        while running.load(Ordering::SeqCst) && samples.len() < target_samples {
            if let Ok(metrics) = inference_rx.recv_timeout(Duration::from_millis(100)) {
                samples.push(metrics);
                if samples.len() % 500 == 0 {
                    println!("[Trainer] Collected {}/{} samples...", samples.len(), target_samples);
                }
            }
        }

        if samples.len() >= target_samples {
            println!("[Trainer] Collection complete in {:.2}s. Training model...", collect_start.elapsed().as_secs_f64());
            train_and_save_model(&samples)?;
            println!("[Trainer] Model config saved successfully to model_config.json.");
        } else {
            println!("[Trainer] Collection aborted or interrupted. Insufficient samples.");
        }

        // Shut down the system
        running.store(false, Ordering::SeqCst);
        
        // Join threads
        let _ = producer_thread.join();
        let _ = router_thread.join();
        for thread in worker_threads {
            let _ = thread.join();
        }

        println!("=== R-NADS: Training Mode Stopped ===");
        Ok(())
    } else {
        // Load the trained model config
        let model_config = match File::open("model_config.json") {
            Ok(file) => {
                println!("[Inference] Loaded model configuration from model_config.json");
                serde_json::from_reader(file)?
            }
            Err(_) => {
                println!("[Warning] model_config.json not found! Running with fallback default baseline config.");
                get_fallback_config()
            }
        };

        let engine = Arc::new(InferenceEngine::new(model_config));
        let (alert_tx, alert_rx) = unbounded::<AnomalyAlert>();

        // Spawn Inference Worker Thread (Phase C)
        let running_flag = running.clone();
        let eng_c = engine.clone();
        let a_tx = alert_tx.clone();

        let inference_thread = thread::Builder::new()
            .name("inference".to_string())
            .spawn(move || {
                println!("[Inference] Engine thread started.");
                let mut total_inferences = 0u64;

                while running_flag.load(Ordering::SeqCst) {
                    if let Ok(metrics) = inference_rx.recv_timeout(Duration::from_millis(50)) {
                        total_inferences += 1;
                        let res = eng_c.predict(&metrics);
                        
                        if res.is_anomaly {
                            let alert = eng_c.create_alert(&metrics, &res);
                            let _ = a_tx.send(alert);
                        }

                        // Periodic debug output for inference
                        if total_inferences % 50000 == 0 {
                            println!(
                                "[Inference] Evaluated {} flow windows. Last distance: {:.4}",
                                total_inferences, res.distance
                            );
                        }
                    }
                }
                println!("[Inference] Thread exiting. Total metric windows evaluated: {}", total_inferences);
            })?;

        // Spawn Monitor/Health and Alerting Thread (Thread 4)
        let running_flag = running.clone();
        let pkt_count = packet_counter.clone();
        let lat_sum = latency_sum_us.clone();

        let monitor_thread = thread::Builder::new()
            .name("monitor".to_string())
            .spawn(move || {
                println!("[Monitor] Health and Alert reporter started.");
                let mut last_time = Instant::now();
                let mut last_packets = 0u64;

                while running_flag.load(Ordering::SeqCst) {
                    // Check for real-time alerts
                    if let Ok(alert) = alert_rx.recv_timeout(Duration::from_millis(20)) {
                        println!(
                            "\n[Monitor] !!! ANOMALY DETECTED !!!\n\
                             Flow: {} -> {}\n\
                             Distance: {:.4} (Threshold: {:.4})\n\
                             Stats: Pkts/sec: {:.1}, Byte/sec: {:.1}, Fwd-Bwd ratio: {:.2}, SYN ratio: {:.2}\n",
                            alert.key.ip_min, alert.key.ip_max, alert.score, alert.threshold,
                            alert.packet_rate, alert.byte_rate, alert.fwd_bwd_ratio, alert.syn_ratio
                        );
                    }

                    // Periodically output system health report
                    let now = Instant::now();
                    if now.duration_since(last_time).as_secs() >= 2 {
                        let elapsed_sec = now.duration_since(last_time).as_secs_f64();
                        let current_packets = pkt_count.load(Ordering::Relaxed);
                        let packets_diff = current_packets - last_packets;
                        let throughput = packets_diff as f64 / elapsed_sec;

                        let sum_us = lat_sum.load(Ordering::Relaxed);
                        let avg_latency = if current_packets > 0 {
                            (sum_us as f64) / (current_packets as f64)
                        } else {
                            0.0
                        };

                        println!(
                            "[Monitor] Health Status: Throughput = {:.1} pps, Avg Routing Latency = {:.3} us, Total Packets = {}",
                            throughput, avg_latency, current_packets
                        );

                        last_time = now;
                        last_packets = current_packets;
                    }
                }
                println!("[Monitor] Thread exiting.");
            })?;

        // Wait for shutdown signal
        while running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100));
        }

        // Join all threads
        let _ = producer_thread.join();
        let _ = router_thread.join();
        for thread in worker_threads {
            let _ = thread.join();
        }
        let _ = inference_thread.join();
        let _ = monitor_thread.join();

        println!("=== R-NADS: Phases A, B & C Stopped ===");
        Ok(())
    }
}

/// Trains the model by calculating the baseline statistics, drawing random matrix projections (RFF),
/// computing the hypersphere mean weight, and setting the anomaly distance threshold.
fn train_and_save_model(samples: &[FlowMetrics]) -> Result<(), Box<dyn std::error::Error>> {
    let n = samples.len();
    if n == 0 {
        return Err("Cannot train on empty samples".into());
    }

    // 1. Calculate means
    let mut means = [0.0; 6];
    for s in samples {
        let x = [
            s.mean_len,
            s.var_len.sqrt(),
            s.packet_rate,
            s.byte_rate,
            s.fwd_bwd_ratio,
            s.syn_ratio,
        ];
        for i in 0..6 {
            means[i] += x[i];
        }
    }
    for i in 0..6 {
        means[i] /= n as f64;
    }

    // 2. Calculate standard deviations
    let mut stddevs = [0.0; 6];
    for s in samples {
        let x = [
            s.mean_len,
            s.var_len.sqrt(),
            s.packet_rate,
            s.byte_rate,
            s.fwd_bwd_ratio,
            s.syn_ratio,
        ];
        for i in 0..6 {
            let diff = x[i] - means[i];
            stddevs[i] += diff * diff;
        }
    }
    for i in 0..6 {
        stddevs[i] = (stddevs[i] / n as f64).sqrt().max(1e-7);
    }

    // 3. Setup LCG Random Generator for reproducible projection space (RFF parameters)
    struct SimpleRand {
        state: u64,
    }
    impl SimpleRand {
        fn next_f64(&mut self) -> f64 {
            self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (self.state >> 11) as f64 / (1u64 << 53) as f64
        }
        fn next_gaussian(&mut self) -> f64 {
            let u1 = self.next_f64().max(1e-15);
            let u2 = self.next_f64();
            (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
        }
    }
    let mut rng = SimpleRand { state: 1337 };

    let projection_dim = 128;
    let gamma: f64 = 0.5; // RBF kernel approximation scale
    let std_dev_proj = (2.0 * gamma).sqrt();

    let mut w_matrix = vec![vec![0.0; 6]; projection_dim];
    let mut b_vector = vec![0.0; projection_dim];

    for j in 0..projection_dim {
        for i in 0..6 {
            w_matrix[j][i] = rng.next_gaussian() * std_dev_proj;
        }
        b_vector[j] = rng.next_f64() * 2.0 * std::f64::consts::PI;
    }

    // 4. Project samples to RFF space
    let mut phi_matrix = vec![vec![0.0; projection_dim]; n];
    let scale = (2.0 / projection_dim as f64).sqrt();

    for k in 0..n {
        let s = &samples[k];
        let x = [
            s.mean_len,
            s.var_len.sqrt(),
            s.packet_rate,
            s.byte_rate,
            s.fwd_bwd_ratio,
            s.syn_ratio,
        ];
        
        let mut z = [0.0; 6];
        for i in 0..6 {
            z[i] = (x[i] - means[i]) / stddevs[i];
        }

        for j in 0..projection_dim {
            let mut proj = 0.0;
            for i in 0..6 {
                proj += w_matrix[j][i] * z[i];
            }
            proj += b_vector[j];
            phi_matrix[k][j] = scale * proj.cos();
        }
    }

    // 5. Compute SVDD center (average projection vector of normal samples)
    let mut w_center = vec![0.0; projection_dim];
    for k in 0..n {
        for j in 0..projection_dim {
            w_center[j] += phi_matrix[k][j];
        }
    }
    for j in 0..projection_dim {
        w_center[j] /= n as f64;
    }

    let weights_norm_sq: f64 = w_center.iter().map(|v| v * v).sum();

    // 6. Compute distances for all training samples and set threshold
    let mut distances_sq = vec![0.0; n];
    for k in 0..n {
        let mut w_dot_phi = 0.0;
        for j in 0..projection_dim {
            w_dot_phi += w_center[j] * phi_matrix[k][j];
        }
        distances_sq[k] = (1.0 - 2.0 * w_dot_phi + weights_norm_sq).max(0.0);
    }

    // Sort to find the 95th percentile
    distances_sq.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let threshold_idx = (n as f64 * 0.95) as usize;
    let threshold = distances_sq[threshold_idx.min(n - 1)];

    println!("[Trainer] Baseline training statistics:");
    println!("  - Mean distance: {:.6}", (distances_sq.iter().sum::<f64>() / n as f64).sqrt());
    println!("  - 95th percentile (threshold) distance: {:.6}", threshold.sqrt());

    // Save model config
    let config = ModelConfig {
        projection_dim,
        means,
        stddevs,
        w_matrix,
        b_vector,
        weights: w_center,
        weights_norm_sq,
        threshold,
    };

    let file = File::create("model_config.json")?;
    serde_json::to_writer_pretty(file, &config)?;
    Ok(())
}

/// Fallback helper to generate a default baseline configuration.
fn get_fallback_config() -> ModelConfig {
    let projection_dim = 128;
    let means = [100.0, 10.0, 1000.0, 10000.0, 1.0, 0.1];
    let stddevs = [10.0, 2.0, 100.0, 1000.0, 0.2, 0.05];
    let w_matrix = vec![vec![0.05; 6]; projection_dim];
    let b_vector = vec![0.1; projection_dim];
    let weights = vec![0.0; projection_dim];
    let weights_norm_sq = weights.iter().map(|v| v * v).sum();
    
    // Fallback threshold
    let threshold = 1.5; 
    
    ModelConfig {
        projection_dim,
        means,
        stddevs,
        w_matrix,
        b_vector,
        weights,
        weights_norm_sq,
        threshold,
    }
}
