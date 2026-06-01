use ahash::AHasher;
use clap::Parser;
use crossbeam_channel::{bounded, unbounded};
use dashmap::DashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use r_nads::analysis::aggregator::{FlowMetrics, FlowTable, PacketEvent};
use r_nads::capture::{run_live_capture, run_mock_capture, run_pcap_file_capture};
use r_nads::mitigation::nginx::run_mitigation_server;
use r_nads::ml::svdd::{AnomalyAlert, InferenceEngine, ModelConfig, MODEL_CONFIG};
use r_nads::{AppConfig, SystemConfig};

/// R-NADS CLI Arguments
#[derive(Parser, Debug)]
#[command(name = "R-NADS")]
#[command(version = "0.1.0")]
#[command(about = "Rust-based Network Anomaly Detection System")]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Overrides the execution mode ('train' or 'classify')
    #[arg(short, long)]
    mode: Option<String>,
}

// Shared configuration structures are imported from the library.

#[allow(clippy::manual_is_multiple_of)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("=== R-NADS: Rust Network Anomaly Detection System ===");

    // 1. Load and parse config.toml
    let config_content = std::fs::read_to_string(&args.config)
        .map_err(|e| format!("Could not read configuration file '{}': {}", args.config, e))?;
    let mut app_config: AppConfig = toml::from_str(&config_content).map_err(|e| {
        format!(
            "Failed to parse configuration file '{}': {}",
            args.config, e
        )
    })?;

    // Override mode if specified via CLI arguments
    if let Some(ref m) = args.mode {
        app_config.system.mode = m.clone();
    }

    // 2. Setup shutdown handling
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\n[System] Shutdown signal received. Gracefully terminating threads...");
        r.store(false, Ordering::SeqCst);
    })?;

    let initial_mode = app_config.system.mode.clone();
    println!("Initial Mode: {}", initial_mode);
    println!("Configuration path: {}", args.config);
    println!("Workers: {}", app_config.system.workers);
    println!("Flow capacity limit: {}", app_config.system.capacity);
    println!("Mitigation Mode: {}", app_config.system.mitigation_mode);

    // Initialize shared dynamic configuration
    let shared_config = Arc::new(std::sync::RwLock::new(app_config.system.clone()));

    // Spawn Config Watcher Thread (watches config.toml for dynamic reloads)
    let config_path = args.config.clone();
    let config_watcher_cfg = shared_config.clone();
    let running_flag_watcher = running.clone();

    let watcher_thread = thread::Builder::new()
        .name("config-watcher".to_string())
        .spawn(move || {
            let mut last_metadata = std::fs::metadata(&config_path)
                .and_then(|m| m.modified())
                .unwrap_or_else(|_| std::time::SystemTime::now());

            println!("[Watcher] Configuration watcher started for '{}'.", config_path);

            while running_flag_watcher.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(2));

                if let Ok(metadata) = std::fs::metadata(&config_path) {
                    if let Ok(modified) = metadata.modified() {
                        if modified > last_metadata {
                            last_metadata = modified;
                            println!("[Watcher] Configuration file modification detected. Reloading...");

                            match std::fs::read_to_string(&config_path) {
                                Ok(content) => {
                                    match toml::from_str::<AppConfig>(&content) {
                                        Ok(new_app_cfg) => {
                                            let mut write_lock = config_watcher_cfg.write().unwrap();
                                            *write_lock = new_app_cfg.system;
                                            println!(
                                                "[Watcher] Configuration reloaded successfully. Mitigation Mode: {}, TTL: {}s",
                                                write_lock.mitigation_mode, write_lock.block_list_ttl
                                            );
                                        }
                                        Err(e) => {
                                            eprintln!("[Watcher] Failed to parse configuration file during reload: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[Watcher] Failed to read configuration file during reload: {}", e);
                                }
                            }
                        }
                    }
                }
            }
            println!("[Watcher] Configuration watcher thread exiting.");
        })?;

    // Performance counters
    let packet_counter = Arc::new(AtomicU64::new(0));
    let latency_sum_us = Arc::new(AtomicU64::new(0));

    // Create worker channels
    let mut worker_txs = Vec::new();
    let mut worker_threads = Vec::new();

    // Spawn Aggregator Workers (Phase B)
    let worker_capacity = app_config.system.capacity / app_config.system.workers;
    let (inference_tx, inference_rx) = unbounded::<FlowMetrics>();

    for i in 0..app_config.system.workers {
        let (tx, rx) = bounded::<PacketEvent>(20000);
        worker_txs.push(tx);

        let inf_tx = inference_tx.clone();
        let running_flag = running.clone();

        let thread_handle = thread::Builder::new()
            .name(format!("aggregator-{}", i))
            .spawn(move || {
                let mut flow_table = FlowTable::new(worker_capacity);
                println!(
                    "[Aggregator-{}] Thread spawned. Slot capacity: {}",
                    i, worker_capacity
                );

                while running_flag.load(Ordering::SeqCst) {
                    if let Ok(event) = rx.recv_timeout(Duration::from_millis(50)) {
                        let metrics = flow_table.process_packet(&event);
                        let _ = inf_tx.send(metrics);
                    }
                }
                println!(
                    "[Aggregator-{}] Thread exiting. Active flows: {}",
                    i,
                    flow_table.len()
                );
            })?;

        worker_threads.push(thread_handle);
    }
    drop(inference_tx); // Drop extra sender so channel closes when all workers exit

    // Spawn Ingestion/Producer Thread (Phase A)
    let (producer_tx, producer_rx) = bounded::<PacketEvent>(30000);
    let capture_source = app_config.system.capture_source.clone();
    let pps = app_config.system.pps;
    let flows = app_config.system.flows;
    let pcap_file = app_config.system.pcap_file.clone();
    let interface = app_config.system.interface.clone();
    let running_flag = running.clone();

    let producer_thread = thread::Builder::new()
        .name("producer".to_string())
        .spawn(move || {
            println!("[Producer] Capture source: {}", capture_source);
            let result = match capture_source.as_str() {
                "mock" => {
                    println!("[Producer] Generating Synthetic Traffic: {} PPS, {} active flows", pps, flows);
                    run_mock_capture(producer_tx, pps, flows, running_flag.clone())
                }
                "pcap" => {
                    if let Some(path) = pcap_file {
                        println!("[Producer] Reading from file: {}", path);
                        run_pcap_file_capture(&path, producer_tx)
                    } else {
                        Err("Error: pcap_file path must be specified in config.toml for pcap capture source.".into())
                    }
                }
                "live" => {
                    if let Some(iface) = interface {
                        println!("[Producer] Sniffing live on: {}", iface);
                        run_live_capture(&iface, producer_tx, running_flag.clone())
                    } else {
                        Err("Error: interface must be specified in config.toml for live capture source.".into())
                    }
                }
                _ => Err(format!("Unknown capture source: {}", capture_source).into()),
            };

            if let Err(e) = result {
                eprintln!("[Producer] Capture stopped with error: {}", e);
            }
            running_flag.store(false, Ordering::SeqCst);
            println!("[Producer] Thread exiting.");
        })?;

    // Spawn Router Thread
    let rx_c = producer_rx.clone();
    let tx_channels = worker_txs.clone();
    let num_workers = app_config.system.workers;
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
    // Unified Pipeline: Auto-Training & Classification
    // ----------------------------------------------------
    let mut classification_threads = Vec::new();

    let model_path = app_config.system.model_path.clone();
    let mut loaded_model = None;

    if std::path::Path::new(&model_path).exists() {
        match std::fs::read_to_string(&model_path) {
            Ok(json_content) => match serde_json::from_str::<ModelConfig>(&json_content) {
                Ok(model_cfg) => {
                    println!(
                        "[Inference] Loaded pretrained Model Config from '{}'.",
                        model_path
                    );
                    loaded_model = Some(model_cfg);
                }
                Err(e) => {
                    eprintln!(
                        "[Inference] Failed to parse model file '{}': {}. Re-training model...",
                        model_path, e
                    );
                }
            },
            Err(e) => {
                eprintln!(
                    "[Inference] Failed to read model file '{}': {}. Re-training model...",
                    model_path, e
                );
            }
        }
    }

    if let Some(model_cfg) = loaded_model {
        MODEL_CONFIG
            .set(model_cfg)
            .map_err(|_| "OnceLock MODEL_CONFIG already initialized")?;

        classification_threads = start_classification_pipeline(
            shared_config.clone(),
            inference_rx,
            running.clone(),
            packet_counter.clone(),
            latency_sum_us.clone(),
        )?;
    } else {
        println!(
            "[Trainer] No model file found or parse failed. Starting auto-training baseline collection..."
        );
        let target_samples = app_config.system.training_samples;
        println!(
            "[Trainer] Gathering {} samples from live network interfaces...",
            target_samples
        );

        let mut samples = Vec::with_capacity(target_samples);
        let collect_start = Instant::now();

        while running.load(Ordering::SeqCst) && samples.len() < target_samples {
            if let Ok(metrics) = inference_rx.recv_timeout(Duration::from_millis(100)) {
                samples.push(metrics);
                if samples.len() % 1000 == 0 {
                    println!(
                        "[Trainer] Collected {}/{} samples...",
                        samples.len(),
                        target_samples
                    );
                }
            }
        }

        if samples.len() >= target_samples {
            println!(
                "[Trainer] Collection complete in {:.2}s. Training SVDD Model...",
                collect_start.elapsed().as_secs_f64()
            );
            let trained_model = train_model(&samples)?;

            // Save trained model to JSON file
            let json_string = serde_json::to_string_pretty(&trained_model)?;
            std::fs::write(&model_path, json_string)?;
            println!(
                "[Trainer] Model parameters written back to '{}'.",
                model_path
            );

            MODEL_CONFIG
                .set(trained_model)
                .map_err(|_| "OnceLock MODEL_CONFIG already initialized")?;
            println!("[Inference] SVDD Hypersphere Model initialized.");

            classification_threads = start_classification_pipeline(
                shared_config.clone(),
                inference_rx,
                running.clone(),
                packet_counter.clone(),
                latency_sum_us.clone(),
            )?;
        } else {
            println!("[Trainer] Training aborted due to early shutdown.");
            running.store(false, Ordering::SeqCst);
        }
    }

    // Keep main alive and join threads upon shutdown
    let _ = producer_thread.join();
    let _ = router_thread.join();
    for thread in worker_threads {
        let _ = thread.join();
    }
    for thread in classification_threads {
        let _ = thread.join();
    }
    let _ = watcher_thread.join();

    println!("=== R-NADS: Stopped ===");
    Ok(())
}

/// Spawns the classification sub-pipeline threads (Inference, Mitigation HTTP, DB Logger, Health Monitor)
#[allow(clippy::manual_is_multiple_of)]
fn start_classification_pipeline(
    config: Arc<std::sync::RwLock<SystemConfig>>,
    inference_rx: crossbeam_channel::Receiver<FlowMetrics>,
    running: Arc<AtomicBool>,
    packet_counter: Arc<AtomicU64>,
    latency_sum_us: Arc<AtomicU64>,
) -> Result<Vec<thread::JoinHandle<()>>, Box<dyn std::error::Error>> {
    let (bind_addr, db_path, log_path) = {
        let cfg = config.read().unwrap();
        (
            cfg.nginx_bind.clone(),
            cfg.database_path.clone(),
            cfg.log_path.clone(),
        )
    };

    let blocklist = Arc::new(DashMap::<IpAddr, Instant>::new());

    // Channels for anomalies
    let (alert_tx, alert_rx) = unbounded::<AnomalyAlert>();
    let mut threads = Vec::new();

    // 1. Spawn Mitigation server thread (Thread 5)
    let blocklist_mitigation = blocklist.clone();
    let running_mitigation = running.clone();
    let config_mitigation = config.clone();
    let packet_counter_mitigation = packet_counter.clone();
    let latency_sum_mitigation = latency_sum_us.clone();
    let mitigation_thread = thread::Builder::new()
        .name("mitigation".to_string())
        .spawn(move || {
            if let Err(e) = run_mitigation_server(
                &bind_addr,
                blocklist_mitigation,
                config_mitigation,
                running_mitigation,
                packet_counter_mitigation,
                latency_sum_mitigation,
            ) {
                eprintln!("[Mitigation] Server error: {}", e);
            }
        })?;
    threads.push(mitigation_thread);

    // 2. Spawn SQLite forensic logger and text file logger thread (Thread 4)
    let alert_rx_db = alert_rx.clone();
    let database_thread = thread::Builder::new()
        .name("sqlite-logger".to_string())
        .spawn(move || {
            println!("[Logger] Connecting to SQLite: {}", db_path);
            let conn = match rusqlite::Connection::open(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[Logger] Failed to open SQLite DB: {}", e);
                    return;
                }
            };

            let create_table_res = conn.execute(
                "CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    src_ip TEXT NOT NULL,
                    dest_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dest_port INTEGER NOT NULL,
                    protocol INTEGER NOT NULL,
                    score REAL NOT NULL,
                    threshold REAL NOT NULL,
                    mean_len REAL NOT NULL,
                    var_len REAL NOT NULL,
                    packet_rate REAL NOT NULL,
                    byte_rate REAL NOT NULL,
                    fwd_bwd_ratio REAL NOT NULL,
                    syn_ratio REAL NOT NULL,
                    rst_ratio REAL NOT NULL,
                    fin_ratio REAL NOT NULL,
                    psh_ratio REAL NOT NULL,
                    ack_ratio REAL NOT NULL,
                    mean_interval REAL NOT NULL,
                    var_interval REAL NOT NULL
                )",
                [],
            );

            if let Err(e) = create_table_res {
                eprintln!("[Logger] Failed to create database table: {}", e);
                return;
            }

            let mut log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .map_err(|e| {
                    eprintln!("[Logger] Failed to open log file '{}': {}", log_path, e);
                })
                .ok();

            while let Ok(alert) = alert_rx_db.recv() {
                let ts_secs = alert.timestamp.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                let insert_res = conn.execute(
                    "INSERT INTO anomalies (timestamp, src_ip, dest_ip, src_port, dest_port, protocol, score, threshold, mean_len, var_len, packet_rate, byte_rate, fwd_bwd_ratio, syn_ratio, rst_ratio, fin_ratio, psh_ratio, ack_ratio, mean_interval, var_interval)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
                    rusqlite::params![
                        ts_secs,
                        &alert.src_ip,
                        &alert.dest_ip,
                        alert.src_port,
                        alert.dest_port,
                        alert.protocol,
                        alert.score,
                        alert.threshold,
                        alert.mean_len,
                        alert.var_len,
                        alert.packet_rate,
                        alert.byte_rate,
                        alert.fwd_bwd_ratio,
                        alert.syn_ratio,
                        alert.rst_ratio,
                        alert.fin_ratio,
                        alert.psh_ratio,
                        alert.ack_ratio,
                        alert.mean_interval,
                        alert.var_interval,
                    ],
                );

                if let Err(e) = insert_res {
                    eprintln!("[Logger] SQLite write error: {}", e);
                }

                if let Some(ref mut file) = log_file {
                    use std::io::Write;
                    let log_line = format!(
                        "[{}] ANOMALY: {} -> {} | Score: {:.4} | Pkts/sec: {:.1} | Bytes/sec: {:.1} | SYN ratio: {:.2}\n",
                        ts_secs, alert.src_ip, alert.dest_ip, alert.score, alert.packet_rate, alert.byte_rate, alert.syn_ratio
                    );
                    let _ = file.write_all(log_line.as_bytes());
                }
            }
            println!("[Logger] Thread exiting.");
        })?;
    threads.push(database_thread);

    // 3. Spawn Inference Engine thread (Phase C)
    let running_flag = running.clone();
    let blocklist_inference = blocklist.clone();
    let alert_tx_c = alert_tx.clone();

    let inference_thread = thread::Builder::new()
        .name("inference".to_string())
        .spawn(move || {
            println!("[Inference] Engine thread started.");
            let mut total_inferences = 0u64;

            while running_flag.load(Ordering::SeqCst) {
                if let Ok(metrics) = inference_rx.recv_timeout(Duration::from_millis(50)) {
                    total_inferences += 1;
                    let res = InferenceEngine::predict(&metrics);
                    let client_ip = metrics.src_ip;

                    if res.is_anomaly {
                        let alert = InferenceEngine::create_alert(&metrics, &res);

                        // Always track anomalous IPs in the blocklist map
                        blocklist_inference.insert(client_ip, Instant::now());

                        let _ = alert_tx_c.send(alert);
                    } else {
                        // Behavioral unblocking: IP returned to normal SVDD space
                        if blocklist_inference.contains_key(&client_ip) {
                            blocklist_inference.remove(&client_ip);
                            println!("[Mitigation] IP {} returned to normal SVDD bounds. Active behavioral unblock triggered.", client_ip);
                        }
                    }

                    if total_inferences % 50000 == 0 {
                        println!("[Inference] Evaluated {} flow windows.", total_inferences);
                    }
                }
            }
            println!("[Inference] Thread exiting. Total metric windows evaluated: {}", total_inferences);
        })?;
    threads.push(inference_thread);

    // 4. Spawn Monitor and Health Reporter (Thread 6)
    let running_flag = running.clone();
    let pkt_count = packet_counter;
    let lat_sum = latency_sum_us;
    let blocklist_monitor = blocklist;
    let alert_rx_monitor = alert_rx;

    let monitor_thread = thread::Builder::new()
        .name("monitor".to_string())
        .spawn(move || {
            println!("[Monitor] Health and Alert reporter started.");
            let mut last_time = Instant::now();
            let mut last_packets = 0u64;

            while running_flag.load(Ordering::SeqCst) {
                // Check for real-time alerts to print to console
                if let Ok(alert) = alert_rx_monitor.recv_timeout(Duration::from_millis(20)) {
                    println!(
                        "\n[Monitor] !!! ANOMALY DETECTED !!!\n\
                         Flow: {} -> {} (Proto: {})\n\
                         Distance SQ: {:.4} (Threshold: {:.4})\n\
                         Stats: Pkts/sec: {:.1}, Byte/sec: {:.1}, Fwd-Bwd ratio: {:.2}, SYN: {:.2}, RST: {:.2}, FIN: {:.2}, PSH: {:.2}, ACK: {:.2}, Interval: {:.1}ms\n",
                        alert.src_ip, alert.dest_ip, alert.protocol, alert.score, alert.threshold,
                        alert.packet_rate, alert.byte_rate, alert.fwd_bwd_ratio, alert.syn_ratio,
                        alert.rst_ratio, alert.fin_ratio, alert.psh_ratio, alert.ack_ratio, alert.mean_interval
                    );
                }

                // Periodic health report
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
                        "[Monitor] Health: Throughput = {:.1} pps, Avg Routing Latency = {:.3} us, Blocked IPs = {}, Total Packets = {}",
                        throughput, avg_latency, blocklist_monitor.len(), current_packets
                    );

                    last_time = now;
                    last_packets = current_packets;
                }
            }
            println!("[Monitor] Thread exiting.");
        })?;
    threads.push(monitor_thread);

    Ok(threads)
}

/// Trains SVDD model, calibrates Gamma via the median trick, and computes centroids.
#[allow(clippy::needless_range_loop)]
fn train_model(samples: &[FlowMetrics]) -> Result<ModelConfig, Box<dyn std::error::Error>> {
    let n = samples.len();
    if n == 0 {
        return Err("Cannot train on an empty sample set".into());
    }

    // 1. Compute means
    let mut means = [0.0; 12];
    for s in samples {
        let x = [
            s.mean_len,
            s.var_len.sqrt(),
            s.packet_rate,
            s.byte_rate,
            s.fwd_bwd_ratio,
            s.syn_ratio,
            s.rst_ratio,
            s.fin_ratio,
            s.psh_ratio,
            s.ack_ratio,
            s.mean_interval,
            s.var_interval.sqrt(),
        ];
        for i in 0..12 {
            means[i] += x[i];
        }
    }
    for i in 0..12 {
        means[i] /= n as f64;
    }

    // 2. Compute standard deviations
    let mut stddevs = [0.0; 12];
    for s in samples {
        let x = [
            s.mean_len,
            s.var_len.sqrt(),
            s.packet_rate,
            s.byte_rate,
            s.fwd_bwd_ratio,
            s.syn_ratio,
            s.rst_ratio,
            s.fin_ratio,
            s.psh_ratio,
            s.ack_ratio,
            s.mean_interval,
            s.var_interval.sqrt(),
        ];
        for i in 0..12 {
            let diff = x[i] - means[i];
            stddevs[i] += diff * diff;
        }
    }
    for i in 0..12 {
        stddevs[i] = (stddevs[i] / n as f64).sqrt().max(1e-7);
    }

    // 3. Normalize samples to do the Median Trick in normalized input feature space
    let mut normalized_samples = vec![[0.0; 12]; n];
    for k in 0..n {
        let s = &samples[k];
        let x = [
            s.mean_len,
            s.var_len.sqrt(),
            s.packet_rate,
            s.byte_rate,
            s.fwd_bwd_ratio,
            s.syn_ratio,
            s.rst_ratio,
            s.fin_ratio,
            s.psh_ratio,
            s.ack_ratio,
            s.mean_interval,
            s.var_interval.sqrt(),
        ];
        for i in 0..12 {
            normalized_samples[k][i] = (x[i] - means[i]) / stddevs[i];
        }
    }

    // Pairwise squared distances of normalized features (using representative subset to keep it fast)
    let num_subset = n.min(2000);
    let mut pair_distances = Vec::with_capacity(num_subset * (num_subset - 1) / 2);
    for k in 0..num_subset {
        for l in (k + 1)..num_subset {
            let mut dist_sq = 0.0;
            for i in 0..12 {
                let diff = normalized_samples[k][i] - normalized_samples[l][i];
                dist_sq += diff * diff;
            }
            pair_distances.push(dist_sq);
        }
    }
    pair_distances.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median_dist_sq = pair_distances[pair_distances.len() / 2].max(1e-7);
    let gamma = 0.5 / median_dist_sq;
    println!(
        "[Trainer] Calibrated Gamma using Median Trick: {:.6}",
        gamma
    );

    // 4. Setup LCG Random Generator for reproducible projection space (RFF parameters)
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

    let projection_dim = 256;
    let std_dev_proj = (2.0 * gamma).sqrt();

    let mut w_matrix = [[0.0; 12]; 256];
    let mut b_vector = [0.0; 256];

    for j in 0..projection_dim {
        for i in 0..12 {
            w_matrix[j][i] = rng.next_gaussian() * std_dev_proj;
        }
        b_vector[j] = rng.next_f64() * 2.0 * std::f64::consts::PI;
    }

    // 5. Project samples to RFF space
    let mut phi_matrix = vec![[0.0; 256]; n];
    let scale = (2.0 / projection_dim as f64).sqrt();

    for k in 0..n {
        for j in 0..projection_dim {
            let mut proj = 0.0;
            for i in 0..12 {
                proj += w_matrix[j][i] * normalized_samples[k][i];
            }
            proj += b_vector[j];
            phi_matrix[k][j] = scale * proj.cos();
        }
    }

    // 6. Compute SVDD center (average projection vector of normal samples)
    let mut centroid = [0.0; 256];
    for k in 0..n {
        for j in 0..projection_dim {
            centroid[j] += phi_matrix[k][j];
        }
    }
    for j in 0..projection_dim {
        centroid[j] /= n as f64;
    }

    // 7. Compute exact squared Euclidean distances for all training samples and set threshold
    let mut distances_sq = vec![0.0; n];
    for k in 0..n {
        let mut sum = 0.0;
        for j in 0..projection_dim {
            let diff = phi_matrix[k][j] - centroid[j];
            sum += diff * diff;
        }
        distances_sq[k] = sum;
    }

    // Sort to find the 95th percentile
    distances_sq.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let threshold_idx = (n as f64 * 0.95) as usize;
    let threshold = distances_sq[threshold_idx.min(n - 1)];

    println!("[Trainer] SVDD Baseline training completed:");
    println!(
        "  - Mean distance (Euclidean): {:.6}",
        (distances_sq.iter().sum::<f64>() / n as f64).sqrt()
    );
    println!(
        "  - 95th percentile threshold (distance^2): {:.6}",
        threshold
    );

    Ok(ModelConfig {
        threshold,
        means,
        stddevs,
        centroid,
        b_vector,
        w_matrix,
    })
}
