# R-NADS // Rust Network Anomaly Detection System

R-NADS is an enterprise-grade, high-performance network anomaly detection system built in Rust. It utilizes a **Support Vector Data Description (SVDD)** machine learning engine approximated via **Random Fourier Features (RFF)** to detect volumetric DDoS attacks, port scans, and zero-day exploits at line-rate. 

The system operates directly at the packet-ingestion layer, performing flow aggregation, feature extraction, real-time SVDD inference, database logging, and HTTP-based mitigation checks.

Demo Video: https://drive.google.com/file/d/19tsmBNHZvDEH2FJ5YuUeGYiAVurmGr6F/view?usp=sharing

---

## 1. Pipeline Architecture

R-NADS utilizes a highly concurrent, zero-heap-allocation ingestion pipeline spanning multiple dedicated threads:

*   **Producer (Capture)**: Sniffs raw packet bytes from network interfaces using `pcap` (or reads from PCAP files / generates synthetic mock traffic).
*   **Router**: Computes symmetric flow hashes and routes packet events to worker aggregators via lock-free channels.
*   **Aggregator Workers**: Maintains sliding flow state buffers ($K=128$) to compute rolling traffic features.
*   **Inference Engine**: Normalizes features and maps them into a 256-dimensional RFF space to compute SVDD hypersphere distances:
    $$\|\Phi(x) - c\|^2 \le R^2$$
*   **HTTP Checker & SOC Dashboard**: Integrates with Nginx's `auth_request` module for dynamic IP mitigation and hosts a live, 3D Plotly.js threat visualization dashboard.
*   **Forensic Logger**: Writes alerts asynchronously into a local SQLite database (`anomalies.db`) and plain-text log files.

---

## 2. Setup & Configuration (`config.toml`)

Operational parameters are configured in `config.toml` at the project root. R-NADS watches this file for modifications and reloads configurations dynamically without restarting:

```toml
[system]
mode = "classify"               # Pipeline mode: 'classify' or 'train'
workers = 4                     # Number of parallel aggregator threads
capacity = 65536                # Maximum active concurrent flows tracked
database_path = "anomalies.db"  # SQLite anomalies forensics database path
log_path = "r-nads.log"         # Plain-text anomalies logs path
block_list_ttl = 3600           # IP block duration in seconds (lazy fallback)
nginx_bind = "127.0.0.1:8080"   # Bind address for HTTP auth and SOC dashboard
capture_source = "mock"         # Packet source: 'live', 'pcap', or 'mock'
pps = 10000                     # Packet-per-second generation rate (mock source only)
flows = 1000                    # Active flows pool size (mock source only)
pcap_file = "test.pcap"         # PCAP file path (pcap source only)
interface = "eth0"              # Target capture interface (live source only)
training_samples = 10000        # Number of normal samples to train SVDD baseline
mitigation_mode = "mitigate"    # Action mode: 'monitor' (alert-only) or 'mitigate' (block)
model_path = "model.json"       # Storage path for serialized model parameters
```

---

## 3. Command Reference

### Build & Compilation
*   **Compile Release Binary** (highly optimized compilation with native CPU target vectors):
    ```bash
    cargo build --release
    ```
*   **Compile Docker Container**:
    ```bash
    docker compose build
    ```

### Run & Start Options
*   **Start native daemon**:
    ```bash
    # Set packet capture capabilities on the binary (allows non-root execution)
    sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/r-nads
    
    # Launch R-NADS
    ./target/release/r-nads
    ```
*   **Start with mode override** (force retraining):
    ```bash
    ./target/release/r-nads --mode train
    ```
*   **Start in Docker** (attaches to host network interface):
    ```bash
    docker compose up -d
    ```

### Testing & Verification
*   **Run the unit test suite**:
    ```bash
    cargo test
    ```
*   **Run Criterion latency benchmarks**:
    ```bash
    cargo bench
    ```

### Termination
*   **Stop native program**: Press **`Ctrl+C`** (triggers graceful thread join).
*   **Stop systemd daemon**: `sudo systemctl stop r-nads`
*   **Stop Docker containers**: `docker compose down`

---

## 4. HTTP Endpoints & Live SOC Dashboard

The R-NADS server listens on the port configured by `nginx_bind` (default: `8080`) and exposes:

*   **`/check`**: High-performance $O(1)$ client IP inspection route called by Nginx `auth_request`. Returns `200 OK` (if allowed) or `403 Forbidden` (if blocked under mitigation mode).
*   **`/svdd_visualization.html`**: The interactive SOC Threat Dashboard. Displays live traffic throughput, microsecond packet-routing latency, a blocklist countdown registry, and an interactive **3D Plotly.js scatter plot** mapping normal and anomalous traffic clusters.
*   **`/api/stats`**: Serves live system telemetry JSON.
*   **`/api/anomalies`**: Serves forensic logs JSON queried directly from the SQLite database.

---

## 5. Deployment Options

### A. Docker Containerization (Recommended)
Docker isolates R-NADS and all its packet capture libraries from the host environment. By running with host-mode networking, the container can capture packets passing through the host's actual interfaces:
```bash
docker compose up -d
```

### B. Standard systemd Service Daemon
You can deploy R-NADS natively as a background service:
1. Run `./deploy.sh` to package files into the `./dist` directory.
2. Copy files and enable the service:
   ```bash
   sudo cp -r dist /opt/r-nads
   sudo cp /opt/r-nads/r-nads.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now r-nads
   ```
