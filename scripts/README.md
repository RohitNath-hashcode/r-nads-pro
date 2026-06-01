# R-NADS Operation, Benchmarking, and Cross-Compilation

This folder contains scripts and instructions to operate, benchmark, and deploy the Rust Network Anomaly Detection System (R-NADS).

---

## 1. Running the System

You can run the R-NADS orchestrator binary directly using `cargo run`.

### Mock Traffic Mode (Local Development)
Simulates high-velocity network packet events with rolling flow tracking. Good for stress-testing and CPU profiling.
```bash
cargo run -p r-nads-bin -- --mode mock --pps 20000 --flows 500
```
- `--pps <number>`: Target packets per second.
- `--flows <number>`: Number of unique active IP addresses (controls map dispersion).
- `--workers <number>`: Number of thread-local aggregator cores (default: 4).

### Offline PCAP File Mode
Processes recorded network traffic.
```bash
cargo run -p r-nads-bin -- --mode pcap --pcap-file path/to/capture.pcap
```

### Live Traffic Mode (Linux/ARM64 Only)
Captures raw network frames directly from an interface (promiscuous mode).
```bash
cargo run -p r-nads-bin -- --mode live --interface eth0
```

---

## 2. Benchmarking (Microsecond Latency Measurements)

We use **Criterion** to measure the exact latency of the flow table sliding window aggregates on hot paths down to the nanosecond level.

Run the benchmarks using:
```bash
cargo bench
```

### Interpretation of Results
The benchmark yields results similar to:
```
process_packet_existing_flow
                        time:   [171.02 ns 172.88 ns 175.08 ns]
```
This represents the time to execute a full cycle of packet ingestion, including:
- Symmetric flow key sorting.
- Hashing and worker routing.
- Map lookup.
- LRU recency promotion.
- Circular buffer sliding window eviction (pre-allocated).
- Rolling statistical aggregates (precise integer variance and sum calculations).
- Feature calculations (packet rate, byte rate, ratios).

An average processing time of **172 nanoseconds** means a single thread can process **~5.8 million packets per second**. With 4 workers, this scales to over **20 million packets per second** (well exceeding 1Gbps line rate requirements).

---

## 3. Cross-Compilation for Raspberry Pi (AArch64 ARM64)

To compile the native binary from Windows/Linux/macOS for Raspberry Pi 4/5 (ARM64 running Linux), we use `cargo-cross` which runs builds inside standardized Docker container toolchains.

### Prerequisites
- Docker Desktop must be running.

### Windows (PowerShell)
Run:
```powershell
.\scripts\cross_compile.ps1
```

### Linux / macOS
Run:
```bash
chmod +x ./scripts/cross_compile.sh
./scripts/cross_compile.sh
```

### Output
The compiled static executable will be generated at:
`target/aarch64-unknown-linux-gnu/release/r-nads-bin`
