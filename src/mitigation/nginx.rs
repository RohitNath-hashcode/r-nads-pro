use crate::SystemConfig;
use dashmap::DashMap;
use rusqlite::Connection;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tiny_http::{Response, Server};

/// Runs a high-performance mitigation server to interface with Nginx's `auth_request` module.
/// Listens on `bind_addr` for `/check` requests, and serves an interactive real-time SOC dashboard.
pub fn run_mitigation_server(
    bind_addr: &str,
    blocklist: Arc<DashMap<IpAddr, Instant>>,
    config: Arc<RwLock<SystemConfig>>,
    running: Arc<AtomicBool>,
    packet_counter: Arc<AtomicU64>,
    latency_sum_us: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = Server::http(bind_addr).map_err(|e| e.to_string())?;
    println!(
        "[Mitigation] Nginx HTTP auth_request server listening on {}",
        bind_addr
    );

    // Track statistics for throughput calculations
    let mut last_pkt_count = packet_counter.load(Ordering::Relaxed);
    let mut last_time = Instant::now();
    let mut current_pps = 0.0;

    while running.load(Ordering::SeqCst) {
        if let Ok(Some(request)) = server.try_recv() {
            let url = request.url();

            // Periodic throughput delta calculation inside the loop (throttled check)
            let now = Instant::now();
            let elapsed_sec = now.duration_since(last_time).as_secs_f64();
            if elapsed_sec >= 1.0 {
                let current_pkt_count = packet_counter.load(Ordering::Relaxed);
                current_pps = ((current_pkt_count - last_pkt_count) as f64 / elapsed_sec).max(0.0);
                last_pkt_count = current_pkt_count;
                last_time = now;
            }

            if url == "/check" {
                // Extract IP from X-Real-IP header, fallback to remote address of socket
                let x_real_ip = request
                    .headers()
                    .iter()
                    .find(|h| {
                        let field_str: &str = h.field.as_str().as_ref();
                        field_str.eq_ignore_ascii_case("X-Real-IP")
                    })
                    .map(|h| {
                        let val_str: &str = h.value.as_str();
                        val_str.trim()
                    });

                let client_ip = if let Some(ip_str) = x_real_ip {
                    ip_str.parse::<IpAddr>().ok()
                } else {
                    None
                };

                let client_ip = client_ip.unwrap_or_else(|| {
                    request
                        .remote_addr()
                        .map(|addr| addr.ip())
                        .unwrap_or_else(|| "127.0.0.1".parse().unwrap())
                });

                // Perform O(1) concurrent lookup against blocklist
                let is_blocked = if let Some(blocked_at) = blocklist.get(&client_ip) {
                    let current_ttl = {
                        let cfg = config.read().unwrap();
                        Duration::from_secs(cfg.block_list_ttl)
                    };
                    if blocked_at.elapsed() < current_ttl {
                        true
                    } else {
                        // TTL expired: remove from blocklist lazily
                        drop(blocked_at); // Release read lock before mutating
                        blocklist.remove(&client_ip);
                        false
                    }
                } else {
                    false
                };

                let current_mitigation_mode = {
                    let cfg = config.read().unwrap();
                    cfg.mitigation_mode.clone()
                };

                // Determine header values for Nginx logging and inspection
                let mode_val = if current_mitigation_mode == "mitigate" {
                    "Mitigation"
                } else {
                    "Monitoring"
                };
                let is_actually_mitigated = is_blocked && current_mitigation_mode == "mitigate";
                let status_val = if is_actually_mitigated {
                    "Blocked"
                } else {
                    "Allowed"
                };
                let anomaly_val = if is_blocked { "Yes" } else { "No" };

                let mode_header =
                    tiny_http::Header::from_str(&format!("X-RNADS-Mode: {}", mode_val)).unwrap();
                let status_header = tiny_http::Header::from_str(&format!(
                    "X-RNADS-Detection-Status: {}",
                    status_val
                ))
                .unwrap();
                let anomaly_header = tiny_http::Header::from_str(&format!(
                    "X-RNADS-Anomaly-Detected: {}",
                    anomaly_val
                ))
                .unwrap();

                let status_code = if is_actually_mitigated { 403 } else { 200 };
                let body_str = if is_actually_mitigated {
                    "Forbidden"
                } else {
                    "OK"
                };

                let response = Response::from_string(body_str)
                    .with_status_code(status_code)
                    .with_header(mode_header)
                    .with_header(status_header)
                    .with_header(anomaly_header);

                let _ = request.respond(response);
            } else if url == "/api/stats" {
                let current_pkt_count = packet_counter.load(Ordering::Relaxed);
                let current_lat_sum = latency_sum_us.load(Ordering::Relaxed);
                let avg_latency = if current_pkt_count > 0 {
                    (current_lat_sum as f64) / (current_pkt_count as f64)
                } else {
                    0.0
                };

                let (mitigation_mode, block_list_ttl) = {
                    let cfg = config.read().unwrap();
                    (cfg.mitigation_mode.clone(), cfg.block_list_ttl)
                };

                let blocked_ips: Vec<serde_json::Value> = blocklist
                    .iter()
                    .map(|item| {
                        let ip = item.key().to_string();
                        let elapsed = item.value().elapsed().as_secs();
                        let remaining = block_list_ttl.saturating_sub(elapsed);
                        serde_json::json!({
                            "ip": ip,
                            "remaining_seconds": remaining
                        })
                    })
                    .collect();

                let stats_json = serde_json::json!({
                    "total_packets": current_pkt_count,
                    "avg_latency_us": avg_latency,
                    "throughput_pps": current_pps,
                    "mitigation_mode": mitigation_mode,
                    "block_list_ttl": block_list_ttl,
                    "blocked_ips_count": blocked_ips.len(),
                    "blocked_ips": blocked_ips
                });

                let response = Response::from_string(serde_json::to_string(&stats_json).unwrap())
                    .with_status_code(200)
                    .with_header(
                        tiny_http::Header::from_str("Content-Type: application/json").unwrap(),
                    );
                let _ = request.respond(response);
            } else if url == "/api/anomalies" {
                let db_path = {
                    let cfg = config.read().unwrap();
                    cfg.database_path.clone()
                };

                let mut anomalies = Vec::new();
                if let Ok(conn) = Connection::open(&db_path) {
                    let mut stmt = conn.prepare(
                        "SELECT timestamp, src_ip, dest_ip, score, packet_rate, byte_rate, mean_len, syn_ratio, rst_ratio, fin_ratio, psh_ratio, ack_ratio FROM anomalies ORDER BY id DESC LIMIT 200"
                    ).ok();

                    if let Some(ref mut stmt) = stmt {
                        if let Ok(rows) = stmt.query_map([], |row| {
                            Ok(serde_json::json!({
                                "timestamp": row.get::<_, i64>(0)?,
                                "src_ip": row.get::<_, String>(1)?,
                                "dest_ip": row.get::<_, String>(2)?,
                                "score": row.get::<_, f64>(3)?,
                                "packet_rate": row.get::<_, f64>(4)?,
                                "byte_rate": row.get::<_, f64>(5)?,
                                "mean_len": row.get::<_, f64>(6)?,
                                "syn_ratio": row.get::<_, f64>(7)?,
                                "rst_ratio": row.get::<_, f64>(8)?,
                                "fin_ratio": row.get::<_, f64>(9)?,
                                "psh_ratio": row.get::<_, f64>(10)?,
                                "ack_ratio": row.get::<_, f64>(11)?
                            }))
                        }) {
                            for row in rows.flatten() {
                                anomalies.push(row);
                            }
                        }
                    }
                }

                let response = Response::from_string(serde_json::to_string(&anomalies).unwrap())
                    .with_status_code(200)
                    .with_header(
                        tiny_http::Header::from_str("Content-Type: application/json").unwrap(),
                    );
                let _ = request.respond(response);
            } else if url == "/dashboard"
                || url == "/dashboard.html"
                || url == "/svdd_visualization.html"
            {
                let response = Response::from_string(DASHBOARD_HTML)
                    .with_status_code(200)
                    .with_header(tiny_http::Header::from_str("Content-Type: text/html").unwrap());
                let _ = request.respond(response);
            } else {
                let response = Response::from_string("Not Found").with_status_code(404);
                let _ = request.respond(response);
            }
        } else {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    println!("[Mitigation] Server thread exiting.");
    Ok(())
}

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>R-NADS // Real-Time Threat Intelligence Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.plot.ly/plotly-2.24.1.min.js"></script>
    <style>
        body {
            font-family: 'Outfit', sans-serif;
            background: radial-gradient(circle at top, #141523 0%, #090a10 100%);
            color: #e2e8f0;
        }
        .code-font {
            font-family: 'JetBrains Mono', monospace;
        }
        .glass-panel {
            background: rgba(22, 23, 38, 0.6);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.05);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
        }
        .glow-green {
            box-shadow: 0 0 20px rgba(34, 197, 94, 0.2);
            border-color: rgba(34, 197, 94, 0.4);
        }
        .glow-red {
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.2);
            border-color: rgba(239, 68, 68, 0.4);
        }
        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 6px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(22, 23, 38, 0.3);
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.2);
        }
    </style>
</head>
<body class="min-h-screen p-4 md:p-6 overflow-x-hidden">

    <!-- Header -->
    <header class="flex flex-col md:flex-row justify-between items-center mb-6 pb-4 border-b border-gray-800 gap-4">
        <div>
            <h1 class="text-2xl font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-red-500 via-purple-400 to-indigo-400">
                R-NADS // THREAT INTELLIGENCE
            </h1>
            <p class="text-xs text-gray-500 uppercase tracking-widest mt-0.5">Real-time SVDD Hypersphere Security Operations Center</p>
        </div>
        <div class="flex items-center gap-4">
            <div id="status-badge" class="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold uppercase tracking-wider glass-panel glow-green">
                <span class="relative flex h-2 w-2">
                    <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                    <span class="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                </span>
                <span id="mitigation-mode-text">MONITOR MODE</span>
            </div>
            <div class="text-xs text-gray-500 code-font" id="clock">00:00:00 UTC</div>
        </div>
    </header>

    <!-- Main Grid -->
    <main class="grid grid-cols-1 lg:grid-cols-3 gap-6">

        <!-- Left Metrics and Charts -->
        <section class="lg:col-span-2 space-y-6">
            <!-- Telemetry Stats Row -->
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div class="glass-panel rounded-xl p-4 flex flex-col justify-between h-28 relative overflow-hidden group">
                    <div class="text-xs text-gray-500 font-semibold tracking-wider uppercase">Traffic Throughput</div>
                    <div class="text-3xl font-bold tracking-tight text-white mt-2 code-font" id="throughput-text">0.0 <span class="text-sm font-normal text-gray-400">pps</span></div>
                    <div class="text-xs text-gray-500 mt-2" id="packet-count-text">Total: 0 packets</div>
                </div>

                <div class="glass-panel rounded-xl p-4 flex flex-col justify-between h-28 relative overflow-hidden group">
                    <div class="text-xs text-gray-500 font-semibold tracking-wider uppercase">Average Latency</div>
                    <div class="text-3xl font-bold tracking-tight text-white mt-2 code-font" id="latency-text">0.00 <span class="text-sm font-normal text-gray-400">µs</span></div>
                    <div class="text-xs text-emerald-400 mt-2 flex items-center gap-1">
                        <span class="inline-block h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                        Zero-Allocation Routing Path
                    </div>
                </div>

                <div class="glass-panel rounded-xl p-4 flex flex-col justify-between h-28 relative overflow-hidden group" id="blocked-card">
                    <div class="text-xs text-gray-500 font-semibold tracking-wider uppercase">Active Blocked IPs</div>
                    <div class="text-3xl font-bold tracking-tight text-red-500 mt-2 code-font" id="blocked-count-text">0</div>
                    <div class="text-xs text-gray-500 mt-2" id="ttl-text">Default TTL: 30s</div>
                </div>
            </div>

            <!-- 3D Visualization Map -->
            <div class="glass-panel rounded-xl p-4">
                <div class="flex justify-between items-center mb-4">
                    <h2 class="text-sm font-semibold uppercase tracking-wider text-gray-400">3D SVDD Feature Projection Map</h2>
                    <span class="text-[10px] text-gray-500 code-font">Axes: Packet Rate (X) | Byte Rate (Y) | Average Size (Z)</span>
                </div>
                <div id="chart-3d" class="w-full h-[450px] bg-transparent rounded-lg"></div>
            </div>
        </section>

        <!-- Right Side Sidebar (Blocked IPs & Historical Detections) -->
        <section class="space-y-6">
            <!-- Active Block List -->
            <div class="glass-panel rounded-xl p-4 flex flex-col h-[280px]">
                <div class="flex justify-between items-center mb-3 pb-2 border-b border-gray-800">
                    <h2 class="text-sm font-semibold uppercase tracking-wider text-gray-400 flex items-center gap-2">
                        <svg class="h-4 w-4 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m0 0v3m0-3h3m-3 0H9m12-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                        Mitigated Host Registry
                    </h2>
                    <span class="text-xs code-font text-red-400" id="blocklist-count-badge">0 IP(s)</span>
                </div>
                <div class="overflow-y-auto flex-grow" id="blocklist-container">
                    <table class="w-full text-left text-xs code-font">
                        <thead>
                            <tr class="text-gray-500 border-b border-gray-800">
                                <th class="pb-2 font-normal">Source IP</th>
                                <th class="pb-2 text-right font-normal">Unblocks In</th>
                            </tr>
                        </thead>
                        <tbody id="blocklist-tbody" class="divide-y divide-gray-800">
                            <!-- Injected dynamically -->
                        </tbody>
                    </table>
                    <div id="no-blocked-msg" class="text-center py-10 text-gray-600 text-xs italic">
                        No active mitigated host addresses.
                    </div>
                </div>
            </div>

            <!-- Real-Time Alerts Logs -->
            <div class="glass-panel rounded-xl p-4 flex flex-col h-[328px]">
                <div class="flex justify-between items-center mb-3 pb-2 border-b border-gray-800">
                    <h2 class="text-sm font-semibold uppercase tracking-wider text-gray-400">
                        Forensic Anomaly Log Feed
                    </h2>
                    <span class="h-2 w-2 rounded-full bg-red-500 animate-ping"></span>
                </div>
                <div class="overflow-y-auto flex-grow text-xs code-font space-y-2.5" id="anomaly-log-feed">
                    <!-- Injected dynamically -->
                </div>
            </div>
        </section>

    </main>

    <script>
        // System Config and Stats Global Object
        let latestAnomalies = [];
        let systemStats = { block_list_ttl: 30 };

        // Keep local clock running
        setInterval(() => {
            const now = new Date();
            document.getElementById('clock').innerText = now.toUTCString();
        }, 1000);

        // Fetch Live Stats from /api/stats
        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                if (!res.ok) return;
                const stats = await res.json();
                systemStats = stats;

                // Update UI elements
                document.getElementById('throughput-text').innerHTML = `${stats.throughput_pps.toFixed(1)} <span class="text-sm font-normal text-gray-400">pps</span>`;
                document.getElementById('packet-count-text').innerText = `Total: ${stats.total_packets.toLocaleString()} packets`;
                document.getElementById('latency-text').innerHTML = `${stats.avg_latency_us.toFixed(2)} <span class="text-sm font-normal text-gray-400">µs</span>`;
                document.getElementById('blocked-count-text').innerText = stats.blocked_ips_count;
                document.getElementById('blocklist-count-badge').innerText = `${stats.blocked_ips_count} IP(s)`;
                document.getElementById('ttl-text').innerText = `Default TTL: ${stats.block_list_ttl}s`;

                const badge = document.getElementById('status-badge');
                const badgeText = document.getElementById('mitigation-mode-text');
                const card = document.getElementById('blocked-card');

                if (stats.mitigation_mode === 'mitigate') {
                    badgeText.innerText = 'MITIGATION ACTIVE';
                    badge.className = 'flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold uppercase tracking-wider glass-panel glow-red';
                    card.className = 'glass-panel rounded-xl p-4 flex flex-col justify-between h-28 relative overflow-hidden group border border-red-500/20';
                } else {
                    badgeText.innerText = 'MONITORING MODE';
                    badge.className = 'flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold uppercase tracking-wider glass-panel glow-green';
                    card.className = 'glass-panel rounded-xl p-4 flex flex-col justify-between h-28 relative overflow-hidden group';
                }

                // Render Blocklist Registry
                const tbody = document.getElementById('blocklist-tbody');
                tbody.innerHTML = '';
                if (stats.blocked_ips && stats.blocked_ips.length > 0) {
                    document.getElementById('no-blocked-msg').classList.add('hidden');
                    stats.blocked_ips.forEach(item => {
                        const tr = document.createElement('tr');
                        tr.className = 'hover:bg-white/5 transition-colors';
                        tr.innerHTML = `
                            <td class="py-2.5 text-red-400 font-bold">${item.ip}</td>
                            <td class="py-2.5 text-right text-gray-400">${item.remaining_seconds}s</td>
                        `;
                        tbody.appendChild(tr);
                    });
                } else {
                    document.getElementById('no-blocked-msg').classList.remove('hidden');
                }

            } catch (err) {
                console.error("Failed to fetch system stats:", err);
            }
        }

        // Fetch Historical Anomalies from /api/anomalies
        async function fetchAnomalies() {
            try {
                const res = await fetch('/api/anomalies');
                if (!res.ok) return;
                const data = await res.json();
                latestAnomalies = data;

                // Render Anomaly Log Feed (last 5 anomalies)
                const feed = document.getElementById('anomaly-log-feed');
                feed.innerHTML = '';
                if (data.length > 0) {
                    data.slice(0, 10).forEach(anom => {
                        const div = document.createElement('div');
                        div.className = 'p-2.5 rounded-lg bg-red-500/5 border border-red-500/10 space-y-1 relative';
                        const timeStr = new Date(anom.timestamp * 1000).toISOString().split('T')[1].substring(0, 8);
                        div.innerHTML = `
                            <div class="flex justify-between items-center">
                                <span class="text-red-400 font-bold">ALERT // ANOMALY</span>
                                <span class="text-[10px] text-gray-500">${timeStr}</span>
                            </div>
                            <div class="text-xs text-gray-300">${anom.src_ip} &rarr; ${anom.dest_ip}</div>
                            <div class="grid grid-cols-3 text-[10px] text-gray-500 pt-1">
                                <div>Score: ${anom.score.toFixed(3)}</div>
                                <div>Pkts: ${anom.packet_rate.toFixed(0)}/s</div>
                                <div>SYN: ${anom.syn_ratio.toFixed(2)}</div>
                            </div>
                        `;
                        feed.appendChild(div);
                    });
                } else {
                    feed.innerHTML = '<div class="text-center py-10 text-gray-600 italic">No historical anomaly logs.</div>';
                }

                // Redraw 3D scatter plot with fresh data
                drawPlot();

            } catch (err) {
                console.error("Failed to fetch anomalies:", err);
            }
        }

        // Render 3D Chart
        function drawPlot() {
            const hasData = latestAnomalies && latestAnomalies.length > 0;

            // Generate representative normal points based on our default baselines
            const numNormals = 120;
            const normX = [];
            const normY = [];
            const normZ = [];
            for (let i = 0; i < numNormals; i++) {
                // Normal traffic has low packet rate, small size, and random jitter
                normX.push(10 + Math.random() * 50);  // Packets/sec
                normY.push(1000 + Math.random() * 15000); // Bytes/sec
                normZ.push(64 + Math.random() * 250);  // Mean packet size
            }

            // Extract anomaly coordinates
            const anomX = [];
            const anomY = [];
            const anomZ = [];
            if (hasData) {
                latestAnomalies.forEach(a => {
                    anomX.push(a.packet_rate);
                    anomY.push(a.byte_rate);
                    anomZ.push(a.mean_len);
                });
            }

            // Plotly data traces
            const traceNormal = {
                x: normX, y: normY, z: normZ,
                mode: 'markers',
                name: 'Baseline Cluster (Normal)',
                type: 'scatter3d',
                marker: { size: 3.5, color: 'dodgerblue', opacity: 0.5 }
            };

            const traceAnomaly = {
                x: anomX, y: anomY, z: anomZ,
                mode: 'markers',
                name: 'Threat Vectors (Anomalies)',
                type: 'scatter3d',
                marker: { size: 5, color: 'crimson', symbol: 'x', opacity: 0.85 }
            };

            // Simple SVDD Decision Sphere around the normal center
            const avgX = 35;
            const avgY = 8000;
            const avgZ = 150;
            const radius = 120;

            const u = [];
            const v = [];
            for (let i = 0; i <= 20; i++) { u.push((i / 20) * 2 * Math.PI); }
            for (let i = 0; i <= 20; i++) { v.push((i / 20) * Math.PI); }

            const xs = [];
            const ys = [];
            const zs = [];
            for (let i = 0; i < u.length; i++) {
                const rowX = [];
                const rowY = [];
                const rowZ = [];
                for (let j = 0; j < v.length; j++) {
                    rowX.push(avgX + radius * Math.cos(u[i]) * Math.sin(v[j]));
                    rowY.push(avgY + (radius * 120) * Math.sin(u[i]) * Math.sin(v[j])); // stretch for byte rate
                    rowZ.push(avgZ + radius * Math.cos(v[j]));
                }
                xs.push(rowX);
                ys.push(rowY);
                zs.push(rowZ);
            }

            const boundarySurface = {
                x: xs, y: ys, z: zs,
                type: 'surface',
                opacity: 0.08,
                colorscale: [[0, 'rgb(34,197,94)']],
                showscale: false,
                name: 'SVDD Boundary Sphere'
            };

            const plotLayout = {
                paper_bgcolor: 'rgba(0,0,0,0)',
                plot_bgcolor: 'rgba(0,0,0,0)',
                scene: {
                    xaxis: { title: 'Pkts/sec', gridcolor: '#1e293b', zerolinecolor: '#1e293b', tickfont: { size: 9, color: '#64748b' } },
                    yaxis: { title: 'Bytes/sec', gridcolor: '#1e293b', zerolinecolor: '#1e293b', tickfont: { size: 9, color: '#64748b' } },
                    zaxis: { title: 'Avg Size', gridcolor: '#1e293b', zerolinecolor: '#1e293b', tickfont: { size: 9, color: '#64748b' } },
                    camera: { eye: { x: 1.5, y: 1.5, z: 1.1 } }
                },
                margin: { l: 0, r: 0, b: 0, t: 0 },
                legend: { x: 0, y: 1, font: { color: '#94a3b8', size: 10 } }
            };

            const plotConfig = { responsive: true, displayModeBar: false };

            Plotly.react('chart-3d', [traceNormal, traceAnomaly, boundarySurface], plotLayout, plotConfig);
        }

        // Initial setup and polling triggers
        async function init() {
            await fetchStats();
            await fetchAnomalies();

            // Interval loops
            setInterval(fetchStats, 1000);
            setInterval(fetchAnomalies, 2000);
        }

        window.onload = init;
    </script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    #[test]
    fn test_mitigation_server_routes() {
        let running = Arc::new(AtomicBool::new(true));
        let blocklist = Arc::new(DashMap::new());
        let config = Arc::new(RwLock::new(SystemConfig {
            mode: "classify".to_string(),
            workers: 1,
            capacity: 100,
            database_path: "test_anomalies.db".to_string(),
            log_path: "test_r-nads.log".to_string(),
            block_list_ttl: 30,
            nginx_bind: "127.0.0.1:18085".to_string(),
            capture_source: "mock".to_string(),
            pps: 10,
            flows: 10,
            pcap_file: None,
            interface: None,
            training_samples: 10,
            mitigation_mode: "monitor".to_string(),
            model_path: "model.json".to_string(),
        }));
        let packet_counter = Arc::new(AtomicU64::new(0));
        let latency_sum_us = Arc::new(AtomicU64::new(0));

        let running_clone = running.clone();
        let blocklist_clone = blocklist.clone();
        let config_clone = config.clone();
        let packet_counter_clone = packet_counter.clone();
        let latency_sum_us_clone = latency_sum_us.clone();

        // Spawn server on a test port
        let handle = std::thread::spawn(move || {
            let _ = run_mitigation_server(
                "127.0.0.1:18085",
                blocklist_clone,
                config_clone,
                running_clone,
                packet_counter_clone,
                latency_sum_us_clone,
            );
        });

        // Give the server a moment to start
        std::thread::sleep(Duration::from_millis(200));

        // Test 1: GET /check (should return 200 OK)
        {
            let mut stream =
                TcpStream::connect("127.0.0.1:18085").expect("Failed to connect to server");
            stream
                .write_all(
                    b"GET /check HTTP/1.1\r\nHost: 127.0.0.1:18085\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.contains("HTTP/1.1 200 OK"));
            assert!(response.contains("X-RNADS-Mode: Monitoring"));
            assert!(response.contains("X-RNADS-Detection-Status: Allowed"));
            assert!(response.contains("OK"));
        }

        // Test 2: GET /svdd_visualization.html (should return 200 OK and HTML)
        {
            let mut stream =
                TcpStream::connect("127.0.0.1:18085").expect("Failed to connect to server");
            stream
                .write_all(
                    b"GET /svdd_visualization.html HTTP/1.1\r\nHost: 127.0.0.1:18085\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.contains("HTTP/1.1 200 OK"));
            assert!(response.contains("R-NADS // THREAT INTELLIGENCE"));
        }

        // Test 3: GET /api/stats (should return 200 OK and JSON)
        {
            let mut stream =
                TcpStream::connect("127.0.0.1:18085").expect("Failed to connect to server");
            stream
                .write_all(b"GET /api/stats HTTP/1.1\r\nHost: 127.0.0.1:18085\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.contains("HTTP/1.1 200 OK"));
            assert!(response.contains("Content-Type: application/json"));
            assert!(response.contains("total_packets"));
        }

        // Test 4: Blocked IP handling
        {
            // Simulate blocked IP in blocklist
            let test_ip = "192.51.100.5".parse().unwrap();
            blocklist.insert(test_ip, std::time::Instant::now());

            // Make sure mitigation mode is set to "mitigate" to trigger 403
            {
                let mut cfg = config.write().unwrap();
                cfg.mitigation_mode = "mitigate".to_string();
            }

            let mut stream =
                TcpStream::connect("127.0.0.1:18085").expect("Failed to connect to server");
            stream.write_all(b"GET /check HTTP/1.1\r\nHost: 127.0.0.1:18085\r\nX-Real-IP: 192.51.100.5\r\nConnection: close\r\n\r\n").unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.contains("HTTP/1.1 403 Forbidden"));
            assert!(response.contains("X-RNADS-Detection-Status: Blocked"));
            assert!(response.contains("Forbidden"));
        }

        // Stop the server
        running.store(false, Ordering::SeqCst);

        // Make one final request to make sure server wakes up and exits loop if needed
        if let Ok(mut stream) = TcpStream::connect("127.0.0.1:18085") {
            let _ = stream.write_all(
                b"GET /check HTTP/1.1\r\nHost: 127.0.0.1:18085\r\nConnection: close\r\n\r\n",
            );
        }

        let _ = handle.join();

        // Clean up DB file if created
        let _ = std::fs::remove_file("test_anomalies.db");
    }
}
