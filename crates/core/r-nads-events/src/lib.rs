use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Alert details for a detected flow anomaly, formatted for SQLite and text log sinks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyAlert {
    pub src_ip: String,
    pub dest_ip: String,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: u8,
    pub timestamp: SystemTime,
    pub score: f64,
    pub threshold: f64,
    pub mean_len: f64,
    pub var_len: f64,
    pub packet_rate: f64,
    pub byte_rate: f64,
    pub fwd_bwd_ratio: f64,
    pub syn_ratio: f64,
    pub rst_ratio: f64,
    pub fin_ratio: f64,
    pub psh_ratio: f64,
    pub ack_ratio: f64,
    pub mean_interval: f64,
    pub var_interval: f64,
}

impl AnomalyAlert {
    /// Formats the alert as a single-line log entry.
    pub fn to_log_line(&self) -> String {
        let ts_secs = self
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!(
            "[{ts_secs}] ANOMALY: {} -> {} | Score: {:.4} | Pkts/sec: {:.1} | Bytes/sec: {:.1} | SYN ratio: {:.2}\n",
            self.src_ip, self.dest_ip, self.score, self.packet_rate, self.byte_rate, self.syn_ratio
        )
    }
}
