pub mod analysis;
pub mod capture;
pub mod mitigation;
pub mod ml;

use serde::{Deserialize, Serialize};

/// System configuration section of config.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    pub mode: String,
    pub workers: usize,
    pub capacity: usize,
    pub database_path: String,
    pub log_path: String,
    pub block_list_ttl: u64,
    pub nginx_bind: String,
    pub capture_source: String,
    pub pps: u64,
    pub flows: u32,
    pub pcap_file: Option<String>,
    pub interface: Option<String>,
    pub training_samples: usize,
    pub mitigation_mode: String,
    pub model_path: String,
}

/// Full application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub system: SystemConfig,
}
