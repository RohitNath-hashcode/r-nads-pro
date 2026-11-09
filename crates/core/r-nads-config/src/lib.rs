use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

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

/// Full application configuration wrapping the system table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub system: SystemConfig,
}

impl AppConfig {
    /// Loads and parses an AppConfig from a file path.
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = std::fs::read_to_string(path)?;
        let parsed = toml::from_str::<AppConfig>(&content)?;
        Ok(parsed)
    }
}

/// Spawns a background thread that monitors config.toml for file-modification changes
/// and updates the shared SystemConfig lock dynamically.
pub fn spawn_config_watcher(
    config_path: String,
    shared_config: Arc<RwLock<SystemConfig>>,
    running: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("config-watcher".to_string())
        .spawn(move || {
            let mut last_metadata = std::fs::metadata(&config_path)
                .and_then(|m| m.modified())
                .unwrap_or_else(|_| std::time::SystemTime::now());

            println!(
                "[Watcher] Configuration watcher started for '{}'.",
                config_path
            );

            while running.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(2));

                if let Ok(metadata) = std::fs::metadata(&config_path) {
                    if let Ok(modified) = metadata.modified() {
                        if modified > last_metadata {
                            last_metadata = modified;
                            println!(
                                "[Watcher] Configuration file modification detected. Reloading..."
                            );

                            match std::fs::read_to_string(&config_path) {
                                Ok(content) => match toml::from_str::<AppConfig>(&content) {
                                    Ok(new_app_cfg) => {
                                        let mut write_lock = shared_config.write().unwrap();
                                        *write_lock = new_app_cfg.system;
                                        println!(
                                            "[Watcher] Configuration reloaded successfully. Mitigation Mode: {}, TTL: {}s",
                                            write_lock.mitigation_mode, write_lock.block_list_ttl
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "[Watcher] Failed to parse configuration file during reload: {}",
                                            e
                                        );
                                    }
                                },
                                Err(e) => {
                                    eprintln!(
                                        "[Watcher] Failed to read configuration file during reload: {}",
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
            }
            println!("[Watcher] Configuration watcher thread exiting.");
        })
        .expect("Failed to spawn config watcher thread")
}

