use r_nads_aggregator::FlowMetrics;
use r_nads_events::AnomalyAlert;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::SystemTime;

/// The dimension D for the Random Fourier Features space.
pub const PROJECTION_DIM: usize = 256;

/// Global static configuration for model weights to avoid heap indirection and runtime disk reads.
pub static MODEL_CONFIG: OnceLock<ModelConfig> = OnceLock::new();

pub mod serde_arrays {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize_256<S>(array: &[f64; 256], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(256))?;
        for &val in array {
            seq.serialize_element(&val)?;
        }
        seq.end()
    }

    pub fn deserialize_256<'de, D>(deserializer: D) -> Result<[f64; 256], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<f64>::deserialize(deserializer)?;
        if vec.len() == 256 {
            let mut arr = [0.0; 256];
            arr.copy_from_slice(&vec);
            Ok(arr)
        } else {
            Err(serde::de::Error::custom(format!(
                "Expected array of length 256, found {}",
                vec.len()
            )))
        }
    }

    pub fn serialize_256_12<S>(matrix: &[[f64; 12]; 256], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(256))?;
        for row in matrix {
            seq.serialize_element(row)?;
        }
        seq.end()
    }

    pub fn deserialize_256_12<'de, D>(deserializer: D) -> Result<[[f64; 12]; 256], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<[f64; 12]>::deserialize(deserializer)?;
        if vec.len() == 256 {
            let mut arr = [[0.0; 12]; 256];
            arr.copy_from_slice(&vec);
            Ok(arr)
        } else {
            Err(serde::de::Error::custom(format!(
                "Expected matrix of 256 rows, found {}",
                vec.len()
            )))
        }
    }
}

/// Model configuration loaded upon startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    /// Configurable threshold R^2
    pub threshold: f64,
    /// Means of the 12 features
    pub means: [f64; 12],
    /// Standard deviations of the 12 features
    pub stddevs: [f64; 12],
    /// SVDD hypersphere centroid vector c of size 256
    #[serde(
        serialize_with = "serde_arrays::serialize_256",
        deserialize_with = "serde_arrays::deserialize_256"
    )]
    pub centroid: [f64; PROJECTION_DIM],
    /// RFF projection bias vector b of size 256
    #[serde(
        serialize_with = "serde_arrays::serialize_256",
        deserialize_with = "serde_arrays::deserialize_256"
    )]
    pub b_vector: [f64; PROJECTION_DIM],
    /// RFF projection weight matrix W of size 256 x 12
    #[serde(
        serialize_with = "serde_arrays::serialize_256_12",
        deserialize_with = "serde_arrays::deserialize_256_12"
    )]
    pub w_matrix: [[f64; 12]; PROJECTION_DIM],
}

/// Anomaly classification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResult {
    /// Squared Euclidean distance in RFF space
    pub distance_sq: f64,
    /// Boolean indicating if the flow is anomalous (distance_sq > threshold)
    pub is_anomaly: bool,
}

/// Support Vector Data Description (SVDD) classifier with Random Fourier Features (RFF).
pub struct InferenceEngine;

impl InferenceEngine {
    /// Performs real-time anomaly detection on a set of flow features.
    /// Runs in O(D * d) time with zero heap allocations on the hot path.
    #[inline]
    #[allow(clippy::needless_range_loop)]
    pub fn predict(metrics: &FlowMetrics) -> InferenceResult {
        let config = MODEL_CONFIG
            .get()
            .expect("MODEL_CONFIG must be initialized");

        // 1. Z-Score Normalization
        let x = [
            metrics.mean_len,
            metrics.var_len.sqrt(),
            metrics.packet_rate,
            metrics.byte_rate,
            metrics.fwd_bwd_ratio,
            metrics.syn_ratio,
            metrics.rst_ratio,
            metrics.fin_ratio,
            metrics.psh_ratio,
            metrics.ack_ratio,
            metrics.mean_interval,
            metrics.var_interval.sqrt(),
        ];

        let mut z = [0.0; 12];
        for i in 0..12 {
            z[i] = (x[i] - config.means[i]) / config.stddevs[i].max(1e-7);
        }

        // 2. Random Fourier Features (RFF) mapping
        let scale = (2.0 / PROJECTION_DIM as f64).sqrt();
        let mut z_projected = [0.0; PROJECTION_DIM];

        for j in 0..PROJECTION_DIM {
            let mut proj = 0.0;
            let w_row = &config.w_matrix[j];
            for i in 0..12 {
                proj += w_row[i] * z[i];
            }
            proj += config.b_vector[j];
            z_projected[j] = scale * proj.cos();
        }

        // 3. Exact Squared Euclidean Distance to Centroid
        let distance_sq = Self::euclidean_distance_sq(&z_projected, &config.centroid);

        InferenceResult {
            distance_sq,
            is_anomaly: distance_sq > config.threshold,
        }
    }

    /// Computes squared Euclidean distance.
    #[inline]
    pub fn euclidean_distance_sq(a: &[f64; PROJECTION_DIM], b: &[f64; PROJECTION_DIM]) -> f64 {
        let mut sum = 0.0;
        for i in 0..PROJECTION_DIM {
            let diff = a[i] - b[i];
            sum += diff * diff;
        }
        sum
    }

    /// Creates an AnomalyAlert struct from flow metrics and inference result.
    pub fn create_alert(metrics: &FlowMetrics, result: &InferenceResult) -> AnomalyAlert {
        let config = MODEL_CONFIG
            .get()
            .expect("MODEL_CONFIG must be initialized");
        AnomalyAlert {
            src_ip: metrics.src_ip.to_string(),
            dest_ip: metrics.dest_ip.to_string(),
            src_port: metrics.src_port,
            dest_port: metrics.dest_port,
            protocol: metrics.protocol,
            timestamp: SystemTime::now(),
            score: result.distance_sq,
            threshold: config.threshold,
            mean_len: metrics.mean_len,
            var_len: metrics.var_len,
            packet_rate: metrics.packet_rate,
            byte_rate: metrics.byte_rate,
            fwd_bwd_ratio: metrics.fwd_bwd_ratio,
            syn_ratio: metrics.syn_ratio,
            rst_ratio: metrics.rst_ratio,
            fin_ratio: metrics.fin_ratio,
            psh_ratio: metrics.psh_ratio,
            ack_ratio: metrics.ack_ratio,
            mean_interval: metrics.mean_interval,
            var_interval: metrics.var_interval,
        }
    }

    /// Trains SVDD model, calibrates Gamma via the median trick, and computes centroids.
    #[allow(clippy::needless_range_loop)]
    pub fn train(
        samples: &[FlowMetrics],
    ) -> Result<ModelConfig, Box<dyn std::error::Error + Send + Sync>> {
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

        let projection_dim = PROJECTION_DIM;
        let std_dev_proj = (2.0 * gamma).sqrt();

        let mut w_matrix = [[0.0; 12]; PROJECTION_DIM];
        let mut b_vector = [0.0; PROJECTION_DIM];

        for j in 0..projection_dim {
            for i in 0..12 {
                w_matrix[j][i] = rng.next_gaussian() * std_dev_proj;
            }
            b_vector[j] = rng.next_f64() * 2.0 * std::f64::consts::PI;
        }

        // 5. Project samples to RFF space
        let mut phi_matrix = vec![[0.0; PROJECTION_DIM]; n];
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
        let mut centroid = [0.0; PROJECTION_DIM];
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
}

#[cfg(test)]
#[allow(clippy::needless_range_loop)]
mod tests {
    use super::*;

    #[test]
    fn test_euclidean_distance_sq() {
        let mut a = [0.0; PROJECTION_DIM];
        let mut b = [0.0; PROJECTION_DIM];

        for i in 0..PROJECTION_DIM {
            a[i] = i as f64;
            b[i] = (i + 1) as f64;
        }

        let dist = InferenceEngine::euclidean_distance_sq(&a, &b);
        assert_eq!(dist, PROJECTION_DIM as f64);
    }

    #[test]
    fn test_model_config_serialization() {
        let mut w_matrix = [[0.0; 12]; PROJECTION_DIM];
        let mut centroid = [0.0; PROJECTION_DIM];
        let mut b_vector = [0.0; PROJECTION_DIM];

        for i in 0..PROJECTION_DIM {
            centroid[i] = i as f64 * 0.1;
            b_vector[i] = i as f64 * 0.2;
            for j in 0..12 {
                w_matrix[i][j] = (i + j) as f64 * 0.01;
            }
        }

        let config = ModelConfig {
            threshold: 1.25,
            means: [
                1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0,
            ],
            stddevs: [0.1; 12],
            centroid,
            b_vector,
            w_matrix,
        };

        let serialized = serde_json::to_string(&config).expect("Failed to serialize");
        let deserialized: ModelConfig =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert!((deserialized.threshold - config.threshold).abs() < 1e-9);
        for i in 0..12 {
            assert!((deserialized.means[i] - config.means[i]).abs() < 1e-9);
            assert!((deserialized.stddevs[i] - config.stddevs[i]).abs() < 1e-9);
        }
        for i in 0..PROJECTION_DIM {
            assert!((deserialized.centroid[i] - config.centroid[i]).abs() < 1e-9);
            assert!((deserialized.b_vector[i] - config.b_vector[i]).abs() < 1e-9);
            for j in 0..12 {
                assert!((deserialized.w_matrix[i][j] - config.w_matrix[i][j]).abs() < 1e-9);
            }
        }
    }

    #[test]
    fn test_svdd_prediction() {
        let mut w_matrix = [[0.0; 12]; PROJECTION_DIM];
        let mut centroid = [0.0; PROJECTION_DIM];
        let mut b_vector = [0.0; PROJECTION_DIM];

        for i in 0..PROJECTION_DIM {
            centroid[i] = 0.5;
            b_vector[i] = 0.1;
            for j in 0..12 {
                w_matrix[i][j] = 0.05;
            }
        }

        let dummy_config = ModelConfig {
            threshold: 0.1,
            means: [10.0; 12],
            stddevs: [1.0; 12],
            centroid,
            b_vector,
            w_matrix,
        };

        let _ = MODEL_CONFIG.set(dummy_config);

        let normal_metrics = FlowMetrics {
            src_ip: "127.0.0.1".parse().unwrap(),
            dest_ip: "127.0.0.2".parse().unwrap(),
            src_port: 1234,
            dest_port: 80,
            protocol: 6,
            key: r_nads_common::FlowKey::new(
                "127.0.0.1".parse().unwrap(),
                1234,
                "127.0.0.2".parse().unwrap(),
                80,
                6,
            ),
            packet_count: 5,
            mean_len: 10.0,
            var_len: 1.0,
            packet_rate: 10.0,
            byte_rate: 10.0,
            fwd_bwd_ratio: 1.0,
            syn_ratio: 0.0,
            rst_ratio: 0.0,
            fin_ratio: 0.0,
            psh_ratio: 0.0,
            ack_ratio: 1.0,
            mean_interval: 10.0,
            var_interval: 1.0,
        };

        let result = InferenceEngine::predict(&normal_metrics);
        assert!(result.distance_sq >= 0.0);

        let alert = InferenceEngine::create_alert(&normal_metrics, &result);
        assert_eq!(alert.src_ip, "127.0.0.1");
        assert_eq!(alert.dest_ip, "127.0.0.2");
        assert_eq!(alert.score, result.distance_sq);
    }
}
