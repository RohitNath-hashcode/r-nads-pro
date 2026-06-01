use std::time::SystemTime;
use serde::{Serialize, Deserialize};
use r_nads_common::AnomalyAlert;
use r_nads_aggregator::FlowMetrics;

/// Model configuration representing the trained normal baseline,
/// including normalization parameters, random projection weights (RFF), and decision boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    /// Dimension of the Random Fourier Features (RFF) space (e.g., 128)
    pub projection_dim: usize,
    /// Means of the 6 features
    pub means: [f64; 6],
    /// Standard deviations of the 6 features
    pub stddevs: [f64; 6],
    /// RFF random projection matrix W of size [projection_dim][6]
    pub w_matrix: Vec<Vec<f64>>,
    /// RFF projection bias vector b of size [projection_dim]
    pub b_vector: Vec<f64>,
    /// SVDD hypersphere center vector w of size [projection_dim]
    pub weights: Vec<f64>,
    /// SVDD hypersphere center squared norm ||w||^2
    pub weights_norm_sq: f64,
    /// Anomaly decision threshold (squared distance)
    pub threshold: f64,
}

/// Anomaly classification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResult {
    /// Distance from the normal hypersphere center in the RFF feature space.
    pub distance: f64,
    /// Boolean indicating if the flow is classified as anomalous.
    pub is_anomaly: bool,
}

/// Outlier/Anomaly Detector based on One-Class Support Vector Machines (OC-SVM) / SVDD
/// optimized using Random Fourier Features (RFF).
pub struct InferenceEngine {
    config: ModelConfig,
}

impl InferenceEngine {
    /// Creates a new InferenceEngine with the loaded configuration.
    pub fn new(config: ModelConfig) -> Self {
        Self { config }
    }

    /// Performs real-time outlier detection on a set of flow features.
    /// Runs in O(D * d) time with zero heap allocations on the hot path.
    pub fn predict(&self, metrics: &FlowMetrics) -> InferenceResult {
        // 1. Extract and normalize the 6 statistical features
        let x = [
            metrics.mean_len,
            metrics.var_len.sqrt(), // StdDev of packet length
            metrics.packet_rate,
            metrics.byte_rate,
            metrics.fwd_bwd_ratio,
            metrics.syn_ratio,
        ];

        let mut z = [0.0; 6];
        for i in 0..6 {
            z[i] = (x[i] - self.config.means[i]) / self.config.stddevs[i].max(1e-7);
        }

        // 2. Project normalized vector into Random Fourier Features space (RFF mapping)
        // Phi(z) = sqrt(2/D) * cos(W * z + b)
        let d = self.config.projection_dim;
        let scale = (2.0 / d as f64).sqrt();
        let mut w_dot_phi = 0.0;

        // Perform matrix-vector multiply and dot product in a single loop to maximize cache hits
        for j in 0..d {
            let mut projection = 0.0;
            let w_row = &self.config.w_matrix[j];
            for i in 0..6 {
                projection += w_row[i] * z[i];
            }
            projection += self.config.b_vector[j];

            let phi_j = scale * projection.cos();
            w_dot_phi += self.config.weights[j] * phi_j;
        }

        // 3. Compute SVDD hypersphere distance squared:
        // dist_sq = ||Phi(z) - w||^2 = ||Phi(z)||^2 - 2 * <Phi(z), w> + ||w||^2
        // Since ||Phi(z)||^2 is approximately 1.0 (cos^2 expectation):
        let dist_sq = (1.0 - 2.0 * w_dot_phi + self.config.weights_norm_sq).max(0.0);

        InferenceResult {
            distance: dist_sq.sqrt(),
            is_anomaly: dist_sq > self.config.threshold,
        }
    }

    /// Helper to convert an InferenceResult and FlowMetrics into an AnomalyAlert.
    pub fn create_alert(&self, metrics: &FlowMetrics, result: &InferenceResult) -> AnomalyAlert {
        AnomalyAlert {
            key: metrics.key,
            timestamp: SystemTime::now(),
            score: result.distance,
            threshold: self.config.threshold.sqrt(),
            mean_len: metrics.mean_len,
            var_len: metrics.var_len,
            packet_rate: metrics.packet_rate,
            byte_rate: metrics.byte_rate,
            fwd_bwd_ratio: metrics.fwd_bwd_ratio,
            syn_ratio: metrics.syn_ratio,
        }
    }

    /// Get a reference to the underlying configuration
    pub fn config(&self) -> &ModelConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r_nads_common::FlowKey;

    #[test]
    fn test_inference_engine() {
        let means = [100.0, 10.0, 1000.0, 10000.0, 1.0, 0.1];
        let stddevs = [10.0, 2.0, 100.0, 1000.0, 0.2, 0.05];

        // 16-dimensional projection
        let projection_dim = 16;
        let w_matrix = vec![vec![0.5; 6]; projection_dim];
        let b_vector = vec![0.1; projection_dim];
        
        // Let's set SVDD center w to a mock projection vector
        let weights = vec![0.1; projection_dim];
        let weights_norm_sq = weights.iter().map(|v| v * v).sum();

        let config = ModelConfig {
            projection_dim,
            means,
            stddevs,
            w_matrix,
            b_vector,
            weights,
            weights_norm_sq,
            threshold: 0.8, // squared distance threshold
        };

        let engine = InferenceEngine::new(config);

        let key = FlowKey::new(
            "10.0.0.1".parse().unwrap(),
            1234,
            "10.0.0.2".parse().unwrap(),
            80,
            6,
        );

        // A normal packet event matching the mean
        let normal_metrics = FlowMetrics {
            key,
            timestamp: SystemTime::now(),
            packet_count: 10,
            mean_len: 100.0,
            var_len: 100.0, // standard dev = 10.0
            packet_rate: 1000.0,
            byte_rate: 10000.0,
            fwd_bwd_ratio: 1.0,
            syn_ratio: 0.1,
        };

        // An anomalous packet event (e.g. extremely high packet rate and SYN ratio)
        let anomalous_metrics = FlowMetrics {
            key,
            timestamp: SystemTime::now(),
            packet_count: 500,
            mean_len: 100.0,
            var_len: 100.0,
            packet_rate: 8000.0, // extremely high! (mean is 1000.0, stddev is 100.0)
            byte_rate: 80000.0, // extremely high!
            fwd_bwd_ratio: 1.0,
            syn_ratio: 0.9,     // extremely high SYN flood! (mean is 0.1, stddev is 0.05)
        };

        let res_normal = engine.predict(&normal_metrics);
        let res_anomaly = engine.predict(&anomalous_metrics);

        println!("Normal distance: {}, Anomaly: {}", res_normal.distance, res_normal.is_anomaly);
        println!("Anomalous distance: {}, Anomaly: {}", res_anomaly.distance, res_anomaly.is_anomaly);

        // The anomalous metrics should yield a much higher distance from the normal weights center
        assert!(res_anomaly.distance > res_normal.distance);
        assert!(!res_normal.is_anomaly, "Normal sample classified as anomaly");
        assert!(res_anomaly.is_anomaly, "Anomalous sample not classified as anomaly");
    }
}
