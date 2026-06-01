use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use hashbrown::HashMap;
use slab::Slab;
use r_nads_common::{FlowKey, PacketEvent, Direction};

/// Window size K for sliding window behavioral analytics.
pub const WINDOW_SIZE: usize = 128;

/// Summary of a single packet inside a flow's sliding window.
#[derive(Debug, Clone, Copy)]
pub struct PacketSummary {
    pub timestamp_ms: u64,
    pub len: u32,
    pub direction: Direction,
    pub tcp_flags: u8,
}

impl Default for PacketSummary {
    fn default() -> Self {
        Self {
            timestamp_ms: 0,
            len: 0,
            direction: Direction::Forward,
            tcp_flags: 0,
        }
    }
}

/// Sliding window rolling metrics for a single network flow.
/// Pre-allocated buffer of size WINDOW_SIZE to guarantee O(1) zero-allocation updates.
#[derive(Debug, Clone)]
pub struct FlowState {
    pub initiator_ip: IpAddr,
    pub total_packets: u64,
    pub buffer: [PacketSummary; WINDOW_SIZE],
    pub head: usize,
    pub count: usize,

    // Rolling aggregates inside the sliding window
    pub packets_fwd: u32,
    pub packets_bwd: u32,
    pub bytes_fwd: u64,
    pub bytes_bwd: u64,
    pub syn_count: u32,
    pub rst_count: u32,
    pub sum_len: u64,
    pub sum_len_sq: u64,
}

impl FlowState {
    pub fn new(initiator_ip: IpAddr) -> Self {
        Self {
            initiator_ip,
            total_packets: 0,
            buffer: [PacketSummary::default(); WINDOW_SIZE],
            head: 0,
            count: 0,
            packets_fwd: 0,
            packets_bwd: 0,
            bytes_fwd: 0,
            bytes_bwd: 0,
            syn_count: 0,
            rst_count: 0,
            sum_len: 0,
            sum_len_sq: 0,
        }
    }

    /// Updates the sliding window with a new packet, evicting the oldest packet if the window is full.
    /// Updates rolling statistical aggregates in O(1) time with no allocations.
    pub fn update(&mut self, timestamp: SystemTime, len: u32, direction: Direction, tcp_flags: Option<u8>) {
        self.total_packets += 1;

        let timestamp_ms = timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let flags = tcp_flags.unwrap_or(0);

        let new_pkt = PacketSummary {
            timestamp_ms,
            len,
            direction,
            tcp_flags: flags,
        };

        // If the window is full, we must evict the oldest packet at `self.head` from the aggregates
        if self.count == WINDOW_SIZE {
            let old_pkt = self.buffer[self.head];
            
            // Subtract old packet stats from rolling aggregates
            self.sum_len -= old_pkt.len as u64;
            self.sum_len_sq -= (old_pkt.len as u64) * (old_pkt.len as u64);

            match old_pkt.direction {
                Direction::Forward => {
                    self.packets_fwd -= 1;
                    self.bytes_fwd -= old_pkt.len as u64;
                }
                Direction::Backward => {
                    self.packets_bwd -= 1;
                    self.bytes_bwd -= old_pkt.len as u64;
                }
            }

            if (old_pkt.tcp_flags & 0x02) != 0 {
                self.syn_count -= 1;
            }
            if (old_pkt.tcp_flags & 0x04) != 0 {
                self.rst_count -= 1;
            }
        }

        // Add the new packet to rolling aggregates
        self.sum_len += len as u64;
        self.sum_len_sq += (len as u64) * (len as u64);

        match direction {
            Direction::Forward => {
                self.packets_fwd += 1;
                self.bytes_fwd += len as u64;
            }
            Direction::Backward => {
                self.packets_bwd += 1;
                self.bytes_bwd += len as u64;
            }
        }

        if (flags & 0x02) != 0 {
            self.syn_count += 1;
        }
        if (flags & 0x04) != 0 {
            self.rst_count += 1;
        }

        // Write new packet to buffer and advance write pointer
        self.buffer[self.head] = new_pkt;
        self.head = (self.head + 1) % WINDOW_SIZE;

        if self.count < WINDOW_SIZE {
            self.count += 1;
        }
    }

    /// Computes aggregated statistical features for ML engine input.
    pub fn compute_metrics(&self, key: FlowKey) -> FlowMetrics {
        let count = self.count.max(1) as f64;
        let mean_len = self.sum_len as f64 / count;
        
        // Variance calculation using rolling integer squared sums (precise, zero drift)
        let variance_len = ((self.sum_len_sq as f64) / count) - (mean_len * mean_len);
        let var_len = variance_len.max(0.0); // handle slight floating point inaccuracies

        // Find oldest and newest packet timestamps in the window to compute rates
        let mut min_ts = u64::MAX;
        let mut max_ts = 0u64;
        for i in 0..self.count {
            let ts = self.buffer[i].timestamp_ms;
            if ts < min_ts { min_ts = ts; }
            if ts > max_ts { max_ts = ts; }
        }

        let duration_ms = if self.count > 1 && max_ts > min_ts {
            max_ts - min_ts
        } else {
            1 // Default to 1ms to avoid divide by zero
        };

        let duration_secs = duration_ms as f64 / 1000.0;
        let packet_rate = self.count as f64 / duration_secs;
        let byte_rate = (self.bytes_fwd + self.bytes_bwd) as f64 / duration_secs;

        let fwd_bwd_ratio = self.packets_fwd as f64 / (self.packets_bwd.max(1) as f64);
        let syn_ratio = self.syn_count as f64 / count;

        FlowMetrics {
            key,
            timestamp: SystemTime::now(),
            packet_count: self.total_packets,
            mean_len,
            var_len,
            packet_rate,
            byte_rate,
            fwd_bwd_ratio,
            syn_ratio,
        }
    }
}

/// Extracted features ready for the One-Class SVM inference engine.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlowMetrics {
    pub key: FlowKey,
    pub timestamp: SystemTime,
    pub packet_count: u64,
    pub mean_len: f64,
    pub var_len: f64,
    pub packet_rate: f64,
    pub byte_rate: f64,
    pub fwd_bwd_ratio: f64,
    pub syn_ratio: f64,
}

/// Thread-local pre-allocated flow table with constant memory footprint and LRU eviction.
pub struct FlowTable {
    map: HashMap<FlowKey, usize>,     // Map FlowKey to Slab index
    slab: Slab<LruNode>,            // Pre-allocated slab storing flow state and LRU links
    capacity: usize,
    lru_head: Option<usize>,        // Index of most recently used node
    lru_tail: Option<usize>,        // Index of least recently used node
}

struct LruNode {
    key: FlowKey,
    state: FlowState,
    prev: Option<usize>,
    next: Option<usize>,
}

impl FlowTable {
    /// Creates a new FlowTable with a fixed capacity limit.
    pub fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            slab: Slab::with_capacity(capacity),
            capacity,
            lru_head: None,
            lru_tail: None,
        }
    }

    /// Process a new packet event.
    /// Updates the flow's sliding window and returns the updated features.
    /// If the table exceeds its capacity, the oldest inactive flow is evicted.
    pub fn process_packet(&mut self, event: &PacketEvent) -> FlowMetrics {
        let key = event.flow_key();

        if let Some(&slab_idx) = self.map.get(&key) {
            // Flow exists: Update LRU order and process packet
            self.promote_lru(slab_idx);
            
            let node = &mut self.slab[slab_idx];
            let direction = if event.src_ip == node.state.initiator_ip {
                Direction::Forward
            } else {
                Direction::Backward
            };

            node.state.update(event.timestamp, event.len, direction, event.tcp_flags);
            node.state.compute_metrics(key)
        } else {
            // New flow: Check capacity first
            let slab_idx = if self.slab.len() >= self.capacity {
                // Table is full: Evict least recently used flow
                let evicted_idx = self.lru_tail.expect("LRU tail cannot be None when Slab is full");
                self.evict_node(evicted_idx);
                evicted_idx
            } else {
                // Slab has free capacity: allocate new slot
                self.slab.vacant_entry().key()
            };

            // Initialize new flow state
            let state = FlowState::new(event.src_ip);
            let mut new_node = LruNode {
                key,
                state,
                prev: None,
                next: None,
            };

            // Ingest the first packet
            new_node.state.update(event.timestamp, event.len, Direction::Forward, event.tcp_flags);
            let metrics = new_node.state.compute_metrics(key);

            // Insert into slab and map
            if slab_idx == self.slab.len() {
                self.slab.insert(new_node);
            } else {
                // Recycle the evicted slot
                self.slab[slab_idx] = new_node;
            }
            self.map.insert(key, slab_idx);

            // Insert at the head of LRU
            self.link_lru_head(slab_idx);

            metrics
        }
    }

    /// Number of active flows in the table.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Promote a node to the head of the LRU list (most recently used).
    fn promote_lru(&mut self, idx: usize) {
        if Some(idx) == self.lru_head {
            return; // Already at the head
        }
        self.unlink_lru(idx);
        self.link_lru_head(idx);
    }

    /// Evict a node by slab index.
    fn evict_node(&mut self, idx: usize) {
        let node = &self.slab[idx];
        self.map.remove(&node.key);
        self.unlink_lru(idx);
        // Note: slab item is left there; it will be overwritten when recycled
    }

    /// Link a node as the new LRU head.
    fn link_lru_head(&mut self, idx: usize) {
        let old_head = self.lru_head;
        self.slab[idx].prev = None;
        self.slab[idx].next = old_head;

        if let Some(h) = old_head {
            self.slab[h].prev = Some(idx);
        } else {
            // First node in the list
            self.lru_tail = Some(idx);
        }
        self.lru_head = Some(idx);
    }

    /// Unlink a node from its current position in the LRU list.
    fn unlink_lru(&mut self, idx: usize) {
        let prev = self.slab[idx].prev;
        let next = self.slab[idx].next;

        if let Some(p) = prev {
            self.slab[p].next = next;
        } else {
            self.lru_head = next;
        }

        if let Some(n) = next {
            self.slab[n].prev = prev;
        } else {
            self.lru_tail = prev;
        }

        self.slab[idx].prev = None;
        self.slab[idx].next = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::{SystemTime, Duration};

    #[test]
    fn test_flow_state_aggregates() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut state = FlowState::new(ip);
        
        let start = SystemTime::now();

        // Feed 3 packets: 100 bytes forward, 200 bytes backward, 300 bytes forward
        state.update(start, 100, Direction::Forward, Some(0x02));
        state.update(start + Duration::from_millis(100), 200, Direction::Backward, Some(0x10));
        state.update(start + Duration::from_millis(200), 300, Direction::Forward, Some(0x04));

        let key = FlowKey::new(ip, 1234, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80, 6);
        let metrics = state.compute_metrics(key);

        assert_eq!(metrics.packet_count, 3);
        assert_eq!(state.packets_fwd, 2);
        assert_eq!(state.packets_bwd, 1);
        assert_eq!(state.bytes_fwd, 400);
        assert_eq!(state.bytes_bwd, 200);
        assert_eq!(state.syn_count, 1);
        assert_eq!(state.rst_count, 1);
        
        // Mean should be (100 + 200 + 300) / 3 = 200.0
        assert_eq!(metrics.mean_len, 200.0);

        // Sum of squares = 100^2 + 200^2 + 300^2 = 140000
        // Variance = 140000 / 3 - 200^2 = 46666.6667 - 40000 = 6666.6667
        assert!((metrics.var_len - 6666.6667).abs() < 0.1);

        // Duration is 200ms = 0.2s. 3 packets / 0.2s = 15.0 packets/sec
        assert_eq!(metrics.packet_rate, 15.0);
        // Bytes rate is 600 bytes / 0.2s = 3000 bytes/sec
        assert_eq!(metrics.byte_rate, 3000.0);
    }

    #[test]
    fn test_flow_table_lru_eviction() {
        // Table capacity 2
        let mut table = FlowTable::new(2);
        
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let dest = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        let make_packet = |src, dest, port| PacketEvent {
            timestamp: SystemTime::now(),
            len: 64,
            src_ip: src,
            dest_ip: dest,
            src_port: port,
            dest_port: 80,
            protocol: 6,
            tcp_flags: None,
        };

        // Ingest flow 1
        table.process_packet(&make_packet(ip1, dest, 1001));
        assert_eq!(table.len(), 1);

        // Ingest flow 2
        table.process_packet(&make_packet(ip2, dest, 1002));
        assert_eq!(table.len(), 2);

        // Access flow 1 again (making it most recently used)
        table.process_packet(&make_packet(ip1, dest, 1001));

        // Ingest flow 3 (should trigger eviction of flow 2, since flow 1 was recently accessed)
        table.process_packet(&make_packet(ip3, dest, 1003));
        assert_eq!(table.len(), 2);

        // Check that flow 1 and 3 are present, and flow 2 was evicted
        let key1 = FlowKey::new(ip1, 1001, dest, 80, 6);
        let key2 = FlowKey::new(ip2, 1002, dest, 80, 6);
        let key3 = FlowKey::new(ip3, 1003, dest, 80, 6);

        assert!(table.map.contains_key(&key1));
        assert!(table.map.contains_key(&key3));
        assert!(!table.map.contains_key(&key2));
    }
}
