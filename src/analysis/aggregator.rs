use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use slab::Slab;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Window size K for sliding window behavioral analytics.
pub const WINDOW_SIZE: usize = 128;

/// Direction of a packet in a flow relative to the flow initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Forward,
    Backward,
}

/// Bidirectional 5-tuple identifying a network flow.
/// The fields are ordered symmetrically to ensure that traffic from A -> B and B -> A
/// maps to the same FlowKey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub ip_min: IpAddr,
    pub ip_max: IpAddr,
    pub port_min: u16,
    pub port_max: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// Creates a new symmetric FlowKey from packet properties.
    #[inline]
    pub fn new(
        src_ip: IpAddr,
        src_port: u16,
        dest_ip: IpAddr,
        dest_port: u16,
        protocol: u8,
    ) -> Self {
        let (ip_min, port_min, ip_max, port_max) = if src_ip < dest_ip {
            (src_ip, src_port, dest_ip, dest_port)
        } else if src_ip > dest_ip {
            (dest_ip, dest_port, src_ip, src_port)
        } else {
            // IPs are equal (e.g. loopback)
            if src_port <= dest_port {
                (src_ip, src_port, dest_ip, dest_port)
            } else {
                (dest_ip, dest_port, src_ip, src_port)
            }
        };

        Self {
            ip_min,
            ip_max,
            port_min,
            port_max,
            protocol,
        }
    }
}

/// A parsed packet event sent from the Ingestion Engine (Producer) to the Aggregators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEvent {
    pub timestamp: SystemTime,
    pub len: u32,
    pub src_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: u8,
    pub tcp_flags: Option<u8>,
}

impl PacketEvent {
    /// Helper to get the FlowKey for this packet.
    #[inline]
    pub fn flow_key(&self) -> FlowKey {
        FlowKey::new(
            self.src_ip,
            self.src_port,
            self.dest_ip,
            self.dest_port,
            self.protocol,
        )
    }
}

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
    pub fin_count: u32,
    pub psh_count: u32,
    pub ack_count: u32,
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
            fin_count: 0,
            psh_count: 0,
            ack_count: 0,
            sum_len: 0,
            sum_len_sq: 0,
        }
    }

    /// Reset the flow state to allow zero-allocation memory recycling inside the Slab.
    pub fn reset(&mut self, initiator_ip: IpAddr) {
        self.initiator_ip = initiator_ip;
        self.total_packets = 0;
        self.head = 0;
        self.count = 0;
        self.packets_fwd = 0;
        self.packets_bwd = 0;
        self.bytes_fwd = 0;
        self.bytes_bwd = 0;
        self.syn_count = 0;
        self.rst_count = 0;
        self.fin_count = 0;
        self.psh_count = 0;
        self.ack_count = 0;
        self.sum_len = 0;
        self.sum_len_sq = 0;
        // The buffer array is left as is since it will be overwritten lazily.
    }

    /// Updates the sliding window with a new packet, evicting the oldest packet if the window is full.
    /// Updates rolling statistical aggregates in O(1) time with no allocations.
    pub fn update(
        &mut self,
        timestamp: SystemTime,
        len: u32,
        direction: Direction,
        tcp_flags: Option<u8>,
    ) {
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

            if (old_pkt.tcp_flags & 0x01) != 0 {
                self.fin_count -= 1;
            }
            if (old_pkt.tcp_flags & 0x02) != 0 {
                self.syn_count -= 1;
            }
            if (old_pkt.tcp_flags & 0x04) != 0 {
                self.rst_count -= 1;
            }
            if (old_pkt.tcp_flags & 0x08) != 0 {
                self.psh_count -= 1;
            }
            if (old_pkt.tcp_flags & 0x10) != 0 {
                self.ack_count -= 1;
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

        if (flags & 0x01) != 0 {
            self.fin_count += 1;
        }
        if (flags & 0x02) != 0 {
            self.syn_count += 1;
        }
        if (flags & 0x04) != 0 {
            self.rst_count += 1;
        }
        if (flags & 0x08) != 0 {
            self.psh_count += 1;
        }
        if (flags & 0x10) != 0 {
            self.ack_count += 1;
        }

        // Write new packet to buffer and advance write pointer
        self.buffer[self.head] = new_pkt;
        self.head = (self.head + 1) % WINDOW_SIZE;

        if self.count < WINDOW_SIZE {
            self.count += 1;
        }
    }

    /// Computes aggregated statistical features for ML engine input.
    #[allow(clippy::needless_range_loop)]
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
            if ts < min_ts {
                min_ts = ts;
            }
            if ts > max_ts {
                max_ts = ts;
            }
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
        let rst_ratio = self.rst_count as f64 / count;
        let fin_ratio = self.fin_count as f64 / count;
        let psh_ratio = self.psh_count as f64 / count;
        let ack_ratio = self.ack_count as f64 / count;

        // Stack-allocated array to compute inter-arrival times without heap allocation
        let mut sorted_ts = [0u64; WINDOW_SIZE];
        for i in 0..self.count {
            let idx = (self.head + WINDOW_SIZE - self.count + i) % WINDOW_SIZE;
            sorted_ts[i] = self.buffer[idx].timestamp_ms;
        }
        let active_ts = &mut sorted_ts[..self.count];
        active_ts.sort_unstable();

        let mut sum_interval = 0.0;
        let mut sum_interval_sq = 0.0;
        let num_intervals = self.count.saturating_sub(1);

        let (mean_interval, var_interval) = if num_intervals > 0 {
            for i in 1..self.count {
                let interval = (active_ts[i] - active_ts[i - 1]) as f64;
                sum_interval += interval;
                sum_interval_sq += interval * interval;
            }
            let m_int = sum_interval / num_intervals as f64;
            let v_int = ((sum_interval_sq / num_intervals as f64) - (m_int * m_int)).max(0.0);
            (m_int, v_int)
        } else {
            (0.0, 0.0)
        };

        FlowMetrics {
            src_ip: key.ip_min, // Normalized reporting IP
            dest_ip: key.ip_max,
            src_port: key.port_min,
            dest_port: key.port_max,
            protocol: key.protocol,
            key,
            packet_count: self.total_packets,
            mean_len,
            var_len,
            packet_rate,
            byte_rate,
            fwd_bwd_ratio,
            syn_ratio,
            rst_ratio,
            fin_ratio,
            psh_ratio,
            ack_ratio,
            mean_interval,
            var_interval,
        }
    }
}

/// Extracted features ready for the One-Class SVM inference engine.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlowMetrics {
    pub src_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: u8,
    pub key: FlowKey,
    pub packet_count: u64,
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

/// Thread-local pre-allocated flow table with constant memory footprint and LRU eviction.
pub struct FlowTable {
    map: HashMap<FlowKey, usize>, // Map FlowKey to Slab index
    slab: Slab<LruNode>,          // Pre-allocated slab storing flow state and LRU links
    capacity: usize,
    lru_head: Option<usize>, // Index of most recently used node
    lru_tail: Option<usize>, // Index of least recently used node
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
    /// If the table exceeds its capacity, the oldest inactive flow is recycled in O(1) without invoking the global allocator.
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

            node.state
                .update(event.timestamp, event.len, direction, event.tcp_flags);
            node.state.compute_metrics(key)
        } else {
            // New flow: Check capacity first
            let slab_idx = if self.slab.len() >= self.capacity {
                // Table is full: Evict least recently used flow
                let evicted_idx = self
                    .lru_tail
                    .expect("LRU tail cannot be None when Slab is full");
                self.evict_node(evicted_idx);
                evicted_idx
            } else {
                // Slab has free capacity: allocate new slot
                self.slab.vacant_entry().key()
            };

            // If we are recycling an existing node in the slab, reset its state to reuse memory
            if self.slab.contains(slab_idx) {
                let node = &mut self.slab[slab_idx];
                node.key = key;
                node.state.reset(event.src_ip);
                node.prev = None;
                node.next = None;

                node.state.update(
                    event.timestamp,
                    event.len,
                    Direction::Forward,
                    event.tcp_flags,
                );
                let metrics = node.state.compute_metrics(key);

                self.map.insert(key, slab_idx);
                self.link_lru_head(slab_idx);
                metrics
            } else {
                // Slab is not fully populated yet: insert a new node
                let state = FlowState::new(event.src_ip);
                let mut new_node = LruNode {
                    key,
                    state,
                    prev: None,
                    next: None,
                };

                new_node.state.update(
                    event.timestamp,
                    event.len,
                    Direction::Forward,
                    event.tcp_flags,
                );
                let metrics = new_node.state.compute_metrics(key);

                self.slab.insert(new_node);
                self.map.insert(key, slab_idx);
                self.link_lru_head(slab_idx);
                metrics
            }
        }
    }

    /// Number of active flows in the table.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns true if the flow table is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
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
        // Note: slab item is left in the slab; it is recycled on next insert
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

    #[test]
    fn test_symmetric_flow_key() {
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        let key1 = FlowKey::new(ip_a, 1234, ip_b, 80, 6);
        let key2 = FlowKey::new(ip_b, 80, ip_a, 1234, 6);

        assert_eq!(key1, key2);
        assert_eq!(key1.ip_min, ip_a);
        assert_eq!(key1.ip_max, ip_b);
        assert_eq!(key1.port_min, 1234);
        assert_eq!(key1.port_max, 80);
    }

    #[test]
    fn test_flow_state_aggregates() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut state = FlowState::new(ip);

        let start = SystemTime::now();

        // Feed 3 packets: 100 bytes forward, 200 bytes backward, 300 bytes forward
        state.update(start, 100, Direction::Forward, Some(0x02));
        state.update(
            start + std::time::Duration::from_millis(100),
            200,
            Direction::Backward,
            Some(0x10),
        );
        state.update(
            start + std::time::Duration::from_millis(200),
            300,
            Direction::Forward,
            Some(0x04),
        );

        let key = FlowKey::new(ip, 1234, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80, 6);
        let metrics = state.compute_metrics(key);

        assert_eq!(metrics.packet_count, 3);
        assert_eq!(state.packets_fwd, 2);
        assert_eq!(state.packets_bwd, 1);
        assert_eq!(state.bytes_fwd, 400);
        assert_eq!(state.bytes_bwd, 200);
        assert_eq!(state.syn_count, 1);
        assert_eq!(state.rst_count, 1);
        assert_eq!(state.fin_count, 0);
        assert_eq!(state.psh_count, 0);
        assert_eq!(state.ack_count, 1);

        // Mean should be (100 + 200 + 300) / 3 = 200.0
        assert_eq!(metrics.mean_len, 200.0);

        // Sum of squares = 100^2 + 200^2 + 300^2 = 140000
        // Variance = 140000 / 3 - 200^2 = 6666.6667
        assert!((metrics.var_len - 6666.6667).abs() < 0.1);

        // Duration is 200ms = 0.2s. 3 packets / 0.2s = 15.0 packets/sec
        assert_eq!(metrics.packet_rate, 15.0);
        // Bytes rate is 600 bytes / 0.2s = 3000 bytes/sec
        assert_eq!(metrics.byte_rate, 3000.0);

        // Ratios
        assert!((metrics.syn_ratio - 0.3333).abs() < 0.01);
        assert!((metrics.rst_ratio - 0.3333).abs() < 0.01);
        assert_eq!(metrics.fin_ratio, 0.0);
        assert_eq!(metrics.psh_ratio, 0.0);
        assert!((metrics.ack_ratio - 0.3333).abs() < 0.01);

        // Interval statistics
        assert_eq!(metrics.mean_interval, 100.0);
        assert_eq!(metrics.var_interval, 0.0);
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
