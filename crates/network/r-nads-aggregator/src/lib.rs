use hashbrown::HashMap;
use r_nads_common::{Direction, FlowKey, PacketEvent};
use serde::{Deserialize, Serialize};
use slab::Slab;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Window size K for sliding window behavioral analytics.
pub const WINDOW_SIZE: usize = 128;

/// Summary of a single packet inside a flow's sliding window.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketSummary {
    pub timestamp_ms: u64,
    pub len: u32,
    pub direction: Direction,
    pub tcp_flags: u8,
    pub is_fragment: bool,
    pub is_malformed: bool,
}

/// Sliding window rolling metrics for a single network flow across IPv4 and IPv6.
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
    pub malformed_count: u32,
    pub fragment_count: u32,
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
            malformed_count: 0,
            fragment_count: 0,
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
        self.malformed_count = 0;
        self.fragment_count = 0;
        self.sum_len = 0;
        self.sum_len_sq = 0;
    }

    /// Updates the sliding window with a new packet, evicting the oldest packet if the window is full.
    pub fn update(
        &mut self,
        timestamp: SystemTime,
        len: u32,
        direction: Direction,
        tcp_flags: Option<u8>,
        is_fragment: bool,
        is_malformed: bool,
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
            is_fragment,
            is_malformed,
        };

        // If the window is full, evict the oldest packet at `self.head` from the aggregates
        if self.count == WINDOW_SIZE {
            let old_pkt = self.buffer[self.head];

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

            if old_pkt.is_malformed {
                self.malformed_count = self.malformed_count.saturating_sub(1);
            }
            if old_pkt.is_fragment {
                self.fragment_count = self.fragment_count.saturating_sub(1);
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

        if is_malformed {
            self.malformed_count += 1;
        }
        if is_fragment {
            self.fragment_count += 1;
        }

        self.buffer[self.head] = new_pkt;
        self.head = (self.head + 1) % WINDOW_SIZE;
        if self.count < WINDOW_SIZE {
            self.count += 1;
        }
    }

    /// Computes the 12 statistical flow features for SVDD/ML anomaly detection,
    /// along with protocol-level malformed and fragment counts.
    pub fn compute_metrics(&self, key: FlowKey) -> FlowMetrics {
        let count = self.count.max(1) as f64;

        // Mean and variance of packet length
        let mean_len = self.sum_len as f64 / count;
        let mean_len_sq = self.sum_len_sq as f64 / count;
        let var_len = (mean_len_sq - (mean_len * mean_len)).max(0.0);

        // Find time range in sliding window
        let (oldest_ts, newest_ts) = if self.count > 0 {
            let oldest_idx = (self.head + WINDOW_SIZE - self.count) % WINDOW_SIZE;
            let newest_idx = (self.head + WINDOW_SIZE - 1) % WINDOW_SIZE;
            (
                self.buffer[oldest_idx].timestamp_ms,
                self.buffer[newest_idx].timestamp_ms,
            )
        } else {
            (0, 0)
        };

        let duration_ms = newest_ts.saturating_sub(oldest_ts).max(1);
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
        #[allow(clippy::needless_range_loop)]
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
            let mean = sum_interval / num_intervals as f64;
            let mean_sq = sum_interval_sq / num_intervals as f64;
            let var = (mean_sq - (mean * mean)).max(0.0);
            (mean, var)
        } else {
            (0.0, 0.0)
        };

        FlowMetrics {
            src_ip: self.initiator_ip,
            dest_ip: if self.initiator_ip == key.ip_min {
                key.ip_max
            } else {
                key.ip_min
            },
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
            malformed_count: self.malformed_count,
            fragment_count: self.fragment_count,
        }
    }
}

/// Extracted 12-dimensional features for SVDD/ML inference plus protocol indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default)]
    pub malformed_count: u32,
    #[serde(default)]
    pub fragment_count: u32,
}

/// Thread-local pre-allocated flow table with constant memory footprint,
/// load factor monitoring, LRU eviction, and automated memory shedding.
pub struct FlowTable {
    map: HashMap<FlowKey, usize>,
    slab: Slab<LruNode>,
    capacity: usize,
    lru_head: Option<usize>,
    lru_tail: Option<usize>,
    pub total_evictions: u64,
    pub total_shed: u64,
}

struct LruNode {
    key: FlowKey,
    state: FlowState,
    prev: Option<usize>,
    next: Option<usize>,
}

impl FlowTable {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            slab: Slab::with_capacity(capacity),
            capacity,
            lru_head: None,
            lru_tail: None,
            total_evictions: 0,
            total_shed: 0,
        }
    }

    /// Process a packet and update or create its flow state.
    pub fn process_packet(&mut self, event: &PacketEvent) -> FlowMetrics {
        let key = event.flow_key();

        if let Some(&slab_idx) = self.map.get(&key) {
            self.promote_lru(slab_idx);

            let node = &mut self.slab[slab_idx];
            let direction = if event.src_ip == node.state.initiator_ip {
                Direction::Forward
            } else {
                Direction::Backward
            };

            node.state.update(
                event.timestamp,
                event.len,
                direction,
                event.tcp_flags,
                event.is_fragment(),
                event.is_malformed(),
            );
            node.state.compute_metrics(key)
        } else {
            let slab_idx = if self.slab.len() >= self.capacity {
                let evicted_idx = self
                    .lru_tail
                    .expect("LRU tail cannot be None when Slab is full");
                self.evict_node(evicted_idx);
                self.total_evictions += 1;
                evicted_idx
            } else {
                self.slab.vacant_entry().key()
            };

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
                    event.is_fragment(),
                    event.is_malformed(),
                );
                let metrics = node.state.compute_metrics(key);

                self.map.insert(key, slab_idx);
                self.link_lru_head(slab_idx);
                metrics
            } else {
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
                    event.is_fragment(),
                    event.is_malformed(),
                );
                let metrics = new_node.state.compute_metrics(key);

                self.slab.insert(new_node);
                self.map.insert(key, slab_idx);
                self.link_lru_head(slab_idx);
                metrics
            }
        }
    }

    /// Current number of tracked active flows.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Capacity of this flow table partition.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns true if no flows are currently active.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Returns the current load factor `len / capacity` in `[0.0, 1.0]`.
    pub fn load_factor(&self) -> f64 {
        self.map.len() as f64 / self.capacity.max(1) as f64
    }

    /// Emergency shed: immediately evicts `count` least-recently-used flows from the LRU tail
    /// when the system is under extreme memory pressure (> 90% capacity).
    pub fn emergency_shed(&mut self, count: usize) -> usize {
        let mut shed_count = 0;
        for _ in 0..count {
            if let Some(tail_idx) = self.lru_tail {
                self.evict_node(tail_idx);
                shed_count += 1;
                self.total_shed += 1;
            } else {
                break;
            }
        }
        shed_count
    }

    /// Sheds stale flows older than `max_idle_ms` relative to `now_ms`.
    /// Traverses from the LRU tail upwards.
    pub fn shed_stale_flows(&mut self, max_idle_ms: u64, now_ms: u64) -> usize {
        let mut shed_count = 0;
        let mut current = self.lru_tail;

        while let Some(idx) = current {
            let prev = self.slab[idx].prev;
            let newest_ts = {
                let state = &self.slab[idx].state;
                if state.count > 0 {
                    let newest_idx = (state.head + WINDOW_SIZE - 1) % WINDOW_SIZE;
                    state.buffer[newest_idx].timestamp_ms
                } else {
                    0
                }
            };

            if now_ms.saturating_sub(newest_ts) >= max_idle_ms {
                self.evict_node(idx);
                shed_count += 1;
                self.total_shed += 1;
                current = prev;
            } else {
                // Since list is ordered by recency, older items are towards the tail.
                // Once we hit an active flow, remaining entries are more recently active.
                break;
            }
        }
        shed_count
    }

    fn promote_lru(&mut self, idx: usize) {
        if Some(idx) == self.lru_head {
            return;
        }
        self.unlink_lru(idx);
        self.link_lru_head(idx);
    }

    fn evict_node(&mut self, idx: usize) {
        let key = self.slab[idx].key;
        self.map.remove(&key);
        self.unlink_lru(idx);
    }

    fn link_lru_head(&mut self, idx: usize) {
        let old_head = self.lru_head;
        self.slab[idx].prev = None;
        self.slab[idx].next = old_head;

        if let Some(h) = old_head {
            self.slab[h].prev = Some(idx);
        } else {
            self.lru_tail = Some(idx);
        }
        self.lru_head = Some(idx);
    }

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
    use r_nads_common::PacketFlags;
    use std::time::Duration;

    #[test]
    fn test_flow_state_aggregates() {
        let ip_a = "192.168.1.5".parse::<IpAddr>().unwrap();
        let ip_b = "10.0.0.1".parse::<IpAddr>().unwrap();
        let key = FlowKey::new(ip_a, 5000, ip_b, 80, 6);

        let mut state = FlowState::new(ip_a);
        let start = UNIX_EPOCH + Duration::from_millis(1000);

        state.update(start, 100, Direction::Forward, Some(0x02), false, false);
        state.update(
            start + Duration::from_millis(10),
            200,
            Direction::Backward,
            Some(0x12),
            false,
            false,
        );
        state.update(
            start + Duration::from_millis(20),
            150,
            Direction::Forward,
            Some(0x10),
            false,
            false,
        );

        let metrics = state.compute_metrics(key);
        assert_eq!(metrics.packet_count, 3);
        assert!((metrics.mean_len - 150.0).abs() < 1e-4);
        assert_eq!(metrics.syn_ratio, 2.0 / 3.0);
        assert_eq!(metrics.fwd_bwd_ratio, 2.0);
        assert_eq!(metrics.malformed_count, 0);
    }

    #[test]
    fn test_flow_table_lru_and_emergency_shed() {
        let mut table = FlowTable::new(3);

        let ip_a = "10.0.0.1".parse::<IpAddr>().unwrap();
        let ip_b = "10.0.0.2".parse::<IpAddr>().unwrap();
        let ip_c = "10.0.0.3".parse::<IpAddr>().unwrap();
        let dest = "192.168.1.1".parse::<IpAddr>().unwrap();

        let event1 = PacketEvent {
            timestamp: SystemTime::now(),
            len: 64,
            src_ip: ip_a,
            dest_ip: dest,
            src_port: 1001,
            dest_port: 80,
            protocol: 6,
            tcp_flags: Some(0x02),
            flags: PacketFlags::default(),
        };

        let event2 = PacketEvent {
            timestamp: SystemTime::now(),
            len: 64,
            src_ip: ip_b,
            dest_ip: dest,
            src_port: 1002,
            dest_port: 80,
            protocol: 6,
            tcp_flags: Some(0x02),
            flags: PacketFlags::default(),
        };

        let event3 = PacketEvent {
            timestamp: SystemTime::now(),
            len: 64,
            src_ip: ip_c,
            dest_ip: dest,
            src_port: 1003,
            dest_port: 80,
            protocol: 6,
            tcp_flags: Some(0x02),
            flags: PacketFlags::default(),
        };

        table.process_packet(&event1);
        table.process_packet(&event2);
        table.process_packet(&event3);

        assert_eq!(table.len(), 3);
        assert!((table.load_factor() - 1.0).abs() < 1e-4);

        // Emergency shed 2 flows
        let shed = table.emergency_shed(2);
        assert_eq!(shed, 2);
        assert_eq!(table.len(), 1);
        assert_eq!(table.total_shed, 2);
    }

    #[test]
    fn test_ipv6_udp_flow_aggregation() {
        let mut table = FlowTable::new(10);
        let src_v6: IpAddr = "2001:db8::10".parse().unwrap();
        let dst_v6: IpAddr = "2001:db8::53".parse().unwrap();

        let event = PacketEvent {
            timestamp: SystemTime::now(),
            len: 128,
            src_ip: src_v6,
            dest_ip: dst_v6,
            src_port: 45000,
            dest_port: 53,
            protocol: 17, // UDP
            tcp_flags: None,
            flags: PacketFlags {
                is_fragment: false,
                is_malformed: false,
            },
        };

        let metrics = table.process_packet(&event);
        assert_eq!(metrics.protocol, 17);
        assert!(metrics.key.is_ipv6());
        assert_eq!(metrics.syn_ratio, 0.0);
        assert_eq!(metrics.rst_ratio, 0.0);
        assert_eq!(metrics.packet_count, 1);
    }
}
