use crate::parser::{PacketEvent, Protocol};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

const WINDOW_SECS: usize = 60;
const MAX_SAMPLES: usize = 50_000;

#[derive(Clone, Debug, Serialize)]
pub struct ProtocolShare {
    pub protocol: Protocol,
    pub packets: u64,
    pub percent: u8,
}

#[derive(Clone, Debug, Serialize)]
pub struct Talker {
    pub ip: IpAddr,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct StatsSnapshot {
    pub pps: u64,
    pub bytes_per_sec: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub sparkline: Vec<u64>,
    pub protocols: Vec<ProtocolShare>,
    pub top_talkers: Vec<Talker>,
    pub parse_errors: u64,
    pub queue_drops: u64,
}

impl Default for StatsSnapshot {
    fn default() -> Self {
        Self {
            pps: 0,
            bytes_per_sec: 0,
            total_packets: 0,
            total_bytes: 0,
            sparkline: vec![0; WINDOW_SECS],
            protocols: Protocol::ALL
                .iter()
                .map(|protocol| ProtocolShare {
                    protocol: *protocol,
                    packets: 0,
                    percent: 0,
                })
                .collect(),
            top_talkers: Vec::new(),
            parse_errors: 0,
            queue_drops: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct SecondBucket {
    second: u64,
    packets: u64,
    bytes: u64,
    protocols: [u64; 5],
}

#[derive(Clone, Copy)]
struct Sample {
    second: u64,
    src_ip: IpAddr,
    bytes: u64,
}

#[derive(Default)]
pub struct TrafficStats {
    buckets: VecDeque<SecondBucket>,
    samples: VecDeque<Sample>,
    total_packets: u64,
    total_bytes: u64,
    parse_errors: u64,
    queue_drops: u64,
}

impl TrafficStats {
    pub fn record(&mut self, event: &PacketEvent) {
        let second = event.timestamp_ms / 1000;
        self.advance(second);

        if let Some(bucket) = self.buckets.back_mut() {
            bucket.packets += 1;
            bucket.bytes += event.length as u64;
            bucket.protocols[event.protocol.index()] += 1;
        }

        self.samples.push_back(Sample {
            second,
            src_ip: event.src_ip,
            bytes: event.length as u64,
        });
        self.prune_samples(second);
        self.total_packets += 1;
        self.total_bytes += event.length as u64;
    }

    pub fn record_parse_error(&mut self) {
        self.parse_errors += 1;
    }

    pub fn record_queue_drop(&mut self, count: u64) {
        self.queue_drops += count;
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        let current = self.buckets.back().copied().unwrap_or(SecondBucket {
            second: 0,
            packets: 0,
            bytes: 0,
            protocols: [0; 5],
        });

        let mut sparkline: Vec<u64> = self.buckets.iter().map(|bucket| bucket.packets).collect();
        if sparkline.len() < WINDOW_SECS {
            let mut padded = vec![0; WINDOW_SECS - sparkline.len()];
            padded.append(&mut sparkline);
            sparkline = padded;
        }

        let mut counts = [0u64; 5];
        for bucket in &self.buckets {
            for (index, count) in counts.iter_mut().enumerate() {
                *count += bucket.protocols[index];
            }
        }
        let window_packets: u64 = counts.iter().sum();
        let protocols = Protocol::ALL
            .iter()
            .map(|protocol| ProtocolShare {
                protocol: *protocol,
                packets: counts[protocol.index()],
                percent: if window_packets == 0 {
                    0
                } else {
                    ((counts[protocol.index()] as f64 / window_packets as f64) * 100.0).round()
                        as u8
                },
            })
            .collect();

        let mut talkers: HashMap<IpAddr, (u64, u64)> = HashMap::new();
        for sample in &self.samples {
            let entry = talkers.entry(sample.src_ip).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += sample.bytes;
        }
        let mut top_talkers: Vec<Talker> = talkers
            .into_iter()
            .map(|(ip, (packets, bytes))| Talker { ip, packets, bytes })
            .collect();
        top_talkers.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(b.packets.cmp(&a.packets)));
        top_talkers.truncate(8);

        StatsSnapshot {
            pps: current.packets,
            bytes_per_sec: current.bytes,
            total_packets: self.total_packets,
            total_bytes: self.total_bytes,
            sparkline,
            protocols,
            top_talkers,
            parse_errors: self.parse_errors,
            queue_drops: self.queue_drops,
        }
    }

    fn advance(&mut self, second: u64) {
        let Some(last) = self.buckets.back().map(|bucket| bucket.second) else {
            self.buckets.push_back(empty_bucket(second));
            return;
        };
        if second < last {
            return;
        }
        let gap = second - last;
        if gap >= WINDOW_SECS as u64 {
            self.buckets.clear();
            self.samples.clear();
        } else {
            for value in (last + 1)..=second {
                self.buckets.push_back(empty_bucket(value));
            }
        }
        while self.buckets.len() > WINDOW_SECS {
            self.buckets.pop_front();
        }
    }

    fn prune_samples(&mut self, second: u64) {
        let cutoff = second.saturating_sub(WINDOW_SECS as u64 - 1);
        while self
            .samples
            .front()
            .is_some_and(|sample| sample.second < cutoff)
        {
            self.samples.pop_front();
        }
        while self.samples.len() > MAX_SAMPLES {
            self.samples.pop_front();
        }
    }
}

fn empty_bucket(second: u64) -> SecondBucket {
    SecondBucket {
        second,
        packets: 0,
        bytes: 0,
        protocols: [0; 5],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::TcpFlags;
    use std::net::Ipv4Addr;

    fn event(ms: u64, ip: [u8; 4], protocol: Protocol, bytes: u32) -> PacketEvent {
        PacketEvent {
            timestamp_ms: ms,
            protocol,
            src_ip: IpAddr::V4(Ipv4Addr::from(ip)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: Some(1234),
            dst_port: Some(80),
            tcp_flags: Some(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            }),
            icmp_type: None,
            icmp_code: None,
            dns_query: None,
            length: bytes,
            ttl: Some(64),
        }
    }

    #[test]
    fn computes_pps_and_top_talkers_from_last_second() {
        let mut stats = TrafficStats::default();
        stats.record(&event(1_000, [10, 0, 0, 2], Protocol::Tcp, 100));
        stats.record(&event(1_500, [10, 0, 0, 2], Protocol::Tcp, 200));
        stats.record(&event(1_700, [10, 0, 0, 3], Protocol::Dns, 50));
        stats.record(&event(2_100, [10, 0, 0, 3], Protocol::Dns, 50));

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.pps, 1);
        assert_eq!(snapshot.bytes_per_sec, 50);
        assert_eq!(snapshot.total_packets, 4);
        assert_eq!(snapshot.sparkline.len(), WINDOW_SECS);
        assert_eq!(snapshot.sparkline[WINDOW_SECS - 2], 3);
        assert_eq!(snapshot.top_talkers[0].ip.to_string(), "10.0.0.2");
        assert_eq!(snapshot.top_talkers[0].bytes, 300);
    }
}
