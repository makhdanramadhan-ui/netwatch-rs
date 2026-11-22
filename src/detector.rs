use crate::parser::{PacketEvent, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum AnomalyKind {
    PortScan,
    SynSpike,
    DnsBurst,
}

impl AnomalyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AnomalyKind::PortScan => "Port Scan",
            AnomalyKind::SynSpike => "SYN Spike",
            AnomalyKind::DnsBurst => "DNS Burst",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    Warn,
    Crit,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Warn => "WARN",
            Severity::Crit => "CRIT",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Alert {
    pub timestamp_ms: u64,
    pub severity: Severity,
    pub kind: AnomalyKind,
    pub source_ip: IpAddr,
    pub detail: String,
}

#[derive(Clone, Copy, Debug)]
pub struct DetectorConfig {
    pub port_scan_ports: usize,
    pub port_scan_window: f64,
    pub syn_spike_count: usize,
    pub syn_spike_window: f64,
    pub dns_burst_count: usize,
    pub dns_burst_window: f64,
    pub cooldown: f64,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            port_scan_ports: 15,
            port_scan_window: 5.0,
            syn_spike_count: 50,
            syn_spike_window: 1.0,
            dns_burst_count: 50,
            dns_burst_window: 10.0,
            cooldown: 10.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    client: IpAddr,
    server: IpAddr,
    client_port: u16,
    server_port: u16,
}

impl FlowKey {
    fn new(client: IpAddr, server: IpAddr, client_port: u16, server_port: u16) -> Self {
        Self {
            client,
            server,
            client_port,
            server_port,
        }
    }

    fn reverse(self) -> Self {
        Self::new(self.server, self.client, self.server_port, self.client_port)
    }
}

#[derive(Clone, Copy)]
struct Observation {
    time: f64,
    source: IpAddr,
    destination_port: Option<u16>,
    protocol: Protocol,
    is_dns_query: bool,
}

#[derive(Default)]
pub struct AnomalyEngine {
    config: DetectorConfig,
    observations: VecDeque<Observation>,
    pending_syns: HashMap<FlowKey, VecDeque<f64>>,
    last_alert: HashMap<(AnomalyKind, IpAddr), f64>,
    observed_count: u64,
}

impl AnomalyEngine {
    pub fn new(config: DetectorConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    pub fn observe(&mut self, event: &PacketEvent) -> Vec<Alert> {
        let time = event.time_secs();
        let flags = event.tcp_flags.unwrap_or_default();
        let is_syn = flags.syn && !flags.ack;
        let is_ack = flags.ack && !flags.syn;
        let max_window = self
            .config
            .port_scan_window
            .max(self.config.syn_spike_window)
            .max(self.config.dns_burst_window);

        self.prune(time, max_window);
        self.observations.push_back(Observation {
            time,
            source: event.src_ip,
            destination_port: event.dst_port,
            protocol: event.protocol,
            is_dns_query: event.dns_query.is_some(),
        });

        if let (Some(src_port), Some(dst_port)) = (event.src_port, event.dst_port) {
            let key = FlowKey::new(event.src_ip, event.dst_ip, src_port, dst_port);
            if is_syn {
                self.pending_syns.entry(key).or_default().push_back(time);
            } else if is_ack {
                let key = key.reverse();
                if let Some(pending) = self.pending_syns.get_mut(&key) {
                    pending.pop_front();
                    if pending.is_empty() {
                        self.pending_syns.remove(&key);
                    }
                }
            }
        }

        self.observed_count += 1;
        if self.observed_count.is_multiple_of(256) {
            self.pending_syns.retain(|_, times| !times.is_empty());
            self.last_alert
                .retain(|_, last| time - *last <= self.config.cooldown);
        }

        let mut alerts = Vec::new();
        if let Some(alert) = self.check_port_scan(time) {
            alerts.push(alert);
        }
        if let Some(alert) = self.check_syn_spike(time) {
            alerts.push(alert);
        }
        if let Some(alert) = self.check_dns_burst(time) {
            alerts.push(alert);
        }
        alerts
    }

    fn check_port_scan(&mut self, time: f64) -> Option<Alert> {
        let mut ports: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
        for observation in &self.observations {
            if time - observation.time > self.config.port_scan_window {
                continue;
            }
            if observation.protocol != Protocol::Tcp {
                continue;
            }
            if let Some(port) = observation.destination_port {
                ports.entry(observation.source).or_default().insert(port);
            }
        }

        let (source, unique) = ports.into_iter().max_by_key(|(_, ports)| ports.len())?;
        if unique.len() <= self.config.port_scan_ports {
            return None;
        }
        if !self.allow(AnomalyKind::PortScan, source, time) {
            return None;
        }

        Some(Alert {
            timestamp_ms: (time * 1000.0) as u64,
            severity: Severity::Warn,
            kind: AnomalyKind::PortScan,
            source_ip: source,
            detail: format!(
                "{} distinct ports in {:.1}s",
                unique.len(),
                self.config.port_scan_window
            ),
        })
    }

    fn check_syn_spike(&mut self, time: f64) -> Option<Alert> {
        let mut counts: HashMap<IpAddr, usize> = HashMap::new();
        for (flow, times) in &self.pending_syns {
            let recent = times
                .iter()
                .filter(|syn_time| time - **syn_time <= self.config.syn_spike_window)
                .count();
            if recent > 0 {
                *counts.entry(flow.client).or_insert(0) += recent;
            }
        }

        let (source, count) = counts.into_iter().max_by_key(|(_, count)| *count)?;
        if count <= self.config.syn_spike_count {
            return None;
        }
        if !self.allow(AnomalyKind::SynSpike, source, time) {
            return None;
        }

        Some(Alert {
            timestamp_ms: (time * 1000.0) as u64,
            severity: Severity::Crit,
            kind: AnomalyKind::SynSpike,
            source_ip: source,
            detail: format!(
                "{} unacknowledged SYN in {:.1}s",
                count, self.config.syn_spike_window
            ),
        })
    }

    fn check_dns_burst(&mut self, time: f64) -> Option<Alert> {
        let mut counts: HashMap<IpAddr, usize> = HashMap::new();
        for observation in &self.observations {
            if observation.is_dns_query && time - observation.time <= self.config.dns_burst_window {
                *counts.entry(observation.source).or_insert(0) += 1;
            }
        }

        let (source, count) = counts.into_iter().max_by_key(|(_, count)| *count)?;
        if count <= self.config.dns_burst_count {
            return None;
        }
        if !self.allow(AnomalyKind::DnsBurst, source, time) {
            return None;
        }

        Some(Alert {
            timestamp_ms: (time * 1000.0) as u64,
            severity: Severity::Warn,
            kind: AnomalyKind::DnsBurst,
            source_ip: source,
            detail: format!("{} queries in {:.1}s", count, self.config.dns_burst_window),
        })
    }

    fn allow(&mut self, kind: AnomalyKind, source: IpAddr, time: f64) -> bool {
        let key = (kind, source);
        if let Some(last) = self.last_alert.get(&key) {
            if time - *last < self.config.cooldown {
                return false;
            }
        }
        self.last_alert.insert(key, time);
        true
    }

    fn prune(&mut self, time: f64, window: f64) {
        while self
            .observations
            .front()
            .is_some_and(|observation| time - observation.time > window)
        {
            self.observations.pop_front();
        }
        for times in self.pending_syns.values_mut() {
            while times
                .front()
                .is_some_and(|syn_time| time - *syn_time > window)
            {
                times.pop_front();
            }
        }
    }
}
