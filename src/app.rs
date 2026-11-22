use crate::detector::Alert;
use crate::parser::{format_clock, PacketEvent, Protocol};
use crate::stats::{StatsSnapshot, TrafficStats};
use serde::Serialize;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

const RECENT_PACKETS: usize = 400;
const MAX_ALERTS: usize = 200;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolFilter {
    All,
    Tcp,
    Udp,
    Dns,
    Icmp,
}

impl ProtocolFilter {
    pub const ALL: [ProtocolFilter; 5] = [
        ProtocolFilter::All,
        ProtocolFilter::Tcp,
        ProtocolFilter::Udp,
        ProtocolFilter::Dns,
        ProtocolFilter::Icmp,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ProtocolFilter::All => "ALL",
            ProtocolFilter::Tcp => "TCP",
            ProtocolFilter::Udp => "UDP",
            ProtocolFilter::Dns => "DNS",
            ProtocolFilter::Icmp => "ICMP",
        }
    }

    pub fn next(self) -> Self {
        let index = Self::ALL
            .iter()
            .position(|filter| *filter == self)
            .unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }

    pub fn matches(self, protocol: Protocol) -> bool {
        match self {
            ProtocolFilter::All => true,
            ProtocolFilter::Tcp => protocol == Protocol::Tcp,
            ProtocolFilter::Udp => protocol == Protocol::Udp,
            ProtocolFilter::Dns => protocol == Protocol::Dns,
            ProtocolFilter::Icmp => protocol == Protocol::Icmp,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tab {
    Dashboard,
    Alerts,
}

#[derive(Clone, Debug, Serialize)]
pub enum CaptureStatus {
    Starting,
    Running,
    Finished,
    Stopped,
    Error(String),
}

impl CaptureStatus {
    pub fn as_str(&self) -> &str {
        match self {
            CaptureStatus::Starting => "STARTING",
            CaptureStatus::Running => "RUNNING",
            CaptureStatus::Finished => "FINISHED",
            CaptureStatus::Stopped => "STOPPED",
            CaptureStatus::Error(_) => "ERROR",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionReport {
    pub generated_at_ms: u64,
    pub interface: String,
    pub status: CaptureStatus,
    pub filter: ProtocolFilter,
    pub summary: StatsSnapshot,
    pub alerts: Vec<Alert>,
    pub recent_packets: Vec<PacketEvent>,
}

#[derive(Clone)]
pub struct AppSnapshot {
    pub stats: StatsSnapshot,
    pub packets: Vec<PacketEvent>,
    pub alerts: Vec<Alert>,
    pub filter: ProtocolFilter,
    pub tab: Tab,
    pub paused: bool,
    pub status: CaptureStatus,
    pub interface: String,
    pub prompt: Option<String>,
    pub export_message: Option<String>,
}

struct Inner {
    stats: TrafficStats,
    packets: VecDeque<PacketEvent>,
    alerts: VecDeque<Alert>,
    frozen_packets: Option<VecDeque<PacketEvent>>,
    frozen_alerts: Option<VecDeque<Alert>>,
    frozen_stats: Option<StatsSnapshot>,
    filter: ProtocolFilter,
    tab: Tab,
    paused: bool,
    status: CaptureStatus,
    interface: String,
    prompt: Option<String>,
    export_path: Option<PathBuf>,
    export_message: Option<String>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            stats: TrafficStats::default(),
            packets: VecDeque::new(),
            alerts: VecDeque::new(),
            frozen_packets: None,
            frozen_alerts: None,
            frozen_stats: None,
            filter: ProtocolFilter::All,
            tab: Tab::Dashboard,
            paused: false,
            status: CaptureStatus::Starting,
            interface: String::new(),
            prompt: None,
            export_path: None,
            export_message: None,
        }
    }
}

pub struct AppState {
    inner: RwLock<Inner>,
    stop: AtomicBool,
}

impl AppState {
    pub fn new(interface: String, export_path: Option<PathBuf>) -> Self {
        let inner = Inner {
            interface,
            export_path,
            ..Inner::default()
        };
        Self {
            inner: RwLock::new(inner),
            stop: AtomicBool::new(false),
        }
    }

    pub fn on_packet(&self, event: PacketEvent, alerts: &[Alert]) {
        let mut inner = self.write();
        inner.stats.record(&event);
        inner.packets.push_back(event);
        while inner.packets.len() > RECENT_PACKETS {
            inner.packets.pop_front();
        }
        for alert in alerts {
            inner.alerts.push_back(alert.clone());
        }
        while inner.alerts.len() > MAX_ALERTS {
            inner.alerts.pop_front();
        }
    }

    pub fn record_parse_error(&self) {
        self.write().stats.record_parse_error();
    }

    pub fn record_queue_drop(&self, count: u64) {
        self.write().stats.record_queue_drop(count);
    }

    pub fn set_status(&self, status: CaptureStatus) {
        self.write().status = status;
    }

    pub fn snapshot(&self) -> AppSnapshot {
        let inner = self.read();
        let paused = inner.paused;
        let packets = if paused {
            inner.frozen_packets.clone().unwrap_or_default()
        } else {
            inner.packets.iter().cloned().collect()
        };
        let alerts = if paused {
            inner.frozen_alerts.clone().unwrap_or_default()
        } else {
            inner.alerts.iter().cloned().collect()
        };

        AppSnapshot {
            stats: inner
                .frozen_stats
                .clone()
                .unwrap_or_else(|| inner.stats.snapshot()),
            packets: packets.into(),
            alerts: alerts.into(),
            filter: inner.filter,
            tab: inner.tab,
            paused,
            status: inner.status.clone(),
            interface: inner.interface.clone(),
            prompt: inner.prompt.clone(),
            export_message: inner.export_message.clone(),
        }
    }

    pub fn cycle_filter(&self) {
        let mut inner = self.write();
        inner.filter = inner.filter.next();
    }

    pub fn toggle_alerts(&self) {
        let mut inner = self.write();
        inner.tab = match inner.tab {
            Tab::Dashboard => Tab::Alerts,
            Tab::Alerts => Tab::Dashboard,
        };
    }

    pub fn toggle_pause(&self) {
        let mut inner = self.write();
        inner.paused = !inner.paused;
        if inner.paused {
            inner.frozen_packets = Some(inner.packets.clone());
            inner.frozen_alerts = Some(inner.alerts.clone());
            inner.frozen_stats = Some(inner.stats.snapshot());
        } else {
            inner.frozen_packets = None;
            inner.frozen_alerts = None;
            inner.frozen_stats = None;
        }
    }

    pub fn open_prompt(&self) {
        self.write().prompt = Some(String::new());
    }

    pub fn push_prompt(&self, character: char) {
        if let Some(prompt) = self.write().prompt.as_mut() {
            if prompt.len() < 200 {
                prompt.push(character);
            }
        }
    }

    pub fn pop_prompt(&self) {
        if let Some(prompt) = self.write().prompt.as_mut() {
            prompt.pop();
        }
    }

    pub fn cancel_prompt(&self) {
        self.write().prompt = None;
    }

    pub fn submit_prompt(&self) -> Result<(), String> {
        let path = {
            let mut inner = self.write();
            match inner.prompt.take() {
                Some(value) if !value.trim().is_empty() => PathBuf::from(value.trim()),
                _ => return Ok(()),
            }
        };
        self.export_to(&path)
    }

    pub fn requested_export_path(&self) -> Option<PathBuf> {
        self.read().export_path.clone()
    }

    pub fn set_export_message(&self, message: String) {
        self.write().export_message = Some(message);
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    pub fn should_stop_flag(&self) -> &AtomicBool {
        &self.stop
    }
    pub fn export_to(&self, path: &Path) -> Result<(), String> {
        let report = {
            let inner = self.read();
            SessionReport {
                generated_at_ms: now_ms(),
                interface: inner.interface.clone(),
                status: inner.status.clone(),
                filter: inner.filter,
                summary: inner.stats.snapshot(),
                alerts: inner.alerts.iter().cloned().collect(),
                recent_packets: inner.packets.iter().cloned().collect(),
            }
        };

        let is_csv = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("csv"));

        let file = File::create(path)
            .map_err(|error| format!("cannot create '{}': {}", path.display(), error))?;
        let mut writer = BufWriter::new(file);

        if is_csv {
            writeln!(writer, "timestamp,severity,kind,source_ip,detail")
                .map_err(|error| format!("cannot write '{}': {}", path.display(), error))?;
            for alert in &report.alerts {
                writeln!(
                    writer,
                    "{},{},{},{},{}",
                    format_clock(alert.timestamp_ms),
                    alert.severity.as_str(),
                    alert.kind.as_str(),
                    alert.source_ip,
                    csv_field(&alert.detail)
                )
                .map_err(|error| format!("cannot write '{}': {}", path.display(), error))?;
            }
        } else {
            serde_json::to_writer_pretty(&mut writer, &report)
                .map_err(|error| format!("cannot write '{}': {}", path.display(), error))?;
            writeln!(writer)
                .map_err(|error| format!("cannot write '{}': {}", path.display(), error))?;
        }
        writer
            .flush()
            .map_err(|error| format!("cannot write '{}': {}", path.display(), error))?;

        self.set_export_message(format!(
            "exported {} -> {}",
            report.alerts.len(),
            path.display()
        ));
        Ok(())
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_cycles_and_matches() {
        assert_eq!(ProtocolFilter::All.next(), ProtocolFilter::Tcp);
        assert_eq!(ProtocolFilter::Icmp.next(), ProtocolFilter::All);
        assert!(ProtocolFilter::Dns.matches(Protocol::Dns));
        assert!(!ProtocolFilter::Dns.matches(Protocol::Udp));
    }
}
