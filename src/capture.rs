use crate::parser::{LinkType, RawPacket};
use pcap::{Capture, Device, Error as PcapError};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_PACKET_LEN: u32 = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub enum CaptureSource {
    Live(String),
    File(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureResult {
    pub outcome: CaptureOutcome,
    pub dropped: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureOutcome {
    Finished,
    Stopped,
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

pub fn available_interfaces() -> Result<Vec<String>, String> {
    let devices = Device::list().map_err(|error| format!("cannot list interfaces: {}", error))?;
    Ok(devices.into_iter().map(|device| device.name).collect())
}

pub fn default_interface() -> Result<String, String> {
    let devices = Device::list().map_err(|error| format!("cannot list interfaces: {}", error))?;
    let preferred = devices.iter().find(|device| {
        let label = format!(
            "{} {}",
            device.name,
            device.desc.as_deref().unwrap_or_default()
        )
        .to_lowercase();
        !label.contains("loopback") && !label.contains("lo0")
    });
    let selected = preferred.or_else(|| devices.first());
    selected
        .map(|device| device.name.clone())
        .ok_or_else(|| "no network interface found".to_string())
}

pub fn run(
    source: &CaptureSource,
    stop: &AtomicBool,
    tx: &SyncSender<RawPacket>,
) -> Result<CaptureResult, String> {
    match source {
        CaptureSource::Live(interface) => capture_live(interface, stop, tx),
        CaptureSource::File(path) => read_pcap_file(path, stop, tx),
    }
}

fn capture_live(
    interface: &str,
    stop: &AtomicBool,
    tx: &SyncSender<RawPacket>,
) -> Result<CaptureResult, String> {
    let mut dropped = 0u64;
    let device = Device::list()
        .map_err(|error| format!("cannot list interfaces: {}", error))?
        .into_iter()
        .find(|device| device.name == interface)
        .ok_or_else(|| format!("interface '{}' not found", interface))?;

    let mut capture = Capture::from_device(device)
        .map_err(|error| format!("cannot open interface '{}': {}", interface, error))?
        .promisc(true)
        .snaplen(65535)
        .timeout(100)
        .open()
        .map_err(|error| format!("cannot start capture on '{}': {}", interface, error))?;

    let datalink = u32::try_from(capture.get_datalink().0)
        .map_err(|_| "invalid pcap datalink value".to_string())?;
    let link = LinkType::from_pcap(datalink);

    while !stop.load(Ordering::Relaxed) {
        match capture.next_packet() {
            Ok(packet) => {
                let header = packet.header;
                let raw = RawPacket::new(
                    timestamp_from_timeval(to_i64(header.ts.tv_sec), to_i64(header.ts.tv_usec)),
                    link,
                    packet.data.to_vec(),
                    header.len,
                );
                match tx.try_send(raw) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => dropped += 1,
                    Err(TrySendError::Disconnected(_)) => {
                        return Ok(CaptureResult {
                            outcome: CaptureOutcome::Stopped,
                            dropped,
                        });
                    }
                }
            }
            Err(PcapError::TimeoutExpired) => continue,
            Err(error) => return Err(format!("capture error: {}", error)),
        }
    }

    Ok(CaptureResult {
        outcome: CaptureOutcome::Stopped,
        dropped,
    })
}

fn read_pcap_file(
    path: &str,
    stop: &AtomicBool,
    tx: &SyncSender<RawPacket>,
) -> Result<CaptureResult, String> {
    let mut dropped = 0u64;
    let mut reader = BufReader::new(
        File::open(path).map_err(|error| format!("cannot open '{}': {}", path, error))?,
    );

    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|error| format!("cannot read pcap header: {}", error))?;

    let (endian, nanosecond) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, true),
        _ => return Err(format!("'{}' is not a classic pcap file", path)),
    };

    let mut global = [0u8; 20];
    reader
        .read_exact(&mut global)
        .map_err(|error| format!("cannot read pcap header: {}", error))?;
    if global[0] != 2 {
        return Err(format!(
            "unsupported pcap version {}.{}",
            global[0], global[1]
        ));
    }

    let link = LinkType::from_pcap(read_u32(&global[16..20], endian));
    if matches!(link, LinkType::Unsupported(_)) {
        return Err(format!(
            "unsupported pcap link type {}",
            read_u32(&global[16..20], endian)
        ));
    }

    let mut record = [0u8; 16];
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(CaptureResult {
                outcome: CaptureOutcome::Stopped,
                dropped,
            });
        }

        match reader.read_exact(&mut record) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(format!("cannot read pcap record: {}", error)),
        }

        let seconds = read_u32(&record[0..4], endian);
        let fraction = read_u32(&record[4..8], endian);
        let captured = read_u32(&record[8..12], endian);
        let original = read_u32(&record[12..16], endian);
        if captured > MAX_PACKET_LEN {
            return Err(format!("pcap packet length {} exceeds limit", captured));
        }

        let mut data = vec![0u8; captured as usize];
        reader
            .read_exact(&mut data)
            .map_err(|error| format!("cannot read pcap packet: {}", error))?;

        let nanos = if nanosecond {
            fraction
        } else {
            fraction.saturating_mul(1000)
        };
        let timestamp = UNIX_EPOCH
            .checked_add(Duration::new(seconds as u64, nanos))
            .unwrap_or(UNIX_EPOCH);
        let raw = RawPacket::new(timestamp, link, data, original);
        match tx.try_send(raw) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => dropped += 1,
            Err(TrySendError::Disconnected(_)) => {
                return Ok(CaptureResult {
                    outcome: CaptureOutcome::Stopped,
                    dropped,
                });
            }
        }
    }

    Ok(CaptureResult {
        outcome: CaptureOutcome::Finished,
        dropped,
    })
}

fn read_u32(bytes: &[u8], endian: Endian) -> u32 {
    match endian {
        Endian::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        Endian::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    }
}

fn to_i64(value: impl Into<i64>) -> i64 {
    value.into()
}
fn timestamp_from_timeval(seconds: i64, micros: i64) -> SystemTime {
    let seconds = seconds.max(0) as u64;
    let nanos = micros.max(0).saturating_mul(1000) as u32;
    UNIX_EPOCH
        .checked_add(Duration::new(seconds, nanos))
        .unwrap_or(UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_u32_both_endiannesses() {
        let bytes = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(read_u32(&bytes, Endian::Big), 0x12345678);
        assert_eq!(read_u32(&bytes, Endian::Little), 0x78563412);
    }

    #[test]
    fn converts_pcap_timeval_microseconds() {
        let timestamp = timestamp_from_timeval(2, 500_000);
        assert_eq!(
            timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            2_500
        );
    }
}
