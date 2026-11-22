use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Tcp,
    Udp,
    Dns,
    Icmp,
    Other,
}

impl Protocol {
    pub const ALL: [Protocol; 5] = [
        Protocol::Tcp,
        Protocol::Udp,
        Protocol::Dns,
        Protocol::Icmp,
        Protocol::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Dns => "DNS",
            Protocol::Icmp => "ICMP",
            Protocol::Other => "OTHER",
        }
    }

    pub fn index(self) -> usize {
        match self {
            Protocol::Tcp => 0,
            Protocol::Udp => 1,
            Protocol::Dns => 2,
            Protocol::Icmp => 3,
            Protocol::Other => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut written = false;
        for (name, set) in [
            ("SYN", self.syn),
            ("ACK", self.ack),
            ("FIN", self.fin),
            ("RST", self.rst),
        ] {
            if set {
                if written {
                    f.write_str("+")?;
                }
                f.write_str(name)?;
                written = true;
            }
        }
        if !written {
            f.write_str("-")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PacketEvent {
    pub timestamp_ms: u64,
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<TcpFlags>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub dns_query: Option<String>,
    pub length: u32,
    pub ttl: Option<u8>,
}

impl PacketEvent {
    pub fn timestamp(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.timestamp_ms)
    }

    pub fn time_secs(&self) -> f64 {
        self.timestamp_ms as f64 / 1000.0
    }

    pub fn endpoint(&self) -> String {
        let src = match self.src_port {
            Some(port) => format!("{}:{}", self.src_ip, port),
            None => self.src_ip.to_string(),
        };
        let dst = match self.dst_port {
            Some(port) => format!("{}:{}", self.dst_ip, port),
            None => self.dst_ip.to_string(),
        };
        format!("{} -> {}", src, dst)
    }
    pub fn detail(&self) -> String {
        if let Some(query) = &self.dns_query {
            return format!("Q: {}", query);
        }
        if let Some(flags) = self.tcp_flags {
            return format!("[{}]", flags);
        }
        if let Some(kind) = self.icmp_type {
            return format!("ICMP type {} code {}", kind, self.icmp_code.unwrap_or(0));
        }
        String::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkType {
    Ethernet,
    RawIp,
    LinuxSll,
    Unsupported(u32),
}

impl LinkType {
    pub fn from_pcap(value: u32) -> Self {
        match value {
            1 => LinkType::Ethernet,
            101 | 228 | 229 => LinkType::RawIp,
            113 | 276 => LinkType::LinuxSll,
            other => LinkType::Unsupported(other),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RawPacket {
    pub timestamp: SystemTime,
    pub link: LinkType,
    pub data: Vec<u8>,
    pub original_len: u32,
}

impl RawPacket {
    pub fn new(timestamp: SystemTime, link: LinkType, data: Vec<u8>, original_len: u32) -> Self {
        Self {
            timestamp,
            link,
            data,
            original_len,
        }
    }

    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

#[derive(Debug)]
pub enum ParseError {
    UnsupportedLink(u32),
    MissingIp,
    Malformed(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnsupportedLink(id) => write!(f, "unsupported pcap link type {}", id),
            ParseError::MissingIp => f.write_str("packet has no IPv4/IPv6 header"),
            ParseError::Malformed(reason) => write!(f, "malformed packet: {}", reason),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn parse(raw: &RawPacket) -> Result<PacketEvent, ParseError> {
    let sliced = match raw.link {
        LinkType::Ethernet => SlicedPacket::from_ethernet(&raw.data),
        LinkType::RawIp => SlicedPacket::from_ip(&raw.data),
        LinkType::LinuxSll => SlicedPacket::from_linux_sll(&raw.data),
        LinkType::Unsupported(id) => return Err(ParseError::UnsupportedLink(id)),
    }
    .map_err(|_| ParseError::Malformed("header slice error"))?;

    let (src_ip, dst_ip, ttl) = match sliced.net {
        Some(InternetSlice::Ipv4(v4)) => {
            let header = v4.header();
            (
                IpAddr::V4(header.source_addr()),
                IpAddr::V4(header.destination_addr()),
                Some(header.ttl()),
            )
        }
        Some(InternetSlice::Ipv6(v6)) => {
            let header = v6.header();
            (
                IpAddr::V6(header.source_addr()),
                IpAddr::V6(header.destination_addr()),
                Some(header.hop_limit()),
            )
        }
        _ => return Err(ParseError::MissingIp),
    };

    let mut protocol = Protocol::Other;
    let mut src_port = None;
    let mut dst_port = None;
    let mut tcp_flags = None;
    let mut icmp_type = None;
    let mut icmp_code = None;
    let mut dns_query = None;

    match sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            src_port = Some(tcp.source_port());
            dst_port = Some(tcp.destination_port());
            let flags = TcpFlags {
                syn: tcp.syn(),
                ack: tcp.ack(),
                fin: tcp.fin(),
                rst: tcp.rst(),
            };
            tcp_flags = Some(flags);
            if is_dns_port(tcp.source_port(), tcp.destination_port()) {
                protocol = Protocol::Dns;
                if let Some(dns) = tcp_dns_payload(tcp.payload()) {
                    dns_query = parse_dns_query(&dns);
                }
            } else {
                protocol = Protocol::Tcp;
            }
        }
        Some(TransportSlice::Udp(udp)) => {
            src_port = Some(udp.source_port());
            dst_port = Some(udp.destination_port());
            protocol = Protocol::Udp;
            if is_dns_port(udp.source_port(), udp.destination_port()) {
                protocol = Protocol::Dns;
                dns_query = parse_dns_query(udp.payload());
            }
        }
        Some(TransportSlice::Icmpv4(icmp)) => {
            protocol = Protocol::Icmp;
            icmp_type = Some(icmp.type_u8());
            icmp_code = Some(icmp.code_u8());
        }
        Some(TransportSlice::Icmpv6(icmp)) => {
            protocol = Protocol::Icmp;
            icmp_type = Some(icmp.type_u8());
            icmp_code = Some(icmp.code_u8());
        }
        Some(TransportSlice::Igmp(_)) | None => {}
    }

    let _ = &sliced.link_exts;
    Ok(PacketEvent {
        timestamp_ms: raw.timestamp_ms(),
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_flags,
        icmp_type,
        icmp_code,
        dns_query,
        length: raw.original_len,
        ttl,
    })
}

fn is_dns_port(src: u16, dst: u16) -> bool {
    src == 53 || dst == 53
}

fn tcp_dns_payload(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    payload.get(2..2 + len).map(|slice| slice.to_vec())
}

fn parse_dns_query(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 || u16::from_be_bytes([payload[4], payload[5]]) == 0 {
        return None;
    }

    let mut pos = 12usize;
    let mut name = String::new();
    let mut pointers = 0usize;

    loop {
        let label_len = *payload.get(pos)? as usize;
        if label_len & 0xC0 == 0xC0 {
            let next = *payload.get(pos + 1)? as usize;
            let pointer = ((label_len & 0x3F) << 8) | next;
            if pointer < 12 || pointer >= pos || pointers >= 16 {
                return None;
            }
            pos = pointer;
            pointers += 1;
            continue;
        }
        pos += 1;
        if label_len == 0 {
            break;
        }
        if label_len > 63 || pos + label_len > payload.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        let label = std::str::from_utf8(&payload[pos..pos + label_len]).ok()?;
        if name.len() + label.len() > 253 {
            return None;
        }
        name.push_str(label);
        pos += label_len;
    }

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

pub fn format_clock(timestamp_ms: u64) -> String {
    let secs = timestamp_ms / 1000;
    let millis = timestamp_ms % 1000;
    let day_secs = secs % 86_400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;
    format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
}

pub fn format_hms(timestamp_ms: u64) -> String {
    format_clock(timestamp_ms)
        .split('.')
        .next()
        .unwrap_or("00:00:00")
        .to_string()
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} B", bytes)
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::net::Ipv4Addr;

    fn eth_ip_udp(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(51000, 53)
            .write(&mut frame, payload)
            .unwrap();
        frame[23] = protocol;
        frame
    }

    #[test]
    fn parses_dns_query_name() {
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["github", "com"] {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.extend_from_slice(&[0, 0, 1, 0, 1]);

        let frame = eth_ip_udp(17, &dns);
        let raw = RawPacket::new(
            UNIX_EPOCH + Duration::from_secs(1),
            LinkType::Ethernet,
            frame,
            64,
        );
        let event = parse(&raw).unwrap();

        assert_eq!(event.protocol, Protocol::Dns);
        assert_eq!(event.dns_query.as_deref(), Some("github.com"));
        assert_eq!(event.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(event.ttl, Some(64));
    }

    #[test]
    fn parses_tcp_flags() {
        let mut frame = Vec::new();
        PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(51000, 443, 0, 65535)
            .write(&mut frame, &[])
            .unwrap();
        frame[47] = 0x02;

        let raw = RawPacket::new(UNIX_EPOCH, LinkType::Ethernet, frame, 60);
        let event = parse(&raw).unwrap();

        assert_eq!(event.protocol, Protocol::Tcp);
        assert_eq!(event.tcp_flags.unwrap().to_string(), "SYN");
        assert_eq!(event.src_port, Some(51000));
        assert_eq!(event.dst_port, Some(443));
    }

    #[test]
    fn parses_raw_ip_link_type() {
        let mut frame = Vec::new();
        PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
            .ipv4([192, 168, 1, 1], [8, 8, 8, 8], 128)
            .udp(1000, 53)
            .write(&mut frame, &[0; 12])
            .unwrap();

        let raw = RawPacket::new(
            UNIX_EPOCH,
            LinkType::RawIp,
            frame[14..].to_vec(),
            frame.len() as u32,
        );
        let event = parse(&raw).unwrap();
        assert_eq!(event.protocol, Protocol::Dns);
        assert_eq!(event.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn rejects_truncated_frame() {
        let raw = RawPacket::new(UNIX_EPOCH, LinkType::Ethernet, vec![0; 8], 8);
        assert!(parse(&raw).is_err());
    }
}
