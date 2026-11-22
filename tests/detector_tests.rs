use etherparse::PacketBuilder;
use netwatch_rs::detector::{AnomalyEngine, AnomalyKind, DetectorConfig, Severity};
use netwatch_rs::parser::{parse, LinkType, PacketEvent, Protocol, RawPacket, TcpFlags};
use std::net::IpAddr;
use std::time::{Duration, Instant, UNIX_EPOCH};

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

#[allow(clippy::too_many_arguments)]
fn event(
    timestamp_ms: u64,
    src: IpAddr,
    dst: IpAddr,
    protocol: Protocol,
    src_port: u16,
    dst_port: u16,
    syn: bool,
    ack: bool,
    dns_query: Option<&str>,
) -> PacketEvent {
    PacketEvent {
        timestamp_ms,
        protocol,
        src_ip: src,
        dst_ip: dst,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        tcp_flags: Some(TcpFlags {
            syn,
            ack,
            ..TcpFlags::default()
        }),
        icmp_type: None,
        icmp_code: None,
        dns_query: dns_query.map(str::to_string),
        length: 60,
        ttl: Some(64),
    }
}

#[test]
fn detects_port_scan_above_threshold() {
    let mut engine = AnomalyEngine::default();
    let attacker = ip("10.0.0.99");
    let target = ip("192.168.1.10");
    let mut alerts = Vec::new();

    for offset in 0..16u64 {
        alerts.extend(engine.observe(&event(
            1_000 + offset * 200,
            attacker,
            target,
            Protocol::Tcp,
            50_000 + offset as u16,
            20 + offset as u16,
            true,
            false,
            None,
        )));
    }

    let scan = alerts
        .iter()
        .find(|alert| alert.kind == AnomalyKind::PortScan)
        .expect("port scan alert");
    assert_eq!(scan.source_ip, attacker);
    assert_eq!(scan.severity, Severity::Warn);
    assert!(scan.detail.contains("16 distinct ports"));
}

#[test]
fn ignores_port_scan_below_threshold() {
    let mut engine = AnomalyEngine::default();
    let attacker = ip("10.0.0.99");
    let target = ip("192.168.1.10");
    let mut alerts = Vec::new();

    for offset in 0..15u64 {
        alerts.extend(engine.observe(&event(
            1_000 + offset * 100,
            attacker,
            target,
            Protocol::Tcp,
            50_000 + offset as u16,
            20 + offset as u16,
            true,
            false,
            None,
        )));
    }

    assert!(!alerts
        .iter()
        .any(|alert| alert.kind == AnomalyKind::PortScan));
}

#[test]
fn detects_syn_spike_without_ack() {
    let mut engine = AnomalyEngine::default();
    let attacker = ip("10.0.0.99");
    let target = ip("192.168.1.10");
    let mut alerts = Vec::new();

    for offset in 0..51u64 {
        alerts.extend(engine.observe(&event(
            2_000 + offset * 10,
            attacker,
            target,
            Protocol::Tcp,
            40_000 + offset as u16,
            80,
            true,
            false,
            None,
        )));
    }

    let spike = alerts
        .iter()
        .find(|alert| alert.kind == AnomalyKind::SynSpike)
        .expect("SYN spike alert");
    assert_eq!(spike.source_ip, attacker);
    assert_eq!(spike.severity, Severity::Crit);
    assert!(spike.detail.contains("unacknowledged SYN"));
}

#[test]
fn ack_pairs_suppress_syn_spike() {
    let mut engine = AnomalyEngine::default();
    let attacker = ip("10.0.0.99");
    let target = ip("192.168.1.10");
    let mut alerts = Vec::new();

    for offset in 0..51u64 {
        let time = 3_000 + offset * 10;
        alerts.extend(engine.observe(&event(
            time,
            attacker,
            target,
            Protocol::Tcp,
            40_000 + offset as u16,
            80,
            true,
            false,
            None,
        )));
        alerts.extend(engine.observe(&event(
            time + 1,
            target,
            attacker,
            Protocol::Tcp,
            80,
            40_000 + offset as u16,
            false,
            true,
            None,
        )));
    }

    assert!(!alerts
        .iter()
        .any(|alert| alert.kind == AnomalyKind::SynSpike));
}

#[test]
fn detects_dns_burst() {
    let mut engine = AnomalyEngine::default();
    let source = ip("192.168.1.45");
    let resolver = ip("8.8.8.8");
    let mut alerts = Vec::new();

    for offset in 0..51u64 {
        let mut packet = event(
            4_000 + offset * 100,
            source,
            resolver,
            Protocol::Dns,
            50_000 + offset as u16,
            53,
            false,
            false,
            Some("example.com"),
        );
        packet.tcp_flags = None;
        alerts.extend(engine.observe(&packet));
    }

    let burst = alerts
        .iter()
        .find(|alert| alert.kind == AnomalyKind::DnsBurst)
        .expect("DNS burst alert");
    assert_eq!(burst.source_ip, source);
    assert_eq!(burst.severity, Severity::Warn);
    assert!(burst.detail.contains("51 queries"));
}

#[test]
fn custom_thresholds_are_honoured() {
    let config = DetectorConfig {
        port_scan_ports: 3,
        port_scan_window: 2.0,
        syn_spike_count: 500,
        syn_spike_window: 1.0,
        dns_burst_window: 10.0,
        dns_burst_count: 500,
        cooldown: 1.0,
    };
    let mut engine = AnomalyEngine::new(config);
    let attacker = ip("10.0.0.99");
    let target = ip("192.168.1.10");
    let mut alerts = Vec::new();

    for offset in 0..4u64 {
        alerts.extend(engine.observe(&event(
            5_000 + offset * 100,
            attacker,
            target,
            Protocol::Tcp,
            50_000 + offset as u16,
            100 + offset as u16,
            true,
            false,
            None,
        )));
    }

    assert_eq!(
        alerts
            .iter()
            .filter(|alert| alert.kind == AnomalyKind::PortScan)
            .count(),
        1
    );
}

#[test]
#[ignore = "manual benchmark"]
fn parser_throughput() {
    let mut frame = Vec::new();
    PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .udp(51_000, 443)
        .write(&mut frame, &[0u8; 32])
        .unwrap();
    let raw = RawPacket::new(
        UNIX_EPOCH + Duration::from_secs(1),
        LinkType::Ethernet,
        frame,
        74,
    );

    let count = 100_000u64;
    let start = Instant::now();
    for _ in 0..count {
        parse(&raw).unwrap();
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!("parser throughput: {:.0} packets/s", count as f64 / elapsed);
}
