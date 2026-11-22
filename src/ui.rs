use crate::app::{AppSnapshot, AppState, Tab};
use crate::parser::{format_bytes, format_clock, Protocol};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table};
use ratatui::Frame;

const ACCENT: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;
const WARNING: Color = Color::Yellow;
const CRITICAL: Color = Color::Red;

pub fn handle_key(key: KeyEvent, state: &AppState) -> bool {
    if state.snapshot().prompt.is_some() {
        match key.code {
            KeyCode::Esc => state.cancel_prompt(),
            KeyCode::Enter => {
                if let Err(error) = state.submit_prompt() {
                    state.set_export_message(error);
                }
            }
            KeyCode::Backspace => state.pop_prompt(),
            KeyCode::Char(character) => state.push_prompt(character),
            _ => {}
        }
        return false;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            state.request_stop();
            return true;
        }
        KeyCode::Char('p') | KeyCode::Char(' ') => state.toggle_pause(),
        KeyCode::Char('f') => state.cycle_filter(),
        KeyCode::Char('a') => state.toggle_alerts(),
        KeyCode::Char('e') => state.open_prompt(),
        _ => {}
    }
    false
}

pub fn draw(frame: &mut Frame, snapshot: &AppSnapshot) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(10),
            Constraint::Percentage(42),
            Constraint::Length(1),
        ])
        .split(frame.area());

    render_header(frame, chunks[0], snapshot);
    render_dashboard(frame, chunks[1], snapshot);
    render_packets(frame, chunks[2], snapshot);
    render_footer(frame, chunks[3], snapshot);
}

fn render_header(frame: &mut Frame, area: Rect, snapshot: &AppSnapshot) {
    let status = snapshot.status.as_str();
    let status_color = match status {
        "RUNNING" => Color::Green,
        "FINISHED" => Color::Cyan,
        "ERROR" => CRITICAL,
        _ => WARNING,
    };
    let line = Line::from(vec![
        Span::styled(
            " netwatch-rs ",
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" interface: {} ", snapshot.interface)),
        Span::styled(
            format!(" {} ", status),
            Style::default()
                .fg(Color::Black)
                .bg(status_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            " {} pkt/s  {}  ",
            snapshot.stats.pps,
            format_bytes(snapshot.stats.bytes_per_sec)
        )),
        Span::styled(
            if snapshot.paused { "PAUSED" } else { "LIVE" },
            Style::default()
                .fg(if snapshot.paused {
                    WARNING
                } else {
                    Color::Green
                })
                .add_modifier(Modifier::BOLD),
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_dashboard(frame: &mut Frame, area: Rect, snapshot: &AppSnapshot) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(columns[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(columns[1]);

    render_sparkline(frame, left[0], snapshot);
    render_talkers(frame, left[1], snapshot);
    render_protocols(frame, right[0], snapshot);
    render_alerts(frame, right[1], snapshot);
}

fn render_sparkline(frame: &mut Frame, area: Rect, snapshot: &AppSnapshot) {
    let max = snapshot
        .stats
        .sparkline
        .iter()
        .copied()
        .max()
        .unwrap_or(1)
        .max(1);
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .title(" TRAFFIC SPARKLINE (60s) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT)),
        )
        .data(&snapshot.stats.sparkline)
        .max(max)
        .style(Style::default().fg(Color::LightGreen));
    frame.render_widget(sparkline, area);
}

fn render_talkers(frame: &mut Frame, area: Rect, snapshot: &AppSnapshot) {
    let rows: Vec<Row> = snapshot
        .stats
        .top_talkers
        .iter()
        .map(|talker| {
            Row::new(vec![
                Cell::from(talker.ip.to_string()),
                Cell::from(format!("{} pkt", talker.packets)),
                Cell::from(format_bytes(talker.bytes)),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(45),
            Constraint::Percentage(30),
            Constraint::Percentage(25),
        ],
    )
    .header(
        Row::new(vec!["SOURCE IP", "PACKETS", "BYTES"])
            .style(Style::default().fg(MUTED).add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .block(
        Block::default()
            .title(" TOP TALKERS (60s) ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT)),
    );
    frame.render_widget(table, area);
}

fn render_protocols(frame: &mut Frame, area: Rect, snapshot: &AppSnapshot) {
    let lines: Vec<Line> = snapshot
        .stats
        .protocols
        .iter()
        .map(|share| {
            let filled = (share.percent as usize * 20) / 100;
            let bar = format!("{}{}", "█".repeat(filled), "░".repeat(20 - filled));
            Line::from(vec![
                Span::styled(
                    format!("{:<6}", share.protocol.as_str()),
                    Style::default()
                        .fg(protocol_color(share.protocol))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(" [{:<20}] {:>3}% ", bar, share.percent)),
            ])
        })
        .collect();
    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" PROTOCOL DISTRIBUTION (60s) ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT)),
    );
    frame.render_widget(paragraph, area);
}

fn render_alerts(frame: &mut Frame, area: Rect, snapshot: &AppSnapshot) {
    let focused = snapshot.tab == Tab::Alerts;
    let border_color = if focused { WARNING } else { ACCENT };
    let mut lines: Vec<Line> = Vec::new();
    for alert in snapshot.alerts.iter().rev().take(20) {
        let color = if alert.severity.as_str() == "CRIT" {
            CRITICAL
        } else {
            WARNING
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("[{}] ", format_clock(alert.timestamp_ms)),
                Style::default().fg(MUTED),
            ),
            Span::styled(
                format!("{} ", alert.severity.as_str()),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{}: {} ", alert.kind.as_str(), alert.source_ip)),
            Span::styled(alert.detail.clone(), Style::default().fg(MUTED)),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "No alerts in this session.",
            Style::default().fg(MUTED),
        )));
    }
    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(format!(
                " SECURITY ALERTS ({}) {} ",
                snapshot.alerts.len(),
                if focused { "[ACTIVE]" } else { "" }
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    );
    frame.render_widget(paragraph, area);
}

fn render_packets(frame: &mut Frame, area: Rect, snapshot: &AppSnapshot) {
    let rows: Vec<Row> = snapshot
        .packets
        .iter()
        .filter(|packet| snapshot.filter.matches(packet.protocol))
        .rev()
        .take(200)
        .map(|packet| {
            let color = protocol_color(packet.protocol);
            Row::new(vec![
                Cell::from(format_clock(packet.timestamp_ms)),
                Cell::from(Span::styled(
                    packet.protocol.as_str(),
                    Style::default().fg(color),
                )),
                Cell::from(packet.endpoint()),
                Cell::from(packet.detail()),
                Cell::from(format!("{} B", packet.length)),
            ])
            .style(Style::default().fg(if snapshot.paused {
                MUTED
            } else {
                Color::White
            }))
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(13),
            Constraint::Length(7),
            Constraint::Percentage(48),
            Constraint::Percentage(27),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(vec!["TIME", "PROTO", "ENDPOINT", "INFO", "SIZE"])
            .style(Style::default().fg(MUTED).add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .block(
        Block::default()
            .title(format!(
                " LIVE PACKETS (Filter: {}) ",
                snapshot.filter.as_str()
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT)),
    );
    frame.render_widget(table, area);
}

fn render_footer(frame: &mut Frame, area: Rect, snapshot: &AppSnapshot) {
    let message = if let Some(prompt) = &snapshot.prompt {
        format!(" Export file (JSON/CSV): {}_ ", prompt)
    } else if let Some(message) = &snapshot.export_message {
        format!(" {} ", message)
    } else {
        " [q] Quit | [p] Pause | [f] Filter | [a] Alerts | [e] Export JSON/CSV ".to_string()
    };
    frame.render_widget(
        Paragraph::new(message).style(Style::default().fg(Color::Black).bg(ACCENT)),
        area,
    );
}

fn protocol_color(protocol: Protocol) -> Color {
    match protocol {
        Protocol::Tcp => Color::Cyan,
        Protocol::Udp => Color::LightBlue,
        Protocol::Dns => Color::LightYellow,
        Protocol::Icmp => Color::LightMagenta,
        Protocol::Other => MUTED,
    }
}
