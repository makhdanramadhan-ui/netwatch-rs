use clap::Parser;
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use netwatch_rs::app::{AppState, CaptureStatus};
use netwatch_rs::capture::{self, CaptureOutcome, CaptureSource};
use netwatch_rs::detector::AnomalyEngine;
use netwatch_rs::parser::{format_bytes, format_clock, parse};
use netwatch_rs::ui;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const QUEUE_CAPACITY: usize = 4096;
const FRAME_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Parser, Debug)]
#[command(
    name = "netwatch-rs",
    version,
    about = "Live packet monitor and mini-IDS TUI"
)]
struct Args {
    #[arg(short, long, value_name = "NAME", conflicts_with = "pcap")]
    interface: Option<String>,

    #[arg(long, value_name = "FILE", conflicts_with = "interface")]
    pcap: Option<PathBuf>,

    #[arg(short, long, value_name = "FILE")]
    export: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("netwatch-rs: {}", error);
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let source = match args.pcap {
        Some(path) => {
            if !path.is_file() {
                return Err(format!("pcap file not found: {}", path.display()));
            }
            CaptureSource::File(path.to_string_lossy().into_owned())
        }
        None => {
            if !io::stdout().is_terminal() {
                return Err(
                    "live capture needs an interactive terminal; use --pcap FILE for offline replay"
                        .to_string(),
                );
            }
            let interface = match args.interface {
                Some(name) => name,
                None => capture::default_interface()?,
            };
            CaptureSource::Live(interface)
        }
    };

    let interface_label = match &source {
        CaptureSource::Live(name) => name.clone(),
        CaptureSource::File(path) => format!("file:{}", path),
    };
    let state = Arc::new(AppState::new(interface_label, args.export));
    let (tx, rx) = sync_channel(QUEUE_CAPACITY);

    let capture_state = Arc::clone(&state);
    let capture_source = source.clone();
    let capture_thread = thread::spawn(move || {
        capture_state.set_status(CaptureStatus::Running);
        let result = capture::run(&capture_source, capture_state.should_stop_flag(), &tx);
        match &result {
            Ok(result) if result.outcome == CaptureOutcome::Finished => {
                capture_state.set_status(CaptureStatus::Finished);
            }
            Ok(_) => capture_state.set_status(CaptureStatus::Stopped),
            Err(error) => capture_state.set_status(CaptureStatus::Error(error.clone())),
        }
        result
    });

    let process_state = Arc::clone(&state);
    let process_thread = thread::spawn(move || {
        let mut detector = AnomalyEngine::default();
        while let Ok(raw) = rx.recv() {
            match parse(&raw) {
                Ok(event) => {
                    let alerts = detector.observe(&event);
                    process_state.on_packet(event, &alerts);
                }
                Err(_) => process_state.record_parse_error(),
            }
        }
    });

    if io::stdout().is_terminal() {
        run_tui(&state)?;
    } else {
        wait_for_capture(&state, &capture_thread, &process_thread)?;
        print_summary(&state);
    }

    let capture_result = capture_thread
        .join()
        .map_err(|_| "capture thread panicked".to_string())?;
    if let Ok(result) = capture_result {
        state.record_queue_drop(result.dropped);
    }
    process_thread
        .join()
        .map_err(|_| "processing thread panicked".to_string())?;

    if let Some(path) = state.requested_export_path() {
        state.export_to(&path)?;
    }

    Ok(())
}

fn wait_for_capture(
    state: &AppState,
    capture_thread: &thread::JoinHandle<Result<capture::CaptureResult, String>>,
    process_thread: &thread::JoinHandle<()>,
) -> Result<(), String> {
    while !capture_thread.is_finished() || !process_thread.is_finished() {
        thread::sleep(Duration::from_millis(20));
    }
    let _ = state;
    Ok(())
}

fn run_tui(state: &Arc<AppState>) -> Result<(), String> {
    enable_raw_mode().map_err(|error| format!("cannot enable raw mode: {}", error))?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(format!("cannot enter alternate screen: {}", error));
    }

    let backend = CrosstermBackend::new(stdout);
    let terminal_result =
        Terminal::new(backend).map_err(|error| format!("cannot start TUI: {}", error));
    let mut terminal = match terminal_result {
        Ok(terminal) => terminal,
        Err(error) => {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            return Err(error);
        }
    };

    let loop_result = tui_loop(&mut terminal, state);

    let _ = disable_raw_mode();
    let _ = terminal.show_cursor();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
    loop_result
}

fn tui_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &Arc<AppState>,
) -> Result<(), String> {
    while !state.should_stop() {
        terminal
            .draw(|frame| ui::draw(frame, &state.snapshot()))
            .map_err(|error| format!("cannot render TUI: {}", error))?;

        if event::poll(FRAME_INTERVAL).map_err(|error| format!("cannot poll input: {}", error))? {
            match event::read() {
                Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                    ui::handle_key(key, state);
                }
                Ok(_) => {}
                Err(error) => return Err(format!("cannot read input: {}", error)),
            }
        }
    }
    Ok(())
}

fn print_summary(state: &AppState) {
    let snapshot = state.snapshot();
    println!(
        "netwatch-rs | interface={} | status={} | packets={} | pps={} | throughput={}",
        snapshot.interface,
        snapshot.status.as_str(),
        snapshot.stats.total_packets,
        snapshot.stats.pps,
        format_bytes(snapshot.stats.bytes_per_sec)
    );
    for talker in snapshot.stats.top_talkers.iter().take(5) {
        println!(
            "talker {} -> {} pkt / {}",
            talker.ip,
            talker.packets,
            format_bytes(talker.bytes)
        );
    }
    for alert in &snapshot.alerts {
        println!(
            "alert [{}] {} {} {} {}",
            format_clock(alert.timestamp_ms),
            alert.severity.as_str(),
            alert.kind.as_str(),
            alert.source_ip,
            alert.detail
        );
    }
}
