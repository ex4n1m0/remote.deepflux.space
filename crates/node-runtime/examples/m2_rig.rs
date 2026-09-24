//! `m2_rig` — the M2 two-process gate binary (RD-006/007/008, delta D2):
//! host + controller as two processes on one machine, manual file-based
//! signaling routed **through the session state machines**, real DXGI
//! capture → MF H.264 encode → RTP, four data channels, real MF decode →
//! D3D11 present, host-side input consumption against the `InputSink`
//! trait, scripted scenarios with chaos injection, network-change
//! recovery, and schema-exact JSONL counters.
//!
//! Run (the wrapper creates a fresh signaling dir per run):
//!
//! ```text
//! cargo build --release -p node-runtime --example m2_rig
//! # terminal 1 (host)
//! ./target/release/examples/m2_rig.exe --role host --dir C:\temp\rd-sig-1
//! # terminal 2 (controller)
//! ./target/release/examples/m2_rig.exe --role controller --dir C:\temp\rd-sig-1 \
//!     --scenario full --summary out/controller-summary.json
//! ```
//!
//! Scenarios (driven by the controller; the host is a scripted peer that
//! auto-accepts consent and re-starts hosting after a transport failure):
//!
//! * `full` — connect → stream `--stream-secs` (default 60 s) with input
//!   chaos from +5 s → network-change recovery at 2/3 of the stream
//!   (`restart_ice` probe, hard transport teardown → both machines
//!   `Disconnected{TransportError}` → fresh transports → full
//!   re-signaling through the adapter → new session) → clean disconnect
//!   (`Disconnect{User}` over control + signaling; host
//!   `AllKeysUp(Disconnect)`).
//! * `loss-reorder-dup` — chaos + duplicate-signaling probe (own outbound
//!   envelopes re-delivered verbatim), no network change.
//! * `cycles` — `--cycles` (default 10) repeated
//!   connect/stream/disconnect rounds (GPU-suspension hammer).
//! * `soak` — one continuous session of `--stream-secs` (default 600 s).
//!
//! Safety: the host input sink here is a **recording** sink implementing
//! `input_windows::InputSink` — scripted input is never injected into the
//! real desktop (this machine is also the controller; the product plugs
//! the `SendInput` adapter into the same slot). SDP bodies travel only in
//! the signaling files; nothing sensitive is logged (invariant 6).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use capture_windows::{CaptureError, CaptureSource, DxgiCapture};
use codec_windows::{EncodeInput, VideoDecoder as _, VideoEncoder as _};
use diagnostics::{CounterRecord, FrameTiming, LinkSample, Origin, PerfSink, QueueKind};
use frame_surface::{GpuDevice, attach_thread_to_input_desktop};
use input_windows::{InputError, InputSink};
use node_runtime::Clock;
use node_runtime::clock::MonotonicClock;
use node_runtime::input::InputPump;
use node_runtime::metrics::{
    ClockFn, DropPolicy, FrameQueue, JsonlReport, LatestSlot, SessionSlot, spawn_resource_sampler,
};
use node_runtime::node::{Node, NodeObserver};
use node_runtime::pacing::FramePacer;
use node_runtime::signaling::{FileSignaling, SignalingDirection, SignalingIo};
use node_runtime::timers::MachineKind;
use protocol::capabilities::{
    Capabilities, EncoderCapabilities, EncoderKind, FeatureFlags, MonitorInfo,
};
use protocol::signaling::SessionSecret;
use protocol::wire::{
    AllKeysUpTrigger, ButtonState, ControlDisconnectReason, CursorMessage, InputEvent, WireMessage,
};
use render_windows::{
    D3D11Renderer, FrameRenderer as _, PresenterWindow, RenderFrame, WindowConfig,
};
use session::{ControllerState, DisconnectCause, HostState, SessionConfig};
use transport_webrtc::chaos::ChaosInjector;
use transport_webrtc::{Channel, VideoFrame, WebrtcTransport, WebrtcTransportRole};

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Args {
    role: &'static str,
    dir: PathBuf,
    scenario: &'static str,
    stream_secs: u64,
    cycles: u64,
    cycle_stream_secs: u64,
    fps: u32,
    encode_w: u32,
    encode_h: u32,
    bitrate_kbps: u32,
    monitor: String,
    window_w: i32,
    window_h: i32,
    drop_fast_pct: u32,
    reorder_fast_pct: u32,
    drop_reliable_nth: u64,
    seed: u64,
    mouse_moves: u64,
    stimulus: bool,
    metrics_dir: Option<PathBuf>,
    summary: PathBuf,
    report_stem: Option<String>,
    idle_timeout_secs: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        role: "",
        dir: std::env::temp_dir().join("rd-m2-signal"),
        scenario: "full",
        stream_secs: 60,
        cycles: 10,
        cycle_stream_secs: 20,
        fps: 60,
        encode_w: 1920,
        encode_h: 1080,
        bitrate_kbps: 8000,
        monitor: "primary".to_owned(),
        window_w: 1280,
        window_h: 720,
        drop_fast_pct: 10,
        reorder_fast_pct: 5,
        drop_reliable_nth: 40,
        seed: 2026,
        mouse_moves: 3000,
        stimulus: true,
        metrics_dir: None,
        summary: std::env::temp_dir().join("rd-m2-summary.json"),
        report_stem: None,
        idle_timeout_secs: 300,
    };
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < raw.len() {
        let (flag, value) = (raw[i].as_str(), raw.get(i + 1));
        let need = |name: &str| -> Result<String, String> {
            value
                .cloned()
                .ok_or_else(|| format!("missing value for {name}"))
        };
        match flag {
            "--role" => {
                let v = need("--role")?;
                args.role = match v.as_str() {
                    "host" => "host",
                    "controller" => "controller",
                    other => return Err(format!("unknown role {other:?}")),
                };
                i += 2;
            }
            "--dir" => {
                args.dir = PathBuf::from(need("--dir")?);
                i += 2;
            }
            "--scenario" => {
                let v = need("--scenario")?;
                args.scenario = match v.as_str() {
                    "full" => "full",
                    "loss-reorder-dup" => "loss-reorder-dup",
                    "cycles" => "cycles",
                    "soak" => "soak",
                    other => return Err(format!("unknown scenario {other:?}")),
                };
                i += 2;
            }
            "--stream-secs" => {
                args.stream_secs = need("--stream-secs")?
                    .parse()
                    .map_err(|e| format!("stream-secs: {e}"))?;
                i += 2;
            }
            "--cycles" => {
                args.cycles = need("--cycles")?
                    .parse()
                    .map_err(|e| format!("cycles: {e}"))?;
                i += 2;
            }
            "--cycle-stream-secs" => {
                args.cycle_stream_secs = need("--cycle-stream-secs")?
                    .parse()
                    .map_err(|e| format!("cycle-stream-secs: {e}"))?;
                i += 2;
            }
            "--fps" => {
                args.fps = need("--fps")?.parse().map_err(|e| format!("fps: {e}"))?;
                i += 2;
            }
            "--encode-size" => {
                let v = need("--encode-size")?;
                if let Some((w, h)) = v.split_once('x') {
                    args.encode_w = w.parse().unwrap_or(1920);
                    args.encode_h = h.parse().unwrap_or(1080);
                }
                i += 2;
            }
            "--bitrate-kbps" => {
                args.bitrate_kbps = need("--bitrate-kbps")?
                    .parse()
                    .map_err(|e| format!("bitrate: {e}"))?;
                i += 2;
            }
            "--monitor" => {
                args.monitor = need("--monitor")?;
                i += 2;
            }
            "--window-size" => {
                let v = need("--window-size")?;
                if let Some((w, h)) = v.split_once('x') {
                    args.window_w = w.parse().unwrap_or(1280);
                    args.window_h = h.parse().unwrap_or(720);
                }
                i += 2;
            }
            "--drop-fast-pct" => {
                args.drop_fast_pct = need("--drop-fast-pct")?
                    .parse()
                    .map_err(|e| format!("drop: {e}"))?;
                i += 2;
            }
            "--reorder-fast-pct" => {
                args.reorder_fast_pct = need("--reorder-fast-pct")?
                    .parse()
                    .map_err(|e| format!("reorder: {e}"))?;
                i += 2;
            }
            "--drop-reliable-nth" => {
                args.drop_reliable_nth = need("--drop-reliable-nth")?
                    .parse()
                    .map_err(|e| format!("drop-nth: {e}"))?;
                i += 2;
            }
            "--seed" => {
                args.seed = need("--seed")?.parse().map_err(|e| format!("seed: {e}"))?;
                i += 2;
            }
            "--mouse-moves" => {
                args.mouse_moves = need("--mouse-moves")?
                    .parse()
                    .map_err(|e| format!("mouse: {e}"))?;
                i += 2;
            }
            "--no-stimulus" => {
                args.stimulus = false;
                i += 1;
            }
            "--metrics-dir" => {
                args.metrics_dir = Some(PathBuf::from(need("--metrics-dir")?));
                i += 2;
            }
            "--summary" => {
                args.summary = PathBuf::from(need("--summary")?);
                i += 2;
            }
            "--report-stem" => {
                args.report_stem = Some(need("--report-stem")?);
                i += 2;
            }
            "--idle-timeout-secs" => {
                args.idle_timeout_secs = need("--idle-timeout-secs")?
                    .parse()
                    .map_err(|e| format!("idle-timeout: {e}"))?;
                i += 2;
            }
            "--help" | "-h" => {
                println!(
                    "m2_rig --role host|controller --dir <sig-dir> [--scenario full|loss-reorder-dup|cycles|soak]\n\
                     [--stream-secs N] [--cycles N] [--cycle-stream-secs N] [--fps 60] [--encode-size WxH]\n\
                     [--bitrate-kbps N] [--monitor primary] [--window-size WxH] [--no-stimulus]\n\
                     [--drop-fast-pct N] [--reorder-fast-pct N] [--drop-reliable-nth N] [--seed N]\n\
                     [--mouse-moves N] [--metrics-dir DIR] [--summary FILE] [--report-stem NAME]\
                     [--idle-timeout-secs N]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    if args.role.is_empty() {
        return Err("required: --role host|controller".into());
    }
    if args.scenario == "soak" && args.stream_secs == 60 {
        args.stream_secs = 600;
    }
    Ok(args)
}

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const HOST_DEVICE: &str = "rig-host";
const CONTROLLER_DEVICE: &str = "rig-controller";

fn rig_capabilities(controller: bool) -> Capabilities {
    Capabilities {
        encoders: if controller {
            vec![]
        } else {
            vec![EncoderCapabilities {
                kind: EncoderKind::Hardware,
                codec: protocol::capabilities::Codec::H264,
                max_width_px: 2560,
                max_height_px: 1440,
                max_fps: 60,
            }]
        },
        monitors: if controller {
            vec![]
        } else {
            vec![MonitorInfo {
                monitor_id: "\\\\.\\DISPLAY1".to_owned(),
                width_px: 1920,
                height_px: 1080,
                is_primary: true,
            }]
        },
        max_bitrate_kbps: 50_000,
        features: FeatureFlags::empty()
            .with(FeatureFlags::TRICKLE_ICE)
            .with(FeatureFlags::CURSOR_CHANNEL)
            .with(FeatureFlags::INPUT_FAST_CHANNEL),
    }
}

fn write_json_atomic(path: &Path, json: &str) {
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, json).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

fn date_string() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (now / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}")
}

// ---------------------------------------------------------------------------
// Recording input sink (real `InputSink` trait object slot; the rig never
// injects into the real desktop — this machine is also the controller)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RecordingSink {
    held: usize,
    applied: u64,
    releases: u64,
}

impl InputSink for RecordingSink {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        match event {
            InputEvent::Key { state, .. } | InputEvent::MouseButton { state, .. } => match state {
                ButtonState::Pressed => self.held += 1,
                ButtonState::Released => self.held = self.held.saturating_sub(1),
            },
            InputEvent::AllKeysUp { .. } => self.held = 0,
            _ => {}
        }
        self.applied += 1;
        Ok(())
    }

    fn all_keys_up(&mut self) -> Result<(), InputError> {
        self.held = 0;
        self.releases += 1;
        Ok(())
    }

    fn held_count(&self) -> usize {
        self.held
    }
}

// ---------------------------------------------------------------------------
// Pipeline items
// ---------------------------------------------------------------------------

struct CapItem {
    frame_id: u64,
    capture_ns: u64,
    surface: frame_surface::FrameSurface,
}

struct WireItem {
    packet: codec_windows::EncodedPacket,
    capture_ns: u64,
    encode_submit_ns: u64,
    encode_done_ns: u64,
}

struct RecvItem {
    frame: transport_webrtc::ReceivedFrame,
    recv_ns: u64,
}

struct DecItem {
    frame_id: u64,
    recv_ns: u64,
    decode_done_ns: u64,
    decoded: codec_windows::DecodedFrame,
}

#[derive(Default)]
struct HostPipeCounters {
    captured: AtomicU64,
    encoded: AtomicU64,
    cursor_only: AtomicU64,
    encode_deferred: AtomicU64,
    keyframes: AtomicU64,
    keyframe_forced: AtomicU64,
    cursor_positions: AtomicU64,
    device_lost: AtomicU64,
    capture_reinit: AtomicU64,
}

/// One live host capture→encode pipeline (rebuilt per session). The
/// F20-fixed capture pacing lives here: absolute-deadline high-resolution
/// waitable timer at `--fps`.
struct HostPipeline {
    q_cap_enc: Arc<FrameQueue<CapItem>>,
    q_enc_send: Arc<FrameQueue<WireItem>>,
    cursor_slot: Arc<LatestSlot<CursorMessage>>,
    capture_stop: Arc<AtomicBool>,
    joins: Vec<std::thread::JoinHandle<()>>,
    counters: Arc<HostPipeCounters>,
    pacer_ticks: Arc<AtomicU64>,
    pacer_skipped: Arc<AtomicU64>,
}

impl HostPipeline {
    fn start(
        device: GpuDevice,
        force_keyframe: Arc<AtomicBool>,
        args: &Args,
        report: &JsonlReport,
        session: Arc<SessionSlot>,
        clock: Arc<MonotonicClock>,
    ) -> Result<Self, String> {
        let q_cap_enc = Arc::new(FrameQueue::new(
            QueueKind::CaptureToEncode,
            1,
            DropPolicy::NewestWins,
            Box::new(report.sink_handle(session.clone())),
            session.clone(),
            Arc::new({
                let clock = clock.clone();
                move || clock.now_ns()
            }) as ClockFn,
        ));
        let q_enc_send = Arc::new(FrameQueue::new(
            QueueKind::EncodeToSend,
            1,
            DropPolicy::NewestWins,
            Box::new(report.sink_handle(session.clone())),
            session.clone(),
            Arc::new({
                let clock = clock.clone();
                move || clock.now_ns()
            }) as ClockFn,
        ));
        let cursor_slot = Arc::new(LatestSlot::new());
        let counters = Arc::new(HostPipeCounters::default());
        let pacer_ticks = Arc::new(AtomicU64::new(0));
        let pacer_skipped = Arc::new(AtomicU64::new(0));
        let capture_stop = Arc::new(AtomicBool::new(false));
        let mut joins = Vec::new();

        // ---- capture thread ----
        {
            let stop = Arc::clone(&capture_stop);
            let q = Arc::clone(&q_cap_enc);
            let cursor_slot = Arc::clone(&cursor_slot);
            let counters = Arc::clone(&counters);
            let clock = clock.clone();
            let device = device.clone();
            let monitor = args.monitor.clone();
            let fps = args.fps;
            let ticks = Arc::clone(&pacer_ticks);
            let skipped = Arc::clone(&pacer_skipped);
            joins.push(
                std::thread::Builder::new()
                    .name("capture".into())
                    .spawn(move || {
                        attach_thread_to_input_desktop().expect("input desktop");
                        let mut cap =
                            DxgiCapture::new(device.clone(), &monitor).expect("duplicate output");
                        let stamp_clock = clock.clone();
                        cap.set_clock(Box::new(move || stamp_clock.now_ns()));
                        eprintln!(
                            "[host] capture: {} at {}x{}, pacer fps {fps}",
                            cap.monitor_id(),
                            cap.dimensions().0,
                            cap.dimensions().1
                        );
                        let mut pacer = FramePacer::new(fps);
                        eprintln!("[host] capture pacer mode: {}", pacer.mode);
                        pacer.start();
                        while !stop.load(Ordering::Acquire) {
                            pacer.wait();
                            ticks.store(pacer.ticks, Ordering::Relaxed);
                            skipped.store(pacer.skipped, Ordering::Relaxed);
                            let budget = pacer.period();
                            match cap.next_frame(budget) {
                                Ok(Some(frame)) => {
                                    if let Some(cursor) = frame.cursor {
                                        if matches!(cursor, CursorMessage::Position { .. }) {
                                            counters
                                                .cursor_positions
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        cursor_slot.put(cursor);
                                    }
                                    if frame.metadata.only_cursor_update {
                                        counters.cursor_only.fetch_add(1, Ordering::Relaxed);
                                        continue;
                                    }
                                    counters.captured.fetch_add(1, Ordering::Relaxed);
                                    let _ = q.push(CapItem {
                                        frame_id: frame.frame_id,
                                        capture_ns: frame.timestamp_ns,
                                        surface: frame.surface,
                                    });
                                }
                                Ok(None) => {}
                                Err(CaptureError::AccessLost(_)) => {
                                    counters.capture_reinit.fetch_add(1, Ordering::Relaxed);
                                    std::thread::sleep(Duration::from_millis(100));
                                    let _ = cap.reinit();
                                }
                                Err(CaptureError::AccessDenied(detail)) => {
                                    eprintln!(
                                        "[host] capture denied (lock screen/protected): {detail}"
                                    );
                                    std::thread::sleep(Duration::from_millis(500));
                                }
                                Err(CaptureError::DisplayChanged(detail)) => {
                                    counters.capture_reinit.fetch_add(1, Ordering::Relaxed);
                                    eprintln!("[host] display changed: {detail}");
                                    std::thread::sleep(Duration::from_millis(200));
                                    match DxgiCapture::new(device.clone(), "primary") {
                                        Ok(new_cap) => cap = new_cap,
                                        Err(e) => eprintln!("[host] re-select failed: {e}"),
                                    }
                                }
                                Err(CaptureError::DeviceLost(detail)) => {
                                    eprintln!("[host] capture DEVICE LOST: {detail}");
                                    counters.device_lost.fetch_add(1, Ordering::Relaxed);
                                    break;
                                }
                                Err(e) => {
                                    eprintln!("[host] capture error: {e}");
                                    std::thread::sleep(Duration::from_millis(100));
                                }
                            }
                        }
                        q.close();
                    })
                    .expect("spawn capture"),
            );
        }

        // ---- encode thread ----
        {
            let q_in = Arc::clone(&q_cap_enc);
            let q_out = Arc::clone(&q_enc_send);
            let counters = Arc::clone(&counters);
            let force = Arc::clone(&force_keyframe);
            let clock = clock.clone();
            let device = device.clone();
            let enc_cfg = codec_windows::MfEncoderConfig {
                width: args.encode_w & !1,
                height: args.encode_h & !1,
                fps: args.fps,
                bitrate_bps: args.bitrate_kbps.saturating_mul(1000),
                gop_size: args.fps * 2,
                preference: codec_windows::MfEncoderPreference::Auto,
            };
            joins.push(
                std::thread::Builder::new()
                    .name("encode".into())
                    .spawn(move || {
                        let mut encoder = match codec_windows::MfEncoder::new(device, enc_cfg) {
                            Ok(encoder) => encoder,
                            Err(e) => {
                                eprintln!("[host] encoder init failed: {e}");
                                q_out.close();
                                return;
                            }
                        };
                        eprintln!("[host] encoder: {}", encoder.describe());
                        loop {
                            let Some(item) = q_in.pop(Duration::from_millis(100)) else {
                                if !q_in.is_open() {
                                    break;
                                }
                                continue;
                            };
                            let submit_ns = clock.now_ns();
                            let input = EncodeInput {
                                frame_id: item.frame_id,
                                timestamp_ns: item.capture_ns,
                                surface: item.surface,
                            };
                            let force = force.swap(false, Ordering::AcqRel);
                            if force {
                                counters.keyframe_forced.fetch_add(1, Ordering::Relaxed);
                            }
                            match encoder.encode(input, force) {
                                Ok(mut packet) => {
                                    packet.timestamp_ns = item.capture_ns;
                                    counters.encoded.fetch_add(1, Ordering::Relaxed);
                                    if packet.is_keyframe {
                                        counters.keyframes.fetch_add(1, Ordering::Relaxed);
                                    }
                                    let done_ns = clock.now_ns();
                                    let _ = q_out.push(WireItem {
                                        packet,
                                        capture_ns: item.capture_ns,
                                        encode_submit_ns: submit_ns,
                                        encode_done_ns: done_ns,
                                    });
                                }
                                Err(codec_windows::CodecError::Timeout(_)) => {
                                    counters.encode_deferred.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(codec_windows::CodecError::DeviceLost(d)) => {
                                    eprintln!("[host] encode DEVICE LOST: {d}");
                                    counters.device_lost.fetch_add(1, Ordering::Relaxed);
                                    break;
                                }
                                Err(e) => eprintln!("[host] encode error: {e}"),
                            }
                        }
                        q_out.close();
                    })
                    .expect("spawn encode"),
            );
        }

        Ok(Self {
            q_cap_enc,
            q_enc_send,
            cursor_slot,
            capture_stop,
            joins,
            counters,
            pacer_ticks,
            pacer_skipped,
        })
    }

    fn stop(mut self) {
        self.capture_stop.store(true, Ordering::Release);
        self.q_cap_enc.close();
        self.q_enc_send.close();
        for join in self.joins.drain(..) {
            let _ = join.join();
        }
    }
}

#[derive(Default)]
struct ControllerPipeCounters {
    received: AtomicU64,
    decoded: AtomicU64,
    presented: AtomicU64,
    decode_errors: AtomicU64,
    idr_gate_drops: AtomicU64,
    keyframe_requests: AtomicU64,
    frames_missing_packets: AtomicU64,
    frame_id_gaps: AtomicU64,
    frames_without_frame_id: AtomicU64,
    device_lost: AtomicU64,
    window_closed: AtomicBool,
}

/// One live controller decode→present pipeline (rebuilt per session).
struct ControllerPipeline {
    q_recv_dec: Arc<FrameQueue<RecvItem>>,
    q_dec_pres: Arc<FrameQueue<DecItem>>,
    joins: Vec<std::thread::JoinHandle<()>>,
    reset_decoder: Arc<AtomicBool>,
    keyframe_needed: Arc<AtomicBool>,
    counters: Arc<ControllerPipeCounters>,
}

impl ControllerPipeline {
    fn start(
        device: GpuDevice,
        args: &Args,
        report: &JsonlReport,
        session: Arc<SessionSlot>,
        clock: Arc<MonotonicClock>,
    ) -> Result<Self, String> {
        let q_recv_dec = Arc::new(FrameQueue::new(
            QueueKind::RecvToDecode,
            2,
            DropPolicy::Reject,
            Box::new(report.sink_handle(session.clone())),
            session.clone(),
            Arc::new({
                let clock = clock.clone();
                move || clock.now_ns()
            }) as ClockFn,
        ));
        let q_dec_pres = Arc::new(FrameQueue::new(
            QueueKind::DecodeToPresent,
            1,
            DropPolicy::NewestWins,
            Box::new(report.sink_handle(session.clone())),
            Arc::clone(&session),
            Arc::new({
                let clock = clock.clone();
                move || clock.now_ns()
            }) as ClockFn,
        ));
        let reset_decoder = Arc::new(AtomicBool::new(false));
        let keyframe_needed = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(ControllerPipeCounters::default());
        let mut joins = Vec::new();

        // ---- decode thread ----
        {
            let q_in = Arc::clone(&q_recv_dec);
            let q_out = Arc::clone(&q_dec_pres);
            let counters = Arc::clone(&counters);
            let reset = Arc::clone(&reset_decoder);
            let keyframe_needed = Arc::clone(&keyframe_needed);
            let clock = clock.clone();
            let device = device.clone();
            joins.push(
                std::thread::Builder::new()
                    .name("decode".into())
                    .spawn(move || {
                        let mut decoder = codec_windows::MfDecoder::new(
                            device,
                            codec_windows::MfDecoderConfig { use_gpu: true },
                        )
                        .expect("decoder");
                        eprintln!("[controller] decoder: {}", decoder.describe());
                        let mut last_frame_id: Option<u64> = None;
                        loop {
                            let Some(item) = q_in.pop(Duration::from_millis(100)) else {
                                if !q_in.is_open() {
                                    break;
                                }
                                continue;
                            };
                            let RecvItem { frame, recv_ns } = item;
                            let frame_id = frame.frame_id;
                            match frame_id {
                                Some(id) => {
                                    if last_frame_id.is_some_and(|last| id != last + 1) {
                                        counters.frame_id_gaps.fetch_add(1, Ordering::Relaxed);
                                        // Application-level loss (a frame never
                                        // arrived): the reference chain is broken
                                        // until the next IDR — flush and ask.
                                        reset.store(true, Ordering::Release);
                                        keyframe_needed.store(true, Ordering::Release);
                                    }
                                    last_frame_id = Some(id);
                                }
                                None => {
                                    counters
                                        .frames_without_frame_id
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            if frame.missing_packets > 0 {
                                counters
                                    .frames_missing_packets
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            if reset.swap(false, Ordering::AcqRel) {
                                let _ = decoder.reset();
                            }
                            // 90 kHz RTP clock → ns (join keys only).
                            let timestamp_ns = u64::from(frame.rtp_timestamp) * 1_000_000 / 90_000;
                            match decoder.decode(
                                &frame.bytes,
                                frame_id.unwrap_or(u64::MAX),
                                timestamp_ns,
                            ) {
                                Ok(decoded) => {
                                    counters.decoded.fetch_add(1, Ordering::Relaxed);
                                    let done_ns = clock.now_ns();
                                    let _ = q_out.push(DecItem {
                                        frame_id: frame_id.unwrap_or(u64::MAX),
                                        recv_ns,
                                        decode_done_ns: done_ns,
                                        decoded,
                                    });
                                }
                                Err(codec_windows::CodecError::DroppedAfterReset(_)) => {
                                    counters.idr_gate_drops.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(codec_windows::CodecError::DeviceLost(d)) => {
                                    eprintln!("[controller] decode DEVICE LOST: {d}");
                                    counters.device_lost.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    counters.decode_errors.fetch_add(1, Ordering::Relaxed);
                                    eprintln!("[controller] decode error: {e}");
                                }
                            }
                        }
                        q_out.close();
                    })
                    .expect("spawn decode"),
            );
        }

        // ---- present thread (owns the real viewer window) ----
        {
            let q = Arc::clone(&q_dec_pres);
            let counters = Arc::clone(&counters);
            let clock = clock.clone();
            let device = device.clone();
            let mut sink = report.sink_handle(session);
            let (win_w, win_h) = (args.window_w, args.window_h);
            joins.push(
                std::thread::Builder::new()
                    .name("present".into())
                    .spawn(move || {
                        attach_thread_to_input_desktop().expect("input desktop");
                        let mut window = PresenterWindow::create(&WindowConfig {
                            title: "M2 rig controller (real desktop capture)".into(),
                            width: win_w,
                            height: win_h,
                        })
                        .expect("viewer window");
                        let mut renderer = D3D11Renderer::new(
                            device,
                            window.hwnd(),
                            win_w.max(1) as u32,
                            win_h.max(1) as u32,
                        )
                        .expect("renderer");
                        loop {
                            let Some(item) = q.pop(Duration::from_millis(20)) else {
                                if !q.is_open() {
                                    break;
                                }
                                if !window.pump() {
                                    eprintln!("[controller] viewer window closed by user");
                                    counters.window_closed.store(true, Ordering::Release);
                                    break;
                                }
                                if window.take_resized() {
                                    let (w, h) = window.client_size();
                                    let _ = renderer.resize(w.max(1) as u32, h.max(1) as u32);
                                }
                                continue;
                            };
                            if !window.pump() {
                                eprintln!("[controller] viewer window closed by user");
                                counters.window_closed.store(true, Ordering::Release);
                                break;
                            }
                            if window.take_resized() {
                                let (w, h) = window.client_size();
                                let _ = renderer.resize(w.max(1) as u32, h.max(1) as u32);
                            }
                            let rf = RenderFrame {
                                frame_id: item.frame_id,
                                timestamp_ns: item.decoded.timestamp_ns,
                                width_px: item.decoded.width,
                                height_px: item.decoded.height,
                                surface: item.decoded.surface,
                            };
                            if let Err(e) = renderer.present(&rf) {
                                eprintln!("[controller] present error: {e}");
                                if matches!(e, render_windows::RenderError::DeviceLost(_)) {
                                    counters.device_lost.fetch_add(1, Ordering::Relaxed);
                                }
                                break;
                            }
                            counters.presented.fetch_add(1, Ordering::Relaxed);
                            let present_ns = clock.now_ns();
                            // Controller half: emitted exactly when
                            // present_ns is filled (pinned timing).
                            sink.record(CounterRecord::FrameTiming(FrameTiming {
                                session_id: sink.session_id(),
                                origin: Origin::Controller,
                                frame_id: item.frame_id,
                                capture_ns: None,
                                encode_submit_ns: None,
                                encode_done_ns: None,
                                send_ns: None,
                                recv_ns: Some(item.recv_ns),
                                decode_done_ns: Some(item.decode_done_ns),
                                present_ns: Some(present_ns),
                            }));
                        }
                    })
                    .expect("spawn present"),
            );
        }

        Ok(Self {
            q_recv_dec,
            q_dec_pres,
            joins,
            reset_decoder,
            keyframe_needed,
            counters,
        })
    }

    fn stop(mut self) {
        self.q_recv_dec.close();
        self.q_dec_pres.close();
        for join in self.joins.drain(..) {
            let _ = join.join();
        }
    }
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("m2_rig: {err}");
            std::process::exit(2);
        }
    };
    let code = run(args);
    std::process::exit(code);
}

// ---------------------------------------------------------------------------
// GDI stimulus window (guaranteed desktop updates during soaks; M1
// methodology — the host captures the real desktop)
// ---------------------------------------------------------------------------

static STIM_TICK: AtomicU64 = AtomicU64::new(0);

fn spawn_stimulus(stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("stimulus".into())
        .spawn(move || {
            let _ = attach_thread_to_input_desktop();
            unsafe {
                use windows::Win32::System::LibraryLoader::GetModuleHandleW;
                use windows::Win32::UI::WindowsAndMessaging::*;
                let module = GetModuleHandleW(None).ok();
                let class_name: Vec<u16> = "rd_m2_stimulus\0".encode_utf16().collect();
                let wc = WNDCLASSW {
                    style: CS_HREDRAW | CS_VREDRAW,
                    lpfnWndProc: Some(stim_wnd_proc),
                    hInstance: module.map(|m| m.into()).unwrap_or_default(),
                    lpszClassName: windows::core::PCWSTR(class_name.as_ptr()),
                    ..Default::default()
                };
                if RegisterClassW(&wc) == 0 {
                    eprintln!("[host] stimulus: RegisterClassW failed");
                    return;
                }
                let title: Vec<u16> = "M2 rig stimulus\0".encode_utf16().collect();
                let hwnd = CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    windows::core::PCWSTR(class_name.as_ptr()),
                    windows::core::PCWSTR(title.as_ptr()),
                    WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                    320,
                    180,
                    640,
                    480,
                    None,
                    None,
                    module.map(|m| m.into()),
                    None,
                )
                .expect("stimulus window");
                let timer = SetTimer(Some(hwnd), 1, 10, None);
                let mut msg = MSG::default();
                while !stop.load(Ordering::Acquire) {
                    while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                let _ = KillTimer(Some(hwnd), timer);
                let _ = DestroyWindow(hwnd);
            }
        })
        .expect("spawn stimulus")
}

unsafe extern "system" fn stim_wnd_proc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::Foundation::{COLORREF, LRESULT};
    use windows::Win32::Graphics::Gdi::{
        BeginPaint, CreateSolidBrush, DeleteObject, EndPaint, FillRect, InvalidateRect, PAINTSTRUCT,
    };
    use windows::Win32::UI::WindowsAndMessaging::{DefWindowProcW, WM_PAINT, WM_TIMER};
    unsafe {
        match msg {
            WM_TIMER => {
                STIM_TICK.fetch_add(1, Ordering::Relaxed);
                let _ = InvalidateRect(Some(hwnd), None, false);
                LRESULT(0)
            }
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);
                let tick = STIM_TICK.load(Ordering::Relaxed);
                let bg = CreateSolidBrush(COLORREF(0x00101820));
                FillRect(hdc, &ps.rcPaint, bg);
                let _ = DeleteObject(bg.into());
                let x = (tick % 300) as i32;
                let bar = CreateSolidBrush(COLORREF(0x0000D7FF));
                let mut rect = ps.rcPaint;
                rect.left = x;
                rect.right = x + 120;
                rect.top += 40;
                rect.bottom -= 40;
                FillRect(hdc, &rect, bar);
                let _ = DeleteObject(bar.into());
                let bar2 = CreateSolidBrush(COLORREF(0x00FFFFFF));
                let mut line = ps.rcPaint;
                line.left = ((tick * 3) % 600) as i32;
                line.right = line.left + 4;
                FillRect(hdc, &line, bar2);
                let _ = DeleteObject(bar2.into());
                let _ = EndPaint(hwnd, &ps);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

// ---------------------------------------------------------------------------
// Rig observer — node effects → pipelines, input pump, status file
// ---------------------------------------------------------------------------

struct RigObserver {
    is_host: bool,
    session_slot: Arc<SessionSlot>,
    status_path: PathBuf,
    device: &'static str,
    /// Host input consumption (real `InputSink` trait object slot; the
    /// recording sink never touches SendInput).
    input_pump: Option<InputPump<RecordingSink>>,
    accept_due: Option<Instant>,
    restart_host_due: Option<Instant>,
    restart_ctrl_due: Option<Instant>,
    prompts: u64,
    host_pipeline: Option<HostPipeline>,
    controller_pipeline: Option<ControllerPipeline>,
    host_force_flag: Arc<AtomicBool>,
    want_streaming: bool,
    want_rendering: bool,
    sessions_established: Vec<String>,
    session_ends: Vec<String>,
    last_activity: Instant,
    transport_failures: u64,
    all_keys_up_disconnect: u64,
    cursor_overlays: u64,
    cursor_shapes_rx: u64,
    /// Peer said goodbye with `TransportError` over the control channel:
    /// the main loop tears our transport down and maps the loss to the
    /// machine (data-plane network-change notice).
    peer_transport_gone: bool,
    /// Counters of pipelines that already finished (one pipeline per
    /// session; the summary sums them all).
    finished_host_pipes: Vec<Arc<HostPipeCounters>>,
    /// Session ended: the transport belongs to the dead session; close it
    /// so re-registration attaches a fresh peer connection.
    host_transport_stale: bool,
    finished_ctrl_pipes: Vec<Arc<ControllerPipeCounters>>,
    finished_pacers: Vec<(Arc<AtomicU64>, Arc<AtomicU64>)>,
    stream_started_at: Option<Instant>,
    stream_secs_accum: f64,
    render_started_at: Option<Instant>,
    render_secs_accum: f64,
}

impl RigObserver {
    fn write_status(&self, node: &Node) {
        let (host_state, controller_state) = if self.is_host {
            (Some(node.host_state_name()), None)
        } else {
            (None, Some(node.controller_state_name()))
        };
        let input = self.input_pump.as_ref().map(|pump| {
            let counters = pump.counters();
            serde_json::json!({
                "moves_applied": counters.moves_applied,
                "moves_stale": counters.moves_stale_suppressed,
                "sequence_gaps": counters.sequence_gaps,
                "held": pump.held_count(),
                "final_position": pump.latest_position(),
                "all_keys_up": counters.all_keys_up,
            })
        });
        let doc = serde_json::json!({
            "device": self.device,
            "host_state": host_state,
            "controller_state": controller_state,
            "session_id": node.current_session_id(),
            "prompts": self.prompts,
            "input": input,
        });
        write_json_atomic(
            &self.status_path,
            &serde_json::to_string(&doc).unwrap_or_default(),
        );
    }
}

fn read_peer_state(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    value
        .get("host_state")
        .and_then(|v| v.as_str())
        .or_else(|| value.get("controller_state").and_then(|v| v.as_str()))
        .map(str::to_owned)
}

fn read_peer_input(path: &Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    value.get("input").cloned()
}

impl NodeObserver for RigObserver {
    fn state_changed(&mut self, machine: MachineKind, state: &str) {
        self.last_activity = Instant::now();
        eprintln!("[{}] {} -> {state}", self.device, machine.name());
    }

    fn prompt_consent(&mut self, controller_device_id: &str, session_id: &str) {
        self.last_activity = Instant::now();
        self.prompts += 1;
        eprintln!(
            "[{}] consent prompt #{}, session {session_id} (auto-accept in 300 ms)",
            self.device, self.prompts
        );
        let _ = controller_device_id;
        self.accept_due = Some(Instant::now() + Duration::from_millis(300));
    }

    fn session_established(&mut self, session_id: &str) {
        self.last_activity = Instant::now();
        self.session_slot.set(session_id);
        self.sessions_established.push(session_id.to_owned());
        eprintln!("[{}] session established: {session_id}", self.device);
        if let Some(pump) = self.input_pump.as_mut() {
            pump.reset_for_new_session();
        }
    }

    fn session_ended(&mut self, cause: &DisconnectCause) {
        self.last_activity = Instant::now();
        self.session_ends.push(format!("{cause:?}"));
        eprintln!("[{}] session ended: {cause:?}", self.device);
        if let Some(pump) = self.input_pump.as_mut() {
            // Stuck-key safety on every teardown path.
            pump.all_keys_up(AllKeysUpTrigger::Disconnect);
            self.all_keys_up_disconnect += 1;
        }
        // Scripted recovery: re-register the role 1 s after any session
        // end so the peer's next connect finds an Online machine. The
        // run-end marker terminates the process before this matters on
        // the final disconnect.
        if self.is_host {
            self.restart_host_due = Some(Instant::now() + Duration::from_secs(1));
            self.host_transport_stale = true;
        } else {
            self.restart_ctrl_due = Some(Instant::now() + Duration::from_secs(1));
        }
    }

    fn start_streaming(&mut self) {
        // Pipeline spawn happens in the main loop (`run`), which owns the
        // report handle; flag it here.
        self.want_streaming = true;
    }

    fn stop_streaming(&mut self) {
        if let Some(pipeline) = self.host_pipeline.take() {
            if let Some(started) = self.stream_started_at.take() {
                self.stream_secs_accum += started.elapsed().as_secs_f64();
            }
            self.finished_host_pipes
                .push(Arc::clone(&pipeline.counters));
            self.finished_pacers.push((
                Arc::clone(&pipeline.pacer_ticks),
                Arc::clone(&pipeline.pacer_skipped),
            ));
            pipeline.stop();
            eprintln!("[{}] streaming stopped", self.device);
        }
        self.want_streaming = false;
    }

    fn start_rendering(&mut self) {
        self.want_rendering = true;
    }

    fn stop_rendering(&mut self) {
        if let Some(pipeline) = self.controller_pipeline.take() {
            if let Some(started) = self.render_started_at.take() {
                self.render_secs_accum += started.elapsed().as_secs_f64();
            }
            self.finished_ctrl_pipes
                .push(Arc::clone(&pipeline.counters));
            pipeline.stop();
            eprintln!("[{}] rendering stopped", self.device);
        }
        self.want_rendering = false;
    }

    fn wire_received(&mut self, channel: Channel, message: &WireMessage) {
        if let (Channel::InputFast | Channel::InputReliable, WireMessage::Input(event)) =
            (channel, message)
        {
            if let Some(pump) = self.input_pump.as_mut() {
                pump.on_input(event);
            }
            return;
        }
        if let (Channel::Cursor, WireMessage::Cursor(cursor)) = (channel, message) {
            match cursor {
                CursorMessage::Position { .. } => self.cursor_overlays += 1,
                CursorMessage::Shape { .. } => self.cursor_shapes_rx += 1,
                CursorMessage::Hide => {}
            }
        }
    }

    fn keyframe_requested(&mut self) {
        self.host_force_flag.store(true, Ordering::Release);
    }

    fn control_disconnect(&mut self, reason: ControlDisconnectReason) {
        eprintln!("[{}] control goodbye received ({reason:?})", self.device);
        if let Some(pump) = self.input_pump.as_mut() {
            pump.all_keys_up(AllKeysUpTrigger::Disconnect);
            self.all_keys_up_disconnect += 1;
        }
        if reason == ControlDisconnectReason::TransportError {
            self.peer_transport_gone = true;
        }
    }

    fn transport_failure(&mut self, reason: &str) {
        self.transport_failures += 1;
        eprintln!("[{}] transport failure: {reason}", self.device);
    }

    fn illegal_transition(&mut self, machine: MachineKind, state: &str, event: &str) {
        eprintln!(
            "[{}] tolerated illegal transition: {event} in {state}",
            machine.name()
        );
    }
}

// ---------------------------------------------------------------------------
// run(): process setup + main loop + scenario engine
// ---------------------------------------------------------------------------

fn fresh_transport(is_host: bool) -> Result<Box<WebrtcTransport>, String> {
    let role = if is_host {
        WebrtcTransportRole::Host
    } else {
        WebrtcTransportRole::Controller
    };
    WebrtcTransport::new(role)
        .map(Box::new)
        .map_err(|e| format!("transport build: {e}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CtrlPhase {
    WaitPeerOnline,
    Connecting(Instant),
    Streaming {
        since: Instant,
        netchange_done: bool,
    },
    NetChangeWaitHost(Instant),
    NetChangeWaitSelfOnline(Instant),
    Reconnecting(Instant),
    Goodbye,
    Finished,
}

fn run(args: Args) -> i32 {
    let is_host = args.role == "host";
    let started = Instant::now();
    let (device, peer_device): (&'static str, &'static str) = if is_host {
        (HOST_DEVICE, CONTROLLER_DEVICE)
    } else {
        (CONTROLLER_DEVICE, HOST_DEVICE)
    };
    println!(
        "[{device}] m2_rig role={} scenario={} dir={} stream={}s seed={} drop-fast={} reorder-fast={} drop-reliable-every={}",
        args.role,
        args.scenario,
        args.dir.display(),
        args.stream_secs,
        args.seed,
        args.drop_fast_pct,
        args.reorder_fast_pct,
        args.drop_reliable_nth,
    );
    std::fs::create_dir_all(&args.dir).expect("signal dir");

    // Desktop attachment (capture + windows must see the input desktop).
    attach_thread_to_input_desktop().expect("input desktop");

    // ---- metrics ----
    let report_dir: PathBuf = match (&args.report_stem, &args.metrics_dir) {
        (_, Some(dir)) => dir.clone(),
        (Some(_), None) => std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("docs/reports/data")
            .canonicalize()
            .expect("repo root"),
        (None, None) => std::env::temp_dir().join("rd-m2-metrics"),
    };
    let stem = args
        .report_stem
        .clone()
        .unwrap_or_else(|| format!("m2-rig-{}", date_string()));
    let report =
        JsonlReport::create(&report_dir, &format!("{stem}-{device}")).expect("metrics report");
    eprintln!("[{device}] metrics: {}", report.path.display());
    let session_slot = Arc::new(SessionSlot::new(&format!("{device}-pre-session")));

    // ---- clock + resource sampler ----
    let clock = Arc::new(MonotonicClock::new());
    let stop_flag = Arc::new(AtomicBool::new(false));
    let resource = spawn_resource_sampler(
        Box::new(report.sink_handle(Arc::clone(&session_slot))),
        Arc::clone(&session_slot),
        if is_host {
            Origin::Host
        } else {
            Origin::Controller
        },
        Arc::clone(&stop_flag),
        Arc::new({
            let clock = clock.clone();
            move || clock.now_ns()
        }) as ClockFn,
    );

    // ---- GPU + MF ----
    let _mf = codec_windows::MfRuntime::new().expect("MFStartup");
    let gpu = GpuDevice::create_hardware().expect("hardware D3D11 device");
    eprintln!(
        "[{device}] gpu: {}",
        gpu.adapter_description().unwrap_or_default()
    );

    // ---- signaling + node ----
    let direction = if is_host {
        SignalingDirection::HostToController
    } else {
        SignalingDirection::ControllerToHost
    };
    let signaling = FileSignaling::new(&args.dir, direction).expect("file signaling");
    eprintln!("[{device}] signaling: {}", signaling.describe());
    let mut node = Node::new(
        device,
        SessionConfig::default(),
        clock.clone(),
        Box::new(signaling),
    );
    let transport = fresh_transport(is_host).expect("transport");
    node.attach_transport(transport);

    // ---- stimulus (host) ----
    let stimulus = if is_host && args.stimulus {
        Some(spawn_stimulus(Arc::clone(&stop_flag)))
    } else {
        None
    };

    // ---- observer ----
    let status_path = args.dir.join(format!("{}-status.json", args.role));
    let mut observer = RigObserver {
        is_host,
        session_slot: Arc::clone(&session_slot),
        status_path: status_path.clone(),
        device,
        input_pump: if is_host {
            Some(InputPump::new(RecordingSink::default()))
        } else {
            None
        },
        accept_due: None,
        restart_host_due: None,
        restart_ctrl_due: None,
        prompts: 0,
        host_pipeline: None,
        controller_pipeline: None,
        host_force_flag: Arc::new(AtomicBool::new(false)),
        want_streaming: false,
        want_rendering: false,
        sessions_established: Vec::new(),
        session_ends: Vec::new(),
        last_activity: Instant::now(),
        transport_failures: 0,
        all_keys_up_disconnect: 0,
        cursor_overlays: 0,
        cursor_shapes_rx: 0,
        peer_transport_gone: false,
        finished_host_pipes: Vec::new(),
        host_transport_stale: false,
        finished_ctrl_pipes: Vec::new(),
        finished_pacers: Vec::new(),
        stream_started_at: None,
        stream_secs_accum: 0.0,
        render_started_at: None,
        render_secs_accum: 0.0,
    };
    let host_pipe_device = if is_host { Some(gpu.clone()) } else { None };
    let ctrl_pipe_device = if is_host { None } else { Some(gpu.clone()) };
    let host_force_flag = Arc::clone(&observer.host_force_flag);

    // ---- role start ----
    let caps = rig_capabilities(!is_host);
    if is_host {
        node.host_start(caps.clone(), &mut observer);
    } else {
        node.controller_start(caps.clone(), &mut observer);
    }
    observer.write_status(&node);

    // ---- controller scenario state ----
    let peer_status_path = args.dir.join(if is_host {
        "controller-status.json"
    } else {
        "host-status.json"
    });
    let done_marker = args.dir.join("done.marker");
    let mut phase = if is_host {
        CtrlPhase::Finished // host is fully scripted by events
    } else {
        CtrlPhase::WaitPeerOnline
    };
    let mut connect_attempts: Vec<(String, u64)> = Vec::new(); // (session, ms)
    let mut chaos = ChaosInjector::new(args.seed, args.drop_fast_pct, args.reorder_fast_pct)
        .with_drop_every_nth(args.drop_reliable_nth);
    let mut moves_sent: u64 = 0;
    let mut reliable_sent: u64 = 0;
    let mut reliable_send_errors: u64 = 0;
    let mut input_phase_started = false;
    let mut chaos_flushed = false;
    let mut dup_probe_sent = false;
    let mut final_position_sent: Option<(u16, u16)> = None;
    let mut last_stats_tick = Instant::now();
    let mut last_keyframe_request = Instant::now() - Duration::from_secs(10);
    let mut final_transport_stats: Option<transport_webrtc::TransportStats> = None;
    let mut cycle: u64 = 0;
    let mut netchange_at_elapsed = Duration::ZERO;
    let mut netchange_self_restarted = false;
    let mut failure_reason = String::new();
    let host_out_file = args.dir.join("c2h.jsonl");

    // Controller start delay: give the host a moment to register.
    let script_start = Instant::now() + Duration::from_millis(700);

    let mut alive_tick = Instant::now();
    loop {
        let now = Instant::now();
        if is_host && alive_tick.elapsed() >= Duration::from_secs(2) {
            alive_tick = now;
            eprintln!("[{device}] loop alive, host={}", node.host_state_name());
        }

        // ---- node pump ----
        node.pump(&mut observer);
        node.poll_transport(&mut observer);

        // ---- scripted user actions ----
        if let Some(due) = observer.accept_due
            && now >= due
        {
            observer.accept_due = None;
            let secret = SessionSecret(format!(
                "rig-{}",
                node.current_session_id().unwrap_or_default()
            ));
            node.user_accept_consent(secret, &mut observer);
        }
        if let Some(due) = observer.restart_host_due
            && now >= due
        {
            observer.restart_host_due = None;
            node.host_start(caps.clone(), &mut observer);
        }
        if let Some(due) = observer.restart_ctrl_due
            && now >= due
        {
            observer.restart_ctrl_due = None;
            node.controller_start(caps.clone(), &mut observer);
        }
        // Host: after a teardown the transport is gone; re-attach a fresh
        // one so the next session's ComposeAnswer has a target.
        if is_host && !node.has_transport() {
            match fresh_transport(true) {
                Ok(transport) => node.attach_transport(transport),
                Err(err) => {
                    failure_reason = format!("host transport rebuild: {err}");
                    break;
                }
            }
        }

        // ---- host: retire the dead session's transport (the rebuild
        // block below attaches a fresh peer connection for re-register).
        if observer.host_transport_stale {
            observer.host_transport_stale = false;
            node.close_transport();
        }

        // ---- host: peer transport gone (data-plane network-change notice)
        if observer.peer_transport_gone {
            observer.peer_transport_gone = false;
            eprintln!("[{device}] tearing transport down after goodbye");
            node.teardown_transport("peer transport gone (control goodbye)", &mut observer);
            eprintln!(
                "[{device}] teardown complete, host={}",
                node.host_state_name()
            );
        }

        // ---- host pipeline on StartStreaming ----
        if is_host
            && observer.want_streaming
            && observer.host_pipeline.is_none()
            && let Some(pipe_device) = host_pipe_device.clone()
        {
            let pipeline = HostPipeline::start(
                pipe_device,
                Arc::clone(&host_force_flag),
                &args,
                &report,
                Arc::clone(&session_slot),
                clock.clone(),
            )
            .expect("host pipeline");
            observer.stream_started_at = Some(Instant::now());
            observer.host_pipeline = Some(pipeline);
            eprintln!("[{device}] streaming started");
        }
        // ---- controller pipeline on StartRendering ----
        if !is_host
            && observer.want_rendering
            && observer.controller_pipeline.is_none()
            && let Some(pipe_device) = ctrl_pipe_device.clone()
        {
            let pipeline = ControllerPipeline::start(
                pipe_device,
                &args,
                &report,
                Arc::clone(&session_slot),
                clock.clone(),
            )
            .expect("controller pipeline");
            observer.render_started_at = Some(Instant::now());
            observer.controller_pipeline = Some(pipeline);
            eprintln!("[{device}] rendering started");
        }

        // ---- host: drain encode→send queue into the transport ----
        if let Some(pipeline) = observer.host_pipeline.as_ref() {
            let mut sink = report.sink_handle(Arc::clone(&session_slot));
            while let Some(item) = pipeline.q_enc_send.pop(Duration::ZERO) {
                let video = VideoFrame {
                    frame_id: item.packet.frame_id,
                    timestamp_ns: item.packet.timestamp_ns,
                    is_keyframe: item.packet.is_keyframe,
                    bytes: item.packet.bytes,
                };
                match node.send_video(video) {
                    Ok(()) => {
                        let send_ns = clock.now_ns();
                        sink.record(CounterRecord::FrameTiming(FrameTiming {
                            session_id: session_slot.get(),
                            origin: Origin::Host,
                            frame_id: item.packet.frame_id,
                            capture_ns: Some(item.capture_ns),
                            encode_submit_ns: Some(item.encode_submit_ns),
                            encode_done_ns: Some(item.encode_done_ns),
                            send_ns: Some(send_ns),
                            recv_ns: None,
                            decode_done_ns: None,
                            present_ns: None,
                        }));
                    }
                    Err(err) => {
                        eprintln!("[{device}] send_video: {err}");
                    }
                }
            }
            // Cursor deltas (latest-state channel).
            while let Some(cursor) = pipeline.cursor_slot.take() {
                let _ = node.send_wire(Channel::Cursor, &WireMessage::Cursor(cursor));
            }
        }

        // ---- controller: gap-triggered keyframe request (app-level loss),
        // rate-limited so a burst of obsolete-frame drops cannot feed an
        // IDR amplification loop (each IDR is the biggest frame in the GOP).
        if let Some(pipeline) = observer.controller_pipeline.as_ref()
            && pipeline.keyframe_needed.load(Ordering::Acquire)
            && now.duration_since(last_keyframe_request) >= Duration::from_millis(250)
            && pipeline.keyframe_needed.swap(false, Ordering::AcqRel)
        {
            last_keyframe_request = now;
            pipeline
                .counters
                .keyframe_requests
                .fetch_add(1, Ordering::Relaxed);
            let _ = node.send_wire(Channel::Control, &WireMessage::KeyframeRequest);
        }

        // ---- controller: drain received video into the decode queue ----
        if let Some(pipeline) = observer.controller_pipeline.as_ref() {
            while let Some(frame) = node.poll_video() {
                pipeline.counters.received.fetch_add(1, Ordering::Relaxed);
                let recv_ns = clock.now_ns();
                let missing = frame.missing_packets;
                let frame_id = frame.frame_id;
                if pipeline
                    .q_recv_dec
                    .push(RecvItem { frame, recv_ns })
                    .is_err()
                {
                    // recv queue rejected: modeled packet loss under
                    // backpressure (counted by the queue's `dropped`).
                }
                // Loss-triggered keyframe request: missing packets or a
                // lost frame (no frame_id or discontinuity handled in the
                // decode thread via counters) → PLI-equivalent over the
                // control channel + decoder reset (IDR gate).
                if missing > 0 || frame_id.is_none() {
                    pipeline
                        .counters
                        .keyframe_requests
                        .fetch_add(1, Ordering::Relaxed);
                    pipeline.reset_decoder.store(true, Ordering::Release);
                    let _ = node.send_wire(Channel::Control, &WireMessage::KeyframeRequest);
                }
            }
        }

        // ---- stats at 1 Hz ----
        if node.has_transport() && now.duration_since(last_stats_tick) >= Duration::from_secs(1) {
            last_stats_tick = now;
            if let Ok(stats) = node.stats() {
                let mut sink = report.sink_handle(Arc::clone(&session_slot));
                sink.record(CounterRecord::LinkSample(LinkSample {
                    session_id: session_slot.get(),
                    send_bitrate_kbps: stats.send_bitrate_kbps.map(|v| v as u32),
                    recv_bitrate_kbps: stats.recv_bitrate_kbps.map(|v| v as u32),
                    rtt_ms: stats.rtt_ms.map(|v| v as u32),
                    loss_percent: stats.loss_percent.map(|v| v as f32),
                    at_ns: clock.now_ns(),
                }));
                for (index, kind) in [
                    QueueKind::ChannelControl,
                    QueueKind::ChannelInputFast,
                    QueueKind::ChannelInputReliable,
                    QueueKind::ChannelCursor,
                ]
                .into_iter()
                .enumerate()
                {
                    sink.record(CounterRecord::QueueSample(diagnostics::QueueSample {
                        session_id: session_slot.get(),
                        queue: kind,
                        depth: stats.channel_queue.depth[index],
                        capacity: stats.channel_queue.capacity[index],
                        high_water: stats.channel_queue.high_water[index],
                        dropped: stats.channel_queue.dropped[index],
                        replaced: stats.channel_queue.replaced[index],
                        at_ns: clock.now_ns(),
                    }));
                }
                if stats.relay_in_use {
                    eprintln!("[{device}] FATAL: relay in use (invariant 4)");
                    failure_reason = "relay_in_use".into();
                    break;
                }
                final_transport_stats = Some(stats);
            }
        }

        // ---- controller scenario engine ----
        if !is_host && now >= script_start {
            match phase {
                CtrlPhase::WaitPeerOnline => {
                    let online = read_peer_state(&peer_status_path).is_some_and(|s| s == "Online");
                    if online || now.duration_since(script_start) > Duration::from_secs(20) {
                        phase = CtrlPhase::Connecting(Instant::now());
                        node.controller_connect(peer_device, &mut observer);
                        eprintln!("[{device}] connect_request sent");
                    }
                }
                CtrlPhase::Connecting(connect_started) => {
                    if matches!(node.controller_state(), ControllerState::Connected { .. }) {
                        let ms = connect_started.elapsed().as_millis() as u64;
                        connect_attempts.push((node.current_session_id().unwrap_or_default(), ms));
                        eprintln!("[{device}] connected in {ms} ms");
                        if !dup_probe_sent && args.scenario == "loss-reorder-dup" {
                            dup_probe_sent = true;
                            duplicate_signaling_probe(&host_out_file);
                        }
                        phase = CtrlPhase::Streaming {
                            since: Instant::now(),
                            netchange_done: args.scenario != "full",
                        };
                    } else if connect_started.elapsed() > Duration::from_secs(30) {
                        failure_reason = "connect timeout".into();
                        phase = CtrlPhase::Finished;
                    }
                }
                CtrlPhase::Streaming {
                    since,
                    netchange_done,
                } => {
                    // Input chaos phase (+5 s into the stream).
                    if !input_phase_started && since.elapsed() > Duration::from_secs(5) {
                        input_phase_started = true;
                        eprintln!("[{device}] input chaos phase starting");
                    }
                    if input_phase_started && moves_sent < args.mouse_moves {
                        for _ in 0..30 {
                            if moves_sent >= args.mouse_moves {
                                break;
                            }
                            moves_sent += 1;
                            let (x, y) = (
                                ((moves_sent * 31) % 65_536) as u16,
                                ((moves_sent * 37) % 65_536) as u16,
                            );
                            final_position_sent = Some((x, y));
                            let msg = WireMessage::Input(InputEvent::MouseMove {
                                seq: moves_sent,
                                x,
                                y,
                            });
                            for bytes in chaos.transform(protocol::wire::encode(&msg)) {
                                let _ = node.send_wire_bytes(Channel::InputFast, &bytes);
                            }
                        }
                        reliable_sent += 1;
                        let seq = reliable_sent;
                        let msg = if seq.is_multiple_of(3) {
                            WireMessage::Input(InputEvent::Wheel {
                                seq,
                                delta_v: -120,
                                delta_h: 0,
                            })
                        } else {
                            WireMessage::Input(InputEvent::Key {
                                seq,
                                scan_code: 0x1E,
                                extended: false,
                                state: if seq.is_multiple_of(2) {
                                    ButtonState::Pressed
                                } else {
                                    ButtonState::Released
                                },
                            })
                        };
                        for bytes in chaos.transform(protocol::wire::encode(&msg)) {
                            if let Err(err) = node.send_wire_bytes(Channel::InputReliable, &bytes) {
                                let _ = err;
                                reliable_send_errors += 1;
                            }
                        }
                    }
                    if input_phase_started && moves_sent >= args.mouse_moves && !chaos_flushed {
                        chaos_flushed = true;
                        let pending = chaos.flush();
                        for bytes in pending {
                            let decoded = protocol::wire::decode(&bytes);
                            let channel = match decoded {
                                Ok(WireMessage::Input(InputEvent::MouseMove { .. })) => {
                                    Channel::InputFast
                                }
                                _ => Channel::InputReliable,
                            };
                            let _ = node.send_wire_bytes(channel, &bytes);
                        }
                        eprintln!(
                            "[{device}] chaos done: dropped={} reordered={}",
                            chaos.dropped, chaos.reordered
                        );
                    }

                    let target = if args.scenario == "cycles" {
                        Duration::from_secs(args.cycle_stream_secs)
                    } else {
                        Duration::from_secs(args.stream_secs)
                    };
                    // Network-change at 2/3 of the stream (full scenario).
                    if !netchange_done
                        && since.elapsed() >= target * 2 / 3
                        && moves_sent >= args.mouse_moves.min(1)
                    {
                        netchange_at_elapsed = since.elapsed();
                        eprintln!(
                            "[{device}] network change: restart_ice probe + goodbye + hard teardown"
                        );
                        match node.restart_ice() {
                            Ok(()) => eprintln!("[{device}] restart_ice ok"),
                            Err(err) => eprintln!("[{device}] restart_ice: {err}"),
                        }
                        // Data-plane goodbye so the peer's runtime learns
                        // the transport died (loopback close is otherwise
                        // invisible until consent timeouts).
                        let _ = node.send_wire(
                            Channel::Control,
                            &WireMessage::Disconnect {
                                reason: ControlDisconnectReason::TransportError,
                            },
                        );
                        // Let the reliable control channel flush the
                        // goodbye before the hard teardown eats it.
                        let goodbye_drain = Instant::now();
                        while goodbye_drain.elapsed() < Duration::from_millis(500) {
                            node.pump(&mut observer);
                            node.poll_transport(&mut observer);
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        node.teardown_transport("simulated interface change", &mut observer);
                        phase = CtrlPhase::NetChangeWaitHost(Instant::now());
                    } else if since.elapsed() >= target {
                        phase = CtrlPhase::Goodbye;
                    }
                }
                CtrlPhase::NetChangeWaitHost(wait_started) => {
                    // Our own machine went Disconnected{TransportError} on
                    // teardown; wait for the host to observe it too.
                    let host_down =
                        read_peer_state(&peer_status_path).is_some_and(|s| s == "Disconnected");
                    if host_down {
                        eprintln!(
                            "[{device}] host observed the network change ({} ms); waiting for self to re-register",
                            wait_started.elapsed().as_millis()
                        );
                        phase = CtrlPhase::NetChangeWaitSelfOnline(Instant::now());
                    } else if wait_started.elapsed() > Duration::from_secs(35) {
                        // Generous window: the host may be inside one
                        // bounded (15 s) send_video bridge when the peer
                        // vanishes, and its own teardown close is bounded
                        // at 7 s on top.
                        failure_reason = "network-change teardown did not reach the host".into();
                        phase = CtrlPhase::Finished;
                    }
                }
                CtrlPhase::NetChangeWaitSelfOnline(wait_started) => {
                    // The scripted recovery re-registers the controller
                    // role after the teardown (the host's signaling
                    // Disconnect can win the race and end the session as
                    // Peer instead of TransportError, so the scenario
                    // drives the re-register itself when needed).
                    let host_online =
                        read_peer_state(&peer_status_path).is_some_and(|s| s == "Online");
                    if matches!(
                        node.controller_state(),
                        ControllerState::Disconnected { .. }
                    ) && !netchange_self_restarted
                        && wait_started.elapsed() >= Duration::from_millis(1_500)
                    {
                        netchange_self_restarted = true;
                        node.controller_start(caps.clone(), &mut observer);
                    }
                    if matches!(node.controller_state(), ControllerState::Online) && host_online {
                        eprintln!(
                            "[{device}] re-establishing after network change ({} ms after host-down)",
                            wait_started.elapsed().as_millis()
                        );
                        match fresh_transport(false) {
                            Ok(transport) => node.attach_transport(transport),
                            Err(err) => {
                                failure_reason = format!("rebuild transport: {err}");
                                phase = CtrlPhase::Finished;
                                continue;
                            }
                        }
                        node.controller_connect(peer_device, &mut observer);
                        phase = CtrlPhase::Reconnecting(Instant::now());
                    } else if wait_started.elapsed() > Duration::from_secs(30) {
                        failure_reason = format!(
                            "controller did not re-register after teardown (state {})",
                            node.controller_state().name()
                        );
                        phase = CtrlPhase::Finished;
                    }
                }
                CtrlPhase::Reconnecting(reconnect_started) => {
                    if matches!(node.controller_state(), ControllerState::Connected { .. }) {
                        let ms = reconnect_started.elapsed().as_millis() as u64;
                        connect_attempts.push((node.current_session_id().unwrap_or_default(), ms));
                        eprintln!("[{device}] re-established in {ms} ms");
                        phase = CtrlPhase::Streaming {
                            since: Instant::now(),
                            netchange_done: true,
                        };
                    } else if reconnect_started.elapsed() > Duration::from_secs(30) {
                        failure_reason = "reconnect timeout".into();
                        phase = CtrlPhase::Finished;
                    }
                }
                CtrlPhase::Goodbye => {
                    // Data-plane goodbye, then the signaling disconnect.
                    let _ = node.send_wire(
                        Channel::Control,
                        &WireMessage::Disconnect {
                            reason: ControlDisconnectReason::User,
                        },
                    );
                    node.controller_disconnect(&mut observer);
                    eprintln!("[{device}] disconnect sent; draining");
                    // Wait for the host to observe the teardown.
                    let drain_start = Instant::now();
                    while drain_start.elapsed() < Duration::from_secs(3) {
                        node.pump(&mut observer);
                        node.poll_transport(&mut observer);
                        if read_peer_state(&peer_status_path).is_some_and(|s| s == "Disconnected") {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    cycle += 1;
                    if args.scenario == "cycles" && cycle < args.cycles {
                        // Next round once the host is Online again.
                        let wait_start = Instant::now();
                        loop {
                            node.pump(&mut observer);
                            node.poll_transport(&mut observer);
                            if read_peer_state(&peer_status_path).is_some_and(|s| s == "Online") {
                                break;
                            }
                            if wait_start.elapsed() > Duration::from_secs(20) {
                                failure_reason = "host did not return Online between cycles".into();
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        if !failure_reason.is_empty() {
                            phase = CtrlPhase::Finished;
                            continue;
                        }
                        // Both machines are terminal after a clean
                        // disconnect: re-register the controller role and
                        // wait for the Register ack before connecting.
                        observer.restart_ctrl_due = None;
                        node.controller_start(caps.clone(), &mut observer);
                        let reg_start = Instant::now();
                        loop {
                            node.pump(&mut observer);
                            node.poll_transport(&mut observer);
                            if matches!(node.controller_state(), ControllerState::Online) {
                                break;
                            }
                            if reg_start.elapsed() > Duration::from_secs(10) {
                                failure_reason =
                                    "controller re-register stalled between cycles".into();
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        if !failure_reason.is_empty() {
                            phase = CtrlPhase::Finished;
                            continue;
                        }
                        match fresh_transport(false) {
                            Ok(transport) => node.attach_transport(transport),
                            Err(err) => {
                                failure_reason = format!("rebuild transport: {err}");
                                phase = CtrlPhase::Finished;
                                continue;
                            }
                        }
                        phase = CtrlPhase::Connecting(Instant::now());
                        node.controller_connect(peer_device, &mut observer);
                    } else {
                        phase = CtrlPhase::Finished;
                    }
                }
                CtrlPhase::Finished => {
                    write_marker(&done_marker, device);
                    break;
                }
            }
        }

        // ---- host termination ----
        if is_host {
            if done_marker.exists() {
                eprintln!("[{device}] done marker observed");
                break;
            }
            // Idle watchdog: only fatal while the host machine is terminal
            // (between cycles the controller drives the next connect).
            if matches!(node.host_state(), HostState::Disconnected { .. })
                && observer.last_activity.elapsed()
                    > Duration::from_secs(args.idle_timeout_secs.max(60))
            {
                failure_reason = "host idle timeout after session end".into();
                break;
            }
        } else if let Some(pipeline) = observer.controller_pipeline.as_ref()
            && pipeline.counters.window_closed.load(Ordering::Acquire)
        {
            failure_reason = "viewer window closed".into();
            break;
        }

        if !failure_reason.is_empty() {
            break;
        }

        observer.write_status(&node);
        std::thread::sleep(Duration::from_millis(2));
    }

    // ---- teardown (keep the counter Arcs for the summary) ----
    stop_flag.store(true, Ordering::Release);
    node.close_transport();
    if let Some(pipeline) = observer.host_pipeline.take() {
        if let Some(started) = observer.stream_started_at.take() {
            observer.stream_secs_accum += started.elapsed().as_secs_f64();
        }
        observer
            .finished_host_pipes
            .push(Arc::clone(&pipeline.counters));
        observer.finished_pacers.push((
            Arc::clone(&pipeline.pacer_ticks),
            Arc::clone(&pipeline.pacer_skipped),
        ));
        pipeline.stop();
    }
    if let Some(pipeline) = observer.controller_pipeline.take() {
        if let Some(started) = observer.render_started_at.take() {
            observer.render_secs_accum += started.elapsed().as_secs_f64();
        }
        observer
            .finished_ctrl_pipes
            .push(Arc::clone(&pipeline.counters));
        pipeline.stop();
    }
    let _ = resource.join();
    if let Some(handle) = stimulus {
        let _ = handle.join();
    }
    observer.write_status(&node);

    let (metrics_path, records, backpressure) = report.close();

    // ---- verification + summary ----
    let mut failures: Vec<String> = Vec::new();
    if !failure_reason.is_empty() {
        failures.push(failure_reason.clone());
    }
    let node_counters = node.counters();
    let input_summary = observer.input_pump.as_ref().map(|pump| {
        let counters = pump.counters();
        serde_json::json!({
            "moves_applied": counters.moves_applied,
            "moves_stale_suppressed": counters.moves_stale_suppressed,
            "reliable_applied": counters.reliable_applied,
            "sequence_gaps": counters.sequence_gaps,
            "all_keys_up": counters.all_keys_up,
            "inject_errors": counters.inject_errors,
            "held_at_end": pump.held_count(),
            "final_position": pump.latest_position(),
        })
    });
    if is_host {
        if let Some(pump) = observer.input_pump.as_ref()
            && pump.held_count() != 0
        {
            failures.push("held input at end".into());
        }
        // One consent prompt per established session; duplicates must
        // never re-prompt (the host does not know the controller's
        // scenario, but every session starts with exactly one prompt).
        let expected_prompts = observer.sessions_established.len() as u64;
        if args.scenario != "soak" && observer.prompts != expected_prompts {
            failures.push(format!(
                "prompts {} != expected {} (duplicate re-prompted)",
                observer.prompts, expected_prompts
            ));
        }
        if observer.all_keys_up_disconnect == 0 {
            failures.push("no AllKeysUp(Disconnect) on teardown".into());
        }
    } else {
        // Cross-process input verification: the host status file carries
        // its final applied position; compare with the newest sent.
        let host_pos = read_peer_input(&peer_status_path)
            .filter(|_| args.mouse_moves > 0 && args.scenario != "cycles")
            .and_then(|input| input.get("final_position").cloned());
        if let (Some((sx, sy)), Some(pos)) = (final_position_sent, host_pos)
            && let (Some(hx), Some(hy)) = (
                pos.as_array()
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_u64()),
                pos.as_array()
                    .and_then(|a| a.get(1))
                    .and_then(|v| v.as_u64()),
            )
            && (sx != hx as u16 || sy != hy as u16)
        {
            failures.push(format!(
                "final position mismatch: sent ({sx},{sy}) host ({hx},{hy})"
            ));
        }
        if observer.sessions_established.is_empty() {
            failures.push("no session established".into());
        }
    }

    let elapsed = started.elapsed().as_secs_f64();
    // Sum counters across every session's pipeline (rebuilt per session).
    let (mut captured, mut encoded, mut keyframes, mut device_lost_host) = (0u64, 0u64, 0u64, 0u64);
    let (mut cursor_only, mut encode_deferred, mut keyframe_forced, mut cursor_positions_tx) =
        (0u64, 0u64, 0u64, 0u64);
    for counters in &observer.finished_host_pipes {
        captured += counters.captured.load(Ordering::Relaxed);
        encoded += counters.encoded.load(Ordering::Relaxed);
        keyframes += counters.keyframes.load(Ordering::Relaxed);
        device_lost_host += counters.device_lost.load(Ordering::Relaxed);
        cursor_only += counters.cursor_only.load(Ordering::Relaxed);
        encode_deferred += counters.encode_deferred.load(Ordering::Relaxed);
        keyframe_forced += counters.keyframe_forced.load(Ordering::Relaxed);
        cursor_positions_tx += counters.cursor_positions.load(Ordering::Relaxed);
    }
    let (pacer_ticks_total, pacer_skipped_total) =
        observer
            .finished_pacers
            .iter()
            .fold((0u64, 0u64), |(t, s), (ticks, skipped)| {
                (
                    t + ticks.load(Ordering::Relaxed),
                    s + skipped.load(Ordering::Relaxed),
                )
            });
    let ctrl_all = ControllerPipeCounters::default();
    for counters in &observer.finished_ctrl_pipes {
        let add = |dst: &AtomicU64, src: &AtomicU64| {
            dst.fetch_add(src.load(Ordering::Relaxed), Ordering::Relaxed)
        };
        add(&ctrl_all.received, &counters.received);
        add(&ctrl_all.decoded, &counters.decoded);
        add(&ctrl_all.presented, &counters.presented);
        add(&ctrl_all.decode_errors, &counters.decode_errors);
        add(&ctrl_all.idr_gate_drops, &counters.idr_gate_drops);
        add(&ctrl_all.keyframe_requests, &counters.keyframe_requests);
        add(
            &ctrl_all.frames_missing_packets,
            &counters.frames_missing_packets,
        );
        add(&ctrl_all.frame_id_gaps, &counters.frame_id_gaps);
        add(
            &ctrl_all.frames_without_frame_id,
            &counters.frames_without_frame_id,
        );
        add(&ctrl_all.device_lost, &counters.device_lost);
    }
    let ctrl_counters = Some(Arc::new(ctrl_all));

    let mut summary = serde_json::json!({
        "role": args.role,
        "device": device,
        "scenario": args.scenario,
        "elapsed_s": elapsed,
        "failed": !failures.is_empty(),
        "failures": failures,
        "sessions": {
            "netchange_at_stream_elapsed_s": netchange_at_elapsed.as_secs_f64(),
            "established": observer.sessions_established,
            "ends": observer.session_ends,
            "connect_attempts_ms": connect_attempts,
        },
        "prompts": observer.prompts,
        "all_keys_up_disconnect": observer.all_keys_up_disconnect,
        "transport_failures": observer.transport_failures,
        "node_counters": {
            "envelopes_sent": node_counters.envelopes_sent,
            "envelopes_received": node_counters.envelopes_received,
            "register_acked": node_counters.register_acked,
            "heartbeats_raised": node_counters.heartbeats_raised,
            "ice_minted": node_counters.ice_minted,
            "ice_forwarded": node_counters.ice_forwarded,
            "ice_forward_errors": node_counters.ice_forward_errors,
            "compose_errors": node_counters.compose_errors,
            "apply_answer_errors": node_counters.apply_answer_errors,
            "illegal_transitions": node_counters.illegal_transitions,
            "late_channels_open": node_counters.late_channels_open,
            "wire_sent": node_counters.wire_sent,
        },
        "input": input_summary,
        "metrics": {
            "path": metrics_path.display().to_string(),
            "records": records,
            "backpressure_events": backpressure,
        },
        "channel_open_order": node.channel_open_order(),
        "cursor": {
            "overlays_received": observer.cursor_overlays,
            "shapes_received": observer.cursor_shapes_rx,
        },
    });
    if is_host {
        let stream_secs = observer.stream_secs_accum.max(0.001);
        summary["host"] = serde_json::json!({
            "frames_captured": captured,
            "frames_encoded": encoded,
            "keyframes": keyframes,
            "encode_deferred": encode_deferred,
            "keyframe_forced": keyframe_forced,
            "cursor_only_updates": cursor_only,
            "cursor_positions_available": cursor_positions_tx,
            "stream_secs": stream_secs,
            "fps_effective": encoded as f64 / stream_secs,
            "fps_target": args.fps,
            "pacer": {
                "ticks": pacer_ticks_total,
                "skipped": pacer_skipped_total,
                "fps_tick_rate": pacer_ticks_total as f64 / stream_secs,
            },
            "device_lost": device_lost_host,
        });
    } else {
        let (
            received,
            decoded,
            presented,
            decode_errors,
            idr_drops,
            kfr,
            missing,
            gaps,
            no_id,
            dlost,
        ) = if let Some(counters) = ctrl_counters.as_ref() {
            (
                counters.received.load(Ordering::Relaxed),
                counters.decoded.load(Ordering::Relaxed),
                counters.presented.load(Ordering::Relaxed),
                counters.decode_errors.load(Ordering::Relaxed),
                counters.idr_gate_drops.load(Ordering::Relaxed),
                counters.keyframe_requests.load(Ordering::Relaxed),
                counters.frames_missing_packets.load(Ordering::Relaxed),
                counters.frame_id_gaps.load(Ordering::Relaxed),
                counters.frames_without_frame_id.load(Ordering::Relaxed),
                counters.device_lost.load(Ordering::Relaxed),
            )
        } else {
            (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        };
        let render_secs = observer.render_secs_accum.max(0.001);
        summary["controller"] = serde_json::json!({
            "frames_received": received,
            "frames_decoded": decoded,
            "frames_presented": presented,
            "decode_errors": decode_errors,
            "idr_gate_drops": idr_drops,
            "keyframe_requests_sent": kfr,
            "frames_missing_packets": missing,
            "frame_id_gaps": gaps,
            "frames_without_frame_id": no_id,
            "fps_presented": presented as f64 / render_secs,
            "render_secs": render_secs,
            "device_lost": dlost,
        });
        summary["chaos"] = serde_json::json!({
            "dropped": chaos.dropped,
            "reordered": chaos.reordered,
            "moves_sent": moves_sent,
            "reliable_sent": reliable_sent,
            "reliable_send_errors": reliable_send_errors,
            "final_position_sent": final_position_sent,
            "seed": args.seed,
        });
    }
    if let Some(stats) = final_transport_stats {
        summary["transport_stats"] = serde_json::json!({
            "rtt_ms": stats.rtt_ms,
            "send_bitrate_kbps": stats.send_bitrate_kbps,
            "recv_bitrate_kbps": stats.recv_bitrate_kbps,
            "loss_percent": stats.loss_percent,
            "packets_sent": stats.packets_sent,
            "packets_received": stats.packets_received,
            "packets_lost": stats.packets_lost,
            "frames_sent": stats.frames_sent,
            "frames_received": stats.frames_received,
            "frames_dropped_rx_queue": stats.frames_dropped,
            "events_dropped_drain_queue": stats.events_dropped,
            "relay_in_use": stats.relay_in_use,
            "selected_pair": stats.selected_pair.as_ref().map(|p| serde_json::json!({
                "local": p.local_address,
                "local_type": p.local_candidate_type,
                "remote": p.remote_address,
                "remote_type": p.remote_candidate_type,
                "nominated": p.nominated,
            })),
        });
    }

    let json = serde_json::to_string_pretty(&summary).unwrap_or_default();
    let _ = std::fs::write(&args.summary, json.clone() + "\n");
    println!("[{device}] summary:\n{json}");

    if summary["failed"].as_bool().unwrap_or(true) {
        1
    } else {
        0
    }
}

fn write_marker(path: &Path, device: &str) {
    let doc = serde_json::json!({"done": true, "by": device});
    write_json_atomic(path, &doc.to_string());
}

/// Duplicate-signaling probe: re-append the first lines of our own
/// outbound stream verbatim (same `message_id`) — the peer's machines
/// must dedupe them to no-ops.
fn duplicate_signaling_probe(out_file: &Path) {
    let Ok(text) = std::fs::read_to_string(out_file) else {
        return;
    };
    let lines: Vec<&str> = text.lines().take(2).collect();
    if lines.is_empty() {
        return;
    }
    let mut appended = 0;
    if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(out_file) {
        for line in lines {
            if !line.trim().is_empty() {
                let _ = writeln!(file, "{line}");
                appended += 1;
            }
        }
        let _ = file.flush();
    }
    eprintln!(
        "[controller] duplicate-signaling probe: {appended} envelope(s) re-delivered verbatim"
    );
}
