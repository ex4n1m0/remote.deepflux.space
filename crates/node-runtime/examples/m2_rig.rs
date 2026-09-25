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
use std::sync::Mutex;
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
use transport_webrtc::{
    CHANNEL_LABELS, Channel, ReceivedFrame, Transport, TransportError, TransportEvent,
    TransportStats, VideoFrame, WebrtcTransport, WebrtcTransportRole,
};

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
    /// M6 soak F79 (sink-off mode): skip the JSONL metrics report entirely
    /// (no file, no writer thread, zero metrics IO). Default off; can also
    /// be set via the environment (`RD_RIG_NO_SINK=1`).
    no_sink: bool,
    idle_timeout_secs: u64,
    /// LAN-checkpoint mode (scope addendum to the M2 QA fix package): the
    /// host injects scripted input through the REAL `SendInputSink`
    /// instead of the recording sink. Default off — on a single machine
    /// the scripted cursor would fight the operator.
    real_input: bool,
    /// M5 netem (host): shape the outgoing RTP path (`loss=N|delay_ms=N|
    /// rate_kbps=N|udp_blocked=B`).
    netem: Option<String>,
    /// M5 netem schedule (host): `secs:spec;secs:spec;...` — profile swaps
    /// at stream-elapsed seconds (bandwidth step-down cells).
    netem_schedule: Option<String>,
    /// M5 congestion controller (host): `on` = transport GCC estimate +
    /// `node_runtime::congestion` policy drive the encoder bitrate/fps.
    congestion: bool,
    /// M5 RTT shaping, controller→host half (ms): input messages enter a
    /// bounded delay line (`chaos::DelayQueue`) so the input path carries
    /// the other half of a +RTT cell.
    input_delay_ms: u64,
    /// M5 UDP-blocked expected-failure cell: every remote candidate's port
    /// is rewritten to the discard port (9) before it reaches the ICE
    /// agent, emulating a network where the peer's UDP is unreachable
    /// (connectivity checks die). Signaling still works — exactly the
    /// "signaling ok, ICE dead" stage the failure UX documents.
    blackhole_candidates: bool,
}

/// Transport wrapper for the `--blackhole-candidates` cell (M5): rewrites
/// every remote candidate's port to the discard port before the ICE agent
/// sees it. Emulates "the network drops every UDP packet toward the peer"
/// at the only seam the rig owns (loopback sockets cannot be filtered
/// without a WFP driver — documented in m5-matrix.md).
struct BlackholeTransport {
    inner: Box<dyn Transport>,
    rewritten: std::sync::atomic::AtomicU64,
}

impl BlackholeTransport {
    fn rewrite(candidate: &str) -> String {
        // `candidate:<foundation> <component> <proto> <priority> <addr>
        //  <port> typ ...` — the port is field 5 (index 4).
        let mut fields = candidate.split(' ').map(str::to_owned).collect::<Vec<_>>();
        if fields.len() >= 5 && fields[0].starts_with("candidate:") {
            fields[4] = "9".to_owned();
        }
        fields.join(" ")
    }
}

impl Transport for BlackholeTransport {
    fn compose_offer(&mut self) -> Result<String, TransportError> {
        self.inner.compose_offer()
    }
    fn compose_answer(&mut self, offer_sdp: &str) -> Result<String, TransportError> {
        self.inner.compose_answer(offer_sdp)
    }
    fn apply_answer(&mut self, answer_sdp: &str) -> Result<(), TransportError> {
        self.inner.apply_answer(answer_sdp)
    }
    fn add_remote_candidate(
        &mut self,
        candidate: &str,
        sdp_mid: Option<&str>,
        sdp_mline_index: Option<u16>,
    ) -> Result<(), TransportError> {
        let rewritten = Self::rewrite(candidate);
        self.rewritten
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner
            .add_remote_candidate(&rewritten, sdp_mid, sdp_mline_index)
    }
    fn send(&mut self, channel: Channel, bytes: &[u8]) -> Result<(), TransportError> {
        self.inner.send(channel, bytes)
    }
    fn poll(&mut self) -> Option<TransportEvent> {
        self.inner.poll()
    }
    fn send_video(&mut self, frame: VideoFrame) -> Result<(), TransportError> {
        self.inner.send_video(frame)
    }
    fn poll_video(&mut self) -> Option<ReceivedFrame> {
        self.inner.poll_video()
    }
    fn stats(&mut self) -> Result<TransportStats, TransportError> {
        self.inner.stats()
    }
    fn channel_queue_gauges(&mut self) -> Option<transport_webrtc::ChannelQueues> {
        self.inner.channel_queue_gauges()
    }
    fn restart_ice(&mut self) -> Result<(), TransportError> {
        self.inner.restart_ice()
    }
    fn close(&mut self) {
        self.inner.close()
    }
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
        no_sink: false,
        idle_timeout_secs: 300,
        real_input: false,
        netem: None,
        netem_schedule: None,
        congestion: false,
        input_delay_ms: 0,
        blackhole_candidates: false,
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
            "--real-input" => {
                args.real_input = true;
                i += 1;
            }
            "--netem" => {
                let spec = need("--netem")?;
                transport_webrtc::chaos::NetemProfile::parse(&spec)?;
                args.netem = Some(spec);
                i += 2;
            }
            "--netem-schedule" => {
                let spec = need("--netem-schedule")?;
                parse_netem_schedule(&spec)?;
                args.netem_schedule = Some(spec);
                i += 2;
            }
            "--congestion" => {
                args.congestion = match need("--congestion")?.as_str() {
                    "on" => true,
                    "off" => false,
                    other => return Err(format!("--congestion: {other:?} (on|off)")),
                };
                i += 2;
            }
            "--blackhole-candidates" => {
                args.blackhole_candidates = true;
                i += 1;
            }
            "--input-delay-ms" => {
                args.input_delay_ms = need("--input-delay-ms")?
                    .parse()
                    .map_err(|e| format!("input-delay: {e}"))?;
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
            "--no-sink" => {
                args.no_sink = true;
                i += 1;
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
                     [--mouse-moves N] [--metrics-dir DIR] [--no-sink] [--summary FILE] [--report-stem NAME]\n\
                     [--idle-timeout-secs N] [--real-input]\n\
                     [M5] [--netem 'loss=N|delay_ms=N|rate_kbps=N|udp_blocked=B']\n\
                     [M5] [--netem-schedule 'secs:spec;secs:spec'] [--congestion on|off]\n\
                     [M5] [--input-delay-ms N]"
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
    // F79: soak wrappers that cannot add a flag get the same switch from
    // the environment. Any value except ""/0/false (case-insensitive)
    // enables it; the default path stays sink-on.
    if !args.no_sink
        && std::env::var("RD_RIG_NO_SINK").is_ok_and(|v| {
            !v.is_empty() && !v.eq_ignore_ascii_case("0") && !v.eq_ignore_ascii_case("false")
        })
    {
        args.no_sink = true;
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

/// Process diagnostics for the run summary (F26 evidence): thread and
/// handle counts alongside working set. Not part of the counter schema.
fn proc_diag() -> (u32, u32, u64, u64) {
    unsafe {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        };
        use windows::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
        let mut threads = 0u32;
        if let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            let mut entry = THREADENTRY32 {
                dwSize: size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            if Thread32First(snap, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == std::process::id() {
                        threads += 1;
                    }
                    if Thread32Next(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snap);
        }
        let mut handles = 0u32;
        let _ = GetProcessHandleCount(GetCurrentProcess(), &mut handles);
        let mut counters = PROCESS_MEMORY_COUNTERS_EX::default();
        let cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
        let (ws, private) = if GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters as *mut _
                as *mut windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS,
            cb,
        )
        .is_ok()
        {
            (counters.WorkingSetSize as u64, counters.PrivateUsage as u64)
        } else {
            (0, 0)
        };
        (threads, handles, ws, private)
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

/// Local trait-object wrapper: `Box<dyn InputSink>` cannot blanket-implement
/// the foreign trait (orphan rules), so the pump's type parameter is this
/// forwarder. The slot is what the product's `SendInputSink` plugs into.
struct SinkBox(Box<dyn InputSink>);

impl InputSink for SinkBox {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        self.0.inject(event)
    }

    fn all_keys_up(&mut self) -> Result<(), InputError> {
        self.0.all_keys_up()
    }

    fn held_count(&self) -> usize {
        self.0.held_count()
    }

    fn release_all(&mut self, trigger: AllKeysUpTrigger) -> input_windows::ReleaseOutcome {
        self.0.release_all(trigger)
    }
}

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
    /// M5 congestion: live `ICodecAPI` reconfigurations applied (no MFT
    /// rebuild — CR-1), internal rebuilds (resolution changes only), and
    /// failed attempts.
    reconfig_live: AtomicU64,
    reconfig_rebuilt: AtomicU64,
    reconfig_errors: AtomicU64,
    /// M5 congestion: pacer fps retargets applied.
    fps_retargets: AtomicU64,
}

/// Process-lifetime codec instances (F26): `MfEncoder`/`MfDecoder` drop
/// paths retain committed memory, threads, and handles (~+14 MiB and
/// ~+1.3 MiB + threads per create/drop respectively, measured by
/// `examples/leak_probe.rs`), so per-session pipeline rebuilds must NOT
/// recreate them. The pool hands the instance to each session's stage
/// thread and takes it back when the thread exits; session boundaries are
/// a `reset()` + forced IDR instead of a new MFT. (The drop-path leaks
/// themselves are a codec-windows change request — see m2-rig.md.)
struct CodecPool {
    encoder: Arc<Mutex<Option<codec_windows::MfEncoder>>>,
    decoder: Arc<Mutex<Option<codec_windows::MfDecoder>>>,
    /// Process-lifetime duplication (F26b): each `DxgiCapture` instance
    /// commits a full-resolution surface ring (~128 MiB private bytes at
    /// 4K) that is NOT decommitted on drop — measured +128.2–128.7 MiB
    /// per rebuild in the 30-cycle hammer (working set stays flat, so the
    /// audit's WS numbers saw only a tenth of it). One duplication lives
    /// for the process; sessions take/return it.
    capture: Arc<Mutex<Option<DxgiCapture>>>,
}

impl CodecPool {
    fn new() -> Self {
        Self {
            encoder: Arc::new(Mutex::new(None)),
            decoder: Arc::new(Mutex::new(None)),
            capture: Arc::new(Mutex::new(None)),
        }
    }
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
    /// M5 congestion slots: the engine loop writes a wanted bitrate/fps,
    /// the owning thread applies it on its next iteration (bounded: one
    /// pending slot each, newest wins).
    want_params: Arc<Mutex<Option<codec_windows::EncoderParams>>>,
    want_fps: Arc<Mutex<Option<u32>>>,
}

impl HostPipeline {
    fn start(
        device: GpuDevice,
        force_keyframe: Arc<AtomicBool>,
        codec_pool: &CodecPool,
        args: &Args,
        report: &JsonlReport,
        session: Arc<SessionSlot>,
        clock: Arc<MonotonicClock>,
    ) -> Result<Self, String> {
        let encoder_pool = Arc::clone(&codec_pool.encoder);
        let capture_pool = Arc::clone(&codec_pool.capture);
        // Session start under a reused encoder: force an IDR so the
        // controller's post-reset IDR gate opens immediately.
        force_keyframe.store(true, Ordering::Release);
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
        // M5 congestion control slots (engine loop → owning threads).
        let want_params: Arc<Mutex<Option<codec_windows::EncoderParams>>> =
            Arc::new(Mutex::new(None));
        let want_fps: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
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
            let capture_pool = Arc::clone(&capture_pool);
            let fps = args.fps;
            let ticks = Arc::clone(&pacer_ticks);
            let skipped = Arc::clone(&pacer_skipped);
            let want_fps = Arc::clone(&want_fps);
            joins.push(
                std::thread::Builder::new()
                    .name("capture".into())
                    .spawn(move || {
                        attach_thread_to_input_desktop().expect("input desktop");
                        // Process-lifetime duplication (F26b): take the
                        // pooled instance or create it on first use.
                        let mut cap = match capture_pool.lock().expect("capture pool").take() {
                            Some(cap) => {
                                eprintln!("[host] capture: reusing duplication");
                                cap
                            }
                            None => DxgiCapture::new(device.clone(), &monitor)
                                .expect("duplicate output"),
                        };
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
                            // M5: apply a congestion fps retarget (if any).
                            if let Some(next_fps) = want_fps.lock().expect("want fps").take()
                                && next_fps != pacer.fps()
                            {
                                eprintln!(
                                    "[host] congestion: fps cap {} -> {}",
                                    pacer.fps(),
                                    next_fps
                                );
                                pacer.retarget(next_fps);
                                counters.fps_retargets.fetch_add(1, Ordering::Relaxed);
                            }
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
                        *capture_pool.lock().expect("capture pool") = Some(cap);
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
            let encoder_pool = Arc::clone(&encoder_pool);
            let device = device.clone();
            let want_params = Arc::clone(&want_params);
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
                        // Reuse the process-lifetime encoder when the
                        // pool holds one (F26); create it on first use.
                        let mut encoder = match encoder_pool.lock().expect("encoder pool").take() {
                            Some(encoder) => {
                                eprintln!("[host] encoder (reused): {}", encoder.describe());
                                encoder
                            }
                            None => match codec_windows::MfEncoder::new(device, enc_cfg) {
                                Ok(encoder) => {
                                    eprintln!("[host] encoder: {}", encoder.describe());
                                    encoder
                                }
                                Err(e) => {
                                    eprintln!("[host] encoder init failed: {e}");
                                    q_out.close();
                                    return;
                                }
                            },
                        };
                        loop {
                            // M5: apply a congestion bitrate step LIVE
                            // (`reconfigure`, CR-1: bitrate changes never
                            // rebuild the MFT on this machine's encoders).
                            if let Some(params) = want_params.lock().expect("want params").take() {
                                match encoder.reconfigure(&params) {
                                    Ok(codec_windows::ReconfigureOutcome::Live { .. }) => {
                                        counters.reconfig_live.fetch_add(1, Ordering::Relaxed);
                                        if let Some(bps) = params.bitrate_bps {
                                            eprintln!(
                                                "[host] congestion: bitrate -> {bps} bps (live)"
                                            );
                                        }
                                    }
                                    Ok(codec_windows::ReconfigureOutcome::Rebuilt { reason }) => {
                                        counters.reconfig_rebuilt.fetch_add(1, Ordering::Relaxed);
                                        eprintln!(
                                            "[host] congestion: reconfigure rebuilt ({reason})"
                                        );
                                    }
                                    Ok(codec_windows::ReconfigureOutcome::Noop) => {}
                                    Err(e) => {
                                        counters.reconfig_errors.fetch_add(1, Ordering::Relaxed);
                                        eprintln!("[host] congestion: reconfigure failed: {e}");
                                    }
                                }
                            }
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
                        *encoder_pool.lock().expect("encoder pool") = Some(encoder);
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
            want_params,
            want_fps,
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
        codec_pool: &CodecPool,
        args: &Args,
        report: &JsonlReport,
        session: Arc<SessionSlot>,
        clock: Arc<MonotonicClock>,
    ) -> Result<Self, String> {
        let decoder_pool = Arc::clone(&codec_pool.decoder);
        let q_recv_dec = Arc::new(FrameQueue::new(
            QueueKind::RecvToDecode,
            // M5 matrix evidence: the GCC pacer releases ~0.1 s bursts
            // (~6 frames at 1080p60); a cap of 2 dropped one frame per
            // burst slip, and every drop cascaded through the decoder's
            // IDR gate (~10 lost frames per gap — rtt150 cell: 3490
            // received, 2102 presented). 8 absorbs a burst plus jitter
            // while staying far below a latency-relevant backlog (8
            // frames ≈ 133 ms, dropped by newest-wins long before).
            8,
            // Schema table says "bounded, drop-oldest" (F35): the oldest
            // queued frame is the stale one; the drop surfaces as a
            // frame-id gap -> keyframe request downstream.
            DropPolicy::NewestWins,
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
            let decoder_pool = Arc::clone(&decoder_pool);
            let device = device.clone();
            joins.push(
                std::thread::Builder::new()
                    .name("decode".into())
                    .spawn(move || {
                        // Reuse the process-lifetime decoder when the
                        // pool holds one (F26); create on first use and
                        // reset per session (IDR gate armed).
                        let mut decoder = match decoder_pool.lock().expect("decoder pool").take() {
                            Some(mut decoder) => {
                                let _ = decoder.reset();
                                eprintln!("[controller] decoder (reused): {}", decoder.describe());
                                decoder
                            }
                            None => {
                                let decoder = codec_windows::MfDecoder::new(
                                    device,
                                    codec_windows::MfDecoderConfig { use_gpu: true },
                                )
                                .expect("decoder");
                                eprintln!("[controller] decoder: {}", decoder.describe());
                                decoder
                            }
                        };
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
                        *decoder_pool.lock().expect("decoder pool") = Some(decoder);
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
    /// Host input consumption (real `InputSink` trait object slot: the
    /// recording sink by default, `SendInputSink` with `--real-input`).
    input_pump: Option<InputPump<SinkBox>>,
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
    /// (threads, handles, ws, private) at each session end (F26 evidence).
    per_session_diag: Vec<(u32, u32, u64, u64)>,
    /// Inject-error watermark for the one-shot UIPI hint.
    last_inject_errors: u64,
    /// Cached process diagnostics: the toolhelp thread snapshot is far too
    /// expensive for the 2 ms loop cadence (it enumerates every thread in
    /// the system), so it refreshes at most every 500 ms and `write_status`
    /// reads the cache.
    cached_diag: (u32, u32, u64, u64),
    diag_refreshed_at: Instant,
}

impl RigObserver {
    /// `--real-input` UIPI hint: injection blocked — elevated foreground
    /// window or locked session (operational mitigation, never retry).
    fn real_input_hint(&mut self) {
        eprintln!(
            "[{}] --real-input: injection was BLOCKED (UIPI). The foreground window is elevated (UAC) or this session is locked. Run the host elevated for sessions that must control elevated apps, or unlock the session.",
            self.device
        );
    }

    /// Refresh `cached_diag` at most every 500 ms (see field docs).
    fn refresh_diag_if_due(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.diag_refreshed_at) >= Duration::from_millis(500) {
            self.diag_refreshed_at = now;
            self.cached_diag = proc_diag();
        }
    }

    /// True when the input pump saw injection failures since the last
    /// status write (drives the one-shot `--real-input` UIPI hint).
    fn note_input_errors(&mut self) -> bool {
        self.input_pump
            .as_mut()
            .map(|pump| {
                let counters = pump.counters();
                let failed = counters.inject_errors > self.last_inject_errors;
                self.last_inject_errors = counters.inject_errors;
                failed
            })
            .unwrap_or(false)
    }

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
        let (threads, handles, ws, private) = self.cached_diag;
        let doc = serde_json::json!({
            "device": self.device,
            "host_state": host_state,
            "controller_state": controller_state,
            "session_id": node.current_session_id(),
            "prompts": self.prompts,
            "input": input,
            "proc": {
                "threads": threads,
                "handles": handles,
                "ws_bytes": ws,
                "private_bytes": private,
            },
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
        let (threads, handles, ws, private) = proc_diag();
        self.per_session_diag.push((threads, handles, ws, private));
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

/// Parse an M5 netem schedule (`secs:spec;secs:spec;...`) into
/// `(secs, profile)` pairs; validates every profile eagerly.
fn parse_netem_schedule(
    spec: &str,
) -> Result<Vec<(u64, transport_webrtc::chaos::NetemProfile)>, String> {
    let mut out = Vec::new();
    for entry in spec.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (secs, profile_spec) = entry
            .split_once(':')
            .ok_or_else(|| format!("schedule entry {entry:?}: expected secs:spec"))?;
        let secs: u64 = secs
            .trim()
            .parse()
            .map_err(|e| format!("schedule secs {secs:?}: {e}"))?;
        let profile = transport_webrtc::chaos::NetemProfile::parse(profile_spec.trim())?;
        out.push((secs, profile));
    }
    if out.is_empty() {
        return Err("empty netem schedule".into());
    }
    Ok(out)
}

/// Send one encoded input message now, or park it in the M5 delay line
/// when the cell shapes the controller→host direction (RTT half).
fn send_input_maybe_delayed(
    node: &mut Node,
    delay: &mut transport_webrtc::chaos::DelayQueue<Vec<u8>>,
    delay_ms: u64,
    now_ms: u64,
    channel: Channel,
    bytes: &[u8],
) -> Result<(), transport_webrtc::TransportError> {
    if delay_ms == 0 {
        node.send_wire_bytes(channel, bytes)
    } else {
        match delay.push(now_ms, delay_ms, bytes.to_vec()) {
            Ok(()) => Ok(()),
            Err(_) => Err(transport_webrtc::TransportError(
                "input delay line full (bounded); message dropped".into(),
            )),
        }
    }
}

/// M5-aware transport factory: the host carries the congestion estimator
/// and (optionally) the netem shaper; the controller stays at the loopback
/// baseline. Returns the handle for mid-run profile changes.
fn fresh_transport_opts(
    is_host: bool,
    args: &Args,
) -> Result<(Box<WebrtcTransport>, Option<transport_webrtc::NetemHandle>), String> {
    let role = if is_host {
        WebrtcTransportRole::Host
    } else {
        WebrtcTransportRole::Controller
    };
    let options = if is_host {
        transport_webrtc::WebrtcTransportOptions {
            congestion: args
                .congestion
                .then_some(transport_webrtc::CongestionOptions {
                    initial_bps: 4_000_000,
                    min_bps: 300_000,
                    max_bps: 12_000_000,
                }),
            video_netem: args
                .netem
                .as_deref()
                .and_then(|spec| transport_webrtc::chaos::NetemProfile::parse(spec).ok()),
            ..Default::default()
        }
    } else {
        transport_webrtc::WebrtcTransportOptions::default()
    };
    let transport = WebrtcTransport::with_options(role, options)
        .map_err(|e| format!("transport build: {e}"))?;
    let handle = transport.netem_handle();
    Ok((Box::new(transport), handle))
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

    // ---- metrics (F79: --no-sink / RD_RIG_NO_SINK skips JSONL entirely) ----
    let report = if args.no_sink {
        eprintln!("[{device}] metrics: sink disabled (--no-sink): no JSONL file, no records");
        JsonlReport::disabled()
    } else {
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
        report
    };
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
    let (transport, mut netem_handle) = fresh_transport_opts(is_host, &args).expect("transport");
    if args.blackhole_candidates {
        eprintln!(
            "[{device}] --blackhole-candidates: remote candidate ports -> 9 (UDP-blocked emulation)"
        );
        node.attach_transport(Box::new(BlackholeTransport {
            inner: transport,
            rewritten: std::sync::atomic::AtomicU64::new(0),
        }));
    } else {
        node.attach_transport(transport);
    }
    // M5 state: netem schedule + congestion controller (host side).
    let netem_schedule: Vec<(u64, transport_webrtc::chaos::NetemProfile)> = args
        .netem_schedule
        .as_deref()
        .map(parse_netem_schedule)
        .transpose()
        .expect("schedule validated at parse")
        .unwrap_or_default();
    let mut netem_schedule_index = 0usize;
    let mut congestion_ctl = if is_host && args.congestion {
        Some(node_runtime::congestion::CongestionController::new(
            node_runtime::congestion::CongestionParams {
                start_bps: u64::from(args.bitrate_kbps) * 1000,
                ..Default::default()
            },
        ))
    } else {
        None
    };
    let mut congestion_events: Vec<serde_json::Value> = Vec::new();
    // M5: controller→host input delay line (the RTT cell's other half).
    let mut input_delay: transport_webrtc::chaos::DelayQueue<Vec<u8>> =
        transport_webrtc::chaos::DelayQueue::new(1024);

    // ---- stimulus (host) ----
    let stimulus = if is_host && args.stimulus {
        Some(spawn_stimulus(Arc::clone(&stop_flag)))
    } else {
        None
    };

    // ---- observer ----
    let status_path = args.dir.join(format!("{}-status.json", args.role));
    // Host input consumption. Default: the recording sink (scripted input
    // must not fight the operator on a single machine). `--real-input`
    // (LAN checkpoint): the real SendInput adapter — same `InputSink`
    // slot, pointer mapped onto the captured monitor's rectangle.
    let input_pump = if is_host {
        if args.real_input {
            // Geometry from the same monitor the capture duplicates (a
            // throwaway duplication, dropped before the pipeline's own).
            let (left, top, width, height) =
                match capture_windows::DxgiCapture::new(gpu.clone(), &args.monitor) {
                    Ok(cap) => {
                        let (w, h) = cap.dimensions();
                        (0, 0, w as i32, h as i32)
                    }
                    Err(_) => (0, 0, 1920, 1080),
                };
            let rect =
                input_windows::MonitorRect::new(left, top, width, height).expect("monitor rect");
            match input_windows::SendInputSink::new(rect) {
                Ok(sink) => {
                    eprintln!(
                        "[{device}] --real-input: SendInputSink active on the primary \
                         monitor ({width}x{height}); the scripted input will MOVE THE \
                         REAL CURSOR. If the controller runs on this same machine it \
                         will fight the operator — this flag is for the two-PC LAN \
                         checkpoint."
                    );
                    Some(InputPump::new(SinkBox(Box::new(sink))))
                }
                Err(err) => {
                    eprintln!("[{device}] --real-input: SendInputSink init failed: {err}");
                    eprintln!("[{device}] falling back to the recording sink");
                    Some(InputPump::new(SinkBox(Box::new(RecordingSink::default()))))
                }
            }
        } else {
            Some(InputPump::new(SinkBox(Box::new(RecordingSink::default()))))
        }
    } else {
        None
    };
    let mut observer = RigObserver {
        is_host,
        session_slot: Arc::clone(&session_slot),
        status_path: status_path.clone(),
        device,
        input_pump,
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
        per_session_diag: Vec::new(),
        last_inject_errors: 0,
        cached_diag: (0, 0, 0, 0),
        diag_refreshed_at: Instant::now() - Duration::from_secs(10),
    };
    let host_pipe_device = if is_host { Some(gpu.clone()) } else { None };
    let ctrl_pipe_device = if is_host { None } else { Some(gpu.clone()) };
    let host_force_flag = Arc::clone(&observer.host_force_flag);
    let codec_pool = CodecPool::new();

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
    // M5: mutable pipeline args (the congestion last resort rewrites the
    // encode geometry once) + the step-down edge flag. F74c: rebuilds the
    // last resort actually performed (summed into `encoder_rebuilds`).
    let mut rig_args = args.clone();
    let mut congestion_step_down_720p = false;
    let mut congestion_rebuilds_stepdown = 0u64;
    let mut moves_sent: u64 = 0;
    let mut reliable_sent: u64 = 0;
    let mut reliable_send_errors: u64 = 0;
    let mut input_phase_started = false;
    let mut chaos_flushed = false;
    let mut dup_probe_sent = false;
    let mut final_position_sent: Option<(u16, u16)> = None;
    let mut last_stats_tick = Instant::now();
    let mut last_keyframe_request = Instant::now() - Duration::from_secs(10);
    let mut last_channel_gauges: Option<transport_webrtc::ChannelQueues> = None;
    let mut last_channel_tick = Instant::now() - Duration::from_secs(10);
    let mut final_transport_stats: Option<transport_webrtc::TransportStats> = None;
    let mut cycle: u64 = 0;
    let mut netchange_at_elapsed = Duration::ZERO;
    let mut netchange_self_restarted = false;
    // F26 evidence: per-session process diagnostics at session end.
    let mut per_session_diag: Vec<(String, u32, u32, u64, u64)> = Vec::new();
    let mut failure_reason = String::new();
    let host_out_file = args.dir.join("c2h.jsonl");

    // Controller start delay: give the host a moment to register.
    let script_start = Instant::now() + Duration::from_millis(700);
    // F31: calibrate the engine's `Instant` domain onto the session clock
    // (both are QPC-based; the offset is constant for the process), so
    // `recv_ns` reflects the engine's first-packet arrival time rather
    // than this loop's poll time.
    let clock_origin = (Instant::now(), clock.now_ns());

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
            match fresh_transport_opts(true, &args) {
                Ok((transport, handle)) => {
                    netem_handle = handle;
                    node.attach_transport(transport)
                }
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
                &codec_pool,
                &rig_args,
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
                &codec_pool,
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
                // F31: engine-side first-packet arrival, mapped onto the
                // session clock; poll time is only the fallback.
                let recv_ns = match frame.recv_instant {
                    Some(arrival) => {
                        clock_origin.1
                            + arrival.saturating_duration_since(clock_origin.0).as_nanos() as u64
                    }
                    None => clock.now_ns(),
                };
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

        // ---- channel-queue sampling (F32 + F63): the depth TRAIL carries
        // every depth change recorded at mutation time (sub-poll bursts
        // included — the M5 matrix's high_water 30/32 was invisible to
        // polled depth), and the ≥1 Hz / nonzero-depth snapshot below
        // provides the periodic baseline. ----
        {
            let (trail, uptime_now) = node.channel_depth_trail();
            if !trail.is_empty() {
                let now_ns = clock.now_ns();
                let mut sink = report.sink_handle(Arc::clone(&session_slot));
                for entry in &trail {
                    let kind = match entry.channel {
                        Channel::Control => QueueKind::ChannelControl,
                        Channel::InputFast => QueueKind::ChannelInputFast,
                        Channel::InputReliable => QueueKind::ChannelInputReliable,
                        Channel::Cursor => QueueKind::ChannelCursor,
                    };
                    let at_ns =
                        now_ns.saturating_sub(uptime_now.saturating_sub(entry.at_uptime_ns));
                    // Capacity/counters from the previous poll's snapshot
                    // (≤ one loop iteration old; capacity is static).
                    let prev = last_channel_gauges.as_ref();
                    sink.record(CounterRecord::QueueSample(diagnostics::QueueSample {
                        session_id: session_slot.get(),
                        queue: kind,
                        depth: entry.depth,
                        capacity: prev
                            .map(|g| g.capacity[entry.channel as usize])
                            .unwrap_or(0),
                        high_water: prev
                            .map(|g| g.high_water[entry.channel as usize])
                            .unwrap_or(0),
                        dropped: prev.map(|g| g.dropped[entry.channel as usize]).unwrap_or(0),
                        replaced: prev
                            .map(|g| g.replaced[entry.channel as usize])
                            .unwrap_or(0),
                        at_ns,
                    }));
                }
            }
        }
        if let Some(gauges) = node.channel_queue_gauges() {
            let any_nonzero = (0..4).any(|i| gauges.depth[i] > 0);
            let tick_due = now.duration_since(last_channel_tick) >= Duration::from_secs(1);
            if any_nonzero || tick_due {
                last_channel_tick = now;
                last_channel_gauges = Some(gauges);
                let mut sink = report.sink_handle(Arc::clone(&session_slot));
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
                        depth: gauges.depth[index],
                        capacity: gauges.capacity[index],
                        high_water: gauges.high_water[index],
                        dropped: gauges.dropped[index],
                        replaced: gauges.replaced[index],
                        at_ns: clock.now_ns(),
                    }));
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
                    rtt_ms: stats.rtt_ms.map(|v| v as f32),
                    loss_percent: stats.loss_percent.map(|v| v as f32),
                    available_bandwidth_kbps: stats
                        .available_bandwidth_bps
                        .map(|v| (v / 1000) as u32),
                    remote_loss_percent: stats.remote_loss_percent.map(|v| v as f32),
                    remote_rtt_ms: stats.remote_rtt_ms.map(|v| v as f32),
                    at_ns: clock.now_ns(),
                }));
                // M5: feed the congestion policy (host, streaming, on) and
                // apply its decision to the live encoder/pacer slots.
                if let (Some(ctl), Some(pipeline)) =
                    (congestion_ctl.as_mut(), observer.host_pipeline.as_ref())
                {
                    let sample = node_runtime::congestion::CongestionSample {
                        at_ms: clock.now_ms(),
                        estimate_bps: stats.available_bandwidth_bps,
                        remote_loss_percent: stats.remote_loss_percent,
                        remote_rtt_ms: stats.remote_rtt_ms,
                        ice_rtt_ms: stats.rtt_ms,
                        send_bitrate_kbps: stats.send_bitrate_kbps,
                    };
                    let decision = ctl.sample(sample);
                    if decision.bitrate_bps.is_some()
                        || decision.fps_cap.is_some()
                        || decision.resolution_step_down
                    {
                        eprintln!(
                            "[{device}] congestion decision: bitrate={:?} fps={:?} res_down={} ({})",
                            decision.bitrate_bps,
                            decision.fps_cap,
                            decision.resolution_step_down,
                            decision.reason
                        );
                        congestion_events.push(serde_json::json!({
                            "at_ms": clock.now_ms(),
                            "bitrate_bps": decision.bitrate_bps,
                            "fps_cap": decision.fps_cap,
                            "resolution_step_down": decision.resolution_step_down,
                            "reason": decision.reason,
                            "estimate_bps": stats.available_bandwidth_bps,
                            "remote_loss_percent": stats.remote_loss_percent,
                            "encoder_bitrate_bps": ctl.bitrate_bps(),
                        }));
                    }
                    if let Some(bps) = decision.bitrate_bps {
                        *pipeline.want_params.lock().expect("want params") =
                            Some(codec_windows::EncoderParams {
                                bitrate_bps: Some(bps.min(u32::MAX as u64) as u32),
                                ..Default::default()
                            });
                    }
                    if let Some(fps) = decision.fps_cap {
                        *pipeline.want_fps.lock().expect("want fps") = Some(fps);
                    }
                    // Resolution step-down (last resort): rebuild the
                    // encode stage at 720p. The pooled encoder is dropped
                    // (wrong geometry for reuse) — the one priced rebuild.
                    if decision.resolution_step_down {
                        eprintln!("[{device}] congestion: resolution step-down (720p rebuild)");
                        congestion_step_down_720p = true;
                    }
                }
                // Channel-queue samples live in the per-change block above
                // (F32 cadence); this 1 Hz tick carries the LinkSample only.
                if stats.relay_in_use {
                    eprintln!("[{device}] FATAL: relay in use (invariant 4)");
                    failure_reason = "relay_in_use".into();
                    break;
                }
                final_transport_stats = Some(stats);
            }
            // M5 netem schedule (host): swap the profile at the planned
            // stream-elapsed seconds (bandwidth step-down cells).
            if let (Some(handle), Some(started)) =
                (netem_handle.as_ref(), observer.stream_started_at)
            {
                let elapsed_s = started.elapsed().as_secs();
                while netem_schedule_index < netem_schedule.len()
                    && netem_schedule[netem_schedule_index].0 <= elapsed_s
                {
                    let (at, profile) = &netem_schedule[netem_schedule_index];
                    eprintln!("[{device}] netem schedule @ {at}s: {profile:?}");
                    handle.set_profile(profile.clone());
                    netem_schedule_index += 1;
                }
            }
        }

        // M5: congestion last resort — apply the 720p rebuild once.
        if congestion_step_down_720p {
            congestion_step_down_720p = false;
            rig_args.encode_w = 1280;
            rig_args.encode_h = 720;
            if let Some(pipeline) = observer.host_pipeline.take() {
                congestion_rebuilds_stepdown += 1;
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
                // The pooled encoder has the old geometry: drop it (the
                // one priced rebuild per sustained-starvation event).
                *codec_pool.encoder.lock().expect("encoder pool") = None;
                // The machine is still Connected; the start block below
                // rebuilds at 720p on its next iteration.
                observer.want_streaming = true;
            }
        }

        // M5: input-delay line (controller→host RTT half). Flush due
        // messages; the scenario pushes new ones through `queue_input`.
        if args.input_delay_ms > 0 {
            let now_ms = clock.now_ms();
            for bytes in input_delay.drain_due(now_ms) {
                let decoded = protocol::wire::decode(&bytes);
                let channel = match decoded {
                    Ok(WireMessage::Input(InputEvent::MouseMove { .. })) => Channel::InputFast,
                    _ => Channel::InputReliable,
                };
                let _ = node.send_wire_bytes(channel, &bytes);
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
                                let _ = send_input_maybe_delayed(
                                    &mut node,
                                    &mut input_delay,
                                    args.input_delay_ms,
                                    clock.now_ms(),
                                    Channel::InputFast,
                                    &bytes,
                                );
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
                            if let Err(err) = send_input_maybe_delayed(
                                &mut node,
                                &mut input_delay,
                                args.input_delay_ms,
                                clock.now_ms(),
                                Channel::InputReliable,
                                &bytes,
                            ) {
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
                        // at 5 s (engine CLOSE_TIMEOUT; +2 s more on Drop).
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
                        match fresh_transport_opts(false, &args) {
                            Ok((transport, _)) => node.attach_transport(transport),
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
                    if let Some(session) = node.current_session_id() {
                        let (threads, handles, ws, private) = proc_diag();
                        per_session_diag.push((session, threads, handles, ws, private));
                    }
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
                        match fresh_transport_opts(false, &args) {
                            Ok((transport, _)) => node.attach_transport(transport),
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

        if observer.note_input_errors() && args.real_input {
            observer.real_input_hint();
        }
        observer.refresh_diag_if_due();
        observer.write_status(&node);
        std::thread::sleep(Duration::from_millis(2));
    }

    // ---- teardown (keep the counter Arcs for the summary) ----
    stop_flag.store(true, Ordering::Release);
    node.close_transport();
    let mut cursor_slot_counters = None;
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
        cursor_slot_counters = Some(pipeline.cursor_slot.counters());
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
            "reliable_duplicates_suppressed": counters.reliable_duplicates_suppressed,
            "reliable_stale_suppressed": counters.reliable_stale_suppressed,
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
    let proc_diag_final = proc_diag();
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
    // M5: live-reconfig / fps-retarget evidence across every host pipeline
    // (finished + the live one at exit).
    let mut reconfig_live = 0u64;
    let mut reconfig_rebuilt = 0u64;
    let mut reconfig_errors = 0u64;
    let mut fps_retargets = 0u64;
    let mut all_host_counters: Vec<&Arc<HostPipeCounters>> =
        observer.finished_host_pipes.iter().collect();
    if let Some(pipeline) = observer.host_pipeline.as_ref() {
        all_host_counters.push(&pipeline.counters);
    }
    for counters in &all_host_counters {
        reconfig_live += counters.reconfig_live.load(Ordering::Relaxed);
        reconfig_rebuilt += counters.reconfig_rebuilt.load(Ordering::Relaxed);
        reconfig_errors += counters.reconfig_errors.load(Ordering::Relaxed);
        fps_retargets += counters.fps_retargets.load(Ordering::Relaxed);
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
        "real_input": args.real_input && is_host,
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
            "disabled": args.no_sink,
            "path": metrics_path.display().to_string(),
            "records": records,
            "backpressure_events": backpressure,
        },
        "channel_open_order": node.channel_open_order(),
        "proc": {
            // (threads, handles, ws) at every session end, both roles.
            "per_session_end": observer
                .per_session_diag
                .iter()
                .map(|(t, h, ws, priv_b)| serde_json::json!({
                    "threads": t,
                    "handles": h,
                    "ws_mib": *ws as f64 / (1 << 20) as f64,
                    "private_mib": *priv_b as f64 / (1 << 20) as f64,
                }))
                .collect::<Vec<_>>(),
            "final": {
                "threads": proc_diag_final.0,
                "handles": proc_diag_final.1,
                "ws_mib": proc_diag_final.2 as f64 / (1 << 20) as f64,
                "private_mib": proc_diag_final.3 as f64 / (1 << 20) as f64,
            },
            // Controller-side variant keyed by session id (scenario engine).
            "per_session": per_session_diag
                .iter()
                .map(|(sid, t, h, ws, priv_b)| serde_json::json!({
                    "session": sid,
                    "threads": t,
                    "handles": h,
                    "ws_mib": *ws as f64 / (1 << 20) as f64,
                    "private_mib": *priv_b as f64 / (1 << 20) as f64,
                }))
                .collect::<Vec<_>>(),
        },
        "cursor": {
            "overlays_received": observer.cursor_overlays,
            "shapes_received": observer.cursor_shapes_rx,
            "slot_replaced": cursor_slot_counters.map(|(r, _)| r).unwrap_or(0),
            "slot_taken": cursor_slot_counters.map(|(_, t)| t).unwrap_or(0),
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
            "reconfig_live": reconfig_live,
            "reconfig_rebuilt": reconfig_rebuilt,
            "reconfig_errors": reconfig_errors,
            "fps_retargets": fps_retargets,
            "encode_size": format!("{}x{}", rig_args.encode_w, rig_args.encode_h),
            "pacer": {
                "ticks": pacer_ticks_total,
                "skipped": pacer_skipped_total,
                "fps_tick_rate": pacer_ticks_total as f64 / stream_secs,
            },
            "device_lost": device_lost_host,
        });
        // M6 F74c: host-side congestion evidence as counters, not stderr
        // lines — the decisions the policy made, the live reconfigs the
        // encoder took, and every rebuild (the priced path the M6 gate
        // wants at zero). Previously this block was written only on the
        // controller (which never runs the policy), so `events` was
        // always empty and the soak had to parse engine log strings.
        summary["congestion"] = serde_json::json!({
            "enabled": args.congestion,
            "congestion_decisions": congestion_events.len() as u64,
            "congestion_reconfigs": reconfig_live,
            "encoder_rebuilds": reconfig_rebuilt + congestion_rebuilds_stepdown,
            "reconfig_errors": reconfig_errors,
            "fps_retargets": fps_retargets,
            "resolution_step_down_rebuilds": congestion_rebuilds_stepdown,
            "events": congestion_events,
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
        // M5 evidence: congestion decisions + netem shaping state.
        summary["congestion"] = serde_json::json!({
            "enabled": args.congestion,
            "events": congestion_events,
            "input_delay_ms": args.input_delay_ms,
            "input_delay_dropped": input_delay.dropped,
            "input_delay_delivered": input_delay.delivered,
        });
        summary["netem"] = serde_json::json!({
            "initial": args.netem,
            "schedule": args.netem_schedule,
        });
    }
    if let Some(stats) = final_transport_stats {
        // F74a/F74b: shaper + channel-queue gauges in the summary —
        // previously `netem_queue` was dropped by the summary entirely and
        // the depth-trail overflow had no export path, so the M6 gate's
        // bounded-queue evidence for those two surfaces required raw-JSONL
        // digging.
        let channel_queues: serde_json::Map<String, serde_json::Value> = CHANNEL_LABELS
            .iter()
            .enumerate()
            .map(|(index, label)| {
                let cq = stats.channel_queue;
                (
                    (*label).to_owned(),
                    serde_json::json!({
                        "depth": cq.depth[index],
                        "capacity": cq.capacity[index],
                        "high_water": cq.high_water[index],
                        "dropped": cq.dropped[index],
                        "replaced": cq.replaced[index],
                        "enqueued": cq.enqueued[index],
                        "dequeued": cq.dequeued[index],
                        "trail_overflow": cq.trail_overflow[index],
                    }),
                )
            })
            .collect();
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
            "netem_queue": stats.netem_queue.map(|q| serde_json::json!({
                "depth": q.depth,
                "capacity": q.capacity,
                "high_water": q.high_water,
                "dropped": q.dropped,
                "delivered": q.delivered,
                "heap_capacity": q.heap_capacity,
                "heap_high_water": q.heap_high_water,
            })),
            "channel_queues": serde_json::Value::Object(channel_queues),
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
