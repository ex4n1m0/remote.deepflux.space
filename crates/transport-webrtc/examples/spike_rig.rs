//! M2 transport spike rig (RD-006/007/008, delta D2): host + controller as
//! two processes on one machine, manual file-based signaling, H.264 RTP
//! video, four data channels, application-layer loss/reorder injection.
//!
//! Run (two terminals):
//!
//! ```text
//! cargo run -p transport-webrtc --example spike_rig -- --role host --dir C:\temp\rd-signal
//! cargo run -p transport-webrtc --example spike_rig -- --role controller --dir C:\temp\rd-signal
//! ```
//!
//! Signaling travels as `protocol::signaling` JSON envelopes in `--dir`
//! (`offer.json`, `answer.json`, `c2h.jsonl`, `h2c.jsonl`, `bye.json`) —
//! the same envelope shapes the M3 Vercel service will forward. SDP bodies
//! and input payloads are never logged (invariants 2/6).
//!
//! The H.264 encoder here is the spike-only software path (openh264,
//! dev-dependency) behind the `VideoEncoder` trait *shape*;
//! `crates/codec-windows` replaces it in M2 integration:
//! `// spike-only, replaced by codec-windows in M2 integration`.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use diagnostics::{CounterRecord, FrameTiming, LinkSample, PerfSink, QueueKind, QueueSample};
use protocol::capabilities::{
    Capabilities, EncoderCapabilities, EncoderKind, FeatureFlags, MonitorInfo,
};
use protocol::signaling::{
    DeviceId, MessageId, SIGNALING_PROTOCOL_VERSION, SignalingBody, SignalingEnvelope,
    ensure_signaling_version,
};
use protocol::wire::{
    AllKeysUpTrigger, ButtonState, ControlDisconnectReason, CursorMessage, InputEvent, MouseButton,
    WireMessage,
};
use transport_webrtc::chaos::ChaosInjector;
use transport_webrtc::{
    Channel, ConnectionState, Transport, TransportEvent, VideoFrame, WebrtcTransport,
    WebrtcTransportRole,
};

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

struct Args {
    role: &'static str,
    dir: PathBuf,
    duration: Duration,
    fps: u32,
    width: u32,
    height: u32,
    bitrate_kbps: u32,
    drop_fast_pct: u32,
    reorder_fast_pct: u32,
    drop_reliable_nth: u64,
    seed: u64,
    mouse_moves: u64,
    metrics: Option<PathBuf>,
    summary: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        role: "",
        dir: std::env::temp_dir().join("rd-spike-signal"),
        duration: Duration::from_secs(300),
        fps: 60,
        width: 1280,
        height: 720,
        bitrate_kbps: 4000,
        drop_fast_pct: 10,
        reorder_fast_pct: 5,
        drop_reliable_nth: 40,
        seed: 2026,
        mouse_moves: 3000,
        metrics: None,
        summary: std::env::temp_dir().join("rd-spike-summary.json"),
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
            "--duration-secs" => {
                args.duration = Duration::from_secs(
                    need("--duration-secs")?
                        .parse()
                        .map_err(|e| format!("duration: {e}"))?,
                );
                i += 2;
            }
            "--fps" => {
                args.fps = need("--fps")?.parse().map_err(|e| format!("fps: {e}"))?;
                i += 2;
            }
            "--width" => {
                args.width = need("--width")?
                    .parse()
                    .map_err(|e| format!("width: {e}"))?;
                i += 2;
            }
            "--height" => {
                args.height = need("--height")?
                    .parse()
                    .map_err(|e| format!("height: {e}"))?;
                i += 2;
            }
            "--bitrate-kbps" => {
                args.bitrate_kbps = need("--bitrate-kbps")?
                    .parse()
                    .map_err(|e| format!("bitrate: {e}"))?;
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
            "--metrics" => {
                args.metrics = Some(PathBuf::from(need("--metrics")?));
                i += 2;
            }
            "--summary" => {
                args.summary = PathBuf::from(need("--summary")?);
                i += 2;
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    if args.role.is_empty() {
        return Err("required: --role host|controller".into());
    }
    Ok(args)
}

// ---------------------------------------------------------------------------
// Metrics sink (JSONL of `diagnostics::CounterRecord`s)
// ---------------------------------------------------------------------------

struct JsonlSink {
    file: fs::File,
    session_start: Instant,
}

impl JsonlSink {
    fn open(path: &Path) -> Self {
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|e| panic!("metrics file {path:?}: {e}"));
        Self {
            file,
            session_start: Instant::now(),
        }
    }

    fn at_ns(&self) -> u64 {
        self.session_start.elapsed().as_nanos() as u64
    }
}

impl PerfSink for JsonlSink {
    fn record(&mut self, record: CounterRecord) {
        let line = serde_json::to_string(&record).unwrap_or_default();
        let _ = writeln!(self.file, "{line}");
    }
}

/// Sink variant that only counts (for runs without --metrics).
struct CountingSink {
    records: std::sync::atomic::AtomicU64,
    session_start: Instant,
}

impl CountingSink {
    fn at_ns(&self) -> u64 {
        self.session_start.elapsed().as_nanos() as u64
    }
}

impl PerfSink for CountingSink {
    fn record(&mut self, _record: CounterRecord) {
        self.records.fetch_add(1, Ordering::Relaxed);
    }
}

enum RigSink {
    File(JsonlSink),
    Counting(CountingSink),
}

impl RigSink {
    fn at_ns(&self) -> u64 {
        match self {
            RigSink::File(s) => s.at_ns(),
            RigSink::Counting(s) => s.at_ns(),
        }
    }
}

impl PerfSink for RigSink {
    fn record(&mut self, record: CounterRecord) {
        match self {
            RigSink::File(s) => PerfSink::record(s, record),
            RigSink::Counting(s) => PerfSink::record(s, record),
        }
    }
}

// ---------------------------------------------------------------------------
// File-based signaling (protocol envelopes)
// ---------------------------------------------------------------------------

const HOST_DEVICE: &str = "rig-host";
const CONTROLLER_DEVICE: &str = "rig-controller";
const SESSION_ID: &str = "m2-transport-spike";

fn message_id(role: &str) -> MessageId {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("rig-{role}-{n}-{nanos}")
}

fn envelope(from: &str, to: &str, body: SignalingBody) -> SignalingEnvelope {
    SignalingEnvelope {
        protocol_version: SIGNALING_PROTOCOL_VERSION,
        message_id: message_id(from),
        session_id: Some(SESSION_ID.to_owned()),
        from_device_id: from.to_owned(),
        to_device_id: to.to_owned(),
        timestamp_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        body,
    }
}

fn write_json_atomic(path: &Path, json: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, json)?;
    fs::rename(&tmp, path)
}

fn wait_for_file(path: &Path, timeout: Duration) -> Option<String> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if let Ok(bytes) = fs::read(path)
            && !bytes.is_empty()
        {
            return Some(String::from_utf8_lossy(&bytes).into_owned());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// Incremental reader for the JSONL candidate streams (tracks its offset).
struct CandidateFile {
    path: PathBuf,
    offset: u64,
    seen: Vec<MessageId>,
}

impl CandidateFile {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            seen: Vec::new(),
        }
    }

    /// Newly appended, version-checked envelopes (idempotent by message_id).
    fn drain(&mut self) -> Vec<SignalingEnvelope> {
        let Ok(mut file) = fs::OpenOptions::new().read(true).open(&self.path) else {
            return vec![];
        };
        let _ = file.seek(SeekFrom::Start(self.offset));
        let mut buf = String::new();
        // Bound the read to avoid unbounded memory on a hostile file.
        let mut chunk = vec![0u8; 1 << 20];
        match file.read(&mut chunk) {
            Ok(n) if n > 0 => {
                let _ = (&chunk[..n]).read_to_string(&mut buf);
                self.offset += buf.len() as u64;
                // Keep partial trailing lines for the next drain by
                // rewinding past them.
                if !buf.ends_with('\n') {
                    if let Some(last_nl) = buf.rfind('\n') {
                        self.offset -= (buf.len() - last_nl - 1) as u64;
                        buf.truncate(last_nl + 1);
                    } else {
                        self.offset -= buf.len() as u64;
                        buf.clear();
                    }
                }
            }
            _ => return vec![],
        }
        let mut out = Vec::new();
        for line in buf.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(env) = serde_json::from_str::<SignalingEnvelope>(line) else {
                eprintln!("[signal] skipping unparseable line ({} bytes)", line.len());
                continue;
            };
            if ensure_signaling_version(env.protocol_version).is_err() {
                eprintln!("[signal] dropping envelope with bad protocol_version");
                continue;
            }
            if self.seen.contains(&env.message_id) {
                continue; // duplicate delivery is a no-op
            }
            if self.seen.len() > 512 {
                self.seen.clear();
            }
            self.seen.push(env.message_id.clone());
            out.push(env);
        }
        out
    }
}

fn append_envelope(path: &Path, env: &SignalingEnvelope) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let line = serde_json::to_string(env).expect("envelope serializes");
    writeln!(file, "{line}")
}

// ---------------------------------------------------------------------------
// Test-pattern source (pure Rust — no DXGI dependency)
// ---------------------------------------------------------------------------

struct TestPattern {
    width: u32,
    height: u32,
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
    frame: u64,
}

impl TestPattern {
    fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            y: vec![0; (width * height) as usize],
            u: vec![128; ((width / 2) * (height / 2)) as usize],
            v: vec![128; ((width / 2) * (height / 2)) as usize],
            frame: 0,
        }
    }

    /// Moving diagonal stripes + a bouncing box + a frame-counter stripe:
    /// enough motion to keep the encoder honest, cheap to compute.
    fn render(&mut self) {
        let (w, h) = (self.width as i32, self.height as i32);
        let t = self.frame as i32;
        let bar_x = (t * 7) % w;
        let box_x = ((w - 120) as f64 * (0.5 + 0.5 * (t as f64 * 0.013).sin())) as i32;
        let box_y = ((h - 120) as f64 * (0.5 + 0.5 * (t as f64 * 0.017).cos())) as i32;
        for yy in 0..h {
            let stripe = ((yy + t) / 24) % 2;
            let base = if stripe == 0 { 70 } else { 100 };

            for xx in 0..w {
                let mut lum = base as u16;
                if (xx - bar_x).abs() < 16 {
                    lum = 235;
                }
                if xx >= box_x && xx < box_x + 120 && yy >= box_y && yy < box_y + 120 {
                    lum = 16 + (((xx / 10) + (yy / 10)) % 2) as u16 * 200;
                }
                // Frame counter stripe: dark block whose width encodes the
                // low bits of the frame number.
                if yy < 24 && xx < (t % 64) * 8 {
                    lum = 250;
                }
                self.y[(yy * w + xx) as usize] = lum as u8;
            }
        }
        // Chroma: slowly shifting hue bands.
        for cy in 0..(h / 2) {
            for cx in 0..(w / 2) {
                let idx = (cy * (w / 2) + cx) as usize;
                self.u[idx] = (128 + ((cx + t / 2) / 16) % 32 - 16) as u8;
                self.v[idx] = (128 + ((cy + t / 2) / 16) % 32 - 16) as u8;
            }
        }
        self.frame += 1;
    }
}

impl openh264::formats::YUVSource for TestPattern {
    fn dimensions(&self) -> (usize, usize) {
        (self.width as usize, self.height as usize)
    }
    fn strides(&self) -> (usize, usize, usize) {
        (
            self.width as usize,
            self.width as usize / 2,
            self.width as usize / 2,
        )
    }
    fn y(&self) -> &[u8] {
        &self.y
    }
    fn u(&self) -> &[u8] {
        &self.u
    }
    fn v(&self) -> &[u8] {
        &self.v
    }
}

// ---------------------------------------------------------------------------
// Spike-only software encoder (VideoEncoder trait shape)
// ---------------------------------------------------------------------------

/// `// spike-only, replaced by codec-windows in M2 integration`
///
/// Mirrors `codec_windows::{VideoEncoder, CodecKind, EncodedPacket}`'s
/// shape: `kind()`, `encode(input, force_keyframe) -> packet`. Input here
/// is the CPU test pattern instead of a GPU texture handoff.
struct SpikeEncoder {
    encoder: openh264::encoder::Encoder,
}

struct SpikeEncodedPacket {
    /// Mirrors `codec_windows::EncodedPacket::timestamp_ns` (trait shape).
    #[allow(dead_code)]
    timestamp_ns: u64,
    is_keyframe: bool,
    bytes: Vec<u8>,
}

impl SpikeEncoder {
    fn new(width: u32, height: u32, fps: u32, bitrate_kbps: u32) -> Result<Self, String> {
        use openh264::encoder::{EncoderConfig, IntraFramePeriod};
        let config = EncoderConfig::new()
            .max_frame_rate(openh264::encoder::FrameRate::from_hz(fps.max(1) as f32))
            .bitrate(openh264::encoder::BitRate::from_bps(bitrate_kbps * 1000))
            .intra_frame_period(IntraFramePeriod::from_num_frames(60))
            .num_threads(0)
            .rate_control_mode(openh264::encoder::RateControlMode::Bitrate);
        let encoder = openh264::encoder::Encoder::with_api_config(
            openh264::OpenH264API::from_source(),
            config,
        )
        .map_err(|e| format!("openh264 encoder init: {e}"))?;
        let _ = (width, height); // resolution comes from the YUV source
        Ok(Self { encoder })
    }

    fn encode(
        &mut self,
        source: &TestPattern,
        timestamp_ns: u64,
        force_keyframe: bool,
    ) -> Result<SpikeEncodedPacket, String> {
        if force_keyframe {
            self.encoder.force_intra_frame();
        }
        let stream = self
            .encoder
            .encode(source)
            .map_err(|e| format!("openh264 encode: {e}"))?;
        let is_keyframe = matches!(
            stream.frame_type(),
            openh264::encoder::FrameType::I | openh264::encoder::FrameType::IDR
        );
        Ok(SpikeEncodedPacket {
            timestamp_ns,
            is_keyframe,
            bytes: stream.to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// Host-side input stub (no SendInput in this spike)
// ---------------------------------------------------------------------------

struct HostInputStub {
    last_reliable_seq: Option<u64>,
    last_fast_seq: Option<u64>,
    held_keys: Vec<u16>,
    held_buttons: Vec<MouseButton>,
    all_keys_up_events: Vec<AllKeysUpTrigger>,
    stale_moves_suppressed: u64,
    moves_applied: u64,
    latest_position: (u16, u16),
}

impl HostInputStub {
    fn new() -> Self {
        Self {
            last_reliable_seq: None,
            last_fast_seq: None,
            held_keys: Vec::new(),
            held_buttons: Vec::new(),
            all_keys_up_events: Vec::new(),
            stale_moves_suppressed: 0,
            moves_applied: 0,
            latest_position: (0, 0),
        }
    }

    fn on_input(&mut self, event: &InputEvent) {
        match event {
            InputEvent::MouseMove { seq, x, y } => {
                // Unordered channel: only the newest sequence wins; older
                // arrivals (reorder artifacts) are suppressed.
                if self.last_fast_seq.is_none_or(|last| *seq > last) {
                    self.last_fast_seq = Some(*seq);
                    self.latest_position = (*x, *y);
                    self.moves_applied += 1;
                } else {
                    self.stale_moves_suppressed += 1;
                }
            }
            InputEvent::Key {
                seq,
                scan_code,
                state,
                ..
            } => {
                self.on_reliable_seq(*seq);
                match state {
                    ButtonState::Pressed => {
                        if !self.held_keys.contains(scan_code) {
                            self.held_keys.push(*scan_code);
                        }
                    }
                    ButtonState::Released => self.held_keys.retain(|k| k != scan_code),
                }
            }
            InputEvent::MouseButton {
                seq, button, state, ..
            } => {
                self.on_reliable_seq(*seq);
                match state {
                    ButtonState::Pressed => {
                        if !self.held_buttons.contains(button) {
                            self.held_buttons.push(*button);
                        }
                    }
                    ButtonState::Released => self.held_buttons.retain(|b| b != button),
                }
            }
            InputEvent::Wheel { seq, .. } | InputEvent::Text { seq, .. } => {
                self.on_reliable_seq(*seq);
            }
            InputEvent::AllKeysUp { trigger } => {
                self.all_keys_up_events.push(*trigger);
                self.held_keys.clear();
                self.held_buttons.clear();
            }
        }
    }

    fn on_reliable_seq(&mut self, seq: u64) {
        if let Some(last) = self.last_reliable_seq
            && seq > last + 1
        {
            // Reliable-sequence gap: stuck-key safety fires before the new
            // event is applied (the wire.rs contract).
            self.all_keys_up_events.push(AllKeysUpTrigger::SequenceGap);
            self.held_keys.clear();
            self.held_buttons.clear();
            eprintln!("[input] sequence gap {last} -> {seq}: all keys released");
        }
        if self.last_reliable_seq.is_none_or(|last| seq > last) {
            self.last_reliable_seq = Some(seq);
        }
    }

    fn disconnect(&mut self) {
        self.all_keys_up_events.push(AllKeysUpTrigger::Disconnect);
        self.held_keys.clear();
        self.held_buttons.clear();
    }
}

// ---------------------------------------------------------------------------
// Summary output
// ---------------------------------------------------------------------------

fn write_summary(path: &Path, value: serde_json::Value) {
    if let Ok(json) = serde_json::to_string_pretty(&value) {
        let _ = fs::write(path, json + "\n");
    }
}

fn monotonic_ms() -> u64 {
    // Rig-local monotonic reference for wall-clock-ish reporting.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn rig_capabilities(controller: bool) -> Capabilities {
    Capabilities {
        encoders: if controller {
            vec![]
        } else {
            vec![EncoderCapabilities {
                kind: EncoderKind::Software,
                codec: protocol::capabilities::Codec::H264,
                max_width_px: 1920,
                max_height_px: 1080,
                max_fps: 60,
            }]
        },
        monitors: if controller {
            vec![]
        } else {
            vec![MonitorInfo {
                monitor_id: "\\\\.\\DISPLAY1".to_owned(),
                width_px: 1280,
                height_px: 720,
                is_primary: true,
            }]
        },
        max_bitrate_kbps: 50000,
        features: FeatureFlags::empty()
            .with(FeatureFlags::TRICKLE_ICE)
            .with(FeatureFlags::CURSOR_CHANNEL)
            .with(FeatureFlags::INPUT_FAST_CHANNEL),
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("spike_rig: {err}");
            eprintln!("usage: spike_rig --role host|controller --dir <signal-dir> [flags]");
            std::process::exit(2);
        }
    };
    fs::create_dir_all(&args.dir).expect("signal dir");
    let role = args.role;
    println!(
        "[rig] role={role} dir={} duration={:?} fps={} {}x{} bitrate={}kbps seed={} drop-fast={} reorder-fast={} drop-reliable-every={}",
        args.dir.display(),
        args.duration,
        args.fps,
        args.width,
        args.height,
        args.bitrate_kbps,
        args.seed,
        args.drop_fast_pct,
        args.reorder_fast_pct,
        args.drop_reliable_nth,
    );

    let sink: RigSink = match &args.metrics {
        Some(path) => RigSink::File(JsonlSink::open(path)),
        None => RigSink::Counting(CountingSink {
            records: std::sync::atomic::AtomicU64::new(0),
            session_start: Instant::now(),
        }),
    };
    // PerfSink takes &mut; guard it behind a mutex-free single-owner pass.
    let mut sink = sink;

    let is_host = role == "host";
    let (me, peer): (DeviceId, DeviceId) = if is_host {
        (HOST_DEVICE.to_owned(), CONTROLLER_DEVICE.to_owned())
    } else {
        (CONTROLLER_DEVICE.to_owned(), HOST_DEVICE.to_owned())
    };

    let (mut transport, connect_started) = if is_host {
        println!(
            "[rig] waiting for offer in {} ...",
            args.dir.join("offer.json").display()
        );
        let t0 = Instant::now();
        let mut t = WebrtcTransport::new(WebrtcTransportRole::Host).expect("host transport");
        let offer_json =
            wait_for_file(&args.dir.join("offer.json"), Duration::from_secs(120)).expect("offer");
        let env: SignalingEnvelope =
            serde_json::from_str(&offer_json).expect("offer envelope parses");
        env.check_version().expect("offer version");
        let SignalingBody::Offer { sdp } = env.body else {
            panic!("expected offer body");
        };
        println!(
            "[rig] offer received ({} bytes sdp) after {:?}",
            sdp.len(),
            t0.elapsed()
        );
        let t1 = Instant::now();
        let answer = t.compose_answer(&sdp).expect("compose_answer");
        println!("[rig] answer composed in {:?}", t1.elapsed());
        let answer_env = envelope(&me, &peer, SignalingBody::Answer { sdp: answer });
        write_json_atomic(
            &args.dir.join("answer.json"),
            &serde_json::to_string(&answer_env).expect("serializes"),
        )
        .expect("write answer");
        println!("[rig] answer written");
        (t, t0)
    } else {
        let t0 = Instant::now();
        let mut t =
            WebrtcTransport::new(WebrtcTransportRole::Controller).expect("controller transport");
        let t1 = Instant::now();
        let offer = t.compose_offer().expect("compose_offer");
        println!(
            "[rig] offer composed in {:?} ({} bytes)",
            t1.elapsed(),
            offer.len()
        );
        let offer_env = envelope(&me, &peer, SignalingBody::Offer { sdp: offer });
        write_json_atomic(
            &args.dir.join("offer.json"),
            &serde_json::to_string(&offer_env).expect("serializes"),
        )
        .expect("write offer");
        (t, t0)
    };

    // State for the run loop.
    let mut remote_candidates =
        CandidateFile::new(
            args.dir
                .join(if is_host { "c2h.jsonl" } else { "h2c.jsonl" }),
        );
    let my_candidates_out = args
        .dir
        .join(if is_host { "h2c.jsonl" } else { "c2h.jsonl" });

    let mut open_order: Vec<(&'static str, u64)> = Vec::new();
    let mut channels_open_at: Option<Instant> = None;
    let mut input = HostInputStub::new();
    let force_keyframe = Arc::new(AtomicBool::new(false));
    let mut controller_state = ControllerState::default();
    let mut decoder = if is_host {
        None
    } else {
        Some(
            openh264::decoder::Decoder::new()
                .map_err(|e| format!("openh264 decoder init: {e}"))
                .expect("decoder"),
        )
    };

    let mut encoder = if is_host {
        Some(
            SpikeEncoder::new(args.width, args.height, args.fps, args.bitrate_kbps)
                .expect("encoder"),
        )
    } else {
        None
    };
    let mut pattern = TestPattern::new(args.width, args.height);

    let mut chaos = ChaosInjector::new(args.seed, args.drop_fast_pct, args.reorder_fast_pct)
        .with_drop_every_nth(args.drop_reliable_nth);

    let session_start = Instant::now();
    let mut next_frame_tick = Instant::now();
    let mut next_stats_tick = Instant::now();
    let mut next_cursor_tick = Instant::now();
    let mut input_phase_started = false;
    let mut done_reason = String::new();
    let mut final_stats: Option<transport_webrtc::TransportStats> = None;

    let frame_period = Duration::from_nanos(1_000_000_000 / u64::from(args.fps.max(1)));

    loop {
        let now = Instant::now();

        // ---- signaling drains ----
        if !is_host && channels_open_at.is_none() {
            // Controller still needs the answer.
            if let Ok(json) = fs::read_to_string(args.dir.join("answer.json"))
                && !json.is_empty()
            {
                let env: SignalingEnvelope =
                    serde_json::from_str(&json).expect("answer envelope parses");
                env.check_version().expect("answer version");
                if let SignalingBody::Answer { sdp } = env.body {
                    println!("[rig] answer received ({} bytes sdp)", sdp.len());
                    transport.apply_answer(&sdp).expect("apply_answer");
                    let _ = fs::remove_file(args.dir.join("answer.json"));
                }
            }
        }
        for env in remote_candidates.drain() {
            if let SignalingBody::IceCandidate {
                candidate,
                sdp_mid,
                sdp_mline_index,
            } = env.body
            {
                transport
                    .add_remote_candidate(&candidate, sdp_mid.as_deref(), sdp_mline_index)
                    .expect("add_remote_candidate");
            }
        }

        // ---- transport events ----
        while let Some(event) = transport.poll() {
            match event {
                TransportEvent::IceCandidate {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                } => {
                    let env = envelope(
                        &me,
                        &peer,
                        SignalingBody::IceCandidate {
                            candidate: candidate.clone(),
                            sdp_mid: sdp_mid.clone(),
                            sdp_mline_index,
                        },
                    );
                    append_envelope(&my_candidates_out, &env).expect("append candidate");
                    if !is_host && open_order.is_empty() {
                        // Duplicate-signaling test: re-deliver the first
                        // candidate (the receiver must no-op it).
                        append_envelope(&my_candidates_out, &env).expect("append dup candidate");
                        println!(
                            "[rig] duplicate-signaling probe sent (same message_id re-delivered)"
                        );
                        let _ = candidate;
                    }
                }
                TransportEvent::ChannelOpened(channel) => {
                    open_order.push((channel.label(), monotonic_ms()));
                    println!("[rig] channel opened: {}", channel.label());
                }
                TransportEvent::ChannelsOpen => {
                    channels_open_at = Some(now);
                    println!(
                        "[rig] all channels open; connect time {:?} (signaling start -> open)",
                        connect_started.elapsed()
                    );
                    if !is_host {
                        transport
                            .send(
                                Channel::Control,
                                &protocol::wire::encode(&WireMessage::Hello {
                                    capabilities: rig_capabilities(false),
                                }),
                            )
                            .expect("hello send");
                    }
                }
                TransportEvent::Message(_channel, message) => {
                    if is_host {
                        match message {
                            WireMessage::Hello { .. } => {
                                transport
                                    .send(
                                        Channel::Control,
                                        &protocol::wire::encode(&WireMessage::HelloAck {
                                            capabilities: rig_capabilities(true),
                                        }),
                                    )
                                    .expect("helloack send");
                            }
                            WireMessage::KeyframeRequest => {
                                force_keyframe.store(true, Ordering::Release);
                                controller_state.keyframe_requests += 1;
                            }
                            WireMessage::Input(event) => input.on_input(&event),
                            WireMessage::Disconnect { reason } => {
                                println!("[rig] peer disconnected ({reason:?})");
                                done_reason = format!("peer_disconnect_{reason:?}");
                                input.disconnect();
                            }
                            _ => {}
                        }
                    } else if let WireMessage::HelloAck { .. } = message {
                        println!("[rig] hello-ack received (control channel round-trip)");
                    }
                }
                TransportEvent::ConnectionStateChanged(state) => {
                    println!("[rig] connection state: {state:?}");
                    if matches!(state, ConnectionState::Failed | ConnectionState::Closed)
                        && !done_reason.is_empty()
                    {
                        done_reason = format!("connection_{state:?}");
                    }
                    if matches!(
                        state,
                        ConnectionState::Failed
                            | ConnectionState::Closed
                            | ConnectionState::Disconnected
                    ) && channels_open_at.is_some()
                    {
                        if done_reason.is_empty() {
                            done_reason = format!("connection_{state:?}");
                        }
                        if is_host {
                            input.disconnect();
                        }
                    }
                }
                TransportEvent::Failed { reason } => {
                    eprintln!("[rig] transport failure: {reason}");
                    if done_reason.is_empty() {
                        done_reason = reason;
                    }
                }
                TransportEvent::LocalAnswer { .. } => {
                    // already written; never logged (invariant 6)
                }
            }
        }

        // ---- controller: receive + decode video ----
        if !is_host && channels_open_at.is_some() {
            while let Some(frame) = transport.poll_video() {
                controller_state.frames_received += 1;
                controller_state.bytes_received += frame.bytes.len() as u64;
                if let Some(id) = frame.frame_id {
                    if controller_state
                        .last_frame_id
                        .is_some_and(|last| id != last + 1)
                    {
                        controller_state.frame_id_gaps += 1;
                    }
                    controller_state.last_frame_id = Some(id);
                } else {
                    controller_state.frames_without_frame_id += 1;
                }
                if frame.missing_packets > 0 {
                    controller_state.frames_with_missing_packets += 1;
                }
                if let Some(decoder) = decoder.as_mut() {
                    match decoder.decode(&frame.bytes) {
                        Ok(Some(_yuv)) => controller_state.frames_decoded += 1,
                        Ok(None) => controller_state.decode_warmup_skips += 1,
                        Err(_) => controller_state.decode_errors += 1,
                    }
                }
                let at = sink.at_ns();
                sink.record(CounterRecord::FrameTiming(FrameTiming {
                    session_id: SESSION_ID.to_owned(),
                    origin: diagnostics::Origin::Controller,
                    frame_id: frame.frame_id.unwrap_or(u64::MAX),
                    capture_ns: None,
                    encode_submit_ns: None,
                    encode_done_ns: None,
                    send_ns: None,
                    recv_ns: Some(at),
                    decode_done_ns: Some(at),
                    present_ns: Some(at),
                }));
                // Video loss visible at the transport layer → ask for a
                // keyframe over the control channel.
                if frame.missing_packets > 0 || frame.frame_id.is_none() {
                    let _ = transport.send(
                        Channel::Control,
                        &protocol::wire::encode(&WireMessage::KeyframeRequest),
                    );
                }
            }
        }

        // ---- host: encode + send video ----
        if is_host && channels_open_at.is_some() && now >= next_frame_tick && done_reason.is_empty()
        {
            pattern.render();
            let capture_ns = sink.at_ns();
            let force = force_keyframe.swap(false, Ordering::AcqRel);
            if let Some(encoder) = encoder.as_mut() {
                let encode_started = Instant::now();
                match encoder.encode(&pattern, capture_ns, force) {
                    Ok(packet) => {
                        let encode_done = sink.at_ns();
                        transport
                            .send_video(VideoFrame {
                                frame_id: pattern.frame,
                                timestamp_ns: capture_ns,
                                is_keyframe: packet.is_keyframe,
                                bytes: packet.bytes,
                            })
                            .expect("send_video");
                        let send_ns = sink.at_ns();
                        controller_state.frames_encoded += 1;
                        if packet.is_keyframe {
                            controller_state.keyframes_sent += 1;
                        }
                        let _ = encode_started;
                        sink.record(CounterRecord::FrameTiming(FrameTiming {
                            session_id: SESSION_ID.to_owned(),
                            origin: diagnostics::Origin::Host,
                            frame_id: pattern.frame,
                            capture_ns: Some(capture_ns),
                            encode_submit_ns: Some(capture_ns),
                            encode_done_ns: Some(encode_done),
                            send_ns: Some(send_ns),
                            recv_ns: None,
                            decode_done_ns: None,
                            present_ns: None,
                        }));
                    }
                    Err(err) => eprintln!("[encode] {err}"),
                }
            }
            next_frame_tick += frame_period;
            if next_frame_tick < now {
                // Encoder fell behind by more than one tick: drop obsolete
                // ticks (invariant 3) and resync.
                controller_state.encode_ticks_skipped += 1;
                next_frame_tick = now + frame_period;
            }
        }

        // ---- host: cursor state (latest-state channel exercise) ----
        if is_host && channels_open_at.is_some() && now >= next_cursor_tick {
            let seq = pattern.frame;
            let (x, y) = (((seq * 11) % 65536) as u16, ((seq * 17) % 65536) as u16);
            let _ = transport.send(
                Channel::Cursor,
                &protocol::wire::encode(&WireMessage::Cursor(CursorMessage::Position {
                    seq,
                    x,
                    y,
                })),
            );
            controller_state.cursor_positions_sent += 1;
            next_cursor_tick = now + Duration::from_millis(100);
        }

        // ---- controller: input injection with chaos ----
        if !is_host
            && channels_open_at.is_some()
            && !input_phase_started
            && session_start.elapsed() > Duration::from_secs(5)
        {
            input_phase_started = true;
            println!("[rig] input injection phase starting");
        }
        if !is_host && input_phase_started && controller_state.moves_sent < args.mouse_moves {
            let emit = |transport: &mut WebrtcTransport, chaos: &mut ChaosInjector, seq: u64| {
                let msg = WireMessage::Input(InputEvent::MouseMove {
                    seq,
                    x: ((seq * 31) % 65536) as u16,
                    y: ((seq * 37) % 65536) as u16,
                });
                for bytes in chaos.transform(protocol::wire::encode(&msg)) {
                    let _ = transport.send(Channel::InputFast, &bytes);
                }
            };
            for _ in 0..30 {
                let seq = controller_state.moves_sent + 1;
                emit(&mut transport, &mut chaos, seq);
                controller_state.moves_sent = seq;
            }
            // Every 30 moves, exercise the reliable path (keys/wheel) so the
            // drop_every_nth gap injection can fire there.
            let reliable_seq = controller_state.reliable_sent + 1;
            let msg = if reliable_seq % 3 == 0 {
                WireMessage::Input(InputEvent::Wheel {
                    seq: reliable_seq,
                    delta_v: -120,
                    delta_h: 0,
                })
            } else {
                WireMessage::Input(InputEvent::Key {
                    seq: reliable_seq,
                    scan_code: 0x1E,
                    extended: false,
                    state: if reliable_seq % 2 == 0 {
                        ButtonState::Pressed
                    } else {
                        ButtonState::Released
                    },
                })
            };
            for bytes in chaos.transform(protocol::wire::encode(&msg)) {
                if let Err(err) = transport.send(Channel::InputReliable, &bytes) {
                    eprintln!("[input] reliable send rejected: {err}");
                    controller_state.reliable_send_errors += 1;
                }
            }
            controller_state.reliable_sent = reliable_seq;
        }
        if !is_host
            && input_phase_started
            && controller_state.moves_sent >= args.mouse_moves
            && !controller_state.chaos_flushed
        {
            // Flush any message still held in the reorder window.
            let pending = chaos.flush();
            controller_state.chaos_flush_pending = pending.len() as u64;
            for bytes in pending {
                if matches!(
                    protocol::wire::decode(&bytes),
                    Ok(WireMessage::Input(InputEvent::MouseMove { .. }))
                ) {
                    let _ = transport.send(Channel::InputFast, &bytes);
                } else {
                    let _ = transport.send(Channel::InputReliable, &bytes);
                }
            }
            controller_state.chaos_flushed = true;
            println!(
                "[rig] injection done: dropped={} reordered={} (flushed {} held)",
                chaos.dropped, chaos.reordered, controller_state.chaos_flush_pending
            );
        }

        // ---- stats + queue samples at >=1 Hz ----
        if channels_open_at.is_some() && now >= next_stats_tick {
            if let Ok(stats) = transport.stats() {
                let at = sink.at_ns();
                sink.record(CounterRecord::LinkSample(LinkSample {
                    session_id: SESSION_ID.to_owned(),
                    send_bitrate_kbps: stats.send_bitrate_kbps.map(|v| v as u32),
                    recv_bitrate_kbps: stats.recv_bitrate_kbps.map(|v| v as u32),
                    rtt_ms: stats.rtt_ms.map(|v| v as u32),
                    loss_percent: stats.loss_percent.map(|v| v as f32),
                    at_ns: at,
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
                    sink.record(CounterRecord::QueueSample(QueueSample {
                        session_id: SESSION_ID.to_owned(),
                        queue: kind,
                        depth: stats.channel_queue.depth[index],
                        capacity: stats.channel_queue.capacity[index],
                        high_water: stats.channel_queue.high_water[index],
                        dropped: stats.channel_queue.dropped[index],
                        replaced: stats.channel_queue.replaced[index],
                        at_ns: at,
                    }));
                }
                final_stats = Some(stats);
                next_stats_tick = now + Duration::from_secs(1);
            } else {
                next_stats_tick = now + Duration::from_secs(1);
            }
        }

        // ---- termination ----
        if done_reason.is_empty()
            && channels_open_at.is_some()
            && session_start.elapsed() >= args.duration
        {
            done_reason = "duration_elapsed".to_owned();
            if !is_host {
                let _ = transport.send(
                    Channel::Control,
                    &protocol::wire::encode(&WireMessage::Disconnect {
                        reason: ControlDisconnectReason::User,
                    }),
                );
                println!("[rig] disconnect sent; draining 2 s");
                std::thread::sleep(Duration::from_secs(2));
            }
        }
        if !done_reason.is_empty() {
            // Give the peer's final events a moment to land.
            std::thread::sleep(Duration::from_millis(if is_host { 1500 } else { 100 }));
            let _ = &mut decoder;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    // ---- summary ----
    let connect_ms = channels_open_at
        .map(|at| at.duration_since(connect_started).as_millis() as u64)
        .unwrap_or(0);
    let elapsed_s = session_start.elapsed().as_secs_f64();
    let mut summary = serde_json::json!({
        "role": role,
        "session_id": SESSION_ID,
        "connect_ms": connect_ms,
        "elapsed_s": elapsed_s,
        "done_reason": done_reason,
        "channel_open_order": open_order.iter().map(|(l, t)| serde_json::json!({"label": l, "at_ms": t})).collect::<Vec<_>>(),
        "mouse": {
            "moves_sent": controller_state.moves_sent,
            "moves_applied": input.moves_applied,
            "stale_suppressed": input.stale_moves_suppressed,
            "final_position": input.latest_position,
        },
        "reliable_input": {
            "sent": controller_state.reliable_sent,
            "send_errors": controller_state.reliable_send_errors,
            "gap_all_keys_up": input.all_keys_up_events.iter().filter(|t| **t == AllKeysUpTrigger::SequenceGap).count(),
            "disconnect_all_keys_up": input.all_keys_up_events.iter().filter(|t| **t == AllKeysUpTrigger::Disconnect).count(),
            "held_keys_at_end": input.held_keys.len(),
        },
        "chaos": {
            "dropped": chaos.dropped,
            "reordered": chaos.reordered,
            "flushed_pending": controller_state.chaos_flush_pending,
            "seed": args.seed,
        },
    });
    if is_host {
        let fps_avg = controller_state.frames_encoded as f64 / elapsed_s.max(0.001);
        summary["video"] = serde_json::json!({
            "frames_encoded": controller_state.frames_encoded,
            "keyframes_sent": controller_state.keyframes_sent,
            "encode_ticks_skipped": controller_state.encode_ticks_skipped,
            "keyframe_requests_received": controller_state.keyframe_requests,
            "fps_avg": fps_avg,
            "fps_target": args.fps,
        });
    } else {
        let fps_avg = controller_state.frames_decoded as f64 / elapsed_s.max(0.001);
        summary["video"] = serde_json::json!({
            "frames_received": controller_state.frames_received,
            "frames_decoded": controller_state.frames_decoded,
            "decode_errors": controller_state.decode_errors,
            "decode_warmup_skips": controller_state.decode_warmup_skips,
            "bytes_received": controller_state.bytes_received,
            "frames_without_frame_id": controller_state.frames_without_frame_id,
            "frame_id_gaps": controller_state.frame_id_gaps,
            "frames_with_missing_packets": controller_state.frames_with_missing_packets,
            "last_frame_id": controller_state.last_frame_id,
            "keyframe_requests_sent": controller_state.keyframe_requests,
            "fps_avg": fps_avg,
            "fps_target": args.fps,
        });
    }
    if let Some(stats) = final_stats {
        summary["transport_stats"] = serde_json::json!({
            "rtt_ms": stats.rtt_ms,
            "send_bitrate_kbps": stats.send_bitrate_kbps,
            "recv_bitrate_kbps": stats.recv_bitrate_kbps,
            "loss_percent": stats.loss_percent,
            "jitter_ms": stats.jitter_ms,
            "packets_sent": stats.packets_sent,
            "packets_received": stats.packets_received,
            "packets_lost": stats.packets_lost,
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
    println!(
        "[rig] summary: {}",
        serde_json::to_string_pretty(&summary).unwrap_or_default()
    );
    write_summary(&args.summary, summary);

    let t0 = Instant::now();
    transport.close();
    println!("[rig] transport closed in {:?}", t0.elapsed());
}

#[derive(Default)]
struct ControllerState {
    moves_sent: u64,
    reliable_sent: u64,
    reliable_send_errors: u64,
    chaos_flushed: bool,
    chaos_flush_pending: u64,
    frames_encoded: u64,
    keyframes_sent: u64,
    encode_ticks_skipped: u64,
    keyframe_requests: u64,
    frames_received: u64,
    frames_decoded: u64,
    decode_errors: u64,
    decode_warmup_skips: u64,
    bytes_received: u64,
    frames_without_frame_id: u64,
    frame_id_gaps: u64,
    frames_with_missing_packets: u64,
    last_frame_id: Option<u64>,
    cursor_positions_sent: u64,
}
