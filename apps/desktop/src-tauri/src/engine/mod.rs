//! The engine: the composition the Tauri commands are a thin veneer over
//! (RD-011/RD-012). One instance drives both role machines of a
//! `node-runtime::Node` on a dedicated loop thread (the m2_rig cadence),
//! owns the pipelines (host capture→encode, controller decode→present with
//! the native viewer window), the host input pump, and the diagnostics
//! aggregation. The UI layer (and the E2E harness) talks to it exclusively
//! through [`EngineCmd`]s in and [`EngineEvent`]s out — the same typed
//! surface the Tauri commands expose — plus a pull status snapshot.
//!
//! This module is tauri-free by design (reused by `e2e_child` and tests).
//!
//! Invariants honored: no frame bytes in events/commands (only names, ids,
//! counters); TURN never configured; every queue bounded with a counted
//! drop policy; SDP secrets and input payloads never logged.

pub mod controller;
pub mod diag;
pub mod displays;
pub mod host;
pub mod ids;
pub mod observer;
pub mod pool;
pub mod quality;
pub mod viewer;

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use diagnostics::{CounterRecord, FrameTiming, LinkSample, Origin, PerfSink};
use frame_surface::GpuDevice;
use input_windows::{InputError, InputSink};
use node_runtime::Clock as _;
use node_runtime::clock::MonotonicClock;
use node_runtime::input::InputPump;
use node_runtime::metrics::SessionSlot;
use node_runtime::node::Node;
use node_runtime::signaling::SignalingIo;
use node_runtime::timers::MachineKind;
use protocol::capabilities::{
    Capabilities, EncoderCapabilities, EncoderKind, FeatureFlags, MonitorInfo,
};
use protocol::wire::{AllKeysUpTrigger, InputEvent, QualityPreset, WireMessage};
use render_windows::ScaleMode;
use session::{ControllerState, HostState, SessionConfig};
use transport_webrtc::{Channel, VideoFrame, WebrtcTransport, WebrtcTransportRole};

pub use diag::DiagSnapshot;
pub use quality::{plan_for, preset_from_name, preset_name};

/// Copy shown when a direct connection fails (M5 documents the
/// expected-failure classes; TURN is explicitly deferred).
pub const DIRECT_ONLY_HINT: &str = "This build supports direct connections only (no relay). \
     If both machines are behind symmetric NAT or UDP is blocked, the connection cannot be \
     established until TURN is added (deferred by the MVP plan).";

/// Bounded command/event queues (invariant 3).
const CMD_QUEUE: usize = 64;
const EVENT_QUEUE: usize = 512;

// ---------------------------------------------------------------------------
// Commands / events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum EngineCmd {
    HostStart,
    HostStop,
    ControllerStart,
    ControllerStop,
    Connect { code: String },
    CancelConnect,
    Disconnect,
    ConsentAccept,
    ConsentReject,
    SetQuality(QualityPreset),
    SelectMonitor { monitor_id: String },
    ViewerScale(ScaleMode),
    ViewerFullscreen,
    Shutdown,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineEvent {
    StateChanged {
        machine: String,
        state: String,
        session_id: Option<String>,
    },
    ConsentRequested {
        controller_device_id: String,
        session_id: String,
    },
    SessionEstablished {
        session_id: String,
        peer: Option<String>,
    },
    SessionEnded {
        cause: String,
        code: String,
        message: String,
        hint: Option<String>,
    },
    PeerOnline {
        device_id: String,
    },
    PeerOffline {
        device_id: String,
    },
    HostCaps {
        monitors: Vec<crate::ipc::MonitorDto>,
    },
    PeerCaps {
        monitors: Vec<crate::ipc::MonitorDto>,
    },
    Diagnostics {
        snapshot: DiagSnapshot,
    },
    Error {
        code: String,
        message: String,
        hint: Option<String>,
    },
    Info {
        message: String,
    },
}

/// User-facing copy for each `DisconnectCause` (mirrored on the TS side;
/// both directions pinned by tests).
pub fn disconnect_copy(cause: &session::DisconnectCause) -> (String, String, Option<String>) {
    use session::DisconnectCause::*;
    match cause {
        User => (
            "user_disconnect".into(),
            "You ended the session.".into(),
            None,
        ),
        Peer => (
            "peer_disconnect".into(),
            "The other machine ended the session.".into(),
            None,
        ),
        Timeout => (
            "timeout".into(),
            "The session timed out before the direct connection opened.".into(),
            Some(DIRECT_ONLY_HINT.into()),
        ),
        Rejected(reason) => (
            "rejected".into(),
            format!("The host declined the connection ({reason:?})."),
            None,
        ),
        Canceled => (
            "canceled".into(),
            "The connection attempt was canceled.".into(),
            None,
        ),
        Collision => (
            "collision".into(),
            "Both machines tried to connect at once; the tie-break canceled this side.".into(),
            None,
        ),
        TransportError => (
            "transport_error".into(),
            "The direct connection failed or dropped.".into(),
            Some(DIRECT_ONLY_HINT.into()),
        ),
    }
}

// ---------------------------------------------------------------------------
// Host input sink slot (product: SendInput; E2E: recording)
// ---------------------------------------------------------------------------

/// Trait-object forwarder (orphan rules; the rig's `SinkBox`).
pub struct SinkBox(pub Box<dyn InputSink>);

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

/// Recording sink (E2E on one machine: scripted input must not fight the
/// operator — the same default the m2_rig uses).
#[derive(Default)]
pub struct RecordingSink {
    held: usize,
    applied: u64,
    releases: u64,
}

impl InputSink for RecordingSink {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        use protocol::wire::ButtonState;
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

/// Shared real sink so the engine can `set_monitor_rect` /
/// `refresh_display_metrics` while the pump holds the trait object.
pub struct SharedSendSink(pub Arc<Mutex<input_windows::SendInputSink>>);

impl InputSink for SharedSendSink {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        self.0.lock().expect("send sink").inject(event)
    }
    fn all_keys_up(&mut self) -> Result<(), InputError> {
        self.0.lock().expect("send sink").all_keys_up()
    }
    fn held_count(&self) -> usize {
        self.0.lock().expect("send sink").held_count()
    }
    fn release_all(&mut self, trigger: AllKeysUpTrigger) -> input_windows::ReleaseOutcome {
        self.0.lock().expect("send sink").release_all(trigger)
    }
}

// ---------------------------------------------------------------------------
// Config / shared status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct EngineCounters {
    pub input_sent_fast: u64,
    pub input_sent_reliable: u64,
    pub input_all_keys_up_sent: u64,
    pub frames_captured: u64,
    pub frames_encoded: u64,
    pub frames_presented: u64,
    pub keyframes: u64,
    pub monitor_switches: u64,
    pub encoder_rebuilds: u64,
}

/// Pull-based snapshot (authoritative; events are push conveniences).
#[derive(Debug, Clone, serde::Serialize)]
pub struct EngineStatus {
    pub device_id: String,
    pub host_state: String,
    pub controller_state: String,
    pub session_id: Option<String>,
    pub viewer_created: bool,
    pub viewer_hwnd: u64,
    pub viewer_fullscreen: bool,
    pub viewer_focused: bool,
    pub viewer_scale: String,
    pub host_monitors: Vec<crate::ipc::MonitorDto>,
    pub peer_monitors: Vec<crate::ipc::MonitorDto>,
    pub active_monitor: Option<String>,
    pub quality: String,
    pub encoder: Option<String>,
    pub counters: EngineCounters,
    pub input: diag::InputStat,
}

#[derive(Default)]
struct SharedInner {
    device_id: String,
    host_state: String,
    controller_state: String,
    session_id: Option<String>,
    current_peer: Option<String>,
    pending_consent: Option<String>,
    host_monitors: Vec<crate::ipc::MonitorDto>,
    peer_monitors: Vec<crate::ipc::MonitorDto>,
    active_monitor: Option<String>,
    quality: String,
    encoder: Option<String>,
    viewer_scale: String,
}

/// Status shared between the engine loop and external readers (the
/// observer runs on the same thread as the loop, so there is no write
/// contention by construction).
pub struct EngineShared {
    inner: Mutex<SharedInner>,
}

impl EngineShared {
    fn new(device_id: &str, initial_quality: &str, initial_scale: &str) -> Self {
        Self {
            inner: Mutex::new(SharedInner {
                device_id: device_id.to_owned(),
                host_state: "Idle".into(),
                controller_state: "Idle".into(),
                quality: initial_quality.to_owned(),
                viewer_scale: initial_scale.to_owned(),
                ..SharedInner::default()
            }),
        }
    }

    pub fn status(
        &self,
        counters: EngineCounters,
        input: diag::InputStat,
        viewer: ViewerFacts,
    ) -> EngineStatus {
        let inner = self.inner.lock().expect("engine shared");
        EngineStatus {
            device_id: inner.device_id.clone(),
            host_state: inner.host_state.clone(),
            controller_state: inner.controller_state.clone(),
            session_id: inner.session_id.clone(),
            viewer_created: viewer.created,
            viewer_hwnd: viewer.hwnd,
            viewer_fullscreen: viewer.fullscreen,
            viewer_focused: viewer.focused,
            viewer_scale: inner.viewer_scale.clone(),
            host_monitors: inner.host_monitors.clone(),
            peer_monitors: inner.peer_monitors.clone(),
            active_monitor: inner.active_monitor.clone(),
            quality: inner.quality.clone(),
            encoder: inner.encoder.clone(),
            counters,
            input,
        }
    }

    fn set_state(&self, machine: MachineKind, state: &str) {
        let mut inner = self.inner.lock().expect("engine shared");
        match machine {
            MachineKind::Host => inner.host_state = state.to_owned(),
            MachineKind::Controller => inner.controller_state = state.to_owned(),
        }
        // The consent prompt exists only in `ConsentPrompted`; leaving the
        // state resolves any pending prompt (accepted, rejected, canceled,
        // timed out).
        if inner.host_state != "ConsentPrompted" {
            inner.pending_consent = None;
        }
    }

    fn state_is(&self, machine: MachineKind, name: &str) -> bool {
        let inner = self.inner.lock().expect("engine shared");
        match machine {
            MachineKind::Host => inner.host_state == name,
            MachineKind::Controller => inner.controller_state == name,
        }
    }

    fn set_session(&self, id: Option<String>) {
        self.inner.lock().expect("engine shared").session_id = id;
    }

    fn set_current_peer(&self, peer: Option<String>) {
        self.inner.lock().expect("engine shared").current_peer = peer;
    }

    fn current_peer(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("engine shared")
            .current_peer
            .clone()
    }

    fn current_session_id(&self) -> Option<String> {
        self.inner.lock().expect("engine shared").session_id.clone()
    }

    fn set_pending_consent(&self, controller: Option<String>) {
        self.inner.lock().expect("engine shared").pending_consent = controller;
    }

    fn clear_pending_consent(&self) {
        self.inner.lock().expect("engine shared").pending_consent = None;
    }

    fn pending_consent(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("engine shared")
            .pending_consent
            .clone()
    }

    fn set_host_monitors(&self, monitors: Vec<crate::ipc::MonitorDto>) {
        self.inner.lock().expect("engine shared").host_monitors = monitors;
    }

    fn set_peer_monitors(&self, monitors: Vec<crate::ipc::MonitorDto>) {
        self.inner.lock().expect("engine shared").peer_monitors = monitors;
    }

    fn set_quality(&self, preset: QualityPreset) {
        self.inner.lock().expect("engine shared").quality = preset_name(preset).to_owned();
    }

    fn quality_name(&self) -> String {
        self.inner.lock().expect("engine shared").quality.clone()
    }

    fn viewer_scale_name(&self) -> String {
        self.inner
            .lock()
            .expect("engine shared")
            .viewer_scale
            .clone()
    }

    fn set_active_monitor(&self, monitor: Option<String>) {
        self.inner.lock().expect("engine shared").active_monitor = monitor;
    }

    fn set_encoder(&self, describe: Option<String>) {
        self.inner.lock().expect("engine shared").encoder = describe;
    }

    fn set_viewer_scale(&self, scale: String) {
        self.inner.lock().expect("engine shared").viewer_scale = scale;
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ViewerFacts {
    pub created: bool,
    pub hwnd: u64,
    pub fullscreen: bool,
    pub focused: bool,
}

pub struct EngineConfig {
    pub device_id: String,
    pub signaling: Box<dyn SignalingIo>,
    /// Spawn real GPU pipelines (product/E2E) vs track state-machine
    /// effects only (unit tests on machines without a display).
    pub real_pipelines: bool,
    /// Host injects through the real `SendInputSink` (product) vs a
    /// recording sink (single-machine E2E safety, rig default).
    pub real_input: bool,
    /// Re-register a role after its session ends (product UX; the rig's
    /// scripted recovery). Explicit Stop disables it.
    pub auto_reonline: bool,
    pub metrics_dir: Option<PathBuf>,
    pub status_file: Option<PathBuf>,
    pub viewer_title: String,
    pub initial_quality: QualityPreset,
    pub initial_scale: ScaleMode,
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

pub struct EngineHandle {
    tx: SyncSender<EngineCmd>,
    shared: Arc<EngineShared>,
    join: Option<std::thread::JoinHandle<()>>,
    counters: Arc<Mutex<EngineCounters>>,
    viewer: Arc<Mutex<ViewerFacts>>,
    input: Arc<Mutex<diag::InputStat>>,
}

impl EngineHandle {
    /// Send one command (bounded; never blocks the caller).
    pub fn send(&self, cmd: EngineCmd) -> Result<(), String> {
        self.tx.try_send(cmd).map_err(|err| match err {
            TrySendError::Full(_) => "engine command queue full".to_owned(),
            TrySendError::Disconnected(_) => "engine stopped".to_owned(),
        })
    }

    /// Authoritative status snapshot (pull counterpart of the events).
    pub fn status(&self) -> EngineStatus {
        let counters = *self.counters.lock().expect("engine counters");
        let viewer = *self.viewer.lock().expect("engine viewer");
        let input = *self.input.lock().expect("engine input");
        self.shared.status(counters, input, viewer)
    }

    /// Stop the engine and wait for its thread.
    pub fn shutdown(mut self) {
        let _ = self.tx.try_send(EngineCmd::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Spawn the engine thread. Returns the command handle and the event
/// receiver (single consumer: the Tauri forwarder or the E2E harness).
pub fn spawn(cfg: EngineConfig) -> (EngineHandle, Receiver<EngineEvent>) {
    let (cmd_tx, cmd_rx) = std::sync::mpsc::sync_channel::<EngineCmd>(CMD_QUEUE);
    let (event_tx, event_rx) = std::sync::mpsc::sync_channel::<EngineEvent>(EVENT_QUEUE);
    let shared = Arc::new(EngineShared::new(
        &cfg.device_id,
        preset_name(cfg.initial_quality),
        scale_name(cfg.initial_scale),
    ));
    let counters = Arc::new(Mutex::new(EngineCounters::default()));
    let viewer = Arc::new(Mutex::new(ViewerFacts::default()));
    let input = Arc::new(Mutex::new(diag::InputStat::default()));
    let join = std::thread::Builder::new()
        .name("engine".into())
        .spawn({
            let shared = Arc::clone(&shared);
            let counters = Arc::clone(&counters);
            let viewer = Arc::clone(&viewer);
            let input = Arc::clone(&input);
            move || run(cfg, cmd_rx, event_tx, shared, counters, viewer, input)
        })
        .expect("spawn engine thread");
    (
        EngineHandle {
            tx: cmd_tx,
            shared,
            join: Some(join),
            counters,
            viewer,
            input,
        },
        event_rx,
    )
}

fn scale_name(mode: ScaleMode) -> &'static str {
    match mode {
        ScaleMode::Fit => "fit",
        ScaleMode::OneToOne => "one_to_one",
    }
}

pub fn scale_from_name(name: &str) -> Option<ScaleMode> {
    match name {
        "fit" => Some(ScaleMode::Fit),
        "one_to_one" => Some(ScaleMode::OneToOne),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

struct Engine {
    real_input: bool,
    auto_reonline: bool,
    status_file: Option<PathBuf>,
    viewer_title: String,
    initial_quality: QualityPreset,
    node: Node,
    clock: Arc<MonotonicClock>,
    session_slot: Arc<SessionSlot>,
    agg: Arc<diag::DiagAgg>,
    report: Option<node_runtime::metrics::JsonlReport>,
    device: Option<GpuDevice>,
    _mf: Option<codec_windows::MfRuntime>,
    resource_stop: Option<Arc<std::sync::atomic::AtomicBool>>,
    resource_join: Option<std::thread::JoinHandle<()>>,
    pool: pool::CodecPool,
    observer: observer::EngineObserver,
    events: SyncSender<EngineEvent>,
    input_pump: Option<Arc<Mutex<InputPump<SinkBox>>>>,
    send_sink: Option<Arc<Mutex<input_windows::SendInputSink>>>,
    host_pipeline: Option<host::HostPipeline>,
    controller_pipeline: Option<controller::ControllerPipeline>,
    finished_host_counters: Vec<Arc<host::HostPipeCounters>>,
    finished_ctrl_counters: Vec<Arc<controller::ControllerPipeCounters>>,
    transport_owner: MachineKind,
    host_started: bool,
    controller_started: bool,
    host_reonline_at: Option<Instant>,
    ctrl_reonline_at: Option<Instant>,
    session_end_handled: bool,
    selected_monitor: Option<String>,
    selected_plan: Option<quality::QualityPlan>,
    fast_seq: u64,
    reliable_seq: u64,
    all_keys_up_sent: u64,
    last_stats_tick: Instant,
    last_diag_tick: Instant,
    last_status_tick: Instant,
    last_keyframe_request: Instant,
    clock_origin: (Instant, u64),
    caps_cache: Option<Capabilities>,
}

fn run(
    cfg: EngineConfig,
    cmd_rx: Receiver<EngineCmd>,
    event_tx: SyncSender<EngineEvent>,
    shared: Arc<EngineShared>,
    counters_arc: Arc<Mutex<EngineCounters>>,
    viewer_arc: Arc<Mutex<ViewerFacts>>,
    input_arc: Arc<Mutex<diag::InputStat>>,
) {
    let device_id = cfg.device_id.clone();
    let clock = Arc::new(MonotonicClock::new());
    let agg = Arc::new(diag::DiagAgg::new());
    let session_slot = Arc::new(SessionSlot::new(&format!("{device_id}-pre-session")));
    let report = cfg.metrics_dir.as_ref().map(|dir| {
        node_runtime::metrics::JsonlReport::create(dir, &format!("m4-app-{device_id}"))
            .expect("metrics report")
    });

    let EngineConfig {
        device_id: _,
        signaling,
        real_pipelines,
        real_input,
        auto_reonline,
        metrics_dir: _,
        status_file,
        viewer_title,
        initial_quality,
        initial_scale: _,
    } = cfg;
    let node = Node::new(
        &device_id,
        SessionConfig::default(),
        clock.clone(),
        signaling,
    );

    // GPU + MF are needed only by real pipelines.
    let mut device = None;
    let mut mf = None;
    let mut resource_stop = None;
    let mut resource_join = None;
    if real_pipelines {
        match codec_windows::MfRuntime::new() {
            Ok(runtime) => mf = Some(runtime),
            Err(err) => {
                let _ = event_tx.try_send(EngineEvent::Error {
                    code: "mf_init_failed".into(),
                    message: format!("Media Foundation init failed: {err}"),
                    hint: None,
                });
            }
        }
        match frame_surface::GpuDevice::create_hardware() {
            Ok(gpu) => device = Some(gpu),
            Err(err) => {
                let _ = event_tx.try_send(EngineEvent::Error {
                    code: "gpu_init_failed".into(),
                    message: format!("D3D11 device init failed: {err}"),
                    hint: None,
                });
            }
        }
        if device.is_some() {
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let join = node_runtime::metrics::spawn_resource_sampler(
                Box::new(diag::TeeSink::new(
                    jsonl_or_null(&report, &session_slot),
                    Arc::clone(&agg),
                )),
                Arc::clone(&session_slot),
                Origin::Host,
                Arc::clone(&stop),
                Arc::new({
                    let clock = Arc::clone(&clock);
                    move || clock.now_ns()
                }),
            );
            resource_stop = Some(stop);
            resource_join = Some(join);
        }
    }

    let flags = Arc::new(Mutex::new(observer::ObserverFlags::default()));
    let observer = observer::EngineObserver {
        events: event_tx.clone(),
        flags: Arc::clone(&flags),
        shared: Arc::clone(&shared),
        input_pump: None,
        cursor_slot: None,
    };

    let mut engine = Engine {
        real_input,
        auto_reonline,
        status_file,
        viewer_title,
        initial_quality,
        node,
        clock,
        session_slot,
        agg,
        report,
        device,
        _mf: mf,
        resource_stop,
        resource_join,
        pool: pool::CodecPool::new(),
        observer,
        events: event_tx,
        input_pump: None,
        send_sink: None,
        host_pipeline: None,
        controller_pipeline: None,
        finished_host_counters: Vec::new(),
        finished_ctrl_counters: Vec::new(),
        transport_owner: MachineKind::Controller,
        host_started: false,
        controller_started: false,
        host_reonline_at: None,
        ctrl_reonline_at: None,
        session_end_handled: false,
        selected_monitor: None,
        selected_plan: None,
        fast_seq: 0,
        reliable_seq: 0,
        all_keys_up_sent: 0,
        last_stats_tick: Instant::now(),
        last_diag_tick: Instant::now(),
        last_status_tick: Instant::now(),
        last_keyframe_request: Instant::now() - Duration::from_secs(10),
        clock_origin: (Instant::now(), 0),
        caps_cache: None,
    };
    engine.clock_origin = (Instant::now(), engine.clock.now_ns());

    loop {
        // ---- commands (bounded batch) ----
        let mut shutdown = false;
        for _ in 0..32 {
            match cmd_rx.try_recv() {
                Ok(cmd) => {
                    if matches!(cmd, EngineCmd::Shutdown) {
                        shutdown = true;
                        break;
                    }
                    engine.handle_cmd(cmd);
                }
                Err(_) => break,
            }
        }
        if shutdown {
            engine.teardown();
            return;
        }

        // ---- node pump ----
        engine.node.pump(&mut engine.observer);
        engine.node.poll_transport(&mut engine.observer);
        shared.set_session(engine.node.current_session_id());

        // ---- flags → pipelines / lifecycle ----
        engine.apply_flags();

        // ---- data planes ----
        engine.drain_host_output();
        engine.drain_controller_input();
        engine.drain_viewer_input();

        // ---- periodic ----
        let now = Instant::now();
        if now.duration_since(engine.last_stats_tick) >= Duration::from_secs(1) {
            engine.last_stats_tick = now;
            engine.sample_link_stats();
        }
        if now.duration_since(engine.last_diag_tick) >= Duration::from_secs(1) {
            engine.last_diag_tick = now;
            engine.sync_encoder_describe();
            engine.agg.set_input(engine.input_stat_now());
            let snapshot = engine.agg.snapshot(engine.node.current_session_id());
            let _ = engine
                .events
                .try_send(EngineEvent::Diagnostics { snapshot });
        }
        if engine.status_file.is_some()
            && now.duration_since(engine.last_status_tick) >= Duration::from_millis(200)
        {
            engine.last_status_tick = now;
            engine.write_status_file(&counters_arc, &viewer_arc, &input_arc);
        }
        if now.duration_since(engine.last_status_tick) >= Duration::from_millis(200) {
            engine.last_status_tick = now;
            engine.publish_snapshot(&counters_arc, &viewer_arc, &input_arc);
        }

        std::thread::sleep(Duration::from_millis(2));
    }
}

impl Engine {
    fn emit(&self, event: EngineEvent) {
        // Bounded (512): diagnostics may drop under a stalled consumer;
        // state stays pull-readable via `EngineHandle::status`.
        let _ = self.events.try_send(event);
    }

    fn info(&self, message: impl Into<String>) {
        self.emit(EngineEvent::Info {
            message: message.into(),
        });
    }

    fn error(&self, code: &str, message: impl Into<String>, hint: Option<String>) {
        self.emit(EngineEvent::Error {
            code: code.to_owned(),
            message: message.into(),
            hint,
        });
    }

    // -- command handling ----------------------------------------------------

    fn handle_cmd(&mut self, cmd: EngineCmd) {
        match cmd {
            EngineCmd::HostStart => self.cmd_host_start(),
            EngineCmd::HostStop => {
                self.host_started = false;
                self.host_reonline_at = None;
                self.node.host_stop(&mut self.observer);
            }
            EngineCmd::ControllerStart => self.cmd_controller_start(),
            EngineCmd::ControllerStop => {
                self.controller_started = false;
                self.ctrl_reonline_at = None;
                self.info("controller role will not re-register after the next session end");
            }
            EngineCmd::Connect { code } => self.cmd_connect(code),
            EngineCmd::CancelConnect => match self.node.controller_state() {
                ControllerState::Connected { .. } => {
                    self.node.controller_disconnect(&mut self.observer)
                }
                _ => self.node.controller_cancel(&mut self.observer),
            },
            EngineCmd::Disconnect => match self.node.controller_state() {
                ControllerState::Connected { .. } => {
                    let _ = self.node.send_wire(
                        Channel::Control,
                        &WireMessage::Disconnect {
                            reason: protocol::wire::ControlDisconnectReason::User,
                        },
                    );
                    self.node.controller_disconnect(&mut self.observer);
                }
                _ => self.node.controller_cancel(&mut self.observer),
            },
            EngineCmd::ConsentAccept => {
                if self.observer.pending_consent().is_none() {
                    self.error("no_consent", "No consent prompt is pending.", None);
                    return;
                }
                self.ensure_transport(MachineKind::Host);
                let secret = ids::new_session_secret();
                self.node.user_accept_consent(secret, &mut self.observer);
            }
            EngineCmd::ConsentReject => {
                self.node.user_reject_consent(&mut self.observer);
            }
            EngineCmd::SetQuality(preset) => self.cmd_set_quality(preset),
            EngineCmd::SelectMonitor { monitor_id } => self.cmd_select_monitor(&monitor_id),
            EngineCmd::ViewerScale(mode) => {
                if let Some(pipeline) = self.controller_pipeline.as_ref() {
                    pipeline.viewer_ctl.set_scale(mode);
                }
                self.observer.set_viewer_scale(scale_name(mode).to_owned());
            }
            EngineCmd::ViewerFullscreen => {
                if let Some(pipeline) = self.controller_pipeline.as_ref() {
                    pipeline.viewer_ctl.request_fullscreen_toggle();
                }
            }
            EngineCmd::Shutdown => unreachable!("handled by the loop"),
        }
    }

    fn cmd_host_start(&mut self) {
        if controller_in_session(self.node.controller_state()) {
            self.error(
                "role_conflict",
                "Finish the active control session before sharing this machine.",
                None,
            );
            return;
        }
        let caps = if self.real_pipeline_ready() {
            match self.build_host_caps() {
                Ok(caps) => caps,
                Err(err) => {
                    self.error("host_caps_failed", err, None);
                    return;
                }
            }
        } else {
            // No GPU (state-machine mode): advertise a stub so the flow is
            // still exercisable end-to-end without real monitors.
            host_caps_stub()
        };
        self.caps_cache = Some(caps.clone());
        self.host_started = true;
        self.ensure_transport(MachineKind::Host);
        self.node.host_start(caps, &mut self.observer);
        self.setup_host_input();
    }

    fn cmd_controller_start(&mut self) {
        if host_in_session(self.node.host_state()) {
            self.error(
                "role_conflict",
                "Finish the active sharing session before controlling another machine.",
                None,
            );
            return;
        }
        self.controller_started = true;
        self.node
            .controller_start(controller_caps(), &mut self.observer);
    }

    fn cmd_connect(&mut self, code: String) {
        if !matches!(self.node.controller_state(), ControllerState::Online) {
            self.error(
                "not_online",
                "The controller role is not Online; enable it first.",
                None,
            );
            return;
        }
        self.ensure_transport(MachineKind::Controller);
        self.observer.set_current_peer(code.clone());
        self.node.controller_connect(&code, &mut self.observer);
    }

    fn cmd_set_quality(&mut self, preset: QualityPreset) {
        self.observer.set_quality(preset);
        match self.node.controller_state() {
            ControllerState::Connected { .. } => {
                let msg = WireMessage::SetQuality { preset };
                if let Err(err) = self.node.send_wire(Channel::Control, &msg) {
                    self.error("send_failed", format!("quality change failed: {err}"), None);
                    return;
                }
                self.info(format!("quality preset set to {}", preset_name(preset)));
            }
            _ => {
                // Host-side default while sharing: apply on rebuild.
                let plan = plan_for(preset);
                self.selected_plan = Some(plan);
                self.agg.bump_encoder_rebuild();
                self.flags_mut().want_reconfig = Some(plan_for(preset));
                self.info(format!(
                    "host quality preset set to {} (applies at next pipeline rebuild)",
                    preset_name(preset)
                ));
            }
        }
    }

    fn cmd_select_monitor(&mut self, monitor_id: &str) {
        match self.node.controller_state() {
            ControllerState::Connected { .. } => {
                let msg = WireMessage::SelectMonitor {
                    monitor_id: monitor_id.to_owned(),
                };
                match self.node.send_wire(Channel::Control, &msg) {
                    Ok(()) => self.info(format!("monitor select sent: {monitor_id}")),
                    Err(err) => {
                        self.error("send_failed", format!("monitor select failed: {err}"), None)
                    }
                }
            }
            _ => {
                self.selected_monitor = Some(monitor_id.to_owned());
                self.observer
                    .set_active_monitor(Some(monitor_id.to_owned()));
                if let Some(pipeline) = self.host_pipeline.as_ref() {
                    pipeline.ctl.select_monitor(monitor_id);
                    pipeline
                        .ctl
                        .force_keyframe
                        .store(true, std::sync::atomic::Ordering::Release);
                    self.retarget_input(monitor_id);
                }
                self.info(format!("shared monitor set to {monitor_id}"));
            }
        }
    }

    // -- flags application -----------------------------------------------------

    fn apply_flags(&mut self) {
        let flags = std::mem::take(&mut *self.flags_mut());
        let observer::ObserverFlags {
            want_streaming,
            want_rendering,
            want_reconfig,
            want_monitor,
            peer_transport_gone,
            viewer_closed,
            force_keyframe,
            peer_caps,
        } = flags;
        if let Some(caps) = peer_caps {
            self.peer_caps_seen(caps);
        }
        let mut next = observer::ObserverFlags {
            want_streaming,
            want_rendering,
            ..observer::ObserverFlags::default()
        };

        // Quality reconfig (host): rebuild the encode stage with the new
        // plan, then re-arm streaming so the start block below (next
        // iteration) rebuilds with `selected_plan`.
        if let Some(plan) = want_reconfig {
            self.selected_plan = Some(plan.clone());
            self.agg.bump_encoder_rebuild();
            if self.host_pipeline.is_some() {
                self.stop_host_pipeline();
                // The pooled encoder has the old config; drop it so the
                // rebuild creates a new MFT (known drop-path leak,
                // counted, bounded by user action).
                *self.pool.encoder.lock().expect("encoder pool") = None;
                next.want_streaming = true;
            }
        }

        // Monitor select from the wire (host).
        if let Some(monitor) = want_monitor {
            self.selected_monitor = Some(monitor.clone());
            if let Some(pipeline) = self.host_pipeline.as_ref() {
                pipeline.ctl.select_monitor(&monitor);
                self.retarget_input(&monitor);
            }
        }

        if let Some(pipeline) = self.host_pipeline.as_ref()
            && (force_keyframe
                || pipeline
                    .ctl
                    .display_changed_edge
                    .swap(false, std::sync::atomic::Ordering::AcqRel))
        {
            pipeline
                .ctl
                .force_keyframe
                .store(true, std::sync::atomic::Ordering::Release);
            self.refresh_input_display();
        } else if force_keyframe {
            self.flags_mut().force_keyframe = true; // pipeline not up yet; keep
        }

        // Host pipeline start/stop.
        if want_streaming && self.host_pipeline.is_none() && self.real_pipeline_ready() {
            self.start_host_pipeline();
        }
        if !want_streaming && self.host_pipeline.is_some() {
            self.stop_host_pipeline();
        }

        // Controller pipeline start/stop.
        if want_rendering && self.controller_pipeline.is_none() && self.real_pipeline_ready() {
            self.start_controller_pipeline();
        }
        if !want_rendering && self.controller_pipeline.is_some() {
            self.stop_controller_pipeline();
        }

        // Peer transport gone (data-plane network-change notice).
        if peer_transport_gone {
            self.node
                .teardown_transport("peer transport gone (control goodbye)", &mut self.observer);
        }

        // Viewer window closed by the user: treat as disconnect intent.
        if viewer_closed
            && matches!(
                self.node.controller_state(),
                ControllerState::Connected { .. }
            )
        {
            self.info("viewer window closed; disconnecting");
            self.node.controller_disconnect(&mut self.observer);
        }

        // Session-end edges: retire the dead session's transport and
        // schedule auto re-online.
        let host_down = self.observer.state_is(MachineKind::Host, "Disconnected");
        let ctrl_down = self
            .observer
            .state_is(MachineKind::Controller, "Disconnected");
        if (host_down || ctrl_down) && !self.session_end_handled {
            self.session_end_handled = true;
            self.node.close_transport();
            if let Some(pump) = self.input_pump.as_ref() {
                pump.lock()
                    .expect("input pump")
                    .all_keys_up(AllKeysUpTrigger::Disconnect);
            }
            if self.auto_reonline {
                if self.host_started && self.host_reonline_at.is_none() && host_down {
                    self.host_reonline_at = Some(Instant::now() + Duration::from_secs(1));
                }
                if self.controller_started && self.ctrl_reonline_at.is_none() && ctrl_down {
                    self.ctrl_reonline_at = Some(Instant::now() + Duration::from_secs(1));
                }
            }
        } else if !host_down && !ctrl_down {
            self.session_end_handled = false;
        }

        if let Some(at) = self.host_reonline_at
            && Instant::now() >= at
            && matches!(self.node.host_state(), HostState::Disconnected { .. })
        {
            self.host_reonline_at = None;
            let caps = self.caps_cache.clone().unwrap_or_else(host_caps_stub);
            self.ensure_transport(MachineKind::Host);
            self.node.host_start(caps, &mut self.observer);
        }
        if let Some(at) = self.ctrl_reonline_at
            && Instant::now() >= at
            && matches!(
                self.node.controller_state(),
                ControllerState::Disconnected { .. }
            )
        {
            self.ctrl_reonline_at = None;
            self.ensure_transport(MachineKind::Controller);
            self.node
                .controller_start(controller_caps(), &mut self.observer);
        }

        // The host answer side needs a transport before consent acceptance.
        if host_in_session(self.node.host_state())
            && (!self.node.has_transport() || self.transport_owner != MachineKind::Host)
        {
            self.ensure_transport(MachineKind::Host);
        }

        *self.flags_mut() = next;
        // Re-arm the kept keyframe request after the overwrite above.
        if force_keyframe && self.host_pipeline.is_none() {
            self.flags_mut().force_keyframe = true;
        }
    }

    fn peer_caps_seen(&mut self, caps: Capabilities) {
        let monitors = caps
            .monitors
            .iter()
            .map(|m| crate::ipc::MonitorDto {
                monitor_id: m.monitor_id.clone(),
                label: format!("{}x{}", m.width_px, m.height_px),
                width_px: m.width_px,
                height_px: m.height_px,
                is_primary: m.is_primary,
                desktop_left: 0,
                desktop_top: 0,
            })
            .collect::<Vec<_>>();
        self.observer.set_peer_monitors(monitors.clone());
        self.emit(EngineEvent::PeerCaps { monitors });
    }

    fn start_host_pipeline(&mut self) {
        let monitor = self
            .selected_monitor
            .clone()
            .unwrap_or_else(|| "primary".to_owned());
        let plan = self
            .selected_plan
            .clone()
            .unwrap_or_else(|| plan_for(self.current_quality()));
        let device = self.device.clone().expect("gpu for host pipeline");
        let report = &self.report;
        let session = Arc::clone(&self.session_slot);
        let agg = Arc::clone(&self.agg);
        let clock = Arc::clone(&self.clock);
        let started = host::HostPipeline::start(
            device,
            &self.pool,
            &plan,
            &monitor,
            || make_tee_sink(report, &session, &agg),
            Arc::clone(&session),
            clock,
        );
        match started {
            Ok(pipeline) => {
                self.observer.set_active_monitor(Some(monitor));
                // The encode thread fills `encoder_describe` within its
                // first iterations; never overwrite a known-good describe
                // with a not-yet-filled slot (the rebuild path reads this
                // right after spawn).
                let describe = pipeline.encoder_describe.lock().expect("describe").clone();
                if let Some(describe) = describe {
                    let kind = if describe.contains("hardware") {
                        "hardware"
                    } else {
                        "software"
                    };
                    self.agg
                        .set_encoder(describe.clone(), Some(kind.to_owned()));
                    self.observer.set_encoder(Some(describe));
                }
                self.host_pipeline = Some(pipeline);
                self.setup_host_input();
            }
            Err(err) => {
                self.error("host_pipeline_failed", err, None);
            }
        }
    }

    fn stop_host_pipeline(&mut self) {
        if let Some(pipeline) = self.host_pipeline.take() {
            self.finished_host_counters
                .push(Arc::clone(&pipeline.counters));
            pipeline.stop();
        }
    }

    fn start_controller_pipeline(&mut self) {
        let device = self.device.clone().expect("gpu for controller pipeline");
        let report = &self.report;
        let session = Arc::clone(&self.session_slot);
        let agg = Arc::clone(&self.agg);
        let clock = Arc::clone(&self.clock);
        let present_sink = make_tee_sink(report, &session, &agg);
        let title = format!(
            "{} — {}",
            self.viewer_title,
            self.observer.current_peer().as_deref().unwrap_or("session")
        );
        let scale = self.current_scale();
        let started = controller::ControllerPipeline::start(
            device,
            &self.pool,
            || make_tee_sink(report, &session, &agg),
            present_sink,
            Arc::clone(&session),
            clock,
            &title,
            1280,
            720,
            scale,
        );
        match started {
            Ok(pipeline) => {
                self.observer.cursor_slot = Some(Arc::clone(&pipeline.cursor_slot));
                self.controller_pipeline = Some(pipeline);
            }
            Err(err) => {
                self.error("controller_pipeline_failed", err, None);
            }
        }
    }

    fn stop_controller_pipeline(&mut self) {
        if let Some(pipeline) = self.controller_pipeline.take() {
            self.observer.cursor_slot = None;
            self.finished_ctrl_counters
                .push(Arc::clone(&pipeline.counters));
            pipeline.stop();
        }
    }

    // -- data planes ------------------------------------------------------------

    fn drain_host_output(&mut self) {
        let Some(pipeline) = self.host_pipeline.as_ref() else {
            return;
        };
        let mut sink = self.make_loop_sink();
        while let Some(item) = pipeline.q_enc_send.pop(Duration::ZERO) {
            let video = VideoFrame {
                frame_id: item.packet.frame_id,
                timestamp_ns: item.packet.timestamp_ns,
                is_keyframe: item.packet.is_keyframe,
                bytes: item.packet.bytes,
            };
            match self.node.send_video(video) {
                Ok(()) => {
                    let send_ns = self.clock.now_ns();
                    sink.record(CounterRecord::FrameTiming(FrameTiming {
                        session_id: self.session_slot.get(),
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
                Err(err) => eprintln!("[engine] send_video: {err}"),
            }
        }
        while let Some(cursor) = pipeline.cursor_slot.take() {
            let _ = self
                .node
                .send_wire(Channel::Cursor, &WireMessage::Cursor(cursor));
        }
    }

    fn drain_controller_input(&mut self) {
        let Some(pipeline) = self.controller_pipeline.as_ref() else {
            return;
        };
        while let Some(frame) = self.node.poll_video() {
            pipeline
                .counters
                .received
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let recv_ns = match frame.recv_instant {
                Some(arrival) => {
                    self.clock_origin.1
                        + arrival
                            .saturating_duration_since(self.clock_origin.0)
                            .as_nanos() as u64
                }
                None => self.clock.now_ns(),
            };
            let missing = frame.missing_packets;
            let frame_id = frame.frame_id;
            let _ = pipeline
                .q_recv_dec
                .push(controller::RecvItem { frame, recv_ns });
            if missing > 0 || frame_id.is_none() {
                pipeline
                    .counters
                    .keyframe_requests
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                pipeline
                    .reset_decoder
                    .store(true, std::sync::atomic::Ordering::Release);
                let _ = self
                    .node
                    .send_wire(Channel::Control, &WireMessage::KeyframeRequest);
            }
        }
        // Gap-triggered keyframe request, rate-limited (rig parity).
        if pipeline
            .keyframe_needed
            .load(std::sync::atomic::Ordering::Acquire)
            && self.last_keyframe_request.elapsed() >= Duration::from_millis(250)
            && pipeline
                .keyframe_needed
                .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            self.last_keyframe_request = Instant::now();
            pipeline
                .counters
                .keyframe_requests
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = self
                .node
                .send_wire(Channel::Control, &WireMessage::KeyframeRequest);
        }
    }

    fn drain_viewer_input(&mut self) {
        let Some(pipeline) = self.controller_pipeline.as_ref() else {
            return;
        };
        self.agg
            .set_viewer_input_dropped(pipeline.viewer_ctl.dropped_count());
        let batch = pipeline.viewer_ctl.drain_input();
        if batch.is_empty() {
            return;
        }
        let wire = viewer::to_wire_events(&batch, &mut self.fast_seq, &mut self.reliable_seq);
        for (channel, event) in wire {
            if matches!(event, InputEvent::AllKeysUp { .. }) {
                self.all_keys_up_sent += 1;
            }
            let msg = WireMessage::Input(event);
            if let Err(err) = self.node.send_wire(channel, &msg) {
                eprintln!("[engine] viewer input send: {err}");
            }
        }
    }

    fn sample_link_stats(&mut self) {
        if !self.node.has_transport() {
            return;
        }
        let Ok(stats) = self.node.stats() else {
            return;
        };
        if stats.relay_in_use {
            self.error(
                "relay_in_use",
                "A relay was selected — forbidden in the MVP (invariant 4).",
                None,
            );
        }
        let mut sink = self.make_loop_sink();
        sink.record(CounterRecord::LinkSample(LinkSample {
            session_id: self.session_slot.get(),
            send_bitrate_kbps: stats.send_bitrate_kbps.map(|v| v as u32),
            recv_bitrate_kbps: stats.recv_bitrate_kbps.map(|v| v as u32),
            rtt_ms: stats.rtt_ms.map(|v| v as f32),
            loss_percent: stats.loss_percent.map(|v| v as f32),
            at_ns: self.clock.now_ns(),
        }));
        if let Some(gauges) = self.node.channel_queue_gauges() {
            for (index, kind) in [
                diagnostics::QueueKind::ChannelControl,
                diagnostics::QueueKind::ChannelInputFast,
                diagnostics::QueueKind::ChannelInputReliable,
                diagnostics::QueueKind::ChannelCursor,
            ]
            .into_iter()
            .enumerate()
            {
                sink.record(CounterRecord::QueueSample(diagnostics::QueueSample {
                    session_id: self.session_slot.get(),
                    queue: kind,
                    depth: gauges.depth[index],
                    capacity: gauges.capacity[index],
                    high_water: gauges.high_water[index],
                    dropped: gauges.dropped[index],
                    replaced: gauges.replaced[index],
                    at_ns: self.clock.now_ns(),
                }));
            }
        }
    }

    // -- helpers ------------------------------------------------------------

    fn flags_mut(&mut self) -> std::sync::MutexGuard<'_, observer::ObserverFlags> {
        self.observer.flags.lock().expect("observer flags")
    }

    fn real_pipeline_ready(&self) -> bool {
        self.device.is_some()
    }

    fn current_quality(&self) -> QualityPreset {
        preset_from_name(&self.observer.quality_name()).unwrap_or(QualityPreset::Balanced)
    }

    fn current_scale(&self) -> ScaleMode {
        scale_from_name(&self.observer.viewer_scale_name()).unwrap_or(ScaleMode::Fit)
    }

    fn make_loop_sink(&self) -> Box<dyn PerfSink> {
        make_tee_sink(&self.report, &self.session_slot, &self.agg)
    }

    fn build_host_caps(&mut self) -> Result<Capabilities, String> {
        let device = self
            .device
            .clone()
            .ok_or_else(|| "no GPU device (pipelines disabled)".to_owned())?;
        let monitors = displays::enumerate_displays();
        let dtos = monitors
            .iter()
            .map(|m| crate::ipc::MonitorDto {
                monitor_id: m.monitor_id.clone(),
                label: m.description.clone(),
                width_px: m.width.max(0) as u32,
                height_px: m.height.max(0) as u32,
                is_primary: m.is_primary,
                desktop_left: m.desktop_left,
                desktop_top: m.desktop_top,
            })
            .collect::<Vec<_>>();
        self.observer.set_host_monitors(dtos.clone());
        self.emit(EngineEvent::HostCaps {
            monitors: dtos.clone(),
        });
        // Probe the encoder once; the instance is process-lifetime (pool).
        let plan = plan_for(self.initial_quality);
        let encoder = match self.pool.encoder.lock().expect("encoder pool").take() {
            Some(encoder) => encoder,
            None => codec_windows::MfEncoder::new(device, plan.encoder_config())
                .map_err(|e| format!("encoder probe failed: {e}"))?,
        };
        let describe = encoder.describe();
        let kind = if describe.contains("hardware") {
            EncoderKind::Hardware
        } else {
            EncoderKind::Software
        };
        *self.pool.encoder.lock().expect("encoder pool") = Some(encoder);
        self.agg.set_encoder(
            describe.clone(),
            Some(
                if matches!(kind, EncoderKind::Hardware) {
                    "hardware"
                } else {
                    "software"
                }
                .to_owned(),
            ),
        );
        self.observer.set_encoder(Some(describe));
        Ok(Capabilities {
            encoders: vec![EncoderCapabilities {
                kind,
                codec: protocol::capabilities::Codec::H264,
                max_width_px: 2560,
                max_height_px: 1440,
                max_fps: 60,
            }],
            monitors: dtos
                .iter()
                .map(|m| MonitorInfo {
                    monitor_id: m.monitor_id.clone(),
                    width_px: m.width_px,
                    height_px: m.height_px,
                    is_primary: m.is_primary,
                })
                .collect(),
            max_bitrate_kbps: 50_000,
            features: shared_features(),
        })
    }

    fn setup_host_input(&mut self) {
        if self.input_pump.is_some() {
            return;
        }
        if self.real_input {
            let rect = self.primary_monitor_rect().unwrap_or_else(|| {
                input_windows::MonitorRect::new(0, 0, 1920, 1080).expect("fallback rect")
            });
            match input_windows::SendInputSink::new(rect) {
                Ok(sink) => {
                    let shared = Arc::new(Mutex::new(sink));
                    self.send_sink = Some(Arc::clone(&shared));
                    self.input_pump = Some(Arc::new(Mutex::new(InputPump::new(SinkBox(
                        Box::new(SharedSendSink(shared)),
                    )))));
                    self.observer.input_pump = self.input_pump.clone();
                }
                Err(err) => {
                    eprintln!("[engine] SendInputSink init failed: {err}; recording instead");
                    self.setup_recording_input();
                }
            }
        } else {
            self.setup_recording_input();
        }
    }

    fn setup_recording_input(&mut self) {
        self.input_pump = Some(Arc::new(Mutex::new(InputPump::new(SinkBox(Box::new(
            RecordingSink::default(),
        ))))));
        self.observer.input_pump = self.input_pump.clone();
    }

    fn primary_monitor_rect(&self) -> Option<input_windows::MonitorRect> {
        let m = displays::primary_display()?;
        input_windows::MonitorRect::new(m.desktop_left, m.desktop_top, m.width, m.height).ok()
    }

    /// Point the injection rectangle at `monitor_id` (`set_monitor_rect`).
    fn retarget_input(&mut self, monitor_id: &str) {
        let monitors = displays::enumerate_displays();
        let Some(m) = monitors.iter().find(|m| m.monitor_id == monitor_id) else {
            return;
        };
        let Ok(rect) =
            input_windows::MonitorRect::new(m.desktop_left, m.desktop_top, m.width, m.height)
        else {
            return;
        };
        if let Some(sink) = self.send_sink.as_ref()
            && let Err(err) = sink.lock().expect("send sink").set_monitor_rect(rect)
        {
            eprintln!("[engine] set_monitor_rect: {err}");
        }
    }

    /// Display changed: refresh the sink's virtual-desktop metrics.
    fn refresh_input_display(&mut self) {
        if let Some(sink) = self.send_sink.as_ref()
            && let Err(err) = sink.lock().expect("send sink").refresh_display_metrics()
        {
            eprintln!("[engine] refresh_display_metrics: {err}");
        }
    }

    fn ensure_transport(&mut self, owner: MachineKind) {
        if self.node.has_transport() {
            if self.transport_owner == owner {
                return;
            }
            self.node.close_transport();
        }
        let role = if owner == MachineKind::Host {
            WebrtcTransportRole::Host
        } else {
            WebrtcTransportRole::Controller
        };
        match WebrtcTransport::new(role) {
            Ok(transport) => {
                self.node.attach_transport(Box::new(transport));
                self.node.set_transport_owner(owner);
                self.transport_owner = owner;
            }
            Err(err) => {
                self.error(
                    "transport_init_failed",
                    format!("transport build failed: {err}"),
                    None,
                );
            }
        }
    }

    fn teardown(&mut self) {
        if let Some(stop) = self.resource_stop.take() {
            stop.store(true, std::sync::atomic::Ordering::Release);
        }
        self.node.close_transport();
        self.stop_host_pipeline();
        self.stop_controller_pipeline();
        if let Some(pump) = self.input_pump.as_ref() {
            pump.lock()
                .expect("input pump")
                .all_keys_up(AllKeysUpTrigger::Disconnect);
        }
        if let Some(join) = self.resource_join.take() {
            let _ = join.join();
        }
        self.info("engine stopped");
    }

    fn collect_counters(&self) -> EngineCounters {
        use std::sync::atomic::Ordering;
        let mut out = EngineCounters {
            input_sent_fast: self.fast_seq,
            input_sent_reliable: self.reliable_seq,
            input_all_keys_up_sent: self.all_keys_up_sent,
            encoder_rebuilds: self.agg.rebuild_count(),
            ..EngineCounters::default()
        };
        let mut add_host = |counters: &host::HostPipeCounters| {
            out.frames_captured += counters.captured.load(Ordering::Relaxed);
            out.frames_encoded += counters.encoded.load(Ordering::Relaxed);
            out.keyframes += counters.keyframes.load(Ordering::Relaxed);
            out.monitor_switches += counters.monitor_switches.load(Ordering::Relaxed);
        };
        for counters in &self.finished_host_counters {
            add_host(counters);
        }
        if let Some(pipeline) = self.host_pipeline.as_ref() {
            add_host(&pipeline.counters);
        }
        for counters in &self.finished_ctrl_counters {
            out.frames_presented += counters.presented.load(Ordering::Relaxed);
        }
        if let Some(pipeline) = self.controller_pipeline.as_ref() {
            out.frames_presented += pipeline.counters.presented.load(Ordering::Relaxed);
        }
        out
    }

    /// The encode thread fills its describe asynchronously; sync it into
    /// the shared status/aggregate once available (covers the racy window
    /// right after a pipeline (re)build).
    fn sync_encoder_describe(&mut self) {
        let Some(pipeline) = self.host_pipeline.as_ref() else {
            return;
        };
        let Some(describe) = pipeline.encoder_describe.lock().expect("describe").clone() else {
            return;
        };
        let kind = if describe.contains("hardware") {
            "hardware"
        } else {
            "software"
        };
        self.agg
            .set_encoder(describe.clone(), Some(kind.to_owned()));
        self.observer.set_encoder(Some(describe));
    }

    fn input_stat_now(&self) -> diag::InputStat {
        self.input_pump
            .as_ref()
            .map(|pump| observer::input_stat(&pump.lock().expect("input pump")))
            .unwrap_or_default()
    }

    fn viewer_facts(&self) -> ViewerFacts {
        match self.controller_pipeline.as_ref() {
            Some(pipeline) => ViewerFacts {
                created: true,
                hwnd: pipeline
                    .viewer_hwnd
                    .load(std::sync::atomic::Ordering::Relaxed),
                fullscreen: pipeline.viewer_ctl.is_fullscreen(),
                focused: pipeline.viewer_ctl.is_focused(),
            },
            None => ViewerFacts::default(),
        }
    }

    fn publish_snapshot(
        &self,
        counters_arc: &Arc<Mutex<EngineCounters>>,
        viewer_arc: &Arc<Mutex<ViewerFacts>>,
        input_arc: &Arc<Mutex<diag::InputStat>>,
    ) {
        *counters_arc.lock().expect("engine counters") = self.collect_counters();
        *viewer_arc.lock().expect("engine viewer") = self.viewer_facts();
        *input_arc.lock().expect("engine input") = self.input_stat_now();
    }

    fn write_status_file(
        &self,
        counters_arc: &Arc<Mutex<EngineCounters>>,
        viewer_arc: &Arc<Mutex<ViewerFacts>>,
        input_arc: &Arc<Mutex<diag::InputStat>>,
    ) {
        self.publish_snapshot(counters_arc, viewer_arc, input_arc);
        let Some(path) = self.status_file.clone() else {
            return;
        };
        let status = self.observer.status_snapshot(
            self.collect_counters(),
            self.input_stat_now(),
            self.viewer_facts(),
        );
        let json = serde_json::to_string(&status).unwrap_or_default();
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, json.as_bytes()).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

fn make_tee_sink(
    report: &Option<node_runtime::metrics::JsonlReport>,
    session: &Arc<SessionSlot>,
    agg: &Arc<diag::DiagAgg>,
) -> Box<dyn PerfSink> {
    Box::new(diag::TeeSink::new(
        jsonl_or_null(report, session),
        Arc::clone(agg),
    ))
}

fn jsonl_or_null(
    report: &Option<node_runtime::metrics::JsonlReport>,
    session: &Arc<SessionSlot>,
) -> Box<dyn PerfSink> {
    match report {
        Some(report) => Box::new(report.sink_handle(Arc::clone(session))),
        None => Box::new(diagnostics::NullSink),
    }
}

fn shared_features() -> FeatureFlags {
    FeatureFlags::empty()
        .with(FeatureFlags::TRICKLE_ICE)
        .with(FeatureFlags::CURSOR_CHANNEL)
        .with(FeatureFlags::INPUT_FAST_CHANNEL)
}

fn controller_caps() -> Capabilities {
    Capabilities {
        encoders: vec![],
        monitors: vec![],
        max_bitrate_kbps: 50_000,
        features: shared_features(),
    }
}

fn host_caps_stub() -> Capabilities {
    Capabilities {
        encoders: vec![],
        monitors: vec![],
        max_bitrate_kbps: 50_000,
        features: FeatureFlags::empty(),
    }
}

pub fn controller_in_session(state: &ControllerState) -> bool {
    matches!(
        state,
        ControllerState::Requesting { .. }
            | ControllerState::Offering { .. }
            | ControllerState::Connecting { .. }
            | ControllerState::Connected { .. }
    )
}

pub fn host_in_session(state: &HostState) -> bool {
    matches!(
        state,
        HostState::ConsentPrompted { .. }
            | HostState::Exchanging { .. }
            | HostState::Connecting { .. }
            | HostState::Connected { .. }
    )
}
