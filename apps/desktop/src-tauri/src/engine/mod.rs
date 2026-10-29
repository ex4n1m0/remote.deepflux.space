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

pub mod blackhole;
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use diagnostics::{CounterRecord, FrameTiming, LinkSample, Origin, PerfSink};
use frame_surface::GpuDevice;
use input_windows::{InputError, InputSink};
use node_runtime::Clock as _;
use node_runtime::clock::MonotonicClock;
use node_runtime::input::InputPump;
use node_runtime::metrics::SessionSlot;
use node_runtime::node::Node;
use node_runtime::screenshot::ShotMeta;
use node_runtime::signaling::SignalingIo;
use node_runtime::timers::MachineKind;
use protocol::capabilities::{
    Capabilities, EncoderCapabilities, EncoderKind, FeatureFlags, MonitorInfo,
};
use protocol::wire::{
    AllKeysUpTrigger, ButtonState, InputEvent, MouseButton, QualityPreset, WireMessage,
};
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
    Connect {
        code: String,
        /// ADR-006: pairing secret for this host (when one is held), used
        /// to stamp the pairing proof on the outgoing `connect_request`.
        /// Redacted wrapper — see `chat::PairingSecret`.
        pairing_secret: Option<crate::chat::PairingSecret>,
        /// ADR-007: the machine display name stamped on the outgoing
        /// `connect_request` so the host's prompt says who is asking.
        /// The command layer refuses to connect without one.
        requester_name: Option<String>,
        /// Agent session: connect WITHOUT the viewer. The session exists
        /// to chat with the peer's assistant, so the controller pipeline
        /// (decode/present/input) stays down until
        /// [`EngineCmd::ViewerShow`] attaches it for monitoring.
        agent: bool,
    },
    /// Attach the viewer to a live agent session ("show the screen"):
    /// clears viewer suppression so the next reconcile starts the
    /// controller pipeline on the SAME session — the visual is then just
    /// monitoring what the agent does. Closing the viewer on an
    /// agent-origin session drops back to chat-only instead of ending
    /// the session.
    ViewerShow,
    /// Detach the viewer from a live agent session ("hide the screen"):
    /// back to chat-only WITHOUT ending the session, and the host stops
    /// streaming video (the `VIDEO_SUPPRESSED` bit goes out again).
    /// Agent-origin sessions only — a visual session ends when its
    /// viewer closes.
    ViewerHide,
    CancelConnect,
    Disconnect,
    /// ADR-006: `remember` is the consent dialog's "remember this machine"
    /// choice — the sole path to a persisted pairing + `PairAck` (see
    /// `drain_chat_and_pairing`).
    ConsentAccept {
        remember: bool,
    },
    ConsentReject,
    /// Host side: acknowledge the pending pairing offer (sent only by the
    /// app layer after a consent accept with `remember` — ADR-006).
    SendPairAck,
    SetQuality(QualityPreset),
    SelectMonitor {
        monitor_id: String,
    },
    ViewerScale(ScaleMode),
    ViewerFullscreen,
    /// ADR-004 (RD-017): synthetic input from the local AI agent. Batches
    /// are capped at [`MAX_AGENT_BATCH`] events (drop-oldest) and routed
    /// to the same wire channels as viewer input with shared per-channel
    /// seq counters.
    AgentInput(Vec<AgentInput>),
    /// ADR-005 (RD-022): send one chat message to the connected peer (the
    /// loop routes it onto the `chat` channel; out-of-session sending is
    /// the app layer's inbox path, not this command).
    ChatSend {
        body: String,
        agent: bool,
    },
    /// ADR-005 (RD-023): controller side — offer pairing to the connected
    /// host (fresh 32-byte secret hex).
    SendPairOffer {
        secret_hex: String,
    },
    Shutdown,
}

/// One high-level agent action (ADR-004, RD-017). Coordinates are already
/// normalized 0..=65535 over the frame. `Debug` is manual: text payloads
/// are redacted (invariant 6 — input is never logged).
#[derive(Clone, PartialEq)]
pub enum AgentInput {
    MouseMove {
        x: u16,
        y: u16,
    },
    MouseButton {
        button: MouseButton,
        state: ButtonState,
    },
    Wheel {
        delta_v: i32,
        delta_h: i32,
    },
    Key {
        scan_code: u16,
        extended: bool,
        state: ButtonState,
    },
    Text(String),
}

impl std::fmt::Debug for AgentInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MouseMove { x, y } => f
                .debug_struct("MouseMove")
                .field("x", x)
                .field("y", y)
                .finish(),
            Self::MouseButton { button, state } => f
                .debug_struct("MouseButton")
                .field("button", button)
                .field("state", state)
                .finish(),
            Self::Wheel { delta_v, delta_h } => f
                .debug_struct("Wheel")
                .field("delta_v", delta_v)
                .field("delta_h", delta_h)
                .finish(),
            Self::Key {
                scan_code,
                extended,
                state,
            } => f
                .debug_struct("Key")
                .field("scan_code", scan_code)
                .field("extended", extended)
                .field("state", state)
                .finish(),
            Self::Text(text) => f
                .debug_struct("Text")
                .field("code_points", &text.encode_utf16().count())
                .finish(),
        }
    }
}

/// Per-command cap for [`EngineCmd::AgentInput`] batches (invariant 3:
/// bounded, explicit drop-oldest — the newest actions win, like input-fast).
pub const MAX_AGENT_BATCH: usize = 512;

/// Convert agent actions into wire input events with the same per-channel
/// seq discipline as viewer input (`viewer::to_wire_events`): fast moves
/// share one counter, reliable events another. Text is chunked into UTF-16
/// code-unit groups (surrogate pairs never split) of ≤
/// [`AGENT_TEXT_CHUNK`] units.
const AGENT_TEXT_CHUNK: usize = 4096;

pub fn agent_to_wire_events(
    batch: &[AgentInput],
    fast_seq: &mut u64,
    reliable_seq: &mut u64,
) -> Vec<(Channel, InputEvent)> {
    let mut out = Vec::with_capacity(batch.len());
    for action in batch {
        match action {
            AgentInput::MouseMove { x, y } => {
                *fast_seq += 1;
                out.push((
                    Channel::InputFast,
                    InputEvent::MouseMove {
                        seq: *fast_seq,
                        x: *x,
                        y: *y,
                    },
                ));
            }
            AgentInput::MouseButton { button, state } => {
                *reliable_seq += 1;
                out.push((
                    Channel::InputReliable,
                    InputEvent::MouseButton {
                        seq: *reliable_seq,
                        button: *button,
                        state: *state,
                    },
                ));
            }
            AgentInput::Wheel { delta_v, delta_h } => {
                *reliable_seq += 1;
                out.push((
                    Channel::InputReliable,
                    InputEvent::Wheel {
                        seq: *reliable_seq,
                        delta_v: *delta_v,
                        delta_h: *delta_h,
                    },
                ));
            }
            AgentInput::Key {
                scan_code,
                extended,
                state,
            } => {
                *reliable_seq += 1;
                out.push((
                    Channel::InputReliable,
                    InputEvent::Key {
                        seq: *reliable_seq,
                        scan_code: *scan_code,
                        extended: *extended,
                        state: *state,
                    },
                ));
            }
            AgentInput::Text(text) => {
                let units: Vec<u16> = text.encode_utf16().collect();
                for chunk in units.chunks(AGENT_TEXT_CHUNK) {
                    *reliable_seq += 1;
                    out.push((
                        Channel::InputReliable,
                        InputEvent::Text {
                            seq: *reliable_seq,
                            code_points: String::from_utf16_lossy(chunk),
                        },
                    ));
                }
            }
        }
    }
    out
}

/// ADR-004 (RD-016): the agent screenshot slot. The controller decode
/// thread publishes one shot per request (latest-wins like the cursor
/// slot); [`EngineHandle::capture_screenshot`] blocks the caller for at
/// most `timeout` on the same condition variable. Bounded by construction:
/// one pending request, one stored shot, one waiter.
pub struct ShotSlot {
    pending: AtomicBool,
    generation: AtomicU64,
    slot: Mutex<Option<ShotMeta>>,
    cond: Condvar,
}

impl Default for ShotSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl ShotSlot {
    pub fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            slot: Mutex::new(None),
            cond: Condvar::new(),
        }
    }

    /// Decode thread: consume one pending request and publish the result
    /// (or a failure marker — the generation still bumps so a waiter
    /// unblocks with the previous/absent shot).
    pub fn publish(&self, result: Result<ShotMeta, String>) {
        let mut slot = self.slot.lock().expect("shot slot");
        if let Ok(meta) = result {
            *slot = Some(meta);
        }
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.cond.notify_all();
    }

    /// Caller: request one fresh shot and wait ≤ `timeout`.
    pub fn capture(&self, timeout: Duration) -> Option<ShotMeta> {
        self.pending.store(true, Ordering::Release);
        let start = self.generation.load(Ordering::Acquire);
        let slot = self.slot.lock().expect("shot slot");
        let (slot, _) = self
            .cond
            .wait_timeout_while(slot, timeout, |_| {
                self.generation.load(Ordering::Acquire) == start
            })
            .expect("shot condvar");
        slot.clone()
    }

    /// Decode thread: is a request outstanding? (Consumes it — one publish
    /// per request by construction.)
    pub fn take_pending(&self) -> bool {
        self.pending.swap(false, Ordering::AcqRel)
    }
}

/// `--mcp` launch mode (ADR-004, RD-018): the controller advertises
/// `FeatureFlags::AI_SESSION` so the host consent prompt distinguishes the
/// agent, and the MCP bridge runs alongside the shell.
static MCP_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_mcp_mode(on: bool) {
    MCP_MODE.store(on, Ordering::Relaxed);
}

pub fn mcp_mode() -> bool {
    MCP_MODE.load(Ordering::Relaxed)
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
        /// ADR-004: the controller advertised `FeatureFlags::AI_SESSION`.
        ai_session: bool,
        /// ADR-006: the claimed pairing proof, forwarded verbatim for the
        /// app layer to verify against its pairing store (v2: message-id
        /// bound + freshness-checked; not secret material).
        pairing_proof_hex: Option<String>,
        /// ADR-007: the controller's machine display name from the wire
        /// (advisory; the device id stays the identity). `None` on
        /// pre-0.8 controllers.
        requester_name: Option<String>,
        /// The request envelope's message_id — part of the v2 proof MAC.
        message_id: String,
    },
    /// Host user accepted the consent prompt; `remember` is the ADR-006
    /// "remember this machine" choice — the app layer persists + acks the
    /// pending pairing offer only when it is true. `requester_name`
    /// (ADR-009) replays the prompt's wire name so the app can cache it
    /// into the host-role pairing row.
    ConsentAccepted {
        controller_device_id: String,
        remember: bool,
        requester_name: Option<String>,
    },
    SessionEstablished {
        session_id: String,
        peer: Option<String>,
        /// ADR-009: the peer's display name learned from the wire
        /// (controller side: `accept.host_name`; host side: `None`).
        peer_name: Option<String>,
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
    /// ADR-005 (RD-022): chat message received from the connected peer.
    ChatReceived {
        /// Peer device id (= connection code) of the sender.
        peer: String,
        id: u64,
        ts_ms: u64,
        /// "user" | "agent" (wire `ChatSender`).
        sender: String,
        body: String,
    },
    /// ADR-005 (RD-023): host received a pairing offer (auto-acked; the
    /// app layer persists it).
    PairOfferReceived {
        controller_device_id: String,
        secret_hex: String,
    },
    /// ADR-005 (RD-023): the host acknowledged our pairing offer.
    PairAckReceived {
        host_device_id: String,
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
    pub viewer_client_w: u32,
    pub viewer_client_h: u32,
    pub viewer_swapchain_w: u32,
    pub viewer_swapchain_h: u32,
    pub host_monitors: Vec<crate::ipc::MonitorDto>,
    pub peer_monitors: Vec<crate::ipc::MonitorDto>,
    pub active_monitor: Option<String>,
    pub quality: String,
    pub encoder: Option<String>,
    /// Agent session: the viewer is currently suppressed (chat-only).
    /// True only while a live controller session runs without its
    /// pipeline — the UI's "show the screen" affordance.
    pub viewer_suppressed: bool,
    /// This controller session was initiated with the Agent verb (chat
    /// only, viewer attached on demand) — sticky for the session.
    pub session_agent: bool,
    /// Host side: the connected controller asked us not to stream video
    /// (`VIDEO_SUPPRESSED` in its `Hello`) — capture/encode stay down.
    pub streaming_suppressed: bool,
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
    /// ADR-009: the requester_name shown on the pending consent prompt —
    /// replayed on ConsentAccepted so the app can cache it into the
    /// host-role pairing row.
    pending_consent_name: Option<String>,
    host_monitors: Vec<crate::ipc::MonitorDto>,
    peer_monitors: Vec<crate::ipc::MonitorDto>,
    active_monitor: Option<String>,
    quality: String,
    encoder: Option<String>,
    viewer_scale: String,
    viewer_suppressed: bool,
    session_agent: bool,
    streaming_suppressed: bool,
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
            viewer_client_w: viewer.client.0,
            viewer_client_h: viewer.client.1,
            viewer_swapchain_w: viewer.swapchain.0,
            viewer_swapchain_h: viewer.swapchain.1,
            viewer_scale: inner.viewer_scale.clone(),
            host_monitors: inner.host_monitors.clone(),
            peer_monitors: inner.peer_monitors.clone(),
            active_monitor: inner.active_monitor.clone(),
            quality: inner.quality.clone(),
            encoder: inner.encoder.clone(),
            viewer_suppressed: inner.viewer_suppressed,
            session_agent: inner.session_agent,
            streaming_suppressed: inner.streaming_suppressed,
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

    /// ADR-009: the pending prompt's requester name (set with the consent,
    /// cleared with it, replayed on the accept).
    fn set_pending_consent_name(&self, name: Option<String>) {
        self.inner
            .lock()
            .expect("engine shared")
            .pending_consent_name = name;
    }

    fn clear_pending_consent(&self) {
        let mut inner = self.inner.lock().expect("engine shared");
        inner.pending_consent = None;
        inner.pending_consent_name = None;
    }

    fn pending_consent(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("engine shared")
            .pending_consent
            .clone()
    }

    fn pending_consent_name(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("engine shared")
            .pending_consent_name
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

    /// Agent-session viewer suppression (level; see
    /// [`Engine::viewer_suppressed`]).
    fn set_viewer_suppressed(&self, suppressed: bool) {
        self.inner.lock().expect("engine shared").viewer_suppressed = suppressed;
    }

    /// The live controller session's origin verb (Agent vs Control).
    fn set_session_agent(&self, agent: bool) {
        self.inner.lock().expect("engine shared").session_agent = agent;
    }

    /// Host side: the peer's video-suppression request (level).
    fn set_streaming_suppressed(&self, suppressed: bool) {
        self.inner
            .lock()
            .expect("engine shared")
            .streaming_suppressed = suppressed;
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
    /// Viewer client size (resize follow is asserted in the E2E; F49).
    pub client: (u32, u32),
    /// Swapchain size — must track `client` after a resize (F49).
    pub swapchain: (u32, u32),
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
    /// Test-only chaos (M6 E2E connect-failure case, mirrors the m5 rig's
    /// `--blackhole-candidates`): rewrite every REMOTE candidate's port to
    /// the discard port before the ICE agent sees it, emulating "UDP
    /// blocked toward the peer" — signaling works, ICE cannot. Never set
    /// by the product shell.
    pub blackhole_remote_candidates: bool,
    /// ADR-009: this machine's display name, stamped onto the outgoing
    /// `accept` so the controlling machine can label its trusted-host
    /// entry (empty = leave the field absent).
    pub host_display_name: String,
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
    shot: Arc<ShotSlot>,
    /// Cleared by a Drop guard inside the engine thread on ANY exit —
    /// clean shutdown or panic (2026-10-28 "engine stopped" incident:
    /// a panicked engine left a zombie handle whose slot was reused
    /// forever; callers now check liveness and respawn).
    alive: Arc<std::sync::atomic::AtomicBool>,
}

/// Sets `alive` false when dropped — runs on both the clean `return` and
/// a panic unwind inside `run`.
struct AliveGuard(Arc<std::sync::atomic::AtomicBool>);

impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

impl EngineHandle {
    /// Is the engine thread still running? False after a clean shutdown
    /// OR a panic — callers use this to respawn instead of erroring
    /// "engine stopped" at the user forever.
    pub fn is_alive(&self) -> bool {
        self.alive.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Send one command (bounded; never blocks the caller).
    pub fn send(&self, cmd: EngineCmd) -> Result<(), String> {
        self.tx.try_send(cmd).map_err(|err| match err {
            TrySendError::Full(_) => "engine command queue full".to_owned(),
            TrySendError::Disconnected(_) => "engine stopped".to_owned(),
        })
    }

    /// ADR-004 (RD-016): request one agent screenshot from the decode
    /// thread and wait ≤ `timeout`. `None` on timeout, when no session is
    /// streaming, or when the capture failed.
    pub fn capture_screenshot(&self, timeout: Duration) -> Option<ShotMeta> {
        self.shot.capture(timeout)
    }

    /// Authoritative status snapshot (pull counterpart of the events).
    pub fn status(&self) -> EngineStatus {
        let counters = *self.counters.lock().expect("engine counters");
        let viewer = *self.viewer.lock().expect("engine viewer");
        let input = *self.input.lock().expect("engine input");
        self.shared.status(counters, input, viewer)
    }

    /// Stop the engine and wait for its thread. `&mut self` (not
    /// consuming) so callers can keep the handle around — e.g. to assert
    /// the liveness flag afterwards.
    pub fn shutdown(&mut self) {
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
    let shot = Arc::new(ShotSlot::new());
    let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let join = std::thread::Builder::new()
        .name("engine".into())
        .spawn({
            let shared = Arc::clone(&shared);
            let counters = Arc::clone(&counters);
            let viewer = Arc::clone(&viewer);
            let input = Arc::clone(&input);
            let shot = Arc::clone(&shot);
            let alive = Arc::clone(&alive);
            move || {
                run(
                    cfg, cmd_rx, event_tx, shared, counters, viewer, input, shot, alive,
                )
            }
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
            shot,
            alive,
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

/// A connect queued while the controller role comes online (see
/// [`Engine::pending_connect`]).
struct PendingConnect {
    code: String,
    pairing_secret: Option<crate::chat::PairingSecret>,
    requester_name: Option<String>,
    agent: bool,
    queued_at: Instant,
}

/// How long a deferred connect waits for the controller role to come
/// online before giving up with a clear error (registration retries
/// underneath; this is the "service unreachable" horizon).
const PENDING_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

struct Engine {
    real_input: bool,
    auto_reonline: bool,
    status_file: Option<PathBuf>,
    viewer_title: String,
    /// ADR-009: this machine's display name, stamped onto the outgoing
    /// `accept` (empty = leave the wire field absent).
    host_display_name: String,
    initial_quality: QualityPreset,
    blackhole_remote_candidates: bool,
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
    shared: Arc<EngineShared>,
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
    /// One-press Control (0.6.3): a connect that arrived while the
    /// controller role was still coming online. Fired the moment the
    /// role reaches Online; dropped (with a clear error) if it never
    /// does. Cleared by cancel/disconnect/stop.
    pending_connect: Option<PendingConnect>,
    /// Agent session (chat-only connect): this controller session was
    /// initiated without the viewer. Sticky for the session's lifetime —
    /// closing a monitoring viewer returns to chat-only instead of
    /// disconnecting.
    session_agent_origin: bool,
    /// Rendering suppression right now: true while the agent session
    /// runs viewer-less (and again after the user closes a monitoring
    /// viewer). `ViewerShow` clears it; session end resets it.
    viewer_suppressed: bool,
    /// Host side: the connected controller asked us not to stream video
    /// (its `Hello` carries `VIDEO_SUPPRESSED` — an agent session). The
    /// capture/encode/stream pipeline stays down until the bit clears;
    /// a peer that never sends the bit streams normally.
    peer_video_suppressed: bool,
    session_end_handled: bool,
    selected_monitor: Option<String>,
    selected_plan: Option<quality::QualityPlan>,
    /// M5: live congestion policy while the `Auto` preset owns the host
    /// pipeline (manual presets pin targets and clear this).
    congestion: Option<node_runtime::congestion::CongestionController>,
    congestion_res_stepped: bool,
    fast_seq: u64,
    reliable_seq: u64,
    all_keys_up_sent: u64,
    last_stats_tick: Instant,
    last_diag_tick: Instant,
    last_status_tick: Instant,
    last_keyframe_request: Instant,
    /// Inject-error watermark (UIPI surfacing, F51).
    last_inject_errors: u64,
    last_uipi_emit: Option<Instant>,
    clock_origin: (Instant, u64),
    caps_cache: Option<Capabilities>,
    /// Agent screenshot slot (ADR-004): decode thread publishes on
    /// request; `EngineHandle::capture_screenshot` waits on it.
    shot: Arc<ShotSlot>,
}

#[allow(clippy::too_many_arguments)]
fn run(
    cfg: EngineConfig,
    cmd_rx: Receiver<EngineCmd>,
    event_tx: SyncSender<EngineEvent>,
    shared: Arc<EngineShared>,
    counters_arc: Arc<Mutex<EngineCounters>>,
    viewer_arc: Arc<Mutex<ViewerFacts>>,
    input_arc: Arc<Mutex<diag::InputStat>>,
    shot: Arc<ShotSlot>,
    alive: Arc<std::sync::atomic::AtomicBool>,
) {
    // Clears the handle's liveness flag on ANY exit from this function,
    // including a panic unwind — the app layer respawns on the next poll.
    let _alive_guard = AliveGuard(Arc::clone(&alive));
    let device_id = cfg.device_id.clone();
    let clock = Arc::new(MonotonicClock::new());
    let agg = Arc::new(diag::DiagAgg::new());
    let session_slot = Arc::new(SessionSlot::new(&format!("{device_id}-pre-session")));
    // Metrics are diagnostics, never load-bearing: an unwritable log dir
    // must not kill the engine thread at startup (the old `.expect` was
    // an instant "engine stopped" for every later command).
    let report = cfg.metrics_dir.as_ref().and_then(|dir| {
        match node_runtime::metrics::JsonlReport::create(dir, &format!("m4-app-{device_id}")) {
            Ok(report) => Some(report),
            Err(err) => {
                let _ = event_tx.try_send(EngineEvent::Error {
                    code: "metrics_unavailable".into(),
                    message: format!("Perf counters disabled (log dir unwritable): {err}"),
                    hint: None,
                });
                None
            }
        }
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
        blackhole_remote_candidates,
        host_display_name,
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
        last_wire_quality: None,
    };

    let mut engine = Engine {
        real_input,
        auto_reonline,
        status_file,
        viewer_title,
        host_display_name,
        initial_quality,
        blackhole_remote_candidates,
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
        shared: Arc::clone(&shared),
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
        pending_connect: None,
        session_agent_origin: false,
        viewer_suppressed: false,
        peer_video_suppressed: false,
        session_end_handled: false,
        selected_monitor: None,
        selected_plan: None,
        congestion: None,
        congestion_res_stepped: false,
        fast_seq: 0,
        reliable_seq: 0,
        all_keys_up_sent: 0,
        last_stats_tick: Instant::now(),
        last_diag_tick: Instant::now(),
        last_status_tick: Instant::now(),
        last_keyframe_request: Instant::now() - Duration::from_secs(10),
        last_inject_errors: 0,
        last_uipi_emit: None,
        clock_origin: (Instant::now(), 0),
        caps_cache: None,
        shot,
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
        engine.fire_pending_connect();
        shared.set_session(engine.node.current_session_id());

        // ---- viewer window closed (F50): pipeline counter → flag ----
        engine.propagate_viewer_closed();

        // ---- flags → pipelines / lifecycle ----
        engine.apply_flags();

        // ---- data planes ----
        engine.drain_host_output();
        engine.drain_controller_input();
        engine.drain_viewer_input();
        engine.drain_chat_and_pairing();

        // ---- channel depth trail (F63): every depth change leaves a
        // sample even when the burst enqueues and drains between polls
        // (M5 matrix: high_water 30/32 with all sampled depths 0). ----
        engine.sample_channel_depth_trail();

        // ---- periodic ----
        let now = Instant::now();
        if now.duration_since(engine.last_stats_tick) >= Duration::from_secs(1) {
            engine.last_stats_tick = now;
            engine.sample_link_stats();
        }
        if now.duration_since(engine.last_diag_tick) >= Duration::from_secs(1) {
            engine.last_diag_tick = now;
            engine.sync_encoder_describe();
            let stat = engine.input_stat_now();
            engine.maybe_emit_uipi(stat.inject_errors, now);
            engine.agg.set_input(stat);
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
                self.pending_connect = None;
                self.info("controller role will not re-register after the next session end");
            }
            EngineCmd::Connect {
                code,
                pairing_secret,
                requester_name,
                agent,
            } => self.cmd_connect(code, pairing_secret, requester_name, agent),
            EngineCmd::ViewerShow => self.cmd_viewer_show(),
            EngineCmd::ViewerHide => self.cmd_viewer_hide(),
            EngineCmd::CancelConnect => {
                self.pending_connect = None;
                match self.node.controller_state() {
                    ControllerState::Connected { .. } => {
                        self.node.controller_disconnect(&mut self.observer)
                    }
                    _ => self.node.controller_cancel(&mut self.observer),
                }
            }
            EngineCmd::Disconnect => {
                self.pending_connect = None;
                match self.node.controller_state() {
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
                }
            }
            EngineCmd::ConsentAccept { remember } => {
                if self.observer.pending_consent().is_none() {
                    self.error("no_consent", "No consent prompt is pending.", None);
                    return;
                }
                let controller = self.observer.pending_consent().unwrap_or_default();
                let requester_name = self.observer.pending_consent_name();
                self.ensure_transport(MachineKind::Host);
                let secret = ids::new_session_secret();
                // ADR-009: the accept carries this machine's display name
                // (empty config = leave the field absent, e.g. rigs/tests).
                let host_name = {
                    let name = self.host_display_name.trim();
                    (!name.is_empty()).then_some(name)
                };
                self.node
                    .user_accept_consent(secret, host_name, &mut self.observer);
                // ADR-006: the pairing decision rides the accept event so
                // the app layer (which holds the in-memory pairing offer)
                // can persist + ack exactly when "remember" was checked.
                let _ = self.events.try_send(EngineEvent::ConsentAccepted {
                    controller_device_id: controller,
                    remember,
                    requester_name,
                });
            }
            EngineCmd::ConsentReject => {
                self.node.user_reject_consent(&mut self.observer);
            }
            EngineCmd::SendPairAck => {
                let ack = WireMessage::PairAck;
                if let Err(err) = self.node.send_wire(Channel::Control, &ack) {
                    eprintln!("[engine] pair ack send: {err}");
                }
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
            EngineCmd::AgentInput(batch) => self.send_agent_input(batch),
            EngineCmd::ChatSend { body, agent } => self.send_chat(body, agent),
            EngineCmd::SendPairOffer { secret_hex } => {
                let msg = WireMessage::PairOffer { secret_hex };
                if let Err(err) = self.node.send_wire(Channel::Control, &msg) {
                    eprintln!("[engine] pair offer send: {err}");
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
        match self.node.controller_state() {
            ControllerState::Idle | ControllerState::Disconnected { .. } => {
                self.controller_started = true;
                self.node
                    .controller_start(controller_caps(), &mut self.observer);
            }
            // Already online (always-ready, 0.6.3) or still registering:
            // re-issuing Start would be an illegal transition. One press
            // means "make sure I can control out" — already true.
            _ => self.info("controller role is already online"),
        }
    }

    /// One-press connect (0.6.3): no separate enable step. Online →
    /// connect now; still coming online (first press after launch, or
    /// the auto re-online gap after a session) → start the role if it
    /// is down and defer the connect to the Online edge.
    fn cmd_connect(
        &mut self,
        code: String,
        pairing_secret: Option<crate::chat::PairingSecret>,
        requester_name: Option<String>,
        agent: bool,
    ) {
        if host_in_session(self.node.host_state()) {
            self.error(
                "role_conflict",
                "Finish the active sharing session before controlling another machine.",
                None,
            );
            return;
        }
        match self.node.controller_state() {
            ControllerState::Online => {
                self.connect_now(code, pairing_secret, requester_name, agent)
            }
            state if controller_in_session(state) => self.error(
                "role_conflict",
                "Finish or cancel the current control session first.",
                None,
            ),
            state => {
                if matches!(
                    state,
                    ControllerState::Idle | ControllerState::Disconnected { .. }
                ) {
                    self.controller_started = true;
                    self.node
                        .controller_start(controller_caps(), &mut self.observer);
                }
                self.observer.set_current_peer(code.clone());
                self.info(format!("Going online to control {code}…"));
                self.pending_connect = Some(PendingConnect {
                    code,
                    pairing_secret,
                    requester_name,
                    agent,
                    queued_at: Instant::now(),
                });
            }
        }
    }

    /// Monitor mode: attach the viewer to a live agent session. The same
    /// WebRTC session keeps running; only the controller pipeline
    /// (decode/present/input) comes up.
    fn cmd_viewer_show(&mut self) {
        if !controller_in_session(self.node.controller_state()) {
            self.error(
                "no_session",
                "No live control session — connect to a machine first.",
                None,
            );
            return;
        }
        if self.viewer_suppressed {
            self.info("viewer attached — the remote screen window is opening");
            self.set_agent_video(false);
        } else {
            self.info("viewer already attached");
        }
    }

    /// Stop watching without ending the agent session: viewer down, host
    /// streaming back off. Visual sessions keep close=disconnect, so this
    /// is refused there.
    fn cmd_viewer_hide(&mut self) {
        if !controller_in_session(self.node.controller_state()) {
            self.error(
                "no_session",
                "No live control session — connect to a machine first.",
                None,
            );
            return;
        }
        if !self.session_agent_origin {
            self.error(
                "not_agent_session",
                "A visual session ends when its viewer closes — hide is for agent sessions.",
                None,
            );
            return;
        }
        if self.viewer_suppressed {
            self.info("viewer already detached");
            return;
        }
        self.info("viewer detached — back to the agent session (chat only)");
        self.set_agent_video(true);
    }

    /// The one toggle for in-session agent video state (show/hide/close
    /// revert): local rendering suppression AND the host-side streaming
    /// request travel together — the refreshed `Hello` flips the peer's
    /// `VIDEO_SUPPRESSED` view, so the host's capture/encode/stream
    /// pipeline follows within a reconcile tick.
    fn set_agent_video(&mut self, suppressed: bool) {
        self.viewer_suppressed = suppressed;
        self.shared.set_viewer_suppressed(suppressed);
        self.node
            .set_controller_caps(controller_caps_with(suppressed));
        self.node.resend_controller_hello();
    }

    /// The connect body shared by the immediate and deferred paths.
    fn connect_now(
        &mut self,
        code: String,
        pairing_secret: Option<crate::chat::PairingSecret>,
        requester_name: Option<String>,
        agent: bool,
    ) {
        self.pending_connect = None;
        // Agent session: arm viewer suppression for the whole session —
        // the reconcile block then never starts the controller pipeline
        // until `ViewerShow` clears it. Reset on session end.
        self.session_agent_origin = agent;
        self.viewer_suppressed = agent;
        self.shared.set_viewer_suppressed(agent);
        self.shared.set_session_agent(agent);
        // Stamp the caps snapshot BEFORE establishment: the direct-path
        // `Hello` (sent the moment the session opens) carries the
        // `VIDEO_SUPPRESSED` bit, so the host never spins up
        // capture/encode for a chat-only session. Visual connects clear
        // any stale bit from a previous agent session.
        self.node.set_controller_caps(controller_caps_with(agent));
        self.ensure_transport(MachineKind::Controller);
        self.observer.set_current_peer(code.clone());
        let secret = pairing_secret.as_ref().map(|s| s.0.as_str());
        self.node
            .controller_connect(&code, secret, requester_name.as_deref(), &mut self.observer);
    }

    /// Fire a deferred connect once the controller role is Online, or
    /// fail it with a clear error when the service stays unreachable.
    fn fire_pending_connect(&mut self) {
        let Some(pending) = self.pending_connect.take() else {
            return;
        };
        // A peer connected to us while we waited — one session per
        // machine; the user retries after that session ends.
        if host_in_session(self.node.host_state()) {
            self.error(
                "role_conflict",
                "This machine is being controlled — finish that session before controlling another machine.",
                None,
            );
            return;
        }
        match self.node.controller_state() {
            ControllerState::Online => self.connect_now(
                pending.code,
                pending.pairing_secret,
                pending.requester_name,
                pending.agent,
            ),
            // RegistrationFailed dropped the role back to Idle — restart
            // it (legal from Idle) so the deferral rides the retry.
            ControllerState::Idle if pending.queued_at.elapsed() < PENDING_CONNECT_TIMEOUT => {
                self.node
                    .controller_start(controller_caps(), &mut self.observer);
                self.pending_connect = Some(pending);
            }
            _ if pending.queued_at.elapsed() >= PENDING_CONNECT_TIMEOUT => self.error(
                "not_online",
                "Couldn't reach the DeepFlux service to start controlling. Check your internet connection and press Control again.",
                None,
            ),
            _ => self.pending_connect = Some(pending),
        }
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
                // Host-side default while not sharing.
                if preset == QualityPreset::Auto && self.current_quality() == QualityPreset::Auto {
                    self.info("host quality preset already auto (congestion-controlled)");
                    return;
                }
                let plan = plan_for(preset);
                self.selected_plan = Some(plan.clone());
                self.agg.bump_encoder_rebuild();
                self.flags_mut().want_reconfig = Some(plan);
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
            chat_in,
            pair_offer_in,
        } = flags;
        if let Some(caps) = peer_caps {
            self.peer_caps_seen(caps);
        }
        let mut next = observer::ObserverFlags {
            want_streaming,
            want_rendering,
            chat_in,
            pair_offer_in,
            ..observer::ObserverFlags::default()
        };

        // F71: typed host-pipeline death (capture dead / device lost)
        // ends the session through the machines — stop streaming, wire
        // goodbye so the controller learns, then the session-end handling
        // below retires the transport and releases input. A frozen
        // `Connected` stream must be impossible (M6 soak: 14.7 min).
        if let Some(pipeline) = self.host_pipeline.as_ref()
            && pipeline
                .ctl
                .fatal
                .load(std::sync::atomic::Ordering::Acquire)
            && host_in_session(self.node.host_state())
        {
            let reason = pipeline
                .ctl
                .fatal_reason
                .lock()
                .expect("fatal reason")
                .clone()
                .unwrap_or_else(|| "host pipeline died".to_owned());
            self.error(
                "host_pipeline_died",
                format!("The session ended because the host stopped producing video: {reason}"),
                None,
            );
            // Best-effort data-plane goodbye (the peer's
            // `peer_transport_gone` path tears its side down); then the
            // machine transition sends the signaling
            // `Disconnect{TransportError}` and fires
            // `SessionEnded{TransportError}` — the UI `session-ended`
            // event with cause follows from the observer.
            let _ = self.node.send_wire(
                Channel::Control,
                &WireMessage::Disconnect {
                    reason: protocol::wire::ControlDisconnectReason::TransportError,
                },
            );
            let _ = self.node.send_wire(
                Channel::InputReliable,
                &WireMessage::Input(InputEvent::AllKeysUp {
                    trigger: AllKeysUpTrigger::Disconnect,
                }),
            );
            self.node.fail_session(&reason, &mut self.observer);
        }

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

        // Host pipeline start/stop. `peer_video_suppressed` (the
        // controller's chat-only request in its `Hello`) gates the start:
        // an agent session's host never captures or encodes, and a
        // mid-session `Hello` flip starts/stops streaming under the SAME
        // session (monitor attach/detach).
        if want_streaming
            && !self.peer_video_suppressed
            && self.host_pipeline.is_none()
            && self.real_pipeline_ready()
        {
            self.start_host_pipeline();
        }
        if (!want_streaming || self.peer_video_suppressed) && self.host_pipeline.is_some() {
            self.stop_host_pipeline();
        }

        // Controller pipeline start/stop. `viewer_suppressed` (agent
        // session) gates the start: the session rides the data channels
        // alone — no decode, no viewer, no input — until `ViewerShow`.
        if want_rendering
            && !self.viewer_suppressed
            && self.controller_pipeline.is_none()
            && self.real_pipeline_ready()
        {
            self.start_controller_pipeline();
        }
        if (!want_rendering || self.viewer_suppressed) && self.controller_pipeline.is_some() {
            self.stop_controller_pipeline();
        }

        // Peer transport gone (data-plane network-change notice).
        if peer_transport_gone {
            self.node
                .teardown_transport("peer transport gone (control goodbye)", &mut self.observer);
            // Same mid-call stop-action clobber hazard as above.
            next.want_streaming = false;
            next.want_rendering = false;
        }

        // Viewer window closed by the user. A visual session treats it as
        // disconnect intent — data-plane goodbye first (the host's key
        // safety fires on it), then the machine transition (F50 wiring
        // completed). An agent-origin session just drops back to
        // chat-only: the viewer was a monitor, closing it must not kill
        // the agent conversation.
        if viewer_closed
            && matches!(
                self.node.controller_state(),
                ControllerState::Connected { .. }
            )
        {
            if self.session_agent_origin {
                self.info("viewer window closed; back to the agent session (chat only)");
                // Suppression back on, and the refreshed `Hello` tells
                // the host to stop streaming (it was monitoring).
                self.set_agent_video(true);
                // `want_rendering` stays armed (level flag, no
                // StopRendering fired) — suppression alone keeps the
                // pipeline down until the next `ViewerShow`.
            } else {
                self.info("viewer window closed; disconnecting");
                let _ = self.node.send_wire(
                    Channel::Control,
                    &WireMessage::Disconnect {
                        reason: protocol::wire::ControlDisconnectReason::User,
                    },
                );
                self.node.controller_disconnect(&mut self.observer);
                // The machine fires StopRendering DURING this call; the flag
                // snapshot taken above is stale-true and would respawn the
                // (user-closed) viewer window on the next iteration if the
                // snapshot restore clobbered it.
                next.want_rendering = false;
                next.want_streaming = false;
            }
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
            // Agent-session flags retire with the session: the next
            // connect (either verb) starts from a clean visual default.
            self.session_agent_origin = false;
            if self.viewer_suppressed {
                self.viewer_suppressed = false;
                self.shared.set_viewer_suppressed(false);
            }
            self.shared.set_session_agent(false);
            if self.peer_video_suppressed {
                self.peer_video_suppressed = false;
                self.shared.set_streaming_suppressed(false);
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
        // Host side: the controller's video-suppression request rides the
        // same `Hello`/`HelloAck` (also re-sent mid-session to toggle).
        let video_off = caps.features.has(FeatureFlags::VIDEO_SUPPRESSED);
        if video_off != self.peer_video_suppressed {
            self.peer_video_suppressed = video_off;
            self.shared.set_streaming_suppressed(video_off);
            if host_in_session(self.node.host_state()) {
                self.info(if video_off {
                    "controller asked for chat-only — video streaming off"
                } else {
                    "controller attached the screen — video streaming on"
                });
            }
        }
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
            Arc::clone(&self.shot),
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

    /// ADR-004 (RD-017): synthetic agent input rides the same wire channels
    /// and shared per-channel seq counters as viewer input. The batch is
    /// capped drop-oldest (invariant 3 — newest actions win, exactly the
    /// input-fast semantics) and dropped entirely when no controller
    /// pipeline (and therefore no session) exists.
    fn send_agent_input(&mut self, mut batch: Vec<AgentInput>) {
        if self.controller_pipeline.is_none() {
            return;
        }
        if batch.len() > MAX_AGENT_BATCH {
            batch = batch.split_off(batch.len() - MAX_AGENT_BATCH);
        }
        let wire = agent_to_wire_events(&batch, &mut self.fast_seq, &mut self.reliable_seq);
        for (channel, event) in wire {
            let msg = WireMessage::Input(event);
            if let Err(err) = self.node.send_wire(channel, &msg) {
                eprintln!("[engine] agent input send: {err}");
            }
        }
    }

    /// ADR-005 (RD-022): send one chat message on the `chat` channel.
    fn send_chat(&mut self, body: String, agent: bool) {
        let message = protocol::wire::ChatMessage {
            id: self.clock.now_ms(),
            ts_ms: self.clock.now_ms(),
            sender: if agent {
                protocol::wire::ChatSender::Agent
            } else {
                protocol::wire::ChatSender::User
            },
            body,
        };
        let msg = WireMessage::Chat(message);
        // Chat rides the CONTROL channel (2026-10-28 crash fix): the
        // dedicated `chat` data channel was never part of the negotiated
        // channel set on the wire, and sending on `Channel::Chat` indexed
        // a nonexistent transport slot — every in-session chat message
        // PANICKED the engine thread. Control is the same reliability
        // class (ordered, reliable, tiny traffic), the channel is not
        // part of the wire payload (no WIRE_VERSION change), and older
        // peers that expect chat on the `chat` channel simply ignore it.
        if let Err(err) = self.node.send_wire(Channel::Control, &msg) {
            eprintln!("[engine] chat send: {err}");
        }
    }

    /// ADR-005 (RD-022/023) + ADR-006: drain observer-side chat input and
    /// pairing offers. Both become events; the app layer holds the offered
    /// pairing secret IN MEMORY until the owner's consent click — the ack
    /// and the persistence happen only on accept-with-remember (the
    /// pre-ADR-006 unconditional auto-ack is gone; the controller-side
    /// un-acked offer simply expires).
    fn drain_chat_and_pairing(&mut self) {
        let (chat_in, _pair_offer) = {
            let mut flags = self.observer.flags.lock().expect("observer flags");
            (
                std::mem::take(&mut flags.chat_in),
                flags.pair_offer_in.take(),
            )
        };
        let peer = self.observer.current_peer().unwrap_or_default();
        for chat in chat_in {
            let _ = self.events.try_send(EngineEvent::ChatReceived {
                peer: peer.clone(),
                id: chat.id,
                ts_ms: chat.ts_ms,
                sender: match chat.sender {
                    protocol::wire::ChatSender::User => "user".to_owned(),
                    protocol::wire::ChatSender::Agent => "agent".to_owned(),
                },
                body: chat.body,
            });
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
            available_bandwidth_kbps: stats.available_bandwidth_bps.map(|v| (v / 1000) as u32),
            remote_loss_percent: stats.remote_loss_percent.map(|v| v as f32),
            remote_rtt_ms: stats.remote_rtt_ms.map(|v| v as f32),
            at_ns: self.clock.now_ns(),
        }));
        // M5: drive the congestion policy while the Auto preset is active
        // on a live host pipeline (manual presets pin their targets).
        self.drive_congestion(&stats);
        if let Some(gauges) = self.node.channel_queue_gauges() {
            for (index, kind) in [
                diagnostics::QueueKind::ChannelControl,
                diagnostics::QueueKind::ChannelInputFast,
                diagnostics::QueueKind::ChannelInputReliable,
                diagnostics::QueueKind::ChannelCursor,
                diagnostics::QueueKind::ChannelChat,
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

    /// F63: drain the transport's channel depth-change trail and emit one
    /// `QueueSample` per entry, timestamped on the session clock by
    /// anchoring the transport's uptime reading. Called every engine-loop
    /// iteration (~2 ms); lock-only on the transport side.
    fn sample_channel_depth_trail(&mut self) {
        if !self.node.has_transport() {
            return;
        }
        let (samples, uptime_now) = self.node.channel_depth_trail();
        if samples.is_empty() {
            return;
        }
        let now_ns = self.clock.now_ns();
        let gauges = self.node.channel_queue_gauges();
        let mut sink = self.make_loop_sink();
        for entry in samples {
            let kind = match entry.channel {
                transport_webrtc::Channel::Control => diagnostics::QueueKind::ChannelControl,
                transport_webrtc::Channel::InputFast => diagnostics::QueueKind::ChannelInputFast,
                transport_webrtc::Channel::InputReliable => {
                    diagnostics::QueueKind::ChannelInputReliable
                }
                transport_webrtc::Channel::Cursor => diagnostics::QueueKind::ChannelCursor,
                transport_webrtc::Channel::Chat => diagnostics::QueueKind::ChannelChat,
            };
            let at_ns = now_ns.saturating_sub(uptime_now.saturating_sub(entry.at_uptime_ns));
            let (capacity, high_water, dropped, replaced) = match gauges.as_ref() {
                Some(g) => (
                    g.capacity[entry.channel as usize],
                    g.high_water[entry.channel as usize],
                    g.dropped[entry.channel as usize],
                    g.replaced[entry.channel as usize],
                ),
                None => (0, 0, 0, 0),
            };
            sink.record(CounterRecord::QueueSample(diagnostics::QueueSample {
                session_id: self.session_slot.get(),
                queue: kind,
                depth: entry.depth,
                capacity,
                high_water,
                dropped,
                replaced,
                at_ns,
            }));
        }
    }

    // -- helpers ------------------------------------------------------------

    /// M5: feed the `Auto`-preset congestion policy from the 1 Hz stats
    /// tick and apply its decision to the live pipeline. Manual presets
    /// pin targets (the controller is dropped); `Auto` adapts.
    fn drive_congestion(&mut self, stats: &transport_webrtc::TransportStats) {
        use node_runtime::congestion::{CongestionController, CongestionParams, CongestionSample};

        if self.current_quality() != QualityPreset::Auto
            || !matches!(self.node.host_state(), session::HostState::Connected { .. })
        {
            self.congestion = None;
            return;
        }
        let Some(pipeline) = self.host_pipeline.as_ref() else {
            return;
        };
        if self.congestion.is_none() {
            let start_kbps = self
                .selected_plan
                .as_ref()
                .map(|plan| plan.bitrate_kbps)
                .unwrap_or(6_000);
            self.congestion = Some(CongestionController::new(CongestionParams {
                start_bps: u64::from(start_kbps) * 1000,
                ..Default::default()
            }));
            self.info("auto quality: congestion controller active (STUN path estimate)");
        }
        let Some(mut ctl) = self.congestion.take() else {
            return;
        };
        let decision = ctl.sample(CongestionSample {
            at_ms: self.clock.now_ms(),
            estimate_bps: stats.available_bandwidth_bps,
            remote_loss_percent: stats.remote_loss_percent,
            remote_rtt_ms: stats.remote_rtt_ms,
            ice_rtt_ms: stats.rtt_ms,
            send_bitrate_kbps: stats.send_bitrate_kbps,
        });
        self.congestion = Some(ctl.clone());
        let target_kbps = self
            .congestion
            .as_ref()
            .map(|c| c.bitrate_bps() / 1000)
            .unwrap_or(0);
        if decision.bitrate_bps.is_some() || decision.fps_cap.is_some() {
            self.info(format!(
                "auto quality: {} (target {target_kbps} kbps, fps cap {:?})",
                decision.reason, decision.fps_cap
            ));
        }
        if let Some(bps) = decision.bitrate_bps {
            *pipeline.ctl.want_params.lock().expect("want params") =
                Some(codec_windows::EncoderParams {
                    bitrate_bps: Some(bps.min(u32::MAX as u64) as u32),
                    ..Default::default()
                });
        }
        if let Some(fps) = decision.fps_cap {
            *pipeline.ctl.want_fps.lock().expect("want fps") = Some(fps);
        }
        if decision.resolution_step_down && !self.congestion_res_stepped {
            self.congestion_res_stepped = true;
            self.info(
                "auto quality: sustained starvation - stepping resolution down (one rebuild)",
            );
            let mut plan = quality::plan_for(QualityPreset::Auto);
            plan.encode_width = 1280;
            plan.encode_height = 720;
            self.selected_plan = Some(plan.clone());
            self.agg.bump_encoder_rebuild();
            self.flags_mut().want_reconfig = Some(plan);
        }
    }

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
            // ADR-006: hosts gate pairing on the consent dialog's
            // "remember" choice — advertising the bit lets 0.5 controllers
            // label trust as deliberate (vs a legacy host's auto-ack).
            features: shared_features().with(FeatureFlags::PAIRING_REMEMBER),
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
        // M5: the product (WAN) configuration — public STUN, all-interface
        // sockets (srflx gathering), sender-side GCC estimate on the host
        // (the `Auto` preset's input). Loopback still works through host
        // candidates; TURN stays rejected at the config layer (invariant 4).
        let mut options = transport_webrtc::WebrtcTransportOptions::wan();
        if role == WebrtcTransportRole::Controller {
            options.congestion = None; // controller sends no media
        }
        match WebrtcTransport::with_options(role, options) {
            Ok(transport) => {
                let boxed: Box<dyn transport_webrtc::Transport> =
                    if self.blackhole_remote_candidates {
                        // Test-only chaos (E2E connect-failure): every
                        // remote candidate port -> discard. See
                        // engine::blackhole's module docs.
                        Box::new(blackhole::BlackholeCandidates::new(transport))
                    } else {
                        Box::new(transport)
                    };
                self.node.attach_transport(boxed);
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
        // F55: quitting mid-session must not leave the peer's key safety
        // waiting on transport-failure detection — best-effort wire
        // goodbye (+ AllKeysUp) first, then the machine transitions.
        if matches!(
            self.node.controller_state(),
            ControllerState::Connected { .. }
        ) {
            let _ = self.node.send_wire(
                Channel::InputReliable,
                &WireMessage::Input(InputEvent::AllKeysUp {
                    trigger: AllKeysUpTrigger::Disconnect,
                }),
            );
            let _ = self.node.send_wire(
                Channel::Control,
                &WireMessage::Disconnect {
                    reason: protocol::wire::ControlDisconnectReason::User,
                },
            );
            // Let the reliable control channel flush before the close.
            std::thread::sleep(Duration::from_millis(150));
            self.node.controller_disconnect(&mut self.observer);
        }
        if host_in_session(self.node.host_state()) {
            // Connected → Disconnected; the machine sends the signaling
            // Disconnect itself.
            self.node.host_stop(&mut self.observer);
        }
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

    /// F50: the present thread counts window closure; surface it as the
    /// observer flag `apply_flags` acts on.
    fn propagate_viewer_closed(&mut self) {
        if let Some(pipeline) = self.controller_pipeline.as_ref()
            && pipeline
                .counters
                .window_closed
                .load(std::sync::atomic::Ordering::Acquire)
        {
            self.flags_mut().viewer_closed = true;
        }
    }

    /// F51: surface UIPI injection blocks to the user (rate-limited).
    fn maybe_emit_uipi(&mut self, inject_errors: u64, now: Instant) {
        let host_connected = matches!(self.node.host_state(), HostState::Connected { .. });
        if should_emit_uipi(
            self.last_inject_errors,
            inject_errors,
            host_connected,
            self.last_uipi_emit,
            now,
        ) {
            self.last_uipi_emit = Some(now);
            self.error(
                "uipi_blocked",
                "The host machine is blocking remote input (an elevated foreground window or a locked session).",
                Some(
                    "Elevate the host app (run it as administrator) for sessions that must                      control elevated windows, or unlock the host session. Input resumes                      automatically once the block is gone."
                        .to_owned(),
                ),
            );
        }
        self.last_inject_errors = inject_errors;
    }

    fn input_stat_now(&self) -> diag::InputStat {
        self.input_pump
            .as_ref()
            .map(|pump| observer::input_stat(&pump.lock().expect("input pump")))
            .unwrap_or_default()
    }

    fn viewer_facts(&self) -> ViewerFacts {
        match self.controller_pipeline.as_ref() {
            Some(pipeline) => {
                let ctl = &pipeline.viewer_ctl;
                let (cw, ch) = ctl.client();
                let (sw, sh) = ctl.swapchain();
                ViewerFacts {
                    created: true,
                    hwnd: pipeline
                        .viewer_hwnd
                        .load(std::sync::atomic::Ordering::Relaxed),
                    fullscreen: ctl.is_fullscreen(),
                    focused: ctl.is_focused(),
                    client: (cw.max(0) as u32, ch.max(0) as u32),
                    swapchain: (sw, sh),
                }
            }
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
    let mut features = shared_features();
    // ADR-004: in `--mcp` mode this instance is driven by a local AI
    // agent — advertise it so the host consent prompt is distinct.
    if mcp_mode() {
        features = features.with(FeatureFlags::AI_SESSION);
    }
    Capabilities {
        encoders: vec![],
        monitors: vec![],
        max_bitrate_kbps: 50_000,
        features,
    }
}

/// Controller caps with the agent-session video bit stamped to match the
/// CURRENT suppression state — what the direct-path `Hello` sends. The
/// bit is additive: hosts that predate it stream anyway (the controller
/// drops the frames), which is exactly the pre-0.9.4 behavior.
fn controller_caps_with(video_suppressed: bool) -> Capabilities {
    let mut caps = controller_caps();
    if video_suppressed {
        caps.features = caps.features.with(FeatureFlags::VIDEO_SUPPRESSED);
    }
    caps
}

fn host_caps_stub() -> Capabilities {
    Capabilities {
        encoders: vec![],
        monitors: vec![],
        max_bitrate_kbps: 50_000,
        features: FeatureFlags::empty(),
    }
}

/// UIPI error-event policy (F51): emit on the first new injection error
/// while the host session is live, then at most once per
/// [`UIPI_EMIT_RATE`] (a permanently elevated foreground must not spam).
pub const UIPI_EMIT_RATE: Duration = Duration::from_secs(5);

pub fn should_emit_uipi(
    prev_errors: u64,
    now_errors: u64,
    host_connected: bool,
    last_emit: Option<Instant>,
    now: Instant,
) -> bool {
    host_connected
        && now_errors > prev_errors
        && last_emit.is_none_or(|at| now.duration_since(at) >= UIPI_EMIT_RATE)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uipi_policy_fires_on_new_errors_and_rate_limits() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        let t6 = t0 + Duration::from_secs(6);
        // No new errors → silent.
        assert!(!should_emit_uipi(5, 5, true, None, t0));
        // New errors while connected → emit.
        assert!(should_emit_uipi(5, 6, true, None, t0));
        // Not connected → silent (recording sinks never block anyway).
        assert!(!should_emit_uipi(5, 6, false, None, t0));
        // Rate-limited after a recent emit…
        assert!(!should_emit_uipi(6, 7, true, Some(t0), t1));
        // …and re-arms after the window.
        assert!(should_emit_uipi(6, 7, true, Some(t0), t6));
    }
}
