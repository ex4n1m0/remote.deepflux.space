//! `EngineObserver` — node effects → engine flags/events (the m2_rig
//! `RigObserver` pattern: pipelines spawn in the loop, which owns the
//! report and device handles; the observer only signals intent).
//!
//! Invariant 6 is inherited: observer callbacks carry state names, ids,
//! and counts — never SDP bodies or input payloads (`NodeObserver` itself
//! is the choke point; `InputEvent`'s Debug is redacted).

use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};

use node_runtime::node::NodeObserver;
use node_runtime::timers::MachineKind;
use protocol::capabilities::Capabilities;
use protocol::wire::{ControlDisconnectReason, QualityPreset, WireMessage};
use transport_webrtc::Channel;

use super::diag::InputStat;
use super::quality::plan_for;
use super::{EngineEvent, EngineStatus, ViewerFacts};
use crate::ipc::MonitorDto;

/// The observer's mutable state, shared with the engine loop through Arc
/// (the loop reads flags each iteration; the observer writes them from
/// `node.pump` on the same thread, so races are impossible by construction).
#[derive(Default)]
pub struct ObserverFlags {
    pub want_streaming: bool,
    pub want_rendering: bool,
    /// Host: a `SetQuality` arrived; the loop rebuilds the encode stage.
    pub want_reconfig: Option<super::quality::QualityPlan>,
    /// Host: a `SelectMonitor` arrived.
    pub want_monitor: Option<String>,
    /// Peer said goodbye with `TransportError` (data-plane network notice).
    pub peer_transport_gone: bool,
    /// Controller: viewer window closed by the user.
    pub viewer_closed: bool,
    /// Pending keyframe request from the controller.
    pub force_keyframe: bool,
    /// Capabilities learned from `Hello`/`HelloAck` (the peer's).
    pub peer_caps: Option<Capabilities>,
}

pub struct EngineObserver {
    pub events: SyncSender<EngineEvent>,
    pub flags: Arc<Mutex<ObserverFlags>>,
    pub shared: Arc<super::EngineShared>,
    /// Host-side input pump hook (loop fills; observer feeds wire input).
    pub input_pump: Option<Arc<Mutex<node_runtime::input::InputPump<super::SinkBox>>>>,
    /// Controller cursor slot (loop fills from observer).
    pub cursor_slot: Option<Arc<node_runtime::metrics::LatestSlot<protocol::wire::CursorMessage>>>,
}

impl EngineObserver {
    fn emit(&self, event: EngineEvent) {
        // Bounded (512): diagnostics may drop under a stalled consumer;
        // state is also pull-readable via `EngineHandle::status`.
        let _ = self.events.try_send(event);
    }

    // -- shared-state wrappers (engine-loop side; same module tree) ---------

    pub fn pending_consent(&self) -> Option<String> {
        self.shared.pending_consent()
    }

    pub fn current_peer(&self) -> Option<String> {
        self.shared.current_peer()
    }

    pub fn set_current_peer(&self, peer: String) {
        self.shared.set_current_peer(Some(peer));
    }

    pub fn set_quality(&self, preset: protocol::wire::QualityPreset) {
        self.shared.set_quality(preset);
    }

    pub fn quality_name(&self) -> String {
        self.shared.quality_name()
    }

    pub fn viewer_scale_name(&self) -> String {
        self.shared.viewer_scale_name()
    }

    pub fn set_viewer_scale(&self, scale: String) {
        self.shared.set_viewer_scale(scale);
    }

    pub fn set_active_monitor(&self, monitor: Option<String>) {
        self.shared.set_active_monitor(monitor);
    }

    pub fn set_encoder(&self, describe: Option<String>) {
        self.shared.set_encoder(describe);
    }

    pub fn set_host_monitors(&self, monitors: Vec<MonitorDto>) {
        self.shared.set_host_monitors(monitors);
    }

    pub fn set_peer_monitors(&self, monitors: Vec<MonitorDto>) {
        self.shared.set_peer_monitors(monitors);
    }

    pub fn state_is(&self, machine: MachineKind, name: &str) -> bool {
        self.shared.state_is(machine, name)
    }

    pub fn status_snapshot(
        &self,
        counters: super::EngineCounters,
        input: InputStat,
        viewer: ViewerFacts,
    ) -> EngineStatus {
        self.shared.status(counters, input, viewer)
    }
}

/// Periodic input-stat refresh into the aggregation sink (engine loop).
pub fn input_stat(pump: &node_runtime::input::InputPump<super::SinkBox>) -> InputStat {
    let c = pump.counters();
    InputStat {
        applied: c.moves_applied + c.reliable_applied,
        suppressed: c.moves_stale_suppressed + c.reliable_stale_suppressed,
        gaps: c.sequence_gaps,
        all_keys_up: c.all_keys_up,
        held: pump.held_count(),
        inject_errors: c.inject_errors,
    }
}

impl NodeObserver for EngineObserver {
    fn state_changed(&mut self, machine: MachineKind, state: &str) {
        let session_id = self.shared.current_session_id();
        self.shared.set_state(machine, state);
        self.emit(EngineEvent::StateChanged {
            machine: machine.name().to_owned(),
            state: state.to_owned(),
            session_id,
        });
    }

    fn prompt_consent(&mut self, controller_device_id: &str, session_id: &str) {
        self.shared
            .set_pending_consent(Some(controller_device_id.to_owned()));
        self.shared
            .set_current_peer(Some(controller_device_id.to_owned()));
        self.emit(EngineEvent::ConsentRequested {
            controller_device_id: controller_device_id.to_owned(),
            session_id: session_id.to_owned(),
        });
        self.emit(EngineEvent::PeerOnline {
            device_id: controller_device_id.to_owned(),
        });
    }

    fn session_established(&mut self, session_id: &str) {
        self.shared.clear_pending_consent();
        self.emit(EngineEvent::SessionEstablished {
            session_id: session_id.to_owned(),
            peer: self.shared.current_peer(),
        });
    }

    fn session_ended(&mut self, cause: &session::DisconnectCause) {
        self.shared.clear_pending_consent();
        let peer = self.shared.current_peer();
        if let Some(peer) = peer {
            self.emit(EngineEvent::PeerOffline { device_id: peer });
        }
        let (code, message, hint) = super::disconnect_copy(cause);
        self.emit(EngineEvent::SessionEnded {
            cause: format!("{cause:?}"),
            code,
            message,
            hint,
        });
    }

    fn start_streaming(&mut self) {
        self.flags.lock().expect("observer flags").want_streaming = true;
    }

    fn stop_streaming(&mut self) {
        self.flags.lock().expect("observer flags").want_streaming = false;
    }

    fn start_rendering(&mut self) {
        self.flags.lock().expect("observer flags").want_rendering = true;
    }

    fn stop_rendering(&mut self) {
        self.flags.lock().expect("observer flags").want_rendering = false;
    }

    fn wire_received(&mut self, channel: Channel, message: &WireMessage) {
        match (channel, message) {
            (Channel::InputFast | Channel::InputReliable, WireMessage::Input(event)) => {
                if let Some(pump) = self.input_pump.as_ref() {
                    pump.lock().expect("input pump").on_input(event);
                }
            }
            (Channel::Cursor, WireMessage::Cursor(cursor)) => {
                if let Some(slot) = self.cursor_slot.as_ref() {
                    slot.put(cursor.clone());
                }
            }
            (Channel::Control, WireMessage::HelloAck { capabilities })
            | (Channel::Control, WireMessage::Hello { capabilities }) => {
                // The peer's live capabilities (re-negotiated on the
                // direct path): monitors for the controller's picker.
                let monitors = capabilities
                    .monitors
                    .iter()
                    .map(|m| MonitorDto {
                        monitor_id: m.monitor_id.clone(),
                        label: format!("{}x{}", m.width_px, m.height_px),
                        width_px: m.width_px,
                        height_px: m.height_px,
                        is_primary: m.is_primary,
                        desktop_left: 0,
                        desktop_top: 0,
                    })
                    .collect::<Vec<_>>();
                self.shared.set_peer_monitors(monitors.clone());
                self.flags.lock().expect("observer flags").peer_caps = Some(capabilities.clone());
                self.emit(EngineEvent::PeerCaps { monitors });
            }
            (Channel::Control, WireMessage::KeyframeRequest) => {
                self.flags.lock().expect("observer flags").force_keyframe = true;
            }
            (Channel::Control, WireMessage::SetQuality { preset }) => {
                self.shared.set_quality(*preset);
                // M5: `Auto` never rebuilds on the wire path either — it
                // engages the congestion controller against the current
                // pipeline (the engine loop owns it); manual presets pin
                // their targets through the rebuild path.
                if *preset != QualityPreset::Auto {
                    let plan = plan_for(*preset);
                    self.flags.lock().expect("observer flags").want_reconfig = Some(plan);
                }
            }
            (Channel::Control, WireMessage::SelectMonitor { monitor_id }) => {
                self.shared.set_active_monitor(Some(monitor_id.clone()));
                self.flags.lock().expect("observer flags").want_monitor = Some(monitor_id.clone());
                self.emit(EngineEvent::Info {
                    message: format!("controller selected monitor {monitor_id}"),
                });
            }
            _ => {}
        }
    }

    fn keyframe_requested(&mut self) {
        self.flags.lock().expect("observer flags").force_keyframe = true;
    }

    fn control_disconnect(&mut self, reason: ControlDisconnectReason) {
        if let Some(pump) = self.input_pump.as_ref() {
            pump.lock()
                .expect("input pump")
                .all_keys_up(protocol::wire::AllKeysUpTrigger::Disconnect);
        }
        if reason == ControlDisconnectReason::TransportError {
            self.flags
                .lock()
                .expect("observer flags")
                .peer_transport_gone = true;
        }
    }

    fn transport_failure(&mut self, reason: &str) {
        self.emit(EngineEvent::Error {
            code: "transport_failure".to_owned(),
            message: reason.to_owned(),
            hint: Some(super::DIRECT_ONLY_HINT.to_owned()),
        });
    }

    fn illegal_transition(&mut self, machine: MachineKind, state: &str, event: &str) {
        // Tolerated races are counted, never fatal (node contract).
        eprintln!(
            "[engine] tolerated illegal transition: {event} in {}::{state}",
            machine.name()
        );
    }
}
