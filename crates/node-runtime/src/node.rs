//! `Node` — the composition owner (RD-006/007/008 core).
//!
//! One instance per role (no global state) that drives the pure
//! `session::HostSession` / `session::ControllerSession` state machines
//! against a real monotonic clock and the [`TimerQueue`], mapping
//! signaling-adapter envelopes and [`TransportEvent`]s into session
//! events and executing the returned [`Action`]s. The semantics it must
//! match are `crates/session/tests/two_peers.rs` (the executable
//! reference model):
//!
//! * duplicate `message_id` delivery is a no-op (the machines' bounded
//!   dedupe log; the signaling adapter is deliberately at-least-once),
//! * simultaneous-call collisions resolve by device-id tie-break in all
//!   legal states (`Requesting`/`Offering`/`Connecting`, both halves of
//!   the node-level rule — `Connect` racing our own host's inbound
//!   session, and an inbound request racing our own outbound session),
//! * timers fire in `(fire_at, schedule-seq)` order and cancel exactly,
//! * transport failures map to `TransportFailed` in the states where it
//!   is legal; in states where it is not (`Offering`), the machine's own
//!   connect timeout is the recovery path (documented mapping).
//!
//! Three documented deviations from the `World` harness, all because the
//! real system has an asymmetric offer/answer split and a stand-in
//! signaling service the scripted tests never exercised:
//!
//! 1. **ICE-candidate routing is role-complementary**: candidates
//!    gathered by a host-role transport are delivered to the peer's
//!    *controller* machine and vice versa — each machine's `ForwardIce`
//!    action must reach its own transport. `World::route` encodes the same
//!    complementary mapping since QA F34 (its earlier arm was dead code
//!    encoding the opposite); minted envelopes carry the
//!    transport-owning role ([`Node::set_transport_owner`]).
//! 2. **`Registered` self-ack**: the manual signaling adapter *is* the
//!    service stand-in, so after a successful `Register` write the node
//!    injects `Registered` on the next pump (the World injects it at
//!    t+50 ms). The ack is queued only after the write succeeds (QA F27).
//!    `Heartbeat` cadence likewise lives here (`HeartbeatDue` raised on
//!    `heartbeat_period_ms` while in a heartbeat-legal state).
//! 3. **Compose/apply failure mapping**: a `compose_answer` failure in
//!    `Exchanging` maps to `TransportFailed` (legal there); a
//!    `compose_offer`/`apply_answer` failure in `Offering` has no legal
//!    `TransportFailed` event — the machine's own connect timer owns
//!    recovery (the machines' design, faithfully mapped).
//!
//! Defensive-only differences from the World harness (counted, never
//! fatal; the World uses test-only `unreachable!`/panic): inbound
//! `Register`/`Heartbeat` envelopes counted as illegal, machine/timer
//! pairing mismatches, late `ChannelsOpen` after teardown, illegal
//! user-level transitions.
//!
//! Illegal transitions are counted and surfaced through
//! [`NodeObserver::illegal_transition`], never propagated as panics: real
//! interleavings can produce tolerated races (e.g. a late `ChannelsOpen`
//! after a timeout) that the pure machine correctly rejects.

use std::collections::VecDeque;
use std::sync::Arc;

use protocol::capabilities::Capabilities;
use protocol::signaling::{
    CancelReason, DisconnectReason, SIGNALING_PROTOCOL_VERSION, SIGNALING_SERVICE_ID,
    SessionSecret, SignalingBody, SignalingEnvelope,
};
use protocol::wire::{ControlDisconnectReason, WireMessage};
use session::{
    Action, ControllerEvent, ControllerSession, ControllerState, DisconnectCause, HostEvent,
    HostSession, HostState, SessionConfig, TimerId,
};
use transport_webrtc::{
    Channel, ConnectionState, ReceivedFrame, Transport, TransportError, TransportEvent,
    TransportStats, VideoFrame,
};

use crate::clock::Clock;
use crate::signaling::{InboundEnvelope, SignalingIo};
use crate::timers::{MachineKind, TimerQueue};

/// Callbacks the embedding binary (rig, tests, future Tauri shell) uses to
/// react to node-level effects. Every method has a no-op default; input
/// payloads and SDP bodies never appear here (invariant 6).
pub trait NodeObserver {
    /// A machine changed state (names only — `HostState::name()`).
    fn state_changed(&mut self, _machine: MachineKind, _state: &str) {}
    /// Host machine asked for a consent decision (`PromptConsent`).
    fn prompt_consent(&mut self, _controller_device_id: &str, _session_id: &str) {}
    fn session_established(&mut self, _session_id: &str) {}
    fn session_ended(&mut self, _cause: &DisconnectCause) {}
    /// Pipeline control (the runtime starts/stops real stage threads).
    fn start_streaming(&mut self) {}
    fn stop_streaming(&mut self) {}
    fn start_rendering(&mut self) {}
    fn stop_rendering(&mut self) {}
    /// A data-channel message arrived (decoded; input is redacted in Debug
    /// but the payload is here for the input pump / renderer).
    fn wire_received(&mut self, _channel: Channel, _message: &WireMessage) {}
    /// Controller asked for an immediate keyframe (loss recovery).
    fn keyframe_requested(&mut self) {}
    /// Peer said goodbye on the control channel (data-plane disconnect
    /// notice; the signaling `Disconnect` follows or the connect timer
    /// fires). Hosts must run input safety now.
    fn control_disconnect(&mut self, _reason: ControlDisconnectReason) {}
    /// Transport-level failure surfaced to the runtime (machines already
    /// transitioned, or the failure has no legal machine event).
    fn transport_failure(&mut self, _reason: &str) {}
    /// An event was not legal in the machine's current state (tolerated
    /// race; counted, never fatal).
    fn illegal_transition(&mut self, _machine: MachineKind, _state: &str, _event: &str) {}
}

/// A `NodeObserver` that ignores everything.
#[derive(Debug, Default)]
pub struct NoObserver;

impl NodeObserver for NoObserver {}

/// Payload-free node counters for the rig summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeCounters {
    pub envelopes_sent: u64,
    pub envelopes_received: u64,
    pub register_acked: u64,
    pub heartbeats_raised: u64,
    pub ice_minted: u64,
    pub ice_forwarded: u64,
    pub ice_forward_errors: u64,
    pub compose_errors: u64,
    pub apply_answer_errors: u64,
    pub send_errors: u64,
    pub late_channels_open: u64,
    pub illegal_transitions: u64,
    pub transport_missing: u64,
    pub wire_sent: u64,
    pub hello_sent: u64,
}

pub struct Node {
    device_id: String,
    cfg: SessionConfig,
    clock: Arc<dyn Clock>,
    host: HostSession,
    controller: ControllerSession,
    host_caps: Option<Capabilities>,
    controller_caps: Option<Capabilities>,
    timers: TimerQueue,
    signaling: Box<dyn SignalingIo>,
    transport: Option<Box<dyn Transport>>,
    /// Which role's machine owns the attached transport — the role tag on
    /// runtime-minted ICE-candidate envelopes (F34: the receiving node
    /// routes candidates role-complementarily, so a host-owned transport's
    /// candidate must be tagged Host even when this node's host machine is
    /// not in a session state).
    transport_owner: MachineKind,
    pending_register_acks: VecDeque<MachineKind>,
    next_host_heartbeat_ms: Option<u64>,
    next_controller_heartbeat_ms: Option<u64>,
    ice_counter: u64,
    counters: NodeCounters,
    channel_open_order: Vec<&'static str>,
}

impl Node {
    /// Build a node. Both role machines are created (matching the `World`
    /// — collision detection needs both); the embedding binary just never
    /// `Start`s the role it does not play.
    pub fn new(
        device_id: &str,
        cfg: SessionConfig,
        clock: Arc<dyn Clock>,
        signaling: Box<dyn SignalingIo>,
    ) -> Self {
        Self {
            device_id: device_id.to_owned(),
            host: HostSession::new(device_id.to_owned(), cfg.clone()),
            controller: ControllerSession::new(device_id.to_owned(), cfg.clone()),
            cfg,
            clock,
            host_caps: None,
            controller_caps: None,
            timers: TimerQueue::new(),
            signaling,
            transport: None,
            transport_owner: MachineKind::Controller,
            pending_register_acks: VecDeque::new(),
            next_host_heartbeat_ms: None,
            next_controller_heartbeat_ms: None,
            ice_counter: 0,
            counters: NodeCounters::default(),
            channel_open_order: Vec::new(),
        }
    }

    // ------------------------------------------------------------------
    // Introspection
    // ------------------------------------------------------------------

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn host_state(&self) -> &HostState {
        self.host.state()
    }

    pub fn controller_state(&self) -> &ControllerState {
        self.controller.state()
    }

    pub fn host_state_name(&self) -> String {
        self.host.state().name().to_owned()
    }

    pub fn controller_state_name(&self) -> String {
        self.controller.state().name().to_owned()
    }

    pub fn counters(&self) -> NodeCounters {
        self.counters
    }

    pub fn timers(&self) -> &TimerQueue {
        &self.timers
    }

    /// Observed channel-open order this session (evidence for the
    /// "order is unspecified" contract).
    pub fn channel_open_order(&self) -> &[&'static str] {
        &self.channel_open_order
    }

    /// The active session id (controller-minted), if any machine is in a
    /// session state. Used to scope diagnostics records.
    pub fn current_session_id(&self) -> Option<String> {
        match self.controller.state() {
            ControllerState::Requesting { session }
            | ControllerState::Offering { session }
            | ControllerState::Connecting { session }
            | ControllerState::Connected { session } => {
                return Some(session.session_id.clone());
            }
            _ => {}
        }
        match self.host.state() {
            HostState::ConsentPrompted { info } => return Some(info.session_id.clone()),
            HostState::Exchanging { session }
            | HostState::Connecting { session }
            | HostState::Connected { session } => return Some(session.session_id.clone()),
            _ => {}
        }
        None
    }

    /// The peer device id of the active session (for minting envelopes).
    fn session_peer(&self) -> Option<String> {
        match self.controller.state() {
            ControllerState::Requesting { session }
            | ControllerState::Offering { session }
            | ControllerState::Connecting { session }
            | ControllerState::Connected { session } => {
                return Some(session.peer_device_id.clone());
            }
            _ => {}
        }
        match self.host.state() {
            HostState::ConsentPrompted { info } => {
                return Some(info.controller_device_id.clone());
            }
            HostState::Exchanging { session }
            | HostState::Connecting { session }
            | HostState::Connected { session } => {
                return Some(session.peer_device_id.clone());
            }
            _ => {}
        }
        None
    }

    // ------------------------------------------------------------------
    // User-level inputs (what a UI / script would raise)
    // ------------------------------------------------------------------

    /// Host role on: register with capabilities.
    pub fn host_start(&mut self, capabilities: Capabilities, observer: &mut dyn NodeObserver) {
        self.host_caps = Some(capabilities.clone());
        self.next_host_heartbeat_ms = Some(self.clock.now_ms() + self.cfg.heartbeat_period_ms);
        self.step_host(HostEvent::Start { capabilities }, observer);
    }

    /// Controller role on.
    pub fn controller_start(
        &mut self,
        capabilities: Capabilities,
        observer: &mut dyn NodeObserver,
    ) {
        self.controller_caps = Some(capabilities.clone());
        self.next_controller_heartbeat_ms =
            Some(self.clock.now_ms() + self.cfg.heartbeat_period_ms);
        self.step_controller(ControllerEvent::Start { capabilities }, observer);
    }

    /// Controller user asked to control `host_device_id`, with the
    /// node-level simultaneous-call rule (`World::controller_connect`):
    /// if this node's host already holds an inbound session toward the
    /// same peer, the controller runs the device-id tie-break.
    pub fn controller_connect(&mut self, host_device_id: &str, observer: &mut dyn NodeObserver) {
        self.step_controller(
            ControllerEvent::Connect {
                host_device_id: host_device_id.to_owned(),
            },
            observer,
        );
        let Some(target) = self.controller_outbound_peer() else {
            return;
        };
        if self.host_sessioned_with(&target) {
            self.step_controller(
                ControllerEvent::CollisionDetected {
                    peer_device_id: target,
                },
                observer,
            );
        }
    }

    /// Host user accepted the consent prompt (one-time secret handed over;
    /// never logged).
    pub fn user_accept_consent(&mut self, secret: SessionSecret, observer: &mut dyn NodeObserver) {
        self.step_host(HostEvent::ConsentAccepted { secret }, observer);
    }

    /// Host user declined the consent prompt.
    pub fn user_reject_consent(&mut self, observer: &mut dyn NodeObserver) {
        self.step_host(HostEvent::ConsentRejected, observer);
    }

    /// Controller user withdrew the attempt (`Cancel`).
    pub fn controller_cancel(&mut self, observer: &mut dyn NodeObserver) {
        self.step_controller(ControllerEvent::Cancel, observer);
    }

    /// Host user stopped sharing.
    pub fn host_stop(&mut self, observer: &mut dyn NodeObserver) {
        self.step_host(HostEvent::Stop, observer);
    }

    /// Controller user disconnected an established session.
    pub fn controller_disconnect(&mut self, observer: &mut dyn NodeObserver) {
        self.step_controller(ControllerEvent::Disconnect, observer);
    }

    // ------------------------------------------------------------------
    // Pump
    // ------------------------------------------------------------------

    /// One iteration: service acks, due timers, heartbeat cadence, then
    /// inbound signaling. The embedding binary calls this on its own loop
    /// cadence (the rig: every ~20 ms).
    pub fn pump(&mut self, observer: &mut dyn NodeObserver) {
        // 1. Register acks from the "service".
        while let Some(machine) = self.pending_register_acks.pop_front() {
            self.counters.register_acked += 1;
            match machine {
                MachineKind::Host => self.step_host(HostEvent::Registered, observer),
                MachineKind::Controller => {
                    self.step_controller(ControllerEvent::Registered, observer)
                }
            }
        }

        // 2. Timers due now, in (fire_at, seq) order.
        let now = self.clock.now_ms();
        for timer in self.timers.due(now) {
            match (timer.machine, timer.id) {
                (MachineKind::Host, TimerId::HostConsent) => {
                    self.step_host(HostEvent::ConsentTimeout, observer)
                }
                (MachineKind::Host, TimerId::HostConnect) => {
                    self.step_host(HostEvent::ConnectTimeout, observer)
                }
                (MachineKind::Controller, TimerId::ControllerRequest) => {
                    self.step_controller(ControllerEvent::RequestTimeout, observer)
                }
                (MachineKind::Controller, TimerId::ControllerConnect) => {
                    self.step_controller(ControllerEvent::ConnectTimeout, observer)
                }
                // Timer ids are machine-specific by construction.
                _ => {
                    self.counters.illegal_transitions += 1;
                    observer.illegal_transition(
                        timer.machine,
                        "TimerQueue",
                        "machine/timer pairing mismatch",
                    );
                }
            }
        }

        // 3. Heartbeat cadence (runtime-owned; the machines have no
        //    heartbeat TimerId). Raised only in heartbeat-legal states.
        if let Some(next) = self.next_host_heartbeat_ms
            && now >= next
        {
            self.next_host_heartbeat_ms = Some(now + self.cfg.heartbeat_period_ms);
            if host_heartbeat_legal(self.host.state()) {
                self.counters.heartbeats_raised += 1;
                self.step_host(HostEvent::HeartbeatDue, observer);
            }
        }
        if let Some(next) = self.next_controller_heartbeat_ms
            && now >= next
        {
            self.next_controller_heartbeat_ms = Some(now + self.cfg.heartbeat_period_ms);
            if controller_heartbeat_legal(self.controller.state()) {
                self.counters.heartbeats_raised += 1;
                self.step_controller(ControllerEvent::HeartbeatDue, observer);
            }
        }

        // 4. Inbound signaling (at-least-once; machines dedupe).
        for inbound in self.signaling.poll_incoming() {
            self.counters.envelopes_received += 1;
            self.inbound(inbound, observer);
        }
    }

    // ------------------------------------------------------------------
    // Inbound envelope routing (World::route for the receiving node)
    // ------------------------------------------------------------------

    pub fn inbound(&mut self, inbound: InboundEnvelope, observer: &mut dyn NodeObserver) {
        let InboundEnvelope {
            from_machine,
            envelope:
                SignalingEnvelope {
                    message_id,
                    from_device_id,
                    session_id,
                    body,
                    ..
                },
        } = inbound;

        match body {
            SignalingBody::ConnectRequest { .. } => {
                self.step_host(
                    HostEvent::IncomingRequest {
                        message_id,
                        controller_device_id: from_device_id.clone(),
                        session_id: session_id.unwrap_or_default(),
                    },
                    observer,
                );
                // Mirror half of the node-level collision rule (QA F2): a
                // request arrived from a peer our controller has an
                // outbound session with — including after our own request
                // was already accepted.
                if self.controller_calling(&from_device_id) {
                    self.step_controller(
                        ControllerEvent::CollisionDetected {
                            peer_device_id: from_device_id,
                        },
                        observer,
                    );
                }
            }
            SignalingBody::Accept { session_secret } => {
                self.step_controller(
                    ControllerEvent::AcceptReceived {
                        message_id,
                        session_secret,
                    },
                    observer,
                );
            }
            SignalingBody::Reject { reason } => {
                self.step_controller(
                    ControllerEvent::RejectReceived { message_id, reason },
                    observer,
                );
            }
            SignalingBody::Offer { sdp } => {
                self.step_host(HostEvent::OfferReceived { message_id, sdp }, observer);
            }
            SignalingBody::Answer { sdp } => {
                // The runtime applies the answer to the transport before
                // the machine consumes it (the machine's contract: it
                // already holds the event payload).
                match self.transport_as_mut() {
                    Some(transport) => {
                        if let Err(err) = transport.apply_answer(&sdp) {
                            self.counters.apply_answer_errors += 1;
                            observer.transport_failure(&sanitize_reason(&err.0));
                        } else {
                            self.step_controller(
                                ControllerEvent::AnswerReceived { message_id, sdp },
                                observer,
                            );
                        }
                    }
                    None => self.counters.transport_missing += 1,
                }
            }
            SignalingBody::Cancel { .. } => {
                // Host policy treats all cancel reasons alike; the runtime
                // reuses the User discriminant (World parity).
                self.step_host(
                    HostEvent::CancelReceived {
                        message_id,
                        reason: CancelReason::User,
                    },
                    observer,
                );
            }
            SignalingBody::Disconnect { .. } => match from_machine {
                // A host hangs up → the controller learns; and vice versa.
                MachineKind::Host => self.step_controller(
                    ControllerEvent::DisconnectReceived {
                        message_id,
                        reason: DisconnectReason::User,
                    },
                    observer,
                ),
                MachineKind::Controller => self.step_host(
                    HostEvent::DisconnectReceived {
                        message_id,
                        reason: DisconnectReason::User,
                    },
                    observer,
                ),
            },
            SignalingBody::IceCandidate {
                candidate,
                sdp_mid,
                sdp_mline_index,
            } => {
                // Role-complementary routing (see module docs): candidates
                // from the peer's controller feed our host transport and
                // vice versa.
                let event_fields = (message_id, candidate, sdp_mid, sdp_mline_index);
                match from_machine {
                    MachineKind::Host => {
                        let (message_id, candidate, sdp_mid, sdp_mline_index) = event_fields;
                        self.step_controller(
                            ControllerEvent::IceCandidateReceived {
                                message_id,
                                candidate,
                                sdp_mid,
                                sdp_mline_index,
                            },
                            observer,
                        );
                    }
                    MachineKind::Controller => {
                        let (message_id, candidate, sdp_mid, sdp_mline_index) = event_fields;
                        self.step_host(
                            HostEvent::IceCandidateReceived {
                                message_id,
                                candidate,
                                sdp_mid,
                                sdp_mline_index,
                            },
                            observer,
                        );
                    }
                }
            }
            SignalingBody::IceComplete | SignalingBody::Error { .. } => {
                // Informational only (World parity).
            }
            SignalingBody::Register { .. } | SignalingBody::Heartbeat => {
                // Service-directed; the adapter never delivers these.
                self.counters.illegal_transitions += 1;
            }
        }
    }

    // ------------------------------------------------------------------
    // Transport event mapping
    // ------------------------------------------------------------------

    /// Feed one transport event. Call after `transport.poll()` in the
    /// embedding loop.
    pub fn transport_event(&mut self, event: TransportEvent, observer: &mut dyn NodeObserver) {
        match event {
            TransportEvent::Message(channel, message) => {
                match &message {
                    WireMessage::Hello { .. } => {
                        // Host side answers capability re-negotiation.
                        if let Some(caps) = self.host_caps.clone()
                            && matches!(self.host.state(), HostState::Connected { .. })
                        {
                            let _ = self.send_wire(
                                Channel::Control,
                                &WireMessage::HelloAck { capabilities: caps },
                            );
                            self.counters.hello_sent += 1;
                        }
                    }
                    WireMessage::KeyframeRequest => observer.keyframe_requested(),
                    WireMessage::Disconnect { reason } => observer.control_disconnect(*reason),
                    _ => {}
                }
                observer.wire_received(channel, &message);
            }
            TransportEvent::ChannelOpened(channel) => {
                self.channel_open_order.push(channel.label());
            }
            TransportEvent::ChannelsOpen => {
                // Per-channel readiness gating, not open order: the single
                // all-open event maps to `DataChannelOpen` on whichever
                // machine is `Connecting`.
                let host_connecting = matches!(self.host.state(), HostState::Connecting { .. });
                let controller_connecting =
                    matches!(self.controller.state(), ControllerState::Connecting { .. });
                if host_connecting {
                    self.step_host(HostEvent::DataChannelOpen, observer);
                } else if controller_connecting {
                    self.step_controller(ControllerEvent::DataChannelOpen, observer);
                } else {
                    self.counters.late_channels_open += 1;
                }
            }
            TransportEvent::ConnectionStateChanged(state) => match state {
                ConnectionState::Failed => {
                    self.inject_transport_failed("peer connection failed", observer);
                }
                ConnectionState::Closed => {
                    // An abrupt close while a session is live is a
                    // transport failure; after our own teardown the
                    // machines are already terminal (guarded inside).
                    self.inject_transport_closed(observer);
                }
                _ => {}
            },
            TransportEvent::IceCandidate {
                candidate,
                sdp_mid,
                sdp_mline_index,
            } => {
                // Runtime-minted envelope (namespaced message id, QA F1).
                let Some(peer) = self.session_peer() else {
                    return;
                };
                self.ice_counter += 1;
                self.counters.ice_minted += 1;
                let machine = self.transport_owner;
                let envelope = SignalingEnvelope {
                    protocol_version: SIGNALING_PROTOCOL_VERSION,
                    message_id: format!("{}-rt-{}", self.device_id, self.ice_counter),
                    session_id: self.current_session_id(),
                    from_device_id: self.device_id.clone(),
                    to_device_id: peer,
                    timestamp_ms: self.clock.now_ms(),
                    body: SignalingBody::IceCandidate {
                        candidate,
                        sdp_mid,
                        sdp_mline_index,
                    },
                };
                if let Err(err) = self.signaling.send(machine, envelope) {
                    observer.transport_failure(&sanitize_reason(&format!("signaling: {err}")));
                }
            }
            TransportEvent::Failed { reason } => {
                observer.transport_failure(&sanitize_reason(&reason));
                self.inject_transport_failed(&reason, observer);
            }
            TransportEvent::LocalAnswer { .. } => {
                // Already sent by `Action::Send`; never logged (invariant 6).
            }
        }
    }

    /// `TransportFailed` is legal for the host in
    /// `Exchanging`/`Connecting`/`Connected` and for the controller in
    /// `Connecting`/`Connected`. In `Offering` there is no legal event —
    /// the connect timer is the documented recovery path there.
    fn inject_transport_failed(&mut self, reason: &str, observer: &mut dyn NodeObserver) {
        match self.host.state() {
            HostState::Exchanging { .. }
            | HostState::Connecting { .. }
            | HostState::Connected { .. } => {
                self.step_host(
                    HostEvent::TransportFailed {
                        reason: reason.to_owned(),
                    },
                    observer,
                );
                return;
            }
            _ => {}
        }
        match self.controller.state() {
            ControllerState::Connecting { .. } | ControllerState::Connected { .. } => {
                self.step_controller(
                    ControllerEvent::TransportFailed {
                        reason: reason.to_owned(),
                    },
                    observer,
                );
            }
            _ => {}
        }
    }

    /// Abrupt close (peer gone / local teardown of a live session).
    fn inject_transport_closed(&mut self, observer: &mut dyn NodeObserver) {
        self.inject_transport_failed("connection closed", observer);
    }

    // ------------------------------------------------------------------
    // Action execution
    // ------------------------------------------------------------------

    fn step_host(&mut self, event: HostEvent, observer: &mut dyn NodeObserver) {
        let before = self.host.state().name().to_owned();
        let now = self.clock.now_ms();
        match self.host.step(event, now) {
            Ok(actions) => self.apply(MachineKind::Host, actions, observer),
            Err(err) => {
                self.counters.illegal_transitions += 1;
                observer.illegal_transition(MachineKind::Host, err.state, err.event);
            }
        }
        let after = self.host.state().name().to_owned();
        if before != after {
            observer.state_changed(MachineKind::Host, &after);
        }
    }

    fn step_controller(&mut self, event: ControllerEvent, observer: &mut dyn NodeObserver) {
        let before = self.controller.state().name().to_owned();
        let now = self.clock.now_ms();
        match self.controller.step(event, now) {
            Ok(actions) => self.apply(MachineKind::Controller, actions, observer),
            Err(err) => {
                self.counters.illegal_transitions += 1;
                observer.illegal_transition(MachineKind::Controller, err.state, err.event);
            }
        }
        let after = self.controller.state().name().to_owned();
        if before != after {
            observer.state_changed(MachineKind::Controller, &after);
        }
    }

    fn apply(
        &mut self,
        machine: MachineKind,
        actions: Vec<Action>,
        observer: &mut dyn NodeObserver,
    ) {
        for action in actions {
            match action {
                Action::Send(envelope) => {
                    let is_register = envelope.to_device_id == SIGNALING_SERVICE_ID
                        && matches!(envelope.body, SignalingBody::Register { .. });
                    // F27: the self-ack is queued only after the adapter
                    // write succeeded — a failed Register write leaves the
                    // machine in `Registering` (the UI can retry), never a
                    // phantom `Online`.
                    match self.signaling.send(machine, envelope) {
                        Ok(()) => {
                            self.counters.envelopes_sent += 1;
                            if is_register {
                                // The adapter stands in for the service: a
                                // successful write acks on the next pump.
                                self.pending_register_acks.push_back(machine);
                            }
                        }
                        Err(err) => {
                            self.counters.send_errors += 1;
                            observer
                                .transport_failure(&sanitize_reason(&format!("signaling: {err}")));
                        }
                    }
                }
                Action::ScheduleTimer { id, fire_at_ms } => {
                    self.timers.schedule(machine, id, fire_at_ms);
                }
                Action::CancelTimer { id } => {
                    self.timers.cancel(machine, id);
                }
                Action::PromptConsent {
                    controller_device_id,
                    session_id,
                } => {
                    observer.prompt_consent(&controller_device_id, &session_id);
                }
                Action::ComposeAnswer { offer_sdp } => {
                    match self.transport_as_mut() {
                        Some(transport) => match transport.compose_answer(&offer_sdp) {
                            Ok(sdp) => {
                                // Feed the produced answer back into the
                                // machine (it mints the Send action).
                                self.step_host(HostEvent::AnswerComposed { sdp }, observer);
                            }
                            Err(err) => {
                                self.counters.compose_errors += 1;
                                observer.transport_failure(&sanitize_reason(&err.0));
                                // `TransportFailed` is legal in
                                // `Exchanging`: map the failure directly.
                                self.step_host(
                                    HostEvent::TransportFailed { reason: err.0 },
                                    observer,
                                );
                            }
                        },
                        None => self.counters.transport_missing += 1,
                    }
                }
                Action::ComposeOffer => {
                    match self.transport_as_mut() {
                        Some(transport) => match transport.compose_offer() {
                            Ok(sdp) => {
                                self.step_controller(
                                    ControllerEvent::OfferComposed { sdp },
                                    observer,
                                );
                            }
                            Err(err) => {
                                self.counters.compose_errors += 1;
                                observer.transport_failure(&sanitize_reason(&err.0));
                                // No legal TransportFailed in Offering: the
                                // connect timer owns recovery (documented).
                            }
                        },
                        None => self.counters.transport_missing += 1,
                    }
                }
                Action::ForwardIce {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                } => {
                    self.counters.ice_forwarded += 1;
                    match self.transport_as_mut() {
                        Some(transport) => {
                            if let Err(err) = transport.add_remote_candidate(
                                &candidate,
                                sdp_mid.as_deref(),
                                sdp_mline_index,
                            ) {
                                self.counters.ice_forward_errors += 1;
                                observer.transport_failure(&sanitize_reason(&err.0));
                            }
                        }
                        None => self.counters.transport_missing += 1,
                    }
                }
                Action::StartStreaming => observer.start_streaming(),
                Action::StopStreaming => observer.stop_streaming(),
                Action::StartRendering => observer.start_rendering(),
                Action::StopRendering => observer.stop_rendering(),
                Action::SessionEstablished { session_id } => {
                    // Controller sends the direct-path Hello right after
                    // establishment (capability re-negotiation, spike
                    // behavior).
                    if machine == MachineKind::Controller
                        && let Some(caps) = self.controller_caps.clone()
                    {
                        let _ = self.send_wire(
                            Channel::Control,
                            &WireMessage::Hello { capabilities: caps },
                        );
                        self.counters.hello_sent += 1;
                    }
                    observer.session_established(&session_id);
                }
                Action::SessionEnded { cause } => observer.session_ended(&cause),
            }
        }
    }

    // ------------------------------------------------------------------
    // Collision helpers (World parity)
    // ------------------------------------------------------------------

    /// Controller has an outbound session toward `device`?
    fn controller_calling(&self, device: &str) -> bool {
        match self.controller.state() {
            ControllerState::Requesting { session }
            | ControllerState::Offering { session }
            | ControllerState::Connecting { session } => session.peer_device_id == device,
            _ => false,
        }
    }

    fn controller_outbound_peer(&self) -> Option<String> {
        match self.controller.state() {
            ControllerState::Requesting { session }
            | ControllerState::Offering { session }
            | ControllerState::Connecting { session } => Some(session.peer_device_id.clone()),
            _ => None,
        }
    }

    /// Does this node's host hold an inbound session toward `device`?
    fn host_sessioned_with(&self, device: &str) -> bool {
        match self.host.state() {
            HostState::ConsentPrompted { info } => info.controller_device_id == device,
            HostState::Exchanging { session }
            | HostState::Connecting { session }
            | HostState::Connected { session } => session.peer_device_id == device,
            _ => false,
        }
    }

    // ------------------------------------------------------------------
    // Transport passthrough (the embedding loop owns cadence)
    // ------------------------------------------------------------------

    pub fn attach_transport(&mut self, transport: Box<dyn Transport>) {
        self.transport = Some(transport);
    }

    /// Declare which role's machine owns the attached transport (the tag
    /// on runtime-minted ICE envelopes; see `transport_owner`). Call right
    /// after `attach_transport`.
    pub fn set_transport_owner(&mut self, owner: MachineKind) {
        self.transport_owner = owner;
    }

    pub fn take_transport(&mut self) -> Option<Box<dyn Transport>> {
        self.transport.take()
    }

    pub fn has_transport(&self) -> bool {
        self.transport.is_some()
    }

    fn transport_as_mut(&mut self) -> Option<&mut Box<dyn Transport>> {
        self.transport.as_mut()
    }

    /// Drain transport events into the node (convenience for the pump
    /// loop; bounded by the transport's own event queue).
    pub fn poll_transport(&mut self, observer: &mut dyn NodeObserver) {
        while let Some(event) = self.transport.as_mut().and_then(|t| t.poll()) {
            self.transport_event(event, observer);
        }
    }

    /// Network-change entry point (M5 wires the real policy; MVP: the
    /// rig tears down and re-establishes through the machines).
    pub fn restart_ice(&mut self) -> Result<(), TransportError> {
        match self.transport_as_mut() {
            Some(transport) => transport.restart_ice(),
            None => Err(TransportError("no transport".into())),
        }
    }

    /// Hard teardown of the live transport (simulated interface loss):
    /// closes it and maps the loss to the machine exactly as a peer-gone
    /// `Closed` would.
    pub fn teardown_transport(&mut self, reason: &str, observer: &mut dyn NodeObserver) {
        if let Some(mut transport) = self.transport.take() {
            transport.close();
        }
        self.channel_open_order.clear();
        self.inject_transport_failed(reason, observer);
    }

    /// Typed local-failure session end (M6 soak F71): a host-side
    /// pipeline death (capture dead, encoder device lost) must end the
    /// session through the machines instead of freezing it `Connected`.
    /// Injects `TransportFailed` WITHOUT closing the transport first, so
    /// a best-effort wire goodbye sent just before this call still has a
    /// chance to reach the peer (the session-end handling then closes the
    /// transport as usual). The host machine fires `StopStreaming`, the
    /// signaling `Disconnect{TransportError}`, and
    /// `SessionEnded{TransportError}`; the UI's `session-ended` event and
    /// the controller's own teardown follow from those.
    pub fn fail_session(&mut self, reason: &str, observer: &mut dyn NodeObserver) {
        self.inject_transport_failed(reason, observer);
    }

    /// Send one wire message on a channel (encoded here).
    pub fn send_wire(
        &mut self,
        channel: Channel,
        message: &WireMessage,
    ) -> Result<(), TransportError> {
        self.counters.wire_sent += 1;
        match self.transport_as_mut() {
            Some(transport) => transport.send(channel, &protocol::wire::encode(message)),
            None => Err(TransportError("no transport".into())),
        }
    }

    /// Send pre-encoded bytes (the rig's chaos injector transforms the
    /// encoded form).
    pub fn send_wire_bytes(
        &mut self,
        channel: Channel,
        bytes: &[u8],
    ) -> Result<(), TransportError> {
        self.counters.wire_sent += 1;
        match self.transport_as_mut() {
            Some(transport) => transport.send(channel, bytes),
            None => Err(TransportError("no transport".into())),
        }
    }

    pub fn send_video(&mut self, frame: VideoFrame) -> Result<(), TransportError> {
        match self.transport_as_mut() {
            Some(transport) => transport.send_video(frame),
            None => Err(TransportError("no transport".into())),
        }
    }

    pub fn poll_video(&mut self) -> Option<ReceivedFrame> {
        self.transport.as_mut().and_then(|t| t.poll_video())
    }

    pub fn stats(&mut self) -> Result<TransportStats, TransportError> {
        match self.transport_as_mut() {
            Some(transport) => transport.stats(),
            None => Err(TransportError("no transport".into())),
        }
    }

    /// Cheap channel-queue gauges for per-change sampling (M2 QA F32);
    /// see `Transport::channel_queue_gauges`.
    pub fn channel_queue_gauges(&mut self) -> Option<transport_webrtc::ChannelQueues> {
        self.transport
            .as_mut()
            .and_then(|transport| transport.channel_queue_gauges())
    }

    /// Drain the channel depth-change trail (M6 QA F63) plus the transport
    /// uptime its entries are stamped on — consumers anchor the entries
    /// onto their own session clock by differencing.
    pub fn channel_depth_trail(&mut self) -> (Vec<transport_webrtc::ChannelDepthSample>, u64) {
        match self.transport.as_mut() {
            Some(transport) => {
                let samples = transport.take_channel_depth_trail();
                let uptime = transport.uptime_ns();
                (samples, uptime)
            }
            None => (Vec::new(), 0),
        }
    }

    /// Close the transport without touching the machines (clean end of
    /// run; the machines should already be `Disconnected`).
    pub fn close_transport(&mut self) {
        if let Some(mut transport) = self.transport.take() {
            transport.close();
        }
    }

    /// Signaling adapter description (diagnostics; no secrets).
    pub fn signaling_description(&self) -> String {
        self.signaling.describe()
    }
}

/// Invariant-6 choke point (QA F36b): transport/signaling error strings
/// embed upstream `Display` text; if an upstream error ever includes SDP
/// content, the marker lines are replaced wholesale before the reason
/// reaches an observer (and through it, logs).
fn sanitize_reason(reason: &str) -> String {
    const MARKERS: [&str; 5] = [
        "a=ice-pwd",
        "a=ice-ufrag",
        "a=fingerprint",
        "o=-",
        "ice-pwd:",
    ];
    let tainted = MARKERS.iter().any(|m| reason.contains(m));
    if tainted {
        "<redacted: error text contained SDP material>".to_owned()
    } else {
        reason.to_owned()
    }
}

fn host_heartbeat_legal(state: &HostState) -> bool {
    matches!(
        state,
        HostState::Online
            | HostState::ConsentPrompted { .. }
            | HostState::Exchanging { .. }
            | HostState::Connecting { .. }
            | HostState::Connected { .. }
    )
}

fn controller_heartbeat_legal(state: &ControllerState) -> bool {
    matches!(
        state,
        ControllerState::Online
            | ControllerState::Requesting { .. }
            | ControllerState::Offering { .. }
            | ControllerState::Connecting { .. }
            | ControllerState::Connected { .. }
    )
}
