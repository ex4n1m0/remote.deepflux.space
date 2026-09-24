//! World-parity tests for `node_runtime::Node` — the executable spec is
//! `crates/session/tests/two_peers.rs`; these prove the runtime reproduces
//! its semantics against the real clock/timer plumbing (here driven by
//! [`ManualClock`] so transcripts stay deterministic), the
//! [`SignalingHub`], and a scripted `Transport` double.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use node_runtime::clock::ManualClock;
use node_runtime::node::{Node, NodeObserver};
use node_runtime::signaling::{InboundEnvelope, SignalingHub};
use node_runtime::timers::MachineKind;
use protocol::capabilities::{
    Capabilities, EncoderCapabilities, EncoderKind, FeatureFlags, MonitorInfo,
};
use protocol::signaling::SessionSecret;
use session::{ControllerState, DisconnectCause, HostState, SessionConfig};
use transport_webrtc::{Channel, Transport, TransportError, TransportEvent, TransportStats};

// ---------------------------------------------------------------- fixtures

fn caps() -> Capabilities {
    Capabilities {
        encoders: vec![EncoderCapabilities {
            kind: EncoderKind::Hardware,
            codec: protocol::capabilities::Codec::H264,
            max_width_px: 2560,
            max_height_px: 1440,
            max_fps: 60,
        }],
        monitors: vec![MonitorInfo {
            monitor_id: "\\\\.\\DISPLAY1".to_owned(),
            width_px: 2560,
            height_px: 1440,
            is_primary: true,
        }],
        max_bitrate_kbps: 15_000,
        features: FeatureFlags::empty().with(FeatureFlags::INPUT_FAST_CHANNEL),
    }
}

/// Scripted transport double: deterministic fake SDPs, no network. Enough
/// to drive offer/answer/candidate actions through the machines.
struct ScriptedTransport {
    offers: AtomicU64,
    answers: AtomicU64,
    candidates: AtomicU64,
    sends: AtomicU64,
}

impl ScriptedTransport {
    fn new() -> Box<Self> {
        Box::new(Self {
            offers: AtomicU64::new(0),
            answers: AtomicU64::new(0),
            candidates: AtomicU64::new(0),
            sends: AtomicU64::new(0),
        })
    }
}

impl Transport for ScriptedTransport {
    fn compose_offer(&mut self) -> Result<String, TransportError> {
        let n = self.offers.fetch_add(1, Ordering::Relaxed);
        Ok(format!("v=0 scripted-offer-{n}"))
    }

    fn compose_answer(&mut self, offer: &str) -> Result<String, TransportError> {
        let n = self.answers.fetch_add(1, Ordering::Relaxed);
        Ok(format!("v=0 scripted-answer-{n}-for-{offer}"))
    }

    fn apply_answer(&mut self, _answer: &str) -> Result<(), TransportError> {
        Ok(())
    }

    fn add_remote_candidate(
        &mut self,
        _candidate: &str,
        _sdp_mid: Option<&str>,
        _sdp_mline_index: Option<u16>,
    ) -> Result<(), TransportError> {
        self.candidates.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn send(&mut self, _channel: Channel, _bytes: &[u8]) -> Result<(), TransportError> {
        self.sends.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn poll(&mut self) -> Option<TransportEvent> {
        None
    }

    fn stats(&mut self) -> Result<TransportStats, TransportError> {
        Ok(TransportStats::default())
    }

    fn close(&mut self) {}
}

/// Records node effects (a transcript) for assertions.
#[derive(Default, Clone)]
struct Recorder {
    log: Arc<Mutex<Vec<String>>>,
    prompts: Arc<AtomicU64>,
}

impl Recorder {
    fn new() -> Self {
        Self::default()
    }

    fn contains(&self, needle: &str) -> bool {
        self.log
            .lock()
            .expect("recorder")
            .iter()
            .any(|line| line.contains(needle))
    }

    fn count(&self, needle: &str) -> usize {
        self.log
            .lock()
            .expect("recorder")
            .iter()
            .filter(|line| line.contains(needle))
            .count()
    }
}

impl NodeObserver for Recorder {
    fn state_changed(&mut self, machine: MachineKind, state: &str) {
        self.log
            .lock()
            .expect("recorder")
            .push(format!("{:?} -> {state}", machine));
    }

    fn prompt_consent(&mut self, controller_device_id: &str, session_id: &str) {
        self.prompts.fetch_add(1, Ordering::Relaxed);
        self.log
            .lock()
            .expect("recorder")
            .push(format!("PromptConsent {controller_device_id} {session_id}"));
    }

    fn session_established(&mut self, session_id: &str) {
        self.log
            .lock()
            .expect("recorder")
            .push(format!("SessionEstablished {session_id}"));
    }

    fn session_ended(&mut self, cause: &DisconnectCause) {
        self.log
            .lock()
            .expect("recorder")
            .push(format!("SessionEnded {cause:?}"));
    }

    fn start_streaming(&mut self) {
        self.log
            .lock()
            .expect("recorder")
            .push("StartStreaming".into());
    }

    fn stop_streaming(&mut self) {
        self.log
            .lock()
            .expect("recorder")
            .push("StopStreaming".into());
    }

    fn start_rendering(&mut self) {
        self.log
            .lock()
            .expect("recorder")
            .push("StartRendering".into());
    }

    fn stop_rendering(&mut self) {
        self.log
            .lock()
            .expect("recorder")
            .push("StopRendering".into());
    }

    fn transport_failure(&mut self, reason: &str) {
        self.log
            .lock()
            .expect("recorder")
            .push(format!("TransportFailure {reason}"));
    }

    fn illegal_transition(&mut self, machine: MachineKind, state: &str, event: &str) {
        self.log
            .lock()
            .expect("recorder")
            .push(format!("IllegalTransition {machine:?} {event} in {state}"));
    }
}

/// One device: both role machines (World parity), manual clock, hub
/// endpoint, scripted transport, and a recorder.
struct TestNode {
    node: Node,
    clock: Arc<ManualClock>,
    recorder: Recorder,
}

impl TestNode {
    fn attach(hub: &SignalingHub, device: &str) -> Self {
        let clock = Arc::new(ManualClock::new());
        let recorder = Recorder::new();
        let mut node = Node::new(
            device,
            SessionConfig::default(),
            clock.clone(),
            Box::new(hub.clone().attach(device)),
        );
        node.attach_transport(ScriptedTransport::new());
        Self {
            node,
            clock,
            recorder,
        }
    }

    fn pump(&mut self) {
        let mut observer = self.recorder.clone();
        self.node.pump(&mut observer);
    }

    fn accept_consent(&mut self, secret: &str) {
        let mut observer = self.recorder.clone();
        self.node
            .user_accept_consent(SessionSecret(secret.to_owned()), &mut observer);
    }

    fn controller_connect(&mut self, host: &str) {
        let mut observer = self.recorder.clone();
        self.node.controller_connect(host, &mut observer);
    }

    fn controller_cancel(&mut self) {
        let mut observer = self.recorder.clone();
        self.node.controller_cancel(&mut observer);
    }

    fn host_stop(&mut self) {
        let mut observer = self.recorder.clone();
        self.node.host_stop(&mut observer);
    }

    fn controller_disconnect(&mut self) {
        let mut observer = self.recorder.clone();
        self.node.controller_disconnect(&mut observer);
    }

    fn open_channels(&mut self) {
        let mut observer = self.recorder.clone();
        self.node
            .transport_event(TransportEvent::ChannelsOpen, &mut observer);
    }

    fn transport_failed(&mut self, reason: &str) {
        let mut observer = self.recorder.clone();
        self.node.transport_event(
            TransportEvent::Failed {
                reason: reason.to_owned(),
            },
            &mut observer,
        );
    }
}

/// Drive both nodes' pumps so envelopes flow (hub delivers on send; pumps
/// consume). Two rounds cover request→prompt→accept→offer→answer.
fn settle(a: &mut TestNode, b: &mut TestNode) {
    for _ in 0..4 {
        a.pump();
        b.pump();
    }
}

fn register_both(nodes: [&mut TestNode; 2], at_ms: u64) {
    for node in nodes {
        node.clock.set_ms(at_ms);
        let mut observer = node.recorder.clone();
        node.node.host_start(caps(), &mut observer);
        node.node.controller_start(caps(), &mut observer);
        node.pump(); // Register envelopes → (service)
        node.pump(); // self-ack Registered
    }
}

fn happy_path() -> (TestNode, TestNode) {
    let hub = SignalingHub::new();
    let mut a = TestNode::attach(&hub, "device-a");
    let mut b = TestNode::attach(&hub, "device-b");
    register_both([&mut a, &mut b], 100);
    settle(&mut a, &mut b);

    // Controller A asks to control host B.
    a.clock.set_ms(200);
    b.clock.set_ms(200);
    a.controller_connect("device-b");
    settle(&mut a, &mut b);
    assert!(matches!(
        b.node.host_state(),
        HostState::ConsentPrompted { .. }
    ));

    // Host user accepts with a one-time secret.
    b.clock.set_ms(300);
    a.clock.set_ms(300);
    b.accept_consent("one-time-secret");
    settle(&mut a, &mut b);
    settle(&mut a, &mut b);
    // The full exchange (offer composed → sent → answered → applied) runs
    // within `settle`; both machines have crossed Offering into Connecting.
    assert!(matches!(
        a.node.controller_state(),
        ControllerState::Connecting { .. }
    ));
    assert!(matches!(b.node.host_state(), HostState::Connecting { .. }));

    // Channels open on both sides (per-channel readiness, not order).
    a.clock.set_ms(340);
    b.clock.set_ms(340);
    a.open_channels();
    b.open_channels();
    settle(&mut a, &mut b);
    (a, b)
}

// ---------------------------------------------------------------- scenarios

/// The M0 exit-gate scenario, now through the real runtime plumbing.
#[test]
fn two_nodes_complete_a_full_session_through_the_runtime() {
    let (mut a, mut b) = happy_path();

    let ControllerState::Connected { session: a_session } = a.node.controller_state() else {
        panic!(
            "controller A must be Connected, is {:?}",
            a.node.controller_state()
        )
    };
    let HostState::Connected { session: b_session } = b.node.host_state() else {
        panic!("host B must be Connected")
    };
    assert_eq!(a_session.session_id, b_session.session_id);
    assert_eq!(a_session.peer_device_id, "device-b");
    assert_eq!(b_session.peer_device_id, "device-a");
    // Secret handed over exactly once, both sides agree (value checked
    // without printing it).
    assert_eq!(
        a_session.secret.as_ref().map(|s| s.0.as_str()),
        Some("one-time-secret")
    );
    assert_eq!(
        b_session.secret.as_ref().map(|s| s.0.as_str()),
        Some("one-time-secret")
    );

    // Pipelines started on the right sides.
    assert!(a.recorder.contains("StartRendering"));
    assert!(a.recorder.contains("SessionEstablished"));
    assert!(b.recorder.contains("StartStreaming"));
    assert!(b.recorder.contains("SessionEstablished"));

    // All timers canceled on the connected path.
    assert!(a.node.timers().is_empty());
    assert!(b.node.timers().is_empty());

    // Clean disconnect: host stops sharing.
    b.host_stop();
    settle(&mut a, &mut b);
    assert!(matches!(
        b.node.host_state(),
        HostState::Disconnected {
            cause: DisconnectCause::User
        }
    ));
    assert!(matches!(
        a.node.controller_state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Peer
        }
    ));
    assert!(b.recorder.contains("StopStreaming"));
    assert!(a.recorder.contains("StopRendering"));
}

/// Duplicate envelope delivery is a no-op everywhere (machine dedupe).
#[test]
fn duplicate_envelope_delivery_is_a_no_op() {
    let hub = SignalingHub::new();
    let mut a = TestNode::attach(&hub, "device-a");
    let mut b = TestNode::attach(&hub, "device-b");
    register_both([&mut a, &mut b], 100);
    settle(&mut a, &mut b);
    a.controller_connect("device-b");
    settle(&mut a, &mut b);

    b.accept_consent("dup-secret");
    settle(&mut a, &mut b);
    let (sender, machine, env) = hub
        .sent_log()
        .into_iter()
        .find(|(_, _, env)| matches!(env.body, protocol::signaling::SignalingBody::Accept { .. }))
        .expect("an Accept envelope was sent");
    assert_eq!(sender, "device-b");
    assert_eq!(machine, MachineKind::Host);
    let inbound = InboundEnvelope {
        from_machine: machine,
        envelope: env,
    };
    let before = a.recorder.count("-> Connected");
    hub.redeliver("device-a", inbound.clone());
    hub.redeliver("device-a", inbound);
    settle(&mut a, &mut b);
    assert_eq!(
        a.recorder.count("-> Connected"),
        before,
        "duplicate Accept must not re-transition"
    );
    assert_eq!(a.node.counters().illegal_transitions, 0);

    // Also duplicate the connect_request at the host: must not re-prompt.
    let prompts_before = b.recorder.count("PromptConsent");
    let (_, machine, env) = hub
        .sent_log()
        .into_iter()
        .find(|(_, _, env)| {
            matches!(
                env.body,
                protocol::signaling::SignalingBody::ConnectRequest { .. }
            )
        })
        .expect("a ConnectRequest was sent");
    hub.redeliver(
        "device-b",
        InboundEnvelope {
            from_machine: machine,
            envelope: env,
        },
    );
    settle(&mut a, &mut b);
    assert_eq!(b.recorder.count("PromptConsent"), prompts_before);
}

/// Simultaneous calls resolve deterministically by device id (the full
/// node-level rule across both nodes).
#[test]
fn simultaneous_calls_resolve_deterministically_by_device_id() {
    let hub = SignalingHub::new();
    let mut a = TestNode::attach(&hub, "device-a");
    let mut b = TestNode::attach(&hub, "device-b");
    register_both([&mut a, &mut b], 100);
    settle(&mut a, &mut b);

    a.clock.set_ms(200);
    b.clock.set_ms(200);
    a.controller_connect("device-b");
    b.controller_connect("device-a");
    settle(&mut a, &mut b);

    // The surviving flow: host B accepts controller A's request.
    b.clock.set_ms(300);
    b.accept_consent("collision-secret");
    settle(&mut a, &mut b);
    a.open_channels();
    b.open_channels();
    settle(&mut a, &mut b);

    // device-a < device-b → device-a keeps the controller role.
    assert!(matches!(
        a.node.controller_state(),
        ControllerState::Connected { .. }
    ));
    assert!(matches!(b.node.host_state(), HostState::Connected { .. }));
    // The loser's controller canceled with the collision cause; the
    // winner's host side returned Online after the loser's cancel.
    assert!(matches!(
        b.node.controller_state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Collision
        }
    ));
    assert_eq!(a.node.host_state().name(), "Online");
    assert_eq!(a.node.counters().illegal_transitions, 0);
    assert_eq!(b.node.counters().illegal_transitions, 0);
}

/// QA F2 window: the peer's request arrives after our own was already
/// accepted — the tie-break still fires in `Offering`.
#[test]
fn late_peer_request_after_accept_still_hits_the_tie_break() {
    let hub = SignalingHub::new();
    let mut a = TestNode::attach(&hub, "device-a");
    let mut b = TestNode::attach(&hub, "device-b");
    register_both([&mut a, &mut b], 100);
    settle(&mut a, &mut b);

    a.clock.set_ms(200);
    a.controller_connect("device-b");
    settle(&mut a, &mut b); // host B prompts
    b.clock.set_ms(300);
    b.accept_consent("late-secret");
    settle(&mut a, &mut b);
    // The full exchange (offer composed → sent → answered → applied) runs
    // within `settle`; both machines have crossed Offering into Connecting.
    assert!(matches!(
        a.node.controller_state(),
        ControllerState::Connecting { .. }
    ));
    assert!(matches!(b.node.host_state(), HostState::Connecting { .. }));

    // device-b's own request only now reaches device-a's host — after
    // a.controller is already Offering.
    b.clock.set_ms(400);
    b.controller_connect("device-a");
    settle(&mut a, &mut b);

    a.open_channels();
    b.open_channels();
    settle(&mut a, &mut b);

    assert!(matches!(
        a.node.controller_state(),
        ControllerState::Connected { .. }
    ));
    assert!(matches!(b.node.host_state(), HostState::Connected { .. }));
    assert!(matches!(
        b.node.controller_state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Collision
        }
    ));
    assert_eq!(a.node.host_state().name(), "Online");
    assert_eq!(b.node.counters().illegal_transitions, 0);
}

/// Request timeout (10 s) fires before consent timeout (30 s); both
/// leave empty timer queues behind.
#[test]
fn request_and_consent_timeouts_fire_in_schedule_order() {
    let hub = SignalingHub::new();
    let mut a = TestNode::attach(&hub, "device-a");
    let mut b = TestNode::attach(&hub, "device-b");
    register_both([&mut a, &mut b], 100);
    settle(&mut a, &mut b);
    a.controller_connect("device-b");
    settle(&mut a, &mut b);

    // Advance both clocks; run a's pump after each advance.
    a.clock.set_ms(11_000);
    a.pump();
    assert!(matches!(
        a.node.controller_state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Timeout
        }
    ));
    assert!(matches!(
        b.node.host_state(),
        HostState::ConsentPrompted { .. }
    ));
    assert!(a.node.timers().is_empty());

    b.clock.set_ms(40_000);
    b.pump();
    assert_eq!(b.node.host_state().name(), "Online");
    assert!(b.node.timers().is_empty());
}

/// Controller cancel returns the host to Online with clean timer state.
#[test]
fn controller_cancel_returns_host_to_online() {
    let hub = SignalingHub::new();
    let mut a = TestNode::attach(&hub, "device-a");
    let mut b = TestNode::attach(&hub, "device-b");
    register_both([&mut a, &mut b], 100);
    settle(&mut a, &mut b);
    a.controller_connect("device-b");
    settle(&mut a, &mut b);
    a.controller_cancel();
    settle(&mut a, &mut b);

    assert!(matches!(
        a.node.controller_state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Canceled
        }
    ));
    assert_eq!(b.node.host_state().name(), "Online");
    assert!(a.node.timers().is_empty());
    assert!(b.node.timers().is_empty());
}

/// Rejection path ends the controller with the typed cause.
#[test]
fn rejection_path_ends_controller_with_typed_cause() {
    let hub = SignalingHub::new();
    let mut a = TestNode::attach(&hub, "device-a");
    let mut b = TestNode::attach(&hub, "device-b");
    register_both([&mut a, &mut b], 100);
    settle(&mut a, &mut b);
    a.controller_connect("device-b");
    settle(&mut a, &mut b);

    let mut observer = b.recorder.clone();
    b.node.user_reject_consent(&mut observer);
    settle(&mut a, &mut b);

    assert!(matches!(
        a.node.controller_state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Rejected(protocol::signaling::RejectReason::Declined)
        }
    ));
    assert_eq!(b.node.host_state().name(), "Online");
    assert!(a.node.timers().is_empty());
}

/// Busy host rejects a second controller; the busy Reject is keyed to the
/// refused controller's session id (QA F10).
#[test]
fn busy_host_rejects_a_second_controller() {
    let hub = SignalingHub::new();
    let mut a = TestNode::attach(&hub, "device-a");
    let mut b = TestNode::attach(&hub, "device-b");
    let mut c = TestNode::attach(&hub, "device-c");
    for node in [&mut a, &mut b, &mut c] {
        node.clock.set_ms(100);
        let mut observer = node.recorder.clone();
        node.node.host_start(caps(), &mut observer);
        node.node.controller_start(caps(), &mut observer);
        node.pump();
        node.pump();
    }
    settle(&mut a, &mut b);
    settle(&mut b, &mut c);
    settle(&mut a, &mut c);

    a.clock.set_ms(200);
    a.controller_connect("device-b");
    c.clock.set_ms(210);
    c.controller_connect("device-b");
    settle(&mut a, &mut b);
    settle(&mut b, &mut c);
    settle(&mut a, &mut c);

    assert!(matches!(
        b.node.host_state(),
        HostState::ConsentPrompted { .. }
    ));
    assert!(matches!(
        c.node.controller_state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Rejected(protocol::signaling::RejectReason::Busy)
        }
    ));
    assert!(matches!(
        a.node.controller_state(),
        ControllerState::Requesting { .. }
    ));

    let busy = hub
        .sent_log()
        .into_iter()
        .find(|(_, _, env)| {
            env.to_device_id == "device-c"
                && matches!(
                    env.body,
                    protocol::signaling::SignalingBody::Reject {
                        reason: protocol::signaling::RejectReason::Busy
                    }
                )
        })
        .expect("busy reject sent to device-c");
    let request = hub
        .sent_log()
        .into_iter()
        .find(|(from, _, env)| {
            from == "device-c"
                && matches!(
                    env.body,
                    protocol::signaling::SignalingBody::ConnectRequest { .. }
                )
        })
        .expect("device-c sent a connect request");
    assert_eq!(
        busy.2.session_id, request.2.session_id,
        "busy reject must carry the requester's session id"
    );
}

/// QA F1: message ids are unique across both roles of one device.
#[test]
fn message_ids_are_unique_across_both_roles_of_one_device() {
    let hub = SignalingHub::new();
    let mut a = TestNode::attach(&hub, "device-a");
    let mut b = TestNode::attach(&hub, "device-b");
    register_both([&mut a, &mut b], 100);
    settle(&mut a, &mut b);
    a.controller_connect("device-b");
    settle(&mut a, &mut b);
    b.accept_consent("f1-secret");
    settle(&mut a, &mut b);
    a.open_channels();
    b.open_channels();
    settle(&mut a, &mut b);

    let sent = hub.sent_log();
    assert!(sent.len() >= 4, "expected the happy-path envelope count");
    let mut seen = std::collections::HashSet::new();
    for (_, _, env) in &sent {
        assert!(
            seen.insert(env.message_id.clone()),
            "duplicate message_id minted: {}",
            env.message_id
        );
    }
    assert!(
        sent.iter().any(
            |(from, _, env)| from == "device-a" && env.message_id.starts_with("device-a-ctrl-")
        ),
        "controller-role ids must be namespaced"
    );
    assert!(
        sent.iter().any(
            |(from, _, env)| from == "device-b" && env.message_id.starts_with("device-b-host-")
        ),
        "host-role ids must be namespaced"
    );
}

/// Transport failure mid-session maps to `TransportFailed`: machines go
/// `Disconnected{TransportError}`, pipelines stop, timers cancel.
#[test]
fn transport_failure_mid_session_maps_to_transport_failed() {
    let (mut a, mut b) = happy_path();
    assert!(matches!(
        a.node.controller_state(),
        ControllerState::Connected { .. }
    ));

    a.transport_failed("ice dead (test)");
    settle(&mut a, &mut b);

    assert!(matches!(
        a.node.controller_state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::TransportError
        }
    ));
    assert!(a.recorder.contains("StopRendering"));
    assert!(a.node.timers().is_empty());

    // The signaling Disconnect reaches the host.
    assert!(matches!(
        b.node.host_state(),
        HostState::Disconnected {
            cause: DisconnectCause::Peer
        }
    ));
    assert!(b.recorder.contains("StopStreaming"));
}

/// Runtime-minted ICE envelopes route role-complementarily: a host-role
/// candidate reaches the peer's controller machine and vice versa.
#[test]
fn ice_candidates_route_to_the_peer_transport_owner() {
    let hub = SignalingHub::new();
    let mut a = TestNode::attach(&hub, "device-a");
    let mut b = TestNode::attach(&hub, "device-b");
    register_both([&mut a, &mut b], 100);
    settle(&mut a, &mut b);
    a.controller_connect("device-b");
    settle(&mut a, &mut b); // host B prompts
    b.accept_consent("ice-secret");
    settle(&mut a, &mut b);
    // The whole exchange ran; both machines are Connecting.

    // The host's transport gathers a candidate.
    let mut observer = b.recorder.clone();
    b.node.transport_event(
        TransportEvent::IceCandidate {
            candidate: "candidate:2 1 UDP 1 10.0.0.2 5001 typ host".to_owned(),
            sdp_mid: Some("0".to_owned()),
            sdp_mline_index: Some(0),
        },
        &mut observer,
    );
    settle(&mut a, &mut b);
    // device-a's controller consumed it (ForwardIce → its transport).
    let forwarded_to_a = hub.sent_log().into_iter().any(|(from, machine, env)| {
        from == "device-b"
            && machine == MachineKind::Host
            && matches!(
                env.body,
                protocol::signaling::SignalingBody::IceCandidate { .. }
            )
            && env.to_device_id == "device-a"
    });
    assert!(
        forwarded_to_a,
        "host candidate must be signaled to device-a"
    );
    assert!(a.node.counters().ice_forwarded >= 1);
}

/// Heartbeat cadence is runtime-owned: HeartbeatDue fires on period while
/// Online, envelopes go to the (swallowed) service.
#[test]
fn heartbeat_cadence_raises_heartbeats_on_schedule() {
    let hub = SignalingHub::new();
    let mut a = TestNode::attach(&hub, "device-a");
    let mut b = TestNode::attach(&hub, "device-b");
    register_both([&mut a, &mut b], 100);
    settle(&mut a, &mut b);
    let before = hub.service_swallowed();
    a.clock.set_ms(15_200); // default period 15 s
    a.pump();
    assert!(a.node.counters().heartbeats_raised >= 1);
    assert!(hub.service_swallowed() > before);
}

/// Clean disconnect from the controller: signaling Disconnect + the
/// machines' teardown actions on both sides.
#[test]
fn controller_disconnect_ends_session_cleanly() {
    let (mut a, mut b) = happy_path();
    a.controller_disconnect();
    settle(&mut a, &mut b);
    assert!(matches!(
        a.node.controller_state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::User
        }
    ));
    assert!(matches!(
        b.node.host_state(),
        HostState::Disconnected {
            cause: DisconnectCause::Peer
        }
    ));
    assert!(a.node.timers().is_empty());
    assert!(b.node.timers().is_empty());
    assert!(a.recorder.contains("SessionEnded"));
    assert!(b.recorder.contains("SessionEnded"));
}

/// Late session traffic in Disconnected is tolerated (no-ops), matching
/// the machines' post-mortem rules.
#[test]
fn late_session_traffic_in_disconnected_is_tolerated() {
    let (mut a, mut b) = happy_path();
    a.controller_disconnect();
    settle(&mut a, &mut b);

    // A stray candidate from the transport while Disconnected:
    // post-mortem no-op, no illegal-transition errors (envelope-level
    // redelivery is covered in the duplicate test).
    let mut observer = a.recorder.clone();
    a.node.transport_event(
        TransportEvent::IceCandidate {
            candidate: "candidate:9 1 UDP 1 10.0.0.9 5009 typ host".to_owned(),
            sdp_mid: None,
            sdp_mline_index: None,
        },
        &mut observer,
    );
    a.pump();
    assert_eq!(a.node.counters().illegal_transitions, 0);
    let _ = &mut b;
}
