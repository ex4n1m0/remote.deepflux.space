//! Deterministic two-peer (and three-peer) session simulation — the M0 exit
//! gate test: "two simulated peers driven by a scripted event interleaving
//! complete a full session deterministically".
//!
//! The `World` here doubles as the reference model for the M2 node runtime:
//! it owns the virtual clock, the timer queue, envelope routing between
//! peers, and the two node-level rules that span the host and controller
//! machines of one device (simultaneous-call collision detection). No real
//! clocks, no network, no threads — running a scenario twice must produce an
//! identical transcript.

use protocol::capabilities::{
    Capabilities, EncoderCapabilities, EncoderKind, FeatureFlags, MonitorInfo,
};
use protocol::signaling::{
    DeviceId, DisconnectReason, RejectReason, SIGNALING_PROTOCOL_VERSION, SessionSecret,
    SignalingBody, SignalingEnvelope,
};
use session::{
    Action, ControllerEvent, ControllerState, DisconnectCause, HostEvent, HostState, SessionConfig,
    TimerId,
};

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

struct Peer {
    id: DeviceId,
    host: session::HostSession,
    controller: session::ControllerSession,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MachineRef {
    Host,
    Controller,
}

impl MachineRef {
    fn name(self) -> &'static str {
        match self {
            MachineRef::Host => "host",
            MachineRef::Controller => "controller",
        }
    }
}

struct Timer {
    at: u64,
    seq: usize,
    peer: usize,
    machine: MachineRef,
    id: TimerId,
}

struct World {
    peers: Vec<Peer>,
    timers: Vec<Timer>,
    next_timer_seq: usize,
    now: u64,
    /// Every envelope ever sent, with its origin, for duplicate-redelivery
    /// tests. `SignalingEnvelope`'s `Debug` redacts secrets, so transcripts
    /// derived from it stay safe to print (invariant 6).
    sent: Vec<(usize, MachineRef, SignalingEnvelope)>,
    transcript: Vec<String>,
}

impl World {
    fn new(ids: &[&str]) -> Self {
        let cfg = SessionConfig::default();
        let peers = ids
            .iter()
            .map(|id| Peer {
                id: (*id).to_owned(),
                host: session::HostSession::new((*id).to_owned(), cfg.clone()),
                controller: session::ControllerSession::new((*id).to_owned(), cfg.clone()),
            })
            .collect();
        Self {
            peers,
            timers: Vec::new(),
            next_timer_seq: 0,
            now: 0,
            sent: Vec::new(),
            transcript: Vec::new(),
        }
    }

    fn log(&mut self, line: String) {
        self.transcript.push(format!("t={} {}", self.now, line));
    }

    fn step_host(&mut self, peer: usize, event: HostEvent) {
        let actions = self.peers[peer]
            .host
            .step(event, self.now)
            .expect("host transition must be legal in a scripted scenario");
        self.apply(peer, MachineRef::Host, actions);
    }

    fn step_controller(&mut self, peer: usize, event: ControllerEvent) {
        let actions = self.peers[peer]
            .controller
            .step(event, self.now)
            .expect("controller transition must be legal in a scripted scenario");
        self.apply(peer, MachineRef::Controller, actions);
    }

    /// `Connect` with the node-level simultaneous-call rule (QA F2: the full
    /// window). If this node's host already has an inbound session (prompt,
    /// exchange, or connect) with the same peer our controller just started
    /// calling, the controller must run the device-id tie-break. (The mirror
    /// case — a request arriving while we are already calling — is handled
    /// in `route`.)
    fn controller_connect(&mut self, peer: usize, host_device_id: &str) {
        self.step_controller(
            peer,
            ControllerEvent::Connect {
                host_device_id: host_device_id.to_owned(),
            },
        );
        let outbound = match self.peers[peer].controller.state() {
            ControllerState::Requesting { session }
            | ControllerState::Offering { session }
            | ControllerState::Connecting { session } => Some(session.peer_device_id.clone()),
            _ => None,
        };
        let Some(target) = outbound else { return };
        if self.host_sessioned_with(peer, &target) {
            self.step_controller(
                peer,
                ControllerEvent::CollisionDetected {
                    peer_device_id: target,
                },
            );
        }
    }

    /// Does this node's host hold an inbound session toward `device`?
    fn host_sessioned_with(&self, peer: usize, device: &str) -> bool {
        match self.peers[peer].host.state() {
            HostState::ConsentPrompted { info } => info.controller_device_id == device,
            HostState::Exchanging { session }
            | HostState::Connecting { session }
            | HostState::Connected { session } => session.peer_device_id == device,
            _ => false,
        }
    }

    fn register_all(&mut self) {
        self.now = 100;
        for peer in 0..self.peers.len() {
            self.step_host(
                peer,
                HostEvent::Start {
                    capabilities: caps(),
                },
            );
            self.step_controller(
                peer,
                ControllerEvent::Start {
                    capabilities: caps(),
                },
            );
        }
        self.now = 150;
        for peer in 0..self.peers.len() {
            self.step_host(peer, HostEvent::Registered);
            self.step_controller(peer, ControllerEvent::Registered);
        }
    }

    fn apply(&mut self, peer: usize, machine: MachineRef, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Send(env) => {
                    self.log(format!(
                        "tx peer{}:{} -> {} {:?}",
                        peer,
                        machine.name(),
                        env.to_device_id,
                        env.body
                    ));
                    self.sent.push((peer, machine, env.clone()));
                    self.route(env, machine);
                }
                Action::ScheduleTimer { id, fire_at_ms } => {
                    self.timers.push(Timer {
                        at: fire_at_ms,
                        seq: self.next_timer_seq,
                        peer,
                        machine,
                        id,
                    });
                    self.next_timer_seq += 1;
                }
                Action::CancelTimer { id } => {
                    self.timers
                        .retain(|t| !(t.peer == peer && t.machine == machine && t.id == id));
                }
                other => {
                    self.log(format!("local peer{}:{} {other:?}", peer, machine.name()));
                }
            }
        }
    }

    fn route(&mut self, env: SignalingEnvelope, from_machine: MachineRef) {
        if env.to_device_id == protocol::signaling::SIGNALING_SERVICE_ID {
            self.log("service swallowed".to_owned());
            return;
        }
        let target = self
            .peers
            .iter()
            .position(|p| p.id == env.to_device_id)
            .unwrap_or_else(|| panic!("unknown target device {}", env.to_device_id));
        let from: DeviceId = env.from_device_id.clone();

        match env.body {
            SignalingBody::ConnectRequest { .. } => {
                self.step_host(
                    target,
                    HostEvent::IncomingRequest {
                        message_id: env.message_id,
                        controller_device_id: from.clone(),
                        session_id: env.session_id.unwrap_or_default(),
                    },
                );
                // Mirror half of the node-level collision rule (QA F2): a
                // request arrived from a peer our controller has an outbound
                // session with — including after our own request was already
                // accepted (mailbox latency / stale redelivery).
                let calling = match self.peers[target].controller.state() {
                    ControllerState::Requesting { session }
                    | ControllerState::Offering { session }
                    | ControllerState::Connecting { session } => session.peer_device_id == from,
                    _ => false,
                };
                if calling {
                    self.step_controller(
                        target,
                        ControllerEvent::CollisionDetected {
                            peer_device_id: from,
                        },
                    );
                }
            }
            SignalingBody::Accept { session_secret } => {
                self.step_controller(
                    target,
                    ControllerEvent::AcceptReceived {
                        message_id: env.message_id,
                        session_secret,
                    },
                );
            }
            SignalingBody::Reject { reason } => {
                self.step_controller(
                    target,
                    ControllerEvent::RejectReceived {
                        message_id: env.message_id,
                        reason,
                    },
                );
            }
            SignalingBody::Offer { sdp } => {
                self.step_host(
                    target,
                    HostEvent::OfferReceived {
                        message_id: env.message_id,
                        sdp,
                    },
                );
            }
            SignalingBody::Answer { sdp } => {
                self.step_controller(
                    target,
                    ControllerEvent::AnswerReceived {
                        message_id: env.message_id,
                        sdp,
                    },
                );
            }
            SignalingBody::Cancel { .. } => {
                // Host policy treats all cancel reasons alike; the harness
                // reuses the User discriminant for the event.
                self.step_host(
                    target,
                    HostEvent::CancelReceived {
                        message_id: env.message_id,
                        reason: protocol::signaling::CancelReason::User,
                    },
                );
            }
            SignalingBody::Disconnect { .. } => match from_machine {
                // A host hangs up → the controller learns; and vice versa.
                MachineRef::Host => self.step_controller(
                    target,
                    ControllerEvent::DisconnectReceived {
                        message_id: env.message_id,
                        reason: DisconnectReason::User,
                    },
                ),
                MachineRef::Controller => self.step_host(
                    target,
                    HostEvent::DisconnectReceived {
                        message_id: env.message_id,
                        reason: DisconnectReason::User,
                    },
                ),
            },
            // Candidates route ROLE-COMPLEMENTARILY (M2 QA F34): the
            // offer/answer split gives each machine ownership of its own
            // role's transport, so a candidate gathered by the peer's
            // host-role transport must reach this node's *controller*
            // machine (whose `ForwardIce` feeds the controller transport),
            // and vice versa. Every scripted scenario below also injects
            // candidates directly in this shape — this arm was dead code
            // encoding the opposite (role-preserving) mapping.
            SignalingBody::IceCandidate {
                candidate,
                sdp_mid,
                sdp_mline_index,
            } => match from_machine {
                MachineRef::Host => self.step_controller(
                    target,
                    ControllerEvent::IceCandidateReceived {
                        message_id: env.message_id,
                        candidate,
                        sdp_mid,
                        sdp_mline_index,
                    },
                ),
                MachineRef::Controller => self.step_host(
                    target,
                    HostEvent::IceCandidateReceived {
                        message_id: env.message_id,
                        candidate,
                        sdp_mid,
                        sdp_mline_index,
                    },
                ),
            },
            SignalingBody::IceComplete | SignalingBody::Error { .. } => {
                self.log("ice/error envelope: informational only".to_owned());
            }
            SignalingBody::Register { .. } | SignalingBody::Heartbeat => {
                unreachable!("service-directed envelopes are handled above");
            }
        }
    }

    /// Fire all timers due at or before `deadline`, in (fire-at, schedule)
    /// order, advancing the logical clock. Deterministic by construction.
    fn run_until(&mut self, deadline: u64) {
        while let Some(index) = self
            .timers
            .iter()
            .enumerate()
            .filter(|(_, t)| t.at <= deadline)
            .min_by_key(|(_, t)| (t.at, t.seq))
            .map(|(i, _)| i)
        {
            let timer = self.timers.remove(index);
            self.now = self.now.max(timer.at);
            self.log(format!(
                "timer {:?} fired peer{}:{}",
                timer.id,
                timer.peer,
                timer.machine.name()
            ));
            match (timer.machine, timer.id) {
                (MachineRef::Host, TimerId::HostConsent) => {
                    self.step_host(timer.peer, HostEvent::ConsentTimeout)
                }
                (MachineRef::Host, TimerId::HostConnect) => {
                    self.step_host(timer.peer, HostEvent::ConnectTimeout)
                }
                (MachineRef::Controller, TimerId::ControllerRequest) => {
                    self.step_controller(timer.peer, ControllerEvent::RequestTimeout)
                }
                (MachineRef::Controller, TimerId::ControllerConnect) => {
                    self.step_controller(timer.peer, ControllerEvent::ConnectTimeout)
                }
                // Timer ids are machine-specific by construction.
                _ => unreachable!("timer/machine pairing mismatch"),
            }
        }
        self.now = self.now.max(deadline);
    }

    fn redeliver(&mut self, index: usize) {
        let (_, machine, env) = self.sent[index].clone();
        self.log(format!(
            "redelivering duplicate {}/{}",
            env.from_device_id, env.message_id
        ));
        self.route(env, machine);
    }
}

// ---------------------------------------------------------------- scenarios

fn happy_path() -> (World, SessionSecret) {
    let mut w = World::new(&["device-a", "device-b"]);
    w.register_all();

    // Controller A asks to control host B.
    w.now = 200;
    w.controller_connect(0, "device-b");
    assert!(matches!(
        w.peers[1].host.state(),
        HostState::ConsentPrompted { .. }
    ));

    // Host user accepts with a one-time secret.
    let secret = SessionSecret("0f4a9b2c-one-time".to_owned());
    w.now = 300;
    w.step_host(
        1,
        HostEvent::ConsentAccepted {
            secret: secret.clone(),
        },
    );
    assert!(matches!(
        w.peers[0].controller.state(),
        ControllerState::Offering { .. }
    ));

    // Transport composes offer/answer (M2 wires webrtc-rs here).
    w.now = 310;
    w.step_controller(
        0,
        ControllerEvent::OfferComposed {
            sdp: "v=0 offer-a".to_owned(),
        },
    );
    w.now = 320;
    w.step_host(
        1,
        HostEvent::AnswerComposed {
            sdp: "v=0 answer-b".to_owned(),
        },
    );

    // One trickle candidate each way, then the channel opens. Routed
    // through `route` (F34): the peer's host-role candidate reaches the
    // controller machine, the peer's controller-role candidate reaches the
    // host machine — the same role-complementary shape the direct
    // injections below the F34 fix encoded.
    w.now = 330;
    let ice_a = SignalingEnvelope {
        protocol_version: SIGNALING_PROTOCOL_VERSION,
        message_id: "ice-a-1".to_owned(),
        session_id: Some("device-a-ctrl-1".to_owned()),
        from_device_id: "device-a".to_owned(),
        to_device_id: "device-b".to_owned(),
        timestamp_ms: w.now,
        body: SignalingBody::IceCandidate {
            candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".to_owned(),
            sdp_mid: Some("0".to_owned()),
            sdp_mline_index: Some(0),
        },
    };
    let ice_b = SignalingEnvelope {
        protocol_version: SIGNALING_PROTOCOL_VERSION,
        message_id: "ice-b-1".to_owned(),
        session_id: Some("device-a-ctrl-1".to_owned()),
        from_device_id: "device-b".to_owned(),
        to_device_id: "device-a".to_owned(),
        timestamp_ms: w.now,
        body: SignalingBody::IceCandidate {
            candidate: "candidate:2 1 UDP 1 10.0.0.2 5001 typ host".to_owned(),
            sdp_mid: Some("0".to_owned()),
            sdp_mline_index: Some(0),
        },
    };
    w.route(ice_a, MachineRef::Controller);
    w.route(ice_b, MachineRef::Host);
    w.now = 340;
    w.step_controller(0, ControllerEvent::DataChannelOpen);
    w.step_host(1, HostEvent::DataChannelOpen);
    (w, secret)
}

#[test]
fn two_simulated_peers_complete_a_full_session_deterministically() {
    let (w, secret) = happy_path();

    let ControllerState::Connected { session: a_session } = w.peers[0].controller.state() else {
        panic!(
            "controller A must be Connected, is {:?}",
            w.peers[0].controller.state()
        )
    };
    let HostState::Connected { session: b_session } = w.peers[1].host.state() else {
        panic!("host B must be Connected, is {:?}", w.peers[1].host.state())
    };
    // Same session, agreed by both sides, secret handed over exactly once.
    assert_eq!(a_session.session_id, b_session.session_id);
    assert_eq!(a_session.peer_device_id, "device-b");
    assert_eq!(b_session.peer_device_id, "device-a");
    assert_eq!(a_session.secret, Some(secret.clone()));
    assert_eq!(b_session.secret, Some(secret));

    // Local pipelines started on the right sides.
    let joined = w.transcript.join("\n");
    assert!(joined.contains("StartRendering"));
    assert!(joined.contains("StartStreaming"));
    assert!(joined.contains("SessionEstablished"));

    // Determinism: a second run must produce an identical transcript.
    let (w2, _) = happy_path();
    assert_eq!(w.transcript, w2.transcript, "scenario is not deterministic");
}

#[test]
fn duplicate_envelope_delivery_is_a_no_op_everywhere() {
    let (mut w, _) = happy_path();
    let accept_index = w
        .sent
        .iter()
        .position(|(_, _, env)| matches!(env.body, SignalingBody::Accept { .. }))
        .expect("an Accept envelope was sent");
    let transcript_len = w.transcript.len();
    let sent_len = w.sent.len();

    w.now = 500;
    w.redeliver(accept_index);

    assert_eq!(w.sent.len(), sent_len, "duplicate produced new sends");
    assert!(
        w.transcript.len() > transcript_len,
        "only the redelivery log line"
    );
    assert!(matches!(
        w.peers[0].controller.state(),
        ControllerState::Connected { .. }
    ));
    assert!(matches!(
        w.peers[1].host.state(),
        HostState::Connected { .. }
    ));

    // Also duplicate the connect_request at the host: must not re-prompt.
    let request_index = w
        .sent
        .iter()
        .position(|(_, _, env)| matches!(env.body, SignalingBody::ConnectRequest { .. }))
        .expect("a ConnectRequest envelope was sent");
    w.redeliver(request_index);
    assert!(matches!(
        w.peers[1].host.state(),
        HostState::Connected { .. }
    ));
    let prompts = w
        .transcript
        .iter()
        .filter(|line| line.contains("PromptConsent"))
        .count();
    assert_eq!(prompts, 1, "duplicate must not re-prompt");
}

#[test]
fn host_disconnect_reaches_controller_and_stops_pipelines() {
    let (mut w, _) = happy_path();
    w.now = 600;
    w.step_host(1, HostEvent::Stop);
    assert!(matches!(
        w.peers[1].host.state(),
        HostState::Disconnected {
            cause: DisconnectCause::User
        }
    ));
    assert!(matches!(
        w.peers[0].controller.state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Peer
        }
    ));
    let joined = w.transcript.join("\n");
    assert!(joined.contains("StopStreaming"));
    assert!(joined.contains("StopRendering"));
}

#[test]
fn rejection_path_ends_controller_with_typed_cause() {
    let mut w = World::new(&["device-a", "device-b"]);
    w.register_all();
    w.now = 200;
    w.controller_connect(0, "device-b");
    w.now = 300;
    w.step_host(1, HostEvent::ConsentRejected);

    assert!(matches!(
        w.peers[0].controller.state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Rejected(RejectReason::Declined)
        }
    ));
    assert_eq!(w.peers[1].host.state().name(), "Online");
    assert!(w.timers.is_empty(), "all timers must be canceled");
}

#[test]
fn request_and_consent_timeouts_fire_in_schedule_order() {
    let mut w = World::new(&["device-a", "device-b"]);
    w.register_all();
    w.now = 200;
    w.controller_connect(0, "device-b");

    // request_timeout (10s) fires before consent_timeout (30s).
    w.run_until(11_000);
    assert!(matches!(
        w.peers[0].controller.state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Timeout
        }
    ));
    assert!(matches!(
        w.peers[1].host.state(),
        HostState::ConsentPrompted { .. }
    ));

    w.run_until(40_000);
    assert_eq!(w.peers[1].host.state().name(), "Online");
    assert!(w.timers.is_empty());
}

#[test]
fn controller_cancel_returns_host_to_online() {
    let mut w = World::new(&["device-a", "device-b"]);
    w.register_all();
    w.now = 200;
    w.controller_connect(0, "device-b");
    w.now = 250;
    w.step_controller(0, ControllerEvent::Cancel);

    assert!(matches!(
        w.peers[0].controller.state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Canceled
        }
    ));
    assert_eq!(w.peers[1].host.state().name(), "Online");
    assert!(w.timers.is_empty());
}

/// F34: trickled candidates route role-complementarily through the
/// harness's own `route` — the peer's host-gathered candidate reaches this
/// node's controller machine and vice versa, and BOTH `ForwardIce` actions
/// fire on the transport-owning machines (the routing the node runtime
/// implements and the real offer/answer split requires).
#[test]
fn trickled_candidates_route_to_the_transport_owner_both_directions() {
    let scenario = || {
        let mut w = World::new(&["device-a", "device-b"]);
        w.register_all();
        w.now = 200;
        w.controller_connect(0, "device-b");
        w.now = 300;
        w.step_host(
            1,
            HostEvent::ConsentAccepted {
                secret: SessionSecret("ice-secret".to_owned()),
            },
        );
        // Controller A's transport gathers a candidate -> host B's machine.
        // Host B's transport gathers a candidate -> controller A's machine.
        w.now = 330;
        let a_to_b = SignalingEnvelope {
            protocol_version: SIGNALING_PROTOCOL_VERSION,
            message_id: "ice-a-1".to_owned(),
            session_id: Some("device-a-ctrl-1".to_owned()),
            from_device_id: "device-a".to_owned(),
            to_device_id: "device-b".to_owned(),
            timestamp_ms: w.now,
            body: SignalingBody::IceCandidate {
                candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".to_owned(),
                sdp_mid: Some("0".to_owned()),
                sdp_mline_index: Some(0),
            },
        };
        let b_to_a = SignalingEnvelope {
            protocol_version: SIGNALING_PROTOCOL_VERSION,
            message_id: "ice-b-1".to_owned(),
            session_id: Some("device-a-ctrl-1".to_owned()),
            from_device_id: "device-b".to_owned(),
            to_device_id: "device-a".to_owned(),
            timestamp_ms: w.now,
            body: SignalingBody::IceCandidate {
                candidate: "candidate:2 1 UDP 1 10.0.0.2 5001 typ host".to_owned(),
                sdp_mid: Some("0".to_owned()),
                sdp_mline_index: Some(0),
            },
        };
        w.route(a_to_b.clone(), MachineRef::Controller);
        w.route(b_to_a.clone(), MachineRef::Host);
        w
    };
    let w = scenario();
    // Both machines are in candidate-legal states and each forwarded the
    // peer-transport's candidate to its OWN transport (ForwardIce on the
    // controller machine of A and on the host machine of B).
    let joined = w.transcript.join("\n");
    let ctrl_forwards = joined
        .lines()
        .filter(|l| l.contains("local peer0:controller ForwardIce"))
        .count();
    let host_forwards = joined
        .lines()
        .filter(|l| l.contains("local peer1:host ForwardIce"))
        .count();
    assert_eq!(
        ctrl_forwards, 1,
        "A's controller forwards B's host candidate"
    );
    assert_eq!(
        host_forwards, 1,
        "B's host forwards A's controller candidate"
    );
    // Neither wrong-side machine saw a candidate (no illegal transition,
    // no swallowed error in the transcript).
    assert!(w.transcript.iter().all(|line| !line.contains("illegal")));
    // Deterministic across runs.
    assert_eq!(w.transcript, scenario().transcript);
}

#[test]
fn simultaneous_calls_resolve_deterministically_by_device_id() {
    let scenario = || {
        let mut w = World::new(&["device-a", "device-b"]);
        w.register_all();
        // Both sides call each other at the same logical instant.
        w.now = 200;
        w.controller_connect(0, "device-b");
        w.controller_connect(1, "device-a");
        // The surviving flow: host B accepts controller A's request.
        w.now = 300;
        w.step_host(
            1,
            HostEvent::ConsentAccepted {
                secret: SessionSecret("collision-secret".to_owned()),
            },
        );
        w.now = 310;
        w.step_controller(
            0,
            ControllerEvent::OfferComposed {
                sdp: "v=0 offer".to_owned(),
            },
        );
        w.now = 320;
        w.step_host(
            1,
            HostEvent::AnswerComposed {
                sdp: "v=0 answer".to_owned(),
            },
        );
        w.now = 330;
        w.step_controller(0, ControllerEvent::DataChannelOpen);
        w.step_host(1, HostEvent::DataChannelOpen);
        w
    };

    let w = scenario();
    // device-a < device-b → device-a keeps the controller role.
    assert!(matches!(
        w.peers[0].controller.state(),
        ControllerState::Connected { .. }
    ));
    assert!(matches!(
        w.peers[1].host.state(),
        HostState::Connected { .. }
    ));
    // The loser's controller canceled with the collision cause; the winner's
    // host side returned Online after the loser's cancel cleaned its prompt.
    assert!(matches!(
        w.peers[1].controller.state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Collision
        }
    ));
    assert_eq!(w.peers[0].host.state().name(), "Online");

    // Deterministic across runs.
    assert_eq!(w.transcript, scenario().transcript);
}

#[test]
fn busy_host_rejects_a_second_controller() {
    let mut w = World::new(&["device-a", "device-b", "device-c"]);
    w.register_all();
    w.now = 200;
    w.controller_connect(0, "device-b");
    w.now = 210;
    w.controller_connect(2, "device-b");

    assert!(matches!(
        w.peers[1].host.state(),
        HostState::ConsentPrompted { .. }
    ));
    assert!(matches!(
        w.peers[2].controller.state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Rejected(RejectReason::Busy)
        }
    ));
    // The first controller's session is unaffected.
    assert!(matches!(
        w.peers[0].controller.state(),
        ControllerState::Requesting { .. }
    ));

    // QA F10: the busy Reject is keyed to the *refused* controller's session
    // id (device-c's), never to the pending one (device-a's).
    let c_request = w
        .sent
        .iter()
        .find(|(_, _, env)| {
            env.from_device_id == "device-c"
                && matches!(env.body, SignalingBody::ConnectRequest { .. })
        })
        .map(|(_, _, env)| env.session_id.clone())
        .expect("device-c sent a connect_request");
    let busy_reject = w
        .sent
        .iter()
        .find(|(_, _, env)| {
            env.to_device_id == "device-c"
                && matches!(
                    env.body,
                    SignalingBody::Reject {
                        reason: RejectReason::Busy
                    }
                )
        })
        .map(|(_, _, env)| env.session_id.clone())
        .expect("host sent a busy Reject to device-c");
    assert_eq!(
        busy_reject, c_request,
        "busy reject must carry the requester's session id"
    );
}

/// QA F1: the two role machines of one device run in one process and must
/// never mint the same `message_id` — the signaling service dedupes on it
/// process-wide. The harness used to swallow service-directed envelopes, so
/// this collided silently (`device-a-1` from both roles).
#[test]
fn message_ids_are_unique_across_both_roles_of_one_device() {
    let (w, _) = happy_path();
    let mut seen = std::collections::HashSet::new();
    let mut total = 0;
    for (_, _, env) in &w.sent {
        total += 1;
        assert!(
            seen.insert(env.message_id.clone()),
            "duplicate message_id minted: {}",
            env.message_id
        );
    }
    assert!(
        total >= 8,
        "expected the happy-path envelope count, got {total}"
    );
    // Spot-check the F1 shape: role-namespaced ids from the same device.
    assert!(
        w.sent
            .iter()
            .any(|(_, _, env)| env.message_id.starts_with("device-a-host-")),
        "host-role ids must be namespaced"
    );
    assert!(
        w.sent
            .iter()
            .any(|(_, _, env)| env.message_id.starts_with("device-a-ctrl-")),
        "controller-role ids must be namespaced"
    );
}

/// QA F2: the peer's `connect_request` can arrive *after* our own request was
/// already accepted (mailbox latency / stale redelivery). The tie-break must
/// still fire in `Offering`/`Connecting`: the loser (larger device id)
/// cancels its accepted session, exactly one session survives, and no
/// `IllegalTransition` occurs.
#[test]
fn late_peer_request_after_accept_still_hits_the_tie_break() {
    let scenario = || {
        let mut w = World::new(&["device-a", "device-b"]);
        w.register_all();
        // device-a calls device-b; host b accepts quickly.
        w.now = 200;
        w.controller_connect(0, "device-b");
        w.now = 300;
        w.step_host(
            1,
            HostEvent::ConsentAccepted {
                secret: SessionSecret("late-collision-secret".to_owned()),
            },
        );
        // device-b's own request only *now* reaches device-a's host — after
        // a.controller is already Offering.
        w.now = 400;
        w.controller_connect(1, "device-a");
        // The surviving flow completes.
        w.now = 410;
        w.step_controller(
            0,
            ControllerEvent::OfferComposed {
                sdp: "v=0 offer".to_owned(),
            },
        );
        w.now = 420;
        w.step_host(
            1,
            HostEvent::AnswerComposed {
                sdp: "v=0 answer".to_owned(),
            },
        );
        w.now = 430;
        w.step_controller(0, ControllerEvent::DataChannelOpen);
        w.step_host(1, HostEvent::DataChannelOpen);
        w
    };

    let w = scenario();
    // device-a (< device-b) keeps the controller role and is connected to
    // device-b's host; device-b's controller abandoned its accepted session.
    assert!(matches!(
        w.peers[0].controller.state(),
        ControllerState::Connected { .. }
    ));
    assert!(matches!(
        w.peers[1].host.state(),
        HostState::Connected { .. }
    ));
    assert!(matches!(
        w.peers[1].controller.state(),
        ControllerState::Disconnected {
            cause: DisconnectCause::Collision
        }
    ));
    // device-a's host dropped device-b's stale prompt and returned Online.
    assert_eq!(w.peers[0].host.state().name(), "Online");
    // Deterministic across runs.
    assert_eq!(w.transcript, scenario().transcript);
}
