//! Two-node live integration against the REAL M3 signaling service (M3
//! gate: "a two-node connect through the real service, no file adapter").
//!
//! `#[ignore]`d — it needs the local rig running:
//!
//! ```bash
//! # terminal 1: store
//! node services/signaling/tools/upstash-emulator.mjs --port 38001
//! # terminal 2: the service (WS-capable standalone instance)
//! UPSTASH_REDIS_REST_URL=http://127.0.0.1:38001 UPSTASH_REDIS_REST_TOKEN=t \
//!   node --import tsx services/signaling/tools/dev-server.mjs --port 38013
//! # run (WS mode):
//! SIGNALING_TEST_BASE_URL=http://127.0.0.1:38013 \
//!   cargo test -p node-runtime --test remote_signaling_live -- --ignored --nocapture
//! # run (HTTP fallback mode; any instance, e.g. vercel dev):
//! SIGNALING_TEST_BASE_URL=http://127.0.0.1:38011 SIGNALING_TEST_HTTP_ONLY=1 \
//!   cargo test -p node-runtime --test remote_signaling_live -- --ignored --nocapture
//! ```
//!
//! The flow is the `world_parity` happy path driven over the network:
//! register both nodes, connect_request → consent → accept(+one-time
//! secret) → offer → answer → trickle ICE both directions → ChannelsOpen
//! (injected — the transport here is the scripted double; M2 proved the
//! real one) → Connected → clean disconnect, plus an end-to-end duplicate
//! probe (exact re-send of the accept envelope must be a service-side
//! dedupe no-op).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use node_runtime::clock::MonotonicClock;
use node_runtime::node::{NoObserver, Node, NodeObserver};
use node_runtime::signaling_remote::{RemoteSignaling, RemoteSignalingConfig};
use node_runtime::timers::MachineKind;
use protocol::capabilities::{
    Capabilities, EncoderCapabilities, EncoderKind, FeatureFlags, MonitorInfo,
};
use protocol::signaling::SessionSecret;
use session::{DisconnectCause, HostState, SessionConfig};
use transport_webrtc::{Channel, Transport, TransportError, TransportEvent, TransportStats};

// ---------------------------------------------------------------- fixtures

fn caps() -> Capabilities {
    Capabilities {
        encoders: vec![EncoderCapabilities {
            kind: EncoderKind::Software,
            codec: protocol::capabilities::Codec::H264,
            max_width_px: 1920,
            max_height_px: 1080,
            max_fps: 30,
        }],
        monitors: vec![MonitorInfo {
            monitor_id: "\\\\.\\DISPLAY1".to_owned(),
            width_px: 1920,
            height_px: 1080,
            is_primary: true,
        }],
        max_bitrate_kbps: 8_000,
        features: FeatureFlags::empty().with(FeatureFlags::TRICKLE_ICE),
    }
}

/// Scripted transport double (same contract as `world_parity`): fake SDPs,
/// counts applied candidates — enough to drive the machines through the
/// service and assert trickle delivery.
struct ScriptedTransport {
    candidates: AtomicU64,
}

impl ScriptedTransport {
    fn new() -> Box<Self> {
        Box::new(Self {
            candidates: AtomicU64::new(0),
        })
    }
}

impl Transport for ScriptedTransport {
    fn compose_offer(&mut self) -> Result<String, TransportError> {
        Ok("v=0 live-offer".to_owned())
    }

    fn compose_answer(&mut self, _offer: &str) -> Result<String, TransportError> {
        Ok("v=0 live-answer".to_owned())
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

#[derive(Default, Clone)]
struct Recorder {
    log: Arc<Mutex<Vec<String>>>,
    established: Arc<AtomicU64>,
    ended: Arc<Mutex<Vec<String>>>,
}

impl Recorder {
    fn has(&self, needle: &str) -> bool {
        self.log
            .lock()
            .expect("recorder")
            .iter()
            .any(|line| line.contains(needle))
    }

    fn ended_causes(&self) -> Vec<String> {
        self.ended.lock().expect("ended").clone()
    }
}

impl NodeObserver for Recorder {
    fn state_changed(&mut self, machine: MachineKind, state: &str) {
        self.log
            .lock()
            .expect("recorder")
            .push(format!("{machine:?}->{state}"));
    }

    fn prompt_consent(&mut self, controller: &str, _session: &str) {
        self.log
            .lock()
            .expect("recorder")
            .push(format!("PromptConsent({controller})"));
    }

    fn session_established(&mut self, _session: &str) {
        self.established.fetch_add(1, Ordering::Relaxed);
    }

    fn session_ended(&mut self, cause: &DisconnectCause) {
        self.ended.lock().expect("ended").push(format!("{cause:?}"));
    }

    fn transport_failure(&mut self, reason: &str) {
        self.log
            .lock()
            .expect("recorder")
            .push(format!("TransportFailure({reason})"));
    }

    fn illegal_transition(&mut self, machine: MachineKind, state: &str, event: &str) {
        self.log
            .lock()
            .expect("recorder")
            .push(format!("IllegalTransition({machine:?}, {state}, {event})"));
    }
}

struct LiveNode {
    node: Node,
    recorder: Recorder,
}

impl LiveNode {
    fn build(base: &str, device: &str, token: &str, owner: MachineKind, force_http: bool) -> Self {
        let mut cfg = RemoteSignalingConfig::new(base, device, token);
        cfg.force_http = force_http;
        let signaling = RemoteSignaling::new(cfg);
        let clock = Arc::new(MonotonicClock::new());
        let recorder = Recorder::default();
        let mut node = Node::new(device, SessionConfig::default(), clock, Box::new(signaling));
        node.attach_transport(ScriptedTransport::new());
        node.set_transport_owner(owner);
        Self { node, recorder }
    }

    fn pump(&mut self) {
        let mut observer = self.recorder.clone();
        self.node.pump(&mut observer);
    }
}

fn wait_for(what: &str, deadline: Instant, mut f: impl FnMut() -> bool) {
    while Instant::now() < deadline {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timeout waiting for {what}");
}

#[test]
#[ignore = "needs the local service rig; see module docs"]
fn two_nodes_connect_through_the_real_service() {
    // F44: skip-with-reason when the rig is not running, so
    // `cargo test --workspace -- --ignored` stays runnable bare (M2's
    // convention for live-hardware sweeps).
    let Ok(base) = std::env::var("SIGNALING_TEST_BASE_URL") else {
        eprintln!(
            "SKIP remote_signaling_live: SIGNALING_TEST_BASE_URL not set (start the rig per the module docs, then re-run with the env)"
        );
        return;
    };
    let force_http = std::env::var("SIGNALING_TEST_HTTP_ONLY").ok().as_deref() == Some("1");
    let run = std::process::id();
    let host_device = format!("live-host-{run}");
    let ctrl_device = format!("live-ctrl-{run}");
    let host_token = RemoteSignalingConfig::new_token();
    let ctrl_token = RemoteSignalingConfig::new_token();

    let t0 = Instant::now();
    let mut host = LiveNode::build(
        &base,
        &host_device,
        &host_token,
        MachineKind::Host,
        force_http,
    );
    let mut ctrl = LiveNode::build(
        &base,
        &ctrl_device,
        &ctrl_token,
        MachineKind::Controller,
        force_http,
    );

    let deadline = Instant::now() + Duration::from_secs(90);

    // 1. Both roles register (self-ack after the service accepts).
    host.node.host_start(caps(), &mut NoObserver);
    ctrl.node.controller_start(caps(), &mut NoObserver);
    eprintln!("[t] +{:?} registered-start; waiting Online", t0.elapsed());
    wait_for("both Online", deadline, || {
        host.pump();
        ctrl.pump();
        matches!(host.node.host_state(), HostState::Online)
            && ctrl.node.controller_state_name() == "Online"
    });
    assert!(
        !host.recorder.has("TransportFailure"),
        "host register failed"
    );
    assert!(
        !ctrl.recorder.has("TransportFailure"),
        "ctrl register failed"
    );

    // 2. Controller calls the host.
    eprintln!("[t] +{:?} Online", t0.elapsed());
    ctrl.node.controller_connect(&host_device, &mut NoObserver);
    wait_for("consent prompt", deadline, || {
        host.pump();
        ctrl.pump();
        host.recorder.has("PromptConsent")
    });

    // 3. Host accepts with a one-time secret (never logged; the recorder
    //    only ever sees state names).
    eprintln!("[t] +{:?} prompted", t0.elapsed());
    let secret = SessionSecret(format!("live-secret-{run}"));
    host.node.user_accept_consent(secret, &mut NoObserver);
    wait_for("controller Connecting after answer", deadline, || {
        host.pump();
        ctrl.pump();
        ctrl.node.controller_state_name() == "Connecting"
            && host.node.host_state_name() == "Connecting"
    });

    eprintln!("[t] +{:?} both Connecting", t0.elapsed());
    // 4. Trickle ICE both directions through the service.
    host.node.transport_event(
        TransportEvent::IceCandidate {
            candidate: "candidate:1 1 UDP 1 127.0.0.1 5000 typ host".to_owned(),
            sdp_mid: Some("0".to_owned()),
            sdp_mline_index: Some(0),
        },
        &mut NoObserver,
    );
    ctrl.node.transport_event(
        TransportEvent::IceCandidate {
            candidate: "candidate:2 1 UDP 1 127.0.0.1 5001 typ host".to_owned(),
            sdp_mid: Some("0".to_owned()),
            sdp_mline_index: Some(0),
        },
        &mut NoObserver,
    );
    // 5. Channels open on both sides (injected; transport is the double).
    host.node
        .transport_event(TransportEvent::ChannelsOpen, &mut NoObserver);
    ctrl.node
        .transport_event(TransportEvent::ChannelsOpen, &mut NoObserver);
    wait_for("both Connected", deadline, || {
        host.pump();
        ctrl.pump();
        host.node.host_state_name() == "Connected"
            && ctrl.node.controller_state_name() == "Connected"
    });
    // Trickle ICE actually crossed the service in both directions.
    eprintln!("[t] +{:?} both Connected", t0.elapsed());
    // Trickle is asynchronous: wait for both directions to be applied.
    wait_for("trickle ICE forwarded both ways", deadline, || {
        host.pump();
        ctrl.pump();
        host.node.counters().ice_forwarded >= 1 && ctrl.node.counters().ice_forwarded >= 1
    });
    assert_eq!(
        host.node.counters().illegal_transitions,
        0,
        "host illegal transitions"
    );
    assert_eq!(
        ctrl.node.counters().illegal_transitions,
        0,
        "ctrl illegal transitions"
    );

    // 6. Clean disconnect from the controller; host learns via the service.
    ctrl.node.controller_disconnect(&mut NoObserver);
    wait_for("both Disconnected", deadline, || {
        host.pump();
        ctrl.pump();
        host.node.host_state_name() == "Disconnected"
            && ctrl.node.controller_state_name() == "Disconnected"
    });
    let causes = host.recorder.ended_causes();
    assert!(
        causes.iter().any(|c| c.contains("Peer")),
        "host ended with peer cause, got {causes:?}"
    );

    // 7. End-to-end idempotency probe: re-send the exact accept envelope
    //    (controller already consumed it; the service must dedupe and the
    //    machine must stay Disconnected — post-mortem tolerance).
    let accept_env = protocol::signaling::SignalingEnvelope {
        protocol_version: protocol::signaling::SIGNALING_PROTOCOL_VERSION,
        message_id: format!("{host_device}-host-2"),
        session_id: Some(format!("{ctrl_device}-ctrl-1")),
        from_device_id: host_device.clone(),
        to_device_id: ctrl_device.clone(),
        timestamp_ms: 0,
        body: protocol::signaling::SignalingBody::Accept {
            session_secret: SessionSecret("duplicate-probe".to_owned()),
        },
    };
    let url = format!("{base}/api/signal?device_id={host_device}");
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();
    let reply = agent
        .post(&url)
        .set("authorization", &format!("Bearer {host_token}"))
        .set("content-type", "application/json")
        .send_string(&serde_json::json!({ "op": "send", "envelope": accept_env }).to_string())
        .expect("duplicate probe http")
        .into_json::<serde_json::Value>()
        .expect("duplicate probe json");
    assert_eq!(
        reply["duplicate"],
        serde_json::json!(true),
        "service deduped the accept"
    );
    for _ in 0..25 {
        ctrl.pump();
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        ctrl.node.controller_state_name(),
        "Disconnected",
        "redelivered accept is a post-mortem no-op"
    );
}
