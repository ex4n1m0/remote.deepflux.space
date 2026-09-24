//! Real-transport integration: two `Node`s in one process, each with a
//! real `WebrtcTransport` over loopback UDP, signaling through the
//! in-memory hub — the rig's connection path as a test (delta D2's
//! automation layer, one level below the two-process file rig).
//!
//! Proves: offer/answer/candidate flow executes through the session
//! machines (`Action`-driven, never direct transport calls), connect time
//! inside the < 5 s budget, a wire message crossing controller→host, and a
//! clean disconnect with both machines ending in the right states.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use node_runtime::clock::MonotonicClock;
use node_runtime::node::{Node, NodeObserver};
use node_runtime::signaling::SignalingHub;
use node_runtime::timers::MachineKind;
use protocol::capabilities::{
    Capabilities, EncoderCapabilities, EncoderKind, FeatureFlags, MonitorInfo,
};
use protocol::signaling::SessionSecret;
use protocol::wire::{ButtonState, InputEvent, MouseButton, WireMessage};
use session::{ControllerState, DisconnectCause, HostState, SessionConfig};
use transport_webrtc::{Channel, WebrtcTransport, WebrtcTransportRole};

fn caps(controller: bool) -> Capabilities {
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

#[derive(Default, Clone)]
struct Rec {
    log: Arc<Mutex<Vec<String>>>,
    inputs: Arc<Mutex<Vec<InputEvent>>>,
    keyframes: Arc<AtomicBool>,
}

impl NodeObserver for Rec {
    fn session_established(&mut self, session_id: &str) {
        self.log
            .lock()
            .expect("rec")
            .push(format!("established {session_id}"));
    }

    fn session_ended(&mut self, cause: &DisconnectCause) {
        self.log
            .lock()
            .expect("rec")
            .push(format!("ended {cause:?}"));
    }

    fn start_streaming(&mut self) {
        self.log.lock().expect("rec").push("start_streaming".into());
    }

    fn stop_streaming(&mut self) {
        self.log.lock().expect("rec").push("stop_streaming".into());
    }

    fn start_rendering(&mut self) {
        self.log.lock().expect("rec").push("start_rendering".into());
    }

    fn stop_rendering(&mut self) {
        self.log.lock().expect("rec").push("stop_rendering".into());
    }

    fn wire_received(&mut self, _channel: Channel, message: &WireMessage) {
        if let WireMessage::Input(event) = message {
            self.inputs.lock().expect("rec").push(event.clone());
        }
    }

    fn keyframe_requested(&mut self) {
        self.keyframes.store(true, Ordering::Release);
    }

    fn illegal_transition(&mut self, machine: MachineKind, state: &str, event: &str) {
        self.log
            .lock()
            .expect("rec")
            .push(format!("illegal {machine:?} {event} in {state}"));
    }
}

struct Side {
    node: Node,
    rec: Rec,
}

fn side(hub: &SignalingHub, device: &str, host_role: bool) -> Side {
    let role = if host_role {
        WebrtcTransportRole::Host
    } else {
        WebrtcTransportRole::Controller
    };
    let transport = WebrtcTransport::new(role).expect("transport build");
    let mut node = Node::new(
        device,
        SessionConfig::default(),
        Arc::new(MonotonicClock::new()),
        Box::new(hub.clone().attach(device)),
    );
    node.attach_transport(Box::new(transport));
    Side {
        node,
        rec: Rec::default(),
    }
}

/// Pump both nodes until `pred` or timeout. Returns false on timeout.
fn pump_until(
    controller: &mut Side,
    host: &mut Side,
    timeout: Duration,
    pred: impl Fn(&Side, &Side) -> bool,
) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        let mut c_obs = controller.rec.clone();
        controller.node.pump(&mut c_obs);
        controller.node.poll_transport(&mut c_obs);
        let mut h_obs = host.rec.clone();
        host.node.pump(&mut h_obs);
        host.node.poll_transport(&mut h_obs);
        if pred(controller, host) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

#[test]
fn nodes_drive_real_webrtc_transports_to_connected_and_back() {
    let hub = SignalingHub::new();
    let mut controller = side(&hub, "test-controller", false);
    let mut host = side(&hub, "test-host", true);

    // Register both roles (service-swallowed; self-acked on next pump).
    {
        let mut obs = controller.rec.clone();
        controller.node.controller_start(caps(true), &mut obs);
    }
    {
        let mut obs = host.rec.clone();
        host.node.host_start(caps(false), &mut obs);
    }
    assert!(pump_until(
        &mut controller,
        &mut host,
        Duration::from_secs(5),
        |c, h| {
            c.node.controller_state().name() == "Online" && h.node.host_state().name() == "Online"
        }
    ));

    // Connect: the controller machine initiates; the runtime auto-accepts.
    let connect_started = Instant::now();
    {
        let mut obs = controller.rec.clone();
        controller.node.controller_connect("test-host", &mut obs);
    }
    let accepted = Arc::new(AtomicBool::new(false));
    let accepted_flag = Arc::clone(&accepted);
    // Wait for the host prompt, then accept.
    assert!(
        pump_until(
            &mut controller,
            &mut host,
            Duration::from_secs(5),
            |_, h| { matches!(h.node.host_state(), HostState::ConsentPrompted { .. }) }
        ),
        "host must prompt"
    );
    if !accepted_flag.load(Ordering::Acquire) {
        accepted_flag.store(true, Ordering::Release);
        let mut obs = host.rec.clone();
        host.node
            .user_accept_consent(SessionSecret("integration-secret".into()), &mut obs);
    }
    let _ = accepted;

    assert!(
        pump_until(
            &mut controller,
            &mut host,
            Duration::from_secs(10),
            |c, h| {
                matches!(c.node.controller_state(), ControllerState::Connected { .. })
                    && matches!(h.node.host_state(), HostState::Connected { .. })
            }
        ),
        "both sides must connect (controller {:?}, host {:?})",
        controller.node.controller_state(),
        host.node.host_state()
    );
    let connect_ms = connect_started.elapsed().as_millis();
    println!("connect: {connect_ms} ms (budget 5000)");
    assert!(connect_ms < 5_000, "connect budget blown: {connect_ms} ms");
    assert!(
        controller
            .rec
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("start_rendering"))
    );
    assert!(
        host.rec
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("start_streaming"))
    );

    // A wire message crosses controller → host over input-reliable.
    {
        controller
            .node
            .send_wire(
                Channel::InputReliable,
                &WireMessage::Input(InputEvent::MouseButton {
                    seq: 1,
                    button: MouseButton::Left,
                    state: ButtonState::Pressed,
                }),
            )
            .expect("send wire");
    }
    assert!(pump_until(
        &mut controller,
        &mut host,
        Duration::from_secs(5),
        |_, h| { h.rec.inputs.lock().unwrap().len() == 1 }
    ));
    // Also the fast channel.
    {
        controller
            .node
            .send_wire(
                Channel::InputFast,
                &WireMessage::Input(InputEvent::MouseMove {
                    seq: 2,
                    x: 1000,
                    y: 2000,
                }),
            )
            .expect("send fast wire");
    }
    assert!(pump_until(
        &mut controller,
        &mut host,
        Duration::from_secs(5),
        |_, h| { h.rec.inputs.lock().unwrap().len() == 2 }
    ));

    // Clean disconnect from the controller.
    {
        let mut obs = controller.rec.clone();
        controller.node.controller_disconnect(&mut obs);
    }
    assert!(pump_until(
        &mut controller,
        &mut host,
        Duration::from_secs(5),
        |c, h| {
            matches!(
                c.node.controller_state(),
                ControllerState::Disconnected {
                    cause: DisconnectCause::User
                }
            ) && matches!(
                h.node.host_state(),
                HostState::Disconnected {
                    cause: DisconnectCause::Peer
                }
            )
        }
    ));
    assert!(
        controller
            .rec
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("stop_rendering"))
    );
    assert!(
        host.rec
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("stop_streaming"))
    );
    assert!(controller.node.timers().is_empty());
    assert!(host.node.timers().is_empty());

    controller.node.close_transport();
    host.node.close_transport();
}
