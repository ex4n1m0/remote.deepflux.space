//! Engine state-flow tests: two engines over the in-memory signaling hub,
//! real transports (loopback ICE), no GPU pipelines (`real_pipelines:
//! false`) — the full connect → consent → accept → Connected →
//! quality/monitor on the wire → disconnect → auto-re-online chain,
//! asserted through the exact events/commands the Tauri layer uses.
//!
//! This pins the UI-facing state machine mapping to the `crates/session`
//! contract (the UI derives its views from these names and nothing else).

use std::time::{Duration, Instant};

use node_runtime::signaling::SignalingHub;
use remote_desktop_app_lib::engine::{self, EngineCmd, EngineConfig, EngineEvent};

const HOST_DEVICE: &str = "m4-test-host";
const CTRL_DEVICE: &str = "m4-test-ctrl";

fn spawn_engine(
    hub: &SignalingHub,
    device: &str,
) -> (engine::EngineHandle, std::sync::mpsc::Receiver<EngineEvent>) {
    let cfg = EngineConfig {
        device_id: device.to_owned(),
        signaling: Box::new(hub.clone().attach(device)),
        real_pipelines: false,
        real_input: false,
        auto_reonline: true,
        metrics_dir: None,
        status_file: None,
        viewer_title: "test".to_owned(),
        initial_quality: protocol::wire::QualityPreset::Low,
        initial_scale: render_windows::ScaleMode::Fit,
    };
    engine::spawn(cfg)
}

fn wait_for(what: &str, deadline: Instant, mut f: impl FnMut() -> bool) {
    while Instant::now() < deadline {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timeout waiting for {what}");
}

fn collect(events: &std::sync::mpsc::Receiver<EngineEvent>, sink: &mut Vec<EngineEvent>) {
    while let Ok(event) = events.try_recv() {
        sink.push(event);
    }
}

fn has_state(events: &[EngineEvent], machine: &str, state: &str) -> bool {
    events.iter().any(|event| {
        matches!(
            event,
            EngineEvent::StateChanged { machine: m, state: s, .. } if m == machine && s == state
        )
    })
}

#[test]
fn full_session_state_flow_through_the_command_layer() {
    let hub = SignalingHub::new();
    let (host, host_events) = spawn_engine(&hub, HOST_DEVICE);
    let (ctrl, ctrl_events) = spawn_engine(&hub, CTRL_DEVICE);
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut host_log = Vec::new();
    let mut ctrl_log = Vec::new();

    // 1. Host start → Online.
    host.send(EngineCmd::HostStart).expect("host start");
    wait_for("host Online", deadline, || {
        collect(&host_events, &mut host_log);
        host.status().host_state == "Online"
    });
    assert!(has_state(&host_log, "host", "Registering"));
    assert!(has_state(&host_log, "host", "Online"));

    // 2. Controller start → Online.
    ctrl.send(EngineCmd::ControllerStart)
        .expect("controller start");
    wait_for("controller Online", deadline, || {
        collect(&ctrl_events, &mut ctrl_log);
        ctrl.status().controller_state == "Online"
    });

    // 3. Connect → host ConsentPrompted + ConsentRequested event.
    ctrl.send(EngineCmd::Connect {
        code: HOST_DEVICE.to_owned(),
    })
    .expect("connect");
    wait_for("consent prompt", deadline, || {
        collect(&host_events, &mut host_log);
        host.status().host_state == "ConsentPrompted"
    });
    let consent = host_log.iter().find_map(|event| match event {
        EngineEvent::ConsentRequested {
            controller_device_id,
            session_id,
        } => Some((controller_device_id.clone(), session_id.clone())),
        _ => None,
    });
    let (consent_controller, consent_session) = consent.expect("ConsentRequested event");
    assert_eq!(consent_controller, CTRL_DEVICE);
    assert!(!consent_session.is_empty());
    // Peer-online surfaced for the favorites indicator.
    assert!(host_log.iter().any(|event| matches!(
        event,
        EngineEvent::PeerOnline { device_id } if device_id == CTRL_DEVICE
    )));

    // 4. Accept → both Connected (real loopback transport).
    host.send(EngineCmd::ConsentAccept).expect("accept");
    wait_for("both Connected", deadline, || {
        collect(&host_events, &mut host_log);
        collect(&ctrl_events, &mut ctrl_log);
        host.status().host_state == "Connected" && ctrl.status().controller_state == "Connected"
    });
    assert!(host_log.iter().any(|event| matches!(
        event,
        EngineEvent::SessionEstablished { session_id, .. } if *session_id == consent_session
    )));
    assert!(ctrl_log.iter().any(|event| matches!(
        event,
        EngineEvent::SessionEstablished { session_id, .. } if *session_id == consent_session
    )));

    // 5. Quality preset over the wire: the host records the preset and the
    //    rebuild counter (no pipeline to rebuild in this mode).
    ctrl.send(EngineCmd::SetQuality(
        protocol::wire::QualityPreset::Balanced,
    ))
    .expect("quality");
    wait_for("host applied quality", deadline, || {
        collect(&host_events, &mut host_log);
        host.status().quality == "balanced"
    });

    // 6. Monitor select over the wire.
    ctrl.send(EngineCmd::SelectMonitor {
        monitor_id: "\\\\.\\DISPLAY2".to_owned(),
    })
    .expect("monitor");
    wait_for("host applied monitor", deadline, || {
        collect(&host_events, &mut host_log);
        host.status().active_monitor.as_deref() == Some("\\\\.\\DISPLAY2")
    });

    // 7. Diagnostics events flow (1 Hz; numbers only).
    wait_for("controller diagnostics event", deadline, || {
        collect(&ctrl_events, &mut ctrl_log);
        ctrl_log
            .iter()
            .any(|event| matches!(event, EngineEvent::Diagnostics { .. }))
    });

    // 8. Disconnect → both Disconnected with the user-cause copy.
    ctrl.send(EngineCmd::Disconnect).expect("disconnect");
    wait_for("both Disconnected", deadline, || {
        collect(&host_events, &mut host_log);
        collect(&ctrl_events, &mut ctrl_log);
        host.status().host_state == "Disconnected"
            && ctrl.status().controller_state == "Disconnected"
    });
    let ended = ctrl_log.iter().find_map(|event| match event {
        EngineEvent::SessionEnded {
            code,
            message,
            hint,
            ..
        } => Some((code.clone(), message.clone(), hint.clone())),
        _ => None,
    });
    let (code, message, hint) = ended.expect("SessionEnded event on controller");
    assert_eq!(code, "user_disconnect");
    assert!(message.contains("You ended"));
    assert!(hint.is_none());
    // Peer-offline surfaced.
    assert!(host_log.iter().any(|event| matches!(
        event,
        EngineEvent::PeerOffline { device_id } if device_id == CTRL_DEVICE
    )));

    // 9. Auto re-online: the host returns Online (composition-driven
    //    `Start`, the rig's scripted recovery).
    wait_for("host back Online", deadline, || {
        collect(&host_events, &mut host_log);
        host.status().host_state == "Online"
    });
    assert!(has_state(&host_log, "host", "Disconnected"));
    assert!(has_state(&host_log, "host", "Registering"));

    host.shutdown();
    ctrl.shutdown();
}

#[test]
fn reject_leaves_host_online_and_controller_disconnected() {
    let hub = SignalingHub::new();
    let (host, host_events) = spawn_engine(&hub, HOST_DEVICE);
    let (ctrl, ctrl_events) = spawn_engine(&hub, CTRL_DEVICE);
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut host_log = Vec::new();
    let mut ctrl_log = Vec::new();

    host.send(EngineCmd::HostStart).expect("host start");
    ctrl.send(EngineCmd::ControllerStart)
        .expect("controller start");
    wait_for("both Online", deadline, || {
        collect(&host_events, &mut host_log);
        collect(&ctrl_events, &mut ctrl_log);
        host.status().host_state == "Online" && ctrl.status().controller_state == "Online"
    });
    ctrl.send(EngineCmd::Connect {
        code: HOST_DEVICE.to_owned(),
    })
    .expect("connect");
    wait_for("consent prompt", deadline, || {
        collect(&host_events, &mut host_log);
        host.status().host_state == "ConsentPrompted"
    });
    host.send(EngineCmd::ConsentReject).expect("reject");
    wait_for("reject resolved", deadline, || {
        collect(&host_events, &mut host_log);
        collect(&ctrl_events, &mut ctrl_log);
        host.status().host_state == "Online" && ctrl.status().controller_state == "Disconnected"
    });
    let ended = ctrl_log.iter().find_map(|event| match event {
        EngineEvent::SessionEnded { code, .. } => Some(code.clone()),
        _ => None,
    });
    assert_eq!(ended.as_deref(), Some("rejected"));

    host.shutdown();
    ctrl.shutdown();
}

/// F55: quitting mid-session must not leave the peer waiting on
/// transport-failure detection — the engine's graceful shutdown sends the
/// wire goodbye (+ `AllKeysUp`) before closing the transport, so the host
/// observes a prompt `Peer` disconnect, not a timeout.
#[test]
fn graceful_shutdown_mid_session_sends_the_peer_goodbye() {
    let hub = SignalingHub::new();
    let (host, host_events) = spawn_engine(&hub, HOST_DEVICE);
    let (ctrl, ctrl_events) = spawn_engine(&hub, CTRL_DEVICE);
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut host_log = Vec::new();
    let mut ctrl_log = Vec::new();

    host.send(EngineCmd::HostStart).expect("host start");
    ctrl.send(EngineCmd::ControllerStart)
        .expect("controller start");
    wait_for("both Online", deadline, || {
        collect(&host_events, &mut host_log);
        collect(&ctrl_events, &mut ctrl_log);
        host.status().host_state == "Online" && ctrl.status().controller_state == "Online"
    });
    ctrl.send(EngineCmd::Connect {
        code: HOST_DEVICE.to_owned(),
    })
    .expect("connect");
    wait_for("consent prompt", deadline, || {
        collect(&host_events, &mut host_log);
        host.status().host_state == "ConsentPrompted"
    });
    host.send(EngineCmd::ConsentAccept).expect("accept");
    wait_for("both Connected", deadline, || {
        collect(&host_events, &mut host_log);
        collect(&ctrl_events, &mut ctrl_log);
        host.status().host_state == "Connected" && ctrl.status().controller_state == "Connected"
    });

    // Quit the controller "app" mid-session (the shell-window close path:
    // engine shutdown, not the Disconnect command).
    let started = Instant::now();
    ctrl.shutdown();
    // The host must learn about it promptly via the goodbye — well before
    // any ICE-failure or timeout path (connect timeout is 10 s).
    wait_for("host Disconnected after controller quit", deadline, || {
        collect(&host_events, &mut host_log);
        host.status().host_state == "Disconnected"
    });
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "peer goodbye must beat failure detection, took {elapsed:?}"
    );
    let host_cause = host_log.iter().find_map(|event| match event {
        EngineEvent::SessionEnded { cause, .. } => Some(cause.clone()),
        _ => None,
    });
    assert!(
        host_cause.as_deref().is_some_and(|c| c.contains("Peer")),
        "host ended via the peer goodbye, got {host_cause:?}"
    );
    host.shutdown();
}

#[test]
fn connect_without_being_online_is_a_clear_error() {
    let hub = SignalingHub::new();
    let (ctrl, ctrl_events) = spawn_engine(&hub, CTRL_DEVICE);
    ctrl.send(EngineCmd::Connect {
        code: HOST_DEVICE.to_owned(),
    })
    .expect("connect");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut log = Vec::new();
    wait_for("not_online error", deadline, || {
        collect(&ctrl_events, &mut log);
        log.iter().any(|event| {
            matches!(
                event,
                EngineEvent::Error { code, .. } if code == "not_online"
            )
        })
    });
    assert_eq!(ctrl.status().controller_state, "Idle");
    ctrl.shutdown();
}
