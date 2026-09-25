//! IPC-surface proof (AGENTS.md invariant 1, gate item: "no frames through
//! IPC (asserted by review + QA audit)").
//!
//! Every event payload and command argument that crosses the Tauri
//! boundary is serialized here and walked recursively: no key may name a
//! byte buffer, surface, SDP body, secret, or input payload, and no array
//! of numbers may exceed cursor-shape-free bounds (frame bytes would be
//! 10⁴–10⁶-element arrays; the diagnostics payloads are scalars/maps).

use remote_desktop_app_lib::engine::{DiagSnapshot, EngineStatus, disconnect_copy};
use remote_desktop_app_lib::ipc::MonitorDto;
use session::DisconnectCause;

/// Field names that must never appear in an IPC payload (frame/input/
/// secret carriage by construction — this test makes it executable).
// Byte/payload-carrying names. Counters like `frames_captured` are
// explicitly allowed (perf schema: "counters are fine over IPC").
const FORBIDDEN_KEYS: &[&str] = &[
    "bytes",
    "pixel",
    "pixels",
    "surface",
    "texture",
    "sdp",
    "secret",
    "session_secret",
    "candidate",
    "input_event",
    "payload",
    "buffer",
];

fn walk(value: &serde_json::Value, path: &str, violations: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if FORBIDDEN_KEYS.iter().any(|bad| key.contains(bad)) {
                    violations.push(format!("{path}.{key}"));
                }
                walk(child, &format!("{path}.{key}"), violations);
            }
        }
        serde_json::Value::Array(items) => {
            if items.len() > 32 {
                violations.push(format!("{path}[] len={}", items.len()));
            }
            for (index, child) in items.iter().enumerate() {
                walk(child, &format!("{path}[{index}]"), violations);
            }
        }
        _ => {}
    }
}

fn sample_diagnostics() -> DiagSnapshot {
    use std::collections::BTreeMap;
    DiagSnapshot {
        session_id: Some("ctrl-1-ctrl-2".into()),
        origin: "controller",
        stages_ms: BTreeMap::from([(
            "decode_to_present".into(),
            remote_desktop_app_lib::engine::diag::StageStat {
                p50_ms: 1.25,
                p95_ms: 2.5,
                count: 240,
            },
        )]),
        fps: BTreeMap::from([("present".into(), 59.5)]),
        link: Some(remote_desktop_app_lib::engine::diag::LinkStat {
            send_bitrate_kbps: Some(64),
            recv_bitrate_kbps: Some(6_100),
            rtt_ms: Some(0.4),
            loss_percent: Some(0.0),
        }),
        queues: BTreeMap::from([(
            "decode_to_present".into(),
            remote_desktop_app_lib::engine::diag::QueueStat {
                depth: 0,
                capacity: 1,
                high_water: 1,
                dropped: 2,
                replaced: 0,
            },
        )]),
        input: remote_desktop_app_lib::engine::diag::InputStat {
            applied: 128,
            suppressed: 1,
            gaps: 0,
            all_keys_up: 1,
            held: 0,
            inject_errors: 0,
        },
        encoder: Some("H264 (software, 1920x1080@60fps)".into()),
        encoder_kind: Some("software".into()),
        encoder_rebuilds: 1,
        viewer_input_dropped: 0,
    }
}

fn sample_status() -> EngineStatus {
    EngineStatus {
        device_id: "dev-a".into(),
        host_state: "Connected".into(),
        controller_state: "Idle".into(),
        session_id: Some("s1".into()),
        viewer_created: false,
        viewer_hwnd: 0,
        viewer_fullscreen: false,
        viewer_focused: false,
        viewer_scale: "fit".into(),
        host_monitors: vec![MonitorDto {
            monitor_id: "\\\\.\\DISPLAY1".into(),
            label: "\\\\.\\DISPLAY1 (1920x1080 @0,0)".into(),
            width_px: 1920,
            height_px: 1080,
            is_primary: true,
            desktop_left: 0,
            desktop_top: 0,
        }],
        peer_monitors: vec![],
        active_monitor: Some("\\\\.\\DISPLAY1".into()),
        quality: "balanced".into(),
        encoder: Some("enc".into()),
        counters: remote_desktop_app_lib::engine::EngineCounters {
            input_sent_fast: 10,
            input_sent_reliable: 4,
            input_all_keys_up_sent: 1,
            frames_captured: 900,
            frames_encoded: 890,
            frames_presented: 0,
            keyframes: 12,
            monitor_switches: 1,
            encoder_rebuilds: 1,
        },
        input: remote_desktop_app_lib::engine::diag::InputStat::default(),
    }
}

#[test]
fn ipc_payloads_carry_metadata_only() {
    let payloads: Vec<(&str, serde_json::Value)> = vec![
        (
            "diagnostics",
            serde_json::to_value(sample_diagnostics()).unwrap(),
        ),
        ("status", serde_json::to_value(sample_status()).unwrap()),
    ];
    let mut violations = Vec::new();
    for (name, value) in &payloads {
        walk(value, name, &mut violations);
    }
    assert!(
        violations.is_empty(),
        "IPC payloads carry forbidden data: {violations:?}"
    );
}

#[test]
fn disconnect_copy_covers_every_cause_without_payloads() {
    let causes = [
        DisconnectCause::User,
        DisconnectCause::Peer,
        DisconnectCause::Timeout,
        DisconnectCause::Rejected(protocol::signaling::RejectReason::Busy),
        DisconnectCause::Canceled,
        DisconnectCause::Collision,
        DisconnectCause::TransportError,
    ];
    for cause in &causes {
        let (code, message, hint) = disconnect_copy(cause);
        assert!(!code.is_empty());
        assert!(message.len() > 8, "copy for {cause:?} too terse");
        let value = serde_json::json!({ "code": code, "message": message, "hint": hint });
        let mut violations = Vec::new();
        walk(&value, "ended", &mut violations);
        assert!(violations.is_empty());
    }
}
