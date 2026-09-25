//! IPC-surface proof (AGENTS.md invariant 1, gate item: "no frames through
//! IPC (asserted by review + QA audit)"). M4 QA F52 hardened this from a
//! sample-based tripwire to an exhaustive walk:
//!
//! * **every** `EngineEvent` variant is constructed (worst-case-ish: any
//!   array-valued field populated beyond 32) and serialized through the
//!   same values `commands.rs::forward_event` ships to the webview;
//! * every command-argument DTO is constructed and walked;
//! * the diagnostics snapshot and engine status samples are walked.
//!
//! `all_events()` is the exhaustiveness list: **a new `EngineEvent` variant
//! must be added there** (the compiler cannot force it — the match in
//! `forward_event` can, so keep both in sync).

use remote_desktop_app_lib::engine::{DiagSnapshot, EngineEvent, EngineStatus, disconnect_copy};
use remote_desktop_app_lib::ipc::{
    AddFavoriteArgs, ConnectArgs, MonitorDto, RemoveFavoriteArgs, RenameFavoriteArgs,
    SelectMonitorArgs, SetQualityArgs, SettingsPatch,
};
use session::DisconnectCause;

/// Field names that must never appear in an IPC payload (byte/secret/
/// input carriage by construction — this test makes it executable).
/// Counters like `frames_captured` are explicitly allowed (perf schema:
/// "counters are fine over IPC").
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

/// Byte blobs serialize as arrays of NUMBERS; legitimate lists (monitors,
/// causes, log lines) serialize as arrays of objects/strings. Bound only
/// the number-array form (F52c: no false positive on >32-monitor hosts).
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
            let all_numbers = items
                .iter()
                .all(|item| matches!(item, serde_json::Value::Number(_)));
            if all_numbers && items.len() > 32 {
                violations.push(format!("{path}[] number-array len={}", items.len()));
            }
            for (index, child) in items.iter().enumerate() {
                walk(child, &format!("{path}[{index}]"), violations);
            }
        }
        _ => {}
    }
}

fn assert_clean(value: &serde_json::Value, name: &str) {
    let mut violations = Vec::new();
    walk(value, name, &mut violations);
    assert!(
        violations.is_empty(),
        "IPC payload {name} carries forbidden data: {violations:?}"
    );
}

fn monitor(id: &str) -> MonitorDto {
    MonitorDto {
        monitor_id: id.to_owned(),
        label: format!("{id} 1920x1080"),
        width_px: 1920,
        height_px: 1080,
        is_primary: true,
        desktop_left: 0,
        desktop_top: 0,
    }
}

/// EVERY `EngineEvent` variant, populated adversarially. New variants MUST
/// be added here (and to `forward_event`).
fn all_events() -> Vec<EngineEvent> {
    vec![
        EngineEvent::StateChanged {
            machine: "host".into(),
            state: "ConsentPrompted".into(),
            session_id: Some("s1".into()),
        },
        EngineEvent::ConsentRequested {
            controller_device_id: "ctrl-1".into(),
            session_id: "s1".into(),
        },
        EngineEvent::SessionEstablished {
            session_id: "s1".into(),
            peer: Some("ctrl-1".into()),
        },
        EngineEvent::SessionEnded {
            cause: "TransportError".into(),
            code: "transport_error".into(),
            message: "The direct connection failed or dropped.".into(),
            hint: Some("direct only".into()),
        },
        EngineEvent::PeerOnline {
            device_id: "ctrl-1".into(),
        },
        EngineEvent::PeerOffline {
            device_id: "ctrl-1".into(),
        },
        // 40 monitors: a legitimate object list longer than 32 must NOT
        // trip the byte-blob bound.
        EngineEvent::HostCaps {
            monitors: (0..40)
                .map(|i| monitor(&format!("\\\\.\\DISPLAY{i}")))
                .collect(),
        },
        EngineEvent::PeerCaps {
            monitors: vec![monitor("\\\\.\\DISPLAY1")],
        },
        EngineEvent::Diagnostics {
            snapshot: sample_diagnostics(),
        },
        EngineEvent::Error {
            code: "uipi_blocked".into(),
            message: "The host machine is blocking remote input.".into(),
            hint: Some("elevate the host".into()),
        },
        EngineEvent::Info {
            message: "quality preset set to high".into(),
        },
    ]
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
                replaced: 3,
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
        viewer_client_w: 1280,
        viewer_client_h: 720,
        viewer_swapchain_w: 1280,
        viewer_swapchain_h: 720,
        host_monitors: vec![monitor("\\\\.\\DISPLAY1")],
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
fn every_engine_event_carries_metadata_only() {
    for event in all_events() {
        let name = format!("{event:?}")
            .split('{')
            .next()
            .unwrap_or("event")
            .to_owned();
        let value = serde_json::to_value(&event).expect("serialize event");
        assert_clean(&value, &name);
        // Every variant must actually serialize to an object (the tagged
        // shape forward_event ships).
        assert!(value.is_object(), "{name} serialized to {value}");
    }
}

#[test]
fn command_argument_dtos_carry_metadata_only() {
    let dtos: Vec<(&str, serde_json::Value)> = vec![
        (
            "SettingsPatch",
            serde_json::to_value(SettingsPatch {
                device_name: "Office PC".into(),
                signaling_base_url: "https://example.vercel.app".into(),
                default_quality: "balanced".into(),
                default_viewer_scale: "fit".into(),
            })
            .unwrap(),
        ),
        (
            "AddFavoriteArgs",
            serde_json::to_value(AddFavoriteArgs {
                name: "Office".into(),
                code: "0123456789abcdef".into(),
            })
            .unwrap(),
        ),
        (
            "RenameFavoriteArgs",
            serde_json::to_value(RenameFavoriteArgs {
                id: "f1".into(),
                name: "Workstation".into(),
            })
            .unwrap(),
        ),
        (
            "RemoveFavoriteArgs",
            serde_json::to_value(RemoveFavoriteArgs { id: "f1".into() }).unwrap(),
        ),
        (
            "SelectMonitorArgs",
            serde_json::to_value(SelectMonitorArgs {
                monitor_id: "\\\\.\\DISPLAY2".into(),
            })
            .unwrap(),
        ),
        (
            "SetQualityArgs",
            serde_json::to_value(SetQualityArgs {
                preset: "high".into(),
            })
            .unwrap(),
        ),
        (
            "ConnectArgs",
            serde_json::to_value(ConnectArgs {
                code: "0123456789abcdef".into(),
            })
            .unwrap(),
        ),
    ];
    for (name, value) in &dtos {
        assert_clean(value, name);
    }
}

#[test]
fn result_payloads_carry_metadata_only() {
    assert_clean(
        &serde_json::to_value(sample_diagnostics()).unwrap(),
        "diagnostics",
    );
    assert_clean(&serde_json::to_value(sample_status()).unwrap(), "status");
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
        assert_clean(&value, "ended");
    }
}

/// The number-array bound stays armed for arrays of NUMBERS (the shape
/// `Vec<u8>` serializes to) while object lists of any length pass — and
/// forbidden key names fire regardless of size (guards the guard).
#[test]
fn walk_bounds_and_keys_fire_as_intended() {
    // Object lists longer than 32 (e.g. a hypotetical 40-monitor host)
    // must NOT trip the byte-blob bound…
    let many_monitors = serde_json::json!({
        "monitors": (0..40).map(|i| serde_json::json!({ "monitor_id": i })).collect::<Vec<_>>(),
    });
    assert_clean(&many_monitors, "many-monitors");
    // …while raw number arrays do, and forbidden names always do.
    let blob = serde_json::json!({ "preview": vec![7u32; 64], "pixels": vec![1u8; 4] });
    let mut violations = Vec::new();
    walk(&blob, "synthetic", &mut violations);
    assert!(
        violations.iter().any(|v| v.contains("number-array")),
        "number-array bound must fire: {violations:?}"
    );
    assert!(
        violations.iter().any(|v| v.contains("pixels")),
        "forbidden key must fire: {violations:?}"
    );
}
