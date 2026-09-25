//! Golden wire fixtures for the signaling service (`services/signaling`).
//!
//! The TypeScript service's zod schemas (`services/signaling/lib/envelope.ts`)
//! must accept EXACTLY what `crates/protocol` emits — delta D7: stable
//! snake_case JSON, flat `type` discriminant, `protocol_version` = 1. This
//! test is the enforcement mechanism:
//!
//! * With `UPDATE_SIGNALING_FIXTURES=1` it (re)writes
//!   `services/signaling/fixtures/golden/*.json` from the Rust types —
//!   deterministic: fixed ids, clocks, and declaration-ordered serde output.
//! * Without the flag it re-serializes and compares byte-for-byte, so any
//!   Rust-side wire change fails CI until the fixtures (and thereby the TS
//!   schemas, validated by `scripts/validate-wires.mjs`) are consciously
//!   regenerated. A diff here is a contract change: it needs a
//!   `protocol_version` bump or an additive-optional field (AGENTS.md).
//!
//! Two direction folders cover both sides of the wire: `client_to_service`
//! (what the desktop sends) and `service_to_client` (what the service
//! forwards or mints — including the service-minted `error` envelope).

use std::path::PathBuf;

use protocol::capabilities::{
    Capabilities, EncoderCapabilities, EncoderKind, FeatureFlags, MonitorInfo,
};
use protocol::signaling::{
    CancelReason, DisconnectReason, RejectReason, SIGNALING_PROTOCOL_VERSION, SIGNALING_SERVICE_ID,
    SessionSecret, SignalingBody, SignalingEnvelope,
};

fn caps() -> Capabilities {
    Capabilities {
        encoders: vec![
            EncoderCapabilities {
                kind: EncoderKind::Hardware,
                codec: protocol::capabilities::Codec::H264,
                max_width_px: 3840,
                max_height_px: 2160,
                max_fps: 60,
            },
            EncoderCapabilities {
                kind: EncoderKind::Software,
                codec: protocol::capabilities::Codec::H264,
                max_width_px: 1920,
                max_height_px: 1080,
                max_fps: 30,
            },
        ],
        monitors: vec![
            MonitorInfo {
                monitor_id: "\\\\.\\DISPLAY1".to_owned(),
                width_px: 2560,
                height_px: 1440,
                is_primary: true,
            },
            MonitorInfo {
                monitor_id: "\\\\.\\DISPLAY2".to_owned(),
                width_px: 1920,
                height_px: 1080,
                is_primary: false,
            },
        ],
        max_bitrate_kbps: 20_000,
        features: FeatureFlags::empty()
            .with(FeatureFlags::TRICKLE_ICE)
            .with(FeatureFlags::CURSOR_CHANNEL)
            .with(FeatureFlags::INPUT_FAST_CHANNEL)
            .with(FeatureFlags::H264_HARDWARE),
    }
}

fn envelope(
    message_id: &str,
    session_id: Option<&str>,
    from: &str,
    to: &str,
    body: SignalingBody,
) -> SignalingEnvelope {
    SignalingEnvelope {
        protocol_version: SIGNALING_PROTOCOL_VERSION,
        message_id: message_id.to_owned(),
        session_id: session_id.map(str::to_owned),
        from_device_id: from.to_owned(),
        to_device_id: to.to_owned(),
        timestamp_ms: 1_760_000_000_000,
        body,
    }
}

fn client_to_service() -> Vec<(&'static str, SignalingEnvelope)> {
    vec![
        (
            "register",
            envelope(
                "rig-host-host-1",
                None,
                "rig-host",
                SIGNALING_SERVICE_ID,
                SignalingBody::Register {
                    capabilities: caps(),
                },
            ),
        ),
        (
            "heartbeat",
            envelope(
                "rig-host-host-2",
                None,
                "rig-host",
                SIGNALING_SERVICE_ID,
                SignalingBody::Heartbeat,
            ),
        ),
        (
            "connect_request",
            envelope(
                "rig-ctrl-ctrl-1",
                Some("rig-ctrl-ctrl-1"),
                "rig-ctrl",
                "rig-host",
                SignalingBody::ConnectRequest {
                    capabilities: caps(),
                },
            ),
        ),
        (
            "offer",
            envelope(
                "rig-ctrl-ctrl-3",
                Some("rig-ctrl-ctrl-1"),
                "rig-ctrl",
                "rig-host",
                SignalingBody::Offer {
                    sdp: "v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n".to_owned(),
                },
            ),
        ),
        (
            "ice_candidate",
            envelope(
                "rig-ctrl-rt-1",
                Some("rig-ctrl-ctrl-1"),
                "rig-ctrl",
                "rig-host",
                SignalingBody::IceCandidate {
                    candidate: "candidate:1 1 UDP 2130706431 192.168.1.10 54321 typ host"
                        .to_owned(),
                    sdp_mid: Some("0".to_owned()),
                    sdp_mline_index: Some(0),
                },
            ),
        ),
        (
            "cancel_collision",
            envelope(
                "rig-ctrl-ctrl-9",
                Some("rig-ctrl-ctrl-2"),
                "rig-ctrl",
                "rig-host",
                SignalingBody::Cancel {
                    reason: CancelReason::Collision,
                },
            ),
        ),
    ]
}

fn service_to_client() -> Vec<(&'static str, SignalingEnvelope)> {
    vec![
        (
            "accept",
            envelope(
                "rig-host-host-4",
                Some("rig-ctrl-ctrl-1"),
                "rig-host",
                "rig-ctrl",
                SignalingBody::Accept {
                    session_secret: SessionSecret("fixture-one-time-secret".to_owned()),
                },
            ),
        ),
        (
            "reject_busy",
            envelope(
                "rig-host-host-5",
                Some("rig-ctrl-ctrl-2"),
                "rig-host",
                "rig-ctrl",
                SignalingBody::Reject {
                    reason: RejectReason::Busy,
                },
            ),
        ),
        (
            "answer",
            envelope(
                "rig-host-host-6",
                Some("rig-ctrl-ctrl-1"),
                "rig-host",
                "rig-ctrl",
                SignalingBody::Answer {
                    sdp: "v=0\r\no=- 4611731400430051337 2 IN IP4 127.0.0.1\r\n".to_owned(),
                },
            ),
        ),
        (
            "ice_candidate_mid_null",
            envelope(
                "rig-host-rt-2",
                Some("rig-ctrl-ctrl-1"),
                "rig-host",
                "rig-ctrl",
                SignalingBody::IceCandidate {
                    candidate: "candidate:2 1 UDP 1694498815 10.0.0.4 61234 typ host".to_owned(),
                    sdp_mid: None,
                    sdp_mline_index: None,
                },
            ),
        ),
        (
            "ice_complete",
            envelope(
                "rig-host-rt-3",
                Some("rig-ctrl-ctrl-1"),
                "rig-host",
                "rig-ctrl",
                SignalingBody::IceComplete,
            ),
        ),
        (
            "disconnect_timeout",
            envelope(
                "rig-host-host-8",
                Some("rig-ctrl-ctrl-1"),
                "rig-host",
                "rig-ctrl",
                SignalingBody::Disconnect {
                    reason: DisconnectReason::Timeout,
                },
            ),
        ),
        // Service-minted typed error (code 400 = unsupported version).
        (
            "error_unsupported_version",
            SignalingEnvelope {
                protocol_version: SIGNALING_PROTOCOL_VERSION,
                message_id: "signaling-err-1".to_owned(),
                session_id: None,
                from_device_id: SIGNALING_SERVICE_ID.to_owned(),
                to_device_id: "rig-ctrl".to_owned(),
                timestamp_ms: 1_760_000_000_000,
                body: SignalingBody::Error {
                    code: 400,
                    detail: "unsupported protocol_version 0 (service speaks 1)".to_owned(),
                },
            },
        ),
    ]
}

fn fixtures_dir(direction: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../services/signaling/fixtures")
        .join(direction)
}

#[test]
fn golden_signaling_fixtures_match_rust_serialization() {
    let update = std::env::var("UPDATE_SIGNALING_FIXTURES").as_deref() == Ok("1");
    for (direction, fixtures) in [
        ("golden/client_to_service", client_to_service()),
        ("golden/service_to_client", service_to_client()),
    ] {
        let dir = fixtures_dir(direction);
        if update {
            std::fs::create_dir_all(&dir).expect("create fixtures dir");
        } else {
            assert!(
                dir.is_dir(),
                "fixtures missing: run UPDATE_SIGNALING_FIXTURES=1 cargo test -p node-runtime --test signaling_fixtures"
            );
        }
        for (name, envelope) in fixtures {
            let json = serde_json::to_string_pretty(&envelope).expect("serialize fixture");
            let path = dir.join(format!("{name}.json"));
            if update {
                std::fs::write(&path, json + "\n").expect("write fixture");
            } else {
                let existing = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                assert_eq!(
                    existing.trim(),
                    json,
                    "fixture drift at {} — wire contract changed; regenerate \
                     consciously (UPDATE_SIGNALING_FIXTURES=1) and update the TS \
                     schemas if needed",
                    path.display()
                );
            }
        }
        // Round trip every fixture back through the Rust types.
        for entry in std::fs::read_dir(&dir).expect("read fixtures dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read fixture");
            let parsed: SignalingEnvelope = serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("fixture {} no longer parses: {e}", path.display()));
            assert_eq!(parsed.protocol_version, SIGNALING_PROTOCOL_VERSION);
            parsed.check_version().expect("version check");
        }
    }
}
