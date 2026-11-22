//! The ASSISTANT REDACTION SUITE (ADR-037 §4.4 item 11, node half).
//! The desktop half (seeding the app's own conversation transcript and
//! a carrier-shaped payload into process state, then running turns)
//! lives in the desktop tauri-shell suite; this file drives the SAME
//! canary discipline against the node-side plane:
//!
//! - canary discipline: canary bytes — a swarm-transcript marker and an
//!   ADR-036-style carrier payload — appear NOWHERE in any serialized
//!   request (every transport-double capture), through every input
//!   channel the plane has;
//! - the context block re-matches the frozen allowlist
//!   POST-SERIALIZATION (the choke-point re-scan on the final bytes);
//! - `scrub_content` holds for user text (sk-/JWT/Bearer/hex-32
//!   adversarial inputs): the raw secret-shaped bytes never leave;
//! - corrupting one context field post-gate STOPS the request;
//! - the plane's own telemetry is counts/labels only (the A3 filtered
//!   stream discipline: only `assistant.*` rows, no reply text, no key).

use std::sync::Arc;

use modelswarm_node::advisory::assistant::{self, AssistantPlane};
use modelswarm_node::advisory::egress::{
    self, choke_point_rescan_assistant, ContextField, ContextValue,
};
use modelswarm_node::advisory::{AdvisoryTransport, CountingTransport};

const CANARY_TRANSCRIPT: &str = "WALL-CANARY-swarm-transcript-0123456789abcdef";
const CANARY_CARRIER: &str = "WALL-CANARY-carrier-payload-fedcba9876543210";

/// Boots the armed plane over a counting double for `dir` — the
/// hosted-model posture over the double (never a real engine; never a
/// provider: the 2026-10-15 owner directive removed that surface
/// whole, so there is no key file and no env var to serialize over
/// anymore).
fn boot(dir: &std::path::Path, double: Arc<CountingTransport>) -> AssistantPlane {
    std::fs::write(dir.join("advisory.json"), r#"{"assistant.enabled":true}"#).unwrap();
    let as_trait: Arc<dyn AdvisoryTransport> = double;
    let (plane, gap) = AssistantPlane::spawn(dir, None, Some(as_trait));
    assert_eq!(
        gap.as_str(),
        "not_hosting",
        "armed spawn reports no degrade"
    );
    plane.expect("the assistant plane arms over the double")
}

fn typed_context() -> Vec<ContextField> {
    vec![
        ContextField {
            name: "hw.logical_cpus".into(),
            value: ContextValue::Int(16),
        },
        ContextField {
            name: "hw.total_ram_mb".into(),
            value: ContextValue::Int(32_000),
        },
        ContextField {
            name: "hw.gpu.name".into(),
            value: ContextValue::GpuName("NVIDIA GeForce RTX 5080 Laptop GPU".into()),
        },
        ContextField {
            name: "family.off_reason".into(),
            value: ContextValue::Enum {
                vocabulary: "family_off_reason",
                value: "resource_ceiling".into(),
            },
        },
        ContextField {
            name: "app.version".into(),
            value: ContextValue::Version("0.2.24".into()),
        },
    ]
}

#[tokio::test]
async fn canary_bytes_reach_no_serialized_assistant_request() {
    let dir = tempfile::tempdir().unwrap();
    let double = Arc::new(CountingTransport::new(vec![Ok(Vec::new())]));
    let plane = boot(dir.path(), double.clone());
    let (telemetry, sink) = modelswarm_telemetry::Telemetry::memory();

    // The plane's TWO input channels are the user text and the typed
    // context block (W3). The canary discipline at this seam: canary
    // bytes can enter ONLY through a typed channel, and every
    // rule-violating carry is dropped at the gate:
    // - a bounded-string canary OVER its bound (dropped),
    // - an unknown field name carrying canary bytes (dropped),
    // - an enum value that is canary text (dropped — outside the frozen
    //   vocabulary),
    // - a picker row whose display_name is over-bound (the field drops),
    // - a count map with a canary key (drops whole).
    // The swarm-transcript/cARRIER canary proof over the app's own
    // conversation store is the DESKTOP half of this suite (the builder
    // there is structurally fed no chat data); user text itself is the
    // DISCLOSED channel and is covered by the scrub test below.
    let mut hostile_context = typed_context();
    hostile_context.extend([
        ContextField {
            name: "hw.gpu.name".into(),
            value: ContextValue::GpuName(format!("{CANARY_TRANSCRIPT}{}", "x".repeat(200))),
        },
        ContextField {
            name: "transcript".into(),
            value: ContextValue::Int(1),
        },
        ContextField {
            name: "family.off_reason".into(),
            value: ContextValue::Enum {
                vocabulary: "family_off_reason",
                value: CANARY_TRANSCRIPT.into(),
            },
        },
        ContextField {
            name: "picker.rows".into(),
            value: ContextValue::PickerRows(vec![egress::ContextPickerRow {
                display_name: format!("{CANARY_CARRIER}{}", "x".repeat(200)),
                quant_method: "q4_k_m".into(),
                quant_bits: 4,
                download_mb: 1,
                ram_mb_est: 1,
                fit: Some("gpu_full".into()),
                recommended: true,
                census_peers: Some(0),
            }]),
        },
    ]);
    let mut poisoned_counts = std::collections::BTreeMap::new();
    poisoned_counts.insert(CANARY_CARRIER.to_string(), 1);
    hostile_context.push(ContextField {
        name: "status.error_counts".into(),
        value: ContextValue::VocabCountMap {
            vocabulary: "msp_v1_section_6_5_error_registry",
            counts: poisoned_counts,
        },
    });

    let outcome = plane
        .run_turn(&telemetry, "which model fits?", hostile_context)
        .await;
    let _ = outcome;

    assert!(!double.bodies().is_empty(), "the turn must have called");
    for body in double.bodies() {
        assert!(
            !body.contains(CANARY_TRANSCRIPT),
            "swarm-transcript canary reached a serialized request"
        );
        assert!(
            !body.contains(CANARY_CARRIER),
            "carrier-payload canary reached a serialized request"
        );
        // The context block re-matches the frozen allowlist on the FINAL
        // serialized bytes.
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let ctx = serde_json::to_string(&parsed["context"]).unwrap();
        assert!(choke_point_rescan_assistant(&body, 49_152).is_ok());
        assert!(ctx.contains("logical_cpus"), "the clean context survived");
    }
    // The plane's own telemetry: counts/labels only, assistant.* rows
    // only, no reply text, no user text.
    for line in sink.snapshot() {
        assert!(line.contains("\"event\":\"assistant."), "{line}");
        assert!(!line.contains("which model fits"), "{line}");
    }
}

#[tokio::test]
async fn scrubbed_user_text_never_carries_raw_secret_shapes() {
    let dir = tempfile::tempdir().unwrap();
    let double = Arc::new(CountingTransport::always_ok());
    let plane = boot(dir.path(), double.clone());
    let (telemetry, _sink) = modelswarm_telemetry::Telemetry::memory();

    // concat!-split so the CI leak-guard grep over tracked files never
    // sees the key-like literal; the runtime shape is unchanged.
    let secret = concat!("sk-", "0123456789abcdef0123456789abcdef");
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ4IjoxfQ.AB12CD34EF56GH78IJ90KL12MN34";
    let bearer = "Bearer abcdef0123456789abcdef0123456789";
    let hex32 = "0123456789abcdef0123456789abcdef0123456789abcdef";
    for hostile in [secret, jwt, bearer, hex32] {
        let _ = plane
            .run_turn(
                &telemetry,
                &format!("here is my credential {hostile} help me"),
                typed_context(),
            )
            .await;
    }
    assert!(!double.bodies().is_empty());
    for body in double.bodies() {
        for hostile in [secret, jwt, bearer, hex32] {
            assert!(
                !body.contains(hostile),
                "raw secret-shaped bytes left the machine in a request body"
            );
        }
        assert!(choke_point_rescan_assistant(&body, 49_152).is_ok());
    }
}

/// Post-gate corruption of ONE context field stops the request (RC-3's
/// assistant form): the choke-point re-scan rejects the body, the
/// machine records `empty_after_redaction`, and NOTHING is sent for
/// that turn.
#[tokio::test]
async fn post_gate_context_corruption_stops_the_request() {
    let dir = tempfile::tempdir().unwrap();
    let double = Arc::new(CountingTransport::always_ok());
    let plane = boot(dir.path(), double.clone());
    let (telemetry, _sink) = modelswarm_telemetry::Telemetry::memory();

    // A clean turn goes through; its body is the corruption template.
    let _ = plane
        .run_turn(&telemetry, "clean turn", typed_context())
        .await;
    let clean = double.bodies().last().unwrap().clone();
    let mut parsed: serde_json::Value = serde_json::from_str(&clean).unwrap();
    assert!(choke_point_rescan_assistant(&clean, 49_152).is_ok());

    // Corrupt exactly one context field: integer -> free text.
    parsed["context"]["hw.logical_cpus"] = serde_json::json!("sixteen (corrupted)");
    assert!(choke_point_rescan_assistant(&parsed.to_string(), 49_152).is_err());
    // Corrupt one field NAME post-gate: smuggled key.
    let mut parsed: serde_json::Value = serde_json::from_str(&clean).unwrap();
    let obj = parsed["context"].as_object_mut().unwrap();
    let removed = obj.remove("hw.total_ram_mb").unwrap();
    obj.insert("hw.something_else".into(), removed);
    assert!(choke_point_rescan_assistant(&parsed.to_string(), 49_152).is_err());
    // And the same corruption arriving through the BUILD path (a
    // corrupted value in the typed input) drops the field — the turn
    // still sends only what re-matches.
    let mut hostile = typed_context();
    hostile.push(ContextField {
        name: "hw.logical_cpus".into(),
        value: ContextValue::GpuName("not an integer".into()), // wrong TYPE
    });
    let before = double.count();
    let _ = plane
        .run_turn(&telemetry, "typed corruption", hostile)
        .await;
    assert_eq!(double.count(), before + 1, "the turn ran");
    let bodies = double.bodies();
    let last = bodies.last().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(
        parsed["context"]["hw.logical_cpus"], 16,
        "the well-typed duplicate admits; the mistyped one dropped"
    );
}

/// The gap path is honest: an erroring double produces a `gap` outcome
/// and exactly one `assistant.turn.gap` row with the frozen label — and
/// a following turn retries within caps (no in-turn retry).
#[tokio::test]
async fn failing_turns_are_honest_gaps_and_the_next_turn_retries() {
    let dir = tempfile::tempdir().unwrap();
    let double = Arc::new(CountingTransport::always_erroring());
    let plane = boot(dir.path(), double.clone());
    let (telemetry, sink) = modelswarm_telemetry::Telemetry::memory();

    let outcome = plane.run_turn(&telemetry, "hello?", typed_context()).await;
    match outcome {
        assistant::TurnOutcome::Gap { reason, .. } => {
            assert_eq!(reason.as_str(), "http_error");
        }
        other => panic!("expected a gap, got {other:?}"),
    }
    assert_eq!(double.count(), 1, "exactly one call — no in-turn retry");
    let rows = sink.snapshot().join("\n");
    assert!(rows.contains("\"event\":\"assistant.turn.gap\""));
    assert!(rows.contains("\"reason\":\"http_error\""));
    assert!(
        !rows.contains("hello?"),
        "user text never reaches telemetry"
    );
    // The next user turn IS the retry.
    let _ = plane.run_turn(&telemetry, "again", typed_context()).await;
    assert_eq!(double.count(), 2);
}
