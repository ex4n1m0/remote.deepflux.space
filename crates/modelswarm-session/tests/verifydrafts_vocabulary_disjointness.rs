//! ADR-032 revision 4 §2 rule (ii) — the vocabulary-disjointness
//! assertion (a per-push test, landed with the §7 item-(iv) migrations
//! "at the latest"): the frozen msp-v1 §6 `WireMessage` variant tags and
//! the VerifyDrafts family's discriminant keys are DISJOINT sets, so no
//! future typed §6 variant tag can ever swallow a family frame (or vice
//! versa) and strand it in the wrong receive path of the transport's
//! two-pass decode.
//!
//! Venue: per-push, DEFAULT features (ADR-032 §7 venue matrix) — this
//! file lives in the session crate precisely because default-feature CI
//! must run it while both vocabularies are visible: the §6 tags come
//! from the REAL `modelswarm_transport::message::WireMessage` enum (the
//! frozen msp-v1 §6 vocabulary), and the family keys are built from the
//! real family wire shapes wherever they are serializable.
//!
//! Rule (i) behind this pin: any change on either side that would break
//! the disjointness requires an ADR and a collision test in the same
//! change — this test is that collision test's permanent home.

use modelswarm_runtime::SamplingParams;
use modelswarm_session::negotiation::{
    Backend, CancelRoundReason, EngineDisclosure, FrameRejectReason, Preset, SessionAccept,
    SessionBudget, SessionOffer, SessionReject, SessionRejectReason, WirePinCarrier,
    COOPERATIVE_PROTOCOL_VERSION,
};
use modelswarm_session::verifydrafts::{
    batch_generation_params_hash, CancelRoundFrame, RejectionFrame, VerifyDrafts,
    VerifyDraftsResult, WINDOW_CAP,
};
use modelswarm_transport::message::WireMessage;
use serde_json::Value;

/// The family's discriminant keys, EXACTLY as ADR-032 revision 4 §2 rule
/// (i) enumerates them plus the two ADR-036 carrier keys
/// (`pin_commitment`, `prompt_tokens` — §4 of that ADR joins them to the
/// rule-(i) enumerated set): `window_tokens`, `accepted_token_ids`, the
/// negotiation/result/reject keys (`preset`, `budget`,
/// `verifier_backend`, `engine`, `reason`, `nonce_echo`, `code`), and
/// the pin-carrier's. The `accepted_token_ids` entry is the §2
/// `PrefixCommit` carrier's discriminant — its field set is byte-pinned
/// by the `verifydrafts-5-commit-carrier.json` golden vector (the
/// node-side `WirePrefixCommit` mirror is feature-gated and not visible
/// to default-feature tests).
const FAMILY_DISCRIMINANT_KEYS: [&str; 11] = [
    "window_tokens",
    "accepted_token_ids",
    "preset",
    "budget",
    "verifier_backend",
    "engine",
    "reason",
    "nonce_echo",
    "code",
    "pin_commitment",
    "prompt_tokens",
];

/// Extracts the LIVE set of `WireMessage` variant tags from serde's own
/// unknown-variant error (the externally-tagged, snake_case form
/// `{"handshake":{…}}`, `{"token_delta":{…}}`, … — the frozen §6 wire
/// vocabulary). A parsing failure is a loud panic, never a silent pass.
fn wire_message_variant_tags() -> Vec<String> {
    let probe = serde_json::json!({ "__disjointness_probe__": null });
    let err = serde_json::from_value::<WireMessage>(probe)
        .expect_err("an unknown variant tag must fail deserialization")
        .to_string();
    let marker = "expected one of `";
    let Some(start) = err.find(marker) else {
        panic!("serde unknown-variant error changed shape; update this probe: {err}");
    };
    let list = err[start + marker.len()..].trim_end_matches('`');
    list.split("`, `")
        .map(|tag| tag.trim_matches('`').to_string())
        .collect()
}

/// Serializes one real family wire shape and returns its field names.
fn keys_of(value: &Value) -> Vec<&'_ str> {
    value
        .as_object()
        .expect("family wire shapes are JSON objects")
        .keys()
        .map(String::as_str)
        .collect()
}

#[test]
fn section6_tags_and_family_discriminant_keys_are_disjoint() {
    // The §6 tags come from the LIVE enum (not a stale copy): the frozen
    // vocabulary is the twelve WireMessage variants (eleven + accepted,
    // ADR-043 §3 — the msp-v1 §6.3 accepted emission un-deferred from
    // ADR-028), and a variant added without a same-change collision test
    // fails the disjointness comparison below whenever it collides.
    let tags = wire_message_variant_tags();
    assert_eq!(
        tags.len(),
        12,
        "the frozen §6 vocabulary is the twelve WireMessage variants: {tags:?}"
    );
    for expected in [
        "handshake",
        "handshake_ack",
        "inference_request",
        "token_delta",
        "usage",
        "stream_error",
        "cancelled",
        "completed",
        "cancel",
        "receipt_ack",
        "accepted",
        "control",
    ] {
        assert!(
            tags.iter().any(|t| t == expected),
            "§6 variant tag {expected} missing from the live enum: {tags:?}"
        );
    }

    // Build the family discriminant keys from the REAL wire shapes and
    // prove every ADR-enumerated key is genuinely one of them (the data
    // list cannot rot: an ADR-listed key absent from every shape fails).
    let params_hash = batch_generation_params_hash(&SamplingParams::default())
        .expect("default sampling params are integral");
    let profile_id = format!("msp1:{}", "ab".repeat(32));
    let offer = SessionOffer {
        session_id: "sess-disjoint".to_string(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
        preset: Preset::Verified,
        budget: SessionBudget {
            max_endpoints: 1,
            max_endpoint_seconds: 120,
            max_output_tokens: 64,
        },
        verifier_backend: Backend::Cpu,
        profile_id: profile_id.clone(),
        generation_params_hash: params_hash.clone(),
    };
    let accept = SessionAccept {
        session_id: offer.session_id.clone(),
        protocol_version: offer.protocol_version.clone(),
        preset: offer.preset,
        budget: offer.budget.clone(),
        engine: EngineDisclosure {
            backend: Backend::Cpu,
            batch_verify: true,
            batch_window_max: WINDOW_CAP,
        },
    };
    let reject = SessionReject {
        session_id: offer.session_id.clone(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
        reason: SessionRejectReason::BackendMismatch,
    };
    let cancel = CancelRoundFrame {
        session_id: offer.session_id.clone(),
        round: 1,
        reason: CancelRoundReason::ParentMismatch,
    };
    let frame_reject = RejectionFrame {
        session_id: offer.session_id.clone(),
        code: FrameRejectReason::BadFrame,
        round: Some(1),
        prefix_hash: None,
    };
    // The ADR-036 pin carrier — a real shape, so `pin_commitment` and
    // `prompt_tokens` are live keys from the type itself (the strict
    // `deny_unknown_fields` form is pinned by the pin-carrier vectors).
    let pin_carrier = WirePinCarrier {
        session_id: offer.session_id.clone(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
        seq: 1,
        round: 0,
        profile_id: offer.profile_id.clone(),
        generation_params_hash: offer.generation_params_hash.clone(),
        prompt_tokens: vec![11, 22, 33],
        pin_commitment: modelswarm_session::negotiation::pin_commitment_of(&[11, 22, 33]),
        nonce: "disjoint-carrier-nonce".to_string(),
        deadline_ms: 2_500,
        sender: "coordinator".to_string(),
        signature: String::new(),
    };
    let request = VerifyDrafts {
        session_id: offer.session_id.clone(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
        seq: 1,
        round: 1,
        profile_id,
        parent_prefix_hash: modelswarm_session::GENESIS_PREFIX_HASH.to_string(),
        generation_params_hash: params_hash,
        window_tokens: vec![1, 2, 3],
        proposer_id: "12D3KooProposer".to_string(),
        nonce: "disjoint-nonce".to_string(),
        deadline_ms: 2_500,
        sender: "coordinator".to_string(),
        signature: String::new(),
    };
    let result = VerifyDraftsResult {
        session_id: offer.session_id.clone(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
        seq: 1,
        round: 1,
        accepted_prefix_len: 3,
        divergence_point: None,
        correction: Some(9),
        new_prefix_hash: modelswarm_session::GENESIS_PREFIX_HASH.to_string(),
        verify_pass_ms: 1,
        nonce_echo: "disjoint-nonce".to_string(),
        sender: "verifier".to_string(),
        signature: String::new(),
    };
    let shapes: Vec<Value> = vec![
        serde_json::to_value(&offer).unwrap(),
        serde_json::to_value(&accept).unwrap(),
        serde_json::to_value(&reject).unwrap(),
        serde_json::to_value(&cancel).unwrap(),
        serde_json::to_value(&frame_reject).unwrap(),
        serde_json::to_value(&request).unwrap(),
        serde_json::to_value(&result).unwrap(),
        serde_json::to_value(&pin_carrier).unwrap(),
    ];
    let mut live_keys: Vec<&str> = Vec::new();
    for shape in &shapes {
        live_keys.extend(keys_of(shape));
    }
    live_keys.sort_unstable();
    live_keys.dedup();

    // THE assertion (§2 rule (i)): disjoint sets.
    for key in FAMILY_DISCRIMINANT_KEYS {
        // `accepted_token_ids` is the carrier key — pinned by the
        // `verifydrafts-5-commit-carrier.json` golden vector, not
        // serializable here (the node mirror is feature-gated); every
        // OTHER enumerated key must be a live field of a family shape.
        if key != "accepted_token_ids" {
            assert!(
                live_keys.contains(&key),
                "ADR-enumerated family key {key} is not a field of any family wire shape"
            );
        }
        assert!(
            !tags.iter().any(|t| t == key),
            "COLLISION: family discriminant key {key} is also a §6 WireMessage variant tag \
             — an ADR and a collision test are REQUIRED before this can exist"
        );
    }

    // And the mirror direction over the FULL live key set: no family
    // wire-shape field is a §6 variant tag (stronger than the enumerated
    // nine; catches a future family field that collides too).
    for key in &live_keys {
        assert!(
            !tags.iter().any(|t| t == key),
            "COLLISION: family field {key} is also a §6 WireMessage variant tag"
        );
    }
}
