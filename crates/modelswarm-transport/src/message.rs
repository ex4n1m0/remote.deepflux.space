//! P2P wire messages (msp-v1 §6) with the ADR-018 staged JSON encoding.
//!
//! The schema of record is `protocol/messages.proto`; field names and shapes
//! here mirror it exactly (snake_case, no invented or renamed fields). The
//! **wire encoding** is JSON inside length-prefixed frames, per ADR-018's
//! signed-frame staging decision — the protobuf-vs-JSON framing ADR at the
//! Phase 3 opening replaces this encoding without touching the fields.
//!
//! Two transport-layer additions exist beyond the frozen inference protocol
//! and are marked as such:
//!
//! - [`WireMessage::Handshake`] is carried as JSON rather than protobuf bytes
//!   (same fields, same signature semantics);
//! - [`WireMessage::Control`] (`ping`/`pong`) exists only for RTT
//!   measurement. msp-v1 defines no ping message; `Control` is transport
//!   bookkeeping, never part of the inference protocol surface.

use serde::{Deserialize, Serialize};

/// Protocol version constant (msp-v1: `"1"`).
pub const MSP_PROTOCOL_VERSION: &str = "1";

/// A chat message in a normalized request (proto `ChatMessage`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ChatMessage {
    /// `system` | `user` | `assistant`.
    pub role: String,
    pub content: String,
}

/// Sampling parameters (proto `Sampling`). Floats are allowed here: sampling
/// parameters are never part of a signed payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Sampling {
    pub temperature: f64,
    pub top_p: f64,
    pub top_k: u32,
    /// Optional; omitted from the wire when absent (proto `optional`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
}

/// msp-v1 §6.1 handshake (proto `Handshake`).
///
/// `signature` is detached base64 Ed25519 over the canonical JSON (msp-v1
/// §2.2) of the other eight fields — see [`crate::handshake`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Handshake {
    /// Always `"1"`.
    pub protocol_version: String,
    /// Sender's peer id (base58(SHA-256(pubkey)), same label as
    /// `installation_id` in the staged backend).
    pub peer_id: String,
    pub installation_id: String,
    /// Profile the request targets.
    pub profile_id: String,
    /// e.g. `"llama.cpp"`.
    pub runtime_name: String,
    pub runtime_build: String,
    /// RFC 3339 UTC; acceptance window ±120 s (msp-v1 §6.6).
    pub ts: String,
    /// Single-use random hex.
    pub nonce: String,
    /// Base64 Ed25519 over canonical fields above.
    pub signature: String,
}

/// msp-v1 §6.1 handshake acknowledgement (proto `HandshakeAck`). Carries no
/// signature: per the staged flow it travels inside the session established
/// by the (signed) client handshake. `error_code` uses msp-v1 §6.5 codes
/// when `ok` is false.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HandshakeAck {
    pub ok: bool,
    pub error_code: String,
    pub queue_position: u32,
    pub eta_ms: u32,
}

/// Normalized inference request (proto `InferenceRequest`, msp-v1 §6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InferenceRequest {
    /// uuid v4, single-use (msp-v1 §6.6).
    pub request_id: String,
    pub profile_id: String,
    /// Signed token string from msp-v1 §5.
    pub capability_token: String,
    pub messages: Vec<ChatMessage>,
    pub sampling: Sampling,
    pub max_tokens: u32,
    /// Total wall budget in milliseconds.
    pub deadline_ms: u32,
    pub stream: bool,
}

/// Stream event: one token chunk (proto `TokenDelta`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TokenDelta {
    pub request_id: String,
    pub delta: String,
    pub index: u32,
}

/// Stream event: usage accounting (proto `Usage`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub prefill_ms: u32,
    pub decode_ms: u32,
}

/// Stream event: terminal error (proto `Errored`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StreamError {
    pub request_id: String,
    /// msp-v1 §6.5 code.
    pub code: String,
    pub message: String,
    pub retryable_peer_hint: bool,
}

/// Stream event: cancellation notice (proto `StreamCancelled` wrapped with
/// the stream's `request_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Cancelled {
    pub request_id: String,
    pub reason: String,
}

/// Stream event: successful termination (proto `Completed`).
///
/// ADR-030 B2: the proto `Completed` event's `job_receipt` field is now
/// carried — the counter-signed-work receipts v2 surface (msp-v1 §7).
/// Additive: `#[serde(default)]` keeps an OLD peer's receipt-less frame
/// parsing here (`None`), and serde's ignore-unknown-fields default lets
/// an OLD peer skip a NEW frame's receipt field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Completed {
    pub request_id: String,
    /// `stop` | `length` | `cancelled` | `error`.
    pub finish_reason: String,
    /// ADR-030: phase-1 (server-signed) work receipt; `None` on old
    /// peers and any path that cannot honestly account the turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_receipt: Option<JobReceipt>,
}

/// The receipts-v2 wire object (ADR-030 §1) — field-for-field the JSON
/// shape of `modelswarm_eligibility::receipt_v2::ReceiptV2` (both sides
/// byte-pinned to `protocol/vectors/receipt-v2-1.json`), mirrored here so
/// the transport stays layer-clean. Conversion lives node-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobReceipt {
    pub request_id: String,
    pub profile_id: String,
    pub preset: String,
    pub mode_id: String,
    pub cohort_digest: String,
    pub peers: Vec<JobReceiptPeer>,
    pub started_at: String,
    pub ended_at: String,
    pub outcome: String,
    pub accepted_tokens: u64,
    pub verified_tokens: u64,
    pub endpoint_seconds: u64,
    pub usage_digest: String,
    pub budgets: serde_json::Value,
    pub server_signature: String,
    pub requester_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobReceiptPeer {
    pub peer_id: String,
    pub installation_id: String,
    pub role: String,
}

/// ADR-030 B2 / msp-v1 §7 `receipt_ack`: the requester's best-effort
/// confirmation that it received + counter-signed the receipt (the
/// accounting POST to the tracker is the durable act; this frame only
/// informs the serving peer). Old peers cannot parse this variant — the
/// serving side awaits it with a timeout and moves on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReceiptAck {
    pub request_id: String,
}

/// Stream event: admission confirmation (msp-v1 §6.3 `accepted`; emission
/// un-deferred from ADR-028 by ADR-043). Emitted ONLY to sessions that
/// actually waited in the serving fair-queue — an immediately admitted
/// stream keeps today's silent admission, so the observable frame sequence
/// of an uncontended stream is unchanged. Old peers cannot parse this
/// variant (the `ReceiptAck` caveat); it appears only under real
/// contention, which the current swarm never hits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Accepted {
    pub request_id: String,
    /// Position the request held when scheduled (0 = no wait left).
    pub queue_position: u32,
    /// Rough admission-pace estimate; 0 when admitted immediately.
    pub eta_ms: u32,
}

/// Cancellation request, either direction, anytime (proto `Cancel`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Cancel {
    pub request_id: String,
    /// Free-form reason; prompt text forbidden (msp-v1 §6.2).
    pub reason: String,
}

/// Transport-layer control message for RTT measurement.
///
/// NOT part of the frozen msp-v1 inference protocol (which has no ping); it
/// exists so [`crate::Session::measure_rtt`] can probe without touching the
/// protocol surface. Pings are answered transparently inside the transport
/// and never delivered to application recv loops; pongs are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Control {
    /// [`Control::PING`] or [`Control::PONG`].
    pub kind: String,
    /// Echo value binding a pong to its ping.
    pub nonce: String,
}

impl Control {
    /// Control kind: request an RTT probe.
    pub const PING: &'static str = "ping";
    /// Control kind: answer to an RTT probe.
    pub const PONG: &'static str = "pong";

    /// Builds a ping with a fresh nonce.
    pub fn ping() -> Self {
        Self {
            kind: Self::PING.to_string(),
            nonce: modelswarm_identity::new_nonce(),
        }
    }

    /// Builds the pong answering `nonce`.
    pub fn pong(nonce: &str) -> Self {
        Self {
            kind: Self::PONG.to_string(),
            nonce: nonce.to_string(),
        }
    }
}

/// One framed P2P message. Externally tagged: `{"handshake":{…}}`,
/// `{"token_delta":{…}}`, …
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireMessage {
    Handshake(Handshake),
    HandshakeAck(HandshakeAck),
    InferenceRequest(InferenceRequest),
    TokenDelta(TokenDelta),
    Usage(Usage),
    StreamError(StreamError),
    Cancelled(Cancelled),
    Completed(Completed),
    Cancel(Cancel),
    ReceiptAck(ReceiptAck),
    Accepted(Accepted),
    Control(Control),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_request() -> InferenceRequest {
        InferenceRequest {
            request_id: "0192f0c0-1337-4004-8000-000000000001".into(),
            profile_id: "msp:sim-mock:v1".into(),
            capability_token: "tok.sig".into(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: "Say hello".into(),
            }],
            sampling: Sampling {
                temperature: 0.7,
                top_p: 0.9,
                top_k: 40,
                seed: Some(42),
            },
            max_tokens: 32,
            deadline_ms: 5_000,
            stream: true,
        }
    }

    #[test]
    fn wire_field_names_are_snake_case_and_match_the_proto_schema() {
        let v = serde_json::to_value(WireMessage::InferenceRequest(sample_request())).unwrap();
        let outer = v.as_object().unwrap();
        assert_eq!(outer.len(), 1, "externally tagged: exactly one key");
        assert!(outer.contains_key("inference_request"));
        let inner = outer.get("inference_request").unwrap().as_object().unwrap();
        for key in [
            "request_id",
            "profile_id",
            "capability_token",
            "messages",
            "sampling",
            "max_tokens",
            "deadline_ms",
            "stream",
        ] {
            assert!(inner.contains_key(key), "missing proto field {key}");
        }
        let sampling = inner.get("sampling").unwrap().as_object().unwrap();
        for key in ["temperature", "top_p", "top_k", "seed"] {
            assert!(sampling.contains_key(key), "missing sampling field {key}");
        }
        let messages = inner.get("messages").unwrap().as_array().unwrap();
        let msg = messages[0].as_object().unwrap();
        for key in ["role", "content"] {
            assert!(msg.contains_key(key), "missing chat field {key}");
        }
    }

    #[test]
    fn optional_seed_is_absent_when_none() {
        let mut req = sample_request();
        req.sampling.seed = None;
        let v = serde_json::to_value(WireMessage::InferenceRequest(req.clone())).unwrap();
        assert!(!v["inference_request"]["sampling"]
            .as_object()
            .unwrap()
            .contains_key("seed"));
        // And it round-trips back.
        let back: WireMessage = serde_json::from_value(v).unwrap();
        assert_eq!(back, WireMessage::InferenceRequest(req));
    }

    #[test]
    fn variant_tags_are_snake_case() {
        let cases = [
            (
                WireMessage::TokenDelta(TokenDelta {
                    request_id: "r".into(),
                    delta: "d".into(),
                    index: 0,
                }),
                "token_delta",
            ),
            (
                WireMessage::Usage(Usage {
                    prompt_tokens: 1,
                    completion_tokens: 2,
                    prefill_ms: 3,
                    decode_ms: 4,
                }),
                "usage",
            ),
            (
                WireMessage::StreamError(StreamError {
                    request_id: "r".into(),
                    code: "runtime_error".into(),
                    message: "m".into(),
                    retryable_peer_hint: true,
                }),
                "stream_error",
            ),
            (
                WireMessage::Cancelled(Cancelled {
                    request_id: "r".into(),
                    reason: "why".into(),
                }),
                "cancelled",
            ),
            (
                WireMessage::Completed(Completed {
                    request_id: "r".into(),
                    finish_reason: "stop".into(),
                    job_receipt: None,
                }),
                "completed",
            ),
            (
                WireMessage::Cancel(Cancel {
                    request_id: "r".into(),
                    reason: "why".into(),
                }),
                "cancel",
            ),
            (
                WireMessage::HandshakeAck(HandshakeAck {
                    ok: true,
                    error_code: String::new(),
                    queue_position: 0,
                    eta_ms: 10,
                }),
                "handshake_ack",
            ),
        ];
        for (msg, tag) in cases {
            let v = serde_json::to_value(&msg).unwrap();
            assert!(v.as_object().unwrap().contains_key(tag), "tag {tag}");
            let back: WireMessage = serde_json::from_value(v).unwrap();
            assert_eq!(back, msg);
        }
    }

    #[test]
    fn control_is_ping_pong_shaped() {
        let ping = Control::ping();
        assert_eq!(ping.kind, "ping");
        let pong = Control::pong(&ping.nonce);
        assert_eq!(pong.nonce, ping.nonce);
        let v = serde_json::to_value(WireMessage::Control(ping.clone())).unwrap();
        assert_eq!(v, json!({"control": {"kind": "ping", "nonce": ping.nonce}}));
    }
}
