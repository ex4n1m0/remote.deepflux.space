//! Chat inbox envelope — the sealed-envelope surface of `PUT/GET /api/chat`
//! (ADR-005 RD-022). Folded into this crate from `apps/desktop/src-tauri`
//! by ADR-006: the contract had drifted TS-only (`services/signaling/lib/
//! chat-schema.ts` plus a hand-copied struct), which is exactly the
//! single-source-of-truth violation the wire policy exists to prevent.
//!
//! The envelope is AES-256-GCM sealed **client-side** under the pairing
//! secret (`apps/desktop/src-tauri/src/chat.rs` `seal`/`open`); the service
//! stores ciphertext only and can neither read nor forge messages
//! (invariant 2, ADR-005 widening). The service-side zod mirror lives in
//! `services/signaling/lib/chat-schema.ts`.
//!
//! `v` gates layout changes; additive-optional rules apply within a
//! version, same as every JSON surface here.
//!
//! ADR-013 P3 fleet slice 2 (additive, `CHAT_PROTOCOL_VERSION` stays 1):
//! the envelope gains optional `agent` / `fleet_call_id` ROUTING HINTS,
//! and a v2 sealed-payload layout ([`ChatPayload`]) carries the
//! authoritative copies INSIDE the ciphertext. The hints are outside the
//! seal and therefore untrusted — a receiver wakes its assistant only on
//! the sealed payload's agent bit (and its own opt-in setting), never on
//! the hint. v1 envelopes (no hints) and v1 payloads (plain text) parse
//! unchanged; a v1 receiver simply ignores the hints and displays a v2
//! payload's JSON as plain text (no wake — safe degradation).

use serde::{Deserialize, Serialize};

pub const CHAT_PROTOCOL_VERSION: u32 = 1;

/// `ct_hex` cap (decoded bytes) — bounded inboxes (invariant 3 discipline);
/// mirrored server-side (`chat-schema.ts`).
pub const CHAT_MAX_CT_BYTES: usize = 20_000;

/// Sealed envelope stored by the signaling service (`/api/chat`).
/// Ciphertext only; the service can neither read nor forge it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatEnvelope {
    pub v: u32,
    /// Sender device id (16 hex).
    pub from: String,
    pub nonce_hex: String,
    pub ct_hex: String,
    pub ts_ms: u64,
    /// ADR-013 P3 fleet slice 2 (additive-optional, v1 envelopes parse):
    /// the sender marked this message agent-authored. ROUTING HINT ONLY —
    /// it rides outside the seal, so the service (or anyone editing the
    /// stored row) can set it; the receiver therefore never wakes on this
    /// field alone. The authoritative agent bit lives INSIDE the sealed
    /// payload ([`ChatPayload`]), authenticated by the AES-GCM tag under
    /// the pairing secret. Kept additive so a v2 sender degrades safely
    /// against v1 infrastructure (unknown keys are ignored/stripped).
    #[serde(default)]
    pub agent: bool,
    /// Fleet call correlation id (slice 3 reply routing). Same discipline
    /// as `agent`: outside the seal = untrusted hint; the authoritative
    /// copy rides inside [`ChatPayload`]. Absent on human chat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_call_id: Option<String>,
}

/// ADR-013 P3 fleet slice 2: the v2 SEALED chat payload — the JSON sealed
/// into `ct_hex` when a message carries fleet metadata. v1 payloads are
/// plain UTF-8 text; a v2 payload is this struct serialized as JSON with
/// `v = CHAT_PAYLOAD_VERSION_V2`. The receiver tries the v2 parse first
/// and falls back to plain text, so v1 senders keep working untouched.
///
/// Everything here is INSIDE the AES-256-GCM seal (pairing secret, AAD =
/// `v|from|to|ts`): the service stores ciphertext only and can neither
/// read nor forge the agent bit (invariant 2, ADR-005). Only a paired
/// machine holding the pairing secret can produce a payload that opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatPayload {
    /// Payload layout version (2 = this struct; v1 payloads are raw text).
    pub v: u32,
    /// The chat body (user text — never logged, invariant 6).
    pub body: String,
    /// Authoritative agent bit: true = authored by the sender's assistant
    /// (an instruction turn for the receiver's assistant, gated by the
    /// receiver's `allow_remote_agent_instructions` opt-in).
    #[serde(default)]
    pub agent: bool,
    /// Fleet call correlation id for slice 3 reply routing (absent on
    /// ordinary agent/human chat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_call_id: Option<String>,
}

/// Payload layout version carried by [`ChatPayload`] (the sealed JSON).
/// Distinct from `CHAT_PROTOCOL_VERSION` (the outer envelope, still 1):
/// the payload change is additive-optional — v1 plain-text payloads keep
/// working, so the envelope version does not bump.
pub const CHAT_PAYLOAD_VERSION_V2: u32 = 2;

impl ChatPayload {
    /// Serialize as the v2 sealed-payload JSON (what `seal` encrypts).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parse a decrypted inbox body: `Some` only for a well-formed v2
    /// payload (correct version tag); `None` = v1 plain text (the caller
    /// displays it as the peer's human chat, never wakes on it).
    pub fn parse(pt: &str) -> Option<Self> {
        let payload: Self = serde_json::from_str(pt).ok()?;
        if payload.v != CHAT_PAYLOAD_VERSION_V2 {
            return None;
        }
        Some(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_envelope_round_trips_with_stable_field_names() {
        let env = ChatEnvelope {
            v: CHAT_PROTOCOL_VERSION,
            from: "0123456789abcdef".to_owned(),
            nonce_hex: "0".repeat(24),
            ct_hex: "ab".repeat(48),
            ts_ms: 1_750_000_000_000,
            agent: false,
            fleet_call_id: None,
        };
        let json = serde_json::to_string(&env).expect("serialize");
        let expected = format!(
            "{{\"v\":1,\"from\":\"0123456789abcdef\",\"nonce_hex\":\"{}\",\"ct_hex\":\"{}\",\
             \"ts_ms\":1750000000000,\"agent\":false}}",
            "0".repeat(24),
            "ab".repeat(48)
        );
        assert_eq!(json, expected);
        let back: ChatEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, env);
    }

    #[test]
    fn chat_envelope_tolerates_additive_fields() {
        let json = "{\"v\":1,\"from\":\"0123456789abcdef\",\"nonce_hex\":\"00\",\"ct_hex\":\"ab\",\
                    \"ts_ms\":1,\"future_field\":42}";
        let env: ChatEnvelope = serde_json::from_str(json).expect("tolerate additive");
        assert_eq!(env.from, "0123456789abcdef");
    }

    #[test]
    fn v1_envelope_parses_with_v2_defaults() {
        // ADR-013 slice 2: the fleet hints are additive-optional — a v1
        // envelope (no agent/fleet_call_id keys) loads with safe defaults
        // (human chat, no fleet correlation).
        let json = "{\"v\":1,\"from\":\"0123456789abcdef\",\"nonce_hex\":\"00\",\"ct_hex\":\"ab\",\
                    \"ts_ms\":1}";
        let env: ChatEnvelope = serde_json::from_str(json).expect("v1 envelope parses");
        assert!(!env.agent);
        assert_eq!(env.fleet_call_id, None);
    }

    #[test]
    fn v2_envelope_round_trips_the_fleet_hints() {
        let env = ChatEnvelope {
            v: CHAT_PROTOCOL_VERSION,
            from: "0123456789abcdef".to_owned(),
            nonce_hex: "0".repeat(24),
            ct_hex: "ab".repeat(48),
            ts_ms: 1_750_000_000_000,
            agent: true,
            fleet_call_id: Some("fleet-1".to_owned()),
        };
        let json = serde_json::to_string(&env).expect("serialize");
        assert!(json.contains("\"agent\":true"));
        assert!(json.contains("\"fleet_call_id\":\"fleet-1\""));
        let back: ChatEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, env);
        // The envelope version did NOT bump (additive-optional within v1).
        assert_eq!(back.v, 1);
    }

    #[test]
    fn chat_payload_v2_round_trips_and_gates_on_version() {
        let payload = ChatPayload {
            v: CHAT_PAYLOAD_VERSION_V2,
            body: "reboot the lab pc".to_owned(),
            agent: true,
            fleet_call_id: Some("fleet-7".to_owned()),
        };
        let json = payload.to_json();
        let back = ChatPayload::parse(&json).expect("v2 payload parses");
        assert_eq!(back, payload);
        // v1 plain text is NOT a v2 payload (the caller displays it).
        assert_eq!(ChatPayload::parse("reboot the lab pc"), None);
        // A JSON body without the v2 version tag is not a v2 payload
        // either — human-typed JSON must not route as an instruction.
        assert_eq!(ChatPayload::parse("{\"body\":\"hi\",\"agent\":true}"), None);
        assert_eq!(
            ChatPayload::parse("{\"v\":3,\"body\":\"hi\",\"agent\":true}"),
            None
        );
        // Additive within the payload: agent defaults false when absent.
        let minimal = ChatPayload::parse("{\"v\":2,\"body\":\"hi\"}").expect("minimal v2");
        assert!(!minimal.agent);
        assert_eq!(minimal.fleet_call_id, None);
    }
}
