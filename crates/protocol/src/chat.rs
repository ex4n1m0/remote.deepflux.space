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
        };
        let json = serde_json::to_string(&env).expect("serialize");
        let expected = format!(
            "{{\"v\":1,\"from\":\"0123456789abcdef\",\"nonce_hex\":\"{}\",\"ct_hex\":\"{}\",\
             \"ts_ms\":1750000000000}}",
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
}
