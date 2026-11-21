//! `RelayAdmissionTicket` (ADR-038): the tracker-signed, content-blind
//! admission grant for MSP circuit relays — the D12 close.
//!
//! The ticket asserts installation liveness ONLY: it grants relay capacity
//! access, never serving eligibility (ADR-026 governs that). It carries
//! exactly `{installation_id, peer_id, issued_at, expires_at, nonce}` plus a
//! detached Ed25519 signature by the hub key (the same pinned root as the
//! lease, `protocol/keys/hub-public.hex`), serialized in the lease's
//! capability-token form:
//!
//! ```text
//! base64url(canonical ticket JSON) "." base64url(signature over that JSON)
//! ```
//!
//! Production issuance lives in the tracker (TS, on every successful
//! heartbeat — msp-v1 §3.3/§5a); the relay verifies with
//! [`RelayAdmissionTicket::verify`]. Minting on the Rust side exists for
//! FIXTURES AND TESTS ONLY (`sign_ticket`).

use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::canonical::canonical_json;

/// Frozen ticket TTL (ADR-038 §3.1): `expires_at − issued_at == 600 s`
/// exactly, pinned by golden vector.
pub const RELAY_TICKET_TTL_SECS: i64 = 600;

/// Frozen serialized-form bound (ADR-038 §3.1): tickets longer than this
/// are refused before any allocation.
pub const RELAY_TICKET_MAX_SERIALIZED_LEN: usize = 1024;

/// Clock-skew window for ticket expiry checks (msp-v1 §6.6, the lease rule:
/// ±120 s). Also the grace past `expires_at` that an admission deadline
/// may carry (ADR-038 §3.4, T4).
pub const RELAY_TICKET_SKEW_GRACE_SECS: i64 = 120;

/// Errors from ticket parse/verify. The variants map 1:1 onto the ADR-038
/// §3.4 first-failure-wins table's parse (`malformed`), signature
/// (`bad_signature`), and expiry (`expired`) outcomes; the binding checks
/// (`peer_mismatch` / `installation_mismatch`) take the authenticated
/// remote values as arguments and live here so the relay composes one
/// frozen order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketError {
    /// Wire/syntax failures (length, segments, base64url, strict JSON,
    /// field set, timestamps, nonce charset, TTL delta). The ADR's
    /// `malformed_message(400)` / `malformed` row.
    Malformed(String),
    /// The detached signature did not verify against the pinned tracker
    /// key. The ADR's `permission_denied(202)` / `bad_signature` row.
    InvalidSignature,
    /// `now` is past `expires_at` by more than the skew allowance, or
    /// `issued_at` is more than the allowance in the future. The ADR's
    /// `permission_denied(202)` / `expired` row.
    Expired { overdue_secs: i64 },
    /// `ticket.peer_id` differs from the connection's Noise-authenticated
    /// remote PeerId (ADR-038 §3.4 check 7 / T3).
    PeerMismatch { remote: String, ticket: String },
    /// `ticket.installation_id` does not re-derive from the authenticated
    /// PeerId's embedded key (ADR-038 §3.4 check 8 / ADR-020).
    InstallationMismatch { derived: String, ticket: String },
}

impl fmt::Display for TicketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TicketError::Malformed(why) => write!(f, "malformed relay ticket: {why}"),
            TicketError::InvalidSignature => write!(f, "relay ticket signature invalid"),
            TicketError::Expired { overdue_secs } => write!(
                f,
                "relay ticket expired {overdue_secs}s beyond the {RELAY_TICKET_SKEW_GRACE_SECS}s allowance"
            ),
            TicketError::PeerMismatch { remote, ticket } => write!(
                f,
                "relay ticket bound to peer {ticket:?} but the connection is {remote:?}"
            ),
            TicketError::InstallationMismatch { derived, ticket } => write!(
                f,
                "relay ticket installation {ticket:?} does not derive from the authenticated peer ({derived:?})"
            ),
        }
    }
}

/// The content-blind admission ticket (ADR-038 §3.1). Field set is EXACTLY
/// the five signed fields (T2); `deny_unknown_fields` makes the strict
/// parse normative. Timestamps are RFC-3339 with millisecond precision,
/// the lease-vector form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAdmissionTicket {
    /// The enrolled installation (base58 b58-shape from the tracker's
    /// authenticated identity row — never client input).
    pub installation_id: String,
    /// The PeerId the ticket admits (the tracker-side registered row).
    pub peer_id: String,
    /// RFC-3339 issue timestamp.
    pub issued_at: String,
    /// RFC-3339 expiry timestamp; `expires_at − issued_at` is exactly
    /// [`RELAY_TICKET_TTL_SECS`] (vector-pinned).
    pub expires_at: String,
    /// 32 lowercase hex chars, fresh per issuance (issuance-dedup).
    pub nonce: String,
}

impl RelayAdmissionTicket {
    /// Strict parse of the wire form (`payload "." signature`), applying
    /// the ADR-038 §3.4 syntax rows (checks 3-4) before any signature
    /// work: length bound, segment shape, base64url, canonical strict
    /// JSON, exact field set, RFC-3339 timestamps, nonce charset, and the
    /// frozen 600 s delta.
    pub fn from_wire(wire: &str) -> Result<(Self, Vec<u8>), TicketError> {
        let malformed = |why: &str| TicketError::Malformed(why.to_string());
        if wire.len() > RELAY_TICKET_MAX_SERIALIZED_LEN {
            return Err(malformed(&format!(
                "serialized ticket is {} bytes; the frozen bound is {RELAY_TICKET_MAX_SERIALIZED_LEN}",
                wire.len()
            )));
        }
        let (payload_b64, signature_b64) = wire
            .split_once('.')
            .ok_or_else(|| malformed("expected exactly two base64url segments separated by '.'"))?;
        let payload = BASE64_URL
            .decode(payload_b64)
            .map_err(|e| malformed(&format!("payload is not base64url: {e}")))?;
        let signature = BASE64_URL
            .decode(signature_b64)
            .map_err(|e| malformed(&format!("signature is not base64url: {e}")))?;
        let ticket: RelayAdmissionTicket = serde_json::from_slice(&payload).map_err(|e| {
            malformed(&format!(
                "strict canonical-JSON parse failed (exact field set): {e}"
            ))
        })?;
        // The payload must round-trip to the SAME canonical bytes — a
        // non-canonical encoding (key order/whitespace/escapes) is a
        // malformed ticket, not a verify-time surprise.
        let canonical = Self::canonical_bytes(&ticket)?;
        if canonical.as_bytes() != payload.as_slice() {
            return Err(malformed(
                "payload is not the canonical JSON encoding of the ticket",
            ));
        }
        if !Self::is_32_lower_hex(&ticket.nonce) {
            return Err(malformed("nonce must be 32 lowercase hex chars"));
        }
        let issued = Self::parse_ts(&ticket.issued_at)?;
        let expires = Self::parse_ts(&ticket.expires_at)?;
        let delta = (expires - issued).whole_seconds();
        if delta != RELAY_TICKET_TTL_SECS {
            return Err(malformed(&format!(
                "expires_at − issued_at is {delta}s; the frozen TTL is exactly {RELAY_TICKET_TTL_SECS}s"
            )));
        }
        Ok((ticket, signature))
    }

    /// Signature + expiry verification against the pinned tracker key
    /// (ADR-038 §3.4 checks 5-6). Binding checks (7-8) are separate so
    /// the relay passes the AUTHENTICATED remote values.
    pub fn verify(
        &self,
        signature: &[u8],
        key: &VerifyingKey,
        now: OffsetDateTime,
    ) -> Result<(), TicketError> {
        let sig = Signature::from_slice(signature).map_err(|_| TicketError::InvalidSignature)?;
        let canonical = Self::canonical_bytes(self)?;
        key.verify(canonical.as_bytes(), &sig)
            .map_err(|_| TicketError::InvalidSignature)?;
        let issued = Self::parse_ts(&self.issued_at)?;
        let expires = Self::parse_ts(&self.expires_at)?;
        if issued - now > time::Duration::seconds(RELAY_TICKET_SKEW_GRACE_SECS) {
            return Err(TicketError::Expired { overdue_secs: 0 });
        }
        let overdue = (now - expires).whole_seconds() - RELAY_TICKET_SKEW_GRACE_SECS;
        if overdue > 0 {
            return Err(TicketError::Expired {
                overdue_secs: overdue,
            });
        }
        Ok(())
    }

    /// Peer binding (ADR-038 §3.4 check 7 / T3): the ticket admits only
    /// the PeerId it names — compared against the connection's
    /// Noise-authenticated remote PeerId (string form).
    pub fn check_peer_binding(&self, remote_peer_id: &str) -> Result<(), TicketError> {
        if self.peer_id == remote_peer_id {
            Ok(())
        } else {
            Err(TicketError::PeerMismatch {
                remote: remote_peer_id.to_string(),
                ticket: self.peer_id.clone(),
            })
        }
    }

    /// Identity consistency (ADR-038 §3.4 check 8): `installation_id`
    /// must equal the value derived from the authenticated PeerId's
    /// embedded Ed25519 key (ADR-020: `base58(SHA-256(pubkey))`). The
    /// derivation itself is the caller's (the relay holds the libp2p
    /// types); this compares the result.
    pub fn check_installation(&self, derived_installation_id: &str) -> Result<(), TicketError> {
        if self.installation_id == derived_installation_id {
            Ok(())
        } else {
            Err(TicketError::InstallationMismatch {
                derived: derived_installation_id.to_string(),
                ticket: self.installation_id.clone(),
            })
        }
    }

    /// The admission deadline (ADR-038 §3.4 check 10 / T4):
    /// `expires_at + skew grace`. Admission never outlives its ticket
    /// beyond the grace.
    pub fn admission_deadline(&self) -> Result<OffsetDateTime, TicketError> {
        Ok(Self::parse_ts(&self.expires_at)?
            + time::Duration::seconds(RELAY_TICKET_SKEW_GRACE_SECS))
    }

    fn parse_ts(ts: &str) -> Result<OffsetDateTime, TicketError> {
        OffsetDateTime::parse(ts, &Rfc3339).map_err(|e| {
            TicketError::Malformed(format!("unparseable RFC-3339 timestamp {ts:?}: {e}"))
        })
    }

    fn canonical_bytes(ticket: &RelayAdmissionTicket) -> Result<String, TicketError> {
        let value = serde_json::to_value(ticket)
            .map_err(|e| TicketError::Malformed(format!("ticket is not a JSON value: {e}")))?;
        canonical_json(&value)
            .ok_or_else(|| TicketError::Malformed("canonical JSON render failed".to_string()))
    }

    fn is_32_lower_hex(s: &str) -> bool {
        s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}

/// Mint a ticket's wire form with a fixture/test key (ADR-038 §6.2's
/// fixture-key discipline). PRODUCTION ISSUANCE IS THE TRACKER'S (TS) —
/// this exists so relay/transport tests and the golden vectors can sign
/// with recorded fixture keys, never the production hub key.
pub fn sign_ticket(ticket: &RelayAdmissionTicket, key: &SigningKey) -> String {
    let canonical = RelayAdmissionTicket::canonical_bytes(ticket)
        .expect("fixture ticket must render canonically");
    let signature = key.sign(canonical.as_bytes());
    format!(
        "{}.{}",
        BASE64_URL.encode(canonical.as_bytes()),
        BASE64_URL.encode(signature.to_bytes())
    )
}

/// Verify a wire-form ticket end-to-end (parse + signature + expiry)
/// against a key — the relay's checks 3-6 in one call, for fixtures and
/// consumers that do not need the binding split.
pub fn verify_wire(wire: &str, key: &VerifyingKey, now: OffsetDateTime) -> Result<(), TicketError> {
    let (ticket, signature) = RelayAdmissionTicket::from_wire(wire)?;
    ticket.verify(&signature, key, now)
}

/// Re-exported for fixture tooling: the canonical payload bytes a ticket
/// signs (signature-omitted canonical JSON, the lease discipline).
pub fn canonical_payload(ticket: &RelayAdmissionTicket) -> String {
    RelayAdmissionTicket::canonical_bytes(ticket).expect("fixture ticket must render canonically")
}
