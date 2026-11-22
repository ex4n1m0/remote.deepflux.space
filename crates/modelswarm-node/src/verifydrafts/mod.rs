//! ADR-032 light-up tier: the VerifyDrafts serve loop + requester client
//! (feature `verifydrafts`, OFF by default).
//!
//! This module is the node-layer wiring of the session crate's
//! batched-speculative-verification family
//! (`modelswarm_session::verifydrafts` — the wire types, the
//! verifier-side admission gate, and the coordinator). It adds NO protocol
//! semantics of its own: every admission decision, hash check, and
//! state transition is delegated to the architect-owned session crate; this
//! layer supplies exactly the things ADR-032 pins to the serve loop:
//!
//! - **Session negotiation** (§3): receive `SessionOffer`, answer
//!   `SessionAccept` with an honest [`EngineDisclosure`] wired through
//!   config (`batch_verify: false` initially — the real engine adapter
//!   lands separately) or `SessionReject` (`backend_mismatch`,
//!   `preset_unavailable`, `budget_infeasible`).
//! - **RC-2 obligations:** sign the gate's unsigned result draft with the
//!   verifier identity; supply the transport-authenticated remote PeerId on
//!   every admission call; advance the budget seconds ledger on wall-clock
//!   deltas; poll the WAIT_COMMIT expiry (`deadline_ms + 250 ms`).
//! - **RC-4/RC-5 round flow:** dispatch the one engine pass through the
//!   [`BatchVerifyEngine`] trait, apply `PrefixCommit`s, serialize
//!   `RejectionFrame`/`CancelRoundFrame` (codes, counts, and hashes ONLY —
//!   token ids never appear in frames or logs, ADR-032 §2 privacy rule).
//!
//! # Transport venues (2026-10-12 update)
//!
//! The family's frames are bare JSON objects riding the ADR-018 amended
//! staging (raw-JSON passthrough frames). BOTH backends now carry it:
//!
//! - the staged TCP backend (`Session::send_json`/`recv_json`) through
//!   [`wire::StagedVerifyWire`] — the CI venue with the staged §6.1
//!   handshake (real sockets, real framing, real signatures);
//! - the REAL libp2p QUIC backend through [`wire::QuicVerifyWire`] — the
//!   production venue, unblocked by the transport crate's 2026-10-12
//!   `Libp2pSession::send_json`/`recv_json` passthrough (the light-up
//!   handoff's G1 gap, closed by the Network Engineer). The QUIC handshake
//!   authenticates the remote PeerId, so RC-1's transport-authenticated
//!   identity holds cryptographically on this venue.
//!
//! [`serve::serve_verifydrafts_quic`] is the QUIC accept loop (the
//! `serve_sessions`-shaped venue the msp-v1 bridge demuxes to when the
//! family goes live); the QUIC loopback tests live in
//! `tests/verifydrafts_quic.rs`.
//!
//! # Composed daemon + the engine seam (2026-10-12)
//!
//! - [`composed::serve_sessions_composed`] (needs `libp2p-backend` too):
//!   ONE listener serving BOTH vocabularies — the msp-v1 bridge and this
//!   family — behind ONE `Admission` gate and ONE ADR-026 lease
//!   discipline (the lease seam: [`composed::FamilyLeaseSource`],
//!   profile-bound and fail-closed at family session open since the
//!   RC-L1 discharge — the production source is
//!   [`composed::RosterFamilyLeases`], which since the 2026-10-12
//!   activation accepts the lease the coordinator PRESENTS at session
//!   open ([`WireSessionLease`] carrier →
//!   [`serve::read_session_open`]) and still honors tracker-fed roster
//!   entries — one validation engine, two token sources).
//! - [`engine_source::FamilyEngineSource`]: the injection seam — a
//!   mock/stub engine, or the production C-API engine under the
//!   `verifydrafts-capi` feature ([`engine_bridge`], the G4 bridge that
//!   hosts the architect's `BatchVerifyEngine` for Runtime's
//!   `CapiVerifyEngine` — the trait-cycle resolution, Runtime's
//!   `tests/capi_verify.rs` pattern hosted in the crate that depends on
//!   both).

pub mod client;
#[cfg(all(feature = "verifydrafts", feature = "libp2p-backend"))]
pub mod composed;
#[cfg(feature = "verifydrafts-capi")]
pub mod engine_bridge;
pub mod engine_source;
pub mod serve;
pub mod wire;

pub use client::{
    ClientOpenError, RoundFailure, RoundOutcome, VerifyDraftsClient, VerifyDraftsClientConfig,
};
// Desktop-facing re-exports (the coordinator self-verify helper lives in the
// desktop and needs the trait + the pinned sampling type; without these the
// desktop would need direct deps on the session/runtime crates just to name
// them). No new semantics — the same public types this module already uses.
#[cfg(all(feature = "verifydrafts", feature = "libp2p-backend"))]
pub use composed::{
    serve_sessions_composed, FamilyLeaseRefusal, FamilyLeaseSource, FamilyServing,
    RefuseFamilyLeases, RosterFamilyLeases, StaticLeaseExpiry,
};
#[cfg(feature = "verifydrafts-capi")]
pub use engine_bridge::{capi_disclosure, CapiBatchVerifyEngine};
pub use engine_source::FamilyEngineSource;
pub use modelswarm_runtime::{RuntimeError, SamplingParams};
pub use modelswarm_session::negotiation::Backend;
pub use modelswarm_session::negotiation::EngineDisclosure;
// ADR-036 (2026-10-13): the session-open pin-carrier surface — the strict
// reader, the first-failure admission table, the per-session carrier the
// serve loop seeds its gate from, and the default-on carriage posture the
// desktop's persisted setting flows into.
pub use modelswarm_session::negotiation::pin_commitment_of;
pub use modelswarm_session::negotiation::WirePinCarrier;
pub use modelswarm_session::verifydrafts::sign_pin_carrier;
pub use modelswarm_session::verifydrafts::BatchVerifyEngine;
pub use serve::{
    admit_pin_carrier, read_session_open, serve_verifydrafts_quic, serve_verifydrafts_session,
    serve_verifydrafts_session_with_pin, AdmittedPinCarrier, ContentCarriage, PinAdmission,
    ServeEndReason, SessionOpen, SessionOpenError, VerifyDraftsServeConfig,
    VerifyDraftsServeReport,
};
pub use wire::{
    accept_quic, accept_staged, dial_quic, dial_staged, PrefacedWire, QuicVerifyWire,
    StagedVerifyWire, VerifyDraftsWire, WireError,
};

use modelswarm_session::negotiation::{Preset, SessionBudget};
use modelswarm_session::verifydrafts::VerifyTelemetry;
use modelswarm_telemetry::Telemetry;
use modelswarm_transport::ed25519_dalek::VerifyingKey;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Wall-clock unix milliseconds (the gate's injected clock source).
pub fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Default per-frame I/O deadline for the family's sessions.
pub const FAMILY_IO_DEADLINE: Duration = Duration::from_secs(30);

/// Default idle timeout before a silent cooperative session ends
/// (mirrors the msp-v1 bridge's between-requests wait).
pub const FAMILY_SESSION_IDLE: Duration = Duration::from_secs(300);

/// Recovers the Ed25519 [`VerifyingKey`] embedded in an ADR-020
/// identity-multihash PeerId (`base58(0x00 0x24 ‖ 0x08 0x01 0x12 0x20 ‖
/// pubkey)` — the `12D3Koo…` form; the inverse of
/// [`modelswarm_identity::peer_id_for`]).
///
/// This is how the serve loop pins the gate's `coordinator_key` from the
/// TRANSPORT-authenticated remote PeerId (ADR-032 §1 rule 5 / security
/// review RC-1): the key is derived from the authenticated identity, never
/// taken from a peer-supplied payload. Non-Ed25519 PeerIds fail closed.
pub fn verifying_key_from_peer_id(peer_id: &str) -> Result<VerifyingKey, String> {
    let bytes = bs58::decode(peer_id)
        .into_vec()
        .map_err(|e| format!("peer id is not base58: {e}"))?;
    if bytes.len() != 38
        || bytes[0] != 0x00
        || bytes[1] != 0x24
        || bytes[2..6] != [0x08, 0x01, 0x12, 0x20]
    {
        return Err("peer id is not an Ed25519 identity multihash".to_string());
    }
    let key_bytes: [u8; 32] = bytes[6..38]
        .try_into()
        .expect("length checked above (38 - 6 == 32)");
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| format!("bad key: {e}"))?;
    // Round-trip guard: the forward ADR-020 derivation must reproduce the
    // input byte-for-byte (rejects any exotic multihash that slipped the
    // prefix check).
    if modelswarm_identity::peer_id_for(&key.to_bytes()) != peer_id {
        return Err("peer id does not round-trip the ADR-020 derivation".to_string());
    }
    Ok(key)
}

/// The node's telemetry adapter for the session crate's
/// [`VerifyTelemetry`] surface (RC-1/RC-2/I8 events). Fields carry ids,
/// codes, and counts only — never frame payloads (privacy rule 5).
pub struct NodeVerifyTelemetry<'a>(pub &'a Telemetry);

impl VerifyTelemetry for NodeVerifyTelemetry<'_> {
    fn verify_ms_lie(&self, session_id: &str, peer: &str) {
        self.0.warn(
            "verifydrafts.verify_ms_lie",
            &[("session", session_id), ("peer", peer)],
        );
    }

    fn verifier_divergence(&self, session_id: &str, peer: &str) {
        self.0.warn(
            "verifydrafts.verifier_divergence",
            &[("session", session_id), ("peer", peer)],
        );
    }

    fn budget_refused(&self, session_id: &str, code: &str) {
        self.0.warn(
            "verifydrafts.budget_refused",
            &[("session", session_id), ("code", code)],
        );
    }
}

/// The honest engine disclosure for a node whose engine cannot batch-verify
/// (the pinned llama.cpp HTTP adapter — ADR-032 §4): `batch_verify: false`
/// with the guidance `batch_window_max: 1`. Such a peer is a first-class
/// single and may propose, but is never a batch verifier.
pub const fn http_adapter_disclosure(backend: Backend) -> EngineDisclosure {
    EngineDisclosure {
        backend,
        batch_verify: false,
        batch_window_max: 1,
    }
}

/// Elementwise budget clamp: the effective budget is the offer clamped DOWN
/// by the node's ceiling, never up (ADR-032 §3).
pub fn clamp_budget_down(offer: &SessionBudget, ceiling: &SessionBudget) -> SessionBudget {
    SessionBudget {
        max_endpoints: offer.max_endpoints.min(ceiling.max_endpoints),
        max_endpoint_seconds: offer.max_endpoint_seconds.min(ceiling.max_endpoint_seconds),
        max_output_tokens: offer.max_output_tokens.min(ceiling.max_output_tokens),
    }
}

/// Presets this node serves for the family: everything but `deep` — a
/// CONSCIOUS post-ADR-045 decision (Integrator, 2026-10-20), not the
/// inherited one: Deep is LOSSLESS under ADR-045 (the ADR-029
/// "approximate tier" justification is retired), but its full-cohort
/// fan-out + disagreement escalation are not implemented yet; serving
/// Deep before P2's fan-out lands would label a single-verifier turn
/// "deep" — a false disclosure. Deep joins the served set when its P2
/// behavior + fixtures land.
pub fn default_supported_presets() -> Vec<Preset> {
    vec![
        Preset::Fast,
        Preset::Balanced,
        Preset::Verified,
        Preset::Maximum,
    ]
}

/// Classifies an inbound family frame by its discriminant keys (strict
/// parsing happens in the session crate; this only routes). The
/// session-open lease carrier ([`WireSessionLease`]) never reaches this
/// router: it is consumed (strictly parsed) by [`serve::read_session_open`]
/// BEFORE the serve loop starts.
pub(crate) enum FamilyFrame {
    /// A `VerifyDrafts` request (carries `window_tokens`).
    Request,
    /// A `PrefixCommit` (carries `accepted_token_ids`).
    Commit,
    /// Anything else — no such family message exists at this tier.
    Unknown,
}

pub(crate) fn demux_family_frame(value: &serde_json::Value) -> FamilyFrame {
    if value.get("window_tokens").is_some() {
        FamilyFrame::Request
    } else if value.get("accepted_token_ids").is_some() {
        FamilyFrame::Commit
    } else {
        FamilyFrame::Unknown
    }
}

/// Wire mirror of the shipped `PrefixCommit` shape for this family
/// (ADR-032 §2: the shipped `CommitPrefix` rides the family; its exact
/// binding migration belongs to the freeze ADR — the field names are the
/// shipped `SpecMessage::PrefixCommit` names, `profile_id` for the state
/// machine's `model_profile_id`, and no signature: the commit rides the
/// authenticated session, and the gate checks RC-4 reproduction).
///
/// FORMAL carrier since ADR-032 revision 4 (§2/G2): the BARE object with
/// exactly these field names — no envelope tag, no signature — parsed
/// STRICTLY at the carrier's entry (the serve loop): unknown fields and
/// wrong types fail deserialization (`deny_unknown_fields` + serde
/// types), non-bare-hex hashes fail
/// [`WirePrefixCommit::passes_strict_carrier_schema`], and a `sender`
/// that does not equal the installation id pinned from the authenticated
/// channel is `bad_frame` in the gate — all BEFORE any state is touched.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WirePrefixCommit {
    pub session_id: String,
    pub round: u64,
    pub previous_prefix_hash: String,
    pub accepted_token_ids: Vec<u32>,
    pub new_prefix_hash: String,
    pub profile_id: String,
    pub generation_params_hash: String,
    pub sender: String,
}

/// Wire mirror of the session-open LEASE CARRIER (ADR-032 §2 admission
/// order: the coordinator presents its consume lease AT SESSION OPEN —
/// the family-side equivalent of msp-v1's per-request `capability_token`,
/// decided per the 2026-10-12 activation gap). The BARE object
/// `{"lease": "<wire token>"}` — no envelope tag, exactly one field,
/// parsed STRICTLY (`deny_unknown_fields` + serde types) at the carrier's
/// entry by [`serve::read_session_open`]; the token string itself is the
/// UNCHANGED `modelswarm-eligibility` wire form (`to_wire`:
/// `base64url(json).base64url(sig)`) — no invented fields, no new
/// signature, no new lease shape. The field name discriminates the
/// carrier from every other family frame (`SessionOffer`, `VerifyDrafts`,
/// `PrefixCommit`, results/rejects/cancels — none carries a `lease` key).
///
/// Freeze-ADR record (for the architect): this carrier is a minimal typed
/// wrapper in the verifydrafts module, NOT a protocol-schema change; when
/// ADR-032's wire freeze lands, the carrier should be recorded in
/// `protocol/` alongside the family's other bare frames.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireSessionLease {
    /// The wire lease token exactly as the tracker issued it
    /// (`EligibilityLease::to_wire`); validated against the SAME pinned
    /// hub key the msp-v1 per-request gate uses.
    pub lease: String,
}

impl WirePrefixCommit {
    /// The §2 strict-schema form check beyond serde's (unknown fields /
    /// wrong types fail `from_value` itself): every hash field is BARE
    /// 64-char lowercase hex ([`is_bare_hash`]) and `profile_id` is the
    /// `msp1:<64 hex>` §1 form. A carrier failing this is `bad_frame`
    /// before the gate is touched (ADR-032 revision 4 §2: "a commit frame
    /// that fails the carrier schema … is `bad_frame` before any state is
    /// touched").
    pub(crate) fn passes_strict_carrier_schema(&self) -> bool {
        let profile_ok = self
            .profile_id
            .strip_prefix("msp1:")
            .is_some_and(modelswarm_session::verifydrafts::is_bare_hash);
        profile_ok
            && modelswarm_session::verifydrafts::is_bare_hash(&self.previous_prefix_hash)
            && modelswarm_session::verifydrafts::is_bare_hash(&self.new_prefix_hash)
            && modelswarm_session::verifydrafts::is_bare_hash(&self.generation_params_hash)
    }
}

impl From<&modelswarm_session::CommitPrefix> for WirePrefixCommit {
    fn from(commit: &modelswarm_session::CommitPrefix) -> Self {
        Self {
            session_id: commit.session_id.clone(),
            round: commit.round,
            previous_prefix_hash: commit.previous_prefix_hash.clone(),
            accepted_token_ids: commit.accepted_token_ids.clone(),
            new_prefix_hash: commit.new_prefix_hash.clone(),
            profile_id: commit.model_profile_id.clone(),
            generation_params_hash: commit.generation_params_hash.clone(),
            sender: commit.sender.clone(),
        }
    }
}

impl From<WirePrefixCommit> for modelswarm_session::CommitPrefix {
    fn from(wire: WirePrefixCommit) -> Self {
        Self {
            session_id: wire.session_id,
            round: wire.round,
            previous_prefix_hash: wire.previous_prefix_hash,
            accepted_token_ids: wire.accepted_token_ids,
            new_prefix_hash: wire.new_prefix_hash,
            model_profile_id: wire.profile_id,
            generation_params_hash: wire.generation_params_hash,
            sender: wire.sender,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use modelswarm_identity::InstallationIdentity;

    #[test]
    fn peer_id_inverse_round_trips_the_adr020_derivation() {
        for seed in [1u8, 42, 0xAB] {
            let identity = InstallationIdentity::from_bytes(&[seed; 32]);
            let peer_id = identity.peer_id();
            let key = verifying_key_from_peer_id(&peer_id).expect("derives");
            assert_eq!(key.to_bytes(), identity.public_key_bytes());
            assert_eq!(modelswarm_identity::peer_id_for(&key.to_bytes()), peer_id);
        }
    }

    #[test]
    fn peer_id_inverse_fails_closed_on_foreign_forms() {
        // Not base58.
        assert!(verifying_key_from_peer_id("!!!not-base58!!!").is_err());
        // Right length, wrong prefix bytes (a digest multihash, not identity).
        let identity = InstallationIdentity::from_bytes(&[3u8; 32]);
        let decoded = bs58::decode(identity.peer_id()).into_vec().unwrap();
        let mut tampered = decoded.clone();
        tampered[0] = 0x12; // sha2-256 code instead of identity
        let tampered = bs58::encode(&tampered).into_string();
        assert!(verifying_key_from_peer_id(&tampered).is_err());
        // Truncated.
        let short = bs58::encode(&decoded[..30]).into_string();
        assert!(verifying_key_from_peer_id(&short).is_err());
        // The installation id is NOT a peer id (different derivation).
        assert!(verifying_key_from_peer_id(&identity.installation_id()).is_err());
    }

    #[test]
    fn budget_clamp_is_elementwise_down_only() {
        let offer = SessionBudget {
            max_endpoints: 4,
            max_endpoint_seconds: 60,
            max_output_tokens: 1024,
        };
        let ceiling = SessionBudget {
            max_endpoints: 2,
            max_endpoint_seconds: 120,
            max_output_tokens: 512,
        };
        let effective = clamp_budget_down(&offer, &ceiling);
        assert_eq!(effective.max_endpoints, 2);
        assert_eq!(effective.max_endpoint_seconds, 60);
        assert_eq!(effective.max_output_tokens, 512);
        // A hostile zero field stays zero (rejected as budget_infeasible
        // upstream, never inflated).
        let zero = SessionBudget {
            max_endpoints: 0,
            max_endpoint_seconds: 0,
            max_output_tokens: 0,
        };
        assert_eq!(clamp_budget_down(&zero, &ceiling).max_endpoints, 0);
    }

    #[test]
    fn http_adapter_disclosure_is_the_honest_false() {
        let d = http_adapter_disclosure(Backend::Cpu);
        assert!(!d.batch_verify);
        assert_eq!(d.batch_window_max, 1);
        assert!(d.is_valid_disclosure());
        // Deep is not in the default served presets (ADR-045: its
        // full-cohort fan-out is P2 — serving it earlier would be a
        // false disclosure, the retired "approximate tier" reason is gone).
        assert!(!default_supported_presets().contains(&Preset::Deep));
        assert!(default_supported_presets().contains(&Preset::Verified));
    }

    #[test]
    fn demux_routes_by_discriminant_keys() {
        use serde_json::json;
        assert!(matches!(
            demux_family_frame(&json!({"window_tokens": [1]})),
            FamilyFrame::Request
        ));
        assert!(matches!(
            demux_family_frame(&json!({"accepted_token_ids": [1]})),
            FamilyFrame::Commit
        ));
        assert!(matches!(
            demux_family_frame(&json!({"preset": "fast"})),
            FamilyFrame::Unknown
        ));
    }

    /// The session-open lease carrier: the BARE `{"lease": …}` object —
    /// strict schema (`deny_unknown_fields`, typed field), and a `lease`
    /// key discriminates it from EVERY other family frame (an offer, a
    /// request, a commit, a result/reject/cancel never carries one).
    #[test]
    fn wire_session_lease_is_the_bare_strict_carrier() {
        use serde_json::json;
        let carrier = json!({ "lease": "YmFyZQ.YmF6" });
        let parsed: WireSessionLease =
            serde_json::from_value(carrier.clone()).expect("the bare carrier parses");
        assert_eq!(parsed.lease, "YmFyZQ.YmF6");
        assert_eq!(
            serde_json::to_value(&WireSessionLease {
                lease: "tok".into()
            })
            .unwrap(),
            json!({ "lease": "tok" })
        );
        // Unknown fields / envelope tags / wrong types all fail closed.
        let mut extra = carrier.clone();
        extra
            .as_object_mut()
            .unwrap()
            .insert("profile_id".to_string(), json!("msp1:x"));
        assert!(serde_json::from_value::<WireSessionLease>(extra).is_err());
        let mut tagged = carrier.clone();
        tagged
            .as_object_mut()
            .unwrap()
            .insert("session_lease".to_string(), json!({}));
        assert!(serde_json::from_value::<WireSessionLease>(tagged).is_err());
        assert!(serde_json::from_value::<WireSessionLease>(json!({ "lease": 7 })).is_err());
        // The discriminant never collides with any other family frame.
        for frame in [
            json!({"session_id": "s", "preset": "verified"}),
            json!({"window_tokens": [1]}),
            json!({"accepted_token_ids": [1]}),
            json!({"engine": {}}),
            json!({"code": "bad_frame"}),
            json!({"reason": "round_mismatch"}),
        ] {
            assert!(frame.get("lease").is_none(), "collision: {frame}");
        }
    }

    #[test]
    fn wire_prefix_commit_mirrors_the_shipped_field_names() {
        use modelswarm_session::CommitPrefix;
        let commit = CommitPrefix {
            session_id: "sess-1".into(),
            round: 3,
            previous_prefix_hash: "a".repeat(64),
            accepted_token_ids: vec![7, 8],
            new_prefix_hash: "b".repeat(64),
            model_profile_id: "msp1:x".into(),
            generation_params_hash: "c".repeat(64),
            sender: "peer".into(),
        };
        let value = serde_json::to_value(WirePrefixCommit::from(&commit)).unwrap();
        // The shipped SpecMessage::PrefixCommit field names, exactly.
        assert_eq!(
            value,
            serde_json::json!({
                "session_id": "sess-1",
                "round": 3,
                "previous_prefix_hash": "a".repeat(64),
                "accepted_token_ids": [7, 8],
                "new_prefix_hash": "b".repeat(64),
                "profile_id": "msp1:x",
                "generation_params_hash": "c".repeat(64),
                "sender": "peer"
            })
        );
        let back: CommitPrefix = serde_json::from_value::<WirePrefixCommit>(value)
            .unwrap()
            .into();
        assert_eq!(back.model_profile_id, "msp1:x");
        assert_eq!(back.accepted_token_ids, vec![7, 8]);
    }

    /// §2 carrier strict schema (ADR-032 revision 4 §2/G2): unknown
    /// fields fail deserialization, non-bare-hex hashes (and a non-`msp1:`
    /// profile form) fail the form check — every failure is the serve
    /// loop's `bad_frame` path before the gate is touched. A valid carrier
    /// passes both.
    #[test]
    fn wire_prefix_commit_strict_schema_pins_the_g2_carrier() {
        use serde_json::json;
        let valid = json!({
            "session_id": "sess-1",
            "round": 3,
            "previous_prefix_hash": "a".repeat(64),
            "accepted_token_ids": [7, 8],
            "new_prefix_hash": "b".repeat(64),
            "profile_id": format!("msp1:{}", "ab".repeat(32)),
            "generation_params_hash": "c".repeat(64),
            "sender": "coordinator"
        });
        let parsed: WirePrefixCommit = serde_json::from_value(valid.clone()).unwrap();
        assert!(parsed.passes_strict_carrier_schema());

        // Unknown field -> deserialization failure (deny_unknown_fields).
        let mut unknown = valid.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("signature".to_string(), json!("not-in-this-carrier"));
        assert!(serde_json::from_value::<WirePrefixCommit>(unknown).is_err());
        let mut envelope = valid.clone();
        envelope
            .as_object_mut()
            .unwrap()
            .insert("prefix_commit".to_string(), json!({}));
        assert!(
            serde_json::from_value::<WirePrefixCommit>(envelope).is_err(),
            "an envelope-tagged form is not the bare carrier"
        );

        // Non-bare-hex hashes -> the strict form check fails.
        let mut prefixed = valid.clone();
        *prefixed.get_mut("new_prefix_hash").unwrap() = json!(format!("sha256:{}", "b".repeat(64)));
        let parsed: WirePrefixCommit = serde_json::from_value(prefixed).unwrap();
        assert!(!parsed.passes_strict_carrier_schema());
        let mut short = valid.clone();
        *short.get_mut("previous_prefix_hash").unwrap() = json!("a".repeat(63));
        let parsed: WirePrefixCommit = serde_json::from_value(short).unwrap();
        assert!(!parsed.passes_strict_carrier_schema());
        let mut bad_profile = valid;
        *bad_profile.get_mut("profile_id").unwrap() = json!("msp:x");
        let parsed: WirePrefixCommit = serde_json::from_value(bad_profile).unwrap();
        assert!(!parsed.passes_strict_carrier_schema());
    }
}
