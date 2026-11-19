//! Cooperative session negotiation: the msp-cooperative-v1 §2/§3 wire
//! shapes plus the ADR-032 §3 additive fields, and the frozen reason
//! vocabularies of the VerifyDrafts family (ADR-032 §2/§3).
//!
//! No Rust `SessionOffer` existed before ADR-032 (only scheduler shadow
//! references), so this module defines all three negotiation messages
//! fresh, byte-matching the frozen document
//! (`protocol/msp-cooperative-v1.md` §2/§3) plus the additive fields
//! ADR-032 §3 pins on top:
//!
//! - `SessionOffer.verifier_backend` — the requester's own backend (under
//!   the project rule the requester hosts exact profile P too). Required
//!   in the new canonical form (`session-offer-2.json` vectors; plan flag
//!   F-6: "additive" in the ADR, required here — no deployed fleet to be
//!   compatible with).
//! - `SessionOffer.profile_id` + `SessionOffer.generation_params_hash` —
//!   the offer-form-v3 binding (ADR-032 revision 4 §3, gap G3): the
//!   coordinator's pinned exact profile and sampling parameters,
//!   negotiation-time DISCOVERY fields compared against the serving
//!   side's own pinned config (verifier-side pinning at stages 4/7 and
//!   §8 commit-time equality REMAINS the enforcement authority — a lying
//!   offer is caught exactly as a lying request is). A THIRD canonical
//!   form (`session-offer-3.json`); absence fails schema, and
//!   `session-offer-1/2.json` are preserved as data that FAILS
//!   deserialization.
//! - `SessionAccept.engine` — the `EngineDisclosure`
//!   `{backend, batch_verify, batch_window_max}` (RC-8): the largest
//!   window this engine verifies in ONE pass.
//! - `SessionReject` — the honest reject path with the frozen reason
//!   vocabulary `preset_unavailable | backend_mismatch |
//!   batch_verify_unsupported | budget_infeasible` (A-4) plus the two
//!   offer-v3 reasons `profile_mismatch | params_mismatch` (ADR-032
//!   revision 4 §3/G3 — negotiation-level vocabulary, the same class as
//!   `preset_unavailable`; the §6.5 registry is untouched).
//!
//! Negotiation messages carry no signature of their own: they ride the
//! handshake-authenticated session (msp-cooperative-v1 §1; msp-v1 §6.6
//! PeerId binding), exactly like today's `SpecMessage` non-commit
//! variants. The frozen §5 `EligibilityLease` signed shape is NOT touched
//! (`protocol/vectors/lease-hubkey-1.json` byte-pins it); backend pairing
//! rides this negotiation layer.
//!
//! The reason vocabularies live here (single home for frozen strings):
//! `SessionRejectReason` (negotiation), `CancelRoundReason` (round-level
//! abandons of the VerifyDrafts family — cooperative-namespace messages,
//! NOT §6.5 codes, per ADR-032 §2 decision B2/A-5), and
//! [`FrameRejectReason`] — the frame/session-level codes this family maps
//! 1:1 onto the effective msp-v1 §6.5 registry (ADR-028 §5: no registry
//! change).

use serde::{Deserialize, Serialize};

use crate::verifydrafts::WINDOW_CAP;

/// The cooperative negotiation namespace version every message in this
/// module carries (msp-cooperative-v1 §2, frozen).
pub const COOPERATIVE_PROTOCOL_VERSION: &str = "msp-cooperative-v1";

// ---------------------------------------------------------------------------
// Preset (msp-cooperative-v1 §1/§2: "SessionOffer and the preset enum")
// ---------------------------------------------------------------------------

/// The negotiated contract tier (ADR-029 names; semantics superseded by
/// ADR-045 — msp-cooperative-v1 §2/§6, frozen: exactly these five
/// values). The ONLY mode-ish field on the wire; primitive-mode
/// resolution is planner-internal (§4 of the doc). ADR-045: every tier
/// is LOSSLESS (no tier samples differently) and the tiers form a
/// strictly upward verification-DEPTH gradient on the always-on family
/// baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    /// Best single host by measured speed + family verification; lossless;
    /// the default (ADR-045: today's behavior, relabeled honestly).
    Fast,
    /// Fast, plus the composed in-process speculative engine when the
    /// live prediction says it beats the fastest single host — lossless
    /// (`speculative_exact`, verified every round), with per-turn honest
    /// fallback (ADR-045 P2 + its pre-registered protocol).
    Balanced,
    /// Balanced, plus the full verification cohort (every available
    /// same-model verifier) and disagreement escalation — LOSSLESS under
    /// ADR-045 (the ADR-029 "approximate — never lossless" reading is
    /// RETIRED; output-influencing additions are P3 and need their own
    /// ADR). Fan-out lands with P2.
    Deep,
    /// Deep, plus cross-model cross-check on the lease-gated ADR-042
    /// serving path (verdict, never rewrite; content egress disclosed at
    /// the point of choice; never the ADR-033 advisory plane).
    Verified,
    /// Verified, plus artifact digest re-verification and the full audit
    /// record (counts and hashes only, never content).
    Maximum,
}

impl Preset {
    /// Stable wire/record label (the frozen msp-cooperative-v1 §2 strings).
    pub fn as_str(self) -> &'static str {
        match self {
            Preset::Fast => "fast",
            Preset::Balanced => "balanced",
            Preset::Deep => "deep",
            Preset::Verified => "verified",
            Preset::Maximum => "maximum",
        }
    }
}

impl std::fmt::Display for Preset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Backend + engine disclosure (ADR-032 §3)
// ---------------------------------------------------------------------------

/// Engine backend vocabulary (ADR-032 §3, from E0/ADR-024: greedy
/// determinism is CPU-identical across thread counts and Vulkan-identical
/// across GPU vendors, with CPU ≠ Vulkan — so pairing is per backend
/// family, never mixed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// CPU (any thread count): E0-proven identical continuations.
    Cpu,
    /// Vulkan (any GPU vendor): E0-proven identical continuations.
    Vulkan,
}

impl Backend {
    /// Stable wire/record label.
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Cpu => "cpu",
            Backend::Vulkan => "vulkan",
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The verifier's engine capability disclosure (ADR-032 §3, RC-8) — the
/// additive `SessionAccept.engine` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineDisclosure {
    /// The backend this peer actually verifies under.
    pub backend: Backend,
    /// Whether this engine can verify a draft window in ONE batched pass
    /// (ADR-031 in-process C-API adapter or an equivalent surface). The
    /// pinned llama.cpp HTTP server cannot — such peers declare `false`
    /// and remain first-class singles, never batch verifiers.
    pub batch_verify: bool,
    /// The largest window this engine verifies in one pass,
    /// `1..=WINDOW_CAP`. `batch_verify: true` REQUIRES an honest value
    /// here (invariant I4); guidance for incapable peers is
    /// `batch_verify: false, batch_window_max: 1`.
    pub batch_window_max: u32,
}

impl EngineDisclosure {
    /// Schema-validity of the disclosure (ADR-032 §3): `batch_window_max`
    /// MUST lie in `1..=WINDOW_CAP`. Any in-range value is schema-valid;
    /// the capability MEANING only attaches to `batch_verify: true` (which
    /// this range check therefore already satisfies — a peer that cannot
    /// honor I4 must declare `batch_verify: false`).
    pub fn is_valid_disclosure(&self) -> bool {
        (1..=WINDOW_CAP).contains(&self.batch_window_max)
    }
}

// ---------------------------------------------------------------------------
// Negotiation messages (msp-cooperative-v1 §2/§3 + ADR-032 §3)
// ---------------------------------------------------------------------------

/// Session budget envelope (msp-cooperative-v1 §2, frozen field set).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBudget {
    /// Cohort-size cap inside the preset envelope (`>= 1`); the planner
    /// still picks the smallest useful cohort.
    pub max_endpoints: u32,
    /// Summed wall-seconds the session may spend across peers (`>= 1`).
    pub max_endpoint_seconds: u64,
    /// Output-token ceiling for the session (`>= 1`). The VerifyDrafts
    /// verifier enforces this cumulatively on COMMITTED tokens (ADR-032
    /// §8e / invariant I8).
    pub max_output_tokens: u32,
}

/// Requester → peer at cooperative session open (msp-cooperative-v1 §2)
/// with the ADR-032 §3 additive `verifier_backend` (the requester's own
/// backend — under the project rule the requester hosts exact profile P
/// too; backend pairing is per family, so a differing peer rejects with
/// `backend_mismatch` and the requester falls back to single, never
/// silently) and the revision-4 offer-form-v3 binding fields
/// `profile_id` + `generation_params_hash` (§3 gap G3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOffer {
    /// Opaque unique string generated by the requester; echoed by
    /// `SessionAccept` and carried by the ReceiptV2.
    pub session_id: String,
    /// Always `"msp-cooperative-v1"`.
    pub protocol_version: String,
    /// The negotiated contract tier (frozen five-value enum).
    pub preset: Preset,
    /// The budget envelope; the serving side clamps DOWN only, never up.
    pub budget: SessionBudget,
    /// ADDITIVE (ADR-032 §3): the requester's own backend. Required in
    /// the canonical form pinned by the `session-offer-2.json`
    /// golden vectors (plan flag F-6).
    pub verifier_backend: Backend,
    /// ADDITIVE (ADR-032 revision 4 §3 / G3): the coordinator's pinned
    /// exact profile (`msp1:<64 hex>`, §1 form — the project rule means
    /// it already holds it). REQUIRED in the THIRD canonical form pinned
    /// by `session-offer-3.json`: absence fails schema, and the base and
    /// v2 forms are preserved as DATA that fails deserialization
    /// (`session-offer-1/2.json`). The serving side compares it against
    /// its own pinned config and rejects `profile_mismatch`; this is
    /// negotiation-time DISCOVERY — verifier-side pinning (stage 7 +
    /// teardown, §8 commit-time equality) remains the enforcement
    /// authority.
    pub profile_id: String,
    /// ADDITIVE (ADR-032 revision 4 §3 / G3): the coordinator's pinned
    /// sampling parameters as this family's canonical
    /// `generation_params_hash` (bare 64-hex, §1 rule-3 preimage — the
    /// F-6 mechanism). REQUIRED in the third canonical form; the serving
    /// side compares it against its own pinned params hash and rejects
    /// `params_mismatch` (discovery, not trusted input).
    pub generation_params_hash: String,
}

/// Peer → requester reply (msp-cooperative-v1 §3) with the ADR-032 §3
/// additive `engine` disclosure (RC-8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAccept {
    /// Echoed from the offer.
    pub session_id: String,
    /// Echoed from the offer.
    pub protocol_version: String,
    /// Echoed from the offer.
    pub preset: Preset,
    /// The EFFECTIVE budget (clamped DOWN only, never up).
    pub budget: SessionBudget,
    /// ADDITIVE (ADR-032 §3): the peer's engine capability disclosure —
    /// `batch_verify: true` REQUIRES an honest `batch_window_max` in
    /// `1..=WINDOW_CAP`; a peer that cannot honor invariant I4 declares
    /// `batch_verify: false`.
    pub engine: EngineDisclosure,
}

/// Peer → requester honest reject (ADR-032 §3, A-4): the wire shape for
/// "this peer cannot take the session". A peer whose backend differs, or
/// that cannot batch-verify, signals it here and the requester falls back
/// to single — mandatory, never silent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReject {
    /// Echoed from the offer.
    pub session_id: String,
    /// Echoed from the offer.
    pub protocol_version: String,
    /// The frozen reject reason.
    pub reason: SessionRejectReason,
}

/// The ADR-036 user-content session-open PIN CARRIER: the coordinator →
/// serving-peer frame that carries an ELECTED family-verified chat's
/// conversation as token ids plus the rule-3 commitment, sent after the
/// `lease` carrier (when presented) and immediately BEFORE the
/// `SessionOffer` (the fixed open sequence; the lease precedes it so
/// lease refusal happens before the conversation is sent). STRICT bare
/// object (`deny_unknown_fields` — it is content-bearing, so the schema
/// is closed); canonical JSON per msp-v1 §2.2; Ed25519 signature over
/// the canonical form with `signature` omitted entirely (§1 rule 4 —
/// use [`crate::verifydrafts::sign_pin_carrier`] / `signing_preimage`).
///
/// `pin_commitment = hex(sha256(prompt_tokens as little-endian u32
/// each))` — the ADR-034 rule-3 pin identity, NO parent: the prefix-hash
/// chain still starts at `GENESIS_PREFIX_HASH`; the commitment binds the
/// ENGINE ROOT (the per-session prefill), never a round's
/// `parent_prefix_hash`.
///
/// Hygiene (ADR-036 §3.2, binding): `prompt_tokens` are content — never
/// logged, telemetered, echoed in rejections, or carried in receipts;
/// the commitment is content-derived and stays OUT of telemetry (local
/// status/diagnostics only, unlike the public neutral pin hash per
/// ADR-034 rule 7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WirePinCarrier {
    /// MUST equal the subsequent `SessionOffer`'s (mismatch `bad_frame`);
    /// echoed by accept/reject.
    pub session_id: String,
    /// Always `"msp-cooperative-v1"` (binds the namespace version).
    pub protocol_version: String,
    /// The coordinator's per-(session, sender) counter (RC-7): the
    /// carrier ESTABLISHES the baseline; every later coordinator
    /// `VerifyDrafts` carries `seq` strictly greater.
    pub seq: u64,
    /// Always `0` — the reserved session-open phase marker; in carrier
    /// sessions every `VerifyDrafts` round is ≥ 1.
    pub round: u32,
    /// The coordinator's pinned exact profile (`msp1:<64 hex>`); MUST
    /// equal the offer's; the serving side compares against its pinned
    /// profile (`profile_mismatch` at the carrier — the honest-early
    /// G3 close).
    pub profile_id: String,
    /// The coordinator's pinned sampling params hash (bare 64-hex); MUST
    /// equal the offer's; compared against the serving side's pinned
    /// params (`params_mismatch`).
    pub generation_params_hash: String,
    /// The user's conversation rendered through the profile's pinned chat
    /// template (ADR-025 application point) and pinned tokenizer, as
    /// token ids, length ≥ 1, bounded by the msp-v1 §6.4 256 KiB frame
    /// limit. The serving side does NOT re-derive — the ids ARE the
    /// contract. Content: see the hygiene note above.
    pub prompt_tokens: Vec<u32>,
    /// `hex(sha256(prompt_tokens LE-u32))` — see the type doc.
    pub pin_commitment: String,
    /// Single-use per session; enters the session nonce ledger.
    pub nonce: String,
    /// Open-phase deadline; the serving side clamps `[1000, 120000]` and
    /// re-checks before prefill dispatch.
    pub deadline_ms: u32,
    /// The coordinator's installation id; MUST equal the id derived from
    /// the signing key AND the QUIC-authenticated remote PeerId.
    pub sender: String,
    /// Base64 Ed25519 over the canonical JSON with this field omitted
    /// entirely.
    pub signature: String,
}

impl WirePinCarrier {
    /// Validates the commitment against the payload:
    /// `pin_commitment == pin_commitment_of(prompt_tokens)` (ADR-036
    /// §3.2 — the `pin_mismatch` admission check's pure core).
    pub fn commitment_matches(&self) -> bool {
        self.pin_commitment == pin_commitment_of(&self.prompt_tokens)
    }

    /// The pure schema/shape validation core (ADR-036 §3.2 — the
    /// `bad_frame`-class admission checks, first-failure-wins): the
    /// frozen protocol version, the reserved session-open markers
    /// (`round == 0`, `seq >= 1`), a non-empty token payload, bare
    /// lowercase 64-hex hashes, and the commitment BINDING the payload.
    /// Signature/sender verification and the deadline clamp live at the
    /// transport-facing admission (node), not here.
    pub fn validate(&self) -> Result<(), PinCarrierError> {
        if self.protocol_version != COOPERATIVE_PROTOCOL_VERSION {
            return Err(PinCarrierError::ProtocolVersion);
        }
        if self.round != 0 {
            return Err(PinCarrierError::RoundNotSessionOpen);
        }
        if self.seq < 1 {
            return Err(PinCarrierError::SeqBaseline);
        }
        if self.prompt_tokens.is_empty() {
            return Err(PinCarrierError::EmptyPromptTokens);
        }
        if !is_bare_lower_hex_64(&self.generation_params_hash) {
            return Err(PinCarrierError::ParamsHashForm);
        }
        if !is_bare_lower_hex_64(&self.pin_commitment) {
            return Err(PinCarrierError::CommitmentForm);
        }
        if !self.commitment_matches() {
            return Err(PinCarrierError::CommitmentMismatch);
        }
        Ok(())
    }
}

/// The pure [`WirePinCarrier::validate`] failures (labels only — no
/// content rides any error, per the ADR-036 hygiene rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinCarrierError {
    /// `protocol_version` is not the frozen namespace constant.
    ProtocolVersion,
    /// `round` is not the reserved session-open marker `0`.
    RoundNotSessionOpen,
    /// `seq` does not establish a valid coordinator baseline (≥ 1).
    SeqBaseline,
    /// `prompt_tokens` is empty (length ≥ 1 is the contract).
    EmptyPromptTokens,
    /// `generation_params_hash` is not bare lowercase 64-hex.
    ParamsHashForm,
    /// `pin_commitment` is not bare lowercase 64-hex.
    CommitmentForm,
    /// The commitment does not bind the payload (`pin_mismatch`'s pure
    /// core).
    CommitmentMismatch,
}

impl PinCarrierError {
    /// Stable label (telemetry/diagnostics vocabulary).
    pub fn as_str(self) -> &'static str {
        match self {
            PinCarrierError::ProtocolVersion => "protocol_version",
            PinCarrierError::RoundNotSessionOpen => "round_not_session_open",
            PinCarrierError::SeqBaseline => "seq_baseline",
            PinCarrierError::EmptyPromptTokens => "empty_prompt_tokens",
            PinCarrierError::ParamsHashForm => "params_hash_form",
            PinCarrierError::CommitmentForm => "commitment_form",
            PinCarrierError::CommitmentMismatch => "commitment_mismatch",
        }
    }
}

impl std::fmt::Display for PinCarrierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bare lowercase 64-hex (the ADR-032 §1 hash form).
fn is_bare_lower_hex_64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The ADR-034 rule-3 / ADR-036 §3.2 commitment construction:
/// `hex(sha256(tokens rendered as little-endian u32 each))`, NO parent
/// (unlike the prefix-hash chain). Pure and public so both ends and the
/// golden vectors share one definition.
pub fn pin_commitment_of(prompt_tokens: &[u32]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for token in prompt_tokens {
        hasher.update(token.to_le_bytes());
    }
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Frozen reason vocabularies
// ---------------------------------------------------------------------------

/// Why a peer rejected a `SessionOffer` (ADR-032 §3, frozen):
/// `preset_unavailable | backend_mismatch | batch_verify_unsupported |
/// budget_infeasible` plus the two offer-form-v3 reasons
/// `profile_mismatch | params_mismatch` (revision 4 §3/G3:
/// negotiation-level vocabulary, the same class as
/// `preset_unavailable`; the §6.5 registry is untouched — the
/// frame-level `profile_mismatch` code is a different vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRejectReason {
    /// The peer cannot honor the offered preset tier.
    PresetUnavailable,
    /// The peer's engine backend differs from the requester's
    /// `verifier_backend` (E0 pairing: CPU ≠ Vulkan, never mixed).
    BackendMismatch,
    /// The peer's engine cannot verify a window in one batched pass
    /// (e.g. the pinned llama.cpp HTTP adapter).
    BatchVerifyUnsupported,
    /// The offered budget is infeasible for this peer.
    BudgetInfeasible,
    /// The offer's `profile_id` differs from the peer's own pinned exact
    /// profile (ADR-032 revision 4 §3/G3): the session would open only to
    /// fail at stage 7 — rejected honestly at negotiation instead, so the
    /// requester falls back to a same-profile peer.
    ProfileMismatch,
    /// The offer's `generation_params_hash` differs from the peer's own
    /// pinned sampling parameters (revision 4 §3/G3): a params-mismatched
    /// pairing would open a session that then fails EVERY round at stage
    /// 4 (`bad_frame`) with no teardown and no discovery — the honest
    /// reject closes that fail-closed gap.
    ParamsMismatch,
    /// ADR-036 §3.2 (rule 8's reserved reason, landing): the pin
    /// carrier's `pin_commitment` does not equal
    /// `sha256(prompt_tokens LE-u32)` — the commitment does not bind the
    /// payload it rode with. The string is deliberately identical to the
    /// frozen probe verdict label so one vocabulary names one fact.
    PinMismatch,
    /// ADR-036 §3.1/§3.2: this peer's user-content carriage setting is
    /// OFF — it refuses to process other users' conversations through
    /// family verification (default-on posture per the owner directive
    /// 2026-10-13; the opt-OUT is honest and labeled, never a silent
    /// drop, and never mislabeled as `pin_mismatch`: a refusal is not a
    /// mismatch).
    ContentCarriageRefused,
}

impl SessionRejectReason {
    /// Stable wire/record label (the frozen ADR-032 §3 strings).
    pub fn as_str(self) -> &'static str {
        match self {
            SessionRejectReason::PresetUnavailable => "preset_unavailable",
            SessionRejectReason::BackendMismatch => "backend_mismatch",
            SessionRejectReason::BatchVerifyUnsupported => "batch_verify_unsupported",
            SessionRejectReason::BudgetInfeasible => "budget_infeasible",
            SessionRejectReason::ProfileMismatch => "profile_mismatch",
            SessionRejectReason::ParamsMismatch => "params_mismatch",
            SessionRejectReason::PinMismatch => "pin_mismatch",
            SessionRejectReason::ContentCarriageRefused => "content_carriage_refused",
        }
    }
}

impl std::fmt::Display for SessionRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why one ROUND of a VerifyDrafts-family session was abandoned (ADR-032
/// §2, frozen): round-level abandons are cooperative-namespace
/// `CancelRound { session_id, round, reason }` messages — NOT §6.5 codes
/// (decision B2/A-5: the effective §6.5 registry contains no
/// chain-position code and none is added). The old vocabulary's
/// `proposal_failed` string belongs to `SpecMessage::CancelRound` and is
/// deliberately NOT reused here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelRoundReason {
    /// `parent_prefix_hash` did not equal the current committed hash; no
    /// state change.
    ParentMismatch,
    /// `round` was not greater than the last handled round; no state
    /// change.
    RoundMismatch,
    /// A `PrefixCommit` chained validly from the parent but did not
    /// reproduce the outstanding `VerifyDraftsResult` (RC-4); the round
    /// is abandoned.
    CommitMismatch,
}

impl CancelRoundReason {
    /// Stable wire/record label (the frozen ADR-032 §2 strings).
    pub fn as_str(self) -> &'static str {
        match self {
            CancelRoundReason::ParentMismatch => "parent_mismatch",
            CancelRoundReason::RoundMismatch => "round_mismatch",
            CancelRoundReason::CommitMismatch => "commit_mismatch",
        }
    }
}

impl std::fmt::Display for CancelRoundReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Frame/session-level reject codes the VerifyDrafts family emits
/// (ADR-032 §2 admission table). These map 1:1 onto the EFFECTIVE msp-v1
/// §6.5 registry strings (msp-v1 §6.5 + ADR-028 §5) with **no registry
/// change** — this enum is the family's subset view of the registry, not a
/// new registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameRejectReason {
    /// Schema invalid / unknown fields, or an invalid signature
    /// (unauthenticated = malformed, fail-closed), or an unknown/mismatched
    /// `session_id`.
    BadFrame,
    /// Duplicate or decreased `seq`, nonce reuse, or a repeated
    /// `VerifyDrafts` while a round is outstanding with a repeated nonce.
    ReplayedRequest,
    /// The ADR-026 lease expired mid-session.
    ExpiredToken,
    /// The session was torn down (e.g. after `profile_mismatch`); stream
    /// closed.
    CancelledByPeer,
    /// `profile_id` mismatch (also tears the session down).
    ProfileMismatch,
    /// Frame over the 256 KiB limit, or a window over
    /// `min(WINDOW_CAP, batch_window_max)` — before any engine work.
    PayloadTooLarge,
    /// The session budget would be exceeded (budget exhausted, I8).
    Overloaded,
    /// The deadline was past at admission or at the pre-dispatch re-check.
    DeadlineExceeded,
}

impl FrameRejectReason {
    /// Stable wire/record label — EXACTLY the effective §6.5 registry
    /// string (ADR-028 §5 folds included; never a new code).
    pub fn as_str(self) -> &'static str {
        match self {
            FrameRejectReason::BadFrame => "bad_frame",
            FrameRejectReason::ReplayedRequest => "replayed_request",
            FrameRejectReason::ExpiredToken => "expired_token",
            FrameRejectReason::CancelledByPeer => "cancelled_by_peer",
            FrameRejectReason::ProfileMismatch => "profile_mismatch",
            FrameRejectReason::PayloadTooLarge => "payload_too_large",
            FrameRejectReason::Overloaded => "overloaded",
            FrameRejectReason::DeadlineExceeded => "deadline_exceeded",
        }
    }
}

impl std::fmt::Display for FrameRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The effective msp-v1 §6.5 registry (msp-v1 §6.5 list + the ADR-026
    /// `invalid_lease` and ADR-028 §5 `bad_frame`/`executor_error` adds
    /// and renames) — every family code MUST be one of these strings.
    const EFFECTIVE_REGISTRY: [&str; 16] = [
        "handshake_failed",
        "incompatible_protocol",
        "profile_mismatch",
        "invalid_token",
        "invalid_lease",
        "expired_token",
        "revoked_token",
        "replayed_request",
        "overloaded",
        "deadline_exceeded",
        "payload_too_large",
        "runtime_error",
        "bad_frame",
        "executor_error",
        "cancelled_by_peer",
        "interrupted",
    ];

    #[test]
    fn preset_serializes_exactly_the_five_frozen_values() {
        let cases = [
            (Preset::Fast, "fast"),
            (Preset::Balanced, "balanced"),
            (Preset::Deep, "deep"),
            (Preset::Verified, "verified"),
            (Preset::Maximum, "maximum"),
        ];
        for (preset, label) in cases {
            assert_eq!(serde_json::to_value(preset).unwrap(), json!(label));
            assert_eq!(preset.as_str(), label);
            assert_eq!(preset.to_string(), label);
            assert_eq!(
                serde_json::from_value::<Preset>(json!(label)).unwrap(),
                preset
            );
        }
        // Anything else fails deserialization (frozen enum).
        assert!(serde_json::from_value::<Preset>(json!("turbo")).is_err());
    }

    #[test]
    fn backend_serializes_lowercase() {
        assert_eq!(serde_json::to_value(Backend::Cpu).unwrap(), json!("cpu"));
        assert_eq!(
            serde_json::to_value(Backend::Vulkan).unwrap(),
            json!("vulkan")
        );
        assert_eq!(Backend::Cpu.as_str(), "cpu");
        assert_eq!(Backend::Vulkan.to_string(), "vulkan");
        assert_eq!(
            serde_json::from_value::<Backend>(json!("cpu")).unwrap(),
            Backend::Cpu
        );
        assert!(serde_json::from_value::<Backend>(json!("CUDA")).is_err());
    }

    #[test]
    fn session_offer_wire_shape_is_frozen_doc_plus_additive_backend() {
        let offer = SessionOffer {
            session_id: "sess-1".to_string(),
            protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
            preset: Preset::Verified,
            budget: SessionBudget {
                max_endpoints: 1,
                max_endpoint_seconds: 120,
                max_output_tokens: 2048,
            },
            verifier_backend: Backend::Cpu,
            profile_id: format!("msp1:{}", "ab".repeat(32)),
            generation_params_hash: "cd".repeat(32),
        };
        let value = serde_json::to_value(&offer).unwrap();
        assert_eq!(
            value,
            json!({
                "session_id": "sess-1",
                "protocol_version": "msp-cooperative-v1",
                "preset": "verified",
                "budget": {
                    "max_endpoints": 1,
                    "max_endpoint_seconds": 120,
                    "max_output_tokens": 2048
                },
                "verifier_backend": "cpu",
                "profile_id": format!("msp1:{}", "ab".repeat(32)),
                "generation_params_hash": "cd".repeat(32),
            })
        );
        // Round-trip and canonicalizability (integer-only: no floats).
        assert_eq!(
            serde_json::from_value::<SessionOffer>(value.clone()).unwrap(),
            offer
        );
        assert!(modelswarm_types::canonical_json(&value).is_ok());
    }

    #[test]
    fn session_offer_form_v3_requires_both_binding_fields() {
        // ADR-032 revision 4 §3/G3 (the F-6 mechanism, a THIRD canonical
        // form): absence of EITHER new field fails schema — the base and
        // v2 forms are preserved as data that does NOT deserialize.
        let v3 = json!({
            "session_id": "sess-1",
            "protocol_version": "msp-cooperative-v1",
            "preset": "verified",
            "budget": {
                "max_endpoints": 1,
                "max_endpoint_seconds": 120,
                "max_output_tokens": 2048
            },
            "verifier_backend": "cpu",
            "profile_id": format!("msp1:{}", "ab".repeat(32)),
            "generation_params_hash": "cd".repeat(32),
        });
        assert!(serde_json::from_value::<SessionOffer>(v3.clone()).is_ok());
        // Without profile_id (the v2 form):
        let mut v2 = v3.clone();
        v2.as_object_mut().unwrap().remove("profile_id");
        assert!(
            serde_json::from_value::<SessionOffer>(v2).is_err(),
            "the v2 offer form must fail the v3 schema"
        );
        // Without generation_params_hash:
        let mut no_params = v3.clone();
        no_params
            .as_object_mut()
            .unwrap()
            .remove("generation_params_hash");
        assert!(
            serde_json::from_value::<SessionOffer>(no_params).is_err(),
            "an offer without the params hash must fail the v3 schema"
        );
    }

    #[test]
    fn session_accept_round_trips_engine_disclosure() {
        let accept = SessionAccept {
            session_id: "sess-1".to_string(),
            protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
            preset: Preset::Balanced,
            budget: SessionBudget {
                max_endpoints: 3,
                max_endpoint_seconds: 60,
                max_output_tokens: 512,
            },
            engine: EngineDisclosure {
                backend: Backend::Vulkan,
                batch_verify: true,
                batch_window_max: 32,
            },
        };
        let value = serde_json::to_value(&accept).unwrap();
        assert_eq!(
            value,
            json!({
                "session_id": "sess-1",
                "protocol_version": "msp-cooperative-v1",
                "preset": "balanced",
                "budget": {
                    "max_endpoints": 3,
                    "max_endpoint_seconds": 60,
                    "max_output_tokens": 512
                },
                "engine": { "backend": "vulkan", "batch_verify": true, "batch_window_max": 32 }
            })
        );
        assert_eq!(
            serde_json::from_value::<SessionAccept>(value).unwrap(),
            accept
        );
    }

    #[test]
    fn engine_disclosure_validity_pins_the_window_cap() {
        // batch_verify: true REQUIRES batch_window_max in 1..=WINDOW_CAP.
        for window in [1u32, 8, WINDOW_CAP] {
            assert!(EngineDisclosure {
                backend: Backend::Cpu,
                batch_verify: true,
                batch_window_max: window,
            }
            .is_valid_disclosure());
        }
        for window in [0u32, WINDOW_CAP + 1, u32::MAX] {
            assert!(!EngineDisclosure {
                backend: Backend::Cpu,
                batch_verify: true,
                batch_window_max: window,
            }
            .is_valid_disclosure());
        }
        // Guidance for incapable peers: false + 1. Any in-range value is
        // schema-valid with batch_verify: false (meaning attaches only to
        // `true`); out-of-range is never schema-valid.
        assert!(EngineDisclosure {
            backend: Backend::Cpu,
            batch_verify: false,
            batch_window_max: 1,
        }
        .is_valid_disclosure());
        assert!(!EngineDisclosure {
            backend: Backend::Cpu,
            batch_verify: false,
            batch_window_max: WINDOW_CAP + 1,
        }
        .is_valid_disclosure());
    }

    #[test]
    fn session_reject_wire_shape_and_frozen_reasons() {
        for (reason, label) in [
            (SessionRejectReason::PresetUnavailable, "preset_unavailable"),
            (SessionRejectReason::BackendMismatch, "backend_mismatch"),
            (
                SessionRejectReason::BatchVerifyUnsupported,
                "batch_verify_unsupported",
            ),
            (SessionRejectReason::BudgetInfeasible, "budget_infeasible"),
            // The two offer-form-v3 reasons (ADR-032 revision 4 §3/G3).
            (SessionRejectReason::ProfileMismatch, "profile_mismatch"),
            (SessionRejectReason::ParamsMismatch, "params_mismatch"),
        ] {
            assert_eq!(reason.as_str(), label);
            assert_eq!(reason.to_string(), label);
            let reject = SessionReject {
                session_id: "sess-1".to_string(),
                protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
                reason,
            };
            assert_eq!(
                serde_json::to_value(&reject).unwrap(),
                json!({
                    "session_id": "sess-1",
                    "protocol_version": "msp-cooperative-v1",
                    "reason": label
                })
            );
            assert_eq!(
                serde_json::from_value::<SessionReject>(serde_json::to_value(&reject).unwrap())
                    .unwrap()
                    .reason,
                reason
            );
        }
    }

    #[test]
    fn cancel_round_reasons_are_the_frozen_three() {
        let cases = [
            (CancelRoundReason::ParentMismatch, "parent_mismatch"),
            (CancelRoundReason::RoundMismatch, "round_mismatch"),
            (CancelRoundReason::CommitMismatch, "commit_mismatch"),
        ];
        for (reason, label) in cases {
            assert_eq!(reason.as_str(), label);
            assert_eq!(reason.to_string(), label);
            assert_eq!(serde_json::to_value(reason).unwrap(), json!(label));
            assert_eq!(
                serde_json::from_value::<CancelRoundReason>(json!(label)).unwrap(),
                reason
            );
        }
        // The old vocabulary's reason string is not expressible here.
        assert!(serde_json::from_value::<CancelRoundReason>(json!("proposal_failed")).is_err());
    }

    #[test]
    fn frame_reject_reasons_match_the_effective_registry_exactly() {
        let codes = [
            FrameRejectReason::BadFrame,
            FrameRejectReason::ReplayedRequest,
            FrameRejectReason::ExpiredToken,
            FrameRejectReason::CancelledByPeer,
            FrameRejectReason::ProfileMismatch,
            FrameRejectReason::PayloadTooLarge,
            FrameRejectReason::Overloaded,
            FrameRejectReason::DeadlineExceeded,
        ];
        for code in codes {
            let label = code.as_str();
            assert_eq!(code.to_string(), label);
            assert_eq!(serde_json::to_value(code).unwrap(), json!(label));
            assert_eq!(
                serde_json::from_value::<FrameRejectReason>(json!(label)).unwrap(),
                code
            );
            // 1:1 onto the effective §6.5 registry: no new codes, ever.
            assert!(
                EFFECTIVE_REGISTRY.contains(&label),
                "{label} is not an effective §6.5 registry string"
            );
        }
    }
}
