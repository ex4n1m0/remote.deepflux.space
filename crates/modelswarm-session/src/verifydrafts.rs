//! ADR-032 §1 — the batched speculative-verification family: the
//! `VerifyDrafts` / `VerifyDraftsResult` wire types, their strict
//! two-pass deserialization, and the family's byte-rule helpers.
//!
//! This module carries the **type and serialization layer** (implementation
//! plan §1, step 1 — sessions 1 and 2), the **verifier-side admission
//! gate and round state machine** (plan §3 / ADR-032 §8, session 3 — see
//! [`BatchVerifyEngine`] and [`VerifyDraftsGate`]), and the
//! **coordinator side** (plan §4 / ADR-032 §2 RC-3, §1 RC-2, §3 RC-1,
//! session 4 — see [`VerifyDraftsCoordinator`] for result admission,
//! [`VerifierTiming`] / [`VerifierTimings`] for the timing-trust rule,
//! and the [`VerifyTelemetry`] / [`WindowAuditor`] trait surfaces the
//! node/desktop layers implement). Nothing here talks to a real engine:
//! engine access is the [`BatchVerifyEngine`] trait, mockable in tests.
//!
//! Wire form: both messages serialize as the BARE objects of ADR-032 §1 —
//! they are NOT new `SpecMessage` variants (no external tag) — and ride
//! the same `Session::send_json`/`recv_json` path as `SpecMessage`
//! (ADR-018 staging), each as one JSON frame, in the
//! `msp-cooperative-v1` namespace.
//!
//! # Byte rules pinned here (ADR-032 §1, rules 1–5)
//!
//! 1. **Hash wire form:** every hash in this family is BARE lowercase
//!    64-hex ([`is_bare_hash`]). The `"sha256:<…>"` prefixed notation is
//!    hub `bodyDigest` prose and MUST NOT appear on the wire.
//! 2. **Prefix-hash preimage:** `new_prefix_hash` is the shipped
//!    [`crate::compute_prefix_hash`] over `(parent ‖ accepted prefix ‖
//!    [correction])` with [`crate::GENESIS_PREFIX_HASH`] at the root. No
//!    new hash function exists in this module.
//! 3. **`generation_params_hash` preimage:** NEW canonical encoding
//!    ([`batch_generation_params_hash`]): sha256 over canonical JSON of
//!    `{"seed":<null|integer>,"temperature":<integer>,"top_k":<u32>,
//!    "top_p":<integer>}`. Integral `f32` values render as bare
//!    integers; a non-integral value fails closed
//!    ([`ParamsHashError::NonIntegral`]). The shipped
//!    [`crate::spec::default_sampling_params_hash`] (Rust `Debug` string)
//!    is the OLD vocabulary's internal value and is NOT this family's
//!    preimage.
//! 4. **Signature preimage:** canonical JSON of the message with the
//!    `signature` field OMITTED ENTIRELY ([`signing_preimage`]) — not
//!    null, not empty string. Every other declared field, including
//!    null-valued `divergence_point` and an EOG `correction`, is PRESENT.
//!    Floats are forbidden in signed payloads (msp-v1 §2.2;
//!    `modelswarm_types::canonical_json` rejects any float).
//! 5. **Sender binding:** `sender` MUST equal
//!    [`installation_id_for`](modelswarm_identity::installation_id_for)
//!    of the verifying key AND the QUIC-authenticated remote PeerId
//!    (msp-v1 §6.6). [`verify_verify_drafts_signature`] and
//!    [`verify_verify_drafts_result_signature`] enforce the key
//!    derivation FIRST — the `verify_commit_signature` discipline; the
//!    remote-PeerId equality is enforced by the serve loop, the only
//!    place that knows the stream's peer id.
//!
//! Signatures are base64 STANDARD (the alphabet of every existing
//! cooperative signature; base64url is the hub lease-token convention,
//! not this wire).

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use modelswarm_identity::{installation_id_for, peer_id_for, InstallationIdentity};
use modelswarm_runtime::{RuntimeError, SamplingParams};
use modelswarm_transport::ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use modelswarm_transport::frame::MAX_FRAME_BYTES;
use modelswarm_types::{canonical_json, CanonicalError};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::negotiation::{
    CancelRoundReason, EngineDisclosure, FrameRejectReason, SessionAccept, SessionBudget,
    SessionOffer, SessionRejectReason, WirePinCarrier,
};
use crate::{
    compute_prefix_hash, CommitPrefix, SpecError, DUPLICATE_MEMORY_ROUNDS, GENESIS_PREFIX_HASH,
};

/// The cooperative namespace version every family message carries
/// (must equal `"msp-cooperative-v1"`).
pub const COOPERATIVE_PROTOCOL_VERSION: &str = "msp-cooperative-v1";

/// Hard cap on `window_tokens` length per `VerifyDrafts` (ADR-032 §1,
/// frozen). A window longer than `min(WINDOW_CAP, the peer's
/// `batch_window_max`)` is `payload_too_large` BEFORE any engine work.
pub const WINDOW_CAP: u32 = 32;

/// Lower bound of the server-side `deadline_ms` clamp (ADR-032 §2, the
/// msp-v1 §6.4 discipline: clamp, not reject).
pub const DEADLINE_CLAMP_MIN_MS: u32 = 1_000;
/// Upper bound of the server-side `deadline_ms` clamp (msp-v1 §6.4).
pub const DEADLINE_CLAMP_MAX_MS: u32 = 120_000;

/// Fixed WAIT_COMMIT grace past the outstanding request's `deadline_ms`
/// before the round is abandoned (ADR-032 §8 RC-5(b)).
pub const WAIT_COMMIT_GRACE_MS: u64 = 250;

/// Allowed clock noise in the `verify_pass_ms` cross-check: a claim above
/// observed round wall time + this is `verify_ms_lie` telemetry
/// (ADR-032 §1).
pub const VERIFY_PASS_CLOCK_NOISE_MS: u64 = 25;

/// A second protocol violation by the same peer within one session tears
/// the session down (ADR-032 §2, RC-3 tail).
pub const TEARDOWN_VIOLATION_THRESHOLD: u32 = 2;

// ---------------------------------------------------------------------------
// Wire messages (ADR-032 §1, field-for-field)
// ---------------------------------------------------------------------------

/// Declared field set of [`VerifyDrafts`] — the two-pass key-set equality
/// check treats a missing OR unknown key as a schema failure (`bad_frame`).
pub const VERIFY_DRAFTS_FIELDS: [&str; 13] = [
    "session_id",
    "protocol_version",
    "seq",
    "round",
    "profile_id",
    "parent_prefix_hash",
    "generation_params_hash",
    "window_tokens",
    "proposer_id",
    "nonce",
    "deadline_ms",
    "sender",
    "signature",
];

/// Declared field set of [`VerifyDraftsResult`] — same two-pass key-set
/// equality rule as [`VERIFY_DRAFTS_FIELDS`].
pub const VERIFY_DRAFTS_RESULT_FIELDS: [&str; 12] = [
    "session_id",
    "protocol_version",
    "seq",
    "round",
    "accepted_prefix_len",
    "divergence_point",
    "correction",
    "new_prefix_hash",
    "verify_pass_ms",
    "nonce_echo",
    "sender",
    "signature",
];

/// Coordinator → verifier: verify ONE draft window in ONE batched engine
/// pass (ADR-032 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyDrafts {
    /// Echoed from the `SessionOffer`.
    pub session_id: String,
    /// Must equal [`COOPERATIVE_PROTOCOL_VERSION`].
    pub protocol_version: String,
    /// Per `(session, sender)` strictly monotone counter (§2 RC-7).
    pub seq: u64,
    /// Strictly monotone per session; gaps allowed after abandonment
    /// (§8 RC-5(c)).
    pub round: u64,
    /// `"msp1:<64 hex>"` — cross-profile isolation (I7).
    pub profile_id: String,
    /// Bare 64-char lowercase hex (§1 rule 1): the current committed
    /// prefix hash this window chains onto.
    pub parent_prefix_hash: String,
    /// Bare 64-char lowercase hex: this family's canonical
    /// generation-params preimage (§1 rule 3 — NOT the old vocabulary's
    /// `default_sampling_params_hash`).
    pub generation_params_hash: String,
    /// The draft window: `u32` token ids, length
    /// `1..=min(WINDOW_CAP, batch_window_max)`. An EMPTY window is
    /// malformed (there is nothing to verify).
    pub window_tokens: Vec<u32>,
    /// The peer that drafted the window.
    pub proposer_id: String,
    /// Single-use per session (I6).
    pub nonce: String,
    /// Clamped server-side to
    /// `[DEADLINE_CLAMP_MIN_MS, DEADLINE_CLAMP_MAX_MS]`.
    pub deadline_ms: u32,
    /// `installation_id_for` of the signer's verifying key (§1 rule 5).
    pub sender: String,
    /// base64 (STANDARD) Ed25519 over the canonical JSON with
    /// `signature` omitted entirely (§1 rule 4).
    pub signature: String,
}

/// Verifier → coordinator: the one-pass verification outcome (ADR-032
/// §1). `seq` is the VERIFIER's own per-session counter — NOT a
/// continuation of the coordinator's (§2 RC-7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyDraftsResult {
    /// Echoed from the request.
    pub session_id: String,
    /// Echoed from the request.
    pub protocol_version: String,
    /// The VERIFIER's own `(session, sender)` counter (§2 RC-7).
    pub seq: u64,
    /// Echoed from the request.
    pub round: u64,
    /// `<= len(window_tokens)` (§2 RC-3 (d)).
    pub accepted_prefix_len: u32,
    /// 0-based index of the first rejected position; `null` on full
    /// acceptance. PRESENT as `null` (never omitted — the two-pass
    /// key-set check enforces presence). On rejection,
    /// `divergence_point == accepted_prefix_len`.
    pub divergence_point: Option<u32>,
    /// Replacement token on rejection, bonus (lookahead) token on full
    /// acceptance; `null` exactly at end-of-generation (plan flag F-2;
    /// PRESENT as `null`, never omitted).
    pub correction: Option<u32>,
    /// Bare 64-char lowercase hex: [`crate::compute_prefix_hash`] over
    /// `(parent ‖ accepted prefix ‖ [correction])` (§1 rule 2).
    pub new_prefix_hash: String,
    /// The verifier's measured engine-pass wall time in WHOLE
    /// milliseconds (u32, rounded to nearest; test pins assert `>= 0`
    /// only, never measured values). MUST be an integer — floats are
    /// forbidden in signed canonical payloads, so a fractional field
    /// would make this message unsignable.
    pub verify_pass_ms: u32,
    /// EQUALS the outstanding request's `nonce` (RC-3 (b)).
    pub nonce_echo: String,
    /// The verifier peer's installation id (§1 rule 5).
    pub sender: String,
    /// base64 (STANDARD) Ed25519, same §1 rule 4 preimage discipline.
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Strict two-pass deserialization (plan §1.2)
// ---------------------------------------------------------------------------

/// Schema failure of a family frame — every variant maps onto the
/// admission code `bad_frame` (ADR-032 §2 table row "schema invalid /
/// unknown fields").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameParseError {
    /// The frame is not a JSON object.
    NotAnObject,
    /// A declared field is absent. This is what enforces PRESENT-AS-NULL:
    /// `divergence_point` and an EOG `correction` must appear with `null`
    /// values, not be omitted (serde alone cannot distinguish missing
    /// from null on `Option` fields).
    MissingKey(String),
    /// A key outside the declared field set is present.
    UnknownKey(String),
    /// A value failed its declared type — e.g. a JSON float where an
    /// integer is pinned (`seq`, `round`, `verify_pass_ms`, …); floats
    /// are forbidden in signed payloads (msp-v1 §2.2).
    BadType(String),
    /// `window_tokens` is empty (ADR-032 §1: an empty window is
    /// malformed — there is nothing to verify).
    EmptyWindow,
}

impl std::fmt::Display for FrameParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameParseError::NotAnObject => write!(f, "frame is not a JSON object"),
            FrameParseError::MissingKey(key) => {
                write!(
                    f,
                    "missing declared field {key:?} (present-as-null fields may not be omitted)"
                )
            }
            FrameParseError::UnknownKey(key) => {
                write!(
                    f,
                    "unknown field {key:?} (key set must equal the declared field set)"
                )
            }
            FrameParseError::BadType(why) => write!(f, "field type mismatch: {why}"),
            FrameParseError::EmptyWindow => {
                write!(f, "window_tokens is empty (an empty window is malformed)")
            }
        }
    }
}

impl std::error::Error for FrameParseError {}

/// Two-pass strict parse: (1) assert the object's key set EQUALS the
/// declared field set — missing key or unknown key is a schema failure;
/// (2) deserialize. `#[serde(deny_unknown_fields)]` is deliberately NOT
/// relied on: this check produces exactly the failure the admission table
/// names, and it is what enforces present-as-null.
fn parse_strict<T: DeserializeOwned>(
    value: &Value,
    declared: &[&str],
) -> Result<T, FrameParseError> {
    let Some(map) = value.as_object() else {
        return Err(FrameParseError::NotAnObject);
    };
    for field in declared {
        if !map.contains_key(*field) {
            return Err(FrameParseError::MissingKey((*field).to_string()));
        }
    }
    for key in map.keys() {
        if !declared.contains(&key.as_str()) {
            return Err(FrameParseError::UnknownKey(key.clone()));
        }
    }
    T::deserialize(value).map_err(|e| FrameParseError::BadType(e.to_string()))
}

impl VerifyDrafts {
    /// Strict two-pass parse from a received JSON frame (see
    /// [`FrameParseError`]; every variant is the `bad_frame` path).
    pub fn parse(value: &Value) -> Result<Self, FrameParseError> {
        let msg: Self = parse_strict(value, &VERIFY_DRAFTS_FIELDS)?;
        if msg.window_tokens.is_empty() {
            return Err(FrameParseError::EmptyWindow);
        }
        Ok(msg)
    }
}

impl VerifyDraftsResult {
    /// Strict two-pass parse from a received JSON frame (see
    /// [`FrameParseError`]; every variant is the `bad_frame` path).
    pub fn parse(value: &Value) -> Result<Self, FrameParseError> {
        parse_strict(value, &VERIFY_DRAFTS_RESULT_FIELDS)
    }
}

// ---------------------------------------------------------------------------
// Byte-rule helpers (ADR-032 §1 rules 1–5)
// ---------------------------------------------------------------------------

/// §1 rule 1: a family hash wire form — exactly 64 characters of
/// `[0-9a-f]`. The `"sha256:<…>"` prefixed notation is hub `bodyDigest`
/// prose and is REJECTED here (the P2P commit-hash convention — shipped
/// `compute_prefix_hash` / `GENESIS_PREFIX_HASH` — is bare hex).
pub fn is_bare_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// §1 rule 3 failure modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamsHashError {
    /// A pinned sampling parameter (`temperature`/`top_p`) is not an
    /// integral `f32` (or is not representable as an integer). This
    /// family renders integral values as bare integers and fails closed —
    /// the canonicalizer rejects floats anyway (msp-v1 §2.2), so a
    /// non-integral value would make the payload unsignable.
    NonIntegral,
    /// Canonical serialization failed. Unreachable in practice: the
    /// rendered object is integer-only by construction.
    Canonical(CanonicalError),
}

impl std::fmt::Display for ParamsHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParamsHashError::NonIntegral => {
                write!(f, "sampling parameter is not integral (fail-closed)")
            }
            ParamsHashError::Canonical(e) => {
                write!(
                    f,
                    "generation-params preimage rejected by canonical JSON: {e}"
                )
            }
        }
    }
}

impl std::error::Error for ParamsHashError {}

/// §1 rule 3: the family's `generation_params_hash` — sha256 over the
/// canonical JSON (msp-v1 §2.2) of the pinned sampling-parameter object
/// `{"seed":<null|integer>,"temperature":<integer>,"top_k":<u32>,
/// "top_p":<integer>}` with `seed` null when unset (rendered as the full
/// integer when set — plan flag F-1).
///
/// Integral `f32` values (`1.0`) render as bare integers (`1`); any
/// non-integral value returns [`ParamsHashError::NonIntegral`] and fails
/// closed. This is NOT the old vocabulary's
/// [`crate::spec::default_sampling_params_hash`] (a Rust `Debug` string)
/// — that value remains internal to the old vocabulary.
pub fn batch_generation_params_hash(params: &SamplingParams) -> Result<String, ParamsHashError> {
    let temperature = integral_i64(params.temperature)?;
    let top_p = integral_i64(params.top_p)?;
    let preimage = serde_json::json!({
        "seed": params.seed,
        "temperature": temperature,
        "top_k": params.top_k,
        "top_p": top_p,
    });
    let canonical = canonical_json(&preimage).map_err(ParamsHashError::Canonical)?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

/// Renders an integral `f32` as `i64`, failing closed on non-integral,
/// non-finite, or out-of-integer-range values.
fn integral_i64(value: f32) -> Result<i64, ParamsHashError> {
    if !value.is_finite() || value.fract() != 0.0 {
        return Err(ParamsHashError::NonIntegral);
    }
    let rendered = value as i64;
    // Saturation guard: an integral f32 beyond i64 range must not render
    // silently as i64::MAX/MIN (fail closed).
    if rendered as f32 != value {
        return Err(ParamsHashError::NonIntegral);
    }
    Ok(rendered)
}

/// §1 rule 4: the signature preimage — canonical JSON of the message with
/// the `signature` field OMITTED ENTIRELY (not null, not empty string).
/// Every other declared field — including a null-valued `divergence_point`
/// and an EOG `correction` — is PRESENT in the canonical form.
///
/// Uses `modelswarm_types::canonical_json` (the `Result`-returning
/// implementation with `FloatRejected`); the old vocabulary's
/// `modelswarm_identity::canonical_json` adapter is untouched (no
/// cross-cutting edits).
pub fn signing_preimage<T: Serialize + ?Sized>(msg: &T) -> Result<String, CanonicalError> {
    let mut value = serde_json::to_value(msg).map_err(|e| CanonicalError::Serde(e.to_string()))?;
    let Some(map) = value.as_object_mut() else {
        return Err(CanonicalError::Serde(
            "signed family messages must be JSON objects".to_string(),
        ));
    };
    map.remove("signature");
    canonical_json(&value)
}

/// Signs a [`VerifyDrafts`] with `signer`'s Ed25519 key (base64 STANDARD,
/// detached, over the [`signing_preimage`] canonical bytes). The caller
/// sets `sender` to the signer's installation id and assigns the returned
/// signature; verification enforces the sender binding.
pub fn sign_verify_drafts(
    msg: &VerifyDrafts,
    signer: &InstallationIdentity,
) -> Result<String, SpecError> {
    let preimage = signing_preimage(msg).map_err(|e| {
        SpecError::Protocol(format!(
            "verify_drafts payload rejected by canonical JSON: {e}"
        ))
    })?;
    let key = SigningKey::from_bytes(&signer.to_bytes());
    Ok(BASE64.encode(key.sign(preimage.as_bytes()).to_bytes()))
}

/// Signs the ADR-036 pin carrier (the same §1-rule-4 discipline: the
/// canonical JSON with `signature` omitted entirely). The coordinator
/// signs; `sender` must be set to the signer's installation id — the
/// serving side enforces the sender binding against the authenticated
/// PeerId at admission.
pub fn sign_pin_carrier(
    msg: &WirePinCarrier,
    signer: &InstallationIdentity,
) -> Result<String, SpecError> {
    let preimage = signing_preimage(msg).map_err(|e| {
        SpecError::Protocol(format!(
            "pin_carrier payload rejected by canonical JSON: {e}"
        ))
    })?;
    let key = SigningKey::from_bytes(&signer.to_bytes());
    Ok(BASE64.encode(key.sign(preimage.as_bytes()).to_bytes()))
}

/// Verifies the ADR-036 pin carrier (§1 rule 5 + the
/// `verify_commit_signature` discipline, same as the family messages):
/// sender binding FIRST (`installation_id_for(expected_key) == sender`),
/// then the Ed25519 signature over the signature-omitted canonical
/// form. The QUIC-authenticated remote-PeerId equality stays with the
/// serve loop (msp-v1 §6.6) — the only place that knows the stream's
/// peer id.
pub fn verify_pin_carrier_signature(
    msg: &WirePinCarrier,
    expected_key: &VerifyingKey,
) -> Result<(), SpecError> {
    verify_family_signature(
        msg,
        &msg.sender,
        &msg.signature,
        expected_key,
        "pin_carrier",
    )
}

/// Signs a [`VerifyDraftsResult`] (same discipline as
/// [`sign_verify_drafts`]; the verifier signs with its own key).
pub fn sign_verify_drafts_result(
    msg: &VerifyDraftsResult,
    signer: &InstallationIdentity,
) -> Result<String, SpecError> {
    let preimage = signing_preimage(msg).map_err(|e| {
        SpecError::Protocol(format!(
            "verify_drafts_result payload rejected by canonical JSON: {e}"
        ))
    })?;
    let key = SigningKey::from_bytes(&signer.to_bytes());
    Ok(BASE64.encode(key.sign(preimage.as_bytes()).to_bytes()))
}

/// §1 rule 5 + the `verify_commit_signature` discipline (base64 STANDARD,
/// 64-byte `Signature::from_slice`, sender binding FIRST):
/// `installation_id_for(expected_key) == sender` must hold BEFORE the
/// Ed25519 check over the signature-omitted canonical form. The
/// QUIC-authenticated remote-PeerId equality is enforced by the serve
/// loop (msp-v1 §6.6), which is the only place that knows the stream's
/// peer id.
fn verify_family_signature(
    msg: &impl Serialize,
    sender: &str,
    signature: &str,
    expected_key: &VerifyingKey,
    what: &str,
) -> Result<(), SpecError> {
    if installation_id_for(&expected_key.to_bytes()) != sender {
        return Err(SpecError::Protocol(format!(
            "{what} sender is not the authenticated session key"
        )));
    }
    let preimage = signing_preimage(msg).map_err(|e| {
        SpecError::Protocol(format!("{what} payload rejected by canonical JSON: {e}"))
    })?;
    let bytes = BASE64
        .decode(signature)
        .map_err(|_| SpecError::Protocol(format!("{what} signature is not valid base64")))?;
    let sig = Signature::from_slice(&bytes)
        .map_err(|_| SpecError::Protocol(format!("{what} signature is not 64 bytes")))?;
    expected_key
        .verify(preimage.as_bytes(), &sig)
        .map_err(|_| SpecError::Protocol("bad_signature".to_string()))
}

/// Verifies a [`VerifyDrafts`]: sender binding FIRST, then the Ed25519
/// signature over the [`signing_preimage`] canonical form. An invalid
/// signature is the `bad_frame` fail-closed path at admission
/// (unauthenticated = malformed).
pub fn verify_verify_drafts_signature(
    msg: &VerifyDrafts,
    expected_key: &VerifyingKey,
) -> Result<(), SpecError> {
    verify_family_signature(
        msg,
        &msg.sender,
        &msg.signature,
        expected_key,
        "verify_drafts",
    )
}

/// Verifies a [`VerifyDraftsResult`] under the session's pinned verifier
/// key (same discipline as [`verify_verify_drafts_signature`]; RC-3 (a)).
pub fn verify_verify_drafts_result_signature(
    msg: &VerifyDraftsResult,
    expected_key: &VerifyingKey,
) -> Result<(), SpecError> {
    verify_family_signature(
        msg,
        &msg.sender,
        &msg.signature,
        expected_key,
        "verify_drafts_result",
    )
}

// ---------------------------------------------------------------------------
// §3 — Verifier-side admission + round state machine (ADR-032 §8 / plan §3)
// ---------------------------------------------------------------------------

/// Engine access for the batched-verify family (plan §3.1): ONE batched
/// engine pass over `[prefix_last, window...]` with logits on every row,
/// the engine's own sampler chain under the pinned `params` (ADR-032 §1).
/// A trait so the whole family is testable with a mock verifier (ADR-032
/// §4 boundary); the production implementation (capi `verify_drafts`
/// wrapped in `spawn_blocking`) is ADR-031-gated engine work and is OUT
/// of this crate's scope.
///
/// Returns `(accepted_len, correction)`: the number of leading window
/// tokens the engine itself would have sampled (`accepted_len <=
/// len(window)`), and the replacement token on rejection / bonus token on
/// full acceptance (`None` exactly at end-of-generation — plan flag F-2).
#[async_trait::async_trait]
pub trait BatchVerifyEngine: Send + Sync {
    /// Executes the one batched pass for `window` under `params`.
    async fn verify_window(
        &self,
        window: &[u32],
        params: &SamplingParams,
    ) -> Result<(u32, Option<u32>), RuntimeError>;
    /// The engine's own capability disclosure (RC-8); its
    /// `batch_window_max` bounds admission (stage 10) BEFORE any engine
    /// work.
    fn capabilities(&self) -> EngineDisclosure;
}

/// The verifier round state machine (ADR-032 §8, normative diagram;
/// plan §3.2). `Validating` is the transient state occupied while the
/// admission stages run inside one synchronous
/// [`VerifyDraftsGate::admit_verify_drafts`] call — with a pure gate it is
/// never observable between calls; the one-outstanding rule (RC-5(a))
/// structurally covers it (any outstanding round rejects a new
/// `VerifyDrafts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateState {
    /// No round outstanding; accepts `VerifyDrafts` (RC-5(d)).
    Prefilled,
    /// Admission stages running (transient, inside one admit call).
    Validating,
    /// A `VerifyDrafts` was admitted; awaiting the ONE engine pass.
    Verify,
    /// The engine pass produced a result; awaiting the reproducing
    /// `PrefixCommit` (bounded by `deadline_ms + 250 ms`, RC-5(b)).
    WaitCommit,
    /// A reproducing commit was applied (chain advanced); settles back to
    /// `Prefilled` on the next admission/tick.
    Committed,
}

impl GateState {
    /// Stable label (test/diagnostic surface).
    pub fn as_str(self) -> &'static str {
        match self {
            GateState::Prefilled => "prefilled",
            GateState::Validating => "validating",
            GateState::Verify => "verify",
            GateState::WaitCommit => "wait_commit",
            GateState::Committed => "committed",
        }
    }
}

impl std::fmt::Display for GateState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The outstanding round: everything the gate must remember between
/// admission and commit/abandonment (plan §3.2).
#[derive(Debug, Clone)]
struct OutstandingRound {
    round: u64,
    nonce: String,
    /// The request's (already clamped) deadline, anchored at its arrival.
    deadline_expires_at_ms: u64,
    parent_prefix_hash: String,
    window_tokens: Vec<u32>,
    /// The verifier's own emitted result once the engine pass ran.
    result: Option<VerifyDraftsResult>,
}

/// Configuration for [`VerifyDraftsGate::new`] — the session binding the
/// gate enforces (plan §3.2): session id, profile id, this family's
/// `generation_params_hash`, the committed prefix-hash root, the pinned
/// COORDINATOR key (requests are authenticated against it, §1 rule 5),
/// the verifier's own installation id (the emitted result's `sender`),
/// the engine disclosure, the effective `SessionAccept` budget (§3.5),
/// and the ADR-026 lease expiry.
#[derive(Debug, Clone)]
pub struct VerifyDraftsGateConfig {
    /// The stream's admitted session id (binding, stage 4).
    pub session_id: String,
    /// The pinned model profile id (stage 7; I7).
    pub profile_id: String,
    /// This family's canonical generation-params hash (binding, stage 4).
    pub generation_params_hash: String,
    /// The committed prefix-hash root (genesis at session open).
    pub committed_prefix_hash: String,
    /// The coordinator's public key; every `VerifyDrafts` signature is
    /// verified under it (stage 3, sender binding FIRST).
    pub coordinator_key: VerifyingKey,
    /// The verifier's installation id — the emitted result's `sender`.
    pub verifier_installation_id: String,
    /// The verifier's engine disclosure (its `batch_window_max` is the
    /// stage-10 cap, RC-8).
    pub engine: EngineDisclosure,
    /// The effective `SessionAccept` budget (clamped DOWN only, §3.5).
    pub budget: SessionBudget,
    /// ADR-026 lease expiry (unix ms); stage 5.
    pub lease_expires_at_ms: u64,
    /// The pinned sampling parameters (engine calls + params-hash binding).
    pub sampling_params: SamplingParams,
    /// The verifier's own next per-session `seq` for an emitted
    /// `VerifyDraftsResult` (RC-7: the VERIFIER's counter, not the
    /// coordinator's; fixture replay seeds the recorded value).
    pub verifier_next_seq: u64,
}

/// Why a gate could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateConfigError {
    /// The committed prefix-hash root is not bare 64-lowercase-hex.
    InvalidCommittedHash(String),
    /// The engine disclosure is schema-invalid (`batch_window_max` out of
    /// `1..=WINDOW_CAP`).
    InvalidDisclosure,
    /// The budget envelope has a zero field (all fields are `>= 1`).
    InvalidBudget,
}

impl std::fmt::Display for GateConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateConfigError::InvalidCommittedHash(v) => {
                write!(
                    f,
                    "committed prefix hash must be 64 lowercase hex chars: {v:?}"
                )
            }
            GateConfigError::InvalidDisclosure => {
                write!(
                    f,
                    "engine disclosure is invalid (batch_window_max out of 1..=WINDOW_CAP)"
                )
            }
            GateConfigError::InvalidBudget => {
                write!(f, "session budget fields must all be >= 1")
            }
        }
    }
}

impl std::error::Error for GateConfigError {}

/// A frame/session-level rejection (ADR-032 §2): codes, counts, and
/// hashes ONLY — `window_tokens`, `correction`, and any token ids NEVER
/// appear here (privacy rule 5 / A-3; asserted by serialization in the
/// property suites).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectionFrame {
    /// The admitted session id.
    pub session_id: String,
    /// The effective-§6.5-registry reject code.
    pub code: FrameRejectReason,
    /// The round the frame claimed, when known (a COUNT, never a token id).
    pub round: Option<u64>,
    /// The current committed prefix hash (a hash; echo is permitted).
    pub prefix_hash: Option<String>,
}

/// A round-level abandon (ADR-032 §2 decision B2/A-5): a
/// cooperative-namespace `CancelRound { session_id, round, reason }`,
/// NOT a §6.5 code. Same privacy shape: no token ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelRoundFrame {
    /// The admitted session id.
    pub session_id: String,
    /// The abandoned round.
    pub round: u64,
    /// The frozen three-value reason vocabulary.
    pub reason: CancelRoundReason,
}

/// Outcome of admitting (or rejecting) one `VerifyDrafts` frame
/// (plan §3.3, stages 1–12; the engine is never touched here).
#[derive(Debug, Clone, PartialEq)]
pub enum AdmissionDecision {
    /// All stages passed; the round is outstanding and the ONE engine
    /// pass is authorized (state `Verify`). `deadline_expires_at_ms`
    /// carries the CLAMPED deadline anchored at the frame's arrival.
    Admitted {
        /// The admitted round number.
        round: u64,
        /// arrival + clamp(deadline_ms) — the WAIT_COMMIT bound is this
        /// plus [`WAIT_COMMIT_GRACE_MS`].
        deadline_expires_at_ms: u64,
    },
    /// Frame/session-level reject (codes, counts, hashes only).
    FrameRejected(RejectionFrame),
    /// Round-level abandon (`round_mismatch` / `parent_mismatch`; no
    /// state change).
    CancelRound(CancelRoundFrame),
}

/// Outcome of dispatching the outstanding round to the engine (stage 13 +
/// the one pass; plan §3.1/§3.3).
#[derive(Debug, Clone, PartialEq)]
pub enum DispatchOutcome {
    /// The ONE pass ran; this is the verifier's own (unsigned) result
    /// draft — the serve loop signs it with the verifier key and sends
    /// it. State is now `WaitCommit`.
    Dispatched(VerifyDraftsResult),
    /// Stage 13: the deadline re-check (after any queue wait, A-2)
    /// failed. The round is abandoned, the request discarded, state back
    /// to `Prefilled`.
    DeadlineExceeded,
    /// The engine pass failed (or violated its contract); the round is
    /// abandoned the same way. Not a wire code — the serve loop decides
    /// the honest stream outcome.
    EngineFailed(RuntimeError),
    /// Dispatch called with no admitted, undispatched round (misuse).
    NoOutstandingRound,
}

/// Outcome of applying a `PrefixCommit` under RC-4 + the gate's own chain
/// rules (plan §3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitApplyOutcome {
    /// RC-4 satisfied: the commit reproduced the outstanding result's
    /// accepted ids AND `new_prefix_hash`; the gate's own chain advanced
    /// (round gaps allowed, I3) and the token budget ledger grew.
    Advanced { round: u64 },
    /// A remembered replay of an already-applied commit (bounded per-round
    /// duplicate memory): a no-op.
    DuplicateRound,
    /// Round-level abandon (`parent_mismatch` / `round_mismatch` — no
    /// state change; `commit_mismatch` — round abandoned, RC-4).
    CancelRound(CancelRoundFrame),
    /// Session-level reject of the commit frame itself (wrong session /
    /// params → `bad_frame`; wrong profile → `profile_mismatch` +
    /// teardown; torn-down session → `cancelled_by_peer`).
    FrameRejected(RejectionFrame),
}

/// Test/fixture-replay seeding of a gate's recorded pre-state (the
/// `context` block of `protocol/vectors/verifydrafts-malformed.json` and
/// the property harness's injected conditions). Production code
/// constructs the gate [`VerifyDraftsGate::new`] and lets the session run.
#[derive(Debug, Clone, Default)]
pub struct GatePreStateSeed {
    /// Tear the session down before replay (stage 5 → `cancelled_by_peer`).
    pub torn_down: bool,
    /// Override the lease expiry (unix ms).
    pub lease_expires_at_ms: Option<u64>,
    /// Last seen `seq` per sender (stage 6 replay defense).
    pub last_seq: Vec<(String, u64)>,
    /// Already-consumed single-use nonces (session-scoped, I6).
    pub consumed_nonces: Vec<String>,
    /// Cumulative committed output tokens (the §3.5 ledger).
    pub committed_output_tokens: Option<u64>,
    /// Cumulative served session milliseconds (advanced by serve-loop
    /// deltas; §3.5).
    pub served_ms: Option<u64>,
    /// The last handled round (rounds may gap past it, RC-5(c)).
    pub last_handled_round: Option<u64>,
}

/// The verifier-side admission gate and round state machine for one
/// session (plan §3.2–§3.5; ADR-032 §2/§8). A PURE state machine: every
/// clock read is injected (`arrival_ms`/`now_ms`/`pass_end_ms`
/// parameters), and engine access is the [`BatchVerifyEngine`] trait.
///
/// CRITICAL reuse decision (plan §3.4): commits are applied through the
/// gate's OWN chain state — NOT [`crate::SessionStateMachine::apply`],
/// whose `round == current + 1` check forbids gaps
/// ([`crate::RejectReason::FutureRound`]); ADR-032 §8 RC-5(c) states the
/// shipped check MUST NOT be inherited by this family. The gate applies
/// the same checks itself: session/profile/params equality, `round >
/// last committed round` (strictly monotone, gaps allowed — I3),
/// parent-hash equality, [`compute_prefix_hash`] verification (reused
/// unchanged), plus bounded per-round duplicate memory
/// ([`DUPLICATE_MEMORY_ROUNDS`]) so replays are remembered no-ops.
#[derive(Debug, Clone)]
pub struct VerifyDraftsGate {
    // Session binding (plan §3.2).
    session_id: String,
    profile_id: String,
    generation_params_hash: String,
    coordinator_key: VerifyingKey,
    /// `installation_id_for(coordinator_key)` — the installation id pinned
    /// from the authenticated channel; the §2 `PrefixCommit` carrier's
    /// `sender` MUST equal it (ADR-032 revision 4 §2/G2; mismatch is
    /// `bad_frame`).
    coordinator_installation_id: String,
    /// `peer_id_for(coordinator_key)` — the PeerId the serve loop's
    /// `remote_peer_id` argument must equal on every request (ADR-032
    /// §1 rule 5's second half; security review RC-1, 2026-10-11).
    coordinator_peer_id: String,
    verifier_installation_id: String,
    engine: EngineDisclosure,
    // Chain state — committed hash and last HANDLED round diverge under
    // gaps (RC-5(c)): an abandoned round advances `last_handled_round`
    // but not the chain.
    committed_prefix_hash: String,
    last_committed_round: u64,
    last_handled_round: u64,
    /// Bounded duplicate memory: applied round -> its `new_prefix_hash`.
    applied_hashes: HashMap<u64, String>,
    applied_order: VecDeque<u64>,
    // Outstanding request (at most ONE, RC-5(a)).
    outstanding: Option<OutstandingRound>,
    // Replay defenses (I6, RC-7).
    consumed_nonces: HashSet<String>,
    last_seq: HashMap<String, u64>,
    // Per-peer protocol-violation counters (RC-3 tail: threshold two).
    violations: HashMap<String, u32>,
    // Budget ledger (§3.5, I8).
    budget: SessionBudget,
    committed_tokens: u64,
    served_ms: u64,
    // Session lifetime.
    lease_expires_at_ms: u64,
    torn_down: Option<String>,
    state: GateState,
    // The verifier's own emitted-message counter (RC-7).
    next_result_seq: u64,
    sampling_params: SamplingParams,
}

impl VerifyDraftsGate {
    /// Constructs the gate in `Prefilled` with no round outstanding,
    /// validating the committed-hash root, the engine disclosure, and the
    /// budget envelope.
    pub fn new(config: VerifyDraftsGateConfig) -> Result<Self, GateConfigError> {
        compute_prefix_hash(&config.committed_prefix_hash, &[]).map_err(|_| {
            GateConfigError::InvalidCommittedHash(config.committed_prefix_hash.clone())
        })?;
        if !config.engine.is_valid_disclosure() {
            return Err(GateConfigError::InvalidDisclosure);
        }
        if config.budget.max_endpoints == 0
            || config.budget.max_endpoint_seconds == 0
            || config.budget.max_output_tokens == 0
        {
            return Err(GateConfigError::InvalidBudget);
        }
        Ok(Self {
            session_id: config.session_id,
            profile_id: config.profile_id,
            generation_params_hash: config.generation_params_hash,
            coordinator_key: config.coordinator_key,
            coordinator_installation_id: installation_id_for(&config.coordinator_key.to_bytes()),
            coordinator_peer_id: peer_id_for(&config.coordinator_key.to_bytes()),
            verifier_installation_id: config.verifier_installation_id,
            engine: config.engine,
            committed_prefix_hash: config.committed_prefix_hash,
            last_committed_round: 0,
            last_handled_round: 0,
            applied_hashes: HashMap::new(),
            applied_order: VecDeque::new(),
            outstanding: None,
            consumed_nonces: HashSet::new(),
            last_seq: HashMap::new(),
            violations: HashMap::new(),
            budget: config.budget,
            committed_tokens: 0,
            served_ms: 0,
            lease_expires_at_ms: config.lease_expires_at_ms,
            torn_down: None,
            state: GateState::Prefilled,
            next_result_seq: config.verifier_next_seq,
            sampling_params: config.sampling_params,
        })
    }

    /// Seeds recorded pre-state (fixture replay / property harness). See
    /// [`GatePreStateSeed`].
    pub fn seed_pre_state(&mut self, seed: GatePreStateSeed) {
        if seed.torn_down {
            self.torn_down = Some("profile_mismatch".to_string());
        }
        if let Some(lease) = seed.lease_expires_at_ms {
            self.lease_expires_at_ms = lease;
        }
        for (sender, seq) in seed.last_seq {
            self.last_seq.insert(sender, seq);
        }
        for nonce in seed.consumed_nonces {
            self.consumed_nonces.insert(nonce);
        }
        if let Some(tokens) = seed.committed_output_tokens {
            self.committed_tokens = tokens;
        }
        if let Some(served) = seed.served_ms {
            self.served_ms = served;
        }
        if let Some(round) = seed.last_handled_round {
            self.last_handled_round = round;
        }
    }

    /// Advances the seconds ledger by a serve-loop-reported wall-clock
    /// delta (§3.5: the ledger advances on reported deltas, mock-fixed in
    /// tests).
    pub fn advance_session_seconds(&mut self, delta_ms: u64) {
        self.served_ms = self.served_ms.saturating_add(delta_ms);
    }

    // -- Inspectors ---------------------------------------------------------

    /// The current round state.
    pub fn state(&self) -> GateState {
        self.state
    }

    /// The current committed prefix hash (the parent every new round must
    /// chain onto).
    pub fn committed_prefix_hash(&self) -> &str {
        &self.committed_prefix_hash
    }

    /// The last COMMITTED round (0 = the root).
    pub fn last_committed_round(&self) -> u64 {
        self.last_committed_round
    }

    /// The last HANDLED round — diverges from [`Self::last_committed_round`]
    /// after an abandonment (RC-5(c)); new rounds must exceed it.
    pub fn last_handled_round(&self) -> u64 {
        self.last_handled_round
    }

    /// Cumulative committed output tokens (the §3.5 ledger).
    pub fn committed_output_tokens(&self) -> u64 {
        self.committed_tokens
    }

    /// Cumulative served session milliseconds (the §3.5 seconds ledger).
    pub fn served_session_ms(&self) -> u64 {
        self.served_ms
    }

    /// The outstanding round number, if any.
    pub fn outstanding_round(&self) -> Option<u64> {
        self.outstanding.as_ref().map(|out| out.round)
    }

    /// The outstanding round's clamped deadline expiry (arrival +
    /// clamp(deadline_ms)).
    pub fn outstanding_deadline_expires_at_ms(&self) -> Option<u64> {
        self.outstanding
            .as_ref()
            .map(|out| out.deadline_expires_at_ms)
    }

    /// The pending (emitted but uncommitted) result, if any.
    pub fn pending_result(&self) -> Option<&VerifyDraftsResult> {
        self.outstanding
            .as_ref()
            .and_then(|out| out.result.as_ref())
    }

    /// Whether the session is torn down (e.g. after `profile_mismatch`).
    pub fn is_torn_down(&self) -> bool {
        self.torn_down.is_some()
    }

    /// The teardown reason, when torn down.
    pub fn teardown_reason(&self) -> Option<&str> {
        self.torn_down.as_deref()
    }

    /// A peer's protocol-violation count.
    pub fn violations_of(&self, peer: &str) -> u32 {
        self.violations.get(peer).copied().unwrap_or(0)
    }

    /// Whether `nonce` is in the session-scoped consumed set.
    pub fn nonce_consumed(&self, nonce: &str) -> bool {
        self.consumed_nonces.contains(nonce)
    }

    // -- Admission (plan §3.3, stages 1–12; first-failure-wins) -----------

    /// Admits one `VerifyDrafts` frame. `now_ms` is the injected admission
    /// clock; `arrival_ms` is the frame's arrival anchor for the deadline
    /// math (equal to `now_ms` in the no-queue case; the ADR-032 §7
    /// `deadline-past` fixture models a queued frame whose deadline
    /// expired before admission).
    ///
    /// Stage order (ADR-032 §2 — first-failure-wins, asserted by the
    /// conjunction property sweep): (1) frame size, (2) schema,
    /// (3) signature, (4) session binding, (5) session alive (torn down,
    /// then lease), (6) seq/nonce — "dropped as `replayed_request` before
    /// any other check" applies to this stage, (7) profile,
    /// (8) round/parent, (9) one-outstanding, (10) window cap, (11) session
    /// budget, (12) deadline at admission. On success the round becomes
    /// the ONE outstanding request (state `Verify`), the nonce is
    /// consumed, the sender's `seq` advances, and `last_handled_round`
    /// moves to the admitted round.
    ///
    /// `remote_peer_id` is the QUIC-authenticated remote PeerId of the
    /// stream the frame arrived on (serve-loop supplied). Per ADR-032
    /// §1 rule 5 it must equal the PeerId derived from the pinned
    /// coordinator key; a mismatch fails closed as `bad_frame` (the
    /// authentication-family reject — unauthenticated = malformed)
    /// BEFORE any stage state is touched (security review RC-1,
    /// 2026-10-11; the coordinator-side mirror is `admit_result`).
    pub fn admit_verify_drafts(
        &mut self,
        frame: &Value,
        arrival_ms: u64,
        now_ms: u64,
        remote_peer_id: &str,
    ) -> AdmissionDecision {
        // Housekeeping first: settle COMMITTED, expire WAIT_COMMIT (RC-5(b)).
        self.settle(now_ms);
        if remote_peer_id != self.coordinator_peer_id {
            return self.reject(FrameRejectReason::BadFrame, None);
        }
        let prior_state = self.state;
        self.state = GateState::Validating;
        let decision = self.run_admission_stages(frame, arrival_ms, now_ms);
        if matches!(decision, AdmissionDecision::Admitted { .. }) {
            self.state = GateState::Verify;
        } else {
            // No rejection may change round/chain/replay state (I3/I6).
            self.state = prior_state;
        }
        decision
    }

    fn run_admission_stages(
        &mut self,
        frame: &Value,
        arrival_ms: u64,
        now_ms: u64,
    ) -> AdmissionDecision {
        // Stage 1 — frame size (msp-v1 §6.4, before any parsing).
        let frame_len = serde_json::to_string(frame).map_or(usize::MAX, |s| s.len());
        if frame_len > MAX_FRAME_BYTES {
            return self.reject(FrameRejectReason::PayloadTooLarge, None);
        }
        // Stage 2 — schema: strict two-pass parse, protocol version,
        // wire forms (bare hex, profile form).
        let Ok(msg) = VerifyDrafts::parse(frame) else {
            return self.reject(FrameRejectReason::BadFrame, None);
        };
        if msg.protocol_version != COOPERATIVE_PROTOCOL_VERSION
            || !is_bare_hash(&msg.parent_prefix_hash)
            || !is_bare_hash(&msg.generation_params_hash)
            || !is_profile_id_form(&msg.profile_id)
        {
            return self.reject(FrameRejectReason::BadFrame, Some(msg.round));
        }
        // Stage 3 — signature (sender binding FIRST, then Ed25519;
        // unauthenticated = malformed, fail-closed).
        if verify_verify_drafts_signature(&msg, &self.coordinator_key).is_err() {
            return self.reject(FrameRejectReason::BadFrame, Some(msg.round));
        }
        // Stage 4 — session binding: session id, and this family's
        // generation-params hash, must equal the admitted session's.
        if msg.session_id != self.session_id
            || msg.generation_params_hash != self.generation_params_hash
        {
            return self.reject(FrameRejectReason::BadFrame, Some(msg.round));
        }
        // Stage 5 — session alive: torn down (row order: before lease).
        if self.torn_down.is_some() {
            return self.reject(FrameRejectReason::CancelledByPeer, Some(msg.round));
        }
        if now_ms >= self.lease_expires_at_ms {
            return self.reject(FrameRejectReason::ExpiredToken, Some(msg.round));
        }
        // Stage 6 — seq/nonce: replayed_request before any other check
        // (RC-7). `seq` is per (session, sender).
        if let Some(&last) = self.last_seq.get(&msg.sender) {
            if msg.seq <= last {
                return self.reject(FrameRejectReason::ReplayedRequest, Some(msg.round));
            }
        }
        if self.consumed_nonces.contains(&msg.nonce) {
            return self.reject(FrameRejectReason::ReplayedRequest, Some(msg.round));
        }
        // Stage 7 — profile (I7): mismatch tears the session down.
        if msg.profile_id != self.profile_id {
            *self.violations.entry(msg.sender.clone()).or_insert(0) += 1;
            self.torn_down = Some("profile_mismatch".to_string());
            return self.reject(FrameRejectReason::ProfileMismatch, Some(msg.round));
        }
        // Stage 8 — round/parent (round-level CancelRound, no state change).
        if msg.round <= self.last_handled_round {
            return self.cancel_round(msg.round, CancelRoundReason::RoundMismatch);
        }
        if msg.parent_prefix_hash != self.committed_prefix_hash {
            return self.cancel_round(msg.round, CancelRoundReason::ParentMismatch);
        }
        // Stage 9 — one-outstanding (RC-5(a)): never queued. A repeated
        // nonce is replayed_request (normally already caught at stage 6);
        // a fresh nonce is bad_frame.
        if let Some(out) = self.outstanding.as_ref() {
            let code = if out.nonce == msg.nonce {
                FrameRejectReason::ReplayedRequest
            } else {
                FrameRejectReason::BadFrame
            };
            return self.reject(code, Some(msg.round));
        }
        // Stage 10 — window cap BEFORE any engine work (RC-8). An empty
        // window was already a stage-2 schema failure.
        let effective_cap = WINDOW_CAP.min(self.engine.batch_window_max);
        if msg.window_tokens.len() as u64 > u64::from(effective_cap) {
            return self.reject(FrameRejectReason::PayloadTooLarge, Some(msg.round));
        }
        // Stage 11 — session budget (I8/§8e, revision 4 / T/R advisory
        // A-2): WOULD-EXCEED on BOTH arms. The token arm refuses a round
        // whose admission would push cumulative committed output tokens
        // past `max_output_tokens`; the seconds arm reserves the round's
        // bounded worst-case residence — clamped `deadline_ms` plus the
        // WAIT_COMMIT grace (exactly the RC-5(b) expiry bound, which the
        // stage-13 re-check makes exact) — and refuses when the ledger
        // plus that reservation would exceed the cap. The one-outstanding
        // rule (RC-5(a)) makes the reservation double-count-free. The
        // seconds LEDGER itself keeps advancing on serve-loop wall-clock
        // deltas (cumulative session seconds, §8e).
        let clamped = msg
            .deadline_ms
            .clamp(DEADLINE_CLAMP_MIN_MS, DEADLINE_CLAMP_MAX_MS);
        let reservation_ms = u64::from(clamped) + WAIT_COMMIT_GRACE_MS;
        if self.committed_tokens + msg.window_tokens.len() as u64
            > u64::from(self.budget.max_output_tokens)
            || self.served_ms.saturating_add(reservation_ms)
                > self.budget.max_endpoint_seconds.saturating_mul(1000)
        {
            return self.reject(FrameRejectReason::Overloaded, Some(msg.round));
        }
        // Stage 12 — deadline at admission. `deadline_ms` is CLAMPED to
        // [1000, 120000] (clamp, not reject — §2, msp-v1 §6.4); the
        // deadline expired iff arrival + clamped deadline <= now.
        let deadline_expires_at_ms = arrival_ms.saturating_add(u64::from(clamped));
        if deadline_expires_at_ms <= now_ms {
            return self.reject(FrameRejectReason::DeadlineExceeded, Some(msg.round));
        }

        // Admitted: the round is handled from this point (RC-5(c) gap
        // semantics), the nonce is consumed, the seq advances.
        self.last_seq.insert(msg.sender.clone(), msg.seq);
        self.consumed_nonces.insert(msg.nonce.clone());
        self.last_handled_round = msg.round;
        self.outstanding = Some(OutstandingRound {
            round: msg.round,
            nonce: msg.nonce.clone(),
            deadline_expires_at_ms,
            parent_prefix_hash: msg.parent_prefix_hash.clone(),
            window_tokens: msg.window_tokens.clone(),
            result: None,
        });
        AdmissionDecision::Admitted {
            round: msg.round,
            deadline_expires_at_ms,
        }
    }

    /// Stage 13 + the ONE engine pass (plan §3.1/§3.3): the deadline is
    /// RE-CHECKED immediately before engine work, after any queue wait
    /// (A-2) — modelled by calling this with the post-queue `now_ms`.
    /// `pass_end_ms` is the injected clock at pass completion;
    /// `verify_pass_ms` is its delta from `now_ms` (the plan keeps the
    /// engine trait clock-free, so the pass duration is caller-supplied
    /// and mock-fixed in tests).
    ///
    /// On success the verifier's own (unsigned) result draft is returned
    /// with its `seq` taken from the VERIFIER's counter (RC-7); the serve
    /// loop signs and sends it. On deadline or engine failure the round is
    /// abandoned (request discarded, state back to `Prefilled`).
    pub async fn dispatch_outstanding<E: BatchVerifyEngine>(
        &mut self,
        engine: &E,
        now_ms: u64,
        pass_end_ms: u64,
    ) -> DispatchOutcome {
        let Some(out) = self.outstanding.as_ref() else {
            return DispatchOutcome::NoOutstandingRound;
        };
        if self.state != GateState::Verify {
            return DispatchOutcome::NoOutstandingRound;
        }
        // Stage 13 — deadline re-check before engine work.
        if out.deadline_expires_at_ms <= now_ms {
            self.abandon_outstanding();
            return DispatchOutcome::DeadlineExceeded;
        }
        let (accepted_len, correction) = match engine
            .verify_window(&out.window_tokens, &self.sampling_params)
            .await
        {
            Ok(pair) => pair,
            Err(e) => {
                self.abandon_outstanding();
                return DispatchOutcome::EngineFailed(e);
            }
        };
        let window_len = out.window_tokens.len();
        if accepted_len > window_len as u32 {
            // Engine contract violation — fail closed, abandon the round.
            self.abandon_outstanding();
            return DispatchOutcome::EngineFailed(RuntimeError::MalformedResponse(format!(
                "engine accepted {accepted_len} of {window_len} window tokens"
            )));
        }
        let mut committed = out.window_tokens[..accepted_len as usize].to_vec();
        if let Some(token) = correction {
            committed.push(token);
        }
        let new_prefix_hash = compute_prefix_hash(&out.parent_prefix_hash, &committed)
            .expect("parent hash is validated bare hex at admission");
        let result = VerifyDraftsResult {
            session_id: self.session_id.clone(),
            protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
            seq: self.next_result_seq,
            round: out.round,
            accepted_prefix_len: accepted_len,
            divergence_point: (accepted_len < out.window_tokens.len() as u32)
                .then_some(accepted_len),
            correction,
            new_prefix_hash,
            verify_pass_ms: u32::try_from(pass_end_ms.saturating_sub(now_ms)).unwrap_or(u32::MAX),
            nonce_echo: out.nonce.clone(),
            sender: self.verifier_installation_id.clone(),
            // The serve loop signs the draft with the verifier key.
            signature: String::new(),
        };
        self.next_result_seq += 1;
        let Some(out) = self.outstanding.as_mut() else {
            return DispatchOutcome::NoOutstandingRound;
        };
        out.result = Some(result.clone());
        self.state = GateState::WaitCommit;
        DispatchOutcome::Dispatched(result)
    }

    // -- WAIT_COMMIT admission (RC-4) + the gate's own chain (plan §3.4) --

    /// Applies a `PrefixCommit` in its §2 carrier form (the bare object
    /// with the shipped `CommitPrefix` field names, no envelope tag, no
    /// signature — ADR-032 revision 4 §2/G2; the serve loop parses the
    /// carrier STRICTLY, and the carrier's `sender` MUST equal the
    /// installation id pinned from the authenticated channel or the
    /// commit is `bad_frame` here before any state is touched). The
    /// commit is applied ONLY if it reproduces the outstanding result:
    /// `accepted_token_ids == window_tokens[..accepted_prefix_len]
    /// ++ [correction]` AND `new_prefix_hash == result.new_prefix_hash`
    /// (RC-4). A commit that chains validly from the parent but does not
    /// reproduce the result WHILE the round is outstanding is
    /// `CancelRound("commit_mismatch")` and the round is abandoned; a
    /// commit for a round already abandoned (handled but uncommitted, no
    /// outstanding result left — RC-5(b) expiry) is a STALE
    /// `round_mismatch` no-op with NO violation-counter increment
    /// (revision 4, Security advisory A1).
    ///
    /// Chain rules (the gate's OWN state, NOT
    /// [`crate::SessionStateMachine::apply`] — gaps are allowed, I3):
    /// session/profile/params equality, `round > last committed round`
    /// (strictly monotone; round NUMBERS may gap after abandonment),
    /// parent-hash equality, [`compute_prefix_hash`] verification, and
    /// bounded per-round duplicate memory so replays are remembered
    /// no-ops.
    pub fn apply_prefix_commit(&mut self, commit: &CommitPrefix) -> CommitApplyOutcome {
        // Session-level rejects first (the admission-table discipline).
        if self.torn_down.is_some() {
            return self.reject_commit(FrameRejectReason::CancelledByPeer, commit.round);
        }
        if commit.session_id != self.session_id
            || commit.generation_params_hash != self.generation_params_hash
        {
            return self.reject_commit(FrameRejectReason::BadFrame, commit.round);
        }
        // §2 carrier sender check (ADR-032 revision 4 §2/G2): the carrier
        // carries NO signature — its authentication is the cryptographically
        // authenticated session channel — so its `sender` MUST equal the
        // installation id pinned from that channel (the same pinned
        // coordinator key that authenticates every `VerifyDrafts`). A
        // mismatch is `bad_frame` before any state is touched.
        if commit.sender != self.coordinator_installation_id {
            return self.reject_commit(FrameRejectReason::BadFrame, commit.round);
        }
        if commit.model_profile_id != self.profile_id {
            *self.violations.entry(commit.sender.clone()).or_insert(0) += 1;
            self.torn_down = Some("profile_mismatch".to_string());
            return self.reject_commit(FrameRejectReason::ProfileMismatch, commit.round);
        }
        // Duplicates of applied rounds are remembered no-ops; any other
        // round at or below the committed round is a round_mismatch.
        if commit.round <= self.last_committed_round {
            if self
                .applied_hashes
                .get(&commit.round)
                .is_some_and(|remembered| *remembered == commit.new_prefix_hash)
            {
                return CommitApplyOutcome::DuplicateRound;
            }
            return self.cancel_round_commit(commit.round, CancelRoundReason::RoundMismatch);
        }
        // RC-5(b) post-expiry stale commits (ADR-032 revision 4 §8,
        // Security advisory A1): a commit for a round already abandoned —
        // handled but uncommitted, with no outstanding result left to
        // reproduce against (the RC-5(b) discard cleared it) — is a STALE
        // ROUND, not a violation: whether it would have reproduced is
        // unknowable after the discard, and an unknowable fact is never
        // charged as a protocol violation (two late commits from an
        // honest-but-slow coordinator must not tear the session down).
        // Rejected `CancelRound("round_mismatch")` with NO state change
        // and NO violation-counter increment; the commit is never applied
        // (an unverifiable commit never advances the chain; I2). The
        // exemption is scoped exactly: a commit failing RC-4 reproduction
        // WHILE the round's result is outstanding remains a
        // `commit_mismatch` violation toward threshold-two teardown, as
        // before (the outstanding check below).
        if self.outstanding.is_none()
            && commit.round <= self.last_handled_round
            && commit.round > self.last_committed_round
        {
            return self.cancel_round_commit(commit.round, CancelRoundReason::RoundMismatch);
        }
        // The chain must continue from the committed hash (I3).
        if commit.previous_prefix_hash != self.committed_prefix_hash {
            return self.cancel_round_commit(commit.round, CancelRoundReason::ParentMismatch);
        }
        // RC-4: the commit must reproduce the outstanding result for THIS
        // round — token ids and hash, both.
        let reproduces = self.outstanding.as_ref().is_some_and(|out| {
            out.round == commit.round
                && out.result.as_ref().is_some_and(|result| {
                    let mut expected =
                        out.window_tokens[..result.accepted_prefix_len as usize].to_vec();
                    if let Some(token) = result.correction {
                        expected.push(token);
                    }
                    commit.accepted_token_ids == expected
                        && commit.new_prefix_hash == result.new_prefix_hash
                })
        });
        let hash_valid =
            compute_prefix_hash(&self.committed_prefix_hash, &commit.accepted_token_ids)
                .is_ok_and(|recomputed| recomputed == commit.new_prefix_hash);
        if !reproduces || !hash_valid {
            // Round abandoned (RC-4); a repeated offender tears the session
            // down (threshold two, §2 RC-3 tail).
            *self.violations.entry(commit.sender.clone()).or_insert(0) += 1;
            if self.violations.get(&commit.sender).copied().unwrap_or(0)
                >= TEARDOWN_VIOLATION_THRESHOLD
            {
                self.torn_down = Some("commit_mismatch".to_string());
            }
            self.abandon_outstanding();
            return self.cancel_round_commit(commit.round, CancelRoundReason::CommitMismatch);
        }
        // Advance the gate's own chain + the budget ledger.
        self.last_committed_round = commit.round;
        self.committed_prefix_hash = commit.new_prefix_hash.clone();
        self.committed_tokens += commit.accepted_token_ids.len() as u64;
        self.remember(commit.round, commit.new_prefix_hash.clone());
        self.outstanding = None;
        self.state = GateState::Committed;
        CommitApplyOutcome::Advanced {
            round: commit.round,
        }
    }

    // -- Expiry (RC-5(b)) ---------------------------------------------------

    /// Expires an outstanding round whose `deadline_ms + 250 ms` grace
    /// has passed: abandons the round, discards the pending result,
    /// returns to `Prefilled`. The verifier never holds an uncommitted
    /// round for a vanished coordinator.
    ///
    /// RC-5(b) pins this for WAIT_COMMIT; an admitted-but-undispatched
    /// round (state `Verify`) past the same bound is equally abandoned —
    /// its dispatch is already impossible (the stage-13 re-check would
    /// refuse), so holding it would only block new rounds at stage 9.
    /// Returns whether an abandonment happened.
    pub fn expire_wait_commit_if_due(&mut self, now_ms: u64) -> bool {
        if !matches!(self.state, GateState::Verify | GateState::WaitCommit) {
            return false;
        }
        let expired = self
            .outstanding
            .as_ref()
            .is_some_and(|out| now_ms >= out.deadline_expires_at_ms + WAIT_COMMIT_GRACE_MS);
        if expired {
            self.abandon_outstanding();
        }
        expired
    }

    /// Housekeeping: settle COMMITTED → PREFILLED and expire a stale
    /// WAIT_COMMIT round.
    fn settle(&mut self, now_ms: u64) {
        if self.state == GateState::Committed {
            self.state = GateState::Prefilled;
        }
        self.expire_wait_commit_if_due(now_ms);
    }

    fn abandon_outstanding(&mut self) {
        self.outstanding = None;
        self.state = GateState::Prefilled;
    }

    fn remember(&mut self, round: u64, new_prefix_hash: String) {
        if self.applied_hashes.insert(round, new_prefix_hash).is_none() {
            self.applied_order.push_back(round);
        }
        while self.applied_hashes.len() > DUPLICATE_MEMORY_ROUNDS {
            match self.applied_order.pop_front() {
                Some(evicted) => {
                    self.applied_hashes.remove(&evicted);
                }
                None => break,
            }
        }
    }

    fn reject(&self, code: FrameRejectReason, round: Option<u64>) -> AdmissionDecision {
        AdmissionDecision::FrameRejected(RejectionFrame {
            session_id: self.session_id.clone(),
            code,
            round,
            prefix_hash: Some(self.committed_prefix_hash.clone()),
        })
    }

    fn reject_commit(&self, code: FrameRejectReason, round: u64) -> CommitApplyOutcome {
        CommitApplyOutcome::FrameRejected(RejectionFrame {
            session_id: self.session_id.clone(),
            code,
            round: Some(round),
            prefix_hash: Some(self.committed_prefix_hash.clone()),
        })
    }

    fn cancel_round(&self, round: u64, reason: CancelRoundReason) -> AdmissionDecision {
        AdmissionDecision::CancelRound(self.cancel_round_frame(round, reason))
    }

    fn cancel_round_commit(&self, round: u64, reason: CancelRoundReason) -> CommitApplyOutcome {
        CommitApplyOutcome::CancelRound(self.cancel_round_frame(round, reason))
    }

    fn cancel_round_frame(&self, round: u64, reason: CancelRoundReason) -> CancelRoundFrame {
        CancelRoundFrame {
            session_id: self.session_id.clone(),
            round,
            reason,
        }
    }
}

/// `profile_id` wire form: `"msp1:"` + bare 64-hex (stage 2 schema).
fn is_profile_id_form(s: &str) -> bool {
    let Some(hex_part) = s.strip_prefix("msp1:") else {
        return false;
    };
    is_bare_hash(hex_part)
}

// ---------------------------------------------------------------------------
// §4 — Coordinator side: result admission (RC-3), timing trust (RC-2),
// telemetry + audit surfaces (RC-1)
// ---------------------------------------------------------------------------

/// Teardown reason the coordinator records when the same peer commits a
/// SECOND result-admission protocol violation in one session (RC-3 tail:
/// threshold exactly [`TEARDOWN_VIOLATION_THRESHOLD`]). An honest label —
/// it names what happened, nothing more.
pub const TEARDOWN_REASON_RESULT_VIOLATION: &str = "verify_result_violation";

/// Receipt-honesty label (ADR-032 §3 RC-1 / §6 non-goals): every counter
/// granted from this family — `verified_tokens` inside counter-signed
/// ReceiptV2s — is a **verifier-claimed** number. The ADR-030 grant rules
/// govern WHO may increment counters; they do not independently measure
/// the claimed values. This label MUST be attached at the receipt intake
/// (the msp-v1 §5 `verified_capacity` honest-label sense) and it adds NO
/// wire field: the family's messages are frozen and this is a
/// documentation-at-intake obligation only.
pub const RECEIPT_COUNTER_HONESTY_LABEL: &str = "verifier-claimed";

/// The outstanding `VerifyDrafts` request the coordinator has sent and is
/// awaiting one `VerifyDraftsResult` for (the mirror of the verifier
/// gate's [`OutstandingRound`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutstandingVerifyRequest {
    /// The request's round (RC-3 (c)).
    pub round: u64,
    /// The COORDINATOR's own request `seq` (RC-7: the result replies with
    /// the VERIFIER's counter, not this one).
    pub seq: u64,
    /// The request's single-use nonce; the first valid result consumes it.
    pub nonce: String,
    /// The request's profile id (RC-3 (c)).
    pub profile_id: String,
    /// The parent the window chains onto (RC-3 (c)/(e)).
    pub parent_prefix_hash: String,
    /// The draft window (RC-3 (d): `accepted_prefix_len <= len`).
    pub window_tokens: Vec<u32>,
}

/// Configuration for [`VerifyDraftsCoordinator::new`] — the session
/// binding the coordinator enforces plus the session's PINNED verifier
/// key (RC-3 (a): results verify under exactly this key).
#[derive(Debug, Clone)]
pub struct VerifyDraftsCoordinatorConfig {
    /// The admitted session id.
    pub session_id: String,
    /// The pinned model profile id.
    pub profile_id: String,
    /// This family's canonical generation-params hash.
    pub generation_params_hash: String,
    /// The verifier's public key pinned at session open; every
    /// `VerifyDraftsResult` signature is verified under it (RC-3 (a)).
    pub verifier_key: VerifyingKey,
}

/// Why a coordinator could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatorConfigError {
    /// The pinned profile id is not `"msp1:" + 64 hex`.
    InvalidProfileId,
    /// The generation-params hash is not bare 64-lowercase-hex.
    InvalidParamsHash,
}

impl std::fmt::Display for CoordinatorConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoordinatorConfigError::InvalidProfileId => {
                write!(f, "profile id must be msp1:<64 hex>")
            }
            CoordinatorConfigError::InvalidParamsHash => {
                write!(f, "generation-params hash must be 64 lowercase hex chars")
            }
        }
    }
}

impl std::error::Error for CoordinatorConfigError {}

/// Why a [`VerifyDraftsCoordinator::track_request`] call was refused
/// (requester-side misuse — the coordinator builds its own requests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackRequestError {
    /// The session is torn down; no new rounds may be sent.
    SessionTornDown,
    /// The request does not bind to the coordinator's session config
    /// (carries the field name).
    Binding(&'static str),
}

impl std::fmt::Display for TrackRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrackRequestError::SessionTornDown => {
                write!(f, "session is torn down; no new rounds may be sent")
            }
            TrackRequestError::Binding(field) => {
                write!(
                    f,
                    "request field {field:?} does not bind to the session config"
                )
            }
        }
    }
}

impl std::error::Error for TrackRequestError {}

/// A result was DROPPED with no state change at all (not even the
/// violation counters) — RC-3 tail: "any later result carrying a consumed
/// nonce, and any result with no outstanding request, is dropped with no
/// state change (a replayed genuine signed result is thereby
/// undetectable-to-harmless)".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultDrop {
    /// No `VerifyDrafts` is outstanding (never sent, already answered, or
    /// abandoned).
    NoOutstandingRequest,
    /// The echoed nonce was already consumed by a prior valid result — a
    /// replayed genuine result; harmless by construction.
    ConsumedNonce,
    /// The session is torn down; nothing is admitted anymore.
    SessionTornDown,
}

impl std::fmt::Display for ResultDrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResultDrop::NoOutstandingRequest => write!(f, "no outstanding request"),
            ResultDrop::ConsumedNonce => write!(f, "consumed nonce (replayed result)"),
            ResultDrop::SessionTornDown => write!(f, "session torn down"),
        }
    }
}

/// Which RC-3 admission check (a)–(e) failed. Every variant is a protocol
/// violation by the result's peer and counts toward the
/// [`TEARDOWN_VIOLATION_THRESHOLD`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultViolation {
    /// The frame does not strictly parse (schema stage).
    Schema,
    /// RC-3 (a): the signature does not verify under the pinned verifier
    /// key, or `sender` does not derive from it.
    Signature,
    /// RC-3 (a): the QUIC-authenticated remote PeerId of the connection
    /// (msp-v1 §6.6) — supplied by the serve loop, the only place that
    /// knows the stream's peer id — does not equal the PeerId derived
    /// from the session's pinned verifier key.
    RemotePeer,
    /// RC-3 (b): `nonce_echo` does not equal the outstanding request's
    /// nonce (and is not a consumed one — that is a drop, not a
    /// violation).
    NonceEcho,
    /// RC-3 (c): an echoed binding field differs from the outstanding
    /// request's (carries the field name; `seq` is the RC-7 per-verifier
    /// strict-monotone mirror — see
    /// [`VerifyDraftsCoordinator::admit_result`]). The `profile_id` and
    /// `parent_prefix_hash` equalities of RC-3 (c) are enforced
    /// transitively (the result wire carries neither field): the parent
    /// through the (e) recomputation, the profile through the pinned
    /// verifier key of (a).
    Binding(&'static str),
    /// RC-3 (d): `accepted_prefix_len > len(window_tokens)`.
    AcceptedPrefixBounds,
    /// RC-3 (d): the divergence shape is inconsistent (`divergence_point`
    /// differs from `Some(accepted_prefix_len)` on a partial acceptance,
    /// or is non-null on a full acceptance).
    DivergenceInconsistent,
    /// RC-3 (e): `new_prefix_hash` does not equal the locally recomputed
    /// [`crate::compute_prefix_hash`] over
    /// `(parent ‖ accepted prefix ‖ [correction])`.
    NewPrefixHash,
}

impl std::fmt::Display for ResultViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResultViolation::Schema => write!(f, "result frame failed the strict schema parse"),
            ResultViolation::Signature => write!(f, "RC-3(a) signature/sender-derivation failed"),
            ResultViolation::RemotePeer => {
                write!(f, "RC-3(a) sender does not equal the remote peer id")
            }
            ResultViolation::NonceEcho => write!(f, "RC-3(b) nonce_echo mismatch"),
            ResultViolation::Binding(field) => {
                write!(f, "RC-3(c) binding mismatch on {field:?}")
            }
            ResultViolation::AcceptedPrefixBounds => {
                write!(f, "RC-3(d) accepted_prefix_len exceeds the window")
            }
            ResultViolation::DivergenceInconsistent => {
                write!(
                    f,
                    "RC-3(d) divergence shape inconsistent with accepted_prefix_len"
                )
            }
            ResultViolation::NewPrefixHash => {
                write!(f, "RC-3(e) new_prefix_hash does not recompute")
            }
        }
    }
}

/// Outcome of [`VerifyDraftsCoordinator::admit_result`] (plan §4.1,
/// ADR-032 §2 RC-3 (a)–(e) exactly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultAdmission {
    /// ALL of (a)–(e) held: the result is admitted, the request's nonce
    /// is consumed, the outstanding round is answered, and the committed
    /// ids — `window_tokens[..accepted_prefix_len] ++ [correction]` (the
    /// correction is absent exactly at EOG, plan flag F-2) — are the
    /// tokens the gateway may surface. The counters this result grants
    /// are VERIFIER-CLAIMED numbers ([`RECEIPT_COUNTER_HONESTY_LABEL`]).
    Accepted { committed: Vec<u32> },
    /// A protocol violation (the carried check failed). The violation
    /// counter for the remote peer grew; every OTHER piece of state is
    /// unchanged. The FIRST violation does not tear the session down.
    Violation(ResultViolation),
    /// The SECOND protocol violation by the same peer within this
    /// session: the session is torn down with the honest reason
    /// [`TEARDOWN_REASON_RESULT_VIOLATION`] (threshold exactly
    /// [`TEARDOWN_VIOLATION_THRESHOLD`]).
    TornDown(ResultViolation),
    /// Dropped with no state change at all (see [`ResultDrop`]).
    Dropped(ResultDrop),
}

/// Receipt-outcome marker for the ADR-032 §3 RC-1 audit path (coordinator
/// side): the receipt of a session whose audit found a divergence is
/// MARKED — verifier-claimed counters from a diverging peer are never
/// presented as clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReceiptOutcome {
    /// No audit divergence recorded (the default).
    #[default]
    Clean,
    /// The audit path re-executed a committed window and diverged from
    /// the verifier-claimed committed stream.
    AuditDivergence,
}

/// Action the audit path mandates after one audited window (plan §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    /// The audited window matched the verifier-claimed committed stream;
    /// the session continues as-is.
    Continue,
    /// Divergence: `verifier_divergence` telemetry was emitted, the
    /// session switched to the `SingleDecode` fallback for the REMAINDER
    /// (the existing, exact-by-construction primitive), and the receipt
    /// outcome was marked ([`ReceiptOutcome::AuditDivergence`]).
    SwitchedToSingleDecode,
}

/// The coordinator side of one batched-verify session (plan §4.1;
/// ADR-032 §2 RC-3): tracks the ONE outstanding `VerifyDrafts` it sent,
/// admits at most one valid `VerifyDraftsResult` per request (the first
/// valid result consumes the nonce), drops replays and unsolicited
/// results with no state change, and tears the session down on the second
/// protocol violation by the same peer.
///
/// The QUIC-authenticated remote PeerId equality of RC-3 (a) is enforced
/// through the `remote_peer_id` parameter of [`Self::admit_result`] —
/// the serve loop supplies it, because the session crate cannot see the
/// stream's peer id itself (msp-v1 §6.6).
///
/// `seq` under RC-3 (c): the ADR's §2 binding list names `seq` equality
/// with the outstanding request, but §1/RC-7 pin the result's `seq` as
/// the VERIFIER's own per-(session, sender) counter — the ADR's own
/// worked example is request `seq: 12`, result `seq: 4`, valid. The
/// coherent rule implemented here is the RC-7 mirror of the verifier's
/// stage-6 check: the result's `seq` must be strictly greater than the
/// last `seq` this coordinator saw from the verifier (the first result
/// establishes the baseline — its counter start is not disclosed on the
/// wire); `seq <= last` is a violation. Recorded in the session-4
/// handoff as an ADR-internal reconciliation.
#[derive(Debug, Clone)]
pub struct VerifyDraftsCoordinator {
    session_id: String,
    profile_id: String,
    generation_params_hash: String,
    /// The pinned verifier key (RC-3 (a)).
    verifier_key: VerifyingKey,
    /// `installation_id_for(verifier_key)` — the verifier's wire sender
    /// identity for telemetry/receipt labeling.
    verifier_peer: String,
    /// `peer_id_for(verifier_key)` — the PeerId the serve loop's
    /// QUIC-authenticated remote PeerId must equal (RC-3 (a), msp-v1
    /// §6.6; ADR-020: the PeerId is the identity-multihash derivation,
    /// a different string from the installation id — both derive from
    /// the SAME pinned key, which is the point of the rule).
    verifier_peer_id: String,
    /// The one outstanding request (RC-3 runs against it).
    outstanding: Option<OutstandingVerifyRequest>,
    /// Session-scoped consumed nonces: every request's nonce moves here
    /// when answered (first valid result), replaced, or abandoned — a
    /// late or replayed genuine result for it is thereby a harmless drop.
    consumed_nonces: HashSet<String>,
    /// Last `seq` seen from the VERIFIER sender (the RC-7 mirror above).
    verifier_last_seq: Option<u64>,
    /// Per-peer protocol-violation counters (RC-3 tail).
    violations: HashMap<String, u32>,
    torn_down: Option<String>,
    /// The committed prefix hash the NEXT request chains onto.
    committed_prefix_hash: String,
    last_accepted_round: Option<u64>,
    /// RC-1 audit-path state.
    fallback_single_decode: bool,
    receipt: ReceiptOutcome,
}

impl VerifyDraftsCoordinator {
    /// Constructs the coordinator in the fresh state (genesis chain root).
    pub fn new(config: VerifyDraftsCoordinatorConfig) -> Result<Self, CoordinatorConfigError> {
        if !is_profile_id_form(&config.profile_id) {
            return Err(CoordinatorConfigError::InvalidProfileId);
        }
        if !is_bare_hash(&config.generation_params_hash) {
            return Err(CoordinatorConfigError::InvalidParamsHash);
        }
        Ok(Self {
            verifier_peer: installation_id_for(&config.verifier_key.to_bytes()),
            verifier_peer_id: peer_id_for(&config.verifier_key.to_bytes()),
            session_id: config.session_id,
            profile_id: config.profile_id,
            generation_params_hash: config.generation_params_hash,
            verifier_key: config.verifier_key,
            outstanding: None,
            consumed_nonces: HashSet::new(),
            verifier_last_seq: None,
            violations: HashMap::new(),
            torn_down: None,
            committed_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
            last_accepted_round: None,
            fallback_single_decode: false,
            receipt: ReceiptOutcome::Clean,
        })
    }

    /// Records the `VerifyDrafts` the coordinator is sending as the ONE
    /// outstanding request. Any previously outstanding request's nonce is
    /// consumed (a late genuine result for the replaced round is thereby
    /// a harmless drop, not a violation).
    pub fn track_request(&mut self, request: &VerifyDrafts) -> Result<(), TrackRequestError> {
        if self.torn_down.is_some() {
            return Err(TrackRequestError::SessionTornDown);
        }
        if request.session_id != self.session_id {
            return Err(TrackRequestError::Binding("session_id"));
        }
        if request.profile_id != self.profile_id {
            return Err(TrackRequestError::Binding("profile_id"));
        }
        if request.generation_params_hash != self.generation_params_hash {
            return Err(TrackRequestError::Binding("generation_params_hash"));
        }
        if let Some(previous) = self.outstanding.take() {
            self.consumed_nonces.insert(previous.nonce);
        }
        self.outstanding = Some(OutstandingVerifyRequest {
            round: request.round,
            seq: request.seq,
            nonce: request.nonce.clone(),
            profile_id: request.profile_id.clone(),
            parent_prefix_hash: request.parent_prefix_hash.clone(),
            window_tokens: request.window_tokens.clone(),
        });
        Ok(())
    }

    /// Abandons the outstanding request (round deadline passed, peer
    /// gone): its nonce is consumed so a late genuine result is a
    /// harmless drop. Returns whether a request was abandoned.
    pub fn abandon_outstanding_request(&mut self) -> bool {
        match self.outstanding.take() {
            Some(previous) => {
                self.consumed_nonces.insert(previous.nonce);
                true
            }
            None => false,
        }
    }

    /// Admits one `VerifyDraftsResult` frame under RC-3 (a)–(e) EXACTLY
    /// (plan §4.1). `remote_peer_id` is the QUIC-authenticated remote
    /// PeerId of the connection, supplied by the serve loop (msp-v1
    /// §6.6) — the session crate cannot see it itself.
    ///
    /// Check order: torn-down drop → strict schema parse → (a) signature
    /// under the pinned verifier key + sender derivation + remote-peer
    /// equality → no-outstanding drop → consumed-nonce drop → (b) nonce
    /// echo → (c) session/protocol/round/seq binding (profile/parent
    /// transitively, see [`ResultViolation::Binding`]) → (d)
    /// accepted-length bounds + divergence consistency → (e)
    /// `new_prefix_hash` recomputation. The first valid result consumes
    /// the nonce; replays and unsolicited results drop with no state
    /// change; every check failure is a protocol violation, and the
    /// SECOND by the same peer tears the session down.
    pub fn admit_result(&mut self, frame: &Value, remote_peer_id: &str) -> ResultAdmission {
        if self.torn_down.is_some() {
            return ResultAdmission::Dropped(ResultDrop::SessionTornDown);
        }
        // Schema (strict two-pass parse).
        let Ok(msg) = VerifyDraftsResult::parse(frame) else {
            return self.violation(remote_peer_id, ResultViolation::Schema);
        };
        // (a) — sender derivation + Ed25519 under the pinned key …
        if verify_verify_drafts_result_signature(&msg, &self.verifier_key).is_err() {
            return self.violation(remote_peer_id, ResultViolation::Signature);
        }
        // … and the QUIC-authenticated remote PeerId equality (serve-loop
        // supplied): the stream's PeerId must equal the PeerId derived
        // from the SAME pinned key (msp-v1 §6.6).
        if remote_peer_id != self.verifier_peer_id {
            return self.violation(remote_peer_id, ResultViolation::RemotePeer);
        }
        // Drops (no state change, not violations).
        if self.consumed_nonces.contains(&msg.nonce_echo) {
            return ResultAdmission::Dropped(ResultDrop::ConsumedNonce);
        }
        let Some(out) = self.outstanding.clone() else {
            return ResultAdmission::Dropped(ResultDrop::NoOutstandingRequest);
        };
        // (b)
        if msg.nonce_echo != out.nonce {
            return self.violation(remote_peer_id, ResultViolation::NonceEcho);
        }
        // (c)
        if msg.session_id != self.session_id {
            return self.violation(remote_peer_id, ResultViolation::Binding("session_id"));
        }
        if msg.protocol_version != COOPERATIVE_PROTOCOL_VERSION {
            return self.violation(remote_peer_id, ResultViolation::Binding("protocol_version"));
        }
        if msg.round != out.round {
            return self.violation(remote_peer_id, ResultViolation::Binding("round"));
        }
        if self.verifier_last_seq.is_some_and(|last| msg.seq <= last) {
            return self.violation(remote_peer_id, ResultViolation::Binding("seq"));
        }
        // (c) profile/parent note: the RESULT wire carries neither
        // `profile_id` nor `parent_prefix_hash` (ADR-032 §1 result shape),
        // so their RC-3(c) equality with the outstanding request is
        // enforced TRANSITIVELY: the parent through (e)'s recomputation
        // under the outstanding request's parent (a hash computed under
        // any other parent cannot match), and the profile through the
        // session-pinned verifier key of (a) plus the fact that
        // [`Self::track_request`] only tracks requests bound to this
        // session/profile config.
        // (d)
        if msg.accepted_prefix_len as usize > out.window_tokens.len() {
            return self.violation(remote_peer_id, ResultViolation::AcceptedPrefixBounds);
        }
        let full_acceptance = msg.accepted_prefix_len as usize == out.window_tokens.len();
        let expected_divergence = (!full_acceptance).then_some(msg.accepted_prefix_len);
        if msg.divergence_point != expected_divergence {
            return self.violation(remote_peer_id, ResultViolation::DivergenceInconsistent);
        }
        // (e) — the §1 rule 2 preimage over (parent ‖ accepted ‖ [correction]).
        let mut committed = out.window_tokens[..msg.accepted_prefix_len as usize].to_vec();
        if let Some(token) = msg.correction {
            committed.push(token);
        }
        let recomputed =
            compute_prefix_hash(&out.parent_prefix_hash, &committed).unwrap_or_default();
        if recomputed != msg.new_prefix_hash {
            return self.violation(remote_peer_id, ResultViolation::NewPrefixHash);
        }

        // Admitted: the FIRST valid result consumes the nonce (RC-3).
        self.consumed_nonces.insert(out.nonce.clone());
        self.outstanding = None;
        self.verifier_last_seq = Some(msg.seq);
        self.committed_prefix_hash = msg.new_prefix_hash.clone();
        self.last_accepted_round = Some(out.round);
        ResultAdmission::Accepted { committed }
    }

    /// Runs the RC-1 audit path over ONE committed window (plan §4.3):
    /// the auditor re-executes the window with the coordinator's own
    /// engine (cache-cold — REQUIRED of implementations, see
    /// [`WindowAuditor`]) and compares token-for-token. On
    /// [`AuditVerdict::Divergence`] this emits `verifier_divergence`
    /// through `telemetry`, switches the session to the `SingleDecode`
    /// fallback for the remainder, and marks the receipt outcome. An
    /// audit already in fallback is a no-op (the session is single-mode
    /// from here on).
    ///
    /// An auditor error propagates: a FAILED audit is not evidence of
    /// divergence and marks nothing (the ADR pins no behavior for it;
    /// the serve loop decides the honest stream outcome).
    pub async fn audit_committed_window<A: WindowAuditor, T: VerifyTelemetry>(
        &mut self,
        auditor: &A,
        telemetry: &T,
        prompt_tokens: &[u32],
        committed_before: &[u32],
        window_commit: &[u32],
    ) -> Result<AuditAction, RuntimeError> {
        if self.fallback_single_decode {
            return Ok(AuditAction::SwitchedToSingleDecode);
        }
        match auditor
            .audit_window(prompt_tokens, committed_before, window_commit)
            .await?
        {
            AuditVerdict::Match => Ok(AuditAction::Continue),
            AuditVerdict::Divergence { .. } => {
                telemetry.verifier_divergence(&self.session_id, &self.verifier_peer);
                self.fallback_single_decode = true;
                self.receipt = ReceiptOutcome::AuditDivergence;
                Ok(AuditAction::SwitchedToSingleDecode)
            }
        }
    }

    /// Counts one protocol violation for `peer`; reaching
    /// [`TEARDOWN_VIOLATION_THRESHOLD`] tears the session down with the
    /// honest reason [`TEARDOWN_REASON_RESULT_VIOLATION`] (RC-3 tail).
    fn violation(&mut self, peer: &str, why: ResultViolation) -> ResultAdmission {
        let count = self.violations.entry(peer.to_string()).or_insert(0);
        *count += 1;
        if *count >= TEARDOWN_VIOLATION_THRESHOLD {
            self.torn_down = Some(TEARDOWN_REASON_RESULT_VIOLATION.to_string());
            ResultAdmission::TornDown(why)
        } else {
            ResultAdmission::Violation(why)
        }
    }

    // -- Inspectors ---------------------------------------------------------

    /// The outstanding request, if any.
    pub fn outstanding_request(&self) -> Option<&OutstandingVerifyRequest> {
        self.outstanding.as_ref()
    }

    /// The committed prefix hash the next request chains onto (genesis at
    /// session open; advances on each accepted result).
    pub fn committed_prefix_hash(&self) -> &str {
        &self.committed_prefix_hash
    }

    /// The last round whose result was accepted.
    pub fn last_accepted_round(&self) -> Option<u64> {
        self.last_accepted_round
    }

    /// The last `seq` seen from the verifier sender (RC-7 mirror).
    pub fn verifier_last_seq(&self) -> Option<u64> {
        self.verifier_last_seq
    }

    /// Whether `nonce` is in the session-scoped consumed set.
    pub fn nonce_consumed(&self, nonce: &str) -> bool {
        self.consumed_nonces.contains(nonce)
    }

    /// A peer's protocol-violation count.
    pub fn violations_of(&self, peer: &str) -> u32 {
        self.violations.get(peer).copied().unwrap_or(0)
    }

    /// Whether the session is torn down.
    pub fn is_torn_down(&self) -> bool {
        self.torn_down.is_some()
    }

    /// The teardown reason, when torn down.
    pub fn teardown_reason(&self) -> Option<&str> {
        self.torn_down.as_deref()
    }

    /// Whether the RC-1 audit path switched this session to the
    /// `SingleDecode` fallback.
    pub fn in_single_decode_fallback(&self) -> bool {
        self.fallback_single_decode
    }

    /// The receipt-outcome marker (RC-1 receipt honesty).
    pub fn receipt_outcome(&self) -> ReceiptOutcome {
        self.receipt
    }
}

// ---------------------------------------------------------------------------
// §4.2 — Timing trust: per-verifier EWMA + the verify_pass_ms cross-check
// ---------------------------------------------------------------------------

/// Default EWMA alpha (plan §4.2 / Appendix A; NOT ADR-pinned — plan flag
/// F-4: the scheduler-facing de-rank semantics need a pinned value before
/// light-up).
pub const EWMA_ALPHA_DEFAULT: f64 = 0.25;

/// [`VerifierTiming::with_alpha`] rejects alphas outside `(0.0, 1.0]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidAlpha;

impl std::fmt::Display for InvalidAlpha {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EWMA alpha must lie in (0.0, 1.0]")
    }
}

impl std::error::Error for InvalidAlpha {}

/// Outcome of the `verify_pass_ms` cross-check (ADR-032 §1, RC-2):
/// `Ok` — the claim is within the observed round wall time plus
/// [`VERIFY_PASS_CLOCK_NOISE_MS`] — or `Lie` — the claim is above it and
/// is recorded as `verify_ms_lie` telemetry, the verifier is de-ranked,
/// and the engage gate discounts it as unverified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossCheckOutcome {
    /// Within `observed_wall_ms + VERIFY_PASS_CLOCK_NOISE_MS`.
    Ok,
    /// Above it: a `verify_ms_lie` (inflation caught; under-reporting
    /// cannot be detected from timing alone — RTT/queue dominate — and is
    /// bounded by the realized-loss guard and acceptance-collapse
    /// telemetry, ADR-032 §1).
    Lie,
}

/// Per-VERIFIER timing trust (plan §4.2; RC-2). The EWMA is fed ONLY by
/// the round wall time the REQUESTER measures itself (send `VerifyDrafts`
/// → receive `VerifyDraftsResult`, via [`Self::record_round`]);
/// `verify_pass_ms` is a lower-bound sanity term only
/// ([`Self::cross_check`]). The EWMA is strictly per-verifier — a
/// cohort-wide blend would let one lying peer de-rank honest peers
/// (FORBIDDEN, ADR-032 §1); see [`VerifierTimings`] for the keyed table.
#[derive(Debug, Clone)]
pub struct VerifierTiming {
    alpha: f64,
    ewma_ms: Option<f64>,
    lie_count: u32,
}

impl Default for VerifierTiming {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierTiming {
    /// Default alpha ([`EWMA_ALPHA_DEFAULT`] = 0.25).
    pub fn new() -> Self {
        Self {
            alpha: EWMA_ALPHA_DEFAULT,
            ewma_ms: None,
            lie_count: 0,
        }
    }

    /// Configurable alpha (plan flag F-4), `(0.0, 1.0]`.
    pub fn with_alpha(alpha: f64) -> Result<Self, InvalidAlpha> {
        if !alpha.is_finite() || alpha <= 0.0 || alpha > 1.0 {
            return Err(InvalidAlpha);
        }
        Ok(Self {
            alpha,
            ewma_ms: None,
            lie_count: 0,
        })
    }

    /// Feeds the REQUESTER-measured round wall time into the EWMA
    /// (first sample initializes it).
    pub fn record_round(&mut self, measured_wall_ms: u64) {
        let sample = measured_wall_ms as f64;
        self.ewma_ms = Some(match self.ewma_ms {
            None => sample,
            Some(previous) => self.alpha * sample + (1.0 - self.alpha) * previous,
        });
    }

    /// The per-verifier EWMA in whole milliseconds (rounded to nearest);
    /// `None` before the first measured round.
    pub fn ewma_ms(&self) -> Option<u64> {
        self.ewma_ms.map(|value| value.round() as u64)
    }

    /// The RC-2 cross-check: `verify_pass_ms <= observed_wall_ms +
    /// VERIFY_PASS_CLOCK_NOISE_MS` is `Ok`; anything above is a `Lie`
    /// (recorded — the caller emits `verify_ms_lie` telemetry and
    /// de-ranks; the lie count is exposed for the de-rank policy). The
    /// EWMA is NOT fed by claimed values.
    pub fn cross_check(&mut self, verify_pass_ms: u32, observed_wall_ms: u64) -> CrossCheckOutcome {
        if u64::from(verify_pass_ms) > observed_wall_ms + VERIFY_PASS_CLOCK_NOISE_MS {
            self.lie_count += 1;
            CrossCheckOutcome::Lie
        } else {
            CrossCheckOutcome::Ok
        }
    }

    /// How many `verify_ms_lie` outcomes this verifier has accumulated
    /// (de-rank policy input, plan flag F-4).
    pub fn lie_count(&self) -> u32 {
        self.lie_count
    }
}

/// The per-verifier timing table, keyed by peer id (plan §4.2 sketch:
/// "per-verifier, keyed by peer id"). Structural per-verifier isolation:
/// every read and write touches exactly one peer's [`VerifierTiming`];
/// no method blends across peers, so one lying peer can never de-rank
/// another (ADR-032 §1, tested by the coordinator property suite).
#[derive(Debug, Clone, Default)]
pub struct VerifierTimings {
    /// Configured per-peer alpha (`None` = the default 0.25).
    alpha: Option<f64>,
    per_peer: HashMap<String, VerifierTiming>,
}

impl VerifierTimings {
    /// Empty table, default alpha per peer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty table with a configurable per-peer alpha (`(0.0, 1.0]`).
    pub fn with_alpha(alpha: f64) -> Result<Self, InvalidAlpha> {
        // Validate eagerly so the configuration error surfaces at
        // construction, not on the first lazy per-peer insert.
        VerifierTiming::with_alpha(alpha)?;
        Ok(Self {
            per_peer: HashMap::new(),
            alpha: Some(alpha),
        })
    }

    /// Feeds one REQUESTER-measured round for `peer`.
    pub fn record_round(&mut self, peer: &str, measured_wall_ms: u64) {
        self.tracker(peer).record_round(measured_wall_ms);
    }

    /// `peer`'s EWMA (`None` before its first measured round).
    pub fn ewma_ms(&self, peer: &str) -> Option<u64> {
        self.per_peer.get(peer).and_then(VerifierTiming::ewma_ms)
    }

    /// The RC-2 cross-check for `peer` (see [`VerifierTiming::cross_check`]).
    pub fn cross_check(
        &mut self,
        peer: &str,
        verify_pass_ms: u32,
        observed_wall_ms: u64,
    ) -> CrossCheckOutcome {
        self.tracker(peer)
            .cross_check(verify_pass_ms, observed_wall_ms)
    }

    /// `peer`'s accumulated `verify_ms_lie` count (0 for unknown peers).
    pub fn lie_count(&self, peer: &str) -> u32 {
        self.per_peer.get(peer).map_or(0, VerifierTiming::lie_count)
    }

    fn tracker(&mut self, peer: &str) -> &mut VerifierTiming {
        self.per_peer
            .entry(peer.to_string())
            .or_insert_with(|| match self.alpha {
                Some(alpha) => VerifierTiming {
                    alpha,
                    ewma_ms: None,
                    lie_count: 0,
                },
                None => VerifierTiming::new(),
            })
    }
}

// ---------------------------------------------------------------------------
// §4.3 — Telemetry + audit interfaces (RC-1; node/desktop implement later)
// ---------------------------------------------------------------------------

/// Telemetry surface for the batched-verify family (plan §4.3). The
/// session crate takes NO `modelswarm-telemetry` dependency (it is a
/// dev-dependency today; the graph stays unchanged) — the node/desktop
/// layers implement this trait.
pub trait VerifyTelemetry: Send + Sync {
    /// RC-2: a `verify_pass_ms` claim exceeded the requester-measured
    /// round wall time + clock noise — the verifier is de-ranked and the
    /// engage gate discounts it as unverified.
    fn verify_ms_lie(&self, session_id: &str, peer: &str);
    /// RC-1: the audit path re-executed a committed window and diverged
    /// from the verifier-claimed committed stream — the session switches
    /// to the `SingleDecode` fallback and the receipt is marked.
    fn verifier_divergence(&self, session_id: &str, peer: &str);
    /// I8: a session budget refusal was recorded (the effective §6.5
    /// code, e.g. `overloaded`).
    fn budget_refused(&self, session_id: &str, code: &str);
}

/// Verdict of one audited window (plan §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditVerdict {
    /// The coordinator's own re-execution reproduced the committed
    /// window token-for-token.
    Match,
    /// The re-execution diverged at `at_index` (0-based into
    /// `window_commit`).
    Divergence { at_index: usize },
}

/// The RC-1 audit path (plan §4.3; ADR-032 §3 "Verifier authority is
/// checkable, not assumed"): the coordinator locally re-executes a
/// SAMPLED fraction of committed windows with its own engine for the same
/// profile — at minimum the first committed window of the session and one
/// window after every acceptance/divergence transition (see
/// [`AuditSampler`]) — and compares token-for-token against the committed
/// stream. Audit is sound only within the E0-pinned backend pairing of
/// the session (re-execution spot-checks are sound within a backend
/// family, not across).
///
/// # REQUIRED property of implementations: cache-cold re-execution
///
/// The re-execution MUST run cache-cold (fresh engine/KV state for the
/// audited window). This is a measured requirement, not a preference:
/// `docs/reviews/accuracy-benefits-study-2026-10-11.md` caught, live, a
/// llama.cpp server flipping its greedy continuation between two
/// attractors on REPEAT requests (prompt-cache state; reproduced 3/3,
/// minority digest always at request 0) — E0's single-shot design
/// structurally could not see it. The study's extracted rule:
/// "divergence checks and audit re-executions MUST run cache-cold, or the
/// check itself can flip the answer." A cache-warm audit can therefore
/// report a DIVERGENCE for an honest verifier (or a match for a lying
/// one) — implementations MUST evict/reset the cache before the audited
/// pass.
#[async_trait::async_trait]
pub trait WindowAuditor: Send + Sync {
    /// Re-executes one committed window with the coordinator's own
    /// engine (cache-cold — REQUIRED, see the trait docs) and compares
    /// token-for-token against `window_commit` (the verifier-claimed
    /// `window_tokens[..accepted_prefix_len] ++ [correction]`).
    async fn audit_window(
        &self,
        prompt_tokens: &[u32],
        committed_before: &[u32],
        window_commit: &[u32],
    ) -> Result<AuditVerdict, RuntimeError>;
}

/// The acceptance/divergence class of one round's result — the audit
/// sampling policy's transition input (plan §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowOutcome {
    /// Full acceptance (`divergence_point` null).
    FullAcceptance,
    /// The window diverged (rejected at some position).
    Divergence,
}

impl WindowOutcome {
    /// Classifies a result's shape.
    pub fn of(divergence_point: Option<u32>) -> Self {
        match divergence_point {
            Some(_) => WindowOutcome::Divergence,
            None => WindowOutcome::FullAcceptance,
        }
    }
}

/// The RC-1 audit SAMPLING policy (plan §4.3, normative): audit at
/// minimum the FIRST committed window of the session and one window
/// after every acceptance/divergence transition. [`Self::sample`] is
/// called with each committed window's [`WindowOutcome`] BEFORE the
/// audit decision; it returns whether THAT window must be audited.
#[derive(Debug, Clone, Default)]
pub struct AuditSampler {
    seen_any: bool,
    last_outcome: Option<WindowOutcome>,
    audited: usize,
}

impl AuditSampler {
    /// Empty sampler (nothing audited yet).
    pub fn new() -> Self {
        Self::default()
    }

    /// Records this window's outcome class and returns whether the
    /// window MUST be audited: the first window of the session, or the
    /// first window whose class differs from the previous one (an
    /// acceptance/divergence transition).
    pub fn sample(&mut self, outcome: WindowOutcome) -> bool {
        let first = !self.seen_any;
        let transition = self.last_outcome != Some(outcome);
        self.seen_any = true;
        self.last_outcome = Some(outcome);
        let audit = first || transition;
        self.audited += usize::from(audit);
        audit
    }

    /// How many windows this sampler has mandated so far.
    pub fn audited_windows(&self) -> usize {
        self.audited
    }
}

// ---------------------------------------------------------------------------
// §4 — Coordinator-side negotiation decisions (SessionAccept honesty)
// ---------------------------------------------------------------------------

/// Requester-side `SessionAccept` validation failure (plan §4.4 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAcceptError {
    /// An echoed field (`session_id` / `protocol_version` / `preset`)
    /// differs from the offer.
    EchoMismatch(&'static str),
    /// The engine disclosure is schema-invalid: `batch_verify: true`
    /// REQUIRES `batch_window_max` in `1..=WINDOW_CAP` (invariant I4).
    InvalidDisclosure,
    /// The effective budget exceeds the offered envelope — it is clamped
    /// DOWN only, never up (carries the field name).
    BudgetInflated(&'static str),
}

impl std::fmt::Display for SessionAcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionAcceptError::EchoMismatch(field) => {
                write!(f, "accept does not echo the offer's {field:?}")
            }
            SessionAcceptError::InvalidDisclosure => {
                write!(
                    f,
                    "engine disclosure invalid (batch_window_max out of 1..=WINDOW_CAP)"
                )
            }
            SessionAcceptError::BudgetInflated(field) => {
                write!(f, "effective budget {field:?} exceeds the offered envelope")
            }
        }
    }
}

impl std::error::Error for SessionAcceptError {}

/// Requester-side honesty check of one `SessionAccept` against the offer
/// it answers (ADR-032 §3): echoed `session_id`/`protocol_version`/
/// `preset`, a schema-valid engine disclosure (`batch_verify: true`
/// REQUIRES `batch_window_max` in `1..=WINDOW_CAP` — I4), and an
/// effective budget clamped DOWN only.
pub fn validate_session_accept(
    offer: &SessionOffer,
    accept: &SessionAccept,
) -> Result<(), SessionAcceptError> {
    if accept.session_id != offer.session_id {
        return Err(SessionAcceptError::EchoMismatch("session_id"));
    }
    if accept.protocol_version != offer.protocol_version {
        return Err(SessionAcceptError::EchoMismatch("protocol_version"));
    }
    if accept.preset != offer.preset {
        return Err(SessionAcceptError::EchoMismatch("preset"));
    }
    if !accept.engine.is_valid_disclosure() {
        return Err(SessionAcceptError::InvalidDisclosure);
    }
    if accept.budget.max_endpoints > offer.budget.max_endpoints {
        return Err(SessionAcceptError::BudgetInflated("max_endpoints"));
    }
    if accept.budget.max_endpoint_seconds > offer.budget.max_endpoint_seconds {
        return Err(SessionAcceptError::BudgetInflated("max_endpoint_seconds"));
    }
    if accept.budget.max_output_tokens > offer.budget.max_output_tokens {
        return Err(SessionAcceptError::BudgetInflated("max_output_tokens"));
    }
    Ok(())
}

/// Requester-side batch-verifier eligibility (ADR-032 §3/§4): the accept
/// must validate AND the peer must actually be able to batch-verify
/// under the session's backend pairing. A `batch_verify: false` peer is
/// a first-class single (and may act as proposer) — it is NEVER selected
/// as this family's batch verifier.
pub fn eligible_batch_verifier(offer: &SessionOffer, accept: &SessionAccept) -> bool {
    validate_session_accept(offer, accept).is_ok()
        && accept.engine.batch_verify
        && accept.engine.backend == offer.verifier_backend
}

/// Peer-side honest reject reason for an incoming offer, if any
/// (ADR-032 §3): a peer whose engine backend differs from the offer's
/// `verifier_backend` rejects with `backend_mismatch` (E0 pairing:
/// CPU ≠ Vulkan, never mixed) and the requester falls back to single —
/// mandatory, never silent. `batch_verify` incapability is NOT a reject
/// here: such a peer ACCEPTS declaring `batch_verify: false` in its
/// engine disclosure (ADR-032 §4) and stays a first-class single; the
/// remaining frozen reasons (`preset_unavailable`,
/// `batch_verify_unsupported`, `budget_infeasible`) fire on the peer's
/// own policy judgments of the offer and are left to the serve loop.
pub fn peer_reject_reason(
    offer: &SessionOffer,
    engine: &EngineDisclosure,
) -> Option<SessionRejectReason> {
    (engine.backend != offer.verifier_backend).then_some(SessionRejectReason::BackendMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::default_sampling_params_hash;
    use crate::{compute_prefix_hash, GENESIS_PREFIX_HASH};
    use modelswarm_identity::canonical_json as identity_canonical_json;
    use serde_json::json;

    /// Fixture-only identity in the `[seed; 32]` style (never production).
    fn fixture_identity(seed: u8) -> InstallationIdentity {
        InstallationIdentity::from_bytes(&[seed; 32])
    }

    fn sample_request(sender: &str, signature: &str) -> VerifyDrafts {
        VerifyDrafts {
            session_id: "sess-1".to_string(),
            protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
            seq: 12,
            round: 3,
            profile_id: format!("msp1:{}", "ab".repeat(32)),
            parent_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
            generation_params_hash: batch_generation_params_hash(&SamplingParams::default())
                .expect("default sampling params are integral"),
            window_tokens: vec![101, 102, 103, 104, 105, 106, 107, 108],
            proposer_id: "12D3KooProposer".to_string(),
            nonce: "a1b2c3d4e5f60718".to_string(),
            deadline_ms: 2_500,
            sender: sender.to_string(),
            signature: signature.to_string(),
        }
    }

    fn sample_result(sender: &str, signature: &str) -> VerifyDraftsResult {
        // ADR-032 §1 rule 2: new_prefix_hash covers
        // (parent ‖ accepted prefix ‖ [correction]) — the FULL accepted
        // prefix of the sample window, not the correction alone. (Session-3
        // fix of the session-1 inconsistency the session-2 handoff flagged:
        // the helper previously hashed [999] only while claiming
        // accepted_prefix_len 8 over the 8-token sample window.)
        let window = [101, 102, 103, 104, 105, 106, 107, 108];
        let mut committed = window.to_vec();
        committed.push(999);
        VerifyDraftsResult {
            session_id: "sess-1".to_string(),
            protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
            seq: 4,
            round: 3,
            accepted_prefix_len: 8,
            divergence_point: None,
            correction: Some(999),
            new_prefix_hash: compute_prefix_hash(GENESIS_PREFIX_HASH, &committed).unwrap(),
            verify_pass_ms: 35,
            nonce_echo: "a1b2c3d4e5f60718".to_string(),
            sender: sender.to_string(),
            signature: signature.to_string(),
        }
    }

    // -- §1.5: round-trip + exact serde_json::to_value shape ----------------

    #[test]
    fn request_wire_shape_is_snake_case_and_round_trips() {
        let msg = sample_request("coordinator-id", "sig");
        let value = serde_json::to_value(&msg).unwrap();
        assert_eq!(
            value,
            json!({
                "session_id": "sess-1",
                "protocol_version": "msp-cooperative-v1",
                "seq": 12,
                "round": 3,
                "profile_id": format!("msp1:{}", "ab".repeat(32)),
                "parent_prefix_hash": GENESIS_PREFIX_HASH,
                "generation_params_hash": msg.generation_params_hash,
                "window_tokens": [101, 102, 103, 104, 105, 106, 107, 108],
                "proposer_id": "12D3KooProposer",
                "nonce": "a1b2c3d4e5f60718",
                "deadline_ms": 2_500,
                "sender": "coordinator-id",
                "signature": "sig"
            })
        );
        // Plain serde round-trip (permissive) AND the strict two-pass parse.
        assert_eq!(
            serde_json::from_value::<VerifyDrafts>(value.clone()).unwrap(),
            msg
        );
        assert_eq!(VerifyDrafts::parse(&value).unwrap(), msg);
    }

    #[test]
    fn result_wire_shape_is_snake_case_and_round_trips() {
        let msg = sample_result("verifier-id", "sig");
        let value = serde_json::to_value(&msg).unwrap();
        assert_eq!(
            value,
            json!({
                "session_id": "sess-1",
                "protocol_version": "msp-cooperative-v1",
                "seq": 4,
                "round": 3,
                "accepted_prefix_len": 8,
                "divergence_point": null,
                "correction": 999,
                "new_prefix_hash": msg.new_prefix_hash,
                "verify_pass_ms": 35,
                "nonce_echo": "a1b2c3d4e5f60718",
                "sender": "verifier-id",
                "signature": "sig"
            })
        );
        assert_eq!(
            serde_json::from_value::<VerifyDraftsResult>(value.clone()).unwrap(),
            msg
        );
        assert_eq!(VerifyDraftsResult::parse(&value).unwrap(), msg);
        // The seq pair of the §1 example is per-sender: request 12, result 4.
        assert_eq!(sample_request("c", "s").seq, 12);
        assert_eq!(msg.seq, 4);
    }

    // -- §1.5: present-as-null ---------------------------------------------

    #[test]
    fn divergence_point_is_present_as_null() {
        let value = serde_json::to_value(sample_result("v", "sig")).unwrap();
        let object = value.as_object().unwrap();
        assert!(object.contains_key("divergence_point"));
        assert_eq!(object.get("divergence_point"), Some(&Value::Null));
        // Omitting the key is a schema failure (bad_frame path).
        let mut missing = object.clone();
        missing.remove("divergence_point");
        assert_eq!(
            VerifyDraftsResult::parse(&Value::Object(missing)).unwrap_err(),
            FrameParseError::MissingKey("divergence_point".to_string())
        );
    }

    #[test]
    fn eog_correction_is_present_as_null() {
        // F-2: the FIELD is always present; null exactly at end-of-generation.
        let mut msg = sample_result("v", "sig");
        msg.correction = None;
        let value = serde_json::to_value(&msg).unwrap();
        assert_eq!(value.get("correction"), Some(&Value::Null));
        assert_eq!(VerifyDraftsResult::parse(&value).unwrap(), msg);
        let mut missing = value.as_object().unwrap().clone();
        missing.remove("correction");
        assert_eq!(
            VerifyDraftsResult::parse(&Value::Object(missing)).unwrap_err(),
            FrameParseError::MissingKey("correction".to_string())
        );
    }

    #[test]
    fn unknown_or_missing_keys_and_non_objects_are_schema_failures() {
        let value = serde_json::to_value(sample_request("c", "sig")).unwrap();
        let mut with_unknown = value.as_object().unwrap().clone();
        with_unknown.insert("extra".to_string(), json!(1));
        assert_eq!(
            VerifyDrafts::parse(&Value::Object(with_unknown)).unwrap_err(),
            FrameParseError::UnknownKey("extra".to_string())
        );
        let mut missing_nonce = value.as_object().unwrap().clone();
        missing_nonce.remove("nonce");
        assert_eq!(
            VerifyDrafts::parse(&Value::Object(missing_nonce)).unwrap_err(),
            FrameParseError::MissingKey("nonce".to_string())
        );
        assert_eq!(
            VerifyDrafts::parse(&json!([1, 2])).unwrap_err(),
            FrameParseError::NotAnObject
        );
        assert_eq!(
            VerifyDraftsResult::parse(&json!("nope")).unwrap_err(),
            FrameParseError::NotAnObject
        );
    }

    #[test]
    fn float_fields_fail_deserialization() {
        // verify_pass_ms MUST be an integer: a float is unsignable and
        // fails the strict parse (fail-closed).
        let value = serde_json::to_value(sample_result("v", "sig")).unwrap();
        let mut float_ms = value.clone();
        *float_ms.get_mut("verify_pass_ms").unwrap() = json!(35.5);
        assert!(matches!(
            VerifyDraftsResult::parse(&float_ms),
            Err(FrameParseError::BadType(_))
        ));
        // Even an integral-looking JSON float (35.0) is a float on the wire.
        *float_ms.get_mut("verify_pass_ms").unwrap() = json!(35.0);
        assert!(matches!(
            VerifyDraftsResult::parse(&float_ms),
            Err(FrameParseError::BadType(_))
        ));
        let mut float_seq = serde_json::to_value(sample_request("c", "sig")).unwrap();
        *float_seq.get_mut("seq").unwrap() = json!(12.0);
        assert!(matches!(
            VerifyDrafts::parse(&float_seq),
            Err(FrameParseError::BadType(_))
        ));
    }

    #[test]
    fn empty_window_is_malformed() {
        let mut msg = sample_request("c", "sig");
        msg.window_tokens.clear();
        let value = serde_json::to_value(&msg).unwrap();
        assert_eq!(
            VerifyDrafts::parse(&value).unwrap_err(),
            FrameParseError::EmptyWindow
        );
    }

    // -- §1.5: bare-hash rule -----------------------------------------------

    #[test]
    fn is_bare_hash_rejects_prefixed_and_malformed_forms() {
        assert!(is_bare_hash(GENESIS_PREFIX_HASH));
        assert!(is_bare_hash(&"0f".repeat(32)));
        // §1 rule 1: the "sha256:" prefixed hub bodyDigest form is rejected.
        assert!(!is_bare_hash(&format!("sha256:{GENESIS_PREFIX_HASH}")));
        assert!(!is_bare_hash(&GENESIS_PREFIX_HASH.to_uppercase()));
        assert!(!is_bare_hash(&"0".repeat(63)));
        assert!(!is_bare_hash(&"0".repeat(65)));
        assert!(!is_bare_hash(&"g".repeat(64)));
        assert!(!is_bare_hash(""));
    }

    #[test]
    fn prefix_chain_reuses_the_shipped_hash_function() {
        // §1 rule 2: no new hash function — genesis is hex(sha256("")),
        // and new_prefix_hash chains via the shipped compute_prefix_hash
        // over (parent ‖ accepted prefix ‖ [correction]).
        assert_eq!(GENESIS_PREFIX_HASH, hex::encode(Sha256::digest(b"")));
        let window = [101, 102, 103, 104, 105, 106, 107, 108];
        let accepted = &window[..3];
        let correction = 999u32;
        let mut committed = accepted.to_vec();
        committed.push(correction);
        let new_hash = compute_prefix_hash(GENESIS_PREFIX_HASH, &committed).unwrap();
        assert!(is_bare_hash(&new_hash));
        assert_ne!(new_hash, GENESIS_PREFIX_HASH);
        // The result's new_prefix_hash pins exactly this construction:
        // full-acceptance (k=8) hashes window[..8] ++ [correction], not
        // the correction alone (session-3 alignment; ADR-032 §1 rule 2).
        let msg = sample_result("v", "sig");
        let mut full = window.to_vec();
        full.push(correction);
        assert_eq!(
            msg.new_prefix_hash,
            compute_prefix_hash(GENESIS_PREFIX_HASH, &full).unwrap()
        );
    }

    // -- §1.5: signature preimage / sign / verify ---------------------------

    fn signed_request() -> (VerifyDrafts, InstallationIdentity) {
        let identity = fixture_identity(0x11);
        let mut msg = sample_request(&identity.installation_id(), "placeholder");
        msg.signature = sign_verify_drafts(&msg, &identity).expect("default params are signable");
        (msg, identity)
    }

    fn signed_result() -> (VerifyDraftsResult, InstallationIdentity) {
        let identity = fixture_identity(0x22);
        let mut msg = sample_result(&identity.installation_id(), "placeholder");
        msg.signature =
            sign_verify_drafts_result(&msg, &identity).expect("default params are signable");
        (msg, identity)
    }

    #[test]
    fn signature_verifies_and_tampering_breaks_it() {
        let (msg, identity) = signed_request();
        verify_verify_drafts_signature(&msg, &identity.verifying_key()).unwrap();

        // Flipping ANY signed field breaks the signature.
        let mut tampered = msg.clone();
        tampered.deadline_ms = 2_501;
        assert!(verify_verify_drafts_signature(&tampered, &identity.verifying_key()).is_err());
        let mut tampered_round = msg.clone();
        tampered_round.round = 4;
        assert!(
            verify_verify_drafts_signature(&tampered_round, &identity.verifying_key()).is_err()
        );
        let mut tampered_window = msg.clone();
        tampered_window.window_tokens[0] = 1;
        assert!(
            verify_verify_drafts_signature(&tampered_window, &identity.verifying_key()).is_err()
        );

        // Tampering the signature itself breaks it.
        let mut bad_sig = msg.clone();
        bad_sig.signature = BASE64.encode([0u8; 64]);
        let err = verify_verify_drafts_signature(&bad_sig, &identity.verifying_key()).unwrap_err();
        assert_eq!(err.to_string(), "spec protocol violation: bad_signature");

        // A signature that is not 64 bytes fails the length check.
        let mut short_sig = msg.clone();
        short_sig.signature = BASE64.encode([0u8; 10]);
        let err =
            verify_verify_drafts_signature(&short_sig, &identity.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("not 64 bytes"));

        // Not base64 at all.
        let mut not_b64 = msg.clone();
        not_b64.signature = "!!!not-base64!!!".to_string();
        let err = verify_verify_drafts_signature(&not_b64, &identity.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("not valid base64"));

        // Wrong expected key fails.
        let other = fixture_identity(0x33);
        assert!(verify_verify_drafts_signature(&msg, &other.verifying_key()).is_err());

        // Same discipline for the result message.
        let (result, verifier) = signed_result();
        verify_verify_drafts_result_signature(&result, &verifier.verifying_key()).unwrap();
        let mut tampered_result = result.clone();
        tampered_result.accepted_prefix_len = 7;
        assert!(
            verify_verify_drafts_result_signature(&tampered_result, &verifier.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn sender_binding_is_checked_first() {
        // Signed by 0x22 with sender = 0x22's installation id, but verified
        // against 0x11's key: the sender check must fire BEFORE the Ed25519
        // check (the verify_commit_signature discipline, §1 rule 5).
        let (result, _verifier) = signed_result();
        let other = fixture_identity(0x11);
        let err =
            verify_verify_drafts_result_signature(&result, &other.verifying_key()).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("sender is not the authenticated session key"),
            "{text}"
        );
        assert!(!text.contains("bad_signature"), "{text}");
        // A signature valid under the expected key but carrying a foreign
        // sender label is likewise rejected on the sender check.
        let (mut msg, identity) = signed_request();
        msg.sender = "someone-else".to_string();
        let err = verify_verify_drafts_signature(&msg, &identity.verifying_key()).unwrap_err();
        assert!(err
            .to_string()
            .contains("sender is not the authenticated session key"));
    }

    #[test]
    fn signing_preimage_omits_signature_entirely() {
        let (msg, _identity) = signed_request();
        let preimage = signing_preimage(&msg).unwrap();
        let parsed: Value = serde_json::from_str(&preimage).unwrap();
        let object = parsed.as_object().unwrap();
        // Omitted entirely — not null, not empty string.
        assert!(!object.contains_key("signature"));
        // Every other declared field is present.
        for field in VERIFY_DRAFTS_FIELDS {
            if field == "signature" {
                continue;
            }
            assert!(object.contains_key(field), "preimage missing {field}");
        }
        // The full message's canonical form differs (it HAS the signature).
        let full = canonical_json(&serde_json::to_value(&msg).unwrap()).unwrap();
        assert_ne!(preimage, full);

        // Null-valued fields survive into the preimage (§1 rule 4): a
        // full-acceptance result keeps divergence_point present-as-null.
        let (result, _verifier) = signed_result();
        let result_preimage = signing_preimage(&result).unwrap();
        let parsed: Value = serde_json::from_str(&result_preimage).unwrap();
        assert_eq!(parsed.get("divergence_point"), Some(&Value::Null));
        for field in VERIFY_DRAFTS_RESULT_FIELDS {
            if field == "signature" {
                continue;
            }
            assert!(parsed.as_object().unwrap().contains_key(field));
        }
    }

    // -- §1.5: batch_generation_params_hash ---------------------------------

    #[test]
    fn batch_generation_params_hash_is_stable_64_hex() {
        let params = SamplingParams::default();
        let once = batch_generation_params_hash(&params).unwrap();
        let twice = batch_generation_params_hash(&params).unwrap();
        assert_eq!(once, twice);
        assert!(is_bare_hash(&once));
    }

    #[test]
    fn batch_generation_params_hash_renders_integrals_as_integers() {
        // The default params (temperature 1.0 / top_p 1.0 / top_k 40 /
        // seed None) render as the bare-integer canonical object
        // {"seed":null,"temperature":1,"top_k":40,"top_p":1}.
        let params = SamplingParams::default();
        let expected_preimage = json!({
            "seed": null,
            "temperature": 1,
            "top_k": 40,
            "top_p": 1
        });
        let expected = hex::encode(Sha256::digest(
            canonical_json(&expected_preimage).unwrap().as_bytes(),
        ));
        assert_eq!(batch_generation_params_hash(&params).unwrap(), expected);
        // Canonical bytes themselves: keys sorted, no floats, no ".0".
        assert_eq!(
            canonical_json(&expected_preimage).unwrap(),
            r#"{"seed":null,"temperature":1,"top_k":40,"top_p":1}"#
        );

        // A set seed renders the full integer (F-1) and changes the hash.
        let seeded = SamplingParams {
            seed: Some(7),
            ..SamplingParams::default()
        };
        assert_ne!(
            batch_generation_params_hash(&seeded).unwrap(),
            batch_generation_params_hash(&params).unwrap()
        );
        let seeded_preimage = json!({
            "seed": 7,
            "temperature": 1,
            "top_k": 40,
            "top_p": 1
        });
        assert_eq!(
            batch_generation_params_hash(&seeded).unwrap(),
            hex::encode(Sha256::digest(
                canonical_json(&seeded_preimage).unwrap().as_bytes()
            ))
        );
    }

    #[test]
    fn batch_generation_params_hash_fails_closed_on_non_integral() {
        let hot = SamplingParams {
            temperature: 0.7,
            ..SamplingParams::default()
        };
        assert_eq!(
            batch_generation_params_hash(&hot).unwrap_err(),
            ParamsHashError::NonIntegral
        );
        let narrow_p = SamplingParams {
            top_p: 0.95,
            ..SamplingParams::default()
        };
        assert_eq!(
            batch_generation_params_hash(&narrow_p).unwrap_err(),
            ParamsHashError::NonIntegral
        );
        let nan = SamplingParams {
            temperature: f32::NAN,
            ..SamplingParams::default()
        };
        assert_eq!(
            batch_generation_params_hash(&nan).unwrap_err(),
            ParamsHashError::NonIntegral
        );
    }

    #[test]
    fn family_params_hash_is_not_the_old_vocabulary_hash() {
        // §1 rule 3: the Debug-string preimage of the OLD vocabulary is
        // NOT this family's wire preimage.
        assert_ne!(
            batch_generation_params_hash(&SamplingParams::default()).unwrap(),
            default_sampling_params_hash()
        );
    }

    // -- §1.5: canonicalizer parity pin --------------------------------------

    #[test]
    fn canonicalizers_agree_byte_for_byte_on_family_payloads() {
        let (request, _c) = signed_request();
        let (result, _v) = signed_result();
        let payloads = [
            serde_json::to_value(&request).unwrap(),
            serde_json::to_value(&result).unwrap(),
            json!({"seed": null, "temperature": 1, "top_k": 40, "top_p": 1}),
            json!({"window_tokens": [1, 2, 3], "nested": {"b": [true, null], "a": "x"}}),
        ];
        for payload in &payloads {
            assert_eq!(
                identity_canonical_json(payload).expect("identity canonicalizer accepts"),
                canonical_json(payload).expect("types canonicalizer accepts"),
                "canonicalizer divergence on {payload}"
            );
        }
        // Parity on rejection too: both refuse floats.
        let floaty = json!({"verify_pass_ms": 35.5});
        assert!(identity_canonical_json(&floaty).is_none());
        assert_eq!(
            canonical_json(&floaty).unwrap_err(),
            CanonicalError::FloatRejected
        );
    }

    // -- §4.2/§4.3 unit pins (the coordinator property suite carries the
    //    RC-3/I2/telemetry coverage) ----------------------------------------

    #[test]
    fn verifier_timing_ewma_default_alpha_and_configuration() {
        // None before the first measured round.
        let mut timing = VerifierTiming::new();
        assert_eq!(timing.ewma_ms(), None);
        assert_eq!(timing.alpha, EWMA_ALPHA_DEFAULT);

        // Default alpha 0.25: 100 then 200 -> 0.25*200 + 0.75*100 = 125.
        timing.record_round(100);
        assert_eq!(timing.ewma_ms(), Some(100));
        timing.record_round(200);
        assert_eq!(timing.ewma_ms(), Some(125));

        // Configurable alpha (plan flag F-4): 0.5 gives 0.5*200+0.5*100.
        let mut half = VerifierTiming::with_alpha(0.5).unwrap();
        half.record_round(100);
        half.record_round(200);
        assert_eq!(half.ewma_ms(), Some(150));

        // Alpha bounds: (0.0, 1.0] — 0.0, 1.0+epsilon, NaN, infinity fail.
        assert!(VerifierTiming::with_alpha(0.0).is_err());
        assert!(VerifierTiming::with_alpha(1.0).is_ok());
        assert!(VerifierTiming::with_alpha(1.0 + f64::EPSILON).is_err());
        assert!(VerifierTiming::with_alpha(f64::NAN).is_err());
        assert!(VerifierTiming::with_alpha(f64::INFINITY).is_err());
    }

    #[test]
    fn verifier_timing_cross_check_pins_the_25ms_bound() {
        // RC-2: claimed <= observed + 25 ms is Ok; above is a Lie. The
        // bound is INCLUSIVE at +25 (clock-noise allowance).
        let mut timing = VerifierTiming::new();
        assert_eq!(
            timing.cross_check(35, 10),
            CrossCheckOutcome::Ok,
            "35 <= 10 + 25"
        );
        assert_eq!(
            timing.cross_check(36, 10),
            CrossCheckOutcome::Lie,
            "36 > 10 + 25"
        );
        assert_eq!(timing.lie_count(), 1);
        assert_eq!(timing.cross_check(0, 0), CrossCheckOutcome::Ok);
        // Under-reporting is NOT detectable from timing alone (ADR §1) —
        // the cross-check stays Ok.
        assert_eq!(timing.cross_check(1, 10_000), CrossCheckOutcome::Ok);
        assert_eq!(timing.lie_count(), 1);
        // Lies never feed the EWMA (requester-measured rounds only).
        assert_eq!(timing.ewma_ms(), None);
        timing.record_round(50);
        assert_eq!(timing.ewma_ms(), Some(50));
    }

    #[test]
    fn audit_sampler_audits_first_window_and_transitions() {
        let mut sampler = AuditSampler::new();
        // First window always; same class again not; class change yes.
        assert!(sampler.sample(WindowOutcome::FullAcceptance));
        assert!(!sampler.sample(WindowOutcome::FullAcceptance));
        assert!(sampler.sample(WindowOutcome::Divergence));
        assert!(!sampler.sample(WindowOutcome::Divergence));
        assert!(!sampler.sample(WindowOutcome::Divergence));
        assert!(sampler.sample(WindowOutcome::FullAcceptance));
        assert_eq!(sampler.audited_windows(), 3);
        // WindowOutcome classifies by the divergence shape.
        assert_eq!(WindowOutcome::of(None), WindowOutcome::FullAcceptance);
        assert_eq!(WindowOutcome::of(Some(3)), WindowOutcome::Divergence);
    }

    #[test]
    fn receipt_honesty_label_is_verifier_claimed_and_adds_no_wire_field() {
        // RC-1 receipt honesty: counters granted from this family are
        // verifier-claimed numbers (documented at receipt intake; NO new
        // wire fields — the label must not leak onto any frozen shape).
        assert_eq!(RECEIPT_COUNTER_HONESTY_LABEL, "verifier-claimed");
        let (result, _verifier) = signed_result();
        let wire = serde_json::to_string(&result).unwrap();
        assert!(!wire.contains(RECEIPT_COUNTER_HONESTY_LABEL));
        assert!(!VERIFY_DRAFTS_RESULT_FIELDS.contains(&RECEIPT_COUNTER_HONESTY_LABEL));
    }
}
