//! The VerifyDrafts serve loop (ADR-032 §8; feature `verifydrafts`) — the
//! verifier side of one cooperative session.
//!
//! Everything adjudicating (admission stages, RC-4 commit admission,
//! RC-5 round state) lives in
//! [`modelswarm_session::verifydrafts::VerifyDraftsGate`]; this loop
//! supplies the §8 operational obligations:
//!
//! - offer → honest `SessionAccept` (engine disclosure wired through
//!   config) or `SessionReject` (frozen reasons only);
//! - the transport-authenticated remote PeerId on every admission call
//!   (RC-1/RC-2), with the coordinator key PINNED from that authenticated
//!   identity ([`super::verifying_key_from_peer_id`]);
//! - the one engine pass via the [`BatchVerifyEngine`] trait, then RC-2
//!   SIGNING of the gate's unsigned draft with the verifier identity and
//!   the wrapper-measured engine-pass wall time as `verify_pass_ms`;
//! - the budget seconds ledger advanced on wall-clock deltas (RC-2, §8e);
//! - WAIT_COMMIT expiry polling at `deadline_ms + 250 ms` (RC-5(b));
//! - `SingleDecode` fallback availability: every teardown carries an
//!   honest reason, so the coordinator's mandatory fallback-to-single is
//!   never silent;
//! - rejections serialized as `RejectionFrame`/`CancelRoundFrame` with
//!   codes, counts, and hashes ONLY (§2 privacy rule).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;

use modelswarm_identity::InstallationIdentity;
use modelswarm_runtime::{RuntimeError, SamplingParams};
use modelswarm_session::negotiation::{
    Backend, EngineDisclosure, FrameRejectReason, PinCarrierError, Preset, SessionAccept,
    SessionBudget, SessionOffer, SessionReject, SessionRejectReason, WirePinCarrier,
    COOPERATIVE_PROTOCOL_VERSION,
};
use modelswarm_session::verifydrafts::{
    batch_generation_params_hash, sign_verify_drafts_result, verify_pin_carrier_signature,
    AdmissionDecision, BatchVerifyEngine, CommitApplyOutcome, DispatchOutcome, GatePreStateSeed,
    GateState, RejectionFrame, VerifyDraftsGate, VerifyDraftsGateConfig, DEADLINE_CLAMP_MAX_MS,
    DEADLINE_CLAMP_MIN_MS, WAIT_COMMIT_GRACE_MS,
};
use modelswarm_session::{CommitPrefix, GENESIS_PREFIX_HASH};
use modelswarm_telemetry::Telemetry;
use modelswarm_transport::ed25519_dalek::VerifyingKey;
use modelswarm_transport::frame::MAX_FRAME_BYTES;
use modelswarm_transport::libp2p_backend::Libp2pListener;

use super::wire::{VerifyDraftsWire, WireError};
use super::{
    clamp_budget_down, default_supported_presets, demux_family_frame, http_adapter_disclosure,
    unix_ms_now, verifying_key_from_peer_id, FamilyFrame, FAMILY_IO_DEADLINE, FAMILY_SESSION_IDLE,
};

/// Why one served VerifyDrafts session ended (labels only — no payloads).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeEndReason {
    /// The remote closed the session (clean teardown path).
    ClientClosed,
    /// No frame arrived for `session_idle`.
    IdleTimeout,
    /// No `SessionOffer` arrived within the open deadline.
    OfferTimeout,
    /// The offer failed schema/protocol-version checks (no reject
    /// vocabulary exists for a non-offer first frame; the session ends).
    BadOffer(&'static str),
    /// The offer was refused with an honest `SessionReject`.
    RejectedOffer(SessionRejectReason),
    /// The gate tore the session down (profile/commit/result violations);
    /// the string is the gate's teardown reason.
    TornDown { reason: String },
    /// A frame-level reject ended the session (teardown-family code).
    FrameRejected { code: FrameRejectReason },
    /// The engine pass failed; the honest stream outcome is session end
    /// (ADR-032: "the serve loop decides the honest stream outcome").
    EngineError(&'static str),
    /// A send/recv transport failure (label only).
    WireFailure { what: &'static str },
    /// A frame no family message exists for arrived mid-session.
    UnexpectedFrame(&'static str),
    /// Local misconfiguration (non-integral sampling params, invalid
    /// disclosure, floor above ceiling, non-Ed25519 remote PeerId) —
    /// detected before any accept.
    Misconfigured(String),
}

impl ServeEndReason {
    /// Stable telemetry label.
    pub fn as_str(&self) -> &'static str {
        match self {
            ServeEndReason::ClientClosed => "client_closed",
            ServeEndReason::IdleTimeout => "idle_timeout",
            ServeEndReason::OfferTimeout => "offer_timeout",
            ServeEndReason::BadOffer(_) => "bad_offer",
            ServeEndReason::RejectedOffer(_) => "rejected_offer",
            ServeEndReason::TornDown { .. } => "torn_down",
            ServeEndReason::FrameRejected { .. } => "frame_rejected",
            ServeEndReason::EngineError(_) => "engine_error",
            ServeEndReason::WireFailure { .. } => "wire_failure",
            ServeEndReason::UnexpectedFrame(_) => "unexpected_frame",
            ServeEndReason::Misconfigured(_) => "misconfigured",
        }
    }
}

impl std::fmt::Display for ServeEndReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeEndReason::BadOffer(why)
            | ServeEndReason::EngineError(why)
            | ServeEndReason::WireFailure { what: why }
            | ServeEndReason::UnexpectedFrame(why) => write!(f, "{}: {why}", self.as_str()),
            ServeEndReason::Misconfigured(why) => write!(f, "misconfigured: {why}"),
            ServeEndReason::TornDown { reason } => write!(f, "torn_down: {reason}"),
            other => write!(f, "{}", other.as_str()),
        }
    }
}

/// The ADR-036 §3.1/§3.2 serving-side user-content carriage setting.
/// DEFAULT ON per the owner directive 2026-10-13 ("the idea of a swarm is
/// that all agents work together, privacy is not a concern at this
/// moment"): a stock install carries elected carrier sessions with no
/// additional configuration. The opt-OUT refuses a pin carrier with the
/// honest labeled reject `content_carriage_refused` — never a silent
/// drop, never a misleading label. Honest boundary of the opt-out
/// (ADR-036 §3.1): it prevents this peer from PROCESSING the content (no
/// prefill, no engine work); it cannot prevent RECEIVING the bytes of a
/// session that was already dialed, because no roster or wire field
/// carries the carriage posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentCarriage {
    /// Carry and process other users' conversations (token-id form)
    /// through family verification — the default-on posture.
    On,
    /// Refuse carrier sessions honestly (`content_carriage_refused`).
    Off,
}

impl ContentCarriage {
    /// Stable label for status surfaces ("on" | "off").
    pub fn as_str(self) -> &'static str {
        match self {
            ContentCarriage::On => "on",
            ContentCarriage::Off => "off",
        }
    }
}

/// Node-side configuration for one served VerifyDrafts session. The engine
/// disclosure is wired through here — the honest default is
/// [`http_adapter_disclosure`] (`batch_verify: false`: the pinned llama.cpp
/// HTTP adapter cannot batch-verify; the real engine adapter is separately
/// gated engine work).
#[derive(Clone)]
pub struct VerifyDraftsServeConfig {
    /// The exact profile this node hosts/serves (`msp1:<64 hex>`; the
    /// project rule — I7 cross-profile isolation).
    pub profile_id: String,
    /// The verifier identity: signs every `VerifyDraftsResult` (RC-2).
    pub verifier_identity: InstallationIdentity,
    /// The engine disclosure answered in `SessionAccept` and enforced at
    /// admission stage 10. Honest default: `batch_verify: false`.
    pub engine: EngineDisclosure,
    /// The pinned sampling parameters for the session (the family's
    /// `generation_params_hash` derives from these).
    pub sampling_params: SamplingParams,
    /// Presets this node serves (default: everything but `deep`).
    pub supported_presets: Vec<Preset>,
    /// The node's budget CEILING — the effective budget is the offer
    /// clamped DOWN by this, never up.
    pub budget_ceiling: SessionBudget,
    /// The minimum budget the node considers feasible; an offer below it
    /// (or with any zero field) is `budget_infeasible`.
    pub budget_floor: SessionBudget,
    /// ADR-026 lease expiry for this session (unix ms) — the gate's stage-5
    /// lease check (`expired_token`). The composed daemon derives this from
    /// the lease the coordinator presented at session open.
    pub lease_expires_at_ms: u64,
    /// Pin a specific coordinator key instead of deriving it from the
    /// transport-authenticated remote PeerId (roster policy / test pinning).
    /// `None` (production default): derive from the authenticated peer.
    pub pinned_coordinator_key: Option<VerifyingKey>,
    /// ADR-036 §3.2: this peer's user-content carriage posture for
    /// session-open pin carriers — DEFAULT [`ContentCarriage::On`] (the
    /// owner's default-on directive). `Off` refuses a carrier with the
    /// honest `content_carriage_refused` reject; the neutral family
    /// (carrier-less sessions) is NOT affected by this field.
    pub content_carriage: ContentCarriage,
    /// ADR-036 §3.2: this peer's session-level prefill bound — a carrier
    /// whose `prompt_tokens` length exceeds it is refused
    /// `budget_infeasible` ("conversation does not fit this peer"),
    /// honestly, never silently degraded. `None` = no session-level bound
    /// is known locally; the ADR-035 governor's machine-level verdict (the
    /// D11 70% ceiling, evaluated at hosting start and owning admission)
    /// remains the enforcement authority either way.
    pub prefill_context_tokens: Option<u64>,
    /// Idle timeout before a silent session ends.
    pub session_idle: Duration,
    /// Per-frame I/O deadline.
    pub io_deadline: Duration,
}

impl VerifyDraftsServeConfig {
    /// The honest node defaults for a peer whose engine cannot
    /// batch-verify: HTTP-adapter disclosure (CPU backend — ADR-024's
    /// default engine class), default integral sampling parameters, all
    /// lossless presets, and a 10-minute session ceiling.
    pub fn honest(profile_id: String, verifier_identity: InstallationIdentity) -> Self {
        Self {
            profile_id,
            verifier_identity,
            engine: http_adapter_disclosure(Backend::Cpu),
            sampling_params: SamplingParams::default(),
            supported_presets: default_supported_presets(),
            budget_ceiling: SessionBudget {
                max_endpoints: 8,
                max_endpoint_seconds: 600,
                max_output_tokens: 4096,
            },
            budget_floor: SessionBudget {
                max_endpoints: 1,
                max_endpoint_seconds: 1,
                max_output_tokens: 1,
            },
            lease_expires_at_ms: u64::MAX,
            pinned_coordinator_key: None,
            // ADR-036 §3.1: carriage of other users' conversations through
            // family verification is ON by default (the owner directive
            // 2026-10-13); the desktop's persisted setting flows in here.
            content_carriage: ContentCarriage::On,
            prefill_context_tokens: None,
            session_idle: FAMILY_SESSION_IDLE,
            io_deadline: FAMILY_IO_DEADLINE,
        }
    }

    /// Fails fast on internally inconsistent settings (floor above
    /// ceiling, or an invalid disclosure — both would otherwise surface
    /// mid-session).
    pub fn validate(&self) -> Result<(), String> {
        if !self.engine.is_valid_disclosure() {
            return Err(
                "engine disclosure invalid (batch_window_max out of 1..=WINDOW_CAP)".to_string(),
            );
        }
        if self.budget_floor.max_endpoints > self.budget_ceiling.max_endpoints
            || self.budget_floor.max_endpoint_seconds > self.budget_ceiling.max_endpoint_seconds
            || self.budget_floor.max_output_tokens > self.budget_ceiling.max_output_tokens
        {
            return Err("budget floor exceeds the ceiling".to_string());
        }
        Ok(())
    }
}

/// Summary of one served session (counts, hashes, and the end reason —
/// never token ids).
#[derive(Debug, Clone)]
pub struct VerifyDraftsServeReport {
    /// The negotiated session id.
    pub session_id: String,
    /// The authenticated remote PeerId (the coordinator).
    pub remote_peer_id: String,
    /// Whether an offer was accepted at all (false = rejected/failed
    /// before the accept).
    pub accepted: bool,
    /// The last HANDLED round number — advances only when a round is
    /// admitted; gaps forward after abandonment (RC-5(c)); stays put on
    /// pre-admission rejects.
    pub rounds_handled: u64,
    /// The last COMMITTED round number (0 = genesis; round numbers may gap
    /// after abandonment, I3/RC-5(c)).
    pub rounds_committed: u64,
    /// Cumulative committed output tokens (the §8e ledger).
    pub committed_output_tokens: u64,
    /// The committed prefix hash at session end.
    pub committed_prefix_hash: String,
    /// Cumulative served session milliseconds (the seconds ledger, RC-2).
    pub served_session_ms: u64,
    /// The gate's final state.
    pub state: GateState,
    /// Why the session ended.
    pub ended_by: ServeEndReason,
}

/// Sends an honest `SessionReject` best-effort (the reject is the last
/// frame on the session).
async fn send_reject<W: VerifyDraftsWire>(
    wire: &mut W,
    offer: &SessionOffer,
    reason: SessionRejectReason,
    io_deadline: Duration,
) {
    let reject = SessionReject {
        session_id: offer.session_id.clone(),
        protocol_version: offer.protocol_version.clone(),
        reason,
    };
    let value = serde_json::to_value(&reject).expect("session reject serializes");
    let _ = wire.send_json(&value, io_deadline).await;
}

/// Why [`read_session_open`] could not read the session-open exchange
/// (labels only — never lease or conversation contents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOpenError {
    /// The lease carrier arrived but failed its STRICT schema
    /// (`deny_unknown_fields`/type) — a malformed presented lease, mapped
    /// by the caller to the `invalid_lease` refusal classification.
    BadCarrier,
    /// The pin carrier arrived but failed its STRICT schema
    /// (`deny_unknown_fields`/types — ADR-036 §3.2's bad_frame class). The
    /// label names the structural fault family, never any content.
    BadPinCarrier(&'static str),
    /// A pin-carrier frame exceeded the msp-v1 §6.4 256 KiB frame limit —
    /// detected BEFORE parse (the transport class; ADR-036 §3.2 row 1).
    PayloadTooLarge,
    /// The fixed open order was violated (a lease carrier after the first
    /// frame, a pin carrier repeated, a lease behind a pin carrier —
    /// ADR-036 §3.2: "any other order is a `bad_frame`-class session
    /// end").
    OutOfOrder(&'static str),
    /// The carriers arrived but no `SessionOffer` followed within the
    /// open deadline.
    OfferTimeout,
    /// Transport failure reading the offer behind the carriers (label
    /// only).
    Wire(&'static str),
}

impl SessionOpenError {
    /// Stable telemetry label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BadCarrier => "bad_lease_carrier",
            Self::BadPinCarrier(_) => "bad_pin_carrier",
            Self::PayloadTooLarge => "payload_too_large",
            Self::OutOfOrder(_) => "open_order_violation",
            Self::OfferTimeout => "offer_timeout",
            Self::Wire(_) => "wire_failure",
        }
    }
}

impl std::fmt::Display for SessionOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadCarrier => write!(f, "lease carrier failed its strict schema"),
            Self::BadPinCarrier(why) => {
                write!(f, "pin carrier failed its strict schema: {why}")
            }
            Self::PayloadTooLarge => {
                write!(
                    f,
                    "pin carrier exceeded the 256 KiB frame limit before parse"
                )
            }
            Self::OutOfOrder(why) => write!(f, "session-open order violation: {why}"),
            Self::OfferTimeout => write!(f, "no session offer behind the carriers"),
            Self::Wire(what) => write!(f, "transport failure: {what}"),
        }
    }
}

/// The read session-open exchange (ADR-036 §3.2, the fixed order):
/// `[lease carrier]? → [pin carrier]? → SessionOffer`. Both carriers are
/// STRICT-parsed here (the reader only routes, never decides admission —
/// that is [`admit_pin_carrier`]'s table); the offer stays UNPARSED for
/// the serve loop, handed pre-read through [`super::wire::PrefacedWire`].
#[derive(Debug, Clone)]
pub struct SessionOpen {
    /// The PRESENTED lease token (the `WireSessionLease` carrier's
    /// unchanged string); `None` when the coordinator opened offer-first
    /// or pin-first (a pin carrier without a lease is valid — roster-fed
    /// coordinators).
    pub lease: Option<String>,
    /// The STRICT-parsed ADR-036 pin carrier, when one was presented;
    /// `None` = a NEUTRAL session (the existing path, byte-unchanged).
    pub pin: Option<WirePinCarrier>,
    /// The raw, unparsed `SessionOffer` frame.
    pub offer: Value,
}

/// The pin carrier's discriminant keys (ADR-036 §4 disjointness: both are
/// disjoint from every frozen §6 tag and every existing family
/// discriminant key, pinned by the session crate's collision test).
fn is_pin_carrier_frame(value: &Value) -> bool {
    value.get("pin_commitment").is_some() && value.get("prompt_tokens").is_some()
}

/// Serialized frame length (the gate's stage-1 measure), saturating on a
/// serialization failure.
fn frame_len(value: &Value) -> usize {
    serde_json::to_string(value).map_or(usize::MAX, |s| s.len())
}

/// Reads the family SESSION-OPEN exchange from an already-read FIRST
/// frame (ADR-032 §2 admission order, wired 2026-10-12; EXTENDED by
/// ADR-036 §3.2 to the fixed three-part order): the coordinator PRESENTS
/// its consume lease in the minimal [`WireSessionLease`] carrier FIRST,
/// then — when the session is an ELECTED family-verified chat — the
/// ADR-036 [`WirePinCarrier`] (the user's conversation as token ids plus
/// the rule-3 commitment), then the `SessionOffer`:
///
/// ```text
/// [lease carrier]?  →  [pin carrier]?  →  SessionOffer
/// ```
///
/// Valid shapes: lease→pin→offer, pin→offer (a pin carrier without a
/// lease is valid — roster-fed coordinators), lease→offer, offer (a
/// NEUTRAL session — the pre-ADR-036 path, byte-unchanged). Any other
/// order (a lease after the first frame, a repeated pin carrier, a lease
/// behind a pin carrier) is [`SessionOpenError::OutOfOrder`] — a
/// bad_frame-class session end. A pin-carrier frame over the 256 KiB
/// limit is [`SessionOpenError::PayloadTooLarge`] BEFORE parse (the
/// transport class; nothing content-sized is decoded).
///
/// This reader only routes, never decides: carrier admission (signature,
/// carriage posture, pairing, commitment binding) is
/// [`admit_pin_carrier`]'s first-failure table, run by the caller after
/// the lease gate.
pub async fn read_session_open<W: VerifyDraftsWire>(
    wire: &mut W,
    first: Value,
    offer_deadline: Duration,
) -> Result<SessionOpen, SessionOpenError> {
    // Position 1: the lease carrier, when presented; position 2 (the pin
    // carrier) is read from the pre-read first frame when the lease is
    // absent, else from the frame behind the lease.
    let (lease, pin_frame_or_offer) = if first.get("lease").is_some() {
        let carrier: super::WireSessionLease =
            serde_json::from_value(first).map_err(|_| SessionOpenError::BadCarrier)?;
        match wire.recv_json(offer_deadline).await {
            Ok(next) => {
                if next.get("lease").is_some() {
                    // A SECOND lease carrier: the lease is the FIRST
                    // frame of the open sequence or not at this position
                    // at all (ADR-036 §3.2: any other order is
                    // bad_frame-class).
                    return Err(SessionOpenError::OutOfOrder("lease carrier repeated"));
                }
                (Some(carrier.lease), next)
            }
            Err(WireError::Timeout) => return Err(SessionOpenError::OfferTimeout),
            Err(_) => return Err(SessionOpenError::Wire("recv frame behind lease carrier")),
        }
    } else {
        (None, first)
    };
    if is_pin_carrier_frame(&pin_frame_or_offer) {
        // Transport-class size gate BEFORE any parse of content-sized
        // frames (ADR-036 §3.2 row 1).
        if frame_len(&pin_frame_or_offer) > MAX_FRAME_BYTES {
            return Err(SessionOpenError::PayloadTooLarge);
        }
        let pin: WirePinCarrier = serde_json::from_value(pin_frame_or_offer)
            .map_err(|_| SessionOpenError::BadPinCarrier("schema"))?;
        let offer = match wire.recv_json(offer_deadline).await {
            Ok(value) => value,
            Err(WireError::Timeout) => return Err(SessionOpenError::OfferTimeout),
            Err(_) => return Err(SessionOpenError::Wire("recv offer behind pin carrier")),
        };
        if is_pin_carrier_frame(&offer) || offer.get("lease").is_some() {
            return Err(SessionOpenError::OutOfOrder(
                "carrier after the pin carrier (the offer must follow)",
            ));
        }
        return Ok(SessionOpen {
            lease,
            pin: Some(pin),
            offer,
        });
    }
    Ok(SessionOpen {
        lease,
        pin: None,
        offer: pin_frame_or_offer,
    })
}

/// The admitted ADR-036 pin carrier — the conversation root plus the
/// facts the serve loop seeds its gate with. `prompt_tokens` are CONTENT
/// (ADR-036 §3.2 hygiene): never logged, never telemetered, never echoed
/// in rejections or receipts; only their COUNT may appear in telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedPinCarrier {
    /// The carrier's session id (MUST equal the subsequent offer's; the
    /// serve loop enforces the binding — mismatch `bad_frame`).
    pub session_id: String,
    /// The conversation as token ids — the per-session PREFILLED root for
    /// the family engine (the F2 seam; torn down at session end, which
    /// bounds KV residency).
    pub prompt_tokens: Vec<u32>,
    /// The coordinator's seq baseline (RC-7): every later coordinator
    /// `VerifyDrafts` carries `seq` strictly greater — enforced by seeding
    /// the gate's `last_seq` with this value.
    pub seq: u64,
    /// The carrier's single-use nonce (I6): enters the session nonce
    /// ledger — any later frame reusing it is `replayed_request`.
    pub nonce: String,
    /// The coordinator's installation id (the `last_seq` key).
    pub sender: String,
    /// The CLAMPED open-phase deadline expiry (`arrival +
    /// clamp(deadline_ms, [1000, 120000])`); re-checked immediately
    /// before prefill dispatch (engine construction).
    pub deadline_expires_at_ms: u64,
}

/// [`admit_pin_carrier`]'s outcome (labels only — no content rides any
/// variant, per the ADR-036 hygiene rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinAdmission {
    /// Admitted: the carrier binds, the posture allows, the conversation
    /// fits — the caller constructs the per-session prefilled engine and
    /// seeds the serve loop's gate from the carried facts.
    Admitted(AdmittedPinCarrier),
    /// An honest `SessionReject` with the frozen reason (the caller sends
    /// it as the session's last frame): `content_carriage_refused` |
    /// `profile_mismatch` | `params_mismatch` | `pin_mismatch` |
    /// `budget_infeasible`.
    Rejected(SessionRejectReason),
    /// A bad_frame-class session end (schema/signature/sender faults) —
    /// no reject vocabulary exists; the label is local telemetry only.
    BadFrame(&'static str),
    /// The clamped open-phase deadline had already passed at admission.
    DeadlineExceeded,
}

/// The ADR-036 §3.2 admission table for the session-open pin carrier —
/// FIRST-FAILURE-WINS, in the ADR's row order:
///
/// 1. (frame size — `payload_too_large` — is enforced by
///    [`read_session_open`] BEFORE parse, the transport class);
/// 2. schema faults (strict parse already done by the reader; the pure
///    [`WirePinCarrier::validate`] core's labels) → [`PinAdmission::BadFrame`],
///    EXCEPT the commitment BIND, which is the `pin_mismatch` reject;
/// 3. signature invalid / `sender` not the authenticated key /
///    remote PeerId not derived from the pinned key → [`PinAdmission::BadFrame`];
/// 4. carriage setting OFF → reject `content_carriage_refused`;
/// 5. `profile_id` ≠ the pinned profile → reject `profile_mismatch`
///    (the G3 early close, now triggerable at the carrier);
/// 6. `generation_params_hash` ≠ the pinned params → reject
///    `params_mismatch`;
/// 7. `pin_commitment` ≠ `pin_commitment_of(prompt_tokens)` → reject
///    `pin_mismatch`;
/// 8. prefill infeasible (the session-level context bound; the ADR-035
///    governor owns the machine-level ceiling) → reject `budget_infeasible`;
/// 9. deadline past at admission (clamped `[1000, 120000]`) →
///    [`PinAdmission::DeadlineExceeded`].
///
/// Pure (injected clocks, no engine work) so the golden vectors and the
/// first-failure property pins replay it directly.
#[allow(clippy::too_many_arguments)]
pub fn admit_pin_carrier(
    carrier: &WirePinCarrier,
    remote_peer_id: &str,
    coordinator_key: &VerifyingKey,
    pinned_profile: &str,
    pinned_params_hash: &str,
    carriage: ContentCarriage,
    prefill_context_tokens: Option<u64>,
    arrival_ms: u64,
    now_ms: u64,
) -> PinAdmission {
    // Row 2 — schema: every pure-validate fault except the commitment
    // BIND is bad_frame class (the bind is row 7's honest reject).
    if let Err(fault) = carrier.validate() {
        if fault != PinCarrierError::CommitmentMismatch {
            return PinAdmission::BadFrame(fault.as_str());
        }
    }
    // Row 3 — authentication family: the coordinator key is pinned from
    // the transport-authenticated remote PeerId (or roster-pinned), and
    // the stream's peer MUST derive from that same key; the signature
    // verifies sender-binding-FIRST (§1 rule 5).
    if modelswarm_identity::peer_id_for(&coordinator_key.to_bytes()) != remote_peer_id {
        return PinAdmission::BadFrame("sender_not_authenticated_peer");
    }
    if verify_pin_carrier_signature(carrier, coordinator_key).is_err() {
        return PinAdmission::BadFrame("bad_signature");
    }
    // Row 4 — the carriage posture (before pairing checks: a refused peer
    // states its posture regardless of who asks).
    if carriage == ContentCarriage::Off {
        return PinAdmission::Rejected(SessionRejectReason::ContentCarriageRefused);
    }
    // Rows 5-6 — the G3 early close at the carrier.
    if carrier.profile_id != pinned_profile {
        return PinAdmission::Rejected(SessionRejectReason::ProfileMismatch);
    }
    if carrier.generation_params_hash != pinned_params_hash {
        return PinAdmission::Rejected(SessionRejectReason::ParamsMismatch);
    }
    // Row 7 — the commitment binds the payload.
    if !carrier.commitment_matches() {
        return PinAdmission::Rejected(SessionRejectReason::PinMismatch);
    }
    // Row 8 — prefill feasibility: the session-level context bound (the
    // machine-level ADR-035 governor verdict stays the authority at
    // hosting start).
    if let Some(cap) = prefill_context_tokens {
        if carrier.prompt_tokens.len() as u64 > cap {
            return PinAdmission::Rejected(SessionRejectReason::BudgetInfeasible);
        }
    }
    // Row 9 — the clamped open-phase deadline at admission.
    let clamped = carrier
        .deadline_ms
        .clamp(DEADLINE_CLAMP_MIN_MS, DEADLINE_CLAMP_MAX_MS);
    let deadline_expires_at_ms = arrival_ms.saturating_add(u64::from(clamped));
    if deadline_expires_at_ms <= now_ms {
        return PinAdmission::DeadlineExceeded;
    }
    PinAdmission::Admitted(AdmittedPinCarrier {
        session_id: carrier.session_id.clone(),
        prompt_tokens: carrier.prompt_tokens.clone(),
        seq: carrier.seq,
        nonce: carrier.nonce.clone(),
        sender: carrier.sender.clone(),
        deadline_expires_at_ms,
    })
}

/// Serves one NEUTRAL VerifyDrafts session (no ADR-036 carrier): the
/// pre-ADR-036 path, byte-unchanged — see [`serve_verifydrafts_session_with_pin`].
pub async fn serve_verifydrafts_session<W: VerifyDraftsWire>(
    wire: W,
    config: VerifyDraftsServeConfig,
    engine: Arc<dyn BatchVerifyEngine>,
    telemetry: &Telemetry,
) -> VerifyDraftsServeReport {
    serve_verifydrafts_session_with_pin(wire, config, engine, None, telemetry).await
}

/// Serves one VerifyDrafts session to its end and returns the report.
/// `pin` carries the ADMITTED ADR-036 pin carrier for a carrier session
/// (the conversation root + the gate-seeding facts — seq baseline, nonce
/// ledger); `None` serves a NEUTRAL session, byte-identically to the
/// pre-ADR-036 path.
///
/// Never panics on peer input: every malformed frame becomes a serialized
/// `RejectionFrame`/`CancelRoundFrame` or ends the session with a stable
/// code; peer-supplied payloads never reach telemetry (privacy rule 5;
/// ADR-036 §3.2 extends it to `prompt_tokens` — counts only, ever).
#[allow(clippy::too_many_lines)]
pub async fn serve_verifydrafts_session_with_pin<W: VerifyDraftsWire>(
    mut wire: W,
    config: VerifyDraftsServeConfig,
    engine: Arc<dyn BatchVerifyEngine>,
    pin: Option<AdmittedPinCarrier>,
    telemetry: &Telemetry,
) -> VerifyDraftsServeReport {
    let remote_peer_id = wire.remote_peer_id().to_string();
    let mut report = VerifyDraftsServeReport {
        session_id: String::new(),
        remote_peer_id: remote_peer_id.clone(),
        accepted: false,
        rounds_handled: 0,
        rounds_committed: 0,
        committed_output_tokens: 0,
        committed_prefix_hash: String::new(),
        served_session_ms: 0,
        state: GateState::Prefilled,
        ended_by: ServeEndReason::ClientClosed,
    };
    if let Err(why) = config.validate() {
        report.ended_by = ServeEndReason::Misconfigured(why);
        return report;
    }
    // The family's params hash must exist before any accept: non-integral
    // sampling parameters are unsignable (fail closed, nothing on the wire).
    let params_hash = match batch_generation_params_hash(&config.sampling_params) {
        Ok(hash) => hash,
        Err(why) => {
            report.ended_by = ServeEndReason::Misconfigured(why.to_string());
            return report;
        }
    };

    // -- Negotiation (ADR-032 §3) -----------------------------------------
    let offer: SessionOffer = match wire.recv_json(config.io_deadline).await {
        Ok(value) => match serde_json::from_value(value) {
            Ok(offer) => offer,
            Err(_) => {
                report.ended_by = ServeEndReason::BadOffer("offer failed schema");
                return report;
            }
        },
        Err(WireError::Timeout) => {
            report.ended_by = ServeEndReason::OfferTimeout;
            return report;
        }
        Err(_) => {
            report.ended_by = ServeEndReason::WireFailure { what: "recv offer" };
            return report;
        }
    };
    if offer.protocol_version != COOPERATIVE_PROTOCOL_VERSION {
        report.ended_by = ServeEndReason::BadOffer("protocol version");
        return report;
    }
    // ADR-036 §3.2: the carrier's `session_id` MUST equal the offer's —
    // mismatch is `bad_frame` (the session-open binding, enforced before
    // any accept).
    if let Some(pin) = &pin {
        if offer.session_id != pin.session_id {
            report.ended_by = ServeEndReason::BadOffer("carrier session id mismatch");
            return report;
        }
    }
    report.session_id = offer.session_id.clone();
    if !config.supported_presets.contains(&offer.preset) {
        send_reject(
            &mut wire,
            &offer,
            SessionRejectReason::PresetUnavailable,
            config.io_deadline,
        )
        .await;
        report.ended_by = ServeEndReason::RejectedOffer(SessionRejectReason::PresetUnavailable);
        telemetry.warn(
            "verifydrafts.offer_rejected",
            &[
                ("peer", remote_peer_id.as_str()),
                ("reason", "preset_unavailable"),
            ],
        );
        return report;
    }
    // Offer-form-v3 binding checks (ADR-032 revision 4 §3/G3): the offer
    // carries the coordinator's pinned `profile_id` and
    // `generation_params_hash`; the serving side compares BOTH against its
    // own pinned config and rejects honestly — the fail-closed gap the
    // wiring tier recorded (a params-mismatched pairing opened a session
    // that then failed EVERY round at stage 4 with no teardown and no
    // discovery; a profile mismatch was discoverable only at first round
    // plus teardown). Discovery, not trusted input: verifier-side pinning
    // (stage 4 params equality, stage 7 profile + teardown, §8
    // commit-time equality) remains the enforcement authority unchanged.
    // Order among negotiation rejects is this loop's choice (only one
    // fires); identity binding before capability pairing.
    if offer.profile_id != config.profile_id {
        send_reject(
            &mut wire,
            &offer,
            SessionRejectReason::ProfileMismatch,
            config.io_deadline,
        )
        .await;
        report.ended_by = ServeEndReason::RejectedOffer(SessionRejectReason::ProfileMismatch);
        telemetry.warn(
            "verifydrafts.offer_rejected",
            &[
                ("peer", remote_peer_id.as_str()),
                ("reason", "profile_mismatch"),
            ],
        );
        return report;
    }
    if offer.generation_params_hash != params_hash {
        send_reject(
            &mut wire,
            &offer,
            SessionRejectReason::ParamsMismatch,
            config.io_deadline,
        )
        .await;
        report.ended_by = ServeEndReason::RejectedOffer(SessionRejectReason::ParamsMismatch);
        telemetry.warn(
            "verifydrafts.offer_rejected",
            &[
                ("peer", remote_peer_id.as_str()),
                ("reason", "params_mismatch"),
            ],
        );
        return report;
    }
    // Backend pairing (E0: CPU ≠ Vulkan, never mixed) — the frozen honest
    // reject; the requester falls back to single, never silently.
    if offer.verifier_backend != config.engine.backend {
        send_reject(
            &mut wire,
            &offer,
            SessionRejectReason::BackendMismatch,
            config.io_deadline,
        )
        .await;
        report.ended_by = ServeEndReason::RejectedOffer(SessionRejectReason::BackendMismatch);
        telemetry.warn(
            "verifydrafts.offer_rejected",
            &[
                ("peer", remote_peer_id.as_str()),
                ("reason", "backend_mismatch"),
            ],
        );
        return report;
    }
    // Budget: clamped DOWN by the ceiling; below the floor (or any hostile
    // zero field) is honestly infeasible.
    let effective = clamp_budget_down(&offer.budget, &config.budget_ceiling);
    if effective.max_endpoints < config.budget_floor.max_endpoints
        || effective.max_endpoint_seconds < config.budget_floor.max_endpoint_seconds
        || effective.max_output_tokens < config.budget_floor.max_output_tokens
    {
        send_reject(
            &mut wire,
            &offer,
            SessionRejectReason::BudgetInfeasible,
            config.io_deadline,
        )
        .await;
        report.ended_by = ServeEndReason::RejectedOffer(SessionRejectReason::BudgetInfeasible);
        telemetry.warn(
            "verifydrafts.offer_rejected",
            &[
                ("peer", remote_peer_id.as_str()),
                ("reason", "budget_infeasible"),
            ],
        );
        return report;
    }
    // The coordinator key is PINNED from the transport-authenticated remote
    // PeerId (RC-1): every VerifyDrafts signature verifies under exactly
    // this key, and the gate independently re-checks that the stream's
    // remote PeerId derives from it before any admission stage runs.
    let coordinator_key = match config.pinned_coordinator_key {
        Some(pinned) => pinned,
        None => match verifying_key_from_peer_id(&remote_peer_id) {
            Ok(key) => key,
            Err(why) => {
                // Not an offer defect and no frozen reject reason exists —
                // end before the accept, honestly.
                report.ended_by = ServeEndReason::Misconfigured(why);
                return report;
            }
        },
    };
    let accept = SessionAccept {
        session_id: offer.session_id.clone(),
        protocol_version: offer.protocol_version.clone(),
        preset: offer.preset,
        budget: effective.clone(),
        engine: config.engine.clone(),
    };
    let accept_value = serde_json::to_value(&accept).expect("session accept serializes");
    if wire
        .send_json(&accept_value, config.io_deadline)
        .await
        .is_err()
    {
        report.ended_by = ServeEndReason::WireFailure {
            what: "send accept",
        };
        return report;
    }
    report.accepted = true;
    telemetry.info(
        "verifydrafts.offer_accepted",
        &[
            ("peer", remote_peer_id.as_str()),
            ("preset", offer.preset.as_str()),
            ("batch_verify", &config.engine.batch_verify.to_string()),
        ],
    );

    // -- The gate (§8 state machine) ---------------------------------------
    let mut gate = match VerifyDraftsGate::new(VerifyDraftsGateConfig {
        session_id: offer.session_id.clone(),
        profile_id: config.profile_id.clone(),
        generation_params_hash: params_hash,
        committed_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        coordinator_key,
        verifier_installation_id: config.verifier_identity.installation_id(),
        engine: config.engine.clone(),
        budget: effective,
        lease_expires_at_ms: config.lease_expires_at_ms,
        sampling_params: config.sampling_params,
        verifier_next_seq: 1,
    }) {
        Ok(gate) => gate,
        Err(why) => {
            report.ended_by = ServeEndReason::Misconfigured(why.to_string());
            return report;
        }
    };
    // ADR-036 §3.2 carrier seeding: the coordinator's seq baseline (every
    // later `VerifyDrafts` strictly greater — RC-7) and the carrier's
    // single-use nonce in the session ledger (reuse → `replayed_request`
    // — I6). Rounds were already ≥ 1-only by construction (round 0 is
    // `round_mismatch` at stage 8); the carrier's own `round: 0` is the
    // session-open marker that monotonicity includes.
    if let Some(pin) = &pin {
        gate.seed_pre_state(GatePreStateSeed {
            last_seq: vec![(pin.sender.clone(), pin.seq)],
            consumed_nonces: vec![pin.nonce.clone()],
            ..GatePreStateSeed::default()
        });
    }

    // RC-2: measure the exact engine-pass wall time around the engine call
    // (the gate trait is clock-free and takes caller-supplied clocks, so
    // the pass duration is sampled by this wrapper and written into the
    // signed draft — see the handoff's RC-2 mapping).
    let pass_timing = Arc::new(PassTiming::default());
    let timed_engine = TimingEngine {
        inner: Arc::clone(&engine),
        timing: Arc::clone(&pass_timing),
    };

    let session_id = offer.session_id.clone();
    let ctx = RoundCtx {
        remote_peer_id: remote_peer_id.as_str(),
        timed_engine: &timed_engine,
        pass_timing: &pass_timing,
        config: &config,
        telemetry,
        session_id: session_id.as_str(),
    };
    let mut last_tick = Instant::now();
    let mut last_activity = Instant::now();
    let ended_by: ServeEndReason = loop {
        let now_ms = unix_ms_now();
        // RC-2 seconds ledger: cumulative session wall-clock deltas (§8e —
        // the session holds the serving slot for exactly this long).
        gate.advance_session_seconds(last_tick.elapsed().as_millis() as u64);
        last_tick = Instant::now();
        // RC-5(b) WAIT_COMMIT expiry polling: abandon a round whose
        // deadline + 250 ms grace passed; the verifier never holds an
        // uncommitted round for a vanished coordinator.
        if let Some(round) = gate.outstanding_round() {
            if gate.expire_wait_commit_if_due(now_ms) {
                telemetry.info(
                    "verifydrafts.round_expired",
                    &[
                        ("session", session_id.as_str()),
                        ("round", &round.to_string()),
                    ],
                );
            }
        }
        if gate.is_torn_down() {
            break ServeEndReason::TornDown {
                reason: gate.teardown_reason().unwrap_or("unknown").to_string(),
            };
        }
        if gate.outstanding_round().is_none() && last_activity.elapsed() >= config.session_idle {
            break ServeEndReason::IdleTimeout;
        }
        // Next wake: the outstanding round's WAIT_COMMIT bound, else the
        // idle timeout. A recv timeout is a pure wake-up (the wire port
        // keeps the session open).
        let deadline = match gate.outstanding_deadline_expires_at_ms() {
            Some(expiry) => Duration::from_millis(
                expiry
                    .saturating_sub(now_ms)
                    .saturating_add(WAIT_COMMIT_GRACE_MS)
                    .max(1),
            ),
            None => config
                .session_idle
                .saturating_sub(last_activity.elapsed())
                .max(Duration::from_millis(1)),
        };
        let frame = match wire.recv_json(deadline).await {
            Ok(value) => value,
            Err(WireError::Timeout) => continue, // re-evaluate expiry/idle
            Err(why) => {
                // Any terminal recv loss means the peer is gone (the staged
                // backend surfaces a vanished peer as an I/O error, not
                // `Closed`); the honest label is the client-closed teardown.
                if let WireError::Io(what) = &why {
                    telemetry.warn(
                        "verifydrafts.wire_failure",
                        &[("session", session_id.as_str()), ("what", what)],
                    );
                }
                break ServeEndReason::ClientClosed;
            }
        };
        last_activity = Instant::now();
        match demux_family_frame(&frame) {
            FamilyFrame::Request => {
                match handle_request(&mut wire, &mut gate, &frame, &ctx).await {
                    Ok(()) => {}
                    Err(reason) => break reason,
                }
            }
            FamilyFrame::Commit => {
                // §2 carrier (ADR-032 revision 4 §2/G2): STRICT parse at
                // the carrier's entry — unknown fields and wrong types
                // fail deserialization (`deny_unknown_fields`), non-bare-
                // hex hashes fail the strict-schema form check — every
                // failure is `bad_frame` BEFORE the gate (and any state)
                // is touched.
                let commit: CommitPrefix =
                    match serde_json::from_value::<super::WirePrefixCommit>(frame) {
                        Ok(wire_commit) if wire_commit.passes_strict_carrier_schema() => {
                            CommitPrefix::from(wire_commit)
                        }
                        _ => {
                            let rejection = RejectionFrame {
                                session_id: session_id.clone(),
                                code: FrameRejectReason::BadFrame,
                                round: None,
                                prefix_hash: Some(gate.committed_prefix_hash().to_string()),
                            };
                            if send_serialized(&mut wire, &rejection, config.io_deadline)
                                .await
                                .is_err()
                            {
                                break ServeEndReason::WireFailure {
                                    what: "send rejection",
                                };
                            }
                            continue;
                        }
                    };
                match gate.apply_prefix_commit(&commit) {
                    CommitApplyOutcome::Advanced { round } => {
                        telemetry.info(
                            "verifydrafts.round_committed",
                            &[
                                ("session", session_id.as_str()),
                                ("round", &round.to_string()),
                                ("tokens", &commit.accepted_token_ids.len().to_string()),
                            ],
                        );
                    }
                    CommitApplyOutcome::DuplicateRound => {}
                    CommitApplyOutcome::CancelRound(cancel) => {
                        if send_serialized(&mut wire, &cancel, config.io_deadline)
                            .await
                            .is_err()
                        {
                            break ServeEndReason::WireFailure {
                                what: "send cancel_round",
                            };
                        }
                    }
                    CommitApplyOutcome::FrameRejected(rejection) => {
                        if send_serialized(&mut wire, &rejection, config.io_deadline)
                            .await
                            .is_err()
                        {
                            break ServeEndReason::WireFailure {
                                what: "send rejection",
                            };
                        }
                    }
                }
                if gate.is_torn_down() {
                    break ServeEndReason::TornDown {
                        reason: gate.teardown_reason().unwrap_or("unknown").to_string(),
                    };
                }
            }
            FamilyFrame::Unknown => {
                telemetry.warn(
                    "verifydrafts.unexpected_frame",
                    &[("session", session_id.as_str())],
                );
                break ServeEndReason::UnexpectedFrame("no such family message");
            }
        }
    };

    report.rounds_handled = gate.last_handled_round();
    report.rounds_committed = gate.last_committed_round();
    report.committed_output_tokens = gate.committed_output_tokens();
    report.committed_prefix_hash = gate.committed_prefix_hash().to_string();
    report.served_session_ms = gate.served_session_ms();
    report.state = gate.state();
    telemetry.info(
        "verifydrafts.session_ended",
        &[
            ("session", session_id.as_str()),
            ("reason", ended_by.as_str()),
            ("rounds", &report.rounds_committed.to_string()),
            ("tokens", &report.committed_output_tokens.to_string()),
        ],
    );
    report.ended_by = ended_by;
    report
}

/// The QUIC venue for the family (the light-up handoff's G1 follow-up):
/// accepts VerifyDrafts sessions on a REAL libp2p QUIC listener and serves
/// each to its end — the parallel of the msp-v1 bridge's `serve_sessions`
/// (`crate::serving`, untouched by design; when the family goes live the
/// composed daemon demuxes there). The lifecycle contract mirrors that
/// bridge exactly: stop when `shutdown` flips true OR its watch sender is
/// dropped.
///
/// Admission note (honest limitation): the msp-v1 bridge's session/per-peer
/// `Admission` lives behind the node `libp2p-backend` feature and is not
/// reused here; per-connection admission control for this venue lives in
/// the composed daemon wiring (`super::composed::serve_sessions_composed`
/// — one listener, both vocabularies, one admission gate, the ADR-026
/// lease seam applied to both paths).
pub async fn serve_verifydrafts_quic(
    mut listener: Libp2pListener,
    config: VerifyDraftsServeConfig,
    engine: Arc<dyn BatchVerifyEngine>,
    telemetry: Arc<Telemetry>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        let session = tokio::select! {
            // The same semantics as the msp-v1 bridge: a CLOSED watch channel
            // (every Sender dropped) must ALSO stop serving — nobody can ever
            // signal stop otherwise, and a permanently-ready branch would
            // cancel every in-flight accept.
            changed = shutdown.changed() => match changed {
                Err(_) => {
                    telemetry.warn(
                        "verifydrafts.serve_stopped",
                        &[("reason", "shutdown_sender_dropped")],
                    );
                    return;
                }
                Ok(()) => {
                    if *shutdown.borrow() {
                        telemetry
                            .info("verifydrafts.serve_stopped", &[("reason", "shutdown_signal")]);
                        return;
                    }
                    continue;
                }
            },
            accepted = listener.accept(Duration::from_secs(1)) => match accepted {
                Ok(s) => s,
                Err(_) => continue, // timeout/accept miss: keep serving
            },
        };
        let session_config = config.clone();
        let session_engine = Arc::clone(&engine);
        let session_telemetry = Arc::clone(&telemetry);
        tokio::spawn(async move {
            let wire = super::wire::QuicVerifyWire::over_session(session);
            // The report's end reason is telemetered inside the serve loop
            // (`verifydrafts.session_ended`); per-session counts stay local.
            let _report = serve_verifydrafts_session(
                wire,
                session_config,
                session_engine,
                &session_telemetry,
            )
            .await;
        });
    }
}

/// Per-round operational context for [`handle_request`] (the §8
/// obligations that live at the serve loop, not inside the gate).
struct RoundCtx<'a> {
    remote_peer_id: &'a str,
    timed_engine: &'a TimingEngine,
    pass_timing: &'a PassTiming,
    config: &'a VerifyDraftsServeConfig,
    telemetry: &'a Telemetry,
    session_id: &'a str,
}

/// Admits one `VerifyDrafts`, runs the ONE engine pass, signs the draft
/// (RC-2), and sends the result; rejections serialize as
/// `RejectionFrame`/`CancelRoundFrame`.
///
/// `Err` carries the reason the whole session must end; `Ok(())` keeps the
/// loop alive.
#[allow(clippy::too_many_lines)]
async fn handle_request<W: VerifyDraftsWire>(
    wire: &mut W,
    gate: &mut VerifyDraftsGate,
    frame: &Value,
    ctx: &RoundCtx<'_>,
) -> Result<(), ServeEndReason> {
    let RoundCtx {
        remote_peer_id,
        timed_engine,
        pass_timing,
        config,
        telemetry,
        session_id,
    } = *ctx;
    // The two clocks coincide here (no queue between recv and admission);
    // the ADR's arrival/now split exists for queued frames.
    let arrival = unix_ms_now();
    match gate.admit_verify_drafts(frame, arrival, arrival, remote_peer_id) {
        AdmissionDecision::Admitted { round, .. } => {
            telemetry.info(
                "verifydrafts.round_admitted",
                &[("session", session_id), ("round", &round.to_string())],
            );
            // Stage-13 deadline re-check happens inside dispatch with the
            // pre-dispatch clock (post-queue-wait semantics, A-2).
            let pre_dispatch = unix_ms_now();
            pass_timing.reset();
            match gate
                .dispatch_outstanding(timed_engine, pre_dispatch, pre_dispatch)
                .await
            {
                DispatchOutcome::Dispatched(mut draft) => {
                    // RC-2: the gate is clock-free by design, so the serve
                    // loop supplies the MEASURED engine-pass wall time and
                    // SIGNS the draft with the verifier identity.
                    draft.verify_pass_ms = pass_timing.measured_pass_ms();
                    draft.signature =
                        match sign_verify_drafts_result(&draft, &config.verifier_identity) {
                            Ok(signature) => signature,
                            Err(why) => {
                                // Unsignable draft = local fault; nothing
                                // honest can be sent for this round.
                                telemetry.error(
                                    "verifydrafts.sign_failed",
                                    &[("session", session_id), ("why", &why.to_string())],
                                );
                                return Err(ServeEndReason::EngineError("sign_failed"));
                            }
                        };
                    telemetry.info(
                        "verifydrafts.round_verified",
                        &[
                            ("session", session_id),
                            ("round", &draft.round.to_string()),
                            ("accepted_len", &draft.accepted_prefix_len.to_string()),
                            ("verify_pass_ms", &draft.verify_pass_ms.to_string()),
                        ],
                    );
                    let value = serde_json::to_value(&draft).expect("result serializes");
                    wire.send_json(&value, config.io_deadline)
                        .await
                        .map_err(|_| ServeEndReason::WireFailure {
                            what: "send result",
                        })?;
                    Ok(())
                }
                DispatchOutcome::DeadlineExceeded => {
                    // The round is abandoned; the honest wire answer is the
                    // frame-level code (a COUNT for the round, never tokens).
                    let rejection = RejectionFrame {
                        session_id: session_id.to_string(),
                        code: FrameRejectReason::DeadlineExceeded,
                        round: Some(round),
                        prefix_hash: Some(gate.committed_prefix_hash().to_string()),
                    };
                    send_serialized(wire, &rejection, config.io_deadline)
                        .await
                        .map_err(|_| ServeEndReason::WireFailure {
                            what: "send rejection",
                        })?;
                    Ok(())
                }
                DispatchOutcome::EngineFailed(err) => {
                    // Not a wire code (ADR-032 §8: the serve loop decides
                    // the honest stream outcome) — end the session with a
                    // stable local label; engine detail stays local.
                    telemetry.error(
                        "verifydrafts.engine_failed",
                        &[("session", session_id), ("kind", engine_error_label(&err))],
                    );
                    Err(ServeEndReason::EngineError(engine_error_label(&err)))
                }
                DispatchOutcome::NoOutstandingRound => Ok(()),
            }
        }
        AdmissionDecision::FrameRejected(rejection) => {
            // Codes, counts, hashes only (privacy rule 5 / A-3). A
            // teardown-family code ends the session after best-effort send.
            if let Some(code) = terminal_frame_code(rejection.code) {
                let _ = send_serialized(wire, &rejection, config.io_deadline).await;
                return Err(ServeEndReason::FrameRejected { code });
            }
            send_serialized(wire, &rejection, config.io_deadline)
                .await
                .map_err(|_| ServeEndReason::WireFailure {
                    what: "send rejection",
                })?;
            Ok(())
        }
        AdmissionDecision::CancelRound(cancel) => {
            send_serialized(wire, &cancel, config.io_deadline)
                .await
                .map_err(|_| ServeEndReason::WireFailure {
                    what: "send cancel_round",
                })?;
            Ok(())
        }
    }
}

/// Serializes and sends one already-decided frame (rejections/cancels carry
/// codes, counts, and hashes only by construction).
async fn send_serialized<W: VerifyDraftsWire, T: serde::Serialize>(
    wire: &mut W,
    frame: &T,
    io_deadline: Duration,
) -> Result<(), ()> {
    let value = serde_json::to_value(frame).map_err(|_| ())?;
    wire.send_json(&value, io_deadline).await.map_err(|_| ())
}

/// Frame-level codes that end the session when sent (teardown family).
fn terminal_frame_code(code: FrameRejectReason) -> Option<FrameRejectReason> {
    match code {
        FrameRejectReason::ProfileMismatch | FrameRejectReason::CancelledByPeer => Some(code),
        _ => None,
    }
}

/// Stable local label for an engine failure (never the error payload).
fn engine_error_label(err: &RuntimeError) -> &'static str {
    match err {
        RuntimeError::Unsupported(_) => "engine_unsupported",
        RuntimeError::Http(_) => "engine_http",
        RuntimeError::Timeout { .. } => "engine_timeout",
        RuntimeError::Api { .. } => "engine_api",
        RuntimeError::MalformedResponse(_) => "engine_malformed",
        RuntimeError::InvalidProfile(_) => "engine_profile",
        RuntimeError::TokenOutOfRange(_) => "engine_token_range",
        RuntimeError::Cancelled(_) => "engine_cancelled",
        RuntimeError::NotLoaded(_) => "engine_not_loaded",
        RuntimeError::InvalidDescriptor(_) => "engine_descriptor",
    }
}

/// Shared engine-pass timing (sampled by [`TimingEngine`], read by the
/// serve loop after the dispatch await).
#[derive(Default)]
struct PassTiming {
    start_ms: AtomicU64,
    end_ms: AtomicU64,
}

impl PassTiming {
    fn reset(&self) {
        self.start_ms.store(0, Ordering::SeqCst);
        self.end_ms.store(0, Ordering::SeqCst);
    }
    fn measured_pass_ms(&self) -> u32 {
        let (start, end) = (
            self.start_ms.load(Ordering::SeqCst),
            self.end_ms.load(Ordering::SeqCst),
        );
        if end >= start && start > 0 {
            u32::try_from(end - start).unwrap_or(u32::MAX)
        } else {
            0
        }
    }
}

/// [`BatchVerifyEngine`] wrapper that samples the exact engine-pass wall
/// time (RC-2: `verify_pass_ms` is the MEASURED pass; the gate's
/// clock-free trait takes caller-supplied clocks, so the wrapper is the
/// honest way to measure what the gate cannot — see the handoff).
struct TimingEngine {
    inner: Arc<dyn BatchVerifyEngine>,
    timing: Arc<PassTiming>,
}

#[async_trait::async_trait]
impl BatchVerifyEngine for TimingEngine {
    async fn verify_window(
        &self,
        window: &[u32],
        params: &SamplingParams,
    ) -> Result<(u32, Option<u32>), RuntimeError> {
        self.timing.start_ms.store(unix_ms_now(), Ordering::SeqCst);
        let result = self.inner.verify_window(window, params).await;
        self.timing.end_ms.store(unix_ms_now(), Ordering::SeqCst);
        result
    }

    fn capabilities(&self) -> EngineDisclosure {
        self.inner.capabilities()
    }
}
