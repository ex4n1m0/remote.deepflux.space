//! The composed daemon: ONE QUIC listener serving BOTH session
//! vocabularies (feature combination `verifydrafts` + `libp2p-backend`;
//! the light-up handoff's composed-daemon seam, closed here).
//!
//! [`serve_sessions_composed`] is the msp-v1 bridge
//! ([`crate::serving::serve_sessions`]) with the VerifyDrafts family
//! demultiplexed in behind the SAME listener, the SAME session admission
//! (serving.rs's `Admission`: total + per-peer session caps — one gate
//! for both vocabularies), and the SAME ADR-026 lease discipline:
//!
//! - **msp-v1 sessions** (typed `WireMessage` frames): the unchanged
//!   [`crate::serving::serve_one`] loop — per-request hub-signed lease
//!   check (`LeasePolicy`), §6.4 clamps, executor streaming;
//! - **family sessions** (raw-JSON ADR-032 frames): the unchanged
//!   [`super::serve::serve_verifydrafts_session`] loop, with the
//!   coordinator's lease checked AT SESSION OPEN (ADR-032 §2 admission
//!   order — session/lease gate passed at open, wired 2026-10-12): the
//!   coordinator PRESENTS its hub-signed lease in the minimal
//!   session-open carrier immediately before its `SessionOffer`
//!   ([`super::serve::read_session_open`]), and the presented token is
//!   validated against the SERVED profile through the
//!   [`FamilyLeaseSource`] seam with every binding the msp-v1
//!   per-request gate enforces (fail-closed: no valid lease ⇒ no family
//!   session).
//!
//!   Since the RC-L1 discharge (ADR-032 §7 disposition item i,
//!   2026-10-12) the seam is PROFILE-bound: [`RosterFamilyLeases`]
//!   validates the coordinator's lease against the SERVED profile with
//!   every binding the msp-v1 per-request gate enforces
//!   ([`FamilyLeaseRefusal`] mirrors its classification), and accepts
//!   the lease from either of two sources with ONE validation engine:
//!   the tracker-fed ROSTER entry (the future distribution path) or the
//!   PRESENTED carrier token (the msp-v1-equivalent discipline that
//!   makes two fresh desktops with earned leases able to pair today).
//!
//! # Demux
//!
//! A session's vocabulary is classified by its FIRST frame, with zero
//! added latency for msp-v1 sessions: the loop awaits a TYPED frame
//! (1 s polls inside the between-requests budget); a typed frame returns
//! immediately, while a raw family frame is STASHED by the typed recv and
//! picked up by a 1 ms raw recv (the transport's stash discipline — stash
//! first, never hidden behind an expired deadline). The peeked frame is
//! handed to the winning serve path pre-read ([`crate::serving::serve_one_seeded`]
//! / [`PrefacedQuicWire`]) — never decoded twice.
//!
//! Default builds (the feature combination off) keep today's
//! single-vocabulary `serve_sessions` byte-identically; this module is
//! additive.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use modelswarm_eligibility::EligibilityLease;
use modelswarm_gateway::InferenceExecutor;
use modelswarm_telemetry::Telemetry;
use modelswarm_transport::libp2p_backend::Libp2pSession;
use modelswarm_transport::message::WireMessage;
use modelswarm_transport::TransportError;

use crate::serving::{rfc3339_now, send_error, serve_one_seeded, Admission, LeasePolicy};

use super::engine_source::FamilyEngineSource;
use super::serve::{
    admit_pin_carrier, read_session_open, serve_verifydrafts_session_with_pin, PinAdmission,
    SessionOpen, SessionOpenError, VerifyDraftsServeConfig,
};
use super::wire::{PrefacedWire, QuicVerifyWire};
use super::{unix_ms_now, verifying_key_from_peer_id};

/// Sends the honest `SessionReject` for a refused pin carrier (the last
/// frame on the session; codes only — the carrier's session id and
/// protocol version are echoed, never its content).
async fn send_pin_reject<W: super::wire::VerifyDraftsWire>(
    wire: &mut W,
    carrier: &modelswarm_session::negotiation::WirePinCarrier,
    reason: modelswarm_session::negotiation::SessionRejectReason,
    io_deadline: std::time::Duration,
) {
    let reject = modelswarm_session::negotiation::SessionReject {
        session_id: carrier.session_id.clone(),
        protocol_version: carrier.protocol_version.clone(),
        reason,
    };
    let value = serde_json::to_value(&reject).expect("session reject serializes");
    let _ = wire.send_json(&value, io_deadline).await;
}

/// How long a composed session may wait for its FIRST frame (mirrors the
/// msp-v1 loop's between-requests wait — both vocabularies get the same
/// session treatment).
const FIRST_FRAME_IDLE: Duration = Duration::from_secs(300);

/// The typed-recv poll inside the first-frame wait (raw family frames are
/// stashed by the typed recv and collected on the next poll boundary —
/// bounded classification latency for family sessions, zero for msp-v1).
const DEMUX_POLL: Duration = Duration::from_secs(1);

/// Why a family session was refused at the composed daemon's ADR-026
/// lease gate. One variant per binding the msp-v1 per-request check
/// enforces (`crate::serving::LeasePolicy::check`, RC-L1): a lease that
/// fails ANY binding refuses the family session, classified exactly like
/// that gate classifies it. Labels only — lease contents never reach
/// telemetry (privacy rule 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyLeaseRefusal {
    /// No lease is on file for the authenticated coordinator (the msp-v1
    /// gate's "no lease presented").
    NoLease,
    /// The lease failed decoding or hub verification — signature,
    /// profile-id form, expiry/freshness beyond the ±120 s skew, or the
    /// lease cap (that gate's "bad lease" / "lease invalid" family).
    InvalidLease,
    /// The lease names another profile than the one this daemon serves
    /// ("lease is for another profile").
    ProfileMismatch,
    /// `can_consume` is false or `slots` is zero ("lease grants no
    /// consume right").
    NoConsumeRight,
    /// The lease is bound to a different peer than the transport
    /// authenticated ("lease is not bound to this peer").
    PeerMismatch,
}

impl FamilyLeaseRefusal {
    /// Stable telemetry label for the refusal (ids/codes only).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoLease => "no_lease",
            Self::InvalidLease => "invalid_lease",
            Self::ProfileMismatch => "profile_mismatch",
            Self::NoConsumeRight => "no_consume_right",
            Self::PeerMismatch => "peer_mismatch",
        }
    }
}

impl std::fmt::Display for FamilyLeaseRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The msp-v1 per-request gate's log reason for the same binding
        // failure, verbatim (no lease contents — ever).
        match self {
            Self::NoLease => write!(f, "no lease presented"),
            Self::InvalidLease => write!(f, "lease invalid"),
            Self::ProfileMismatch => write!(f, "lease is for another profile"),
            Self::NoConsumeRight => write!(f, "lease grants no consume right"),
            Self::PeerMismatch => write!(f, "lease is not bound to this peer"),
        }
    }
}

/// ADR-026 lease admission for family sessions AT SESSION OPEN — the
/// composed daemon's seam. Given the QUIC-authenticated coordinator
/// PeerId and the lease the coordinator PRESENTED in the session-open
/// carrier (`None` when it opened offer-first), returns the lease expiry
/// (unix ms) the session serves under — validated against the SERVED
/// profile with every binding the msp-v1 per-request gate enforces
/// (RC-L1) — or the refusal; a refusal means NO family session (the
/// coordinator's client surfaces a transport failure and falls back to
/// single, never silently).
///
/// The token comes from whichever source the implementation trusts — the
/// PRESENTED carrier token (the msp-v1-equivalent discipline: hub-signed,
/// so a self-asserted token is exactly as strong as the one on the wire
/// in `InferenceRequest.capability_token`) and/or the tracker-fed roster
/// ([`RosterFamilyLeases`] honors both with one validation engine).
pub trait FamilyLeaseSource: Send + Sync {
    /// The validated lease expiry (unix ms) for `coordinator_peer_id` (the
    /// transport-authenticated remote PeerId) serving `served_profile`
    /// (this daemon's pinned profile), given the PRESENTED wire token
    /// (`None` = the coordinator opened without presenting) — or the
    /// refusal.
    fn lease_for(
        &self,
        coordinator_peer_id: &str,
        presented_lease: Option<&str>,
        served_profile: &str,
    ) -> Result<u64, FamilyLeaseRefusal>;
}

/// Fail-closed default: refuses every family session regardless of what
/// was presented (the honest default until the daemon wires a real lease
/// source — serving family sessions without a lease check would break the
/// ADR-026 discipline the msp-v1 path enforces per request).
pub struct RefuseFamilyLeases;

impl FamilyLeaseSource for RefuseFamilyLeases {
    fn lease_for(
        &self,
        _coordinator_peer_id: &str,
        _presented_lease: Option<&str>,
        _served_profile: &str,
    ) -> Result<u64, FamilyLeaseRefusal> {
        Err(FamilyLeaseRefusal::NoLease)
    }
}

/// Fixed-expiry source (the TEST/stub seam ONLY — it skips every lease
/// binding by design and must never back a production daemon; the
/// production source is [`RosterFamilyLeases`]).
pub struct StaticLeaseExpiry(pub u64);

impl FamilyLeaseSource for StaticLeaseExpiry {
    fn lease_for(
        &self,
        _coordinator_peer_id: &str,
        _presented_lease: Option<&str>,
        _served_profile: &str,
    ) -> Result<u64, FamilyLeaseRefusal> {
        Ok(self.0)
    }
}

/// The production [`FamilyLeaseSource`] (RC-L1, ADR-032 §7 disposition
/// item i; PRESENTED-lease activation 2026-10-12): the daemon's
/// eligibility/roster state — the hub-signed lease tokens the daemon
/// holds per coordinator peer — PLUS the lease the coordinator PRESENTS
/// at session open, validated with the SAME discipline
/// `crate::serving::LeasePolicy::check` applies per msp-v1 request: hub
/// signature + freshness, binding to the daemon's pinned profile,
/// `can_consume` with `slots >= 1`, and binding to the
/// transport-authenticated PeerId.
///
/// Lookup order: a ROSTER entry for the authenticated peer wins (the
/// tracker-fed future — the daemon's own record of the coordinator's
/// lease); without one, the PRESENTED token is validated directly (the
/// msp-v1-equivalent discipline: the hub signature is the authority, so
/// two fresh installations holding earned leases can pair with an EMPTY
/// roster). Either way the SAME [`validate_family_lease`] runs — a
/// stale, misfiled, or forged entry refuses exactly like a missing one,
/// the same "well-formed but policy-violating leases must fail at every
/// enforcing peer" stance `EligibilityLease::issue` documents.
///
/// The roster trusts its FEEDER (the tracker/roster wiring that calls
/// [`Self::upsert`]); presented tokens trust the pinned hub key —
/// nothing else.
pub struct RosterFamilyLeases {
    policy: LeasePolicy,
    roster: Mutex<HashMap<String, String>>,
}

impl RosterFamilyLeases {
    /// An empty roster under `policy` — family sessions then admit only
    /// through a PRESENTED lease (the fail-closed production default:
    /// nothing is on file, so the coordinator must bring its own
    /// hub-signed token).
    pub fn new(policy: LeasePolicy) -> Self {
        Self {
            policy,
            roster: Mutex::new(HashMap::new()),
        }
    }

    /// Records or refreshes the wire lease token for a coordinator peer
    /// (`base64url(json).base64url(sig)` — the tracker's issuance form).
    pub fn upsert(&self, coordinator_peer_id: &str, wire_lease: &str) {
        self.roster
            .lock()
            .expect("family lease roster lock")
            .insert(coordinator_peer_id.to_string(), wire_lease.to_string());
    }

    /// Drops a peer's entry (revocation / audit-sweep wiring); the peer
    /// may still present a valid lease at its next session open.
    pub fn remove(&self, coordinator_peer_id: &str) {
        self.roster
            .lock()
            .expect("family lease roster lock")
            .remove(coordinator_peer_id);
    }

    /// Number of entries on file (diagnostics: the honest roster size —
    /// 0 means presentation is the only admission path, which the status
    /// surface says instead of implying refusal).
    pub fn len(&self) -> usize {
        self.roster.lock().expect("family lease roster lock").len()
    }

    /// `true` when no lease is on file at all (diagnostics).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl FamilyLeaseSource for RosterFamilyLeases {
    fn lease_for(
        &self,
        coordinator_peer_id: &str,
        presented_lease: Option<&str>,
        served_profile: &str,
    ) -> Result<u64, FamilyLeaseRefusal> {
        let roster_token = self
            .roster
            .lock()
            .expect("family lease roster lock")
            .get(coordinator_peer_id)
            .cloned();
        match roster_token {
            // The tracker-fed roster entry is authoritative when present.
            Some(token) => {
                validate_family_lease(&self.policy, &token, coordinator_peer_id, served_profile)
            }
            // No roster entry: the PRESENTED token is the whole claim —
            // validated exactly like the msp-v1 per-request gate
            // validates its `capability_token` (empty/unverified forms
            // classify as NoLease, that gate's "no lease presented").
            None => match presented_lease {
                Some(token) => validate_presented_lease(
                    &self.policy,
                    token,
                    coordinator_peer_id,
                    served_profile,
                ),
                None => Err(FamilyLeaseRefusal::NoLease),
            },
        }
    }
}

/// The RC-L1 gate: one place, mirroring `crate::serving::LeasePolicy::check`
/// binding for binding — decode + hub verification (signature,
/// `msp1:` profile form, expiry within the ±120 s skew, lease cap),
/// profile binding, consume right + slots, peer binding — and returning
/// the token's operative `expires_at` as unix ms (the session's stage-5
/// lease bound; ADR-026 caps the token at the underlying lease + 60 s
/// grace, so `expires_at` is the latest an honest session may serve).
fn validate_family_lease(
    policy: &LeasePolicy,
    wire_token: &str,
    authenticated_peer_id: &str,
    served_profile: &str,
) -> Result<u64, FamilyLeaseRefusal> {
    let lease =
        EligibilityLease::from_wire(wire_token).map_err(|_| FamilyLeaseRefusal::InvalidLease)?;
    lease
        .verify(policy.hub_key(), &rfc3339_now())
        .map_err(|_| FamilyLeaseRefusal::InvalidLease)?;
    if lease.model_profile_id != served_profile {
        return Err(FamilyLeaseRefusal::ProfileMismatch);
    }
    if !lease.can_consume || lease.slots == 0 {
        return Err(FamilyLeaseRefusal::NoConsumeRight);
    }
    if lease.peer_id != authenticated_peer_id {
        return Err(FamilyLeaseRefusal::PeerMismatch);
    }
    // Freshness past the open check is the gate's hard stage-5 bound: the
    // session serves until the token's own operative expiry, no longer.
    let expires_at = OffsetDateTime::parse(&lease.expires_at, &Rfc3339)
        .map_err(|_| FamilyLeaseRefusal::InvalidLease)?;
    let seconds =
        u64::try_from(expires_at.unix_timestamp()).map_err(|_| FamilyLeaseRefusal::InvalidLease)?;
    Ok(seconds * 1000 + u64::from(expires_at.millisecond()))
}

/// The PRESENTED-token entry classification (the msp-v1 gate's first
/// check, verbatim): an empty or `f0-unverified` placeholder token is "no
/// lease presented" ([`FamilyLeaseRefusal::NoLease`]), anything else runs
/// the full binding validation.
fn validate_presented_lease(
    policy: &LeasePolicy,
    presented: &str,
    authenticated_peer_id: &str,
    served_profile: &str,
) -> Result<u64, FamilyLeaseRefusal> {
    if presented.is_empty() || presented.starts_with("f0-unverified") {
        return Err(FamilyLeaseRefusal::NoLease);
    }
    validate_family_lease(policy, presented, authenticated_peer_id, served_profile)
}

/// The family half of the composed daemon's configuration.
pub struct FamilyServing {
    /// The serve-loop config (profile, identity, budgets, presets, idle
    /// and I/O deadlines). `engine` is overridden at session open with the
    /// injected engine's REAL capabilities — the honest disclosure from
    /// real geometry, never hand-set.
    pub config: VerifyDraftsServeConfig,
    /// Where family sessions get their batch-verify engine (mock/stub or
    /// the production C-API bridge under `verifydrafts-capi`); one shared
    /// handle, asked for a fresh engine per accepted family session.
    pub engine: Arc<FamilyEngineSource>,
    /// The ADR-026 lease seam (see [`FamilyLeaseSource`]).
    pub lease: Arc<dyn FamilyLeaseSource>,
}

/// What the first-frame classifier found (the frame rides along — the
/// winning serve path consumes it pre-read).
enum FirstFrame {
    /// A typed msp-v1 frame won.
    MspV1(Box<WireMessage>),
    /// A raw family frame won.
    Family(Value),
    /// The session went idle or vanished before any frame arrived.
    Gone,
}

/// Classifies one accepted session by its first frame. msp-v1 frames
/// return from the typed recv immediately (no added latency); raw family
/// frames are stashed by the typed recv and collected on the poll
/// boundary via the stash-first raw recv.
async fn demux_first_frame(session: &mut Libp2pSession, idle: Duration) -> FirstFrame {
    let started = Instant::now();
    loop {
        let remaining = idle.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return FirstFrame::Gone;
        }
        let poll = remaining.min(DEMUX_POLL);
        match session.recv(poll).await {
            Ok(msg) => return FirstFrame::MspV1(Box::new(msg)),
            Err(TransportError::Timeout) => {
                // A raw family frame may have arrived and been stashed by
                // the typed recv: the stash-first raw recv returns it
                // immediately (the 1 ms bound only applies when nothing
                // was stashed).
                match session.recv_json(Duration::from_millis(1)).await {
                    Ok(value) => return FirstFrame::Family(value),
                    Err(TransportError::Timeout) => continue,
                    Err(_) => return FirstFrame::Gone,
                }
            }
            Err(_) => return FirstFrame::Gone,
        }
    }
}

// The peeked first family frame is handed to the serve loop pre-read via
// the venue-agnostic `PrefacedWire<W>` (wire.rs); the composed loop
// constructs it per accepted family session over the QUIC wire (whose
// Drop still FINs + drains gracefully).

/// The composed serve loop: ONE serving inbox (the direct listener plus,
/// since F2B, the relay reservation slot — see
/// [`crate::serving::ServingInbox`]), BOTH vocabularies, ONE admission
/// gate, ONE lease discipline. Lifecycle contract identical to
/// [`crate::serving::serve_sessions`]: stop when `shutdown` flips true OR
/// its watch sender drops. Per accepted session (in its own task, holding
/// one `Admission` slot for its whole lifetime regardless of vocabulary):
///
/// 1. admit (total + per-peer caps — refusal is the msp-v1 `overloaded`
///    `StreamError` and a telemetry label; a family client cannot parse
///    that frame and honestly sees the session close);
/// 2. classify by first frame (see [`demux_first_frame`]);
/// 3. msp-v1 → [`serve_one_seeded`] with the peeked frame (per-request
///    lease checks unchanged inside); family → the session-open exchange
///    ([`read_session_open`]: optional lease carrier, then the offer),
///    the profile-bound lease seam ([`FamilyLeaseSource::lease_for`] with
///    the PRESENTED token against the served profile, fail-closed with
///    the [`FamilyLeaseRefusal`] classification), engine from
///    [`FamilyEngineSource::engine_for`] (per-session, prefilled — never
///    constructed for a refused session), disclosure overridden with the
///    engine's real capabilities, then [`serve_verifydrafts_session`] with
///    the offer handed pre-read ([`PrefacedWire`]).
#[allow(clippy::too_many_arguments)]
pub async fn serve_sessions_composed(
    mut serving: crate::serving::ServingInbox,
    identity: std::sync::Arc<modelswarm_identity::InstallationIdentity>,
    executor: Arc<dyn InferenceExecutor>,
    profile_id: String,
    lease_policy: LeasePolicy,
    family: FamilyServing,
    telemetry: Arc<Telemetry>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let admission = Admission::defaults();
    loop {
        let session = tokio::select! {
            // The same semantics as the msp-v1 bridge: a CLOSED watch channel
            // (every Sender dropped) must ALSO stop serving — nobody can
            // ever signal stop otherwise, and a permanently-ready branch
            // would cancel every in-flight accept.
            changed = shutdown.changed() => match changed {
                Err(_) => {
                    telemetry.warn(
                        "serving.stopped",
                        &[("reason", "shutdown_sender_dropped")],
                    );
                    return;
                }
                Ok(()) => {
                    if *shutdown.borrow() {
                        telemetry.info("serving.stopped", &[("reason", "shutdown_signal")]);
                        return;
                    }
                    continue;
                }
            },
            accepted = serving.recv(Duration::from_secs(1)) => match accepted {
                Ok(s) => s,
                Err(_) => continue, // timeout/accept miss: keep serving
            },
        };
        let peer_id = session.remote_peer_id().to_string();
        let executor = Arc::clone(&executor);
        let profile = profile_id.clone();
        let policy = lease_policy.clone();
        let session_admission = admission.clone();
        let session_telemetry = Arc::clone(&telemetry);
        let family_config = family.config.clone();
        let family_engine = Arc::clone(&family.engine);
        let family_lease = Arc::clone(&family.lease);
        let composed_identity = Arc::clone(&identity);
        tokio::spawn(async move {
            let mut session = session;
            let _session_slot = match session_admission.admit_session(&peer_id) {
                Ok(guard) => guard,
                Err(reason) => {
                    session_telemetry
                        .warn("serving.refused", &[("peer", &peer_id), ("reason", reason)]);
                    send_error(&mut session, "overloaded", reason).await;
                    return;
                }
            };
            match demux_first_frame(&mut session, FIRST_FRAME_IDLE).await {
                FirstFrame::MspV1(frame) => {
                    if let Err(code) = serve_one_seeded(
                        session,
                        composed_identity,
                        executor,
                        profile,
                        &policy,
                        &session_admission,
                        &session_telemetry,
                        Some(*frame),
                    )
                    .await
                    {
                        // `code` is a stable reason code by construction.
                        session_telemetry.warn("serving.session_ended", &[("code", code.as_str())]);
                    }
                }
                FirstFrame::Family(first) => {
                    // The session-open exchange (ADR-032 §2 admission
                    // order, extended by ADR-036 §3.2 to the fixed
                    // three-part order): the coordinator's FIRST frame is
                    // its lease carrier when it presents one, then — for
                    // an ELECTED family-verified chat — the ADR-036 pin
                    // carrier (the user's conversation as token ids),
                    // immediately followed by the `SessionOffer`. Reading
                    // all of it here (before any engine work) keeps the
                    // lease gate AT SESSION OPEN, the carrier admission
                    // BEFORE the serve loop, and the engine untouched on
                    // refusal.
                    let mut wire = QuicVerifyWire::over_session(session);
                    let open: SessionOpen = match read_session_open(
                        &mut wire,
                        first,
                        family_config.io_deadline,
                    )
                    .await
                    {
                        Ok(open) => open,
                        Err(SessionOpenError::BadCarrier) => {
                            // A carrier that fails its strict schema
                            // IS a malformed presented lease — the
                            // gate's own classification.
                            session_telemetry.warn(
                                "verifydrafts.family_refused",
                                &[("peer", &peer_id), ("reason", "invalid_lease")],
                            );
                            return;
                        }
                        Err(SessionOpenError::BadPinCarrier(_)) => {
                            // ADR-036 §3.2 bad_frame class: strict
                            // schema is closed (content-bearing frames
                            // admit no unknown fields); labels only.
                            session_telemetry.warn(
                                "verifydrafts.pin_carrier_refused",
                                &[("peer", &peer_id), ("reason", "bad_frame")],
                            );
                            return;
                        }
                        Err(SessionOpenError::PayloadTooLarge) => {
                            session_telemetry.warn(
                                "verifydrafts.pin_carrier_refused",
                                &[("peer", &peer_id), ("reason", "payload_too_large")],
                            );
                            return;
                        }
                        Err(SessionOpenError::OutOfOrder(_)) => {
                            session_telemetry.warn(
                                "verifydrafts.pin_carrier_refused",
                                &[("peer", &peer_id), ("reason", "bad_frame")],
                            );
                            return;
                        }
                        Err(SessionOpenError::OfferTimeout) => {
                            session_telemetry
                                .info("serving.session_ended", &[("code", "offer_timeout")]);
                            return;
                        }
                        Err(SessionOpenError::Wire(_)) => {
                            session_telemetry
                                .info("serving.session_ended", &[("code", "wire_failure")]);
                            return;
                        }
                    };
                    // ADR-026 at family session open (RC-L1): the
                    // coordinator's lease — PRESENTED at open and/or on
                    // file in the daemon's source — is validated against
                    // the SERVED profile with every binding the msp-v1
                    // per-request gate enforces, fail-closed; no frozen
                    // family reject code exists for a refused lease, so
                    // the honest answer is the session end (the client's
                    // fallback-to-single signal). The lease stays FIRST
                    // in the processing order exactly as it is first on
                    // the wire (the disclosure-minimizing rationale:
                    // lease refusal happens before the conversation is
                    // processed).
                    let lease_expires_at_ms =
                        match family_lease.lease_for(&peer_id, open.lease.as_deref(), &profile) {
                            Ok(expires_at_ms) => expires_at_ms,
                            Err(refusal) => {
                                session_telemetry.warn(
                                    "verifydrafts.family_refused",
                                    &[("peer", &peer_id), ("reason", refusal.as_str())],
                                );
                                return;
                            }
                        };
                    // ADR-036 §3.2: the pin-carrier admission table —
                    // BEFORE any engine work (a refused or malformed
                    // carrier never constructs a prefilled engine), with
                    // the coordinator key pinned from the
                    // transport-authenticated PeerId exactly as the
                    // serve loop pins it for round frames.
                    let (pin, engine_root) = match open.pin {
                        None => (None, None),
                        Some(carrier) => {
                            let coordinator_key = match family_config.pinned_coordinator_key {
                                Some(pinned) => pinned,
                                None => match verifying_key_from_peer_id(&peer_id) {
                                    Ok(key) => key,
                                    Err(_) => {
                                        session_telemetry.warn(
                                            "verifydrafts.pin_carrier_refused",
                                            &[("peer", &peer_id), ("reason", "bad_frame")],
                                        );
                                        return;
                                    }
                                },
                            };
                            let params_hash =
                                match modelswarm_session::verifydrafts::batch_generation_params_hash(
                                    &family_config.sampling_params,
                                ) {
                                    Ok(hash) => hash,
                                    Err(_) => {
                                        session_telemetry.warn(
                                            "verifydrafts.pin_carrier_refused",
                                            &[("peer", &peer_id), ("reason", "misconfigured")],
                                        );
                                        return;
                                    }
                                };
                            let arrival = unix_ms_now();
                            match admit_pin_carrier(
                                &carrier,
                                &peer_id,
                                &coordinator_key,
                                &profile,
                                &params_hash,
                                family_config.content_carriage,
                                family_config.prefill_context_tokens,
                                arrival,
                                arrival,
                            ) {
                                PinAdmission::Admitted(admitted) => {
                                    // COUNTS ONLY (ADR-036 §3.2 hygiene:
                                    // the token COUNT is permitted; ids,
                                    // arrays, and content-derived hashes
                                    // — including the pin commitment —
                                    // never reach telemetry).
                                    session_telemetry.info(
                                        "verifydrafts.pin_carrier_admitted",
                                        &[
                                            ("peer", peer_id.as_str()),
                                            ("tokens", &admitted.prompt_tokens.len().to_string()),
                                            ("seq", &admitted.seq.to_string()),
                                        ],
                                    );
                                    let root = admitted.prompt_tokens.clone();
                                    (Some(admitted), Some(root))
                                }
                                PinAdmission::Rejected(reason) => {
                                    send_pin_reject(
                                        &mut wire,
                                        &carrier,
                                        reason,
                                        family_config.io_deadline,
                                    )
                                    .await;
                                    session_telemetry.warn(
                                        "verifydrafts.pin_carrier_refused",
                                        &[("peer", peer_id.as_str()), ("reason", reason.as_str())],
                                    );
                                    return;
                                }
                                PinAdmission::BadFrame(_) => {
                                    session_telemetry.warn(
                                        "verifydrafts.pin_carrier_refused",
                                        &[("peer", peer_id.as_str()), ("reason", "bad_frame")],
                                    );
                                    return;
                                }
                                PinAdmission::DeadlineExceeded => {
                                    session_telemetry.warn(
                                        "verifydrafts.pin_carrier_refused",
                                        &[
                                            ("peer", peer_id.as_str()),
                                            ("reason", "deadline_exceeded"),
                                        ],
                                    );
                                    return;
                                }
                            }
                        }
                    };
                    // The ADR-036 deadline RE-CHECK immediately before
                    // prefill dispatch (engine construction IS the
                    // prefill under the Capi seam).
                    if let Some(pin) = &pin {
                        if unix_ms_now() >= pin.deadline_expires_at_ms {
                            session_telemetry.warn(
                                "verifydrafts.pin_carrier_refused",
                                &[("peer", peer_id.as_str()), ("reason", "deadline_exceeded")],
                            );
                            return;
                        }
                    }
                    // The engine: per-session prefilled — the CARRIER's
                    // conversation root for a carrier session (ADR-036),
                    // the daemon-pinned neutral prompt otherwise
                    // (ADR-034). The per-session handle's drop at session
                    // end bounds KV residency.
                    let engine = match family_engine.engine_for_root(engine_root.as_deref()).await {
                        Ok(engine) => engine,
                        Err(_) => {
                            // Local engine-load failure: stable label, no
                            // engine detail crosses the wire.
                            session_telemetry.warn(
                                "verifydrafts.family_refused",
                                &[("peer", &peer_id), ("reason", "engine_unavailable")],
                            );
                            return;
                        }
                    };
                    let mut config = family_config;
                    config.lease_expires_at_ms = lease_expires_at_ms;
                    // The honest disclosure from the engine's REAL
                    // geometry (RC-8) — never the hand-set field.
                    config.engine = engine.capabilities();
                    let wire = PrefacedWire::new(wire, Some(open.offer));
                    // The report's end reason is telemetered inside the
                    // serve loop (`verifydrafts.session_ended`).
                    let _report = serve_verifydrafts_session_with_pin(
                        wire,
                        config,
                        engine,
                        pin,
                        &session_telemetry,
                    )
                    .await;
                }
                FirstFrame::Gone => {
                    // Idle/vanished before any frame: nothing honest to
                    // send in either vocabulary.
                    session_telemetry
                        .info("serving.session_ended", &[("code", "first_frame_timeout")]);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use modelswarm_eligibility::{CapacityClass, EligibilityLease};

    /// A profile id that passes the msp1 form checks (serving.rs's test
    /// pattern).
    const TEST_PROFILE: &str =
        "msp1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    /// A DIFFERENT well-formed profile (the wrong-profile binding arm).
    const OTHER_PROFILE: &str =
        "msp1:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn rfc3339(plus_secs: i64) -> String {
        OffsetDateTime::now_utc()
            .saturating_add(time::Duration::seconds(plus_secs))
            .format(&Rfc3339)
            .unwrap()
    }

    /// Issues a consume lease under `key` with overridable bindings and
    /// returns the wire token (the serving.rs lease_helpers pattern,
    /// parameterized for each refusal arm).
    #[allow(clippy::too_many_arguments)]
    fn lease_wire(
        key: &SigningKey,
        profile: &str,
        peer_id: &str,
        can_consume: bool,
        slots: u8,
        expires_in_secs: i64,
    ) -> String {
        EligibilityLease::issue(
            peer_id,
            "test-installation",
            profile,
            rfc3339(-60),
            rfc3339(expires_in_secs),
            rfc3339(expires_in_secs + 60),
            true,
            can_consume,
            slots,
            CapacityClass::GpuMid,
            1,
            "test-challenge",
            "test-nonce",
            1,
            key,
        )
        .to_wire()
    }

    fn policy_over(key: &SigningKey) -> LeasePolicy {
        LeasePolicy::from_hex(&hex::encode(key.verifying_key().to_bytes())).unwrap()
    }

    /// The fail-closed default refuses every family session (no lease, no
    /// serving — the ADR-026 discipline the msp-v1 path enforces per
    /// request), regardless of what was presented.
    #[test]
    fn fail_closed_lease_source_refuses_everything() {
        let source = RefuseFamilyLeases;
        assert_eq!(
            source.lease_for("12D3Kooanything", Some("any-token"), TEST_PROFILE),
            Err(FamilyLeaseRefusal::NoLease)
        );
    }

    /// The static source supplies its pinned expiry (the TEST/stub seam —
    /// binding-free by design; production uses RosterFamilyLeases).
    #[test]
    fn static_lease_source_supplies_expiry() {
        let source = StaticLeaseExpiry(u64::MAX);
        assert_eq!(source.lease_for("peer", None, TEST_PROFILE), Ok(u64::MAX));
    }

    /// RC-L1: an empty production roster with NOTHING presented refuses
    /// fail-closed (NoLease) — the ADR-026 discipline.
    #[test]
    fn empty_roster_refuses_fail_closed() {
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let roster = RosterFamilyLeases::new(policy_over(&key));
        assert!(roster.is_empty());
        assert_eq!(
            roster.lease_for("peer-a", None, TEST_PROFILE),
            Err(FamilyLeaseRefusal::NoLease)
        );
    }

    /// The msp-v1 gate's first check, verbatim on the PRESENTED token:
    /// empty and `f0-unverified` placeholders classify as `no_lease`
    /// ("no lease presented"), not `invalid_lease`.
    #[test]
    fn presented_placeholder_forms_classify_as_no_lease() {
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let roster = RosterFamilyLeases::new(policy_over(&key));
        assert_eq!(
            roster.lease_for("peer-a", Some(""), TEST_PROFILE),
            Err(FamilyLeaseRefusal::NoLease)
        );
        assert_eq!(
            roster.lease_for("peer-a", Some("f0-unverified-peer-a"), TEST_PROFILE),
            Err(FamilyLeaseRefusal::NoLease)
        );
    }

    /// RC-L1: a VALID lease on file serves — and the expiry handed to the
    /// session is the token's own operative `expires_at` (unix ms), the
    /// ADR-026-capped bound the gate's stage-5 check enforces.
    #[test]
    fn roster_accepts_valid_lease_and_returns_token_expiry() {
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let token = lease_wire(&key, TEST_PROFILE, "peer-a", true, 2, 300);
        let roster = RosterFamilyLeases::new(policy_over(&key));
        roster.upsert("peer-a", &token);
        assert_eq!(roster.len(), 1);
        let expires_ms = roster
            .lease_for("peer-a", None, TEST_PROFILE)
            .expect("valid lease serves");
        // within (300 s - 120 s skew, 300 s] of now, in ms
        let now_ms = OffsetDateTime::now_utc().unix_timestamp() as u64 * 1000;
        assert!(expires_ms > now_ms + 120 * 1000, "{expires_ms} vs {now_ms}");
        assert!(
            expires_ms <= now_ms + 300 * 1000 + 1100,
            "{expires_ms} vs {now_ms}"
        );
        // The served profile was part of the validation: the same token
        // under another served profile is a ProfileMismatch, not a serve.
        assert_eq!(
            roster.lease_for("peer-a", None, OTHER_PROFILE),
            Err(FamilyLeaseRefusal::ProfileMismatch)
        );
        // And the authenticated peer matters: another peer id has no
        // entry at all.
        assert_eq!(
            roster.lease_for("peer-b", None, TEST_PROFILE),
            Err(FamilyLeaseRefusal::NoLease)
        );
        // Removal (revocation wiring) refuses again — until the peer
        // presents a valid lease of its own (below).
        roster.remove("peer-a");
        assert_eq!(
            roster.lease_for("peer-a", None, TEST_PROFILE),
            Err(FamilyLeaseRefusal::NoLease)
        );
    }

    /// The PRESENTED-lease activation (2026-10-12): with an EMPTY roster,
    /// the token the coordinator presents at session open is the whole
    /// claim — validated exactly like the msp-v1 per-request
    /// `capability_token` (the same pin set as the roster arm above).
    #[test]
    fn presented_lease_admits_on_an_empty_roster() {
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let token = lease_wire(&key, TEST_PROFILE, "peer-a", true, 2, 300);
        let roster = RosterFamilyLeases::new(policy_over(&key));
        assert!(roster.is_empty(), "nothing on file — presentation only");
        let expires_ms = roster
            .lease_for("peer-a", Some(&token), TEST_PROFILE)
            .expect("a presented valid lease serves on an empty roster");
        let now_ms = OffsetDateTime::now_utc().unix_timestamp() as u64 * 1000;
        assert!(expires_ms > now_ms + 120 * 1000);
        // The same bindings the roster arm checks: profile + peer.
        let other = lease_wire(&key, OTHER_PROFILE, "peer-a", true, 1, 300);
        assert_eq!(
            roster.lease_for("peer-a", Some(&other), TEST_PROFILE),
            Err(FamilyLeaseRefusal::ProfileMismatch)
        );
        let stranger = lease_wire(&key, TEST_PROFILE, "peer-b", true, 1, 300);
        assert_eq!(
            roster.lease_for("peer-a", Some(&stranger), TEST_PROFILE),
            Err(FamilyLeaseRefusal::PeerMismatch)
        );
    }

    /// Roster precedence: when a roster entry exists it IS the lease under
    /// test (the tracker-fed record is authoritative); the presented token
    /// is then not even consulted — pinned by a garbage roster entry
    /// refusing despite a valid presented lease (fail-closed feeder
    /// posture; `remove` restores the presentation path).
    #[test]
    fn roster_entry_takes_precedence_over_the_presented_token() {
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let roster = RosterFamilyLeases::new(policy_over(&key));
        roster.upsert("peer-a", "not-a-lease");
        let valid = lease_wire(&key, TEST_PROFILE, "peer-a", true, 1, 300);
        assert_eq!(
            roster.lease_for("peer-a", Some(&valid), TEST_PROFILE),
            Err(FamilyLeaseRefusal::InvalidLease),
            "the roster entry (garbage) is the lease under test"
        );
        roster.remove("peer-a");
        assert!(roster
            .lease_for("peer-a", Some(&valid), TEST_PROFILE)
            .is_ok());
    }

    /// RC-L1, binding-by-binding (each refuses with the msp-v1 gate's own
    /// classification) — EVERY broken binding pinned through BOTH token
    /// sources: filed in the roster AND presented at session open on an
    /// empty roster. Wrong profile, expired beyond skew, can_consume
    /// false, slots zero, lease bound to another peer, a token signed by
    /// a foreign hub, and undecodable garbage.
    #[test]
    fn each_broken_binding_refuses_via_roster_and_via_presentation() {
        let key = SigningKey::generate(&mut rand_core::OsRng);
        // Both arms share one check: file the token (roster arm) or
        // present it (presentation arm, empty roster).
        let check = |token: String| {
            let roster = RosterFamilyLeases::new(policy_over(&key));
            roster.upsert("peer-a", &token);
            let via_roster = roster.lease_for("peer-a", None, TEST_PROFILE);
            let presented = RosterFamilyLeases::new(policy_over(&key));
            let via_presented = presented.lease_for("peer-a", Some(&token), TEST_PROFILE);
            (via_roster, via_presented)
        };

        // Wrong profile: lease for OTHER_PROFILE.
        let (roster, presented) = check(lease_wire(&key, OTHER_PROFILE, "peer-a", true, 1, 300));
        assert_eq!(roster, Err(FamilyLeaseRefusal::ProfileMismatch));
        assert_eq!(presented, Err(FamilyLeaseRefusal::ProfileMismatch));

        // Expired beyond the ±120 s skew (issued 10 min ago, expired
        // 5 min ago): fails hub verification.
        let expired = EligibilityLease::issue(
            "peer-a",
            "test-installation",
            TEST_PROFILE,
            rfc3339(-600),
            rfc3339(-300),
            rfc3339(-240),
            true,
            true,
            1,
            CapacityClass::GpuMid,
            1,
            "test-challenge",
            "test-nonce",
            1,
            &key,
        )
        .to_wire();
        let (roster, presented) = check(expired);
        assert_eq!(roster, Err(FamilyLeaseRefusal::InvalidLease));
        assert_eq!(presented, Err(FamilyLeaseRefusal::InvalidLease));

        // can_consume false.
        let (roster, presented) = check(lease_wire(&key, TEST_PROFILE, "peer-a", false, 1, 300));
        assert_eq!(roster, Err(FamilyLeaseRefusal::NoConsumeRight));
        assert_eq!(presented, Err(FamilyLeaseRefusal::NoConsumeRight));

        // Slots zero.
        let (roster, presented) = check(lease_wire(&key, TEST_PROFILE, "peer-a", true, 0, 300));
        assert_eq!(roster, Err(FamilyLeaseRefusal::NoConsumeRight));
        assert_eq!(presented, Err(FamilyLeaseRefusal::NoConsumeRight));

        // Bound to another peer (misfiled/stolen token: carried by
        // peer-a, signed for peer-b — the signature binds peer-b, so the
        // authenticated-peer check refuses).
        let (roster, presented) = check(lease_wire(&key, TEST_PROFILE, "peer-b", true, 1, 300));
        assert_eq!(roster, Err(FamilyLeaseRefusal::PeerMismatch));
        assert_eq!(presented, Err(FamilyLeaseRefusal::PeerMismatch));

        // Signed by a FOREIGN hub: signature verification fails.
        let stranger = SigningKey::generate(&mut rand_core::OsRng);
        let (roster, presented) =
            check(lease_wire(&stranger, TEST_PROFILE, "peer-a", true, 1, 300));
        assert_eq!(roster, Err(FamilyLeaseRefusal::InvalidLease));
        assert_eq!(presented, Err(FamilyLeaseRefusal::InvalidLease));

        // Undecodable garbage: fails closed the same way in both arms
        // (and on the wire, a malformed carrier is BadCarrier → the same
        // invalid_lease classification).
        let (roster, presented) = check("not-a-lease".to_string());
        assert_eq!(roster, Err(FamilyLeaseRefusal::InvalidLease));
        assert_eq!(presented, Err(FamilyLeaseRefusal::InvalidLease));
    }

    /// The refusal labels are stable (telemetry contract) and the Display
    /// mirrors the msp-v1 gate's log reasons.
    #[test]
    fn refusal_labels_and_display_mirror_the_msp_v1_gate() {
        assert_eq!(FamilyLeaseRefusal::NoLease.as_str(), "no_lease");
        assert_eq!(FamilyLeaseRefusal::InvalidLease.as_str(), "invalid_lease");
        assert_eq!(
            FamilyLeaseRefusal::ProfileMismatch.as_str(),
            "profile_mismatch"
        );
        assert_eq!(
            FamilyLeaseRefusal::NoConsumeRight.as_str(),
            "no_consume_right"
        );
        assert_eq!(FamilyLeaseRefusal::PeerMismatch.as_str(), "peer_mismatch");
        assert_eq!(
            FamilyLeaseRefusal::NoLease.to_string(),
            "no lease presented"
        );
        assert_eq!(
            FamilyLeaseRefusal::ProfileMismatch.to_string(),
            "lease is for another profile"
        );
        assert_eq!(
            FamilyLeaseRefusal::NoConsumeRight.to_string(),
            "lease grants no consume right"
        );
        assert_eq!(
            FamilyLeaseRefusal::PeerMismatch.to_string(),
            "lease is not bound to this peer"
        );
    }
}
