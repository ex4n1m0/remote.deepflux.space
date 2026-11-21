//! Security-review pin tests — post-implementation review of the landed
//! VerifyDrafts family (ADR-032 §7 checklist item 8; review document
//! `docs/reviews/review-verifydrafts-implementation-security-2026-10-11.md`).
//!
//! These tests PIN current implementation behavior that the review found
//! behavior-determining but not explicitly pinned by the ADR or the existing
//! property suites. They change NO production behavior; they freeze the
//! behavior so any later amendment is a deliberate, review-visible change
//! (the repo's own precedent: session 3 pinned the over-constrained
//! `deadline-past` fixture's literal-seeding classification before the
//! session-4 fixture repair).
//!
//! Pins carried here:
//! 1. The coordinator-side drop-vs-violation partition of
//!    [`VerifyDraftsCoordinator::admit_result`] (review advisory A2): the
//!    consumed-nonce and no-outstanding drops run AFTER the signature and
//!    remote-peer checks, so a GENUINE replay drops with no state change
//!    while a frame that fails signature/remote-peer counts a violation
//!    even when it carries a consumed nonce or no round is outstanding
//!    (session-4 handoff assumption 3).
//! 2. The verifier-side treatment of a LATE `PrefixCommit` after the
//!    WAIT_COMMIT grace has expired (review advisory A1): AMENDED at
//!    ADR-032 revision 4 (§8 RC-5(b), 2026-10-12) — post-expiry commits
//!    are STALE `round_mismatch` no-ops exempt from the violation
//!    counter (whether they would have reproduced is unknowable after
//!    the RC-5(b) discard), while commits failing RC-4 reproduction
//!    while the round's result is OUTSTANDING remain `commit_mismatch`
//!    violations toward threshold-two teardown. This file freezes the
//!    NEW semantics (the pre-revision-4 classification — post-expiry
//!    reproductions counted — is superseded).
//! 3. The §2 `PrefixCommit` carrier `sender` check (revision 4 §2/G2):
//!    the unsigned carrier's `sender` MUST equal the installation id
//!    pinned from the authenticated channel; mismatch is `bad_frame`
//!    before any state is touched.

use modelswarm_identity::InstallationIdentity;

/// The QUIC remote PeerId a serve loop would supply for this
/// coordinator identity (RC-1: admitted requests must carry it).
fn peer_of(c: &InstallationIdentity) -> String {
    modelswarm_identity::peer_id_for(&c.verifying_key().to_bytes())
}
use modelswarm_runtime::SamplingParams;
use modelswarm_session::negotiation::{
    Backend, CancelRoundReason, EngineDisclosure, FrameRejectReason, SessionBudget,
};
use modelswarm_session::verifydrafts::{
    batch_generation_params_hash, sign_verify_drafts, sign_verify_drafts_result, AdmissionDecision,
    BatchVerifyEngine, CancelRoundFrame, CommitApplyOutcome, DispatchOutcome, ResultAdmission,
    ResultDrop, ResultViolation, VerifyDrafts, VerifyDraftsCoordinator,
    VerifyDraftsCoordinatorConfig, VerifyDraftsGate, VerifyDraftsGateConfig, VerifyDraftsResult,
    TEARDOWN_VIOLATION_THRESHOLD, WINDOW_CAP,
};
use modelswarm_session::{compute_prefix_hash, CommitPrefix, GENESIS_PREFIX_HASH};
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};

/// 2026-10-12T00:00:00Z (the shared fixture anchor).
const NOW: u64 = 1_791_763_200_000;
const SESSION: &str = "sess-sec-review";
const WINDOW: [u32; 3] = [9_600_001, 9_600_002, 9_600_003];

fn fixture_id(seed: u8) -> InstallationIdentity {
    InstallationIdentity::from_bytes(&[seed; 32])
}

fn profile() -> String {
    format!("msp1:{}", "ab".repeat(32))
}

fn params_hash() -> String {
    batch_generation_params_hash(&SamplingParams::default()).unwrap()
}

// ---------------------------------------------------------------------------
// Shared builders (minimal; self-contained, not shared with the property
// suites so a suite edit cannot silently move these pins)
// ---------------------------------------------------------------------------

fn build_request(
    coordinator: &InstallationIdentity,
    seq: u64,
    round: u64,
    nonce: &str,
) -> VerifyDrafts {
    let mut msg = VerifyDrafts {
        session_id: SESSION.to_string(),
        protocol_version: "msp-cooperative-v1".to_string(),
        seq,
        round,
        profile_id: profile(),
        parent_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        generation_params_hash: params_hash(),
        window_tokens: WINDOW.to_vec(),
        proposer_id: "12D3KooProposer".to_string(),
        nonce: nonce.to_string(),
        deadline_ms: 2_500,
        sender: coordinator.installation_id(),
        signature: String::new(),
    };
    msg.signature = sign_verify_drafts(&msg, coordinator).unwrap();
    msg
}

fn result_draft(
    verifier: &InstallationIdentity,
    req: &VerifyDrafts,
    seq: u64,
    accepted: u32,
    correction: Option<u32>,
    new_prefix_hash: String,
) -> VerifyDraftsResult {
    let divergence = (accepted < req.window_tokens.len() as u32).then_some(accepted);
    let mut msg = VerifyDraftsResult {
        session_id: req.session_id.clone(),
        protocol_version: "msp-cooperative-v1".to_string(),
        seq,
        round: req.round,
        accepted_prefix_len: accepted,
        divergence_point: divergence,
        correction,
        new_prefix_hash,
        verify_pass_ms: 35,
        nonce_echo: req.nonce.clone(),
        sender: verifier.installation_id(),
        signature: String::new(),
    };
    msg.signature = sign_verify_drafts_result(&msg, verifier).unwrap();
    msg
}

/// An internally-consistent (honest-shape) result for `req`.
fn honest_result(
    verifier: &InstallationIdentity,
    req: &VerifyDrafts,
    seq: u64,
) -> VerifyDraftsResult {
    let mut committed = req.window_tokens.to_vec();
    committed.push(999);
    let hash = compute_prefix_hash(&req.parent_prefix_hash, &committed).unwrap();
    result_draft(
        verifier,
        req,
        seq,
        req.window_tokens.len() as u32,
        Some(999),
        hash,
    )
}

struct MockEngine {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl BatchVerifyEngine for MockEngine {
    async fn verify_window(
        &self,
        window: &[u32],
        _params: &SamplingParams,
    ) -> Result<(u32, Option<u32>), modelswarm_runtime::RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok((window.len() as u32, Some(999)))
    }
    fn capabilities(&self) -> EngineDisclosure {
        EngineDisclosure {
            backend: Backend::Cpu,
            batch_verify: true,
            batch_window_max: WINDOW_CAP,
        }
    }
}

fn gate(coordinator: &InstallationIdentity) -> VerifyDraftsGate {
    VerifyDraftsGate::new(VerifyDraftsGateConfig {
        session_id: SESSION.to_string(),
        profile_id: profile(),
        generation_params_hash: params_hash(),
        committed_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        coordinator_key: coordinator.verifying_key(),
        verifier_installation_id: fixture_id(0x22).installation_id(),
        engine: EngineDisclosure {
            backend: Backend::Cpu,
            batch_verify: true,
            batch_window_max: WINDOW_CAP,
        },
        budget: SessionBudget {
            max_endpoints: 1,
            max_endpoint_seconds: 120,
            max_output_tokens: 10_000,
        },
        lease_expires_at_ms: NOW + 3_600_000,
        sampling_params: SamplingParams::default(),
        verifier_next_seq: 4,
    })
    .unwrap()
}

// ---------------------------------------------------------------------------
// Pin 1 — coordinator drop-vs-violation partition (review advisory A2)
// ---------------------------------------------------------------------------

#[test]
fn pin_coordinator_replay_partition_genuine_drop_garbage_violation() {
    assert_eq!(TEARDOWN_VIOLATION_THRESHOLD, 2);
    let coordinator_id = fixture_id(0x11);
    let verifier = fixture_id(0x22);
    let request = build_request(&coordinator_id, 12, 3, "pin-nonce");
    let mut coord = VerifyDraftsCoordinator::new(VerifyDraftsCoordinatorConfig {
        session_id: SESSION.to_string(),
        profile_id: profile(),
        generation_params_hash: params_hash(),
        verifier_key: verifier.verifying_key(),
    })
    .unwrap();
    coord.track_request(&request).unwrap();

    let wire = |msg: &VerifyDraftsResult| -> Value { serde_json::to_value(msg).unwrap() };

    let result = honest_result(&verifier, &request, 4);
    assert_eq!(
        coord.admit_result(&wire(&result), &verifier.peer_id()),
        ResultAdmission::Accepted {
            committed: vec![9_600_001, 9_600_002, 9_600_003, 999]
        }
    );

    // (1) A replayed GENUINE result (consumed nonce, valid signature,
    // right peer) is dropped with NO state change — RC-3 tail.
    assert_eq!(
        coord.admit_result(&wire(&result), &verifier.peer_id()),
        ResultAdmission::Dropped(ResultDrop::ConsumedNonce)
    );
    assert_eq!(coord.violations_of(&verifier.peer_id()), 0);

    // (2) A frame carrying the CONSUMED nonce that fails the signature is
    // a VIOLATION, not a drop: the signature check precedes the
    // consumed-nonce drop (session-4 handoff assumption 3).
    let mut garbage = result.clone();
    garbage.signature = "AAAAnot-base64".to_string();
    assert_eq!(
        coord.admit_result(&wire(&garbage), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::Signature)
    );
    assert_eq!(coord.violations_of(&verifier.peer_id()), 1);
    assert!(
        !coord.is_torn_down(),
        "the FIRST violation never tears down"
    );

    // (3) A VALIDLY-signed result with no outstanding request and a fresh
    // nonce is a drop, not a violation.
    let mut orphan = honest_result(&verifier, &request, 5);
    orphan.nonce_echo = "fresh-unconsumed".to_string();
    orphan.signature = sign_verify_drafts_result(&orphan, &verifier).unwrap();
    assert_eq!(
        coord.admit_result(&wire(&orphan), &verifier.peer_id()),
        ResultAdmission::Dropped(ResultDrop::NoOutstandingRequest)
    );
    assert_eq!(
        coord.violations_of(&verifier.peer_id()),
        1,
        "the no-outstanding drop changes no state"
    );

    // (4) A SECOND signature violation by the same peer tears down at
    // exactly two (the threshold pin, mirrored from the property suite).
    let mut garbage2 = result.clone();
    garbage2.nonce_echo = "fresh-unconsumed-2".to_string();
    garbage2.signature = "AAAAnot-base64".to_string();
    assert_eq!(
        coord.admit_result(&wire(&garbage2), &verifier.peer_id()),
        ResultAdmission::TornDown(ResultViolation::Signature)
    );
    assert!(coord.is_torn_down());
}

// ---------------------------------------------------------------------------
// Pin 2 — verifier-side LATE commit after WAIT_COMMIT expiry (review A1,
// AMENDED by ADR-032 revision 4 §8 RC-5(b), 2026-10-12)
// ---------------------------------------------------------------------------

/// Post-expiry commits are STALE ROUNDS, not violations (ADR-032 revision
/// 4, §8 RC-5(b) / Security advisory A1, ruled 2026-10-12): a
/// `PrefixCommit` arriving for a round already abandoned — round handled
/// but uncommitted, no outstanding result left to reproduce against — is
/// rejected `CancelRound("round_mismatch")` with NO state change and NO
/// violation-counter increment; the commit is never applied (I2), and TWO
/// late commits from an honest-but-slow coordinator do NOT tear the
/// session down. The pre-revision-4 classification (post-expiry
/// reproductions counted as `commit_mismatch` violations toward
/// threshold-two teardown) is superseded; this pin freezes the new
/// semantics.
#[tokio::test]
async fn pin_verifier_late_commit_after_expiry_is_exempt_stale_round_mismatch() {
    let coordinator = fixture_id(0x31);
    let engine = MockEngine {
        calls: AtomicUsize::new(0),
    };
    let mut gate = gate(&coordinator);
    gate.seed_pre_state(modelswarm_session::verifydrafts::GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        ..Default::default()
    });

    let frame = build_request(&coordinator, 13, 2, "late-nonce");
    let AdmissionDecision::Admitted {
        deadline_expires_at_ms,
        ..
    } = gate.admit_verify_drafts(
        &serde_json::to_value(&frame).unwrap(),
        NOW,
        NOW,
        &peer_of(&coordinator),
    )
    else {
        panic!("round must admit");
    };
    let DispatchOutcome::Dispatched(result) =
        gate.dispatch_outstanding(&engine, NOW, NOW + 35).await
    else {
        panic!("dispatch must succeed");
    };

    // WAIT_COMMIT grace expiry abandons the round and discards the result.
    assert!(gate.expire_wait_commit_if_due(deadline_expires_at_ms + 250));
    assert_eq!(gate.outstanding_round(), None);

    // The late REPRODUCING commit (it exactly matches the discarded
    // result) is a stale round_mismatch NO-OP: no state change, NO
    // violation-counter increment, never applied.
    let mut committed = frame.window_tokens.to_vec();
    committed.push(999);
    let late = CommitPrefix {
        session_id: SESSION.to_string(),
        round: 2,
        previous_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        accepted_token_ids: committed,
        new_prefix_hash: result.new_prefix_hash.clone(),
        model_profile_id: profile(),
        generation_params_hash: params_hash(),
        sender: coordinator.installation_id(),
    };
    assert_eq!(
        gate.apply_prefix_commit(&late),
        CommitApplyOutcome::CancelRound(CancelRoundFrame {
            session_id: SESSION.to_string(),
            round: 2,
            reason: CancelRoundReason::RoundMismatch,
        })
    );
    assert_eq!(
        gate.violations_of(&coordinator.installation_id()),
        0,
        "an unknowable reproduction is never charged as a violation"
    );
    assert_eq!(gate.committed_prefix_hash(), GENESIS_PREFIX_HASH);
    assert_eq!(gate.committed_output_tokens(), 0);
    assert_eq!(gate.last_committed_round(), 0);

    // A SECOND late commit by the same peer: still exempt — the session
    // is NOT torn down (two late commits from an honest-but-slow
    // coordinator must not end it; the exemption is not a counter).
    assert_eq!(
        gate.apply_prefix_commit(&late),
        CommitApplyOutcome::CancelRound(CancelRoundFrame {
            session_id: SESSION.to_string(),
            round: 2,
            reason: CancelRoundReason::RoundMismatch,
        })
    );
    assert!(!gate.is_torn_down());
    assert_eq!(gate.violations_of(&coordinator.installation_id()), 0);

    // The coordinator learns of the abandonment honestly and gaps
    // forward (RC-5(c)): the NEXT round chains on the unchanged
    // committed hash and admits.
    let next = build_request(&coordinator, 14, 3, "post-stale-nonce");
    assert!(matches!(
        gate.admit_verify_drafts(
            &serde_json::to_value(&next).unwrap(),
            NOW,
            NOW,
            &peer_of(&coordinator),
        ),
        AdmissionDecision::Admitted { .. }
    ));
}

/// The exemption's scope (ADR-032 revision 4 §8 RC-5(b) tail): a commit
/// failing RC-4 reproduction WHILE the round's result is outstanding
/// remains a `commit_mismatch` violation toward threshold-two teardown,
/// exactly as before the reclassification.
#[tokio::test]
async fn pin_commit_mismatch_while_result_outstanding_still_violates() {
    let coordinator = fixture_id(0x37);
    let engine = MockEngine {
        calls: AtomicUsize::new(0),
    };
    let mut gate = gate(&coordinator);
    gate.seed_pre_state(modelswarm_session::verifydrafts::GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        ..Default::default()
    });
    let frame = build_request(&coordinator, 13, 2, "outstanding-nonce");
    assert!(matches!(
        gate.admit_verify_drafts(
            &serde_json::to_value(&frame).unwrap(),
            NOW,
            NOW,
            &peer_of(&coordinator),
        ),
        AdmissionDecision::Admitted { .. }
    ));
    assert!(
        matches!(
            gate.dispatch_outstanding(&engine, NOW, NOW + 35).await,
            DispatchOutcome::Dispatched(_)
        ),
        "dispatch must succeed (result outstanding)"
    );

    // A hash-VALID commit over different ids while the result is
    // outstanding: commit_mismatch, ONE violation — unchanged semantics.
    let impostor = CommitPrefix {
        session_id: SESSION.to_string(),
        round: 2,
        previous_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        accepted_token_ids: vec![9_700_001, 9_700_002],
        new_prefix_hash: compute_prefix_hash(GENESIS_PREFIX_HASH, &[9_700_001, 9_700_002]).unwrap(),
        model_profile_id: profile(),
        generation_params_hash: params_hash(),
        sender: coordinator.installation_id(),
    };
    assert_eq!(
        gate.apply_prefix_commit(&impostor),
        CommitApplyOutcome::CancelRound(CancelRoundFrame {
            session_id: SESSION.to_string(),
            round: 2,
            reason: CancelRoundReason::CommitMismatch,
        })
    );
    assert_eq!(gate.violations_of(&coordinator.installation_id()), 1);
    assert!(!gate.is_torn_down(), "the first violation never tears down");
}

/// RC-1 (security review 2026-10-11, required change): a request
/// arriving on a stream whose QUIC-authenticated remote PeerId differs
/// from the pinned coordinator's fails closed as `bad_frame` BEFORE any
/// admission stage touches state — and the nonce is not consumed, so a
/// retry on the correct stream still admits.
#[test]
fn remote_peer_mismatch_fails_closed_before_stages() {
    let coordinator = fixture_id(0x33);
    let mut gate = gate(&coordinator);
    let frame = build_request(&coordinator, 12, 1, "peer-mismatch-nonce");
    let decision = gate.admit_verify_drafts(
        &serde_json::to_value(&frame).unwrap(),
        NOW,
        NOW,
        "12D3KooWWrongStreamPeerIdFailsClosedBeforeStages",
    );
    match decision {
        AdmissionDecision::FrameRejected(reject) => {
            assert_eq!(reject.code, FrameRejectReason::BadFrame);
        }
        other => panic!("expected bad_frame on remote-peer mismatch, got {other:?}"),
    }
    assert_eq!(gate.state().as_str(), "prefilled");
    // Nothing was consumed: the same frame on the correct stream admits.
    let ok = gate.admit_verify_drafts(
        &serde_json::to_value(&frame).unwrap(),
        NOW,
        NOW,
        &peer_of(&coordinator),
    );
    assert!(
        matches!(ok, AdmissionDecision::Admitted { .. }),
        "correct-stream retry must admit after a mismatch reject"
    );
}

/// The RC-5(b) stale-exemption's OUTSTANDING-GATED CORNER (light-up
/// disposition review, 2026-10-12; ADR-032 revision 4 §8 RC-5(b)). The
/// landed stale condition is `outstanding.is_none() && round <=
/// last_handled && round > last_committed`: a late commit for an OLDER
/// abandoned round that arrives while a NEWER round is outstanding does
/// NOT hit the exempt path — the outstanding result is for the NEWER
/// round, so reproduction fails and the commit is charged
/// `commit_mismatch` (a violation), and the abandonment it triggers also
/// discards the NEWER round's outstanding result. Read against the ADR
/// letter ("a round already abandoned — handled but uncommitted, no
/// outstanding result left to reproduce against" — round-scoped), this
/// corner is STRICTER than the letter: the older round's result is gone,
/// so the letter would classify it as an exempt stale no-op.
/// Reachability: NOT reachable by an honest coordinator on one ordered
/// session stream (the shipped client commits round n before requesting
/// round n+k; QUIC/staged frames are ordered, so a delayed commit cannot
/// arrive after a later request it preceded) — only a coordinator that
/// deliberately sends a commit for a round it already abandoned after
/// starting a newer round hits it, and the charge lands on that sender.
/// This pin freezes the CURRENT classification so any move to the
/// round-scoped letter (or an ADR amendment) is a deliberate,
/// review-visible change; it also pins the side effect (the newer
/// outstanding round is abandoned by the mismatch path).
#[tokio::test]
async fn pin_stale_commit_for_older_round_while_newer_outstanding_is_charged() {
    let coordinator = fixture_id(0x51);
    let engine = MockEngine {
        calls: AtomicUsize::new(0),
    };
    let mut gate = gate(&coordinator);
    gate.seed_pre_state(modelswarm_session::verifydrafts::GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        ..Default::default()
    });

    // Round 3 admitted, dispatched, then EXPIRED (abandoned; result
    // discarded — the RC-5(b) discard).
    let frame3 = build_request(&coordinator, 13, 3, "corner-round-3");
    let AdmissionDecision::Admitted {
        deadline_expires_at_ms,
        ..
    } = gate.admit_verify_drafts(
        &serde_json::to_value(&frame3).unwrap(),
        NOW,
        NOW,
        &peer_of(&coordinator),
    )
    else {
        panic!("round 3 must admit");
    };
    assert!(matches!(
        gate.dispatch_outstanding(&engine, NOW, NOW + 35).await,
        DispatchOutcome::Dispatched(_)
    ));
    assert!(gate.expire_wait_commit_if_due(deadline_expires_at_ms + 250));
    assert_eq!(gate.outstanding_round(), None);

    // Round 5 gaps forward (RC-5(c)) and is dispatched — its result is
    // now the OUTSTANDING one.
    let frame5 = build_request(&coordinator, 14, 5, "corner-round-5");
    assert!(matches!(
        gate.admit_verify_drafts(
            &serde_json::to_value(&frame5).unwrap(),
            NOW,
            NOW,
            &peer_of(&coordinator),
        ),
        AdmissionDecision::Admitted { .. }
    ));
    assert!(matches!(
        gate.dispatch_outstanding(&engine, NOW, NOW + 35).await,
        DispatchOutcome::Dispatched(_)
    ));
    assert_eq!(gate.outstanding_round(), Some(5));

    // A late REPRODUCING-AS-OF-ROUND-3 commit (parent = genesis = the
    // committed hash) while round 5 is outstanding: the outstanding-gated
    // stale exemption does NOT fire — charged commit_mismatch with ONE
    // violation, never applied, and round 5's outstanding result is
    // discarded by the abandonment.
    let mut committed3 = frame3.window_tokens.to_vec();
    committed3.push(999);
    let late3 = CommitPrefix {
        session_id: SESSION.to_string(),
        round: 3,
        previous_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        accepted_token_ids: committed3.clone(),
        new_prefix_hash: compute_prefix_hash(GENESIS_PREFIX_HASH, &committed3).unwrap(),
        model_profile_id: profile(),
        generation_params_hash: params_hash(),
        sender: coordinator.installation_id(),
    };
    assert_eq!(
        gate.apply_prefix_commit(&late3),
        CommitApplyOutcome::CancelRound(CancelRoundFrame {
            session_id: SESSION.to_string(),
            round: 3,
            reason: CancelRoundReason::CommitMismatch,
        })
    );
    assert_eq!(gate.violations_of(&coordinator.installation_id()), 1);
    assert_eq!(gate.committed_prefix_hash(), GENESIS_PREFIX_HASH);
    assert_eq!(gate.last_committed_round(), 0);
    assert_eq!(
        gate.outstanding_round(),
        None,
        "the mismatch path also abandons the NEWER outstanding round"
    );
    assert!(!gate.is_torn_down(), "the first violation never tears down");
}

/// The §2 `PrefixCommit` carrier sender check (ADR-032 revision 4
/// §2/G2): the carrier carries NO signature — its `sender` MUST equal the
/// installation id pinned from the authenticated channel (the same pinned
/// coordinator key that authenticates every `VerifyDrafts`), and a
/// mismatch is `bad_frame` BEFORE any state is touched (no violation
/// counter, no teardown, nothing consumed).
#[tokio::test]
async fn pin_carrier_sender_mismatch_is_bad_frame_before_state() {
    let coordinator = fixture_id(0x41);
    let stranger = fixture_id(0x42);
    let engine = MockEngine {
        calls: AtomicUsize::new(0),
    };
    let mut gate = gate(&coordinator);
    gate.seed_pre_state(modelswarm_session::verifydrafts::GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        ..Default::default()
    });
    let frame = build_request(&coordinator, 13, 2, "sender-nonce");
    assert!(matches!(
        gate.admit_verify_drafts(
            &serde_json::to_value(&frame).unwrap(),
            NOW,
            NOW,
            &peer_of(&coordinator),
        ),
        AdmissionDecision::Admitted { .. }
    ));
    let DispatchOutcome::Dispatched(result) =
        gate.dispatch_outstanding(&engine, NOW, NOW + 35).await
    else {
        panic!("dispatch must succeed")
    };

    // A perfectly REPRODUCING commit carrying a foreign sender: bad_frame
    // (the carrier's only authentication is the channel — a foreign
    // sender label fails closed), no violation, no teardown, and the
    // round STAYS outstanding for a correctly-sent retry.
    let mut committed = frame.window_tokens.to_vec();
    committed.push(999);
    let mut foreign_sender = CommitPrefix {
        session_id: SESSION.to_string(),
        round: 2,
        previous_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        accepted_token_ids: committed.clone(),
        new_prefix_hash: result.new_prefix_hash.clone(),
        model_profile_id: profile(),
        generation_params_hash: params_hash(),
        sender: stranger.installation_id(),
    };
    match gate.apply_prefix_commit(&foreign_sender) {
        CommitApplyOutcome::FrameRejected(rejection) => {
            assert_eq!(rejection.code, FrameRejectReason::BadFrame);
        }
        other => panic!("foreign-sender carrier must be bad_frame, got {other:?}"),
    }
    assert_eq!(gate.violations_of(&stranger.installation_id()), 0);
    assert_eq!(gate.violations_of(&coordinator.installation_id()), 0);
    assert!(!gate.is_torn_down());
    assert_eq!(
        gate.outstanding_round(),
        Some(2),
        "the round stays outstanding — nothing was consumed"
    );

    // The same commit under the pinned sender applies (RC-4).
    foreign_sender.sender = coordinator.installation_id();
    assert_eq!(
        gate.apply_prefix_commit(&foreign_sender),
        CommitApplyOutcome::Advanced { round: 2 }
    );
    assert_eq!(gate.committed_output_tokens(), committed.len() as u64);
}
