//! ADR-032 coordinator-side properties for result admission (RC-3),
//! timing trust (RC-2), the audit path (RC-1), and negotiation honesty
//! (implementation plan §4.4; venue: per-push, default features — §7
//! execution-venue matrix, item "I2 coordinator property,
//! `SessionAccept` honesty, `verify_pass_ms` cross-check").
//!
//! The four property groups follow plan §4.4 items 1–4 exactly:
//!
//! 1. **I2 hostile fake verifier**: a mock verifier returning
//!    false-but-hash-consistent results passes RC-3 (that is the point —
//!    a false result is not detectable from the signature or the hash
//!    chain alone) and is caught by the `WindowAuditor` mock:
//!    `verifier_divergence` recorded, session switched to the
//!    `SingleDecode` fallback, receipt marked.
//! 2. **RC-3 (a)–(e) negatives** → dropped/violation with no state
//!    change; consumed-nonce replays dropped; second violation by the
//!    same peer → teardown (threshold exactly two).
//! 3. **`SessionAccept` honesty**: `batch_verify: true` requires an
//!    in-range `batch_window_max`; `batch_verify: false` peers are
//!    first-class singles, never selected as batch verifiers; backend
//!    mismatch → `SessionReject("backend_mismatch")`.
//! 4. **`verify_pass_ms` cross-check**: a claimed value above the
//!    measured wall time by more than 25 ms fires `verify_ms_lie` (via
//!    a mock `VerifyTelemetry`) and de-ranks; per-verifier isolation —
//!    one lying peer never de-ranks another.
//!
//! The coordinator is a pure state machine — no clock reads, no engine
//! access; the QUIC-authenticated remote PeerId of RC-3 (a) is supplied
//! as a parameter exactly as the serve loop would supply it.

use modelswarm_identity::InstallationIdentity;
use modelswarm_runtime::SamplingParams;
use modelswarm_session::negotiation::{
    Backend, EngineDisclosure, Preset, SessionAccept, SessionBudget, SessionOffer, SessionReject,
    SessionRejectReason,
};
use modelswarm_session::verifydrafts::{
    batch_generation_params_hash, eligible_batch_verifier, peer_reject_reason, sign_verify_drafts,
    sign_verify_drafts_result, validate_session_accept, AuditAction, AuditSampler, AuditVerdict,
    CrossCheckOutcome, ReceiptOutcome, ResultAdmission, ResultDrop, ResultViolation,
    SessionAcceptError, TrackRequestError, VerifierTimings, VerifyDrafts, VerifyDraftsCoordinator,
    VerifyDraftsCoordinatorConfig, VerifyDraftsResult, VerifyTelemetry, WindowAuditor,
    WindowOutcome, EWMA_ALPHA_DEFAULT, RECEIPT_COUNTER_HONESTY_LABEL,
    TEARDOWN_REASON_RESULT_VIOLATION, TEARDOWN_VIOLATION_THRESHOLD, VERIFY_PASS_CLOCK_NOISE_MS,
    WINDOW_CAP,
};
use modelswarm_session::{compute_prefix_hash, GENESIS_PREFIX_HASH};
use proptest::prelude::*;
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Fixture material
// ---------------------------------------------------------------------------

const SESSION: &str = "sess-coord-prop";
/// Distinctive token ids so privacy-style assertions can search for them.
const BASE_WINDOW: [u32; 4] = [9_100_101, 9_100_102, 9_100_103, 9_100_104];

fn fixture_id(seed: u8) -> InstallationIdentity {
    InstallationIdentity::from_bytes(&[seed; 32])
}

fn profile() -> String {
    format!("msp1:{}", "ab".repeat(32))
}

fn params_hash() -> String {
    batch_generation_params_hash(&SamplingParams::default()).unwrap()
}

fn coordinator(verifier: &InstallationIdentity) -> VerifyDraftsCoordinator {
    VerifyDraftsCoordinator::new(VerifyDraftsCoordinatorConfig {
        session_id: SESSION.to_string(),
        profile_id: profile(),
        generation_params_hash: params_hash(),
        verifier_key: verifier.verifying_key(),
    })
    .expect("coordinator config is valid")
}

fn build_request(
    coordinator_id: &InstallationIdentity,
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
        window_tokens: BASE_WINDOW.to_vec(),
        proposer_id: "12D3KooProposer".to_string(),
        nonce: nonce.to_string(),
        deadline_ms: 2_500,
        sender: coordinator_id.installation_id(),
        signature: String::new(),
    };
    msg.signature = sign_verify_drafts(&msg, coordinator_id).unwrap();
    msg
}

/// A result for `req`'s round with arbitrary shape fields — the HOSTILE
/// verifier model: the verifier signs whatever it claims (a valid
/// signature proves origin, never honesty). Echoes the request's nonce.
fn result_draft(
    verifier_id: &InstallationIdentity,
    req: &VerifyDrafts,
    seq: u64,
    accepted_prefix_len: u32,
    divergence_point: Option<u32>,
    correction: Option<u32>,
    new_prefix_hash: String,
) -> VerifyDraftsResult {
    let mut msg = VerifyDraftsResult {
        session_id: req.session_id.clone(),
        protocol_version: "msp-cooperative-v1".to_string(),
        seq,
        round: req.round,
        accepted_prefix_len,
        divergence_point,
        correction,
        new_prefix_hash,
        verify_pass_ms: 35,
        nonce_echo: req.nonce.clone(),
        sender: verifier_id.installation_id(),
        signature: String::new(),
    };
    msg.signature = sign_verify_drafts_result(&msg, verifier_id).unwrap();
    msg
}

/// An internally-consistent result: divergence derived from
/// `accepted` vs the window length, `new_prefix_hash` recomputed over
/// `(parent ‖ accepted ‖ [correction])` — honest on shape, whatever the
/// claimed numbers.
fn honest_result(
    verifier_id: &InstallationIdentity,
    req: &VerifyDrafts,
    seq: u64,
    accepted: u32,
    correction: Option<u32>,
) -> VerifyDraftsResult {
    let divergence = (accepted < req.window_tokens.len() as u32).then_some(accepted);
    let mut committed = req.window_tokens[..accepted as usize].to_vec();
    if let Some(token) = correction {
        committed.push(token);
    }
    let hash = compute_prefix_hash(&req.parent_prefix_hash, &committed).unwrap();
    result_draft(
        verifier_id,
        req,
        seq,
        accepted,
        divergence,
        correction,
        hash,
    )
}

fn wire(msg: &VerifyDraftsResult) -> Value {
    serde_json::to_value(msg).unwrap()
}

/// A fresh coordinator with one tracked round-3 request (`seq` 12,
/// nonce `prop-nonce`), against the 0x22 verifier.
fn fresh_with_request() -> (
    VerifyDraftsCoordinator,
    VerifyDrafts,
    InstallationIdentity,
    InstallationIdentity,
) {
    let coordinator_id = fixture_id(0x11);
    let verifier = fixture_id(0x22);
    let request = build_request(&coordinator_id, 12, 3, "prop-nonce");
    let mut coord = coordinator(&verifier);
    coord.track_request(&request).unwrap();
    (coord, request, coordinator_id, verifier)
}

/// Flips the first hex character of a bare hash (tamper helper).
fn flip_first_hex_char(hash: &str) -> String {
    let mut bytes = hash.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).unwrap()
}

// ---------------------------------------------------------------------------
// Mocks (plan §4.3 surfaces, node/desktop implement in production)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockTelemetry {
    events: Mutex<Vec<(&'static str, String, String)>>,
}

impl MockTelemetry {
    fn push(&self, kind: &'static str, a: &str, b: &str) {
        self.events
            .lock()
            .unwrap()
            .push((kind, a.to_string(), b.to_string()));
    }

    fn count(&self, kind: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _, _)| *k == kind)
            .count()
    }

    fn only(&self, kind: &str) -> (String, String) {
        let matching: Vec<_> = self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _, _)| *k == kind)
            .map(|(_, a, b)| (a.clone(), b.clone()))
            .collect();
        assert_eq!(matching.len(), 1, "exactly one {kind} event expected");
        matching.into_iter().next().unwrap()
    }
}

impl VerifyTelemetry for MockTelemetry {
    fn verify_ms_lie(&self, session_id: &str, peer: &str) {
        self.push("verify_ms_lie", session_id, peer);
    }
    fn verifier_divergence(&self, session_id: &str, peer: &str) {
        self.push("verifier_divergence", session_id, peer);
    }
    fn budget_refused(&self, session_id: &str, code: &str) {
        self.push("budget_refused", session_id, code);
    }
}

struct MockAuditor {
    verdict: AuditVerdict,
    calls: AtomicUsize,
}

impl MockAuditor {
    fn with(verdict: AuditVerdict) -> Self {
        Self {
            verdict,
            calls: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl WindowAuditor for MockAuditor {
    async fn audit_window(
        &self,
        _prompt_tokens: &[u32],
        _committed_before: &[u32],
        _window_commit: &[u32],
    ) -> Result<AuditVerdict, modelswarm_runtime::RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.verdict)
    }
}

// ---------------------------------------------------------------------------
// Plan §4.4 item 2 — RC-3 admission (happy path, negatives, replays,
// teardown)
// ---------------------------------------------------------------------------

#[test]
fn rc3_accepts_honest_results_and_consumes_the_nonce() {
    let (mut coord, request, _c, verifier) = fresh_with_request();

    // Full acceptance: committed = window[..4] ++ [bonus].
    let result = honest_result(&verifier, &request, 4, 4, Some(999));
    assert_eq!(
        coord.admit_result(&wire(&result), &verifier.peer_id()),
        ResultAdmission::Accepted {
            committed: vec![9_100_101, 9_100_102, 9_100_103, 9_100_104, 999],
        }
    );
    assert!(
        coord.nonce_consumed(&request.nonce),
        "first valid result consumes the nonce"
    );
    assert!(coord.outstanding_request().is_none());
    assert_eq!(coord.committed_prefix_hash(), result.new_prefix_hash);
    assert_eq!(coord.verifier_last_seq(), Some(4));
    assert_eq!(coord.last_accepted_round(), Some(3));

    // The next round chains onto the accepted hash; the verifier's next
    // result must carry a strictly greater seq (RC-7 mirror).
    let mut next = build_request(&fixture_id(0x11), 13, 4, "prop-nonce-2");
    next.parent_prefix_hash = result.new_prefix_hash.clone();
    coord.track_request(&next).unwrap();
    let next_result = honest_result(&verifier, &next, 5, 2, Some(777));
    assert_eq!(
        coord.admit_result(&wire(&next_result), &verifier.peer_id()),
        ResultAdmission::Accepted {
            committed: vec![9_100_101, 9_100_102, 777],
        }
    );

    // Partial acceptance (fresh coordinator): divergence == accepted.
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let partial = honest_result(&verifier, &request, 4, 2, Some(777));
    assert_eq!(partial.divergence_point, Some(2));
    assert_eq!(
        coord.admit_result(&wire(&partial), &verifier.peer_id()),
        ResultAdmission::Accepted {
            committed: vec![9_100_101, 9_100_102, 777],
        }
    );

    // EOG shape (F-2): full acceptance, correction null, prefix-only
    // commit — hash over the accepted prefix only, admitted.
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let eog = honest_result(&verifier, &request, 4, 4, None);
    assert_eq!(
        coord.admit_result(&wire(&eog), &verifier.peer_id()),
        ResultAdmission::Accepted {
            committed: BASE_WINDOW.to_vec(),
        }
    );
}

#[test]
fn rc3_a_signature_sender_and_remote_peer_negatives() {
    let other = fixture_id(0x33);

    // Signature by the WRONG key (sender names the other identity): the
    // pinned-key check fails.
    let (mut coord, request, _c, _v) = fresh_with_request();
    let wrong_key = result_draft(
        &other,
        &request,
        4,
        4,
        None,
        Some(999),
        compute_prefix_hash(GENESIS_PREFIX_HASH, &[9_100_101]).unwrap(),
    );
    assert_eq!(
        coord.admit_result(&wire(&wrong_key), &other.peer_id()),
        ResultAdmission::Violation(ResultViolation::Signature)
    );
    assert!(!coord.nonce_consumed(&request.nonce), "no state change");
    assert!(coord.outstanding_request().is_some());
    assert_eq!(coord.violations_of(&other.peer_id()), 1);

    // Foreign sender label under a valid pinned-key signature cannot be
    // built without failing the derivation check — pin that the label
    // mismatch also lands on Signature.
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let mut foreign = honest_result(&verifier, &request, 4, 4, Some(999));
    foreign.sender = "someone-else".to_string();
    foreign.signature = sign_verify_drafts_result(&foreign, &verifier).unwrap();
    assert_eq!(
        coord.admit_result(&wire(&foreign), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::Signature)
    );

    // Remote-peer equality (msp-v1 §6.6): the stream's QUIC PeerId must
    // equal the PeerId derived from the pinned verifier key — an honest
    // result arriving on the WRONG stream is a violation.
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let honest = honest_result(&verifier, &request, 4, 4, Some(999));
    assert_eq!(
        coord.admit_result(&wire(&honest), &other.peer_id()),
        ResultAdmission::Violation(ResultViolation::RemotePeer)
    );
    // … and admits on the right stream.
    assert_eq!(
        coord.admit_result(&wire(&honest), &verifier.peer_id()),
        ResultAdmission::Accepted {
            committed: vec![9_100_101, 9_100_102, 9_100_103, 9_100_104, 999]
        }
    );
}

#[test]
fn rc3_b_nonce_echo_negative() {
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let mut wrong_echo = honest_result(&verifier, &request, 4, 4, Some(999));
    wrong_echo.nonce_echo = "not-the-nonce".to_string();
    wrong_echo.signature = sign_verify_drafts_result(&wrong_echo, &verifier).unwrap();
    assert_eq!(
        coord.admit_result(&wire(&wrong_echo), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::NonceEcho)
    );
    assert!(!coord.nonce_consumed(&request.nonce));
    assert!(coord.outstanding_request().is_some());
    // A nonce that was never issued (fabricated) fails the same check.
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let mut fabricated = honest_result(&verifier, &request, 4, 4, Some(999));
    fabricated.nonce_echo = "never-issued".to_string();
    fabricated.signature = sign_verify_drafts_result(&fabricated, &verifier).unwrap();
    assert_eq!(
        coord.admit_result(&wire(&fabricated), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::NonceEcho)
    );
}

#[test]
fn rc3_c_binding_negatives() {
    // session_id
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let mut other_session = honest_result(&verifier, &request, 4, 4, Some(999));
    other_session.session_id = "sess-other".to_string();
    other_session.signature = sign_verify_drafts_result(&other_session, &verifier).unwrap();
    assert_eq!(
        coord.admit_result(&wire(&other_session), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::Binding("session_id"))
    );

    // protocol_version
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let mut other_version = honest_result(&verifier, &request, 4, 4, Some(999));
    other_version.protocol_version = "msp-v1".to_string();
    other_version.signature = sign_verify_drafts_result(&other_version, &verifier).unwrap();
    assert_eq!(
        coord.admit_result(&wire(&other_version), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::Binding("protocol_version"))
    );

    // round
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let mut other_round = honest_result(&verifier, &request, 4, 4, Some(999));
    other_round.round = 99;
    other_round.signature = sign_verify_drafts_result(&other_round, &verifier).unwrap();
    assert_eq!(
        coord.admit_result(&wire(&other_round), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::Binding("round"))
    );

    // seq: the RC-7 mirror — a repeated or decreased verifier counter.
    // The first accepted result establishes the baseline (seq 4); the
    // next round's result with seq <= 4 is a violation.
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let first = honest_result(&verifier, &request, 4, 4, Some(999));
    assert!(matches!(
        coord.admit_result(&wire(&first), &verifier.peer_id()),
        ResultAdmission::Accepted { .. }
    ));
    let mut next = build_request(&fixture_id(0x11), 13, 4, "prop-nonce-2");
    next.parent_prefix_hash = first.new_prefix_hash.clone();
    coord.track_request(&next).unwrap();
    for repeated_seq in [4u64, 3] {
        // Fresh coordinator per case (two violations in a row against
        // one coordinator would — correctly — tear the session down),
        // with the seq baseline established by ONE accepted result.
        let mut fresh = coordinator(&verifier);
        fresh.track_request(&request).unwrap();
        let baseline = honest_result(&verifier, &request, 4, 4, Some(999));
        assert!(matches!(
            fresh.admit_result(&wire(&baseline), &verifier.peer_id()),
            ResultAdmission::Accepted { .. }
        ));
        fresh.track_request(&next).unwrap();
        let mut stale_seq = honest_result(&verifier, &next, repeated_seq, 4, Some(999));
        stale_seq.signature = sign_verify_drafts_result(&stale_seq, &verifier).unwrap();
        assert_eq!(
            fresh.admit_result(&wire(&stale_seq), &verifier.peer_id()),
            ResultAdmission::Violation(ResultViolation::Binding("seq")),
            "seq {repeated_seq} <= last seen 4 must violate"
        );
    }
    // A strictly greater seq admits (5).
    let good = honest_result(&verifier, &next, 5, 4, Some(999));
    assert!(matches!(
        coord.admit_result(&wire(&good), &verifier.peer_id()),
        ResultAdmission::Accepted { .. }
    ));

    // profile: the result wire carries no profile_id (§1 shape) — the
    // profile binding rides the session-pinned verifier key (covered by
    // the Signature negative above) and the request tracking:
    let (mut coord, _request, coordinator_id, _v) = fresh_with_request();
    let mut wrong_profile_request = build_request(&coordinator_id, 14, 5, "prop-nonce-3");
    wrong_profile_request.profile_id = format!("msp1:{}", "cd".repeat(32));
    wrong_profile_request.signature =
        sign_verify_drafts(&wrong_profile_request, &coordinator_id).unwrap();
    assert_eq!(
        coord.track_request(&wrong_profile_request).unwrap_err(),
        TrackRequestError::Binding("profile_id")
    );

    // parent: likewise not on the result wire — enforced transitively
    // through (e): a hash computed under a different parent cannot
    // recompute (pinned in the (e) test below).
}

#[test]
fn rc3_d_bounds_and_divergence_negatives() {
    // accepted_prefix_len > len(window_tokens).
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let over_long = result_draft(&verifier, &request, 4, 5, None, Some(999), "0".repeat(64));
    assert_eq!(
        coord.admit_result(&wire(&over_long), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::AcceptedPrefixBounds)
    );

    // divergence_point != accepted_prefix_len on a partial acceptance.
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let mut mismatched = honest_result(&verifier, &request, 4, 2, Some(777));
    mismatched.divergence_point = Some(1);
    mismatched.signature = sign_verify_drafts_result(&mismatched, &verifier).unwrap();
    assert_eq!(
        coord.admit_result(&wire(&mismatched), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::DivergenceInconsistent)
    );

    // Partial acceptance claiming divergence null (full-acceptance shape).
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let mut null_divergence = honest_result(&verifier, &request, 4, 2, Some(777));
    null_divergence.divergence_point = None;
    null_divergence.signature = sign_verify_drafts_result(&null_divergence, &verifier).unwrap();
    assert_eq!(
        coord.admit_result(&wire(&null_divergence), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::DivergenceInconsistent)
    );

    // Full acceptance claiming a divergence point.
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let mut full_with_divergence = honest_result(&verifier, &request, 4, 4, Some(999));
    full_with_divergence.divergence_point = Some(4);
    full_with_divergence.signature =
        sign_verify_drafts_result(&full_with_divergence, &verifier).unwrap();
    assert_eq!(
        coord.admit_result(&wire(&full_with_divergence), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::DivergenceInconsistent)
    );

    // None of the above consumed the nonce or answered the round.
    assert!(!coord.nonce_consumed(&request.nonce));
    assert!(coord.outstanding_request().is_some());
}

#[test]
fn rc3_e_hash_recomputation_negatives() {
    // Tampered hash (properly signed — a hostile verifier can sign a
    // false claim; the recomputation catches it).
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let mut tampered = honest_result(&verifier, &request, 4, 4, Some(999));
    tampered.new_prefix_hash = flip_first_hex_char(&tampered.new_prefix_hash);
    tampered.signature = sign_verify_drafts_result(&tampered, &verifier).unwrap();
    assert_eq!(
        coord.admit_result(&wire(&tampered), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::NewPrefixHash)
    );
    assert!(!coord.nonce_consumed(&request.nonce));

    // The same committed ids claimed under the WRONG parent (a foreign
    // chain) cannot recompute — the RC-3(c) parent equality, enforced
    // transitively through (e).
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let mut committed = BASE_WINDOW.to_vec();
    committed.push(999);
    let hash_under_other_parent = compute_prefix_hash(&"0f".repeat(32), &committed).unwrap();
    let wrong_parent = result_draft(
        &verifier,
        &request,
        4,
        4,
        None,
        Some(999),
        hash_under_other_parent,
    );
    assert_eq!(
        coord.admit_result(&wire(&wrong_parent), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::NewPrefixHash)
    );

    // A hash consistent with a DIFFERENT accepted length than claimed
    // (shape (d) holds, the hash pins the other length).
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let mut committed_short = BASE_WINDOW[..2].to_vec();
    committed_short.push(777);
    let hash_of_short = compute_prefix_hash(&request.parent_prefix_hash, &committed_short).unwrap();
    let swapped = result_draft(&verifier, &request, 4, 3, Some(3), Some(777), hash_of_short);
    assert_eq!(
        coord.admit_result(&wire(&swapped), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::NewPrefixHash)
    );
}

#[test]
fn rc3_drops_replays_and_unsolicited_results_with_no_state_change() {
    // No outstanding request at all.
    let verifier = fixture_id(0x22);
    let coordinator_id = fixture_id(0x11);
    let mut coord = coordinator(&verifier);
    let orphan = honest_result(
        &verifier,
        &build_request(&coordinator_id, 12, 3, "prop-nonce"),
        4,
        4,
        Some(999),
    );
    assert_eq!(
        coord.admit_result(&wire(&orphan), &verifier.peer_id()),
        ResultAdmission::Dropped(ResultDrop::NoOutstandingRequest)
    );
    assert_eq!(coord.violations_of(&verifier.peer_id()), 0);

    // Replayed genuine result after acceptance (consumed nonce).
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let result = honest_result(&verifier, &request, 4, 4, Some(999));
    assert!(matches!(
        coord.admit_result(&wire(&result), &verifier.peer_id()),
        ResultAdmission::Accepted { .. }
    ));
    assert_eq!(
        coord.admit_result(&wire(&result), &verifier.peer_id()),
        ResultAdmission::Dropped(ResultDrop::ConsumedNonce),
        "a replayed genuine signed result is undetectable-to-harmless"
    );
    assert_eq!(coord.violations_of(&verifier.peer_id()), 0);
    assert_eq!(coord.committed_prefix_hash(), result.new_prefix_hash);

    // Late genuine result for an ABANDONED round: the nonce was consumed
    // at abandonment — a harmless drop, not a violation.
    let (mut coord, request, _c, verifier) = fresh_with_request();
    assert!(coord.abandon_outstanding_request());
    let late = honest_result(&verifier, &request, 4, 4, Some(999));
    assert_eq!(
        coord.admit_result(&wire(&late), &verifier.peer_id()),
        ResultAdmission::Dropped(ResultDrop::ConsumedNonce)
    );
    assert_eq!(coord.violations_of(&verifier.peer_id()), 0);

    // Replaced round: tracking a new request consumes the old nonce too.
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let next = build_request(&fixture_id(0x11), 13, 4, "prop-nonce-2");
    coord.track_request(&next).unwrap();
    let stale = honest_result(&verifier, &request, 4, 4, Some(999));
    assert_eq!(
        coord.admit_result(&wire(&stale), &verifier.peer_id()),
        ResultAdmission::Dropped(ResultDrop::ConsumedNonce)
    );
}

#[test]
fn rc3_second_violation_by_same_peer_tears_down_exactly_at_two() {
    assert_eq!(TEARDOWN_VIOLATION_THRESHOLD, 2, "the threshold is two");
    let (mut coord, request, _c, verifier) = fresh_with_request();

    // First violation: counted, session alive, round still outstanding.
    let mut bad_nonce = honest_result(&verifier, &request, 4, 4, Some(999));
    bad_nonce.nonce_echo = "wrong".to_string();
    bad_nonce.signature = sign_verify_drafts_result(&bad_nonce, &verifier).unwrap();
    assert_eq!(
        coord.admit_result(&wire(&bad_nonce), &verifier.peer_id()),
        ResultAdmission::Violation(ResultViolation::NonceEcho)
    );
    assert!(!coord.is_torn_down());
    assert_eq!(coord.violations_of(&verifier.peer_id()), 1);
    assert!(
        coord.outstanding_request().is_some(),
        "round still outstanding"
    );

    // Second violation by the SAME peer: teardown with the honest reason.
    let mut bad_hash = honest_result(&verifier, &request, 4, 4, Some(999));
    bad_hash.new_prefix_hash = flip_first_hex_char(&bad_hash.new_prefix_hash);
    bad_hash.signature = sign_verify_drafts_result(&bad_hash, &verifier).unwrap();
    assert_eq!(
        coord.admit_result(&wire(&bad_hash), &verifier.peer_id()),
        ResultAdmission::TornDown(ResultViolation::NewPrefixHash)
    );
    assert!(coord.is_torn_down());
    assert_eq!(
        coord.teardown_reason(),
        Some(TEARDOWN_REASON_RESULT_VIOLATION)
    );
    assert_eq!(coord.violations_of(&verifier.peer_id()), 2);

    // After teardown everything drops, nothing counts.
    let honest = honest_result(&verifier, &request, 5, 4, Some(999));
    assert_eq!(
        coord.admit_result(&wire(&honest), &verifier.peer_id()),
        ResultAdmission::Dropped(ResultDrop::SessionTornDown)
    );
    assert_eq!(coord.violations_of(&verifier.peer_id()), 2);
    assert_eq!(
        coord.track_request(&request).unwrap_err(),
        TrackRequestError::SessionTornDown
    );

    // "By the same peer": one violation from EACH of two distinct peers
    // does NOT tear the session down.
    let (mut coord, request, _c, _verifier) = fresh_with_request();
    let peer_x = fixture_id(0x33);
    let peer_y = fixture_id(0x44);
    let garbage_x = result_draft(&peer_x, &request, 4, 4, None, Some(999), "0".repeat(64));
    assert_eq!(
        coord.admit_result(&wire(&garbage_x), &peer_x.peer_id()),
        ResultAdmission::Violation(ResultViolation::Signature)
    );
    let garbage_y = result_draft(&peer_y, &request, 4, 4, None, Some(999), "0".repeat(64));
    assert_eq!(
        coord.admit_result(&wire(&garbage_y), &peer_y.peer_id()),
        ResultAdmission::Violation(ResultViolation::Signature)
    );
    assert!(
        !coord.is_torn_down(),
        "one violation per peer is below the threshold"
    );
    assert_eq!(coord.violations_of(&peer_x.peer_id()), 1);
    assert_eq!(coord.violations_of(&peer_y.peer_id()), 1);
}

proptest! {
    /// RC-3 (e) on random windows: an internally-consistent result admits
    /// with exactly the recomputable committed ids, and any tampered
    /// hash (properly re-signed by the hostile verifier) is caught.
    #[test]
    fn rc3_e_catches_tampered_hashes_on_random_windows(
        window in prop::collection::vec(100u32..100_000, 1..=8),
        accepted in 0u32..8,
        correction in proptest::option::of(100u32..100_000),
        seq in 1u64..1_000,
    ) {
        let accepted = accepted.min(window.len() as u32);
        let coordinator_id = fixture_id(0x11);
        let verifier = fixture_id(0x22);
        let mut request = build_request(&coordinator_id, 12, 3, "prop-nonce");
        request.window_tokens = window.clone();
        request.signature = sign_verify_drafts(&request, &coordinator_id).unwrap();

        let mut expected = window[..accepted as usize].to_vec();
        if let Some(token) = correction {
            expected.push(token);
        }

        // Honest-shape result admits.
        let mut coord = coordinator(&verifier);
        coord.track_request(&request).unwrap();
        let honest = honest_result(&verifier, &request, seq, accepted, correction);
        prop_assert_eq!(
            coord.admit_result(&wire(&honest), &verifier.peer_id()),
            ResultAdmission::Accepted { committed: expected }
        );

        // Tampered hash on a fresh coordinator (same outstanding round):
        // the recomputation catches it no matter the window shape.
        let mut coord2 = coordinator(&verifier);
        coord2.track_request(&request).unwrap();
        let mut hostile = honest_result(&verifier, &request, seq, accepted, correction);
        hostile.new_prefix_hash = flip_first_hex_char(&hostile.new_prefix_hash);
        hostile.signature = sign_verify_drafts_result(&hostile, &verifier).unwrap();
        prop_assert_eq!(
            coord2.admit_result(&wire(&hostile), &verifier.peer_id()),
            ResultAdmission::Violation(ResultViolation::NewPrefixHash)
        );
    }
}

// ---------------------------------------------------------------------------
// Plan §4.4 item 1 — I2: hostile fake verifier caught by the audit path
// ---------------------------------------------------------------------------

#[test]
fn i2_hostile_fake_verifier_caught_by_the_audit_path() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime");
    let (mut coord, request, _c, verifier) = fresh_with_request();

    // The fake verifier claims FULL acceptance with a bonus token —
    // false (the true engine would have rejected at position 2) but
    // hash-CONSISTENT and properly signed: RC-3 admits it. This is
    // exactly why I2 needs the audit path: a false result is not
    // detectable from the signature or the hash chain alone.
    let false_result = honest_result(&verifier, &request, 4, 4, Some(9_200_999));
    let committed = match coord.admit_result(&wire(&false_result), &verifier.peer_id()) {
        ResultAdmission::Accepted { committed } => committed,
        other => panic!("false-but-hash-consistent result must pass RC-3: {other:?}"),
    };

    // Sampling policy (RC-1): the first committed window is audited.
    let mut sampler = AuditSampler::new();
    assert!(sampler.sample(WindowOutcome::of(false_result.divergence_point)));

    // The coordinator's own cache-cold re-execution diverges at index 2.
    let telemetry = MockTelemetry::default();
    let auditor = MockAuditor::with(AuditVerdict::Divergence { at_index: 2 });
    let action = rt
        .block_on(coord.audit_committed_window(&auditor, &telemetry, &[1, 2, 3], &[], &committed))
        .expect("audit runs");
    assert_eq!(action, AuditAction::SwitchedToSingleDecode);

    // verifier_divergence recorded against the verifier's identity …
    let (session, peer) = telemetry.only("verifier_divergence");
    assert_eq!(session, SESSION);
    assert_eq!(peer, verifier.installation_id());
    // … session switched to SingleDecode for the remainder, receipt marked.
    assert!(coord.in_single_decode_fallback());
    assert_eq!(coord.receipt_outcome(), ReceiptOutcome::AuditDivergence);
    // Idempotent: an already-fallback session runs no further audits.
    let action = rt
        .block_on(coord.audit_committed_window(&auditor, &telemetry, &[1, 2, 3], &[], &committed))
        .expect("audit short-circuits");
    assert_eq!(action, AuditAction::SwitchedToSingleDecode);
    assert_eq!(auditor.calls(), 1, "no second engine re-execution");
    assert_eq!(telemetry.count("verifier_divergence"), 1);

    // The Match control: an honest verifier's audited window matches —
    // no telemetry, no fallback, clean receipt.
    let (mut coord, request, _c, verifier) = fresh_with_request();
    let result = honest_result(&verifier, &request, 4, 2, Some(777));
    let committed = match coord.admit_result(&wire(&result), &verifier.peer_id()) {
        ResultAdmission::Accepted { committed } => committed,
        other => panic!("honest result must admit: {other:?}"),
    };
    let telemetry = MockTelemetry::default();
    let auditor = MockAuditor::with(AuditVerdict::Match);
    let action = rt
        .block_on(coord.audit_committed_window(&auditor, &telemetry, &[1, 2, 3], &[], &committed))
        .expect("audit runs");
    assert_eq!(action, AuditAction::Continue);
    assert!(!coord.in_single_decode_fallback());
    assert_eq!(coord.receipt_outcome(), ReceiptOutcome::Clean);
    assert_eq!(telemetry.count("verifier_divergence"), 0);

    // Receipt honesty (RC-1): the counters this family grants are
    // verifier-claimed numbers, documented at intake, no wire fields.
    assert_eq!(RECEIPT_COUNTER_HONESTY_LABEL, "verifier-claimed");
    assert!(!wire(&result)
        .to_string()
        .contains(RECEIPT_COUNTER_HONESTY_LABEL));
}

// ---------------------------------------------------------------------------
// Plan §4.4 item 3 — SessionAccept honesty + backend pairing
// ---------------------------------------------------------------------------

fn sample_offer() -> SessionOffer {
    SessionOffer {
        session_id: SESSION.to_string(),
        protocol_version: "msp-cooperative-v1".to_string(),
        preset: Preset::Verified,
        budget: SessionBudget {
            max_endpoints: 2,
            max_endpoint_seconds: 120,
            max_output_tokens: 2_048,
        },
        verifier_backend: Backend::Cpu,
        profile_id: profile(),
        generation_params_hash: params_hash(),
    }
}

fn sample_accept(engine: EngineDisclosure) -> SessionAccept {
    SessionAccept {
        session_id: SESSION.to_string(),
        protocol_version: "msp-cooperative-v1".to_string(),
        preset: Preset::Verified,
        budget: SessionBudget {
            max_endpoints: 1,
            max_endpoint_seconds: 60,
            max_output_tokens: 512,
        },
        engine,
    }
}

#[test]
fn session_accept_honesty_pins_disclosure_budget_and_echoes() {
    let offer = sample_offer();

    // batch_verify: true REQUIRES batch_window_max in 1..=WINDOW_CAP.
    for out_of_range in [0u32, WINDOW_CAP + 1, u32::MAX] {
        let accept = sample_accept(EngineDisclosure {
            backend: Backend::Cpu,
            batch_verify: true,
            batch_window_max: out_of_range,
        });
        assert_eq!(
            validate_session_accept(&offer, &accept).unwrap_err(),
            SessionAcceptError::InvalidDisclosure,
            "batch_window_max {out_of_range} with batch_verify: true is schema-invalid"
        );
    }
    let valid = sample_accept(EngineDisclosure {
        backend: Backend::Cpu,
        batch_verify: true,
        batch_window_max: 8,
    });
    validate_session_accept(&offer, &valid).unwrap();

    // The effective budget is clamped DOWN only.
    let mut inflated = valid.clone();
    inflated.budget.max_output_tokens = 4_096;
    assert_eq!(
        validate_session_accept(&offer, &inflated).unwrap_err(),
        SessionAcceptError::BudgetInflated("max_output_tokens")
    );
    let mut inflated_seconds = valid.clone();
    inflated_seconds.budget.max_endpoint_seconds = 240;
    assert_eq!(
        validate_session_accept(&offer, &inflated_seconds).unwrap_err(),
        SessionAcceptError::BudgetInflated("max_endpoint_seconds")
    );

    // Echoes are mandatory.
    let mut wrong_session = valid.clone();
    wrong_session.session_id = "sess-other".to_string();
    assert_eq!(
        validate_session_accept(&offer, &wrong_session).unwrap_err(),
        SessionAcceptError::EchoMismatch("session_id")
    );
    let mut wrong_preset = valid.clone();
    wrong_preset.preset = Preset::Fast;
    assert_eq!(
        validate_session_accept(&offer, &wrong_preset).unwrap_err(),
        SessionAcceptError::EchoMismatch("preset")
    );
}

#[test]
fn batch_verify_false_peers_are_first_class_singles_never_batch_verifiers() {
    let offer = sample_offer();
    let capable = sample_accept(EngineDisclosure {
        backend: Backend::Cpu,
        batch_verify: true,
        batch_window_max: 8,
    });
    // An HTTP-adapter peer (ADR-032 §4): declares batch_verify: false
    // with the guidance window max — schema-VALID (a first-class single,
    // eligible proposer), but never selected as a batch verifier.
    let http_peer = sample_accept(EngineDisclosure {
        backend: Backend::Cpu,
        batch_verify: false,
        batch_window_max: 1,
    });
    validate_session_accept(&offer, &http_peer).unwrap();
    // A Vulkan peer under a CPU pairing request is equally ineligible.
    let vulkan_peer = sample_accept(EngineDisclosure {
        backend: Backend::Vulkan,
        batch_verify: true,
        batch_window_max: 8,
    });
    validate_session_accept(&offer, &vulkan_peer).unwrap();

    let roster = [
        ("capable", &capable),
        ("http", &http_peer),
        ("vulkan", &vulkan_peer),
    ];
    let selected: Vec<&str> = roster
        .iter()
        .filter(|(name, accept)| {
            let eligible = eligible_batch_verifier(&offer, accept);
            assert_eq!(
                eligible,
                *name == "capable",
                "selection must pick exactly the capable CPU batch verifier"
            );
            eligible
        })
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(selected, ["capable"]);
}

#[test]
fn backend_mismatch_yields_session_reject_backend_mismatch() {
    let offer = sample_offer();

    // The peer-side honest reject: a differing engine backend rejects
    // with backend_mismatch and the requester falls back to single.
    let vulkan_engine = EngineDisclosure {
        backend: Backend::Vulkan,
        batch_verify: true,
        batch_window_max: 8,
    };
    assert_eq!(
        peer_reject_reason(&offer, &vulkan_engine),
        Some(SessionRejectReason::BackendMismatch)
    );
    let reject = SessionReject {
        session_id: offer.session_id.clone(),
        protocol_version: offer.protocol_version.clone(),
        reason: SessionRejectReason::BackendMismatch,
    };
    let serialized = serde_json::to_value(&reject).unwrap();
    assert_eq!(serialized["reason"], serde_json::json!("backend_mismatch"));
    assert_eq!(serialized["session_id"], serde_json::json!(SESSION));

    // A matching backend does not reject on pairing grounds …
    let cpu_engine = EngineDisclosure {
        backend: Backend::Cpu,
        batch_verify: true,
        batch_window_max: 8,
    };
    assert_eq!(peer_reject_reason(&offer, &cpu_engine), None);
    // … and a batch-verify-INCAPABLE CPU peer does not reject either:
    // it accepts declaring batch_verify: false (ADR-032 §4) and stays a
    // first-class single — never a batch verifier (previous property).
    let http_engine = EngineDisclosure {
        backend: Backend::Cpu,
        batch_verify: false,
        batch_window_max: 1,
    };
    assert_eq!(peer_reject_reason(&offer, &http_engine), None);
}

// ---------------------------------------------------------------------------
// Plan §4.4 item 4 — verify_pass_ms cross-check + per-verifier isolation
// ---------------------------------------------------------------------------

#[test]
fn verify_pass_ms_cross_check_fires_verify_ms_lie_above_the_bound() {
    assert_eq!(VERIFY_PASS_CLOCK_NOISE_MS, 25, "the +25 ms bound");
    let telemetry = MockTelemetry::default();
    let mut timings = VerifierTimings::new();
    let peer = "12D3KooVerifierA";
    let observed_wall_ms = 100u64;

    // Boundary: claimed == observed + 25 is Ok (inclusive noise bound).
    assert_eq!(
        timings.cross_check(peer, 125, observed_wall_ms),
        CrossCheckOutcome::Ok
    );
    assert_eq!(telemetry.count("verify_ms_lie"), 0);
    assert_eq!(timings.lie_count(peer), 0);

    // One millisecond above: a lie — the serve loop emits the telemetry
    // event and de-ranks (lie count exposed for the policy).
    assert_eq!(
        timings.cross_check(peer, 126, observed_wall_ms),
        CrossCheckOutcome::Lie
    );
    telemetry.verify_ms_lie(SESSION, peer);
    assert_eq!(
        telemetry.only("verify_ms_lie"),
        (SESSION.to_string(), peer.to_string())
    );
    assert_eq!(timings.lie_count(peer), 1, "de-rank signal recorded");

    // Under-reporting cannot be detected from timing alone (ADR-032 §1):
    // a small claim against a long observed round stays Ok.
    assert_eq!(timings.cross_check(peer, 1, 10_000), CrossCheckOutcome::Ok);
    assert_eq!(timings.lie_count(peer), 1);
}

#[test]
fn per_verifier_isolation_one_lying_peer_never_de_ranks_another() {
    let mut timings = VerifierTimings::new();
    assert_eq!(EWMA_ALPHA_DEFAULT, 0.25);
    let liar = "12D3KooLiar";
    let honest = "12D3KooHonest";

    // The liar inflates claim after claim (each a lie); the honest peer
    // records honest requester-measured rounds and a consistent claim.
    for _ in 0..5 {
        timings.record_round(liar, 100);
        assert_eq!(
            timings.cross_check(liar, 5_000, 100),
            CrossCheckOutcome::Lie
        );
    }
    timings.record_round(honest, 200);
    timings.record_round(honest, 300);
    assert_eq!(timings.cross_check(honest, 250, 300), CrossCheckOutcome::Ok);

    // The liar is flagged; the honest peer is untouched — per-verifier
    // EWMA (0.25*300 + 0.75*200 = 225) and zero lies. A cohort-wide
    // blend would have poisoned the honest peer's estimate: forbidden.
    assert_eq!(timings.lie_count(liar), 5);
    assert_eq!(timings.lie_count(honest), 0);
    assert_eq!(timings.ewma_ms(honest), Some(225));
    // The liar's EWMA is its own requester-measured rounds only — lies
    // never feed any EWMA.
    assert_eq!(timings.ewma_ms(liar), Some(100));
    // An unknown peer has no estimate and no lies (never blended in).
    assert_eq!(timings.ewma_ms("12D3KooUnknown"), None);
    assert_eq!(timings.lie_count("12D3KooUnknown"), 0);
}
