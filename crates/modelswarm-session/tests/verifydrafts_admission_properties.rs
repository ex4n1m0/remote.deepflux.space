//! ADR-032 §2 admission properties for the verifier-side
//! [`VerifyDraftsGate`] (implementation plan §3.6, file 1 of 2; venue:
//! per-push, default features — §7 execution-venue matrix, item 3).
//!
//! The 13 numbered properties below follow plan §3.6 items 1–13 exactly,
//! including the **first-failure-wins conjunction sweep** (item 2): for
//! random pairs/triples of injected admission conditions (and, stronger,
//! ALL 120 exhaustive pairs), the emitted code equals the earliest in
//! the §3.3 stage order — ADR-032 §2 "the earliest code in this table's
//! order".
//!
//! Clock discipline: every time read is injected. `NOW` is the fixture
//! anchor 2026-10-12T00:00:00Z (unix ms), the same value
//! `protocol/vectors/*` record as `verify_at`.

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
    batch_generation_params_hash, sign_verify_drafts, AdmissionDecision, BatchVerifyEngine,
    GatePreStateSeed, VerifyDrafts, VerifyDraftsGate, VerifyDraftsGateConfig,
    COOPERATIVE_PROTOCOL_VERSION, DEADLINE_CLAMP_MAX_MS, DEADLINE_CLAMP_MIN_MS,
    WAIT_COMMIT_GRACE_MS, WINDOW_CAP,
};
use modelswarm_session::{compute_prefix_hash, CommitPrefix, GENESIS_PREFIX_HASH};
use proptest::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// 2026-10-12T00:00:00Z in unix ms (the shared fixture anchor).
const NOW: u64 = 1_791_763_200_000;
/// The session's pinned profile (the `ab`-block fixture profile).
fn profile() -> String {
    format!("msp1:{}", "ab".repeat(32))
}
/// This family's generation-params hash over the runtime default.
fn params_hash() -> String {
    batch_generation_params_hash(&SamplingParams::default()).unwrap()
}
/// A second, wrong-but-well-formed profile.
fn other_profile() -> String {
    format!("msp1:{}", "cd".repeat(32))
}
/// A wrong-but-bare-64-hex parent.
fn other_hash() -> String {
    hex::encode(Sha256::digest(b"other parent"))
}

fn fixture_id(seed: u8) -> InstallationIdentity {
    InstallationIdentity::from_bytes(&[seed; 32])
}

/// Distinctive token ids so the privacy assertions (item 12) can search
/// serialized reject frames for the ids without hash collisions.
const BASE_WINDOW: [u32; 3] = [9_000_101, 9_000_102, 9_000_103];

fn base_gate_config(coordinator: &InstallationIdentity) -> VerifyDraftsGateConfig {
    VerifyDraftsGateConfig {
        session_id: "sess-prop".to_string(),
        profile_id: profile(),
        generation_params_hash: params_hash(),
        committed_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        coordinator_key: coordinator.verifying_key(),
        verifier_installation_id: fixture_id(0x22).installation_id(),
        engine: EngineDisclosure {
            backend: Backend::Cpu,
            batch_verify: true,
            batch_window_max: 8,
        },
        budget: SessionBudget {
            max_endpoints: 1,
            max_endpoint_seconds: 120,
            max_output_tokens: 1000,
        },
        lease_expires_at_ms: NOW + 3_600_000,
        sampling_params: SamplingParams::default(),
        verifier_next_seq: 4,
    }
}

fn base_gate(coordinator: &InstallationIdentity) -> VerifyDraftsGate {
    VerifyDraftsGate::new(base_gate_config(coordinator)).unwrap()
}

/// [`base_gate`] with a configurable seconds budget — the deadline-clamp
/// cases need a WIDE one, because a clamp-ceiling reservation
/// (`DEADLINE_CLAMP_MAX_MS` + grace = 120_250 ms) can never fit a 120 s
/// cap under the §8e revision-4 would-exceed seconds arm (the
/// reservation is charged at stage 11, before the deadline stage
/// decides).
fn base_gate_with_seconds(coordinator: &InstallationIdentity, seconds: u64) -> VerifyDraftsGate {
    VerifyDraftsGate::new(VerifyDraftsGateConfig {
        budget: SessionBudget {
            max_endpoints: 1,
            max_endpoint_seconds: seconds,
            max_output_tokens: 1000,
        },
        ..base_gate_config(coordinator)
    })
    .unwrap()
}

fn build_request(
    coordinator: &InstallationIdentity,
    seq: u64,
    round: u64,
    nonce: &str,
    parent: &str,
    window: &[u32],
) -> Value {
    let mut msg = VerifyDrafts {
        session_id: "sess-prop".to_string(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
        seq,
        round,
        profile_id: profile(),
        parent_prefix_hash: parent.to_string(),
        generation_params_hash: params_hash(),
        window_tokens: window.to_vec(),
        proposer_id: "12D3KooProposer".to_string(),
        nonce: nonce.to_string(),
        deadline_ms: 2_500,
        sender: coordinator.installation_id(),
        signature: String::new(),
    };
    msg.signature = sign_verify_drafts(&msg, coordinator).unwrap();
    serde_json::to_value(&msg).unwrap()
}

/// The clean baseline frame inside `run_case` (documented here for
/// readability): seq 13 (> seeded 12) or 14 when a busy round is admitted
/// first, round 2 (> seeded 1) or 3 likewise, fresh nonce
/// "prop-nonce-main", genesis parent, 3-token window, live deadline.
const CLEAN_NONCE: &str = "prop-nonce-main";

// ---------------------------------------------------------------------------
// Mock engine (counting, fixed outcome — plan §3.5 "mocked as fixed")
// ---------------------------------------------------------------------------

struct MockEngine {
    disclosure: EngineDisclosure,
    outcome: Mutex<(u32, Option<u32>)>,
    calls: AtomicUsize,
}

impl MockEngine {
    fn new(batch_window_max: u32, outcome: (u32, Option<u32>)) -> Self {
        Self {
            disclosure: EngineDisclosure {
                backend: Backend::Cpu,
                batch_verify: true,
                batch_window_max,
            },
            outcome: Mutex::new(outcome),
            calls: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl BatchVerifyEngine for MockEngine {
    async fn verify_window(
        &self,
        window: &[u32],
        _params: &SamplingParams,
    ) -> Result<(u32, Option<u32>), modelswarm_runtime::RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (accepted, correction) = *self.outcome.lock().unwrap();
        Ok((accepted.min(window.len() as u32), correction))
    }
    fn capabilities(&self) -> EngineDisclosure {
        self.disclosure.clone()
    }
}

// ---------------------------------------------------------------------------
// The injected-condition framework (plan §3.6 item 2)
// ---------------------------------------------------------------------------

/// One injectable admission condition = one ADR-032 §2 table row.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Cond {
    OversizeFrame,
    SchemaInvalid,
    BadSignature,
    WrongSession,
    TornDown,
    LeaseExpired,
    DuplicateSeq,
    ReusedNonce,
    ProfileMismatch,
    RoundMismatch,
    ParentMismatch,
    OutstandingBusy,
    WindowOverCap,
    BudgetTokens,
    BudgetSeconds,
    DeadlinePast,
}

const ALL_CONDS: [Cond; 16] = [
    Cond::OversizeFrame,
    Cond::SchemaInvalid,
    Cond::BadSignature,
    Cond::WrongSession,
    Cond::TornDown,
    Cond::LeaseExpired,
    Cond::DuplicateSeq,
    Cond::ReusedNonce,
    Cond::ProfileMismatch,
    Cond::RoundMismatch,
    Cond::ParentMismatch,
    Cond::OutstandingBusy,
    Cond::WindowOverCap,
    Cond::BudgetTokens,
    Cond::BudgetSeconds,
    Cond::DeadlinePast,
];

/// What a condition expects when it is the earliest failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Expected {
    Reject(FrameRejectReason),
    Cancel(CancelRoundReason),
}

impl Cond {
    /// Position in the §3.3 stage order (first-failure-wins).
    fn order(self) -> (u8, u8) {
        match self {
            Cond::OversizeFrame => (1, 0),
            Cond::SchemaInvalid => (2, 0),
            Cond::BadSignature => (3, 0),
            Cond::WrongSession => (4, 0),
            Cond::TornDown => (5, 0),
            Cond::LeaseExpired => (5, 1),
            Cond::DuplicateSeq => (6, 0),
            Cond::ReusedNonce => (6, 1),
            Cond::ProfileMismatch => (7, 0),
            Cond::RoundMismatch => (8, 0),
            Cond::ParentMismatch => (8, 1),
            Cond::OutstandingBusy => (9, 0),
            Cond::WindowOverCap => (10, 0),
            Cond::BudgetTokens => (11, 0),
            Cond::BudgetSeconds => (11, 1),
            Cond::DeadlinePast => (12, 0),
        }
    }
    fn expected(self) -> Expected {
        match self {
            Cond::OversizeFrame | Cond::WindowOverCap => {
                Expected::Reject(FrameRejectReason::PayloadTooLarge)
            }
            Cond::SchemaInvalid
            | Cond::BadSignature
            | Cond::WrongSession
            | Cond::OutstandingBusy => Expected::Reject(FrameRejectReason::BadFrame),
            Cond::TornDown => Expected::Reject(FrameRejectReason::CancelledByPeer),
            Cond::LeaseExpired => Expected::Reject(FrameRejectReason::ExpiredToken),
            Cond::DuplicateSeq | Cond::ReusedNonce => {
                Expected::Reject(FrameRejectReason::ReplayedRequest)
            }
            Cond::ProfileMismatch => Expected::Reject(FrameRejectReason::ProfileMismatch),
            Cond::RoundMismatch => Expected::Cancel(CancelRoundReason::RoundMismatch),
            Cond::ParentMismatch => Expected::Cancel(CancelRoundReason::ParentMismatch),
            Cond::BudgetTokens | Cond::BudgetSeconds => {
                Expected::Reject(FrameRejectReason::Overloaded)
            }
            Cond::DeadlinePast => Expected::Reject(FrameRejectReason::DeadlineExceeded),
        }
    }
}

/// Runs one admission with the injected conditions applied and returns
/// the gate (post-admit, for state assertions) and its decision.
fn run_case(conds: &[Cond]) -> (VerifyDraftsGate, AdmissionDecision) {
    let coordinator = fixture_id(0x31);
    let mut gate = base_gate(&coordinator);
    // The recorded pre-state baseline (mirrors the malformed fixture
    // template): seq 12 and round 1 already handled, one consumed nonce.
    gate.seed_pre_state(GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        consumed_nonces: vec!["seed-nonce-0".to_string()],
        last_handled_round: Some(1),
        ..GatePreStateSeed::default()
    });

    // OutstandingBusy: admit one clean prior round first (never dispatched).
    let busy = conds.contains(&Cond::OutstandingBusy);
    if busy {
        let prior = build_request(
            &coordinator,
            13,
            2,
            "busy-nonce",
            GENESIS_PREFIX_HASH,
            &BASE_WINDOW,
        );
        assert!(
            matches!(
                gate.admit_verify_drafts(&prior, NOW, NOW, &peer_of(&coordinator)),
                AdmissionDecision::Admitted { .. }
            ),
            "the busy-setup prior round must be admitted"
        );
    }
    // Gate-side conditions.
    if conds.contains(&Cond::TornDown) {
        gate.seed_pre_state(GatePreStateSeed {
            torn_down: true,
            ..GatePreStateSeed::default()
        });
    }
    if conds.contains(&Cond::LeaseExpired) {
        gate.seed_pre_state(GatePreStateSeed {
            lease_expires_at_ms: Some(NOW - 1),
            ..GatePreStateSeed::default()
        });
    }
    if conds.contains(&Cond::BudgetTokens) {
        gate.seed_pre_state(GatePreStateSeed {
            committed_output_tokens: Some(1000),
            ..GatePreStateSeed::default()
        });
    }
    if conds.contains(&Cond::BudgetSeconds) {
        // At the seconds cap the would-exceed reservation (§8e, revision
        // 4: ledger + clamped deadline + grace) is over the ceiling for
        // ANY deadline — the condition still fires at stage 11.
        gate.seed_pre_state(GatePreStateSeed {
            served_ms: Some(120_000),
            ..GatePreStateSeed::default()
        });
    }

    // Frame-side conditions (applied BEFORE signing so the signature
    // stays valid for stages after 3).
    let mut msg = VerifyDrafts {
        session_id: "sess-prop".to_string(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
        seq: if busy { 14 } else { 13 },
        round: if busy { 3 } else { 2 },
        profile_id: profile(),
        parent_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        generation_params_hash: params_hash(),
        window_tokens: BASE_WINDOW.to_vec(),
        proposer_id: "12D3KooProposer".to_string(),
        nonce: CLEAN_NONCE.to_string(),
        deadline_ms: 2_500,
        sender: coordinator.installation_id(),
        signature: String::new(),
    };
    if conds.contains(&Cond::WrongSession) {
        msg.session_id = "sess-other".to_string();
    }
    if conds.contains(&Cond::DuplicateSeq) {
        msg.seq = 12;
    }
    if conds.contains(&Cond::ReusedNonce) {
        msg.nonce = "seed-nonce-0".to_string();
    }
    if conds.contains(&Cond::ProfileMismatch) {
        msg.profile_id = other_profile();
    }
    if conds.contains(&Cond::RoundMismatch) {
        msg.round = 1;
    }
    if conds.contains(&Cond::ParentMismatch) {
        msg.parent_prefix_hash = other_hash();
    }
    if conds.contains(&Cond::WindowOverCap) {
        msg.window_tokens = vec![9_000_201; 9];
    }
    if conds.contains(&Cond::OversizeFrame) {
        // A schema-valid > 256 KiB frame via the (unbounded) nonce field.
        msg.nonce = "x".repeat(300_000);
    }
    msg.signature = sign_verify_drafts(&msg, &coordinator).unwrap();
    let mut frame = serde_json::to_value(&msg).unwrap();
    // Post-signature conditions (ordered after the stages they follow).
    if conds.contains(&Cond::SchemaInvalid) {
        frame
            .as_object_mut()
            .unwrap()
            .insert("unknown_key".to_string(), Value::from(1));
    }
    if conds.contains(&Cond::BadSignature) {
        *frame.get_mut("signature").unwrap() = Value::from("AAAAnot-a-signature");
    }

    let arrival = if conds.contains(&Cond::DeadlinePast) {
        NOW - 5_000
    } else {
        NOW
    };
    let decision = gate.admit_verify_drafts(&frame, arrival, NOW, &peer_of(&coordinator));
    (gate, decision)
}

fn assert_decision(decision: &AdmissionDecision, expected: Expected, conds: &[Cond]) {
    match (decision, expected) {
        (AdmissionDecision::FrameRejected(frame), Expected::Reject(code)) => {
            assert_eq!(frame.code, code, "conds {conds:?}");
        }
        (AdmissionDecision::CancelRound(cancel), Expected::Cancel(reason)) => {
            assert_eq!(cancel.reason, reason, "conds {conds:?}");
        }
        (actual, expected) => {
            panic!("conds {conds:?}: expected {expected:?}, got {actual:?}");
        }
    }
}

/// A hash-valid commit over `ids` chaining from `committed_hash` (free
/// helper — a closure would capture the gate and fight the borrow
/// checker).
fn commit_from(committed_hash: &str, ids: &[u32], round: u64, sender: &str) -> CommitPrefix {
    CommitPrefix {
        session_id: "sess-prop".to_string(),
        round,
        previous_prefix_hash: committed_hash.to_string(),
        accepted_token_ids: ids.to_vec(),
        new_prefix_hash: compute_prefix_hash(committed_hash, ids).unwrap(),
        model_profile_id: profile(),
        generation_params_hash: params_hash(),
        sender: sender.to_string(),
    }
}

// ---------------------------------------------------------------------------
// §3.6 item 1 — every §2-table row singly
// ---------------------------------------------------------------------------

#[test]
fn admission_table_rows_singly() {
    // Positive control: the clean baseline is admitted.
    let (_, decision) = run_case(&[]);
    assert!(
        matches!(decision, AdmissionDecision::Admitted { round: 2, .. }),
        "clean baseline must be admitted: {decision:?}"
    );

    for cond in ALL_CONDS {
        let (_, decision) = run_case(&[cond]);
        assert_decision(&decision, cond.expected(), &[cond]);
    }

    // Table rows the Cond set models separately:
    // (a) empty window_tokens — schema row (§1: an empty window is malformed).
    let coordinator = fixture_id(0x31);
    let mut frame = build_request(
        &coordinator,
        13,
        2,
        "empty-window-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    *frame.get_mut("window_tokens").unwrap() = Value::Array(vec![]);
    // The frame must be RE-signed: emptying the window breaks the signature,
    // but the schema stage (2) fires before the signature stage (3) anyway.
    let (gate, decision) = {
        let mut gate = base_gate(&coordinator);
        gate.seed_pre_state(GatePreStateSeed {
            last_seq: vec![(coordinator.installation_id(), 12)],
            last_handled_round: Some(1),
            ..GatePreStateSeed::default()
        });
        let decision = gate.admit_verify_drafts(&frame, NOW, NOW, &peer_of(&coordinator));
        (gate, decision)
    };
    assert_decision(
        &decision,
        Expected::Reject(FrameRejectReason::BadFrame),
        &[],
    );
    assert_eq!(gate.state().as_str(), "prefilled");

    // (b) VerifyDrafts while a round is outstanding, nonce REPEATS —
    // replayed_request (the row normally caught at stage 6).
    let mut gate = base_gate(&coordinator);
    gate.seed_pre_state(GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        ..GatePreStateSeed::default()
    });
    let first = build_request(
        &coordinator,
        13,
        2,
        "repeat-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    assert!(matches!(
        gate.admit_verify_drafts(&first, NOW, NOW, &peer_of(&coordinator)),
        AdmissionDecision::Admitted { .. }
    ));
    match gate.admit_verify_drafts(&first, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => {
            assert_eq!(f.code, FrameRejectReason::ReplayedRequest);
        }
        other => panic!("replayed outstanding request must reject: {other:?}"),
    }
    assert_eq!(gate.outstanding_round(), Some(2), "never queued");

    // (c) seq DECREASE with a fresh nonce (the non-monotone row).
    let decreased = build_request(
        &coordinator,
        11,
        2,
        "decrease-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    match gate.admit_verify_drafts(&decreased, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => {
            assert_eq!(f.code, FrameRejectReason::ReplayedRequest);
        }
        other => panic!("decreased seq must reject: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// §3.6 item 2 — first-failure-wins conjunction sweep
// ---------------------------------------------------------------------------

#[test]
fn first_failure_wins_all_exhaustive_pairs() {
    // ALL C(16,2) = 120 pairs, deterministically.
    for (i, a) in ALL_CONDS.iter().enumerate() {
        for b in ALL_CONDS.iter().skip(i + 1) {
            let (_, decision) = run_case(&[*a, *b]);
            let earliest = [*a, *b].into_iter().min_by_key(|c| c.order()).unwrap();
            assert_decision(&decision, earliest.expected(), &[*a, *b]);
        }
    }
}

proptest! {
    /// Random TRIPLES of distinct injected conditions: the emitted code is
    /// the earliest in §3.3 order. Includes the ADR-decided budget-before-
    /// deadline precedence (BudgetTokens + DeadlinePast → `overloaded`),
    /// which is exactly why the committed `verifydrafts-malformed.json`
    /// `deadline-past` case replays with a fresh budget ledger (its shared
    /// template context records an at-ceiling budget that would otherwise
    /// mask the deadline condition — see the golden test's pinned note).
    #[test]
    fn first_failure_wins_random_triples(idx in proptest::collection::vec(0usize..16, 3)) {
        let mut conds: Vec<Cond> = idx.iter().map(|i| ALL_CONDS[*i]).collect();
        conds.sort();
        conds.dedup();
        if conds.len() < 2 { return Ok(()); }
        let (_, decision) = run_case(&conds);
        let earliest = *conds.iter().min_by_key(|c| c.order()).unwrap();
        assert_decision(&decision, earliest.expected(), &conds);
    }
}

// ---------------------------------------------------------------------------
// §3.6 item 3 — replay (I6): no state change
// ---------------------------------------------------------------------------

#[test]
fn replays_reject_without_state_change() {
    let coordinator = fixture_id(0x31);
    let mut gate = base_gate(&coordinator);
    gate.seed_pre_state(GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        consumed_nonces: vec!["n0".to_string()],
        last_handled_round: Some(5),
        ..GatePreStateSeed::default()
    });
    let snapshot = (
        gate.committed_prefix_hash().to_string(),
        gate.last_handled_round(),
        gate.state(),
        gate.nonce_consumed("n1"),
    );
    // Same nonce, ANY seq (fresh seq 13 > 12).
    let nonce_replay = build_request(&coordinator, 13, 6, "n0", GENESIS_PREFIX_HASH, &BASE_WINDOW);
    match gate.admit_verify_drafts(&nonce_replay, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => {
            assert_eq!(f.code, FrameRejectReason::ReplayedRequest)
        }
        other => panic!("{other:?}"),
    }
    // Duplicate seq (== last seen), fresh nonce.
    let seq_replay = build_request(&coordinator, 12, 6, "n1", GENESIS_PREFIX_HASH, &BASE_WINDOW);
    match gate.admit_verify_drafts(&seq_replay, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => {
            assert_eq!(f.code, FrameRejectReason::ReplayedRequest)
        }
        other => panic!("{other:?}"),
    }
    // Decreased seq, fresh nonce.
    let mut decreased = seq_replay.clone();
    {
        let msg: VerifyDrafts = serde_json::from_value(decreased.clone()).unwrap();
        let mut m = msg.clone();
        m.seq = 11;
        m.signature = sign_verify_drafts(&m, &coordinator).unwrap();
        decreased = serde_json::to_value(&m).unwrap();
    }
    match gate.admit_verify_drafts(&decreased, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => {
            assert_eq!(f.code, FrameRejectReason::ReplayedRequest)
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(snapshot.0, gate.committed_prefix_hash());
    assert_eq!(snapshot.1, gate.last_handled_round());
    assert_eq!(snapshot.2, gate.state());
    assert!(
        !gate.nonce_consumed("n1"),
        "a rejected frame consumes nothing"
    );
}

// ---------------------------------------------------------------------------
// §3.6 item 4 — reorder/stale rounds; committed state unchanged
// ---------------------------------------------------------------------------

#[test]
fn stale_and_reordered_rounds_cancel_without_state_change() {
    let coordinator = fixture_id(0x31);
    let mut gate = base_gate(&coordinator);
    gate.seed_pre_state(GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(7),
        ..GatePreStateSeed::default()
    });
    let before = gate.committed_prefix_hash().to_string();

    let stale = build_request(
        &coordinator,
        13,
        7,
        "stale-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    match gate.admit_verify_drafts(&stale, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::CancelRound(c) => {
            assert_eq!(c.reason, CancelRoundReason::RoundMismatch);
            assert_eq!(c.round, 7);
        }
        other => panic!("{other:?}"),
    }
    let wrong_parent = build_request(
        &coordinator,
        13,
        8,
        "parent-nonce",
        &other_hash(),
        &BASE_WINDOW,
    );
    match gate.admit_verify_drafts(&wrong_parent, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::CancelRound(c) => {
            assert_eq!(c.reason, CancelRoundReason::ParentMismatch);
            assert_eq!(c.round, 8);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(before, gate.committed_prefix_hash());
    assert_eq!(
        gate.last_handled_round(),
        7,
        "round-level rejects do not move the handled round"
    );
    assert_eq!(gate.state().as_str(), "prefilled");
    assert!(!gate.nonce_consumed("stale-nonce"), "no state change");
}

// ---------------------------------------------------------------------------
// §3.6 item 5 — cross-profile isolation (I7) + teardown
// ---------------------------------------------------------------------------

#[test]
fn cross_profile_tears_down_and_later_frames_are_cancelled() {
    let coordinator = fixture_id(0x31);
    let mut gate = base_gate(&coordinator);
    gate.seed_pre_state(GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        ..GatePreStateSeed::default()
    });
    let foreign = build_request(
        &coordinator,
        13,
        2,
        "cross-profile-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    let mut foreign: VerifyDrafts = serde_json::from_value(foreign).unwrap();
    foreign.profile_id = other_profile();
    foreign.signature = sign_verify_drafts(&foreign, &coordinator).unwrap();
    let frame = serde_json::to_value(&foreign).unwrap();

    match gate.admit_verify_drafts(&frame, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => {
            assert_eq!(f.code, FrameRejectReason::ProfileMismatch)
        }
        other => panic!("{other:?}"),
    }
    assert!(gate.is_torn_down());
    assert_eq!(gate.teardown_reason(), Some("profile_mismatch"));

    // Later frames on this stream see cancelled_by_peer.
    let next = build_request(
        &coordinator,
        14,
        3,
        "after-teardown-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    match gate.admit_verify_drafts(&next, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => {
            assert_eq!(f.code, FrameRejectReason::CancelledByPeer)
        }
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// §3.6 item 6 — window cap fires BEFORE any engine work (RC-8)
// ---------------------------------------------------------------------------

#[test]
fn window_cap_rejects_before_engine_work() {
    let coordinator = fixture_id(0x31);
    // len 33 > min(WINDOW_CAP=32, batch_window_max=32).
    let engine = MockEngine::new(32, (3, Some(9_000_301)));
    let mut gate = base_gate(&coordinator);
    gate.seed_pre_state(GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        ..GatePreStateSeed::default()
    });
    let over_global = build_request(
        &coordinator,
        13,
        2,
        "cap33-nonce",
        GENESIS_PREFIX_HASH,
        &[9_000_401; 33],
    );
    match gate.admit_verify_drafts(&over_global, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => {
            assert_eq!(f.code, FrameRejectReason::PayloadTooLarge)
        }
        other => panic!("{other:?}"),
    }

    // len 9 > min(WINDOW_CAP=32, batch_window_max=8): the engine-bound row.
    let over_batch = build_request(
        &coordinator,
        13,
        2,
        "cap9-nonce",
        GENESIS_PREFIX_HASH,
        &[9_000_501; 9],
    );
    match gate.admit_verify_drafts(&over_batch, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => {
            assert_eq!(f.code, FrameRejectReason::PayloadTooLarge)
        }
        other => panic!("{other:?}"),
    }
    // Zero engine passes for both (engine never touched by admission).
    assert_eq!(engine.calls(), 0);
    assert_eq!(WINDOW_CAP, 32);
}

// ---------------------------------------------------------------------------
// §3.6 item 7 — one-outstanding (RC-5(a)): never queued
// ---------------------------------------------------------------------------

#[tokio::test]
async fn one_outstanding_never_queued() {
    let coordinator = fixture_id(0x31);
    let engine = MockEngine::new(8, (3, Some(9_000_301)));
    let mut gate = base_gate(&coordinator);
    gate.seed_pre_state(GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        ..GatePreStateSeed::default()
    });

    let first = build_request(
        &coordinator,
        13,
        2,
        "one-nonce-a",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    assert!(matches!(
        gate.admit_verify_drafts(&first.clone(), NOW, NOW, &peer_of(&coordinator)),
        AdmissionDecision::Admitted { .. }
    ));
    assert_eq!(gate.state().as_str(), "verify");

    // While in VERIFY: fresh-nonce VerifyDrafts → bad_frame.
    let fresh = build_request(
        &coordinator,
        14,
        3,
        "one-nonce-b",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    match gate.admit_verify_drafts(&fresh, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => assert_eq!(f.code, FrameRejectReason::BadFrame),
        other => panic!("{other:?}"),
    }
    // Repeated nonce → replayed_request (stage 6 path).
    match gate.admit_verify_drafts(&first, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => {
            assert_eq!(f.code, FrameRejectReason::ReplayedRequest)
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        gate.outstanding_round(),
        Some(2),
        "the FIRST round stays outstanding"
    );

    // Same after the engine pass, in WAIT_COMMIT.
    let dispatch = gate.dispatch_outstanding(&engine, NOW, NOW + 35).await;
    assert!(matches!(
        dispatch,
        modelswarm_session::verifydrafts::DispatchOutcome::Dispatched(_)
    ));
    assert_eq!(gate.state().as_str(), "wait_commit");
    let fresh2 = build_request(
        &coordinator,
        15,
        3,
        "one-nonce-c",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    match gate.admit_verify_drafts(&fresh2, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => assert_eq!(f.code, FrameRejectReason::BadFrame),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        engine.calls(),
        1,
        "exactly one pass for the one admitted round"
    );
    assert_eq!(gate.outstanding_round(), Some(2));
}

// ---------------------------------------------------------------------------
// §3.6 item 8 — WAIT_COMMIT timeout abandons; gaps tolerated (RC-5(b)/(c))
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wait_commit_timeout_abandons_and_gaps_are_tolerated() {
    let coordinator = fixture_id(0x31);
    let engine = MockEngine::new(8, (3, Some(9_000_301)));
    let mut gate = base_gate(&coordinator);
    gate.seed_pre_state(GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        ..GatePreStateSeed::default()
    });
    let frame = build_request(
        &coordinator,
        13,
        2,
        "timeout-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    let AdmissionDecision::Admitted {
        deadline_expires_at_ms,
        ..
    } = gate.admit_verify_drafts(&frame, NOW, NOW, &peer_of(&coordinator))
    else {
        panic!("baseline must admit");
    };
    gate.dispatch_outstanding(&engine, NOW, NOW + 35).await;
    assert!(gate.pending_result().is_some());
    let committed_before = gate.committed_prefix_hash().to_string();

    // One ms before the grace boundary: still held.
    assert!(!gate.expire_wait_commit_if_due(deadline_expires_at_ms + WAIT_COMMIT_GRACE_MS - 1));
    assert_eq!(gate.state().as_str(), "wait_commit");
    // At deadline + 250 ms exactly: abandoned, pending result discarded.
    assert!(gate.expire_wait_commit_if_due(deadline_expires_at_ms + WAIT_COMMIT_GRACE_MS));
    assert_eq!(gate.state().as_str(), "prefilled");
    assert!(gate.pending_result().is_none());
    assert_eq!(gate.outstanding_round(), None);
    assert_eq!(
        gate.committed_prefix_hash(),
        committed_before,
        "abandonment never commits"
    );
    assert_eq!(
        gate.last_handled_round(),
        2,
        "the abandoned round stays handled"
    );

    // The NEXT VerifyDrafts: round > last handled (a GAP is fine, I3) and
    // parent == the (unchanged) committed hash — accepted.
    let next = build_request(
        &coordinator,
        14,
        4,
        "post-timeout-nonce",
        &committed_before,
        &BASE_WINDOW,
    );
    assert!(matches!(
        gate.admit_verify_drafts(&next, NOW, NOW, &peer_of(&coordinator)),
        AdmissionDecision::Admitted { round: 4, .. }
    ));
}

// ---------------------------------------------------------------------------
// §3.6 item 9 — RC-4: commit must reproduce the outstanding result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rc4_commit_mismatch_abandons_and_reproducing_commits_advance() {
    let coordinator = fixture_id(0x31);
    let engine = MockEngine::new(8, (2, Some(9_000_301)));
    let mut gate = base_gate(&coordinator);
    gate.seed_pre_state(GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        ..GatePreStateSeed::default()
    });
    let window: Vec<u32> = BASE_WINDOW.to_vec();
    let frame = build_request(
        &coordinator,
        13,
        2,
        "rc4-nonce",
        GENESIS_PREFIX_HASH,
        &window,
    );
    assert!(matches!(
        gate.admit_verify_drafts(&frame, NOW, NOW, &peer_of(&coordinator)),
        AdmissionDecision::Admitted { .. }
    ));
    let modelswarm_session::verifydrafts::DispatchOutcome::Dispatched(result) =
        gate.dispatch_outstanding(&engine, NOW, NOW + 35).await
    else {
        panic!("dispatch must succeed");
    };

    let commit_for = |ids: &[u32], round: u64, committed: &str| {
        commit_from(committed, ids, round, &coordinator.installation_id())
    };

    // Hash-VALID commit over different ids → CancelRound(commit_mismatch),
    // round abandoned (RC-4), committed state unchanged.
    let impostor = commit_for(&[9_000_901, 9_000_902], 2, gate.committed_prefix_hash());
    match gate.apply_prefix_commit(&impostor) {
        modelswarm_session::verifydrafts::CommitApplyOutcome::CancelRound(c) => {
            assert_eq!(c.reason, CancelRoundReason::CommitMismatch);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(gate.state().as_str(), "prefilled");
    assert_eq!(gate.outstanding_round(), None);
    assert_eq!(gate.committed_prefix_hash(), GENESIS_PREFIX_HASH);
    assert_eq!(gate.last_committed_round(), 0);
    assert_eq!(gate.violations_of(&coordinator.installation_id()), 1);
    assert_eq!(gate.committed_output_tokens(), 0);

    // A reproducing commit for a NEW round advances (gaps allowed: round 3
    // here, but any round > 0 works).
    let frame3 = build_request(
        &coordinator,
        14,
        3,
        "rc4-nonce-3",
        GENESIS_PREFIX_HASH,
        &window,
    );
    assert!(matches!(
        gate.admit_verify_drafts(&frame3, NOW, NOW, &peer_of(&coordinator)),
        AdmissionDecision::Admitted { .. }
    ));
    let modelswarm_session::verifydrafts::DispatchOutcome::Dispatched(result3) =
        gate.dispatch_outstanding(&engine, NOW, NOW + 35).await
    else {
        panic!("round-3 dispatch must succeed");
    };
    let mut expected_ids = window[..result3.accepted_prefix_len as usize].to_vec();
    if let Some(token) = result3.correction {
        expected_ids.push(token);
    }
    let good = CommitPrefix {
        session_id: "sess-prop".to_string(),
        round: 3,
        previous_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        accepted_token_ids: expected_ids.clone(),
        new_prefix_hash: result3.new_prefix_hash.clone(),
        model_profile_id: profile(),
        generation_params_hash: params_hash(),
        sender: coordinator.installation_id(),
    };
    assert_eq!(
        gate.apply_prefix_commit(&good),
        modelswarm_session::verifydrafts::CommitApplyOutcome::Advanced { round: 3 }
    );
    assert_eq!(gate.committed_prefix_hash(), result3.new_prefix_hash);
    assert_eq!(gate.last_committed_round(), 3);
    assert_eq!(gate.committed_output_tokens(), expected_ids.len() as u64);
    assert_eq!(gate.state().as_str(), "committed");

    // Duplicate replay of the applied commit: a remembered no-op.
    assert_eq!(
        gate.apply_prefix_commit(&good),
        modelswarm_session::verifydrafts::CommitApplyOutcome::DuplicateRound
    );
    assert_eq!(gate.committed_output_tokens(), expected_ids.len() as u64);

    // A SECOND commit_mismatch by the same peer crosses the threshold-2
    // teardown (§2 RC-3 tail).
    let frame4 = build_request(
        &coordinator,
        15,
        4,
        "rc4-nonce-4",
        &result3.new_prefix_hash,
        &window,
    );
    assert!(matches!(
        gate.admit_verify_drafts(&frame4, NOW, NOW, &peer_of(&coordinator)),
        AdmissionDecision::Admitted { .. }
    ));
    gate.dispatch_outstanding(&engine, NOW, NOW + 35).await;
    let impostor2 = commit_for(&[9_000_951], 4, gate.committed_prefix_hash());
    assert!(matches!(
        gate.apply_prefix_commit(&impostor2),
        modelswarm_session::verifydrafts::CommitApplyOutcome::CancelRound(_)
    ));
    assert!(
        gate.is_torn_down(),
        "second violation tears the session down"
    );
    let _ = result;
}

// ---------------------------------------------------------------------------
// §3.6 item 10 — budget enforcement (I8)
// ---------------------------------------------------------------------------

#[test]
fn budget_exhaustion_refuses_with_overloaded() {
    let coordinator = fixture_id(0x31);
    // Token ledger: 998 committed + 3 window > 1000.
    let mut gate = base_gate(&coordinator);
    gate.seed_pre_state(GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        committed_output_tokens: Some(998),
        ..GatePreStateSeed::default()
    });
    let frame = build_request(
        &coordinator,
        13,
        2,
        "budget-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    match gate.admit_verify_drafts(&frame, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => assert_eq!(f.code, FrameRejectReason::Overloaded),
        other => panic!("{other:?}"),
    }
    // Exactly-at-budget (997 + 3 == 1000) still admits — would not EXCEED.
    gate.seed_pre_state(GatePreStateSeed {
        committed_output_tokens: Some(997),
        ..GatePreStateSeed::default()
    });
    assert!(matches!(
        gate.admit_verify_drafts(&frame, NOW, NOW, &peer_of(&coordinator)),
        AdmissionDecision::Admitted { .. }
    ));
    // Abandon the outstanding round so the seconds case starts clean.
    assert!(gate.expire_wait_commit_if_due(NOW + 500_000));

    // Seconds arm (ADR-032 §8e, revision 4 / T/R advisory A-2):
    // WOULD-EXCEED on BOTH arms. The seconds arm reserves the round's
    // bounded worst-case residence — the clamped deadline_ms (2_500, in
    // range so unclamped) plus the 250 ms WAIT_COMMIT grace = 2_750 ms —
    // and refuses when the ledger plus that reservation would exceed
    // `max_endpoint_seconds * 1000` (120_000 ms here). The
    // one-outstanding rule makes the reservation double-count-free; the
    // LEDGER itself keeps advancing on serve-loop deltas.
    let reservation_ms = WAIT_COMMIT_GRACE_MS + 2_500u64;
    assert_eq!(reservation_ms, 2_750);
    // One below the boundary: 117_249 + 2_750 = 119_999 <= 120_000 admits.
    gate.advance_session_seconds(120_000 - reservation_ms - 1);
    let frame2 = build_request(
        &coordinator,
        14,
        3,
        "budget-seconds-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    assert!(matches!(
        gate.admit_verify_drafts(&frame2, NOW, NOW, &peer_of(&coordinator)),
        AdmissionDecision::Admitted { .. }
    ));
    // Exactly at the boundary: 117_250 + 2_750 == 120_000 — would not
    // EXCEED, still admits (the would-exceed letter, not already-at-cap).
    assert!(gate.expire_wait_commit_if_due(NOW + 500_000));
    gate.advance_session_seconds(1);
    let frame3 = build_request(
        &coordinator,
        15,
        4,
        "budget-seconds-nonce-2",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    assert!(matches!(
        gate.admit_verify_drafts(&frame3, NOW, NOW, &peer_of(&coordinator)),
        AdmissionDecision::Admitted { .. }
    ));
    // One past the boundary: 117_251 + 2_750 = 120_001 > 120_000 refuses.
    assert!(gate.expire_wait_commit_if_due(NOW + 500_000));
    gate.advance_session_seconds(1);
    let frame4 = build_request(
        &coordinator,
        16,
        5,
        "budget-seconds-nonce-3",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    match gate.admit_verify_drafts(&frame4, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => assert_eq!(f.code, FrameRejectReason::Overloaded),
        other => panic!("seconds reservation must refuse: {other:?}"),
    }
    // A long-deadline round reserves more and refuses EARLIER: at the
    // same 117_251 ms ledger, a 120 s (clamp-ceiling) deadline reserves
    // 120_250 ms — far past the cap.
    let mut long = serde_json::from_value::<VerifyDrafts>(frame4).unwrap();
    long.deadline_ms = DEADLINE_CLAMP_MAX_MS;
    long.nonce = "budget-seconds-nonce-4".to_string();
    long.signature = sign_verify_drafts(&long, &coordinator).unwrap();
    let long_frame = serde_json::to_value(&long).unwrap();
    match gate.admit_verify_drafts(&long_frame, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => assert_eq!(f.code, FrameRejectReason::Overloaded),
        other => panic!("the clamp-ceiling reservation must refuse: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// §3.6 item 11 — deadline: admission, dispatch re-check, clamping
// ---------------------------------------------------------------------------

#[test]
fn deadline_past_at_admission_and_clamping_boundaries() {
    let coordinator = fixture_id(0x31);
    // A WIDE seconds budget: the clamp-high case reserves the clamp
    // ceiling + grace (120_250 ms) at stage 11, which can never fit a
    // 120 s cap under the §8e revision-4 would-exceed seconds arm.
    let mut gate = base_gate_with_seconds(&coordinator, 3_600);
    gate.seed_pre_state(GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        ..GatePreStateSeed::default()
    });
    // Past at admission: arrival + clamped deadline <= now.
    let past = build_request(
        &coordinator,
        13,
        2,
        "deadline-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    match gate.admit_verify_drafts(&past, NOW - 10_000, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => {
            assert_eq!(f.code, FrameRejectReason::DeadlineExceeded)
        }
        other => panic!("{other:?}"),
    }
    // Clamping: deadline_ms below the floor clamps UP to 1000 (clamp, not
    // reject — §2); above the ceiling clamps DOWN to 120000.
    let clamp_low = {
        let mut msg: VerifyDrafts = serde_json::from_value(build_request(
            &coordinator,
            13,
            2,
            "clamp-low",
            GENESIS_PREFIX_HASH,
            &BASE_WINDOW,
        ))
        .unwrap();
        msg.deadline_ms = DEADLINE_CLAMP_MIN_MS - 500;
        msg.signature = sign_verify_drafts(&msg, &coordinator).unwrap();
        serde_json::to_value(&msg).unwrap()
    };
    match gate.admit_verify_drafts(&clamp_low, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::Admitted {
            deadline_expires_at_ms,
            ..
        } => assert_eq!(
            deadline_expires_at_ms,
            NOW + u64::from(DEADLINE_CLAMP_MIN_MS)
        ),
        other => panic!("{other:?}"),
    }
    // Cancel the outstanding round by expiry so the gate is clean again.
    assert!(gate.expire_wait_commit_if_due(NOW + 500_000));

    let clamp_high = {
        let mut msg: VerifyDrafts = serde_json::from_value(build_request(
            &coordinator,
            14,
            3,
            "clamp-high",
            GENESIS_PREFIX_HASH,
            &BASE_WINDOW,
        ))
        .unwrap();
        msg.deadline_ms = DEADLINE_CLAMP_MAX_MS + 1;
        msg.signature = sign_verify_drafts(&msg, &coordinator).unwrap();
        serde_json::to_value(&msg).unwrap()
    };
    match gate.admit_verify_drafts(&clamp_high, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::Admitted {
            deadline_expires_at_ms,
            ..
        } => assert_eq!(
            deadline_expires_at_ms,
            NOW + u64::from(DEADLINE_CLAMP_MAX_MS)
        ),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn deadline_rechecked_at_dispatch_after_queue_wait() {
    let coordinator = fixture_id(0x31);
    let engine = MockEngine::new(8, (3, Some(9_000_301)));
    let mut gate = base_gate(&coordinator);
    gate.seed_pre_state(GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        ..GatePreStateSeed::default()
    });
    let frame = build_request(
        &coordinator,
        13,
        2,
        "dispatch-deadline-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    let AdmissionDecision::Admitted {
        deadline_expires_at_ms,
        ..
    } = gate.admit_verify_drafts(&frame, NOW, NOW, &peer_of(&coordinator))
    else {
        panic!("must admit");
    };
    // Queued past the deadline: stage 13 refuses BEFORE engine work.
    let outcome = gate
        .dispatch_outstanding(&engine, deadline_expires_at_ms, deadline_expires_at_ms + 35)
        .await;
    assert_eq!(
        outcome,
        modelswarm_session::verifydrafts::DispatchOutcome::DeadlineExceeded
    );
    assert_eq!(engine.calls(), 0, "no engine pass after a stage-13 refuse");
    assert_eq!(gate.state().as_str(), "prefilled");
    assert_eq!(gate.outstanding_round(), None);

    // One ms inside the deadline: dispatched.
    let frame2 = build_request(
        &coordinator,
        14,
        3,
        "dispatch-ok-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    assert!(matches!(
        gate.admit_verify_drafts(&frame2, NOW, NOW, &peer_of(&coordinator)),
        AdmissionDecision::Admitted { .. }
    ));
    let outcome = gate
        .dispatch_outstanding(&engine, NOW + 2_499, NOW + 2_534)
        .await;
    assert!(matches!(
        outcome,
        modelswarm_session::verifydrafts::DispatchOutcome::Dispatched(_)
    ));
    assert_eq!(engine.calls(), 1);
}

// ---------------------------------------------------------------------------
// §3.6 item 12 — reject frames carry codes/counts/hashes ONLY (A-3)
// ---------------------------------------------------------------------------

#[test]
fn reject_frames_never_carry_token_ids() {
    let mut reject_frames: Vec<Value> = Vec::new();
    for cond in ALL_CONDS {
        let (_, decision) = run_case(&[cond]);
        if let AdmissionDecision::FrameRejected(frame) = decision {
            reject_frames.push(serde_json::to_value(&frame).unwrap());
        }
    }
    assert!(
        reject_frames.len() >= 10,
        "the sweep must have produced frame rejects"
    );
    for frame in &reject_frames {
        let serialized = serde_json::to_string(frame).unwrap();
        // No window/bonus token id from any test window appears anywhere.
        assert!(
            !serialized.contains("90000"),
            "token id leaked: {serialized}"
        );
        // Structural pin: codes, counts, and hashes only.
        let mut keys: Vec<&str> = frame
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["code", "prefix_hash", "round", "session_id"]);
        assert!(frame.get("round").unwrap().is_u64() || frame["round"].is_null());
    }
    // CancelRound frames: session_id, round, reason — no ids either.
    let (_, decision) = run_case(&[Cond::RoundMismatch]);
    if let AdmissionDecision::CancelRound(cancel) = decision {
        let serialized = serde_json::to_string(&cancel).unwrap();
        assert!(!serialized.contains("90000"));
        let value: Value = serde_json::from_str(&serialized).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["reason", "round", "session_id"]);
    } else {
        panic!("expected CancelRound");
    }
}

// ---------------------------------------------------------------------------
// §3.6 item 13 — lease expiry mid-session (expired_token)
// ---------------------------------------------------------------------------

#[test]
fn lease_expiry_mid_session_refuses_with_expired_token() {
    let coordinator = fixture_id(0x31);
    let mut gate = base_gate(&coordinator);
    gate.seed_pre_state(GatePreStateSeed {
        last_seq: vec![(coordinator.installation_id(), 12)],
        last_handled_round: Some(1),
        ..GatePreStateSeed::default()
    });
    let live = build_request(
        &coordinator,
        13,
        2,
        "lease-live-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    assert!(matches!(
        gate.admit_verify_drafts(&live, NOW, NOW, &peer_of(&coordinator)),
        AdmissionDecision::Admitted { .. }
    ));
    assert!(gate.expire_wait_commit_if_due(NOW + 500_000));

    // The lease expires mid-session.
    gate.seed_pre_state(GatePreStateSeed {
        lease_expires_at_ms: Some(NOW - 1),
        ..GatePreStateSeed::default()
    });
    let after = build_request(
        &coordinator,
        14,
        3,
        "lease-dead-nonce",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    match gate.admit_verify_drafts(&after, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => assert_eq!(f.code, FrameRejectReason::ExpiredToken),
        other => panic!("{other:?}"),
    }
    // And every later frame too.
    let later = build_request(
        &coordinator,
        15,
        4,
        "lease-dead-nonce-2",
        GENESIS_PREFIX_HASH,
        &BASE_WINDOW,
    );
    match gate.admit_verify_drafts(&later, NOW, NOW, &peer_of(&coordinator)) {
        AdmissionDecision::FrameRejected(f) => assert_eq!(f.code, FrameRejectReason::ExpiredToken),
        other => panic!("{other:?}"),
    }
}
