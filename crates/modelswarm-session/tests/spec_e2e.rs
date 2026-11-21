//! Phase D end-to-end speculative-protocol tests over real loopback TCP
//! (ephemeral ports, `SignedFrameTransport`), exercising the D-gate items:
//!
//! - **D4 happy path**: full session, commits advance round by round, receipt
//!   signed + acked.
//! - **D4 disconnect**: proposer killed mid-round → coordinator observes the
//!   closed session, falls back to exact single decoding against the
//!   verifier, and the verifier's state machine is intact (reconnect + replay
//!   of the last commit → `duplicate`, no advance).
//! - **Replay**: a replayed commit (same round) is a remembered duplicate; a
//!   conflicting same-round commit is stale — the state-machine property now
//!   over the wire.
//! - **Bad signature** commit → `CommitAck ok:false`, no advance.
//! - **D6 fallback**: `draft_accuracy = 0` collapses acceptance →
//!   `acceptance_collapse` fallback; output still exactly equals single
//!   decoding (the fallback path is the plain decoder).
//! - **D7 receipts**: two-phase close; a mismatched ack ends the session with
//!   `receipt_mismatch`; a missing ack ends it `closed_without_receipt_ack`.
//!
//! Every case is hang-free by construction (`tokio::time::timeout`).

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use modelswarm_identity::InstallationIdentity;
use modelswarm_runtime::{InferenceRuntime, MockRuntime, SamplingParams};
use modelswarm_session::spec::{
    default_sampling_params_hash, serve_proposer, serve_speculative, sign_receipt_ack, speculate,
    verify_receipt_signature, FallbackPolicy, FallbackReason, SpecError, SpecMessage, SpecPeer,
    SpeculativeExecutor, GENESIS_PREFIX_HASH,
};
use modelswarm_session::{compute_prefix_hash, CommitPrefix};
use modelswarm_transport::{Handshake, Listener, SignedFrameTransport};

const PROFILE: &str = "msp:spec-e2e:v1";
const D: Duration = Duration::from_secs(10);
/// Global per-case timeout: no test may hang.
const GLOBAL: Duration = Duration::from_secs(30);

fn ident(seed: u8) -> InstallationIdentity {
    InstallationIdentity::from_bytes(&[seed; 32])
}

/// Deterministic prompt from a seed (valid mock-vocab ids).
fn prompt_for(seed: u64) -> Vec<u32> {
    (0..8u64)
        .map(|k| (seed.wrapping_mul(k + 7) % 256) as u32)
        .collect()
}

async fn listen() -> (Listener, String) {
    let listener = SignedFrameTransport::listen("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    (listener, addr)
}

type Server<T> = tokio::task::JoinHandle<Result<Vec<T>, SpecError>>;

async fn spawn_verifier(
    runtime: Arc<MockRuntime>,
    identity: InstallationIdentity,
    requester: &InstallationIdentity,
    max_sessions: usize,
) -> (String, Server<modelswarm_session::spec::VerifierReport>) {
    let (listener, addr) = listen().await;
    let key = requester.verifying_key();
    let task = tokio::spawn(async move {
        serve_speculative(
            listener,
            runtime as Arc<dyn InferenceRuntime>,
            PROFILE,
            identity,
            key,
            max_sessions,
        )
        .await
    });
    (addr, task)
}

async fn spawn_proposer(
    runtime: Arc<MockRuntime>,
    identity: InstallationIdentity,
    requester: &InstallationIdentity,
) -> (String, Server<modelswarm_session::spec::ProposerReport>) {
    let (listener, addr) = listen().await;
    let key = requester.verifying_key();
    let task = tokio::spawn(async move {
        serve_proposer(
            listener,
            runtime as Arc<dyn InferenceRuntime>,
            PROFILE,
            identity,
            key,
            1,
        )
        .await
    });
    (addr, task)
}

/// Plain single decoding of `n` tokens (the D1 equality oracle).
async fn single_decode(runtime: &Arc<MockRuntime>, prompt: &[u32], n: u32) -> Vec<u32> {
    let handle = runtime.load(PROFILE).await.expect("load");
    runtime
        .decode_stream(&handle, prompt, &SamplingParams::default(), n, D)
        .await
        .expect("single decode")
}

/// Prefix-hash chain over the committed batches (recomputes what every peer's
/// state machine committed).
fn chain_hashes(batches: &[Vec<u32>]) -> Vec<String> {
    let mut hashes = vec![GENESIS_PREFIX_HASH.to_string()];
    for batch in batches {
        let next = compute_prefix_hash(hashes.last().unwrap(), batch).expect("chain");
        hashes.push(next);
    }
    hashes
}

/// Rebuilds the signed wire commit for `round` from the outcome's batches
/// (the test owns the coordinator identity, so the re-signature is valid).
fn rebuild_commit(
    outcome_batches: &[Vec<u32>],
    round: u64,
    session_id: &str,
    coordinator: &InstallationIdentity,
) -> SpecMessage {
    let hashes = chain_hashes(outcome_batches);
    let tokens = outcome_batches[(round - 1) as usize].clone();
    let commit = CommitPrefix {
        session_id: session_id.to_string(),
        round,
        previous_prefix_hash: hashes[(round - 1) as usize].clone(),
        accepted_token_ids: tokens,
        new_prefix_hash: hashes[round as usize].clone(),
        model_profile_id: PROFILE.to_string(),
        generation_params_hash: default_sampling_params_hash(),
        sender: coordinator.installation_id(),
    };
    SpecMessage::signed_commit(&commit, coordinator).expect("sign")
}

async fn send_msg(session: &mut modelswarm_transport::Session, msg: &SpecMessage) {
    session
        .send_json(&serde_json::to_value(msg).unwrap(), D)
        .await
        .expect("send_json");
}

async fn recv_msg(session: &mut modelswarm_transport::Session) -> SpecMessage {
    let value = session.recv_json(D).await.expect("recv_json");
    serde_json::from_value(value).expect("spec message")
}

async fn connect_as(addr: &str, identity: &InstallationIdentity) -> modelswarm_transport::Session {
    let handshake = Handshake::build(identity, PROFILE, "mock", "test");
    SignedFrameTransport::connect(addr, handshake, D)
        .await
        .expect("connect")
}

/// Minimal prefill exchange with the verifier.
async fn prefill(
    session: &mut modelswarm_transport::Session,
    session_id: &str,
    prompt: &[u32],
) -> String {
    send_msg(
        session,
        &SpecMessage::PrefillRequest {
            session_id: session_id.to_string(),
            profile_id: PROFILE.to_string(),
            prompt_tokens: prompt.to_vec(),
            generation_params_hash: default_sampling_params_hash(),
        },
    )
    .await;
    match recv_msg(session).await {
        SpecMessage::PrefillReady {
            accepted_prefix_hash,
            ..
        } => accepted_prefix_hash,
        other => panic!("expected prefill_ready, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// D4: happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn d4_happy_path_five_rounds_commits_advance_receipt_acked() {
    let coordinator = ident(1);
    let verifier_id = ident(2);
    let proposer_id = ident(3);
    let prompt = prompt_for(42);

    let verifier_runtime = Arc::new(MockRuntime::new(11, 1.0));
    let proposer_runtime = Arc::new(MockRuntime::new(11, 1.0));
    let client_runtime = Arc::new(MockRuntime::new(11, 1.0));
    let (verifier_addr, verifier_server) = spawn_verifier(
        verifier_runtime.clone(),
        verifier_id.clone(),
        &coordinator,
        1,
    )
    .await;
    let (proposer_addr, proposer_server) =
        spawn_proposer(proposer_runtime, proposer_id, &coordinator).await;

    let outcome = tokio::time::timeout(
        GLOBAL,
        speculate(
            &verifier_addr,
            &proposer_addr,
            client_runtime.clone(),
            PROFILE,
            &prompt,
            4,
            25,
            &coordinator,
            &verifier_id.verifying_key(),
            FallbackPolicy::default(),
        ),
    )
    .await
    .expect("no hang")
    .expect("speculate succeeds");

    // Greedy equality against plain single decoding, token for token.
    let single = single_decode(&client_runtime, &prompt, 25).await;
    assert_eq!(outcome.tokens, single, "greedy contract");
    assert_eq!(outcome.tokens.len(), 25);
    // Exactly five rounds (window 4 + bonus per round, window capped near the
    // budget end).
    assert_eq!(outcome.rounds, 5, "batches: {:?}", outcome.round_batches);
    assert_eq!(
        outcome.round_batches.len(),
        5,
        "batches: {:?}",
        outcome.round_batches
    );
    assert!(outcome.fallback.is_none());
    assert!(outcome.receipts_verified);

    let verifier_reports = verifier_server.await.unwrap().expect("verifier served");
    assert_eq!(verifier_reports.len(), 1);
    let report = &verifier_reports[0];
    assert_eq!(report.close_reason, "closed");
    assert_eq!(report.receipt_ack_valid, Some(true));
    assert_eq!(report.rounds, 5);
    assert_eq!(report.committed_tokens, 25);
    assert_eq!(report.stats.rounds, 5);
    // Perfect drafts: every round accepted the full window (+1 bonus).
    assert!((report.stats.mean_acceptance_length() - 5.0).abs() < 0.2);

    let proposer_reports = proposer_server.await.unwrap().expect("proposer served");
    assert_eq!(proposer_reports.len(), 1);
    assert_eq!(proposer_reports[0].proposals_served, 5);
    assert_eq!(proposer_reports[0].commits_applied, 5);
    assert_eq!(proposer_reports[0].close_reason, "closed");
}

// ---------------------------------------------------------------------------
// D4: proposer disconnect mid-round
// ---------------------------------------------------------------------------

/// A raw-JSON fake proposer that serves one round, then dies on the second
/// proposal request (the injected mid-round peer loss).
async fn fake_proposer_that_dies(listener: Listener, requester: InstallationIdentity, window: u32) {
    let mut session = listener
        .accept(&requester.verifying_key(), D)
        .await
        .expect("fake proposer accept");
    // Prefill (capture the real session id from the request).
    let session_id = match recv_msg(&mut session).await {
        SpecMessage::PrefillRequest { session_id, .. } => session_id,
        other => panic!("fake proposer expected prefill, got {other:?}"),
    };
    send_msg(
        &mut session,
        &SpecMessage::PrefillReady {
            session_id: session_id.clone(),
            kv_commitment_digest: "fake-digest".to_string(),
            accepted_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        },
    )
    .await;
    // Round 1: garbage candidate (the verifier content-checks it; only the
    // correction token commits), then ack the commit.
    match recv_msg(&mut session).await {
        SpecMessage::ProposalRequest { round, .. } => assert_eq!(round, 1),
        other => panic!("fake proposer expected round 1, got {other:?}"),
    }
    send_msg(
        &mut session,
        &SpecMessage::CandidateBlock {
            session_id: session_id.clone(),
            round: 1,
            parent_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
            tokens: vec![7; window as usize],
            proposer_id: "fake-proposer".to_string(),
        },
    )
    .await;
    match recv_msg(&mut session).await {
        SpecMessage::PrefixCommit { round, .. } => assert_eq!(round, 1),
        other => panic!("fake proposer expected commit, got {other:?}"),
    }
    send_msg(
        &mut session,
        &SpecMessage::CommitAck {
            session_id,
            round: 1,
            ok: true,
            reason: "advanced".to_string(),
        },
    )
    .await;
    // Round 2: abrupt death.
    match recv_msg(&mut session).await {
        SpecMessage::ProposalRequest { round, .. } => assert_eq!(round, 2),
        other => panic!("fake proposer expected round 2, got {other:?}"),
    }
    session.close();
}

#[tokio::test]
async fn d4_proposer_disconnect_falls_back_and_verifier_state_intact() {
    let coordinator = ident(10);
    let verifier_id = ident(11);
    let prompt = prompt_for(77);

    let verifier_runtime = Arc::new(MockRuntime::new(12, 0.5));
    let client_runtime = Arc::new(MockRuntime::new(12, 0.5));
    // Two sessions on the verifier: the speculate run + the reconnect replay.
    let (verifier_addr, verifier_server) =
        spawn_verifier(verifier_runtime, verifier_id.clone(), &coordinator, 2).await;
    let (fake_listener, fake_addr) = listen().await;
    let fake = tokio::spawn(fake_proposer_that_dies(
        fake_listener,
        coordinator.clone(),
        4,
    ));

    let outcome = tokio::time::timeout(
        GLOBAL,
        speculate(
            &verifier_addr,
            &fake_addr,
            client_runtime.clone(),
            PROFILE,
            &prompt,
            4,
            16,
            &coordinator,
            &verifier_id.verifying_key(),
            FallbackPolicy::default(),
        ),
    )
    .await
    .expect("no hang")
    .expect("speculate survives proposer loss");

    // Explicit fallback, exact output even in fallback mode.
    assert_eq!(outcome.fallback, Some(FallbackReason::PeerLost));
    let single = single_decode(&client_runtime, &prompt, 16).await;
    assert_eq!(outcome.tokens, single, "fallback path is exact");
    assert_eq!(outcome.tokens.len(), 16);
    // Round 1 committed one correction token; the single tail is one batch.
    assert_eq!(outcome.rounds, 2, "batches: {:?}", outcome.round_batches);
    assert!(outcome.receipts_verified);
    fake.await.expect("fake proposer reaped");

    // Reconnect: the verifier resumes from the last committed prefix...
    let expected_chain = chain_hashes(&outcome.round_batches);
    let mut session = connect_as(&verifier_addr, &coordinator).await;
    let resumed = prefill(&mut session, &outcome.session_id, &prompt).await;
    assert_eq!(
        resumed, expected_chain[2],
        "reconnect must resume from the last committed prefix"
    );

    // ...the replayed last commit is a remembered duplicate (no advance)...
    let replay = rebuild_commit(&outcome.round_batches, 2, &outcome.session_id, &coordinator);
    send_msg(&mut session, &replay).await;
    match recv_msg(&mut session).await {
        SpecMessage::CommitAck {
            ok, reason, round, ..
        } => {
            assert_eq!(round, 2);
            assert!(ok, "duplicate is a benign no-op");
            assert_eq!(reason, "duplicate");
        }
        other => panic!("expected commit_ack, got {other:?}"),
    }

    // ...and a fresh round still chains correctly onto it.
    let parent = expected_chain[2].clone();
    let fresh_tokens = vec![42u32];
    let fresh_commit = CommitPrefix {
        session_id: outcome.session_id.clone(),
        round: 3,
        previous_prefix_hash: parent.clone(),
        accepted_token_ids: fresh_tokens.clone(),
        new_prefix_hash: compute_prefix_hash(&parent, &fresh_tokens).unwrap(),
        model_profile_id: PROFILE.to_string(),
        generation_params_hash: default_sampling_params_hash(),
        sender: coordinator.installation_id(),
    };
    let next = SpecMessage::signed_commit(&fresh_commit, &coordinator).unwrap();
    send_msg(&mut session, &next).await;
    match recv_msg(&mut session).await {
        SpecMessage::CommitAck { ok, reason, .. } => {
            assert!(ok, "state must still advance: {reason}");
            assert_eq!(reason, "advanced");
        }
        other => panic!("expected commit_ack, got {other:?}"),
    }

    // Clean close of the second session.
    send_msg(
        &mut session,
        &SpecMessage::SessionClose {
            session_id: outcome.session_id.clone(),
            reason: "done".to_string(),
        },
    )
    .await;
    let receipt = recv_msg(&mut session).await;
    assert!(matches!(receipt, SpecMessage::Receipt { .. }));
    assert!(verify_receipt_signature(&receipt, &verifier_id.verifying_key()).is_ok());
    let ack = SpecMessage::ReceiptAck {
        requester_signature: sign_receipt_ack(&receipt, &coordinator).unwrap(),
    };
    send_msg(&mut session, &ack).await;
    session.close();

    let reports = verifier_server.await.unwrap().expect("verifier served");
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].close_reason, "closed");
    assert_eq!(reports[0].receipt_ack_valid, Some(true));
    assert_eq!(reports[1].close_reason, "closed");
    assert_eq!(reports[1].receipt_ack_valid, Some(true));
    // The replay session saw the duplicate and the fresh round 3.
    assert_eq!(reports[1].rounds, 3);
}

// ---------------------------------------------------------------------------
// Replay + bad signature (manual drive against the verifier)
// ---------------------------------------------------------------------------

/// Drives one verification round on a raw session: candidate → result.
async fn drive_round(
    session: &mut modelswarm_transport::Session,
    session_id: &str,
    round: u64,
    parent: &str,
    tokens: &[u32],
) -> (Vec<u32>, Option<u32>, String) {
    send_msg(
        session,
        &SpecMessage::CandidateBlock {
            session_id: session_id.to_string(),
            round,
            parent_prefix_hash: parent.to_string(),
            tokens: tokens.to_vec(),
            proposer_id: "test-proposer".to_string(),
        },
    )
    .await;
    match recv_msg(session).await {
        SpecMessage::VerificationResult {
            accepted_tokens,
            correction,
            new_prefix_hash,
            ..
        } => (accepted_tokens, correction, new_prefix_hash),
        other => panic!("expected verification_result, got {other:?}"),
    }
}

fn commit_from_result(
    session_id: &str,
    round: u64,
    previous: &str,
    accepted: &[u32],
    correction: Option<u32>,
    coordinator: &InstallationIdentity,
) -> SpecMessage {
    let mut tokens = accepted.to_vec();
    tokens.extend(correction);
    let new_hash = compute_prefix_hash(previous, &tokens).unwrap();
    let commit = CommitPrefix {
        session_id: session_id.to_string(),
        round,
        previous_prefix_hash: previous.to_string(),
        accepted_token_ids: tokens,
        new_prefix_hash: new_hash,
        model_profile_id: PROFILE.to_string(),
        generation_params_hash: default_sampling_params_hash(),
        sender: coordinator.installation_id(),
    };
    SpecMessage::signed_commit(&commit, coordinator).unwrap()
}

async fn expect_ack(session: &mut modelswarm_transport::Session) -> (bool, String) {
    match recv_msg(session).await {
        SpecMessage::CommitAck { ok, reason, .. } => (ok, reason),
        other => panic!("expected commit_ack, got {other:?}"),
    }
}

#[tokio::test]
async fn replayed_commit_is_duplicate_and_conflicting_replay_is_stale() {
    let coordinator = ident(20);
    let verifier_id = ident(21);
    let runtime = Arc::new(MockRuntime::new(13, 0.5));
    let (verifier_addr, verifier_server) =
        spawn_verifier(runtime, verifier_id, &coordinator, 1).await;

    let mut session = connect_as(&verifier_addr, &coordinator).await;
    let resumed = prefill(&mut session, "replay-session", &[1, 2, 3]).await;
    assert_eq!(resumed, GENESIS_PREFIX_HASH);

    let (accepted, correction, new_hash) = drive_round(
        &mut session,
        "replay-session",
        1,
        GENESIS_PREFIX_HASH,
        &[9, 9, 9],
    )
    .await;
    let commit = commit_from_result(
        "replay-session",
        1,
        GENESIS_PREFIX_HASH,
        &accepted,
        correction,
        &coordinator,
    );
    assert_eq!(
        commit.commit_prefix().unwrap().new_prefix_hash,
        new_hash,
        "coordinator assembles the verifier's hash exactly"
    );

    send_msg(&mut session, &commit).await;
    let (ok, reason) = expect_ack(&mut session).await;
    assert!(ok && reason == "advanced");

    // Exact replay: remembered duplicate, no advance.
    send_msg(&mut session, &commit).await;
    let (ok, reason) = expect_ack(&mut session).await;
    assert!(ok, "duplicate is a benign no-op");
    assert_eq!(reason, "duplicate");

    // Conflicting same-round commit (different tokens/hash): stale, rejected.
    let conflicting = commit_from_result(
        "replay-session",
        1,
        GENESIS_PREFIX_HASH,
        &[1],
        None,
        &coordinator,
    );
    send_msg(&mut session, &conflicting).await;
    let (ok, reason) = expect_ack(&mut session).await;
    assert!(!ok, "conflicting replay must be rejected");
    assert_eq!(reason, "stale_round");

    // Round 2 still chains (proves no phantom advance happened).
    let parent = commit.commit_prefix().unwrap().new_prefix_hash;
    let (accepted2, correction2, new_hash2) =
        drive_round(&mut session, "replay-session", 2, &parent, &[5]).await;
    let commit2 = commit_from_result(
        "replay-session",
        2,
        &parent,
        &accepted2,
        correction2,
        &coordinator,
    );
    assert_eq!(commit2.commit_prefix().unwrap().new_prefix_hash, new_hash2);
    send_msg(&mut session, &commit2).await;
    let (ok, reason) = expect_ack(&mut session).await;
    assert!(ok && reason == "advanced");

    send_msg(
        &mut session,
        &SpecMessage::SessionClose {
            session_id: "replay-session".to_string(),
            reason: "done".to_string(),
        },
    )
    .await;
    let receipt = recv_msg(&mut session).await;
    let ack = SpecMessage::ReceiptAck {
        requester_signature: sign_receipt_ack(&receipt, &coordinator).unwrap(),
    };
    send_msg(&mut session, &ack).await;
    session.close();

    let reports = verifier_server.await.unwrap().expect("verifier served");
    assert_eq!(reports[0].rounds, 2, "replay did not advance the round");
    assert_eq!(reports[0].stats.rounds, 2);
    assert_eq!(reports[0].receipt_ack_valid, Some(true));
}

#[tokio::test]
async fn bad_signature_commit_rejected_without_advance() {
    let coordinator = ident(30);
    let stranger = ident(31);
    let verifier_id = ident(32);
    let runtime = Arc::new(MockRuntime::new(14, 0.5));
    let (verifier_addr, verifier_server) =
        spawn_verifier(runtime, verifier_id, &coordinator, 1).await;

    let mut session = connect_as(&verifier_addr, &coordinator).await;
    prefill(&mut session, "badsig-session", &[4, 5]).await;
    let (accepted, correction, _) = drive_round(
        &mut session,
        "badsig-session",
        1,
        GENESIS_PREFIX_HASH,
        &[8, 8],
    )
    .await;

    // Signed by the stranger: the sender label is not the session key.
    let wrong_sender = commit_from_result(
        "badsig-session",
        1,
        GENESIS_PREFIX_HASH,
        &accepted,
        correction,
        &stranger,
    );
    send_msg(&mut session, &wrong_sender).await;
    let (ok, reason) = expect_ack(&mut session).await;
    assert!(!ok, "wrong-key commit must be rejected");
    assert!(
        reason.contains("sender is not the authenticated session key"),
        "reason: {reason}"
    );

    // Valid sender label, corrupted signature bytes.
    let mut tampered = commit_from_result(
        "badsig-session",
        1,
        GENESIS_PREFIX_HASH,
        &accepted,
        correction,
        &coordinator,
    );
    if let SpecMessage::PrefixCommit { signature, .. } = &mut tampered {
        // Still valid base64, wrong bytes (first char is never '=' padding).
        let flipped = if signature.starts_with('A') { 'B' } else { 'A' };
        signature.replace_range(0..1, &flipped.to_string());
    }
    send_msg(&mut session, &tampered).await;
    let (ok, reason) = expect_ack(&mut session).await;
    assert!(!ok, "tampered signature must be rejected");
    assert!(reason.contains("bad_signature"), "reason: {reason}");

    // No advance happened: the properly signed round-1 commit still applies.
    let good = commit_from_result(
        "badsig-session",
        1,
        GENESIS_PREFIX_HASH,
        &accepted,
        correction,
        &coordinator,
    );
    send_msg(&mut session, &good).await;
    let (ok, reason) = expect_ack(&mut session).await;
    assert!(ok && reason == "advanced");

    send_msg(
        &mut session,
        &SpecMessage::SessionClose {
            session_id: "badsig-session".to_string(),
            reason: "done".to_string(),
        },
    )
    .await;
    let receipt = recv_msg(&mut session).await;
    let ack = SpecMessage::ReceiptAck {
        requester_signature: sign_receipt_ack(&receipt, &coordinator).unwrap(),
    };
    send_msg(&mut session, &ack).await;
    session.close();

    let reports = verifier_server.await.unwrap().expect("verifier served");
    assert_eq!(reports[0].rounds, 1, "rejected commits never advance");
}

// ---------------------------------------------------------------------------
// D6: acceptance-collapse fallback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn d6_accuracy_zero_triggers_acceptance_collapse_and_stays_exact() {
    let coordinator = ident(40);
    let verifier_id = ident(41);
    let proposer_id = ident(42);
    let prompt = prompt_for(99);

    let verifier_runtime = Arc::new(MockRuntime::new(15, 0.5));
    let proposer_runtime = Arc::new(MockRuntime::new(15, 0.0)); // always-wrong drafts
    let client_runtime = Arc::new(MockRuntime::new(15, 0.5));
    let (verifier_addr, verifier_server) =
        spawn_verifier(verifier_runtime, verifier_id.clone(), &coordinator, 1).await;
    let (proposer_addr, proposer_server) =
        spawn_proposer(proposer_runtime, proposer_id, &coordinator).await;

    let outcome = tokio::time::timeout(
        GLOBAL,
        speculate(
            &verifier_addr,
            &proposer_addr,
            client_runtime.clone(),
            PROFILE,
            &prompt,
            4,
            32,
            &coordinator,
            &verifier_id.verifying_key(),
            FallbackPolicy::default(),
        ),
    )
    .await
    .expect("no hang")
    .expect("speculate with collapsed acceptance still completes");

    assert_eq!(
        outcome.fallback,
        Some(FallbackReason::AcceptanceCollapse),
        "accuracy 0 must trip the fallback"
    );
    let single = single_decode(&client_runtime, &prompt, 32).await;
    assert_eq!(outcome.tokens, single, "fallback output is still exact");
    assert_eq!(outcome.tokens.len(), 32);
    assert!(outcome.receipts_verified);

    let reports = verifier_server.await.unwrap().expect("verifier served");
    assert_eq!(reports[0].stats.accepted_draft_tokens, 0);
    assert_eq!(reports[0].stats.rollbacks, reports[0].stats.rounds);
    let proposer_reports = proposer_server.await.unwrap().expect("proposer served");
    assert!(proposer_reports[0].proposals_served >= 10);
}

// ---------------------------------------------------------------------------
// D7: receipt two-phase close
// ---------------------------------------------------------------------------

#[tokio::test]
async fn d7_mismatched_receipt_ack_ends_session_with_receipt_mismatch() {
    let coordinator = ident(50);
    let stranger = ident(51);
    let verifier_id = ident(52);
    let runtime = Arc::new(MockRuntime::new(16, 0.5));
    // Two sessions: mismatch case, then the missing-ack case.
    let (verifier_addr, verifier_server) =
        spawn_verifier(runtime, verifier_id.clone(), &coordinator, 2).await;

    // Case 1: the receipt verifies, but the ack is signed by the wrong key.
    let mut session = connect_as(&verifier_addr, &coordinator).await;
    prefill(&mut session, "d7-mismatch", &[6, 6, 6]).await;
    send_msg(
        &mut session,
        &SpecMessage::SessionClose {
            session_id: "d7-mismatch".to_string(),
            reason: "done".to_string(),
        },
    )
    .await;
    let receipt = recv_msg(&mut session).await;
    assert!(verify_receipt_signature(&receipt, &verifier_id.verifying_key()).is_ok());
    let bad_ack = SpecMessage::ReceiptAck {
        requester_signature: sign_receipt_ack(&receipt, &stranger).unwrap(),
    };
    send_msg(&mut session, &bad_ack).await;
    // The verifier ends the session: further reads surface an error, not a hang.
    let _ = tokio::time::timeout(GLOBAL, session.recv_json(D)).await;
    session.close();

    // Case 2: the requester never acks — the verifier reports it.
    let mut session2 = connect_as(&verifier_addr, &coordinator).await;
    prefill(&mut session2, "d7-missing", &[7, 7]).await;
    send_msg(
        &mut session2,
        &SpecMessage::SessionClose {
            session_id: "d7-missing".to_string(),
            reason: "done".to_string(),
        },
    )
    .await;
    let receipt2 = recv_msg(&mut session2).await;
    assert!(matches!(receipt2, SpecMessage::Receipt { .. }));
    session2.close(); // no ack

    let reports = tokio::time::timeout(GLOBAL, verifier_server)
        .await
        .expect("server finishes")
        .unwrap()
        .expect("verifier served");
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].receipt_ack_valid, Some(false));
    assert_eq!(reports[0].close_reason, "receipt_mismatch");
    assert_eq!(reports[1].receipt_ack_valid, None);
    assert_eq!(reports[1].close_reason, "closed_without_receipt_ack");
}

// ---------------------------------------------------------------------------
// Gateway executor (greedy/single) event mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn speculative_executor_maps_session_to_gateway_events() {
    use modelswarm_gateway::{
        ExecutorEvent, FinishReason, InferenceExecutor, NormalizedMessage, NormalizedRequest,
        Sampling as GatewaySampling,
    };

    let coordinator = ident(60);
    let verifier_id = ident(61);
    let proposer_id = ident(62);

    let verifier_runtime = Arc::new(MockRuntime::new(17, 1.0));
    let proposer_runtime = Arc::new(MockRuntime::new(17, 1.0));
    let client_runtime = Arc::new(MockRuntime::new(17, 1.0));
    let (verifier_addr, verifier_server) =
        spawn_verifier(verifier_runtime, verifier_id.clone(), &coordinator, 1).await;
    let (proposer_addr, proposer_server) =
        spawn_proposer(proposer_runtime, proposer_id, &coordinator).await;

    let executor = SpeculativeExecutor::new(
        vec![SpecPeer {
            verifier_addr,
            proposer_addr,
            verifier_key: verifier_id.verifying_key(),
        }],
        coordinator,
        client_runtime.clone(),
        PROFILE,
        4,
        FallbackPolicy::default(),
    );
    let request = NormalizedRequest {
        request_id: "req-exec-1".to_string(),
        profile_id: PROFILE.to_string(),
        capability_token: None,
        messages: vec![NormalizedMessage {
            role: "user".to_string(),
            content: "spec executor".to_string(),
        }],
        sampling: GatewaySampling {
            temperature: 1.0,
            top_p: 1.0,
            top_k: 40,
            seed: None,
        },
        max_tokens: 16,
        deadline_ms: 10_000,
        stream: true,
    };

    let events: Vec<ExecutorEvent> = tokio::time::timeout(GLOBAL, async {
        let mut collected = Vec::new();
        let mut stream = executor.execute(request).await.expect("execute");
        while let Some(event) = stream.next().await {
            collected.push(event);
        }
        collected
    })
    .await
    .expect("no hang");

    // Event shape: Accepted once, TokenDelta per committed batch (indices in
    // order), Usage, Completed.
    assert!(matches!(
        events.first(),
        Some(ExecutorEvent::Accepted { .. })
    ));
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, ExecutorEvent::Accepted { .. }))
            .count(),
        1,
        "accepted exactly once"
    );
    let deltas: Vec<&ExecutorEvent> = events
        .iter()
        .filter(|e| matches!(e, ExecutorEvent::TokenDelta { .. }))
        .collect();
    assert!(!deltas.is_empty());
    for (index, event) in deltas.iter().enumerate() {
        if let ExecutorEvent::TokenDelta {
            index: i, delta, ..
        } = event
        {
            assert_eq!(*i, index as u32);
            assert!(!delta.is_empty());
        }
    }
    // The batch deltas concatenate to the detokenization of exactly 16 mock
    // tokens: the executor's own prompt (tokenized request text) drives the
    // session, so equality against a local decode of the same text holds.
    let conversation = "spec executor\n";
    let prompt = client_runtime.tokenize(conversation).await.unwrap();
    let single = single_decode(&client_runtime, &prompt, 16).await;
    let expected_text = client_runtime.detokenize(&single).await.unwrap();
    let mut text = String::new();
    for event in &deltas {
        if let ExecutorEvent::TokenDelta { delta, .. } = event {
            text.push_str(delta);
        }
    }
    assert_eq!(
        text, expected_text,
        "concatenated deltas equal single decode"
    );
    let usage = events
        .iter()
        .find_map(|e| match e {
            ExecutorEvent::Usage {
                completion_tokens,
                prompt_tokens,
                ..
            } => Some((*completion_tokens, *prompt_tokens)),
            _ => None,
        })
        .expect("usage precedes completed");
    assert_eq!(usage.0, 16);
    assert_eq!(usage.1, prompt.len() as u32);
    let finish = events
        .iter()
        .find_map(|e| match e {
            ExecutorEvent::Completed { finish_reason } => Some(*finish_reason),
            _ => None,
        })
        .expect("completed event");
    assert_eq!(finish, FinishReason::Length);
    assert_eq!(
        events.last(),
        Some(&ExecutorEvent::Completed {
            finish_reason: FinishReason::Length
        })
    );

    // Drain servers.
    let _ = verifier_server.await;
    let _ = proposer_server.await;
}
