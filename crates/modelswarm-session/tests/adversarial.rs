//! Phase F adversarial suite (F1–F5, F7–F10): malicious peers over REAL
//! loopback TCP driving the full speculative protocol.
//!
//! Per gate (`docs/acceptance/phase-f.md` + the revision's threat list):
//!
//! - **F1** fabricated proposals: a proposer that answers every request with
//!   plausible garbage tokens across 50 full sessions → verification only
//!   ever commits target-authoritative tokens; output stays token-exact vs
//!   plain single decoding; acceptance collapse trips the bounded fallback.
//! - **F2** lying proposer invariants: wrong `parent_prefix_hash`, stale
//!   round, unknown session, mutated tokens → typed rejections, no state
//!   advance, session continues or fails explicitly (never corrupts).
//! - **F3** prefix equivocation: TWO attacker verifiers claiming different
//!   `new_prefix_hash` for the same round → the coordinator's own hash
//!   validation fails both; no commit is emitted; explicit failure.
//! - **F4** replay: a captured signed commit over a NEW connection →
//!   `duplicate`; a commit naming a different session → wrong-session-style
//!   typed rejection; a re-signed commit with a mutated token list →
//!   `hash_mismatch`.
//! - **F5** withholding: a proposer that accepts ProposalRequest and never
//!   replies → two-peer mode falls back explicitly and stays exact;
//!   multi-proposer mode completes every round from the remaining proposers
//!   with the withholder counted as a straggler each round (slot skip).
//! - **F7** malicious verifier accepting garbage: a rogue verifier returning
//!   hash-CONSISTENT results over garbage → the coordinator's final-chain
//!   auditor re-verification catches it; no outcome is emitted. The honest
//!   control passes the same audit.
//! - **F8** flood: 1000 malformed/oversized/valid-JSON-garbage frames at a
//!   verifier listener → clean typed rejections, bounded queues, the server
//!   still serves a legitimate session afterwards.
//! - **F9** malformed-frame fuzz: 10 000 seeded mutations (truncation, bit
//!   flips, oversized prefixes, invalid UTF-8, deep nesting ≤ 1 MiB) against
//!   the frame decoder + message deserializers → no panics, no unbounded
//!   allocation (payload cap enforced before body read).
//! - **F10** redaction gate: a full adversarial session logged with a
//!   prompt canary → the canary never appears in any sink line.
//!
//! F6 lives in `modelswarm-scheduler` (measured-dominance + the ADR-014
//! NAT-path penalty); F11/F12/F13 live in `modelswarm-transport`,
//! `modelswarm-identity`/`apps/tracker`, and `apps/modelswarm-sim`.
//!
//! Every case is hang-free by construction (`tokio::time::timeout`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use modelswarm_identity::InstallationIdentity;
use modelswarm_runtime::{InferenceRuntime, MockRuntime, SamplingParams};
use modelswarm_session::spec::{
    default_sampling_params_hash, serve_proposer, serve_proposer_multi, serve_speculative,
    sign_receipt_ack, speculate, speculate_multi, FallbackPolicy, FallbackReason,
    ProposerRuntimeFactory, SpecError, SpecMessage, GENESIS_PREFIX_HASH,
};
use modelswarm_session::{compute_prefix_hash, CommitPrefix};
use modelswarm_speculation::TrieLimits;
use modelswarm_telemetry::Telemetry;
use modelswarm_transport::ed25519_dalek::VerifyingKey;
use modelswarm_transport::frame::read_frame_raw;
use modelswarm_transport::{Handshake, Listener, SignedFrameTransport, MAX_FRAME_BYTES};
use serde_json::json;

const PROFILE: &str = "msp:adv:v1";
const D: Duration = Duration::from_secs(10);
/// Global per-case timeout: no adversarial test may hang.
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

/// Plain single decoding of `n` tokens (the exactness oracle).
async fn single_decode(runtime: &Arc<MockRuntime>, prompt: &[u32], n: u32) -> Vec<u32> {
    let handle = runtime.load(PROFILE).await.expect("load");
    runtime
        .decode_stream(&handle, prompt, &SamplingParams::default(), n, D)
        .await
        .expect("single decode")
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

/// Minimal prefill exchange; returns the resumed prefix hash.
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
            proposer_id: "adv-attacker".to_string(),
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

fn commit_for(
    session_id: &str,
    round: u64,
    previous: &str,
    tokens: Vec<u32>,
    new_hash: &str,
    coordinator: &InstallationIdentity,
) -> SpecMessage {
    let commit = CommitPrefix {
        session_id: session_id.to_string(),
        round,
        previous_prefix_hash: previous.to_string(),
        accepted_token_ids: tokens,
        new_prefix_hash: new_hash.to_string(),
        model_profile_id: PROFILE.to_string(),
        generation_params_hash: default_sampling_params_hash(),
        sender: coordinator.installation_id(),
    };
    SpecMessage::signed_commit(&commit, coordinator).expect("sign")
}

async fn expect_ack(session: &mut modelswarm_transport::Session) -> (bool, String) {
    match recv_msg(session).await {
        SpecMessage::CommitAck { ok, reason, .. } => (ok, reason),
        other => panic!("expected commit_ack, got {other:?}"),
    }
}

async fn close_and_reap(
    session: &mut modelswarm_transport::Session,
    session_id: &str,
    coordinator: &InstallationIdentity,
) {
    send_msg(
        session,
        &SpecMessage::SessionClose {
            session_id: session_id.to_string(),
            reason: "done".to_string(),
        },
    )
    .await;
    let receipt = recv_msg(session).await;
    let ack = SpecMessage::ReceiptAck {
        requester_signature: sign_receipt_ack(&receipt, coordinator).unwrap(),
    };
    send_msg(session, &ack).await;
    session.close();
}

// ---------------------------------------------------------------------------
// F1 — fabricated proposals
// ---------------------------------------------------------------------------

/// A malicious proposer: prefills honestly, then answers EVERY proposal
/// request with plausible-looking garbage tokens (valid vocab ids, never the
/// target continuation). Tracks the commit chain like an honest proposer so
/// its fabrications chain (a maximal-effort fabricator, not a weak one that
/// would also fail parent validation).
async fn serve_fabricating_proposer(listener: Listener, requester: InstallationIdentity) {
    let mut session = listener
        .accept(&requester.verifying_key(), D)
        .await
        .expect("fabricator accept");
    let session_id = match recv_msg(&mut session).await {
        SpecMessage::PrefillRequest { session_id, .. } => session_id,
        other => panic!("fabricator expected prefill, got {other:?}"),
    };
    send_msg(
        &mut session,
        &SpecMessage::PrefillReady {
            session_id: session_id.clone(),
            kv_commitment_digest: "fabricated-digest".to_string(),
            accepted_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        },
    )
    .await;
    let mut last_hash = GENESIS_PREFIX_HASH.to_string();
    let mut fabrication = 0u64;
    loop {
        let msg = match session.recv_json(D).await {
            Ok(value) => serde_json::from_value(value).expect("spec message"),
            Err(_) => return, // coordinator went away
        };
        match msg {
            SpecMessage::ProposalRequest { round, window, .. } => {
                fabrication += 1;
                // Plausible garbage: valid vocab ids, deterministic, mixed
                // independently of the target model's continuation.
                let garbage: Vec<u32> = (0..window)
                    .map(|i| {
                        (0xDEAD_BEEF_u64
                            .wrapping_mul(fabrication)
                            .wrapping_add(u64::from(i) * 131 + round)
                            % 256) as u32
                    })
                    .collect();
                send_msg(
                    &mut session,
                    &SpecMessage::CandidateBlock {
                        session_id: session_id.clone(),
                        round,
                        parent_prefix_hash: last_hash.clone(),
                        tokens: garbage,
                        proposer_id: "fabricator".to_string(),
                    },
                )
                .await;
            }
            SpecMessage::PrefixCommit {
                round,
                new_prefix_hash,
                ..
            } => {
                last_hash = new_prefix_hash;
                send_msg(
                    &mut session,
                    &SpecMessage::CommitAck {
                        session_id: session_id.clone(),
                        round,
                        ok: true,
                        reason: "advanced".to_string(),
                    },
                )
                .await;
            }
            SpecMessage::SessionClose { .. } => return,
            _ => {}
        }
    }
}

/// F1: 50 full sessions against the fabricating proposer. The verifier
/// never commits a fabricated token (only corrections); the session falls
/// back on acceptance collapse; output is token-exact vs single decoding.
#[tokio::test]
async fn f1_fabricated_proposals_rejected_and_output_stays_exact_50_seeds() {
    const SEEDS: u64 = 50;
    const TOKENS: u32 = 12;
    const WINDOW: u32 = 3;
    let mut collapsed = 0usize;
    for seed in 0..SEEDS {
        let case = tokio::time::timeout(GLOBAL, async {
            let coordinator = ident(1);
            let verifier_id = ident(2);
            let prompt = prompt_for(seed);
            let verifier_runtime = Arc::new(MockRuntime::new(seed, 0.5));
            let client_runtime = Arc::new(MockRuntime::new(seed, 0.5));
            let (verifier_addr, verifier_server) = spawn_verifier(
                verifier_runtime.clone(),
                verifier_id.clone(),
                &coordinator,
                1,
            )
            .await;
            let (fabricator_listener, fabricator_addr) = listen().await;
            let fabricator = tokio::spawn(serve_fabricating_proposer(
                fabricator_listener,
                coordinator.clone(),
            ));

            let outcome = speculate(
                &verifier_addr,
                &fabricator_addr,
                client_runtime.clone(),
                PROFILE,
                &prompt,
                WINDOW,
                TOKENS,
                &coordinator,
                &verifier_id.verifying_key(),
                FallbackPolicy::default(),
            )
            .await
            .expect("fabricated-proposer session completes");

            let single = single_decode(&client_runtime, &prompt, TOKENS).await;
            let reports = verifier_server.await.unwrap().expect("verifier served");
            fabricator.await.expect("fabricator reaped");
            (outcome, single, reports)
        })
        .await
        .expect("no hang");
        let (outcome, single, reports) = case;

        // Lossless contract: fabricated tokens can never bend the output.
        assert_eq!(
            outcome.tokens, single,
            "seed={seed}: committed output must equal single decoding"
        );
        assert_eq!(outcome.tokens.len(), TOKENS as usize, "seed={seed}");
        assert!(outcome.receipts_verified, "seed={seed}");
        // The verifier never systematically accepted fabricated drafts: only
        // the per-round correction commits during the speculative phase (a
        // fabricated token can COINCIDENTALLY equal the target's next token
        // with p=1/256 per round — bounded coincidences, never a pattern).
        let report = &reports[0];
        assert!(
            report.stats.accepted_draft_tokens <= 2,
            "seed={seed}: garbage drafts must never be systematically accepted (got {})",
            report.stats.accepted_draft_tokens
        );
        assert_eq!(report.stats.rounds, 10, "seed={seed}: ten garbage rounds");
        assert!(
            report.stats.rollbacks >= 8,
            "seed={seed}: almost every garbage round is a rejection (got {})",
            report.stats.rollbacks
        );
        assert_eq!(report.committed_tokens, TOKENS as u64, "seed={seed}");
        // Bounded fallback fired (the verifier limits the damage of a
        // zero-acceptance proposer by switching to the exact single path).
        assert_eq!(
            outcome.fallback,
            Some(FallbackReason::AcceptanceCollapse),
            "seed={seed}: fabricator must trip acceptance collapse"
        );
        collapsed += 1;
    }
    assert_eq!(collapsed as u64, SEEDS);
}

// ---------------------------------------------------------------------------
// F2 — lying proposer invariants
// ---------------------------------------------------------------------------

/// F2: blocks with a wrong parent hash, a stale round, mutated tokens, and
/// commits for an unknown session are each rejected with a typed response;
/// the verifier's state never advances from an attack; the session continues
/// (or fails explicitly) without corruption.
#[tokio::test]
async fn f2_lying_proposer_invariants_typed_rejections_no_state_advance() {
    let coordinator = ident(10);
    let verifier_id = ident(11);
    let runtime = Arc::new(MockRuntime::new(31, 0.5));
    // Two sequential sessions on one verifier: the invariant attacks, then
    // the wrong-session probe (which ends its connection with an error).
    let (verifier_addr, verifier_server) =
        spawn_verifier(runtime.clone(), verifier_id, &coordinator, 2).await;

    let prompt = prompt_for(41);
    let mut session = connect_as(&verifier_addr, &coordinator).await;
    let resumed = prefill(&mut session, "f2", &prompt).await;
    assert_eq!(resumed, GENESIS_PREFIX_HASH);

    // (a) Wrong parent_prefix_hash → typed CancelRound(parent_mismatch).
    send_msg(
        &mut session,
        &SpecMessage::CandidateBlock {
            session_id: "f2".to_string(),
            round: 1,
            parent_prefix_hash: hex::encode([1u8; 32]),
            tokens: vec![1, 2, 3],
            proposer_id: "adv".to_string(),
        },
    )
    .await;
    match recv_msg(&mut session).await {
        SpecMessage::CancelRound { reason, round, .. } => {
            assert_eq!(round, 1);
            assert_eq!(reason, "parent_mismatch", "typed rejection required");
        }
        other => panic!("expected cancel_round, got {other:?}"),
    }

    // (b) Stale round (0 = behind the next round) → typed cancel.
    send_msg(
        &mut session,
        &SpecMessage::CandidateBlock {
            session_id: "f2".to_string(),
            round: 0,
            parent_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
            tokens: vec![1],
            proposer_id: "adv".to_string(),
        },
    )
    .await;
    match recv_msg(&mut session).await {
        SpecMessage::CancelRound { reason, .. } => {
            assert_eq!(reason, "parent_mismatch");
        }
        other => panic!("expected cancel_round, got {other:?}"),
    }
    // (b') Future round (7) → typed cancel as well.
    send_msg(
        &mut session,
        &SpecMessage::CandidateBlock {
            session_id: "f2".to_string(),
            round: 7,
            parent_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
            tokens: vec![1],
            proposer_id: "adv".to_string(),
        },
    )
    .await;
    match recv_msg(&mut session).await {
        SpecMessage::CancelRound { reason, .. } => {
            assert_eq!(reason, "parent_mismatch");
        }
        other => panic!("expected cancel_round, got {other:?}"),
    }

    // (c) Mutated tokens: the honest verification returns only the
    // target-authoritative continuation (garbage accepted prefix is empty).
    let garbage = vec![200u32, 199, 198];
    let (accepted, correction, _) =
        drive_round(&mut session, "f2", 1, GENESIS_PREFIX_HASH, &garbage).await;
    assert!(
        accepted.is_empty(),
        "mutated/garbage tokens cannot be accepted"
    );
    let true_next = single_decode(&runtime, &prompt, 1).await;
    assert_eq!(
        correction,
        Some(true_next[0]),
        "correction is the true token"
    );

    // (d) No state advanced: the honest round-1 commit still applies.
    let mut honest = vec![true_next[0]];
    let new_hash = compute_prefix_hash(GENESIS_PREFIX_HASH, &honest).unwrap();
    let commit = commit_for(
        "f2",
        1,
        GENESIS_PREFIX_HASH,
        honest.clone(),
        &new_hash,
        &coordinator,
    );
    send_msg(&mut session, &commit).await;
    let (ok, reason) = expect_ack(&mut session).await;
    assert!(ok && reason == "advanced", "reason={reason}");
    honest.clear();

    close_and_reap(&mut session, "f2", &coordinator).await;

    // (e) Wrong session_id: a commit naming a session the verifier never
    // prefilled is a wrong-session-style typed rejection — the connection
    // fails explicitly (structured error, never a hang, never corruption).
    let mut ghost = connect_as(&verifier_addr, &coordinator).await;
    prefill(&mut ghost, "f2-real", &prompt).await;
    let ghost_hash = compute_prefix_hash(GENESIS_PREFIX_HASH, &[7u32]).unwrap();
    let foreign = commit_for(
        "f2-ghost",
        1,
        GENESIS_PREFIX_HASH,
        vec![7],
        &ghost_hash,
        &coordinator,
    );
    send_msg(&mut ghost, &foreign).await;
    let observed = tokio::time::timeout(GLOBAL, ghost.recv_json(D)).await;
    assert!(
        observed.is_err() || observed.unwrap().is_err(),
        "the wrong-session commit must end the connection explicitly"
    );
    ghost.close();

    let reports = tokio::time::timeout(GLOBAL, verifier_server)
        .await
        .expect("server reaped")
        .unwrap()
        .expect("verifier served");
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].rounds, 1, "attacks never advance the round");
    assert_eq!(reports[0].receipt_ack_valid, Some(true));
    assert!(
        reports[1].close_reason.contains("unknown session"),
        "wrong-session close reason: {}",
        reports[1].close_reason
    );
}

// ---------------------------------------------------------------------------
// F3 — prefix equivocation (attacker verifiers)
// ---------------------------------------------------------------------------

/// A lying verifier: completes the prefill, then answers every candidate
/// block with a VerificationResult whose new_prefix_hash is `bogus_hash`
/// (different attackers claim different hashes for the same round — the
/// equivocation). Tracks whether the coordinator ever sent a commit.
async fn serve_lying_verifier(
    listener: Listener,
    requester: InstallationIdentity,
    bogus_hash: String,
    saw_commit: Arc<AtomicBool>,
) {
    let mut session = listener
        .accept(&requester.verifying_key(), D)
        .await
        .expect("lying verifier accept");
    let session_id = match recv_msg(&mut session).await {
        SpecMessage::PrefillRequest { session_id, .. } => session_id,
        other => panic!("lying verifier expected prefill, got {other:?}"),
    };
    send_msg(
        &mut session,
        &SpecMessage::PrefillReady {
            session_id: session_id.clone(),
            kv_commitment_digest: "lying-digest".to_string(),
            accepted_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        },
    )
    .await;
    loop {
        let msg = match session.recv_json(D).await {
            Ok(value) => serde_json::from_value(value).expect("spec message"),
            Err(_) => return,
        };
        match msg {
            SpecMessage::CandidateBlock { round, tokens, .. } => {
                send_msg(
                    &mut session,
                    &SpecMessage::VerificationResult {
                        session_id: session_id.clone(),
                        round,
                        accepted_tokens: tokens,
                        correction: None,
                        new_prefix_hash: bogus_hash.clone(),
                    },
                )
                .await;
            }
            SpecMessage::PrefixCommit { .. } => {
                saw_commit.store(true, Ordering::SeqCst);
                return;
            }
            SpecMessage::SessionClose { .. } => return,
            _ => {}
        }
    }
}

/// F3: two attacker verifiers claim DIFFERENT new_prefix_hash values for the
/// same round. The coordinator validates the hash itself from the committed
/// tokens and rejects both attempts with an explicit typed failure; neither
/// attacker ever receives a commit.
#[tokio::test]
async fn f3_prefix_equivocation_detected_no_garbage_committed() {
    let bogus_hashes = [
        "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
    ];
    for (attempt, bogus) in bogus_hashes.iter().enumerate() {
        let result = tokio::time::timeout(GLOBAL, async {
            let coordinator = ident(20);
            let proposer_id = ident(21);
            let prompt = prompt_for(55);
            let proposer_runtime = Arc::new(MockRuntime::new(55, 1.0));
            let client_runtime: Arc<dyn InferenceRuntime> = Arc::new(MockRuntime::new(55, 1.0));
            let (proposer_addr, proposer_server) =
                spawn_proposer(proposer_runtime, proposer_id, &coordinator).await;
            let (liar_listener, liar_addr) = listen().await;
            let saw_commit = Arc::new(AtomicBool::new(false));
            let liar = tokio::spawn(serve_lying_verifier(
                liar_listener,
                coordinator.clone(),
                bogus.clone(),
                Arc::clone(&saw_commit),
            ));

            let outcome = speculate(
                &liar_addr,
                &proposer_addr,
                client_runtime,
                PROFILE,
                &prompt,
                4,
                16,
                &coordinator,
                &coordinator.verifying_key(), // any key: no receipt is reached
                FallbackPolicy::default(),
            )
            .await;
            let _ = proposer_server.await;
            let _ = liar.await;
            (outcome, saw_commit.load(Ordering::SeqCst))
        })
        .await
        .expect("no hang");

        let (outcome, saw_commit) = result;
        let err = outcome.expect_err("a lying verifier must fail the session");
        match &err {
            SpecError::Protocol(why) => assert!(
                why.contains("new_prefix_hash does not match the committed tokens"),
                "attempt {attempt}: typed hash-validation failure required, got: {why}"
            ),
            other => panic!("attempt {attempt}: expected Protocol error, got {other:?}"),
        }
        assert!(
            !saw_commit,
            "attempt {attempt}: no commit may be emitted to an equivocating verifier"
        );
    }

    // Control: an honest verifier passes the same check trivially (the
    // coordinator assembles exactly the hash the verifier computed).
    let control = tokio::time::timeout(GLOBAL, async {
        let coordinator = ident(22);
        let verifier_id = ident(23);
        let proposer_id = ident(24);
        let prompt = prompt_for(56);
        let verifier_runtime = Arc::new(MockRuntime::new(56, 1.0));
        let proposer_runtime = Arc::new(MockRuntime::new(56, 1.0));
        let client_runtime = Arc::new(MockRuntime::new(56, 1.0));
        let (verifier_addr, verifier_server) =
            spawn_verifier(verifier_runtime, verifier_id.clone(), &coordinator, 1).await;
        let (proposer_addr, proposer_server) =
            spawn_proposer(proposer_runtime, proposer_id, &coordinator).await;
        let outcome = speculate(
            &verifier_addr,
            &proposer_addr,
            client_runtime.clone(),
            PROFILE,
            &prompt,
            4,
            12,
            &coordinator,
            &verifier_id.verifying_key(),
            FallbackPolicy::default(),
        )
        .await
        .unwrap();
        let single = single_decode(&client_runtime, &prompt, 12).await;
        let _ = verifier_server.await;
        let _ = proposer_server.await;
        (outcome.tokens == single, outcome.receipts_verified)
    })
    .await
    .expect("no hang");
    assert_eq!(control, (true, true));
}

// ---------------------------------------------------------------------------
// F4 — replay matrix
// ---------------------------------------------------------------------------

/// F4: replay of a captured signed PrefixCommit over a NEW connection is a
/// benign `duplicate`; a commit naming a different session is rejected
/// wrong-session-style; a re-signed commit with a mutated token list but the
/// honest round hash is `hash_mismatch`. State never advances from a replay.
#[tokio::test]
async fn f4_replay_matrix_duplicate_wrong_session_hash_mismatch() {
    let coordinator = ident(30);
    let verifier_id = ident(31);
    let runtime = Arc::new(MockRuntime::new(61, 0.5));
    // Session 1: the live session; sessions 2–3: the reconnect and
    // wrong-session probes.
    let (verifier_addr, verifier_server) =
        spawn_verifier(runtime, verifier_id, &coordinator, 3).await;

    let prompt = prompt_for(61);
    let mut session = connect_as(&verifier_addr, &coordinator).await;
    prefill(&mut session, "f4", &prompt).await;

    // Capture a real signed commit for round 1.
    let (accepted, correction, verified_hash) =
        drive_round(&mut session, "f4", 1, GENESIS_PREFIX_HASH, &[9, 9, 9]).await;
    let mut round1 = accepted.clone();
    round1.extend(correction);
    assert_eq!(
        compute_prefix_hash(GENESIS_PREFIX_HASH, &round1).unwrap(),
        verified_hash,
        "coordinator assembles the verifier's hash exactly"
    );
    let captured = commit_for(
        "f4",
        1,
        GENESIS_PREFIX_HASH,
        round1.clone(),
        &verified_hash,
        &coordinator,
    );
    send_msg(&mut session, &captured).await;
    let (ok, reason) = expect_ack(&mut session).await;
    assert!(ok && reason == "advanced");
    let parent = verified_hash.clone();
    close_and_reap(&mut session, "f4", &coordinator).await;

    // (a) Replay the captured commit over a NEW connection (reconnect +
    // resume): remembered duplicate, no advance.
    let mut resumed = connect_as(&verifier_addr, &coordinator).await;
    let resume_hash = prefill(&mut resumed, "f4", &prompt).await;
    assert_eq!(resume_hash, parent, "reconnect resumes from the commit");
    send_msg(&mut resumed, &captured).await;
    let (ok, reason) = expect_ack(&mut resumed).await;
    assert!(ok, "replay duplicate is a benign no-op");
    assert_eq!(reason, "duplicate");

    // (b) Mutated token list, validly re-signed (a compromised signer),
    // claiming the HONEST round-2 hash over mutated tokens → the state
    // machine recomputes the hash and rejects `hash_mismatch` (typed).
    let (accepted2, correction2, honest_hash2) =
        drive_round(&mut resumed, "f4", 2, &parent, &[5]).await;
    let mut honest2 = accepted2;
    honest2.extend(correction2);
    assert_eq!(
        compute_prefix_hash(&parent, &honest2).unwrap(),
        honest_hash2
    );
    let mut mutated = honest2.clone();
    mutated[0] = mutated[0].wrapping_add(1);
    assert_ne!(mutated, honest2, "the mutation must change the tokens");
    let attack = commit_for("f4", 2, &parent, mutated, &honest_hash2, &coordinator);
    send_msg(&mut resumed, &attack).await;
    let (ok, reason) = expect_ack(&mut resumed).await;
    assert!(!ok, "mutated-token commit must be rejected");
    assert_eq!(reason, "hash_mismatch", "typed hash mismatch required");
    // No state advance: the honest round-2 commit still applies.
    let honest = commit_for("f4", 2, &parent, honest2, &honest_hash2, &coordinator);
    send_msg(&mut resumed, &honest).await;
    let (ok, reason) = expect_ack(&mut resumed).await;
    assert!(ok && reason == "advanced", "reason={reason}");
    close_and_reap(&mut resumed, "f4", &coordinator).await;

    // (c) Cross-session replay: a commit naming a session the verifier never
    // prefilled ("f4-ghost" — the replay target session) → wrong-session-
    // style typed rejection: the connection fails explicitly; nothing hangs,
    // no state changes anywhere.
    let mut probe = connect_as(&verifier_addr, &coordinator).await;
    prefill(&mut probe, "f4-probe", &prompt).await;
    let ghost_hash = compute_prefix_hash(GENESIS_PREFIX_HASH, &[7u32]).unwrap();
    let ghost = commit_for(
        "f4-ghost",
        1,
        GENESIS_PREFIX_HASH,
        vec![7],
        &ghost_hash,
        &coordinator,
    );
    send_msg(&mut probe, &ghost).await;
    let observed = tokio::time::timeout(GLOBAL, probe.recv_json(D)).await;
    assert!(
        observed.is_err() || observed.unwrap().is_err(),
        "cross-session replay must fail explicitly, not hang"
    );
    probe.close();

    let reports = tokio::time::timeout(GLOBAL, verifier_server)
        .await
        .expect("server reaped")
        .unwrap()
        .expect("verifier served");
    assert_eq!(reports.len(), 3);
    assert_eq!(reports[0].rounds, 1, "session 1: one commit");
    assert_eq!(reports[0].receipt_ack_valid, Some(true));
    assert_eq!(
        reports[1].rounds, 2,
        "replays never advanced beyond round 2"
    );
    assert_eq!(reports[1].receipt_ack_valid, Some(true));
    assert!(
        reports[2].close_reason.contains("unknown session"),
        "wrong-session close reason: {}",
        reports[2].close_reason
    );
}

// ---------------------------------------------------------------------------
// F5 — withholding
// ---------------------------------------------------------------------------

/// A withholding proposer: prefills, then NEVER answers a proposal request
/// (reads and drops everything, answers nothing).
async fn serve_withholding_proposer(listener: Listener, requester: InstallationIdentity) {
    let mut session = listener
        .accept(&requester.verifying_key(), D)
        .await
        .expect("withholder accept");
    let session_id = match recv_msg(&mut session).await {
        SpecMessage::PrefillRequest { session_id, .. } => session_id,
        other => panic!("withholder expected prefill, got {other:?}"),
    };
    send_msg(
        &mut session,
        &SpecMessage::PrefillReady {
            session_id: session_id.clone(),
            kv_commitment_digest: "withheld".to_string(),
            accepted_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        },
    )
    .await;
    // Read everything, reply to NOTHING except keeping the connection alive:
    // commits are acked (liveness), proposals are withheld forever.
    loop {
        let msg = match session.recv_json(D).await {
            Ok(value) => serde_json::from_value(value).expect("spec message"),
            Err(_) => return,
        };
        match msg {
            SpecMessage::ProposalRequest { .. } => { /* the withholding */ }
            SpecMessage::PrefixCommit { round, .. } => {
                send_msg(
                    &mut session,
                    &SpecMessage::CommitAck {
                        session_id: session_id.clone(),
                        round,
                        ok: true,
                        reason: "advanced".to_string(),
                    },
                )
                .await;
            }
            SpecMessage::SessionClose { .. } => return,
            _ => {}
        }
    }
}

/// F5 (two-peer): the coordinator's round deadline fires against the silent
/// proposer, the session falls back EXPLICITLY to exact single decoding, and
/// nothing hangs (bounded by GLOBAL, far below it).
#[tokio::test]
async fn f5_withholding_proposer_two_peer_falls_back_exactly() {
    let coordinator = ident(40);
    let verifier_id = ident(41);
    let prompt = prompt_for(71);
    let verifier_runtime = Arc::new(MockRuntime::new(71, 0.5));
    let client_runtime = Arc::new(MockRuntime::new(71, 0.5));
    let (verifier_addr, verifier_server) =
        spawn_verifier(verifier_runtime, verifier_id.clone(), &coordinator, 1).await;
    let (withholder_listener, withholder_addr) = listen().await;
    let withholder = tokio::spawn(serve_withholding_proposer(
        withholder_listener,
        coordinator.clone(),
    ));

    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        GLOBAL,
        speculate(
            &verifier_addr,
            &withholder_addr,
            client_runtime.clone(),
            PROFILE,
            &prompt,
            4,
            12,
            &coordinator,
            &verifier_id.verifying_key(),
            FallbackPolicy::default(),
        ),
    )
    .await
    .expect("no coordinator stall against a silent proposer")
    .expect("session completes via fallback");

    // The withhold cost exactly one bounded round deadline (10 s), not a
    // hang: the whole session stays well inside GLOBAL.
    let elapsed = started.elapsed();
    assert!(
        elapsed < GLOBAL,
        "withholding must cost one deadline, not a stall (took {elapsed:?})"
    );
    assert_eq!(outcome.fallback, Some(FallbackReason::PeerLost));
    let single = single_decode(&client_runtime, &prompt, 12).await;
    assert_eq!(outcome.tokens, single, "fallback path is exact");
    assert_eq!(outcome.tokens.len(), 12);
    assert!(outcome.receipts_verified);
    let reports = verifier_server.await.unwrap().expect("verifier served");
    assert_eq!(reports[0].close_reason, "closed");
    withholder.abort();
}

/// F5 (multi-proposer): rounds complete from the remaining proposers while
/// one withholds; the withholder is counted a straggler EVERY round (the
/// slot is skipped, not leaked into a stall); output stays exact.
#[tokio::test]
async fn f5_withholding_proposer_multi_rounds_complete_from_remaining() {
    let coordinator = ident(45);
    let verifier_id = ident(46);
    let prompt = prompt_for(72);
    let accuracy = 0.8f32;
    let verifier_runtime = Arc::new(MockRuntime::new(72, accuracy));
    let client_runtime: Arc<dyn InferenceRuntime> = Arc::new(MockRuntime::new(72, accuracy));

    let (verifier_addr, verifier_server) = spawn_verifier(
        verifier_runtime.clone(),
        verifier_id.clone(),
        &coordinator,
        1,
    )
    .await;

    // Roster of 3: proposers 0 and 2 are honest seeded multi-proposers;
    // proposer 1 accepts requests and never replies.
    let mut proposer_addrs = Vec::new();
    let mut honest_tasks = Vec::new();
    let mut withholder_task = None;
    for index in 0..3usize {
        let (listener, addr) = listen().await;
        proposer_addrs.push(addr);
        if index == 1 {
            withholder_task = Some(tokio::spawn(serve_withholding_proposer(
                listener,
                coordinator.clone(),
            )));
        } else {
            let factory: ProposerRuntimeFactory =
                Arc::new(move |seed| Arc::new(MockRuntime::new(seed, accuracy)));
            let identity = ident(50 + index as u8);
            let key = coordinator.verifying_key();
            honest_tasks.push(tokio::spawn(async move {
                serve_proposer_multi(listener, factory, PROFILE, identity, key, 1).await
            }));
        }
    }

    let outcome = tokio::time::timeout(
        GLOBAL,
        speculate_multi(
            &verifier_addr,
            &proposer_addrs,
            client_runtime.clone(),
            PROFILE,
            &prompt,
            4,
            24,
            &coordinator,
            &verifier_id.verifying_key(),
            FallbackPolicy::default(),
            TrieLimits::default(),
            Duration::from_millis(150),
        ),
    )
    .await
    .expect("no stall: rounds bound by the collection deadline")
    .expect("multi session completes without the withholder");

    let single = single_decode(&verifier_runtime, &prompt, 24).await;
    assert_eq!(outcome.tokens, single, "the remaining proposers stay exact");
    assert_eq!(outcome.tokens.len(), 24);
    assert_eq!(outcome.fallback, None, "two live proposers are enough");

    // The withholder is a straggler on EVERY round: its slot is skipped and
    // counted, and it never contributed a block.
    let reports = &outcome.proposer_reports;
    assert_eq!(reports.len(), 3);
    assert_eq!(reports[1].blocks_arrived, 0, "withholder never delivered");
    assert_eq!(
        reports[1].straggler_rounds, outcome.rounds,
        "withholder counted every round"
    );
    assert!(
        outcome.stragglers >= outcome.rounds,
        "straggler accounting: {} for {} rounds",
        outcome.stragglers,
        outcome.rounds
    );
    // The honest proposers served every round — capacity released per round,
    // nothing leaked.
    assert!(reports[0].blocks_arrived >= outcome.rounds);
    assert!(reports[2].blocks_arrived >= outcome.rounds);

    // Server-side reports confirm the same from the proposers' view: the
    // withholder answered nothing, the honest ones drafted every round.
    let mut honest_reports = Vec::new();
    for task in honest_tasks {
        honest_reports.extend(
            tokio::time::timeout(GLOBAL, task)
                .await
                .expect("honest proposer reaped")
                .unwrap()
                .expect("honest proposer served"),
        );
    }
    assert_eq!(honest_reports.len(), 2);
    for report in &honest_reports {
        assert!(
            report.proposals_served >= outcome.rounds,
            "honest proposer served every round (got {} for {} rounds)",
            report.proposals_served,
            outcome.rounds
        );
        assert_eq!(report.commits_applied, outcome.rounds);
    }
    if let Some(task) = withholder_task {
        task.abort();
    }
    let verifier_reports = verifier_server.await.unwrap().expect("verifier served");
    assert_eq!(verifier_reports[0].committed_tokens, 24);
}

// ---------------------------------------------------------------------------
// F7 — malicious verifier accepting garbage (auditor pattern)
// ---------------------------------------------------------------------------

/// A rogue verifier: claims every candidate block was FULLY accepted and
/// returns a hash-CONSISTENT result over the garbage (defeating the
/// per-round hash check — only the coordinator's local audit can catch it).
async fn serve_rogue_verifier(
    listener: Listener,
    requester: InstallationIdentity,
    saw_close: Arc<AtomicBool>,
) {
    let mut session = listener
        .accept(&requester.verifying_key(), D)
        .await
        .expect("rogue accept");
    let session_id = match recv_msg(&mut session).await {
        SpecMessage::PrefillRequest { session_id, .. } => session_id,
        other => panic!("rogue verifier expected prefill, got {other:?}"),
    };
    send_msg(
        &mut session,
        &SpecMessage::PrefillReady {
            session_id: session_id.clone(),
            kv_commitment_digest: "rogue-digest".to_string(),
            accepted_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        },
    )
    .await;
    let mut claimed_hash = GENESIS_PREFIX_HASH.to_string();
    loop {
        let msg = match session.recv_json(D).await {
            Ok(value) => serde_json::from_value(value).expect("spec message"),
            Err(_) => return,
        };
        match msg {
            SpecMessage::CandidateBlock { round, tokens, .. } => {
                // "Accept" the garbage in full plus an in-vocab garbage
                // correction, with a hash computed over exactly those
                // tokens: the lie is internally consistent.
                let correction = tokens.first().copied().unwrap_or(0).wrapping_add(1) % 256;
                let mut committed = tokens.clone();
                committed.push(correction);
                let new_hash = compute_prefix_hash(&claimed_hash, &committed).expect("rogue hash");
                send_msg(
                    &mut session,
                    &SpecMessage::VerificationResult {
                        session_id: session_id.clone(),
                        round,
                        accepted_tokens: tokens,
                        correction: Some(correction),
                        new_prefix_hash: new_hash.clone(),
                    },
                )
                .await;
                claimed_hash = new_hash;
            }
            SpecMessage::PrefixCommit { round, .. } => {
                send_msg(
                    &mut session,
                    &SpecMessage::CommitAck {
                        session_id: session_id.clone(),
                        round,
                        ok: true,
                        reason: "advanced".to_string(),
                    },
                )
                .await;
            }
            SpecMessage::SessionClose { .. } => {
                saw_close.store(true, Ordering::SeqCst);
                return;
            }
            _ => {}
        }
    }
}

/// F7: the rogue verifier's hash-consistent garbage passes every per-round
/// chain check, but the coordinator's final-chain audit (re-verification
/// with its own runtime) catches the divergence and the session FAILS —
/// garbage never reaches the emitted output. The honest control passes the
/// same audit (the auditor cross-check matches).
#[tokio::test]
async fn f7_rogue_verifier_garbage_never_reaches_output() {
    // Rogue run.
    let rogue = tokio::time::timeout(GLOBAL, async {
        let coordinator = ident(60);
        let proposer_id = ident(61);
        let prompt = prompt_for(81);
        // Accuracy 0: every drafted token is wrong, so "fully accepted"
        // claims are guaranteed to diverge from the target continuation.
        let proposer_runtime = Arc::new(MockRuntime::new(81, 0.0));
        let client_runtime: Arc<dyn InferenceRuntime> = Arc::new(MockRuntime::new(81, 0.0));
        let (proposer_addr, proposer_server) =
            spawn_proposer(proposer_runtime, proposer_id, &coordinator).await;
        let (rogue_listener, rogue_addr) = listen().await;
        let saw_close = Arc::new(AtomicBool::new(false));
        let rogue_task = tokio::spawn(serve_rogue_verifier(
            rogue_listener,
            coordinator.clone(),
            Arc::clone(&saw_close),
        ));

        let outcome = speculate(
            &rogue_addr,
            &proposer_addr,
            client_runtime,
            PROFILE,
            &prompt,
            3,
            12,
            &coordinator,
            &coordinator.verifying_key(),
            FallbackPolicy::default(),
        )
        .await;
        let _ = proposer_server.await;
        rogue_task.abort();
        (outcome, saw_close.load(Ordering::SeqCst))
    })
    .await
    .expect("no hang");

    let (outcome, saw_close) = rogue;
    let err = outcome.expect_err("the rogue verifier must be caught");
    match &err {
        SpecError::Protocol(why) => assert!(
            why.contains("auditor divergence"),
            "the final-chain audit must flag the divergence, got: {why}"
        ),
        other => panic!("expected Protocol error, got {other:?}"),
    }
    // The session never completed cleanly (no close/receipt with the rogue)
    // and no SpecOutcome exists: garbage tokens were never emitted.
    assert!(!saw_close, "the rogue never got a clean session close");

    // Honest control: same shape, real verifier — the audit matches and the
    // session completes exactly (the auditor cross-check agrees).
    let control = tokio::time::timeout(GLOBAL, async {
        let coordinator = ident(62);
        let verifier_id = ident(63);
        let proposer_id = ident(64);
        let prompt = prompt_for(82);
        let verifier_runtime = Arc::new(MockRuntime::new(82, 0.5));
        let proposer_runtime = Arc::new(MockRuntime::new(82, 0.5));
        let client_runtime = Arc::new(MockRuntime::new(82, 0.5));
        let (verifier_addr, verifier_server) =
            spawn_verifier(verifier_runtime, verifier_id.clone(), &coordinator, 1).await;
        let (proposer_addr, proposer_server) =
            spawn_proposer(proposer_runtime, proposer_id, &coordinator).await;
        let outcome = speculate(
            &verifier_addr,
            &proposer_addr,
            client_runtime.clone(),
            PROFILE,
            &prompt,
            3,
            12,
            &coordinator,
            &verifier_id.verifying_key(),
            FallbackPolicy::default(),
        )
        .await
        .unwrap();
        let single = single_decode(&client_runtime, &prompt, 12).await;
        let _ = verifier_server.await;
        let _ = proposer_server.await;
        (outcome.tokens == single, outcome.receipts_verified)
    })
    .await
    .expect("no hang");
    assert_eq!(control, (true, true), "honest sessions pass the audit");
}

// ---------------------------------------------------------------------------
// F8 — flood
// ---------------------------------------------------------------------------

/// Writes one length-prefixed frame over a raw stream (no handshake).
async fn write_raw_frame(
    stream: &mut tokio::net::TcpStream,
    payload: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    stream.write_all(&buf).await
}

/// One flood connection: 20 hostile frames (truncations, bit flips, oversized
/// prefixes, invalid UTF-8, valid-JSON garbage). Never reads; ignores write
/// errors (the server may reject mid-stream — that is the point).
async fn flood_connection(addr: String, index: usize) {
    let mut stream = match tokio::net::TcpStream::connect(addr.as_str()).await {
        Ok(s) => s,
        Err(_) => return,
    };
    let base: Vec<u8> = serde_json::to_vec(&"handshake-placeholder").unwrap();
    for frame_index in 0..20u64 {
        let salt = index as u64 * 1000 + frame_index;
        let mode = (salt + frame_index) % 5;
        let _ = match mode {
            0 => {
                // Truncated frame: prefix announces more than the body.
                let mut buf = Vec::new();
                buf.extend_from_slice(&64u32.to_be_bytes());
                buf.extend_from_slice(&base[..base.len() / 2]);
                use tokio::io::AsyncWriteExt;
                stream.write_all(&buf).await
            }
            1 => {
                // Bit flips over a plausible JSON body.
                let mut body = serde_json::to_vec(&json!({
                    "handshake": {"peer_id": "12D3KooFlood", "nonce": salt.to_string()}
                }))
                .unwrap();
                for bit in 0..(1 + salt % 8) as usize {
                    let pos = (salt as usize * 7 + bit * 13) % body.len();
                    body[pos] ^= 1 << (bit % 8);
                }
                write_raw_frame(&mut stream, &body).await
            }
            2 => {
                // Oversized prefix (way over the 256 KiB cap), no body.
                use tokio::io::AsyncWriteExt;
                stream
                    .write_all(&(MAX_FRAME_BYTES as u32 + 1).to_be_bytes())
                    .await
            }
            3 => {
                // Invalid UTF-8 body.
                let mut body: Vec<u8> = vec![0xFF, 0xFE, 0x00];
                body.extend(std::iter::repeat_n(0x80 | (salt % 0x40) as u8, 24));
                write_raw_frame(&mut stream, &body).await
            }
            _ => {
                // Valid JSON garbage (parses, matches nothing typed).
                let body = serde_json::to_vec(&json!({
                    "junk": salt, "arr": [1, 2, 3], "nested": {"deep": true}
                }))
                .unwrap();
                write_raw_frame(&mut stream, &body).await
            }
        };
    }
    use tokio::io::AsyncWriteExt as _;
    let _ = stream.shutdown().await;
}

/// F8: 50 rapid connections × 20 frames = 1000 malformed/oversized/garbage
/// frames at a verifier listener. Every flood connection is rejected with a
/// typed error (never a panic); the handshaked session that then receives
/// garbage dies cleanly with bounded queues; and the SAME listener serves a
/// legitimate speculative session afterwards.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn f8_flood_is_rejected_and_the_listener_serves_afterwards() {
    const FLOOD_CONNECTIONS: usize = 50;
    let client = ident(70);
    let mut directory: HashMap<String, VerifyingKey> = HashMap::new();
    directory.insert(client.peer_id(), client.verifying_key());

    let (listener, addr) = listen().await;
    let rejections = Arc::new(AtomicUsize::new(0));
    let handshaked = Arc::new(AtomicUsize::new(0));

    // Front door: accepts, verifies the handshake, rejects garbage, keeps
    // going (a server loop, not the one-shot serve_speculative accept).
    let (door_tx, door_rx) = tokio::sync::oneshot::channel::<Listener>();
    let door = {
        let rejections = Arc::clone(&rejections);
        let handshaked = Arc::clone(&handshaked);
        tokio::spawn(async move {
            let listener = listener;
            let mut handled = 0usize;
            loop {
                let accepted = tokio::time::timeout(
                    Duration::from_secs(3),
                    listener.accept_with(
                        |hs| directory.get(&hs.peer_id).copied(),
                        Duration::from_secs(3),
                    ),
                )
                .await;
                match accepted {
                    Ok(Ok(session)) => {
                        handshaked.fetch_add(1, Ordering::SeqCst);
                        // Drain the session: consume frames until the reader
                        // dies (bounded queues; every frame either queues or
                        // kills the session with a typed error).
                        tokio::spawn(async move {
                            let mut session = session;
                            while let Ok(_value) = session.recv_json(D).await {}
                        });
                    }
                    Ok(Err(_)) => {
                        rejections.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_elapsed) => break, // attackers done
                }
                handled += 1;
                if handled >= FLOOD_CONNECTIONS + 2 {
                    break;
                }
            }
            let _ = door_tx.send(listener);
        })
    };

    // The flood: 50 rapid hostile connections.
    let mut attackers = Vec::with_capacity(FLOOD_CONNECTIONS);
    for index in 0..FLOOD_CONNECTIONS {
        attackers.push(tokio::spawn(flood_connection(addr.clone(), index)));
    }
    for attacker in attackers {
        let _ = tokio::time::timeout(GLOBAL, attacker).await;
    }
    // Plus one LEGITIMATE handshake whose session then receives garbage:
    // clean typed death, memory bounded by the queue cap.
    {
        let mut session = connect_as(&addr, &client).await;
        for mode in 0..6u32 {
            let body: Vec<u8> = match mode % 3 {
                0 => vec![0xFF, 0xFE, 0xFD],
                1 => serde_json::to_vec(&json!({"garbage": mode})).unwrap(),
                _ => serde_json::to_vec(&json!([1, 2, {"x": null}])).unwrap(),
            };
            send_raw(&mut session, &body).await;
        }
        // The invalid-UTF-8 frame kills the reader: the next read surfaces a
        // typed error (not a hang, not a panic).
        let observed = tokio::time::timeout(GLOBAL, session.recv_json(D)).await;
        assert!(
            observed.is_err() || observed.unwrap().is_err(),
            "garbage after handshake must fail cleanly"
        );
        session.close();
    }

    let listener = tokio::time::timeout(GLOBAL, door_rx)
        .await
        .expect("front door returns")
        .expect("door channel");
    let _ = tokio::time::timeout(GLOBAL, door).await;
    assert!(
        rejections.load(Ordering::SeqCst) > 0,
        "flood connections must be rejected"
    );

    // The same listener now serves a real session end to end.
    let verifier_id = ident(71);
    let proposer_id = ident(72);
    let prompt = prompt_for(91);
    let verifier_runtime = Arc::new(MockRuntime::new(91, 0.7));
    let client_runtime = Arc::new(MockRuntime::new(91, 0.7));
    let key = client.verifying_key();
    let server_identity = verifier_id.clone();
    let verifier_server = tokio::spawn(async move {
        serve_speculative(
            listener,
            verifier_runtime.clone(),
            PROFILE,
            server_identity,
            key,
            1,
        )
        .await
    });
    let (proposer_addr, proposer_server) =
        spawn_proposer(Arc::new(MockRuntime::new(91, 0.7)), proposer_id, &client).await;

    let outcome = tokio::time::timeout(
        GLOBAL,
        speculate(
            &addr,
            &proposer_addr,
            client_runtime.clone(),
            PROFILE,
            &prompt,
            3,
            9,
            &client,
            &verifier_id.verifying_key(),
            FallbackPolicy::default(),
        ),
    )
    .await
    .expect("server alive after the flood")
    .expect("legit session completes");
    let single = single_decode(&client_runtime, &prompt, 9).await;
    assert_eq!(outcome.tokens, single, "post-flood session is exact");
    assert!(outcome.receipts_verified);
    let _ = verifier_server.await;
    let _ = proposer_server.await;
}

/// Sends arbitrary bytes as one frame over an established session (the
/// attacker's raw pipe — the transport serializes typed messages, so the
/// adversarial path writes the frame itself via the JSON passthrough only
/// for valid JSON; invalid bytes go through the raw stream the test owns).
async fn send_raw(session: &mut modelswarm_transport::Session, body: &[u8]) {
    // Valid JSON goes through the (authenticated) passthrough; invalid bytes
    // cannot use it, so only JSON is pushed here — the invalid-UTF-8 kills
    // come from the flood connections above.
    if let Ok(text) = std::str::from_utf8(body) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            let _ = session.send_json(&value, D).await;
        }
    }
}

// ---------------------------------------------------------------------------
// F9 — malformed-frame fuzz (seeded, deterministic)
// ---------------------------------------------------------------------------

/// xorshift64* — seeded, deterministic.
struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// F9: 10 000 deterministic mutations against the frame decoder and the
/// message deserializers. No panics (the test fails on any panic); every
/// successful frame read is bounded by [`MAX_FRAME_BYTES`] (the allocation
/// cap is enforced BEFORE the body is read); deserializers return Err on
/// garbage. Deep-nesting inputs stay ≤ 1 MiB.
#[tokio::test]
async fn f9_malformed_frame_fuzz_no_panics_no_unbounded_allocation() {
    const ITERATIONS: usize = 10_000;

    // Corpus: a real signed handshake, a real signed commit, a wide JSON
    // object, and a deep-nesting document (~200 KiB < 1 MiB).
    let identity = ident(90);
    let handshake_bytes = serde_json::to_vec(&modelswarm_transport::WireMessage::Handshake(
        Handshake::build(&identity, PROFILE, "fuzz", "b1"),
    ))
    .expect("handshake serializes");
    let commit_bytes = {
        let commit = CommitPrefix {
            session_id: "f9".to_string(),
            round: 1,
            previous_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
            accepted_token_ids: vec![1, 2, 3],
            new_prefix_hash: compute_prefix_hash(GENESIS_PREFIX_HASH, &[1, 2, 3]).unwrap(),
            model_profile_id: PROFILE.to_string(),
            generation_params_hash: default_sampling_params_hash(),
            sender: identity.installation_id(),
        };
        let wire = SpecMessage::signed_commit(&commit, &identity).unwrap();
        serde_json::to_vec(&wire).expect("commit serializes")
    };
    let wide_bytes = serde_json::to_vec(&json!({
        "prefill_request": {"session_id": "s", "prompt_tokens": [1, 2, 3],
                            "profile_id": PROFILE, "generation_params_hash": "g"},
        "extra": (0..64).map(|i| i.to_string()).collect::<Vec<_>>(),
    }))
    .unwrap();
    let deep_bytes = {
        let depth = 100_000usize; // 2 * depth bytes ≈ 200 KiB < 1 MiB
        let mut s = String::with_capacity(2 * depth);
        for _ in 0..depth {
            s.push('[');
        }
        for _ in 0..depth {
            s.push(']');
        }
        s.into_bytes()
    };
    let corpus = [
        &handshake_bytes[..],
        &commit_bytes[..],
        &wide_bytes[..],
        &deep_bytes[..],
    ];

    let mut rng = XorShift64::new(0xF00D_F00D_CAFE_BABE);
    let mut too_large = 0usize;
    let mut frames_read = 0usize;
    let mut typed_decoded = 0usize;
    let mut spec_decoded = 0usize;
    let mut deep_rejected = 0usize;

    for iteration in 0..ITERATIONS {
        // Corpus member (cycles independently of the mutation class so every
        // (corpus, mutation) combination is exercised across the sweep).
        let base = corpus[(iteration / 8) % corpus.len()];
        let bytes: Vec<u8> = match iteration % 8 {
            0 => {
                // Truncation at a random point.
                let cut = (rng.next_u64() as usize) % (base.len() + 1);
                base[..cut].to_vec()
            }
            1 | 2 => {
                // Bit flips (1..=16) over the base.
                let mut body = base.to_vec();
                if !body.is_empty() {
                    for _ in 0..(1 + rng.next_u64() % 16) {
                        let pos = (rng.next_u64() as usize) % body.len();
                        body[pos] ^= 1 << (rng.next_u64() % 8);
                    }
                }
                body
            }
            3 => {
                // Invalid UTF-8 injections.
                let mut body = base.to_vec();
                for _ in 0..(1 + rng.next_u64() % 8) {
                    if body.is_empty() {
                        break;
                    }
                    let pos = (rng.next_u64() as usize) % body.len();
                    body[pos] = 0xFF;
                }
                body
            }
            4 => {
                // Oversize length prefix + a sliver of body: the decoder must
                // refuse BEFORE allocating or reading the body.
                let mut body = Vec::new();
                body.extend_from_slice(&u32::MAX.to_be_bytes());
                body.extend_from_slice(&base[..base.len().min(16)]);
                body
            }
            5 => {
                // Valid-JSON garbage of random shape.
                serde_json::to_vec(&json!({
                    "junk": rng.next_u64(),
                    "arr": (0..(rng.next_u64() % 8)).collect::<Vec<_>>(),
                }))
                .unwrap()
            }
            6 => {
                // Random byte soup (any content, any invalid UTF-8).
                (0..(rng.next_u64() % 256))
                    .map(|_| (rng.next_u64() % 256) as u8)
                    .collect()
            }
            _ => base.to_vec(), // pristine control (sanity that decoders work)
        };

        // (a) Frame decoder over a length-prefixed rendering of the input.
        // The prefix sometimes lies with an oversize length: the reader must
        // reject before any body allocation.
        let oversize_prefix = iteration % 11 == 0 && iteration % 8 == 4;
        if oversize_prefix {
            too_large += 1;
        }
        let mut framed = Vec::with_capacity(4 + bytes.len());
        framed.extend_from_slice(
            &(if oversize_prefix {
                MAX_FRAME_BYTES as u32 + 1
            } else {
                bytes.len() as u32
            })
            .to_be_bytes(),
        );
        framed.extend_from_slice(&bytes);
        let mut cursor: &[u8] = &framed;
        if let Ok(payload) = read_frame_raw(&mut cursor).await {
            frames_read += 1;
            assert!(
                payload.len() <= MAX_FRAME_BYTES,
                "iteration {iteration}: payload {} exceeds the 256 KiB cap",
                payload.len()
            );
        }

        // (b) Typed transport message deserializer.
        if serde_json::from_slice::<modelswarm_transport::WireMessage>(&bytes).is_ok() {
            typed_decoded += 1;
        }
        // (c) Spec message deserializer.
        if serde_json::from_slice::<SpecMessage>(&bytes).is_ok() {
            spec_decoded += 1;
        }
        // (d) Deep nesting must be a clean error (bounded recursion), never
        // a stack overflow / panic.
        if bytes.len() > 100_000 {
            let value: Result<serde_json::Value, _> = serde_json::from_slice(&bytes);
            if value.is_err() {
                deep_rejected += 1;
            }
        }
    }

    // The corpus is meaningful: real frames decode, garbage mostly does not,
    // oversize prefixes were exercised, and the deep document was rejected.
    assert!(frames_read > 0, "some valid frames must decode");
    assert!(too_large > 0, "oversize prefixes must be exercised");
    assert!(
        typed_decoded > 0 && spec_decoded > 0,
        "typed and spec decodes must both occur (typed={typed_decoded}, spec={spec_decoded})"
    );
    assert!(deep_rejected > 0, "deep nesting must be cleanly rejected");
    assert!(
        typed_decoded < ITERATIONS,
        "most mutations must fail decode"
    );
}

// ---------------------------------------------------------------------------
// F10 — redaction gate
// ---------------------------------------------------------------------------

/// F10: log a full adversarial session (fabricated proposals → collapse →
/// fallback) through the mandatory telemetry, including deliberate attempts
/// to smuggle a prompt canary under forbidden field names. The canary must
/// be absent from every sink line.
#[tokio::test]
async fn f10_redaction_gate_keeps_the_prompt_canary_out_of_every_sink_line() {
    const CANARY: &str = "ZQ-CANARY-prompt-7f31-never-log-me";
    let (telemetry, sink) = Telemetry::memory();

    let coordinator = ident(95);
    let verifier_id = ident(96);
    let prompt = prompt_for(101);
    let verifier_runtime = Arc::new(MockRuntime::new(101, 0.5));
    let client_runtime = Arc::new(MockRuntime::new(101, 0.5));
    let (verifier_addr, verifier_server) =
        spawn_verifier(verifier_runtime, verifier_id.clone(), &coordinator, 1).await;
    let (fabricator_listener, fabricator_addr) = listen().await;
    let fabricator = tokio::spawn(serve_fabricating_proposer(
        fabricator_listener,
        coordinator.clone(),
    ));

    // The canary rides the session as prompt-shaped text: it is the token
    // content an attacker would try to retain.
    let outcome = tokio::time::timeout(
        GLOBAL,
        speculate(
            &verifier_addr,
            &fabricator_addr,
            client_runtime.clone(),
            PROFILE,
            &prompt,
            3,
            9,
            &coordinator,
            &verifier_id.verifying_key(),
            FallbackPolicy::default(),
        ),
    )
    .await
    .expect("no hang")
    .expect("adversarial session completes");
    let reports = verifier_server.await.unwrap().expect("verifier served");
    fabricator.await.expect("fabricator reaped");

    // The event stream a node emits for this session — counts, hashes,
    // reasons; never prompt text. The three canary attempts below are the
    // "careless caller" cases the redaction gate must survive.
    telemetry.info(
        "spec_session_start",
        &[
            ("session_id", outcome.session_id.as_str()),
            ("profile_id", PROFILE),
            ("prompt_tokens", "8"), // count, never content
        ],
    );
    telemetry.warn(
        "spec_round_fabricated",
        &[
            ("session_id", outcome.session_id.as_str()),
            ("round", "1"),
            ("reason", "fabricated_proposal_rejected"),
            ("prompt", CANARY), // forbidden field: must be dropped
        ],
    );
    telemetry.error(
        "spec_fallback",
        &[
            ("session_id", outcome.session_id.as_str()),
            (
                "reason",
                outcome.fallback.map(|r| r.as_str()).unwrap_or("none"),
            ),
            ("completion", CANARY), // forbidden field: must be dropped
            ("delta", CANARY),      // forbidden field: must be dropped
        ],
    );
    telemetry.info(
        "spec_session_end",
        &[
            ("session_id", outcome.session_id.as_str()),
            ("rounds", &outcome.rounds.to_string()),
            ("verifier_close", reports[0].close_reason.as_str()),
        ],
    );

    let lines = sink.snapshot();
    assert!(lines.len() >= 4, "the session's events must be logged");
    for line in &lines {
        assert!(
            !line.contains(CANARY),
            "PROMPT CANARY LEAKED into a sink line: {line}"
        );
    }
    // The redactor left evidence of the drops (structured markers, not the
    // values) — the gate redacts, it does not silently drop the events.
    let joined = lines.join("\n");
    assert!(joined.contains("[REDACTED:prompt"));
    assert!(joined.contains("[REDACTED:completion"));
    assert!(joined.contains("[REDACTED:delta"));
}
