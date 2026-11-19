//! Phase E end-to-end multi-proposer tests over real loopback TCP
//! (ephemeral ports, `SignedFrameTransport`), exercising the E-gate items:
//!
//! - **(a) Happy path**: 4 seeded proposers + verifier; output token-exact
//!   vs plain single decoding; trie telemetry collected; every proposer
//!   server reports a clean session.
//! - **(b) Peer loss**: one proposer killed mid-session → the round completes
//!   from the remaining candidates (no stall, no fallback while proposers
//!   remain), output still exact.
//! - **(c) Straggler drop (E5)**: every proposer misses one round's
//!   collection deadline → the round still commits the lookahead bonus token
//!   (empty-trie trie property), later rounds recover, output exact.
//! - **(d) Replay (shared commit path)**: a replayed round commit is a
//!   remembered `duplicate` on the verifier and rejected (`parent_mismatch`)
//!   by a proposer whose chain already advanced; a conflicting same-round
//!   commit is `stale_round`.
//! - **(e) Determinism**: same seeds/identities/parameters → the same token
//!   stream (equal to plain single decoding both times).
//!
//! Every case is hang-free by construction (`tokio::time::timeout`).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use modelswarm_identity::InstallationIdentity;
use modelswarm_runtime::{
    Handle, InferenceRuntime, KvCommitment, MockRuntime, RuntimeDescriptor, RuntimeError,
    RuntimeMetrics, SamplingParams, TaskId,
};
use modelswarm_session::spec::{
    default_sampling_params_hash, serve_proposer_multi, serve_speculative, speculate_multi,
    FallbackPolicy, ProposerRuntimeFactory, SpecMessage, SpecMode, GENESIS_PREFIX_HASH,
};
use modelswarm_session::{compute_prefix_hash, CommitPrefix};
use modelswarm_speculation::TrieLimits;
use modelswarm_transport::{Handshake, Listener, SignedFrameTransport};

const PROFILE: &str = "msp:spec-multi:v1";
const D: Duration = Duration::from_secs(10);
/// Global per-case timeout: no test may hang.
const GLOBAL: Duration = Duration::from_secs(60);
/// Coordinator proposal-collection deadline used by the tests: short enough
/// that the injected straggler delay (600 ms) always misses it.
const COLLECT: Duration = Duration::from_millis(250);
/// Straggler injection delay (E5): comfortably above `COLLECT`.
const STRAGGLER_DELAY: Duration = Duration::from_millis(600);

fn ident(seed: u8) -> InstallationIdentity {
    InstallationIdentity::from_bytes(&[seed; 32])
}

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

type Server<T> = tokio::task::JoinHandle<Result<Vec<T>, modelswarm_session::spec::SpecError>>;

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

/// Which `propose` call (1-based, per proposer server) sleeps for the
/// straggler delay before drafting.
#[derive(Debug, Clone)]
struct DelaySpec {
    call: usize,
    delay: Duration,
}

/// TEST-ONLY wrapper delaying one `propose` call of the wrapped runtime —
/// the straggler injection point (the runtime API has no propose-delay
/// knob, and honesty forbids faking it inside the protocol layer).
struct DelayedRuntime {
    inner: Arc<dyn InferenceRuntime>,
    spec: DelaySpec,
    calls: Arc<Mutex<usize>>,
}

impl DelayedRuntime {
    fn wrap(inner: Arc<dyn InferenceRuntime>, spec: DelaySpec, calls: Arc<Mutex<usize>>) -> Self {
        Self { inner, spec, calls }
    }
}

#[async_trait]
impl InferenceRuntime for DelayedRuntime {
    fn id(&self) -> RuntimeDescriptor {
        self.inner.id()
    }
    async fn load(&self, profile_id: &str) -> Result<Handle, RuntimeError> {
        self.inner.load(profile_id).await
    }
    async fn tokenize(&self, text: &str) -> Result<Vec<u32>, RuntimeError> {
        self.inner.tokenize(text).await
    }
    async fn detokenize(&self, ids: &[u32]) -> Result<String, RuntimeError> {
        self.inner.detokenize(ids).await
    }
    async fn prefill(&self, handle: &Handle, ids: &[u32]) -> Result<KvCommitment, RuntimeError> {
        self.inner.prefill(handle, ids).await
    }
    async fn decode_step(
        &self,
        handle: &Handle,
        prefix: &[u32],
        sampling: &SamplingParams,
    ) -> Result<u32, RuntimeError> {
        self.inner.decode_step(handle, prefix, sampling).await
    }
    fn metrics(&self) -> RuntimeMetrics {
        self.inner.metrics()
    }
    fn cancel(&self, task: TaskId) -> Result<(), RuntimeError> {
        self.inner.cancel(task)
    }
    async fn propose(
        &self,
        handle: &Handle,
        prefix: &[u32],
        window: u32,
    ) -> Result<Vec<u32>, RuntimeError> {
        let call = {
            let mut calls = self.calls.lock().expect("delay counter");
            *calls += 1;
            *calls
        };
        if call == self.spec.call {
            tokio::time::sleep(self.spec.delay).await;
        }
        self.inner.propose(handle, prefix, window).await
    }
}

/// Spawns a Phase E proposer server whose drafts come from
/// `MockRuntime::new(branch_seed, accuracy)` — the documented branch
/// distinctness mechanism — optionally delaying one propose call.
async fn spawn_multi_proposer(
    accuracy: f32,
    identity: InstallationIdentity,
    requester: &InstallationIdentity,
    delay: Option<DelaySpec>,
) -> (String, Server<modelswarm_session::spec::ProposerReport>) {
    let (listener, addr) = listen().await;
    let key = requester.verifying_key();
    let calls = Arc::new(Mutex::new(0usize));
    let factory: ProposerRuntimeFactory = Arc::new(move |seed| {
        let inner: Arc<dyn InferenceRuntime> = Arc::new(MockRuntime::new(seed, accuracy));
        match delay.clone() {
            Some(spec) => Arc::new(DelayedRuntime::wrap(inner, spec, Arc::clone(&calls))),
            None => inner,
        }
    });
    let task = tokio::spawn(async move {
        serve_proposer_multi(listener, factory, PROFILE, identity, key, 1).await
    });
    (addr, task)
}

/// Plain single decoding of `n` tokens (the equality oracle).
async fn single_decode(runtime: &Arc<MockRuntime>, prompt: &[u32], n: u32) -> Vec<u32> {
    let handle = runtime.load(PROFILE).await.expect("load");
    runtime
        .decode_stream(&handle, prompt, &SamplingParams::default(), n, D)
        .await
        .expect("single decode")
}

async fn run_multi(
    verifier_addr: &str,
    proposer_addrs: &[String],
    client_runtime: Arc<MockRuntime>,
    coordinator: &InstallationIdentity,
    verifier_key: &modelswarm_transport::ed25519_dalek::VerifyingKey,
    prompt: &[u32],
    max_tokens: u32,
) -> modelswarm_session::spec::SpecOutcome {
    speculate_multi(
        verifier_addr,
        proposer_addrs,
        client_runtime,
        PROFILE,
        prompt,
        4,
        max_tokens,
        coordinator,
        verifier_key,
        FallbackPolicy::default(),
        TrieLimits::default(),
        COLLECT,
    )
    .await
    .expect("speculate_multi succeeds")
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
// (a) 4-proposer happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e_happy_path_four_proposers_exact_vs_single() {
    let coordinator = ident(1);
    let verifier_id = ident(2);
    let prompt = prompt_for(42);

    let verifier_runtime = Arc::new(MockRuntime::new(21, 0.8));
    let client_runtime = Arc::new(MockRuntime::new(21, 0.8));
    let (verifier_addr, verifier_server) =
        spawn_verifier(verifier_runtime, verifier_id.clone(), &coordinator, 1).await;
    let mut proposer_addrs = Vec::new();
    let mut proposer_servers = Vec::new();
    for i in 0..4u8 {
        let (addr, server) = spawn_multi_proposer(0.8, ident(10 + i), &coordinator, None).await;
        proposer_addrs.push(addr);
        proposer_servers.push(server);
    }

    let outcome = tokio::time::timeout(
        GLOBAL,
        run_multi(
            &verifier_addr,
            &proposer_addrs,
            client_runtime.clone(),
            &coordinator,
            &verifier_id.verifying_key(),
            &prompt,
            24,
        ),
    )
    .await
    .expect("no hang");

    // Greedy equality against plain single decoding, token for token.
    let single = single_decode(&client_runtime, &prompt, 24).await;
    assert_eq!(outcome.tokens, single, "greedy contract (multi)");
    assert_eq!(outcome.tokens.len(), 24);
    assert_eq!(outcome.mode, SpecMode::MultiProposer);
    assert_eq!(outcome.fallback, None);
    assert!(outcome.receipts_verified);
    assert!(outcome.rounds >= 1);
    assert_eq!(
        outcome.round_batches.iter().map(Vec::len).sum::<usize>(),
        24,
        "batches: {:?}",
        outcome.round_batches
    );
    // Phase E telemetry: full attendance, nothing pruned under default
    // bounds (4 branches ≤ 8; ≤ 4 × 16 nodes ≤ 128).
    assert_eq!(outcome.stragglers, 0);
    assert_eq!(outcome.pruned, 0);
    assert_eq!(outcome.proposer_reports.len(), 4);
    for report in &outcome.proposer_reports {
        assert!(report.alive);
        assert_eq!(report.blocks_arrived, outcome.rounds);
        assert_eq!(report.straggler_rounds, 0);
        assert!(report.drafted_tokens > 0);
    }
    // Distinctness materialized: at accuracy 0.8 the seeded proposers
    // disagree somewhere over the session (duplicate work is real but not
    // total).
    assert!(
        outcome.duplicate_work
            < outcome
                .proposer_reports
                .iter()
                .map(|report| report.drafted_tokens)
                .sum::<u64>(),
        "branches must diverge across proposers at accuracy 0.8"
    );

    let verifier_reports = verifier_server.await.unwrap().expect("verifier served");
    assert_eq!(verifier_reports.len(), 1);
    assert_eq!(verifier_reports[0].close_reason, "closed");
    assert_eq!(verifier_reports[0].receipt_ack_valid, Some(true));
    assert_eq!(verifier_reports[0].rounds, outcome.rounds);
    assert_eq!(verifier_reports[0].committed_tokens, 24);

    for (i, server) in proposer_servers.into_iter().enumerate() {
        let reports = server.await.unwrap().expect("proposer served");
        assert_eq!(reports.len(), 1, "proposer {i}");
        assert_eq!(reports[0].close_reason, "closed");
        assert_eq!(reports[0].proposals_served, outcome.rounds);
        assert_eq!(reports[0].commits_applied, outcome.rounds);
    }
}

// ---------------------------------------------------------------------------
// (b) one proposer killed mid-session
// ---------------------------------------------------------------------------

/// A raw-JSON fake multi proposer serving `survive_rounds` rounds, then
/// closing the session mid-round (the injected peer loss).
async fn fake_multi_proposer_that_dies(
    listener: Listener,
    requester: InstallationIdentity,
    die_on_round: u64,
) {
    let mut session = listener
        .accept(&requester.verifying_key(), D)
        .await
        .expect("fake proposer accept");
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
    let mut last_hash = GENESIS_PREFIX_HASH.to_string();
    let mut next_round = 1u64;
    loop {
        match recv_msg(&mut session).await {
            SpecMessage::ProposalRequest { round, window, .. } => {
                assert_eq!(round, next_round);
                next_round += 1;
                if round >= die_on_round {
                    // Abrupt mid-round death.
                    session.close();
                    return;
                }
                // Garbage branch (the verifier content-checks it; only the
                // correction tokens ever commit from it).
                send_msg(
                    &mut session,
                    &SpecMessage::CandidateBlock {
                        session_id: session_id.clone(),
                        round,
                        parent_prefix_hash: last_hash.clone(),
                        tokens: vec![200; window as usize],
                        proposer_id: "fake-multi".to_string(),
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
            other => panic!("fake proposer got an unexpected message: {other:?}"),
        }
    }
}

#[tokio::test]
async fn e_one_proposer_killed_mid_session_round_completes() {
    let coordinator = ident(20);
    let verifier_id = ident(21);
    let prompt = prompt_for(77);

    let verifier_runtime = Arc::new(MockRuntime::new(22, 0.8));
    let client_runtime = Arc::new(MockRuntime::new(22, 0.8));
    let (verifier_addr, verifier_server) =
        spawn_verifier(verifier_runtime, verifier_id.clone(), &coordinator, 1).await;

    let mut proposer_addrs = Vec::new();
    let mut proposer_servers = Vec::new();
    for i in 0..3u8 {
        let (addr, server) = spawn_multi_proposer(0.8, ident(30 + i), &coordinator, None).await;
        proposer_addrs.push(addr);
        proposer_servers.push(server);
    }
    // The doomed proposer: dies on round 3.
    let (fake_listener, fake_addr) = listen().await;
    let fake = tokio::spawn(fake_multi_proposer_that_dies(
        fake_listener,
        coordinator.clone(),
        3,
    ));
    let fake_index = proposer_addrs.len();
    proposer_addrs.push(fake_addr);

    let outcome = tokio::time::timeout(
        GLOBAL,
        run_multi(
            &verifier_addr,
            &proposer_addrs,
            client_runtime.clone(),
            &coordinator,
            &verifier_id.verifying_key(),
            &prompt,
            24,
        ),
    )
    .await
    .expect("no stall: the round completes from the remaining proposers");

    // Output is still exact and the session never fell back (three proposers
    // remain — peer loss is absorbed by the roster, not by single mode).
    let single = single_decode(&client_runtime, &prompt, 24).await;
    assert_eq!(outcome.tokens, single, "survivor output is exact");
    assert_eq!(outcome.tokens.len(), 24);
    assert_eq!(
        outcome.fallback, None,
        "remaining proposers keep spec alive"
    );
    assert!(outcome.receipts_verified);
    // The dead proposer is accounted: excluded, marked dead, straggled.
    assert_eq!(outcome.proposer_reports.len(), 4);
    let dead = &outcome.proposer_reports[fake_index];
    assert!(!dead.alive, "the killed proposer must be marked dead");
    assert!(dead.straggler_rounds >= 1);
    assert!(outcome.stragglers >= 1);
    for (i, report) in outcome.proposer_reports.iter().enumerate() {
        if i != fake_index {
            assert!(report.alive, "survivor {i} must stay in the roster");
        }
    }
    fake.await.expect("fake proposer reaped");

    let verifier_reports = verifier_server.await.unwrap().expect("verifier served");
    assert_eq!(verifier_reports[0].close_reason, "closed");
    assert_eq!(verifier_reports[0].committed_tokens, 24);
    for server in proposer_servers {
        let reports = server.await.unwrap().expect("proposer served");
        assert_eq!(reports[0].close_reason, "closed");
    }
}

// ---------------------------------------------------------------------------
// (c) all proposers straggling one round → bonus-token progress
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e_all_proposers_straggling_one_round_still_progresses() {
    let coordinator = ident(40);
    let verifier_id = ident(41);
    let prompt = prompt_for(101);

    let verifier_runtime = Arc::new(MockRuntime::new(23, 0.9));
    let client_runtime = Arc::new(MockRuntime::new(23, 0.9));
    let (verifier_addr, verifier_server) =
        spawn_verifier(verifier_runtime, verifier_id.clone(), &coordinator, 1).await;
    let mut proposer_addrs = Vec::new();
    let mut proposer_servers = Vec::new();
    for i in 0..4u8 {
        // Every proposer delays its SECOND propose call (round 2) past the
        // collection deadline — the whole roster straggles that one round.
        let (addr, server) = spawn_multi_proposer(
            0.9,
            ident(50 + i),
            &coordinator,
            Some(DelaySpec {
                call: 2,
                delay: STRAGGLER_DELAY,
            }),
        )
        .await;
        proposer_addrs.push(addr);
        proposer_servers.push(server);
    }

    let outcome = tokio::time::timeout(
        GLOBAL,
        run_multi(
            &verifier_addr,
            &proposer_addrs,
            client_runtime.clone(),
            &coordinator,
            &verifier_id.verifying_key(),
            &prompt,
            24,
        ),
    )
    .await
    .expect("no stall: straggler rounds still commit");

    let single = single_decode(&client_runtime, &prompt, 24).await;
    assert_eq!(outcome.tokens, single, "straggler path is exact");
    assert_eq!(outcome.tokens.len(), 24);
    // The straggled round(s) committed exactly the lookahead bonus token
    // (empty trie ⇒ one committed token) — the E5 no-stall guarantee.
    assert!(
        outcome.round_batches.iter().any(|batch| batch.len() == 1),
        "expected at least one bonus-only round, batches: {:?}",
        outcome.round_batches
    );
    assert!(outcome.stragglers >= 4, "all proposers straggled");
    // The proposers are not punished: still alive, still serving later
    // rounds (their late blocks are drained as stale messages).
    for report in &outcome.proposer_reports {
        assert!(report.alive, "a deadline miss is not peer loss");
        assert!(report.straggler_rounds >= 1);
        assert!(report.blocks_arrived >= 1);
    }
    assert!(outcome.receipts_verified);

    let verifier_reports = verifier_server.await.unwrap().expect("verifier served");
    assert_eq!(verifier_reports[0].close_reason, "closed");
    assert_eq!(verifier_reports[0].committed_tokens, 24);
    for server in proposer_servers {
        let reports = server.await.unwrap().expect("proposer served");
        assert_eq!(reports[0].close_reason, "closed");
    }
}

// ---------------------------------------------------------------------------
// (d) replayed commit across proposers: duplicate (verifier) / rejected
//     (proposer), conflicting replay stale
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e_replayed_commit_is_duplicate_or_rejected_across_peers() {
    let coordinator = ident(60);
    let verifier_id = ident(61);
    let runtime = Arc::new(MockRuntime::new(24, 0.5));
    let (verifier_addr, verifier_server) =
        spawn_verifier(runtime.clone(), verifier_id, &coordinator, 1).await;
    let (proposer_addr, proposer_server) =
        spawn_multi_proposer(0.5, ident(70), &coordinator, None).await;

    // Drive one tree round on the verifier manually.
    let mut vsession = connect_as(&verifier_addr, &coordinator).await;
    let resumed = prefill(&mut vsession, "replay-multi", &[3, 1, 4]).await;
    assert_eq!(resumed, GENESIS_PREFIX_HASH);

    let branches = vec![vec![9, 9, 9], vec![7, 7, 7]];
    send_msg(
        &mut vsession,
        &SpecMessage::TreeVerifyRequest {
            session_id: "replay-multi".to_string(),
            round: 1,
            branches,
        },
    )
    .await;
    let (accepted, correction, new_hash) = match recv_msg(&mut vsession).await {
        SpecMessage::TreeVerifyResult {
            accepted_tokens,
            correction,
            new_prefix_hash,
            ..
        } => (accepted_tokens, correction, new_prefix_hash),
        other => panic!("expected tree_verify_result, got {other:?}"),
    };
    let mut committed = accepted.clone();
    committed.extend(correction);
    assert!(!committed.is_empty(), "a tree round always commits");

    let commit = CommitPrefix {
        session_id: "replay-multi".to_string(),
        round: 1,
        previous_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        accepted_token_ids: committed.clone(),
        new_prefix_hash: compute_prefix_hash(GENESIS_PREFIX_HASH, &committed).unwrap(),
        model_profile_id: PROFILE.to_string(),
        generation_params_hash: default_sampling_params_hash(),
        sender: coordinator.installation_id(),
    };
    assert_eq!(commit.new_prefix_hash, new_hash);
    let wire = SpecMessage::signed_commit(&commit, &coordinator).unwrap();

    send_msg(&mut vsession, &wire).await;
    match recv_msg(&mut vsession).await {
        SpecMessage::CommitAck { ok, reason, .. } => {
            assert!(ok && reason == "advanced", "{ok}/{reason}");
        }
        other => panic!("expected commit_ack, got {other:?}"),
    }
    // Exact replay on the verifier: remembered duplicate, no advance.
    send_msg(&mut vsession, &wire).await;
    match recv_msg(&mut vsession).await {
        SpecMessage::CommitAck { ok, reason, .. } => {
            assert!(ok, "duplicate is a benign no-op");
            assert_eq!(reason, "duplicate");
        }
        other => panic!("expected commit_ack, got {other:?}"),
    }
    // Conflicting same-round commit: stale, rejected.
    let conflicting = CommitPrefix {
        session_id: "replay-multi".to_string(),
        round: 1,
        previous_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        accepted_token_ids: vec![1],
        new_prefix_hash: compute_prefix_hash(GENESIS_PREFIX_HASH, &[1]).unwrap(),
        model_profile_id: PROFILE.to_string(),
        generation_params_hash: default_sampling_params_hash(),
        sender: coordinator.installation_id(),
    };
    send_msg(
        &mut vsession,
        &SpecMessage::signed_commit(&conflicting, &coordinator).unwrap(),
    )
    .await;
    match recv_msg(&mut vsession).await {
        SpecMessage::CommitAck { ok, reason, .. } => {
            assert!(!ok, "conflicting replay must be rejected");
            assert_eq!(reason, "stale_round");
        }
        other => panic!("expected commit_ack, got {other:?}"),
    }
    send_msg(
        &mut vsession,
        &SpecMessage::SessionClose {
            session_id: "replay-multi".to_string(),
            reason: "done".to_string(),
        },
    )
    .await;
    let receipt = recv_msg(&mut vsession).await;
    let ack = SpecMessage::ReceiptAck {
        requester_signature: modelswarm_session::spec::sign_receipt_ack(&receipt, &coordinator)
            .unwrap(),
    };
    send_msg(&mut vsession, &ack).await;
    vsession.close();
    let verifier_reports = verifier_server.await.unwrap().expect("verifier served");
    assert_eq!(verifier_reports[0].rounds, 1, "replays never advance");

    // The same commit forwarded to a proposer: first delivery advances its
    // chain, the replay is rejected (parent mismatch — its chain already
    // moved past the replayed parent).
    let mut psession = connect_as(&proposer_addr, &coordinator).await;
    prefill(&mut psession, "replay-multi", &[3, 1, 4]).await;
    send_msg(&mut psession, &wire).await;
    match recv_msg(&mut psession).await {
        SpecMessage::CommitAck { ok, reason, .. } => {
            assert!(ok && reason == "advanced", "{ok}/{reason}");
        }
        other => panic!("expected commit_ack, got {other:?}"),
    }
    send_msg(&mut psession, &wire).await;
    match recv_msg(&mut psession).await {
        SpecMessage::CommitAck { ok, reason, .. } => {
            assert!(!ok, "a replayed commit must be rejected by the proposer");
            assert_eq!(reason, "parent_mismatch");
        }
        other => panic!("expected commit_ack, got {other:?}"),
    }
    send_msg(
        &mut psession,
        &SpecMessage::SessionClose {
            session_id: "replay-multi".to_string(),
            reason: "done".to_string(),
        },
    )
    .await;
    psession.close();
    let proposer_reports = proposer_server.await.unwrap().expect("proposer served");
    assert_eq!(proposer_reports[0].commits_applied, 1);
    assert_eq!(proposer_reports[0].close_reason, "closed");
}

// ---------------------------------------------------------------------------
// (e) determinism: same seeds → same token stream
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e_same_seeds_same_token_stream() {
    let prompt = prompt_for(2024);
    let mut runs = Vec::new();
    for run in 0..2 {
        let coordinator = ident(80);
        let verifier_id = ident(81);
        // Identical runtime seeds/accuracy/parameters across runs; only the
        // minted session id differs (as in production).
        let verifier_runtime = Arc::new(MockRuntime::new(25, 0.6));
        let client_runtime = Arc::new(MockRuntime::new(25, 0.6));
        let (verifier_addr, verifier_server) =
            spawn_verifier(verifier_runtime, verifier_id.clone(), &coordinator, 1).await;
        let mut proposer_addrs = Vec::new();
        let mut proposer_servers = Vec::new();
        for i in 0..4u8 {
            let (addr, server) = spawn_multi_proposer(0.6, ident(90 + i), &coordinator, None).await;
            proposer_addrs.push(addr);
            proposer_servers.push(server);
        }
        let outcome = tokio::time::timeout(
            GLOBAL,
            run_multi(
                &verifier_addr,
                &proposer_addrs,
                client_runtime.clone(),
                &coordinator,
                &verifier_id.verifying_key(),
                &prompt,
                20,
            ),
        )
        .await
        .expect("no hang");
        let single = single_decode(&client_runtime, &prompt, 20).await;
        assert_eq!(outcome.tokens, single, "run {run}: greedy contract");
        runs.push(outcome.tokens);
        verifier_server.await.unwrap().expect("verifier served");
        for server in proposer_servers {
            server.await.unwrap().expect("proposer served");
        }
    }
    assert_eq!(runs[0], runs[1], "same seeds must yield the same stream");
}
