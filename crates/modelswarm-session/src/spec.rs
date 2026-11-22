//! Exact speculative decoding over the wire (Phase D, `speculative_exact`).
//!
//! Three roles on top of the Phase B commit gate ([`crate::SessionStateMachine`])
//! and the ADR-018 staged transport:
//!
//! - **Verifier** ([`serve_speculative`]): the server owning the target model.
//!   Receives candidate blocks, decodes the target continuation with
//!   [`SamplingParams::default()`] (the greedy E2E contract — the draft
//!   accuracy is the only error source), applies
//!   [`modelswarm_speculation::verify_greedy`], and advances its own
//!   [`SessionStateMachine`] only on signed, chain-valid
//!   [`SpecMessage::PrefixCommit`]s. Tracks [`AcceptanceStats`].
//! - **Proposer** ([`serve_proposer`]): the server with the (cheap) draft
//!   model. On each [`SpecMessage::ProposalRequest`] it prefills the accepted
//!   prefix and calls [`InferenceRuntime::propose`]; it too applies the
//!   coordinator's commits — the coordinator forwards every commit to BOTH
//!   peers so the proposer's next `parent_prefix_hash` and its prefix-token
//!   reconstruction stay current.
//! - **Coordinator** ([`speculate`]): the client driving rounds — request a
//!   proposal, forward it, receive the verification result, build and sign the
//!   [`SpecMessage::PrefixCommit`] (wrapping the exact [`crate::CommitPrefix`]
//!   rules), apply it locally, emit the committed tokens. The window is
//!   adaptive (grow ×1.5 after 2 fully accepted rounds, cap 16; halve after a
//!   rejection streak of 2, floor 1) and a bounded [`FallbackPolicy`]
//!   switches to plain single decoding against the verifier's runtime on
//!   acceptance collapse (ADR-013 mandatory fallback) or when a round costs
//!   more than the policy multiplier times the coordinator's single-decode
//!   estimate; peer loss falls back explicitly, never corrupts.
//!
//! Wire encoding: [`SpecMessage`] is snake_case externally-tagged JSON sent via
//! [`Session::send_json`](modelswarm_transport::Session::send_json) /
//! [`recv_json`](modelswarm_transport::Session::recv_json) — the ADR-018
//! amended staging: the cooperative namespace rides the handshake-authenticated
//! session, and state-changing messages ([`SpecMessage::PrefixCommit`],
//! [`SpecMessage::Receipt`], [`SpecMessage::ReceiptAck`]) are additionally
//! signed at this layer over canonical JSON (msp-v1 §2.2 via
//! [`modelswarm_identity::canonical_json`]) and verified before application.
//!
//! Close is two-phase (D7): the verifier signs a [`SpecMessage::Receipt`] over
//! its committed rounds/tokens; the requester answers with a
//! [`SpecMessage::ReceiptAck`] signed over the receipt's binding digest; a
//! mismatched ack ends the session with reason `receipt_mismatch`.
//!
//! Sampled mode: the verifier path here is greedy (the E2E contract with the
//! TEST-ONLY mock backend). The lossless sampled rules
//! ([`modelswarm_speculation::verify_sampled_full_q`]) are pure functions
//! exercised unit-level with synthetic distributions; wiring them needs a
//! runtime that exposes full distributions (Phase-D entry ADR per ADR-019).
//!
//! # Phase E — multi-proposer candidate trees
//!
//! [`speculate_multi`] extends the coordinator to 2..=7 proposers. Each round
//! the coordinator sends every proposer a [`SpecMessage::ProposalRequest`]
//! carrying that proposer's [`branch_assignment`] seed (E1: deterministic and
//! distinct per `(session_id, round, roster, index)`), collects
//! [`SpecMessage::CandidateBlock`]s under an anchored per-round deadline
//! (E5: stragglers are dropped and counted, never block the round), assembles
//! a bounded [`CandidateTrie`] (E2/E3: pruning and duplicate-work counting),
//! and sends one [`SpecMessage::TreeVerifyRequest`] to the verifier, which
//! replies [`SpecMessage::TreeVerifyResult`] computed with
//! [`modelswarm_speculation::verify_tree_greedy`]. The commit path is the
//! SAME signed [`SpecMessage::PrefixCommit`] as Phase D, so replay/duplicate
//! protection, receipts, and the single-decode fallback are inherited
//! unchanged. Losing branches need no explicit cancellation: proposals are
//! drafted statelessly per round, so not committing a branch releases all of
//! its capacity immediately (E6 — no leaked slots).
//!
//! Branch distinctness (honest mechanism): [`serve_proposer_multi`] takes a
//! runtime *factory*. On each request it builds the per-round draft runtime
//! via `factory(branch_seed)` — for the TEST-ONLY `MockRuntime` that is
//! `MockRuntime::new(branch_seed, accuracy)`, whose `propose` folds the
//! runtime seed into the per-position correct/wrong draw
//! (`prefix_hash ^ seed`). Distinct branch seeds therefore draft distinct
//! wrong-token patterns deterministically, while every position still draws
//! the target's true continuation with the configured draft accuracy (the
//! accuracy semantics of Phase D are preserved; at accuracy 1.0 proposers
//! genuinely agree and the trie counts them as `duplicate_work`).
//!
//! Batch-vs-sequential equivalence (E4): the mock backend has no tree
//! attention, so the verifier's decode of `max_depth + 1` steps IS the
//! sequential-equivalent path. A runtime declaring `tree_attention` /
//! `batch_verify` capabilities (msp manifests, `modelswarm_types`) verifies
//! the same trie in one batched pass; both paths must select the identical
//! accepted prefix — proven unit-level in `tests` below by checking
//! [`modelswarm_speculation::verify_tree_greedy`] against per-branch
//! [`modelswarm_speculation::verify_greedy`] loops taking the max.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use futures_util::stream;
use modelswarm_gateway::{
    ExecutorError, ExecutorEvent, ExecutorStream, FinishReason, InferenceExecutor,
    NormalizedRequest,
};
use modelswarm_identity::{canonical_json, installation_id_for, new_nonce, InstallationIdentity};
use modelswarm_runtime::{Handle, InferenceRuntime, RuntimeError, SamplingParams};
use modelswarm_speculation::{
    branch_assignment, verify_greedy, verify_tree_greedy, AcceptanceStats, BranchBlock,
    CandidateTrie, TrieLimits,
};
use modelswarm_transport::ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use modelswarm_transport::{Handshake, Listener, Session, SignedFrameTransport, TransportError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{compute_prefix_hash, ApplyOutcome, CommitPrefix, SessionStateMachine};

/// The genesis prefix hash: `hex(sha256(""))` — the committed prefix of every
/// fresh session before any output token exists. The prompt lives in the KV
/// commitment, not in the hash chain (the chain covers committed *output*).
pub const GENESIS_PREFIX_HASH: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Adaptive window growth: fully accepted rounds required before `×1.5`.
pub const WINDOW_GROW_STREAK: u32 = 2;
/// Adaptive window shrink: consecutive rejected rounds before `÷2`.
pub const WINDOW_SHRINK_STREAK: u32 = 2;
/// Consecutive rounds over the RTT budget before the `rtt_spike` fallback
/// fires (a single slow round is scheduler noise, not a sustained overrun).
pub const RTT_SPIKE_STREAK: u32 = 2;
/// Adaptive window ceiling.
pub const WINDOW_MAX: u32 = 16;

/// Deadline for one coordinator round (proposal + verification + commit).
pub const ROUND_DEADLINE: Duration = Duration::from_secs(10);
/// Deadline for a server to accept a connection and finish the handshake.
pub const ACCEPT_DEADLINE: Duration = Duration::from_secs(10);
/// Server-side idle deadline between messages on an open session.
pub const SERVER_IDLE: Duration = Duration::from_secs(60);
/// Default per-round proposal-collection deadline of [`speculate_multi`]
/// (E5): a proposer whose candidate block misses this deadline is excluded
/// from that round's assembly and counted as a straggler.
pub const DEFAULT_PROPOSAL_DEADLINE: Duration = Duration::from_millis(750);
/// Minimum proposer count of [`speculate_multi`].
pub const MULTI_PROPOSERS_MIN: usize = 2;
/// Maximum proposer count of [`speculate_multi`].
pub const MULTI_PROPOSERS_MAX: usize = 7;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised by the speculative protocol layer.
#[derive(Debug)]
pub enum SpecError {
    /// Transport failure (disconnect, deadline, handshake).
    Transport(TransportError),
    /// Runtime failure (load/prefill/decode/propose).
    Runtime(RuntimeError),
    /// Protocol violation (unexpected message, bad chaining, bad hash).
    Protocol(String),
}

impl std::fmt::Display for SpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpecError::Transport(e) => write!(f, "spec transport failure: {e}"),
            SpecError::Runtime(e) => write!(f, "spec runtime failure: {e}"),
            SpecError::Protocol(why) => write!(f, "spec protocol violation: {why}"),
        }
    }
}

impl std::error::Error for SpecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SpecError::Transport(e) => Some(e),
            SpecError::Runtime(e) => Some(e),
            SpecError::Protocol(_) => None,
        }
    }
}

impl From<TransportError> for SpecError {
    fn from(e: TransportError) -> Self {
        SpecError::Transport(e)
    }
}

impl From<RuntimeError> for SpecError {
    fn from(e: RuntimeError) -> Self {
        SpecError::Runtime(e)
    }
}

impl From<crate::SessionError> for SpecError {
    fn from(e: crate::SessionError) -> Self {
        SpecError::Protocol(format!("session error: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Wire messages
// ---------------------------------------------------------------------------

/// One message of the speculative namespace (snake_case externally-tagged JSON
/// over [`Session::send_json`](modelswarm_transport::Session::send_json)).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecMessage {
    /// Coordinator → peer: prefill this prompt; pins the session's profile and
    /// generation-parameters hash.
    PrefillRequest {
        session_id: String,
        profile_id: String,
        prompt_tokens: Vec<u32>,
        generation_params_hash: String,
    },
    /// Peer → coordinator: prefill done. `accepted_prefix_hash` is the peer's
    /// current committed prefix hash — [`GENESIS_PREFIX_HASH`] for a fresh
    /// session, the last commit hash after a reconnect (resume point).
    PrefillReady {
        session_id: String,
        kv_commitment_digest: String,
        accepted_prefix_hash: String,
    },
    /// Coordinator → proposer: draft a window continuing the committed prefix.
    /// `branch_seed` (Phase E multi-proposer mode) is the proposer's
    /// deterministic branch assignment — see
    /// [`branch_assignment`](modelswarm_speculation::branch_assignment). The
    /// two-peer path leaves it `None`.
    ProposalRequest {
        session_id: String,
        round: u64,
        window: u32,
        deadline_ms: u32,
        branch_seed: Option<u64>,
    },
    /// Proposer → coordinator (forwarded verbatim to the verifier): drafted
    /// tokens. Content-verified by the verifier against the target model — a
    /// lying proposer cannot bend the output.
    CandidateBlock {
        session_id: String,
        round: u64,
        parent_prefix_hash: String,
        tokens: Vec<u32>,
        proposer_id: String,
    },
    /// Coordinator → verifier (Phase E): the assembled candidate set for one
    /// round — the coordinator's post-assembly branch list (already
    /// deduplicated and bounded by its [`TrieLimits`], E2/E3). Stragglers
    /// simply never appear in the set (E5); an empty set asks the verifier
    /// for the one lookahead token (bonus progress).
    TreeVerifyRequest {
        session_id: String,
        round: u64,
        branches: Vec<Vec<u32>>,
    },
    /// Verifier → coordinator (Phase E): greedy tree-verification outcome over
    /// a [`TreeVerifyRequest`], same commitment shape as
    /// [`SpecMessage::VerificationResult`]: `accepted_tokens` is the winning
    /// branch's matched prefix, `correction` the target-authoritative token
    /// appended after it (correction on mismatch, bonus token when the whole
    /// branch held), `new_prefix_hash` the hash of the would-be commit.
    TreeVerifyResult {
        session_id: String,
        round: u64,
        accepted_tokens: Vec<u32>,
        correction: Option<u32>,
        new_prefix_hash: String,
    },
    /// Verifier → coordinator: greedy verification outcome. `committed =
    /// accepted_tokens ++ [correction]` always holds: `correction` carries the
    /// target-authoritative token appended after the accepted draft prefix —
    /// the correction on rejection, the bonus (lookahead) token when the whole
    /// window held.
    VerificationResult {
        session_id: String,
        round: u64,
        accepted_tokens: Vec<u32>,
        correction: Option<u32>,
        new_prefix_hash: String,
    },
    /// Coordinator → both peers: the signed commit (D4). Wraps exactly the
    /// [`CommitPrefix`] field and chain rules; `signature` is base64 Ed25519
    /// over the canonical JSON of the other eight fields, verified before the
    /// state machine is touched.
    PrefixCommit {
        session_id: String,
        round: u64,
        previous_prefix_hash: String,
        accepted_token_ids: Vec<u32>,
        new_prefix_hash: String,
        profile_id: String,
        generation_params_hash: String,
        sender: String,
        signature: String,
    },
    /// Peer → coordinator: commit application outcome. `ok` with reason
    /// `advanced`/`duplicate` (duplicate = remembered no-op), or `ok:false`
    /// with the reject reason (`bad_signature` or a
    /// [`crate::RejectReason`] name).
    CommitAck {
        session_id: String,
        round: u64,
        ok: bool,
        reason: String,
    },
    /// Verifier → coordinator at close: server-signed accounting (D7).
    Receipt {
        session_id: String,
        rounds: u64,
        committed_tokens: u64,
        server_signature: String,
    },
    /// Coordinator → verifier: requester signature over the receipt binding
    /// digest (two-phase close). A mismatched ack ends the session with reason
    /// `receipt_mismatch`.
    ReceiptAck { requester_signature: String },
    /// Either side: abandon this round (parent mismatch, proposal failure).
    /// No commit follows; state is untouched.
    CancelRound {
        session_id: String,
        round: u64,
        reason: String,
    },
    /// Coordinator → peer: session over. On the verifier this triggers the
    /// receipt exchange.
    SessionClose { session_id: String, reason: String },
    /// Coordinator → verifier (fallback mode, D6): decode `n` tokens directly
    /// with default sampling continuing the committed `prefix` — the exact
    /// single-mode path, so fallback output is exact by construction.
    SingleDecode {
        session_id: String,
        prefix: Vec<u32>,
        n: u32,
    },
    /// Verifier → coordinator: the single-mode tokens.
    SingleDecodeResult {
        session_id: String,
        tokens: Vec<u32>,
    },
}

impl SpecMessage {
    /// The session the message belongs to (`ReceiptAck` carries none — it
    /// answers the message it follows).
    pub fn session_id(&self) -> Option<&str> {
        match self {
            SpecMessage::PrefillRequest { session_id, .. }
            | SpecMessage::PrefillReady { session_id, .. }
            | SpecMessage::ProposalRequest { session_id, .. }
            | SpecMessage::CandidateBlock { session_id, .. }
            | SpecMessage::TreeVerifyRequest { session_id, .. }
            | SpecMessage::TreeVerifyResult { session_id, .. }
            | SpecMessage::VerificationResult { session_id, .. }
            | SpecMessage::PrefixCommit { session_id, .. }
            | SpecMessage::CommitAck { session_id, .. }
            | SpecMessage::Receipt { session_id, .. }
            | SpecMessage::CancelRound { session_id, .. }
            | SpecMessage::SessionClose { session_id, .. }
            | SpecMessage::SingleDecode { session_id, .. }
            | SpecMessage::SingleDecodeResult { session_id, .. } => Some(session_id),
            SpecMessage::ReceiptAck { .. } => None,
        }
    }
}

/// The generation-parameters hash pinned by every greedy E2E session: a digest
/// over the exact [`SamplingParams::default()`] the verifiers decode with (the
/// runtime contract: proposals continue the default-sampling continuation, so
/// default decoding is the only honest verification basis).
pub fn default_sampling_params_hash() -> String {
    let params = SamplingParams::default();
    let described = format!(
        "temperature={};top_p={};top_k={};seed={}",
        params.temperature,
        params.top_p,
        params.top_k,
        params.seed.unwrap_or(0)
    );
    hex::encode(Sha256::digest(described.as_bytes()))
}

// ---------------------------------------------------------------------------
// Commit wrapping + signatures (session layer, ADR-018 amended staging)
// ---------------------------------------------------------------------------

impl SpecMessage {
    /// Builds a signed [`SpecMessage::PrefixCommit`] wrapping `commit`.
    pub fn signed_commit(
        commit: &CommitPrefix,
        signer: &InstallationIdentity,
    ) -> Result<SpecMessage, SpecError> {
        let signature = sign_commit(commit, signer)?;
        Ok(SpecMessage::PrefixCommit {
            session_id: commit.session_id.clone(),
            round: commit.round,
            previous_prefix_hash: commit.previous_prefix_hash.clone(),
            accepted_token_ids: commit.accepted_token_ids.clone(),
            new_prefix_hash: commit.new_prefix_hash.clone(),
            profile_id: commit.model_profile_id.clone(),
            generation_params_hash: commit.generation_params_hash.clone(),
            sender: commit.sender.clone(),
            signature,
        })
    }

    /// Unwraps a [`SpecMessage::PrefixCommit`] into the state-machine
    /// [`CommitPrefix`] (signature dropped — check it first via
    /// [`verify_commit_signature`]).
    pub fn commit_prefix(&self) -> Option<CommitPrefix> {
        let SpecMessage::PrefixCommit {
            session_id,
            round,
            previous_prefix_hash,
            accepted_token_ids,
            new_prefix_hash,
            profile_id,
            generation_params_hash,
            sender,
            ..
        } = self
        else {
            return None;
        };
        Some(CommitPrefix {
            session_id: session_id.clone(),
            round: *round,
            previous_prefix_hash: previous_prefix_hash.clone(),
            accepted_token_ids: accepted_token_ids.clone(),
            new_prefix_hash: new_prefix_hash.clone(),
            model_profile_id: profile_id.clone(),
            generation_params_hash: generation_params_hash.clone(),
            sender: sender.clone(),
        })
    }
}

/// Canonical JSON of a commit's eight signed fields.
fn commit_signing_payload(commit: &CommitPrefix) -> Option<String> {
    canonical_json(&json!({
        "session_id": commit.session_id,
        "round": commit.round,
        "previous_prefix_hash": commit.previous_prefix_hash,
        "accepted_token_ids": commit.accepted_token_ids,
        "new_prefix_hash": commit.new_prefix_hash,
        "model_profile_id": commit.model_profile_id,
        "generation_params_hash": commit.generation_params_hash,
        "sender": commit.sender,
    }))
}

/// Signs a commit with `signer`'s Ed25519 key (base64, detached, over the
/// canonical JSON of the wrapped [`CommitPrefix`] fields).
pub fn sign_commit(
    commit: &CommitPrefix,
    signer: &InstallationIdentity,
) -> Result<String, SpecError> {
    let payload = commit_signing_payload(commit)
        .ok_or_else(|| SpecError::Protocol("commit payload rejected by canonical JSON".into()))?;
    let key = SigningKey::from_bytes(&signer.to_bytes());
    Ok(BASE64.encode(key.sign(payload.as_bytes()).to_bytes()))
}

/// Verifies a wire [`SpecMessage::PrefixCommit`]: the signature must verify
/// under `expected_signer` AND the `sender` label must derive from that key
/// (msp-v1 §6.6 binding discipline). Callers must run this BEFORE applying.
pub fn verify_commit_signature(
    commit: &SpecMessage,
    expected_signer: &VerifyingKey,
) -> Result<(), SpecError> {
    let Some(wrapped) = commit.commit_prefix() else {
        return Err(SpecError::Protocol("not a prefix_commit".into()));
    };
    let SpecMessage::PrefixCommit {
        sender, signature, ..
    } = commit
    else {
        return Err(SpecError::Protocol("not a prefix_commit".into()));
    };
    if installation_id_for(&expected_signer.to_bytes()) != *sender {
        return Err(SpecError::Protocol(
            "commit sender is not the authenticated session key".into(),
        ));
    }
    let payload = commit_signing_payload(&wrapped)
        .ok_or_else(|| SpecError::Protocol("commit payload rejected by canonical JSON".into()))?;
    let bytes = BASE64
        .decode(signature)
        .map_err(|_| SpecError::Protocol("commit signature is not valid base64".into()))?;
    let sig = Signature::from_slice(&bytes)
        .map_err(|_| SpecError::Protocol("commit signature is not 64 bytes".into()))?;
    expected_signer
        .verify(payload.as_bytes(), &sig)
        .map_err(|_| SpecError::Protocol("bad_signature".into()))
}

/// Canonical JSON of the three receipt content fields (everything but the
/// server signature).
fn receipt_content(session_id: &str, rounds: u64, committed_tokens: u64) -> Value {
    json!({
        "session_id": session_id,
        "rounds": rounds,
        "committed_tokens": committed_tokens,
    })
}

/// The digest a [`SpecMessage::ReceiptAck`] must sign: `hex(sha256(canonical
/// JSON of the full receipt including the server signature))` — binds the
/// requester's ack to one exact server-signed receipt.
pub fn receipt_binding_digest(receipt: &SpecMessage) -> Result<String, SpecError> {
    let SpecMessage::Receipt {
        session_id,
        rounds,
        committed_tokens,
        server_signature,
    } = receipt
    else {
        return Err(SpecError::Protocol("not a receipt".into()));
    };
    let mut full = receipt_content(session_id, *rounds, *committed_tokens);
    if let Value::Object(map) = &mut full {
        map.insert(
            "server_signature".to_string(),
            Value::String(server_signature.clone()),
        );
    }
    let canonical = canonical_json(&full)
        .ok_or_else(|| SpecError::Protocol("receipt rejected by canonical JSON".into()))?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

/// Builds the server-signed receipt for the session's accounting (D7).
pub fn sign_receipt(
    session_id: &str,
    rounds: u64,
    committed_tokens: u64,
    signer: &InstallationIdentity,
) -> Result<SpecMessage, SpecError> {
    let content = receipt_content(session_id, rounds, committed_tokens);
    let payload = canonical_json(&content)
        .ok_or_else(|| SpecError::Protocol("receipt rejected by canonical JSON".into()))?;
    let key = SigningKey::from_bytes(&signer.to_bytes());
    Ok(SpecMessage::Receipt {
        session_id: session_id.to_string(),
        rounds,
        committed_tokens,
        server_signature: BASE64.encode(key.sign(payload.as_bytes()).to_bytes()),
    })
}

/// Verifies the receipt's server signature against the verifier's key.
pub fn verify_receipt_signature(
    receipt: &SpecMessage,
    server_key: &VerifyingKey,
) -> Result<(), SpecError> {
    let SpecMessage::Receipt {
        session_id,
        rounds,
        committed_tokens,
        server_signature,
    } = receipt
    else {
        return Err(SpecError::Protocol("not a receipt".into()));
    };
    let content = receipt_content(session_id, *rounds, *committed_tokens);
    let payload = canonical_json(&content)
        .ok_or_else(|| SpecError::Protocol("receipt rejected by canonical JSON".into()))?;
    let bytes = BASE64
        .decode(server_signature)
        .map_err(|_| SpecError::Protocol("receipt signature is not valid base64".into()))?;
    let sig = Signature::from_slice(&bytes)
        .map_err(|_| SpecError::Protocol("receipt signature is not 64 bytes".into()))?;
    server_key
        .verify(payload.as_bytes(), &sig)
        .map_err(|_| SpecError::Protocol("receipt signature failed verification".into()))
}

/// Signs the receipt binding digest with the requester's key (the
/// [`SpecMessage::ReceiptAck`] payload).
pub fn sign_receipt_ack(
    receipt: &SpecMessage,
    requester: &InstallationIdentity,
) -> Result<String, SpecError> {
    let digest = receipt_binding_digest(receipt)?;
    let key = SigningKey::from_bytes(&requester.to_bytes());
    Ok(BASE64.encode(key.sign(digest.as_bytes()).to_bytes()))
}

/// Verifies a receipt ack: the signature must verify under `requester_key`
/// over the binding digest of `receipt`.
pub fn verify_receipt_ack(
    receipt: &SpecMessage,
    requester_signature: &str,
    requester_key: &VerifyingKey,
) -> Result<(), SpecError> {
    let digest = receipt_binding_digest(receipt)?;
    let bytes = BASE64
        .decode(requester_signature)
        .map_err(|_| SpecError::Protocol("receipt ack is not valid base64".into()))?;
    let sig = Signature::from_slice(&bytes)
        .map_err(|_| SpecError::Protocol("receipt ack is not 64 bytes".into()))?;
    requester_key
        .verify(digest.as_bytes(), &sig)
        .map_err(|_| SpecError::Protocol("receipt_mismatch".into()))
}

// ---------------------------------------------------------------------------
// Fallback policy + outcomes
// ---------------------------------------------------------------------------

/// Bounded controller deciding when `speculative_exact` must fall back to
/// plain single decoding (ADR-013: mandatory when measured acceptance or
/// synchronization crosses the predicted budget).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FallbackPolicy {
    /// Minimum accepted-draft fraction over the trailing window.
    pub min_acceptance_rate: f32,
    /// Trailing rounds the acceptance rate is computed over (the check arms
    /// only once this many rounds exist — no early flap).
    pub rate_window_rounds: usize,
    /// A round must cost less than this multiple of the coordinator's
    /// single-decode estimate for the tokens it committed. The check arms
    /// after [`FallbackPolicy::rate_window_rounds`] warm-up rounds and fires
    /// only when the overrun is sustained ([`RTT_SPIKE_STREAK`] consecutive
    /// rounds) — a single scheduler hiccup is noise, not a budget crossing.
    pub rtt_multiplier: f64,
}

impl Default for FallbackPolicy {
    fn default() -> Self {
        Self {
            min_acceptance_rate: 0.15,
            rate_window_rounds: 10,
            rtt_multiplier: 2.0,
        }
    }
}

/// Why a session left speculative mode for single decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackReason {
    /// Trailing acceptance rate fell below [`FallbackPolicy::min_acceptance_rate`].
    AcceptanceCollapse,
    /// A round cost more than [`FallbackPolicy::rtt_multiplier`] × the
    /// coordinator's single-decode estimate (RTT spike).
    RttSpike,
    /// A peer connection died mid-round (D4: explicit, never corruption).
    PeerLost,
}

impl FallbackReason {
    /// Stable wire/record label.
    pub fn as_str(&self) -> &'static str {
        match self {
            FallbackReason::AcceptanceCollapse => "acceptance_collapse",
            FallbackReason::RttSpike => "rtt_spike",
            FallbackReason::PeerLost => "peer_lost",
        }
    }
}

impl std::fmt::Display for FallbackReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which coordinator shape produced a [`SpecOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecMode {
    /// Phase D: one verifier + one proposer ([`speculate`]).
    TwoPeer,
    /// Phase E: one verifier + 2..=7 seeded proposers ([`speculate_multi`]).
    MultiProposer,
}

impl SpecMode {
    /// Stable wire/record label.
    pub fn as_str(self) -> &'static str {
        match self {
            SpecMode::TwoPeer => "two_peer",
            SpecMode::MultiProposer => "multi_proposer",
        }
    }
}

impl std::fmt::Display for SpecMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Coordinator-side accounting for one proposer of a multi-proposer session
/// (Phase E). The server-side counterpart lives in [`ProposerReport`].
#[derive(Debug, Clone)]
pub struct ProposerPeerReport {
    /// Roster index (position in the coordinator's proposer address list).
    pub index: usize,
    /// The proposer's dial address.
    pub addr: String,
    /// Candidate blocks that arrived in time and entered assembly.
    pub blocks_arrived: u64,
    /// Rounds this proposer missed the collection deadline or failed
    /// (E5 straggler accounting).
    pub straggler_rounds: u64,
    /// Drafted tokens across arrived blocks.
    pub drafted_tokens: u64,
    /// Tokens of this proposer's branches that were accepted (winning-branch
    /// attribution; the add-one-smoothed ratio feeds the assembly score).
    pub accepted_tokens: u64,
    /// Whether the connection was still alive at close.
    pub alive: bool,
}

impl ProposerPeerReport {
    /// The coordinator's assembly score for this proposer: add-one-smoothed
    /// trailing acceptance rate `(accepted + 1) / (drafted + 2)` — defined
    /// from the first round, bounded in `(0, 1)`, deterministic.
    pub fn score(&self) -> f32 {
        (self.accepted_tokens as f32 + 1.0) / (self.drafted_tokens as f32 + 2.0)
    }
}

/// The coordinator's result.
#[derive(Debug, Clone)]
pub struct SpecOutcome {
    /// The session id (nonce minted by the coordinator).
    pub session_id: String,
    /// Committed output tokens (exactly `max_tokens`; token-identical to plain
    /// default-sampling decode in greedy mode).
    pub tokens: Vec<u32>,
    /// Committed tokens per round (the final entry is the single-mode tail
    /// when the session fell back).
    pub round_batches: Vec<Vec<u32>>,
    /// Rounds committed (including a single-mode tail round).
    pub rounds: u64,
    /// Speculative-phase acceptance telemetry (vLLM convention).
    pub acceptance: AcceptanceStats,
    /// Why the session ended in single mode, if it did.
    pub fallback: Option<FallbackReason>,
    /// The verifier's receipt verified (signature + two-phase ack exchanged).
    pub receipts_verified: bool,
    /// Which coordinator shape ran (Phase D two-peer vs Phase E multi).
    pub mode: SpecMode,
    /// Phase E: draft tokens dropped as exact duplicates across proposers
    /// before verification (E3). Zero in two-peer mode.
    pub duplicate_work: u64,
    /// Phase E: branches/nodes removed by the trie bounds (E2). Zero in
    /// two-peer mode.
    pub pruned: u64,
    /// Phase E: (round, proposer) deadline misses — blocks that never made
    /// assembly (E5). Zero in two-peer mode.
    pub stragglers: u64,
    /// Phase E: per-proposer coordinator-side accounting, roster order.
    /// Empty in two-peer mode.
    pub proposer_reports: Vec<ProposerPeerReport>,
}

// ---------------------------------------------------------------------------
// Framing helpers
// ---------------------------------------------------------------------------

async fn send_spec(
    session: &mut Session,
    msg: &SpecMessage,
    deadline: Duration,
) -> Result<(), SpecError> {
    let value = serde_json::to_value(msg)
        .map_err(|e| SpecError::Protocol(format!("spec encode failed: {e}")))?;
    session.send_json(&value, deadline).await?;
    Ok(())
}

async fn recv_spec(session: &mut Session, deadline: Duration) -> Result<SpecMessage, SpecError> {
    let value = session.recv_json(deadline).await?;
    serde_json::from_value(value)
        .map_err(|e| SpecError::Protocol(format!("malformed spec message: {e}")))
}

/// Rounds a commit ack into `(ok, reason)` with duplicate treated as success.
fn ack_result(reason: &str) -> (bool, String) {
    let ok = reason == "advanced" || reason == "duplicate";
    (ok, reason.to_string())
}

// ---------------------------------------------------------------------------
// Verifier (server)
// ---------------------------------------------------------------------------

/// Per-session verifier report (one per accepted connection).
#[derive(Debug, Clone)]
pub struct VerifierReport {
    /// The session this report covers.
    pub session_id: String,
    /// Acceptance telemetry over the verification rounds of this session.
    pub stats: AcceptanceStats,
    /// Committed round count of the state machine at close.
    pub rounds: u64,
    /// Committed output tokens at close (prefix minus prompt).
    pub committed_tokens: u64,
    /// Receipt two-phase outcome: `Some(true)` verified ack, `Some(false)`
    /// mismatch (session ended `receipt_mismatch`), `None` no ack arrived
    /// (session ended `closed_without_receipt_ack`).
    pub receipt_ack_valid: Option<bool>,
    /// Why the session ended.
    pub close_reason: String,
}

/// One verified-but-uncommitted round awaiting its [`SpecMessage::PrefixCommit`].
struct PendingRound {
    accepted_draft: usize,
    rejected: bool,
}

/// A verifier conversation, kept across reconnects (D4: resume from the last
/// committed prefix).
struct VerifierConversation {
    state: SessionStateMachine,
    prompt: Vec<u32>,
    /// prompt ++ committed output — the authoritative verification prefix.
    prefix: Vec<u32>,
    stats: AcceptanceStats,
    pending: Option<PendingRound>,
    handle: Handle,
}

impl VerifierConversation {
    fn committed_output_len(&self) -> u64 {
        (self.prefix.len() - self.prompt.len()) as u64
    }
}

/// Serves the VERIFIER role: accepts up to `max_sessions` connections on
/// `listener` (handshake verified against `expected_requester`), runs the
/// speculative verification flow on each, and returns one report per session.
///
/// State (commit chain, accumulated prefix, stats) is keyed by session id and
/// survives reconnects: a re-`PrefillRequest` for a known session resumes from
/// the last committed prefix rather than genesis.
pub async fn serve_speculative(
    listener: Listener,
    runtime: Arc<dyn InferenceRuntime>,
    profile_id: &str,
    identity: InstallationIdentity,
    expected_requester: VerifyingKey,
    max_sessions: usize,
) -> Result<Vec<VerifierReport>, SpecError> {
    let mut conversations: HashMap<String, VerifierConversation> = HashMap::new();
    let mut reports = Vec::new();
    for _ in 0..max_sessions {
        let mut session = match listener.accept(&expected_requester, ACCEPT_DEADLINE).await {
            Ok(session) => session,
            Err(e) => {
                if reports.is_empty() {
                    return Err(SpecError::Transport(e));
                }
                break;
            }
        };
        let report = serve_verifier_session(
            &mut session,
            &mut conversations,
            &runtime,
            profile_id,
            &identity,
            &expected_requester,
        )
        .await;
        session.close();
        reports.push(report);
    }
    Ok(reports)
}

async fn serve_verifier_session(
    session: &mut Session,
    conversations: &mut HashMap<String, VerifierConversation>,
    runtime: &Arc<dyn InferenceRuntime>,
    profile_id: &str,
    identity: &InstallationIdentity,
    expected_requester: &VerifyingKey,
) -> VerifierReport {
    match verifier_session_flow(
        session,
        conversations,
        runtime,
        profile_id,
        identity,
        expected_requester,
    )
    .await
    {
        Ok(report) => report,
        Err(e) => VerifierReport {
            session_id: String::new(),
            stats: AcceptanceStats::default(),
            rounds: 0,
            committed_tokens: 0,
            receipt_ack_valid: None,
            close_reason: format!("{e}"),
        },
    }
}

#[allow(clippy::too_many_lines)]
async fn verifier_session_flow(
    session: &mut Session,
    conversations: &mut HashMap<String, VerifierConversation>,
    runtime: &Arc<dyn InferenceRuntime>,
    profile_id: &str,
    identity: &InstallationIdentity,
    expected_requester: &VerifyingKey,
) -> Result<VerifierReport, SpecError> {
    // Prefill phase ---------------------------------------------------------
    let SpecMessage::PrefillRequest {
        session_id,
        profile_id: requested_profile,
        prompt_tokens,
        generation_params_hash,
    } = recv_spec(session, SERVER_IDLE).await?
    else {
        return Err(SpecError::Protocol("expected prefill_request first".into()));
    };
    if requested_profile != profile_id {
        return Err(SpecError::Protocol(format!(
            "cross-profile prefill: session wants {requested_profile:?}, server serves {profile_id:?}"
        )));
    }
    let handle = runtime.load(profile_id).await?;
    let commitment = runtime.prefill(&handle, &prompt_tokens).await?;
    let conversation =
        conversations
            .entry(session_id.clone())
            .or_insert_with(|| VerifierConversation {
                state: SessionStateMachine::new(
                    &session_id,
                    profile_id,
                    &generation_params_hash,
                    GENESIS_PREFIX_HASH,
                )
                .expect("genesis is valid hex sha256"),
                prompt: prompt_tokens.clone(),
                prefix: prompt_tokens.clone(),
                stats: AcceptanceStats::default(),
                pending: None,
                handle: handle.clone(),
            });
    conversation.handle = handle;
    send_spec(
        session,
        &SpecMessage::PrefillReady {
            session_id: session_id.clone(),
            kv_commitment_digest: commitment.digest,
            accepted_prefix_hash: conversation.state.committed_prefix_hash().to_string(),
        },
        ROUND_DEADLINE,
    )
    .await?;

    // Round loop ------------------------------------------------------------
    loop {
        let msg = recv_spec(session, SERVER_IDLE).await?;
        let message_session = msg.session_id().unwrap_or_default().to_string();
        let Some(conversation) = conversations.get_mut(&message_session) else {
            return Err(SpecError::Protocol(format!(
                "message for unknown session {message_session:?}"
            )));
        };
        match msg {
            SpecMessage::CandidateBlock {
                round,
                parent_prefix_hash,
                tokens,
                ..
            } => {
                if round != conversation.state.round() + 1
                    || parent_prefix_hash != conversation.state.committed_prefix_hash()
                {
                    send_spec(
                        session,
                        &SpecMessage::CancelRound {
                            session_id: message_session,
                            round,
                            reason: "parent_mismatch".to_string(),
                        },
                        ROUND_DEADLINE,
                    )
                    .await?;
                    continue;
                }
                // Target continuation: window+1 greedy decodes with DEFAULT
                // sampling (the E2E contract — draft accuracy is the only
                // error source).
                let window = tokens.len();
                let mut work = conversation.prefix.clone();
                let mut target = Vec::with_capacity(window + 1);
                for _ in 0..=window {
                    let token = runtime
                        .decode_step(&conversation.handle, &work, &SamplingParams::default())
                        .await?;
                    target.push(token);
                    work.push(token);
                }
                let outcome = verify_greedy(&tokens, &target);
                let new_hash = compute_prefix_hash(
                    conversation.state.committed_prefix_hash(),
                    &outcome.committed,
                )?;
                conversation.pending = Some(PendingRound {
                    accepted_draft: outcome.accepted_draft,
                    rejected: outcome.first_rejection.is_some(),
                });
                send_spec(
                    session,
                    &SpecMessage::VerificationResult {
                        session_id: message_session,
                        round,
                        accepted_tokens: tokens[..outcome.accepted_draft].to_vec(),
                        correction: outcome.committed.last().copied(),
                        new_prefix_hash: new_hash,
                    },
                    ROUND_DEADLINE,
                )
                .await?;
            }
            SpecMessage::TreeVerifyRequest {
                round, branches, ..
            } => {
                // Phase E: tree verification of one round's assembled branch
                // set (feature-detected on message type — linear
                // CandidateBlock rounds keep working alongside). The wire set
                // is the coordinator's post-assembly trie, so re-assembly
                // with no-op bounds reproduces it exactly (dedup is
                // first-wins on both sides, no bound can fire); the commit
                // hash chain then pins verifier and coordinator to the same
                // branch list.
                if round != conversation.state.round() + 1 {
                    send_spec(
                        session,
                        &SpecMessage::CancelRound {
                            session_id: message_session,
                            round,
                            reason: "round_mismatch".to_string(),
                        },
                        ROUND_DEADLINE,
                    )
                    .await?;
                    continue;
                }
                // Target continuation: deepest branch + 1 greedy decode with
                // DEFAULT sampling (the E2E contract). A runtime declaring
                // tree_attention/batch_verify executes this as one batched
                // pass; the selected prefix is identical either way (E4,
                // unit-tested at the speculation layer).
                let branch_count = branches.len();
                let blocks: Vec<BranchBlock> = branches
                    .into_iter()
                    .enumerate()
                    .map(|(i, tokens)| BranchBlock {
                        proposer: i,
                        tokens,
                        score: 0.0,
                    })
                    .collect();
                let max_nodes: usize = blocks.iter().map(|b| b.tokens.len()).sum();
                let trie = CandidateTrie::assemble(
                    blocks,
                    TrieLimits {
                        max_branches: branch_count.max(1),
                        max_nodes: max_nodes.max(1),
                    },
                );
                let max_depth = trie
                    .branches()
                    .iter()
                    .map(|b| b.tokens.len())
                    .max()
                    .unwrap_or(0);
                let mut work = conversation.prefix.clone();
                let mut target = Vec::with_capacity(max_depth + 1);
                for _ in 0..=max_depth {
                    let token = runtime
                        .decode_step(&conversation.handle, &work, &SamplingParams::default())
                        .await?;
                    target.push(token);
                    work.push(token);
                }
                let outcome = verify_tree_greedy(&trie, &target);
                let accepted_tokens = match outcome.winning_branch {
                    Some(index) => trie.branches()[index].tokens[..outcome.accepted_depth].to_vec(),
                    None => Vec::new(),
                };
                let committed = outcome.committed.clone();
                let new_hash =
                    compute_prefix_hash(conversation.state.committed_prefix_hash(), &committed)?;
                let winning_len = outcome
                    .winning_branch
                    .map(|index| trie.branches()[index].tokens.len());
                conversation.pending = Some(PendingRound {
                    accepted_draft: outcome.accepted_depth,
                    rejected: winning_len.is_some_and(|len| outcome.accepted_depth < len),
                });
                send_spec(
                    session,
                    &SpecMessage::TreeVerifyResult {
                        session_id: message_session,
                        round,
                        accepted_tokens,
                        correction: committed.last().copied(),
                        new_prefix_hash: new_hash,
                    },
                    ROUND_DEADLINE,
                )
                .await?;
            }
            SpecMessage::PrefixCommit { .. } => {
                // Signature BEFORE state, always.
                let reason = match verify_commit_signature(&msg, expected_requester) {
                    Err(e) => format!("{e}"),
                    Ok(()) => {
                        let commit = msg.commit_prefix().expect("matched prefix_commit above");
                        match conversation.state.apply(&commit) {
                            ApplyOutcome::Advanced => {
                                conversation
                                    .prefix
                                    .extend_from_slice(&commit.accepted_token_ids);
                                if let Some(pending) = conversation.pending.take() {
                                    conversation.stats.record_round(
                                        pending.accepted_draft,
                                        commit.accepted_token_ids.len(),
                                    );
                                    if pending.rejected {
                                        conversation.stats.record_rollback();
                                    }
                                }
                                "advanced".to_string()
                            }
                            ApplyOutcome::Duplicate => "duplicate".to_string(),
                            ApplyOutcome::Rejected(reason) => {
                                conversation.pending = None;
                                reason.to_string()
                            }
                        }
                    }
                };
                let round = msg.commit_prefix().map(|c| c.round).unwrap_or_default();
                let (ok, reason) = ack_result(&reason);
                send_spec(
                    session,
                    &SpecMessage::CommitAck {
                        session_id: message_session,
                        round,
                        ok,
                        reason,
                    },
                    ROUND_DEADLINE,
                )
                .await?;
            }
            SpecMessage::SingleDecode { prefix, n, .. } => {
                if prefix != conversation.prefix {
                    return Err(SpecError::Protocol(
                        "single_decode prefix does not match the committed prefix".into(),
                    ));
                }
                let mut work = conversation.prefix.clone();
                let mut produced = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let token = runtime
                        .decode_step(&conversation.handle, &work, &SamplingParams::default())
                        .await?;
                    work.push(token);
                    produced.push(token);
                }
                send_spec(
                    session,
                    &SpecMessage::SingleDecodeResult {
                        session_id: message_session,
                        tokens: produced,
                    },
                    ROUND_DEADLINE,
                )
                .await?;
            }
            SpecMessage::CancelRound { .. } => {
                conversation.pending = None;
            }
            SpecMessage::SessionClose { .. } => {
                // Two-phase receipt (D7).
                let receipt = sign_receipt(
                    &message_session,
                    conversation.state.round(),
                    conversation.committed_output_len(),
                    identity,
                )?;
                send_spec(session, &receipt, ROUND_DEADLINE).await?;
                let (receipt_ack_valid, close_reason) = match recv_spec(session, ROUND_DEADLINE)
                    .await
                {
                    Ok(SpecMessage::ReceiptAck {
                        requester_signature,
                    }) => {
                        let valid =
                            verify_receipt_ack(&receipt, &requester_signature, expected_requester)
                                .is_ok();
                        (
                            Some(valid),
                            if valid {
                                "closed".to_string()
                            } else {
                                "receipt_mismatch".to_string()
                            },
                        )
                    }
                    Ok(other) => {
                        return Err(SpecError::Protocol(format!(
                            "expected receipt_ack, got {other:?}"
                        )))
                    }
                    Err(_) => (None, "closed_without_receipt_ack".to_string()),
                };
                return Ok(VerifierReport {
                    session_id: message_session,
                    stats: conversation.stats,
                    rounds: conversation.state.round(),
                    committed_tokens: conversation.committed_output_len(),
                    receipt_ack_valid,
                    close_reason,
                });
            }
            other => {
                return Err(SpecError::Protocol(format!(
                    "verifier received an unexpected message: {other:?}"
                )))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Proposer (server)
// ---------------------------------------------------------------------------

/// Per-session proposer report.
#[derive(Debug, Clone)]
pub struct ProposerReport {
    /// The session this report covers.
    pub session_id: String,
    /// Proposal requests answered with a candidate block.
    pub proposals_served: u64,
    /// Coordinator commits applied (hash-chain verified).
    pub commits_applied: u64,
    /// Why the session ended.
    pub close_reason: String,
}

/// A proposer conversation (reconstructs the accepted prefix from the prompt
/// plus every applied commit).
struct ProposerConversation {
    prefix: Vec<u32>,
    last_hash: String,
    handle: Handle,
    proposals_served: u64,
    commits_applied: u64,
}

/// Serves the PROPOSER role: accepts up to `max_sessions` connections,
/// prefills, drafts on request, and applies the coordinator's commits.
pub async fn serve_proposer(
    listener: Listener,
    runtime: Arc<dyn InferenceRuntime>,
    profile_id: &str,
    identity: InstallationIdentity,
    expected_requester: VerifyingKey,
    max_sessions: usize,
) -> Result<Vec<ProposerReport>, SpecError> {
    let mut conversations: HashMap<String, ProposerConversation> = HashMap::new();
    let mut reports = Vec::new();
    for _ in 0..max_sessions {
        let mut session = match listener.accept(&expected_requester, ACCEPT_DEADLINE).await {
            Ok(session) => session,
            Err(e) => {
                if reports.is_empty() {
                    return Err(SpecError::Transport(e));
                }
                break;
            }
        };
        let report = proposer_session_flow(
            &mut session,
            &mut conversations,
            &runtime,
            profile_id,
            &identity,
            &expected_requester,
        )
        .await;
        session.close();
        reports.push(report);
    }
    Ok(reports)
}

async fn proposer_session_flow(
    session: &mut Session,
    conversations: &mut HashMap<String, ProposerConversation>,
    runtime: &Arc<dyn InferenceRuntime>,
    profile_id: &str,
    identity: &InstallationIdentity,
    expected_requester: &VerifyingKey,
) -> ProposerReport {
    match proposer_flow(
        session,
        conversations,
        runtime,
        profile_id,
        identity,
        expected_requester,
    )
    .await
    {
        Ok(report) => report,
        Err(e) => ProposerReport {
            session_id: String::new(),
            proposals_served: 0,
            commits_applied: 0,
            close_reason: format!("{e}"),
        },
    }
}

async fn proposer_flow(
    session: &mut Session,
    conversations: &mut HashMap<String, ProposerConversation>,
    runtime: &Arc<dyn InferenceRuntime>,
    profile_id: &str,
    identity: &InstallationIdentity,
    expected_requester: &VerifyingKey,
) -> Result<ProposerReport, SpecError> {
    let SpecMessage::PrefillRequest {
        session_id,
        prompt_tokens,
        ..
    } = recv_spec(session, SERVER_IDLE).await?
    else {
        return Err(SpecError::Protocol("expected prefill_request first".into()));
    };
    let handle = runtime.load(profile_id).await?;
    let commitment = runtime.prefill(&handle, &prompt_tokens).await?;
    let conversation =
        conversations
            .entry(session_id.clone())
            .or_insert_with(|| ProposerConversation {
                prefix: prompt_tokens.clone(),
                last_hash: GENESIS_PREFIX_HASH.to_string(),
                handle: handle.clone(),
                proposals_served: 0,
                commits_applied: 0,
            });
    conversation.handle = handle;
    let resume_hash = conversation.last_hash.clone();
    send_spec(
        session,
        &SpecMessage::PrefillReady {
            session_id: session_id.clone(),
            kv_commitment_digest: commitment.digest,
            accepted_prefix_hash: resume_hash,
        },
        ROUND_DEADLINE,
    )
    .await?;

    loop {
        let msg = recv_spec(session, SERVER_IDLE).await?;
        let message_session = msg.session_id().unwrap_or_default().to_string();
        let Some(conversation) = conversations.get_mut(&message_session) else {
            return Err(SpecError::Protocol(format!(
                "message for unknown session {message_session:?}"
            )));
        };
        match msg {
            SpecMessage::ProposalRequest {
                round,
                window,
                deadline_ms,
                ..
            } => {
                let budget = Duration::from_millis(u64::from(deadline_ms.max(1)));
                let drafted = tokio::time::timeout(
                    budget,
                    runtime.propose(&conversation.handle, &conversation.prefix, window),
                )
                .await;
                match drafted {
                    Ok(Ok(tokens)) => {
                        conversation.proposals_served += 1;
                        send_spec(
                            session,
                            &SpecMessage::CandidateBlock {
                                session_id: message_session,
                                round,
                                parent_prefix_hash: conversation.last_hash.clone(),
                                tokens,
                                proposer_id: identity.installation_id(),
                            },
                            ROUND_DEADLINE,
                        )
                        .await?;
                    }
                    _ => {
                        send_spec(
                            session,
                            &SpecMessage::CancelRound {
                                session_id: message_session,
                                round,
                                reason: "proposal_failed".to_string(),
                            },
                            ROUND_DEADLINE,
                        )
                        .await?;
                    }
                }
            }
            SpecMessage::PrefixCommit { .. } => {
                let reason = match verify_commit_signature(&msg, expected_requester) {
                    Err(e) => format!("{e}"),
                    Ok(()) => {
                        let commit = msg.commit_prefix().expect("matched prefix_commit above");
                        let chained = commit.previous_prefix_hash == conversation.last_hash
                            && compute_prefix_hash(
                                &commit.previous_prefix_hash,
                                &commit.accepted_token_ids,
                            )
                            .map(|h| h == commit.new_prefix_hash)
                            .unwrap_or(false);
                        if chained {
                            conversation
                                .prefix
                                .extend_from_slice(&commit.accepted_token_ids);
                            conversation.last_hash = commit.new_prefix_hash.clone();
                            conversation.commits_applied += 1;
                            "advanced".to_string()
                        } else {
                            "parent_mismatch".to_string()
                        }
                    }
                };
                let round = msg.commit_prefix().map(|c| c.round).unwrap_or_default();
                let (ok, reason) = ack_result(&reason);
                send_spec(
                    session,
                    &SpecMessage::CommitAck {
                        session_id: message_session,
                        round,
                        ok,
                        reason,
                    },
                    ROUND_DEADLINE,
                )
                .await?;
            }
            SpecMessage::CancelRound { .. } => {}
            SpecMessage::SessionClose { .. } => {
                return Ok(ProposerReport {
                    session_id: message_session,
                    proposals_served: conversation.proposals_served,
                    commits_applied: conversation.commits_applied,
                    close_reason: "closed".to_string(),
                });
            }
            other => {
                return Err(SpecError::Protocol(format!(
                    "proposer received an unexpected message: {other:?}"
                )))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Coordinator (client)
// ---------------------------------------------------------------------------

/// Drives one `speculative_exact` session end to end.
///
/// Greedy E2E contract: `outcome.tokens` are token-identical to plain
/// default-sampling decoding of the same prompt — the verifier only ever
/// consults target outputs, and the single-mode fallback path is the exact
/// plain decoder. Deviations from the call sketch in the phase notes:
/// `profile_id` (pinning the session's commits) and `verifier_key` (verifying
/// the receipt signature — the staged backend authenticates the client to the
/// server, so the server's key must come from the caller's directory) are
/// explicit parameters.
#[allow(clippy::too_many_arguments)]
pub async fn speculate(
    addr_verifier: &str,
    addr_proposer: &str,
    runtime_client: Arc<dyn InferenceRuntime>,
    profile_id: &str,
    prompt_tokens: &[u32],
    window: u32,
    max_tokens: u32,
    identity: &InstallationIdentity,
    verifier_key: &VerifyingKey,
    fallback_policy: FallbackPolicy,
) -> Result<SpecOutcome, SpecError> {
    let session_id = new_nonce();
    let params_hash = default_sampling_params_hash();
    let descriptor = runtime_client.id();
    let handshake = Handshake::build(
        identity,
        profile_id,
        descriptor.name(),
        descriptor.version(),
    );

    let mut verifier =
        SignedFrameTransport::connect(addr_verifier, handshake.clone(), ROUND_DEADLINE).await?;
    let mut proposer =
        SignedFrameTransport::connect(addr_proposer, handshake, ROUND_DEADLINE).await?;

    // Prefill both peers.
    let prefill = SpecMessage::PrefillRequest {
        session_id: session_id.clone(),
        profile_id: profile_id.to_string(),
        prompt_tokens: prompt_tokens.to_vec(),
        generation_params_hash: params_hash.clone(),
    };
    send_spec(&mut verifier, &prefill, ROUND_DEADLINE).await?;
    expect_prefill_ready(&mut verifier, &session_id, GENESIS_PREFIX_HASH).await?;
    send_spec(&mut proposer, &prefill, ROUND_DEADLINE).await?;
    expect_prefill_ready(&mut proposer, &session_id, GENESIS_PREFIX_HASH).await?;

    let mut state =
        SessionStateMachine::new(&session_id, profile_id, &params_hash, GENESIS_PREFIX_HASH)?;
    let mut stats = AcceptanceStats::default();
    let mut tokens: Vec<u32> = Vec::with_capacity(max_tokens as usize);
    let mut round_batches: Vec<Vec<u32>> = Vec::new();
    let mut window_curr = window.clamp(1, WINDOW_MAX);
    let mut consecutive_full: u32 = 0;
    let mut rejection_streak: u32 = 0;
    let mut rtt_streak: u32 = 0;
    // Warm-up round wall times (ms): calibrates the RTT-spike baseline to
    // THIS machine's real speed so a uniformly slow runner (CI) does not
    // trip the detector on healthy acceptance (Phase-F CI incident).
    let mut warmup_round_ms: Vec<f64> = Vec::new();
    let mut rate_history: VecDeque<(u64, u64)> = VecDeque::new();
    let mut fallback: Option<FallbackReason> = None;
    let mut proposer_alive = true;
    let decode_tps = runtime_client.metrics().decode_tokens_per_ms;

    while (tokens.len() as u32) < max_tokens && fallback.is_none() {
        let remaining = max_tokens - tokens.len() as u32;
        let round = state.round() + 1;
        let round_started = Instant::now();
        // Cap the window so a round never commits past the budget: the
        // verifier's hash is authoritative over exactly what it verified.
        let window_eff = window_curr.min(remaining.saturating_sub(1));

        // 1. Proposal (the proposer may die here — the D4 disconnect point).
        let candidate = if proposer_alive {
            let requested = send_spec(
                &mut proposer,
                &SpecMessage::ProposalRequest {
                    session_id: session_id.clone(),
                    round,
                    window: window_eff,
                    deadline_ms: ROUND_DEADLINE.as_millis().min(u128::from(u32::MAX)) as u32,
                    branch_seed: None,
                },
                ROUND_DEADLINE,
            )
            .await
            .is_ok();
            if !requested {
                proposer_alive = false;
                fallback = Some(FallbackReason::PeerLost);
                None
            } else {
                match recv_spec(&mut proposer, ROUND_DEADLINE).await {
                    Ok(msg @ SpecMessage::CandidateBlock { round: r, .. }) if r == round => {
                        Some(msg)
                    }
                    Ok(SpecMessage::CancelRound { reason, .. }) => {
                        return Err(SpecError::Protocol(format!("proposer cancelled: {reason}")))
                    }
                    Ok(other) => {
                        return Err(SpecError::Protocol(format!(
                            "expected candidate_block, got {other:?}"
                        )))
                    }
                    Err(_) => {
                        proposer_alive = false;
                        fallback = Some(FallbackReason::PeerLost);
                        None
                    }
                }
            }
        } else {
            None
        };
        let Some(candidate) = candidate else {
            continue; // fallback set; the loop condition exits to the single tail
        };
        let drafted_len = match &candidate {
            SpecMessage::CandidateBlock { tokens, .. } => tokens.len(),
            _ => unreachable!("matched candidate_block above"),
        };

        // 2. Forward to the verifier and collect the greedy verification.
        send_spec(&mut verifier, &candidate, ROUND_DEADLINE).await?;
        let result = match recv_spec(&mut verifier, ROUND_DEADLINE).await {
            Ok(SpecMessage::VerificationResult {
                round: r,
                accepted_tokens,
                correction,
                new_prefix_hash,
                ..
            }) if r == round => (accepted_tokens, correction, new_prefix_hash),
            Ok(SpecMessage::CancelRound { reason, .. }) => {
                return Err(SpecError::Protocol(format!("verifier cancelled: {reason}")))
            }
            Ok(other) => {
                return Err(SpecError::Protocol(format!(
                    "expected verification_result, got {other:?}"
                )))
            }
            Err(_) => {
                fallback = Some(FallbackReason::PeerLost);
                continue;
            }
        };
        let (accepted_tokens, correction, verified_hash) = result;

        // 3. Assemble + commit. committed = accepted ++ [correction] (the
        // correction on rejection, the bonus token on full acceptance).
        let mut committed_round = accepted_tokens.clone();
        committed_round.extend(correction);
        if committed_round.is_empty() {
            return Err(SpecError::Protocol(
                "verification committed no tokens".into(),
            ));
        }
        let expected_hash = compute_prefix_hash(state.committed_prefix_hash(), &committed_round)?;
        if expected_hash != verified_hash {
            return Err(SpecError::Protocol(
                "verification new_prefix_hash does not match the committed tokens".into(),
            ));
        }
        let commit = CommitPrefix {
            session_id: session_id.clone(),
            round,
            previous_prefix_hash: state.committed_prefix_hash().to_string(),
            accepted_token_ids: committed_round.clone(),
            new_prefix_hash: expected_hash,
            model_profile_id: profile_id.to_string(),
            generation_params_hash: params_hash.clone(),
            sender: identity.installation_id(),
        };
        let wire_commit = SpecMessage::signed_commit(&commit, identity)?;
        send_spec(&mut verifier, &wire_commit, ROUND_DEADLINE).await?;
        match recv_spec(&mut verifier, ROUND_DEADLINE).await? {
            SpecMessage::CommitAck { ok: true, .. } => {}
            SpecMessage::CommitAck {
                ok: false, reason, ..
            } => {
                return Err(SpecError::Protocol(format!(
                    "verifier rejected commit: {reason}"
                )))
            }
            other => {
                return Err(SpecError::Protocol(format!(
                    "expected commit_ack, got {other:?}"
                )))
            }
        }
        if proposer_alive {
            let proposer_ack = async {
                send_spec(&mut proposer, &wire_commit, ROUND_DEADLINE).await?;
                recv_spec(&mut proposer, ROUND_DEADLINE).await
            }
            .await;
            if proposer_ack.is_err() {
                proposer_alive = false;
            }
        }
        if state.apply(&commit) != ApplyOutcome::Advanced {
            return Err(SpecError::Protocol(
                "coordinator's own commit did not advance".into(),
            ));
        }
        tokens.extend_from_slice(&committed_round);
        round_batches.push(committed_round.clone());

        // 4. Telemetry + bounded controllers. The window cap guarantees the
        // committed set is exactly what the verifier hashed, so a correction
        // missing from `committed_round` cannot happen; a round is fully
        // accepted exactly when every drafted token was accepted.
        let fully_accepted = accepted_tokens.len() == drafted_len;
        let accepted_here = accepted_tokens.len().min(committed_round.len());
        stats.record_round(accepted_here, committed_round.len());
        if fully_accepted {
            consecutive_full += 1;
            rejection_streak = 0;
        } else {
            stats.record_rollback();
            rejection_streak += 1;
            consecutive_full = 0;
        }
        rate_history.push_back((accepted_here as u64, committed_round.len() as u64));
        if consecutive_full >= WINDOW_GROW_STREAK {
            window_curr = ((f64::from(window_curr) * 1.5).floor() as u32).clamp(1, WINDOW_MAX);
            consecutive_full = 0;
        }
        if rejection_streak >= WINDOW_SHRINK_STREAK {
            window_curr = (window_curr / 2).max(1);
            rejection_streak = 0;
        }
        if rate_history.len() >= fallback_policy.rate_window_rounds {
            let accepted_sum: u64 = rate_history.iter().map(|entry| entry.0).sum();
            let committed_sum: u64 = rate_history.iter().map(|entry| entry.1).sum();
            if committed_sum > 0
                && (accepted_sum as f32 / committed_sum as f32)
                    < fallback_policy.min_acceptance_rate
            {
                fallback = Some(FallbackReason::AcceptanceCollapse);
            }
        }
        if decode_tps > 0.0 && rate_history.len() >= fallback_policy.rate_window_rounds {
            // Sustained synchronization overrun, not a single scheduling
            // hiccup (ADR-013: measured synchronization crossing the
            // predicted budget). Baseline = max(synthetic estimate, the
            // median of THIS session's warm-up round wall times) so a
            // uniformly slow machine (CI runners) calibrates a slow
            // baseline instead of tripping on healthy acceptance.
            let round_ms = round_started.elapsed().as_secs_f64() * 1_000.0;
            if warmup_round_ms.len() < fallback_policy.rate_window_rounds {
                warmup_round_ms.push(round_ms);
            } else {
                let mut calibration = warmup_round_ms.clone();
                calibration.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let calibrated_ms = calibration[calibration.len() / 2];
                let estimate_ms = (committed_round.len() as f64 / decode_tps).max(calibrated_ms);
                if round_ms > fallback_policy.rtt_multiplier * estimate_ms {
                    rtt_streak += 1;
                    if rtt_streak >= RTT_SPIKE_STREAK {
                        fallback = Some(FallbackReason::RttSpike);
                    }
                } else {
                    rtt_streak = 0;
                }
            }
        }
    }

    // 5. Single-mode tail (exact: same verifier runtime, same default
    // sampling — the fallback output equals plain decoding by construction).
    let remaining = max_tokens - tokens.len() as u32;
    if remaining > 0 && fallback.is_some() {
        let mut prefix = prompt_tokens.to_vec();
        prefix.extend_from_slice(&tokens);
        send_spec(
            &mut verifier,
            &SpecMessage::SingleDecode {
                session_id: session_id.clone(),
                prefix,
                n: remaining,
            },
            ROUND_DEADLINE,
        )
        .await?;
        let single_tokens = match recv_spec(&mut verifier, ROUND_DEADLINE).await? {
            SpecMessage::SingleDecodeResult { tokens, .. } => tokens,
            other => {
                return Err(SpecError::Protocol(format!(
                    "expected single_decode_result, got {other:?}"
                )))
            }
        };
        if single_tokens.len() != remaining as usize {
            return Err(SpecError::Protocol(
                "single decode returned the wrong count".into(),
            ));
        }
        let round = state.round() + 1;
        let new_hash = compute_prefix_hash(state.committed_prefix_hash(), &single_tokens)?;
        let commit = CommitPrefix {
            session_id: session_id.clone(),
            round,
            previous_prefix_hash: state.committed_prefix_hash().to_string(),
            accepted_token_ids: single_tokens.clone(),
            new_prefix_hash: new_hash,
            model_profile_id: profile_id.to_string(),
            generation_params_hash: params_hash.clone(),
            sender: identity.installation_id(),
        };
        let wire_commit = SpecMessage::signed_commit(&commit, identity)?;
        send_spec(&mut verifier, &wire_commit, ROUND_DEADLINE).await?;
        match recv_spec(&mut verifier, ROUND_DEADLINE).await? {
            SpecMessage::CommitAck { ok: true, .. } => {}
            SpecMessage::CommitAck {
                ok: false, reason, ..
            } => {
                return Err(SpecError::Protocol(format!(
                    "verifier rejected tail commit: {reason}"
                )))
            }
            other => {
                return Err(SpecError::Protocol(format!(
                    "expected commit_ack for tail, got {other:?}"
                )))
            }
        }
        if proposer_alive {
            let _ = async {
                send_spec(&mut proposer, &wire_commit, ROUND_DEADLINE).await?;
                recv_spec(&mut proposer, ROUND_DEADLINE).await
            }
            .await;
        }
        if state.apply(&commit) != ApplyOutcome::Advanced {
            return Err(SpecError::Protocol("tail commit did not advance".into()));
        }
        tokens.extend_from_slice(&single_tokens);
        round_batches.push(single_tokens);
    }

    // 6. Auditor cross-check (F7): the coordinator re-verifies the whole
    // committed chain against its own runtime BEFORE emitting or closing —
    // a verifier whose accepted tokens diverge from the plain target
    // continuation fails the session here, garbage never reaches the output.
    audit_final_chain(&runtime_client, profile_id, prompt_tokens, &tokens).await?;

    // 7. Two-phase close with the verifier.
    send_spec(
        &mut verifier,
        &SpecMessage::SessionClose {
            session_id: session_id.clone(),
            reason: "done".to_string(),
        },
        ROUND_DEADLINE,
    )
    .await?;
    let mut receipts_verified = false;
    match recv_spec(&mut verifier, ROUND_DEADLINE).await? {
        receipt @ SpecMessage::Receipt { .. } => {
            if verify_receipt_signature(&receipt, verifier_key).is_ok() {
                let ack = SpecMessage::ReceiptAck {
                    requester_signature: sign_receipt_ack(&receipt, identity)?,
                };
                send_spec(&mut verifier, &ack, ROUND_DEADLINE).await?;
                receipts_verified = true;
            }
        }
        other => {
            return Err(SpecError::Protocol(format!(
                "expected receipt, got {other:?}"
            )))
        }
    }
    if proposer_alive {
        let _ = send_spec(
            &mut proposer,
            &SpecMessage::SessionClose {
                session_id: session_id.clone(),
                reason: "done".to_string(),
            },
            ROUND_DEADLINE,
        )
        .await;
    }
    verifier.close();
    proposer.close();

    Ok(SpecOutcome {
        session_id,
        tokens,
        round_batches,
        rounds: state.round(),
        acceptance: stats,
        fallback,
        receipts_verified,
        mode: SpecMode::TwoPeer,
        duplicate_work: 0,
        pruned: 0,
        stragglers: 0,
        proposer_reports: Vec::new(),
    })
}

async fn expect_prefill_ready(
    session: &mut Session,
    session_id: &str,
    expected_hash: &str,
) -> Result<String, SpecError> {
    match recv_spec(session, ROUND_DEADLINE).await? {
        SpecMessage::PrefillReady {
            session_id: sid,
            kv_commitment_digest,
            accepted_prefix_hash,
        } => {
            if sid != session_id {
                return Err(SpecError::Protocol(
                    "prefill_ready for the wrong session".into(),
                ));
            }
            if accepted_prefix_hash != expected_hash {
                return Err(SpecError::Protocol(format!(
                    "peer resumed from {accepted_prefix_hash}, coordinator expected {expected_hash}"
                )));
            }
            Ok(kv_commitment_digest)
        }
        other => Err(SpecError::Protocol(format!(
            "expected prefill_ready, got {other:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Auditor cross-check (F7)
// ---------------------------------------------------------------------------

/// Re-verifies the final committed chain locally with the coordinator's own
/// runtime before the outcome is emitted — the F7 auditor pattern: a
/// malicious or faulty verifier that returns hash-consistent results over
/// garbage tokens (defeating the per-round prefix-chain check) is still
/// caught here, because the plain target continuation is a pure function of
/// the prompt under default sampling. Divergence fails the session
/// explicitly; garbage never reaches [`SpecOutcome`].
///
/// Cost: one load plus `committed.len()` decode steps per session on the
/// requester (the ADR-013 security overhead the cost model prices).
async fn audit_final_chain(
    runtime: &Arc<dyn InferenceRuntime>,
    profile_id: &str,
    prompt_tokens: &[u32],
    committed: &[u32],
) -> Result<(), SpecError> {
    let handle = runtime.load(profile_id).await?;
    let mut prefix = prompt_tokens.to_vec();
    for (index, expected) in committed.iter().enumerate() {
        let token = runtime
            .decode_step(&handle, &prefix, &SamplingParams::default())
            .await?;
        if token != *expected {
            return Err(SpecError::Protocol(format!(
                "auditor divergence at committed token {index}: verifier committed {expected}, \
                 the local target continuation is {token}"
            )));
        }
        prefix.push(token);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Multi-proposer (Phase E): seeded proposer server + tree coordinator
// ---------------------------------------------------------------------------

/// Builds the per-round draft runtime for a proposer from the round's branch
/// seed (see the crate-doc "Branch distinctness" note). Factories must be
/// deterministic: same seed ⇒ same draft behavior.
pub type ProposerRuntimeFactory = Arc<dyn Fn(u64) -> Arc<dyn InferenceRuntime> + Send + Sync>;

/// Serves the Phase E PROPOSER role: like [`serve_proposer`], but each
/// [`SpecMessage::ProposalRequest`] carries the round's branch seed and the
/// draft is produced by a runtime built from that seed via `factory` — so
/// distinct proposers (distinct seeds) draft distinct branches
/// deterministically while keeping the runtime's draft-accuracy semantics.
/// Commits are applied exactly as in the two-peer flow.
#[allow(clippy::too_many_arguments)]
pub async fn serve_proposer_multi(
    listener: Listener,
    factory: ProposerRuntimeFactory,
    profile_id: &str,
    identity: InstallationIdentity,
    expected_requester: VerifyingKey,
    max_sessions: usize,
) -> Result<Vec<ProposerReport>, SpecError> {
    let mut conversations: HashMap<String, ProposerConversation> = HashMap::new();
    let mut reports = Vec::new();
    for _ in 0..max_sessions {
        let mut session = match listener.accept(&expected_requester, ACCEPT_DEADLINE).await {
            Ok(session) => session,
            Err(e) => {
                if reports.is_empty() {
                    return Err(SpecError::Transport(e));
                }
                break;
            }
        };
        let report = proposer_multi_session_flow(
            &mut session,
            &mut conversations,
            &factory,
            profile_id,
            &identity,
            &expected_requester,
        )
        .await;
        session.close();
        reports.push(report);
    }
    Ok(reports)
}

async fn proposer_multi_session_flow(
    session: &mut Session,
    conversations: &mut HashMap<String, ProposerConversation>,
    factory: &ProposerRuntimeFactory,
    profile_id: &str,
    identity: &InstallationIdentity,
    expected_requester: &VerifyingKey,
) -> ProposerReport {
    match proposer_multi_flow(
        session,
        conversations,
        factory,
        profile_id,
        identity,
        expected_requester,
    )
    .await
    {
        Ok(report) => report,
        Err(e) => ProposerReport {
            session_id: String::new(),
            proposals_served: 0,
            commits_applied: 0,
            close_reason: format!("{e}"),
        },
    }
}

async fn proposer_multi_flow(
    session: &mut Session,
    conversations: &mut HashMap<String, ProposerConversation>,
    factory: &ProposerRuntimeFactory,
    profile_id: &str,
    identity: &InstallationIdentity,
    expected_requester: &VerifyingKey,
) -> Result<ProposerReport, SpecError> {
    let SpecMessage::PrefillRequest {
        session_id,
        prompt_tokens,
        ..
    } = recv_spec(session, SERVER_IDLE).await?
    else {
        return Err(SpecError::Protocol("expected prefill_request first".into()));
    };
    // A persistent runtime instance owns the conversation handle (prefill
    // bookkeeping only — drafts come from the per-round seeded factories).
    let persistent = factory(0);
    let handle = persistent.load(profile_id).await?;
    let conversation =
        conversations
            .entry(session_id.clone())
            .or_insert_with(|| ProposerConversation {
                prefix: prompt_tokens.clone(),
                last_hash: GENESIS_PREFIX_HASH.to_string(),
                handle: handle.clone(),
                proposals_served: 0,
                commits_applied: 0,
            });
    conversation.handle = handle;
    let commitment = persistent
        .prefill(&conversation.handle, &prompt_tokens)
        .await?;
    let resume_hash = conversation.last_hash.clone();
    send_spec(
        session,
        &SpecMessage::PrefillReady {
            session_id: session_id.clone(),
            kv_commitment_digest: commitment.digest,
            accepted_prefix_hash: resume_hash,
        },
        ROUND_DEADLINE,
    )
    .await?;

    loop {
        let msg = recv_spec(session, SERVER_IDLE).await?;
        let message_session = msg.session_id().unwrap_or_default().to_string();
        let Some(conversation) = conversations.get_mut(&message_session) else {
            return Err(SpecError::Protocol(format!(
                "message for unknown session {message_session:?}"
            )));
        };
        match msg {
            SpecMessage::ProposalRequest {
                round,
                window,
                deadline_ms,
                branch_seed,
                ..
            } => {
                // E1: the branch seed from the request drives the draft —
                // the ONLY mechanism by which proposers diverge.
                let budget = Duration::from_millis(u64::from(deadline_ms.max(1)));
                let seed = branch_seed.unwrap_or(0);
                let draft_runtime = factory(seed);
                let drafted = match draft_runtime.load(profile_id).await {
                    Ok(handle) => {
                        tokio::time::timeout(
                            budget,
                            draft_runtime.propose(&handle, &conversation.prefix, window),
                        )
                        .await
                    }
                    Err(e) => Ok(Err(e)),
                };
                match drafted {
                    Ok(Ok(tokens)) => {
                        conversation.proposals_served += 1;
                        send_spec(
                            session,
                            &SpecMessage::CandidateBlock {
                                session_id: message_session,
                                round,
                                parent_prefix_hash: conversation.last_hash.clone(),
                                tokens,
                                proposer_id: identity.installation_id(),
                            },
                            ROUND_DEADLINE,
                        )
                        .await?;
                    }
                    _ => {
                        send_spec(
                            session,
                            &SpecMessage::CancelRound {
                                session_id: message_session,
                                round,
                                reason: "proposal_failed".to_string(),
                            },
                            ROUND_DEADLINE,
                        )
                        .await?;
                    }
                }
            }
            SpecMessage::PrefixCommit { .. } => {
                let reason = match verify_commit_signature(&msg, expected_requester) {
                    Err(e) => format!("{e}"),
                    Ok(()) => {
                        let commit = msg.commit_prefix().expect("matched prefix_commit above");
                        let chained = commit.previous_prefix_hash == conversation.last_hash
                            && compute_prefix_hash(
                                &commit.previous_prefix_hash,
                                &commit.accepted_token_ids,
                            )
                            .map(|h| h == commit.new_prefix_hash)
                            .unwrap_or(false);
                        if chained {
                            conversation
                                .prefix
                                .extend_from_slice(&commit.accepted_token_ids);
                            conversation.last_hash = commit.new_prefix_hash.clone();
                            conversation.commits_applied += 1;
                            "advanced".to_string()
                        } else {
                            "parent_mismatch".to_string()
                        }
                    }
                };
                let round = msg.commit_prefix().map(|c| c.round).unwrap_or_default();
                let (ok, reason) = ack_result(&reason);
                send_spec(
                    session,
                    &SpecMessage::CommitAck {
                        session_id: message_session,
                        round,
                        ok,
                        reason,
                    },
                    ROUND_DEADLINE,
                )
                .await?;
            }
            SpecMessage::CancelRound { .. } => {}
            SpecMessage::SessionClose { .. } => {
                return Ok(ProposerReport {
                    session_id: message_session,
                    proposals_served: conversation.proposals_served,
                    commits_applied: conversation.commits_applied,
                    close_reason: "closed".to_string(),
                });
            }
            other => {
                return Err(SpecError::Protocol(format!(
                    "multi proposer received an unexpected message: {other:?}"
                )))
            }
        }
    }
}

/// Reads the next reply for `round`, discarding stale round-tagged messages
/// (late candidate blocks / acks from rounds the coordinator already
/// committed — the straggler-drain rule that keeps connections in sync after
/// a deadline drop).
async fn recv_round_reply(
    session: &mut Session,
    round: u64,
    deadline: Duration,
) -> Result<SpecMessage, SpecError> {
    loop {
        let msg = recv_spec(session, deadline).await?;
        let stale = match &msg {
            SpecMessage::CandidateBlock { round: r, .. }
            | SpecMessage::CancelRound { round: r, .. }
            | SpecMessage::CommitAck { round: r, .. } => *r < round,
            _ => false,
        };
        if !stale {
            return Ok(msg);
        }
    }
}

/// Drives one Phase E `speculative_exact` session with 2..=7 proposers end
/// to end (see the crate-doc Phase E section). Same deviations from the call
/// sketch as [`speculate`] (`profile_id`, `verifier_key`), plus two explicit
/// knobs: `trie_limits` (E2 bounds) and `proposal_deadline` (E5 collection
/// deadline; defaults to [`DEFAULT_PROPOSAL_DEADLINE`] at call sites).
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
pub async fn speculate_multi(
    addr_verifier: &str,
    addr_proposers: &[String],
    runtime_client: Arc<dyn InferenceRuntime>,
    profile_id: &str,
    prompt_tokens: &[u32],
    window: u32,
    max_tokens: u32,
    identity: &InstallationIdentity,
    verifier_key: &VerifyingKey,
    fallback_policy: FallbackPolicy,
    trie_limits: TrieLimits,
    proposal_deadline: Duration,
) -> Result<SpecOutcome, SpecError> {
    if !(MULTI_PROPOSERS_MIN..=MULTI_PROPOSERS_MAX).contains(&addr_proposers.len()) {
        return Err(SpecError::Protocol(format!(
            "speculate_multi needs {MULTI_PROPOSERS_MIN}..={MULTI_PROPOSERS_MAX} proposers, got {}",
            addr_proposers.len()
        )));
    }
    let session_id = new_nonce();
    let params_hash = default_sampling_params_hash();
    let descriptor = runtime_client.id();
    let handshake = Handshake::build(
        identity,
        profile_id,
        descriptor.name(),
        descriptor.version(),
    );

    let mut verifier =
        SignedFrameTransport::connect(addr_verifier, handshake.clone(), ROUND_DEADLINE).await?;
    let mut proposers = Vec::with_capacity(addr_proposers.len());
    for addr in addr_proposers {
        proposers
            .push(SignedFrameTransport::connect(addr, handshake.clone(), ROUND_DEADLINE).await?);
    }

    // Prefill every peer (verifier + roster).
    let prefill = SpecMessage::PrefillRequest {
        session_id: session_id.clone(),
        profile_id: profile_id.to_string(),
        prompt_tokens: prompt_tokens.to_vec(),
        generation_params_hash: params_hash.clone(),
    };
    send_spec(&mut verifier, &prefill, ROUND_DEADLINE).await?;
    expect_prefill_ready(&mut verifier, &session_id, GENESIS_PREFIX_HASH).await?;
    for proposer in &mut proposers {
        send_spec(proposer, &prefill, ROUND_DEADLINE).await?;
        expect_prefill_ready(proposer, &session_id, GENESIS_PREFIX_HASH).await?;
    }

    let mut state =
        SessionStateMachine::new(&session_id, profile_id, &params_hash, GENESIS_PREFIX_HASH)?;
    let mut stats = AcceptanceStats::default();
    let mut tokens: Vec<u32> = Vec::with_capacity(max_tokens as usize);
    let mut round_batches: Vec<Vec<u32>> = Vec::new();
    let mut window_curr = window.clamp(1, WINDOW_MAX);
    let mut consecutive_full: u32 = 0;
    let mut rejection_streak: u32 = 0;
    let mut rtt_streak: u32 = 0;
    // Warm-up round wall times (ms): calibrates the RTT-spike baseline to
    // THIS machine's real speed so a uniformly slow runner (CI) does not
    // trip the detector on healthy acceptance (Phase-F CI incident).
    let mut warmup_round_ms: Vec<f64> = Vec::new();
    let mut rate_history: VecDeque<(u64, u64)> = VecDeque::new();
    let mut fallback: Option<FallbackReason> = None;
    let decode_tps = runtime_client.metrics().decode_tokens_per_ms;
    let mut trackers: Vec<ProposerPeerReport> = addr_proposers
        .iter()
        .enumerate()
        .map(|(index, addr)| ProposerPeerReport {
            index,
            addr: addr.clone(),
            blocks_arrived: 0,
            straggler_rounds: 0,
            drafted_tokens: 0,
            accepted_tokens: 0,
            alive: true,
        })
        .collect();
    let mut duplicate_work: u64 = 0;
    let mut pruned: u64 = 0;
    let mut stragglers: u64 = 0;

    while (tokens.len() as u32) < max_tokens && fallback.is_none() {
        let remaining = max_tokens - tokens.len() as u32;
        let round = state.round() + 1;
        let round_started = Instant::now();
        let window_eff = window_curr.min(remaining.saturating_sub(1));
        // E5: the collection deadline is anchored at the round start, so any
        // number of stragglers costs at most one deadline per round.
        let collect_by = round_started + proposal_deadline;

        // 1. Fan out seeded proposal requests (E1). Dead proposers are
        // skipped; the roster length stays the FULL roster so branch
        // assignments remain reproducible across peer loss.
        let roster_len = trackers.len();
        for (i, proposer) in proposers.iter_mut().enumerate() {
            if !trackers[i].alive {
                continue;
            }
            let request = SpecMessage::ProposalRequest {
                session_id: session_id.clone(),
                round,
                window: window_eff,
                deadline_ms: proposal_deadline.as_millis().min(u128::from(u32::MAX)) as u32,
                branch_seed: Some(branch_assignment(&session_id, round, roster_len, i)),
            };
            if send_spec(proposer, &request, ROUND_DEADLINE).await.is_err() {
                trackers[i].alive = false;
                stragglers += 1;
                trackers[i].straggler_rounds += 1;
            }
        }
        if trackers.iter().all(|tracker| !tracker.alive) {
            // Every proposer is gone: explicit fallback (D4 posture), the
            // verifier-backed single tail keeps the output exact.
            fallback = Some(FallbackReason::PeerLost);
            continue;
        }

        // 2. Collect blocks under the anchored deadline; misses are counted
        // stragglers and the proposer stays in the roster (its late replies
        // are drained as stale by `recv_round_reply`).
        let mut blocks: Vec<BranchBlock> = Vec::with_capacity(roster_len);
        for (i, proposer) in proposers.iter_mut().enumerate() {
            if !trackers[i].alive {
                continue;
            }
            let budget = collect_by
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1));
            match tokio::time::timeout(budget, recv_round_reply(proposer, round, ROUND_DEADLINE))
                .await
            {
                Ok(Ok(SpecMessage::CandidateBlock { tokens, .. })) => {
                    trackers[i].blocks_arrived += 1;
                    trackers[i].drafted_tokens += tokens.len() as u64;
                    blocks.push(BranchBlock {
                        proposer: i,
                        score: trackers[i].score(),
                        tokens,
                    });
                }
                Ok(Ok(SpecMessage::CancelRound { .. })) => {
                    stragglers += 1;
                    trackers[i].straggler_rounds += 1;
                }
                Ok(Ok(other)) => {
                    return Err(SpecError::Protocol(format!(
                        "expected candidate_block, got {other:?}"
                    )))
                }
                Ok(Err(_transport)) => {
                    // Connection died mid-collection: straggler this round and
                    // out of the roster for good (D4 explicit peer loss).
                    stragglers += 1;
                    trackers[i].straggler_rounds += 1;
                    trackers[i].alive = false;
                }
                Err(_elapsed) => {
                    // Deadline miss (E5): counted and excluded this round;
                    // the proposer stays in the roster — its late reply is
                    // drained as a stale message on the next round.
                    stragglers += 1;
                    trackers[i].straggler_rounds += 1;
                }
            }
        }

        // 3. Assemble the bounded trie (E2 bounds, E3 duplicate counting).
        let trie = CandidateTrie::assemble(blocks, trie_limits);
        duplicate_work += trie.duplicate_work() as u64;
        pruned += trie.pruned() as u64;
        let branches: Vec<Vec<u32>> = trie
            .branches()
            .iter()
            .map(|block| block.tokens.clone())
            .collect();

        // 4. One tree verification round against the verifier.
        send_spec(
            &mut verifier,
            &SpecMessage::TreeVerifyRequest {
                session_id: session_id.clone(),
                round,
                branches,
            },
            ROUND_DEADLINE,
        )
        .await?;
        let result = match recv_spec(&mut verifier, ROUND_DEADLINE).await {
            Ok(SpecMessage::TreeVerifyResult {
                round: r,
                accepted_tokens,
                correction,
                new_prefix_hash,
                ..
            }) if r == round => (accepted_tokens, correction, new_prefix_hash),
            Ok(SpecMessage::CancelRound { reason, .. }) => {
                return Err(SpecError::Protocol(format!("verifier cancelled: {reason}")))
            }
            Ok(other) => {
                return Err(SpecError::Protocol(format!(
                    "expected tree_verify_result, got {other:?}"
                )))
            }
            Err(_) => {
                fallback = Some(FallbackReason::PeerLost);
                continue;
            }
        };

        // 5. Commit through the SAME signed PrefixCommit path as Phase D.
        let (accepted_tokens, correction, verified_hash) = result;
        let mut committed_round = accepted_tokens.clone();
        committed_round.extend(correction);
        if committed_round.is_empty() {
            return Err(SpecError::Protocol(
                "tree verification committed no tokens".into(),
            ));
        }
        let expected_hash = compute_prefix_hash(state.committed_prefix_hash(), &committed_round)?;
        if expected_hash != verified_hash {
            return Err(SpecError::Protocol(
                "tree_verify new_prefix_hash does not match the committed tokens".into(),
            ));
        }
        let commit = CommitPrefix {
            session_id: session_id.clone(),
            round,
            previous_prefix_hash: state.committed_prefix_hash().to_string(),
            accepted_token_ids: committed_round.clone(),
            new_prefix_hash: expected_hash,
            model_profile_id: profile_id.to_string(),
            generation_params_hash: params_hash.clone(),
            sender: identity.installation_id(),
        };
        let wire_commit = SpecMessage::signed_commit(&commit, identity)?;
        send_spec(&mut verifier, &wire_commit, ROUND_DEADLINE).await?;
        match recv_round_reply(&mut verifier, round, ROUND_DEADLINE).await? {
            SpecMessage::CommitAck { ok: true, .. } => {}
            SpecMessage::CommitAck {
                ok: false, reason, ..
            } => {
                return Err(SpecError::Protocol(format!(
                    "verifier rejected commit: {reason}"
                )))
            }
            other => {
                return Err(SpecError::Protocol(format!(
                    "expected commit_ack, got {other:?}"
                )))
            }
        }
        // Forward the commit to every live proposer (prefix reconstruction);
        // a proposer that fails here drops out of the roster silently — the
        // commit itself is already chained on the verifier.
        for (i, proposer) in proposers.iter_mut().enumerate() {
            if !trackers[i].alive {
                continue;
            }
            let ack = async {
                send_spec(proposer, &wire_commit, ROUND_DEADLINE).await?;
                recv_round_reply(proposer, round, ROUND_DEADLINE).await
            }
            .await;
            // Liveness only (Phase D posture): a failing connection drops
            // the proposer; a received message of any kind keeps it.
            if ack.is_err() {
                trackers[i].alive = false;
            }
        }
        if state.apply(&commit) != ApplyOutcome::Advanced {
            return Err(SpecError::Protocol(
                "coordinator's own commit did not advance".into(),
            ));
        }
        tokens.extend_from_slice(&committed_round);
        round_batches.push(committed_round.clone());

        // 6. Telemetry: winning-branch attribution (first assembled branch
        // having the accepted tokens as a prefix — exactly
        // verify_tree_greedy's first-with-max-depth tie-break).
        let winning = trie.branches().iter().find(|block| {
            block.tokens.len() >= accepted_tokens.len()
                && block.tokens[..accepted_tokens.len()] == accepted_tokens[..]
        });
        match winning {
            Some(block) => {
                let fully_accepted = accepted_tokens.len() == block.tokens.len();
                trackers[block.proposer].accepted_tokens += accepted_tokens.len() as u64;
                stats.record_round(accepted_tokens.len(), committed_round.len());
                if fully_accepted {
                    consecutive_full += 1;
                    rejection_streak = 0;
                } else {
                    stats.record_rollback();
                    rejection_streak += 1;
                    consecutive_full = 0;
                }
                rate_history
                    .push_back((accepted_tokens.len() as u64, committed_round.len() as u64));
            }
            None => {
                // No branch survived (all stragglers): the round committed
                // exactly the lookahead bonus token — progress without any
                // speculative rejection.
                stats.record_round(0, committed_round.len());
                rate_history.push_back((0, committed_round.len() as u64));
                consecutive_full = 0;
                rejection_streak = 0;
            }
        }
        if consecutive_full >= WINDOW_GROW_STREAK {
            window_curr = ((f64::from(window_curr) * 1.5).floor() as u32).clamp(1, WINDOW_MAX);
            consecutive_full = 0;
        }
        if rejection_streak >= WINDOW_SHRINK_STREAK {
            window_curr = (window_curr / 2).max(1);
            rejection_streak = 0;
        }
        if rate_history.len() >= fallback_policy.rate_window_rounds {
            let accepted_sum: u64 = rate_history.iter().map(|entry| entry.0).sum();
            let committed_sum: u64 = rate_history.iter().map(|entry| entry.1).sum();
            if committed_sum > 0
                && (accepted_sum as f32 / committed_sum as f32)
                    < fallback_policy.min_acceptance_rate
            {
                fallback = Some(FallbackReason::AcceptanceCollapse);
            }
        }
        let round_ms = round_started.elapsed().as_secs_f64() * 1_000.0;
        if warmup_round_ms.len() < fallback_policy.rate_window_rounds {
            // Warm-up: record this machine's real round cost.
            warmup_round_ms.push(round_ms);
        } else if decode_tps > 0.0 {
            // Baseline: max(synthetic estimate, median of this session's
            // warm-up rounds) — environment-adaptive (Phase-F CI incident).
            let mut calibration = warmup_round_ms.clone();
            calibration.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let calibrated_ms = calibration[calibration.len() / 2];
            let estimate_ms = (committed_round.len() as f64 / decode_tps).max(calibrated_ms);
            if round_ms > fallback_policy.rtt_multiplier * estimate_ms {
                rtt_streak += 1;
                if rtt_streak >= RTT_SPIKE_STREAK {
                    fallback = Some(FallbackReason::RttSpike);
                }
            } else {
                rtt_streak = 0;
            }
        }
    }

    // 7. Single-mode tail (exact by construction; same mechanism as D).
    let remaining = max_tokens - tokens.len() as u32;
    if remaining > 0 && fallback.is_some() {
        let mut prefix = prompt_tokens.to_vec();
        prefix.extend_from_slice(&tokens);
        send_spec(
            &mut verifier,
            &SpecMessage::SingleDecode {
                session_id: session_id.clone(),
                prefix,
                n: remaining,
            },
            ROUND_DEADLINE,
        )
        .await?;
        let single_tokens = match recv_spec(&mut verifier, ROUND_DEADLINE).await? {
            SpecMessage::SingleDecodeResult { tokens, .. } => tokens,
            other => {
                return Err(SpecError::Protocol(format!(
                    "expected single_decode_result, got {other:?}"
                )))
            }
        };
        if single_tokens.len() != remaining as usize {
            return Err(SpecError::Protocol(
                "single decode returned the wrong count".into(),
            ));
        }
        let round = state.round() + 1;
        let new_hash = compute_prefix_hash(state.committed_prefix_hash(), &single_tokens)?;
        let commit = CommitPrefix {
            session_id: session_id.clone(),
            round,
            previous_prefix_hash: state.committed_prefix_hash().to_string(),
            accepted_token_ids: single_tokens.clone(),
            new_prefix_hash: new_hash,
            model_profile_id: profile_id.to_string(),
            generation_params_hash: params_hash.clone(),
            sender: identity.installation_id(),
        };
        let wire_commit = SpecMessage::signed_commit(&commit, identity)?;
        send_spec(&mut verifier, &wire_commit, ROUND_DEADLINE).await?;
        match recv_spec(&mut verifier, ROUND_DEADLINE).await? {
            SpecMessage::CommitAck { ok: true, .. } => {}
            SpecMessage::CommitAck {
                ok: false, reason, ..
            } => {
                return Err(SpecError::Protocol(format!(
                    "verifier rejected tail commit: {reason}"
                )))
            }
            other => {
                return Err(SpecError::Protocol(format!(
                    "expected commit_ack for tail, got {other:?}"
                )))
            }
        }
        for (i, proposer) in proposers.iter_mut().enumerate() {
            if !trackers[i].alive {
                continue;
            }
            let _ = send_spec(proposer, &wire_commit, ROUND_DEADLINE).await;
        }
        if state.apply(&commit) != ApplyOutcome::Advanced {
            return Err(SpecError::Protocol("tail commit did not advance".into()));
        }
        tokens.extend_from_slice(&single_tokens);
        round_batches.push(single_tokens);
    }

    // 8. Auditor cross-check (F7): re-verify the committed chain against the
    // coordinator's own runtime before emitting (same rule as Phase D).
    audit_final_chain(&runtime_client, profile_id, prompt_tokens, &tokens).await?;

    // 9. Two-phase close with the verifier, then the proposers.
    send_spec(
        &mut verifier,
        &SpecMessage::SessionClose {
            session_id: session_id.clone(),
            reason: "done".to_string(),
        },
        ROUND_DEADLINE,
    )
    .await?;
    let mut receipts_verified = false;
    match recv_spec(&mut verifier, ROUND_DEADLINE).await? {
        receipt @ SpecMessage::Receipt { .. } => {
            if verify_receipt_signature(&receipt, verifier_key).is_ok() {
                let ack = SpecMessage::ReceiptAck {
                    requester_signature: sign_receipt_ack(&receipt, identity)?,
                };
                send_spec(&mut verifier, &ack, ROUND_DEADLINE).await?;
                receipts_verified = true;
            }
        }
        other => {
            return Err(SpecError::Protocol(format!(
                "expected receipt, got {other:?}"
            )))
        }
    }
    for (i, proposer) in proposers.iter_mut().enumerate() {
        if trackers[i].alive {
            let _ = send_spec(
                proposer,
                &SpecMessage::SessionClose {
                    session_id: session_id.clone(),
                    reason: "done".to_string(),
                },
                ROUND_DEADLINE,
            )
            .await;
        }
    }
    verifier.close();
    for proposer in &mut proposers {
        proposer.close();
    }

    Ok(SpecOutcome {
        session_id,
        tokens,
        round_batches,
        rounds: state.round(),
        acceptance: stats,
        fallback,
        receipts_verified,
        mode: SpecMode::MultiProposer,
        duplicate_work,
        pruned,
        stragglers,
        proposer_reports: trackers,
    })
}

/// One verifier/proposer pair the [`SpeculativeExecutor`] rotates through.
#[derive(Debug, Clone)]
pub struct SpecPeer {
    /// Verifier (target model) address.
    pub verifier_addr: String,
    /// Proposer (draft model) address.
    pub proposer_addr: String,
    /// The verifier's public key — verifies the close receipt.
    pub verifier_key: VerifyingKey,
}

/// [`InferenceExecutor`] driving [`speculate`] for greedy/single requests
/// (Phase-D plug-in point of the gateway).
///
/// Contract mapping:
///
/// - [`ExecutorEvent::Accepted`] once; [`ExecutorEvent::TokenDelta`] per
///   committed round batch (batch deltas concatenated, index per event);
///   [`ExecutorEvent::Usage`] from the session stats; [`ExecutorEvent::Completed`]
///   with the finish reason.
/// - Failure policy (ADR-007): events are emitted only once the whole
///   cooperative-or-fallback result is known, so no token boundary is ever
///   crossed mid-flight — a failed session surfaces as a pre-first-token
///   [`ExecutorError::Retryable`] and the gateway re-invokes `execute`
///   unchanged; this executor then advances to the next pair in its rotation
///   list. Mid-stream interruption events therefore never fabricate output.
/// - Sampling limitation: the cooperative session is pinned to
///   [`SamplingParams::default()`] (see [`default_sampling_params_hash`]);
///   request-sampled generation is not served by this executor.
pub struct SpeculativeExecutor {
    peers: Vec<SpecPeer>,
    identity: InstallationIdentity,
    runtime: Arc<dyn InferenceRuntime>,
    profile_id: String,
    window: u32,
    fallback_policy: FallbackPolicy,
    next: AtomicUsize,
}

impl SpeculativeExecutor {
    /// Builds the executor over a non-empty rotation list.
    pub fn new(
        peers: Vec<SpecPeer>,
        identity: InstallationIdentity,
        runtime: Arc<dyn InferenceRuntime>,
        profile_id: impl Into<String>,
        window: u32,
        fallback_policy: FallbackPolicy,
    ) -> Self {
        Self {
            peers,
            identity,
            runtime,
            profile_id: profile_id.into(),
            window,
            fallback_policy,
            next: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl InferenceExecutor for SpeculativeExecutor {
    async fn execute(&self, request: NormalizedRequest) -> Result<ExecutorStream, ExecutorError> {
        let Some(peer) = self
            .peers
            .get(self.next.fetch_add(1, Ordering::Relaxed) % self.peers.len().max(1))
        else {
            return Err(ExecutorError::NoPeer);
        };
        let hint = || Some(peer.verifier_addr.clone());
        let mut conversation = String::new();
        for message in &request.messages {
            conversation.push_str(&message.content);
            conversation.push('\n');
        }
        let prompt = self
            .runtime
            .tokenize(&conversation)
            .await
            .map_err(|_| ExecutorError::Retryable { peer_hint: hint() })?;
        let started = Instant::now();
        let budget = Duration::from_millis(u64::from(request.deadline_ms.max(1)));
        let outcome = tokio::time::timeout(
            budget,
            speculate(
                &peer.verifier_addr,
                &peer.proposer_addr,
                Arc::clone(&self.runtime),
                &self.profile_id,
                &prompt,
                self.window,
                request.max_tokens,
                &self.identity,
                &peer.verifier_key,
                self.fallback_policy,
            ),
        )
        .await
        .map_err(|_| ExecutorError::Fatal {
            code: "deadline_exceeded".to_string(),
        })?
        .map_err(|_| ExecutorError::Retryable { peer_hint: hint() })?;

        let mut events = Vec::with_capacity(outcome.round_batches.len() + 3);
        events.push(ExecutorEvent::Accepted {
            queue_position: 0,
            eta_ms: 0,
        });
        for (index, batch) in outcome.round_batches.iter().enumerate() {
            let delta = self
                .runtime
                .detokenize(batch)
                .await
                .map_err(|_| ExecutorError::Fatal {
                    code: "detokenize_failed".to_string(),
                })?;
            events.push(ExecutorEvent::TokenDelta {
                delta,
                index: index as u32,
            });
        }
        events.push(ExecutorEvent::Usage {
            prompt_tokens: prompt.len() as u32,
            completion_tokens: outcome.tokens.len() as u32,
            prefill_ms: 0.0,
            decode_ms: started.elapsed().as_secs_f64() * 1_000.0,
        });
        let finish = if outcome.tokens.len() >= request.max_tokens as usize {
            FinishReason::Length
        } else {
            FinishReason::Stop
        };
        events.push(ExecutorEvent::Completed {
            finish_reason: finish,
        });
        Ok(Box::pin(stream::iter(events)))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> InstallationIdentity {
        InstallationIdentity::from_bytes(&[seed; 32])
    }

    #[test]
    fn genesis_prefix_hash_is_sha256_of_empty() {
        assert_eq!(
            GENESIS_PREFIX_HASH,
            hex::encode(Sha256::digest(b"")),
            "genesis must be hex(sha256(empty))"
        );
    }

    #[test]
    fn spec_message_tags_are_snake_case_and_round_trip() {
        let commit = CommitPrefix {
            session_id: "s1".into(),
            round: 1,
            previous_prefix_hash: GENESIS_PREFIX_HASH.into(),
            accepted_token_ids: vec![1, 2],
            new_prefix_hash: compute_prefix_hash(GENESIS_PREFIX_HASH, &[1, 2]).unwrap(),
            model_profile_id: "msp1:aa".into(),
            generation_params_hash: default_sampling_params_hash(),
            sender: "peer-a".into(),
        };
        let wire = SpecMessage::signed_commit(&commit, &identity(1)).unwrap();
        let value = serde_json::to_value(&wire).unwrap();
        assert_eq!(
            value,
            json!({
                "prefix_commit": {
                    "session_id": "s1",
                    "round": 1,
                    "previous_prefix_hash": GENESIS_PREFIX_HASH,
                    "accepted_token_ids": [1, 2],
                    "new_prefix_hash": commit.new_prefix_hash,
                    "profile_id": "msp1:aa",
                    "generation_params_hash": default_sampling_params_hash(),
                    "sender": "peer-a",
                    "signature": value["prefix_commit"]["signature"].clone(),
                }
            })
        );
        let back: SpecMessage = serde_json::from_value(value).unwrap();
        assert_eq!(back, wire);
        assert_eq!(back.commit_prefix().unwrap(), commit);
    }

    #[test]
    fn commit_signature_binds_sender_and_fails_on_wrong_key() {
        let signer = identity(2);
        let stranger = identity(3);
        let commit = CommitPrefix {
            session_id: "s".into(),
            round: 1,
            previous_prefix_hash: GENESIS_PREFIX_HASH.into(),
            accepted_token_ids: vec![5],
            new_prefix_hash: compute_prefix_hash(GENESIS_PREFIX_HASH, &[5]).unwrap(),
            model_profile_id: "p".into(),
            generation_params_hash: "g".into(),
            sender: signer.installation_id(),
        };
        let wire = SpecMessage::signed_commit(&commit, &signer).unwrap();
        assert!(verify_commit_signature(&wire, &signer.verifying_key()).is_ok());
        // The wrong expected key fails the sender binding first.
        let err = verify_commit_signature(&wire, &stranger.verifying_key()).unwrap_err();
        assert!(
            err.to_string()
                .contains("sender is not the authenticated session key"),
            "wrong key must fail the binding: {err}"
        );
        // Tampering any signed field breaks the signature itself.
        let mut tampered = wire.clone();
        if let SpecMessage::PrefixCommit {
            accepted_token_ids, ..
        } = &mut tampered
        {
            accepted_token_ids.push(6);
        }
        let err = verify_commit_signature(&tampered, &signer.verifying_key()).unwrap_err();
        assert!(
            err.to_string().contains("bad_signature"),
            "tampered commit must fail verification: {err}"
        );
    }

    #[test]
    fn receipt_and_ack_signatures_round_trip() {
        let server = identity(4);
        let requester = identity(5);
        let stranger = identity(6);
        let receipt = sign_receipt("s", 3, 12, &server).unwrap();
        assert!(verify_receipt_signature(&receipt, &server.verifying_key()).is_ok());
        assert!(verify_receipt_signature(&receipt, &stranger.verifying_key()).is_err());

        let ack = sign_receipt_ack(&receipt, &requester).unwrap();
        assert!(verify_receipt_ack(&receipt, &ack, &requester.verifying_key()).is_ok());
        // An ack over a different receipt must NOT verify (binding digest).
        let other = sign_receipt("s", 3, 13, &server).unwrap();
        assert!(verify_receipt_ack(&other, &ack, &requester.verifying_key()).is_err());
        let stranger_ack = sign_receipt_ack(&receipt, &stranger).unwrap();
        let err =
            verify_receipt_ack(&receipt, &stranger_ack, &requester.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("receipt_mismatch"));
    }

    #[test]
    fn default_sampling_params_hash_is_stable() {
        assert_eq!(
            default_sampling_params_hash(),
            default_sampling_params_hash()
        );
        assert_eq!(default_sampling_params_hash().len(), 64);
    }

    // -----------------------------------------------------------------------
    // Phase E unit tests (E1/E4)
    // -----------------------------------------------------------------------

    /// E4: batch/tree selection equals per-branch sequential verification
    /// taking the max — the two verifier paths (tree-attention runtime vs
    /// sequential fallback) commit identical prefixes.
    #[test]
    fn tree_verify_equals_max_per_branch_linear_verify() {
        let mut cases_with_full_match = 0usize;
        for case in 0..200u64 {
            let mut rng = modelswarm_speculation::SplitMix64::new(0xE4E4_0000 + case);
            let branch_count = 1 + (rng.next_u64() % 6) as usize;
            let depth = 1 + (rng.next_u64() % 6) as usize;
            // Branches drawn from a small token alphabet so shared prefixes
            // (and exact duplicates, E3) occur frequently.
            let blocks: Vec<BranchBlock> = (0..branch_count)
                .map(|proposer| {
                    let tokens: Vec<u32> =
                        (0..depth).map(|_| (rng.next_u64() % 4) as u32).collect();
                    BranchBlock {
                        proposer,
                        tokens,
                        score: (rng.next_u64() % 7) as f32,
                    }
                })
                .collect();
            // Target continuation: deepest branch + lookahead, padded so the
            // pruning pass below (which can leave branches of up to
            // `max_nodes` tokens) is also covered.
            let max_depth = blocks.iter().map(|b| b.tokens.len()).max().unwrap_or(0);
            let target: Vec<u32> = (0..max_depth + 7)
                .map(|_| (rng.next_u64() % 4) as u32)
                .collect();
            // No-prune limits: the pure selection-rule comparison...
            let trie = CandidateTrie::assemble(
                blocks,
                TrieLimits {
                    max_branches: branch_count.max(1),
                    max_nodes: 4096,
                },
            );
            assert_tree_equals_linear(&trie, &target);
            // ...and the same assertion after a real pruning pass (E2):
            // tight bounds truncate tails, and whatever survives must still
            // verify identically both ways.
            let pruned_trie = CandidateTrie::assemble(
                trie.branches().to_vec(),
                TrieLimits {
                    max_branches: 2,
                    max_nodes: 5,
                },
            );
            assert_tree_equals_linear(&pruned_trie, &target);
            if trie
                .branches()
                .iter()
                .any(|b| b.tokens.iter().zip(&target).all(|(a, t)| a == t))
            {
                cases_with_full_match += 1;
            }
        }
        assert!(
            cases_with_full_match > 0,
            "the sweep should exercise full-acceptance rounds too"
        );
    }

    /// The empty trie (every proposer straggled) still commits exactly the
    /// lookahead bonus token — the E5 no-stall progress guarantee.
    #[test]
    fn empty_trie_commits_the_bonus_token() {
        let trie = CandidateTrie::assemble(Vec::new(), TrieLimits::default());
        let target = vec![7u32, 9, 11];
        let outcome = verify_tree_greedy(&trie, &target);
        assert_eq!(outcome.committed, vec![7]);
        assert_eq!(outcome.winning_branch, None);
        assert_eq!(outcome.accepted_depth, 0);
    }

    /// E1: branch assignments are reproducible, distinct per proposer, and
    /// vary with (session, round, roster) — the coordinator's seed schedule.
    #[test]
    fn branch_assignments_are_deterministic_and_distinct() {
        let roster = 7usize;
        for round in 1..50u64 {
            let mut seeds = Vec::with_capacity(roster);
            for index in 0..roster {
                let seed = branch_assignment("sess-e1", round, roster, index);
                assert_eq!(seed, branch_assignment("sess-e1", round, roster, index));
                seeds.push(seed);
            }
            let mut sorted = seeds.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), roster, "seeds must be pairwise distinct");
            // Different round ⇒ different assignment vector (with overwhelming
            // probability across the sweep).
            if round > 1 {
                let prev: Vec<u64> = (0..roster)
                    .map(|index| branch_assignment("sess-e1", round - 1, roster, index))
                    .collect();
                assert_ne!(prev, seeds, "assignment must depend on the round");
            }
        }
        assert_ne!(
            branch_assignment("a", 1, 4, 0),
            branch_assignment("b", 1, 4, 0),
            "assignment must depend on the session id"
        );
        assert_ne!(
            branch_assignment("a", 1, 4, 0),
            branch_assignment("a", 1, 5, 0),
            "assignment must depend on the roster length"
        );
    }

    /// Helper for the E4 comparison: `verify_tree_greedy` on the assembled
    /// trie vs the per-branch sequential `verify_greedy` rule taking the
    /// longest committed run (ties commit identical tokens: the committed
    /// stream is always `target[..d] ++ [target[d]]`).
    fn assert_tree_equals_linear(trie: &CandidateTrie, target: &[u32]) {
        let tree = verify_tree_greedy(trie, target);
        let mut best_linear: Vec<u32> = Vec::new();
        let mut best_accepted = 0usize;
        for block in trie.branches() {
            let window = &target[..block.tokens.len() + 1];
            let linear = verify_greedy(&block.tokens, window);
            if linear.committed.len() > best_linear.len() {
                best_linear = linear.committed;
                best_accepted = linear.accepted_draft;
            }
        }
        assert_eq!(
            tree.committed,
            best_linear,
            "tree vs linear committed mismatch (branches: {:?}, target: {target:?})",
            trie.branches()
                .iter()
                .map(|b| &b.tokens)
                .collect::<Vec<_>>()
        );
        assert_eq!(tree.accepted_depth, best_accepted);
        if best_linear.is_empty() {
            // No branch at all: the bonus token is the whole round.
            assert_eq!(tree.committed, vec![target[0]]);
        }
    }
}
