//! Cooperative session state machine (Phase D, `/msp/cooperative/1.0.0`):
//! round sequencing and prefix-hash-linked commits.
//!
//! One `SessionStateMachine` tracks a single cooperative session for one
//! exact model profile and one exact generation-parameters hash. Peers send
//! [`CommitPrefix`] messages; the machine only advances on the strictly next
//! round whose `previous_prefix_hash` chains onto the committed prefix and
//! whose `new_prefix_hash` is the correct SHA-256 over
//! `sha256(prev_hash_bytes || token_ids as little-endian u32)`.
//!
//! Guarantees (property-tested in `tests/`):
//!
//! - Duplicate commits never advance state twice (bounded round memory).
//! - Stale, future, reordered, cross-session, cross-profile, cross-params
//!   and hash-inconsistent commits are rejected without state change.
//!
//! Session open/close, rollback beyond the last committed prefix, straggler
//! drops and peer replacement are Phase D concerns layered on top of this
//! machine; the commit gate itself is the Phase B deliverable (ADR-015).
//!
//! Phase D layers those concerns in [`spec`]: the exact speculative-decoding
//! protocol (verifier/proposer servers, coordinator, signed commits over the
//! ADR-018 staged transport, fallback, receipts).

pub mod negotiation;
pub mod spec;
pub mod verifydrafts;

pub use spec::{
    default_sampling_params_hash, serve_proposer_multi, sign_commit, sign_receipt,
    sign_receipt_ack, speculate, speculate_multi, verify_commit_signature, verify_receipt_ack,
    verify_receipt_signature, FallbackPolicy, FallbackReason, ProposerPeerReport, ProposerReport,
    ProposerRuntimeFactory, SpecError, SpecMessage, SpecMode, SpecOutcome, SpecPeer,
    SpeculativeExecutor, VerifierReport, ACCEPT_DEADLINE, DEFAULT_PROPOSAL_DEADLINE,
    GENESIS_PREFIX_HASH, MULTI_PROPOSERS_MAX, MULTI_PROPOSERS_MIN, ROUND_DEADLINE,
    RTT_SPIKE_STREAK, SERVER_IDLE, WINDOW_GROW_STREAK, WINDOW_MAX, WINDOW_SHRINK_STREAK,
};
use std::collections::{HashMap, VecDeque};

use sha2::{Digest, Sha256};

/// Maximum number of applied rounds remembered for duplicate detection.
/// Commits older than this fall out of memory and are rejected as stale
/// rather than recognized as duplicates.
pub const DUPLICATE_MEMORY_ROUNDS: usize = 1024;

/// Errors from constructing or feeding the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// The initial (genesis) prefix hash was not 64 lowercase hex characters.
    InvalidPrefixHash(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::InvalidPrefixHash(v) => {
                write!(f, "prefix hash must be 64 lowercase hex chars: {v:?}")
            }
        }
    }
}

impl std::error::Error for SessionError {}

/// Why a [`CommitPrefix`] was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectReason {
    /// Round is behind the committed round and not an exact remembered
    /// duplicate.
    StaleRound,
    /// Round is ahead of the committed round (gaps are forbidden).
    FutureRound,
    /// `previous_prefix_hash` does not chain onto the committed prefix.
    PrefixMismatch,
    /// Commit names a different model profile.
    CrossProfile,
    /// Commit names different generation parameters.
    CrossParams,
    /// Commit belongs to another session.
    WrongSession,
    /// `new_prefix_hash` does not equal the computed hash of
    /// `sha256(prev_hash_bytes || token ids)`.
    HashMismatch,
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            RejectReason::StaleRound => "stale_round",
            RejectReason::FutureRound => "future_round",
            RejectReason::PrefixMismatch => "prefix_mismatch",
            RejectReason::CrossProfile => "cross_profile",
            RejectReason::CrossParams => "cross_params",
            RejectReason::WrongSession => "wrong_session",
            RejectReason::HashMismatch => "hash_mismatch",
        };
        f.write_str(name)
    }
}

/// Result of applying a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplyOutcome {
    /// State advanced: round + 1, committed prefix replaced.
    Advanced,
    /// Exact duplicate of an already-applied commit; no state change.
    Duplicate,
    /// Rejected; no state change.
    Rejected(RejectReason),
}

/// A peer's proposal to extend the accepted prefix by `accepted_token_ids`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPrefix {
    /// Owning session id.
    pub session_id: String,
    /// 1-based commit sequence number; must be exactly current round + 1.
    pub round: u64,
    /// Hex SHA-256 of the prefix this commit chains onto.
    pub previous_prefix_hash: String,
    /// The tokens this commit appends to the accepted prefix.
    pub accepted_token_ids: Vec<u32>,
    /// Hex SHA-256 of the resulting prefix (see [`compute_prefix_hash`]).
    pub new_prefix_hash: String,
    /// Model profile the session is pinned to.
    pub model_profile_id: String,
    /// Generation-parameters hash the session is pinned to.
    pub generation_params_hash: String,
    /// Identifies the sending peer. Informational for the commit gate:
    /// peer replacement mid-session must not corrupt the accepted sequence,
    /// so the hash chain (not the sender) carries correctness.
    pub sender: String,
}

/// Computes the next prefix hash: `hex(sha256(prev_hash_bytes ||
/// accepted_token_ids as little-endian u32))`, where `prev_hash_bytes` are
/// the 32 raw bytes decoded from the previous hash's hex form.
///
/// The previous hash must be 64 lowercase hex characters (msp-v1 §1: all
/// digests are lowercase hex).
pub fn compute_prefix_hash(
    previous_prefix_hash_hex: &str,
    accepted_token_ids: &[u32],
) -> Result<String, SessionError> {
    let invalid = || SessionError::InvalidPrefixHash(previous_prefix_hash_hex.to_string());
    if previous_prefix_hash_hex.len() != 64
        || !previous_prefix_hash_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let mut bytes = hex::decode(previous_prefix_hash_hex).map_err(|_| invalid())?;
    for token in accepted_token_ids {
        bytes.extend_from_slice(&token.to_le_bytes());
    }
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// The per-session commit gate.
#[derive(Debug, Clone)]
pub struct SessionStateMachine {
    session_id: String,
    model_profile_id: String,
    generation_params_hash: String,
    committed_prefix_hash: String,
    round: u64,
    /// Bounded duplicate memory: applied round -> its `new_prefix_hash`.
    applied_hashes: HashMap<u64, String>,
    /// Insertion order of `applied_hashes` keys for FIFO eviction.
    applied_order: VecDeque<u64>,
}

impl SessionStateMachine {
    /// Creates the machine at round 0 with `initial_prefix_hash` (the genesis
    /// prefix, e.g. the hash of the shared prompt) committed.
    pub fn new(
        session_id: impl Into<String>,
        model_profile_id: impl Into<String>,
        generation_params_hash: impl Into<String>,
        initial_prefix_hash: impl Into<String>,
    ) -> Result<Self, SessionError> {
        let initial_prefix_hash = initial_prefix_hash.into();
        // Validate by decoding 32 bytes (rejects non-hex and wrong length).
        compute_prefix_hash(&initial_prefix_hash, &[])?;
        Ok(Self {
            session_id: session_id.into(),
            model_profile_id: model_profile_id.into(),
            generation_params_hash: generation_params_hash.into(),
            committed_prefix_hash: initial_prefix_hash,
            round: 0,
            applied_hashes: HashMap::new(),
            applied_order: VecDeque::new(),
        })
    }

    /// The session id.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The pinned model profile id.
    pub fn model_profile_id(&self) -> &str {
        &self.model_profile_id
    }

    /// The pinned generation-parameters hash.
    pub fn generation_params_hash(&self) -> &str {
        &self.generation_params_hash
    }

    /// Hex SHA-256 of the committed prefix.
    pub fn committed_prefix_hash(&self) -> &str {
        &self.committed_prefix_hash
    }

    /// The committed round (0 = genesis).
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Applies a commit under the frozen rules. Checks run in a fixed order:
    ///
    /// 1. `session_id`, `model_profile_id`, `generation_params_hash` must
    ///    match the session (`WrongSession` / `CrossProfile` / `CrossParams`).
    /// 2. `round` must be exactly `current + 1`; higher is `FutureRound`.
    /// 3. Lower rounds are exact-duplicate-checked against bounded memory
    ///    (`Duplicate` on match, `StaleRound` otherwise).
    /// 4. `previous_prefix_hash` must equal the committed hash
    ///    (`PrefixMismatch`).
    /// 5. `new_prefix_hash` must equal [`compute_prefix_hash`] over the
    ///    previous hash and the token ids (`HashMismatch`).
    ///
    /// Only then does state advance (`Advanced`).
    pub fn apply(&mut self, commit: &CommitPrefix) -> ApplyOutcome {
        if commit.session_id != self.session_id {
            return ApplyOutcome::Rejected(RejectReason::WrongSession);
        }
        if commit.model_profile_id != self.model_profile_id {
            return ApplyOutcome::Rejected(RejectReason::CrossProfile);
        }
        if commit.generation_params_hash != self.generation_params_hash {
            return ApplyOutcome::Rejected(RejectReason::CrossParams);
        }

        if commit.round == self.round.saturating_add(1) {
            if commit.previous_prefix_hash != self.committed_prefix_hash {
                return ApplyOutcome::Rejected(RejectReason::PrefixMismatch);
            }
            let expected = match compute_prefix_hash(
                &self.committed_prefix_hash,
                &commit.accepted_token_ids,
            ) {
                Ok(hash) => hash,
                Err(_) => {
                    // Unreachable: the committed hash is valid by invariant.
                    return ApplyOutcome::Rejected(RejectReason::HashMismatch);
                }
            };
            if commit.new_prefix_hash != expected {
                return ApplyOutcome::Rejected(RejectReason::HashMismatch);
            }
            self.round = commit.round;
            self.committed_prefix_hash = commit.new_prefix_hash.clone();
            self.remember(commit.round, commit.new_prefix_hash.clone());
            ApplyOutcome::Advanced
        } else if commit.round <= self.round {
            match self.applied_hashes.get(&commit.round) {
                Some(remembered) if *remembered == commit.new_prefix_hash => {
                    ApplyOutcome::Duplicate
                }
                _ => ApplyOutcome::Rejected(RejectReason::StaleRound),
            }
        } else {
            ApplyOutcome::Rejected(RejectReason::FutureRound)
        }
    }

    /// Records an applied round in the bounded duplicate memory, evicting
    /// the oldest entry (FIFO) past [`DUPLICATE_MEMORY_ROUNDS`].
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis() -> String {
        hex::encode(Sha256::digest(b"genesis prefix"))
    }

    fn machine() -> SessionStateMachine {
        SessionStateMachine::new("session-1", "msp1:aa", "params-1", genesis()).unwrap()
    }

    fn commit(tokens: &[u32]) -> CommitPrefix {
        let prev = genesis();
        CommitPrefix {
            session_id: "session-1".to_string(),
            round: 1,
            previous_prefix_hash: prev.clone(),
            accepted_token_ids: tokens.to_vec(),
            new_prefix_hash: compute_prefix_hash(&prev, tokens).unwrap(),
            model_profile_id: "msp1:aa".to_string(),
            generation_params_hash: "params-1".to_string(),
            sender: "peer-a".to_string(),
        }
    }

    fn build_chain(machine: &SessionStateMachine, rounds: &[Vec<u32>]) -> Vec<CommitPrefix> {
        let mut prev = machine.committed_prefix_hash().to_string();
        let mut commits = Vec::with_capacity(rounds.len());
        for (i, tokens) in rounds.iter().enumerate() {
            let new = compute_prefix_hash(&prev, tokens).unwrap();
            commits.push(CommitPrefix {
                session_id: machine.session_id().to_string(),
                round: (i + 1) as u64,
                previous_prefix_hash: prev.clone(),
                accepted_token_ids: tokens.clone(),
                new_prefix_hash: new.clone(),
                model_profile_id: machine.model_profile_id().to_string(),
                generation_params_hash: machine.generation_params_hash().to_string(),
                sender: "peer-a".to_string(),
            });
            prev = new;
        }
        commits
    }

    #[test]
    fn genesis_must_be_valid_hex_sha256() {
        assert!(SessionStateMachine::new("s", "p", "g", genesis()).is_ok());
        assert_eq!(
            SessionStateMachine::new("s", "p", "g", "not-hex").unwrap_err(),
            SessionError::InvalidPrefixHash("not-hex".to_string())
        );
        assert!(SessionStateMachine::new("s", "p", "g", "a".repeat(63)).is_err());
        assert!(SessionStateMachine::new("s", "p", "g", "A".repeat(64)).is_err());
        assert!(SessionStateMachine::new("s", "p", "g", "zz".repeat(32)).is_err());
    }

    #[test]
    fn valid_commit_advances() {
        let mut sm = machine();
        let c = commit(&[7, 8, 9]);
        assert_eq!(sm.round(), 0);
        assert_eq!(sm.apply(&c), ApplyOutcome::Advanced);
        assert_eq!(sm.round(), 1);
        assert_eq!(sm.committed_prefix_hash(), c.new_prefix_hash);
    }

    #[test]
    fn duplicate_never_advances_twice() {
        let mut sm = machine();
        let c = commit(&[1]);
        assert_eq!(sm.apply(&c), ApplyOutcome::Advanced);
        assert_eq!(sm.apply(&c), ApplyOutcome::Duplicate);
        assert_eq!(sm.apply(&c), ApplyOutcome::Duplicate);
        assert_eq!(sm.round(), 1);

        // Same round, different hash: stale, not duplicate.
        let mut other = c.clone();
        other.new_prefix_hash = hex::encode([9u8; 32]);
        assert_eq!(
            sm.apply(&other),
            ApplyOutcome::Rejected(RejectReason::StaleRound)
        );
    }

    #[test]
    fn future_and_stale_rounds_rejected() {
        let mut sm = machine();
        let chain = build_chain(&sm, &[vec![1], vec![2], vec![3]]);
        // Round 3 out of order.
        assert_eq!(
            sm.apply(&chain[2]),
            ApplyOutcome::Rejected(RejectReason::FutureRound)
        );
        assert_eq!(sm.apply(&chain[0]), ApplyOutcome::Advanced);
        // Skipping round 2.
        assert_eq!(
            sm.apply(&chain[2]),
            ApplyOutcome::Rejected(RejectReason::FutureRound)
        );
        assert_eq!(sm.apply(&chain[1]), ApplyOutcome::Advanced);
        assert_eq!(sm.apply(&chain[2]), ApplyOutcome::Advanced);
        assert_eq!(sm.round(), 3);
        // Now round 1 again is a remembered duplicate; round 0-style garbage
        // (a fabricated round value far behind with unknown hash) is stale.
        assert_eq!(sm.apply(&chain[0]), ApplyOutcome::Duplicate);
        let mut stale = chain[0].clone();
        stale.round = 0;
        assert_eq!(
            sm.apply(&stale),
            ApplyOutcome::Rejected(RejectReason::StaleRound)
        );
    }

    #[test]
    fn cross_session_profile_params_rejected() {
        let mut sm = machine();
        let c = commit(&[1]);
        let mut wrong_session = c.clone();
        wrong_session.session_id = "session-2".to_string();
        assert_eq!(
            sm.apply(&wrong_session),
            ApplyOutcome::Rejected(RejectReason::WrongSession)
        );
        let mut cross_profile = c.clone();
        cross_profile.model_profile_id = "msp1:bb".to_string();
        assert_eq!(
            sm.apply(&cross_profile),
            ApplyOutcome::Rejected(RejectReason::CrossProfile)
        );
        let mut cross_params = c.clone();
        cross_params.generation_params_hash = "params-2".to_string();
        assert_eq!(
            sm.apply(&cross_params),
            ApplyOutcome::Rejected(RejectReason::CrossParams)
        );
        assert_eq!(sm.round(), 0, "no rejection may change state");
    }

    #[test]
    fn prefix_and_hash_mismatch_rejected() {
        let mut sm = machine();
        let mut bad_prev = commit(&[1]);
        bad_prev.previous_prefix_hash = hex::encode([1u8; 32]);
        assert_eq!(
            sm.apply(&bad_prev),
            ApplyOutcome::Rejected(RejectReason::PrefixMismatch)
        );

        let mut bad_hash = commit(&[1, 2]);
        // Correct previous, but new hash computed for different tokens.
        bad_hash.new_prefix_hash = compute_prefix_hash(&genesis(), &[9]).unwrap();
        assert_eq!(
            sm.apply(&bad_hash),
            ApplyOutcome::Rejected(RejectReason::HashMismatch)
        );
        assert_eq!(sm.round(), 0);
    }

    #[test]
    fn sender_is_informational() {
        // Peer replacement mid-session must not corrupt the accepted
        // sequence: a commit from a different sender still advances when the
        // chain is correct.
        let mut sm = machine();
        let mut c = commit(&[5]);
        c.sender = "peer-b".to_string();
        assert_eq!(sm.apply(&c), ApplyOutcome::Advanced);
    }

    #[test]
    fn duplicate_memory_is_bounded_and_evicts_oldest() {
        let mut sm = machine();
        let rounds: Vec<Vec<u32>> = (0..=DUPLICATE_MEMORY_ROUNDS)
            .map(|i| vec![i as u32])
            .collect();
        let chain = build_chain(&sm, &rounds);
        for c in &chain {
            assert_eq!(sm.apply(c), ApplyOutcome::Advanced);
        }
        assert_eq!(sm.round() as usize, DUPLICATE_MEMORY_ROUNDS + 1);
        // Round 1 fell out of the bounded memory: stale, not duplicate.
        assert_eq!(
            sm.apply(&chain[0]),
            ApplyOutcome::Rejected(RejectReason::StaleRound)
        );
        // The most recent round is still remembered.
        let last = chain.last().unwrap();
        assert_eq!(sm.apply(last), ApplyOutcome::Duplicate);
    }

    #[test]
    fn empty_token_commit_is_a_valid_no_op_round() {
        // A commit with zero tokens still hashes the previous prefix and
        // advances the round (rounds carry meaning beyond token count).
        let mut sm = machine();
        let c = commit(&[]);
        assert_eq!(sm.apply(&c), ApplyOutcome::Advanced);
        assert_eq!(sm.committed_prefix_hash(), c.new_prefix_hash);
        // Hash of empty extension differs from the previous hash.
        assert_ne!(sm.committed_prefix_hash(), genesis());
    }
}
