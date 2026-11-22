//! Property tests for the commit gate (ADR-015 Phase B exit gate):
//! duplicated, reordered, stale, cross-profile and hash-inconsistent commits
//! can never advance session state.

use modelswarm_session::{
    compute_prefix_hash, ApplyOutcome, CommitPrefix, RejectReason, SessionStateMachine,
};
use proptest::prelude::*;

/// Fixed 64-hex genesis prefix for tests (SHA-256 of "property-test genesis").
const GENESIS: &str = "e750bb7c423fd0b74d0bcf2e796988b4c2218f74a7e0d59d033845950990efb6";

fn new_machine() -> SessionStateMachine {
    SessionStateMachine::new("sess", "msp1:profile-a", "params-hash-a", GENESIS).unwrap()
}

fn build_chain(rounds: &[Vec<u32>]) -> Vec<CommitPrefix> {
    let mut prev = GENESIS.to_string();
    let mut commits = Vec::with_capacity(rounds.len());
    for (i, tokens) in rounds.iter().enumerate() {
        let new = compute_prefix_hash(&prev, tokens).unwrap();
        commits.push(CommitPrefix {
            session_id: "sess".to_string(),
            round: (i + 1) as u64,
            previous_prefix_hash: prev.clone(),
            accepted_token_ids: tokens.clone(),
            new_prefix_hash: new.clone(),
            model_profile_id: "msp1:profile-a".to_string(),
            generation_params_hash: "params-hash-a".to_string(),
            sender: format!("peer-{}", i % 3),
        });
        prev = new;
    }
    commits
}

fn token_rounds() -> impl Strategy<Value = Vec<Vec<u32>>> {
    // Random valid commit chains of length 1..=50, each commit carrying
    // 0..=4 token ids.
    proptest::collection::vec(proptest::collection::vec(any::<u32>(), 0..5), 1..=50)
}

proptest! {
    /// (a) Replaying any prefix of a valid chain advances exactly those
    /// rounds, leaving the committed hash equal to that prefix's hash.
    #[test]
    fn prefix_replay_advances_exactly_k_rounds(rounds in token_rounds()) {
        let chain = build_chain(&rounds);
        for k in 0..=chain.len() {
            let mut sm = new_machine();
            for commit in &chain[..k] {
                prop_assert_eq!(sm.apply(commit), ApplyOutcome::Advanced);
            }
            prop_assert_eq!(sm.round(), k as u64);
            prop_assert_eq!(
                sm.committed_prefix_hash(),
                if k == 0 { GENESIS.to_string() } else { chain[k - 1].new_prefix_hash.clone() }
            );
        }
    }

    /// (b) Cloning commits (duplicates) never advances twice: interleaving a
    /// replay of every applied commit after a full run changes nothing.
    #[test]
    fn duplicates_never_advance_twice(rounds in token_rounds()) {
        let chain = build_chain(&rounds);
        let mut sm = new_machine();
        for commit in &chain {
            prop_assert_eq!(sm.apply(commit), ApplyOutcome::Advanced);
            // Immediate duplicate of the just-applied commit.
            prop_assert_eq!(sm.apply(commit), ApplyOutcome::Duplicate);
        }
        // And a full second pass of the whole chain: all duplicates.
        for commit in &chain {
            prop_assert_eq!(sm.apply(commit), ApplyOutcome::Duplicate);
        }
        prop_assert_eq!(sm.round(), chain.len() as u64);

        // Out-of-order duplicates still never advance.
        let mut shuffled = chain.clone();
        shuffled.reverse();
        for commit in &shuffled {
            prop_assert_eq!(sm.apply(commit), ApplyOutcome::Duplicate);
        }
        prop_assert_eq!(sm.round(), chain.len() as u64);
    }

    /// (c) Swapping two commits' rounds: both swapped commits are rejected
    /// in either presentation order, and state stays where the honest chain
    /// left it. Strict sequencing cannot be bypassed by round relabeling.
    #[test]
    fn swapped_rounds_are_rejected(rounds in token_rounds(), swap in any::<(usize, usize)>()) {
        let chain = build_chain(&rounds);
        let n = chain.len();
        let i = swap.0 % n;
        let j = swap.1 % n;
        prop_assume!(i != j);
        let (lo, _hi) = if i < j { (i, j) } else { (j, i) };

        let mut ci = chain[i].clone();
        ci.round = chain[j].round;
        let mut cj = chain[j].clone();
        cj.round = chain[i].round;

        // From the state just before the earlier commit.
        let mut sm = new_machine();
        for commit in &chain[..lo] {
            prop_assert_eq!(sm.apply(commit), ApplyOutcome::Advanced);
        }
        let baseline_round = sm.round();
        let baseline_hash = sm.committed_prefix_hash().to_string();

        for presentation in [[&ci, &cj], [&cj, &ci]] {
            for commit in presentation {
                let outcome = sm.apply(commit);
                prop_assert_ne!(outcome, ApplyOutcome::Advanced);
                prop_assert_ne!(outcome, ApplyOutcome::Duplicate);
            }
            prop_assert_eq!(sm.round(), baseline_round);
            prop_assert_eq!(sm.committed_prefix_hash(), baseline_hash.as_str());
        }

        // The honest chain still applies cleanly afterwards.
        for commit in &chain[lo..] {
            prop_assert_eq!(sm.apply(commit), ApplyOutcome::Advanced);
        }
        prop_assert_eq!(sm.round(), n as u64);
    }

    /// (d) Mutating profile or params yields exactly CrossProfile /
    /// CrossParams and never advances.
    #[test]
    fn cross_profile_and_params_rejected(
        rounds in token_rounds(),
        which in any::<usize>(),
    ) {
        let chain = build_chain(&rounds);
        let idx = which % chain.len();
        let mut sm = new_machine();
        for commit in &chain[..idx] {
            prop_assert_eq!(sm.apply(commit), ApplyOutcome::Advanced);
        }
        let baseline_round = sm.round();
        let baseline_hash = sm.committed_prefix_hash().to_string();

        let mut cross_profile = chain[idx].clone();
        cross_profile.model_profile_id = "msp1:profile-b".to_string();
        prop_assert_eq!(
            sm.apply(&cross_profile),
            ApplyOutcome::Rejected(RejectReason::CrossProfile)
        );

        let mut cross_params = chain[idx].clone();
        cross_params.generation_params_hash = "params-hash-b".to_string();
        prop_assert_eq!(
            sm.apply(&cross_params),
            ApplyOutcome::Rejected(RejectReason::CrossParams)
        );

        let mut wrong_session = chain[idx].clone();
        wrong_session.session_id = "other-session".to_string();
        prop_assert_eq!(
            sm.apply(&wrong_session),
            ApplyOutcome::Rejected(RejectReason::WrongSession)
        );

        prop_assert_eq!(sm.round(), baseline_round);
        prop_assert_eq!(sm.committed_prefix_hash(), baseline_hash);

        // The untampered commit still applies.
        prop_assert_eq!(sm.apply(&chain[idx]), ApplyOutcome::Advanced);
    }

    /// (e) Mutating a token id without fixing the hash yields HashMismatch
    /// and never advances.
    #[test]
    fn mutated_token_is_hash_mismatch(
        rounds in token_rounds(),
        which in any::<usize>(),
        token_index in any::<Option<usize>>(),
    ) {
        let chain = build_chain(&rounds);
        let idx = which % chain.len();
        let mut sm = new_machine();
        for commit in &chain[..idx] {
            prop_assert_eq!(sm.apply(commit), ApplyOutcome::Advanced);
        }
        let baseline_round = sm.round();
        let baseline_hash = sm.committed_prefix_hash().to_string();

        let mut tampered = chain[idx].clone();
        let tokens = &mut tampered.accepted_token_ids;
        prop_assume!(!tokens.is_empty());
        let t = token_index.unwrap_or(0) % tokens.len();
        tokens[t] = tokens[t].wrapping_add(1);

        prop_assert_eq!(
            sm.apply(&tampered),
            ApplyOutcome::Rejected(RejectReason::HashMismatch)
        );
        prop_assert_eq!(sm.round(), baseline_round);
        prop_assert_eq!(sm.committed_prefix_hash(), baseline_hash);

        // Original still applies.
        prop_assert_eq!(sm.apply(&chain[idx]), ApplyOutcome::Advanced);
    }
}
