//! Exact speculative-decoding algorithms (Phases D–E, ADR-013).
//!
//! Phase D core (this crate, pure functions): the lossless greedy
//! acceptance rule, the sampled rejection-sampling rule with correction
//! (`acceptance`), acceptance telemetry in vLLM's convention (`metrics`),
//! and a deterministic seeded RNG for reproducible tests (`rng`).
//!
//! Correctness contracts under test:
//! - greedy speculative output is token-identical to plain greedy decoding
//!   for ANY draft policy (including adversarial garbage — the verifier
//!   consults only target outputs);
//! - sampled full-q output distribution equals the target distribution
//!   exactly (rejection-sampling theorem);
//! - partial-q mode is a documented approximation, not the contract.
//!
//! Later phases: candidate tries / branch assignment / batch verification
//! (Phase E), and runtime adapters supplying real logits (Phase D entry
//! ADR per ADR-019).
//!
//! Approximate/semantic acceptance is out of scope by ADR-013.

pub mod acceptance;
pub mod metrics;
pub mod rng;
pub mod trie;

pub use acceptance::{
    sample_from, simulate_greedy, verify_greedy, verify_sampled, verify_sampled_full_q,
    verify_sampled_with_bonus, DraftStep, GreedyOutcome, SampledOutcome,
};
// re-exported for tests that draw honest drafts from q
pub use metrics::AcceptanceStats;
pub use rng::SplitMix64;
pub use trie::{
    branch_assignment, simulate_tree_greedy, verify_tree_greedy, BranchBlock, CandidateTrie,
    TreeOutcome, TrieLimits,
};
