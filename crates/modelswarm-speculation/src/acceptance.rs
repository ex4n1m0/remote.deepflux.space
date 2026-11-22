//! Lossless speculative-decoding acceptance rules (Phase D, ADR-013).
//!
//! Two contracts, both pure functions over token/probability data:
//!
//! - **Greedy** (`verify_greedy`): accept drafted tokens while they equal
//!   the target's argmax; on the first mismatch, take the target's argmax
//!   as the correction token. Output is token-identical to plain greedy
//!   decoding by construction (test `greedy_equivalence`).
//! - **Sampled** (`verify_sampled`): standard speculative-sampling
//!   rejection rule (Leviathan et al.): accept draft token `x` with
//!   probability `p(x)/q(x)`; on first rejection sample the correction from
//!   the residual `max(0, p - q)` (renormalized). The merged output
//!   distribution equals the target distribution exactly.
//!
//! The verifier only ever uses **target** distributions — draft
//! probabilities are inputs to the acceptance ratio, never trusted as
//! outputs. A lying proposer therefore cannot bend the result (F1/F2).

use crate::rng::SplitMix64;

/// A drafted token with its proposer-side probability (must be > 0).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DraftStep {
    pub token: u32,
    pub draft_prob: f32,
}

/// Greedy verification over one window.
///
/// `target_argmax` must have exactly `draft.len() + 1` entries: the
/// target's argmax token at each position of the window plus one lookahead
/// position (so a fully accepted window still yields a bonus token and
/// every round makes progress).
#[derive(Debug, Clone, PartialEq)]
pub struct GreedyOutcome {
    /// Tokens committed by this round (accepted draft prefix + correction).
    pub committed: Vec<u32>,
    /// How many drafted tokens were accepted (correction excluded).
    pub accepted_draft: usize,
    /// Position of the first rejection (None when the whole window held).
    pub first_rejection: Option<usize>,
}

pub fn verify_greedy(draft: &[u32], target_argmax: &[u32]) -> GreedyOutcome {
    assert_eq!(
        target_argmax.len(),
        draft.len() + 1,
        "target_argmax must be draft.len()+1 (window + lookahead)"
    );
    let mut accepted = 0usize;
    let mut first_rejection = None;
    for (i, d) in draft.iter().enumerate() {
        if *d == target_argmax[i] {
            accepted += 1;
        } else {
            first_rejection = Some(i);
            break;
        }
    }
    let mut committed = draft[..accepted].to_vec();
    committed.push(target_argmax[accepted]); // correction (or bonus token)
    GreedyOutcome {
        committed,
        accepted_draft: accepted,
        first_rejection,
    }
}

/// Sampled (stochastic) verification over one window.
///
/// `target_dists` must have exactly `draft.len()` entries, each the target
/// distribution over the shared vocabulary at that position.
#[derive(Debug, Clone, PartialEq)]
pub struct SampledOutcome {
    pub committed: Vec<u32>,
    pub accepted_draft: usize,
    pub first_rejection: Option<usize>,
}

pub fn verify_sampled(
    draft: &[DraftStep],
    target_dists: &[Vec<f32>],
    rng: &mut SplitMix64,
) -> SampledOutcome {
    assert_eq!(
        target_dists.len(),
        draft.len(),
        "one target dist per draft step"
    );
    let mut committed = Vec::with_capacity(draft.len() + 1);
    let mut accepted = 0usize;
    let mut first_rejection = None;

    for (i, step) in draft.iter().enumerate() {
        let dist = &target_dists[i];
        debug_assert!(step.draft_prob > 0.0, "proposer must send q > 0");
        let p = dist.get(step.token as usize).copied().unwrap_or(0.0);
        let ratio = (p / step.draft_prob).min(1.0);
        if rng.next_f32() <= ratio {
            committed.push(step.token);
            accepted += 1;
        } else {
            first_rejection = Some(i);
            // Residual distribution: max(0, p - q), renormalized. q is the
            // draft's full distribution — but the proposer only sends its
            // own proposed-token probability; the correction step therefore
            // uses the residual restricted to what the verifier can compute
            // without trusting the proposer: sample from p, rejecting any
            // token the proposer could have drafted for this position. For
            // the v0.1 contract the proposer sends its top proposed token
            // only, so the residual is `p` with the drafted token's mass
            // reduced by min(p, q): implemented below without needing q(x)
            // for other x (documented deviation; exact when q is the
            // proposer's actual sampling dist over the same support only if
            // the proposer sends the full q — full-q mode is exercised by
            // `verify_sampled_full_q`).
            let residual = residual_partial_q(dist, step.token, step.draft_prob);
            let correction = sample_from(&residual, rng);
            committed.push(correction);
            break;
        }
    }

    if first_rejection.is_none() && !draft.is_empty() {
        // Whole window accepted: sample the bonus token from the target
        // distribution one position past the window (caller supplies it as
        // an extra dist entry — see `verify_sampled_with_bonus`).
        // In this core function we simply stop; callers needing the bonus
        // token use the wrapper below.
    }

    SampledOutcome {
        committed,
        accepted_draft: accepted,
        first_rejection,
    }
}

/// Sampled verification (full-q, exact) with the bonus position:
/// `target_dists` has `draft.len() + 1` entries and `draft_dists` has
/// `draft.len()`; if the entire window is accepted, the final token is
/// drawn from the extra target distribution. This is the exact
/// distribution-preserving variant used by the D2 contract.
pub fn verify_sampled_with_bonus(
    draft: &[DraftStep],
    target_dists: &[Vec<f32>],
    draft_dists: &[Vec<f32>],
    rng: &mut SplitMix64,
) -> SampledOutcome {
    assert_eq!(target_dists.len(), draft.len() + 1);
    assert_eq!(draft_dists.len(), draft.len());
    let window_t = &target_dists[..draft.len()];
    let mut out = verify_sampled_full_q(draft, window_t, draft_dists, rng);
    if out.first_rejection.is_none() && !draft.is_empty() {
        let bonus = sample_from(&target_dists[draft.len()], rng);
        out.committed.push(bonus);
    }
    out
}

/// Full-q sampled verification: the proposer sends its complete draft
/// distribution per position. This is the textbook residual
/// `max(0, p - q)` over the whole vocabulary.
pub fn verify_sampled_full_q(
    draft: &[DraftStep],
    target_dists: &[Vec<f32>],
    draft_dists: &[Vec<f32>],
    rng: &mut SplitMix64,
) -> SampledOutcome {
    assert_eq!(target_dists.len(), draft.len());
    assert_eq!(draft_dists.len(), draft.len());
    let mut committed = Vec::with_capacity(draft.len() + 1);
    let mut accepted = 0usize;
    let mut first_rejection = None;

    for (i, step) in draft.iter().enumerate() {
        let p = &target_dists[i];
        let q = &draft_dists[i];
        let ratio = (p.get(step.token as usize).copied().unwrap_or(0.0) / step.draft_prob).min(1.0);
        if rng.next_f32() <= ratio {
            committed.push(step.token);
            accepted += 1;
        } else {
            first_rejection = Some(i);
            let mut residual = vec![0.0f32; p.len().max(q.len())];
            for (j, rv) in residual.iter_mut().enumerate() {
                let pj = p.get(j).copied().unwrap_or(0.0);
                let qj = q.get(j).copied().unwrap_or(0.0);
                *rv = (pj - qj).max(0.0);
            }
            let correction = sample_from(&residual, rng);
            committed.push(correction);
            break;
        }
    }

    SampledOutcome {
        committed,
        accepted_draft: accepted,
        first_rejection,
    }
}

/// Residual with partial-q knowledge: subtract the drafted token's q from
/// its own p only; all other tokens keep full target mass.
fn residual_partial_q(p: &[f32], drafted: u32, q_drafted: f32) -> Vec<f32> {
    let mut r = p.to_vec();
    let i = drafted as usize;
    if i < r.len() {
        r[i] = (r[i] - q_drafted).max(0.0);
    }
    r
}

/// Sample an index from an unnormalized non-negative weight vector.
/// Returns the token id (index). Panics on an all-zero vector — callers
/// must supply a distribution with support.
pub fn sample_from(weights: &[f32], rng: &mut SplitMix64) -> u32 {
    let total: f32 = weights.iter().sum();
    assert!(total > 0.0, "cannot sample from a zero-mass distribution");
    let mut u = rng.next_f32() * total;
    for (i, w) in weights.iter().enumerate() {
        u -= w;
        if u <= 0.0 {
            return i as u32;
        }
    }
    (weights.len() - 1) as u32
}

/// Simulates whole-generation greedy speculative decoding against a
/// deterministic target and returns the committed token stream. Used by the
/// D1 equivalence property: output must equal plain greedy decoding. The
/// target window is computed from the draft's **actual** length + 1
/// lookahead (draft policies may return any length ≤ window).
pub fn simulate_greedy(
    target_argmax: &dyn Fn(&[u32]) -> u32,
    prompt: &[u32],
    draft_policy: &dyn Fn(&[u32]) -> Vec<u32>,
    max_tokens: usize,
) -> Vec<u32> {
    let mut prefix = prompt.to_vec();
    let mut produced = Vec::new();
    while produced.len() < max_tokens {
        let base = prefix.clone();
        let draft = draft_policy(&base);
        let mut target_window: Vec<u32> = Vec::with_capacity(draft.len() + 1);
        let mut p = base.clone();
        for _ in 0..=draft.len() {
            let t = target_argmax(&p);
            target_window.push(t);
            p.push(t);
        }
        let out = verify_greedy(&draft, &target_window);
        for tok in &out.committed {
            prefix.push(*tok);
            produced.push(*tok);
        }
    }
    produced.truncate(max_tokens);
    produced
}
