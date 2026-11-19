//! Multi-proposer candidate trie (Phase E, ADR-013 `speculative_exact`).
//!
//! Pure algorithms only — no transport, no runtime. Proposers produce
//! branch token sequences; the coordinator assembles them into a bounded
//! trie sharing the committed prefix, deduplicates identical prefixes, and
//! the verifier selects the branch that matches the target continuation
//! deepest. Greedy tree verification is token-exact by the same argument
//! as the linear rule: the committed stream equals the target's plain
//! greedy continuation regardless of branch contents (property-tested).

use crate::rng::SplitMix64;

/// Deterministic branch assignment: proposer `index` of `roster_len`, for
/// (`session_id`, `round`), gets a reproducible seed/branch id. Same inputs
/// → same assignment (E1). Distinct proposers get distinct seeds.
pub fn branch_assignment(session_id: &str, round: u64, roster_len: usize, index: usize) -> u64 {
    assert!(index < roster_len, "proposer index outside roster");
    let mut h = SplitMix64::new(0xE0EE_0000_0000_0001);
    for b in session_id.as_bytes() {
        h.mix(*b as u64);
    }
    h.mix(round);
    h.mix(roster_len as u64);
    // Decorrelate per-proposer streams; XOR-fold so order permutations of
    // (round, roster) don't collide across proposers.
    let mut out = h.next_u64();
    out ^= (index as u64)
        .rotate_left(29)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    out ^ (out >> 31)
}

/// One proposer's arrived block (stragglers simply never appear in the
/// assembly input).
#[derive(Debug, Clone, PartialEq)]
pub struct BranchBlock {
    pub proposer: usize,
    pub tokens: Vec<u32>,
    /// Coordinator-assigned score used for bound-driven pruning (higher is
    /// kept longer). Callers derive it from prior acceptance history.
    pub score: f32,
}

/// A trie node (compressed: children keyed by next token).
#[derive(Debug, Default, PartialEq)]
pub struct CandidateTrie {
    /// All inserted branches (deduplicated by exact token-sequence
    /// equality), deepest-first order preserved as inserted.
    branches: Vec<BranchBlock>,
    total_nodes: usize,
    duplicate_work: usize,
    pruned: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrieLimits {
    pub max_branches: usize,
    pub max_nodes: usize,
}

impl Default for TrieLimits {
    fn default() -> Self {
        Self {
            max_branches: 8,
            max_nodes: 128,
        }
    }
}

impl CandidateTrie {
    /// Assembles arrived blocks into the bounded trie (E2/E3): duplicates
    /// (exact token-sequence equality) are dropped and counted; if the
    /// branch bound is exceeded, lowest-score branches are pruned; if the
    /// node bound is exceeded, longest tails are truncated from the
    /// lowest-score branches first, then those branches re-checked.
    pub fn assemble(blocks: Vec<BranchBlock>, limits: TrieLimits) -> Self {
        let mut trie = CandidateTrie::default();
        let mut seen: Vec<Vec<u32>> = Vec::new();
        for b in blocks {
            if seen.contains(&b.tokens) {
                trie.duplicate_work += b.tokens.len();
                continue;
            }
            seen.push(b.tokens.clone());
            trie.total_nodes += b.tokens.len();
            trie.branches.push(b);
        }
        // Branch bound: keep highest score; deterministic tie-break by
        // proposer id then token sequence (stable sort keeps insertion
        // order among equals).
        if trie.branches.len() > limits.max_branches {
            let mut keep = trie.branches.clone();
            keep.sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.proposer.cmp(&b.proposer))
            });
            keep.truncate(limits.max_branches);
            keep.sort_by_key(|b| b.proposer);
            trie.pruned += trie.branches.len() - keep.len();
            trie.branches = keep;
            trie.total_nodes = trie.branches.iter().map(|b| b.tokens.len()).sum();
        }
        // Node bound: truncate tails of lowest-score branches first until
        // within budget (a branch reduced to 0 tokens is dropped).
        if trie.total_nodes > limits.max_nodes {
            let mut order: Vec<usize> = (0..trie.branches.len()).collect();
            order.sort_by(|&i, &j| {
                trie.branches[i]
                    .score
                    .partial_cmp(&trie.branches[j].score)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| trie.branches[j].proposer.cmp(&trie.branches[i].proposer))
            });
            let over = trie.total_nodes - limits.max_nodes;
            let mut to_cut = over;
            for &i in &order {
                if to_cut == 0 {
                    break;
                }
                let len = trie.branches[i].tokens.len();
                let cut = len.min(to_cut);
                trie.branches[i].tokens.truncate(len - cut);
                to_cut -= cut;
            }
            let before = trie.branches.len();
            trie.branches.retain(|b| !b.tokens.is_empty());
            trie.pruned += before - trie.branches.len();
            trie.total_nodes = trie.branches.iter().map(|b| b.tokens.len()).sum();
        }
        trie
    }

    pub fn branches(&self) -> &[BranchBlock] {
        &self.branches
    }

    pub fn total_nodes(&self) -> usize {
        self.total_nodes
    }

    pub fn duplicate_work(&self) -> usize {
        self.duplicate_work
    }

    pub fn pruned(&self) -> usize {
        self.pruned
    }
}

/// Greedy tree verification (E4/E7): `target_argmax` is the target's greedy
/// continuation for window `max_depth + 1` (deepest branch + lookahead).
/// Selects the branch with the longest matching prefix against the target;
/// committed = matched tokens + correction/bonus token from the target.
/// Token-exact vs plain greedy decoding for ANY branch set.
#[derive(Debug, Clone, PartialEq)]
pub struct TreeOutcome {
    pub committed: Vec<u32>,
    pub winning_branch: Option<usize>,
    pub accepted_depth: usize,
    /// Per-branch matched depth (diversity/cost telemetry).
    pub matched_depths: Vec<(usize, usize)>,
}

pub fn verify_tree_greedy(trie: &CandidateTrie, target_argmax: &[u32]) -> TreeOutcome {
    let max_depth = trie
        .branches()
        .iter()
        .map(|b| b.tokens.len())
        .max()
        .unwrap_or(0);
    assert!(
        target_argmax.len() > max_depth,
        "target_argmax must cover deepest branch + lookahead"
    );
    let mut best: Option<(usize, usize)> = None; // (branch idx, matched depth)
    let mut matched = Vec::with_capacity(trie.branches().len());
    for (i, b) in trie.branches().iter().enumerate() {
        let mut d = 0usize;
        while d < b.tokens.len() && b.tokens[d] == target_argmax[d] {
            d += 1;
        }
        matched.push((i, d));
        match best {
            Some((_, bd)) if bd >= d => {}
            _ => best = Some((i, d)),
        }
    }
    let (idx, depth) = best.unwrap_or((usize::MAX, 0));
    let mut committed = if idx == usize::MAX {
        Vec::new()
    } else {
        trie.branches()[idx].tokens[..depth].to_vec()
    };
    committed.push(target_argmax[depth]); // correction or bonus
    TreeOutcome {
        committed,
        winning_branch: if idx == usize::MAX { None } else { Some(idx) },
        accepted_depth: depth,
        matched_depths: matched,
    }
}

/// Whole-generation greedy tree simulation (multi-proposer analogue of
/// `simulate_greedy`): the draft policy produces ALL branch blocks per
/// round (some proposers may be missing — straggler drop — by simply not
/// including a block). Output must equal plain greedy decoding (E7).
pub fn simulate_tree_greedy(
    target_argmax: &dyn Fn(&[u32]) -> u32,
    prompt: &[u32],
    blocks_policy: &dyn Fn(&[u32]) -> Vec<BranchBlock>,
    max_tokens: usize,
    limits: TrieLimits,
) -> Vec<u32> {
    let mut prefix = prompt.to_vec();
    let mut produced = Vec::new();
    while produced.len() < max_tokens {
        let blocks = blocks_policy(&prefix);
        let max_depth = blocks.iter().map(|b| b.tokens.len()).max().unwrap_or(0);
        let mut window: Vec<u32> = Vec::with_capacity(max_depth + 1);
        let mut p = prefix.clone();
        for _ in 0..=max_depth {
            let t = target_argmax(&p);
            window.push(t);
            p.push(t);
        }
        let trie = CandidateTrie::assemble(blocks, limits);
        let out = verify_tree_greedy(&trie, &window);
        for t in &out.committed {
            prefix.push(*t);
            produced.push(*t);
        }
    }
    produced.truncate(max_tokens);
    produced
}
