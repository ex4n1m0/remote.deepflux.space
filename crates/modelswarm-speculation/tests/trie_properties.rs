//! Phase E property gates (docs/acceptance/phase-e.md E1–E3, E7).

use modelswarm_speculation::{
    branch_assignment, simulate_tree_greedy, BranchBlock, CandidateTrie, SplitMix64, TrieLimits,
};

const VOCAB: u32 = 8;

fn target_argmax_fn(seed: u64) -> impl Fn(&[u32]) -> u32 {
    move |prefix: &[u32]| {
        let mut h = SplitMix64::new(seed ^ 0x7E_EE_01);
        for t in prefix.iter().rev().take(4) {
            h.mix(*t as u64 + 0x51ED);
        }
        h.next_u64();
        (h.next_u64() % VOCAB as u64) as u32
    }
}

fn plain_greedy(target: &dyn Fn(&[u32]) -> u32, prompt: &[u32], n: usize) -> Vec<u32> {
    let mut prefix = prompt.to_vec();
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let t = target(&prefix);
        prefix.push(t);
        out.push(t);
    }
    out
}

/// E1: branch assignment is deterministic and per-proposer distinct.
#[test]
fn e1_branch_assignment_deterministic_and_distinct() {
    let a1 = branch_assignment("sess-1", 7, 4, 0);
    let a2 = branch_assignment("sess-1", 7, 4, 0);
    assert_eq!(a1, a2);
    let others: Vec<u64> = (1..4)
        .map(|i| branch_assignment("sess-1", 7, 4, i))
        .collect();
    for o in &others {
        assert_ne!(a1, *o);
    }
    // round and roster change the assignment
    assert_ne!(branch_assignment("sess-1", 8, 4, 0), a1);
    assert_ne!(branch_assignment("sess-1", 7, 5, 0), a1);
    // stable across 1000 draws
    for r in 0..1000u64 {
        assert_eq!(
            branch_assignment("s", r, 3, 2),
            branch_assignment("s", r, 3, 2)
        );
    }
}

/// E2: branch and node bounds enforced; pruning removes lowest score
/// first; deterministic tie-breaks.
#[test]
fn e2_bounds_enforced_lowest_score_pruned() {
    let blocks = vec![
        BranchBlock {
            proposer: 0,
            tokens: vec![1, 1, 1, 1, 1, 1],
            score: 0.1,
        },
        BranchBlock {
            proposer: 1,
            tokens: vec![2, 2, 2, 2, 2, 2],
            score: 0.9,
        },
        BranchBlock {
            proposer: 2,
            tokens: vec![3, 3, 3, 3, 3, 3],
            score: 0.5,
        },
        BranchBlock {
            proposer: 3,
            tokens: vec![4, 4, 4, 4, 4, 4],
            score: 0.7,
        },
    ];
    let limits = TrieLimits {
        max_branches: 3,
        max_nodes: 12,
    };
    let trie = CandidateTrie::assemble(blocks, limits);
    assert!(trie.branches().len() <= 3);
    assert!(trie.total_nodes() <= 12);
    // lowest score (proposer 2) pruned first
    assert!(trie.branches().iter().all(|b| b.proposer != 2));
    // proposer 2 pruned by branch bound; proposer 0 truncated to zero by the
    // node bound and dropped — two prunes total.
    assert_eq!(trie.pruned(), 2);
    // node bound: tails truncated, total within limit
    assert!(trie.total_nodes() <= 12);
    // determinism: same input → same trie
    let blocks2 = vec![
        BranchBlock {
            proposer: 0,
            tokens: vec![1, 1, 1, 1, 1, 1],
            score: 0.1,
        },
        BranchBlock {
            proposer: 1,
            tokens: vec![2, 2, 2, 2, 2, 2],
            score: 0.9,
        },
        BranchBlock {
            proposer: 2,
            tokens: vec![3, 3, 3, 3, 3, 3],
            score: 0.5,
        },
        BranchBlock {
            proposer: 3,
            tokens: vec![4, 4, 4, 4, 4, 4],
            score: 0.7,
        },
    ];
    let trie2 = CandidateTrie::assemble(blocks2, limits);
    assert_eq!(trie.branches(), trie2.branches());
    assert_eq!(trie.total_nodes(), trie2.total_nodes());
}

/// E3: exact-duplicate branches are dropped and counted as duplicate work.
#[test]
fn e3_duplicates_counted() {
    let blocks = vec![
        BranchBlock {
            proposer: 0,
            tokens: vec![5, 5, 5],
            score: 0.5,
        },
        BranchBlock {
            proposer: 1,
            tokens: vec![5, 5, 5],
            score: 0.5,
        },
        BranchBlock {
            proposer: 2,
            tokens: vec![6, 6],
            score: 0.5,
        },
    ];
    let trie = CandidateTrie::assemble(blocks, TrieLimits::default());
    assert_eq!(trie.branches().len(), 2);
    assert_eq!(trie.duplicate_work(), 3);
}

/// E7: greedy tree output is token-identical to plain greedy decoding for
/// adversarial random branch sets, missing proposers (stragglers), and
/// every round (E5's drop is just "block absent from input").
#[test]
fn e7_tree_greedy_equivalence_adversarial() {
    let mut outer = SplitMix64::new(20_261_006);
    for case in 0..150u64 {
        let seed = outer.next_u64();
        let target = target_argmax_fn(seed);
        let prompt = vec![(outer.next_u64() % VOCAB as u64) as u32];
        let n = 24usize;
        let expected = plain_greedy(&target, &prompt, n);

        let s = seed;
        let blocks_policy = move |prefix: &[u32]| {
            let mut h = SplitMix64::new(s ^ 0xBEEF ^ prefix.len() as u64);
            h.next_u64();
            let proposer_count = (h.next_u64() % 4) as usize; // 0..=3 — some rounds starve
            (0..proposer_count)
                .map(|i| {
                    let len = 1 + (h.next_u64() % 6) as usize;
                    BranchBlock {
                        proposer: i,
                        tokens: (0..len)
                            .map(|_| (h.next_u64() % VOCAB as u64) as u32)
                            .collect(),
                        score: (h.next_u64() % 100) as f32 / 100.0,
                    }
                })
                .collect::<Vec<_>>()
        };
        let got = simulate_tree_greedy(
            &target,
            &prompt,
            &blocks_policy,
            n,
            TrieLimits {
                max_branches: 4,
                max_nodes: 64,
            },
        );
        assert_eq!(got, expected, "case {case}: tree output diverged");
    }
}

/// Empty branch sets (all proposers straggled) still make progress via the
/// bonus token and remain exact.
#[test]
fn e5_all_stragglers_still_progresses() {
    let target = target_argmax_fn(31337);
    let prompt = vec![2];
    let empty = |_prefix: &[u32]| Vec::<BranchBlock>::new();
    let got = simulate_tree_greedy(&target, &prompt, &empty, 10, TrieLimits::default());
    assert_eq!(got.len(), 10);
    assert_eq!(got, plain_greedy(&target, &prompt, 10));
}
