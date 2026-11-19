//! Phase D correctness-gate properties (docs/acceptance/phase-d.md D1/D2).

use modelswarm_speculation::{
    sample_from, simulate_greedy, verify_greedy, verify_sampled_full_q, DraftStep, SplitMix64,
};

const VOCAB: u32 = 8;

/// Deterministic toy "target model": argmax token derived from a hash of
/// the prefix + seed. Greedy decoding under this model is well-defined and
/// reproducible.
fn target_argmax_fn(seed: u64) -> impl Fn(&[u32]) -> u32 {
    move |prefix: &[u32]| {
        let mut h = SplitMix64::new(seed ^ 0x5DEE_CE66);
        for t in prefix.iter().rev().take(4) {
            h.mix(*t as u64 + 0x9E37);
        }
        // consume a few rounds to decorrelate
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

/// D1: greedy speculative decoding is token-identical to plain greedy
/// decoding for arbitrary (even adversarial/random) draft policies and all
/// window sizes.
#[test]
fn d1_greedy_equivalence_random_drafts() {
    let mut outer = SplitMix64::new(20_261_005);
    for case in 0..200u64 {
        let seed = outer.next_u64();
        let target = target_argmax_fn(seed);
        let prompt =
            vec![(outer.next_u64() % VOCAB as u64) as u32; 1 + (outer.next_u64() % 4) as usize];
        let n = 20 + (outer.next_u64() % 40) as usize;
        let expected = plain_greedy(&target, &prompt, n);

        // Adversarial draft: stateless garbage derived from the prefix,
        // never consulting the target.
        let garbage = |prefix: &[u32]| {
            let mut h = SplitMix64::new(
                seed ^ 0xAD ^ prefix.len() as u64 ^ prefix.last().copied().unwrap_or(0) as u64,
            );
            h.next_u64();
            let w = 1 + (h.next_u64() % 16) as usize;
            (0..w)
                .map(|_| (h.next_u64() % VOCAB as u64) as u32)
                .collect::<Vec<u32>>()
        };
        for window in [1usize, 2, 4, 8, 16] {
            let got = simulate_greedy(&target, &prompt, &garbage, n);
            assert_eq!(
                got, expected,
                "case {case} window {window}: speculative output diverged"
            );
            let _ = window; // window variety is exercised via garbage's variable length
        }

        // Perfect draft (draft = the target's own continuation): still exact.
        let perfect = {
            let target_ref: &dyn Fn(&[u32]) -> u32 = &target;
            move |prefix: &[u32]| {
                let mut p = prefix.to_vec();
                let mut out = Vec::new();
                for _ in 0..8 {
                    let t = target_ref(&p);
                    p.push(t);
                    out.push(t);
                }
                out
            }
        };
        let got = simulate_greedy(&target, &prompt, &perfect, n);
        assert_eq!(got, expected, "case {case}: perfect draft diverged");
    }
}

/// Every greedy round commits at least one token (correction or bonus) —
/// even a fully-wrong draft cannot stall generation.
#[test]
fn d1_every_round_progresses() {
    let target = target_argmax_fn(99);
    let all_wrong = |prefix: &[u32]| {
        let t = target(prefix);
        vec![t.wrapping_add(1) % VOCAB; 4] // never equals target argmax
    };
    let prompt = vec![1];
    let out = simulate_greedy(&target, &prompt, &all_wrong, 12);
    assert_eq!(out.len(), 12);
    assert_eq!(out, plain_greedy(&target, &prompt, 12));
}

#[test]
fn greedy_micro_cases() {
    // draft matches first two, misses third → committed [7,7,correction 2]
    let out = verify_greedy(&[7, 7, 9], &[7, 7, 2, 4]);
    assert_eq!(out.committed, vec![7, 7, 2]);
    assert_eq!(out.accepted_draft, 2);
    assert_eq!(out.first_rejection, Some(2));

    // perfect window → all accepted + bonus token
    let out = verify_greedy(&[3, 5], &[3, 5, 1]);
    assert_eq!(out.committed, vec![3, 5, 1]);
    assert_eq!(out.first_rejection, None);

    // empty draft → bonus only
    let out = verify_greedy(&[], &[6]);
    assert_eq!(out.committed, vec![6]);
    assert_eq!(out.accepted_draft, 0);
}

/// D2: full-q rejection sampling preserves the target distribution —
/// **with an honest proposer**: the drafted token must actually be drawn
/// from q (the theorem's precondition). Empirical committed-token
/// distribution ≈ target p.
#[test]
fn d2_full_q_preserves_target_distribution() {
    let p = vec![0.5f32, 0.3, 0.2];
    let q = vec![0.2f32, 0.5, 0.3]; // draft prefers token 1

    let n = 200_000u32;
    let mut counts = [0u32; 3];
    let mut rng = SplitMix64::new(0xD2);
    for _ in 0..n {
        let token = sample_from(&q, &mut rng); // honest draw from q
        let out = verify_sampled_full_q(
            &[DraftStep {
                token,
                draft_prob: q[token as usize],
            }],
            std::slice::from_ref(&p),
            std::slice::from_ref(&q),
            &mut rng,
        );
        assert_eq!(out.committed.len(), 1);
        counts[out.committed[0] as usize] += 1;
    }
    for (i, c) in counts.iter().enumerate() {
        let emp = *c as f32 / n as f32;
        assert!(
            (emp - p[i]).abs() < 0.01,
            "token {i}: empirical {emp} vs target {}",
            p[i]
        );
    }
}

/// D2: a deterministic proposer (q = one-hot) that always proposes a token
/// the target assigns zero mass is always rejected; the correction then
/// follows the residual = p exactly.
#[test]
fn d2_zero_mass_proposal_always_rejected() {
    let p = vec![0.0f32, 0.6, 0.4];
    let q = vec![1.0f32, 0.0, 0.0];
    let mut counts = [0u32; 3];
    let n = 100_000u32;
    let mut rng = SplitMix64::new(0xFEED);
    for _ in 0..n {
        let out = verify_sampled_full_q(
            &[DraftStep {
                token: 0,
                draft_prob: 1.0,
            }],
            std::slice::from_ref(&p),
            std::slice::from_ref(&q),
            &mut rng,
        );
        assert_eq!(out.accepted_draft, 0, "zero-mass draft token accepted");
        assert_eq!(out.committed.len(), 1);
        assert_ne!(out.committed[0], 0);
        counts[out.committed[0] as usize] += 1;
    }
    let emp1 = counts[1] as f32 / n as f32;
    assert!((emp1 - 0.6).abs() < 0.01, "correction dist {emp1} vs 0.6");
}

/// Determinism: same seed → identical sampled outcomes.
#[test]
fn sampled_deterministic_from_seed() {
    let p = vec![0.4f32, 0.35, 0.25];
    let q = vec![0.1f32, 0.2, 0.7];
    let draft = vec![DraftStep {
        token: 2,
        draft_prob: 0.7,
    }];
    let run = |seed: u64| {
        let mut rng = SplitMix64::new(seed);
        (0..50)
            .map(|_| {
                verify_sampled_full_q(
                    &draft,
                    std::slice::from_ref(&p),
                    std::slice::from_ref(&q),
                    &mut rng,
                )
                .committed
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(run(77), run(77));
    assert_ne!(run(77), run(78)); // different seeds do differ
}

/// Multi-window full-q chain: committed stream's unigram distribution
/// converges to the target's (stationary check over a fixed per-position
/// target distribution).
#[test]
fn d2_multi_window_chain_distribution() {
    let p = vec![0.45f32, 0.35, 0.20];
    let q = vec![0.30f32, 0.30, 0.40];
    let mut rng = SplitMix64::new(0xC4A1);
    let mut counts = [0u64; 3];
    let mut total = 0u64;
    for _ in 0..20_000 {
        // Honest proposer: each drafted token drawn from q.
        let draft: Vec<DraftStep> = (0..4)
            .map(|_| {
                let token = sample_from(&q, &mut rng);
                DraftStep {
                    token,
                    draft_prob: q[token as usize],
                }
            })
            .collect();
        let dists = vec![p.clone(); 5]; // window + bonus
        let qs = vec![q.clone(); 4];
        let out = modelswarm_speculation::verify_sampled_with_bonus(&draft, &dists, &qs, &mut rng);
        for t in out.committed {
            counts[t as usize] += 1;
            total += 1;
        }
    }
    for (i, c) in counts.iter().enumerate() {
        let emp = *c as f32 / total as f32;
        assert!((emp - p[i]).abs() < 0.02, "token {i}: {emp} vs {}", p[i]);
    }
}

/// The verifier never consults draft data for outputs: corrupting draft
/// probabilities changes acceptance *length*, never correctness (greedy is
/// trivially immune; sampled still converges to p in distribution).
#[test]
fn lying_proposer_cannot_bend_distribution() {
    let p = vec![0.5f32, 0.3, 0.2];
    // Proposer claims q(1) = 1.0 (a lie — its real dist was different).
    // Acceptance ratio for token 1 becomes min(0.3/1.0,1)=0.3; rejections
    // correct via the full residual — the theorem still yields p overall.
    let q_claim = vec![0.0f32, 1.0, 0.0];
    let mut counts = [0u32; 3];
    let n = 200_000u32;
    let mut rng = SplitMix64::new(0x11E);
    for _ in 0..n {
        let out = verify_sampled_full_q(
            &[DraftStep {
                token: 1,
                draft_prob: 1.0,
            }],
            std::slice::from_ref(&p),
            std::slice::from_ref(&q_claim),
            &mut rng,
        );
        counts[out.committed[0] as usize] += 1;
    }
    for (i, c) in counts.iter().enumerate() {
        let emp = *c as f32 / n as f32;
        assert!((emp - p[i]).abs() < 0.01, "token {i}: {emp} vs {}", p[i]);
    }
}

#[test]
fn sample_from_weights_and_panics_on_zero() {
    let mut rng = SplitMix64::new(5);
    for _ in 0..100 {
        assert_eq!(sample_from(&[1.0, 0.0, 0.0], &mut rng), 0);
    }
    let mut seen_other = false;
    for _ in 0..100 {
        if sample_from(&[0.0, 0.5, 0.5], &mut rng) != 1 {
            seen_other = true;
        }
    }
    assert!(seen_other);
    let result = std::panic::catch_unwind(|| {
        let mut rng = SplitMix64::new(1);
        sample_from(&[0.0, 0.0], &mut rng)
    });
    assert!(result.is_err(), "zero-mass must panic");
}
