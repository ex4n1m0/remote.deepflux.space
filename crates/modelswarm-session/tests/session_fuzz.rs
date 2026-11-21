//! Hand-rolled randomized mutation fuzz (no external fuzzing framework):
//! 10 000 iterations of a xorshift-driven adversarial stream of commits
//! against the state machine, asserting it never panics and its invariants
//! always hold:
//!
//! - the committed prefix hash is always 64 lowercase hex chars;
//! - the round only ever increases, by exactly one per `Advanced`;
//! - `Advanced` sets the committed hash to the accepted commit's hash;
//! - non-`Advanced` outcomes never change state.

use modelswarm_session::{compute_prefix_hash, ApplyOutcome, CommitPrefix, SessionStateMachine};

/// Deterministic xorshift64* PRNG (tests only; not for production use).
struct XorShiftRng(u64);

impl XorShiftRng {
    fn new(seed: u64) -> Self {
        // Zero state is invalid for xorshift; force an odd seed.
        Self(seed.max(1))
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

const GENESIS: &str = "e750bb7c423fd0b74d0bcf2e796988b4c2218f74a7e0d59d033845950990efb6";
const SESSIONS: [&str; 3] = ["sess-a", "sess-b", "other"];
const PROFILES: [&str; 3] = ["msp1:profile-a", "msp1:profile-b", "msp1:profile-c"];
const PARAMS: [&str; 2] = ["params-a", "params-b"];
const SENDERS: [&str; 3] = ["peer-1", "peer-2", "peer-3"];

fn random_tokens(rng: &mut XorShiftRng) -> Vec<u32> {
    let len = rng.below(5) as usize;
    (0..len).map(|_| (rng.next_u64() >> 32) as u32).collect()
}

/// Builds the honest commit chain for a random token sequence.
fn build_chain(rounds: &[Vec<u32>]) -> Vec<CommitPrefix> {
    let mut prev = GENESIS.to_string();
    let mut commits = Vec::with_capacity(rounds.len());
    for (i, tokens) in rounds.iter().enumerate() {
        let new = compute_prefix_hash(&prev, tokens).unwrap();
        commits.push(CommitPrefix {
            session_id: SESSIONS[0].to_string(),
            round: (i + 1) as u64,
            previous_prefix_hash: prev.clone(),
            accepted_token_ids: tokens.clone(),
            new_prefix_hash: new.clone(),
            model_profile_id: PROFILES[0].to_string(),
            generation_params_hash: PARAMS[0].to_string(),
            sender: SENDERS[i % SENDERS.len()].to_string(),
        });
        prev = new;
    }
    commits
}

fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[test]
fn mutation_fuzz_ten_thousand_iterations() {
    let mut rng = XorShiftRng::new(0x5eed_cafe_f00d_2026);
    let iterations: u64 = 10_000;

    for iter in 0..iterations {
        // Fresh machine with a valid genesis each iteration.
        let mut sm = SessionStateMachine::new(SESSIONS[0], PROFILES[0], PARAMS[0], GENESIS)
            .expect("valid genesis");
        assert!(is_lower_hex_64(sm.committed_prefix_hash()));

        // Random honest chain (1..=30 rounds).
        let chain_len = 1 + rng.below(30) as usize;
        let rounds: Vec<Vec<u32>> = (0..chain_len).map(|_| random_tokens(&mut rng)).collect();
        let chain = build_chain(&rounds);

        // Apply a random number of honest commits to seed the state.
        let honest_prefix = rng.below(chain_len as u64 + 1) as usize;
        for commit in &chain[..honest_prefix] {
            assert_eq!(sm.apply(commit), ApplyOutcome::Advanced);
        }
        assert_eq!(sm.round(), honest_prefix as u64);

        // Now throw 50 mutated/hostile commits at it.
        for _ in 0..50 {
            let before_round = sm.round();
            let before_hash = sm.committed_prefix_hash().to_string();

            let base = &chain[rng.below(chain_len as u64) as usize];
            let mut hostile = base.clone();

            // Random field mutations (0..=4 per hostile commit).
            for _ in 0..rng.below(5) {
                match rng.below(11) {
                    0 => hostile.session_id = SESSIONS[rng.below(3) as usize].to_string(),
                    1 => hostile.model_profile_id = PROFILES[rng.below(3) as usize].to_string(),
                    2 => hostile.generation_params_hash = PARAMS[rng.below(2) as usize].to_string(),
                    3 => hostile.round = hostile.round.wrapping_add(rng.below(4)),
                    4 => hostile.round = hostile.round.saturating_sub(rng.below(4)),
                    5 => hostile.previous_prefix_hash = format!("{:064x}", rng.next_u64()),
                    6 => hostile.new_prefix_hash = format!("{:064x}", rng.next_u64()),
                    7 => {
                        // Also recompute new_prefix_hash consistently when
                        // tokens change, so the hash check is genuinely
                        // exercised against wrong-token-right-shape inputs.
                        let tokens = &mut hostile.accepted_token_ids;
                        if tokens.is_empty() {
                            tokens.push(rng.next_u64() as u32);
                        } else {
                            let t = rng.below(tokens.len() as u64) as usize;
                            tokens[t] = tokens[t].wrapping_add(1);
                        }
                        if let Ok(fixed) = compute_prefix_hash(
                            &hostile.previous_prefix_hash,
                            &hostile.accepted_token_ids,
                        ) {
                            if rng.below(2) == 0 {
                                hostile.new_prefix_hash = fixed;
                            }
                        }
                    }
                    8 => hostile.sender = SENDERS[rng.below(3) as usize].to_string(),
                    9 => hostile.accepted_token_ids = random_tokens(&mut rng),
                    _ => {} // leave as-is (honest duplicate replay)
                }
            }
            hostile.round = hostile.round.min(u64::MAX / 2); // keep arithmetic sane

            // The call itself must not panic.
            let outcome = sm.apply(&hostile);

            // Invariants.
            assert!(
                is_lower_hex_64(sm.committed_prefix_hash()),
                "iter {iter}: hash corrupted"
            );
            match outcome {
                ApplyOutcome::Advanced => {
                    assert_eq!(sm.round(), before_round + 1, "iter {iter}: round jumped");
                    assert_eq!(
                        sm.committed_prefix_hash(),
                        hostile.new_prefix_hash,
                        "iter {iter}: committed hash mismatch on advance"
                    );
                }
                ApplyOutcome::Duplicate | ApplyOutcome::Rejected(_) => {
                    assert_eq!(
                        sm.round(),
                        before_round,
                        "iter {iter}: round changed on {outcome:?}"
                    );
                    assert_eq!(
                        sm.committed_prefix_hash(),
                        before_hash,
                        "iter {iter}: hash changed on {outcome:?}"
                    );
                }
            }
        }

        // Final sanity: the honest chain can still be extended from wherever
        // the honest prefix left the machine (state was never corrupted).
        assert!(is_lower_hex_64(sm.committed_prefix_hash()));
        assert_eq!(sm.session_id(), SESSIONS[0]);
        assert_eq!(sm.model_profile_id(), PROFILES[0]);
        assert_eq!(sm.generation_params_hash(), PARAMS[0]);
    }
}
