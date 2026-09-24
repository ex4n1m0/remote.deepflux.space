//! Deterministic application-layer loss/reorder injection for the M2 rig.
//!
//! The spike runs over loopback where the real network drops nothing, so
//! loss/reorder behavior is injected at the application layer, *below* the
//! `input-fast`/`input-reliable` send calls and above the SCTP channel —
//! the same boundary where a real network would act on the unordered,
//! maxRetransmits-0 channel. The RNG is a seeded xorshift64* so a failing
//! rig run reproduces exactly.
//!
//! What the injector does NOT model: SCTP-level retransmission on reliable
//! channels (loopback SCTP is reliable by construction). Reliable-channel
//! gaps are injected explicitly via [`ChaosInjector::should_drop_nth`] to
//! exercise the host-side sequence-gap detector that must answer with
//! `AllKeysUp` semantics.

/// Seeded xorshift64* — small, deterministic, no dependency.
#[derive(Debug, Clone)]
pub struct ChaosRng {
    state: u64,
}

impl ChaosRng {
    /// Any nonzero seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    /// Uniform-ish u64; multiply-shift for a percent check is sufficient
    /// for fault injection (not cryptography).
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// True with probability `percent_inclusive_percent`%.
    pub fn percent_chance(&mut self, percent: u32) -> bool {
        if percent == 0 {
            return false;
        }
        if percent >= 100 {
            return true;
        }
        // Scale to a 0..100 bucket on the high bits.
        (self.next_u64() >> 32) % 100 < u64::from(percent)
    }
}

/// Per-message verdicts for one injection point.
#[derive(Debug, Clone)]
pub struct ChaosInjector {
    rng: ChaosRng,
    drop_percent: u32,
    reorder_percent: u32,
    /// Held message to emit after the next one (reordering window of 1).
    pending: Option<Vec<u8>>,
    /// Every `n`-th message on the reliable path is dropped (0 = never) —
    /// deterministic sequence-gap injection.
    drop_every_nth: u64,
    seen: u64,
    pub dropped: u64,
    pub reordered: u64,
}

impl ChaosInjector {
    /// `drop_percent`/`reorder_percent` in 0..=100; `drop_every_nth` drops
    /// exactly every n-th `filter`ed message (gap injection for the
    /// reliable-channel sequence detector).
    pub fn new(seed: u64, drop_percent: u32, reorder_percent: u32) -> Self {
        Self {
            rng: ChaosRng::new(seed),
            drop_percent,
            reorder_percent,
            pending: None,
            drop_every_nth: 0,
            seen: 0,
            dropped: 0,
            reordered: 0,
        }
    }

    /// Enable deterministic every-n-th dropping (reliable-gap injection).
    pub fn with_drop_every_nth(mut self, n: u64) -> Self {
        self.drop_every_nth = n;
        self
    }

    /// Feed one outgoing message; returns the messages that should be sent
    /// *now* (0, 1, or 2 — the reorder window is one message).
    ///
    /// Order of verdicts: loss first (a dropped message never reorders),
    /// then reorder (the previous message is held back and emitted after
    /// this one, i.e. the pair arrives swapped).
    pub fn transform(&mut self, message: Vec<u8>) -> Vec<Vec<u8>> {
        self.seen += 1;
        if self.drop_every_nth != 0 && self.seen.is_multiple_of(self.drop_every_nth) {
            self.dropped += 1;
            // A held message is unaffected by a drop.
            return self.pending.take().into_iter().collect();
        }
        if self.rng.percent_chance(self.drop_percent) {
            self.dropped += 1;
            return self.pending.take().into_iter().collect();
        }
        if self.rng.percent_chance(self.reorder_percent) {
            self.reordered += 1;
            match self.pending.take() {
                Some(prev) => vec![message, prev], // prev leaves after current: swapped pair
                None => {
                    self.pending = Some(message);
                    vec![]
                }
            }
        } else {
            let mut out = self.pending.take().into_iter().collect::<Vec<_>>();
            out.push(message);
            out
        }
    }

    /// Flush any message still held by the reorder window (call at end of
    /// an injection phase so the last message is not silently delayed).
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        self.pending.take().into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_chaos_is_identity() {
        let mut chaos = ChaosInjector::new(42, 0, 0);
        for i in 0..100u8 {
            assert_eq!(chaos.transform(vec![i]), vec![vec![i]]);
        }
    }

    #[test]
    fn full_drop_drops_everything() {
        let mut chaos = ChaosInjector::new(7, 100, 0);
        for i in 0..50u8 {
            assert!(chaos.transform(vec![i]).is_empty());
        }
        assert_eq!(chaos.dropped, 50);
    }

    #[test]
    fn deterministic_across_instances() {
        let run = |seed: u64| {
            let mut chaos = ChaosInjector::new(seed, 30, 20);
            (0..500u32)
                .map(|_| chaos.transform(vec![]).len() as u64)
                .sum::<u64>()
                + chaos.flush().len() as u64
        };
        assert_eq!(run(99), run(99), "same seed must reproduce exactly");
        assert_ne!(
            run(99),
            run(100),
            "different seeds should diverge (probabilistic but near-certain over 500 draws)"
        );
    }

    #[test]
    fn transform_never_loses_or_duplicates_bytes() {
        // Conservation: every input byte is either emitted or counted
        // dropped; reorder only permutes.
        let mut chaos = ChaosInjector::new(1, 25, 25);
        let mut emitted = 0u64;
        let input_count = 1000u64;
        for i in 0..input_count {
            emitted += chaos.transform(vec![i as u8; (i % 7) as usize + 1]).len() as u64;
        }
        emitted += chaos.flush().len() as u64;
        assert_eq!(emitted + chaos.dropped, input_count);
    }

    #[test]
    fn drop_every_nth_creates_exact_gaps() {
        let mut chaos = ChaosInjector::new(3, 0, 0).with_drop_every_nth(4);
        let mut sent = Vec::new();
        for i in 0..12u8 {
            sent.extend(chaos.transform(vec![i]));
        }
        sent.extend(chaos.flush());
        // seq 3, 7, 11 dropped (0-indexed every 4th).
        let emitted: Vec<u8> = sent.into_iter().flatten().collect();
        assert_eq!(emitted, vec![0, 1, 2, 4, 5, 6, 8, 9, 10]);
        assert_eq!(chaos.dropped, 3);
    }

    #[test]
    fn reorder_swaps_adjacent_pairs() {
        // 100% reorder: messages leave in swapped pairs (1,0),(3,2),...
        let mut chaos = ChaosInjector::new(5, 0, 100);
        let mut out = Vec::new();
        for i in 0..6u8 {
            out.extend(chaos.transform(vec![i]));
        }
        out.extend(chaos.flush());
        let flat: Vec<u8> = out.into_iter().flatten().collect();
        assert_eq!(flat, vec![1, 0, 3, 2, 5, 4]);
        // Every message passed through a reorder verdict (3 pairs × 2).
        assert_eq!(chaos.reordered, 6);
    }
}
