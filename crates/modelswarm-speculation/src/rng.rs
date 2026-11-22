//! Deterministic, seedable RNG for protocol tests and simulations.
//!
//! **Not cryptographic.** Production sampling randomness comes from the
//! runtime adapter (OS-backed). This exists so acceptance-rule tests,
//! benchmarks, and property sweeps are bit-reproducible from a seed.

#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Mixes external entropy (e.g. prefix context) into the state so
    /// per-position streams decorrelate while staying deterministic.
    pub fn mix(&mut self, value: u64) {
        self.state ^= value.rotate_left(17).wrapping_mul(0xA24B_AED4_96D1_2C11);
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform f32 in [0, 1). 24 bits of mantissa — sufficient for
    /// acceptance-ratio comparisons in tests; documented as such.
    pub fn next_f32(&mut self) -> f32 {
        (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32
    }

    /// Uniform integer in [0, n).
    pub fn next_below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_from_seed() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn f32_in_unit_interval() {
        let mut rng = SplitMix64::new(7);
        for _ in 0..10_000 {
            let v = rng.next_f32();
            assert!((0.0..1.0).contains(&v));
        }
    }

    #[test]
    fn below_stays_in_range() {
        let mut rng = SplitMix64::new(9);
        for _ in 0..10_000 {
            assert!(rng.next_below(5) < 5);
        }
    }
}
