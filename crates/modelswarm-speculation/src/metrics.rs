//! Acceptance telemetry per ADR-13 / vLLM's convention.

/// Aggregate acceptance statistics over verification rounds.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct AcceptanceStats {
    pub rounds: u64,
    pub verification_steps: u64,
    pub accepted_draft_tokens: u64,
    pub committed_tokens: u64,
    pub rollbacks: u64,
}

impl AcceptanceStats {
    pub fn record_round(&mut self, accepted_draft: usize, committed: usize) {
        self.rounds += 1;
        self.verification_steps += 1;
        self.accepted_draft_tokens += accepted_draft as u64;
        self.committed_tokens += committed as u64;
    }

    pub fn record_rollback(&mut self) {
        self.rollbacks += 1;
    }

    /// Mean acceptance length, vLLM convention: `1 + accepted/steps`
    /// (a round always commits at least one token: correction or bonus).
    pub fn mean_acceptance_length(&self) -> f32 {
        if self.verification_steps == 0 {
            return 0.0;
        }
        1.0 + self.accepted_draft_tokens as f32 / self.verification_steps as f32
    }

    /// Fraction of drafted tokens accepted.
    pub fn acceptance_rate(&self) -> f32 {
        if self.verification_steps == 0 || self.accepted_draft_tokens == 0 {
            return 0.0;
        }
        // drafted-per-round isn't tracked separately; rate over committed
        // tokens is the stable definition used in our records.
        self.accepted_draft_tokens as f32 / self.committed_tokens.max(1) as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mean_acceptance_length_follows_vllm_convention() {
        let mut s = AcceptanceStats::default();
        // 3 rounds: accepted 2/2/0 drafted tokens → mean = 1 + 4/3
        s.record_round(2, 3);
        s.record_round(2, 3);
        s.record_round(0, 1);
        assert!((s.mean_acceptance_length() - (1.0 + 4.0 / 3.0)).abs() < 1e-6);
    }

    #[test]
    fn empty_stats_are_zero() {
        let s = AcceptanceStats::default();
        assert_eq!(s.mean_acceptance_length(), 0.0);
        assert_eq!(s.acceptance_rate(), 0.0);
    }
}
