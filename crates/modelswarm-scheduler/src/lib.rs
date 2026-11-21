//! Swarm scheduling: filtering ineligible candidates, scoring peers by
//! predicted completion time (`docs/architecture.md` §10 v1 formula), the
//! ADR-013 cost model v2 for cooperative modes, the frozen engage rule with
//! its margin floor, bounded micro-swarm selection, and the EWMA estimator
//! that keeps requester-measured values dominant over self-reported ones.
//! The [`shadow`] module wires those formulas over the F15 measurement
//! plumbing in shadow mode — it logs the plan it would choose and never
//! acts (dependency-graph edge 11).
//!
//! # Frozen rules (ADR-013)
//!
//! - `confidence_margin` defaults to [`DEFAULT_CONFIDENCE_MARGIN`] (0.15) and
//!   may never be below [`MIN_CONFIDENCE_MARGIN`] (0.05) — enforced with
//!   [`SchedulerError::MarginTooLow`], not by silently raising the value.
//! - Cooperative modes engage only when
//!   `predicted_swarm × (1 + margin) < predicted_fastest_single`.
//! - The comparator is always the **fastest eligible single host**, never an
//!   average (revision invariant).

use modelswarm_types::ModelProfileId;
use serde::{Deserialize, Serialize};

pub mod shadow;

/// Default confidence margin for the engage rule (ADR-013: 0.15).
pub const DEFAULT_CONFIDENCE_MARGIN: f64 = 0.15;
/// Hard floor for any confidence margin (ADR-013: ≥ 0.05, frozen rule).
pub const MIN_CONFIDENCE_MARGIN: f64 = 0.05;
/// Maximum micro-swarm size (ADR-013 `speculative_exact`: 2–8 peers).
pub const MICROSWARM_CAP: usize = 8;
/// Eligibility filter: peers whose stale-advertisement penalty exceeds this
/// are excluded from selection (tunable default; measured staleness feeds
/// the penalty, the filter only refuses clearly stale data).
pub const MAX_STALE_ADVERTISEMENT_PENALTY_MS: f64 = 1_000.0;
/// Minimum hardware capacity class eligible for cooperative rounds.
pub const MIN_CAPACITY_CLASS: CapacityClass = CapacityClass::Cpu;
/// EWMA smoothing factor for requester-measured observations.
pub const EWMA_ALPHA: f64 = 0.3;
/// Additive scoring penalty for hole-punched paths (ADR-014 rule 4: NAT path
/// type is a scheduler input and relayed paths carry a cost penalty — a
/// punched path still pays extra coordination/synchronization cost versus
/// direct). Milliseconds added to [`predicted_single_ms`].
pub const HOLEPUNCHED_PATH_PENALTY_MS: f64 = 10.0;
/// Additive scoring penalty for relayed paths (ADR-014 rule 4): a relay adds
/// at least one extra network hop each way plus relay queuing, so an
/// otherwise-equal relayed candidate must rank strictly below the direct one.
/// Milliseconds added to [`predicted_single_ms`].
pub const RELAYED_PATH_PENALTY_MS: f64 = 40.0;

/// Hardware capacity classes, ordered weakest → strongest (matches the
/// `hardware_class_peers` vocabulary of the run-manifest schema).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityClass {
    /// CPU-only host.
    Cpu,
    /// Entry-level GPU.
    GpuEntry,
    /// Mid-range GPU.
    GpuMid,
    /// High-end GPU.
    GpuHigh,
}

/// NAT situation of a candidate (matches the `nat_path` vocabulary of the
/// mode-result schema; ADR-014).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatPath {
    /// Direct QUIC connection.
    Direct,
    /// Hole-punched path.
    HolePunched,
    /// Relayed path (Phase F+).
    Relayed,
}

/// One eligible-or-not serving candidate for a profile, mixing
/// requester-measured fields (RTT, prefill/decode rates, penalties) with
/// peer-advertised ones (`advertised_queue_ms`, `slots`). Measured fields
/// dominate scoring by construction: they carry the token-rate terms.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// Peer id (libp2p `PeerId` string); also the deterministic tie-break.
    pub peer_id: String,
    /// The exact profile this peer hosts (project rule).
    pub profile_id: ModelProfileId,
    /// Requester-measured round-trip time in milliseconds (EWMA).
    pub measured_rtt_ms: f64,
    /// Peer-advertised queue backlog in milliseconds.
    pub advertised_queue_ms: f64,
    /// Measured prefill throughput (tokens/ms).
    pub prefill_tokens_per_ms: f64,
    /// Measured decode throughput (tokens/ms).
    pub decode_tokens_per_ms: f64,
    /// Historical failure penalty in milliseconds.
    pub failure_penalty_ms: f64,
    /// Penalty for staleness of the advertisement in milliseconds.
    pub stale_advertisement_penalty_ms: f64,
    /// Currently advertised free serving slots.
    pub slots: u32,
    /// Hardware class of the host.
    pub capacity_class: CapacityClass,
    /// Network path type to this peer.
    pub nat_path: NatPath,
    /// Whether this peer's serving adapter DECLARED batch-verify
    /// capability: it can verify a speculative draft window in ONE
    /// batched engine pass (ADR-032 §4 — the in-process C-API adapter
    /// class; the pinned llama.cpp HTTP adapter, today's only production
    /// adapter, cannot, so **no production peer may declare it yet**).
    /// The flag defaults to ABSENT at every construction site here:
    /// cost models must charge cohorts whose verifier has not declared
    /// the capability the wire-true sequential verification term
    /// (window+1 sequential verifier tokens per round plus the per-round
    /// prefix re-post — pass 2 measured the msp-v1 whole-request wire at
    /// 2.8–8.3× the 1.5-step batch term's prediction). A peer
    /// misreporting the capability degrades its acceptance economics,
    /// never output correctness (ADR-032 §3).
    pub batch_verify: bool,
}

/// Scheduler-rule violations (frozen rules, not heuristics).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SchedulerError {
    /// A caller-supplied margin was below [`MIN_CONFIDENCE_MARGIN`]
    /// (ADR-013 frozen floor; the caller must raise it explicitly).
    #[error(
        "confidence margin {provided} is below the frozen floor {MIN_CONFIDENCE_MARGIN} \
         (ADR-013); pass an explicit, reviewed margin"
    )]
    MarginTooLow {
        /// The rejected margin value.
        provided: f64,
    },
}

/// `predicted_ms` for a single host, v1 formula
/// (`docs/architecture.md` §10) plus the ADR-014 NAT-path penalty:
///
/// ```text
/// measured_rtt_ms
/// + advertised_queue_ms
/// + prompt_tokens / measured_prefill_tokens_per_ms
/// + output_tokens / measured_decode_tokens_per_ms
/// + failure_penalty_ms
/// + stale_advertisement_penalty_ms
/// + nat_path_penalty_ms(candidate.nat_path)
/// ```
///
/// A non-positive measured rate yields `INFINITY` (an unusable peer ranks
/// last instead of dividing by zero).
pub fn predicted_single_ms(candidate: &Candidate, prompt_tokens: u32, output_tokens: u32) -> f64 {
    candidate.measured_rtt_ms
        + candidate.advertised_queue_ms
        + tokens_over_rate(prompt_tokens, candidate.prefill_tokens_per_ms)
        + tokens_over_rate(output_tokens, candidate.decode_tokens_per_ms)
        + candidate.failure_penalty_ms
        + candidate.stale_advertisement_penalty_ms
        + nat_path_penalty_ms(candidate.nat_path)
}

/// The ADR-014 NAT-path cost penalty: direct pays nothing, hole-punched pays
/// [`HOLEPUNCHED_PATH_PENALTY_MS`], relayed pays [`RELAYED_PATH_PENALTY_MS`].
/// Deterministic, monotone in path indirection — a relayed candidate never
/// outscores an otherwise-equal direct one.
pub fn nat_path_penalty_ms(nat_path: NatPath) -> f64 {
    match nat_path {
        NatPath::Direct => 0.0,
        NatPath::HolePunched => HOLEPUNCHED_PATH_PENALTY_MS,
        NatPath::Relayed => RELAYED_PATH_PENALTY_MS,
    }
}

fn tokens_over_rate(tokens: u32, rate_per_ms: f64) -> f64 {
    if rate_per_ms > 0.0 {
        f64::from(tokens) / rate_per_ms
    } else {
        f64::INFINITY
    }
}

/// Named inputs of the ADR-013 cost model v2. The function
/// [`predicted_swarm_ms`] is pure arithmetic over these terms — coefficients
/// are measured by the bench harness, never invented here.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SwarmInputs {
    /// Target-model prefill of the prompt on the verifier (ms).
    pub prefill_cost_ms: f64,
    /// Expected wall time for one proposal window on the proposer:
    /// network round trips plus drafter compute (ms).
    pub proposal_cost_ms: f64,
    /// Target-model batched verification of the window: per-token verify
    /// cost × window size (ms).
    pub verification_cost_ms: f64,
    /// Coordination overhead per bounded round window: RTT + jitter + relay
    /// effects on the commit path (ms).
    pub synchronization_cost_ms: f64,
    /// Expected rollback loss: P(window mismatch) × (discard + re-decode)
    /// cost, derived from the measured acceptance rate (ms).
    pub expected_rollback_cost_ms: f64,
    /// Expected loss from peer failure mid-round, from session failure
    /// history (ms).
    pub failure_risk_penalty_ms: f64,
}

impl SwarmInputs {
    /// Zero inputs (a base to overwrite field-by-field in tests).
    pub const ZERO: Self = Self {
        prefill_cost_ms: 0.0,
        proposal_cost_ms: 0.0,
        verification_cost_ms: 0.0,
        synchronization_cost_ms: 0.0,
        expected_rollback_cost_ms: 0.0,
        failure_risk_penalty_ms: 0.0,
    };
}

/// `predicted_swarm_completion` — the frozen ADR-013 v2 sum:
/// prefill + proposal + verification + synchronization +
/// expected rollback + failure risk. Pure arithmetic over [`SwarmInputs`].
pub fn predicted_swarm_ms(inputs: &SwarmInputs) -> f64 {
    inputs.prefill_cost_ms
        + inputs.proposal_cost_ms
        + inputs.verification_cost_ms
        + inputs.synchronization_cost_ms
        + inputs.expected_rollback_cost_ms
        + inputs.failure_risk_penalty_ms
}

/// Frozen engage rule (ADR-013): engage a cooperative mode only when
/// `predicted_swarm × (1 + margin) < predicted_fastest_single`.
///
/// `margin` below [`MIN_CONFIDENCE_MARGIN`] (0.05) is rejected with
/// [`SchedulerError::MarginTooLow`] — never silently clamped. Use
/// [`DEFAULT_CONFIDENCE_MARGIN`] (0.15) unless a reviewed ADR-backed value
/// exists; the margin actually used must be recorded in every run record.
pub fn should_engage_cooperative(
    predicted_swarm_ms: f64,
    predicted_fastest_single_ms: f64,
    margin: f64,
) -> Result<bool, SchedulerError> {
    if margin < MIN_CONFIDENCE_MARGIN {
        return Err(SchedulerError::MarginTooLow { provided: margin });
    }
    Ok(predicted_swarm_ms * (1.0 + margin) < predicted_fastest_single_ms)
}

/// How a cooperative cohort's verification cost must be charged — the
/// ADR-032 §4 companion correction ("required regardless of this ADR's
/// fate"): engine-true and capability-aware, with the wire-true
/// sequential term as the default for every cohort whose verifier has
/// not declared the capability. This selection and the decision logic
/// below it live here (default features) so the engage-gate tests are
/// per-push CI-runnable (ADR-032 rev 2 execution-venue matrix, item 4a).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyTerm {
    /// The verifier DECLARED batch-verify capability
    /// ([`Candidate::batch_verify`]): one batched engine pass per draft
    /// window, charged with the caller's batch coefficient (ADR-013's
    /// ENGINE constant `VERIFY_BATCH_STEPS = 1.5` lives with the
    /// cost-model coefficients in the bench crate). No production
    /// adapter can declare the capability today (ADR-032 §4).
    Batch,
    /// No batch-verify declaration — every production cohort today. The
    /// msp-v1 whole-request wire verifies a draft window in **window+1
    /// sequential verifier tokens** plus a per-round re-post of the
    /// committed prefix; pass 2 measured that reality at
    /// realized/predicted 2.8–8.3× against the 1.5-step batch term
    /// (`experiments/raw/PASS-2-ENGAGE-LAN-2026-10-10/ANALYSIS.md`,
    /// finding 4). With this term the engage gate blocks engagement on
    /// HTTP-only cohorts — the pass-2 never-engage conclusion enforced,
    /// not advised.
    SequentialWire,
}

impl VerifyTerm {
    /// The term one verifier is charged, from its declared capability.
    #[must_use]
    pub fn of_verifier(verifier: &Candidate) -> Self {
        if verifier.batch_verify {
            Self::Batch
        } else {
            Self::SequentialWire
        }
    }

    /// The term a cohort is charged: the VERIFIER decides — the
    /// fastest-ranked peer (`cohort[0]`) is the role that executes
    /// verification. An HTTP peer may still act as proposer (a
    /// first-class single, never a batch verifier — ADR-032 §4), so a
    /// mixed cohort whose verifier has not declared the capability is
    /// charged the sequential wire term. An empty cohort is charged the
    /// conservative wire term.
    #[must_use]
    pub fn of_cohort(cohort: &[Candidate]) -> Self {
        cohort
            .first()
            .map_or(Self::SequentialWire, Self::of_verifier)
    }

    /// Decode steps charged per verify round under this term: the
    /// caller's batch coefficient (ADR-013's 1.5) for a declared
    /// verifier, or `window + 1` sequential steps on the msp-v1 wire.
    #[must_use]
    pub fn decode_steps_per_round(self, window: u32, batch_steps: f64) -> f64 {
        match self {
            Self::Batch => batch_steps,
            Self::SequentialWire => f64::from(window + 1),
        }
    }

    /// Stable, grep-able label for run artifacts and fallback reasons.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Batch => {
                "batch-verify engine term (verifier declared the capability)"
            }
            Self::SequentialWire => {
                "wire-true sequential verify (window+1 verifier tokens/round + per-round prefix re-post; no batch-verify declaration)"
            }
        }
    }
}

/// Selects a micro-swarm: filter to exact-profile peers with a free slot,
/// non-stale advertisements, and at least [`MIN_CAPACITY_CLASS`] hardware;
/// order by [`predicted_single_ms`] (fastest first) with a deterministic
/// `peer_id` tie-break; take at most `want`, never more than
/// [`MICROSWARM_CAP`].
pub fn select_microswarm<'a>(
    candidates: &'a [Candidate],
    profile: &ModelProfileId,
    prompt_tokens: u32,
    output_tokens: u32,
    want: usize,
) -> Vec<&'a Candidate> {
    let mut eligible: Vec<&Candidate> = candidates
        .iter()
        .filter(|c| {
            &c.profile_id == profile
                && c.slots > 0
                && c.stale_advertisement_penalty_ms <= MAX_STALE_ADVERTISEMENT_PENALTY_MS
                && c.capacity_class >= MIN_CAPACITY_CLASS
        })
        .collect();
    eligible.sort_by(|a, b| {
        predicted_single_ms(a, prompt_tokens, output_tokens)
            .total_cmp(&predicted_single_ms(b, prompt_tokens, output_tokens))
            .then_with(|| a.peer_id.cmp(&b.peer_id))
    });
    let take = want.min(MICROSWARM_CAP);
    eligible.truncate(take);
    eligible
}

/// Exponentially weighted moving average for requester-measured
/// observations (RTT, throughput). Persistence-agnostic: the store crate
/// serializes [`Ewma::value`] later; nothing here touches disk.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ewma {
    alpha: f64,
    value: Option<f64>,
}

impl Ewma {
    /// Creates an estimator with the given smoothing factor (0..1).
    #[must_use]
    pub fn new(alpha: f64) -> Self {
        Self {
            alpha: alpha.clamp(0.0, 1.0),
            value: None,
        }
    }

    /// Creates an estimator with the default [`EWMA_ALPHA`] (0.3).
    #[must_use]
    pub fn default_alpha() -> Self {
        Self::new(EWMA_ALPHA)
    }

    /// Feeds one observation and returns the updated estimate. The first
    /// observation seeds the estimate directly.
    pub fn update(&mut self, observation: f64) -> f64 {
        let next = match self.value {
            None => observation,
            Some(previous) => self.alpha * observation + (1.0 - self.alpha) * previous,
        };
        self.value = Some(next);
        next
    }

    /// The current estimate, if any observation has been fed.
    pub fn value(&self) -> Option<f64> {
        self.value
    }

    /// The configured smoothing factor.
    pub fn alpha(&self) -> f64 {
        self.alpha
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ModelProfileId {
        ModelProfileId::new("msp:qwen3-4b:q4_k_m:v1").unwrap()
    }

    fn candidate(peer: &str, rtt: f64, queue: f64, prefill: f64, decode: f64) -> Candidate {
        Candidate {
            peer_id: peer.to_string(),
            profile_id: profile(),
            measured_rtt_ms: rtt,
            advertised_queue_ms: queue,
            prefill_tokens_per_ms: prefill,
            decode_tokens_per_ms: decode,
            failure_penalty_ms: 0.0,
            stale_advertisement_penalty_ms: 0.0,
            slots: 2,
            capacity_class: CapacityClass::GpuMid,
            nat_path: NatPath::Direct,
            batch_verify: false,
        }
    }

    #[test]
    fn v1_formula_matches_architecture_section_10() {
        let c = Candidate {
            failure_penalty_ms: 30.0,
            stale_advertisement_penalty_ms: 10.0,
            ..candidate("p1", 20.0, 50.0, 2.0, 0.5)
        };
        // 20 + 50 + 512/2 + 256/0.5 + 30 + 10 = 878
        let predicted = predicted_single_ms(&c, 512, 256);
        assert!((predicted - 878.0).abs() < 1e-9, "got {predicted}");
    }

    #[test]
    fn zero_measured_rate_ranks_as_infinite_time() {
        let c = candidate("p1", 10.0, 0.0, 0.0, 0.0);
        assert!(predicted_single_ms(&c, 10, 10).is_infinite());
    }

    #[test]
    fn swarm_model_is_the_frozen_sum_of_terms() {
        let inputs = SwarmInputs {
            prefill_cost_ms: 100.0,
            proposal_cost_ms: 20.0,
            verification_cost_ms: 40.0,
            synchronization_cost_ms: 15.0,
            expected_rollback_cost_ms: 25.0,
            failure_risk_penalty_ms: 10.0,
        };
        assert!((predicted_swarm_ms(&inputs) - 210.0).abs() < 1e-9);
        assert!((predicted_swarm_ms(&SwarmInputs::ZERO) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn engage_rule_flips_at_break_even_with_default_margin() {
        // Margin 0.5 is exact in binary, so the break-even product is exact:
        // 100 * 1.5 == 150 → not strictly faster → disengage.
        assert!(!should_engage_cooperative(100.0, 150.0, 0.5).unwrap());
        // One millisecond of headroom → engage.
        assert!(should_engage_cooperative(100.0, 151.0, 0.5).unwrap());
        // With the default 0.15 margin: clearly faster engages, slower not.
        assert!(should_engage_cooperative(100.0, 120.0, DEFAULT_CONFIDENCE_MARGIN).unwrap());
        assert!(!should_engage_cooperative(100.0, 110.0, DEFAULT_CONFIDENCE_MARGIN).unwrap());
    }

    #[test]
    fn margin_below_floor_is_rejected_not_clamped() {
        let err = should_engage_cooperative(1.0, 100.0, 0.049).unwrap_err();
        assert_eq!(err, SchedulerError::MarginTooLow { provided: 0.049 });
        assert!(should_engage_cooperative(1.0, 100.0, MIN_CONFIDENCE_MARGIN).unwrap());
        assert!(matches!(
            should_engage_cooperative(1.0, 100.0, 0.05 - f64::EPSILON * 8.0),
            Err(SchedulerError::MarginTooLow { .. })
        ));
    }

    #[test]
    fn three_distinct_peers_select_lowest_predicted_first() {
        let peers = [
            candidate("slow", 80.0, 200.0, 1.0, 0.2),
            candidate("middle", 40.0, 100.0, 2.0, 0.4),
            candidate("fast", 10.0, 20.0, 4.0, 1.0),
        ];
        let picked = select_microswarm(&peers, &profile(), 512, 256, 2);
        assert_eq!(picked.len(), 2);
        assert_eq!(picked[0].peer_id, "fast");
        assert_eq!(picked[1].peer_id, "middle");
    }

    #[test]
    fn measured_beats_advertised_when_they_contradict() {
        // Fake-fast advertiser: claims zero queue but is slow where it
        // matters (measured RTT + measured rates).
        let fake_fast = candidate("fake-fast", 200.0, 0.0, 0.5, 0.1);
        // Honest peer: advertises a real queue but measures fast everywhere.
        let honest = candidate("honest", 5.0, 100.0, 4.0, 1.0);
        let peers = [fake_fast.clone(), honest.clone()];
        let picked = select_microswarm(&peers, &profile(), 1024, 512, 8);
        assert_eq!(picked[0].peer_id, "honest");
        // The measured terms must dominate: honest wins despite the 100 ms
        // advertised queue versus the fake 0 ms.
        assert!(
            predicted_single_ms(&honest, 1024, 512) * 3.0
                < predicted_single_ms(&fake_fast, 1024, 512),
            "measured fields should dominate by a wide margin"
        );
    }

    /// F6 (Phase F gate): a candidate ADVERTISING 10× better throughput than
    /// the requester ever measured is still ranked by the measured values —
    /// advertised fields carry no token-rate term, so the lie changes
    /// nothing. Only the advertised queue moves the score, and 10× claims
    /// cannot outrank measured reality.
    #[test]
    fn ten_x_advertised_lies_never_outrank_measured_reality() {
        // The liar advertises a 0 ms queue; the honest peer 80 ms. The liar's
        // MEASURED decode is 10× worse (0.1 vs 1.0 tokens/ms) — exactly the
        // "advertise huge decode rate" abuse of docs/threat-model.md §6.
        let liar = candidate("liar-10x", 20.0, 0.0, 1.0, 0.1);
        let honest = candidate("honest", 30.0, 80.0, 2.0, 1.0);
        let peers = vec![liar.clone(), honest.clone()];
        let picked = select_microswarm(&peers, &profile(), 512, 1024, 2);
        assert_eq!(
            picked[0].peer_id, "honest",
            "measured decode/rtt must dominate advertised queue"
        );
        // And the dominance is exactly the measured term: predicted uses ONLY
        // measured rates, so swapping the advertised queues (0 <-> 80) cannot
        // flip the ordering.
        let swapped = [
            Candidate {
                advertised_queue_ms: 80.0,
                ..liar.clone()
            },
            Candidate {
                advertised_queue_ms: 0.0,
                ..honest.clone()
            },
        ];
        let picked_swapped = select_microswarm(&swapped, &profile(), 512, 1024, 2);
        assert_eq!(picked_swapped[0].peer_id, "honest");
        // Identity check: the formula is a pure function of the measured +
        // penalty fields once the advertised queue is equalized.
        let liar_norm = predicted_single_ms(
            &Candidate {
                advertised_queue_ms: 0.0,
                ..liar
            },
            512,
            1024,
        );
        let honest_norm = predicted_single_ms(
            &Candidate {
                advertised_queue_ms: 0.0,
                ..honest
            },
            512,
            1024,
        );
        assert!(
            honest_norm * 2.0 < liar_norm,
            "10x worse measured decode must cost more than any advertised queue can hide"
        );
    }

    /// F6/ADR-014 rule 4: the relayed NAT path scores strictly worse than
    /// the direct path all-else-equal; hole-punched sits between them; and a
    /// relayed candidate is demoted in selection even when its measured
    /// fields are marginally better (within the penalty).
    #[test]
    fn nat_path_penalty_orders_relayed_below_direct_all_else_equal() {
        let direct = candidate("direct", 20.0, 10.0, 2.0, 0.5);
        let punched = Candidate {
            nat_path: NatPath::HolePunched,
            ..candidate("punched", 20.0, 10.0, 2.0, 0.5)
        };
        let relayed = Candidate {
            nat_path: NatPath::Relayed,
            ..candidate("relayed", 20.0, 10.0, 2.0, 0.5)
        };

        // Monotone penalties.
        assert_eq!(nat_path_penalty_ms(NatPath::Direct), 0.0);
        assert!(nat_path_penalty_ms(NatPath::HolePunched) < nat_path_penalty_ms(NatPath::Relayed));

        // All-else-equal ordering: direct < hole-punched < relayed.
        let d = predicted_single_ms(&direct, 256, 128);
        let h = predicted_single_ms(&punched, 256, 128);
        let r = predicted_single_ms(&relayed, 256, 128);
        assert!(d < h, "direct {d} must beat hole-punched {h}");
        assert!(h < r, "hole-punched {h} must beat relayed {r}");
        assert!((r - d - RELAYED_PATH_PENALTY_MS).abs() < 1e-9);
        assert!((h - d - HOLEPUNCHED_PATH_PENALTY_MS).abs() < 1e-9);

        // Selection order flips only because of nat_path, and a relayed peer
        // with slightly better measured RTT still loses inside the penalty
        // band (the relay cost is priced in, ADR-014).
        let peers = vec![
            Candidate {
                nat_path: NatPath::Relayed,
                ..candidate("relayed-fast", 5.0, 0.0, 4.0, 1.0)
            },
            candidate("direct-slower", 20.0, 10.0, 2.0, 0.5),
        ];
        let picked = select_microswarm(&peers, &profile(), 64, 64, 2);
        assert_eq!(picked[0].peer_id, "relayed-fast"); // 15 ms better > 40 ms penalty
        let near_tie = vec![
            Candidate {
                nat_path: NatPath::Relayed,
                ..candidate("relayed-near", 35.0, 10.0, 2.0, 0.5)
            },
            candidate("direct-near", 20.0, 10.0, 2.0, 0.5),
        ];
        let picked = select_microswarm(&near_tie, &profile(), 64, 64, 2);
        assert_eq!(
            picked[0].peer_id, "direct-near",
            "a relayed peer only 15 ms 'better' on paper loses to the relay penalty"
        );
    }

    #[test]
    fn selection_filters_wrong_profile_slots_staleness_and_capacity() {
        let other_profile = ModelProfileId::new("msp:qwen3-4b:q8_0:v1").unwrap();
        let wrong_profile = Candidate {
            profile_id: other_profile,
            ..candidate("wrong-profile", 1.0, 0.0, 9.0, 9.0)
        };
        let no_slots = Candidate {
            slots: 0,
            ..candidate("no-slots", 1.0, 0.0, 9.0, 9.0)
        };
        let stale = Candidate {
            stale_advertisement_penalty_ms: MAX_STALE_ADVERTISEMENT_PENALTY_MS + 0.1,
            ..candidate("stale", 1.0, 0.0, 9.0, 9.0)
        };
        let good = candidate("good", 5.0, 0.0, 9.0, 9.0);
        let peers = [wrong_profile, no_slots, stale, good];
        let picked = select_microswarm(&peers, &profile(), 16, 16, 8);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].peer_id, "good");
    }

    #[test]
    fn selection_is_capped_at_eight_and_want() {
        let peers: Vec<Candidate> = (0..20)
            .map(|i| candidate(&format!("peer-{i:02}"), f64::from(i), 0.0, 1.0, 1.0))
            .collect();
        assert_eq!(select_microswarm(&peers, &profile(), 0, 0, 20).len(), 8);
        assert_eq!(select_microswarm(&peers, &profile(), 0, 0, 3).len(), 3);
        assert_eq!(select_microswarm(&peers, &profile(), 0, 0, 0).len(), 0);
    }

    #[test]
    fn tie_break_is_peer_id_and_selection_is_deterministic() {
        let peers = vec![
            candidate("delta", 10.0, 10.0, 2.0, 0.5),
            candidate("alpha", 10.0, 10.0, 2.0, 0.5),
            candidate("charlie", 10.0, 10.0, 2.0, 0.5),
            candidate("bravo", 10.0, 10.0, 2.0, 0.5),
        ];
        let first: Vec<&str> = select_microswarm(&peers, &profile(), 64, 64, 3)
            .iter()
            .map(|c| c.peer_id.as_str())
            .collect();
        let second: Vec<&str> = select_microswarm(&peers, &profile(), 64, 64, 3)
            .iter()
            .map(|c| c.peer_id.as_str())
            .collect();
        assert_eq!(first, vec!["alpha", "bravo", "charlie"]);
        assert_eq!(first, second, "identical inputs must select identically");
    }

    #[test]
    fn ewma_seeds_then_smooths_with_alpha_03() {
        let mut ewma = Ewma::default_alpha();
        assert_eq!(ewma.alpha(), EWMA_ALPHA);
        assert_eq!(ewma.value(), None);
        assert!((ewma.update(100.0) - 100.0).abs() < 1e-12);
        // 0.3 * 200 + 0.7 * 100 = 130
        assert!((ewma.update(200.0) - 130.0).abs() < 1e-12);
        // 0.3 * 0 + 0.7 * 130 = 91
        assert!((ewma.update(0.0) - 91.0).abs() < 1e-12);
        assert_eq!(ewma.value(), Some(91.0));
        // Repeated large observations converge toward the new level.
        for _ in 0..60 {
            ewma.update(1000.0);
        }
        assert!(ewma.value().unwrap() > 999.0);
    }

    #[test]
    fn ewma_alpha_is_bounded() {
        assert_eq!(Ewma::new(7.0).alpha(), 1.0);
        assert_eq!(Ewma::new(-1.0).alpha(), 0.0);
    }

    #[test]
    fn capacity_classes_order_weakest_to_strongest() {
        assert!(CapacityClass::Cpu < CapacityClass::GpuEntry);
        assert!(CapacityClass::GpuEntry < CapacityClass::GpuMid);
        assert!(CapacityClass::GpuMid < CapacityClass::GpuHigh);
    }

    /// ADR-032 §4 companion correction (option A): the verification term
    /// is capability-aware, ABSENT by default, and charges window+1
    /// sequential steps when the verifier has not declared the
    /// capability. Runs under DEFAULT features (execution-venue matrix
    /// item 4a: per-push, `modelswarm-scheduler`).
    #[test]
    fn verify_term_is_absent_by_default_and_charges_window_plus_one() {
        let verifier = candidate("v", 5.0, 0.0, 3.0, 0.10);
        assert!(!verifier.batch_verify, "capability defaults to ABSENT");
        assert_eq!(
            VerifyTerm::of_verifier(&verifier),
            VerifyTerm::SequentialWire
        );
        assert_eq!(
            VerifyTerm::of_verifier(&Candidate {
                batch_verify: true,
                ..verifier.clone()
            }),
            VerifyTerm::Batch
        );
        // The cohort term follows the VERIFIER (cohort[0]); proposers
        // never upgrade it, an empty cohort stays conservative.
        assert_eq!(
            VerifyTerm::of_cohort(std::slice::from_ref(&verifier)),
            VerifyTerm::SequentialWire
        );
        assert_eq!(VerifyTerm::of_cohort(&[]), VerifyTerm::SequentialWire);
        // Steps per round: window+1 sequential vs the caller's batch
        // coefficient — the (window+1)/1.5 ≈ 6× (w8) to 11× (w16) gap
        // pass 2 measured on the wire.
        assert!((VerifyTerm::SequentialWire.decode_steps_per_round(8, 1.5) - 9.0).abs() < 1e-12);
        assert!((VerifyTerm::SequentialWire.decode_steps_per_round(16, 1.5) - 17.0).abs() < 1e-12);
        assert!((VerifyTerm::Batch.decode_steps_per_round(8, 1.5) - 1.5).abs() < 1e-12);
        assert!((VerifyTerm::Batch.decode_steps_per_round(16, 1.5) - 1.5).abs() < 1e-12);
    }

    /// ADR-032 §4 companion correction, the decision logic (item 4a):
    /// an HTTP-only cohort NEVER engages — with the verifier of a cohort
    /// being the fastest eligible single's own peer class, the wire-true
    /// verification term alone already exceeds the single's whole decode
    /// budget — while a batch-DECLARED cohort engages exactly when
    /// `predicted × (1 + margin)` still beats that single.
    #[test]
    fn http_never_engages_and_batch_engages_only_beating_the_fastest_single() {
        // Pass-2 engagement-pool arithmetic (window 8, target 16,
        // acceptance 1.0 ⇒ 2 rounds; rtt 5 ms; prompt 153 tokens; V
        // decode 0.10 / prefill 3.0 = the cohort verifier AND the
        // fastest single; drafter decode 4.0).
        let verifier = candidate("v", 5.0, 0.0, 3.0, 0.10);
        let fastest_single = predicted_single_ms(&verifier, 153, 16);
        assert!((fastest_single - 216.0).abs() < 1e-9, "{fastest_single}");

        // Wire-true verification alone: 2 rounds × (8+1) / 0.10 = 180 ms,
        // already more than the single's ENTIRE decode term (160 ms) —
        // before any prefill/proposal/sync/rollback overhead.
        let wire_verify = 2.0 * VerifyTerm::SequentialWire.decode_steps_per_round(8, 1.5)
            / verifier.decode_tokens_per_ms;
        let single_decode = 16.0 / verifier.decode_tokens_per_ms;
        assert!(
            wire_verify > single_decode,
            "sequential verification alone must exceed the single's decode budget"
        );
        let wire_prediction = 2.0 * (153.0 + 4.0) / 3.0 /* prefix re-post */
            + 2.0 * 8.0 / 4.0 /* proposal */
            + wire_verify
            + 2.0 * 5.0 /* sync */
            + 0.0 /* rollback at acceptance 1.0 */
            + 5.0; /* failure risk (bench coefficient) */
        assert!(!should_engage_cooperative(wire_prediction, fastest_single, 0.15).unwrap());
        assert!(
            wire_prediction > fastest_single,
            "the wire-true prediction loses outright, before any margin"
        );

        // Batch-declared twin: 2 × 1.5 / 0.10 = 30 ms verification, one
        // prompt prefill per round — engages at the default margin, and
        // stops the moment the fastest single wins instead.
        let batch_verify =
            2.0 * VerifyTerm::Batch.decode_steps_per_round(8, 1.5) / verifier.decode_tokens_per_ms;
        assert!((batch_verify - 30.0).abs() < 1e-9);
        let batch_prediction = 2.0 * 153.0 / 3.0 + 2.0 * 8.0 / 4.0 + batch_verify + 10.0 + 5.0;
        assert!(should_engage_cooperative(batch_prediction, fastest_single, 0.15).unwrap());
        let faster_single = predicted_single_ms(
            &Candidate {
                decode_tokens_per_ms: 0.25,
                ..verifier.clone()
            },
            153,
            16,
        );
        assert!(!should_engage_cooperative(batch_prediction, faster_single, 0.15).unwrap());
    }
}
