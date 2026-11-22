//! Shadow-mode scheduler wiring (dependency-graph hard edge 11: "Shadow
//! planner BEFORE any acting planner — logs the plan it would choose and
//! never acts until 9.6 calibrates τ").
//!
//! This module joins the F15 measurement plumbing
//! (`modelswarm_transport::observe::PeerObservations`, filled by
//! `modelswarm_node::measure::PeerMetrics`) with the frozen ADR-013 cost
//! model ([`crate::select_microswarm`], [`crate::predicted_single_ms`]):
//!
//! - [`candidate_from_observations`] maps one roster row + its measured
//!   snapshot into a [`crate::Candidate`] (the mapping the audit's S1/S2
//!   asked for; measured fields dominate by construction of the frozen
//!   formula).
//! - [`shadow_decision`] ranks the roster the way the acting planner
//!   WOULD and returns a serializable decision record. Callers log it as
//!   telemetry; NOTHING here dials, selects, or otherwise acts.
//! - [`QueueDiscountPolicy`] is the reviewed advertised-vs-measured
//!   queue-depth discount (see the module-level policy statement below).
//!
//! # Honest limitations (labeled on every decision record)
//!
//! - **Profile-id type mismatch** (recorded): production ids are
//!   ADR-011 derived (`msp1:<64 hex>`); the frozen
//!   [`crate::Candidate`] carries the catalog-format [`ModelProfileId`].
//!   [`shadow_profile_id`] adapts deterministically and injectively so
//!   the exact-profile filter stays structurally satisfied; the proper
//!   API change belongs to the acting-wiring step.
//! - Prompt/output token counts are ESTIMATES from character counts
//!   ([`estimate_tokens_from_chars`]) — shadow predictions only, never a
//!   user-facing number.
//! - Jitter/loss/bandwidth have no fields yet (F15 measures jitter; loss
//!   is honestly unavailable —
//!   `modelswarm_transport::observe::QUINN_STATS_UNAVAILABLE`).
//! - `stale_advertisement_penalty_ms` is 0.0: roster freshness is not
//!   plumbed. `nat_path` is [`crate::NatPath::Direct`] for every
//!   candidate because production only dials direct QUIC multiaddrs
//!   until F2b lands.
//! - An unmeasured peer (no Usage-derived rates) has a non-positive
//!   token rate, so the frozen formula yields `INFINITY` and it ranks
//!   last — cold peers never outrank measured ones.
//!
//! # The advertised-vs-measured queue discount (reviewed decision)
//!
//! F15 records the peer-advertised `queueMs` alongside the MEASURED
//! admission-to-first-token (which contains network RTT + real serving
//! queue + prefill). Expanded-mission review §5: "advertised values are
//! untrusted inputs, not measurements". The conservative policy:
//!
//! 1. **Measured dominates**: the effective queue term is never allowed
//!    BELOW the measured estimate — a peer whose measurements show more
//!    queue than it advertises is charged the measured value (a liar
//!    advertising `0` cannot benefit from the lie).
//! 2. **Advertised only penalizes, never rewards**: relative to the
//!    measured-only baseline, an advertisement can only ADD delay
//!    (`effective = max(advertised_term, measured_term)`), never
//!    subtract. A cold peer (no measurements) is charged its full
//!    advertised value — claiming load is self-penalizing, claiming
//!    nothing costs nothing extra.
//! 3. Both terms are clamped to [`QueueDiscountPolicy::cap_ms`] (default
//!    120 000 ms = the gateway's maximum request deadline) so garbage
//!    advertisements stay finite; weights are clamped to `[0, 1]` so no
//!    experiment amplifies an untrusted input beyond its raw claim.
//!
//! Constants are env-tunable for the 9.6 pass-1 experiments
//! ([`QueueDiscountPolicy::from_env`]): weights `0` isolate one source,
//! `1` (the default) is the conservative shipped policy.

use crate::{select_microswarm, Candidate, CapacityClass, NatPath};
use modelswarm_transport::observe::PeerObservations;
use modelswarm_types::ModelProfileId;
use serde::{Deserialize, Serialize};

/// Label stamped on every shadow decision record — the no-action
/// contract is part of the data, not just the docs.
pub const SHADOW_LABEL: &str = "shadow-no-action";

/// Env var scaling the advertised queue term (default 1.0; clamped to
/// [0, 1]).
pub const ENV_QUEUE_ADVERTISED_WEIGHT: &str = "MSP_SHADOW_QUEUE_ADVERTISED_WEIGHT";
/// Env var scaling the measured queue estimate term (default 1.0;
/// clamped to [0, 1]).
pub const ENV_QUEUE_MEASURED_WEIGHT: &str = "MSP_SHADOW_QUEUE_MEASURED_WEIGHT";
/// Env var bounding the effective queue term in milliseconds (default
/// 120 000 — the gateway's maximum request deadline).
pub const ENV_QUEUE_CAP_MS: &str = "MSP_SHADOW_QUEUE_CAP_MS";

/// Failure penalty per recorded transport-level failure (dial, send,
/// dead stream, failed probe). Deterministic linear penalty — the same
/// heuristic family as the frozen ADR-014 path penalties, awaiting
/// calibration from shadow data (9.6).
pub const FAILURE_PENALTY_MS_PER_FAILURE: f64 = 50.0;

/// Coarse chars-per-token heuristic for the shadow-only token-count
/// estimate (real tokenization is the serving side's job; the shadow
/// planner must never gate on it).
pub const ESTIMATED_CHARS_PER_TOKEN: usize = 4;

/// The advertised-vs-measured queue discount policy (see the module-level
/// policy statement). Pure data; resolution happens in
/// [`QueueDiscountPolicy::effective_queue_ms`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct QueueDiscountPolicy {
    /// Scale on the advertised term, clamped to `[0, 1]`.
    pub advertised_weight: f64,
    /// Scale on the measured estimate term, clamped to `[0, 1]`.
    pub measured_weight: f64,
    /// Upper bound on the effective queue term (ms).
    pub cap_ms: f64,
}

impl QueueDiscountPolicy {
    /// The shipped conservative default: both sources at full weight,
    /// cap at the gateway's max request deadline.
    pub const DEFAULT: Self = Self {
        advertised_weight: 1.0,
        measured_weight: 1.0,
        cap_ms: 120_000.0,
    };

    /// Reads the env-tunable constants (see the `ENV_QUEUE_*` vars).
    /// Unset vars keep the default; unparsable or non-positive values
    /// keep the default for THAT var and produce a visible warning
    /// string the caller logs. Weights outside `[0, 1]` are clamped
    /// with a warning (never amplified).
    pub fn from_env() -> EnvPolicy {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Testable core of [`QueueDiscountPolicy::from_env`].
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> EnvPolicy {
        let mut policy = Self::DEFAULT;
        let mut warnings = Vec::new();
        let mut env_overrides = 0usize;

        let mut apply = |name: &str, target: &mut f64, is_weight: bool| {
            let Some(raw) = lookup(name) else { return };
            let trimmed = raw.trim().to_string();
            match trimmed.parse::<f64>() {
                Ok(value) if value.is_finite() => {
                    if is_weight {
                        if !(0.0..=1.0).contains(&value) {
                            warnings.push(format!(
                                "{name}={value} outside [0,1] — clamped \
                                 (untrusted inputs are never amplified)"
                            ));
                        }
                        *target = value.clamp(0.0, 1.0);
                    } else {
                        if value <= 0.0 {
                            warnings.push(format!("{name}={value} not positive — default kept"));
                            return;
                        }
                        *target = value;
                    }
                    env_overrides += 1;
                }
                Ok(_) | Err(_) => warnings.push(format!(
                    "{name}={trimmed:?} is not a finite number — default kept"
                )),
            }
        };

        apply(
            ENV_QUEUE_ADVERTISED_WEIGHT,
            &mut policy.advertised_weight,
            true,
        );
        apply(ENV_QUEUE_MEASURED_WEIGHT, &mut policy.measured_weight, true);
        apply(ENV_QUEUE_CAP_MS, &mut policy.cap_ms, false);

        EnvPolicy {
            policy,
            env_overrides,
            warnings,
        }
    }

    /// Resolves the discount for one candidate. The invariant:
    /// `effective_ms = clamp(max(w_adv · min(advertised, cap),
    /// w_meas · clamp(measured_estimate, 0, cap)), 0, cap)` — never below
    /// either term, never above the cap, never negative.
    #[must_use]
    pub fn effective_queue_ms(
        &self,
        advertised_ms: Option<u64>,
        measured_estimate_ms: Option<f64>,
    ) -> QueueDiscount {
        let cap = self.cap_ms.max(0.0);
        let advertised_term = advertised_ms
            .map(|a| self.advertised_weight.clamp(0.0, 1.0) * (a as f64).min(cap))
            .unwrap_or(0.0);
        let measured_term = measured_estimate_ms
            .map(|m| self.measured_weight.clamp(0.0, 1.0) * m.clamp(0.0, cap))
            .unwrap_or(0.0);
        QueueDiscount {
            advertised_raw_ms: advertised_ms.map(|a| a as f64),
            measured_estimate_ms,
            effective_ms: advertised_term.max(measured_term).min(cap),
        }
    }
}

/// Result of [`QueueDiscountPolicy::from_env`]: the resolved policy plus
/// honesty bookkeeping for the decision record and caller-side warnings.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvPolicy {
    /// The resolved policy.
    pub policy: QueueDiscountPolicy,
    /// How many env vars actually overrode a default (recorded on the
    /// decision so experiment runs are distinguishable from defaults).
    pub env_overrides: usize,
    /// Human-readable warnings for unparsable/clamped values; callers
    /// log these before the decision.
    pub warnings: Vec<String>,
}

/// One discount resolution, recorded per candidate for the 9.6 dataset.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct QueueDiscount {
    /// The raw advertised value, when the roster carried one.
    pub advertised_raw_ms: Option<f64>,
    /// The measured queue estimate, when measurements allowed one.
    pub measured_estimate_ms: Option<f64>,
    /// The term actually fed into [`crate::Candidate::advertised_queue_ms`].
    pub effective_ms: f64,
}

/// Requester-measured admission-queue estimate: the measured TTFT EWMA
/// minus the measured RTT EWMA minus the expected prefill of THIS
/// request's estimated prompt tokens. Missing TTT or RTT yields `None`
/// (cold peer — no measurement to dominate with). A missing prefill rate
/// subtracts nothing, making the estimate an upper bound — the
/// conservative direction for a penalty term.
#[must_use]
pub fn measured_queue_estimate(
    ttft_ewma_ms: Option<f64>,
    rtt_ewma_ms: Option<f64>,
    prompt_tokens: u32,
    prefill_tokens_per_ms: Option<f64>,
) -> Option<f64> {
    let ttft = ttft_ewma_ms?;
    let rtt = rtt_ewma_ms?;
    let prefill_ms = match prefill_tokens_per_ms {
        Some(rate) if rate > 0.0 => f64::from(prompt_tokens) / rate,
        _ => 0.0,
    };
    Some((ttft - rtt - prefill_ms).max(0.0))
}

/// Roster facts for one candidate peer, as the tracker lookup returned
/// them (untrusted inputs). Kept scheduler-local so this crate does not
/// depend on the tracker client.
#[derive(Debug, Clone, PartialEq)]
pub struct RosterFacts {
    /// libp2p `PeerId` string.
    pub peer_id: String,
    /// Advertised free serving slots.
    pub free_slots: u32,
    /// Advertised `queueMs` (untrusted input).
    pub advertised_queue_ms: Option<u64>,
    /// Roster `capacityClass` vocabulary (`cpu` | `gpu_entry` |
    /// `gpu_mid` | `gpu_high`); anything else maps to the conservative
    /// `cpu` (the eligibility floor — a mislabeled strong peer is never
    /// excluded, merely not boosted).
    pub capacity_class: Option<String>,
    /// Whether the roster carries a dialable direct QUIC multiaddr
    /// (production only dials direct addresses until F2b).
    pub has_direct_quic_addr: bool,
}

/// One shadow-planner input: a roster row joined with this requester's
/// F15 measurement snapshot for that peer.
#[derive(Debug, Clone, PartialEq)]
pub struct ShadowCandidateInput {
    /// The untrusted roster half.
    pub roster: RosterFacts,
    /// The measured half (requester-side EWMAs).
    pub observed: PeerObservations,
}

/// Adapt a production profile id into the frozen selector's
/// [`ModelProfileId`] type.
///
/// **Recorded type mismatch (to resolve at the acting-wiring step):**
/// production profile ids are ADR-011 derived ids (`msp1:<64 hex>`,
/// `modelswarm_types::manifest::PROFILE_ID_PREFIX`), which
/// `ModelProfileId::new` rejects — that type carries the catalog format
/// (`msp:family:quant:version`). Rather than unfreeze
/// [`crate::Candidate`] here, the shadow adapter hex-encodes the real id
/// into a guaranteed-valid catalog shape (`msp:s<hex>:x:v1`) —
/// deterministic and injective, so the frozen selector's exact-profile
/// filter remains structurally satisfied (every candidate of one lookup
/// maps to the same synthetic id; two different profiles can never
/// collide). Catalog-format ids pass through unchanged. Changing
/// `Candidate.profile_id` to the production id string is the reviewed
/// API change that belongs to the wiring step (M10 build item 5).
fn shadow_profile_id(profile: &str) -> Option<ModelProfileId> {
    if let Ok(direct) = ModelProfileId::new(profile) {
        return Some(direct);
    }
    let hex: String = profile.bytes().map(|b| format!("{b:02x}")).collect();
    ModelProfileId::new(format!("msp:s{hex}:x:v1")).ok()
}

/// A mapped candidate plus the discount details that shaped it — the
/// decision record needs both.
#[derive(Debug, Clone, PartialEq)]
pub struct MappedCandidate {
    /// The frozen-model candidate (safe to feed
    /// [`crate::select_microswarm`]).
    pub candidate: Candidate,
    /// How the advertised-vs-measured queue term was resolved.
    pub discount: QueueDiscount,
    /// Whether any requester measurement exists for this peer (RTT probe
    /// or completion).
    pub measured: bool,
}

/// Coarse prompt-token estimate from character count (~4 chars/token).
/// Shadow-only: it parameterizes a logged prediction, never a decision
/// that acts.
#[must_use]
pub fn estimate_tokens_from_chars(chars: usize) -> u32 {
    u32::try_from(chars.saturating_add(ESTIMATED_CHARS_PER_TOKEN - 1) / ESTIMATED_CHARS_PER_TOKEN)
        .unwrap_or(u32::MAX)
}

fn parse_capacity_class(raw: Option<&str>) -> CapacityClass {
    match raw {
        Some("gpu_entry") => CapacityClass::GpuEntry,
        Some("gpu_mid") => CapacityClass::GpuMid,
        Some("gpu_high") => CapacityClass::GpuHigh,
        // "cpu", unknown, and absent all stay at the eligibility floor.
        _ => CapacityClass::Cpu,
    }
}

/// Maps one roster row + measured snapshot into a frozen-model
/// [`Candidate`]. Returns `None` only when `profile` cannot be adapted
/// into a [`ModelProfileId`] (see [`shadow_profile_id`]; the caller logs
/// and skips the shadow entirely).
///
/// Unmeasured fields degrade conservatively: missing token rates stay at
/// `0.0` (the frozen formula turns them into `INFINITY`, ranking the
/// cold peer last); missing RTT stays at `0.0` (harmless — the rate
/// terms already dominate); each recorded failure adds
/// [`FAILURE_PENALTY_MS_PER_FAILURE`].
#[must_use]
pub fn candidate_from_observations(
    input: &ShadowCandidateInput,
    profile: &str,
    prompt_tokens: u32,
    policy: &QueueDiscountPolicy,
) -> Option<MappedCandidate> {
    let profile_id = shadow_profile_id(profile)?;
    let profile_obs = input.observed.profile(profile);
    let discount = policy.effective_queue_ms(
        input.roster.advertised_queue_ms,
        measured_queue_estimate(
            profile_obs.and_then(|p| p.ttft_ewma_ms),
            input.observed.rtt_ewma_ms,
            prompt_tokens,
            profile_obs.and_then(|p| p.prefill_tokens_per_ms_ewma),
        ),
    );
    let measured =
        input.observed.rtt_ewma_ms.is_some() || profile_obs.is_some_and(|p| p.completion_count > 0);
    Some(MappedCandidate {
        candidate: Candidate {
            peer_id: input.roster.peer_id.clone(),
            profile_id,
            measured_rtt_ms: input.observed.rtt_ewma_ms.unwrap_or(0.0),
            advertised_queue_ms: discount.effective_ms,
            prefill_tokens_per_ms: profile_obs
                .and_then(|p| p.prefill_tokens_per_ms_ewma)
                .unwrap_or(0.0),
            decode_tokens_per_ms: profile_obs
                .and_then(|p| p.decode_tokens_per_ms_ewma)
                .unwrap_or(0.0),
            failure_penalty_ms: FAILURE_PENALTY_MS_PER_FAILURE
                * input.observed.failure_count as f64,
            stale_advertisement_penalty_ms: 0.0,
            slots: input.roster.free_slots,
            capacity_class: parse_capacity_class(input.roster.capacity_class.as_deref()),
            nat_path: NatPath::Direct,
            // ADR-032 §4 companion correction: the batch-verify capability
            // is ABSENT until a peer actually declares it. The roster
            // carries no such disclosure today (a production declaration
            // surface would be the cooperative negotiation — ADR-032 §3's
            // `SessionAccept.engine.batch_verify`, not the tracker roster),
            // so every mapped candidate is charged the wire-true
            // sequential verification term by its consumers.
            batch_verify: false,
        },
        discount,
        measured,
    })
}

/// One ranked row of the decision record. `predicted_ms` is `None` when
/// the frozen formula yields infinity (unmeasured token rates) — JSON
/// cannot carry infinities, and "unusable prediction" is exactly the
/// honest value to record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowRankEntry {
    pub peer_id: String,
    /// [`crate::predicted_single_ms`] over the mapped candidate, `None`
    /// when infinite (cold peer).
    pub predicted_ms: Option<f64>,
    /// The raw advertised queue, when the roster carried one.
    pub advertised_queue_ms: Option<f64>,
    /// The measured queue estimate, when measurements allowed one.
    pub measured_queue_estimate_ms: Option<f64>,
    /// The queue term actually charged.
    pub effective_queue_ms: f64,
    /// Whether [`crate::select_microswarm`]'s eligibility filters pass
    /// (profile/slots/staleness/capacity).
    pub eligible: bool,
    /// Whether any requester measurement exists for this peer.
    pub measured: bool,
}

/// The policy actually used, recorded on every decision.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ShadowPolicyRecord {
    pub advertised_weight: f64,
    pub measured_weight: f64,
    pub cap_ms: f64,
    /// How many env overrides were applied (0 = pure defaults).
    pub env_overrides: usize,
}

impl From<&EnvPolicy> for ShadowPolicyRecord {
    fn from(env: &EnvPolicy) -> Self {
        Self {
            advertised_weight: env.policy.advertised_weight,
            measured_weight: env.policy.measured_weight,
            cap_ms: env.policy.cap_ms,
            env_overrides: env.env_overrides,
        }
    }
}

/// The full shadow decision: what the frozen cost model would choose
/// over the F15 measurements, next to what production actually chose.
/// Serializes to JSON for telemetry; carries timings, ids, and estimates
/// only (AGENTS.md rule 5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowDecision {
    /// Always [`SHADOW_LABEL`] — the no-action contract in the data.
    pub label: String,
    pub profile: String,
    /// Shadow-only token-count estimates (chars-derived).
    pub prompt_tokens_estimate: u32,
    pub output_tokens_estimate: u32,
    /// Dialable, not-self roster peers considered.
    pub candidate_count: usize,
    /// Candidates with any requester measurement (RTT or completion).
    pub measured_count: usize,
    /// The queue-discount policy in force.
    pub policy: ShadowPolicyRecord,
    /// Every considered candidate, fastest-predicted first (infinite
    /// predictions last, deterministic `peer_id` tie-break).
    pub ranked: Vec<ShadowRankEntry>,
    /// The peer [`crate::select_microswarm`] ranked first, `None` when
    /// no prediction is finite (insufficient measurement — recorded as
    /// such, never guessed alphabetically).
    pub pick: Option<String>,
    /// The production pick (`None` when production found nobody).
    pub production_pick: Option<String>,
    /// `Some(true/false)` when both sides picked; `None` when either
    /// side has no pick.
    pub agree: Option<bool>,
}

/// Computes the shadow decision over the mapped inputs. Pure: no I/O, no
/// env, no telemetry — callers log the result. `exclude_peer_id` is the
/// requester's own peer id (never rank yourself); `production_pick` is
/// the peer production actually chose, recorded for divergence
/// measurement.
#[must_use]
pub fn shadow_decision(
    inputs: &[ShadowCandidateInput],
    exclude_peer_id: &str,
    profile: &str,
    production_pick: Option<&str>,
    prompt_tokens: u32,
    output_tokens: u32,
    policy: &EnvPolicy,
) -> ShadowDecision {
    // Only peers production itself would consider dialing.
    let considered: Vec<&ShadowCandidateInput> = inputs
        .iter()
        .filter(|i| i.roster.peer_id != exclude_peer_id && i.roster.has_direct_quic_addr)
        .collect();
    let mapped: Vec<MappedCandidate> = considered
        .iter()
        .filter_map(|i| candidate_from_observations(i, profile, prompt_tokens, &policy.policy))
        .collect();
    let measured_count = mapped.iter().filter(|m| m.measured).count();

    // The frozen selector over the mapped candidates (want = 1: the
    // shadow's comparable decision against production's single pick).
    let candidates: Vec<Candidate> = mapped.iter().map(|m| m.candidate.clone()).collect();
    let picked = shadow_profile_id(profile)
        .map(|profile_id| {
            select_microswarm(&candidates, &profile_id, prompt_tokens, output_tokens, 1)
        })
        .unwrap_or_default();
    let pick_is_finite = picked
        .first()
        .is_some_and(|c| crate::predicted_single_ms(c, prompt_tokens, output_tokens).is_finite());
    let pick = if pick_is_finite {
        picked.first().map(|c| c.peer_id.clone())
    } else {
        // All predictions infinite (no measured token rates anywhere):
        // record insufficient measurement instead of an alphabetical
        // guess from the INFINITY tie-break.
        None
    };

    let mut ranked: Vec<ShadowRankEntry> = mapped
        .iter()
        .map(|m| {
            let predicted = crate::predicted_single_ms(&m.candidate, prompt_tokens, output_tokens);
            ShadowRankEntry {
                peer_id: m.candidate.peer_id.clone(),
                predicted_ms: predicted.is_finite().then_some(predicted),
                advertised_queue_ms: m.discount.advertised_raw_ms,
                measured_queue_estimate_ms: m.discount.measured_estimate_ms,
                effective_queue_ms: m.discount.effective_ms,
                eligible: m.candidate.slots > 0
                    && m.candidate.stale_advertisement_penalty_ms
                        <= crate::MAX_STALE_ADVERTISEMENT_PENALTY_MS
                    && m.candidate.capacity_class >= crate::MIN_CAPACITY_CLASS,
                measured: m.measured,
            }
        })
        .collect();
    ranked.sort_by(|a, b| {
        // `None` predictions are infinite (unmeasured rates) — rank last.
        let key = |e: &ShadowRankEntry| e.predicted_ms.unwrap_or(f64::INFINITY);
        key(a)
            .total_cmp(&key(b))
            .then_with(|| a.peer_id.cmp(&b.peer_id))
    });

    ShadowDecision {
        label: SHADOW_LABEL.to_string(),
        profile: profile.to_string(),
        prompt_tokens_estimate: prompt_tokens,
        output_tokens_estimate: output_tokens,
        candidate_count: mapped.len(),
        measured_count,
        policy: ShadowPolicyRecord::from(policy),
        ranked,
        pick: pick.clone(),
        production_pick: production_pick.map(str::to_string),
        agree: match (pick.as_deref(), production_pick) {
            (Some(s), Some(p)) => Some(s == p),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use modelswarm_transport::observe::ProfileObservations;

    fn profile() -> &'static str {
        "msp:qwen3-4b:q4_k_m:v1"
    }

    fn env_policy(policy: QueueDiscountPolicy) -> EnvPolicy {
        EnvPolicy {
            policy,
            env_overrides: 0,
            warnings: Vec::new(),
        }
    }

    fn input(peer: &str, slots: u32, advertised: Option<u64>) -> ShadowCandidateInput {
        ShadowCandidateInput {
            roster: RosterFacts {
                peer_id: peer.to_string(),
                free_slots: slots,
                advertised_queue_ms: advertised,
                capacity_class: Some("gpu_mid".into()),
                has_direct_quic_addr: true,
            },
            observed: PeerObservations {
                peer_id: peer.to_string(),
                ..Default::default()
            },
        }
    }

    /// Attach a fully-measured profile: fast rates, small TTFT.
    fn measured(mut input: ShadowCandidateInput, ttft: f64) -> ShadowCandidateInput {
        input.observed.rtt_ewma_ms = Some(5.0);
        input.observed.rtt_probe_count = 3;
        input.observed.profiles = vec![ProfileObservations {
            profile_id: profile().to_string(),
            ttft_ewma_ms: Some(ttft),
            itl_mean_ewma_ms: Some(10.0),
            total_ewma_ms: Some(ttft + 400.0),
            prefill_tokens_per_ms_ewma: Some(2.0),
            decode_tokens_per_ms_ewma: Some(0.5),
            advertised_queue_ms_last: input.roster.advertised_queue_ms,
            completion_count: 4,
            last_completion_unix_ms: Some(1),
        }];
        input
    }

    // ---- discount policy ----

    #[test]
    fn measured_dominates_when_peer_underadvertises() {
        // The liar claims 0 queue; measurements show 400 ms of admission
        // delay. The lie must not help.
        let d = QueueDiscountPolicy::DEFAULT.effective_queue_ms(Some(0), Some(400.0));
        assert!((d.effective_ms - 400.0).abs() < 1e-9);
        assert_eq!(d.advertised_raw_ms, Some(0.0));
        assert_eq!(d.measured_estimate_ms, Some(400.0));
    }

    #[test]
    fn advertised_only_ever_penalizes_never_rewards() {
        // Advertised above measured: the advertisement keeps its penalty
        // (max, not min) — claiming load is self-penalizing.
        let d = QueueDiscountPolicy::DEFAULT.effective_queue_ms(Some(500), Some(100.0));
        assert!((d.effective_ms - 500.0).abs() < 1e-9);
        // And the effective term is never below either source (the
        // larger bound subsumes the smaller).
        let d = QueueDiscountPolicy::DEFAULT.effective_queue_ms(Some(120), Some(90.0));
        assert!(d.effective_ms >= 120.0 - 1e-9);
    }

    #[test]
    fn cold_peer_is_charged_the_full_advertisement() {
        let d = QueueDiscountPolicy::DEFAULT.effective_queue_ms(Some(300), None);
        assert!((d.effective_ms - 300.0).abs() < 1e-9);
        // Nothing advertised, nothing measured: zero — no invented term.
        let d = QueueDiscountPolicy::DEFAULT.effective_queue_ms(None, None);
        assert!((d.effective_ms - 0.0).abs() < 1e-9);
        assert_eq!(d.advertised_raw_ms, None);
        assert_eq!(d.measured_estimate_ms, None);
    }

    #[test]
    fn garbage_advertisement_is_capped() {
        let d = QueueDiscountPolicy::DEFAULT.effective_queue_ms(Some(u64::MAX), None);
        assert!((d.effective_ms - 120_000.0).abs() < 1e-9);
    }

    #[test]
    fn weights_isolate_sources_for_experiments() {
        let pure_measured = QueueDiscountPolicy {
            advertised_weight: 0.0,
            ..QueueDiscountPolicy::DEFAULT
        };
        let d = pure_measured.effective_queue_ms(Some(999), Some(50.0));
        assert!((d.effective_ms - 50.0).abs() < 1e-9, "advertised ignored");
        let pure_advertised = QueueDiscountPolicy {
            measured_weight: 0.0,
            ..QueueDiscountPolicy::DEFAULT
        };
        let d = pure_advertised.effective_queue_ms(Some(999), Some(50.0));
        assert!((d.effective_ms - 999.0).abs() < 1e-9, "measured ignored");
    }

    // ---- measured queue estimate ----

    #[test]
    fn measured_queue_estimate_subtracts_rtt_and_prefill() {
        // TTFT 310 = RTT 10 + prefill 200 + queue 100.
        let est = measured_queue_estimate(Some(310.0), Some(10.0), 400, Some(2.0));
        assert!((est.unwrap() - 100.0).abs() < 1e-9);
        // Missing prefill rate: upper bound (nothing subtracted).
        let est = measured_queue_estimate(Some(310.0), Some(10.0), 400, None);
        assert!((est.unwrap() - 300.0).abs() < 1e-9);
        // Never negative.
        let est = measured_queue_estimate(Some(10.0), Some(50.0), 0, Some(2.0));
        assert!((est.unwrap() - 0.0).abs() < 1e-9);
        // Cold peer: no estimate at all.
        assert_eq!(
            measured_queue_estimate(None, Some(5.0), 10, Some(2.0)),
            None
        );
        assert_eq!(
            measured_queue_estimate(Some(5.0), None, 10, Some(2.0)),
            None
        );
    }

    // ---- mapping ----

    #[test]
    fn mapping_carries_measured_fields_and_discount() {
        let i = measured(input("p1", 2, Some(120)), 300.0);
        let m = candidate_from_observations(&i, profile(), 512, &QueueDiscountPolicy::DEFAULT)
            .expect("valid profile maps");
        assert_eq!(m.candidate.peer_id, "p1");
        assert!((m.candidate.measured_rtt_ms - 5.0).abs() < 1e-9);
        assert!((m.candidate.prefill_tokens_per_ms - 2.0).abs() < 1e-9);
        assert!((m.candidate.decode_tokens_per_ms - 0.5).abs() < 1e-9);
        assert_eq!(m.candidate.slots, 2);
        assert_eq!(m.candidate.failure_penalty_ms, 0.0);
        assert!(m.measured);
        // Queue discount: measured estimate = 300 - 5 - 512/2 = 39 < 120
        // advertised → effective stays 120 (advertised keeps its penalty).
        assert!((m.discount.measured_estimate_ms.unwrap() - 39.0).abs() < 1e-9);
        assert!((m.candidate.advertised_queue_ms - 120.0).abs() < 1e-9);
        // Direct QUIC roster → no NAT penalty charged.
        assert_eq!(m.candidate.nat_path, NatPath::Direct);
        // ADR-032 §4: the batch-verify capability is ABSENT — the roster
        // has no declaration surface, so mapped candidates must never
        // claim it.
        assert!(!m.candidate.batch_verify);
    }

    #[test]
    fn unmeasured_peer_maps_to_zero_rates_and_failure_penalty() {
        let mut i = input("cold", 1, Some(80));
        i.observed.failure_count = 3;
        let m = candidate_from_observations(&i, profile(), 64, &QueueDiscountPolicy::DEFAULT)
            .expect("maps");
        assert_eq!(m.candidate.prefill_tokens_per_ms, 0.0);
        assert_eq!(m.candidate.decode_tokens_per_ms, 0.0);
        assert_eq!(m.candidate.measured_rtt_ms, 0.0);
        assert!((m.candidate.failure_penalty_ms - 150.0).abs() < 1e-9); // 3 × 50
        assert!((m.candidate.advertised_queue_ms - 80.0).abs() < 1e-9); // cold → full advertised
        assert!(!m.measured);
        // Zero rates ⇒ infinite prediction (ranks last in the frozen model).
        assert!(crate::predicted_single_ms(&m.candidate, 64, 32).is_infinite());
    }

    #[test]
    fn profile_id_adapter_passes_catalog_format_and_adapts_derived_ids() {
        // Catalog format passes through unchanged.
        let direct = shadow_profile_id("msp:qwen3-4b:q4_k_m:v1").expect("parses");
        assert_eq!(direct.as_str(), "msp:qwen3-4b:q4_k_m:v1");
        // ADR-011 derived ids (the PRODUCTION shape) adapt
        // deterministically and injectively — different profiles never
        // collide, so the frozen exact-profile filter keeps its meaning.
        let derived = "msp1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let a = shadow_profile_id(derived).expect("adapts");
        let b = shadow_profile_id(derived).expect("adapts");
        assert_eq!(a, b, "deterministic");
        let other = shadow_profile_id(
            "msp1:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("adapts");
        assert_ne!(a, other, "injective");
        assert!(a.as_str().starts_with("msp:s"));
        // The mapping works end-to-end for a derived id: the candidate
        // carries the SAME adapted id the selector will filter on.
        let i = input("p1", 2, None);
        let m = candidate_from_observations(&i, derived, 8, &QueueDiscountPolicy::DEFAULT)
            .expect("derived profile maps");
        assert_eq!(m.candidate.profile_id, a);
    }

    #[test]
    fn capacity_class_vocabulary_maps_conservatively() {
        let mut i = input("p1", 1, None);
        for (raw, expected) in [
            (Some("cpu"), CapacityClass::Cpu),
            (Some("gpu_entry"), CapacityClass::GpuEntry),
            (Some("gpu_mid"), CapacityClass::GpuMid),
            (Some("gpu_high"), CapacityClass::GpuHigh),
            (Some("quantum"), CapacityClass::Cpu),
            (None, CapacityClass::Cpu),
        ] {
            i.roster.capacity_class = raw.map(str::to_string);
            let m = candidate_from_observations(&i, profile(), 8, &QueueDiscountPolicy::DEFAULT)
                .unwrap();
            assert_eq!(m.candidate.capacity_class, expected, "raw={raw:?}");
        }
    }

    // ---- decision ----

    #[test]
    fn shadow_picks_measured_fastest_over_roster_order() {
        // Production semantics: first-found (roster order). The measured
        // fast peer is SECOND in the roster.
        let inputs = vec![
            input("aaa-first-found", 2, Some(0)), // alphabetically first, cold
            measured(input("zzz-measured-fast", 2, Some(10)), 50.0),
        ];
        let decision = shadow_decision(
            &inputs,
            "own-peer",
            profile(),
            Some("aaa-first-found"),
            256,
            128,
            &env_policy(QueueDiscountPolicy::DEFAULT),
        );
        assert_eq!(decision.pick.as_deref(), Some("zzz-measured-fast"));
        assert_eq!(decision.production_pick.as_deref(), Some("aaa-first-found"));
        assert_eq!(decision.agree, Some(false));
        assert_eq!(decision.candidate_count, 2);
        assert_eq!(decision.measured_count, 1);
        assert_eq!(decision.label, SHADOW_LABEL);
        // Ranking: finite prediction first, infinite last.
        assert_eq!(decision.ranked[0].peer_id, "zzz-measured-fast");
        assert!(decision.ranked[0].predicted_ms.is_some());
        assert_eq!(decision.ranked[1].peer_id, "aaa-first-found");
        assert_eq!(decision.ranked[1].predicted_ms, None);
        assert!(!decision.ranked[1].measured);
        assert!(decision.ranked.iter().all(|r| r.eligible));
    }

    #[test]
    fn agreement_detected_when_both_pick_the_same_peer() {
        let inputs = vec![
            measured(input("fast", 2, Some(0)), 40.0),
            input("slow-cold", 2, Some(0)),
        ];
        let decision = shadow_decision(
            &inputs,
            "own",
            profile(),
            Some("fast"),
            64,
            64,
            &env_policy(QueueDiscountPolicy::DEFAULT),
        );
        assert_eq!(decision.pick.as_deref(), Some("fast"));
        assert_eq!(decision.agree, Some(true));
    }

    #[test]
    fn all_cold_roster_records_insufficient_measurement_not_a_guess() {
        let inputs = vec![input("aaa", 2, Some(0)), input("bbb", 2, Some(0))];
        let decision = shadow_decision(
            &inputs,
            "own",
            profile(),
            Some("aaa"),
            64,
            64,
            &env_policy(QueueDiscountPolicy::DEFAULT),
        );
        assert_eq!(decision.pick, None, "no finite prediction ⇒ no pick");
        assert_eq!(decision.measured_count, 0);
        assert!(decision.ranked.iter().all(|r| r.predicted_ms.is_none()));
        assert_eq!(decision.agree, None);
    }

    #[test]
    fn own_peer_and_undialable_addresses_are_excluded() {
        let inputs = vec![
            measured(input("own-peer", 2, Some(0)), 40.0),
            {
                let mut i = measured(input("no-addr", 2, Some(0)), 40.0);
                i.roster.has_direct_quic_addr = false;
                i
            },
            {
                let mut i = measured(input("no-slots", 0, Some(0)), 40.0);
                i.roster.free_slots = 0;
                i
            },
            measured(input("real", 1, Some(0)), 60.0),
        ];
        let decision = shadow_decision(
            &inputs,
            "own-peer",
            profile(),
            Some("real"),
            64,
            64,
            &env_policy(QueueDiscountPolicy::DEFAULT),
        );
        assert_eq!(decision.candidate_count, 2); // own peer + no-addr filtered
        let ids: Vec<&str> = decision.ranked.iter().map(|r| r.peer_id.as_str()).collect();
        assert!(!ids.contains(&"own-peer"));
        assert!(!ids.contains(&"no-addr"));
        // no-slots stays visible but is ineligible.
        let no_slots = decision
            .ranked
            .iter()
            .find(|r| r.peer_id == "no-slots")
            .unwrap();
        assert!(!no_slots.eligible);
        assert_eq!(decision.pick.as_deref(), Some("real"));
    }

    #[test]
    fn failure_penalty_can_demote_a_measured_peer() {
        // Same measurements, but one peer has 20 recorded failures
        // (20 × 50 ms = 1000 ms penalty) — the clean peer wins.
        let mut flaky = measured(input("flaky", 2, Some(0)), 40.0);
        flaky.observed.failure_count = 20;
        let clean = measured(input("clean", 2, Some(0)), 40.0);
        let decision = shadow_decision(
            &[flaky, clean],
            "own",
            profile(),
            Some("flaky"),
            128,
            128,
            &env_policy(QueueDiscountPolicy::DEFAULT),
        );
        assert_eq!(decision.pick.as_deref(), Some("clean"));
    }

    // ---- serialization (telemetry shape) ----

    #[test]
    fn decision_serializes_with_finite_numbers_only() {
        let inputs = vec![
            measured(input("m1", 2, Some(120)), 300.0),
            input("cold", 2, Some(90)),
        ];
        let decision = shadow_decision(
            &inputs,
            "own",
            profile(),
            Some("m1"),
            256,
            128,
            &env_policy(QueueDiscountPolicy::DEFAULT),
        );
        let json = serde_json::to_string(&decision).expect("serializes");
        assert!(json.contains("\"label\":\"shadow-no-action\""));
        // Production also picked m1 here (it is first in roster order AND
        // the only measured peer) — the agreement flag is data, not dogma.
        assert!(json.contains("\"agree\":true"));
        assert!(json.contains("\"predicted_ms\":null"), "infinity is null");
        assert!(!json.contains("infinity") && !json.contains("NaN"));
        let back: ShadowDecision = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(back, decision);
    }

    // ---- env policy ----

    #[test]
    fn env_policy_defaults_when_unset_and_parses_overrides() {
        // Pure lookup — no process env touched (tests run in parallel).
        let unset = QueueDiscountPolicy::from_lookup(|_| None);
        assert_eq!(unset.policy, QueueDiscountPolicy::DEFAULT);
        assert_eq!(unset.env_overrides, 0);
        assert!(unset.warnings.is_empty());

        let vars = [
            (ENV_QUEUE_ADVERTISED_WEIGHT, "0.0".to_string()),
            (ENV_QUEUE_MEASURED_WEIGHT, "0.5".to_string()),
            (ENV_QUEUE_CAP_MS, "30000".to_string()),
        ];
        let set = QueueDiscountPolicy::from_lookup(|name| {
            vars.iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.clone())
        });
        assert_eq!(set.env_overrides, 3);
        assert!((set.policy.advertised_weight - 0.0).abs() < 1e-9);
        assert!((set.policy.measured_weight - 0.5).abs() < 1e-9);
        assert!((set.policy.cap_ms - 30_000.0).abs() < 1e-9);
        assert!(set.warnings.is_empty());
        // The record distinguishes env runs from defaults.
        let record = ShadowPolicyRecord::from(&set);
        assert_eq!(record.env_overrides, 3);
    }

    #[test]
    fn env_policy_clamps_and_warns_on_garbage() {
        let vars = [
            (ENV_QUEUE_ADVERTISED_WEIGHT, "7".to_string()), // > 1: clamped
            (ENV_QUEUE_MEASURED_WEIGHT, "not-a-number".to_string()), // default kept
            (ENV_QUEUE_CAP_MS, "-5".to_string()),           // non-positive: default kept
        ];
        let set = QueueDiscountPolicy::from_lookup(|name| {
            vars.iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.clone())
        });
        assert!(
            (set.policy.advertised_weight - 1.0).abs() < 1e-9,
            "clamped to 1"
        );
        assert!(
            (set.policy.measured_weight - QueueDiscountPolicy::DEFAULT.measured_weight).abs()
                < 1e-9
        );
        assert!((set.policy.cap_ms - QueueDiscountPolicy::DEFAULT.cap_ms).abs() < 1e-9);
        assert_eq!(set.warnings.len(), 3);
        assert!(set.warnings.iter().any(|w| w.contains("outside [0,1]")));
        assert!(set
            .warnings
            .iter()
            .any(|w| w.contains("not a finite number")));
        assert!(set.warnings.iter().any(|w| w.contains("not positive")));
    }

    // ---- estimator ----

    #[test]
    fn token_estimator_is_coarse_and_saturating() {
        assert_eq!(estimate_tokens_from_chars(0), 0);
        assert_eq!(estimate_tokens_from_chars(1), 1);
        assert_eq!(estimate_tokens_from_chars(4), 1);
        assert_eq!(estimate_tokens_from_chars(5), 2);
        assert_eq!(estimate_tokens_from_chars(400), 100);
        assert_eq!(estimate_tokens_from_chars(usize::MAX), u32::MAX);
    }
}
