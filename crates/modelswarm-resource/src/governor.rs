//! The M2 resource governor (ADR-035): the runtime ENFORCEMENT authority
//! for gate D11's 70% ceiling. The desktop's v0.2.23 advisory check
//! (`family_resource_verdict`, weights-only projection, unobservable inputs
//! pass with a logged gap) becomes a CONSUMER of this module's verdict —
//! the numbers move from the desktop into the Resource Engineer's crate
//! and gain enforcement-grade semantics:
//!
//! 1. **Fail closed.** A governor that cannot observe an input a required
//!    check depends on does NOT pass-with-gap: it degrades the optional
//!    tier ([`Decision::Degrade`]) with an explicit reason. Advisory code
//!    may pass with a gap; enforcement may not (master prompt §2, gate
//!    D11). Degrading the FAMILY TIER never touches primary serving.
//! 2. **Honest KV.** The projection is `used + weights + kv` when the
//!    caller can compute the added copy's KV/context overhead from the
//!    runtime's context policy, and `used + weights` otherwise — the
//!    missing term is recorded as an explicit [`KnowledgeGap::KvUnmodeled`]
//!    in the verdict, never a guessed number. (The runtime's capi adapter
//!    has a capacity-based estimator — `2 × n_layer × n_ctx × n_head_kv ×
//!    head_dim × 2 B` — and a live `kv_usage()` report; the HTTP sidecar
//!    has neither per-handle. Today's desktop swap passes `None`; see the
//!    ADR for the mapping rules.)
//! 3. **Enforcement in depth.** On [`Decision::Admit`] the governor can
//!    ARM an OS-level committed-memory cap over the supervised engine
//!    tree through the [`crate::enforce`] seam — on Windows the
//!    kill-on-close job objects already owned by `modelswarm-winjob`
//!    (`JOB_OBJECT_LIMIT_PROCESSMEMORY`), so a runaway engine hits the
//!    cap instead of freezing the machine. Platforms without a wired
//!    seam carry the honest `not_enforced_unsupported_platform` label.
//!
//! The 70%-vs-90% reconciliation (gate D11): the RECOMMENDATION side may
//! advise up to its own bar — the desktop model picker's 0.90 headroom
//! gate (`fit_and_score`) is the live example — while the runtime governor
//! enforces [`ENFORCED_CEILING_PERCENT`] = 70 for coexistence decisions
//! (family enablement today; contribution admission later). No advisory
//! output can relax the enforced number; the enforced number never
//! pretends to be a fit recommendation.

use crate::enforce::{CeilingEnforcer, EnforcementRecord};
use crate::source::SampleSource;
use crate::ResourceSampler;

/// The enforced ceiling, percent of total (gate D11 / ADR-035): the
/// runtime governor's single authority number for memory coexistence
/// decisions. Supersedes the desktop-side `FAMILY_RESOURCE_CEILING_PERCENT`
/// (same value, advisory-grade) once the call-site swap lands.
pub const ENFORCED_CEILING_PERCENT: u64 = 70;

/// The recommendation side's own bar (desktop `fit_and_score` headroom
/// gate, 0.90): documented here ONLY as the D11 reconciliation anchor —
/// this constant is NOT enforced by the governor and must never be used
/// in an [`crate::governor`] decision path. A recommender may advise up
/// to 90%; the governor still enforces 70 at runtime.
pub const RECOMMENDATION_BAR_CEILING_PERCENT: u64 = 90;

/// The admission being judged: ONE added resident copy of a model (the
/// family tier's in-process verify engine next to the serving sidecar —
/// the same shape any future coexistence admission takes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionRequest {
    /// Bytes of model weights the admission would add (file size of the
    /// GGUF artifact the second engine will map).
    pub added_weights_bytes: u64,
    /// KV/context overhead of the added copy, when the caller can compute
    /// it from the runtime's context policy (capacity-based estimate).
    /// `None` = not modeled: the projection degrades to weights-only and
    /// the verdict carries [`KnowledgeGap::KvUnmodeled`] — an explicit
    /// gap, never a guessed number.
    pub added_kv_bytes: Option<u64>,
    /// True when the added copy's footprint lands in VRAM (the serving
    /// backend is GPU/vulkan, so both copies double in dedicated VRAM).
    /// When true, the VRAM ceiling check runs and requires both live VRAM
    /// usage and static VRAM geometry.
    pub added_copy_lands_in_vram: bool,
    /// Total dedicated VRAM from the M1 hardware profile
    /// ([`crate::profile::HardwareProfile`] / the desktop's
    /// `--list-devices` detection), bytes. Required when
    /// `added_copy_lands_in_vram` is true; ignored otherwise.
    pub vram_total_bytes: Option<u64>,
    /// Arm the OS-level committed-memory cap over the supervised engine
    /// tree on Admit (enforcement in depth, ADR-035 §3). When false the
    /// verdict is still binding for the admission decision; the
    /// enforcement record says `not_enforced_caller_opted_out`.
    pub arm_tree_commit_cap: bool,
}

/// One memory domain's exact numbers (bytes) — the evidence behind a
/// verdict, rendered verbatim in [`GovernorVerdict::detail_line`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DomainNumbers {
    /// Total capacity of the domain (system RAM or dedicated VRAM).
    pub total_bytes: u64,
    /// Bytes in use before the admission (live sample).
    pub used_bytes: u64,
    /// Bytes the admission would add (weights + modeled KV).
    pub added_bytes: u64,
    /// `used + added`, saturating.
    pub projected_bytes: u64,
    /// `total * ENFORCED_CEILING_PERCENT / 100`, saturating.
    pub ceiling_bytes: u64,
}

impl DomainNumbers {
    /// Builds the domain's numbers from a live reading. Saturating
    /// throughout: inconsistent counters clamp rather than wrap.
    pub fn project(total_bytes: u64, used_bytes: u64, added_bytes: u64) -> Self {
        let projected_bytes = used_bytes.saturating_add(added_bytes);
        let ceiling_bytes = total_bytes.saturating_mul(ENFORCED_CEILING_PERCENT) / 100;
        Self {
            total_bytes,
            used_bytes,
            added_bytes,
            projected_bytes,
            ceiling_bytes,
        }
    }

    /// The D11 breach test: strictly greater than the ceiling degrades;
    /// exactly-at-ceiling admits (parity with the desktop's `>` compare).
    pub fn breaches(&self) -> bool {
        self.projected_bytes > self.ceiling_bytes
    }
}

/// Why an admission degraded. Carries the exact numbers so telemetry and
/// the UI never have to re-derive them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradeReason {
    /// `added_weights_bytes == 0` — not a valid admission; a caller bug
    /// surfaced as a degrade, not a panic.
    WeightsNotPositive,
    /// System RAM used/total unobservable: the ceiling CANNOT be enforced,
    /// so the optional tier degrades (fail closed — the advisory-era
    /// pass-with-gap does not survive enforcement).
    RamUnobservable,
    /// The added copy lands in VRAM but live VRAM usage is unobservable
    /// (no PDH GPU counters): fail closed.
    VramUnobservable,
    /// The added copy lands in VRAM but no total-VRAM geometry exists (no
    /// M1 GPU detection): fail closed.
    VramTotalUnknown,
    /// System RAM projection exceeds the enforced ceiling.
    RamProjectionBreachesCeiling(DomainNumbers),
    /// VRAM projection exceeds the enforced ceiling (only possible when
    /// `added_copy_lands_in_vram`).
    VramProjectionBreachesCeiling(DomainNumbers),
}

impl DegradeReason {
    /// Stable machine label for telemetry/UI routing (frozen vocabulary,
    /// ADR-035 §5).
    pub fn label(&self) -> &'static str {
        match self {
            DegradeReason::WeightsNotPositive => "weights_not_positive",
            DegradeReason::RamUnobservable => "ram_unobservable",
            DegradeReason::VramUnobservable => "vram_unobservable",
            DegradeReason::VramTotalUnknown => "vram_total_unknown",
            DegradeReason::RamProjectionBreachesCeiling(_) => "ram_ceiling",
            DegradeReason::VramProjectionBreachesCeiling(_) => "vram_ceiling",
        }
    }

    /// Human-readable one-liner (desktop `FamilyStatus::off_detail`
    /// parity for the breach cases; new honest lines for the
    /// fail-closed cases).
    pub fn detail(&self) -> String {
        let mb = |b: u64| b / 1_000_000;
        match self {
            DegradeReason::WeightsNotPositive => {
                "added weights bytes is zero — not a valid admission request".to_string()
            }
            DegradeReason::RamUnobservable => format!(
                "system RAM usage unobservable — the {}% ceiling cannot be enforced; degrading (fail closed, never a guessed pass)",
                ENFORCED_CEILING_PERCENT
            ),
            DegradeReason::VramUnobservable => format!(
                "VRAM usage unobservable while the added copy lands in VRAM — the {}% ceiling cannot be enforced; degrading (fail closed)",
                ENFORCED_CEILING_PERCENT
            ),
            DegradeReason::VramTotalUnknown => format!(
                "total VRAM unknown (no GPU geometry) while the added copy lands in VRAM — the {}% ceiling cannot be enforced; degrading (fail closed)",
                ENFORCED_CEILING_PERCENT
            ),
            DegradeReason::RamProjectionBreachesCeiling(n) => format!(
                "system RAM: projected {}/{} MB would pass the {}% ceiling ({} MB in use + the verify engine's {} MB copy)",
                mb(n.projected_bytes),
                mb(n.total_bytes),
                ENFORCED_CEILING_PERCENT,
                mb(n.used_bytes),
                mb(n.added_bytes)
            ),
            DegradeReason::VramProjectionBreachesCeiling(n) => format!(
                "VRAM: projected {}/{} MB would pass the {}% ceiling ({} MB in use + the verify engine's {} MB copy)",
                mb(n.projected_bytes),
                mb(n.total_bytes),
                ENFORCED_CEILING_PERCENT,
                mb(n.used_bytes),
                mb(n.added_bytes)
            ),
        }
    }
}

/// An explicit knowledge gap recorded in a verdict — something the
/// projection could NOT observe and therefore did NOT include. A gap is
/// reported, never papered over with an estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnowledgeGap {
    /// The added copy's KV/context overhead is not modeled: the caller
    /// could not compute it from the runtime's context policy at decision
    /// time, so the projection is weights-only. The real footprint is
    /// HIGHER than projected by the unmodeled KV amount.
    KvUnmodeled,
}

impl KnowledgeGap {
    /// Stable machine label (telemetry).
    pub fn label(&self) -> &'static str {
        match self {
            KnowledgeGap::KvUnmodeled => "kv_unmodeled",
        }
    }
}

/// The numbers behind a verdict, per domain that actually ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerdictNumbers {
    /// The enforced ceiling percent in effect (audit trail).
    pub ceiling_percent: u64,
    /// System RAM numbers (always present unless the request was invalid
    /// or RAM was unobservable — check the reason).
    pub ram: Option<DomainNumbers>,
    /// VRAM numbers (present only when `added_copy_lands_in_vram` and the
    /// inputs were observable).
    pub vram: Option<DomainNumbers>,
}

/// The governor's binding answer to an [`AdmissionRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernorVerdict {
    /// The decision. [`Decision::Admit`] binds the enablement;
    /// [`Decision::Degrade`] must turn the optional tier off at the
    /// consumer (the desktop swap maps it to
    /// `FamilyStatus::off_detail("resource_ceiling", …)`).
    pub decision: Decision,
    /// The degrade reason, when degraded.
    pub reason: Option<DegradeReason>,
    /// Explicit knowledge gaps (never a guessed number).
    pub gaps: Vec<KnowledgeGap>,
    /// The exact per-domain numbers behind the decision.
    pub numbers: VerdictNumbers,
    /// What enforcement was armed (or the honest label for why not).
    pub enforcement: EnforcementRecord,
}

impl GovernorVerdict {
    /// Convenience for the consumer's match arm.
    pub fn admitted(&self) -> bool {
        self.decision == Decision::Admit
    }

    /// The honest one-line rendering (desktop parity for breach lines;
    /// explicit fail-closed lines for unobservables; the KV gap is
    /// appended whenever present so the log can never show a
    /// weights-only projection as complete).
    pub fn detail_line(&self) -> String {
        let mut line = match &self.reason {
            Some(reason) => reason.detail(),
            None => {
                let mb = |b: u64| b / 1_000_000;
                let mut ok = String::new();
                if let Some(n) = self.numbers.ram {
                    ok.push_str(&format!(
                        "system RAM: projected {}/{} MB stays under the {}% ceiling",
                        mb(n.projected_bytes),
                        mb(n.total_bytes),
                        ENFORCED_CEILING_PERCENT
                    ));
                }
                if let Some(n) = self.numbers.vram {
                    if !ok.is_empty() {
                        ok.push_str("; ");
                    }
                    ok.push_str(&format!(
                        "VRAM: projected {}/{} MB stays under the {}% ceiling",
                        mb(n.projected_bytes),
                        mb(n.total_bytes),
                        ENFORCED_CEILING_PERCENT
                    ));
                }
                ok
            }
        };
        if self.gaps.contains(&KnowledgeGap::KvUnmodeled) {
            line.push_str(" [gap: KV/context overhead not modeled — projection is weights-only]");
        }
        match &self.enforcement {
            EnforcementRecord::Armed {
                mechanism,
                cap_bytes,
            } => line.push_str(&format!(
                " [enforcement: {} MB tree commit cap armed via {}]",
                cap_bytes / 1_000_000,
                mechanism
            )),
            EnforcementRecord::NotEnforced { label } => {
                line.push_str(&format!(" [enforcement: {label}]"))
            }
        }
        line
    }
}

/// The decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The projection stays under the enforced ceiling in every required
    /// domain; the optional tier may start (and keep) the added copy.
    Admit,
    /// Degrade the optional tier (fail closed). Primary serving is
    /// unaffected — this decision governs the ADDED consumption only.
    Degrade,
}

/// The M2 governor: owns the sample source (so the verdict's inputs are
/// the governor's own, not the caller's), owns the enforcement seam, and
/// answers [`AdmissionRequest`]s with binding verdicts.
///
/// Construct once per hosting session (or per verdict, like the desktop's
/// current sampler usage — construction is one tree read plus the PDH
/// baseline) and call [`ResourceGovernor::evaluate`] at admission time
/// and again on monitor ticks: a later sample under pressure flips the
/// verdict to [`Decision::Degrade`], which the consumer applies by
/// dropping the optional tier. `evaluate` takes `&mut self`; from async
/// context wrap the whole governor in `spawn_blocking`, exactly like the
/// desktop's advisory check does today.
pub struct ResourceGovernor {
    sampler: ResourceSampler<Box<dyn SampleSource>>,
    enforcer: Box<dyn CeilingEnforcer>,
}

impl ResourceGovernor {
    /// The platform pair: this OS's [`SampleSource`] plus this OS's
    /// [`CeilingEnforcer`] (Windows: winjob job objects; elsewhere the
    /// honest `not_enforced_unsupported_platform` seam — the admission
    /// verdict itself still binds everywhere).
    pub fn platform(scope: crate::ProcessScope) -> Self {
        Self {
            sampler: ResourceSampler::new(crate::platform_source(scope)),
            enforcer: crate::enforce::platform_enforcer(),
        }
    }

    /// Test/library constructor over injected seams.
    pub fn new(
        sampler: ResourceSampler<Box<dyn SampleSource>>,
        enforcer: Box<dyn CeilingEnforcer>,
    ) -> Self {
        Self { sampler, enforcer }
    }

    /// Read-only access to the enforcement seam (diagnostics).
    pub fn enforcer(&self) -> &dyn CeilingEnforcer {
        self.enforcer.as_ref()
    }

    /// Takes one live sample and answers the request. Order of checks:
    /// request validity, then system RAM (always), then VRAM (only when
    /// the added copy lands there). The FIRST failing check wins; later
    /// domains are not evaluated (their numbers stay absent — a verdict
    /// never carries numbers for a check that did not run).
    pub fn evaluate(&mut self, request: &AdmissionRequest) -> GovernorVerdict {
        let sample = self.sampler.sample();
        let mut gaps = Vec::new();
        if request.added_kv_bytes.is_none() {
            gaps.push(KnowledgeGap::KvUnmodeled);
        }
        // The KV term rides `added` only when the caller MODELED it; a
        // gap is recorded above either way.
        let added = request
            .added_weights_bytes
            .saturating_add(request.added_kv_bytes.unwrap_or(0));

        let no_admission = EnforcementRecord::NotEnforced {
            label: "not_enforced_no_admission",
        };
        if request.added_weights_bytes == 0 {
            return GovernorVerdict {
                decision: Decision::Degrade,
                reason: Some(DegradeReason::WeightsNotPositive),
                gaps,
                numbers: VerdictNumbers::default(),
                enforcement: no_admission,
            };
        }

        // System RAM: always required — an unobservable reading cannot
        // enforce the ceiling, so it degrades (fail closed).
        let ram = match (sample.system_ram_used_bytes, sample.system_ram_total_bytes) {
            (Some(used), Some(total)) => DomainNumbers::project(total, used, added),
            _ => {
                return GovernorVerdict {
                    decision: Decision::Degrade,
                    reason: Some(DegradeReason::RamUnobservable),
                    gaps,
                    numbers: VerdictNumbers {
                        ceiling_percent: ENFORCED_CEILING_PERCENT,
                        ram: None,
                        vram: None,
                    },
                    enforcement: no_admission,
                };
            }
        };
        if ram.breaches() {
            return GovernorVerdict {
                decision: Decision::Degrade,
                reason: Some(DegradeReason::RamProjectionBreachesCeiling(ram)),
                gaps,
                numbers: VerdictNumbers {
                    ceiling_percent: ENFORCED_CEILING_PERCENT,
                    ram: Some(ram),
                    vram: None,
                },
                enforcement: no_admission,
            };
        }

        // VRAM: only when the added copy lands there; both the live usage
        // and the static geometry must be observable or the check fails
        // closed (distinct labels so telemetry can tell them apart).
        let vram = if request.added_copy_lands_in_vram {
            match (sample.gpu_vram_used_bytes, request.vram_total_bytes) {
                (Some(used), Some(total)) => {
                    let n = DomainNumbers::project(total, used, added);
                    if n.breaches() {
                        return GovernorVerdict {
                            decision: Decision::Degrade,
                            reason: Some(DegradeReason::VramProjectionBreachesCeiling(n)),
                            gaps,
                            numbers: VerdictNumbers {
                                ceiling_percent: ENFORCED_CEILING_PERCENT,
                                ram: Some(ram),
                                vram: Some(n),
                            },
                            enforcement: no_admission,
                        };
                    }
                    Some(n)
                }
                (None, _) => {
                    return GovernorVerdict {
                        decision: Decision::Degrade,
                        reason: Some(DegradeReason::VramUnobservable),
                        gaps,
                        numbers: VerdictNumbers {
                            ceiling_percent: ENFORCED_CEILING_PERCENT,
                            ram: Some(ram),
                            vram: None,
                        },
                        enforcement: no_admission,
                    };
                }
                (Some(_), None) => {
                    return GovernorVerdict {
                        decision: Decision::Degrade,
                        reason: Some(DegradeReason::VramTotalUnknown),
                        gaps,
                        numbers: VerdictNumbers {
                            ceiling_percent: ENFORCED_CEILING_PERCENT,
                            ram: Some(ram),
                            vram: None,
                        },
                        enforcement: no_admission,
                    };
                }
            }
        } else {
            None
        };

        // Admit: arm the tree commit cap (enforcement in depth). The cap
        // is the RAM ceiling minus everything OUTSIDE the sampled tree,
        // so the supervised tree may grow exactly until the SYSTEM would
        // reach the enforced ceiling. On Admit the cap is provably >
        // `added` (> current tree usage by at least the same margin), so
        // arming can never be an instant-allocation-failure
        // configuration; the underflow guard stays as a belt.
        let enforcement = if request.arm_tree_commit_cap {
            let outside_tree = sample
                .system_ram_used_bytes
                .unwrap_or(0)
                .saturating_sub(sample.process_tree_working_set_bytes.unwrap_or(0));
            let cap = ram.ceiling_bytes.saturating_sub(outside_tree);
            if cap == 0 {
                EnforcementRecord::NotEnforced {
                    label: "not_enforced_cap_underflow",
                }
            } else {
                self.enforcer.arm_tree_commit_cap(cap)
            }
        } else {
            EnforcementRecord::NotEnforced {
                label: "not_enforced_caller_opted_out",
            }
        };

        GovernorVerdict {
            decision: Decision::Admit,
            reason: None,
            gaps,
            numbers: VerdictNumbers {
                ceiling_percent: ENFORCED_CEILING_PERCENT,
                ram: Some(ram),
                vram,
            },
            enforcement,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_numbers_math_is_saturating_and_boundary_exact() {
        let n = DomainNumbers::project(10_000, 5_000, 2_000);
        assert_eq!(n.ceiling_bytes, 7_000);
        assert_eq!(n.projected_bytes, 7_000);
        assert!(!n.breaches(), "exactly at the ceiling admits (parity)");

        let over = DomainNumbers::project(10_000, 5_000, 2_001);
        assert!(over.breaches(), "one byte over degrades");

        // 70% of a non-round total truncates (integer parity with the
        // desktop's `total * 70 / 100`), never rounds up into leniency.
        let odd = DomainNumbers::project(10_003, 0, 0);
        assert_eq!(odd.ceiling_bytes, 7_002);

        // inconsistent counters clamp, never wrap
        let weird = DomainNumbers::project(10, u64::MAX, u64::MAX);
        assert_eq!(weird.projected_bytes, u64::MAX);
    }

    #[test]
    fn ceiling_constants_are_the_d11_pair() {
        assert_eq!(ENFORCED_CEILING_PERCENT, 70);
        assert_eq!(RECOMMENDATION_BAR_CEILING_PERCENT, 90);
    }

    #[test]
    fn reason_labels_are_stable_and_disjoint() {
        let labels = [
            DegradeReason::WeightsNotPositive.label(),
            DegradeReason::RamUnobservable.label(),
            DegradeReason::VramUnobservable.label(),
            DegradeReason::VramTotalUnknown.label(),
            DegradeReason::RamProjectionBreachesCeiling(DomainNumbers::default()).label(),
            DegradeReason::VramProjectionBreachesCeiling(DomainNumbers::default()).label(),
        ];
        for (i, a) in labels.iter().enumerate() {
            for b in labels.iter().skip(i + 1) {
                assert_ne!(a, b, "labels must be disjoint: {a} vs {b}");
            }
        }
    }
}
