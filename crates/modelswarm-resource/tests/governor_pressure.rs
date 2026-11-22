//! Memory-exhaustion / responsiveness suite for the M2 governor
//! (ownership-map obligation; ADR-035 §6): verdicts degrade HONESTLY
//! under simulated pressure. All pressure is MOCKED — no real
//! allocation, no real OOM; the OS-level enforcement paths are exercised
//! separately in `tests/winjob_enforcement.rs` (Windows) and their
//! absence elsewhere is pinned here as the explicit
//! `not_enforced_unsupported_platform` label, never an unstated gap.
//!
//! The behavioral anchor throughout: the desktop's v0.2.23 advisory
//! check passed-with-gap on unobservable inputs; the governor is the
//! enforcement authority and FAILS CLOSED instead (gate D11 / master
//! prompt §2) — degrading the optional tier, never primary serving.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

use modelswarm_resource::enforce::MockEnforcer;
use modelswarm_resource::governor::{
    AdmissionRequest, Decision, DegradeReason, KnowledgeGap, ResourceGovernor,
    ENFORCED_CEILING_PERCENT,
};
use modelswarm_resource::source::{ProcSample, SampleSource, SystemMemory, TreeSnapshot};
use modelswarm_resource::{GpuLive, MockSource, ResourceSampler};

const MB: u64 = 1_000_000;

fn tree_with_working_set(ws: Option<u64>) -> TreeSnapshot {
    TreeSnapshot {
        procs: vec![ProcSample {
            pid: 1,
            cpu_time: Duration::ZERO,
            working_set: ws,
        }],
    }
}

/// A governor over a static mocked machine. One `evaluate` is scripted
/// (construction consumes the sampler baseline, the evaluate consumes
/// the next tick).
fn governor(
    memory: Option<SystemMemory>,
    gpu: Option<GpuLive>,
    tree_ws: Option<u64>,
) -> ResourceGovernor {
    let t0 = Instant::now();
    let mut src = MockSource::new(
        vec![t0, t0 + Duration::from_secs(1)],
        vec![
            Ok(tree_with_working_set(tree_ws)),
            Ok(tree_with_working_set(tree_ws)),
        ],
    );
    src.memory = memory;
    src.gpu = gpu;
    ResourceGovernor::new(
        ResourceSampler::new(Box::new(src)),
        Box::new(MockEnforcer::new()),
    )
}

fn ram(total_mb: u64, used_mb: u64) -> Option<SystemMemory> {
    Some(SystemMemory {
        total_bytes: total_mb * MB,
        available_bytes: (total_mb - used_mb) * MB,
    })
}

fn request(weights_mb: u64) -> AdmissionRequest {
    AdmissionRequest {
        added_weights_bytes: weights_mb * MB,
        added_kv_bytes: None,
        added_copy_lands_in_vram: false,
        vram_total_bytes: None,
        arm_tree_commit_cap: true,
    }
}

/// A source whose system memory changes per tick (pressure arriving),
/// for the responsiveness test. Every other field is static/None.
struct PressureSource {
    memories: RefCell<VecDeque<SystemMemory>>,
}

impl SampleSource for PressureSource {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn logical_cores(&self) -> u32 {
        1
    }
    fn process_tree(&self) -> io::Result<TreeSnapshot> {
        Ok(TreeSnapshot::default())
    }
    fn system_memory(&self) -> io::Result<SystemMemory> {
        let mut seq = self.memories.borrow_mut();
        let next = if seq.len() > 1 {
            seq.pop_front()
        } else {
            seq.front().copied()
        };
        next.ok_or_else(|| io::Error::other("no memory scripted"))
    }
    fn gpu(&mut self) -> Option<GpuLive> {
        None
    }
}

/// A one-evaluate scripted source with static memory/GPU and the empty
/// tree (no working-set observability).
fn boxed_source(memory: Option<SystemMemory>) -> Box<dyn SampleSource> {
    let t0 = Instant::now();
    let mut src = MockSource::new(
        vec![t0, t0 + Duration::from_secs(1)],
        vec![Ok(TreeSnapshot::default()), Ok(TreeSnapshot::default())],
    );
    src.memory = memory;
    Box::new(src)
}

// ---------------------------------------------------------------------------
// Admission math (parity with, then stricter than, the desktop advisory)
// ---------------------------------------------------------------------------

#[test]
fn admits_under_ceiling_with_exact_numbers_and_arms_the_cap() {
    // 32 GB total, 10 GB used, 2 GB tree WS, +4 GB weights +0.5 GB KV:
    // projected 14.5 GB < 22.4 GB ceiling.
    let mut gov = governor(ram(32_000, 10_000), None, Some(2_000 * MB));
    let req = AdmissionRequest {
        added_kv_bytes: Some(500 * MB),
        ..request(4_000)
    };
    let v = gov.evaluate(&req);
    assert!(v.admitted(), "detail: {}", v.detail_line());
    assert_eq!(v.gaps, Vec::<KnowledgeGap>::new(), "KV was modeled");
    let n = v.numbers.ram.expect("ram numbers");
    assert_eq!(n.total_bytes, 32_000 * MB);
    assert_eq!(n.used_bytes, 10_000 * MB);
    assert_eq!(n.added_bytes, 4_500 * MB);
    assert_eq!(n.projected_bytes, 14_500 * MB);
    assert_eq!(n.ceiling_bytes, 22_400 * MB);
    // Cap = ceiling - (used - tree WS) = 22.4 GB - 8 GB = 14.4 GB: the
    // tree may grow exactly until the SYSTEM would reach the ceiling.
    let enforcer = gov
        .enforcer()
        .as_any()
        .downcast_ref::<MockEnforcer>()
        .expect("mock enforcer");
    assert_eq!(enforcer.armed, vec![14_400 * MB]);
    assert!(v.enforcement.armed());
    assert_eq!(v.enforcement.label(), "mock");
}

#[test]
fn unmodeled_kv_degrades_to_weights_only_with_an_explicit_gap() {
    // With KV modeled this would breach (18 GB + 4 GB + 0.5 GB = 22.5 GB
    // > 22.4 GB); unmodeled it admits at 22.0 GB — and the verdict MUST
    // say the projection is incomplete rather than silently pass.
    let mut gov = governor(ram(32_000, 18_000), None, None);
    let v = gov.evaluate(&request(4_000));
    assert!(
        v.admitted(),
        "weights-only projection admits: {}",
        v.detail_line()
    );
    assert_eq!(v.gaps, vec![KnowledgeGap::KvUnmodeled]);
    assert_eq!(v.numbers.ram.unwrap().projected_bytes, 22_000 * MB);
    assert!(
        v.detail_line().contains("KV/context overhead not modeled"),
        "gap must be explicit in the rendering: {}",
        v.detail_line()
    );

    // The same request WITH the KV term modeled degrades instead.
    let mut gov = governor(ram(32_000, 18_000), None, None);
    let v = gov.evaluate(&AdmissionRequest {
        added_kv_bytes: Some(500 * MB),
        ..request(4_000)
    });
    assert!(!v.admitted(), "modeled KV must enter the projection");
    assert_eq!(v.gaps, Vec::<KnowledgeGap>::new());
    assert_eq!(
        v.reason.map(|r| r.label()),
        Some("ram_ceiling"),
        "22.5 GB > 22.4 GB ceiling"
    );
}

#[test]
fn ram_breach_degrades_with_the_desktop_parity_detail_string() {
    let mut gov = governor(ram(32_000, 19_000), None, None);
    let v = gov.evaluate(&request(4_000));
    assert_eq!(v.decision, Decision::Degrade);
    let DegradeReason::RamProjectionBreachesCeiling(n) = v.reason.expect("reason") else {
        panic!("wrong reason: {:?}", v.reason);
    };
    assert_eq!(n.projected_bytes, 23_000 * MB);
    assert_eq!(n.ceiling_bytes, 22_400 * MB);
    // Verbatim shape of the desktop's advisory line, so the UI text
    // survives the call-site swap unchanged.
    assert_eq!(
        v.reason.as_ref().unwrap().detail(),
        "system RAM: projected 23000/32000 MB would pass the 70% ceiling (19000 MB in use + the verify engine's 4000 MB copy)"
    );
    assert_eq!(v.reason.as_ref().unwrap().label(), "ram_ceiling");
    // No admission => nothing armed.
    assert!(!v.enforcement.armed());
    assert_eq!(v.enforcement.label(), "not_enforced_no_admission");
    let enforcer = gov
        .enforcer()
        .as_any()
        .downcast_ref::<MockEnforcer>()
        .expect("mock enforcer");
    assert!(enforcer.armed.is_empty(), "degrade must not arm");
}

#[test]
fn ceiling_boundary_admits_exactly_at_and_degrades_one_byte_over() {
    // 70% of 10 GB = 7 GB; used 3 GB + weights 4 GB = exactly 7 GB.
    let mut at = governor(ram(10_000, 3_000), None, None);
    assert!(at.evaluate(&request(4_000)).admitted(), "at-ceiling admits");
    let mut over = governor(ram(10_000, 3_000), None, None);
    let mut req = request(4_000);
    req.added_weights_bytes += 1;
    let v = over.evaluate(&req);
    assert_eq!(v.decision, Decision::Degrade, "one byte over degrades");
}

#[test]
fn vram_doubling_check_runs_only_for_gpu_copies() {
    // vulkan-class copy: 6 GB used of 10 GB + 1.5 GB weights = 7.5 GB >
    // 7.0 GB ceiling => degrade with the VRAM parity string.
    let mut gov = governor(
        ram(32_000, 5_000),
        Some(GpuLive {
            utilization_percent: None,
            vram_used_bytes: Some(6_000 * MB),
        }),
        None,
    );
    let mut req = request(1_500);
    req.added_copy_lands_in_vram = true;
    req.vram_total_bytes = Some(10_000 * MB);
    let v = gov.evaluate(&req);
    assert_eq!(v.decision, Decision::Degrade);
    assert_eq!(v.reason.as_ref().unwrap().label(), "vram_ceiling");
    assert_eq!(
        v.reason.as_ref().unwrap().detail(),
        "VRAM: projected 7500/10000 MB would pass the 70% ceiling (6000 MB in use + the verify engine's 1500 MB copy)"
    );
    // RAM numbers are still present (that check ran and passed).
    assert!(v.numbers.ram.is_some());
    assert!(v.numbers.vram.is_some());

    // CPU-class copy with NO GPU observability at all: the VRAM domain
    // does not run and the admission stands (parity with the desktop).
    let mut cpu = governor(ram(32_000, 5_000), None, None);
    let v = cpu.evaluate(&request(1_500));
    assert!(v.admitted(), "cpu copy needs no vram numbers");
    assert!(v.numbers.vram.is_none());
}

// ---------------------------------------------------------------------------
// Fail-closed semantics (the advisory->enforcement upgrade)
// ---------------------------------------------------------------------------

#[test]
fn unobservable_ram_degrades_fail_closed_instead_of_passing_with_gap() {
    // THE upgrade over the desktop's advisory check: it logged the gap
    // and passed; the governor cannot enforce what it cannot observe, so
    // the optional tier degrades. (Primary serving is unaffected — this
    // decision governs the ADDED copy only.)
    let mut gov = governor(None, None, None);
    let v = gov.evaluate(&request(4_000));
    assert_eq!(v.decision, Decision::Degrade);
    assert_eq!(v.reason.as_ref().unwrap().label(), "ram_unobservable");
    assert!(
        v.detail_line().contains("cannot be enforced"),
        "detail must say why: {}",
        v.detail_line()
    );
    assert!(
        v.numbers.ram.is_none(),
        "no numbers for a check that never ran"
    );
    assert!(!v.enforcement.armed());
}

#[test]
fn unobservable_vram_inputs_degrade_fail_closed_with_distinct_labels() {
    // usage unreadable (no PDH GPU counters) vs geometry unknown (no M1
    // GPU detection) are different failures and must be distinguishable
    // in telemetry.
    let base = || governor(ram(32_000, 5_000), None, None);
    let mut usage_missing = base();
    let mut req = request(1_000);
    req.added_copy_lands_in_vram = true;
    req.vram_total_bytes = Some(10_000 * MB);
    let v = usage_missing.evaluate(&req);
    assert_eq!(v.reason.as_ref().unwrap().label(), "vram_unobservable");

    // Geometry missing while usage IS observable (PDH counters present,
    // no M1 GPU detection): a different failure, a different label.
    let mut total_missing = governor(
        ram(32_000, 5_000),
        Some(GpuLive {
            utilization_percent: None,
            vram_used_bytes: Some(1_000 * MB),
        }),
        None,
    );
    let mut req = request(1_000);
    req.added_copy_lands_in_vram = true;
    // vram_total_bytes stays None while the copy lands in VRAM.
    let v = total_missing.evaluate(&req);
    assert_eq!(v.reason.as_ref().unwrap().label(), "vram_total_unknown");
}

#[test]
fn zero_weights_is_an_invalid_request_not_a_crash() {
    let mut gov = governor(ram(32_000, 5_000), None, None);
    let v = gov.evaluate(&request(0));
    assert_eq!(v.decision, Decision::Degrade);
    assert_eq!(v.reason.as_ref().unwrap().label(), "weights_not_positive");
}

// ---------------------------------------------------------------------------
// Responsiveness under arriving pressure
// ---------------------------------------------------------------------------

#[test]
fn pressure_arriving_later_flips_the_verdict_from_admit_to_degrade() {
    // The monitor-tick contract: the same governor, re-evaluated as the
    // machine fills up, flips to Degrade — the consumer drops the
    // optional tier instead of silently exceeding the ceiling.
    let src = PressureSource {
        memories: RefCell::new(VecDeque::from(vec![
            SystemMemory {
                total_bytes: 32_000 * MB,
                available_bytes: 22_000 * MB, // 10 GB used
            },
            SystemMemory {
                total_bytes: 32_000 * MB,
                available_bytes: 13_000 * MB, // 19 GB used
            },
        ])),
    };
    let mut gov = ResourceGovernor::new(
        ResourceSampler::new(Box::new(src)),
        Box::new(MockEnforcer::new()),
    );
    let v1 = gov.evaluate(&request(4_000));
    assert!(v1.admitted(), "tick 1 admits: {}", v1.detail_line());
    let v2 = gov.evaluate(&request(4_000));
    assert_eq!(v2.decision, Decision::Degrade, "tick 2 pressure degrades");
    assert_eq!(v2.reason.as_ref().unwrap().label(), "ram_ceiling");
    // The cap was armed exactly once (at the admitting tick) and never
    // re-armed after the degrade.
    let enforcer = gov
        .enforcer()
        .as_any()
        .downcast_ref::<MockEnforcer>()
        .expect("mock enforcer");
    assert_eq!(enforcer.armed.len(), 1);
}

#[test]
fn cap_arithmetic_accounts_for_the_tree_and_saturates() {
    // Tree working set unknown (empty tree read): everything outside the
    // tree is the whole used figure — the most conservative cap.
    let mut unknown_ws = governor(ram(32_000, 10_000), None, None);
    let v = unknown_ws.evaluate(&request(1_000));
    assert!(v.admitted());
    let enforcer = unknown_ws
        .enforcer()
        .as_any()
        .downcast_ref::<MockEnforcer>()
        .expect("mock enforcer");
    assert_eq!(enforcer.armed, vec![12_400 * MB], "22.4 GB - 10 GB used");

    // A working set LARGER than system used (inconsistent counters)
    // saturates at "nothing is outside the tree" => cap == ceiling, the
    // most generous defensible bound, never a wrapped number.
    let mut weird = governor(ram(32_000, 1_000), None, Some(5_000 * MB));
    let v = weird.evaluate(&request(500));
    assert!(v.admitted());
    let enforcer = weird
        .enforcer()
        .as_any()
        .downcast_ref::<MockEnforcer>()
        .expect("mock enforcer");
    assert_eq!(
        enforcer.armed,
        vec![22_400 * MB],
        "saturates at the ceiling"
    );
}

// ---------------------------------------------------------------------------
// Enforcement honesty (mocked; the OS-level paths are in
// tests/winjob_enforcement.rs on Windows)
// ---------------------------------------------------------------------------

#[test]
fn caller_opt_out_and_unsupported_platform_carry_honest_labels() {
    let mut gov = governor(ram(32_000, 5_000), None, None);
    let mut req = request(1_000);
    req.arm_tree_commit_cap = false;
    let v = gov.evaluate(&req);
    assert!(v.admitted());
    assert_eq!(v.enforcement.label(), "not_enforced_caller_opted_out");

    // The platform-honest label, pinnable on EVERY OS (on Windows the
    // platform enforcer is winjob; this type exists so the label's shape
    // is pinned where the seam lives too).
    let mut unsupported = ResourceGovernor::new(
        ResourceSampler::new(boxed_source(ram(32_000, 5_000))),
        Box::new(modelswarm_resource::UnsupportedEnforcer),
    );
    let v = unsupported.evaluate(&request(1_000));
    assert!(v.admitted(), "the admission verdict still binds");
    assert_eq!(v.enforcement.label(), "not_enforced_unsupported_platform");
    assert!(v
        .detail_line()
        .contains("not_enforced_unsupported_platform"));
}

#[test]
fn enforcer_failure_leaves_the_admission_standing_with_an_honest_label() {
    // A failed backstop is not a failed admission: the binding decision
    // is the verdict. The record says exactly what happened; a consumer
    // that wants the backstop mandatory can degrade on the label.
    let mut gov = ResourceGovernor::new(
        ResourceSampler::new(boxed_source(ram(32_000, 5_000))),
        Box::new(MockEnforcer {
            armed: Vec::new(),
            fail: true,
        }),
    );
    let v = gov.evaluate(&request(1_000));
    assert!(v.admitted());
    assert_eq!(v.enforcement.label(), "not_enforced_arm_failed");
}

#[test]
fn admit_detail_line_reports_projection_gap_and_enforcement_together() {
    let mut gov = governor(ram(32_000, 10_000), None, Some(2_000 * MB));
    let v = gov.evaluate(&request(4_000)); // kv None => gap expected
    let line = v.detail_line();
    assert!(line.contains("stays under the 70% ceiling"), "line: {line}");
    assert!(
        line.contains("KV/context overhead not modeled"),
        "line: {line}"
    );
    assert!(
        line.contains("14400 MB tree commit cap armed via mock"),
        "line: {line}"
    );
    assert_eq!(ENFORCED_CEILING_PERCENT, 70, "D11 number is the authority");
}
