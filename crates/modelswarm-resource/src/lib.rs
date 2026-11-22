//! Live resource sampling for the desktop monitor panel (owner request
//! 2026-10-12) plus the M2 resource governor (ADR-035, 2026-10-13): the
//! runtime 70%-ceiling ENFORCEMENT authority of gate D11. The sampler is
//! the read-only observability layer; the governor
//! ([`crate::governor::ResourceGovernor`]) is the decision layer that
//! consumes it — verdicts are binding for the optional tiers they govern
//! (family enablement today), fail closed when a required input is
//! unobservable, and arm OS-level caps through the [`crate::enforce`]
//! seam (winjob job objects on Windows; honest
//! `not_enforced_unsupported_platform` labels elsewhere).
//!
//! # What the desktop should do with it
//!
//! - Build ONE [`ResourceSampler`] (via [`ResourceSampler::platform`]) at
//!   panel open and poll `sample()` at **<= 1 Hz**. Each poll costs one
//!   process-table pass plus, on Windows, one PDH collect — sub-millisecond
//!   on typical machines, but it is a poll API, not an event stream; do not
//!   call it per frame. PDH rate counters need two collects separated in
//!   time, so the constructor takes the baseline collect and the FIRST
//!   `sample()` (a second or so later) already carries every field.
//! - [`crate::profile::HardwareProfile`] is the static-geometry side
//!   (total RAM/VRAM, core count). Inject the existing M1 detection
//!   results — the bundled engine's `--list-devices` output the desktop
//!   already parses — instead of re-detecting; the sampler never
//!   re-enumerates hardware per sample.
//! - Scope the "process tree" as the winjob job-object membership once the
//!   winjob crate exposes it; until then [`ProcessScope::CurrentTree`]
//!   covers the same processes (the desktop spawns the engine itself).
//!
//! # Field availability (honesty matrix)
//!
//! | Field | Windows (primary OS) | Linux | other OS |
//! |---|---|---|---|
//! | `process_tree_cpu_percent` | Toolhelp snapshot + `GetProcessTimes` deltas | `/proc/<pid>/stat` utime+stime deltas | `None` |
//! | `system_ram_used_*` | `GlobalMemoryStatusEx` | `/proc/meminfo` | `None` |
//! | `process_tree_working_set_bytes` | `GetProcessMemoryInfo` working sets | `statm` RSS (page size assumed 4 KiB) | `None` |
//! | `gpu_utilization_percent` | PDH `GPU Engine` counters (the Task-Manager source); `None` if PDH/GPU absent | `None` | `None` |
//! | `gpu_vram_used_bytes` | PDH `GPU Process Memory` local usage summed per adapter; `None` if absent | `None` | `None` |
//!
//! An honest `None` (panel shows "n/a") always beats a guessed number.
//! Linux assumptions: `USER_HZ == 100` and 4 KiB pages (true on every
//! mainstream distro; documented rather than queried to keep the path
//! trivial, per the owner's cross-platform-honesty instruction).

pub mod enforce;
pub mod governor;
pub mod parsers;
pub mod profile;
pub mod source;

#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(not(any(windows, target_os = "linux")))]
pub mod fallback;

use std::collections::HashMap;
use std::time::{Duration, Instant};

#[cfg(windows)]
pub use enforce::WinJobEnforcer;
pub use enforce::{CeilingEnforcer, EnforcementRecord, MockEnforcer, UnsupportedEnforcer};
pub use governor::{
    AdmissionRequest, Decision, DegradeReason, DomainNumbers, GovernorVerdict, KnowledgeGap,
    ResourceGovernor, VerdictNumbers, ENFORCED_CEILING_PERCENT, RECOMMENDATION_BAR_CEILING_PERCENT,
};
pub use profile::{GpuGeometry, HardwareProfile};
pub use source::{
    descendant_pids, GpuLive, MockSource, ProcSample, ProcessScope, SampleSource, SystemMemory,
    TreeSnapshot,
};

/// One pollable reading of the machine. Every field degrades to `None`
/// independently when its counter could not be read this tick (fail-soft:
/// a monitor panel must keep painting, and a missing number must stay
/// visibly missing).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ResourceSample {
    /// Tree CPU usage as a percentage of TOTAL system capacity (all
    /// logical cores), Task-Manager style: 100% = every core busy.
    pub process_tree_cpu_percent: Option<f64>,
    /// Physical RAM in use system-wide, 0–100.
    pub system_ram_used_percent: Option<f64>,
    /// Physical RAM in use system-wide, bytes.
    pub system_ram_used_bytes: Option<u64>,
    /// Total physical RAM, bytes (static per boot; repeated for convenience).
    pub system_ram_total_bytes: Option<u64>,
    /// Sum of per-process working sets over the tree, bytes. Roughly the
    /// Task-Manager "Memory" column for those processes summed.
    pub process_tree_working_set_bytes: Option<u64>,
    /// Busiest adapter's GPU utilization, 0–100 (sum over its engine
    /// instances, clamped). `None` = not reliably measurable here.
    pub gpu_utilization_percent: Option<f64>,
    /// Dedicated VRAM in use on that same adapter, bytes (WDDM-tracked).
    pub gpu_vram_used_bytes: Option<u64>,
}

/// CPU% of total system capacity from raw deltas. Normalized by logical
/// cores, clamped to 0–100 (float safety), `None` when the inputs cannot
/// produce a number (zero wall interval or unknown core count).
pub fn cpu_percent(delta_cpu: Duration, delta_wall: Duration, logical_cores: u32) -> Option<f64> {
    if logical_cores == 0 || delta_wall.is_zero() {
        return None;
    }
    let pct = delta_cpu.as_secs_f64() / delta_wall.as_secs_f64() * 100.0 / f64::from(logical_cores);
    Some(pct.clamp(0.0, 100.0))
}

/// `used/total` as a clamped 0–100 percentage; `None` when unknown
/// (`total == 0`) and 100.0 (not a crash) when counters are inconsistent.
pub fn used_percent(used: u64, total: u64) -> Option<f64> {
    if total == 0 {
        return None;
    }
    Some((used as f64 / total as f64 * 100.0).clamp(0.0, 100.0))
}

/// Cheap, pollable resource sampler: pure delta/percentage math over an
/// injectable [`SampleSource`]. Construct once, poll `sample()` at <= 1 Hz.
///
/// The constructor takes a baseline process-tree reading (plus the PDH
/// baseline collect on Windows) so the first `sample()` a second later
/// already reports every field. When a tree read fails mid-run the CPU
/// baseline is dropped (that tick reports `None`) and re-established on
/// the next successful read — degraded display, never a fabricated number.
pub struct ResourceSampler<S: SampleSource> {
    source: S,
    prev_tree: Option<HashMap<u32, Duration>>,
    prev_wall: Option<Instant>,
}

impl ResourceSampler<Box<dyn SampleSource>> {
    /// The platform source for this OS: Windows (full), Linux (`/proc`),
    /// or an honest all-`None` fallback elsewhere.
    pub fn platform(scope: ProcessScope) -> Self {
        Self::new(platform_source(scope))
    }
}

fn platform_source(scope: ProcessScope) -> Box<dyn SampleSource> {
    #[cfg(windows)]
    {
        Box::new(windows::WindowsSource::new(scope))
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxSource::new(scope))
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = scope;
        Box::new(fallback::FallbackSource::new())
    }
}

impl<S: SampleSource> ResourceSampler<S> {
    /// Builds the sampler and takes the CPU baseline (one tree read).
    pub fn new(source: S) -> Self {
        let (prev_tree, prev_wall) = match source.process_tree() {
            Ok(tree) => (Some(tree.cpu_map()), Some(source.now())),
            Err(_) => (None, None),
        };
        Self {
            source,
            prev_tree,
            prev_wall,
        }
    }

    /// Read-only access to the source (e.g. to inspect scope).
    pub fn source(&self) -> &S {
        &self.source
    }

    /// Mutable access to the source (e.g. to reconfigure scope).
    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    /// Takes one reading. Per-field fail-soft; see [`ResourceSample`].
    pub fn sample(&mut self) -> ResourceSample {
        let now = self.source.now();
        let mut out = ResourceSample::default();
        match self.source.process_tree() {
            Ok(tree) => {
                out.process_tree_working_set_bytes = tree.total_working_set();
                if let (Some(prev), Some(prev_wall)) = (&self.prev_tree, self.prev_wall) {
                    if now > prev_wall {
                        let delta_cpu = tree.cpu_delta_since(prev);
                        out.process_tree_cpu_percent =
                            cpu_percent(delta_cpu, now - prev_wall, self.source.logical_cores());
                    }
                }
                self.prev_tree = Some(tree.cpu_map());
                self.prev_wall = Some(now);
            }
            Err(_) => {
                // Unreadable tree: degrade this tick and re-baseline.
                self.prev_tree = None;
                self.prev_wall = None;
            }
        }
        if let Ok(mem) = self.source.system_memory() {
            out.system_ram_used_percent = used_percent(mem.used_bytes(), mem.total_bytes);
            out.system_ram_used_bytes = Some(mem.used_bytes());
            out.system_ram_total_bytes = Some(mem.total_bytes);
        }
        if let Some(gpu) = self.source.gpu() {
            out.gpu_utilization_percent = gpu.utilization_percent;
            out.gpu_vram_used_bytes = gpu.vram_used_bytes;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    fn tree(entries: &[(u32, u64, u64)]) -> io::Result<TreeSnapshot> {
        Ok(TreeSnapshot {
            procs: entries
                .iter()
                .map(|&(pid, cpu_ms, ws)| ProcSample {
                    pid,
                    cpu_time: Duration::from_millis(cpu_ms),
                    working_set: Some(ws),
                })
                .collect(),
        })
    }

    fn tick(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn cpu_percent_normalizes_by_cores() {
        // one full core busy for 1s of wall on a 2-core machine = 50%
        let got = cpu_percent(Duration::from_secs(1), Duration::from_secs(1), 2);
        assert_eq!(got, Some(50.0));
        // a single-core machine fully busy = 100%
        assert_eq!(
            cpu_percent(Duration::from_secs(1), Duration::from_secs(1), 1),
            Some(100.0)
        );
        // half a core-second per second on 4 cores = 12.5%
        let got = cpu_percent(Duration::from_millis(500), Duration::from_secs(1), 4);
        assert_eq!(got, Some(12.5));
    }

    #[test]
    fn cpu_percent_clamps_over_capacity() {
        // 2 core-seconds in 1 wall-second on a 1-core machine: clamp, not 200
        let got = cpu_percent(Duration::from_secs(2), Duration::from_secs(1), 1);
        assert_eq!(got, Some(100.0));
    }

    #[test]
    fn cpu_percent_rejects_degenerate_inputs() {
        assert_eq!(cpu_percent(Duration::from_secs(1), Duration::ZERO, 4), None);
        assert_eq!(
            cpu_percent(Duration::from_secs(1), Duration::from_secs(1), 0),
            None
        );
    }

    #[test]
    fn used_percent_math_and_guards() {
        assert_eq!(used_percent(8, 16), Some(50.0));
        assert_eq!(used_percent(0, 16), Some(0.0));
        assert_eq!(used_percent(16, 16), Some(100.0));
        // inconsistent counters clamp instead of reporting >100 or NaN
        assert_eq!(used_percent(20, 16), Some(100.0));
        assert_eq!(used_percent(8, 0), None);
    }

    #[test]
    fn sampler_reports_cpu_on_first_poll_after_baseline() {
        let t0 = Instant::now();
        // baseline consumes tick[0] + trees[0]
        let mut src = MockSource::new(
            vec![t0, tick(t0, 1)],
            vec![tree(&[(1, 1_000, 100)]), tree(&[(1, 1_500, 120)])],
        );
        src.cores = 2;
        let mut sampler = ResourceSampler::new(src);
        let s = sampler.sample();
        assert_eq!(s.process_tree_cpu_percent, Some(25.0)); // +0.5s cpu / 1s wall / 2 cores
        assert_eq!(s.process_tree_working_set_bytes, Some(120));
    }

    #[test]
    fn sampler_cpu_none_when_baseline_failed() {
        let t0 = Instant::now();
        let mut sampler = ResourceSampler::new(MockSource::new(
            vec![t0, tick(t0, 1), tick(t0, 2)],
            vec![
                Err(io::Error::other("boom")),
                tree(&[(1, 1_000, 100)]),
                tree(&[(1, 2_000, 100)]),
            ],
        ));
        // baseline failed -> first poll only establishes the baseline
        let s1 = sampler.sample();
        assert_eq!(s1.process_tree_cpu_percent, None);
        // second poll has a real delta
        let s2 = sampler.sample();
        assert_eq!(s2.process_tree_cpu_percent, Some(100.0));
    }

    #[test]
    fn sampler_rebaselines_after_transient_read_error() {
        let t0 = Instant::now();
        let mut sampler = ResourceSampler::new(MockSource::new(
            vec![t0, tick(t0, 1), tick(t0, 2), tick(t0, 3), tick(t0, 4)],
            vec![
                tree(&[(1, 1_000, 100)]), // construction baseline
                Err(io::Error::other("snapshot failed")),
                tree(&[(1, 5_000, 100)]), // re-baseline tick: no delta reported
                tree(&[(1, 5_500, 100)]),
                tree(&[(1, 6_000, 100)]),
            ],
        ));
        // the failing read degrades the whole tree section for that tick
        let degraded = sampler.sample();
        assert_eq!(degraded.process_tree_cpu_percent, None);
        assert_eq!(degraded.process_tree_working_set_bytes, None);
        // the next good read only re-establishes the baseline
        assert_eq!(sampler.sample().process_tree_cpu_percent, None);
        assert_eq!(sampler.sample().process_tree_working_set_bytes, Some(100));
        // and the tick after that reports the delta since the re-baseline
        assert_eq!(sampler.sample().process_tree_cpu_percent, Some(50.0));
    }

    #[test]
    fn sampler_clamps_cpu_over_capacity() {
        let t0 = Instant::now();
        let mut src = MockSource::new(
            vec![t0, tick(t0, 1)],
            vec![tree(&[(1, 0, 0)]), tree(&[(1, 5_000, 0)])], // 5 core-seconds in 1s wall
        );
        src.cores = 4;
        let mut sampler = ResourceSampler::new(src);
        assert_eq!(sampler.sample().process_tree_cpu_percent, Some(100.0));
    }

    #[test]
    fn sampler_zero_wall_interval_is_none_not_nan() {
        let t0 = Instant::now();
        let mut sampler = ResourceSampler::new(MockSource::new(
            vec![t0, t0],
            vec![tree(&[(1, 0, 0)]), tree(&[(1, 500, 0)])],
        ));
        let s = sampler.sample();
        assert_eq!(s.process_tree_cpu_percent, None);
    }

    #[test]
    fn sampler_memory_and_gpu_passthrough_with_none_honesty() {
        let t0 = Instant::now();
        let mut src = MockSource::new(
            vec![t0, tick(t0, 1), tick(t0, 2)],
            vec![tree(&[(1, 0, 0)]), tree(&[(1, 0, 0)]), tree(&[(1, 0, 0)])],
        );
        src.memory = Some(SystemMemory {
            total_bytes: 16,
            available_bytes: 8,
        });
        src.gpu = Some(GpuLive {
            utilization_percent: Some(33.5),
            vram_used_bytes: Some(1_000),
        });
        let mut sampler = ResourceSampler::new(src);
        let s = sampler.sample();
        assert_eq!(s.system_ram_used_percent, Some(50.0));
        assert_eq!(s.system_ram_used_bytes, Some(8));
        assert_eq!(s.system_ram_total_bytes, Some(16));
        assert_eq!(s.gpu_utilization_percent, Some(33.5));
        assert_eq!(s.gpu_vram_used_bytes, Some(1_000));

        // absent sources degrade to None, not errors or guesses
        let mut bare = MockSource::new(vec![t0, tick(t0, 1)], vec![tree(&[]), tree(&[])]);
        bare.cores = 1;
        let mut sampler = ResourceSampler::new(bare);
        let s = sampler.sample();
        assert_eq!(s.system_ram_used_percent, None);
        assert_eq!(s.system_ram_total_bytes, None);
        assert_eq!(s.gpu_utilization_percent, None);
        assert_eq!(s.process_tree_working_set_bytes, None); // empty tree = n/a
        assert_eq!(s.process_tree_cpu_percent, Some(0.0)); // empty tree still burns 0 cpu
    }
}
