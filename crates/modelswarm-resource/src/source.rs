//! The platform seam every sampler reads through, plus the pure data types
//! and helpers the per-OS modules share. Platform modules
//! ([`crate::windows`], [`crate::linux`], [`crate::fallback`]) implement
//! [`SampleSource`]; the [`crate::ResourceSampler`] itself is pure math over
//! whatever the source reports, which is what makes the delta/percentage
//! logic mockable and unit-testable on every OS.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::time::{Duration, Instant};

/// One process's contribution to a sampling tick. `cpu_time` is the
/// cumulative kernel+user CPU time (monotonic for a live process);
/// `working_set` is `None` when the OS refused or cannot report memory for
/// that process (e.g. an access-denied handle), which the tree aggregate
/// simply skips rather than failing the whole sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcSample {
    pub pid: u32,
    pub cpu_time: Duration,
    pub working_set: Option<u64>,
}

/// A point-in-time reading of every process in the configured tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeSnapshot {
    pub procs: Vec<ProcSample>,
}

impl TreeSnapshot {
    /// The cumulative-CPU-time view used as the delta baseline.
    pub fn cpu_map(&self) -> HashMap<u32, Duration> {
        self.procs.iter().map(|p| (p.pid, p.cpu_time)).collect()
    }

    /// Total tree CPU time gained since `prev`. Robust to tree churn:
    /// a PID absent from `prev` (newly spawned engine) contributes zero
    /// until it has a baseline, a PID absent now (engine restart) simply
    /// drops out, and a per-PID backwards reading (PID reuse) saturates at
    /// zero — none of these zero out or poison the whole tree's delta.
    pub fn cpu_delta_since(&self, prev: &HashMap<u32, Duration>) -> Duration {
        self.procs
            .iter()
            .map(|p| {
                let base = prev.get(&p.pid).copied().unwrap_or(p.cpu_time);
                p.cpu_time.saturating_sub(base)
            })
            .sum()
    }

    /// Sum of the working sets the OS actually reported; `None` when
    /// nothing in the tree was reportable (empty tree = "n/a", the panel
    /// shows the engine as not running).
    pub fn total_working_set(&self) -> Option<u64> {
        let mut total: Option<u64> = None;
        for p in &self.procs {
            if let Some(ws) = p.working_set {
                total = Some(total.unwrap_or(0).saturating_add(ws));
            }
        }
        total
    }
}

/// System physical memory at a tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemMemory {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

impl SystemMemory {
    /// Physical bytes in use (`total - available`, saturating).
    pub fn used_bytes(&self) -> u64 {
        self.total_bytes.saturating_sub(self.available_bytes)
    }
}

/// Live GPU counters. Both fields are independently honest: a source that
/// cannot read one of them reports `None` for it rather than a guess.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct GpuLive {
    /// Utilization of the busiest adapter, 0–100 (sum over that adapter's
    /// engine instances, clamped — concurrent 3D + decode can exceed 100
    /// before clamping).
    pub utilization_percent: Option<f64>,
    /// Dedicated VRAM in use on the same adapter (bytes). WDDM-tracked
    /// usage, i.e. the Task-Manager "dedicated GPU memory" approximation,
    /// not a hardware register read.
    pub vram_used_bytes: Option<u64>,
}

/// Which processes constitute "the process tree" for CPU/working-set
/// aggregation.
///
/// Scope note for the desktop (owner request 2026-10-12): the natural set
/// is the winjob job-object membership — every engine child
/// `modelswarm_winjob::assign_child` accepted is in the kill-on-close job.
/// Until the winjob crate exposes a membership query, `CurrentTree`
/// (this process + descendants) covers the same processes because the
/// desktop spawns the engine as its own child; `Roots` lets a caller pass
/// an explicit PID set (e.g. the known engine child) when the sampler runs
/// outside the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessScope {
    /// `std::process::id()` plus every descendant (panel default: the
    /// desktop app, the node, and the supervised engine children — in the
    /// ADR-031 composed mode the engine is in-process and is simply part
    /// of this process's own CPU time).
    CurrentTree,
    /// Explicit root PIDs plus their descendants.
    Roots(Vec<u32>),
}

impl ProcessScope {
    /// Root PIDs to walk descendants from.
    pub fn root_pids(&self) -> Vec<u32> {
        match self {
            ProcessScope::CurrentTree => vec![std::process::id()],
            ProcessScope::Roots(pids) => pids.clone(),
        }
    }
}

/// The per-OS sampling seam. Implementations must be cheap (a poll costs
/// one process-table pass plus, on Windows, one PDH collect — designed for
/// a <= 1 Hz UI cadence, never per-frame) and must not re-detect static
/// hardware: static geometry belongs to the caller's M1 profile
/// ([`crate::profile::HardwareProfile`]), not to per-sample reads.
pub trait SampleSource: Send {
    /// Monotonic clock (mockable in tests).
    fn now(&self) -> Instant;
    /// Total logical processors of the machine (CPU% is normalized by
    /// this, Task-Manager style: 100% = all cores busy).
    fn logical_cores(&self) -> u32;
    /// CPU time + working set of every process in the configured scope.
    fn process_tree(&self) -> io::Result<TreeSnapshot>;
    /// System physical memory.
    fn system_memory(&self) -> io::Result<SystemMemory>;
    /// Live GPU counters, or `None` when the platform provides none.
    fn gpu(&mut self) -> Option<GpuLive>;
}

impl<S: SampleSource + ?Sized> SampleSource for Box<S> {
    fn now(&self) -> Instant {
        (**self).now()
    }
    fn logical_cores(&self) -> u32 {
        (**self).logical_cores()
    }
    fn process_tree(&self) -> io::Result<TreeSnapshot> {
        (**self).process_tree()
    }
    fn system_memory(&self) -> io::Result<SystemMemory> {
        (**self).system_memory()
    }
    fn gpu(&mut self) -> Option<GpuLive> {
        (**self).gpu()
    }
}

/// Every PID reachable from `roots` via the `parent_of` map (roots
/// included). Guards against PID-reuse cycles by never visiting a PID
/// twice, so a corrupted/odd parent graph cannot loop.
pub fn descendant_pids(parent_of: &HashMap<u32, u32>, roots: &[u32]) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (&pid, &ppid) in parent_of {
        children.entry(ppid).or_default().push(pid);
    }
    for kids in children.values_mut() {
        kids.sort_unstable();
    }
    let mut seen: HashSet<u32> = HashSet::new();
    let mut queue: VecDeque<u32> = VecDeque::new();
    for &r in roots {
        if seen.insert(r) {
            queue.push_back(r);
        }
    }
    let mut out = Vec::new();
    while let Some(pid) = queue.pop_front() {
        out.push(pid);
        if let Some(kids) = children.get(&pid) {
            for &k in kids {
                if seen.insert(k) {
                    queue.push_back(k);
                }
            }
        }
    }
    out
}

/// Extracts the adapter key from a PDH GPU instance name such as
/// `pid_1234_luid_0x00000000_0x0000C3B7_phys_0_eng_0_engtype_3D`
/// (engine counters) or
/// `pid_1234_luid_0x00000000_0x0000C3B7_phys_0` (process-memory
/// counters), so utilization and VRAM can be correlated per adapter.
/// `None` when the name carries no LUID (not a GPU instance).
#[cfg(any(windows, test))]
pub(crate) fn luid_of_instance(name: &str) -> Option<String> {
    let tokens: Vec<&str> = name.split('_').collect();
    let i = tokens.iter().position(|t| *t == "luid")?;
    let (high, low) = (tokens.get(i + 1)?, tokens.get(i + 2)?);
    if !high.starts_with("0x") || !low.starts_with("0x") {
        return None;
    }
    Some(format!("luid_{high}_{low}"))
}

/// Scripted [`SampleSource`] for tests (ours and the desktop's). Every
/// field is consumed in order: `now()` pops the next tick, `process_tree()`
/// pops the next scripted result; both panic when exhausted so a test bug
/// fails loudly instead of silently repeating stale data.
#[derive(Debug, Default)]
pub struct MockSource {
    pub cores: u32,
    pub ticks: RefCell<VecDeque<Instant>>,
    pub trees: RefCell<VecDeque<io::Result<TreeSnapshot>>>,
    pub memory: Option<SystemMemory>,
    pub gpu: Option<GpuLive>,
}

impl MockSource {
    /// Ticks are consumed one per `now()` call: the first by
    /// [`crate::ResourceSampler::new`]'s baseline, then one per
    /// [`crate::ResourceSampler::sample`].
    pub fn new(ticks: Vec<Instant>, trees: Vec<io::Result<TreeSnapshot>>) -> Self {
        Self {
            cores: 1,
            ticks: RefCell::new(ticks.into()),
            trees: RefCell::new(trees.into()),
            memory: None,
            gpu: None,
        }
    }
}

impl SampleSource for MockSource {
    fn now(&self) -> Instant {
        self.ticks
            .borrow_mut()
            .pop_front()
            .expect("mock clock exhausted")
    }
    fn logical_cores(&self) -> u32 {
        self.cores
    }
    fn process_tree(&self) -> io::Result<TreeSnapshot> {
        self.trees
            .borrow_mut()
            .pop_front()
            .expect("mock trees exhausted")
    }
    fn system_memory(&self) -> io::Result<SystemMemory> {
        self.memory
            .ok_or_else(|| io::Error::other("mock: no system_memory configured"))
    }
    fn gpu(&mut self) -> Option<GpuLive> {
        self.gpu
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descendants_walk_tree_and_exclude_siblings() {
        let mut parent_of = HashMap::new();
        for (pid, ppid) in [(2u32, 1u32), (3, 1), (4, 2), (5, 9)] {
            parent_of.insert(pid, ppid);
        }
        let mut got = descendant_pids(&parent_of, &[1]);
        got.sort_unstable();
        assert_eq!(got, vec![1, 2, 3, 4]);
        assert_eq!(descendant_pids(&parent_of, &[3]), vec![3]);
        // a root not present in the map is still reported (it is a live PID)
        assert_eq!(descendant_pids(&parent_of, &[42]), vec![42]);
    }

    #[test]
    fn descendants_terminate_on_pid_reuse_cycles() {
        let mut parent_of = HashMap::new();
        for (pid, ppid) in [(1u32, 2u32), (2, 1), (3, 1)] {
            parent_of.insert(pid, ppid);
        }
        let mut got = descendant_pids(&parent_of, &[1]);
        got.sort_unstable();
        assert_eq!(got, vec![1, 2, 3]);
    }

    #[test]
    fn luid_extraction_from_engine_and_memory_instance_names() {
        assert_eq!(
            luid_of_instance("pid_1234_luid_0x00000000_0x0000C3B7_phys_0_eng_0_engtype_3D"),
            Some("luid_0x00000000_0x0000C3B7".to_string())
        );
        assert_eq!(
            luid_of_instance("pid_7_luid_0x00000000_0x0000D10E_phys_0"),
            Some("luid_0x00000000_0x0000D10E".to_string())
        );
        assert_eq!(luid_of_instance("pid_7_phys_0"), None);
        assert_eq!(luid_of_instance("garbage"), None);
        // LUID tokens must be hex words, not the following fields
        assert_eq!(luid_of_instance("pid_7_luid_0x1_phys_0"), None);
    }

    #[test]
    fn tree_delta_survives_churn() {
        let mk = |entries: &[(u32, u64)]| TreeSnapshot {
            procs: entries
                .iter()
                .map(|&(pid, ms)| ProcSample {
                    pid,
                    cpu_time: Duration::from_millis(ms),
                    working_set: Some(1000),
                })
                .collect(),
        };
        let baseline = mk(&[(1, 10_000), (2, 5_000)]);
        let prev = baseline.cpu_map();
        // pid 1 advanced 1s, pid 2 died, pid 3 spawned (no baseline yet)
        let now = mk(&[(1, 11_000), (3, 7_000)]);
        assert_eq!(now.cpu_delta_since(&prev), Duration::from_secs(1));
        // a per-PID backwards reading (PID reuse) contributes zero, not negative
        let reset = mk(&[(1, 11_000), (2, 400)]);
        assert_eq!(reset.cpu_delta_since(&prev), Duration::from_secs(1));
    }

    #[test]
    fn working_set_sums_reported_entries_only() {
        let tree = TreeSnapshot {
            procs: vec![
                ProcSample {
                    pid: 1,
                    cpu_time: Duration::ZERO,
                    working_set: Some(100),
                },
                ProcSample {
                    pid: 2,
                    cpu_time: Duration::ZERO,
                    working_set: Some(200),
                },
                ProcSample {
                    pid: 3,
                    cpu_time: Duration::ZERO,
                    working_set: None,
                },
            ],
        };
        assert_eq!(tree.total_working_set(), Some(300));
        assert_eq!(TreeSnapshot::default().total_working_set(), None);
    }

    #[test]
    fn mock_source_drains_in_order() {
        let base = Instant::now();
        let tree = TreeSnapshot::default();
        let mut src = MockSource::new(
            vec![base, base + Duration::from_secs(1)],
            vec![Ok(tree.clone()), Ok(tree)],
        );
        assert_eq!(src.now(), base);
        assert_eq!(
            SampleSource::process_tree(&src).unwrap(),
            TreeSnapshot::default()
        );
        assert_eq!(src.now(), base + Duration::from_secs(1));
        assert!(src.system_memory().is_err());
        assert_eq!(src.gpu(), None);
    }
}
