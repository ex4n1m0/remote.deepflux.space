//! The governor's enforcement seam (ADR-035 §3): the platform-neutral
//! trait behind which OS-level limiting lives, so nothing
//! Windows-shaped leaks above it (gate D19). On Windows the seam is the
//! `modelswarm-winjob` crate the desktop already uses to tie engine
//! children to its lifetime: the SAME kill-on-close job objects gain a
//! committed-memory cap (`JOB_OBJECT_LIMIT_PROCESSMEMORY`), so a runaway
//! engine hits the cap instead of exhausting the pagefile and freezing
//! the machine — the M2 exit criterion "memory-exhaustion tests cannot
//! freeze the machine".
//!
//! The cap is a BACKSTOP, not the ceiling itself: the OS enforces it on
//! COMMITTED memory of the job members, while the admission projection
//! is working-set arithmetic. Because mapped (section-backed) weights
//! largely do not count against commit, the cap can only bite at or
//! before the point the working-set projection would reach the enforced
//! system ceiling — never later. The binding decision remains the
//! verdict; a caller that wants the backstop treated as mandatory may
//! inspect [`EnforcementRecord`] and degrade on any `NotEnforced` label.
//!
//! Platforms without a wired seam return the honest
//! `not_enforced_unsupported_platform` record (Linux cgroup-v2 path is
//! recorded follow-up work in the ADR); the admission verdict itself is
//! still binding everywhere, because it is the verdict the consumer
//! consumes — not a suggestion.

/// What the governor armed (or the honest label for why it did not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementRecord {
    /// The OS-level cap is armed over the supervised engine tree.
    /// `mechanism` names the enforcing primitive
    /// (e.g. `winjob:JOB_OBJECT_LIMIT_PROCESS_MEMORY`); `cap_bytes` is the
    /// committed-memory bound.
    Armed {
        mechanism: &'static str,
        cap_bytes: u64,
    },
    /// Nothing was armed; `label` says exactly why (frozen vocabulary,
    /// ADR-035 §5):
    /// - `not_enforced_no_admission` — the verdict degraded, so there is
    ///   nothing to arm for;
    /// - `not_enforced_caller_opted_out` — the request did not ask for
    ///   the backstop;
    /// - `not_enforced_unsupported_platform` — no OS seam wired here;
    /// - `not_enforced_no_supervised_processes` — the platform seam has
    ///   no processes to cap (and cannot self-cap the caller);
    /// - `not_enforced_arm_failed` — the OS refused the cap (label only;
    ///   the verdict carries no error text — check platform logs);
    /// - `not_enforced_cap_underflow` — the cap arithmetic degenerated
    ///   (a belt; provably unreachable on Admit today).
    NotEnforced { label: &'static str },
}

impl EnforcementRecord {
    /// True when a cap is armed.
    pub fn armed(&self) -> bool {
        matches!(self, EnforcementRecord::Armed { .. })
    }

    /// The mechanism or the not-enforced label (one stable string for
    /// telemetry either way).
    pub fn label(&self) -> &'static str {
        match self {
            EnforcementRecord::Armed { mechanism, .. } => mechanism,
            EnforcementRecord::NotEnforced { label } => label,
        }
    }
}

/// The platform-neutral enforcement seam. Implementations must be cheap
/// (a couple of Win32 calls on Windows) and idempotent — the governor
/// re-arms on every admitting `evaluate`, tightening or relaxing with
/// the live sample.
pub trait CeilingEnforcer: Send + std::any::Any {
    /// Arms (or re-arms) the committed-memory cap over the supervised
    /// engine tree and reports what happened. Must never panic: an
    /// enforcement failure is an honest [`EnforcementRecord::NotEnforced`],
    /// not a crash of the governing process.
    fn arm_tree_commit_cap(&mut self, cap_bytes: u64) -> EnforcementRecord;

    /// Downcast support so callers holding the governor can inspect
    /// their concrete enforcer (tests assert on [`MockEnforcer`] state
    /// through it). Required because the `&Self -> &dyn Any` coercion
    /// needs the concrete type: implement as `self`.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Windows: enforces through the `modelswarm-winjob` job objects — the
/// same retained kill-on-close jobs that already supervise the engine
/// children. Arming applies the cap to every retained job AND leaves it
/// remembered in winjob so children assigned later (future engine
/// spawns) inherit the same limit at assignment time.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WinJobEnforcer;

#[cfg(windows)]
impl CeilingEnforcer for WinJobEnforcer {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn arm_tree_commit_cap(&mut self, cap_bytes: u64) -> EnforcementRecord {
        match modelswarm_winjob::apply_tree_memory_cap(cap_bytes) {
            Ok(_jobs_capped) => EnforcementRecord::Armed {
                mechanism: "winjob:JOB_OBJECT_LIMIT_PROCESS_MEMORY",
                cap_bytes,
            },
            Err(_) => EnforcementRecord::NotEnforced {
                label: "not_enforced_arm_failed",
            },
        }
    }
}

/// The honest "no OS seam wired here" enforcer: every platform without a
/// wired seam (all non-Windows platforms today; the cgroup-v2 path for
/// Linux is the recorded follow-up in ADR-035 §7). Defined on every
/// platform so its label is pinnable by tests everywhere; only
/// [`platform_enforcer`] selects it — never on Windows.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedEnforcer;

impl CeilingEnforcer for UnsupportedEnforcer {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn arm_tree_commit_cap(&mut self, _cap_bytes: u64) -> EnforcementRecord {
        EnforcementRecord::NotEnforced {
            label: "not_enforced_unsupported_platform",
        }
    }
}

/// Scripted enforcer for tests (ours and the desktop's) — records every
/// armed cap in order so a test can assert exactly what the governor
/// asked the OS seam to do, without any OS in the loop.
#[derive(Debug, Default)]
pub struct MockEnforcer {
    /// Every cap passed to `arm_tree_commit_cap`, in call order.
    pub armed: Vec<u64>,
    /// When true, the seam reports an arm failure (the honest
    /// `not_enforced_arm_failed` record) instead of arming.
    pub fail: bool,
}

impl MockEnforcer {
    /// An enforcer that arms successfully.
    pub fn new() -> Self {
        Self::default()
    }
}

impl CeilingEnforcer for MockEnforcer {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn arm_tree_commit_cap(&mut self, cap_bytes: u64) -> EnforcementRecord {
        if self.fail {
            return EnforcementRecord::NotEnforced {
                label: "not_enforced_arm_failed",
            };
        }
        self.armed.push(cap_bytes);
        EnforcementRecord::Armed {
            mechanism: "mock",
            cap_bytes,
        }
    }
}

/// The platform enforcer for [`crate::ResourceGovernor::platform`].
pub fn platform_enforcer() -> Box<dyn CeilingEnforcer> {
    #[cfg(windows)]
    {
        Box::new(WinJobEnforcer)
    }
    #[cfg(not(windows))]
    {
        Box::new(UnsupportedEnforcer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_enforcer_records_armed_caps_in_order() {
        let mut e = MockEnforcer::new();
        assert_eq!(
            e.arm_tree_commit_cap(1_000),
            EnforcementRecord::Armed {
                mechanism: "mock",
                cap_bytes: 1_000
            }
        );
        assert_eq!(
            e.arm_tree_commit_cap(2_000),
            EnforcementRecord::Armed {
                mechanism: "mock",
                cap_bytes: 2_000
            }
        );
        assert_eq!(e.armed, vec![1_000, 2_000]);
    }

    #[test]
    fn mock_enforcer_failure_is_an_honest_not_enforced_record() {
        let mut e = MockEnforcer {
            armed: Vec::new(),
            fail: true,
        };
        let r = e.arm_tree_commit_cap(1_000);
        assert!(!r.armed());
        assert_eq!(r.label(), "not_enforced_arm_failed");
        assert!(e.armed.is_empty());
    }

    #[test]
    fn record_labels_are_stable() {
        assert_eq!(
            EnforcementRecord::NotEnforced {
                label: "not_enforced_unsupported_platform"
            }
            .label(),
            "not_enforced_unsupported_platform"
        );
        assert_eq!(
            EnforcementRecord::Armed {
                mechanism: "m",
                cap_bytes: 1
            }
            .label(),
            "m"
        );
    }

    #[test]
    fn unsupported_platform_says_so_honestly() {
        let mut e = UnsupportedEnforcer;
        let r = e.arm_tree_commit_cap(1_000);
        assert_eq!(
            r,
            EnforcementRecord::NotEnforced {
                label: "not_enforced_unsupported_platform"
            }
        );
    }
}
