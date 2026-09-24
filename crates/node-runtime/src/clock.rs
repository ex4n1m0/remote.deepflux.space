//! Session clocks (perf-counter schema: "own monotonic clock, zero-based
//! at session start, in nanoseconds").
//!
//! The session state machines are clock-injected (`now_ms`), so the same
//! source feeds both views: `now_ns()` for the diagnostics timestamps and
//! `now_ms()` for the machines and the timer queue. Two implementations:
//!
//! * [`MonotonicClock`] — the production clock over `std::time::Instant`.
//! * [`ManualClock`] — a settable clock for deterministic tests
//!   (`tests/world_parity.rs` advances it by hand exactly like the `World`
//!   harness in `crates/session/tests/two_peers.rs`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Time source for a node. `Send + Sync` so every pipeline stage can share
/// one clone of the handle and its stamps stay mutually subtractable
/// within the device.
pub trait Clock: Send + Sync {
    /// Nanoseconds since node start (zero-based monotonic).
    fn now_ns(&self) -> u64;
    /// Milliseconds since node start — the unit the session machines and
    /// their timers speak.
    fn now_ms(&self) -> u64 {
        self.now_ns() / 1_000_000
    }
}

/// Production clock. `Clone` handles share the same start instant.
#[derive(Clone)]
pub struct MonotonicClock {
    start: Instant,
}

impl MonotonicClock {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    fn now_ns(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }
}

/// Test clock: an atomic millisecond counter the harness advances.
/// `now_ns` derives from the stored milliseconds, so ns/ms never disagree.
pub struct ManualClock {
    ms: AtomicU64,
}

impl ManualClock {
    pub fn new() -> Self {
        Self {
            ms: AtomicU64::new(0),
        }
    }

    /// Advance to an absolute time (ms). Monotonic: never moves backwards.
    pub fn set_ms(&self, ms: u64) {
        self.ms.fetch_max(ms, Ordering::Release);
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now_ns(&self) -> u64 {
        self.ms.load(Ordering::Acquire) * 1_000_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_clock_is_zero_based_and_increasing() {
        let clock = MonotonicClock::new();
        assert!(clock.now_ns() < 10_000_000, "starts near zero");
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(clock.now_ns() >= 2_000_000);
        assert!(clock.now_ms() <= clock.now_ns() / 1_000_000 + 1);
    }

    #[test]
    fn manual_clock_is_monotonic_and_settable() {
        let clock = ManualClock::new();
        assert_eq!(clock.now_ms(), 0);
        clock.set_ms(5_000);
        clock.set_ms(4_000); // backwards is ignored
        assert_eq!(clock.now_ms(), 5_000);
        assert_eq!(clock.now_ns(), 5_000_000_000);
    }
}
