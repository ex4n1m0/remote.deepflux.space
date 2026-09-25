//! 60 Hz frame pacing (M1 QA F20 fix).
//!
//! The M1 loop slept `1/fps` after the *start* of each iteration and then
//! paid `next_frame` plus sleep granularity on top, making the real period
//! 16.7 ms + ~0.8 ms → 57 fps. The fix has two parts:
//!
//! 1. **Absolute deadlines**: the pacer keeps `next = start + k * period`
//!    and waits until that absolute instant, so per-iteration work is not
//!    additive across iterations (drift-free by construction).
//! 2. **High-resolution waitable timer** (`CreateWaitableTimerExW` with
//!    `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION`, Windows 10 1803+): ~0.5 ms
//!    accuracy instead of the ~1–15.6 ms quantum of `thread::sleep`, so
//!    the wait lands before the deadline instead of a whole tick after it.
//!
//! If the high-resolution flag is unsupported the pacer falls back to a
//! plain waitable timer (still absolute-deadline), and if timer creation
//! fails entirely, to `thread::sleep` with a short spin finish. Every mode
//! keeps the same absolute-deadline contract; only accuracy differs.
//!
//! Backpressure (invariant 3): when the consumer is more than one period
//! behind, obsolete ticks are skipped and counted — never queued.

use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, CreateWaitableTimerExW, INFINITE, SetWaitableTimer,
    TIMER_ALL_ACCESS, WaitForSingleObject,
};

/// Outcome of one [`FramePacer::wait`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tick {
    /// True when this tick arrived without needing a skip resync.
    pub on_time: bool,
}

pub struct FramePacer {
    period: Duration,
    next: Option<Instant>,
    timer: Option<HANDLE>,
    pub ticks: u64,
    pub skipped: u64,
    pub mode: &'static str,
}

// The handle is used from the owning thread only.
unsafe impl Send for FramePacer {}

impl FramePacer {
    /// Create a pacer for `fps` ticks per second. Does not start it.
    pub fn new(fps: u32) -> Self {
        let fps = fps.max(1);
        let period = Duration::from_secs_f64(1.0 / fps as f64);
        let (timer, mode) = unsafe {
            match CreateWaitableTimerExW(
                None,
                None,
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                TIMER_ALL_ACCESS.0,
            ) {
                Ok(handle) => (Some(handle), "high-resolution waitable timer"),
                Err(_) => {
                    match CreateWaitableTimerExW(None, None, Default::default(), TIMER_ALL_ACCESS.0)
                    {
                        Ok(handle) => (Some(handle), "waitable timer"),
                        Err(_) => (None, "thread::sleep fallback"),
                    }
                }
            }
        };
        Self {
            period,
            next: None,
            timer,
            ticks: 0,
            skipped: 0,
            mode,
        }
    }

    /// Arm the schedule: the first [`wait`](Self::wait) returns after one
    /// full period.
    pub fn start(&mut self) {
        self.next = Some(Instant::now() + self.period);
    }

    /// The configured tick period.
    pub fn period(&self) -> Duration {
        self.period
    }

    /// The configured rate, fps (M5 congestion fps cap).
    pub fn fps(&self) -> u32 {
        (1.0 / self.period.as_secs_f64()).round() as u32
    }

    /// Change the rate (M5 congestion fps cap / cap lift). The schedule
    /// resyncs to now + new period — no timer recreation (the handle is
    /// reused), no queued backlog. Same-rate calls are no-ops.
    pub fn retarget(&mut self, fps: u32) {
        let fps = fps.max(1);
        if fps == self.fps() {
            return;
        }
        self.period = Duration::from_secs_f64(1.0 / fps as f64);
        self.next = Some(Instant::now() + self.period);
    }

    /// Block until the next absolute deadline. If the caller is behind by
    /// more than one period, deadlines are skipped (counted) and the
    /// schedule resyncs to now + period — obsolete time is dropped, never
    /// queued.
    pub fn wait(&mut self) -> Tick {
        let now = Instant::now();
        let Some(mut deadline) = self.next else {
            self.start();
            return Tick { on_time: true };
        };
        if deadline <= now {
            // We are at/past the deadline already: count the missed ticks.
            while deadline <= now {
                deadline += self.period;
                self.skipped += 1;
            }
            self.next = Some(deadline);
            self.ticks += 1;
            return Tick { on_time: false };
        }
        self.wait_until(deadline);
        self.ticks += 1;
        self.next = Some(deadline + self.period);
        Tick { on_time: true }
    }

    /// Sleep until the absolute `deadline` with the best available
    /// primitive. Waitable timer: one `SetWaitableTimer` (relative
    /// negative due time, 100 ns units) + wait. Sleep fallback parks
    /// coarsely and spins the last ~2 ms for accuracy.
    fn wait_until(&mut self, deadline: Instant) {
        if let Some(handle) = self.timer {
            let remaining = deadline.saturating_duration_since(Instant::now());
            // Negative value = relative due time in 100 ns units.
            let due: i64 = -((remaining.as_nanos() / 100).max(1) as i64);
            let armed = unsafe { SetWaitableTimer(handle, &due, 0, None, None, false).is_ok() };
            if armed {
                unsafe {
                    let _ = WaitForSingleObject(handle, INFINITE);
                }
                return;
            }
        }
        loop {
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            let remaining = deadline - now;
            if remaining > Duration::from_millis(2) {
                std::thread::sleep(remaining - Duration::from_millis(2));
            } else {
                std::thread::yield_now();
            }
        }
    }
}

impl Drop for FramePacer {
    fn drop(&mut self) {
        if let Some(handle) = self.timer.take() {
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sixty_hz_pacer_holds_rate_within_tolerance() {
        let mut pacer = FramePacer::new(60);
        assert_eq!(pacer.period(), Duration::from_secs_f64(1.0 / 60.0));
        pacer.start();
        let started = Instant::now();
        let ticks = 120;
        for _ in 0..ticks {
            pacer.wait();
        }
        let elapsed = started.elapsed();
        // 120 ticks at 60 Hz = 2.0 s. Tolerate scheduling noise: 5%.
        let expect = Duration::from_secs_f64(ticks as f64 / 60.0);
        assert!(
            elapsed >= expect,
            "pacer ran fast: {elapsed:?} for {ticks} ticks ({})",
            pacer.mode
        );
        assert!(
            elapsed <= expect + Duration::from_millis(100),
            "pacer ran slow: {elapsed:?} for {ticks} ticks (mode {})",
            pacer.mode
        );
        assert!(pacer.skipped == 0, "no skips expected in a bare loop");
    }

    #[test]
    fn behind_consumer_skips_obsolete_ticks_instead_of_bursting() {
        let mut pacer = FramePacer::new(60);
        pacer.start();
        pacer.wait();
        // Simulate the consumer stalling 5 periods (e.g. slow encode).
        std::thread::sleep(pacer.period() * 5);
        let tick = pacer.wait();
        assert!(!tick.on_time);
        assert!(
            pacer.skipped >= 3,
            "obsolete ticks skipped: {}",
            pacer.skipped
        );
        // After the resync, the next wait is a full period again.
        let t0 = Instant::now();
        pacer.wait();
        assert!(t0.elapsed() >= pacer.period() * 9 / 10);
    }

    /// M5: the congestion controller's fps cap retargets the live pacer —
    /// same handle, new period, resynced schedule.
    #[test]
    fn retarget_changes_the_rate_without_recreating_the_pacer() {
        let mut pacer = FramePacer::new(60);
        pacer.start();
        pacer.wait();
        let before = pacer.fps();
        pacer.retarget(30);
        assert_eq!(pacer.fps(), 30);
        assert_eq!(pacer.period(), Duration::from_secs_f64(1.0 / 30.0));
        // The first wait after retarget is a full new period.
        let t0 = Instant::now();
        pacer.wait();
        assert!(
            t0.elapsed() >= Duration::from_millis(32),
            "30 Hz period must apply immediately: {:?}",
            t0.elapsed()
        );
        // Idempotent same-rate call.
        pacer.retarget(30);
        assert_eq!(pacer.fps(), 30);
        pacer.retarget(0);
        assert_eq!(pacer.fps(), 1, "fps clamps at 1");
        assert_eq!(before, 60);
    }
}
