//! The real-clock timer queue matching `World` semantics
//! (`crates/session/tests/two_peers.rs`).
//!
//! The `World` fires timers in `(fire_at_ms, schedule_seq)` order and
//! advances its logical clock to each timer's fire time; this queue keeps
//! exactly that ordering discipline against the node's real clock:
//!
//! * [`TimerQueue::schedule`] assigns a monotonically increasing sequence
//!   number, so two timers with the same deadline fire in the order they
//!   were scheduled (deterministic tie-break — the property the
//!   `request_and_consent_timeouts_fire_in_schedule_order` scenario pins).
//! * [`TimerQueue::due`] drains everything at or before `now_ms` in that
//!   order, removing each entry as it is returned (a fired timer cannot
//!   re-fire; the machine re-arms by scheduling a fresh entry).
//! * [`TimerQueue::cancel`] removes matching `(machine, id)` entries —
//!   the runtime translates `Action::CancelTimer` into exactly this call,
//!   and the machines guarantee pairing (every `ScheduleTimer` for one
//!   `TimerId` is bracketed by cancels on every exit path).

use std::collections::BTreeMap;

use session::TimerId;

/// Which machine of the node a timer belongs to (mirrors `MachineRef`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MachineKind {
    Host,
    Controller,
}

impl MachineKind {
    pub fn name(self) -> &'static str {
        match self {
            MachineKind::Host => "host",
            MachineKind::Controller => "controller",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiredTimer {
    pub machine: MachineKind,
    pub id: TimerId,
    pub fire_at_ms: u64,
}

/// Ordered timer store. `(fire_at_ms, seq)` keyed `BTreeMap` gives the
/// World's drain order with O(log n) insert/cancel.
#[derive(Debug, Default)]
pub struct TimerQueue {
    entries: BTreeMap<(u64, u64), FiredTimer>,
    next_seq: u64,
}

impl TimerQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm a timer. Returns the schedule sequence (diagnostics only).
    pub fn schedule(&mut self, machine: MachineKind, id: TimerId, fire_at_ms: u64) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.insert(
            (fire_at_ms, seq),
            FiredTimer {
                machine,
                id,
                fire_at_ms,
            },
        );
        seq
    }

    /// Remove every timer with this `(machine, id)` — `Action::CancelTimer`.
    /// Returns how many entries were removed (0 or 1 for well-formed
    /// machines; the machines never double-schedule one id).
    pub fn cancel(&mut self, machine: MachineKind, id: TimerId) -> usize {
        let doomed: Vec<(u64, u64)> = self
            .entries
            .iter()
            .filter(|(_, t)| t.machine == machine && t.id == id)
            .map(|(key, _)| *key)
            .collect();
        let n = doomed.len();
        for key in doomed {
            self.entries.remove(&key);
        }
        n
    }

    /// Drain every timer due at or before `now_ms`, in `(fire_at, seq)`
    /// order. The caller fires the matching `*Timeout` event immediately
    /// for each returned entry.
    // `while let` would keep the map borrow alive across the `remove`
    // (clippy's suggestion does not borrow-check), hence `loop` + let-else.
    #[allow(clippy::while_let_loop)]
    pub fn due(&mut self, now_ms: u64) -> Vec<FiredTimer> {
        let mut out = Vec::new();
        loop {
            let Some((key, timer)) = self.entries.first_key_value() else {
                break;
            };
            if key.0 > now_ms {
                break;
            }
            let timer = *timer;
            let key = *key;
            self.entries.remove(&key);
            out.push(timer);
        }
        out
    }

    /// Next fire time (for sleep-until calculations); `None` when idle.
    pub fn next_deadline_ms(&self) -> Option<u64> {
        self.entries.first_key_value().map(|(key, _)| key.0)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_deadline_fires_in_schedule_order() {
        let mut q = TimerQueue::new();
        q.schedule(MachineKind::Controller, TimerId::ControllerRequest, 10_000);
        q.schedule(MachineKind::Host, TimerId::HostConsent, 10_000);
        let due = q.due(10_000);
        assert_eq!(due.len(), 2);
        // Sequence order: controller's request timer was scheduled first.
        assert_eq!(due[0].machine, MachineKind::Controller);
        assert_eq!(due[0].id, TimerId::ControllerRequest);
        assert_eq!(due[1].machine, MachineKind::Host);
        assert!(q.is_empty());
    }

    #[test]
    fn due_respects_fire_at_order_and_boundary() {
        let mut q = TimerQueue::new();
        q.schedule(MachineKind::Host, TimerId::HostConnect, 20_000);
        q.schedule(MachineKind::Host, TimerId::HostConsent, 10_000);
        assert!(q.due(9_999).is_empty());
        let due = q.due(10_000);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, TimerId::HostConsent);
        let due = q.due(25_000);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, TimerId::HostConnect);
    }

    #[test]
    fn cancel_removes_only_that_machine_id() {
        let mut q = TimerQueue::new();
        q.schedule(MachineKind::Host, TimerId::HostConnect, 100);
        q.schedule(MachineKind::Controller, TimerId::ControllerConnect, 100);
        q.schedule(MachineKind::Controller, TimerId::ControllerRequest, 200);
        assert_eq!(
            q.cancel(MachineKind::Controller, TimerId::ControllerConnect),
            1
        );
        let due = q.due(1_000);
        assert_eq!(due.len(), 2);
        assert!(
            due.iter()
                .all(|t| !(t.machine == MachineKind::Controller
                    && t.id == TimerId::ControllerConnect))
        );
    }

    #[test]
    fn re_arm_after_fire_is_a_new_entry() {
        let mut q = TimerQueue::new();
        q.schedule(MachineKind::Host, TimerId::HostConnect, 100);
        assert_eq!(q.due(100).len(), 1);
        q.schedule(MachineKind::Host, TimerId::HostConnect, 300);
        assert_eq!(q.len(), 1);
        assert_eq!(q.next_deadline_ms(), Some(300));
    }
}
