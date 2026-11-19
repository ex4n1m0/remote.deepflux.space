//! Deterministic suspension policy (ADR-012): repeated challenge refusal,
//! timeout, or invalid output reduces slots to zero for an escalating backoff
//! window; a streak of clean serves decays the violation history.
//!
//! The table below is the frozen Phase B policy: it is a public `const` so
//! tests (and any future hub implementation) encode the exact same values.

/// Backoff window per violation within a streak, in seconds:
/// 1st violation -> 5 min, 2nd -> 30 min, 3rd and beyond -> 24 h.
pub const SUSPENSION_BACKOFF_WINDOWS_SECS: [u64; 3] = [5 * 60, 30 * 60, 24 * 60 * 60];

/// Consecutive [`PolicyEvent::ServedOk`] events after which the violation
/// streak decays to zero.
pub const CLEAN_EVENTS_FOR_DECAY: u32 = 100;

/// Slot count while suspended (ADR-012: suspension reduces slots to zero).
pub const SUSPENDED_SLOTS: u8 = 0;

/// An observable peer behavior feeding the suspension policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyEvent {
    /// The peer refused to answer a hosting challenge.
    ChallengeRefused,
    /// The peer let a hosting challenge deadline pass.
    ChallengeTimeout,
    /// The peer answered with output that failed verification.
    InvalidOutput,
    /// The peer completed a verified serving job.
    ServedOk,
}

impl PolicyEvent {
    /// True for the three violation classes (all treated identically by the
    /// frozen table).
    pub fn is_violation(&self) -> bool {
        !matches!(self, PolicyEvent::ServedOk)
    }
}

/// The deterministic outcome of replaying a peer's event history through the
/// policy table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuspensionDecision {
    /// True when the most recent event is a violation: the peer is inside a
    /// backoff window and must not serve or consume.
    pub suspended: bool,
    /// The backoff window incurred by the most recent violation (0 when not
    /// suspended).
    pub backoff_secs: u64,
    /// Consecutive violations since the last decay (or start of history).
    pub violation_streak: u32,
    /// Consecutive clean serves accumulated toward
    /// [`CLEAN_EVENTS_FOR_DECAY`].
    pub clean_streak: u32,
}

impl SuspensionDecision {
    /// The effective slot count given a peer's base slot allocation: zero
    /// while suspended, unchanged otherwise.
    pub fn slots(&self, base_slots: u8) -> u8 {
        if self.suspended {
            SUSPENDED_SLOTS
        } else {
            base_slots
        }
    }
}

/// Replays `events` through the frozen policy table:
///
/// - A violation increments the violation streak, zeroes the clean streak,
///   suspends the peer, and sets the backoff window to
///   `SUSPENSION_BACKOFF_WINDOWS_SECS[min(streak - 1, 2)]`
///   (5 min / 30 min / 24 h).
/// - A clean serve ends the current suspension (the backoff window has
///   elapsed) and increments the clean streak; at [`CLEAN_EVENTS_FOR_DECAY`]
///   consecutive clean serves the violation streak decays to zero and the
///   clean streak restarts.
///
/// Purely a fold over the history — no clock, no randomness: the same event
/// sequence always yields the same decision.
pub fn suspension(events: &[PolicyEvent]) -> SuspensionDecision {
    let mut decision = SuspensionDecision {
        suspended: false,
        backoff_secs: 0,
        violation_streak: 0,
        clean_streak: 0,
    };
    for event in events {
        if event.is_violation() {
            decision.violation_streak = decision
                .violation_streak
                .checked_add(1)
                .expect("streak bounded by event count");
            decision.clean_streak = 0;
            decision.suspended = true;
            decision.backoff_secs = backoff_for_streak(decision.violation_streak);
        } else {
            decision.suspended = false;
            decision.backoff_secs = 0;
            decision.clean_streak += 1;
            if decision.clean_streak >= CLEAN_EVENTS_FOR_DECAY {
                decision.violation_streak = 0;
                decision.clean_streak = 0;
            }
        }
    }
    decision
}

/// The frozen table lookup: 1st violation 5 min, 2nd 30 min, 3rd+ 24 h.
pub fn backoff_for_streak(violation_streak: u32) -> u64 {
    let index = (violation_streak.saturating_sub(1) as usize)
        .min(SUSPENSION_BACKOFF_WINDOWS_SECS.len() - 1);
    SUSPENSION_BACKOFF_WINDOWS_SECS[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn violations(n: u32, kind: PolicyEvent) -> Vec<PolicyEvent> {
        std::iter::repeat_n(kind, n as usize).collect()
    }

    #[test]
    fn empty_history_is_clean() {
        let d = suspension(&[]);
        assert!(!d.suspended);
        assert_eq!(d.backoff_secs, 0);
        assert_eq!(d.violation_streak, 0);
        assert_eq!(d.slots(4), 4);
    }

    #[test]
    fn table_encodes_the_frozen_windows() {
        // The test encodes the const table literally, so an accidental
        // change to SUSPENSION_BACKOFF_WINDOWS_SECS fails here.
        assert_eq!(SUSPENSION_BACKOFF_WINDOWS_SECS, [300, 1800, 86_400]);
        assert_eq!(CLEAN_EVENTS_FOR_DECAY, 100);
    }

    #[test]
    fn escalating_windows_per_streak() {
        let d = suspension(&violations(1, PolicyEvent::ChallengeRefused));
        assert!(d.suspended);
        assert_eq!(d.backoff_secs, 300);
        assert_eq!(d.violation_streak, 1);
        assert_eq!(d.slots(2), SUSPENDED_SLOTS);

        let d = suspension(&violations(2, PolicyEvent::ChallengeRefused));
        assert_eq!(d.backoff_secs, 1800);
        assert_eq!(d.violation_streak, 2);

        let d = suspension(&violations(3, PolicyEvent::ChallengeTimeout));
        assert_eq!(d.backoff_secs, 86_400);
        assert_eq!(d.violation_streak, 3);

        // Fourth and further violations stay at 24 h.
        let d = suspension(&violations(4, PolicyEvent::InvalidOutput));
        assert_eq!(d.backoff_secs, 86_400);
        assert_eq!(d.violation_streak, 4);
        assert!(d.suspended);
    }

    #[test]
    fn all_violation_classes_share_the_table() {
        for kind in [
            PolicyEvent::ChallengeRefused,
            PolicyEvent::ChallengeTimeout,
            PolicyEvent::InvalidOutput,
        ] {
            assert_eq!(
                suspension(&violations(2, kind)).backoff_secs,
                1800,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn mixed_streaks_escalate_across_classes() {
        let d = suspension(&[
            PolicyEvent::ChallengeRefused,
            PolicyEvent::InvalidOutput,
            PolicyEvent::ChallengeTimeout,
        ]);
        assert!(d.suspended);
        assert_eq!(d.violation_streak, 3);
        assert_eq!(d.backoff_secs, 86_400);
    }

    #[test]
    fn serving_ends_suspension_but_keeps_the_streak() {
        let d = suspension(&[PolicyEvent::ChallengeRefused]);
        assert!(d.suspended);
        let mut events = vec![PolicyEvent::ChallengeRefused];
        events.extend(std::iter::repeat_n(PolicyEvent::ServedOk, 50));
        let d = suspension(&events);
        assert!(!d.suspended, "backoff elapsed and the peer served again");
        assert_eq!(d.backoff_secs, 0);
        assert_eq!(d.violation_streak, 1, "streak persists through 50 clean");
        assert_eq!(d.clean_streak, 50);
        assert_eq!(d.slots(3), 3);
    }

    #[test]
    fn decay_after_100_clean_resets_the_streak() {
        let mut events = violations(2, PolicyEvent::ChallengeRefused);
        events.extend(std::iter::repeat_n(PolicyEvent::ServedOk, 99));
        let d = suspension(&events);
        assert_eq!(d.violation_streak, 2, "99 clean is not enough");
        assert_eq!(d.clean_streak, 99);

        let mut events = violations(2, PolicyEvent::ChallengeRefused);
        events.extend(std::iter::repeat_n(PolicyEvent::ServedOk, 100));
        let d = suspension(&events);
        assert_eq!(d.violation_streak, 0, "decay fires at exactly 100 clean");
        assert_eq!(d.clean_streak, 0, "clean streak restarts after decay");

        // After decay, a fresh violation starts over at the 5 min window.
        let mut events = violations(2, PolicyEvent::ChallengeRefused);
        events.extend(std::iter::repeat_n(PolicyEvent::ServedOk, 100));
        events.push(PolicyEvent::ChallengeRefused);
        let d = suspension(&events);
        assert!(d.suspended);
        assert_eq!(d.violation_streak, 1);
        assert_eq!(d.backoff_secs, 300);

        // But 99 clean between violations does NOT decay: the streak grows
        // to 3, so the fresh violation incurs the 24 h window.
        let mut events = violations(2, PolicyEvent::ChallengeRefused);
        events.extend(std::iter::repeat_n(PolicyEvent::ServedOk, 99));
        events.push(PolicyEvent::ChallengeRefused);
        let d = suspension(&events);
        assert_eq!(d.violation_streak, 3);
        assert_eq!(d.backoff_secs, 86_400);
    }

    #[test]
    fn decay_counter_does_not_carry_leftover_clean_events() {
        // 120 clean events then a violation: decay fired once at 100 and the
        // extra 20 restart from zero, so the new violation is streak 1.
        let mut events = std::iter::repeat_n(PolicyEvent::ServedOk, 120).collect::<Vec<_>>();
        events.push(PolicyEvent::ChallengeRefused);
        let d = suspension(&events);
        assert_eq!(d.violation_streak, 1);
        assert_eq!(d.backoff_secs, 300);
        assert_eq!(d.clean_streak, 0);
    }
}
