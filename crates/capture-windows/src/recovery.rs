//! F71 reinit/recovery policy: bounded retries with exponential backoff
//! for transient duplication failures, immediate typed death for
//! non-retryable ones.
//!
//! The M6 soak died at minute 45.2 through exactly the hole this module
//! closes: `DxgiCapture::reinit()` cleared the duplication and failed,
//! callers discarded the error, and the session froze `Connected` for the
//! remaining 14.7 minutes (`docs/reports/m6-soak.md` F71). Policy, in one
//! place so no caller can invent its own:
//!
//! * [`CaptureError::AccessLost`] / [`CaptureError::Exhausted`] /
//!   [`CaptureError::Api`] / [`CaptureError::DisplayChanged`] /
//!   [`CaptureError::Invalid`] are *transient* in the reinit path (display
//!   churn settles; another duplication may be released; an unknown HRESULT
//!   during re-duplication deserves a bounded retry): retry with
//!   exponential backoff, at most [`REINIT_MAX_ATTEMPTS`] times
//!   (≈ [`REINIT_BUDGET`] wall-clock worst case), then die.
//! * [`CaptureError::DeviceLost`] (adapter removed/reset) and an already-
//!   dead capture die **immediately** — retrying a removed device only
//!   delays the session-ending error.
//! * [`CaptureError::AccessDenied`] is *not* reinit's business: the secure
//!   desktop (lock screen/UAC) outlives any sane retry budget, so callers
//!   keep their documented poll-with-sleep behavior while the desktop is
//!   switched away. It never converts into [`CaptureError::Dead`].
//!
//! Death is typed ([`CaptureError::Dead`]) and sticky: every later
//! `next_frame`/`reinit` returns it, so a caller that ignores it has to
//! ignore a variant whose name says "end the session".

use std::time::Duration;

use crate::CaptureError;

/// Maximum transient-failure reinit attempts before typed death.
pub const REINIT_MAX_ATTEMPTS: u32 = 8;

/// Backoff base for transient reinit failures; delay doubles per attempt
/// (100 ms, 200 ms, … 12.8 s), so 8 attempts span ≈ 25.5 s.
pub const REINIT_BACKOFF_BASE: Duration = Duration::from_millis(100);

/// Wall-clock retry budget implied by [`REINIT_MAX_ATTEMPTS`] × doubling
/// [`REINIT_BACKOFF_BASE`] (informational; used by tests and docs):
/// 100+200+…+12 800 ms = 25 500 ms.
pub const REINIT_BUDGET: Duration = Duration::from_millis(25_500);

/// What the caller should do after one failed recovery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryDecision {
    /// Transient cause — re-attempt after `delay` (this was attempt number
    /// `attempts`). The capture object stays exactly as it was.
    Retry {
        delay: Duration,
        attempts: u32,
        cause: String,
    },
    /// Irrecoverable — transition the capture to the typed dead state and
    /// end the session that feeds on it.
    Die { reason: String },
}

/// Classify one reinit failure given how many transient attempts already
/// burned. Pure — unit-tested without a GPU.
pub fn recovery_decision(failure: &CaptureError, attempts_so_far: u32) -> RecoveryDecision {
    let cause = failure.to_string();
    match failure {
        // Non-retryable, in reinit or anywhere else.
        CaptureError::Dead(reason) => RecoveryDecision::Die {
            reason: format!("capture already dead: {reason}"),
        },
        CaptureError::DeviceLost(reason) => RecoveryDecision::Die {
            reason: format!("device removed/reset: {reason}"),
        },
        // Transient in the reinit path: retry with backoff until the
        // attempt budget is gone, then die (a stream that cannot
        // re-duplicate within ~25 s of display churn is dead for a
        // remote-desktop session).
        CaptureError::AccessLost(_)
        | CaptureError::Exhausted(_)
        | CaptureError::Api { .. }
        | CaptureError::DisplayChanged(_)
        | CaptureError::Invalid(_) => {
            let attempts = attempts_so_far + 1;
            if attempts > REINIT_MAX_ATTEMPTS {
                return RecoveryDecision::Die {
                    reason: format!(
                        "reinit failed {REINIT_MAX_ATTEMPTS} times (last: {cause}); giving up after {:.1}s",
                        REINIT_BUDGET.as_secs_f64()
                    ),
                };
            }
            // Delay doubles per burned attempt: 100 ms, 200 ms, … 12.8 s
            // across the 8-attempt budget (= REINIT_BUDGET, ≈25.5 s).
            let delay = REINIT_BACKOFF_BASE.saturating_mul(1u32 << attempts_so_far.min(20));
            RecoveryDecision::Retry {
                delay,
                attempts,
                cause,
            }
        }
        // Secure desktop: outside the reinit policy (see module docs).
        // Callers poll; this never reaches a Dead transition through
        // reinit. Returning Retry with no delay keeps the decision total.
        CaptureError::AccessDenied(_) => RecoveryDecision::Retry {
            delay: Duration::from_millis(500),
            attempts: attempts_so_far,
            cause,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_failures_back_off_then_die_at_the_bound() {
        let mut delays = Vec::new();
        for attempts in 0..REINIT_MAX_ATTEMPTS {
            match recovery_decision(&CaptureError::AccessLost("churn".into()), attempts) {
                RecoveryDecision::Retry {
                    delay, attempts: n, ..
                } => {
                    assert_eq!(n, attempts + 1);
                    delays.push(delay);
                }
                other => panic!("attempt {attempts} should retry, got {other:?}"),
            }
        }
        // 100, 200, … doubling; the full budget sums to REINIT_BUDGET.
        let budget: Duration = delays.iter().sum();
        assert_eq!(budget, REINIT_BUDGET);
        assert_eq!(delays[0], Duration::from_millis(100));
        assert_eq!(delays[7], Duration::from_millis(12_800));
        // The budget exhausted: the next failure dies with the last cause
        // in the reason (no silent freeze).
        match recovery_decision(
            &CaptureError::AccessLost("churn".into()),
            REINIT_MAX_ATTEMPTS,
        ) {
            RecoveryDecision::Die { reason } => {
                assert!(reason.contains("8 times"), "reason: {reason}");
                assert!(reason.contains("churn"), "reason names the cause: {reason}");
            }
            other => panic!("should die at the bound, got {other:?}"),
        }
    }

    #[test]
    fn device_lost_dies_immediately_on_the_first_failure() {
        for attempts in [0u32, 3, 100] {
            match recovery_decision(&CaptureError::DeviceLost("removed".into()), attempts) {
                RecoveryDecision::Die { reason } => {
                    assert!(reason.contains("device removed/reset"), "{reason}");
                }
                other => panic!("attempt {attempts} must die, got {other:?}"),
            }
        }
    }

    #[test]
    fn dead_stays_dead() {
        match recovery_decision(&CaptureError::Dead("previous".into()), 0) {
            RecoveryDecision::Die { reason } => {
                assert!(reason.contains("already dead"), "{reason}")
            }
            other => panic!("dead is terminal, got {other:?}"),
        }
    }

    #[test]
    fn access_denied_never_converts_to_death_through_reinit() {
        for attempts in 0..(REINIT_MAX_ATTEMPTS + 4) {
            match recovery_decision(
                &CaptureError::AccessDenied("secure desktop".into()),
                attempts,
            ) {
                RecoveryDecision::Retry {
                    delay, attempts: n, ..
                } => {
                    assert_eq!(n, attempts, "denied does not consume the budget");
                    assert_eq!(delay, Duration::from_millis(500));
                }
                other => panic!("lock screen must not kill the session: {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_hresult_is_bounded_transient() {
        let err = CaptureError::Api {
            op: "DuplicateOutput",
            hr: 0x8000_4005u32 as i32,
            detail: "unmapped".into(),
        };
        assert!(matches!(
            recovery_decision(&err, 0),
            RecoveryDecision::Retry { .. }
        ));
        assert!(matches!(
            recovery_decision(&err, REINIT_MAX_ATTEMPTS),
            RecoveryDecision::Die { .. }
        ));
    }

    #[test]
    fn budget_is_about_25_seconds() {
        assert!((25.0..26.0).contains(&REINIT_BUDGET.as_secs_f64()));
    }
}
