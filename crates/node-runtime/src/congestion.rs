//! Congestion policy for the host (M5, RD-013) — the encoder/pacer-facing
//! layer on top of the transport's bandwidth estimate.
//!
//! Division of labor (documented design decision):
//!
//! * **Rate dynamics** live in the transport (`transport-webrtc` builds
//!   `rtc`'s GCC — delay-gradient + loss based — over TWCC feedback when
//!   `CongestionOptions` is set). GCC answers "what can the path carry".
//! * **This module** answers "what should the encoder/pacer do about it":
//!   it turns [`CongestionSample`]s (estimate + receiver-reported loss +
//!   RTTs) into bounded [`CongestionDecision`]s — live bitrate steps (via
//!   `VideoEncoder::reconfigure`, never rebuilds: M4 QA F56/CR-1), an fps
//!   cap (via `FramePacer::retarget`), and — only as a documented last
//!   resort after sustained starvation — a resolution step-down (the one
//!   path that rebuilds).
//!
//! The controller is **pure and clock-injected**: every sample carries its
//! own `at_ms`, so the reaction functions below are unit-tested without a
//! live network (the M5 gate requirement), and the matrix runs drive the
//! same code that ships.
//!
//! ## Signals (inputs)
//!
//! | Signal | Source | Used for |
//! |---|---|---|
//! | `estimate_bps` | transport GCC target (`TransportStats::available_bandwidth_bps`) | primary target (×0.9 safety) |
//! | `remote_loss_percent` | controller's RTCP RR (`remote-inbound-rtp`) | severe-loss emergency step; increase block |
//! | `remote_rtt_ms` | RR-implied RTT | increase block when trend runs away |
//! | `ice_rtt_ms` | ICE pair RTT | fallback baseline when RR RTT absent |
//! | `send_bitrate_kbps` | achieved send rate | diagnostics/decision `reason` only |
//!
//! ## Hysteresis / anti-oscillation (all unit-tested)
//!
//! * **Severe loss** (≥ 10%): immediate ×0.5 step, but at most one step per
//!   `min_step_ms` (500 ms) — a burst cannot hammer the encoder.
//! * **Loss step-down** (≥ 2% for 2 consecutive samples): ×0.75.
//! * **Estimate following**: down immediately when the estimate collapses
//!   (GCC already rate-limits the estimate itself), never above min.
//! * **Increase**: additive (`up_step_bps`, ≥ 250 kbps, ~5%), only when
//!   loss < 1%, RTT not trending away, ≥ `down_to_up_cooldown_ms` (3 s)
//!   after the last decrease and ≥ `up_cooldown_ms` (1 s) after the last
//!   increase, and always capped at estimate × 0.95.
//! * **fps cap**: 60→30 below `fps30_bps` (2.5 Mbps), 30→15 below
//!   `fps15_bps` (1.2 Mbps); recovery requires 1.2× the threshold
//!   (hysteresis band) plus a 5 s dwell. `Auto` only — manual presets pin
//!   fps.
//! * **Resolution step-down**: only after `resolution_sustain_ms` (10 s)
//!   *continuously* below 800 kbps, and it fires at most once per session
//!   (the rebuild leak, F56, makes this a priced action).
//!
//! The `Auto` quality preset runs this controller; manual presets pin
//! targets and do not instantiate it.

use std::time::Duration;

/// One control-interval observation (all fields optional: `None` = the
/// transport could not measure it this interval).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CongestionSample {
    pub at_ms: u64,
    /// Sender-side GCC estimate, bps.
    pub estimate_bps: Option<u64>,
    /// Receiver-reported loss of our outbound stream, percent (0..=100).
    pub remote_loss_percent: Option<f64>,
    /// RTT implied by the latest receiver report, ms.
    pub remote_rtt_ms: Option<f64>,
    /// ICE candidate-pair RTT, ms (fallback/baseline).
    pub ice_rtt_ms: Option<f64>,
    /// Achieved send bitrate, kbps.
    pub send_bitrate_kbps: Option<f64>,
}

impl CongestionSample {
    /// The RTT this policy considers (media path preferred).
    fn rtt_ms(&self) -> Option<f64> {
        self.remote_rtt_ms.or(self.ice_rtt_ms)
    }
}

/// What the controller wants applied this interval. All fields are deltas —
/// `None`/`false` means "no change".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CongestionDecision {
    /// New encoder bitrate target, bps (applied live via `reconfigure`).
    pub bitrate_bps: Option<u64>,
    /// New pacer cap, fps (applied via `FramePacer::retarget`).
    pub fps_cap: Option<u32>,
    /// Resolution step-down (the rebuild path) — last resort, once.
    pub resolution_step_down: bool,
    /// Human/machine-readable cause (diagnostics; never a secret).
    pub reason: &'static str,
}

/// Tunable knobs (defaults are the product values; tests override).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CongestionParams {
    pub min_bps: u64,
    pub max_bps: u64,
    pub start_bps: u64,
    /// Safety factor applied to the GCC estimate before targeting the
    /// encoder (encode slightly under the path's capacity).
    pub estimate_safety: f64,
    /// Severe-loss threshold (percent) triggering an immediate ×`severe_factor` step.
    pub severe_loss_percent: f64,
    pub severe_factor: f64,
    /// Sustained-loss threshold (percent) for a ×0.75 step.
    pub loss_down_percent: f64,
    /// Loss below which increases are allowed.
    pub loss_up_percent: f64,
    /// Minimum spacing between any two bitrate steps.
    pub min_step_ms: u64,
    /// Cooldown after a decrease before any increase.
    pub down_to_up_cooldown_ms: u64,
    /// Cooldown between increases.
    pub up_cooldown_ms: u64,
    /// Additive increase step, bps (floored at 5% of current).
    pub up_step_bps: u64,
    /// fps caps and their bitrate thresholds (hysteresis ×1.2 on recovery,
    /// 5 s dwell between fps changes).
    pub fps30_bps: u64,
    pub fps15_bps: u64,
    pub base_fps: u32,
    /// Resolution step-down threshold + sustain window.
    pub resolution_down_bps: u64,
    pub resolution_sustain_ms: u64,
}

impl Default for CongestionParams {
    fn default() -> Self {
        Self {
            min_bps: 500_000,
            max_bps: 12_000_000,
            start_bps: 6_000_000,
            estimate_safety: 0.90,
            severe_loss_percent: 10.0,
            severe_factor: 0.5,
            loss_down_percent: 2.0,
            loss_up_percent: 1.0,
            min_step_ms: 500,
            down_to_up_cooldown_ms: 3_000,
            up_cooldown_ms: 1_000,
            up_step_bps: 300_000,
            fps30_bps: 2_500_000,
            fps15_bps: 1_200_000,
            base_fps: 60,
            resolution_down_bps: 800_000,
            resolution_sustain_ms: 10_000,
        }
    }
}

/// The controller. Feed one sample per control interval (the engine's 1 Hz
/// stats tick); apply returned decisions.
#[derive(Debug, Clone)]
pub struct CongestionController {
    params: CongestionParams,
    bitrate_bps: u64,
    fps: u32,
    last_step_ms: Option<u64>,
    last_direction_down_ms: Option<u64>,
    last_increase_ms: Option<u64>,
    /// Consecutive loss-down samples (need 2).
    loss_down_streak: u32,
    /// Minimum RTT observed (baseline for the trend guard).
    rtt_baseline_ms: Option<f64>,
    /// Consecutive samples with loss below `loss_up_percent` — increases
    /// additionally require a 3-sample recovery dwell so a flapping loss
    /// signal cannot probe up between loss bursts (unit-tested).
    clean_streak: u32,
    /// fps change dwell bookkeeping.
    last_fps_change_ms: Option<u64>,
    /// Starvation window for the resolution last resort.
    starved_since_ms: Option<u64>,
    resolution_stepped_down: bool,
    /// Diagnostics: number of direction changes (oscillation evidence).
    pub steps_up: u64,
    pub steps_down: u64,
    pub fps_changes: u64,
}

impl CongestionController {
    pub fn new(params: CongestionParams) -> Self {
        let bitrate_bps = params.start_bps.clamp(params.min_bps, params.max_bps);
        Self {
            params,
            bitrate_bps,
            fps: params.base_fps,
            last_step_ms: None,
            last_direction_down_ms: None,
            last_increase_ms: None,
            loss_down_streak: 0,
            rtt_baseline_ms: None,
            clean_streak: 0,
            last_fps_change_ms: None,
            starved_since_ms: None,
            resolution_stepped_down: false,
            steps_up: 0,
            steps_down: 0,
            fps_changes: 0,
        }
    }

    /// Current pinned bitrate target (diagnostics / initial encoder setup).
    pub fn bitrate_bps(&self) -> u64 {
        self.bitrate_bps
    }

    /// Current fps cap.
    pub fn fps(&self) -> u32 {
        self.fps
    }

    /// One control step. Pure: mutates only its own state.
    pub fn sample(&mut self, sample: CongestionSample) -> CongestionDecision {
        let mut decision = CongestionDecision::default();
        let base_fps = self.params.base_fps;
        let resolution_down_bps = self.params.resolution_down_bps;
        let resolution_sustain_ms = self.params.resolution_sustain_ms;

        // RTT baseline bookkeeping (trend guard).
        if let Some(rtt) = sample.rtt_ms().filter(|r| *r > 0.0) {
            self.rtt_baseline_ms = Some(match self.rtt_baseline_ms {
                Some(base) => base.min(rtt),
                None => rtt,
            });
        }
        let rtt_trending_away = match (self.rtt_baseline_ms, sample.rtt_ms()) {
            (Some(base), Some(rtt)) => rtt > base * 2.5,
            _ => false,
        };

        let loss = sample.remote_loss_percent;
        let estimate = sample.estimate_bps;

        // --- starvation bookkeeping (resolution last resort) ---
        match estimate {
            Some(est) if est < resolution_down_bps => {
                if self.starved_since_ms.is_none() {
                    self.starved_since_ms = Some(sample.at_ms);
                }
            }
            _ => self.starved_since_ms = None,
        }
        if !self.resolution_stepped_down
            && let Some(since) = self.starved_since_ms
            && sample.at_ms.saturating_sub(since) >= resolution_sustain_ms
        {
            self.resolution_stepped_down = true;
            decision.resolution_step_down = true;
            decision.reason = "sustained starvation: resolution step-down (last resort)";
        }

        // --- bitrate step selection ---
        let next_bps = self.pick_bitrate(sample, loss, estimate, rtt_trending_away);
        let min_delta = (self.bitrate_bps / 20).max(100_000); // ignore <5%/100k jitter
        if next_bps.is_some_and(|bps| bps.abs_diff(self.bitrate_bps) >= min_delta) {
            let bps = next_bps.expect("checked");
            let going_down = bps < self.bitrate_bps;
            self.bitrate_bps = bps;
            self.last_step_ms = Some(sample.at_ms);
            if going_down {
                self.steps_down += 1;
                self.last_direction_down_ms = Some(sample.at_ms);
            } else {
                self.steps_up += 1;
                self.last_increase_ms = Some(sample.at_ms);
            }
            decision.bitrate_bps = Some(bps);
        }

        // --- fps cap with hysteresis ---
        let fps_target = self.pick_fps();
        if fps_target != self.fps
            && self
                .last_fps_change_ms
                .is_none_or(|at| sample.at_ms.saturating_sub(at) >= 5_000)
        {
            self.fps = fps_target;
            self.last_fps_change_ms = Some(sample.at_ms);
            self.fps_changes += 1;
            decision.fps_cap = Some(fps_target);
            if decision.reason.is_empty() {
                decision.reason = if fps_target < base_fps {
                    "bandwidth collapsed: fps cap applied"
                } else {
                    "bandwidth recovered: fps cap lifted"
                };
            }
        }

        decision
    }

    /// The bitrate step decision. Returns the new target or `None` to hold.
    fn pick_bitrate(
        &mut self,
        sample: CongestionSample,
        loss: Option<f64>,
        estimate: Option<u64>,
        rtt_trending_away: bool,
    ) -> Option<u64> {
        let params = &self.params;
        let now = sample.at_ms;
        let rate_bounded = self
            .last_step_ms
            .is_some_and(|at| now.saturating_sub(at) < params.min_step_ms);

        // Clean-dwell bookkeeping (before any early return: a loss sample
        // anywhere in the sequence resets the streak).
        let loss_ok = loss.is_none_or(|l| l < params.loss_up_percent);
        self.clean_streak = if loss_ok {
            self.clean_streak.saturating_add(1)
        } else {
            0
        };

        // Emergency severe-loss step (rate-bounded even here).
        if let Some(loss_pct) = loss
            && loss_pct >= params.severe_loss_percent
            && !rate_bounded
        {
            self.loss_down_streak = self.loss_down_streak.saturating_add(1);
            return Some(
                ((self.bitrate_bps as f64 * params.severe_factor) as u64).max(params.min_bps),
            );
        }

        // Sustained loss step-down (2 consecutive samples ≥ threshold).
        if let Some(loss_pct) = loss {
            if loss_pct >= params.loss_down_percent {
                self.loss_down_streak += 1;
            } else {
                self.loss_down_streak = 0;
            }
            if self.loss_down_streak >= 2 && !rate_bounded {
                return Some(((self.bitrate_bps as f64 * 0.75) as u64).max(params.min_bps));
            }
        }

        // Estimate following — DOWN tracks the estimate directly (the
        // interceptor pacer already enforces the GCC target on the wire,
        // so an encoder held above it just donates packets to the pacer's
        // overflow queue; matrix evidence in docs/reports/m5-matrix.md).
        // Jitter protection is the decision layer's min_delta filter, not
        // a deadband here. Up is the additive gate below.
        if let Some(est) = estimate {
            let safe = ((est as f64) * params.estimate_safety) as u64;
            if safe < self.bitrate_bps {
                return Some(safe.max(params.min_bps));
            }
        }

        // Additive increase: needs a 3-sample clean dwell, low loss, calm
        // RTT, cooldowns, and headroom.
        if rate_bounded {
            return None;
        }
        if !loss_ok || self.clean_streak < 3 || rtt_trending_away {
            return None;
        }
        if self
            .last_direction_down_ms
            .is_some_and(|at| now.saturating_sub(at) < params.down_to_up_cooldown_ms)
        {
            return None;
        }
        if self
            .last_increase_ms
            .is_some_and(|at| now.saturating_sub(at) < params.up_cooldown_ms)
        {
            return None;
        }
        // The increase ceiling is the SAME factor as the down-follow
        // (estimate × safety): parking at the ceiling means the next
        // down-follow does not immediately retract the probe (measured
        // 3.6M↔3.8M flapping with a 0.95 ceiling vs 0.9 follow).
        let ceiling = match estimate {
            Some(est) => ((est as f64) * params.estimate_safety) as u64,
            None => params.max_bps,
        }
        .min(params.max_bps)
        .max(params.min_bps);
        if self.bitrate_bps >= ceiling {
            return None;
        }
        let step = params.up_step_bps.max(self.bitrate_bps / 20);
        Some((self.bitrate_bps + step).min(ceiling).max(params.min_bps))
    }

    /// fps cap from the current bitrate target: bands are
    /// `[fps30_bps, ∞) → base`, `[fps15_bps, fps30_bps) → 30`,
    /// otherwise 15. Moving up a band needs 1.2× the band's lower
    /// threshold (hysteresis); moving down is immediate.
    fn pick_fps(&self) -> u32 {
        let params = &self.params;
        let target = if self.bitrate_bps >= params.fps30_bps {
            params.base_fps
        } else if self.bitrate_bps >= params.fps15_bps {
            30
        } else {
            15
        };
        if target > self.fps {
            let needed = match target {
                f if f >= params.base_fps => params.fps30_bps, // 30 → 60
                _ => params.fps15_bps,                         // 15 → 30
            };
            let needed = ((needed as f64) * 1.2) as u64;
            if self.bitrate_bps < needed {
                return self.fps; // hold the lower cap until the band clears
            }
        }
        target
    }
}

/// Convenience: the control interval this policy is designed for (matches
/// the engine's 1 Hz stats tick and RTCP RR cadence).
pub const CONTROL_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> CongestionParams {
        CongestionParams {
            min_bps: 500_000,
            max_bps: 12_000_000,
            start_bps: 6_000_000,
            estimate_safety: 0.9,
            severe_loss_percent: 10.0,
            severe_factor: 0.5,
            loss_down_percent: 2.0,
            loss_up_percent: 1.0,
            min_step_ms: 500,
            down_to_up_cooldown_ms: 3_000,
            up_cooldown_ms: 1_000,
            up_step_bps: 300_000,
            fps30_bps: 2_500_000,
            fps15_bps: 1_200_000,
            base_fps: 60,
            resolution_down_bps: 800_000,
            resolution_sustain_ms: 10_000,
        }
    }

    fn sample(at_ms: u64, estimate: Option<u64>, loss: Option<f64>) -> CongestionSample {
        CongestionSample {
            at_ms,
            estimate_bps: estimate,
            remote_loss_percent: loss,
            remote_rtt_ms: None,
            ice_rtt_ms: Some(20.0),
            send_bitrate_kbps: None,
        }
    }

    /// Healthy = estimate above start/safety so equilibrium is quiet.
    const HEALTHY: u64 = 7_000_000;

    #[test]
    fn severe_loss_steps_down_immediately_but_rate_bounded() {
        let mut ctl = CongestionController::new(params());
        // t=0: healthy equilibrium, no step.
        assert!(
            ctl.sample(sample(0, Some(HEALTHY), Some(0.0)))
                .bitrate_bps
                .is_none()
        );
        // t=1000: severe loss → ×0.5 immediately.
        let d = ctl.sample(sample(1000, Some(HEALTHY), Some(25.0)));
        assert_eq!(d.bitrate_bps, Some(3_000_000), "×0.5 on ≥10% loss");
        // t=1200: still severe — rate-bounded (min_step 500 ms), no hammering.
        let d = ctl.sample(sample(1200, Some(HEALTHY), Some(25.0)));
        assert!(d.bitrate_bps.is_none(), "steps must be ≥500 ms apart");
        // t=2000: next severe step allowed.
        let d = ctl.sample(sample(2000, Some(HEALTHY), Some(25.0)));
        assert_eq!(d.bitrate_bps, Some(1_500_000));
        // Halving continues, floored at min_bps.
        let d = ctl.sample(sample(3000, Some(HEALTHY), Some(25.0)));
        assert_eq!(d.bitrate_bps, Some(750_000));
        let d = ctl.sample(sample(4000, Some(HEALTHY), Some(25.0)));
        assert_eq!(
            d.bitrate_bps,
            Some(500_000),
            "floored at min_bps (375k → 500k)"
        );
        let d = ctl.sample(sample(5000, Some(HEALTHY), Some(25.0)));
        assert!(d.bitrate_bps.is_none(), "already at the floor");
    }

    #[test]
    fn loss_stepdown_needs_two_consecutive_samples() {
        let mut ctl = CongestionController::new(params());
        // One 5% blip: no step.
        assert!(
            ctl.sample(sample(0, Some(HEALTHY), Some(5.0)))
                .bitrate_bps
                .is_none()
        );
        assert!(
            ctl.sample(sample(1000, Some(HEALTHY), Some(0.2)))
                .bitrate_bps
                .is_none(),
            "streak reset by a clean sample"
        );
        // Two consecutive 5% samples: ×0.75.
        assert!(
            ctl.sample(sample(2000, Some(HEALTHY), Some(5.0)))
                .bitrate_bps
                .is_none()
        );
        let d = ctl.sample(sample(3000, Some(HEALTHY), Some(5.0)));
        assert_eq!(d.bitrate_bps, Some(4_500_000), "×0.75 on sustained loss");
    }

    #[test]
    fn estimate_collapse_is_followed_down_and_bounded() {
        let mut ctl = CongestionController::new(params());
        assert!(
            ctl.sample(sample(0, Some(HEALTHY), None))
                .bitrate_bps
                .is_none()
        );
        let d = ctl.sample(sample(1000, Some(2_000_000), None));
        assert_eq!(d.bitrate_bps, Some(1_800_000), "estimate ×0.9 safety");
        let d = ctl.sample(sample(2000, Some(100_000), None));
        assert_eq!(d.bitrate_bps, Some(500_000), "floored at min_bps");
    }

    #[test]
    fn increases_are_additive_capped_and_cooldown_gated() {
        let mut ctl = CongestionController::new(params());
        ctl.sample(sample(0, Some(HEALTHY), Some(0.0)));
        // The 3-sample clean dwell gates the very first probe too.
        let d = ctl.sample(sample(500, Some(12_000_000), Some(0.0)));
        assert!(
            d.bitrate_bps.is_none(),
            "clean dwell (3 samples) not yet met"
        );
        // Estimate headroom: 12 Mbps. Third clean sample at t=1000.
        let d = ctl.sample(sample(1000, Some(12_000_000), Some(0.0)));
        assert_eq!(
            d.bitrate_bps,
            Some(6_300_000),
            "additive +300k step (5% floor not yet active)"
        );
        // t=1500: up_cooldown (1 s) not elapsed since the increase.
        let d = ctl.sample(sample(1500, Some(12_000_000), Some(0.0)));
        assert!(
            d.bitrate_bps.is_none(),
            "up_cooldown 1 s gates the next step"
        );
        // t=2100: step floor is now max(300k, 5% of 6.3M = 315k) = 315k.
        let d = ctl.sample(sample(2100, Some(12_000_000), Some(0.0)));
        assert_eq!(
            d.bitrate_bps,
            Some(6_615_000),
            "step floors at 5% of current"
        );
        // Loss ≥1% blocks increases.
        let d = ctl.sample(sample(3200, Some(12_000_000), Some(1.5)));
        assert!(d.bitrate_bps.is_none(), "loss ≥1% blocks increases");
    }

    #[test]
    fn no_increase_immediately_after_a_decrease() {
        let mut ctl = CongestionController::new(params());
        ctl.sample(sample(0, Some(HEALTHY), Some(0.0)));
        ctl.sample(sample(1000, Some(1_000_000), Some(0.0))); // collapse
        assert_eq!(ctl.bitrate_bps(), 900_000);
        // Path recovers instantly — the down→up cooldown (3 s) must hold.
        let d = ctl.sample(sample(2500, Some(12_000_000), Some(0.0)));
        assert!(d.bitrate_bps.is_none(), "3 s down→up cooldown");
        let d = ctl.sample(sample(3300, Some(12_000_000), Some(0.0)));
        assert!(d.bitrate_bps.is_none(), "clean dwell not yet met (2/3)");
        let d = ctl.sample(sample(4100, Some(12_000_000), Some(0.0)));
        assert!(
            d.bitrate_bps.is_some(),
            "cooldown + dwell elapsed: increase allowed"
        );
    }

    #[test]
    fn alternating_conditions_do_not_oscillate_unboundedly() {
        // The classic oscillation attempt: severe loss alternating with a
        // fat estimate every sample for 60 s. A flapping controller would
        // log ~60 direction changes; the cooldowns must keep the count
        // small and the direction sequence sane.
        let mut ctl = CongestionController::new(params());
        let mut direction_changes = 0u64;
        let mut last_direction: Option<bool> = None; // true = up
        for t in 0..60u64 {
            let loss = if t % 2 == 0 { Some(12.0) } else { Some(0.0) };
            let estimate = if t % 2 == 0 {
                Some(HEALTHY)
            } else {
                Some(12_000_000)
            };
            let before = ctl.bitrate_bps();
            let _ = ctl.sample(sample(t * 1000, estimate, loss));
            let after = ctl.bitrate_bps();
            if after != before {
                let up = after > before;
                if last_direction != Some(up) {
                    direction_changes += 1;
                    last_direction = Some(up);
                }
            }
        }
        assert!(
            direction_changes <= 10,
            "direction changes under alternating stress: {direction_changes} \
             (steps_up={}, steps_down={})",
            ctl.steps_up,
            ctl.steps_down
        );
        assert!(
            ctl.steps_down <= 60,
            "decreases rate-bounded: {}",
            ctl.steps_down
        );
        assert!(
            ctl.steps_up <= 30,
            "increases must be cooldown-gated: {}",
            ctl.steps_up
        );
    }

    #[test]
    fn fps_cap_bands_and_recovery_hysteresis() {
        // Band entries (fresh controllers, healthy baseline first).
        let mut ctl = CongestionController::new(params());
        ctl.sample(sample(0, Some(HEALTHY), Some(0.0)));
        let d = ctl.sample(sample(1000, Some(2_000_000), Some(0.0)));
        assert_eq!(d.bitrate_bps, Some(1_800_000), "estimate ×0.9");
        assert_eq!(d.fps_cap, Some(30), "1.8 Mbps sits in the 30 fps band");

        let mut ctl = CongestionController::new(params());
        ctl.sample(sample(0, Some(HEALTHY), Some(0.0)));
        let d = ctl.sample(sample(1000, Some(1_000_000), Some(0.0)));
        assert_eq!(d.bitrate_bps, Some(900_000));
        assert_eq!(d.fps_cap, Some(15), "0.9 Mbps sits in the 15 fps band");

        // Recovery with hysteresis: from 15 fps, a 2.9 Mbps estimate lets
        // the bitrate climb into the 30 fps band (≥1.44 M = 1.2×fps15)
        // but not to 60 (needs ≥3.0 M = 1.2×fps30).
        let mut ctl = CongestionController::new(params());
        ctl.sample(sample(0, Some(HEALTHY), Some(0.0)));
        ctl.sample(sample(1000, Some(1_000_000), Some(0.0)));
        assert_eq!(ctl.fps(), 15);
        for t in 2..40u64 {
            let _ = ctl.sample(sample(t * 1000, Some(2_900_000), Some(0.0)));
        }
        assert!(
            ctl.bitrate_bps() >= 1_440_000,
            "bitrate climbed above the 15→30 recovery band: {}",
            ctl.bitrate_bps()
        );
        assert_eq!(ctl.fps(), 30, "recovers to 30 but not 60");
        // A fat estimate lifts the cap fully once the 3.0 M band clears.
        for t in 40..90u64 {
            let _ = ctl.sample(sample(t * 1000, Some(8_000_000), Some(0.0)));
        }
        assert_eq!(ctl.fps(), 60, "full rate restored above the 60 fps band");
    }

    /// A 7 Mbps estimate: the climb parks exactly at the ceiling
    /// (0.9×estimate, the same factor as the down-follow) and STAYS there
    /// — no probe above a level the next down-follow would retract.
    #[test]
    fn additive_climb_parks_at_the_ceiling_without_flapping() {
        let mut ctl = CongestionController::new(params());
        ctl.sample(sample(0, Some(HEALTHY), Some(0.0)));
        for t in 1..30u64 {
            let _ = ctl.sample(sample(t * 1000, Some(7_000_000), Some(0.0)));
        }
        assert_eq!(ctl.bitrate_bps(), 6_300_000, "parks at 0.9×estimate");
        // And it does not oscillate around the ceiling: the last three
        // samples all held the same target.
        assert_eq!(ctl.steps_up, 1, "one probe step, then stable");
        assert_eq!(ctl.steps_down, 0);
    }

    #[test]
    fn resolution_step_down_fires_once_after_sustained_starvation() {
        let mut ctl = CongestionController::new(params());
        // 10 s below 800 kbps: the window is at-since ≥ 10_000 ms.
        for t in 0..10u64 {
            let d = ctl.sample(sample(t * 1000, Some(600_000), None));
            assert!(!d.resolution_step_down, "t={t}: under the 10 s window");
        }
        let d = ctl.sample(sample(10_000, Some(600_000), None));
        assert!(d.resolution_step_down, "10 s continuous starvation fires");
        // Never again in this session.
        for t in 11..20u64 {
            let d = ctl.sample(sample(t * 1000, Some(600_000), None));
            assert!(!d.resolution_step_down, "fires at most once");
        }
        // A recovery sample resets the window.
        let mut ctl2 = CongestionController::new(params());
        for t in 0..5u64 {
            ctl2.sample(sample(t * 1000, Some(600_000), None));
        }
        ctl2.sample(sample(5_000, Some(5_000_000), None)); // reset
        for t in 6..12u64 {
            let d = ctl2.sample(sample(t * 1000, Some(600_000), None));
            assert!(!d.resolution_step_down, "window restarted at t=5000");
        }
        let d = ctl2.sample(sample(16_000, Some(600_000), None));
        assert!(d.resolution_step_down, "fires 10 s after the restart");
    }

    #[test]
    fn rtt_trend_blocks_increases() {
        let mut ctl = CongestionController::new(params());
        // Establish a 20 ms baseline.
        for t in 0..3 {
            let mut s = sample(t * 1000, Some(12_000_000), Some(0.0));
            s.remote_rtt_ms = Some(20.0);
            ctl.sample(s);
        }
        // RTT runs away (60 ms = 3×): even clean loss must not increase.
        let mut s = sample(5_000, Some(12_000_000), Some(0.0));
        s.remote_rtt_ms = Some(60.0);
        let d = ctl.sample(s);
        assert!(
            d.bitrate_bps.is_none(),
            "RTT trend blocks additive increases (GCC owns the decrease)"
        );
    }
}
