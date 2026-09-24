//! Host-side input consumption: `InputSink` trait object fed from
//! `input-fast` / `input-reliable` messages (RD-008 runtime half).
//!
//! The transport delivers decoded [`WireMessage::Input`] events (any
//! channel); this pump owns all host-side input policy:
//!
//! * **Reliable-sequence gap detection** — `input-reliable` events carry a
//!   monotonic `seq`; a gap means loss, and every held key/button must be
//!   released (`InputSink::release_all`) *before* the post-gap event is
//!   applied (the `protocol::wire` contract; the spike stub proved the
//!   semantics, this is the same policy against the real trait).
//! * **Fast-channel stale suppression** — `input-fast` (`MouseMove`) is
//!   unordered; only a strictly newer `seq` is applied, older arrivals are
//!   reorder artifacts and counted, never injected.
//! * **`AllKeysUp` passthrough** — focus-loss releases from the controller
//!   clear local tracking and go to the sink.
//! * **Disconnect safety** — [`InputPump::all_keys_up`] with the
//!   `Disconnect` trigger on session teardown; held state must be empty
//!   afterwards (asserted by the rig).
//!
//! Release paths use the M2 `release_all(trigger)` addition so the sink
//! reports what was freed (counts only — `ReleasedInput` is incapable of
//! carrying key identities, invariant 6).
//!
//! Invariant 6: input payloads are never logged here — counters only.
//! The pump also holds the input-path diagnostics counters
//! (perf-schema F8 note): applied/suppressed/gap/release counts are
//! surfaced through [`InputPump::counters`] for the rig summary until the
//! schema grows additive input timestamps.

use input_windows::InputSink;
use protocol::wire::{AllKeysUpTrigger, InputEvent};

/// Policy outcome counters (all payload-free).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InputCounters {
    pub moves_applied: u64,
    pub moves_stale_suppressed: u64,
    pub reliable_applied: u64,
    /// Exact-duplicate reliable seqs suppressed (F28: a re-delivered
    /// `Wheel`/`Text` must not double-fire; keys/buttons would be
    /// neutralized by the sink anyway, this closes the class).
    pub reliable_duplicates_suppressed: u64,
    /// Reliable events below the watermark dropped (reorder artifacts on
    /// an ordered channel — defensive only, counted separately from fast
    /// stales).
    pub reliable_stale_suppressed: u64,
    pub sequence_gaps: u64,
    pub all_keys_up: u64,
    pub inject_errors: u64,
    /// Buttons/keys addressed by release batches (sink-reported counts).
    pub released_buttons: u64,
    pub released_keys: u64,
}

pub struct InputPump<S: InputSink> {
    sink: S,
    last_reliable_seq: Option<u64>,
    last_fast_seq: Option<u64>,
    counters: InputCounters,
    /// Last applied `MouseMove` position (coalescing proof; never logged).
    latest_position: Option<(u16, u16)>,
    /// Last `all_keys_up` trigger seen (diagnostic state, not user input).
    last_trigger: Option<AllKeysUpTrigger>,
}

impl<S: InputSink> InputPump<S> {
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            last_reliable_seq: None,
            last_fast_seq: None,
            counters: InputCounters::default(),
            latest_position: None,
            last_trigger: None,
        }
    }

    /// Apply one wire input event. Called from the node's pump thread with
    /// events the transport already decoded; never logs the payload.
    pub fn on_input(&mut self, event: &InputEvent) {
        match event {
            InputEvent::MouseMove { seq, x, y } => {
                if self.last_fast_seq.is_none_or(|last| *seq > last) {
                    self.last_fast_seq = Some(*seq);
                    self.latest_position = Some((*x, *y));
                    self.inject(event);
                    self.counters.moves_applied += 1;
                } else {
                    self.counters.moves_stale_suppressed += 1;
                }
            }
            InputEvent::Key { seq, .. }
            | InputEvent::MouseButton { seq, .. }
            | InputEvent::Wheel { seq, .. }
            | InputEvent::Text { seq, .. } => {
                // Order: gap check (may force-release) → apply only a
                // strictly-newer seq. An exact duplicate of the watermark
                // is suppressed (F28); older reliable events are stale
                // reorder artifacts, suppressed separately.
                let pre_watermark = self.last_reliable_seq;
                let post_gap = self.gap_check(*seq);
                match pre_watermark {
                    Some(last) if *seq == last => {
                        self.counters.reliable_duplicates_suppressed += 1;
                    }
                    Some(last) if *seq < last => {
                        self.counters.reliable_stale_suppressed += 1;
                    }
                    _ => {
                        let _ = post_gap;
                        self.inject(event);
                        self.counters.reliable_applied += 1;
                    }
                }
            }
            InputEvent::AllKeysUp { trigger } => {
                self.release_all(*trigger);
            }
        }
    }

    /// Sequence-gap check for reliable-path events. Returns `true` when the
    /// event follows a detected gap (post-gap delivery after a forced
    /// `all_keys_up`). Order: gap → release everything → apply the event.
    fn gap_check(&mut self, seq: u64) -> bool {
        let post_gap = match self.last_reliable_seq {
            Some(last) if seq > last + 1 => {
                // Reliable-sequence gap: stuck-key safety fires before the
                // new event is applied (wire.rs contract).
                self.counters.sequence_gaps += 1;
                self.release_all(AllKeysUpTrigger::SequenceGap);
                true
            }
            _ => false,
        };
        if self.last_reliable_seq.is_none_or(|last| seq > last) {
            self.last_reliable_seq = Some(seq);
        }
        post_gap
    }

    /// Session-teardown / focus-loss safety: release every held
    /// key/button, reporting counts through the counters.
    pub fn all_keys_up(&mut self, trigger: AllKeysUpTrigger) {
        self.release_all(trigger);
    }

    /// Reset sequence tracking for a fresh session (a new controller
    /// starts seq at 1; the old session's watermark must not gate it).
    pub fn reset_for_new_session(&mut self) {
        self.last_reliable_seq = None;
        self.last_fast_seq = None;
    }

    fn release_all(&mut self, trigger: AllKeysUpTrigger) {
        self.last_trigger = Some(trigger);
        self.counters.all_keys_up += 1;
        let outcome = self.sink.release_all(trigger);
        self.counters.released_buttons += u64::from(outcome.released.buttons);
        self.counters.released_keys += u64::from(outcome.released.keys);
        if outcome.error.is_some() {
            // The safety path must not error the session (trait contract);
            // count it for diagnostics.
            self.counters.inject_errors += 1;
        }
    }

    fn inject(&mut self, event: &InputEvent) {
        if self.sink.inject(event).is_err() {
            self.counters.inject_errors += 1;
        }
    }

    pub fn counters(&self) -> InputCounters {
        self.counters
    }

    pub fn held_count(&self) -> usize {
        self.sink.held_count()
    }

    pub fn latest_position(&self) -> Option<(u16, u16)> {
        self.latest_position
    }

    pub fn last_trigger(&self) -> Option<AllKeysUpTrigger> {
        self.last_trigger
    }

    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use input_windows::{InputError, ReleaseOutcome, ReleasedInput};
    use protocol::wire::{AllKeysUpTrigger, ButtonState, InputEvent, MouseButton};

    /// A recording sink implementing the real `input_windows::InputSink`
    /// trait (the same shape the product's `SendInput` adapter fills).
    struct RecordingSink {
        held: usize,
        injected: u64,
        releases: u64,
        last_release: Option<AllKeysUpTrigger>,
        fail_inject: bool,
    }

    impl RecordingSink {
        fn new() -> Self {
            Self {
                held: 0,
                injected: 0,
                releases: 0,
                last_release: None,
                fail_inject: false,
            }
        }
    }

    impl InputSink for RecordingSink {
        fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
            if self.fail_inject {
                return Err(InputError::Other("scripted".into()));
            }
            match event {
                InputEvent::Key { state, .. } | InputEvent::MouseButton { state, .. } => {
                    match state {
                        ButtonState::Pressed => self.held += 1,
                        ButtonState::Released => self.held = self.held.saturating_sub(1),
                    }
                }
                InputEvent::AllKeysUp { .. } => self.held = 0,
                _ => {}
            }
            self.injected += 1;
            Ok(())
        }

        fn all_keys_up(&mut self) -> Result<(), InputError> {
            self.held = 0;
            self.releases += 1;
            Ok(())
        }

        fn held_count(&self) -> usize {
            self.held
        }

        fn release_all(&mut self, trigger: AllKeysUpTrigger) -> ReleaseOutcome {
            let held = self.held;
            let _ = self.all_keys_up();
            self.last_release = Some(trigger);
            ReleaseOutcome {
                trigger,
                released: ReleasedInput {
                    buttons: 0,
                    keys: held as u32,
                },
                error: None,
            }
        }
    }

    fn key(seq: u64, pressed: bool) -> InputEvent {
        InputEvent::Key {
            seq,
            scan_code: 0x1E,
            extended: false,
            state: if pressed {
                ButtonState::Pressed
            } else {
                ButtonState::Released
            },
        }
    }

    #[test]
    fn reliable_gap_releases_held_keys_before_applying() {
        let mut pump = InputPump::new(RecordingSink::new());
        pump.on_input(&key(1, true));
        pump.on_input(&key(2, true));
        assert_eq!(pump.held_count(), 2);
        // Gap: seq 5 after 2 → AllKeysUp(SequenceGap) then apply.
        pump.on_input(&key(5, true));
        assert_eq!(pump.counters().sequence_gaps, 1);
        assert_eq!(pump.counters().all_keys_up, 1);
        assert_eq!(pump.counters().released_keys, 2, "sink-reported release");
        assert_eq!(pump.held_count(), 1, "gap released the two held keys");
        assert_eq!(pump.counters().reliable_applied, 3);
        assert_eq!(pump.last_trigger(), Some(AllKeysUpTrigger::SequenceGap));
    }

    #[test]
    fn fast_channel_suppresses_stale_arrivals() {
        let mut pump = InputPump::new(RecordingSink::new());
        let mv = |seq: u64, x: u16, y: u16| InputEvent::MouseMove { seq, x, y };
        pump.on_input(&mv(10, 100, 200));
        pump.on_input(&mv(9, 1, 2)); // reorder artifact
        pump.on_input(&mv(11, 300, 400));
        assert_eq!(pump.counters().moves_applied, 2);
        assert_eq!(pump.counters().moves_stale_suppressed, 1);
        assert_eq!(pump.latest_position(), Some((300, 400)));
    }

    #[test]
    fn disconnect_releases_everything_and_is_idempotent() {
        let mut pump = InputPump::new(RecordingSink::new());
        pump.on_input(&key(1, true));
        pump.on_input(&InputEvent::MouseButton {
            seq: 2,
            button: MouseButton::Left,
            state: ButtonState::Pressed,
        });
        assert_eq!(pump.held_count(), 2);
        pump.all_keys_up(AllKeysUpTrigger::Disconnect);
        pump.all_keys_up(AllKeysUpTrigger::Disconnect);
        assert_eq!(pump.held_count(), 0);
        assert_eq!(pump.counters().all_keys_up, 2);
        assert_eq!(pump.last_trigger(), Some(AllKeysUpTrigger::Disconnect));
    }

    /// F28: an exact-duplicate reliable seq is suppressed, not re-applied
    /// (a re-delivered `Wheel` must not scroll twice, `Text` not type
    /// twice); older reliable arrivals are counted as stale reorders.
    #[test]
    fn duplicate_reliable_seq_is_suppressed_not_reapplied() {
        let mut pump = InputPump::new(RecordingSink::new());
        let wheel = |seq: u64| InputEvent::Wheel {
            seq,
            delta_v: -120,
            delta_h: 0,
        };
        pump.on_input(&wheel(5));
        pump.on_input(&wheel(5)); // exact duplicate
        pump.on_input(&wheel(3)); // stale reorder artifact
        pump.on_input(&wheel(6)); // next in sequence
        let counters = pump.counters();
        assert_eq!(counters.reliable_applied, 2, "only seq 5 and 6 applied");
        assert_eq!(counters.reliable_duplicates_suppressed, 1);
        assert_eq!(counters.reliable_stale_suppressed, 1);
        // The sink saw exactly two injections (duplicate and stale dropped
        // before inject, not neutralized inside the sink).
        let sink = pump.sink_mut();
        assert_eq!(sink.injected, 2);
        // A duplicate after a gap is still a duplicate (watermark moved).
        pump.on_input(&wheel(9)); // gap 6→9 fires release, then applies 9
        pump.on_input(&wheel(9));
        assert_eq!(pump.counters().reliable_duplicates_suppressed, 2);
        assert_eq!(pump.counters().reliable_applied, 3);
    }

    #[test]
    fn new_session_resets_watermarks() {
        let mut pump = InputPump::new(RecordingSink::new());
        pump.on_input(&key(500, true));
        pump.reset_for_new_session();
        // A fresh controller's seq 1 must not read as a gap.
        pump.on_input(&key(1, true));
        assert_eq!(pump.counters().sequence_gaps, 0);
    }

    #[test]
    fn controller_all_keys_up_passthrough() {
        let mut pump = InputPump::new(RecordingSink::new());
        pump.on_input(&key(1, true));
        pump.on_input(&InputEvent::AllKeysUp {
            trigger: AllKeysUpTrigger::FocusLost,
        });
        assert_eq!(pump.held_count(), 0);
        assert_eq!(pump.counters().all_keys_up, 1);
        assert_eq!(pump.last_trigger(), Some(AllKeysUpTrigger::FocusLost));
    }

    #[test]
    fn inject_errors_are_counted_not_fatal() {
        let mut sink = RecordingSink::new();
        sink.fail_inject = true;
        let mut pump = InputPump::new(sink);
        let mv = InputEvent::MouseMove { seq: 1, x: 2, y: 3 };
        pump.on_input(&mv);
        assert_eq!(pump.counters().inject_errors, 1);
        assert_eq!(pump.counters().moves_applied, 1);
    }
}
