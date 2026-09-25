//! # `input-windows` — `SendInput` injection adapter (M2, RD-008)
//!
//! Platform boundary for input (invariant 7). The controller side never
//! touches this crate; only the **host** injects. Input events arrive as
//! `protocol::wire::InputEvent` on the data channels and are injected via
//! `SendInput` by [`sendinput::SendInputSink`].
//!
//! Hard rules from the source plan baked into the contract:
//! * normalized `0..=65535` coordinates (absolute `MOUSEEVENTF_ABSOLUTE`,
//!   translated through `MOUSEEVENTF_VIRTUALDESK` onto the selected
//!   monitor),
//! * never log input (invariant 6) — including the release-path types
//!   below, which carry counts only,
//! * track held keys/buttons and release everything on
//!   [`InputSink::all_keys_up`] / [`InputSink::release_all`] — called on
//!   focus loss, disconnect, and reliable-input sequence gaps,
//! * documented MVP limit: input into elevated/UAC surfaces can be blocked
//!   by UIPI and fails with [`InputError::BlockedByUipi`]; it fails
//!   visibly, never silently corrupts modifier state.

pub mod capture;
pub mod sendinput;

pub use capture::{
    INPUT_QUEUE_CAP, PresenterInput, ViewerInputEvent, WindowInputCapture, map_into_dest,
};
pub use protocol::wire::AllKeysUpTrigger;
pub use sendinput::{MonitorRect, SendInputSink};

use protocol::wire::{ButtonState, InputEvent, MouseButton};

/// Typed injection failure. Windows API details stay inside this crate
/// (invariant 7); callers see typed variants through the [`InputSink`]
/// boundary. No variant carries input payloads — counts and error codes only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    /// `SendInput` was blocked — almost certainly UIPI: the foreground
    /// window runs at a higher integrity level (elevated/UAC), or the
    /// calling thread is not attached to the interactive input desktop.
    /// Known MVP limit (PLAN risk register): the mitigation is operational
    /// (run the host elevated for sessions that must control elevated
    /// apps), not silent retry.
    BlockedByUipi,
    /// `SendInput` injected fewer events than requested.
    Injection {
        injected: u32,
        requested: u32,
        last_error: Option<u32>,
    },
    /// The configured monitor rectangle has non-positive extents.
    InvalidMonitorRect { width: i32, height: i32 },
    /// The monitor rectangle does not intersect the current virtual desktop
    /// (the display configuration changed since the monitor was selected).
    MonitorOutsideDesktop { left: i32, top: i32 },
    /// Virtual-desktop metrics are unavailable (no interactive desktop,
    /// e.g. a service session without `WinSta0` input access).
    VirtualDesktopUnavailable,
    /// Anything else (e.g. a bounded-input rejection such as an over-long
    /// text event).
    Other(String),
}

impl core::fmt::Display for InputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InputError::BlockedByUipi => write!(
                f,
                "input blocked (UIPI): the foreground window is elevated or \
                 the thread is not on the interactive desktop"
            ),
            InputError::Injection {
                injected,
                requested,
                last_error,
            } => write!(
                f,
                "SendInput injected {injected}/{requested} events (last error {last_error:?})"
            ),
            InputError::InvalidMonitorRect { width, height } => {
                write!(
                    f,
                    "monitor rectangle has non-positive extents ({width}x{height})"
                )
            }
            InputError::MonitorOutsideDesktop { left, top } => write!(
                f,
                "monitor rectangle at ({left},{top}) does not intersect the virtual desktop"
            ),
            InputError::VirtualDesktopUnavailable => {
                write!(
                    f,
                    "virtual desktop metrics unavailable (no interactive desktop?)"
                )
            }
            InputError::Other(why) => write!(f, "input injection failed: {why}"),
        }
    }
}

impl std::error::Error for InputError {}

/// Payload-free summary of what a release path freed. Counts only — no
/// button identities, no scan codes, no text (invariant 6: the safety path
/// must be incapable of carrying input content into logs or diagnostics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReleasedInput {
    /// Mouse buttons released (L/R/M/X1/X2).
    pub buttons: u32,
    /// Keyboard keys released (distinct scan-code + extended pairs).
    pub keys: u32,
}

/// Result of [`InputSink::release_all`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseOutcome {
    /// Which safety path fired. Diagnostic state, not user input.
    pub trigger: AllKeysUpTrigger,
    /// What was held and addressed by the release batch. On injection
    /// failure the affected inputs stay tracked for a later retry but are
    /// still counted here (they were addressed, not necessarily delivered).
    pub released: ReleasedInput,
    /// Release-batch injection failure, if any. Deliberately not an `Err`:
    /// the safety path must not block teardown (M0 trait contract);
    /// diagnostics/counters consume this field instead.
    pub error: Option<InputError>,
}

/// Narrow platform boundary for injecting remote input on the host.
///
/// Implementations must maintain full button/key state so `all_keys_up` /
/// `release_all` can synthesize the correct release set. Logging of event
/// contents inside implementations is forbidden (invariant 6).
pub trait InputSink: Send {
    /// Inject one decoded wire input event. `seq` gap detection on
    /// `input-reliable` is the caller's job; on a gap the caller must invoke
    /// [`InputSink::all_keys_up`] (or [`InputSink::release_all`]) before
    /// resuming.
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError>;

    /// Release every held key and button. Idempotent; must succeed even when
    /// individual releases fail (report via diagnostics, not by erroring the
    /// safety path).
    fn all_keys_up(&mut self) -> Result<(), InputError>;

    /// Which buttons/keys are currently held (for the host-side safety
    /// indicator). Never logged with content.
    fn held_count(&self) -> usize;

    /// M2 addition — additive with a default impl, so the M0 trait shape is
    /// unchanged for existing implementors: [`InputSink::all_keys_up`] with
    /// the triggering safety reason and a payload-free report of what was
    /// released. Trigger wiring: `FocusLost` arrives on the wire as
    /// `InputEvent::AllKeysUp` (controller-side focus loss); `SequenceGap`
    /// and `Disconnect` are host-side decisions and belong in direct calls
    /// to this method.
    fn release_all(&mut self, trigger: AllKeysUpTrigger) -> ReleaseOutcome {
        let error = self.all_keys_up().err();
        ReleaseOutcome {
            trigger,
            released: ReleasedInput::default(),
            error,
        }
    }
}

/// Coordinate mapping helper shared by tests and the M2 implementation:
/// normalized 0..=65535 → absolute pixels on a monitor of `width`/`height`.
pub fn normalized_to_px(value: u16, extent_px: u32) -> i32 {
    let scaled = (u32::from(value) + 1) * extent_px;
    // Round to nearest: ((v + 1) * extent) >> 16, clamped to extent.
    ((scaled >> 16) as i32).min(extent_px as i32 - 1).max(0)
}

/// M0 smoke helper proving the enum vocabulary lines up with Windows input
/// semantics; kept for parity with the M0 contract tests.
pub fn describe_button(button: MouseButton, state: ButtonState) -> String {
    let name = match button {
        MouseButton::Left => "left",
        MouseButton::Right => "right",
        MouseButton::Middle => "middle",
        MouseButton::X1 => "x1",
        MouseButton::X2 => "x2",
    };
    let verb = match state {
        ButtonState::Pressed => "down",
        ButtonState::Released => "up",
    };
    format!("{name} {verb}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_coordinates_map_to_monitor_extents() {
        assert_eq!(normalized_to_px(0, 1920), 0);
        assert_eq!(normalized_to_px(32_767, 1920), 960);
        assert_eq!(normalized_to_px(65_535, 1920), 1919);
        assert_eq!(normalized_to_px(65_535, 3840), 3839);
        assert_eq!(normalized_to_px(0, 1), 0);
    }

    #[test]
    fn wire_input_events_match_sink_vocabulary() {
        // The wire enum and the sink share the same vocabulary by
        // construction; pin the round trip of names used in diagnostics.
        assert_eq!(
            describe_button(MouseButton::X1, ButtonState::Pressed),
            "x1 down"
        );
        assert_eq!(
            describe_button(MouseButton::Left, ButtonState::Released),
            "left up"
        );
    }

    /// The M2 `release_all` addition is additive: an M0-shaped implementor
    /// (no `release_all` override) keeps compiling and the default
    /// delegates to `all_keys_up` without inventing release counts.
    #[test]
    fn default_release_all_delegates_to_all_keys_up() {
        struct Stub;
        impl InputSink for Stub {
            fn inject(&mut self, _event: &InputEvent) -> Result<(), InputError> {
                Ok(())
            }
            fn all_keys_up(&mut self) -> Result<(), InputError> {
                Err(InputError::VirtualDesktopUnavailable)
            }
            fn held_count(&self) -> usize {
                0
            }
        }
        let outcome = InputSink::release_all(&mut Stub, AllKeysUpTrigger::SequenceGap);
        assert_eq!(outcome.trigger, AllKeysUpTrigger::SequenceGap);
        assert_eq!(outcome.released, ReleasedInput::default());
        assert_eq!(outcome.error, Some(InputError::VirtualDesktopUnavailable));
    }
}
