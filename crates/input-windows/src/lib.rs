//! # `input-windows` — `SendInput` injection adapter (M2, RD-008)
//!
//! Platform boundary for input (invariant 7). The controller side never
//! touches this crate; only the **host** injects. Input events arrive as
//! `protocol::wire::InputEvent` on the data channels and are injected via
//! `SendInput` here.
//!
//! Hard rules from the source plan baked into the contract:
//! * normalized `0..=65535` coordinates (absolute `MOUSEEVENTF_ABSOLUTE`),
//! * never log input (invariant 6),
//! * track held keys/buttons and release everything on
//!   [`InputSink::all_keys_up`] — called on focus loss, disconnect, and
//!   reliable-input sequence gaps,
//! * documented MVP limit: input into elevated/UAC surfaces can be blocked by
//!   UIPI; it fails visibly, never silently corrupts modifier state.

use protocol::wire::{ButtonState, InputEvent, MouseButton};

#[derive(Debug)]
pub struct InputError(pub String);

impl core::fmt::Display for InputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "input injection failed: {}", self.0)
    }
}

impl std::error::Error for InputError {}

/// Narrow platform boundary for injecting remote input on the host.
///
/// Implementations must maintain full button/key/scroll-button/lock-key state
/// so `all_keys_up` can synthesize the correct release set. Logging of event
/// contents inside implementations is forbidden (invariant 6).
pub trait InputSink: Send {
    /// Inject one decoded wire input event. `seq` gap detection on
    /// `input-reliable` is the caller's job; on a gap the caller must invoke
    /// [`InputSink::all_keys_up`] before resuming.
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError>;

    /// Release every held key and button. Idempotent; must succeed even when
    /// individual releases fail (report via diagnostics, not by erroring the
    /// safety path).
    fn all_keys_up(&mut self) -> Result<(), InputError>;

    /// Which buttons/keys are currently held (for the host-side safety
    /// indicator). Never logged with content.
    fn held_count(&self) -> usize;
}

/// Coordinate mapping helper shared by tests and the M2 implementation:
/// normalized 0..=65535 → absolute pixels on a monitor of `width`/`height`.
pub fn normalized_to_px(value: u16, extent_px: u32) -> i32 {
    let scaled = (u32::from(value) + 1) * extent_px;
    // Round to nearest: ((v + 1) * extent) >> 16, clamped to extent.
    ((scaled >> 16) as i32).min(extent_px as i32 - 1).max(0)
}

/// M0 smoke helper proving the enum vocabulary lines up with Windows input
/// semantics; the real `SendInput` adapter lands in M2.
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
}
