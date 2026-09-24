//! `SendInput`-backed [`InputSink`] — the M2 host-side input adapter.
//!
//! ## Injection model
//!
//! One wire event maps to one `SendInput` call with one event (mouse move,
//! button, key, one per non-zero wheel axis). `Text` maps to one
//! `KEYEVENTF_UNICODE` event per UTF-16 code unit — including both units of
//! a surrogate pair, in order — as down events only, which is the documented
//! `KEYEVENTF_UNICODE` usage; `wVk` stays zero. The only multi-event call is
//! [`InputSink::release_all`], which releases every held button/key in one
//! batch so the release set is applied in order within a single call.
//! Nothing is queued: `inject` is a synchronous hand-off into the OS input
//! stream, so the ordering of the `input-reliable` data channel is the only
//! ordering; unordered `input-fast` moves are last-write-wins (the OS
//! coalesces absolute moves itself).
//!
//! ## Coordinate spaces
//!
//! * The wire carries `0..=65535` normalized over the **selected monitor**.
//! * `SendInput` absolute mode maps `0..=65535` onto the **primary monitor**,
//!   or onto the **whole virtual desktop** when `MOUSEEVENTF_VIRTUALDESK` is
//!   set. This adapter always sets it and translates:
//!   wire value → monitor pixel ([`crate::normalized_to_px`], the M0
//!   mapping) → virtual-desktop pixel (monitor origin offset) →
//!   virtual-desktop normalized coordinate. The last step is the exact
//!   inverse of the `(a + 1) * extent >> 16` decode the OS applies, so the
//!   composition is pixel-exact under that convention and within one pixel
//!   of any other rounding an OS build might use.
//! * The monitor rectangle must be expressed in the same virtual-desktop
//!   pixel space `GetSystemMetrics(SM_XVIRTUALSCREEN…)` reports. On
//!   mixed-DPI systems the runtime must select monitors by their
//!   `EnumDisplayMonitors`/`GetSystemMetrics` rectangles, not raw DXGI
//!   output coordinates.
//!
//! ## Held-state tracking and the safety contract
//!
//! Every `Key` press and every `MouseButton` press is recorded (scan code +
//! `extended` for keys, so e.g. left and right Ctrl stay distinct);
//! releases remove entries. The tracking is deliberately failure-biased:
//!
//! * presses are tracked even when their injection fails — a spurious
//!   release later is harmless, an untracked stuck-down key is not;
//! * releases clear tracking only when injection succeeded — failed
//!   releases stay tracked so a later [`InputSink::release_all`] can retry;
//! * duplicate presses and releases of unheld inputs are dropped rather
//!   than re-injected (no synthesized auto-repeat, no phantom UPS);
//! * `Text` events are never tracked: `KEYEVENTF_UNICODE` events are not
//!   holdable keys and have nothing to release.
//!
//! [`InputSink::release_all`] / [`InputSink::all_keys_up`] releases
//! everything still held — mouse buttons including X1/X2 and every
//! scan-code key — in one batch, is idempotent, and never blocks the
//! teardown path (the M0 trait contract: individual release failures
//! surface via the returned [`ReleaseOutcome`], not as `Err`). **The runtime
//! must call it on every reliable-input sequence gap, disconnect, and
//! controller focus loss.** Those triggers reach this sink either as
//! `InputEvent::AllKeysUp { trigger }` on the wire (focus loss) or as a
//! direct host-side call (gap, disconnect); this crate's job is that the
//! call is complete whenever it happens.
//!
//! ## Known MVP limit: UIPI / elevated surfaces (PLAN risk register)
//!
//! `SendInput` from a normal-integrity process cannot inject into windows
//! running at a higher integrity level (elevated/UAC applications) or into
//! the secure desktop (UAC prompts). The observable form is a zero return
//! from `SendInput` with `GetLastError() == ERROR_ACCESS_DENIED`; this crate
//! classifies that as [`InputError::BlockedByUipi`] and every other short
//! count as [`InputError::Injection`]. What is **not** detectable: input
//! delivered to a process that then ignores it, and events sent while the
//! caller's thread is attached to a non-input desktop. The mitigation is
//! operational (run the host elevated for sessions that must control
//! elevated apps), never silent retry.
//!
//! ## Threading
//!
//! `SendInput` only reaches the interactive desktop from a thread attached
//! to it (`SetThreadDesktop` — the same requirement the capture side
//! documents as `frame_surface::attach_thread_to_input_desktop`; kept as a
//! doc reference because platform crates must not depend on each other).
//! The sink is `Send` and used single-threaded by design: the runtime owns
//! the injection thread. No locks, no queues, no reordering, and no input
//! payloads are ever logged (invariant 6; the release-path types carry
//! counts only).
//!
//! ```no_run
//! # use input_windows::{InputError, InputSink, MonitorRect, SendInputSink};
//! # use protocol::wire::{AllKeysUpTrigger, InputEvent};
//! # fn main() -> Result<(), InputError> {
//! let mut sink = SendInputSink::new(MonitorRect::primary()?)?;
//! // Nothing held, so this is a verified no-op — safe to demonstrate.
//! sink.inject(&InputEvent::AllKeysUp { trigger: AllKeysUpTrigger::Disconnect })?;
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeSet;

use protocol::wire::{AllKeysUpTrigger, ButtonState, InputEvent, MouseButton};
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, GetLastError};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS, KEYBDINPUT,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE,
    MOUSE_EVENT_FLAGS, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
    MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL,
    MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT, SendInput, VIRTUAL_KEY,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXSCREEN, SM_CXVIRTUALSCREEN, SM_CYSCREEN, SM_CYVIRTUALSCREEN,
    SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, XBUTTON1, XBUTTON2,
};

use crate::{InputError, InputSink, ReleaseOutcome, ReleasedInput, normalized_to_px};

/// Wire `Text` events larger than this many UTF-16 code units are rejected
/// before any `INPUT` is built. Wire messages are bounded by
/// `MAX_WIRE_MESSAGE_BYTES`, but a hostile peer could still send ~1 MiB of
/// text; this keeps the transient batch (and the OS input stream) small
/// (invariant 3 spirit: bounded everything).
const MAX_TEXT_UTF16_UNITS: usize = 1024;

/// The five trackable mouse buttons, in held-state slot order.
const BUTTON_ORDER: [MouseButton; BUTTON_COUNT] = [
    MouseButton::Left,
    MouseButton::Right,
    MouseButton::Middle,
    MouseButton::X1,
    MouseButton::X2,
];
const BUTTON_COUNT: usize = 5;

/// A monitor rectangle in virtual-desktop pixels — the confine target for
/// all absolute pointer motion. Built by the runtime from monitor selection
/// (`SelectMonitor` control message); must be in the coordinate space
/// `GetSystemMetrics(SM_XVIRTUALSCREEN…)` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorRect {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}

impl MonitorRect {
    /// Validated constructor: extents must be positive.
    pub fn new(left: i32, top: i32, width: i32, height: i32) -> Result<Self, InputError> {
        if width <= 0 || height <= 0 {
            return Err(InputError::InvalidMonitorRect { width, height });
        }
        Ok(Self {
            left,
            top,
            width,
            height,
        })
    }

    /// The primary monitor's rectangle (`(0,0)`-anchored in virtual-desktop
    /// pixels). Useful as the default target before the runtime applies a
    /// `SelectMonitor`.
    pub fn primary() -> Result<Self, InputError> {
        // SAFETY: constant metric indices; GetSystemMetrics has no
        // preconditions beyond a valid index.
        let (width, height) =
            unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
        MonitorRect::new(0, 0, width, height)
    }

    /// Intersection with the virtual desktop, or `None` when disjoint (the
    /// display configuration changed underneath the selection).
    fn clamped_to(self, vdesk: &VirtualDesktop) -> Option<MonitorRect> {
        let left = self.left.max(vdesk.left);
        let top = self.top.max(vdesk.top);
        let right = (self.left + self.width).min(vdesk.left + vdesk.width);
        let bottom = (self.top + self.height).min(vdesk.top + vdesk.height);
        if right > left && bottom > top {
            Some(MonitorRect {
                left,
                top,
                width: right - left,
                height: bottom - top,
            })
        } else {
            None
        }
    }
}

/// Virtual-desktop geometry as `GetSystemMetrics` reports it — the same
/// space `MOUSEEVENTF_VIRTUALDESK` coordinates resolve against.
#[derive(Clone, Copy, PartialEq, Eq)]
struct VirtualDesktop {
    left: i32,
    top: i32,
    width: i32,
    height: i32,
}

impl VirtualDesktop {
    #[cfg(test)]
    fn new(left: i32, top: i32, width: i32, height: i32) -> Self {
        Self {
            left,
            top,
            width,
            height,
        }
    }

    fn query() -> Result<Self, InputError> {
        // SAFETY: constant metric indices; no preconditions.
        let (left, top, width, height) = unsafe {
            (
                GetSystemMetrics(SM_XVIRTUALSCREEN),
                GetSystemMetrics(SM_YVIRTUALSCREEN),
                GetSystemMetrics(SM_CXVIRTUALSCREEN),
                GetSystemMetrics(SM_CYVIRTUALSCREEN),
            )
        };
        if width <= 0 || height <= 0 {
            return Err(InputError::VirtualDesktopUnavailable);
        }
        Ok(Self {
            left,
            top,
            width,
            height,
        })
    }
}

/// One tracked physical key: scan code plus the extended flag, so plain and
/// extended occurrences of the same scan code (left/right Ctrl, arrows vs
/// numpad) are independent. No `Debug`: identities must not be printable
/// into logs (invariant 6).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TrackedKey {
    scan_code: u16,
    extended: bool,
}

/// What one raw dispatch reports: how many events `SendInput` injected and,
/// on a short count, the thread's last error captured immediately after the
/// call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RawResult {
    injected: u32,
    last_error: Option<u32>,
}

/// Seam between the adapter logic and the OS call. Production uses
/// [`real_send_input`]; unit tests substitute a recorder so no real input
/// is ever injected.
type RawSendFn = Box<dyn FnMut(&[INPUT]) -> RawResult + Send>;

/// The [`InputSink`] implementation over `SendInput`.
pub struct SendInputSink {
    monitor: MonitorRect,
    vdesk: VirtualDesktop,
    held_buttons: [bool; BUTTON_COUNT],
    held_keys: BTreeSet<TrackedKey>,
    raw: RawSendFn,
}

impl SendInputSink {
    /// Real-`SendInput` sink confined to `monitor`.
    ///
    /// Fails typed when the virtual desktop cannot be queried (no
    /// interactive desktop) or the rect does not intersect it (display
    /// configuration changed since selection).
    pub fn new(monitor: MonitorRect) -> Result<Self, InputError> {
        Self::build(monitor, VirtualDesktop::query()?, Box::new(real_send_input))
    }

    fn build(
        monitor: MonitorRect,
        vdesk: VirtualDesktop,
        raw: RawSendFn,
    ) -> Result<Self, InputError> {
        let clamped = monitor
            .clamped_to(&vdesk)
            .ok_or(InputError::MonitorOutsideDesktop {
                left: monitor.left,
                top: monitor.top,
            })?;
        Ok(Self {
            monitor: clamped,
            vdesk,
            held_buttons: [false; BUTTON_COUNT],
            held_keys: BTreeSet::new(),
            raw,
        })
    }

    /// Re-target the sink (the runtime applies `SelectMonitor`, or
    /// re-selects after a display change). Re-queries the virtual desktop
    /// first so a changed display configuration is picked up. Held-key
    /// state is deliberately untouched: switching monitors must not release
    /// anything the controller still holds.
    pub fn set_monitor_rect(&mut self, monitor: MonitorRect) -> Result<(), InputError> {
        let vdesk = VirtualDesktop::query()?;
        self.retarget(monitor, vdesk)
    }

    /// Re-read display metrics after a display change and re-confine the
    /// current monitor selection (failure handling for display-change
    /// events; the runtime calls this alongside capture's display-change
    /// recovery).
    pub fn refresh_display_metrics(&mut self) -> Result<(), InputError> {
        let current = self.monitor;
        self.set_monitor_rect(current)
    }

    /// Confine to `monitor` against the given desktop geometry. Pure core
    /// of [`SendInputSink::set_monitor_rect`] so the clamp/disjoint logic is
    /// unit-testable without touching the OS.
    fn retarget(&mut self, monitor: MonitorRect, vdesk: VirtualDesktop) -> Result<(), InputError> {
        let clamped = monitor
            .clamped_to(&vdesk)
            .ok_or(InputError::MonitorOutsideDesktop {
                left: monitor.left,
                top: monitor.top,
            })?;
        self.vdesk = vdesk;
        self.monitor = clamped;
        Ok(())
    }

    /// Fire one batch at the raw seam and classify the result.
    fn dispatch(&mut self, inputs: &[INPUT]) -> Result<(), InputError> {
        let result = (self.raw)(inputs);
        classify(result, inputs.len())
    }

    fn inject_button(&mut self, button: MouseButton, state: ButtonState) -> Result<(), InputError> {
        let slot = button_slot(button);
        match state {
            ButtonState::Pressed => {
                if self.held_buttons[slot] {
                    return Ok(()); // duplicate press — drop, no auto-repeat
                }
                self.held_buttons[slot] = true; // track first (failure bias)
                self.dispatch(&[button_event(button, state)])
            }
            ButtonState::Released => {
                if !self.held_buttons[slot] {
                    return Ok(()); // release of an unheld button — drop
                }
                let result = self.dispatch(&[button_event(button, state)]);
                if result.is_ok() {
                    self.held_buttons[slot] = false;
                }
                result
            }
        }
    }

    fn inject_key(
        &mut self,
        scan_code: u16,
        extended: bool,
        state: ButtonState,
    ) -> Result<(), InputError> {
        let key = TrackedKey {
            scan_code,
            extended,
        };
        match state {
            ButtonState::Pressed => {
                if self.held_keys.contains(&key) {
                    return Ok(()); // duplicate press — drop
                }
                self.held_keys.insert(key); // track first (failure bias)
                self.dispatch(&[key_event(scan_code, extended, state)])
            }
            ButtonState::Released => {
                if !self.held_keys.contains(&key) {
                    return Ok(()); // release of an unheld key — drop
                }
                let result = self.dispatch(&[key_event(scan_code, extended, state)]);
                if result.is_ok() {
                    self.held_keys.remove(&key);
                }
                result
            }
        }
    }

    /// Core of the safety path: release everything still held in one batch.
    /// Never errors; see [`ReleaseOutcome`].
    fn release_held(&mut self, trigger: AllKeysUpTrigger) -> ReleaseOutcome {
        let held_button_slots: Vec<usize> = self
            .held_buttons
            .iter()
            .enumerate()
            .filter(|(_, held)| **held)
            .map(|(slot, _)| slot)
            .collect();
        let mut batch = Vec::with_capacity(held_button_slots.len() + self.held_keys.len());
        for slot in held_button_slots {
            batch.push(button_event(BUTTON_ORDER[slot], ButtonState::Released));
        }
        let keys: Vec<TrackedKey> = self.held_keys.iter().copied().collect();
        for key in &keys {
            batch.push(key_event(
                key.scan_code,
                key.extended,
                ButtonState::Released,
            ));
        }

        let released = ReleasedInput {
            buttons: batch.len() as u32 - keys.len() as u32,
            keys: keys.len() as u32,
        };
        if batch.is_empty() {
            return ReleaseOutcome {
                trigger,
                released: ReleasedInput::default(),
                error: None,
            };
        }

        let error = match self.dispatch(&batch) {
            Ok(()) => {
                self.held_buttons = [false; BUTTON_COUNT];
                self.held_keys.clear();
                None
            }
            // Keep tracking so a later retry (another release_all, or the
            // runtime's disconnect sweep) can still free them.
            Err(e) => Some(e),
        };
        ReleaseOutcome {
            trigger,
            released,
            error,
        }
    }

    fn inject_event(&mut self, event: &InputEvent) -> Result<(), InputError> {
        match event {
            InputEvent::MouseMove { x, y, .. } => {
                let input = move_event(*x, *y, self.monitor, self.vdesk);
                self.dispatch(&[input])
            }
            InputEvent::MouseButton { button, state, .. } => self.inject_button(*button, *state),
            InputEvent::Wheel {
                delta_v, delta_h, ..
            } => {
                // One event per non-zero axis, batched into a single call.
                // A (0,0) wheel injects nothing.
                let mut batch = Vec::with_capacity(2);
                if *delta_v != 0 {
                    batch.push(mouse_input(0, 0, *delta_v as u32, MOUSEEVENTF_WHEEL));
                }
                if *delta_h != 0 {
                    batch.push(mouse_input(0, 0, *delta_h as u32, MOUSEEVENTF_HWHEEL));
                }
                if batch.is_empty() {
                    return Ok(());
                }
                self.dispatch(&batch)
            }
            InputEvent::Key {
                scan_code,
                extended,
                state,
                ..
            } => self.inject_key(*scan_code, *extended, *state),
            InputEvent::Text { code_points, .. } => {
                let mut batch = Vec::new();
                unicode_events(code_points, &mut batch)?;
                if batch.is_empty() {
                    return Ok(());
                }
                // Not tracked: UNICODE events are not holdable keys.
                self.dispatch(&batch)
            }
            InputEvent::AllKeysUp { trigger } => {
                let _ = self.release_held(*trigger);
                // Safety path must never block teardown (M0 contract);
                // failures surface via `release_all`'s outcome instead.
                Ok(())
            }
        }
    }
}

impl InputSink for SendInputSink {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        self.inject_event(event)
    }

    fn all_keys_up(&mut self) -> Result<(), InputError> {
        // This M0 method carries no trigger; the recorded reason defaults
        // to Disconnect (the teardown default). Callers wanting accurate
        // labels use `release_all` or inject the wire `AllKeysUp` event.
        let _ = self.release_held(AllKeysUpTrigger::Disconnect);
        Ok(())
    }

    fn held_count(&self) -> usize {
        self.held_buttons.iter().filter(|held| **held).count() + self.held_keys.len()
    }

    fn release_all(&mut self, trigger: AllKeysUpTrigger) -> ReleaseOutcome {
        self.release_held(trigger)
    }
}

/// Thin unsafe wrapper around `SendInput`, capturing the return count and,
/// on a short count, the thread's last error for typed classification.
fn real_send_input(inputs: &[INPUT]) -> RawResult {
    // SAFETY: `inputs` is a valid slice of `INPUT` for the duration of the
    // synchronous call, and the size argument matches the element type by
    // construction. GetLastError is read immediately, before any other
    // Win32 call can clobber it.
    unsafe {
        let injected = SendInput(inputs, core::mem::size_of::<INPUT>() as i32);
        let last_error = ((injected as usize) < inputs.len()).then(|| GetLastError().0);
        RawResult {
            injected,
            last_error,
        }
    }
}

/// Turn a raw dispatch into a typed result. `ERROR_ACCESS_DENIED` on a short
/// count is the UIPI signature (elevated foreground window / wrong desktop).
fn classify(result: RawResult, requested: usize) -> Result<(), InputError> {
    if result.injected as usize >= requested {
        return Ok(());
    }
    if result.last_error == Some(ERROR_ACCESS_DENIED.0) {
        return Err(InputError::BlockedByUipi);
    }
    Err(InputError::Injection {
        injected: result.injected,
        requested: requested as u32,
        last_error: result.last_error,
    })
}

fn button_slot(button: MouseButton) -> usize {
    BUTTON_ORDER
        .iter()
        .position(|candidate| *candidate == button)
        .expect("BUTTON_ORDER covers every MouseButton variant")
}

fn mouse_input(dx: i32, dy: i32, mouse_data: u32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        // SAFETY-free by construction: writing a union arm (no read).
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: mouse_data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn keyboard_input(scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0), // required for SCANCODE/UNICODE events
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn button_event(button: MouseButton, state: ButtonState) -> INPUT {
    let (flags, data) = match (button, state) {
        (MouseButton::Left, ButtonState::Pressed) => (MOUSEEVENTF_LEFTDOWN, 0),
        (MouseButton::Left, ButtonState::Released) => (MOUSEEVENTF_LEFTUP, 0),
        (MouseButton::Right, ButtonState::Pressed) => (MOUSEEVENTF_RIGHTDOWN, 0),
        (MouseButton::Right, ButtonState::Released) => (MOUSEEVENTF_RIGHTUP, 0),
        (MouseButton::Middle, ButtonState::Pressed) => (MOUSEEVENTF_MIDDLEDOWN, 0),
        (MouseButton::Middle, ButtonState::Released) => (MOUSEEVENTF_MIDDLEUP, 0),
        (MouseButton::X1, ButtonState::Pressed) => (MOUSEEVENTF_XDOWN, u32::from(XBUTTON1)),
        (MouseButton::X1, ButtonState::Released) => (MOUSEEVENTF_XUP, u32::from(XBUTTON1)),
        (MouseButton::X2, ButtonState::Pressed) => (MOUSEEVENTF_XDOWN, u32::from(XBUTTON2)),
        (MouseButton::X2, ButtonState::Released) => (MOUSEEVENTF_XUP, u32::from(XBUTTON2)),
    };
    mouse_input(0, 0, data, flags)
}

fn key_event(scan_code: u16, extended: bool, state: ButtonState) -> INPUT {
    let mut flags = KEYEVENTF_SCANCODE;
    if extended {
        flags |= KEYEVENTF_EXTENDEDKEY;
    }
    if state == ButtonState::Released {
        flags |= KEYEVENTF_KEYUP;
    }
    keyboard_input(scan_code, flags)
}

/// Wire `0..=65535` over one monitor axis → `MOUSEEVENTF_VIRTUALDESK`
/// absolute coordinate over the same axis of the virtual desktop. Composes
/// the M0 monitor decode with the exact inverse of the OS's
/// `(a + 1) * extent >> 16` virtual-desktop decode:
/// `a = ceil(px * 65536 / extent) - 1`, clamped. Axis extents are passed
/// explicitly — x and y have different monitor/desktop extents in general.
fn normalized_to_virtual_absolute(
    value: u16,
    monitor_offset: i32,
    monitor_extent: i32,
    desktop_extent: i32,
) -> i32 {
    let px = i64::from(normalized_to_px(value, monitor_extent as u32)) + i64::from(monitor_offset);
    let extent = i64::from(desktop_extent);
    let absolute = ((px * 65_536 + extent - 1) / extent - 1).clamp(0, 65_535);
    absolute as i32
}

fn move_event(x: u16, y: u16, monitor: MonitorRect, vdesk: VirtualDesktop) -> INPUT {
    let dx =
        normalized_to_virtual_absolute(x, monitor.left - vdesk.left, monitor.width, vdesk.width);
    let dy =
        normalized_to_virtual_absolute(y, monitor.top - vdesk.top, monitor.height, vdesk.height);
    mouse_input(
        dx,
        dy,
        0,
        MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
    )
}

/// Expand a `Text` payload into `KEYEVENTF_UNICODE` down events, one per
/// UTF-16 code unit (`encode_utf16` emits surrogate pairs for astral
/// characters, which the OS keyboard buffer composes). Bounded by
/// [`MAX_TEXT_UTF16_UNITS`]; rejected before any event is built.
fn unicode_events(text: &str, out: &mut Vec<INPUT>) -> Result<(), InputError> {
    let units = text.encode_utf16().collect::<Vec<u16>>();
    if units.len() > MAX_TEXT_UTF16_UNITS {
        return Err(InputError::Other(format!(
            "text event exceeds {MAX_TEXT_UTF16_UNITS} utf-16 units"
        )));
    }
    for unit in units {
        out.push(keyboard_input(unit, KEYEVENTF_UNICODE));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // Harmless set-1 scan codes (F13/F14/F15: 0x64/0x65/0x66) — no default
    // Windows binding, no modifier, nothing printable.
    const SCAN_F13: u16 = 0x64;
    const SCAN_F14: u16 = 0x65;
    const SCAN_F15: u16 = 0x66;
    const SCAN_CTRL: u16 = 0x1D;

    /// Test-only mirror of one injected `INPUT`, so assertions never touch
    /// unions in every test body.
    #[derive(Debug, Clone, PartialEq)]
    enum Recorded {
        Move { dx: i32, dy: i32 },
        Wheel { delta: i32, horizontal: bool },
        Button { button: MouseButton, down: bool },
        Key { scan: u16, extended: bool, up: bool },
        Unicode { unit: u16 },
    }

    fn describe(input: &INPUT) -> Recorded {
        // SAFETY: read of the union arm matching `r#type`, which the
        // builders in this module always set consistently.
        unsafe {
            match input.r#type {
                INPUT_MOUSE => {
                    let mi = input.Anonymous.mi;
                    let flags = mi.dwFlags.0;
                    if flags & MOUSEEVENTF_MOVE.0 != 0 {
                        return Recorded::Move {
                            dx: mi.dx,
                            dy: mi.dy,
                        };
                    }
                    if flags & MOUSEEVENTF_WHEEL.0 != 0 {
                        return Recorded::Wheel {
                            delta: mi.mouseData as i32,
                            horizontal: false,
                        };
                    }
                    if flags & MOUSEEVENTF_HWHEEL.0 != 0 {
                        return Recorded::Wheel {
                            delta: mi.mouseData as i32,
                            horizontal: true,
                        };
                    }
                    let down = flags
                        & (MOUSEEVENTF_LEFTDOWN.0
                            | MOUSEEVENTF_RIGHTDOWN.0
                            | MOUSEEVENTF_MIDDLEDOWN.0
                            | MOUSEEVENTF_XDOWN.0)
                        != 0;
                    let button = if flags & (MOUSEEVENTF_LEFTDOWN.0 | MOUSEEVENTF_LEFTUP.0) != 0 {
                        MouseButton::Left
                    } else if flags & (MOUSEEVENTF_RIGHTDOWN.0 | MOUSEEVENTF_RIGHTUP.0) != 0 {
                        MouseButton::Right
                    } else if flags & (MOUSEEVENTF_MIDDLEDOWN.0 | MOUSEEVENTF_MIDDLEUP.0) != 0 {
                        MouseButton::Middle
                    } else if mi.mouseData == u32::from(XBUTTON1) {
                        MouseButton::X1
                    } else {
                        MouseButton::X2
                    };
                    Recorded::Button { button, down }
                }
                INPUT_KEYBOARD => {
                    let ki = input.Anonymous.ki;
                    let flags = ki.dwFlags.0;
                    if flags & KEYEVENTF_UNICODE.0 != 0 {
                        assert_eq!(ki.wVk.0, 0, "UNICODE events must keep wVk zero");
                        Recorded::Unicode { unit: ki.wScan }
                    } else {
                        assert_eq!(ki.wVk.0, 0, "SCANCODE events must keep wVk zero");
                        assert!(
                            flags & KEYEVENTF_SCANCODE.0 != 0,
                            "key events must be scan-code based"
                        );
                        Recorded::Key {
                            scan: ki.wScan,
                            extended: flags & KEYEVENTF_EXTENDEDKEY.0 != 0,
                            up: flags & KEYEVENTF_KEYUP.0 != 0,
                        }
                    }
                }
                other => panic!("unexpected input type {other:?}"),
            }
        }
    }

    #[derive(Default)]
    struct RecorderState {
        batches: Vec<Vec<Recorded>>,
        fail_with: Option<RawResult>,
    }

    /// Sink wired to a recorder instead of the OS: no real input is ever
    /// injected by the unit tests.
    fn recorder_sink(
        monitor: MonitorRect,
        vdesk: VirtualDesktop,
    ) -> (SendInputSink, Arc<Mutex<RecorderState>>) {
        let state = Arc::new(Mutex::new(RecorderState::default()));
        let seam_state = Arc::clone(&state);
        let raw: RawSendFn = Box::new(move |inputs: &[INPUT]| {
            let mut st = seam_state.lock().expect("recorder lock");
            st.batches.push(inputs.iter().map(describe).collect());
            st.fail_with.unwrap_or(RawResult {
                injected: inputs.len() as u32,
                last_error: None,
            })
        });
        let sink = SendInputSink::build(monitor, vdesk, raw).expect("valid test geometry");
        (sink, state)
    }

    fn batches(state: &Arc<Mutex<RecorderState>>) -> Vec<Vec<Recorded>> {
        state.lock().expect("recorder lock").batches.clone()
    }

    fn single() -> (MonitorRect, VirtualDesktop) {
        // The common case: one monitor == the whole virtual desktop.
        (
            MonitorRect::new(0, 0, 1920, 1080).unwrap(),
            VirtualDesktop::new(0, 0, 1920, 1080),
        )
    }

    // Wire-event shorthands (payload-bearing; never formatted).
    fn key(seq: u64, scan: u16, extended: bool, state: ButtonState) -> InputEvent {
        InputEvent::Key {
            seq,
            scan_code: scan,
            extended,
            state,
        }
    }
    fn button(seq: u64, button: MouseButton, state: ButtonState) -> InputEvent {
        InputEvent::MouseButton { seq, button, state }
    }
    fn move_to(seq: u64, x: u16, y: u16) -> InputEvent {
        InputEvent::MouseMove { seq, x, y }
    }
    fn wheel(seq: u64, delta_v: i32, delta_h: i32) -> InputEvent {
        InputEvent::Wheel {
            seq,
            delta_v,
            delta_h,
        }
    }

    /// The OS-side decode of a VIRTUALDESK absolute coordinate (the exact
    /// formula the adapter's encode inverts).
    fn virtual_absolute_to_px(absolute: i32, extent: i32) -> i64 {
        ((i64::from(absolute) + 1) * i64::from(extent)) >> 16
    }

    #[test]
    fn mouse_move_maps_wire_space_onto_virtual_desktop() {
        // Left monitor of a two-monitor desktop: the wire's monitor-normal
        // space must land inside that monitor's slice of the virtual one.
        let monitor = MonitorRect::new(-1920, 0, 1920, 1080).unwrap();
        let vdesk = VirtualDesktop::new(-1920, 0, 3840, 2160);
        let (mut sink, state) = recorder_sink(monitor, vdesk);

        sink.inject(&move_to(1, 0, 0)).unwrap();
        sink.inject(&move_to(2, 65_535, 65_535)).unwrap();
        sink.inject(&move_to(3, 32_767, 32_767)).unwrap();

        let batches = batches(&state);
        assert_eq!(batches.len(), 3, "one SendInput per move");
        for (i, wire) in [(0u16, 0u16), (65_535, 65_535), (32_767, 32_767)]
            .into_iter()
            .enumerate()
        {
            let Recorded::Move { dx, dy } = &batches[i][0] else {
                panic!("expected a move event");
            };
            let expect_x = normalized_to_px(wire.0, monitor.width as u32);
            let expect_y = normalized_to_px(wire.1, monitor.height as u32);
            assert_eq!(
                virtual_absolute_to_px(*dx, vdesk.width),
                i64::from(expect_x),
                "x decode mismatch for wire {wire:?}"
            );
            assert_eq!(
                virtual_absolute_to_px(*dy, vdesk.height),
                i64::from(expect_y),
                "y decode mismatch for wire {wire:?}"
            );
        }
        // Corners pin exactly: monitor origin and last pixel.
        let Recorded::Move { dx, dy } = &batches[0][0] else {
            panic!("expected a move event");
        };
        assert_eq!((*dx, *dy), (0, 0));
    }

    #[test]
    fn single_monitor_mapping_is_pixel_exact_round_trip() {
        let (monitor, vdesk) = single();
        let (mut sink, state) = recorder_sink(monitor, vdesk);
        for wire in [0u16, 1, 100, 4_000, 32_767, 60_000, 65_535] {
            sink.inject(&move_to(u64::from(wire), wire, (65_535 - wire) % 4096))
                .unwrap();
        }
        for (i, batch) in batches(&state).iter().enumerate() {
            let Recorded::Move { dx, dy } = &batch[0] else {
                panic!("expected a move event");
            };
            let wire_x = [0u16, 1, 100, 4_000, 32_767, 60_000, 65_535][i];
            let wire_y = (65_535 - wire_x) % 4096;
            assert_eq!(
                virtual_absolute_to_px(*dx, vdesk.width),
                i64::from(normalized_to_px(wire_x, monitor.width as u32))
            );
            assert_eq!(
                virtual_absolute_to_px(*dy, vdesk.height),
                i64::from(normalized_to_px(wire_y, monitor.height as u32))
            );
        }
    }

    #[test]
    fn button_press_and_release_flags_and_tracking() {
        let (monitor, vdesk) = single();
        let (mut sink, state) = recorder_sink(monitor, vdesk);

        for (i, mouse_button) in BUTTON_ORDER.iter().enumerate() {
            sink.inject(&button(
                u64::try_from(i).unwrap(),
                *mouse_button,
                ButtonState::Pressed,
            ))
            .unwrap();
        }
        assert_eq!(sink.held_count(), 5);

        // Duplicate press: dropped, not re-injected.
        sink.inject(&button(99, MouseButton::Left, ButtonState::Pressed))
            .unwrap();
        assert_eq!(sink.held_count(), 5);

        sink.inject(&button(100, MouseButton::X2, ButtonState::Released))
            .unwrap();
        assert_eq!(sink.held_count(), 4);
        // Release of an unheld button: dropped.
        sink.inject(&button(101, MouseButton::X2, ButtonState::Released))
            .unwrap();
        assert_eq!(sink.held_count(), 4);

        let batches = batches(&state);
        assert_eq!(
            batches.len(),
            6,
            "5 presses + 1 release; duplicates dropped"
        );
        assert_eq!(
            batches[0],
            vec![Recorded::Button {
                button: MouseButton::Left,
                down: true
            }]
        );
        assert_eq!(
            batches[3],
            vec![Recorded::Button {
                button: MouseButton::X1,
                down: true
            }]
        );
        assert_eq!(
            batches[5],
            vec![Recorded::Button {
                button: MouseButton::X2,
                down: false
            }]
        );
    }

    #[test]
    fn key_events_carry_scan_codes_and_extended_flag() {
        let (monitor, vdesk) = single();
        let (mut sink, state) = recorder_sink(monitor, vdesk);

        // Plain Ctrl and right Ctrl share scan code 0x1D but differ in
        // `extended`: both may be held simultaneously.
        sink.inject(&key(1, SCAN_CTRL, false, ButtonState::Pressed))
            .unwrap();
        sink.inject(&key(2, SCAN_CTRL, true, ButtonState::Pressed))
            .unwrap();
        sink.inject(&key(3, SCAN_F13, false, ButtonState::Pressed))
            .unwrap();
        assert_eq!(sink.held_count(), 3);
        // Duplicate press of plain Ctrl: dropped.
        sink.inject(&key(4, SCAN_CTRL, false, ButtonState::Pressed))
            .unwrap();
        assert_eq!(sink.held_count(), 3);

        sink.inject(&key(5, SCAN_CTRL, true, ButtonState::Released))
            .unwrap();
        assert_eq!(sink.held_count(), 2);
        // Release of an unheld key: dropped.
        sink.inject(&key(6, SCAN_CTRL, true, ButtonState::Released))
            .unwrap();
        assert_eq!(sink.held_count(), 2);

        let batches = batches(&state);
        assert_eq!(
            batches[0],
            vec![Recorded::Key {
                scan: SCAN_CTRL,
                extended: false,
                up: false
            }]
        );
        assert_eq!(
            batches[1],
            vec![Recorded::Key {
                scan: SCAN_CTRL,
                extended: true,
                up: false
            }]
        );
        assert_eq!(
            batches[3],
            vec![Recorded::Key {
                scan: SCAN_CTRL,
                extended: true,
                up: true
            }]
        );
        assert_eq!(
            batches.len(),
            4,
            "3 presses + 1 release; duplicates dropped"
        );
    }

    #[test]
    fn wheel_emits_one_event_per_nonzero_axis() {
        let (monitor, vdesk) = single();
        let (mut sink, state) = recorder_sink(monitor, vdesk);

        sink.inject(&wheel(1, -120, 0)).unwrap();
        sink.inject(&wheel(2, 0, 40)).unwrap();
        sink.inject(&wheel(3, -120, 40)).unwrap();
        sink.inject(&wheel(4, 0, 0)).unwrap(); // no-op

        let batches = batches(&state);
        assert_eq!(batches.len(), 3, "(0,0) wheel injects nothing");
        assert_eq!(
            batches[0],
            vec![Recorded::Wheel {
                delta: -120,
                horizontal: false
            }]
        );
        assert_eq!(
            batches[1],
            vec![Recorded::Wheel {
                delta: 40,
                horizontal: true
            }]
        );
        assert_eq!(
            batches[2],
            vec![
                Recorded::Wheel {
                    delta: -120,
                    horizontal: false
                },
                Recorded::Wheel {
                    delta: 40,
                    horizontal: true
                },
            ],
            "both axes in one SendInput batch"
        );
        assert_eq!(sink.held_count(), 0, "wheel is not tracked");
    }

    #[test]
    fn text_events_expand_to_unicode_downs_with_surrogate_pairs() {
        let (monitor, vdesk) = single();
        let (mut sink, state) = recorder_sink(monitor, vdesk);

        sink.inject(&InputEvent::Text {
            seq: 1,
            code_points: "a\u{1F600}b".to_owned(), // BMP + astral (surrogate pair) + BMP
        })
        .unwrap();
        sink.inject(&InputEvent::Text {
            seq: 2,
            code_points: String::new(),
        })
        .unwrap();

        let batches = batches(&state);
        assert_eq!(batches.len(), 1, "empty text injects nothing");
        assert_eq!(
            batches[0],
            vec![
                Recorded::Unicode { unit: 0x0061 }, // 'a'
                Recorded::Unicode { unit: 0xD83D }, // high surrogate
                Recorded::Unicode { unit: 0xDE00 }, // low surrogate
                Recorded::Unicode { unit: 0x0062 }, // 'b'
            ],
            "surrogate pairs emitted in order, down events only"
        );
        assert_eq!(sink.held_count(), 0, "unicode text is not tracked");
    }

    #[test]
    fn oversize_text_events_are_rejected_before_injection() {
        let (monitor, vdesk) = single();
        let (mut sink, state) = recorder_sink(monitor, vdesk);

        let big = "x".repeat(MAX_TEXT_UTF16_UNITS + 1);
        let result = sink.inject(&InputEvent::Text {
            seq: 1,
            code_points: big,
        });
        assert!(matches!(result, Err(InputError::Other(_))));
        assert!(batches(&state).is_empty(), "nothing reached SendInput");
    }

    #[test]
    fn release_all_frees_every_held_button_and_key_in_one_batch() {
        let (monitor, vdesk) = single();
        let (mut sink, state) = recorder_sink(monitor, vdesk);

        sink.inject(&button(1, MouseButton::Left, ButtonState::Pressed))
            .unwrap();
        sink.inject(&button(2, MouseButton::X2, ButtonState::Pressed))
            .unwrap();
        sink.inject(&key(3, SCAN_CTRL, false, ButtonState::Pressed))
            .unwrap();
        sink.inject(&key(4, SCAN_CTRL, true, ButtonState::Pressed))
            .unwrap();
        sink.inject(&key(5, SCAN_F13, false, ButtonState::Pressed))
            .unwrap();
        assert_eq!(sink.held_count(), 5);

        let outcome = InputSink::release_all(&mut sink, AllKeysUpTrigger::FocusLost);
        assert_eq!(
            outcome.released,
            ReleasedInput {
                buttons: 2,
                keys: 3
            }
        );
        assert_eq!(outcome.trigger, AllKeysUpTrigger::FocusLost);
        assert!(outcome.error.is_none());
        assert_eq!(sink.held_count(), 0);

        // Idempotent: second call is a verified no-op.
        let again = InputSink::release_all(&mut sink, AllKeysUpTrigger::Disconnect);
        assert_eq!(again.released, ReleasedInput::default());
        assert!(again.error.is_none());

        let batches = batches(&state);
        assert_eq!(batches.len(), 6, "5 holds + exactly one release batch");
        assert_eq!(
            batches[5],
            vec![
                Recorded::Button {
                    button: MouseButton::Left,
                    down: false
                },
                Recorded::Button {
                    button: MouseButton::X2,
                    down: false
                },
                Recorded::Key {
                    scan: SCAN_CTRL,
                    extended: false,
                    up: true
                },
                Recorded::Key {
                    scan: SCAN_CTRL,
                    extended: true,
                    up: true
                },
                Recorded::Key {
                    scan: SCAN_F13,
                    extended: false,
                    up: true
                },
            ]
        );
    }

    #[test]
    fn release_paths_survive_injection_failure_and_retry() {
        let (monitor, vdesk) = single();
        let (mut sink, state) = recorder_sink(monitor, vdesk);

        sink.inject(&button(1, MouseButton::Left, ButtonState::Pressed))
            .unwrap();
        sink.inject(&key(2, SCAN_CTRL, false, ButtonState::Pressed))
            .unwrap();

        // Every release attempt fails like UIPI would.
        state.lock().expect("recorder lock").fail_with = Some(RawResult {
            injected: 0,
            last_error: Some(ERROR_ACCESS_DENIED.0),
        });

        // The M0 trait method must not error the safety path...
        assert!(InputSink::all_keys_up(&mut sink).is_ok());
        // ...but the failure is visible on the typed path, and the inputs
        // stay tracked so a retry can still free them.
        let outcome = InputSink::release_all(&mut sink, AllKeysUpTrigger::SequenceGap);
        assert_eq!(
            outcome.released,
            ReleasedInput {
                buttons: 1,
                keys: 1
            }
        );
        assert_eq!(outcome.error, Some(InputError::BlockedByUipi));
        assert_eq!(sink.held_count(), 2, "failed releases stay tracked");

        // Retry once injection works again.
        state.lock().expect("recorder lock").fail_with = None;
        let outcome = InputSink::release_all(&mut sink, AllKeysUpTrigger::Disconnect);
        assert_eq!(
            outcome.released,
            ReleasedInput {
                buttons: 1,
                keys: 1
            }
        );
        assert!(outcome.error.is_none());
        assert_eq!(sink.held_count(), 0);
    }

    #[test]
    fn wire_all_keys_up_triggers_release_and_never_errors() {
        let (monitor, vdesk) = single();
        let (mut sink, state) = recorder_sink(monitor, vdesk);

        sink.inject(&key(1, SCAN_F13, false, ButtonState::Pressed))
            .unwrap();
        for trigger in [
            AllKeysUpTrigger::FocusLost,
            AllKeysUpTrigger::SequenceGap,
            AllKeysUpTrigger::Disconnect,
        ] {
            sink.inject(&key(10, SCAN_F14, false, ButtonState::Pressed))
                .unwrap();
            sink.inject(&InputEvent::AllKeysUp { trigger }).unwrap();
            assert_eq!(sink.held_count(), 0, "trigger {trigger:?} must release");
        }

        // Even with injection failing, the wire safety event returns Ok.
        state.lock().expect("recorder lock").fail_with = Some(RawResult {
            injected: 0,
            last_error: Some(ERROR_ACCESS_DENIED.0),
        });
        // The press itself fails typed (UIPI) but stays tracked (failure
        // bias) — so the later safety release still addresses it.
        assert_eq!(
            sink.inject(&key(20, SCAN_F15, false, ButtonState::Pressed)),
            Err(InputError::BlockedByUipi)
        );
        assert_eq!(sink.held_count(), 1);
        sink.inject(&InputEvent::AllKeysUp {
            trigger: AllKeysUpTrigger::FocusLost,
        })
        .expect("safety path never errors");
    }

    #[test]
    fn uipi_blocks_are_typed_while_other_short_counts_are_generic() {
        let (monitor, vdesk) = single();
        let (mut sink, state) = recorder_sink(monitor, vdesk);

        state.lock().expect("recorder lock").fail_with = Some(RawResult {
            injected: 0,
            last_error: Some(ERROR_ACCESS_DENIED.0),
        });
        let err = sink
            .inject(&key(1, SCAN_F13, false, ButtonState::Pressed))
            .unwrap_err();
        assert_eq!(err, InputError::BlockedByUipi);
        // Press failed but stays tracked (failure bias).
        assert_eq!(sink.held_count(), 1);

        state.lock().expect("recorder lock").fail_with = Some(RawResult {
            injected: 0,
            last_error: None,
        });
        let err = sink.inject(&move_to(2, 1, 1)).unwrap_err();
        assert_eq!(
            err,
            InputError::Injection {
                injected: 0,
                requested: 1,
                last_error: None,
            }
        );
    }

    #[test]
    fn monitor_rects_are_validated_and_confined() {
        assert_eq!(
            MonitorRect::new(0, 0, 0, 1080),
            Err(InputError::InvalidMonitorRect {
                width: 0,
                height: 1080
            })
        );
        assert_eq!(
            MonitorRect::new(0, 0, 1920, -1),
            Err(InputError::InvalidMonitorRect {
                width: 1920,
                height: -1
            })
        );

        // A rect entirely outside the virtual desktop is a typed error.
        // (`SendInputSink` carries a closure seam, so no `Debug`; match by
        // hand instead of `unwrap_err`.)
        let vdesk = VirtualDesktop::new(0, 0, 1920, 1080);
        let built = SendInputSink::build(
            MonitorRect::new(5000, 5000, 1920, 1080).unwrap(),
            vdesk,
            Box::new(|_inputs: &[INPUT]| RawResult {
                injected: 1,
                last_error: None,
            }),
        );
        assert_eq!(
            built.err(),
            Some(InputError::MonitorOutsideDesktop {
                left: 5000,
                top: 5000
            })
        );

        // A partially overlapping rect is clamped to the intersection and
        // moves stay inside the desktop.
        let (mut sink, state) = recorder_sink(
            MonitorRect::new(-960, 0, 2880, 1080).unwrap(),
            VirtualDesktop::new(-1920, 0, 3840, 1080),
        );
        sink.inject(&move_to(1, 0, 0)).unwrap();
        sink.inject(&move_to(2, 65_535, 65_535)).unwrap();
        for batch in batches(&state) {
            let Recorded::Move { dx, dy } = &batch[0] else {
                panic!("expected a move event");
            };
            // Decode is vdesk-relative: must land inside the desktop, and
            // inside the clamped monitor slice [-960, 1920) for x.
            let px_x = virtual_absolute_to_px(*dx, 3840);
            let px_y = virtual_absolute_to_px(*dy, 1080);
            assert!(
                (960..3840).contains(&px_x),
                "clamped monitor produced x {px_x}"
            );
            assert!(
                (0..1080).contains(&px_y),
                "clamped monitor produced y {px_y}"
            );
            assert!((*dx >= 0) && (*dy >= 0) && (*dx <= 65_535) && (*dy <= 65_535));
        }

        // set_monitor_rect on a now-disjoint selection: typed failure, state
        // (and confine target) unchanged. Uses the pure retarget core so
        // the assertion does not depend on this machine's real desktop.
        assert!(
            sink.retarget(
                MonitorRect::new(9000, 9000, 800, 600).unwrap(),
                VirtualDesktop::new(-1920, 0, 3840, 1080),
            )
            .is_err()
        );
        sink.inject(&key(3, SCAN_F13, false, ButtonState::Pressed))
            .unwrap();
        assert_eq!(sink.held_count(), 1);
    }

    /// Real-`SendInput` smoke test. Injects ONLY harmless events: F13–F15
    /// scan codes (no default Windows binding, no modifiers, nothing
    /// printable) and a zero-delta wheel tick (scrolls nothing). No mouse
    /// moves, no buttons, no text, no modifiers — never.
    ///
    /// If the environment blocks injection (locked console, secure desktop,
    /// or an elevated foreground window — the documented UIPI limit), the
    /// typed-failure path is verified instead and the test skips with a
    /// message; re-run on an unlocked interactive desktop to exercise the
    /// success assertions.
    #[test]
    #[ignore = "injects real (harmless) input: F13-F15 scan codes and a zero-delta wheel tick; run manually on an interactive desktop"]
    fn real_sendinput_harmless_events_succeed_and_track() {
        let mut sink = SendInputSink::new(MonitorRect::primary().expect("primary monitor metrics"))
            .expect("virtual desktop metrics");

        // Probe with the first harmless event.
        let probe = sink.inject(&key(1, SCAN_F13, false, ButtonState::Pressed));
        if let Err(InputError::BlockedByUipi) = probe {
            // Failure-biased tracking: the press is still held even though
            // the OS refused it, so the safety path can address it.
            assert_eq!(sink.held_count(), 1);
            sink.inject(&InputEvent::AllKeysUp {
                trigger: AllKeysUpTrigger::Disconnect,
            })
            .expect("safety path never errors even when blocked");
            assert_eq!(
                sink.held_count(),
                1,
                "failed releases stay tracked for retry"
            );
            eprintln!(
                "SKIP success-path assertions: SendInput is blocked in this environment \
                 (locked console / secure desktop / elevated foreground, i.e. the \
                 documented UIPI limit). Re-run on an unlocked interactive desktop."
            );
            return;
        }
        probe.expect("F13 press injects");
        assert_eq!(sink.held_count(), 1);
        sink.inject(&key(2, SCAN_F13, false, ButtonState::Released))
            .expect("F13 release injects");
        assert_eq!(sink.held_count(), 0);

        // F14 held, freed by the controller-side focus-loss safety event.
        sink.inject(&key(3, SCAN_F14, false, ButtonState::Pressed))
            .expect("F14 press injects");
        assert_eq!(sink.held_count(), 1);
        sink.inject(&InputEvent::AllKeysUp {
            trigger: AllKeysUpTrigger::FocusLost,
        })
        .expect("safety path never errors");
        assert_eq!(sink.held_count(), 0);

        // F15 held, freed by the host-side disconnect release.
        sink.inject(&key(4, SCAN_F15, false, ButtonState::Pressed))
            .expect("F15 press injects");
        let outcome = InputSink::release_all(&mut sink, AllKeysUpTrigger::Disconnect);
        assert_eq!(outcome.released.keys, 1, "F15 should have been released");
        assert!(
            outcome.error.is_none(),
            "release failed: {:?}",
            outcome.error
        );
        assert_eq!(sink.held_count(), 0);

        // Zero-delta wheel tick: exercises the wheel path through the real
        // SendInput without scrolling the user's foreground window (a
        // nonzero delta would).
        let tick = mouse_input(0, 0, 0, MOUSEEVENTF_WHEEL);
        let result = real_send_input(&[tick]);
        assert_eq!(
            result.injected, 1,
            "SendInput wheel tick blocked (last error {:?})",
            result.last_error
        );
    }
}
