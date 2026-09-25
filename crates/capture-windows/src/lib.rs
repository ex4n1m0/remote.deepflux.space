//! # `capture-windows` — DXGI Desktop Duplication capture (M1, RD-004)
//!
//! Platform boundary for desktop acquisition (invariant 7). Everything
//! Windows/DXGI-specific stays inside this crate; the session and transport
//! layers know only the [`CaptureSource`] trait.
//!
//! ## What M1 implements
//!
//! * Monitor enumeration over DXGI (`monitors()` returns the
//!   `\\\\.\\DISPLAYn` device names that also key
//!   `protocol::capabilities::MonitorInfo::monitor_id`).
//! * `IDXGIOutputDuplication` acquisition of one monitor, copying each
//!   acquired desktop surface into a small ring of pool textures
//!   ([`frame_surface::FrameSurface`]) so the duplication surface can be
//!   released immediately (the API requires `ReleaseFrame` before the next
//!   `AcquireNextFrame` — this GPU->GPU copy is the one unavoidable copy on
//!   the capture path and is reported as such).
//! * Dirty-rect / move-rect metadata per frame (used to skip redundant
//!   work; surfaced on [`CaptureMetadata`]).
//! * Cursor extraction: position (normalized 0..=65535 over the captured
//!   output, matching `CursorMessage::Position`) and shape, converted into
//!   the exact `protocol::wire::CursorMessage` formats the `cursor` data
//!   channel will carry in M2.
//! * Typed failure handling for the documented DXGI limits:
//!   [`CaptureError::AccessLost`] (mode change / fullscreen transition —
//!   re-duplicate via [`DxgiCapture::reinit`]),
//!   [`CaptureError::DeviceLost`] (adapter removed — recreate the device),
//!   [`CaptureError::AccessDenied`] (lock screen / protected content —
//!   known-unsupported MVP, retry with backoff),
//!   [`CaptureError::DisplayChanged`] (output no longer exists —
//!   re-enumerate). Fullscreen-exclusive apps, protected content and the
//!   secure desktop are documented-unsupported in the MVP (risk register).
//!
//! ## M0 -> M1 trait deltas (documented, minimal)
//!
//! * `next_frame` now takes a timeout and returns
//!   `Result<Option<CapturedFrame>, _>`: `None` means "no update within
//!   `timeout`". The M0 sketch said "blocks up to one frame interval";
//!   an explicit timeout is required so a static desktop does not block
//!   shutdown and so `--fps-cap` can pace the loop. Everything else the
//!   M0 trait promised (newest-frame-wins, at most one outstanding frame)
//!   is unchanged.
//! * `CapturedFrame` carries the GPU surface
//!   (`frame_surface::FrameSurface`) plus the host-assigned `frame_id`
//!   that joins diagnostics records (perf-counter schema).
//! * `monitors()` now returns [`MonitorInfo`] (id + geometry) so callers
//!   can pick a monitor without a second API; selection still happens at
//!   construction (`DxgiCapture::new`) — capture of one output cannot be
//!   re-targeted without re-duplication.

use std::time::Duration;

use diagnostics::PerfSink;
pub use frame_surface::FrameSurface;
use protocol::wire::CursorMessage;

mod cursor;
mod dupl;
pub mod recovery;

pub use cursor::{monochrome_pitch, shape_to_cursor_message};
// CR-3 (M4 QA): display enumeration is exported so `apps/desktop` (and
// any future runtime) stops re-implementing raw Win32 monitor walks —
// one source of truth for monitor identity (the DXGI device names that
// `SelectMonitor` consumes). The app can switch in a follow-up.
pub use dupl::{DxgiCapture, MonitorInfo, enumerate_monitors};
pub use recovery::{REINIT_BACKOFF_BASE, REINIT_BUDGET, REINIT_MAX_ATTEMPTS, RecoveryDecision};

/// Stable identifier matching `protocol::capabilities::MonitorInfo::monitor_id`
/// (the DXGI device name, e.g. `\\.\DISPLAY5`).
pub type MonitorId = String;

/// One dirty rectangle (desktop coordinates of the captured output).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirtyRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// One move region: `source` is the pre-move offset within the frame,
/// `destination` is where it now is (DXGI `MOVE_RECT` semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveRect {
    pub source_x: i32,
    pub source_y: i32,
    pub destination: DirtyRect,
}

/// Dirty/move metadata plus cursor state for one acquired frame.
///
/// Dirty rects and move rects let downstream stages skip redundant work
/// (e.g. not re-encoding unchanged frames when the only update was a
/// cursor move — see `only_cursor_update`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureMetadata {
    pub dirty_rects: Vec<DirtyRect>,
    pub move_rects: Vec<MoveRect>,
    /// DXGI `AccumulatedFrames`: updates accumulated since the previous
    /// acquire (>=1 on real updates; >1 means we coalesced updates).
    pub accumulated_frames: u32,
    /// True when this frame carries only a cursor update — the desktop
    /// pixels are unchanged, so the surface is the previous frame's
    /// texture and encoding it again would be redundant work.
    pub only_cursor_update: bool,
}

/// One acquired desktop frame. The pixels stay on the GPU in `surface`;
/// bytes exist only inside the platform crates (invariant 1).
///
/// Note on cursor-only updates (`metadata.only_cursor_update`): they
/// carry the *previous* pixel frame's surface and `frame_id` unchanged —
/// consumers must not emit a new `FrameTiming` record for them (the
/// schema joins on `frame_id`; a second record with the same id smears
/// the latency join). The M1 loop skips them for encode entirely.
#[derive(Debug)]
pub struct CapturedFrame {
    /// Host-assigned frame id (perf-counter schema join key; starts at 1
    /// and increments per pixel-update frame).
    pub frame_id: u64,
    /// Monotonic timestamp (ns on the capture thread's session clock,
    /// zero-based at session start) — feeds `FrameTiming::capture_ns`.
    pub timestamp_ns: u64,
    pub width_px: u32,
    pub height_px: u32,
    pub surface: FrameSurface,
    pub metadata: CaptureMetadata,
    /// Cursor delta for this frame, if any (position moves, shape changes
    /// or hide). Exactly the `CursorMessage` wire vocabulary.
    pub cursor: Option<CursorMessage>,
}

/// Typed capture failure. Each variant names the recovery the caller must
/// perform — this is the "failure handling reviewed" part of the standing
/// contract for unsafe/Win32 code.
#[derive(Debug, Clone)]
pub enum CaptureError {
    /// DXGI_ERROR_ACCESS_LOST — the duplication is invalid (mode change,
    /// fullscreen transition, desktop switch). Recoverable by
    /// re-duplicating the same output ([`DxgiCapture::reinit`]).
    AccessLost(String),
    /// D3D device removed/reset — recreate the device and everything on
    /// it (duplication, codec, swapchain).
    DeviceLost(String),
    /// E_ACCESSDENIED — protected content or the secure desktop (lock
    /// screen, UAC prompt). Known-unsupported in MVP; callers should stop
    /// and retry with backoff, not spin.
    AccessDenied(String),
    /// The output this source duplicated no longer exists
    /// (DXGI_ERROR_NOT_FOUND / NOT_CURRENTLY_AVAILABLE on re-duplicate).
    /// Re-enumerate (`monitors()`) and pick again.
    DisplayChanged(String),
    /// Too many duplication objects exist on the output already.
    Exhausted(String),
    /// Programming/contract error (bad monitor id, wrong state).
    Invalid(String),
    /// Irrecoverable capture death (M6 soak F71): the source exhausted its
    /// bounded reinit budget (or hit a non-retryable failure such as device
    /// removal) and entered a terminal state. Every subsequent
    /// [`CaptureSource::next_frame`] / [`DxgiCapture::reinit`] returns this
    /// variant again. Callers MUST treat it as session-ending — a stream
    /// that ignores it is a frozen session (the F71 soak signature).
    Dead(String),
    /// Anything else; `hr` is the failing HRESULT.
    Api {
        op: &'static str,
        hr: i32,
        detail: String,
    },
}

impl CaptureError {
    pub fn api(op: &'static str, hr: i32, detail: impl Into<String>) -> Self {
        CaptureError::Api {
            op,
            hr,
            detail: detail.into(),
        }
    }

    /// F71: true when this failure is terminal for the capture (and thus
    /// for the streaming session it feeds). `Dead` and `DeviceLost` have no
    /// in-place recovery; every other variant has a documented retry or
    /// re-enumeration path.
    pub fn is_fatal(&self) -> bool {
        matches!(self, CaptureError::Dead(_) | CaptureError::DeviceLost(_))
    }
}

impl core::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CaptureError::AccessLost(d) => write!(f, "duplication access lost (reinit): {d}"),
            CaptureError::DeviceLost(d) => write!(f, "device lost (recreate device): {d}"),
            CaptureError::AccessDenied(d) => {
                write!(f, "access denied (lock screen/protected content): {d}")
            }
            CaptureError::DisplayChanged(d) => write!(f, "display changed (re-enumerate): {d}"),
            CaptureError::Exhausted(d) => write!(f, "duplication limit reached: {d}"),
            CaptureError::Invalid(d) => write!(f, "invalid capture state: {d}"),
            CaptureError::Dead(d) => write!(f, "capture dead (end the session): {d}"),
            CaptureError::Api { op, hr, detail } => {
                write!(f, "{op} failed: hr=0x{hr:08X} {detail}")
            }
        }
    }
}

impl std::error::Error for CaptureError {}

/// Narrow platform boundary: one monitor's desktop as a stream of frames.
///
/// Backpressure rule (invariant 3): `next_frame` never buffers more than
/// one outstanding frame; if the consumer is behind, `AcquireNextFrame`
/// coalesces updates and the newest desktop state is returned —
/// intermediates are dropped by the OS, never queued by us.
pub trait CaptureSource: Send {
    /// Monitors this source's device can duplicate, primary first.
    fn monitors(&mut self) -> Result<Vec<MonitorInfo>, CaptureError>;

    /// Acquire the next frame. Blocks up to `timeout`; `None` means no
    /// desktop update arrived in that window (static desktop or
    /// cursor-only frame consumed internally). On success returns the
    /// *newest* desktop state.
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<CapturedFrame>, CaptureError>;

    /// Where per-frame counter records go. The capture stage itself
    /// emits no `FrameTiming` records (the host half is emitted by the
    /// transport-send stage per the schema's pinned emission timing), so
    /// the default drops them.
    fn set_perf_sink(&mut self, _sink: Box<dyn PerfSink>) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_names_the_recovery() {
        let e = CaptureError::AccessLost("mode change".into());
        assert!(e.to_string().contains("reinit"));
        let e = CaptureError::AccessDenied("secure desktop".into());
        assert!(e.to_string().contains("lock screen"));
    }
}
