//! # `capture-windows` — DXGI Desktop Duplication capture (M1)
//!
//! Platform boundary for desktop acquisition (invariant 7). Everything
//! Windows/DXGI-specific stays inside this crate; the session and transport
//! layers know only the [`CaptureSource`] trait.
//!
//! M1 (RD-004) fills in: monitor enumeration, `IDXGIOutputDuplication`,
//! dirty-rect/move-rect metadata, separate cursor extraction, and
//! device-loss / display-change recovery on every path. The signature below
//! is the M0 sketch; M1 may extend it (e.g. richer metadata on
//! [`CaptureMetadata`]) but must keep it synchronous-allocation-free and must
//! never hand frame bytes to anything but the encoder handoff type.

use diagnostics::PerfSink;

/// Stable identifier matching `protocol::capabilities::MonitorInfo::monitor_id`.
pub type MonitorId = String;

/// Opaque handle to one acquired desktop frame. The payload stays on the GPU:
/// in M1 this will wrap the DXGI surface/texture handle plus dirty/move
/// metadata and extracted cursor info. Bytes exist only inside the crate.
#[derive(Debug)]
pub struct CapturedFrame {
    /// Monotonic capture timestamp (ns) — feeds
    /// `FrameTiming::capture_ns`.
    pub timestamp_ns: u64,
    pub width_px: u32,
    pub height_px: u32,
    /// Dirty regions + move rects + cursor metadata land here in M1.
    pub metadata: CaptureMetadata,
}

/// M1 fills this with dirty/move rectangles and cursor geometry. Kept
/// non-empty in M0 so the trait shape is honest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureMetadata {
    /// Number of dirty rects reported by DXGI for this frame.
    pub dirty_rect_count: u32,
    /// Number of move rects reported by DXGI for this frame.
    pub move_rect_count: u32,
}

#[derive(Debug)]
pub struct CaptureError(pub String);

impl core::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "capture failed: {}", self.0)
    }
}

impl std::error::Error for CaptureError {}

/// Narrow platform boundary: one monitor's desktop as a stream of frames.
///
/// Backpressure rule (invariant 3): `next_frame` never blocks the caller
/// longer than a frame interval and never buffers more than one outstanding
/// frame; if the consumer is behind, the previous frame is dropped, not
/// queued.
pub trait CaptureSource: Send {
    /// Monitors this source can duplicate. Fails on device loss; callers
    /// must re-enumerate on display-change events (M1).
    fn monitors(&mut self) -> Result<Vec<MonitorId>, CaptureError>;

    /// Acquire the next frame. Blocks up to one frame interval; returns the
    /// *newest* desktop state, dropping intermediates.
    fn next_frame(&mut self) -> Result<CapturedFrame, CaptureError>;

    /// Where per-frame counter records go (`capture_ns` timestamps). Wired in
    /// M1; the default drops them so trait impls stay minimal.
    fn set_perf_sink(&mut self, _sink: Box<dyn PerfSink>) {}
}
