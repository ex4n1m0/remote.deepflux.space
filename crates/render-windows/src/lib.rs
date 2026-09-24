//! # `render-windows` — native GPU presentation (M1/M2, delta D4)
//!
//! Platform boundary for presenting decoded frames (invariant 7). The MVP
//! renderer is a minimal D3D11 swapchain presentation (delta D4):
//! `wgpu`/advanced GPU composition is deliberately deferred to Milestone 6.
//!
//! Hard rule (invariant 1): decoded frames go GPU-texture → swapchain. They
//! never enter Tauri IPC, React state, JSON, or a 2D canvas. This crate is
//! the *only* place the controller's frame path touches a window.

use diagnostics::PerfSink;

/// M0 placeholder for the presentable frame handoff; M1 pairs this with the
/// decoder's output texture (see ADR-001 open questions for the handoff type
/// decision).
#[derive(Debug)]
pub struct RenderFrame {
    pub timestamp_ns: u64,
    pub width_px: u32,
    pub height_px: u32,
    /// Opaque M1: shared GPU texture handle from the decoder.
    pub opaque: (),
}

/// Cursor compositor input, mirroring `protocol::wire::CursorMessage`.
/// Composited on the GPU over the video texture — never on the CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorOverlay {
    pub x_norm: u16,
    pub y_norm: u16,
    pub shape_id: u32,
}

#[derive(Debug)]
pub struct RenderError(pub String);

impl core::fmt::Display for RenderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "render failed: {}", self.0)
    }
}

impl std::error::Error for RenderError {}

/// Scaling modes for the viewer (M4 exposes these in the UI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScaleMode {
    #[default]
    Fit,
    OneToOne,
}

/// Narrow platform boundary: the controller's presentation surface.
///
/// Backpressure rule (invariant 3): `present` shows the *newest* decoded
/// frame; queued stale frames are dropped, never displayed late.
pub trait FrameRenderer: Send {
    /// Present one frame. Returns after submission to the swapchain; the
    /// `present_ns` counter timestamp is recorded by the implementation.
    fn present(&mut self, frame: &RenderFrame) -> Result<(), RenderError>;

    /// Update the locally composited cursor overlay (latest-state; the
    /// `cursor` channel semantics).
    fn set_cursor(&mut self, overlay: Option<CursorOverlay>);

    fn set_scale_mode(&mut self, mode: ScaleMode);

    fn set_perf_sink(&mut self, _sink: Box<dyn PerfSink>) {}
}
