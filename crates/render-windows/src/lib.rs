//! # `render-windows` — native GPU presentation (M1/M2, delta D4)
//!
//! Platform boundary for presenting decoded frames (invariant 7). The MVP
//! renderer is a minimal D3D11 swapchain presentation (delta D4):
//! `wgpu`/advanced GPU composition is deliberately deferred to Milestone 6.
//!
//! Hard rule (invariant 1): decoded frames go GPU-texture -> swapchain.
//! They never enter Tauri IPC, React state, JSON, or a 2D canvas. This
//! crate is the *only* place the controller's frame path touches a
//! window.
//!
//! M1 implementation notes:
//!
//! * [`PresenterWindow`] owns a plain Win32 window; the presenting thread
//!   must call [`frame_surface::attach_thread_to_input_desktop`] before
//!   creating it (agent/service spawn contexts start on a private desktop
//!   where windows are invisible — see frame-surface docs).
//! * [`D3D11Renderer`] draws with `ID3D11VideoProcessor`: NV12 (decoded)
//!   or BGRA (local preview) input -> backbuffer, with the same color
//!   space pairing as the encode-side converter (BT.709 studio <-> sRGB
//!   full). One GPU pass per present; no CPU pixels.
//! * Scaling: [`ScaleMode::Fit`] letterboxes into the client area;
//!   [`ScaleMode::OneToOne`] anchors 1:1 at the top-left (cropping as
//!   needed).
//! * `Present(0, 0)` — do not wait for vsync: the present timestamp
//!   records submission latency, not display refresh; a later milestone
//!   can make vsync a tunable.
//! * The window is created on the input desktop and the renderer draws
//!   the *newest* frame (invariant 3); stale frames are dropped by the
//!   decode->present queue, not displayed late.
//! * Device loss (`DXGI_ERROR_DEVICE_REMOVED/RESET`) is surfaced as the
//!   typed [`RenderError::DeviceLost`] for the runtime to rebuild on a
//!   fresh device.

use diagnostics::PerfSink;
pub use frame_surface::FrameSurface;
use frame_surface::GpuDevice;

mod rect;
mod renderer;
mod window;

pub use rect::{destination_rect, fit_rect};
pub use renderer::D3D11Renderer;
pub use window::{PresenterWindow, WindowConfig};

/// Presentable frame handoff; pairs with the decoder's output surface.
#[derive(Debug)]
pub struct RenderFrame {
    pub frame_id: u64,
    pub timestamp_ns: u64,
    /// Visible width/height (DXVA surfaces may be padded; see the decoder).
    pub width_px: u32,
    pub height_px: u32,
    pub surface: FrameSurface,
}

/// Cursor compositor input, mirroring `protocol::wire::CursorMessage`.
/// Composited on the GPU over the video texture — never on the CPU.
///
/// M1 status: stored, not yet drawn (delta D4 — GPU shape compositing is
/// M2/M4 polish; the `cursor` channel data path itself is exercised by
/// capture and the loop's counters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorOverlay {
    pub x_norm: u16,
    pub y_norm: u16,
    pub shape_id: u32,
}

#[derive(Debug)]
pub enum RenderError {
    /// D3D device removed — recreate device + swapchain.
    DeviceLost(String),
    /// Window/swapchain state broken (resize failed, occluded beyond
    /// recovery).
    Surface(String),
    Api {
        op: &'static str,
        hr: i32,
        detail: String,
    },
}

impl RenderError {
    pub fn api(op: &'static str, hr: i32, detail: impl Into<String>) -> Self {
        RenderError::Api {
            op,
            hr,
            detail: detail.into(),
        }
    }
}

impl core::fmt::Display for RenderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RenderError::DeviceLost(d) => write!(f, "render device lost: {d}"),
            RenderError::Surface(d) => write!(f, "render surface error: {d}"),
            RenderError::Api { op, hr, detail } => {
                write!(f, "{op} failed: hr=0x{hr:08X} {detail}")
            }
        }
    }
}

impl std::error::Error for RenderError {}

/// Scaling modes for the viewer (M4 exposes these in the UI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScaleMode {
    /// Letterbox-fit the frame into the client area.
    #[default]
    Fit,
    /// 1:1 pixels, top-left anchored, cropping as needed.
    OneToOne,
}

/// Narrow platform boundary: the controller's presentation surface.
///
/// Backpressure rule (invariant 3): `present` shows the *newest* decoded
/// frame; queued stale frames are dropped upstream, never displayed late.
///
/// M1 note on `present_ns`: the node runtime stamps
/// `FrameTiming::present_ns` from its own session clock immediately after
/// `present` returns (Present returned = submitted). The M0 docstring
/// said the implementation records it; the session clock lives in the
/// runtime, so the runtime stamps — documented deviation, same
/// measurement point.
pub trait FrameRenderer: Send {
    fn present(&mut self, frame: &RenderFrame) -> Result<(), RenderError>;

    /// Update the locally composited cursor overlay (latest-state; the
    /// `cursor` channel semantics).
    fn set_cursor(&mut self, overlay: Option<CursorOverlay>);

    fn set_scale_mode(&mut self, mode: ScaleMode);

    fn set_perf_sink(&mut self, _sink: Box<dyn PerfSink>) {}
}

/// Construct the renderer's shared device (same helper as capture/codec:
/// one device per process in M1).
pub fn create_render_device() -> Result<GpuDevice, RenderError> {
    GpuDevice::create_hardware().map_err(|e| RenderError::DeviceLost(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_letterboxes_without_distortion() {
        // 16:9 frame into an 8:5 window letterboxes (pillarbox would
        // distort; the frame is width-bound and centered vertically).
        let r = fit_rect(1920, 1080, 1600, 1000);
        assert_eq!(r, (0, 50, 1600, 900));
        // 4:3 frame into a wide window pillarboxes.
        let r = fit_rect(1024, 768, 1920, 1080);
        assert_eq!(r, ((1920 - 1440) / 2, 0, 1440, 1080));
        // Exact fit.
        let r = fit_rect(1920, 1080, 1920, 1080);
        assert_eq!(r, (0, 0, 1920, 1080));
    }

    #[test]
    fn one_to_one_anchors_top_left() {
        let r = fit_rect_one_to_one(2560, 1440, 1920, 1080);
        assert_eq!(r, (0, 0, 1920, 1080));
    }

    fn fit_rect_one_to_one(w: u32, h: u32, cw: u32, ch: u32) -> (i32, i32, u32, u32) {
        (0, 0, w.min(cw), h.min(ch))
    }
}
