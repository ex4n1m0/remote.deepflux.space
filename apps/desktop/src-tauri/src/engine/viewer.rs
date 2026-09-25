//! The native viewer window (controller side): the `render-windows`
//! presenter extended with input capture, scale/fullscreen control, and
//! the focus-loss safety hook.
//!
//! Window topology (M4): the shell is a Tauri webview window; the viewer is
//! a **separate native Win32 window** owned by the controller pipeline's
//! present thread. Decoded frames go GPU-surface → `D3D11Renderer` →
//! swapchain; no frame bytes ever reach Tauri IPC, React, or JSON
//! (invariant 1).
//!
//! Input capture subclasses the presenter window proc: keyboard/mouse
//! messages become wire-shaped input events (payload only; never logged —
//! invariant 6) in a bounded queue drained by the engine loop onto the
//! `input-fast` / `input-reliable` channels — the same wire path the M2
//! rig's scripted input used. `WM_KILLFOCUS` enqueues `AllKeysUp{
//! FocusLost}` (the M2 input package's documented M4 hook). `F11` toggles
//! borderless fullscreen locally and is never forwarded to the host.
//!
//! CR-2 (M5, landed): the subclass proc + focus-loss/dest-rect mapping
//! moved into `input-windows::capture` behind the narrow
//! [`input_windows::PresenterInput`] trait; the fullscreen window-style
//! unsafe moved into
//! [`PresenterWindow::toggle_borderless_fullscreen`]. This module composes
//! those behind the same `ViewerCtl` surface the engine always used — no
//! Win32 unsafe remains in `apps/desktop`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use input_windows::capture::WindowInputCapture;
use input_windows::{PresenterInput, ViewerInputEvent};
use protocol::wire::InputEvent;
use render_windows::{D3D11Renderer, FrameRenderer as _, PresenterWindow, RenderFrame, ScaleMode};
use windows::Win32::UI::WindowsAndMessaging::WINDOWPLACEMENT;

use frame_surface::GpuDevice;

/// Present-side control/state shared between the present thread (owner of
/// the window) and the engine loop. Input capture itself lives behind
/// [`PresenterInput`] (`input-windows::capture`).
pub struct ViewerCtl {
    /// Latest requested scale mode (applied by the present thread).
    scale: Mutex<ScaleMode>,
    /// The CR-2 capture: subclass proc + bounded input queue + focus +
    /// fullscreen-request + dest rect.
    input: Mutex<Option<Arc<WindowInputCapture>>>,
    /// Last known client size (present thread refreshes every pump).
    client: Mutex<(i32, i32)>,
    /// Current swapchain size (after F49 resize handling).
    swapchain: Mutex<(u32, u32)>,
    dropped_mirror: AtomicU64,
}

impl ViewerCtl {
    pub fn new(scale: ScaleMode) -> Self {
        Self {
            scale: Mutex::new(scale),
            input: Mutex::new(None),
            client: Mutex::new((1, 1)),
            swapchain: Mutex::new((1, 1)),
            dropped_mirror: AtomicU64::new(0),
        }
    }

    pub fn set_scale(&self, mode: ScaleMode) {
        *self.scale.lock().expect("viewer scale") = mode;
    }

    /// Attach the capture to a freshly created viewer window (present
    /// thread only, before any input can arrive).
    pub fn attach_input(&self, capture: Arc<WindowInputCapture>) {
        *self.input.lock().expect("viewer input") = Some(capture);
    }

    pub fn is_fullscreen(&self) -> bool {
        self.input
            .lock()
            .expect("viewer input")
            .as_ref()
            .is_some_and(|input| input.is_fullscreen())
    }

    pub fn is_focused(&self) -> bool {
        self.input
            .lock()
            .expect("viewer input")
            .as_ref()
            .is_some_and(|input| input.is_focused())
    }

    pub fn request_fullscreen_toggle(&self) {
        if let Some(input) = self.input.lock().expect("viewer input").as_ref() {
            input.request_fullscreen_toggle();
        }
    }

    pub fn dropped_count(&self) -> u64 {
        // Mirror at read time: the queue itself is inside the capture.
        self.input
            .lock()
            .expect("viewer input")
            .as_ref()
            .map(|input| input.dropped_count())
            .unwrap_or_else(|| self.dropped_mirror.load(Ordering::Relaxed))
    }

    /// Drain captured events (engine loop, then assigns seq and sends).
    pub fn drain_input(&self) -> Vec<ViewerInputEvent> {
        self.input
            .lock()
            .expect("viewer input")
            .as_ref()
            .map(|input| {
                let dropped = input.dropped_count();
                self.dropped_mirror.store(dropped, Ordering::Relaxed);
                input.drain_input()
            })
            .unwrap_or_default()
    }

    /// Destination rect input is normalized over (F48); set by the present
    /// thread after each present and after each resize.
    pub fn set_dest_rect(&self, rect: Option<(i32, i32, u32, u32)>) {
        if let Some(input) = self.input.lock().expect("viewer input").as_ref() {
            input.set_dest_rect(rect);
        }
    }

    /// Current swapchain size (F49: observable resize follow).
    pub fn set_swapchain(&self, size: (u32, u32)) {
        *self.swapchain.lock().expect("viewer swapchain") = size;
    }

    pub fn swapchain(&self) -> (u32, u32) {
        *self.swapchain.lock().expect("viewer swapchain")
    }

    pub fn client(&self) -> (i32, i32) {
        *self.client.lock().expect("viewer client")
    }
}

/// The native viewer: presenter window + renderer + the CR-2 input
/// capture. Thread-owned by the present thread (created, used, and dropped
/// there).
pub struct ViewerWindow {
    window: PresenterWindow,
    renderer: D3D11Renderer,
    capture: Arc<WindowInputCapture>,
    fullscreen: bool,
    saved_placement: Option<WINDOWPLACEMENT>,
    /// Size of the last presented frame (dest-rect recomputation on
    /// resize before the next frame arrives).
    last_frame: Option<(u32, u32)>,
}

impl ViewerWindow {
    /// Create the viewer on the calling (present) thread. The thread must
    /// be attached to the input desktop (`attach_thread_to_input_desktop`).
    pub fn create(
        device: &GpuDevice,
        title: &str,
        width: i32,
        height: i32,
        ctl: Arc<ViewerCtl>,
    ) -> Result<Self, String> {
        let window = PresenterWindow::create(&render_windows::WindowConfig {
            title: title.to_owned(),
            width,
            height,
        })
        .map_err(|e| format!("viewer window: {e}"))?;
        let renderer = D3D11Renderer::new(
            device.clone(),
            window.hwnd(),
            width.max(1) as u32,
            height.max(1) as u32,
        )
        .map_err(|e| format!("viewer renderer: {e}"))?;
        let capture = WindowInputCapture::attach(window.hwnd())
            .map_err(|e| format!("viewer input capture: {e}"))?;
        ctl.attach_input(Arc::clone(&capture));
        let viewer = Self {
            window,
            renderer,
            capture,
            fullscreen: false,
            saved_placement: None,
            last_frame: None,
        };
        viewer.sync_client(ctl.as_ref());
        viewer.ctl_set_swapchain(&ctl, (width.max(1) as u32, height.max(1) as u32));
        Ok(viewer)
    }

    fn sync_client(&self, ctl: &ViewerCtl) {
        *ctl.client.lock().expect("viewer client") = self.window.client_size();
    }

    fn ctl_set_swapchain(&self, ctl: &ViewerCtl, size: (u32, u32)) {
        ctl.set_swapchain(size);
    }

    pub fn hwnd(&self) -> windows::Win32::Foundation::HWND {
        self.window.hwnd()
    }

    /// Update the locally composited cursor overlay (cursor channel state).
    pub fn set_cursor(&mut self, overlay: Option<render_windows::CursorOverlay>) {
        self.renderer.set_cursor(overlay);
    }

    /// Pump messages, apply control (scale/fullscreen/resize), present one
    /// frame. Returns `false` when the window was closed — stop the
    /// pipeline.
    pub fn pump_and_present(&mut self, frame: Option<&RenderFrame>, ctl: &ViewerCtl) -> bool {
        if !self.window.pump() {
            return false;
        }
        self.sync_client(ctl);
        // Scale mode changes.
        {
            let mode = *ctl.scale.lock().expect("viewer scale");
            self.renderer.set_scale_mode(mode);
        }
        // Fullscreen toggles (F11 arrives through the capture's proc).
        if self.capture.take_fullscreen_toggle() {
            self.window
                .toggle_borderless_fullscreen(&mut self.fullscreen, &mut self.saved_placement);
            self.capture.set_fullscreen(self.fullscreen);
        }
        // Resize: the swapchain must follow the client or it goes stale
        // (F18 wiring, m2_rig parity; M4 QA F49 re-added).
        if self.window.take_resized() {
            let (w, h) = self.window.client_size();
            let (w, h) = (w.max(1) as u32, h.max(1) as u32);
            if self.renderer.resize(w, h).is_ok() {
                ctl.set_swapchain((w, h));
            }
            self.refresh_dest_rect(ctl);
        }
        if let Some(frame) = frame {
            // Publish the destination rect BEFORE presenting so pointer
            // input normalizes over exactly where the frame lands (F48);
            // `present` computes the same rect via the shared helper.
            let rect = self
                .renderer
                .destination_rect_for(frame.width_px, frame.height_px);
            ctl.set_dest_rect(Some(rect));
            self.last_frame = Some((frame.width_px, frame.height_px));
            if self.renderer.present(frame).is_err() {
                return false;
            }
        }
        true
    }

    /// Recompute the destination rect after a resize (before the next
    /// frame arrives the mapping must already use the new client size).
    fn refresh_dest_rect(&self, ctl: &ViewerCtl) {
        if let Some((fw, fh)) = self.last_frame {
            ctl.set_dest_rect(Some(self.renderer.destination_rect_for(fw, fh)));
        }
    }
}

/// Convert drained viewer events into wire input events with monotonic seq
/// (fast moves share one counter, reliable events another — per-channel
/// monotonic per the wire contract). Consecutive text code units coalesce
/// into one `Text` event (surrogate pairs must not be split).
pub fn to_wire_events(
    batch: &[ViewerInputEvent],
    fast_seq: &mut u64,
    reliable_seq: &mut u64,
) -> Vec<(transport_webrtc::Channel, InputEvent)> {
    use transport_webrtc::Channel;
    let mut out = Vec::with_capacity(batch.len());
    let mut text_buf: Vec<u16> = Vec::new();
    let flush_text = |out: &mut Vec<(Channel, InputEvent)>, buf: &mut Vec<u16>, seq: &mut u64| {
        if !buf.is_empty() {
            *seq += 1;
            // UTF-16 join: WM_CHAR delivers code units, and surrogate
            // pairs must survive as one character.
            let text = String::from_utf16_lossy(buf);
            out.push((
                Channel::InputReliable,
                InputEvent::Text {
                    seq: *seq,
                    code_points: text,
                },
            ));
            buf.clear();
        }
    };
    for event in batch {
        match event {
            ViewerInputEvent::Move { x, y } => {
                flush_text(&mut out, &mut text_buf, reliable_seq);
                *fast_seq += 1;
                out.push((
                    Channel::InputFast,
                    InputEvent::MouseMove {
                        seq: *fast_seq,
                        x: *x,
                        y: *y,
                    },
                ));
            }
            ViewerInputEvent::Button { button, state } => {
                flush_text(&mut out, &mut text_buf, reliable_seq);
                *reliable_seq += 1;
                out.push((
                    Channel::InputReliable,
                    InputEvent::MouseButton {
                        seq: *reliable_seq,
                        button: *button,
                        state: *state,
                    },
                ));
            }
            ViewerInputEvent::Wheel { delta_v, delta_h } => {
                flush_text(&mut out, &mut text_buf, reliable_seq);
                *reliable_seq += 1;
                out.push((
                    Channel::InputReliable,
                    InputEvent::Wheel {
                        seq: *reliable_seq,
                        delta_v: *delta_v,
                        delta_h: *delta_h,
                    },
                ));
            }
            ViewerInputEvent::Key {
                scan_code,
                extended,
                state,
            } => {
                flush_text(&mut out, &mut text_buf, reliable_seq);
                *reliable_seq += 1;
                out.push((
                    Channel::InputReliable,
                    InputEvent::Key {
                        seq: *reliable_seq,
                        scan_code: *scan_code,
                        extended: *extended,
                        state: *state,
                    },
                ));
            }
            ViewerInputEvent::Text { code_unit } => {
                text_buf.push(*code_unit);
            }
            ViewerInputEvent::AllKeysUp { trigger } => {
                flush_text(&mut out, &mut text_buf, reliable_seq);
                out.push((
                    Channel::InputReliable,
                    InputEvent::AllKeysUp { trigger: *trigger },
                ));
            }
        }
    }
    flush_text(&mut out, &mut text_buf, reliable_seq);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::wire::ButtonState;

    #[test]
    fn wire_conversion_assigns_per_channel_seq_and_coalesces_text() {
        let batch = vec![
            ViewerInputEvent::Move { x: 1, y: 2 },
            ViewerInputEvent::Move { x: 3, y: 4 },
            ViewerInputEvent::Text {
                code_unit: u16::from(b'a'),
            },
            ViewerInputEvent::Text {
                code_unit: u16::from(b'b'),
            },
            ViewerInputEvent::Key {
                scan_code: 0x1E,
                extended: false,
                state: ButtonState::Pressed,
            },
            ViewerInputEvent::AllKeysUp {
                trigger: protocol::wire::AllKeysUpTrigger::FocusLost,
            },
        ];
        let (mut fast, mut reliable) = (0u64, 0u64);
        let wire = to_wire_events(&batch, &mut fast, &mut reliable);
        assert_eq!(wire.len(), 5, "two moves, one coalesced text, key, all-up");
        assert_eq!(wire[0].0, transport_webrtc::Channel::InputFast);
        assert!(matches!(wire[0].1, InputEvent::MouseMove { seq: 1, .. }));
        assert!(matches!(wire[1].1, InputEvent::MouseMove { seq: 2, .. }));
        match &wire[2].1 {
            InputEvent::Text { seq, code_points } => {
                assert_eq!(*seq, 1);
                assert_eq!(code_points, "ab");
            }
            other => panic!("expected coalesced text, got {other:?}"),
        }
        assert!(matches!(wire[3].1, InputEvent::Key { seq: 2, .. }));
        assert!(matches!(
            wire[4].1,
            InputEvent::AllKeysUp {
                trigger: protocol::wire::AllKeysUpTrigger::FocusLost
            }
        ));
        assert_eq!((fast, reliable), (2, 2));
    }

    #[test]
    fn ctl_without_window_drains_nothing() {
        // The engine can drain before the viewer window exists (pipeline
        // start ordering): the empty path must be a no-op, not a panic.
        let ctl = ViewerCtl::new(ScaleMode::Fit);
        assert!(ctl.drain_input().is_empty());
        assert_eq!(ctl.dropped_count(), 0);
        assert!(!ctl.is_fullscreen());
        assert!(!ctl.is_focused());
    }
}
