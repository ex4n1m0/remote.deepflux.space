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
//! Input capture is implemented by subclassing the presenter window proc:
//! keyboard/mouse messages become `protocol::wire` input events (payload
//! only; never logged — invariant 6) in a bounded queue drained by the
//! engine loop onto the `input-fast` / `input-reliable` channels — the same
//! wire path the M2 rig's scripted input used.
//!
//! `WM_KILLFOCUS` enqueues `AllKeysUp{FocusLost}` (the M2 input package's
//! documented M4 hook). `F11` toggles borderless fullscreen locally and is
//! never forwarded to the host.
//!
//! NOTE on unsafe placement: AGENTS.md confines Win32 unsafe to the
//! `*-windows` crates (sanctioned exceptions listed). This module needs it
//! for window subclassing, which no crate exposes; it is filed as change
//! request CR-2 (move viewer input capture into `render-windows`/`
//! input-windows` behind a narrow trait). Until then it lives here,
//! reviewed, with failure handling below.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use protocol::wire::{AllKeysUpTrigger, ButtonState, InputEvent, MouseButton};
use render_windows::{D3D11Renderer, FrameRenderer as _, PresenterWindow, RenderFrame, ScaleMode};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    GetMonitorInfoW, HMONITOR, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallWindowProcW, GWL_STYLE, GWLP_WNDPROC, GetWindowPlacement, SWP_FRAMECHANGED, SWP_NOACTIVATE,
    SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SetWindowLongPtrW, SetWindowPos, WINDOWPLACEMENT,
    WM_CHAR, WM_KEYDOWN, WM_KEYUP, WM_KILLFOCUS, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN,
    WM_MBUTTONUP, WM_MOUSEHWHEEL, WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_RBUTTONDOWN, WM_RBUTTONUP,
    WM_SETFOCUS, WM_SYSKEYDOWN, WM_SYSKEYUP, WM_XBUTTONDOWN, WM_XBUTTONUP, WNDPROC,
    WS_OVERLAPPEDWINDOW, WS_POPUP, WS_VISIBLE,
};

use frame_surface::GpuDevice;

/// Input events waiting for the engine loop (bounded; invariant 3).
const INPUT_QUEUE_CAP: usize = 256;

/// A captured input occurrence before the engine assigns wire seq numbers.
#[derive(Debug, Clone, PartialEq)]
pub enum ViewerInput {
    Move {
        x: u16,
        y: u16,
    },
    Button {
        button: MouseButton,
        state: ButtonState,
    },
    Wheel {
        delta_v: i32,
        delta_h: i32,
    },
    Key {
        scan_code: u16,
        extended: bool,
        state: ButtonState,
    },
    Text {
        code_unit: u16,
    },
    AllKeysUp {
        trigger: AllKeysUpTrigger,
    },
}

/// Shared control/state between the present thread (owner of the window)
/// and the engine loop.
pub struct ViewerCtl {
    /// Latest requested scale mode (applied by the present thread).
    scale: Mutex<ScaleMode>,
    /// Fullscreen toggle request counter (odd = apply pending toggle).
    fullscreen_toggles: AtomicUsize,
    fullscreen: AtomicBool,
    focused: AtomicBool,
    queue: Mutex<VecDeque<ViewerInput>>,
    dropped: AtomicU64,
    /// Last known client size (present thread refreshes every pump).
    client: Mutex<(i32, i32)>,
    /// Destination rect of the last presented frame — the rect input is
    /// normalized over (M4 QA F48; `(x, y, w, h)`, `None` until the first
    /// present).
    dest_rect: Mutex<Option<(i32, i32, u32, u32)>>,
    /// Current swapchain size (after F49 resize handling).
    swapchain: Mutex<(u32, u32)>,
}

impl ViewerCtl {
    pub fn new(scale: ScaleMode) -> Self {
        Self {
            scale: Mutex::new(scale),
            fullscreen_toggles: AtomicUsize::new(0),
            fullscreen: AtomicBool::new(false),
            focused: AtomicBool::new(false),
            queue: Mutex::new(VecDeque::with_capacity(INPUT_QUEUE_CAP)),
            dropped: AtomicU64::new(0),
            client: Mutex::new((1, 1)),
            dest_rect: Mutex::new(None),
            swapchain: Mutex::new((1, 1)),
        }
    }

    pub fn set_scale(&self, mode: ScaleMode) {
        *self.scale.lock().expect("viewer scale") = mode;
    }

    pub fn request_fullscreen_toggle(&self) {
        self.fullscreen_toggles.fetch_add(1, Ordering::Release);
    }

    pub fn is_fullscreen(&self) -> bool {
        self.fullscreen.load(Ordering::Acquire)
    }

    pub fn is_focused(&self) -> bool {
        self.focused.load(Ordering::Acquire)
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Drain captured events (engine loop, then assigns seq and sends).
    pub fn drain_input(&self) -> Vec<ViewerInput> {
        let mut q = self.queue.lock().expect("viewer queue");
        q.drain(..).collect()
    }

    /// Destination rect input is normalized over (F48); set by the present
    /// thread after each present and after each resize.
    pub fn set_dest_rect(&self, rect: Option<(i32, i32, u32, u32)>) {
        *self.dest_rect.lock().expect("viewer dest rect") = rect;
    }

    pub fn dest_rect(&self) -> Option<(i32, i32, u32, u32)> {
        *self.dest_rect.lock().expect("viewer dest rect")
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

    fn push(&self, event: ViewerInput) {
        let mut q = self.queue.lock().expect("viewer queue");
        if q.len() >= INPUT_QUEUE_CAP {
            // Bounded, drop-oldest: the freshest event always lands; the
            // engine cannot stall the window thread (invariant 3).
            q.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        q.push_back(event);
    }
}

/// The native viewer: presenter window + renderer + subclass proc state.
/// Thread-owned by the present thread (created, used, and dropped there).
pub struct ViewerWindow {
    window: PresenterWindow,
    renderer: D3D11Renderer,
    orig_proc: isize,
    ctl: Arc<ViewerCtl>,
    saved_placement: Option<WINDOWPLACEMENT>,
    /// Size of the last presented frame (dest-rect recomputation on
    /// resize before the next frame arrives).
    last_frame: Option<(u32, u32)>,
}

thread_local! {
    /// Subclass state for THIS thread's viewer window. One viewer per
    /// present thread by construction (one controller session per app).
    static SUBCLASS: std::cell::RefCell<Option<(isize, Arc<ViewerCtl>)>> =
        const { std::cell::RefCell::new(None) };
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
        let hwnd = window.hwnd();
        let orig =
            unsafe { SetWindowLongPtrW(hwnd, GWLP_WNDPROC, viewer_proc as *const () as isize) };
        if orig == 0 {
            return Err("viewer subclass failed".to_owned());
        }
        SUBCLASS.with(|slot| *slot.borrow_mut() = Some((orig, Arc::clone(&ctl))));
        let viewer = Self {
            window,
            renderer,
            orig_proc: orig,
            ctl,
            saved_placement: None,
            last_frame: None,
        };
        viewer.sync_client();
        viewer
            .ctl
            .set_swapchain((width.max(1) as u32, height.max(1) as u32));
        Ok(viewer)
    }

    fn sync_client(&self) {
        *self.ctl.client.lock().expect("viewer client") = self.window.client_size();
    }

    pub fn hwnd(&self) -> HWND {
        self.window.hwnd()
    }

    /// Update the locally composited cursor overlay (cursor channel state).
    pub fn set_cursor(&mut self, overlay: Option<render_windows::CursorOverlay>) {
        self.renderer.set_cursor(overlay);
    }

    /// Pump messages, apply control (scale/fullscreen/resize), present one
    /// frame. Returns `false` when the window was closed — stop the
    /// pipeline.
    pub fn pump_and_present(&mut self, frame: Option<&RenderFrame>) -> bool {
        if !self.window.pump() {
            return false;
        }
        self.sync_client();
        // Scale mode changes.
        {
            let mode = *self.ctl.scale.lock().expect("viewer scale");
            self.renderer.set_scale_mode(mode);
        }
        // Fullscreen toggles.
        if self.ctl.fullscreen_toggles.swap(0, Ordering::AcqRel) > 0 {
            self.toggle_fullscreen();
        }
        // Resize: the swapchain must follow the client or it goes stale
        // (F18 wiring, m2_rig parity; M4 QA F49 re-added).
        if self.window.take_resized() {
            let (w, h) = self.window.client_size();
            let (w, h) = (w.max(1) as u32, h.max(1) as u32);
            if self.renderer.resize(w, h).is_ok() {
                self.ctl.set_swapchain((w, h));
            }
            self.refresh_dest_rect();
        }
        if let Some(frame) = frame {
            // Publish the destination rect BEFORE presenting so pointer
            // input normalizes over exactly where the frame lands (F48);
            // `present` computes the same rect via the shared helper.
            let rect = self
                .renderer
                .destination_rect_for(frame.width_px, frame.height_px);
            self.ctl.set_dest_rect(Some(rect));
            self.last_frame = Some((frame.width_px, frame.height_px));
            if self.renderer.present(frame).is_err() {
                return false;
            }
        }
        true
    }

    /// Recompute the destination rect after a resize (before the next
    /// frame arrives the mapping must already use the new client size).
    fn refresh_dest_rect(&self) {
        if let Some((fw, fh)) = self.last_frame {
            self.ctl
                .set_dest_rect(Some(self.renderer.destination_rect_for(fw, fh)));
        }
    }

    fn toggle_fullscreen(&mut self) {
        let hwnd = self.window.hwnd();
        unsafe {
            if self.ctl.fullscreen.load(Ordering::Acquire) {
                // Leave fullscreen: restore style + placement.
                SetWindowLongPtrW(
                    hwnd,
                    GWL_STYLE,
                    (WS_OVERLAPPEDWINDOW | WS_VISIBLE).0 as isize,
                );
                if let Some(placement) = self.saved_placement.take() {
                    let _ = windows::Win32::UI::WindowsAndMessaging::SetWindowPlacement(
                        hwnd, &placement,
                    );
                }
                let _ = SetWindowPos(
                    hwnd,
                    None,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
                );
                self.ctl.fullscreen.store(false, Ordering::Release);
            } else {
                let mut placement = WINDOWPLACEMENT {
                    length: std::mem::size_of::<WINDOWPLACEMENT>() as u32,
                    ..Default::default()
                };
                if GetWindowPlacement(hwnd, &mut placement).is_ok() {
                    self.saved_placement = Some(placement);
                }
                SetWindowLongPtrW(hwnd, GWL_STYLE, (WS_POPUP | WS_VISIBLE).0 as isize);
                let monitor: HMONITOR = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
                let mut info = MONITORINFO {
                    cbSize: std::mem::size_of::<MONITORINFO>() as u32,
                    ..Default::default()
                };
                if GetMonitorInfoW(monitor, &mut info).as_bool() {
                    let RECT {
                        left,
                        top,
                        right,
                        bottom,
                    } = info.rcMonitor;
                    let _ = SetWindowPos(
                        hwnd,
                        None,
                        left,
                        top,
                        right - left,
                        bottom - top,
                        SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
                    );
                }
                self.ctl.fullscreen.store(true, Ordering::Release);
            }
        }
    }
}

impl Drop for ViewerWindow {
    fn drop(&mut self) {
        // Unsubclass before the window is destroyed, then let
        // PresenterWindow's Drop destroy it.
        SUBCLASS.with(|slot| {
            *slot.borrow_mut() = None;
        });
        let _ = unsafe { SetWindowLongPtrW(self.window.hwnd(), GWLP_WNDPROC, self.orig_proc) };
    }
}

// ---------------------------------------------------------------------------
// The subclass procedure: Win32 input → bounded ViewerInput queue
// ---------------------------------------------------------------------------

unsafe extern "system" fn viewer_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        let state = SUBCLASS.with(|slot| slot.borrow().clone());
        let Some((orig, ctl)) = state else {
            // Not subclassed (teardown race): default handling.
            return windows::Win32::UI::WindowsAndMessaging::DefWindowProcW(
                hwnd, msg, wparam, lparam,
            );
        };
        let orig: WNDPROC = std::mem::transmute(orig);
        match msg {
            WM_SETFOCUS => {
                ctl.focused.store(true, Ordering::Release);
                // Focus freshly gained: any queued release (from the
                // preceding kill-focus) is stale.
                let mut q = ctl.queue.lock().expect("viewer queue");
                q.retain(|e| !matches!(e, ViewerInput::AllKeysUp { .. }));
                drop(q);
                LRESULT(0)
            }
            WM_KILLFOCUS => {
                ctl.focused.store(false, Ordering::Release);
                // The M4 hook (M2 input package): stuck-key safety on focus
                // loss travels to the host as an explicit wire event.
                ctl.push(ViewerInput::AllKeysUp {
                    trigger: AllKeysUpTrigger::FocusLost,
                });
                LRESULT(0)
            }
            WM_KEYDOWN | WM_SYSKEYDOWN => {
                let vk = wparam.0 & 0xFFFF;
                if vk == 0x7A {
                    // F11: local fullscreen toggle, never forwarded.
                    ctl.request_fullscreen_toggle();
                    return LRESULT(0);
                }
                if ctl.is_focused() {
                    ctl.push(ViewerInput::Key {
                        scan_code: scan_code_of(lparam),
                        extended: extended_of(lparam),
                        state: ButtonState::Pressed,
                    });
                }
                // System keys must also reach DefWindowProc for alt-menu
                // handling to stay inert; we forward everything we consume
                // so no local UI state builds up.
                CallWindowProcW(orig, hwnd, msg, wparam, lparam)
            }
            WM_KEYUP | WM_SYSKEYUP => {
                if ctl.is_focused() {
                    ctl.push(ViewerInput::Key {
                        scan_code: scan_code_of(lparam),
                        extended: extended_of(lparam),
                        state: ButtonState::Released,
                    });
                }
                CallWindowProcW(orig, hwnd, msg, wparam, lparam)
            }
            WM_CHAR => {
                if ctl.is_focused() && (wparam.0 & 0xFFFF) != 0 {
                    ctl.push(ViewerInput::Text {
                        code_unit: (wparam.0 & 0xFFFF) as u16,
                    });
                }
                LRESULT(0)
            }
            WM_MOUSEMOVE => {
                if ctl.is_focused() {
                    let (x, y) = mouse_of(lparam);
                    // Normalize over the DESTINATION rect (where the frame
                    // is actually composited), not the client rect; drops
                    // moves inside letterbox bars (M4 QA F48).
                    if let Some((nx, ny)) = map_into_dest(x, y, ctl.dest_rect()) {
                        ctl.push(ViewerInput::Move { x: nx, y: ny });
                    }
                }
                CallWindowProcW(orig, hwnd, msg, wparam, lparam)
            }
            WM_LBUTTONDOWN => button(&ctl, MouseButton::Left, ButtonState::Pressed, lparam),
            WM_LBUTTONUP => button(&ctl, MouseButton::Left, ButtonState::Released, lparam),
            WM_RBUTTONDOWN => button(&ctl, MouseButton::Right, ButtonState::Pressed, lparam),
            WM_RBUTTONUP => button(&ctl, MouseButton::Right, ButtonState::Released, lparam),
            WM_MBUTTONDOWN => button(&ctl, MouseButton::Middle, ButtonState::Pressed, lparam),
            WM_MBUTTONUP => button(&ctl, MouseButton::Middle, ButtonState::Released, lparam),
            WM_XBUTTONDOWN => {
                if ctl.is_focused() {
                    let which = ((wparam.0 >> 16) & 0xFFFF) as u16;
                    let (x, y) = mouse_of(lparam);
                    if map_into_dest(x, y, ctl.dest_rect()).is_some() {
                        ctl.push(ViewerInput::Button {
                            button: if which == 1 {
                                MouseButton::X1
                            } else {
                                MouseButton::X2
                            },
                            state: ButtonState::Pressed,
                        });
                    }
                }
                LRESULT(1)
            }
            WM_XBUTTONUP => {
                if ctl.is_focused() {
                    let which = ((wparam.0 >> 16) & 0xFFFF) as u16;
                    let (x, y) = mouse_of(lparam);
                    if map_into_dest(x, y, ctl.dest_rect()).is_some() {
                        ctl.push(ViewerInput::Button {
                            button: if which == 1 {
                                MouseButton::X1
                            } else {
                                MouseButton::X2
                            },
                            state: ButtonState::Released,
                        });
                    }
                }
                LRESULT(1)
            }
            WM_MOUSEWHEEL | WM_MOUSEHWHEEL => {
                if ctl.is_focused() {
                    let delta = ((wparam.0 >> 16) & 0xFFFF) as u16 as i16 as i32;
                    let (dv, dh) = if msg == WM_MOUSEWHEEL {
                        (delta, 0)
                    } else {
                        (0, delta)
                    };
                    ctl.push(ViewerInput::Wheel {
                        delta_v: dv,
                        delta_h: dh,
                    });
                }
                LRESULT(0)
            }
            _ => CallWindowProcW(orig, hwnd, msg, wparam, lparam),
        }
    }
}

fn button(ctl: &ViewerCtl, button: MouseButton, state: ButtonState, lparam: LPARAM) -> LRESULT {
    if ctl.is_focused() {
        // Clicks outside the presented frame (letterbox bars, the area
        // beyond a smaller-than-window 1:1 frame) are dropped, not
        // clamped to an edge (F48).
        let (x, y) = mouse_of(lparam);
        if map_into_dest(x, y, ctl.dest_rect()).is_some() {
            ctl.push(ViewerInput::Button { button, state });
        }
    }
    LRESULT(0)
}

fn scan_code_of(lparam: LPARAM) -> u16 {
    ((lparam.0 >> 16) & 0xFF) as u16
}

fn extended_of(lparam: LPARAM) -> bool {
    (lparam.0 & (1 << 24)) != 0
}

fn mouse_of(lparam: LPARAM) -> (i32, i32) {
    let x = (lparam.0 & 0xFFFF) as u16 as i32;
    let y = ((lparam.0 >> 16) & 0xFFFF) as u16 as i32;
    (x, y)
}

/// Map client pixels onto the wire's 0..=65535 space **over the frame's
/// destination rect** `(x, y, w, h)` (M4 QA F48). `None` when the point is
/// outside the rect (letterbox bars / beyond a 1:1 frame) or no frame has
/// been presented yet — callers drop the event rather than clamp to an
/// edge.
fn map_into_dest(x: i32, y: i32, rect: Option<(i32, i32, u32, u32)>) -> Option<(u16, u16)> {
    let (dx, dy, dw, dh) = rect?;
    if dw == 0 || dh == 0 {
        return None;
    }
    if x < dx || y < dy || x >= dx + dw as i32 || y >= dy + dh as i32 {
        return None;
    }
    let nx = if dw <= 1 {
        32_767
    } else {
        ((x - dx) * 65_535) / (dw as i32 - 1)
    };
    let ny = if dh <= 1 {
        32_767
    } else {
        ((y - dy) * 65_535) / (dh as i32 - 1)
    };
    Some((nx.clamp(0, 65_535) as u16, ny.clamp(0, 65_535) as u16))
}

/// Convert drained viewer events into wire input events with monotonic seq
/// (fast moves share one counter, reliable events another — per-channel
/// monotonic per the wire contract). Consecutive text code units coalesce
/// into one `Text` event (surrogate pairs must not be split).
pub fn to_wire_events(
    batch: &[ViewerInput],
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
            ViewerInput::Move { x, y } => {
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
            ViewerInput::Button { button, state } => {
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
            ViewerInput::Wheel { delta_v, delta_h } => {
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
            ViewerInput::Key {
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
            ViewerInput::Text { code_unit } => {
                text_buf.push(*code_unit);
            }
            ViewerInput::AllKeysUp { trigger } => {
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

    /// The rect under test always comes from the renderer's own pure
    /// geometry helper, so mapping and compositing cannot drift apart.
    fn dest(
        scale: ScaleMode,
        frame: (u32, u32),
        client: (u32, u32),
    ) -> Option<(i32, i32, u32, u32)> {
        Some(render_windows::destination_rect(
            scale, frame.0, frame.1, client.0, client.1,
        ))
    }

    #[test]
    fn f48_fit_letterbox_maps_over_the_video_rect_not_the_client() {
        // The audit's repro: 16:9 4K frame, 1600x1000 client → video at
        // (0, 50, 1600, 900), 50 px bars top/bottom.
        let rect = dest(ScaleMode::Fit, (3840, 2160), (1600, 1000));
        assert_eq!(rect, Some((0, 50, 1600, 900)));
        // The video's top edge must be remote y=0 — the old client-rect
        // mapping sent ~3279 (≈108 px into the remote) here.
        assert_eq!(map_into_dest(0, 50, rect), Some((0, 0)));
        assert_eq!(map_into_dest(1599, 949, rect), Some((65_535, 65_535)));
        assert_eq!(
            map_into_dest(800, 500, rect),
            Some((
                ((800i64 * 65_535) / 1599) as u16,
                ((450i64 * 65_535) / 899) as u16,
            ))
        );
        // Clicks in the letterbox bars are dropped, not clamped.
        assert_eq!(map_into_dest(800, 10, rect), None);
        assert_eq!(map_into_dest(800, 980, rect), None);
    }

    #[test]
    fn f48_fit_pillarbox_maps_over_the_video_rect() {
        // 4:3 frame in a 16:9 client → 240 px bars left/right.
        let rect = dest(ScaleMode::Fit, (1024, 768), (1920, 1080));
        assert_eq!(rect, Some((240, 0, 1440, 1080)));
        assert_eq!(map_into_dest(240, 0, rect), Some((0, 0)));
        assert_eq!(map_into_dest(1679, 1079, rect), Some((65_535, 65_535)));
        assert_eq!(map_into_dest(100, 540, rect), None, "left bar");
        assert_eq!(map_into_dest(1900, 540, rect), None, "right bar");
    }

    #[test]
    fn f48_fit_matching_aspect_equals_client_mapping() {
        // The only geometry where the old mapping was accidentally right.
        let rect = dest(ScaleMode::Fit, (1280, 720), (1280, 720));
        assert_eq!(rect, Some((0, 0, 1280, 720)));
        assert_eq!(map_into_dest(0, 0, rect), Some((0, 0)));
        assert_eq!(map_into_dest(1279, 719, rect), Some((65_535, 65_535)));
    }

    #[test]
    fn f48_one_to_one_crops_top_left_not_centered_scaled() {
        // 1:1 is top-left anchored (renderer semantics): a 1280x720 window
        // over a 4K frame shows the top-left crop; the audit's 3× error
        // came from normalizing center-clicks over the whole client.
        let rect = dest(ScaleMode::OneToOne, (3840, 2160), (1280, 720));
        assert_eq!(rect, Some((0, 0, 1280, 720)));
        // Center click maps to the CENTER OF THE CROPPED VIEW, i.e. remote
        // (1920, 1080) in absolute pixels — exactly what is displayed
        // there. The old mapping sent the same 32767/32767 against the
        // client rect; identical here, but see the larger-client case.
        assert_eq!(
            map_into_dest(640, 360, rect),
            Some((
                ((640i64 * 65_535) / 1279) as u16,
                ((360i64 * 65_535) / 719) as u16,
            ))
        );
        // 1:1 with the window larger than the frame: the frame sits
        // top-left; clicks beyond it are dropped (nothing is displayed
        // there), and in-frame clicks map 1:1 to the full 0..=65535 range.
        let rect = dest(ScaleMode::OneToOne, (1280, 720), (1920, 1080));
        assert_eq!(rect, Some((0, 0, 1280, 720)));
        assert_eq!(map_into_dest(1279, 719, rect), Some((65_535, 65_535)));
        assert_eq!(map_into_dest(1500, 900, rect), None, "beyond the 1:1 frame");
    }

    #[test]
    fn f48_non_widescreen_window_geometry() {
        // 21:9 frame in an 8:5 client: bars top/bottom.
        let rect = dest(ScaleMode::Fit, (2560, 1080), (1600, 1000));
        assert_eq!(rect, Some((0, 162, 1600, 675)));
        assert_eq!(
            map_into_dest(800, 162, rect),
            Some((((800i64 * 65_535) / 1599) as u16, 0))
        );
        assert_eq!(
            map_into_dest(800, 836, rect),
            Some((((800i64 * 65_535) / 1599) as u16, 65_535))
        );
        assert_eq!(map_into_dest(800, 100, rect), None);
    }

    #[test]
    fn f48_no_frame_no_mapping_and_degenerate_rects() {
        // Before the first present there is nothing on screen to click.
        assert_eq!(map_into_dest(10, 10, None), None);
        // Degenerate rect (zero-size destination) drops instead of
        // dividing by zero.
        assert_eq!(map_into_dest(10, 10, Some((0, 0, 0, 0))), None);
        assert_eq!(
            map_into_dest(5, 5, Some((5, 5, 1, 1))),
            Some((32_767, 32_767))
        );
    }

    #[test]
    fn wire_conversion_assigns_per_channel_seq_and_coalesces_text() {
        let batch = vec![
            ViewerInput::Move { x: 1, y: 2 },
            ViewerInput::Move { x: 3, y: 4 },
            ViewerInput::Text {
                code_unit: u16::from(b'a'),
            },
            ViewerInput::Text {
                code_unit: u16::from(b'b'),
            },
            ViewerInput::Key {
                scan_code: 0x1E,
                extended: false,
                state: ButtonState::Pressed,
            },
            ViewerInput::AllKeysUp {
                trigger: AllKeysUpTrigger::FocusLost,
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
                trigger: AllKeysUpTrigger::FocusLost
            }
        ));
        assert_eq!((fast, reliable), (2, 2));
    }

    #[test]
    fn bounded_queue_drops_oldest_and_counts() {
        let ctl = ViewerCtl::new(ScaleMode::Fit);
        for i in 0..(INPUT_QUEUE_CAP + 10) {
            ctl.push(ViewerInput::Move { x: i as u16, y: 0 });
        }
        assert_eq!(ctl.dropped_count(), 10);
        let drained = ctl.drain_input();
        assert_eq!(drained.len(), INPUT_QUEUE_CAP);
        assert_eq!(drained[0], ViewerInput::Move { x: 10, y: 0 });
    }
}
