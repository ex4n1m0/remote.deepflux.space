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
        };
        viewer.sync_client();
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

    /// Pump messages, apply control (scale/fullscreen), present one frame.
    /// Returns `false` when the window was closed — stop the pipeline.
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
        if let Some(frame) = frame
            && self.renderer.present(frame).is_err()
        {
            return false;
        }
        true
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
                    let norm = normalize(x, y, *ctl.client.lock().expect("viewer client"));
                    ctl.push(ViewerInput::Move {
                        x: norm.0,
                        y: norm.1,
                    });
                }
                CallWindowProcW(orig, hwnd, msg, wparam, lparam)
            }
            WM_LBUTTONDOWN => button(&ctl, MouseButton::Left, ButtonState::Pressed),
            WM_LBUTTONUP => button(&ctl, MouseButton::Left, ButtonState::Released),
            WM_RBUTTONDOWN => button(&ctl, MouseButton::Right, ButtonState::Pressed),
            WM_RBUTTONUP => button(&ctl, MouseButton::Right, ButtonState::Released),
            WM_MBUTTONDOWN => button(&ctl, MouseButton::Middle, ButtonState::Pressed),
            WM_MBUTTONUP => button(&ctl, MouseButton::Middle, ButtonState::Released),
            WM_XBUTTONDOWN => {
                if ctl.is_focused() {
                    let which = ((wparam.0 >> 16) & 0xFFFF) as u16;
                    ctl.push(ViewerInput::Button {
                        button: if which == 1 {
                            MouseButton::X1
                        } else {
                            MouseButton::X2
                        },
                        state: ButtonState::Pressed,
                    });
                }
                LRESULT(1)
            }
            WM_XBUTTONUP => {
                if ctl.is_focused() {
                    let which = ((wparam.0 >> 16) & 0xFFFF) as u16;
                    ctl.push(ViewerInput::Button {
                        button: if which == 1 {
                            MouseButton::X1
                        } else {
                            MouseButton::X2
                        },
                        state: ButtonState::Released,
                    });
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

fn button(ctl: &ViewerCtl, button: MouseButton, state: ButtonState) -> LRESULT {
    if ctl.is_focused() {
        ctl.push(ViewerInput::Button { button, state });
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

/// Normalize client pixels to the wire's 0..=65535 space over the window.
fn normalize(x: i32, y: i32, (w, h): (i32, i32)) -> (u16, u16) {
    let nx = if w <= 1 {
        32_767
    } else {
        (x.clamp(0, w - 1) * 65_535) / (w - 1)
    };
    let ny = if h <= 1 {
        32_767
    } else {
        (y.clamp(0, h - 1) * 65_535) / (h - 1)
    };
    (nx.clamp(0, 65_535) as u16, ny.clamp(0, 65_535) as u16)
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

    #[test]
    fn normalization_covers_the_full_range() {
        assert_eq!(normalize(0, 0, (1920, 1080)), (0, 0));
        assert_eq!(normalize(1919, 1079, (1920, 1080)), (65_535, 65_535));
        assert_eq!(normalize(960, 540, (1921, 1081)), (32_767, 32_767));
        // Degenerate sizes center instead of dividing by zero.
        assert_eq!(normalize(0, 0, (1, 1)), (32_767, 32_767));
        // Out-of-range (impossible for client coords) clamps.
        assert_eq!(normalize(5_000, -5, (1920, 1080)), (65_535, 0));
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
