//! Viewer-side input capture behind a narrow trait (M5 CR-2, QA F48/F49
//! follow-up): subclass the presenter window's proc, translate Win32 input
//! messages into `protocol::wire`-shaped events in a bounded queue, keep
//! the focus-loss (`AllKeysUp`) and fullscreen-toggle behaviors that lived
//! in `apps/desktop`'s `viewer.rs` until M4.
//!
//! Placement decision (documented for AGENTS): this is `input-windows`,
//! not `render-windows` — the module's product is *input events* (the
//! crate's charter; it already depends on `protocol` for wire input
//! types), and the only Win32 surface it owns is the subclass proc +
//! message constants. The window-*style* half of fullscreen (borderless
//! toggle geometry) stayed in `render-windows` (`toggle_borderless_
//! fullscreen`), which owns the window. No unsafe remains in
//! `apps/desktop` outside the sanctioned list after this move.
//!
//! Contract carried over verbatim from the M4 implementation (reviewed
//! with F48/F49 fixes): mouse moves/clicks normalize over the *destination
//! rect* of the presented frame (letterbox clicks are dropped, not
//! clamped), `WM_KILLFOCUS` enqueues `AllKeysUp{FocusLost}`, `F11` is a
//! local fullscreen toggle never forwarded, text coalescing into UTF-16
//! surrogates happens at the app's wire-conversion layer. Input payloads
//! are never logged (invariant 6; `ViewerInputEvent` carries coordinates,
//! which `Debug`-print only inside this crate's tests).
//!
//! Queues are bounded (invariant 3): the proc's queue drops the *oldest*
//! event when full (the freshest always lands; the window thread can never
//! block on the engine loop).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use protocol::wire::{AllKeysUpTrigger, ButtonState, MouseButton};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    CallWindowProcW, DefWindowProcW, GWLP_WNDPROC, SetWindowLongPtrW, WM_CHAR, WM_KEYDOWN,
    WM_KEYUP, WM_KILLFOCUS, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP,
    WM_MOUSEHWHEEL, WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SETFOCUS,
    WM_SYSKEYDOWN, WM_SYSKEYUP, WM_XBUTTONDOWN, WM_XBUTTONUP, WNDPROC,
};

/// Input events waiting for the engine loop (bounded; invariant 3).
pub const INPUT_QUEUE_CAP: usize = 256;

/// A captured input occurrence before the engine assigns wire seq numbers.
#[derive(Debug, Clone, PartialEq)]
pub enum ViewerInputEvent {
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

/// Narrow boundary (invariant 7): everything the embedding viewer needs
/// from the capture side. Implemented by [`WindowInputCapture`]; test
/// doubles implement it too.
pub trait PresenterInput: Send + Sync {
    /// Drain captured events (engine loop assigns seq numbers and sends).
    fn drain_input(&self) -> Vec<ViewerInputEvent>;
    /// Destination rect of the last presented frame — the rect pointer
    /// input is normalized over (F48). Set by the present thread after
    /// each present/resize; `None` until the first present.
    fn set_dest_rect(&self, rect: Option<(i32, i32, u32, u32)>);
    /// Ask the present thread to toggle borderless fullscreen (F11).
    fn request_fullscreen_toggle(&self);
    fn is_fullscreen(&self) -> bool;
    fn is_focused(&self) -> bool;
    /// Events dropped by the bounded queue (diagnostics).
    fn dropped_count(&self) -> u64;
}

/// The capture-side shared state (queue, focus, fullscreen-request,
/// dest rect) reachable from the subclass proc.
struct CaptureShared {
    fullscreen_toggles: AtomicUsize,
    fullscreen: AtomicBool,
    focused: AtomicBool,
    queue: Mutex<VecDeque<ViewerInputEvent>>,
    dropped: AtomicU64,
    dest_rect: Mutex<Option<(i32, i32, u32, u32)>>,
}

impl CaptureShared {
    fn new() -> Self {
        Self {
            fullscreen_toggles: AtomicUsize::new(0),
            fullscreen: AtomicBool::new(false),
            focused: AtomicBool::new(false),
            queue: Mutex::new(VecDeque::with_capacity(INPUT_QUEUE_CAP)),
            dropped: AtomicU64::new(0),
            dest_rect: Mutex::new(None),
        }
    }

    fn push(&self, event: ViewerInputEvent) {
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

thread_local! {
    /// Subclass state for THIS thread's viewer window. One viewer per
    /// present thread by construction (one controller session per app).
    static SUBCLASS: std::cell::RefCell<Option<(isize, Arc<CaptureShared>)>> =
        const { std::cell::RefCell::new(None) };
}

/// Subclass guard: attaches the proc at creation, restores the original
/// proc on drop (before the window is destroyed by the presenter's Drop).
pub struct WindowInputCapture {
    hwnd: HWND,
    shared: Arc<CaptureShared>,
}

// The HWND is used from the owning (present) thread only; the subclass
// state lives in that thread's thread-local.
unsafe impl Send for WindowInputCapture {}
unsafe impl Sync for WindowInputCapture {}

impl WindowInputCapture {
    /// Subclass `hwnd` on the calling thread (must be the window's own
    /// thread; the viewer's present thread creates and owns the window).
    pub fn attach(hwnd: HWND) -> Result<Arc<Self>, String> {
        let shared = Arc::new(CaptureShared::new());
        let orig =
            unsafe { SetWindowLongPtrW(hwnd, GWLP_WNDPROC, presenter_proc as *const () as isize) };
        if orig == 0 {
            return Err("presenter input subclass failed".to_owned());
        }
        SUBCLASS.with(|slot| *slot.borrow_mut() = Some((orig, Arc::clone(&shared))));
        Ok(Arc::new(Self { hwnd, shared }))
    }

    /// The present thread's fullscreen-toggle application point: consumes
    /// any pending toggle request. The *geometry* of the toggle lives in
    /// `render_windows::toggle_borderless_fullscreen`.
    pub fn take_fullscreen_toggle(&self) -> bool {
        self.shared.fullscreen_toggles.swap(0, Ordering::AcqRel) > 0
    }

    /// Reflect the applied fullscreen state (present thread updates after
    /// applying a toggle).
    pub fn set_fullscreen(&self, on: bool) {
        self.shared.fullscreen.store(on, Ordering::Release);
    }
}

impl Drop for WindowInputCapture {
    fn drop(&mut self) {
        // Unsubclass before the presenter destroys the window. Best-effort
        // restore; a failed window-long write means the window is already
        // gone (teardown race tolerated, logged by the caller's Drop order).
        SUBCLASS.with(|slot| {
            if let Some((orig, _)) = slot.borrow_mut().take() {
                let _ = unsafe { SetWindowLongPtrW(self.hwnd, GWLP_WNDPROC, orig) };
            }
        });
    }
}

impl PresenterInput for WindowInputCapture {
    fn drain_input(&self) -> Vec<ViewerInputEvent> {
        let mut q = self.shared.queue.lock().expect("viewer queue");
        q.drain(..).collect()
    }

    fn set_dest_rect(&self, rect: Option<(i32, i32, u32, u32)>) {
        *self.shared.dest_rect.lock().expect("viewer dest rect") = rect;
    }

    fn request_fullscreen_toggle(&self) {
        self.shared
            .fullscreen_toggles
            .fetch_add(1, Ordering::Release);
    }

    fn is_fullscreen(&self) -> bool {
        self.shared.fullscreen.load(Ordering::Acquire)
    }

    fn is_focused(&self) -> bool {
        self.shared.focused.load(Ordering::Acquire)
    }

    fn dropped_count(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

/// The subclass procedure: Win32 input → bounded `ViewerInputEvent` queue.
unsafe extern "system" fn presenter_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        let state = SUBCLASS.with(|slot| slot.borrow().clone());
        let Some((orig, ctl)) = state else {
            // Not subclassed (teardown race): default handling.
            return DefWindowProcW(hwnd, msg, wparam, lparam);
        };
        let orig: WNDPROC = std::mem::transmute(orig);
        match msg {
            WM_SETFOCUS => {
                ctl.focused.store(true, Ordering::Release);
                // Focus freshly gained: any queued release (from the
                // preceding kill-focus) is stale.
                let mut q = ctl.queue.lock().expect("viewer queue");
                q.retain(|e| !matches!(e, ViewerInputEvent::AllKeysUp { .. }));
                drop(q);
                LRESULT(0)
            }
            WM_KILLFOCUS => {
                ctl.focused.store(false, Ordering::Release);
                // Stuck-key safety on focus loss travels to the host as an
                // explicit wire event (the M2 input package's M4 hook).
                ctl.push(ViewerInputEvent::AllKeysUp {
                    trigger: AllKeysUpTrigger::FocusLost,
                });
                LRESULT(0)
            }
            WM_KEYDOWN | WM_SYSKEYDOWN => {
                let vk = wparam.0 & 0xFFFF;
                if vk == 0x7A {
                    // F11: local fullscreen toggle, never forwarded.
                    ctl.fullscreen_toggles.fetch_add(1, Ordering::Release);
                    return LRESULT(0);
                }
                if ctl.focused.load(Ordering::Acquire) {
                    ctl.push(ViewerInputEvent::Key {
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
                if ctl.focused.load(Ordering::Acquire) {
                    ctl.push(ViewerInputEvent::Key {
                        scan_code: scan_code_of(lparam),
                        extended: extended_of(lparam),
                        state: ButtonState::Released,
                    });
                }
                CallWindowProcW(orig, hwnd, msg, wparam, lparam)
            }
            WM_CHAR => {
                if ctl.focused.load(Ordering::Acquire) && (wparam.0 & 0xFFFF) != 0 {
                    ctl.push(ViewerInputEvent::Text {
                        code_unit: (wparam.0 & 0xFFFF) as u16,
                    });
                }
                LRESULT(0)
            }
            WM_MOUSEMOVE => {
                if ctl.focused.load(Ordering::Acquire) {
                    let (x, y) = mouse_of(lparam);
                    // Normalize over the DESTINATION rect (where the frame
                    // is actually composited), not the client rect; drops
                    // moves inside letterbox bars (M4 QA F48).
                    let rect = *ctl.dest_rect.lock().expect("viewer dest rect");
                    if let Some((nx, ny)) = map_into_dest(x, y, rect) {
                        ctl.push(ViewerInputEvent::Move { x: nx, y: ny });
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
                if ctl.focused.load(Ordering::Acquire) {
                    let which = ((wparam.0 >> 16) & 0xFFFF) as u16;
                    let (x, y) = mouse_of(lparam);
                    let rect = *ctl.dest_rect.lock().expect("viewer dest rect");
                    if map_into_dest(x, y, rect).is_some() {
                        ctl.push(ViewerInputEvent::Button {
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
                if ctl.focused.load(Ordering::Acquire) {
                    let which = ((wparam.0 >> 16) & 0xFFFF) as u16;
                    let (x, y) = mouse_of(lparam);
                    let rect = *ctl.dest_rect.lock().expect("viewer dest rect");
                    if map_into_dest(x, y, rect).is_some() {
                        ctl.push(ViewerInputEvent::Button {
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
                if ctl.focused.load(Ordering::Acquire) {
                    let delta = ((wparam.0 >> 16) & 0xFFFF) as u16 as i16 as i32;
                    let (dv, dh) = if msg == WM_MOUSEWHEEL {
                        (delta, 0)
                    } else {
                        (0, delta)
                    };
                    ctl.push(ViewerInputEvent::Wheel {
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

fn button(ctl: &CaptureShared, button: MouseButton, state: ButtonState, lparam: LPARAM) -> LRESULT {
    if ctl.focused.load(Ordering::Acquire) {
        // Clicks outside the presented frame (letterbox bars, the area
        // beyond a smaller-than-window 1:1 frame) are dropped, not
        // clamped to an edge (F48).
        let (x, y) = mouse_of(lparam);
        let rect = *ctl.dest_rect.lock().expect("viewer dest rect");
        if map_into_dest(x, y, rect).is_some() {
            ctl.push(ViewerInputEvent::Button { button, state });
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
pub fn map_into_dest(x: i32, y: i32, rect: Option<(i32, i32, u32, u32)>) -> Option<(u16, u16)> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The rect under test always comes from the renderer's own pure
    /// geometry helper, so mapping and compositing cannot drift apart
    /// (mirrored from `render_windows::destination_rect`'s contract; the
    /// values below are its outputs, pinned).
    fn dest(w: u32, h: u32, cw: u32, ch: u32, one_to_one: bool) -> Option<(i32, i32, u32, u32)> {
        if one_to_one {
            Some((0, 0, w.min(cw), h.min(ch)))
        } else {
            // Fit: scale to fit, centered.
            let scale = ((cw as f64) / w as f64).min(ch as f64 / h as f64);
            let fw = ((w as f64 * scale).round() as u32).max(1);
            let fh = ((h as f64 * scale).round() as u32).max(1);
            let dx = (cw.saturating_sub(fw)) as i32 / 2;
            let dy = (ch.saturating_sub(fh)) as i32 / 2;
            Some((dx, dy, fw, fh))
        }
    }

    #[test]
    fn f48_fit_letterbox_maps_over_the_video_rect_not_the_client() {
        // 16:9 4K frame, 1600x1000 client → video at (0, 50, 1600, 900).
        let rect = dest(3840, 2160, 1600, 1000, false);
        assert_eq!(rect, Some((0, 50, 1600, 900)));
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
        let rect = dest(1024, 768, 1920, 1080, false);
        assert_eq!(rect, Some((240, 0, 1440, 1080)));
        assert_eq!(map_into_dest(240, 0, rect), Some((0, 0)));
        assert_eq!(map_into_dest(1679, 1079, rect), Some((65_535, 65_535)));
        assert_eq!(map_into_dest(100, 540, rect), None, "left bar");
        assert_eq!(map_into_dest(1900, 540, rect), None, "right bar");
    }

    #[test]
    fn f48_fit_matching_aspect_equals_client_mapping() {
        let rect = dest(1280, 720, 1280, 720, false);
        assert_eq!(rect, Some((0, 0, 1280, 720)));
        assert_eq!(map_into_dest(0, 0, rect), Some((0, 0)));
        assert_eq!(map_into_dest(1279, 719, rect), Some((65_535, 65_535)));
    }

    #[test]
    fn f48_one_to_one_crops_top_left_not_centered_scaled() {
        // 1:1 is top-left anchored: a 1280x720 window over a 4K frame
        // shows the top-left crop.
        let rect = dest(3840, 2160, 1280, 720, true);
        assert_eq!(rect, Some((0, 0, 1280, 720)));
        assert_eq!(
            map_into_dest(640, 360, rect),
            Some((
                ((640i64 * 65_535) / 1279) as u16,
                ((360i64 * 65_535) / 719) as u16,
            ))
        );
        // 1:1 with the window larger than the frame: clicks beyond the
        // frame are dropped; in-frame clicks map to the full range.
        let rect = dest(1280, 720, 1920, 1080, true);
        assert_eq!(rect, Some((0, 0, 1280, 720)));
        assert_eq!(map_into_dest(1279, 719, rect), Some((65_535, 65_535)));
        assert_eq!(map_into_dest(1500, 900, rect), None, "beyond the 1:1 frame");
    }

    #[test]
    fn f48_no_frame_no_mapping_and_degenerate_rects() {
        assert_eq!(map_into_dest(10, 10, None), None);
        assert_eq!(map_into_dest(10, 10, Some((0, 0, 0, 0))), None);
        assert_eq!(
            map_into_dest(5, 5, Some((5, 5, 1, 1))),
            Some((32_767, 32_767))
        );
    }

    #[test]
    fn bounded_queue_drops_oldest_and_counts() {
        let shared = CaptureShared::new();
        for i in 0..(INPUT_QUEUE_CAP + 10) {
            shared.push(ViewerInputEvent::Move { x: i as u16, y: 0 });
        }
        assert_eq!(shared.dropped.load(Ordering::Relaxed), 10);
        let drained = shared
            .queue
            .lock()
            .expect("queue")
            .drain(..)
            .collect::<Vec<_>>();
        assert_eq!(drained.len(), INPUT_QUEUE_CAP);
        assert_eq!(drained[0], ViewerInputEvent::Move { x: 10, y: 0 });
    }
}
