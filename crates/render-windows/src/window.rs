//! Minimal Win32 window for the presenter (delta D4: no composition
//! polish). All windowing unsafe code in M1 lives here.

use windows::Win32::Foundation::RECT;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRect, CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, DestroyWindow,
    DispatchMessageW, GWL_STYLE, GetClientRect, GetWindowPlacement, MSG, PM_REMOVE, PeekMessageW,
    RegisterClassW, SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER,
    SetWindowLongPtrW, SetWindowPlacement, SetWindowPos, TranslateMessage, UnregisterClassW,
    WINDOW_EX_STYLE, WINDOWPLACEMENT, WM_CLOSE, WM_DESTROY, WM_ERASEBKGND, WNDCLASSW,
    WS_OVERLAPPEDWINDOW, WS_POPUP, WS_VISIBLE,
};
use windows::core::PCWSTR;
use windows::core::w;

/// Window creation parameters.
#[derive(Debug, Clone)]
pub struct WindowConfig {
    pub title: String,
    pub width: i32,
    pub height: i32,
}

/// An owned Win32 window for video presentation. Not `Send`: like all
/// windows it belongs to the thread that created it; the presenting
/// thread owns it for its lifetime.
pub struct PresenterWindow {
    hwnd: HWND,
    class_atom: u16,
    client: (i32, i32),
    /// Set when the client size changed since the last `take_resized()`
    /// (F18: previously documented but never set — the resize path was
    /// dead code until this was wired).
    resized: bool,
}

impl PresenterWindow {
    /// Create a visible window. The calling thread must already be
    /// attached to the input desktop (see
    /// `frame_surface::attach_thread_to_input_desktop`) — windows created
    /// on a private desktop are invisible to the user and to capture.
    pub fn create(config: &WindowConfig) -> Result<Self, crate::RenderError> {
        unsafe {
            let module = GetModuleHandleW(PCWSTR::null())
                .map_err(|e| crate::RenderError::api("GetModuleHandleW", e.code().0, "window"))?;
            let hinstance: windows::Win32::Foundation::HINSTANCE = module.into();
            let class_name = w!("rd_m1_presenter");
            let wc = WNDCLASSW {
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(wnd_proc),
                hInstance: hinstance,
                lpszClassName: class_name,
                ..Default::default()
            };
            let atom = RegisterClassW(&wc);
            if atom == 0 {
                return Err(crate::RenderError::api(
                    "RegisterClassW",
                    windows::Win32::Foundation::GetLastError().0 as i32,
                    "window class",
                ));
            }
            let mut title_buf: Vec<u16> = config.title.encode_utf16().collect();
            title_buf.push(0);
            let mut rect = RECT {
                left: 0,
                top: 0,
                right: config.width,
                bottom: config.height,
            };
            AdjustWindowRect(&mut rect, WS_OVERLAPPEDWINDOW, false)
                .map_err(|e| crate::RenderError::api("AdjustWindowRect", e.code().0, "window"))?;
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class_name,
                PCWSTR(title_buf.as_ptr()),
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                64,
                64,
                rect.right - rect.left,
                rect.bottom - rect.top,
                None,
                None,
                Some(hinstance),
                None,
            )
            .map_err(|e| crate::RenderError::api("CreateWindowExW", e.code().0, "window"))?;
            let mut window = Self {
                hwnd,
                class_atom: atom,
                client: (config.width, config.height),
                resized: false,
            };
            window.update_client_size();
            Ok(window)
        }
    }

    fn update_client_size(&mut self) {
        unsafe {
            let mut rect = RECT::default();
            if GetClientRect(self.hwnd, &mut rect).is_ok() {
                self.client = (rect.right - rect.left, rect.bottom - rect.top);
            }
        }
    }

    pub fn hwnd(&self) -> HWND {
        self.hwnd
    }

    pub fn client_size(&self) -> (i32, i32) {
        self.client
    }

    /// Drain pending window messages (non-blocking). Returns `false`
    /// when the window has been closed/destroyed — stop presenting.
    ///
    /// WM_SIZE itself goes to `DefWindowProcW`; resize detection happens
    /// here by comparing the client rect every pump (robust against
    /// missed messages) and latches `resized` for the renderer.
    pub fn pump(&mut self) -> bool {
        unsafe {
            let mut msg = MSG::default();
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                if msg.message == WM_CLOSE || msg.message == WM_DESTROY {
                    return false;
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            let before = self.client;
            self.update_client_size();
            if self.client != before {
                self.resized = true;
            }
            true
        }
    }

    /// Consume the pending-resize flag (F18). The presenting thread must
    /// call `D3D11Renderer::resize` with the new client size when this
    /// returns true, or the swapchain goes stale.
    pub fn take_resized(&mut self) -> bool {
        std::mem::take(&mut self.resized)
    }

    /// Toggle borderless fullscreen (M5 CR-2: the window-style unsafe that
    /// lived in `apps/desktop`'s viewer now lives with the window). The
    /// caller keeps the `fullscreen` flag and the saved window placement
    /// (restored on leave). Failure handling: each Win32 call is
    /// best-effort — a failed placement save still toggles the style; a
    /// failed monitor query leaves the window at its current position.
    pub fn toggle_borderless_fullscreen(
        &self,
        fullscreen: &mut bool,
        saved: &mut Option<WINDOWPLACEMENT>,
    ) {
        unsafe {
            if *fullscreen {
                // Leave fullscreen: restore style + placement.
                SetWindowLongPtrW(
                    self.hwnd,
                    GWL_STYLE,
                    (WS_OVERLAPPEDWINDOW | WS_VISIBLE).0 as isize,
                );
                if let Some(placement) = saved.take() {
                    let _ = SetWindowPlacement(self.hwnd, &placement);
                }
                let _ = SetWindowPos(
                    self.hwnd,
                    None,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
                );
                *fullscreen = false;
            } else {
                let mut placement = WINDOWPLACEMENT {
                    length: std::mem::size_of::<WINDOWPLACEMENT>() as u32,
                    ..Default::default()
                };
                if GetWindowPlacement(self.hwnd, &mut placement).is_ok() {
                    *saved = Some(placement);
                }
                SetWindowLongPtrW(self.hwnd, GWL_STYLE, (WS_POPUP | WS_VISIBLE).0 as isize);
                let monitor = MonitorFromWindow(self.hwnd, MONITOR_DEFAULTTONEAREST);
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
                        self.hwnd,
                        None,
                        left,
                        top,
                        right - left,
                        bottom - top,
                        SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
                    );
                }
                *fullscreen = true;
            }
        }
    }
}

impl Drop for PresenterWindow {
    fn drop(&mut self) {
        unsafe {
            let _ = DestroyWindow(self.hwnd);
            if let Ok(module) = GetModuleHandleW(PCWSTR::null()) {
                let _ = UnregisterClassW(w!("rd_m1_presenter"), Some(module.into()));
            }
            let _ = self.class_atom;
        }
    }
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        match msg {
            // The video processor covers the window every frame.
            WM_ERASEBKGND => LRESULT(1),
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}
