//! Display enumeration for the shell (monitor picker, injection rect).
//!
//! `capture_windows` keeps its DXGI-based `enumerate_monitors` private
//! (only `DxgiCapture`/`MonitorInfo` are exported), and M4 may not edit
//! crates outside `apps/desktop` — so the shell enumerates through the
//! Win32 monitor APIs directly. Filed as change request CR-3: export a
//! display-enumeration API from `capture-windows` so the shell stops
//! owning Win32 unsafe for this (same review class as CR-2).

use windows::Win32::Foundation::{LPARAM, RECT};
use windows::Win32::Graphics::Gdi::{
    EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO, MONITORINFOEXW,
};
use windows::core::BOOL;

/// `MONITORINFOF_PRIMARY` (winuser.h): the monitor is the primary.
const MONITORINFOF_PRIMARY: u32 = 1;

/// One display attached to the desktop (same shape as the capture crate's
/// private `MonitorInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayInfo {
    /// Win32 device name (`\\.\DISPLAY1`, ...). This is the id the capture
    /// duplication and `SelectMonitor` use.
    pub monitor_id: String,
    pub description: String,
    pub desktop_left: i32,
    pub desktop_top: i32,
    pub width: i32,
    pub height: i32,
    pub is_primary: bool,
}

/// Enumerate desktop-attached monitors, primary first. Failure is an empty
/// list (the picker shows "no monitors" rather than failing the shell).
pub fn enumerate_displays() -> Vec<DisplayInfo> {
    let mut out: Vec<DisplayInfo> = Vec::new();
    let slot = &mut out as *mut Vec<DisplayInfo>;
    unsafe {
        let _ = EnumDisplayMonitors(None, None, Some(monitor_proc), LPARAM(slot as isize));
    }
    out.sort_by(|a, b| {
        b.is_primary
            .cmp(&a.is_primary)
            .then_with(|| a.monitor_id.cmp(&b.monitor_id))
    });
    out
}

unsafe extern "system" fn monitor_proc(
    hmonitor: HMONITOR,
    _hdc: HDC,
    _rect: *mut RECT,
    lparam: LPARAM,
) -> BOOL {
    unsafe {
        let out = &mut *(lparam.0 as *mut Vec<DisplayInfo>);
        let mut info = MONITORINFOEXW::default();
        info.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
        if GetMonitorInfoW(hmonitor, &mut info.monitorInfo as *mut MONITORINFO).as_bool() {
            let RECT {
                left,
                top,
                right,
                bottom,
            } = info.monitorInfo.rcMonitor;
            let name_len = info
                .szDevice
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(info.szDevice.len());
            let device = String::from_utf16_lossy(&info.szDevice[..name_len]);
            let width = right - left;
            let height = bottom - top;
            let is_primary = info.monitorInfo.dwFlags & MONITORINFOF_PRIMARY != 0;
            out.push(DisplayInfo {
                description: format!("{device} ({width}x{height} @{left},{top})"),
                monitor_id: device,
                desktop_left: left,
                desktop_top: top,
                width,
                height,
                is_primary,
            });
        }
        BOOL(1) // continue
    }
}

/// The primary display (fallback: the first enumerated).
pub fn primary_display() -> Option<DisplayInfo> {
    let displays = enumerate_displays();
    displays
        .iter()
        .find(|d| d.is_primary)
        .or_else(|| displays.first())
        .cloned()
}
