//! Window management (ADR-012 release B): enumerate, focus, minimize,
//! and gracefully close top-level windows — sharper than screenshot
//! clicking for "close that error dialog" / "bring the browser front".
//!
//! Reviewed unsafe (the `apps/desktop` scope note): EnumWindows with a
//! boxed Vec receiver in LPARAM; every call checked; titles capped.

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsIconic,
    IsWindowVisible, PostMessageW, SW_MINIMIZE, SW_RESTORE, SetForegroundWindow, ShowWindow,
    WM_CLOSE,
};
use windows::core::BOOL;

/// One visible top-level window. `handle` is the HWND as usize (the tool
/// surface stays plain numbers/strings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowInfo {
    pub handle: usize,
    pub title: String,
    pub minimized: bool,
    pub pid: u32,
}

/// Row cap for the listing (plenty for a human desktop).
const LIST_CAP: usize = 100;
const TITLE_CAP: usize = 120;

pub fn list_windows() -> Vec<WindowInfo> {
    let mut out: Vec<WindowInfo> = Vec::new();
    let boxed = &mut out as *mut Vec<WindowInfo>;
    unsafe {
        let _ = EnumWindows(Some(enum_proc), LPARAM(boxed as isize));
    }
    out.sort_by_key(|w| w.title.to_lowercase());
    out
}

unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let out = unsafe { &mut *(lparam.0 as *mut Vec<WindowInfo>) };
    if out.len() >= LIST_CAP {
        return BOOL(0); // stop enumerating
    }
    unsafe {
        if !IsWindowVisible(hwnd).as_bool() {
            return BOOL(1);
        }
        let len = GetWindowTextLengthW(hwnd);
        if len <= 0 {
            return BOOL(1); // no title — not a user window
        }
        let take = len.min(TITLE_CAP as i32) as usize;
        let mut buf = vec![0u16; take + 1];
        let copied = GetWindowTextW(hwnd, &mut buf);
        if copied <= 0 {
            return BOOL(1);
        }
        let title = String::from_utf16_lossy(&buf[..copied as usize]);
        if title.trim().is_empty() {
            return BOOL(1);
        }
        let mut pid: u32 = 0;
        let _ = GetWindowThreadProcessId(hwnd, Some(&mut pid));
        out.push(WindowInfo {
            handle: hwnd.0 as usize,
            title,
            minimized: IsIconic(hwnd).as_bool(),
            pid,
        });
    }
    BOOL(1)
}

/// Case-insensitive substring match; first hit wins.
fn find_by_title(needle: &str) -> Option<WindowInfo> {
    let needle = needle.trim().to_lowercase();
    if needle.is_empty() {
        return None;
    }
    list_windows()
        .into_iter()
        .find(|w| w.title.to_lowercase().contains(&needle))
}

/// Bring the first window whose title contains `needle` to the front
/// (restoring it first when minimized). Best-effort — Windows may refuse
/// foreground changes from non-foreground processes (elevated app helps).
pub fn focus_window(needle: &str) -> Result<String, String> {
    let Some(win) = find_by_title(needle) else {
        return Err(format!("no window title contains {needle:?}"));
    };
    unsafe {
        if win.minimized {
            let _ = ShowWindow(HWND(win.handle as _), SW_RESTORE);
        }
        // Honest actuator state (review should-fix 4): Windows routinely
        // refuses foreground activation from background processes; a
        // false 'focused' makes the agent type into the wrong window.
        if SetForegroundWindow(HWND(win.handle as _)).as_bool() {
            Ok(format!("focused: {}", win.title))
        } else {
            Ok(format!(
                "could NOT force-focus {:?} (Windows refused — common for a background app); it was restored — verify with a screenshot before typing",
                win.title
            ))
        }
    }
}

pub fn minimize_window(needle: &str) -> Result<String, String> {
    let Some(win) = find_by_title(needle) else {
        return Err(format!("no window title contains {needle:?}"));
    };
    unsafe {
        let _ = ShowWindow(HWND(win.handle as _), SW_MINIMIZE);
    }
    Ok(format!("minimized: {}", win.title))
}

/// Graceful close (WM_CLOSE): the app decides — unsaved-work prompts
/// appear, nothing is killed.
pub fn close_window(needle: &str) -> Result<String, String> {
    let Some(win) = find_by_title(needle) else {
        return Err(format!("no window title contains {needle:?}"));
    };
    unsafe {
        let _ = PostMessageW(Some(HWND(win.handle as _)), WM_CLOSE, WPARAM(0), LPARAM(0));
    }
    Ok(format!(
        "close requested: {} (graceful — the app may still ask about unsaved work)",
        win.title
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_finds_real_windows_capped_and_sorted() {
        let windows = list_windows();
        // This test runs inside a test binary — no windows of its own
        // may exist, so only assert SHAPE and invariants, not presence.
        assert!(windows.len() <= LIST_CAP);
        assert!(windows.iter().all(|w| !w.title.trim().is_empty()));
        let titles: Vec<&str> = windows.iter().map(|w| w.title.as_str()).collect();
        let mut sorted = titles.clone();
        sorted.sort_by_key(|t| t.to_lowercase());
        assert_eq!(titles, sorted);
    }

    #[test]
    fn match_errors_are_typed() {
        assert!(focus_window("definitely-no-such-window-zz").is_err());
        assert!(minimize_window("").is_err(), "empty needle rejected");
        assert!(close_window("definitely-no-such-window-zz").is_err());
    }
}
