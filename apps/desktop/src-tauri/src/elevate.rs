//! Elevation (ADR-011, owner decision 2026-10-29: "a very powerful agent
//! with admin rights … access to everything"): the app relaunches itself
//! elevated when the `agent_admin` setting is on, so the assistant can
//! administer the whole machine — shell, files, processes, and input into
//! elevated windows (the UIPI wall an unelevated process cannot cross).
//!
//! Small, reviewed Win32 surface (the `apps/desktop` unsafe scope note in
//! AGENTS.md covers exactly this class of app-level concern):
//! * [`is_elevated`] — process token elevation check.
//! * [`relaunch_elevated`] — one UAC prompt, then the caller exits.
//! * [`ensure_admin_autostart`] / [`remove_admin_autostart`] — a logon
//!   scheduled task at HIGHEST run level replaces the registry Run key
//!   while admin mode is on, so family machines get the elevated app at
//!   login WITHOUT a UAC prompt every boot.

use std::os::windows::process::CommandExt;
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::PCWSTR;

/// Scheduled-task name for the elevated logon autostart.
const TASK_NAME: &str = "DeepFluxHostAdmin";
/// `CREATE_NO_WINDOW` for schtasks (never flash consoles).
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// True when this process runs with an elevated token (administrator).
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

/// Relaunch this executable with a UAC prompt ("runas"). Returns `true`
/// when the elevated replacement started — the caller should exit
/// immediately. A declined prompt or a spawn failure returns `false`
/// (the app continues unelevated rather than dying).
pub fn relaunch_elevated() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let exe = wide(&exe.to_string_lossy());
    let verb = wide("runas");
    unsafe {
        let code = ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(exe.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
        // ShellExecuteW returns a value > 32 on success (HINSTANCE-as-int
        // legacy contract, not a HRESULT).
        code.0 as usize > 32
    }
}

fn schtasks(args: &[&str]) -> bool {
    std::process::Command::new("schtasks")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Register the elevated logon task (replaces any previous one). Only
/// meaningful from an elevated process — schtasks /RL HIGHEST needs it.
pub fn ensure_admin_autostart(exe: &Path) -> bool {
    let tr = format!("\"{}\"", exe.display());
    schtasks(&[
        "/Create", "/F", "/TN", TASK_NAME, "/TR", &tr, "/SC", "ONLOGON", "/RL", "HIGHEST",
    ])
}

/// Remove the elevated logon task (admin mode turned off / autostart off).
pub fn remove_admin_autostart() -> bool {
    schtasks(&["/Delete", "/F", "/TN", TASK_NAME])
}
