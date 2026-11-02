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
    // Forward the launch arguments — `--minimized` (logon tray start)
    // and `--mcp` must survive the elevation relaunch.
    let argv: Vec<String> = std::env::args().collect();
    let parameters = launch_parameters(&argv);
    let parameters_wide = wide(&parameters);
    let parameters = if parameters.is_empty() {
        PCWSTR::null()
    } else {
        PCWSTR(parameters_wide.as_ptr())
    };
    unsafe {
        let code = ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(exe.as_ptr()),
            parameters,
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
        // ShellExecuteW returns a value > 32 on success (HINSTANCE-as-int
        // legacy contract, not a HRESULT).
        code.0 as usize > 32
    }
}

/// Everything after argv[0], re-joined as the elevated replacement's
/// parameter line.
fn launch_parameters(argv: &[String]) -> String {
    if argv.len() > 1 {
        argv[1..].join(" ")
    } else {
        String::new()
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
/// The action carries `--minimized` (tray-only logon start); the
/// idempotent refresh at every elevated launch rewrites pre-0.15.3
/// no-arg entries on the fleet's first post-update boot.
pub fn ensure_admin_autostart(exe: &Path) -> bool {
    let tr = admin_task_action(exe);
    schtasks(&[
        "/Create", "/F", "/TN", TASK_NAME, "/TR", &tr, "/SC", "ONLOGON", "/RL", "HIGHEST",
    ])
}

/// The logon task's action line: the exe quoted plus `--minimized`.
fn admin_task_action(exe: &Path) -> String {
    format!("\"{}\" --minimized", exe.display())
}

/// Remove the elevated logon task (admin mode turned off / autostart off).
pub fn remove_admin_autostart() -> bool {
    schtasks(&["/Delete", "/F", "/TN", TASK_NAME])
}

#[cfg(test)]
mod tests {
    use super::*;

    // String-only tests — nothing here touches the OS (the merge gate
    // must never mutate the machine as a side effect).

    #[test]
    fn task_action_quotes_exe_and_carries_minimized() {
        let tr = admin_task_action(Path::new(
            r"C:\Users\Fam\AppData\Local\Programs\Remote Desktop\Remote Desktop.exe",
        ));
        assert_eq!(
            tr,
            "\"C:\\Users\\Fam\\AppData\\Local\\Programs\\Remote Desktop\\Remote Desktop.exe\" --minimized"
        );
    }

    #[test]
    fn launch_parameters_forward_flags_and_drop_argv0() {
        let argv = vec![
            r"C:\Apps\Remote Desktop.exe".to_string(),
            "--minimized".to_string(),
        ];
        assert_eq!(launch_parameters(&argv), "--minimized");
        assert_eq!(launch_parameters(&["exe".to_string()]), "");
        assert!(launch_parameters(&[]).is_empty());
    }
}
