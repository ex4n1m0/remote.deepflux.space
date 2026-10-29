//! Installed-application inventory (ADR-012 release A): native registry
//! enumeration over the three Uninstall hives. Deliberately NOT winget:
//! the inventory must work on machines without App Installer, with no
//! table parsing, in milliseconds.
//!
//! Reviewed unsafe (the `apps/desktop` scope note covers app-level Win32
//! like `engine/displays.rs`): every registry call is checked; a failing
//! key or value skips that entry — the inventory never fails whole.

use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    REG_EXPAND_SZ, REG_NONE, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegEnumKeyExW,
    RegOpenKeyExW, RegQueryValueExW,
};
use windows::core::PCWSTR;

/// One installed program, as the tool reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEntry {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub uninstall_string: String,
    /// "machine-64" | "machine-32" | "user"
    pub source: &'static str,
}

const UNINSTALL_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

/// Enumerate installed programs: HKLM 64-bit, HKLM 32-bit (Wow6432Node),
/// then HKCU. Sorted by name; entries without a DisplayName are skipped
/// (they are not real programs — MSI scaffolding, patches, etc.).
pub fn installed_apps() -> Vec<AppEntry> {
    let mut out = Vec::new();
    enumerate_hive(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, "machine-64", &mut out);
    enumerate_hive(HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, "machine-32", &mut out);
    enumerate_hive(HKEY_CURRENT_USER, KEY_WOW64_64KEY, "user", &mut out);
    out.sort_by_key(|a| a.name.to_lowercase());
    out.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name) && a.version == b.version);
    out
}

fn enumerate_hive(
    root: HKEY,
    access: REG_SAM_FLAGS,
    source: &'static str,
    out: &mut Vec<AppEntry>,
) {
    unsafe {
        let path = wide(UNINSTALL_PATH);
        let mut hive = HKEY::default();
        if RegOpenKeyExW(
            root,
            PCWSTR(path.as_ptr()),
            None,
            KEY_READ | access,
            &mut hive,
        )
        .is_err()
        {
            return; // hive/view absent on this machine — not an error
        }
        let mut index: u32 = 0;
        loop {
            let mut name_buf = [0u16; 260];
            let mut name_len = name_buf.len() as u32;
            let status = RegEnumKeyExW(
                hive,
                index,
                Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
                &mut name_len,
                None,
                None,
                None,
                None,
            );
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status.is_err() {
                index += 1;
                continue;
            }
            let subkey = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            if let Some(entry) = read_entry(hive, &subkey, source) {
                out.push(entry);
            }
            index += 1;
        }
        let _ = RegCloseKey(hive);
    }
}

/// Read one Uninstall\<subkey> entry; `None` when it has no DisplayName.
fn read_entry(hive: HKEY, subkey: &str, source: &'static str) -> Option<AppEntry> {
    let mut key = HKEY::default();
    let sub = wide(subkey);
    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(sub.as_ptr()), None, KEY_READ, &mut key).is_err() {
            return None;
        }
    }
    let name = query_string(key, "DisplayName").unwrap_or_default();
    if name.trim().is_empty() {
        unsafe {
            let _ = RegCloseKey(key);
        }
        return None;
    }
    let entry = AppEntry {
        name,
        version: query_string(key, "DisplayVersion").unwrap_or_default(),
        publisher: query_string(key, "Publisher").unwrap_or_default(),
        uninstall_string: query_string(key, "UninstallString").unwrap_or_default(),
        source,
    };
    unsafe {
        let _ = RegCloseKey(key);
    }
    Some(entry)
}

/// REG_SZ/REG_EXPAND_SZ value as a String (absent/wrong type → None —
/// never fatal). Expandable strings come back unexpanded; callers only
/// display them.
fn query_string(key: HKEY, value: &str) -> Option<String> {
    let name = wide(value);
    unsafe {
        let mut kind: REG_VALUE_TYPE = REG_NONE;
        let mut size: u32 = 0;
        if RegQueryValueExW(
            key,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        )
        .is_err()
            || (kind != REG_SZ && kind != REG_EXPAND_SZ)
        {
            return None;
        }
        if size == 0 || size > 1 << 20 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        if RegQueryValueExW(
            key,
            PCWSTR(name.as_ptr()),
            None,
            None,
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        )
        .is_err()
        {
            return None;
        }
        let units: Vec<u16> = buf[..size as usize]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(
            String::from_utf16_lossy(&units)
                .trim_end_matches('\0')
                .to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_lists_real_programs_sorted_and_deduped() {
        let apps = installed_apps();
        // Any real Windows install has programs in HKLM; the exact count
        // varies, so pin behavior, not a number.
        assert!(
            !apps.is_empty(),
            "an installed-program inventory is expected"
        );
        assert!(apps.iter().all(|a| !a.name.trim().is_empty()));
        let names: Vec<&str> = apps.iter().map(|a| a.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_by_key(|n| n.to_lowercase());
        assert_eq!(names, sorted, "case-insensitive sort");
        // Every machine this project runs on has something published by
        // Microsoft — a cheap sanity probe that values actually parse.
        assert!(
            apps.iter()
                .any(|a| a.publisher.to_lowercase().contains("microsoft")),
            "expected at least one Microsoft-published entry"
        );
    }
}
