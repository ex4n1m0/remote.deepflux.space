//! Startup-entry management (ADR-012 next tier): what launches with
//! Windows, enumerated natively, with a reversible disable/enable.
//!
//! Sources: the registry Run keys (HKLM 64/32, HKCU) and the two Startup
//! folders (user + all users). Disabling an entry MOVES it — registry
//! command into `startup-disabled.json`, folder file into our backup
//! dir — so enabling restores it exactly; nothing depends on the
//! undocumented StartupApproved binary blob Task Manager writes, and
//! nothing is destroyed while the app's data dir exists.
//!
//! Reviewed unsafe (the `apps/desktop` scope note, same class as
//! `agent/apps.rs`): checked registry calls; a failing value or key
//! skips that entry, never the whole list.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_EXPAND_SZ, REG_NONE,
    REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegEnumValueW,
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows::core::PCWSTR;

const RUN_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
const RUN_PATH_WOW64: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
/// Row cap for the listing.
const LIST_CAP: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StartupEntry {
    pub name: String,
    /// The command (registry) or file name (folder).
    pub command: String,
    /// "machine-64" | "machine-32" | "user" | "user-folder" | "machine-folder"
    pub source: &'static str,
    /// True when this agent disabled it (backed up).
    pub disabled_by_us: bool,
}

/// The disable backup (`<app data>/startup-disabled.json`).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
struct DisabledDoc {
    entries: Vec<DisabledBackup>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct DisabledBackup {
    name: String,
    command: String,
    /// The label the entry had (serde can't mint 'static; mapped back to
    /// the known literals on use — unknown labels are skipped, never
    /// guessed).
    source: String,
    ts_ms: u64,
}

/// The five labels we write, as 'static for StartupEntry.
fn static_label(source: &str) -> Option<&'static str> {
    match source {
        "machine-64" => Some("machine-64"),
        "machine-32" => Some("machine-32"),
        "user" => Some("user"),
        "user-folder" => Some("user-folder"),
        "machine-folder" => Some("machine-folder"),
        _ => None,
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// listing
// ---------------------------------------------------------------------------

pub fn list_entries(app: &AppHandle) -> String {
    let mut entries = collect_all();
    // Merge our disabled backups: they appear as disabled rows.
    let backups = read_backups(app).unwrap_or_default();
    for b in &backups.entries {
        let Some(label) = static_label(&b.source) else {
            continue; // foreign/corrupt label — skip, never guess
        };
        if !entries
            .iter()
            .any(|e| e.name == b.name && e.source == label)
        {
            entries.push(StartupEntry {
                name: b.name.clone(),
                command: b.command.clone(),
                source: label,
                disabled_by_us: true,
            });
        }
    }
    entries.truncate(LIST_CAP);
    if entries.is_empty() {
        return "no startup entries found".to_owned();
    }
    let rows: Vec<String> = entries
        .iter()
        .map(|e| {
            format!(
                "{}\t{}\t{}{}",
                if e.disabled_by_us { "[OFF]" } else { "[on ]" },
                e.name,
                e.source,
                if e.command.is_empty() {
                    String::new()
                } else {
                    format!("\t{}", e.command.chars().take(140).collect::<String>())
                }
            )
        })
        .collect();
    format!("{}\n{}", entries.len(), rows.join("\n"))
}

fn collect_all() -> Vec<StartupEntry> {
    let mut out = Vec::new();
    enum_run_values(HKEY_LOCAL_MACHINE, RUN_PATH, "machine-64", &mut out);
    enum_run_values(HKEY_LOCAL_MACHINE, RUN_PATH_WOW64, "machine-32", &mut out);
    enum_run_values(HKEY_CURRENT_USER, RUN_PATH, "user", &mut out);
    enum_folder(&startup_folder_user(), "user-folder", &mut out);
    enum_folder(&startup_folder_machine(), "machine-folder", &mut out);
    out
}

fn enum_run_values(root: HKEY, path: &str, source: &'static str, out: &mut Vec<StartupEntry>) {
    unsafe {
        let p = wide(path);
        let mut key = HKEY::default();
        if RegOpenKeyExW(root, PCWSTR(p.as_ptr()), None, KEY_READ, &mut key).is_err() {
            return;
        }
        let mut index: u32 = 0;
        loop {
            let mut name_buf = [0u16; 512];
            let mut name_len = name_buf.len() as u32;
            let status = RegEnumValueW(
                key,
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
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            if let Some(command) = run_value_string(key, &name) {
                out.push(StartupEntry {
                    name,
                    command,
                    source,
                    disabled_by_us: false,
                });
            }
            index += 1;
        }
        let _ = RegCloseKey(key);
    }
}

/// REG_SZ/REG_EXPAND_SZ value as a lossy string (unexpanded for EXPAND_SZ).
fn run_value_string(key: HKEY, name: &str) -> Option<String> {
    let n = wide(name);
    unsafe {
        let mut kind: REG_VALUE_TYPE = REG_NONE;
        let mut size: u32 = 0;
        if RegQueryValueExW(
            key,
            PCWSTR(n.as_ptr()),
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
        if size == 0 || size > 1 << 18 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        if RegQueryValueExW(
            key,
            PCWSTR(n.as_ptr()),
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
        let text = String::from_utf16_lossy(&units);
        let trimmed = text.trim_end_matches('\0');
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    }
}

fn startup_folder_user() -> PathBuf {
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_default();
    base.join(r"Microsoft\Windows\Start Menu\Programs\Startup")
}

fn startup_folder_machine() -> PathBuf {
    let base = std::env::var("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_default();
    base.join(r"Microsoft\Windows\Start Menu\Programs\Startup")
}

fn enum_folder(dir: &PathBuf, source: &'static str, out: &mut Vec<StartupEntry>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        out.push(StartupEntry {
            name,
            command: entry.path().display().to_string(),
            source,
            disabled_by_us: false,
        });
    }
}

// ---------------------------------------------------------------------------
// disable / enable
// ---------------------------------------------------------------------------

fn backups_path(app: &AppHandle) -> Option<PathBuf> {
    app.path()
        .app_data_dir()
        .ok()
        .map(|d| d.join("startup-disabled.json"))
}

fn read_backups(app: &AppHandle) -> Option<DisabledDoc> {
    let path = backups_path(app)?;
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
}

fn write_backups(app: &AppHandle, doc: &DisabledDoc) -> Result<(), String> {
    let path = backups_path(app).ok_or("no app data dir")?;
    let tmp = path.with_extension("tmp");
    let text = serde_json::to_string(doc).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, text).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename {}: {e}", path.display()))
}

/// Which hive/path a source label maps to for restore.
fn source_root_path(source: &str) -> Option<(HKEY, &'static str)> {
    match source {
        "machine-64" => Some((HKEY_LOCAL_MACHINE, RUN_PATH)),
        "machine-32" => Some((HKEY_LOCAL_MACHINE, RUN_PATH_WOW64)),
        "user" => Some((HKEY_CURRENT_USER, RUN_PATH)),
        _ => None,
    }
}

pub fn disable_entry(app: &AppHandle, name: &str) -> Result<String, String> {
    let Some(entry) = collect_all()
        .into_iter()
        .find(|e| e.name.eq_ignore_ascii_case(name))
    else {
        return Err(format!("no startup entry named {name:?}"));
    };
    match source_root_path(entry.source) {
        Some((root, path)) => {
            // Back up, then delete the Run value.
            let mut doc = read_backups(app).unwrap_or_default();
            if doc.entries.iter().any(|b| b.name == entry.name) {
                return Err(format!("{:?} is already disabled", entry.name));
            }
            doc.entries.push(DisabledBackup {
                name: entry.name.clone(),
                command: entry.command.clone(),
                source: entry.source.to_owned(),
                ts_ms: now_ms(),
            });
            write_backups(app, &doc)?;
            delete_run_value(root, path, &entry.name)?;
            Ok(format!(
                "disabled {} ({}; backed up — startup_toggle enable restores it)",
                entry.name, entry.source
            ))
        }
        None => {
            // Folder item: move the file into our backup dir.
            let mut doc = read_backups(app).unwrap_or_default();
            if doc.entries.iter().any(|b| b.name == entry.name) {
                return Err(format!("{:?} is already disabled", entry.name));
            }
            let from = PathBuf::from(&entry.command);
            let backup_dir = backups_path(app)
                .and_then(|p| p.parent().map(|d| d.to_owned()))
                .map(|d| d.join("startup-backup"))
                .ok_or("no app data dir")?;
            std::fs::create_dir_all(&backup_dir).map_err(|e| e.to_string())?;
            let to = backup_dir.join(&entry.name);
            std::fs::rename(&from, &to).map_err(|e| format!("move {}: {e}", from.display()))?;
            doc.entries.push(DisabledBackup {
                name: entry.name.clone(),
                command: to.display().to_string(),
                source: entry.source.to_owned(),
                ts_ms: now_ms(),
            });
            write_backups(app, &doc)?;
            Ok(format!(
                "disabled {} (folder item moved to the app's backup; startup_toggle enable restores it)",
                entry.name
            ))
        }
    }
}

pub fn enable_entry(app: &AppHandle, name: &str) -> Result<String, String> {
    let mut doc = read_backups(app).unwrap_or_default();
    let idx = doc
        .entries
        .iter()
        .position(|b| b.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| format!("nothing disabled named {name:?}"))?;
    let backup = doc.entries.remove(idx);
    match source_root_path(&backup.source) {
        Some((root, path)) => {
            write_run_value(root, path, &backup.name, &backup.command)?;
            write_backups(app, &doc)?;
            Ok(format!(
                "restored {} ({}), enabled at login",
                backup.name, backup.source
            ))
        }
        None => {
            // Folder item: move the file back to its Startup folder.
            let target = if backup.source == "user-folder" {
                startup_folder_user().join(&backup.name)
            } else {
                startup_folder_machine().join(&backup.name)
            };
            std::fs::rename(&backup.command, &target)
                .map_err(|e| format!("restore {}: {e}", target.display()))?;
            write_backups(app, &doc)?;
            Ok(format!(
                "restored {} — it starts at login again",
                backup.name
            ))
        }
    }
}

fn delete_run_value(root: HKEY, path: &str, name: &str) -> Result<(), String> {
    unsafe {
        let p = wide(path);
        let mut key = HKEY::default();
        let status = RegOpenKeyExW(root, PCWSTR(p.as_ptr()), None, KEY_WRITE, &mut key);
        if status.is_err() {
            return Err(format!("open {path}: {}", status.0));
        }
        let n = wide(name);
        let del = RegDeleteValueW(key, PCWSTR(n.as_ptr()));
        let _ = RegCloseKey(key);
        if del.is_err() {
            return Err(format!("delete {name}: {}", del.0));
        }
        Ok(())
    }
}

fn write_run_value(root: HKEY, path: &str, name: &str, command: &str) -> Result<(), String> {
    unsafe {
        let p = wide(path);
        let mut key = HKEY::default();
        let status = RegCreateKeyExW(
            root,
            PCWSTR(p.as_ptr()),
            None,
            PCWSTR::null(),
            windows::Win32::System::Registry::REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        );
        if status.is_err() {
            return Err(format!("open {path}: {}", status.0));
        }
        let n = wide(name);
        let data = wide(command);
        // REG_SZ requires the terminating NUL — `wide` adds it.
        let bytes = std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), data.len() * 2);
        let set = RegSetValueExW(key, PCWSTR(n.as_ptr()), None, REG_SZ, Some(bytes));
        let _ = RegCloseKey(key);
        if set.is_err() {
            return Err(format!("write {name}: {}", set.0));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_paths_are_the_windows_standard() {
        let user = startup_folder_user().to_string_lossy().to_lowercase();
        assert!(user.contains("appdata"), "{user}");
        assert!(user.contains("startup"), "{user}");
        let machine = startup_folder_machine().to_string_lossy().to_lowercase();
        assert!(machine.contains("programdata"), "{machine}");
    }

    #[test]
    fn source_labels_map_back_to_their_hives() {
        assert!(source_root_path("machine-64").is_some());
        assert!(source_root_path("machine-32").is_some());
        assert!(source_root_path("user").is_some());
        assert!(source_root_path("user-folder").is_none());
        assert!(source_root_path("machine-folder").is_none());
    }
}
