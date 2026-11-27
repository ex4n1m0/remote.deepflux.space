//! Command-argument wire shapes — the regression test for the save-key bug
//! found live on 2026-11-25.
//!
//! The frontend (`src/ipc.ts`) sends Tauri command arguments in camelCase
//! (`apiKey`, `baseUrl`, `monitorId`). Tauri converts only the TOP-LEVEL
//! argument names; the fields of a typed `args:` struct are deserialized by
//! serde under their Rust names, and an unknown key is dropped silently. So
//! `AgentConfigureArgs { api_key, base_url }` never received the key or the
//! Base URL the dialog "Saved", in every build since 2026-10-24 — only the
//! single-word `model` landed. `SelectMonitorArgs { monitor_id }` had the
//! same hole.
//!
//! Two guards:
//! * the explicit shapes deserialize from the keys the frontend sends;
//! * a source rule — an `…Args` struct with a multi-word field must carry
//!   `#[serde(rename_all = "camelCase")]`, so the next such struct cannot
//!   reintroduce the bug unnoticed.

use std::path::{Path, PathBuf};

use remote_desktop_app_lib::agent::AgentConfigureArgs;
use remote_desktop_app_lib::ipc::SelectMonitorArgs;

fn src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Recursively collect every `.rs` file under `dir` (std-only walk).
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Every `pub struct …Args` in a source file: its name, whether it renames
/// to camelCase, and its field names. (Line-based on purpose — the structs
/// are small and flat; a parse that found nothing is caught by the test.)
fn arg_structs(text: &str) -> Vec<(String, bool, Vec<String>)> {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let mut out = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(rest) = line.strip_prefix("pub struct ") else {
            continue;
        };
        let Some(name) = rest.strip_suffix("Args {") else {
            continue;
        };
        let camel = lines[index.saturating_sub(3)..index]
            .iter()
            .any(|earlier| earlier.contains("rename_all = \"camelCase\""));
        let mut fields = Vec::new();
        for next in &lines[index + 1..] {
            if *next == "}" {
                break;
            }
            if let Some(field) = next
                .strip_prefix("pub ")
                .and_then(|rest| rest.split(':').next())
            {
                fields.push(field.trim().to_owned());
            }
        }
        out.push((name.to_owned(), camel, fields));
    }
    out
}

#[test]
fn the_frontend_keys_deserialize_into_the_command_arguments() {
    // Exactly the object `ipc.ts` sends for the Assistant settings dialog.
    let configure: AgentConfigureArgs = serde_json::from_value(serde_json::json!({
        "apiKey": "sk-test-key",
        "baseUrl": "https://api.example.com/v1",
        "model": "some-model"
    }))
    .expect("camelCase agent settings must deserialize");
    assert_eq!(configure.api_key.as_deref(), Some("sk-test-key"));
    assert_eq!(
        configure.base_url.as_deref(),
        Some("https://api.example.com/v1")
    );
    assert_eq!(configure.model.as_deref(), Some("some-model"));

    // Exactly the object `ipc.ts` sends for a monitor picked in the UI.
    let monitor: SelectMonitorArgs = serde_json::from_value(serde_json::json!({
        "monitorId": "\\\\?\\DISPLAY#A1"
    }))
    .expect("camelCase monitorId must deserialize");
    assert_eq!(monitor.monitor_id, "\\\\?\\DISPLAY#A1");

    // Absent keys still mean "leave it alone".
    let partial: AgentConfigureArgs = serde_json::from_value(serde_json::json!({ "model": "m" }))
        .expect("a lone model must deserialize");
    assert_eq!(partial.api_key, None);
    assert_eq!(partial.base_url, None);
    assert_eq!(partial.model.as_deref(), Some("m"));
}

#[test]
fn every_multi_word_command_argument_is_camel_case_on_the_wire() {
    let mut files = Vec::new();
    collect_rs_files(&src_root(), &mut files);
    let mut found = Vec::new();
    let mut violations = Vec::new();
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for (name, camel, fields) in arg_structs(&text) {
            let multi_word = fields.iter().any(|field| field.contains('_'));
            if multi_word && !camel {
                violations.push(format!(
                    "{}: {name}Args has multi-word fields {fields:?} but no \
                     #[serde(rename_all = \"camelCase\")] — the frontend's camelCase keys \
                     would be dropped silently",
                    path.display()
                ));
            }
            found.push(name);
        }
    }
    assert!(
        violations.is_empty(),
        "camelCase wire keys must reach every command argument; found:\n{violations:#?}"
    );
    // The scan really saw the typed command arguments (not an empty walk).
    for expected in [
        "AgentConfigure",
        "AgentSend",
        "ChatSend",
        "Connect",
        "SelectMonitor",
        "SetQuality",
    ] {
        assert!(
            found.iter().any(|name| name.as_str() == expected),
            "the scan must find {expected}Args — found {found:?}"
        );
    }
}
