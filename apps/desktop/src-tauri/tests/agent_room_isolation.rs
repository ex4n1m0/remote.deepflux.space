//! Agent↔human-room structural isolation (ADR-013 D4 / P3 slice 7).
//!
//! D4 freezes the separation: "The agent tool layer gains NO tools that read
//! or post into rooms — structural separation, the same way MSP walls its
//! advisory plane off swarm transcripts." Human chat (slice 6: `human_chat.rs`,
//! the pinned `onlyhumans_core` crate, the `rooms_*` Tauri commands) is a
//! humans-only surface; remote-control and fleet authority must never leak
//! through it, and the agent must never be able to drive it.
//!
//! This test makes that invariant executable — it FAILS the build if the agent
//! layer ever couples to human chat:
//!
//! * a source walk of `src/agent/**` and `src/mcp.rs` (the TWO agent tool
//!   surfaces) rejects any reference to the human-chat surface;
//! * the live `tool_specs()` name universe is enumerated and rejected against
//!   a room denylist (a new room-named tool cannot slip in);
//! * the MCP bridge's tool method names are scanned the same way.
//!
//! Source-walk mechanics are std-only (no walkdir dep); the path anchor is
//! `CARGO_MANIFEST_DIR` (= apps/desktop/src-tauri), the same crate root the
//! other integration tests compile against.

use std::path::{Path, PathBuf};

/// Tokens that must never appear in the agent tool layer. Naming the human-chat
/// surface at all (import, invoke string, event name, comment) is treated as
/// coupling — the separation is structural, so the agent code simply never
/// names it. `onlyhumans` covers the pinned crate; `rooms_*`/`human-chat://`
/// cover the Tauri command/event surface; `HumanRoom` covers the UI/DTO types.
const FORBIDDEN_TOKENS: &[&str] = &[
    "human_chat",
    "onlyhumans",
    "rooms_join",
    "rooms_send",
    "rooms_rotate",
    "rooms_leave",
    "rooms_state",
    "human-chat://",
    "useHumanRooms",
    "HumanRoom",
];

/// Substrings that disqualify an agent TOOL NAME (a tool whose name targets a
/// room is suspect regardless of its implementation).
const ROOM_NAME_TOKENS: &[&str] = &["room", "human_chat", "onlyhumans", "passcode"];

fn manifest_src() -> PathBuf {
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

/// The agent tool layer's source files: everything under src/agent plus the
/// MCP bridge (the second, external-agent tool surface).
fn agent_layer_files() -> Vec<PathBuf> {
    let src = manifest_src();
    let mut files = Vec::new();
    collect_rs_files(&src.join("agent"), &mut files);
    files.push(src.join("mcp.rs"));
    files
}

#[test]
fn agent_layer_source_never_names_human_chat() {
    let mut violations = Vec::new();
    for path in agent_layer_files() {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (lineno, line) in text.lines().enumerate() {
            for token in FORBIDDEN_TOKENS {
                if line.contains(token) {
                    violations.push(format!("{}:{}: {token}", path.display(), lineno + 1));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "the agent tool layer must not reference the humans-only chat surface \
         (ADR-013 D4 structural separation); found:\n{violations:#?}"
    );
}

#[test]
fn agent_tool_names_never_target_rooms() {
    // tool_specs() is the live name universe the assistant advertises; calling
    // it (rather than grepping literals) means a newly added tool is covered
    // automatically.
    let specs = remote_desktop_app_lib::agent::tools::tool_specs();
    assert!(!specs.is_empty(), "tool_specs() must advertise tools");
    let mut violations = Vec::new();
    for spec in &specs {
        let Some(name) = spec["function"]["name"].as_str() else {
            continue;
        };
        let lower = name.to_lowercase();
        if ROOM_NAME_TOKENS.iter().any(|t| lower.contains(t)) {
            violations.push(name.to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "no agent tool may target a human room (ADR-013 D4); offending tool \
         names: {violations:?}"
    );
}

#[test]
fn mcp_tool_names_never_target_rooms() {
    // The MCP bridge is the external-agent surface; scan its method names the
    // same way. rmcp exposes `#[tool]` methods — any fn identifier carrying a
    // room token is a violation (the source-coupling walk above already rejects
    // naming the human-chat module itself).
    let path = manifest_src().join("mcp.rs");
    let text = std::fs::read_to_string(&path).expect("mcp.rs must exist");
    let mut violations = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        // Method declarations look like `fn name(` / `async fn name(`.
        let Some(rest) = trimmed.strip_prefix("fn ").or_else(|| {
            trimmed
                .strip_prefix("async fn ")
                .or_else(|| trimmed.strip_prefix("pub fn "))
                .or_else(|| trimmed.strip_prefix("pub async fn "))
        }) else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let lower = name.to_lowercase();
        if ROOM_NAME_TOKENS.iter().any(|t| lower.contains(t)) {
            violations.push(name);
        }
    }
    assert!(
        violations.is_empty(),
        "no MCP bridge tool may target a human room (ADR-013 D4); offending \
         method names: {violations:?}"
    );
}
