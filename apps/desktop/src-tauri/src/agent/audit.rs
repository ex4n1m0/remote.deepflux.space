//! Local audit rail (ADR-013 P3, slice 1): every agent action performed
//! on this machine leaves a who/what/when/result record. Two hook points
//! today — the assistant's single tool funnel and a remote peer-agent
//! wake, both in `agent/mod.rs`. Groundwork only: no query, rotation, or
//! UI in this slice.
//!
//! Storage mirrors the chat-history discipline: one JSONL file under the
//! app data dir (`audit/audit.jsonl`), hard-capped, oldest evicted,
//! atomic tmp+rename writes. The rail must never break what it records:
//! any IO failure drops the row with a console note and nothing else.
//! Invariant 6 applies absolutely — tool INPUT arguments and chat bodies
//! never enter the log; only bounded metadata (actor, tool name,
//! outcome) does.

use std::path::PathBuf;
use std::sync::OnceLock;

use serde::Serialize;
use tauri::{AppHandle, Manager};

/// Hard cap on stored entries (the chat.rs `HISTORY_CAP` discipline: the
/// file stays bounded; the oldest rows are evicted first).
const AUDIT_CAP: usize = 2000;
/// Field bounds in chars. Actor ids and tool names are short by shape;
/// the outcome message carries at most the ToolCall-summary clip length
/// (160, `agent/mod.rs`). Everything caller-supplied is clipped — audit
/// rows are metadata, and a rogue model-emitted "tool name" must not
/// bloat the file.
const ACTOR_MAX: usize = 64;
const ACTION_MAX: usize = 64;
const OUTCOME_MSG_MAX: usize = 160;

/// One audit record. The serde shape is the slice-1 contract; stored
/// rows are preserved verbatim on reload (see [`AuditLog::record`]), so
/// fields added in later slices can never corrupt or evict older rows.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    /// Wall-clock ms since the Unix epoch.
    pub ts_ms: u64,
    /// Who initiated: "local-assistant" or "peer-agent:<device-id>".
    pub actor: String,
    /// Which rail recorded: "tool" | "remote-wake".
    pub origin: String,
    /// What ran — the bounded TOOL NAME (never arguments), or a fixed
    /// wake label (never instruction content).
    pub action: String,
    /// "ok" | "error:<bounded msg>" | "denied".
    pub outcome: String,
}

impl AuditEntry {
    /// A freshly stamped entry. Caller-supplied text is clipped to the
    /// bounds above, so hooks cannot accidentally log an unbounded blob.
    pub fn new(actor: &str, origin: &str, action: &str, outcome: impl Into<String>) -> Self {
        Self {
            ts_ms: now_ms(),
            actor: clip(actor, ACTOR_MAX),
            origin: origin.to_owned(),
            action: clip(action, ACTION_MAX),
            outcome: clip(&outcome.into(), OUTCOME_MSG_MAX),
        }
    }
}

/// The process-wide audit log. Reached through a `OnceLock` because
/// `AppServices` is assembled in `lib.rs` and this slice must not widen
/// it; the app data dir is stable for the process lifetime, so
/// first-caller-wins is correct. All methods are `&self` — the log is
/// immutable after init and every write goes through the file.
pub struct AuditLog {
    path: PathBuf,
}

static AUDIT_LOG: OnceLock<AuditLog> = OnceLock::new();

impl AuditLog {
    /// The shared log, rooted at `<app data>/audit/audit.jsonl`.
    pub fn shared(app: &AppHandle) -> &'static AuditLog {
        AUDIT_LOG.get_or_init(|| AuditLog {
            path: audit_dir(app).join("audit.jsonl"),
        })
    }

    /// Append one entry. Cheap and non-fatal: an unreadable or
    /// unwritable file drops the row with a console note — the audited
    /// action is never affected.
    pub fn record(&self, entry: AuditEntry) {
        // Raw-line storage (not parsed structs): existing rows are
        // preserved verbatim — fields added in later slices survive in
        // old rows — and a corrupt line costs only its own slot.
        let mut lines: Vec<String> = match std::fs::read_to_string(&self.path) {
            Ok(text) => text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_owned)
                .collect(),
            Err(_) => Vec::new(), // missing (first row) or unreadable — start fresh
        };
        // Cannot fail for this all-string struct; the guard is belt-only.
        if let Ok(line) = serde_json::to_string(&entry) {
            lines.push(line);
        }
        if lines.len() > AUDIT_CAP {
            let drop = lines.len() - AUDIT_CAP;
            lines.drain(..drop);
        }
        let mut text = lines.join("\n");
        text.push('\n');
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        } else {
            eprintln!("[audit] audit write failed — entry dropped (non-fatal)");
        }
    }
}

/// `<app data>/audit` — the same dir resolution the chat history uses.
fn audit_dir(app: &AppHandle) -> PathBuf {
    let dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    let d = dir.join("audit");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// Best-effort outcome for the tool funnel. Tool results are plain text
/// (no structured error flag), but the module's convention is stable:
/// failures render as "<tool> failed: …", "error: …", or "unknown
/// tool: …"; a refused confirmation as "… denied by the local user" or
/// "… not allowed"; a guard refusal of an own-screen action (ADR-015) as
/// "<tool>: not done: …" or "<tool>: … refused". Judged on the FIRST line
/// only, so a successful result whose content mentions failure (a status
/// snapshot, a read file) is not misclassified. `ask_the_human` returning
/// NO is a successful tool call and stays "ok".
pub fn outcome_from_tool_text(text: &str) -> String {
    let head = text.lines().next().unwrap_or("");
    let denied = head.contains("denied by the local user")
        || head.contains("not allowed")
        || head.contains("not done")
        || head.contains("refused");
    if denied {
        return "denied".to_owned();
    }
    let failed = head.contains(" failed")
        || head.contains("could not inject")
        || head.contains("too long")
        || head.starts_with("error:")
        || head.starts_with("unknown tool");
    if failed {
        let msg = head.strip_prefix("error: ").unwrap_or(head);
        format!("error:{msg}")
    } else {
        "ok".to_owned()
    }
}

/// Bound a caller-supplied field (chars, so no panic mid-multibyte-char).
fn clip(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_path(tag: &str) -> PathBuf {
        // Per-test, per-process scratch file (tests run in parallel —
        // each needs its own).
        let dir = std::env::temp_dir().join(format!("deepflux-audit-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("audit.jsonl")
    }

    fn entry(ts_ms: u64, action: &str) -> AuditEntry {
        AuditEntry {
            ts_ms,
            actor: "local-assistant".to_owned(),
            origin: "tool".to_owned(),
            action: action.to_owned(),
            outcome: "ok".to_owned(),
        }
    }

    #[test]
    fn cap_evicts_oldest_rows() {
        // The chat-history discipline: hard cap, oldest first out, the
        // file never grows past AUDIT_CAP rows.
        let path = temp_path("cap");
        let _ = std::fs::remove_file(&path); // a prior run's leftovers
        let log = AuditLog { path: path.clone() };
        for i in 0..(AUDIT_CAP + 5) as u64 {
            log.record(entry(i, &format!("tool-{i}")));
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), AUDIT_CAP, "hard cap holds");
        assert!(
            lines[0].contains(r#""action":"tool-5""#),
            "the five oldest rows are gone"
        );
        assert!(
            lines[AUDIT_CAP - 1].contains(&format!(r#""action":"tool-{}""#, AUDIT_CAP + 4)),
            "the newest row survives"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn entry_serializes_the_slice1_contract() {
        // Five additive-friendly fields, values intact, one JSONL row —
        // no embedded newline that could break the line-per-entry shape.
        let e = entry(1_700_000_000_000, "status");
        let value = serde_json::to_value(&e).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert_eq!(value["ts_ms"], json!(1_700_000_000_000u64));
        assert_eq!(value["actor"], json!("local-assistant"));
        assert_eq!(value["origin"], json!("tool"));
        assert_eq!(value["action"], json!("status"));
        assert_eq!(value["outcome"], json!("ok"));
        let line = serde_json::to_string(&e).unwrap();
        assert!(!line.contains('\n'), "one JSONL row per entry");
    }

    #[test]
    fn unwritable_path_never_breaks_the_caller() {
        // The rail must be cheaper than the action it records: with the
        // parent "directory" being a FILE, every write fails — record
        // still returns, twice in a row (repeated failures stay
        // non-fatal), and the blocker is untouched.
        let blocker =
            std::env::temp_dir().join(format!("deepflux-audit-blocker-{}", std::process::id()));
        std::fs::write(&blocker, b"x").unwrap();
        let log = AuditLog {
            path: blocker.join("audit.jsonl"),
        };
        log.record(entry(1, "status"));
        log.record(entry(2, "status"));
        assert!(blocker.is_file(), "blocker untouched");
        let _ = std::fs::remove_file(&blocker);
    }

    #[test]
    fn tool_outcomes_follow_the_result_text_convention() {
        // Failures render "<tool> failed: …" / "error: …" / "unknown
        // tool: …"; refusals render the deny texts; everything else —
        // including a body that merely MENTIONS failure — is ok.
        assert_eq!(outcome_from_tool_text("host sharing started"), "ok");
        assert_eq!(
            outcome_from_tool_text("connect failed: signaling unreachable"),
            "error:connect failed: signaling unreachable"
        );
        assert_eq!(
            outcome_from_tool_text("error: bad job state"),
            "error:bad job state"
        );
        assert_eq!(
            outcome_from_tool_text("unknown tool: nonsense"),
            "error:unknown tool: nonsense"
        );
        assert_eq!(
            outcome_from_tool_text("download denied by the local user (host.example)"),
            "denied"
        );
        assert_eq!(
            outcome_from_tool_text(
                "no answer from the local user in 5 minutes — download not allowed (host.example)"
            ),
            "denied"
        );
        assert_eq!(
            outcome_from_tool_text("file read ok:\nlater: it failed to build"),
            "ok",
            "classification reads the first line only"
        );
        // Own-screen guard refusals (ADR-015), injection failures and
        // oversized input: never "ok" on the audit rail.
        assert_eq!(
            outcome_from_tool_text(
                "local_click: not done: that point is inside this app's own window"
            ),
            "denied"
        );
        assert_eq!(
            outcome_from_tool_text(
                "local_press_key: a remotely-woken turn may not do that — refused"
            ),
            "denied"
        );
        assert_eq!(
            outcome_from_tool_text("local_click: could not inject input: blocked"),
            "error:local_click: could not inject input: blocked"
        );
        assert_eq!(
            outcome_from_tool_text("local_type_text: text is too long for one call"),
            "error:local_type_text: text is too long for one call"
        );
    }

    #[test]
    fn caller_supplied_text_is_bounded() {
        // The model authors the tool NAME — a rogue 10k-char "name" (or
        // error blob) must not bloat the audit file.
        let e = AuditEntry::new(
            &"a".repeat(10_000),
            "tool",
            &"n".repeat(10_000),
            outcome_from_tool_text(&format!("run failed: {}", "x".repeat(10_000))),
        );
        assert!(e.actor.chars().count() <= ACTOR_MAX);
        assert!(e.action.chars().count() <= ACTION_MAX);
        assert!(e.outcome.chars().count() <= OUTCOME_MSG_MAX);
        assert!(e.outcome.starts_with("error:"));
    }
}
