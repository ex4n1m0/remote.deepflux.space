//! Scheduled agent tasks (ADR-012 release B): named instructions that
//! fire as assistant turns on a repeating schedule — "every night at
//! 02:00 clean temp files and report". Pure storage + due-time logic
//! here; the scheduler thread and the reporting live in `agent::mod`.
//!
//! Deliberately NOT Task Scheduler entries: a second app instance would
//! fight the always-ready one over presence and the tray. The app is the
//! always-ready family agent — it runs at login, so an in-app tick
//! covers every moment the machine can act at all. `scheduled.json` is
//! the durable contract; times are LOCAL (wall clock) because a family
//! machine's "02:00" means the human's 02:00.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

const DOC_VERSION: u16 = 1;
const MAX_TASKS: usize = 32;
const NAME_MAX_CHARS: usize = 32;
const INSTRUCTION_MIN_CHARS: usize = 1;
const INSTRUCTION_MAX_CHARS: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScheduledDoc {
    pub v: u16,
    pub tasks: Vec<ScheduledTask>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScheduledTask {
    /// Slug: lowercase letters/digits/dashes (unique within the doc).
    pub name: String,
    /// The instruction fed to the assistant when the task fires.
    pub instruction: String,
    pub trigger: Trigger,
    pub enabled: bool,
    pub created_ms: u64,
    /// Last time the task was DELIVERED to the assistant (0 = never).
    pub last_fire_ms: u64,
    /// Short tail of the last final answer (display/diagnostics).
    pub last_result: Option<String>,
}

/// When a task fires. Local wall-clock times.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Trigger {
    /// Every day at HH:MM (24h local).
    Daily { at: String },
    /// Every N minutes while the app runs (1..=1440).
    EveryMinutes { minutes: u32 },
    /// Once, at "YYYY-MM-DD HH:MM" local; the task stays but never
    /// refires (and `schedule_remove` cleans it up).
    Once { at: String },
}

// ---------------------------------------------------------------------------
// validation (pure)
// ---------------------------------------------------------------------------

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_MAX_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub fn valid_instruction(instruction: &str) -> bool {
    let len = instruction.trim().chars().count();
    (INSTRUCTION_MIN_CHARS..=INSTRUCTION_MAX_CHARS).contains(&len)
}

/// "HH:MM", 24h, zero-padded.
pub fn valid_hh_mm(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 5
        && bytes[2] == b':'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 2 || b.is_ascii_digit())
        && bytes[0] <= b'2'
        && (bytes[0] != b'2' || bytes[1] <= b'3')
        && bytes[3] <= b'5'
}

/// "YYYY-MM-DD HH:MM" with a plausible calendar shape (the scheduler
/// compares strings against a formatted local time; both sides use the
/// same format, so strict calendar validation is a nicety, not a
/// correctness need).
pub fn valid_once_at(value: &str) -> bool {
    let bytes = value.as_bytes();
    valid_hh_mm(&value[11.min(value.len())..]) && bytes.len() == 16 && bytes[10] == b' ' && {
        let date = &value[..10];
        let d = date.as_bytes();
        d.len() == 10
            && d[4] == b'-'
            && d[7] == b'-'
            && d
                .iter()
                .enumerate()
                .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
    }
}

pub fn valid_trigger(trigger: &Trigger) -> bool {
    match trigger {
        Trigger::Daily { at } => valid_hh_mm(at),
        Trigger::EveryMinutes { minutes } => (1..=1440).contains(minutes),
        Trigger::Once { at } => valid_once_at(at),
    }
}

// ---------------------------------------------------------------------------
// due-time logic (pure; wall-clock inputs, ms since epoch, local)
// ---------------------------------------------------------------------------

/// Local civil time breakdown for a unix-ms stamp (via the OS local
/// timezone — the same clock the human means).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalStamp {
    pub year: i32,
    /// 1-12
    pub month: u32,
    /// 1-31
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
}

/// Whether `task` should fire at `now_ms` given `last_fire_ms`.
pub fn is_due(task: &ScheduledTask, now_ms: u64, now: &LocalStamp) -> bool {
    if !task.enabled {
        return false;
    }
    match &task.trigger {
        Trigger::Daily { at } => {
            let Some((h, m)) = split_hh_mm(at) else {
                return false;
            };
            let now_hm = now.hour * 60 + now.minute;
            let due_hm = h * 60 + m;
            if now_hm < due_hm {
                return false; // not yet today
            }
            // Fire once per day: due when the last fire predates today's
            // due time (never fired, or fired yesterday or earlier).
            let today_due_ms = now_ms.saturating_sub(u64::from(now_hm - due_hm) * 60_000);
            task.last_fire_ms < today_due_ms
        }
        Trigger::EveryMinutes { minutes } => {
            let span = u64::from(*minutes) * 60_000;
            now_ms.saturating_sub(task.last_fire_ms) >= span
        }
        Trigger::Once { at } => {
            // Same-format string compare against the formatted now.
            let now_key = format!(
                "{:04}-{:02}-{:02} {:02}:{:02}",
                now.year, now.month, now.day, now.hour, now.minute
            );
            task.last_fire_ms == 0 && now_key >= *at
        }
    }
}

fn split_hh_mm(value: &str) -> Option<(u32, u32)> {
    let (h, m) = value.split_once(':')?;
    Some((h.parse().ok()?, m.parse().ok()?))
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

fn doc_path(app: &AppHandle) -> PathBuf {
    app.path()
        .app_data_dir()
        .expect("app data dir")
        .join("scheduled.json")
}

pub fn read_doc(app: &AppHandle) -> ScheduledDoc {
    std::fs::read_to_string(doc_path(app))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(ScheduledDoc {
            v: DOC_VERSION,
            tasks: Vec::new(),
        })
}

pub fn write_doc(app: &AppHandle, doc: &ScheduledDoc) -> Result<(), String> {
    let path = doc_path(app);
    let tmp = path.with_extension("tmp");
    let text = serde_json::to_string(doc).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, text).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename {}: {e}", path.display()))
}

/// Insert or replace by name; enforces bounds. Returns the stored doc.
pub fn upsert_task(app: &AppHandle, task: ScheduledTask) -> Result<ScheduledDoc, String> {
    if !valid_name(&task.name) {
        return Err(format!(
            "task name must be 1-{NAME_MAX_CHARS} chars: lowercase, digits, dashes"
        ));
    }
    if !valid_instruction(&task.instruction) {
        return Err("instruction must be 1-2000 characters".to_owned());
    }
    if !valid_trigger(&task.trigger) {
        return Err("trigger is malformed (daily \"HH:MM\", every_mins 1-1440, once \"YYYY-MM-DD HH:MM\")".to_owned());
    }
    let mut doc = read_doc(app);
    doc.tasks.retain(|t| t.name != task.name);
    if doc.tasks.len() >= MAX_TASKS {
        return Err(format!("too many scheduled tasks (cap {MAX_TASKS}) — remove one first"));
    }
    doc.tasks.push(task);
    write_doc(app, &doc)?;
    Ok(doc)
}

pub fn remove_task(app: &AppHandle, name: &str) -> Result<ScheduledDoc, String> {
    let mut doc = read_doc(app);
    let before = doc.tasks.len();
    doc.tasks.retain(|t| t.name != name);
    if doc.tasks.len() == before {
        return Err(format!("no scheduled task named {name:?}"));
    }
    write_doc(app, &doc)?;
    Ok(doc)
}

/// Mark a fire (delivery) — best-effort; the scheduler retries on the
/// next tick if this fails.
pub fn mark_fired(app: &AppHandle, name: &str, result: Option<String>) {
    let mut doc = read_doc(app);
    if let Some(task) = doc.tasks.iter_mut().find(|t| t.name == name) {
        task.last_fire_ms = now_ms();
        task.last_result = result.map(|r| r.chars().take(200).collect());
    }
    let _ = write_doc(app, &doc);
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Local civil time for a unix-ms stamp via chrono-free OS formatting:
/// localtime is not in std, so lean on PowerShell-free env? No — use the
/// Windows local time directly (the scheduler thread already knows the
/// tick time as local components via `LocalStamp::now()` below).
impl LocalStamp {
    /// Now, local (GetLocalTime — reviewed unsafe, tiny).
    pub fn now() -> Self {
        let st = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
        Self {
            year: st.wYear as i32,
            month: st.wMonth as u32,
            day: st.wDay as u32,
            hour: st.wHour as u32,
            minute: st.wMinute as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(trigger: Trigger, last_fire_ms: u64) -> ScheduledTask {
        ScheduledTask {
            name: "night-clean".into(),
            instruction: "clean temp files".into(),
            trigger,
            enabled: true,
            created_ms: 0,
            last_fire_ms,
            last_result: None,
        }
    }

    fn stamp(hour: u32, minute: u32) -> LocalStamp {
        LocalStamp {
            year: 2026,
            month: 10,
            day: 30,
            hour,
            minute,
        }
    }

    #[test]
    fn daily_fires_once_per_day_after_its_time() {
        let t = task(Trigger::Daily { at: "02:00".into() }, 0);
        // 01:59 — not yet.
        assert!(!is_due(&t, fixed_ms(1, 59), &stamp(1, 59)));
        // 02:00 — fires (never fired).
        assert!(is_due(&t, fixed_ms(2, 0), &stamp(2, 0)));
        // 09:00 with last fire at 02:00 today — not again today.
        let fired = task(Trigger::Daily { at: "02:00".into() }, fixed_ms(2, 0));
        assert!(!is_due(&fired, fixed_ms(9, 0), &stamp(9, 0)));
        // ...and a disabled task never fires.
        let mut off = fired.clone();
        off.enabled = false;
        assert!(!is_due(&off, fixed_ms(9, 0), &stamp(9, 0)));
    }

    #[test]
    fn every_minutes_fires_on_span_since_last() {
        let t = task(Trigger::EveryMinutes { minutes: 30 }, 0);
        assert!(is_due(&t, 30 * 60_000, &stamp(3, 0)));
        let fired_at = 30 * 60_000;
        let t2 = task(Trigger::EveryMinutes { minutes: 30 }, fired_at);
        assert!(!is_due(&t2, fired_at + 29 * 60_000, &stamp(3, 29)));
        assert!(is_due(&t2, fired_at + 30 * 60_000, &stamp(3, 30)));
    }

    #[test]
    fn once_fires_at_and_only_at() {
        let t = task(Trigger::Once { at: "2026-10-30 14:00".into() }, 0);
        assert!(!is_due(&t, 0, &stamp(13, 59)));
        assert!(is_due(&t, 0, &stamp(14, 0)));
        let fired = task(Trigger::Once { at: "2026-10-30 14:00".into() }, 1);
        assert!(!is_due(&fired, 5, &stamp(15, 0)), "never refires");
    }

    #[test]
    fn validation_pins() {
        assert!(valid_name("night-clean"));
        assert!(valid_name("a"));
        assert!(!valid_name("Night Clean"));
        assert!(!valid_name(""));
        assert!(valid_hh_mm("00:00"));
        assert!(valid_hh_mm("23:59"));
        assert!(!valid_hh_mm("24:00"));
        assert!(!valid_hh_mm("2:00"));
        assert!(!valid_hh_mm("12:60"));
        assert!(valid_once_at("2026-10-30 14:00"));
        assert!(!valid_once_at("2026-10-30T14:00"));
        assert!(!valid_once_at("2026-10-30 14:0"));
        assert!(valid_trigger(&Trigger::EveryMinutes { minutes: 1 }));
        assert!(!valid_trigger(&Trigger::EveryMinutes { minutes: 0 }));
        assert!(!valid_trigger(&Trigger::EveryMinutes { minutes: 1441 }));
        assert!(!valid_instruction(""));
        assert!(valid_instruction(&"x".repeat(2000)));
        assert!(!valid_instruction(&"x".repeat(2001)));
    }

    /// Fixed epoch-ms for a time-of-day on 2026-10-30 (test-only helper:
    /// any consistent base works — is_due only diffs within a day).
    fn fixed_ms(hour: u32, minute: u32) -> u64 {
        // 2026-10-30T00:00:00Z ≈ 1793347200_000; add the wall offset.
        1_793_347_200_000 + u64::from(hour) * 3_600_000 + u64::from(minute) * 60_000
    }
}
