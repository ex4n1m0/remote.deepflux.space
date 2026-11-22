//! Structured, redacted telemetry for the ModelSwarm node.
//!
//! Every log line is a JSON object with `ts`, `level`, `event`, and
//! redacted fields (`redact::Redactor` enforces the privacy contract).
//! Metrics are in-process counters/timers with snapshot support — no
//! background threads, no timers (ADR-001 discipline applies locally too).
//!
//! Sinks: `MemSink` (ring buffer, default for tests) and `FileSink`
//! (append-only JSONL). The node wires one `Telemetry` and passes it down;
//! crates must not build their own loggers (AGENTS.md).

pub mod redact;

use redact::Redactor;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

pub trait Sink: Send + Sync {
    fn write_line(&self, line: &str);
}

/// In-memory ring buffer sink (bounded — slow consumers can't grow memory,
/// consistent with the transport's backpressure posture).
pub struct MemSink {
    inner: Mutex<std::collections::VecDeque<String>>,
    capacity: usize,
}

impl MemSink {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(std::collections::VecDeque::with_capacity(
                capacity.min(1024),
            )),
            capacity: capacity.max(1),
        }
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.inner.lock().unwrap().iter().cloned().collect()
    }
}

impl Sink for MemSink {
    fn write_line(&self, line: &str) {
        let mut q = self.inner.lock().unwrap();
        if q.len() == self.capacity {
            q.pop_front();
        }
        q.push_back(line.to_string());
    }
}

/// Append-only JSONL file sink.
pub struct FileSink {
    file: Mutex<std::fs::File>,
}

impl FileSink {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl Sink for FileSink {
    fn write_line(&self, line: &str) {
        if let Ok(mut f) = self.file.lock() {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// Simple counters and timing accumulators (metrics snapshot via
/// `snapshot_metrics`, not log lines).
#[derive(Debug, Default)]
pub struct Metrics {
    counters: Mutex<std::collections::BTreeMap<String, u64>>,
    timings_ms: Mutex<std::collections::BTreeMap<String, (u64, f64)>>, // (count, sum)
}

impl Metrics {
    pub fn incr(&self, name: &str) {
        *self
            .counters
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_insert(0) += 1;
    }

    pub fn observe_ms(&self, name: &str, ms: f64) {
        let mut map = self.timings_ms.lock().unwrap();
        let e = map.entry(name.to_string()).or_insert((0, 0.0));
        e.0 += 1;
        e.1 += ms;
    }

    pub fn snapshot(&self) -> String {
        let counters = self.counters.lock().unwrap().clone();
        let timings = self.timings_ms.lock().unwrap().clone();
        let mut parts: Vec<String> = counters
            .iter()
            .map(|(k, v)| format!("\"{k}\":{v}"))
            .collect();
        for (k, (n, sum)) in &timings {
            parts.push(format!(
                "\"{k}_count\":{n},\"{k}_mean_ms\":{}",
                sum / *n as f64
            ));
        }
        format!("{{{}}}", parts.join(","))
    }
}

pub struct Telemetry {
    sink: Box<dyn Sink>,
    redactor: Redactor,
    pub metrics: Metrics,
}

impl Telemetry {
    pub fn with_sink(sink: Box<dyn Sink>) -> Self {
        Self {
            sink,
            redactor: Redactor::default(),
            metrics: Metrics::default(),
        }
    }

    /// Telemetry + a shared handle on its memory sink (tests, diagnostics
    /// export).
    pub fn memory() -> (Self, std::sync::Arc<MemSink>) {
        let mem = std::sync::Arc::new(MemSink::new(1024));
        let t = Self::with_sink(Box::new(MemSinkShim(mem.clone())));
        (t, mem)
    }

    /// Emit one structured event. Fields pass through the redactor.
    pub fn log(&self, level: Level, event: &str, fields: &[(&str, &str)]) {
        let mut line = format!(
            "{{\"ts\":\"{}\",\"level\":\"{}\",\"event\":\"{}\"",
            iso_now(),
            level.as_str(),
            escape(event)
        );
        for (k, v) in fields {
            line.push_str(&format!(
                ",\"{}\":\"{}\"",
                escape(k),
                escape(&self.redactor.redact_field(k, v))
            ));
        }
        line.push('}');
        self.sink.write_line(&line);
    }

    pub fn info(&self, event: &str, fields: &[(&str, &str)]) {
        self.log(Level::Info, event, fields);
    }

    pub fn warn(&self, event: &str, fields: &[(&str, &str)]) {
        self.log(Level::Warn, event, fields);
    }

    pub fn error(&self, event: &str, fields: &[(&str, &str)]) {
        self.log(Level::Error, event, fields);
    }
}

/// Shares one `Arc<MemSink>` between the telemetry and its creator.
struct MemSinkShim(std::sync::Arc<MemSink>);

impl Sink for MemSinkShim {
    fn write_line(&self, line: &str) {
        self.0.write_line(line);
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// UTC ISO-8601 from the system clock, second resolution, no deps.
/// (Log timestamps are for correlation, not protocol windows — the
/// protocol's ±120 s checks live in modelswarm-identity with real
/// RFC3339 parsing.)
fn iso_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_line_is_valid_json_and_redacted() {
        let (t, mem) = Telemetry::memory();
        t.info(
            "request_completed",
            &[
                ("request_id", "req-123"),
                ("prompt", "tell me a secret"),
                ("hf_token", "hf_ABCDEFGHIJKLMNOP"),
                ("peer_id", "12D3Koo"),
            ],
        );
        let lines = mem.snapshot();
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert!(line.contains("\"event\":\"request_completed\""));
        assert!(line.contains("req-123"));
        assert!(!line.contains("tell me a secret"));
        assert!(!line.contains("hf_ABCDEFGHIJKLMNOP"));
        assert!(line.starts_with('{') && line.ends_with('}'));
    }

    #[test]
    fn metrics_snapshot_shape() {
        let (t, _mem) = Telemetry::memory();
        t.metrics.incr("requests");
        t.metrics.incr("requests");
        t.metrics.observe_ms("round_ms", 10.0);
        t.metrics.observe_ms("round_ms", 30.0);
        let snap = t.metrics.snapshot();
        assert!(snap.contains("\"requests\":2"));
        assert!(snap.contains("\"round_ms_count\":2"));
        assert!(snap.contains("\"round_ms_mean_ms\":20"));
    }

    #[test]
    fn iso_now_shape() {
        let ts = iso_now();
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
    }

    #[test]
    fn civil_from_days_known_dates() {
        // epoch anchors: day 0 = 1970-01-01; 2024 is a leap year
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(20_453), (2025, 12, 31));
        assert_eq!(civil_from_days(20_454), (2026, 1, 1));
        assert_eq!(civil_from_days(20_731), (2026, 10, 5));
    }

    #[test]
    fn file_sink_appends_jsonl() {
        let dir = std::env::temp_dir().join(format!("msp-tel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.jsonl");
        let _ = std::fs::remove_file(&path);
        {
            let sink = FileSink::open(&path).unwrap();
            let t = Telemetry::with_sink(Box::new(sink));
            t.info("boot", &[("phase", "test")]);
        }
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"event\":\"boot\""));
        assert!(content.ends_with('\n'));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn concurrent_logging_is_safe() {
        let (t, mem) = Telemetry::memory();
        let t = std::sync::Arc::new(t);
        let mut handles = Vec::new();
        for i in 0..4 {
            let t = t.clone();
            handles.push(std::thread::spawn(move || {
                for j in 0..100 {
                    t.info(
                        "threaded",
                        &[("worker", "ok"), ("count", &format!("{i}-{j}"))],
                    );
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(mem.snapshot().len(), 400);
    }
}
