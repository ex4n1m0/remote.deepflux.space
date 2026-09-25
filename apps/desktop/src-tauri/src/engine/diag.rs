//! Diagnostics aggregation for the UI overlay (RD-012, perf-schema M4
//! obligation: "diagnostics overlay reads these records (aggregates only
//! through typed Tauri commands — counters are fine over IPC, frames are
//! not)").
//!
//! [`DiagAgg`] is an in-process [`PerfSink`]: pipelines tee their
//! schema-exact `CounterRecord`s into it (alongside the JSONL report) and
//! it maintains bounded ring buffers per stage + latest queue/link state.
//! The snapshot it produces is numbers and short strings only — it is the
//! only diagnostics surface that crosses Tauri IPC, and it is structurally
//! incapable of carrying frame or input payloads.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Instant;

use diagnostics::{CounterRecord, Origin, PerfSink, QueueKind};
use serde::Serialize;

/// Samples retained per stage for percentiles (bounded; invariant 3).
const STAGE_RING: usize = 512;
/// Window for fps estimation (records seen in the last N ms).
const FPS_WINDOW_MS: u128 = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    CaptureToEncode,
    Encode,
    EncodeToSend,
    RecvToDecode,
    DecodeToPresent,
}

impl Stage {
    fn name(self) -> &'static str {
        match self {
            Stage::CaptureToEncode => "capture_to_encode",
            Stage::Encode => "encode",
            Stage::EncodeToSend => "encode_to_send",
            Stage::RecvToDecode => "recv_to_decode",
            Stage::DecodeToPresent => "decode_to_present",
        }
    }
}

#[derive(Default)]
struct StageRing {
    samples_ns: Vec<u64>,
    head: usize,
    filled: usize,
}

impl StageRing {
    fn push(&mut self, ns: u64) {
        if self.samples_ns.len() < STAGE_RING {
            self.samples_ns.push(ns);
        } else {
            self.samples_ns[self.head] = ns;
            self.head = (self.head + 1) % STAGE_RING;
        }
        self.filled = (self.filled + 1).min(STAGE_RING);
    }

    fn percentile_ns(&self, q: f64) -> Option<u64> {
        if self.samples_ns.is_empty() {
            return None;
        }
        let mut sorted = self.samples_ns.clone();
        sorted.sort_unstable();
        let idx = ((q * (sorted.len() - 1) as f64).round() as usize).min(sorted.len() - 1);
        Some(sorted[idx])
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct StageStat {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct LinkStat {
    pub send_bitrate_kbps: Option<u32>,
    pub recv_bitrate_kbps: Option<u32>,
    pub rtt_ms: Option<f32>,
    pub loss_percent: Option<f32>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct QueueStat {
    pub depth: u32,
    pub capacity: u32,
    pub high_water: u32,
    pub dropped: u64,
    pub replaced: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct InputStat {
    pub applied: u64,
    pub suppressed: u64,
    pub gaps: u64,
    pub all_keys_up: u64,
    pub held: usize,
    pub inject_errors: u64,
}

/// The overlay snapshot. Numbers and id strings only (invariant 1).
#[derive(Debug, Clone, Serialize)]
pub struct DiagSnapshot {
    pub session_id: Option<String>,
    pub origin: &'static str,
    pub stages_ms: BTreeMap<String, StageStat>,
    pub fps: BTreeMap<String, f64>,
    pub link: Option<LinkStat>,
    pub queues: BTreeMap<String, QueueStat>,
    pub input: InputStat,
    pub encoder: Option<String>,
    pub encoder_kind: Option<String>,
    pub encoder_rebuilds: u64,
    pub viewer_input_dropped: u64,
}

#[derive(Default)]
struct AggState {
    stages: BTreeMap<&'static str, StageRing>,
    /// (arrival Instant, stage label) for fps estimation.
    events: Vec<(Instant, &'static str)>,
    queues: BTreeMap<String, QueueStat>,
    link: Option<LinkStat>,
}

impl AggState {
    fn push_stage(&mut self, stage: Stage, ns: u64) {
        self.stages
            .entry(stage.name())
            .or_default()
            .push(ns.saturating_sub(0));
        self.events.push((Instant::now(), stage.name()));
    }

    fn count_event(&mut self, label: &'static str) {
        self.events.push((Instant::now(), label));
        // Bound the event log even at extreme rates (fps window needs only
        // 2 s of history; anything older is pruned on read).
        if self.events.len() > 16_384 {
            self.events.drain(..8_192);
        }
    }
}

/// Shared aggregation sink. `Send + Sync` (one mutex).
#[derive(Default)]
pub struct DiagAgg {
    state: Mutex<AggState>,
    input: Mutex<InputStat>,
    encoder: Mutex<(Option<String>, Option<String>)>,
    encoder_rebuilds: std::sync::atomic::AtomicU64,
    viewer_input_dropped: std::sync::atomic::AtomicU64,
    origin: Mutex<&'static str>,
}

impl DiagAgg {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_origin(&self, origin: Origin) {
        let label = match origin {
            Origin::Host => "host",
            Origin::Controller => "controller",
        };
        *self.origin.lock().expect("diag origin") = label;
    }

    pub fn set_encoder(&self, describe: String, kind: Option<String>) {
        *self.encoder.lock().expect("diag encoder") = (Some(describe), kind);
    }

    pub fn bump_encoder_rebuild(&self) {
        self.encoder_rebuilds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn rebuild_count(&self) -> u64 {
        self.encoder_rebuilds
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_viewer_input_dropped(&self, n: u64) {
        self.viewer_input_dropped
            .store(n, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_input(&self, stat: InputStat) {
        *self.input.lock().expect("diag input") = stat;
    }

    pub fn snapshot(&self, session_id: Option<String>) -> DiagSnapshot {
        let mut state = self.state.lock().expect("diag state");
        let now = Instant::now();
        state
            .events
            .retain(|(t, _)| now.duration_since(*t).as_millis() <= FPS_WINDOW_MS);
        let window_secs = FPS_WINDOW_MS as f64 / 1000.0;

        let mut fps = BTreeMap::new();
        {
            // Per-label counts over the window. Stage labels double as
            // throughput markers (a `decode_to_present` sample == one
            // presented frame, `encode_to_send` == one encoded frame, ...).
            let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
            for (_, label) in &state.events {
                *counts.entry(label).or_default() += 1;
            }
            let present_fps =
                counts.get("decode_to_present").copied().unwrap_or(0) as f64 / window_secs;
            let encode_fps =
                counts.get("encode_to_send").copied().unwrap_or(0) as f64 / window_secs;
            if encode_fps > 0.0 {
                fps.insert("encode".to_owned(), encode_fps);
            }
            if present_fps > 0.0 {
                fps.insert("present".to_owned(), present_fps);
            }
        }

        let stages_ms = state
            .stages
            .iter()
            .map(|(name, ring)| {
                (
                    (*name).to_owned(),
                    StageStat {
                        p50_ms: ring.percentile_ns(0.50).map(ns_to_ms).unwrap_or_default(),
                        p95_ms: ring.percentile_ns(0.95).map(ns_to_ms).unwrap_or_default(),
                        count: ring.filled as u32,
                    },
                )
            })
            .collect();

        // Hoisted: two `encoder.lock()` temporaries inside one struct
        // literal would both stay alive until the statement ends and
        // deadlock the (non-reentrant) mutex on the second lock.
        let (encoder_describe, encoder_kind) = self.encoder.lock().expect("diag encoder").clone();
        let input = *self.input.lock().expect("diag input");
        let origin = *self.origin.lock().expect("diag origin");
        DiagSnapshot {
            session_id,
            origin,
            stages_ms,
            fps,
            link: state.link,
            queues: state.queues.clone(),
            input,
            encoder: encoder_describe,
            encoder_kind,
            encoder_rebuilds: self.rebuild_count(),
            viewer_input_dropped: self
                .viewer_input_dropped
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

fn ns_to_ms(ns: u64) -> f64 {
    (ns as f64) / 1e6
}

fn queue_name(kind: QueueKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{kind:?}"))
}

impl DiagAgg {
    /// Ingest one record (interior mutability; shared across threads).
    pub fn ingest(&self, record: CounterRecord) {
        let mut state = self.state.lock().expect("diag state");
        match record {
            CounterRecord::FrameTiming(t) => {
                let stage = |a: u64, b: u64| b.saturating_sub(a);
                match t.origin {
                    Origin::Host => {
                        if let (Some(c), Some(s)) = (t.capture_ns, t.encode_submit_ns) {
                            state.push_stage(Stage::CaptureToEncode, stage(c, s));
                            state.count_event("capture_to_encode");
                        }
                        if let (Some(s), Some(d)) = (t.encode_submit_ns, t.encode_done_ns) {
                            state.push_stage(Stage::Encode, stage(s, d));
                        }
                        if let (Some(d), Some(x)) = (t.encode_done_ns, t.send_ns) {
                            state.push_stage(Stage::EncodeToSend, stage(d, x));
                        }
                    }
                    Origin::Controller => {
                        if let (Some(r), Some(d)) = (t.recv_ns, t.decode_done_ns) {
                            state.push_stage(Stage::RecvToDecode, stage(r, d));
                        }
                        if let (Some(d), Some(p)) = (t.decode_done_ns, t.present_ns) {
                            state.push_stage(Stage::DecodeToPresent, stage(d, p));
                        }
                    }
                }
            }
            CounterRecord::QueueSample(q) => {
                state.queues.insert(
                    queue_name(q.queue),
                    QueueStat {
                        depth: q.depth,
                        capacity: q.capacity,
                        high_water: q.high_water,
                        dropped: q.dropped,
                        replaced: q.replaced,
                    },
                );
            }
            CounterRecord::LinkSample(l) => {
                state.link = Some(LinkStat {
                    send_bitrate_kbps: l.send_bitrate_kbps,
                    recv_bitrate_kbps: l.recv_bitrate_kbps,
                    rtt_ms: l.rtt_ms,
                    loss_percent: l.loss_percent,
                });
            }
            CounterRecord::ResourceSample(_) => {
                // Not part of the compact overlay (M6 soak owns resources).
            }
        }
    }
}

impl PerfSink for DiagAgg {
    fn record(&mut self, record: CounterRecord) {
        self.ingest(record);
    }
}

/// Tee: every record goes to the JSONL report (raw evidence) and the
/// aggregation state (overlay). Cheap — both sides are bounded/non-blocking.
pub struct TeeSink {
    pub jsonl: Box<dyn PerfSink + Send>,
    pub agg: std::sync::Arc<DiagAgg>,
}

impl TeeSink {
    pub fn new(jsonl: Box<dyn PerfSink + Send>, agg: std::sync::Arc<DiagAgg>) -> Self {
        Self { jsonl, agg }
    }
}

impl PerfSink for TeeSink {
    fn record(&mut self, record: CounterRecord) {
        self.agg.ingest(record.clone());
        self.jsonl.record(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diagnostics::{FrameTiming, QueueSample};

    #[test]
    fn percentiles_track_ring() {
        let mut ring = StageRing::default();
        for i in 0..STAGE_RING as u64 {
            ring.push(i * 1_000);
        }
        assert_eq!(ring.percentile_ns(0.50), Some(256_000));
        assert_eq!(ring.percentile_ns(0.95), Some(485_000));
        assert_eq!(ring.filled, STAGE_RING);
        // Wrap: the newest STAGE_RING values replace the oldest — after
        // 1_000 pushes the retained window is 488..=999.
        for i in STAGE_RING as u64..1_000 {
            ring.push(i * 1_000);
        }
        assert_eq!(ring.percentile_ns(0.50), Some(744_000));
        assert_eq!(ring.percentile_ns(0.95), Some(973_000));
    }

    #[test]
    fn snapshot_aggregates_frame_timings_and_queues() {
        let agg = DiagAgg::new();
        agg.set_origin(Origin::Host);
        for i in 0..100u64 {
            agg.ingest(CounterRecord::FrameTiming(FrameTiming {
                session_id: "s".into(),
                origin: Origin::Host,
                frame_id: i,
                capture_ns: Some(i * 10_000_000),
                encode_submit_ns: Some(i * 10_000_000 + 2_000_000),
                encode_done_ns: Some(i * 10_000_000 + 6_000_000),
                send_ns: Some(i * 10_000_000 + 7_000_000),
                recv_ns: None,
                decode_done_ns: None,
                present_ns: None,
            }));
        }
        agg.ingest(CounterRecord::QueueSample(QueueSample {
            session_id: "s".into(),
            queue: QueueKind::CaptureToEncode,
            depth: 1,
            capacity: 1,
            high_water: 1,
            dropped: 3,
            replaced: 5,
            at_ns: 1,
        }));
        let snap = agg.snapshot(Some("s".to_owned()));
        assert_eq!(snap.origin, "host");
        let cap = snap.stages_ms.get("capture_to_encode").expect("stage");
        assert!((cap.p50_ms - 2.0).abs() < 0.01, "p50 {cap:?}");
        let enc = snap.stages_ms.get("encode").expect("stage");
        assert!((enc.p50_ms - 4.0).abs() < 0.01, "p50 {enc:?}");
        let q = snap.queues.get("capture_to_encode").expect("queue");
        assert_eq!((q.depth, q.capacity, q.dropped), (1, 1, 3));
        assert!(snap.fps.get("encode").is_some_and(|v| *v > 0.0));
    }
}
