//! # `diagnostics` — performance-counter schema (executable contract)
//!
//! These types are the Rust encoding of `docs/perf-counter-schema.md`, which
//! is the contract M1–M6 code against. The rule from the source plan:
//! *instrument timestamps at capture, encode submission/completion, packet
//! send, packet receive, decode completion, and presentation; optimize from
//! measured stage latency rather than aggregate FPS.*
//!
//! Design constraints baked in:
//!
//! * **Two clock domains.** `Origin::Host` records capture/encode/send on the
//!   host's monotonic clock; `Origin::Controller` records recv/decode/present
//!   on the controller's. Never subtract across domains — the fields are
//!   `Option<u64>` precisely because each side only fills its own stages.
//!   Input-to-visible latency is computed per side plus reported RTT (M5's
//!   problem; the schema just records both halves, linked by `frame_id`).
//! * **Session scoping (QA F7).** Every record carries the `session_id` from
//!   `protocol::signaling` (the controller-minted session id). A soak that
//!   spans reconnects must not alias frames from two sessions; M1's local
//!   loop assigns a synthetic id (e.g. `"local-loop"`).
//! * **Queue gauges, not just timestamps.** Every bounded queue reports
//!   depth+capacity plus cumulative high-water/dropped/replaced counters
//!   (invariant 3). A queue silently at capacity — or silently dropping — is
//!   a backpressure bug you can see here (QA F5).
//! * **Resource and link samples (QA F7).** CPU/GPU/memory and
//!   bitrate/RTT/loss have record kinds, so the soak and WAN gates have
//!   evidence beyond frame timing.
//! * **A narrow sink trait.** Stages emit through [`PerfSink`];
//!   implementations must be cheap and non-blocking on the hot path; the
//!   formatting happens off-thread or off-line.
//!
//! Schema changes are contract changes: update this file, the doc, and the
//! consumers in the same package, and pin the JSON field names with a test.

use serde::{Deserialize, Serialize};

/// Which device produced a record. Serialization is part of the schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Host,
    Controller,
}

/// Per-frame timestamps, nanoseconds on the recording device's monotonic
/// clock, zero-based at session start. Host fills
/// `capture_ns`/`encode_submit_ns`/`encode_done_ns`/`send_ns`; controller
/// fills `recv_ns`/`decode_done_ns`/`present_ns`. Absent stages are `None`
/// (never zero-as-missing).
///
/// Emission timing (pinned so windows never double-count a frame): the host
/// emits one record when `send_ns` is filled; the controller emits when
/// `present_ns` is filled (dropped frames therefore leave no record — they
/// are visible in the queue `dropped` counters instead).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameTiming {
    /// Protocol session id (`protocol::signaling::SessionId`); synthetic for
    /// local-loop diagnostics (QA F7).
    pub session_id: String,
    pub origin: Origin,
    /// Shared id assigned by the host at capture; the controller echoes it
    /// back so the two halves can be joined when computing end-to-end views.
    pub frame_id: u64,
    /// Desktop frame acquired (DXGI AcquireNextFrame returned).
    pub capture_ns: Option<u64>,
    /// Frame handed to the encoder.
    pub encode_submit_ns: Option<u64>,
    /// Encoded packet(s) produced.
    pub encode_done_ns: Option<u64>,
    /// Packet(s) handed to the transport (RTP send).
    pub send_ns: Option<u64>,
    /// First packet of the frame received from the transport.
    pub recv_ns: Option<u64>,
    /// Decoder produced the frame.
    pub decode_done_ns: Option<u64>,
    /// Frame presented to the swapchain (D3D11 Present returned).
    pub present_ns: Option<u64>,
}

/// The bounded queues that must be gauged. Adding a queue here is a contract
/// change (docs update + consumer update).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueKind {
    /// Host: acquired frames awaiting encode. Budget: depth ≤ 1 steady state.
    CaptureToEncode,
    /// Host: encoded packets awaiting transport send.
    EncodeToSend,
    /// Controller: received packets awaiting decode (jitter-adjacent).
    RecvToDecode,
    /// Controller: decoded frames awaiting present.
    DecodeToPresent,
    /// Transport data channels — depth of the local send queue per channel.
    ChannelInputFast,
    ChannelInputReliable,
    ChannelControl,
    ChannelCursor,
}

/// One queue-depth sample with cumulative lifetime counters (QA F5).
///
/// `at_ns` uses the same per-device monotonic, zero-based-at-session-start
/// clock as [`FrameTiming`]. Sampling cadence (doc contract): the four frame
/// queues are sampled on **every depth change** (≥ once per frame during
/// measurement runs); the channel queues at ≥1 Hz plus on change. The
/// cumulative counters make drop/backpressure events measurable even between
/// samples: `high_water` is the max depth, `dropped` counts items dropped for
/// capacity/backpressure, `replaced` counts newest-wins overwrites — all
/// since session start, so any reporting window can difference them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueSample {
    pub session_id: String,
    pub queue: QueueKind,
    pub depth: u32,
    pub capacity: u32,
    /// Max observed depth since session start.
    pub high_water: u32,
    /// Items dropped (queue full / obsolete frame dropped) since session
    /// start. Sustained growth here is the measurable face of invariant 3.
    pub dropped: u64,
    /// Newest-wins overwrites since session start (`input-fast`, `cursor`,
    /// and frame-drop points).
    pub replaced: u64,
    /// Nanoseconds on the sampling device's monotonic clock.
    pub at_ns: u64,
}

/// Machine resource usage (QA F7), for the "bounded memory / no runaway
/// growth" soak evidence and the M6 gate. Fields are `Option` because not
/// every platform exposes every counter; `None` never means zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceSample {
    pub session_id: String,
    pub origin: Origin,
    /// Process CPU utilization, percent of one core (can exceed 100).
    pub cpu_percent: Option<f32>,
    /// GPU utilization, percent (GPU-engine based where available).
    pub gpu_percent: Option<f32>,
    /// Process working set, bytes. Must stay flat over a 60-minute soak.
    pub memory_working_set_bytes: Option<u64>,
    /// GPU memory held by the pipelines, bytes where exposeable.
    pub gpu_memory_bytes: Option<u64>,
    /// Same zero-based monotonic clock as `FrameTiming`.
    pub at_ns: u64,
}

/// Transport link quality (QA F7; RTT/loss filled from M5's transport
/// statistics, bitrate from M2's RTP counters). `Option` for the same reason
/// as [`ResourceSample`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LinkSample {
    pub session_id: String,
    pub send_bitrate_kbps: Option<u32>,
    pub recv_bitrate_kbps: Option<u32>,
    pub rtt_ms: Option<u32>,
    pub loss_percent: Option<f32>,
    /// Same zero-based monotonic clock as `FrameTiming`.
    pub at_ns: u64,
}

/// Everything a stage can report. Extend by adding variants — never repurpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "snake_case"
)]
pub enum CounterRecord {
    FrameTiming(FrameTiming),
    QueueSample(QueueSample),
    ResourceSample(ResourceSample),
    LinkSample(LinkSample),
}

/// Narrow emission boundary for pipeline stages. Implementations must be
/// cheap and non-blocking; the hot path never pays for formatting.
pub trait PerfSink: Send {
    fn record(&mut self, record: CounterRecord);
}

/// A sink that drops everything — the default during bring-up and the
/// zero-cost baseline for benchmarks.
#[derive(Debug, Default)]
pub struct NullSink;

impl PerfSink for NullSink {
    fn record(&mut self, _record: CounterRecord) {}
}

/// In-memory sink for tests and short diagnostics runs. Bounded: keeps the
/// last `capacity` records (invariant 3 — diagnostics must not grow without
/// bound during a soak). For full-distribution latency reports, record to
/// the JSONL file sink instead (M1 obligation, see the schema doc).
#[derive(Debug)]
pub struct BoundedMemorySink {
    records: std::collections::VecDeque<CounterRecord>,
    capacity: usize,
}

impl BoundedMemorySink {
    pub fn new(capacity: usize) -> Self {
        Self {
            records: std::collections::VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    pub fn records(&self) -> impl Iterator<Item = &CounterRecord> {
        self.records.iter()
    }
}

impl PerfSink for BoundedMemorySink {
    fn record(&mut self, record: CounterRecord) {
        if self.records.len() == self.capacity {
            self.records.pop_front();
        }
        self.records.push_back(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_field_names_are_stable_snake_case() {
        let frame = FrameTiming {
            session_id: "device-a-ctrl-2".to_owned(),
            origin: Origin::Host,
            frame_id: 42,
            capture_ns: Some(1_000),
            encode_submit_ns: Some(1_100),
            encode_done_ns: Some(1_900),
            send_ns: Some(2_000),
            recv_ns: None,
            decode_done_ns: None,
            present_ns: None,
        };
        let value = serde_json::to_value(CounterRecord::FrameTiming(frame)).unwrap();
        assert_eq!(value["kind"], "frame_timing");
        assert_eq!(value["session_id"], "device-a-ctrl-2");
        assert_eq!(value["origin"], "host");
        assert_eq!(value["frame_id"], 42);
        assert_eq!(value["capture_ns"], 1_000);
        assert_eq!(value["encode_submit_ns"], 1_100);
        assert_eq!(value["encode_done_ns"], 1_900);
        assert_eq!(value["send_ns"], 2_000);
        assert_eq!(value["recv_ns"], serde_json::Value::Null);

        let sample = CounterRecord::QueueSample(QueueSample {
            session_id: "device-a-ctrl-2".to_owned(),
            queue: QueueKind::CaptureToEncode,
            depth: 1,
            capacity: 3,
            high_water: 2,
            dropped: 4,
            replaced: 5,
            at_ns: 99,
        });
        let value = serde_json::to_value(sample).unwrap();
        assert_eq!(value["kind"], "queue_sample");
        assert_eq!(value["session_id"], "device-a-ctrl-2");
        assert_eq!(value["queue"], "capture_to_encode");
        assert_eq!(value["depth"], 1);
        assert_eq!(value["capacity"], 3);
        assert_eq!(value["high_water"], 2);
        assert_eq!(value["dropped"], 4);
        assert_eq!(value["replaced"], 5);
        assert_eq!(value["at_ns"], 99);
    }

    #[test]
    fn resource_and_link_field_names_are_stable_snake_case() {
        let record = CounterRecord::ResourceSample(ResourceSample {
            session_id: "s".to_owned(),
            origin: Origin::Host,
            cpu_percent: Some(31.5),
            gpu_percent: None,
            memory_working_set_bytes: Some(240 * 1024 * 1024),
            gpu_memory_bytes: None,
            at_ns: 1_000,
        });
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["kind"], "resource_sample");
        assert_eq!(value["session_id"], "s");
        assert_eq!(value["origin"], "host");
        assert_eq!(value["cpu_percent"], 31.5);
        assert_eq!(value["gpu_percent"], serde_json::Value::Null);
        assert_eq!(value["memory_working_set_bytes"], 240 * 1024 * 1024u64);
        assert_eq!(value["gpu_memory_bytes"], serde_json::Value::Null);
        assert_eq!(value["at_ns"], 1_000);

        let record = CounterRecord::LinkSample(LinkSample {
            session_id: "s".to_owned(),
            send_bitrate_kbps: Some(9_500),
            recv_bitrate_kbps: None,
            rtt_ms: Some(12),
            loss_percent: Some(0.2),
            at_ns: 2_000,
        });
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["kind"], "link_sample");
        assert_eq!(value["send_bitrate_kbps"], 9_500);
        assert_eq!(value["recv_bitrate_kbps"], serde_json::Value::Null);
        assert_eq!(value["rtt_ms"], 12);
        // f32 -> JSON keeps the exact f32 value; compare numerically.
        let loss = value["loss_percent"].as_f64().unwrap();
        assert!((loss - 0.2).abs() < 1e-6, "loss_percent drifted: {loss}");
    }

    #[test]
    fn bounded_memory_sink_is_bounded() {
        let mut sink = BoundedMemorySink::new(4);
        for i in 0..100 {
            sink.record(CounterRecord::QueueSample(QueueSample {
                session_id: "s".to_owned(),
                queue: QueueKind::ChannelControl,
                depth: i as u32,
                capacity: 16,
                high_water: i as u32,
                dropped: 0,
                replaced: 0,
                at_ns: i,
            }));
        }
        assert_eq!(sink.records().count(), 4);
        // Keeps the most recent.
        let last = sink.records().last().unwrap();
        assert_eq!(
            match last {
                CounterRecord::QueueSample(s) => s.depth,
                _ => unreachable!(),
            },
            99
        );
    }

    #[test]
    fn records_round_trip_through_json() {
        let records = vec![
            CounterRecord::FrameTiming(FrameTiming {
                session_id: "s".to_owned(),
                origin: Origin::Controller,
                frame_id: 7,
                capture_ns: None,
                encode_submit_ns: None,
                encode_done_ns: None,
                send_ns: None,
                recv_ns: Some(10),
                decode_done_ns: Some(20),
                present_ns: Some(30),
            }),
            CounterRecord::QueueSample(QueueSample {
                session_id: "s".to_owned(),
                queue: QueueKind::DecodeToPresent,
                depth: 0,
                capacity: 2,
                high_water: 1,
                dropped: 0,
                replaced: 0,
                at_ns: 15,
            }),
            CounterRecord::ResourceSample(ResourceSample {
                session_id: "s".to_owned(),
                origin: Origin::Controller,
                cpu_percent: Some(12.0),
                gpu_percent: Some(4.0),
                memory_working_set_bytes: Some(1),
                gpu_memory_bytes: Some(2),
                at_ns: 16,
            }),
            CounterRecord::LinkSample(LinkSample {
                session_id: "s".to_owned(),
                send_bitrate_kbps: Some(1),
                recv_bitrate_kbps: Some(2),
                rtt_ms: Some(3),
                loss_percent: Some(0.0),
                at_ns: 17,
            }),
        ];
        for record in &records {
            let json = serde_json::to_string(record).unwrap();
            let back: CounterRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, record);
        }
    }
}
