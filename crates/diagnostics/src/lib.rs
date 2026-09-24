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
//! * **Queue gauges, not just timestamps.** Every bounded queue in the
//!   pipeline reports depth+capacity on a cadence (invariant 3). A queue
//!   silently at capacity is a latency bug you can see here.
//! * **A narrow sink trait.** Stages emit through [`PerfSink`]; implementations
//!   (in-memory histogram, JSONL file for soak reports) live here in M1+.
//!   Nothing in the hot path formats strings.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameTiming {
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
    /// Transport data channels (`input-fast`, `input-reliable`, `control`,
    /// `cursor`) — depth of the local send queue per channel.
    ChannelInputFast,
    ChannelInputReliable,
    ChannelControl,
    ChannelCursor,
}

/// One queue-depth sample. `depth == capacity` sustained is the visible
/// symptom of a backpressure failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueSample {
    pub queue: QueueKind,
    pub depth: u32,
    pub capacity: u32,
    /// Nanoseconds on the sampling device's monotonic clock.
    pub at_ns: u64,
}

/// Everything a stage can report. Extend by adding variants — never repurpose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "snake_case"
)]
pub enum CounterRecord {
    FrameTiming(FrameTiming),
    QueueSample(QueueSample),
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
/// bound during a soak).
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
        assert_eq!(value["origin"], "host");
        assert_eq!(value["frame_id"], 42);
        assert_eq!(value["capture_ns"], 1_000);
        assert_eq!(value["encode_submit_ns"], 1_100);
        assert_eq!(value["encode_done_ns"], 1_900);
        assert_eq!(value["send_ns"], 2_000);
        assert_eq!(value["recv_ns"], serde_json::Value::Null);

        let sample = CounterRecord::QueueSample(QueueSample {
            queue: QueueKind::CaptureToEncode,
            depth: 1,
            capacity: 3,
            at_ns: 99,
        });
        let value = serde_json::to_value(sample).unwrap();
        assert_eq!(value["kind"], "queue_sample");
        assert_eq!(value["queue"], "capture_to_encode");
        assert_eq!(value["depth"], 1);
        assert_eq!(value["capacity"], 3);
        assert_eq!(value["at_ns"], 99);
    }

    #[test]
    fn bounded_memory_sink_is_bounded() {
        let mut sink = BoundedMemorySink::new(4);
        for i in 0..100 {
            sink.record(CounterRecord::QueueSample(QueueSample {
                queue: QueueKind::ChannelControl,
                depth: i as u32,
                capacity: 16,
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
                queue: QueueKind::DecodeToPresent,
                depth: 0,
                capacity: 2,
                at_ns: 15,
            }),
        ];
        for record in &records {
            let json = serde_json::to_string(record).unwrap();
            let back: CounterRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, record);
        }
    }
}
