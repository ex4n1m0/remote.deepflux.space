# Performance-counter schema (M0 contract; executable in `crates/diagnostics`)

This document is the contract M1–M6 code against. The Rust encoding is
`crates/diagnostics/src/lib.rs` (`FrameTiming`, `QueueSample`,
`CounterRecord`, `PerfSink`); the JSON field names there are pinned by test
and are as snake_case-stable as the signaling schema. **Changing this schema
is a contract change**: update the crate, this doc, and every consumer in the
same package.

Source-plan rule being implemented: *instrument timestamps at capture, encode
submission/completion, packet send, packet receive, decode completion, and
presentation; optimize from measured stage latency rather than aggregate
FPS.* A perf-relevant patch ships a number from these counters or a
benchmark, not an adjective (AGENTS.md quality bar).

## Clock domains

Each device records on its **own monotonic clock, zero-based at session
start, in nanoseconds**:

- `Origin::Host` fills `capture_ns`, `encode_submit_ns`, `encode_done_ns`,
  `send_ns`.
- `Origin::Controller` fills `recv_ns`, `decode_done_ns`, `present_ns`.

Never subtract timestamps across domains. Both halves are joined by
`frame_id` (assigned by the host at capture) for offline analysis.
Input-to-visible latency (budget: ≤80 ms LAN / ≤150 ms WAN median) is
computed as controller-side receive→present plus reported transport RTT plus
host-side capture→send — an M5 reporting concern; the schema only guarantees
both halves exist and are joinable.

## FrameTiming

| Field              | Stage                                        | Origin     |
|--------------------|----------------------------------------------|------------|
| `origin`           | which device recorded                        | both       |
| `frame_id`         | host-assigned id, echoed by controller       | both       |
| `capture_ns`       | DXGI `AcquireNextFrame` returned             | Host       |
| `encode_submit_ns` | frame handed to encoder                      | Host       |
| `encode_done_ns`   | encoded packet(s) produced                   | Host       |
| `send_ns`          | packet(s) handed to RTP/transport            | Host       |
| `recv_ns`          | first packet of frame received               | Controller |
| `decode_done_ns`   | decoder produced the frame                   | Controller |
| `present_ns`       | swapchain `Present` returned                 | Controller |

Missing stages are `None`, never `0`. A stage gap that persists is itself a
reportable defect (a dropped frame somewhere upstream).

## QueueSample — queue-depth gauges

Every bounded queue (invariant 3) reports `depth`, `capacity`, `at_ns` on a
cadence (≥1 Hz steady-state; on every change while unstable):

| `QueueKind`            | Queue                                        | Budget                  |
|------------------------|----------------------------------------------|-------------------------|
| `capture_to_encode`    | acquired frames awaiting encode              | depth ≤ 1 steady state  |
| `encode_to_send`       | encoded packets awaiting transport send      | depth ≤ 1 steady state  |
| `recv_to_decode`       | received packets awaiting decode             | bounded, drop-oldest    |
| `decode_to_present`    | decoded frames awaiting present              | depth ≤ 1 steady state  |
| `channel_input_fast`   | local send queue, `input-fast`               | newest-wins             |
| `channel_input_reliable` | local send queue, `input-reliable`         | bounded, error on full  |
| `channel_control`      | local send queue, `control`                  | bounded, error on full  |
| `channel_cursor`       | local send queue, `cursor`                  | newest-wins             |

`depth == capacity` sustained is the visible symptom of a backpressure
failure and is a release blocker in M6. Sustained `depth > 1` on the frame
queues is an M1 gate failure.

## CounterRecord

```json
{ "kind": "frame_timing", "origin": "host", "frame_id": 42, "capture_ns": 1000, ... }
{ "kind": "queue_sample", "queue": "capture_to_encode", "depth": 1, "capacity": 3, "at_ns": 99 }
```

Additive variants/fields only within a milestone review; removing or renaming
anything requires an explicit schema-version note in this file.

## PerfSink

Stages emit through `PerfSink::record`. Requirements:

- Implementations must be cheap and non-blocking on the hot path; formatting
  happens off-thread or off-line.
- Sinks are bounded (`BoundedMemorySink` keeps the last N records; the M1
  JSONL file sink rotates). No unbounded growth during the 60-minute soak.
- Counter emission must not itself perturb the measured stages (M6 audits
  this: compare stage distributions with sinks on/off).

## Milestone obligations

- **M1**: capture/encode/decode/present timestamps + the four frame queues,
  in the local loop binary; latency report in `docs/reports/`.
- **M2**: `recv_ns`/`send_ns` wired to the transport; channel queue gauges.
- **M4**: diagnostics overlay reads these records (aggregates only through
  typed Tauri commands — counters are fine over IPC, frames are not).
- **M5**: RTT/loss joined per frame; congestion response measured against
  the gauges.
- **M6**: soak gate consumes the full schema; pass/fail from distributions,
  never from FPS alone.
