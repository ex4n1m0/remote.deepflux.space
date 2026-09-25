# Performance-counter schema (M0 contract; executable in `crates/diagnostics`)

This document is the contract M1–M6 code against. The Rust encoding is
`crates/diagnostics/src/lib.rs` (`FrameTiming`, `QueueSample`,
`ResourceSample`, `LinkSample`, `CounterRecord`, `PerfSink`); the JSON field
names there are pinned by test and are as snake_case-stable as the signaling
schema. **Changing this schema is a contract change**: update the crate, this
doc, and every consumer in the same package. (M0 QA audit additions —
session scoping, drop counters, resource/link kinds, report format — are
findings F5/F6/F7/F8 of `docs/reports/m0-qa-audit.md`.)

Source-plan rule being implemented: *instrument timestamps at capture, encode
submission/completion, packet send, packet receive, decode completion, and
presentation; optimize from measured stage latency rather than aggregate
FPS.* A perf-relevant patch ships a number from these counters or a
benchmark, not an adjective (AGENTS.md quality bar).

## Clock domains

Each device records on its **own monotonic clock, zero-based at session
start, in nanoseconds** — this applies to every `*_ns` field in every record,
including `QueueSample::at_ns`:

- `Origin::Host` fills `capture_ns`, `encode_submit_ns`, `encode_done_ns`,
  `send_ns`.
- `Origin::Controller` fills `recv_ns`, `decode_done_ns`, `present_ns`.

Never subtract timestamps across domains. Both halves are joined by
`frame_id` (host-assigned at capture; see "Frame-id carriage" below for how
the controller learns it over the real transport) **and** `session_id`.
Input-to-visible latency (budget: ≤80 ms LAN / ≤150 ms WAN median) is
computed as controller-side receive→present plus reported transport RTT plus
host-side capture→send — an M5 reporting concern; the schema only guarantees
both halves exist and are joinable. **Known gap (F8, doc note):** this
formula omits controller input→send and host inject→capture (one capture
interval plus injection latency, plausibly 8–20 ms at 60 fps). M5 reports
must label it a *proxy*; additive input-path counters (`input_send_ns` on the
controller, `input_inject_ns` on the host) land with M2's input wiring.

## Session scoping (F7)

Every record carries `session_id` — the protocol session id
(`protocol::signaling::SessionId`, controller-minted). M1's in-process local
loop has no signaling session and assigns a synthetic id (`"local-loop"`).
This keeps a 60-minute soak that spans reconnects (M6 gate) from aliasing
frames of two sessions when `frame_id` resets.

## FrameTiming

| Field              | Stage                                        | Origin     |
|--------------------|----------------------------------------------|------------|
| `session_id`       | protocol (or synthetic) session              | both       |
| `origin`           | which device recorded                        | both       |
| `frame_id`         | host-assigned id, echoed by controller       | both       |
| `capture_ns`       | DXGI `AcquireNextFrame` returned             | Host       |
| `encode_submit_ns` | frame handed to encoder                      | Host       |
| `encode_done_ns`   | encoded packet(s) produced                   | Host       |
| `send_ns`          | packet(s) handed to RTP/transport            | Host       |
| `recv_ns`          | first packet of frame received               | Controller |
| `decode_done_ns`   | decoder produced the frame                   | Controller |
| `present_ns`       | swapchain `Present` returned                 | Controller |

Missing stages are `None`, never `0`. **Emission timing is pinned:** the host
emits one record when `send_ns` is filled; the controller emits when
`present_ns` is filled. Dropped frames leave no `FrameTiming` record — they
are accounted for by the queue `dropped`/`replaced` counters instead, so
frame-gap accounting works even under loss.

### Frame-id carriage over the transport (F4 decision)

In M1's in-process loop the frame handoff types carry `frame_id` directly.
Over the real transport the controller learns it via an **RTP header
extension** carrying the 64-bit `frame_id`, set per packet by the host (M2
implements; ADR-002 records the decision and the fallback — a `control`-
channel frame-mark message — if the webrtc-rs header-extension API proves
impractical). SEI embedding is rejected: it couples diagnostics to codec
particulars.

## QueueSample — queue-depth gauges and drop counters (F5)

Every bounded queue (invariant 3) reports per sample: `depth`, `capacity`,
and the cumulative-since-session-start `high_water`, `dropped` (items dropped
for capacity/backpressure — obsolete frame drops included), and `replaced`
(newest-wins overwrites on `input-fast`, `cursor`, and frame-drop points).
Cumulative counters are difference-able into any reporting window offline.

| `QueueKind`              | Queue                                      | Budget                  |
|--------------------------|--------------------------------------------|-------------------------|
| `capture_to_encode`      | acquired frames awaiting encode            | depth ≤ 1 steady state  |
| `encode_to_send`         | encoded packets awaiting transport send    | depth ≤ 1 steady state  |
| `recv_to_decode`         | received packets awaiting decode           | bounded, drop-oldest    |
| `decode_to_present`      | decoded frames awaiting present            | depth ≤ 1 steady state  |
| `channel_input_fast`     | local send queue, `input-fast`             | newest-wins             |
| `channel_input_reliable` | local send queue, `input-reliable`         | bounded, error on full  |
| `channel_control`        | local send queue, `control`                | bounded, error on full  |
| `channel_cursor`         | local send queue, `cursor`                | newest-wins             |

**Sampling cadence (binding):**

- The four **frame queues** are sampled on **every depth change** — and at
  least once per frame during measurement runs. At 1080p60 that is 60+ samples
  per queue per second; a 1 Hz snapshot would hide exactly the 0→2→0
  oscillation the "depth ≤ 1 steady state" gate exists to catch.
- The four **channel queues** are sampled at ≥1 Hz plus on every depth change
  while any of them is non-empty. (M6 F63: since an enqueue→drain burst
  routinely completes inside one poll interval — the M5 matrix polled at
  ~2–5 ms and still recorded `depth: 0` everywhere while high-water hit
  30/32 — the depth changes are recorded INSIDE the transport's bounded
  queues (`Transport::take_channel_depth_trail`, a per-slot ring) and the
  engine/rig loops drain that trail every iteration, so every change
  becomes a sample at its true depth.)
- `depth == capacity` sustained, or monotonic growth of `dropped`/`replaced`
  on the frame queues during steady state, is the visible symptom of a
  backpressure failure and is a release blocker in M6.

**Definitions (binding, for the M1/M6 gates):**

- *Pipeline start*: the moment `StartStreaming`/`StartRendering` executes.
- *Warm-up*: the first 60 s after pipeline start. Excluded from gate
  judgments; still recorded.
- *Steady state*: any 60 s window after warm-up in which no queue hit
  capacity, no stage reported a drop (`dropped`/`replaced` delta > 0 on frame
  queues), and no display-change/device-loss event was reported. Windows not
  meeting this are *unstable* and must be reported as such, never silently
  averaged in.
- *Cap-1 refinement (M1 QA F15)*: for queues with capacity 1 — the
  newest-wins frame slots — `depth == capacity` between a push and its
  pop is normal per-frame residency, not saturation (measured: ~50% of
  `capture_to_encode` samples sit at depth 1 in a healthy 1080p60 run).
  The `depth == capacity sustained` blocker applies to cap-1 queues only
  when the queue **stops draining**: at capacity for ≥95% of a window's
  samples *and* zero depth-0 samples in that window (bounded-residency
  failure), or sustained growth of `dropped`/`replaced`. For capacity ≥ 2
  queues the original wording stands. The cap-1 gate remains
  high-water ≤ 1 with per-window drop deltas of 0.

## ResourceSample and LinkSample (F7)

Soak and WAN-matrix evidence beyond frame timing (all fields `Option`;
`None` means "counter unavailable", never zero):

- `ResourceSample`: `cpu_percent`, `gpu_percent`,
  `memory_working_set_bytes` (must stay flat across the 60-minute soak),
  `gpu_memory_bytes`, `origin`, `at_ns`. Cadence ≥1 Hz per device.
- `LinkSample`: `send_bitrate_kbps` / `recv_bitrate_kbps` (M2 RTP counters),
  `rtt_ms`, `loss_percent` (M5 transport statistics). Cadence ≥1 Hz while
  connected. **2026-09-25 (M2 QA F30, explicit change):** `rtt_ms` changed
  `u32` → `f32` — loopback/LAN round trips are sub-millisecond and the
  integer field serialized every committed M2 loopback sample as `0`
  (measured RTT 0.18–0.2 ms). `f32` matches `loss_percent`'s numeric
  policy; JSON consumers reading the field as a number are unaffected.
  **2026-09-25 (M5, RD-013, additive optional fields):**
  `available_bandwidth_kbps` (sender-side congestion estimate — `rtc`'s
  GCC over TWCC feedback; `None` when the transport runs without
  congestion control), `remote_loss_percent`, and `remote_rtt_ms`
  (receiver-reported RTCP-RR projection of the outbound stream — the
  sender's media-path loss/RTT signals, distinct from the ICE pair's
  `rtt_ms`). Additive within the version per the policy above.

## CounterRecord

```json
{ "kind": "frame_timing", "session_id": "device-a-ctrl-2", "origin": "host", "frame_id": 42, "capture_ns": 1000, ... }
{ "kind": "queue_sample", "session_id": "device-a-ctrl-2", "queue": "capture_to_encode", "depth": 1, "capacity": 3, "high_water": 2, "dropped": 4, "replaced": 5, "at_ns": 99 }
{ "kind": "resource_sample", "session_id": "device-a-ctrl-2", "origin": "host", "cpu_percent": 31.5, ... }
{ "kind": "link_sample", "session_id": "device-a-ctrl-2", "send_bitrate_kbps": 9500, "rtt_ms": 12.25, ... }
```

Additive variants/fields only within a milestone review; removing or renaming
anything requires an explicit schema-version note in this file.

## PerfSink

Stages emit through `PerfSink::record`. Requirements:

- Implementations must be cheap and non-blocking on the hot path; formatting
  happens off-thread or off-line.
- Sinks are bounded (`BoundedMemorySink` keeps the last N records). **A
  bounded memory sink must not be the recording mechanism for a latency
  report** — it silently loses the distribution tail; report runs record to
  the JSONL file sink.
- Counter emission must not itself perturb the measured stages (M6 audits
  this: compare stage distributions with sinks on/off).

## Latency report format (F6, binding for the M1 gate)

- **Raw**: one JSONL file, one `CounterRecord` per line, schema-exact. Name:
  `docs/reports/<milestone>-<yyyymmdd>-<n>.jsonl` (e.g.
  `m1-local-loop-20260101-1.jsonl`). The recording run must retain **all**
  records for the reported window — no in-memory truncation. Sink rotation:
  split at 128 MiB into `.jsonl.1`, `.jsonl.2`, ... (tooling safety only; all
  parts retained for the run). Gzip after the run. Sizing headroom: 60 fps ×
  30 min ≈ 108k frames × 2 `FrameTiming` + per-change queue samples ≈
  70–100 MB raw — acceptable on disk.
- **Summary**: `docs/reports/<same-stem>-summary.json`, generated from the
  JSONL, containing per stage (capture→encode, encode submit→done,
  encode→send, recv→decode, decode→present, and host-half/controller-half
  totals): **p50 / p95 / p99 / max**, computed over fixed 60 s windows with
  warm-up excluded, plus: frame-gap/drop accounting (frames emitted vs.
  presented, `dropped`/`replaced` deltas per queue), per-queue high-water,
  resource-sample ranges, and an explicit `unstable_windows` list with
  reasons. Pass/fail lines quote the budget and the measured number
  side by side — a verdict without its number is not a gate.
- **Retention**: summaries are kept forever (small); raw JSONL gzipped, keep
  the current and previous gate run per milestone, delete older.

## Milestone obligations

- **M1**: capture/encode/decode/present timestamps + the four frame queues
  with the F5 cadence/counters, in the local loop binary; latency report in
  the F6 format under `docs/reports/`.
- **M2**: `recv_ns`/`send_ns` wired to the transport; channel queue gauges;
  the F4 frame-id header extension; input-path counters (F8).
- **M3**: nothing (control plane carries no perf data).
- **M4**: diagnostics overlay reads these records (aggregates only through
  typed Tauri commands — counters are fine over IPC, frames are not).
- **M5**: RTT/loss joined per frame via `LinkSample`; congestion response
  measured against the gauges; input-to-visible reported with the F8 proxy
  label until the input counters land. (Delivered: `LinkSample` now carries
  the GCC estimate + RR loss/RTT above; the M5 matrix JSONL under
  `docs/reports/data/m5-matrix/` is the reference recording.)
- **M6**: soak gate consumes the full schema (session-scoped); pass/fail from
  distributions, never from FPS alone.
