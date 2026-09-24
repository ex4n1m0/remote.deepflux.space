# M0 Performance-QA Audit — Contract & Skeleton

- Verdict: **PASS-WITH-FINDINGS**
- Milestone: M0 (RD-001, RD-002, RD-003), gate tag `m0-contract`
- Audited commit: `93f701d` ("M0: workspace skeleton, contracts, session state machines"), clean working tree
- Auditor: `rd-performance-qa` (read-only; only this report was written)
- Date: 2026-09-24
- Scope: PLAN.md §2 invariants, §4 M0 definition, §7 quality bar; source-plan performance
  budgets; perf-counter schema adequacy for the M1 gate; invariant encoding; test
  quality; gate reproducibility. M0 is contract-only — there is no runtime to profile,
  so this audit validates the *measurability contracts* M1–M6 will be judged against.

## 1. Gate reproduction (run by auditor)

Environment: Windows 10.0.26200 x64, Git Bash, rustc 1.98.1 (48a229cea 2026-09-01),
cargo 1.98.1 (797e8a9bc 2026-08-05).

| Step | Command | Result | Wall time |
|---|---|---|---|
| Format | `cargo fmt --all -- --check` | green | 0.14 s |
| Clippy | `scripts/check.sh` (warm) | green, 0 warnings | 0.20 s |
| Tests | `scripts/test.sh` (warm) | green | 0.57 s |
| Cold full gate | `cargo clean` → fmt + check.sh + test.sh | green | 8.3 s |

Test tally: **44 passed, 0 failed** across 17 test binaries — protocol 17
(signaling 6, wire 8, capabilities 3), session 14 unit (common 4, host 5, controller 5),
session 8 integration (`tests/two_peers.rs`), diagnostics 3, input-windows 2.

The "44 tests green" claim is accurate. `scripts/check.sh`, `scripts/test.sh`, and
`.github/workflows/ci.yml` run identical commands (`clippy --workspace --all-targets --
-D warnings`), so CI will enforce the same gate once a remote exists (delta D6). Tag
`m0-contract` exists on `93f701d` as PLAN §7 requires.

## 2. M0 deliverables check (PLAN §4)

All M0 line items are present: workspace with 8 compilable crates; fmt/clippy/test
scripts + CI definition; AGENTS.md with invariants, budgets, commands, wire-version
policy; `crates/protocol` v0 (JSON signaling envelopes, versioned binary data-channel
messages, capability negotiation, round-trip + compatibility tests); `crates/session`
dual deterministic state machines with a two-peer (and three-peer) simulation; ADR-001,
ADR-002, state-machine diagrams; perf-counter schema (`docs/perf-counter-schema.md` +
`crates/diagnostics`). All six invariant-7 platform traits exist as M0 stubs with
backpressure rules documented at the trait level. No runtime code exists to profile —
correct for M0.

## 3. Findings

Severity labels: **blocking-for-M1** (none found), **should-fix** (with the milestone by
which it must land), **note**.

### F1 — `message_id` values collide between the two role machines of one device — should-fix (land before M2; contract bug in the M0 reference model)

`crates/session/src/common.rs` — `EnvelopeBuilder` is constructed per machine
(`HostSession::new` and `ControllerSession::new` each build their own with counter 0),
so the first envelope from each machine of the same device gets the identical
`message_id` `"{device}-1"`, the second `"{device}-2"`, etc. The doc comment claims ids
are "unique for the process lifetime" — false whenever one process runs both roles,
which is the product design (one binary, two roles; the simultaneous-collision rule in
`docs/protocol/state-machines.md` explicitly assumes a device can be host and controller
at once). `crates/session/tests/two_peers.rs` instantiates exactly this shape
(`Peer { host, controller }`) and `register_all()` emits two `Register` envelopes with
`message_id "device-a-1"` — the harness routes service-directed envelopes to
"service swallowed", so the test never catches it.

Verified empirically (scratch crate in `%TEMP%`, since deleted, driving
`HostSession::new("device-a")` + `ControllerSession::new("device-a")`):

```text
host Register  message_id = "device-a-1"
ctrl Register  message_id = "device-a-1"
IDs equal: true
```

Impact: the source plan (§Signaling messages) and `crates/protocol/src/signaling.rs`
both make `message_id` the service-wide idempotency key ("retaining recently seen
messageId values during the signaling TTL"). A conforming M3 service will treat the
controller's `Register`/`Heartbeat`/`Offer`/`Cancel` as duplicate deliveries of the
host machine's envelopes (or vice versa) and silently drop them. Every signaling-level
dedupe/idempotency test in M3 will be flaky until this is fixed. Cheapest fix now:
namespace per role (`"{device}-host-{n}"` / `"{device}-ctrl-{n}"`) or share one builder
per device. Reproduction: the scratch program above, or inspect
`w.sent` ids after `register_all()` in `two_peers.rs`.

### F2 — Simultaneous-call collision is only modeled in the `Requesting` window — should-fix (before the M2 rig)

`crates/session/src/controller.rs`: `CollisionDetected` is legal only in `Requesting`.
`two_peers.rs::route` correspondingly raises the collision event only when the target's
controller is `Requesting`, and `docs/protocol/state-machines.md` documents only that
case. If the peer's `connect_request` is delivered after our controller has already
received `Accept` (state `Offering`/`Connecting`) — possible via mailbox latency or the
stale/duplicate redelivery M3 explicitly plans to test (TTL 2–5 min) — the runtime
either hits `IllegalTransition` or, worse, skips the tie-break entirely: both devices
then run host+controller sessions toward each other (the exact hall-of-mirrors the
tie-break exists to prevent). PLAN §4 M0 explicitly scopes in "simultaneous-call paths";
this interleaving is uncovered by the deterministic harness and by the machine tables.
Fix while the contract is cheap: make `CollisionDetected` legal in
`Offering`/`Connecting` with the same tie-break (loser cancels), or define the runtime
rule that suppresses an incoming request while this device has an outbound session to
that peer, and pin it in `state-machines.md` + `two_peers.rs`.

### F3 — Invariant 6 asymmetry: input events are trivially printable; only `SessionSecret` is redacted — should-fix (before M2)

`crates/protocol/src/wire.rs`: `InputEvent` derives `Debug` (including
`Text { code_points }` = typed characters, key scan codes, mouse coordinates).
`crates/transport-webrtc/src/lib.rs`: `TransportEvent::Message(Channel, WireMessage)`
derives `Debug`. The M2 rig and any `tracing`/debug logging of transport events will
print keystroke and mouse content by default ergonomics — invariant 6 ("input never
logged") is enforced nowhere except docstrings, while the analogous secret rule got a
redacted `Debug` + three tests (`signaling.rs`, `host.rs`, `two_peers.rs` transcript
note). Recommend the same treatment for input (redacting wrapper or manual `Debug` for
`InputEvent`, plus a regression test) before M2 wires real input.

### F4 — `frame_id` join mechanism for the controller half is assumed, not designed — should-fix (decide before M2)

`docs/perf-counter-schema.md` states both clock halves "are joined by `frame_id`
(host-assigned at capture, echoed by the controller)". Over the real transport the
controller cannot know the host's `frame_id` for an H.264 RTP frame without a carriage
mechanism (RTP header extension, SEI, or a control-channel mapping) — none is chosen,
and ADR-002/`Transport` say nothing about it. The schema is fine for M1's in-process
loopback (frame_id can be carried in the handoff types), but M5's input-to-visible
formula (host capture→send + RTT + controller recv→present, all per frame) is built on
this join. Recording the decision now avoids a mid-M2 contract change; it is also the
kind of silent cross-layer coupling ADR-001 forbids.

### F5 — Queue-gauge cadence is too coarse to gate "queue depth ≤ 1 steady state" — should-fix (must be resolved before the M1 gate report is accepted)

`docs/perf-counter-schema.md` / `QueueSample`: sampling "≥1 Hz steady-state; on every
change while unstable". At 1080p60, 1 Hz observes 1/60 of queue states; a queue
oscillating 0→2→0 between samples reads as depth 0. "Unstable" is undefined, so the
every-change clause has no operational meaning, and the M1 gate ("queue depth ≤ 1 frame
steady state") plus the M6 release blocker ("depth == capacity sustained") both depend
on this measurement. Fix in the doc + M1 loop binary: sample the four frame queues on
every depth change (or per frame), keep ≥1 Hz only for the channel queues, and record
max/high-water depth per reporting window — not just instantaneous snapshots. Also add
a per-queue dropped/replaced counter: the newest-wins queues (`input-fast`, `cursor`,
frame-drop points) have no measurable backpressure event today.

### F6 — The M1 "latency report" has no defined format; sink obligations are incomplete — should-fix (before the M1 gate report is accepted)

`docs/perf-counter-schema.md` §Milestone obligations requires "latency report in
`docs/reports/`" but never defines it: no percentile set (p50/p95/p99/max), no
windowing, no statement of whether the report is raw JSONL + summary or a derived
table, and no pass criteria phrasing beyond the budgets. The JSONL file sink is
referenced ("the M1 JSONL file sink rotates") but does not exist in
`crates/diagnostics` and its rotation policy (size/time/file count) is unspecified.
Sizing check for the M1 run: 60 fps × 30 min ≈ 108k frames × 2 `FrameTiming` records
+ ~7k `QueueSample`s ≈ 70–100 MB JSONL — fine on disk, but `BoundedMemorySink` with any
small default silently loses the distribution tail, and nothing states that the loop
binary must retain all records for the report. Define the report template (recommend:
per-stage p50/p95/p99/max + frame-gap/drop accounting + queue high-water, generated
from the JSONL) before M1 declares its gate met.

### F7 — Records carry no session scope; resource/quality counters absent — should-fix (additive lands by M2, latest M5/M6)

`FrameTiming`/`QueueSample` have no session identifier. A 60-minute soak spanning a
reconnect (M6 gate) interleaves records from two sessions; if `frame_id` resets per
session, offline joins alias old and new frames. Also, the source plan's performance
matrix (frame-time histogram, bitrate, loss, RTT, CPU, GPU, memory) has no record
kinds — only timestamps and queue gauges exist; RTT/loss are deferred to M5 by the doc,
but memory/CPU/GPU (needed for "bounded memory" and "no runaway growth" evidence in the
soak report) appear nowhere. All are additive under the schema's own evolution rule;
add `session_id` early (M2) because retro-fitting filled JSONL files is annoying.

### F8 — No input-path timestamps; the M5 proxy formula understates input-to-visible — note

The schema records nothing on the input path (`input_send_ns`, `input_inject_ns`,
inject→capture delay). The documented M5 computation (host capture→send + RTT +
controller recv→present) omits controller input→send and host inject→capture — at
least one capture interval plus injection latency, plausibly 8–20 ms at 60 fps — so the
"measured" median will read better than the true input-to-visible latency the ≤80/150 ms
budgets govern. Plan additive input counters when M2 wires input; until then, M5
reports should label the proxy explicitly.

### F9 — `sdp_mid: Option<u16>` will not represent string mids — note (cheapest to fix now)

`crates/protocol/src/signaling.rs` `IceCandidate`. JSEP/SDP mids are strings
("0", "1", "video", "data"); webrtc-rs models `sdp_mid` as `String`. A non-numeric mid
is unrepresentable in this envelope. Wire version 0 has zero deployed peers — changing
to `Option<String>` now is free; after M3 it is a protocol bump. Affects M2/M3
integration and the trickle-forwarding contract tests.

### F10 — Busy-reject envelope `session_id` is inconsistent across host states — note

`crates/session/src/host.rs`: while `ConsentPrompted`, the busy `Reject` carries
`Some(pending_session_id)` (the *first* controller's session, sent to the *second*
controller); in `Exchanging`/`Connecting`/`Connected` the busy `Reject` carries `None`.
Consumers correlating by `session_id` will see inconsistent values for the same logical
message. The two_peers busy test only asserts controller state, not the envelope.
Cosmetic today; worth normalizing (use the incoming request's session id, or always
`None`) before the M3 service starts keying on it.

### F11 — Binary layout changes are policy-detected, not test-detected — note

`crates/protocol/src/wire.rs`: round-trip, version-gate, truncation, trailing-byte,
oversize, and bad-variant tests are genuinely good. But nothing pins the *encoded
bytes*: an accidental field reorder/type change fails no test and only the WIRE_VERSION
bump policy (invariant 5) catches it in review. A small golden-bytes fixture test
(encoded hex for one message per variant class) would make silent layout changes fail
CI, forcing the bump. Suggest adding alongside the next wire change.

### F12 — Duplicated doc comment on `DedupeLog` — note

`crates/session/src/common.rs` lines 164–167: the same three-line doc comment appears
twice in a row. Cosmetic; fold into any F1-era edit of that file.

## 4. Perf-counter schema adequacy (focus 1) — assessment

**Adequate for the M1 gate as a data model; the obligations around it need tightening
(F5, F6).** All six source-plan instrumentation points exist as fields
(capture/encode_submit/encode_done/send/recv/decode_done/present), units (ns) and clock
domains (per-device monotonic, zero-based, never subtract across domains) are stated,
missing-vs-zero is pinned (`None`, never 0), JSON field names are pinned by test, and
all four frame queues plus the four data-channel queues are enumerated with budgets.
The `PerfSink` design is hot-path-sound: by-value record moves, no formatting on the
path, no locks or channels, bounded sinks, `NullSink` baseline for the M6
telemetry-distortion audit. Nothing M1 needs requires a *breaking* schema change — the
gaps (F4 join mechanism, F5 cadence/drop counters, F6 report format, F7 session scope,
F8 input stages) are additive or documentation, which is what "no schema changes to
measure M1" promised. Two nits inside the doc: `QueueSample::at_ns` does not restate
the zero-based convention `FrameTiming` uses; and when a `FrameTiming` record is
emitted (host: after `send_ns`? controller: after `present_ns`?) is unstated.

## 5. Invariant encoding (focus 2) — assessment

| Invariant | Encoded in M0 by | Gap |
|---|---|---|
| 1 No frame bytes through IPC/JSON/canvas | By construction: no frame type exists in `protocol`; `wire.rs` states video is RTP-only; ADR-001 data paths; cursor-pixel exception bounded and documented | None for M0 (Tauri does not exist); enforced by review from M4 |
| 2 Vercel control plane only | By construction: `SignalingBody` has no payload-carrying variant beyond SDP/ICE/capabilities | None |
| 3 Bounded queues | `DedupeLog` bounded (tested), `BoundedMemorySink` bounded (tested), 1 MiB decode limit (tested), trait-level backpressure docstrings | Review convention only — as planned; needs the F5 drop counters to be *measurable*, not just reviewable |
| 4 TURN forbidden | ADR-002 decision 5 + `transport-webrtc` docs | Prose only until M2; pin "no relay candidates configured/rejected" with a test when the transport lands |
| 5 Version policy | Both version constants, typed errors, compatibility tests both surfaces | F11 (golden bytes) |
| 6 No logging of input/SDP secrets | `SessionSecret` redacted `Debug` + 3 tests | F3 (input side has the inverse ergonomics) |
| 7 Narrow traits | All six traits present with backpressure and perf-sink seams | None |
| 8 Small patches | Process rule (AGENTS.md) | N/A |

## 6. Test quality (focus 3) — assessment

Strong overall. The exhaustive state×event tables (136 pairs per machine, illegals
rejected without mutation, non-vacuity guard), transcript-equality determinism checks,
red-envelope redelivery tests, collision tie-break in both directions, decode
hardening (unknown version, empty, truncated, trailing, bad variant index, oversize
claim), and stable-JSON-name pins for both `protocol` and `diagnostics` meaningfully
pin the contracts. Load-bearing behaviors found untested or under-tested: the
`message_id` uniqueness claim (F1 — currently *false*, and untested), the
`Offering`/`Connecting` collision window (F2), the busy-reject envelope shape (F10),
and the encoded-bytes stability of the binary codec (F11). Minor harness shortcuts,
acceptable as reference-model code: `two_peers.rs::route` discards the real
`Cancel`/`Disconnect` reasons (reuses `User`) and hardcodes `DisconnectReason::User`.

## 7. Recommendation

M0 may count as done: the gate is green and reproducible (8.3 s cold), all PLAN §4
deliverables exist, and nothing found blocks M1's local-loop work from starting.
Before the respective next milestones: fix F1 (id collision — smallest change, largest
blast radius if it survives to M3), F3 and F9 (both wire-surface fixes that are free
only while version 0 has no peers), F2 (contract completeness of the simultaneous-call
rule), and decide F4. F5 and F6 do not block M1 development but must land before the
M1 latency report is accepted as gate evidence, since the current cadence and report
definition cannot prove "queue depth ≤ 1 steady state" or a latency distribution
unambiguously.

## 8. Reproduction commands

```bash
# Gate (from repo root, Git Bash; auditor timings in §1)
cargo fmt --all -- --check
scripts/check.sh
scripts/test.sh

# F1 evidence: both machines of one device emit "{device}-1" first —
# instantiate HostSession::new("device-a") and ControllerSession::new("device-a"),
# step Start on each, and compare the emitted envelopes' message_id fields
# (per-machine EnvelopeBuilder counters both start at 0; see
# crates/session/src/common.rs, EnvelopeBuilder::envelope, and
# crates/session/tests/two_peers.rs, Peer/register_all).
```
