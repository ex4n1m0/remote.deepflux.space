# M2 rig report — node runtime + two-process composition (RD-006/007/008 core)

- Work package: M2 core (PLAN.md §4; deltas D2), backlog RD-006/007/008
- Date: 2026-09-24/25
- Scope: `crates/node-runtime` (new) — the composition owner driving the host AND
  controller `session` state machines with a real monotonic clock + timer queue
  matching `World` semantics; manual file-based signaling routed **through** the
  session machines; the real pipeline swap (DXGI capture → MF H.264 hw encode →
  RTP → MF decode → D3D11 present); host-side input consumption against the real
  `InputSink` trait; the F20 pacing fix; the two-process rig with scripted
  scenarios and schema-exact counters.
- Exit-gate status: `cargo test -p node-runtime` (34 tests) and
  `cargo test -p transport-webrtc` (23) green;
  `cargo clippy --all-targets -p node-runtime -- -D warnings` green;
  `cargo fmt --all -- --check` green; all four rig scenarios pass end-to-end on
  this machine (two processes, real display).
- Evidence: `docs/reports/data/m2-rig-20260924-*` (gzipped JSONL metrics per
  process, per-run summaries, latency summaries, final-run logs).

## What was built

| Path | Role |
|---|---|
| `crates/node-runtime/src/clock.rs` | `MonotonicClock` (zero-based ns, the schema's session clock) + `ManualClock` for deterministic tests |
| `src/timers.rs` | `TimerQueue`: `(fire_at_ms, schedule_seq)` ordered drain, cancel by `(machine, id)` — the `World`'s ordering discipline on the real clock |
| `src/signaling.rs` | `SignalingIo` boundary + `SignalingHub` (in-memory, tests) + `FileSignaling` (manual adapter: `c2h.jsonl`/`h2c.jsonl`, atomic appends, byte-accurate offset reads retaining torn lines, 1 MiB/drain bound, at-least-once delivery so the machines' dedupe is what proves idempotency) |
| `src/node.rs` | `Node` — drives both role machines, maps envelopes + `TransportEvent`s into session events, executes `Action`s (signaling writes, transport compose/apply/forward, pipeline control, timers), node-level collision rule in all legal states, `Registered` self-ack, heartbeat cadence, `TransportFailed` mapping with state-legality guards |
| `src/input.rs` | `InputPump<S: InputSink>` — reliable-seq gap → `release_all(SequenceGap)` *before* the post-gap event, fast-channel stale suppression, `AllKeysUp` passthrough, disconnect safety |
| `src/pacing.rs` | `FramePacer` — absolute-deadline pacing on `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` (F20 fix), skip-counted resync when behind |
| `src/metrics.rs` | session-scoped JSONL sink (bounded channel + writer thread), `FrameQueue` with F5 on-every-depth-change sampling, `LatestSlot` (cursor newest-wins), 1 Hz resource sampler |
| `examples/m2_rig.rs` | the two-process rig (scenarios below) |
| `examples/latency_summary.py` | F6-format summarizer over the JSONL (per-session frame ids, warm-up rule) |
| `tests/world_parity.rs` | 14 tests reproducing `crates/session/tests/two_peers.rs` through the runtime |
| `tests/webrtc_drive.rs` | two real `WebrtcTransport`s driven to `Connected` through the `Node`s + wire traffic + clean disconnect |

Runtime design in one paragraph: the `Node` owns both machines of one device
(collision detection needs both, like the `World`), a clock, the timer queue,
the signaling adapter and the transport trait object. `pump()` is the only
entry: register acks → due timers (in `(fire_at, seq)` order) → heartbeat
cadence (only in heartbeat-legal states) → inbound signaling. Transport events
map as: `ChannelsOpen` → `DataChannelOpen` on whichever machine is `Connecting`
(per-channel readiness gating, never open order); `Failed`/`Closed`-while-live
→ `TransportFailed` (state-legality guarded); gathered ICE candidates →
runtime-minted envelopes (`{device}-rt-N`, QA-F1-namespaced). Illegal
transitions are counted and surfaced, never propagated (real interleavings
have tolerated races; the World-parity tests assert zero of them on scripted
paths).

### Documented deviations from the `World` harness

1. **ICE-candidate routing is role-complementary** (host-gathered → peer's
   *controller* machine and vice versa). `World::route`'s candidate branch is
   dead code in the scripted scenarios — candidates are always injected
   directly there, and those injections are exactly role-complementary (each
   machine's `ForwardIce` must reach its own transport).
2. **`Registered` self-ack**: the manual adapter *is* the service stand-in;
   a successful `Register` write is acked on the next pump (the World injects
   at t+50 ms). `Heartbeat` never reaches a file (swallowed, counted).
3. **Compose/apply failures**: `compose_answer` failure in `Exchanging` maps to
   `TransportFailed` (legal); `compose_offer`/`apply_answer` failures in
   `Offering` have no legal `TransportFailed` — the connect timer owns
   recovery there (the machines' own design).

### Network-change recovery semantics

The state machines have no auto-reconnect (MVP; `ReconnectPolicy` placeholder),
so the honest mapping — exercised by the `full` scenario — is: live connection →
`restart_ice()` probe (wired through `Transport::restart_ice`, returns Ok) →
data-plane goodbye `Disconnect{TransportError}` over the control channel (a
one-sided loopback `close()` is otherwise invisible to the peer until consent
timeouts) → hard teardown → both machines `Disconnected{TransportError}` (or
the peer's signaling `Disconnect` wins the race → `{Peer}`; the scenario
re-registers in either case) → `StopStreaming`/`StopRendering` +
`AllKeysUp(Disconnect)` on the host → both roles re-`Start` after 1 s →
fresh transports → full re-signaling through the adapter → new session.
Note for M5: a same-peer-connection ICE restart does not re-emit channel-open
(SCTP survives over the unchanged DTLS), so reconnect-after-network-change in
this MVP is session teardown + fresh peer connection — matching the machines.

## Scenario results (this machine, two processes, real display)

Environment: same as M1 (Windows 11 10.0.26200, RTX 5080 Laptop GPU,
`\\.\DISPLAY5` 3840x2160 primary; capture 4K → encode 1920x1080@60 NVENC
8 Mbps CBR, DXVA decode, D3D11 present window 1280x720). Both processes run
full pipelines concurrently on the one GPU — the M1-flagged suspension
configuration.

### `full` — connect → 60 s stream + input chaos → network change → clean disconnect

Final gate run (30 s stream, 1000 scripted moves; the 60 s runs behaved
identically — see evidence `-26` and section numbers from the 60 s runs):

| measure | value | budget |
|---|---|---|
| connect (connect_request → Connected, incl. 300 ms scripted consent + file-signaling polling) | **1145 ms**; 60 s runs: 1145/1148 ms | < 5 000 ms |
| network change at 2/3 of stream | teardown settled, re-established as a **new session** in **1143 ms** | — |
| input convergence (seed 2026, 10 % drop / 5 % reorder / every-40th reliable dropped) | 60 s runs: 3 000 moves sent → 2 516 applied + 113 stale suppressed; final position **exactly** the newest sent; 16 reliable gaps → `AllKeysUp`, held keys 0 at end | final position equal |
| clean disconnect | control goodbye + signaling `Disconnect{User}`; host `AllKeysUp(Disconnect)`, both machines terminal, all timers canceled | — |

### `loss-reorder-dup`

Duplicate-signaling probe (own outbound `connect_request` + `offer` lines
re-delivered verbatim, same `message_id`): **prompts stayed 1**, no state
re-entry, no illegal transitions — machine-level dedupe no-ops file-level
duplication. Chaos results identical in profile to the spike (above).

### `cycles` — GPU-suspension hammer

10 × (connect → 20 s stream → clean disconnect), fresh peer connection and
rebuilt pipelines per cycle:

- **10/10 sessions** established and cleanly ended; consent prompts 10 (one per
  session); connect times **1134–1152 ms** (spread 18 ms).
- **`device_lost` = 0 on both sides** across all cycles (typed counters on
  capture/encode/decode/present).
- Combined with the 10-minute continuous soak below: the M1-observed device
  suspension **did not reproduce** in ≥10 cycles + 10 min of overlapping full
  pipelines. Counts recorded; the typed `DeviceLost` paths exist but were
  never taken.

### `soak` — 10 minutes continuous

Single session, 600.0 s streaming, input chaos throughout (6 000 moves):

- 34 630 captured / 33 573 encoded / 30 252 decoded+presented; 0 decode
  errors, 0 missing-packet frames, 0 packets lost (RTCP), RTT ~0.2 ms,
  selected pair `127.0.0.1:host ↔ 127.0.0.1:host`, nominated, **no relay**.
- **Memory flat**: 2-minute bucket averages host 112.4 → 116.3 → 117.0 →
  117.2 → 117.2 → 117.2 MiB, controller 90.2 → 92.5 → 92.4 → 92.9 → 92.8 →
  92.7 MiB (both plateau by minute 2). CPU ≤ 76.6 % (host) / 57.8 %
  (controller) of one core.
- `device_lost` = 0 both sides; sink backpressure 0; channel queues 0 depth /
  0 dropped / 0 replaced for the whole hour-equivalent of channel traffic.

### Frame rate (F20 pacing fix)

| measure | M1 (sleep-paced loop) | M2 rig (waitable-timer pacer) |
|---|---|---|
| pacing loop rate | ~57.2 Hz (16.7 ms + ~0.8 ms overhead) | **60.007–60.02 Hz** (all runs; 36 001 ticks / 600.01 s in the soak) |
| captured | 57.05 fps sustained | 57.8–58.1 fps |
| encoded | 57.0 fps | 56.0 fps |
| presented | 57.0 fps (in-process) | 50.4–51.6 fps (two-process, see drops below) |

The pacing overhead is gone (tick rate is the requested 60.000 Hz with
drift-free absolute deadlines; pacer unit test pins ±5 % over 120 ticks). The
remaining shortfall is **source availability and load**: DDA yields ~58
updates/s of this desktop while *both* full pipelines run on one GPU (M1's
57.05 was a single pipeline), and the cap-1 newest-wins queues drop obsolete
frames under encoder pressure — 1 056 `capture_to_encode` replacements +
28 `encode_to_send` over 600 s (all counted, invariant 3; no queue was pinned,
no unbounded growth). Each such drop surfaces as a controller-side frame-id
gap; the policy below resets the decoder and forces an IDR, costing ~3
IDR-gated frames per event — that is the presented-rate gap, by design
(picture integrity over smoothness until M5 congestion control).

### Per-stage latency (soak, warm-up 60 s excluded; n = 30 380 host / 27 509 controller frames)

| stage | p50 | p95 | p99 | max |
|---|---|---|---|---|
| capture→encode submit | 0.11 ms | 3.45 ms | 4.20 ms | 5.87 ms |
| encode submit→done | 3.82 ms | 13.28 ms | 22.76 ms | 32.42 ms |
| encode done→send | 1.84 ms | 3.43 ms | 3.72 ms | 9.80 ms |
| **host half (capture→send)** | **6.19 ms** | **16.01 ms** | **24.88 ms** | **35.51 ms** |
| recv→decode | 0.29 ms | 0.39 ms | 0.44 ms | 1.18 ms |
| decode→present | 0.07 ms | 0.10 ms | 0.13 ms | 4.51 ms |
| **controller half (recv→present)** | **0.36 ms** | **0.48 ms** | **0.53 ms** | **4.87 ms** |

The controller half is now properly split across receive → decode → present
(spike item #4 done; the M1 in-process numbers were 0.27/0.55/3.33/7.74 — the
two-process rig's decode stage is *faster* than M1's, the encode stage pays
the dual-pipeline GPU load). Input-to-visible proxy (F8 label: excludes
controller input→send and host inject→capture): host half + RTT (0.2 ms) +
controller half ≈ **p50 6.8 ms / p95 16.5 ms / p99 25.6 ms** on loopback —
the ≤ 80 ms LAN budget has headroom for one display refresh plus the omitted
stages.

`encode_done→send` p50 of 1.8 ms is the rig's pump-thread cadence (2 ms), not
codec work: the `Node` owns the transport on one thread (`Transport: Send`
without `Sync`), so `send_video` executes on the pump. An M4-era optimization
is a dedicated send thread behind the same node API.

### Loss-triggered keyframes

Two triggers wired: transport-level (`missing_packets > 0` or absent frame-id
extension → immediate `KeyframeRequest` + decoder reset, the spike path) and
application-level (frame-id discontinuity from host-side obsolete-frame drops
→ decoder reset + `KeyframeRequest`, rate-limited to one per 250 ms to prevent
IDR amplification — each IDR is the largest frame in the GOP and worsens the
pressure that caused the drop). Soak: 1 011 requests sent / 1 011 honored
(`force_keyframe` → NVENC `CODECAPI_AVEncVideoForceKeyFrame`), 3 291 IDR-gated
frames dropped awaiting the refresh, 0 decode errors, 0 corrupted output.

### Cursor channel

Host capture's cursor extraction feeds the `cursor` channel through a
capacity-1 newest-wins slot. In the rig the scripted input is **never injected
into the local desktop** (recording sink — this machine is also the
controller; the product plugs `input_windows::SendInputSink` into the same
`InputSink` slot), so the desktop cursor rarely moves: 1–2 position messages
crossed per run (1 per session, plus `Hide`/shape events when they occur).
The path is exercised end-to-end; motion counts wait for the real-LAN
checkpoint.

## `input-windows` integration (parallel package)

Coded against the trait at HEAD: the rig's recording sink implements
`InputSink`; every safety path uses the additive
`release_all(trigger) -> ReleaseOutcome` (counts accumulate into payload-free
counters; `outcome.error` counted, never fatal) and `InputError` is consumed
as the typed enum. Not consumed: `SendInputSink::set_monitor_rect` /
`refresh_display_metrics` — `SelectMonitor` handling belongs to the M4 shell;
noted here so the integrator knows the runtime's host input path deliberately
leaves them to the UI layer.

## Incompatibilities / contract-change requests

- None blocking. No edits to `session`, `protocol`, `capture-windows`,
  `codec-windows`, `render-windows`, `frame-surface`, `input-windows`, or
  `apps/`.
- Additive, documented uses of existing seams: root `Cargo.toml` **members**
  gained `crates/node-runtime` (not `[workspace.dependencies]`); the spike's
  `Transport` surface was used as-is (`restart_ice`, `stats`, `poll_video`).
- Suggested (non-blocking) follow-ups for the main session:
  - `FrameQueue`-style `is_open()` semantics matter wherever `pop(timeout)`
    is used — worth a note in the perf-schema or a crate-level convention;
  - schema F8 input-path timestamps (`input_send_ns` / `input_inject_ns`)
    still have no `FrameTiming`-adjacent home; the rig carries the counts in
    its summary JSON until an additive schema decision lands.

## Risks for M3

1. **Drop→IDR cycle under encoder pressure**: obsolete-frame drops (cap-1
   queues doing their job) each cost an IDR refresh (~3 gated frames). With
   M5 congestion pacing this should relax; at 8 Mbps CBR with two pipelines
   on one GPU the encode p99 is 22.8 ms against a 16.7 ms budget.
2. **One-sided teardown detection**: a hard transport close is invisible on
   loopback until ICE/consent timeouts; the rig uses the control-channel
   goodbye (`Disconnect{TransportError}`) as the data-plane notice. M3's
   service adds signaling-level presence, which will also cover this.
3. **Signaling adapter is single-direction per process** (`FileSignaling`
   serves one role). M3's network client replaces it behind the same
   `SignalingIo` trait — that is the intended seam, but the multiplexed
   both-roles-in-one-process case (the product) needs the M3 client, not the
   file adapter.
4. **Rig scripting lives in the example**: consent auto-accept, role
   re-registration after session end, and the idle watchdog are rig concerns;
   the M4 shell owns the user-driven equivalents.
5. **Software-encoder fallback** was not exercised by the rig (hardware path
   selected on this machine); it remains covered by the M1 codec integration
   tests only.
6. Cursor shape traffic and real cursor motion counts, true cross-machine
   RTT/jitter, and NAT/loss behavior all wait for the **real-LAN user
  checkpoint** (D2) — loopback ICE proves the protocol, not the network.

## Reproduction

```bash
cargo test -p node-runtime                 # 34 tests incl. World parity + real transport
cargo test -p transport-webrtc             # 23 tests
cargo clippy --all-targets -p node-runtime -- -D warnings
cargo build --release -p node-runtime --example m2_rig

# two terminals (or adapt scripts): fresh signaling dir per run
SIG=$(mktemp -d); mkdir -p /tmp/rd-m2-out
./target/release/examples/m2_rig.exe --role host --dir "$(cygpath -w $SIG)" \
    --summary 'C:\temp\rd-m2-out\host.json' --idle-timeout-secs 60 &
./target/release/examples/m2_rig.exe --role controller --dir "$(cygpath -w $SIG)" \
    --scenario full --stream-secs 60 --summary 'C:\temp\rd-m2-out\controller.json'
# scenarios: full | loss-reorder-dup | cycles (--cycles 10 --cycle-stream-secs 20) | soak (--stream-secs 600)
# latency summaries:
python crates/node-runtime/examples/latency_summary.py <metrics.jsonl> [--warmup-secs=0]
```

Evidence files: `m2-rig-20260924-{host,controller}-{24,25,26}.jsonl.gz`
(24 = cycles, 25 = soak, 26 = final full run), `m2-rig-{soak,cycles,final-full}-*-summary.json`
(latency/queue/resource), `m2-rig-final-full-{host,controller}-summary.json`
(run summaries), `m2-rig-final-full-*.log` (rig transcripts).
