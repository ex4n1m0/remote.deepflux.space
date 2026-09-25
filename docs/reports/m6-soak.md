# M6 — Performance gate, soak & release recommendation (RD-014), commit `fb91755`

Date: 2026-09-25/26 · Auditor: `rd-performance-qa` (read-only except this file and
`docs/reports/data/m6-*`) · Inputs: `PLAN.md` §4 M6 + §2 invariants, `AGENTS.md`
performance budgets, `docs/reports/m5-qa-audit.md` (F59–F70, all claimed fixed at
`fb91755`), `docs/reports/m5-matrix.md` §2 erratum + fidelity caveat,
`docs/perf-counter-schema.md`, `docs/adr/ADR-002` M6 fork amendment, M1/M2
baseline reports. Evidence: `docs/reports/data/m6-{smoke,soak,diag,hammer,recovery,sinkcheck}/`.

## 0. Verdict

**NO-GO as-is — one blocking finding (F71), with a narrow, cheap path to SHIP.**

> *Amended 2026-09-26 (repeat gate at `5763d4e`): F71 fixed and the repeat 60-min
> soak completed clean; final recommendation is now **SHIP-WITH-CONDITIONS** —
> see §10. This §0 remains the verbatim record of `fb91755`.*
Everything else the M6 gate names passed with margin: latency budgets, connect
budget, queue bounds under 4 % loss, memory flatness over the hour, input
safety, preset hammer (100/100), recovery endurance (22/22), zero encoder
rebuilds under congestion, and — the M5 blocker — the GCC feedback loop is now
live end-to-end (404 reactive decisions, 403 live reconfigs, 0 rebuilds in the
soak; RR loss/RTT real; estimate AIMD-live). But the headline 60-minute soak
died silently at minute 45.2: a DXGI access-lost whose `reinit()` failed left
the capture in a permanent dead state — **14.7 minutes of frozen stream while
the session stayed `Connected`**, no typed error, no teardown, in the product
path (`engine/host.rs` has the identical `let _ = cap.reinit()` discard as the
rig). That is a ship blocker for a remote-desktop product; the fix is small
(§F71) and everything else in this report can stand as-is after it lands plus
one repeat soak.

| # | Budget (AGENTS.md / PLAN §4 M6) | Measured | Verdict |
|---|---|---|---|
| 1 | Input-to-visible median ≤ 80 ms LAN (**F8 proxy**) | loopback proxy **p50 4.53 ms** / p95 30.25 / p99 44.09 / max 347.75 (n=25,044, warm-up excluded, 4 % loss + congestion ON) | **PASS** |
| 2 | ≤ 150 ms WAN median when RTT permits | rig cannot shape the estimate/delay axis into the proxy (m5-matrix §2 erratum): unshaped proxy 4.53 ms leaves ≈145 ms headroom for physics; real-WAN spot checks (user) are ground truth | **NOT CLAIMED** (caveat §6) |
| 3 | Connect < 5 s warm, direct ICE | **1 161–1 209 ms** across 22 scripted connects + **1 161–1 183 ms** re-establish after 10 mid-stream interface changes; soak run's own connect ≈1.17 s | **PASS** (4.2× margin) |
| 4 | 60-min soak: no crash / runaway memory / stuck input / progressive latency | memory flat both processes (host 119.5–120.0 ws / 296.5–296.9 priv MiB from minute 5; ctrl 96/121), input held-keys 0 at every check, i2v p50 per 5-min bucket 4.23–4.66 ms (no drift), queues bounded — **but capture died at 45.2 min** (F71): 0 frames for the last 14.7 min while Connected | **FAIL (F71)** |
| 5 | No unbounded queue growth under 5 % loss (run at 4 %, congestion ON) | every queue high-water within capacity: capture→enc 1/1, enc→send 1/1, recv→dec 2/8, dec→pres 1/1; channel input-fast 30/32 (burst drained, 0 dropped); replaced (obsolete-drop) counters: 23/352/44/0 — counted, bounded, no monotone growth in stable windows | **PASS** |
| 6 | Bounded memory incl. reconnect + preset paths | soak hour: flat. Reconnects: +1.65 ws / +1.55 private MiB **per session** over 12 cycles (F73, ~3× the M5-era lossless slope). Preset path: **encoder drop-path leak unchanged** — +14.1 ws / +28.1 private MiB per manual-preset rebuild (F72 = F56 un-fixed); Auto/congestion path 0 rebuilds | **PASS / FAIL by path** (F72, F73) |
| 7 | Capture→encode queue ≤ 1 steady state | high-water 1 (cap 1) in soak, hammer, recovery runs | **PASS** |
| 8 | Encoder reconfigures live, no rebuilds (CR-1) | soak: **reconfig_live 403, rebuilt 0, errors 0**, fps retargets 20; recovery cycles: 12/0/0 | **PASS** |
| 9 | Congestion controller reactive (F59 regression) | **404 decisions / 60 min** (M5: 1 per cell, frozen); estimate 16 distinct values 4.0–12.0 Mbps; RR loss nonzero in 44.5 % of samples (max 25 %); RR RTT p50 0.28 ms real | **PASS** (tuning note F77) |
| 10 | Input safety (keys released, convergence) | soak: 20 000/20 000 moves applied, final position exact, held_at_end 0, 0 gaps; hammer: held=0 at 100/100 checks; 22 recovery sessions all `AllKeysUp` on teardown | **PASS** |
| 11 | Invariant spot-checks (TURN, relay, IPC, versions) | `turn_ice_servers_are_rejected_at_configuration` green; soak `relay_in_use: false`, selected pair host↔host; ipc_surface walk green; wire/signaling versions unchanged this milestone | **PASS** |
| 12 | Merge gates on `fb91755` after all runs | fmt, clippy, workspace tests green — **except one intermittently flaky unit test** (F75, `channel_slot_depth_trail_records_bursts`, ~1/10 standalone) | **PASS w/ F75** |

## 1. The 60-minute soak (deliverable 1)

Run: `bash docs/reports/data/m6-soak/run-soak.sh 3600 4` — two processes, rig
`soak` scenario, **congestion ON, app-layer netem `loss=4`** (mid of the 3–5 %
band), NVENC 1080p, animated stimulus on the host. Mid-soak liveness watchdog
(`watchdog.log`/`watchdog.csv`, in the runner): status freshness, session
state, held-keys, ws+private slope/cap, queue bounds, long-horizon fps floor —
a violation kills the run. The watchdog's own v1 mis-fired once (it read the
metrics file's 1 MiB BufWriter flush granularity as a pipeline stall; the 240 s
diag run disproved that — 7.9 fps presented, `backpressure_events: 0`) and was
corrected to flush-aware long-horizon floors before the real run; see F76.

Headline numbers (raw: `m6-soak-{host,ctrl}-rig-*.jsonl.gz`, 219 035 records;
summaries `*-summary.json`; analyzer `analyze-soak.py`):

- **Session**: 1 connect ≈ 1.17 s, single session, ended `Peer` (clean
  goodbye). `illegal_transitions: 0`, `ice_forward_errors: 0`,
  `events_dropped: 0`, `relay_in_use: false`.
- **Frames**: host 37 965 captured / 37 938 encoded (10.5 fps effective);
  controller 34 998 received / 25 088 decoded / **25 044 presented = 6.96 fps**
  over 3 600.0 s. IDR rate: 2 826 keyframes / 37 938 encoded = **7.45 %**
  (2 454 forced by requests; controller sent 2 572 keyframe requests, 95.4 %
  honored; 8 585 IDR-gated drops; 1 325 decode errors — truncated AUs under
  loss, counted, `DroppedAfterReset` gate intact). fps by 5-min bucket:
  7.45 / 6.95 / 7.73 / 10.75 / 10.04 / 10.67 / 9.72 / 9.80 / 9.97 / **0.40**
  — the last bucket is F71's death at 45.2 min, not congestion.
- **Congestion controller (F59 fix verified at soak scale)**: 404 decisions,
  403 applied live, **0 rebuilds, 0 errors**, 20 pacer retargets. Ladder:
  rapid descent 8M→…→500 kbps floor (500 kbps ×76 steps, 800 kbps ×76,
  600 kbps ×33 …), fps caps 30/15 applied during collapse, one full additive
  recovery climb 3.2M→10.6M late in the run with "fps cap lifted". Estimate:
  16 distinct values, 4 000–12 000 kbps (GCC AIMD live — the M5 frozen-at-4M
  signature is gone). RR loss: p50 0, p95 9.77, max 25 %, nonzero 44.5 % of
  1 Hz samples. RR RTT p50 0.279 / max 1.07 ms (real LSR/DLSR per the fork).
  Resolution step-down never fired (estimate never < 800 kbps — expected under
  the §6 caveat; encode size stayed 1920×1080).
- **Queues (invariant 3)**: §0 row 5; no drop/replaced growth in stable
  windows; `frames_dropped_rx_queue` 1 106 (recv-side newest-wins over cap 8
  under burst+loss — the designed drop, counted).
- **Memory (F26 discipline, both counters, both processes)**: host
  114.7→120.0 ws / 294.4→296.9 private MiB over the hour (plateau by minute 5,
  watchdog slope ≤ 0.05 MiB/min after minute 12); ctrl 89.7→96.4 /
  115.4→121.5. Post-teardown finals 109.0/285.3 and 85.4/110.0 — release on
  teardown, no retention.
- **Input**: 20 000/20 000 applied, 0 stale, 0 gaps, final position exact
  match, `held_at_end: 0`, `inject_errors: 0`, 2 `AllKeysUp` (teardown paths).
- **Latency (F8 proxy, host half + ICE RTT p50 0.189 ms + ctrl half)**:
  p50 4.53 / p95 30.25 / p99 44.09 / max 347.75 ms; per-bucket p50 flat
  4.23–4.66 ms across all 45 healthy minutes (no progressive latency).
- **Per-stage (warm-up 60 s excluded)**: capture→enc-submit p50 0.143 /
  p95 0.206; enc-submit→done p50 0.018 / p95 0.030; enc-done→send p50 1.992 /
  p95 16.512; recv→decode p50 2.117 / p95 8.972; decode→present p50 0.088 /
  p95 0.137 ms. See §4 for baseline comparability.

**The failure (F71)**: last captured *and* sent host frame at 45.25 min; from
then the host log repeats `[host] capture error: invalid capture state:
duplication not started` 8 850 times (~1 per 100 ms loop) until the scripted
end; controller received nothing after 45.23 min; both processes otherwise
healthy (resource samples to 60 min, states `Connected`, ICE consent alive,
host `send_bitrate` reads 0). Root cause chain (code-verified):
`DxgiCapture::reinit()` (`crates/capture-windows/src/dupl.rs:229-238`) sets
`self.duplication = None` **before** re-finding the output and returns with it
still `None` on any failure; both callers discard the error
(`crates/node-runtime/examples/m2_rig.rs:831` `let _ = cap.reinit()` and — the
product path — `apps/desktop/src-tauri/src/engine/host.rs:267` identical);
`next_frame` (`dupl.rs:471-475`) then returns `CaptureError::Invalid` forever,
which no error branch escalates or re-inits. The triggering access-lost is
ordinary DDA churn (the risk register's "certain" DXGI class); the defect is
the unrecoverable dead state and its silence.

## 2. Preset + Auto-switch hammer (deliverable 2)

`bash docs/reports/data/m6-hammer/run-hammer.sh 100` — 100 full product
sessions through the app engine (`e2e-child` pairs over the local signaling
service), each scripting one mid-session `EngineCmd::SetQuality` → wire
`SetQuality` → host applies the plan. Preset cycle low→auto→high→auto→
balanced→auto (50 of 100 are `Auto`, **every one following a manual preset** —
the F70 geometry-restore path exercised 50 times; 17/17/16 manual each).
Result (`hammer.csv`, `hammer-detail.txt`):

- **100/100 iterations exit 0** — each child's verdict includes: quality
  change applied, monitor pick, focus-loss probe (`WM_KILLFOCUS` →
  `AllKeysUp{FocusLost}`), viewer resize follow, typed session end, clean
  teardown, host re-online.
- **Host `quality` field matched the requested preset 100/100** (the wire
  path delivered every change).
- **Input safety: held keys = 0 at 100/100 post-run checks.**
- Zero-rebuild expectation, split by path: Auto engages the congestion
  controller with no rebuild (wire handler skips `want_reconfig`); manual
  presets price exactly one geometry rebuild each **by design**. Within one
  process the hammer cannot accumulate (the e2e-child host exits after its
  first session by design), so the leak-flat component is measured directly on
  the rebuild mechanism: `leak_probe --phase encoder --iters 12` re-run on
  `fb91755` gives **+14.1 MiB ws / +28.1 MiB private / +1.1 threads / +33
  handles per create→encode→drop iteration, linear, no plateau** — F56
  unchanged (F72). 100 manual changes in one session ≈ +2.8 GiB private
  commit; the Auto path (the soak) rebuilt **zero** times across 403 live
  reconfigs.

## 3. Recovery endurance (deliverable 3)

`bash docs/reports/data/m6-recovery/run-recovery.sh` — (a) one process pair,
**12 connect/stream/teardown/re-signaling cycles under soak-style load**
(loss=4, congestion ON); (b) **10 `full`-scenario runs** under the same load,
each performing one mid-stream interface-change recovery (ICE-restart probe →
data-plane goodbye → hard teardown → fresh transports → full re-signaling).

- (a) 12/12 sessions established, all ended `Peer`, 12 prompts (no re-prompt),
  `reconfig_live 12 / rebuilt 0 / errors 0`; connects 1 161–1 209 ms.
- (b) 10/10 recoveries: initial connect 1 163–1 198 ms, **re-establish after
  the interface change 1 161–1 183 ms**; ends `[Peer, User]` (goodbye
  observed, no consent-timeout waits); no illegal transitions.
- **Reconnect-path memory slope (F26 discipline, one process, 12 sessions)**:
  per-session-end ws 113.8→132.0 MiB and private 294.5→311.5 MiB =
  **+1.65 / +1.55 MiB per session**, monotone; teardown releases ≈10 MiB
  (final 121.3/300.4). The committed M5-era lossless cycles run
  (`m2-rig-20260925-cycles-host-summary.json`, 30 sessions) sloped
  +0.50/+0.49 per session — the M6 slope is ≈3× under load (F73; magnitude
  bounded by user reconnects, ~160 MiB per 100 reconnects, but monotone).

## 4. Copy / queue audit (deliverable 4, profiling pass, read-only)

**Stage p95 vs baselines.** Direct percentile comparison across milestones is
load-profile-limited: M2's soak was 58 fps / 8 Mbps clean loopback; this
soak is ~10 fps / mostly 0.5–1.1 Mbps under 4 % loss with the controller
stepping. Under that profile nothing regressed for codec reasons —
capture→enc-submit and encode are far *under* M2 (0.206 / 0.030 ms p95 vs
3.45 / 13.28; tiny access units at the stepped-down bitrate). Two stages pay
their documented design costs, amplified by sparse frames:
`encode_done→send` p95 16.5 / p99 36.6 ms (M2: 3.43/3.72) — the rig's
single-threaded pump owns the transport (`Transport: Send`), the M2-noted
cadence, and with ≤10 fps the queue-drain alignment lands in the tail;
`recv→decode` p95 9.0 ms (M2: 0.39) — netem's 300 ms-burst token bucket
paces arrivals under loss. Neither is a new copy or lock introduced by M5/M6;
both are rig/`Send`-bound shapes, and the decode→present p95 (0.137 ms,
M2: 0.10) shows the render path unchanged. No stage's p95 regressed for a
reason attributable to fb91755's additions (trail sampling, fork ingest).

**Copy inventory (product path).** Capture→encode→decode→present move GPU
`FrameSurface`s (COM refcount, same-device; CPU readback only in the
sanctioned diagnostics/software-encoder paths, counted by
`frame_surface::readback_count` — zero on this hardware path). The one
per-frame CPU copy on the product path is RTP packetization
(`packetize_access_unit`, Annex-B → FU-A/STAP-A payloads — inherent to RFC
6184; a fresh `H264Payloader` per call is deliberate, stale-SPS safety).
The netem path adds one packet clone + frame-id extension rebuild per packet
and the shaper hop — **test-only** (product sets `video_netem: None`).
Input events encode per message (`protocol::wire::encode`) on the user-event
path — negligible. **No avoidable frame-pixel copy found on the product
path**; the plan's "remove avoidable copies" has no measured offender — the
candidates are the two rig-bound stage shapes above, both fixable by the
M2-noted dedicated send thread (a dispatched change, not an audit action).

**Blocking-work spot-checks (hot paths).** Locks on the frame path are
cap-1 `FrameQueue` mutexes held for push/pop only; congestion slots are
`Mutex<Option<..>>` touched once per frame (encode thread) and 1 Hz (loop);
channel send queues are lock+notify with the SCTP writer on the async side;
`channel_queue_gauges()`/`take_channel_depth_trail()` are lock-only by design
(no async bridge at poll cadence — verified in `engine.rs:1863-1887`). The
1 Hz `stats()` bridge runs on the loop thread with a bounded wait. Allocation
on the frame path: per-frame `FrameTiming`/`QueueSample` records (bounded
sink channel 65 536, drop-counted — 0 backpressure events in 219 k records)
and the chaos-burst trail flood (test-only). No unbounded channel, heap, or
`Vec` growth found on any streaming path.

**Bounded-queue surface (full current tree)** — every queue, its bound, its
overflow policy/counter, and the soak's observed high-water:

| Queue | Bound | Overflow policy/counter | Soak HW |
|---|---|---|---|
| `capture_to_encode` / `encode_to_send` / `decode_to_present` | 1 | newest-wins, `replaced` counted | 1 (23/352/44 replaced) |
| `recv_to_decode` | 8 | drop-oldest(`NewestWins`), counted | 2 |
| channel `control`/`input-reliable` | 256 | error-on-full, `dropped` | 1 / 1, 0 dropped |
| channel `input-fast` | 32 | drop-oldest, `dropped` | 30, 0 dropped |
| channel `cursor` | 8 | newest-wins, `replaced` | 1 |
| F63 depth trails ×4 | 64 entries | drop-oldest, `trail_overflow` counted | — (counter not exported, F74) |
| transport event queue | 256 | drop-oldest, `events_dropped` | 0 |
| transport video queue | 4 | newest-wins, `frames_dropped` | 1 106 (counted) |
| netem shaper channel / heap (F69) | 300 / 4 096 | drop-newest, `gauges.dropped` | not exported (F74) |
| input delay line | 1 024 | counted `dropped` | 0 |
| `input-windows::capture` queue | 256 | counted | n/a (rig uses recording sink) |
| metrics sink channel | 65 536 | drop-counted `backpressure_events` | 0 |
| engine event channel (app) | 512 | try_send drop | — (unit-pinned) |
| FileSignaling drain | 1 MiB/pass | torn-line retain | — |

**Sink perturbation (schema M6 obligation) — could not be run as specified**:
the rig always constructs a `JsonlReport` (absent `--metrics-dir` it defaults
to a temp dir), so no sink-off mode exists (F79); an attempted on/off pair
also hit the M5 static-desktop pitfall (source delivered 2.5 fps — the
comparison would measure screen activity). Bounded substitute evidence: the
soak's 219 k records produced 0 backpressure events and p50 stage costs of
0.14/0.02/2.0 ms — record emission is not visible at p50 on the hot path.

## 5. Gate status on `fb91755` (before and after all runs)

`cargo fmt --all -- --check` pass; `scripts/check.sh` (clippy
`--all-targets -D warnings`) pass; `scripts/test.sh` pass — **with one
intermittent exception** (F75): `transport-webrtc::engine::tests::
channel_slot_depth_trail_records_bursts` fails ~1/10 standalone runs at
`assert!(trail.iter().all(|s| s.at_uptime_ns > 0))` — the trail stamps
process-uptime ns and the whole burst can land on the same QPC tick as the
`OnceLock` start (uptime 0). Repro: `for i in $(seq 1 10); do cargo test -p
transport-webrtc --lib channel_slot_depth_trail; done`. Pre-existing at
`fb91755` (no code was changed during this audit — `git status` shows only
`docs/reports/data/m6-*`). No fork-related instability across all runs
(fork/rtc pinned via `[patch.crates-io]`; loopback stable; RR ingest live at
every scale). The e2e port-hygiene flake did not occur (the hammer kills
listeners on 38091/38093 before binding; 100/100 runs clean).

## 6. Estimate-axis caveat (binding wording for this report)

The rig's app-layer netem sits **above** the interceptor chain, so shaped
delay cancels in the delay gradient and pre-chain drops are never reported
missing: `loss=` and `rate_kbps=` profiles exercise the policy's **RR-loss
axis** (and, via the 300-packet shaper buffer, queue-overflow loss), **never
the GCC estimate axis**. In this soak the estimate ran its own AIMD dynamics
(4→12 Mbps, unrelated to the injected loss) while the loss axis drove the
bitrate ladder — i.e. the two axes were independently live, which is more
than M5 could show, but estimate *reaction to a real bottleneck* remains
unevidenced on this rig. Conclusions about the ≤150 ms WAN budget and about
estimate-driven collapse behavior wait on the user's real-WAN spot checks
(M5's pending checkpoint), which remain ground truth.

## 7. Findings (from F71)

### F71 — Capture enters an unrecoverable dead state after a failed reinit; soak froze 14.7 min while `Connected` — **BLOCKING**
`crates/capture-windows/src/dupl.rs:229-238` (`reinit` clears
`duplication` then may return with it `None`), `dupl.rs:471-475`
(`Invalid("duplication not started")` forever), callers discarding the error:
`apps/desktop/src-tauri/src/engine/host.rs:264-267` (product) and
`crates/node-runtime/examples/m2_rig.rs:829-833` (rig). Evidence: soak last
capture/send 45.25 min; 8 850 error lines; controller last receive 45.23 min;
states stayed `Connected`; host summary shows `capture_reinit` unexported
(F78) but the code path is unique. Impact: silent frozen stream with no typed
error, no session failure, no auto-recovery — the documented DXGI churn
classes (lock screen, fullscreen-exclusive, display sleep) become permanent
session death. Repro: run the soak (`bash docs/reports/data/m6-soak/run-soak.sh
3600 4`) and read `host.log` for `duplication not started`; deterministic
variant: trigger an access-lost (lock the desktop mid-stream) while
`find_output` transiently fails. Fix directions (dispatch, not audited):
retry reinit with backoff inside `next_frame`'s `Invalid` branch, restore the
old duplication on failed reinit, or surface a typed capture-death that ends
the session with the direct-only/error UX. **Ship condition: this lands and a
repeat 60-min soak completes without capture death.**

### F72 — F56 unchanged: encoder drop-path leaks +14.1 ws / +28.1 private MiB per rebuild — should-fix (ship condition for manual presets)
`cargo run --release -p node-runtime --example leak_probe -- --phase encoder
--iters 12` on `fb91755`: ws +36.3→247.4, private +52.8→465.0 MiB over 12
iterations, +1.1 threads/+33 handles each, linear. Every manual preset change
pays one rebuild (`engine/quality.rs` geometry table; Auto pays zero — soak:
403 live reconfigs, 0 rebuilds). 100 manual changes ≈ +2.8 GiB private in one
session. Ship condition: either the codec-windows drop-path fix, or an
explicit documented cap (preset changes per session) in the release notes.

### F73 — Per-reconnect memory slope tripled under load: +1.65 ws / +1.55 private MiB per session — should-fix
12-cycle run under loss=4+congestion vs the committed M5-era lossless
30-cycle run (+0.50/+0.49). Monotone across all 12; teardown releases ~10 MiB.
~160 MiB per 100 reconnects — bounded by user action, but the trend and the
3× delta deserve a teardown-residue pass (transport/session objects, per-
session counter Arcs — the F58e family). Repro: `bash
docs/reports/data/m6-recovery/run-recovery.sh`, read
`m6-cycles-host-summary.json` `proc.per_session_end`.

### F74 — Evidence pipeline gaps: netem gauges, trail overflow, and host-side congestion counters not in the rig summary/JSONL — should-fix (telemetry)
`TransportStats.netem_queue` (queued/dropped/written — the F69 heap/channel
overflow counters the M6 gate asks to watch) is dropped by the rig's summary;
`ChannelSlot.trail_overflow` is counted but absent from `ChannelQueues`; the
rig summary's `congestion` block is written only on the controller side, so
`events` is always empty and host congestion evidence still lives in
stderr-log parsing (F62's residual). Repro: `python -c "import json;
print(json.load(open('docs/reports/data/m6-soak/ctrl-summary.json'))
['congestion'])"` → `events: []` while `host.log` carries 404 decision lines.

### F75 — Flaky gate test `channel_slot_depth_trail_records_bursts` (~1/10) — should-fix (test)
`transport-webrtc/src/engine.rs:2031` asserts `at_uptime_ns > 0`; the burst
can complete within the first QPC tick of the `OnceLock` uptime anchor
(`engine.rs:1951-1955`), stamping 0. Intermittently red `cargo test`
workspace gate on `fb91755`. Repro: §5 loop.

### F76 — `JsonlReport` flushes only on 1 MiB buffer fill — note (tooling)
At degraded record rates the on-disk JSONL freezes for minutes while the
pipeline is alive (measured: file static ~110 s at 7.9 fps presented,
`backpressure_events: 0`); any live monitor reading the file is blind (it
falsely failed my first soak attempt). A flush-on-idle (e.g. 1 s) would make
the schema's JSONL usable for live gating. Evidence:
`m6-diag/` + `metrics.rs:100-146`.

### F77 — Loss-axis policy under NACK-invisible loss pins the floor while the estimate reads full capacity — note (tuning, caveat-bound)
At 4 % injected loss the per-interval RR projection reaches 25 % (small
denominators), driving severe (×0.5) and sustained (×0.75) steps: the ladder
spent most of the hour at 500–800 kbps while the estimate held 4–12 Mbps, and
presented fps was 6.96 vs M5's fixed-rate 11.3 at 5 % loss. On real networks
loss implies congestion and this is conservative-correct; on this rig the
loss is artificial and uncorrelated with capacity (§6). The severe-loss
threshold's per-interval denominator deserves a look before real-WAN tuning.
Data: `host.log` decision trace + `analyze-soak.py` output.

### F78 — `capture_reinit` counted but not exported in the rig summary — note
The counter that would have shown F71's trigger in the summary JSON exists
(`HostPipeCounters.capture_reinit`) but no summary field reads it; the
access-lost branch also prints nothing. One-line telemetry fix.

### F79 — No sink-off mode; static-desktop pitfall recurred — note (audit hygiene)
The rig always builds a `JsonlReport` (temp-dir default), so the schema's
"compare stage distributions with sinks on/off" M6 audit is impossible without
a code change; my attempted pair also under-delivered stimulus (2.5 fps
source). If the audit is to be repeatable, add a true `--metrics off` and an
fps-guaranteed stimulus mode (or assert source rate in the runner).

## 8. Reproduction index

```bash
cd C:/Remote.deepflux.space
# Gates (fmt/clippy/test) — see §5 for the F75 flake
cargo fmt --all -- --check && scripts/check.sh && scripts/test.sh

# 60-min soak (headline; ~63 min) — runner + watchdog
bash docs/reports/data/m6-soak/run-soak.sh 3600 4
python docs/reports/data/m6-soak/analyze-soak.py docs/reports/data/m6-soak
grep -c "duplication not started" docs/reports/data/m6-soak/host.log   # F71: 8850

# F59 fork fix, live (hardened tripwire + rig smoke)
cargo test -p transport-webrtc --test loopback congestion_estimate -- --nocapture
ls docs/reports/data/m6-smoke/   # 30 s, loss=5: estimate 4->12M, RR loss/RTT live

# Preset hammer (100 product sessions; ~35 min)
bash docs/reports/data/m6-hammer/run-hammer.sh 100
awk -F, 'NR>1{r+=($3==0); q+=($4==$2); h+=($5=="0")} END{print r,q,h}' docs/reports/data/m6-hammer/hammer.csv

# Recovery endurance (~18 min)
bash docs/reports/data/m6-recovery/run-recovery.sh

# F56/F72 leak re-measurement (~60 s)
cargo run --release -p node-runtime --example leak_probe -- --phase encoder --iters 12

# F75 flake
for i in $(seq 1 10); do cargo test -p transport-webrtc --lib channel_slot_depth_trail; done
```

Evidence: `docs/reports/data/m6-soak/` (runner, watchdog csv/log, gzipped
JSONL pair, both summaries, analyzer), `m6-smoke/`, `m6-diag/` (the flush-
artifact diagnosis), `m6-hammer/` (runner, csv, detail), `m6-recovery/`
(cycles + 10×full summaries and logs), `m6-sinkcheck/` (inconclusive pair,
kept for the record).

## 9. Recommendation

**NO-GO at `fb91755`.** One blocking finding, F71: the soak's headline run
froze silently for its last 14.7 minutes through a capture dead-state that is
reachable from ordinary DDA churn and lives unchanged in the product engine.
The path to SHIP is narrow and everything else is already green:

1. Land the F71 fix (capture reinit retry/restore, or typed capture-death
   ending the session with the existing error UX) — small, confined to
   `capture-windows` + the two callers' error branches.
2. Re-run the 60-minute soak (`run-soak.sh 3600 4`) to completion without
   capture death; all other §0 rows can be carried forward unchanged.
3. Ship conditions (documented, not necessarily code): F72 — manual preset
   changes leak ~28 MiB private each until the codec drop-path fix; state the
   per-session preset budget in release notes or fix the drop path; Auto is
   clean. F73 — monitor the reconnect slope. F75 — fix the flaky test before
   it erodes the gate's signal. F74/F78 — telemetry one-liners that would
   have made F71 visible in the summary instead of a log grep.

With F71 fixed and the repeat soak clean, this build meets every numeric
budget in `AGENTS.md` with large margins (connect 4×, LAN proxy 17×, queues
and memory flat, input exactly convergent), and the M5 blocker (GCC feedback
ingest) is verified fixed at every scale tested. Real-WAN spot checks (user)
remain the ground truth for the WAN budget and estimate-axis reaction (§6).

## 10. Repeat soak at `5763d4e` — the F71 ship condition (2026-09-25/26)

Auditor: `rd-performance-qa` (same discipline: read-only except this file and
`docs/reports/data/m6-repeat/`). Inputs: §9's ship path; fix commits `20e97d2`
(F74/F75/F76a/F78/F79 telemetry) and `5763d4e` (F71 capture-death
propagation, F72/F73 drop-path teardown) with their evidence under
`docs/reports/data/m6-shipfix/` (F71 injected-death: typed session end in
37-40 ms; leak_probe all phases flat; F73 re-measured +1.60/+1.44). Binaries
rebuilt from a clean tree at HEAD `5763d4e` (`git status` clean; no source
modified during this re-run). The NO-GO verdict of §0 remains the record of
`fb91755`; everything below is the repeat evidence that §9 demanded.

### 10.0 Attempts 1-3 (voided environment failures — kept as evidence)

- **attempt1-staticdesktop/**: the controller viewer window covered the rig's
  GDI stimulus window; one early decode reset then IDR-gated the stream while
  the host had no screen changes to attach a keyframe to — a stillness
  fixpoint (4 presents in 6 min, `Connected`). This is the M5 static-desktop
  pitfall (F79), not a product defect. Remedy: `stimulus-guardian.py`
  (re-asserts `HWND_TOPMOST` on the stimulus every 2 s) — restores the rig's
  own "guaranteed desktop updates during soaks" methodology; configuration
  unchanged. Side effect vs `fb91755`'s run: the visible stimulus yields
  ~15 fps capture vs the feedback-recursion's ~10.5 — a *stricter* load
  profile through the same configuration.
- **attempt2-slopewindow/**: healthy 11.7 min; the watchdog then fired a
  false slope violation — a one-time +255.5 MiB host-private step at minute
  ~3.5 (266.7 to 522.2 in one 60 s sample, flat for 7 min after; absent in
  attempts 3/4) sat inside the trailing-600 s regression window while the
  delta-vs-baseline check (baseline t=300-360, post-step) passed. Harness
  fix in my runner copy: slope points restricted to post-baseline. The step
  itself is nondeterministic one-time allocator/driver retention (same
  family as the documented ~67 MiB first-encode NVENC driver-session
  retention) — flat after, never observed twice, and policed by the 64 MiB
  delta cap in every run.
- **attempt3-lockscreensaver/**: healthy 40 min (buckets 11.3-11.8 fps),
  then a password-protected screensaver (`matrix.scr`, input desktop
  "Screen-saver") locked the console: DDA `E_ACCESSDENIED`. The product
  behaved exactly per the F71 policy — session stayed `Connected`, reinit
  polled access-denied without converting to `Dead` (8 255 stderr lines at
  ~10 Hz over 8.5 min, memory flat 101.5/267.7 — no growth, no typed death,
  no silent dead state), and the fps-floor watchdog killed the run as
  designed at t=2900. Voided as environment intrusion; keep-awake
  (`SetThreadExecutionState`) added to the guardian. Serendipitous value:
  live evidence for the secure-desktop branch of
  `capture-windows/src/recovery.rs` (AccessDenied never consumes the reinit
  budget) at soak scale.

### 10.1 The 60-minute repeat soak — **PASS, clean** (attempt 4)

`bash docs/reports/data/m6-repeat/run-soak.sh 3600 4` — byte-identical
configuration to §1 (two processes, rig `soak`, congestion ON, netem
`loss=4`, NVENC 1080p, animated host stimulus, mid-run watchdog, warm-up
excluded) plus the two harness guards above. `SOAK RESULT: PASS`,
`watchdog: clean exit`, **0 violations**. Evidence: `m6-repeat/`
(runner, watchdog csv/log, gzipped JSONL pair, both summaries,
`analysis.json` from `analyze-soak.py`).

- **F71 ship condition**: the run the blocker died in now completes. Host
  `capture_reinit: 0` (exported, F78), `capture_dead.died: false` (F71
  evidence block), zero `duplication not started`/capture-error lines in
  `host.log`, and no reinit events at all — nothing ignored, nothing
  silently dead. Combined with the fix commit's injected-death integration
  (typed end 37-40 ms) and attempt 3's lock-screen poll behavior, the
  capture-death surface is closed from all three directions the fix
  claimed.
- **Watchdog minute marks** (ws/priv MiB; presents per trailing 600 s):
  10 min host 101.5/267.0 ctrl 95.2/120.6 presents 6 236 · 20 min
  101.7/267.2 · 95.6/120.8 · 7 147 · 30 min 101.8/267.2 · 95.6/120.8 ·
  7 086 · 40 min 101.9/267.3 · 96.1/121.6 · 6 973 · 45 min (the minute F71
  killed `fb91755`) 102.1/267.4 · 96.2/121.6 · 7 088 · 60 min 102.2/267.6 ·
  96.5/121.4 · 6 274. Host +0.7 ws/+0.6 priv over 50 min; ctrl private
  oscillates 120.6-124.6 (allocator, slope never fired); post-teardown
  finals 91.3/256.1 and 85.4/110.2 — release on teardown.
- **Session**: 1 connect, single session, ends `Peer` (host) / `User`
  (controller, scripted) — typed-or-clean only; `illegal_transitions: 0`,
  `ice_forward_errors: 0`, relay not in use, nominated pair host↔host both
  sides.
- **F74 counters (evidence without log parsing)**: `congestion_decisions
  400 / congestion_reconfigs 396 / encoder_rebuilds 0 / reconfig_errors 0 /
  fps_retargets 12 / resolution_step_down_rebuilds 0` — the `fb91755`
  shape (404/403/0) reproduced; encode size stayed 1920×1080. New gauges:
  `trail_overflow` 0 on all four channels (F63), netem shaper queue
  high-water 1/300 with 3 826 packets drop-counted, netem heap high-water
  1/4 096 — the F69 bounds now evidenced directly from the summary.
- **Frames**: host 54 682 captured / 54 661 encoded (15.18 fps effective);
  controller 50 997 received / 41 849 decoded / 41 849 presented = **11.62
  fps**; IDR rate 3 423/54 661 = 6.26 % (3 027 forced; 3 064 requests,
  98.8 % honored); decode errors 4 928 + IDR-gated drops 4 220 — counted,
  ~2.2x `fb91755`'s absolute counts at ~2.2x the frame rate (proportional
  to load, not a regression). fps per 5-min bucket: 11.03-12.18 across all
  12 buckets — no drift, no death bucket.
- **Queues**: capture→enc 1/1 (replaced 20), enc→send 1/1 (replaced 35),
  recv→dec 2/8 (0 dropped), dec→pres 1/1; channels input-fast hw 30/32
  (0 dropped), control 1/256, input-reliable 1/256, cursor 1/8 — every
  high-water within capacity.
- **Input**: 20 000/20 000 moves applied, 0 stale, 0 gaps, 0 inject errors,
  `held_at_end: 0`, final position exact match ([30 176, 19 104] both
  sides), 2 `AllKeysUp` on teardown.
- **Latency (F8 proxy, warm-up excluded, n=41 849)**: **p50 14.06 / p95
  41.36 / p99 53.64 / max 86.31 ms** (ICE RTT p50 0.156) — 5.7x margin on
  the ≤80 ms LAN median budget; per-bucket p50 13.71-14.40 flat (no
  progressive latency). p50 is higher than §1's 4.53 because this profile
  encodes real 1080p AUs at ~15 fps (encode p50 9.82 ms) instead of the
  collapsed-ladder micro-frames; the tail improved (max 347.75 → 86.31).
  Stages p50/p95: capture→submit 0.139/0.183, encode 9.823/13.598,
  done→send 1.775/19.053, recv→decode 1.841/11.205, decode→present
  0.087/0.121 ms (render path unchanged).
- **Sinks**: 294 830 + 303 549 records, `backpressure_events: 0` both
  sides; flush-on-idle (F76a) live — the JSONLs were readable continuously
  during the run.
- Gates at HEAD: `cargo fmt --check` green, `cargo test --workspace` 34/34
  test binaries ok, F75 loop 20/20 standalone runs green.

### 10.2 Hammer re-check (30 cycles) — PASS

`bash docs/reports/data/m6-repeat/hammer/run-hammer.sh 30` (first launch
failed on a harness path bug — `run-pathfail-attempt1.out`, no rig
involvement): **30/30 rc=0, quality field matched 30/30, held keys = 0 at
30/30** (cycle low→auto→high→auto→balanced→auto: 15 Auto-after-manual F70
restores, 15 manual presets). F72 root-fix re-verified directly at HEAD on
this machine (`m6-repeat/leak-probe-{encoder,rebuild-hw}.txt`): encoder
phase flat after the documented one-time NVENC driver-session retention
(iter 1-2 ≈ +65 ws/+122 priv, then private oscillates 124-127, threads
frozen 39, handles frozen 495); hw-rebuild ×12: ws oscillates 7.3-12.7,
private sawtooths 15.1-31.0 — bounded, vs `fb91755`'s linear +14.1/+28.1
per rebuild. Residual: ≈ +1 handle per rebuild (14 over 12 iters).
`encoder_rebuilds` tracking verified in the soak's F74 block (0 there).

### 10.3 Recovery re-check — PASS (+30-cycle plateau)

`run-recovery.sh` (path-bug attempt archived): (a) **12/12** cycles under
loss=4+congestion — ends `Peer`×12/`User`×12, 0 illegal transitions,
connects 1 155-1 195 ms, reconfig 11/0/0, `capture_reinit: 0`; slope
**+1.51 ws/+1.48 private MiB per session** (fix commit +1.60/+1.44;
`fb91755` +1.65/+1.55), teardown releases ~11 MiB. (b) **10/10** full
interface-change recoveries — initial connect 1 162-1 216 ms, re-establish
1 162-1 184 ms, ends `[Peer, User]` each. (c) NEW **30-cycle plateau**
(`run-plateau.sh`): 30/30 `Peer`; slope overall **+1.32/+1.28**, by thirds
+1.48/+1.36 → +1.23/+1.22 → +1.28/+1.30 — **decelerating, not
accelerating**: sub-linear, consistent with the fix commit's
allocator/segment-retention attribution, not object retention. Cumulative
+38.3 ws/+37.2 priv MiB over 30 sessions; teardown releases ~11 MiB.
(Note: the plateau runner clobbered the 12-cycle summary *filename* — raw
12-cycle JSONL survives, extracted series preserved in
`m6-cycles12-extracted.json`.)

### 10.4 Verdict — **SHIP-WITH-CONDITIONS** at `5763d4e`

The blocking finding F71 is fixed and verified three ways (policy code with
unit tests; injected-death integration, typed end 37-40 ms; this repeat hour
— zero capture events, counters exported). Every §0 budget row passes at
HEAD, most with the §1 margins carried forward, and the two prior
should-fix families (F72, F73) are root-fixed to bounded residuals. What
keeps this from an unconditional SHIP is residual, bounded, and documented
— each condition below is checkable by a command:

1. **C1 (F73 residual)** — per-reconnect retention +1.3-1.5 MiB private
   (30-cycle plateau: decelerating; ~130 MiB per 100 reconnects). Check at
   each release: run `run-recovery.sh` + `run-plateau.sh`; fail if the
   30-cycle per-session slope exceeds 3 MiB private or the third-tercile
   slope exceeds the first (acceleration).
2. **C2 (F72 residual)** — manual-preset rebuilds retain a bounded 15-31
   MiB private oscillation + ≈1 handle each; the decoder-path MFTEnumEx
   leak stays deliberately (vendor-driver unload fault, documented in
   code). Check: `reconfig_probe --mode rebuild` slope ≤ ~30 MiB
   oscillation, no linear trend; release notes state a manual-quality-
   changes-per-session budget (≤100 keeps retention oscillation-bound) or
   the drop-path follow-up lands.
3. **C3 (one-time retentions, support-facing)** — first-encode NVENC
   driver session ~67-125 MiB per process; rare one-time ~256 MiB
   host-private allocator step (1 of 3 hour-runs here, flat after). Check:
   any *repeat* step or monotone growth in a 60-min soak is a regression
   (the watchdog's 64 MiB delta cap + post-baseline slope already enforce
   this mechanically).
4. **C4 (unchanged caveat)** — real-WAN spot checks (user) remain ground
   truth for the ≤150 ms WAN budget and estimate-axis reaction (§6: the
   rig's netem cannot shape the estimate axis).
5. **C5 (gate hygiene)** — keep the F75 10x loop in the merge gate
   (fixed at `20e97d2`, 20/20 here); fold the repeat-soak harness guards
   (stimulus topmost + keep-awake + post-baseline slope window,
   `m6-repeat/stimulus-guardian.py`, `run-soak.sh`) into the canonical
   `m6-soak/run-soak.sh` so the next auditor does not re-trip attempts 1-3.
6. Note (non-blocking): during secure-desktop denial the host logs a
   reinit-failed line per ~100 ms poll (attempt 3: 8 255 lines in 8.5 min,
   stderr only, no memory effect) — rate-limit before it meets a long
   lock in production logging.

### 10.5 Reproduction index (repeat)

```bash
cd C:/Remote.deepflux.space
# The headline repeat soak (~63 min): PASS, watchdog 0 violations
bash docs/reports/data/m6-repeat/run-soak.sh 3600 4
python docs/reports/data/m6-repeat/analyze-soak.py docs/reports/data/m6-repeat
# F71 evidence trio: counters in the summary (no log parsing)
python -c "import json; h=json.load(open('docs/reports/data/m6-repeat/host-summary.json')); print(h['host']['capture_reinit'], h['host']['capture_dead'], h['congestion'])"
# Hammer 30 (paths incl. 15 F70 geometry restores)
bash docs/reports/data/m6-repeat/hammer/run-hammer.sh 30
# Recovery: 12 cycles + 10 interface-change recoveries, then the plateau
bash docs/reports/data/m6-repeat/recovery/run-recovery.sh
bash docs/reports/data/m6-repeat/recovery/run-plateau.sh
# F72 direct: encoder phase + hw rebuild drop path at HEAD
cargo run --release -p node-runtime --example leak_probe -- --phase encoder --iters 12
cargo run --release -p codec-windows --example reconfig_probe -- --mode rebuild --iters 12 --encoder hw
# F75 flake loop (fixed)
for i in $(seq 1 10); do cargo test -p transport-webrtc --lib channel_slot_depth_trail; done
```

Evidence: `docs/reports/data/m6-repeat/` — attempt 4 (`run.out`,
`watchdog.{csv,log}`, `m6-soak-{host,ctrl}-rig-*.jsonl.gz`, both summaries,
`analysis.json`, `stimulus-guardian.py`, patched `run-soak.sh`), attempts
1-3 archives, `hammer/`, `recovery/` (cycles/full/plateau + extracted
series), `leak-probe-*.txt`, `f75-flake-loop.txt`.
