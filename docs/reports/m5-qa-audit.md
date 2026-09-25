# M5 QA audit — WAN tuning & matrix (RD-013), commit `e295b0e`

Date: 2026-09-25/26 · Auditor: `rd-performance-qa` (read-only; this file is the
only write) · Inputs: `PLAN.md` §4 M5 + §2 invariants, `AGENTS.md`,
`docs/reports/m5-matrix.md`, `docs/reports/data/m5-matrix{,-run1,-run2}/`,
`docs/perf-counter-schema.md`, `docs/reports/m4-qa-audit.md` (findings F48–F58).

## Verdict

**PASS-WITH-FINDINGS.** The M5 gate as written in `PLAN.md` §4 — *matrix
results + a written expected-direct-only-failures section with the explicit
error UX* — is met and the evidence is reproducible (§2 below). The congestion
*machinery* (pure policy + live `ICodecApi` reconfigure + fps/resolution
tiers + Auto-only instantiation) landed and is unit-pinned; the closed
feedback loop is **not live** (F59, self-reported, verified worse than
reported in one respect: not even loss reacts in the matrix). That is the
top blocking-for-M6 item and does not invalidate what the matrix does prove:
queue bounds, zero rebuilds, recovery timing, and the failure UX. Findings
continue from F58: F59 blocking-for-M6, F60–F63 should-fix, F64–F70 notes.

## 1. Gate reproduction (all green, timings recorded)

| Gate | Command | Result | Time |
|---|---|---|---|
| Format | `cargo fmt --all -- --check` | pass | 0.4 s |
| Lint | `scripts/check.sh` (clippy workspace `--all-targets -D warnings`) | pass | 1.6 s (warm) |
| Workspace tests | `scripts/test.sh` (cargo + signaling TS + headless contract) | pass (35 test-result blocks, incl. signaling 21/21) | 50.9 s |
| Ignored set | `cargo test --workspace -- --ignored` | 13 tests pass | 13.5 s |
| — internet-gated | `stun_gathers_srflx_when_online` | **ran online and passed** (0.11 s; not skipped — this machine has internet). Also `duplication_acquires_real_frames`, `sendinput real`, 9 codec tests, `two_nodes_connect_through_the_real_service` | — |
| Transport M5 set | `cargo test -p transport-webrtc` | 25 lib + 10/11 loopback pass | 8.5 s |
| Congestion policy | `cargo test -p node-runtime --lib congestion` | 10/10 pass | 0.7 s |
| App TS gate | `pnpm run typecheck && lint && test` (apps/desktop) | 38/38 vitest | ~10 s |
| App E2E | `M4_E2E=1 cargo test -p remote-desktop-app --test e2e -- --nocapture` | 1/1 pass | 21.3 s test / 30.3 s wall |
| GCC repro | `cargo test -p transport-webrtc --test loopback congestion_estimate -- --nocapture` | passes **vacuously** (F59b): prints `estimate=2000000 delay_based=Some(2000000) loss_based=Some(2000000) updates=359` — delay/loss halves equal the configured initial (frozen), updates timer-driven | 6.2 s |

## 2. Evidence verification (matrix recomputation)

Method: regenerated `matrix-summary.json` from the committed per-cell inputs
via `scripts/m5-summarize.py` in a scratch copy (`M5_MATRIX_DIR` override) —
**byte-identical (0 diffs)**; then independently recomputed headline numbers
straight from the gzipped JSONL, bypassing the summarizer.

- **fps/table numbers match**: every cell of the §3 table in
  `m5-matrix.md` equals `matrix-summary.json` (e.g. baseline 3287 frames /
  51.3 fps; loss10 313 / 4.9; worst 262 / 4.1). My independent fps-over-
  present-span (51.8/35.3/4.9/35.8/46.5) agrees within the denominator
  choice (rig `render_secs` vs present-span).
- **Input-to-visible proxy p50 matches exactly** for the cells I recomputed
  from raw frame timings (baseline 8.1, loss1 4.5, loss10 8.6, rtt250 8.4,
  bwstep 5.7 ms) — host capture→send p50 + ICE RTT + controller recv→present,
  no cross-domain subtraction, `proxy` labeled as the schema requires.
- **Queue high-water ≤ 1 across ALL cells**: `capture_to_encode` and
  `encode_to_send` high-water = 1 in all 11 streaming cells (udpblocked
  null); `decode_to_present` = 1 everywhere; `recv_to_decode` ≤ 4 against
  the post-fix capacity 8. The invariant-3 claim as worded is true.
- **Recovery timings verified**: iface cell summary has both sessions —
  initial connect 1199 ms, re-establish 1172 ms, teardown at 42.667 s,
  `ends: ["Peer","User"]` (goodbye observed, no consent-timeout wait);
  5487 frames across both sessions. Matches the report.
- **Run provenance distinguished**: `m5-matrix-run1/` rtt150 has
  `recv_to_decode` capacity **2** / 2102 presented; final run capacity **8**
  / 2660 — the committed matrix is definitively the post-pacer-fix binary.
  `m5-matrix-run2/` shows the invalidated static-desktop numbers (baseline
  1105 frames / 17.3 fps) and is explicitly written off in §3 obs 5.
- **Cell durations**: 64.0–64.1 s render for soak cells, 84.1 s bwstep,
  106.8 s iface (two sessions) — the "≥ 60 s each" claim holds; udpblocked
  is the expected-failure cell (31.1 s, `failed: true`, failures
  `["connect timeout","no session established"]`, ends `Timeout`,
  signaling counters nonzero — "signaling ok → ICE dead" demonstrated).
- **"Congestion ON" verified, but not from the summary JSON**: every
  streaming cell's host log has exactly one `congestion decision:
  bitrate=Some(3600000)` and one `congestion: bitrate -> 3600000 bps
  (live)` line (0 rebuilt, 0 errors); `scripts/m5-matrix.sh` passes
  `--congestion on` for every cell. The `congestion.enabled: false` in
  `matrix-summary.json` is the *controller-side* congestion (correctly off
  — the controller sends no media); the block mixes provenances (F62).

## 3. Congestion-policy audit (`node-runtime/src/congestion.rs` + wiring)

**Hysteresis/cooldowns — correct and tested.** Severe-loss ×0.5 is
rate-bounded by `min_step_ms` (500 ms) even in the emergency branch;
sustained loss needs 2 consecutive samples; increases need a 3-sample clean
dwell + loss < 1% + RTT-trend guard (< 2.5× running-min baseline) + 3 s
down→up cooldown + 1 s up cooldown + ceiling = estimate×`estimate_safety`;
the `<5%`/100 kbps `min_delta` filter suppresses jitter steps; the
alternating-stress test bounds direction changes ≤ 10 (assert), and the
same-factor ceiling (0.9 follow = 0.9 ceiling) is the anti-flap fix with a
measured justification (3.6M↔3.8M flap at 0.95). 10/10 tests pass in 0.7 s.

**fps-cap ordering — coherent.** `pick_fps` runs after the bitrate step in
the same `sample()`, so the fps band follows the *new* target; band entry
down is immediate, recovery needs 1.2× the band threshold + 5 s dwell
(unit-tested 15→30→60 ladder). Down-follow of the estimate is deliberately
not rate-bounded (GCC already rate-limits the estimate) — documented.

**720p once-per-session — double-guarded.** Controller state
(`resolution_stepped_down`) *and* engine `congestion_res_stepped_down`; the
sustain window resets on any recovery sample (tested). It is the only
`want_reconfig` (rebuild) emission in `drive_congestion`.

**Manual presets never instantiate the controller — verified.**
`engine::drive_congestion` (apps/desktop `engine/mod.rs:1510`) sets
`self.congestion = None` whenever preset ≠ Auto or host not Connected;
controller is created lazily on the first Auto tick. Wire path: observer's
`SetQuality` handler skips `want_reconfig` for Auto (no rebuild), manual
presets rebuild once — matches the report.

**Signals + cadence — present, 1 Hz.** `TransportStats` carries
`available_bandwidth_bps`, `remote_loss_percent`, `remote_rtt_ms`,
`rtt_ms`, `send_bitrate_kbps`; `sample_link_stats` runs on the engine's
1 s tick and `CONTROL_INTERVAL` is 1 s — matched. `LinkSample` gained the
three M5 fields additively and `docs/perf-counter-schema.md` documents them
as additive optional (schema policy respected).

Warts: the module doc (line 42) still says increases are "capped at
estimate × 0.95" while code and report use 0.9 (F64); the RTT baseline is a
running **min** that never decays within a session (F65); see F60/F61 for
the input-value defects.

## 4. The frozen-estimate issue (F59) — assessment

**The self-report is honest and I confirm it from the committed data — it is
actually slightly worse than "estimate-driven adaptation not evidenced":**

- In every streaming cell the estimate published exactly two distinct values
  in the JSONL: `0` (pre-first-publish, ~1.2–2.2 s) then `4000000` for the
  whole session (`gcc_estimate_kbps.p50/p95/p99/max` all 4000 in all cells).
- `remote_loss_percent` is `Some(0.0)` in the **loss cells with 10.15%
  measured loss** (`remote_loss_percent_mean = 0.0` in all 12 cells;
  `loss10-rig-host.jsonl` contains only `{None, 0.0}`). Same for
  `remote_rtt_ms`.
- Therefore the controller made **exactly one decision per cell — the
  initial estimate-follow** (6 Mbps start → 4 Mbps × 0.9 = 3.6 Mbps,
  visible as the single `bitrate -> 3600000 bps (live)` host-log line), and
  **zero reactive decisions anywhere in the matrix**. Matrix cells are not
  "loss/RTT-driven adaptation": the loss signal is dead, so loss cells
  degrade purely through the receiver IDR-gate/decoder path at a constant
  3.6 Mbps encoder rate. The report's §1.2 table and §3 obs 1 describe the
  policy; the matrix evidences *stability under a fixed target*, not
  reaction. To its credit the report never claims otherwise for the loss
  cells, but "congestion adaptation" as a delivered M5 work item is, live,
  a fixed-rate pipeline with unit-tested reaction logic.
- Reproduction confirms the mechanism: `congestion_estimate...` test prints
  delay/loss halves frozen at the configured initial with timer-only
  `updates`; `CongestionPublish::snapshot` (transport `engine.rs:432`)
  returns `Some(target_bps)` unconditionally — the atomic starts at 0.
  `get_stats`' `RemoteInboundRtp` entry exists with zero fields (facade
  surfaces the entry, values dead), so SDP/interceptor registration is
  genuinely not the problem — consistent with "interceptors active, SDP
  verified". `register_default_interceptors` (rtc 0.21) does include the
  receiver-side TWCC responder + RR generator, so the receiver *should* be
  emitting feedback; the ingest break is in the webrtc-0.21 facade layer,
  as self-reported.
- **Test vacuity (F59b)**: `congestion_estimate_and_remote_report_surface`
  (transport `tests/loopback.rs:827`) asserts only `.is_some()` for
  `remote_rtt_ms`/`remote_loss_percent` — `Some(0.0)` satisfies it, so the
  pinned test cannot fail while the feature is dead. This is the same
  class as M4's F53 (evidence claim not actually asserted).

**Is the M5 gate still met?** Yes, with the finding. `PLAN.md` §4 M5's gate
text is "matrix results + a written section documenting expected
direct-only failures with the explicit error UX" — both delivered and
reproducible. The work item "congestion adaptation" is delivered as: policy
(pure, tested), application path (live reconfigure, zero rebuilds — the
CR-1-critical property), and transport GCC wiring, with the feedback-ingest
link missing and disclosed as the first M6 item. I judge this
pass-with-findings rather than fail because (a) the gate's letter is met,
(b) every claim the matrix *does* make (queues, rebuilds, recovery, failure
UX, stability) verified true, and (c) the missing link is isolated, has a
faithful repro, and its absence makes the matrix *harsher*, not flattering.
But M6 must not start soak/tuning before F59 lands — everything
estimate-driven is otherwise unexercised.

**M6 fix sizing (F59a):**

1. *Facade diagnosis + upstream issue + `[patch]` fork of webrtc 0.21* —
   first trace where received RTCP should reach
   `BandwidthEstimator::on_reports` in the facade's driver/rtp path vs the
   rtc-core example composition. Estimate: 2–4 days including a fork/pin
   and the hardened regression test (assert `remote_rtt_ms > 0.0` and a
   delay/loss-half divergence under shaping, not `.is_some()`).
2. *Direct rtc-core composition behind the `Transport` seam* (ADR-002's
   fallback logic) — 1–2 weeks; the facade currently owns negotiation,
   demux, data channels, stats.
3. *Bridge now (optional, 1–2 days)*: pin the estimate from app-layer
   feedback — the controller already measures loss/bitrate in its
   `TransportStats`; a periodic stats message on `control` feeds the same
   policy. Cost: a new `WireMessage` variant = WIRE_VERSION bump per the
   bincode policy (explicit contract change). Reasonable only if the
   facade fix stalls.

Whichever lands: fix F61 first or together, else the policy's loss guard
stays inert (RR zeros read as "perfectly clean") and probing-up under real
loss becomes possible once the estimate moves.

## 5. Invariant audit

- **Invariant 4 (TURN)**: enforced at the config layer —
  `WebrtcTransportOptions::validate` rejects `turn:`/`turns:` schemes with a
  typed `TransportError` naming invariant 4, before any peer connection
  exists; pinned by `turn_ice_servers_are_rejected_at_configuration`
  (turn, turns, unknown scheme, plus congestion-tuning ordering).
  Runtime backstop: `sample_link_stats` errors on `relay_in_use` every
  second; `wan()` = two Google STUN servers only; app builds every
  transport via `WebrtcTransportOptions::wan()` (engine `ensure_transport`),
  controller drops `congestion`. No gaps found.
- **Invariant 3 (bounded queues) in the new paths**:
  - `input-windows::capture`: queue cap 256, drop-oldest, counted, tested.
  - netem: shaper channel bounded at 300 (`try_send` overflow → counted
    drop); input `DelayQueue` bounded with `dropped` counter (0 in all
    cells). Note the shaper's due-heap has no explicit cap (F68) — bounded
    in practice by profile physics (delay × rate), test-only surface.
  - Channel send queues unchanged: input-fast 32 drop-oldest (HW 30/32
    observed, `replaced=0` — a burst drained, no violation), control/
    input-reliable 256 error-on-full.
- **Invariant 6 (no SDP/input in logs)**: new M5 log lines (congestion
  decisions, netem swaps, connect timings) carry numbers/addresses only; no
  SDP bodies or input payloads found in the committed cell logs.
  `ViewerInputEvent`'s `Debug` is a plain derive (coordinates) — module
  docs scope it to tests (F67).
- **CR-2 unsafe audit** (`input-windows/src/capture.rs`, 521 lines, 7
  unsafe): failure handling is reviewed (subclass failure → typed `Err`;
  teardown race → `DefWindowProcW` fallback; Drop restores the original
  proc, best-effort). Focus-loss completeness: `WM_KILLFOCUS` →
  `AllKeysUp{FocusLost}`; F48/F49 geometry pinned by 5 tests (letterbox
  drop-not-clamp, 1:1 crop, degenerate rects) — note the expected rects are
  a *duplicated* helper, drift is caught only if someone re-pins (platform
  crates may not depend on each other; documented). `WM_SETFOCUS` still
  discards a queued `AllKeysUp` (F58d carried, F67). `apps/desktop`
  viewer.rs contains no unsafe (confirmed) — but AGENTS.md's blanket
  "`apps/desktop` is unsafe-free again" overstates: `engine/displays.rs`
  (CR-3, unlanded) and `bin/e2e_child.rs` still hold Win32 unsafe (F66).

## 6. Expected-failure UX (task 6)

Code-verified end-to-end: rig udpblocked cell → controller `ConnectTimeout`
→ `session_ended(Timeout)` → `disconnect_copy` (engine/mod.rs:133) →
`SessionEnded{cause: "Timeout", code: "timeout", message, hint:
DIRECT_ONLY_HINT}` over the bounded event channel; TS
`state/mapping.ts`/`reducer.ts` surface `lastEnd` (code/message/hint) and
`disconnectCopy` mirrors the same codes (19 mapping tests pin both
directions); `TransportError` → `transport_error` + the same hint. The
committed cell summary proves the session-level leg (bounded 31 s, typed
cause, no hang). Gap (self-declared, agreed): no scripted app-level E2E
connect-failure case — `M4_E2E` only connects successfully. Recommend the
M6 addition (unreachable peer → assert the `timeout` `SessionEnded` event
with the hint reaches the shell) — should-fix, not blocking.

## 7. Findings (from F59)

### F59 — GCC feedback ingest inert; matrix adaptation = one fixed step — **blocking-for-M6**
Transport `engine.rs` (`CongestionPublish`, `stats()`), policy
`congestion.rs`, facade boundary. Estimate frozen at 4 Mbps initial in all
cells; RR loss/RTT dead (`Some(0.0)`) even at 10.15% measured loss; one
decision per cell (initial 6→3.6 Mbps), zero reactive decisions anywhere.
Sub-finding (b): the pinned surface test asserts `.is_some()` and passes
vacuously. Repro: `cargo test -p transport-webrtc --test loopback
congestion_estimate -- --nocapture` (delay/loss halves = initial;
updates timer-only); data: `docs/reports/data/m5-matrix/m5-loss10-*`
(`remote_loss_percent {None,0.0}` vs `loss_percent_mean 10.15`). Fix sizing
in §4. No tuning or soak work before this lands.

### F60 — `available_bandwidth_bps` publishes `Some(0)` before the first GCC update — should-fix (M6, small)
`CongestionPublish::snapshot` returns `Some(target_bps)` from a
zero-initialized atomic; observed as `0` at t≈1.2–2.2 s in every cell's
JSONL. If streaming starts before the first estimator publish, Auto's first
tick sees estimate 0 → down-follow clamps to the 500 kbps floor and climbs
back additively (visible bitrate dip). Today masked only by timing (first
estimate lands ~3.2 s, pipeline later). Publish `None` (or gate the
controller on the first nonzero estimate) and treat 0 as absent in
`pick_bitrate`. Repro: `zcat docs/reports/data/m5-matrix/m5-baseline-rig-host.jsonl.gz
| grep available | sort -u | head`.

### F61 — Dead RR fields published as `Some(0.0)` instead of `None` — should-fix (M6, with F59)
Transport `stats()` maps a present-but-zero `RemoteInboundRtp` to
`Some(0.0)`, which (a) disables the policy's ICE-RTT fallback
(`remote_rtt_ms.or(ice_rtt_ms)` never falls back on `Some(0.0)`), and (b)
reads as "perfectly clean loss", so the loss gate for increases is inert —
dangerous probing becomes possible the moment F59 makes the estimate move.
Publish `None` when the RR is absent/zero-carrier; add a policy test for
`Some(0.0)` ≠ clean.

### F62 — `matrix-summary.json` congestion block mixes provenances — should-fix (M6 telemetry)
`congestion.enabled`/`events`/`decision_count` come from the
**controller-side** rig summary (always false/empty — controller sends no
media) while `reconfig_live`/`bitrate steps` are string-parsed from the
**host log**. An auditor reading the JSON alone must conclude congestion
was OFF; the ON proof lives only in host-log lines + the script's
`--congestion on`. Emit host-side congestion counters into the rig summary
(e.g. reuse the host log parse into a `congestion.host` block) so the
headline artifact is self-contained. Repro: compare
`docs/reports/data/m5-matrix/matrix-summary.json` (any cell:
`enabled:false, decision_count:0, reconfig_live:1`) with
`loss5-host.log:18-20`.

### F63 — Channel-queue gauges still not sampled on depth change (F58a carried, now with matrix evidence) — should-fix (M6)
The schema's binding cadence ("≥1 Hz plus on every depth change while
non-empty") is still unimplemented: every `channel_input_fast` sample in
every cell records `depth: 0` while `high_water: 30` (capacity 32) — the 1
Hz (host) / ~5 Hz (rig) polls miss the entire burst; only the internal
high-water counter saw it. F58a said "tighten in M5"; it wasn't. The
per-change plumbing (`quick_gauges`) exists — wire it to the engine loop's
fast poll. Repro: `zcat docs/reports/data/m5-matrix/m5-baseline-rig-controller.jsonl.gz
| grep -m3 channel_input_fast`.

### F64 — congestion.rs doc drift: ×0.95 ceiling text vs 0.9 code — note
Module doc line 42 ("always capped at estimate × 0.95") contradicts
`pick_bitrate`'s same-factor 0.9 ceiling and the report's measured
anti-flap rationale. One-line doc fix.

### F65 — RTT trend baseline is a session-lifetime running min — note
`rtt_baseline_ms` never decays; a path whose RTT floor legitimately rises
>2.5× the historical min permanently blocks increases until the controller
is recreated (preset flip or reconnect). Today bounded because reconnects
recreate it; consider a windowed/decaying baseline in M6.

### F66 — AGENTS.md "apps/desktop is unsafe-free again" overstates — note (doc honesty)
True for `viewer.rs` (CR-2 done, verified), but `engine/displays.rs`
(CR-3, still open — M4 audit said M5 should-fix) and `bin/e2e_child.rs`
still contain Win32 unsafe. Reword to the sanctioned-exception list
(displays.rs pending CR-3; e2e_child is a test binary) or land CR-3.

### F67 — capture.rs residual notes — note
(a) F58d carried: `WM_SETFOCUS` discards a queued `AllKeysUp` from a
kill+refocus blur (~2 ms window); keys held across it stay held on the
host until next release — consider sending the release anyway.
(b) `ViewerInputEvent` Debug is not redacted (coordinates); documented,
tests-only printing. (c) The subclass `Drop` relies on `ViewerCtl`'s Arc
outliving the window (engine-loop drop would call `SetWindowLongPtrW`
cross-thread; in practice the window is destroyed first — documented
tolerance, worth a comment at the `Drop`). (d) dest-rect geometry is
duplicated from `render_windows` and pinned by test constants — re-pin if
the renderer's helper changes.

### F68 — netem shaper due-heap has no explicit cap — note
The 300-cap bounds only the pre-shaper channel; the shaper's `BinaryHeap`
is bounded in practice by profile physics (one-way delay × packet rate ≈
40 packets at rtt250) and would grow with a pathological `delay_ms`.
Test-only surface (product options set `video_netem: None`); add an
explicit heap cap + counter if netem survives into M6 tooling.

### F69 — udpblocked cell `ice_forward_errors: 1` — note
One ICE forward error in the expected-failure cell (candidate rewrite /
post-teardown forward). Cosmetic; worth a glance when scripting the M6 E2E
connect-failure case so it doesn't mask a real forward defect.

### F70 — manual→Auto switch keeps the manual geometry — note
Switching Low→Auto mid-session adopts the congestion controller without a
rebuild (correct) but keeps 720p until the once-per-session starvation
step-down (which only steps *down*). Intended per the module docs; document
in user-facing copy if anyone asks why Auto "doesn't go back up".

## 8. M6 input (§6 of the M5 report — evaluated + additions)

Their list is the right shape (GCC ingest first, preset hammer, IDR
amplification, pacer burst, E2E gap, matrix fidelity). Additions:

1. **F59 test hardening as part of item 1** (assert `remote_rtt_ms > 0.0`,
   divergence under shaping) — otherwise the fix can regress silently.
2. **F60 + F61 before any tuning** — else the fixed estimator drives the
   policy against dead loss/zero-estimate semantics.
3. **Soak spec: 60 min with congestion ON at moderate stress** (e.g. 3–5%
   loss + a 2–5 Mbps cap schedule or `bwstep` cycling), not the clean
   loopback soak — the plan's "no unbounded growth under 5% loss" budget
   must be exercised with the controller active (its decision counters,
   reconfigure volume, and any estimate flapping are the soak signals).
   Include the preset+Auto hammer *while* shaped.
4. **E2E connect-failure case** (their item, agreed): unreachable peer →
   assert the typed `SessionEnded{code:"timeout", hint}` reaches the shell
   inside the 10 s window (also covers §4.1 symmetric-NAT copy).
5. **F63 channel-queue per-change sampling** before the soak so the soak
   JSONL actually contains channel bursts.
6. Carry-overs to watch in the soak: M4 F58c (device-lost encoder returned
   to pool), F58e (finished counters Arc growth), F56 leak slope under the
   (now bounded) rebuild paths, F58d/F67a focus-loss drain window.
7. Real-WAN spot checks remain the user's checkpoint (matrix ICE RTT is
   unshaped by construction — §2 of their report says so, correctly).

## 9. Reproduction index

```bash
cd C:/Remote.deepflux.space
# Gates (timings §1)
cargo fmt --all -- --check && scripts/check.sh && scripts/test.sh
cargo test --workspace -- --ignored          # incl. online srflx (13.5 s)
cargo test -p node-runtime --lib congestion  # 10 policy tests
M4_E2E=1 cargo test -p remote-desktop-app --test e2e -- --nocapture
cd apps/desktop && pnpm run typecheck && pnpm run lint && pnpm test

# F59
cargo test -p transport-webrtc --test loopback congestion_estimate -- --nocapture
python - <<'EOF'
import gzip,json,collections
rl=collections.Counter()
for line in gzip.open(r'docs/reports/data/m5-matrix/m5-loss10-rig-host.jsonl.gz','rt'):
    r=json.loads(line)
    if r.get('kind')=='link_sample': rl.update([r.get('remote_loss_percent')])
print('remote_loss values at 10% actual loss:', dict(rl))
EOF

# F60 (estimate Some(0) pre-first-publish)
zcat docs/reports/data/m5-matrix/m5-baseline-rig-host.jsonl.gz | grep -o '"available_bandwidth_kbps": [0-9]*' | sort | uniq -c

# F62 (summary says congestion off; host log says on)
python -c "import json;d=json.load(open(r'docs/reports/data/m5-matrix/matrix-summary.json'))['cells']['loss5'];print(d['congestion'])"
grep -m2 congestion docs/reports/data/m5-matrix/loss5-host.log

# F63 (burst invisible to sampled depth, visible in high_water)
zcat docs/reports/data/m5-matrix/m5-baseline-rig-controller.jsonl.gz | grep -m2 channel_input_fast

# Evidence regeneration (scratch copy, byte-identical check §2)
mkdir -p /tmp/m5verify && cp -r docs/reports/data/m5-matrix /tmp/m5verify/
M5_MATRIX_DIR=/tmp/m5verify/m5-matrix python scripts/m5-summarize.py
# run provenance: recv_to_decode capacity 2 (run1) vs 8 (final)
zcat docs/reports/data/m5-matrix-run1/m5-rtt150-rig-controller.jsonl.gz | grep -m1 -o '"capacity": [0-9]*'

# Full matrix (~15 min) if re-running evidence
scripts/m5-matrix.sh && scripts/m5-summarize.py
```

## 10. Recommendation

**PASS-WITH-FINDINGS.** Tag `m5-wan-matrix` is defensible now: gates green,
matrix evidence reproducible and honest, expected-failure UX documented and
code-verified, queue bounds and zero-rebuild claims verified in every cell.
M6 must open with F59 (ingest fix + hardened test + F60/F61 semantics) and
must define the 60-minute soak with congestion ON under moderate loss;
F62/F63 tighten the evidence pipeline so the soak artifacts are
self-contained. F64–F70 are notes to fold into M6 hygiene.
