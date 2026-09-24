# M1 Performance-QA Audit — Local video loop (DXGI + MF H.264 + D3D11 present)

- Verdict: **PASS-WITH-FINDINGS**
- Milestone: M1 (RD-004, RD-005), gate per PLAN.md §4 M1; quality bar §7
- Audited commit: `dc50c70` (M1 landed in `4aa330b`; M2 spike `b594f35` + integration after), clean working tree
- Auditor: `rd-performance-qa` (read-only except this report and audit run artifacts under `docs/reports/data/m1-qa-audit-60s.*`)
- Date: 2026-09-24
- Scope: gate reproduction; independent recomputation of the committed JSONL evidence; invariants 1/3 (+ unsafe confinement, copy counting); budgets vs measurement; test quality; M1→M2 risks register; light scan of the M2 transport spike for contract contradictions.

## 1. Gate reproduction (run by auditor)

Same machine as the gate run (Windows 10.0.26200, RTX 5080 Laptop GPU, `\\.\DISPLAY5`
3840x2160 primary). Target dir warm from the integration build.

| Step | Command | Result | Wall time |
|---|---|---|---|
| Format | `cargo fmt --all -- --check` | green | 0.22 s |
| Clippy | `scripts/check.sh` | green, 0 warnings | 0.35 s (warm) |
| Tests | `scripts/test.sh` | green: **92 passed, 0 failed** (slowest binary: transport loopback 5.3 s) | 6.49 s |
| Ignored GPU/MF tests | `cargo test --workspace -- --ignored` | **6/6 pass** on the real display: `duplication_acquires_real_frames`, `software_encoder_decoder_round_trip`, `hardware_encoder_candidates_reported`, `converter_scales_directly`, `hardware_encoder_scales_on_rebind`, `hardware_encoder_accepts_gpu_input` | 1.76 s |
| 60 s loop sanity | `cargo run --release -p capture-windows --example local_loop -- --duration-secs 60 --report-stem m1-qa-audit-60s` | exit 0; hardware NVENC + DXVA decoder selected; 3451 captured / 3450 encoded / 3450 decoded / 3450 presented (57.5 fps), 29 keyframes, wire 53.06 MiB, 0 queue drops/replaces, 0 sink backpressure, working set 120.7–127.7 MiB flat, 34,621 records | 1 m 03 s |

Schema conformance of my 60 s artifacts (checked directly against
`docs/perf-counter-schema.md` and `crates/diagnostics`): record kinds
`frame_timing` / `queue_sample` / `resource_sample` / `link_sample`, snake_case
fields, `session_id: "local-loop"` on every record, queue names snake_case
(`capture_to_encode`), absent stages serialized as `null` (never 0), frame
queues sampled on every depth change (27,601 queue samples for 3,450 frames =
2.00 per frame per queue), summary written as `<stem>.summary.json`. One
expected artifact of a 60 s run: the 60 s warm-up exclusion leaves n=31 joined
frames — short passes are sanity-only, not distribution evidence (the report
uses them correctly).

## 2. Evidence verification (independent recompute from the committed JSONL)

Decompressed and re-parsed all three soak parts
(`m1-soak-30min.jsonl{,.1,.2}.gz`, 184,144,690 bytes raw) with an independent
Python implementation (nearest-rank percentiles, same warm-up rule).

**Record reconciliation — exact.** 447,393 + 447,393 + 135,207 = **1,029,993
records** = the report's counters line (claim: 1,029,993). Zero malformed
lines, single `session_id` `local-loop`, 821,163 queue samples + 205,254 frame
timings + 1,799 resource samples + 1,777 link samples. First→last record span
1799.99 s (claim: 30 min 0.7 s run). 205,254 frame timings = 2 × 102,627
exactly.

**Headline percentiles — reproduce to rounding** (n = 99,217 post-warm-up
joined frames, exactly as claimed; warm-up excluded by `send_ns`):

| stage | report p50/p95/p99/max (ms) | recompute p50/p95/p99/max (ms) |
|---|---|---|
| capture→encode submit | 0.02 / 3.41 / 4.47 / 10.04 | 0.015 / 3.409 / 4.475 / 10.036 |
| encode submit→done | 3.62 / 13.00 / 14.45 / 21.43 | 3.620 / 12.999 / 14.456 / 21.428 |
| encode done→send | 0.02 / 0.03 / 0.07 / 0.16 | 0.017 / 0.030 / 0.073 / 0.235 |
| recv→decode | 0.20 / 0.45 / 3.23 / 7.65 | 0.200 / 0.449 / 3.230 / 7.646 |
| decode→present | 0.07 / 0.10 / 0.15 / 3.39 | 0.070 / 0.103 / 0.153 / 3.393 |
| host half | 3.99 / 13.10 / 14.51 / 21.46 | 3.989 / 13.098 / 14.513 / 21.459 |
| controller half | 0.27 / 0.55 / 3.33 / 7.74 | 0.267 / 0.552 / 3.333 / 7.739 |
| **capture→present (same clock)** | **4.25 / 13.54 / 14.95 / 22.11** | **4.254 / 13.543 / 14.958 / 22.112** |

**Frame/drop accounting — exact and internally consistent.** Host frame ids
1..102,773 with 102,627 records; the 146 missing ids are exactly the 146
`capture_to_encode` `replaced` events (newest-wins doing its job); 102,774
captured = 102,627 encoded + 146 replaced + 1 in flight at shutdown; **0 host
frames lack a controller record** (100.0% presented, as claimed). Keyframes 856
≈ 102,627/120 (GOP 120 encoder-driven). Wire 1,651,042,836 B = 1574.57 MiB
(claim 1574.56), average link bitrate 7,430 kbps (claim ≈7.3 Mbps). CPU
0.00–35.94 % of one core (claim 0.0–35.9).

**Queue sampling — F5 cadence met.** Every frame queue shows 2.00 samples per
frame (push + pop per frame): 205,254–205,401 samples per queue over 102,627
frames. High-water 1/1, 1/1, 1/2, 1/1 with dropped=0 everywhere, replaced=146
on `capture_to_encode` only. The schema's per-change sampling rule is
implemented (`FrameQueue::sample` on push/replace/pop/reject) and the data
proves it ran.

**Memory — does NOT hold over the full 30 minutes (see F13).** Recomputed
working-set range over all 1,799 samples: **120.3 .. 232.0 MiB**, strictly
monotonic ~3.4–4.5 MiB per minute, no plateau: 5-min bucket averages
136.1 → 154.0 → 171.3 → 188.6 → 206.0 → 223.3 MiB. The report's "120.3 ..
173.0 MiB across 30 minutes (plateau, no monotonic growth)" line is the
**part-1-only** range (F13/F14). The 5-minute sanity summary is complete and
consistent on its own (57.3 fps, c2p p50 4.215 / p99 14.973, ws 120.3–145.6).

## 3. Findings (F13 onward)

Severity labels: **blocking-for-M2** (must land before/with M2 integration),
**should-fix** (milestone indicated), **note**.

### F13 — 30-minute "bounded memory" gate claim is not supported by the committed evidence; report memory line contradicts the raw data — blocking-for-M2

`docs/reports/m1-local-loop.md` ("Memory: working set 120.3 .. 173.0 MiB across
30 minutes … plateau, no monotonic growth") vs the committed JSONL (above:
120.3→232.0 MiB, monotonic, +112 MiB over the run). The 173.0 figure is the
maximum of part 1 only (782 s) — the same truncation as F14. The report's
post-soak note is honest about the cause (second leak: one video-processor
input view per presented frame in the renderer, fixed after the soak by
per-slot view caching) but the headline line remains wrong as stated, and the
fix's only evidence is a **90-second** run whose artifacts are **not committed**
(only `m1-sanity-5min.*` and `m1-soak-30min.*` exist in
`docs/reports/data/`). My own 60 s pass of the final binary (120.7–127.7 MiB
flat) corroborates the fix at 60 s scale — it does not substitute for 30-minute
evidence: leak classes found in this project surfaced at 3,600 frames (decoder
ring) and ~30 min (renderer views); a per-frame leak at 57 fps needs ≥
tens of minutes to be distinguishable from allocator noise, and the M6 gate is
60 minutes.
Required: (1) correct the memory line in `m1-local-loop.md` to the full-run
numbers with the leak explicitly called out; (2) run and commit a fresh ≥30 min
soak of the final binary (post-leak-fix) whose `ResourceSample` range is flat —
this can be folded into the M2 integration soak, but until it exists the M1
memory budget is "fixed but unverified at gate duration".
Reproduction:

```bash
python - <<'EOF'
import gzip, json, statistics
ws=[]
for p in ["m1-soak-30min.jsonl.gz","m1-soak-30min.jsonl.1.gz","m1-soak-30min.jsonl.2.gz"]:
    with gzip.open(r"docs/reports/data"+"\\"+p,"rt") as f:
        for line in f:
            if '"resource_sample"' in line:
                r=json.loads(line)
                if r["memory_working_set_bytes"] is not None: ws.append((r["at_ns"],r["memory_working_set_bytes"]))
ws.sort(); B=300_000_000_000
for i in range(0,int(ws[-1][0])+1,B):
    b=[v for t,v in ws if i<=t<i+B]
    if b: print(f"{i/60e9:5.1f}-{(i+B)/60e9:5.1f} min: avg {statistics.mean(b)/2**20:6.1f} max {max(b)/2**20:6.1f} MiB")
EOF
```

### F14 — Committed machine-readable summary covers only rotation part 1 — should-fix (regenerate now; blocking-for-M2 when combined with F13)

`docs/reports/data/m1-soak-30min.summary.json` contains `frames.host: 44577`,
`run_secs: 782`, `replaced: 64`, `ws max 173.0 MiB`, 13 unstable windows —
i.e. it summarizes `m1-soak-30min.jsonl` only, not `.1`/`.2`. The md report
says this ("the in-run summary printed before the multi-part reader fix
landed") and quotes recomputed numbers, but the tree's only machine-readable
gate artifact disagrees with the report's headline table — anyone consuming
`summary.json` (M4 overlay, M6 tooling) gets a 13-minute, part-1 view. The
fixed multi-part reader is already in `loop_common::summarize`; nobody reran
it. Regenerate the summary from the committed parts (one short offline run of
`summarize` against `m1-soak-30min.jsonl`) or replace it during the F13 re-soak.

### F15 — Summarizer unstable-window deltas miscount at window boundaries; "sustained at capacity" is ill-defined for cap-1 queues — should-fix (land with M2; hard requirement before the M6 release gate)

`crates/capture-windows/examples/loop_common/mod.rs` (`summarize`, win_stats
logic): each 60 s window starts `last_dropped = 0`, so the **first sample of
every window re-counts the full cumulative `dropped`** as an in-window delta
(false-positive "dropped/replaced N in window"); `replaced` has the inverse
baseline-carry branch that **swallows a replacement that is the window's first
sample** (false negative at boundaries). Neither fired wrongly in this soak
(`dropped` stayed 0 everywhere; the 146 replacements were sporadic), so M1's
`unstable_windows` list is credible — but M6's release blocker consumes exactly
this logic. Fix: carry the previous window's last cumulative counters into the
next window's baseline. Related definitional gap: the schema's
"`depth == capacity` sustained … is a release blocker" cannot be applied to
cap-1 queues as written — in this healthy soak `capture_to_encode` (cap 1) sat
at depth==capacity for **50.03%** of its samples (102,774/205,401), which is
simply "a frame is waiting" at 60 fps. The real signal for cap-1 queues is
push-time replacement while at capacity. Refine the definition in
`docs/perf-counter-schema.md` before M6.

### F16 — CPU-copy counters exist but are never surfaced or asserted; "0 CPU copies" is an inspection claim, not a measurement — should-fix (M2)

`frame_surface::READBACK_COUNT` / `UPLOAD_COUNT` are incremented on every
readback/upload (the mechanism is real and does distinguish hardware from
software paths: only `readback`/`upload*` bump them, and only the software
encoder/decoder call those), but **no binary, test, or summary reads them**
(`grep` shows zero consumers of `readback_count()`/`upload_count()`). The
report's parenthetical "(READBACK_COUNT/UPLOAD_COUNT deltas are zero apart from
diagnostics)" cannot have been observed in any committed artifact. Wire the
two counters into the loop's counters line + summary JSON, and assert
`readback_count() > 0` in `software_encoder_decoder_round_trip` and
`== expected` (0) in a hardware-path test so the claim becomes regression-
protected.

### F17 — `capture_ns` is stamped after `ReleaseFrame`, not when `AcquireNextFrame` returned — should-fix (align with schema; M2)

The schema pins `capture_ns` = "DXGI AcquireNextFrame returned". In
`local_loop.rs` the stamp is taken in the capture thread after
`DxgiCapture::next_frame` returns — i.e. after the pool `CopyResource`
submission, `GetFrameMoveRects`/`GetFrameDirtyRects`, cursor shape fetch, and
`ReleaseFrame`. The DDA acquire+metadata+copy work (~0.3–1 ms) is therefore
outside every measured stage: capture→encode p50 0.015 ms measures only queue
wait, and the same-clock capture→present total excludes the front of the
pipeline. Same-clock totals are still internally valid (single `SessionClock`),
so the headline numbers are not wrong — but the schema's measurement point and
the implementation disagree, and M5's input-to-visible formula starts at
`capture_ns`. Stamp inside `dupl.rs` right after `AcquireNextFrame` succeeds
(and pass it out on `CapturedFrame`), or amend the schema text explicitly.
Related nit: cursor-only updates return the *previous* frame's surface with
`frame_id = next_frame_id - 1` (`dupl.rs` `next_frame`); the M1 loop discards
them, but any consumer that forwarded them would emit duplicate frame ids into
the diagnostics join — worth a doc line on `CapturedFrame`.

### F18 — Renderer resize path is dead code and the Annex-B doc promises IDR gating that does not exist — should-fix (before the M2 rig wires real windows)

`render-windows/src/window.rs`: `PresenterWindow.resized` is documented as "Set
by WM_SIZE; consumed by the renderer to resize its swapchain", but `wnd_proc`
never handles `WM_SIZE` and nothing calls `D3D11Renderer::resize`; after a user
resize the swapchain is stale (`DXGI_ERROR_INVALID_CALL` or wrong-size present;
`pump()` also ignores `WM_SIZE`, silently changing client size). The soak never
resized the window, so this is latent. `codec-windows/src/annexb.rs` documents
keyframe detection as serving "the renderer's 'wait for IDR after reset'
logic" — no such logic exists in `render-windows` or the loop. Over M2's lossy
transport, decode-after-loss without IDR gating produces visual corruption;
plan the IDR gate (drop non-IDR frames after `VideoDecoder::reset` until the
next IDR) as an explicit M2 work item, and either wire or delete the resize
path.

### F19 — `plane_layout` NV12 UV offset is wrong for tight buffers — note

`frame-surface/src/lib.rs`: `plane_layout(Nv12, w)` returns UV offset
`y_stride * 2` (comment: "UV plane starts after 2 rows of Y"), but in a tight
NV12 `CpuSurface` the UV plane starts at `width * height` — `readback`,
`upload_nv12_into`, and `upload_nv12` all correctly use `rows_y * y_stride` and
only consume the stride component, so the bug is confined to the public
`CpuSurface::plane_span(1)`, which returns bytes from the middle of the Y plane
(64x32 test: bytes [128..1152) instead of [2048..3072)). No production caller
today — a trap for the M2+ cursor/software paths. Fix the offset (and the test
that currently pins the wrong value) or make the function take height.

### F20 — "1080p60" achieved as a stable 57.0 fps (95% of cap); cause is pacing overhead — note (M2 pacing work item)

The gate language is "stable 1080p60"; measured is 57.0 fps sustained (my 60 s
run: 57.5). The 5% shortfall is deterministic, not load: the capture thread
paces by sleeping until `1/fps_cap` after the *start* of the previous
iteration, then pays `next_frame` (metadata + copy submit) plus sleep
granularity, so the loop period is 16.7 ms + ~0.8 ms. The evidence for
"explained by pacing, not saturation": capture→encode p50 0.015 ms and queue
high-water 1 — nothing downstream is back-pressured. M2's transport pacing
(uncapped-collapse risk item) should fix the pacing loop (wake-before-deadline
with drift correction) rather than inherit it. Not a stability failure; the
report's numbers are honest but should state 57.0-vs-60 explicitly against the
budget line.

### F21 — Async encoder attributes output to the current input's frame_id with no in-flight tracking — note (harden in M2)

`codec-windows/src/encoder.rs` `Backend::Async`: `encode()` submits input N and
returns whichever output arrives first, stamped `frame_id = input.frame_id`.
The sync backend carefully tracks an `in_flight` deque for its depth-1
pipeline; the async backend assumes strict 1-in-1-out. Evidence this holds
today on NVENC: keyframe cadence exactly GOP 120, 0 unjoined frames, queue
watermarks 1. If the async MFT ever buffers (rate-control hiccup, stream
change), every subsequent packet is attributed to the wrong frame id and the
latency join smears by one frame. Add an async in-flight deque (or map MFT
sample time → frame id) when M2 wires real transport.

### F22 — JSONL rotation size is estimated (300 B/record), not measured — note

`loop_common/mod.rs` writer: `written += 300` per record. Actual mean record is
~179 B, so parts rotate at ~76–80 MiB, not the 128 MiB the schema's F6 rule
states (all parts retained, so no evidence loss). Use the serialized length if
the 128 MiB figure is meant to be exact; otherwise document the estimate.

### F23 — `summarize` materializes every line in memory — note

`loop_common::summarize` collects `BufReader::lines().collect::<Vec<_>>()` per
part plus two `HashMap<u64, FrameTiming>` — roughly 1 GiB peak for this 30-min
soak, ~2 GiB for M6's 60-min gate. Offline tool, not hot path; stream the
second pass or read twice if M6's runs get bigger.

### F24 — `m1-local-loop` gate tag absent — note (process, required by PLAN §7)

Only `m0-contract` exists. Tag the M1 gate (on `4aa330b` or `dc50c70`) only
after the F13 re-soak lands, per "a milestone is done only when its gate is
demonstrably met and rd-performance-qa has reviewed it".

### F25 — Doc drift: `MF_LOW_LATENCY` attribute not set; spike report's `frame_id` note — note

`codec-windows/src/lib.rs` claims "`CODECAPI_AVLowLatencyMode` +
`MF_LOW_LATENCY`" but only the codec-API property is set (never the
`MF_LOW_LATENCY` attribute on the media type); either set it on the input type
or fix the doc. `m2-transport-spike.md` says `EncodedPacket` should "add
`frame_id` from the capture stage" — `EncodedPacket` already carries
`frame_id`; the spike's mirror type lacks it, not M1's. Also for M5 planning:
`present_ns` measures `Present` submission (no vsync wait, delta D4), so
input-to-visible budgets must add the display-refresh interval or read frame
timing — noted here so it is not rediscovered.

## 4. Invariant audit (focus)

| Invariant | M1 encoding | Assessment |
|---|---|---|
| 3 — bounded queues, drop-obsolete | `FrameQueue` (caps 1/1/2/1, newest-wins or reject-with-counter) in the loop; encoder worker `sync_channel(2)` in / `sync_channel(4)` out with try_send + `dropped_outputs` counter; sink channel 65,536 with try_send + backpressure counter; capture pool 4; NV12 ring 4; decoder owned ring 4; sync `in_flight` ≤ 2; converter/renderer view caches capped at 16 with clear; `BoundedMemorySink` bounded | **Holds.** Every queue found is bounded with an explicit, counted drop policy. The only unbounded structures are in offline `summarize` (F23). Measured: high-water ≤ 1 everywhere, 0 dropped, 146 replaced on the intended queue |
| 1 — counters never carry pixels | `FrameTiming`/`QueueSample`/`ResourceSample`/`LinkSample` carry ids/timestamps/gauges only; JSONL verified field-by-field; `EncodedPacket.bytes` exists only inside codec/transport handoffs; cursor pixels travel only in `CursorMessage` (the documented bounded exception) | **Holds** |
| unsafe confined to `*-windows`/`frame-surface` with failure handling | `grep -rln unsafe`: only `frame-surface`, `capture-windows`, `codec-windows`, `render-windows` (+ their examples); zero in `protocol`, `session`, `diagnostics`, `transport-webrtc`, `apps`, `services` | **Holds.** Failure handling is typed on every path reviewed (`CaptureError::{AccessLost,DeviceLost,AccessDenied,DisplayChanged,Exhausted}`, `CodecError::DeviceLost`, `RenderError::DeviceLost`); the local loop maps DeviceLost to a clean stop (full in-process recovery is declared M2 work — risks §6) |
| CPU copies counted | `READBACK_COUNT`/`UPLOAD_COUNT` incremented at exactly the two sanctioned readback sites and both upload sites | Mechanism correct and hw/sw-distinguishing, but **unwired** (F16) |

## 5. Budget check (PLAN/AGENTS vs measured)

| Budget | Measured | Verdict |
|---|---|---|
| Stable 1080p60 loopback, 30 min, one process | 30 min 0.7 s single process, exit 0, 57.0 fps sustained, 100% of encoded frames presented, no stage failure | **Met as stability**; 57.0-vs-60 shortfall explained by pacing (F20), M2 work item |
| Capture-to-encode queue ≤ 1 steady state | high-water 1 (cap 1); recv→decode ≤ 1 of 2; 0 dropped; 146 sporadic replacements ≈ 5/min, each a single obsolete frame | **Met** |
| Bounded memory | Soak binary: 120.3→232.0 MiB monotonic (renderer view leak); final binary flat 120.7–127.7 MiB over my 60 s + their 90 s | **Not demonstrated at gate duration** — F13; the 90 s re-verify is insufficient evidence for a 30-min claim (and is uncommitted) |
| Local-loop latency sanity (no M1 budget, context for M2) | c2p p50 4.25 / p99 14.95 / max 22.11 ms same-clock; encode dominates (p95 13.0 ms) | Well inside one 16.6 ms frame; encode p95 consumes ~78% of a frame interval — M2's RTP send must not serialize with the encode wait |

## 6. Test quality (what M2 inherits)

Well-pinned: Annex-B parsing (SPS/PPS/IDR, non-IDR, garbage/no-panic),
monochrome pitch word-alignment (5 widths, 2-plane size), cursor shape
conversion (color/mono/masked/truncated/unknown/hotspot clamp) and 0–65535
position normalization (incl. negative-origin monitor and clamping), fit/1:1
letterbox math, encoder fallback selection (software round trip 31/31 with
first-frame IDR, hardware candidate enumeration, adapter-LUID skip implicitly
exercised on this hybrid machine), converter scaling with a p50 budget
assertion, error-taxonomy unit tests, diagnostics JSON-name pins.

Under-pinned / untested that M2 inherits:

1. **Pixel fidelity**: no test anywhere compares decoded pixels to input (the
   round trip feeds one blank surface 31 times; `make_nv12_test_input` is
   dead code). Nothing validates the BT.709 conversion, the decoder CPU-path
   tight-pitch assumption (`decoder.rs` copies assuming stride == width), or
   end-to-end visual correctness. A luma/PSNR check on a synthetic gradient is
   cheap and load-bearing for a remote desktop.
2. **Keyframe forcing**: `force_keyframe=true` is passed in
   `hardware_encoder_accepts_gpu_input` (i==0) but never asserted; no mid-run
   forced-IDR test. M2's PLI/FIR path depends on it.
3. **Decoder `reset()`** (flush) has no test; IDR-gating after reset does not
   exist (F18).
4. **Mid-stream resolution change**: converter rebind and decode
   stream-change renegotiation are exercised only at first frame; no test
   changes geometry mid-stream (matches the report's risk #3).
5. **Cursor path end-to-end**: shape → `CursorMessage` conversion is unit-
   tested, but nothing carries it through a queue or renders it (renderer
   stores `CursorOverlay`, never draws — declared M2/M4).
6. Live `set_bitrate` (sync path untested; async path unsupported — M5 item).

## 7. M1 → M2 risks register (which must become M2 work items)

| Risk (from M1 report) | Assessment | Disposition |
|---|---|---|
| MF quirks encapsulation | Verified: activation-object attributes, `GetAttributes` unlock, adapter-LUID matching, caller-allocated output samples, CBR buffer size, sync depth-1 pipeline are all inside `codec-windows`; `EncodedPacket` is clean Annex-B + frame_id. One gap: `set_bitrate` on the async (hardware) MFT returns an error in M1 — M5 congestion adaptation needs it wired through the worker | Accepted-note + one M2/M5 work item (async `set_bitrate`) |
| Uncapped >60 Hz capture collapse | Measured and reproducible (encode ~8 fps while capture runs 74 fps); default `--fps-cap 60` models the session rate. Pacing/adaptation is transport-shaped work | **Must be an M2 work item** (fix the pacing loop, not just the default — F20) |
| Resolution-change path untested on real panel | `AccessLost` reinit, converter rebind, decode stream-change exist; zero automated display-change coverage | **Must be an M2 work item** (scripted mode-change test on the physical panel) |
| GPU device suspension with two pipelines | Elevated by M2's own plan: the D2 rig (delta D2) is two processes × full pipeline (DDA+NVENC+DXVA+swapchain) on one GPU — exactly the configuration that suspended once. `local_loop` treats `DeviceLost` as fatal; the M2 node runtime needs typed recovery (recreate device + stages + forced IDR) and the rig needs a reproduction/soak with both processes live | **Must be an M2 work item** (highest-signal of the four) |
| Keyframe latency over loss | API exists (`encode(force_keyframe)`, NVENC supports it — reported `true` in both runs); unasserted (§6.2). M2 must force IDR immediately on PLI/FIR | M2 work item (already planned) |

## 8. M2 transport spike — contradiction scan (light, per brief)

`git diff 4aa330b b594f35` shows zero changes to M1 crates; the spike mirrors
codec trait shapes in `examples/spike_rig.rs` without importing platform
crates (ADR-001 rule 3 holds). No unsafe in `transport-webrtc`. Nothing
contradicts M1's contracts; two doc-level notes only (F25: "add frame_id" is
stale; the spike's one-pass recv/decode/present stamping is self-flagged as an
M2-integration item and matches F17's concern). Full audit belongs to M2.

## 9. Recommendation

**PASS-WITH-FINDINGS.** The gate is reproducible (fmt/clippy/test green,
92+6 tests, my own 60 s pass schema-exact), and the load-bearing evidence —
per-stage latency distributions, frame/drop accounting, queue cadence and
watermarks — verifies *exactly* against the committed JSONL, which is
unusually clean for a first pipeline milestone. The one substantive hole is
memory-boundedness: the 30-min soak demonstrably leaked (the renderer-view
leak), the committed summary and the report's memory line misdescribe the run
(F13/F14), and the fix's evidence is 90 s. Accept M1 as functionally complete
conditional on: F13 re-soak (≥30 min, committed artifacts) and F14 summary
regeneration landing before or with the M2 integration; F16/F17/F18 as normal
M2-adjacent fixes; F15 hardened before M6; F19–F25 as tracked notes. Tag
`m1-local-loop` only after the F13 re-soak (F24).

## 10. Reproduction

```bash
# Gates (timings in §1)
cargo fmt --all -- --check
scripts/check.sh
scripts/test.sh
cargo test --workspace -- --ignored          # needs the real display/GPU

# Short loop sanity (artifacts: docs/reports/data/m1-qa-audit-60s.*)
cargo run --release -p capture-windows --example local_loop -- \
    --duration-secs 60 --report-stem m1-qa-audit-60s

# Full evidence recompute (§2) — the Python in F13 plus a percentile pass
# over all three gz parts with warm-up = 60e9 ns excluded by send_ns;
# auditor scratch script mirrored at the F13 snippet

# F14 evidence: compare summary.json frames.host (44577) vs report (102627)
jq '.frames, .run_secs, .queues.CaptureToEncode.replaced' \
   docs/reports/data/m1-soak-30min.summary.json
```
