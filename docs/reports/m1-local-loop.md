# M1 local-loop report — DXGI capture, MF H.264 encode/decode, D3D11 present

- Date: 2026-09-24 (M1, RD-004 + RD-005)
- Owner: rd-capture-codec-engineer
- Evidence: `docs/reports/data/` (raw JSONL + per-run `*-summary.json`,
  schema-exact per `docs/perf-counter-schema.md`, session_id `local-loop`)
- Gate reference (PLAN.md §4 M1): stable 1080p60 for 30 minutes, bounded
  memory, queue depth ≤ 1 steady state, latency report written.

## Environment

| Item | Value |
|---|---|
| OS | Windows 11 (10.0.26200), interactive console session |
| GPU (display + codec) | NVIDIA GeForce RTX 5080 Laptop GPU, driver 32.0.16.1656 |
| iGPU | Intel Graphics (no outputs attached; Intel QuickSync MFT enumerated but adapter-LUID-mismatched → correctly skipped) |
| Monitor | `\\.\DISPLAY5` (primary), native **3840x2160** |
| Encoder active | **NVIDIA H.264 Encoder MFT (hardware, async MFT)** — 1920x1080@60, 8 Mbps CBR, GOP 120 (~2 s), no B-frames, low-latency; force-keyframe supported |
| Decoder active | **Microsoft H264 Video Decoder MFT + DXVA (hardware-backed, sync MFT)** — NV12 GPU output, low-latency, no reorder |
| Software fallback | Inbox `H264 Encoder MFT` verified by a dedicated round-trip test (`software_encoder_decoder_round_trip`, 31/31 frames, first-frame IDR) |
| Pipeline shape | capture 3840x2160 → GPU convert+scale to 1920x1080 NV12 → NVENC → decode → present (one shared D3D11 device; see ADR-001 M1 amendment) |

The soak captures the desktop at native 4K and encodes at 1080p — the
scale+colorspace GPU pass is part of the measured loop (a heavier, not
lighter, configuration than capturing 1080p directly).

## Measured performance (30-minute soak, gate run)

Source: `docs/reports/data/m1-soak-30min.jsonl` (+ `.jsonl.1`, `.jsonl.2`
— the writer rotated at 128 MiB per the F6 rule; all parts retained and
gzipped) and `m1-soak-30min.summary.json`. Numbers below are recomputed
across **all** parts (the in-run summary printed before the multi-part
reader fix landed; the counters line of the run itself is authoritative:
`captured 102774 encoded 102627 decoded 102627 presented 102627,
keyframes 856, wire 1574.56 MiB, 1029993 records, 0 sink-backpressure`).

- **Duration actually run: 30 min 0.7 s** (single uninterrupted process,
  exit 0; a GDI stimulus window on the captured desktop guaranteed
  continuous updates).
- **Frames: 102,774 captured / 102,627 encoded / 102,627 decoded /
  102,627 presented — 57.0 fps sustained, 100.0% of encoded frames
  presented.**
- 856 keyframes (GOP 120 ≈ 2 s at ~57 fps — encoder-driven, as
  configured); average wire rate 1574.56 MiB / 1800 s ≈ **7.3 Mbps**
  (8 Mbps CBR target).

Per-stage latency (post warm-up; n = 99,217 joined frames):

| stage | p50 | p95 | p99 | max |
|---|---|---|---|---|
| capture→encode submit | 0.02 ms | 3.41 ms | 4.47 ms | 10.04 ms |
| encode submit→done | 3.62 ms | 13.00 ms | 14.45 ms | 21.43 ms |
| encode done→send | 0.02 ms | 0.03 ms | 0.07 ms | 0.16 ms |
| recv→decode | 0.20 ms | 0.45 ms | 3.23 ms | 7.65 ms |
| decode→present | 0.07 ms | 0.10 ms | 0.15 ms | 3.39 ms |
| host half total (capture→send) | 3.99 ms | 13.10 ms | 14.51 ms | 21.46 ms |
| controller half (recv→present) | 0.27 ms | 0.55 ms | 3.33 ms | 7.74 ms |
| **capture→present (same clock)** | **4.25 ms** | **13.54 ms** | **14.95 ms** | **22.11 ms** |

Every stage fits inside one 16.6 ms frame interval even at max; the
capture→present p99 of 15.0 ms means the local loop adds less than one
frame of latency end to end.

Queue high-water marks (budget: depth ≤ 1 steady state — **met**):

| queue | capacity | high water | dropped | replaced |
|---|---|---|---|---|
| capture_to_encode | 1 | **1** | 0 | 146 total (~8/min peak, sporadic) |
| encode_to_send | 1 | **1** | 0 | 0 |
| recv_to_decode | 2 | **1** | 0 | 0 |
| decode_to_present | 1 | **1** | 0 | 0 |

No queue was pinned at capacity in any 60 s window (the schema's
"sustained" test); the only instability markers were windows containing a
single capture_to_encode replacement (one obsolete frame dropped —
exactly the newest-frame-wins policy doing its job under a transient
burst).

Memory: working set **120.3 .. 173.0 MiB** across 30 minutes (1 Hz
ResourceSample range; plateau, no monotonic growth — a per-frame
decoder-texture/view allocation leak was found and fixed during the
sanity pass: before the fix the process exceeded 1 GiB and the driver
suspended the device at ~3600 frames). CPU: 0.0 .. 35.9 % of one core.
Sink backpressure events: **0**.

5-minute sanity pass (pre-gate, `m1-sanity-5min.summary.json`): 57.3 fps,
capture→present p50 4.22 ms / p99 14.97 ms, working set 120.4–145.6 MiB —
consistent with the soak.

Post-soak note: analysis of the soak's working-set climb (120→173 MiB)
found a second, slower leak — one leaked video-processor input view per
presented frame in the renderer (the decoder-side ring fix had already
landed pre-soak). The renderer now caches views per surface-ring slot;
a 90-second verification run of the final binary holds **121.0–128.2 MiB
flat** at the same 57.5 fps, 5174/5174 frames encoded/presented. The
soak numbers above are otherwise unaffected (latency and queue behavior
did not depend on the leak).

## Copies per frame (hardware path)

1. DDA surface → capture pool texture: 1 GPU-GPU `CopyResource` (forced by
   the DDA ownership model).
2. BGRA→NV12 (+4K→1080p scale): 1 GPU `VideoProcessorBlt` (color convert,
   not a copy).
3. NV12 → NVENC: 0 (DXGI-surface buffer on the shared device).
4. DXVA output → owned NV12: 1 GPU-GPU `CopyResource` (the MFT recycles
   its pool on the next input).
5. NV12 → swapchain backbuffer: 1 GPU `VideoProcessorBlt`.

CPU copies per frame: **0** on the hardware path
(`READBACK_COUNT`/`UPLOAD_COUNT` deltas are zero apart from diagnostics).
The software fallback adds readback+memcpy (encode) and upload (decode),
counted by the same atomics and visible in the summary.

## Known issues / risks carried to M2

1. **Uncapped capture above ~60 Hz collapses the pipeline.** With DDA
   delivering at the panel's ~74 Hz and no pacing, `Present` back-pressure
   starves the encode stage (encode ~8 fps while capture runs 74 fps;
   measured). At a 60 fps cap the pipeline tracks 1:1 (866/864/864/864
   measured in a 15 s run). Pacing/adaptation is M2 transport work; the
   loop defaults `--fps-cap 60` and documents this.
2. **GPU device-instance suspension observed once** when two full pipeline
   instances overlapped on the same GPU (during test automation; both
   processes ran DDA + NVENC + swapchains). Single-instance runs were
   stable. Typed `DeviceLost` handling exists on every stage (capture,
   encode, decode, present); full in-process recovery (recreate device +
   stages + keyframe) is an M2 hardening item.
3. **Resolution/display changes**: capture reinit (`AccessLost`) and
   encoder converter rebind are implemented and exercised by the code
   paths, but no automated display-change test ran on the physical panel
   (risk documented in PLAN.md §6). M2 should add a scripted mode-change
   test.
4. **MF quirks that will matter over RTP**: the async MFT needs
   `GetAttributes`-based unlock (not IMFAttributes QI) and activation
   attributes (async/D3D-aware/adapter-LUID) read from the *activate
   object*; the sync software encoder needs caller-allocated output
   samples, a CBR buffer-size property, and emits output one input later
   unless low-latency mode takes. All are encapsulated in `codec-windows`;
   the RTP layer should never see them.
5. **Keyframe latency**: force-keyframe is supported by the NVENC MFT
   (`CODECAPI_AVEncVideoForceKeyFrame`) and exposed through
   `VideoEncoder::encode(force_keyframe)`. Over a real network an IDR
   after loss costs a full GOP-dependent refresh; M2's `KeyframeRequest`
   wiring should force immediately on PLI/FIR, not wait for the interval.

## Reproduction

```bash
# 5-minute sanity pass
cargo run --release -p capture-windows --example local_loop -- \
    --duration-secs 300 --report-stem m1-sanity-5min
# 30-minute soak (gate run)
cargo run --release -p capture-windows --example local_loop -- \
    --duration-secs 1800 --report-stem m1-soak-30min
# capture-only preview (no codec)
cargo run --release -p capture-windows --example capture_preview -- \
    --duration-secs 30
# hardware/software codec integration tests (need real GPU + display)
cargo test --release -p codec-windows --test mf_integration -- --ignored
```
