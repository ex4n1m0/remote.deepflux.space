# ADR-001: System architecture and module boundaries

- Status: Accepted (M0, 2026-09-24)
- Deciders: rd-architecture-owner (M0 work package RD-001/RD-002/RD-003)
- Sources: `PLAN.md`, `P2P Remote Desktop Development Plan.md` (source plan §System architecture, §Repository layout)

## Context

One Windows 10/11 application with two runtime roles (Host / Controller) in a
single executable: a Tauri 2 + React/TypeScript shell around a Rust native
engine. Vercel is the signaling/control plane only. Direct sessions use
WebRTC (STUN, no TURN) with an H.264 GPU pipeline and `SendInput` injection.
The project's hard constraints (AGENTS.md invariants) are architectural, not
procedural: no frame bytes through Tauri IPC/JSON/canvas, control plane
carries only envelopes, every queue bounded, narrow traits at every platform
boundary.

The source plan fixes the repository layout; this ADR fixes the *dependency
rules* and the homes of the boundary traits, which the layout alone does not
pin down.

## Decision

### Module map and dependency rules

```text
apps/desktop (M4)         Tauri + React shell; typed commands only, never frames
services/signaling (M3)   Vercel control plane; consumes protocol's JSON schema (D7)

crates/protocol           wire vocabulary: signaling JSON envelopes, binary
                          data-channel messages, capability negotiation.
                          Depends on: serde/bincode only. NOTHING internal.
crates/session            host + controller state machines. Depends on: protocol.
                          No platform crates, no async runtime, no clock, no I/O.
crates/diagnostics        perf-counter schema + sinks. Depends on: serde only.
crates/frame-surface      M1 leaf: shared GPU frame handoff (see the M1
                          amendment below).
crates/capture-windows    CaptureSource trait + M1 DXGI implementation.
crates/codec-windows      VideoEncoder/VideoDecoder traits + M1 MF implementation.
crates/transport-webrtc   Transport trait + M2 webrtc-rs implementation (ADR-002).
crates/input-windows      InputSink trait + M2 SendInput implementation.
crates/render-windows     FrameRenderer trait + M1/M2 D3D11 presentation (D4).
```

Rules:

1. **`protocol` and `diagnostics` are leaves.** No crate dependency beyond
   serde/bincode. If a platform crate needs either, it depends on them; never
   the reverse.
2. **`session` stays pure.** It consumes injected events and a logical
   `now_ms`, returns `Action`s. The state machines must never hold a socket,
   a timer handle, or a platform trait object. This is what makes the M0 gate
   ("two simulated peers complete a session deterministically") possible and
   keeps M2's runtime replaceable.
3. **Platform crates never depend on each other.** Cross-boundary handoffs
   (capture frame → encoder, decoder frame → renderer) are composed by the
   *node runtime* — in M1 the diagnostic binaries, from M4 the app — not by
   platform crates importing each other. Exception: platform crates may
   depend on `protocol` (shared vocabulary, e.g. `InputSink` consumes
   `InputEvent`) and `diagnostics` (counter emission).
4. **`apps/desktop` composes everything but owns no pipeline logic.** UI state
   is derived from `session` states via typed Tauri commands; the native
   viewer window owns the frame path (invariant 1).

### Where the boundary traits live

Each of the six named traits (`CaptureSource`, `VideoEncoder`, `VideoDecoder`,
`Transport`, `InputSink`, `FrameRenderer`) is defined in the crate that owns
that boundary, next to its reference implementation. This matches the source
plan's crate list verbatim and keeps M0 free of an extra "traits" crate.

Consequence: a future macOS/Linux port replaces the `*-windows` crates
one-for-one without touching `session` or `protocol` — but only code that
already restricts itself to the traits (runtime binaries, tests with mocks)
is portable for free. The one deliberate asymmetry is `Transport`, whose
fallback seam is a full-crate swap; see ADR-002 for those mechanics.

### Data paths (the two invariants that shape everything)

```text
Host:     DXGI capture → [GPU] color convert → MF H.264 encode → RTP → peer
Controller: peer → jitter → MF/DXVA decode → [GPU] texture → D3D11 present
Control:  Tauri command → session machine → Action → transport/signal
```

Frame bytes exist only inside `capture-windows` / `codec-windows` /
`render-windows` / `transport-webrtc` and the GPU. They never appear in:
Tauri IPC, React state, JSON, canvas, the signaling service, logs, or
`protocol` messages (cursor *shape* pixels are the one bitmap exception and
travel on the direct `cursor` data channel as bounded binary, never via
signaling).

### Determinism strategy for control logic

Both state machines are pure functions `(state, event, now) -> (state',
actions)`. All nondeterminism (clocks, network, transport) is injected by the
caller. The M2 node runtime is the only place that bridges to the real world,
and `crates/session/tests/two_peers.rs` is its executable reference model.

## Consequences

- Positive: M1 (capture/codec) and M2 (transport spike) can proceed in
  parallel behind traits without cross-review conflicts; the deterministic
  harness catches protocol races (it already caught a cancel/timeout race in
  M0 development) before any network exists.
- Positive: the libwebrtc fallback (source plan frozen decision) and future
  platforms are crate-scoped changes.
- Negative: the frame handoff *type* between capture → codec → render is not
  yet fixed (GPU texture handles are M1 territory); M0 uses placeholder types
  inside each crate. **Open question for M1:** pick the shared GPU handle
  representation (likely in a small shared crate or re-exported from
  `codec-windows`) — must be settled in the M1 integration patch, not
  silently.
- Negative: `session`'s `Action` enum is a widening contract surface; every
  new runtime capability touches it. Acceptable — it is exactly the seam the
  integrator owns.
- Open: bincode 1.x is in maintenance mode. The codec is confined to
  `protocol::wire::{encode, decode}`; a bincode 2/3 migration is a one-file
  change plus a `WIRE_VERSION` bump. No action before a demonstrated need.
- Open: `Transport` is poll-based in M0 (`fn poll(&mut self) ->
  Option<TransportEvent>`). M2 may add async plumbing *inside*
  `transport-webrtc` but must keep the public surface runtime-agnostic so the
  deterministic mock harness keeps working.

## M1 amendment: the GPU frame-handoff contract (settlement of open question #1)

- Status: Accepted (M1, 2026-09-24)
- Deciders: rd-capture-codec-engineer (M1 work package RD-004/RD-005)

### Decision

**`crates/frame-surface` is the shared handoff crate** (pre-authorized in
the M1 work package; a leaf like `diagnostics`, depending on nothing but
the `windows`/D3D bindings):

* `FrameSurface` — a `Clone`-cheap (COM refcount) wrapper over one
  `ID3D11Texture2D` plus width/height/format and the host-assigned
  `frame_id` (the perf-counter join key). It is the *only* type platform
  crates share.
* `GpuDevice` — one D3D11 device + immediate context per process
  (`D3D11_CREATE_DEVICE_BGRA_SUPPORT`, `SetMultithreadProtected(TRUE)` so
  the capture/codec/render threads can all submit). `Clone` shares the
  device.
* Cross-device/cross-process sharing is provided but not used by the M1
  loop: `share_handle()` mints an NT DXGI shared handle, `open_shared()`
  opens one on another device. The M2 runtime (or a future multi-device
  M1 configuration) can split stages onto separate devices without a
  contract change.
* CPU readback/upload helpers exist for exactly two sanctioned uses:
  the Media Foundation **software encoder fallback** (delta D3; the
  software MFT only accepts CPU NV12) and diagnostics. Both are counted
  (`READBACK_COUNT` / `UPLOAD_COUNT`) and reported.

### Reasoning

* The MF async hardware MFTs (NVENC-class) require an
  `IMFDXGIDeviceManager` over a D3D11 device; same-device input via
  `MFCreateDXGISurfaceBuffer` is the only zero-CPU-copy path into the
  encoder. One shared device makes capture → convert → encode a chain of
  GPU texture references with no CPU pixel traffic.
* The one-device choice was *measured*, not assumed: the pipeline
  sustains 57.7 presented fps (866 captured / 864 encoded / 864 decoded /
  864 presented in 15 s) at 3840x2160 capture → 1920x1080 encode with
  convert p50 ≈ 2–6 µs and encode wait ≈ 2–4 ms. (Two M1 bugs found by
  these measurements are recorded below.)
* The copies that remain, and where they are measured:
  1. capture: duplication surface → pool texture (`CopyResource`) — forced
     by the DDA ownership model (ReleaseFrame before next acquire);
  2. decode: DXVA output → owned texture (`CopyResource`) — the MFT
     recycles its pool on the next input;
  3. software-codec fallback only: NV12 GPU→CPU readback + CPU→MF-buffer
     copy (encode side) and CPU→GPU upload (decode side) — counted by
     frame-surface's atomic counters and printed in the run summary.
* Color conversion (BGRA→NV12, with 4K→1080p scaling) is a GPU
  `ID3D11VideoProcessor` pass inside `codec-windows`
  (`Nv12Converter`); the reverse (NV12→backbuffer) is the same mechanism
  inside `render-windows`. No CPU pixels anywhere on the hot path.

### M1 measurement notes (for the record)

* `VideoProcessor*View` creation costs tens of milliseconds of driver
  sync; the converter and renderer cache views per pool texture. Before
  caching, encode ran at ~7 fps; after, convert p50 returned to
  single-digit microseconds.
* A `VideoProcessorSetStreamDestRect` given the *source* rect fails Blt
  with `E_INVALIDARG` only when input ≠ output size — caught by a
  dedicated scaling test (`converter_scales_directly`), which is why the
  1:1-only smoke test passed while the real loop failed.
* Capture must attach its thread to the input desktop
  (`frame_surface::attach_thread_to_input_desktop`) or Desktop
  Duplication returns `E_ACCESSDENIED` even in an interactive session
  (processes spawned from services/agents start on a private desktop).

### Consequences

- Positive: platform crates still never import each other; the node
  runtime (M1 diagnostic binaries, M4 app) composes them through
  `frame-surface` types only.
- Positive: the M2 transport receives `EncodedPacket` bytes (Annex-B)
  produced at the encode stage boundary — no GPU type crosses the wire
  seam, matching ADR-002's RTP framing plans.
- Negative: one shared device means MF's device-manager serialization and
  the app's direct immediate-context use contend; at capture rates above
  the sustainable composition rate this was observed to back-pressure
  `Present` until the encode stage starves (uncapped ~74 Hz desktop).
  The M1 loop therefore caps capture at the session target (60 fps);
  pacing under real network conditions is M2 transport work. A
  multi-device split (already supported by the shared-handle API) is the
  documented escalation if profiling demands it.
