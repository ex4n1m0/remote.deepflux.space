# AGENTS.md — P2P Remote Desktop (Windows-first, one binary, two roles)

Standing contract for every agent (human or AI) working in this repository.
Read before proposing code. The operational plan is `PLAN.md`; the source
plan (requirements, backlog IDs `RD-0xx`, budgets) is
`C:\Users\igorc\Downloads\P2P Remote Desktop Development Plan.md`. Where they
disagree, `PLAN.md`'s deltas (D1–D7) win.

## Architecture summary

One Windows 10/11 application with two runtime roles (Host / Controller).
Tauri 2 + React/TypeScript shell (M4) around a Rust native engine. Vercel is
the signaling/control plane only; after SDP/ICE exchange everything flows
over a direct WebRTC peer connection (STUN, TURN disabled in MVP). H.264 GPU
pipeline, native rendering, `SendInput` injection. No accounts, no relay, one
controlled machine per session.

Module map (source-plan layout, verbatim):

| Path                     | Role                                        | Milestone |
|--------------------------|---------------------------------------------|-----------|
| `apps/desktop/`          | Tauri + React shell; typed commands only    | M4 (D1)   |
| `services/signaling/`    | Vercel control plane (JSON schema = `protocol`) | M3 (D5) |
| `crates/protocol/`       | Versioned wire messages + capability negotiation | M0 ✓  |
| `crates/session/`        | Host/controller state machines (pure, deterministic) | M0 ✓ |
| `crates/transport-webrtc/`| `Transport` trait + webrtc-rs implementation (ADR-002) | M2 |
| `crates/capture-windows/`| `CaptureSource` trait + DXGI duplication    | M1        |
| `crates/codec-windows/`  | `VideoEncoder`/`VideoDecoder` + Media Foundation | M1   |
| `crates/input-windows/`  | `InputSink` + `SendInput`, 0–65535 normalized coords | M2 |
| `crates/render-windows/` | `FrameRenderer` + D3D11 presentation (D4)   | M1/M2     |
| `crates/diagnostics/`    | Perf-counter schema + sinks (`docs/perf-counter-schema.md`) | M0 ✓ |
| `docs/adr/`, `docs/protocol/` | Decision records, state machines      | living    |

Dependency rules (ADR-001): `protocol` and `diagnostics` are leaves;
`session` depends only on `protocol` and stays pure (no clocks, no network,
no platform traits — events in, `Action`s out); platform crates never depend
on each other (the node runtime composes them); nothing depends on
`apps/desktop`. Specialists return small reviewable patches or evidence
reports; the main session integrates.

Key docs: `docs/adr/ADR-001-architecture.md`,
`docs/adr/ADR-002-webrtc-rs-behind-transport-trait.md`,
`docs/protocol/state-machines.md`, `docs/perf-counter-schema.md`.

## Non-negotiable invariants

1. No frame bytes through Tauri IPC, React state, JSON, or canvas — ever.
2. Vercel is control plane only: IDs, presence, SDP/ICE envelopes. Nothing else.
3. Every queue is bounded; under pressure drop obsolete frames, never queue latency.
4. TURN/relay forbidden in MVP.
5. No undocumented wire-format changes; `protocolVersion` bumps are explicit.
6. Input never logged; SDP secrets never logged.
7. Narrow traits at every platform boundary: `CaptureSource`, `VideoEncoder`, `VideoDecoder`, `Transport`, `InputSink`, `FrameRenderer`.
8. Specialists return small reviewable patches or evidence reports; the main session integrates. No subagent redesigns another subsystem.

## Performance budgets (acceptance targets, not promises)

- 1080p60 on a modern hardware encoder/decoder; graceful fallback to 1080p30
  (software MF encoder is a first-class fallback, delta D3).
- Input-to-visible median **≤ 80 ms LAN**, **≤ 150 ms WAN** when network RTT
  permits.
- Capture-to-encode queue depth **≤ 1 frame** steady state.
- Connection setup **< 5 s** on a warm client when direct ICE succeeds.
- No unbounded queue growth during 5% packet loss or bandwidth collapse.
- **60-minute soak**: no crash, runaway memory, stuck input, or progressive
  latency.
- Instrument per stage (capture/encode/send/recv/decode/present per
  `docs/perf-counter-schema.md`); optimize the measured stage, never
  aggregate FPS. Every perf-relevant patch ships a number or a benchmark.

## Commands

From the workspace root (Git Bash):

```bash
scripts/fmt.sh     # cargo fmt --all
scripts/check.sh   # cargo clippy --workspace --all-targets -- -D warnings
scripts/test.sh    # cargo test --workspace
```

Merge gate (all three green, every merge, every milestone):

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

CI (`.github/workflows/ci.yml`, windows-latest) runs the same three steps;
it executes in the cloud only after a remote exists (delta D6).

## Wire-format & versioning policy

Two surfaces, both owned by `crates/protocol` (delta D7):

1. **Signaling envelopes = JSON**, stable **snake_case** field names,
   flattened `type` discriminant. The TypeScript signaling service (M3) is
   generated against exactly these keys — renaming a field is a breaking
   change. `protocol_version` is currently `0`
   (`SIGNALING_PROTOCOL_VERSION`). JSON is self-describing, so *additive
   optional fields* may appear within a version (serde ignores unknown
   keys); anything else requires a bump.
2. **Data-channel/control messages = compact versioned binary**:
   `[version byte][bincode payload]` (bincode 1.x default options:
   little-endian, varint, trailing bytes rejected, 1 MiB decode limit).
   `WIRE_VERSION` is currently `0`. Bincode is **not** self-describing: any
   layout change — field reorder, type change, variant insertion — requires
   a version bump.

Rules:

- A version bump is an explicit, reviewed contract change and must ship with
  an updated compatibility test in `crates/protocol` (unknown version →
  typed `DecodeError::UnsupportedVersion` / `SignalingVersionError`, never
  garbage).
- Never log SDP bodies, the one-time session secret (`SessionSecret`'s
  Debug is redacted — keep it that way), or input event contents.
- Cursor shape pixels travel on the direct `cursor` data channel (bounded
  binary). They never appear in signaling, Tauri IPC, or logs. Video frames
  are an RTP track, not messages (invariant 1).

## Session state machines

`crates/session`: `Idle → Registering → Online → … → Connected →
Disconnected` for both roles; deterministic, event-injected, clock-injected.
Illegal transitions return typed `IllegalTransition` errors; duplicate
`message_id` delivery is a no-op; simultaneous-call collisions resolve by
device-id tie-break (smaller id keeps the controller role); late session
traffic in `Disconnected` is dropped. Full diagrams and legal-transition
tables: `docs/protocol/state-machines.md`. The M2 node runtime must behave
like `crates/session/tests/two_peers.rs` (the executable reference model).

## Conventions

- **Edition 2024** (deliberate: toolchain is Rust 1.98; no legacy reason to
  stay on 2021; 2024's stricter unsafe/lifetime rules fit new code). MSRV
  1.85 (first edition-2024 stable). Recorded in `[workspace.package]`.
- Workspace versioning/lints come from the root `Cargo.toml`
  (`clippy::all = warn` + `rust_2018_idioms = warn`, escalated to deny by the
  gate). Crate dependencies go through `[workspace.dependencies]`.
- Crate names are unprefixed (`protocol`, `session`, ...); this workspace is
  local-only and never published.
- Formatting: rustfmt defaults; no `rustfmt.toml` by design. Line endings LF
  (`.gitattributes` enforces; scripts are bash).
- Every queue in new code is bounded with an explicit drop policy (invariant
  3) — reviewers reject unbounded channels.
- Git: local only until the user provides a remote (D6). Phase gates are
  tagged (`m0-contract`, `m1-local-loop`, ...). Secrets/tokens: environment
  variables only, never committed, never printed.
- Windows API surface stays inside the `*-windows` crates behind the
  invariant-7 traits; unsafe code is confined to those crates and always
  reviewed with its failure handling (device loss, display change, UIPI).

## Workflow for agents

Before proposing code: read this file, `PLAN.md` §4 for your milestone, and
the affected modules. Return: decision, affected files/symbols, contract
changes, risks, tests, and the smallest next patch. Do not expand MVP scope,
restructure another subsystem, or change wire formats silently — request a
contract change from the architecture owner instead.
