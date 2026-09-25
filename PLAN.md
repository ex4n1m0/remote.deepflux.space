# Execution Plan — P2P Remote Desktop (working plan)

Derived from `C:\Users\igorc\Downloads\P2P Remote Desktop Development Plan.md` (the "source plan").
This is the operational plan the main GLM 5.3 session will follow. Where it differs from the
source plan, the difference and its reason is stated in §3. Backlog IDs (`RD-0xx`) and phase
numbers from the source plan are kept for traceability.

> **Execution status (2026-09-26): MVP engineering COMPLETE — SHIP-WITH-CONDITIONS**
> (`docs/reports/m6-soak.md` §10). Tags: `m0-contract`, `m1-local-loop`, `m2-direct-transport`,
> `m5-wan-matrix`, `m6-perf-soak`. M3's tag awaits deployed-service verification (needs Upstash
> env vars; README has the steps); M4's awaits the user's UX acceptance. Audit trail: 79 findings
> (F1–F79) across six milestone audits, all discharged or documented as ship conditions C1–C5.
> Post-MVP queue opens with the trusted-device roster (§ below).

---

## 1. Mission

One Windows 10/11 application, two runtime roles (Host / Controller). Tauri 2 + React/TypeScript
shell around a Rust native engine. Vercel is the signaling/control plane only — no screen, input,
cursor, or payload bytes ever traverse it. After SDP/ICE exchange, everything flows over a direct
WebRTC peer connection (STUN, TURN disabled in MVP). H.264 hardware pipeline on GPU, native
rendering, `SendInput` injection. No accounts, no relay, one controlled machine per session.

**Frozen decisions (from source plan §Key decisions):** unchanged — Windows-first, one binary /
both roles, Vercel + ephemeral Redis control plane, WebRTC STUN-only, H.264 GPU path, split
fast/reliable input channels, local-only favorites, bounded queues + newest-frame preference,
one-time consent gate + WebRTC built-in encryption as the security floor, libwebrtc fallback seam
if `webrtc-rs` misses the gate.

## 2. Non-negotiable invariants (will be encoded in AGENTS.md)

1. No frame bytes through Tauri IPC, React state, JSON, or canvas — ever.
2. Vercel is control plane only: IDs, presence, SDP/ICE envelopes. Nothing else.
3. Every queue is bounded; under pressure drop obsolete frames, never queue latency.
4. TURN/relay forbidden in MVP.
5. No undocumented wire-format changes; `protocolVersion` bumps are explicit.
6. Input never logged; SDP secrets never logged.
7. Narrow traits at every platform boundary: `CaptureSource`, `VideoEncoder`, `VideoDecoder`,
   `Transport`, `InputSink`, `FrameRenderer`.
8. Specialists return small reviewable patches or evidence reports; the main session integrates.
   No subagent redesigns another subsystem.

## 3. Deltas from the source plan (my judgment calls)

| # | Delta | Reason |
|---|---|---|
| D1 | Tauri shell moves out of RD-001 into Milestone 4 (RD-011) | Milestones 0–3 are pure Rust engine work driven by tests and diagnostic binaries. Keeping the shell out until the state machine and typed commands are stable avoids maintaining a UI against a churning backend — the source plan itself starts the UI engineer only after that point. |
| D2 | Phase 2's primary automated rig is **two processes on one machine** (host + controller over loopback); real two-PC LAN becomes an explicit user checkpoint | I automate on a single machine. Loopback ICE host candidates let offer/answer, RTP, and data channels be tested end-to-end without hardware; only true-LAN validation needs the user. |
| D3 | The Media Foundation **software** H.264 encoder is a first-class fallback, not an afterthought | Guarantees Milestone 1's gate can pass on any machine (including VMs without vendor encoders). Hardware path is detected, used when present, and reported in diagnostics. |
| D4 | MVP renderer is a minimal D3D11 swapchain presentation; `wgpu`/advanced GPU composition deferred to Milestone 6 | Source plan allows either. Simplest correct path to measured decode→present latency; polish later. |
| D5 | Signaling is developed against `vercel dev` locally; cloud deploy happens once, at the end of Milestone 3 | Keeps cloud debugging from hiding transport defects (source plan's own rule) and contains the Vercel/Upstash account dependency to one checkpoint. Vercel CLI 59.x is already installed. |
| D6 | Repo starts local-git only (`git init`, tags per phase gate); remote/CI push configured when the user provides a GitHub remote | Workspace is not a git repository yet. CI definitions land in M0 but run locally via the same scripts until a remote exists. |
| D7 | Wire formats: signaling envelopes = JSON (shared crate, also consumed by the TS service); control/data-channel messages = compact binary (serde + bincode-style, versioned) | Signaling must be inspectable and TS-friendly; data channels must be small. Both live in `crates/protocol` with round-trip tests. |

## 4. Milestones

Each milestone lists: work items (source backlog IDs), owner, exit gate, and whether the user must
participate. A milestone is done only when its gate is demonstrably met and `rd-performance-qa`
has reviewed it.

### M0 — Contract & skeleton (RD-001, RD-002, RD-003) · owner: `rd-architecture-owner`
- `git init`; Cargo workspace with all crates from the source layout as minimal compilable stubs;
  `rustfmt`, `clippy -D warnings`, test script; CI definition (windows-latest runner).
- `AGENTS.md`: architecture summary, the §2 invariants, performance budgets, command list,
  wire-version policy.
- `crates/protocol` v0: signaling envelope schema, binary control/input/cursor messages,
  capability negotiation struct, round-trip + compatibility tests.
- `crates/session`: host and controller state machines (`Idle → Registering → … → Connected →
  Disconnected`), fully deterministic, including reject/timeout/duplicate/simultaneous-call paths.
- `docs/adr/ADR-001` (architecture), ADR-002 (webrtc-rs behind Transport trait), state-machine
  diagrams, performance-counter schema (capture/encode/send/recv/decode/present timestamps).
- **Gate:** `cargo fmt --check && cargo clippy --workspace -- -D warnings && cargo test --workspace`
  green; two simulated peers complete a full session deterministically in tests.
- **User:** none.

### M1 — Local video loop (RD-004, RD-005) · owner: `rd-capture-codec-engineer`
- DXGI Desktop Duplication capture of one monitor with dirty/move metadata + cursor extraction;
  diagnostic binary that renders a local preview (validates capture without codec).
- MF H.264 encode → decode loop (hardware first, software fallback per D3), low-delay settings:
  no B-frames, short GOP, one-slice-per-frame low-latency mode.
- Minimal D3D11 presentation (D4); per-stage latency counters from the M0 schema.
- **Gate:** stable 1080p60 loopback for 30 minutes in one process; bounded memory and queue
  depth ≤ 1 frame steady-state; latency report written to `docs/reports/`.
- **User:** none (runs on this machine's real display).

### M2 — Direct transport, manual signaling (RD-006, RD-007, RD-008) · owners: `rd-p2p-transport-engineer`, integration by main session
- `webrtc-rs` peer connection behind the `Transport` trait; offer/answer exchanged by file copy
  (no STUN for the loopback baseline).
- H.264 RTP video track wired to M1's encoder output; data channels: `control` (reliable),
  `input-fast` (unordered, maxRetransmits 0), `input-reliable` (ordered), `cursor`.
- `crates/input-windows`: `SendInput` adapter, 0–65535 normalized coordinates, key/button
  tracking, `all_keys_up` on focus loss / disconnect / sequence gap.
- **Automated rig (D2):** host + controller as two processes on this machine; scripted
  connect → stream → inject → network-change recovery → clean disconnect.
- **Gate:** rig passes including loss/reorder/duplicate-signal tests; then **user checkpoint: run
  the two binaries on two PCs over real LAN** and confirm screen + input work.
- **User:** one LAN session with a second PC.

### M3 — Vercel linking (RD-009, RD-010) · owner: `rd-vercel-signaling-engineer`
- `services/signaling`: register/heartbeat presence, connect_request → accept/reject with one-time
  session secret, SDP/ICE mailbox, trickle forwarding, `cancel`/`disconnect`, idempotency by
  `messageId`, TTL cleanup (device 30–60 s, mailbox 2–5 min, session 5–10 min) on Upstash Redis.
- WebSocket (beta) primary with resumable sessions + HTTP polling fallback; state never
  authoritative in function memory.
- Contract tests: stale presence, duplicate delivery, reconnect, timeout, cross-instance.
- Developed against `vercel dev` (D5); single deploy at the end.
- **Gate:** two clients connect by machine ID with no manual SDP exchange, against the deployed
  service; all contract tests green.
- **User:** provide/link Vercel project + Upstash Redis (accounts, tokens via env vars — never
  committed).

### M4 — Product shell (RD-011, RD-012) · owner: `rd-desktop-ui-engineer`
- Tauri 2 + React shell now (D1): home with two roles, local machine identity + connection code,
  favorites (local persistence), connect/accept flow, online status, monitor picker, fit/1:1/
  fullscreen, quality presets, disconnect, compact diagnostics overlay driven by the counter
  schema; native viewer window owns the frame path.
- Typed Tauri commands bound to the session engine; UI state derived from the M0 state machine.
- **Gate:** one installer, both roles work end-to-end; component + state-transition tests; no
  frames through IPC (asserted by review + QA audit).
- **User:** accept the UX on a real session.

### M5 — WAN tuning & matrix (RD-013) · owners: `rd-p2p-transport-engineer`, `rd-performance-qa`
- STUN, congestion adaptation, bitrate/FPS/resolution controls, reconnect after interface change.
- Network matrix: loss 1–10%, RTT 50–250 ms, bandwidth step-down, UDP-blocked, ordinary NAT.
- **Gate:** matrix results + a written section documenting expected direct-only failures
  (symmetric NAT, UDP blocked) with the explicit error UX.
- **User:** real-WAN spot checks (e.g. phone-hotspot ↔ home network).

### M6 — Performance gate & soak (RD-014) · owner: `rd-performance-qa`
- Profile against the source targets (≤ 80 ms LAN / ≤ 150 ms WAN input-to-visible median, ≤ 5 s
  connect, 60-min soak, no unbounded growth under 5% loss); remove avoidable copies; enforce
  bounded queues everywhere; pass/fail release recommendation.
- **Gate:** soak report + prioritized findings with reproduction commands.
- **User:** none beyond M5's networks.

Post-MVP (source phase 7 — hardening, service mode, signing, TURN decision): out of scope for
this plan; revisited after M6.

**Post-MVP feature commitment (user, 2026-09-25): trusted-device roster with optional accounts.**
Username/password identity so a user can collect their usual machines as pre-approved remote
links — connect without the one-time consent prompt each time. Deferred until the current plan
(M5/M6) completes; design considerations to carry into that work:

- **Opt-in layer, not a replacement:** the anonymous connection-code flow stays the default;
  accounts exist only to sync/roster trusted devices. The "no accounts, ever" landing-page copy
  and MVP invariants describe the base product and will need rewording when this ships.
- **Pre-approval should be pairing-key trust, not a weaker consent:** each roster entry is a
  device the user explicitly paired once (e.g., per-device keypair exchanged during that first
  consent), so "pre-approved" means cryptographic recognition of the paired device — not merely
  "same username". One-time session secrets remain for transport; pairing replaces the repeated
  human prompt.
- **Reversible per device:** the roster must support revoking a device (host side: unpair →
  future connections from it fall back to the consent prompt).
- **Hosting implications:** auth + roster storage extends the signaling service (still control
  plane only — never frame/input bytes); password hashing (argon2/bcrypt-class), rate limiting
  (the M3 audit's missing token-bucket), and the CR-4 presence-query op become prerequisites.
- **Windows credential surface:** username/password sign-in in the M4 shell; token storage in
  Windows Credential Manager, never plaintext in the local favorites JSON.

## 5. Orchestration model

- **Main session (me):** integrator and only merger of cross-module change. Dispatches subagents,
  reviews their patches/evidence, keeps AGENTS.md current, tags phase gates.
- **Dispatch:** one work package at a time per subagent, with the affected contract quoted
  inline. Subagents return: files changed, tests/benchmarks, measured numbers, risks.
- **Availability caveat:** the six `rd-*` agents were just created in `~/.zcode/agents/` and may
  only be selectable after a session restart. Until they appear, the same work runs through the
  general-purpose agent with the exact system prompt from the corresponding agent file, or in the
  main session under the same rules. No work is blocked on this.
- **Review cadence:** `rd-performance-qa` audits at the end of every milestone (source rule),
  read-only except `docs/reports/` and benchmark outputs.
- **Parallelism:** M1 (capture/codec) and M2's transport spike (pure loopback video/data channel,
  test-pattern source, no DXGI dependency) can run in parallel exactly as the source plan's
  work-package 2 intends; I integrate both behind the traits afterward.

## 6. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| `webrtc-rs` pre-1.0 API churn or perf gap | Medium | Pin exact version; isolate behind `Transport` trait; libwebrtc replacement is a single-crate swap (frozen decision) |
| No hardware H.264 encoder on dev/test machine | Medium | Software MF encoder fallback is a gate-tested path (D3), not an exception |
| DXGI: fullscreen-exclusive apps, protected content, lock screen | Certain (known limits) | Documented unsupported in MVP; device-loss/display-change handling required in every capture patch |
| Input blocked into elevated/UAC windows (UIPI) | Certain | Documented MVP limitation; `all_keys_up` safety on every gap |
| Symmetric NAT / UDP blocked → connection impossible | Certain subset | Expected-failure UX with explicit error; TURN explicitly deferred |
| Vercel WS beta: instance-local sockets, duration limits | Medium | Resumable protocol + HTTP polling fallback from day one; state in Redis only |
| Latency budget missed at some stage | Medium | Per-stage timestamps from M0 onward; optimize the measured stage, never aggregate FPS |
| Single-machine automation hides real-network defects | Medium | Two-process rig covers protocol; every network-realistic claim waits for the M2/M5 user checkpoints |
| Secrets (Upstash/Vercel tokens) leakage | Low | Env vars only; never committed; agents never print them |

## 7. Quality bar (every merge, every milestone)

- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` — all green.
- Frontend (from M4): `tsc --noEmit`, lint, component/state tests.
- Every perf-relevant patch ships a number or a benchmark, not an adjective.
- Phase gates tagged in git (`m0-contract`, `m1-local-loop`, …).

## 8. External dependencies (user-side)

1. Vercel project + Upstash Redis accounts (M3) — tokens via environment variables.
2. A second Windows PC on the same LAN (M2 gate).
3. Real WAN networks for spot checks (M5).
4. Optional: GitHub remote for CI to actually run in the cloud (otherwise CI scripts run locally).

## 9. Immediate next actions (M0 kickoff, on approval)

1. `git init` + Cargo workspace skeleton (all crates as compilable stubs) + fmt/clippy/test
   scripts + CI definition.
2. `AGENTS.md` with §2 invariants and the command list.
3. `crates/protocol` v0 + `crates/session` state machines with deterministic two-peer tests.
4. ADR-001/002, state diagrams, counter schema.
5. Dispatch M1 (capture/codec) and the M2 transport spike in parallel once M0's traits land.
