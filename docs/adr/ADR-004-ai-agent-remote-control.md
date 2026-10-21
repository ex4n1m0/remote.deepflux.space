# ADR-004: AI-agent control of the remote machine

- Status: Accepted (post-MVP, 2026-10-21)
- Deciders: main session (integrator), on the user's 2026-10-20 directive to
  act on the deep study
- Sources: `docs/research/ai-agent-remote-control.md` (the study),
  `crates/protocol/src/capabilities.rs`, `crates/session/src/{host,common}.rs`,
  `apps/desktop/src-tauri/src/engine/{mod,observer}.rs`, wire policy in
  `AGENTS.md`

## Context

The user wants to give instructions to an AI agent on their own machine and
have that agent perform actions on the remote machine through DeepFlux.
The deep study (2026-10-20) found the idea sound and timely — the market
validated it in 2026 (HopToDesk shipped built-in MCP support in March,
Jump Desktop ships a beta agent CLI, RustDesk has nothing) — and grounded
that DeepFlux already owns every load-bearing integration point: the
`InputEvent` wire path, a sanctioned CPU frame-readback precedent, an
additive capability-flag slot, and the consent flow.

This ADR records the contract changes the study recommends and gates the
first implementation slice (RD-015). The full agent driver, frame tap, and
MCP bridge are later slices (RD-016–RD-019) and do not ship here.

## Decision

### 1. Architecture: the agent runs on the controller, never on the host

The agent loop (screenshot → model → synthetic input → settle → repeat)
executes entirely on the controller machine, with the model being a cloud
API or a local VLM on the controller's own hardware. The host is unchanged
at the wire level: agent input is ordinary `InputEvent`s. The agent is
fronted by a local MCP server (stdio, the official Rust `rmcp` SDK,
RD-018) exposing screenshot/click/type/key tools, so the user's existing
coding agent treats the remote machine as a tool server; human supervision
through the existing viewer is the default posture, not an afterthought.
Rejected for v1: agent processes on the host (different footprint and
security posture), UIA side-channels (new channel + privacy review), and
any relay/TURN change.

### 2. Wire impact: one additive capability bit, nothing else

`FeatureFlags::AI_SESSION = 1 << 4` in `protocol::capabilities` — the next
free bit, advertised by a controller in the signaling `ConnectRequest`
(the controller already sends its full `Capabilities` there). This is
additive within `SIGNALING_PROTOCOL_VERSION = 1` per the wire policy:
a JSON u32 bitmask value that old peers parse but don't interpret. No new
or changed `InputEvent` variants, no `WIRE_VERSION` bump, no new data
channels, no signaling field renames. The bit's only v1 semantic: the host
consent prompt distinguishes "an AI agent requests control" from a human
request. Later semantic load (RD-017 status channel) is its own change.

### 3. Consent: the host machine derives the AI flag, the UI shows it

`HostEvent::IncomingRequest` gains the controller's advertised
`Capabilities` (the node runtime already has it from `ConnectRequest`).
The pure host state machine derives `ai_session =
capabilities.features.has(AI_SESSION)` and carries it on
`Action::PromptConsent`, so the decision is deterministic and testable in
the session crate — the runtime just transports a bool through
`NodeObserver::prompt_consent` → `EngineEvent::ConsentRequested` → Tauri
event → `HostPanel`. The consent dialog gains a distinct
"requests AI-agent control" wording. Consent remains the one-time,
per-session, human-accept gate; the AI flag changes presentation only.

### 4. Scoped invariant exceptions (documented now, exercised by RD-016+)

Two invariants need *narrow, reviewed* exceptions for the later slices.
Recording them here is the gate; code that claims them must cite this ADR.

- **Invariant 1** (no frame bytes through JSON/IPC): the RD-016 frame tap
  (CPU readback → downscale → PNG/JPEG) serves screenshots only to the
  *local, explicitly authorized* MCP agent at ≤2 fps, opt-in per session,
  host-consented — never through Tauri IPC or React, never on the
  real-time video path. Model: the M2 F33 sanctioned-unsafe exception for
  `node-runtime`, which is named and bounded, not a general license.
- **Invariant 6** (input never logged): the RD-017 action journal records
  action intents and outcomes but redacts `Text` payloads, mirroring the
  existing redacted `Debug` implementations. New agent-carrying types
  follow the redaction rule from day one.

### 5. Safety requirements v1 (RD-017 gates)

Supervision by default (the human viewer can always take over; host-side
local input preempts agent input); a host-side panic control that
immediately stops agent control; **no remote shell** — pixels and input
only (the same line HopToDesk drew); step budgets and rate limits reusing
the existing bounded-queue drop policy; screenshots treated as untrusted
input (prompt-injection posture) — credentials are typed by the human,
never by the agent. A future exec channel would be its own ADR.

### 6. Phasing

RD-015 (this ADR + the flag and consent plumbing, below) →
RD-016 (frame tap) → RD-017 (agent driver core) → RD-018 (MCP bridge) →
RD-019 (eval harness on the m2_rig, with the study's success-rate and
cost acceptance numbers).

## Consequences

- **Positive.** The consent path, capability negotiation, and UI are ready
  for the agent slices with zero wire-format churn; the host needs no
  agent-specific input handling (agent input is indistinguishable from
  human input at the wire, which is the point).
- **Negative.** `HostEvent::IncomingRequest` and `Action::PromptConsent`
  gain fields — a compile-time break for every observer/rig implementor
  and session test fixture (mechanical, all updated in the same patch).
  A malicious controller could set `AI_SESSION` untruthfully; the bit only
  changes prompt wording, and the host's posture (consent gate, bounded
  queues, UIPI) does not weaken — a spoofed flag does not grant new
  capability, only a different label, and later slices must not assume the
  flag proves anything stronger than that.
- **Risks.** Model reliability is the long pole (the study's Windows
  success-rate caveats), not transport; the v1 scope contains that risk by
  being assistive, supervised, and shell-free.
