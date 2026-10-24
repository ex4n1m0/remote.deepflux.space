# ADR-005: Agent-first product — in-app assistant, machine chat, pairing

- Status: Accepted (2026-10-24); RD-020/RD-021 land with this ADR,
  RD-022/RD-023 implement the chat/pairing sections below.
- Deciders: main session (integrator), on the user's 2026-10-24 answers to
  the study's open questions (`docs/research/agent-first-ux-study.md`).
- Sources: that study; ADR-003 (control-plane widening precedent),
  ADR-004 (agent control + frame tap); the user's OnlyHumans
  (`C:\OnlyHumans-app`, `C:\OnlyHumans-main`) and MSP
  (`C:\ModelSwarm Protocol (MSP)`, DeepSeek cloud-executor client pattern)
  projects.

## Context

The 0.3.0 release made the app *controllable* by an external agent over
stdio MCP. The user's next phase makes the agent a first-class part of the
product: an always-visible assistant that configures the app, chat between
machines that works with or without a session, agent-to-agent instruction
flow (model on machine A converses with model on machine B), and
paired/unattended access so a family member's machine can be helped
without a per-session consent click.

## Decision

### 1. The assistant is in-app, model-backed, DeepSeek first (RD-021)

A Rust-side agent (`apps/desktop/src-tauri/src/agent/`), not webview
logic: an OpenAI-compatible chat-completions client (ureq, non-streaming
v1) pointed at `https://api.deepseek.com/v1` by default, model
`deepseek-flash` (vision-capable — screenshots ride as base64
`image_url` tool results; function calling drives the tool loop; text-only
`deepseek-chat` remains a settings option). The API key is the user's,
stored in the Windows Credential Manager through the existing
`credstore::SessionStore` seam under the synthetic user `agent-api-key`;
never in the repo, never in settings JSON, never logged (invariant 6
discipline). Provider config is settings fields (`agent_base_url`,
`agent_model`), so any OpenAI-compatible endpoint (cloud or local) works
without code change.

### 2. One tool layer, two consumers

The tool implementations (session control from ADR-004's bridge + new
app-config tools: machines CRUD, settings, host start/stop, identity)
live in `agent/tools.rs` and are called by both the in-app assistant and
the existing `--mcp` stdio bridge. Tools ride the same typed
command/store surfaces the UI uses — no privileged path. The tool loop is
bounded (max steps per turn), and every tool call is surfaced to the user
as a card in the assistant panel (observability = the 2026 safety
consensus applied at product scale).

### 3. Machine chat is always available (RD-022; user decision)

Chat between two machines works **with or without a remote-control
session**, OnlyHumans-style:
- **In-session:** rides the direct DTLS data channel — new `Channel::Chat`
  + `WireMessage::Chat`, `WIRE_VERSION` 0→1 with the policy compatibility
  test. Vercel never sees a byte.
- **Out-of-session:** the signaling service gains OnlyHumans-shaped
  **sealed envelopes** (`inbox:<device>`: ciphertext + nonce only, TTL'd,
  drained by owner — invariant 2 read the same way ADR-003 widened it:
  control plane carries envelopes, never plaintext). Pair-derived keys
  (§4) seal them; unpaired machines can still chat within a session.
- History persists locally per machine (SQLite, schema modeled on
  OnlyHumans `core/src/store.rs`).

### 4. Agent-to-agent: the models converse on the chat channel (user decision)

Chat messages carry a sender kind (`user` | `agent`). Each side's
assistant can read agent-addressed traffic; the controller's model
orchestrates and sends instruction messages to the peer's model, which
executes and reports back — over the same always-available channel. v1
safety posture: the host-side agent's actuator set is the same ADR-004
surface (it may drive its own machine only through the reviewed input
path and only while a session is live, i.e. under the human's eye in the
viewer); autonomous host-side action without a live session remains out
of scope until the §6 review.

### 5. Pairing: full control once connected (RD-023; user decision)

The consent dialog gains "remember this device": the host stores a
per-device pairing entry (device id + shared secret from the one-time
session), and paired controllers connect **without a fresh consent
prompt** — PLAN.md's deferred "pairing-key trust", now activated for the
family-support scenario. Trust anchor: the pairing event + the action
journal on both ends; revocation per device from the machines list.
"Full control once connected" means the ADR-004 surface (screen + input)
with no additional per-action prompts for the paired controller.

### 6. Still deferred (unchanged)

The allowlisted host-side admin command channel (temp-clean/language
cmdlets) stays deferred — the user did not activate it; `deepseek-flash`
vision makes the pixels path viable first. Agent-side autonomous
destructive actions remain forbidden; every action is journaled and
visible in the assistant panel.

## Consequences

- Positive: one key, one provider covers chat + config + vision control;
  the contact-list UI, assistant, and chat all reuse existing typed
  surfaces; OnlyHumans' hub/store patterns transfer without embedding a
  second transport.
- Negative: `WIRE_VERSION` 0→1 (first binary bump — the policy's
  compatibility-test requirement applies); the signaling service gains a
  ciphertext-envelope endpoint (deploy needed when RD-022 ships);
  DeepSeek outages degrade the assistant (manual UI unaffected).
- Risks: prompt injection through screenshots (ADR-004 §5 posture
  stands); agent-to-agent loops (both models talking forever) are bounded
  by step budgets and a turn-passing rule; key leakage is bounded by
  Credential Manager storage + redacted logs.
