# RD-015…018: AI-agent remote control — delivery report

Date: 2026-10-21 · Scope: ADR-004 · Commits: `d44abd3` (RD-015),
`ae93b2b` (RD-016/017/018) · Decision record:
`docs/adr/ADR-004-ai-agent-remote-control.md` · Study:
`docs/research/ai-agent-remote-control.md`

## What shipped

The user's local AI agent can see and drive the remote machine through the
same P2P session a human uses, with zero wire-format changes:

- **RD-015** — `FeatureFlags::AI_SESSION = 1<<4` (additive bit) threaded
  through consent: `HostEvent::IncomingRequest.capabilities` →
  `Action::PromptConsent.ai_session` (derived in the pure host machine) →
  `NodeObserver::prompt_consent(.., ai_session)` → `EngineEvent::ConsentRequested`
  → Tauri → the host dialog's distinct "requests AI-agent control of this
  machine" wording.
- **RD-016** — the frame tap: `node-runtime::screenshot`
  (`frame_surface::readback` → NV12/BGRA → RGB → fixed-point bilinear
  downscale ≤1600 px → JPEG q80 via the `image` crate), published by the
  controller decode thread through a condvar-bounded `ShotSlot`;
  `EngineHandle::capture_screenshot(timeout)`. ADR-004's scoped
  invariant-1 exception; every capture still increments `readback_count`.
- **RD-017** — synthetic input: `EngineCmd::AgentInput(Vec<AgentInput>)`
  converted by `agent_to_wire_events` with the same per-channel seq
  discipline as viewer input (fast moves on `input-fast`, the rest on
  `input-reliable`), 512-event drop-oldest batch cap, redacted `Debug`
  (invariant 6). No new wire variants (a new `AllKeysUpTrigger` would be a
  `WIRE_VERSION` bump — deliberately avoided; the existing gap→release_all
  safety covers agent input).
- **RD-018** — the stdio MCP bridge (`apps/desktop/src-tauri/src/mcp.rs`,
  official `rmcp` 3.6.0 SDK): `deepflux_status`, `connect`, `disconnect`,
  `screenshot` (JPEG image content + coordinate metadata), `click`,
  `type_text`, `key`, `scroll`, `wait_connected`. `--mcp` launch mode
  auto-starts the engine and advertises `AI_SESSION`.

## Verification

| Check | Result |
|---|---|
| `cargo fmt` / `clippy --workspace --all-targets -D warnings` | clean |
| `cargo test --workspace` | **282 passed / 0 failed / 16 ignored** |
| desktop TS (`pnpm typecheck`, `pnpm test`) | **60/60** |
| M4 E2E (real hardware, serial) incl. agent probe | **2/2** |
| MCP stdio handshake against the built exe | `initialize` + `tools/list` OK, 9 tools with schemas |

### Measured numbers (agent loop)

Real-hardware E2E (debug binaries, loopback session, real DXGI capture +
MF decode):

- Screenshot tap, cold (right after connect): **355 ms** including the
  wait for the stream's first frames. Earlier debug build (f64 resize):
  2594 ms — the fixed-point rewrite cut it ~7×.
- Screenshot tap, steady state, debug build: 947 ms (dominated by the
  unoptimized pure-Rust JPEG encode in debug; see below).
- Screenshot content: **40,529-byte JPEG, 1600×906** from a 1920×1088
  decoded frame.
- Synthetic agent input (move + click + text): accepted by the engine and
  **applied on the host recording sink** (`/input/applied ≥ 1`), riding
  the normal wire channels.

Release-mode timing reference (pure CPU, no GPU readback;
`cargo test -p node-runtime --lib screenshot --release -- --ignored`):

- 1920×1088 → 1600×906 resize + JPEG q80 (232 KB): **24.4 ms**
  (244.6 ms in the debug profile).

Expected release end-to-end tap: frame wait (~16–60 ms at streaming
cadence) + GPU readback + NV12→RGB + resize/JPEG ≈ **60–130 ms** — two
orders of magnitude under the model's per-step inference time (seconds),
which is the agent loop's real cost per the study (§3.4).

## Honest limitations of v1

- **Panic control = host takeover.** Agent input is indistinguishable from
  human input at the wire (by design), so there is no in-band "stop agent"
  signal; the host's v1 panic path is taking over the pointer, the existing
  Stop-sharing button, or closing the session (gap→AllKeysUp releases
  stuck keys). A per-session input-source tag would be a wire change —
  deferred, see ADR-004 §5.
- **No host-side live "AI session" banner** — the consent dialog and its
  supervision wording carry the distinction; a session-live indicator is
  queued with the UI work.
- **Prompt injection is the agent client's threat**: the remote screen is
  untrusted input to whatever model drives it; our side bounds the blast
  radius (consent gate, bounded queues, UIPI, no remote shell) but cannot
  make the agent's decisions safe. Credentials must be typed by the human.
- WAN reachability is unchanged from human remote control (direct ICE, no
  TURN in MVP).
- No remote shell, no file transfer, no unattended operation — per ADR-004.

## How to test

`docs/ai-agent-mcp-usage.md` — build exe at
`target/release/remote-desktop-app.exe`, host shares, controller runs with
`--mcp`, agent client points at it via stdio MCP config, then
`deepflux_connect` → host Accept → `deepflux_screenshot`/`click`/`type_text`.
