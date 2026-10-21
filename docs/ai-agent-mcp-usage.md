# AI-agent remote control — local test guide (ADR-004, RD-015…019)

What shipped: your **local AI agent can see and drive the remote machine**
through the same P2P session the human viewer uses. The agent loop is:
screenshot (JPEG, ≤1600 px long edge) → model decides → click/type/key/
scroll — exposed to the agent as **MCP tools** over stdio. The host side is
unchanged except the consent prompt: a controller that advertised
`FeatureFlags::AI_SESSION` (bit 1<<4) shows *"requests AI-agent control of
this machine"* instead of the ordinary wording. Consent is still a human
click on the host, every session.

Scope today (RD-015–RD-018, `--mcp` mode): pixels + input only — **no
remote shell**, no TURN, no unattended operation. The viewer window stays
the supervision surface: watch it and take over with the mouse at any time.

## Setup (two machines, or two app instances on one machine)

1. **Host machine:** run the app normally (`pnpm tauri dev` or the built
   installer), go to *Share this machine*, note the connection code.
2. **Controller machine:** configure the signaling URL once in Settings
   (the deployed service `https://remote.deepflux.space` — the landing
   domain serves signaling — or a local dev server), then **quit the app**.
3. Re-launch the controller app **with `--mcp`**:

   ```bash
   # dev build
   cd apps/desktop && pnpm tauri dev -- -- --mcp
   # or the built exe
   ./target/release/remote-desktop.exe --mcp
   ```

   In this mode the app auto-starts the engine and serves the MCP bridge on
   **stdio** (the client spawns it; nothing listens on a port).

## Point your agent at the bridge

MCP config for your agent client (ZCode/Claude Code/etc.) — spawn the app
with `--mcp` and `stdio` transport:

```json
{
  "mcpServers": {
    "deepflux": {
      "command": "C:\\path\\to\\remote-desktop.exe",
      "args": ["--mcp"],
      "transport": "stdio"
    }
  }
}
```

## The tools

| Tool | What it does |
|---|---|
| `deepflux_status` | engine/session state + input counters (JSON) |
| `deepflux_connect {device_code}` | connect to a remote machine (host human still consents) |
| `deepflux_disconnect` | end the session |
| `deepflux_screenshot` | JPEG of the remote screen + pixel dimensions |
| `deepflux_click {x, y, button?}` | click in the last screenshot's pixels (left/right/middle) |
| `deepflux_type_text {text}` | type text (Unicode; text is never logged) |
| `deepflux_key {name}` | press a named key (enter, escape, tab, arrows, f1–f12, …) |
| `deepflux_scroll {delta_v}` | mouse wheel (negative = down) |
| `deepflux_wait_connected {timeout_ms?}` | block until the host accepted consent |

Example session: `deepflux_connect` → `deepflux_wait_connected` (the human
on the host clicks Accept) → `deepflux_screenshot` → look at the image,
then `deepflux_click`/`deepflux_type_text` → verify with another
`screenshot`.

## Design & safety notes (per ADR-004)

- **Frames never leave the process.** The screenshot tap is the one new CPU
  readback (`frame_surface::readback`, counted), downscaled and JPEG-encoded
  on the controller — served only to the local stdio client at agent rates,
  never through Tauri IPC or the real-time video path (invariant 1's
  scoped, ADR-004 exception).
- **Input is ordinary `InputEvent`s.** The agent's actions ride the same
  `input-fast`/`input-reliable` channels and per-channel seq discipline as
  the human viewer — no wire changes, no `WIRE_VERSION` bump. Batches are
  capped (512, drop-oldest) and dropped when no session exists.
- **A spoofed `AI_SESSION` bit grants nothing** beyond the prompt wording:
  the consent gate, bounded queues, and UIPI are unchanged.
- **Prompt injection:** the remote screen is untrusted input to your agent.
  Never put credentials in the agent's context; type passwords yourself.
- **Known limits:** no host-side live "AI session" banner yet (the consent
  dialog carries the distinction); single monitor default; WAN reachability
  is the same as human remote control (direct ICE, no TURN in MVP).

## Where the code lives

- `crates/node-runtime/src/screenshot.rs` — readback → NV12/BGRA → RGB →
  bilinear downscale → JPEG (pure functions unit-tested).
- `apps/desktop/src-tauri/src/engine/{mod,controller}.rs` — `ShotSlot`
  (decode-thread tap, `EngineHandle::capture_screenshot`), `AgentInput` +
  `agent_to_wire_events` + `EngineCmd::AgentInput` drain.
- `apps/desktop/src-tauri/src/mcp.rs` — the stdio MCP bridge (official
  `rmcp` SDK), tool set, coordinate mapping, key table.
- `crates/protocol/src/capabilities.rs` — `FeatureFlags::AI_SESSION`.
- `apps/desktop/src-tauri/src/bin/e2e_child.rs` + `tests/e2e.rs` — the
  agent-path E2E probe (screenshot JPEG + synthetic input applied on the
  host recording sink).

Deep study: `docs/research/ai-agent-remote-control.md`. Decisions:
`docs/adr/ADR-004-ai-agent-remote-control.md`.
