# M4 — Product shell (RD-011/RD-012) report

Date: 2026-09-25 · Owner: `rd-desktop-ui-engineer` (M4 work package) ·
Baseline: `a2bc0a2` + this working tree (not committed, per instructions).

Deliverable: `apps/desktop/` — a Tauri 2 + React/TypeScript product shell
around the existing Rust engine, plus tests, an E2E gate, and one NSIS
installer. No files outside `apps/desktop/**` were modified except the two
mechanical integration points the work package requires:

- `Cargo.toml` (root): added `"apps/desktop/src-tauri"` to `[workspace]
  members` (one line + comment) so the gate covers the crate.
- `.gitignore` (root): ignore `apps/desktop/dist/` (vite build output).

`Cargo.lock` changed because the tauri tree enters the workspace build.

## 1. Architecture

### 1.1 Window topology (invariant 1: the viewer is a NATIVE window)

```
┌──────────────────────────── process: remote-desktop-app.exe ─────────────┐
│                                                                          │
│  [Tauri webview window "shell"]          [native Win32 viewer window]    │
│  React control surface only              created + owned by the engine's │
│  - home / favorites / consent            controller "present" thread via │
│  - session controls, diagnostics         render-windows::PresenterWindow│
│  - NO video, NO input payloads           + D3D11Renderer swapchain       │
│                                          (the m2_rig presenter pattern)  │
│        ▲ typed invoke() commands                  │ GPU surfaces only    │
│        │ + engine://* events (metadata)           ▼ never cross IPC      │
│  ┌─────┴──────────────────────── engine thread (2 ms loop) ───────────┐  │
│  │ node-runtime::Node (both machines) + RemoteSignaling (WS+HTTP)     │  │
│  │ host pipeline: DxgiCapture → MfEncoder (CodecPool, F26 lifetimes)  │  │
│  │ controller pipeline: RTP recv → MfDecoder → present thread         │  │
│  │ viewer input: subclassed wnd_proc → bounded queue → wire channels  │  │
│  │ host input: InputPump → SendInputSink (set_monitor_rect on pick)   │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

The engine (`src-tauri/src/engine/`) is **tauri-free** — the Tauri commands,
the E2E child binary, and the integration tests all drive the identical
`EngineCmd` → engine → `EngineEvent` surface. Frames travel
GPU-surface→encoder→RTP→decoder→swapchain entirely inside the engine; the
shell sees state names, ids, and counters only.

Viewer input (controller keyboard/mouse) is captured by subclassing the
presenter window proc (`engine/viewer.rs`), normalized to the wire's
0..=65535 space, queued in a bounded (256, drop-oldest, counted) queue, and
sent by the engine loop on `input-fast`/`input-reliable` — the same wire path
the m2_rig's scripted input used. `WM_KILLFOCUS` emits
`AllKeysUp{FocusLost}` (the M2 input package's documented M4 hook — asserted
in the E2E). `F11` toggles borderless fullscreen locally and is never
forwarded. Text is joined as UTF-16 (surrogate pairs survive coalescing).

### 1.2 Session engine policy (composition, not machine changes)

The state machines are untouched. Engine-level policies on top of them:

- **Transport ownership**: one transport per engine, `set_transport_owner`
  set to the role that needs it (host before consent accept, controller
  before connect); a dead session's transport is closed on the session-end
  edge so re-register attaches a fresh peer connection (rig parity).
- **Auto re-online** (`auto_reonline`, on by default): after a session ends,
  the engine re-issues `Start` ~1 s later (the m2_rig's scripted recovery) so
  "share this machine" stays on. Explicit Stop disables it.
- **One session per app instance**: starting a role while the other role is
  in-session returns a typed `role_conflict` error (UI disables it too).
- **Signaling** is `RemoteSignaling` (M3) against the base URL from settings;
  the app self-acks registers only after the service accepts (F27 inherited).

### 1.3 Persistence (local-only, RD-011)

`%APPDATA%/space.deepflux.remote.desktop/settings.json` (device id, presence
token, display name, signaling URL, default quality/scale) and
`favorites.json` (id/name/code). Atomic writes (tmp+rename), corrupt files
log-and-default. Identity is generated once and immutable from the UI; the
connection code IS the device id (no directory service in the MVP).

## 2. IPC surface (invariant-1 proof)

All payloads are JSON-serializable metadata. `tests/ipc_surface.rs` makes
this executable: it serializes the diagnostics snapshot and engine status and
recursively walks the JSON, failing on any byte-buffer/surface/SDP/secret/
input-payload key or any array > 32 elements.

### 2.1 Commands (webview → Rust, `src/commands.rs`)

| Command | Argument type | Result type |
|---|---|---|
| `engine_start` | — | `EngineStatusDto` |
| `engine_status` | — | `EngineStatusDto` |
| `get_identity` | — | `Identity {device_id, device_name, connection_code}` |
| `get_settings` / `set_settings` | `SettingsPatch` | `SettingsDto` |
| `list_favorites` | — | `Vec<FavoriteDto {id, name, code}>` |
| `add_favorite` | `{name, code}: String` | `FavoriteDto` |
| `remove_favorite` / `rename_favorite` | `{id[, name]}` | `FavoriteDto` / list |
| `host_start` / `host_stop` | — | `()` |
| `controller_start` / `controller_stop` | — | `()` |
| `connect` | `{code}: String` | `()` |
| `cancel_connect` / `disconnect` | — | `()` |
| `consent_accept` / `consent_reject` | — | `()` |
| `set_quality` | `{preset}: "auto"\|"low"\|"balanced"\|"high"` | `()` |
| `select_monitor` | `{monitor_id}: String` | `()` |
| `list_monitors` | — | `{host, peer}: Vec<MonitorDto>` |
| `viewer_set_scale` | `scale: "fit"\|"one_to_one"` | `()` |
| `viewer_toggle_fullscreen` | — | `()` |

### 2.2 Events (Rust → webview, `engine://*`)

| Channel | Payload | When |
|---|---|---|
| `engine://state` | `{machine: "host"\|"controller", state, session_id}` | every machine state change (names from `*State::name()`) |
| `engine://consent` | `{controller_device_id, session_id}` | `PromptConsent` |
| `engine://session-established` | `{session_id, peer}` | `SessionEstablished` |
| `engine://session-ended` | `{cause, code, message, hint}` | `SessionEnded` (cause = `DisconnectCause` Debug; copy per §3.2) |
| `engine://peer` | `{device_id, online: bool}` | consent prompt / session end |
| `engine://caps` | `{origin: "host"\|"peer", monitors: [MonitorDto]}` | host caps built / `Hello`/`HelloAck` |
| `engine://diagnostics` | `{snapshot: DiagSnapshot}` | 1 Hz aggregate (p50/p95 per stage, fps, link, queues, input counters, encoder hw/sw) |
| `engine://error` | `{code, message, hint}` | direct-connection failures etc. |
| `engine://info` | `{message}` | confirmations (quality applied, monitor picked…) |

Every queue on the path is bounded with an explicit drop policy (invariant 3):
command channel 64 (error on full), event channel 512 (diagnostics
droppable; state pull-readable via `engine_status`), viewer input 256
(drop-oldest, counted in the snapshot).

## 3. State mapping (UI derives from the machines only)

`src/state/mapping.ts` is exhaustive over the state names; the component
tests assert every state and the transition triggers
(`tests/mapping.test.ts`, 19 cases).

### 3.1 Host machine → host panel

| `HostState::name()` | view | tone | actions offered |
|---|---|---|---|
| `Idle` | idle | neutral | Share |
| `Registering` | registering | progress | — |
| `Online` | online | good | Stop (+ connection code shown) |
| `ConsentPrompted` | incoming | warn | Accept / Reject (consent dialog) |
| `Exchanging` | sharing | progress | Stop |
| `Connecting` | sharing | progress | Stop |
| `Connected` | sharing | good | Stop |
| `Disconnected` | ended | bad | Share (auto re-online makes this transient) |

### 3.2 Controller machine → controller panel

| `ControllerState::name()` | view | tone | actions offered |
|---|---|---|---|
| `Idle` | idle | neutral | (start via connect flow) |
| `Registering` | registering | progress | — |
| `Online` | online | good | enter code / favorite Connect |
| `Requesting` | connecting | progress | Cancel |
| `Offering` | connecting | progress | Cancel |
| `Connecting` | connecting | progress | Cancel |
| `Connected` | session | good | monitor picker, quality, fit/1:1, fullscreen, Disconnect |
| `Disconnected` | ended | bad | reconnect flow |

Disconnect copy (`engine::disconnect_copy` + TS `disconnectCopy`, both
tested): `user_disconnect`, `peer_disconnect`, `timeout`, `rejected`,
`canceled`, `collision`, `transport_error` — the last two carry the
direct-only hint ("…symmetric NAT or UDP is blocked… TURN deferred"), the
M5 expected-failure UX requirement.

### 3.3 Quality presets and monitor selection

`QualityPreset → (fps, bitrate, WxH)`: low 30/2 Mbps/720p, balanced (and
auto, until M5 congestion owns it) 60/6 Mbps/1080p, high 60/12 Mbps/1440p.
The controller sends `WireMessage::SetQuality`/`SelectMonitor` on `control`;
the host applies the preset by rebuilding the encode stage (one MFT instance
dropped per change — the known codec-windows drop-path leak, counted as
`encoder_rebuilds`, bounded by user action; CR-1 asks for live ICodecAPI
reconfiguration instead), and the monitor by swapping the DXGI duplication
plus `SendInputSink::set_monitor_rect`; display changes call
`refresh_display_metrics`.

## 4. Test evidence

### 4.1 Gates (all green, this machine)

- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean (the whole
  workspace, with the new crate).
- `cargo test --workspace` — green: pre-existing suites unchanged; new:
  11 lib unit tests, 3 `state_flow`, 2 `ipc_surface`, 1 `e2e` (skips
  without the env, F44 convention).
- Frontend: `tsc --noEmit` clean; `eslint .` clean; `vitest run` 36/36
  (state mapping 19, reducer 6, components 11).

### 4.2 State flow (`tests/state_flow.rs`, no GPU needed)

Two engines over the in-memory `SignalingHub` with **real loopback
transports**: host start→Online; connect→ConsentPrompted (+`ConsentRequested`
event, peer-online); accept→both Connected (+`SessionEstablished` on both,
session id equality); `SetQuality`/`SelectMonitor` round-trip on the wire;
diagnostics event received; disconnect→both Disconnected with
`user_disconnect` copy; auto re-online→host Online again. Plus the reject
path and the not-Online connect error.

### 4.3 E2E (reduced-but-real form) — `tests/e2e.rs`; passed 3× pre-fix-package and 2× with the QA fix package

Logs: `docs/reports/data/m4-e2e-20260925-run.log` (pre-fix) and
`docs/reports/data/m4-e2e-20260925-fixpkg.log` (fix package — adds the
resize and viewer-close probes and the asserted causes).

Topology: the test spawns the local signaling stack itself —
`node tools/upstash-emulator.mjs --port 38091` +
`node --import tsx tools/dev-server.mjs --port 38093` (the same standalone
server the M3 contract tests drive) — then **two app instances**
(`e2e-child`, the full engine incl. real pipelines; the controller opens the
real native viewer window on this machine's desktop).

Scenario and assertions (all passed, ~21 s):

| Step | Evidence |
|---|---|
| host start → Online | state log `host->Registering`, `host->Online`; status file |
| controller connect → consent | `verdict.consent_prompted = true`; host `ConsentPrompted` |
| host accept → session live | both `Connected`; host captured **840** / encoded **829** frames (7 keyframes); viewer **presented 456** frames (real desktop through DXGI→NVENC→loopback WebRTC→MF decode→D3D11) |
| quality preset change | `SetQuality(high)` on the wire; host encoder rebuilt 1920x1080@6 Mbps → **2560x1440@12 Mbps** (`encoder_rebuilds = 1`; describe string asserted) |
| monitor pick | `SelectMonitor(primary)` round-tripped; host `active_monitor` set |
| focus-loss safety | `WM_KILLFOCUS` posted to the real viewer HWND → controller sent **1** `AllKeysUp{FocusLost}`, host pump counted the release |
| viewer resize | scripted 1600x1000 off-aspect client → swapchain follows (asserted equal to client size; F49 fix) |
| diagnostics events | controller received **16** 1 Hz aggregate events |
| disconnect (via closing the viewer window) | both `Disconnected`; **causes asserted**: controller `User`, host `Peer` (F53 fix; previously log-described only) |
| host returns Online | `back Online after session end`; final `host_state = Online` |

**What remains manual** (tauri-driver multi-window automation was judged
impractical here; the drive is at the command layer — the identical code
path the buttons invoke):

1. The webview shell itself (button → command → engine wiring; verified by
   component tests + the command layer being the same code).
2. Real keyboard/mouse forwarding *feel* (the E2E proves the capture → wire
   → `InputPump` path with the recording sink; the product's `SendInputSink`
   path is M2-tested and needs a two-PC or manual single-PC session).
3. The M4 gate's "user accepts the UX on a real session" checkpoint
   (PLAN.md M4 user line) — inherently human.
4. Cursor-shape compositing is counted, not drawn (position overlay IS
   drawn); see gaps.

## 5. Installer

`pnpm tauri build` → `target/release/bundle/nsis/Remote
Desktop_0.1.0_x64-setup.exe` (6.3 MB), per-user install
(`installMode: currentUser`), English NSIS. **NSIS over MSI** because the
app is a per-user desktop tool with no machine-wide registry/COM/service
needs: NSIS gives the smaller, faster, elevation-free install that matches
the "no accounts, local-only" MVP posture (MSI would add WiX/toolchain
weight for enterprise deployment features the MVP does not have). Release
binary smoke-launched: window "Remote Desktop" opens and idles cleanly.

## 6. QA fix package (F48–F53, F55, F57 — `docs/reports/m4-qa-audit.md`)

Landed after the audit, before the UX checkpoint:

- **F48 (blocking-UX)**: pointer input now normalizes over the renderer's
  **destination rect**, not the window client. `render-windows` gained the
  sanctioned additive pure helper `rect::destination_rect` (+ a read-only
  `D3D11Renderer::destination_rect_for`); `present` delegates to it, so
  drawn and mapped rects cannot drift. Clicks in letterbox bars / beyond a
  smaller-than-window 1:1 frame are dropped, not clamped. Tested across
  fit-letterbox, fit-pillarbox, matching-aspect, 1:1 crop (window smaller),
  1:1 window-larger, 21:9-in-8:5, degenerate rects, and the audit's two
  repro geometries (6 new unit tests + 1 in render-windows).
- **F49 (blocking-UX)**: `take_resized()` → `renderer.resize()` wired in
  `pump_and_present` (m2_rig parity); the dest rect recomputes on resize
  before the next frame; client and swapchain sizes are observable in
  `EngineStatus` and the E2E asserts the swapchain follows a scripted
  1600x1000 off-aspect resize.
- **F50 (blocking-UX)**: viewer-close is wired end-to-end — the present
  thread's `window_closed` counter propagates to the observer flag, the
  engine sends the data-plane goodbye and `controller_disconnect`
  (controller cause `User`, host `Peer`), and a stale-flag clobber that
  would have respawned the closed window is closed. E2E ends the session
  by closing the viewer and asserts the causes.
- **F51**: `BlockedByUipi` surfaces as a rate-limited (5 s)
  `engine://error` (`uipi_blocked`, with the elevate/unlock hint) on new
  inject errors while hosting, and the overlay's input line shows
  `blocked N`. Policy unit-tested; overlay rendering component-tested.
- **F52**: `tests/ipc_surface.rs` now walks **every** `EngineEvent`
  variant (worst-case payloads, incl. a 40-monitor list that must NOT
  trip), every command-argument DTO, and keeps the snapshot walks; the
  >32 bound applies to number arrays only (byte-blob shape). New variants
  must be added to `all_events()` — noted in the test.
- **F53**: E2E asserts the controller disconnect cause `User` and the
  host cause `Peer`; this report's evidence table corrected (the old row
  described the log, not an assertion).
- **F55**: engine teardown (app quit / window close mid-session) sends
  wire `AllKeysUp{Disconnect}` + `Disconnect{User}`, drains 150 ms, then
  transitions the machines before closing the transport. Pinned by
  `state_flow::graceful_shutdown_mid_session_sends_the_peer_goodbye`
  (host sees the `Peer` end in < 5 s, not the failure-detection path).
- **F57**: favorites show a green dot only while known-online (session
  with that machine); otherwise a neutral "?" labeled "status unknown"
  with the no-presence-query explanation. Never a definite "Offline".

Not in this package (tracked by the audit): F54 (dead controller Stop
affordance — mapping-table note), F56 (CR-1 leak re-quantification,
blocking-for-M5), F58 notes.

## 7. Known gaps for M5/M6

- **Quality changes rebuild the encode stage** (~1 s gap, one leaked MFT
  drop-path allocation per change, counted). CR-1 requests live
  `ICodecAPI` bitrate reconfiguration in codec-windows.
- **`Auto` preset == `Balanced`** until M5's congestion control owns it.
- **Peer online/offline is session-scoped**: the service exposes no presence
  query to clients, so favorites show online only during active
  sessions/prompts. CR-4 requests a presence-query op.
- **Cursor shapes** are counted, not composited (positions ARE overlaid).
- **Both roles simultaneously** are prevented (`role_conflict`) — one live
  session per app instance (MVP scoping, matches "one controlled machine
  per session").
- **Viewer input** requires window focus; no pointer capture outside the
  window; `Ctrl+Alt+Del` and other SAS sequences never arrive (OS).
- Diagnostics overlay shows live-session aggregates; host+controller
  halves both flow into one snapshot per instance (two instances see their
  own halves — matches the two-clock-domain schema rule).
- The E2E harness kills stray signaling services on its ports before/after
  the run; repeated runs must not reuse device ids against a warm mailbox
  (the service dedupes by `message_id`) — handled with per-run ids.

## 8. Change requests (for the architecture owner)

- **CR-1 (codec-windows)**: expose live encoder reconfiguration
  (ICodecAPI bitrate/fps) so quality presets stop rebuilding the MFT.
- **CR-2 (render-windows/input-windows)**: viewer-window input capture
  (subclass proc, focus-loss, fullscreen) currently lives in
  `apps/desktop/src-tauri/src/engine/viewer.rs` with reviewed unsafe — the
  only AGENTS-convention deviation in M4. Request: a narrow
  `PresenterInput` trait in a `*-windows` crate so the unsafe moves home.
- **CR-3 (capture-windows)**: export the existing private
  `enumerate_monitors` (or an equivalent display-info API); the shell
  currently re-enumerates via Win32 (`engine/displays.rs`).
- **CR-4 (services/signaling)**: a presence-query op so favorites can show
  online state before a connect request (optional field, no schema break).
- **CR-5 (node-runtime, M3-note follow-up)**: the proposed additive
  `sender_role` envelope field would remove the remote-adapter's role
  inference for disconnect routing (nice-to-have; current learning table
  is proven by M3 tests and M4 E2E).

## 9. Risks for M5/M6

- The tauri tree (~4.5 k lock lines) enters the workspace; version drift
  between tauri/tauri-build/wry should be watched on upgrades (pinned by
  the lockfile now).
- Two engines in one process (state_flow tests) share nothing global;
  the E2E uses two processes like the rig — but M5's reconnection matrix
  must re-run the full app E2E, not just the rig.
- The encoder rebuild path leaks ~14 MiB per quality change (measured by
  M2's leak probe class); a soak that hammers preset changes would show it
  (M6 gate should add a preset-hammer soak item).
- WebView2 runtime dependency for the shell (video is native, but the
  control surface needs it; preinstalled on Win10/11).
