# apps/desktop — the product shell (M4, RD-011/RD-012)

One Windows application, both roles. A **Tauri 2 + React/TypeScript webview
shell** (the control surface) around the **Rust engine** (`src-tauri/src/engine/`),
which composes the exact `node-runtime` stack the m2_rig proved: DXGI capture →
MF H.264 → WebRTC (loopback-capable, STUN-only, TURN forbidden) → MF decode →
native D3D11 viewer window; `SendInput` injection on the host.

**Video never crosses the UI boundary** (AGENTS.md invariant 1): the viewer is a
separate native Win32 window owned by the engine's present thread. The webview
only ever sees state names, ids, and counters.

## Layout

```
src/                      React control surface
  state/mapping.ts        UI views = pure functions of the machine states
  state/reducer.ts        engine events → one UI state (tested)
  state/account.ts        account reducer + onboarding gate + error copy (tested)
  hooks/useEngine.ts      Tauri events + 1 Hz status poll wiring
  hooks/useAccount.ts     account/roster wiring + 30 s presence poll (logged in only)
  components/             home, onboarding, computers, favorites, consent,
                          session controls, overlay
src-tauri/
  src/commands.rs         typed Tauri commands (thin veneer)
  src/ipc.rs              IPC DTOs (metadata only — the invariant-1 proof)
  src/store.rs            settings + favorites + account.json + roster.json
  src/account.rs          AccountManager: login/register/unlock/logout,
                          encrypted-roster merge + sync (fake-service tested)
  src/credstore.rs        session token in the Windows Credential Manager
  src/engine/             the tauri-free engine (reused by tests + e2e child)
    mod.rs                loop thread: commands in, events out, pipelines
    host.rs               capture→encode pipeline (monitor switch, presets)
    controller.rs         decode→present pipeline (owns the viewer window)
    viewer.rs             native viewer: subclass input capture, focus-loss
                          AllKeysUp, scale modes, borderless fullscreen
    pool.rs               process-lifetime codec/capture pool (m2_rig F26)
    diag.rs               diagnostics aggregation (numbers-only snapshots)
    quality.rs            QualityPreset → encoder/pacer plan
    displays.rs           Win32 display enumeration (see CR-3 in the report)
  src/bin/e2e_child.rs    one scripted engine instance for E2E
  tests/state_flow.rs     two engines over the in-memory hub: full state flow
  tests/ipc_surface.rs    invariant-1 executable proof (payload walking)
  tests/e2e.rs            two app instances over the local signaling server
```

## Prerequisites

- Rust 1.98 (workspace MSRV 1.88), MSVC toolchain
- Node 22 + pnpm 9 (frontend + the local signaling rig)
- WebView2 runtime (preinstalled on Windows 10/11)

## Commands

```bash
cd apps/desktop
pnpm install          # once
pnpm dev              # vite dev server (tauri dev needs it via beforeDevCommand)
pnpm tauri dev        # run the app in dev mode

pnpm typecheck        # tsc --noEmit
pnpm lint             # eslint
pnpm test             # vitest: component + state-mapping tests

# Rust side (also covered by the workspace scripts):
cargo fmt --all
cargo clippy -p remote-desktop-app --all-targets -- -D warnings
cargo test -p remote-desktop-app
```

## End-to-end test (real pipelines, this machine)

```bash
# local signaling rig is spawned by the test itself (Upstash emulator +
# standalone WS server from services/signaling); the viewer window appears:
M4_E2E=1 cargo test -p remote-desktop-app --test e2e -- --nocapture
```

The scenario: host start → Online; controller connect → host consent → accept
→ session live (real capture/encode/decode/present) → quality preset change
(asserted by the rebuilt encoder's bitrate) → monitor pick → off-aspect
viewer resize (swapchain must follow, F49) → focus-loss `AllKeysUp`
→ **disconnect by closing the viewer window** (F50; causes asserted: F53)
→ host back Online; asserts state transitions, presented-frame counts, and
diagnostics events. Without `M4_E2E=1` the test skips with a reason (no
display/GPU on CI). Evidence logs: `docs/reports/data/m4-e2e-20260925-run.log`
and `docs/reports/data/m4-e2e-20260925-fixpkg.log`.

## Settings & favorites

Local JSON under the app data dir (`%APPDATA%/space.deepflux.remote.desktop`):
`settings.json` (device id + presence token, display name, signaling base URL,
default quality/scale, onboarding-skip flag) and `favorites.json`. The
signaling URL defaults to the deployed service (`https://signaling.deepflux.space`,
accounts phase); an explicit empty string is the documented opt-out — the local
dev rig is `http://127.0.0.1:38013` (see `services/signaling/README.md`).

## Accounts & the synced computer list (post-MVP, ADR-003)

First run shows an onboarding card (Sign in / Create account, "Skip for now"
keeps the account-less behavior). The wire + crypto layers live in
`crates/protocol/src/account.rs` and `crates/node-runtime/src/account_{crypto,
remote}.rs`; this shell only composes them:

- **Registration** mints the per-user key material client-side (random DEK
  wrapped under a password-derived KEK), imports the current favorites as the
  initial roster, and uploads it encrypted. The service never sees a password
  or plaintext.
- **Login** fetches salts, proves the password via its scrypt image, unwraps
  the DEK in memory, and merges the server roster with the local encrypted
  cache (`roster.json`) — union by code, newest `updated_at_ms` wins, entries
  are never lost; favorites saved while signed out join the merge. The merged
  list is written back to `favorites.json` so the logged-out UI stays coherent.
- **Saved-account unlock**: the DEK cannot be unwrapped without the password,
  so a restart validates only the persisted session token and shows a
  one-field "Welcome back, @user" card; the roster stays encrypted until the
  password is re-entered.
- **Storage**: `account.json` (salts + wrapped DEK, no secrets), `roster.json`
  (AES-GCM ciphertext under the DEK), and the session token in the **Windows
  Credential Manager** (`credstore.rs`) — never plaintext on disk. The DEK and
  session live in memory only and are dropped on exit/logout.
- **Commands** (engine-independent; only "Add this computer" starts host
  mode, from the UI): `account_state`, `account_register`, `account_login`,
  `account_unlock`, `account_logout`, `computers_list`, `computer_add`,
  `computer_add_this`, `computer_remove`, `computer_rename`,
  `computers_presence`. Result DTOs are clean metadata — no tokens, no
  passwords, no ciphertext (asserted by `tests/ipc_surface.rs`).
- Unit tests drive register/login/merge/conflict/offline flows against an
  in-memory fake service (`src/account/tests.rs`); the network is never used.

## Installer

NSIS, per-user install (`installMode: currentUser`): one
`Remote Desktop_<version>_x64-setup.exe` per build. NSIS over MSI because the
app is a per-user desktop tool with no machine-wide registry/COM needs — NSIS
gives the smaller, faster, userscope install without elevation, matching the
"no accounts, local-only" MVP posture.

```bash
pnpm tauri build
# → target/release/bundle/nsis/Remote Desktop_0.1.0_x64-setup.exe
```

(The workspace shares one `target/` — src-tauri has no target dir of its own.)

## Keyboard

- `Ctrl+Shift+D` — toggle the diagnostics overlay (shell window)
- `F11` — toggle the viewer fullscreen (handled locally in the viewer, never
  forwarded to the host)
- `Esc` — clears the connect-code input
- All controls are reachable by keyboard (native buttons/inputs, focus rings).
