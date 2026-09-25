# M4 QA audit — Product shell (RD-011/RD-012)

Date: 2026-09-24 · Auditor: `rd-performance-qa` (read-only except this report)
· Tree audited: `e7c197d` (M4 `1bcc694` + lockfile) · Continues findings from
`docs/reports/m3-qa-audit.md` (F37–F47). Findings here start at **F48**.

## 1. Verdict

**PASS-WITH-FINDINGS.**

The M4 gate as written is met and fully reproducible: every gate command is
green on this machine (§2), the E2E re-ran clean end-to-end against a fresh
local signaling stack with a real native viewer window (my run: 840-class
capture, **446 presented frames**, focus-loss `AllKeysUp` round-trip,
auto re-online; the committed log's 456 is consistent), the installer
artifact exists at the claimed size, invariant 1 holds structurally across
every IPC surface I could walk (§4), and the state mapping is exhaustive on
both sides with no UI-invented states (§5).

The qualification: the gate's reduced form (command-layer drive, default
window geometry) systematically misses the **viewer-window input/render
surface** — and that surface carries three mechanical defects (F48, F49,
F50) that the user's UX-acceptance checkpoint will hit within the first
minute of a real session (resize the viewer, or close it, or control an
elevated window). None is a gate regression; all three are small patches in
one file. I recommend fixing F48–F51 **before** the user checkpoint so the
acceptance judges UX, not geometry bugs. The invariant-1 "asserted by
review + QA audit" clause is satisfied by this audit plus the existing
test, but the test itself is a partial tripwire (F52).

## 2. Gate reproduction (all re-run on the audited tree, 2026-09-24)

| Command | Result | Time |
|---|---|---|
| `cargo fmt --all -- --check` | clean | <1 s |
| `scripts/check.sh` (clippy `-D warnings`) | clean | 1.3 s (cached) |
| `scripts/test.sh` (cargo test --workspace + signaling TS gate) | all green; signaling headless contract matrix **21/21** (F41 fix verified: TS gate now wired into `scripts/test.sh`, incl. F42b/F42c/F45 regression cases) | ~35 s |
| `cd apps/desktop && pnpm run typecheck && pnpm run lint && pnpm test` | tsc clean, eslint clean, vitest **36/36** (mapping 19, reducer 6, components 11) | ~4 s |
| `M4_E2E=1 cargo test -p remote-desktop-app --test e2e -- --nocapture` | **PASS** — 20.8 s; controller verdict: connected → streamed → disconnected, `presented=446`, `diag_events=15`, `ended_causes=["User"]`; host online→session→online | 20.8 s |
| Installer artifact | `target/release/bundle/nsis/Remote Desktop_0.1.0_x64-setup.exe` = **6,330,427 bytes (6.3 MB)** — exists, matches the report | — |

E2E assertion check (audit task 1): `frames_presented > 50` ✓
(`e2e.rs:318`), `encoder_rebuilds >= 1` + describe contains `12000000` ✓
(`e2e.rs:294-302`), `input_all_keys_up_sent >= 1` on the controller +
`/input/all_keys_up >= 1` on the host ✓ (`e2e.rs:323-334`), **disconnect
cause: recorded but NOT asserted** — `verdict.ended_causes` is written by
`e2e_child.rs:399` and never checked by `e2e.rs` (F53). The report's §4.3
"disconnect | host cause Peer; controller copy user_disconnect" row
describes the log, not an assertion.

## 3. Audited-sound (checked and held)

- **Window topology / invariant 1 (architecture claim).** Verified
  end-to-end in code: the webview receives only
  `commands.rs::forward_event` outputs (string/number DTOs); the frame path
  (capture→encode→RTP→decode→swapchain) lives entirely in the engine's
  stage threads; no `canvas`, `img`, blob, or byte-array surface exists in
  `apps/desktop/src` (components render text/tables only). The Tauri shell
  holds no GPU handles; `EngineStatus.viewer_hwnd` is an opaque id.
- **Diagnostics snapshot path (audit task 2, aggregator side).**
  `node-runtime` stage threads emit schema-exact `CounterRecord`s into
  `TeeSink` (JSONL report + `DiagAgg`). `DiagAgg::ingest` reduces
  `FrameTiming` to per-stage rings (512 samples, ring-replaced), event
  markers to a 2 s fps window **capped at 16,384 with a drain to 8,192**,
  `QueueSample` to one latest-stat per queue kind, `LinkSample` to the
  latest struct, `ResourceSample` ignored. No `frame_ids` arrays, no
  unbounded growth, no payload retention — the 1 Hz `DiagSnapshot` is
  numbers + short strings by construction (`engine/diag.rs`). Frame-queue
  sampling keeps the F5 on-every-depth-change cadence (`FrameQueue::sample`
  on push/pop via the tee), so the overlay and the JSONL both see depth
  oscillation.
- **State mapping (task 3).** `HOST_VIEWS`/`CONTROLLER_VIEWS` enumerate all
  8+8 states; names byte-match `HostState::name()`/`ControllerState::name()`
  (`crates/session/src/host.rs:56`, `controller.rs:63`). The reducer never
  invents states (it casts machine names only); unknown future names
  degrade to a defensive "Unknown state" view with all actions disabled
  (tested). Disconnect copy exists for all 7 causes on both sides
  (Rust `disconnect_copy` tested over the full `DisconnectCause` list incl.
  `Rejected(reason)`; TS `disconnectCopy` tested over all 7 codes + fallback),
  with the direct-only hint on `timeout`/`transport_error` (M5 UX
  requirement). Push-vs-pull race: `StateChanged` pushes are droppable
  (bounded 512, `try_send`), but the hook's **1 Hz `engine_status` poll is
  authoritative** and reconciles `host_state`/`controller_state`/`session_id`
  (`useEngine.ts:137-148`, reducer `poll`), so "connected while the machine
  says otherwise" is bounded to ≤1 s of staleness — acceptable, note-level.
- **Viewer input queue.** Bounded 256, drop-oldest, counted
  (`viewer.rs::push`, unit-tested at the cap). `AllKeysUp{FocusLost}` is
  enqueued in-order on `input-reliable` behind already-queued events — the
  release cannot overtake a queued press. Alt-tab away triggers
  `WM_KILLFOCUS` (proven by the E2E probe); F11 fullscreen exit retains
  focus so no spurious release. Text joins as UTF-16 (surrogate pairs
  survive; unit-tested).
- **Process lifetime (task 5).** `EngineHandle::shutdown` sends `Shutdown`,
  joins the engine thread; engine `teardown()` order: stop resource-sampler
  flag → close transport → stop host pipeline (join capture/encode) → stop
  controller pipeline (join decode/present; viewer unsubclasses then
  destroys its window) → `all_keys_up(Disconnect)` on the input pump → join
  sampler. Shell-window close (`WindowEvent::Destroyed` in `lib.rs:28-38`)
  calls exactly this even mid-session. The app's `CodecPool`
  (`engine/pool.rs`) is the m2_rig F26 pattern verbatim: encoder/decoder/
  capture live for the process, sessions reset + force IDR instead of
  rebuilding; stage threads return instances to the pool on exit. Per
  session the app runs: engine loop (2 ms), event forwarder, resource
  sampler, + the session's 4 stage threads; between sessions only the first
  three — no zombie threads/handles observed across the state-flow tests
  (multiple engines in one process) and the two-process E2E.
- **Bounded queues everywhere on the IPC/command path** (invariant 3):
  commands 64 (typed error on full), events 512 (diagnostics droppable,
  state pull-readable), viewer input 256 (drop-oldest, counted),
  frame queues 1/1/2/1 with newest-wins — all surfaced in the snapshot.

## 4. Invariant-1 audit (task 2, detail)

**Holds in the audited code.** Every command argument (`ipc.rs`) is
strings/primitives; every result and event payload is a DTO of
ids/names/counters/short strings; the diagnostics snapshot is aggregate
(§3). The `FORBIDDEN_KEYS` walk (bytes/pixel(s)/surface/texture/sdp/
secret/candidate/input_event/payload/buffer, `contains`-matched) plus the
>32-array bound is a reasonable runtime tripwire.

**But the test is sample-based, not exhaustive** (F52):

- `tests/ipc_surface.rs` walks two **hand-authored samples**
  (`sample_diagnostics`, `sample_status`) and the disconnect copy. The
  `EngineEvent` enum — the actual Rust→webview surface serialized by
  `forward_event` — is never walked: no test constructs each variant and
  serializes it. A future variant (or a new field on an existing one)
  carrying, say, `preview: Vec<u8>` or `frame_ids: Vec<u64>` passes the
  suite unless someone also edits the samples — `Vec<u8>` serializes as a
  number array and is caught only by the >32 length bound *if the sample
  happens to be long*.
- Mitigations that exist: the struct-literal samples mean adding a field to
  `DiagSnapshot`/`EngineStatus` breaks the test's compilation, forcing a
  visit; the FORBIDDEN key list catches bad *names* regardless of size.
  So: byte-blobs under innocuous names at small sample sizes, and any new
  `EngineEvent` variant, escape today. Enforcement for those is
  convention-only.
- One false-positive risk: `monitors: Vec<MonitorDto>` would trip the >32
  bound on a >32-display machine (not realistic; rename the bound's
  purpose or exempt monitor lists when fixing).

**Conclusion:** invariant 1 is true of the code as of `e7c197d` (audited
surface-by-surface), the executable test adds real value for the two
biggest payloads, and the gap (F52) is a should-fix test-strengthening
patch, not a violation.

## 5. State-mapping audit (task 3, detail)

Held as claimed (§3). Two soft spots beyond F54/F57: (a) the
`engine://peer` online map is never reconciled by the 1 Hz poll — if a
`PeerOffline` push drops, a favorite can show online indefinitely (push
channel is the only source); low risk given the forwarder drains fast, but
the poll could carry it. (b) `disconnectCopy("rejected")` drops the
`RejectReason` the Rust side appends ("(Busy)"/"(Declined)") — the TS title
is generic by design, fine, just noting the intentional asymmetry.

## 6. Findings (F48–)

Severity labels: **blocking-for-UX-acceptance** (fix before the user's M4
checkpoint) / **blocking-for-M5** / **should-fix** / **note**.

### F48 — Viewer pointer coordinates are normalized over the window client rect, not the presented frame rect — blocking-for-UX-acceptance

`apps/desktop/src-tauri/src/engine/viewer.rs:476-488` (`normalize`) maps
`WM_MOUSEMOVE` client coords over the **whole client area**, but the
renderer composites the frame into a **destination rect**:
`render-windows/src/renderer.rs:250-263` — Fit letterboxes via
`fit_rect` (centered, aspect-preserved; empty bars when aspects differ)
and 1:1 draws at origin cropped. The mapping is exact only when the
destination rect equals the client rect (Fit with matching aspect —
accidentally true for the default 1280x720 window showing a 16:9 remote,
which is why the E2E and the report missed it).

Quantified (host 3840x2160 = this machine's primary, viewer resized to
1600x1000 client): `fit_rect` → video at (0, 50, 1600, 900). A click at the
video's top edge (client y=50) should be remote y=0; `normalize` sends
3279/65535 → remote **y≈108**. Every click is vertically offset 0→108 px.
In 1:1 with a smaller window (1280x720 view of a 4K remote) a click at
client (640,360) lands at remote **(1920,1080)** — 3× off. After F49's
stale-swapchain effect the error compounds (displayed content is the old
buffer size stretched; `normalize` uses the fresh client size).

Fix: the present thread already knows the last frame size and client size;
expose the current destination rect (or last frame w×h + scale mode) from
the renderer/`ViewerCtl` and normalize as
`(x − dx) / (dw − 1) → 0..=65535` (clamp + drop clicks inside letterbox or
outside the 1:1 crop). Repro: connect to a 4K host, resize the viewer to a
non-16:9 client, click corners; or switch to 1:1 and click center.

### F49 — Viewer resize is never forwarded to the renderer (F18 wiring dropped vs the m2_rig) — blocking-for-UX-acceptance

`viewer.rs::pump_and_present` calls `window.pump()`, scale, fullscreen,
present — but never `window.take_resized()` / `renderer.resize()`. The
m2_rig does exactly this (`crates/node-runtime/examples/m2_rig.rs:1026-
1028, 1037-1039`), and `PresenterWindow::take_resized`'s doc
(`render-windows/src/window.rs:142-146`) says the presenter **must** call
`D3D11Renderer::resize` "or the swapchain goes stale". Consequence: after
any user resize the swapchain stays 1280x720 and DWM stretches it (visible
aspect distortion in Fit, blur in 1:1), `fit_rect` keeps computing against
the stale `target_size`, and — with F48 — input mapping degrades further.
Repro: connect, drag the viewer window to 2× size; observe stretched video.

### F50 — "Viewer window closed → disconnect" is dead-wired — blocking-for-UX-acceptance

`engine/mod.rs:1092-1100` implements the report's §1.1/§4.3 behavior
(viewer closed by the user ⇒ `controller_disconnect`), gated on
`ObserverFlags.viewer_closed` — **which nothing ever sets** (grep: declared
`observer.rs:37`, read in `apply_flags`, written nowhere). The present
thread instead sets `ControllerPipeCounters.window_closed`
(`controller.rs:244, 273, 287`) — a counter the engine loop never reads.
Net: closing the viewer window mid-session leaves the session fully live —
decode continues, `q_dec_pres` (cap 1) silently drops every frame,
`frames_presented` freezes, the shell still says "Session live / The viewer
window shows the remote desktop", and the user must find the shell's
Disconnect button. The report's architecture claim is currently untrue.
Fix: in the engine loop (e.g. where `viewer_facts()` is computed), map
`pipeline.counters.window_closed.load()` → the observer flag (or directly
`controller_disconnect`). Repro: connect two engines (state_flow harness or
E2E topology), close the native viewer window; observe
`controller_state == Connected` persisting and frames decoding.

### F51 — UIPI blocks are invisible to the user (M2's `BlockedByUipi` never surfaces) — should-fix (recommend before the UX checkpoint)

`InputError::BlockedByUipi` is counted by the pump as `inject_errors`,
which reaches `DiagSnapshot.input.inject_errors` (`observer.rs:130`) — but
`DiagnosticsOverlay.tsx:99-105` renders only
applied/stale/gaps/all-up/held, dropping `inject_errors`, and no
`EngineEvent::Error` is emitted on first block. The risk register calls
UIPI "Certain" (elevated/UAC foreground ⇒ input silently does nothing).
The UX checkpoint will likely foreground an elevated window at some point;
without a hint the failure looks like a broken product. One-line overlay
addition + a rate-limited Error event on the first `BlockedByUipi`.

### F52 — `ipc_surface` test is a partial tripwire, not an exhaustive surface proof — should-fix (M5)

See §4. Strengthen by (a) constructing one instance of **every**
`EngineEvent` variant (worst-case-ish: an array-valued field populated
beyond 32) and walking each, (b) walking every command-argument DTO, (c) a
comment pinning that new variants must be added to the walk (the compiler
won't force it). This converts most of the convention-only enforcement
into the executable form the gate description claims.

### F53 — The E2E does not assert the disconnect cause (report overstates) — should-fix

`e2e.rs` records `verdict.ended_causes` (written by `e2e_child.rs`) but
never asserts it; the report's evidence table lists "host cause Peer;
controller copy user_disconnect" as if checked. My run's status shows
`ended_causes: ["User"]` — correct — but a regression to a wrong cause
would pass. One line: assert the controller's cause is `User` and the
host's contains `Peer` after the scripted disconnect.

### F54 — Controller "Stop" affordance is dead and asymmetric — note

The controller machine has no deregister event (no Online→Idle; by design
per `docs/protocol/state-machines.md`), so `controllerView("Online").can.stop
= true` is rendered nowhere (`ControllerPanel` never uses `can.stop`) and
the `controller_stop` command only *prevents re-registration after the next
session end* (`engine/mod.rs:840-844`) — while the host's Stop truly stops.
Either hide the flag or file a machine-level decision (deregister-on-stop)
with the architecture owner. Not a bug today (no button exists), but a
mapping-table claim (`mapping.ts` TRANSITION_TRIGGERS controller.stop) that
does not correspond to a reachable UI action.

### F55 — App quit mid-session sends no wire goodbye; peer key-safety waits on transport-failure detection — should-fix

`Engine::teardown` (`engine/mod.rs:1636-1652`) closes the transport without
sending `WireMessage::Disconnect` or `InputEvent::AllKeysUp{Disconnect}`,
even when a session is live. The graceful UI path (`EngineCmd::Disconnect`)
does send both first. On shell-window close with a session active, the
controller's held keys stay injected on the host until the host's
`TransportFailed` detection fires (ICE/DTLS failure — seconds). Cheap fix:
in `teardown`, if either machine is in-session, best-effort
`send_wire(Control, Disconnect)` + `AllKeysUp` before `close_transport`.
Repro (rig): connect, hold a key via scripted input, kill the controller
process; observe the host's `held` counter non-zero until the failure edge
clears it.

### F56 — CR-1 leak re-quantified on this machine: +13.9 MiB working set / +28.1 MiB private, +~1 thread, +~34 handles per encoder rebuild; linear, no plateau — blocking-for-M5 (via CR-1), M6 soak item

Fresh measurement (audit task 6), `cargo run --release -p node-runtime
--example leak_probe -- --phase encoder --iters 10` (create MfEncoder
1920x1080@60/8 Mbps → 1 encode → drop):

```text
iter 0: ws +36.2 MiB priv +51.7  threads 35 handles 403
iter10: ws +210.6 MiB priv +405.2 threads 49 handles 844
```

Per-iteration averages (iters 1→10): ws **+13.9 MiB**, private **+28.1
MiB**, +1.1 threads, +33.6 handles — straight line, no plateau. The m4
report's "~14 MiB per quality change" is the working-set slope; private
bytes leak at **2×** that. Triage: today the trigger is a user action
(bounded); M5's congestion/bitrate work (PLAN M5: "bitrate/FPS/resolution
controls") must not implement adaptation via rebuilds — CR-1 (live
`ICodecAPI` reconfiguration) is therefore **blocking-for-M5**, not merely
M6 hygiene. M6's soak must add a preset-hammer item (e.g. 100 preset
cycles; with the current leak that alone is ~1.4 GiB WS / ~2.8 GiB private
— the 60-min soak would fail on memory grounds without ever touching
video).

### F57 — Favorites "Offline" dot states more than the app knows — note (CR-4 acknowledged; copy should soften)

`Favorites.tsx:108-112` renders a definite Offline dot/title whenever no
session-scoped `PeerOnline` event names the code. A machine can be online
and controllable while showing "Offline" (the service exposes no presence
query — CR-4). The m4 report discloses the scoping honestly; the residual
issue is the UI's wording: label it "status unknown" (or render the dot
only when known-online) until CR-4 lands. Also note the peer-online map is
push-only (§5a): a dropped `PeerOffline` sticks "online" — reconcile via
`engine_status` when adding CR-4.

### F58 — Notes (bundle)

(a) Channel-queue gauges are sampled 1 Hz only (`sample_link_stats`); the
schema also asks for on-depth-change while non-empty — the JSONL misses
sub-second channel bursts; fine for M4's overlay, tighten in M5.
(b) Auto re-online reuses `caps_cache` without re-enumerating monitors and
without re-emitting `HostCaps` — a display plugged in between sessions
shows a stale picker until the next explicit Host start.
(c) The encode thread returns a **device-lost** encoder to the pool
(`host.rs:358`); the next session reuses a dead MFT. Device-loss edge; have
the thread drop instead of pool on `DeviceLost`.
(d) `WM_SETFOCUS` discards a queued `AllKeysUp` from the immediately
preceding kill-focus (`viewer.rs:334-341`); the drain window is ~2 ms so
it is rare, but keys held across a kill+refocus blur stay held on the host
until the next release — consider sending the release anyway (the host pump
tolerates redundant all-up).
(e) `finished_host_counters`/`finished_ctrl_counters` grow one small Arc
per session — unbounded count, negligible size; note for the M6 soak.
(f) `tauri.conf.json` sets `"csp": null` — fine for a bundled-asset control
surface, but set a restrictive CSP before any release build ships.
(g) The ipc walk's >32-array bound would false-positive a >32-monitor
`monitors` list (see F52c).

## 7. CR triage (audit task 6)

| CR | Assessment | Milestone |
|---|---|---|
| CR-1 live encoder reconfiguration | **Agree, promote to blocking-for-M5.** Leak re-measured at +13.9 MiB WS / +28.1 MiB private / +1 thread / +34 handles per rebuild, linear (F56). Any M5 congestion adaptation that rebuilds converts a user-bounded leak into a throughput-driven one. M6 soak adds the preset-hammer item regardless. | M5 (+M6 soak item) |
| CR-2 move viewer input capture unsafe into a `*-windows` crate | **Agree.** It is the only AGENTS unsafe-placement deviation (sanctioned list does not include `apps/desktop`), the unsafe is reviewed and failure-handled, and F48/F49's fixes touch the same file — do them together behind the narrow `PresenterInput` trait. | M5, early (with F48/F49) |
| CR-3 export display enumeration from capture-windows | **Agree.** `engine/displays.rs` is a second Win32 unsafe copy and a second source of truth for monitor identity (ids do match today: Win32 device names are what `DxgiCapture`/`SelectMonitor` consume, E2E round-tripped `\\.\DISPLAY5`). Drift risk only. | M5, should-fix |
| CR-4 presence-query op | **Agree, optional but cheap;** additive per the report. Until then fix the misleading copy (F57). | M5, optional |
| CR-5 `sender_role` envelope field | **Agree as nice-to-have**, consistent with the M3 audit's blessing of the learning table + its one-lost-accept caveat. | M5, optional |

## 8. Residual-manual honesty check (audit task 7)

The report's four-item manual list is accurate and I found **no silently
skipped gate work**: gates/E2E/installer all reproduce; the webview wiring
is genuinely component-tested + command-layer-identical; input feel is
genuinely manual (E2E uses the recording sink by design, single-machine
safety). Three accuracy caveats: (1) F50 — the report's §1.1/§4.3 claim
that viewer-close disconnects is dead code, i.e. one described behavior
does not exist (worse than manual); (2) F53 — one evidence-table row
(cause/copy) is unasserted; (3) F48/F49 are deterministic geometry defects,
not "feel" — they will surface in the manual UX pass as objective bugs, so
the checkpoint should happen after fixing them, else it will fail for the
wrong reasons. Favorites online-state scoping is disclosed (F57 covers the
remaining copy issue).

## 9. Reproduction index

```bash
# Gates
cd C:/Remote.deepflux.space
cargo fmt --all -- --check && scripts/check.sh && scripts/test.sh
cd apps/desktop && pnpm run typecheck && pnpm run lint && pnpm test

# E2E (real viewer window; ~21 s)
M4_E2E=1 cargo test -p remote-desktop-app --test e2e -- --nocapture

# F56 leak quantification (~30 s)
cargo run --release -p node-runtime --example leak_probe -- --phase encoder --iters 10

# F48/F49 (needs a second engine or the E2E topology): connect, resize the
# viewer off-aspect (e.g. 1600x1000 client for a 16:9 remote), click the
# video's top edge — the remote cursor lands ~100+ px low; then resize to
# 2x and observe the stretched (stale-swapchain) picture.

# F50: with the E2E children running (or two state_flow engines with
# real_pipelines), close the native viewer window: controller_state stays
# Connected, frames keep decoding, presented freezes.

# F51: host foreground = elevated window (e.g. Task Manager "Run new task"
# elevated), send keys from the controller: nothing injects, no UI signal;
# snapshot.input.inject_errors climbs (inspect via engine://diagnostics).

# F55: connect, hold a key (scripted input), kill the controller process;
# host's input.held > 0 until the transport-failure edge clears it.
```

## 10. Recommendation

**PASS-WITH-FINDINGS.** Tag-ready once the report is corrected for F50
(the described behavior does not exist) and F53 (unasserted evidence
claim); both are documentation-honesty one-liners. Before the user's UX
checkpoint, land F48 + F49 + F50 (one file, `viewer.rs` + one flag wire,
plus the renderer-rect exposure) and preferably F51 (one overlay line + one
rate-limited error event) — otherwise the checkpoint will judge geometry
bugs, not UX. F52 (test hardening) and F55 (teardown goodbye) should ride
into M5 with CR-2; CR-1 is blocking-for-M5 with the F56 numbers as its
justification; F54/F57/F58 are tracked notes.
