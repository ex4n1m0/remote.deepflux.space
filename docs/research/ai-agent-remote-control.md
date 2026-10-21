# Deep study: AI-agent control of the remote machine

**Date:** 2026-10-20
**Status:** research study — not a committed plan. Nothing here changes MVP
scope, wire formats, or invariants without an ADR.
**Question:** Can a cloud or local model — driven by the AI agent on the
user's (controller) machine — perform actions on the remote (host) machine
through DeepFlux, and what would it take to build that well?

---

## 1. TL;DR verdict

**The idea is sound, timely, and unusually well-matched to this codebase.**
The market validated it in 2026: HopToDesk shipped built-in MCP agent
support (Mar 2026), Jump Desktop ships a beta agent CLI, TeamViewer runs an
autonomous IT-support agent, and RustDesk — the open-source leader — has
only an open proposal. The engineering pattern is standardized
(screenshot → model → synthetic input → settle → repeat), and DeepFlux
already owns every piece of the plumbing: normalized-input injection, a
bounded binary side-channel precedent, a sanctioned CPU frame-readback
precedent, capability negotiation with a free flag bit, and a consent flow.

**Recommended v1 architecture** (§5): an *agent driver on the controller*
that reuses the existing `InputEvent` wire path unchanged, plus an *MCP
server (stdio, `rmcp`)* exposing `screenshot`/`click`/`type`/`key`/`scroll`
so the user's local agent (ZCode, Claude Code, Cursor, Copilot…) drives the
remote machine as if it were a tool server. **Zero wire-format changes**
(no `WIRE_VERSION` bump; one additive `FeatureFlags` bit for host consent
UX). The main costs are model reliability and safety engineering, not
transport.

**Why DeepFlux specifically wins at this:** the agent loop can run entirely
on the controller — cloud API or a local VLM on the user's own GPU — while
frames and input stay on the P2P link. No vendor cloud ever sees the remote
machine's screen. HopToDesk and Jump Desktop both route through their
accounts/relays; RustDesk hasn't shipped it. That is a real, defensible
niche: *private, open, agent-controllable remote desktop*.

---

## 2. The idea, precisely

Two distinct user loops, both implied by "I give instructions to my
computer's AI agent to perform actions on the remote machine":

1. **Supervised AI control (primary).** The user watches the live viewer
   window (or walks away and checks in) while an agent executes a task on
   the host: "open the build folder on my office PC, zip the logs from
   yesterday, put the archive in Dropbox." Human can intervene at any time.
2. **Local-agent tool use (the workflow the user literally described).**
   The user is already talking to a coding/assistant agent on their machine.
   The remote machine appears to that agent as MCP tools — screenshot,
   click, type — backed by the DeepFlux P2P session. The agent plans; the
   remote machine obeys.

Both loops share one engine: a decision loop that observes the remote
screen and emits input events. They differ only in who fronts it (our UI
vs. an external agent over MCP).

Out of scope for v1: fully unattended autonomous operation, agent processes
running on the host itself, and TURN/relay paths (invariant 4 still holds —
see §8 for the WAN caveat).

---

## 3. Prior art and state of the art (as of 2026-10)

### 3.1 Capability benchmarks

| Benchmark | What it measures | Human | Best agents |
|---|---|---|---|
| OSWorld / OSWorld-Verified (369 real desktop tasks) | general GUI control | ~72% | Anthropic computer use 61.4% (Sep 2025); Opus 4.5 system card 66.26% (Nov 2025); third-party trackers claim 82–86% for 2026 frontier models (unverified — see sources) |
| OSWorld 2.0 (108 long-horizon workflows) | hour-long multi-app tasks | n/a | best ~44% |
| WindowsAgentArena (154 Windows tasks, MSR) | Windows-specific control | 74.5% | Navi 19.5% (original paper); UI-TARS-2 50.6% (Sep 2025) |
| AndroidWorld / WebArena | adjacent | — | UI-TARS-2 73.3% Android |

Three honest readings for us:

- **Generic desktop control got good fast** — frontier agents now sit at or
  above the human baseline on short benchmark tasks.
- **Windows is the weak spot.** Classic Win32 apps, Office, VLC remain hard;
  the Windows-specific gap is still ~24 points for the best open model.
- **Benchmarks overstate real-workflow reliability.** A widely-cited 2026
  analysis: agents "hit 85% on OSWorld but fail 80% of real workflows."
  Long-horizon tasks collapse (44% on OSWorld 2.0). This is why §8 makes
  human supervision the default and v1 positions the feature as *assistive
  automation*, not autonomy.

### 3.2 Cloud computer-use platforms

- **OpenAI:** Operator (Jan 2025) and Atlas (Oct 2025) are deprecated as
  standalone products (by May 2026); the CUA capability lives on inside the
  agent API stack. API computer use remains "hit or miss" per developer
  sentiment. Baseline: 38.1% OSWorld at debut, ~61% by early 2026.
- **Anthropic:** computer use is a mature API tool; Claude Cowork runs it
  on the user's own desktop with **no sandbox** (their docs say so
  explicitly) plus a background "Dispatch" mode. Opus 4.5: 66.26%
  OSWorld (P@1, avg@5).
- **Google:** Gemini computer-use API continues (Project Mariner lineage).
- **Microsoft:** Copilot Vision / agent modes for Windows apps (consumer
  local-control angle; not a remote-control product).

### 3.3 Remote-desktop products with agent support (direct competitors)

| Product | What shipped | Agent placement | Transport trust |
|---|---|---|---|
| **HopToDesk 1.45.10** (Mar 2026) | Built-in MCP server, 26 tools: screenshot, click, type, `connect_to_peer`, clipboard, file read; `run_command` gated behind enterprise tier | Local-only (127.0.0.1; agent co-located with the app) | Vendor relay/account |
| **Jump Desktop** (beta) | `jump-cli mcp` + Mission Control supervision dashboard; ≤8 sessions; privacy mode; **human types passwords, never the agent**; screenshots auto-deleted at session end; revocable viewer tokens | CLI on agent's machine, cloud account sign-in | E2E-encrypted but account-mediated |
| **TeamViewer** | "Tia" autonomous IT-support agent (Nov 2025); MCP interfaces for TeamViewer ONE (initiate sessions, retrieve logs); ServiceNow alliance (Jul 2026) | Enterprise cloud | Vendor cloud |
| **RustDesk** | Nothing shipped — community proposal #16246 (Sep 2026) for exactly this design (agent observes/operates while human watches) | — | Self-hosted |
| Generic bridges | mcp-vnc, VNC-MCP, WinRemote (40+ tools), Conduit Desktop (RDP/VNC automation), windows-mcp family | Local or VNC-based | VNC/RDP stack |

Design patterns worth stealing (all three shipped products converge on
them): localhost-bound MCP with token auth; confirmation annotations on
destructive tools; supervision UI with instant human takeover; scoped
tokens that can connect but not reconfigure; ephemeral screenshots.

### 3.4 Cost and latency of the agent loop

- Screenshot cost: **~1,000–1,800 input tokens each** (Anthropic docs);
  high-resolution modes up to ~4.2k tokens. Screenshots accumulate in
  context every step.
- Task shape: **~53 steps and ~551k tokens per task on average** vs ~8
  calls / 12k tokens for the same task via structured APIs — **~45× cost
  multiple** (Reflex.dev measurement).
- Per-step wall time: several seconds (model inference dominates; capture
  and injection are milliseconds). A typical task runs 2–10 minutes.
- Consequence for us: **DeepFlux's ≤150 ms pipeline budget is irrelevant to
  the agent loop.** The remote-desktop transport is essentially free
  compared to the model; the agent can sample at 0.5–2 fps and still be
  bottlenecked by inference. This inverts our usual perf discipline: for
  the agent path we optimize *token count per screenshot* (downscale,
  crop), not latency.

### 3.5 Local models

- **UI-TARS-2** (ByteDance, open weights, Sep 2025): 47.5% OSWorld, 50.6%
  WindowsAgentArena — the strongest open GUI agent; Qwen2.5-VL-derived,
  small grounding variants down to ~675M for low-resource setups; community
  reports it works noticeably better on Ubuntu than Windows and is
  prompt-sensitive.
- **Qwen-UI-Agent** technical report (Jul 2026) and Microsoft's
  coordinate-free **GUI-Actor** grounding line: the local-model ecosystem is
  active and improving.
- Practical takeaway: **local works today for supervised, simple Windows
  tasks and maximizes the privacy story; cloud models are needed for
  reliability on complex tasks.** Supporting both behind one provider trait
  is cheap for us (both are OpenAI-compatible-ish HTTP).

### 3.6 MCP tooling

The official Rust SDK **`rmcp`** (modelcontextprotocol/rust-sdk) is a Tier-1
SDK with stdio transport — the MCP bridge can live natively inside our Rust
engine, no Node sidecar, no new runtime process model.

### 3.7 Safety research every adopter cites

- **Visual prompt injection is real:** VPI-Bench (306 cases; webpages embed
  malicious visual instructions), MIRAGE, EVA red-teaming. A screenshot is
  untrusted input; anything the remote screen displays can attempt to
  steer the agent.
- **Defenses are immature:** SnapGuard (screenshot-level injection
  detection, Apr 2026), probing frameworks (ICON), isolation architectures.
  OWASP ranks prompt injection the #1 LLM risk (LLM01:2025). OpenAI
  published agent-injection-resistance design guidance (Mar 2026).
- Shipped products' actual answer: **human supervision + scoped permissions
  + confirmation gates**, not detection. Ours should be the same.

---

## 4. What we already have (repo grounding)

Every load-bearing integration point exists today:

- **Input wire contract:** `InputEvent` (`crates/protocol/src/wire.rs:120-152`)
  — `MouseMove` (u16 normalized coords), `MouseButton`, `Wheel`, `Key`
  (scan codes), `Text` (code points), `AllKeysUp`. Coordinates are
  normalized 0..=65535 over the selected monitor, matching `SendInput`
  absolute mode (`wire.rs:33-35`). An agent that can name (x, y) in
  normalized space and text can already drive the host through the
  **existing** `input-fast`/`input-reliable` channels — no new input
  variants, no `WIRE_VERSION` bump.
- **Controller input path to imitate:** `WindowInputCapture` →
  `PresenterInput` trait (`crates/input-windows/src/capture.rs:96-109`,
  bounded drop-oldest queue cap 256 at `capture.rs:44`) → `ViewerCtl::drain_input`
  (`apps/desktop/src-tauri/src/engine/viewer.rs:108-119`) → `to_wire_events`
  (`viewer.rs:271-364`, per-channel monotonic `seq`) → `Engine::drain_viewer_input`
  (`engine/mod.rs:1497-1509`) → `Node::send_wire` (`crates/node-runtime/src/node.rs:978-989`).
  An agent driver is a second producer of the same events.
- **Frame access precedent:** decoded frames are GPU-resident
  `DecodedFrame`/`FrameSurface` (`crates/codec-windows/src/lib.rs:99-105`,
  `crates/frame-surface/src/lib.rs:276-309`), and there is already a
  sanctioned CPU readback — `frame_surface::readback` (`frame-surface/lib.rs:573`)
  — used by diagnostics and the software-encoder fallback, policy-scoped in
  module docs. That is the exact mechanism a 0.5–2 fps agent screenshot tap
  reuses. **No PNG/JPEG encoder exists anywhere in the workspace yet** —
  net-new dependency (WIC or `image`), worth its own review.
- **Bounded binary side-channel precedent:** cursor shapes ride
  `Channel::Cursor` as raw bytes, newest-wins `LatestSlot`, 1 MiB cap
  (`wire.rs:214-231`, host side `engine/host.rs:288-294`, engine send
  `engine/mod.rs:1427-1431`). An agent-status/backpressure channel would
  copy this pattern.
- **Capability negotiation:** `FeatureFlags` bitmask
  (`crates/protocol/src/capabilities.rs:61-74`) — next free bit is **1<<4**;
  negotiated in JSON at signaling (`Register`/`ConnectRequest`,
  `signaling.rs:142-146`) and re-negotiated in binary on the direct path
  (`Hello`/`HelloAck`, `wire.rs:60-64`). A new bit is additive within
  `SIGNALING_PROTOCOL_VERSION = 1` per the JSON additive-fields rule
  (AGENTS.md wire-format policy); peers that don't know the bit simply
  don't set it.
- **Consent flow:** `Node::user_accept_consent` / `prompt_consent` observer
  (`node.rs:326-334`, `:85`) → `EngineEvent::ConsentRequested`
  (`engine/observer.rs:148-161`) → Tauri `consent_accept`/`consent_reject`
  commands (`commands.rs:502-509`). An "AI-controlled session" consent mode
  and host-side banner hang directly off this pair plus the negotiated
  flag.
- **Eval rig already drives input programmatically and asserts outcomes:**
  `m2_rig.rs` scripts input bursts through the chaos injector and the host
  `RecordingSink` asserts applied events, dedup, staleness, and final
  position (`m2_rig.rs:2737-2790`, `:605-632`, summary `:3105-3117`);
  `e2e_child.rs` drives the full engine through `EngineCmd`. This is 80% of
  an agent acceptance harness.
- **Diagnostics:** counter kinds and the `CounterRecord`/`PerfSink` emission
  pattern (`docs/perf-counter-schema.md`, `node-runtime/src/metrics.rs:300-311`)
  extend naturally to agent counters (steps, tokens, screenshot age,
  journal size).
- **Numbering:** highest backlog ID is RD-014; next ADR is ADR-004; new
  work would be RD-015+ (this doc proposes RD-015–RD-019).

---

## 5. Architecture options considered

### Option A — controller-side AI driver (the engine) ✅ adopted

The agent runs on the controller machine. Observation: tap the latest
decoded frame (post-decode, pre/at-present — the `q_dec_pres` handoff in
`engine/controller.rs:254-320` is the natural vantage), `readback` →
downscale (e.g. ≤1600 px long edge) → PNG/JPEG encode, served from a
`LatestSlot` at agent-requested rate. Action: translate model output into
the same `InputEvent`s the human viewer emits (including `seq` assignment
and channel routing, mirroring `to_wire_events`). Model I/O behind a
provider trait: cloud (Anthropic/OpenAI computer-use-style APIs) or local
(OpenAI-compatible endpoint hosting UI-TARS/Qwen-VL on the controller GPU
or LAN).

- Host changes: **none for input** (it cannot distinguish agent from human
  input at the wire level — which is the point); consent UX/banner rides
  the negotiated `AI_SESSION` flag.
- Protocol changes: none on the data channel; one additive `FeatureFlags`
  bit on signaling.
- Failure containment: agent rate is bounded by the same queues; a runaway
  agent hits the drop-oldest policy exactly like a jittery human hand.

### Option B — MCP bridge (the front door) ✅ adopted (composed with A)

A stdio MCP server (`rmcp`, official Tier-1 Rust SDK) hosted by the desktop
app — or a small headless binary composing the same engine — exposing
tools: `remote_screenshot`, `remote_click{x,y}`, `remote_type{text}`,
`remote_key{name}`, `remote_scroll{dx,dy}`, `session_status`,
(optionally `session_connect{device}`). The user's local agent discovers it
like any MCP server. This is precisely the workflow in §2.2 and precisely
what HopToDesk shipped — but ours is backed by a P2P, account-optional,
no-relay link.

- HopToDesk's design constraints (localhost-only binding, token auth in a
  discovery file, confirmation annotations on dangerous tools) are proven
  and should be copied; their enterprise-gated `run_command` says the
  market prices remote shell as the scary feature — we keep v1
  pixels-and-input only (§8).

### Option C — agent process on the host (headless) ❌ deferred

Run the model/agent on the remote machine itself; remote desktop becomes
supervision. Rejected for v1: different install footprint on the machine
you're trying to keep clean, worse security posture (agent code executes
where the data lives), no reuse of our input pipeline, and it doesn't match
the user's stated workflow (agent stays on their machine). Worth revisiting
as a future host-side "headless agent" mode since the engine composes the
same crates.

### Option D — UIA/accessibility side-channel hybrid ❌ deferred

Microsoft's UFO line shows UI Automation trees boost Windows agents
significantly over pixels alone. But it needs a new data channel, leaks
structured content (privacy review), and multiplies surface area. v1 stays
pixels-only, matching every shipped competitor's v1. Revisit if Windows
reliability is the binding constraint.

### Composed v1 (recommended)

**A as the engine, B as the front door.** The MCP tools and (optionally
later) our own chat UI are both thin fronts over the same driver: tap →
model → `InputEvent`. That gives the user both loops of §2 from one
implementation.

---

## 6. Protocol and invariant impact (ADR-004 material)

| Surface | Change | Version impact |
|---|---|---|
| `WireMessage` / `InputEvent` | none — agent reuses existing variants | no `WIRE_VERSION` bump |
| Signaling `FeatureFlags` | add `AI_SESSION = 1<<4` (`capabilities.rs:74` next bit) | additive within `SIGNALING_PROTOCOL_VERSION = 1` |
| New binary paths | PNG/JPEG encode of readback frames (controller-local); optional agent-status records in diagnostics | local only, no wire impact |
| Data channels | none new in v1 (cursor channel pattern reserved for future agent-status) | none |

Invariant tensions that ADR-004 must resolve explicitly:

1. **Invariant 1 (no frame bytes through JSON/IPC) vs. the MCP screenshot
   tool.** The tool returns a PNG over stdio JSON-RPC to a *local, explicitly
   authorized* agent process. This must be written as a scoped exception —
   like the M2 F33 unsafe exception for `node-runtime` — not a quiet
   erosion: low-rate (≤2 fps), opt-in per session, host-consented,
   never through Tauri IPC or React, never on the real-time video path.
   The real-time pipeline remains untouched.
2. **Invariant 6 (input never logged) vs. the action journal.** Supervised
   AI control needs an audit trail of what the agent did. Resolution:
   journal records action *intents and outcomes* (event kind, coordinates,
   step id, model reasoning reference) but redacts `Text` payloads —
   mirroring the existing hand-written `Debug` redactions
   (`wire.rs:168-191`) and the `SessionToken`/`SessionSecret` patterns.
   New agent-carrying types follow the redaction rule from day one.
3. **Invariant 2 (control-plane scope) is untouched**: screenshots, model
   calls, and the MCP server are all controller-local; signaling still
   carries only envelopes. The model provider is the one new data sink —
   cloud providers see screenshots by design; the local-model path exists
   precisely so privacy-critical users never make that trade.

---

## 7. Performance and cost analysis

- **Transport is free; the model is the budget.** End-to-end our pipeline
  adds ≤~150 ms per step (readback + encode + P2P roundtrip + injection) —
  noise next to multi-second inference. No new perf budget is needed for
  the agent path; instead add counters (`agent_step_ns`, `screenshot_age_ns`,
  `steps`, `tokens_in/out`) per the perf-counter schema so cost is
  measurable per session.
- **Screenshot economics:** encode ≤1600 px long edge JPEG (~100–200 KB);
  ~1–1.8k tokens each at Claude-class tokenization. Context management
  (crop-to-region after the first full shot, drop stale history) is the
  lever that keeps tasks in the $0.5–2 cloud range instead of $5+.
  Budget rule of thumb from the literature: **~53 steps / ~551k tokens /
  several minutes per realistic task**; plan step budgets (e.g. default cap
  100 steps, configurable) and an idle-overflow abort.
- **Local model path:** UI-TARS-2-class weights on the controller's GPU
  (or a LAN box behind an OpenAI-compatible endpoint) → marginal cost ~0,
  full privacy, lower success rate on Windows (§3.5). Marketing-wise this
  is the headline: *the screen never leaves your machines*.
- **Soak implications:** agent sessions are long by construction; the
  existing 60-minute soak standard applies unchanged, plus a new acceptance
  criterion — no context/queue/journal growth proportional to steps
  (journals rotate, bounded).

## 8. Safety and security design (v1 requirements)

1. **Consent & signaling.** Host sees a distinct "AI agent wants control"
   consent (new flag bit) and a persistent banner while an AI session is
   live. Reject paths reuse `RejectReason`. Consent is per-session.
2. **Supervision by default.** v1 requires the viewer window to be alive;
   agent pauses (does not abort) on host-side local input — the host user
   always wins the pointer. Host-side panic hotkey kills agent control
   instantly (teardown only the agent producer, not the session).
3. **Hard platform limits that are actually safety features** (document,
   don't fight): non-elevated host cannot inject into elevated windows
   (UIPI); UAC secure desktop and the lock screen are unreachable. The
   agent cannot escalate privileges through us.
4. **Prompt injection posture.** The remote screen is hostile input: task
   prompts must be scoped, no secrets in agent context, credentials typed
   by the human (Jump Desktop's pattern — agent never sees passwords).
   Detection (SnapGuard-class) is future work; v1 relies on supervision +
   bounded actions.
5. **No remote shell in v1.** Pixels and input only — same line HopToDesk
   drew (their `run_command` is enterprise-gated). An opt-in exec channel
   would be its own ADR.
6. **Action journal (redacted per §6.2) + step budget + rate limits.**
   Reuse `INPUT_QUEUE_CAP` drop-oldest semantics; the bounded queue already
   protects the host from a spinning agent.
7. **WAN caveat:** no TURN (invariant 4) means agent control inherits the
   existing direct-ICE reachability constraint; on hard NATs the feature
   needs the same conditions as human remote control. Fine — same
   product boundary as today.

---

## 9. Reliability expectations (honest)

With a frontier cloud model: short Windows tasks (launch app, click
through a dialog, copy a file via Explorer) succeed reliably; multi-app
long-horizon tasks fail often (§3.1). With local UI-TARS-class models:
simple tasks, best effort. Position the feature as **supervised assistive
automation with an audit trail**, and set the acceptance bar accordingly:
e.g. ≥80% success on a 15-task scripted suite with a cloud model, ≥50%
with the reference local model, zero safety-gate violations (journal
review) in both.

## 10. Competitive positioning

- vs **HopToDesk:** they were first to ship MCP-in-app (Mar 2026) but the
  agent sits on the machine running the client and sessions traverse their
  infrastructure; no local-model story, closed source.
- vs **Jump Desktop:** strong supervision UX (steal their Mission Control
  and human-types-passwords ideas), but cloud-account-mediated.
- vs **TeamViewer Tia:** enterprise autonomous IT support — different
  market entirely.
- vs **RustDesk:** open-source leader with nothing shipped and a community
  proposal matching our design — **the open-source/P2P/privacy niche is
  open right now.** First-mover window in the FLOSS P2P segment argues for
  scheduling this soon after the MVP checkpoints, not eventually.
- Our moat compounds with what exists: accounts + encrypted roster
  (ADR-003) already give the agent a target list and an identity story;
  the connection-code escape hatch gives agent sessions without accounts.

## 11. Milestone sketch (post-MVP, proposed RD-015 – RD-019)

- **RD-015 — ADR-004 + consent plumbing.** Write the invariant exceptions
  (§6), add `FeatureFlags::AI_SESSION = 1<<4`, host consent mode + banner,
  tests for negotiation both ways.
- **RD-016 — frame tap.** `readback` → downscale → JPEG/PNG (WIC),
  `LatestSlot`, bounded, diagnostics counters, m2_rig loopback test.
  Controller-side only; smallest safe first patch.
- **RD-017 — agent driver core.** Provider trait (cloud + local
  OpenAI-compatible), action→`InputEvent` translation with `seq`/channel
  mirroring `to_wire_events`, settle heuristic, step budget, redacted
  action journal, panic hotkey.
- **RD-018 — MCP bridge.** `rmcp` stdio server exposing §5-B tools,
  localhost-only, token discovery file; demo workflow: local coding agent
  completes a task on a second machine.
- **RD-019 — eval harness + report.** Scripted task suite on the
  m2_rig/e2e_child rig; success-rate/cost/latency table per provider;
  `docs/reports/` entry, per the every-patch-ships-a-number rule.

## 12. Sources

Benchmarks/platforms: OSWorld-Verified leaderboard (osworld-v1.xlang.ai);
Anthropic computer-use docs (platform.claude.com); Opus 4.5 system card;
OpenAI CUA (openai.com/index/computer-using-agent), Atlas page, deprecation
coverage (presenc.ai tracker, coasty.ai 2026 roundups); UI-TARS-2 report
(arXiv 2509.02544) and repo (github.com/bytedance/ui-tars); WindowsAgentArena
(microsoft.github.io/WindowsAgentArena, ICML 2025); OSWorld 2.0 (Snorkel);
Qwen-UI-Agent report (arXiv 2607.28227); GUI-Actor (microsoft.github.io/GUI-Actor).
Cost/latency: Anthropic computer-use docs (tokens/screenshot); Reflex.dev
"computer use is 45× more expensive than structured APIs"; arXiv 2506.16042
(latency study).
Safety: VPI-Bench (arXiv 2506.02456); SnapGuard (arXiv 2604.25562); MIRAGE
(arXiv 2606.20717); EVA; OWASP LLM01:2025; OpenAI "Designing Agents to
Resist Prompt Injection" (Mar 2026).
Market: HopToDesk MCP announcement (blog.hoptodesk.com, Mar 26 2026); Jump
Desktop AI agents (jumpdesktop.com/ai-agents.html); TeamViewer Tia press
release (Nov 2025) + TeamViewer ONE MCP page; RustDesk discussion #16246
(Sep 16 2026); mcp-vnc / WinRemote / Conduit Desktop listings.
Tooling: modelcontextprotocol/rust-sdk (`rmcp`, Tier-1).
Note: 82–86% 2026 OSWorld-Verified claims come from third-party tracker
sites (benchlm.ai, llm-stats, llmlearner) and could not be corroborated
against the official leaderboard; treat as directional.
