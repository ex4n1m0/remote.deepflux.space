# Deep study: agent-first UX — contact-list UI, in-app assistant chat, machine-to-machine messaging

**Date:** 2026-10-24
**Status:** research study + proposed plan — nothing here is committed work;
wire changes and new features named below each need their ADR/patch before
code lands.
**Prompt (user, verbatim intent):** polish the UI so the agent chat is
visible from the start; the agent helps configure the app (adding remote
machine IDs, everything editable); once connected it takes control of the
remote machine to troubleshoot Windows issues for the user's mother
(clean temp files, adjust preferred language — "ideally it takes full
control"); one client for both roles, designed with agent cooperation in
mind; UI like LogMeIn/TeamViewer with machines as a contact list like an
IM app; direct text messaging included, reusing the OnlyHumans solution.

---

## 1. Goal decomposition (what the request actually contains)

1. **G1 — Agent chat visible from the start.** The assistant is a
   first-class surface of the main window, not a hidden `--mcp` mode.
   Today the MCP bridge is invisible in-app (stdio, external agents only).
2. **G2 — The agent configures the app.** Natural language → actions on
   the app's editable surface: add/rename machines, set settings, start
   host, connect by code. The editable surface is exactly the 33 typed
   Tauri commands (`apps/desktop/src-tauri/src/commands.rs`; settings
   fields at `store.rs:18-33`: device name, signaling URL, default
   quality/scale…; machines = favorites (guest) or roster computers).
3. **G3 — In-session agent control, family-support grade.** Beyond the
   shipped screenshot/click/type loop (ADR-004): the primary scenario is
   "fix mom's Windows" — clean temporary files, set preferred language.
   "Ideally full control" needs a definition of *control surface*: pixels
   only, or pixels + a host-approved admin command channel (see §6).
4. **G4 — Symmetric client, agent cooperation.** One binary, two roles
   (already true). The design must work when the *same* app+agent runs on
   both ends — controller-side agent drives; host-side agent assists
   (read status, narrate, answer chat) but does not self-control.
5. **G5 — IM-style machines list.** Contact list like TeamViewer/AnyDesk
   address books / IM apps: saved machines with presence, one-click
   connect, rename, groups-lite. Unify the current duplicate concepts
   (Favorites vs Computers) into one **Machines** list.
6. **G6 — Direct text messaging, reusing OnlyHumans.** Machine-to-machine
   chat: in-session at minimum; out-of-session (presence + offline
   envelopes) is the OnlyHumans-shaped extension (§7).

---

## 2. Where the app is today (grounding)

- **Layout:** single stacked grid — `HostPanel | ConnectPanel+SessionControls
  | Identity+Machines+Settings` (`App.tsx:225-350`), 1180×800 window, no
  navigation model, onboarding gate in front (sign-in / unlock / skip).
  ~3.3k LOC of TS across 8 components + reducer/mapping. No chat, no
  agent surface, no tray (app must be open to be reachable).
- **Machines today are two concepts:** guest **Favorites** (local JSON,
  `store.rs`) and signed-in **Computers** (encrypted roster, ADR-003),
  rendered conditionally (`App.tsx:275-347`). Presence: favorites get
  `peerOnline` only from session events; roster gets true presence via
  `computers_presence` (CR-4). A contact-list UI wants ONE list with
  best-available presence.
- **Agent today:** `--mcp` stdio bridge for external agents
  (`mcp.rs`, 9 `deepflux_*` tools), `AI_SESSION` consent wording, frame
  tap + `AgentInput` wire path (ADR-004). Nothing visible in the UI; no
  model integration inside the app.
- **Chat today:** none. The wire has no chat message; adding one is a
  binary-surface change → `WIRE_VERSION` 0→1 (AGENTS.md policy: bincode
  is not self-describing; a new variant/channel requires the bump, with
  the compatibility test).

## 3. Prior art — what the reference products converge on

**Contact-list layout (TeamViewer/AnyDesk/RustDesk/LogMeIn):**
- TeamViewer's 2026 "new interface" replaces the classic Computers &
  Contacts tab with **device groups** in the main window ([switch-to-new-interface](https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-remote/get-started/switch-to-the-new-interface), [device groups](https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-remote/devices/device-groups-explained));
  chat lives in the **remote-session toolbar** ([session toolbar](https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-remote/remote-control/remote-session-toolbar))
  and as contact chat with **saved chat history / transcripts**
  ([Tensor transcripts](https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-tensor/security/provide-in-session-chat-transcripts-for-integrations)).
- AnyDesk: **Address Book** (contacts + tags), **unattended access
  password** for 24/7 reach, simple in-session text chat
  ([address book](https://anydesk.com/en/features/address-book),
  [unattended access](https://support.anydesk.com/docs/unattended-access),
  [text chat](https://anydesk.com/en/features/text-chat)).
- RustDesk: address book is a **paid/pro** feature (tags, shared lists,
  saved passwords) — free users lack it
  ([docs](https://rustdesk.com/docs/en/self-host/rustdesk-server-pro/address-book),
  [discussion #6161](https://github.com/rustdesk/rustdesk/discussions/6161));
  in-session chat exists. **A free, built-in, beautiful machines list is a
  real differentiator vs RustDesk's free tier.**
- Convergence: left contact list (name, id, presence, tags) + main pane
  per-selected-machine + in-session toolbar. Exactly the IM shape the
  user asked for.

**Assistant placement and onboarding (AI UX):**
- A **persistent side panel = co-pilot framing** (ongoing assistive role)
  vs dashboards implying autonomy
  ([Where should AI agents live in your UI](https://medium.com/@claus.nisslmueller/where-should-ai-agents-live-in-your-ui-cd27965a577a),
  [uxdesign.cc](https://uxdesign.cc/where-should-ai-sit-in-your-ui-1710a258390e))
  — matches "visible from the start, helps configure".
- Onboarding best practice: capability framing, **prompt starters**,
  permission/consent flows, personalization
  ([11 onboarding flows](https://screensdesign.com/articles/ai-chat-app-onboarding-examples)).
- HopToDesk's MCP tool set is the precedent for G2: it exposes
  `get_ui_state`, `click_toolbar_button`, `connect_to_peer` — the agent
  drives the app itself (research §3.3 of `ai-agent-remote-control.md`).

**Safety for "full control" (2026 consensus):**
- Human confirmation for **destructive** actions, least-privilege
  permissions, journaling/observability, pause/stop controls; the
  OpenClaw email-deletion incident is the canonical "destructive
  permission is THE boundary" case
  ([incident analysis](https://www.penligent.ai/hackinglabs/meta-ai-alignment-directors-openclaw-email-deletion-incident-exposes-the-real-agent-safety-boundary),
  [Kiteworks study](https://www.kiteworks.com/cybersecurity-risk-management/ai-agent-security-risks-agents-of-chaos-study),
  [agentic incident maturity levels](https://www.ilert.com/agentic-incident-management-guide)).
- For family support: unattended access is the standard answer
  (AnyDesk password, TeamViewer Host) — i.e. **trust moves from
  per-session consent to a pairing event + audit trail**. PLAN.md already
  reserves exactly this ("pairing-key trust", deferred 2026-10-01).

**OnlyHumans (the user's own system — studied locally):**
- `C:\OnlyHumans-app` (Tauri 2 + vanilla TS + Rust `core`) and
  `C:\OnlyHumans-main` (Vercel/Upstash hub + site). P2P chat over libp2p
  (QUIC/TCP, noise, yamux, relay v2 + DCUtR hole-punching), Ed25519
  libp2p identities, **ChaCha20-Poly1305 frames with HKDF per-message
  subkeys and kind-domain AAD** (`core/src/crypto.rs:221-304`), room
  protocol + **DMs** (deterministic pair room id, re-invite resync,
  memory-only DMs — `rooms.rs`), **SQLite history** (contacts /
  conversations / messages — `store.rs:100-118`), and an **untrusted hub**
  (signed registrations, sealed 24 h fallback inbox, presence counter).
- The user's own DM study (`OnlyHumans-main/docs/direct-messages-study.md`)
  already solved: invite sealing, split-brain convergence, entry-point UX
  (⇄ chip per member, "private chats" sidebar section, non-committing
  rows) and a full UI-redesign proposal (P1 one-home-per-intent, P2 calm
  trust, P3 say-it-human) — the design language transfers 1:1.
- Reuse verdict (§7): the **concepts and store schema** transfer cheaply;
  embedding the whole libp2p core is a second transport and should be a
  later, separable phase. DeepFlux already has a P2P session (WebRTC/
  DTLS) — chat rides it; no new crypto is needed in-session.

---

## 4. Proposed UI (the deliverable of this study)

### 4.1 Main window — IM shape, three zones

```
┌─────────────────────────────────────────────────────────────────────────┐
│ DeepFlux   [This machine ▾]                    @user · Settings · Diag  │
├───────────────────────┬─────────────────────────────────┬───────────────┤
│ MACHINES  🔍 ⚙        │  Mom's PC        ● online        │  ASSISTANT    │
│ ┌───────────────────┐ │  ─────────────────────────────   │  ┌─────────┐ │
│ │ 🖥 Mom's PC   ●   │ │  [ chat history / live chat ]    │  │ agent   │ │
│ │ 🖥 Office box  ○  │ │                                  │  │ messages│ │
│ │ ➕ Add machine    │ │  ┌────────────────────┐ ┌──────┐  │  │ + tool  │ │
│ └───────────────────┘ │  │ message…          ⏎ │ Send │  │  │ cards   │ │
│ ───────────────────── │  └────────────────────┘ └──────┘  │  └─────────┘ │
│ THIS MACHINE          │  [ Connect ] [ Request help ]     │  ┌─────────┐ │
│ 🖥 igor-pc · code …   │  Session controls (when live)     │  │ ask… ⏎  │ │
│ [ Share this machine ]│                                  │  └─────────┘ │
└───────────────────────┴─────────────────────────────────┴───────────────┘
```

- **Left rail — Machines (G5):** one unified list (guest favorites and
  roster computers merged by code, ADR-003 union rules already do this);
  presence dot (roster presence when signed in; event-derived otherwise);
  "This machine" card pinned at the bottom with its code + Share toggle
  (host role without a separate panel). Add-machine: paste a code (or
  scan later), name it — the same flow the agent performs for you (G2).
- **Center — the selected machine:** a conversation-first pane (chat
  history lives here per machine), with action buttons (Connect,
  Request help = send a help-request chat + ring, later) and the session
  controls (quality/monitor/scale/fullscreen/disconnect) folding in when
  connected. Host consent prompts surface as a system-style card on the
  machine that's being controlled.
- **Right rail — Assistant (G1):** persistent, collapsible, visible from
  first run (after onboarding). It is a co-pilot: suggests, explains,
  does. Shows tool-call cards ("Added *Mom's PC*", "Screenshot taken",
  "Clicked Start → Settings"), and — when a session is live — the agent's
  narration ("cleaning temp files… clicked Clean up"). Prompt starters on
  first run: *"Add a machine"*, *"Share this screen"*, *"Connect to Mom's
  PC and empty the Recycle Bin"*. Provider/key setup happens in the
  assistant's first-run card (cloud key or local endpoint), never a
  settings dead-end.
- **Onboarding gate:** unchanged mechanics, but the assistant is
  introduced inside it ("skip for now" still exits to the full UI; the
  rail shows a "configure me" card when no provider is set).

### 4.2 Role symmetry (G4)

Same window both roles. The Machines list contains "This machine" plus
saved peers; sharing is a toggle, connecting is a button. The host-side
agent (mom's copy) is **read-only**: it can read status, answer her
questions in chat ("what is my son doing?" → narrated from the journal),
and explain the consent prompt — it never drives her input (ADR-004
Option C stays deferred). One consent flow gains a "remember this
device (pair)" checkbox → G3's unattended path (§6).

---

## 5. Architecture for the in-app agent (G1+G2)

New `apps/desktop/src-tauri/src/agent.rs` (Rust, not webview — the webview
only renders):

1. **Provider trait** `AgentProvider` — two implementations day one:
   - `OpenAiCompatible` (base URL + key): covers OpenAI, OpenRouter,
     Anthropic-compatible gateways, and **local** Ollama / LM Studio /
     llama.cpp servers (`http://127.0.0.1:11434/v1`) — one client, both
     worlds; vision support declared per-endpoint (screenshots need a
     VLM; text-only endpoints still do G2 config tasks).
   - keys/endpoints stored via the existing settings/credstore pattern
     (Credential Manager for keys, never settings JSON).
2. **Shared tool layer:** factor the 9 `deepflux_*` tool impls out of
   `mcp.rs` into a `tool_provider.rs` both consumers call (the stdio MCP
   bridge unchanged for external agents). Add **app-config tools**:
   `machine_add/rename/remove`, `settings_get/set`, `host_share/stop`,
   `connect/disconnect`, `status`. This is HopToDesk's proven pattern,
   executed in-process with no stdio hop.
3. **Loop & journal:** bounded agent loop (step budget, per-session
   action journal with redacted text per ADR-004 §4). Agent actions that
   hit the typed commands surface are inherently bounded by the same
   validation the UI goes through — no new privileged path.
4. **Chat events to the UI:** `EngineEvent`-style typed events
   (`agent://message`, `agent://tool-call`) — text only, invariant 1
   untouched (screenshots stay engine-side; the panel shows captions).

## 6. "Full control" for mom's machine (G3) — the honest core

Three capability tiers, each separately consented:

- **T1 — pixels + input (shipped, ADR-004).** Works for anything a human
  could click. For "clean temp files" this means driving Settings /
  Disk Cleanup via screenshots — works, but slow (many steps) and
  brittle (localization-dependent UI — mom's Windows may not be English).
- **T2 — pairing/unattended access (needs the user's go).** PLAN.md's
  deferred "pairing-key trust": first consent installs a per-device
  pairing key; paired controllers connect without a fresh prompt
  (AnyDesk-password / TeamViewer-Host equivalent). For family support
  this is the difference between a product and a demo. Trust anchor =
  pairing + journal; host can revoke per device (roster already models
  this).
- **T3 — admin command channel (ADR-005, new).** Opt-in, host-paired
  only: the controller may run a **journaled, allowlisted** command set
  on the host (start with read-only diagnostics + `cleanmgr`-style temp
  cleanup + language/culture set via `Set-WinUILanguageOverride` /
  `Set-Culture` / `Set-SystemPreferredUILanguage`), each run shown live
  in chat with output, full local journal on both ends. This is what
  makes temp-clean/language actually reliable and language-agnostic.
  It needs its own ADR (it crosses ADR-004 §5's "no remote shell" line —
  deliberately: narrow, allowlisted, journaled, paired-only). 2026
  safety consensus (§3) = confirmation for destructive ops + least
  privilege + journaling; the design encodes exactly that.

Recommendation: ship T1+T2 with the UX work; draft ADR-005 for T3 in
parallel since "clean temp files, adjust preferred language" is the
stated primary use case.

## 7. Machine-to-machine chat (G6) — two-phase plan

- **Phase A (with this work): in-session chat on the existing session.**
  New `Channel::Chat` + `WireMessage::Chat { id, ts, sender_id, body }`
  → `WIRE_VERSION` 0→1 with the policy's compatibility test; rides the
  DTLS-encrypted data channel (Vercel sees nothing, invariant 2 intact).
  Persistence per machine in SQLite modeled on OnlyHumans'
  `store.rs` schema (conversations/messages tables transfer almost
  verbatim); UI = the center pane conversation. Also carries the
  agent's narration as system-style messages, and the host's "request
  declined/accepted" notices — one channel, three senders (you, peer,
  agent).
- **Phase B (separable, later): out-of-session presence + offline
  envelopes, OnlyHumans-shaped.** Requires an always-on reachability
  path (tray/background mode + a hub rendezvous like OnlyHumans'
  signed registrations and sealed inbox). Reuse verdict: adopt
  OnlyHumans' **hub protocol concepts and store schema** (and the
  DM-study's split-brain rule verbatim if rooms ever appear); do NOT
  embed its libp2p core — the signaling service already provides
  rendezvous and the WebRTC stack provides transport, so a DeepFlux
  flavor of `peer:<id>` presence + sealed `inbox:<id>` on the existing
  Vercel/Upstash (ciphertext-only, invariant 2's widened-but-not-broken
  reading from ADR-003) is the smaller lift than a second transport.
  Decision needed: whether mom-messaging without a session is a v1
  requirement (it changes scope materially).

## 8. Proposed phasing (new backlog RD-020…)

| ID | Scope | Wire/ADR impact |
|---|---|---|
| RD-020 | UI restructure: Machines rail (unified list + presence + This-machine card), center conversation pane, assistant rail shell (no brain yet) | none (UI + commands already exist) |
| RD-021 | In-app agent: provider trait (cloud-key + local endpoint), shared tool layer refactor out of mcp.rs, app-config tools, first-run provider card, tool-call cards, journal | none |
| RD-022 | In-session chat: `Channel::Chat`, `WireMessage::Chat`, WIRE_VERSION 1 + compat tests, SQLite history, center-pane conversation UI | WIRE_VERSION bump 0→1 |
| RD-023 | Pairing/unattended access (T2): pair-on-consent checkbox, per-device keys, revoke UI, agent "connect without prompt" | signaling-additive; ADR-004 addendum |
| RD-024 | Host-side read-only assistant + session-live AI banner + chat-noticed consent help | none |
| RD-025 | Admin command channel (T3): allowlisted cmdlet set, live output in chat, dual journals | ADR-005 (new) |
| RD-026 | Family-task eval suite on the E2E rig (temp-clean, language set, update check) with per-provider success rates | none (tests) |

Order rationale: RD-020/021 deliver the visible transformation (G1, G2,
G5) with zero protocol risk; RD-022/023 make the family scenario real
(G3, G6); RD-024/025/026 deepen it.

## 9. Sources

TeamViewer: [new interface](https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-remote/get-started/switch-to-the-new-interface) ·
[device groups](https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-remote/devices/device-groups-explained) ·
[session toolbar/chat](https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-remote/remote-control/remote-session-toolbar) ·
[chat transcripts](https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-tensor/security/provide-in-session-chat-transcripts-for-integrations) ·
[unattended support](https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-remote/remote-control/provide-unattended-remote-support).
AnyDesk: [address book](https://anydesk.com/en/features/address-book) ·
[unattended access](https://support.anydesk.com/docs/unattended-access) ·
[text chat](https://anydesk.com/en/features/text-chat).
RustDesk: [address book (pro)](https://rustdesk.com/docs/en/self-host/rustdesk-server-pro/address-book) ·
[free-tier gap discussion](https://github.com/rustdesk/rustdesk/discussions/6161).
AI UX: [Where should AI agents live in your UI](https://medium.com/@claus.nisslmueller/where-should-ai-agents-live-in-your-ui-cd27965a577a) ·
[uxdesign.cc placement patterns](https://uxdesign.cc/where-should-ai-sit-in-your-ui-1710a258390e) ·
[AI chat onboarding examples](https://screensdesign.com/articles/ai-chat-app-onboarding-examples).
Safety: [OpenClaw incident analysis](https://www.penligent.ai/hackinglabs/meta-ai-alignment-directors-openclaw-email-deletion-incident-exposes-the-real-agent-safety-boundary) ·
[Kiteworks agent-power study](https://www.kiteworks.com/cybersecurity-risk-management/ai-agent-security-risks-agents-of-chaos-study) ·
[ilert agentic maturity levels](https://www.ilert.com/agentic-incident-management-guide).
Local: OnlyHumans app (`C:\OnlyHumans-app`: core libp2p/chat/crypto/store)
and hub (`C:\OnlyHumans-main`: API + docs incl. the DM study); DeepFlux
ADR-003/004, PLAN.md §pairing trust, AGENTS.md wire policy.
