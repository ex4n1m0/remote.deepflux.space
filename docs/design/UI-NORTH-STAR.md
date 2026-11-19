# UI north star — the merged app's control surface

- Source: owner-provided concept image, 2026-11-19
  (`docs/design/ui-north-star.png` — "Overseer Remote" concept). The
  NAME in the image is not adopted (product stays **ModelSwarm** per
  ADR-013); the layout, visual language, and interaction model ARE the
  direction. This document translates the image into tokens and a
  component inventory, and maps every element to the roadmap so P2/P3
  UI work builds against a fixed target.
- Status: Accepted as design direction (owner: "use this image as
  inspiration for the UI/UX/HID").

## What the image shows (information architecture)

A full-viewport, three-column mission-control dashboard:

1. **Top app bar** — hexagonal logo + product name; center status pill
   ("● 5 machines online"); right controls: full-access shield toggle,
   **Pause All Agents**, red **Stop All**.
2. **Left rail — MACHINES** — machine cards (mini desktop thumbnail
   with green status dot, name, status pill: `Agent working` /
   `Needs approval` / `Idle`), active card carries the teal border
   glow; dashed **＋ Add machine** button at the bottom.
3. **Center — session workspace** — header row (machine name, latency,
   mode tabs **Manual / Shared / Agent**, icon toolbar: keyboard,
   mouse, clipboard, file transfer, monitor, record; **Take Over**
   button) above the remote desktop viewport. The concept's signature
   detail: **two labeled cursors in the viewport** — `You` (blue) and
   `Agent` (teal) — making shared control legible.
4. **Right rail — two stacked agent panels**
   - **MACHINE AGENT** (the selected machine's agent): task checklist
     (done = teal check, in-progress = spinner ring, pending = hollow),
     amber **approval card** ("Agent wants to reboot this machine" →
     Approve / Deny), instruction input ("Instruct this machine's
     agent…").
   - **MASTER AGENT**: instruction input ("Instruct the master
     agent…"), and a **fleet tree** — Master node branching to every
     machine, each node a progress ring showing live per-machine
     status of the current fleet instruction.

Instruction bubbles are blue, right-aligned, chat-style. Machine
names are uppercase, semibold. Terminal/monospace text inside the
viewport for agent work product.

## Design tokens (derived from the image; tune, don't drift)

| Token | Value (approx) | Use |
|---|---|---|
| `--bg-0` | #12151B–#171B22 | page background |
| `--surface-1` | #1A2028 | panels |
| `--surface-2` | #1C222B | cards |
| `--border` | #2A323D | hairlines, card borders |
| `--accent` | #3EE8B5 (mint-teal) | primary: active states, progress, agent identity, selected glow |
| `--accent-2` | #4A9EFF (blue) | secondary: human identity ("You"), instruction bubbles, Take Over |
| `--danger` | #E23B3B | Stop All, record |
| `--warning` | #E8A33C | approval gates, needs-attention |
| `--ok` | #34C759 | online dots, working pills |
| `--text` | #E6EAF0 | primary text |
| `--text-muted` | #8A94A3 | labels, secondary text |

Color semantics are **identity-coded**, and that is the image's core
interaction idea: **teal = agent/machine action, blue = human action**,
amber = needs a human decision, green = healthy, red = stop. Every
shared-control surface (cursors, input previews, chat bubbles, tree
nodes) must keep that coding.

Spacing: compact — 12–16px card padding, 10–12px list gaps, 20px panel
padding. Radii: panels ~12px, cards ~10px, buttons ~8px, pills full
round. Type: modern grotesk (Inter-class); panel headers 16–18px bold
slightly letterspaced uppercase; body 12–13px; pills 11px. Effects:
flat dark surfaces, soft shadows on floating windows, teal glow ONLY on
the focused/selected thing; no noise textures.

The website (tracker) already shares the family (dark navy + cyan
#38D9F5, see apps/tracker globals.css). Default: the app follows this
image exactly (mint-teal primary); the site keeps its cyan until the P5
branding pass decides whether to unify on one accent.

## Component inventory → roadmap mapping

| Concept element | Product feature | Phase |
|---|---|---|
| Machine cards + status pills | account-scoped machine rail (replaces pairings+circle view) | P2 |
| ＋ Add machine | enrollment entry (device code → dashboard approve) | P1/P2 |
| Mode tabs Manual / Shared / Agent | control-mode switch: human-only, shared, agent-driving | P2 (Manual), P3 (Shared/Agent) |
| Dual cursors `You`/`Agent` | input-source tagging on the wire + labeled remote cursor rendering | **P3 — requires the rd15 "input-source tag" gap to be closed first** |
| Take Over | exclusive-control claim (existing controller semantics) | P2 |
| Toolbar (kbd/mouse/clipboard/files/monitor/record) | existing viewer toolbar, restyled | P2 |
| Latency in session header | existing RTT display | P2 |
| MACHINE AGENT panel | existing in-app assistant per machine, restyled + checklist/task streaming | P3 |
| Approval card (Approve/Deny) | slave-side capability model surface — high-impact agent actions gate on a human decision (the ADR-011 posture revisited, per-machine setting) | P3 |
| MASTER AGENT fleet tree + progress rings | `fleet_run` generalization: N-machine fan-out with live per-machine progress | P3 |
| Pause All Agents / Stop All | global agent pause + fleet-wide input kill (safety surface; Stop All must also drop AI sessions) | P3 |
| "N machines online" pill | account directory presence | P2 |
| Session viewport (light desktop in dark chrome) | existing WebRTC viewer — the "window into a light world" contrast is the intentional look | P2 |

## Interaction principles extracted (the HID part)

1. **Legibility of who is acting** — every action in the shared space
   carries its actor (cursor labels, bubble colors, tree-node states).
   Never render agent action ambiguously as human action.
2. **Human is the circuit breaker** — Pause All / Stop All are
   always-visible, one-click, and idempotent; approval gates are
   opt-out-able per machine but never hidden.
3. **Fleet state at a glance** — the tree and the rail must answer
   "what is everything doing right now" without interaction.
4. **One instruction surface per scope** — machine-scoped input under
   the machine panel, fleet-scoped input under the master panel; the
   two never mix.
5. **Viewport is sacred** — chrome stays dark and quiet; the remote
   desktop is the brightest thing on screen.

## Open design decisions (not blocking, decide at P2 kickoff)

- Where the human chat layer (OnlyHumans protocol rooms, ADR-013 D4)
  surfaces in this layout — likely a third right-rail panel or a
  collapsible column; must keep humans-only traffic visually distinct
  from agent panels.
- Swarm inference status (P4) — per-machine "hosting models" pill in
  the rail; where serving stats live.
- Whether `Manual / Shared / Agent` tabs apply per session or globally.
