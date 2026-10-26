# Subagent roster study — what this project needs reviewed

2026-10-26, after the ADR-006 release. Trigger: the user asked for a deep
study of which subagents the project should have, and an audit of the
existing set. Agent files live in `~/.zcode/agents/*.md` (outside the repo
by design); this doc records the analysis so it survives sessions.

## Criteria (an agent must earn its slot)

1. **Recurring work type** — a need that appeared multiple times in the
   project's history, not a one-off.
2. **Distinct trigger** — the main session must know *when* to dispatch it
   without thinking ("before every release", "when a user reports X").
3. **Returnable artifact** — a fixed output shape (evidence report, patch,
   verdict) the integrator can act on.
4. **Not the main session's job** — integration, docs, ADR writing, and
   research stay with the integrator by design (PLAN.md §5).

## Audit of the existing roster

| Agent | Remit | Verdict |
|---|---|---|
| rd-architecture-owner | boundaries, contracts, ADRs, integration | current — read it before contract changes |
| rd-capture-codec-engineer | DXGI + MF H.264 pipeline | current (subsystem unchanged in nature) |
| rd-p2p-transport-engineer | WebRTC/ICE/RTP/data channels | current |
| rd-desktop-ui-engineer | Tauri/React shell | current (role text predates chat/assistant/circle but the remit is generic; dispatch prompts carry current context) |
| rd-vercel-signaling-engineer | signaling service + store | **amended** — add live-incident triage (see below) |
| rd-performance-qa | latency/soak acceptance | current |
| security-reviewer (generic) | appsec review | keep generic — worked well on ADR-003/006; a project-specific clone would add sprawl, not insight |
| rd-code-reviewer (2026-10-26) | pre-merge patch review | new |
| rd-ux-reviewer (2026-10-26) | family-user UX review | new |
| rd-release-reviewer (2026-10-26) | pre-release checklist | new |

## Gaps found

**1. Field debugging of user-reported issues — the biggest gap, now filled
by `rd-field-debugger`.** Evidence: the three most valuable bugs of the
last month were all user-reported and all diagnosed by hands-on inspection
of the *installed* app — 0.4.2 (every Rust→UI event silently ACL-denied;
found via `capabilities.json == {}`), 0.4.3 (identity regenerated every
launch; found by diffing `settings.json` across runs), 0.5.0 (empty
signaling URL from a pre-0.5 upgrade; found via the settings file). That
knowledge existed only in the main session's memory notes. The new agent
encodes it as a runbook: install layout, appdata files, ProductVersion
rules, NSIS traps, service smokes, credential-store targets, and the
never-print-secrets rule.

**2. Live-service incident triage — folded into the existing signaling
engineer** rather than a new agent. The trigger ("the live service is
misbehaving") belongs with whoever owns the service. Amendment adds:
`vercel inspect`/logs, Upstash REST key reads, endpoint smoke commands,
and the standing traps (local `vercel dev` POST bridge broken on this
machine — headless contract is the local truth; `api/*.js` bundles are
build artifacts; only schema-valid requests consume rate-limit quota).

## Deliberate non-additions (anti-sprawl)

- **No project-specific security reviewer** — the generic one reads the
  dispatch context and has produced two good ADR-gating reviews.
- **No AI-agent eval trainer** — RD-026 (family-task eval) is future work
  and belongs to the existing engineers + QA.
- **No docs/ADR writer** — integration discipline (PLAN.md §5) keeps that
  with the main session.
- **No landing/marketing agent** — the page is a single static file.

## Dispatch patterns (when to use which)

- Any patch → `rd-code-reviewer` before merge.
- User-visible flow changed → `rd-ux-reviewer` over that flow.
- Any installer/deploy → `rd-release-reviewer` (it checks what the
  code reviewer cannot: the live artifact).
- User reports breakage → `rd-field-debugger` with the verbatim symptom.
- Contract/ADR change → `rd-architecture-owner`; security-relevant →
  `security-reviewer` too.
- "Service weird in prod" → `rd-vercel-signaling-engineer` (live-ops mode).
