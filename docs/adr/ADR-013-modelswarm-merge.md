# ADR-013: ModelSwarm merge — one product: swarm inference + fleet remote control

- Status: **Accepted** (all decisions confirmed by the owner,
  2026-11-19 — "go with the recommendations")
- Deciders: the owner (2026-11-19) — merge Remote with Model Swarm: the
  same app collaborates models (swarm) and remote-controls every machine
  that joins (visual desktop + agent command, direct or agent-to-agent,
  including mass instruction deployment). Two websites become one, with
  a user account system. One binary serves as master and slave: the
  machine the user works at is the master; all others are slaves.
  Adding a machine must be simple. Refinement (same day): OnlyHumans
  the product stays untouched; its protocol becomes the merged app's
  chat layer for humans — humans only, never agents.
- Relates: ADR-003/ADR-007/ADR-009 (accounts lineage — designed, gated
  control, then retired for the family-distribution model; this ADR
  revives accounts at the *website* layer for multi-user), ADR-005
  (agent-first), ADR-011 (agent power), ADR-012 (fleet fan-out).

## Context

Three products exist today (all deepflux.space, all Tauri 2 + Rust):

- **This repo (Remote, v0.15.3):** mature desktop remote control —
  WebRTC P2P engine (DXGI capture → H.264/RTP, 5 SCTP channels,
  SendInput, TURN forbidden), one binary with host+controller roles,
  pairing (8-byte code + consent + `pairings.json` + HMAC pairing-proof
  v2), circle directory, sealed machine chat, auto-update. Agent layer:
  in-app assistant, 53 tools, stdio MCP bridge, `fleet_run` (≤4 paired
  machines, serial), scheduled unattended tasks. Signaling on Vercel +
  Upstash. Windows-only.
- **ModelSwarm Protocol (MSP, v0.2.42):** inference swarm — llama.cpp
  runtime + C-API engine, scheduler, eligibility leases, OpenAI-compatible
  loopback gateway (127.0.0.1:11435), speculative decoding + family
  verification, cloud executor, libp2p QUIC transport (direct-first,
  hand-rolled circuit-relay-v2 client fallback), tracker on Vercel
  (Next.js + Neon Postgres, device enrollment, admin routes, relay
  tickets), relay binary. ~850 tests, 45 ADRs. MSP's "collaboration" is
  inference-layer (peers cooperating to produce tokens); it has **no**
  command-another-machine's-agent surface.
- **OnlyHumans (v1.2.0):** P2P E2E-encrypted group chat — word-addressed
  rooms, GK-derived room ids, epoch key rotation with epoch-bound
  deliveries, admission proofs, an untrusted-storage hub (signed
  records, sealed inbox, presence), a browser portal, and a self-contained
  libp2p net stack (QUIC+TCP/noise/yamux, identify, ping, relay v2,
  **DCUtR hole-punching**, request-response rooms protocol). No agents,
  no AI, no remote control — deliberately humans-only. Per D4 below,
  this protocol is the designated human chat layer of the merged
  product.

Verified gap analysis for the owner's vision:

1. Mass instruction deployment does not exist anywhere. The closest
   primitive is `fleet_run` (`src-tauri/src/agent/tools.rs`) — capped at
   4 machines, serial, no retry, no audit trail.
2. Accounts are greenfield in all three products. The only reusable
   primitives: Ed25519 device keypairs (Remote pairing, MSP
   installation identity) and MSP tracker's device-enrollment/approval
   schema on Postgres.
3. Three identity systems must become one.
4. Current security posture is family-grade, not multi-user: the public
   installer embeds a working DeepSeek API key and the circle key
   (`scripts/build-family.sh`); ADR-011 grants admin-by-default with no
   per-command confirmation; there is no host-side AI-session banner
   (rd15 "honest limitations"); MSP relayed circuits are relay-vouched,
   not end-to-end authenticated (`relay_client.rs`).
5. Two overlapping Tauri shells (this repo's `src-tauri`, ~21k lines;
   MSP's `modelswarm-desktop`, one 10.4k-line `app.rs`). One must win.

## Decision

**D1 (confirmed): the merged app grows out of THIS repo.** Remote's
Tauri shell already has the host/controller roles, agent layer, WebRTC
engine, updater, and installer. MSP contributes crates as workspace
members: `modelswarm-runtime`, `-gateway`, `-scheduler`, `-eligibility`,
`-transport`, `-identity`, `-types`, `-store`, `-resource`, (relay
stays a separate binary). MSP's `modelswarm-desktop` is dropped; its
`bench`/`sim` come over only as dev-tools if needed. Mechanism: copy
the crates in at a pinned MSP version (both repos are ours; cross-repo
git deps complicate CI), then the MSP repo freezes as upstream
reference. The `fork/rtc` patch is inherited unchanged.

**D2 (confirmed): one website, grown from MSP's tracker** (Next.js +
Neon Postgres). It absorbs: Remote's signaling API (serverless TS
functions, portable), the landing/downloads/latest.json update
manifest, and adds accounts + dashboard. One Vercel project, one
domain. Upstash stays for signaling-presence style ephemera; Postgres
becomes the system of record. During P1 the accounts work lands in the
tracker's current home (MSP repo `apps/tracker`) so its existing CI
(typecheck/build/Postgres integration suite) verifies it; the physical
move of the tracker into this repo is a later mechanical consolidation
step (workflow port + Vercel relink).

**D3 (confirmed): accounts are self-built** — email + password + server
sessions on Vercel + Neon. No third-party auth vendor. Account model:

- A **user** owns **machines**. A machine is one installation with one
  Ed25519 device keypair (unifying Remote's pairing identity and MSP's
  installation identity): device id = base58(SHA-256(pubkey)); the
  same key is the libp2p PeerId when swarm serving is enabled.
- **Adding a machine (the "simple system"):** install → sign in (or
  enter a short add-machine code from the dashboard) → the machine
  appears as pending → owner approves (or auto-approve for trusted
  sessions) → it is a swarm member. First-connection consent on the
  slave side is retained (ADR-009's prompt), generalized from
  per-pairing to per-account: *machines in my account may connect*.
- **Master/slave is a role, not an identity:** the machine the user
  sits at and drives is the master; every other member acts as a slave
  (serve desktop, run its agent, optionally host models). Any member
  can be the master.

**D4 (confirmed 2026-11-19): OnlyHumans stays untouched; its protocol
becomes the human chat layer of the merged app.**

- The OnlyHumans app and website are **not modified, not rebranded,
  not retired** — the standalone product keeps shipping exactly as is.
- The merged app ports the *protocol* at a pinned version (v1.2.0) by
  copying the implementation from OnlyHumans' `core` crate into this
  workspace as new crates: the room state machine (`rooms.rs` envelope
  + admission proofs), the crypto (`crypto.rs`: XChaCha20-Poly1305,
  HKDF, Argon2id, padding buckets, epoch-bound key deliveries), and
  the chat net stack (`net.rs`: QUIC+TCP/noise/yamux, identify, ping,
  relay v2, DCUtR hole-punching, request-response rooms protocol —
  DCUtR is a capability neither Remote nor MSP has today).
- The hub API contract (reg/lookup, room claim, sealed inbox, presence
  — signed records over untrusted storage) is deployed on the combined
  site, Upstash-backed, in a **separate keyspace** from
  onlyhumans.deepflux.space. The browser-portal join flow is not
  ported initially; chat is in-app.
- **Humans only, never agents.** Room envelopes carry people; agent,
  fleet, and machine traffic stays on the machine chat / command
  plane. The agent tool layer gains **no** tools that read or post
  into rooms — structural separation, the same way MSP walls its
  advisory plane off swarm transcripts.
- Rooms remain account-orthogonal (word + channel GK, exactly the
  OnlyHumans design), so the human chat layer keeps working even if
  the account backend is down. The merged product mints **its own
  channel GK** — its own room universe, no shared secrets with the
  standalone product.

**Additional confirmed calls (2026-11-19):**

- **UI/UX direction (2026-11-19):** the owner provided a concept image
  as the design north star — `docs/design/ui-north-star.png`, decoded
  into tokens and a component-to-roadmap map in
  `docs/design/UI-NORTH-STAR.md`. Mission-control layout (machine rail
  / session viewport with dual labeled cursors, human blue vs agent
  teal / machine-agent + master-agent panels with a fleet progress
  tree), amber approval gates for high-impact agent actions, always-
  visible Pause-All/Stop-All safety controls. The concept's own
  product name is not adopted; the layout, tokens, and interaction
  principles are. Notable dependency it creates: the dual-cursor
  design requires closing rd15's input-source-tag gap on the wire (P3).
- **Brand/domain (amended 2026-11-19):** the merged product is named
  **DeepMulti** (owner decision, same day as acceptance — supersedes
  the ModelSwarm working brand used while planning). Target domain
  `deepmulti.deepflux.space` (to be confirmed at cutover); the
  tracker's current `modelswarm.deepflux.space` and
  `remote.deepflux.space` both redirect to it. App
  renaming/rebranding lands with P5.
- **Circle directory:** replaced by the account directory at P2; the
  sealed machine-chat it was paired with stays.
- **Platform:** Windows-only for v1 (both engines are Windows-native;
  cross-platform capture/input is out of scope).
- **MSP tracker transition:** cut over when P1 ships; the old tracker
  serves read-only until then.
- **Relay:** GCP `msp-relay` is the go-forward relay (owner directive
  2026-11-16); the repo docs that still describe Oracle as live get
  reconciled in P1.

**Capability map (what reuses, what is new):**

| Capability | Source | Status |
|---|---|---|
| Visual remote desktop | Remote engine crates | reuse |
| One binary, master/slave by context | Remote host+controller | reuse |
| Add-a-machine enrollment | pairing + tracker enrollment | extend (D3) |
| Accounts, registry, dashboard | new (tracker schema seeds it) | **new** |
| Per-machine agent (53 tools) | Remote agent layer | reuse |
| Direct agent chat (user ⇄ machine) | Remote machine chat + assistant | reuse |
| Human ⇄ human chat (E2E rooms) | OnlyHumans protocol, pinned v1.2.0 | port (D4) |
| Agent→agent, mass deploy to N | `fleet_run` | **major extension** |
| External agent driving | Remote MCP bridge | reuse |
| Swarm inference (host + serve) | MSP crates (D1) | port |
| One website | tracker absorbs signaling + landing (D2) | consolidate |

**Security posture changes required by multi-user (blocking for
public launch, woven through the phases):**

- No secrets in installers. DeepSeek/cloud keys and any circle-style
  key move to per-machine or per-account config entered at setup.
- Slave-side capability model: what masters (and master *agents*) may
  do is a per-machine setting; admin elevation default is revisited
  (opt-in per machine rather than global ADR-011 stance); visible
  AI-session indicator on the host while an agent drives.
- Every agent action on a slave writes a local audit record (who/what/
  when/result); fleet operations collect per-machine outcomes.
- Agent-command traffic that transits the MSP relay must be
  end-to-end authenticated to the peer device key (noise to the peer,
  not trust-the-relay), or gated to direct connections until it is.
  WebRTC desktop sessions are already E2E (DTLS-SRTP) and unaffected.
- Human chat rides the OnlyHumans protocol — E2E by construction over
  an untrusted hub (everything signed, verified client-side). Agent
  traffic is structurally excluded from the room layer (D4), so
  remote-control and fleet authority can never leak through rooms.

## Roadmap

- **P0 (this ADR): DONE — all decisions confirmed 2026-11-19.**
  Remaining P0 housekeeping: reconcile the relay-hosting records in
  MSP's docs with the GCP directive (scheduled within P1).
- **P1 — one workspace, one identity, accounts:** crate import (D1);
  single device identity; account schema + auth + enrollment +
  dashboard on the site (D2/D3). *Accept:* fresh Windows machine →
  install → sign in → pending in dashboard → approved → shows online;
  merge gate + tracker CI green.
- **P2 — account-scoped remote control:** machine list in-app →
  connect → consent once → full desktop; circle directory replaced by
  the account directory. *Accept:* two machines across NATs controlled
  via the account directory with no code exchange. **Gates recorded
  from the P1 security review (2026-11-19), mandatory before remote
  control rides on account ownership:** (a) enrollment-approval hardening
  — an 8-char userCode leaked (screenshot/shoulder-surf) currently lets
  any account holder bind that machine to themselves; add device-side
  claim confirmation at device/complete ("claimed by account X") or
  bind via the 256-bit deviceCode channel instead; (b) session posture —
  shorten the 30-day account-session TTL (7–14 d) and/or add a user
  "revoke all sessions" affordance; (c) the account suites' PgStore SQL
  must have run once against real Postgres (CI integration job or a
  throwaway Neon branch) before any account data is production-real;
  (d) device-seed theft model (from the P1 app-side security review) —
  the app's Ed25519 seed is a never-rotating per-user credential-store
  key; theft lets an attacker sign as that installation indefinitely
  and the dashboard-side revoke is the only kill switch. P2's ownership
  story must document this and give the owner a re-key path (new seed =
  new installation id = fresh enrollment).
- **P3 — agent fleet commands + human chat:** `fleet_run` generalized
  — N machines, parallel, per-machine results, retries, audit;
  agent-to-agent instruction routing master→slaves. In the same phase,
  the OnlyHumans protocol port (D4): word rooms with epoch rotation
  live in the merged app over its own GK universe, hub routes on the
  combined site. *Accept:* one instruction to 5+ machines, all results
  collected, audit entries present on each slave; AND two humans on
  merged-app machines join the same word room and chat E2E with key
  rotation verified — and no agent tool can read or write a room.
- **P4 — swarm inference in the app:** per-machine "host models"
  toggle; local gateway on every node; master's agent gains swarm
  inference tools. *Accept:* master's assistant answers a prompt
  served by a slave's hosted model through the swarm path, including
  via relay.
- **P5 — hardening + launch:** posture items above closed, security
  review pass, app rebrand to DeepMulti, unified domain, public
  positioning.

## Resolved questions (2026-11-19)

1. D1–D4 — all confirmed (D4 first, then D1–D3 with the
   recommendations).
2. Room universe: **separate GK**, own universe, no shared secrets
   with the standalone OnlyHumans product. Cross-product interop would
   require deliberately sharing a channel key later; default no.
3. Brand/domain: **ModelSwarm** on `modelswarm.deepflux.space`;
   `remote.deepflux.space` redirects. *Amended 2026-11-19: product
   named **DeepMulti**; domain decision moves to cutover (P5).*
4. Platform: **Windows-only v1**.
5. Circle directory: **replaced at P2** by the account directory;
   sealed machine-chat stays.
6. Tracker transition: **cut over when P1 ships**; read-only until
   then.

## Consequences

- This repo becomes the flagship; the MSP repo freezes at its pinned
  version (reference/upstream), and its desktop shell is abandoned.
- The OnlyHumans repos are not touched; its protocol lives on as a
  pinned copy inside this workspace. If the standalone product evolves
  the protocol (e.g., a v1.3 envelope change), syncing is a manual
  port decision per release — drift is possible and must be noticed.
- Accounts return, but at the website layer — in-app UX keeps the
  no-ceremony feel (ADR-009's motivation) for family-scale use.
- The family-distribution model (embedded keys, open circle) ends;
  distribution becomes per-account.
- Windows-first remains the host/controller platform for v1.
- Two Vercel projects (remote-signaling, remote-landing) consolidate
  into the tracker project; DNS/domains to be arranged at P1.
- Bonus transport capability: the D4 port brings DCUtR hole-punching
  into this codebase for the first time.
