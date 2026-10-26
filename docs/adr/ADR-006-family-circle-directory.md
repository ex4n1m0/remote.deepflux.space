# ADR-006: Family circle — shared machine directory and owner-approved trust

- Status: Accepted (post-MVP, 2026-10-26)
- Deciders: main session (integrator), on the user's 2026-10-26 request
  (family/friends machine directory with owner-gated connection and
  favorites), reviewed by the architecture, security, signaling, and UI
  seats before acceptance.
- Sources: `crates/protocol/src/directory.rs` (the contract),
  `services/signaling` `/api/directory`, `apps/desktop/src-tauri/src/directory.rs`
  (client composition), ADR-003 (control-plane widening precedent),
  ADR-005 §5 (the consent "remember this device" this ADR completes).

## Context

The product is used by one family and their friends. Today every machine
is an island: discovery is a 16-hex connection code read out over the
phone, favorites are a local nickname map, and ADR-003's roster is
private per account. The user asked for a centralized list: machines
appear in it on install, are searchable by nickname, any member can send
a connection request, and the machine's **owner** approves — both the
connection and the requester's ability to favorite the machine.

Two pre-existing weaknesses matter here. First, RD-023 shipped pairing
as an automatic post-consent handshake: the host stores and acks every
pairing offer unconditionally, and `auto_accept_if_paired` then grants
silent full control **on device id alone** — and device ids are
re-claimable through the documented presence-tombstone window roughly
three minutes after a machine goes offline. A directory that publishes
member device ids would turn that into a takeover primitive, so this ADR
fixes it rather than amplifying it. Second, ADR-005 §5 specified a
"remember this device" choice in the consent dialog plus revocation from
the machines list; the implementation skipped both (auto-ack, dormant
revocation commands). This ADR completes that decision.

## Decision

### 1. A circle of machines, keyed by a shared secret, listed on the control plane

Membership unit is the **machine**, not the account (family machines run
accountless via "skip for now"). A circle is a 32-byte random key; the
invite code is the key itself; `circle_id = sha256("deepflux-circle:" +
key_hex)` is the only circle identifier the server ever sees. The family
installer embeds the key at build time (`DEEPFLUX_CIRCLE_KEY`, the
`build.rs` mechanism ADR-005 uses for the agent key, with a build guard
that refuses an embedded key without an explicit family-build flag); the
public build joins by pasting the invite once in Settings, and any
member can create a fresh circle locally.

Each circle member registers exactly one sealed directory entry for its
own device id. The server is an opaque blob store plus a presence join:
it never sees nicknames, and invariant 2 is widened the same way ADR-003
and ADR-005 widened it — the control plane now also carries sealed
directory entries and circle-id hashes, never plaintext user data.

### 2. Wire surface: `POST /api/directory`, owned by `crates/protocol::directory`

Fourth service surface (signaling, account, chat, directory — see §7 on
the chat surface reconciliation). `DIRECTORY_PROTOCOL_VERSION = 1`,
action-dispatched flat snake_case JSON, 1 MiB body cap, header-only
bearer auth where the `(device, token)` pair is validated against
signaling presence exactly like `/api/chat`. Three actions:

- **put** `{device, circle_id, ciphertext_hex, nonce_hex}` — registers or
  refreshes the caller's own sealed entry. Timestamps are server-minted
  (client-supplied times are never trusted; house rule from
  `roster_put`). Storage is a single ZSET `sg1:dir:{circle_id}` of JSON
  members scored by server time, TTL 30 days, pruned on write, capped at
  128 members (`circle_full` 409; a refresh by an existing member is
  always allowed; no silent eviction).
- **list** `{device, circle_id}` — all live entries plus a server-joined
  `online` flag read from `sg1:p:{device}` presence keys in one pipeline
  (`Store.mget`, added for this purpose). Search is client-side over the
  decrypted ≤128 entries; there is deliberately no server-side search.
- **remove** `{device, circle_id}` — deletes the caller's own entry;
  idempotent.

Entry plaintext: `DirectoryEntryDoc {v:1, name (1..64 chars), joined_ms}`
sealed AES-256-GCM under the circle key with AAD
`"dir-entry:v1:{circle_id}|{device_id}"`. The machine id is **not**
inside the sealed blob — the server-attested device id is the entry's
identity, which removes the cross-member code-spoofing class entirely.
The circle key lives in the Windows Credential Manager (the
`credstore::SessionStore` seam); `circle.json` under the app data dir
holds only `circle_id` and flags. `CircleKey`'s Debug is redacted
(invariant 6 discipline).

Rate limits bound both per-device abuse (ids are free) and per-circle
aggregate abuse (keys leak): put 10/min/device + 60/min/IP + 5
new-members/day/circle; list 60/min/device + 300/min/circle; remove
10/min/device. Fixed-window buckets via the existing `rl:`/`rlt:` seam.

### 3. Trust: the owner's click is the pairing ceremony (completes ADR-005 §5)

The consent dialog gains a **"remember this machine"** checkbox and
shows the requester's directory nickname with the device code always
visible beside it (`Mom's PC · a41f…`) — nicknames are self-chosen, so
the code is the identity that cannot be impersonated within the prompt.
`EngineCmd::ConsentAccept` gains `remember: bool`:

- **remember ON** → the host acks the pending `PairOffer` and persists
  the pairing; the controller auto-saves a favorite (directory nickname,
  code as placeholder). This click is the owner approval that gates
  favoriting; directory rows offer saving only once paired.
- **remember OFF** → no ack, nothing persisted; the controller's pending
  offer expires at session end. Host silence is the refusal signal —
  no `PairNack` variant and no `WIRE_VERSION` bump: an un-acked
  controller correctly shows as untrusted (it *will* be prompted next
  time). Established pairings are never silently overwritten; re-pairing
  requires explicit removal in Trusted machines.
- Additive `FeatureFlags::PAIRING_REMEMBER = 1<<5` lets 0.5 controllers
  distinguish deliberate trust from a legacy 0.4 host's unconditional
  auto-ack (transitional residual: old hosts keep auto-acking).

The AI-session variant (`AI_SESSION`) defaults the checkbox **off** with
blunt copy — remembering means an agent can start controlling the
machine without asking.

### 4. Pairing proof: silent accept must prove the secret

`connect_request` gains an additive optional `pairing_proof_hex` =
HMAC-SHA256(pairing_secret, `"pair-proof:v1|{controller_id}|{host_id}|{session_id}"`).
Host rule: pairing exists **and** proof verifies → silent accept;
pairing exists but the proof is missing/invalid → the consent prompt
with "claimed to be a trusted machine but could not prove it" copy
(fail open to the human, never to accept); no pairing → unchanged.
Controllers send the proof whenever they hold a pairing. Old hosts
ignore the field; they remain vulnerable to the id-squat until updated,
which the rollout notes state plainly. The `record_pairing` overwrite
path is closed at the same time.

### 5. Always-ready reachability, behind explicit consent moments

When a circle is joined, the app auto-starts the engine and host
presence at launch, so family machines are reachable; "launch at Windows
login" (tauri autostart, default ON only in the family build) implies a
tray mode with close-to-tray, plus a single-instance guard. Two consent
moments keep this honest: sharing this machine in the circle is asked
once at first run/join (the toggle in Settings thereafter), and every
untrusted session still hits the consent prompt. Prompt-flood defense
lands with it: the host auto-rejects repeat requests from an unpaired
controller for 60 s after a timeout and 5 min after an explicit reject,
and the signaling send path gains fixed-window rate limits (60
envelopes/min/sender, 5 connect_request/min per sender+target) — the
M3-audit gap that until now only the account surface had closed.

### 6. Desktop composition

`node-runtime::directory_remote` (ureq, mirrors `account_remote`:
version gates both directions, typed errors, redacted logs) behind
`apps/desktop/src-tauri/src/directory.rs`, which owns the circle state,
a single-flight latest-wins 60 s list poller, the auto-`put` on engine
Online and on display-name change, and engine-off-capable commands
(`circle_status/create/join/leave/set_shared`, `directory_list`) on the
account-command pattern. The UI event is app-layer (`app://directory`),
not `engine://`. The machine rail stays one merged contact list
(`unifiedMachines` union favorites ∪ roster ∪ circle, name precedence
roster > favorite > circle > code) with client-side search; favorites
gain a local `source` field (`manual` | `directory`); the login
roster write-back becomes merge-by-code instead of wholesale replace
(today it would wipe directory favorites). The consent payload is
enriched at emit time in Rust (`requester_name`, `paired`,
`pairing_proof_ok`, `ai_session`) so a paired-and-proven reconnect
renders a passive status card, never a dialog.

### 7. Surface reconciliation

AGENTS.md's "three surfaces, all owned by `crates/protocol`" was already
stale: RD-022's chat inbox envelope (`ChatEnvelope`,
`CHAT_PROTOCOL_VERSION`) lives only in TypeScript plus a hand-copied
struct in `apps/desktop`. This ADR folds it into `crates/protocol` as
part of slice 1, making the honest count **five** wire surfaces
(signaling, wire, account, chat, directory), all protocol-owned and
golden-fixture-pinned.

## Consequences

- **Residual risks, accepted for a home deployment:** the embedded
  circle key is extractable from the installer (same class as the
  embedded agent API key — revisiting that embedding is separate work);
  a leaked circle key grants directory read (ids, nicknames, online
  patterns) and targeted requests, but with §4 in place no control;
  there is no in-app key rotation or member eviction — operational
  rotation is minting a new key/new installer (the old namespace TTLs
  out in 30 days; pairings survive and are revoked in Trusted machines);
  one circle per machine; host-id squatting against controllers (fake
  host) remains the documented pre-existing residual; legacy plaintext
  secrets (`device_token`, `pairings.json`) stay as they are — new
  secrets (the circle key) use the credential store, old ones are a
  recorded DPAPI follow-up.
- **Behavior change to RD-023:** pairing is no longer automatic; one
  consent click without "remember" grants exactly one session. Existing
  `pairings.json` entries keep working.
- The service gains one function and one Store method (`mget`, one
  pipeline); deploy is purely additive and rollback-safe (clients gate
  on 404; orphaned `sg1:dir*` keys expire within 30 days).
- Deferred: in-app rotation/eviction, multi-circle, deep-link invites,
  offline request queuing, server-side search, DPAPI migration,
  tombstone-authenticated directory writes for engine-off refresh.

## Addendum — distribution collapsed to the family build (2026-10-26)

User decision, recorded verbatim intent: *"i just want the Family
installer, we can delete the other approach from existence"* followed by
*"no, the public version is the family version."* The two-installer model
(private family exe + public keyless exe with invite pasting) is
DISCONTINUED. There is one build — the family build with the embedded
circle key — and it is the public download at remote.deepflux.space.
Everyone installs the same file and auto-joins the circle; the invite/
join-by-paste path remains in the app as an escape hatch but is no
longer the distribution story.

Accepted residuals (supersede §"Consequences" where they conflict):

- Any downloader can extract the circle key from the public artifact:
  directory read (ids, nicknames, online patterns) and auto-join are
  open to anyone who finds the site. Control remains gated per-machine
  (consent prompt; silent reconnect still requires a valid pairing
  proof), and prompt-flood defenses (host cooldowns + signaling rate
  limits) plus the 128-member directory cap bound the abuse surface.
- Rotation blast radius grows: minting a new key now means replacing
  the website's installer; existing installs keep the old key and their
  namespace TTLs out in 30 days — machines must reinstall to rejoin.
- The embedded-key extraction residual and the no-rotation/no-eviction
  items are unchanged; the "never publish the family build" rule is
  explicitly retired by this decision (the key FILE and the git repo
  stay secret; the published artifact intentionally carries the key).

Operational consequences: `scripts/build-family.sh` is THE installer
build; releases copy its artifact to `apps/landing/download/` under the
public filename and deploy the landing. Landing fineprint discloses the
auto-join and the opt-out. v0.6.0 was the first release shipped this
way (SHA-256 `96507d1a4962…`, byte-verified live).
