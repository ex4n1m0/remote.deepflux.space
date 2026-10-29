# ADR-009: Machine-name identity and the trusted-host list — accounts, favorites, and the circle directory retired

- Status: Accepted (0.10.0, 2026-10-29)
- Deciders: main session (integrator), on the user's 2026-10-29 simplification
  mandate ("the add feature is causing more problems than anything … a
  simple software that uses the machine name for everything, machine name
  is the chat name, no login, no favorites, we can instead create a list
  of always approved hosts"), after a four-agent deep study of the
  affected systems.
- Supersedes: ADR-003 (accounts and roster) in full; ADR-007 (named
  accounts gate control) in full; ADR-006 §§1–2, §6 circle-directory
  portions and its distribution addendum. ADR-006 §§3–4 (the pairing
  ceremony, durable "Always allow" intent, pairing proofs) and the
  2026-10-28 durability addendum SURVIVE unchanged — they become the core
  of this design.

## Context

Through 0.9.x the machine list grew into a three-way union — local
favorites (`favorites.json`), the ADR-003 encrypted account roster, and
the ADR-006 sealed circle directory — merged in the rail with name
precedence (roster > favorite > circle > code), login-time merge
glue, roster→favorites write-back mirroring, "Added — awaiting their
approval" grouping, and an auto-favorite on pairing ack. Since 0.8.0
(ADR-007) controlling any machine additionally required a signed-in
account carrying a person name, which added onboarding, unlock, and
name-prompt screens. Field pain concentrated exactly there: pairing
deadlocks (0.9.1), crash-adjacent session glue (0.9.2/0.9.3), and a
machine list whose states few flows could keep coherent.

Meanwhile the piece the family actually relies on — "Always allow this
machine" — already is a durable, cryptographically proven
always-approved list (`pairings.json` + the ADR-006 pairing-proof HMAC),
independent of accounts, favorites, and the directory.

## Decision

1. **One identity: the machine's display name.** `display_name()`
   (settings `device_name`, falling back to the Windows hostname) is the
   only name. It is what the host publishes, what a controller sees in
   its trusted list and chat, and what fills `connect_request.
   requester_name` (additive-optional within `SIGNALING_PROTOCOL_VERSION`
   1, value semantics changed from person name to machine display name —
   advisory, exactly as ADR-007 §4 already stated). The ADR-007 control
   gate is deleted everywhere it lives (UI, `connect` command, in-app
   agent `connect` tool, `--mcp` bridge): anyone who knows a machine's
   connection code can *ask* to control it; the consent prompt and
   pairing proofs remain the gate, as before 0.8.0.
2. **One list: `pairings.json` is the trusted-host list.** The rail
   renders pairings (established + pending) with a cached display `name`
   per entry — a client-side field, no wire impact, learned from the
   peer (below) and editable in Trusted machines. Favorites, the roster,
   and their merge/mirror glue are deleted; `favorites.json`,
   `account.json`, `roster.json`, and `circle.json` are cleaned up on
   load. Discovery is the connection code (read from the host's
   "This machine" card); pairing ("Always allow") makes it permanent.
3. **The peer's name travels on signaling.** The host→controller accept
   envelope gains additive-optional `host_name` (same pattern as
   `requester_name`; the TS envelope schema must know the key or the
   relay strips it — deploy the service before shipping the client).
   The controller caches it into the pairing's `name` at ack/establish.
   No `WIRE_VERSION` change: the binary surface (PairOffer/PairAck)
   is untouched, and chat envelopes already carry only device ids.
4. **The circle directory is retired** (client and, after an update
   soak, the `/api/directory` surface). The single-installer rule
   survives with only the agent key embedded; circle-key embedding and
   its build guard are deleted. Residual from ADR-006's distribution
   addendum — the public installer publishing every member's device id —
   is thereby closed.
5. **The account surface is retired the same way.** Client account
   code, onboarding, unlock, and name prompt are deleted now;
   `/api/account` (and `/api/directory`) stay deployed untouched until
   the 0.10.0 client has soaked, because an old 0.9.x client that gets a
   404 there is locked out of controlling entirely (its own ADR-007
   gate). Endpoints, zod schemas, and fixtures are removed in a
   follow-up deploy; orphaned Upstash `acct:*`/`roster:*` keys (10-year
   TTL) may be flushed manually.
6. **Online status is honest and minimal**: a machine shows online only
   while a session with it is live. Roster presence and the directory
   presence join die with their systems; no replacement probe is built.

Wire surfaces shrink from five to three: signaling, the binary
data-channel surface, and chat. Invariant 2 reverts to: Vercel carries
ids, presence, SDP/ICE envelopes, and sealed chat ciphertext — nothing
else. `PAIRING_REMEMBER`, `AI_SESSION`, and `VIDEO_SUPPRESSED` capability
bits are unchanged.

## Consequences

- Existing `pairings.json` entries survive the update — the trusted list
  is continuous across the release. Rows that existed only as favorites
  (never paired) need their code entered once.
- The consent prompt shows the controller's machine display name beside
  the device id; a pre-0.10.0 anonymous controller sends no
  `requester_name`, and the host shows the bare code (transitional).
- Credential Manager keeps the machine-identity anchor and agent key;
  account session entries are orphaned harmlessly.
- The landing page loses its sign-in and circle copy; the product story
  is: install → read the code once → Always allow → it's in your list.
- Test suite shrinks by roughly 80 dedicated account/directory/favorites
  tests; new pins cover the pairing-name cache, machine-name consent
  copy, and the single-list rail.
