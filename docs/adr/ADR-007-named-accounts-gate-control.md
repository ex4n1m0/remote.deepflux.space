# ADR-007: Named accounts gate control — the invite carries a person name

- Status: Superseded by ADR-009 (2026-10-29) — the account gate is
  deleted; `requester_name` survives with new value semantics (the
  controller's machine display name)
- Deciders: main session (integrator), on the user's 2026-10-27 request
  ("only people with an account can invite; those that go in without an
  account will not be able to control other machines; force people to add
  a name to their account so the invite to take control goes with a
  name"), reviewed by the code-review and UX seats before release.
- Sources: `crates/protocol/src/account.rs` (`display_name`,
  `profile_set`), `crates/protocol/src/signaling.rs`
  (`connect_request.requester_name`), `services/signaling`
  `lib/account-service.ts` + zod mirrors, `crates/session` (event/action
  threading), `crates/node-runtime/src/node.rs` (stamping), ADR-003
  (accounts), ADR-006 (advisory-name posture, additive-optional
  precedent).

## Context

Through 0.7.x, controlling a machine required no account at all, and the
host's consent prompt identified the requester only by device id — or, if
the host happened to have the controller in its own circle-directory
cache, by that self-chosen nickname. A family member pressing Control on
a machine whose owner did not have them cached saw only
`1a2b3c4d5e6f7788 wants to control this PC`. The user judged that
unacceptable for the family product: the person asking should be named,
and the way to guarantee a name exists is to require an account (with the
name) before a machine may control anything.

## Decision

1. **Accounts gain a display name** (person name, 1–64 chars trimmed, no
   control characters). Additive-optional within `ACCOUNT_PROTOCOL_VERSION`
   1: `register` may carry `display_name`; a new authenticated action
   `profile_set { display_name }` sets/updates it; `register`/`login`
   responses echo it. Accounts created before 0.8.0 have none — the client
   prompts for the name the first time the user tries to control.
2. **Controlling requires a signed-in account WITH a name.** The gate
   lives in the `connect` command (`commands.rs`), the in-app agent
   `connect` tool, and the `--mcp` bridge's `deepflux_connect` — one
   shared helper (`AccountManager::control_identity`). Hosting, being
   controlled, and chat are deliberately NOT gated: an anonymous machine
   remains a fully usable family host (that is the escape hatch
   ADR-003 promised, now scoped to the host side).
3. **The name travels on the control request.**
   `connect_request.requester_name` (additive-optional within
   `SIGNALING_PROTOCOL_VERSION` 1, same pattern as ADR-006's
   `pairing_proof_hex`; the TS envelope schema MUST know the key or the
   relay strips it). The composition layer stamps it (pure session
   machines have no account knowledge — same precedent as
   `stamp_pairing_proof`), and the host threads it through
   `HostEvent::IncomingRequest` → `Action::PromptConsent` →
   `NodeObserver::prompt_consent` into the consent payload. The host
   prefers the wire name, falling back to the circle nickname, then the
   bare device id.
4. **The name is advisory; the device id stays the identity.** Any client
   can put any string in the field. The consent prompt keeps showing the
   device id beside the name, and pairing proofs (ADR-006) remain the
   only machine-verifiable trust. The server does not enforce name
   truthfulness — the gate exists to guarantee OUR clients always send a
   deliberate, user-chosen name, not to authenticate it.
5. **UX (one press, first time only):** the Control buttons stay one
   press. When the gate blocks, the app remembers the intent, opens the
   shortest path (create-account card with a required "Your name" field,
   or a one-field add-name card for legacy accounts), and fires the
   deferred connect automatically once a name exists.

## Consequences

- Wire surfaces touched (all additive-optional, no version bumps):
  account API (`display_name`, `profile_set`, response echoes), signaling
  envelope (`requester_name`). Golden fixtures extended
  (`register_named`, `profile_set`, `connect_request_named`); zod mirrors
  updated in lockstep (`account-schema.ts`, `envelope.ts`).
- `crates/session` event/action types gained an `Option` field — an
  in-repo ripple only (two_peers reference model updated), not a wire
  change.
- The MCP/agent paths are gated identically: an external agent driving a
  machine that is not signed in gets a clear blocked-tool message. Sign
  in once on machines you agent from.
- Anonymous hosting remains first-class: the family build still
  auto-joins the circle on install and can be controlled without any
  account — only the *controller* side of the relationship needs a name.
- Deployment order matters: the signaling service (account
  `display_name` storage, `profile_set`, envelope passthrough) must be
  live before 0.8.0 clients ship; older servers strip the unknown
  envelope field silently (the zod passthrough fix) and reject
  `profile_set` with `unknown_action`.
