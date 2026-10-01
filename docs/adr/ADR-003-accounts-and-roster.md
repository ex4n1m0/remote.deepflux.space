# ADR-003: Accounts and the encrypted device roster

- Status: Accepted (post-MVP, 2026-10-01)
- Deciders: main session (integrator), on the user's 2026-09-25 post-MVP
  commitment and 2026-10-01 activation directive
- Sources: `PLAN.md` §"Post-MVP feature commitment",
  `crates/protocol/src/account.rs` (the contract),
  `services/signaling/lib/account.ts` (service), `apps/desktop/src-tauri/src/account.rs`
  (client composition)

## Context

The MVP shipped with "no accounts": a device claims its self-chosen id by
possessing a random token, and controllers type a 16-hex connection code.
The user committed (2026-09-25) to a post-MVP trusted-device roster with
optional accounts, and activated it (2026-10-01) with a sharper product
shape: the hub stays **Vercel-only**; the first-run flow becomes
*install → sign in with username/password → see your saved computers →
"add this computer"*; and the saved list exists locally **and** on the
server, server-stored data being encrypted under a **random key generated
per user**.

What the user asked for does **not** include the deeper "pairing-key trust"
idea from the PLAN.md commitment (connecting without the consent prompt) —
the one-time consent gate is unchanged. This ADR covers identity, roster
storage, and sync only.

## Decision

### 1. Accounts live on the existing control plane, as a third wire surface

A second Vercel function, `POST /api/account` (action-dispatched JSON,
`protocol_version` 1), backed by the same Upstash store and the same
`Store` seam as signaling. Invariant 2's meaning is thereby widened but not
broken: the control plane now carries ids, presence, SDP/ICE envelopes,
**scrypt password verifiers, wrapped key material, and encrypted roster
ciphertext** — still never a frame, input, cursor, or any plaintext user
data. The surface is owned by `crates/protocol::account` and pinned by the
same golden-fixture discipline as signaling (Rust exports →
`services/signaling/fixtures/account/` → zod mirror checked by
`scripts/validate-wires.mjs`).

The anonymous connection-code flow is unchanged and remains the escape
hatch ("skip for now" on the onboarding screen); accounts are the default
first-run path, not a requirement.

### 2. Envelope encryption: one random DEK per user, wrapped by the password

All crypto is client-side (Rust, `node-runtime::account_crypto`); the
server is a blob store.

- At registration the client mints `DEK = random(32)` — the per-user random
  key — plus two 16-byte salts.
- `auth_key = scrypt(password, auth_salt, N=2^15, r=8, p=1)` — sent to the
  server as a password equivalent.
- `kek = scrypt(password, wrap_salt, N=2^15, r=8, p=1)` — never sent.
- `wrapped_dek = AES-256-GCM(kek, DEK, aad = "acct-dek:v1:{username}")`;
  the server stores only `wrapped_dek` + nonce.
- The roster document (`protocol::account::RosterDoc`: `{v, computers:[{id,
  name, code, added_at_ms, updated_at_ms}]}`, ≤128 entries) is encrypted as
  `AES-256-GCM(DEK, aad = "roster:v1:{username}")` — the server stores only
  ciphertext + nonce + version.
- The server adds a second hash layer: `verifier = scrypt(auth_key,
  server_salt, N=2^14, r=8, p=1)`, compared with `timingSafeEqual`. A full
  store leak therefore grants neither login (can't invert the verifier) nor
  the roster (needs the KEK, i.e. the password).

Username-binding AAD on both ciphertexts prevents blob swaps between
accounts. Key material is held in `Zeroizing` buffers client-side;
`SessionToken`'s `Debug` is redacted (invariant 6 discipline).

### 3. Login is a two-step pre-auth (salts first), with enumeration hardening

`login_pre` fetches the two salts so scrypt can run client-side before
`login` sends `auth_key`. Unknown usernames get **deterministic decoy
salts** (`sha256("account-decoy"|username|…)`) so the response shape is
identical; `login` against an unknown username runs one dummy scrypt and
answers the same `invalid_credentials`. Rate limits (the M3 audit's missing
token-bucket, finally): register 10/h/IP, login 20/15min/username and
60/15min/IP, roster_put/presence 60/min/user — 429 with `retry_after_s`.

### 4. Sessions and local storage

Sessions are opaque 32-byte tokens (only `sha256(token)` stored, 30-day
TTL, bearer header only). The desktop stores the session token in the
**Windows Credential Manager** (per the PLAN.md commitment — never
plaintext JSON), and two files under the app data dir: `account.json`
(username + salts + wrapped DEK — no secrets, but offline brute-force
material; protected by scrypt cost) and `roster.json` (the encrypted blob).
Because the DEK is password-wrapped, a returning user re-enters only their
password (session token validation aside); there is deliberately **no
offline login** — the verifier lives server-side.

### 5. Roster sync: versioned optimistic concurrency, client-side merge

Server stores `{ciphertext, nonce, version}`; `roster_put` requires
`base_version` == current (short lock via `setNxEx`, conflict → 409 with
`current_version`). Merging is client-side: union by `code`, per-entry
`updated_at_ms` wins. On login the local and server rosters merge, the
merged doc is written back to the server and mirrored to `favorites.json`
so the anonymous/logged-out path stays coherent. Device online status comes
from a `presence` action reading the existing `sg1:p:{device}` keys (CR-4).

## Consequences

- **Password change/reset: not in v1.** Changing the password re-wraps the
  DEK server-side (mechanism already echoes `wrapped_dek` at login); a
  forgotten password loses the server roster (local file still decrypts
  only with the old password). Accepted for this phase; revisit with
  account recovery.
- **Offline brute-force:** a thief with `account.json` + `roster.json` (or
  a store leak) can mount an offline dictionary attack against the wrapped
  DEK; scrypt at N=2^15 is the mitigation, as with every password-based
  envelope scheme. DPAPI-encrypting `account.json` is a possible hardening
  (post-phase), noted as a risk, not adopted now.
- **Account deletion/rotation** and multi-device session revocation are
  future work; logout deletes the single presented token.
- The TS service carries one new endpoint, no new external dependencies;
  the desktop adds `windows`-crate Credential Manager access inside
  `apps/desktop` (reviewed unsafe, alongside `engine/displays.rs`).
- Landing-page "no accounts, ever" copy must be reworded when this ships
  (tracked in PLAN.md).
