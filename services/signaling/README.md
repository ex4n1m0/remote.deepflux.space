# services/signaling — Vercel control plane (M3, RD-009/RD-010)

Signaling/control-plane ONLY (AGENTS.md invariant 2): device presence,
connect_request/accept/reject routing, SDP/ICE mailbox with trickle
forwarding, cancel/disconnect propagation, `message_id` idempotency, TTL
cleanup. **Never** frames, input, cursor payloads, clipboard, or file data.

- Wire contract: `crates/protocol/src/signaling.rs` (snake_case JSON, flat
  `type`, `protocol_version` = 1). The TS mirror is `lib/envelope.ts`,
  pinned by golden fixtures (below). v0 is rejected with a typed `error`
  envelope (`code: 400`).
- All state lives in an **external ephemeral store** (Upstash Redis REST in
  production; the bundled emulator locally). Function instances hold only
  sockets and timers — nothing authoritative, so restarts, reconnects, and
  cross-instance routing are correct by construction.
- Transports on ONE endpoint (`/api/signal`): **WebSocket primary**
  (resumable, per-connection mailbox polling) + **HTTP polling fallback**
  (`send`/`poll`/`ack` POST ops) that also serves `vercel dev` locally.
- Since the accounts phase (2026-10-01) a SECOND endpoint serves the
  account/roster API: **`POST /api/account`** (see "Account & roster API"
  below). Same store, same discipline; the service sees only scrypt
  verifiers and ciphertext — never passwords, unwrapped DEKs, or roster
  plaintext.

## Layout

```
api/signal.ts        Vercel function (Node runtime): http.Server + WSS
api/health.ts        Liveness probe (no store access)
api/account.ts       Vercel function: account/roster API (POST /api/account)
lib/envelope.ts      zod mirror of the Rust envelope contract (THE TS types)
lib/account-schema.ts zod mirror of the Rust account contract (accounts)
lib/frames.ts        client<->service framing ops (svc_version 1)
lib/service.ts       core logic: presence, dedupe, mailbox, sessions
lib/account-service.ts account core: scrypt verifiers, sessions, roster, RL
lib/server.ts        http.Server factory: HTTP fallback + WS transport
lib/account-server.ts http.Server factory for the account API
lib/store.ts         thin storage seam (interface)
lib/upstash.ts       Upstash Redis REST driver (production + local emulator)
lib/config.ts        env-tunable TTLs/bounds (see .env.example)
lib/log.ts           redaction-safe logging (no envelopes, no tokens, no SDP,
                     no account key material)
tools/upstash-emulator.mjs  local store (out-of-process, real TTLs)
tools/dev-server.mjs standalone runner of BOTH servers (signal + account)
tests/contract.test.ts       contract matrix, signaling (spawns everything)
tests/account.test.ts        contract matrix, account API (spawns emulator +
                             standalone account server)
scripts/validate-wires.mjs   fixtures <-> zod mirror validation (both surfaces)
fixtures/            golden (Rust-exported) + reject wire fixtures; the
                     account goldens live under fixtures/account/
```

## Local development (exact commands)

Prereqs: Node 22, pnpm 9 (already installed). No Docker/WSL/Redis needed —
the emulator is plain Node.

```bash
cd services/signaling
pnpm install

# 1. Store (terminal 1) — Upstash REST emulator, real TTLs, out-of-process:
node tools/upstash-emulator.mjs --port 38001

# 2. Service (terminal 2) — pick one:
#    a) through the Vercel dev pipeline (HTTP path; see Known limitations):
UPSTASH_REDIS_REST_URL=http://127.0.0.1:38001 UPSTASH_REDIS_REST_TOKEN=local-t \
  pnpm dev:vercel                      # http://127.0.0.1:38011
#    b) standalone (WebSocket-capable; same lib/server.ts the function runs).
#       Serves BOTH servers: signaling on --port (default 38013) and the
#       account API on --account-port (default signal port + 1000 = 39013):
UPSTASH_REDIS_REST_URL=http://127.0.0.1:38001 UPSTASH_REDIS_REST_TOKEN=local-t \
  pnpm dev:standalone                  # signaling 38013, account 39013
#       Only one of the two? --only signal | --only account.

# 3. Checks:
pnpm test                     # typecheck + wire validation + unit + account tests
pnpm test:contract            # full signaling matrix (emulator + 2x vercel dev + 2x standalone)
pnpm test:contract:headless   # same matrix, no Vercel toolchain/auth (also in scripts/test.sh)
pnpm test:account             # account API matrix (emulator + standalone account server)
```

Notes:
- `pnpm dev:vercel` uses the project-local Vercel CLI (`vercel@60`, pinned
  devDependency) with `--local` — **no project link, no deploy**. The
  pinned `@vercel/node@15.0.0` builder is installed on first run (`.npmrc`
  sets `legacy-peer-deps` for that one install only).
- Windows: kill strays with
  `powershell "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | Where-Object {$_.CommandLine -match 'vercel|dev-server|upstash-emulator'} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"`.

### Rust-side local integration (the two-node gate)

```bash
# with the rig from above running (emulator + standalone):
SIGNALING_TEST_BASE_URL=http://127.0.0.1:38013 \
  cargo test -p node-runtime --test remote_signaling_live -- --ignored --nocapture
# HTTP-fallback variant against the vercel dev instance:
SIGNALING_TEST_BASE_URL=http://127.0.0.1:38011 SIGNALING_TEST_HTTP_ONLY=1 \
  cargo test -p node-runtime --test remote_signaling_live -- --ignored --nocapture
```

### Wire fixtures (delta D7)

```bash
# regenerate consciously after a protocol change (writes services/signaling/fixtures/golden):
UPDATE_SIGNALING_FIXTURES=1 cargo test -p node-runtime --test signaling_fixtures
# account surface (writes services/signaling/fixtures/account/{request,response,reject}):
UPDATE_ACCOUNT_FIXTURES=1 cargo test -p node-runtime --test account_fixtures
pnpm validate:wires   # TS schemas must accept every golden + reject every reject fixture
```

## Account & roster API (`POST /api/account`)

Second JSON surface owned by `crates/protocol` (`account.rs`; TS mirror
`lib/account-schema.ts`, pinned by the account goldens). Requests are
`{protocol_version: 1, action: "<discriminant>", ...fields}` (flat snake_case);
authenticated actions carry `Authorization: Bearer {session_token}` — header
ONLY (token in query/body is rejected, QA F42b rule). Responses are
`{ok:true, protocol_version:1, action, ...}` or
`{ok:false, error:"<code>", detail?, retry_after_s?, current_version?}`.

| action         | auth    | request fields -> response |
|----------------|---------|---------------------------|
| `register`     | —       | `username, auth_key, auth_salt_hex, wrap_salt_hex, wrapped_dek_hex, dek_nonce_hex` -> `session_token, expires_ms`; 409 `username_taken` |
| `login_pre`    | —       | `username` -> `auth_salt_hex, wrap_salt_hex` (deterministic DECOYS for unknown users) |
| `login`        | —       | `username, auth_key` -> `session_token, expires_ms, wrapped_dek_hex, dek_nonce_hex`; 401 `invalid_credentials` |
| `logout`       | bearer  | — (invalidates the presented token) |
| `roster_get`   | bearer  | — -> `ciphertext_hex, nonce_hex, version` (v0 + empty strings when absent) |
| `roster_put`   | bearer  | `ciphertext_hex, nonce_hex, base_version` -> `version`; 409 `roster_conflict` + `current_version` |
| `presence`     | bearer  | `codes: [1..50]` -> `online: [codes with live signaling presence]` |

Server-side crypto (node:crypto only): verifiers are
`scrypt(auth_key, server_salt, {N:16384, r:8, p:1})` — the password and the
unwrapped DEK never reach the service. Session tokens are 32 random bytes,
stored ONLY as `sha256(token)`. Unknown-username `login` runs one dummy
scrypt so error shape and latency match the wrong-password path (existence
is not disclosed); `login_pre` decoys are deterministic
(`sha256("account-decoy|{user}|{auth|wrap}")` first 16 bytes).

Store keys (same `sg1:` prefix, same Upstash store — no new external
services): `acct:{user}` (SETNX claim -> `username_taken` on race),
`roster:{user}` (+ version), `rosterlock:{user}` (5 s SETNX lock for
optimistic concurrency; a stale `base_version` or a busy lock both answer
`roster_conflict` with the current version), `sess:{sha256(token)}`,
`rl:{bucket}:{key}` / `rlt:{bucket}:{key}` rate-limit counters, and
read-only reuse of the signaling presence keys `p:{device}`.

Rate limits (fixed windows, see `.env.example` for the knobs): register
10/h per IP; login_pre 120/min per IP; login 20/15min per username AND
60/15min per IP; roster_put and presence 60/min per username. Only
well-formed requests consume quota. Oversize (but valid-hex) roster
ciphertext answers 413 `roster_too_large` (> 65536 decoded bytes); shape
violations answer 400 `malformed`.

## Environment variables

See `.env.example` (names + defaults; never commit real values):
`UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`,
`SIGNALING_TTL_DEVICE_SECONDS` (45), `SIGNALING_TTL_MAILBOX_SECONDS` (180),
`SIGNALING_TTL_SESSION_SECONDS` (480), `SIGNALING_TTL_DEDUPE_SECONDS` (120),
`SIGNALING_MAILBOX_MAX` (256), `SIGNALING_MAILBOX_BATCH` (64),
`SIGNALING_ENVELOPE_MAX_BYTES` (32768), `SIGNALING_WS_POLL_MS` (250),
`SIGNALING_MAX_CONNECTION_SECONDS` (290), `SIGNALING_STORE_PREFIX` (`sg1:`),
plus the account knobs: `SIGNALING_TTL_ACCOUNT_SESSION_SECONDS` (2592000),
`SIGNALING_TTL_ACCOUNT_SECONDS` (315532800),
`SIGNALING_ROSTER_MAX_CIPHERTEXT_BYTES` (65536),
`SIGNALING_RL_REGISTER_PER_HOUR` (10), `SIGNALING_RL_REGISTER_GLOBAL_PER_DAY` (500 — all-IP ceiling against rotating-address register spam), `SIGNALING_RL_LOGIN_PRE_PER_MIN` (120),
`SIGNALING_RL_LOGIN_PER_USER_15M` (20), `SIGNALING_RL_LOGIN_PER_IP_15M` (60),
`SIGNALING_RL_ROSTER_PUT_PER_MIN` (60), `SIGNALING_RL_PRESENCE_PER_MIN` (60).

## Deployment — LIVE (deployed 2026-10-01)

**Production: https://signaling.deepflux.space** (project `remote-signaling`,
team `timedivision`, region hkg1). Everything was deployed and verified by
the agent session; the original "user runs this once" runbook below is kept
for history/reprovisioning.

Deployed-and-verified state (2026-10-01):

- `/api/health`, `/api/signal` (HTTP ops + **WebSocket hello_ok**), and the
  full `/api/account` round-trip (register -> login_pre/login -> roster
  get/put incl. 409 conflict -> presence -> logout invalidation, decoy salts
  for unknown users) all pass against production Upstash.
- Storage: Vercel Marketplace resource `remote-signaling-redis`
  (Upstash KV) connected to the project — credentials arrive as the legacy
  `KV_REST_API_URL` / `KV_REST_API_TOKEN` env names, which
  `UpstashRestStore.fromEnv` accepts alongside `UPSTASH_REDIS_REST_*`.

### How to redeploy

```bash
cd services/signaling
pnpm deploy:prod     # = pnpm build:api && vercel deploy --prod -S timedivision
```

### Production-only facts (each cost a failed deploy to learn)

1. **The functions ship as esbuild bundles** (`pnpm build:api` ->
   `api/*.js`, gitignored, sources excluded from uploads via
   `.vercelignore`). Raw `.ts` sources with NodeNext `.ts`-extension imports
   deploy as ESM that cannot resolve `./lib/x.ts` at runtime
   (ERR_MODULE_NOT_FOUND). Bundling sidesteps specifier rewriting entirely.
   NOTE: Vercel matches `functions` patterns BEFORE any build command, so
   the bundles must exist pre-deploy — hence the `deploy:prod` script.
2. **Do not call `server.listen()` in the API entries.** A bare `listen()`
   binds a random port and keeps the worker alive ->
   INTERNAL_FUNCTION_INVOCATION_FAILED with no runtime logs. Just
   `export default server`; the runtime bridges it (WS works).
3. **Pipeline wire shape**: `POST /pipeline` takes an array of command
   ARRAYS (`[["SET","k","v"]]`), not `[{command:[...]}]` objects. Real
   Upstash rejects the object shape; the local emulator now enforces the
   production shape so it can never drift again.
4. **Builder install**: the exact-pinned `@vercel/node@15.0.0` peers on
   `@vercel/build-utils@14.12.0` while the build image bundles a newer one;
   the project env `NPM_CONFIG_LEGACY_PEER_DEPS=true` (production) works
   around the ERESOLVE. The `vercel` CLI is NOT a devDependency (it
   conflicts with the pinned runtime on cloud installs).
5. **Plan-cap check (QA F42a) still applies**: if the effective
   maxDuration is clamped below 300 s, set
   `SIGNALING_MAX_CONNECTION_SECONDS = <effective-cap> - 10` and redeploy,
   or WS connections get hard-killed without a bye frame.
6. Domain: attached with `vercel domains add signaling.deepflux.space
   remote-signaling` (never a bare `vercel alias set` — SSO trap).

### The original first-deploy runbook (historical, for reprovisioning)

```bash
cd services/signaling
vercel link                                            # or: vercel integration resource connect <upstash-resource> <project>
vercel env add UPSTASH_REDIS_REST_URL production       # or rely on KV_REST_API_* from the marketplace resource
vercel env add UPSTASH_REDIS_REST_TOKEN production
pnpm deploy:prod
# then the smokes above (health, WS hello, account round-trip)
```

The desktop default signaling URL is `https://signaling.deepflux.space`
(`DEFAULT_SIGNALING_BASE_URL` in `apps/desktop/src-tauri/src/store.rs`).

## Known limitations (verified locally, 2026-09-24)

- **`vercel dev` does not forward WebSocket upgrades**: the @vercel/node
  dev bridge proxies plain HTTP only (`compileUserCode` + `undici` fetch;
  no `upgrade` handler). WS behavior is therefore verified against
  `tools/dev-server.mjs` — the SAME `lib/server.ts` the function exports —
  and the WS-through-deployment path must be spot-checked after deploy
  (step 5 above). CLI 59's bundled builder (5.10.1) also lacks the
  http.Server dev detection; CLI 60 + pinned builder 15 works for the HTTP
  path (that is what `pnpm dev:vercel` uses).
- Live WS delivery is a per-connection mailbox poll
  (`SIGNALING_WS_POLL_MS`, default 250 ms): Upstash REST has no
  pub/sub push. Signaling-only latency; connection setup stays well
  inside the 5 s budget.
- The emulator is ephemeral by design (matches production Upstash TTL
  semantics; no persistence).
- **Auth is header-only** (`Authorization: Bearer`): `?token=` on the WS URL
  is rejected (query strings leak into intermediary logs — QA F42b).
- **Device-id takeover** (no-accounts model, QA F38b): a live presence
  refuses a different token, and after presence expiry a previous-owner
  tombstone (TTL = mailbox TTL) keeps refusing other tokens; only after the
  owner has been silent for the mailbox TTL can a new token claim the id
  (bounded, documented DoS window). Acked mail is purged on ack (F38a), so
  only future mail is exposed to a successful squatter. **Accounts note
  (2026-10-01):** the account/roster API now offers a DURABLE identity path
  (username + scrypt verifier + bearer session tokens) that sidesteps this
  window for users who want it — but the ANONYMOUS device-id flow is
  completely unchanged and remains the default; the two coexist on the same
  store.
- **Mailbox eras** (QA F37): after a mailbox-TTL idle gap the per-device seq
  restarts at 1; the service clamps any stale cursor to 0 at the single
  drain choke point and the WS resume path, and the Rust client resets its
  cursor on `hello_ok.latest_seq` regression — covered by contract test 14
  and the `era_restart_resets_cursor_and_delivers` unit test.
