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

## Layout

```
api/signal.ts        Vercel function (Node runtime): http.Server + WSS
api/health.ts        Liveness probe (no store access)
lib/envelope.ts      zod mirror of the Rust envelope contract (THE TS types)
lib/frames.ts        client<->service framing ops (svc_version 1)
lib/service.ts       core logic: presence, dedupe, mailbox, sessions
lib/server.ts        http.Server factory: HTTP fallback + WS transport
lib/store.ts         thin storage seam (interface)
lib/upstash.ts       Upstash Redis REST driver (production + local emulator)
lib/config.ts        env-tunable TTLs/bounds (see .env.example)
lib/log.ts           redaction-safe logging (no envelopes, no tokens, no SDP)
tools/upstash-emulator.mjs  local store (out-of-process, real TTLs)
tools/dev-server.mjs standalone runner of the SAME server (WS tests)
tests/contract.test.ts       16-case contract matrix (spawns everything)
scripts/validate-wires.mjs   fixtures <-> zod mirror validation
fixtures/            golden (Rust-exported) + reject wire fixtures
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
#    b) standalone (WebSocket-capable; same lib/server.ts the function runs):
UPSTASH_REDIS_REST_URL=http://127.0.0.1:38001 UPSTASH_REDIS_REST_TOKEN=local-t \
  pnpm dev:standalone                  # http://127.0.0.1:38013

# 3. Checks:
pnpm test                     # typecheck + wire validation + unit tests
pnpm test:contract            # full matrix (emulator + 2x vercel dev + 2x standalone)
pnpm test:contract:headless   # same matrix, no Vercel toolchain/auth (also in scripts/test.sh)
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
pnpm validate:wires   # TS schemas must accept every golden + reject every reject fixture
```

## Environment variables

See `.env.example` (names + defaults; never commit real values):
`UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`,
`SIGNALING_TTL_DEVICE_SECONDS` (45), `SIGNALING_TTL_MAILBOX_SECONDS` (180),
`SIGNALING_TTL_SESSION_SECONDS` (480), `SIGNALING_TTL_DEDUPE_SECONDS` (120),
`SIGNALING_MAILBOX_MAX` (256), `SIGNALING_MAILBOX_BATCH` (64),
`SIGNALING_ENVELOPE_MAX_BYTES` (32768), `SIGNALING_WS_POLL_MS` (250),
`SIGNALING_MAX_CONNECTION_SECONDS` (290), `SIGNALING_STORE_PREFIX` (`sg1:`).

## The single deploy (USER runs this, at the END of M3)

Everything below is prepared and verified; none of it was executed by the
agent (per plan delta D5 — one cloud deploy, with your accounts):

```bash
cd services/signaling

# 1. Accounts (one-time): create/log in at vercel.com; create an Upstash
#    Redis database (any region near your devices) and copy its REST URL +
#    token from the Upstash console.

# 2. Link this directory to a Vercel project (interactive; uses your login):
vercel link

# 3. Set the production env vars (values from Upstash; never commit them):
vercel env add UPSTASH_REDIS_REST_URL production
vercel env add UPSTASH_REDIS_REST_TOKEN production
#    optional overrides: SIGNALING_TTL_*, SIGNALING_WS_POLL_MS, ...

# 4. The single deploy:
vercel deploy --prod

# 5. Verify (first things after deploy):

# 5a. Liveness (NOTE: /api/health never touches the store — it proves the
#     deployment answers, NOT that Upstash env vars are correct; 5b does):
curl https://<your-deployment>.vercel.app/api/health

# 5b. WS smoke with HEADER auth (query-string tokens are rejected by design;
#     this also exercises the store — a broken Upstash env fails here):
node --input-type=module -e "
import WebSocket from 'ws';
const ws = new WebSocket('wss://<your-deployment>.vercel.app/api/signal?device_id=probe', {
  headers: { authorization: 'Bearer probe-token' },
});
ws.on('open', () => ws.send(JSON.stringify({op:'hello',device_id:'probe',resume_seq:0,svc_version:1})));
ws.on('message', (m) => { console.log(String(m)); process.exit(0); });
ws.on('error', (e) => { console.log('ERR', e.message); process.exit(1); });
"
# Expected: a hello_ok frame. If the upgrade is refused, the HTTP fallback
# still carries M4 (the desktop client tries WS, falls back automatically);
# file the WS-beta gap with Vercel support and retry after a platform bump.

# 5c. Plan-cap check (QA F42a): vercel.json requests maxDuration 300, but
#     plans CLAMP it (Hobby lower than Pro). Check the deployed function's
#     effective maximum duration (dashboard: Project -> Settings ->
#     Functions, or `vercel inspect <deployment-url>`). If the effective cap
#     is below 300 s, pin the graceful-bye bound 10 s under it and redeploy:
vercel env add SIGNALING_MAX_CONNECTION_SECONDS production   # value: <effective-cap> - 10
vercel deploy --prod
#     Without this, WS connections are hard-killed at the plan cap with no
#     bye frame (the client still resumes, but reconnect churns).

# 5d. Idle-gap connect probe (QA F37's scenario against the real service):
#     register a host, leave it idle > SIGNALING_TTL_MAILBOX_SECONDS with
#     only heartbeats, then send it a connect_request from a second device —
#     the consent prompt must appear (era-safe seq handling).
```

The desktop client config for M4 is then simply the deployed base URL
(`RemoteSignalingConfig::new("https://<deployment>.vercel.app", device, token)`).

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
  only future mail is exposed to a successful squatter.
- **Mailbox eras** (QA F37): after a mailbox-TTL idle gap the per-device seq
  restarts at 1; the service clamps any stale cursor to 0 at the single
  drain choke point and the WS resume path, and the Rust client resets its
  cursor on `hello_ok.latest_seq` regression — covered by contract test 14
  and the `era_restart_resets_cursor_and_delivers` unit test.
