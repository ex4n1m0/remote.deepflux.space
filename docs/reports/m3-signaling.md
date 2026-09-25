# M3 — Vercel signaling service (RD-009/RD-010)

Date: 2026-09-24 · Owner: `rd-vercel-signaling-engineer` · State: complete,
local gate green; single cloud deploy prepared but NOT executed (delta D5 —
needs the user's Vercel/Upstash accounts).

## What landed

- `services/signaling/` — the control-plane service: Vercel Node-runtime
  functions (WebSocket primary + HTTP polling fallback), all state in an
  external ephemeral store, env-tunable TTLs, contract tests, Upstash REST
  emulator for local dev, deploy prep.
- `crates/node-runtime/src/signaling_remote.rs` — additive `SignalingIo`
  client (WS actor thread + HTTP fallback, resumable sessions, learned
  sender roles). No trait changes; no changes to `protocol`/`session`.
- `crates/node-runtime/tests/signaling_fixtures.rs` — golden wire fixtures
  exported from the Rust contract, enforced in CI both directions.
- `crates/node-runtime/tests/remote_signaling_live.rs` — `#[ignore]`d
  two-node integration through the real service.

Modified existing files: `Cargo.toml` (+`tungstenite 0.26.2`, `native-tls
0.2.14`, `ureq 2.12.1`, `getrandom 0.3.3` workspace pins), root
`.gitignore` (+`node_modules/`), `crates/node-runtime/Cargo.toml` (same
deps), `crates/node-runtime/src/lib.rs` (module + re-exports, 2 lines),
`services/signaling/README.md` (placeholder → real). Nothing else touched;
nothing committed; no tags.

## Architecture (local verification topology)

```
                       ┌────────────────────────────┐
                       │ Upstash REST emulator      │  tools/upstash-emulator.mjs
                       │ (out-of-process, real TTLs)│  :38001
                       └───────▲────────▲───────────┘
                               │        │  (same REST protocol as production Upstash)
              ┌────────────────┘        └────────────────┐
   ┌──────────┴──────────┐                    ┌──────────┴──────────┐
   │ vercel dev #1 :38011│  cross-instance    │ vercel dev #2 :38012│  (independent builder
   │ (Vercel pipeline)   │◄──────────────────►│                     │   instances)
   └─────────────────────┘                    └─────────────────────┘
   ┌─────────────────────┐                    ┌─────────────────────┐
   │ standalone :38013   │  WS-capable        │ standalone :38014   │  short TTLs (1s/2s/1s,
   │ (same lib/server.ts)│                    │ (same, short TTLs)  │  max-conn 3s) — expiry matrix
   └─────────────────────┘                    └─────────────────────┘
```

Key decisions:

1. **One protocol, one driver.** The service speaks the documented Upstash
   Redis REST pipeline format (`POST /pipeline`, `[{"command":[...]}]`)
   through `lib/upstash.ts`. Production points at real Upstash; local dev
   points the same driver at the emulator. No second (RESP) code path.
2. **Store seam.** `lib/store.ts` is a ~15-method interface (string KV with
   TTL + one capped ZSET shape). The whole service composes from it; a
   different backend is a single-file adapter.
3. **Redis schema** (prefix `sg1:`, every key TTL'd):
   `p:{device}` presence `{v,th:sha256(token)}` EX device-TTL (raw token
   never stored); `mb:{device}` ZSET mailbox (score = per-device monotonic
   seq from `INCR mbseq:{device}`, member embeds enqueue-ms + verbatim
   envelope), capped by rank and logically expired by enqueue age;
   `mbc:{device}` acked-seq cursor (the resume point); `dd:{from}:{mid}`
   SET-NX-EX dedupe tombstones; `s:{session}` minimal pair record EX
   session-TTL, DEL on `disconnect`.
4. **Delivery contract.** At-least-once until the consumer acks; acks
   happen at handoff to the node (`poll_incoming`), never on wire receipt,
   so a crash between delivery and processing re-delivers and the machines'
   `message_id` dedupe (pinned by `crates/session`) no-ops it. Exact
   re-ENQUEUE of a seen `(from, message_id)` is suppressed server-side
   within the dedupe window (RD-010 "idempotency by messageId").
5. **Instance-local state is non-authoritative by construction.** Sockets,
   per-connection poll timers, and each connection's last-delivered seq
   live in the function instance; everything else is in the store. The
   cross-instance test proves it (two independent `vercel dev` servers
   route through the shared store).
6. **Auth bootstrap.** `Register`/`Heartbeat` are the only ops exempt from
   the authenticate-first rule (they bind/verify the token); a live
   presence bound to a different token refuses rebind until it expires.
   Unauthenticated callers can never mint `Error` envelopes into anyone's
   mailbox.
7. **Session-secret single-use** is enforced where the protocol puts it:
   the host machine consumes `Accept` exactly once (`Requesting→Offering`;
   redelivery is post-mortem-tolerated), and the service guarantees at most
   one mailbox entry per `message_id` plus mailbox TTL bounding replay.
   Pinned by contract test 14 and the live integration's duplicate probe.
8. **Learned sender roles (client-side).** The envelope contract carries no
   sender-role field and `crates/protocol` is out of M3 scope, so
   `RemoteSignaling` learns each session's peer role from the definitive
   types (`connect_request`/`offer`/`cancel` → Controller;
   `accept`/`reject`/`answer` → Host) and applies it to
   role-ambiguous `ice_candidate`/`disconnect`/`ice_complete`. The state
   machines guarantee the definitive message precedes the ambiguous ones.
   **M4 change request:** add an additive-optional `sender_role` field
   (allowed within v1 per the serde policy) and delete the inference.
9. **Service-frame protocol** (`lib/frames.ts`, `svc_version` 1): WS
   `hello`→`hello_ok{authed,resume_seq}` / `send`→`send_result{ok,
   duplicate}` / `deliver{seq,envelope}` / `ack{seq}` / `bye{reason}`; the
   HTTP fallback POSTs the same ops to the same path. A graceful
   `bye{max_duration}` precedes every server-initiated close (default
   290 s < the 300 s `maxDuration`), and the client resumes from its acked
   seq.

## TTL / bound decisions (env-tunable, defaults per source-plan ranges)

| Knob | Default | Range | Rationale |
|---|---|---|---|
| `SIGNALING_TTL_DEVICE_SECONDS` | 45 | 30–60 | Client heartbeat is 15 s (SessionConfig default) → two missed beats tolerated |
| `SIGNALING_TTL_MAILBOX_SECONDS` | 180 | 120–300 | Offline-window delivery vs replay bound |
| `SIGNALING_TTL_SESSION_SECONDS` | 480 | 300–600 | Covers request(10s)+consent(30s)+connect(10s) with margin |
| `SIGNALING_TTL_DEDUPE_SECONDS` | 120 | — | > max client retry storm, < mailbox TTL |
| `SIGNALING_MAILBOX_MAX` / `_BATCH` | 256 / 64 | — | Bounded queues (invariant 3) |
| `SIGNALING_ENVELOPE_MAX_BYTES` | 32 768 | — | SDP fits comfortably; hostile frames rejected pre-parse |
| `SIGNALING_WS_POLL_MS` | 250 | 50–10 000 | Live-delivery poll (REST has no push) |
| `SIGNALING_MAX_CONNECTION_SECONDS` | 290 | — | `bye` before the 300 s function `maxDuration` |

## Local-Redis approach (what was verified)

No Docker, WSL, `redis-server`, or Memurai exists on this machine, and
Upstash's REST API cannot target a local Redis binary. Instead of a
RESP-based second driver that would only ever run locally, the emulator
(`tools/upstash-emulator.mjs`, plain Node) implements the exact Upstash
REST pipeline subset the service uses, **as a separate process** with real
TTLs — matching production semantics (ephemeral, shared across function
instances, survives instance restarts). Verified: register/presence
expiry, mailbox TTL sweep, dedupe tombstones, cross-instance routing
between two `vercel dev` servers, and reconnect-resume all behave
identically through it. If a real local Redis becomes available, only
`lib/upstash.ts`'s transport would need a RESP sibling — the `Store` seam
isolates it.

## Contract-test matrix (all green, run by me, 2026-09-24)

`pnpm test:contract` — 16/16 in ~45 s (spawns emulator + 2× `vercel dev
--local` + 2× standalone instances itself):

| # | Case | Target | Result |
|---|---|---|---|
| 1 | Health/version probes | all | PASS |
| 2 | Register presence; wrong token 401; re-register with same token ok | vdev A | PASS |
| 3 | Peer send → HTTP poll delivery | vdev A | PASS |
| 4 | Duplicate `message_id`: one mailbox entry; second send `duplicate:true`; at-least-once re-poll | vdev A | PASS |
| 5 | v0 rejection: HTTP 400 + typed `error{code:400}` envelope; v0 payload never delivered | vdev A | PASS |
| 6 | Bogus target 404 + error envelope; forged `from_device_id` 403; missing bearer 401 | vdev A | PASS |
| 7 | Session-scoped type without `session_id` → 400 | vdev A | PASS |
| 8 | **Cross-instance**: A→B and B→A between two independent dev servers via shared store | vdev A+B | PASS |
| 9 | WS hello/register/live-push/ack; reconnect resume-from-cursor (no redelivery below ack) | standalone | PASS |
| 10 | WS un-acked redelivery on reconnect (at-least-once), then ack stops it | standalone | PASS |
| 11 | `bye{max_duration}` at 3 s → clean immediate resume + re-register | short-TTL | PASS |
| 12 | Stale presence: expired target → typed 404 error envelope | short-TTL | PASS |
| 13 | Mailbox TTL expiry: undelivered entries vanish | short-TTL | PASS |
| 14 | Session-secret single-use: exactly one accept entry; re-send deduped; disconnect propagates | vdev A | PASS |
| 15 | WS/HTTP parity (HTTP→WS push and WS→HTTP poll on one instance) | standalone | PASS |
| 16 | No session secret / SDP / store token anywhere in service logs | all | PASS |

Wire contract: `pnpm validate:wires` — 17/17 (13 golden fixtures accepted
by the TS zod mirror + additive-field tolerance; 4 reject fixtures fail
exactly as documented: v0 version-gated, numeric-mid / unknown-type /
camelCase schema-invalid). Golden fixtures regenerate only via
`UPDATE_SIGNALING_FIXTURES=1 cargo test -p node-runtime --test
signaling_fixtures`; without the flag the test byte-compares, so
Rust-side drift fails CI.

Two-node Rust integration (`cargo test -p node-runtime --test
remote_signaling_live -- --ignored`, real `Node` machines + scripted
transport over the real service):

| Mode | Target | Result |
|---|---|---|
| WebSocket | standalone :38013 | PASS in 2.1 s (register → connect_request → consent → accept+secret → offer → answer → trickle ICE both ways → Connected → disconnect; 0 illegal transitions; duplicate-accept probe deduped + post-mortem no-op) |
| HTTP-only (`SIGNALING_TEST_HTTP_ONLY=1`) | vercel dev :38011 | PASS in 42.7 s (same flow over the polling fallback through the Vercel pipeline) |

Gates at the final tree: `cargo fmt --all -- --check` OK ·
`cargo clippy --workspace --all-targets -- -D warnings` OK ·
`cargo test --workspace` 150 passed / 0 failed (+1 ignored = the live rig
test) · `pnpm test` (typecheck + validate-wires 17 + unit 4) OK.

## Deploy (user runs; agent did not execute — see services/signaling/README.md)

`vercel link` → `vercel env add UPSTASH_REDIS_REST_URL/TOKEN production` →
`vercel deploy --prod` from `services/signaling/` → verify `/api/health`
→ run the README's one-line WS smoke against the deployment. Local
`vercel dev` runs used `--local` only (no project link, no deploy).

## Risks / known issues for M4

1. **WS through `vercel dev` is impossible locally** (verified against CLI
   59 and 60): the @vercel/node dev bridge proxies plain HTTP only — its
   `compileUserCode`/`undici` handler has no `upgrade` path, so upgrades
   reset. The WS transport was therefore verified against
   `tools/dev-server.mjs`, which runs the SAME `lib/server.ts` module the
   function exports, and the current cloud docs (http.Server default
   export + `listen()` capture) match what `api/signal.ts` ships.
   **First post-deploy action: the README WS smoke.** If the cloud also
   refuses the upgrade, the HTTP fallback carries M4 unchanged (the Rust
   client falls back automatically); retest after the next platform/CLI
   bump. Also note: CLI 59's bundled builder (5.10.1) cannot run the
   http.Server export shape in dev at all — use the pinned project-local
   `vercel@60` + `@vercel/node@15.0.0` (`pnpm dev:vercel`).
2. **`maxDuration` caps by plan** (Hobby < Pro < Enterprise): the 300 s in
   `vercel.json` may be clamped. The `bye`-at-`SIGNALING_MAX_CONNECTION_
   SECONDS` knob must be set below the plan's real cap after deploy.
3. **Live-delivery latency is poll-bounded** (default 250 ms): fine for
   signaling (setup < 5 s budget measured at ~2 s over WS), but if M5
   wants faster negotiation, options are Upstash's RESP pub/sub (new
   driver behind the `Store` seam) or lowering `SIGNALING_WS_POLL_MS`.
4. **No per-device rate limiting yet** beyond size/count caps (envelope ≤
   32 KiB, mailbox ≤ 256, batches ≤ 64, inbound queue ≤ 512 with
   disconnect-on-overflow). A Redis token bucket is a contained follow-up
   if abuse shows up post-deploy.
5. **Single Upstash region**: latency for far-away devices; acceptable for
   MVP, revisit at M5.
6. **Learned sender roles** (decision 8): correct under the machines'
   guaranteed ordering; replace with the additive `sender_role` field in
   M4 (contract change request, additive-optional within v1).
7. **Client caveat**: `RemoteSignaling` acks at handoff, so a crash after
   handoff but before the machine consumed the envelope can no-op on
   redelivery only via the machines' dedupe — which is the pinned
   contract; no action needed, documented for reviewers.
