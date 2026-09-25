# M3 QA audit — Vercel signaling (RD-009/RD-010)

Date: 2026-09-25 · Auditor: `rd-performance-qa` (read-only) · Tree audited:
`870da33` (service `5486d40` + client `870da33`) · Continues findings from
`docs/reports/m2-qa-audit.md` (F26–F36).

## 1. Verdict

**PASS-WITH-FINDINGS.**

Everything the milestone claims locally is reproducible to the digit: every
gate command is green, all 16 contract cases pass, the two-node Rust
integration passes over WS (2.12 s) and HTTP (standalone 1.35 s; vercel dev
42.76 s — the report's 42.7 s exactly), the zod mirror matches the Rust
contract on every message type, state-in-REST-only holds by construction and
by the two-independent-`vercel dev` cross-instance test, and F27's
register-acked-only-after-write semantics are intact through the remote
adapter. The gate's "against the deployed service" clause remains open by
design (D5: deploy awaits the user's accounts); everything locally
verifiable was verified.

The qualification: one **blocking-for-deploy** correctness bug found by
probing beyond the test matrix (**F37**: after a mailbox idle-expiry the
per-device seq counter restarts while clients keep their acked cursor — an
online host silently misses the next session's `connect_request`), plus a
security should-fix (**F38**: acked mailbox entries — including SDP and an
`accept`'s one-time secret — stay readable for up to the mailbox TTL and are
readable by whoever rebinds the device id after presence expiry), and a
handful of gate/deploy-hygiene items. None of them is exercised by the
current matrix because every test runs inside a single mailbox "era".

## 2. Gate reproduction (all re-run on the audited tree)

| Command | Result | Time |
|---|---|---|
| `cargo fmt --all -- --check` | OK | 0.3 s |
| `scripts/check.sh` (clippy `-D warnings`) | OK | 0.4 s (cached) |
| `scripts/test.sh` (`cargo test --workspace`) | 150 passed / 0 failed | 11.0 s |
| `cargo test --workspace -- --ignored` (rig up: emulator :38001 + standalone :38013) | all runnable ignored tests pass, incl. `two_nodes_connect_through_the_real_service` | 4.8 s |
| same, without `SIGNALING_TEST_BASE_URL` | **panics** (F44 below) | — |
| `pnpm test` (typecheck + `validate:wires` 17/17 + unit 4/4) | OK | 2.5 s |
| `pnpm test:contract` (spawns emulator + 2× `vercel dev` + 2× standalone) | 16/16 | 45.0 s |
| Two-node live, WS, standalone :38013 | PASS — register→Online 91 ms, Connected +1.18 s, total | 2.12 s |
| Two-node live, HTTP-only, standalone :38013 (new measurement) | PASS — Connected +0.52 s, total | 1.35 s |
| Two-node live, HTTP-only, `vercel dev` :38011 | PASS — matches the report's 42.7 s | 42.76 s |

**Decomposition of the 42.7 s** (audit question 5): it is not client poll
cadence. A trivial `POST {op:poll}` through `vercel dev` costs ~0.72 s
(measured, 6 samples, 0.71–0.74 s — the dev bridge's per-request overhead);
the full connect flow is ~60 requests → ~42 s. The same client code against
the standalone server completes in 1.35 s with a 150 ms poll floor
(`HTTP_POLL_MIN_INTERVAL`) and the server's 250 ms live-delivery bound. So
the HTTP fallback itself meets the 5 s connect budget; the 42.7 s is a
dev-tool artifact. WS-primary-as-production-path is stated in
`services/signaling/README.md` and `m3-signaling.md` risk 3. WS upgrade
through `vercel dev` re-verified: `500 InvalidArgumentError: invalid
connection header` (undici bridge), consistent with the documented
limitation.

## 3. Audited-sound (what was checked and held)

**Contract fidelity (audit task 2).** Every message type in
`crates/protocol/src/signaling.rs` was spot-checked against
`services/signaling/lib/envelope.ts`:

- Base fields: `protocol_version` (u16 ↔ int), `message_id`, `session_id`
  (serde `Option` serializes as always-present `null`; TS `.nullable()`
  requires the key — match), `from_device_id`, `to_device_id`,
  `timestamp_ms`. Flat `type` discriminant, no `payload` nesting.
- All 12 body variants and their snake_case tags: `register`, `heartbeat`,
  `connect_request`, `accept`, `reject`, `offer`, `answer`, `ice_candidate`,
  `ice_complete`, `cancel`, `disconnect`, `error`. Enum values match exactly
  (`busy/declined/timeout/unavailable`; `user/collision`;
  `user/timeout/transport_error`; `Hardware/Software` — PascalCase both
  sides; `H264`).
- `ice_candidate.sdp_mid` string / `sdp_mline_index` u16 (`.max(65535)`)
  — the v1 shape; numeric-mid rejected by both sides (fixture
  `v1_ice_numeric_mid.json`).
- Version semantics: raw `protocol_version` checked before body parse
  (mirrors the Rust typed-gate rule); v0 → typed `error{code:400}` envelope,
  never garbage. Error-envelope codes (`ERROR_CODES`) are service-minted
  only; `message_id` namespace `signaling-…` respects the M0 QA F1 rule.
- Capabilities mirror (`capabilities.rs` ↔ TS): field names, `FeatureFlags`
  as plain number, newtype unwrap — match.

Golden-fixture wiring (audit question): the **Rust side is wired** —
`signaling_fixtures.rs` byte-compares inside `cargo test --workspace`, so
Rust-side wire drift fails the merge gate. The **TS side is not wired**:
nothing runs `pnpm test`/`validate:wires` automatically (F41 below); the
report's "enforced in CI both directions" is half true (and CI itself only
runs after a remote exists, D6).

**State-in-REST-only (task 3).** `SignalingService` is stateless (every
method recomputes from the store); `lib/server.ts` holds only sockets,
per-connection poll timers, per-connection `lastSentSeq`/`authed`, and the
diagnostics-only `liveSockets` counter — all reconstructable. No module-scope
cache of presence/mailbox/cursors beyond the store client itself. The
cross-instance test really does span two contexts: contract case 8 uses two
separate `vercel dev` OS processes (separate builders/runtimes) sharing only
the emulator; A→B and B→A both route. Restart-tolerance is covered by case
10 (un-acked redelivery) on the client side.

**F27 (task 5).** Preserved: `node.rs::apply` queues the `Registered`
self-ack only after `SignalingIo::send` returns `Ok` (line ~761), and
`RemoteSignaling::send` returns `Ok` only on a WS `send_result.ok` or an
HTTP 2xx with `ok:true` — a failing register leaves the machine in
`Registering`. Verified by code and by the live test's
`!recorder.has("TransportFailure")` register assertions.

**TTLs vs source plan (task 4).** device 45 s (30–60 ✓), mailbox 180 s
(120–300 ✓), session 480 s (300–600 ✓); dedupe 120 s; all env-tunable with
clamped ranges (`config.ts`). Every store key written carries a TTL.

**Log redaction (task 4).** `lib/log.ts` is the single choke point and types
fields `string | number` — envelope bodies cannot be passed. Reviewed every
call site: `send_rejected`, `mailbox_swept`, `ws_*` failures log
`String(err)` slices from store/service errors (JSON.parse errors are caught
before logging; zod failures log only the issue *path*, not values). WS
frames are never logged; `/api/health` logs nothing. Contract case 16 plus
my own probes (secrets, SDP, store token) found no leak. One caveat: the
auto-check greps only for the three specific literals used in the matrix —
it proves the samples, not the class.

**Payload caps (task 4).** Envelope >32 KiB → 413 (verified). HTTP body
bounded at 1 MiB (`HTTP_BODY_MAX`), WS `maxPayload` 1 MiB, mailbox 256 /
batch 64, drain caps — bounded throughout (invariant 3). Nit: oversize HTTP
bodies get the socket destroyed before the 413 is written, so clients see a
reset, not a typed error (F42c).

**CORS/origin (task 4).** No CORS headers are emitted anywhere and no
`Origin` check exists — cross-origin browser calls fail closed by default
(safe); the WS path accepts `?token=` in the URL as well as the bearer
header (browser-compat; the Rust client uses the header) — F42b.

**Emulator fidelity.** `tools/upstash-emulator.mjs` executes commands
single-threaded (per-command atomicity), enforces TTLs lazily and via a
250 ms sweeper, implements exclusive-min `ZRANGEBYSCORE` + `+INF` +
negative ranks, and preserves TTL across `INCR` — a faithful subset of the
REST pipeline semantics the service uses. The `Store` seam
(`lib/store.ts`) is genuinely thin (14 methods; one unused — see F38).

**One-time secret (task 4).** Single-use is enforced where the protocol
puts it (the host machine's `Requesting→Offering` consumes `Accept` once;
redelivery is post-mortem-tolerated), backed server-side by per-`message_id`
dedupe (`SET NX EX`, atomic) and mailbox TTL bounding replay. Two concurrent
*identical* accepts: exactly one enqueues (SETNX). Two accepts with
*different* `message_id`s both enqueue; the machine drops the second as an
illegal transition — acceptable per the documented design, but note the
secret then sits in the mailbox like any envelope (see F38).

## 4. Findings (F37–)

Severity labels: **blocking-for-deploy** / **blocking-for-M4** /
should-fix / note. Repro commands in §6.

### F37 — Mailbox seq-era collision: silent non-delivery after an idle gap — blocking-for-deploy (fix before the single deploy; blocks M4)

`enqueue` refreshes the `mbseq` counter's TTL to the mailbox TTL
(`expireAfterIncr`), and `mb`/`mbc` carry the same TTL — so after
`SIGNALING_TTL_MAILBOX_SECONDS` (default 180 s) **with zero inbound mail**
(heartbeats do not refresh `mbseq`), all three keys expire together and the
counter restarts at 1. Every consumer then filters by a cursor from the
previous era:

- HTTP: `drain` → `ZRANGEBYSCORE (after_seq +INF` — new entries at seq 1..N
  are invisible to a client holding `after_seq` = old cursor;
- WS reconnect: `resumeSeq = max(hello.resume_seq, storedCursor)`
  (`server.ts:294`) — the client's `acked_seq` (`AtomicU64`, never reset)
  wins and the era-2 entries are filtered;
- live WS connection: per-connection `lastSentSeq` from era 1 keeps
  filtering.

The Rust client never resets `acked_seq` and ignores `hello_ok.latest_seq`
(the datum that would reveal the regression). Net effect: **a host that
stays online through a ≥3-minute quiet period will not see the next
session's `connect_request`** — the controller sees a successful send, the
host never prompts consent, no error anywhere. Demonstrated empirically
(short-TTL instance, §6): `poll after_seq=1` → `envelopes: []` for an entry
enqueued at seq 1 after expiry; `after_seq=0` (fresh process) sees it.
No current test catches it because every test runs inside one era.

Affected: `services/signaling/lib/service.ts` (`enqueue`,
`expireAfterIncr`), `lib/server.ts` (`resumeSeq`, `lastSentSeq`),
`crates/node-runtime/src/signaling_remote.rs` (`acked_seq`,
`handle_server_frame`'s `last_delivered_seq` filter, unused
`hello_ok.latest_seq`). Fix is cheap on either side: persist (or long-TTL /
epoch-qualify) `mbseq`, or have the client reset its cursor when
`hello_ok.latest_seq < acked_seq` (redelivery is already dedupe-safe).

### F38 — Acked mailbox entries are retained and readable; presence-expiry token takeover reads them — should-fix (before deploy recommended)

(a) `service.ack()` advances the cursor but never purges delivered entries —
they survive until the mailbox TTL sweeps them. `Store.zremrangebyscoreMax`
exists **exactly** for this and is never called (dead code marking the
missing step). Combined with (b):

(b) `register`/`heartbeat` re-bind an *expired* presence with **any** token
(by design — "idempotent re-register after TTL lapse"). Probed: after
presence expiry an attacker heartbeat with a different token returns 200,
the victim's own re-register then gets 401 (lockout until the attacker
stops heartbeating), and the attacker can `poll` the victim's mailbox —
including **acked-but-retained SDP offers and any un-acked `accept`
carrying the one-time session secret** — for up to the mailbox TTL
(default 180 s) after takeover. Preconditions: knowledge of the device id
and a ≥45 s presence lapse; inherent to the no-accounts model, but the
retention in (a) extends the blast radius from "future mail" to "recent
past mail".

Fix: purge ≤ acked seq on ack (one call to the existing primitive); that
alone caps (b) at un-acked entries. Document the takeover window as an
accepted MVP risk (a device-id squatter can also DoS an id).

### F39 — The different-token rebind-refusal branch has no contract-test coverage — should-fix

Contract case 2's "hijack" probe re-sends the register with the **same**
token (`hdr(device)`), so `existing.th !== th → unauthorized`
(`service.ts` `register`/`heartbeat`) is never exercised by the matrix. I
probed it manually (live presence + different token → 401, both for
register and poll). One-line addition to `tests/contract.test.ts`; without
it, a future refactor of the refusal path would pass the matrix silently.

### F40 — Client inbound-overflow path contradicts its contract and loses envelopes — should-fix

`signaling_remote.rs` docs say overflow (512-cap inbound queue) "drops the
connection and entries re-deliver on resume". The code does none of that:
`handle_server_frame` merely counts when `push_inbound` returns false —
the socket stays up, so the server's per-connection `lastSentSeq` advances
past the dropped entries; and even after a reconnect the actor's
`seq <= *last_delivered_seq` filter discards the redelivery. The envelopes
are then unrecoverable until mailbox expiry (and F37 makes the cursor story
worse). Also the overflow is counted as `send_errors` — inbound loss
reported as a send error (telemetry distortion). Fix: actually close the
socket on overflow and reset `last_delivered_seq` to the *acked* (not
last-seen) seq on reconnect; count a dedicated counter.

### F41 — The TS service gate is not wired into any automated gate — should-fix

`scripts/check.sh`, `scripts/test.sh`, and `.github/workflows/ci.yml` run
only cargo commands. `pnpm test` (typecheck + `validate:wires` + unit) is
manual-only, so a TS-side schema/logic edit — exactly the half of the D7
contract that lives in TypeScript — is caught only if someone remembers.
Add `pnpm --dir services/signaling test` to `scripts/test.sh` (and CI,
with a node/pnpm setup step). The m3 report's "enforced in CI both
directions" overstates this.

### F42 — Deploy-readiness nits that bite on the first real deploy — should-fix

(a) **Plan-cap vs bye**: `vercel.json` requests `maxDuration: 300` with
`SIGNALING_MAX_CONNECTION_SECONDS=290` default. The m3 report knows plans
clamp (risk 2), but the README deploy section never operationalizes it —
no step verifies the effective cap or sets the env var. On a plan clamped
to 60 s, every WS is hard-killed at 60 s with no `bye` (the client still
resumes, but reconnect churns and the graceful path is never exercised).
Add to README step 5: check the deployed function's effective maxDuration;
if < 300, `vercel env add SIGNALING_MAX_CONNECTION_SECONDS <cap-10>`.
(b) `?token=` on the WS URL is accepted (browser-compat) — query strings
can reach intermediary logs; consider header-only once M4 confirms no
browser client. (c) An HTTP body over 1 MiB gets `req.destroy()` before the
413 is written — clients see a connection reset, not the typed error
(verified: `ConnectionResetError` client-side). (d) `/api/health` never
touches the store, so a deploy with broken Upstash env passes health; the
README's WS smoke happens to catch it (`hello_ok` path calls
`service.cursor`), which is fine but indirect — a one-line note would
prevent false confidence.

### F43 — Server/client small nits — note

(a) `liveSockets` leaks on the early-exit WS paths (unauthorized,
hello-timeout, hello device-mismatch return before the decrementing
`close` handler is registered) — diagnostics-only over-report. (b)
`service.ack` is GET-then-SET: concurrent acks can regress the cursor
(benign redelivery; the comment says "only lag" but it can also move
backwards). (c) `upstash.zrangebyscore`'s `maxExclusive` parameter is dead
(always `+INF`). (d) `http_json` builds a fresh `ureq::Agent` per call —
one TCP/TLS handshake per HTTP-fallback request (fine at signaling rates;
revisit if M5 tightens negotiation). (e) The actor's `pending` map grows
without bound against a server that never answers `send_result` (swept
only on disconnect) — invariant-3 hygiene on a hostile-server path.
(f) `RemoteCounters.received` counts only WS deliveries; HTTP-mode
receives are invisible (`describe()` shows `recv=0`). (g)
`secure_random_hex`'s getrandom-failure fallback is a predictable LCG with
no runtime flag (comment claims one) — unreachable on Windows in practice.
(h) `Drop` for `RemoteSignaling` can block up to the 8 s backoff/10 s
connect timeout joining the actor.

### F44 — `cargo test --workspace -- --ignored` now fails without the signaling rig — should-fix (gate regression)

M2's audit ran that command clean as the "real hardware + live SendInput"
sweep. The new `remote_signaling_live` test `.expect`s
`SIGNALING_TEST_BASE_URL` and panics without it (verified). Make it skip
gracefully (print + pass when the env is absent) or document the rig
requirement in AGENTS.md's command list.

### F45 — Dedupe tombstone-before-enqueue crash window — note

`sendEnvelope` does `SET NX EX dd:…` **then** `ZADD`. If the function dies
between them, the sender's retry of the same `message_id` gets
`{ok:true, duplicate:true}` while the mailbox never received the entry —
an at-most-once hole inside the at-least-once contract, until the machines
mint a fresh `message_id` (which they don't on a successful duplicate
reply). Low probability on serverless; fix by pipelining SETNX+ZADD (the
Upstash pipeline supports multi-command batches) or verifying ZCARD on the
duplicate path.

### F46 — The `force_http` actor busy-spins — should-fix (test-mode only)

With `force_http=true` the actor loop's `ws.is_none() → continue` path has
no sleep: intake → continue → intake, at 100% of one core per node for the
process lifetime. The production fallback (WS down, `force_http=false`)
sleeps in reconnect backoff and is unaffected, but the HTTP-only rig mode
burns a core per node and pollutes any CPU measurements taken in that mode
(the 42.7 s vercel-dev run ran with two spinning cores). One
`thread::sleep` on that path fixes it.

### F47 — TS mirror is silently stricter than the Rust contract — note

`envelope.ts` adds constraints Rust does not declare: `message_id ≤ 128`,
device ids ≤ 64, `offer/answer.sdp` non-empty, `session_id` non-empty when
present. All currently satisfied by every emitter, but a future Rust-side
id mint outside those bounds would be service-rejected with a 422-shaped
`malformed` rather than a contract error. One comment in
`crates/protocol/src/signaling.rs` (or a shared limits constant) would
make the tightening deliberate.

## 5. M3 report claim-check

| Claim (`m3-signaling.md`) | Assessment |
|---|---|
| Gates green at final tree | Reproduced exactly (§2) |
| 16/16 contract matrix in ~45 s | Reproduced (45.0 s) |
| validate:wires 17/17 | Reproduced (2.5 s incl. typecheck) |
| WS two-node 2.1 s / HTTP-only 42.7 s via vercel dev | Reproduced (2.12 s / 42.76 s); decomposition added (§2) |
| "enforced in CI both directions" | Half true — Rust fixture byte-compare is in `cargo test --workspace`; TS validation runs nowhere automatic (F41) |
| "state never authoritative in function memory" | Holds by construction + cross-instance test (§3) |
| Single-use secret "pinned by contract test 14" | Pinned for the same-`message_id` retry; different-id replay relies on machine illegal-transition drops (§3); retention risk F38 |
| "no rate limiting yet (size/count caps only)" | Accurate; also no per-device send-rate cap — the 32 KiB × mailbox-256 bounds are the only brake |
| TTL defaults per source-plan ranges | Verified (§3) |
| Local-Redis approach (emulator) | Fidelity verified (§3) |

## 6. Reproduction index

```bash
# Gates
cargo fmt --all -- --check && scripts/check.sh && scripts/test.sh   # 150 pass
cd services/signaling && pnpm test && pnpm test:contract            # 4+17, 16/16

# Two-node live (rig)
node services/signaling/tools/upstash-emulator.mjs --port 38001 &
UPSTASH_REDIS_REST_URL=http://127.0.0.1:38001 UPSTASH_REDIS_REST_TOKEN=t \
  node --import tsx services/signaling/tools/dev-server.mjs --port 38013 &
SIGNALING_TEST_BASE_URL=http://127.0.0.1:38013 \
  cargo test -p node-runtime --test remote_signaling_live -- --ignored --nocapture
# HTTP fallback variants: add SIGNALING_TEST_HTTP_ONLY=1; point at a
# `vercel dev --local --listen 127.0.0.1:38011` instance for the 42.7 s path.

# F37 (seq-era collision): standalone with SIGNALING_TTL_MAILBOX_SECONDS=2,
# then: register a,b; a->b offer (seq 1); b polls + acks 1; sleep 3 s;
# a->b second offer (new message_id) -> seq 1 again; b poll after_seq=1
# returns [] while after_seq=0 returns the envelope. (Full python one-liner
# in the audit transcript; requires only curl-equivalent POSTs.)

# F38: same rig, SIGNALING_TTL_DEVICE_SECONDS=2: register victim tokA;
# register with tokB -> 401 (the untested branch, F39); sleep 2.5 s;
# heartbeat with tokB -> 200 (rebind); victim re-register tokA -> 401;
# poll with tokB -> 200 with retained entries (send an offer before expiry).

# F44: cargo test -p node-runtime --test remote_signaling_live -- --ignored
# (no env) -> panics at remote_signaling_live.rs:215.

# F46: SIGNALING_TEST_HTTP_ONLY=1 run; observe one full core per node in
# Task Manager (actor thread), vs idle in WS mode.
```

## 7. Recommendation

**PASS-WITH-FINDINGS.** Tag nothing yet: land F37 (blocking — one small
server- or client-side patch plus an era-crossing contract test), and
preferably F38's ack-purge, F39's missing matrix case, F41 (gate wiring),
F42a (README plan-cap step), F44 (graceful skip), and F46 (spin) — all
small, all before the single deploy, since the deploy is the next planned
action and post-deploy smoke tests will not exercise any of them. F40, the
F43/F45/F47 notes can ride into M4. The M4 `sender_role` additive-field
proposal (report decision 8) is the right call — the learned-role fallback
is correct under guaranteed ordering but is one lost `accept` away from a
misrouted `disconnect`, and the inference is already client-side only.

Post-deploy first actions (unchanged from the report, plus one): the WS
smoke, the plan-cap check (F42a), and one idle-gap connect probe (F37's
scenario) against the deployment.
