# M3 QA fix package — F37–F46 per `docs/reports/m3-qa-audit.md`

Date: 2026-09-25 · Follow-up to the M3 QA audit (verdict PASS-WITH-FINDINGS,
F37–F47). All deploy-blocking and should-fix findings landed; the note-level
findings F43/F45/F47 are addressed where they were one-liners (see the
disposition table). Everything below is verified locally by re-run gates and
new tests. The tree is NOT tagged: `m3-vercel-linking` waits for the
deployed-service verification (QA's recommendation).

## Per-finding disposition

| # | Disposition |
|---|---|
| F37 (blocking) | **Fixed on both sides.** Server: `drain()` clamps any cursor above the current `latestSeq` to 0 at the single choke point both transports use (era restart detection); the WS hello path does the same for `max(hello.resume_seq, storedCursor)`; a live connection whose `drained.latestSeq` regresses below its `lastSentSeq` resets to 0 and redelivers. Client (`signaling_remote.rs`): `hello_ok.latest_seq` below the acked cursor resets `acked_seq`; a `deliver` seq regression resets the redelivery filter (per-device seq is monotonic within an era, so regression ⇒ era restart or benign duplicate — at-least-once + machine dedupe absorbs both). Redelivery overlap is safe by the pinned `message_id` dedupe contract. Evidence: contract test 14 (`mailbox-era crossing`: stale HTTP cursor delivers; stale WS resume gets `hello_ok.resume_seq=0` + delivery) and unit test `era_restart_resets_cursor_and_delivers` (two-era double). |
| F38a | **Fixed.** `service.ack()` now purges everything ≤ the acked seq via the previously-dead `zremrangebyscoreMax` primitive — accepted SDP/secret material no longer lingers for the mailbox TTL. Evidence: contract test 4 asserts a post-ack poll from 0 returns nothing. |
| F38b | **Fixed (tombstone policy).** `register`/`heartbeat` share one `bindPresence`: a live presence refuses a different token, and an EXPIRED presence also refuses while the previous-owner tombstone (`po:{device}`, TTL = mailbox TTL, refreshed on every successful write) lives. The legitimate owner rebinds immediately; a new token can claim the id only after the owner was silent for the mailbox TTL (documented bounded DoS window — inherent to the no-accounts model; with ack-purge, only future mail is exposed). Evidence: contract test 15 (attacker register/heartbeat/poll all 401 inside the window; owner rebind 200; post-tombstone claim 200). |
| F39 | **Fixed.** Contract test 2 now exercises the different-token refusal for register AND heartbeat against a live presence (the old probe reused the same token), and test 15 covers the expired-presence branch. |
| F40 | **Fixed.** Inbound overflow (`push_incoming` false) now returns `false` from `handle_server_frame` → the actor closes the socket, `note_disconnect` runs, and the reconnect resumes from the ACKED cursor (the redelivery filter restarts from `resume` on every connect). Dedicated `inbound_overflow` counter (was miscounted as `send_errors`). Evidence: unit test `inbound_overflow_drops_socket_and_redelivers` (540-envelope flood > 512-cap: socket drop observed, reconnect redelivers, all 540 unique envelopes arrive, `inbound_overflow ≥ 1`). |
| F41 | **Fixed.** `scripts/test.sh` now runs, after `cargo test --workspace`: `pnpm --dir services/signaling install --frozen-lockfile`, `pnpm --dir services/signaling test` (typecheck + validate-wires + unit), and `pnpm --dir services/signaling run test:contract:headless`. CI (`.github/workflows/ci.yml`) gained pnpm/node steps and the same chain. Headless mode (`CONTRACT_NO_VERCEL=1`): the matrix runs against the emulator + standalone instances only (cross-instance spans two standalone processes), so no Vercel auth/toolchain is needed; `pnpm test:contract` (full mode) still spans two `vercel dev` pipelines. The m3 report's "enforced in CI both directions" claim is now true: Rust fixtures byte-compare inside `cargo test`, TS schemas validate inside the same gate. |
| F42 | **Fixed.** (a) README deploy step 5 is now 5a–5d: health (with the explicit note that `/api/health` never touches the store), header-auth WS smoke (which does exercise the store), the **plan-cap check** — if the effective `maxDuration` < 300, `vercel env add SIGNALING_MAX_CONNECTION_SECONDS <cap-10>` and redeploy — and an idle-gap connect probe (F37's scenario against the deployment). (b) `?token=` on the WS URL is rejected; header-only auth (contract test 18). (c) Oversize HTTP bodies get a typed 413 JSON reply (bounded drain of the remaining upload instead of an immediate destroy — the destroy raced the client's upload and intermittently surfaced as a reset; contract test 19 pins the JSON). One caveat: through the `vercel dev` bridge the same early-answer surfaces as a 500 from the proxy, so the test targets the standalone instance of the same `lib/server.ts` (documented in the test). |
| F43 | **Notes, cheap ones fixed:** (a) `liveSockets` counted on every exit path (one decrementing close handler at connection level); (c) `Store.zrangebyscore`'s dead `maxExclusive` parameter removed; (e) `pending` bounded at 128 with an explicit error to the evicted waiter; (f) HTTP-mode receives now count toward `received`. Not addressed (M4): (b) ack cursor compare-then-set races (benign redelivery, documented), (d) per-call `ureq` agents, (g) CSPRNG fallback flag, (h) Drop join budget. |
| F44 | **Fixed.** `remote_signaling_live` prints `SKIP remote_signaling_live: SIGNALING_TEST_BASE_URL not set (…)` and passes when the env is absent; `cargo test --workspace -- --ignored` is green bare (verified). |
| F45 | **Fixed.** Dedupe tombstones now carry state: `'P'` (pending, written before enqueue) → the assigned seq (after) → `'A'` (consumed — marked by `ack()` when it purges the entry, in one batched `setExMany` round trip). On a duplicate hit: `'A'` ⇒ true duplicate; a seq still present in the mailbox ⇒ true duplicate; anything else (crash between SETNX and ZADD, or the entry vanished) ⇒ **repair**: re-enqueue under a fresh tombstone. Evidence: contract test 20 deletes the mailbox key via the emulator's REST API (the crash-window state) and asserts the retry re-enqueues (`duplicate:false`) and delivers. The interaction with F38a (ack-purge making consumed entries absent) is exactly what the `'A'` state resolves — caught by the live two-node duplicate probe. |
| F46 | **Fixed.** The socketless actor pass (HTTP-only mode) sleeps one read-timeout tick (50 ms) instead of spinning; sends still process each pass. |
| F47 | **Documented, not changed:** the TS mirror's deliberate tightenings (id lengths, non-empty SDP, non-empty session ids) are now called out in `lib/envelope.ts` comments; touching `crates/protocol` is outside this package's allowed surface — the shared-limits constant belongs to the M4 `sender_role` contract change. |

## New/changed test evidence

| Test | What it proves | Result |
|---|---|---|
| contract 14 `mailbox-era crossing` | F37 end-to-end: stale HTTP cursor and stale WS resume both see era-2 mail; `hello_ok.resume_seq` resets to 0 | PASS |
| contract 15 `token takeover … tombstone window` | F38b/F39: different-token rebind refused live AND after expiry; owner rebinds; bounded post-tombstone window | PASS |
| contract 4 (extended) | F38a: acked entries purged | PASS |
| contract 18 `WS header-only auth` | F42b: `?token=` never reaches `hello_ok` | PASS |
| contract 19 `typed 413` | F42c: JSON reply, no reset | PASS |
| contract 20 `dedupe crash window` | F45: vanished entry repaired (`duplicate:false`), delivered | PASS |
| unit `era_restart_resets_cursor_and_delivers` | Rust client: `hello_ok.latest_seq` regression resets the cursor; era-2 deliver accepted + acked | PASS |
| unit `inbound_overflow_drops_socket_and_redelivers` | F40: overflow drops the socket; reconnect from acked cursor; all 540 envelopes recovered; dedicated counter | PASS |
| live `two_nodes_connect_through_the_real_service` | Whole-stack regression incl. the duplicate-accept probe against the F38a/F45 interaction | WS standalone **2.15 s**, HTTP-only standalone **1.44 s**, HTTP-only `vercel dev` **43.28 s** — all PASS |

## Gate tails (final tree)

```
$ cargo fmt --all -- --check                 # OK
$ ./scripts/check.sh                         # clippy -D warnings: Finished, 0 errors
$ ./scripts/test.sh
  cargo test --workspace                     # 152 passed / 0 failed / 0 ignored (+1 live test skip-capable)
  pnpm --dir services/signaling test         # typecheck OK; validate-wires 17/17; unit 4/4
  test:contract:headless                     # 21/21 (emulator + standalone instances only)
$ pnpm --dir services/signaling test:contract  # FULL mode: 21/21 (2x vercel dev + standalone x2)
$ cargo test --workspace -- --ignored       # bare: PASS (SKIP line for the rig test)
  with rig (WS / HTTP-standalone / HTTP-vercel-dev): 3/3 PASS
```

Stability note: the two heavyweight WS-double unit tests serialize on a
static mutex and carry generous budgets — this machine shares cores with
unrelated long-running dev servers (visible in Task Manager), which
occasionally stalls thread scheduling by seconds; 8 consecutive runs green.

## Files touched

- `services/signaling/lib/service.ts` (era clamp, ack purge + tombstone marking, `bindPresence` takeover policy, F45 tombstone states)
- `services/signaling/lib/server.ts` (resume/deliver era reset, header-only WS auth, typed 413 + bounded drain, socket accounting)
- `services/signaling/lib/store.ts` / `lib/upstash.ts` (`zrangebyscore` signature cleanup, `setExMany` batch)
- `services/signaling/tests/contract.test.ts` (21 cases, headless mode), `scripts/contract-headless.mjs`, `scripts/validate-wires.mjs` (unchanged), `README.md` (5a–5d + notes)
- `crates/node-runtime/src/signaling_remote.rs` (era reset, overflow reconnect, pending bound, received counter, F46 sleep, 2 new unit tests)
- `crates/node-runtime/tests/remote_signaling_live.rs` (F44 skip-with-reason)
- `scripts/test.sh`, `.github/workflows/ci.yml` (F41 wiring)
- `docs/reports/m3-qa-audit.md` (the audit, committed herewith)
