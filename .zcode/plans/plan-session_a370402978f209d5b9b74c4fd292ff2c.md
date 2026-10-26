# Family Circle — shared machine directory & owner-approved trust (v0.5.0, ADR-006)

## Your requirements → what this delivers
1. **Install → machine auto-registered in one shared list, searchable in-app**: a "family circle". Family installer embeds the circle key (auto-join); public build joins by pasting an invite once. Each machine auto-registers a sealed entry {nickname} when it goes online; nickname defaults to the existing device display name.
2. **Entry = machine id + nickname** — machine id is the server-attested 16-hex connection code; nickname is self-chosen, 1–64 chars.
3. **Anyone in the circle can send a connection request** — one click from the machine list; rides the existing connect_request flow.
4. **Connection AND favorites only via owner approval** — host consent dialog gains "remember this machine": ON → pairing forms (silent reconnect allowed) and the controller auto-saves the machine to favorites; OFF → single session, no pairing, no favorite. Manual add-by-code escape hatch unchanged.

**Two defaults I chose when your questions timed out (both reversible):** scope is **circle-scoped** (not a public registry — strangers can't enumerate your machines); reachability is **always-ready** (circle machines go online at app launch; "launch at Windows login" default ON in the family build with close-to-tray; every untrusted session still prompts).

## Critical finding fixed first (from security review)
`auto_accept_if_paired` (chat.rs:441) grants silent full control on **device id alone**; ids are re-claimable ~3 min after a machine goes offline (tombstone window) → silent takeover today, and the directory would publish the ids. Fixed in this feature: `connect_request` gains additive optional `pairing_proof_hex` = HMAC-SHA256(pairing_secret, "pair-proof:v1|{controller}|{host}|{session_id}"). Valid proof → silent accept; claimed-trusted without proof → prompt with warning copy; unpaired → today's prompt. Legal within signaling v1 (additive optional field). Old hosts ignore it (transitional residual, documented).

## Design

### Circle & privacy
- circle_key = 32 random bytes; **circle_id = sha256("deepflux-circle:"+key)** — only the hash reaches Vercel. Invite = the key. Family build embeds it via new build env `DEEPFLUX_CIRCLE_KEY` (same build.rs mechanism as the agent key; build **fails** if set without an explicit family flag; never published). Public build: Settings → Create circle (shows copyable invite) / Join by invite.
- Entries sealed AES-256-GCM under circle_key, AAD `"dir-entry:v1:{circle_id}|{device_id}"`. Sealed plaintext `DirectoryEntryDoc {v:1, name, joined_ms}` — **no code inside**; the server-attested device id is the identity (kills cross-member spoofing). Vercel sees: circle_id, device ids (already visible via presence), ciphertext, server timestamps, online flags. Invariant 2 widened like ADR-003/005.
- Circle key stored in **Windows Credential Manager** (existing credstore seam); `circle.json` holds circle_id + flags only. New `CircleKey` type, redacted Debug.
- v1 limits (ADR-006): one circle per machine; no in-app rotation (operational rotation = new key/new installer; old namespace TTLs out in 30d; pairings survive — revoke via Trusted machines); no member eviction.

### New wire surface: `POST /api/directory` (owned by `crates/protocol/src/directory.rs`)
- `DIRECTORY_PROTOCOL_VERSION=1`; flat snake_case, action tag; 1 MiB cap; header-only bearer; `device` in body, authenticated as the (device, token) pair against presence exactly like /api/chat; account's full validation ladder (cap→JSON→token-placement→raw version gate→action→zod→auth→size→rate-limit).
- **put** {device, circle_id, ciphertext_hex, nonce_hex} → {refreshed_ms} — server-minted timestamps only. Storage: **single ZSET** `sg1:dir:{circle_id}` of JSON members, score = server ts, EX 30d (expire as part of the write); prune-on-write; cap 128 → 409 `circle_full` (existing-member refresh always allowed; no silent eviction).
- **list** {device, circle_id} → entries + `online` flags (server joins presence via new `Store.mget` — one Upstash pipeline; emulator case added; chat test-double stub fixed).
- **remove** {device, circle_id} — own entry, idempotent.
- Errors: malformed/unsupported_version/unknown_action 400, unauthorized 401, circle_full 409, entry_too_large/too_large 413, rate_limited 429+retry_after_s, store_unavailable 503, internal 500.
- Rate limits: put 10/min/device + 60/min/IP + 5 new-members/day/circle; list 60/min/device + 300/min/circle; remove 10/min/device. Config knobs mirror account (`SIGNALING_TTL_DIRECTORY_SECONDS` 30d, `SIGNALING_DIRECTORY_MAX_MEMBERS` 128, `SIGNALING_DIRECTORY_ENTRY_MAX_BYTES` 2048).
- TS layout mirrors chat/account: `lib/directory-{schema,service,server}.ts`, `api/directory.ts` (no listen()), bundle-api.mjs + vercel.json (`api/directory.js` key), `fixtures/directory/{request,response,reject}`, validate-wires.mjs section, unit + emulator contract tests, dev-server.mjs gains directory **and chat** (closing that gap), README/.env.example; verify the api/*.js gitignore claim.

### Trust model (completes ADR-005 §5, which specified this dialog but shipped auto-ack)
1. Pairing proof (above).
2. **Choice-gated pairing**: offered secret held in memory; `PairAck` + `record_pairing` fire only on consent-accept **with remember checked**; established pairings never silently overwritten (re-pair requires explicit removal); pending offers expire at session end (host) / 24h (controller).
3. `ConsentAccept` gains `remember: bool` (EngineCmd + Tauri command). `FeatureFlags::PAIRING_REMEMBER = 1<<5` (additive bit) lets 0.5 controllers label trust as deliberate vs legacy auto-ack.
4. **No WIRE_VERSION bump, no PairNack**: host silence = not remembered; controller treats un-acked pending as untrusted (correct UX — it *will* be prompted next time).
5. Prompt-flood defense: host auto-rejects repeat requests from an unpaired controller (60s after timeout, 5min after reject); signaling service gains fixed-window RL on the send path (60 envelopes/min/sender; 5 connect_request/min per sender+target).
6. Consent event enriched at emit (app layer): {requester_name (from directory cache), paired, pairing_proof_ok, ai_session}. paired+valid-proof → passive status card ("trusted machine connecting"), never a dialog; claimed-trusted-without-proof → warning dialog.
7. Anti-spoof: code always shown beside nickname ("Mom's PC · a41f…"); name pinned into pairings.json at pairing time. Fix the login roster write-back that wholesale-replaces favorites (merge-by-code instead — today it would wipe directory favorites).

### Desktop client
- `apps/desktop/src-tauri/src/directory.rs`: circle state, credstore key, seal/open, single-flight latest-wins poller (60s while Online; backoff on 401/429), auto-put on engine Online + on display-name change. Commands `circle_status/create/join/leave/set_shared`, `directory_list` — engine-off capable (account-command pattern). Event `app://directory` (app-layer, not engine://).
- `crates/node-runtime/src/directory_remote.rs` (ureq, mirrors account_remote: version gates both ways, typed errors, redacted logs); fixtures exported from a node-runtime test.
- `crates/protocol`: also folds `ChatEnvelope`/CHAT_PROTOCOL_VERSION in from apps/desktop — AGENTS.md's "three surfaces" is already stale; ADR-006 reconciles to five, all protocol-owned.
- **UI — one merged contact list** (not two sections): MachinesRail gains search (name+code, aria-labeled, count) over an extended `unifiedMachines` union favorites ∪ roster ∪ circle, name precedence roster > favorite > circle > code; trusted-shield badge with plain-language aria; subtle circle tag; a11y fix for nested interactive rows; offline rows stay connectable with honest copy + `unknown_target` error mapping.
- New `ConsentDialog.tsx` (replaces the inline App.tsx dialog + orphaned HostPanel copy + their tests): copy matrix {nickname+code} × {human/AI_SESSION} × {paired/proof}; remember default ON (human), OFF + blunt copy (AI_SESSION); hidden when paired.
- Settings: Circle section (status, create→invite, join, leave with two-step confirm, "Show this machine in the circle" toggle; first-run/join-time share ask = the consent moment) + **Trusted machines** (groups "Can connect without asking" / "You can chat with these" via new `Pairing.role` field; inline-confirm remove — finally wires the dormant pairings commands).
- Onboarding: `circleJoined` bypasses the account gate in the family build; first-run banner doubles as share consent; public build unchanged.
- Controller side: on PairAck auto-favorite (directory name, code placeholder); info line, no modal. Directory rows offer "Save" only once paired.
- Always-ready slice: engine + host auto-start at launch when circle-joined; tauri-plugin-autostart + tauri-plugin-single-instance + close-to-tray (new plugins = recorded sign-off). Largest client slice; can slip to 0.5.1 without contract impact.
- Collateral: verify + fix `chat.rs` inbox_drain missing `?device=` (out-of-session chat appears broken today).

## Slices (merge gate green after each; deployable in order)
0. **Docs**: ADR-006 (decisions + residuals: extractable embedded key, no rotation/eviction, host-id squatting, legacy plaintext secrets, old-host transitional auto-ack), AGENTS.md (surfaces + invariant-2 wording), PLAN.md activation record.
1. **protocol**: directory contract + fixtures + version tests; PAIRING_REMEMBER bit; pairing_proof_hex field + compatibility tests; ChatEnvelope fold-in.
2. **node-runtime**: directory_remote + fixture-export test; pure pairing-proof helper.
3. **Service**: Store.mget + emulator; endpoint + RL + fixtures + validate-wires + unit/contract tests + dev-server(+chat) + README; **deploy** (purely additive).
4. **Trust core**: ConsentAccept{remember}, memory-held offers, ack-on-choice, no-overwrite, expiries, proof verification, host cooldown, signal-path RL; engine + service tests (squatter without proof → prompt; with proof → silent).
5. **Desktop directory**: module + commands + poller + rail search/merge/badges + useDirectory + Settings circle UI + tests.
6. **Consent UI**: ConsentDialog + enriched payload + status card + copy matrix + auto-favorite + favorites `source` field + roster merge fix; agent `machines_list` includes circle.
7. **Trusted machines UI** (backend-free after 4).
8. **Always-ready**: autostart/tray/single-instance/auto-start + first-run banner + onboarding bypass.
9. **Family build + release 0.5.0**: build.rs key + guard + build script (agent + circle keys); full gates (fmt/clippy/test, tsc, component tests, fixture validation); service deployed first, then installer.

## Acceptance checks
- Family installer on a fresh VM: appears in the circle on another machine's rail within ~60s (nickname + online dot); search finds it; connect → owner sees "Mom's PC · a41f… asks to control" with remember checkbox; remember → favorited + silent reconnect; revoke in Settings → prompts return.
- Squatter with re-registered id, no proof → prompt, not silent accept.
- Offline machine → honest offline row + error copy; login no longer wipes directory favorites.
- All merge gates + emulator contract tests + golden fixtures green.

## Deferred (recorded in ADR-006)
In-app key rotation/member eviction; multi-circle; deep-link invites; offline request queuing; server-side search; DPAPI migration of legacy plaintext secrets; tombstone-based directory auth for engine-off refresh.