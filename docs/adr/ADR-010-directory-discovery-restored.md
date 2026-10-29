# ADR-010: The discovery list restored — sealed circle directory alongside the trusted-host list

- Status: Accepted (0.11.0, 2026-10-29)
- Deciders: the user (owner), 2026-10-29 — "i want to keep the discovery
  list, just make sure we will not have duplicates, the approval request
  is only asked one time, and it works" — after installing 0.10.2 on two
  machines and finding the rail empty until codes are typed by hand.
- Amends: ADR-009 §Decision 4 (circle directory retired) — reversed;
  ADR-009 §Decision 6 (online status session-only) — partially relaxed
  (below). Every other ADR-009 decision stands unchanged: no accounts, no
  login, no favorites, machine display name as the only identity,
  `pairings.json` as the one trusted-host list, the one-field connect
  box, `host_sharing` default ON.

## Context

ADR-009 (four days earlier) deleted the discovery list on the theory
that the connection code + "Always allow" covers everything. Field use
immediately showed the cost: two fresh installs see **nothing** in the
rail; every machine relationship starts with reading a 16-hex code off
one screen and typing it into the other. The family relied on the
pre-0.10 behavior — machines simply appear.

The server surface never went away: `/api/directory` stayed deployed
untouched for 0.9.x clients, the golden fixtures and zod schemas stayed
in `services/signaling`, and the circle key file
(`~/.deepflux/circle-key.txt`) survived on the build machine. 0.11.0
therefore rejoins the **same circle** the 0.9.x clients used — no new
invite ceremony, no server deploy.

## Decision

Restore the discovery list as a **view**, not a trust path:

1. **Client restoration, contract-identical.** `protocol::directory`,
   `node-runtime::directory_remote`, the app poller/client, and the
   fixtures test are restored from `0474978^` (the ADR-009 deletion
   commit's parent). `DIRECTORY_PROTOCOL_VERSION` stays 1; the wire
   contract is pinned byte-for-byte by the golden fixtures against the
   deployed zod schemas. No server change.
2. **One row per machine, always.** The rail merges pairings + directory
   keyed by device code (`unifiedMachines`): a machine in both lists is
   one row (paired semantics win; a placeholder name that is just the
   bare code adopts the discovered name). The server keys entries by
   device id, and the Credential-Manager identity anchor keeps a
   machine's device id stable across reinstalls — so a reinstall cannot
   mint a second row either. Duplicate directory rows for one device
   collapse on merge.
3. **Approval is asked once — unchanged engine.** A discovered row's
   Control button is the ordinary connect-by-code path. The host's
   consent prompt appears; "Always allow" records the click-time
   remember-intent and the pairing proof (ADR-006 §3, v0.9.1 durability);
   every later connect auto-accepts silently (`auto_accept_if_paired`).
   Discovery introduces no new trust, no silent accepts, no wire change
   (`PAIRING_REMEMBER` semantics untouched).
4. **Presence honesty, partially relaxed.** Paired rows still show
   session-live presence first; when no session is running they upgrade
   to the directory's live signaling flag instead of "unknown".
   Discovered rows show directory presence. The pre-0.10 roster presence
   join stays dead.
5. **Simplifications kept (ADR-009 spirit):** no join/create/invite/
   leave UI — the family installer auto-joins from its embedded key (the
   installer is the invite; `build.rs` refuses a non-empty embedded key
   without `DEEPFLUX_FAMILY_BUILD=1`, and `build-family.sh` fails on a
   missing/empty key). No separate visibility toggle — the `host_sharing`
   setting (default ON) gates both launch host presence and the
   directory entry (OFF removes the entry; the machine still sees
   others). The connect box stays for out-of-circle machines. Agent
   tools stay trusted-list-only. `circle.json` survives loads again
   (removed from the ADR-009 cleanup list); `favorites.json`/
   `account.json`/`roster.json` are still purged.
6. **`/api/directory` deletion cancelled.** ADR-009 §5 planned to delete
   the endpoint after the 0.10.0 soak; with the client restored it is a
   live surface again and must not be deleted. The `/api/account`
   deletion plan stands — accounts stay retired.

## Consequences

- Fresh installs see each other automatically once each machine's engine
  registers (first directory refresh lands seconds after launch; the
  poller re-syncs every 30 s; entries TTL out after 30 days, refreshed
  every 6 h).
- The public installer embeds the circle key again — the standing
  single-installer decision (ADR-006 distribution addendum, reaffirmed
  2026-10-26: "never re-warn about the published family build"). Anyone
  holding the installer can read the directory (device ids + nicknames)
  and list/put/remove **their own** entry; the server still never sees
  nicknames (AES-256-GCM under the circle key) and control still rides
  the consent prompt + pairing proofs. Key rotation = delete the key
  file; old entries TTL out, pairings survive.
- Upgrades from 0.10.x: the 0.10.x loader deleted `circle.json`, so the
  first 0.11.0 launch re-mints it from the embedded key (fresh
  `joined_ms`); the Credential-Manager circle key survives where present,
  and the identity anchor keeps the device id — the machine re-appears
  as itself, not a new row.
- Test surface: the restored crates re-gain their original suites
  (protocol round-trips/redaction, seal/open + AAD binding, error
  parsing, golden fixtures) and the rail gains merge pins (dedup,
  placeholder-name adoption, presence upgrade, self-exclusion,
  duplicate-row collapse) in `agent-first.test.tsx`.
