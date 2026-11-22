# Device-seed theft model (ADR-013 gate (d))

Status: **recorded 2026-11-19 — P2's ownership story**, per the P1 app-side
security review of the swarm-enrollment work (`swarm.rs`).

## The asset

This installation's swarm identity is a 32-byte Ed25519 seed, generated
on first run and stored (hex) under the Windows Credential Manager
synthetic user `swarm-device-seed` (`SwarmIdentity::load_or_create`,
`apps/desktop/src-tauri/src/swarm.rs`). Everything else derives from it:

- `installation_id = base58(SHA-256(pubkey))` — the enrollment wire identity;
- the libp2p PeerId form (the future swarm-inference transport identity);
- every `Authorization: MSP1 …` signature — enrollment, heartbeat, and the
  P2 account proof on `connect_request`.

The seed **never rotates**. It deliberately survives reinstalls (the
`machine-identity` anchor precedent) — a machine that re-enrolls after a
reinstall is the SAME machine to the account.

## The threat

Seed theft (malware reading credstore, a copied disk image, a stolen
laptop) lets the attacker **sign as this installation indefinitely**:

- enroll (a fresh session is minted on `/auth/device/complete` — approval
  gates only NEW codes; the identity itself is already known to the
  tracker),
- heartbeat as this machine (keeps its dashboard row "online"),
- and, from P2 on, present the account proof: other machines in the
  account that remembered this installation's consent would silently
  accept its control sessions, exactly like the stolen pairing secrets of
  rd15's `pairings.json` model.

The 24 h session TTL is NOT a mitigation — the seed mints a new one at
will. **The dashboard-side revoke is the only kill switch**: revoking the
machine row (`/account` → Revoke) makes every tracker-authed call
(enroll-complete, heartbeat, directory) answer 404/401, which the app maps
to `NeedsRejoin`. Remembered consent on OTHER machines is keyed to the
installation id and dies with nobody's cooperation: a revoked installation
drops out of every account directory poll, so no controller ever offers it
a session again.

## The re-key path (owner recovery)

`swarm_rekey` (Config → Swarm → "Reset this machine's identity…"):
mint a FRESH seed (new installation id), drop the local session, and
return the machine to `NotJoined`. The consequences are the recovery:

- the stolen identity is dead **locally** immediately (heartbeats stop);
- the owner revokes its row on the dashboard — dead **server-side**;
- every trust the old identity carried is gone: account binding, the
  remembered account-consent rows on all other machines, any pairing
  history. Fresh enrollment (pairing code → claim confirm) rebuilds only
  what the owner re-grants.

Re-key is safe by construction because consent is keyed to the
installation id: there is no legacy-trust carryover to clean up.

## Non-goals / future work

- No automatic seed rotation (would break the survives-reinstalls identity
  invariant; the re-key ceremony is the honest cost).
- Seed encryption at rest beyond the OS credstore ACL is out of scope.
- P3+ relayed agent commands must E2E-authenticate to the peer device key
  (ADR-013 security posture) — the same theft model then applies to the
  relay path, with the same revoke answer.
