# services/signaling

Placeholder. The Vercel signaling service lands here in **Milestone 3**
(RD-009/RD-010, plan delta D5): register/heartbeat presence,
`connect_request` → accept/reject with a one-time session secret, the
SDP/ICE mailbox with trickle forwarding, `cancel`/`disconnect`, idempotency
by `message_id`, and TTL cleanup on Upstash Redis.

The wire contract it must implement lives in `crates/protocol/src/signaling.rs`
(stable snake_case JSON; the TS types are generated against it — delta D7).
Vercel is control plane only (AGENTS.md invariant 2): IDs, presence, SDP/ICE
envelopes — never frames, input, cursor payloads, or anything else.
