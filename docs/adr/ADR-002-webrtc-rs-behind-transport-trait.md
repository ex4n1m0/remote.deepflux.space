# ADR-002: `webrtc-rs` behind the `Transport` trait, with a libwebrtc fallback seam

- Status: Accepted (M0, 2026-09-24)
- Deciders: rd-architecture-owner
- Sources: source plan §Transport decision ("Recommended spike"), §Key decisions to freeze ("Fallback")

## Context

The direct peer transport is `webrtc-rs` (0.21.x as of September 2026):
async peer connections, tracks, data channels, ICE/STUN, RTP/RTCP,
DTLS/SRTP. It is **pre-1.0**; minor releases can break API, and the source
plan's two-week spike gate (1080p60 over LAN, input injection, network-change
recovery, useful stats on two Windows machines) may expose performance or
platform-integration gaps versus Google's native libwebrtc. The frozen
decision is: if the Rust WebRTC spike misses the gate, *preserve interfaces
and replace only `transport-webrtc` with a libwebrtc-backed implementation*.
TURN/relay is forbidden in MVP regardless of library (invariant 4).

## Decision

1. **All `webrtc-rs` types, config, and async plumbing are confined to
   `crates/transport-webrtc`.** The rest of the system sees only the `Transport`
   trait and `TransportEvent` enum defined there:
   compose/apply offer+answer, add remote candidates, `send(channel, bytes)`,
   `poll() -> Option<TransportEvent>`, `close()`. webrtc-rs types never leak
   past the crate boundary — not into `session`, not into signatures of other
   crates.
2. **The M0 trait is poll-based and runtime-agnostic.** M2's implementation
   may run tokio *inside* the crate (behind a drain queue that is bounded and
   newest-first per invariant 3), but the public surface stays callable from
   any executor and mockable in deterministic tests. A `MockTransport` for the
   session-level tests lives in the same crate (test feature) so both
   implementations are exercised against one contract.
3. **Version pinning:** an exact `webrtc-rs` version is pinned the moment M2
   adds the dependency; upgrades are deliberate patches with the M2 rig
   re-run, not floating.
4. **Channel policy is trait-level, not implementation-level:** `control`
   ordered/reliable, `input-fast` unordered with `maxRetransmits = 0`,
   `input-reliable` ordered/reliable, `cursor` latest-state. Any
   implementation must provide exactly these four `Channel`s with these
   semantics — this is what `session`/`input-windows` correctness assumes.
5. **No TURN servers configured, ever, in MVP; relayed candidate types are
   rejected.** Direct-connection failure (symmetric NAT, UDP blocked) is an
   explicit user-visible error, not a silent fallback (M5 owns the error UX).

### The libwebrtc fallback seam — single-crate swap mechanics

If the gate is missed:

1. Lift the `Transport` trait + `TransportEvent`/`Channel` definitions from
   `transport-webrtc` into a trait-only crate (e.g. `crates/transport`) in one
   mechanical commit: move items, re-export from `transport-webrtc` for
   compatibility. No behavioral change; the session machines and tests are
   untouched because they never named the implementation crate.
2. Create `crates/transport-libwebrtc` implementing the same trait over the
   native stack (bindings choice — likely prebuilt binaries — is its own
   decision record at that time).
3. Switch the node runtime's constructor from the webrtc-rs provider to the
   libwebrtc provider: one call site in the runtime binary, one workspace
   member entry, no changes to `session`, `protocol`, `input-windows`, or the
   UI.

The swap is "single-crate" in the sense that matters: *no protocol or
state-machine code changes*; the trait is the contract and step 1 exists only
so two implementations can coexist for A/B measurement during the spike
decision.

## Consequences

- Positive: the spike decision is reversible and measurable; transport
  statistics (ICE pair, RTT, loss) surface through the same trait either way.
- Positive: deterministic tests keep working against `MockTransport`
  regardless of implementation.
- Negative: a poll-based trait adds a small latency/complexity tax versus
  exposing async directly; accepted because it keeps `session` pure and the
  test harness deterministic. M2 may revisit with a `try_recv`-style API if
  profiling shows the drain tick hurting.
- Negative: two live WebRTC stacks (during any A/B window) double the Windows
  CI surface; time-boxed by only building the fallback when the gate is
  actually missed.
- Risk: webrtc-rs API churn between M2 and M5; mitigated by the version pin
  (decision 3) and the confinement rule (decision 1).
