# ADR-002: `webrtc-rs` behind the `Transport` trait, with a libwebrtc fallback seam

- Status: Accepted (M0, 2026-09-24); amended by the M2 transport spike (2026-09-24 — version pin, frame-id verdict, trait extension)
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

### Frame-id carriage (QA F4 decision, recorded here because it is a transport contract)

The perf-counter schema joins the host and controller halves of each frame by
`frame_id` (host-assigned at capture). Over the real transport the controller
cannot know that id from RTP alone, so the carriage mechanism is part of this
ADR:

- **Decision: RTP header extension.** The host stamps every RTP packet of a
  frame with a header extension carrying the 64-bit `frame_id`; the
  controller reads it and stamps its controller-side `FrameTiming` records.
  Header extensions are codec-agnostic and per-packet, which is exactly the
  needed granularity (SEI embedding is rejected — it couples diagnostics to
  codec particulars; a `control`-channel mapping is the documented fallback
  if the webrtc-rs header-extension API proves impractical at M2).
- **Open item for M2 (not pre-built):** confirm the webrtc-rs API for
  registering/negotiating the extension URI (`urn:rd:frame-id`) and expose it
  through the `Transport` trait as a per-frame marker — an additive trait
  change, reviewed with the first M2 transport patch. M1's in-process loop
  needs none of this (the handoff types carry `frame_id` directly).

## M2 spike amendments (2026-09-24)

### Version pin (decision 3 executed)

`crates/transport-webrtc` pins, exact:

| Crate | Version | Note |
|---|---|---|
| `webrtc` | **0.21.0** | thin async layer over the Sans-I/O `rtc` core; the rtc rearchitecture landed in 0.20.0 (2026-07-31) — the classic `RTCPeerConnection`/`webrtc::api` API is gone, replaced by `PeerConnectionBuilder` + the `PeerConnection`/`DataChannel` traits |
| `rtc` | **0.21.0** | direct dependency: RTP packet/extension types, `H264Payloader`/`H264Packet`, and the `Marshal` trait are not re-exported by `webrtc` |
| `tokio` | 1.53.1 | private runtime inside the crate (public trait stays runtime-agnostic) |
| `bytes` | 1.12.1 | |
| `async-trait` | 0.1.92 | required to implement `PeerConnectionEventHandler` |
| `openh264` | 0.9.8 (dev-dep) | spike-only software codec for the rig example |

**MSRV note:** `webrtc`/`rtc` declare no `rust-version`, but the `rtc` 0.21
source uses let-chains (stable Rust 1.88), so the dependency tree's
*effective* MSRV is 1.88 even though the workspace declares 1.85. The
installed toolchain (1.98.1) builds everything green; CI must use ≥ 1.88 for
this crate. No workspace MSRV change was forced by this spike.

### Frame-id carriage verdict (open item resolved)

**The webrtc-rs header-extension API is sufficient — no fallback needed.**
Send side: `TrackLocalStaticRTP::write_rtp_with_extensions(packet,
&[HeaderExtension::Custom { uri, .. }])` maps the URI onto the negotiated
extmap id per packet; negotiation comes from
`MediaEngine::register_header_extension`. Receive side: the parsed
`rtp::Packet` exposes `header.get_extension(id)`. Two caveats, both handled
in `crates/transport-webrtc/src/engine.rs`:

1. The receive-side extmap id could not be resolved from
   `RtpReceiver::get_parameters().header_extensions` (empty at
   post-signaling time in 0.21.0); the engine scans the negotiated SDP
   (`a=extmap:<id> urn:rd:frame-id`) instead.
2. `RTCIceCandidate::to_json()` returns placeholder mids (`""`), which the
   engine normalizes to `None` before raising
   `TransportEvent::IceCandidate`.

Spike evidence: 17,946 frames over 5 minutes with `frame_id` present on
every received frame, zero gaps, zero frames without the extension.

### Trait extension (additive, as pre-declared)

`Transport` gained `send_video`/`poll_video`/`stats`/`restart_ice` plus
`VideoFrame`/`ReceivedFrame`/`TransportStats`/`SelectedIcePair` types — all
with default implementations, so no existing implementor breaks. Rationale:
video is an RTP track, not messages (invariant 1), so it cannot ride
`send(Channel, _)`; the stats snapshot feeds `diagnostics::LinkSample`.
The M0 method set is unchanged.

### Spike API-risk register (for M2 full integration)

- **Rearchitected API surface (0.20+):** every webrtc-rs integration written
  against ≤ 0.17 needs a rewrite; churn risk stays Medium. Our exposure is
  confined to `crates/transport-webrtc/src/engine.rs` per decision 1.
- **`RTCStatsReport` id prefixes:** candidate entries carry
  `RTCLocalIceCandidate_<id>` while pair entries reference the bare `<id>`;
  matching must be by suffix (implemented + unit-tested).
- **Inbound `jitter` stat is implausible** in 0.21.0 (7–73 "s" on loopback);
  `jitter_ms` in `TransportStats` maps it verbatim — treat as unreliable
  until upstream clarifies units/semantics.
- **Channel-open order is not deterministic** even though SCTP ids are:
  correctness must rely on per-channel readiness + the all-four
  `ChannelsOpen` event, never on cross-channel open ordering.
- **`TokioRuntime::block_on` builds a fresh runtime per call** — never use
  it as a bridge; own a real `tokio::runtime::Runtime` and spawn onto it
  (what `WebrtcTransport::bridge` does, with a bounded wait).
- **`DataChannel::poll()` is the only receive path** (no callbacks), so
  channel reads live in spawned tasks; teardown relies on the `closing`
  flag + `Notify`, plus `shutdown_timeout` on drop.

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
