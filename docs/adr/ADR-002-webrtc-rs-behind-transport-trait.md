# ADR-002: `webrtc-rs` behind the `Transport` trait, with a libwebrtc fallback seam

- Status: Accepted (M0, 2026-09-24); amended by the M2 transport spike (2026-09-24 — version pin, frame-id verdict, trait extension); amended by the M6 GCC-ingest fix (2026-09-26 — `[patch]` fork of `rtc`)
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

## M6 fork amendment (2026-09-26): `[patch]` fork of `rtc` 0.21.0 — the F59 GCC-ingest fix

### Diagnosis (what swallowed the feedback)

The M5 matrix froze the GCC estimate at its initial value in every cell and
reported the receiver's RTCP RR projection (`remote-inbound-rtp`) as exact
zeros. Tracing a live loopback pair with probes through the stack found the
ingest broken in **three** places (two upstream defects, one integration
defect in our layer):

1. **Send-track encoding without a codec silently disables the sender-side
   interceptor bind** (our layer, `transport-webrtc/src/engine.rs`).
   `RTCPeerConnection::start_rtp_senders` binds local streams to the
   interceptor chain via `interceptor_local_streams_op`, which skips any
   track coding whose `codec` fuzzy-matches nothing against the negotiated
   codec list. `TrackLocalStaticRTP` built with an encoding that carries
   only the SSRC (our `compose_answer`, and arguably the least-surprising
   API use) leaves `codec` at `RTCRtpCodec::default()` — empty
   `mime_type` → `CodecMatch::None` → **no bind, silently**. Consequences:
   the TWCC sender never stamped transport-wide sequence numbers (so the
   receiver's TWCC recorder never armed and no congestion feedback was
   ever generated), and the congestion-control send history never tracked
   the outbound SSRC (so even feedback that arrived found nothing to
   acknowledge). rtc's own examples set `codec: video_codec.rtp_codec`
   explicitly; upstream did not treat the omission as an error.
   **Fix (our layer):** the encoding now carries the registered H.264
   codec (`registered_h264_codec()` in `engine.rs`).
2. **`rtc` 0.21.0 defines `process_read_rtcp_for_stats` but never calls
   it** (upstream dead code). Receiver Reports that arrive and traverse
   the chain never update the `remote-inbound-rtp` accumulator — fraction
   lost and RTT read as exact zeros however lossy the path is. The write
   leg (`process_write_rtcp_for_stats`) is wired; the read leg is not.
   **Fix (fork):** the read-leg ingest is called in
   `InterceptorHandler::handle_read` as RTCP enters the chain. It cannot
   live in `poll_read`: the chain's terminus (`NoopInterceptor`)
   deliberately ends the inbound RTCP path — only packets marked
   `DeliverToApplication` surface — so the application-ward poll never
   sees an RR.
3. **RR round-trip time hardcoded to `0.0`** (upstream): the RR ingest
   called `on_rtcp_rr_received(..., 0.0 /* "RTT calculation would require
   additional tracking" */)`. **Fix (fork):** RFC 3550 §6.4.1 LSR/DLSR
   correlation — the middle 32 bits + local send instant of each Sender
   Report are recorded on the write leg (a 4-deep ring per SSRC, because
   a report typically echoes the *previous* SR), and each RR block's
   `last_sender_report`/`delay` resolve to a real measurement. An
   uncorrelatable report passes 0.0, which the transport maps to `None`
   (a matched measurement is always strictly positive).

### Fork mechanics

- `fork/rtc/` is a copy of `rtc` 0.21.0 (unmodified package version) with
  exactly the two upstream fixes above, confined to
  `src/peer_connection/handler/interceptor.rs`.
- Pinned workspace-wide in the root `Cargo.toml`:
  `[patch.crates-io] rtc = { path = "fork/rtc" }`. The `webrtc` 0.21.0
  facade itself needs no fork — it re-exports `rtc` wholesale, so the
  patch reaches both.
- Upgrade policy (extends decision 3): a future `rtc`/`webrtc` bump must
  either include these fixes upstream (drop the patch) or rebase it; the
  F59 regression test (`congestion_estimate_and_remote_report_surface`
  in `crates/transport-webrtc/tests/loopback.rs`) is the tripwire — it
  asserts the estimate *moves* above its initial under flowing media and
  that RR loss/RTT are live, which a dead ingest cannot satisfy.

### Verified live (loopback, after the fix)

- GCC estimate moves under feedback-driven AIMD (initial 2 Mbps → 2.8–8
  Mbps on a clean path; delay-based and loss-based halves diverge),
  instead of holding the initial value with timer-only updates.
- `remote_rtt_ms` is a real LSR/DLSR measurement (≈0.5 ms loopback).
- `remote_loss_percent` tracks injected loss (5% netem → RR-reported
  1–10% per report interval) and clears when the loss is removed.

### Fidelity note discovered by the fix (rig semantics, not a defect)

The M5 report's §2 claim that "the GCC delay-gradient does see [shaped
delay] (TWCC records arrivals of shaped packets)" is **wrong**: the netem
shaper sits above the interceptor chain, so a shaped delay shifts the
sender-side departure stamp and the receiver-side arrival stamp equally
(the gradient cancels), and a pre-chain drop is never stamped with a
transport-wide sequence — it cannot be reported missing against a send
history that never recorded it. Application-layer `loss`/`rate_kbps`
profiles therefore move the *policy's* signals (`remote_loss_percent`
counts the RTP sequence holes the RR reports) but never the GCC estimate.
A real inter-path bottleneck still moves the estimate (wire-side queueing
delays arrivals relative to paced departures). Consequence for the M6
soak: the loss axis exercises the policy's severe/sustained-loss steps
live; the estimate axis runs its own AIMD dynamics rather than reacting
to the shaper. Documented in `crates/transport-webrtc/src/chaos.rs`.

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
