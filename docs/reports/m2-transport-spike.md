# M2 Transport Spike Report — webrtc-rs behind the `Transport` trait

- Work package: M2 parallel spike (PLAN.md §5; source plan RD-006/007/008, delta D2)
- Date: 2026-09-24
- Scope: `webrtc` 0.21.0 peer connection behind the `Transport` trait, manual
  file-based signaling (no STUN, no service), H.264 RTP video from a pure-Rust
  test pattern (software codec, spike-only), four data channels per
  `protocol::wire`, application-layer loss/reorder injection, stats into
  `diagnostics` records, two processes on loopback.
- Code: `crates/transport-webrtc` (lib + `examples/spike_rig.rs` + `tests/loopback.rs`)
- ADR: `docs/adr/ADR-002-webrtc-rs-behind-transport-trait.md` (amended: version
  pin, frame-id verdict, trait extension, API-risk register)

## How it was run

```bash
cargo build --release -p transport-webrtc --example spike_rig
# terminal 1
./target/release/examples/spike_rig.exe --role host      --dir <sig> --duration-secs 300 --fps 60 \
    --summary <out>/host-summary.json --metrics <out>/host-metrics.jsonl
# terminal 2
./target/release/examples/spike_rig.exe --role controller --dir <sig> --duration-secs 300 --fps 60 \
    --summary <out>/controller-summary.json --metrics <out>/controller-metrics.jsonl
```

Signaling = `protocol::signaling::SignalingEnvelope` JSON: `offer.json`,
`answer.json` (single-shot, atomic rename), `c2h.jsonl` / `h2c.jsonl`
(trickle candidates, idempotent by `message_id`). Defaults inject 10 % drop +
5 % reorder on `input-fast` and drop every 40th reliable message
(`--drop-reliable-nth`), seed 2026 (deterministic xorshift64*).

## What was proven (numbers)

### Connect

| Run | Controller (offer write → all channels open) | Host |
|---|---|---|
| smoke (25 s, debug, 30 fps) | 833 ms | 1169 ms |
| soak (300 s, release, 60 fps) | 882 ms | 2682 ms* |

\* the host's number starts at process start and includes waiting for the
offer file (the controller process was started ~2 s later by hand); the
controller figure is the honest end-to-end signaling+ICE+DTLS+SCTP time.
Both are far inside the < 5 s budget. Selected pair both runs:
`127.0.0.1:host ↔ 127.0.0.1:host`, nominated, **no relay** (invariant 4).

### Sustained video (5 minutes, release, 1280x720@60, openh264 software)

| Metric | Host | Controller |
|---|---|---|
| frames encoded/sent | 17,947 | — |
| frames received/decoded | — | 17,946 / 17,946 |
| achieved fps (avg over 301 s) | 59.53 | 59.40 |
| encode ticks skipped | 2 | — |
| decode errors | — | 0 |
| RTP packets sent/received | 115,336 | 115,023 |
| packets lost (RTCP) | — | 0 |
| send/recv bitrate | 3,485 kbps | 3,530 kbps |
| RTT (candidate pair) | 0.31 ms | 0.21 ms |
| frame_id gaps / frames without extension | — | **0 / 0** |
| frames with missing packets (mid-frame seq gap) | — | 0 |
| rx video-queue drops | — | 0 |

The one-frame difference (17,947 vs 17,946) is the final in-flight frame at
disconnect. Encode stage latency (host, from `FrameTiming` records):
p50 11.3 ms, p95 14.5 ms, p99 16.3 ms, max 21.2 ms (software 720p, release).
Controller-side `recv_ns`/`decode_done_ns` were stamped in the same loop pass
(delta 0) — splitting them is an M2-integration item, not a transport gap.

### Input channels under injected loss/reorder

Injected (controller, app layer, below `input-fast` send): 3,000
`MouseMove` (390 dropped = 13 %, 148 reordered = 4.9 %) and 100
reliable-path messages with every 40th dropped (gap injection).

Observed on the host input stub:

- 2,516 moves applied, **109 stale arrivals suppressed** (reorder artifacts
  older than the newest seen seq) — the unordered channel contract.
- Final tracked position = **exactly the newest sent position**
  (seq 3000 → (27464, 45464)): coalescing survives loss+reorder by design.
- Reliable sequence gaps → **16 `AllKeysUp(SequenceGap)`** events; held keys
  and buttons were empty at every check and at teardown.
- Clean disconnect (`Disconnect{User}` over control) → host emitted
  `AllKeysUp(Disconnect)`, closed in 31–81 µs; the peer observed the
  connection-state teardown.
- Duplicate-signaling probe (first candidate line re-delivered verbatim):
  no-op at both layers (signaling `message_id` dedupe + engine candidate
  dedupe). Integration-test-level duplicates also no-op.
- Malformed/empty remote candidates → typed `TransportError`, no panic
  (covered in `tests/loopback.rs::ice_failure_paths_and_disconnect_cleanup`).

### Channel-open ordering

Channel **ids** are deterministic (creation order → SCTP ids 0–3), but the
`ChannelOpened` **arrival order is not**: across runs the four open events
arrived in different permutations (e.g. `[control, input-fast, cursor,
input-reliable]`, then `[input-fast, control, input-reliable, cursor]`, and
in the soak `[cursor, control, input-fast, input-reliable]`). Correctness
relies on per-channel readiness + the single `ChannelsOpen` (all-four) event,
which is what the trait exposes. The rig records actual order per run.

### Queue/backpressure evidence (invariant 3)

- Bounded queues everywhere (map in `engine.rs` module docs); reliable
  overflow = typed error + counted drop (unit test); lossy overflow =
  newest-wins replacement, counted.
- In the debug-build smoke run the host's *event drain* was the bottleneck
  (encode blocking the single-threaded rig loop): `events_dropped` showed the
  overflow and the mouse position still converged — bounded, visible, and
  gone in release (`events_dropped_drain_queue: 0` over the full soak).
- Channel-queue gauges (`QueueKind::Channel*` `QueueSample` records at 1 Hz):
  input-fast high-water 29/32 during bursts, `replaced: 0` (no app-queue
  eviction needed; SCTP absorbed the bursts), all others 0/256.

## webrtc-rs 0.21.0 API risks discovered

Full register in the amended ADR-002; summary:

1. **The 0.20+ rtc rearchitecture is a clean break** from the classic API
   (`webrtc::api::API`, `RTCPeerConnection`, `RTCDataChannel` are gone;
   `PeerConnectionBuilder`, `PeerConnection`/`DataChannel` traits,
   event-handler trait, `poll()`-based receive). Anything written against
   ≤ 0.17 needs a rewrite. Our confinement to one crate held: the whole
   integration is `engine.rs`.
2. **`rtc` must be a direct dependency** (RTP types, H264 payloader,
   `Marshal` are not re-exported by `webrtc`).
3. **Stats entry ids carry type prefixes** (`RTCLocalIceCandidate_<id>`)
   while candidate-pair entries reference bare ids — suffix matching
   required (unit-tested `find_extmap_id`-style pitfall, fixed).
4. **Inbound `jitter` is implausible** in 0.21.0 (7–73 "seconds" on
   loopback). Mapped verbatim into `TransportStats::jitter_ms` and flagged;
   do not gate on it until upstream clarifies.
5. **`RtpReceiver::get_parameters().header_extensions` was empty**
   post-signaling — receive-side frame-id id resolution scans the negotiated
   SDP instead (see verdict below).
6. **`RTCIceCandidate::to_json()` fills placeholder mids** (`""`), which we
   normalize to `None` before signaling.
7. **`DataChannel::poll()` is the only receive path** (no `onmessage`
   callback): channel reads live in spawned tasks; teardown needs an explicit
   closing flag + `Notify` + `shutdown_timeout`.
8. **`TokioRuntime::block_on` builds a new runtime per call** — unusable as
   a sync bridge; we own one runtime and spawn with a bounded wait.

## Frame-id extension verdict (ADR-002 open item)

**Supported — the documented fallback (control-channel mapping) is not
needed.** Mechanism: `MediaEngine::register_header_extension(urn:rd:frame-id)`
negotiates the extmap; the host stamps every RTP packet via
`TrackLocalStaticRTP::write_rtp_with_extensions` +
`HeaderExtension::Custom` (8-byte big-endian `u64`, RFC 8285 one-byte
element form); the controller reads `packet.header.get_extension(id)` with
the id resolved from the SDP (risk 5 above). Evidence: 17,946 frames, zero
missing/absent ids over 5 minutes; the extension survives FU-A
fragmentation (id stamped per packet, verified in unit tests with golden
round-trips).

## M1 integration plan (swap the spike encoder/capture in)

1. `SpikeEncoder`/`TestPattern` live only in `examples/spike_rig.rs` —
   delete nothing, point the rig's encode loop at
   `codec_windows::VideoEncoder` once M1 lands (the call shapes already
   match: `encode(input, force_keyframe) -> packet{timestamp_ns,
   is_keyframe, bytes}`). `KeyframeRequest` → `force_intra_frame` /
   M1's keyframe path is already wired end-to-end over the control channel.
2. `VideoFrame { frame_id, timestamp_ns, is_keyframe, bytes }` is the
   transport-side handoff; M1's `EncodedPacket` already carries all four
   fields (frame_id flows from capture through the handoff — no codec
   change needed; the spike's own mirror type simply lacked it).
3. `send_video` packetizes Annex-B (RFC 6184) at MTU 1200 with 90 kHz
   timestamps from `timestamp_ns`; M1's decoder consumes
   `ReceivedFrame.bytes` (Annex-B) directly — the rig's openh264 decoder
   proved depacketized AUs are decodable as-is.
4. Split the controller's `recv_ns`/`decode_done_ns`/`present_ns` stamps
   across the real receive → decode → present stages (the rig stamps them in
   one loop pass).
5. `WebrtcTransport::stats()` → `LinkSample` mapping exists; the node
   runtime should sample it at 1 Hz and derive loss-triggered
   `KeyframeRequest`s (rig demonstrates the reaction path).

## Incompatibilities / contract-change requests

- None blocking. No changes were made to `protocol`, `session`,
  `capture-windows`, `codec-windows`, `render-windows`, `input-windows`, or
  `apps/`.
- Note for the integrator: `Cargo.lock` now includes the webrtc/rtc tree
  (added via `cargo build`, not by editing `[workspace.dependencies]`).
- Suggested (non-blocking) follow-ups owned by the main session:
  - treat channel-open *order* as unspecified in the M2 node runtime (per
    above);
  - the MSRV footnote: `rtc` 0.21 uses let-chains ⇒ effective dep-tree MSRV
    1.88 vs declared workspace 1.85 (toolchain 1.98.1 unaffected).

## Reproduction

- Unit + integration: `cargo test -p transport-webrtc` (18 lib + 5 loopback
  tests; loopback tests connect two in-process peers over real UDP
  loopback sockets).
- Gates: `cargo fmt --all -- --check`, `cargo clippy --all-targets -p
  transport-webrtc -- -D warnings`, `cargo test -p transport-webrtc` — all
  green at hand-off.
- Soak artifacts from this report's run (not committed): summaries and
  ~19.4k-line JSONL metric files under `%TEMP%\rd-soak`.
