# M5 — WAN tuning & network matrix (RD-013)

Date: 2026-09-25 · Machine: the dev laptop (RTX 5080 laptop GPU, NVENC) ·
Harness: `m2_rig` two-process loopback (delta D2) driven by
`scripts/m5-matrix.sh`, evidence under `docs/reports/data/m5-matrix/`
(schema-exact JSONL per `docs/perf-counter-schema.md`, per-cell rig
summaries, `matrix-summary.json` from `scripts/m5-summarize.py`).

## 1. What landed (design)

### 1.1 STUN (deliverable 1)

`WebrtcTransportOptions` (`crates/transport-webrtc/src/engine.rs`) is the
M5 construction surface:

- `ice_servers: Vec<String>` — validated at the configuration layer to
  `stun:`/`stuns:` schemes only; TURN/TURNS URLs are a typed
  construction error naming invariant 4 (test
  `turn_ice_servers_are_rejected_at_configuration`). A relayed candidate
  that somehow still appears is surfaced as a transport failure (M2
  behavior, unchanged).
- `bind_all_interfaces` — WAN sockets (`0.0.0.0:0`) vs the pre-M5
  loopback-only sockets. srflx gathering requires it (a 127.0.0.1-bound
  socket cannot reach a public STUN server).
- `WebrtcTransportOptions::wan()` is the product configuration:
  `DEFAULT_STUN_SERVERS` = `stun.l.google.com:19302` +
  `stun1.l.google.com:19302` (two independent providers), all-interface
  sockets, sender-side congestion estimator on (host role only — the
  controller sends no media).

**Behavior on this machine (verified):**

- `stun_gathers_srflx_when_online` (internet-gated, run explicitly):
  **1 srflx + 1 host candidate gathered** from the Google STUN server in
  ~60 ms after the offer. 
- `wan_stun_configuration_loopback_still_connects`: with STUN configured
  and all-interface sockets, two loopback peers connect in **< 5 s**
  (budget) through **host↔host** candidates; the selected pair reported in
  stats is `host↔host`, never relay. Offline, srflx gathering fails
  silently and loopback connectivity is unchanged — STUN is strictly
  additive to host candidates on this machine.
- Candidate selection behavior documented from `m5-matrix` runs: the
  selected pair on loopback is always the private-address host pair;
  srflx candidates are gathered (WAN config) but never nominated — correct
  for a same-subnet peer, and the pair the WAN case would prefer once a
  NAT is crossed (real-WAN nomination is the user's M5 spot-check).
- The app shell builds every transport with the WAN options
  (`engine::ensure_transport`); `M4_E2E` (loopback, app-level) stays green
  with STUN configured — the app-level proof of "loopback still works
  with STUN".

### 1.2 Congestion adaptation (deliverable 2)

Two layers, deliberately split:

**Rate dynamics — the transport.** With `congestion: Some(CongestionOptions)`
the host transport registers `rtc` 0.21's send-side congestion control:
`configure_congestion_control` (GCC — delay-gradient **and** loss based —
over TWCC feedback) + pacer + TWCC sender, with the default interceptors
(NACK/RR/SR) layered on top. The estimate is published through atomics
(`ReportingGcc`, the rtc example's ReportingEstimator pattern adapted to
the poll-based trait) and surfaces as
`TransportStats::available_bandwidth_bps` plus `congestion_stats`
(delay/loss halves). Two rtc-integration findings, both fixed in our layer
and pinned by tests/evidence:

1. `configure_congestion_control`'s pacer starts at the library default
   **1 Mbps**, and the estimator only re-rates it when its target
   *changes* — on a healthy path (target constant) the wire rate is
   clamped to 1 Mbps forever. Measured: 974 kbps delivered against a
   3.6 Mbps encoder. Fix: we replace the pacer slot with
   `PacerBuilder::new().with_target_bitrate(initial)` (slots replace, not
   stack).
2. SDP negotiation is fine out of the box (probe: `a=extmap` for
   `draft-holmer-rmcat-transport-wide-cc` and `a=rtcp-fb:102 transport-cc`
   present in offer+answer) — no SDP work was needed.

**Policy — `node-runtime::congestion` (pure, clock-injected, 10 unit
tests, no live network needed).** Signals (all from `stats()` at the 1 Hz
tick): the GCC estimate (primary target, ×0.9 safety), receiver-reported
loss of the outbound stream (`remote-inbound-rtp` via RTCP RR — the
media-path loss signal), RR-implied RTT (trend guard), ICE-pair RTT
(fallback), achieved send bitrate (diagnostics). Reactions:

| Trigger | Reaction | Bound |
|---|---|---|
| loss ≥ 10% (severe) | ×0.5 step immediately | ≥500 ms between steps |
| loss ≥ 2% × 2 consecutive samples | ×0.75 step | same rate bound |
| estimate below current×0.9 | follow down (the pacer enforces the estimate; holding the encoder above it donates packets to the pacer's overflow queue — measured) | floored at 500 kbps |
| clean (loss <1% ×3 samples), RTT not trending (>2.5× baseline blocks), ≥3 s after any decrease, ≥1 s after the last increase | additive +max(300 kbps, 5%) | ceiling = estimate×0.9 (same factor as the down-follow: a 0.95 ceiling measurably flapped 3.6M↔3.8M) |
| bitrate < 2.5 Mbps / < 1.2 Mbps | fps cap 30 / 15 (pacer `retarget`, live) | recovery needs 1.2× the band + 5 s dwell |
| estimate < 800 kbps sustained 10 s | resolution step-down to 720p — **the only rebuild**, at most once per session (the priced action, F56) | once |

Anti-oscillation evidence: `alternating_conditions_do_not_oscillate_*
unboundedly` (severe-loss/fat-estimate alternation at 1 Hz for 60 s →
direction changes ≤ 10, observed 1 in the unit run; on the matrix the
loss cells show single-digit decisions with minutes-stable targets).

**Application:** bitrate steps go to the encoder LIVE via
`VideoEncoder::reconfigure` (`ICodecApi`; CR-1 — **no MFT rebuild**; the
matrix host summaries report `reconfig_live` with
`reconfig_rebuilt: 0`), fps caps via `FramePacer::retarget` (same timer
handle). The **`Auto` quality preset runs this controller** (M4's
"Auto==Balanced" note is retired — `engine::quality` + `drive_congestion`);
manual presets pin targets (Low/Balanced/High) and never instantiate it.
The app shell's `Auto` never rebuilds on preset change; the wire
`SetQuality{Auto}` no longer triggers the rebuild path either.

The controller-side KeyframeRequest-on-loss policy (M2) is unchanged and
integrated: gap/missing-packet detection → rate-limited (250 ms) IDR
request over `control`; the host forces the IDR on the next encode. The
matrix quantifies its pressure point (§3).

### 1.3 Reconnect after interface change (deliverable 3)

M2's rig path (ICE-restart probe → data-plane goodbye → hard teardown →
fresh transports → full re-signaling through the machines) is the same
path the M4 shell runs (`teardown_transport` / `peer_transport_gone` /
auto re-online in `engine::apply_flags` — verified identical: both go
through `Node::teardown_transport` and re-`ensure_transport`), so the
matrix's `iface` cell exercises the product path's machinery. The cell
runs the `full` scenario with congestion ON: teardown at 2/3 of the
stream, recovery timed in `sessions.connect_attempts_ms` (§3).

### 1.4 CR-2 (rider)

Landed: `input-windows::capture` (new module) — the subclass proc,
focus-loss `AllKeysUp`, bounded input queue, destination-rect mapping
(F48/F49 geometry tests moved with it) — behind the narrow
`PresenterInput` trait; the fullscreen window-style toggle moved to
`render-windows::PresenterWindow::toggle_borderless_fullscreen`.
`apps/desktop/src-tauri/src/engine/viewer.rs` composes both and contains
no unsafe; `AGENTS.md`'s sanctioned-list note is updated. Placement
rationale documented in the module docs: input events are
`input-windows`' charter (it already owns `protocol` wire input types);
window *style* is `render-windows`' (it owns the HWND).

## 2. Matrix fidelity (what the loopback netem does and does not model)

Shaping is at the application layer (`transport-webrtc::chaos`,
deterministic, seeded): per-RTP-packet loss, one-way delay, token-bucket
bandwidth (300 ms burst), blackhole — applied on the host's outgoing
video path; the controller→host input direction gets the RTT cell's other
half via a bounded `DelayQueue`. Documented limits (also in the chaos
module docs):

- Injected loss is **NACK-invisible** (drops happen above the interceptor
  chain, so the sender's NACK responder never buffered the packet):
  recovery exercises the app-level keyframe path — the harsher, and
  product-owned, of the two.
- **ICE/STUN consent traffic does not cross the shaper**: `rtt_ms` (ICE
  pair) stays ~0.2 ms in RTT cells; the added delay shows in the
  receiver-side percentiles (`recv_ns`-anchored) and the netem queue
  gauges, not in `rtt_ms`. The GCC delay-gradient *does* see it (TWCC
  records arrivals of shaped packets).
- UDP-blocked at *connect time* is emulated by pointing both sides'
  candidates at the discard port (`--blackhole-candidates` rewrites the
  port before the ICE agent sees it) — a socket-level block needs a WFP
  filter, out of MVP scope. Signaling still works, which is exactly the
  "signaling ok → ICE dead" stage the failure UX documents.

## 3. Matrix results

All cells ≥60 s sustained stream (bwstep 84 s), congestion ON, 1080p60
Auto start (6 Mbps), NVENC. Full distributions in
`docs/reports/data/m5-matrix/matrix-summary.json`; raw JSONL alongside
(same directory). Input-to-visible is the F8 **proxy** (host
capture→send + measured transport RTT + controller recv→present; never a
cross-domain timestamp subtraction).

| Cell | Presented frames | fps (presented) | Send kbps (p50) | Recv kbps (p50) | Loss % (meas.) | i2v proxy p50 (ms) | KF reqs | Live reconfigs | Queue HW (cap→enc / enc→send / recv→dec / dec→pres) |
|---|---|---|---|---|---|---|---|---|---|
| baseline | 3287 | 51.3 | 2319 | 2318 | 0.00 | 8.1 | 126 | 1 | 1 / 1 / ≤4 / 1 |
| loss 1% | 2240 | 35.0 | 2028 | 2029 | 0.94 | 4.5 | 200 | 1 | 1 / 1 / ≤4 / 1 |
| loss 3% | 1139 | 17.8 | 1894 | 1885 | 2.74 | 9.1 | 268 | 1 | 1 / 1 / ≤2 / 1 |
| loss 5% | 724 | 11.3 | 1857 | 1850 | 5.04 | 9.2 | 315 | 1 | 1 / 1 / ≤4 / 1 |
| loss 10% | 313 | 4.9 | 1736 | 1731 | 10.15 | 8.6 | 470 | 1 | 1 / 1 / ≤3 / 1 |
| rtt +50 ms | 3015 | 47.1 | 2299 | 2281 | 0.00 | 8.3 | 130 | 1 | 1 / 1 / ≤4 / 1 |
| rtt +150 ms | 2660 | 41.5 | 2362 | 2350 | 0.00 | 8.7 | 130 | 1 | 1 / 1 / ≤4 / 1 |
| rtt +250 ms | 2267 | 35.4 | 2356 | 2347 | 0.00 | 8.4 | 131 | 1 | 1 / 1 / ≤4 / 1 |
| bw 20→10→5→2 | 3879 | 46.1 | 2207 | 2211 | 0.00 | 5.7 | 168 | 1 | 1 / 1 / ≤4 / 1 |
| worst (10%+250ms+2M) | 262 | 4.1 | 1732 | 1728 | 10.28 | 8.9 | 464 | 1 | 1 / 1 / ≤4 / 1 |
| iface change | 5487 | 51.4 | 2255 | 2245 | 0.00 | 8.6 | 212 | 1 | 1 / 1 / ≤4 / 1 |
| udp-blocked | 0 | 0 (never connected) | — | — | — | — | 0 | 0 | — |

Every streaming cell: ≥60 s sustained (bwstep 84 s), 1080p, NVENC,
congestion ON. **Queue budget held everywhere**: `capture_to_encode` and
`encode_to_send` high-water = 1 (budget: ≤1 steady state) in every cell
including 10% loss and the 2 Mbps collapse — no unbounded growth
(invariant 3; per-queue counters in `matrix-summary.json`). The
input-to-visible **proxy** (host capture→send + measured transport RTT +
controller recv→present) excludes the shaped delay by construction — both
netem halves sit *between* the measured spans and the proxy's RTT term is
the (unshaped) ICE RTT. For the shaped cells, add the cell's RTT to the
proxy: rtt250 ≈ 8.4 + 250 ≈ **258 ms**, worst ≈ 8.9 + 250 ≈ **259 ms** —
against the ≤150 ms WAN budget *for networks that actually have that RTT*,
i.e. the pipeline overhead above the physics is the single-digit proxy
number.

Recovery (iface cell): **iface cell** (teardown at 42.7 s of the stream, then full re-signaling
through the machines): initial connect **1199 ms**; re-establish after the
interface change **1172 ms** — both far inside the 5 s warm-connect
budget. The controller observed the peer-down through the data-plane
goodbye (no consent-timeout wait), both machines ended `Disconnected`, and
the second session streamed to the scenario's end (5487 frames presented
across the two sessions).

Congestion-controller behavior across cells: One live bitrate reconfiguration per cell (6 Mbps start → **3.6 Mbps**,
`reconfig_live: 1`, `reconfig_rebuilt: 0`, `reconfig_errors: 0` in every
cell) and then **stability** — zero oscillation across 60+ s in all 11
streaming cells (the target sits at estimate×0.9 = 3.6 Mbps and never
flaps). The fps-cap and resolution-step-down paths did not trigger in the
matrix (the target never fell below their thresholds — see the GCC finding
below); they are unit-tested (`congestion.rs`, `pacing.rs`) and the pacer
retarget path is exercised by
`retarget_changes_the_rate_without_recreating_the_pacer`.

### Observations (analysis)

1. **The GCC feedback loop is inert in this composition (top finding).**
   In every cell the estimate stayed at its 4 Mbps initial and
   `remote-inbound-rtp` reported loss/RTT as exact zeros — the receiver's
   RTCP (RR + TWCC) never reached the sender's estimator through the
   `webrtc` 0.21 async facade. Verified not-the-causes: SDP negotiation is
   correct (probe: `a=extmap` transport-cc + `a=rtcp-fb: transport-cc /
   nack / pli` in offer and answer), and the send-path interceptor chain
   is demonstrably active (the pacer clamped an early smoke run to its
   1 Mbps builder default until we set the initial rate — §1.2 finding 1).
   Consequence in the matrix: the estimate acts as a fixed 3.6 Mbps
   target; behavior under it is stable and bounded, but estimate-driven
   adaptation (collapse → down-steps, recovery → probing) is NOT evidenced
   live. The policy layer around it (steps, hysteresis, live reconfigure,
   fps/resolution tiers) is fully unit-tested; the missing link is
   feedback ingest in the facade — the rtc sans-io example composes the
   same estimator successfully, so the fix is either an upstream issue
   against webrtc-rs 0.21 or composing the rtc core directly at our seam
   (ADR-002's libwebrtc-fallback logic applies). This is the first M6
   item, ahead of any tuning.

2. **Loss axis: presentation degrades steeper than the loss itself**
   (51→35→18→11→5 fps at 0/1/3/5/10%). Mechanism (from run-1 evidence,
   kept in `m5-matrix-run1/`): injected loss is NACK-invisible (§2), so
   every damaged frame is a full frame loss; the receiver's decoder reset
   + IDR gate then drops the *subsequent* clean P-frames until the next
   IDR arrives, and the 250 ms-limited keyframe requests cap IDR arrival
   at ~4/s — at 10% loss even IDR-sized frames rarely complete. The
   controller kept requesting (470 requests in 64 s) and the host kept
   forcing (no cap misses) — the policy integrates correctly; the
   *amount* of loss the app-level recovery path can paper over is roughly
   ≤3%. M6: PLI pacing per stream state, FEC, or making the injection
   NACK-visible to measure retransmission recovery.

3. **RTT axis**: 47/41/35 fps at +50/150/250 ms — the GCC pacer's 100 ms
   burst cadence (library default) delivers ~6-frame bursts; the receive
   path now absorbs them (`recv_to_decode` cap 2→8 after run-1 showed the
   cap-2 newest-wins queue dropping one frame per burst and the IDR gate
   amplifying each drop ~10×: rtt150 run-1 = 2102 presented vs run-3 =
   2660). Residual fps decay is burst/decode cadence, not queue overflow
   (high-water ≤4 against cap 8).

4. **Bandwidth step-down**: with the shaper's buffer sized to a real
   shallow bottleneck (300 packets — run-1's 1024-packet buffer buffered
   away the entire 20 s phase: pure bufferbloat, receiver saw 3.0 Mbps
   straight through the 2 Mbps phase), the delivered rate rides the cap
   (~2.2 Mbps against 2.0 Mbps — the 300 ms burst allowance) with zero
   queue-budget violations on either side of the transport.

5. **Static-desktop pitfall (process note)**: run 2's numbers were
   invalidated by `--no-stimulus` on a quiet desktop — DXGI emits frames
   only for dirty regions, so "fps" measured screen activity, not the
   pipeline. The final run uses the rig's animated stimulus window; keep
   `--stimulus` for any future matrix re-runs.

## 4. Expected direct-only failures & the error UX (deliverable 5)

Direct-only (invariant 4: no TURN/relay) has two hard failure classes.
Both are *expected* and must produce a typed, UI-visible cause — never a
hang.

### 4.1 Symmetric NAT (both peers behind address-and-port-dependent NAT)

Each peer's STUN binding is only reachable from the STUN server it
created it with; peer-to-peer checks from a different external endpoint
fail, so ICE never finds a working pair and no relay exists to fall back
to. Sequence the user sees on this machine's harness (from the
`udpblocked` cell, which produces the same ICE outcome):

1. **Signaling OK**: presence/connect/accept all succeed against Vercel
   (control plane is unaffected) — the UI shows the connecting state.
2. **ICE fails silently while trying**: consent checks die; nothing
   surfaces until a timeout.
3. **Typed failure, bounded**: the controller machine's
   `ConnectTimeout` (10 s, `SessionConfig::default`) fires →
   `Disconnected{Timeout}` → UI event `Error{code: "timeout"}` with copy
   *"The session timed out before the direct connection opened."* and the
   hint `DIRECT_ONLY_HINT` ("This build supports direct connections only
   (no relay). …"). The rig's `udpblocked` cell demonstrates the bound:
   the controller exits through this exact cause inside the connect
   window (summary `failed: true`, failures `["connect timeout"]`), the
   host-side rig observes the signaling-level disconnect — no hang, no
   unbounded wait.

### 4.2 UDP blocked (firewall drops all UDP toward the peer)

Identical ICE outcome to 4.1 (checks never land) — covered by the same
cell and the same copy. The mid-stream variant (UDP path dies during a
session) is detected by ICE consent timeouts: rtc-ice defaults are
5 s disconnected → 25 s failed; the peer connection state change maps to
`TransportEvent::ConnectionStateChanged(Failed)` → machines'
`TransportFailed` → `Disconnected{TransportError}` → UI
`Error{code: "transport_error"}` *"The direct connection failed or
dropped."* + the same hint. The M2 rig's network-change scenario already
exercises the teardown half; the matrix's `netem_blackhole_then_recovery`
transport test pins the recovery half (frames flow again after the
blackhole lifts).

### 4.3 Cause-code reach to the UI (verification)

`session_ended(cause)` → `disconnect_copy(cause)` (`engine/mod.rs`)
produces the codes above; `EngineEvent::Error` carries them over the
bounded event channel to the React layer (`state/mapping.ts` renders
them). The **`udpblocked` cell verifies the stage sequence end-to-end at
the rig level** (signaling ok → connect timeout → typed cause in the
committed summary). Gap noted for the app-level: `M4_E2E` does not
currently script a connect-failure case (it connects successfully); the
cause-to-UI path for `timeout` is covered by app unit tests of
`disconnect_copy` and by the rig evidence — an M6 E2E addition (scripted
unreachable peer) is recommended, not a blocker.

## 5. Reproduction

```bash
# full matrix (~15 min): writes docs/reports/data/m5-matrix/
scripts/m5-matrix.sh            # add --quick for 16 s smoke cells
scripts/m5-summarize.py         # -> matrix-summary.json

# transport-layer M5 tests (STUN/netem/GCC estimate, ~6 s)
cargo test -p transport-webrtc
cargo test -p transport-webrtc --test loopback -- --ignored --nocapture  # srflx (online)

# congestion policy, no network
cargo test -p node-runtime --lib congestion

# app-level E2E with the WAN (STUN) transport config
M4_E2E=1 cargo test -p remote-desktop-app --test e2e -- --nocapture
```

## 6. M6 risks / soak recommendations

- **GCC feedback ingest** (§3 item 1): the estimate-driven half of the
  controller is unexercised live until RTCP/TWCC reaches the estimator.
  Reproduce: `cargo test -p transport-webrtc --test loopback
  congestion_estimate -- --nocapture` (updates counter climbs from timers
  only; `delay_based`/`loss_based` frozen at initial; `remote_rtt_ms`
  placeholder 0.0). Fix paths: upstream webrtc-rs issue, or direct
  rtc-core composition behind the same `Transport` seam.
- **Preset hammer** (audit F56 recommendation, unchanged): 100 preset
  cycles under the M6 soak. `Auto` no longer rebuilds (live reconfigure),
  so the hammer should also drive manual-preset cycling (Low/Balanced/
  High still rebuild once per change) plus `Auto`↔manual switching through
  the app engine — the one-rebuild-per-switch path is bounded by user
  action but must be proven leak-flat over a hammer, not assumed.
- **IDR amplification under loss >3%** (§3 item 2): the keyframe-request
  rate limit (250 ms) + full-IDR recovery is the app-level ceiling; M6
  should measure FEC or a smarter PLI policy against the 5/10% cells.
- **Pacer burst cadence**: 100 ms bursts cost ~15% of frame rate at
  +250 ms RTT; revisit `PacerBuilder::with_burst_bits` once feedback flows
  (the right burst size depends on a working estimator).
- **E2E gap**: add a scripted connect-failure case to `M4_E2E`
  (unreachable peer → assert the `timeout` cause event reaches the
  shell), closing the app-level leg of §4.3.
- **Matrix fidelity**: NACK-invisible loss and unshaped ICE RTT (§2) both
  make the matrix *harsher*, not flattering; real-WAN spot checks (the
  user checkpoint) remain the ground truth for srflx nomination and true
  RTT behavior.
