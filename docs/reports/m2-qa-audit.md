# M2 Performance-QA Audit — Direct transport + node runtime + input adapter

- Verdict: **PASS-WITH-FINDINGS**
- Milestone: M2 (RD-006, RD-007, RD-008), gate per PLAN.md §4 M2 (rig incl. loss/reorder/duplicate-signal tests; real-LAN is the user checkpoint after this audit, delta D2); quality bar §7
- Audited commit: `b6491a9` (input adapter `dc723c0`, spike `b594f35`), clean working tree, tag `m1-local-loop` present
- Auditor: `rd-performance-qa` (read-only except this report; audit run artifacts under `C:\temp\rd-m2-qa-out\`, not committed)
- Date: 2026-09-25
- Scope: gate reproduction incl. one live rig scenario; independent recompute of the committed `m2-rig-*` evidence; world-parity review (documented deviations + undocumented-drift hunt); input-safety audit; invariant audit (3/4/6/7, unsafe confinement); M3 risk evaluation. Findings numbered from F26 (M1 audit ended at F25).

## 1. Gate reproduction (run by auditor)

Same machine as the gate run (Windows 11 10.0.26200, RTX 5080 Laptop GPU, `\\.\DISPLAY5`
3840x2160 primary). Warm target dir.

| Step | Command | Result |
|---|---|---|
| Format | `cargo fmt --all -- --check` | green |
| Clippy | `scripts/check.sh` | green, 0 warnings |
| Tests | `scripts/test.sh` | green: **140 passed, 0 failed, 9 ignored** workspace-wide; `cargo test -p node-runtime` = **34** (19 lib + 14 world-parity + 1 webrtc-drive), `-p transport-webrtc` = **23** — both exactly as claimed in `m2-rig.md` |
| Ignored live tests | `cargo test --workspace -- --ignored` | **8/8 pass** on the real display/GPU: 6 MF integration (incl. `software_encoder_decoder_round_trip`, `hardware_encoder_scales_on_rebind`), capture duplication, and `sendinput::tests::real_sendinput_harmless_events_succeed_and_track` |
| Own rig scenario | `full`, `--stream-secs 12`, 400 scripted moves, fresh signaling dir, two processes | **PASS** both exit 0: connect **1156 ms**, network-change teardown observed by host in 3 ms, re-established as a new session in **1141 ms**, clean disconnect; input converged **exactly** (sent `(12400,14800)` = host final position), `held_at_end 0`, `device_lost 0` both sides, `illegal_transitions 0`, no relay (pair `127.0.0.1:host ↔ 127.0.0.1:host`, nominated); pacer tick rate **59.95 Hz** (F20 fix confirmed); 55.4 fps encoded / 51.0 presented — same source-limited profile as the report |

Reproduction (my run):

```bash
cargo build --release -p node-runtime --example m2_rig
SIG=$(mktemp -d); mkdir -p /c/temp/rd-m2-qa-out
./target/release/examples/m2_rig.exe --role host --dir "$(cygpath -w $SIG)" \
    --metrics-dir 'C:\temp\rd-m2-qa-out' --summary 'C:\temp\rd-m2-qa-out\host.json' --idle-timeout-secs 60 &
sleep 2
./target/release/examples/m2_rig.exe --role controller --dir "$(cygpath -w $SIG)" --scenario full \
    --stream-secs 12 --metrics-dir 'C:\temp\rd-m2-qa-out' --summary 'C:\temp\rd-m2-qa-out\controller.json' --mouse-moves 400
```

Schema conformance of my run's JSONL (checked against `docs/perf-counter-schema.md`):
0 malformed lines; all fields snake_case; kinds `frame_timing`/`queue_sample`/
`resource_sample`/`link_sample` only; `LinkSample` cadence exactly 1.00 s (one
1.87 s gap during network-change teardown); **session scoping correct across the
reconnect** — pre-session records carry the `rig-*-pre-session` placeholder, the
two sessions' frames never alias (`rig-controller-ctrl-2` / `-ctrl-6`, F7's
stated purpose demonstrated); frame queues sampled on every depth change
(soak: 68,203 `capture_to_encode` samples = 34,630 pushes + 33,573 pops, 1.97
per frame); absent stages `null`, never 0.

## 2. Evidence verification (independent recompute from committed JSONL)

Nearest-rank percentiles, warm-up 60 s excluded by the same rule
(`latency_summary.py` semantics reimplemented independently).

**Soak (`m2-rig-20260924-{host,controller}-25.jsonl.gz`) — reproduces exactly.**

| stage | report p50/p95/p99/max (ms) | recompute (ms) | n |
|---|---|---|---|
| capture→encode submit | 0.11 / 3.45 / 4.20 / 5.87 | 0.110 / 3.450 / 4.202 / 5.870 | 30,380 |
| encode submit→done | 3.82 / 13.28 / 22.76 / 32.42 | 3.824 / 13.284 / 22.761 / 32.419 | 30,380 |
| encode done→send | 1.84 / 3.43 / 3.72 / 9.80 | 1.837 / 3.425 / 3.719 / 9.800 | 30,380 |
| host half | 6.19 / 16.01 / 24.88 / 35.51 | 6.191 / 16.008 / 24.875 / 35.505 | 30,380 |
| recv→decode | 0.29 / 0.39 / 0.44 / 1.18 | 0.292 / 0.392 / 0.443 / 1.175 | 27,509 |
| decode→present | 0.07 / 0.10 / 0.13 / 4.51 | 0.068 / 0.102 / 0.131 / 4.508 | 27,509 |
| controller half | 0.36 / 0.48 / 0.53 / 4.87 | 0.364 / 0.477 / 0.534 / 4.874 | 27,509 |

Frame/drop accounting — exact: host 33,544 `FrameTiming` records = 33,573
encoded − 28 `encode_to_send` replaced − 1 in flight; `capture_to_encode`
pushes 34,630 / pops 33,573 / replaced 1,056 (report: 34,630 / 33,573 / 1,056);
controller 30,252 presented = `decode_to_present` drained (report: 30,252).
Queues: high-water 1/1/2/1, `dropped` 1 (recv_to_decode), `replaced` 1,056 + 28
— matches "high-water ≤ 2, counted drops only". Memory (2-min bucket averages)
host 112.4 → 116.3 → 117.0 → 117.2 → 117.2 → 117.2 MiB, controller 90.2 → 92.5
→ 92.4 → 92.9 → 92.8 → 92.7 MiB — flat from minute 2, exactly as claimed (the
M1 F13 re-soak obligation is thereby met for the single-session case). CPU
7.8–76.6 % / 4.7–57.8 % of one core — matches.

**Cycles (`-24`) — 10 sessions confirmed, but see F26 (memory) and F29
(retention).** 10 distinct session ids, 1,036–1,136 host frames per cycle
(11,118 total). The claimed connect-time spread (1134–1152 ms) and
`device_lost = 0` live only in uncommitted run summaries (the committed
`m2-rig-cycles-*-summary.json` are latency summaries without those fields).

**Final-full (`-26`) — connect numbers differ from the report text.** The
committed log and run summary show connect **1136 ms** and re-establish
**1138 ms**; the report's headline 1145/1143/1148 ms are from the 60 s runs
whose artifacts are not committed. Same order, all far inside the 5 s budget
(my own run: 1156/1141). See F29.

**Input-to-visible proxy — math verified, caveat respected.** host half + RTT +
controller half, halves never subtracted across clock domains, and the report
labels it a proxy with the F8 caveat (excludes controller input→send and host
inject→capture). Recompute: p50 6.19+0.18+0.36 = 6.7 ≈ 6.8 ✓; p99
24.88+0.2+0.53 = 25.6 ✓; p95 recomputes to 16.7 vs the report's 16.5 — the
0.2 ms gap is the u32-RTT truncation (F30): with the truncated `rtt_ms: 0` the
sum is 16.485. Input convergence for the 60 s runs (3,000 sent → 2,516 applied
+ 113 stale; final position exact) is consistent with my 400-move run
(329 applied + 28 stale, exact convergence) and with the committed final-full
summary (803 + 84, exact). Reliable-seq gaps under the rig's chaos are a mix
of true nth-drops and app-layer reorders of reliable messages — both correctly
answered by `AllKeysUp(SequenceGap)` (conservative by design).

## 3. World-parity review

The two documented deviations are **benign mappings, not semantic drift**:

1. **Role-complementary ICE routing**: in the real offer/answer split, the
   host machine owns the host device's transport; candidates gathered by the
   peer's host transport must reach this node's *controller* machine
   (`ForwardIce` → its own transport). The node implements exactly that, and
   `world_parity::ice_candidates_route_to_the_peer_transport_owner` plus
   `webrtc_drive.rs` (real transports, real candidate flow, both directions,
   connect < 5 s asserted) prove the routing the real system uses. The
   deviation is real but the *deterministic harness* never proves it:
   `World::route`'s `IceCandidate` arm is dead code in every scripted scenario
   and encodes the *opposite* (role-preserving) routing — F34.
2. **`Registered` self-ack / heartbeat cadence**: the file adapter is the
   service stand-in; ack on next pump ≈ World's t+50 ms injection. Heartbeat
   cadence is runtime-owned and raised only in heartbeat-legal states — no
   drift (the World has no heartbeat semantics to drift from; the parity test
   pins the runtime's own behavior). One seam hazard: the ack is queued
   *before* the adapter write result is known (F27) — harmless with the M2
   adapters (service-directed sends always succeed), wrong for an M3 network
   client that can fail a Register write.
3. **Compose/apply failure mapping** (documented in the report and in code
   comments, but undercounted in `node.rs`'s "Two documented deviations"
   module docs — F36): `compose_answer` failure → `TransportFailed` (legal in
   `Exchanging`); `compose_offer`/`apply_answer` failures in `Offering` leave
   recovery to the connect timer — the machines' own design, faithfully
   mapped.

Undocumented-drift hunt — **no semantic drift found**: duplicate `message_id`
delivery no-ops through the machines' dedupe (file adapter deliberately
at-least-once; pinned by `world_parity::duplicate_envelope_delivery_is_a_no_op`
and the rig's verbatim-line dup probe); the node-level collision rule covers
both halves in the same states as the World (`Requesting`/`Offering`/
`Connecting` vs `ConsentPrompted`/`Exchanging`/`Connecting`/`Connected`);
timer order `(fire_at, seq)` with exact cancel; teardown paths
(`Stop`, `Disconnect`, `TransportFailed`, cancel, timeouts, late traffic in
`Disconnected`) all match; `Cancel`/`Disconnect` reason mappings match the
World's discriminant reuse. Defensive-only differences (counted, not fatal, vs
the World's test-only `unreachable!`/panic): inbound `Register`/`Heartbeat`
counted as illegal, machine/timer pairing mismatch, late `ChannelsOpen`,
illegal user-level transitions. These are correct hardening, worth one doc
line (F36).

## 4. Input-safety audit (`input-windows` + `InputPump`)

- **Gap ordering — correct.** `InputPump::gap_check` fires
  `release_all(SequenceGap)` *before* the post-gap event is applied
  (`crates/node-runtime/src/input.rs:116-131`); unit test
  `reliable_gap_releases_held_keys_before_applying` pins it.
- **Stale suppression — correct** on both channels (`seq > watermark` only).
- **Disconnect teardown — correct and double-covered**: `session_ended` and
  `control_disconnect` both run `all_keys_up(Disconnect)`; the rig asserts
  `held_at_end == 0` and fails the run otherwise; `reset_for_new_session`
  clears watermarks so a fresh controller's seq 1 is not a gap.
- **UIPI classification — correct**: short count + `ERROR_ACCESS_DENIED` →
  `BlockedByUipi`, other short counts → typed `Injection` with counts;
  `GetLastError` read immediately after `SendInput`. Documented MVP limit
  (operational mitigation, never silent retry).
- **No key identities anywhere**: `TrackedKey` has no `Debug`;
  `ReleasedInput`/`ReleaseOutcome` carry counts only; `InputEvent`'s Debug is
  redacted (F3, pinned end-to-end through `TransportEvent`); `InputError`
  variants are payload-free.
- **Failure-biased tracking — correct under every sequence I could construct**:
  press fails → stays tracked (spurious later release harmless); release fails
  → stays tracked (retryable); duplicate press / release-of-unheld dropped;
  `Text` never tracked; partial release batches keep everything tracked
  (idempotent retry). Pinned by `release_paths_survive_injection_failure_and_retry`
  and the live ignored test.
- **One defect (defense-in-depth default inverted)**: an exact-duplicate
  reliable seq is *re-applied*, not suppressed — F28. Keys/buttons are
  neutralized by the sink's held-state dedupe, but a duplicated `Wheel`/`Text`
  would double-fire. Unreachable through a well-behaved SCTP reliable channel;
  the rig's duplicate probe only duplicates signaling lines, not wire
  messages, so this path is untested.

## 5. Invariant audit

| Invariant | Encoding | Assessment |
|---|---|---|
| 3 — bounded queues | `FrameQueue` caps 1/1/2/1 with counted newest-wins/reject; `LatestSlot` cap 1; JSONL sink `sync_channel(65,536)` + backpressure counter; `FileSignaling` 1 MiB/drain read bound + torn-line retention + version check; engine: events 256 (oldest-drop, counted), video rx 4 (newest-wins, counted), per-channel send queues 256/32/256/8 with SCTP-backpressure pump | **Holds** in production paths. Test-only `SignalingHub` inboxes are unbounded `VecDeque` (fine for a test fabric; M3 client tests should not reuse it for load). `Node::channel_open_order` grows 4 `&'static str` per clean-disconnect (cleared only on `teardown_transport`, not `close_transport`) — trivial, but sweep it per session |
| 4 — no TURN | Zero ICE servers configured; gathered `relay` candidates rejected with a typed failure; rig FATALs (`relay_in_use` → run failure) | **Holds**; verified no relay in my run and all committed evidence |
| 6 — no SDP/input in logs | No `eprintln` in node-runtime lib; rig logs states/ids/counters only; SDP travels only in the signaling files (the adapter's documented channel); secret Debug redacted; input Debug redacted | **Holds**, with one unpinned edge: engine errors format upstream `{e}` into strings that reach `transport_failure` → logs (F36b) |
| 7 / unsafe confinement | `unsafe` now in `node-runtime/src/pacing.rs` (waitable timer + `unsafe impl Send`, sound: single-owner-thread use), `node-runtime/src/metrics.rs` (`GetProcessTimes`/`GetProcessMemoryInfo`), `examples/m2_rig.rs` (stimulus window) — all with SAFETY comments and failure handling (pacer falls back to plain timer → sleep) | **Holds in substance, drifts in letter** — AGENTS.md confines unsafe to the `*-windows` crates (F33) |
| 1 — counters carry no pixels | `FrameTiming`/`QueueSample`/`ResourceSample`/`LinkSample` verified field-by-field; cursor pixels only in `CursorMessage` on the cursor channel | **Holds** |

## 6. Budget check

| Budget (AGENTS/PLAN) | Measured | Verdict |
|---|---|---|
| Connect < 5 s warm, direct ICE | 1.14–1.16 s loopback incl. 300 ms scripted consent + file polling (committed 1136/1138; mine 1156/1141) | **Met** |
| Input-to-visible ≤ 80 ms LAN (median) | proxy p50 ≈ 6.8 ms loopback (F8-labeled; adds one refresh + omitted stages for real display) | **Met on loopback**; real-LAN number is the user checkpoint's job |
| Queue depth ≤ 1 steady state | cap-1 queues high-water 1; recv_to_decode high-water 2 of 2 with 1 counted drop in 10 min | **Met** (policy wording mismatch — F35) |
| 60 fps | pacing 60.00 Hz (mine 59.95; F20 fixed and unit-pinned); effective 56 fps encoded / ~51 presented, source- and drop-limited with both pipelines on one GPU, drop→IDR cost quantified | **Pacing met**; effective rate honestly reported; drop→IDR cost is the registered M5 item |
| Memory flat | soak flat (above); **cycles run grows ~+10–12 MiB/session monotonically on both processes** (F26) | **Not bounded across reconnects** |

## 7. Findings (F26 onward)

Severity labels: **blocking-for-M3** (must land before/with M3 integration),
**blocking-for-LAN-checkpoint**, **should-fix** (milestone indicated),
**note**.

### F26 — Per-session memory growth in the cycles hammer (~+10–12 MiB/session, monotonic, both processes), present in committed evidence but unreported — blocking-for-M3

The report's memory-flat claim is scoped to the single-session soak and is
exact there. But the committed cycles artifacts
(`docs/reports/data/m2-rig-20260924-{host,controller}-24.jsonl.gz`, 10 ×
connect/20 s-stream/disconnect with pipelines rebuilt per cycle) show host
working-set bucket averages 109.4 → 135.6 → 152.9 → 175.4 → 194.0 → 212.3 →
232.9 → 242.9 MiB and controller 88.0 → 110.8 → 129.1 → 150.5 → 169.6 → 185.2
→ 208.0 → 216.5 MiB (30 s buckets) — no plateau, ~10–12 MiB retained per
session teardown/rebuild. Ten points on a straight line cannot distinguish a
true leak (DXGI duplication objects, MF transform instances, D3D11 deferred
releases not returned) from allocator/working-set retention, but either way
the M6 gate ("no unbounded growth", soak spanning reconnects) and any real
reconnect flow (the product's network-change path is exactly this
teardown/rebuild) are threatened: ~100 reconnects ⇒ >1 GiB. Required: (1)
surface this in `m2-rig.md`; (2) root-cause (track private bytes vs working
set; test whether explicit device/transform teardown or heap decommit flattens
it); (3) re-run ≥30 cycles with the run summary committed. Reproduction:

```bash
python - <<'EOF'
import gzip, json
with gzip.open(r"docs/reports/data/m2-rig-20260924-host-24.jsonl.gz","rt") as f:
    s=[(r["at_ns"], r["memory_working_set_bytes"]/2**20) for r in map(json.loads, f)
       if r["kind"]=="resource_sample" and r.get("memory_working_set_bytes")]
s.sort(); B=30*10**9
for i in range(0, int(s[-1][0])+1, B):
    b=[v for t,v in s if i<=t<i+B]
    if b: print(f"{i/1e9:5.0f}s avg {sum(b)/len(b):6.1f} max {max(b):6.1f} MiB")
EOF
```

Affected: `crates/node-runtime/examples/m2_rig.rs` (`HostPipeline::stop`,
`ControllerPipeline::stop`, per-session rebuild), the platform crates'
teardown paths (`capture-windows`, `codec-windows`, `render-windows`).

### F27 — `Register` self-ack is queued before the adapter write result is known — should-fix (M3 seam, land with the M3 client)

`crates/node-runtime/src/node.rs` `apply()` → `Action::Send`: the ack is pushed
to `pending_register_acks` and *then* `signaling.send()` is attempted; a
failed Register write still acks `Registered` on the next pump and the machine
goes `Online` despite never having registered. Both M2 adapters make
service-directed sends infallible (file/hub swallow them), so this is latent
today — it becomes a live defect the moment `SignalingIo` is a network client
whose `send` can fail. Fix: queue the ack only when the send returned `Ok`
(and surface the failure via `transport_failure` so the UI can retry). Repro:
unit test with a `SignalingIo` double whose service-directed `send` errs;
assert the machine stays `Registering`.

### F28 — `InputPump` re-applies exact-duplicate reliable sequence numbers — should-fix (M3/M4, small)

`crates/node-runtime/src/input.rs` reliable branch: `gap_check` updates the
watermark to `seq` first, so the guard
`post_gap || last_reliable_seq.is_none_or(|last| *seq == last)` is true for
*every* event at or above the watermark — including a re-delivered duplicate
(`seq == watermark`), which is injected again instead of suppressed. With the
real sink, duplicate key/button events are neutralized by held-state dedupe,
but a duplicated `Wheel` scrolls twice and duplicated `Text` types twice. The
ordered reliable channel does not redeliver, so this is defense-in-depth with
the default inverted; nothing tests it (the rig's dup probe is signaling-only).
Fix: apply only when `seq > watermark` (or first-ever), suppress `==` with its
own counter (also stops reliable stales from incrementing
`moves_stale_suppressed`, which today conflates the two). Repro: extend the
`input.rs` unit tests with a duplicate `Wheel{seq:n}` after `Wheel{seq:n}` and
assert one injection.

### F29 — Headline connect/recovery numbers and the cycles/soak device-lost & pacer claims are not in the committed artifacts — should-fix (evidence retention; same class as M1 F14)

Committed final-full evidence (log + run summary) shows connect 1136 ms /
re-establish 1138 ms; the report's 1145/1143/1148 ms are from uncommitted 60 s
runs. The cycles claims (10/10, connect 1134–1152 ms spread 18 ms,
`device_lost = 0`) and the soak's `device_lost = 0` / `36,001 ticks /
600.01 s` live only in run summaries that were not committed (the committed
`m2-rig-{cycles,soak}-*-summary.json` are latency summaries without those
fields; only the final-full run summaries and logs are committed). All numbers
are mutually consistent and far inside budget — my own run reproduces the
profile — but a gate report's headline numbers must be recomputable from the
tree. Fix: commit the cycles/soak run summaries + logs (or regenerate them
from the committed JSONL where possible) and quote those numbers.

### F30 — `LinkSample.rtt_ms` truncated f64→u32: every committed loopback sample reads 0 — should-fix (before M5 consumes it)

`crates/node-runtime/examples/m2_rig.rs` 1 Hz stats block maps
`stats.rtt_ms.map(|v| v as u32)`. All 601 committed soak samples carry
`rtt_ms: 0` while the actual RTT was 0.18–0.2 ms (visible only in the run
summary's untruncated `transport_stats`). The report's own proxy math is
inconsistent by exactly this amount (p95 16.5 quoted vs 16.7 recomputed with
real RTT). On LAN, single-digit-ms RTTs quantize to whole ms; WAN-matrix
reporting (M5) would lose usable resolution. Fix: keep f64 in `LinkSample`
(schema fields are numeric; check `diagnostics` serde) or store integer
microseconds. Repro:

```bash
python -c "import gzip,json; print(max(r.get('rtt_ms') or 0 for r in map(json.loads, gzip.open(r'docs/reports/data/m2-rig-20260924-host-25.jsonl.gz','rt')) if r['kind']=='link_sample'))"
```

### F31 — `recv_ns` is stamped at poll-drain, not packet arrival — should-fix (measurement point; land with M3/M5)

`m2_rig.rs` stamps `recv_ns` when the controller's ~2 ms main loop drains
`poll_video()`; the transport's actual arrival time is never surfaced. The
controller half (p50 0.36 ms) therefore excludes the arrival→poll interval
(bounded by loop cadence plus any preceding same-iteration work — my run shows
a 1.87 s `LinkSample` cadence gap during teardown, proving the loop can stall).
The schema pins `recv_ns` = "first packet of frame received". Not wrong enough
to move the loopback conclusions, but the same stamping will under-report on
real networks and M5 will consume it. Fix: stamp inside the engine at
depacketize/assembly completion and carry it on `ReceivedFrame`, or amend the
schema note to say "drained by the runtime".

### F32 — Channel-queue F5 cadence is half-implemented (1 Hz only, no per-change samples) — should-fix (M3/M4 when channel queues are formalized)

The schema binds channel queues to "≥1 Hz plus on every depth change while
any of them is non-empty". The rig samples them only inside the 1 Hz stats
tick; the engine's internal per-channel queues have no per-change hook into
the sink. During input bursts (30 moves per loop iteration) transient
non-empty windows fall between ticks, so "high_water 0 / 0 dropped / 0
replaced" in the soak is plausible (SCTP absorbing bursts, as the spike
observed at higher sampling) but not proven per the schema's own rule. Either
wire per-change samples from the engine or record an explicit schema
amendment that transport-internal queues are snapshot-polled.

### F33 — `unsafe` outside the `*-windows` crates violates the AGENTS.md confinement wording — note (fix the doc or move the code)

`node-runtime/src/pacing.rs` (`CreateWaitableTimerExW`/`SetWaitableTimer`/
`WaitForSingleObject` + `unsafe impl Send for FramePacer` — sound: the handle
is used single-threaded, kernel handles are process-wide, and the pacer owns
no other shared state), `node-runtime/src/metrics.rs`
(`GetProcessTimes`/`GetProcessMemoryInfo`), and the rig's stimulus window.
All carry SAFETY comments and failure handling (pacer degrades to plain timer
then sleep+spin; samplers return `None`). Either amend AGENTS.md's
confinement rule to name `node-runtime` (composition crate with sanctioned
Win32: pacing + process introspection) or move `FramePacer` next to the
platform crates. Decide before more Win32 accretes in the runtime.

### F34 — `World::route`'s ICE-candidate arm is dead code encoding the opposite routing; the deterministic harness never proves the routing the real system uses — should-fix (extend the harness, do not trust it)

In `crates/session/tests/two_peers.rs` every candidate is injected directly
(role-complementarily: controller A receives → A's controller machine), so
`route`'s `IceCandidate` arm (role-preserving: host-minted → target's *host*
machine) is unreachable — and it contradicts `node.rs`'s correct
role-complementary mapping. The real routing is proven only by
`webrtc_drive.rs` (real webrtc-rs, both directions) and rig runs — good
evidence, but the *executable spec* diverges from the runtime on this arm, so
any future harness-driven candidate scenario would test the wrong thing or
fail confusingly. Fix: align the arm with the runtime's routing (or delete it
and document direct injection), add a two-direction candidate scenario to
`two_peers.rs` (each side's gathered candidate reaches the peer's
transport-owning machine and both `ForwardIce`s fire), and mirror it in
`world_parity.rs` (current `ice_candidates_route_to_the_peer_transport_owner`
covers one direction only).

### F35 — `recv_to_decode` drop policy mismatches the schema table — note

`docs/perf-counter-schema.md` says `recv_to_decode` is "bounded, drop-oldest";
the runtime implements `DropPolicy::Reject` (drop-*newest*, counted). For a
video pipeline with the IDR-gate design this is defensible (a dropped newest
frame becomes a frame-id gap → keyframe request), but the binding doc and the
implementation disagree. Amend the schema line (explicit contract change) or
switch the policy. Impact today: 1 drop in 10 minutes.

### F36 — Doc/robustness nits — note

(a) `node.rs` module docs say "Two documented deviations" while `m2-rig.md`
lists three (compose/apply failure mapping is the third) and several
defensive-only differences (inbound service envelopes counted, late
`ChannelsOpen`, `World`'s `unreachable!` → counted illegal transitions) are
documented only in code comments — one doc pass. (b) Engine error strings
embed upstream `webrtc-rs` `Display` text and flow into
`transport_failure` → logs; observed strings are SDP-free, but invariant 6
would benefit from a cheap pinning test asserting transport error strings
never contain SDP markers (`o=-`, `a=ice-pwd`, `a=fingerprint`) before M3's
network error paths arrive. (c) `JsonlReport` has no 128 MiB rotation (F6
rule): soak raw files are 33/63 MB, so nothing was lost, but a 60-min M6 soak
is ~4–6× that in a single file — implement rotation or waive explicitly before
M6. (d) The rig comment "teardown close is bounded at 7 s" — engine
`CLOSE_TIMEOUT` is 5 s (+2 s on Drop). (e) `LatestSlot` (cursor) counters are
never surfaced anywhere; cursor newest-wins replacements are unobservable.

## 8. M3 risk evaluation (report §"Risks for M3")

| Report risk | Assessment | Disposition |
|---|---|---|
| 1. Drop→IDR cycle under encoder pressure | Real and quantified: soak 1,056 obsolete drops → 1,011 IDR requests → 3,291 gated frames; my 20 s run: 27/27/83. The 250 ms keyframe-request rate limit already prevents IDR amplification; the cost is presented-fps ~51 vs encoded 56 on a single GPU running both pipelines. Root causes are M5-shaped (congestion pacing, encode headroom). | **M5 work item**, not M3; report should own the presented-rate gap in its budget table |
| 2. One-sided teardown detection | The control-channel goodbye is a data-plane workaround; a hard kill (process death, power loss, network partition with no goodbye) is invisible until ICE/consent timeouts — exactly what the real-LAN checkpoint could hit. M3's signaling `Disconnect` propagation + presence TTL is the designed fix. | **Must be an M3 work item** (disconnect propagation + stale-presence handling, with a contract test for silent-peer death) |
| 3. `SignalingIo` seam is single-direction per process | Correct and intended; the product's both-roles-one-process case needs the M3 client. F27 (self-ack before write result) lives exactly on this seam and must be fixed with it; do not reuse the unbounded `SignalingHub` inboxes for client load tests (§5). | **Must be an M3 work item** (+ F27) |
| 4. Rig scripting in the example | Fine — consent/re-registration/watchdog are rig concerns; M4 owns the UX equivalents | No action |
| 5. Software-encoder fallback not exercised by the rig | True (hardware selected); covered by M1 codec tests only. The LAN checkpoint should note it if the second PC lacks NVENC | Note for the checkpoint; a one-flag rig run would close it cheaply |
| 6. Real cursor motion, cross-machine RTT/jitter, NAT/loss | Waits for the user checkpoint (D2) — correct scoping | User checkpoint |
| *(new)* Per-session memory growth (F26) | Not in the report's risk list; committed cycles evidence shows it | **Must be an M3 work item** before reconnect flows ship |

Also for the LAN checkpoint brief: the rig's host input path uses a recording
sink — the checkpoint is the first time the real `SendInputSink` runs in a
session (its only live evidence is the ignored unit test, which passed);
`set_monitor_rect`/`SelectMonitor` wiring is deliberately M4, so the host will
confine pointer input to the primary monitor — expected, not a bug.

## 9. Recommendation

**PASS-WITH-FINDINGS.** The M2 gate is genuinely met and reproducible: all
quality-bar commands green (140 + 8 ignored tests), the four rig scenarios'
committed soak evidence recomputes *exactly* (percentiles, frame/drop
accounting, queue cadence/watermarks, flat single-session memory), my own
bounded rig run passes end-to-end with schema-exact counters across a
reconnect, the input-safety design is correct and well-tested, TURN is absent
and guarded, and the two documented World deviations are benign mappings
backed by real-transport tests. The substantive items: **F26** (per-reconnect
memory growth visible in the committed cycles data and unreported — the M1
F13 lesson repeated in a new place), the **F27/F28** latent correctness bugs
at exactly the seams M3 will light up, and the measurement-fidelity set
(**F29–F32, F34**) that M5/M6 evidence quality depends on. None blocks the
real-LAN user checkpoint. Conditions: F26 root-caused and re-evidenced, F27
fixed, and F28 fixed before or with M3 integration; F29 evidence committed
with the F26 re-run; F30–F32/F34 before the M5 WAN matrix; notes tracked.
Tag `m2-direct-transport` after the report updates land.

## 10. Reproduction index

```bash
# Gates (§1)
cargo fmt --all -- --check && scripts/check.sh && scripts/test.sh
cargo test --workspace -- --ignored            # real display/GPU + live SendInput
cargo test -p node-runtime                     # 34
cargo test -p transport-webrtc                 # 23

# Own rig scenario (§1) — see the two-command block there
# Evidence recompute (§2): the Python snippets in F26/F30 plus the
# percentile pass in §2 (nearest-rank, warm-up 60 s by send_ns/present_ns)

# F27 repro: SignalingIo double with failing service-directed send → machine must stay Registering
# F28 repro: unit test re-delivering Wheel{seq:n} twice → exactly one injection

# Schema check of any rig JSONL: kinds, snake_case, session scoping,
# LinkSample 1 Hz, queue-sample cadence (see §1 paragraph)
```
