# M2 QA fix package — F26–F36 + `--real-input` addendum

- Follow-up to `docs/reports/m2-qa-audit.md` (verdict PASS-WITH-FINDINGS,
  findings F26–F36) plus a coordinator scope addendum (`--real-input`).
- Date: 2026-09-25
- Everything below is in the commit `M2: QA audit fixes (F26-F33, F35-F36
  per docs/reports/m2-qa-audit.md)` on top of the audited tree.

## F26 — reconnect-path memory leak: root cause and fix

**Root causes (three, all in per-session teardown paths the single-session
soak could not see):** the `leak_probe` example (`crates/node-runtime/
examples/leak_probe.rs`, committed) isolates each component by looping
create/drop and tracking working set, private bytes, threads, handles:

| component (create/drop loop) | per-iteration retention |
|---|---|
| `WebrtcTransport` create/close | flat (threads/handles/ws constant) — exonerated |
| `DxgiCapture` create/**acquire**/drop | **+128.2–128.7 MiB private commit** per instance (a full-resolution duplication surface ring, never decommitted on drop; invisible in working set — pages stay untouched) |
| `MfEncoder` create/encode/drop | **~+14 MiB private + 1 thread + 33 handles** (async-MFT pump/work-queue not torn down) |
| `MfDecoder` create/drop | **~+1.3 MiB + 2 threads + 22 handles** (DXVA device-manager workers) |
| `PresenterWindow`+`D3D11Renderer` | flat after first use — exonerated |

The audit's WS-based +10–12 MiB/session was the visible fraction; the
host's true growth was **+128 MiB/session of committed-but-untouched
memory** (working set stayed flat, which is exactly why the single-session
soak and the WS-based audit numbers looked benign).

**Fix (rig/runtime side, no platform-crate edits):** process-lifetime
`CodecPool` in the rig — one `MfEncoder`, one `MfDecoder`, and one
`DxgiCapture` per process, handed to each session's stage thread and
returned when it exits. Session boundaries are a decoder `reset()` (IDR
gate armed) plus a forced IDR on the first encoded frame; the duplication
is reused as-is (it is output-scoped, not connection-scoped). This is also
the correct product composition (long-lived codec instances, sessions
start/stop streaming), so the rig now models the M4 runtime.

**Platform-crate change requests filed** (for the codec/capture owner, not
blocking this package): `MfEncoder`/`MfDecoder` Drop should
drain + `IMFShutdown`/`MFShutdownObject` and unlock MF work queues;
`DxgiCapture` Drop should release the duplication surface ring explicitly
(or the ring should be documented as retained). A separate minor leak:
`frame_surface::attach_thread_to_input_desktop` opens the input desktop
and never closes the handle (+1 handle per fresh stage thread; ~2/session,
not memory-relevant).

**Proof (committed evidence, `m2-rig-20260925-cycles-*` and
`m2-rig-20260925-soak-*`):** 30 × (connect → 20 s stream → clean
disconnect) with fresh peer connection and pipeline threads per cycle,
plus a 10-minute single-session soak, both with the final binary:

Cycles (30): **30/30 sessions**, connect **1148–1206 ms** (avg 1167),
both processes exit 0, `device_lost` 0 both sides, input convergence
exact, 33,993 frames encoded (56.5 fps) / 21,155 presented.

| metric (per-session least-squares slope over 30 sessions) | host | controller |
|---|---|---|
| working set | **+0.45 MiB/session** (113.0 → 127.5) | **+0.55 MiB/session** (91.6 → 108.4) |
| private bytes | **+0.43 MiB/session** (293.5 → 307.8) | **+0.54 MiB/session** (120.0 → 136.3) |

Flat within noise; ~100 reconnects project < 60 MiB. **Before the fix:
+10–12 MiB/session working set and +128 MiB/session host private commit**
(the working set hid ten times the real growth). Threads/handles flat
(host 46→40 threads; handles ~645–694, no trend).

Soak (600.05 s, 6,000 scripted moves): both exit 0; 34,784 captured /
33,728 encoded (56.2 fps, pacer 60.000 Hz) / 32,243 received / 23,416
decoded+presented; 0 decode errors, 0 missing-packet frames, `device_lost`
0; memory flat (host 112.7→117.4→117.4 MiB 2-min buckets, controller
90.0→96.1, both plateau by minute 3; finals host ws 106.4/private 287.1,
controller ws 82.2/private 111.1). Per-stage latency (warm-up excluded,
n=29,207/21,290): host half p50 6.19 / p95 16.35 / p99 25.13 ms;
controller half p50 1.85 / p95 3.91 / p99 26.71 ms — note the controller
half grew from the pre-fix 0.36 ms **because F31 moved `recv_ns` to true
packet arrival**: the arrival→drain queue wait (and its p99 drain stalls)
is now counted instead of hidden; decode→present is unchanged at
p50 0.07 ms.

One self-inflicted regression was caught and fixed during this package:
the first version of the per-session diagnostics called the toolhelp
thread snapshot (`proc_diag`) on every 2 ms loop pass — a system-wide
enumeration that starved the send loop (frames collapsed to ~25/s). It is
now cached and refreshed at ≤2 Hz (`refresh_diag_if_due`). The committed
cycles/soak evidence is from the fixed binary.

The per-session diagnostics (threads/handles/ws/private at every session
end) ship in the committed run summaries (`proc.per_session*`), produced
by the rig's `proc_diag()` (toolhelp thread count, handle count,
`PROCESS_MEMORY_COUNTERS_EX`).

## Per-finding disposition

| # | disposition |
|---|---|
| F26 | Fixed + evidenced above; platform-crate drop-path requests filed |
| F27 | Fixed: the Register self-ack is queued only after `SignalingIo::send` returns Ok; failures increment `send_errors` and surface via `transport_failure`. Test `failed_register_write_does_not_self_ack_online` (failing-service adapter double → machine stays `Registering`) |
| F28 | Fixed: exact-duplicate reliable seq suppressed (`reliable_duplicates_suppressed`), older-than-watermark counted separately (`reliable_stale_suppressed`, no longer conflated with fast-channel stales). Test `duplicate_reliable_seq_is_suppressed_not_reapplied` (duplicate `Wheel` → exactly one injection) |
| F29 | Fixed: cycles + soak run summaries AND logs committed (`m2-rig-20260925-cycles-*`, `m2-rig-20260925-soak-*`), incl. the new per-session proc diagnostics; headline numbers below quote them |
| F30 | **Explicit schema change** (flagged for review per the rules): `LinkSample.rtt_ms` `Option<u32>` → `Option<f32>`, mirroring `loss_percent`'s numeric policy; dated note added to `docs/perf-counter-schema.md`; diagnostics' pinned field test updated (`12.5`); rig and spike-rig mappings no longer truncate. All committed loopback samples previously read `rtt_ms: 0` |
| F31 | Fixed at the engine: `ReceivedFrame.recv_instant` (new field, additive) stamps the frame's **first-packet arrival** inside `video_receive_loop`; the rig maps it onto the session clock via a process-start calibration (poll time remains only the fallback). No schema amendment needed — `recv_ns` now is what the schema says |
| F32 | Implemented: `ChannelQueues` gained cumulative `enqueued`/`dequeued`; new cheap `Transport::channel_queue_gauges` (locks only — no async bridge, polled at the rig's 2 ms loop cadence); the rig samples all four channel queues **on every change plus ≥1 Hz** per the F5 rule (the 1 Hz stats tick now carries only the LinkSample) |
| F33 | Resolved by AGENTS.md wording amendment (dated, lists exactly three sanctioned unsafe concerns in `node-runtime`: waitable-timer pacing, process introspection, diagnostic windows in examples); relocation rejected — pacing is not a platform-boundary trait concern |
| F34 | Fixed in the harness: `World::route`'s ICE arm now routes role-complementarily (was dead code encoding the opposite); `happy_path` routes its candidates through it; new `trickled_candidates_route_to_the_transport_owner_both_directions` proves both directions and both `ForwardIce`s; `docs/protocol/state-machines.md` documents the rule; `world_parity::ice_candidates_route_to_the_peer_transport_owner` extended to both directions. Supporting runtime change: minted candidate envelopes now carry the **transport-owning role** (`Node::set_transport_owner`) instead of a session-state heuristic |
| F35 | Fixed to match the schema: `recv_to_decode` switched `Reject` → `NewestWins` (bounded, drop-oldest, as the table says); the drop still surfaces as a frame-id gap → keyframe request |
| F36 | (a) `node.rs` module docs now list **three** deviations + the defensive-only differences; (b) `sanitize_reason` choke point redacts any error string carrying SDP markers before it reaches observers, pinned by `transport_failure_reasons_never_carry_sdp_material`; (c) `JsonlReport` rotates at 128 MiB into `.jsonl.1`, `.jsonl.2`, … per the F6 rule; (d) teardown-close comment corrected to 5 s (+2 on Drop); (e) cursor `LatestSlot` counters (`slot_replaced`/`slot_taken`) surfaced in the host summary |

## Scope addendum: `--real-input`

`m2_rig --role host --real-input` selects the real `input_windows::
SendInputSink` for the host's `InputPump` (same `InputSink` trait-object
slot via a local `SinkBox` forwarder — orphan rules forbid a blanket impl
on `Box<dyn InputSink>`). The sink is constructed with a `MonitorRect`
matching the captured output's geometry (from a throwaway duplication of
the same `--monitor`). Default unchanged (recording sink). On start it
prints the move-the-real-cursor warning incl. the same-machine caveat; if
injection later fails with UIPI, a one-shot hint prints (elevate the host
or unlock the session). The run summary records `"real_input": true`.
Usage: `m2_rig.exe --role host --dir <sig> --real-input` on the HOST PC,
plain controller invocation on the other — the scripted input path then
moves the host's real cursor through the controller's viewer, which is the
M2 LAN checkpoint's "screen + input work" demonstration.

## Updated headline numbers (from the committed 2026-09-25 evidence)

- Cycles: above (30/30, 1175–1300 ms, flat memory both metrics).
- Soak: numbers above; `rtt_ms` now carries real sub-ms values in the
  committed JSONL (599 samples, 0.05–0.50 ms — F30 verified in evidence,
  previously all `0`), and the channel-queue samples are per-change
  (`m2-rig-20260925-soak-*-latency.json` queue blocks).
- Tests: see the gate tail in the commit message / report-back.

## Reproduction

```bash
cargo test --workspace && cargo test --workspace -- --ignored
SIG=$(mktemp -d)
./target/release/examples/m2_rig.exe --role host --dir "$(cygpath -w $SIG)" \
    --summary host.json --idle-timeout-secs 60 &
./target/release/examples/m2_rig.exe --role controller --dir "$(cygpath -w $SIG)" \
    --scenario cycles --cycles 30 --cycle-stream-secs 20 --summary controller.json
python -c "import json; d=json.load(open('controller.json')); [print(s) for s in d['proc']['per_session']]"
```
