#!/usr/bin/env bash
# M5 network matrix (RD-013): drives the m2_rig two-process harness through
# the WAN cells on loopback with application-layer netem shaping
# (loss / one-way delay / bandwidth step-down / blackhole) and the
# congestion controller ON. Writes schema-exact JSONL + per-cell summary
# JSON + logs into docs/reports/data/m5-matrix/.
#
# Usage: scripts/m5-matrix.sh [--quick]   (--quick: 16 s cells, smoke only)
set -uo pipefail
cd "$(dirname "$0")/.."

OUT="docs/reports/data/m5-matrix"
BIN="target/release/examples/m2_rig.exe"
CELL_SECS=64            # >= 60 s sustained stream per the M5 gate
BW_SECS=84              # 20/10/5/2 Mbps phases ~20 s each
BLACKHOLE_SECS=15       # connect-time UDP-blocked probe (expected failure)
if [[ "${1:-}" == "--quick" ]]; then CELL_SECS=16; BW_SECS=24; BLACKHOLE_SECS=12; fi

cargo build --release -p node-runtime --example m2_rig
mkdir -p "$OUT"

# run_cell NAME SCENARIO SECS HOST_NETEM [HOST_EXTRA...] -- [CTRL_EXTRA...]
run_cell() {
  local name="$1" scenario="$2" secs="$3" host_netem="$4"
  shift 4
  local host_extra=() controller_extra=()
  local seen_dash=0
  for arg in "$@"; do
    if [[ "$arg" == "--" ]]; then seen_dash=1; continue; fi
    if [[ $seen_dash -eq 0 ]]; then host_extra+=("$arg"); else controller_extra+=("$arg"); fi
  done
  local dir; dir="$(mktemp -d "$PWD/$OUT/.cell-XXXXXX")"
  echo "=== cell $name: scenario=$scenario stream=${secs}s netem='$host_netem' host_extra='${host_extra[*]:-}' ctrl_extra='${controller_extra[*]:-}'"
  "$BIN" --role host --dir "$dir" --scenario "$scenario" \
    --stream-secs "$secs" --congestion on \
    --netem "$host_netem" "${host_extra[@]}" \
    --metrics-dir "$OUT" --report-stem "m5-$name" \
    >"$OUT/$name-host.log" 2>&1 &
  local host_pid=$!
  sleep 1
  "$BIN" --role controller --dir "$dir" --scenario "$scenario" \
    --stream-secs "$secs" --no-stimulus \
    --mouse-moves 3000 --drop-fast-pct 0 --reorder-fast-pct 0 --drop-reliable-nth 0 \
    "${controller_extra[@]}" \
    --metrics-dir "$OUT" --report-stem "m5-$name" \
    --summary "$OUT/$name-summary.json" \
    >"$OUT/$name-controller.log" 2>&1
  local rc=$?
  wait "$host_pid" || true
  rm -rf "$dir"
  echo "--- cell $name rc=$rc"
  return $rc
}

rc_all=0

# Control cell: clean loopback, congestion ON (unshaped GCC baseline).
run_cell baseline soak "$CELL_SECS" "loss=0" || rc_all=1

# Loss axis: 1 / 3 / 5 / 10 %.
for pct in 1 3 5 10; do
  run_cell "loss$pct" soak "$CELL_SECS" "loss=$pct" || rc_all=1
done

# RTT axis: +50 / +150 / +250 ms (half on the video path, half on input).
run_cell rtt50  soak "$CELL_SECS" "delay_ms=25"  -- --input-delay-ms 25  || rc_all=1
run_cell rtt150 soak "$CELL_SECS" "delay_ms=75"  -- --input-delay-ms 75  || rc_all=1
run_cell rtt250 soak "$CELL_SECS" "delay_ms=125" -- --input-delay-ms 125 || rc_all=1

# Bandwidth step-down: 20 -> 10 -> 5 -> 2 Mbps (schedule on the host).
run_cell bwstep soak "$BW_SECS" "rate_kbps=20000" \
  --netem-schedule "21:rate_kbps=10000;41:rate_kbps=5000;61:rate_kbps=2000" || rc_all=1

# Combined worst case: 10% loss + 250 ms RTT + 2 Mbps cap.
run_cell worst soak "$CELL_SECS" "loss=10,delay_ms=125,rate_kbps=2000" \
  -- --input-delay-ms 125 || rc_all=1

# Interface change mid-stream (teardown + re-offer path, recovery timed):
# the `full` scenario tears down at 2/3 of the stream and re-establishes.
run_cell iface full "$CELL_SECS" "loss=0" || rc_all=1

# Connect-time UDP-blocked (expected failure, no hang): both sides'
# candidates point at the discard port so ICE checks die; the typed
# cause must surface within the machines' 10 s connect timeout.
run_cell udpblocked soak "$BLACKHOLE_SECS" "loss=0" \
  --blackhole-candidates -- --blackhole-candidates || rc_all=1

echo "matrix overall rc=$rc_all"
exit $rc_all
