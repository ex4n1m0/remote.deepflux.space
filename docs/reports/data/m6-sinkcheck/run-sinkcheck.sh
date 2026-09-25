#!/usr/bin/env bash
# M6 sink-perturbation check (perf-counter-schema M6 obligation: counter
# emission must not itself perturb the measured stages): two short clean
# loopback runs (loss=0, congestion off, no input chaos) — one WITHOUT
# metrics, one WITH the JSONL sink — compare encode-side stage percentiles.
set -uo pipefail
cd "$(dirname "$0")/../../../.."
OUT="docs/reports/data/m6-sinkcheck"
BIN="target/release/examples/m2_rig.exe"
mkdir -p "$OUT"

run_pair() {  # $1 = tag, $2 = metrics-dir-or-empty
  local tag="$1" metrics="$2"
  local SIG; SIG="$(mktemp -d "$PWD/$OUT/.sig-$tag-XXXXXX")"
  local margs=()
  if [ -n "$metrics" ]; then margs=(--metrics-dir "$metrics" --report-stem "sink-$tag-host"); fi
  "$BIN" --role host --dir "$SIG" --scenario soak --stream-secs 70 "${margs[@]}" \
    > "$OUT/$tag-host.log" 2>&1 &
  local HP=$!
  sleep 1
  local margsc=()
  if [ -n "$metrics" ]; then margsc=(--metrics-dir "$metrics" --report-stem "sink-$tag-ctrl" --summary "$metrics/$tag-ctrl-summary.json"); fi
  "$BIN" --role controller --dir "$SIG" --scenario soak --stream-secs 70 --no-stimulus \
    --mouse-moves 0 --drop-fast-pct 0 --reorder-fast-pct 0 --drop-reliable-nth 0 "${margsc[@]}" \
    > "$OUT/$tag-ctrl.log" 2>&1
  local RC=$?
  wait $HP || RC=1
  sleep 3; taskkill //IM m2_rig.exe //F >/dev/null 2>&1 || true
  rm -rf "$SIG"
  echo "--- $tag rc=$RC"
}

run_pair off ""
run_pair on "$PWD/$OUT"
echo "sinkcheck runs done"
