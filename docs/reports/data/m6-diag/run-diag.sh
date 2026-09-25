#!/usr/bin/env bash
# M6 diagnostic: reproduce the soak's controller-side record stall with a
# natural finish, so the rig summary can discriminate writer-drop vs
# pipeline stall (metrics.records / backpressure_events / presented).
set -uo pipefail
cd "$(dirname "$0")/../../../.."
OUT="docs/reports/data/m6-diag"
SIG="$(mktemp -d "$PWD/$OUT/.sig-XXXXXX")"
SECS="${1:-240}"
./target/release/examples/m2_rig.exe --role host --dir "$SIG" --scenario soak \
  --stream-secs "$SECS" --congestion on --netem "loss=4" \
  --metrics-dir "$PWD/$OUT" --report-stem diag-host \
  --summary "$PWD/$OUT/host-summary.json" > "$OUT/host.log" 2>&1 &
sleep 1
./target/release/examples/m2_rig.exe --role controller --dir "$SIG" --scenario soak \
  --stream-secs "$SECS" --no-stimulus --mouse-moves 20000 \
  --drop-fast-pct 0 --reorder-fast-pct 0 --drop-reliable-nth 0 \
  --metrics-dir "$PWD/$OUT" --report-stem diag-ctrl \
  --summary "$PWD/$OUT/ctrl-summary.json" > "$OUT/ctrl.log" 2>&1
RC=$?
sleep 15
taskkill //IM m2_rig.exe //F >/dev/null 2>&1 || true
rm -rf "$SIG"
echo "diag done rc=$RC"
