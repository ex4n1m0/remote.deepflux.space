#!/usr/bin/env bash
# M6 recovery endurance (RD-014): (a) one process pair, 12 connect/stream/
# teardown/re-signaling cycles under soak-style load (loss=4, congestion
# ON) — the reconnect-path memory slope (F26 discipline: working set AND
# private commit per session end, one process); (b) 10 `full`-scenario
# runs under the same load — each performs ONE mid-stream interface-change
# recovery (ICE-restart probe + data-plane goodbye + hard teardown + full
# re-signaling), timing the re-establishment.
set -uo pipefail
cd "$(dirname "$0")/../../../../.."

OUT="docs/reports/data/m6-repeat/recovery"
BIN="target/release/examples/m2_rig.exe"
mkdir -p "$OUT"

echo "=== (a) cycles x12 under load start=$(date -Iseconds)"
SIG="$(mktemp -d "$PWD/$OUT/.sigA-XXXXXX")"
"$BIN" --role host --dir "$SIG" --scenario cycles --cycles 12 --cycle-stream-secs 25 \
  --congestion on --netem "loss=4" \
  --metrics-dir "$PWD/$OUT" --report-stem m6-cyc-host \
  --summary "$PWD/$OUT/m6-cycles-host-summary.json" > "$OUT/m6-cycles-host.log" 2>&1 &
HP=$!
sleep 1
"$BIN" --role controller --dir "$SIG" --scenario cycles --cycles 12 --cycle-stream-secs 25 \
  --no-stimulus --mouse-moves 1500 --drop-fast-pct 0 --reorder-fast-pct 0 --drop-reliable-nth 0 \
  --metrics-dir "$PWD/$OUT" --report-stem m6-cyc-ctrl \
  --summary "$PWD/$OUT/m6-cycles-ctrl-summary.json" > "$OUT/m6-cycles-ctrl.log" 2>&1
RC_A=$?
wait $HP || RC_A=1
sleep 5; taskkill //IM m2_rig.exe //F >/dev/null 2>&1 || true
rm -rf "$SIG"
echo "=== (a) done rc=$RC_A"

echo "=== (b) full x10 (interface change each) start=$(date -Iseconds)"
RC_B=0
for i in $(seq 1 10); do
  SIG="$(mktemp -d "$PWD/$OUT/.sigB-XXXXXX")"
  "$BIN" --role host --dir "$SIG" --scenario full --stream-secs 45 \
    --congestion on --netem "loss=4" \
    --metrics-dir "$PWD/$OUT" --report-stem "m6-full$i-host" \
    --summary "$PWD/$OUT/m6-full$i-host-summary.json" > "$OUT/m6-full$i-host.log" 2>&1 &
  HP=$!
  sleep 1
  "$BIN" --role controller --dir "$SIG" --scenario full --stream-secs 45 \
    --no-stimulus --mouse-moves 1500 --drop-fast-pct 0 --reorder-fast-pct 0 --drop-reliable-nth 0 \
    --metrics-dir "$PWD/$OUT" --report-stem "m6-full$i-ctrl" \
    --summary "$PWD/$OUT/m6-full$i-ctrl-summary.json" > "$OUT/m6-full$i-ctrl.log" 2>&1
  RC=$?
  wait $HP || RC=1
  [ $RC -ne 0 ] && RC_B=1
  sleep 3; taskkill //IM m2_rig.exe //F >/dev/null 2>&1 || true
  rm -rf "$SIG"
  echo "--- full#$i rc=$RC"
done
echo "=== (b) done rc=$RC_B"

if [ $RC_A -ne 0 ] || [ $RC_B -ne 0 ]; then
  echo "RECOVERY RESULT: FAIL"
  exit 1
fi
echo "RECOVERY RESULT: PASS"
