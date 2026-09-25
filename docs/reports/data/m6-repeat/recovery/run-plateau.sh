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

echo "=== plateau: cycles x30 under load start=$(date -Iseconds)"
SIG="$(mktemp -d "$PWD/$OUT/.sigA-XXXXXX")"
"$BIN" --role host --dir "$SIG" --scenario cycles --cycles 30 --cycle-stream-secs 25 \
  --congestion on --netem "loss=4" \
  --metrics-dir "$PWD/$OUT" --report-stem m6-plateau-host \
  --summary "$PWD/$OUT/m6-cycles-host-summary.json" > "$OUT/m6-cycles-host.log" 2>&1 &
HP=$!
sleep 1
"$BIN" --role controller --dir "$SIG" --scenario cycles --cycles 30 --cycle-stream-secs 25 \
  --no-stimulus --mouse-moves 1500 --drop-fast-pct 0 --reorder-fast-pct 0 --drop-reliable-nth 0 \
  --metrics-dir "$PWD/$OUT" --report-stem m6-plateau-ctrl \
  --summary "$PWD/$OUT/m6-cycles-ctrl-summary.json" > "$OUT/m6-cycles-ctrl.log" 2>&1
RC_A=$?
wait $HP || RC_A=1
sleep 5; taskkill //IM m2_rig.exe //F >/dev/null 2>&1 || true
rm -rf "$SIG"
echo "=== plateau done rc=$RC_A"
if [ $RC_A -ne 0 ]; then echo "PLATEAU RESULT: FAIL"; exit 1; fi
echo "PLATEAU RESULT: PASS"
