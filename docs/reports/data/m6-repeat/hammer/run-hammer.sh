#!/usr/bin/env bash
# M6 preset + Auto-switch hammer (RD-014): ~100 scripted quality changes
# through the REAL product path — e2e-child controller sends
# EngineCmd::SetQuality -> wire SetQuality -> host engine applies the plan
# (manual presets pin geometry + rebuild once; Auto engages the congestion
# controller, no rebuild except the F70 one-time geometry restore after a
# manual preset). Each iteration is a full product session (connect ->
# stream -> quality change -> viewer-close end -> teardown -> re-online),
# driven against the local signaling service (emulator + dev server).
#
# The e2e-child host exits after its first session by design, so each
# iteration runs a fresh host+controller pair (exit code 0 asserts the
# child's scripted verdicts: quality applied, monitor picked, focus-loss
# probe, resize follow, typed session end). The leak-flat component of the
# F56 history is measured separately on the encoder drop path by
# leak_probe (one process, N rebuilds) — see the m6 report.
#
# Usage: bash docs/reports/data/m6-repeat/hammer/run-hammer.sh [iterations]
set -uo pipefail
cd "$(dirname "$0")/../../../../.."

N="${1:-100}"
OUT="docs/reports/data/m6-repeat/hammer"
BIN="target/release/e2e-child.exe"
EMULATOR_PORT=38091
SERVER_PORT=38093
mkdir -p "$OUT"

# Port hygiene (fb91755 residual risk: e2e port flake)
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort $EMULATOR_PORT,$SERVER_PORT -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id \$_.OwningProcess -Force }" || true
sleep 1

(cd services/signaling && node tools/upstash-emulator.mjs --port $EMULATOR_PORT > "$OLDPWD/$OUT/emulator.log" 2>&1) &
EMU=$!
sleep 1
(cd services/signaling && UPSTASH_REDIS_REST_URL="http://127.0.0.1:$EMULATOR_PORT" UPSTASH_REDIS_REST_TOKEN=local-t \
  node --import tsx tools/dev-server.mjs --port $SERVER_PORT > "$OLDPWD/$OUT/server.log" 2>&1) &
SRV=$!
for i in $(seq 1 40); do
  powershell -NoProfile -Command "(Test-NetConnection -ComputerName 127.0.0.1 -Port $SERVER_PORT -InformationLevel Quiet -WarningAction SilentlyContinue)" 2>/dev/null | grep -qi true && break
  sleep 1
done

TAG=$(date +%s)
HOSTDEV="m6-hammer-host-$TAG"
WORK="$(mktemp -d "$PWD/$OUT/.work-XXXXXX")"
echo "hammer: n=$N host=$HOSTDEV work=$WORK start=$(date -Iseconds)"

CYCLE=(low auto high auto balanced auto)
fails=0
transitions=0
held_violations=0
printf "iter,preset,rc,quality_seen,held\n" > "$OUT/hammer.csv"
for i in $(seq 0 $((N-1))); do
  preset=${CYCLE[$((i % 6))]}
  hstatus="$WORK/h.json"
  cstatus="$WORK/c.json"
  "$BIN" --role host --base-url "http://127.0.0.1:$SERVER_PORT" \
    --device-id "$HOSTDEV-$i" --status-file "$hstatus" \
    --metrics-dir "$WORK/metrics" > "$OUT/last-host.log" 2>&1 &
  HP=$!
  sleep 1
  "$BIN" --role controller --base-url "http://127.0.0.1:$SERVER_PORT" \
    --device-id "m6-hammer-ctrl-$TAG-$i" --host-status-file "$hstatus" \
    --status-file "$cstatus" --quality "$preset" --stream-secs 10 \
    > "$OUT/last-ctrl.log" 2>&1
  RC=$?
  wait $HP || true
  # quality reached the host + input safety from the host status file
  qseen=""; held=""
  python - "$hstatus" "$cstatus" <<'PY' >> "$OUT/hammer-detail.txt" 2>/dev/null || true
import json, sys
try:
    h = json.load(open(sys.argv[1])); c = json.load(open(sys.argv[2]))
    print("HOSTQUAL:%s HELD:%s EST:%d CAUSES:%s" % (
        h.get("quality"), (h.get("input") or {}).get("held"),
        (c.get("verdict") or {}).get("established", 0) if isinstance(c.get("verdict"), dict) else c.get("established", 0),
        (c.get("verdict") or {}).get("ended_causes") if isinstance(c.get("verdict"), dict) else c.get("ended_causes")))
except Exception as e:
    print("STATUSERR", e)
PY
  line=$(tail -1 "$OUT/hammer-detail.txt" 2>/dev/null)
  qseen=$(echo "$line" | sed -n 's/.*HOSTQUAL:\([^ ]*\).*/\1/p')
  held=$(echo "$line" | sed -n 's/.*HELD:\([^ ]*\).*/\1/p')
  echo "$i,$preset,$RC,$qseen,$held" >> "$OUT/hammer.csv"
  [ "$RC" -ne 0 ] && fails=$((fails+1))
  [ "$held" != "0" ] && [ -n "$held" ] && held_violations=$((held_violations+1))
  [ "$qseen" == "$preset" ] && transitions=$((transitions+1))
  # host device id must be stable per iteration set? fresh per run is fine;
  # give the service a beat to settle
  sleep 1
done

kill $EMU $SRV 2>/dev/null || true
rm -rf "$WORK"
echo "hammer: done iterations=$N fails=$fails quality_applied=$transitions held_violations=$held_violations end=$(date -Iseconds)"
if [ "$fails" -gt 0 ] || [ "$held_violations" -gt 0 ] || [ "$transitions" -lt $((N*9/10)) ]; then
  echo "HAMMER RESULT: FAIL"
  exit 1
fi
echo "HAMMER RESULT: PASS"
