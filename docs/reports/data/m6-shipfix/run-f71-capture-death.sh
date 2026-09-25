#!/usr/bin/env bash
# M6 ship-fix F71 integration evidence: inject a typed capture death
# mid-stream (`--chaos-capture-death-after N` forces the sticky dead state
# the M6 soak hit naturally at minute 45.2) and assert the session ends
# `TransportError` within seconds — never a frozen `Connected` stream.
#
# Asserts on the host summary:
#   * a session was established first (the death is genuinely mid-stream),
#   * host.capture_dead.died == true with the forced reason,
#   * host.capture_dead.session_end_after_ms exists and is < 10 000 ms,
#   * sessions.ends contains `TransportError` (the typed machine end).
set -uo pipefail
cd "$(dirname "$0")/../../../.."

OUT="docs/reports/data/m6-shipfix"
BIN="target/release/examples/m2_rig.exe"
mkdir -p "$OUT"

SIG="$(mktemp -d "$PWD/$OUT/.sigF71-XXXXXX")"
"$BIN" --role host --dir "$SIG" --scenario soak --stream-secs 40 \
  --chaos-capture-death-after 40 \
  --metrics-dir "$PWD/$OUT" --report-stem f71-death-host \
  --summary "$PWD/$OUT/f71-death-host-summary.json" > "$OUT/f71-death-host.log" 2>&1 &
HP=$!
sleep 1
"$BIN" --role controller --dir "$SIG" --scenario soak --stream-secs 40 \
  --no-stimulus --mouse-moves 200 --drop-fast-pct 0 --reorder-fast-pct 0 --drop-reliable-nth 0 \
  --metrics-dir "$PWD/$OUT" --report-stem f71-death-ctrl \
  --summary "$PWD/$OUT/f71-death-ctrl-summary.json" > "$OUT/f71-death-ctrl.log" 2>&1
RC=$?
wait $HP || RC=1
sleep 2; taskkill //IM m2_rig.exe //F >/dev/null 2>&1 || true
rm -rf "$SIG"

python - "$OUT/f71-death-host-summary.json" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1]))
fail = []
if s.get("failed"):
    fail.append(f"run failures: {s['failures']}")
if not s.get("sessions", {}).get("established"):
    fail.append("no session established (death was not mid-stream)")
host = s.get("host", {})
dead = host.get("capture_dead", {})
if not dead.get("died"):
    fail.append(f"capture_dead.died is false: {dead}")
if "chaos" not in (dead.get("reason") or ""):
    fail.append(f"death reason missing chaos marker: {dead.get('reason')}")
after = dead.get("session_end_after_ms")
if after is None:
    fail.append("session_end_after_ms absent — session never ended after death (F71 freeze!)")
elif after >= 10_000:
    fail.append(f"session end took {after} ms >= 10 s after capture death")
ends = s.get("sessions", {}).get("ends", [])
if "TransportError" not in ends:
    fail.append(f"session end cause not TransportError: {ends}")
if fail:
    print("F71 RESULT: FAIL")
    for f in fail:
        print(" -", f)
    sys.exit(1)
print(f"F71 RESULT: PASS (death -> typed session end in {after} ms; ends={ends})")
EOF
PYRC=$?

if [ $RC -ne 0 ] || [ $PYRC -ne 0 ]; then
  echo "F71 SHIP TEST: FAIL (rig rc=$RC, asserts rc=$PYRC)"
  exit 1
fi
echo "F71 SHIP TEST: PASS"
