#!/usr/bin/env bash
# M6 60-minute soak runner (RD-014): two-process rig, congestion ON,
# 4% app-layer loss, with a hard mid-soak liveness watchdog (fps floor /
# stall, queue bounds, memory slope + cap, input safety, status freshness).
# A violation kills the run and marks it FAILED — it must not survive to
# the summary.
#
# Usage: bash docs/reports/data/m6-soak/run-soak.sh [stream_secs] [loss_pct]
set -uo pipefail
cd "$(dirname "$0")/../../../.."   # repo root

SECS="${1:-3600}"
LOSS="${2:-4}"
OUT="docs/reports/data/m6-soak"
BIN="target/release/examples/m2_rig.exe"
SIG="$(mktemp -d "$PWD/$OUT/.sig-XXXXXX")"

mkdir -p "$OUT"
echo "=== m6 soak: stream=${SECS}s loss=${LOSS}% congestion=on start=$(date -Iseconds)"

"$BIN" --role host --dir "$SIG" --scenario soak --stream-secs "$SECS" \
    --congestion on --netem "loss=$LOSS" \
    --metrics-dir "$PWD/$OUT" --report-stem m6-soak-host \
    --summary "$PWD/$OUT/host-summary.json" > "$OUT/host.log" 2>&1 &
sleep 1
"$BIN" --role controller --dir "$SIG" --scenario soak --stream-secs "$SECS" \
    --no-stimulus --mouse-moves 20000 --drop-fast-pct 0 --reorder-fast-pct 0 --drop-reliable-nth 0 \
    --metrics-dir "$PWD/$OUT" --report-stem m6-soak-ctrl \
    --summary "$PWD/$OUT/ctrl-summary.json" > "$OUT/ctrl.log" 2>&1 &
CTRLPID=$!

python - "$SIG" "$SECS" "$OUT" <<'WATCHDOG'
import json, os, sys, time, glob, subprocess

sig, secs, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]

def status_path(role):
    return os.path.join(sig, f"{role}-status.json")

def read_status(role):
    try:
        with open(status_path(role), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def mtime_age(path):
    try:
        return time.time() - os.path.getmtime(path)
    except OSError:
        return None

def ctrl_jsonl():
    cands = glob.glob(os.path.join(out, "m6-soak-ctrl-rig-controller*.jsonl"))
    cands = [c for c in cands if not c.endswith((".gz", ".1", ".2"))]
    return max(cands, key=os.path.getmtime) if cands else None

cursor_file, cursor_off = None, 0
last_csv_t = -60.0
last_size, last_size_t = -1, 0.0
presents = []            # (t, n_new)
mem = []                 # (t, host_ws, host_priv, ctrl_ws, ctrl_priv)
csv = open(os.path.join(out, "watchdog.csv"), "w", buffering=1)
csv.write("t_s,host_ws_mib,host_priv_mib,ctrl_ws_mib,ctrl_priv_mib,presents_60s\n")
viol = open(os.path.join(out, "watchdog.log"), "w", buffering=1)
fail = None
t0 = time.time()
BASELINE_AT = 300
MAX_DELTA_MIB = 64.0
SLOPE_MIB_PER_MIN = 1.5
# v2 (post-diagnosis): the rig's JsonlReport flushes a 1 MiB BufWriter
# only on fill/close — at degraded record rates the on-disk file freezes
# for minutes while the pipeline is alive (diag run: 7.9 fps presented,
# backpressure 0, file frozen ~110 s). Liveness floors are therefore
# long-horizon and flush-aware; quality judgments happen post-hoc from the
# full JSONL + summary.
FPS_FLOOR_PER_600S = 60   # >= 0.1 fps over any rolling 600 s of flushed records
FILE_FROZEN_S = 600       # metrics file (size+mtime) unchanged this long = writer/producer death

def violation(reason):
    global fail
    if fail is None:
        fail = f"{reason} (at t={int(time.time()-t0)}s)"
        viol.write("VIOLATION: " + fail + "\n")

while True:
    now = time.time() - t0
    done = os.path.exists(os.path.join(sig, "done.marker"))
    # --- liveness: status freshness (the rig loop rewrites it every ~2 ms)
    hage, cage = mtime_age(status_path("host")), mtime_age(status_path("controller"))
    if now > 20 and not done:
        if hage is not None and hage > 20 and fail is None:
            violation(f"host status stale {hage:.0f}s (process hung or dead)")
        if cage is not None and cage > 20 and fail is None:
            violation(f"controller status stale {cage:.0f}s (process hung or dead)")
    if done and (cage is None or cage > 20):
        viol.write("controller finished cleanly (done marker, status went quiet)\n")
        break
    hs, cs = read_status("host"), read_status("controller")
    if now > 30 and not done:
        if hs and hs.get("host_state") != "Connected" and fail is None:
            violation(f"host state {hs.get('host_state')} mid-soak")
        if cs and cs.get("controller_state") != "Connected" and fail is None:
            violation(f"controller state {cs.get('controller_state')} mid-soak")
        # input safety: held keys must be zero at every check after warm-up
        if hs:
            held = (hs.get("input") or {}).get("held")
            if held not in (0, None) and fail is None:
                violation(f"host held keys {held} != 0 mid-soak")
    # --- memory (working set AND private bytes, both processes)
    if hs and cs:
        hw = hs["proc"]["ws_bytes"]/2**20; hp = hs["proc"]["private_bytes"]/2**20
        cw = cs["proc"]["ws_bytes"]/2**20; cp = cs["proc"]["private_bytes"]/2**20
        mem.append((now, hw, hp, cw, cp))
        if now > BASELINE_AT + 60:
            b = min((m for m in mem if BASELINE_AT <= m[0] <= BASELINE_AT + 60),
                    key=lambda m: m[0])
            if hw - b[1] > MAX_DELTA_MIB: violation(f"host ws +{hw-b[1]:.0f} MiB over baseline")
            if hp - b[2] > MAX_DELTA_MIB: violation(f"host private +{hp-b[2]:.0f} MiB over baseline")
            if cw - b[3] > MAX_DELTA_MIB: violation(f"ctrl ws +{cw-b[3]:.0f} MiB over baseline")
            if cp - b[4] > MAX_DELTA_MIB: violation(f"ctrl private +{cp-b[4]:.0f} MiB over baseline")
            def slope(idx):
                pts = [m for m in mem if m[0] >= now - 600]
                n = len(pts)
                if n < 30: return 0.0
                xs = [p[0]/60 for p in pts]; ys = [p[idx] for p in pts]
                mx = sum(xs)/n; my = sum(ys)/n
                num = sum((x-mx)*(y-my) for x, y in zip(xs, ys))
                den = sum((x-mx)**2 for x in xs)
                return num/den if den else 0.0
            if now > 700:
                for idx, name in ((1,"host ws"),(2,"host priv"),(3,"ctrl ws"),(4,"ctrl priv")):
                    s = slope(idx)
                    if s > SLOPE_MIB_PER_MIN: violation(f"{name} slope {s:.2f} MiB/min")
    # --- jsonl tail: rolling fps floor, stall detection, queue bounds
    # (judged only while the session is streaming: after the stream target
    # the controller drains and presents legitimately stop)
    streaming = bool(cs and cs.get("controller_state") == "Connected" and now <= secs + 20)
    jf = ctrl_jsonl()
    if jf:
        if jf != cursor_file:
            cursor_file, cursor_off = jf, 0
        size = os.path.getsize(jf)
        if size < cursor_off:
            cursor_off = 0  # rotation: fresh current file
        new_p = 0
        with open(jf, "r", encoding="utf-8", errors="replace") as f:
            f.seek(cursor_off)
            for line in f:
                try: r = json.loads(line)
                except Exception: continue
                k = r.get("kind")
                if k == "frame_timing" and r.get("present_ns") is not None:
                    new_p += 1
                elif k == "queue_sample":
                    q = r.get("queue"); hwq = r.get("high_water") or 0
                    if q in ("capture_to_encode","encode_to_send","decode_to_present") and hwq > 1:
                        violation(f"{q} high_water {hwq} > 1")
                    if q == "recv_to_decode" and hwq > 8:
                        violation(f"recv_to_decode high_water {hwq} > 8")
                    if q in ("channel_input_fast","channel_input_reliable","channel_control","channel_cursor"):
                        cap = r.get("capacity") or 1
                        if (r.get("depth") or 0) > cap:
                            violation(f"{q} depth {r.get('depth')} > cap {cap}")
            cursor_off = f.tell()
        if streaming or now < 120:
            presents.append((now, new_p))
        size_now = os.path.getsize(jf)
        if streaming and now > 700:
            per_10min = sum(n for t, n in presents if t >= now - 600)
            if per_10min < FPS_FLOOR_PER_600S:
                violation(f"fps floor: {per_10min} flushed presents in trailing 600 s (< {FPS_FLOOR_PER_600S})")
        if streaming and now > 700 and size_now == last_size and now - last_size_t > FILE_FROZEN_S:
            violation(f"metrics file frozen {now - last_size_t:.0f}s at {size_now} bytes while Connected")
        if size_now != last_size:
            last_size, last_size_t = size_now, now
    if now - last_csv_t >= 55 and mem:
        last_csv_t = now
        m = mem[-1]
        w60 = sum(n for t, n in presents if t >= now - 600)
        csv.write("%d,%.1f,%.1f,%.1f,%.1f,%d\n" % (int(now), m[1], m[2], m[3], m[4], w60))
    if fail:
        break
    if now > secs + 180:
        viol.write("watchdog: run window elapsed without completion\n")
        violation("run exceeded stream window + 180 s")
        break
    time.sleep(10)

csv.close()
if fail:
    viol.write("SOAK FAILED: %s\n" % fail)
    subprocess.run(["taskkill", "/IM", "m2_rig.exe", "/F"], capture_output=True)
    sys.exit(1)
viol.write("watchdog: clean exit\n")
WATCHDOG
WD=$?

wait $CTRLPID; CTRLRC=$?
sleep 20   # host observes the done marker and exits
taskkill //IM m2_rig.exe //F >/dev/null 2>&1 || true
rm -rf "$SIG"
echo "=== m6 soak done ctrl_rc=$CTRLRC watchdog_rc=$WD end=$(date -Iseconds)"
if [ "$CTRLRC" -ne 0 ] || [ "$WD" -ne 0 ]; then
  echo "SOAK RESULT: FAIL"
  exit 1
fi
echo "SOAK RESULT: PASS"
