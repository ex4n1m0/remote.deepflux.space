#!/usr/bin/env python
"""M6 soak post-hoc analyzer: reads the rig's schema-exact JSONL pair and
produces the F6-format numbers the m6-soak report quotes. Never subtracts
timestamps across clock domains: per-stage percentiles per side; the
input-to-visible PROXY is host capture->send + ICE RTT + controller
recv->present (F8 label: omits controller input->send and host
inject->capture)."""
import json, sys, gzip, collections
from pathlib import Path

def load(path):
    op = gzip.open if str(path).endswith(".gz") else open
    with op(path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except Exception:
                    pass

def pct(vals, q):
    if not vals:
        return None
    v = sorted(vals)
    return v[min(len(v) - 1, int(q * len(v)))]

def pctl(vals):
    if not vals:
        return None
    v = sorted(vals)
    return {"p50": pct(v, .5), "p95": pct(v, .95), "p99": pct(v, .99), "max": v[-1],
            "n": len(v)}

def ms(dividend):
    return None if dividend is None else round(dividend / 1e6, 3)

def main(outdir):
    host_j = sorted(Path(outdir).glob("m6-soak-host-rig-host*.jsonl*"))
    ctrl_j = sorted(Path(outdir).glob("m6-soak-ctrl-rig-controller*.jsonl*"))
    # stage latencies (same clock domain per side)
    stages = collections.defaultdict(list)
    queue = {}   # kind -> dict(depth_max, cap, hw_max, dropped_last, replaced_last)
    link = collections.defaultdict(list)  # field -> value
    est_trace = []
    presents = []
    frames_host = []
    warm_ns = 60_000_000_000
    res = {"warmup_excluded_s": 60}
    for rec in load(host_j[0]):
        k = rec.get("kind")
        if k == "frame_timing":
            frames_host.append(rec)
            c, es, ed, s = (rec.get(x) for x in ("capture_ns", "encode_submit_ns", "encode_done_ns", "send_ns"))
            if None not in (c, es) and s is not None and s >= warm_ns:
                stages["capture_to_encode_submit"].append(es - c)
                if ed is not None:
                    stages["encode_submit_to_done"].append(ed - es)
                    stages["encode_done_to_send"].append(s - ed)
                stages["host_half_capture_to_send"].append(s - c)
        elif k == "queue_sample":
            q = queue.setdefault(rec["queue"], {"depth_max": 0, "cap": rec.get("capacity"),
                                                "hw_max": 0, "dropped": 0, "replaced": 0,
                                                "depth_hist": collections.Counter()})
            q["depth_max"] = max(q["depth_max"], rec.get("depth") or 0)
            q["cap"] = rec.get("capacity") or q["cap"]
            q["hw_max"] = max(q["hw_max"], rec.get("high_water") or 0)
            q["dropped"] = max(q["dropped"], rec.get("dropped") or 0)
            q["replaced"] = max(q["replaced"], rec.get("replaced") or 0)
            q["depth_hist"][rec.get("depth") or 0] += 1
        elif k == "link_sample":
            for f in ("rtt_ms", "send_bitrate_kbps", "available_bandwidth_kbps",
                      "remote_loss_percent", "remote_rtt_ms", "loss_percent"):
                v = rec.get(f)
                if v is not None:
                    link[f].append(v)
            est_trace.append((rec.get("at_ns"), rec.get("available_bandwidth_kbps"),
                              rec.get("remote_loss_percent")))
    for rec in load(ctrl_j[0]):
        k = rec.get("kind")
        if k == "frame_timing":
            r, d, p = (rec.get(x) for x in ("recv_ns", "decode_done_ns", "present_ns"))
            if p is not None:
                presents.append(rec)
                if p >= warm_ns and None not in (r, d):
                    stages["recv_to_decode"].append(d - r)
                    stages["decode_to_present"].append(p - d)
                    stages["ctrl_half_recv_to_present"].append(p - r)
        elif k == "queue_sample":
            q = queue.setdefault(rec["queue"], {"depth_max": 0, "cap": rec.get("capacity"),
                                                "hw_max": 0, "dropped": 0, "replaced": 0,
                                                "depth_hist": collections.Counter()})
            q["depth_max"] = max(q["depth_max"], rec.get("depth") or 0)
            q["cap"] = rec.get("capacity") or q["cap"]
            q["hw_max"] = max(q["hw_max"], rec.get("high_water") or 0)
            q["dropped"] = max(q["dropped"], rec.get("dropped") or 0)
            q["replaced"] = max(q["replaced"], rec.get("replaced") or 0)
            q["depth_hist"][rec.get("depth") or 0] += 1

    res["stages_ms"] = {k: {kk: (ms(vv) if kk != "n" else vv) for kk, vv in pctl(v).items()}
                        for k, v in stages.items()}
    res["queues"] = {k: {"capacity": v["cap"], "high_water": v["hw_max"],
                         "depth_max": v["depth_max"], "dropped": v["dropped"],
                         "replaced": v["replaced"]} for k, v in queue.items()}
    res["link"] = {k: pctl(v) for k, v in link.items()}

    # i2v proxy join by frame_id (host half + ICE RTT p50 + controller half)
    host_by_id = {r["frame_id"]: r for r in frames_host if r.get("send_ns") is not None}
    rtt_p50 = pct(link.get("rtt_ms", []), .5) or 0.0
    prox = []
    for r in presents:
        h = host_by_id.get(r["frame_id"])
        if h and h.get("send_ns") is not None and r.get("recv_ns") is not None:
            prox.append((h["send_ns"] - h["capture_ns"]) / 1e6 + rtt_p50 +
                        (r["present_ns"] - r["recv_ns"]) / 1e6)
    if prox:
        v = sorted(prox)
        res["i2v_proxy_ms"] = {"p50": round(pct(v, .5), 2), "p95": round(pct(v, .95), 2),
                               "p99": round(pct(v, .99), 2), "max": round(v[-1], 2),
                               "n": len(v), "note": "F8 proxy: + ICE RTT p50 %.3f ms" % rtt_p50}
    # presented fps per 5-min bucket (whole file, incl. warmup, labeled)
    if presents:
        t0 = min(r["present_ns"] for r in presents)
        buckets = collections.Counter()
        for r in presents:
            buckets[int((r["present_ns"] - t0) / 300e9)] += 1
        res["fps_per_5min"] = {f"{b*5}-{b*5+5}min": round(n / 300, 2) for b, n in sorted(buckets.items())}
    # estimate dynamics: distinct values, min/max, decision-adjacent trace
    ests = [e for _, e, _ in est_trace if e is not None]
    if ests:
        res["estimate_kbps"] = {"distinct": len(set(ests)), "min": min(ests), "max": max(ests)}
    rls = [x for x in link.get("remote_loss_percent", []) if x is not None]
    if rls:
        res["rr_loss_nonzero_frac"] = round(sum(1 for x in rls if x > 0) / len(rls), 3)
    print(json.dumps(res, indent=1))

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "docs/reports/data/m6-soak")
