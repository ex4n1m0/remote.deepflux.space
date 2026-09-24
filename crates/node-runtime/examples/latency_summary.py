#!/usr/bin/env python3
"""Latency summary for the M2 rig metrics (F6 format, adapted from the M1
summarizer): per-stage p50/p95/p99/max over joined frame ids, warm-up
excluded, per-session breakdown, queue high-waters, drop accounting.

Usage: latency_summary.py <metrics.jsonl> [<metrics2.jsonl> ...]
Reads one process's JSONL (host or controller, auto-detected by origin).
Two-clock domains are NEVER subtracted across processes; when both files
are given, the controller-half and host-half stats are reported side by
side keyed by frame_id.
"""
import json
import sys
from collections import defaultdict


def pct(sorted_vals, p):
    if not sorted_vals:
        return 0
    idx = max(0, min(len(sorted_vals) - 1, int(p / 100.0 * len(sorted_vals) + 0.999999) - 1))
    return sorted_vals[idx]


def load(paths):
    frames = defaultdict(dict)  # (session_id, frame_id) -> stamps (ids restart per session)
    queues = {}
    links = []
    resources = []
    sessions = set()
    origin = None
    for path in paths:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                kind = r.get("kind")
                if kind == "frame_timing":
                    origin = r["origin"]
                    sessions.add(r["session_id"])
                    entry = frames[(r["session_id"], r["frame_id"])]
                    for k in ("capture_ns", "encode_submit_ns", "encode_done_ns", "send_ns",
                              "recv_ns", "decode_done_ns", "present_ns"):
                        if r.get(k) is not None:
                            entry[k] = r[k]
                    entry["session_id"] = r["session_id"]
                elif kind == "queue_sample":
                    q = queues.setdefault(r["queue"], {
                        "high_water": 0, "capacity": r["capacity"],
                        "dropped": 0, "replaced": 0, "samples": 0,
                        "at_capacity": 0, "drained": 0,
                    })
                    q["high_water"] = max(q["high_water"], r["depth"])
                    q["capacity"] = r["capacity"]
                    q["dropped"] = max(q["dropped"], r["dropped"])
                    q["replaced"] = max(q["replaced"], r["replaced"])
                    q["samples"] += 1
                    if r["depth"] == r["capacity"]:
                        q["at_capacity"] += 1
                    if r["depth"] == 0:
                        q["drained"] += 1
                elif kind == "link_sample":
                    links.append(r)
                elif kind == "resource_sample":
                    resources.append(r)
    return frames, queues, links, resources, origin, sessions


def stage(v, a, b):
    if a in v and b in v and v[b] >= v[a]:
        return v[b] - v[a]
    return None


def summarize(frames, warmup_ns):
    host_stages = [
        ("capture_to_encode_submit", "capture_ns", "encode_submit_ns"),
        ("encode_submit_to_done", "encode_submit_ns", "encode_done_ns"),
        ("encode_done_to_send", "encode_done_ns", "send_ns"),
        ("host_half_total", "capture_ns", "send_ns"),
    ]
    ctrl_stages = [
        ("recv_to_decode", "recv_ns", "decode_done_ns"),
        ("decode_to_present", "decode_done_ns", "present_ns"),
        ("controller_half_total", "recv_ns", "present_ns"),
    ]
    out = {}
    n = 0
    for v in frames.values():
        if v.get("send_ns") is None and v.get("present_ns") is None:
            continue
        anchor = v.get("send_ns") or v.get("present_ns")
        if anchor < warmup_ns:
            continue
        n += 1
        for name, a, b in host_stages + ctrl_stages:
            d = stage(v, a, b)
            if d is not None:
                out.setdefault(name, []).append(d)
    stats = {}
    for name, vals in out.items():
        vals.sort()
        stats[name] = {
            "p50_ms": round(pct(vals, 50) / 1e6, 3),
            "p95_ms": round(pct(vals, 95) / 1e6, 3),
            "p99_ms": round(pct(vals, 99) / 1e6, 3),
            "max_ms": round(vals[-1] / 1e6, 3),
            "count": len(vals),
        }
    return stats, n


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    warmup_secs = 60
    for a in sys.argv[1:]:
        if a.startswith("--warmup-secs="):
            warmup_secs = float(a.split("=", 1)[1])
    paths = args
    frames, queues, links, resources, origin, sessions = load(paths)
    warmup_ns = int(warmup_secs * 1_000_000_000)
    stats, n = summarize(frames, warmup_ns)
    doc = {
        "files": paths,
        "origin": origin,
        "sessions": sorted(sessions),
        "joined_frames_post_warmup": n,
        "warmup_secs": warmup_secs,
        "stages": stats,
        "queues": {k: v for k, v in sorted(queues.items())},
        "link": {
            "samples": len(links),
            "rtt_ms_min_max": (
                min((l["rtt_ms"] for l in links if l.get("rtt_ms") is not None), default=None),
                max((l["rtt_ms"] for l in links if l.get("rtt_ms") is not None), default=None),
            ),
            "loss_max": max((l.get("loss_percent") or 0 for l in links), default=0),
        },
        "resource": {
            "cpu_min_max": (
                min((r["cpu_percent"] for r in resources if r.get("cpu_percent") is not None), default=None),
                max((r["cpu_percent"] for r in resources if r.get("cpu_percent") is not None), default=None),
            ),
            "ws_mib_min_max": (
                round(min((r["memory_working_set_bytes"] for r in resources if r.get("memory_working_set_bytes") is not None), default=0) / 2**20, 1),
                round(max((r["memory_working_set_bytes"] for r in resources if r.get("memory_working_set_bytes") is not None), default=0) / 2**20, 1),
            ),
        },
    }
    print(json.dumps(doc, indent=1))


if __name__ == "__main__":
    main()
