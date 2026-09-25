#!/usr/bin/env python
"""M5 matrix summarizer: turns the per-cell JSONL + rig summaries under
docs/reports/data/m5-matrix/ into one summary JSON + a markdown table for
docs/reports/m5-matrix.md. Per docs/perf-counter-schema.md: never subtracts
timestamps across clock domains (host and controller are separate
processes), so latency percentiles are per-stage; the input-to-visible
proxy is host capture→send + measured transport RTT + controller
recv→present, labeled as proxy in the report.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import os
MATRIX = ROOT / os.environ.get("M5_MATRIX_DIR", "docs/reports/data/m5-matrix")


def pct(sorted_vals, q):
    if not sorted_vals:
        return None
    i = min(len(sorted_vals) - 1, int(q * len(sorted_vals)))
    return sorted_vals[i]


def percentiles(vals):
    v = sorted(vals)
    return {
        "p50": pct(v, 0.50),
        "p95": pct(v, 0.95),
        "p99": pct(v, 0.99),
        "max": v[-1] if v else None,
    }


def load_jsonl(path):
    import gzip

    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def stage_ms(recs, from_ns, to_ns):
    out = []
    for r in recs:
        a, b = r.get(from_ns), r.get(to_ns)
        if a is not None and b is not None and b >= a:
            out.append((b - a) / 1e6)
    return out


def parse_host_log(name):
    """Host-side evidence from the rig's stderr log (the script writes
    --summary only on the controller side): live reconfig count, fps
    retargets, congestion decision trace, netem schedule swaps."""
    log = MATRIX / f"{name}-host.log"
    out = {"reconfig_live": 0, "reconfig_rebuilt": 0, "reconfig_errors": 0,
           "fps_retargets": 0, "bitrate_steps": [], "netem_swaps": 0,
           "decision_lines": 0}
    if not log.exists():
        return out
    for line in open(log, encoding="utf-8", errors="replace"):
        if "bitrate ->" in line and "(live)" in line:
            out["reconfig_live"] += 1
            try:
                out["bitrate_steps"].append(int(line.split("bitrate -> ")[1].split(" bps")[0]))
            except (IndexError, ValueError):
                pass
        elif "reconfigure rebuilt" in line:
            out["reconfig_rebuilt"] += 1
        elif "reconfigure failed" in line:
            out["reconfig_errors"] += 1
        elif "congestion decision:" in line:
            out["decision_lines"] += 1
        elif "fps cap" in line:
            out["fps_retargets"] += 1
        elif "netem schedule @" in line:
            out["netem_swaps"] += 1
    return out


def jsonl_path(stem):
    """Prefer the gzipped evidence (post-run retention), fall back to raw."""
    for candidate in (f"{stem}.jsonl.gz", f"{stem}.jsonl"):
        p = MATRIX / candidate
        if p.exists():
            return p
    return None


def summarize_cell(name):
    host = jsonl_path(f"m5-{name}-rig-host")
    ctrl = jsonl_path(f"m5-{name}-rig-controller")
    summary_path = MATRIX / f"{name}-summary.json"
    if not (host.exists() and ctrl.exists() and summary_path.exists()):
        return None
    summary = json.load(open(summary_path, encoding="utf-8"))
    host_log = parse_host_log(name)

    host_frames, ctrl_frames, links = [], [], []
    queue_hw = {}
    for r in load_jsonl(host):
        k = r.get("kind")
        if k == "frame_timing" and r.get("origin") == "host":
            host_frames.append(r)
        elif k == "link_sample":
            links.append(r)
        elif k == "queue_sample":
            q = r["queue"]
            hw = queue_hw.get(q, 0)
            queue_hw[q] = max(hw, r.get("high_water", 0))
    for r in load_jsonl(ctrl):
        k = r.get("kind")
        if k == "frame_timing" and r.get("origin") == "controller":
            ctrl_frames.append(r)
        elif k == "link_sample":
            links.append(r)
        elif k == "queue_sample":
            q = r["queue"]
            hw = queue_hw.get(q, 0)
            queue_hw[q] = max(hw, r.get("high_water", 0))

    send_kbps = [l["send_bitrate_kbps"] for l in links if l.get("send_bitrate_kbps")]
    recv_kbps = [l["recv_bitrate_kbps"] for l in links if l.get("recv_bitrate_kbps")]
    loss = [l["loss_percent"] for l in links if l.get("loss_percent") is not None]
    est = [l["available_bandwidth_kbps"] for l in links if l.get("available_bandwidth_kbps") is not None]
    ice_rtt = [l["rtt_ms"] for l in links if l.get("rtt_ms") is not None]
    remote_loss = [l["remote_loss_percent"] for l in links if l.get("remote_loss_percent") is not None]

    enc = dict(summary.get("host", {}))
    enc.setdefault("frames_encoded", len(host_frames))
    if enc.get("stream_secs") in (None, 0) and host_frames:
        last = max(r["send_ns"] for r in host_frames if r.get("send_ns"))
        first = min(
            r["capture_ns"] for r in host_frames if r.get("capture_ns") is not None
        )
        if last > first:
            enc["stream_secs"] = (last - first) / 1e9
        if enc.get("stream_secs"):
            enc["fps_effective"] = round(len(host_frames) / enc["stream_secs"], 1)
    ctlr = summary.get("controller", {})
    congestion = summary.get("congestion", {})
    events = congestion.get("events", [])

    # Input-to-visible proxy (schema F8 label): host capture→send +
    # measured ICE RTT + controller recv→present. Both video halves are
    # in-domain; the RTT join is the only cross-domain term and is a
    # measured transport statistic, not a timestamp subtraction.
    host_half = stage_ms(host_frames, "capture_ns", "send_ns")
    ctrl_half = stage_ms(ctrl_frames, "recv_ns", "present_ns")
    mean_rtt = (sum(ice_rtt) / len(ice_rtt)) if ice_rtt else None

    stream_secs = enc.get("stream_secs") or 0.001
    render_secs = ctlr.get("render_secs") or 0.001

    return {
        "cell": name,
        "failed": summary.get("failed"),
        "failures": summary.get("failures"),
        "frames_encoded": enc.get("frames_encoded"),
        "frames_presented": ctlr.get("frames_presented"),
        "fps_encoded": enc.get("fps_effective"),
        "fps_presented": round(ctlr.get("frames_presented", 0) / render_secs, 1),
        "send_bitrate_kbps": percentiles(send_kbps),
        "recv_bitrate_kbps": percentiles(recv_kbps),
        "loss_percent_mean": round(sum(loss) / len(loss), 2) if loss else None,
        "remote_loss_percent_mean": (
            round(sum(remote_loss) / len(remote_loss), 2) if remote_loss else None
        ),
        "gcc_estimate_kbps": percentiles(est),
        "ice_rtt_ms_mean": round(mean_rtt, 3) if mean_rtt is not None else None,
        "latency_ms": {
            "capture_to_send": percentiles(host_half),
            "recv_to_present": percentiles(ctrl_half),
            "input_to_visible_proxy_p50": (
                round(pct(sorted(host_half), 0.5) + mean_rtt + pct(sorted(ctrl_half), 0.5), 1)
                if host_half and ctrl_half and mean_rtt is not None
                else None
            ),
        },
        "queue_high_water": queue_hw,
        "keyframe_requests": ctlr.get("keyframe_requests_sent"),
        "frames_missing_packets": ctlr.get("frames_missing_packets"),
        # F62 (M6): the congestion block is self-contained host-side
        # evidence. The controller-side rig summary's congestion fields
        # (always enabled:false/empty — the controller sends no media) stay
        # available but under an explicitly-labeled provenance key, so an
        # auditor reading this JSON alone sees the host controller was ON
        # and acting without cross-referencing the cell logs.
        "congestion": {
            "host": {
                "source": "m5-<cell>-host.log + host link samples",
                "decision_count": host_log["decision_lines"],
                "reconfig_live": host_log["reconfig_live"],
                "reconfig_rebuilt": host_log["reconfig_rebuilt"],
                "reconfig_errors": host_log["reconfig_errors"],
                "fps_retargets": host_log["fps_retargets"],
                "live_bitrate_steps_bps": host_log["bitrate_steps"],
                "netem_schedule_swaps": host_log["netem_swaps"],
                "estimate_kbps": percentiles(est),
                "estimate_sampled": len(est),
            },
            "controller_side_summary": {
                "source": "controller rig summary; the controller sends no media, so its congestion controller is correctly absent (enabled:false here is NOT evidence about the host)",
                "enabled": congestion.get("enabled"),
                "decision_count": len(events),
                "bitrate_targets_kbps": [
                    e["encoder_bitrate_bps"] // 1000 for e in events if e.get("encoder_bitrate_bps")
                ],
                "resolution_step_downs": sum(
                    1 for e in events if e.get("resolution_step_down")
                ),
                "input_delay_dropped": congestion.get("input_delay_dropped"),
            },
        },
        "recovery": summary.get("sessions"),
        "transport_stats": summary.get("transport_stats"),
    }


CELLS = [
    "baseline", "loss1", "loss3", "loss5", "loss10",
    "rtt50", "rtt150", "rtt250", "bwstep", "worst", "iface", "udpblocked",
]


def main():
    out = {"cells": {}, "generated_from": str(MATRIX)}
    for name in CELLS:
        cell = summarize_cell(name)
        if cell:
            out["cells"][name] = cell
    dest = MATRIX / "matrix-summary.json"
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print(f"wrote {dest} ({len(out['cells'])} cells)")


if __name__ == "__main__":
    sys.exit(main())
