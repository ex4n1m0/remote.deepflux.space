/** Compact diagnostics overlay (RD-012): per-stage p50/p95 latencies,
 * fps, link, queue depths, encoder hw/sw. Numbers only — aggregates from
 * the perf-counter schema (`docs/perf-counter-schema.md`, M4 obligation:
 * "counters are fine over IPC, frames are not"). */
import type { DiagSnapshot } from "../types";

const STAGE_ORDER = [
  "capture_to_encode",
  "encode",
  "encode_to_send",
  "recv_to_decode",
  "decode_to_present",
] as const;

function fmtMs(value: number): string {
  return value >= 100 ? value.toFixed(0) : value.toFixed(1);
}

function fmtOpt(value: number | null | undefined, unit: string): string {
  return value === null || value === undefined ? "—" : `${Number(value.toFixed(2))}${unit}`;
}

export function DiagnosticsOverlay({ snapshot }: { snapshot: DiagSnapshot | null }) {
  if (!snapshot) {
    return (
      <aside className="diag" aria-label="Diagnostics">
        <h3>Diagnostics</h3>
        <p className="muted">Waiting for counters…</p>
      </aside>
    );
  }
  const stages = STAGE_ORDER.filter((name) => snapshot.stages_ms[name]?.count);
  const queues = Object.entries(snapshot.queues);
  return (
    <aside className="diag" aria-label="Diagnostics" role="region">
      <h3>Diagnostics</h3>
      <table className="diag-table">
        <caption className="sr-only">Per-stage latency</caption>
        <thead>
          <tr>
            <th scope="col">Stage</th>
            <th scope="col">p50</th>
            <th scope="col">p95</th>
            <th scope="col">n</th>
          </tr>
        </thead>
        <tbody>
          {stages.map((name) => {
            const stat = snapshot.stages_ms[name]!;
            return (
              <tr key={name}>
                <td>{name}</td>
                <td className="num">{fmtMs(stat.p50_ms)} ms</td>
                <td className="num">{fmtMs(stat.p95_ms)} ms</td>
                <td className="num">{stat.count}</td>
              </tr>
            );
          })}
          {stages.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                No samples yet
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
      <dl className="diag-kv">
        <div>
          <dt>fps</dt>
          <dd>
            {Object.entries(snapshot.fps)
              .map(([key, value]) => `${key} ${value.toFixed(0)}`)
              .join(" · ") || "—"}
          </dd>
        </div>
        <div>
          <dt>link</dt>
          <dd>
            {snapshot.link
              ? `tx ${fmtOpt(snapshot.link.send_bitrate_kbps, " kbps")} · rx ${fmtOpt(
                  snapshot.link.recv_bitrate_kbps,
                  " kbps",
                )} · rtt ${fmtOpt(snapshot.link.rtt_ms, " ms")} · loss ${fmtOpt(
                  snapshot.link.loss_percent,
                  "%",
                )}`
              : "—"}
          </dd>
        </div>
        <div>
          <dt>encoder</dt>
          <dd>
            {snapshot.encoder_kind ?? "—"}
            {snapshot.encoder_rebuilds > 0 ? ` (rebuilds ${snapshot.encoder_rebuilds})` : ""}
          </dd>
        </div>
        <div>
          <dt>input</dt>
          <dd>
            applied {snapshot.input.applied} · stale {snapshot.input.suppressed} · gaps{" "}
            {snapshot.input.gaps} · all-up {snapshot.input.all_keys_up} · held{" "}
            {snapshot.input.held}
            {snapshot.input.inject_errors > 0
              ? ` · blocked ${snapshot.input.inject_errors}`
              : ""}
          </dd>
        </div>
      </dl>
      {queues.length > 0 ? (
        <table className="diag-table">
          <caption className="sr-only">Queue depths</caption>
          <thead>
            <tr>
              <th scope="col">Queue</th>
              <th scope="col">depth</th>
              <th scope="col">hw</th>
              <th scope="col">dropped</th>
            </tr>
          </thead>
          <tbody>
            {queues.map(([name, stat]) => (
              <tr key={name}>
                <td>{name}</td>
                <td className="num">
                  {stat.depth}/{stat.capacity}
                </td>
                <td className="num">{stat.high_water}</td>
                <td className="num">{stat.dropped}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </aside>
  );
}
