/** Controller session card: the ONE connect/session surface
 * (UX-simplify pass, 2026-10-26 — replaces the old ConnectPanel + separate
 * SessionControls stack). While a connect is in flight or a session is
 * live, this card pins to the top of the center column regardless of
 * which machine is selected, so chatting with other machines keeps
 * working during a session. RD-012 controls (monitor/quality/scale/
 * fullscreen) fold in when live. */

import { Section, StatusChip } from "./Common";
import { controllerView, formatMonitorLabel } from "../state/mapping";
import type {
  ControllerStateName,
  MonitorInfo,
  QualityPresetName,
  ScaleModeName,
} from "../types";
import { QUALITY_PRESETS, SCALE_MODES } from "../types";
import { QUALITY_LABELS, SCALE_LABELS } from "../state/mapping";

export function SessionCard({
  controllerState,
  machineName,
  monitors,
  activeMonitor,
  quality,
  scale,
  viewerCreated,
  onCancel,
  onQuality,
  onMonitor,
  onScale,
  onFullscreen,
  onDisconnect,
}: {
  controllerState: ControllerStateName;
  /** Display name of the machine this session belongs to (best known). */
  machineName: string | null;
  monitors: MonitorInfo[];
  activeMonitor: string | null;
  quality: string;
  scale: string;
  viewerCreated: boolean;
  onCancel: () => void;
  onQuality: (preset: QualityPresetName) => void;
  onMonitor: (monitorId: string) => void;
  onScale: (mode: ScaleModeName) => void;
  onFullscreen: () => void;
  onDisconnect: () => void;
}) {
  const view = controllerView(controllerState);
  const who = machineName ?? "the other machine";
  const connecting = view.view === "connecting";

  return (
    <Section
      title={connecting ? `Asking ${who} to allow control` : `Controlling ${who}`}
      actions={<StatusChip tone={view.tone} label="Session" text={view.status} />}
      className={connecting ? "session-card connecting" : "session-card"}
    >
      {connecting ? (
        <>
          <p className="muted">{view.detail}</p>
          <div className="row">
            <button type="button" onClick={onCancel}>
              Cancel request
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="muted">
            {viewerCreated
              ? "The viewer window shows the remote desktop. Click it to send keyboard and mouse; F11 toggles fullscreen."
              : "Opening the viewer window…"}
          </p>
          <div className="controls-grid">
            <fieldset>
              <legend>Monitor</legend>
              {monitors.length === 0 ? (
                <p className="muted">Waiting for the host's monitor list…</p>
              ) : (
                monitors.map((monitor, index) => (
                  <label key={monitor.monitor_id} className="radio">
                    <input
                      type="radio"
                      name="monitor"
                      checked={activeMonitor === monitor.monitor_id}
                      onChange={() => onMonitor(monitor.monitor_id)}
                    />
                    {formatMonitorLabel(monitor, index)}
                  </label>
                ))
              )}
            </fieldset>
            <fieldset>
              <legend>Quality</legend>
              {QUALITY_PRESETS.map((preset) => (
                <label key={preset} className="radio">
                  <input
                    type="radio"
                    name="quality"
                    checked={quality === preset}
                    onChange={() => onQuality(preset)}
                  />
                  {QUALITY_LABELS[preset]}
                </label>
              ))}
            </fieldset>
            <fieldset>
              <legend>Viewer</legend>
              {SCALE_MODES.map((mode) => (
                <label key={mode} className="radio">
                  <input
                    type="radio"
                    name="scale"
                    checked={scale === mode}
                    onChange={() => onScale(mode)}
                  />
                  {SCALE_LABELS[mode]}
                </label>
              ))}
              <div className="row">
                <button type="button" onClick={onFullscreen}>
                  Fullscreen (F11)
                </button>
              </div>
            </fieldset>
          </div>
          <div className="row">
            <button type="button" className="danger" onClick={onDisconnect}>
              Stop controlling
            </button>
          </div>
        </>
      )}
    </Section>
  );
}
