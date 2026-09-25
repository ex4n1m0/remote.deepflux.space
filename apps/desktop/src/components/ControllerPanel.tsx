/** Controller panel: connect flow + live-session controls (RD-012). */
import { useState } from "react";
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

export function ConnectPanel({
  controllerState,
  onConnect,
  onCancel,
}: {
  controllerState: ControllerStateName;
  onConnect: (code: string) => void;
  onCancel: () => void;
}) {
  const view = controllerView(controllerState);
  const [code, setCode] = useState("");
  return (
    <Section
      title="Control another machine"
      actions={<StatusChip tone={view.tone} label="Controller" text={view.status} />}
    >
      <p className="muted">{view.detail}</p>
      {view.can.connect ? (
        <form
          className="connect-form"
          onSubmit={(event) => {
            event.preventDefault();
            onConnect(code.trim().toLowerCase());
          }}
        >
          <label>
            Connection code
            <input
              value={code}
              onChange={(event) => setCode(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Escape") {
                  setCode("");
                }
              }}
              placeholder="Ask the host for their code"
              spellCheck={false}
              autoFocus
            />
          </label>
          <button type="submit" className="primary">
            Connect
          </button>
        </form>
      ) : null}
      {view.can.cancel ? (
        <div className="row">
          <button type="button" onClick={onCancel}>
            Cancel request
          </button>
        </div>
      ) : null}
    </Section>
  );
}

export function SessionControls({
  monitors,
  activeMonitor,
  quality,
  scale,
  viewerCreated,
  onQuality,
  onMonitor,
  onScale,
  onFullscreen,
  onDisconnect,
}: {
  monitors: MonitorInfo[];
  activeMonitor: string | null;
  quality: string;
  scale: string;
  viewerCreated: boolean;
  onQuality: (preset: QualityPresetName) => void;
  onMonitor: (monitorId: string) => void;
  onScale: (mode: ScaleModeName) => void;
  onFullscreen: () => void;
  onDisconnect: () => void;
}) {
  return (
    <Section title="Session">
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
          Disconnect
        </button>
      </div>
    </Section>
  );
}
