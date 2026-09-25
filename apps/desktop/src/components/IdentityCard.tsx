/** This machine: identity + connection code + local settings. */
import { useState } from "react";
import { CopyButton, Section } from "./Common";
import { QUALITY_LABELS, SCALE_LABELS } from "../state/mapping";
import { normalizeCode } from "../ipc";
import type { Identity, Settings } from "../types";
import { QUALITY_PRESETS, SCALE_MODES } from "../types";

export function IdentityCard({ identity }: { identity: Identity | null }) {
  if (!identity) {
    return (
      <Section title="This machine">
        <p className="muted">Loading identity…</p>
      </Section>
    );
  }
  return (
    <Section title="This machine">
      <dl className="identity">
        <div>
          <dt>Name</dt>
          <dd>{identity.device_name}</dd>
        </div>
        <div>
          <dt>Connection code</dt>
          <dd>
            <code className="code">{identity.connection_code}</code>
            <CopyButton value={identity.connection_code} label="connection code" />
          </dd>
        </div>
      </dl>
      <p className="muted">
        Share this code with someone you trust. They enter it on their machine to request
        control; you approve every session.
      </p>
    </Section>
  );
}

export function SettingsPanel({
  settings,
  onSave,
}: {
  settings: Settings | null;
  onSave: (patch: Settings) => Promise<Settings | null>;
}) {
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState("");
  const [name, setName] = useState("");
  const [quality, setQuality] = useState("balanced");
  const [scale, setScale] = useState("fit");
  const [saving, setSaving] = useState(false);
  const [loadedFor, setLoadedFor] = useState<string | null>(null);

  if (settings && loadedFor !== settings.device_id + settings.signaling_base_url) {
    setLoadedFor(settings.device_id + settings.signaling_base_url);
    setUrl(settings.signaling_base_url);
    setName(settings.device_name);
    setQuality(settings.default_quality);
    setScale(settings.default_viewer_scale);
  }

  return (
    <Section
      title="Settings"
      actions={
        <button type="button" className="ghost" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
          {open ? "Close" : "Open"}
        </button>
      }
    >
      {!open ? (
        <p className="muted">
          Signaling service: <code className="code">{settings?.signaling_base_url || "not configured"}</code>
        </p>
      ) : (
        <form
          className="settings-form"
          onSubmit={async (event) => {
            event.preventDefault();
            if (!settings) {
              return;
            }
            setSaving(true);
            await onSave({
              ...settings,
              device_name: name,
              signaling_base_url: normalizeBaseUrl(url),
              default_quality: quality,
              default_viewer_scale: scale,
            });
            setSaving(false);
          }}
        >
          <label>
            Signaling service URL
            <input
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://your-service.vercel.app"
              spellCheck={false}
              autoComplete="off"
            />
          </label>
          <p className="muted">
            The deployed Vercel service in normal use; the local dev server
            (<code className="code">http://127.0.0.1:38013</code>) for testing.
          </p>
          <label>
            This machine's display name
            <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Office PC" />
          </label>
          <label>
            Default quality
            <select value={quality} onChange={(event) => setQuality(event.target.value)}>
              {QUALITY_PRESETS.map((preset) => (
                <option key={preset} value={preset}>
                  {QUALITY_LABELS[preset]}
                </option>
              ))}
            </select>
          </label>
          <label>
            Default viewer scale
            <select value={scale} onChange={(event) => setScale(event.target.value)}>
              {SCALE_MODES.map((mode) => (
                <option key={mode} value={mode}>
                  {SCALE_LABELS[mode]}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" disabled={saving}>
            {saving ? "Saving…" : "Save settings"}
          </button>
        </form>
      )}
    </Section>
  );
}

export function normalizeBaseUrl(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.includes("://")) {
    return trimmed;
  }
  return `https://${trimmed}`;
}

/** Re-export for tests: normalized connection codes. */
export { normalizeCode };
