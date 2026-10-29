/** This machine's local settings (the identity + connection code live in
 * the rail's This-machine card, ADR-009). */
import { useState } from "react";
import { Section } from "./Common";
import { QUALITY_LABELS, SCALE_LABELS } from "../state/mapping";
import { normalizeCode } from "../ipc";
import type { Settings } from "../types";
import { QUALITY_PRESETS, SCALE_MODES } from "../types";

export function SettingsPanel({
  settings,
  onSave,
  version,
  initiallyOpen = false,
}: {
  settings: Settings | null;
  onSave: (patch: Settings) => Promise<Settings | null>;
  /** Shell version (from tauri.conf via getVersion); null in tests/jsdom. */
  version?: string | null;
  /** Inside the Config modal the user already chose this section — skip
   * the extra Open disclosure. */
  initiallyOpen?: boolean;
}) {
  const [open, setOpen] = useState(initiallyOpen);
  const [url, setUrl] = useState("");
  const [name, setName] = useState("");
  const [quality, setQuality] = useState("balanced");
  const [scale, setScale] = useState("fit");
  const [launchAtLogin, setLaunchAtLogin] = useState(false);
  const [hostSharing, setHostSharing] = useState(true);
  const [autoUpdate, setAutoUpdate] = useState(true);
  const [domains, setDomains] = useState("");
  const [saving, setSaving] = useState(false);
  const [loadedFor, setLoadedFor] = useState<string | null>(null);

  if (settings && loadedFor !== settings.device_id + settings.signaling_base_url) {
    setLoadedFor(settings.device_id + settings.signaling_base_url);
    setUrl(settings.signaling_base_url);
    setName(settings.device_name);
    setQuality(settings.default_quality);
    setScale(settings.default_viewer_scale);
    setLaunchAtLogin(settings.launch_at_login);
    setHostSharing(settings.host_sharing);
    setAutoUpdate(settings.auto_update);
    setDomains((settings.agent_download_domains ?? []).join(", "));
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
        <>
          <p className="muted">
            Signaling service: <code className="code">{settings?.signaling_base_url || "not configured"}</code>
          </p>
          {version ? (
            <p className="muted">
              App version: <code className="code">{version}</code>
            </p>
          ) : null}
        </>
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
              launch_at_login: launchAtLogin,
              host_sharing: hostSharing,
              auto_update: autoUpdate,
              agent_download_domains: domains
                .split(",")
                .map((d) => d.trim().toLowerCase())
                .filter((d) => d.length > 0),
            });
            setSaving(false);
          }}
        >
          <label>
            This machine's display name
            <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Office PC" maxLength={64} />
            <span className="hint">the name family members see when you connect or message them — e.g. "Mom's laptop"</span>
          </label>
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
            The deployed Vercel service in normal use — the default is{" "}
            <code className="code">https://signaling.deepflux.space</code>; the local dev server
            (<code className="code">http://127.0.0.1:38013</code>) for testing. Clear the field
            to opt out (accounts and the engine then need a URL set before use).
          </p>
          <label>
            Assistant download sites
            <input
              value={domains}
              onChange={(event) => setDomains(event.target.value)}
              placeholder="example.com, cdn.example.com"
              spellCheck={false}
              autoComplete="off"
            />
          </label>
          <p className="muted">
            Sites the assistant may download from without asking. The first
            download from any other site asks you once (Allow once / Always
            allow / Deny).
          </p>
          <label className="settings-check">
            <input
              type="checkbox"
              checked={launchAtLogin}
              onChange={(event) => setLaunchAtLogin(event.target.checked)}
            />
            Launch at Windows login (stay reachable in the tray)
          </label>
          <label className="settings-check">
            <input
              type="checkbox"
              checked={hostSharing}
              onChange={(event) => setHostSharing(event.target.checked)}
            />
            Let family connect to this computer — each new machine still
            needs your approval (takes effect the next time DeepFlux starts)
          </label>
          <label className="settings-check">
            <input
              type="checkbox"
              checked={autoUpdate}
              onChange={(event) => setAutoUpdate(event.target.checked)}
            />
            Check for updates automatically (Help menu works either way;
            installing is always your press)
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
          {version ? (
            <p className="muted">
              App version: <code className="code">{version}</code>
            </p>
          ) : null}
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
