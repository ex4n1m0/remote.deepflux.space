/** Small presentational pieces shared across the shell. */
import type { ReactNode } from "react";
import type { Tone } from "../state/mapping";
import { Icon } from "./Icon";

export function StatusChip({
  tone,
  label,
  text,
}: {
  tone: Tone;
  label: string;
  text: string;
}) {
  return (
    <span className={`chip chip-${tone}`} role="status" aria-label={`${label}: ${text}`}>
      <span className="chip-dot" aria-hidden="true" />
      <span className="chip-label">{label}</span>
      <span className="chip-text">{text}</span>
    </span>
  );
}

export function Section({
  title,
  actions,
  className,
  children,
}: {
  title: string;
  actions?: ReactNode;
  /** Extra classes for the section element (e.g. `session-card`). */
  className?: string;
  children: ReactNode;
}) {
  return (
    <section className={`section${className ? ` ${className}` : ""}`}>
      <header className="section-head">
        <h2>{title}</h2>
        {actions}
      </header>
      {children}
    </section>
  );
}

export function ErrorBanner({
  message,
  hint,
  title = "Something went wrong",
  onDismiss,
}: {
  message: string;
  hint?: string | null;
  /** Heading; neutral by default (connection flows pass their own). */
  title?: string;
  onDismiss: () => void;
}) {
  return (
    <div className="banner banner-error" role="alert">
      <div>
        <strong>{title}</strong>
        <p>{message}</p>
        {hint ? <p className="hint">{hint}</p> : null}
      </div>
      <button type="button" onClick={onDismiss} aria-label="Dismiss error">
        Dismiss
      </button>
    </div>
  );
}

export function InfoLine({ text }: { text: string }) {
  return (
    <p className="info-line" role="status">
      {text}
    </p>
  );
}

/** Copy-to-clipboard. Plain: an icon and the word. `chip`: the value itself
 * inside a small pill with a copy glyph — for a code shown on screen. */
export function CopyButton({
  value,
  label,
  chip = false,
}: {
  value: string;
  label: string;
  chip?: boolean;
}) {
  return (
    <button
      type="button"
      className={chip ? "ghost code-chip" : "ghost"}
      onClick={() => {
        navigator.clipboard?.writeText(value).catch(() => {
          // Clipboard may be unavailable; the code is selectable text.
        });
      }}
      aria-label={`Copy ${label}`}
      title={`Copy ${label}`}
    >
      {chip ? <code className="code">{value}</code> : null}
      <Icon name="copy" size={chip ? 12 : 16} />
      {chip ? null : "Copy"}
    </button>
  );
}
