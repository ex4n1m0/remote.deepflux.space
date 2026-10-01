/** Small presentational pieces shared across the shell. */
import type { ReactNode } from "react";
import type { Tone } from "../state/mapping";

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
  children,
}: {
  title: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="section">
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
  title = "Connection problem",
  onDismiss,
}: {
  message: string;
  hint?: string | null;
  /** Heading; defaults to the connection copy (accounts flows override). */
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

export function CopyButton({ value, label }: { value: string; label: string }) {
  return (
    <button
      type="button"
      className="ghost"
      onClick={() => {
        navigator.clipboard?.writeText(value).catch(() => {
          // Clipboard may be unavailable; the code is selectable text.
        });
      }}
      aria-label={`Copy ${label}`}
    >
      Copy
    </button>
  );
}
