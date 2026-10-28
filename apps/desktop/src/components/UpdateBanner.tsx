/** Update banner (ADR-008): the whole update flow's UI, a quiet
 * info-banner under the header like the circle notice. Update now →
 * downloading (passive progress) → "Restart & update", whose copy names
 * the cost: DeepFlux closes for a moment. Installing closes the app (the
 * Rust side refused earlier if a session was live), so the installing
 * state renders one last line before the process exits.
 * Pure presentational — driven entirely by the updater's state. */
import type { UpdateState } from "../ipc";

export interface UpdateBannerProps {
  state: UpdateState;
  /** A remote session is live (either role, including handshake/consent):
   * the install button disables — updating would kill the session. */
  sessionLive: boolean;
  onUpdate: () => void;
  onInstall: () => void;
  /** Error-state retry: re-runs the failed stage (check or download). */
  onRetry: () => void;
  onDismiss: () => void;
}

/** Error banner title by stage — the body copy comes Rust-side in the
 * product's plain voice; this only names what failed. */
export function updateErrorTitle(stage: string): string {
  if (stage === "check") return "Couldn't check for updates.";
  if (stage === "install") return "The update couldn't start.";
  return "The update didn't finish.";
}

export function UpdateBanner({ state, sessionLive, onUpdate, onInstall, onRetry, onDismiss }: UpdateBannerProps) {
  if (state.status === "available") {
    return (
      <div className="banner banner-info update-banner" role="status">
        <p>
          <strong>DeepFlux {state.latest_version} is available</strong>
          {state.notes ? <> — {state.notes}</> : null}
          {state.size_text ? (
            <span className="muted small"> ({state.size_text})</span>
          ) : null}
        </p>
        <div className="row">
          <button type="button" className="primary" onClick={onUpdate}>
            Update now
          </button>
          <button type="button" className="ghost" onClick={onDismiss}>
            Not now
          </button>
        </div>
      </div>
    );
  }
  if (state.status === "checking") {
    return (
      <div className="banner banner-info update-banner" role="status">
        <p>Checking for updates…</p>
      </div>
    );
  }
  if (state.status === "none") {
    // The explicit "Check for updates" answer when nothing is new;
    // self-dismisses (App wires the timer).
    return (
      <div className="banner banner-info update-banner" role="status">
        <p>DeepFlux is up to date (v{state.current_version}).</p>
      </div>
    );
  }
  if (state.status === "downloading") {
    return (
      <div className="banner banner-info update-banner">
        {/* The live region carries only the transition line — percent
         * ticks stay out of it (screen-reader chatter). */}
        <p role="status">Downloading DeepFlux {state.latest_version}…</p>
        <div className="update-progress-line">
          <span className="muted small">{state.progress_percent}%</span>
          <div
            className="update-progress"
            role="progressbar"
            aria-valuenow={state.progress_percent}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Update download progress"
          >
            <div
              className="update-progress-fill"
              style={{ width: `${state.progress_percent}%` }}
            />
          </div>
        </div>
      </div>
    );
  }
  if (state.status === "ready") {
    return (
      <div className="banner banner-info update-banner" role="status">
        <p>
          <strong>DeepFlux {state.latest_version} is downloaded and checked.</strong>{" "}
          Restart &amp; update closes DeepFlux for a moment, then opens it again by
          itself.
        </p>
        <div className="row">
          <button
            type="button"
            className="primary"
            disabled={sessionLive}
            title={
              sessionLive
                ? "Finish the remote session first — updating restarts DeepFlux"
                : undefined
            }
            onClick={onInstall}
          >
            Restart &amp; update
          </button>
          <button type="button" className="ghost" onClick={onDismiss}>
            Not now
          </button>
        </div>
        {sessionLive ? (
          <p className="muted small">Finish the remote session first — updating restarts DeepFlux.</p>
        ) : null}
      </div>
    );
  }
  if (state.status === "installing") {
    return (
      <div className="banner banner-info update-banner" role="status">
        <p>Installing DeepFlux {state.latest_version} — the app restarts by itself…</p>
      </div>
    );
  }
  if (state.status === "error") {
    return (
      <div className="banner banner-error update-banner" role="alert">
        <p>
          <strong>{updateErrorTitle(state.stage)}</strong> {state.error}
        </p>
        <div className="row">
          <button type="button" className="primary" onClick={onRetry}>
            Try again
          </button>
          <button type="button" className="ghost" onClick={onDismiss}>
            Not now
          </button>
        </div>
      </div>
    );
  }
  return null;
}
