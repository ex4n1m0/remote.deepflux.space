/** Onboarding: the accounts-phase first-run card (sign in / create
 * account), and the saved-account unlock card ("Welcome back" — one
 * password field; the roster stays encrypted until unlocked). Props-only
 * so the component tests run without Tauri. */
import { useState } from "react";
import { ErrorBanner } from "./Common";
import { accountErrorCopy } from "../state/account";

export type OnboardingMode = "signin" | "create" | "unlock";

export interface OnboardingProps {
  mode: OnboardingMode;
  /** Saved-account username (unlock mode). */
  username?: string | null;
  busy: boolean;
  error: string | null;
  onModeChange: (mode: "signin" | "create") => void;
  onSignIn: (username: string, password: string) => void;
  onCreate: (username: string, password: string) => void;
  onUnlock: (password: string) => void;
  onDismissError: () => void;
  onSkip: () => void;
}

/** Client-side mirror of the wire username rules (normalized first). */
export function usernameValid(normalized: string): boolean {
  return (
    /^[a-z0-9][a-z0-9._-]{2,31}$/.test(normalized) &&
    normalized.length >= 3 &&
    normalized.length <= 32
  );
}

export const USERNAME_HINT = "3–32 characters: lowercase letters, digits, . _ -";
export const PASSWORD_HINT = "At least 8 characters.";

export function Onboarding({
  mode,
  username,
  busy,
  error,
  onModeChange,
  onSignIn,
  onCreate,
  onUnlock,
  onDismissError,
  onSkip,
}: OnboardingProps) {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [validation, setValidation] = useState<string | null>(null);

  const submit = () => {
    if (mode === "unlock") {
      if (password.length < 8) {
        setValidation(PASSWORD_HINT);
        return;
      }
      setValidation(null);
      onUnlock(password);
      setPassword(""); // never linger in React state / DOM
      return;
    }
    const normalized = name.trim().toLowerCase();
    if (!usernameValid(normalized)) {
      setValidation(`Username: ${USERNAME_HINT}`);
      return;
    }
    if (password.length < 8) {
      setValidation(PASSWORD_HINT);
      return;
    }
    setValidation(null);
    if (mode === "create") {
      onCreate(normalized, password);
    } else {
      onSignIn(normalized, password);
    }
    setPassword(""); // never linger in React state / DOM
  };

  return (
    <div className="onboarding-wrap">
      <section className="onboarding-card" aria-label="Account">
        <h1>Remote Desktop</h1>
        {mode === "unlock" ? (
          <>
            <p className="muted">Welcome back, @{username ?? "user"}</p>
            <p className="hint">
              Your saved computers are encrypted on this machine — enter your password to unlock
              the list.
            </p>
          </>
        ) : (
          <>
            <div className="onboarding-tabs" role="tablist" aria-label="Sign in or create an account">
              <button
                type="button"
                role="tab"
                aria-selected={mode === "signin"}
                className={mode === "signin" ? "tab-active" : "ghost"}
                onClick={() => onModeChange("signin")}
              >
                Sign in
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={mode === "create"}
                className={mode === "create" ? "tab-active" : "ghost"}
                onClick={() => onModeChange("create")}
              >
                Create account
              </button>
            </div>
            <p className="hint">
              {mode === "create"
                ? "Your saved computers sync, encrypted end to end — only your password can read the list."
                : "Access the saved computer list for this account."}
            </p>
          </>
        )}

        <form
          className="onboarding-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (!busy) {
              submit();
            }
          }}
        >
          {mode !== "unlock" ? (
            <label>
              Username
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="alice"
                autoComplete="username"
                spellCheck={false}
              />
              <span className="hint">{USERNAME_HINT}</span>
            </label>
          ) : null}
          <label>
            Password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder={mode === "create" ? "At least 8 characters" : "Password"}
              autoComplete={mode === "create" ? "new-password" : "current-password"}
            />
            {mode === "create" ? <span className="hint">{PASSWORD_HINT}</span> : null}
          </label>
          {validation ? (
            <p className="form-error" role="alert">
              {validation}
            </p>
          ) : null}
          <button type="submit" className="primary" disabled={busy}>
            {busy
              ? "Working…"
              : mode === "unlock"
                ? "Unlock"
                : mode === "create"
                  ? "Create account"
                  : "Sign in"}
          </button>
        </form>

        {error ? (
          <ErrorBanner
            title={mode === "unlock" ? "Unlock problem" : "Account problem"}
            message={accountErrorCopy(error)}
            hint={null}
            onDismiss={onDismissError}
          />
        ) : null}

        <button type="button" className="ghost onboarding-skip" onClick={onSkip}>
          Skip for now →
        </button>
      </section>
    </div>
  );
}
