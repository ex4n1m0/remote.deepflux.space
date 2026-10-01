/** The shell: webview control surface only — video lives in the native
 * viewer window owned by the engine (invariant 1). The accounts phase
 * adds the onboarding gate (sign in / create / saved-account unlock) in
 * front of the main grid. */
import { useEffect, useState } from "react";
import { useEngine } from "./hooks/useEngine";
import { useAccount } from "./hooks/useAccount";
import { IdentityCard, SettingsPanel } from "./components/IdentityCard";
import { Favorites } from "./components/Favorites";
import { Computers } from "./components/Computers";
import { Onboarding } from "./components/Onboarding";
import { HostPanel } from "./components/HostPanel";
import { ConnectPanel, SessionControls } from "./components/ControllerPanel";
import { DiagnosticsOverlay } from "./components/DiagnosticsOverlay";
import { ErrorBanner, StatusChip } from "./components/Common";
import { api, normalizeCode } from "./ipc";
import { accountErrorCopy, accountGate } from "./state/account";
import { controllerView, disconnectCopy, hostView } from "./state/mapping";

export default function App() {
  const engine = useEngine();
  const [ui] = engine.ui;
  const account = useAccount();
  const [accountUi] = account.ui;
  const [showDiag, setShowDiag] = useState(false);
  const [settingsOpenHint, setSettingsOpenHint] = useState(false);
  // The onboarding card is also reachable later via the header's Sign in.
  const [signInOpen, setSignInOpen] = useState(false);
  const [onboardingMode, setOnboardingMode] = useState<"signin" | "create">("signin");

  // Ctrl+Shift+D toggles the diagnostics overlay (keyboard accessibility).
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "d") {
        event.preventDefault();
        setShowDiag((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const host = hostView(ui.hostState);
  const controller = controllerView(ui.controllerState);
  const endCopy = ui.lastEnd ? disconnectCopy(ui.lastEnd.code) : null;
  // Both inputs of the gate must be loaded (the skip flag lives in
  // settings.json) or a restart could flash the onboarding card.
  const gate =
    engine.settings === null
      ? ("loading" as const)
      : accountGate(accountUi, engine.settings.skipped_onboarding, signInOpen);

  const startEngine = () =>
    engine.run(async () => {
      await api.engineStart();
    });

  const ensureEngine = async (): Promise<boolean> => {
    if (ui.engineStarted) {
      return true;
    }
    try {
      await api.engineStart();
      return true;
    } catch (err) {
      engine.clearCommandError();
      engine.run(async () => {
        throw err;
      });
      setSettingsOpenHint(true);
      return false;
    }
  };

  /** Persist the skip flag so the gate opens straight into the main UI. */
  const skipOnboarding = async () => {
    setSignInOpen(false);
    if (engine.settings && !engine.settings.skipped_onboarding) {
      await engine.saveSettings({ ...engine.settings, skipped_onboarding: true });
    }
  };

  /** After a successful auth action: close the card + resync favorites
   * (the roster write-back keeps the logged-out list coherent). */
  const afterAuth = async (error: string | null) => {
    if (error === null) {
      setSignInOpen(false);
      await engine.refreshFavorites();
    }
  };

  const signOut = async () => {
    await account.logout();
    // Sign-out behaves as an explicit skip: the main UI stays available
    // (guest mode); "Sign in" in the header re-opens the card.
    if (engine.settings && !engine.settings.skipped_onboarding) {
      await engine.saveSettings({ ...engine.settings, skipped_onboarding: true });
    }
    await engine.refreshFavorites();
  };

  const connectByCode = async (code: string) => {
    if (await ensureEngine()) {
      await engine.run(async () => {
        await api.controllerStart();
        await api.connect(code);
      });
    }
  };

  // -- onboarding gate: the card replaces the whole shell ---------------
  if (gate === "loading") {
    return (
      <div className="app">
        <p className="muted onboarding-loading" role="status">
          Loading…
        </p>
      </div>
    );
  }
  if (gate === "onboarding" || gate === "unlock") {
    return (
      <div className="app">
        <Onboarding
          mode={gate === "unlock" ? "unlock" : onboardingMode}
          username={accountUi.username}
          busy={accountUi.busy}
          error={accountUi.error}
          onModeChange={(mode) => setOnboardingMode(mode)}
          onSignIn={(username, password) => {
            void account.login(username, password).then(afterAuth);
          }}
          onCreate={(username, password) => {
            void account.register(username, password).then(afterAuth);
          }}
          onUnlock={(password) => {
            void account.unlock(password).then(afterAuth);
          }}
          onDismissError={account.clearError}
          onSkip={() => void skipOnboarding()}
        />
      </div>
    );
  }

  const signedIn = accountUi.status === "logged_in";

  return (
    <div className="app">
      <header className="app-head">
        <h1>Remote Desktop</h1>
        <div className="chips">
          <StatusChip tone={host.tone} label="Host" text={ui.hostState} />
          <StatusChip tone={controller.tone} label="Controller" text={ui.controllerState} />
          {signedIn && accountUi.username ? (
            <span className="chip chip-good account-chip" title="Signed in">
              <span className="chip-dot" aria-hidden="true" />
              @{accountUi.username}
            </span>
          ) : (
            <button
              type="button"
              className="ghost"
              onClick={() => {
                setOnboardingMode("signin");
                setSignInOpen(true);
              }}
            >
              Sign in
            </button>
          )}
          {signedIn ? (
            <button type="button" className="ghost" onClick={() => void signOut()}>
              Sign out
            </button>
          ) : null}
          <button
            type="button"
            className="ghost"
            onClick={() => setShowDiag((v) => !v)}
            aria-pressed={showDiag}
          >
            Diagnostics (Ctrl+Shift+D)
          </button>
        </div>
      </header>

      {engine.commandError ? (
        <ErrorBanner
          message={engine.commandError}
          hint={null}
          onDismiss={engine.clearCommandError}
        />
      ) : null}
      {ui.lastError ? (
        <ErrorBanner
          message={ui.lastError.message}
          hint={ui.lastError.hint}
          onDismiss={() => {
            /* engine errors are informational; the banner is replaced by the next one */
          }}
        />
      ) : null}
      {endCopy && ui.controllerState === "Disconnected" ? (
        <div className="banner banner-info" role="status">
          <p>{endCopy.title}</p>
          {endCopy.hint ? <p className="hint">{endCopy.hint}</p> : null}
        </div>
      ) : null}
      {ui.lastInfo ? <p className="info-line">{ui.lastInfo}</p> : null}

      {!ui.engineStarted ? (
        <div className="banner banner-info" role="status">
          <p>
            The engine is not started yet.{" "}
            {settingsOpenHint ? "Configure the signaling URL in Settings, then " : ""}
            press <strong>Start engine</strong> once the signaling service is configured.
          </p>
          <button type="button" className="primary" onClick={startEngine}>
            Start engine
          </button>
        </div>
      ) : null}

      <main className="grid">
        <HostPanel
          hostState={ui.hostState}
          consent={ui.consent}
          connectionCode={engine.identity?.connection_code ?? "…"}
          onStart={async () => {
            if (await ensureEngine()) {
              await engine.run(() => api.hostStart());
            }
          }}
          onStop={() => engine.run(() => api.hostStop())}
          onAccept={() => engine.run(() => api.consentAccept())}
          onReject={() => engine.run(() => api.consentReject())}
        />
        <div>
          <ConnectPanel
            controllerState={ui.controllerState}
            onConnect={async (code) => {
              if (await ensureEngine()) {
                await engine.run(async () => {
                  await api.controllerStart();
                  await api.connect(normalizeCode(code));
                });
              }
            }}
            onCancel={() => engine.run(() => api.cancelConnect())}
          />
          {controller.can.controls ? (
            <SessionControls
              monitors={ui.peerMonitors}
              activeMonitor={ui.activeMonitor}
              quality={ui.quality}
              scale={
                (ui.viewer.scale as "fit" | "one_to_one") ??
                (engine.settings?.default_viewer_scale as "fit" | "one_to_one") ??
                "fit"
              }
              viewerCreated={ui.viewer.created}
              onQuality={(preset) => engine.run(() => api.setQuality(preset))}
              onMonitor={(monitorId) => engine.run(() => api.selectMonitor(monitorId))}
              onScale={(mode) => engine.run(() => api.viewerSetScale(mode))}
              onFullscreen={() => engine.run(() => api.viewerToggleFullscreen())}
              onDisconnect={() => engine.run(() => api.disconnect())}
            />
          ) : null}
        </div>
        <div>
          <div id="identity">
            <IdentityCard identity={engine.identity} />
          </div>
          {signedIn ? (
            <Computers
              computers={accountUi.computers}
              online={accountUi.online}
              canConnect={controller.can.connect || ui.controllerState === "Online"}
              onConnect={(code) => void connectByCode(code)}
              onAdd={async (name, code) => {
                const error = await account.addComputer(name, code);
                if (error !== null) {
                  throw new Error(accountErrorCopy(error));
                }
              }}
              onAddThis={async () => {
                const error = await account.addThisComputer();
                if (error !== null) {
                  engine.run(async () => {
                    throw new Error(accountErrorCopy(error));
                  });
                  return;
                }
                // Immediately shareable: start host mode.
                if (await ensureEngine()) {
                  await engine.run(() => api.hostStart());
                }
              }}
              onRemove={(id) => {
                void account.removeComputer(id).then((error) => {
                  if (error !== null) {
                    engine.run(async () => {
                      throw new Error(accountErrorCopy(error));
                    });
                  }
                });
              }}
              onRename={(id, name) => {
                void account.renameComputer(id, name).then((error) => {
                  if (error !== null) {
                    engine.run(async () => {
                      throw new Error(accountErrorCopy(error));
                    });
                  }
                });
              }}
              onViewCode={() => {
                document.getElementById("identity")?.scrollIntoView({ behavior: "smooth" });
              }}
            />
          ) : (
            <Favorites
              favorites={engine.favorites}
              peerOnline={ui.peerOnline}
              canConnect={controller.can.connect || ui.controllerState === "Online"}
              onConnect={async (code) => {
                await connectByCode(code);
              }}
              onAdd={async (name, code) => {
                await api.addFavorite(name, code);
                await engine.refreshFavorites();
              }}
              onRemove={async (id) => {
                await engine.run(async () => {
                  const next = await api.removeFavorite(id);
                  return next;
                });
              }}
              onRename={async (id, name) => {
                await engine.run(async () => {
                  const next = await api.renameFavorite(id, name);
                  return next;
                });
              }}
            />
          )}
          <SettingsPanel settings={engine.settings} onSave={engine.saveSettings} />
        </div>
      </main>

      {showDiag ? <DiagnosticsOverlay snapshot={ui.diagnostics} /> : null}
    </div>
  );
}
