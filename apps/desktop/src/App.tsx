/** The shell: webview control surface only — video lives in the native
 * viewer window owned by the engine (invariant 1). Agent-first layout
 * (ADR-005): machines rail (left) · selected machine / session (center) ·
 * assistant panel (right). The accounts onboarding gate stays in front. */
import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { useEngine } from "./hooks/useEngine";
import { useAccount } from "./hooks/useAccount";
import { useAssistant } from "./hooks/useAssistant";
import { useChat } from "./hooks/useChat";
import { SettingsPanel } from "./components/IdentityCard";
import { MachinesRail, unifiedMachines } from "./components/MachinesRail";
import { AssistantPanel } from "./components/AssistantPanel";
import { Conversation } from "./components/Conversation";
import { Onboarding } from "./components/Onboarding";
import { ConnectPanel, SessionControls } from "./components/ControllerPanel";
import { DiagnosticsOverlay } from "./components/DiagnosticsOverlay";
import { ErrorBanner, StatusChip } from "./components/Common";
import { api, normalizeCode } from "./ipc";
import { accountErrorCopy, accountGate } from "./state/account";
import { controllerView, disconnectCopy, hostView } from "./state/mapping";
import mark from "./assets/mark.png";

export default function App() {
  const engine = useEngine();
  const [ui] = engine.ui;
  const account = useAccount();
  const [accountUi] = account.ui;
  const assistant = useAssistant();
  const [showDiag, setShowDiag] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [signInOpen, setSignInOpen] = useState(false);
  const [onboardingMode, setOnboardingMode] = useState<"signin" | "create">("signin");
  const [selectedCode, setSelectedCode] = useState<string | null>(null);
  const chat = useChat(selectedCode);

  // Shell version for the Settings label; tauri.conf is the single source
  // of truth. jsdom/tests have no Tauri bridge — stays null there.
  const [appVersion, setAppVersion] = useState<string | null>(null);
  useEffect(() => {
    getVersion()
      .then((v) => setAppVersion(v))
      .catch(() => setAppVersion(null));
  }, []);

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
  const gate =
    engine.settings === null
      ? ("loading" as const)
      : accountGate(accountUi, engine.settings.skipped_onboarding, signInOpen);

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
      return false;
    }
  };

  const skipOnboarding = async () => {
    setSignInOpen(false);
    if (engine.settings && !engine.settings.skipped_onboarding) {
      await engine.saveSettings({ ...engine.settings, skipped_onboarding: true });
    }
  };

  const afterAuth = async (error: string | null) => {
    if (error === null) {
      setSignInOpen(false);
      await engine.refreshFavorites();
    }
  };

  const signOut = async () => {
    await account.logout();
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
  const machines = unifiedMachines(
    engine.favorites,
    signedIn ? accountUi.computers : null,
    signedIn ? accountUi.online : [],
    ui.peerOnline,
    selectedCode,
  );
  const selected = machines.find((m) => m.code === selectedCode) ?? null;
  const sharing = ui.hostState !== "Idle" && ui.hostState !== "Registering";

  const share = async () => {
    if (await ensureEngine()) {
      await engine.run(() => api.hostStart());
    }
  };

  return (
    <div className="app agent-first">
      <header className="app-head">
        <div className="brand">
          <img className="brand-mark" src={mark} alt="" width="28" height="28" />
          <h1>DeepFlux</h1>
        </div>
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
            onClick={() => setShowSettings((v) => !v)}
            aria-pressed={showSettings}
          >
            Settings
          </button>
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
            /* engine errors are informational; replaced by the next one */
          }}
        />
      ) : null}
      {ui.lastInfo ? <p className="info-line">{ui.lastInfo}</p> : null}

      {!ui.engineStarted ? (
        <div className="banner banner-info" role="status">
          <p>
            The engine is not started yet — press <strong>Start engine</strong> once
            the signaling service is configured (Settings), or just ask the
            assistant to connect: it starts the engine for you.
          </p>
          <button
            type="button"
            className="primary"
            onClick={() => engine.run(() => api.engineStart())}
          >
            Start engine
          </button>
        </div>
      ) : null}

      <main className="workspace">
        <MachinesRail
          machines={machines}
          thisCode={engine.identity?.connection_code ?? "…"}
          hostState={ui.hostState}
          sharing={sharing}
          canConnect={controller.can.connect || ui.controllerState === "Online"}
          onPick={(code) => setSelectedCode(code)}
          onConnect={(code) => {
            setSelectedCode(code);
            void connectByCode(normalizeCode(code));
          }}
          onAdd={async (name, code) => {
            await api.addFavorite(name, code);
            await engine.refreshFavorites();
            setSelectedCode(code);
          }}
          onShare={() => void share()}
          onStopShare={() => engine.run(() => api.hostStop())}
        />

        <section className="center" aria-label="Selected machine">
          {/* Host-side consent prompt: the one modal-ish interruption. */}
          {host.can.accept && ui.consent ? (
            <div className="consent center-card" role="alertdialog" aria-label="Connection request">
              <p>
                <strong>{ui.consent.controller_device_id}</strong>{" "}
                {ui.consent.ai_session
                  ? "requests AI-agent control of this machine."
                  : "asks to control this machine."}
              </p>
              <p className="muted">
                {ui.consent.ai_session
                  ? "An AI agent will see the screen and drive mouse/keyboard for this one session. You can watch and take over at any time; the agent cannot type your passwords."
                  : "Accepting hands over screen viewing and keyboard/mouse control for this one session. The other side sees nothing until you accept."}
              </p>
              <div className="row">
                <button
                  type="button"
                  className="primary"
                  autoFocus
                  onClick={() => engine.run(() => api.consentAccept())}
                >
                  Accept
                </button>
                <button type="button" onClick={() => engine.run(() => api.consentReject())}>
                  Reject
                </button>
              </div>
            </div>
          ) : null}

          {selected ? (
            <div className="machine-head">
              <h2>{selected.name}</h2>
              <p className="muted">
                code <code className="code">{selected.code}</code> ·{" "}
                {selected.online === true ? "online" : selected.online === false ? "offline" : "presence unknown"}
              </p>
              {controller.can.connect || ui.controllerState === "Online" ? (
                <button
                  type="button"
                  className="primary"
                  onClick={() => void connectByCode(normalizeCode(selected.code))}
                >
                  Connect
                </button>
              ) : null}
            </div>
          ) : (
            <div className="machine-head">
              <h2>Pick a machine</h2>
              <p className="muted">
                Select one on the left, paste a code below, or ask the assistant
                to set things up.
              </p>
            </div>
          )}

          <Conversation name={selected?.name ?? null} chat={chat} />

          <ConnectPanel
            controllerState={ui.controllerState}
            onConnect={async (code) => {
              const normalized = normalizeCode(code);
              setSelectedCode((current) => current ?? normalized);
              await connectByCode(normalized);
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

          {endCopy && ui.controllerState === "Disconnected" ? (
            <div className="banner banner-info" role="status">
              <p>{endCopy.title}</p>
              {endCopy.hint ? <p className="hint">{endCopy.hint}</p> : null}
            </div>
          ) : null}

          {showSettings ? (
            <div className="center-card">
              <SettingsPanel
                settings={engine.settings}
                onSave={engine.saveSettings}
                version={appVersion}
              />
            </div>
          ) : null}
        </section>

        <AssistantPanel assistant={assistant} />
      </main>

      {showDiag ? <DiagnosticsOverlay snapshot={ui.diagnostics} /> : null}
    </div>
  );
}

// Re-exported for the account-error copy used by the Computers flow (kept
// from the previous layout; the roster Computers list rejoins the rail
// with the chat phase).
export { accountErrorCopy };
