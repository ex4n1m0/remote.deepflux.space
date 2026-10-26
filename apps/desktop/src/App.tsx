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
import { useDirectory } from "./hooks/useDirectory";
import { SettingsPanel } from "./components/IdentityCard";
import { excludeSelf, MachinesRail, unifiedMachines } from "./components/MachinesRail";
import { ConsentDialog, TrustedConnectCard } from "./components/ConsentDialog";
import { CircleSection, TrustedMachinesSection } from "./components/CircleSettings";
import { AssistantPanel } from "./components/AssistantPanel";
import { Conversation } from "./components/Conversation";
import { Onboarding } from "./components/Onboarding";
import { ConnectPanel, SessionControls } from "./components/ControllerPanel";
import { DiagnosticsOverlay } from "./components/DiagnosticsOverlay";
import { ErrorBanner, StatusChip } from "./components/Common";
import { api, normalizeCode } from "./ipc";
import { accountErrorCopy, accountGate } from "./state/account";
import { controllerView, disconnectCopy, engineErrorCopy, hostView } from "./state/mapping";
import mark from "./assets/mark.png";

export default function App() {
  const engine = useEngine();
  const [ui] = engine.ui;
  const account = useAccount();
  const [accountUi] = account.ui;
  const assistant = useAssistant();
  const directory = useDirectory();
  const [directoryUi] = directory.ui;
  // Trusted (paired) codes for the rail's shield badges — pulled at mount,
  // after consent decisions, and whenever a pairing event lands.
  const [trustedCodes, setTrustedCodes] = useState<Set<string>>(new Set());
  const refreshTrusted = async () => {
    try {
      const pairings = await api.pairingsList();
      setTrustedCodes(new Set(pairings.filter((p) => !p.pending_ack).map((p) => p.code)));
    } catch {
      /* engine-independent; the next event retries */
    }
  };
  const [showDiag, setShowDiag] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  // ADR-006 §5 first-run circle notice: session-only dismissal — the
  // point is the one-time notice on first contact, not a settings gate.
  const [circleNoticeDismissed, setCircleNoticeDismissed] = useState(false);
  const [signInOpen, setSignInOpen] = useState(false);
  const [onboardingMode, setOnboardingMode] = useState<"signin" | "create">("signin");
  const [selectedCode, setSelectedCode] = useState<string | null>(null);
  const chat = useChat(selectedCode);
  useEffect(() => {
    void refreshTrusted();
  }, []);
  useEffect(() => {
    // engine://pairing — trusted-set changes; engine://favorites — the
    // engine auto-favorited the controller-side machine on PairAck (the
    // saved row appears without a restart).
    const stops: Array<() => void> = [];
    void (async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        stops.push(await listen("engine://favorites", () => void engine.refreshFavorites()));
        stops.push(await listen("engine://pairing", () => void refreshTrusted()));
      } catch {
        /* jsdom/tests */
      }
    })();
    return () => {
      for (const stop of stops) stop();
    };
  }, []);

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
  const endCopy = ui.lastEnd ? disconnectCopy(ui.lastEnd.code, ui.lastEnd.cause) : null;
  const errCopy = ui.lastError ? engineErrorCopy(ui.lastError) : null;
  const gate =
    engine.settings === null
      ? ("loading" as const)
      : accountGate(accountUi, engine.settings.skipped_onboarding, signInOpen, {
          circleJoined: directoryUi.joined,
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
  // This machine's own directory row never becomes a connectable contact —
  // the pinned "This machine" card already represents self.
  const directoryRows =
    directoryUi.joined && directoryUi.loaded
      ? excludeSelf(directoryUi.machines, engine.identity?.device_id ?? null)
      : null;
  const machines = unifiedMachines(
    engine.favorites,
    signedIn ? accountUi.computers : null,
    signedIn ? accountUi.online : [],
    ui.peerOnline,
    selectedCode,
    directoryRows,
    trustedCodes,
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
          <StatusChip tone={host.tone} label="Host" text={host.status} />
          <StatusChip tone={controller.tone} label="Controller" text={controller.status} />
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
      {ui.lastError && errCopy ? (
        <ErrorBanner
          title={errCopy.title}
          message={errCopy.message}
          hint={errCopy.hint}
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

      {/* ADR-006 §5 consent moment: the one-time notice that this PC is
       * now visible in the family circle (the Settings toggle rules
       * afterwards; dismissal is session-only). */}
      {directoryUi.loaded && directoryUi.joined && !circleNoticeDismissed ? (
        <div className="banner banner-info" role="status">
          <p>
            This PC now appears in your family circle — family can see it's
            online and ask to connect. You control who connects: every new
            machine needs your approval.
          </p>
          <div className="row">
            <button
              type="button"
              className="primary"
              onClick={() => setCircleNoticeDismissed(true)}
            >
              OK
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => {
                void directory.setShared(false);
                setCircleNoticeDismissed(true);
              }}
            >
              Hide me from the circle
            </button>
          </div>
        </div>
      ) : null}

      <main className="workspace">
        <MachinesRail
          machines={machines}
          thisCode={engine.identity?.connection_code ?? "…"}
          hostState={ui.hostState}
          sharing={sharing}
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
          {/* Host-side consent prompt: the one modal-ish interruption.
           * ADR-006: paired-and-PROVEN reconnects render a passive status
           * card (the app layer already auto-accepted); everything else
           * gets the dialog with the "remember this machine" choice. */}
          {host.can.accept && ui.consent ? (
            ui.consent.pairing_proof_ok ? (
              <TrustedConnectCard consent={ui.consent} />
            ) : (
              <ConsentDialog
                consent={ui.consent}
                onAccept={(remember) =>
                  engine.run(() => api.consentAccept(remember)).then(() => void refreshTrusted())
                }
                onReject={() => engine.run(() => api.consentReject())}
              />
            )
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
              <CircleSection directory={directory} />
              <TrustedMachinesSection onRevoked={() => void refreshTrusted()} />
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
