/** The shell: webview control surface only — video lives in the native
 * viewer window owned by the engine (invariant 1). Agent-first layout
 * (ADR-005), simplified 2026-10-26 per user feedback: ONE machine list
 * (rail, left) where every row is both a chat and a remote-control
 * target; the center column is the selected machine's page (header +
 * one Control action + conversation); a connect/session card pins above
 * it while in flight; the assistant panel stays on the right. The
 * accounts onboarding gate stays in front. */
import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { useEngine } from "./hooks/useEngine";
import { useAccount } from "./hooks/useAccount";
import { useAssistant } from "./hooks/useAssistant";
import { useChat } from "./hooks/useChat";
import { useDirectory } from "./hooks/useDirectory";
import { SettingsPanel } from "./components/IdentityCard";
import { excludeSelf, MachinesRail, RemoveMachineButton, unifiedMachines } from "./components/MachinesRail";
import { ConsentDialog, TrustedConnectCard } from "./components/ConsentDialog";
import { CircleSection, TrustedMachinesSection } from "./components/CircleSettings";
import { AssistantPanel } from "./components/AssistantPanel";
import { Conversation } from "./components/Conversation";
import { Onboarding } from "./components/Onboarding";
import { SessionCard } from "./components/ControllerPanel";
import { DiagnosticsOverlay } from "./components/DiagnosticsOverlay";
import { ErrorBanner } from "./components/Common";
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
  // The machine the current connect/session belongs to — the session card
  // stays labeled with it even when the user browses another machine.
  const [sessionCode, setSessionCode] = useState<string | null>(null);
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

  // Machine list + selection: computed before the onboarding gate so the
  // hooks below it never become conditional (Rules of Hooks).
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
  // Landing with machines but no selection: open the first one — the
  // center column should never be an empty "pick something" screen when
  // there is an obvious page to show.
  useEffect(() => {
    if (selectedCode === null && machines.length > 0) {
      setSelectedCode(machines[0].code);
    }
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

  // One-step remote control: the ONLY connect path (rail Control button,
  // machine-page Control button, add-machine "Save & control" — all end
  // up here). Starts the engine if needed, then asks to control.
  const controlMachine = async (code: string) => {
    const normalized = normalizeCode(code);
    setSelectedCode(normalized);
    setSessionCode(normalized);
    if (await ensureEngine()) {
      await engine.run(async () => {
        await api.controllerStart();
        await api.connect(normalized);
      });
    }
  };

  // Remove a machine YOU added (or that's pending approval): drops the
  // saved entry (favorite + roster row when signed in) and forgets the
  // pairing — established or still pending — so trust goes back to
  // asking. A circle machine merely falls back to "Not added yet".
  // Each leg is independent best-effort: a machine can be any mix of
  // roster row, favorite, and pairing record.
  const removeMachine = async (code: string) => {
    const favorite = engine.favorites.find((f) => f.code === code);
    const roster = signedIn ? accountUi.computers.find((c) => c.code === code) : undefined;
    if (favorite) {
      await engine.run(async () => {
        await api.removeFavorite(favorite.id);
      });
    }
    if (roster) {
      await account.removeComputer(roster.id);
    }
    // Pairing removal covers both established trust and pending offers;
    // absence is not an error worth surfacing.
    try {
      await api.pairingRemove(code);
    } catch {
      /* no pairing row for this code */
    }
    await engine.refreshFavorites();
    await refreshTrusted();
    setSelectedCode((current) => (current === code ? null : current));
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

  const sharing = ui.hostState !== "Idle" && ui.hostState !== "Registering";
  // The session card pins while a connect is in flight or a session is
  // live; afterwards its label is not needed (the end banner names it).
  const sessionRow = sessionCode ? machines.find((m) => m.code === sessionCode) ?? null : null;

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
          {/* Build label (0.5.3): visible version so family support never
              guesses — includes the family-build marker when applicable. */}
          {appVersion ? (
            <span className="brand-version" title="App version">
              v{appVersion}
              {directoryUi.familyBuild ? " family" : ""}
            </span>
          ) : null}
        </div>
        <div className="chips">
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
            The app isn't online yet — start it to control machines and be
            reachable yourself, or just pick a machine: it starts
            automatically.
          </p>
          <button
            type="button"
            className="primary"
            onClick={() => engine.run(() => api.engineStart())}
          >
            Start now
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
          onConnect={(code) => void controlMachine(code)}
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
           * gets the one-request dialog with the explicit remember verb. */}
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

          {/* Controller session card: pinned while asking/connecting/
           * controlling, whatever machine is selected below it. */}
          {controller.view === "connecting" || controller.view === "session" ? (
            <SessionCard
              controllerState={ui.controllerState}
              machineName={sessionRow?.name ?? sessionCode}
              monitors={ui.peerMonitors}
              activeMonitor={ui.activeMonitor}
              quality={ui.quality}
              scale={
                (ui.viewer.scale as "fit" | "one_to_one") ??
                (engine.settings?.default_viewer_scale as "fit" | "one_to_one") ??
                "fit"
              }
              viewerCreated={ui.viewer.created}
              onCancel={() => engine.run(() => api.cancelConnect())}
              onQuality={(preset) => engine.run(() => api.setQuality(preset))}
              onMonitor={(monitorId) => engine.run(() => api.selectMonitor(monitorId))}
              onScale={(mode) => engine.run(() => api.viewerSetScale(mode))}
              onFullscreen={() => engine.run(() => api.viewerToggleFullscreen())}
              onDisconnect={() => engine.run(() => api.disconnect())}
            />
          ) : null}

          {/* The selected machine's page: one primary action (remote
           * control) + the conversation. Same list, same verbs. */}
          {selected ? (
            <div className="machine-head">
              <div className="machine-title">
                <h2>{selected.name}</h2>
                <p className="muted">
                  <span
                    className={`dot ${selected.online === true ? "on" : selected.online === false ? "off" : "unknown"}`}
                    aria-hidden="true"
                  />{" "}
                  {selected.online === true
                    ? "online"
                    : selected.online === false
                      ? "offline"
                      : "presence unknown"}{" "}
                  · code <code className="code">{selected.code}</code>
                </p>
              </div>
              <div className="machine-actions">
                <button
                  type="button"
                  className="primary machine-control"
                  onClick={() => void controlMachine(selected.code)}
                  title={
                    selected.trusted
                      ? "Trusted machine — connects without asking again"
                      : "They'll be asked to allow it — once per machine"
                  }
                >
                  Control
                </button>
                {/* Circle-only machines aren't yours to remove — they leave
                 * the list when their owner leaves the circle. */}
                {selected.fromCircle ? null : (
                  <RemoveMachineButton
                    name={selected.name}
                    onRemove={() => void removeMachine(selected.code)}
                  />
                )}
              </div>
            </div>
          ) : (
            <div className="machine-head">
              <h2>Your machines</h2>
              <p className="muted">
                One list for messaging and remote control: pick a machine on
                the left (or add one with + Add / ask the assistant), then
                press Control. The other machine just allows it once.
              </p>
            </div>
          )}

          <Conversation name={selected?.name ?? null} chat={chat} />

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
