/** The shell: webview control surface only — video lives in the native
 * viewer window owned by the engine (invariant 1). Agent-first layout
 * (ADR-005), simplified 2026-10-26 per user feedback: ONE machine list
 * (rail, left) where every row is both a chat and a remote-control
 * target; the center column is the selected machine's page (header +
 * one Control action + conversation); a connect/session card pins above
 * it while in flight; the assistant panel stays on the right.
 *
 * 0.10.0 (ADR-009): no accounts, no onboarding gate — the machine's
 * display name is the only identity and it travels on the connect
 * request; the host's prompt shows it beside the device id. Everything
 * configurable lives in the top menu bar (File / Config / Help). */
import { useEffect, useRef, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { useEngine } from "./hooks/useEngine";
import { useAssistant } from "./hooks/useAssistant";
import { useChat } from "./hooks/useChat";
import { useDirectory } from "./hooks/useDirectory";
import { excludeSelf, MachinesRail, RemoveMachineButton, unifiedMachines } from "./components/MachinesRail";
import { ConsentDialog, TrustedConnectCard } from "./components/ConsentDialog";
import { MenuBar } from "./components/MenuBar";
import { ConfigDialog, type ConfigSection } from "./components/ConfigDialog";
import { AssistantPanel } from "./components/AssistantPanel";
import { AgentChat } from "./components/AgentChat";
import { Conversation } from "./components/Conversation";
import { SessionCard } from "./components/ControllerPanel";
import { DiagnosticsOverlay } from "./components/DiagnosticsOverlay";
import { ErrorBanner } from "./components/Common";
import { UpdateBanner } from "./components/UpdateBanner";
import { useUpdate } from "./hooks/useUpdate";
import { api, normalizeCode } from "./ipc";
import { controllerView, disconnectCopy, engineErrorCopy, hostView } from "./state/mapping";
import mark from "./assets/mark.png";

export default function App() {
  const engine = useEngine();
  const [ui] = engine.ui;
  const assistant = useAssistant();
  const directory = useDirectory();
  const [directoryUi] = directory.ui;
  // ADR-008 update flow: banner states + the user verbs. Declared with
  // the other hooks (never conditional); jsdom keeps state null.
  const update = useUpdate();
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
  // 0.8.0 GUI restructure: configuration lives in the Config modal behind
  // the top menu bar; About is its own small modal.
  const [configSection, setConfigSection] = useState<ConfigSection | null>(null);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [addMachineSignal, setAddMachineSignal] = useState(0);
  // ADR-006 §5 first-run circle notice: a PASSIVE toast now (0.8.0 — no
  // OK button); it self-dismisses and visibility is managed in
  // Config → Circle.
  const [circleNoticeDismissed, setCircleNoticeDismissed] = useState(false);
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
  // ADR-008: installing restarts the app — the install button disables
  // while any session machinery is live (connected, consent prompt, or
  // handshake), matching the Rust-side refusal set.
  const quietRoleStates: ReadonlySet<string> = new Set([
    "Idle",
    "Registering",
    "Online",
    "Disconnected",
  ]);
  const updateSessionLive =
    !quietRoleStates.has(ui.hostState) || !quietRoleStates.has(ui.controllerState);
  // The up-to-date answer to an explicit check self-dismisses (it rides
  // on the updater's status, so the timer only arms on the transition —
  // poll re-renders don't restart it; the CircleNoticeToast lesson).
  useEffect(() => {
    if (update.state?.status !== "none") return;
    const timer = setTimeout(() => update.dismiss(), 8_000);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [update.state?.status]);

  // Machine list + selection. This machine's own directory row never
  // becomes a connectable contact — the pinned "This machine" card
  // already represents self.
  const directoryRows =
    directoryUi.joined && directoryUi.loaded
      ? excludeSelf(directoryUi.machines, engine.identity?.device_id ?? null)
      : null;
  const machines = unifiedMachines(
    engine.favorites,
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

  // One-step remote control: the ONLY connect path (rail Control button,
  // machine-page Control button, add-machine "Save & control" — all end
  // up here). Starts the engine if needed and asks to control; the
  // engine brings the controller role online itself when it isn't yet
  // (always-ready, 0.6.3) — there is no enable step anywhere. The
  // connect request carries this machine's display name (ADR-009).
  const controlMachine = async (code: string, agent = false) => {
    const normalized = normalizeCode(code);
    setSelectedCode(normalized);
    setSessionCode(normalized);
    if (await ensureEngine()) {
      await engine.run(() => api.connect(normalized, agent));
    }
  };

  // Remove a machine YOU added (or that's pending approval): drops the
  // saved entry (favorite) and forgets the pairing — established or still
  // pending — so trust goes back to asking. A circle machine merely falls
  // back to "Not added yet". Each leg is independent best-effort: a
  // machine can be any mix of favorite and pairing record.
  const removeMachine = async (code: string) => {
    const favorite = engine.favorites.find((f) => f.code === code);
    if (favorite) {
      await engine.run(async () => {
        await api.removeFavorite(favorite.id);
      });
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

  const sharing = ui.hostState !== "Idle" && ui.hostState !== "Registering";
  // The session card pins while a connect is in flight or a session is
  // live; afterwards its label is not needed (the end banner names it).
  const sessionRow = sessionCode ? machines.find((m) => m.code === sessionCode) ?? null : null;
  // Live session with the SELECTED machine (either verb): the agent chat
  // box is up, and Control turns into "Show screen" while the viewer is
  // suppressed (agent session without the visual attached).
  const connectedToSelected =
    ui.controllerState === "Connected" &&
    sessionCode !== null &&
    sessionCode === selected?.code;

  const share = async () => {
    if (await ensureEngine()) {
      await engine.run(() => api.hostStart());
    }
  };

  return (
    <div className="app agent-first">
      <header className="app-head">
        <MenuBar
          version={appVersion}
          onAddMachine={() => setAddMachineSignal((n) => n + 1)}
          onOpenConfig={(section) => setConfigSection(section)}
          onAbout={() => setAboutOpen(true)}
          onDiagnostics={() => setShowDiag((v) => !v)}
          onCheckForUpdates={() => update.check()}
          onQuit={() => void api.quitApp()}
        />
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

      {/* ADR-006 §5 consent moment, passive since 0.8.0: a one-time notice
       * that this PC is visible in the family circle. No OK press — it
       * self-dismisses; visibility is managed in Config → Family circle. */}
      {directoryUi.loaded && directoryUi.joined && !circleNoticeDismissed ? (
        <CircleNoticeToast onDone={() => setCircleNoticeDismissed(true)} />
      ) : null}

      {/* ADR-008 update flow: available / downloading / ready / installing
       * / error, plus the quiet "checking" and up-to-date answers to an
       * explicit Check (Help). Idle renders nothing; the up-to-date line
       * self-dismissed via the effect below. */}
      {update.state ? (
        <UpdateBanner
          state={update.state}
          sessionLive={updateSessionLive}
          onUpdate={update.download}
          onInstall={update.install}
          onRetry={() =>
            update.state?.stage === "check" ? update.check() : update.download()
          }
          onDismiss={update.dismiss}
        />
      ) : null}

      <main className="workspace">
        <MachinesRail
          machines={machines}
          thisCode={engine.identity?.connection_code ?? "…"}
          hostState={ui.hostState}
          sharing={sharing}
          addSignal={addMachineSignal}
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
              agentSession={ui.viewerSuppressed}
              agentOrigin={ui.sessionAgent}
              onCancel={() => engine.run(() => api.cancelConnect())}
              onQuality={(preset) => engine.run(() => api.setQuality(preset))}
              onMonitor={(monitorId) => engine.run(() => api.selectMonitor(monitorId))}
              onScale={(mode) => engine.run(() => api.viewerSetScale(mode))}
              onFullscreen={() => engine.run(() => api.viewerToggleFullscreen())}
              onShowViewer={() => engine.run(() => api.viewerShow())}
              onHideViewer={() => engine.run(() => api.viewerHide())}
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
                {connectedToSelected && ui.viewerSuppressed ? (
                  <button
                    type="button"
                    className="primary machine-control"
                    onClick={() => engine.run(() => api.viewerShow())}
                    title="Attach the viewer window to this live session — watch what the assistant is doing; closing it keeps the session"
                  >
                    Show screen
                  </button>
                ) : (
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
                )}
                <button
                  type="button"
                  className="machine-agent"
                  disabled={connectedToSelected}
                  onClick={() => void controlMachine(selected.code, true)}
                  title={
                    connectedToSelected
                      ? "This machine's assistant is already reachable — its chat box is below"
                      : "Connect chat-only: give this machine's assistant instructions without opening the screen"
                  }
                >
                  Agent
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

          {/* Agent box (session-gated, its own surface): the peer
           * machine's assistant is reachable only while a live session
           * with THIS machine exists — controller side (we connected to
           * it, either verb) or host side (it connected to us; the
           * session peer comes from the SessionEstablished event). Out of
           * session the inbox carries no agent bit, so the backend would
           * refuse anyway. */}
          {!!selected &&
          ((ui.controllerState === "Connected" && sessionCode === selected.code) ||
            (ui.hostState === "Connected" && ui.sessionPeer === selected.code)) ? (
            <AgentChat name={selected.name} chat={chat} />
          ) : null}
          <Conversation name={selected?.name ?? null} chat={chat} />

          {endCopy && ui.controllerState === "Disconnected" ? (
            <div className="banner banner-info" role="status">
              <p>{endCopy.title}</p>
              {endCopy.hint ? <p className="hint">{endCopy.hint}</p> : null}
            </div>
          ) : null}
        </section>

        <AssistantPanel
          assistant={assistant}
          onOpenConfig={() => setConfigSection("assistant")}
        />
      </main>

      {configSection ? (
        <ConfigDialog
          open
          section={configSection}
          settings={engine.settings}
          onSaveSettings={engine.saveSettings}
          version={appVersion}
          directory={directory}
          assistant={assistant}
          onRevokedTrusted={() => void refreshTrusted()}
          onClose={() => setConfigSection(null)}
        />
      ) : null}

      {aboutOpen ? (
        <div className="modal-backdrop" onClick={() => setAboutOpen(false)}>
          <div className="modal about-modal" role="dialog" aria-modal="true" aria-label="About">
            <header className="modal-head">
              <h2>DeepFlux</h2>
              <button
                type="button"
                className="ghost small"
                onClick={() => setAboutOpen(false)}
                aria-label="Close"
                autoFocus
              >
                Close
              </button>
            </header>
            <p>
              Peer-to-peer remote desktop for the family — direct connection, no relay, video
              never leaves the two machines.
            </p>
            <p className="muted">
              Version {appVersion ?? "—"}
              {directoryUi.familyBuild ? " (family build)" : ""}
            </p>
            <p className="muted small">
              Diagnostics: Ctrl+Shift+D · Website: remote.deepflux.space
            </p>
          </div>
        </div>
      ) : null}

      {showDiag ? <DiagnosticsOverlay snapshot={ui.diagnostics} /> : null}
    </div>
  );
}

/** The ADR-006 §5 first-run circle notice as a passive toast: no buttons,
 * self-dismisses, click to dismiss. The timer holds the callback in a ref
 * with empty deps — App re-renders every poll tick (engine 1 Hz,
 * assistant 2 s) and a deps-bound timer would restart forever. */
function CircleNoticeToast({ onDone }: { onDone: () => void }) {
  const doneRef = useRef(onDone);
  doneRef.current = onDone;
  useEffect(() => {
    const timer = setTimeout(() => doneRef.current(), 12_000);
    return () => clearTimeout(timer);
  }, []);
  return (
    <div
      className="banner banner-info circle-toast"
      role="status"
      onClick={() => doneRef.current()}
      title="Click to dismiss"
    >
      <p>
        This PC now appears in your family circle — family can see it's online and ask to
        connect. You control who connects: every new machine needs your approval. (Manage
        visibility in Config → Family circle.)
      </p>
    </div>
  );
}

// Exported for the toast-timer test (the self-dismiss depends on a stable
// timer across the 1–2 s polls that re-render the shell).
export { CircleNoticeToast };
