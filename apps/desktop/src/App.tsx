/** The shell: webview control surface only — video lives in the native
 * viewer window owned by the engine (invariant 1). */
import { useEffect, useState } from "react";
import { useEngine } from "./hooks/useEngine";
import { IdentityCard, SettingsPanel } from "./components/IdentityCard";
import { Favorites } from "./components/Favorites";
import { HostPanel } from "./components/HostPanel";
import { ConnectPanel, SessionControls } from "./components/ControllerPanel";
import { DiagnosticsOverlay } from "./components/DiagnosticsOverlay";
import { ErrorBanner, StatusChip } from "./components/Common";
import { api, normalizeCode } from "./ipc";
import { controllerView, disconnectCopy, hostView } from "./state/mapping";

export default function App() {
  const engine = useEngine();
  const [ui] = engine.ui;
  const [showDiag, setShowDiag] = useState(false);
  const [settingsOpenHint, setSettingsOpenHint] = useState(false);

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

  return (
    <div className="app">
      <header className="app-head">
        <h1>Remote Desktop</h1>
        <div className="chips">
          <StatusChip tone={host.tone} label="Host" text={ui.hostState} />
          <StatusChip tone={controller.tone} label="Controller" text={ui.controllerState} />
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
          <IdentityCard identity={engine.identity} />
          <Favorites
            favorites={engine.favorites}
            peerOnline={ui.peerOnline}
            canConnect={controller.can.connect || ui.controllerState === "Online"}
            onConnect={async (code) => {
              if (await ensureEngine()) {
                await engine.run(async () => {
                  await api.controllerStart();
                  await api.connect(code);
                });
              }
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
          <SettingsPanel settings={engine.settings} onSave={engine.saveSettings} />
        </div>
      </main>

      {showDiag ? <DiagnosticsOverlay snapshot={ui.diagnostics} /> : null}
    </div>
  );
}
