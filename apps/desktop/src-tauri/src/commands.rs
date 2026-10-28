//! Typed Tauri commands — a THIN veneer over the engine (RD-011). Every
//! command maps 1:1 onto an [`engine::EngineCmd`] or a local store read;
//! every payload is metadata (strings/numbers). No command or event in
//! this file can transport frame bytes, GPU handles, SDP bodies, or input
//! payloads (invariant 1 — asserted by the IPC surface test).

use std::sync::Mutex;

use tauri::{AppHandle, Emitter, Manager};

use crate::engine::{
    self, EngineCmd, EngineConfig, EngineEvent, EngineHandle, preset_from_name, scale_from_name,
};
use crate::ipc::*;
use crate::store::{AppSettings, LocalStore};

/// Event channel names (engine → UI). Payloads: see `forward_event`.
pub mod events {
    pub const STATE: &str = "engine://state";
    pub const CONSENT: &str = "engine://consent";
    pub const SESSION_ESTABLISHED: &str = "engine://session-established";
    pub const SESSION_ENDED: &str = "engine://session-ended";
    pub const PEER: &str = "engine://peer";
    pub const CAPS: &str = "engine://caps";
    pub const DIAGNOSTICS: &str = "engine://diagnostics";
    pub const ERROR: &str = "engine://error";
    pub const INFO: &str = "engine://info";
    pub const CHAT: &str = "engine://chat";
    pub const PAIRING: &str = "engine://pairing";
}

pub struct AppServices {
    pub store: Mutex<LocalStore>,
    pub engine: Mutex<Option<EngineHandle>>,
    /// Account/roster state (post-MVP accounts). Lock order when both are
    /// held: store first, then account (see `with_account`).
    pub account: Mutex<crate::account::AccountManager>,
    /// In-app assistant (ADR-005): worker thread + busy flag.
    pub assistant: crate::agent::AssistantState,
    /// ADR-006 pairing-ceremony state: the in-memory pairing offer, the
    /// live prompt mark, and prompt-flood cooldowns.
    pub trust: Mutex<crate::chat::TrustState>,
    /// ADR-006 circle-directory cache (single-flight, latest-wins).
    pub directory: Mutex<crate::directory::DirectoryCache>,
    /// ADR-008 automatic updates: the UI state machine plus the last
    /// fetched manifest (input for the download step).
    pub update: crate::updater::UpdateEngine,
    pub update_manifest: Mutex<Option<crate::updater::UpdateManifest>>,
}

type CmdResult<T> = Result<T, String>;

fn with_engine<T>(app: &AppHandle, f: impl FnOnce(&EngineHandle) -> CmdResult<T>) -> CmdResult<T> {
    let services = app.state::<AppServices>();
    let guard = services.engine.lock().expect("engine slot");
    let Some(handle) = guard.as_ref() else {
        return Err("engine not started (set the signaling URL and go online first)".into());
    };
    f(handle)
}

/// Run an account operation with the store + account locks held (store
/// first — the only place both are taken together). Keeps the service
/// adapter in sync with signaling-URL changes without a restart.
fn with_account<T>(
    app: &AppHandle,
    f: impl FnOnce(&mut LocalStore, &mut crate::account::AccountManager) -> CmdResult<T>,
) -> CmdResult<T> {
    let services = app.state::<AppServices>();
    let mut store = services.store.lock().expect("store");
    let mut account = services.account.lock().expect("account");
    let url = store.settings().signaling_base_url.clone();
    account.set_base_url(&url);
    if url.trim().is_empty() {
        return Err(format!(
            "No account service configured. Open Settings and set the service URL to {} first.",
            crate::store::DEFAULT_SIGNALING_BASE_URL
        ));
    }
    f(&mut store, &mut account)
}

/// Create the engine thread (signaling connection + runtime). Idempotent.
#[tauri::command]
pub fn engine_start(app: AppHandle) -> CmdResult<EngineStatusDto> {
    start_engine(&app)
}

/// Shared engine-start path: the typed command above and the MCP bridge's
/// auto-start (ADR-004, RD-018) both call this.
pub(crate) fn start_engine(app: &AppHandle) -> CmdResult<EngineStatusDto> {
    // A dead engine thread (panic) must not zombie the app: the old code
    // reused the slot forever, so every later command failed "engine
    // stopped" until a manual restart (2026-10-28 incident). The slot is
    // now checked for LIVENESS; a dead handle is replaced and the
    // always-ready roles are replayed on the fresh engine.
    let replay = {
        let services = app.state::<AppServices>();
        let mut guard = services.engine.lock().expect("engine slot");
        match guard.as_ref() {
            Some(handle) if handle.is_alive() => {
                return Ok(handle.status().into());
            }
            Some(dead) => {
                let status = dead.status();
                let replay = (
                    status.controller_state != "Idle",
                    status.host_state != "Idle",
                );
                *guard = None; // drop the zombie handle
                Some(replay)
            }
            None => None,
        }
    };
    let (settings, metrics_dir) = {
        let services = app.state::<AppServices>();
        let store = services.store.lock().expect("store");
        (
            store.settings().clone(),
            app.path()
                .app_log_dir()
                .unwrap_or_else(|_| std::env::temp_dir()),
        )
    };
    if settings.signaling_base_url.trim().is_empty() {
        return Err(
            "No signaling server configured. Open Settings and set the service URL \
             (the deployed Vercel service, or the local dev server for testing)."
                .into(),
        );
    }
    let signaling = node_runtime::signaling_remote::RemoteSignaling::new(
        node_runtime::signaling_remote::RemoteSignalingConfig::new(
            &settings.signaling_base_url,
            &settings.device_id,
            &settings.device_token,
        ),
    );
    let quality = preset_from_name(&settings.default_quality)
        .unwrap_or(protocol::wire::QualityPreset::Balanced);
    let scale =
        scale_from_name(&settings.default_viewer_scale).unwrap_or(render_windows::ScaleMode::Fit);
    let cfg = EngineConfig {
        device_id: settings.device_id.clone(),
        signaling: Box::new(signaling),
        real_pipelines: true,
        real_input: true,
        auto_reonline: true,
        metrics_dir: Some(metrics_dir),
        status_file: None,
        viewer_title: "Remote Desktop".to_owned(),
        initial_quality: quality,
        initial_scale: scale,
        // Test-only chaos is never set by the product shell (E2E only).
        blackhole_remote_candidates: false,
    };
    let (mut handle, events) = engine::spawn(cfg);
    // Forwarder: engine events → webview events (metadata only).
    let forward_app = app.clone();
    std::thread::Builder::new()
        .name("engine-events".into())
        .spawn(move || {
            while let Ok(event) = events.recv() {
                if !forward_event(&forward_app, event) {
                    break;
                }
            }
        })
        .map_err(|e| format!("event forwarder spawn: {e}"))?;
    // Two callers can race a respawn (UI poll + assistant); the loser's
    // fresh engine is shut down and the winner's status returned.
    let status = {
        let services = app.state::<AppServices>();
        let mut slot = services.engine.lock().expect("engine slot");
        if let Some(existing) = slot.as_ref()
            && existing.is_alive()
        {
            let status = existing.status().into();
            drop(slot);
            handle.shutdown();
            return Ok(status);
        }
        *slot = Some(handle);
        let Some(live) = slot.as_ref() else {
            unreachable!("just stored");
        };
        live.status().into()
    };
    // Replay the always-ready roles the dead engine had (0.6.3): the
    // controller role for everyone, host presence when it was sharing.
    if let Some((controller, host)) = replay {
        let _ = with_engine(app, |handle| {
            if controller {
                let _ = handle.send(EngineCmd::ControllerStart);
            }
            if host {
                let _ = handle.send(EngineCmd::HostStart);
            }
            Ok(())
        });
        let _ = app.emit(
            events::INFO,
            Some(serde_json::json!({ "message":
                "The connection engine stopped unexpectedly and was restarted. If a session was live, it has ended — connect again."
            })),
        );
    }
    Ok(status)
}

/// Map one engine event onto a Tauri event. Returns false when the engine
/// event channel closed (forwarder exits).
fn forward_event(app: &AppHandle, event: EngineEvent) -> bool {
    let emit = |name: &str, payload: Option<serde_json::Value>| {
        let _ = app.emit(name, payload.unwrap_or(serde_json::Value::Null));
    };
    match event {
        EngineEvent::StateChanged {
            machine,
            state,
            session_id,
        } => {
            // ADR-006 B3: a host consent prompt that fell back to Online
            // without an accept or an explicit reject was a TIMEOUT — cool
            // the controller down so an unanswered prompt cannot be
            // re-spammed.
            if machine == "Host" && state == "Online" {
                let now = crate::chat::now_ms();
                let services = app.state::<AppServices>();
                let mut trust = services.trust.lock().expect("trust state");
                trust.sweep(now);
                if let Some((controller, accepted, rejected)) = trust.prompt.take()
                    && !accepted
                    && !rejected
                    && !trust.blocked(&controller, now)
                {
                    trust.block(&controller, now + crate::chat::TIMEOUT_COOLDOWN_MS);
                }
            }
            emit(
                events::STATE,
                Some(
                    serde_json::json!({ "machine": machine, "state": state, "session_id": session_id }),
                ),
            )
        }
        EngineEvent::ConsentRequested {
            controller_device_id,
            session_id,
            ai_session,
            pairing_proof_hex,
            requester_name,
            message_id,
        } => {
            // ADR-006: silent auto-accept requires a VALID pairing proof.
            // The bare device id proves nothing — ids are claimable through
            // the presence-tombstone window minutes after a machine goes
            // offline — so a claimed-trusted request without a matching
            // proof falls back to the human prompt (with a warning flag);
            // fail open to the human, never to accept.
            let host_device_id = {
                let services = app.state::<AppServices>();
                let store = services.store.lock().expect("store");
                store.settings().device_id.clone()
            };
            let pairing = crate::chat::pairing_for(app, &controller_device_id);
            let paired = pairing.is_some();
            let verified = pairing
                .as_ref()
                .map(|p| {
                    node_runtime::pairing_proof::verify_pairing_proof(
                        &p.secret_hex,
                        &controller_device_id,
                        &host_device_id,
                        &session_id,
                        &message_id,
                        pairing_proof_hex.as_deref(),
                        crate::chat::now_ms(),
                    )
                })
                .unwrap_or(false);
            let mut proof_ok = false;
            if verified {
                // RD-023 (user decision 2, 2026-10-24) + ADR-006 proof:
                // proven-paired controllers are auto-accepted — silent full
                // control. The emitted event still fires; the state change
                // resolves any prompt within a tick. `proof_ok` in the
                // payload means "silent accept actually sent" — if the
                // engine send failed the UI must show the dialog, not a
                // decisionless passive card.
                proof_ok = crate::chat::auto_accept_if_paired(app, &controller_device_id);
            } else {
                // ADR-006 B3 prompt-flood defense: a controller in cooldown
                // (explicit reject / unanswered timeout) is auto-rejected
                // without a prompt.
                let now = crate::chat::now_ms();
                let services = app.state::<AppServices>();
                let mut trust = services.trust.lock().expect("trust state");
                trust.sweep(now);
                if trust.blocked(&controller_device_id, now) {
                    drop(trust);
                    let _ = with_engine(app, |handle| handle.send(EngineCmd::ConsentReject));
                    return true;
                }
                trust.prompt = Some((controller_device_id.clone(), false, false));
                // The window must be VISIBLE for the consent moment: an
                // always-ready family host normally lives in the tray, and
                // an invisible prompt dies at the 30 s timeout.
                if let Some(window) = app.get_webview_window("shell") {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
            }
            emit(
                events::CONSENT,
                Some(serde_json::json!({
                    "controller_device_id": controller_device_id,
                    "session_id": session_id,
                    "ai_session": ai_session,
                    "paired": paired,
                    "pairing_proof_ok": proof_ok,
                    // ADR-007: the account name from the wire wins; the
                    // circle nickname (self-chosen, advisory — the code
                    // beside it in the prompt is the identity) is the
                    // fallback for pre-0.8 controllers.
                    "requester_name": requester_name.or_else(|| {
                        crate::directory::nickname_for(app, &controller_device_id)
                    }),
                })),
            );
        }
        EngineEvent::ConsentAccepted {
            controller_device_id,
            remember,
        } => {
            // ADR-006: the owner's click IS the pairing ceremony — but the
            // controller's PairOffer arrives only after the session
            // establishes, so RECORD the decision now and apply it when the
            // offer lands (see PairOfferReceived below).
            {
                let services = app.state::<AppServices>();
                let mut trust = services.trust.lock().expect("trust state");
                if let Some((_, accepted, _)) = trust.prompt.as_mut() {
                    *accepted = true;
                }
                trust.decision = Some((controller_device_id.clone(), remember));
            }
            // ADR-006 amendment (2026-10-28): "Always allow" is durable at
            // click time. The in-memory decision above dies with the
            // session — if the controller's PairOffer is lost to a short
            // session or a teardown race, the standing intent completes
            // the pairing in the next session the owner allows instead of
            // silently voiding the click (the "approved forever, asked
            // again" bug). "Allow once" neither arms nor revokes: a
            // standing Always survives it; only Decline or removing the
            // machine in Trusted machines revokes.
            if remember {
                crate::chat::remember_intent(app, &controller_device_id);
            }
        }
        EngineEvent::SessionEstablished { session_id, peer } => {
            // RD-023 + ADR-006 amendment (2026-10-28): offer pairing only
            // when THIS machine is the controller of the session. The owed
            // flag was set by our own connect command for this peer; a
            // host-side establish (we're being controlled) has none — the
            // host must never mint/offer pairings toward its controller
            // (spurious offers cross-wired the two sides' secrets and
            // could strand both at endless prompts).
            let controller_session = {
                let services = app.state::<AppServices>();
                let mut trust = services.trust.lock().expect("trust state");
                trust
                    .owed_pair_offer
                    .take()
                    .is_some_and(|owed| Some(owed) == peer)
            };
            if controller_session && let Some(peer) = peer.as_deref() {
                crate::chat::offer_pairing_if_new(app, peer);
            }
            emit(
                events::SESSION_ESTABLISHED,
                Some(serde_json::json!({ "session_id": session_id, "peer": peer })),
            );
        }
        EngineEvent::SessionEnded {
            cause,
            code,
            message,
            hint,
        } => {
            // ADR-006: the ceremony state dies with the session — an
            // un-applied decision or lingering prompt never crosses into
            // the next one.
            {
                let services = app.state::<AppServices>();
                let mut trust = services.trust.lock().expect("trust state");
                trust.decision = None;
                trust.prompt = None;
            }
            emit(
                events::SESSION_ENDED,
                Some(
                    serde_json::json!({ "cause": cause, "code": code, "message": message, "hint": hint }),
                ),
            )
        }
        EngineEvent::PeerOnline { device_id } => emit(
            events::PEER,
            Some(serde_json::json!({ "device_id": device_id, "online": true })),
        ),
        EngineEvent::PeerOffline { device_id } => emit(
            events::PEER,
            Some(serde_json::json!({ "device_id": device_id, "online": false })),
        ),
        EngineEvent::HostCaps { monitors } => emit(
            events::CAPS,
            Some(serde_json::json!({ "origin": "host", "monitors": monitors })),
        ),
        EngineEvent::PeerCaps { monitors } => emit(
            events::CAPS,
            Some(serde_json::json!({ "origin": "peer", "monitors": monitors })),
        ),
        EngineEvent::Diagnostics { snapshot } => emit(
            events::DIAGNOSTICS,
            Some(serde_json::json!({ "snapshot": snapshot })),
        ),
        EngineEvent::Error {
            code,
            message,
            hint,
        } => {
            // Pre-connection send failures about the TARGET are "that
            // machine is offline", not a direct-connection problem — the
            // raw code + NAT hint reads as breakage to family users.
            if message.contains("unknown_target") {
                emit(
                    events::ERROR,
                    Some(serde_json::json!({
                        "code": "host_offline",
                        "message": "That machine isn\u{2019}t online right now. Ask whoever uses it to open the app (it starts automatically when their PC is on), then try again.",
                        "hint": null
                    })),
                );
            } else {
                emit(
                    events::ERROR,
                    Some(serde_json::json!({ "code": code, "message": message, "hint": hint })),
                )
            }
        }
        EngineEvent::Info { message } => emit(
            events::INFO,
            Some(serde_json::json!({ "message": message })),
        ),
        // ADR-005 (RD-022/023): chat + pairing are persisted app-side (the
        // engine only transports), then forwarded to the webview.
        EngineEvent::ChatReceived {
            peer,
            id,
            ts_ms,
            sender,
            body,
        } => {
            crate::chat::record_incoming(app, &peer, id, ts_ms, &sender, &body);
            emit(
                events::CHAT,
                Some(serde_json::json!({
                    "peer": peer, "id": id, "ts_ms": ts_ms, "sender": sender, "body": body
                })),
            );
        }
        EngineEvent::PairOfferReceived {
            controller_device_id,
            secret_hex,
        } => {
            // ADR-006: apply the owner's "Always allow" when the offer
            // lands — this session's click (trust.decision) or a standing
            // intent from an earlier click whose offer was lost (2026-10-28
            // amendment; both are explicit human choices for this device
            // id). Anything else → drop un-acked (the controller's pending
            // offer expires client-side; nothing is stored).
            let click_remembered = {
                let services = app.state::<AppServices>();
                let mut trust = services.trust.lock().expect("trust state");
                trust
                    .decision
                    .take_if(|(controller, _)| controller == &controller_device_id)
                    .is_some_and(|(_, remember)| remember)
            };
            let remember =
                click_remembered || crate::chat::has_remember_intent(app, &controller_device_id);
            if remember {
                // Human-backed: a stale secret (controller reinstall, lost
                // ack) is replaced instead of refused, so one Always-click
                // re-pairs instead of prompting forever.
                let live =
                    crate::chat::record_pairing(app, &controller_device_id, &secret_hex, true);
                if live {
                    let _ = with_engine(app, |handle| handle.send(EngineCmd::SendPairAck));
                } else {
                    // Unreachable under the human-backed path, kept as the
                    // fail-safe copy for any future non-backed caller.
                    let _ = app.emit(
                        events::INFO,
                        Some(serde_json::json!({ "message": format!(
                            "Pairing key mismatch with {controller_device_id} - remove it in Settings, Trusted machines, to re-pair."
                        ) })),
                    );
                }
                emit(
                    events::PAIRING,
                    Some(serde_json::json!({ "device_id": controller_device_id, "paired": live })),
                );
            }
        }
        EngineEvent::PairAckReceived { host_device_id } => {
            crate::chat::pairing_ack(app, &host_device_id);
            // ADR-006: the ack means the owner accepted with "remember" —
            // save the machine to favorites (circle nickname when known,
            // the code as placeholder). The rail's name precedence
            // backfills the display name from the directory later.
            let name = crate::directory::nickname_for(app, &host_device_id)
                .unwrap_or_else(|| host_device_id.clone());
            {
                let services = app.state::<AppServices>();
                let mut store = services.store.lock().expect("store");
                let _ = store.add_favorite_sourced(&name, &host_device_id, "directory");
            }
            emit(
                events::PAIRING,
                Some(serde_json::json!({ "device_id": host_device_id, "paired": true })),
            );
            let _ = app.emit("engine://favorites", serde_json::json!({}));
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Identity / settings / favorites (local persistence)
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_identity(app: AppHandle) -> CmdResult<Identity> {
    let services = app.state::<AppServices>();
    let store = services.store.lock().expect("store");
    Ok(Identity {
        connection_code: store.settings().device_id.clone(),
        device_id: store.settings().device_id.clone(),
        device_name: display_name(store.settings()),
    })
}

pub(crate) fn display_name(settings: &AppSettings) -> String {
    if settings.device_name.trim().is_empty() {
        hostname()
    } else {
        settings.device_name.trim().to_owned()
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "this-pc".into())
}

#[tauri::command]
pub fn get_settings(app: AppHandle) -> CmdResult<SettingsDto> {
    let services = app.state::<AppServices>();
    let store = services.store.lock().expect("store");
    let s = store.settings();
    Ok(SettingsDto {
        device_id: s.device_id.clone(),
        device_name: s.device_name.clone(),
        signaling_base_url: s.signaling_base_url.clone(),
        default_quality: s.default_quality.clone(),
        default_viewer_scale: s.default_viewer_scale.clone(),
        skipped_onboarding: s.skipped_onboarding,
        launch_at_login: s.launch_at_login,
        agent_download_domains: s.agent_download_domains.clone(),
        auto_update: s.auto_update,
    })
}

#[tauri::command]
pub fn set_settings(app: AppHandle, patch: SettingsPatch) -> CmdResult<SettingsDto> {
    // ADR-006: the login-autostart toggle drives the plugin immediately.
    set_launch_at_login(&app, patch.launch_at_login)?;
    let services = app.state::<AppServices>();
    let mut store = services.store.lock().expect("store");
    let next = AppSettings {
        device_id: store.settings().device_id.clone(),
        device_name: patch.device_name,
        // URL/token changes apply on next engine start (the signaling
        // connection is engine-lifetime).
        signaling_base_url: patch.signaling_base_url.trim().to_owned(),
        default_quality: patch.default_quality,
        default_viewer_scale: patch.default_viewer_scale,
        device_token: store.settings().device_token.clone(),
        skipped_onboarding: patch.skipped_onboarding,
        launch_at_login: patch.launch_at_login,
        autostart_default_applied: store.settings().autostart_default_applied,
        // Assistant provider fields are managed via `agent_configure`,
        // not the settings patch — preserve them here.
        agent_base_url: store.settings().agent_base_url.clone(),
        agent_model: store.settings().agent_model.clone(),
        agent_download_domains: patch.agent_download_domains,
        auto_update: patch.auto_update,
    };
    store.update_settings(next)?;
    let s = store.settings().clone();
    Ok(SettingsDto {
        device_id: s.device_id,
        device_name: s.device_name,
        signaling_base_url: s.signaling_base_url,
        default_quality: s.default_quality,
        default_viewer_scale: s.default_viewer_scale,
        skipped_onboarding: s.skipped_onboarding,
        launch_at_login: s.launch_at_login,
        agent_download_domains: s.agent_download_domains.clone(),
        auto_update: s.auto_update,
    })
}

#[tauri::command]
pub fn list_favorites(app: AppHandle) -> CmdResult<Vec<FavoriteDto>> {
    let services = app.state::<AppServices>();
    let store = services.store.lock().expect("store");
    Ok(store
        .favorites()
        .iter()
        .map(|f| FavoriteDto {
            id: f.id.clone(),
            name: f.name.clone(),
            code: f.code.clone(),
        })
        .collect())
}

#[tauri::command]
pub fn add_favorite(app: AppHandle, args: AddFavoriteArgs) -> CmdResult<FavoriteDto> {
    let services = app.state::<AppServices>();
    let mut store = services.store.lock().expect("store");
    let favorite = store.add_favorite(&args.name, &args.code)?;
    Ok(FavoriteDto {
        id: favorite.id,
        name: favorite.name,
        code: favorite.code,
    })
}

#[tauri::command]
pub fn remove_favorite(app: AppHandle, args: RemoveFavoriteArgs) -> CmdResult<Vec<FavoriteDto>> {
    let services = app.state::<AppServices>();
    let mut store = services.store.lock().expect("store");
    store.remove_favorite(&args.id)?;
    Ok(store
        .favorites()
        .iter()
        .map(|f| FavoriteDto {
            id: f.id.clone(),
            name: f.name.clone(),
            code: f.code.clone(),
        })
        .collect())
}

#[tauri::command]
pub fn rename_favorite(app: AppHandle, args: RenameFavoriteArgs) -> CmdResult<FavoriteDto> {
    let services = app.state::<AppServices>();
    let mut store = services.store.lock().expect("store");
    let favorite = store.rename_favorite(&args.id, &args.name)?;
    Ok(FavoriteDto {
        id: favorite.id,
        name: favorite.name,
        code: favorite.code,
    })
}

// ---------------------------------------------------------------------------
// Account / computers (post-MVP accounts; works with the engine stopped —
// only "Add this computer" starts host mode, from the UI side)
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn account_state(app: AppHandle) -> CmdResult<AccountStateDto> {
    let services = app.state::<AppServices>();
    let store = services.store.lock().expect("store");
    let mut account = services.account.lock().expect("account");
    // One-time startup session validation, run here (a Tauri worker
    // thread) instead of the setup hook so a blackholed network cannot
    // delay the window (security review P3 availability).
    if !account.restored {
        account.restored = true;
        let _ = account.restore(&store);
    }
    Ok(account.status(&store).into())
}

#[tauri::command]
pub fn account_register(
    app: AppHandle,
    args: AccountCredentialsArgs,
) -> CmdResult<AccountStateDto> {
    with_account(&app, |store, account| {
        // `normalize_display_name` gives the friendly empty-name message.
        let name = args.display_name.clone().unwrap_or_default();
        account.register(store, &args.username, &name, &args.password)?;
        Ok(account.status(store).into())
    })
}

#[tauri::command]
pub fn account_login(app: AppHandle, args: AccountCredentialsArgs) -> CmdResult<AccountStateDto> {
    with_account(&app, |store, account| {
        account.login(store, &args.username, &args.password)?;
        Ok(account.status(store).into())
    })
}

/// ADR-007: set or update the signed-in account's display name (the name
/// hosts see on control requests; also the unlock for legacy name-less
/// accounts that want to control machines).
#[tauri::command]
pub fn account_set_name(app: AppHandle, args: AccountNameArgs) -> CmdResult<AccountStateDto> {
    with_account(&app, |store, account| {
        account.set_display_name(store, &args.display_name)?;
        Ok(account.status(store).into())
    })
}

#[tauri::command]
pub fn account_unlock(app: AppHandle, args: AccountPasswordArgs) -> CmdResult<AccountStateDto> {
    with_account(&app, |store, account| {
        account.unlock(store, &args.password)?;
        Ok(account.status(store).into())
    })
}

#[tauri::command]
pub fn account_logout(app: AppHandle) -> CmdResult<AccountStateDto> {
    let services = app.state::<AppServices>();
    let store = services.store.lock().expect("store");
    let mut account = services.account.lock().expect("account");
    Ok(account.logout(&store).into())
}

#[tauri::command]
pub fn computers_list(app: AppHandle) -> CmdResult<ComputersListDto> {
    with_account(&app, |store, account| {
        let device_id = store.settings().device_id.clone();
        Ok(account.computers(&device_id)?.into())
    })
}

#[tauri::command]
pub fn computer_add(app: AppHandle, args: ComputerAddArgs) -> CmdResult<ComputersListDto> {
    with_account(&app, |store, account| {
        let device_id = store.settings().device_id.clone();
        Ok(account
            .add_computer(store, &device_id, &args.name, &args.code)?
            .into())
    })
}

#[tauri::command]
pub fn computer_add_this(app: AppHandle) -> CmdResult<ComputersListDto> {
    with_account(&app, |store, account| {
        let device_id = store.settings().device_id.clone();
        let name = display_name(store.settings());
        Ok(account.add_this_computer(store, &device_id, &name)?.into())
    })
}

#[tauri::command]
pub fn computer_remove(app: AppHandle, args: ComputerIdArgs) -> CmdResult<ComputersListDto> {
    with_account(&app, |store, account| {
        let device_id = store.settings().device_id.clone();
        Ok(account.remove_computer(store, &device_id, &args.id)?.into())
    })
}

#[tauri::command]
pub fn computer_rename(app: AppHandle, args: ComputerRenameArgs) -> CmdResult<ComputersListDto> {
    with_account(&app, |store, account| {
        let device_id = store.settings().device_id.clone();
        Ok(account
            .rename_computer(store, &device_id, &args.id, &args.name)?
            .into())
    })
}

#[tauri::command]
pub fn computers_presence(app: AppHandle) -> CmdResult<PresenceDto> {
    with_account(&app, |_store, account| {
        Ok(PresenceDto {
            online: account.presence()?,
        })
    })
}

// ---------------------------------------------------------------------------
// Engine commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn engine_status(app: AppHandle) -> CmdResult<EngineStatusDto> {
    // Self-heal (2026-10-28): the UI polls status every few seconds — a
    // dead engine (panic) is respawned here instead of erroring "engine
    // stopped" at the user forever.
    {
        let dead = app
            .state::<AppServices>()
            .engine
            .lock()
            .expect("engine slot")
            .as_ref()
            .is_some_and(|h| !h.is_alive());
        if dead {
            let _ = start_engine(&app);
        }
    }
    with_engine(&app, |handle| Ok(handle.status().into()))
}

#[tauri::command]
pub fn host_start(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::HostStart))
}

#[tauri::command]
pub fn host_stop(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::HostStop))
}

#[tauri::command]
pub fn controller_start(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::ControllerStart))
}

#[tauri::command]
pub fn controller_stop(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::ControllerStop))
}

/// Shut the engine down cleanly (an in-flight host session tells the
/// peer before the process dies), then exit. The File → Quit command and
/// the updater's install step share this path.
pub fn shutdown_and_exit(app: &AppHandle) {
    if let Some(services) = app.try_state::<AppServices>()
        && let Some(mut engine) = services.engine.lock().expect("engine slot").take()
    {
        engine.shutdown();
    }
    app.exit(0);
}

/// File → Quit: the same shutdown path as the tray's Quit item (engine
/// down, then process exit). Keeping the engine shutdown explicit means an
/// in-flight host session tells the peer before the process dies.
#[tauri::command]
pub fn quit_app(app: AppHandle) {
    shutdown_and_exit(&app);
}

#[tauri::command]
pub fn connect(app: AppHandle, args: ConnectArgs) -> CmdResult<()> {
    let code = args.code.trim().to_owned();
    if code.is_empty() {
        return Err("Enter the host machine's connection code.".into());
    }
    // ADR-007 control gate: the connect_request carries the account's
    // display name so the host's prompt says who is asking. Anonymous
    // users can host and be controlled, but not control — the marker
    // error opens the sign-in / add-name card instead of a raw error.
    let requester_name = {
        let services = app.state::<AppServices>();
        let account = services.account.lock().expect("account");
        account.control_identity().map_err(|gate| gate.message())?
    };
    // ADR-006: attach the pairing secret (when one is held with this host)
    // so the engine stamps the single-use pairing proof on the
    // connect_request — silent paired accept must prove the secret, not
    // just claim the (claimable) device id.
    let pairing_secret =
        crate::chat::pairing_for(&app, &code).map(|p| crate::chat::PairingSecret(p.secret_hex));
    // ADR-006 amendment (2026-10-28): this connect owes the session an
    // outbound pairing offer — consumed at establishment to send it from
    // the CONTROLLER side only (see SessionEstablished).
    {
        let services = app.state::<AppServices>();
        services.trust.lock().expect("trust state").owed_pair_offer =
            Some(crate::store::normalize_machine_code(&code));
    }
    with_engine(&app, |handle| {
        handle.send(EngineCmd::Connect {
            code,
            pairing_secret,
            requester_name: Some(requester_name),
        })
    })
}

#[tauri::command]
pub fn cancel_connect(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::CancelConnect))
}

#[tauri::command]
pub fn disconnect(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::Disconnect))
}

#[tauri::command]
pub fn consent_accept(app: AppHandle, remember: bool) -> CmdResult<()> {
    with_engine(&app, |handle| {
        handle.send(EngineCmd::ConsentAccept { remember })
    })
}

#[tauri::command]
pub fn consent_reject(app: AppHandle) -> CmdResult<()> {
    // ADR-006 B3: an explicit reject puts the controller in cooldown —
    // repeat prompts from it are auto-rejected for REJECT_COOLDOWN_MS.
    let declined = {
        let services = app.state::<AppServices>();
        let mut trust = services.trust.lock().expect("trust state");
        let controller = trust.prompt.as_ref().map(|(c, _, _)| c.clone());
        if let Some(controller) = controller.as_deref() {
            if let Some((_, _, rejected)) = trust.prompt.as_mut() {
                *rejected = true;
            }
            let now = crate::chat::now_ms();
            trust.block(controller, now + crate::chat::REJECT_COOLDOWN_MS);
        }
        trust.decision = None;
        controller
    };
    // ADR-006 amendment (2026-10-28): Decline is the explicit un-trust —
    // it also revokes any standing "Always allow" intent for this machine.
    if let Some(controller) = declined {
        crate::chat::revoke_intent(&app, &controller);
    }
    with_engine(&app, |handle| handle.send(EngineCmd::ConsentReject))
}

#[tauri::command]
pub fn set_quality(app: AppHandle, args: SetQualityArgs) -> CmdResult<()> {
    let Some(preset) = preset_from_name(&args.preset) else {
        return Err(format!("unknown quality preset {:?}", args.preset));
    };
    with_engine(&app, |handle| handle.send(EngineCmd::SetQuality(preset)))
}

#[tauri::command]
pub fn select_monitor(app: AppHandle, args: SelectMonitorArgs) -> CmdResult<()> {
    with_engine(&app, |handle| {
        handle.send(EngineCmd::SelectMonitor {
            monitor_id: args.monitor_id,
        })
    })
}

#[tauri::command]
pub fn viewer_set_scale(app: AppHandle, scale: String) -> CmdResult<()> {
    let Some(mode) = scale_from_name(&scale) else {
        return Err(format!("unknown scale mode {scale:?}"));
    };
    with_engine(&app, |handle| handle.send(EngineCmd::ViewerScale(mode)))
}

#[tauri::command]
pub fn viewer_toggle_fullscreen(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::ViewerFullscreen))
}

#[tauri::command]
pub fn list_monitors(app: AppHandle) -> CmdResult<serde_json::Value> {
    with_engine(&app, |handle| {
        let status = handle.status();
        Ok(serde_json::json!({
            "host": status.host_monitors,
            "peer": status.peer_monitors,
        }))
    })
}

// -- machine chat + pairing (ADR-005, RD-022/RD-023) -----------------------

#[derive(serde::Deserialize)]
pub struct ChatSendArgs {
    pub code: String,
    pub text: String,
    /// True when the message addresses the peer machine's assistant (the
    /// Conversation pane's "their assistant" toggle). Sets the wire's
    /// agent bit so the peer wakes its assistant as an instruction turn.
    /// The local assistant has its own path (`agent::tools`) and never
    /// calls this command.
    #[serde(default)]
    pub agent: bool,
}

/// Send one chat message to a machine: in-session over the direct `chat`
/// channel, otherwise sealed through the signaling inbox.
#[tauri::command]
pub fn chat_send(app: AppHandle, args: ChatSendArgs) -> CmdResult<()> {
    let code = args.code.trim().to_lowercase();
    let text = args.text.trim();
    if text.is_empty() {
        return Err("empty message".to_owned());
    }
    // Local perspective: the human typed it, addressed to the peer's
    // assistant ("to-agent" renders as "you → their assistant"). The
    // local assistant authoring a message records "agent" on its own path.
    let sender = if args.agent { "to-agent" } else { "user" };
    crate::chat::record_outgoing(&app, &code, sender, text);
    let (in_session, base_url, token, me) = {
        let services = app.state::<AppServices>();
        let store = services.store.lock().expect("store");
        let in_session = services
            .engine
            .lock()
            .expect("engine slot")
            .as_ref()
            .is_some_and(|handle| {
                let s = handle.status();
                s.controller_state == "Connected" && s.session_id.is_some()
                    || s.host_state == "Connected"
            });
        let settings = store.settings().clone();
        (
            in_session,
            settings.signaling_base_url,
            settings.device_token,
            settings.device_id,
        )
    };
    if in_session {
        return with_engine(&app, |handle| {
            handle
                .send(EngineCmd::ChatSend {
                    body: text.to_owned(),
                    agent: args.agent,
                })
                .map_err(|e| e.to_string())
        });
    }
    // The inbox envelope carries no agent bit (v1): an agent-addressed
    // send would silently land as a plain message and never wake the
    // peer's assistant. Refuse rather than mislead.
    if args.agent {
        return Err(
            "their assistant only answers during a session — connect to that machine first"
                .to_owned(),
        );
    }
    crate::chat::inbox_send(&app, &base_url, &token, &me, &code, text)
}

/// Chat history with one machine.
#[tauri::command]
pub fn chat_history(app: AppHandle, code: String) -> CmdResult<Vec<crate::chat::ChatLine>> {
    Ok(crate::chat::history(&app, &code.trim().to_lowercase()))
}

/// Established pairings (trusted machines: silent reconnect + chat keys).
#[tauri::command]
pub fn pairings_list(app: AppHandle) -> CmdResult<Vec<PairingDto>> {
    Ok(crate::chat::pairings(&app)
        .into_iter()
        .map(PairingDto::from)
        .collect())
}

/// Redacted pairing row for the webview (ADR-006): the shared secret never
/// crosses the IPC boundary (invariant-6 discipline).
#[derive(Debug, Clone, serde::Serialize)]
pub struct PairingDto {
    pub code: String,
    pub created_ms: u64,
    pub pending_ack: bool,
    pub role: String,
}

impl From<crate::chat::Pairing> for PairingDto {
    fn from(p: crate::chat::Pairing) -> Self {
        Self {
            code: p.code,
            created_ms: p.created_ms,
            pending_ack: p.pending_ack,
            role: p.role,
        }
    }
}

/// Revoke a pairing: future connects prompt for consent again.
#[tauri::command]
pub fn pairing_remove(app: AppHandle, code: String) -> CmdResult<()> {
    crate::chat::remove_pairing(&app, &code);
    Ok(())
}

// ---------------------------------------------------------------------------
// Family circle / machine directory (ADR-006)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub struct CircleStatusDto {
    pub joined: bool,
    pub circle_id: Option<String>,
    pub share_in_circle: bool,
    pub family_build: bool,
    pub machines: Vec<crate::directory::DirectoryMachineDto>,
    pub loaded: bool,
}

#[tauri::command]
pub fn circle_status(app: AppHandle) -> CmdResult<CircleStatusDto> {
    let doc = crate::directory::read_circle(&app);
    let loaded = {
        let services = app.state::<AppServices>();
        services.directory.lock().expect("directory cache").loaded
    };
    Ok(CircleStatusDto {
        joined: doc.is_some(),
        circle_id: doc.as_ref().map(|d| d.circle_id.clone()),
        share_in_circle: doc.as_ref().is_some_and(|d| d.share_in_circle),
        family_build: doc.as_ref().is_some_and(|d| d.family_build),
        machines: crate::directory::machines(&app),
        loaded,
    })
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct CircleJoinArgs {
    pub invite: String,
}

#[tauri::command]
pub fn circle_join(app: AppHandle, args: CircleJoinArgs) -> CmdResult<CircleStatusDto> {
    crate::directory::join(&app, args.invite.trim(), false)?;
    let _ = crate::directory::put_entry(&app); // presence may lag; poller retries
    let _ = crate::directory::refresh(&app);
    circle_status(app)
}

#[tauri::command]
pub fn circle_create(app: AppHandle) -> CmdResult<CircleStatusDto> {
    // The invite is returned once through the pairing DTO — the key lives
    // in the Credential Manager; `circle_invite` re-exposes it on demand.
    crate::directory::create(&app)?;
    circle_status(app)
}

#[tauri::command]
pub fn circle_invite(app: AppHandle) -> CmdResult<String> {
    crate::directory::invite(&app)
}

#[tauri::command]
pub fn circle_leave(app: AppHandle) -> CmdResult<CircleStatusDto> {
    crate::directory::leave(&app)?;
    circle_status(app)
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct CircleShareArgs {
    pub share: bool,
}

#[tauri::command]
pub fn circle_set_shared(app: AppHandle, args: CircleShareArgs) -> CmdResult<CircleStatusDto> {
    crate::directory::set_shared(&app, args.share)?;
    circle_status(app)
}

#[tauri::command]
pub fn directory_refresh(app: AppHandle) -> CmdResult<Vec<crate::directory::DirectoryMachineDto>> {
    crate::directory::refresh(&app)?;
    Ok(crate::directory::machines(&app))
}

// ---------------------------------------------------------------------------
// Automatic updates (ADR-008)
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn update_state(app: AppHandle) -> CmdResult<crate::updater::UpdateUiState> {
    Ok(app.state::<AppServices>().update.state())
}

/// Help → Check for updates: force a check now (the automatic-toggle off
/// only silences the scheduled checks, never an explicit one). No-op
/// while an update is already downloading/staged/installed — a re-check
/// must not clobber that.
#[tauri::command]
pub fn update_check(app: AppHandle) -> CmdResult<()> {
    let services = app.state::<AppServices>();
    services.update.force_check_now(&app);
    Ok(())
}

/// Download the offered installer and verify it (ADR-008: the user
/// pressed Update; installing stays a second, deliberate press).
#[tauri::command]
pub fn update_download(app: AppHandle) -> CmdResult<()> {
    crate::updater::start_download(app)
}

/// Run the verified installer: silent NSIS, app restarts via the
/// detached wrapper. Refuses during a live remote session.
#[tauri::command]
pub fn update_install(app: AppHandle) -> CmdResult<()> {
    crate::updater::install(app)
}

/// "Later": quiet for this version until the app restarts.
#[tauri::command]
pub fn update_dismiss(app: AppHandle) -> CmdResult<()> {
    app.state::<AppServices>().update.dismiss(&app);
    Ok(())
}

// ---------------------------------------------------------------------------
// Login autostart (ADR-006 always-ready)
// ---------------------------------------------------------------------------

fn set_launch_at_login(app: &AppHandle, enabled: bool) -> CmdResult<()> {
    use tauri_plugin_autostart::ManagerExt;
    let autolaunch = app.autolaunch();
    let result = if enabled {
        autolaunch.enable()
    } else {
        autolaunch.disable()
    };
    // The plugin can fail on exotic setups — surface it but never block
    // saving the rest of the settings.
    if let Err(err) = result {
        eprintln!(
            "[autostart] {} failed: {err}",
            if enabled { "enable" } else { "disable" }
        );
    }
    Ok(())
}

/// One-time family-build default: the embedded-key first run turns login
/// autostart on once (ADR-006: family machines are reachable at login).
pub fn enable_autostart_default(app: &AppHandle) {
    let services = app.state::<AppServices>();
    let (already, applied) = {
        let store = services.store.lock().expect("store");
        (
            store.settings().launch_at_login,
            store.settings().autostart_default_applied,
        )
    };
    if already || applied {
        return;
    }
    let _ = set_launch_at_login(app, true);
    if let Ok(mut store) = services.store.lock() {
        let mut next = store.settings().clone();
        next.launch_at_login = true;
        next.autostart_default_applied = true;
        let _ = store.update_settings(next);
    }
}
