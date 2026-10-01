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
}

pub struct AppServices {
    pub store: Mutex<LocalStore>,
    pub engine: Mutex<Option<EngineHandle>>,
    /// Account/roster state (post-MVP accounts). Lock order when both are
    /// held: store first, then account (see `with_account`).
    pub account: Mutex<crate::account::AccountManager>,
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
        return Err(
            "No account service configured. Open Settings and set the service URL first.".into(),
        );
    }
    f(&mut store, &mut account)
}

/// Create the engine thread (signaling connection + runtime). Idempotent.
#[tauri::command]
pub fn engine_start(app: AppHandle) -> CmdResult<EngineStatusDto> {
    {
        let services = app.state::<AppServices>();
        let guard = services.engine.lock().expect("engine slot");
        if let Some(handle) = guard.as_ref() {
            return Ok(handle.status().into());
        }
    }
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
    let (handle, events) = engine::spawn(cfg);
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
    let status = handle.status().into();
    *app.state::<AppServices>()
        .engine
        .lock()
        .expect("engine slot") = Some(handle);
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
        } => emit(
            events::STATE,
            Some(
                serde_json::json!({ "machine": machine, "state": state, "session_id": session_id }),
            ),
        ),
        EngineEvent::ConsentRequested {
            controller_device_id,
            session_id,
        } => emit(
            events::CONSENT,
            Some(serde_json::json!({
                "controller_device_id": controller_device_id,
                "session_id": session_id
            })),
        ),
        EngineEvent::SessionEstablished { session_id, peer } => emit(
            events::SESSION_ESTABLISHED,
            Some(serde_json::json!({ "session_id": session_id, "peer": peer })),
        ),
        EngineEvent::SessionEnded {
            cause,
            code,
            message,
            hint,
        } => emit(
            events::SESSION_ENDED,
            Some(
                serde_json::json!({ "cause": cause, "code": code, "message": message, "hint": hint }),
            ),
        ),
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
        } => emit(
            events::ERROR,
            Some(serde_json::json!({ "code": code, "message": message, "hint": hint })),
        ),
        EngineEvent::Info { message } => emit(
            events::INFO,
            Some(serde_json::json!({ "message": message })),
        ),
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

fn display_name(settings: &AppSettings) -> String {
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
    })
}

#[tauri::command]
pub fn set_settings(app: AppHandle, patch: SettingsPatch) -> CmdResult<SettingsDto> {
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
        account.register(store, &args.username, &args.password)?;
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

#[tauri::command]
pub fn connect(app: AppHandle, args: ConnectArgs) -> CmdResult<()> {
    let code = args.code.trim().to_owned();
    if code.is_empty() {
        return Err("Enter the host machine's connection code.".into());
    }
    with_engine(&app, |handle| handle.send(EngineCmd::Connect { code }))
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
pub fn consent_accept(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::ConsentAccept))
}

#[tauri::command]
pub fn consent_reject(app: AppHandle) -> CmdResult<()> {
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
