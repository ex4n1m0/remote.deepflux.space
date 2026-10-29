//! Tauri 2 product shell (M4, RD-011/RD-012): a thin veneer over the
//! engine. The webview window you are looking through is the CONTROL
//! surface only; video lives in the native viewer window owned by the
//! engine's controller pipeline (AGENTS.md invariant 1).

pub mod agent;
pub mod chat;
pub mod commands;
pub mod credstore;
mod directory;
pub mod dl;
pub mod engine;
pub mod ipc;
pub mod mcp;
pub mod store;
pub mod updater;

use std::sync::Mutex;

use tauri::Manager;

use commands::AppServices;

pub fn run() {
    // ADR-004 (RD-018): `--mcp` runs the stdio MCP bridge alongside the
    // shell, auto-starts the engine, and advertises `AI_SESSION` so the
    // host consent prompt distinguishes the agent.
    let mcp_mode = std::env::args().any(|arg| arg == "--mcp");
    engine::set_mcp_mode(mcp_mode);
    // ADR-006: single instance (login autostart + manual launch must not
    // double-run), then the tray (close-to-tray keeps always-ready hosts
    // reachable), then login autostart.
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // A second launch focuses the existing window instead.
            if let Some(window) = app.get_webview_window("shell") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(|app| {
            // Persisted panic log (2026-10-28 "engine stopped" incident):
            // a GUI-subsystem process has no stderr, so a thread panic —
            // e.g. the engine thread dying mid-session — vanished without
            // a trace. Every panic now lands in the log dir with a
            // timestamp, thread name and backtrace; write failures are
            // swallowed (the hook must never panic itself).
            {
                let panic_dir = app
                    .path()
                    .app_log_dir()
                    .unwrap_or_else(|_| std::env::temp_dir());
                let _ = std::fs::create_dir_all(&panic_dir);
                let default_hook = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |info| {
                    let thread = std::thread::current();
                    let thread_name = thread.name().unwrap_or("<unnamed>").to_owned();
                    let backtrace = std::backtrace::Backtrace::force_capture().to_string();
                    let mut entry = format!(
                        "[{} ms] thread {thread_name} panicked at {info}\n",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis())
                            .unwrap_or(0)
                    );
                    // Backtraces in release builds are long address walls;
                    // keep the file bounded (8 KiB per entry).
                    if backtrace.len() > 8192 {
                        entry.push_str(&backtrace[..8192]);
                        entry.push_str("…\n");
                    } else {
                        entry.push_str(&backtrace);
                    }
                    entry.push('\n');
                    let path = panic_dir.join("panics.log");
                    use std::io::Write;
                    if let Ok(mut file) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                    {
                        let _ = file.write_all(entry.as_bytes());
                    }
                    default_hook(info);
                }));
            }
            let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
            let mut store = store::LocalStore::load(&dir).map_err(|e| e.to_string())?;
            // Durable identity anchor: mirror/restore this machine's
            // identity via the Credential Manager so a reinstall (wiped
            // appdata) keeps the same device id — one circle-directory
            // entry per machine, pairings survive reinstalls.
            store
                .adopt_identity_anchor(&crate::credstore::WindowsCredStore)
                .map_err(|e| e.to_string())?;
            app.manage(AppServices {
                store: Mutex::new(store),
                engine: Mutex::new(None),
                assistant: agent::AssistantState::new(),
                trust: Mutex::new(chat::TrustState::default()),
                directory: Mutex::new(directory::DirectoryCache::default()),
                update: updater::UpdateEngine::default(),
                update_manifest: Mutex::new(None),
            });
            // ADR-006: family build auto-joins from the embedded key; the
            // directory poller keeps the machine list fresh while online.
            let family_first_run = directory::auto_join_embedded(app.handle());
            directory::spawn_poller(app.handle().clone());
            if family_first_run {
                // The embedded key IS the consent moment for always-ready:
                // turn on login autostart once (reversible in Settings).
                commands::enable_autostart_default(app.handle());
            }
            // The assistant is live from app start (ADR-005): its worker
            // only calls the provider once a key is configured.
            app.state::<AppServices>()
                .assistant
                .spawn(app.handle().clone());
            // Machine-chat inbox poller (RD-022): out-of-session chat is
            // always available while the app runs. The purge first drops
            // pairing rows / chat threads keyed by a non-device-id code
            // (dead data from the pre-validation era) — one sweep per
            // launch, alongside the favorite purge in LocalStore::load.
            chat::purge_dead_data(app.handle());
            chat::spawn_poller(app.handle().clone());
            // ADR-008 update poller: first check ~20 s after launch (past
            // the engine's own startup), then daily; Help → Check for
            // updates forces one anytime.
            updater::spawn_poller(app.handle().clone());
            // Always-ready, both directions (0.6.3): the engine and the
            // controller role start at launch for everyone — controlling
            // out is one press (Control) with no enable step, and the
            // engine defers the connect itself while the role registers.
            // Host presence (being controllable) still follows the
            // circle-visibility choice; every untrusted session still
            // hits the consent prompt, trusted machines connect silently
            // per their pairing. Deferred a beat so the window paints
            // first.
            {
                let share_host =
                    directory::read_circle(app.handle()).is_some_and(|d| d.share_in_circle);
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    if commands::start_engine(&handle).is_ok() {
                        let services = handle.state::<AppServices>();
                        if let Ok(slot) = services.engine.lock()
                            && let Some(engine) = slot.as_ref()
                        {
                            let _ = engine.send(engine::EngineCmd::ControllerStart);
                            if share_host {
                                let _ = engine.send(engine::EngineCmd::HostStart);
                            }
                        }
                    }
                });
            }

            // ADR-006: tray icon with open/quit — close-to-tray keeps the
            // app running (and reachable) when the window closes.
            setup_tray(app.handle().clone())?;

            if engine::mcp_mode() {
                // The bridge is the front door in this mode: start the
                // engine without UI interaction (errors surface on the
                // bridge tools) and serve stdio.
                let handle = app.handle().clone();
                if let Err(err) = commands::start_engine(&handle) {
                    eprintln!("[mcp] engine auto-start failed: {err}");
                }
                mcp::spawn(handle);
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Close-to-tray (ADR-006): hide instead of exit while the tray
            // exists; quitting happens from the tray menu. The engine keeps
            // the machine reachable either way.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
                return;
            }
            if matches!(event, tauri::WindowEvent::Destroyed) {
                // Clean engine shutdown when the shell window closes
                // (pipelines, transports, input safety).
                if let Some(services) = window.app_handle().try_state::<AppServices>()
                    && let Some(mut engine) = services.engine.lock().expect("engine slot").take()
                {
                    engine.shutdown();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::engine_start,
            commands::engine_status,
            commands::get_identity,
            commands::get_settings,
            commands::set_settings,
            commands::list_favorites,
            commands::add_favorite,
            commands::remove_favorite,
            commands::rename_favorite,
            commands::host_start,
            commands::host_stop,
            commands::controller_start,
            commands::controller_stop,
            commands::quit_app,
            commands::connect,
            commands::cancel_connect,
            commands::disconnect,
            commands::consent_accept,
            commands::consent_reject,
            commands::set_quality,
            commands::select_monitor,
            commands::list_monitors,
            commands::viewer_set_scale,
            commands::viewer_toggle_fullscreen,
            commands::viewer_show,
            commands::viewer_hide,
            agent::agent_configure,
            agent::agent_status,
            agent::agent_send,
            agent::agent_confirm,
            agent::agent_reset,
            commands::chat_send,
            commands::chat_history,
            commands::pairings_list,
            commands::pairing_remove,
            commands::pairing_rename,
            commands::circle_status,
            commands::circle_join,
            commands::circle_create,
            commands::circle_invite,
            commands::circle_leave,
            commands::circle_set_shared,
            commands::directory_refresh,
            commands::update_state,
            commands::update_check,
            commands::update_download,
            commands::update_install,
            commands::update_dismiss,
        ])
        .run(tauri::generate_context!())
        .expect("tauri shell run");
}

// ---------------------------------------------------------------------------
// Tray (ADR-006 always-ready)
// ---------------------------------------------------------------------------

fn setup_tray(app: tauri::AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    let open = MenuItem::with_id(&app, "open", "Open DeepFlux", true, None::<&str>)?;
    let quit = MenuItem::with_id(&app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(&app, &[&open, &quit])?;
    let tray = tauri::tray::TrayIconBuilder::with_id("main")
        .icon(app.default_window_icon().cloned().expect("app icon"))
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => {
                if let Some(window) = app.get_webview_window("shell") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "quit" => {
                if let Some(services) = app.try_state::<AppServices>()
                    && let Some(mut engine) = services.engine.lock().expect("engine slot").take()
                {
                    engine.shutdown();
                }
                app.exit(0);
            }
            _ => {}
        })
        .build(&app)?;
    tray.set_tooltip(Some("DeepFlux — family circle host"))?;
    Ok(())
}
