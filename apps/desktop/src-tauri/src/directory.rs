//! Circle-directory client (ADR-006, restored 0.11.0 by ADR-010 after the
//! ADR-009 retirement): the discovery list — machines running the app
//! appear here automatically, sealed under the embedded circle key.
//!
//! ADR-010 keeps every ADR-009 simplification: no join/invite/create UI
//! (the family installer auto-joins from its embedded key — the one
//! installer IS the circle), no separate visibility toggle (the
//! `host_sharing` setting, default ON, gates both launch-time host
//! presence and whether this machine's directory entry is published),
//! and `pairings.json` remains the ONLY trust — a discovered row
//! connects through the ordinary consent prompt, and "Always allow"
//! makes it permanent exactly once (ADR-006 §3 durability).
//!
//! Local state:
//! * `circle.json` (app data dir) — `{v, circle_id, joined_ms,
//!   family_build}`; NO key material (invariant-6 class).
//! * the circle key (the invite) — Windows Credential Manager via the
//!   [`crate::credstore::SessionStore`] seam, synthetic user `circle-key`.
//! * an in-memory cache of the decrypted directory (single-flight,
//!   latest-wins — never queue-shaped, invariant 3).
//!
//! Server state is the sealed directory on `/api/directory` (see
//! `node_runtime::directory_remote`). The poller keeps the cache fresh
//! while the engine is online and re-registers this machine's entry on
//! launch, on display-name change, and every 6 h (TTL refresh — entries
//! self-expire after 30 days).

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};

use crate::credstore::SessionStore;
use node_runtime::directory_remote::{CircleEntry, CircleKey, DirectoryClient, circle_id_from_key};

/// Credential-manager synthetic user for the circle key.
const KEY_USER: &str = "circle-key";
/// Cache refresh cadence while online.
const POLL_PERIOD: Duration = Duration::from_secs(30);
/// Entry TTL refresh cadence (server TTL is 30 days).
const REPUT_PERIOD_MS: u64 = 6 * 60 * 60 * 1000;
/// Webview event channel (app-layer state, not engine state).
pub const DIRECTORY_EVENT: &str = "app://directory";

/// Embedded circle key (family build only; empty in a bare dev build —
/// `build.rs` refuses a non-empty embedded key without
/// DEEPFLUX_FAMILY_BUILD=1). An empty key means no directory: the rail
/// falls back to the connection-code box alone.
const EMBEDDED_CIRCLE_KEY: &str = include_str!(concat!(env!("OUT_DIR"), "/circle_key.txt"));

// ---------------------------------------------------------------------------
// circle.json
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CircleDoc {
    pub v: u16,
    pub circle_id: String,
    pub joined_ms: u64,
    /// True when the circle came from the embedded family-build key.
    pub family_build: bool,
}

fn circle_path(app: &AppHandle) -> PathBuf {
    app.path()
        .app_data_dir()
        .expect("app data dir")
        .join("circle.json")
}

fn read_circle(app: &AppHandle) -> Option<CircleDoc> {
    std::fs::read_to_string(circle_path(app))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
}

fn write_circle(app: &AppHandle, doc: &CircleDoc) {
    let path = circle_path(app);
    let tmp = path.with_extension("tmp");
    if let Ok(text) = serde_json::to_string(doc)
        && std::fs::write(&tmp, text).is_ok()
    {
        let _ = std::fs::rename(&tmp, &path);
    }
}

fn load_key(_app: &AppHandle) -> Option<CircleKey> {
    let store = crate::credstore::WindowsCredStore;
    match store.load(KEY_USER) {
        Ok(Some(hex)) => CircleKey::parse(&hex).ok(),
        _ => None,
    }
}

fn save_key(key: &CircleKey) -> Result<(), String> {
    crate::credstore::WindowsCredStore.save(KEY_USER, key.invite_hex())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Cache (single-flight, latest-wins)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct DirectoryCache {
    pub entries: Vec<CircleEntry>,
    pub loaded: bool,
    pub last_refresh_ms: u64,
    pub last_put_ms: u64,
    pub last_put_name: String,
}

/// One webview-facing machine row. `name` is the decrypted nickname.
#[derive(Debug, Clone, Serialize)]
pub struct DirectoryMachineDto {
    pub device: String,
    pub name: String,
    pub online: bool,
    pub refreshed_ms: u64,
    pub is_self: bool,
}

pub fn machines(app: &AppHandle) -> Vec<DirectoryMachineDto> {
    let services = app.state::<crate::commands::AppServices>();
    let cache = services.directory.lock().expect("directory cache");
    let self_device = {
        let store = services.store.lock().expect("store");
        store.settings().device_id.clone()
    };
    cache
        .entries
        .iter()
        .map(|e| DirectoryMachineDto {
            device: e.device.clone(),
            name: e.name.clone(),
            online: e.online,
            refreshed_ms: e.refreshed_ms,
            is_self: e.device == self_device,
        })
        .collect()
}

fn emit_directory(app: &AppHandle) {
    let _ = app.emit(
        DIRECTORY_EVENT,
        serde_json::json!({ "machines": machines(app) }),
    );
}

// ---------------------------------------------------------------------------
// Directory operations (put / list / remove)
// ---------------------------------------------------------------------------

struct CircleCtx {
    key: CircleKey,
    doc: CircleDoc,
    client: DirectoryClient,
    device: String,
    token: String,
    name: String,
    host_sharing: bool,
}

fn circle_ctx(app: &AppHandle) -> Option<CircleCtx> {
    let doc = read_circle(app)?;
    let key = load_key(app)?;
    let services = app.state::<crate::commands::AppServices>();
    let (device, token, name, base, host_sharing) = {
        let store = services.store.lock().expect("store");
        let s = store.settings();
        (
            s.device_id.clone(),
            s.device_token.clone(),
            // The directory nickname must be 1–64 chars — resolve the
            // "empty = OS hostname" display-name fallback the same way
            // get_identity does, or the put would be refused forever.
            crate::commands::display_name(s),
            s.signaling_base_url.clone(),
            s.host_sharing,
        )
    };
    if base.trim().is_empty() {
        return None;
    }
    Some(CircleCtx {
        client: DirectoryClient::new(&base),
        key,
        doc,
        device,
        token,
        name,
        host_sharing,
    })
}

/// Register/refresh this machine's sealed entry. Requires live presence
/// (the service authenticates the (device, token) pair) — callers retry.
/// ADR-010: `host_sharing` OFF means "hidden from the list" — no put.
pub fn put_entry(app: &AppHandle) -> Result<(), String> {
    let Some(ctx) = circle_ctx(app) else {
        return Ok(()); // not joined / not configured — nothing to do
    };
    if !ctx.host_sharing {
        return Ok(());
    }
    let refreshed = ctx
        .client
        .put(
            &ctx.key,
            &ctx.doc.circle_id,
            &ctx.device,
            &ctx.token,
            &ctx.name,
            ctx.doc.joined_ms,
        )
        .map_err(|e| e.to_string())?;
    let services = app.state::<crate::commands::AppServices>();
    let mut cache = services.directory.lock().expect("directory cache");
    cache.last_put_ms = refreshed;
    cache.last_put_name = ctx.name;
    Ok(())
}

/// Fetch + decrypt the directory into the cache (latest-wins) and notify
/// the webview. Errors are swallowed into `loaded=false` semantics — a
/// failed refresh never blanks a good cache (stale beats empty).
pub fn refresh(app: &AppHandle) -> Result<(), String> {
    let Some(ctx) = circle_ctx(app) else {
        let services = app.state::<crate::commands::AppServices>();
        services
            .directory
            .lock()
            .expect("directory cache")
            .entries
            .clear();
        emit_directory(app);
        return Ok(());
    };
    let entries = ctx
        .client
        .list(&ctx.key, &ctx.doc.circle_id, &ctx.device, &ctx.token)
        .map_err(|e| e.to_string())?;
    {
        let services = app.state::<crate::commands::AppServices>();
        let mut cache = services.directory.lock().expect("directory cache");
        cache.entries = entries;
        cache.loaded = true;
        cache.last_refresh_ms = now_ms();
    }
    emit_directory(app);
    Ok(())
}

/// Remove this machine's entry (host_sharing turned off — the only
/// "leave the list" path in the ADR-010 world).
pub fn remove_entry(app: &AppHandle) -> Result<(), String> {
    let Some(ctx) = circle_ctx(app) else {
        return Ok(());
    };
    ctx.client
        .remove(&ctx.doc.circle_id, &ctx.device, &ctx.token)
        .map_err(|e| e.to_string())
}

/// Visibility sync for the `host_sharing` setting flip: ON republishes
/// the entry (best-effort — the poller retries), OFF removes it. Reading
/// the list always continues either way.
pub fn sync_visibility(app: &AppHandle) {
    let sharing = app
        .state::<crate::commands::AppServices>()
        .store
        .lock()
        .map(|s| s.settings().host_sharing)
        .unwrap_or(true);
    if sharing {
        let _ = put_entry(app);
        let _ = refresh(app);
    } else {
        let _ = remove_entry(app);
    }
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

/// Family-build first run: auto-join from the embedded key. The embedded
/// installer IS the consent moment for being listed (Settings → host
/// sharing off removes the entry again).
///
/// The 0.9.x-era empty-URL self-heal that used to live here is NOT
/// restored: since 0.10.1 `LocalStore::load` heals a blank signaling URL
/// unconditionally — one healer, not two.
pub fn auto_join_embedded(app: &AppHandle) -> bool {
    let embedded = EMBEDDED_CIRCLE_KEY.trim();
    if embedded.is_empty() {
        return false;
    }
    if read_circle(app).is_some() {
        return false;
    }
    let key = match CircleKey::parse(embedded) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("[directory] embedded key is malformed: {err}");
            return false;
        }
    };
    if let Err(err) = save_key(&key) {
        eprintln!("[directory] embedded auto-join failed: {err}");
        return false;
    }
    let doc = CircleDoc {
        v: 1,
        circle_id: circle_id_from_key(&key),
        joined_ms: now_ms(),
        family_build: true,
    };
    write_circle(app, &doc);
    true
}

// ---------------------------------------------------------------------------
// Poller (single thread, latest-wins cache)
// ---------------------------------------------------------------------------

pub fn spawn_poller(app: AppHandle) {
    std::thread::Builder::new()
        .name("directory-poller".into())
        .spawn(move || {
            // First discovery should land well before the steady 30 s
            // cadence: two quick retries cover the engine's deferred
            // registration (~2 s + register), then the loop settles.
            let mut schedule = [5u64, 15].iter();
            loop {
                let delay = schedule
                    .next()
                    .map(|s| Duration::from_secs(*s))
                    .unwrap_or(POLL_PERIOD);
                std::thread::sleep(delay);
                if read_circle(&app).is_none() {
                    continue; // not in a circle — nothing to poll
                }
                let services = app.state::<crate::commands::AppServices>();
                let engine_online = services
                    .engine
                    .lock()
                    .map(|slot| slot.is_some())
                    .unwrap_or(false);
                let (name, put_due) = {
                    let cache = services.directory.lock().expect("directory cache");
                    let store = services.store.lock().expect("store");
                    // Resolve the hostname fallback BEFORE comparing —
                    // comparing the raw setting would re-put every tick
                    // on machines whose name comes from the OS.
                    let name = crate::commands::display_name(store.settings());
                    let due = engine_online
                        && store.settings().host_sharing
                        && (cache.last_put_ms == 0
                            || cache.last_put_name != name
                            || now_ms().saturating_sub(cache.last_put_ms) > REPUT_PERIOD_MS);
                    (name, due)
                };
                let _ = name;
                if put_due {
                    let _ = put_entry(&app); // 401 (offline) retries next tick
                }
                let _ = refresh(&app); // 401 while offline: stale beats empty
            }
        })
        .expect("spawn directory poller");
}
