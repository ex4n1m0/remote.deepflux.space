//! Family-circle directory client (ADR-006): circle membership, the
//! machine-list poller, and the consent-prompt nickname lookup.
//!
//! Local state:
//! * `circle.json` (app data dir) — `{v, circle_id, joined_ms,
//!   share_in_circle, family_build}`; NO key material (invariant-6 class).
//! * the circle key (the invite) — Windows Credential Manager via the
//!   [`crate::credstore::SessionStore`] seam, synthetic user `circle-key`.
//! * an in-memory cache of the decrypted directory (single-flight,
//!   latest-wins — never queue-shaped, invariant 3).
//!
//! Server state is the sealed directory on `/api/directory` (see
//! `node_runtime::directory_remote`). The poller (30 s) keeps the cache
//! fresh while the engine is online and re-registers this machine's entry
//! on launch, on display-name change, and every 6 h (TTL refresh — entries
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

/// Embedded circle key (family build only; empty in the public build —
/// `build.rs` refuses an embedded key without DEEPFLUX_FAMILY_BUILD=1).
const EMBEDDED_CIRCLE_KEY: &str = include_str!(concat!(env!("OUT_DIR"), "/circle_key.txt"));

// ---------------------------------------------------------------------------
// circle.json
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CircleDoc {
    pub v: u16,
    pub circle_id: String,
    pub joined_ms: u64,
    /// Whether this machine appears in the circle directory (the Settings
    /// toggle; the first-run banner is the consent moment).
    pub share_in_circle: bool,
    /// True when the circle came from the embedded family-build key.
    pub family_build: bool,
}

fn circle_path(app: &AppHandle) -> PathBuf {
    app.path()
        .app_data_dir()
        .expect("app data dir")
        .join("circle.json")
}

pub fn read_circle(app: &AppHandle) -> Option<CircleDoc> {
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

fn clear_circle(app: &AppHandle) {
    let _ = std::fs::remove_file(circle_path(app));
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

fn clear_key() {
    let _ = crate::credstore::WindowsCredStore.clear(KEY_USER);
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

/// Consent-prompt nickname lookup (ADR-006: prompt shows the nickname with
/// the device code always beside it — the code is the unforgeable part).
pub fn nickname_for(app: &AppHandle, code: &str) -> Option<String> {
    let services = app.state::<crate::commands::AppServices>();
    let cache = services.directory.lock().expect("directory cache");
    cache
        .entries
        .iter()
        .find(|e| e.device == code)
        .map(|e| e.name.clone())
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
}

fn circle_ctx(app: &AppHandle) -> Option<CircleCtx> {
    let doc = read_circle(app)?;
    let key = load_key(app)?;
    let services = app.state::<crate::commands::AppServices>();
    let (device, token, name, base) = {
        let store = services.store.lock().expect("store");
        let s = store.settings();
        (
            s.device_id.clone(),
            s.device_token.clone(),
            // The directory nickname must be 1-64 chars — resolve the
            // "empty = OS hostname" display-name fallback the same way
            // get_identity does, or the put would be refused forever.
            crate::commands::display_name(s),
            s.signaling_base_url.clone(),
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
    })
}

/// Register/refresh this machine's sealed entry. Requires live presence
/// (the service authenticates the (device, token) pair) — callers retry.
pub fn put_entry(app: &AppHandle) -> Result<(), String> {
    let Some(ctx) = circle_ctx(app) else {
        return Ok(()); // not joined / not configured — nothing to do
    };
    if !ctx.doc.share_in_circle {
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

/// Remove this machine's entry (share toggle off / leave circle).
pub fn remove_entry(app: &AppHandle) -> Result<(), String> {
    let Some(ctx) = circle_ctx(app) else {
        return Ok(());
    };
    if !ctx.doc.share_in_circle {
        return Ok(());
    }
    ctx.client
        .remove(&ctx.doc.circle_id, &ctx.device, &ctx.token)
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Membership commands (join / leave / create)
// ---------------------------------------------------------------------------

pub fn join(app: &AppHandle, invite: &str, family_build: bool) -> Result<CircleDoc, String> {
    if read_circle(app).is_some() {
        return Err("Already in a circle (leave it first).".to_owned());
    }
    let key = CircleKey::parse(invite).map_err(|e| e.to_string())?;
    save_key(&key)?;
    let doc = CircleDoc {
        v: 1,
        circle_id: circle_id_from_key(&key),
        joined_ms: now_ms(),
        share_in_circle: true,
        family_build,
    };
    write_circle(app, &doc);
    Ok(doc)
}

pub fn create(app: &AppHandle) -> Result<String, String> {
    if read_circle(app).is_some() {
        return Err("Already in a circle (leave it first).".to_owned());
    }
    let key = CircleKey::generate();
    save_key(&key)?;
    let doc = CircleDoc {
        v: 1,
        circle_id: circle_id_from_key(&key),
        joined_ms: now_ms(),
        share_in_circle: true,
        family_build: false,
    };
    write_circle(app, &doc);
    Ok(key.invite_hex().to_owned())
}

pub fn leave(app: &AppHandle) -> Result<(), String> {
    let _ = remove_entry(app); // best-effort server cleanup
    clear_circle(app);
    clear_key();
    {
        let services = app.state::<crate::commands::AppServices>();
        let mut cache = services.directory.lock().expect("directory cache");
        cache.entries.clear();
        cache.loaded = false;
    }
    emit_directory(app);
    Ok(())
}

pub fn set_shared(app: &AppHandle, share: bool) -> Result<(), String> {
    let Some(mut doc) = read_circle(app) else {
        return Err("Not in a circle.".to_owned());
    };
    doc.share_in_circle = share;
    write_circle(app, &doc);
    if share {
        put_entry(app)?; // requires online presence; the poller retries
    } else {
        let _ = remove_entry(app);
    }
    Ok(())
}

/// The current invite code (display/copy in Settings — the user's own key).
pub fn invite(app: &AppHandle) -> Result<String, String> {
    if read_circle(app).is_none() {
        return Err("Not in a circle.".to_owned());
    }
    load_key(app)
        .map(|k| k.invite_hex().to_owned())
        .ok_or_else(|| "Circle key missing from the credential store.".to_owned())
}

/// Family-build first run: auto-join from the embedded key. The embedded
/// installer IS the consent moment for sharing (the first-run banner in
/// the UI explains it and Settings can revoke).
pub fn auto_join_embedded(app: &AppHandle) -> bool {
    let embedded = EMBEDDED_CIRCLE_KEY.trim();
    if embedded.is_empty() || read_circle(app).is_some() {
        return false;
    }
    match join(app, embedded, true) {
        Ok(_) => true,
        Err(err) => {
            eprintln!("[directory] embedded auto-join failed: {err}");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Poller (single thread, latest-wins cache)
// ---------------------------------------------------------------------------

pub fn spawn_poller(app: AppHandle) {
    std::thread::Builder::new()
        .name("directory-poller".into())
        .spawn(move || {
            loop {
                std::thread::sleep(POLL_PERIOD);
                let Some(doc) = read_circle(&app) else {
                    continue;
                };
                let services = app.state::<crate::commands::AppServices>();
                let engine_online = services
                    .engine
                    .lock()
                    .map(|slot| slot.is_some())
                    .unwrap_or(false);
                let (name, put_due) = {
                    let cache = services.directory.lock().expect("directory cache");
                    let store = services.store.lock().expect("store");
                    let name = store.settings().device_name.clone();
                    let due = engine_online
                        && doc.share_in_circle
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
