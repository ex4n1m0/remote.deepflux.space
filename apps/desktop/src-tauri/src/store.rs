//! Local persistence. Small JSON files under the app data dir, written
//! atomically (tmp + rename), read defensively: a corrupt file logs-and-
//! defaults instead of failing startup.
//! post-MVP accounts phase adds `account.json` (key material, no secrets)
//! and `roster.json` (an AES-GCM-encrypted cache of the server-synced
//! computer list — plaintext roster data never touches disk). The session
//! token never appears here at all: it lives in the Windows Credential
//! Manager (`credstore.rs`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// App settings. The signaling base URL is a setting (M3 contract: the
/// deployed Vercel service when the user has one; the standalone dev
/// server for local use).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppSettings {
    /// Stable device identity (16 hex chars; generated on first run).
    pub device_id: String,
    /// Human label advertised in the shell. Empty = use the OS hostname.
    pub device_name: String,
    /// Signaling service base URL, e.g. `https://<project>.vercel.app`.
    /// Defaults to the deployed service; an explicit empty string is the
    /// documented opt-out (accounts phase default, 2026-10-01).
    pub signaling_base_url: String,
    /// Default quality preset name (wire tag: auto|low|balanced|high).
    pub default_quality: String,
    /// Default viewer scale (fit|one_to_one).
    pub default_viewer_scale: String,
    /// Presence-binding token for the signaling service (local secret;
    /// never logged, never synced).
    #[serde(default = "new_token")]
    pub device_token: String,
    /// ADR-006 always-ready: launch at Windows login (drives the autostart
    /// plugin; the family build turns it on once at first run).
    #[serde(default)]
    pub launch_at_login: bool,
    /// ADR-009: answer connection requests (host presence at launch).
    /// Replaces the circle visibility toggle; defaults ON — the consent
    /// prompt still gates every untrusted session.
    #[serde(default = "default_true")]
    pub host_sharing: bool,
    /// One-shot: the family-build autostart default has been applied —
    /// persisted so leave/rejoin never re-enables a login setting the
    /// user deliberately turned off.
    #[serde(default)]
    pub autostart_default_applied: bool,
    /// In-app assistant provider (ADR-005): any OpenAI-compatible base
    /// URL. Default DeepSeek. The API key is NOT here — it lives in the
    /// Windows Credential Manager (`agent-api-key` seam).
    #[serde(default = "default_agent_base_url")]
    pub agent_base_url: String,
    /// Assistant model id. Default vision-capable so screenshot tools work
    /// (`deepseek-flash`); text-only `deepseek-chat` is a settings option.
    #[serde(default = "default_agent_model")]
    pub agent_model: String,
    /// Domains the local user permanently allowed the assistant to
    /// download from (`download_file` asks once per new domain; "always
    /// allow" lands here). Empty = ask every time.
    #[serde(default)]
    pub agent_download_domains: Vec<String>,
    /// ADR-008 automatic updates: scheduled update checks (download and
    /// install are always explicit user presses). Existing settings files
    /// predate the field — defaults ON.
    #[serde(default = "default_true")]
    pub auto_update: bool,
}

/// Default assistant provider (ADR-005): DeepSeek, OpenAI-compatible.
pub const DEFAULT_AGENT_BASE_URL: &str = "https://api.deepseek.com/v1";

fn default_agent_base_url() -> String {
    DEFAULT_AGENT_BASE_URL.to_owned()
}

fn default_agent_model() -> String {
    "deepseek-flash".to_owned()
}

fn default_true() -> bool {
    true
}

/// Default signaling service (accounts phase): the deployed Vercel
/// control plane. Overridable in settings; empty = explicit opt-out.
pub const DEFAULT_SIGNALING_BASE_URL: &str = "https://signaling.deepflux.space";

fn new_token() -> String {
    node_runtime::signaling_remote::RemoteSignalingConfig::new_token()
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            device_id: crate::engine::ids::new_device_id(),
            device_name: String::new(),
            signaling_base_url: DEFAULT_SIGNALING_BASE_URL.to_owned(),
            default_quality: "balanced".to_owned(),
            default_viewer_scale: "fit".to_owned(),
            device_token: new_token(),
            launch_at_login: false,
            host_sharing: true,
            autostart_default_applied: false,
            agent_base_url: default_agent_base_url(),
            agent_model: default_agent_model(),
            agent_download_domains: Vec::new(),
            auto_update: true,
        }
    }
}

/// A machine's connection code IS its device id: 16 hex chars
/// (`engine::ids::new_device_id`). A saved code of any other shape (a
/// short or mistyped code, a pre-device-id leftover) can never be dialed,
/// paired, chatted with, or seen in presence — the engine and every store
/// key by device id. Such rows are dead data that shadows the same
/// machine's live circle-directory row (the duplicate-list bug,
/// 2026-10-27), so they are refused at entry and purged on load.
pub fn is_machine_code(code: &str) -> bool {
    let c = code.trim();
    c.len() == 16 && c.chars().all(|ch| ch.is_ascii_hexdigit())
}

/// Canonical stored form of a machine code: trimmed, lowercase (device
/// ids are minted lowercase; the roster paths already normalize this way).
pub fn normalize_machine_code(code: &str) -> String {
    code.trim().to_lowercase()
}

/// Credential-manager synthetic user for the durable identity anchor
/// (see [`LocalStore::adopt_identity_anchor`]).
const IDENTITY_ANCHOR_USER: &str = "machine-identity";

/// The identity mirror stored under [`IDENTITY_ANCHOR_USER`]. `Debug`
/// redacts the token (invariant-6 discipline — it is a bearer secret).
#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct AnchorDoc {
    v: u8,
    device_id: String,
    device_token: String,
}

impl core::fmt::Debug for AnchorDoc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AnchorDoc")
            .field("v", &self.v)
            .field("device_id", &self.device_id)
            .field("device_token", &"<redacted>")
            .finish()
    }
}

/// User-facing copy for a rejected code (the Add form and the roster add
/// path surface it as-is).
pub const BAD_CODE_COPY: &str = "That doesn't look like a connection code — it's the 16-character code shown on the other machine's \"This machine\" card (or in its Share prompt).";

const SETTINGS_FILE: &str = "settings.json";

/// Errors are strings: they cross IPC as user-facing copy.
pub type StoreResult<T> = Result<T, String>;

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> StoreResult<Option<T>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("read {}: {err}", path.display())),
    };
    match serde_json::from_slice(&bytes) {
        Ok(value) => Ok(Some(value)),
        // Corrupt file: log-and-default instead of failing startup (the
        // next save rewrites it atomically).
        Err(err) => {
            eprintln!("store: ignoring corrupt {}: {err}", path.display());
            Ok(None)
        }
    }
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> StoreResult<()> {
    let json = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, json.as_bytes())
        .map_err(|err| format!("write {}: {err}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|err| format!("rename {}: {err}", path.display()))
}

/// Local JSON store for settings.
pub struct LocalStore {
    dir: PathBuf,
    settings: AppSettings,
    /// True when this load minted an identity (no settings file / empty
    /// ids) — the app-startup [`LocalStore::adopt_identity_anchor`] uses
    /// it to restore a surviving identity instead.
    pub(crate) fresh_identity: bool,
}

impl LocalStore {
    /// Load (or initialize) the store under `dir` (the Tauri app data dir;
    /// a temp dir in tests).
    pub fn load(dir: &Path) -> StoreResult<Self> {
        std::fs::create_dir_all(dir).map_err(|err| format!("create {}: {err}", dir.display()))?;
        let settings_path = dir.join(SETTINGS_FILE);
        let had_settings = settings_path.exists();
        let mut settings = read_json::<AppSettings>(&settings_path)?.unwrap_or_default();
        // Empty-URL self-heal (0.5.1 one-time migration, made unconditional
        // in 0.10.1): an EMPTY signaling URL means the machine silently
        // never registers — every connect to it answers "not online". The
        // pre-0.5 "blank = opt-out" era is long gone and the 0.9.x family
        // build healed this at every launch; ADR-009 deleted that healing
        // with the circle code, so it lives here now. A CUSTOM URL (local
        // dev server, private deploy) is untouched — only blank heals.
        let mut healed_url = false;
        if settings.signaling_base_url.trim().is_empty() {
            settings.signaling_base_url = DEFAULT_SIGNALING_BASE_URL.to_owned();
            healed_url = true;
        }
        // Identity is never absent after first load. `default()` already
        // mints a random device_id/token, so the empty checks only catch
        // old files parsed without those keys — the missing-file case is
        // `!had_settings`. Either way the minted identity must be PERSISTED
        // here: until a settings change writes the file, every launch would
        // otherwise regenerate the connection code (pairings
        // key on it staying stable).
        let mut fresh_identity = !had_settings; // default() mints ids already
        if settings.device_id.trim().is_empty() {
            settings.device_id = crate::engine::ids::new_device_id();
            fresh_identity = true;
        }
        if settings.device_token.trim().is_empty() {
            settings.device_token = new_token();
            fresh_identity = true;
        }
        if fresh_identity || !had_settings || healed_url {
            write_json_atomic(&settings_path, &settings)?;
        }
        // ADR-009 cleanup: `account.json` / `roster.json` (accounts
        // phase) and `favorites.json` / `circle.json` (favorites + circle
        // phase) belong to retired systems — delete them instead of
        // orphaning them (the machine list is pairings.json, untouched).
        // ADR-009 cleanup: `account.json` / `roster.json` belong to the
        // retired accounts phase — delete them instead of orphaning them
        // (the trusted-host list is pairings.json, which is untouched).
        for legacy in [
            "account.json",
            "roster.json",
            "favorites.json",
            "circle.json",
        ] {
            let _ = std::fs::remove_file(dir.join(legacy));
        }
        Ok(Self {
            dir: dir.to_owned(),
            settings,
            fresh_identity,
        })
    }

    /// Durable identity anchor (2026-10-27 duplicate-directory incident):
    /// a machine's device id/token live in `settings.json` inside the app
    /// data dir, which a reinstall wipes — and a wiped identity means a
    /// NEW id, which registers a SECOND circle-directory entry for the
    /// same machine (the duplicate row every family member then sees).
    /// The Windows Credential Manager survives an appdata wipe, so the
    /// identity is mirrored there: a fresh install restores its old
    /// identity instead of minting a new one, keeping one directory entry
    /// per machine — and pairings/trust survive reinstalls too.
    ///
    /// Called once at app startup, right after [`LocalStore::load`]:
    /// - fresh identity (appdata was wiped) → adopt the anchor's
    ///   id/token when present, persisting them to settings.json;
    /// - no valid anchor → backfill it with the current identity (this
    ///   is how the existing fleet gets covered); an existing anchor is
    ///   NEVER overwritten — a settings folder cloned from another
    ///   machine must not destroy this machine's own anchor.
    pub fn adopt_identity_anchor(
        &mut self,
        creds: &dyn crate::credstore::SessionStore,
    ) -> StoreResult<()> {
        let anchored = creds
            .load(IDENTITY_ANCHOR_USER)
            .ok()
            .flatten()
            .and_then(|blob| serde_json::from_str::<AnchorDoc>(&blob).ok())
            .filter(|a| is_machine_code(&a.device_id) && !a.device_token.trim().is_empty());
        if self.fresh_identity
            && let Some(anchor) = &anchored
        {
            self.settings.device_id = anchor.device_id.clone();
            self.settings.device_token = anchor.device_token.clone();
            self.persist_settings()?;
        }
        if anchored.is_none() {
            let current = AnchorDoc {
                v: 1,
                device_id: self.settings.device_id.clone(),
                device_token: self.settings.device_token.clone(),
            };
            if let Ok(blob) = serde_json::to_string(&current) {
                let _ = creds.save(IDENTITY_ANCHOR_USER, &blob);
            }
        }
        Ok(())
    }

    fn persist_settings(&self) -> StoreResult<()> {
        write_json_atomic(&self.dir.join(SETTINGS_FILE), &self.settings)
    }

    pub fn settings(&self) -> &AppSettings {
        &self.settings
    }

    pub fn update_settings(&mut self, patch: AppSettings) -> StoreResult<()> {
        // Identity is immutable from the UI side (it would strand pairings
        // and signaling presence); the token rotates only on regeneration.
        let mut next = patch;
        next.device_id = self.settings.device_id.clone();
        next.device_token = self.settings.device_token.clone();
        self.settings = next.clone();
        write_json_atomic(&self.dir.join(SETTINGS_FILE), &next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credstore::{InMemorySessionStore, SessionStore as _};

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rd-m4-store-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn settings_persist_and_identity_is_stable() {
        let dir = temp_dir("settings");
        let mut store = LocalStore::load(&dir).unwrap();
        let id = store.settings().device_id.clone();
        assert_eq!(id.len(), 16);
        assert_eq!(
            store.settings().signaling_base_url,
            DEFAULT_SIGNALING_BASE_URL,
            "accounts-phase default service URL"
        );
        store
            .update_settings(AppSettings {
                signaling_base_url: "http://127.0.0.1:38013".into(),
                ..store.settings().clone()
            })
            .unwrap();
        let reloaded = LocalStore::load(&dir).unwrap();
        assert_eq!(reloaded.settings().device_id, id, "identity survives");
        assert_eq!(
            reloaded.settings().signaling_base_url,
            "http://127.0.0.1:38013"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn first_load_persists_identity_without_any_settings_change() {
        // Regression (0.4.3): `unwrap_or_default()` mints a random device_id
        // in memory, so the old empty-check never fired and settings.json
        // was not written until a manual settings change — every launch
        // minted a NEW connection code and device token, silently breaking
        // saved machines and pairing across restarts.
        let dir = temp_dir("first-load-identity");
        let first = LocalStore::load(&dir).unwrap();
        assert!(
            dir.join(SETTINGS_FILE).exists(),
            "first load must persist settings.json"
        );
        let second = LocalStore::load(&dir).unwrap();
        assert_eq!(
            second.settings().device_id,
            first.settings().device_id,
            "connection code survives a relaunch with zero settings changes"
        );
        assert_eq!(
            second.settings().device_token,
            first.settings().device_token,
            "device token survives a relaunch"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn old_settings_files_keep_identity_and_default_the_new_flag() {
        let dir = temp_dir("upgrade");
        // A pre-accounts settings.json (missing later-added keys): the
        // serde defaults must kick in instead of the corrupt-file path,
        // which would have minted a NEW device id.
        std::fs::write(
            dir.join(SETTINGS_FILE),
            serde_json::json!({
                "device_id": "0123456789abcdef",
                "device_name": "old install",
                "signaling_base_url": "",
                "default_quality": "balanced",
                "default_viewer_scale": "fit",
                "device_token": "aabb",
            })
            .to_string(),
        )
        .unwrap();
        let store = LocalStore::load(&dir).unwrap();
        assert_eq!(store.settings().device_id, "0123456789abcdef");
        // 0.5.1 migration: a pre-0.5 file (no launch_at_login key) with an
        // empty URL gets the production default — the empty-URL opt-out
        // predates anyone choosing it deliberately in 0.5+.
        assert_eq!(
            store.settings().signaling_base_url,
            DEFAULT_SIGNALING_BASE_URL
        );
        // ...and the healed value is persisted (not just in memory).
        let reloaded = LocalStore::load(&dir).unwrap();
        assert_eq!(
            reloaded.settings().signaling_base_url,
            DEFAULT_SIGNALING_BASE_URL
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_url_heals_to_the_default_on_every_load() {
        let dir = temp_dir("url-heal");
        // 0.10.1: a blank URL is never a valid state — the machine would
        // silently never register and every connect to it would answer
        // "not online". Every load heals it to the deployed service (the
        // old "blank = deliberate opt-out" rule died with the circle).
        std::fs::write(
            dir.join(SETTINGS_FILE),
            serde_json::json!({
                "device_id": "0123456789abcdef",
                "device_name": "legacy install",
                "signaling_base_url": "",
                "default_quality": "balanced",
                "default_viewer_scale": "fit",
                "device_token": "aabb",
                "launch_at_login": false,
            })
            .to_string(),
        )
        .unwrap();
        let store = LocalStore::load(&dir).unwrap();
        assert_eq!(
            store.settings().signaling_base_url,
            DEFAULT_SIGNALING_BASE_URL
        );
        // ...and the healed value is persisted (not just in memory).
        let mut reloaded = LocalStore::load(&dir).unwrap();
        assert_eq!(
            reloaded.settings().signaling_base_url,
            DEFAULT_SIGNALING_BASE_URL
        );
        // A custom URL (dev server) is never touched.
        let mut custom = reloaded.settings().clone();
        custom.signaling_base_url = "http://127.0.0.1:38013".to_owned();
        reloaded.update_settings(custom).unwrap();
        let after = LocalStore::load(&dir).unwrap();
        assert_eq!(
            after.settings().signaling_base_url,
            "http://127.0.0.1:38013"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn identity_anchor_restores_identity_after_appdata_wipe() {
        // The 2026-10-27 incident: a reinstall wipes appdata → a minted
        // new id registers a SECOND circle-directory row for the same
        // machine. The anchor (Credential Manager survives the wipe)
        // must restore the old identity instead.
        let dir = temp_dir("anchor-restore");
        let creds = InMemorySessionStore::default();
        let (id, token) = {
            let mut store = LocalStore::load(&dir).unwrap();
            assert!(store.fresh_identity);
            store.adopt_identity_anchor(&creds).unwrap();
            (
                store.settings().device_id.clone(),
                store.settings().device_token.clone(),
            )
        };
        assert_anchor(&creds, &id);
        // "Reinstall": appdata gone, credential store intact.
        std::fs::remove_dir_all(&dir).unwrap();
        let store = LocalStore::load(&dir).unwrap();
        assert!(store.fresh_identity, "wiped appdata mints fresh");
        let mut store = store;
        store.adopt_identity_anchor(&creds).unwrap();
        assert_eq!(store.settings().device_id, id, "old id restored");
        assert_eq!(store.settings().device_token, token, "old token restored");
        let reloaded = LocalStore::load(&dir).unwrap();
        assert_eq!(reloaded.settings().device_id, id, "restored id persisted");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn identity_anchor_backfills_but_never_overwrites() {
        // Existing installs (no anchor yet) get backfilled with their
        // current identity; an existing anchor is never clobbered — even
        // by a settings folder cloned from another machine.
        let dir = temp_dir("anchor-backfill");
        let creds = InMemorySessionStore::default();
        let mut store = LocalStore::load(&dir).unwrap();
        let id = store.settings().device_id.clone();
        assert!(creds.load(IDENTITY_ANCHOR_USER).unwrap().is_none());
        store.adopt_identity_anchor(&creds).unwrap();
        assert_anchor(&creds, &id);

        // Foreign settings.json (folder cloned from another machine):
        // adopting must NOT overwrite this machine's anchor.
        let mut foreign = store.settings().clone();
        foreign.device_id = "1111111111111111".to_owned();
        foreign.device_token = "2222".to_owned();
        write_json_atomic(&dir.join(SETTINGS_FILE), &foreign).unwrap();
        let mut store = LocalStore::load(&dir).unwrap();
        assert!(!store.fresh_identity);
        store.adopt_identity_anchor(&creds).unwrap();
        assert_anchor(&creds, &id);
        assert_eq!(store.settings().device_id, "1111111111111111");
        std::fs::remove_dir_all(&dir).ok();
    }

    fn assert_anchor(creds: &InMemorySessionStore, device_id: &str) {
        let blob = creds
            .load(IDENTITY_ANCHOR_USER)
            .unwrap()
            .expect("anchor saved");
        let anchor: AnchorDoc = serde_json::from_str(&blob).unwrap();
        assert_eq!(anchor.device_id, device_id);
        assert!(!anchor.device_token.is_empty());
    }

    #[test]
    fn corrupt_files_default_instead_of_failing() {
        let dir = temp_dir("corrupt");
        std::fs::write(dir.join(SETTINGS_FILE), "{not json").unwrap();
        let store = LocalStore::load(&dir).unwrap();
        assert!(!store.settings().device_id.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retired_files_are_cleaned_up_on_load() {
        // ADR-009: account.json/roster.json (accounts era) and
        // favorites.json/circle.json (favorites + circle era) must not
        // linger as dead data on upgraded machines.
        let dir = temp_dir("legacy-files");
        std::fs::write(dir.join("account.json"), "{\"v\":1}").unwrap();
        std::fs::write(dir.join("roster.json"), "{\"v\":1}").unwrap();
        std::fs::write(dir.join("favorites.json"), "{\"favorites\":[]}").unwrap();
        std::fs::write(dir.join("circle.json"), "{\"v\":1}").unwrap();
        let _ = LocalStore::load(&dir).unwrap();
        assert!(!dir.join("account.json").exists());
        assert!(!dir.join("roster.json").exists());
        assert!(!dir.join("favorites.json").exists());
        assert!(!dir.join("circle.json").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
