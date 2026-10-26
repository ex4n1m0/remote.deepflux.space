//! Local persistence. Small JSON files under the app data dir, written
//! atomically (tmp + rename), read defensively: a corrupt file logs-and-
//! defaults instead of failing startup. Favorites remain local-only; the
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
    /// The user skipped the first-run account onboarding (persisted so the
    /// gate opens straight into the main UI; signing in later still works).
    #[serde(default)]
    pub skipped_onboarding: bool,
    /// ADR-006 always-ready: launch at Windows login (drives the autostart
    /// plugin; the family build turns it on once at first run).
    #[serde(default)]
    pub launch_at_login: bool,
    /// In-app assistant provider (ADR-005): any OpenAI-compatible base
    /// URL. Default DeepSeek. The API key is NOT here — it lives in the
    /// Windows Credential Manager (`agent-api-key` seam).
    #[serde(default = "default_agent_base_url")]
    pub agent_base_url: String,
    /// Assistant model id. Default vision-capable so screenshot tools work
    /// (`deepseek-flash`); text-only `deepseek-chat` is a settings option.
    #[serde(default = "default_agent_model")]
    pub agent_model: String,
}

/// Default assistant provider (ADR-005): DeepSeek, OpenAI-compatible.
pub const DEFAULT_AGENT_BASE_URL: &str = "https://api.deepseek.com/v1";

fn default_agent_base_url() -> String {
    DEFAULT_AGENT_BASE_URL.to_owned()
}

fn default_agent_model() -> String {
    "deepseek-flash".to_owned()
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
            skipped_onboarding: false,
            launch_at_login: false,
            agent_base_url: default_agent_base_url(),
            agent_model: default_agent_model(),
        }
    }
}

/// One saved remote machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Favorite {
    /// Stable local id (8 hex chars).
    pub id: String,
    /// User-chosen display name.
    pub name: String,
    /// The host's connection code (= its device id).
    pub code: String,
    /// ADR-006: how the row was saved — "manual" (typed a code) or
    /// "directory" (saved when the owner's approval paired the machine).
    /// Local format only, never a wire field.
    #[serde(default = "manual_source")]
    pub source: String,
}

fn manual_source() -> String {
    "manual".to_owned()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct FavoritesDoc {
    pub favorites: Vec<Favorite>,
}

/// Account material (post-MVP accounts): everything needed to log in again
/// except the password. The session token is NOT here (it lives in the
/// Windows Credential Manager) and the roster is NOT here (it lives
/// encrypted in `roster.json` under a DEK wrapped by this material).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountDoc {
    pub v: u16,
    pub username: String,
    pub auth_salt_hex: String,
    pub wrap_salt_hex: String,
    pub wrapped_dek_hex: String,
    pub dek_nonce_hex: String,
}

/// Encrypted roster cache: AES-256-GCM under the account DEK — decryptable
/// only while logged in (the DEK itself needs the password).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RosterCacheDoc {
    pub v: u16,
    pub username: String,
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    /// Last-known server roster version (optimistic-concurrency base).
    pub version: u32,
}

const SETTINGS_FILE: &str = "settings.json";
const FAVORITES_FILE: &str = "favorites.json";
const ACCOUNT_FILE: &str = "account.json";
const ROSTER_FILE: &str = "roster.json";

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

/// Local JSON store for settings + favorites.
pub struct LocalStore {
    dir: PathBuf,
    settings: AppSettings,
    favorites: FavoritesDoc,
    account: Option<AccountDoc>,
    roster_cache: Option<RosterCacheDoc>,
}

impl LocalStore {
    /// Load (or initialize) the store under `dir` (the Tauri app data dir;
    /// a temp dir in tests).
    pub fn load(dir: &Path) -> StoreResult<Self> {
        std::fs::create_dir_all(dir).map_err(|err| format!("create {}: {err}", dir.display()))?;
        let settings_path = dir.join(SETTINGS_FILE);
        let had_settings = settings_path.exists();
        let raw_settings = std::fs::read_to_string(&settings_path).unwrap_or_default();
        let mut settings = read_json::<AppSettings>(&settings_path)?.unwrap_or_default();
        // One-time upgrade migration (0.5.1): settings written before 0.5
        // lack the `launch_at_login` key; if such a file carries an EMPTY
        // signaling URL (the old opt-out), it predates anyone choosing
        // that deliberately in 0.5+ — restore the default so login, the
        // engine, and the circle work after an upgrade (the second-machine
        // bug). A URL cleared in 0.5+ keeps the field in the file and the
        // opt-out intact.
        let mut healed_url = false;
        if had_settings
            && !raw_settings.contains("\"launch_at_login\"")
            && settings.signaling_base_url.trim().is_empty()
        {
            settings.signaling_base_url = DEFAULT_SIGNALING_BASE_URL.to_owned();
            healed_url = true;
        }
        // Identity is never absent after first load. `default()` already
        // mints a random device_id/token, so the empty checks only catch
        // old files parsed without those keys — the missing-file case is
        // `!had_settings`. Either way the minted identity must be PERSISTED
        // here: until a settings change writes the file, every launch would
        // otherwise regenerate the connection code (favorites and pairing
        // key on it staying stable).
        let mut fresh_identity = false;
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
        let favorites = read_json::<FavoritesDoc>(&dir.join(FAVORITES_FILE))?.unwrap_or_default();
        let account = read_json::<AccountDoc>(&dir.join(ACCOUNT_FILE))?;
        let roster_cache = read_json::<RosterCacheDoc>(&dir.join(ROSTER_FILE))?;
        Ok(Self {
            dir: dir.to_owned(),
            settings,
            favorites,
            account,
            roster_cache,
        })
    }

    pub fn settings(&self) -> &AppSettings {
        &self.settings
    }

    pub fn favorites(&self) -> &[Favorite] {
        &self.favorites.favorites
    }

    /// Saved account material, when this machine has logged in before.
    pub fn account(&self) -> Option<&AccountDoc> {
        self.account.as_ref()
    }

    /// Encrypted local roster cache, when present.
    pub fn roster_cache(&self) -> Option<&RosterCacheDoc> {
        self.roster_cache.as_ref()
    }

    pub fn save_account(&mut self, doc: AccountDoc) -> StoreResult<()> {
        self.account = Some(doc.clone());
        write_json_atomic(&self.dir.join(ACCOUNT_FILE), &doc)
    }

    pub fn save_roster_cache(&mut self, doc: RosterCacheDoc) -> StoreResult<()> {
        self.roster_cache = Some(doc.clone());
        write_json_atomic(&self.dir.join(ROSTER_FILE), &doc)
    }

    /// Replace the favorites wholesale (the roster write-back path: the
    /// logged-out UI and e2e flows stay coherent with the account list).
    pub fn replace_favorites(&mut self, favorites: Vec<Favorite>) -> StoreResult<()> {
        self.favorites = FavoritesDoc { favorites };
        self.save_favorites()
    }

    /// ADR-006: save a favorite recording its provenance; existing rows
    /// for the code are left alone (idempotent auto-save).
    pub fn add_favorite_sourced(
        &mut self,
        name: &str,
        code: &str,
        source: &str,
    ) -> StoreResult<Favorite> {
        let code_norm = code.trim().to_owned();
        if let Some(existing) = self
            .favorites
            .favorites
            .iter()
            .find(|f| f.code == code_norm)
            .cloned()
        {
            return Ok(existing);
        }
        let favorite = Favorite {
            id: crate::engine::ids::new_device_id()[..8].to_owned(),
            name: name.trim().to_owned(),
            code: code_norm,
            source: source.to_owned(),
        };
        self.favorites.favorites.push(favorite.clone());
        self.save_favorites()?;
        Ok(favorite)
    }

    pub fn update_settings(&mut self, patch: AppSettings) -> StoreResult<()> {
        // Identity is immutable from the UI side (it would strand favorites
        // and signaling presence); the token rotates only on regeneration.
        let mut next = patch;
        next.device_id = self.settings.device_id.clone();
        next.device_token = self.settings.device_token.clone();
        self.settings = next.clone();
        write_json_atomic(&self.dir.join(SETTINGS_FILE), &next)
    }

    pub fn add_favorite(&mut self, name: &str, code: &str) -> StoreResult<Favorite> {
        let code = code.trim().to_owned();
        if code.is_empty() {
            return Err("connection code is empty".to_owned());
        }
        if self.favorites.favorites.iter().any(|f| f.code == code) {
            return Err("this code is already in favorites".to_owned());
        }
        let favorite = Favorite {
            id: crate::engine::ids::new_device_id()[..8].to_owned(),
            name: name.trim().to_owned(),
            code,
            source: "manual".to_owned(),
        };
        self.favorites.favorites.push(favorite.clone());
        self.save_favorites()?;
        Ok(favorite)
    }

    pub fn remove_favorite(&mut self, id: &str) -> StoreResult<()> {
        let before = self.favorites.favorites.len();
        self.favorites.favorites.retain(|f| f.id != id);
        if self.favorites.favorites.len() == before {
            return Err("favorite not found".to_owned());
        }
        self.save_favorites()
    }

    pub fn rename_favorite(&mut self, id: &str, name: &str) -> StoreResult<Favorite> {
        let favorite = self
            .favorites
            .favorites
            .iter_mut()
            .find(|f| f.id == id)
            .ok_or_else(|| "favorite not found".to_owned())?;
        favorite.name = name.trim().to_owned();
        let out = favorite.clone();
        self.save_favorites()?;
        Ok(out)
    }

    fn save_favorites(&self) -> StoreResult<()> {
        write_json_atomic(&self.dir.join(FAVORITES_FILE), &self.favorites)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(!store.settings().skipped_onboarding);
        store
            .update_settings(AppSettings {
                signaling_base_url: "http://127.0.0.1:38013".into(),
                skipped_onboarding: true,
                ..store.settings().clone()
            })
            .unwrap();
        let reloaded = LocalStore::load(&dir).unwrap();
        assert_eq!(reloaded.settings().device_id, id, "identity survives");
        assert_eq!(
            reloaded.settings().signaling_base_url,
            "http://127.0.0.1:38013"
        );
        assert!(reloaded.settings().skipped_onboarding);
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
        // A pre-accounts settings.json (no skipped_onboarding key): the
        // serde default must kick in instead of the corrupt-file path,
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
        assert!(!store.settings().skipped_onboarding);
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
    fn post_05_empty_url_opt_out_is_preserved() {
        let dir = temp_dir("optout");
        // A 0.5+ file carries launch_at_login; an empty URL here IS a
        // deliberate opt-out and must survive the migration untouched.
        std::fs::write(
            dir.join(SETTINGS_FILE),
            serde_json::json!({
                "device_id": "0123456789abcdef",
                "device_name": "privacy install",
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
        assert_eq!(store.settings().signaling_base_url, "");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn favorites_add_remove_rename_and_dedupe() {
        let dir = temp_dir("favorites");
        let mut store = LocalStore::load(&dir).unwrap();
        let a = store.add_favorite("Laptop", "aaaaaaaaaaaaaaaa").unwrap();
        assert!(store.add_favorite("Again", "aaaaaaaaaaaaaaaa").is_err());
        let b = store.add_favorite("", "bbbbbbbbbbbbbbbb").unwrap();
        assert_eq!(b.name, "");
        let renamed = store.rename_favorite(&a.id, "Work laptop").unwrap();
        assert_eq!(renamed.name, "Work laptop");
        store.remove_favorite(&b.id).unwrap();
        assert!(store.remove_favorite(&b.id).is_err());
        let reloaded = LocalStore::load(&dir).unwrap();
        assert_eq!(reloaded.favorites().len(), 1);
        assert_eq!(reloaded.favorites()[0].name, "Work laptop");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_files_default_instead_of_failing() {
        let dir = temp_dir("corrupt");
        std::fs::write(dir.join(SETTINGS_FILE), "{not json").unwrap();
        std::fs::write(dir.join(FAVORITES_FILE), "]]").unwrap();
        std::fs::write(dir.join(ACCOUNT_FILE), "{not json").unwrap();
        std::fs::write(dir.join(ROSTER_FILE), "]]").unwrap();
        let store = LocalStore::load(&dir).unwrap();
        assert!(!store.settings().device_id.is_empty());
        assert!(store.favorites().is_empty());
        assert!(store.account().is_none());
        assert!(store.roster_cache().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    fn account_doc(username: &str) -> AccountDoc {
        AccountDoc {
            v: 1,
            username: username.to_owned(),
            auth_salt_hex: "aa".repeat(16),
            wrap_salt_hex: "bb".repeat(16),
            wrapped_dek_hex: "cc".repeat(48),
            dek_nonce_hex: "dd".repeat(12),
        }
    }

    #[test]
    fn account_and_roster_cache_persist_with_identity_stability() {
        let dir = temp_dir("account");
        let mut store = LocalStore::load(&dir).unwrap();
        assert!(store.account().is_none() && store.roster_cache().is_none());

        store.save_account(account_doc("alice")).unwrap();
        let roster = RosterCacheDoc {
            v: 1,
            username: "alice".to_owned(),
            ciphertext_hex: "ab".repeat(64),
            nonce_hex: "0".repeat(24),
            version: 7,
        };
        store.save_roster_cache(roster.clone()).unwrap();

        let reloaded = LocalStore::load(&dir).unwrap();
        assert_eq!(reloaded.account(), Some(&account_doc("alice")));
        assert_eq!(reloaded.roster_cache(), Some(&roster));
        // The roster cache carries NO plaintext entry data.
        let raw = std::fs::read_to_string(dir.join(ROSTER_FILE)).unwrap();
        assert!(!raw.contains("alice@") && !raw.contains("\"computers\""));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn replace_favorites_overwrites_wholesale() {
        let dir = temp_dir("replace");
        let mut store = LocalStore::load(&dir).unwrap();
        store.add_favorite("A", "aaaaaaaaaaaaaaaa").unwrap();
        store
            .replace_favorites(vec![
                Favorite {
                    id: "11111111".into(),
                    name: "B".into(),
                    code: "bbbbbbbbbbbbbbbb".into(),
                    source: "manual".into(),
                },
                Favorite {
                    id: "22222222".into(),
                    name: "C".into(),
                    code: "cccccccccccccccc".into(),
                    source: "manual".into(),
                },
            ])
            .unwrap();
        let reloaded = LocalStore::load(&dir).unwrap();
        assert_eq!(reloaded.favorites().len(), 2);
        assert_eq!(reloaded.favorites()[0].name, "B");
        std::fs::remove_dir_all(&dir).ok();
    }
}
