//! Local persistence (RD-011: favorites are LOCAL-only — no sync, no
//! accounts). Two small JSON files under the app data dir, written
//! atomically (tmp + rename), read defensively: a corrupt file logs-and-
//! defaults instead of failing startup.

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
    pub signaling_base_url: String,
    /// Default quality preset name (wire tag: auto|low|balanced|high).
    pub default_quality: String,
    /// Default viewer scale (fit|one_to_one).
    pub default_viewer_scale: String,
    /// Presence-binding token for the signaling service (local secret;
    /// never logged, never synced).
    #[serde(default = "new_token")]
    pub device_token: String,
}

fn new_token() -> String {
    node_runtime::signaling_remote::RemoteSignalingConfig::new_token()
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            device_id: crate::engine::ids::new_device_id(),
            device_name: String::new(),
            signaling_base_url: String::new(),
            default_quality: "balanced".to_owned(),
            default_viewer_scale: "fit".to_owned(),
            device_token: new_token(),
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct FavoritesDoc {
    pub favorites: Vec<Favorite>,
}

const SETTINGS_FILE: &str = "settings.json";
const FAVORITES_FILE: &str = "favorites.json";

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
}

impl LocalStore {
    /// Load (or initialize) the store under `dir` (the Tauri app data dir;
    /// a temp dir in tests).
    pub fn load(dir: &Path) -> StoreResult<Self> {
        std::fs::create_dir_all(dir).map_err(|err| format!("create {}: {err}", dir.display()))?;
        let mut settings = read_json::<AppSettings>(&dir.join(SETTINGS_FILE))?.unwrap_or_default();
        // Identity is never absent after first load.
        if settings.device_id.trim().is_empty() {
            settings.device_id = crate::engine::ids::new_device_id();
            write_json_atomic(&dir.join(SETTINGS_FILE), &settings)?;
        }
        let favorites = read_json::<FavoritesDoc>(&dir.join(FAVORITES_FILE))?.unwrap_or_default();
        Ok(Self {
            dir: dir.to_owned(),
            settings,
            favorites,
        })
    }

    pub fn settings(&self) -> &AppSettings {
        &self.settings
    }

    pub fn favorites(&self) -> &[Favorite] {
        &self.favorites.favorites
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
        let store = LocalStore::load(&dir).unwrap();
        assert!(!store.settings().device_id.is_empty());
        assert!(store.favorites().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
