//! Account-manager tests against an in-memory fake service (never the
//! network). The fake stores exactly what the wire would: auth verifiers,
//! wrapped DEKs, opaque roster ciphertext + versions. Multiple managers
//! over the same fake simulate several machines sharing one account; a
//! shared [`InMemorySessionStore`] simulates one machine's persisted
//! credential across "restarts".

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use node_runtime::account_remote::{
    AccountError, LoginOutcome, LoginSalts, RosterBlob, SessionToken,
};
use protocol::account::RosterDoc;

use super::{
    AccountManager, AccountService, AccountStatus, ComputersList, Favorite, LocalStore,
    SavedAccount, import_favorites, merge_rosters, normalize_username, union_favorites,
};
use crate::credstore::{InMemorySessionStore, SessionStore};

const PW: &str = "correct horse battery";

// ---------------------------------------------------------------------------
// Fake service
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct FakeService(Arc<Mutex<FakeState>>);

#[derive(Default)]
struct FakeState {
    users: HashMap<String, FakeUser>,
    /// token hex → username.
    sessions: HashMap<String, String>,
    next_token: u64,
    /// When > 0, the next roster_put fails with a network error (offline).
    fail_puts: u32,
    online: HashSet<String>,
}

struct FakeUser {
    auth_key_hex: String,
    auth_salt_hex: String,
    wrap_salt_hex: String,
    wrapped_dek_hex: String,
    dek_nonce_hex: String,
    roster: RosterBlob,
}

impl FakeService {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(FakeState::default())))
    }

    fn mint_token(state: &mut FakeState) -> SessionToken {
        state.next_token += 1;
        SessionToken::from_persisted(&format!("{:064x}", state.next_token)).expect("token hex")
    }

    /// Simulate another device uploading (bump version, same content).
    fn bump_version(&self, username: &str) {
        self.0
            .lock()
            .unwrap()
            .users
            .get_mut(username)
            .unwrap()
            .roster
            .version += 1;
    }

    /// Corrupt the stored wrapped DEK (key-material damage; still hex).
    fn damage_material(&self, username: &str) {
        let mut state = self.0.lock().unwrap();
        let user = state.users.get_mut(username).unwrap();
        let replacement = if user.wrapped_dek_hex.starts_with('f') {
            "0"
        } else {
            "f"
        };
        user.wrapped_dek_hex.replace_range(0..1, replacement);
    }

    /// Invalidate every session (expired/revoked tokens).
    fn drop_sessions(&self) {
        self.0.lock().unwrap().sessions.clear();
    }

    fn fail_next_put(&self) {
        self.0.lock().unwrap().fail_puts = 1;
    }

    fn set_online(&self, codes: &[&str]) {
        self.0.lock().unwrap().online = codes.iter().map(|c| c.to_string()).collect();
    }
}

fn api_err(status: u16, code: &str, current_version: Option<u32>) -> AccountError {
    AccountError::Api {
        status,
        code: code.to_owned(),
        detail: None,
        retry_after_s: None,
        current_version,
    }
}

impl AccountService for FakeService {
    fn register(
        &self,
        username: &str,
        auth_key_hex: &str,
        auth_salt_hex: &str,
        wrap_salt_hex: &str,
        wrapped_dek_hex: &str,
        dek_nonce_hex: &str,
    ) -> Result<SessionToken, AccountError> {
        let mut state = self.0.lock().unwrap();
        if state.users.contains_key(username) {
            return Err(api_err(
                409,
                protocol::account::error_code::USERNAME_TAKEN,
                None,
            ));
        }
        let token = Self::mint_token(&mut state);
        state.users.insert(
            username.to_owned(),
            FakeUser {
                auth_key_hex: auth_key_hex.to_owned(),
                auth_salt_hex: auth_salt_hex.to_owned(),
                wrap_salt_hex: wrap_salt_hex.to_owned(),
                wrapped_dek_hex: wrapped_dek_hex.to_owned(),
                dek_nonce_hex: dek_nonce_hex.to_owned(),
                roster: RosterBlob {
                    ciphertext_hex: String::new(),
                    nonce_hex: String::new(),
                    version: 0,
                },
            },
        );
        state
            .sessions
            .insert(token.secret().to_owned(), username.to_owned());
        Ok(token)
    }

    fn login_pre(&self, username: &str) -> Result<LoginSalts, AccountError> {
        let state = self.0.lock().unwrap();
        match state.users.get(username) {
            Some(user) => Ok(LoginSalts {
                auth_salt_hex: user.auth_salt_hex.clone(),
                wrap_salt_hex: user.wrap_salt_hex.clone(),
            }),
            // Decoy salts: existence is not disclosed.
            None => Ok(LoginSalts {
                auth_salt_hex: "1".repeat(32),
                wrap_salt_hex: "2".repeat(32),
            }),
        }
    }

    fn login(&self, username: &str, auth_key_hex: &str) -> Result<LoginOutcome, AccountError> {
        let mut state = self.0.lock().unwrap();
        let Some(user) = state.users.get(username) else {
            return Err(api_err(
                401,
                protocol::account::error_code::INVALID_CREDENTIALS,
                None,
            ));
        };
        if user.auth_key_hex != auth_key_hex {
            return Err(api_err(
                401,
                protocol::account::error_code::INVALID_CREDENTIALS,
                None,
            ));
        }
        let (wrapped, nonce) = (user.wrapped_dek_hex.clone(), user.dek_nonce_hex.clone());
        let token = Self::mint_token(&mut state);
        state
            .sessions
            .insert(token.secret().to_owned(), username.to_owned());
        Ok(LoginOutcome {
            token,
            expires_ms: 1_760_000_000_000,
            wrapped_dek_hex: wrapped,
            dek_nonce_hex: nonce,
        })
    }

    fn logout(&self, token: &SessionToken) -> Result<(), AccountError> {
        self.0.lock().unwrap().sessions.remove(token.secret());
        Ok(())
    }

    fn roster_get(&self, token: &SessionToken) -> Result<RosterBlob, AccountError> {
        let state = self.0.lock().unwrap();
        let username = state
            .sessions
            .get(token.secret())
            .ok_or_else(|| api_err(401, protocol::account::error_code::UNAUTHORIZED, None))?;
        Ok(state.users[username].roster.clone())
    }

    fn roster_put(
        &self,
        token: &SessionToken,
        ciphertext_hex: &str,
        nonce_hex: &str,
        base_version: u32,
    ) -> Result<u32, AccountError> {
        let mut state = self.0.lock().unwrap();
        if state.fail_puts > 0 {
            state.fail_puts -= 1;
            return Err(AccountError::Network("simulated offline".to_owned()));
        }
        let username = state
            .sessions
            .get(token.secret())
            .ok_or_else(|| api_err(401, protocol::account::error_code::UNAUTHORIZED, None))?
            .clone();
        let roster = &mut state.users.get_mut(&username).unwrap().roster;
        if base_version != roster.version {
            return Err(api_err(
                409,
                protocol::account::error_code::ROSTER_CONFLICT,
                Some(roster.version),
            ));
        }
        roster.version += 1;
        roster.ciphertext_hex = ciphertext_hex.to_owned();
        roster.nonce_hex = nonce_hex.to_owned();
        Ok(roster.version)
    }

    fn presence(
        &self,
        token: &SessionToken,
        codes: &[String],
    ) -> Result<Vec<String>, AccountError> {
        let state = self.0.lock().unwrap();
        if !state.sessions.contains_key(token.secret()) {
            return Err(api_err(
                401,
                protocol::account::error_code::UNAUTHORIZED,
                None,
            ));
        }
        Ok(codes
            .iter()
            .filter(|code| state.online.contains(*code))
            .cloned()
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Rig
// ---------------------------------------------------------------------------

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rd-account-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn new_manager(service: &FakeService, creds: &InMemorySessionStore) -> AccountManager {
    let mut manager =
        AccountManager::with_service(Box::new(service.clone()), Box::new(creds.clone()));
    // Recorded (not swapped: the service is pinned) so restore() performs
    // its session check.
    manager.set_base_url("https://unit.test");
    manager
}

fn logged_in(status: &AccountStatus, username: &str) {
    assert_eq!(
        status,
        &AccountStatus::LoggedIn {
            username: username.to_owned(),
            expires_ms: 1_760_000_000_000,
        }
    );
}

fn codes(list: &ComputersList) -> Vec<String> {
    list.computers.iter().map(|c| c.code.clone()).collect()
}

// ---------------------------------------------------------------------------
// Pure logic
// ---------------------------------------------------------------------------

#[test]
fn username_normalization_and_validation() {
    assert_eq!(normalize_username("  Alice.X \n").as_deref(), Ok("alice.x"));
    assert!(normalize_username("ab").is_err());
    assert!(normalize_username("Alice!").is_err());
}

fn entry(code: &str, updated: u64) -> protocol::account::RosterEntry {
    protocol::account::RosterEntry {
        id: format!("{code:0>8}")[..8].to_owned(),
        name: code.to_owned(),
        code: code.to_owned(),
        added_at_ms: 1,
        updated_at_ms: updated,
    }
}

fn doc(entries: Vec<protocol::account::RosterEntry>) -> RosterDoc {
    RosterDoc::v1(entries)
}

#[test]
fn merge_unions_by_code_and_keeps_the_newest() {
    let server = doc(vec![entry("aaaa", 10), entry("bbbb", 5)]);
    let local = doc(vec![entry("bbbb", 9), entry("cccc", 1)]);
    let merged = merge_rosters(Some(&server), Some(&local));
    let got = merged
        .computers
        .iter()
        .map(|e| (e.code.as_str(), e.updated_at_ms))
        .collect::<Vec<_>>();
    assert_eq!(got, vec![("aaaa", 10), ("bbbb", 9), ("cccc", 1)]);
    // Ties keep the server copy.
    let tie = merge_rosters(
        Some(&doc(vec![entry("aaaa", 7)])),
        Some(&doc(vec![entry("aaaa", 7)])),
    );
    assert_eq!(tie.computers.len(), 1);
}

#[test]
fn favorites_join_the_union_without_duplicating() {
    let roster = doc(vec![entry("aaaa", 10)]);
    let favorites = vec![
        Favorite {
            id: "11111111".into(),
            name: "A".into(),
            code: "AAAA".into(), // same code, different case → duplicate avoided
        },
        Favorite {
            id: "22222222".into(),
            name: "New".into(),
            code: "dddddddddddddddd".into(),
        },
    ];
    let merged = union_favorites(roster, &favorites, 99);
    assert_eq!(merged.computers.len(), 2);
    assert!(
        merged
            .computers
            .iter()
            .any(|e| e.code == "dddddddddddddddd" && e.updated_at_ms == 99)
    );
}

#[test]
fn import_favorites_keeps_identity_fields() {
    let favorites = vec![Favorite {
        id: "abcd1234".into(),
        name: "Laptop".into(),
        code: "0123456789abcdef".into(),
    }];
    let entries = import_favorites(&favorites, 5);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, "abcd1234");
    assert_eq!(entries[0].name, "Laptop");
    assert_eq!(entries[0].code, "0123456789abcdef");
    assert_eq!(entries[0].added_at_ms, 5);
}

// ---------------------------------------------------------------------------
// Register / login / merge / mutations (fake service)
// ---------------------------------------------------------------------------

#[test]
fn register_imports_favorites_and_persists_only_encrypted_data() {
    let service = FakeService::new();
    let creds = InMemorySessionStore::default();
    let dir = temp_dir("register");
    let mut store = LocalStore::load(&dir).unwrap();
    store.add_favorite("Laptop", "aaaaaaaaaaaaaaaa").unwrap();
    store.add_favorite("Desk", "bbbbbbbbbbbbbbbb").unwrap();
    let mut manager = new_manager(&service, &creds);

    let status = manager.register(&mut store, "Alice", PW).unwrap();
    // Normalized username; register carries no expiry (the wire response
    // has none), so 0 = unknown.
    assert_eq!(
        status,
        AccountStatus::LoggedIn {
            username: "alice".into(),
            expires_ms: 0,
        }
    );

    // account.json + roster.json exist; the roster cache is ciphertext.
    let account = store.account().unwrap().clone();
    assert_eq!(account.username, "alice");
    assert!(store.roster_cache().is_some());
    let raw = std::fs::read_to_string(dir.join("roster.json")).unwrap();
    assert!(!raw.contains("Laptop"), "roster.json must stay encrypted");
    assert!(raw.contains("ciphertext_hex"), "v1 cache shape");

    // The session token went to the credential store, never to disk.
    let persisted_token = creds.load("alice").unwrap().expect("token in credstore");
    let account_raw = std::fs::read_to_string(dir.join("account.json")).unwrap();
    assert!(!account_raw.contains(&persisted_token));

    // The list = the imported favorites (ids kept).
    let device = store.settings().device_id.clone();
    let list = manager.computers(&device).unwrap();
    assert_eq!(codes(&list), vec!["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"]);
    assert_eq!(list.computers[0].name, "Laptop");
    assert!(list.computers.iter().all(|c| !c.is_self));

    // Server version advanced from the register-time put.
    assert_eq!(list.server_version, 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn register_validates_input_before_any_cryptography() {
    let service = FakeService::new();
    let creds = InMemorySessionStore::default();
    let dir = temp_dir("validate");
    let mut store = LocalStore::load(&dir).unwrap();
    let mut manager = new_manager(&service, &creds);

    let err = manager.register(&mut store, "alice", "short").unwrap_err();
    assert!(err.contains("Password must be"), "{err}");
    let err = manager.register(&mut store, "x!", PW).unwrap_err();
    assert!(err.contains("Username must be"), "{err}");
    assert_eq!(manager.status(&store), AccountStatus::LoggedOut);
    assert!(store.account().is_none(), "nothing persisted on rejection");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn second_machine_login_merges_down_and_writes_favorites_back() {
    let service = FakeService::new();
    // Machine A registers with one favorite.
    let dir_a = temp_dir("machine-a");
    let mut store_a = LocalStore::load(&dir_a).unwrap();
    store_a.add_favorite("Laptop", "aaaaaaaaaaaaaaaa").unwrap();
    let creds_a = InMemorySessionStore::default();
    let mut manager_a = new_manager(&service, &creds_a);
    manager_a.register(&mut store_a, "alice", PW).unwrap();

    // Machine B: fresh profile + credential store, same account.
    let dir_b = temp_dir("machine-b");
    let mut store_b = LocalStore::load(&dir_b).unwrap();
    let creds_b = InMemorySessionStore::default();
    let mut manager_b = new_manager(&service, &creds_b);
    let status = manager_b.login(&mut store_b, "alice", PW).unwrap();
    logged_in(&status, "alice");

    let device_b = store_b.settings().device_id.clone();
    let list = manager_b.computers(&device_b).unwrap();
    assert_eq!(codes(&list), vec!["aaaaaaaaaaaaaaaa"]);
    // Favorites write-back: B's logged-out UI/e2e view is coherent.
    assert_eq!(store_b.favorites().len(), 1);
    assert_eq!(store_b.favorites()[0].name, "Laptop");
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}

#[test]
fn offline_upload_self_heals_on_next_login() {
    let service = FakeService::new();
    let creds = InMemorySessionStore::default();
    let dir = temp_dir("offline");
    let mut store = LocalStore::load(&dir).unwrap();
    let mut m = new_manager(&service, &creds);
    m.register(&mut store, "alice", PW).unwrap();
    let device = store.settings().device_id.clone();

    // The upload fails (offline) — the local cache still records the add.
    service.fail_next_put();
    let list = m
        .add_computer(&mut store, &device, "Office", "aaaaaaaaaaaaaaaa")
        .unwrap();
    assert_eq!(codes(&list), vec!["aaaaaaaaaaaaaaaa"]);
    assert_eq!(list.server_version, 1, "stale base version kept");

    // Next login: server (empty) ∪ local cache (one entry) → re-upload.
    let mut m = new_manager(&service, &creds);
    m.login(&mut store, "alice", PW).unwrap();
    let list = m.computers(&device).unwrap();
    assert_eq!(codes(&list), vec!["aaaaaaaaaaaaaaaa"], "entry survived");
    assert_eq!(list.server_version, 2, "merged doc uploaded");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn conflict_re_fetches_re_merges_and_retries_once() {
    let service = FakeService::new();
    let creds = InMemorySessionStore::default();
    let dir = temp_dir("conflict");
    let mut store = LocalStore::load(&dir).unwrap();
    let mut m = new_manager(&service, &creds);
    m.register(&mut store, "alice", PW).unwrap();
    let device = store.settings().device_id.clone();

    // Another device uploads between our fetch and our put.
    service.bump_version("alice"); // server now at version 2
    let list = m
        .add_computer(&mut store, &device, "Office", "aaaaaaaaaaaaaaaa")
        .unwrap();
    assert_eq!(codes(&list), vec!["aaaaaaaaaaaaaaaa"]);
    assert_eq!(list.server_version, 3, "409 → re-fetch → retry at v2 → v3");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn add_by_code_dedupes_add_this_bumps_presence_filters() {
    let service = FakeService::new();
    let creds = InMemorySessionStore::default();
    let dir = temp_dir("mutations");
    let mut store = LocalStore::load(&dir).unwrap();
    let mut manager = new_manager(&service, &creds);
    manager.register(&mut store, "alice", PW).unwrap();
    let device = store.settings().device_id.clone();

    // Dedupe by code: the second add renames + bumps instead of adding.
    manager
        .add_computer(&mut store, &device, "Office", "AAAAAAAAAAAAAAAA")
        .unwrap();
    let list = manager
        .add_computer(&mut store, &device, "Renamed", "aaaaaaaaaaaaaaaa")
        .unwrap();
    assert_eq!(list.computers.len(), 1);
    assert_eq!(list.computers[0].name, "Renamed");
    assert!(list.computers[0].updated_at_ms >= list.computers[0].added_at_ms);

    // This computer: added once, re-add only bumps; flagged is_self.
    manager
        .add_this_computer(&mut store, &device, "This PC")
        .unwrap();
    let list = manager
        .add_this_computer(&mut store, &device, "Other name")
        .unwrap();
    assert_eq!(list.computers.len(), 2);
    let this_pc = list.computers.iter().find(|c| c.is_self).unwrap();
    assert_eq!(this_pc.name, "This PC", "re-add keeps the existing name");
    assert_eq!(this_pc.code, device);

    // Presence: only roster codes marked online come back.
    service.set_online(&["aaaaaaaaaaaaaaaa"]);
    assert_eq!(manager.presence().unwrap(), vec!["aaaaaaaaaaaaaaaa"]);

    // Rename + remove round out the mutations.
    let id = list.computers[0].id.clone();
    let list = manager
        .rename_computer(&mut store, &device, &id, "Office 2")
        .unwrap();
    assert_eq!(list.computers[0].name, "Office 2");
    assert!(manager.remove_computer(&mut store, &device, &id).is_ok());
    assert!(
        manager
            .rename_computer(&mut store, &device, &id, "X")
            .is_err()
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn roster_capacity_is_enforced_with_a_friendly_error() {
    let service = FakeService::new();
    let creds = InMemorySessionStore::default();
    let dir = temp_dir("capacity");
    let mut store = LocalStore::load(&dir).unwrap();
    let favorites: Vec<Favorite> = (0..protocol::account::ROSTER_MAX_COMPUTERS)
        .map(|i| Favorite {
            id: format!("{i:08x}"),
            name: format!("PC {i}"),
            code: format!("{i:016x}"),
        })
        .collect();
    store.replace_favorites(favorites).unwrap();
    let mut manager = new_manager(&service, &creds);
    manager.register(&mut store, "alice", PW).unwrap();
    let device = store.settings().device_id.clone();

    let err = manager
        .add_computer(&mut store, &device, "One more", "ffffffffffffffff")
        .unwrap_err();
    assert!(err.contains("list is full"), "{err}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn unlock_reuses_the_saved_username_and_rejects_bad_passwords() {
    let service = FakeService::new();
    let creds = InMemorySessionStore::default();
    let dir = temp_dir("unlock");
    let mut store = LocalStore::load(&dir).unwrap();
    let mut manager = new_manager(&service, &creds);
    manager.register(&mut store, "alice", PW).unwrap();

    // Fresh manager (app restart) — only the password is entered.
    let mut manager = new_manager(&service, &creds);
    assert_eq!(
        manager.status(&store),
        AccountStatus::SavedAccount {
            username: "alice".into()
        }
    );
    let err = manager.unlock(&mut store, "wrong password").unwrap_err();
    assert!(err.contains("invalid_credentials"), "{err}");
    let status = manager.unlock(&mut store, PW).unwrap();
    logged_in(&status, "alice");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn restore_validates_the_persisted_session_only() {
    let service = FakeService::new();
    let creds = InMemorySessionStore::default();
    let dir = temp_dir("restore");
    let mut store = LocalStore::load(&dir).unwrap();
    let mut manager = new_manager(&service, &creds);
    manager.register(&mut store, "alice", PW).unwrap();
    drop(manager);

    // Valid persisted token → session_valid (the roster stays encrypted
    // until the user re-enters the password).
    let mut restored = new_manager(&service, &creds);
    assert_eq!(
        restored.restore(&store).unwrap(),
        SavedAccount {
            username: "alice".into(),
            session_valid: true,
        }
    );
    assert_eq!(
        restored.status(&store),
        AccountStatus::SavedAccount {
            username: "alice".into()
        },
        "restore never leaves the manager logged in (no DEK without the password)"
    );

    // Expired/revoked token → invalid + the dead credential is cleared.
    service.drop_sessions();
    let mut restored = new_manager(&service, &creds);
    assert!(!restored.restore(&store).unwrap().session_valid);
    assert_eq!(
        creds.load("alice").unwrap(),
        None,
        "dead session cleared from the credential store"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn damaged_key_material_has_its_own_error() {
    let service = FakeService::new();
    let creds = InMemorySessionStore::default();
    let dir = temp_dir("damaged");
    let mut store = LocalStore::load(&dir).unwrap();
    let mut manager = new_manager(&service, &creds);
    manager.register(&mut store, "alice", PW).unwrap();

    service.damage_material("alice");
    let mut manager = new_manager(&service, &creds);
    let err = manager.login(&mut store, "alice", PW).unwrap_err();
    assert!(err.contains("key material damaged"), "{err}");
    std::fs::remove_dir_all(&dir).ok();
}

/// Security review P3: switching accounts must retire the previous user's
/// session — their bearer token must not survive in the credential vault.
#[test]
fn switching_users_retires_the_previous_session_and_credential() {
    let service = FakeService::new();
    let creds = InMemorySessionStore::default();

    // Machine 1: alice registers and is logged in.
    let dir_a = temp_dir("switch-a");
    let mut store_a = LocalStore::load(&dir_a).unwrap();
    let mut manager = new_manager(&service, &creds);
    manager.register(&mut store_a, "alice", PW).unwrap();
    let alice_token = creds.load("alice").unwrap().expect("alice's token");

    // Somewhere else, bob exists.
    let dir_b = temp_dir("switch-b");
    let mut store_b = LocalStore::load(&dir_b).unwrap();
    let creds_b = InMemorySessionStore::default();
    let mut manager_b = new_manager(&service, &creds_b);
    manager_b.register(&mut store_b, "bob", PW).unwrap();

    // Same machine 1: log in as bob.
    manager.login(&mut store_a, "bob", PW).unwrap();
    logged_in(&manager.status(&store_a), "bob");

    // Alice's credential is gone from the vault and her session is dead
    // server-side (the token no longer authenticates).
    assert!(creds.load("alice").unwrap().is_none());
    assert!(
        !service
            .0
            .lock()
            .unwrap()
            .sessions
            .contains_key(&alice_token)
    );
    // Bob's credential is present; the saved account is now bob's.
    assert!(creds.load("bob").unwrap().is_some());
    assert_eq!(
        store_a.account().map(|d| d.username.clone()),
        Some("bob".to_owned())
    );
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}

#[test]
fn logout_keeps_files_and_clears_the_session() {
    let service = FakeService::new();
    let creds = InMemorySessionStore::default();
    let dir = temp_dir("logout");
    let mut store = LocalStore::load(&dir).unwrap();
    let mut m = new_manager(&service, &creds);
    m.register(&mut store, "alice", PW).unwrap();
    let device = store.settings().device_id.clone();
    m.add_computer(&mut store, &device, "Office", "aaaaaaaaaaaaaaaa")
        .unwrap();

    let status = m.logout(&store);
    assert_eq!(
        status,
        AccountStatus::SavedAccount {
            username: "alice".into()
        }
    );
    assert!(store.account().is_some(), "account.json kept");
    assert!(store.roster_cache().is_some(), "encrypted roster kept");
    assert_eq!(creds.load("alice").unwrap(), None, "token cleared");
    let err = m.computers("any").unwrap_err();
    assert!(err.contains("Not signed in"), "{err}");

    // The list survives for the next login (encrypted).
    let mut m = new_manager(&service, &creds);
    m.login(&mut store, "alice", PW).unwrap();
    let device = store.settings().device_id.clone();
    assert_eq!(
        codes(&m.computers(&device).unwrap()),
        vec!["aaaaaaaaaaaaaaaa"]
    );
    std::fs::remove_dir_all(&dir).ok();
}
