//! Account manager (post-MVP accounts & encrypted roster, ADR-003).
//!
//! Wraps the wire/crypto layers that already exist —
//! `node_runtime::account_remote` (service client) and
//! `node_runtime::account_crypto` (scrypt + AES-GCM envelope) — behind the
//! command surface. Responsibilities:
//!
//! * register / login / unlock / logout, with the DEK and session token
//!   held in memory only (the token additionally persists in the Windows
//!   Credential Manager via [`crate::credstore`]);
//! * roster sync: merge server blob + local encrypted cache (union by
//!   `code`, newest `updated_at_ms` wins, entries are never lost), upload
//!   on divergence with optimistic concurrency (`roster_conflict` →
//!   re-fetch, re-merge, retry once);
//! * roster mutations (`add/add-this/remove/rename`) that update the
//!   in-memory doc, re-encrypt, re-upload, and persist both the encrypted
//!   cache (`roster.json`) and the plaintext favorites list (so the
//!   logged-out UI and the e2e paths stay coherent).
//!
//! Saved-account unlock flow (explicit design decision, 2026-10-01): the
//! DEK is wrapped under a password-derived KEK, so it cannot be opened
//! without the password. [`AccountManager::restore`] therefore validates
//! the persisted session token only and reports
//! [`SavedAccount { username, session_valid }`](SavedAccount) — the roster
//! stays encrypted until the user re-enters the password via
//! [`AccountManager::unlock`] (a one-field form), which runs the full
//! login + merge + sync path.
//!
//! Passwords exist only as arguments: never in results, never persisted,
//! never logged (invariant 6 discipline — same for session tokens).

use zeroize::Zeroizing;

use node_runtime::account_crypto as crypto;
use node_runtime::account_remote::{
    AccountClient, AccountError, LoginOutcome, LoginSalts, RosterBlob, SessionToken,
};
use protocol::account::{
    ROSTER_MAX_CIPHERTEXT_BYTES, ROSTER_MAX_COMPUTERS, RosterDoc, RosterEntry, error_code,
    valid_username,
};

use crate::credstore::{SessionStore, WindowsCredStore};
use crate::store::{AccountDoc, Favorite, LocalStore, RosterCacheDoc};
const NOT_LOGGED_IN: &str = "Not signed in — unlock or sign in first.";
const KEY_MATERIAL_DAMAGED: &str = "account key material damaged — re-register required (the saved computer list cannot be \
     decrypted on this machine)";

/// Password policy (the only one): 8..=128 characters.
const PASSWORD_MIN_CHARS: usize = 8;
const PASSWORD_MAX_CHARS: usize = 128;
/// Display-name policy from the roster schema (`RosterEntry::name`).
const NAME_MAX_CHARS: usize = 64;

// ---------------------------------------------------------------------------
// Service seam (tests drive the manager against an in-memory fake; the
// product adapter is a thin wrapper over the blocking ureq client)
// ---------------------------------------------------------------------------

/// The account service surface the manager needs (one method per wire
/// action). Implemented by [`RemoteAccountService`]; tests use a fake.
pub trait AccountService: Send + Sync {
    fn register(
        &self,
        username: &str,
        auth_key_hex: &str,
        auth_salt_hex: &str,
        wrap_salt_hex: &str,
        wrapped_dek_hex: &str,
        dek_nonce_hex: &str,
    ) -> Result<SessionToken, AccountError>;
    fn login_pre(&self, username: &str) -> Result<LoginSalts, AccountError>;
    fn login(&self, username: &str, auth_key_hex: &str) -> Result<LoginOutcome, AccountError>;
    fn logout(&self, token: &SessionToken) -> Result<(), AccountError>;
    fn roster_get(&self, token: &SessionToken) -> Result<RosterBlob, AccountError>;
    fn roster_put(
        &self,
        token: &SessionToken,
        ciphertext_hex: &str,
        nonce_hex: &str,
        base_version: u32,
    ) -> Result<u32, AccountError>;
    fn presence(&self, token: &SessionToken, codes: &[String])
    -> Result<Vec<String>, AccountError>;
}

/// Product adapter over `node_runtime::account_remote::AccountClient`.
pub struct RemoteAccountService {
    client: AccountClient,
}

impl RemoteAccountService {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: AccountClient::new(base_url),
        }
    }
}

impl AccountService for RemoteAccountService {
    fn register(
        &self,
        username: &str,
        auth_key_hex: &str,
        auth_salt_hex: &str,
        wrap_salt_hex: &str,
        wrapped_dek_hex: &str,
        dek_nonce_hex: &str,
    ) -> Result<SessionToken, AccountError> {
        self.client.register(
            username,
            auth_key_hex,
            auth_salt_hex,
            wrap_salt_hex,
            wrapped_dek_hex,
            dek_nonce_hex,
        )
    }

    fn login_pre(&self, username: &str) -> Result<LoginSalts, AccountError> {
        self.client.login_pre(username)
    }

    fn login(&self, username: &str, auth_key_hex: &str) -> Result<LoginOutcome, AccountError> {
        self.client.login(username, auth_key_hex)
    }

    fn logout(&self, token: &SessionToken) -> Result<(), AccountError> {
        self.client.logout(token)
    }

    fn roster_get(&self, token: &SessionToken) -> Result<RosterBlob, AccountError> {
        self.client.roster_get(token)
    }

    fn roster_put(
        &self,
        token: &SessionToken,
        ciphertext_hex: &str,
        nonce_hex: &str,
        base_version: u32,
    ) -> Result<u32, AccountError> {
        self.client
            .roster_put(token, ciphertext_hex, nonce_hex, base_version)
    }

    fn presence(
        &self,
        token: &SessionToken,
        codes: &[String],
    ) -> Result<Vec<String>, AccountError> {
        self.client.presence(token, codes)
    }
}

// ---------------------------------------------------------------------------
// Pure logic (unit-tested without I/O)
// ---------------------------------------------------------------------------

/// Trim + lowercase (the wire rules are lowercase-only).
pub fn normalize_username(raw: &str) -> Result<String, String> {
    let username = raw.trim().to_lowercase();
    if valid_username(&username) {
        Ok(username)
    } else {
        Err(
            "Username must be 3–32 characters: lowercase letters, digits, dots, underscores or \
             hyphens, starting with a letter or digit."
                .to_owned(),
        )
    }
}

fn validate_password(password: &str) -> Result<(), String> {
    let len = password.chars().count();
    if (PASSWORD_MIN_CHARS..=PASSWORD_MAX_CHARS).contains(&len) {
        Ok(())
    } else {
        Err(format!(
            "Password must be {PASSWORD_MIN_CHARS}–{PASSWORD_MAX_CHARS} characters."
        ))
    }
}

fn validate_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    let len = name.chars().count();
    if len == 0 {
        Err("Enter a name.".to_owned())
    } else if len > NAME_MAX_CHARS {
        Err(format!("Name must be at most {NAME_MAX_CHARS} characters."))
    } else {
        Ok(name.to_owned())
    }
}

/// Union two roster docs by `code`: a code present in both keeps the entry
/// with the greater `updated_at_ms` (ties → `server`, the canonical copy).
/// Entries are never dropped by the merge itself; the result is capped at
/// [`ROSTER_MAX_COMPUTERS`] (server entries first) so a put stays within
/// the wire bound.
pub fn merge_rosters(server: Option<&RosterDoc>, local: Option<&RosterDoc>) -> RosterDoc {
    let mut out: Vec<RosterEntry> = Vec::new();
    if let Some(doc) = server {
        for entry in &doc.computers {
            if !out.iter().any(|e| e.code == entry.code) {
                out.push(entry.clone());
            }
        }
    }
    if let Some(doc) = local {
        for entry in &doc.computers {
            match out.iter().position(|e| e.code == entry.code) {
                None => out.push(entry.clone()),
                Some(index) => {
                    if entry.updated_at_ms > out[index].updated_at_ms {
                        out[index] = entry.clone();
                    }
                }
            }
        }
    }
    out.truncate(ROSTER_MAX_COMPUTERS);
    RosterDoc::v1(out)
}

/// Guest-mode favorites join the merge as a lowest-precedence third input:
/// codes already in the roster win (their `updated_at_ms` is real), codes
/// only known locally are added so nothing a user saved while signed out
/// is lost when the roster writes favorites back.
pub fn union_favorites(doc: RosterDoc, favorites: &[Favorite], now_ms: u64) -> RosterDoc {
    let mut computers = doc.computers;
    for favorite in favorites {
        let code = favorite.code.trim().to_lowercase();
        if !code.is_empty() && !computers.iter().any(|e| e.code == code) {
            computers.push(RosterEntry {
                id: favorite.id.clone(),
                name: favorite.name.clone(),
                code,
                added_at_ms: now_ms,
                updated_at_ms: now_ms,
            });
        }
    }
    computers.truncate(ROSTER_MAX_COMPUTERS);
    RosterDoc::v1(computers)
}

/// One roster entry per favorite (the register-time import): id/name/code
/// are kept, `added_at_ms = updated_at_ms = now`.
pub fn import_favorites(favorites: &[Favorite], now_ms: u64) -> Vec<RosterEntry> {
    favorites
        .iter()
        .filter(|f| !f.code.trim().is_empty())
        .map(|f| RosterEntry {
            id: f.id.clone(),
            name: f.name.clone(),
            code: f.code.trim().to_lowercase(),
            added_at_ms: now_ms,
            updated_at_ms: now_ms,
        })
        .collect()
}

/// The write-back direction: roster → favorites (id/name/code kept).
pub fn roster_to_favorites(doc: &RosterDoc) -> Vec<Favorite> {
    doc.computers
        .iter()
        .map(|e| Favorite {
            id: e.id.clone(),
            name: e.name.clone(),
            code: e.code.clone(),
        })
        .collect()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn crypto_err(err: crypto::AccountCryptoError) -> String {
    err.to_string()
}

/// Map a service error onto user-facing copy. The machine-readable code
/// stays embedded (the React layer maps `username_taken`,
/// `invalid_credentials`, `rate_limited` to its own friendly copy).
fn service_err(err: AccountError) -> String {
    err.to_string()
}

fn is_unauthorized(err: &AccountError) -> bool {
    match err {
        AccountError::Api { status, code, .. } => {
            *status == 401 || code == error_code::UNAUTHORIZED
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/// A live login: DEK + token live ONLY here (memory), dropped on logout
/// and on app exit.
struct Session {
    username: String,
    dek: Zeroizing<[u8; crypto::KEY_LEN]>,
    token: SessionToken,
    expires_ms: u64,
    /// Last-known server roster version (put base version).
    server_version: u32,
    /// Decrypted working copy of the roster.
    doc: RosterDoc,
}

/// One saved computer with the "this machine" flag resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputerRow {
    pub id: String,
    pub name: String,
    pub code: String,
    pub added_at_ms: u64,
    pub updated_at_ms: u64,
    pub is_self: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputersList {
    pub computers: Vec<ComputerRow>,
    pub server_version: u32,
}

/// What [`AccountManager::restore`] reports for a saved account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedAccount {
    pub username: String,
    /// Whether the persisted session token still authenticates. When
    /// false the UI still shows the one-field unlock form (a fresh login
    /// re-mints the session); the roster stays encrypted either way.
    pub session_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountStatus {
    LoggedOut,
    SavedAccount { username: String },
    LoggedIn { username: String, expires_ms: u64 },
}

pub struct AccountManager {
    base_url: String,
    /// True when constructed with a custom service (tests): URL changes
    /// are recorded but never swap the service out.
    pinned_service: bool,
    service: Box<dyn AccountService>,
    creds: Box<dyn SessionStore>,
    session: Option<Session>,
    /// Lazy-restore guard (security review P3 availability): the startup
    /// session validation runs inside the first `account_state` command —
    /// a Tauri worker thread — instead of the setup hook, so a blackholed
    /// network can never delay the window.
    pub(crate) restored: bool,
}

impl AccountManager {
    /// The product manager: remote service + Windows Credential Manager.
    pub fn remote(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_owned(),
            pinned_service: false,
            service: Box::new(RemoteAccountService::new(base_url)),
            creds: Box::new(WindowsCredStore),
            session: None,
            restored: false,
        }
    }

    /// Test constructor: injected service + credential store.
    pub fn with_service(service: Box<dyn AccountService>, creds: Box<dyn SessionStore>) -> Self {
        Self {
            base_url: String::new(),
            pinned_service: true,
            service,
            creds,
            session: None,
            restored: false,
        }
    }

    /// Pick up signaling-URL changes without an app restart (rebuilds the
    /// adapter only when the URL actually changed and the service is not
    /// pinned).
    pub fn set_base_url(&mut self, base_url: &str) {
        let changed = base_url != self.base_url;
        self.base_url = base_url.to_owned();
        if changed && !self.pinned_service {
            self.service = Box::new(RemoteAccountService::new(base_url));
        }
    }

    /// Current state for the UI. `saved_account` = account.json exists but
    /// no live login (the unlock form).
    pub fn status(&self, store: &LocalStore) -> AccountStatus {
        if let Some(session) = &self.session {
            return AccountStatus::LoggedIn {
                username: session.username.clone(),
                expires_ms: session.expires_ms,
            };
        }
        match store.account() {
            Some(doc) => AccountStatus::SavedAccount {
                username: doc.username.clone(),
            },
            None => AccountStatus::LoggedOut,
        }
    }

    fn session_mut(&mut self) -> Result<&mut Session, String> {
        self.session
            .as_mut()
            .ok_or_else(|| NOT_LOGGED_IN.to_owned())
    }

    /// Create an account and log in. The current favorites are imported as
    /// the initial roster (one entry each), encrypted, and uploaded; then
    /// everything persists (account.json, roster.json, credential token).
    pub fn register(
        &mut self,
        store: &mut LocalStore,
        username: &str,
        password: &str,
    ) -> Result<AccountStatus, String> {
        let username = normalize_username(username)?;
        validate_password(password)?;
        self.retire_previous_session(&username);

        let material = crypto::generate_account_material();
        // Password equivalent — zeroized on drop (security review P3).
        let auth_key = Zeroizing::new(
            crypto::derive_auth_key_hex(password, &material.auth_salt).map_err(crypto_err)?,
        );
        let kek = crypto::derive_kek(password, &material.wrap_salt).map_err(crypto_err)?;
        let (wrapped, nonce) =
            crypto::wrap_dek(&kek, &material.dek, &username).map_err(crypto_err)?;
        let (auth_salt_hex, wrap_salt_hex) = (
            crypto::encode_hex(&material.auth_salt),
            crypto::encode_hex(&material.wrap_salt),
        );
        let (wrapped_hex, nonce_hex) = (crypto::encode_hex(&wrapped), crypto::encode_hex(&nonce));
        let token = self
            .service
            .register(
                &username,
                &auth_key,
                &auth_salt_hex,
                &wrap_salt_hex,
                &wrapped_hex,
                &nonce_hex,
            )
            .map_err(service_err)?;

        let doc = RosterDoc::v1(import_favorites(store.favorites(), now_ms()));
        self.session = Some(Session {
            username: username.clone(),
            dek: material.dek,
            token,
            expires_ms: 0, // the register response carries no expiry
            server_version: 0,
            doc,
        });
        // Persist exactly the material the server stores (account.json is
        // the local mirror of the register request's key material).
        store
            .save_account(AccountDoc {
                v: 1,
                username: username.clone(),
                auth_salt_hex,
                wrap_salt_hex,
                wrapped_dek_hex: wrapped_hex,
                dek_nonce_hex: nonce_hex,
            })
            .map_err(|e| format!("save account.json: {e}"))?;
        self.creds
            .save(
                &username,
                self.session.as_ref().expect("just set").token.secret(),
            )
            .map_err(|e| format!("credential manager: {e}"))?;
        self.sync_roster(store)?;
        Ok(self.status(store))
    }

    /// Log in: fetch salts, prove the password, unwrap the DEK, merge the
    /// server roster with the local encrypted cache (and any favorites
    /// saved while signed out), upload on divergence, persist everything.
    pub fn login(
        &mut self,
        store: &mut LocalStore,
        username: &str,
        password: &str,
    ) -> Result<AccountStatus, String> {
        let username = normalize_username(username)?;
        validate_password(password)?;

        self.retire_previous_session(&username);
        let salts = self.service.login_pre(&username).map_err(service_err)?;
        let auth_salt = crypto::decode_hex(&salts.auth_salt_hex, crypto::SALT_LEN, "auth salt")
            .map_err(crypto_err)?;
        let wrap_salt = crypto::decode_hex(&salts.wrap_salt_hex, crypto::SALT_LEN, "wrap salt")
            .map_err(crypto_err)?;
        // Password equivalent — zeroized on drop (security review P3).
        let auth_key =
            Zeroizing::new(crypto::derive_auth_key_hex(password, &auth_salt).map_err(crypto_err)?);
        let outcome = self
            .service
            .login(&username, &auth_key)
            .map_err(service_err)?;
        self.finish_login(store, username, password, &wrap_salt, outcome, &salts)
    }

    /// The saved-account re-entry: full login with the stored username.
    pub fn unlock(
        &mut self,
        store: &mut LocalStore,
        password: &str,
    ) -> Result<AccountStatus, String> {
        let username = store
            .account()
            .map(|doc| doc.username.clone())
            .ok_or_else(|| "No saved account on this machine.".to_owned())?;
        self.login(store, &username, password)
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_login(
        &mut self,
        store: &mut LocalStore,
        username: String,
        password: &str,
        wrap_salt: &[u8],
        outcome: LoginOutcome,
        salts: &LoginSalts,
    ) -> Result<AccountStatus, String> {
        let kek = crypto::derive_kek(password, wrap_salt).map_err(crypto_err)?;
        let wrapped = crypto::decode_hex(
            &outcome.wrapped_dek_hex,
            crypto::KEY_LEN + 16,
            "wrapped dek",
        )
        .map_err(crypto_err)?;
        let nonce: [u8; crypto::NONCE_LEN] =
            crypto::decode_hex(&outcome.dek_nonce_hex, crypto::NONCE_LEN, "dek nonce")
                .map_err(crypto_err)?
                .try_into()
                .expect("NONCE_LEN bytes");
        // Unwrap failure AFTER a successful login means the stored key
        // material is damaged (a wrong password was rejected by the
        // service earlier) — surfaced with its own message.
        let dek = crypto::unwrap_dek(&kek, &wrapped, &nonce, &username)
            .map_err(|_| KEY_MATERIAL_DAMAGED.to_owned())?;

        // Server roster (authoritative) …
        let server_blob = self
            .service
            .roster_get(&outcome.token)
            .map_err(service_err)?;
        let server_doc = decrypt_blob(&dek, &username, &server_blob)?;
        // … merged with the local encrypted cache …
        let local_doc = self.decrypt_cache(store, &dek, &username);
        let merged = merge_rosters(server_doc.as_ref(), local_doc.as_ref());
        // … plus anything saved as a favorite while signed out.
        let merged = union_favorites(merged, store.favorites(), now_ms());

        self.session = Some(Session {
            username: username.clone(),
            dek,
            token: outcome.token.clone(),
            expires_ms: outcome.expires_ms,
            server_version: server_blob.version,
            doc: merged,
        });

        if self.session.as_ref().map(|s| &s.doc) == server_doc.as_ref() {
            // Nothing diverged: cache the server blob as-is + write the
            // favorites back.
            let cache_username = username.clone();
            store
                .save_roster_cache(RosterCacheDoc {
                    v: 1,
                    username: cache_username,
                    ciphertext_hex: server_blob.ciphertext_hex,
                    nonce_hex: server_blob.nonce_hex,
                    version: server_blob.version,
                })
                .map_err(|e| format!("save roster.json: {e}"))?;
            if let Some(session) = self.session.as_ref() {
                store
                    .replace_favorites(roster_to_favorites(&session.doc))
                    .map_err(|e| format!("save favorites.json: {e}"))?;
            }
        } else {
            self.sync_roster(store)?;
        }

        // Persist the account material (the login_pre salts + the wrapped
        // DEK echoed by login) and the session token (credential manager)
        // so the next launch offers the unlock form.
        store
            .save_account(AccountDoc {
                v: 1,
                username: username.clone(),
                auth_salt_hex: salts.auth_salt_hex.clone(),
                wrap_salt_hex: salts.wrap_salt_hex.clone(),
                wrapped_dek_hex: outcome.wrapped_dek_hex.clone(),
                dek_nonce_hex: outcome.dek_nonce_hex.clone(),
            })
            .map_err(|e| format!("save account.json: {e}"))?;
        self.creds
            .save(&username, outcome.token.secret())
            .map_err(|e| format!("credential manager: {e}"))?;
        Ok(self.status(store))
    }

    /// Account switch (security review P3): logging in as a different user
    /// must not leave the previous user's live bearer token in the
    /// credential vault — best-effort service logout + vault clear.
    fn retire_previous_session(&mut self, new_username: &str) {
        if let Some(old) = &self.session
            && old.username != new_username
        {
            let _ = self.service.logout(&old.token);
            let _ = self.creds.clear(&old.username);
        }
    }

    /// Startup: if account.json exists, report the saved username and
    /// whether the persisted session token still authenticates. This
    /// deliberately does NOT decrypt the roster (impossible without the
    /// password) and does not mutate any state beyond clearing a dead
    /// credential.
    pub fn restore(&mut self, store: &LocalStore) -> Option<SavedAccount> {
        if self.session.is_some() {
            // A live session supersedes startup validation (the user logged
            // in before the lazy restore ran) — never clobber it.
            return None;
        }
        self.session = None;
        let doc = store.account()?;
        let username = doc.username.clone();
        let invalid = || SavedAccount {
            username: username.clone(),
            session_valid: false,
        };
        if self.base_url.trim().is_empty() {
            return Some(invalid()); // no service configured — cannot check
        }
        let token_hex = match self.creds.load(&username) {
            Ok(Some(token)) => token,
            Ok(None) => return Some(invalid()),
            Err(err) => {
                eprintln!("account: credential manager read failed: {err}");
                return Some(invalid());
            }
        };
        let Ok(token) = SessionToken::from_persisted(&token_hex) else {
            let _ = self.creds.clear(&username);
            return Some(invalid());
        };
        match self.service.roster_get(&token) {
            Ok(_) => Some(SavedAccount {
                username,
                session_valid: true,
            }),
            Err(err) if is_unauthorized(&err) => {
                // Dead session: drop the credential, keep account.json
                // (the user can log in again).
                let _ = self.creds.clear(&username);
                Some(invalid())
            }
            Err(err) => {
                // Network unknown — keep the token for the next launch.
                eprintln!("account: session check failed: {err}");
                Some(invalid())
            }
        }
    }

    /// Invalidate the session. Network failures on the service call are
    /// ignored; the local credential is cleared and in-memory keys are
    /// dropped. account.json + roster.json stay (the encrypted list is
    /// kept for the next login).
    pub fn logout(&mut self, store: &LocalStore) -> AccountStatus {
        if let Some(session) = self.session.take() {
            let _ = self.service.logout(&session.token);
            let _ = self.creds.clear(&session.username);
        }
        self.status(store)
    }

    /// The decrypted list with the "this computer" flag resolved.
    pub fn computers(&self, device_id: &str) -> Result<ComputersList, String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| NOT_LOGGED_IN.to_owned())?;
        Ok(ComputersList {
            computers: session
                .doc
                .computers
                .iter()
                .map(|entry| ComputerRow {
                    id: entry.id.clone(),
                    name: entry.name.clone(),
                    code: entry.code.clone(),
                    added_at_ms: entry.added_at_ms,
                    updated_at_ms: entry.updated_at_ms,
                    is_self: entry.code == device_id,
                })
                .collect(),
            server_version: session.server_version,
        })
    }

    /// Add a computer by code. Dedupe: an existing code is renamed and
    /// `updated_at_ms` bumped instead of duplicated.
    pub fn add_computer(
        &mut self,
        store: &mut LocalStore,
        device_id: &str,
        name: &str,
        code: &str,
    ) -> Result<ComputersList, String> {
        let code = code.trim().to_lowercase();
        if code.is_empty() {
            return Err("Enter a connection code.".to_owned());
        }
        let provided = validate_name(name)?;
        let now = now_ms();
        let session = self.session_mut()?;
        match session.doc.computers.iter_mut().find(|e| e.code == code) {
            Some(entry) => {
                entry.name = provided;
                entry.updated_at_ms = now;
            }
            None => {
                if session.doc.computers.len() >= ROSTER_MAX_COMPUTERS {
                    return Err(format!(
                        "Your computers list is full ({ROSTER_MAX_COMPUTERS}). Remove one first."
                    ));
                }
                session.doc.computers.push(RosterEntry {
                    id: new_roster_id(),
                    name: provided,
                    code,
                    added_at_ms: now,
                    updated_at_ms: now,
                });
            }
        }
        self.sync_roster(store)?;
        self.computers(device_id)
    }

    /// Add THIS machine (identity code + display name). If already
    /// present, only `updated_at_ms` is bumped.
    pub fn add_this_computer(
        &mut self,
        store: &mut LocalStore,
        device_id: &str,
        device_name: &str,
    ) -> Result<ComputersList, String> {
        let name = validate_name(device_name)?;
        let now = now_ms();
        let session = self.session_mut()?;
        match session
            .doc
            .computers
            .iter_mut()
            .find(|e| e.code == device_id)
        {
            Some(entry) => entry.updated_at_ms = now,
            None => {
                if session.doc.computers.len() >= ROSTER_MAX_COMPUTERS {
                    return Err(format!(
                        "Your computers list is full ({ROSTER_MAX_COMPUTERS}). Remove one first."
                    ));
                }
                session.doc.computers.push(RosterEntry {
                    id: new_roster_id(),
                    name,
                    code: device_id.to_owned(),
                    added_at_ms: now,
                    updated_at_ms: now,
                });
            }
        }
        self.sync_roster(store)?;
        self.computers(device_id)
    }

    pub fn remove_computer(
        &mut self,
        store: &mut LocalStore,
        device_id: &str,
        id: &str,
    ) -> Result<ComputersList, String> {
        let session = self.session_mut()?;
        let before = session.doc.computers.len();
        session.doc.computers.retain(|e| e.id != id);
        if session.doc.computers.len() == before {
            return Err("Computer not found.".to_owned());
        }
        self.sync_roster(store)?;
        self.computers(device_id)
    }

    pub fn rename_computer(
        &mut self,
        store: &mut LocalStore,
        device_id: &str,
        id: &str,
        name: &str,
    ) -> Result<ComputersList, String> {
        let name = validate_name(name)?;
        let session = self.session_mut()?;
        let entry = session
            .doc
            .computers
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| "Computer not found.".to_owned())?;
        entry.name = name;
        entry.updated_at_ms = now_ms();
        self.sync_roster(store)?;
        self.computers(device_id)
    }

    /// Which of the roster's non-self codes are online (capped at the
    /// presence wire bound).
    pub fn presence(&self) -> Result<Vec<String>, String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| NOT_LOGGED_IN.to_owned())?;
        let codes: Vec<String> = session
            .doc
            .computers
            .iter()
            .map(|e| e.code.clone())
            .take(protocol::account::PRESENCE_MAX_CODES)
            .collect();
        if codes.is_empty() {
            return Ok(Vec::new());
        }
        self.service
            .presence(&session.token, &codes)
            .map_err(service_err)
    }

    // -- internals ----------------------------------------------------------

    /// Re-encrypt the working doc, upload it (one conflict re-merge retry),
    /// then persist the encrypted cache + the favorites write-back. A put
    /// that fails for non-conflict reasons (offline) still persists
    /// locally: the cache diverges, and the next login/mutation merges the
    /// union back up (entries are never lost).
    fn sync_roster(&mut self, store: &mut LocalStore) -> Result<(), String> {
        let service = self.service.as_ref();
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| NOT_LOGGED_IN.to_owned())?;
        if session.doc.computers.len() > ROSTER_MAX_COMPUTERS {
            return Err(format!(
                "Your computers list is full ({ROSTER_MAX_COMPUTERS}). Remove one first."
            ));
        }
        let (mut ciphertext_hex, mut nonce_hex) =
            encrypt_doc(&session.dek, &session.username, &session.doc)?;
        match service.roster_put(
            &session.token,
            &ciphertext_hex,
            &nonce_hex,
            session.server_version,
        ) {
            Ok(version) => session.server_version = version,
            Err(err) if err.is_roster_conflict() => {
                // Someone else uploaded first: re-fetch, re-merge, retry once.
                let blob = service.roster_get(&session.token).map_err(service_err)?;
                let server_doc = decrypt_blob(&session.dek, &session.username, &blob)?;
                session.doc = merge_rosters(server_doc.as_ref(), Some(&session.doc));
                let (ct, nonce) = encrypt_doc(&session.dek, &session.username, &session.doc)?;
                let version = service
                    .roster_put(&session.token, &ct, &nonce, blob.version)
                    .map_err(service_err)?;
                session.server_version = version;
                ciphertext_hex = ct;
                nonce_hex = nonce;
            }
            Err(err) => {
                eprintln!("account: roster upload failed, keeping local cache: {err}");
            }
        }
        store
            .save_roster_cache(RosterCacheDoc {
                v: 1,
                username: session.username.clone(),
                ciphertext_hex,
                nonce_hex,
                version: session.server_version,
            })
            .map_err(|e| format!("save roster.json: {e}"))?;
        store
            .replace_favorites(roster_to_favorites(&session.doc))
            .map_err(|e| format!("save favorites.json: {e}"))
    }

    /// Local cache decrypt: a corrupt/unopenable cache is logged and
    /// treated as absent (the server copy is authoritative and the merge
    /// would restore the entries anyway).
    fn decrypt_cache(
        &self,
        store: &LocalStore,
        dek: &Zeroizing<[u8; crypto::KEY_LEN]>,
        username: &str,
    ) -> Option<RosterDoc> {
        let cache = store.roster_cache()?;
        if cache.username != username {
            return None;
        }
        let blob = RosterBlob {
            ciphertext_hex: cache.ciphertext_hex.clone(),
            nonce_hex: cache.nonce_hex.clone(),
            version: cache.version,
        };
        match decrypt_blob(dek, username, &blob) {
            Ok(doc) => doc,
            Err(err) => {
                eprintln!("account: ignoring unreadable local roster cache: {err}");
                None
            }
        }
    }
}

/// Encrypt a roster doc to the wire shape (hex + fresh nonce).
fn encrypt_doc(
    dek: &Zeroizing<[u8; crypto::KEY_LEN]>,
    username: &str,
    doc: &RosterDoc,
) -> Result<(String, String), String> {
    let plaintext = serde_json::to_vec(doc).map_err(|e| format!("serialize roster: {e}"))?;
    if plaintext.len() > ROSTER_MAX_CIPHERTEXT_BYTES {
        return Err("The computer list is too large to sync.".to_owned());
    }
    let (ct, nonce) = crypto::encrypt_roster(dek, &plaintext, username).map_err(crypto_err)?;
    Ok((crypto::encode_hex(&ct), crypto::encode_hex(&nonce)))
}

/// Decrypt a stored blob; `None` for an empty roster (version 0).
fn decrypt_blob(
    dek: &Zeroizing<[u8; crypto::KEY_LEN]>,
    username: &str,
    blob: &RosterBlob,
) -> Result<Option<RosterDoc>, String> {
    if blob.version == 0 || blob.ciphertext_hex.is_empty() {
        return Ok(None);
    }
    // Bound the server-controlled blob before decoding it (defense against
    // a hostile service forcing a huge allocation).
    if blob.ciphertext_hex.len() / 2 > ROSTER_MAX_CIPHERTEXT_BYTES {
        return Err("The saved computer list is too large to be valid.".to_owned());
    }
    let ct = crypto::decode_hex(
        &blob.ciphertext_hex,
        blob.ciphertext_hex.len() / 2,
        "roster",
    )
    .map_err(crypto_err)?;
    let nonce: [u8; crypto::NONCE_LEN] =
        crypto::decode_hex(&blob.nonce_hex, crypto::NONCE_LEN, "roster nonce")
            .map_err(crypto_err)?
            .try_into()
            .expect("NONCE_LEN bytes");
    let plaintext = crypto::decrypt_roster(dek, &ct, &nonce, username)
        .map_err(|_| "The saved computer list could not be decrypted.".to_owned())?;
    serde_json::from_slice(&plaintext)
        .map(Some)
        .map_err(|e| format!("The saved computer list is damaged (unreadable): {e}"))
}

fn new_roster_id() -> String {
    crate::engine::ids::new_device_id()[..8].to_owned()
}

#[cfg(test)]
mod tests;
