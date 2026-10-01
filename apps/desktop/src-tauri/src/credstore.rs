//! Session-token persistence: Windows Credential Manager (post-MVP accounts
//! phase; PLAN.md: "token storage in Windows Credential Manager, never
//! plaintext"). One generic credential per username, target name
//! `RemoteDesktop/account-session/<username>`; the blob is the bearer
//! token's hex string. Never logged (invariant 6 discipline — the secret
//! only ever moves between [`SessionStore`] calls and the service header).
//!
//! The Win32 surface is the same reviewed-unsafe pattern as
//! `engine/displays.rs`: confined to this module, every call
//! failure-handled, `CredFree` on the read path. A missing credential is
//! `Ok(None)` (`ERROR_NOT_FOUND`), not an error.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use windows::Win32::Foundation::ERROR_NOT_FOUND;
use windows::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW,
    CredWriteW,
};
use windows::core::{PCWSTR, PWSTR};

/// Narrow seam (invariant-7 style): save/load/clear one secret per
/// username. `WindowsCredStore` is the product impl; the in-memory map is
/// for tests and for profiles where the credential manager is unavailable.
pub trait SessionStore: Send + Sync {
    fn save(&self, username: &str, secret: &str) -> Result<(), String>;
    fn load(&self, username: &str) -> Result<Option<String>, String>;
    fn clear(&self, username: &str) -> Result<(), String>;
}

fn target_name(username: &str) -> String {
    format!("RemoteDesktop/account-session/{username}")
}

/// Null-terminated UTF-16 for the wide-char Win32 APIs.
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

fn is_not_found(err: &windows::core::Error) -> bool {
    err.code() == ERROR_NOT_FOUND.to_hresult()
}

/// Windows Credential Manager (per-user, local machine persistence).
pub struct WindowsCredStore;

impl SessionStore for WindowsCredStore {
    fn save(&self, username: &str, secret: &str) -> Result<(), String> {
        let target = wide(&target_name(username));
        let user = wide(username);
        // CredWriteW copies the blob (CredentialBlobSize bytes) and the
        // strings; the buffers only need to outlive this call.
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            TargetName: PWSTR(target.as_ptr().cast_mut()),
            UserName: PWSTR(user.as_ptr().cast_mut()),
            CredentialBlob: secret.as_ptr().cast_mut(),
            CredentialBlobSize: secret.len() as u32,
            ..CREDENTIALW::default()
        };
        // SAFETY: `credential` is fully initialized above; its pointers are
        // valid for the duration of the call (see CredWriteW contract).
        unsafe { CredWriteW(&credential, 0) }.map_err(|e| format!("CredWriteW: {e}"))
    }

    fn load(&self, username: &str) -> Result<Option<String>, String> {
        let target = wide(&target_name(username));
        let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `credential` is an out-pointer initialized to null; the
        // API replaces it with a buffer the caller must free via CredFree.
        let read = unsafe {
            CredReadW(
                PCWSTR(target.as_ptr()),
                CRED_TYPE_GENERIC,
                None,
                &mut credential,
            )
        };
        match read {
            Ok(()) => {
                // SAFETY: on success `credential` points at one
                // API-allocated CREDENTIALW; we copy the blob out, then
                // free the allocation (both failure paths included).
                let result = unsafe {
                    let cred = &*credential;
                    let blob = std::slice::from_raw_parts(
                        cred.CredentialBlob,
                        cred.CredentialBlobSize as usize,
                    );
                    let out = String::from_utf8(blob.to_vec())
                        .map_err(|e| format!("credential blob is not UTF-8: {e}"));
                    CredFree(credential.cast());
                    out
                };
                result.map(Some)
            }
            Err(err) if is_not_found(&err) => Ok(None),
            Err(err) => Err(format!("CredReadW: {err}")),
        }
    }

    fn clear(&self, username: &str) -> Result<(), String> {
        let target = wide(&target_name(username));
        // SAFETY: `target` is a valid null-terminated wide string for the
        // duration of the call.
        let deleted = unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, None) };
        match deleted {
            Ok(()) => Ok(()),
            // Clearing a credential that is already gone is success.
            Err(err) if is_not_found(&err) => Ok(()),
            Err(err) => Err(format!("CredDeleteW: {err}")),
        }
    }
}

/// In-memory [`SessionStore`] (tests; also the fallback when a profile has
/// no credential manager). No persistence across processes by design;
/// `Clone` shares the same map (several manager instances = one "profile",
/// mirroring how the Windows store persists across app restarts).
#[derive(Default, Clone)]
pub struct InMemorySessionStore {
    entries: Arc<Mutex<HashMap<String, String>>>,
}

impl SessionStore for InMemorySessionStore {
    fn save(&self, username: &str, secret: &str) -> Result<(), String> {
        self.entries
            .lock()
            .expect("credstore")
            .insert(username.to_owned(), secret.to_owned());
        Ok(())
    }

    fn load(&self, username: &str) -> Result<Option<String>, String> {
        Ok(self
            .entries
            .lock()
            .expect("credstore")
            .get(username)
            .cloned())
    }

    fn clear(&self, username: &str) -> Result<(), String> {
        self.entries.lock().expect("credstore").remove(username);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_round_trip_and_clear() {
        let store = InMemorySessionStore::default();
        assert_eq!(store.load("alice").unwrap(), None);
        store.save("alice", "feedbeef").unwrap();
        assert_eq!(store.load("alice").unwrap().as_deref(), Some("feedbeef"));
        // Save replaces (token rotation on re-login).
        store.save("alice", "deadbeef").unwrap();
        assert_eq!(store.load("alice").unwrap().as_deref(), Some("deadbeef"));
        store.clear("alice").unwrap();
        assert_eq!(store.load("alice").unwrap(), None);
        // Clearing a missing entry is success.
        store.clear("bob").unwrap();
    }

    #[test]
    fn target_name_scopes_per_username() {
        assert_eq!(target_name("alice"), "RemoteDesktop/account-session/alice");
    }
}
