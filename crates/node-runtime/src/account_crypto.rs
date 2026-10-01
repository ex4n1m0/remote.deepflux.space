//! Client-side account cryptography (post-MVP accounts & roster).
//!
//! Implements the envelope described in `protocol::account`'s module docs:
//!
//! * `auth_key = scrypt(password, auth_salt)` — the password equivalent sent
//!   to the server (which stores only a second-layer scrypt verifier);
//! * `kek = scrypt(password, wrap_salt)` — never leaves this process;
//! * `dek` — the per-user random 32-byte data key minted at registration,
//!   stored server-side only in AES-256-GCM-wrapped form;
//! * the roster itself is AES-256-GCM ciphertext under the DEK, so neither
//!   the service nor a store leak can read a user's saved computers.
//!
//! All key material is held in [`zeroize::Zeroizing`] buffers; nothing in
//! this module logs or `Debug`-prints key bytes (invariant 6 discipline).
//! The AAD strings bind ciphertexts to the username so blobs cannot be
//! swapped between accounts.
//!
//! Wire-side parameters (hex lengths, salt/nonce sizes, roster caps) live in
//! `protocol::account` and are re-used here for validation.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use scrypt::Params;
use zeroize::Zeroizing;

/// scrypt cost for both client-side derivations (N = 2^15 = 32768, r=8, p=1
/// → 32 MiB per call). The server's second-layer verifier uses its own
/// cheaper parameters; both sides' constants are pinned by the account
/// fixtures and `docs/adr/ADR-003-accounts-and-roster.md`.
pub const SCRYPT_LOG_N: u8 = 15;
pub const SCRYPT_R: u32 = 8;
pub const SCRYPT_P: u32 = 1;

/// Derived-key and DEK length (AES-256).
pub const KEY_LEN: usize = 32;
/// Salt length (hex on the wire: 32 chars, see `protocol::account`).
pub const SALT_LEN: usize = 16;
/// AES-GCM nonce length (hex on the wire: 24 chars).
pub const NONCE_LEN: usize = 12;

/// Typed crypto failures. `UnwrapAuth` means a wrapped DEK did not open —
/// after a successful server-side login that indicates corrupted stored key
/// material (a wrong password is rejected earlier by the server), which the
/// app surfaces as "account key material damaged — re-register required".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountCryptoError {
    Kdf,
    Wrap,
    Unwrap,
    Roster,
    BadHex(String),
}

impl core::fmt::Display for AccountCryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AccountCryptoError::Kdf => write!(f, "scrypt derivation failed"),
            AccountCryptoError::Wrap => write!(f, "AES-GCM wrap failed"),
            AccountCryptoError::Unwrap => {
                write!(f, "AES-GCM unwrap failed (wrong key or corrupted material)")
            }
            AccountCryptoError::Roster => write!(f, "roster encrypt/decrypt failed"),
            AccountCryptoError::BadHex(what) => write!(f, "bad hex ({what})"),
        }
    }
}

impl std::error::Error for AccountCryptoError {}

fn scrypt_params() -> Result<Params, AccountCryptoError> {
    Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, KEY_LEN).map_err(|_| AccountCryptoError::Kdf)
}

/// scrypt(password, salt) → 32 bytes, zeroized on drop.
fn kdf(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, AccountCryptoError> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    scrypt::scrypt(password.as_bytes(), salt, &scrypt_params()?, out.as_mut())
        .map_err(|_| AccountCryptoError::Kdf)?;
    Ok(out)
}

/// The password equivalent sent to the server at register/login (lowercase
/// hex, `AUTH_KEY_HEX_LEN` chars).
pub fn derive_auth_key_hex(password: &str, auth_salt: &[u8]) -> Result<String, AccountCryptoError> {
    let key = kdf(password, auth_salt)?;
    Ok(hex::encode(key.as_ref()))
}

/// The key-encryption key wrapping the DEK. Never serialized, never sent.
pub fn derive_kek(
    password: &str,
    wrap_salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, AccountCryptoError> {
    kdf(password, wrap_salt)
}

/// Fresh random bytes (OS CSPRNG; hard failure on exhaustion — same policy
/// as `engine/ids.rs`/`signaling_remote`).
fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).expect("OS CSPRNG unavailable");
    buf
}

/// Random lowercase hex of `bytes` bytes (ids, nonces are re-randomized by
/// callers that need fresh ones).
pub fn random_hex(bytes: usize) -> String {
    hex::encode(random_bytes(bytes))
}

/// Client-generated account material minted at registration: two KDF salts
/// and the per-user random DEK (the "random key generated per user").
pub struct AccountMaterial {
    pub auth_salt: [u8; SALT_LEN],
    pub wrap_salt: [u8; SALT_LEN],
    pub dek: Zeroizing<[u8; KEY_LEN]>,
}

impl core::fmt::Debug for AccountMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AccountMaterial(<redacted>)")
    }
}

pub fn generate_account_material() -> AccountMaterial {
    let auth_salt = random_bytes(SALT_LEN);
    let wrap_salt = random_bytes(SALT_LEN);
    // Zeroizing intermediate (security review): the fresh DEK must not sit
    // in a plain Vec that is freed un-wiped.
    let dek = Zeroizing::new(random_bytes(KEY_LEN));
    let mut dek_arr = Zeroizing::new([0u8; KEY_LEN]);
    dek_arr.copy_from_slice(&dek);
    AccountMaterial {
        auth_salt: auth_salt.try_into().expect("SALT_LEN bytes"),
        wrap_salt: wrap_salt.try_into().expect("SALT_LEN bytes"),
        dek: dek_arr,
    }
}

fn dek_aad(username: &str) -> Vec<u8> {
    format!("acct-dek:v1:{username}").into_bytes()
}

fn roster_aad(username: &str) -> Vec<u8> {
    format!("roster:v1:{username}").into_bytes()
}

fn cipher_for(key: &[u8; KEY_LEN]) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
}

/// Wrap the DEK under the KEK. Returns `(ciphertext, nonce)`; the nonce is
/// fresh random per wrap (safe: one wrap per password-lifetime).
pub fn wrap_dek(
    kek: &[u8; KEY_LEN],
    dek: &[u8; KEY_LEN],
    username: &str,
) -> Result<(Vec<u8>, [u8; NONCE_LEN]), AccountCryptoError> {
    let nonce_bytes = random_bytes(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().expect("NONCE_LEN bytes");
    let ct = cipher_for(kek)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: dek,
                aad: &dek_aad(username),
            },
        )
        .map_err(|_| AccountCryptoError::Wrap)?;
    Ok((ct, nonce))
}

/// Open the stored wrapped DEK. Fails closed on any byte of drift (GCM tag).
pub fn unwrap_dek(
    kek: &[u8; KEY_LEN],
    wrapped: &[u8],
    nonce: &[u8; NONCE_LEN],
    username: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>, AccountCryptoError> {
    // Zeroizing intermediate (security review): without it the decrypted
    // DEK sits in a plain Vec that is freed un-wiped.
    let pt = Zeroizing::new(
        cipher_for(kek)
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: wrapped,
                    aad: &dek_aad(username),
                },
            )
            .map_err(|_| AccountCryptoError::Unwrap)?,
    );
    let mut dek = Zeroizing::new([0u8; KEY_LEN]);
    dek.copy_from_slice(&pt);
    Ok(dek)
}

/// Encrypt a roster document for storage (server or local cache). Returns
/// `(ciphertext, nonce)` with a fresh nonce per encryption — callers MUST
/// store both.
pub fn encrypt_roster(
    dek: &[u8; KEY_LEN],
    plaintext: &[u8],
    username: &str,
) -> Result<(Vec<u8>, [u8; NONCE_LEN]), AccountCryptoError> {
    let nonce_bytes = random_bytes(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().expect("NONCE_LEN bytes");
    let ct = cipher_for(dek)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &roster_aad(username),
            },
        )
        .map_err(|_| AccountCryptoError::Roster)?;
    Ok((ct, nonce))
}

/// Decrypt a stored roster. Fails closed on tampering or wrong DEK.
pub fn decrypt_roster(
    dek: &[u8; KEY_LEN],
    ciphertext: &[u8],
    nonce: &[u8; NONCE_LEN],
    username: &str,
) -> Result<Vec<u8>, AccountCryptoError> {
    cipher_for(dek)
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &roster_aad(username),
            },
        )
        .map_err(|_| AccountCryptoError::Roster)
}

/// Hex helpers keeping the wire's lowercase-hex convention in one place.
pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn decode_hex(
    value: &str,
    expected_bytes: usize,
    what: &str,
) -> Result<Vec<u8>, AccountCryptoError> {
    let bytes = hex::decode(value).map_err(|_| AccountCryptoError::BadHex(what.to_owned()))?;
    if bytes.len() != expected_bytes {
        return Err(AccountCryptoError::BadHex(format!(
            "{what}: expected {expected_bytes} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse battery staple";
    const USER: &str = "alice";

    fn salt(seed: u8) -> [u8; SALT_LEN] {
        [seed; SALT_LEN]
    }

    #[test]
    fn kdf_is_deterministic_and_salt_sensitive() {
        let a = derive_auth_key_hex(PW, &salt(1)).expect("kdf");
        let b = derive_auth_key_hex(PW, &salt(1)).expect("kdf");
        let c = derive_auth_key_hex(PW, &salt(2)).expect("kdf");
        let d = derive_auth_key_hex("other", &salt(1)).expect("kdf");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_eq!(a.len(), protocol::account::AUTH_KEY_HEX_LEN);
        assert!(protocol::account::valid_hex(&a, KEY_LEN));
    }

    #[test]
    fn generated_material_is_unique() {
        let m1 = generate_account_material();
        let m2 = generate_account_material();
        assert_ne!(m1.auth_salt, m2.auth_salt);
        assert_ne!(m1.wrap_salt, m2.wrap_salt);
        assert_ne!(m1.dek.as_ref(), m2.dek.as_ref());
        assert_eq!(
            encode_hex(&m1.auth_salt).len(),
            protocol::account::SALT_HEX_LEN
        );
    }

    #[test]
    fn dek_wrap_round_trip_and_failure_modes() {
        let kek = derive_kek(PW, &salt(9)).expect("kek");
        let material = generate_account_material();
        let (wrapped, nonce) = wrap_dek(&kek, &material.dek, USER).expect("wrap");
        assert_eq!(wrapped.len(), KEY_LEN + 16, "ciphertext + GCM tag");

        let opened = unwrap_dek(&kek, &wrapped, &nonce, USER).expect("unwrap");
        assert_eq!(opened.as_ref(), &*material.dek);

        // Wrong password → different KEK → auth failure.
        let wrong = derive_kek("not the password", &salt(9)).expect("kek");
        assert_eq!(
            unwrap_dek(&wrong, &wrapped, &nonce, USER),
            Err(AccountCryptoError::Unwrap)
        );
        // AAD is username-bound: same key, different account → fail.
        assert_eq!(
            unwrap_dek(&kek, &wrapped, &nonce, "mallory"),
            Err(AccountCryptoError::Unwrap)
        );
        // Tampered ciphertext → fail.
        let mut corrupt = wrapped.clone();
        corrupt[0] ^= 1;
        assert_eq!(
            unwrap_dek(&kek, &corrupt, &nonce, USER),
            Err(AccountCryptoError::Unwrap)
        );
    }

    #[test]
    fn roster_round_trip_through_doc_json() {
        use protocol::account::{RosterDoc, RosterEntry};

        let material = generate_account_material();
        let doc = RosterDoc::v1(vec![RosterEntry {
            id: "ab12cd34".to_owned(),
            name: "Desk PC".to_owned(),
            code: "0123456789abcdef".to_owned(),
            added_at_ms: 1,
            updated_at_ms: 2,
        }]);
        let json = serde_json::to_vec(&doc).expect("serialize roster");

        let (ct, nonce) = encrypt_roster(&material.dek, &json, USER).expect("encrypt");
        let mut pt = decrypt_roster(&material.dek, &ct, &nonce, USER).expect("decrypt");
        let back: RosterDoc = serde_json::from_slice(&pt).expect("parse roster");
        assert_eq!(back, doc);
        pt.clear();

        // Wrong account AAD and tampering both fail.
        assert!(decrypt_roster(&material.dek, &ct, &nonce, "bob").is_err());
        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decrypt_roster(&material.dek, &tampered, &nonce, USER).is_err());
    }

    #[test]
    fn hex_codec_enforces_lengths() {
        assert!(decode_hex("0a0b", 2, "test").is_ok());
        assert_eq!(
            decode_hex("0a", 2, "test"),
            Err(AccountCryptoError::BadHex(
                "test: expected 2 bytes, got 1".to_owned()
            ))
        );
        assert!(matches!(
            decode_hex("zz", 1, "test"),
            Err(AccountCryptoError::BadHex(_))
        ));
    }
}
