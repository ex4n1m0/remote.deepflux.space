//! Pairing proof (ADR-006): the HMAC that makes silent paired accept
//! cryptographically authenticated instead of id-based.
//!
//! Before ADR-006, `auto_accept_if_paired` granted silent full control on
//! the bare controller device id — and device ids are re-claimable through
//! the signaling presence-tombstone window minutes after a machine goes
//! offline, so a squatter could silently take over a family host. The proof
//! is HMAC-SHA256 over a domain-separated string binding controller, host,
//! **and session id** (single-use: a proof observed on one request cannot
//! be replayed onto another), keyed by the 32-byte pairing secret only the
//! two paired machines hold:
//!
//! ```text
//! HMAC-SHA256(secret, "pair-proof:v1|{controller_id}|{host_id}|{session_id}")
//! ```
//!
//! Host rule (app layer): pairing exists **and** proof verifies → silent
//! accept; pairing exists but proof missing/invalid → normal consent prompt
//! with "claimed trusted but could not prove it" copy — fail open to the
//! human, never to accept. A bad secret or proof shape simply fails
//! verification; the proof hex is not secret material (it crosses the
//! control plane inside the `connect_request` envelope), so its `Debug`
//! need not be redacted, but the secret must never be logged.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Domain separator prefix (pinned by tests).
pub const PROOF_DOMAIN: &str = "pair-proof:v1";

type HmacSha256 = Hmac<Sha256>;

fn proof_message(controller_id: &str, host_id: &str, session_id: &str) -> String {
    format!("{PROOF_DOMAIN}|{controller_id}|{host_id}|{session_id}")
}

/// Compute the pairing proof as 64 lowercase hex chars. Returns `None` if
/// the secret is not 64 valid hex chars (fail closed: no proof → the host
/// falls back to the consent prompt).
pub fn pairing_proof_hex(
    secret_hex: &str,
    controller_id: &str,
    host_id: &str,
    session_id: &str,
) -> Option<String> {
    let secret = hex::decode(secret_hex).ok()?;
    if secret.len() != 32 {
        return None;
    }
    let mut mac = HmacSha256::new_from_slice(&secret).ok()?;
    mac.update(proof_message(controller_id, host_id, session_id).as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// Verify a claimed proof. `None` proof, malformed proof hex, wrong
/// secret, or any mismatched domain field → `false`.
pub fn verify_pairing_proof(
    secret_hex: &str,
    controller_id: &str,
    host_id: &str,
    session_id: &str,
    proof_hex: Option<&str>,
) -> bool {
    let Some(proof_hex) = proof_hex else {
        return false;
    };
    let Some(expected) = pairing_proof_hex(secret_hex, controller_id, host_id, session_id) else {
        return false;
    };
    let Ok(claimed) = hex::decode(proof_hex) else {
        return false;
    };
    let Ok(expected) = hex::decode(expected) else {
        return false;
    };
    constant_time_eq(&claimed, &expected)
}

/// Length-checked constant-time byte comparison (early `return` only on
/// length mismatch, which is not secret).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60";

    #[test]
    fn proof_round_trips_and_is_64_hex() {
        let proof = pairing_proof_hex(SECRET, "ctrl", "host", "s-1").expect("valid secret");
        assert_eq!(proof.len(), 64);
        assert!(proof.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(verify_pairing_proof(
            SECRET,
            "ctrl",
            "host",
            "s-1",
            Some(&proof)
        ));
    }

    #[test]
    fn every_domain_field_binds() {
        let proof = pairing_proof_hex(SECRET, "ctrl", "host", "s-1").unwrap();
        for (c, h, s) in [
            ("ctrL", "host", "s-1"),
            ("ctrl", "hosT", "s-1"),
            ("ctrl", "host", "s-2"),
        ] {
            assert!(
                !verify_pairing_proof(SECRET, c, h, s, Some(&proof)),
                "proof must not verify for {c}/{h}/{s}"
            );
        }
    }

    #[test]
    fn wrong_secret_or_proof_fails_closed() {
        let proof = pairing_proof_hex(SECRET, "ctrl", "host", "s-1").unwrap();
        assert!(!verify_pairing_proof(
            &"0".repeat(64),
            "ctrl",
            "host",
            "s-1",
            Some(&proof)
        ));
        assert!(!verify_pairing_proof(SECRET, "ctrl", "host", "s-1", None));
        assert!(!verify_pairing_proof(
            SECRET,
            "ctrl",
            "host",
            "s-1",
            Some("zz")
        ));
        assert!(!verify_pairing_proof(
            SECRET,
            "ctrl",
            "host",
            "s-1",
            Some(&"ab".repeat(16)) // 32 hex chars = 16 bytes: wrong length
        ));
        // Fail-closed compute: malformed secret never yields a proof.
        assert!(pairing_proof_hex("nothex", "c", "h", "s").is_none());
        assert!(pairing_proof_hex(&"ab".repeat(16), "c", "h", "s").is_none());
    }

    #[test]
    fn domain_string_is_pinned() {
        assert_eq!(
            proof_message("ctrl-a", "host-b", "s-3"),
            "pair-proof:v1|ctrl-a|host-b|s-3"
        );
    }
}
