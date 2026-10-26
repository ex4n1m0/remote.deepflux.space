//! Pairing proof (ADR-006): the HMAC that makes silent paired accept
//! cryptographically authenticated instead of id-based.
//!
//! Before ADR-006, `auto_accept_if_paired` granted silent full control on
//! the bare controller device id — and device ids are re-claimable through
//! the signaling presence-tombstone window minutes after a machine goes
//! offline, so a squatter could silently take over a family host. The proof
//! is HMAC-SHA256 keyed by the 32-byte pairing secret only the two paired
//! machines hold.
//!
//! **v2 domain (0.5.2, security review):** the original v1 proof was
//! replayable — it bound only `controller|host|session_id`, and session ids
//! are deterministic (`{device}-ctrl-{n}`, counter reset per process), so a
//! captured proof re-verified verbatim in a fresh envelope after an id
//! squat. v2 binds the envelope `message_id` (a fresh envelope therefore
//! needs a fresh MAC — an attacker without the secret cannot mint one) and
//! embeds a freshness timestamp inside the proof blob (replaying the
//! captured envelope itself fails once it is older than
//! [`PROOF_MAX_AGE_MS`], surviving host restarts and dedupe expiry).
//!
//! Wire shape: `connect_request.pairing_proof_hex` stays an opaque
//! lowercase-hex string (additive-optional within signaling version 1).
//! v2 = 80 hex chars = HMAC-SHA256 (32 B) ‖ timestamp_ms big-endian (8 B).
//! v1 (64 hex) proofs are REFUSED — they cannot be distinguished from
//! replays; refusing fails open to the human consent prompt, never to
//! accept. The deployed base is the owner's own machines; upgrading both
//! sides restores silent reconnect, mixed versions degrade to prompting.
//!
//! Host rule (app layer): pairing exists **and** v2 proof verifies → silent
//! accept; anything else → consent prompt (with warning copy when a pairing
//! exists but the proof failed). A bad secret or proof shape simply fails
//! verification; the proof hex is not secret material (it crosses the
//! control plane inside the envelope), but the secret must never be logged.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// v1 domain separator (REJECTED at verification — kept for the pin test).
pub const PROOF_DOMAIN_V1: &str = "pair-proof:v1";
/// v2 domain separator: binds controller, host, session id, message id.
pub const PROOF_DOMAIN_V2: &str = "pair-proof:v2";
/// Proof freshness window: an older embedded timestamp fails verification.
/// Generous for clock skew between family PCs (NTP-normalized in practice).
pub const PROOF_MAX_AGE_MS: u64 = 10 * 60 * 1000;

/// MAC bytes (HMAC-SHA256).
const MAC_LEN: usize = 32;
/// Timestamp bytes (u64 big-endian).
const TS_LEN: usize = 8;

type HmacSha256 = Hmac<Sha256>;

fn v2_message(
    controller_id: &str,
    host_id: &str,
    session_id: &str,
    message_id: &str,
    ts_ms: u64,
) -> String {
    format!("{PROOF_DOMAIN_V2}|{controller_id}|{host_id}|{session_id}|{message_id}|{ts_ms}")
}

fn mac_v2(
    secret_hex: &str,
    controller_id: &str,
    host_id: &str,
    session_id: &str,
    message_id: &str,
    ts_ms: u64,
) -> Option<[u8; MAC_LEN]> {
    let secret = hex::decode(secret_hex).ok()?;
    if secret.len() != 32 {
        return None;
    }
    let mut mac = HmacSha256::new_from_slice(&secret).ok()?;
    mac.update(v2_message(controller_id, host_id, session_id, message_id, ts_ms).as_bytes());
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; MAC_LEN];
    buf.copy_from_slice(&out);
    Some(buf)
}

/// Compute the v2 proof as 80 lowercase hex chars
/// (HMAC-SHA256 ‖ timestamp_ms big-endian). Returns `None` if the secret is
/// not 64 valid hex chars (fail closed: no proof → the host falls back to
/// the consent prompt).
pub fn pairing_proof_hex(
    secret_hex: &str,
    controller_id: &str,
    host_id: &str,
    session_id: &str,
    message_id: &str,
    ts_ms: u64,
) -> Option<String> {
    let mac = mac_v2(
        secret_hex,
        controller_id,
        host_id,
        session_id,
        message_id,
        ts_ms,
    )?;
    let mut blob = Vec::with_capacity(MAC_LEN + TS_LEN);
    blob.extend_from_slice(&mac);
    blob.extend_from_slice(&ts_ms.to_be_bytes());
    Some(hex::encode(blob))
}

/// Verify a claimed proof for one envelope (`message_id`) at host time
/// `now_ms`. Accepts only v2 (80 hex). Fails closed on: `None` proof,
/// malformed hex, wrong length (including v1's 64), wrong secret, any
/// mismatched domain field, or a timestamp outside [`PROOF_MAX_AGE_MS`].
pub fn verify_pairing_proof(
    secret_hex: &str,
    controller_id: &str,
    host_id: &str,
    session_id: &str,
    message_id: &str,
    proof_hex: Option<&str>,
    now_ms: u64,
) -> bool {
    let Some(proof_hex) = proof_hex else {
        return false;
    };
    let Ok(blob) = hex::decode(proof_hex) else {
        return false;
    };
    if blob.len() != MAC_LEN + TS_LEN {
        return false; // v1 (64 hex) and every other shape: refused
    }
    let (claimed_mac, ts) = blob.split_at(MAC_LEN);
    let mut ts_bytes = [0u8; TS_LEN];
    ts_bytes.copy_from_slice(ts);
    let proof_ts = u64::from_be_bytes(ts_bytes);
    // Freshness (symmetric window, generous for family-PC clock skew): an
    // old proof (captured envelope replay) must not verify, even after a
    // host restart or dedupe-tombstone expiry — and a wildly future one
    // means broken clocks, not a valid controller.
    if now_ms.abs_diff(proof_ts) > PROOF_MAX_AGE_MS {
        return false;
    }
    let Some(expected) = mac_v2(
        secret_hex,
        controller_id,
        host_id,
        session_id,
        message_id,
        proof_ts,
    ) else {
        return false;
    };
    constant_time_eq(claimed_mac, &expected)
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
    const CTRL: &str = "0123456789abcdef";
    const HOST: &str = "fedcba9876543210";
    const NOW: u64 = 1_760_000_000_000;

    #[test]
    fn proof_round_trips_and_is_80_hex() {
        let proof = pairing_proof_hex(SECRET, CTRL, HOST, "s-1", "m-1", NOW).expect("valid");
        assert_eq!(proof.len(), 80);
        assert!(proof.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(verify_pairing_proof(
            SECRET,
            CTRL,
            HOST,
            "s-1",
            "m-1",
            Some(&proof),
            NOW
        ));
    }

    #[test]
    fn message_id_binds_replayed_envelope_needs_new_mac() {
        let proof = pairing_proof_hex(SECRET, CTRL, HOST, "s-1", "m-1", NOW).unwrap();
        // A fresh envelope (new message_id) cannot reuse the captured MAC.
        assert!(!verify_pairing_proof(
            SECRET,
            CTRL,
            HOST,
            "s-1",
            "m-2",
            Some(&proof),
            NOW
        ));
        assert!(!verify_pairing_proof(
            SECRET,
            CTRL,
            HOST,
            "s-1",
            "m-1x",
            Some(&proof),
            NOW
        ));
    }

    #[test]
    fn freshness_window_rejects_old_captures() {
        let proof = pairing_proof_hex(SECRET, CTRL, HOST, "s-1", "m-1", NOW).unwrap();
        let old = NOW + PROOF_MAX_AGE_MS + 1;
        assert!(!verify_pairing_proof(
            SECRET,
            CTRL,
            HOST,
            "s-1",
            "m-1",
            Some(&proof),
            old
        ));
        // Inside the window (including modest clock skew both ways) passes.
        let edge = NOW + PROOF_MAX_AGE_MS;
        assert!(verify_pairing_proof(
            SECRET,
            CTRL,
            HOST,
            "s-1",
            "m-1",
            Some(&proof),
            edge
        ));
        let skew_back = NOW.saturating_sub(PROOF_MAX_AGE_MS);
        assert!(verify_pairing_proof(
            SECRET,
            CTRL,
            HOST,
            "s-1",
            "m-1",
            Some(&proof),
            skew_back
        ));
        let before = skew_back.saturating_sub(1);
        assert!(!verify_pairing_proof(
            SECRET,
            CTRL,
            HOST,
            "s-1",
            "m-1",
            Some(&proof),
            before
        ));
    }

    #[test]
    fn every_domain_field_binds() {
        let proof = pairing_proof_hex(SECRET, CTRL, HOST, "s-1", "m-1", NOW).unwrap();
        for (c, h, s, m) in [
            ("0123456789abcdee", HOST, "s-1", "m-1"),
            (CTRL, "fedcba9876543211", "s-1", "m-1"),
            (CTRL, HOST, "s-2", "m-1"),
            (CTRL, HOST, "s-1", "m-9"),
        ] {
            assert!(
                !verify_pairing_proof(SECRET, c, h, s, m, Some(&proof), NOW),
                "proof must not verify for {c}/{h}/{s}/{m}"
            );
        }
    }

    #[test]
    fn v1_shapes_and_garbage_fail_closed() {
        // A v1-length (64 hex) value must be refused — it is either legacy
        // or a replay candidate; the host prompts instead.
        let v1ish = "9e".repeat(32);
        assert!(!verify_pairing_proof(
            SECRET,
            CTRL,
            HOST,
            "s-1",
            "m-1",
            Some(&v1ish),
            NOW
        ));
        // Real v1 MAC over the v1 domain: still refused (domain gone).
        let secret = hex::decode(SECRET).unwrap();
        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(format!("{PROOF_DOMAIN_V1}|{CTRL}|{HOST}|s-1").as_bytes());
        let v1_mac = hex::encode(mac.finalize().into_bytes());
        assert!(!verify_pairing_proof(
            SECRET,
            CTRL,
            HOST,
            "s-1",
            "m-1",
            Some(&v1_mac),
            NOW
        ));
        assert!(!verify_pairing_proof(
            SECRET, CTRL, HOST, "s-1", "m-1", None, NOW
        ));
        assert!(!verify_pairing_proof(
            SECRET,
            CTRL,
            HOST,
            "s-1",
            "m-1",
            Some("zz"),
            NOW
        ));
        // 80 hex of the wrong MAC: right length, fails the constant-time
        // compare.
        assert!(!verify_pairing_proof(
            SECRET,
            CTRL,
            HOST,
            "s-1",
            "m-1",
            Some(&"ab".repeat(40)),
            NOW
        ));
        // Wrong secret against a real proof.
        let real = pairing_proof_hex(SECRET, CTRL, HOST, "s-1", "m-1", NOW).unwrap();
        assert!(!verify_pairing_proof(
            &"0".repeat(64),
            CTRL,
            HOST,
            "s-1",
            "m-1",
            Some(&real),
            NOW
        ));
        // Fail-closed compute: malformed secret never yields a proof.
        assert!(pairing_proof_hex("nothex", CTRL, HOST, "s-1", "m-1", NOW).is_none());
    }

    #[test]
    fn domains_are_pinned() {
        assert_eq!(PROOF_DOMAIN_V1, "pair-proof:v1");
        assert_eq!(PROOF_DOMAIN_V2, "pair-proof:v2");
        assert_eq!(v2_message("c", "h", "s", "m", 7), "pair-proof:v2|c|h|s|m|7");
    }
}
