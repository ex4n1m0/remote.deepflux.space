//! Timestamps, replay windows, and nonces (msp-v1 §2.2–§2.3).

use rand_core::{CryptoRngCore, OsRng};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Signed-envelope replay window in seconds (msp-v1 §2.3, frozen: ±120 s).
pub const REPLAY_WINDOW_SECS: i64 = 120;

/// Current time as an RFC 3339 UTC timestamp, e.g. `2026-10-04T12:00:00Z`.
pub fn rfc3339_now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("formatting the current UTC time as RFC 3339 cannot fail")
}

/// True when `ts` parses as RFC 3339 and lies within ±`secs` of `now_ts`
/// (also RFC 3339). Unparseable inputs are outside the window (fail closed).
pub fn within_window(ts: &str, now_ts: &str, secs: i64) -> bool {
    match (
        OffsetDateTime::parse(ts, &Rfc3339),
        OffsetDateTime::parse(now_ts, &Rfc3339),
    ) {
        (Ok(t), Ok(now)) => (t - now).whole_seconds().abs() <= secs,
        _ => false,
    }
}

/// A fresh 32-hex-character nonce from 16 OS-random bytes. Protocol rule:
/// 16+ random hex chars, unique per installation within the replay window.
pub fn new_nonce() -> String {
    new_nonce_with(&mut OsRng)
}

/// [`new_nonce`] with a caller-supplied RNG (tests, simulations).
pub fn new_nonce_with(rng: &mut impl CryptoRngCore) -> String {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// `bodyDigest` for bodyless calls (GET): `sha256:` + SHA-256 of the empty
/// string (msp-v1 §2.3).
pub fn empty_body_digest() -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(b"")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn at(epoch_secs: i64) -> String {
        (OffsetDateTime::from_unix_timestamp(epoch_secs).unwrap())
            .format(&Rfc3339)
            .unwrap()
    }

    #[test]
    fn rfc3339_now_parses_back() {
        let now = rfc3339_now();
        assert!(OffsetDateTime::parse(&now, &Rfc3339).is_ok());
        assert!(
            now.ends_with('Z'),
            "UTC timestamps must use the Z offset: {now}"
        );
    }

    #[test]
    fn window_accepts_inside_and_rejects_outside() {
        let now = at(1_800_000_000);
        assert!(within_window(&at(1_800_000_000), &now, REPLAY_WINDOW_SECS));
        assert!(within_window(
            &at(1_800_000_000 + 119),
            &now,
            REPLAY_WINDOW_SECS
        ));
        assert!(within_window(
            &at(1_800_000_000 - 119),
            &now,
            REPLAY_WINDOW_SECS
        ));
        // Exactly on the boundary counts as inside (<=).
        assert!(within_window(
            &at(1_800_000_000 + 120),
            &now,
            REPLAY_WINDOW_SECS
        ));
        assert!(within_window(
            &at(1_800_000_000 - 120),
            &now,
            REPLAY_WINDOW_SECS
        ));
        // One second beyond the boundary is outside.
        assert!(!within_window(
            &at(1_800_000_000 + 121),
            &now,
            REPLAY_WINDOW_SECS
        ));
        assert!(!within_window(
            &at(1_800_000_000 - 121),
            &now,
            REPLAY_WINDOW_SECS
        ));
    }

    #[test]
    fn window_fails_closed_on_garbage() {
        assert!(!within_window(
            "not-a-timestamp",
            &rfc3339_now(),
            REPLAY_WINDOW_SECS
        ));
        assert!(!within_window(
            &rfc3339_now(),
            "garbage",
            REPLAY_WINDOW_SECS
        ));
    }

    #[test]
    fn window_respects_custom_sizes() {
        let now = at(500);
        assert!(within_window(&at(505), &now, 5));
        assert!(!within_window(&at(506), &now, 5));
    }

    #[test]
    fn nonces_are_unique_over_100_draws() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let nonce = new_nonce();
            assert_eq!(nonce.len(), 32, "16 bytes -> 32 hex chars");
            assert!(nonce.bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(seen.insert(nonce), "nonce repeated within 100 draws");
        }
        assert_eq!(seen.len(), 100);
    }

    #[test]
    fn empty_body_digest_is_sha256_of_nothing() {
        assert_eq!(
            empty_body_digest(),
            format!("sha256:{}", hex::encode(Sha256::digest(b"")))
        );
        assert_eq!(
            empty_body_digest(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn duration_math_matches_expectations() {
        // Guard the time-crate semantics used by within_window.
        let a = OffsetDateTime::from_unix_timestamp(1_000).unwrap();
        let b = OffsetDateTime::from_unix_timestamp(1_130).unwrap();
        assert_eq!((a - b).whole_seconds(), -130);
        assert_eq!((a - b), -Duration::seconds(130));
    }
}
