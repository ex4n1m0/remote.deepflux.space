//! CSPRNG identifiers: stable device id material and the one-time session
//! secret (never logged — `SessionSecret`'s Debug is redacted upstream).

use protocol::signaling::SessionSecret;

/// 64-bit device id, hex-encoded (stable identity stored in settings).
pub fn new_device_id() -> String {
    let mut buf = [0u8; 8];
    fill(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// One-time consent secret: 256-bit hex (handed to the accepting host user's
/// `ConsentAccepted`, sent exactly once inside `Accept`, never logged).
pub fn new_session_secret() -> SessionSecret {
    let mut buf = [0u8; 32];
    fill(&mut buf);
    SessionSecret(
        buf.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(""),
    )
}

fn fill(buf: &mut [u8]) {
    // The OS CSPRNG is the only source; a failure is fatal for identity
    // minting (falling back to time-based ids would risk collisions).
    getrandom::fill(buf).expect("OS CSPRNG unavailable for id generation");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_hex_and_unique() {
        let a = new_device_id();
        let b = new_device_id();
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        let s = new_session_secret();
        assert_eq!(s.0.len(), 64);
        assert!(s.0.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
