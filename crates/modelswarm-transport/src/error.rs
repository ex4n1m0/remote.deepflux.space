//! Error surface for the signed-frame transport.
//!
//! `TransportError` is the public error type; msp-v1 §6.5 P2P error codes are
//! mapped where a transport condition has a protocol analogue.

use std::fmt;

/// P2P error codes (msp-v1 §6.5, frozen initial set).
pub const P2P_ERROR_CODES: &[&str] = &[
    "handshake_failed",
    "incompatible_protocol",
    "profile_mismatch",
    "invalid_token",
    "expired_token",
    "revoked_token",
    "replayed_request",
    "overloaded",
    "deadline_exceeded",
    "payload_too_large",
    "runtime_error",
    "cancelled_by_peer",
    "interrupted",
];

/// Low-level frame encode/decode/read/write failures.
#[derive(Debug)]
pub enum FrameError {
    /// Underlying socket I/O failure (includes premature EOF).
    Io(std::io::Error),
    /// The operation did not complete within its deadline.
    Timeout,
    /// The length prefix exceeded [`crate::frame::MAX_FRAME_BYTES`]
    /// (msp-v1 §6.4: max frames 256 KiB). Detected before any body read.
    TooLarge,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "frame i/o error: {e}"),
            FrameError::Timeout => write!(f, "frame operation timed out"),
            FrameError::TooLarge => write!(
                f,
                "frame exceeds the {} byte maximum (payload_too_large)",
                crate::frame::MAX_FRAME_BYTES
            ),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrameError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// Public transport error type.
#[derive(Debug)]
pub enum TransportError {
    /// Socket-level I/O failure. JSON frames that fail to parse surface here
    /// as `InvalidData` I/O errors.
    Io(std::io::Error),
    /// A send/recv/handshake deadline elapsed. A timed-out session is closed:
    /// later calls return [`TransportError::Closed`]. There is never a silent
    /// hang.
    Timeout,
    /// Peer sent a frame whose length prefix exceeded the 256 KiB cap
    /// (msp-v1 §6.5 `payload_too_large`).
    TooLarge,
    /// Handshake exchange failed. The string carries the msp-v1 §6.5 error
    /// code when the peer supplied one (e.g. `handshake_failed`,
    /// `incompatible_protocol`), otherwise a short diagnostic.
    HandshakeFailed(String),
    /// A bind address outside 127.0.0.1/::1 was refused. ADR-018 honesty
    /// guard: the signed-frame backend has no confidentiality and must never
    /// listen beyond loopback. No §6.5 analogue (local policy refusal).
    NonLoopbackDenied,
    /// The session (or its peer) is gone.
    Closed,
}

impl TransportError {
    /// The msp-v1 §6.5 P2P code for this condition, when one applies.
    ///
    /// `NonLoopbackDenied` has no §6.5 analogue (it is a local policy
    /// refusal, not a protocol failure) and maps to `None`. A
    /// `HandshakeFailed` carrying a known peer-supplied code maps to itself;
    /// anything else maps to `handshake_failed`.
    pub fn msp_code(&self) -> Option<&'static str> {
        match self {
            TransportError::Io(_) => Some("interrupted"),
            TransportError::Timeout => Some("deadline_exceeded"),
            TransportError::TooLarge => Some("payload_too_large"),
            TransportError::HandshakeFailed(detail) => Some(
                P2P_ERROR_CODES
                    .iter()
                    .find(|code| detail == **code)
                    .copied()
                    .unwrap_or("handshake_failed"),
            ),
            TransportError::NonLoopbackDenied => None,
            TransportError::Closed => Some("interrupted"),
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "transport i/o error: {e}"),
            TransportError::Timeout => write!(f, "transport operation timed out"),
            TransportError::TooLarge => write!(f, "frame too large (max 256 KiB)"),
            TransportError::HandshakeFailed(d) => write!(f, "handshake failed: {d}"),
            TransportError::NonLoopbackDenied => {
                write!(
                    f,
                    "refusing non-loopback bind: signed-frame backend is loopback-only (ADR-018)"
                )
            }
            TransportError::Closed => write!(f, "session closed"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        TransportError::Io(e)
    }
}

impl From<FrameError> for TransportError {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Io(e) => TransportError::Io(e),
            FrameError::Timeout => TransportError::Timeout,
            FrameError::TooLarge => TransportError::TooLarge,
        }
    }
}

/// Why a handshake failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// Required fields are absent/empty/unparseable, or the protocol version
    /// is not `"1"` (msp-v1 §6.5 `incompatible_protocol` folds here in the
    /// staged three-variant surface).
    MissingFields,
    /// The Ed25519 signature over the canonical JSON of the handshake fields
    /// did not verify against the presented key material.
    BadSignature,
    /// The claimed `peer_id`/`installation_id` do not derive from the
    /// expected public key (msp-v1 §6.6 binding rule).
    WrongPeer,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::MissingFields => write!(f, "handshake fields missing or malformed"),
            HandshakeError::BadSignature => write!(f, "handshake signature failed verification"),
            HandshakeError::WrongPeer => {
                write!(f, "handshake peer id does not match the expected key")
            }
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Wraps a serde failure as an `InvalidData` I/O error (JSON frames that do
/// not parse must surface as I/O-corruption, not panics).
pub(crate) fn invalid_data(context: &str, e: impl fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{context}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msp_codes_map_to_frozen_section_6_5_set() {
        assert_eq!(
            TransportError::Timeout.msp_code(),
            Some("deadline_exceeded")
        );
        assert_eq!(
            TransportError::TooLarge.msp_code(),
            Some("payload_too_large")
        );
        assert_eq!(
            TransportError::HandshakeFailed("incompatible_protocol".into()).msp_code(),
            Some("incompatible_protocol")
        );
        assert_eq!(
            TransportError::HandshakeFailed("made up code".into()).msp_code(),
            Some("handshake_failed")
        );
        assert_eq!(TransportError::NonLoopbackDenied.msp_code(), None);
        assert_eq!(TransportError::Closed.msp_code(), Some("interrupted"));
    }

    #[test]
    fn frame_error_converts_into_transport_error() {
        assert!(matches!(
            TransportError::from(FrameError::TooLarge),
            TransportError::TooLarge
        ));
        assert!(matches!(
            TransportError::from(FrameError::Timeout),
            TransportError::Timeout
        ));
    }
}
