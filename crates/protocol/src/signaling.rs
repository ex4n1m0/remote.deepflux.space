//! Signaling envelopes for the Vercel control plane (JSON).
//!
//! Every message that the signaling service forwards is one
//! [`SignalingEnvelope`]. The service is a dumb, idempotent mailbox: it keys
//! dedupe on `message_id`, stores per-record TTLs, and forwards. It never
//! interprets payloads beyond `protocol_version` compatibility checks.
//!
//! Wire contract notes (see AGENTS.md "Wire-format & versioning policy"):
//! * Field names are **stable snake_case**; the TypeScript signaling service
//!   (M3) is generated against exactly these keys. Renaming a field is a
//!   breaking change requiring a `protocol_version` bump.
//! * `timestamp_ms` is the sender's local clock. It is informational only;
//!   ordering comes from `message_id` plus the mailbox, never from comparing
//!   clocks across devices.
//! * The one-time session secret travels only inside `Accept`. It must never
//!   be logged: [`SessionSecret`]'s `Debug` impl is redacted for that reason
//!   (invariant 6).

use serde::{Deserialize, Serialize};

use crate::capabilities::Capabilities;

/// Current signaling protocol version. Bumps are explicit contract changes
/// (AGENTS.md invariant 5) and must update the compatibility test below.
pub const SIGNALING_PROTOCOL_VERSION: u16 = 0;

/// Pseudo-device-id used to address messages that go *to the service itself*
/// (`Register`, `Heartbeat`) rather than to a peer device.
pub const SIGNALING_SERVICE_ID: &str = "signaling";

pub type DeviceId = String;
pub type MessageId = String;
pub type SessionId = String;

/// One-time session secret issued by the host on accept (safety floor:
/// 128-bit random value in production; the type is the contract, the source
/// of randomness is the host UI/runtime). Serialization is a plain string;
/// `Debug` is redacted so a stray log line cannot leak it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSecret(pub String);

impl core::fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionSecret(<redacted>)")
    }
}

/// The outer envelope. Serializes flat: the `type` discriminant and the body
/// fields are merged into the envelope object via `#[serde(flatten)]`
/// (internally tagged enum), matching the layout agreed with the TS service:
///
/// ```json
/// {
///   "protocol_version": 0,
///   "message_id": "device-a-7",
///   "session_id": "device-a-1",
///   "from_device_id": "device-a",
///   "to_device_id": "device-b",
///   "timestamp_ms": 1695000000000,
///   "type": "connect_request",
///   "capabilities": { ... }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalingEnvelope {
    pub protocol_version: u16,
    /// Idempotency key. The service retains recently seen values for the
    /// signaling TTL; state machines deduplicate on it as well
    /// (`crates/session`).
    pub message_id: MessageId,
    /// Present for all session-scoped messages (`connect_request` and later);
    /// `None` for `Register`/`Heartbeat`.
    pub session_id: Option<SessionId>,
    pub from_device_id: DeviceId,
    /// A peer device id, or [`SIGNALING_SERVICE_ID`] for service-directed
    /// messages.
    pub to_device_id: DeviceId,
    /// Sender-local wall clock, milliseconds. Informational only.
    pub timestamp_ms: u64,
    #[serde(flatten)]
    pub body: SignalingBody,
}

impl SignalingEnvelope {
    /// Typed version check. Callers (service and clients) must reject
    /// envelopes whose version they do not understand instead of guessing at
    /// the payload layout.
    pub fn check_version(&self) -> Result<(), SignalingVersionError> {
        ensure_signaling_version(self.protocol_version)
    }
}

/// Typed error for an unsupported `protocol_version`. Compatibility rule:
/// unknown versions fail loudly, never decode into garbage fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalingVersionError {
    Unsupported { supported: u16, found: u16 },
}

impl core::fmt::Display for SignalingVersionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignalingVersionError::Unsupported { supported, found } => write!(
                f,
                "unsupported signaling protocol_version {found} (this build speaks {supported})"
            ),
        }
    }
}

impl std::error::Error for SignalingVersionError {}

pub fn ensure_signaling_version(version: u16) -> Result<(), SignalingVersionError> {
    if version == SIGNALING_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(SignalingVersionError::Unsupported {
            supported: SIGNALING_PROTOCOL_VERSION,
            found: version,
        })
    }
}

/// Discriminated message body. Variant names serialize to snake_case `type`
/// values; variant fields are snake_case and stable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "snake_case"
)]
pub enum SignalingBody {
    /// Register presence and capabilities. Directed at the service.
    Register { capabilities: Capabilities },
    /// Keep presence alive. Directed at the service.
    Heartbeat,
    /// Controller asks a host for a session.
    ConnectRequest { capabilities: Capabilities },
    /// Host grants the session and hands over the one-time secret.
    Accept { session_secret: SessionSecret },
    /// Host refuses. `reason` is machine-readable for UX mapping.
    Reject { reason: RejectReason },
    /// SDP offer (controller to host), via the mailbox.
    Offer { sdp: String },
    /// SDP answer (host to controller), via the mailbox.
    Answer { sdp: String },
    /// Trickle ICE candidate, forwarded verbatim.
    IceCandidate {
        candidate: String,
        sdp_mid: Option<u16>,
        sdp_mline_index: Option<u16>,
    },
    /// ICE gathering finished on the sender (no payload).
    IceComplete,
    /// Controller withdraws a pending request/attempt.
    Cancel { reason: CancelReason },
    /// Either side ends an established or establishing session.
    Disconnect { reason: DisconnectReason },
    /// Service-reported error (bad target, TTL expired, rate limited...).
    Error { code: u16, detail: String },
}

/// Why a host rejected a connection request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// Host already has an active or pending session.
    Busy,
    /// The host user declined the consent prompt.
    Declined,
    /// The consent prompt timed out without an answer.
    Timeout,
    /// Recipient is not accepting sessions (e.g. hosting disabled).
    Unavailable,
}

/// Why a controller canceled its own attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelReason {
    /// The controller user withdrew the attempt.
    User,
    /// Simultaneous-call collision resolved against this controller
    /// (deterministic device-id tie-break; see `docs/protocol/state-machines.md`).
    Collision,
}

/// Why a side disconnected an established/establishing session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectReason {
    User,
    Timeout,
    TransportError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::capabilities_sample;

    fn envelope(body: SignalingBody) -> SignalingEnvelope {
        SignalingEnvelope {
            protocol_version: SIGNALING_PROTOCOL_VERSION,
            message_id: "device-a-7".to_owned(),
            session_id: Some("device-a-1".to_owned()),
            from_device_id: "device-a".to_owned(),
            to_device_id: "device-b".to_owned(),
            timestamp_ms: 1_695_000_000_000,
            body,
        }
    }

    fn all_bodies() -> Vec<SignalingBody> {
        vec![
            SignalingBody::Register {
                capabilities: capabilities_sample(),
            },
            SignalingBody::Heartbeat,
            SignalingBody::ConnectRequest {
                capabilities: capabilities_sample(),
            },
            SignalingBody::Accept {
                session_secret: SessionSecret("one-time-secret".to_owned()),
            },
            SignalingBody::Reject {
                reason: RejectReason::Busy,
            },
            SignalingBody::Offer {
                sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1".to_owned(),
            },
            SignalingBody::Answer {
                sdp: "v=0\r\no=- 2 1 IN IP4 127.0.0.1".to_owned(),
            },
            SignalingBody::IceCandidate {
                candidate: "candidate:1 1 UDP 2130706431 192.168.1.10 54321 typ host".to_owned(),
                sdp_mid: Some(0),
                sdp_mline_index: Some(0),
            },
            SignalingBody::IceComplete,
            SignalingBody::Cancel {
                reason: CancelReason::User,
            },
            SignalingBody::Disconnect {
                reason: DisconnectReason::User,
            },
            SignalingBody::Error {
                code: 404,
                detail: "unknown device".to_owned(),
            },
        ]
    }

    #[test]
    fn every_body_round_trips_through_json() {
        for body in all_bodies() {
            let json = serde_json::to_string(&envelope(body.clone())).expect("serialize");
            let back: SignalingEnvelope = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, envelope(body), "round trip mismatch for {json}");
        }
    }

    #[test]
    fn envelope_field_names_are_stable_snake_case() {
        let value = serde_json::to_value(envelope(SignalingBody::ConnectRequest {
            capabilities: capabilities_sample(),
        }))
        .expect("serialize");

        assert_eq!(value["protocol_version"], 0);
        assert_eq!(value["message_id"], "device-a-7");
        assert_eq!(value["session_id"], "device-a-1");
        assert_eq!(value["from_device_id"], "device-a");
        assert_eq!(value["to_device_id"], "device-b");
        assert_eq!(
            value["timestamp_ms"],
            serde_json::json!(1_695_000_000_000u64)
        );
        assert_eq!(value["type"], "connect_request");
        // The payload is flattened to the top level; there is no nested
        // "payload" object on the wire.
        assert!(value.get("payload").is_none());
        assert_eq!(value["capabilities"]["monitors"][0]["width_px"], 2560);
    }

    #[test]
    fn body_type_tags_are_stable_snake_case() {
        let cases: Vec<(SignalingBody, &str)> = vec![
            (SignalingBody::Heartbeat, "heartbeat"),
            (
                SignalingBody::Accept {
                    session_secret: SessionSecret("x".to_owned()),
                },
                "accept",
            ),
            (
                SignalingBody::Reject {
                    reason: RejectReason::Declined,
                },
                "reject",
            ),
            (SignalingBody::IceComplete, "ice_complete"),
            (
                SignalingBody::Cancel {
                    reason: CancelReason::Collision,
                },
                "cancel",
            ),
        ];
        for (body, tag) in cases {
            let value = serde_json::to_value(envelope(body)).expect("serialize");
            assert_eq!(value["type"], tag, "unexpected tag for {value}");
        }
        // Enum payloads are snake_case too.
        let value = serde_json::to_value(envelope(SignalingBody::Reject {
            reason: RejectReason::Busy,
        }))
        .expect("serialize");
        assert_eq!(value["reason"], "busy");
        let value = serde_json::to_value(envelope(SignalingBody::Cancel {
            reason: CancelReason::User,
        }))
        .expect("serialize");
        assert_eq!(value["reason"], "user");
    }

    #[test]
    fn unknown_protocol_version_fails_with_typed_error() {
        let mut env = envelope(SignalingBody::Heartbeat);
        env.protocol_version = SIGNALING_PROTOCOL_VERSION + 1;
        let err = env
            .check_version()
            .expect_err("must reject unknown version");
        assert_eq!(
            err,
            SignalingVersionError::Unsupported {
                supported: SIGNALING_PROTOCOL_VERSION,
                found: 1,
            }
        );
        // A future-version envelope still parses as JSON (the service must be
        // able to read the header to reject it); the typed error comes from
        // the explicit check.
        let json = serde_json::to_string(&env).unwrap();
        let parsed: SignalingEnvelope = serde_json::from_str(&json).unwrap();
        assert!(parsed.check_version().is_err());
    }

    #[test]
    fn session_secret_debug_is_redacted() {
        let secret = SessionSecret("hunter2-do-not-log".to_owned());
        let formatted = format!("{secret:?}");
        assert!(!formatted.contains("hunter2"), "Debug leaked the secret");
        assert!(formatted.contains("redacted"));
        // Debug of a whole envelope must not leak it either.
        let env = envelope(SignalingBody::Accept {
            session_secret: secret,
        });
        let formatted = format!("{env:?}");
        assert!(!formatted.contains("hunter2"));
    }

    #[test]
    fn json_decoder_tolerates_unknown_additive_fields() {
        // Policy: additive Optional fields may appear within a version.
        let mut value =
            serde_json::to_value(envelope(SignalingBody::Heartbeat)).expect("serialize");
        let obj = value.as_object_mut().unwrap();
        obj.insert("future_field".to_owned(), serde_json::json!(42));
        let back: SignalingEnvelope = serde_json::from_value(value).expect("deserialize");
        assert_eq!(back.body, SignalingBody::Heartbeat);
    }
}
