//! Binary messages for the direct WebRTC data channels.
//!
//! Channel layout (source plan, frozen decision):
//!
//! | Channel         | Delivery policy                  | Carries                    |
//! |-----------------|----------------------------------|----------------------------|
//! | `control`       | ordered, reliable                | everything except input/cursor below |
//! | `input-fast`    | unordered, maxRetransmits 0      | `InputEvent::MouseMove`    |
//! | `input-reliable`| ordered, reliable                | other `InputEvent`s        |
//! | `cursor`        | latest-state oriented            | `CursorMessage`            |
//!
//! Video never appears here: it is an H.264 RTP track, not a data-channel
//! message, and never passes through signaling or Tauri IPC (invariants 1–2).
//!
//! ## Framing
//!
//! `[version byte u8 = WIRE_VERSION][bincode payload]`.
//!
//! Bincode 1.x `options()` default encoding: little-endian, base-128 varint
//! integers, trailing bytes rejected. Chosen deliberately: tiny dependency
//! tree, deterministic layout, and varint keeps high-frequency input events
//! (`seq`/coordinates) at a few bytes. Because bincode is **not
//! self-describing**, any layout change — field reorder, type change, variant
//! insert in the middle — requires bumping [`WIRE_VERSION`]. Unknown version
//! bytes fail with [`DecodeError::UnsupportedVersion`]; they must never be
//! decoded as garbage (compatibility test below).
//!
//! ## Input safety
//!
//! Every `InputEvent` carries a per-channel monotonic `seq`. The host watches
//! the reliable-input sequence; a gap signals loss, and the host must release
//! all held keys/buttons (`InputEvent::AllKeysUp` is also sent by the
//! controller on focus loss and by the host on disconnect). Coordinates are
//! normalized to `0..=65535` over the selected monitor, matching `SendInput`
//! absolute-mode semantics (source plan input mapping).

use std::io::Read;

use bincode::Options;
use serde::{Deserialize, Serialize};

use crate::capabilities::Capabilities;

/// Current binary wire version. Bump is an explicit contract change and must
/// update the compatibility tests in this module.
pub const WIRE_VERSION: u8 = 0;

/// Decode limit for a single data-channel message. Input/control messages are
/// a few dozen bytes; cursor shapes are bounded by the largest Windows cursor
/// (256x256 BGRA = 256 KiB), so 1 MiB is generous headroom while keeping a
/// hostile peer from making us allocate unbounded memory (invariant 3).
pub const MAX_WIRE_MESSAGE_BYTES: u64 = 1 << 20;

/// One message on a direct-session data channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WireMessage {
    // ---- `control` channel (ordered, reliable) ----
    /// First message after the control channel opens; capability negotiation
    /// is re-done over the direct path (what signaling carried may be stale).
    Hello {
        capabilities: Capabilities,
    },
    HelloAck {
        capabilities: Capabilities,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    /// Request an H.264 immediate keyframe (after loss, display change,
    /// monitor switch).
    KeyframeRequest,
    SetQuality {
        preset: QualityPreset,
    },
    SelectMonitor {
        monitor_id: String,
    },
    Disconnect {
        reason: ControlDisconnectReason,
    },

    // ---- input channels (`input-fast` / `input-reliable`) ----
    Input(InputEvent),

    // ---- `cursor` channel (latest-state oriented) ----
    Cursor(CursorMessage),
}

/// Quality presets understood by the host encoder controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityPreset {
    Auto,
    Low,
    Balanced,
    High,
}

/// Why the control channel is being closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlDisconnectReason {
    User,
    Timeout,
    TransportError,
}

/// Controller-to-host input events. `seq` is per-channel monotonic from the
/// controller; the host never trusts it for ordering on `input-fast`
/// (unordered channel) but does detect gaps on `input-reliable`.
///
/// Invariant 6 (input never logged) is enforced here, not just in docstrings:
/// [`core::fmt::Debug`] prints only the variant name and `seq`; every payload
/// field — coordinates, buttons, scan codes, typed text — is redacted (QA
/// F3). Logging frameworks get the redacted form for free via the derived
/// `Debug` on [`WireMessage`] and on transport event types wrapping it.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum InputEvent {
    /// Coalesced pointer position. Normalized `0..=65535` over the active
    /// monitor. Travels on `input-fast`.
    MouseMove { seq: u64, x: u16, y: u16 },
    /// Button transitions are never coalesced. `input-reliable`.
    MouseButton {
        seq: u64,
        button: MouseButton,
        state: ButtonState,
    },
    /// Wheel ticks. `input-reliable`.
    Wheel {
        seq: u64,
        delta_v: i32,
        delta_h: i32,
    },
    /// Scan-code based key event (physical key, layout independent).
    /// `input-reliable`.
    Key {
        seq: u64,
        scan_code: u16,
        extended: bool,
        state: ButtonState,
    },
    /// Unicode text path, separate from scan codes (IME/typed characters).
    /// `input-reliable`.
    Text { seq: u64, code_points: String },
    /// Release every held key/button. Sent by the controller on focus loss;
    /// emitted locally by the host on reliable-input sequence gap or
    /// disconnect. Safety net for stuck keys.
    AllKeysUp { trigger: AllKeysUpTrigger },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

/// Invariant 6: input payloads (coordinates, buttons, keys, text) are never
/// printable via `Debug`. Only the variant name and `seq` appear; the safety
/// trigger on `AllKeysUp` is diagnostic state, not user input, and stays
/// visible. Regression-tested in `tests` below (QA F3).
impl core::fmt::Debug for InputEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InputEvent::MouseMove { seq, .. } => {
                write!(f, "MouseMove {{ seq: {seq}, payload: <redacted> }}")
            }
            InputEvent::MouseButton { seq, .. } => {
                write!(f, "MouseButton {{ seq: {seq}, payload: <redacted> }}")
            }
            InputEvent::Wheel { seq, .. } => {
                write!(f, "Wheel {{ seq: {seq}, payload: <redacted> }}")
            }
            InputEvent::Key { seq, .. } => {
                write!(f, "Key {{ seq: {seq}, payload: <redacted> }}")
            }
            InputEvent::Text { seq, .. } => {
                write!(f, "Text {{ seq: {seq}, payload: <redacted> }}")
            }
            InputEvent::AllKeysUp { trigger } => {
                write!(f, "AllKeysUp {{ trigger: {trigger:?} }}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ButtonState {
    Pressed,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllKeysUpTrigger {
    /// Controller-side focus loss.
    FocusLost,
    /// Host detected a reliable-input sequence gap.
    SequenceGap,
    /// Host-side session teardown.
    Disconnect,
}

/// Host-to-controller cursor state, kept out of the video track so the pointer
/// stays crisp (source plan: capture the cursor separately, composite on the
/// controller).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CursorMessage {
    /// Normalized `0..=65535` position over the same space as mouse input.
    Position { seq: u64, x: u16, y: u16 },
    /// Full shape bitmap. `pixels` layout depends on `format`; bounded by
    /// [`MAX_WIRE_MESSAGE_BYTES`].
    Shape {
        id: u32,
        width: u16,
        height: u16,
        hotspot_x: u16,
        hotspot_y: u16,
        format: CursorFormat,
        pixels: Vec<u8>,
    },
    /// Cursor left the captured surface (hidden).
    Hide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorFormat {
    /// 32-bit BGRA, `width * 4` bytes per row.
    Bgra8,
    /// 1-bpp monochrome with 1-bpp AND mask.
    Monochrome,
    /// 32-bit color with 1-bpp transparency mask (Windows masked-color cursor).
    MaskedColor,
}

/// Typed decode failure. "Fail loudly, never garbage" is the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    MissingVersionByte,
    UnsupportedVersion {
        supported: u8,
        found: u8,
    },
    /// Input ended before the message did.
    Truncated,
    /// Claimed structure exceeds [`MAX_WIRE_MESSAGE_BYTES`].
    TooLarge,
    /// Bytes decoded as *something*, but not a valid message of this version
    /// (bad variant index, trailing bytes, corrupt contents).
    Corrupted(String),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::MissingVersionByte => write!(f, "empty input: no version byte"),
            DecodeError::UnsupportedVersion { supported, found } => write!(
                f,
                "unsupported wire version {found} (this build speaks {supported})"
            ),
            DecodeError::Truncated => write!(f, "input truncated mid-message"),
            DecodeError::TooLarge => {
                write!(f, "message exceeds {} byte limit", MAX_WIRE_MESSAGE_BYTES)
            }
            DecodeError::Corrupted(why) => write!(f, "corrupt message: {why}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encode a message with the current version prefix byte.
///
/// Infallible for in-crate messages: `WireMessage` payloads are bounded by
/// construction (cursor pixels are the largest field and are size-checked by
/// the caller that builds them). Panicking here means an internal bug, not a
/// runtime condition to handle.
pub fn encode(message: &WireMessage) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.push(WIRE_VERSION);
    bincode::options()
        .with_limit(MAX_WIRE_MESSAGE_BYTES)
        .serialize_into(&mut bytes, message)
        .expect("in-workspace message within MAX_WIRE_MESSAGE_BYTES");
    bytes
}

/// Decode a `[version][payload]` frame, rejecting unknown versions and any
/// trailing bytes explicitly (independent of bincode's trailing-bytes policy).
pub fn decode(bytes: &[u8]) -> Result<WireMessage, DecodeError> {
    let Some((&version, payload)) = bytes.split_first() else {
        return Err(DecodeError::MissingVersionByte);
    };
    if version != WIRE_VERSION {
        return Err(DecodeError::UnsupportedVersion {
            supported: WIRE_VERSION,
            found: version,
        });
    }

    let mut reader = CountingReader {
        data: payload,
        pos: 0,
    };
    let message = bincode::options()
        .with_limit(MAX_WIRE_MESSAGE_BYTES)
        .deserialize_from(&mut reader)
        .map_err(classify_bincode_error)?;
    if reader.pos != payload.len() {
        return Err(DecodeError::Corrupted(
            "trailing bytes after message".to_owned(),
        ));
    }
    Ok(message)
}

/// `Read` over a byte slice that records how much was consumed, so trailing
/// bytes can be detected after `deserialize_from`.
struct CountingReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = &self.data[self.pos..];
        let n = remaining.len().min(buf.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        Ok(n)
    }
}

fn classify_bincode_error(err: bincode::Error) -> DecodeError {
    use std::io::ErrorKind as IoErrorKind;

    match &*err {
        bincode::ErrorKind::Io(e) if e.kind() == IoErrorKind::UnexpectedEof => {
            DecodeError::Truncated
        }
        bincode::ErrorKind::SizeLimit => DecodeError::TooLarge,
        // Every other encoding/decoding fault (invalid variant index, bad
        // UTF-8, malformed bool/char, ...) is corruption: a typed error,
        // never garbage.
        _ => DecodeError::Corrupted(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_messages() -> Vec<WireMessage> {
        vec![
            WireMessage::Hello {
                capabilities: crate::capabilities::capabilities_sample(),
            },
            WireMessage::HelloAck {
                capabilities: crate::capabilities::capabilities_sample(),
            },
            WireMessage::Ping { nonce: 42 },
            WireMessage::Pong { nonce: 42 },
            WireMessage::KeyframeRequest,
            WireMessage::SetQuality {
                preset: QualityPreset::Balanced,
            },
            WireMessage::SelectMonitor {
                monitor_id: "\\\\.\\DISPLAY2".to_owned(),
            },
            WireMessage::Disconnect {
                reason: ControlDisconnectReason::User,
            },
            WireMessage::Input(InputEvent::MouseMove {
                seq: 7,
                x: 1234,
                y: 5678,
            }),
            WireMessage::Input(InputEvent::MouseButton {
                seq: 8,
                button: MouseButton::Left,
                state: ButtonState::Pressed,
            }),
            WireMessage::Input(InputEvent::Wheel {
                seq: 9,
                delta_v: -120,
                delta_h: 0,
            }),
            WireMessage::Input(InputEvent::Key {
                seq: 10,
                scan_code: 0x1D,
                extended: false,
                state: ButtonState::Pressed,
            }),
            WireMessage::Input(InputEvent::Text {
                seq: 11,
                code_points: "héllo →".to_owned(),
            }),
            WireMessage::Input(InputEvent::AllKeysUp {
                trigger: AllKeysUpTrigger::FocusLost,
            }),
            WireMessage::Cursor(CursorMessage::Position {
                seq: 3,
                x: 100,
                y: 200,
            }),
            WireMessage::Cursor(CursorMessage::Shape {
                id: 1,
                width: 32,
                height: 32,
                hotspot_x: 4,
                hotspot_y: 2,
                format: CursorFormat::Bgra8,
                pixels: vec![0xAB; 32 * 32 * 4],
            }),
            WireMessage::Cursor(CursorMessage::Hide),
        ]
    }

    #[test]
    fn every_message_round_trips_through_the_binary_codec() {
        for message in all_messages() {
            let bytes = encode(&message);
            assert_eq!(bytes[0], WIRE_VERSION, "version prefix missing");
            let back = decode(&bytes).expect("decode");
            assert_eq!(back, message, "round trip mismatch");
        }
    }

    #[test]
    fn unknown_version_fails_with_typed_error_not_garbage() {
        let mut bytes = encode(&WireMessage::Ping { nonce: 1 });
        bytes[0] = WIRE_VERSION + 1;
        // Followed by what would be a perfectly valid payload — the version
        // gate must fire before any payload decoding.
        assert_eq!(
            decode(&bytes),
            Err(DecodeError::UnsupportedVersion {
                supported: WIRE_VERSION,
                found: WIRE_VERSION + 1,
            })
        );
        // Arbitrary junk with an unknown version byte also fails typed.
        assert_eq!(
            decode(&[0xFF, 0xDE, 0xAD, 0xBE, 0xEF]),
            Err(DecodeError::UnsupportedVersion {
                supported: WIRE_VERSION,
                found: 0xFF,
            })
        );
    }

    #[test]
    fn empty_input_is_missing_version_byte() {
        assert_eq!(decode(&[]), Err(DecodeError::MissingVersionByte));
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let mut bytes = encode(&WireMessage::Input(InputEvent::Text {
            seq: 1,
            code_points: "truncate me".to_owned(),
        }));
        bytes.truncate(bytes.len() - 4);
        assert_eq!(decode(&bytes), Err(DecodeError::Truncated));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = encode(&WireMessage::Pong { nonce: 9 });
        bytes.push(0x00);
        assert!(matches!(decode(&bytes), Err(DecodeError::Corrupted(_))));
    }

    #[test]
    fn unknown_variant_index_is_corrupted_not_garbage() {
        // Claim an out-of-range variant index (varint-encoded 999; the enum
        // has 10 variants). Layout: [version][varint variant index][...].
        let mut bytes = vec![WIRE_VERSION, 0xE7, 0x07];
        bytes.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            decode(&bytes),
            Err(DecodeError::Corrupted(_)) | Err(DecodeError::Truncated)
        ));
    }

    #[test]
    fn oversize_claim_is_rejected_not_allocated() {
        // Encode a real Shape message with a tiny pixels buffer, then replace
        // the trailing [varint len][bytes] with a varint length claiming
        // 2 MiB (> the 1 MiB limit) and no data. The decode limit (or EOF)
        // must produce a typed Err — never an allocation proportional to the
        // claim.
        let mut bytes = encode(&WireMessage::Cursor(CursorMessage::Shape {
            id: 1,
            width: 32,
            height: 32,
            hotspot_x: 0,
            hotspot_y: 0,
            format: CursorFormat::Bgra8,
            pixels: vec![0u8; 8],
        }));
        let keep = bytes.len() - 9; // drop [len=8 varint][8 pixel bytes]
        bytes.truncate(keep);
        // varint(2 MiB) = [0x80, 0x80, 0x40]
        bytes.extend_from_slice(&[0x80, 0x80, 0x40]);
        let result = decode(&bytes);
        assert!(matches!(
            result,
            Err(DecodeError::TooLarge) | Err(DecodeError::Truncated)
        ));
    }

    #[test]
    fn json_encoding_of_shared_enums_stays_snake_case() {
        // QualityPreset etc. also appear in JSON exports (diagnostics) —
        // pin their serde tags.
        assert_eq!(
            serde_json::to_string(&QualityPreset::Balanced).unwrap(),
            "\"balanced\""
        );
        assert_eq!(
            serde_json::to_string(&ControlDisconnectReason::TransportError).unwrap(),
            "\"transport_error\""
        );
        assert_eq!(
            serde_json::to_string(&AllKeysUpTrigger::SequenceGap).unwrap(),
            "\"sequence_gap\""
        );
    }

    /// QA F3: input payloads must never be printable — not as a bare event,
    /// not wrapped in `WireMessage` (what transport/log layers actually
    /// carry). Coordinates, buttons, scan codes, and typed text all redact.
    #[test]
    fn input_event_debug_is_redacted() {
        let cases: Vec<(InputEvent, &str)> = vec![
            (
                InputEvent::MouseMove {
                    seq: 7,
                    x: 12_345,
                    y: 54_321,
                },
                "12",
            ),
            (
                InputEvent::MouseButton {
                    seq: 8,
                    button: MouseButton::Right,
                    state: ButtonState::Pressed,
                },
                "Right",
            ),
            (
                InputEvent::Key {
                    seq: 9,
                    scan_code: 0x1E,
                    extended: true,
                    state: ButtonState::Pressed,
                },
                "30",
            ),
            (
                InputEvent::Text {
                    seq: 10,
                    code_points: "hunter2-do-not-log".to_owned(),
                },
                "hunter2",
            ),
        ];
        for (event, secret) in cases {
            let direct = format!("{event:?}");
            assert!(
                !direct.contains(secret),
                "bare Debug leaked {secret:?}: {direct}"
            );
            assert!(
                direct.contains("<redacted>"),
                "missing redaction marker: {direct}"
            );
            let wrapped = format!("{:?}", WireMessage::Input(event));
            assert!(
                !wrapped.contains(secret),
                "WireMessage Debug leaked {secret:?}: {wrapped}"
            );
        }
        // AllKeysUp's trigger is diagnostic state, not user input — visible
        // (derived Debug uses the Rust variant name, not the serde tag).
        let all_up = format!(
            "{:?}",
            InputEvent::AllKeysUp {
                trigger: AllKeysUpTrigger::SequenceGap
            }
        );
        assert!(all_up.contains("SequenceGap"));
        // Cursor state is host→controller metadata, not input: unaffected.
        let cursor = format!(
            "{:?}",
            CursorMessage::Position {
                seq: 3,
                x: 100,
                y: 200
            }
        );
        assert!(cursor.contains("100"));
    }

    /// QA F11: golden bytes pin the binary layout so an accidental field
    /// reorder/type change fails CI instead of relying on review policy
    /// alone. If this test fails intentionally (a deliberate layout change),
    /// bump `WIRE_VERSION` and regenerate the hex in the same patch.
    #[test]
    fn golden_bytes_pin_the_binary_layout() {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
        let cases: Vec<(WireMessage, &str)> = vec![
            // Ping: [version][variant 2][nonce 42]
            (WireMessage::Ping { nonce: 42 }, "00022a"),
            // Input/Key: [version][variant 8][InputEvent::Key=3][seq 10]
            // [scan 29][extended false][Pressed=0]
            (
                WireMessage::Input(InputEvent::Key {
                    seq: 10,
                    scan_code: 29,
                    extended: false,
                    state: ButtonState::Pressed,
                }),
                "0008030a1d0000",
            ),
            // Cursor/Hide: [version][variant 9][CursorMessage::Hide=2]
            (WireMessage::Cursor(CursorMessage::Hide), "000902"),
        ];
        for (message, expected) in cases {
            let encoded = encode(&message);
            assert_eq!(hex(&encoded), expected, "layout drift for {message:?}");
        }
    }
}
