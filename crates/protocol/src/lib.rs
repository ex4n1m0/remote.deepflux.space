//! # `protocol` — versioned wire messages and capability negotiation
//!
//! Single source of truth for every byte and JSON key that crosses a process
//! boundary in this project. Two distinct surfaces live here:
//!
//! * [`signaling`] — JSON envelopes exchanged through the Vercel control plane
//!   (register/heartbeat presence, connect request, accept/reject with a
//!   one-time session secret, SDP/ICE mailbox, trickle candidates, cancel,
//!   disconnect). Field names are **stable snake_case** and are the contract
//!   the TypeScript signaling service is generated against (M3, delta D7).
//!   JSON is chosen deliberately: inspectable, debuggable, TS-friendly. The
//!   control plane carries only envelopes — never frames, never input.
//!
//! * [`wire`] — compact **binary** messages for the WebRTC data channels
//!   (control, input, cursor) plus the capability-negotiation payload. Framed
//!   as `[version byte][bincode payload]`. Bincode is not self-describing, so
//!   *any* change to a binary layout requires a `WIRE_VERSION` bump; unknown
//!   versions must fail with [`wire::DecodeError::UnsupportedVersion`], never
//!   decode into garbage.
//!
//! * [`capabilities`] — the capability-negotiation struct shared by both
//!   surfaces (hardware/software encoders, max resolution/fps, monitor list,
//!   feature flags).
//!
//! * [`chat`] — the sealed chat-inbox envelope (`PUT/GET /api/chat`,
//!   ADR-005), folded in from `apps/desktop` by ADR-006 so every surface is
//!   owned here.
//!
//! * [`directory`] — the circle-directory API (`POST /api/directory`,
//!   ADR-006): the family-circle machine directory. Entries are AES-256-GCM
//!   sealed under the client-held circle key; the server sees device ids,
//!   ciphertext, server-minted timestamps, and online flags only.
//!
//! ## Versioning policy (AGENTS.md invariant 5)
//!
//! * Signaling `protocol_version` is currently `1` ([`signaling::SIGNALING_PROTOCOL_VERSION`];
//!   bumped 0→1 in the M0 QA patch for the `sdp_mid` string change — see the
//!   constant's history note).
//! * Chat envelope version is currently `1` ([`chat::CHAT_PROTOCOL_VERSION`]).
//! * Directory API `protocol_version` is currently `1`
//!   ([`directory::DIRECTORY_PROTOCOL_VERSION`]).
//! * Binary wire version is currently `1` ([`wire::WIRE_VERSION`]; bumped
//!   0→1 by ADR-005 for the chat channel + pairing handshake).
//! * A version bump is an explicit, reviewed contract change and must ship
//!   with an updated compatibility test in this crate.
//! * JSON: additive `Option` fields are tolerated within a version (serde
//!   ignores unknown keys). Binary: no in-version layout changes at all.

pub mod capabilities;
pub mod chat;
pub mod directory;
pub mod signaling;
pub mod wire;
