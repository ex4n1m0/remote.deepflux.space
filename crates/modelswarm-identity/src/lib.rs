//! Cryptographic services for ModelSwarm nodes: Ed25519 installation identity
//! (ADR-004), the signed request envelope (msp-v1 §2.3), canonical JSON
//! signing form (§2.2), RFC 3339 timestamps, replay windows, and nonces.
//!
//! Capability-token/lease verification lives in `modelswarm-eligibility`
//! (ADR-012). The libp2p `PeerId` type arrives with `modelswarm-transport`;
//! its string derivation is [`InstallationIdentity::peer_id`] (ADR-020:
//! base58(0x12 0x20 ‖ SHA-256(pubkey)), distinct from the installation id).

pub mod canonical;
pub mod envelope;
pub mod installation;
pub mod timestamp;

pub use canonical::canonical_json;
pub use envelope::SignedEnvelope;
pub use installation::{
    installation_id_for, peer_id_for, InstallationIdentity, PEER_ID_MULTIHASH_PREFIX,
};
pub use timestamp::{
    empty_body_digest, new_nonce, new_nonce_with, rfc3339_now, within_window, REPLAY_WINDOW_SECS,
};
