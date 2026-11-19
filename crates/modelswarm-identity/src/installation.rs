//! Per-installation Ed25519 identity (ADR-004, msp-v1 §2.1).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRngCore, OsRng};
use sha2::{Digest, Sha256};

/// An installation's Ed25519 signing identity.
///
/// One keypair per installation. Two public derivations (ADR-020):
///
/// - `installation_id()` = base58(SHA-256(public key bytes)) — the hub-side
///   identity and envelope signer label.
/// - [`InstallationIdentity::peer_id`] = base58(0x12 0x20 ‖ SHA-256(public
///   key bytes)) — the wire identity, exactly libp2p's identity-multihash
///   PeerId (the `12D3Koo…` form). Typed `PeerId` wrappers arrive with the
///   libp2p backend; the string derivation is final.
#[derive(Debug, Clone)]
pub struct InstallationIdentity {
    signing_key: SigningKey,
}

impl InstallationIdentity {
    /// Generates a fresh keypair from the operating system CSPRNG.
    pub fn generate() -> Self {
        Self::generate_with(&mut OsRng)
    }

    /// Generates a fresh keypair from a caller-supplied RNG (tests,
    /// deterministic simulations).
    pub fn generate_with(rng: &mut impl CryptoRngCore) -> Self {
        Self {
            signing_key: SigningKey::generate(rng),
        }
    }

    /// Restores an identity from its 32 seed bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    /// The 32 seed bytes (SECRET — never log, transmit, or persist unencrypted).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// The 32-byte Ed25519 public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The Ed25519 verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// `installationId` = base58(SHA-256(public key bytes)) (msp-v1 §2.1).
    pub fn installation_id(&self) -> String {
        installation_id_for(&self.public_key_bytes())
    }

    /// The public key itself, base58 — the enrollment wire form
    /// (`/auth/device/start` `pubKey`, msp-v1 §3.2).
    pub fn pub_key_b58(&self) -> String {
        bs58::encode(self.public_key_bytes()).into_string()
    }

    /// The wire identity (ADR-020): base58 of the identity multihash over
    /// the protobuf-encoded public key — exactly libp2p's PeerId for an
    /// Ed25519 identity key (the `12D3Koo…` form). Distinct from
    /// [`Self::installation_id`].
    pub fn peer_id(&self) -> String {
        peer_id_for(&self.public_key_bytes())
    }

    /// Phase B–E placeholder kept as a deprecated alias of
    /// [`Self::peer_id`] (ADR-020 migration: the old placeholder returned
    /// the installation id; it now derives the real PeerId so stale call
    /// sites cannot keep the placeholder equality alive).
    #[deprecated(
        since = "0.1.0",
        note = "ADR-020: use peer_id() (identity-multihash derivation)"
    )]
    pub fn peer_id_label(&self) -> String {
        self.peer_id()
    }

    /// Signs an arbitrary message (used by the envelope and lease modules).
    pub(crate) fn sign_raw(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

/// base58(SHA-256(public key bytes)) — the public identity label derivation.
pub fn installation_id_for(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    bs58::encode(digest).into_string()
}

/// The identity-multihash prefix of a libp2p Ed25519 PeerId: code `0x00`
/// (identity) with length `0x24` (36) — the protobuf-encoded public key
/// that follows is exactly 36 bytes.
pub const PEER_ID_MULTIHASH_PREFIX: [u8; 2] = [0x00, 0x24];

/// The protobuf encoding of an Ed25519 `PublicKey` (libp2p key proto):
/// field 1 `Type = 1` (Ed25519, varint) + field 2 `Data` (length-delimited
/// 32-byte key). The `0x12 0x20` in the middle is the Data field tag and
/// length — the two bytes ADR-020's shorthand formula names. Verified
/// byte-identical to `libp2p_identity::PublicKey::encode_protobuf` (the
/// `libp2p-backend` F11 test cross-checks the full PeerId).
fn ed25519_public_key_protobuf(public_key: &[u8]) -> Vec<u8> {
    let mut protobuf = Vec::with_capacity(4 + public_key.len());
    protobuf.extend_from_slice(&[0x08, 0x01]); // field 1 (Type) = 1 (Ed25519)
    protobuf.extend_from_slice(&[0x12, 0x20]); // field 2 (Data) tag + length 32
    protobuf.extend_from_slice(public_key);
    protobuf
}

/// `peer_id` = base58(identity-multihash(protobuf(pubkey))) (ADR-020) —
/// exactly libp2p's PeerId for an Ed25519 identity key: the `12D3Koo…`
/// form, 52 base58 characters. Deterministic, and distinct from
/// [`installation_id_for`] for every key.
///
/// Byte form: `0x00 0x24 ‖ 0x08 0x01 0x12 0x24 ‖ pubkey` — the identity
/// multihash code (0x00), the protobuf length (36 = 0x24), then the
/// protobuf body. (ADR-020's shorthand "0x12 0x20 ‖ SHA-256" names the
/// CIDv0-style digest multihash; the normative `12D3Koo` PeerId form
/// mandated by the acceptance gate is this identity-multihash derivation.)
pub fn peer_id_for(public_key: &[u8]) -> String {
    let protobuf = ed25519_public_key_protobuf(public_key);
    let mut multihash = Vec::with_capacity(PEER_ID_MULTIHASH_PREFIX.len() + protobuf.len());
    multihash.extend_from_slice(&PEER_ID_MULTIHASH_PREFIX);
    multihash.extend_from_slice(&protobuf);
    bs58::encode(multihash).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installation_id_is_deterministic_and_key_derived() {
        let seed = [7u8; 32];
        let a = InstallationIdentity::from_bytes(&seed);
        let b = InstallationIdentity::from_bytes(&seed);
        assert_eq!(a.installation_id(), b.installation_id());
        assert_eq!(
            a.installation_id(),
            installation_id_for(&a.public_key_bytes())
        );

        // Cross-check the derivation against a hand-computed value over the
        // PUBLIC key (not the seed).
        let digest = Sha256::digest(a.public_key_bytes());
        assert_eq!(a.installation_id(), bs58::encode(digest).into_string());
    }

    /// ADR-020 / F12 known vector: `peer_id` = base58(identity-multihash of
    /// the protobuf-encoded Ed25519 public key) computed step by step with
    /// the raw primitives (no `peer_id_for` in the path), decoded back, and
    /// cross-checked against the libp2p Ed25519 PeerId invariants.
    #[test]
    fn peer_id_known_vector_matches_identity_multihash_algorithm() {
        let identity = InstallationIdentity::from_bytes(&[9u8; 32]);
        let pubkey = identity.public_key_bytes();

        // Hand computation with the raw algorithm.
        let mut multihash: Vec<u8> = vec![0x00u8, 0x24]; // identity code, length 36
        multihash.extend_from_slice(&[0x08, 0x01]); // protobuf field 1: Type = Ed25519
        multihash.extend_from_slice(&[0x12, 0x20]); // protobuf field 2: Data (32 bytes)
        multihash.extend_from_slice(&pubkey);
        let hand_computed = bs58::encode(&multihash).into_string();

        assert_eq!(identity.peer_id(), hand_computed);
        assert_eq!(peer_id_for(&pubkey), hand_computed);
        assert_eq!(multihash.len(), 38, "2 multihash bytes + 36 protobuf bytes");

        // The libp2p identity-PeerId form: every Ed25519 identity multihash
        // base58-encodes to a 52-char string starting "12D3Koo" (the fixed
        // 0x00 0x24 0x08 0x01 prefix fixes the leading digits; if this
        // prefix is wrong the derivation is wrong).
        assert_eq!(hand_computed.len(), 52, "got {hand_computed}");
        assert!(
            hand_computed.starts_with("12D3Koo"),
            "libp2p identity PeerIds start with 12D3Koo: got {hand_computed}"
        );

        // Decoding round-trips to exactly the multihash bytes.
        let decoded = bs58::decode(&hand_computed).into_vec().unwrap();
        assert_eq!(decoded, multihash);
        assert_eq!(&decoded[..2], &[0x00, 0x24]);
        assert_eq!(&decoded[2..6], &[0x08, 0x01, 0x12, 0x20]);
        assert_eq!(&decoded[6..], &pubkey[..]);

        // The two derivations are distinct for the same key (ADR-020).
        assert_ne!(identity.peer_id(), identity.installation_id());

        // Cross-language golden (TS `derivePeerId` in apps/tracker asserts the
        // same literal; the `libp2p-backend` F11 test asserts the same
        // derivation against `libp2p_identity` itself): seed [9u8; 32] fixes
        // every byte of this string.
        assert_eq!(
            hand_computed,
            "12D3KooWSrKnMZUcSxK8G7wmBbXdU8nFEfWGhLu6H8xjn8LmCSJb"
        );
    }

    #[test]
    fn peer_id_is_deterministic_key_derived_and_distinct_from_installation_id() {
        let a = InstallationIdentity::from_bytes(&[1u8; 32]);
        let b = InstallationIdentity::from_bytes(&[1u8; 32]);
        let c = InstallationIdentity::from_bytes(&[2u8; 32]);
        assert_eq!(a.peer_id(), b.peer_id());
        assert_ne!(a.peer_id(), c.peer_id());
        assert_ne!(a.peer_id(), a.installation_id());
        assert_ne!(b.peer_id(), b.installation_id());
        assert!(a.peer_id().starts_with("12D3Koo"));
        assert_eq!(a.peer_id().len(), 52);
        // The deprecated alias forwards to the real derivation.
        #[allow(deprecated)]
        {
            assert_eq!(a.peer_id_label(), a.peer_id());
        }
    }

    #[test]
    fn distinct_keys_have_distinct_ids() {
        let a = InstallationIdentity::generate();
        let b = InstallationIdentity::generate();
        assert_ne!(a.installation_id(), b.installation_id());
        assert!(!a.installation_id().is_empty());
    }

    #[test]
    fn from_bytes_round_trips() {
        let id = InstallationIdentity::generate();
        let restored = InstallationIdentity::from_bytes(&id.to_bytes());
        assert_eq!(restored.installation_id(), id.installation_id());
    }
}
