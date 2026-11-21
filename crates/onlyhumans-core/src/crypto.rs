//! Cryptographic core of the OnlyHumans room protocol.
//!
//! Threat model and key lifecycle (as specified by the product owner):
//!
//! * A **global key (GK)** ships inside the software and gates first
//!   contact: both sides prove knowledge of it via HMAC over a fresh nonce,
//!   without ever transmitting it. (Honest caveat: an embedded key can be
//!   extracted from binaries; admission additionally requires host approval
//!   and room keys rotate, containing the blast radius.)
//! * When a room is established, the **host generates a random room key**
//!   and delivers it to participants encrypted under the GK.
//! * All room traffic is sealed with the room key; each message uses a
//!   unique subkey derived from (room key, epoch, sender, seq) so nonce
//!   reuse is impossible and message keys never repeat.
//! * **Rotation**: the host mints a fresh random key and sends it sealed
//!   *under the current room key* — only current participants learn it.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as AeadKey, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub type Key = [u8; 32];
pub type RoomId = [u8; 16];

const OH_DOMAIN: &[u8] = b"OH1";

// ---------------------------------------------------------------------------
// Global-key admission proofs
// ---------------------------------------------------------------------------

/// Prove knowledge of the GK without revealing it.
/// proof = HMAC-SHA256(GK, "OH1-adm" || prover_id || nonce)
pub fn admission_proof(gk: &Key, prover_id: &str, nonce: &[u8; 16]) -> Key {
    let mut ikm = Vec::with_capacity(OH_DOMAIN.len() + 4 + prover_id.len() + 16);
    ikm.extend_from_slice(b"adm");
    ikm.extend_from_slice(prover_id.as_bytes());
    ikm.extend_from_slice(nonce);
    hkdf_sha256(gk, &[], &ikm)
}

pub fn verify_admission_proof(
    gk: &Key,
    prover_id: &str,
    nonce: &[u8; 16],
    proof: &Key,
) -> bool {
    let expect = admission_proof(gk, prover_id, nonce);
    // Constant-time compare — proof bytes cross the network.
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= expect[i] ^ proof[i];
    }
    diff == 0
}

/// Encrypt a room key for delivery to a participant, under the GK.
/// The keystream is bound to (GK, room, epoch, recipient) and the AAD to
/// the same, so no two delivery targets ever share cipher output.
pub fn seal_room_key(gk: &Key, room_id: &RoomId, epoch: u64, recipient: &str, key: &Key) -> Vec<u8> {
    let (nonce, cipher) = gk_cipher(gk, room_id, epoch, recipient);
    let aad = aad_bytes(b"gk-deliv", room_id, epoch, recipient, 0);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: key,
                aad: &aad,
            },
        )
        .expect("seal_room_key encrypt")
}

pub fn open_room_key(gk: &Key, room_id: &RoomId, epoch: u64, recipient: &str, ct: &[u8]) -> anyhow::Result<Key> {
    let (nonce, cipher) = gk_cipher(gk, room_id, epoch, recipient);
    let aad = aad_bytes(b"gk-deliv", room_id, epoch, recipient, 0);
    let pt = cipher
        .decrypt(
            &nonce,
            Payload { msg: ct, aad: &aad },
        )
        .map_err(|_| anyhow::anyhow!("room key delivery failed GK authentication"))?;
    let k: Key = pt
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("room key payload has wrong length"))?;
    Ok(k)
}

/// Deterministic nonce + cipher for the GK delivery channel, bound to
/// (GK, room, epoch, recipient). Binding the derivation to epoch and
/// recipient is what makes rotation meaningful: under the earlier
/// (GK, room)-only derivation every delivery for a room shared one
/// keystream, so a former member holding an old room key plus any two
/// captured deliveries could XOR out the newer key. Replay within the
/// same (epoch, recipient) still yields the identical frame, which the
/// idempotent delivery path already tolerates.
fn gk_cipher(gk: &Key, room_id: &RoomId, epoch: u64, recipient: &str) -> (XNonce, XChaCha20Poly1305) {
    let mut info = Vec::with_capacity(12 + 8 + recipient.len());
    info.extend_from_slice(b"gk-deliv-v2|");
    info.extend_from_slice(&epoch.to_le_bytes());
    info.extend_from_slice(recipient.as_bytes());
    let mut info_n = info.clone();
    info_n.extend_from_slice(b"|n");
    let mut info_k = info;
    info_k.extend_from_slice(b"|k");
    let nonce_bytes = hkdf_sha256(gk, room_id, &info_n);
    let mut n = [0u8; 24];
    n.copy_from_slice(&nonce_bytes[..24]);
    let key_bytes = hkdf_sha256(gk, room_id, &info_k);
    (XNonce::from(n), XChaCha20Poly1305::new(AeadKey::from_slice(&key_bytes)))
}

// ---------------------------------------------------------------------------
// Room crypto
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RoomCrypto {
    pub room_id: RoomId,
    /// Monotonic key epoch; incremented on every rotation.
    pub epoch: u64,
    /// The current epoch's room key.
    key: Key,
}

/// A sealed frame travelling over the (already noise-encrypted) libp2p
/// stream. `ct` is XChaCha20-Poly1305 output; the rest is the AAD.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Sealed {
    pub room_id_hex: String,
    pub epoch: u64,
    pub sender: String,
    pub seq: u64,
    pub nonce_b64: String,
    pub ct_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationSecret {
    pub room_id_hex: String,
    pub next_epoch: u64,
    pub next_key_b64: String,
}

/// Pad a payload to the next size bucket so sealed-frame lengths reveal
/// (almost) nothing about the plaintext: [len:4][body][zeros]. An
/// interceptor measuring ciphertext can only see which bucket a message
/// fell into, not its actual length.
const PAD_BUCKETS: [usize; 8] = [128, 256, 512, 1024, 2048, 4096, 8192, 16384];

fn pad(body: &[u8]) -> Vec<u8> {
    let real = 4 + body.len();
    let target = PAD_BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= real)
        .unwrap_or_else(|| real.div_ceil(16384) * 16384);
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out.resize(target, 0);
    out
}

fn unpad(padded: &[u8]) -> anyhow::Result<&[u8]> {
    let (len_b, rest) = padded.split_at_checked(4).ok_or_else(|| anyhow::anyhow!("short pad"))?;
    let len = u32::from_le_bytes(len_b.try_into().unwrap()) as usize;
    let body = rest.get(..len).ok_or_else(|| anyhow::anyhow!("pad length out of range"))?;
    Ok(body)
}

impl RoomCrypto {
    /// Host side: create a room with a fresh random key.
    pub fn new_host() -> Self {
        let mut room_id = RoomId::default();
        rand::thread_rng().fill_bytes(&mut room_id);
        let mut key = Key::default();
        rand::thread_rng().fill_bytes(&mut key);
        Self { room_id, epoch: 1, key }
    }

    /// Participant side: adopt a delivered key.
    pub fn from_delivered(room_id: RoomId, key: Key) -> Self {
        Self { room_id, epoch: 1, key }
    }

    pub fn room_id_hex(&self) -> String {
        hex::encode(self.room_id)
    }

    pub fn room_key(&self) -> &Key {
        &self.key
    }

    /// Host side, step 1: mint the next key WITHOUT switching to it yet.
    /// The returned secret must be sealed under the CURRENT key, delivered
    /// to every participant, and only then committed locally via
    /// [`RoomCrypto::commit_rotation`].
    pub fn prepare_rotation(&self) -> RotationSecret {
        let mut next = Key::default();
        rand::thread_rng().fill_bytes(&mut next);
        RotationSecret {
            room_id_hex: self.room_id_hex(),
            next_epoch: self.epoch + 1,
            next_key_b64: base64(&next),
        }
    }

    /// Host side, step 2 (after delivery): switch to the prepared key.
    /// Participants use the identical code path via [`RoomCrypto::apply_rotation`].
    pub fn commit_rotation(&mut self, secret: &RotationSecret) -> anyhow::Result<()> {
        self.apply_rotation(secret)
    }

    /// Seal an arbitrary payload under the current key (chat, rotation,
    /// membership). The plaintext is padded to a size bucket first, so the
    /// ciphertext length does not leak the payload length.
    pub fn seal(&self, sender: &str, seq: u64, kind: &[u8; 8], plaintext: &[u8]) -> Sealed {
        let padded = pad(plaintext);
        let mk = self.message_key(sender, seq, kind);
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(&mk));
        let aad = aad_bytes(kind, &self.room_id, self.epoch, sender, seq);
        let ct = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload { msg: &padded, aad: &aad },
            )
            .expect("aead encrypt never fails on valid input");
        Sealed {
            room_id_hex: self.room_id_hex(),
            epoch: self.epoch,
            sender: sender.to_string(),
            seq,
            nonce_b64: base64(&nonce),
            ct_b64: base64(&ct),
        }
    }

    /// Open a sealed frame; returns the plaintext or an error (wrong key,
    /// tampering, replay across epochs — epoch is part of the AAD).
    pub fn open(&self, frame: &Sealed, kind: &[u8; 8]) -> anyhow::Result<Vec<u8>> {
        if frame.room_id_hex != self.room_id_hex() {
            anyhow::bail!("frame belongs to a different room");
        }
        if frame.epoch != self.epoch {
            anyhow::bail!(
                "frame epoch {} != current {} (rotation race or replay)",
                frame.epoch,
                self.epoch
            );
        }
        let mk = self.message_key(&frame.sender, frame.seq, kind);
        let nonce: [u8; 24] = unbase64(&frame.nonce_b64)?;
        let ct = unbase64_vec(&frame.ct_b64)?;
        let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(&mk));
        let aad = aad_bytes(kind, &self.room_id, self.epoch, &frame.sender, frame.seq);
        let padded = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload { msg: &ct, aad: &aad },
            )
            .map_err(|_| anyhow::anyhow!("frame failed authentication"))?;
        unpad(&padded).map(|s| s.to_vec())
    }

    /// Apply a rotation received from the host.
    pub fn apply_rotation(&mut self, secret: &RotationSecret) -> anyhow::Result<()> {
        if secret.next_epoch != self.epoch + 1 {
            anyhow::bail!(
                "rotation epoch {} does not follow current {}",
                secret.next_epoch,
                self.epoch
            );
        }
        let k = unbase64::<32>(&secret.next_key_b64)?;
        self.epoch = secret.next_epoch;
        self.key = k;
        Ok(())
    }

    /// Per-message subkey: HKDF(room_key, salt=room||epoch, info=kind||sender||seq).
    /// Message keys are derived, never stored, and never repeat for a given
    /// (epoch, sender, seq) triple.
    fn message_key(&self, sender: &str, seq: u64, kind: &[u8; 8]) -> Key {
        let mut salt = Vec::with_capacity(24);
        salt.extend_from_slice(&self.room_id);
        salt.extend_from_slice(&self.epoch.to_le_bytes());
        let mut info = Vec::with_capacity(kind.len() + sender.len() + 8);
        info.extend_from_slice(kind);
        info.extend_from_slice(sender.as_bytes());
        info.extend_from_slice(&seq.to_le_bytes());
        hkdf_sha256(&self.key, &salt, &info)
    }
}

fn aad_bytes(kind: &[u8; 8], room: &RoomId, epoch: u64, sender: &str, seq: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 16 + 8 + sender.len() + 8);
    v.extend_from_slice(OH_DOMAIN);
    v.extend_from_slice(kind);
    v.extend_from_slice(room);
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(sender.as_bytes());
    v.extend_from_slice(&seq.to_le_bytes());
    v
}

/// Public base64 helpers used by the hub and rooms modules.
pub fn base64_encode(data: &[u8]) -> String {
    base64(data)
}

pub fn base64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    unbase64_vec(s)
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Key::default();
    hk.expand(info, &mut out).expect("32 bytes is valid HKDF size");
    out
}

fn base64(data: &[u8]) -> String {
    // Minimal std base64 (URL-safe, no padding) to avoid another dependency.
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHA[(n >> 18) as usize & 63] as char);
        out.push(ALPHA[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHA[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHA[n as usize & 63] as char);
        }
    }
    out
}

fn unbase64_vec(s: &str) -> anyhow::Result<Vec<u8>> {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut vals = Vec::with_capacity(s.len());
    for c in s.bytes() {
        let idx = ALPHA
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| anyhow::anyhow!("invalid base64 character"))?;
        vals.push(idx as u32);
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4 + 3);
    for chunk in vals.chunks(4) {
        let mut n = 0u32;
        for (i, v) in chunk.iter().enumerate() {
            n |= v << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

fn unbase64<const N: usize>(s: &str) -> anyhow::Result<[u8; N]> {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut vals = Vec::with_capacity(s.len());
    for c in s.bytes() {
        let idx = ALPHA
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| anyhow::anyhow!("invalid base64 character"))?;
        vals.push(idx as u32);
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4 + 3);
    for chunk in vals.chunks(4) {
        let mut n = 0u32;
        for (i, v) in chunk.iter().enumerate() {
            n |= v << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    out.try_into()
        .map_err(|_| anyhow::anyhow!("base64 payload has wrong length"))
}

/// Frame kinds used as AAD tags so a chat frame can't be replayed as a
/// rotation frame and vice versa.
pub mod kinds {
    pub const CHAT: &[u8; 8] = b"chat\0\0\0\0";
    pub const ROTATE: &[u8; 8] = b"rotate\0\0";
    pub const MEMBERS: &[u8; 8] = b"members\0";
    pub const CLEAR: &[u8; 8] = b"clear\0\0\0";
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gk() -> Key {
        let mut k = Key::default();
        k[0] = 42;
        k
    }

    #[test]
    fn admission_proof_roundtrip_and_specificity() {
        let gk = gk();
        let nonce = [7u8; 16];
        let proof = admission_proof(&gk, "peer-a", &nonce);
        assert!(verify_admission_proof(&gk, "peer-a", &nonce, &proof));
        // Wrong peer id or nonce must fail
        assert!(!verify_admission_proof(&gk, "peer-b", &nonce, &proof));
        assert!(!verify_admission_proof(&gk, "peer-a", &[8u8; 16], &proof));
        // Different GK must fail
        let mut other = Key::default();
        other[0] = 43;
        assert!(!verify_admission_proof(&other, "peer-a", &nonce, &proof));
    }

    #[test]
    fn padding_hides_message_lengths() {
        let mut id = RoomId::default();
        rand::thread_rng().fill_bytes(&mut id);
        let rc = RoomCrypto::from_delivered(id, [7u8; 32]);

        // Two very different plaintexts in the same bucket must produce
        // identical ciphertext lengths — an interceptor measuring frames
        // learns only the bucket, not the message size.
        let short = rc.seal("a", 1, kinds::CHAT, b"k");
        let long = rc.seal("a", 2, kinds::CHAT, &[0u8; 100][..]);
        assert_eq!(short.ct_b64.len(), long.ct_b64.len());

        // Cross-bucket: a 400-byte body lands in the next bucket up.
        let big = rc.seal("a", 3, kinds::CHAT, &[0u8; 400][..]);
        assert!(big.ct_b64.len() > long.ct_b64.len());

        // Roundtrips preserve the exact body regardless of padding.
        assert_eq!(rc.open(&short, kinds::CHAT).unwrap(), b"k");
        assert_eq!(rc.open(&long, kinds::CHAT).unwrap(), vec![0u8; 100]);
        assert_eq!(rc.open(&big, kinds::CHAT).unwrap(), vec![0u8; 400]);

        // Tampered length prefix must not yield a body.
        let mut tampered = pad(b"hello");
        tampered[0] = 0xFF;
        assert!(unpad(&tampered).is_err());
    }

    #[test]
    fn room_key_delivery_requires_gk() {
        let gk = gk();
        let host = RoomCrypto::new_host();
        let ct = seal_room_key(&gk, &host.room_id, 1, "peer-b", host.room_key());
        let got = open_room_key(&gk, &host.room_id, 1, "peer-b", &ct).unwrap();
        assert_eq!(got, *host.room_key());
        // Wrong recipient, wrong epoch, or wrong GK must fail
        assert!(open_room_key(&gk, &host.room_id, 1, "peer-c", &ct).is_err());
        assert!(open_room_key(&gk, &host.room_id, 2, "peer-b", &ct).is_err());
        let mut other = Key::default();
        other[0] = 43;
        assert!(open_room_key(&other, &host.room_id, 1, "peer-b", &ct).is_err());
    }

    #[test]
    fn delivery_keystreams_differ_across_epochs_and_recipients() {
        // F1 regression: under the old (GK, room)-only derivation every
        // delivery for a room shared one keystream, so a former member
        // (holding an old room key) plus two captured deliveries could
        // XOR out the newer key — defeating rotation. Bound to (room,
        // epoch, recipient), the XOR of two ciphertexts must not leak the
        // XOR of the plaintexts.
        let gk = gk();
        let host = RoomCrypto::new_host();
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];

        let ct_e1 = seal_room_key(&gk, &host.room_id, 1, "peer-b", &k1);
        let ct_e2 = seal_room_key(&gk, &host.room_id, 2, "peer-b", &k2);
        let ct_other = seal_room_key(&gk, &host.room_id, 1, "peer-c", &k1);

        let xor = |a: &[u8], b: &[u8]| -> Vec<u8> { a.iter().zip(b).map(|(x, y)| x ^ y).collect() };
        let leaked = xor(&k1, &k2);
        assert_ne!(xor(&ct_e1[..32], &ct_e2[..32]), leaked);
        assert_ne!(ct_e1, ct_other, "recipients must not share ciphertexts");

        // All are individually sound.
        assert_eq!(open_room_key(&gk, &host.room_id, 1, "peer-b", &ct_e1).unwrap(), k1);
        assert_eq!(open_room_key(&gk, &host.room_id, 2, "peer-b", &ct_e2).unwrap(), k2);
        assert_eq!(open_room_key(&gk, &host.room_id, 1, "peer-c", &ct_other).unwrap(), k1);
    }

    #[test]
    fn chat_roundtrip_and_key_isolation() {
        let host = RoomCrypto::new_host();
        let guest = RoomCrypto::from_delivered(host.room_id, *host.room_key());

        let frame = host.seal("host", 1, kinds::CHAT, b"hello onlyhumans");
        let pt = guest.open(&frame, kinds::CHAT).unwrap();
        assert_eq!(pt, b"hello onlyhumans");

        // Guest replies
        let frame = guest.seal("guest", 1, kinds::CHAT, b"hi back");
        assert_eq!(host.open(&frame, kinds::CHAT).unwrap(), b"hi back");

        // An outsider with the same room id but wrong key cannot open.
        let mut wrong = Key::default();
        wrong[31] = 1;
        let outsider = RoomCrypto::from_delivered(host.room_id, wrong);
        assert!(outsider.open(&frame, kinds::CHAT).is_err());

        // Kind confusion is rejected: chat frame presented as rotation.
        assert!(guest.open(&frame, kinds::ROTATE).is_err());
    }

    #[test]
    fn rotation_is_visible_only_to_current_participants() {
        let host = RoomCrypto::new_host();
        let old_key = *host.room_key();
        let mut guest = RoomCrypto::from_delivered(host.room_id, old_key);

        // Host prepares the rotation (no state change yet)...
        let secret = host.prepare_rotation();
        // ...seals it under the CURRENT (epoch 1) key and sends it...
        let payload = serde_json::to_vec(&secret).unwrap();
        let frame = host.seal("host", 900, kinds::ROTATE, &payload);
        // ...the guest opens it with the current key and applies it.
        let pt = guest.open(&frame, kinds::ROTATE).unwrap();
        let received: RotationSecret = serde_json::from_slice(&pt).unwrap();
        guest.apply_rotation(&received).unwrap();
        assert_eq!(guest.epoch, 2);

        // Only now does the host commit its own rotation.
        let mut host = host;
        host.commit_rotation(&secret).unwrap();

        // Post-rotation traffic opens with the new key on both sides...
        let frame = host.seal("host", 1, kinds::CHAT, b"after rotate");
        assert_eq!(guest.open(&frame, kinds::CHAT).unwrap(), b"after rotate");

        // ...and the OLD key can no longer open new traffic, nor can a
        // participant stuck on epoch 1 (epoch is part of the AAD).
        let old = RoomCrypto::from_delivered(host.room_id, old_key);
        assert!(old.open(&frame, kinds::CHAT).is_err());
        assert_eq!(old.epoch, 1);
    }

    #[test]
    fn message_subkeys_never_repeat() {
        let host = RoomCrypto::new_host();
        let a = host.message_key("p", 1, kinds::CHAT);
        let b = host.message_key("p", 2, kinds::CHAT);
        let c = host.message_key("q", 1, kinds::CHAT);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn base64_roundtrip() {
        // Exact-size roundtrips for every chunk shape
        for data in [
            vec![5u8],
            vec![5u8, 6],
            vec![9u8, 8, 7],
            (1u8..=16).collect::<Vec<_>>(),
            (0u8..32).collect::<Vec<_>>(),
        ] {
            let enc = base64(&data);
            assert!(
                enc.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
                "invalid charset in {enc}"
            );
            match data.len() {
                1 => assert_eq!(unbase64::<1>(&enc).unwrap().to_vec(), data),
                2 => assert_eq!(unbase64::<2>(&enc).unwrap().to_vec(), data),
                3 => assert_eq!(unbase64::<3>(&enc).unwrap().to_vec(), data),
                16 => assert_eq!(unbase64::<16>(&enc).unwrap().to_vec(), data),
                32 => assert_eq!(unbase64::<32>(&enc).unwrap().to_vec(), data),
                _ => {}
            }
        }
    }
}
