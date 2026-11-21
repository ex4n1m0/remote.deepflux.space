//! Device identity: a libp2p Ed25519 keypair persisted in the app data
//! directory. The derived PeerId is the user's public address-book ID.

use libp2p::identity::Keypair;
use libp2p::PeerId;
use std::path::Path;

#[derive(Clone)]
pub struct Identity {
    keypair: Keypair,
}

impl Identity {
    /// Load `identity.key` from `dir`, creating it on first run.
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let file = dir.join("identity.key");
        if file.exists() {
            let bytes = std::fs::read(&file)?;
            let keypair = Keypair::from_protobuf_encoding(&bytes)
                .map_err(|e| anyhow::anyhow!("corrupt identity file: {e}"))?;
            Ok(Self { keypair })
        } else {
            let keypair = Keypair::generate_ed25519();
            let bytes = keypair
                .to_protobuf_encoding()
                .map_err(|e| anyhow::anyhow!("serialize identity: {e}"))?;
            std::fs::write(&file, &bytes)?;
            Ok(Self { keypair })
        }
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId::from(self.keypair.public())
    }

    /// Human-facing ID string (base58 PeerId).
    pub fn id_string(&self) -> String {
        self.peer_id().to_string()
    }

    /// Public key in protobuf encoding, for hub registration payloads.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.keypair.public().encode_protobuf()
    }

    pub fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.keypair
            .sign(msg)
            .map_err(|e| anyhow::anyhow!("signing failed: {e}"))
    }

    /// Verify a signature against a protobuf-encoded public key.
    pub fn verify(pub_bytes: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        libp2p::identity::PublicKey::try_decode_protobuf(pub_bytes)
            .map(|pk| pk.verify(msg, sig))
            .unwrap_or(false)
    }

    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_stability() {
        let dir = std::env::temp_dir().join(format!("oh-id-{}", std::process::id()));
        let a = Identity::load_or_create(&dir).unwrap();
        let b = Identity::load_or_create(&dir).unwrap();
        assert_eq!(a.id_string(), b.id_string(), "same file must give same ID");

        let msg = b"hub registration";
        let sig = a.sign(msg).unwrap();
        assert!(Identity::verify(&a.public_key_bytes(), msg, &sig));
        assert!(!Identity::verify(&a.public_key_bytes(), b"other", &sig));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
