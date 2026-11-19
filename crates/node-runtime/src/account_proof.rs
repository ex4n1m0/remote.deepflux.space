//! Account proof (ADR-013 P2): the Ed25519 signature that lets a host
//! treat a `connect_request` as coming from a specific installation of its
//! own website account — the trust basis for account-scoped remote control
//! without a pairing-code exchange.
//!
//! Mirrors [`pairing_proof`]: the pure session machines hold no keys, so
//! the composition layer stamps the proof onto machine-built
//! `connect_request` actions ([`AccountProver`]) and verifies inbound ones
//! ([`verify_account_proof`]). Domain separation (`account-proof:v1`) plus
//! the bound `{controller}|{host}|{session_id}|{message_id}|{ts_ms}` make a
//! captured proof useless in a fresh envelope and stale once past
//! [`PROOF_MAX_AGE_MS`].
//!
//! What a valid proof DOES establish: the signer holds the private key of
//! exactly the named installation (`installation_id` is
//! `base58(SHA-256(pub_key))` — self-certifying, no issuer needed). What it
//! does NOT: account membership. The host checks that against its own
//! account-directory cache (app layer) — signature valid but installation
//! unknown is treated as unpaired traffic (prompt with cooldowns, never
//! silent accept).

use std::sync::Arc;

use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey;
use protocol::signaling::AccountProof;
use sha2::Digest;
use sha2::Sha256;

/// Domain separator (version-pin test below).
pub const ACCOUNT_PROOF_DOMAIN: &str = "account-proof:v1";
/// Freshness window — mirrors the pairing-proof rule (generous for
/// family-PC clock skew; NTP-normalized in practice).
pub const PROOF_MAX_AGE_MS: u64 = 10 * 60 * 1000;

/// The signed string. Field order is frozen (the domain-pin test).
fn domain_string(
    installation_id: &str,
    controller_device: &str,
    host_device: &str,
    session_id: &str,
    message_id: &str,
    ts_ms: u64,
) -> String {
    format!(
        "{ACCOUNT_PROOF_DOMAIN}|{installation_id}|{controller_device}|{host_device}|{session_id}|{message_id}|{ts_ms}"
    )
}

/// base58(SHA-256(pub_key)) — the identity crate's derivation, local copy
/// (the tracker and the app both compute exactly this).
pub fn installation_id_for(pub_key: &[u8]) -> String {
    bs58::encode(Sha256::digest(pub_key)).into_string()
}

/// The controller's account-identity signer: everything needed to stamp
/// account proofs, with the private key behind a closure so the pure
/// runtime never touches key material directly (the app wraps its
/// `SwarmIdentity::sign_raw`).
/// The private-key half lives behind this closure so the pure runtime
/// never touches key material directly (the app wraps its
/// `SwarmIdentity::sign_raw`).
pub type AccountSigner = Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

#[derive(Clone)]
pub struct AccountProver {
    installation_id: String,
    pub_key_b58: String,
    /// Signs the domain string, returns the lowercase-hex signature.
    sign: AccountSigner,
}

impl AccountProver {
    pub fn new(installation_id: String, pub_key_b58: String, sign: AccountSigner) -> Self {
        Self {
            installation_id,
            pub_key_b58,
            sign,
        }
    }

    /// Build the proof for one outgoing `connect_request`. `None` when the
    /// signer fails (fail closed: no proof → the host falls back to its
    /// normal unpaired path).
    pub fn prove(
        &self,
        controller_device: &str,
        host_device: &str,
        session_id: &str,
        message_id: &str,
        ts_ms: u64,
    ) -> Option<AccountProof> {
        let domain = domain_string(
            &self.installation_id,
            controller_device,
            host_device,
            session_id,
            message_id,
            ts_ms,
        );
        let signature_hex = (self.sign)(&domain).ok()?;
        Some(AccountProof {
            installation_id: self.installation_id.clone(),
            pub_key_b58: self.pub_key_b58.clone(),
            signature_hex,
            ts_ms,
        })
    }
}

impl core::fmt::Debug for AccountProver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The closure may capture the private key — never derive Debug.
        f.debug_struct("AccountProver")
            .field("installation_id", &self.installation_id)
            .field("sign", &"<closure>")
            .finish()
    }
}

/// Verify an inbound proof for one envelope at host time `now_ms`. Fails
/// closed on: missing proof, malformed base58/hex, a public key whose hash
/// does not equal the claimed `installation_id` (self-certification), any
/// mismatched domain field, a bad signature, or a timestamp outside
/// [`PROOF_MAX_AGE_MS`]. Membership is the caller's call.
pub fn verify_account_proof(
    proof: Option<&AccountProof>,
    controller_device: &str,
    host_device: &str,
    session_id: &str,
    message_id: &str,
    now_ms: u64,
) -> bool {
    let Some(proof) = proof else {
        return false;
    };
    if now_ms.abs_diff(proof.ts_ms) > PROOF_MAX_AGE_MS {
        return false;
    }
    let Ok(pub_key) = bs58::decode(&proof.pub_key_b58).into_vec() else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&{
        // from_bytes wants [u8; 32]; longer keys are refused.
        let arr: [u8; 32] = match pub_key.try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };
        arr
    }) else {
        return false;
    };
    // Self-certification: the installation id must be the key's hash —
    // otherwise the signer picked a victim's id and its own key.
    if installation_id_for(&verifying.to_bytes()) != proof.installation_id {
        return false;
    }
    let Ok(signature_bytes) = hex::decode(&proof.signature_hex) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(&signature_bytes) else {
        return false;
    };
    let domain = domain_string(
        &proof.installation_id,
        controller_device,
        host_device,
        session_id,
        message_id,
        proof.ts_ms,
    );
    verifying.verify(domain.as_bytes(), &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn prover() -> (AccountProver, SigningKey) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let pub_key_b58 = bs58::encode(signing.verifying_key().to_bytes()).into_string();
        let installation_id = installation_id_for(&signing.verifying_key().to_bytes());
        let captured = signing.clone();
        let prover = AccountProver::new(
            installation_id.clone(),
            pub_key_b58,
            Arc::new(move |domain: &str| {
                use ed25519_dalek::Signer;
                Ok(hex::encode(captured.sign(domain.as_bytes()).to_bytes()))
            }),
        );
        (prover, signing)
    }

    const CTRL: &str = "0123456789abcdef";
    const HOST: &str = "fedcba9876543210";
    const NOW: u64 = 1_760_000_000_000;

    #[test]
    fn round_trip_verify() {
        let (prover, _) = prover();
        let proof = prover
            .prove(CTRL, HOST, "s-1", "m-1", NOW)
            .expect("valid proof");
        assert!(verify_account_proof(
            Some(&proof),
            CTRL,
            HOST,
            "s-1",
            "m-1",
            NOW
        ));
    }

    #[test]
    fn domain_fields_bind() {
        let (prover, _) = prover();
        let proof = prover.prove(CTRL, HOST, "s-1", "m-1", NOW).unwrap();
        for (c, h, s, m) in [
            ("0123456789abcdee", HOST, "s-1", "m-1"),
            (CTRL, "fedcba9876543211", "s-1", "m-1"),
            (CTRL, HOST, "s-2", "m-1"),
            (CTRL, HOST, "s-1", "m-9"),
        ] {
            assert!(
                !verify_account_proof(Some(&proof), c, h, s, m, NOW),
                "must not verify for {c}/{h}/{s}/{m}"
            );
        }
    }

    #[test]
    fn freshness_window_rejects_old_captures() {
        let (prover, _) = prover();
        let proof = prover.prove(CTRL, HOST, "s-1", "m-1", NOW).unwrap();
        assert!(!verify_account_proof(
            Some(&proof),
            CTRL,
            HOST,
            "s-1",
            "m-1",
            NOW + PROOF_MAX_AGE_MS + 1
        ));
        assert!(verify_account_proof(
            Some(&proof),
            CTRL,
            HOST,
            "s-1",
            "m-1",
            NOW + PROOF_MAX_AGE_MS
        ));
    }

    #[test]
    fn self_certification_fails_a_stolen_installation_id() {
        let (prover, _) = prover();
        let mut proof = prover.prove(CTRL, HOST, "s-1", "m-1", NOW).unwrap();
        // Claim someone else's installation id with our valid signature.
        proof.installation_id = "SomebodyElse1111111111111111111111111111".to_owned();
        assert!(!verify_account_proof(
            Some(&proof),
            CTRL,
            HOST,
            "s-1",
            "m-1",
            NOW
        ));
    }

    #[test]
    fn garbage_fails_closed() {
        let (prover, _) = prover();
        let proof = prover.prove(CTRL, HOST, "s-1", "m-1", NOW).unwrap();
        assert!(!verify_account_proof(None, CTRL, HOST, "s-1", "m-1", NOW));
        let mut bad_key = proof.clone();
        bad_key.pub_key_b58 = "notbase58!!".to_owned();
        assert!(!verify_account_proof(
            Some(&bad_key),
            CTRL,
            HOST,
            "s-1",
            "m-1",
            NOW
        ));
        let mut bad_sig = proof.clone();
        bad_sig.signature_hex = "zz".to_owned();
        assert!(!verify_account_proof(
            Some(&bad_sig),
            CTRL,
            HOST,
            "s-1",
            "m-1",
            NOW
        ));
        // A signature from a DIFFERENT key (forged with another signer).
        let other = SigningKey::from_bytes(&[9u8; 32]);
        use ed25519_dalek::Signer;
        let domain = domain_string(&proof.installation_id, CTRL, HOST, "s-1", "m-1", NOW);
        let mut forged = proof.clone();
        forged.signature_hex = hex::encode(other.sign(domain.as_bytes()).to_bytes());
        assert!(!verify_account_proof(
            Some(&forged),
            CTRL,
            HOST,
            "s-1",
            "m-1",
            NOW
        ));
    }

    #[test]
    fn domain_is_pinned() {
        assert_eq!(ACCOUNT_PROOF_DOMAIN, "account-proof:v1");
        assert_eq!(
            domain_string("inst", "c", "h", "s", "m", 7),
            "account-proof:v1|inst|c|h|s|m|7"
        );
    }
}
