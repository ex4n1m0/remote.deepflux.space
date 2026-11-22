//! Regeneration helper for the ADR-038 relay-ticket vectors (the §6.1
//! review's drift ruling (b) follow-up): derives a REAL installation
//! pair — `peer_id` (libp2p) and `installation_id = base58(SHA-256(
//! pubkey))`, the ADR-020 rule — from a recorded seed, so the frozen
//! vectors' `installation_id` re-derives from their `peer_id`'s embedded
//! key and checks 7-8 become replayable cross-language.
//!
//! Run: `cargo run -p modelswarm-identity --example derive_pair`

use modelswarm_identity::InstallationIdentity;

fn main() {
    // Recorded in the vectors as peer_identity_seed_hex. Any 32 bytes
    // work; this seed is frozen with the vectors.
    let seed: [u8; 32] = [0x51; 32];
    let identity = InstallationIdentity::from_bytes(&seed);
    println!("peer_identity_seed_hex: {}", hex(&seed));
    println!("public_key_hex: {}", hex(&identity.public_key_bytes()));
    println!("peer_id: {}", identity.peer_id());
    println!("installation_id: {}", identity.installation_id());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
