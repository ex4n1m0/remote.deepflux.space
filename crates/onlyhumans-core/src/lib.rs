// OnlyHumans core — peer-to-peer chat with a Vercel address hub.
// Proprietary/unlicensed (user's choice); no third-party copyleft code.

pub mod crypto;
pub mod hub;
pub mod identity;
pub mod net;
pub mod rooms;
pub mod store;

/// Public release-channel identifier (16 bytes, committed). Same for every
/// clone, but by itself it derives nothing useful — the room key domain
/// also needs the channel secret, which exists only in release builds.
#[cfg(test)]
static GK_CHANNEL: &[u8] = include_bytes!("gk_channel.bin");

/// The community global key.
///
/// GK = SHA-256("OH1-gk-v2|" | channel | secret). The whole derivation
/// runs in build.rs, which resolves the secret from exactly one of:
///  * release builds: `OH_GK_A` / `OH_GK_B` env vars — two XOR shares of
///    the channel secret;
///  * `OH_GLOBAL_KEY` (raw hex) as a build-time override;
///  * everyone else (fresh clones, CI, dev): a per-clone random secret in
///    the gitignored `secrets/local-gk.key`, auto-generated on first
///    build — every clone gets its own global key and therefore its own
///    room, and can never join a release-channel room.
///
/// build.rs writes the finished 32 raw key bytes to OUT_DIR/gk.bin and
/// this function embeds them. The share/env hex values never become
/// string literals in the compiled binary (deriving here via `option_env!`
/// did exactly that on targets where the optimizer keeps the literals in
/// .rodata). Note the finished release-channel GK is PUBLIC BY DESIGN
/// since the web portal: the site's /gk.json hands it to every browser
/// tab (they must seal/unseal with it), so GK knowledge is not a secret
/// from the site's audience — admission strength comes from the room
/// word, and "earth" is public. The SHARES and the channel secret remain
/// the protected material: they exist only on release machines and in
/// release builds' derivation, never on the site.
pub fn global_key() -> crypto::Key {
    *include_bytes!(concat!(env!("OUT_DIR"), "/gk.bin"))
}

/// Test-only mirror of the build.rs derivation (same formula), so unit
/// tests can prove channel/secret isolation properties.
#[cfg(test)]
fn derive_gk(channel: &[u8], secret: &[u8; 32]) -> crypto::Key {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"OH1-gk-v2|");
    h.update(channel);
    h.update(secret);
    let mut k = crypto::Key::default();
    k.copy_from_slice(&h.finalize());
    k
}

/// Test-only XOR recombination, mirroring build.rs.
#[cfg(test)]
fn derive_gk_secret(a: &[u8], b: &[u8]) -> [u8; 32] {
    assert!(a.len() == 32 && b.len() == 32, "GK shares must be 32 bytes");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_secrets_never_share_a_room() {
        let mut s1 = [0u8; 32];
        s1[0] = 1;
        let mut s2 = [0u8; 32];
        s2[0] = 2;
        // Same channel, different secrets -> different GK -> different room.
        assert_ne!(derive_gk(GK_CHANNEL, &s1), derive_gk(GK_CHANNEL, &s2));
        // Different channels with the same secret also isolate rooms.
        assert_ne!(derive_gk(b"other-channel-xx", &s1), derive_gk(GK_CHANNEL, &s1));
        // Determinism: same inputs, same key.
        assert_eq!(derive_gk(GK_CHANNEL, &s1), derive_gk(GK_CHANNEL, &s1));
    }

    #[test]
    fn shares_recombine_to_the_secret() {
        let secret = [42u8; 32];
        let mut a = [7u8; 32];
        for i in 0..32 {
            a[i] = i as u8;
        }
        let b: Vec<u8> = secret.iter().zip(a.iter()).map(|(s, x)| s ^ x).collect();
        assert_eq!(derive_gk_secret(&a, &b), secret);
    }
}
