// Ensure a per-clone local GK secret exists before compilation: fresh
// clones auto-generate one, so every clone derives its own global key and
// can never join a release-channel room. Release builds instead inject the
// channel secret via OH_GK_A/OH_GK_B env vars (never stored in git).
//
// This script also DERIVES the global key and writes the final 32 raw
// bytes to OUT_DIR/gk.bin, which lib.rs embeds with include_bytes!.
// Deriving here (instead of option_env! in lib.rs) guarantees the share
// hex strings never become string literals in the compiled binary: a
// Linux target once kept the option_env! literals in .rodata while
// Windows const-folded them away — optimizer luck is not a security
// property. The binary carries only the finished 32-byte key.
use std::path::PathBuf;

fn main() {
    // The GK derivation consumes these env vars; without these directives
    // changing the env would NOT rerun this script and a release build
    // could silently reuse a previous (e.g. local/dev) global key.
    println!("cargo:rerun-if-env-changed=OH_GK_A");
    println!("cargo:rerun-if-env-changed=OH_GK_B");
    println!("cargo:rerun-if-env-changed=OH_GLOBAL_KEY");

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // workspace root = core/.. ; secrets/ lives there
    let secrets = manifest.parent().unwrap().join("secrets");
    std::fs::create_dir_all(&secrets).expect("create secrets dir");
    let local = secrets.join("local-gk.key");
    if !local.exists() {
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        std::fs::write(&local, buf).expect("write local-gk.key");
        println!("cargo:warning=generated new per-clone GK secret (this build gets its own room)");
    }
    println!("cargo:rerun-if-changed={}", local.display());

    // Derive the global key with the SAME formula lib.rs used to apply at
    // runtime: SHA-256("OH1-gk-v2|" | channel | secret).
    let channel = std::fs::read(manifest.join("src").join("gk_channel.bin"))
        .expect("read src/gk_channel.bin");
    assert_eq!(channel.len(), 16, "gk_channel.bin must be 16 bytes");

    let secret: [u8; 32] = if let Ok(hexstr) = std::env::var("OH_GLOBAL_KEY") {
        let raw = hex::decode(hexstr).expect("OH_GLOBAL_KEY must be hex");
        assert!(raw.len() == 32, "OH_GLOBAL_KEY must be 32 bytes");
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        k
    } else if let (Ok(a), Ok(b)) = (std::env::var("OH_GK_A"), std::env::var("OH_GK_B")) {
        let a = hex::decode(a).expect("OH_GK_A must be hex");
        let b = hex::decode(b).expect("OH_GK_B must be hex");
        assert!(a.len() == 32 && b.len() == 32, "GK shares must be 32 bytes");
        let mut s = [0u8; 32];
        for i in 0..32 {
            s[i] = a[i] ^ b[i];
        }
        s
    } else {
        // Per-clone local secret; generated above if this is a fresh clone.
        let raw = std::fs::read(&local).expect("read local-gk.key");
        assert!(raw.len() == 32, "local-gk.key must be 32 bytes");
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        k
    };

    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"OH1-gk-v2|");
    h.update(&channel);
    h.update(&secret);
    let gk: [u8; 32] = h.finalize().into();

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out_dir.join("gk.bin"), gk).expect("write gk.bin");
    // cargo does not track OUT_DIR files as compile inputs of lib.rs, so
    // the embedded key could go stale when only the env changed. A changed
    // rustc-env directive dirties the crate, forcing a recompile that
    // re-runs include_bytes!. First 4 bytes only — enough to change on any
    // key change, useless to an attacker reading it anywhere.
    println!("cargo:rustc-env=OH_GK_FP={}", hex::encode(gk[..4].iter()));
}
