//! Print THIS build's global key (GK) as base64url — the exact value the
//! web portal's gk.json carries. Builder tool: a local portal serving
//! your own build must use this GK, not the production one, or the
//! browser tab never meets your app (different universe). Write it with:
//!   cargo run -p onlyhumans_core --example gk > gk.json
//! then serve it:  OH_GK_JSON=$PWD/gk.json node portal/local-portal-server.mjs
use onlyhumans_core::crypto::base64_encode;
use onlyhumans_core::global_key;

fn main() {
    let gk = global_key();
    println!(
        "{{\"version\": \"local\", \"gk_b64\": \"{}\"}}",
        base64_encode(&gk)
    );
}
