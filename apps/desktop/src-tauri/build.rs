fn main() {
    // ADR-005 (user decision 4, 2026-10-24): optionally embed a default
    // assistant API key at BUILD time (DEEPFLUX_AGENT_KEY env). Family
    // installers built with it are zero-config; the public landing
    // installer builds without it. The Credential Manager always wins.
    // The value is written whole to OUT_DIR — never echoed, never in
    // source control.
    let key = std::env::var("DEEPFLUX_AGENT_KEY").unwrap_or_default();
    let dest = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(format!("{dest}/agent_key.txt"), key.trim()).expect("write agent_key.txt");
    println!("cargo:rerun-if-env-changed=DEEPFLUX_AGENT_KEY");

    // ADR-010 (0.11.0): optionally embed the circle key at BUILD time
    // (DEEPFLUX_CIRCLE_KEY env, 64 hex chars). The family installer IS
    // the public download and auto-joins the circle from this key —
    // restored from ADR-006's distribution addendum verbatim. A
    // NON-EMPTY embedded key additionally requires DEEPFLUX_FAMILY_BUILD
    // =1 (the guard that keeps a stray env var from silently circling a
    // dev build). The file is always written (empty when unset) so
    // `include_str!` in src/directory.rs compiles in bare dev builds.
    let circle = std::env::var("DEEPFLUX_CIRCLE_KEY").unwrap_or_default();
    let family = std::env::var("DEEPFLUX_FAMILY_BUILD").unwrap_or_default() == "1";
    if !circle.trim().is_empty() && !family {
        panic!(
            "DEEPFLUX_CIRCLE_KEY is set but DEEPFLUX_FAMILY_BUILD != 1 — refusing to embed a circle key in a non-family build"
        );
    }
    std::fs::write(format!("{dest}/circle_key.txt"), circle.trim()).expect("write circle_key.txt");
    println!("cargo:rerun-if-env-changed=DEEPFLUX_CIRCLE_KEY");
    println!("cargo:rerun-if-env-changed=DEEPFLUX_FAMILY_BUILD");

    tauri_build::build()
}
