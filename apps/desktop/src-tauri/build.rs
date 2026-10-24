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
    tauri_build::build()
}
