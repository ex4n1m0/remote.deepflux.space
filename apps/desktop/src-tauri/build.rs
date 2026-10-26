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

    // ADR-006: optionally embed the family-circle key at BUILD time
    // (DEEPFLUX_CIRCLE_KEY). The embedded key is a whole-circle read
    // credential extractable from the binary — building with it is a
    // deliberate, flagged act: it REFUSES unless DEEPFLUX_FAMILY_BUILD=1
    // is also set, so a public build can never carry one by accident.
    // Family installers auto-join on first run; the public build joins by
    // pasting the invite in Settings. The Credential Manager entry always
    // wins. Never echoed, never in source control, never published.
    let circle = std::env::var("DEEPFLUX_CIRCLE_KEY").unwrap_or_default();
    let family = std::env::var("DEEPFLUX_FAMILY_BUILD").unwrap_or_default();
    if !circle.trim().is_empty() && family.trim() != "1" {
        panic!(
            "DEEPFLUX_CIRCLE_KEY is set but DEEPFLUX_FAMILY_BUILD != 1 — an embedded circle key is a shareable whole-circle credential; only deliberate family builds may carry it"
        );
    }
    std::fs::write(format!("{dest}/circle_key.txt"), circle.trim()).expect("write circle_key.txt");
    println!("cargo:rerun-if-env-changed=DEEPFLUX_CIRCLE_KEY");
    println!("cargo:rerun-if-env-changed=DEEPFLUX_FAMILY_BUILD");
    tauri_build::build()
}
