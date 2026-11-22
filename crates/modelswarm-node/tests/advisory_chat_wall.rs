//! The CHAT-WALL SUITE (ADR-037 §4.4 item 10 — W1–W4), layers 1–2 plus
//! the runtime-less behavioral leg. This suite must be GREEN before any
//! assistant-surface code exists (ADR-037 §7 step 2). The mock-runtime
//! success-path behavioral test lives in the advisory module's unit
//! tests (`crates/modelswarm-node/src/advisory/mod.rs`,
//! `chat_wall_success_path_records_zero_assistant_calls` — the mock
//! runtime compiles under `cfg(test)` there); the desktop
//! `try_swarm_chat` failure-path leg lives in the desktop tauri-shell
//! suite.
//!
//! - **Layer 1 (dependency graph)**: `cargo metadata --no-deps` — the
//!   frozen decision-crate set depends on NO advisory host, and
//!   `modelswarm-node` (the crate hosting `modelswarm-node::advisory`)
//!   is depended on ONLY by `modelswarm-desktop` (+bench, the sanctioned
//!   shadow-ledger exemption).
//! - **Layer 2 (source scope, directional)**: advisory client type
//!   names appear ONLY in the advisory module and tests — never in the
//!   gateway crate, the node serving/verifydrafts modules, or the
//!   `send_chat`/`try_swarm_chat` scopes; the advisory (request
//!   builder) modules reference no chat/serving/carrier types; the
//!   transport call executes from exactly ONE site (the assistant
//!   turn runner); the node composition wires NO plane at all (the
//!   2026-10-15 collapse deleted the digest wiring).
//! - **Layer 3 (behavioral, this file)**: with the assistant plane
//!   ARMED in-process over a counting transport double (the
//!   hosted-model stand-in), chat turns through the loopback gateway
//!   record ZERO assistant calls — here the runtime-less failure paths
//!   (no_peer); the success path and the desktop swarm paths ride the
//!   suites named above.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use modelswarm_node::advisory::{
    AdvisoryTransport, AssistantPlane, CountingTransport, TurnOutcome,
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn read_file(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Production-source view of one file: trailing `#[cfg(test)] mod …`
/// blocks (the inline unit-test surface, on the ADR's layer-2 allowlist
/// as `*/tests/`) are stripped — each one only when its module is the
/// file's LAST item (brace-matched; only whitespace/comments may follow
/// the close). A NON-TRAILING `#[cfg(test)]` marker is a hard error:
/// production code after a test module must never silently leave the
/// layer-2 scan (protocol review 2026-10-14, Finding R-2 — the
/// under-inclusive direction is the UNSAFE one). Panics here fail every
/// layer-2 test loudly.
fn production_source(path: &Path) -> String {
    let text = read_file(path);
    strip_trailing_test_modules(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Pure core of [`production_source`] (unit-fixture-tested below).
/// Repeatedly removes the file's last `#[cfg(test)] mod` while it runs to
/// EOF; errors on any marker whose module has production items after it.
/// The marker match is CRLF-tolerant (`\r?\n`) so a CRLF checkout cannot
/// silently disable the strip (that failure direction is over-inclusive,
/// i.e. safe — but pinning it is free).
fn strip_trailing_test_modules(text: &str) -> Result<String, String> {
    let mut text = text.to_string();
    loop {
        let Some(marker_pos) = rfind_cfg_test_mod_marker(&text) else {
            return Ok(text);
        };
        let open = match find_module_open_brace(&text, marker_pos) {
            Some(open) => open,
            None => {
                return Err(format!(
                    "at byte {marker_pos}: #[cfg(test)] marker is not followed by a `mod … {{` item"
                ))
            }
        };
        let close = brace_match(&text, open).map_err(|e| {
            format!("at byte {marker_pos}: test module braces do not balance ({e})")
        })?;
        let after = &text[close..];
        if !is_only_trivia(after) {
            return Err(format!(
                "at byte {marker_pos}: NON-TRAILING #[cfg(test)] module — production items follow its close (byte {close}); move the test module to the end of the file (or a tests/ tree) so the layer-2 scan cannot skip production code"
            ));
        }
        text.truncate(marker_pos);
    }
}

/// The byte position of the LAST `#[cfg(test)]` in `text` that is
/// immediately followed by a newline (`\n` or `\r\n`), further
/// attributes, and a `mod` item.
fn rfind_cfg_test_mod_marker(text: &str) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut from = 0usize;
    while let Some(rel) = text[from..].find("#[cfg(test)]") {
        let pos = from + rel;
        from = pos + 1;
        if is_cfg_test_mod_at(text, pos) {
            best = Some(pos);
        }
    }
    best
}

/// Whether the exact-token `#[cfg(test)]` at `pos` introduces a `mod`
/// item (newline, then any further `#[…]` attributes/whitespace, then
/// `mod` + non-identifier continuation).
fn is_cfg_test_mod_at(text: &str, pos: usize) -> bool {
    let mut i = pos + "#[cfg(test)]".len();
    let bytes = text.as_bytes();
    if bytes.get(i) == Some(&b'\r') && bytes.get(i + 1) == Some(&b'\n') {
        i += 2;
    } else if bytes.get(i) == Some(&b'\n') {
        i += 1;
    } else {
        return false;
    }
    let mod_at = skip_attributes_and_trivia(text, i);
    text[mod_at..].starts_with("mod") && !rest_is_ident_char(&text[mod_at + 3..])
}

fn rest_is_ident_char(rest: &str) -> bool {
    rest.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Advances past whitespace, comments, and stacked `#[…]` attributes.
fn skip_attributes_and_trivia(text: &str, mut i: usize) -> usize {
    loop {
        i = skip_trivia(text, i);
        if text[i..].starts_with("#[") {
            // Skip one balanced-bracket attribute group.
            let mut depth = 0usize;
            let mut j = i;
            let bytes = text.as_bytes();
            while j < bytes.len() {
                match bytes[j] {
                    b'[' => depth += 1,
                    b']' => {
                        depth -= 1;
                        if depth == 0 {
                            i = j + 1;
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            if depth != 0 {
                return i; // malformed tail — caller reports
            }
        } else {
            return i;
        }
    }
}

/// The byte index of the module's opening `{` (after `mod NAME` and any
/// trivia/comments), or None if the item shape is not a braced module.
fn find_module_open_brace(text: &str, marker_pos: usize) -> Option<usize> {
    let after_marker = marker_pos + "#[cfg(test)]".len();
    // Newline first (\r\n or \n) — the marker check guaranteed one.
    let start = skip_attributes_and_trivia(text, after_marker);
    let rest = &text[start..];
    if !rest.starts_with("mod") || rest_is_ident_char(&rest[3..]) {
        return None;
    }
    let mut i = start + 3;
    // Identifier, then trivia, then `{`.
    i = skip_trivia(text, i);
    let bytes = text.as_bytes();
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    i = skip_trivia(text, i);
    (bytes.get(i) == Some(&b'{')).then_some(i)
}

/// Index just past the `}` matching the `{` at `open`, Rust-lexically
/// (string literals, raw strings, char literals, and nested comments
/// cannot open or close the module).
fn brace_match(text: &str, open: usize) -> Result<usize, String> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                i = skip_line_comment(text, i);
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i = skip_block_comment(text, i)
                    .ok_or_else(|| "unterminated block comment".to_string())?;
            }
            b'"' => {
                i = skip_string(text, i)
                    .ok_or_else(|| "unterminated string literal".to_string())?;
            }
            b'r' if is_raw_string_start(text, i) => {
                i = skip_raw_string(text, i)
                    .ok_or_else(|| "unterminated raw string".to_string())?;
            }
            b'\'' => {
                i = skip_char_or_lifetime(text, i);
            }
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Ok(i);
                }
            }
            _ => i += 1,
        }
    }
    Err("module braces do not balance before EOF".to_string())
}

/// Whitespace and comments only (line comments; nested block comments).
fn is_only_trivia(mut text: &str) -> bool {
    loop {
        text = text.trim_start();
        if text.is_empty() {
            return true;
        }
        if let Some(rest) = text.strip_prefix("//") {
            text = match rest.find('\n') {
                Some(nl) => &rest[nl..],
                None => "",
            };
            continue;
        }
        if text.starts_with("/*") {
            match skip_block_comment(text, 0) {
                Some(next) => text = &text[next..],
                None => return true, // unterminated trailing comment
            }
            continue;
        }
        return false;
    }
}

fn skip_trivia(text: &str, mut i: usize) -> usize {
    loop {
        let bytes = text.as_bytes();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) == Some(&b'/') && bytes.get(i + 1) == Some(&b'/') {
            i = skip_line_comment(text, i);
            continue;
        }
        if bytes.get(i) == Some(&b'/') && bytes.get(i + 1) == Some(&b'*') {
            match skip_block_comment(text, i) {
                Some(next) => i = next,
                None => return text.len(),
            }
            continue;
        }
        return i;
    }
}

/// Index just past the line comment starting at `i` (`// …` to EOL).
fn skip_line_comment(text: &str, i: usize) -> usize {
    match text[i..].find('\n') {
        Some(nl) => i + nl + 1,
        None => text.len(),
    }
}

/// Index just past a (nested) block comment starting at `i`; None if
/// unterminated.
fn skip_block_comment(text: &str, i: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut j = i;
    while j < bytes.len() {
        if bytes[j] == b'/' && bytes.get(j + 1) == Some(&b'*') {
            depth += 1;
            j += 2;
        } else if bytes[j] == b'*' && bytes.get(j + 1) == Some(&b'/') {
            depth -= 1;
            j += 2;
            if depth == 0 {
                return Some(j);
            }
        } else {
            j += 1;
        }
    }
    None
}

/// Index just past a `"…"` string literal (backslash escapes honored).
fn skip_string(text: &str, i: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut j = i + 1;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => j += 2,
            b'"' => return Some(j + 1),
            _ => j += 1,
        }
    }
    None
}

/// Whether `r` at `i` begins a raw string (`r"…"`, `r#"…"#`, …).
fn is_raw_string_start(text: &str, i: usize) -> bool {
    let bytes = text.as_bytes();
    if bytes.get(i) != Some(&b'r') {
        return false;
    }
    match bytes.get(i + 1) {
        Some(b'"') => true,
        Some(b'#') => {
            let mut j = i + 1;
            while bytes.get(j) == Some(&b'#') {
                j += 1;
            }
            bytes.get(j) == Some(&b'"')
        }
        _ => false,
    }
}

/// Index just past a raw string starting at `i`.
fn skip_raw_string(text: &str, i: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut j = i + 1;
    while bytes.get(j) == Some(&b'#') {
        j += 1;
    }
    let hashes = j - i - 1;
    if bytes.get(j) != Some(&b'"') {
        return None;
    }
    j += 1;
    while j < bytes.len() {
        if bytes[j] == b'"' {
            let mut k = j + 1;
            let mut seen = 0usize;
            while seen < hashes && bytes.get(k) == Some(&b'#') {
                k += 1;
                seen += 1;
            }
            if seen == hashes {
                return Some(k);
            }
        }
        j += 1;
    }
    None
}

/// Index just past a char literal (`'a'`, `'\n'`, `'\u{1F600}'`) or a
/// lifetime tick (`'a`, `'_` — identifiers cannot carry braces, so
/// skipping the tick alone is sound).
fn skip_char_or_lifetime(text: &str, i: usize) -> usize {
    let bytes = text.as_bytes();
    let n = bytes.len();
    // `'\u{…}'`: consume the unicode escape's braces, then the quote.
    if bytes.get(i + 1) == Some(&b'\\')
        && bytes.get(i + 2) == Some(&b'u')
        && bytes.get(i + 3) == Some(&b'{')
    {
        if let Some(close) = text[i + 4..].find('}') {
            let after = i + 4 + close + 1;
            return if bytes.get(after) == Some(&b'\'') {
                after + 1
            } else {
                after
            };
        }
        return i + 1;
    }
    // `'\''` / `'\n'`: escaped single char, then the quote.
    if bytes.get(i + 1) == Some(&b'\\') {
        return if bytes.get(i + 3) == Some(&b'\'') {
            i + 4
        } else if i + 2 < n {
            i + 2 // lone escape inside a lifetime-ish token — skip conservatively
        } else {
            n
        };
    }
    // `'x'`: one non-quote char then the quote; anything else is a
    // lifetime (`'a`) — skip the tick only.
    match bytes.get(i + 1) {
        Some(c) if *c != b'\'' && bytes.get(i + 2) == Some(&b'\'') => i + 3,
        _ => i + 1,
    }
}

#[test]
fn layer2_strip_fails_loudly_on_midfile_test_modules() {
    // R-2's unit fixture: the helper must ERROR on a synthetic mid-file
    // marker (production after a test module can never silently leave
    // the layer-2 scan) and strip only trailing modules.
    let trailing =
        "fn prod() {}\n#[cfg(test)]\nmod tests {\n    fn f() { let s = format!(\"{}\"); }\n}\n";
    assert_eq!(
        strip_trailing_test_modules(trailing).unwrap(),
        "fn prod() {}\n"
    );
    let midfile = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nfn b() {}\n";
    assert!(strip_trailing_test_modules(midfile).is_err());
    // Two stacked trailing modules both strip (egress.rs's shape).
    let stacked = "fn a() {}\n#[cfg(test)]\nmod one {}\n#[cfg(test)]\nmod two {}\n";
    assert_eq!(strip_trailing_test_modules(stacked).unwrap(), "fn a() {}\n");
    // CRLF checkouts strip too (the marker match is `\\r?\\n`-tolerant).
    let crlf = "fn a() {}\r\n#[cfg(test)]\r\nmod tests {}\r\n";
    assert_eq!(strip_trailing_test_modules(crlf).unwrap(), "fn a() {}\r\n");
    // Only whitespace and comments may follow the close.
    let commented = "fn a() {}\n#[cfg(test)]\nmod t {}\n// trailing comment\n/* block */\n";
    assert_eq!(
        strip_trailing_test_modules(commented).unwrap(),
        "fn a() {}\n"
    );
    // Raw strings, nested block comments, char/lifetime ticks, and
    // format-string braces inside the module body must not break the
    // brace match (the tree's real test modules contain all of these).
    let gnarly = "fn a() {}\n#[cfg(test)]\nmod tests {\n    let j = r#\"{ \\\"raw\\\": 1 }\"#;\n    /* { nested } */ let c = '}';\n    let l: &'static str = \"}\";\n    let f = format!(\"{}{}\", '{', '}');\n}\n";
    assert_eq!(strip_trailing_test_modules(gnarly).unwrap(), "fn a() {}\n");
    // A cfg(test) FUNCTION (not a module) is not a strip marker — it
    // stays in the production view like today.
    let cfg_fn = "#[cfg(test)]\nfn helper() {}\nfn prod() {}\n";
    assert_eq!(strip_trailing_test_modules(cfg_fn).unwrap(), cfg_fn);
    // An unterminated module brace is a loud error, never a silent skip.
    let unbalanced = "fn a() {}\n#[cfg(test)]\nmod tests {\n";
    assert!(strip_trailing_test_modules(unbalanced).is_err());
}

fn rust_sources_under(dir: &Path, skip: Option<&Path>) -> BTreeMap<PathBuf, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        // Integration/perf test trees (`*/tests/`) are on the ADR's
        // layer-2 allowlist ("…and */tests/") — this scanner walks
        // PRODUCTION sources only.
        if current.file_name().is_some_and(|n| n == "tests") {
            continue;
        }
        let entries = std::fs::read_dir(&current)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", current.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(skip) = skip {
                if path == skip {
                    continue;
                }
            }
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.insert(path.clone(), production_source(&path));
            }
        }
    }
    out
}

/// Advisory client type names + the module path prefix (the layer-2
/// vocabulary of record; extend ONLY via an ADR-037 amendment). The
/// 2026-10-15 collapse renamed the production transport to the
/// loopback-only `LocalGatewayTransport` and deleted `ReqwestTransport`
/// with the provider surface.
const ADVISORY_NAMES: &[&str] = &[
    "modelswarm_node::advisory",
    "advisory::wire",
    "advisory::AdvisoryHandle",
    "AdvisoryState",
    "AdvisoryConfig",
    "AdvisoryTransport",
    "AdvisoryHandle",
    "CountingTransport",
    "LocalGatewayTransport",
    "HostedBacking",
    "AssistantArm",
    "RecordedSuggestion",
    "ProviderRequest",
    "advisory-egress",
    "advisory-clamp-table",
    // The assistant surface's names (ADR-037 §7 step 3): same rules —
    // they live only in the advisory module, the sanctioned desktop
    // assistant module, and tests.
    "AssistantPlane",
    "AssistantState",
    "AssistantRuntimeCaps",
    "ASSISTANT_SYSTEM_PROMPT",
    "advisory-assistant",
];

fn find_hits(sources: &BTreeMap<PathBuf, String>, needle: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for (path, text) in sources {
        if text.contains(needle) {
            hits.push(path.display().to_string());
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// Layer 1 — the dependency graph (ADR-033 §9.2(6) + ADR-037 item 10)
// ---------------------------------------------------------------------------

#[test]
fn layer1_decision_crates_do_not_depend_on_the_advisory_host() {
    // `cargo metadata --no-deps` compiles nothing and lists every
    // workspace member's declared dependencies.
    let output = std::process::Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(workspace_root())
        .output()
        .expect("cargo metadata runs");
    assert!(output.status.success(), "cargo metadata failed");
    let meta: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("metadata json parses");

    let decision_set = [
        "modelswarm-scheduler",
        "modelswarm-session",
        "modelswarm-eligibility",
        "modelswarm-gateway",
        "modelswarm-runtime",
        "modelswarm-transport",
        "modelswarm-tracker-api",
        "modelswarm-store",
        "modelswarm-types",
    ];
    // The five §9.2(6)-named decision crates additionally carry NO
    // dev-dependency on the advisory host (fixture reuse is tolerated
    // elsewhere, recommended against there).
    let no_dev = [
        "modelswarm-gateway",
        "modelswarm-session",
        "modelswarm-types",
        "modelswarm-eligibility",
        "modelswarm-scheduler",
    ];
    let mut dependents_of_node: Vec<String> = Vec::new();
    for package in meta["packages"].as_array().expect("packages") {
        let name = package["name"].as_str().unwrap_or_default();
        if !decision_set.contains(&name) {
            continue;
        }
        for dep in package["dependencies"].as_array().expect("dependencies") {
            let dep_name = dep["name"].as_str().unwrap_or_default();
            let kind = dep["kind"].as_str().unwrap_or("normal");
            if dep_name == "modelswarm-node" {
                panic!(
                    "{name} declares a {kind} dependency on modelswarm-node (the advisory-plane host) — the wall is a dependency-graph property (ADR-033 §9.2(6))"
                );
            }
            if dep_name == "modelswarm-advisory" {
                panic!("{name} depends on a dedicated advisory crate — none may exist without Integrator sign-off (ADR-033 §9.4)");
            }
            // The five §9.2(6)-named decision crates carry no DEV
            // dependency on the advisory host either (fixture reuse is
            // tolerated elsewhere, recommended against here).
            if no_dev.contains(&name) && dep_name == "modelswarm-node" {
                panic!("{name} declares a dev-dependency on modelswarm-node");
            }
        }
    }
    // ADR-037 item-10 extension: the advisory host is depended on ONLY
    // by modelswarm-node/modelswarm-desktop — with the module placement,
    // `modelswarm-node` (the host) may be a normal dependency of
    // `modelswarm-desktop` and NOTHING else among workspace members.
    for package in meta["packages"].as_array().expect("packages") {
        let name = package["name"].as_str().unwrap_or_default();
        for dep in package["dependencies"].as_array().expect("dependencies") {
            if dep["name"].as_str() == Some("modelswarm-node")
                && dep["kind"].as_str().unwrap_or("normal") != "dev"
            {
                dependents_of_node.push(name.to_string());
            }
        }
    }
    let mut expected = vec![
        "modelswarm-bench".to_string(),
        "modelswarm-desktop".to_string(),
    ];
    expected.sort();
    dependents_of_node.sort();
    assert_eq!(
        dependents_of_node, expected,
        "modelswarm-node (the advisory host) may be a normal dependency of the desktop and — per ADR-033 §9.2(6)'s explicit exemption — modelswarm-bench (the sanctioned shadow-ledger consumer; it uses node's measure/remote/serving, and the layer-2 source scan below proves it touches no advisory name) and NOTHING else"
    );
}

// ---------------------------------------------------------------------------
// Layer 2 — source scope (directional)
// ---------------------------------------------------------------------------

#[test]
fn layer2_advisory_names_live_only_in_the_advisory_module_and_tests() {
    let root = workspace_root();
    let advisory_dir = root.join("crates/modelswarm-node/src/advisory");
    // The module's sanctioned homes: the advisory module itself, the
    // node's lib.rs (the daemon COMPOSITION file whose Node::start
    // wires the plane — §9.4: "the advisory client lands … in
    // crates/modelswarm-node::advisory", hosted by this crate), and —
    // since the ADR-037 §7 step-3 leg — the desktop's assistant module
    // (`crates/modelswarm-desktop/src/app/assistant.rs`), the §4.5
    // sanctioned home of the panel/IPC/renderer/static-help/disclosure
    // surface. app.rs itself stays UNEXEMPTED: the chat scopes live
    // there and must not know the plane exists (the test below).
    let composition_host = root.join("crates/modelswarm-node/src/lib.rs");
    let desktop_assistant = root.join("crates/modelswarm-desktop/src/app/assistant.rs");
    let crates = root.join("crates");
    let mut sources = rust_sources_under(&crates, None);
    sources.retain(|path, _| {
        !path.starts_with(&advisory_dir) && *path != composition_host && *path != desktop_assistant
    });
    for name in ADVISORY_NAMES {
        let hits = find_hits(&sources, name);
        assert!(
            hits.is_empty(),
            "advisory name {name:?} outside the advisory module (the wall is source-scoped): {hits:?}"
        );
    }
    // The wall's named hot zones, checked EXPLICITLY (belt and braces —
    // including lib.rs's serving-path composition neighbors):
    for zone in [
        root.join("crates/modelswarm-gateway/src"),
        root.join("crates/modelswarm-node/src/serving.rs"),
        root.join("crates/modelswarm-node/src/verifydrafts"),
    ] {
        let zone_sources = if zone.is_file() {
            BTreeMap::from([(zone.clone(), production_source(&zone))])
        } else {
            rust_sources_under(&zone, None)
        };
        for name in ADVISORY_NAMES {
            let hits = find_hits(&zone_sources, name);
            assert!(
                hits.is_empty(),
                "advisory name {name:?} inside wall zone {}: {hits:?}",
                zone.display()
            );
        }
    }
}

/// Extracts one function's source from `app.rs` (from `async fn NAME(`
/// to the next top-level `\nasync fn `/`\nfn ` — a drift detector in
/// itself: if the file's shape changes, extraction fails loudly).
fn function_scope(app_rs: &str, name: &str) -> String {
    let start = app_rs
        .find(&format!("async fn {name}("))
        .unwrap_or_else(|| panic!("{name} not found in app.rs — wall scope extraction drifted"));
    let rest = &app_rs[start..];
    let end = ["\nasync fn ", "\nfn ", "\npub async fn ", "\npub fn "]
        .iter()
        .filter_map(|marker| rest[1..].find(marker).map(|i| i + 1))
        .min()
        .unwrap_or(rest.len());
    let body = &rest[..end];
    assert!(
        body.len() > 200,
        "{name} extraction too small ({}) — drifted",
        body.len()
    );
    body.to_string()
}

#[test]
fn layer2_chat_scopes_reference_no_advisory_surface() {
    let root = workspace_root();
    let app_rs = read_file(&root.join("crates/modelswarm-desktop/src/app.rs"));
    for scope_name in ["send_chat", "try_swarm_chat"] {
        let scope = function_scope(&app_rs, scope_name);
        for name in ADVISORY_NAMES {
            assert!(
                !scope.contains(name),
                "chat scope {scope_name} references advisory name {name:?} — W1: NO ROUTE, EVER"
            );
        }
        // The full chat-wall vocabulary (W1/W3): no advisory reach, no
        // provider endpoint, no key material near the chat path.
        for forbidden in ["advisory", "MSP_ADVISORY", "DeepSeek"] {
            assert!(
                !scope.to_lowercase().contains(&forbidden.to_lowercase()),
                "chat scope {scope_name} mentions {forbidden:?} — the chat path must not know the advisory plane exists"
            );
        }
    }
}

#[test]
fn layer2_request_builder_modules_reference_no_chat_or_carrier_types() {
    // W3 (data wall, directional): the advisory module — whose egress
    // modules ARE the digest request builder at this leg — cannot name
    // chat or carrier types. There is no `chat_log`/`ChatTurn`/delta/
    // serving-frame/carrier type in ANY advisory module file.
    let root = workspace_root();
    let advisory_dir = root.join("crates/modelswarm-node/src/advisory");
    let sources = rust_sources_under(&advisory_dir, None);
    assert!(!sources.is_empty());
    let forbidden = [
        "chat_log",
        "ChatTurn",
        "chat-delta",
        "prompt_tokens",
        "pin_commitment",
        "InferenceRequest",
        "WireMessage",
        "GatewayState",
        "render_chatml",
    ];
    for (path, text) in &sources {
        for needle in &forbidden {
            assert!(
                !text.contains(needle),
                "advisory module {} references {needle:?} — the data wall (W3) is structural",
                path.display()
            );
        }
    }
}

#[test]
fn layer2_the_transport_call_executes_from_exactly_one_site() {
    // The enumerated-call-sites pin (W2), collapsed by the 2026-10-15
    // owner directive: the plane has exactly ONE entry class — the
    // user-triggered assistant turn (assistant.rs). The timer-driven
    // digest cycle died with the provider surface. Asserted by source
    // scan: `transport.send(&request` executes solely in assistant.rs;
    // `advisory::wire(` appears NOWHERE (the node composition hosts no
    // plane at all — a resurrected wiring needs an ADR); the
    // loopback-pinned production transport is constructed only inside
    // the advisory module (the desktop goes through
    // `AssistantPlane::spawn`).
    let root = workspace_root();
    let node_src = root.join("crates/modelswarm-node/src");
    let desktop_src = root.join("crates/modelswarm-desktop/src");
    let mut production = rust_sources_under(&node_src, None);
    for (path, text) in rust_sources_under(&desktop_src, None) {
        production.insert(path, text);
    }
    let send_hits = find_hits(&production, ".send(&request");
    let expected_assistant = node_src.join("advisory").join("assistant.rs");
    assert_eq!(
        send_hits.iter().map(Path::new).collect::<Vec<_>>(),
        vec![expected_assistant.as_path()],
        "the ONLY transport execution site is the assistant turn runner (W2's one entry class)"
    );
    let wire_hits = find_hits(&production, "advisory::wire(");
    assert!(
        wire_hits.is_empty(),
        "advisory::wire must not exist — the node composition wires no plane (2026-10-15): {wire_hits:?}"
    );
    let advisory_dir = node_src.join("advisory");
    let backing_hits = find_hits(&production, "LocalGatewayTransport::new(");
    assert!(
        !backing_hits.is_empty()
            && backing_hits
                .iter()
                .all(|hit| Path::new(hit).starts_with(&advisory_dir)),
        "the loopback-only production transport is constructed only inside the advisory module: {backing_hits:?}"
    );
}

// ---------------------------------------------------------------------------
// Layer 3 (behavioral, runtime-less legs) — an ARMED assistant plane
// (the hosted-model posture over a counting double) alive in the
// process; chat turns through the loopback gateway record ZERO calls.
// ---------------------------------------------------------------------------

/// Arms the assistant plane in-process over a counting double (the
/// hosted-model stand-in — never a real engine) for `data_dir`, and
/// boots the runtime-less node whose gateway the chat turns ride.
async fn armed_plane_with_node(
    data_dir: &Path,
) -> (
    AssistantPlane,
    modelswarm_node::NodeHandle,
    Arc<CountingTransport>,
    tokio::sync::watch::Sender<bool>,
) {
    std::fs::write(
        data_dir.join("advisory.json"),
        r#"{"assistant.enabled":true}"#,
    )
    .unwrap();
    let double = Arc::new(CountingTransport::assistant_echo("unused".into()));
    let (plane, gap) = AssistantPlane::spawn(
        data_dir,
        None,
        Some(double.clone() as Arc<dyn AdvisoryTransport>),
    );
    assert_eq!(
        gap.as_str(),
        "not_hosting",
        "armed spawn reports no degrade"
    );
    let plane = plane.expect("the assistant plane arms over the double");
    let (tx, rx) = tokio::sync::watch::channel(false);
    let config = modelswarm_node::NodeConfig {
        gateway_port: 0,
        data_dir: data_dir.to_path_buf(),
        profile_id: Some("msp1:chatwall".to_string()),
        ..modelswarm_node::NodeConfig::default()
    };
    let handle = modelswarm_node::Node::start(config, rx)
        .await
        .expect("node starts");
    (plane, handle, double, tx)
}

#[tokio::test]
async fn chat_wall_runtimeless_failure_paths_record_zero_assistant_calls() {
    let dir = tempfile::tempdir().unwrap();
    let (plane, handle, double, tx) = armed_plane_with_node(dir.path()).await;
    let addr = handle.local_addr;

    // Failure path 1: no runtime (no engine, no sidecar) — the gateway
    // answers no_peer/503; the honest failure of a chat turn.
    let reply = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "msp1:chatwall",
            "messages": [{"role": "user", "content": "wall test"}],
            "max_tokens": 8,
        }))
        .send()
        .await
        .expect("gateway responds");
    assert_eq!(
        reply.status().as_u16(),
        503,
        "runtime-less node fails honestly"
    );

    // Failure path 2: unknown profile — 404/400, still no assistant call.
    let reply = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "msp1:not-hosted",
            "messages": [{"role": "user", "content": "wall test"}],
            "max_tokens": 8,
        }))
        .send()
        .await
        .expect("gateway responds");
    assert!(!reply.status().is_success());

    // The wall: ZERO assistant calls from any chat turn.
    assert_eq!(
        double.count(),
        0,
        "a chat turn must never reach the assistant plane (W1)"
    );
    assert!(double.bodies().is_empty());

    // Sensitivity control (the zero is not vacuous): driving the ARMED
    // plane with an assistant turn DOES call the double.
    let (telemetry, _sink) = modelswarm_telemetry::Telemetry::memory();
    let outcome = plane.run_turn(&telemetry, "which model?", vec![]).await;
    assert!(matches!(outcome, TurnOutcome::Reply { .. }));
    assert_eq!(double.count(), 1, "the counter is alive");

    tx.send(true).unwrap();
    handle.stopped().await;
}
