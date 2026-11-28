//! Command-argument wire shapes — the regression test for the save-key bug
//! found live on 2026-11-25.
//!
//! The frontend (`src/ipc.ts`) passes Tauri command arguments in TWO
//! styles: snake_case object literals (`{ args: { code, agent } }`) and,
//! for the assistant settings, camelCase (`{ apiKey, baseUrl, model }`).
//! Tauri converts only the TOP-LEVEL argument names; the fields of a typed
//! `args:` struct are deserialized by serde under their Rust names, and an
//! unknown key is dropped silently. So `AgentConfigureArgs { api_key,
//! base_url }` never received the key or the Base URL the dialog "Saved",
//! in every build since 2026-10-24 — only the single-word `model` landed.
//!
//! The contract is checked in ONE direction here: this test READS `ipc.ts`,
//! extracts the keys every `invoke("<cmd>", { args: … })` passes, and
//! requires each typed argument struct to serialize to exactly that key
//! set. A new typed command, or a renamed key on either side, fails here.
//! (An earlier draft asserted a hand-written shape instead and "found" a
//! bug in monitor selection that did not exist: read the caller, do not
//! restate it.)

use std::path::{Path, PathBuf};

use remote_desktop_app_lib::agent::{AgentConfigureArgs, AgentSendArgs};
use remote_desktop_app_lib::commands::ChatSendArgs;
use remote_desktop_app_lib::ipc::{ConnectArgs, SelectMonitorArgs, SetQualityArgs};
use serde::Serialize;
use serde_json::{Value, json};

/// Every Tauri command that takes a typed `args:` struct. A new one fails
/// the test until it is listed here — the list cannot drift silently.
const TYPED_ARGUMENT_COMMANDS: [&str; 6] = [
    "agent_configure",
    "agent_send",
    "chat_send",
    "connect",
    "select_monitor",
    "set_quality",
];

fn desktop_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("apps/desktop/src-tauri has a parent")
        .to_path_buf()
}

/// Keys of the object literal that follows `marker` in `text`, up to the
/// first `}`: `{ code, agent }`, `{ monitor_id: monitorId }`, or a
/// parameter type `{ apiKey?: string; baseUrl?: string }`.
fn object_keys_after(marker: &str, text: &str) -> Option<Vec<String>> {
    let at = text.find(marker)?;
    let body = &text[at + marker.len()..];
    let close = body.find('}')?;
    Some(
        body[..close]
            .split([',', ';'])
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(|part| {
                part.split([':', '?'])
                    .next()
                    .unwrap_or(part)
                    .trim()
                    .to_owned()
            })
            .collect(),
    )
}

/// For every `invoke("<cmd>", …)` call in `ipc_ts` that passes a typed
/// argument object: the command and the keys it sends.
fn frontend_args(ipc_ts: &str) -> Vec<(String, Vec<String>)> {
    let mut calls = Vec::new();
    let mut cursor = 0usize;
    while let Some(at) = ipc_ts[cursor..].find("invoke(\"") {
        let start = cursor + at + "invoke(\"".len();
        let Some(len) = ipc_ts[start..].find('"') else {
            break;
        };
        let cmd = ipc_ts[start..start + len].to_owned();
        cursor = start + len;
        let line_end = ipc_ts[cursor..]
            .find('\n')
            .map_or(ipc_ts.len(), |offset| cursor + offset);
        let call = &ipc_ts[cursor..line_end];
        if let Some(keys) = object_keys_after("args: {", call) {
            calls.push((cmd, keys));
        } else if call.contains("{ args }") {
            // `invoke("<cmd>", { args })`, with `args` declared in the
            // enclosing arrow function: `…: (args: { a?: T; b?: U }): …`.
            let Some(declaration) = ipc_ts[..start].rfind("args: {") else {
                continue;
            };
            if let Some(keys) = object_keys_after("args: {", &ipc_ts[declaration..line_end]) {
                calls.push((cmd, keys));
            }
        }
    }
    calls
}

fn to_value<T: Serialize>(args: T) -> Value {
    serde_json::to_value(args).expect("argument struct serializes")
}

/// The keys a typed argument puts on the wire (every field set).
fn wire_keys(cmd: &str) -> Vec<String> {
    let value = match cmd {
        "agent_configure" => to_value(AgentConfigureArgs {
            api_key: Some(String::new()),
            base_url: Some(String::new()),
            model: Some(String::new()),
        }),
        "agent_send" => to_value(AgentSendArgs {
            text: String::new(),
        }),
        "chat_send" => to_value(ChatSendArgs {
            code: String::new(),
            text: String::new(),
            agent: false,
        }),
        "connect" => to_value(ConnectArgs {
            code: String::new(),
            agent: false,
        }),
        "select_monitor" => to_value(SelectMonitorArgs {
            monitor_id: String::new(),
        }),
        "set_quality" => to_value(SetQualityArgs {
            preset: String::new(),
        }),
        other => panic!("new typed command argument `{other}` — add it to this test"),
    };
    let mut keys: Vec<String> = value
        .as_object()
        .expect("an argument serializes to an object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

#[test]
fn every_typed_command_argument_is_exactly_what_the_frontend_sends() {
    let ipc_ts = std::fs::read_to_string(desktop_root().join("src").join("ipc.ts"))
        .expect("apps/desktop/src/ipc.ts sits beside the Rust crate");
    let calls = frontend_args(&ipc_ts);
    let seen: Vec<&str> = calls.iter().map(|(cmd, _)| cmd.as_str()).collect();
    for expected in TYPED_ARGUMENT_COMMANDS {
        assert!(
            seen.contains(&expected),
            "the scan of ipc.ts must find the `{expected}` call; it found {seen:?}"
        );
    }
    for (cmd, keys) in &calls {
        let mut frontend = keys.clone();
        frontend.sort();
        assert_eq!(
            frontend,
            wire_keys(cmd),
            "`{cmd}`: ipc.ts and the Rust argument disagree on the keys they exchange"
        );
    }
    assert_eq!(
        calls.len(),
        TYPED_ARGUMENT_COMMANDS.len(),
        "a typed command argument is missing from TYPED_ARGUMENT_COMMANDS: {seen:?}"
    );
}

#[test]
fn the_assistant_settings_dialog_shape_deserializes() {
    // Exactly the object the dialog sends (ConfigDialog → ipc.agentConfigure).
    let configure: AgentConfigureArgs = serde_json::from_value(json!({
        "apiKey": "sk-test-key",
        "baseUrl": "https://api.example.com/v1",
        "model": "some-model"
    }))
    .expect("camelCase agent settings must deserialize");
    assert_eq!(configure.api_key.as_deref(), Some("sk-test-key"));
    assert_eq!(
        configure.base_url.as_deref(),
        Some("https://api.example.com/v1")
    );
    assert_eq!(configure.model.as_deref(), Some("some-model"));

    // Absent keys still mean "leave it alone".
    let partial: AgentConfigureArgs =
        serde_json::from_value(json!({ "model": "m" })).expect("a lone model must deserialize");
    assert_eq!(partial.api_key, None);
    assert_eq!(partial.base_url, None);
    assert_eq!(partial.model.as_deref(), Some("m"));
}

#[test]
fn the_scan_reads_both_call_styles() {
    let ipc_ts = r#"
  connect: (code: string, agent = false): Promise<void> =>
    invoke("connect", { args: { code, agent } }),
  selectMonitor: (monitorId: string): Promise<void> =>
    invoke("select_monitor", { args: { monitor_id: monitorId } }),
  agentConfigure: (args: { apiKey?: string; baseUrl?: string; model?: string }): Promise<void> =>
    invoke("agent_configure", { args }),
  engineStart: (): Promise<void> => invoke("engine_start"),
  pairingRemove: (code: string): Promise<void> => invoke("pairing_remove", { code }),
"#;
    assert_eq!(
        frontend_args(ipc_ts),
        vec![
            (
                "connect".to_owned(),
                vec!["code".to_owned(), "agent".to_owned()]
            ),
            ("select_monitor".to_owned(), vec!["monitor_id".to_owned()]),
            (
                "agent_configure".to_owned(),
                vec![
                    "apiKey".to_owned(),
                    "baseUrl".to_owned(),
                    "model".to_owned()
                ]
            ),
        ]
    );
}
