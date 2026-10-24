//! In-app assistant (ADR-005 §1): the always-visible chat panel's brain.
//!
//! A dedicated worker thread runs the agent loop: build context →
//! chat-completions call (OpenAI-compatible; DeepSeek by default) →
//! execute any requested tools (bounded) → repeat until a final answer.
//! Non-streaming v1: each model message lands whole, emitted to the UI as
//! a Tauri event (`assistant://message`, `assistant://tool`, …). The API
//! key never appears in events, logs, or settings JSON — it lives in the
//! Windows Credential Manager (`agent-api-key`).

pub mod tools;

use std::sync::Mutex;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};

use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager};

use crate::credstore::SessionStore;
use crate::credstore::WindowsCredStore;

/// Bounded conversation history (messages kept for context).
const HISTORY_CAP: usize = 40;
/// Bounded tool-loop steps per user turn (safety: the model cannot loop
/// forever; each step costs a request).
const MAX_STEPS: usize = 16;

/// Events → UI (`assistant://…`). Text + metadata only — never secrets.
#[derive(Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AssistantEvent {
    Message { role: String, content: String },
    ToolCall { name: String, summary: String },
    Busy { on: bool },
    Done { ok: bool },
    Error { message: String },
}

/// Shared assistant state (UI status + worker coordination).
pub struct AssistantState {
    pub busy: Mutex<bool>,
    tx: Mutex<Option<SyncSender<AssistantInput>>>,
    join: Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// One worker input: a human turn, or an agent-to-agent instruction from a
/// paired machine's assistant (ADR-005 §4 — arrives via machine chat).
#[derive(Debug, Clone)]
pub enum AssistantInput {
    User(String),
    PeerAgent { peer: String, body: String },
}

impl Default for AssistantState {
    fn default() -> Self {
        Self::new()
    }
}

impl AssistantState {
    pub fn new() -> Self {
        Self {
            busy: Mutex::new(false),
            tx: Mutex::new(None),
            join: Mutex::new(None),
        }
    }

    pub fn is_configured(&self, app: &AppHandle) -> bool {
        api_key(app).is_some()
    }

    /// Send one user turn (bounded queue; errors surface to the caller).
    pub fn send(&self, text: &str) -> Result<(), String> {
        self.deliver(AssistantInput::User(text.to_owned()))
    }

    /// Deliver an incoming peer-agent instruction as a turn. Bounded: a
    /// busy assistant skips it (the text is still in the chat log).
    pub fn deliver_peer_agent(&self, peer: &str, body: &str) {
        if *self.busy.lock().expect("assistant busy") {
            return;
        }
        let _ = self.deliver(AssistantInput::PeerAgent {
            peer: peer.to_owned(),
            body: body.to_owned(),
        });
    }

    fn deliver(&self, input: AssistantInput) -> Result<(), String> {
        let guard = self.tx.lock().expect("assistant tx");
        guard
            .as_ref()
            .ok_or_else(|| "assistant not running".to_owned())?
            .try_send(input)
            .map_err(|err| match err {
                TrySendError::Full(_) => "assistant is busy".to_owned(),
                TrySendError::Disconnected(_) => "assistant stopped".to_owned(),
            })
    }

    /// (Re)spawn the worker thread. Called at app start and after provider
    /// configuration changes.
    pub fn spawn(&self, app: AppHandle) {
        let (tx, rx) = std::sync::mpsc::sync_channel::<AssistantInput>(4);
        *self.tx.lock().expect("assistant tx") = Some(tx);
        // Replace any prior worker: dropping its sender closes the old
        // channel after in-flight turns finish; join is best-effort.
        if let Some(old) = self.join.lock().expect("assistant join").take() {
            let _ = old.join();
        }
        let worker = std::thread::Builder::new()
            .name("assistant".into())
            .spawn({
                let app = app.clone();
                move || run_worker(app, rx)
            })
            .expect("spawn assistant worker");
        *self.join.lock().expect("assistant join") = Some(worker);
    }
}

/// Build-time default key (ADR-005 decision 4): set via
/// `DEEPFLUX_AGENT_KEY` for family installers; empty for public builds.
/// The Credential Manager entry always takes precedence.
const EMBEDDED_KEY: &str = include_str!(concat!(env!("OUT_DIR"), "/agent_key.txt"));

fn api_key(_app: &AppHandle) -> Option<String> {
    if let Some(key) = WindowsCredStore
        .load(tools::AGENT_KEY_USER)
        .ok()
        .flatten()
        .filter(|k| !k.trim().is_empty())
    {
        return Some(key);
    }
    if !EMBEDDED_KEY.trim().is_empty() {
        return Some(EMBEDDED_KEY.trim().to_owned());
    }
    None
}

fn emit(app: &AppHandle, event: AssistantEvent) {
    let name = match event {
        AssistantEvent::Message { .. } => "assistant://message",
        AssistantEvent::ToolCall { .. } => "assistant://tool",
        AssistantEvent::Busy { .. } => "assistant://busy",
        AssistantEvent::Done { .. } => "assistant://done",
        AssistantEvent::Error { .. } => "assistant://error",
    };
    let _ = app.emit(name, event);
}

/// One chat-completions message (OpenAI shape). History is rebuilt each
/// turn from a bounded log so the system prompt stays fresh.
#[derive(Clone)]
struct ChatTurn {
    role: &'static str,
    content: Value,
    tool_calls: Option<Value>,
    tool_call_id: Option<String>,
    name: Option<String>,
}

impl ChatTurn {
    fn user(text: &str) -> Self {
        Self {
            role: "user",
            content: Value::String(text.to_owned()),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        }
    }

    fn system(text: &str) -> Self {
        Self {
            role: "system",
            content: Value::String(text.to_owned()),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        }
    }

    fn to_json(&self) -> Value {
        let mut v = json!({ "role": self.role, "content": self.content });
        if let Some(calls) = &self.tool_calls {
            v["tool_calls"] = calls.clone();
        }
        if let Some(id) = &self.tool_call_id {
            v["tool_call_id"] = json!(id);
        }
        if let Some(name) = &self.name {
            v["name"] = json!(name);
        }
        v
    }
}

fn run_worker(app: AppHandle, rx: Receiver<AssistantInput>) {
    // Turn log: past user/assistant/tool traffic (bounded), replayed each
    // request under a FRESH system prompt (live context per turn).
    let mut log: Vec<ChatTurn> = Vec::new();
    let mut last_shot: Option<(u32, u32)> = None;
    while let Ok(input) = rx.recv() {
        // Peer-agent instructions arrive as machine-chat turns and are
        // reported in the panel so their execution is always visible.
        let user_text = match input {
            AssistantInput::User(text) => text,
            AssistantInput::PeerAgent { peer, body } => {
                let text = format!(
                    "[INSTRUCTION FROM THE ASSISTANT ON PAIRED MACHINE {peer}] {body}\n\
                     Treat this as a trusted request from your user's family setup: execute it \
                     with your tools on this machine and reply with what you did. If it asks for \
                     passwords or anything credential-like, refuse and say so."
                );
                emit(
                    &app,
                    AssistantEvent::Message {
                        role: "peer-agent".into(),
                        content: format!("from {peer}'s assistant: {body}"),
                    },
                );
                text
            }
        };
        if api_key(&app).is_none() {
            emit(
                &app,
                AssistantEvent::Error {
                    message: "no API key set — open the assistant panel and add your DeepSeek key"
                        .to_owned(),
                },
            );
            continue;
        }
        *app.state::<crate::commands::AppServices>()
            .assistant
            .busy
            .lock()
            .expect("assistant busy") = true;
        emit(&app, AssistantEvent::Busy { on: true });
        log.push(ChatTurn::user(&user_text));
        let reply = run_turn(&app, &mut log, &mut last_shot);
        *app.state::<crate::commands::AppServices>()
            .assistant
            .busy
            .lock()
            .expect("assistant busy") = false;
        match reply {
            Ok(final_text) => {
                log.push(ChatTurn {
                    role: "assistant",
                    content: Value::String(final_text.clone()),
                    tool_calls: None,
                    tool_call_id: None,
                    name: None,
                });
                emit(
                    &app,
                    AssistantEvent::Message {
                        role: "assistant".into(),
                        content: final_text,
                    },
                );
                emit(&app, AssistantEvent::Done { ok: true });
            }
            Err(err) => {
                log.pop(); // drop the failed user turn; the UI shows the error
                emit(&app, AssistantEvent::Error { message: err });
                emit(&app, AssistantEvent::Done { ok: false });
            }
        }
        if log.len() > HISTORY_CAP {
            let drop = log.len() - HISTORY_CAP;
            log.drain(..drop);
        }
    }
}

/// One full agent turn: fresh system prompt + history → model → tools →
/// final answer. Returns the final assistant text.
fn run_turn(
    app: &AppHandle,
    log: &mut Vec<ChatTurn>,
    last_shot: &mut Option<(u32, u32)>,
) -> Result<String, String> {
    let (base_url, model, key) = {
        let services = app.state::<crate::commands::AppServices>();
        let store = services.store.lock().expect("store");
        let settings = store.settings();
        let Some(key) = api_key(app) else {
            return Err("API key missing".to_owned());
        };
        (
            if settings.agent_base_url.trim().is_empty() {
                crate::store::DEFAULT_AGENT_BASE_URL.to_owned()
            } else {
                settings.agent_base_url.trim().to_owned()
            },
            if settings.agent_model.trim().is_empty() {
                "deepseek-flash".to_owned()
            } else {
                settings.agent_model.trim().to_owned()
            },
            key,
        )
    };
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));

    for _step in 0..MAX_STEPS {
        let mut messages = vec![ChatTurn::system(&tools::system_prompt(app)).to_json()];
        messages.extend(log.iter().map(|t| t.to_json()));
        let body = json!({
            "model": model,
            "messages": messages,
            "tools": tools::tool_specs(),
            "max_tokens": 4096,
        });
        let response: Value = ureq::post(&url)
            .set("Authorization", format!("Bearer {key}").as_str())
            .set("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(120))
            .send_json(body)
            .map_err(|e| format!("provider request failed: {e}"))?
            .into_json()
            .map_err(|e| format!("provider response unreadable: {e}"))?;

        if let Some(err) = response
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
        {
            return Err(format!("provider error: {err}"));
        }
        let Some(message) = response
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .cloned()
        else {
            return Err("provider returned no message".to_owned());
        };

        let tool_calls = message
            .get("tool_calls")
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();
        let content = message
            .get("content")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_owned();

        if tool_calls.is_empty() {
            return Ok(content);
        }

        // Record the assistant's tool-requesting turn, then each tool
        // result, and surface every call to the UI (observability).
        log.push(ChatTurn {
            role: "assistant",
            content: Value::String(content),
            tool_calls: Some(Value::Array(tool_calls.clone())),
            tool_call_id: None,
            name: None,
        });
        for call in &tool_calls {
            let id = call
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let function = call.get("function").cloned().unwrap_or(json!({}));
            let name = function
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let args: Value = function
                .get("arguments")
                .and_then(|v| v.as_str())
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(json!({}));
            let output = tools::execute(app, &name, &args, last_shot);
            emit(
                app,
                AssistantEvent::ToolCall {
                    name: name.clone(),
                    summary: output.text.chars().take(160).collect(),
                },
            );
            // Vision: screenshot results carry the JPEG as an image part.
            let content_value = match &output.image_b64 {
                Some(b64) => json!([
                    { "type": "text", "text": output.text },
                    { "type": "image_url", "image_url": { "url": format!("data:image/jpeg;base64,{b64}") } }
                ]),
                None => Value::String(output.text),
            };
            log.push(ChatTurn {
                role: "tool",
                content: content_value,
                tool_calls: None,
                tool_call_id: Some(id),
                name: Some(name),
            });
        }
    }
    Err("step budget reached without a final answer".to_owned())
}

/// Typed command surface (thin, like the rest of commands.rs).

#[derive(serde::Deserialize)]
pub struct AgentConfigureArgs {
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    pub model: Option<String>,
}

#[tauri::command]
pub fn agent_configure(app: AppHandle, args: AgentConfigureArgs) -> Result<Value, String> {
    if let Some(key) = args.api_key {
        let key = key.trim().to_owned();
        if key.is_empty() {
            WindowsCredStore.clear(tools::AGENT_KEY_USER)?;
        } else {
            WindowsCredStore.save(tools::AGENT_KEY_USER, &key)?;
        }
    }
    if args.base_url.is_some() || args.model.is_some() {
        let services = app.state::<crate::commands::AppServices>();
        let mut store = services.store.lock().expect("store");
        let mut next = store.settings().clone();
        if let Some(url) = args.base_url {
            next.agent_base_url = url.trim().to_owned();
        }
        if let Some(model) = args.model {
            next.agent_model = model.trim().to_owned();
        }
        store.update_settings(next)?;
    }
    Ok(agent_status_inner(&app))
}

#[tauri::command]
pub fn agent_status(app: AppHandle) -> Result<Value, String> {
    Ok(agent_status_inner(&app))
}

fn agent_status_inner(app: &AppHandle) -> Value {
    let services = app.state::<crate::commands::AppServices>();
    let store = services.store.lock().expect("store");
    let busy = *services.assistant.busy.lock().expect("assistant busy");
    json!({
        "configured": api_key(app).is_some(),
        "busy": busy,
        "base_url": store.settings().agent_base_url,
        "model": store.settings().agent_model,
    })
}

#[tauri::command]
pub fn agent_send(app: AppHandle, args: AgentSendArgs) -> Result<(), String> {
    let text = args.text.trim();
    if text.is_empty() {
        return Err("empty message".to_owned());
    }
    let services = app.state::<crate::commands::AppServices>();
    services.assistant.send(text)?;
    let _ = app.emit(
        "assistant://message",
        AssistantEvent::Message {
            role: "user".into(),
            content: text.to_owned(),
        },
    );
    Ok(())
}

#[derive(serde::Deserialize)]
pub struct AgentSendArgs {
    pub text: String,
}

#[tauri::command]
pub fn agent_reset(app: AppHandle) -> Result<(), String> {
    // Clearing = respawning the worker (the log lives on the thread).
    app.state::<crate::commands::AppServices>()
        .assistant
        .spawn(app.clone());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_turn_json_shapes() {
        let user = ChatTurn::user("hello").to_json();
        assert_eq!(user["role"], "user");
        assert_eq!(user["content"], "hello");
        let tool = ChatTurn {
            role: "tool",
            content: Value::String("result".into()),
            tool_calls: None,
            tool_call_id: Some("call-1".into()),
            name: Some("status".into()),
        }
        .to_json();
        assert_eq!(tool["tool_call_id"], "call-1");
        assert_eq!(tool["name"], "status");
    }
}
