//! AI-agent MCP bridge (ADR-004, RD-018): the product front door for
//! local agents.
//!
//! When the app runs with `--mcp`, a stdio MCP server (official `rmcp`
//! SDK) serves the engine to the user's local agent — ZCode, Claude Code,
//! Cursor — as tools: the agent sees screenshots (ADR-004's scoped
//! invariant-1 exception) and drives the remote machine through the same
//! `InputEvent` wire path as the human viewer.
//!
//! Safety posture (ADR-004 §4/§5): localhost process only (stdio), text
//! payloads never logged (`AgentInput`'s redacted Debug), no remote shell
//! in v1, bounded batches (`MAX_AGENT_BATCH`), and the host consent gate
//! is unchanged — the bridge cannot accept on the host's behalf.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::{AppHandle, Manager};

use crate::engine::{self, AgentInput, EngineHandle};
use crate::ipc::EngineStatusDto;

/// One screenshot's coordinate space: agents address pixels in the last
/// shot; clicks are normalized over the full frame.
#[derive(Debug, Clone, Copy)]
struct ShotSpace {
    shot_w: u32,
    shot_h: u32,
    frame_w: u32,
    frame_h: u32,
}

/// The most recent screenshot the bridge served (coordinate space +
/// JPEG bytes).
#[derive(Debug, Clone)]
struct LastShot {
    space: ShotSpace,
    jpeg: Vec<u8>,
}

/// Map screenshot-pixel coordinates to wire-normalized 0..=65535 over the
/// frame (aspect-identical spaces, so one scale factor suffices).
fn to_normalized(px: f64, dim: u32) -> u16 {
    ((px / f64::from(dim.max(1))) * 65_535.0)
        .round()
        .clamp(0.0, 65_535.0) as u16
}

/// Common key names → Set-1 scan codes (`extended` for the E0-prefixed
/// keys, matching what the viewer capture produces).
fn key_scan_code(name: &str) -> Option<(u16, bool)> {
    let key = name.trim().to_ascii_lowercase();
    Some(match key.as_str() {
        "escape" | "esc" => (0x01, false),
        "tab" => (0x0F, false),
        "backspace" => (0x0E, false),
        "enter" | "return" => (0x1C, false),
        "space" => (0x39, false),
        "delete" | "del" => (0x53, true),
        "insert" | "ins" => (0x52, true),
        "home" => (0x47, true),
        "end" => (0x4F, true),
        "pageup" | "page_up" => (0x49, true),
        "pagedown" | "page_down" => (0x51, true),
        "up" | "arrow_up" => (0x48, true),
        "down" | "arrow_down" => (0x50, true),
        "left" | "arrow_left" => (0x4B, true),
        "right" | "arrow_right" => (0x4D, true),
        "alt" | "left_alt" => (0x38, false),
        "ctrl" | "control" | "left_ctrl" => (0x1D, false),
        "shift" | "left_shift" => (0x2A, false),
        "win" | "windows" => (0x5B, true),
        "f1" => (0x3B, false),
        "f2" => (0x3C, false),
        "f3" => (0x3D, false),
        "f4" => (0x3E, false),
        "f5" => (0x3F, false),
        "f6" => (0x40, false),
        "f7" => (0x41, false),
        "f8" => (0x42, false),
        "f9" => (0x43, false),
        "f10" => (0x44, false),
        "f11" => (0x57, false),
        "f12" => (0x58, false),
        _ => return None,
    })
}

fn button_name(name: Option<&str>) -> protocol::wire::MouseButton {
    match name.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("right") => protocol::wire::MouseButton::Right,
        Some("middle") => protocol::wire::MouseButton::Middle,
        _ => protocol::wire::MouseButton::Left,
    }
}

/// Spawn the stdio MCP server thread (tokio current-thread runtime). The
/// process's stdio belongs to the MCP client from here on — only spawned
/// in `--mcp` mode.
pub fn spawn(app: AppHandle) {
    std::thread::Builder::new()
        .name("mcp-bridge".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("mcp tokio runtime");
            rt.block_on(async move {
                use rmcp::ServiceExt;
                match AgentBridge::new(app).serve(rmcp::transport::stdio()).await {
                    Ok(server) => {
                        eprintln!("[mcp] stdio server running");
                        let _ = server.waiting().await;
                    }
                    Err(err) => eprintln!("[mcp] server error: {err}"),
                }
            });
        })
        .expect("spawn mcp bridge");
}

#[derive(Clone)]
struct AgentBridge {
    app: AppHandle,
    last_shot: Arc<Mutex<Option<LastShot>>>,
}

impl AgentBridge {
    fn new(app: AppHandle) -> Self {
        Self {
            app,
            last_shot: Arc::new(Mutex::new(None)),
        }
    }

    /// Engine access with lazy auto-start (the bridge is the front door in
    /// `--mcp` mode; starting here keeps the UI-less run one step).
    fn with_engine<T>(
        &self,
        f: impl FnOnce(&EngineHandle) -> Result<T, String>,
    ) -> Result<T, String> {
        let services = self.app.state::<crate::commands::AppServices>();
        let guard = services.engine.lock().expect("engine slot");
        if let Some(handle) = guard.as_ref() {
            return f(handle);
        }
        drop(guard);
        crate::commands::start_engine(&self.app)?;
        let guard = services.engine.lock().expect("engine slot");
        guard
            .as_ref()
            .ok_or_else(|| "engine failed to start".to_owned())
            .and_then(f)
    }

    fn status_json(&self) -> Result<String, String> {
        self.with_engine(|handle| {
            let s = handle.status();
            let dto: EngineStatusDto = s.into();
            serde_json::to_string(&dto).map_err(|e| e.to_string())
        })
    }

    fn send_actions(&self, actions: Vec<AgentInput>) -> Result<(), String> {
        self.with_engine(|handle| {
            handle
                .send(engine::EngineCmd::AgentInput(actions))
                .map_err(|e| format!("agent input rejected: {e}"))
        })
    }

    fn capture(&self) -> Result<LastShot, String> {
        self.with_engine(|handle| {
            let meta = handle
                .capture_screenshot(Duration::from_secs(5))
                .ok_or_else(|| {
                    "no screenshot: no live session, decode stalled, or timeout".to_owned()
                })?;
            Ok(LastShot {
                space: ShotSpace {
                    shot_w: meta.width,
                    shot_h: meta.height,
                    frame_w: meta.frame_width,
                    frame_h: meta.frame_height,
                },
                jpeg: meta.jpeg,
            })
        })
    }

    fn click(&self, x: f64, y: f64, button: Option<String>) -> Result<(), String> {
        let space = self
            .last_shot
            .lock()
            .expect("last shot")
            .as_ref()
            .map(|shot| shot.space)
            .ok_or("no screenshot yet — call deepflux_screenshot first")?;
        let (nx, ny) = (
            to_normalized(x, space.shot_w),
            to_normalized(y, space.shot_h),
        );
        let button = button_name(button.as_deref());
        use protocol::wire::ButtonState;
        // Move first (input-fast), settle, then press+release (reliable):
        // the channels are ordered differently, so a short pause keeps the
        // click landing where the move stopped.
        self.send_actions(vec![AgentInput::MouseMove { x: nx, y: ny }])?;
        std::thread::sleep(Duration::from_millis(80));
        self.send_actions(vec![
            AgentInput::MouseButton {
                button,
                state: ButtonState::Pressed,
            },
            AgentInput::MouseButton {
                button,
                state: ButtonState::Released,
            },
        ])
    }
}

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{schemars, tool, tool_router};

fn err_json(kind: &str, msg: &str) -> String {
    serde_json::json!({ "ok": false, "kind": kind, "error": msg }).to_string()
}

fn ok_json(msg: &str) -> String {
    serde_json::json!({ "ok": true, "detail": msg }).to_string()
}

#[tool_router(server_handler)]
impl AgentBridge {
    /// Engine/session status as JSON (states, session id, input counters).
    #[tool(
        description = "DeepFlux engine status: host/controller state, live session id, input counters — JSON text."
    )]
    fn deepflux_status(&self) -> String {
        self.status_json()
            .unwrap_or_else(|e| err_json("status", &e))
    }

    /// Connect to a remote device by connection code (controller role).
    #[tool(
        description = "Connect to a remote machine by its connection code (16-hex). The host human still accepts the consent prompt."
    )]
    fn deepflux_connect(
        &self,
        Parameters(ConnectParams { device_code }): Parameters<ConnectParams>,
    ) -> String {
        // ADR-007 control gate: the account display name travels on the
        // request (same rule as the UI and the in-app agent tool).
        let requester_name = {
            let services = self.app.state::<crate::AppServices>();
            let account = services.account.lock().expect("account");
            match account.control_identity() {
                Ok(name) => name,
                Err(gate) => return err_json("connect", &gate.message()),
            }
        };
        // ADR-006: carry the pairing secret so the engine stamps the
        // pairing proof (silent paired accept must prove the secret).
        let pairing_secret = crate::chat::pairing_for(&self.app, &device_code)
            .map(|p| crate::chat::PairingSecret(p.secret_hex));
        match self.with_engine(|handle| {
            handle.send(engine::EngineCmd::Connect {
                code: device_code,
                pairing_secret,
                requester_name: Some(requester_name),
            })
        }) {
            Ok(()) => {
                ok_json("connect requested — wait for host consent, then poll deepflux_status")
            }
            Err(e) => err_json("connect", &e),
        }
    }

    /// Disconnect the current session.
    #[tool(description = "Disconnect the current session (controller role).")]
    fn deepflux_disconnect(&self) -> String {
        match self.with_engine(|handle| handle.send(engine::EngineCmd::Disconnect)) {
            Ok(()) => ok_json("disconnect sent"),
            Err(e) => err_json("disconnect", &e),
        }
    }

    /// Screenshot of the remote machine (JPEG) + coordinate metadata.
    #[tool(
        description = "Capture the remote machine's screen (JPEG image + text metadata with dimensions). Coordinate space for deepflux_click is this screenshot's pixels."
    )]
    fn deepflux_screenshot(&self) -> CallToolResult {
        let shot = match self.capture() {
            Ok(v) => v,
            Err(e) => {
                return CallToolResult::success(vec![ContentBlock::text(err_json(
                    "screenshot",
                    &e,
                ))]);
            }
        };
        let space = shot.space;
        let b64 = base64_encode(&shot.jpeg);
        *self.last_shot.lock().expect("last shot") = Some(shot);
        let meta = format!(
            "screenshot {}x{} px (frame {}x{}). deepflux_click x,y use these pixel coordinates.",
            space.shot_w, space.shot_h, space.frame_w, space.frame_h
        );
        CallToolResult::success(vec![
            ContentBlock::image(b64, "image/jpeg"),
            ContentBlock::text(meta),
        ])
    }

    /// Left/right/middle click at screenshot-pixel coordinates.
    #[tool(
        description = "Click at screenshot-pixel coordinates (x, y from the last deepflux_screenshot). button: left (default), right, middle."
    )]
    fn deepflux_click(
        &self,
        Parameters(ClickParams { x, y, button }): Parameters<ClickParams>,
    ) -> String {
        match self.click(x, y, button) {
            Ok(()) => ok_json("click sent"),
            Err(e) => err_json("click", &e),
        }
    }

    /// Type text as keystrokes (Unicode text events, no scan codes).
    #[tool(
        description = "Type text on the remote machine (Unicode text input; use for anything printable). Text payloads are never logged."
    )]
    fn deepflux_type_text(
        &self,
        Parameters(TypeTextParams { text }): Parameters<TypeTextParams>,
    ) -> String {
        if text.is_empty() {
            return err_json("type_text", "empty text");
        }
        match self.send_actions(vec![AgentInput::Text(text)]) {
            Ok(()) => ok_json("text sent"),
            Err(e) => err_json("type_text", &e),
        }
    }

    /// Press a named key (press+release).
    #[tool(
        description = "Press a named key once (press+release): escape, enter, tab, backspace, delete, home, end, pageup, pagedown, arrows (up/down/left/right), space, alt, ctrl, shift, win, f1-f12. Use deepflux_type_text for printable characters."
    )]
    fn deepflux_key(&self, Parameters(KeyParams { name }): Parameters<KeyParams>) -> String {
        match key_scan_code(&name) {
            Some((scan_code, extended)) => {
                use protocol::wire::ButtonState;
                match self.send_actions(vec![
                    AgentInput::Key {
                        scan_code,
                        extended,
                        state: ButtonState::Pressed,
                    },
                    AgentInput::Key {
                        scan_code,
                        extended,
                        state: ButtonState::Released,
                    },
                ]) {
                    Ok(()) => ok_json("key sent"),
                    Err(e) => err_json("key", &e),
                }
            }
            None => err_json("key", &format!("unknown key name: {name}")),
        }
    }

    /// Scroll vertically (wheel delta; negative = down).
    #[tool(
        description = "Scroll the mouse wheel: delta_v in wheel clicks (positive = up, negative = down)."
    )]
    fn deepflux_scroll(
        &self,
        Parameters(ScrollParams { delta_v }): Parameters<ScrollParams>,
    ) -> String {
        match self.send_actions(vec![AgentInput::Wheel {
            delta_v,
            delta_h: 0,
        }]) {
            Ok(()) => ok_json("scroll sent"),
            Err(e) => err_json("scroll", &e),
        }
    }

    /// Block until the session is live (or timeout) — for consent waits.
    #[tool(
        description = "Wait up to timeout_ms (default 30000) for the controller session to reach Connected (i.e. the host human accepted). Returns the final state."
    )]
    fn deepflux_wait_connected(
        &self,
        Parameters(WaitParams { timeout_ms }): Parameters<WaitParams>,
    ) -> String {
        let deadline = std::time::Instant::now()
            + Duration::from_millis(timeout_ms.unwrap_or(30_000).min(120_000));
        loop {
            match self.with_engine(|handle| Ok(handle.status().controller_state)) {
                Ok(state) if state == "Connected" => {
                    return ok_json("session connected");
                }
                Ok(state) if std::time::Instant::now() >= deadline => {
                    return err_json("wait_connected", &format!("timed out in state {state}"));
                }
                Ok(_) => std::thread::sleep(Duration::from_millis(200)),
                Err(e) => return err_json("wait_connected", &e),
            }
        }
    }
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ConnectParams {
    device_code: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ClickParams {
    x: f64,
    y: f64,
    button: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct TypeTextParams {
    text: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct KeyParams {
    name: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ScrollParams {
    delta_v: i32,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct WaitParams {
    timeout_ms: Option<u64>,
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_maps_shot_pixels_to_65535() {
        let space = ShotSpace {
            shot_w: 1600,
            shot_h: 900,
            frame_w: 1920,
            frame_h: 1080,
        };
        let _ = space;
        assert_eq!(to_normalized(0.0, 1600), 0);
        assert_eq!(to_normalized(1600.0, 1600), 65_535);
        assert_eq!(to_normalized(800.0, 1600), 32_768);
        // Out-of-range clamps instead of wrapping.
        assert_eq!(to_normalized(-5.0, 1600), 0);
        assert_eq!(to_normalized(9000.0, 1600), 65_535);
    }

    #[test]
    fn key_table_covers_common_names() {
        assert_eq!(key_scan_code("enter"), Some((0x1C, false)));
        assert_eq!(key_scan_code("Return"), Some((0x1C, false)));
        assert_eq!(key_scan_code("arrow_right"), Some((0x4D, true)));
        assert_eq!(key_scan_code("f12"), Some((0x58, false)));
        assert_eq!(key_scan_code("space"), Some((0x39, false)));
        assert_eq!(key_scan_code("nonsense"), None);
    }

    #[test]
    fn button_names_map_to_wire_variants() {
        use protocol::wire::MouseButton;
        assert_eq!(button_name(None), MouseButton::Left);
        assert_eq!(button_name(Some("left")), MouseButton::Left);
        assert_eq!(button_name(Some("Right")), MouseButton::Right);
        assert_eq!(button_name(Some("middle")), MouseButton::Middle);
    }
}
