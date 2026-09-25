//! Typed IPC surface (RD-011: "communicate through typed commands/
//! channels"). Every type here is JSON-serializable **metadata**: state
//! names, ids, counters, and short strings — snake_case like the signaling
//! schema. Nothing in this module can carry frame bytes, GPU surfaces, SDP
//! bodies, or input payloads — that is the structural proof of AGENTS.md
//! invariant 1 (see the IPC surface table in `docs/reports/m4-shell.md`).

use serde::{Deserialize, Serialize};

use crate::engine::{EngineCounters, EngineStatus};

// ---------------------------------------------------------------------------
// Commands (frontend → Rust). Arguments are primitives/strings only.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SettingsPatch {
    pub device_name: String,
    pub signaling_base_url: String,
    pub default_quality: String,
    pub default_viewer_scale: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddFavoriteArgs {
    pub name: String,
    pub code: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RenameFavoriteArgs {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemoveFavoriteArgs {
    pub id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SelectMonitorArgs {
    pub monitor_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SetQualityArgs {
    pub preset: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConnectArgs {
    pub code: String,
}

// ---------------------------------------------------------------------------
// Results / event payloads (Rust → frontend).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Identity {
    pub device_id: String,
    pub device_name: String,
    /// The connection code other machines enter to control this one
    /// (= the device id; one code per machine, no directory service in MVP).
    pub connection_code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsDto {
    pub device_id: String,
    pub device_name: String,
    pub signaling_base_url: String,
    pub default_quality: String,
    pub default_viewer_scale: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FavoriteDto {
    pub id: String,
    pub name: String,
    pub code: String,
}

/// One display the host can share.
#[derive(Debug, Clone, Serialize)]
pub struct MonitorDto {
    pub monitor_id: String,
    pub label: String,
    pub width_px: u32,
    pub height_px: u32,
    pub is_primary: bool,
    pub desktop_left: i32,
    pub desktop_top: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ViewerInfo {
    pub created: bool,
    pub fullscreen: bool,
    pub focused: bool,
    pub scale: String,
}

/// Pull-based engine status (the authoritative counterpart to the
/// `engine://state` push events).
#[derive(Debug, Clone, Serialize)]
pub struct EngineStatusDto {
    pub host_state: String,
    pub controller_state: String,
    pub session_id: Option<String>,
    pub viewer: ViewerInfo,
    pub host_monitors: Vec<MonitorDto>,
    pub peer_monitors: Vec<MonitorDto>,
    pub active_monitor: Option<String>,
    pub quality: String,
    pub encoder: Option<String>,
    pub counters: EngineCounters,
}

impl From<EngineStatus> for EngineStatusDto {
    fn from(status: EngineStatus) -> Self {
        Self {
            host_state: status.host_state,
            controller_state: status.controller_state,
            session_id: status.session_id,
            viewer: ViewerInfo {
                created: status.viewer_created,
                fullscreen: status.viewer_fullscreen,
                focused: status.viewer_focused,
                scale: status.viewer_scale,
            },
            host_monitors: status.host_monitors,
            peer_monitors: status.peer_monitors,
            active_monitor: status.active_monitor,
            quality: status.quality,
            encoder: status.encoder,
            counters: status.counters,
        }
    }
}
