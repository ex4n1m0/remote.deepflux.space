//! `e2e-child` — one engine instance for the M4 end-to-end scenario
//! (`apps/desktop/src-tauri/tests/e2e.rs`). It is the "second app
//! instance": the same engine the Tauri commands drive, scripted through
//! the exact same [`EngineCmd`] surface the UI buttons invoke
//! (command-layer drive; see the E2E section of `docs/reports/m4-shell.md`
//! for what remains manual).
//!
//! Roles:
//! * `--role host`: HostStart → Online → auto-accept consent → stream →
//!   after the session ends, re-register (auto-reonline) → Online again →
//!   exit 0.
//! * `--role controller`: ControllerStart → wait for host Online →
//!   Connect → Connected → stream with scripted mid-session quality and
//!   monitor changes + a focus-loss probe → Disconnect → Disconnected →
//!   exit 0.
//!
//! Host input uses the recording sink (single-machine safety, rig
//! default); the product's real `SendInputSink` path is M2-tested and
//! exercised by manual UX runs.

use std::path::PathBuf;
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};

use node_runtime::signaling_remote::{RemoteSignaling, RemoteSignalingConfig};
use protocol::wire::QualityPreset;

use remote_desktop_app_lib::engine::{
    self, EngineCmd, EngineConfig, EngineEvent, preset_from_name,
};

#[derive(Debug, Clone)]
struct Args {
    base_url: String,
    device_id: String,
    role: String,
    status_file: PathBuf,
    host_status_file: PathBuf,
    metrics_dir: Option<PathBuf>,
    quality: String,
    stream_secs: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        base_url: String::new(),
        device_id: String::new(),
        role: String::new(),
        status_file: std::env::temp_dir().join("rd-m4-e2e-status.json"),
        host_status_file: std::env::temp_dir().join("rd-m4-e2e-host-status.json"),
        metrics_dir: None,
        quality: "high".to_owned(),
        stream_secs: 12,
    };
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < raw.len() {
        let need = |name: &str, value: Option<&String>| {
            value
                .cloned()
                .ok_or_else(|| format!("missing value for {name}"))
        };
        match raw[i].as_str() {
            "--base-url" => {
                args.base_url = need("--base-url", raw.get(i + 1))?;
                i += 2;
            }
            "--device-id" => {
                args.device_id = need("--device-id", raw.get(i + 1))?;
                i += 2;
            }
            "--role" => {
                args.role = need("--role", raw.get(i + 1))?;
                i += 2;
            }
            "--status-file" => {
                args.status_file = PathBuf::from(need("--status-file", raw.get(i + 1))?);
                i += 2;
            }
            "--host-status-file" => {
                args.host_status_file = PathBuf::from(need("--host-status-file", raw.get(i + 1))?);
                i += 2;
            }
            "--metrics-dir" => {
                args.metrics_dir = Some(PathBuf::from(need("--metrics-dir", raw.get(i + 1))?));
                i += 2;
            }
            "--quality" => {
                args.quality = need("--quality", raw.get(i + 1))?;
                i += 2;
            }
            "--stream-secs" => {
                args.stream_secs = need("--stream-secs", raw.get(i + 1))?
                    .parse()
                    .map_err(|e| format!("stream-secs: {e}"))?;
                i += 2;
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    if args.base_url.is_empty() || args.device_id.is_empty() || args.role.is_empty() {
        return Err("required: --base-url --device-id --role".into());
    }
    Ok(args)
}

/// Child verdict written into the status file (asserted by the harness).
#[derive(Default, Clone)]
struct Verdict {
    online_reached: bool,
    consent_prompted: bool,
    connected_reached: bool,
    established: u64,
    ended_causes: Vec<String>,
    diag_events: u64,
    state_log: Vec<String>,
    final_note: String,
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("e2e-child: {err}");
            std::process::exit(2);
        }
    };
    let is_host = args.role == "host";
    let signaling = RemoteSignaling::new(RemoteSignalingConfig::new(
        &args.base_url,
        &args.device_id,
        "e2e-child-token",
    ));
    let cfg = EngineConfig {
        device_id: args.device_id.clone(),
        signaling: Box::new(signaling),
        real_pipelines: true,
        real_input: false, // recording sink: single-machine safety
        auto_reonline: true,
        metrics_dir: args.metrics_dir.clone(),
        status_file: Some(args.status_file.clone()),
        viewer_title: "M4 E2E viewer (real desktop)".to_owned(),
        initial_quality: QualityPreset::Balanced,
        initial_scale: render_windows::ScaleMode::Fit,
    };
    let (handle, events) = engine::spawn(cfg);
    let mut verdict = Verdict::default();
    let deadline = Instant::now() + Duration::from_secs(150);
    let code = if is_host {
        run_host(&handle, &args, events, &mut verdict, deadline)
    } else {
        run_controller(&handle, &args, events, &mut verdict, deadline)
    };
    handle.shutdown();
    write_verdict(&args, verdict);
    std::process::exit(code);
}

fn pump_events(
    events: &std::sync::mpsc::Receiver<EngineEvent>,
    verdict: &mut Verdict,
    mut on_event: impl FnMut(&EngineEvent),
) {
    loop {
        match events.try_recv() {
            Ok(event) => {
                match &event {
                    EngineEvent::StateChanged { machine, state, .. } => {
                        verdict.state_log.push(format!("{machine}->{state}"));
                        if state == "Online" {
                            verdict.online_reached = true;
                        }
                        if state == "Connected" {
                            verdict.connected_reached = true;
                        }
                    }
                    EngineEvent::ConsentRequested { .. } => verdict.consent_prompted = true,
                    EngineEvent::SessionEstablished { .. } => verdict.established += 1,
                    EngineEvent::SessionEnded { cause, .. } => {
                        verdict.ended_causes.push(cause.clone())
                    }
                    EngineEvent::Diagnostics { .. } => verdict.diag_events += 1,
                    _ => {}
                }
                on_event(&event);
            }
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => return,
        }
    }
}

fn host_status_state(path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    value
        .get("host_state")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
}

fn run_host(
    handle: &remote_desktop_app_lib::engine::EngineHandle,
    _args: &Args,
    events: std::sync::mpsc::Receiver<EngineEvent>,
    verdict: &mut Verdict,
    deadline: Instant,
) -> i32 {
    handle.send(EngineCmd::HostStart).expect("host start");
    // Online.
    while Instant::now() < deadline {
        pump_events(&events, verdict, |_| {});
        if verdict.online_reached {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if !verdict.online_reached {
        verdict.final_note = "host never reached Online".into();
        return 1;
    }
    eprintln!("[e2e-host] Online");
    // Wait for consent, accept after a beat.
    let mut accepted = false;
    let mut reonline_after_end = false;
    let mut saw_end = false;
    while Instant::now() < deadline {
        pump_events(&events, verdict, |_| {});
        if verdict.consent_prompted && !accepted {
            std::thread::sleep(Duration::from_millis(400));
            handle.send(EngineCmd::ConsentAccept).expect("accept");
            accepted = true;
            eprintln!("[e2e-host] consent accepted");
        }
        if !verdict.ended_causes.is_empty() && !saw_end {
            saw_end = true;
            eprintln!("[e2e-host] session ended: {:?}", verdict.ended_causes);
        }
        if saw_end && !reonline_after_end {
            // Give the auto-reonline timer (1 s) a moment, then confirm.
            std::thread::sleep(Duration::from_millis(2_500));
            reonline_after_end = true;
        }
        if reonline_after_end {
            let state = handle.status();
            if state.host_state == "Online" {
                eprintln!("[e2e-host] back Online after session end");
                verdict.final_note = "host: online->session->online".into();
                return 0;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    verdict.final_note = "host timed out".into();
    1
}

fn run_controller(
    handle: &remote_desktop_app_lib::engine::EngineHandle,
    args: &Args,
    events: std::sync::mpsc::Receiver<EngineEvent>,
    verdict: &mut Verdict,
    deadline: Instant,
) -> i32 {
    handle
        .send(EngineCmd::ControllerStart)
        .expect("controller start");
    // Wait for the host side to be Online and its status file to carry the
    // device id (cross-instance coordination via the host's status file —
    // the same channel the m2_rig used; the id appears after the first
    // engine status write, ~200 ms after spawn).
    let mut host_device = None;
    while Instant::now() < deadline {
        pump_events(&events, verdict, |_| {});
        if verdict.online_reached
            && host_status_state(&args.host_status_file).as_deref() == Some("Online")
        {
            host_device = host_device_from_status(&args.host_status_file);
            if host_device.is_some() {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let Some(host_device) = host_device else {
        verdict.final_note = "host status file missing device id".into();
        return 1;
    };
    eprintln!("[e2e-ctrl] connecting to {host_device}");
    handle
        .send(EngineCmd::Connect { code: host_device })
        .expect("connect");
    // Connected.
    while Instant::now() < deadline && !verdict.connected_reached {
        pump_events(&events, verdict, |_| {});
        std::thread::sleep(Duration::from_millis(20));
    }
    if !verdict.connected_reached {
        verdict.final_note = "controller never reached Connected".into();
        return 1;
    }
    eprintln!("[e2e-ctrl] Connected; streaming");
    let started = Instant::now();
    let mut quality_changed = false;
    let mut monitor_picked = false;
    let mut focus_probe_done = false;
    let mut disconnected = false;
    while Instant::now() < deadline {
        pump_events(&events, verdict, |_| {});
        let elapsed = started.elapsed().as_secs();
        // Mid-session quality preset change (RD-012).
        if !quality_changed && elapsed >= args.stream_secs / 3 {
            quality_changed = true;
            let preset = preset_from_name(&args.quality).unwrap_or(QualityPreset::High);
            handle.send(EngineCmd::SetQuality(preset)).expect("quality");
            eprintln!("[e2e-ctrl] quality preset changed to {}", args.quality);
        }
        // Monitor pick: the primary monitor of the host's advertised list.
        if !monitor_picked && elapsed >= (args.stream_secs * 2) / 3 {
            monitor_picked = true;
            let status = handle.status();
            let monitor = status
                .peer_monitors
                .iter()
                .find(|m| m.is_primary)
                .or_else(|| status.peer_monitors.first())
                .map(|m| m.monitor_id.clone());
            if let Some(monitor) = monitor {
                handle
                    .send(EngineCmd::SelectMonitor {
                        monitor_id: monitor,
                    })
                    .expect("monitor");
                eprintln!("[e2e-ctrl] monitor picked");
            } else {
                eprintln!("[e2e-ctrl] no peer monitors advertised; skipping pick");
            }
        }
        // Focus-loss probe: post WM_KILLFOCUS to the real viewer window;
        // the engine must send AllKeysUp{FocusLost} (M2 input hook).
        if !focus_probe_done && elapsed >= 1 {
            focus_probe_done = true;
            let hwnd = handle.status().viewer_hwnd;
            if hwnd != 0 {
                post_kill_focus(hwnd);
                eprintln!("[e2e-ctrl] focus-loss probe posted to viewer {hwnd:#x}");
            }
        }
        if elapsed >= args.stream_secs && !disconnected {
            disconnected = true;
            handle.send(EngineCmd::Disconnect).expect("disconnect");
            eprintln!("[e2e-ctrl] disconnect sent");
        }
        if disconnected {
            let state = handle.status();
            if state.controller_state == "Disconnected" {
                eprintln!(
                    "[e2e-ctrl] Disconnected; presented={} all_keys_up_sent={}",
                    state.counters.frames_presented, state.counters.input_all_keys_up_sent
                );
                verdict.final_note = format!(
                    "controller: connected->streamed->disconnected (presented={}, diag_events={})",
                    state.counters.frames_presented, verdict.diag_events
                );
                // One status-write cadence before shutdown so the rolling
                // status file records the final state.
                std::thread::sleep(Duration::from_millis(400));
                return 0;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    verdict.final_note = "controller timed out".into();
    1
}

fn host_device_from_status(path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    value
        .get("device_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
}

fn write_verdict(args: &Args, verdict: Verdict) {
    // Merge the verdict into the engine's rolling status file.
    let mut base: serde_json::Value = std::fs::read_to_string(&args.status_file)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    base["device_id"] = serde_json::json!(args.device_id);
    base["role"] = serde_json::json!(args.role);
    base["verdict"] = serde_json::json!({
        "online_reached": verdict.online_reached,
        "consent_prompted": verdict.consent_prompted,
        "connected_reached": verdict.connected_reached,
        "established": verdict.established,
        "ended_causes": verdict.ended_causes,
        "diag_events": verdict.diag_events,
        "state_log": verdict.state_log,
        "final_note": verdict.final_note,
    });
    let tmp = args.status_file.with_extension("tmp");
    if std::fs::write(
        &tmp,
        serde_json::to_string_pretty(&base).unwrap_or_default(),
    )
    .is_ok()
    {
        let _ = std::fs::rename(&tmp, &args.status_file);
    }
}

/// Post `WM_KILLFOCUS` to the viewer window (8 = WM_KILLFOCUS).
fn post_kill_focus(hwnd: u64) {
    use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_KILLFOCUS};
    unsafe {
        let _ = PostMessageW(
            Some(HWND(hwnd as *mut _)),
            WM_KILLFOCUS,
            WPARAM(0),
            LPARAM(0),
        );
    }
}
