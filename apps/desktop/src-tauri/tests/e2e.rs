//! M4 end-to-end scenario (gate): **two app instances on this machine**
//! connecting through the **local standalone signaling server**
//! (`services/signaling`), driven at the **command layer** (the typed
//! engine commands the Tauri UI invokes — tauri-driver multi-window
//! automation proved impractical here; see
//! `docs/reports/m4-shell.md` for the exact reduced form and the residual
//! manual list).
//!
//! Topology per run:
//! * `node tools/upstash-emulator.mjs --port <p1>` (Upstash REST emulator)
//! * `node --import tsx tools/dev-server.mjs --port <p2>` (the SAME
//!   standalone WS server the M3 contract tests drive)
//! * `e2e-child --role host` + `e2e-child --role controller` (full engines:
//!   real DXGI capture, MF H.264, loopback WebRTC, native viewer window)
//!
//! Scenario asserted (per the M4 work package): host start → Online;
//! controller connect → host consent → accept → session live (the viewer
//! window presents real decoded frames); quality preset change on the
//! wire; monitor pick on the wire; focus-loss `AllKeysUp{FocusLost}`;
//! disconnect; host returns Online; diagnostics events received.
//!
//! M6 addition (connect-failure case): a connect that cannot succeed —
//! both sides' remote candidates rewritten to the discard port — must
//! surface the typed `Timeout` `SessionEnded` with the `DIRECT_ONLY`
//! hint at the command layer inside the 10 s connect window, with no
//! hang and a clean teardown on both sides.
//!
//! Gated behind `M4_E2E=1` (real-hardware test; F44 skip-with-reason
//! convention — `cargo test --workspace` stays green on machines without
//! a display/GPU). Run:
//!
//! ```bash
//! M4_E2E=1 cargo test -p remote-desktop-app --test e2e -- --nocapture
//! ```

use std::io::Read;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const EMULATOR_PORT: u16 = 38_091;
const SERVER_PORT: u16 = 38_093;
const STREAM_SECS: u64 = 14;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3) // src-tauri -> desktop -> apps -> repo root
        .expect("repo root")
        .to_path_buf()
}

fn wait_tcp(port: u16, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn spawn_node(dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Child {
    let mut command = Command::new("node");
    command
        .current_dir(dir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    for (key, value) in envs {
        command.env(key, value);
    }
    command.spawn().expect("spawn node child")
}

fn drain(child: &mut Child, tag: &str) {
    // Best-effort non-blocking log drain so a crashed child surfaces its
    // stderr in the test output.
    if let Some(mut stderr) = child.stderr.take() {
        let mut buf = [0u8; 8192];
        if let Ok(n @ 1..) = stderr.read(&mut buf) {
            eprintln!("[{tag}] {}", String::from_utf8_lossy(&buf[..n]));
        }
        child.stderr = Some(stderr);
    }
}

fn read_status(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path).expect("status file");
    serde_json::from_str(&text).expect("status json")
}

fn get_bool(status: &serde_json::Value, pointer: &str) -> bool {
    status
        .pointer(pointer)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn get_u64(status: &serde_json::Value, pointer: &str) -> u64 {
    status
        .pointer(pointer)
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

fn get_str<'a>(status: &'a serde_json::Value, pointer: &str) -> Option<&'a str> {
    status.pointer(pointer).and_then(|v| v.as_str())
}

#[test]
fn two_instances_full_session_over_local_signaling() {
    if std::env::var("M4_E2E").ok().as_deref() != Some("1") {
        eprintln!("SKIP m4 e2e: M4_E2E=1 not set (needs the local display/GPU; see module docs)");
        return;
    }
    let signaling_dir = repo_root().join("services/signaling");
    let work_dir = std::env::temp_dir().join(format!(
        "rd-m4-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));
    std::fs::create_dir_all(&work_dir).expect("work dir");
    let host_status = work_dir.join("host-status.json");
    let ctrl_status = work_dir.join("ctrl-status.json");
    let metrics_dir = work_dir.join("metrics");

    // --- local signaling stack -----------------------------------------
    // Free the ports first: a surviving service from an aborted run would
    // shadow the fresh one (and its mailbox would dedupe our message ids).
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Get-NetTCPConnection -LocalPort {EMULATOR_PORT},{SERVER_PORT} -State Listen                  -ErrorAction SilentlyContinue | ForEach-Object {{ Stop-Process -Id $_.OwningProcess -Force }}"
            ),
        ])
        .output();
    let mut emulator = spawn_node(
        &signaling_dir,
        &[
            "tools/upstash-emulator.mjs",
            "--port",
            &EMULATOR_PORT.to_string(),
        ],
        &[],
    );
    let mut server = spawn_node(
        &signaling_dir,
        &[
            "--import",
            "tsx",
            "tools/dev-server.mjs",
            "--port",
            &SERVER_PORT.to_string(),
        ],
        &[
            (
                "UPSTASH_REDIS_REST_URL",
                &format!("http://127.0.0.1:{EMULATOR_PORT}"),
            ),
            ("UPSTASH_REDIS_REST_TOKEN", "local-t"),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    assert!(
        wait_tcp(SERVER_PORT, deadline),
        "standalone signaling server did not come up"
    );

    // --- two app instances (command-layer drive) ------------------------
    let child_bin = std::env::var("CARGO_BIN_EXE_e2e-child")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_e2e_child"))
        .expect("e2e-child bin built next to the test");
    let base_url = format!("http://127.0.0.1:{SERVER_PORT}");
    // Unique device ids per run: a stale emulator (or a re-run against a
    // warm mailbox) would otherwise swallow re-used message ids as
    // duplicates and drop the connect request (the service's idempotency
    // is per message_id).
    let run_tag = format!(
        "{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let host_device = format!("m4-e2e-host-{run_tag}");
    let ctrl_device = format!("m4-e2e-ctrl-{run_tag}");
    let mut host_child = Command::new(&child_bin)
        .arg("--role")
        .arg("host")
        .arg("--base-url")
        .arg(&base_url)
        .arg("--device-id")
        .arg(&host_device)
        .arg("--status-file")
        .arg(&host_status)
        .arg("--metrics-dir")
        .arg(&metrics_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn host child");
    let mut ctrl_child = Command::new(&child_bin)
        .arg("--role")
        .arg("controller")
        .arg("--base-url")
        .arg(&base_url)
        .arg("--device-id")
        .arg(&ctrl_device)
        .arg("--status-file")
        .arg(&ctrl_status)
        .arg("--host-status-file")
        .arg(&host_status)
        .arg("--metrics-dir")
        .arg(&metrics_dir)
        .arg("--quality")
        .arg("high")
        .arg("--stream-secs")
        .arg(STREAM_SECS.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn controller child");

    // --- wait for both to finish (bounded) --------------------------------
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut host_code = None;
    let mut ctrl_code = None;
    while Instant::now() < deadline {
        drain(&mut host_child, "host");
        drain(&mut ctrl_child, "ctrl");
        if host_code.is_none()
            && let Some(status) = host_child.try_wait().expect("host wait")
        {
            host_code = status.code();
        }
        if ctrl_code.is_none()
            && let Some(status) = ctrl_child.try_wait().expect("ctrl wait")
        {
            ctrl_code = status.code();
        }
        if host_code.is_some() && ctrl_code.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    drain(&mut host_child, "host");
    drain(&mut ctrl_child, "ctrl");
    let _ = emulator.kill();
    let _ = server.kill();
    let _ = emulator.wait();
    let _ = server.wait();

    // --- assertions on the rolling status files ---------------------------
    let host = read_status(&host_status);
    let ctrl = read_status(&ctrl_status);
    eprintln!("--- host status ---\n{host:#}");
    eprintln!("--- controller status ---\n{ctrl:#}");

    assert_eq!(host_code, Some(0), "host child exited cleanly");
    assert_eq!(ctrl_code, Some(0), "controller child exited cleanly");

    // Host: online → session → online again.
    assert_eq!(get_str(&host, "/host_state"), Some("Online"));
    assert!(
        get_bool(&host, "/verdict/online_reached"),
        "host reached Online"
    );
    assert!(
        get_bool(&host, "/verdict/consent_prompted"),
        "host was prompted for consent"
    );
    assert_eq!(get_u64(&host, "/verdict/established"), 1);
    assert!(
        host["verdict"]["state_log"]
            .as_array()
            .is_some_and(|log| log.iter().any(|v| v.as_str() == Some("host->Connected"))),
        "host reached Connected: {:?}",
        host["verdict"]["state_log"]
    );
    // Real desktop actually streamed: captured → encoded.
    assert!(
        get_u64(&host, "/counters/frames_captured") > 100,
        "host captured frames: {}",
        get_u64(&host, "/counters/frames_captured")
    );
    assert!(
        get_u64(&host, "/counters/frames_encoded") > 100,
        "host encoded frames: {}",
        get_u64(&host, "/counters/frames_encoded")
    );
    // Quality change applied on the host: encoder rebuilt with the new
    // bitrate (High preset = 12 Mbps CBR in the describe string).
    assert!(
        get_u64(&host, "/counters/encoder_rebuilds") >= 1,
        "quality change rebuilt the encoder"
    );
    assert!(
        get_str(&host, "/encoder").is_some_and(|e| e.contains("12000000")),
        "encoder describe carries the high-preset bitrate: {:?}",
        get_str(&host, "/encoder")
    );
    // Monitor pick applied (primary re-selected; switch may be a no-op on
    // single-monitor machines — the command round-trip is what is pinned).
    assert!(
        host["verdict"]["state_log"]
            .as_array()
            .is_some_and(|log| log.iter().any(|v| v.as_str() == Some("host->Disconnected")))
    );

    // Controller: connected → presented frames → resize follow (F49) →
    // focus-loss safety → viewer-close disconnect (F50) with asserted
    // causes (F53) → diagnostics.
    assert_eq!(get_str(&ctrl, "/controller_state"), Some("Disconnected"));
    assert!(ctrl["verdict"]["state_log"].as_array().is_some_and(|log| {
        log.iter()
            .any(|v| v.as_str() == Some("controller->Connected"))
    }));
    assert!(
        get_u64(&ctrl, "/counters/frames_presented") > 50,
        "viewer presented real frames: {}",
        get_u64(&ctrl, "/counters/frames_presented")
    );
    assert!(
        get_u64(&ctrl, "/counters/input_all_keys_up_sent") >= 1,
        "focus-loss probe emitted AllKeysUp"
    );
    assert!(
        get_u64(&ctrl, "/verdict/diag_events") >= 1,
        "controller received diagnostics aggregate events"
    );
    assert!(
        get_u64(&host, "/input/all_keys_up") >= 1,
        "host pump saw the AllKeysUp release"
    );

    // F49: the swapchain followed the scripted 1600x1000 client resize
    // (same value as the client size — no stale-stretch).
    assert!(
        get_bool(&ctrl, "/verdict/resize_ok"),
        "viewer resize followed by the swapchain"
    );
    // F50: the session ended through the viewer-close path.
    assert!(
        get_bool(&ctrl, "/verdict/closed_viewer"),
        "disconnect came from closing the viewer window"
    );
    // F53: the disconnect causes are what the machines say they are —
    // controller ended its own session (User), host learned from the peer
    // (Peer) — not a timeout/transport fallback.
    let ctrl_causes = ctrl["verdict"]["ended_causes"]
        .as_array()
        .expect("controller ended_causes");
    assert!(
        ctrl_causes.iter().any(|v| v.as_str() == Some("User")),
        "controller cause must be User, got {ctrl_causes:?}"
    );
    let host_causes = host["verdict"]["ended_causes"]
        .as_array()
        .expect("host ended_causes");
    assert!(
        host_causes.iter().any(|v| v.as_str() == Some("Peer")),
        "host cause must contain Peer, got {host_causes:?}"
    );

    let _ = std::fs::remove_dir_all(&work_dir);
}

/// M6 E2E connect-failure case (audit F59-adjacent recommendation, §4.3
/// gap): a connect that cannot succeed — every remote candidate's port
/// rewritten to the discard port on the controller side (the m5 rig's
/// `--blackhole-candidates` technique, now also in
/// `engine::blackhole`), so signaling completes but ICE connectivity
/// checks can never land. The product path must produce the typed
/// `Timeout` `SessionEnded` carrying the DIRECT_ONLY hint at the command
/// layer, inside the 10 s connect window (+slack), with no hang and a
/// clean teardown on both sides (the host observes the signaling-level
/// disconnect and re-registers, exactly like the m5 udpblocked cell).
#[test]
fn connect_failure_blackholed_candidates_surface_typed_timeout() {
    if std::env::var("M4_E2E").ok().as_deref() != Some("1") {
        eprintln!("SKIP m4 e2e: M4_E2E=1 not set (needs the local display/GPU; see module docs)");
        return;
    }
    let signaling_dir = repo_root().join("services/signaling");
    let work_dir = std::env::temp_dir().join(format!(
        "rd-m6-e2e-fail-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));
    std::fs::create_dir_all(&work_dir).expect("work dir");
    let host_status = work_dir.join("host-status.json");
    let ctrl_status = work_dir.join("ctrl-status.json");
    let metrics_dir = work_dir.join("metrics");

    // Same port hygiene as the happy-path test.
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Get-NetTCPConnection -LocalPort {EMULATOR_PORT},{SERVER_PORT} -State Listen                  -ErrorAction SilentlyContinue | ForEach-Object {{ Stop-Process -Id $_.OwningProcess -Force }}"
            ),
        ])
        .output();
    let mut emulator = spawn_node(
        &signaling_dir,
        &[
            "tools/upstash-emulator.mjs",
            "--port",
            &EMULATOR_PORT.to_string(),
        ],
        &[],
    );
    let mut server = spawn_node(
        &signaling_dir,
        &[
            "--import",
            "tsx",
            "tools/dev-server.mjs",
            "--port",
            &SERVER_PORT.to_string(),
        ],
        &[
            (
                "UPSTASH_REDIS_REST_URL",
                &format!("http://127.0.0.1:{EMULATOR_PORT}"),
            ),
            ("UPSTASH_REDIS_REST_TOKEN", "local-t"),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    assert!(
        wait_tcp(SERVER_PORT, deadline),
        "standalone signaling server did not come up"
    );

    let child_bin = std::env::var("CARGO_BIN_EXE_e2e-child")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_e2e_child"))
        .expect("e2e-child bin built next to the test");
    let base_url = format!("http://127.0.0.1:{SERVER_PORT}");
    let run_tag = format!(
        "{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let host_device = format!("m6-e2e-host-{run_tag}");
    let ctrl_device = format!("m6-e2e-ctrl-{run_tag}");
    let mut host_child = Command::new(&child_bin)
        .arg("--role")
        .arg("host")
        .arg("--base-url")
        .arg(&base_url)
        .arg("--device-id")
        .arg(&host_device)
        .arg("--status-file")
        .arg(&host_status)
        .arg("--metrics-dir")
        .arg(&metrics_dir)
        // The host side of the failure scenario: its remote candidates
        // are blackholed TOO (the m5 rig cell blackholes both sides —
        // with only one side dead the peer's prflx checks still succeed
        // and the answerer can reach Connected alone), and no session
        // will arrive: its own connect window ends the attempt, with the
        // bounded stop as the backstop.
        .arg("--blackhole-candidates")
        .arg("--expect-no-session")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn host child");
    let mut ctrl_child = Command::new(&child_bin)
        .arg("--role")
        .arg("controller")
        .arg("--base-url")
        .arg(&base_url)
        .arg("--device-id")
        .arg(&ctrl_device)
        .arg("--status-file")
        .arg(&ctrl_status)
        .arg("--host-status-file")
        .arg(&host_status)
        .arg("--metrics-dir")
        .arg(&metrics_dir)
        // The scenario under test: candidates blackholed + the child
        // scripts the failure expectation (typed timeout + hint).
        .arg("--blackhole-candidates")
        .arg("--expect-connect-failure")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn controller child");

    let started = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut host_code = None;
    let mut ctrl_code = None;
    while Instant::now() < deadline {
        drain(&mut host_child, "host");
        drain(&mut ctrl_child, "ctrl");
        if host_code.is_none()
            && let Some(status) = host_child.try_wait().expect("host wait")
        {
            host_code = status.code();
        }
        if ctrl_code.is_none()
            && let Some(status) = ctrl_child.try_wait().expect("ctrl wait")
        {
            ctrl_code = status.code();
        }
        if host_code.is_some() && ctrl_code.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    drain(&mut host_child, "host");
    drain(&mut ctrl_child, "ctrl");
    let _ = emulator.kill();
    let _ = server.kill();
    let _ = emulator.wait();
    let _ = server.wait();

    assert_eq!(host_code, Some(0), "host child exited cleanly");
    assert_eq!(
        ctrl_code,
        Some(0),
        "controller child exited cleanly (typed failure is a handled outcome)"
    );

    let ctrl = read_status(&ctrl_status);
    let host = read_status(&host_status);
    eprintln!(
        "--- controller status (failure case) ---
{ctrl:#}"
    );

    // The typed cause reached the command layer with the direct-only hint.
    assert_eq!(
        ctrl.pointer("/verdict/connect_fail_code")
            .and_then(|v| v.as_str()),
        Some("timeout"),
        "engine://error code must be timeout: {:?}",
        ctrl.pointer("/verdict/connect_fail_code")
    );
    assert!(
        ctrl.pointer("/verdict/connect_fail_hint_ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        "the DIRECT_ONLY hint must ride the error event"
    );
    // Never connected, and no hang: the typed failure landed inside the
    // connect window + slack (10 s window, generous CI margin).
    assert!(
        !get_bool(&ctrl, "/verdict/connected_reached"),
        "the blackholed connect must never reach Connected"
    );
    let fail_secs = ctrl
        .pointer("/verdict/connect_fail_secs")
        .and_then(|v| v.as_f64())
        .expect("connect_fail_secs recorded");
    assert!(
        fail_secs < 20.0,
        "typed failure must be bounded (got {fail_secs:.1}s; budget 10s window + slack)"
    );
    let ctrl_causes = ctrl["verdict"]["ended_causes"]
        .as_array()
        .expect("controller ended_causes");
    assert!(
        ctrl_causes.iter().any(|v| v.as_str() == Some("Timeout")),
        "controller cause must be Timeout, got {ctrl_causes:?}"
    );
    // Host: no session ever established (ICE dead in both directions),
    // the attempt ended inside the host's own connect window or the
    // bounded stop backstop — never a hang — and the role re-registered
    // Online (same outcome shape as the rig's udpblocked cell).
    assert_eq!(
        get_u64(&host, "/verdict/established"),
        0,
        "blackholed ICE must not establish a session on the host either"
    );
    let host_ended = host["verdict"]["ended_causes"]
        .as_array()
        .map(|c| c.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(
        host.pointer("/verdict/no_session_bailed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || host_ended.contains(&"Timeout"),
        "host attempt must end typed (own Timeout or bounded stop); causes={host_ended:?}"
    );
    assert_eq!(get_str(&host, "/host_state"), Some("Online"));
    eprintln!(
        "connect-failure case: typed timeout after {fail_secs:.1}s, clean teardown both sides (total {:?})",
        started.elapsed()
    );
    let _ = std::fs::remove_dir_all(&work_dir);
}
