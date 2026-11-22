//! Node self-test: ONE OpenAI-format request through the real loopback
//! gateway against the TEST-ONLY mock runtime (ADR-019), with a log-redaction
//! canary.
//!
//! Compiled only under `cfg(test)` or the `node-selftest` feature — the same
//! compile gate as the mock runtime itself. The flow:
//!
//! 1. start a node (mock runtime, ephemeral or caller-fixed port, everything
//!    under `data_dir`);
//! 2. send exactly one streaming chat-completions request to
//!    `http://127.0.0.1:{port}/v1/chat/completions` via reqwest;
//! 3. assert an SSE answer arrived (`text/event-stream`, `data:` frames,
//!    token deltas, terminal `[DONE]`);
//! 4. shut the node down gracefully and read back the node's own JSONL log;
//! 5. assert the prompt canary ([`CANARY`]) appears NOWHERE in the log —
//!    the redaction gate proven against the file on disk, not an in-memory
//!    sink.
//!
//! Everything stays inside `data_dir` (the caller passes a temp dir); no
//! network beyond loopback, no other files touched.

use std::path::Path;

use serde_json::{json, Value};

use crate::{Node, NodeConfig};

/// Unique string embedded in the self-test prompt; MUST be absent from every
/// log sink after the run (redaction gate).
pub const CANARY: &str = "MSP-SELFTEST-CANARY-PROMPT-7F3A9B2C";
/// Profile the self-test serves through the mock runtime.
pub const SELFTEST_PROFILE: &str = "msp1:selftest";
/// Output size requested (tokens) — small, deterministic.
pub const SELFTEST_MAX_TOKENS: u32 = 24;

/// What the self-test observed.
#[derive(Debug, Clone)]
pub struct SelfTestReport {
    /// Number of SSE token-delta chunks that arrived.
    pub tokens: usize,
    /// The ephemeral/fixed port the gateway actually bound.
    pub port: u16,
    /// True iff [`CANARY`] is absent from the on-disk log file.
    pub redacted_logs: bool,
    /// The installation id the node generated/loaded.
    pub installation_id: String,
}

/// Runs the full self-test against `data_dir` (use a temp dir). `port` may be
/// `0` for an OS-assigned ephemeral port; tests may pass a fixed one.
pub async fn run(data_dir: &Path, port: u16) -> Result<SelfTestReport, String> {
    let config = NodeConfig {
        tracker_base: None,
        gateway_port: port,
        data_dir: data_dir.to_path_buf(),
        profile_id: Some(SELFTEST_PROFILE.to_string()),
        mock: true,
        engine_binary: None,
        engine_gpu_binary: None,
        engine_model: None,
        engine_threads: None,
        cloud: None,
    };
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = Node::start(config, shutdown_rx)
        .await
        .map_err(|e| format!("node start failed: {e}"))?;

    let url = format!("http://{}/v1/chat/completions", handle.local_addr);
    let client = reqwest::Client::new();
    let body = json!({
        "model": SELFTEST_PROFILE,
        "messages": [{
            "role": "user",
            "content": format!("modelswarm node self-test request. {CANARY} this text must never reach any log sink.")
        }],
        "stream": true,
        "max_tokens": SELFTEST_MAX_TOKENS,
    });
    let response = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("gateway request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("gateway answered {}", response.status()));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if !content_type.contains("text/event-stream") {
        return Err(format!("expected SSE, got content-type {content_type:?}"));
    }
    let sse = response
        .text()
        .await
        .map_err(|e| format!("reading SSE body failed: {e}"))?;

    // Parse SSE frames: role chunk + N token deltas + finish + [DONE].
    let frames: Vec<&str> = sse
        .split("\n\n")
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .collect();
    let data_frames: Vec<&str> = frames
        .iter()
        .map(|f| f.trim_start_matches("data: "))
        .collect();
    match data_frames.last() {
        Some(&"[DONE]") => {}
        other => return Err(format!("stream must end with [DONE], got {other:?}")),
    }
    let mut tokens = 0usize;
    for frame in &data_frames {
        let chunk: Value = match serde_json::from_str(frame) {
            Ok(value) => value,
            Err(_) => continue, // [DONE] is not JSON
        };
        // Count real token deltas only — the leading role chunk carries an
        // empty content string and must not count.
        if chunk["choices"][0]["delta"]["content"]
            .as_str()
            .is_some_and(|content| !content.is_empty())
        {
            tokens += 1;
        }
    }
    if tokens == 0 {
        return Err("no token deltas arrived in the SSE stream".to_string());
    }

    // Graceful shutdown, then check the on-disk log for the canary.
    let installation_id = handle.installation_id.clone();
    let report_port = handle.local_addr.port();
    shutdown.send(true).expect("shutdown channel alive");
    handle.stopped().await;

    let log_path = data_dir.join(crate::LOG_RELATIVE_PATH);
    let logs = std::fs::read_to_string(&log_path)
        .map_err(|e| format!("reading node log {}: {e}", log_path.display()))?;
    let redacted_logs = !logs.contains(CANARY);
    if !redacted_logs {
        return Err(format!(
            "REDaction failure: canary present in {} — prompts must never reach log sinks",
            log_path.display()
        ));
    }

    Ok(SelfTestReport {
        tokens,
        port: report_port,
        redacted_logs,
        installation_id,
    })
}
