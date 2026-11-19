//! 9.6 PASS-2 loopback experiment (ADR-031 §5 "next consumer"; the
//! repeat/P50 protocol the spike's single-run numbers deferred).
//!
//! Three arms, same pinned engine + model + starting prefix, same target
//! token count, greedy (exactness asserted every run):
//!
//! - **B1 `single-http`** — the production fastest-single path TODAY: one
//!   completion streamed via sequential per-token HTTP steps (each POST
//!   re-posts the whole prefix). This is the comparator M10's exit rule
//!   names.
//! - **B2 `wire-spec-http`** — the same speculative PROTOCOL as the capi
//!   arm, but every propose/verify step is a per-position HTTP POST (the
//!   pass-1 wire shape; the ADR-032 §4 structural reason it falls back).
//! - **A `spec-capi`** — propose k one-token in-context decodes + ONE
//!   batched verify decode per round, in-process (ADR-031 linear verify).
//!
//! Protocol per cell: window k ∈ {4, 8, 16, 32}; N runs (default 30,
//! `MSP_PASS2_RUNS`); target 32 output tokens per run (`MSP_PASS2_TARGET`);
//! one discarded warmup run per cell; per-run elapsed per arm; P50/P95/
//! min/max reported; acceptance rate recorded. Headline = P50(B1)/P50(A)
//! — "does in-process speculative cooperation beat the fastest single".
//!
//! Gate (owner-local): `MSP_LLAMA_SERVER` + `MSP_REAL_GGUF` (+ optional
//! `MSP_CAPI_ENGINE_DIR`), `cargo test -p modelswarm-runtime --features
//! capi-adapter --test capi_pass2 -- --ignored --nocapture`.
//! Resilience (run-5 lesson, 2026-10-19): one llama-server per cell,
//! server stderr to `server-w<k>-<stamp>.log`, every completed run
//! appended to `pass2-runs-<stamp>.jsonl` immediately; set
//! `MSP_PASS2_RESUME=<that jsonl>` to skip completed runs and fold their
//! timings into the aggregates after a crash.
//! Environment label: single machine, loopback, dev-session load — NOT
//! LAN, NOT a product claim. Whatever the numbers say is the result.
#![cfg(feature = "capi-adapter")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use modelswarm_runtime::capi::{CapiConfig, LlamaCppCapi};
use modelswarm_runtime::llamacpp::{EngineIdentity, LlamaCppAdapter, LlamaCppConfig};
use modelswarm_runtime::{InferenceRuntime, SamplingParams};

const FILLER: &str = "The swarm serves one exact profile per cohort and every peer verifies the artifact digest before hosting. ";
const N_CTX: u32 = 4096;

fn sha256_of(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("read file for hashing");
    let digest = Sha256::digest(&bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn find_repo_root() -> PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    loop {
        if dir.join("runtime-pins.json").is_file() {
            return dir;
        }
        dir = dir.parent().expect("repo root reached").to_path_buf();
    }
}

fn load_pins() -> (String, String) {
    let root = find_repo_root();
    let raw = std::fs::read_to_string(root.join("runtime-pins.json")).expect("runtime-pins.json");
    let pins: serde_json::Value = serde_json::from_str(&raw).expect("pins parse");
    let platform = &pins["platforms"]["windows-x64"];
    for file in ["llama-server.exe", "llama.dll", "ggml.dll", "ggml-base.dll"] {
        let expected = platform["files"][file]
            .as_str()
            .unwrap_or_else(|| panic!("pins entry for {file}"));
        let engine_dir = std::env::var("MSP_CAPI_ENGINE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(std::env::var("MSP_LLAMA_SERVER").expect("MSP_LLAMA_SERVER"))
                    .parent()
                    .expect("engine dir")
                    .to_path_buf()
            });
        assert_eq!(
            sha256_of(&engine_dir.join(file)),
            expected,
            "sha256 mismatch for {file} — refusing to experiment on an unpinned engine"
        );
    }
    (
        pins["tag"].as_str().expect("tag").to_string(),
        pins["canonical_build_hash"]
            .as_str()
            .expect("canonical_build_hash")
            .to_string(),
    )
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn spawn_server(exe: &Path, model: &Path, port: u16, bearer: &str, log: &Path) -> Child {
    let mut command = Command::new(exe);
    command
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "-m",
            &model.display().to_string(),
            "-c",
            &N_CTX.to_string(),
            "--no-webui",
            "--api-key",
            bearer,
        ])
        .stdout(Stdio::null())
        // stderr to a file, never discarded: when a server dies mid-cell
        // (run 5, 2026-10-19: one shared server for all 124 runs went
        // unreachable at ~75 min) the panic must be able to name evidence.
        .stderr(
            std::fs::File::create(log)
                .unwrap_or_else(|e| panic!("create server log {}: {e}", log.display())),
        );
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    command.spawn().expect("spawn llama-server")
}

struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_healthy(base_url: &str, bearer: &str, timeout: Duration) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("client");
    let started = Instant::now();
    loop {
        assert!(started.elapsed() < timeout, "server never became healthy");
        let healthy = client
            .get(format!("{base_url}/health"))
            .bearer_auth(bearer)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if healthy {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn ms(elapsed: Duration) -> f64 {
    elapsed.as_secs_f64() * 1000.0
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

use serde::Serialize;

/// Unwrap an HTTP-arm step with the server's log path in the panic, so a
/// dead llama-server explains itself instead of leaving a bare reqwest error.
fn http_expect<T, E: std::fmt::Display>(r: Result<T, E>, step: &str, log: &Path) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{step} failed: {e} — llama-server log: {}", log.display()),
    }
}

/// One completed measurement run, appended to the session JSONL the moment
/// it finishes. A crash mid-protocol must never again discard the session's
/// samples (run 5 lost ~75 minutes by holding everything in memory).
#[derive(Serialize, serde::Deserialize)]
struct RunRecord {
    window: u32,
    run_idx: usize,
    want: usize,
    b1_ms: f64,
    b2_ms: f64,
    a_ms: f64,
    accepted: usize,
    proposed: usize,
}

/// Load prior per-run records for `MSP_PASS2_RESUME`: completed runs are
/// skipped and their timings re-seeded into the cell aggregates (the final
/// table then covers both sessions, environment-labeled in the report).
fn load_resume(path: &Path) -> std::collections::HashMap<u32, Vec<RunRecord>> {
    let mut map: std::collections::HashMap<u32, Vec<RunRecord>> = std::collections::HashMap::new();
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read resume file {}: {e}", path.display()));
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let rec: RunRecord = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("bad resume line in {}: {e}", path.display()));
        map.entry(rec.window).or_default().push(rec);
    }
    map
}

#[derive(Default, Serialize)]
struct CellRecord {
    window: u32,
    runs: usize,
    target_tokens: usize,
    single_http_ms: Vec<f64>,
    wire_spec_http_ms: Vec<f64>,
    spec_capi_ms: Vec<f64>,
    accepted_tokens: usize,
    proposed_tokens: usize,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "set MSP_LLAMA_SERVER and MSP_REAL_GGUF"]
async fn pass2_loopback_repeat_p50() {
    let exe = PathBuf::from(std::env::var("MSP_LLAMA_SERVER").expect("MSP_LLAMA_SERVER"));
    let model = PathBuf::from(std::env::var("MSP_REAL_GGUF").expect("MSP_REAL_GGUF"));
    let engine_dir = std::env::var("MSP_CAPI_ENGINE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| exe.parent().expect("engine dir").to_path_buf());
    let runs: usize = std::env::var("MSP_PASS2_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let target: usize = std::env::var("MSP_PASS2_TARGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);

    let (tag, build_hash) = load_pins();
    println!("=== 9.6 PASS-2 LOOPBACK (capi) ===");
    println!(
        "env: single machine, loopback, {} logical CPUs, dev-session load — NOT LAN, NOT a product claim",
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0)
    );
    println!("engine: pinned {tag} (canonical_build_hash {build_hash}), sha256-verified bundle");
    println!(
        "model: {} ({:.1} MiB), ctx {N_CTX}, greedy; protocol: runs={runs} (+1 warmup/cell), target={target} tokens/run",
        model.display(),
        std::fs::metadata(&model).expect("model stat").len() as f64 / (1024.0 * 1024.0)
    );

    // Artifact dir + stamp FIRST: per-run records append incrementally, so
    // a crash mid-protocol never discards the session's samples (run 5,
    // 2026-10-19: died at ~75 min holding every sample in memory).
    use std::io::Write as _;
    let out = std::path::Path::new("target/pass2-capi");
    std::fs::create_dir_all(out).expect("out dir");
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let run_log_path = out.join(format!("pass2-runs-{stamp}.jsonl"));
    let mut run_log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&run_log_path)
        .expect("run log open");

    // Optional resume: MSP_PASS2_RESUME=<jsonl> replays completed runs'
    // timings into the aggregates and skips their re-measurement.
    let resume: std::collections::HashMap<u32, Vec<RunRecord>> = std::env::var("MSP_PASS2_RESUME")
        .ok()
        .map(|p| load_resume(std::path::Path::new(&p)))
        .unwrap_or_default();
    if !resume.is_empty() {
        println!(
            "resume: {} prior run(s) loaded",
            resume.values().map(Vec::len).sum::<usize>()
        );
    }

    let bearer = "pass2-internal-secret";
    let identity = EngineIdentity {
        version: tag.clone(),
        build_hash: build_hash.clone(),
    };
    let vocab = {
        let metadata = modelswarm_types::read_metadata(&model).expect("gguf metadata");
        std::sync::Arc::new(modelswarm_types::token_vocab(&metadata).expect("gguf tokenizer vocab"))
    };
    let capi =
        LlamaCppCapi::new(CapiConfig::new(&engine_dir, &model).with_engine(identity.clone()))
            .expect("capi adapter constructs");
    let sampling = SamplingParams::default(); // greedy on both adapters

    let mut all_cells: Vec<CellRecord> = Vec::new();
    for window in [4u32, 8, 16, 32] {
        // One llama-server PER CELL (B1 + B2 arms): run 5's finding — a
        // single server shared by the whole 124-run protocol went
        // unreachable at ~75 min and took the session with it. Per-cell
        // respawn bounds any server-side degradation uniformly across
        // cells; each cell re-warms its fresh server before measuring.
        let port = free_port();
        let base_url = format!("http://127.0.0.1:{port}");
        let server_log = out.join(format!("server-w{window}-{stamp}.log"));
        let mut server = ServerGuard(spawn_server(&exe, &model, port, bearer, &server_log));
        wait_healthy(&base_url, bearer, Duration::from_secs(120)).await;

        let http = LlamaCppAdapter::new(LlamaCppConfig {
            base_url: base_url.clone(),
            bearer_token: bearer.to_string(),
            request_timeout: Duration::from_secs(120),
            engine: Some(identity.clone()),
            vocab: Some(vocab.clone()),
            // Research determinism: the verify pattern probes backward
            // relative to the slot's furthest state and the server's cached-
            // prefix reuse perturbs greedy output there (this experiment's
            // finding); every step recomputes from the posted prefix alone.
            // Labeled in the report: B1/B2 pay the full re-prefill per step
            // (the structural wire-re-post cost), production keeps the cache.
            no_prompt_cache: true,
        })
        .expect("http adapter constructs");
        let http_handle = http.load("msp1:pass2").await.expect("http load");

        // A base long prompt (the P1 measurement class, ~1200 tokens) —
        // rebuilt per cell so cells never share server state.
        let mut base_prompt = String::new();
        while http.tokenize(&base_prompt).await.unwrap().len() < 1200 {
            base_prompt.push_str(FILLER);
        }

        // Warm both engines for this cell (slot cache + reserved graphs).
        {
            let ids = http.tokenize(&base_prompt).await.unwrap();
            let _ = http
                .decode_stream(&http_handle, &ids, &sampling, 8, Duration::from_secs(60))
                .await
                .unwrap();
            let warm_handle = capi.load("msp1:pass2-warm").await.expect("capi warm load");
            let _ = capi
                .decode_stream(&warm_handle, &ids, &sampling, 8, Duration::from_secs(60))
                .await
                .unwrap();
        }

        let mut cell = CellRecord {
            window,
            runs,
            target_tokens: target,
            ..CellRecord::default()
        };
        if let Some(prior) = resume.get(&window) {
            for r in prior {
                cell.single_http_ms.push(r.b1_ms);
                cell.wire_spec_http_ms.push(r.b2_ms);
                cell.spec_capi_ms.push(r.a_ms);
                cell.accepted_tokens += r.accepted;
                cell.proposed_tokens += r.proposed;
            }
        }
        // Warmup run (discarded): same flow, results unused except to
        // prove it doesn't panic.
        for run_idx in 0..=runs {
            // Resume: completed measured runs replay from the JSONL; only
            // the warmup (run 0) always re-executes.
            if run_idx > 0
                && resume
                    .get(&window)
                    .is_some_and(|v| v.iter().any(|r| r.run_idx == run_idx))
            {
                continue;
            }
            // Decorrelate runs WITHOUT leaving the filler-continuation
            // regime: the "Run number N:" experiment found near-tie argmax
            // tokens (space/newline variants) that flip between compute
            // paths (full re-prefill vs incremental vs batched verify) —
            // bit-parity across engines is only holdable where the greedy
            // margin is wide, which the filler class is (the capi_loopback
            // 32-token parity + productionization pins prove it). Vary the
            // trailing filler count instead of the content.
            let prompt = format!("{base_prompt}{}", FILLER.repeat(run_idx % 7));
            let ids = http_expect(http.tokenize(&prompt).await, "tokenize", &server_log);
            // FRESH capi context per run (the experiment finding: reusing
            // one handle across runs whose prompt LENGTHS differ corrupts
            // the handle's KV sync — output drifts into degenerate loops.
            // Production sessions are fresh contexts too; per-handle cost
            // is documented KV RAM).
            let capi_handle = capi
                .load(&format!("msp1:pass2-w{window}-r{run_idx}"))
                .await
                .expect("capi per-run load");

            // ---- B1: single-http (production fastest-single) -----------
            // A REAL completion stops at eos (propose does; production
            // streams do) — the truth generator must too, or the
            // speculative arms' eos-terminated commits can never match it.
            let eos = capi.eos_id();
            let b1_started = Instant::now();
            let mut truth: Vec<u32> = Vec::with_capacity(target);
            let mut p = ids.clone();
            for _ in 0..target {
                let t = http_expect(
                    http.decode_step(&http_handle, &p, &sampling).await,
                    "B1 decode_step",
                    &server_log,
                );
                if Some(t) == eos {
                    break;
                }
                truth.push(t);
                p.push(t);
            }
            let b1_ms = ms(b1_started.elapsed());
            let want = truth.len();
            assert!(
                want > 0,
                "run {run_idx}: greedy truth is empty (immediate eos)"
            );

            // ---- B2: wire-spec-http (pass-1 protocol over HTTP) --------
            let b2_started = Instant::now();
            let mut committed: Vec<u32> = Vec::with_capacity(want);
            let mut prefix = ids.clone();
            let mut trace: Vec<(Vec<u32>, usize, u32)> = Vec::new(); // (draft, accepted, next)
            while committed.len() < want {
                let draft = http_expect(
                    http.propose(&http_handle, &prefix, window).await,
                    "B2 propose",
                    &server_log,
                );
                let mut accepted = 0usize;
                for (i, draft_token) in draft.iter().enumerate() {
                    let mut vp = prefix.clone();
                    vp.extend_from_slice(&draft[..i]);
                    let verifier_token = http_expect(
                        http.decode_step(&http_handle, &vp, &sampling).await,
                        "B2 verify decode_step",
                        &server_log,
                    );
                    if verifier_token == *draft_token {
                        accepted += 1;
                    } else {
                        break;
                    }
                }
                // The correction/bonus token (the verifier's own next
                // token at the commit point) commits with the accepted
                // prefix — full or partial acceptance alike.
                let mut vp = prefix.clone();
                vp.extend_from_slice(&draft[..accepted]);
                let next = http_expect(
                    http.decode_step(&http_handle, &vp, &sampling).await,
                    "B2 commit decode_step",
                    &server_log,
                );
                trace.push((draft.clone(), accepted, next));
                committed.extend_from_slice(&draft[..accepted]);
                committed.push(next);
                prefix = ids.clone();
                prefix.extend_from_slice(&committed);
                if committed.len() > want {
                    committed.truncate(want);
                }
            }
            let b2_ms = ms(b2_started.elapsed());
            let mismatch = committed.iter().zip(truth.iter()).position(|(a, b)| a != b);
            assert!(
                mismatch.is_none(),
                "B2 wire-spec mismatch at {mismatch:?} (run {run_idx}, window {window}):\n\
                 committed {:?}\ntruth      {:?}\ntrace      {trace:?}",
                &committed[..want.min(16)],
                &truth[..want.min(16)],
            );

            // ---- A: spec-capi (in-process linear verify) ---------------
            let a_started = Instant::now();
            let mut acom: Vec<u32> = Vec::with_capacity(want);
            let mut aprefix = ids.clone();
            let mut run_accepted = 0usize;
            let mut run_proposed = 0usize;
            while acom.len() < want {
                let draft = capi.propose(&capi_handle, &aprefix, window).await.unwrap();
                run_proposed += draft.len();
                cell.proposed_tokens += draft.len();
                let outcome = capi
                    .verify_drafts(&capi_handle, &aprefix, &draft, &sampling)
                    .await
                    .unwrap();
                run_accepted += outcome.accepted.len();
                cell.accepted_tokens += outcome.accepted.len();
                acom.extend_from_slice(&outcome.accepted);
                if let Some(bonus) = outcome.bonus {
                    acom.push(bonus);
                }
                aprefix = ids.clone();
                aprefix.extend_from_slice(&acom);
                if acom.len() > want {
                    acom.truncate(want);
                }
            }
            let a_ms = ms(a_started.elapsed());
            assert_eq!(
                acom.as_slice(),
                &truth[..acom.len().min(want)],
                "A spec-capi must match the greedy truth (bit-parity run {run_idx}, window {window})"
            );

            if run_idx > 0 {
                cell.single_http_ms.push(b1_ms);
                cell.wire_spec_http_ms.push(b2_ms);
                cell.spec_capi_ms.push(a_ms);
                // Durable the moment the run completes: a crash in a later
                // run loses nothing (run-5 lesson).
                writeln!(
                    run_log,
                    "{}",
                    serde_json::to_string(&RunRecord {
                        window,
                        run_idx,
                        want,
                        b1_ms,
                        b2_ms,
                        a_ms,
                        accepted: run_accepted,
                        proposed: run_proposed,
                    })
                    .unwrap()
                )
                .expect("append run record");
            }
        }
        // The server must have outlived the cell — a mid-cell exit is a
        // finding, not a flake; the log file carries the evidence.
        if let Some(status) = server.0.try_wait().expect("server try_wait") {
            panic!(
                "llama-server exited mid-cell (window {window}): {status} — log: {}",
                server_log.display()
            );
        }
        drop(server);
        all_cells.push(cell);
    }

    // ---- Report ------------------------------------------------------------
    println!("\n| window | B1 single-http P50 | B2 wire-spec P50 | A spec-capi P50 | P95(A) | accept | B1/A P50 | B2/A P50 |");
    println!("|---|---|---|---|---|---|---|---|");
    let mut json_cells = Vec::new();
    for cell in &all_cells {
        let mut b1 = cell.single_http_ms.clone();
        let mut b2 = cell.wire_spec_http_ms.clone();
        let mut a = cell.spec_capi_ms.clone();
        b1.sort_by(|x, y| x.partial_cmp(y).unwrap());
        b2.sort_by(|x, y| x.partial_cmp(y).unwrap());
        a.sort_by(|x, y| x.partial_cmp(y).unwrap());
        let p = |v: &[f64], q: f64| format!("{:.1}", percentile(v, q));
        let accept = cell.accepted_tokens as f64 / cell.proposed_tokens.max(1) as f64;
        let ratio_b1 = percentile(&b1, 0.5) / percentile(&a, 0.5);
        let ratio_b2 = percentile(&b2, 0.5) / percentile(&a, 0.5);
        println!(
            "| k={} | {} ms | {} ms | {} ms | {} | {:.1}% | {:.2}x | {:.2}x |",
            cell.window,
            p(&b1, 0.5),
            p(&b2, 0.5),
            p(&a, 0.5),
            p(&a, 0.95),
            accept * 100.0,
            ratio_b1,
            ratio_b2,
        );
        json_cells.push(serde_json::to_value(cell).unwrap());
    }
    let artifact = out.join(format!("pass2-capi-{stamp}.json"));
    std::fs::write(
        &artifact,
        serde_json::to_string_pretty(&serde_json::json!({
            "experiment": "9.6-pass2-loopback-capi",
            "environment": "single-machine loopback, Windows x64, dev-session load — NOT LAN, NOT a product claim",
            "engine_tag": tag,
            "runs_per_cell": runs,
            "target_tokens": target,
            "run_log": run_log_path.display().to_string(),
            "cells": json_cells,
        }))
        .unwrap(),
    )
    .expect("write artifact");
    println!("\nartifact: {}", artifact.display());
    println!("run log:  {}", run_log_path.display());
    println!("exactness: every run, every window — both speculative arms token-for-token == the greedy truth");
}
