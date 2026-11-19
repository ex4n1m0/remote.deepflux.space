//! ADR-045 P2 — the PRE-REGISTERED Balanced fallback property test
//! (experiments/reports/P2-BALANCED-FALLBACK-PROTOCOL.md, T/R R5).
//!
//! Arms per pair, SAME pinned engine + model + prompt:
//! - **B (the Fast baseline)** — the production local path shape: one
//!   sequential per-token completion over llama-server HTTP
//!   (`no_prompt_cache: true`, the determinism requirement — labeled in
//!   the report: B pays the full re-prefill per step, production keeps
//!   the cache, so this is the WORST case for B, biasing the test
//!   AGAINST the composed arm winning).
//! - **A (the composed path)** — try_composed_chat's loop shape: greedy
//!   window draft + ONE batched capi verify per round, committed stream.
//!
//! Protocol (registered BEFORE any data, 2026-10-20): interleaved
//! A/B order per run; >= 60 paired turns total across >= 3 prompt
//! regimes (the filler continuation class + two real-prompt classes);
//! greedy only; per-pair token-for-token exactness (the lossless
//! precondition — a non-exact pair is excluded from the bounds and
//! recorded, coverage reported); VERDICT = PASS when pooled P50(A) <=
//! P50(B) x 1.05 AND P95(A) <= P95(B) x 1.15 — else BREACH (engagement
//! ships DISABLED, the negative published as visibly as a win). Either
//! bound failure = BREACH. Coverage < 90% exact pairs = INCONCLUSIVE
//! (regimes must be re-picked, never force-counted).
//!
//! The harness NEVER flips composed_unlock itself: a PASS authorizes
//! the Integrator/owner to flip the persisted unlock (the registered
//! path); BREACH keeps it false. Owner-local gate:
//! `MSP_LLAMA_SERVER` + `MSP_REAL_GGUF` (+ `MSP_CAPI_ENGINE_DIR`),
//! `cargo test -p modelswarm-runtime --features capi-adapter --test
//! composed_ab -- --ignored --nocapture`. Durability: per-pair JSONL,
//! `MSP_AB_RESUME` replays; per-regime-cell llama-server with stderr
//! to file (the pass-2 F4 pattern). Environment label: single machine,
//! loopback, dev-session load — NOT LAN, NOT a product claim.
#![cfg(feature = "capi-adapter")]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use modelswarm_runtime::capi::{CapiConfig, LlamaCppCapi};
use modelswarm_runtime::llamacpp::{EngineIdentity, LlamaCppAdapter, LlamaCppConfig};
use modelswarm_runtime::{InferenceRuntime, SamplingParams};

const FILLER: &str = "The swarm serves one exact profile per cohort and every peer verifies the artifact digest before hosting. ";
const N_CTX: u32 = 4096;

const REGIME_TAILS: [&str; 3] = [
    "", // regime 0: pure filler continuation (the proven-stable class)
    "List the first twelve prime numbers, one per line.",
    "Describe what cooperative inference means in three short sentences.",
];

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

fn http_expect<T, E: std::fmt::Display>(r: Result<T, E>, step: &str, log: &Path) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{step} failed: {e} — llama-server log: {}", log.display()),
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PairRecord {
    run_idx: usize,
    regime: usize,
    order_a_first: bool,
    exact: bool,
    tokens: usize,
    b_ms: f64,
    a_ms: f64,
}

fn load_resume(path: &Path) -> Vec<PairRecord> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read resume file {}: {e}", path.display()));
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("bad resume line in {}: {e}", path.display()))
        })
        .collect()
}

fn load_pins() -> (String, String) {
    // Mirror of capi_pass2's pin loader: runtime-pins.json at the repo
    // root, the pinned llama.cpp tag + canonical build hash.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../");
    let pins: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("runtime-pins.json")).expect("runtime-pins.json"),
    )
    .expect("pins json");
    let platforms = pins["platforms"].as_object().expect("platforms");
    let win = platforms
        .get("windows-x86_64")
        .or_else(|| platforms.values().next())
        .expect("a platform row");
    (
        win["tag"].as_str().unwrap_or("unknown").to_string(),
        win["canonical_build_hash"]
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
    )
}

async fn plain_decode(
    http: &LlamaCppAdapter,
    handle: &modelswarm_runtime::Handle,
    ids: &[u32],
    eos: Option<u32>,
    target: usize,
    sampling: &SamplingParams,
    log: &Path,
) -> Vec<u32> {
    let mut truth: Vec<u32> = Vec::with_capacity(target);
    let mut p = ids.to_vec();
    for _ in 0..target {
        let t = http_expect(
            http.decode_step(handle, &p, sampling).await,
            "B decode_step",
            log,
        );
        if Some(t) == eos {
            break;
        }
        truth.push(t);
        p.push(t);
    }
    truth
}

async fn composed_decode(
    capi: &LlamaCppCapi,
    handle: &modelswarm_runtime::Handle,
    ids: &[u32],
    target: usize,
    window: u32,
    sampling: &SamplingParams,
) -> Vec<u32> {
    let mut committed: Vec<u32> = Vec::with_capacity(target);
    while committed.len() < target {
        let mut prefix = ids.to_vec();
        prefix.extend_from_slice(&committed);
        let draft = capi.propose(handle, &prefix, window).await.unwrap();
        if draft.is_empty() {
            break; // EOS in the draft: an honest short reply
        }
        let outcome = capi
            .verify_drafts(handle, &prefix, &draft, sampling)
            .await
            .unwrap();
        committed.extend_from_slice(&outcome.accepted);
        if let Some(bonus) = outcome.bonus {
            committed.push(bonus);
        }
        if committed.len() > target {
            committed.truncate(target);
        }
    }
    committed
}

#[ignore = "set MSP_LLAMA_SERVER and MSP_REAL_GGUF"]
#[tokio::test]
async fn composed_ab_registered_bounds() {
    let exe = PathBuf::from(std::env::var("MSP_LLAMA_SERVER").expect("MSP_LLAMA_SERVER"));
    let model = PathBuf::from(std::env::var("MSP_REAL_GGUF").expect("MSP_REAL_GGUF"));
    let engine_dir = std::env::var("MSP_CAPI_ENGINE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| exe.parent().expect("engine dir").to_path_buf());
    let runs: usize = std::env::var("MSP_AB_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    assert!(
        runs >= 60,
        "the pre-registration requires >= 60 paired turns"
    );
    let target: usize = std::env::var("MSP_AB_TARGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);
    let window: u32 = std::env::var("MSP_AB_WINDOW")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);

    let (tag, build_hash) = load_pins();
    println!("=== ADR-045 P2 A/B — the pre-registered Balanced fallback bounds ===");
    println!(
        "env: single machine, loopback, {} logical CPUs, dev-session load — NOT LAN, NOT a product claim",
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0)
    );
    println!("engine: pinned {tag} (canonical_build_hash {build_hash}), sha256-verified bundle");
    println!(
        "model: {} ({:.1} MiB), ctx {N_CTX}, greedy; pairs={runs} (>=60 registered), window={window}, target={target} tokens",
        model.display(),
        std::fs::metadata(&model).expect("model stat").len() as f64 / (1024.0 * 1024.0)
    );
    println!(
        "registered bounds (2026-10-20, pre-data): P50(A) <= P50(B) x1.05 AND P95(A) <= P95(B) x1.15; either breach = BREACH; coverage < 90% exact = INCONCLUSIVE"
    );

    let out = std::path::Path::new("target/ab-registered");
    std::fs::create_dir_all(out).expect("out dir");
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let log_path = out.join(format!("ab-pairs-{stamp}.jsonl"));
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("pair log open");

    let resume: Vec<PairRecord> = std::env::var("MSP_AB_RESUME")
        .ok()
        .map(|p| load_resume(std::path::Path::new(&p)))
        .unwrap_or_default();
    let mut records: Vec<PairRecord> = resume.iter().filter(|r| r.exact).cloned().collect();
    let mut total_pairs = resume.len();
    if !resume.is_empty() {
        println!("resume: {} prior pair(s) loaded", resume.len());
    }

    let bearer = "ab-internal-secret";
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
    let sampling = SamplingParams::default(); // greedy on both arms

    // One llama-server PER REGIME CELL (the pass-2 F4 pattern): a dying
    // server costs one cell, every cell starts fresh.
    for (regime, _tail) in REGIME_TAILS.iter().enumerate() {
        let port = free_port();
        let base_url = format!("http://127.0.0.1:{port}");
        let server_log = out.join(format!("ab-server-r{regime}-{stamp}.log"));
        let mut server = ServerGuard(spawn_server(&exe, &model, port, bearer, &server_log));
        wait_healthy(&base_url, bearer, Duration::from_secs(120)).await;

        let http = LlamaCppAdapter::new(LlamaCppConfig {
            base_url: base_url.clone(),
            bearer_token: bearer.to_string(),
            request_timeout: Duration::from_secs(120),
            engine: Some(identity.clone()),
            vocab: Some(vocab.clone()),
            no_prompt_cache: true, // the pass-2 determinism requirement (F2)
        })
        .expect("http adapter constructs");
        let http_handle = http.load("msp1:ab").await.expect("http load");

        // The regime base: ~1200 filler tokens (the proven-stable greedy
        // class) + the regime tail (F3: exactness only holdable in
        // wide-margin regimes; the filler anchor provides it).
        let mut base_prompt = String::new();
        while http.tokenize(&base_prompt).await.unwrap().len() < 1200 {
            base_prompt.push_str(FILLER);
        }
        let base_prompt = format!("{base_prompt}{}", REGIME_TAILS[regime]);

        // Warm both engines for this cell.
        {
            let ids = http.tokenize(&base_prompt).await.unwrap();
            let _ = http
                .decode_stream(&http_handle, &ids, &sampling, 8, Duration::from_secs(60))
                .await
                .unwrap();
            let warm = capi.load("msp1:ab-warm").await.expect("capi warm load");
            let _ = capi
                .decode_stream(&warm, &ids, &sampling, 8, Duration::from_secs(60))
                .await
                .unwrap();
        }

        for regime_run in 0..runs / REGIME_TAILS.len() {
            let run_idx = regime * (runs / REGIME_TAILS.len()) + regime_run;
            if resume.iter().any(|r| r.run_idx == run_idx) {
                continue;
            }
            // Decorrelate within the regime the pass-2 way (F3): vary the
            // trailing filler count, never the content.
            let prompt = format!("{base_prompt}{}", FILLER.repeat(regime_run % 7));
            let ids = http_expect(http.tokenize(&prompt).await, "tokenize", &server_log);
            // FRESH capi context per pair (the pass-2 F2 KV hazard).
            let capi_handle = capi
                .load(&format!("msp1:ab-r{regime}-p{run_idx}"))
                .await
                .expect("capi per-pair load");
            let eos = capi.eos_id();

            // Interleaved order: even pairs B→A, odd pairs A→B.
            let a_first = run_idx % 2 == 1;
            let b_timed;
            let a_timed;
            let truth;
            if a_first {
                let a0 = Instant::now();
                let ac =
                    composed_decode(&capi, &capi_handle, &ids, target, window, &sampling).await;
                a_timed = ms(a0.elapsed());
                let b0 = Instant::now();
                truth = plain_decode(
                    &http,
                    &http_handle,
                    &ids,
                    eos,
                    target,
                    &sampling,
                    &server_log,
                )
                .await;
                b_timed = ms(b0.elapsed());
                let exact = ac == truth;
                if !exact {
                    eprintln!(
                        "pair {run_idx}: exactness FAILED (regime {regime}); composed {:?} vs plain {:?}",
                        &ac[..ac.len().min(16)],
                        &truth[..truth.len().min(16)]
                    );
                }
                append_pair(
                    &mut log,
                    &log_path,
                    PairRecord {
                        run_idx,
                        regime,
                        order_a_first: true,
                        exact,
                        tokens: truth.len(),
                        b_ms: b_timed,
                        a_ms: a_timed,
                    },
                );
                total_pairs += 1;
                if exact {
                    records.push(PairRecord {
                        run_idx,
                        regime,
                        order_a_first: true,
                        exact,
                        tokens: truth.len(),
                        b_ms: b_timed,
                        a_ms: a_timed,
                    });
                }
            } else {
                let b0 = Instant::now();
                truth = plain_decode(
                    &http,
                    &http_handle,
                    &ids,
                    eos,
                    target,
                    &sampling,
                    &server_log,
                )
                .await;
                b_timed = ms(b0.elapsed());
                let a0 = Instant::now();
                let ac =
                    composed_decode(&capi, &capi_handle, &ids, target, window, &sampling).await;
                a_timed = ms(a0.elapsed());
                let exact = ac == truth;
                if !exact {
                    eprintln!(
                        "pair {run_idx}: exactness FAILED (regime {regime}); composed {:?} vs plain {:?}",
                        &ac[..ac.len().min(16)],
                        &truth[..truth.len().min(16)]
                    );
                }
                append_pair(
                    &mut log,
                    &log_path,
                    PairRecord {
                        run_idx,
                        regime,
                        order_a_first: false,
                        exact,
                        tokens: truth.len(),
                        b_ms: b_timed,
                        a_ms: a_timed,
                    },
                );
                total_pairs += 1;
                if exact {
                    records.push(PairRecord {
                        run_idx,
                        regime,
                        order_a_first: false,
                        exact,
                        tokens: truth.len(),
                        b_ms: b_timed,
                        a_ms: a_timed,
                    });
                }
            }
            println!(
                "pair {run_idx} (regime {regime}, {} first): B {b_timed:.0} ms | A {a_timed:.0} ms",
                if a_first { "A" } else { "B" }
            );
        }

        if let Some(status) = server.0.try_wait().expect("server try_wait") {
            panic!(
                "llama-server exited mid-cell (regime {regime}): {status} — log: {}",
                server_log.display()
            );
        }
        drop(server);
    }

    // ---- the registered verdict --------------------------------------
    let mut bs: Vec<f64> = records.iter().map(|r| r.b_ms).collect();
    let mut as_: Vec<f64> = records.iter().map(|r| r.a_ms).collect();
    bs.sort_by(|x, y| x.partial_cmp(y).unwrap());
    as_.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let p50b = percentile(&bs, 0.5);
    let p50a = percentile(&as_, 0.5);
    let p95b = percentile(&bs, 0.95);
    let p95a = percentile(&as_, 0.95);
    let exact_pairs = records.len();
    let coverage = exact_pairs as f64 / total_pairs.max(1) as f64;

    println!("\n| regime | pairs | B P50 | B P95 | A P50 | A P95 | A/B P50 | A/B P95 |");
    println!("|---|---|---|---|---|---|---|---|");
    for regime in 0..REGIME_TAILS.len() {
        let rs: Vec<&PairRecord> = records.iter().filter(|r| r.regime == regime).collect();
        let mut rb: Vec<f64> = rs.iter().map(|r| r.b_ms).collect();
        let mut ra: Vec<f64> = rs.iter().map(|r| r.a_ms).collect();
        rb.sort_by(|x, y| x.partial_cmp(y).unwrap());
        ra.sort_by(|x, y| x.partial_cmp(y).unwrap());
        if rb.is_empty() {
            println!("| {regime} | {} | — | — | — | — | — | — |", rs.len());
            continue;
        }
        println!(
            "| {regime} | {} | {:.0} | {:.0} | {:.0} | {:.0} | {:.2}x | {:.2}x |",
            rs.len(),
            percentile(&rb, 0.5),
            percentile(&rb, 0.95),
            percentile(&ra, 0.5),
            percentile(&ra, 0.95),
            percentile(&ra, 0.5) / percentile(&rb, 0.5),
            percentile(&ra, 0.95) / percentile(&rb, 0.95),
        );
    }

    let verdict = if coverage < 0.90 {
        "INCONCLUSIVE"
    } else if p50a <= p50b * 1.05 && p95a <= p95b * 1.15 {
        "PASS"
    } else {
        "BREACH"
    };
    let artifact = out.join(format!("ab-verdict-{stamp}.json"));
    serde_json::to_writer_pretty(
        std::fs::File::create(&artifact).expect("artifact"),
        &serde_json::json!({
            "experiment": "adr-045-p2-balanced-ab",
            "registered_bounds": { "p50": 1.05, "p95": 1.15 },
            "environment": "single-machine loopback, Windows x64, dev-session load — NOT LAN, NOT a product claim",
            "engine_tag": tag,
            "pairs_total": total_pairs,
            "pairs_exact": exact_pairs,
            "coverage": coverage,
            "pooled": { "b_p50_ms": p50b, "b_p95_ms": p95b, "a_p50_ms": p50a, "a_p95_ms": p95a,
                        "a_over_b_p50": p50a / p50b, "a_over_b_p95": p95a / p95b },
            "verdict": verdict,
        }),
    )
    .expect("write artifact");
    println!(
        "\nPOOLED: B P50 {p50b:.0} ms / P95 {p95b:.0} ms | A P50 {p50a:.0} ms / P95 {p95a:.0} ms"
    );
    println!(
        "BOUNDS: A/B P50 = {:.3} (<= 1.05 registered) | A/B P95 = {:.3} (<= 1.15 registered) | coverage {:.1}% (>= 90%)",
        p50a / p50b,
        p95a / p95b,
        coverage * 100.0
    );
    println!("VERDICT: {verdict} — artifact: {}", artifact.display());
    if verdict == "BREACH" {
        println!("NEGATIVE RESULT: the composed engagement ships DISABLED (composed_unlock stays false) and this breach is published as visibly as a win.");
    } else if verdict == "PASS" {
        println!("PASS: the unlock flip is AUTHORIZED (the Integrator/owner writes composed_unlock=true; the harness itself never flips it).");
    }
}

fn append_pair(log: &mut std::fs::File, path: &Path, record: PairRecord) {
    writeln!(log, "{}", serde_json::to_string(&record).unwrap())
        .unwrap_or_else(|e| panic!("append pair to {}: {e}", path.display()));
}
