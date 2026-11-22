//! ADR-031 §5.1 shape-stability measurement: per-call wall time over a FIXED
//! call sequence, designed for before/after comparison across the
//! productionization change (pooled batch + pinned output reservation +
//! load-time warmup). No assertions on timings — this is a measurement
//! record, environment-labeled (single machine, load-sensitive). The only
//! asserted properties are behavioral invariants that must hold on every
//! build (greedy self-agreement of verify outcomes across repeats).
//!
//! Gate: `cargo test -p modelswarm-runtime --features capi-adapter
//! --test capi_batching -- --ignored --nocapture` with
//! `MSP_CAPI_ENGINE_DIR` (hash-verified engine bundle) and `MSP_REAL_GGUF`
//! (verified GGUF) set. Defaults `MSP_CAPI_ENGINE_DIR` to the parent of
//! `MSP_LLAMA_SERVER` when only that is set (loopback-test symmetry).
//!
//! Method (why these phases): the P16 spike attributed a ~10–13 ms
//! `graph_reserve`-class cost to ALTERNATING batch shapes, but its printed
//! baseline for the cheap rounds was a delta-0 sync — a NO-OP — so the
//! comparison mixed compute against no-op. This test separates the effects:
//! steady-state phases measure each shape in isolation (shape-stable call
//! sequences), the interleave phase measures the SAME shapes alternating,
//! and the delta-0 phase pins the pure bookkeeping floor. Shape churn, if
//! real, shows up as (interleave median − steady median) per shape class.
//! Discrimination phases: G removes the verify from the step→delta
//! alternation; H holds the batch shape FIXED and varies only the KV state
//! (fresh tail cells vs freed/rolled-back cells) — any H2−H1 gap is
//! KV-geometry cost, not batch-shape cost; F measures verify calls of
//! differing widths (the ADR-032 adaptive-window pattern) steady vs
//! alternating.
#![cfg(feature = "capi-adapter")]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use modelswarm_runtime::capi::{CapiConfig, LlamaCppCapi};
use modelswarm_runtime::llamacpp::EngineIdentity;
use modelswarm_runtime::{InferenceRuntime, SamplingParams};

const FILLER: &str = "The swarm serves one exact profile per cohort and every peer verifies the artifact digest before hosting. ";
const N_CTX: u32 = 4096;
/// Repetitions per steady-state phase (medians need a sane sample).
const STEADY_REPS: usize = 20;
/// Interleave cycles of {step, +3 prefill, verify}.
const INTERLEAVE_CYCLES: usize = 10;

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

/// Verifies the bundle files this test loads against `runtime-pins.json`
/// (refuses to measure against an unpinned engine).
fn verify_pinned_windows_files(dir: &Path) -> (String, String) {
    let root = find_repo_root();
    let raw = std::fs::read_to_string(root.join("runtime-pins.json")).expect("runtime-pins.json");
    let pins: serde_json::Value = serde_json::from_str(&raw).expect("pins parse");
    let files = pins["platforms"]["windows-x64"]["files"]
        .as_object()
        .expect("windows-x64 files");
    for file in ["llama.dll", "ggml.dll", "ggml-base.dll"] {
        let expected = files[file]
            .as_str()
            .unwrap_or_else(|| panic!("no pin for {file}"));
        assert_eq!(
            sha256_of(&dir.join(file)),
            expected,
            "sha256 mismatch for {file} — refusing to measure an unpinned engine"
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

fn ms(elapsed: Duration) -> f64 {
    elapsed.as_secs_f64() * 1000.0
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    sorted[sorted.len() / 2]
}

fn p90(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    sorted[(sorted.len() as f64 * 0.9) as usize % sorted.len()]
}

fn report(name: &str, values: &[f64]) {
    println!(
        "{name:<38} n={:<3} median {:>8.3} ms  p90 {:>8.3} ms  min {:>8.3} ms  max {:>8.3} ms",
        values.len(),
        median(values),
        p90(values),
        values.iter().copied().fold(f64::INFINITY, f64::min),
        values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "set MSP_CAPI_ENGINE_DIR (or MSP_LLAMA_SERVER) and MSP_REAL_GGUF"]
async fn capi_batch_shape_stability_measurements() {
    let engine_dir =
        std::env::var("MSP_CAPI_ENGINE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(std::env::var("MSP_LLAMA_SERVER").expect(
                    "MSP_CAPI_ENGINE_DIR (engine bundle) or MSP_LLAMA_SERVER (to derive it)",
                ))
                .parent()
                .expect("engine dir")
                .to_path_buf()
            });
    let model = PathBuf::from(std::env::var("MSP_REAL_GGUF").expect("MSP_REAL_GGUF"));

    let (tag, build_hash) = verify_pinned_windows_files(&engine_dir);
    println!("env: single-machine, Windows x64; engine pinned {tag} (canonical_build_hash {build_hash}); NOT LAN, NOT a product claim");
    println!(
        "model: {} ({:.1} MiB), ctx {N_CTX}, greedy",
        model.display(),
        std::fs::metadata(&model).expect("model stat").len() as f64 / (1024.0 * 1024.0)
    );

    let capi = LlamaCppCapi::new(CapiConfig::new(&engine_dir, &model).with_engine(
        EngineIdentity {
            version: tag,
            build_hash,
        },
    ))
    .expect("capi adapter constructs");
    let handle = capi.load("msp1:batching").await.expect("load");

    // ~1217-token prompt class (same as the loopback A/B).
    let mut long_prompt = String::new();
    while capi.tokenize(&long_prompt).await.unwrap().len() < 1200 {
        long_prompt.push_str(FILLER);
    }
    let base: Vec<u32> = capi.tokenize(&long_prompt).await.unwrap();
    let sampling = SamplingParams::default(); // greedy on both paths

    // Initial prefill (the one large-shape call; happens once per session).
    {
        let started = Instant::now();
        capi.prefill(&handle, &base).await.expect("initial prefill");
        println!(
            "initial prefill ({} tokens, one call): {:.3} ms",
            base.len(),
            ms(started.elapsed())
        );
    }

    // A fixed draft + fixed verify prefix shared by every verify measurement
    // (greedy is deterministic, so the draft is stable across repeats).
    let verify_prefix = base.clone();
    let draft = capi
        .propose(&handle, &verify_prefix, 8)
        .await
        .expect("propose");
    assert_eq!(draft.len(), 8, "greedy self-draft fills the window");

    // Deterministic token pool consumed by the delta phases (generated once,
    // 1/1 stream shape, BEFORE any measured phase, so no phase interleaves
    // generation with its own measurements). Sums every consumer below:
    // A-skip 20 + B 60 + D/G/H1/H2/K 30 each, plus margin.
    const POOL_SKIP_A: usize = STEADY_REPS;
    const POOL_TOTAL: usize = POOL_SKIP_A + STEADY_REPS * 3 + INTERLEAVE_CYCLES * 3 * 5 + 8;
    let token_pool: Vec<u32> = capi
        .decode_stream(
            &handle,
            &base,
            &sampling,
            POOL_TOTAL as u32,
            Duration::from_secs(300),
        )
        .await
        .expect("token pool");
    assert!(
        token_pool.len() >= POOL_TOTAL - 8,
        "pool generation ended early (eos?) — shorten the phases"
    );

    // ---- phase A: steady 1-token/1-output steps -------------------------
    let mut step_ms = Vec::with_capacity(STEADY_REPS);
    let mut step_working = base.clone();
    for _ in 0..STEADY_REPS {
        let started = Instant::now();
        let token = capi
            .decode_step(&handle, &step_working, &sampling)
            .await
            .expect("step");
        step_ms.push(ms(started.elapsed()));
        step_working.push(token);
    }

    // ---- phase B: steady 3-token/0-output delta decodes ------------------
    // Skip the pool tokens phase A already pushed into the trail (greedy is
    // deterministic, so pool[0..STEADY_REPS] == phase A's own tokens) —
    // otherwise the early rounds are delta-0 no-ops instead of real 3/0
    // decodes (the spike's original confound, avoided on purpose here).
    let mut delta3_ms = Vec::with_capacity(STEADY_REPS);
    let mut delta_round = base.clone();
    let mut pool_b = token_pool.iter().skip(STEADY_REPS);
    for _ in 0..STEADY_REPS {
        let next: Vec<u32> = pool_b.by_ref().take(3).copied().collect();
        delta_round.extend_from_slice(&next);
        let started = Instant::now();
        capi.prefill(&handle, &delta_round).await.expect("delta");
        delta3_ms.push(ms(started.elapsed()));
    }

    // ---- phase C: steady 9-row/9-output verify passes --------------------
    let mut verify_ms = Vec::with_capacity(STEADY_REPS);
    let mut first_outcome = None;
    for _ in 0..STEADY_REPS {
        let started = Instant::now();
        let outcome = capi
            .verify_drafts(&handle, &verify_prefix, &draft, &sampling)
            .await
            .expect("verify");
        verify_ms.push(ms(started.elapsed()));
        if let Some(prev) = &first_outcome {
            assert_eq!(
                &outcome, prev,
                "repeated identical verify must be token-exact every time (greedy determinism)"
            );
        } else {
            first_outcome = Some(outcome);
        }
    }
    let steady_outcome = first_outcome.expect("at least one verify");

    // ---- phase D: interleaved shapes {1/1 step, 3/0 delta, 9/9 verify} ---
    let mut inter_step_ms = Vec::with_capacity(INTERLEAVE_CYCLES);
    let mut inter_delta_ms = Vec::with_capacity(INTERLEAVE_CYCLES);
    let mut inter_verify_ms = Vec::with_capacity(INTERLEAVE_CYCLES);
    let mut inter_working = base.clone();
    let mut inter_round = base.clone();
    let mut pool_d = token_pool.iter().skip(STEADY_REPS * 3);
    for _ in 0..INTERLEAVE_CYCLES {
        let started = Instant::now();
        let token = capi
            .decode_step(&handle, &inter_working, &sampling)
            .await
            .expect("step");
        inter_step_ms.push(ms(started.elapsed()));
        inter_working.push(token);

        let next: Vec<u32> = pool_d.by_ref().take(3).copied().collect();
        inter_round.extend_from_slice(&next);
        let started = Instant::now();
        capi.prefill(&handle, &inter_round).await.expect("delta");
        inter_delta_ms.push(ms(started.elapsed()));

        let started = Instant::now();
        let outcome = capi
            .verify_drafts(&handle, &verify_prefix, &draft, &sampling)
            .await
            .expect("verify");
        inter_verify_ms.push(ms(started.elapsed()));
        assert_eq!(outcome, steady_outcome, "interleaved verify stays exact");
    }

    // ---- phase E: delta-0 sync floor --------------------------------------
    let mut noop_ms = Vec::with_capacity(STEADY_REPS);
    for _ in 0..STEADY_REPS {
        let started = Instant::now();
        capi.prefill(&handle, &base).await.expect("noop sync");
        noop_ms.push(ms(started.elapsed()));
    }

    // ---- phase F: verify calls of DIFFERING widths -------------------------
    // The ADR-032 adaptive-window pattern: consecutive rounds verify windows
    // of different lengths (shapes 5/9/13/17 rows). F1 measures each width in
    // consecutive (shape-stable) blocks; F2 alternates the same widths in the
    // same cycle order. The difference per width is the verify shape-churn
    // term the productionization change targets.
    let widths: [(usize, u32); 4] = [(4, 5), (8, 9), (12, 13), (16, 17)];
    let mut drafts: Vec<(usize, Vec<u32>)> = Vec::with_capacity(widths.len());
    for (k, _) in &widths {
        let draft = capi
            .propose(&handle, &verify_prefix, *k as u32)
            .await
            .expect("propose width");
        drafts.push((*k, draft));
    }
    let mut f_steady: Vec<(usize, Vec<f64>)> = Vec::new();
    for (k, draft) in &drafts {
        let mut samples = Vec::with_capacity(5);
        for _ in 0..5 {
            let started = Instant::now();
            capi.verify_drafts(&handle, &verify_prefix, draft, &sampling)
                .await
                .expect("verify width steady");
            samples.push(ms(started.elapsed()));
        }
        f_steady.push((*k, samples));
    }
    let mut f_alternating: Vec<(usize, Vec<f64>)> = vec![
        (0, Vec::new()),
        (0, Vec::new()),
        (0, Vec::new()),
        (0, Vec::new()),
    ];
    for _ in 0..5 {
        for (index, (k, draft)) in drafts.iter().enumerate() {
            let started = Instant::now();
            let outcome = capi
                .verify_drafts(&handle, &verify_prefix, draft, &sampling)
                .await
                .expect("verify width alternating");
            let elapsed = ms(started.elapsed());
            f_alternating[index].0 = *k;
            f_alternating[index].1.push(elapsed);
            // Behavioral pin that must hold under every shape order.
            assert_eq!(
                outcome.accepted.as_slice(),
                &draft[..outcome.accepted.len()],
                "accepted must be a prefix of its own draft"
            );
        }
    }

    // ---- phase G: {step, delta} alternation WITHOUT verify ----------------
    // Discriminates whether the D delta penalty needs the interleaved verify
    // or only the step→delta shape transition.
    let mut g_step_ms = Vec::with_capacity(INTERLEAVE_CYCLES);
    let mut g_delta_ms = Vec::with_capacity(INTERLEAVE_CYCLES);
    let mut g_working = base.clone();
    let mut g_round = base.clone();
    let mut pool_g = token_pool
        .iter()
        .skip(STEADY_REPS + STEADY_REPS * 3 + INTERLEAVE_CYCLES * 3);
    for _ in 0..INTERLEAVE_CYCLES {
        let started = Instant::now();
        let token = capi
            .decode_step(&handle, &g_working, &sampling)
            .await
            .expect("g step");
        g_step_ms.push(ms(started.elapsed()));
        g_working.push(token);

        let next: Vec<u32> = pool_g.by_ref().take(3).copied().collect();
        g_round.extend_from_slice(&next);
        let started = Instant::now();
        capi.prefill(&handle, &g_round).await.expect("g delta");
        g_delta_ms.push(ms(started.elapsed()));
    }

    // ---- phase H: same-shape delta, fresh tail vs freed cells -------------
    // H1: consecutive +3 deltas on a monotonically growing round (every decode
    //     appends at the KV tail — no holes). Identical to B by construction.
    // H2: same +3 deltas, but each round first rolls the KV back 24 cells via
    //     a sync to a shorter prefix, so the delta decodes INTO freed cells
    //     (the hole-filling pattern every rollback-based verify round creates).
    // Same batch shape both phases: any H2−H1 gap is KV-geometry cost, not
    // batch-shape cost.
    let mut h_tail_ms = Vec::with_capacity(10);
    let mut h_round = base.clone();
    let mut pool_h = token_pool
        .iter()
        .skip(STEADY_REPS + STEADY_REPS * 3 + INTERLEAVE_CYCLES * 3 + INTERLEAVE_CYCLES * 3);
    for _ in 0..10 {
        let next: Vec<u32> = pool_h.by_ref().take(3).copied().collect();
        h_round.extend_from_slice(&next);
        let started = Instant::now();
        capi.prefill(&handle, &h_round).await.expect("h tail");
        h_tail_ms.push(ms(started.elapsed()));
    }
    let mut h_hole_ms = Vec::with_capacity(10);
    let mut pool_h2 = token_pool
        .iter()
        .skip(STEADY_REPS + STEADY_REPS * 3 + INTERLEAVE_CYCLES * 3 + INTERLEAVE_CYCLES * 3 + 30);
    // Anchor: a long trail with 30 spare tokens beyond `base`.
    let mut h_anchor = base.clone();
    h_anchor.extend_from_slice(&token_pool[STEADY_REPS..STEADY_REPS + 30]);
    capi.prefill(&handle, &h_anchor).await.expect("h anchor");
    for _ in 0..10 {
        // Roll back to `base` (frees 30 cells) then decode 3 into the holes.
        capi.prefill(&handle, &base).await.expect("h rollback");
        let next: Vec<u32> = pool_h2.by_ref().take(3).copied().collect();
        let mut target = base.clone();
        target.extend_from_slice(&next);
        let started = Instant::now();
        capi.prefill(&handle, &target).await.expect("h hole delta");
        h_hole_ms.push(ms(started.elapsed()));
        // Re-extend so the next rollback frees cells again.
        let mut full = target;
        let rest: Vec<u32> = token_pool[STEADY_REPS + 3..STEADY_REPS + 30].to_vec();
        full.extend_from_slice(&rest);
        capi.prefill(&handle, &full).await.expect("h refill");
    }

    // ---- phase I: rollback-only calls --------------------------------------
    // Measures prefill(base) when the trail is `anchor` long (frees N cells,
    // decodes nothing) — isolates the KV rollback cost from decode cost.
    let mut i_rollback_ms = Vec::with_capacity(10);
    {
        let mut anchor = base.clone();
        anchor.extend_from_slice(&token_pool[STEADY_REPS..STEADY_REPS + 30]);
        for _ in 0..10 {
            capi.prefill(&handle, &anchor).await.expect("i anchor");
            let started = Instant::now();
            capi.prefill(&handle, &base).await.expect("i rollback");
            i_rollback_ms.push(ms(started.elapsed()));
        }
    }

    // ---- phase K: 1-token → 3-token transition with NO rollback ------------
    // step leaves the trail exactly at its (pre-sample) prefix; the
    // following prefill extends it (sampled token + 3 pool tokens) with no
    // rollback and no holes. If K's delta decodes are expensive anyway, the
    // cost is the 1-token→k-token decode transition itself; if cheap, the
    // rollback (or the holes it leaves) is the cost.
    let mut k_step_ms = Vec::with_capacity(10);
    let mut k_delta_ms = Vec::with_capacity(10);
    {
        let mut working = base.clone();
        let mut pool_k = token_pool
            .iter()
            .skip(STEADY_REPS + STEADY_REPS * 3 + INTERLEAVE_CYCLES * 3 * 2 + 30 + 30);
        for _ in 0..10 {
            let started = Instant::now();
            let token = capi
                .decode_step(&handle, &working, &sampling)
                .await
                .expect("k step");
            k_step_ms.push(ms(started.elapsed()));
            working.push(token);
            // The step's own sampled token continues the trail naturally:
            // prefill(working + 3 pool tokens) extends with no rollback.
            let next: Vec<u32> = pool_k.by_ref().take(3).copied().collect();
            let mut target = working.clone();
            target.extend_from_slice(&next);
            working = target.clone();
            let started = Instant::now();
            capi.prefill(&handle, &target).await.expect("k delta");
            k_delta_ms.push(ms(started.elapsed()));
        }
    }

    // ---- phase L: 1-token decode → k-token delta, NO rollback --------------
    // The one clean transition K no longer probes (uniform outputs made its
    // steps decode-free): a REAL 1/1 decode (propose's first draft step)
    // immediately followed by an extending multi-token delta with no
    // rollback and no holes. Expensive ⇒ the 1→k decode-shape transition
    // itself; cheap ⇒ the rollback is a necessary ingredient.
    let mut l_delta_ms = Vec::with_capacity(10);
    {
        let mut working = base.clone();
        let mut pool_l = token_pool
            .iter()
            .skip(POOL_SKIP_A + STEADY_REPS * 3 + INTERLEAVE_CYCLES * 3 * 5);
        for _ in 0..10 {
            // One real 1/1 decode at the trail tail: propose syncs to
            // `working` (already the trail — tail logits are live from the
            // previous iteration's delta, so the sample is decode-free) and
            // then decodes its first draft token (window 2 = exactly one
            // 1-token decode).
            let draft2 = capi.propose(&handle, &working, 2).await.expect("l propose");
            assert_eq!(draft2.len(), 2);
            let next: Vec<u32> = pool_l.by_ref().take(3).copied().collect();
            let mut target = working.clone();
            target.extend_from_slice(&draft2);
            target.extend_from_slice(&next);
            working = target.clone();
            let started = Instant::now();
            capi.prefill(&handle, &target).await.expect("l delta");
            l_delta_ms.push(ms(started.elapsed()));
        }
    }

    // ---- phase M: the REAL speculative loop ---------------------------------
    // The pattern the ADR-032 family actually runs: each round proposes a
    // window (k one-token decodes), verifies in one batched pass, then the
    // next round's prefix grows by (accepted + bonus) — decoded as a delta
    // by the following sync. Reports propose / verify / next-round delta.
    let mut m_propose_ms = Vec::with_capacity(6);
    let mut m_verify_ms = Vec::with_capacity(6);
    let mut m_delta_ms = Vec::with_capacity(6);
    {
        let mut round_prefix = base.clone();
        for _ in 0..6 {
            let started = Instant::now();
            let draft = capi
                .propose(&handle, &round_prefix, 8)
                .await
                .expect("m propose");
            m_propose_ms.push(ms(started.elapsed()));
            let started = Instant::now();
            let outcome = capi
                .verify_drafts(&handle, &round_prefix, &draft, &sampling)
                .await
                .expect("m verify");
            m_verify_ms.push(ms(started.elapsed()));
            let mut next = round_prefix.clone();
            next.extend_from_slice(&outcome.accepted);
            if let Some(token) = outcome.bonus {
                next.push(token);
            }
            round_prefix = next;
            // The delta the NEXT verify's sync would decode, measured via
            // the same engine path (prefill sync), plus one extra token.
            let mut delta_probe = round_prefix.clone();
            delta_probe.push(round_prefix[0]);
            let started = Instant::now();
            capi.prefill(&handle, &delta_probe).await.expect("m delta");
            m_delta_ms.push(ms(started.elapsed()));
        }
    }

    // ---- record ------------------------------------------------------------
    report("A steady step (1 tok / 1 out)", &step_ms);
    report("B steady delta (+3 tok / 0 out)", &delta3_ms);
    report("C steady verify (9 rows / 9 out)", &verify_ms);
    report("D interleave step (1/1)", &inter_step_ms);
    report("D interleave delta (3/0)", &inter_delta_ms);
    report("D interleave verify (9/9)", &inter_verify_ms);
    report("E delta-0 sync (no engine work)", &noop_ms);
    println!("\n--- discrimination phases ---");
    report("G step (1/1) w/o verify between", &g_step_ms);
    report("G delta (3/0) w/o verify between", &g_delta_ms);
    report("H1 delta (3/0) fresh tail cells", &h_tail_ms);
    report("H2 delta (3/0) into freed cells", &h_hole_ms);
    println!(
        "H2−H1 (same batch shape, KV holes vs tail): {:+.3} ms",
        median(&h_hole_ms) - median(&h_tail_ms)
    );
    report("I rollback-only (frees 30 cells)", &i_rollback_ms);
    report("K step (1/1) no rollback after", &k_step_ms);
    report("K delta (1→4 tok) no rollback", &k_delta_ms);
    println!("\n--- production-shape phases ---");
    report("L delta after real 1/1, no rollbk", &l_delta_ms);
    report("M propose (8 one-token steps)", &m_propose_ms);
    report("M verify (one 9-row pass)", &m_verify_ms);
    report("M next-round delta sync", &m_delta_ms);
    println!("\n--- verify width churn (F2 alternating - F1 steady, per width) ---");
    for (index, (k, steady)) in f_steady.iter().enumerate() {
        let alternating = &f_alternating[index].1;
        println!(
            "width {:>2} ({} rows): steady median {:>8.3} ms | alternating median {:>8.3} ms | delta {:+8.3} ms",
            k,
            k + 1,
            median(steady),
            median(alternating),
            median(alternating) - median(steady),
        );
    }
    println!(
        "\nchurn deltas (interleave median - steady median): step {:+.3} ms, delta {:+.3} ms, verify {:+.3} ms",
        median(&inter_step_ms) - median(&step_ms),
        median(&inter_delta_ms) - median(&delta3_ms),
        median(&inter_verify_ms) - median(&verify_ms),
    );
    println!(
        "verify accepted {}/8, bonus {:?} (must equal the steady outcome — asserted)",
        steady_outcome.accepted.len(),
        steady_outcome.bonus
    );
}
