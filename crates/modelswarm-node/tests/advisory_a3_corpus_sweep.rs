//! The §9.2(7) FULL A3 CORPUS SWEEP (ADR-033 (7) as extended by ADR-037
//! §4.4 item 14 and retargeted by the 2026-10-15 owner directive): with
//! the assistant plane in its TWO postures — HOSTED-MODEL-BACKED (the
//! plane armed over a double standing in for the machine's hosted
//! model, turns driven and answering) vs STATIC-ONLY (no backing: the
//! plane is absent, the surface serves the frozen static floor) — every
//! observable decision surface is byte-identical and the telemetry
//! stream is byte-identical after filtering the plane's own
//! `assistant.*` rows.
//!
//! Corpus families executed here (the ADR-033 §9.2(7) letter, at the
//! composition seam where the plane can exist):
//!
//! - **(a) the scheduler/shadow decision surface** — the FULL candidate
//!   matrix over the shipped production decision functions
//!   (`select_microswarm`, `predicted_single_ms`,
//!   `should_engage_cooperative` incl. the frozen margin floor): every
//!   capacity class × NAT path × batch-verify flag × slot/staleness/
//!   rate tiers, deterministic cohorts, and the engage boundary swept at
//!   exact `ratio × (1 + margin)` equality ± 1e-9. No re-implementation:
//!   these are the production imports the sim also rides.
//! - **the node workload corpus** — the same runtime-less gateway turns
//!   (no-peer 503, unknown-profile) through a REAL `Node::start` in both
//!   postures; the node's `logs/node.jsonl` streams are diffed
//!   byte-for-byte after filtering plane rows and normalizing ONLY the
//!   log timestamp, the ephemeral port, and the per-installation identity
//!   (declared normalizations — everything else must match exactly). In
//!   the hosted-backed posture the assistant turns run AGAINST A
//!   TELEMETRY SINK OPENED ON THE SAME DATA DIR, so their `assistant.*`
//!   rows genuinely interleave into the compared stream — the filter
//!   removes REAL rows, never a vacuous absence.
//! - **the assistant plane** — armed in-process over an ECHOING double
//!   (the hosted-model posture; turns complete and answer), with the
//!   plane-rows-only confinement pinned on a shared memory sink.
//!
//! Corpus families (b) session admission/coordinator suites, (c) the
//! sim pinned-verdict scenarios, and (d) the bench corpora execute BELOW
//! the advisory host in the crate graph — the chat-wall layer 1 test
//! (`advisory_chat_wall.rs`) pins that they cannot even name the plane,
//! so the static-only posture IS their only possible posture; they
//! re-run per-push in their own suites (the venue matrix rows).
//!
//! ADR-037 item 14's picker corpus (the deterministic `fit_and_score`
//! shortlist) lives in the desktop crate; the desktop seam's A3 pattern
//! test (`assistant_a3_extension_static_only_vs_hosted_backed`) pins
//! it, and the chat-wall layer-2 scan pins that `app.rs` (the picker's
//! home) carries no advisory name at all — structurally incapable of
//! seeing the plane.

use std::sync::Arc;

use modelswarm_node::advisory::assistant::{AssistantPlane, HostedBacking, TurnOutcome};
use modelswarm_node::advisory::egress::{ContextField, ContextValue};
use modelswarm_node::advisory::{AdvisoryTransport, CountingTransport};
use modelswarm_scheduler::{
    predicted_single_ms, select_microswarm, should_engage_cooperative, Candidate, CapacityClass,
    NatPath, SchedulerError, DEFAULT_CONFIDENCE_MARGIN, MICROSWARM_CAP, MIN_CONFIDENCE_MARGIN,
};
use modelswarm_types::ModelProfileId;

// No env mutation in this binary: arming rides advisory.json plus the
// caller-supplied hosted backing facts (no key, no env var — the
// 2026-10-15 collapse removed those surfaces).

// ---------------------------------------------------------------------------
// Corpus (a): the scheduler decision surface — the full candidate matrix
// ---------------------------------------------------------------------------

const PROFILE: &str = "msp:a3-sweep:q4_k_m:v1";

fn candidate(ix: usize) -> Candidate {
    // A deterministic grid over the Candidate space: every capacity
    // class, NAT path, batch-verify flag, slot tier (incl. the ineligible
    // 0), staleness tier (incl. the over-cap 1500ms), and measured-rate
    // tier (incl. the unusable 0.0 -> INFINITY). The tiers cycle by index
    // so cohorts mix classes deterministically.
    let classes = [
        CapacityClass::Cpu,
        CapacityClass::GpuEntry,
        CapacityClass::GpuMid,
        CapacityClass::GpuHigh,
    ];
    let paths = [NatPath::Direct, NatPath::HolePunched, NatPath::Relayed];
    let slots = [0u32, 1, 3];
    let stale = [0.0f64, 500.0, 999.0, 1500.0];
    let rates = [0.0f64, 0.05, 0.5];
    let rtts = [8.0f64, 40.0, 180.0];
    let queues = [0.0f64, 25.0, 400.0];
    let failures = [0.0f64, 75.0];
    Candidate {
        peer_id: format!("peer-{ix:05}"),
        profile_id: ModelProfileId::new(PROFILE).unwrap(),
        measured_rtt_ms: rtts[ix % rtts.len()],
        advertised_queue_ms: queues[ix % queues.len()],
        prefill_tokens_per_ms: rates[ix % rates.len()],
        decode_tokens_per_ms: rates[(ix / 3) % rates.len()],
        failure_penalty_ms: failures[ix % failures.len()],
        stale_advertisement_penalty_ms: stale[ix % stale.len()],
        slots: slots[ix % slots.len()],
        capacity_class: classes[ix % classes.len()],
        nat_path: paths[ix % paths.len()],
        batch_verify: ix % 2 == 0,
    }
}

/// One stable serialization of the FULL decision corpus over `candidates`
/// (selection order + per-candidate predictions + the engage boundary).
fn engage_corpus_digest(candidates: &[Candidate]) -> String {
    let mut out = serde_json::json!({});
    let token_profiles = [(128u32, 64u32), (1024, 256), (8192, 2048)];
    for (pi, (prompt, output)) in token_profiles.iter().enumerate() {
        for want in [1usize, 4, MICROSWARM_CAP] {
            let picked: Vec<&str> = select_microswarm(
                candidates,
                &ModelProfileId::new(PROFILE).unwrap(),
                *prompt,
                *output,
                want,
            )
            .into_iter()
            .map(|c| c.peer_id.as_str())
            .collect();
            out[format!("select/p{pi}/w{want}")] = serde_json::json!(picked);
        }
        let preds: Vec<String> = candidates
            .iter()
            .map(|c| format!("{:e}", predicted_single_ms(c, *prompt, *output)))
            .collect();
        out[format!("predict/p{pi}")] = serde_json::json!(preds);
    }
    // The engage boundary at exact equality ± 1e-9 for each margin tier,
    // plus the frozen-floor rejection (ADR-013).
    let margins = [MIN_CONFIDENCE_MARGIN, DEFAULT_CONFIDENCE_MARGIN, 0.5, 1.0];
    for (mi, margin) in margins.iter().enumerate() {
        for (ri, delta) in [-1e-9f64, 0.0, 1e-9, 1.0, -1.0].iter().enumerate() {
            let swarm = 100.0f64;
            let single = 100.0 * (1.0 + margin) + delta;
            let verdict = match should_engage_cooperative(swarm, single, *margin) {
                Ok(engage) => serde_json::json!(engage),
                Err(e) => serde_json::json!(format!("err:{e}")),
            };
            out[format!("engage/m{mi}/r{ri}")] = verdict;
        }
    }
    let below_floor = should_engage_cooperative(100.0, 100.0, MIN_CONFIDENCE_MARGIN - 0.01)
        .map_err(|e: SchedulerError| e.to_string());
    out["engage/floor"] = serde_json::json!(below_floor);
    out.to_string()
}

// ---------------------------------------------------------------------------
// The node workload corpus (real Node::start, runtime-less gateway turns)
// ---------------------------------------------------------------------------

/// Boots a runtime-less node in `dir`, drives the identical gateway turn
/// set (3 × no-peer 503, 2 × unknown-profile), stops it, and returns the
/// NORMALIZED + plane-filtered `logs/node.jsonl` stream. When
/// `hosted_backed` is set, the assistant plane is armed in-process over
/// an echoing double (the hosted-model posture) and THREE turns are
/// driven DURING the workload against a telemetry sink opened on the
/// same data dir — their `assistant.*` rows interleave into the compared
/// file stream, so the plane-row filter removes real rows.
async fn node_workload(dir: &std::path::Path, hosted_backed: bool) -> String {
    let (tx, rx) = tokio::sync::watch::channel(false);
    // logs/node.jsonl APPENDS across boots in one data dir — compare only
    // THIS boot's lines (the workload window).
    let log_path = dir.join("logs/node.jsonl");
    let prior_lines = std::fs::read_to_string(&log_path)
        .map(|text| text.lines().count())
        .unwrap_or(0);
    let config = modelswarm_node::NodeConfig {
        gateway_port: 0,
        data_dir: dir.to_path_buf(),
        profile_id: Some("msp1:a3workload".to_string()),
        ..modelswarm_node::NodeConfig::default()
    };
    let handle = modelswarm_node::Node::start(config, rx)
        .await
        .expect("node starts");
    let addr = handle.local_addr;
    let client = reqwest::Client::new();

    let mut double: Option<Arc<CountingTransport>> = None;
    let mut memory_sink_rows: Vec<String> = Vec::new();
    if hosted_backed {
        std::fs::write(dir.join("advisory.json"), r#"{"assistant.enabled":true}"#).unwrap();
        let echo = Arc::new(CountingTransport::assistant_echo(
            "hosted-model advice".into(),
        ));
        let backing = HostedBacking {
            gateway_addr: addr,
            profile: "msp1:a3workload".to_string(),
        };
        let (plane, gap) = AssistantPlane::spawn(
            dir,
            Some(&backing),
            Some(echo.clone() as Arc<dyn AdvisoryTransport>),
        );
        assert_eq!(
            gap.as_str(),
            "not_hosting",
            "armed spawn reports no degrade"
        );
        let plane = plane.expect("the plane arms over the hosted-model double");
        double = Some(echo);
        // The turns run against a FILE telemetry sink on the same data
        // dir (the desktop's own posture: the app-level telemetry), so
        // the assistant.* rows interleave with the node's rows in the
        // compared stream; the confinement check rides a memory sink.
        let file_telemetry = open_file_telemetry(dir);
        let (memory_telemetry, sink) = modelswarm_telemetry::Telemetry::memory();
        for question in ["which model fits?", "why is family off?", "third turn"] {
            let outcome = plane
                .run_turn(&memory_telemetry, question, typed_context())
                .await;
            let _ = plane
                .run_turn(&file_telemetry, question, typed_context())
                .await;
            assert!(
                matches!(outcome, TurnOutcome::Reply { .. }),
                "the hosted-model double answers"
            );
        }
        memory_sink_rows = sink.snapshot();
    }

    for _ in 0..3 {
        let r = client
            .post(format!("http://{addr}/v1/chat/completions"))
            .json(&serde_json::json!({
                "model": "msp1:a3workload",
                "messages": [{"role": "user", "content": "a3 sweep turn"}],
                "max_tokens": 8,
            }))
            .send()
            .await
            .expect("gateway responds");
        assert_eq!(r.status().as_u16(), 503, "runtime-less node fails honestly");
    }
    for _ in 0..2 {
        let r = client
            .post(format!("http://{addr}/v1/chat/completions"))
            .json(&serde_json::json!({
                "model": "msp1:not-hosted",
                "messages": [{"role": "user", "content": "a3 sweep turn"}],
                "max_tokens": 8,
            }))
            .send()
            .await
            .expect("gateway responds");
        assert!(!r.status().is_success());
    }
    tx.send(true).unwrap();
    handle.stopped().await;
    let raw = std::fs::read_to_string(&log_path).unwrap();
    let window: String = raw.lines().skip(prior_lines).collect::<Vec<_>>().join("\n");
    if hosted_backed {
        let echo = double.expect("armed posture carries the double");
        assert_eq!(echo.count(), 6, "three turns x two telemetry sinks called");
        // Confinement: the plane's memory-sink rows are ALL assistant.*
        // (counts/labels only; no reply text).
        for line in &memory_sink_rows {
            assert!(line.contains("\"event\":\"assistant."), "{line}");
            assert!(!line.contains("hosted-model advice"), "{line}");
        }
    }
    normalize_node_log(&window)
}

/// Opens a telemetry file sink on the node's data dir — the same
/// `logs/node.jsonl` the node appends to (the desktop's app-level
/// posture for the plane's rows).
fn open_file_telemetry(dir: &std::path::Path) -> modelswarm_telemetry::Telemetry {
    let _ = std::fs::create_dir_all(dir.join("logs"));
    let sink = modelswarm_telemetry::FileSink::open(&dir.join("logs").join("node.jsonl"))
        .expect("telemetry file sink opens");
    modelswarm_telemetry::Telemetry::with_sink(Box::new(sink))
}

/// The declared normalizations for cross-run file comparison (everything
/// else must match byte-for-byte): the log `ts` field, the ephemeral
/// gateway port, and the per-installation identity string. Plane rows
/// (`assistant.*`) are the A3 carve-out — filtered.
fn normalize_node_log(raw: &str) -> String {
    let mut kept: Vec<String> = Vec::new();
    for line in raw.lines() {
        if line.contains("\"event\":\"advisory.") || line.contains("\"event\":\"assistant.") {
            continue;
        }
        // "ts":"2026-10-14T20:00:00Z" -> "ts":"T"
        let mut l = String::new();
        let mut rest = line;
        if let Some(pos) = rest.find("\"ts\":\"") {
            let after = &rest[pos + 6..];
            let end = after.find('"').unwrap();
            l.push_str(&rest[..pos + 6]);
            l.push('T');
            rest = &after[end..];
        }
        l.push_str(rest);
        // 127.0.0.1:<ephemeral> -> 127.0.0.1:P
        let l = l
            .split("127.0.0.1:")
            .enumerate()
            .fold(String::new(), |acc, (i, part)| {
                if i == 0 {
                    part.to_string()
                } else {
                    let digits = part.chars().take_while(|c| c.is_ascii_digit()).count();
                    acc + "127.0.0.1:P" + &part[digits..]
                }
            });
        // installation ids (base58-ish runs) -> ID
        let l = replace_field_value(&l, "installation_id");
        let l = replace_field_value(&l, "peer");
        let l = replace_field_value(&l, "conversation_id");
        kept.push(l);
    }
    kept.join("\n")
}

fn replace_field_value(line: &str, field: &str) -> String {
    let needle = format!("\"{field}\":\"");
    let Some(pos) = line.find(&needle) else {
        return line.to_string();
    };
    let after = &line[pos + needle.len()..];
    let end = after.find('"').unwrap_or(after.len());
    format!("{}{}{}", &line[..pos + needle.len()], "ID", &after[end..])
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

fn typed_context() -> Vec<ContextField> {
    vec![ContextField {
        name: "hw.logical_cpus".into(),
        value: ContextValue::Int(16),
    }]
}

/// ADR-033 §9.2(7) + ADR-037 §4.4 item (14), post-2026-10-15 postures:
/// the FULL corpus, STATIC-ONLY (no model backing — the plane is absent)
/// vs HOSTED-MODEL-BACKED (the plane armed over the hosted-model double,
/// turns driven and answering during the workload). Decision outputs
/// byte-identical; the node workload telemetry byte-identical after the
/// declared normalizations + plane filtering; the plane confined to its
/// own rows.
#[tokio::test]
async fn a3_full_corpus_static_only_vs_hosted_model_backed() {
    let dir = tempfile::tempdir().unwrap();
    let candidates: Vec<Candidate> = (0..96).map(candidate).collect();

    // Warm-up boot: creates the identity so BOTH measured postures log
    // identity.loaded (the first boot would log identity.created and
    // poison the diff with a posture-independent difference).
    {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let config = modelswarm_node::NodeConfig {
            gateway_port: 0,
            data_dir: dir.path().to_path_buf(),
            profile_id: Some("msp1:a3workload".to_string()),
            ..modelswarm_node::NodeConfig::default()
        };
        let handle = modelswarm_node::Node::start(config, rx).await.unwrap();
        tx.send(true).unwrap();
        handle.stopped().await;
    }

    // ---- Posture A: STATIC-ONLY (no backing; the plane is absent) ----
    let digest_static = engage_corpus_digest(&candidates);
    let workload_static = node_workload(dir.path(), false).await;
    // The honest static-floor arming: not_hosting, no plane.
    let (plane, gap) = AssistantPlane::spawn(dir.path(), None, None);
    assert!(plane.is_none());
    assert_eq!(gap.as_str(), "not_hosting");
    let digest_static_again = engage_corpus_digest(&candidates);
    assert_eq!(
        digest_static, digest_static_again,
        "the pure decision corpus is deterministic"
    );

    // ---- Posture B: HOSTED-MODEL-BACKED ------------------------------
    // The plane arms over the echoing double (the hosted-model posture)
    // and turns run DURING the workload (see node_workload); the corpus
    // is re-evaluated with the plane armed in-process.
    std::fs::write(
        dir.path().join("advisory.json"),
        r#"{"assistant.enabled":true}"#,
    )
    .unwrap();
    let armed_double = Arc::new(CountingTransport::assistant_echo("advice".into()));
    let armed_backing = HostedBacking {
        gateway_addr: "127.0.0.1:1".parse().unwrap(),
        profile: "msp1:a3workload".to_string(),
    };
    let (ambient_plane, gap) = AssistantPlane::spawn(
        dir.path(),
        Some(&armed_backing),
        Some(armed_double.clone() as Arc<dyn AdvisoryTransport>),
    );
    assert_eq!(
        gap.as_str(),
        "not_hosting",
        "armed spawn reports no degrade"
    );
    let _ambient_plane = ambient_plane.expect("the plane arms over the double");
    let (ambient_telemetry, ambient_sink) = modelswarm_telemetry::Telemetry::memory();
    for question in ["ambient q1", "ambient q2"] {
        let outcome = _ambient_plane
            .run_turn(&ambient_telemetry, question, typed_context())
            .await;
        assert!(matches!(outcome, TurnOutcome::Reply { .. }));
    }
    assert_eq!(armed_double.count(), 2, "the ambient plane is live");

    // The corpus evaluated WHILE the assistant plane is armed in-process
    // (ambient plane activity must not perturb the decisions).
    let digest_hosted = engage_corpus_digest(&candidates);

    // The node workload with the hosted-backed posture (turns driven
    // inside, assistant.* rows interleaved into the compared stream).
    let workload_hosted = node_workload(dir.path(), true).await;

    // ---- (i) Decision outputs byte-identical -------------------------
    assert_eq!(
        digest_static, digest_hosted,
        "A3(i): the full scheduler decision corpus is byte-identical with the plane hosted-model-backed and live"
    );

    // ---- (ii) The telemetry stream byte-identical after filtering -----
    assert_eq!(
        workload_static, workload_hosted,
        "A3(ii): the node workload telemetry is byte-identical after filtering assistant.* (declared normalizations: ts, ephemeral port, installation/conversation ids)"
    );

    // Non-vacuous filtered equality: the hosted-backed stream REALLY
    // carried assistant.* rows that the filter removed.
    let raw_hosted = std::fs::read_to_string(dir.path().join("logs/node.jsonl")).unwrap();
    assert!(
        raw_hosted.contains("\"event\":\"assistant.turn.sent\""),
        "the hosted-backed posture must have interleaved real assistant rows"
    );

    // Confinement: the ambient plane's memory-sink rows are ALL
    // assistant.* (counts/labels only; no reply text).
    for line in ambient_sink.snapshot() {
        assert!(line.contains("\"event\":\"assistant."), "{line}");
        assert!(!line.contains("advice"), "{line}");
    }
}
