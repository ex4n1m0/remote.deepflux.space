//! `modelswarm-node` CLI (std-only arg parsing, no clap).
//!
//! Subcommands:
//!
//! - `modelswarm-node run [--port N] [--data-dir D] [--tracker URL]
//!   [--profile msp1:…] [--allow-mock-runtime] [--check-tracker]`
//!   — compose and serve until Ctrl-C (graceful shutdown via the watch
//!   channel).
//! - `modelswarm-node self-test [--port N]` — the no-network self-test
//!   (ADR-019 mock runtime; requires the `node-selftest` feature, refused
//!   loudly otherwise). Touches nothing outside a temp dir; prints exactly
//!   one JSON line: `{"self_test":"ok","tokens":N,"redacted_logs":true}`.

use std::path::PathBuf;
use std::process::ExitCode;

use modelswarm_node::{Node, NodeConfig};

const USAGE: &str = "\
modelswarm-node — ModelSwarm background node daemon

USAGE:
    modelswarm-node run [--port N] [--data-dir DIR] [--tracker URL]
                        [--profile MSP1_ID] [--engine EXE] [--model GGUF] [--threads N]
                        [--allow-mock-runtime] [--check-tracker]
    modelswarm-node self-test [--port N]
    modelswarm-node --version

OPTIONS (run):
    --port N               Loopback gateway port (default 11435; 0 = ephemeral)
    --data-dir DIR         Data directory (default %LOCALAPPDATA%\\ModelSwarm)
    --tracker URL          Tracker base URL; no calls are made at startup
    --profile MSP1_ID      Profile id this node hosts/serves (msp1:…)
    --allow-mock-runtime   TEST-ONLY (ADR-019): requires a build with
                           --features node-selftest; loopback-only, never
                           serves remote peers
    --engine EXE           Path to the pinned llama-server.exe; with --model,
                           the node spawns and supervises the engine (Phase H3)
    --model GGUF           Path to the verified GGUF artifact to host
    --threads N            Engine compute threads (default: engine decides)
    --check-tracker        After startup, issue one read-only GET /health to
                           the configured tracker and log the outcome

OPTIONS (self-test):
    --port N               Fixed gateway port (default: ephemeral)
";

enum Command {
    Run {
        port: Option<u16>,
        data_dir: Option<PathBuf>,
        tracker: Option<String>,
        profile: Option<String>,
        engine: Option<PathBuf>,
        model: Option<PathBuf>,
        threads: Option<u32>,
        allow_mock: bool,
        check_tracker: bool,
    },
    SelfTest {
        port: Option<u16>,
    },
    Version,
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    let Some(sub) = args.first() else {
        return Err(format!("missing subcommand\n\n{USAGE}"));
    };
    let mut port: Option<u16> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut tracker: Option<String> = None;
    let mut profile: Option<String> = None;
    let mut engine: Option<PathBuf> = None;
    let mut model: Option<PathBuf> = None;
    let mut threads: Option<u32> = None;
    let mut allow_mock = false;
    let mut check_tracker = false;
    let mut rest = args[1..].iter();
    while let Some(flag) = rest.next() {
        let mut value = || {
            rest.next()
                .cloned()
                .ok_or_else(|| format!("{} needs a value\n\n{USAGE}", flag))
        };
        match flag.as_str() {
            "--port" => {
                let raw = value()?;
                port = Some(raw.parse().map_err(|_| format!("bad port {raw:?}"))?);
            }
            "--data-dir" => data_dir = Some(PathBuf::from(value()?)),
            "--tracker" => tracker = Some(value()?),
            "--profile" => profile = Some(value()?),
            "--engine" => engine = Some(PathBuf::from(value()?)),
            "--model" => model = Some(PathBuf::from(value()?)),
            "--threads" => {
                threads = Some(
                    value()?
                        .parse()
                        .map_err(|_| "bad --threads value".to_string())?,
                )
            }
            "--allow-mock-runtime" => allow_mock = true,
            "--check-tracker" => check_tracker = true,
            other => return Err(format!("unknown flag {other:?}\n\n{USAGE}")),
        }
    }
    match sub.as_str() {
        "run" => Ok(Command::Run {
            port,
            data_dir,
            tracker,
            profile,
            engine,
            model,
            threads,
            allow_mock,
            check_tracker,
        }),
        "self-test" => Ok(Command::SelfTest { port }),
        "--version" | "-V" | "version" => Ok(Command::Version),
        other => Err(format!("unknown subcommand {other:?}\n\n{USAGE}")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Ok(Command::Version) => {
            println!(
                "modelswarm-node {} (MSP protocol v{})",
                env!("CARGO_PKG_VERSION"),
                modelswarm_types::MSP_PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }
        Ok(Command::Run {
            port,
            data_dir,
            tracker,
            profile,
            engine,
            model,
            threads,
            allow_mock,
            check_tracker,
        }) => run_cli(
            port,
            data_dir,
            tracker,
            profile,
            engine,
            model,
            threads,
            allow_mock,
            check_tracker,
        ),
        Ok(Command::SelfTest { port }) => self_test_cli(port),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_cli(
    port: Option<u16>,
    data_dir: Option<PathBuf>,
    tracker: Option<String>,
    profile: Option<String>,
    engine: Option<PathBuf>,
    model: Option<PathBuf>,
    threads: Option<u32>,
    allow_mock: bool,
    check_tracker: bool,
) -> ExitCode {
    let mut config = NodeConfig::default();
    if let Some(port) = port {
        config.gateway_port = port;
    }
    if let Some(data_dir) = data_dir {
        config.data_dir = data_dir;
    }
    config.tracker_base = tracker;
    config.profile_id = profile;
    config.mock = allow_mock;
    config.engine_binary = engine;
    config.engine_model = model;
    config.engine_threads = threads;
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    match runtime.block_on(run_node(config, check_tracker)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("modelswarm-node: {error}");
            ExitCode::FAILURE
        }
    }
}

fn self_test_cli(port: Option<u16>) -> ExitCode {
    #[cfg(feature = "node-selftest")]
    {
        let dir = std::env::temp_dir().join(format!(
            "modelswarm-node-selftest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        if let Err(error) = std::fs::create_dir_all(&dir) {
            eprintln!("self-test: cannot create temp dir: {error}");
            return ExitCode::FAILURE;
        }
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        let result = runtime.block_on(async {
            tokio::select! {
                result = modelswarm_node::selftest::run(&dir, port.unwrap_or(0)) => result,
                _ = tokio::signal::ctrl_c() => Err("interrupted".to_string()),
            }
        });
        let _ = std::fs::remove_dir_all(&dir); // best-effort cleanup
        match result {
            Ok(report) => {
                // Exactly one JSON line on stdout (machine-readable evidence).
                println!(
                    "{{\"self_test\":\"ok\",\"tokens\":{},\"redacted_logs\":{}}}",
                    report.tokens, report.redacted_logs
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                println!(
                    "{{\"self_test\":\"failed\",\"error\":{}}}",
                    serde_json::to_string(&error).unwrap_or_else(|_| "\"?\"".to_string())
                );
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(feature = "node-selftest"))]
    {
        let _ = port;
        eprintln!(
            "self-test refused: this build has no self-test support.\n\
             Rebuild with: cargo build -p modelswarm-node --features node-selftest\n\
             (TEST-ONLY mock runtime, ADR-019; production builds never enable it)"
        );
        ExitCode::from(2)
    }
}

async fn run_node(config: NodeConfig, check_tracker: bool) -> Result<(), String> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = Node::start(config, shutdown_rx)
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "modelswarm-node {} listening on {} (installation {})",
        env!("CARGO_PKG_VERSION"),
        handle.local_addr,
        handle.installation_id
    );

    if check_tracker {
        let tracker = handle
            .tracker
            .as_ref()
            .ok_or("--check-tracker requires --tracker")?;
        match tracker.health().await {
            Ok(health) => println!("tracker health: {health}"),
            Err(error) => println!("tracker unreachable: {error}"),
        }
    }

    // Ctrl-C → graceful shutdown; the same joined future also covers the
    // server dying on its own (bind lost / fatal serve error).
    let server_exit = handle.stopped();
    tokio::pin!(server_exit);
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("ctrl-c received; shutting down");
            let _ = shutdown_tx.send(true);
            server_exit.await;
            println!("node stopped");
        }
        _ = &mut server_exit => {
            println!("gateway exited on its own");
        }
    }
    Ok(())
}
