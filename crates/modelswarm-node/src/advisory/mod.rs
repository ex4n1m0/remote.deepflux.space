//! The advisory plane client (ADR-033 as amended by the 2026-10-15
//! owner directive: "how about we remove this deepseek key completely,
//! and make the helper use the hosted model when hosted"). Hosted as a
//! module of the node daemon's crate per ADR-033 §9.4
//! ("`crates/modelswarm-node::advisory`"), which the chat-wall suite's
//! layer-1 dependency assertion guards directly.
//!
//! The 2026-10-15 collapse, in one paragraph: the provider-key era
//! ENDED. The timer-driven digest cycle (the metadata-egress-to-provider
//! brain), its typed accumulators, its reqwest adapter, its https
//! arming, and every key surface (`MSP_ADVISORY_KEY_FILE`, `key_file`,
//! the platform-default path) are DELETED, not defaulted off. What
//! remains is the ASSISTANT plane and only it: a user-triggered setup
//! helper whose model backing is the machine's OWN hosted model behind
//! the node's loopback gateway while hosting, and the frozen static
//! floor otherwise. The deterministic-local invariant — every decision
//! the shipped system makes — is the only mode there ever is now.
//!
//! Layout:
//! - [`config`] — `advisory.json` (TR-RC-8), collapsed to the ADR-037
//!   §3.4 `assistant.*` rows + the enable posture; old provider/digest
//!   keys are ignored and preserved, never fatal, never rewritten.
//! - [`egress`] — the ONE value-typed allowlist for the assistant
//!   context block, driven by the frozen artifact
//!   `protocol/advisory-egress-v1.json`, plus the RC-3 choke-point
//!   re-scan and the clamp table.
//! - [`state`] — the SHARED vocabulary types: the frozen gap enum, the
//!   suggestion schema, and the transport seam's request/failure
//!   shapes.
//! - [`transport`] — the injectable transport trait, the pinned
//!   LOOPBACK-ONLY local-gateway adapter (the production backing), and
//!   the counting double the test suites ride.
//! - [`assistant`] — the pure `step(state, input) -> (state, effects)`
//!   machine (TR-RC-4/TR-AD-2: injected clock and transport) plus the
//!   [`assistant::AssistantPlane`] handle whose `run_turn` is the ONLY
//!   transport execution site (W2's enumerated call sites).
//!
//! The ADR-033 §1 invariants hold structurally at this leg, retargeted
//! to the local seam: content-blind egress (one value-typed gate
//! exhaustively tied to the frozen vocabulary artifact — and the only
//! egress left is the machine's own gateway), advisory-only (the
//! recorded suggestion type exposes clamped/typed values and a Display
//! summary — there is no API through which production code could apply
//! a hint), full function without the plane (default-off; without
//! hosting the static floor serves; A3 telemetry discipline: the plane
//! emits only `assistant.*` rows), and measured-before-trusted
//! (nothing here applies anything).

pub mod assistant;
pub mod config;
pub mod egress;
pub mod state;
pub mod transport;

pub use assistant::{AssistantPlane, HostedBacking, TurnOutcome};
pub use config::AdvisoryConfig;
pub use state::Gap;
pub use transport::{AdvisoryTransport, CountingTransport, LocalGatewayTransport};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Layer 3 of the chat-wall suite (behavioral): a FULL SUCCESS chat
    /// turn through the node's loopback gateway — the exact surface
    /// `send_chat`'s local fallback posts to — with an ARMED assistant
    /// plane (hosted-model posture, over a counting double that stands
    /// in for the hosted model) alive in the same process, records ZERO
    /// assistant calls. The mock runtime (cfg(test)) serves the turn;
    /// the runtime-less failure paths ride
    /// `tests/advisory_chat_wall.rs` and the desktop swarm paths ride
    /// the desktop tauri-shell suite.
    #[tokio::test]
    async fn chat_wall_success_path_records_zero_assistant_calls() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(config::ADVISORY_CONFIG_FILE),
            r#"{"assistant.enabled":true}"#,
        )
        .unwrap();
        // The hosted-model stand-in: the double plays the local backing
        // (never a real engine — the standing test discipline).
        let double = Arc::new(CountingTransport::assistant_echo("unused".into()));
        let (plane, gap) = AssistantPlane::spawn(
            dir.path(),
            None,
            Some(double.clone() as Arc<dyn AdvisoryTransport>),
        );
        assert_eq!(
            gap.as_str(),
            "not_hosting",
            "armed spawn reports no degrade"
        );
        let plane = plane.expect("the assistant plane arms over the double");

        let (tx, rx) = tokio::sync::watch::channel(false);
        let config = crate::NodeConfig {
            gateway_port: 0,
            data_dir: dir.path().to_path_buf(),
            profile_id: Some("msp1:wall".to_string()),
            mock: true,
            ..crate::NodeConfig::default()
        };
        let node = crate::Node::start(config, rx)
            .await
            .expect("node starts (mock runtime)");

        let addr = node.local_addr;
        let reply = reqwest::Client::new()
            .post(format!("http://{addr}/v1/chat/completions"))
            .json(&serde_json::json!({
                "model": "msp1:wall",
                "messages": [{"role": "user", "content": "say ok"}],
                "max_tokens": 8,
            }))
            .send()
            .await
            .expect("chat turn completes");
        assert!(
            reply.status().is_success(),
            "the mock runtime serves the turn"
        );

        // THE WALL: zero calls, zero bodies — the chat turn never
        // reached the assistant plane (W1).
        assert_eq!(
            double.count(),
            0,
            "W1: a chat turn NEVER calls the assistant plane"
        );
        assert!(double.bodies().is_empty());

        // Sensitivity control (non-vacuous zero): the SAME armed plane,
        // driven with an assistant turn, DOES call the double.
        let (telemetry, _sink) = modelswarm_telemetry::Telemetry::memory();
        let outcome = plane
            .run_turn(&telemetry, "which model fits?", vec![])
            .await;
        assert!(
            matches!(outcome, assistant::TurnOutcome::Reply { .. }),
            "the armed plane answers through the double"
        );
        assert_eq!(double.count(), 1, "the counter is alive");

        tx.send(true).unwrap();
        node.stopped().await;
    }

    /// The armed plane over an ERRORING double records honest gap rows —
    /// and ONLY `assistant.*` rows (the A3 filtered-stream discipline;
    /// counts and labels only, no reply text).
    #[tokio::test]
    async fn armed_plane_gaps_honestly_and_stays_in_its_own_rows() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(config::ADVISORY_CONFIG_FILE),
            r#"{"assistant.enabled":true}"#,
        )
        .unwrap();
        let double = Arc::new(CountingTransport::always_erroring());
        let (plane, _) = AssistantPlane::spawn(
            dir.path(),
            None,
            Some(double.clone() as Arc<dyn AdvisoryTransport>),
        );
        let plane = plane.expect("the assistant plane arms over the double");
        let (telemetry, sink) = modelswarm_telemetry::Telemetry::memory();
        let outcome = plane.run_turn(&telemetry, "hello?", vec![]).await;
        assert!(matches!(outcome, assistant::TurnOutcome::Gap { .. }));
        assert_eq!(double.count(), 1, "exactly one call — no in-turn retry");
        let rows = sink.snapshot().join("\n");
        assert!(rows.contains("\"event\":\"assistant.turn.gap\""));
        assert!(rows.contains("\"reason\":\"http_error\""));
        for line in sink.snapshot() {
            assert!(line.contains("\"event\":\"assistant."), "{line}");
        }
    }

    /// The shipped default data dir is the silent static floor (no
    /// advisory.json): `spawn` without hosting returns None with the
    /// honest `not_hosting` label — never an error, never a blank box.
    #[tokio::test]
    async fn default_data_dir_without_hosting_is_the_static_floor() {
        let dir = tempfile::tempdir().unwrap();
        let (plane, gap) = AssistantPlane::spawn(dir.path(), None, None);
        assert!(plane.is_none());
        assert_eq!(gap.as_str(), "not_hosting");
    }
}
