//! # `node-runtime` — the composition owner (M2, RD-006/007/008 core)
//!
//! The one place the pure contract crates and the platform crates are
//! composed (ADR-001 rule 3: platform crates never depend on each other).
//! It owns:
//!
//! * [`Node`] — drives the host AND controller `session` state machines
//!   with a real monotonic [`Clock`] and a [`TimerQueue`] matching the
//!   `World` semantics of `crates/session/tests/two_peers.rs` (message-id
//!   dedupe, simultaneous-call tie-break in all legal states,
//!   cancel/timeout paths), maps signaling envelopes and
//!   [`TransportEvent`]s into session events, and executes the returned
//!   `Action`s. One instance per role; no global state.
//! * [`signaling`] — the manual file-based signaling adapter (spike rig
//!   envelope format: `c2h.jsonl` / `h2c.jsonl`, atomic appends,
//!   offset-tracked reads, at-least-once delivery so the machines' dedupe
//!   is what proves idempotency) plus an in-memory hub for tests.
//! * [`input::InputPump`] — host-side input consumption against the real
//!   `input_windows::InputSink` trait: reliable-sequence gap detection →
//!   `AllKeysUp`, fast-channel stale suppression, disconnect safety.
//! * [`pacing::FramePacer`] — the M1 QA F20 fix: 60 Hz absolute-deadline
//!   pacing on a high-resolution waitable timer (57 → 60 fps).
//! * [`metrics`] — session-scoped JSONL counter sink (F6), bounded
//!   hand-off queues with F5 sampling, 1 Hz resource sampler.
//!
//! The rig (`examples/m2_rig.rs`) is the two-process gate binary: connect
//! → full-pipeline stream → scripted input under chaos → network-change
//! recovery → clean disconnect, with counters per
//! `docs/perf-counter-schema.md`.
//!
//! Invariants honored here: TURN never configured (the transport owns
//! that, the node requests nothing); SDP bodies and input payloads are
//! never logged (envelope JSON contains SDP — it is written to the
//! signaling files, never to logs or records); every queue bounded with a
//! counted drop policy.

pub mod clock;
pub mod input;
pub mod metrics;
pub mod node;
pub mod pacing;
pub mod signaling;
pub mod signaling_remote;
pub mod timers;

pub use clock::{Clock, ManualClock, MonotonicClock};
pub use node::{NoObserver, Node, NodeCounters, NodeObserver};
pub use signaling::{
    FileSignaling, HubEndpoint, InboundEnvelope, SignalingDirection, SignalingHub, SignalingIo,
};
pub use signaling_remote::{RemoteCounters, RemoteSignaling, RemoteSignalingConfig};
pub use timers::{FiredTimer, MachineKind, TimerQueue};
