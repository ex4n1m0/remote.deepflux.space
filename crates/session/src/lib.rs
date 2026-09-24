//! # `session` — deterministic host and controller state machines
//!
//! Both machines are pure decision functions: **no clocks, no network, no
//! threads**. The caller injects every event plus a logical `now_ms`; the
//! machine returns the actions the runtime must execute
//! ([`Action::Send`] envelopes, timer scheduling, local pipeline start/stop).
//! This is what makes the M0 gate possible: two simulated peers driven by a
//! scripted interleaving complete a full session deterministically
//! (`tests/two_peers.rs`).
//!
//! Dependency direction (ADR-001): this crate depends only on `protocol`.
//! It never touches a platform crate or an async runtime; wiring `Transport`,
//! `CaptureSource`, etc. into these decisions is the M2 runtime's job, behind
//! the actions returned here.
//!
//! Robustness rules baked in:
//! * duplicate `message_id` delivery is a no-op (idempotency, bounded log),
//! * every event not legal in the current state is a typed
//!   [`IllegalTransition`] error — never a silent ignore,
//! * simultaneous-call collisions resolve deterministically by device-id
//!   ordering (smaller id keeps the controller role).

pub mod common;
pub mod controller;
pub mod host;

pub use common::{Action, DisconnectCause, IllegalTransition, SessionConfig, TimerId};
pub use controller::{ControllerEvent, ControllerSession, ControllerState};
pub use host::{HostEvent, HostSession, HostState};
