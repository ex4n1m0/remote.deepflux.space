# apps/desktop

Placeholder. The Tauri 2 + React/TypeScript product shell lands here in
**Milestone 4** (RD-011/RD-012, plan delta D1): one application, both roles
(This device / Control another device), favorites, monitor picker, quality
presets, and the diagnostics overlay driven by the `diagnostics` counter
schema.

Until then, milestones 0–3 are pure Rust engine work driven by tests and
diagnostic binaries. Rules that will apply from day one (AGENTS.md invariants
1 and 7): no frame bytes through Tauri IPC, React state, JSON, or canvas; the
native viewer window owns the frame path; the UI talks to the engine through
typed commands bound to the `session` state machines.
