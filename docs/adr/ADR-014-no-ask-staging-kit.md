# ADR-014: The no-ask staging kit — a test-only build that skips the consent prompt

- Status: Accepted (owner request, 2026-11-24)
- Deciders: the user (owner), 2026-11-24 — "can you build another kit that
  doesn't require pressing 'Always allow this machine'?", with the standing
  design guideline "near no questions to the user, very few text, just
  buttons that do actions".
- Relates to: ADR-006 (the consent click as pairing ceremony, the
  prompt-flood defenses), ADR-009 (every untrusted session hits the prompt),
  ADR-011 (no per-command ceremony), ADR-013 (the P2 staging kit).

## Context

The 2026-11-23/24 live runs of the staging kit (ADR-013 P2) could not
complete a single session. The kit exe ran on both machines, the host
showed its consent prompt every time, and every prompt expired unclicked:
the controller abandons a request after 10 s (`request_timeout_ms`) while
the host keeps the prompt for 30 s (`consent_timeout_ms`), and nobody was
at the host inside that 10 s window. The two prompt-free paths that exist
— a proven pairing ("Always allow this machine") and account trust — both
begin with exactly one such click, so an owner who cannot reach the host
has no way to test.

## Decision

A **compile-time, test-only build**: `DEEPFLUX_STAGING_KIT=1` at build
time sets `cfg(deepflux_staging_kit)`, and with it the host answers every
unproven consent request itself, as "Allow once" would
(`commands.rs`, the `ConsentRequested` arm; `build.rs`). `remember: false`
is deliberate — the kit never asks and never remembers, so no trust
outlives the session and the machine's pairings stay untouched.

Boundaries, all enforced in code rather than by convention:

1. **No runtime switch.** An installed app can never be talked into
   skipping consent — not by a setting, an env var, or a file.
2. **Never the public installer.** `build.rs` panics when
   `DEEPFLUX_STAGING_KIT=1` is combined with `DEEPFLUX_FAMILY_BUILD=1`.
3. **Ordinary builds are pinned by a test.** `cargo test` refuses to pass
   in a kit build (`ordinary_builds_keep_the_consent_prompt`), so CI can
   only ever certify builds that keep the prompt.

The kit is built by `.github/workflows/staging-kit.yml` (push to `kit/**`
or by hand), keyless and without the NSIS bundle, by the same
`pnpm tauri build` entry point as `scripts/build-family.sh`.

## Failure analysis

- **Anyone holding a connection code can control a kit machine** — that
  is the accepted property of this build, and why the artifact is for the
  owner's test machines only. It must never be published on the landing
  (`scripts/publish-landing.sh` and `apps/landing/download/` are for
  installer builds).
- **A stray env var cannot leak the behavior into a release**: the family
  build refuses it (2), and a build without the env var cannot enable it
  (`rerun-if-env-changed` recompiles the crate when the variable changes).
- **A failed accept degrades to the ordinary prompt**, not to a silent
  refusal: the arm reports `proof_ok = false` and the window shows the
  normal dialog, the same contract as the paired and account arms.
- **Flood defenses are not exercised in the kit**: with no prompts there is
  no prompt budget to spend, and nothing is blocked. The kit is therefore
  not a valid build for testing the consent or flood paths themselves.

## Consequences

- The live acceptance runs (two-NAT, account directory, fleet, agent
  control) can proceed without a human at the host.
- Machines running the kit must be test machines, powered off or restored
  to an ordinary build after the run.
- Found by the same runs, **not fixed here** (each is its own change):
  (a) the 60 s cooldown after an unanswered prompt never fires —
  `forward_event` compares `machine == "Host"` while the engine emits
  lowercase `"host"`, so only the 10-per-hour budget bounds an unanswered
  requester; (b) the 10 s controller wait against the 30 s host prompt
  leaves a stale prompt that a late click cannot satisfy.
