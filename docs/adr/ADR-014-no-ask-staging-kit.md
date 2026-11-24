# ADR-014: The no-ask staging kit — a test-only build that skips the consent prompt

- Status: Accepted (owner request, 2026-11-24)
- Deciders: the user (owner), 2026-11-24 — "can you build another kit that
  doesn't require pressing 'Always allow this machine'?", with the standing
  design guideline "near no questions to the user, very few text, just
  buttons that do actions".
- Relates to: ADR-006 (the consent click as pairing ceremony, the
  prompt-flood defenses), ADR-008 (the updater), ADR-009 (every untrusted
  session hits the prompt), ADR-011 (admin posture and autostart, no
  per-command ceremony), ADR-013 (the P2 staging kit).

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
unproven consent request itself, as "Allow once" would (`commands.rs`, the
`ConsentRequested` arm; `build.rs`). Nothing in the request is inspected —
remote agent sessions (`AI_SESSION`) are accepted too.

`remember: false` is deliberate: the kit itself creates no trust. It
records no intent and sends no pairing ack, so nothing it does outlives
the session. (A "Always allow" intent a human armed earlier on that
machine is honored exactly as on any "Allow once".)

Under the same cfg the kit differs from an ordinary build in three more
ways, so a test run stays bounded and recognizable:

- **It never registers itself for logon** — no autostart default, no
  elevated-task refresh (`lib.rs`) — and it leaves an existing entry
  (the ordinary app's) exactly as it is. Closing the kit ends the exposure;
  a reboot does not bring it back.
- **It says what it is**: the window title reads
  "Remote Desktop — NO-ASK TEST KIT" and the tray tooltip says the same.
- **A failed accept falls back to the ordinary prompt path** (window
  raised, prompt recorded, flood defenses), as for any unproven request.

Boundaries:

1. **No runtime switch.** An installed app can never be talked into
   skipping consent — not by a setting, an env var, or a file.
2. **Ordinary builds are unchanged, and a test pins it.** `cargo test`
   refuses to pass in a kit build (`ordinary_builds_keep_the_consent_prompt`).
   That certifies the build the test runs in; CI never builds an installer.
3. **The public installer refuses the combination.** `build.rs` panics when
   `DEEPFLUX_STAGING_KIT=1` meets `DEEPFLUX_FAMILY_BUILD=1`. This closes the
   accidental route — a stray variable in a `scripts/build-family.sh` run.
   It does not stop a deliberate act: setting the variable while building
   an installer without the family flag, or passing the cfg by hand through
   `RUSTFLAGS`. A build script cannot prevent that. Possible hardening, not
   done: a build marker that `scripts/publish-landing.sh` refuses to publish.

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
  build refuses it (3), and a build without the variable cannot enable it
  (`rerun-if-env-changed` recompiles the crate when the variable changes;
  `cargo:rustc-cfg` applies to this package's own targets only).
- **The kit does not persist.** It never writes a logon entry. The one
  exception is a deliberate act from inside the kit: turning "launch at
  login" on in its own Settings registers the kit exe — do not.
- **A failed accept degrades to the ordinary prompt**, never to a silent
  refusal: the prompt path runs as for any unproven request.
- **Flood defenses are not exercised while the kit is accepting**: nothing
  prompts, so nothing is blocked. The kit is therefore not a valid build
  for testing the consent or flood paths themselves.
- **The update check still runs** in a kit; accepting an update installs
  the ordinary build over it — the safe direction.

## Consequences

- The live acceptance runs (two-NAT, account directory, fleet, agent
  control) can proceed without a human at the host.
- Machines running the kit must be test machines. The exposure lasts
  exactly as long as the kit is running.
- Found by the same runs, **not fixed here** (each is its own change):
  (a) the 60 s cooldown after an unanswered prompt never fires —
  `forward_event` compares `machine == "Host"` while the engine emits
  lowercase `"host"`, so only the 10-per-hour budget bounds an unanswered
  requester; (b) the 10 s controller wait against the 30 s host prompt
  leaves a stale prompt that a late click cannot satisfy.
- Reviewed independently (security review, 2026-11-24): no blocker, no
  major finding. Its findings — the logon-autostart hazard, the
  failed-accept fallback, and the over-strong claims in the first draft of
  this record — are what the three "differs" bullets and boundary 3 above
  now state.
