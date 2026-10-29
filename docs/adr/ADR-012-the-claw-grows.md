# ADR-012: The claw grows — applications, power, search, scheduling, windows

- Status: Accepted (0.13.0, 2026-10-30)
- Deciders: the user (owner), 2026-10-29 — "what other powers … could we
  give to this super claw?" followed by "ok do it in that order and have
  all the related agents help you confirm on the way, take it slow and
  always check everything several times."
- Extends: ADR-011 (the powerful agent: elevation + shell/files/
  processes). Same trust model — the consent prompt gates who may ask;
  inside, the owner's agent acts without per-command ceremony.

## Context

After 0.12.0 the agent had shell, filesystem, and process tools. The
owner asked for a survey of further powers; the agreed menu, in build
order (his "in that order"):

- **Release A (0.13.0):** application management, power control, file
  search.
- **Release B (0.14.0):** scheduling (the agent runs unattended and
  reports by chat), window management.

Skipped/deferred (survey, not ordered): browser automation (Deeptorrent
prior art, its own project), Windows Update verbs (run_shell covers the
 interim), startup-entry manager, fleet fan-out, volume/clipboard/TTS.

## Decision

1. **Dedicated tools where raw shell is flaky, structured, or needs app
   help — not ceremony.** winget's interactive prompts and unbounded
   runtimes, structured inventories, and anything that must wake the
   agent itself justify tools; everything else stays a `run_shell` away.
2. **Release A tools (0.13.0):**
   - `apps_list` (native registry inventory over the three Uninstall
     hives — no winget dependency, no parsing fragility),
     `app_search` / `app_install` / `app_uninstall` / `app_upgrade`
     (winget with `--silent --disable-interactivity
     --accept-package-agreements --accept-source-agreements`, long
     tool-specific timeouts, capped output; winget-missing is reported
     as an actionable answer, not a hang).
   - `power` (`restart|shutdown|sleep|lock|signout`, `delay_secs`
     default 10, max 300) and `power_cancel` (`shutdown /a`) — every
     restart/shutdown carries an abort window; sleep notes the
     hibernate caveat; lock is immediate.
   - `search` (name and/or content, case-insensitive, native walker,
     reparse points skipped, 2 MiB per file for content matches,
     default 200 / cap 500 results, wall-clock cap with an honest
     "stopped early" report).
3. **Release B tools (0.14.0):** `windows_list` / `window_focus` /
   `window_minimize` / `window_close` (EnumWindows surface), and
   `schedule` / `schedule_list` / `schedule_remove` — Task Scheduler
   entries that relaunch the app with `--agent-task=<name>`; the stored
   instruction runs as one assistant turn and the result is reported by
   chat to every paired machine (visible trail of what the claw did
   unattended).
4. **Process:** each release ships only after the standing reviewer
   pass (rd-code-reviewer on the diff; security-reviewer on the
   power/surface changes) and two full merge-gate runs — the owner's
   "take it slow and always check everything several times."

## Consequences

- The agent can install, remove, and update software, reboot the
  machine (with an abort window), and find files by content — the core
  family-administration verbs — without the model hand-writing shell
  incantations for them.
- Power actions end sessions by nature (the machine goes down); the
  delay + cancel window is the safety margin, and the prompt tells the
  agent to announce before acting.
- Scheduled runs act with nobody asking: every run reports to all
  paired machines by chat, so unattended action always leaves a trail.
- Native Win32 surface added: registry enumeration (release A),
  EnumWindows/SetForegroundWindow/ShowWindow (release B) — reviewed
  unsafe in `apps/desktop` per the standing scope note.
