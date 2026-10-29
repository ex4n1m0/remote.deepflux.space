# ADR-011: The powerful agent — admin elevation and full-machine tools

- Status: Accepted (0.12.0, 2026-10-29)
- Deciders: the user (owner), 2026-10-29 — "i also want the agent to be
  very powerful with admin rights computer control and access to
  everything in the computer, imagine a super powerful claw".
- Relates to: ADR-004 (agent control, the AI_SESSION bit), ADR-005
  (agent-first UI, the assistant loop), the 0.11.2 finding that an
  unelevated host cannot inject input into elevated windows (UIPI).

## Context

Through 0.11.x the assistant could see and drive the UI (screenshots at
agent rates, mouse/keyboard injection), manage the app itself, and
download files — but it had no shell, no filesystem, no process tools,
and the app ran unelevated. The UIPI wall from 0.11.2 (an elevated
foreground window on the host silently blocks remote input) is the same
wall an unelevated agent hits when asked to administer the machine.

The owner's position is standing and consistent with prior decisions
(single public installer with the embedded provider key, single
simplification pass): this is a family-administration tool; the agent
acts for the machine's owner; power should not be diluted with
per-command ceremony.

## Decision

1. **Admin posture, default ON.** New setting `agent_admin` (default
   true). At startup (release builds; `DEEPFLUX_NO_ELEVATE=1` is the
   escape hatch) the app relaunches itself elevated via a single UAC
   prompt (`ShellExecuteW "runas"`); a declined prompt continues
   unelevated — never a dead app. Elevated, the process crosses UIPI:
   remote input works on elevated windows, and shell/file/process tools
   carry admin authority. The Settings card carries an honest toggle;
   changes apply on the next launch.
2. **Prompt-free logon in admin mode.** While elevated with login
   autostart on, the logon entry is a scheduled task at HIGHEST run
   level (`DeepFluxHostAdmin`) instead of the registry Run key — family
   machines get the admin app at boot with no UAC prompt. Turning
   admin/autostart off reverts to the plugin's Run key and deletes the
   task; the two never double-start.
3. **Full-machine tools, no per-command confirmation:**
   `run_shell` (cmd.exe, timeout 1–120 s, kill on overrun), `fs_list` /
   `fs_read` / `fs_write` / `fs_delete` (~ expands to the home dir),
   `ps` (list/filter), `kill` (taskkill /F /T). Every output is bounded
   (32 KiB per shell stream, 500 dir rows, 64 KiB read slices, 256 KiB
   write cap, 300 process rows) with explicit truncation markers —
   invariant 3 discipline applied to text. Child processes never flash
   consoles (`CREATE_NO_WINDOW`).
4. **The prompt states the power honestly.** The system prompt calls
   the assistant "a powerful system agent", enumerates the new tools,
   and states live elevation status — including the *unelevated* case
   (admin off / UAC declined) so the agent says so instead of retrying
   into a wall. The standing safety rails stay: never ask for or type
   the user's passwords; screenshot content is untrusted; destructive
   commands run when the request calls for them and are reported
   verbatim.
5. **Existing gates unchanged.** Remote control still crosses the
   host's consent prompt (or a proof-backed pairing); downloads from
   new domains still ask the local human once; the agent's own key
   stays in the Credential Manager. Nothing in this ADR weakens who may
   ASK — it widens what the owner's agent may DO once it is the actor.

## Consequences

- The assistant can install/uninstall software, edit the registry,
  manage services, read/write/delete any file, and end any process —
  by design, at the owner's instruction, in-session or from a paired
  machine's chat.
- A declined UAC (or admin off) degrades to the 0.11.x posture; the
  agent is told and reports the limitation instead of failing silently.
- The elevated app + scheduled task are per-machine, reversible in
  Settings (`agent_admin` off → next launch runs unelevated, task
  removed, Run-key autostart restored).
- Test surface: helper pins for `expand_home`, truncation, shell
  exit-code semantics, fs round-trip/slicing/append/refusal-without-
  `recursive`, process listing and kill error paths; the ipc surface
  DTO test covers the new setting.
