# ADR-015: Native computer use — the assistant operates its own screen

- Status: Accepted (owner request, 2026-11-27)
- Deciders: the user (owner) — 2026-11-27 "give it power, agent computer
  use"; the direction behind it, 2026-11-25: "the idea is that the agent
  takes the prompt from the human, send the prompt already re formated to
  the other agent … and the other agent executes the request, this is why
  the app needs native computer use".
- Relates to: ADR-004 (agent control, the remote `screenshot`/`click` tap),
  ADR-005 (the assistant loop), ADR-011 (the powerful agent — admin
  posture, full-machine tools), ADR-013 (P3 agent-to-agent routing).

## Context

Until now the assistant's eyes and hands were for the *other* machine
only: `screenshot`, `click`, `type_text`, `press_key`, `scroll` ride a
live remote session and address the peer's screen. On its own machine the
assistant had window tools, shell, files, processes — but could not see
its own desktop or click on it.

That is the wrong way round for the product's core flow (human → local
assistant → remote assistant executes on its own machine). The first live
agent-to-agent test on 2026-11-25 proved it: a shell task passed, and the
desktop task ("open Notepad and type") failed because the instructed
machine's assistant had no native way to operate its own screen. It fell
back to `run_shell` plus PowerShell `AppActivate`/`SendKeys`, got stuck
on a modal dialog its own attempt had raised, and both assistants ran out
of steps.

## Decision

1. **Seven own-screen tools**, named with a `local_` prefix so no model
   can confuse them with the session tools:
   `local_screenshot`, `local_click` (single / double / triple, three
   buttons), `local_type_text` (Unicode, any length, newline = Enter),
   `local_press_key` (named keys, one letter or digit, `modifiers` for
   shortcuts, `count` 1–3), `local_scroll` (notches, at a point or at the
   pointer), `local_drag`, `local_wait` (≤ 30 s). The unprefixed tools keep
   meaning "the OTHER machine in the live session"; every description of
   either set says which screen it acts on.
2. **Seeing = a GDI copy of the primary monitor**, converted by the pure
   helpers in `node_runtime::screenshot` (downscale to a 1600 px long
   edge, JPEG q80 — the same limits as the remote screenshot, so both
   address a comparable pixel space). Every call is a fresh picture; the
   result also names the pointer position.
3. **Acting = the product's own injector.** Input goes through
   `input_windows::SendInputSink`, the invariant-7 trait implementation
   the host role already uses for remote control: wire-normalized
   coordinates, held-state tracking and the release-all safety path are
   the product's, not a second implementation. A fresh sink per tool call
   sits inside a drop guard, so a step that fails half-way can never leave
   a modifier or a button held down.
4. **The assistant never operates its own app.** Three guards, all inside
   the tool layer:
   - no click, drag or scroll aim inside a window of this process
     (`WindowFromPoint` → root window → owning pid);
   - no typing while this app's window is in front — except the chords
     that hand control to Windows itself (Win and Win chords,
     ctrl+escape, alt+tab), because that is how a task starts right after
     the human typed it into this app;
   - nothing at all while a consent prompt is on screen unanswered.
   Consent and settings are the human's decisions.
5. **Available to every turn, including remotely-woken ones.** Acting on
   THIS machine is what an instructed assistant is for; the origin guard
   (ADR-013 P3 FIX 1) is unchanged — `fleet_run` and `schedule` stay
   forbidden on Remote turns.
6. **A turn that can finish a desktop task.** Step budget 16 → 40; one
   extra request past the budget asks for a report instead of ending the
   turn with nothing to say; the history cap holds a whole maximum-length
   turn; only the three newest screenshots stay as images in the replayed
   log. An instructed assistant that fails — or has no key — answers the
   machine that asked; the requester collects the answer with one blocking
   `chat_wait` instead of polling. An agent-sent instruction is recorded
   as "to-agent", so the answer is read as an answer, not as a new
   instruction.

## Non-goals

- The `--mcp` stdio bridge does not gain own-screen tools. It is a second,
  external-agent surface; widening it is a separate decision.
- Multi-monitor aiming: the primary monitor only, which is what
  `MonitorRect::primary()` confines the injector to as well.
- No OCR, no accessibility-tree reading, no element addressing. Pixels
  and keys, as a person at the keyboard.

## Failure analysis

| What can go wrong | Why it is bounded |
| --- | --- |
| The assistant clicks something destructive by mistake | Same authority it already has through `run_shell` and `fs_delete` (ADR-011): a misclick is not a new class of power. Tool calls stay on the audit rail (name + outcome). |
| A remote instruction drives this machine's own screen | Already true through shell and files on Remote turns (ADR-013 accepted residual). The guards in decision 4 hold for remote turns identically. |
| The assistant approves its own consent prompt | Mouse: the point lies in this app's window → refused. Keyboard: a consent prompt unanswered → refused. |
| Typing lands in the wrong window | Refused while this app is in front; elsewhere the next `local_screenshot` shows it, and `local_type_text` cannot submit the assistant's own box. |
| Screen content reaches the model provider | Inherent in looking at the screen: a screenshot is sent as an image to the configured provider, as the remote screenshot already is. No image crosses Tauri IPC (invariant 1): the panel receives text only. |
| A locked workstation, the UAC secure desktop | `SendInput` cannot reach the secure desktop from any user process; the capture shows the user's desktop, never the secure one. |
| A stuck modifier or button after a failed step | The drop guard calls `release_all` on every path. |
| A huge or corrupt screen metric | Capture refuses above 4096×4096; the screenshot is capped at a 1600 px long edge. |
| A turn loops on GUI steps | 40 steps, then one report-only request; images in context capped at three. |

## Consequences

- The agent-to-agent desktop task that failed on 2026-11-25 has a direct
  path: look, click, type, look.
- A human asking their own assistant to do something visual on their own
  PC gets the same tools.
- Two more bugs surfaced by the same live test are fixed alongside:
  command arguments were dropped silently unless their keys were camelCase
  (the assistant key and Base URL never saved; monitor selection from the
  UI was refused), and the consent-timeout cooldown never ran (the engine
  names the role `host`, the caller compared with `Host`). The controller's
  request wait now outlasts the host's 30 s consent prompt, so the whole
  window is usable and an unanswered prompt comes back as an explicit
  "no one answered".
- Not validated between two real machines at the time of writing: that
  needs the kit build and the owner's laptop.
