# ADR-015: Native computer use — the assistant operates its own screen

- Status: Accepted (owner request, 2026-11-27); revised the same day after
  an independent security review and a correctness review.
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
   buttons), `local_type_text` (Unicode, newline = Enter, at most 100
   lines / 4000 characters per call), `local_press_key` (named keys, one
   letter or digit, `modifiers` for shortcuts, `count` 1–3),
   `local_scroll` (notches, at a point or at the pointer), `local_drag`,
   `local_wait` (≤ 30 s). The unprefixed tools keep meaning "the OTHER
   machine in the live session"; every description of either set says
   which screen it acts on.
2. **Seeing = a GDI copy of the primary monitor**, converted by the pure
   helpers in `node_runtime::screenshot` (downscale to a 1600 px long
   edge, JPEG q80 — the same limits as the remote screenshot, so both
   address a comparable pixel space). Every call is a fresh picture; the
   result also names the pointer position. It is a one-shot copy for the
   model, not a `CaptureSource`, and never touches the real-time pipeline.
3. **Acting = the product's own injector.** Input goes through
   `input_windows::SendInputSink`, the invariant-7 trait implementation
   the host role already uses for remote control: wire-normalized
   coordinates, held-state tracking and the release-all safety path are
   the product's, not a second implementation. A fresh sink per tool call
   sits inside a drop guard that calls `release_all` — up to three times,
   since a key left down outlives the sink.
4. **The assistant never operates its own app.** Three guards, all inside
   the tool layer, all re-evaluated before every group of events a plan
   sends (the desktop can change under a running plan):
   - no click, drag or scroll aims inside a window of this process — its
     top-level windows and the popups owned by them (`WindowFromPoint`
     → `GA_ROOT` / `GA_ROOTOWNER` → owning pid); for a drag both ends
     count. The guard tests the pixel the sink will actually hit
     (`normalized_to_px`), not a rounded neighbour;
   - no typing and no keys while this app's window is in the foreground —
     except the chords that hand control to Windows itself (the bare Win
     key and Win chords, `ctrl+escape`, `alt+tab`), because that is how a
     task starts right after the human typed it into this app;
   - nothing at all while a consent prompt is on screen unanswered. The
     engine says whether a prompt is up (`host_state ==
     ConsentPrompted`); the trust state says whether it was answered.
   The window tools (`windows_list`, `window_focus`, `window_minimize`,
   `window_close`) no longer see this app's own windows either.
5. **Available to every turn, including remotely-woken ones.** Acting on
   THIS machine is what an instructed assistant is for; the origin guard
   (ADR-013 P3 FIX 1) is unchanged — `fleet_run` and `schedule` stay
   forbidden on Remote turns.
6. **A turn that can finish a desktop task.** Step budget 16 → 40; one
   extra request past the budget asks for a report instead of ending the
   turn with nothing to say; only the three newest screenshots stay as
   images in the replayed log; nothing is trimmed mid-turn, and a trimmed
   log restarts on a turn boundary. An instructed assistant that fails,
   that ends without an answer, that has no key, or whose turn could not
   even start (busy, wake budget spent) answers the machine that asked;
   the requester collects the answer with one blocking `chat_wait`
   instead of polling. `Clear` no longer waits on the UI thread for a
   running turn to end. The assistant's Base URL must be `https://` (or
   `http://` to this machine): every request carries the key and, now,
   pictures of the screen.

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
| The assistant clicks something destructive by mistake | Same authority it already has through `run_shell` and `fs_delete` (ADR-011): a misclick is not a new class of power. Tool calls stay on the audit rail (name + outcome — refusals as `denied`, failures as `error`). |
| A remote instruction drives this machine's own screen | Already true through shell and files on Remote turns (ADR-013 accepted residual). The guards in decision 4 hold for remote turns identically. What is genuinely new: a Remote turn, and anything on the screen that fools the model (prompt injection in a page or a dialog), can now also work a logged-in browser or mail client through its normal interface. That is the feature. |
| The assistant approves its own consent prompt | The prompt appears with the app window pulled to the front. From then on every further group of a running plan is refused (consent guard), so a queued Enter cannot land on "Allow once"; mouse aims inside the app's windows are refused outright. Residual: a single event group already handed to Windows in the instant the prompt appears. |
| Typing lands in the wrong window | Refused while this app is in front; elsewhere the next `local_screenshot` shows it. |
| Screen content reaches the model provider | Inherent in looking at the screen: a screenshot is sent as an image to the configured provider, as the remote screenshot already is. No image crosses Tauri IPC (invariant 1): the panel receives text only. |
| A locked workstation, the UAC secure desktop | `SendInput` cannot reach the secure desktop from any user process; a still capture shows the user's desktop. Not verified on a live locked machine. |
| A stuck modifier or button after a failed step | The drop guard calls `release_all`, up to three times. If Windows itself keeps refusing the release (secure desktop), the key stays down until a later local input or the session's all-keys-up. |
| A huge or corrupt screen metric, a runaway text | Capture refuses above 8K; the screenshot is capped at a 1600 px long edge; a typed text at 100 lines / 4000 characters per call. |
| A turn loops on GUI steps | 40 steps, then one report-only request; images in context capped at three. |

## Known limits

- **In-session replies are matched by position, not by id.** The live
  chat wire carries no correlation id (the sealed inbox does, for
  `fleet_run`). An ask of ours is read as answered by the next
  agent-authored line from that machine, for ten minutes
  (`ASK_REPLY_WINDOW_MS`); after that it is presumed lost and a later
  arrival is treated as the instruction it probably is. An instruction
  from the peer that arrives while our fresh ask is still unanswered is
  read as its answer. A wire-level marker would remove the ambiguity; it
  is a protocol change and needs its own decision.
- An agent-sent instruction is recorded as `"to-agent"` (like the human's
  own "address their assistant" line), so its answer is read as an
  answer and does not wake a new turn. The panel labels both the same
  way ("you → their assistant").
- `fleet_run` still collects replies for 90 s — short for a desktop task.
- A reply that has to fall back to the plain inbox (the session dropped
  mid-task) lands as a human-visible line; `chat_wait` does not see it.
- Some Win chords do act on the foreground window (Win+arrow snaps it).
  Snapping this app's own window is harmless and not prevented.

## Consequences

- The agent-to-agent desktop task that failed on 2026-11-25 has a direct
  path: look, click, type, look.
- A human asking their own assistant to do something visual on their own
  PC gets the same tools.
- Fixed alongside, from the same live test: command arguments were
  dropped silently unless their keys matched the Rust field names — the
  assistant key and Base URL never saved through the dialog (camelCase
  keys against snake_case fields). `tests/command_args_wire.rs` now reads
  `ipc.ts` and checks every typed command argument against the keys the
  frontend really sends. (Monitor selection was briefly suspected of the
  same bug and cleared: that call is snake_case on both sides.)
- The consent-timeout cooldown never ran (the engine names the role
  `host`, the caller compared with `Host`). It now runs for real timeouts
  only — a prompt the requester cancelled puts nobody on cooldown. The
  controller's request wait outlasts the host's 30 s consent prompt, so
  the whole window is usable and an unanswered prompt comes back as an
  explicit "no one answered".
- Not validated between two real machines at the time of writing: that
  needs the kit build and the owner's laptop.
