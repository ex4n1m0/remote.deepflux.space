# ADR-016: SSH power — the assistant runs commands on another machine directly

- Status: Accepted (owner request, 2026-11-28); revised the same day after
  an independent security review and a correctness review, and after the
  first CI run.
- Deciders: the user (owner) — 2026-11-28 "could you give SSH power to our
  client, so that it gives the same type of remote power control", then
  "yes add it as a tool to the client".
- Relates to: ADR-004 (the `--mcp` agent bridge), ADR-005 (the assistant
  loop), ADR-011 (the powerful agent — admin posture, full-machine tools),
  ADR-013 (P3: the turn-origin guard and the audit rail), ADR-014 (the
  no-ask staging kit), ADR-015 (own-screen tools and agent-to-agent).

## Context

The assistant could already run a command on another machine, but only
through the assistant running THERE: `connect` → `chat_send(to_agent=true)`
→ the far assistant wakes and runs `run_shell` → `chat_wait` for the
answer. The first live run of that path (2026-11-25) took one to two
minutes for a single `echo`, and it needs the app running on the far
machine, an API key configured there, and a model turn on every hop.

Most of what a human asks for on another machine is plain machine work —
files, services, configuration, logs. That needs the exact output of an
exact command, not a second assistant's summary of it.

## Decision

1. **One tool, `ssh_run`.** It runs one command on another machine over
   SSH and returns the same report shape as `run_shell`: exit code, capped
   stdout, capped stderr. Arguments: `host` (hostname or IP), `command`,
   and optional `user` (default: this Windows account's name), `port`
   (default 22; anything but a whole number is refused), `shell` (`cmd`,
   the default: the server's own default shell; `powershell`; anything
   else is refused), `timeout_secs` (1–300, default 30).
2. **The OpenSSH client that ships with Windows is the transport.** The
   binary holds no SSH implementation and no unsafe for this. `ssh.exe`
   and `ssh-keygen.exe` are resolved from `SystemRoot\System32\OpenSSH`,
   never from `PATH`, and started with a direct argv — no local shell.
   The client runs with `-F none`: no config file of this machine is
   read, and every option is pinned on the command line — one identity
   file, no agent, no GSSAPI, no forwarding, no proxy, no local command,
   one host-key type, no host-key updates — and `--` ends the options
   before the host. (Checked on the shipped client 9.5.6 with `ssh -G`.)
3. **The app's own key.** `<app data>\ssh\id_ed25519` (ed25519, no
   passphrase), made by the assistant worker on the first launch and
   never replaced — other machines may already allow it. A lost public
   half is remade from the private key; the folder never falls back to
   the temp directory. The host keys live in
   `<app data>\ssh\known_hosts`, separate from the user's own.
4. **Nothing can make it prompt, and a first contact is said out loud.**
   `BatchMode=yes` (no password authentication),
   `StrictHostKeyChecking=accept-new`, `IdentitiesOnly=yes`,
   `IdentityAgent=none`. A host key is only accepted from a machine that
   is not in `known_hosts` yet, or matches what is recorded there; a
   changed key is refused by ssh itself, and with
   `HostKeyAlgorithms=ssh-ed25519` there is no second key type an impostor
   could offer instead. A first contact is noted after the output
   (`FIRST CONTACT`), and as a warning when its entry could not be
   recorded (then every connection to it is a first contact). The report's
   first line stays the runner's, because the audit rail judges a tool by
   its first line: a note that came first, with the word "refused" in it,
   had the first live run recorded as `denied`.
   `ServerAliveInterval` ends a dead link early.
5. **The target is checked before any process exists.** The host may not
   start with `-` (ssh would read it as an option) and may contain only
   hostname/address characters; the login is passed with `-l`, not as a
   `user@host` string, and obeys the same rules. A command is one argv
   element of at most 8 000 characters; the `powershell` form travels
   base64-encoded (UTF-16, `-EncodedCommand`, `-OutputFormat Text`), so no
   quoting has to survive two shells, and is refused when that encoded
   form would not fit the far `cmd.exe` line. A refusal never quotes what
   was refused — tool text reaches the audit rail's outcome.
6. **Not for remotely-woken turns — at the tool level.** `ssh_run` joins
   `fleet_run` and `schedule` in `REMOTE_FORBIDDEN_TOOLS`: a turn that
   another machine's assistant started is neither advertised the tool,
   told about it in the system prompt, nor allowed past the dispatch
   boundary. This is the ADR-013 guard and it has the ADR-013 limit: such
   a turn still has `run_shell`, and the app's key sits at a known path,
   so `run_shell` with `ssh.exe -i` is the same pivot. As ADR-013 records
   it, the origin guard is a model-behavior guardrail, not a sandbox;
   confining a remote turn's exec surface is the open P5 item.
7. **The `--mcp` bridge can drive the in-app assistant.** Two tools:
   `deepflux_prompt` hands in a prompt (the same call the panel's input
   box makes; refused when the assistant has no key or is busy) and
   returns the sequence number the turn's events will start at;
   `deepflux_assistant` reads back the latest events — what the panel is
   shown, except typed prompts — bounded to 200, numbered, read from a
   sequence number on (inclusive), cleared with
   the panel. A `done` event ends a turn; `busy` alone is no start or end
   signal. The audit rail records that an external agent started a turn
   (actor `mcp-bridge`), as ever without the prompt text. The panel shows
   such a prompt like a typed one; the audit rail is what tells them
   apart. Such a turn runs with the LOCAL user's full authority — the
   launching process's own authority, since stdio exists only for the
   process that started the app and the elevation relaunch
   (`elevate.rs`: a fresh process started through the shell) does not
   carry those pipes. That last point is relied on from how the relaunch
   is written; it has not been exercised live.
8. **Authorizing the key is not in the binary.** This ADR adds no setting,
   no dialog and no wire message that puts a key on another machine. A
   machine is reachable when its SSH server allows this machine's public
   key and nothing else is offered: allowing the key IS the grant. In the
   owner's test fleet the keys are placed by the kit's one-time setup
   script, outside the app.

## Non-goals

- No key exchange between machines. It needs a wire change (or a tailnet)
  and is a separate decision (see Known limits).
- No host or login discovery: the model is told the hostname or address,
  and the login when it differs from this account's name.
- No file copy, no agent forwarding, no passphrases, no interactive
  sessions, no tunnels.
- No router crossing: plain TCP to an SSH port, so one network.

## Failure analysis

| What can go wrong | Why it is bounded |
| --- | --- |
| A command runs on the wrong machine | Only machines whose SSH server allows this machine's key are reachable, and only that key is offered (no config file, no agent). Within those it is the same authority `run_shell` has here (ADR-011), and on Windows an administrator's key is a full administrator shell with no UAC there. Tool name + outcome stay on the audit rail: a failed connection and a timeout begin with `ssh_run failed`, so they are recorded as errors, not as `ok`. The rail does not record WHICH machine was addressed (ADR-013: no arguments in the log) — see Known limits. |
| The model smuggles an ssh option in through `host` or `user` | A leading `-` is refused, and so is every character outside the hostname / login sets; `--` ends the options before the host, and the login goes through `-l`. Checked before any process exists; unit-tested. |
| The command is re-parsed by a shell HERE | Never: one argv element to `ssh.exe`, no `cmd.exe` in between, no config file. On the far machine the command is run by its shell — that is the tool. |
| Something on this machine re-routes the connection | `-F none`: neither the user's nor the system's ssh config is read. Proxy, jump, local command, forwarding and GSSAPI are each pinned off. |
| A password or host-key prompt hangs the assistant's only thread | `BatchMode=yes` and `accept-new` leave nothing to ask. The tool's own timeout (≤ 300 s) kills the process tree, with `taskkill.exe` taken from `System32`, not from the app's folder. |
| An impostor answers the first connection | Trust on first use. The first contact is announced in the report; an entry that could not be written is a warning. Afterwards an offered key must match the recorded one, and only one key type is ever accepted. Residual: the very first connection to a machine, on a network where someone can answer for it. |
| An impostor takes over a PINNED machine | It would have to present the recorded ed25519 key itself; another key type is not negotiated. |
| The private key is stolen | It is a file in the user's profile, protected like the app's other data, without a passphrase. It opens exactly the machines that allowed it; they revoke it by removing one line. |
| Output floods memory or the context | The same pumps and caps as `run_shell`: at most 1 MiB stored per stream, 32 KiB of each reported. stdout and stderr are now labelled by stream, not by which arrived first. |
| Remote output talks the assistant into something | The system prompt tells the model that what comes back over `ssh_run` is untrusted, like screen content. |
| A remotely-woken turn pivots to a third machine | `ssh_run` is neither advertised nor executed on a Remote turn (the FIX 1 boundary). A Remote turn keeps `run_shell`, which can run `ssh.exe` itself — the ADR-013 accepted residual, unchanged in kind. |
| The bridge's prompt tool gives an unelevated caller an elevated assistant | The stdio bridge exists only for the process that launched the app, and the elevation relaunch starts a fresh process through the shell (`elevate.rs`) without those pipes. Relied on, not exercised live. |
| The bridge's transcript shows more than the panel | It holds the panel's events — assistant messages, peer-agent and scheduled-task instruction bodies, the first 160 characters of each tool result, errors — and, unlike the panel, no typed prompts. It is cleared with the panel. |
| The far command outlives a timed-out call | ssh is killed here; the report says the command may still be running there. Whether the far machine ends it is up to its SSH server. Not verified live. |
| The far machine is not reachable | `ConnectTimeout=10`, then a report that starts with `ssh_run failed`, says what happened and where this machine's public key is. |
| A key is left half-made or without its public half | Made under a temporary name and renamed into place; leftover temporaries are swept before a new key is made; a lost public half is remade from the private key; a key whose public half cannot be published is withdrawn again. |

## Known limits

- **Not validated between two real machines at the time of writing.** The
  unit tests cover the pure parts — validation, the argv, the encoded
  PowerShell form and its own length bound, the report framing, the key
  made once and its public half remade (`ssh-keygen` runs for real) — and
  the option list was checked against the shipped client's own
  configuration dump (`ssh -G`, 9.5.6).
- The client must understand `-F none`. It does on 9.5.6; older clients
  shipped with early Windows 10 were not tried.
- Only `ssh-ed25519` host keys are accepted: a server with none is
  unreachable (the report says so).
- On Windows the `cmd` shell writes in the console code page, so accented
  text may come back mangled; the `powershell` shell sets UTF-8 first.
- The `powershell` form of a command is refused when its encoded form
  would not fit the far `cmd.exe` line (roughly beyond 2 900 characters).
- On a timeout the partial output is empty: the runner reads each stream
  to its end before it reports.
- Key exchange between machines is manual by design in this ADR. The
  natural next step is automatic exchange over an established session
  (the session is already the trust grant for agent-to-agent), which is a
  protocol change and needs its own decision.
- The audit rail records that `ssh_run` ran and how it ended, not which
  machine it addressed. Whether a destination belongs on the rail or on
  the panel's tool line is a policy question for the owner (ADR-013 keeps
  arguments out of the log).
- A prompt from the bridge looks like a typed one in the panel.
- Other places that start a Windows tool by bare name (`schtasks` at an
  elevated launch, the winget helpers) are outside this ADR; `taskkill`
  was changed here only because the SSH timeout path uses it.
- The test kit's setup script (outside the binary) enables the Windows
  SSH server and places public keys on a machine once, at install time.
  It lives in the private kit zip, never in the public executable.

## Consequences

- Plain machine work on another computer no longer needs a second
  assistant, a second API key, or a model turn on the far side.
- The ADR-015 path (instruct the far assistant, which uses its own
  `local_*` tools) stays the way to do anything visual there.
- An external agent driving the app through the bridge can run a whole
  assistant turn — hand in the prompt, wait for its `done` event, read
  what happened — which is how the two- and three-machine tests are run
  without a human typing.
- `run_command` (the bounded process runner behind `run_shell`) is shared
  with the SSH call, and now labels the two streams by stream.
