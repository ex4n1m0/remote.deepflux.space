# ADR-016: SSH power — the assistant runs commands on another machine directly

- Status: Accepted (owner request, 2026-11-28).
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
   (default 22), `shell` (`cmd`, the default: the server's own default
   shell; or `powershell`), `timeout_secs` (1–300, default 30).
2. **The OpenSSH client that ships with Windows is the transport.** The
   binary holds no SSH implementation and no unsafe for this. `ssh.exe`
   and `ssh-keygen.exe` are resolved from `SystemRoot\System32\OpenSSH`,
   never from `PATH`, and started with a direct argv — no local shell.
3. **The app's own key.** `<app data>\ssh\id_ed25519` (ed25519, no
   passphrase), made by the assistant worker on the first launch and
   never replaced — other machines may already allow it. The host keys
   live in `<app data>\ssh\known_hosts`, separate from the user's own.
4. **Nothing can make it prompt.** `BatchMode=yes` (no password
   authentication), `StrictHostKeyChecking=accept-new` (a first connection
   records the host key; a changed key is refused by ssh itself),
   `IdentitiesOnly=yes`, `ConnectTimeout=10`.
5. **The target is checked before any process exists.** The host may not
   start with `-` (ssh would read it as an option) and may contain only
   hostname/address characters; the login is passed with `-l`, not as a
   `user@host` string, and obeys the same rules. A command is one argv
   element of at most 8 000 characters; the `powershell` form travels
   base64-encoded (UTF-16, `-EncodedCommand`), so no quoting has to
   survive two shells.
6. **Not for remotely-woken turns.** `ssh_run` joins `fleet_run` and
   `schedule` in `REMOTE_FORBIDDEN_TOOLS`: a turn that another machine's
   assistant started is not advertised the tool and is refused at the
   dispatch boundary — it may act on this machine, not reach others.
7. **The `--mcp` bridge can drive the in-app assistant.** Two tools:
   `deepflux_prompt` hands in a prompt (the same call the panel's input
   box makes; refused when the assistant has no key or is busy) and
   `deepflux_assistant` reads back the latest events — the same events
   the panel shows, bounded to 200, with sequence numbers. The audit rail
   records that an external agent started a turn (actor `mcp-bridge`), as
   ever without the prompt text.
8. **Authorizing the key is not in the binary.** This ADR adds no setting,
   no dialog and no wire message that puts a key on another machine. A
   machine is reachable exactly when its SSH server already allows this
   machine's public key: allowing the key IS the grant. In the owner's
   test fleet the keys are placed by the kit's one-time setup script,
   outside the app.

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
| A command runs on the wrong machine | Only machines whose SSH server allows this machine's key are reachable — allowing the key is the grant. Within those it is the same authority `run_shell` has here (ADR-011), and on Windows an administrator's key is a full administrator shell with no UAC there. Tool name + outcome stay on the audit rail. |
| The model smuggles an ssh option in through `host` or `user` | A leading `-` is refused, and so is every character outside the hostname / login sets. The login goes through `-l`, the host is the only positional before the command. Checked before any process exists; unit-tested. |
| The command is re-parsed by a shell HERE | Never: one argv element to `ssh.exe`, no `cmd.exe` in between. On the far machine the command is run by its shell — that is the tool. |
| A password or host-key prompt hangs the assistant's only thread | `BatchMode=yes` and `accept-new` leave nothing to ask. The tool's own timeout (≤ 300 s) kills the process tree. |
| An impostor answers the first connection | Trust on first use: the first contact records the host key without checking it; every later change is refused. Residual on a hostile network. |
| The private key is stolen | It is a file in the user's profile, protected like the app's other data, without a passphrase. It opens exactly the machines that allowed it; they revoke it by removing one line. |
| Output floods memory or the context | The same pumps and caps as `run_shell`: at most 1 MiB stored per stream, 32 KiB of each reported. |
| A remotely-woken turn pivots to a third machine | `ssh_run` is neither advertised nor executed on a Remote turn (the FIX 1 boundary), covered by the existing test that walks `REMOTE_FORBIDDEN_TOOLS`. |
| The bridge's prompt tool gives an unelevated caller an elevated assistant | The stdio bridge exists only for the process that launched the app, and the elevation relaunch starts a fresh process through the shell (`elevate.rs`) without those pipes. |
| The bridge's transcript shows more than the panel | It holds exactly the panel's events: assistant messages, the first 160 characters of each tool result, errors. |
| The far command outlives a timed-out call | ssh is killed here; whether the far machine ends the command is up to its SSH server. Not verified live. |
| The far machine is not reachable | `ConnectTimeout=10`, then exit code 255 with a line saying what 255 means and where this machine's public key is. |

## Known limits

- **Not validated between two real machines at the time of writing.** The
  unit tests cover the pure parts (validation, the argv, the encoded
  PowerShell form, the key made once and kept) and the unit test that
  makes a key runs `ssh-keygen` for real.
- On Windows the `cmd` shell writes in the console code page, so accented
  text may come back mangled; the `powershell` shell sets UTF-8 first.
- A machine that has never been connected to is trusted on its first
  contact only (trust on first use). Pinning host keys would need a
  channel that is already trusted.
- Key exchange between machines is manual by design in this ADR. The
  natural next step is automatic exchange over an established session
  (the session is already the trust grant for agent-to-agent), which is a
  protocol change and needs its own decision.
- The test kit's setup script (outside the binary) enables the Windows
  SSH server and places public keys on a machine once, at install time.
  It lives in the private kit zip, never in the public executable.

## Consequences

- Plain machine work on another computer no longer needs a second
  assistant, a second API key, or a model turn on the far side.
- The ADR-015 path (instruct the far assistant, which uses its own
  `local_*` tools) stays the way to do anything visual there.
- An external agent driving the app through the bridge can run a whole
  assistant turn — hand in the prompt, read what happened — which is how
  the two- and three-machine tests are run without a human typing.
- `run_command` (the bounded process runner behind `run_shell`) is now
  shared with the SSH call.
