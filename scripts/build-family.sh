#!/usr/bin/env bash
# THE installer build (ADR-009, 2026-10-29: one build, one embedded secret —
# the assistant provider key). The circle key and its embedding machinery
# were retired with the circle directory; there is no family/public split
# anymore, just this script.
#
#   scripts/build-family.sh
#
# What it does:
#   1. DEEPFLUX_AGENT_KEY — the assistant's provider key, read from
#      ~/.deepflux/agent-key.txt (chmod 600; the env var of the same name
#      OVERRIDES the file for one-off builds). File-backed on purpose: the
#      pre-0.8.0 script read only the env var, and every installer from
#      0.5.0 through 0.7.2 was silently built with an EMPTY embedded key
#      the moment the exporting shell session ended (root cause of the
#      "DeepSeek key missing on a fresh install" report, 2026-10-27).
#      The installer is the public download and must carry the key: a
#      missing key FAILS the build unless explicitly overridden with
#      DEEPFLUX_ALLOW_NO_AGENT_KEY=1.
#   2. Builds via `pnpm tauri build`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEYDIR="$HOME/.deepflux"
AGENTKEYFILE="$KEYDIR/agent-key.txt"

# The assistant key: env override first, then the persistent file. Never
# echoed — only its presence/shape is reported.
AGENT_KEY="${DEEPFLUX_AGENT_KEY:-}"
if [ -z "$AGENT_KEY" ] && [ -f "$AGENTKEYFILE" ]; then
  AGENT_KEY="$(tr -d '[:space:]' < "$AGENTKEYFILE")"
fi
if [ -z "$AGENT_KEY" ] && [ "${DEEPFLUX_ALLOW_NO_AGENT_KEY:-0}" != "1" ]; then
  echo "error: no assistant provider key found." >&2
  echo "  Put it in $AGENTKEYFILE (one line, chmod 600). The installer is" >&2
  echo "  the public download and ships WITH the key (user decision; the" >&2
  echo "  0.5.0–0.7.2 installers shipped empty and every fresh install hit" >&2
  echo "  the key prompt)." >&2
  echo "  To deliberately build keyless, set DEEPFLUX_ALLOW_NO_AGENT_KEY=1." >&2
  exit 1
fi
if [ -n "$AGENT_KEY" ]; then
  # Shape sanity without printing it: provider keys are 20+ chars, no
  # whitespace (the tr above already stripped it).
  if [ "${#AGENT_KEY}" -lt 20 ]; then
    echo "error: $AGENTKEYFILE does not look like a provider key (too short)." >&2
    exit 1
  fi
  export DEEPFLUX_AGENT_KEY="$AGENT_KEY"
  echo "==> assistant provider key: present (${#AGENT_KEY} chars, never echoed)"
else
  echo "==> assistant provider key: ABSENT — deliberate keyless build" >&2
fi

echo "==> building THE installer"
echo "    artifact: target/release/bundle/nsis/"
echo "    This is the public download: copy it to"
echo "    apps/landing/download/Remote-Desktop-<version>-x64-setup.exe and"
echo "    deploy. Still NEVER commit the exe or the key file to git."
cd "$ROOT/apps/desktop"
pnpm tauri build

# Post-build assertion (0.8.0): the 0.5.0–0.7.2 regression was a silently
# EMPTY embedded key. Assert the artifact actually holds one — by checking
# the OUT_DIR file build.rs wrote for THIS release profile, newest first,
# and comparing its length against the key we passed. Never prints the key.
if [ -n "${DEEPFLUX_AGENT_KEY:-}" ]; then
  OUTTXT="$(
    find "$ROOT/target/release" -path '*build/*/out/agent_key.txt' 2>/dev/null |
      while read -r f; do echo "$(stat -c %Y "$f") $f"; done |
      sort -rn | head -n 1 | cut -d' ' -f2-
  )"
  if [ -z "$OUTTXT" ] || [ ! -s "$OUTTXT" ]; then
    echo "error: build finished but the embedded agent key is EMPTY or missing" >&2
    echo "  (checked: ${OUTTXT:-<no agent_key.txt under target/release>})." >&2
    echo "  Do not ship this artifact — inspect build.rs rerun behavior and rebuild." >&2
    exit 1
  fi
  # build.rs writes the env var verbatim: byte length must equal the key's.
  BYTES="$(wc -c < "$OUTTXT" | tr -d '[:space:]')"
  if [ "$BYTES" -ne "${#DEEPFLUX_AGENT_KEY}" ]; then
    echo "error: embedded agent key length $BYTES != supplied key length ${#DEEPFLUX_AGENT_KEY}" >&2
    echo "  (a stale OUT_DIR file from an earlier build was likely picked up —" >&2
    echo "  cargo clean -p remote-desktop-app and rebuild). Do not ship." >&2
    exit 1
  fi
  echo "==> embedded agent key verified (length ${BYTES}, value never echoed)"
fi
