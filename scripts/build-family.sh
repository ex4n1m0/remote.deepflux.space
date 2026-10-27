#!/usr/bin/env bash
# THE installer build (ADR-006 + its 2026-10-26 distribution addendum).
# One build exists: the family build with the embedded circle key. The
# user's decision (2026-10-26): this artifact is the public download —
# everyone installs it and auto-joins the circle; the keyless
# "public build" was discontinued. Accepted residuals live in the ADR
# addendum (key is extractable by any downloader; control still gated
# per-machine; rotation now means replacing the website's installer).
#
#   scripts/build-family.sh
#
# What it does:
#   1. DEEPFLUX_AGENT_KEY  — the assistant's provider key, read from
#      ~/.deepflux/agent-key.txt (chmod 600; the env var of the same name
#      OVERRIDES the file for one-off builds). File-backed on purpose: the
#      pre-0.8.0 script read only the env var, and every installer from
#      0.5.0 through 0.7.2 was silently built with an EMPTY embedded key
#      the moment the exporting shell session ended (root cause of the
#      "DeepSeek key missing on a fresh install" report, 2026-10-27).
#      The family build is the public download and must carry the key:
#      a missing key now FAILS the build unless explicitly overridden with
#      DEEPFLUX_ALLOW_NO_AGENT_KEY=1.
#   2. DEEPFLUX_CIRCLE_KEY — read from ~/.deepflux/circle-key.txt; minted
#      (32 random bytes, hex) on first run and saved there. That file IS
#      the circle: whoever holds it can read the directory — never commit
#      it to git, never paste it into logs or chat.
#   3. Builds with DEEPFLUX_FAMILY_BUILD=1 (build.rs refuses an embedded
#      circle key without this flag) via `pnpm tauri build`.
#
# Rotation (documented residual, ADR-006 §"Consequences"): minting a new
# key (delete the file) starts a FRESH circle namespace; the old one TTLs
# out server-side after 30 days. Pairings survive rotation — revoke them
# in Config → Trusted machines.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEYDIR="$HOME/.deepflux"
KEYFILE="$KEYDIR/circle-key.txt"
AGENTKEYFILE="$KEYDIR/agent-key.txt"

# The assistant key: env override first, then the persistent file. Never
# echoed — only its presence/shape is reported.
AGENT_KEY="${DEEPFLUX_AGENT_KEY:-}"
if [ -z "$AGENT_KEY" ] && [ -f "$AGENTKEYFILE" ]; then
  AGENT_KEY="$(tr -d '[:space:]' < "$AGENTKEYFILE")"
fi
if [ -z "$AGENT_KEY" ] && [ "${DEEPFLUX_ALLOW_NO_AGENT_KEY:-0}" != "1" ]; then
  echo "error: no assistant provider key found." >&2
  echo "  Put it in $AGENTKEYFILE (one line, chmod 600) — the same file" >&2
  echo "  discipline as the circle key. The family build IS the public" >&2
  echo "  download and ships WITH the key (user decision; the 0.5.0–0.7.2" >&2
  echo "  installers shipped empty and every fresh install hit the key" >&2
  echo "  prompt)." >&2
  echo "  To deliberately build circle-only, set DEEPFLUX_ALLOW_NO_AGENT_KEY=1." >&2
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
  echo "==> assistant provider key: ABSENT — deliberate circle-only build" >&2
fi

mkdir -p "$KEYDIR"
if [ ! -f "$KEYFILE" ]; then
  python - "$KEYFILE" <<'PY'
import secrets, sys
key = secrets.token_hex(32)
with open(sys.argv[1], "w") as f:
    f.write(key + "\n")
print(f"minted a NEW circle key -> {sys.argv[1]}")
print("This file is the circle invite. Back it up somewhere safe;")
print("losing it means minting a new circle (old entries expire in 30 days).")
PY
  chmod 600 "$KEYFILE"
fi

CIRCLE_KEY="$(tr -d '[:space:]' < "$KEYFILE")"
if [ ${#CIRCLE_KEY} -ne 64 ]; then
  echo "error: $KEYFILE does not hold a 64-hex key." >&2
  exit 1
fi

echo "==> building THE installer (family build: embedded circle key)"
echo "    artifact: target/release/bundle/nsis/"
echo "    This is the public download (user decision 2026-10-26): copy it to"
echo "    apps/landing/download/Remote-Desktop-<version>-x64-setup.exe and"
echo "    deploy. Still NEVER commit the exe or the key file to git."
cd "$ROOT/apps/desktop"
DEEPFLUX_CIRCLE_KEY="$CIRCLE_KEY" \
DEEPFLUX_FAMILY_BUILD=1 \
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
