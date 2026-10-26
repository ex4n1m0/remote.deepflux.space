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
#   1. DEEPFLUX_AGENT_KEY  — taken from the environment (the assistant's
#      provider key; omit it for a circle-only build where each machine
#      pastes its own assistant key).
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
# in Settings → Trusted machines.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEYDIR="$HOME/.deepflux"
KEYFILE="$KEYDIR/circle-key.txt"

# The assistant key is OPTIONAL: without it this is a circle-only family
# build (machines join the circle automatically; the assistant asks for a
# pasted key on first use). With it, family machines are fully zero-config.
if [ -z "${DEEPFLUX_AGENT_KEY:-}" ]; then
  echo "note: DEEPFLUX_AGENT_KEY is not set - building CIRCLE-ONLY (the" >&2
  echo "      assistant will ask each machine for an API key)." >&2
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
DEEPFLUX_AGENT_KEY="${DEEPFLUX_AGENT_KEY:-}" \
DEEPFLUX_CIRCLE_KEY="$CIRCLE_KEY" \
DEEPFLUX_FAMILY_BUILD=1 \
  pnpm tauri build
