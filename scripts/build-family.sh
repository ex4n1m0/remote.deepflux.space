#!/usr/bin/env bash
# Family installer build (ADR-006). The ONLY sanctioned way to build an
# installer carrying the circle key.
#
#   scripts/build-family.sh
#
# What it does:
#   1. DEEPFLUX_AGENT_KEY  — taken from the environment (the assistant's
#      provider key; the public build embeds nothing).
#   2. DEEPFLUX_CIRCLE_KEY — read from ~/.deepflux/circle-key.txt; minted
#      (32 random bytes, hex) on first run and saved there. That file IS
#      the circle: whoever holds it can read the directory — never commit
#      it, never upload the built installer anywhere public.
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

echo "==> building FAMILY installer (embedded circle key + agent key)"
echo "    artifact: apps/desktop/src-tauri/target/release/bundle/nsis/"
echo "    NEVER publish this build — it carries the circle credential."
cd "$ROOT/apps/desktop"
DEEPFLUX_AGENT_KEY="${DEEPFLUX_AGENT_KEY:-}" \
DEEPFLUX_CIRCLE_KEY="$CIRCLE_KEY" \
DEEPFLUX_FAMILY_BUILD=1 \
  pnpm tauri build
