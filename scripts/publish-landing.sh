#!/usr/bin/env bash
# Landing publisher (ADR-008, 0.9.0): stage the built installer, mint the
# update manifest, and patch the landing page's version strings — ONE
# command, because hand-editing index.html was the stale-website trap.
#
#   scripts/publish-landing.sh [path-to-installer.exe] ["release notes"]
#
# Default installer: the newest target/release/bundle/nsis/*.exe. Notes
# come from the second argument or DEEPFLUX_RELEASE_NOTES (a placeholder
# ships if neither is set). After it runs, review
# `git diff apps/landing/index.html` + the new latest.json, commit them,
# then deploy:
#
#   cd apps/landing && vercel deploy --prod -S timedivision
#
# The exe itself is never committed (.gitignore) — latest.json is: it is
# the published update contract every installed client reads.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LANDING="$ROOT/apps/landing"

# -- locate the installer ----------------------------------------------------
EXE="${1:-}"
if [ -z "$EXE" ]; then
  EXE="$(
    find "$ROOT/target/release/bundle/nsis" -name '*-setup.exe' 2>/dev/null |
      while read -r f; do echo "$(stat -c %Y "$f") $f"; done |
      sort -rn | head -n 1 | cut -d' ' -f2-
  )"
fi
if [ -z "$EXE" ] || [ ! -f "$EXE" ]; then
  echo "error: no installer found — build one first (scripts/build-family.sh)" >&2
  echo "  or pass its path: scripts/publish-landing.sh /path/to/setup.exe" >&2
  exit 1
fi
EXE="$(cd "$(dirname "$EXE")" && pwd)/$(basename "$EXE")"

# Tauri names it "Remote Desktop_X.Y.Z_x64-setup.exe" (product with space).
BASE="$(basename "$EXE")"
if ! [[ "$BASE" =~ ^.*([0-9]+\.[0-9]+\.[0-9]+).*$ ]]; then
  echo "error: installer name has no X.Y.Z version: $BASE" >&2
  exit 1
fi
VERSION="${BASH_REMATCH[1]}"
# Guard the stale-artifact trap: the script must never re-stage an older
# build as "latest" (e.g. run before rebuilding after a version bump —
# it would mint a downlevel manifest AND delete the deployed exe).
WORKSPACE_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
if [ "$VERSION" != "$WORKSPACE_VERSION" ]; then
  echo "error: installer is $VERSION but the workspace says $WORKSPACE_VERSION." >&2
  echo "  Rebuild first (scripts/build-family.sh) or pass the right exe." >&2
  exit 1
fi
PUBLIC_NAME="Remote-Desktop-${VERSION}-x64-setup.exe"
echo "==> installer: $BASE"
echo "    version:   $VERSION -> download/$PUBLIC_NAME"

# -- stage + hash ------------------------------------------------------------
mkdir -p "$LANDING/download"
cp "$EXE" "$LANDING/download/$PUBLIC_NAME"
# One installer policy: only the newest stays public.
find "$LANDING/download" -name 'Remote-Desktop-*-x64-setup.exe' ! -name "$PUBLIC_NAME" -delete
SHA="$(sha256sum "$LANDING/download/$PUBLIC_NAME" | cut -d' ' -f1)"
SIZE="$(stat -c %s "$LANDING/download/$PUBLIC_NAME")"
MB="$(awk -v b="$SIZE" 'BEGIN { printf "%.1f", b / 1048576 }')"
echo "==> staged: $PUBLIC_NAME ($MB MB, sha256 ${SHA:0:12}…)"

# -- mint latest.json (the update contract, committed) -----------------------
# Release notes: second argument, or DEEPFLUX_RELEASE_NOTES. The default
# line below is only a placeholder so an unattended run never ships an
# empty banner — replace it per release.
NOTES="${2:-${DEEPFLUX_RELEASE_NOTES:-Release notes not set — see the website.}}"
cat > "$LANDING/latest.json" <<EOF
{
  "product": "remote-desktop",
  "version": "$VERSION",
  "url": "https://remote.deepflux.space/download/$PUBLIC_NAME",
  "sha256_hex": "$SHA",
  "size_bytes": $SIZE,
  "notes": "$NOTES",
  "published_at": "$(date -u +%F)"
}
EOF
echo "==> latest.json written (v$VERSION, notes: $NOTES)"

# -- patch the landing page (version + size strings) --------------------------
PAGE="$LANDING/index.html"
python - "$PAGE" "$VERSION" "$PUBLIC_NAME" "$MB" <<'PY'
import re, sys
page, version, public_name, mb = sys.argv[1:5]
with open(page, encoding="utf-8") as f:
    html = f.read()
# Filename (href + label), the v-beta pill, the bare version <b> label,
# and both size spellings ("~7.3 MB" and "~7.3&nbsp;MB").
html, n_name = re.subn(r"Remote-Desktop-[0-9.]+-x64-setup\.exe", public_name, html)
html, n_ver = re.subn(r"v[0-9]+\.[0-9]+\.[0-9]+ beta", f"v{version} beta", html)
html, n_plain = re.subn(r"<b>0\.[0-9]+\.[0-9]+ beta</b>", f"<b>{version} beta</b>", html)
html, n_size = re.subn(r"~[0-9.]+(&nbsp;|\x20)MB", f"~{mb}\\1MB", html)
missing = []
if n_name < 2: missing.append("download filename (want 2)")
if n_ver < 1: missing.append("vX.Y.Z beta pill (want 1)")
if n_plain < 1: missing.append("version <b> label (want 1)")
if n_size < 2: missing.append("size strings (want 2)")
if missing:
    sys.exit(f"error: landing page markers out of shape: {'; '.join(missing)} — fix index.html by hand")
with open(page, "w", encoding="utf-8", newline="\n") as f:
    f.write(html)
print(f"    index.html: {n_name} filename, {n_ver}+{n_plain} version, {n_size} size refs patched")
PY

echo "==> done. Next:"
echo "    git add apps/landing/latest.json && git commit -am \"release $VERSION: …\""
echo "    cd apps/landing && vercel deploy --prod -S timedivision"
