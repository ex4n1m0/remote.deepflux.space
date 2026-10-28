# remote.deepflux.space — landing page

Static single-page site for the P2P remote desktop. Zero framework, zero build step:
`index.html` + `download/` is the whole site; Vercel serves it as-is.

## Live

- Domain: https://remote.deepflux.space (Vercel project `remote-landing`, team `timedivision`)
- Subdomain of `deepflux.space` (Vercel-registered, Vercel DNS — no manual DNS records needed)

## Deploying an update

There is ONE installer: the family build with the embedded circle key
(`scripts/build-family.sh`; user decision 2026-10-26, ADR-006 distribution
addendum). The website hosts it — that auto-join is the distribution model.

```bash
# 1. build the installer — REQUIRES ~/.deepflux/agent-key.txt (the build
#    fails without it; since 0.8.0 the key is file-backed exactly like the
#    circle key, never a transient env var)
scripts/build-family.sh

# 2. stage it + mint the update manifest + patch this page's version/size
#    strings (ADR-008: one command — hand-editing index.html was the
#    stale-website trap). Stages download/Remote-Desktop-X.Y.Z-x64-setup.exe
#    (deleting older ones), writes latest.json, patches index.html. The
#    script REFUSES if the installer's version ≠ the workspace version.
#    Release notes: second arg (or DEEPFLUX_RELEASE_NOTES).
scripts/publish-landing.sh target/release/bundle/nsis/"Remote Desktop_X.Y.Z_x64-setup.exe" \
  "What's new in one line."

# 3. review the diff (latest.json + index.html), commit, deploy
git add latest.json
git commit -am "release X.Y.Z: …"
vercel deploy --prod -S timedivision
```

`latest.json` IS the update contract installed clients read (ADR-008):
product/version/url/sha256/size. Shipping an exe without a matching
manifest means every installed 0.9.0+ silently stays on its old version —
never hand-copy an installer here again.

Notes:
- Attach a new subdomain with `vercel domains add <sub>.deepflux.space remote-landing`
  (NOT `vercel alias set` — a bare alias leaves the domain unverified and Vercel serves
  it behind SSO authentication; the domains-add flow is what makes it public).
- The download link, version label, size, and the "know what you're installing" fineprint
  live in `index.html` — `scripts/publish-landing.sh` keeps them in sync with the shipped
  build (marker-shaped; if it errors, fix the page by hand).
- Rotation blast radius (ADR-006 addendum): minting a new circle key means a new
  installer replaces this download; old installs keep the old key and their circle
  TTLs out after 30 days. Pre-0.9.0 machines must reinstall to rejoin; 0.9.0+
  get the new installer through the in-app updater (one press each).
- Unsigned-beta disclaimer stays until code signing exists (post-MVP item).
