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

# 2. stage it under the public filename (NOT committed to git — build artifact;
#    the key file itself never leaves ~/.deepflux)
cp "target/release/bundle/nsis/Remote Desktop_X.Y.Z_x64-setup.exe" \
   "download/Remote-Desktop-X.Y.Z-x64-setup.exe"   # bump filename + page link + size

# 3. deploy
vercel deploy --prod -S timedivision
```

Notes:
- Attach a new subdomain with `vercel domains add <sub>.deepflux.space remote-landing`
  (NOT `vercel alias set` — a bare alias leaves the domain unverified and Vercel serves
  it behind SSO authentication; the domains-add flow is what makes it public).
- The download link, version label, size, and the "know what you're installing" fineprint
  live in `index.html` — keep them in sync with the actual shipped build.
- Rotation blast radius (ADR-006 addendum): minting a new circle key means a new
  installer replaces this download; old installs keep the old key and their circle
  TTLs out after 30 days — machines must reinstall to rejoin.
- Unsigned-beta disclaimer stays until code signing exists (post-MVP item).
