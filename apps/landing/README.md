# remote.deepflux.space — landing page

Static single-page site for the P2P remote desktop. Zero framework, zero build step:
`index.html` + `download/` is the whole site; Vercel serves it as-is.

## Live

- Domain: https://remote.deepflux.space (Vercel project `remote-landing`, team `timedivision`)
- Subdomain of `deepflux.space` (Vercel-registered, Vercel DNS — no manual DNS records needed)

## Deploying an update

```bash
# 1. refresh the installer asset (NOT committed to git — it is a build artifact)
cp "../../target/release/bundle/nsis/Remote Desktop_0.1.0_x64-setup.exe" \
   "download/Remote-Desktop-0.2.0-x64-setup.exe"   # bump filename + page link on new versions

# 2. deploy
vercel deploy --prod -S timedivision
```

Notes:
- Attach a new subdomain with `vercel domains add <sub>.deepflux.space remote-landing`
  (NOT `vercel alias set` — a bare alias leaves the domain unverified and Vercel serves
  it behind SSO authentication; the domains-add flow is what makes it public).
- The download link, version label, size, and the "know what you're installing" fineprint
  live in `index.html` — keep them in sync with the actual shipped build.
- Unsigned-beta disclaimer stays until code signing exists (post-MVP item).
