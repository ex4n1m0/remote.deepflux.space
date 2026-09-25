#!/usr/bin/env bash
# Test gate: run every test target in the workspace.
# Since M3 this includes the signaling service's TypeScript gate (typecheck,
# wire-fixture validation, unit tests) and its headless contract matrix —
# the TS half of the D7 wire contract lives there (QA F41).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --workspace
pnpm --dir services/signaling install --frozen-lockfile
pnpm --dir services/signaling test
pnpm --dir services/signaling run test:contract:headless
