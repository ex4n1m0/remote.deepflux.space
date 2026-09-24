#!/usr/bin/env bash
# Format the whole workspace with rustfmt defaults (no rustfmt.toml by design).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all "$@"
