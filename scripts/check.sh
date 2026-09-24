#!/usr/bin/env bash
# Lint gate: clippy over the whole workspace with warnings denied.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo clippy --workspace --all-targets -- -D warnings
