#!/usr/bin/env bash
# Test gate: run every test target in the workspace.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --workspace
