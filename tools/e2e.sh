#!/usr/bin/env bash
set -euo pipefail
exec cargo run --quiet --locked --manifest-path "$(dirname "$0")/../Cargo.toml" -p no-warden-conformance -- "$@"
