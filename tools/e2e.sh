#!/usr/bin/env bash
set -euo pipefail
exec cargo run --quiet --locked --profile "${NO_WARDEN_CONFORMANCE_PROFILE:-dev}" --manifest-path "$(dirname "$0")/../Cargo.toml" -p no-warden-conformance -- "$@"
