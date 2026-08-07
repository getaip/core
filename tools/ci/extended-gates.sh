#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

tools/ci/check-publication-hygiene.sh
cargo run -p xtask -- release-check
git diff --exit-code -- schemas/aip
