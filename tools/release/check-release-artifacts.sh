#!/usr/bin/env sh
set -eu

# Full canonical-source gate. The filtered GitHub snapshot intentionally uses
# check-code-only-release.sh because it excludes Markdown and CHANGELOG.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

test -f Cargo.lock
test -f package-lock.json
test -f LICENSE
test -f NOTICE
test -f CHANGELOG
test -d schemas/aip
test -f schemas/aip/envelope.schema.json
test -f schemas/aip/manifest.schema.json
python3 tools/ci/check-getaip-naming.py enforce
tools/ci/check-publication-hygiene.sh --source
npm ci --ignore-scripts
npm test
npm run check
python3 -m unittest discover -s tools/release -p 'test_*.py'
cargo run -p xtask -- release-check
git diff --exit-code -- schemas/aip
