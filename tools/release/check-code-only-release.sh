#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

test "$#" -le 1 || {
    echo "usage: $0 [expected-source-branch]" >&2
    exit 2
}
EXPECTED_SOURCE_BRANCH=${1:-develop}

test -f Cargo.lock
test -f package-lock.json
test -f LICENSE
test -f NOTICE
test -f SOURCE_SNAPSHOT.json
test -f PUBLICATION_MANIFEST.json
test ! -e CHANGELOG
test -d schemas/aip
test -f schemas/aip/envelope.schema.json
test -f schemas/aip/manifest.schema.json
test "$(git ls-files | awk 'tolower($0) ~ /\.md$/')" = "README.md"
python3 tools/release/verify_code_only_snapshot.py \
    --repository . \
    --expected-source-branch "$EXPECTED_SOURCE_BRANCH"
python3 tools/ci/check-getaip-naming.py enforce
tools/ci/check-publication-hygiene.sh --code-only "$EXPECTED_SOURCE_BRANCH"
npm ci --ignore-scripts
npm test
npm run check
python3 -m unittest discover -s tools/release -p 'test_*.py'
cargo run -p xtask -- release-check
git diff --exit-code -- schemas/aip
