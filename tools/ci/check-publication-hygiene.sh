#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

MODE=${1:---source}
case "$MODE" in
    --source)
        test "$#" -le 1 || {
            echo "usage: $0 [--source]" >&2
            exit 2
        }
        EXPECTED_SOURCE_BRANCH=develop
        ;;
    --code-only)
        test "$#" -le 2 || {
            echo "usage: $0 --code-only [expected-source-branch]" >&2
            exit 2
        }
        EXPECTED_SOURCE_BRANCH=${2:-develop}
        ;;
    *)
        echo "usage: $0 --source | --code-only [expected-source-branch]" >&2
        exit 2
        ;;
esac

fail() {
    echo "publication hygiene: $*" >&2
    exit 1
}

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        fail "sha256sum or shasum is required"
    fi
}

test -z "$(git ls-files 'web/**')" || fail "tracked web/ files belong in getaip/docs"
test -z "$(git rev-list --all -- web/)" || \
    fail "reachable Git history contains the separately owned web/ frontend"

markdown_files=$(git ls-files | awk 'tolower($0) ~ /\.md$/')
if [ "$MODE" = "--source" ]; then
    test "$markdown_files" = "README.md" || \
        fail "the canonical source branch must track README.md as its only Markdown file"
else
    test -z "$markdown_files" || \
        fail "the code-only publication must not track Markdown files"
    test ! -e CHANGELOG || \
        fail "the code-only publication must not contain CHANGELOG"
fi

for excluded_path in benches docs/testing/evidence tests; do
    test -z "$(git ls-files "$excluded_path/**")" || \
        fail "tracked $excluded_path/ files are excluded from the code branch"
done

if git rev-list --objects --all | awk '
    NF > 1 && $2 ~ /^web\// { found = 1 }
    END { exit(found ? 0 : 1) }
'; then
    fail "reachable Git objects contain the separately owned web/ frontend"
fi

machine_root="/""Users/"
if git grep -n -I -e "$machine_root" -- .; then
    fail "tracked files contain a machine-specific home-directory path"
fi

legacy_github="https://github.com/""aip-labs/agent-interoperability-protocol"
retired_github="https://github.com/""getaip/aip-core"
local_gitea="http://localhost:3000/""admin/agent-interoperability-protocol.git"
if git grep -n -I -e "$legacy_github" -e "$retired_github" -e "$local_gitea" \
    -- . ':(exclude)SOURCE_SNAPSHOT.json'; then
    fail "stale repository location found outside SOURCE_SNAPSHOT.json"
fi

for manifest in crates/*/Cargo.toml; do
    grep -Eq '^publish[[:space:]]*=[[:space:]]*false([[:space:]]*(#.*)?)?$' "$manifest" || \
        fail "$manifest must set publish = false"
done

grep -Fqx 'license = "BUSL-1.1"' Cargo.toml || \
    fail "workspace license must be BUSL-1.1"
grep -Fqx 'repository = "https://github.com/getaip/core"' Cargo.toml || \
    fail "workspace repository must target getaip/core"
grep -Fq 'license = { text = "BUSL-1.1" }' \
    crates/aip-connector-crewai/sidecar/pyproject.toml || \
    fail "CrewAI sidecar license must be BUSL-1.1"
grep -Fq 'Licensor:             WAI LLC' LICENSE || \
    fail "LICENSE must name WAI LLC as Licensor"
grep -Fq 'Change Date:          2030-07-21' LICENSE || \
    fail "LICENSE has an unexpected Change Date"
grep -Fq 'Change License:       Apache License, Version 2.0' LICENSE || \
    fail "LICENSE has an unexpected Change License"
grep -Fqx 'private = { ignore = true }' deny.toml || \
    fail "cargo-deny must ignore only private workspace package licenses"

for path in \
    .gitleaks.toml \
    .mailmap \
    private-sdk-release.json \
    SOURCE_SNAPSHOT.json \
    THIRD_PARTY_NOTICES \
    third_party/modelcontextprotocol/LICENSE; do
    test -f "$path" || fail "required publication file is missing: $path"
done

for pattern in \
    '.env' \
    '.env.*' \
    '**/.env' \
    '**/.env.*' \
    '.aipd-*' \
    '**/.aipd-*' \
    '.getaip-*' \
    '**/.getaip-*' \
    '.repo-metadata-archive/' \
    '**/.repo-metadata-archive/' \
    'node_modules/' \
    '**/node_modules/' \
    '.venv-*/' \
    '**/.venv-*/' \
    '**/.runtime/' \
    '**/secrets/'; do
    grep -Fqx "$pattern" .dockerignore || fail ".dockerignore is missing $pattern"
done

check_hash() {
    expected=$1
    path=$2
    actual=$(hash_file "$path")
    test "$actual" = "$expected" || fail "$path checksum is $actual, expected $expected"
}

check_hash 61cea2392d4f284092d09bc84b9ac488c0d5618ac2b38a56942fc5b99fd960ce \
    schemas/mcp/2024-11-05/schema.json
check_hash e720669548c8100a4282c49e580efd6ddf7f28899ea786fc8db251dbdb356131 \
    schemas/mcp/2025-03-26/schema.json
check_hash b3db8f1ca839bc5171ceb4ba013fdf240c5a8a13d4653bb1bdf21f94677aa220 \
    schemas/mcp/2025-06-18/schema.json
check_hash 7b2d96fd95efd2216aa953606b83f5a740ddeaa5ebd3a5d27b45a8296545a118 \
    schemas/mcp/2025-11-25/schema.json
check_hash 0382b0057770ca05e9c350a50aa3b1c1fea84da0bc81d723bf00b9aa841be58a \
    third_party/modelcontextprotocol/LICENSE

python3 - "$MODE" "$EXPECTED_SOURCE_BRANCH" <<'PY'
import json
import re
import sys
from pathlib import Path

mode = sys.argv[1]
expected_source_branch = sys.argv[2]
data = json.loads(Path("SOURCE_SNAPSHOT.json").read_text(encoding="utf-8"))
assert data["publication"]["repository"] == "https://github.com/getaip/core"
assert data["licensing"]["spdx_identifier"] == "BUSL-1.1"
assert data["licensing"]["licensor"] == "WAI LLC"

if mode == "--code-only":
    assert data["schema_version"] == 2
    assert data["mode"] == "code-only-single-root"
    assert data["release"]["name"] == "GetAIP Core"
    assert data["release"]["version"] == "2.1.0"
    assert data["publication"]["branch"] == "main"
    assert data["publication"]["tag"] == "v2.1.0"
    assert data["history"] == {
        "strategy": "single-root-snapshot",
        "imported_commits": 0,
        "imported_tags": [],
        "initial_branch": "main",
        "expected_initial_commit_count": 1,
    }
    source = data["source"]
    assert source["repository"] == "http://localhost:3000/admin/core.git"
    assert source["branch"] == expected_source_branch
    assert re.fullmatch(r"[0-9a-f]{40}", source["revision"])
    assert re.fullmatch(r"[0-9a-f]{40}", source["tree"])
    assert source["export_method"] == "reviewed-filtered-index"
    boundary = data["publication_boundary"]
    assert boundary["excluded_markdown"] is True
    assert boundary["excluded_changelog"] is True
    assert boundary["publication_manifest"] == "PUBLICATION_MANIFEST.json"
PY

git diff --check
echo "publication hygiene: PASS"
