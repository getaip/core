#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
EVIDENCE_DIR=${AIP_MIGRATION_IMAGE_EVIDENCE_DIR:-${ROOT}/.getaip-migration-image-qualification}

fail() {
    echo "AIP daemon image qualification: $*" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || fail "docker is required"
docker info >/dev/null 2>&1 || fail "the Docker daemon is unavailable"
if command -v syft >/dev/null 2>&1; then
    SYFT_BIN=$(command -v syft)
elif [ -x "${HOME}/.local/bin/syft" ]; then
    SYFT_BIN=${HOME}/.local/bin/syft
else
    fail "the pinned Syft SBOM generator is required"
fi
SYFT_CHECK_FOR_APP_UPDATE=false "$SYFT_BIN" version >/dev/null 2>&1 || \
    fail "the Syft SBOM generator is not executable"

cd "$ROOT"
VERSION=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
test -n "$VERSION" || fail "workspace version is missing"
SOURCE_DIGEST=$(
    git ls-files -co --exclude-standard -z |
        LC_ALL=C sort -z |
        xargs -0 shasum -a 256 |
        shasum -a 256 |
        awk '{print $1}'
)
test "${#SOURCE_DIGEST}" -eq 64 || fail "workspace source digest could not be calculated"
SOURCE_REVISION=workspace-sha256:${SOURCE_DIGEST}
TAG=qualification-$(printf '%s' "$SOURCE_DIGEST" | cut -c 1-16)
CORE_IMAGE=getaip/server:${TAG}
MIGRATION_IMAGE=getaip/server-migration-bundle:${TAG}

rm -rf "$EVIDENCE_DIR"
mkdir -p "$EVIDENCE_DIR"
chmod 700 "$EVIDENCE_DIR"

if ! docker build \
    --file crates/getaip-server/Dockerfile \
    --build-arg "SOURCE_REVISION=${SOURCE_REVISION}" \
    --build-arg "IMAGE_VERSION=${VERSION}" \
    --tag "$CORE_IMAGE" \
    . > "${EVIDENCE_DIR}/core-build.log" 2>&1
then
    tail -n 200 "${EVIDENCE_DIR}/core-build.log" >&2
    fail "the core image build failed"
fi
if ! docker build \
    --file crates/getaip-server-legacy-bundled/Dockerfile \
    --build-arg "SOURCE_REVISION=${SOURCE_REVISION}" \
    --build-arg "IMAGE_VERSION=${VERSION}" \
    --tag "$MIGRATION_IMAGE" \
    . > "${EVIDENCE_DIR}/migration-build.log" 2>&1
then
    tail -n 200 "${EVIDENCE_DIR}/migration-build.log" >&2
    fail "the migration image build failed"
fi

verify_image() {
    image="$1"
    component="$2"
    evidence_name="$3"
    image_id=$(docker image inspect --format '{{.Id}}' "$image")
    user=$(docker image inspect --format '{{.Config.User}}' "$image")
    entrypoint=$(docker image inspect --format '{{json .Config.Entrypoint}}' "$image")
    revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")
    version=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$image")
    actual_component=$(docker image inspect --format '{{index .Config.Labels "dev.getaip.component"}}' "$image")
    case "$image_id" in
        sha256:????????????????????????????????????????????????????????????????) ;;
        *) fail "${image} has no immutable local image id" ;;
    esac
    test "$user" = "10001:10001" || fail "${image} runs as unexpected user ${user}"
    test "$entrypoint" = '["/usr/local/bin/getaip-server"]' || fail "${image} has unexpected entrypoint ${entrypoint}"
    test "$revision" = "$SOURCE_REVISION" || fail "${image} has unexpected source revision"
    test "$version" = "$VERSION" || fail "${image} has unexpected version"
    test "$actual_component" = "$component" || fail "${image} has unexpected component label"
    docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges:true \
        "$image" --help > "${EVIDENCE_DIR}/${evidence_name}-help.txt"
    docker image inspect "$image" > "${EVIDENCE_DIR}/${evidence_name}-inspect.json"
    docker history --no-trunc --format '{{json .}}' "$image" \
        > "${EVIDENCE_DIR}/${evidence_name}-history.jsonl"
    SYFT_CHECK_FOR_APP_UPDATE=false "$SYFT_BIN" "$image" --output spdx-json \
        > "${EVIDENCE_DIR}/${evidence_name}-sbom.spdx.json"
    printf '{"image":"%s","image_id":"%s","component":"%s","source_revision":"%s","version":"%s","user":"%s","entrypoint":%s,"status":"passed"}\n' \
        "$image" "$image_id" "$component" "$revision" "$version" "$user" "$entrypoint" \
        >> "${EVIDENCE_DIR}/images.jsonl"
}

: > "${EVIDENCE_DIR}/images.jsonl"
verify_image "$CORE_IMAGE" getaip-server-core core
verify_image "$MIGRATION_IMAGE" getaip-server-migration-bundle migration

CORE_ID=$(docker image inspect --format '{{.Id}}' "$CORE_IMAGE")
MIGRATION_ID=$(docker image inspect --format '{{.Id}}' "$MIGRATION_IMAGE")
test "$CORE_ID" != "$MIGRATION_ID" || fail "core and migration images are identical"

if grep -Eiq 'cal[_-]?diy|hermes|chatwoot|dify|crewai|support[_-]?sandbox|enterprise[_-]?sandbox' \
    "${EVIDENCE_DIR}/core-help.txt" "${EVIDENCE_DIR}/core-sbom.spdx.json"
then
    fail "the core image exposes product connector content"
fi
grep -Eiq 'cal[_-]?diy|hermes' "${EVIDENCE_DIR}/migration-help.txt" || \
    fail "the migration image does not expose its compatibility configuration"

cargo run -q -p xtask -- check-getaip-server-boundary \
    > "${EVIDENCE_DIR}/source-boundary.log" 2>&1
printf '{"status":"passed","source_revision":"%s","version":"%s","core_image_id":"%s","migration_image_id":"%s","sbom_format":"SPDX-2.3"}\n' \
    "$SOURCE_REVISION" "$VERSION" "$CORE_ID" "$MIGRATION_ID" \
    > "${EVIDENCE_DIR}/summary.json"
printf 'AIP daemon image qualification: PASS evidence=%s\n' "$EVIDENCE_DIR"
