#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DEPLOY_DIR=${ROOT}/deploy/connector-fleet
ENV_FILE=${DEPLOY_DIR}/.env.qualification
EVIDENCE_DIR=${AIP_PRODUCT_IMAGE_EVIDENCE_DIR:-${ROOT}/.getaip-product-image-qualification}

fail() {
    echo "connector product image qualification: $*" >&2
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
"${DEPLOY_DIR}/prepare.sh"
# This file is generated from the exact source digest by prepare.sh. It contains
# image coordinates only and is owner-readable; it never contains credentials.
# shellcheck disable=SC1090
. "$ENV_FILE"

# prepare.sh has already built every source-bound image through the same
# Dockerfiles and build arguments used by the fleet. Verify and exercise those
# exact images instead of creating a second, potentially divergent build.

rm -rf "$EVIDENCE_DIR"
mkdir -p "$EVIDENCE_DIR"
: > "${EVIDENCE_DIR}/images.jsonl"
chmod 700 "$EVIDENCE_DIR"

verify_image() {
    image="$1"
    component="$2"
    expected_entrypoint="$3"
    expected_image_id="${4:-}"
    image_id=$(docker image inspect --format '{{.Id}}' "$image")
    user=$(docker image inspect --format '{{.Config.User}}' "$image")
    entrypoint=$(docker image inspect --format '{{json .Config.Entrypoint}}' "$image")
    revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")
    version=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$image")
    image_component=$(docker image inspect --format '{{index .Config.Labels "dev.getaip.component"}}' "$image")
    case "$image_id" in
        sha256:????????????????????????????????????????????????????????????????) ;;
        *) fail "${image} has no immutable sha256 image id" ;;
    esac
    if [ -n "$expected_image_id" ]; then
        test "$image_id" = "$expected_image_id" || \
            fail "${image} no longer matches the image prepared for ${SOURCE_REVISION}"
    fi
    test "$user" = "10001:10001" || fail "${image} runs as unexpected user ${user}"
    test "$entrypoint" = "[\"${expected_entrypoint}\"]" || fail "${image} has unexpected entrypoint ${entrypoint}"
    test "$revision" = "$SOURCE_REVISION" || fail "${image} has unexpected source revision"
    test "$version" = "$IMAGE_VERSION" || fail "${image} has unexpected version"
    test "$image_component" = "$component" || fail "${image} has unexpected component label"
    docker image inspect "$image" > "${EVIDENCE_DIR}/${component}-inspect.json"
    docker history --no-trunc --format '{{json .}}' "$image" \
        > "${EVIDENCE_DIR}/${component}-history.jsonl"
    SYFT_CHECK_FOR_APP_UPDATE=false "$SYFT_BIN" "$image" --output spdx-json \
        > "${EVIDENCE_DIR}/${component}-sbom.spdx.json"
    printf '{"image":"%s","image_id":"%s","component":"%s","source_revision":"%s","version":"%s","user":"%s","entrypoint":%s,"status":"passed"}\n' \
        "$image" "$image_id" "$component" "$revision" "$version" "$user" "$entrypoint" \
        >> "${EVIDENCE_DIR}/images.jsonl"
}

for package in \
    aip-host-cal-diy \
    aip-host-hermes-agent \
    aip-host-chatwoot \
    aip-host-dify \
    aip-host-crewai \
    aip-host-twenty \
    aip-host-wa-archive
do
    image="getaip/${package}:${AIP_IMAGE_TAG}"
    case "$package" in
        aip-host-cal-diy) expected_image_id=$CAL_IMAGE_DIGEST ;;
        aip-host-hermes-agent) expected_image_id=$HERMES_IMAGE_DIGEST ;;
        aip-host-chatwoot) expected_image_id=$CHATWOOT_IMAGE_DIGEST ;;
        aip-host-dify) expected_image_id=$DIFY_IMAGE_DIGEST ;;
        aip-host-crewai) expected_image_id=$CREWAI_IMAGE_DIGEST ;;
        aip-host-twenty) expected_image_id=$TWENTY_IMAGE_DIGEST ;;
        aip-host-wa-archive) expected_image_id=$WA_ARCHIVE_HOST_IMAGE_DIGEST ;;
        *) fail "unsupported product host package ${package}" ;;
    esac
    docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges:true \
        "$image" --help > "${EVIDENCE_DIR}/${package}-help.txt"
    verify_image \
        "$image" \
        "$package" \
        /usr/local/bin/aip-connector-host \
        "$expected_image_id"
done

sidecar_image="getaip/aip-crewai-sidecar:${AIP_IMAGE_TAG}"
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --entrypoint python "$sidecar_image" -c \
    'import importlib.metadata; assert importlib.metadata.version("crewai") == "1.15.2"; print(importlib.metadata.version("aip-crewai-sidecar"))' \
    > "${EVIDENCE_DIR}/aip-crewai-sidecar-version.txt"
test "$(docker image inspect --format '{{index .Config.Labels "dev.getaip.crewai.revision"}}' "$sidecar_image")" = \
    "bfa652a7be8637562cc9b0833f75d927a64552d1" \
    || fail "CrewAI sidecar is not pinned to the qualified upstream source revision"
verify_image "$sidecar_image" aip-crewai-sidecar aip-crewai-sidecar

printf '{"status":"passed","source_revision":"%s","version":"%s","rust_hosts":7,"python_sidecars":1}\n' \
    "$SOURCE_REVISION" "$IMAGE_VERSION" > "${EVIDENCE_DIR}/summary.json"
printf 'connector product image qualification: PASS evidence=%s\n' "$EVIDENCE_DIR"
