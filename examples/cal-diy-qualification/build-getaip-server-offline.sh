#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
EXAMPLE="$ROOT/examples/cal-diy-qualification"
BUILDER_IMAGE=rust:1.94-alpine
RUNTIME_IMAGE=getaip/server:local
OUTPUT_IMAGE=getaip/server:cal-diy-qualification
TARGET_VOLUME=aip-cal-diy-linux-target
CONTAINER="aip-cal-diy-package-$$"
UID_VALUE=$(id -u)
GID_VALUE=$(id -g)
OUTPUT="$EXAMPLE/.runtime/prebuilt"

cleanup() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker image inspect "$BUILDER_IMAGE" "$RUNTIME_IMAGE" >/dev/null
mkdir -p "$OUTPUT"
docker volume create "$TARGET_VOLUME" >/dev/null
docker run --rm --pull never -v "$TARGET_VOLUME:/target" alpine:3.22 \
    chown -R "$UID_VALUE:$GID_VALUE" /target
docker run --rm --pull never \
    --user "$UID_VALUE:$GID_VALUE" \
    -e CARGO_HOME=/cargo \
    -e CARGO_TARGET_DIR=/target \
    -e RUSTUP_TOOLCHAIN=1.94.1-aarch64-unknown-linux-musl \
    -v "$ROOT:/workspace:ro" \
    -v "$HOME/.cargo:/cargo" \
    -v "$TARGET_VOLUME:/target" \
    -v "$OUTPUT:/out" \
    "$BUILDER_IMAGE" \
    sh -c 'cd /workspace && cargo build --release -p getaip-server-legacy-bundled --locked --offline && cp /target/release/getaip-server-legacy-bundled /out/getaip-server'

test -x "$OUTPUT/getaip-server"
AIP_BASE_COMMIT=${AIP_BASE_COMMIT:-$(git -C "$ROOT" rev-parse HEAD)}
AIP_SOURCE_DIGEST=${AIP_SOURCE_DIGEST:-unrecorded}
RUNTIME_IMAGE_ID=$(docker image inspect "$RUNTIME_IMAGE" --format '{{.Id}}')
BUILDER_IMAGE_ID=$(docker image inspect "$BUILDER_IMAGE" --format '{{.Id}}')

docker create --name "$CONTAINER" "$RUNTIME_IMAGE" >/dev/null
docker cp "$OUTPUT/getaip-server" "$CONTAINER:/usr/local/bin/getaip-server"
docker commit --pause=false \
    --change "LABEL org.opencontainers.image.title=GetAIP-server" \
    --change "LABEL org.opencontainers.image.version=2.0.0" \
    --change "LABEL org.opencontainers.image.revision=$AIP_BASE_COMMIT" \
    --change "LABEL io.aip.source-digest=$AIP_SOURCE_DIGEST" \
    --change "LABEL io.aip.builder-image=$BUILDER_IMAGE_ID" \
    --change "LABEL io.aip.runtime-base-image=$RUNTIME_IMAGE_ID" \
    "$CONTAINER" "$OUTPUT_IMAGE" >/dev/null
docker rm "$CONTAINER" >/dev/null
trap - EXIT INT TERM

docker run --rm --pull never --entrypoint /usr/local/bin/getaip-server "$OUTPUT_IMAGE" --help >/dev/null
rm -f "$OUTPUT/getaip-server"
echo "Built $OUTPUT_IMAGE without registry access"
