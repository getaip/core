#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
EXAMPLE="$ROOT/examples/cal-diy-qualification"
: "${CAL_DIY_SOURCE_ROOT:?set CAL_DIY_SOURCE_ROOT to the pinned Cal.diy checkout}"
CAL_ROOT=$CAL_DIY_SOURCE_ROOT
CAL_COMMIT_EXPECTED=f00434927386c9ecdcbd7e6c5f82d22044a245bc
CAL_IMAGE=cal-diy-api:aip-f004349-runtime
COMPOSE="docker compose --env-file $EXAMPLE/.runtime/compose.env -f $EXAMPLE/docker-compose.yml"

cd "$ROOT"
python3 "$EXAMPLE/prepare-runtime.py"
$COMPOSE down --volumes --remove-orphans >/dev/null 2>&1 || true

test "$(git -C "$CAL_ROOT" rev-parse HEAD)" = "$CAL_COMMIT_EXPECTED"
test -z "$(git -C "$CAL_ROOT" status --porcelain)"
docker image inspect "$CAL_IMAGE" >/dev/null
docker image inspect aip-restaurant-coordinator:local >/dev/null
test "$(docker run --rm --entrypoint python aip-restaurant-coordinator:local -c 'import importlib.metadata as m; print(m.version("httpx"), m.version("mcp"), m.version("psycopg"))')" = "0.28.1 1.26.0 3.2.13"

for file in package.json apps/api/v2/package.json packages/prisma/schema.prisma apps/api/v2/src/platform/bookings/2024-08-13/controllers/bookings.controller.ts; do
    host_hash=$(shasum -a 256 "$CAL_ROOT/$file" | awk '{print $1}')
    image_hash=$(docker run --rm --entrypoint sha256sum "$CAL_IMAGE" "/calcom/$file" | awk '{print $1}')
    test "$host_hash" = "$image_hash"
done

if $COMPOSE config --services | grep -Eiq 'hermes|agent'; then
    echo "qualification compose must not contain agent services" >&2
    exit 1
fi

export AIP_BASE_COMMIT
AIP_BASE_COMMIT=$(git rev-parse HEAD)
export AIP_SOURCE_DIGEST
AIP_SOURCE_DIGEST=$(git ls-files -co --exclude-standard -z -- Cargo.toml Cargo.lock rust-toolchain.toml crates | xargs -0 shasum -a 256 | LC_ALL=C sort | shasum -a 256 | awk '{print $1}')
export AIP_HARNESS_DIGEST
AIP_HARNESS_DIGEST=$(git ls-files -co --exclude-standard -z -- examples/cal-diy-qualification examples/restaurant-booking/cal-seed.ts examples/getaip-server-docker/oauth-introspection.py | xargs -0 shasum -a 256 | LC_ALL=C sort | shasum -a 256 | awk '{print $1}')
export CAL_COMMIT="$CAL_COMMIT_EXPECTED"
export CAL_IMAGE_ID
CAL_IMAGE_ID=$(docker image inspect "$CAL_IMAGE" --format '{{.Id}}')
export CAL_SOURCE_DIGEST
CAL_SOURCE_DIGEST=$(git -C "$CAL_ROOT" rev-parse 'HEAD^{tree}')
export QUALIFICATION_RUNNER_IMAGE_ID
QUALIFICATION_RUNNER_IMAGE_ID=$(docker image inspect aip-restaurant-coordinator:local --format '{{.Id}}')

"$EXAMPLE/build-getaip-server-offline.sh"
export AIP_IMAGE_ID
AIP_IMAGE_ID=$(docker image inspect getaip/server:cal-diy-qualification --format '{{.Id}}')
export AIP_BUILDER_IMAGE_ID
AIP_BUILDER_IMAGE_ID=$(docker image inspect rust:1.94-alpine --format '{{.Id}}')
export AIP_RUNTIME_BASE_IMAGE_ID
AIP_RUNTIME_BASE_IMAGE_ID=$(docker image inspect getaip/server:local --format '{{.Id}}')

$COMPOSE up -d runtime-postgres cal-postgres cal-redis getaip-server oauth cal-api

attempt=0
until docker exec aip-cal-diy-qualification-getaip-server-1 wget -q -O /dev/null http://127.0.0.1:8080/ready >/dev/null 2>&1 \
    && docker exec aip-cal-diy-qualification-getaip-server-1 wget -q -O /dev/null http://127.0.0.1:18282/health >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 180 ]; then
        $COMPOSE ps
        $COMPOSE logs --tail 200 getaip-server oauth cal-migrate cal-seed cal-api
        exit 1
    fi
    sleep 2
done

$COMPOSE --profile test run --rm --no-deps -e QUALIFICATION_MODE=run qualification
$COMPOSE restart getaip-server
# OAuth and Cal.diy intentionally share getaip-server's private network namespace so
# plaintext fixture traffic never crosses a Docker network. Restart the
# namespace-bound sidecars after the namespace owner to rebind their listeners.
$COMPOSE restart oauth cal-api

attempt=0
until docker exec aip-cal-diy-qualification-getaip-server-1 wget -q -O /dev/null http://127.0.0.1:8080/ready >/dev/null 2>&1 \
    && docker exec aip-cal-diy-qualification-getaip-server-1 wget -q -O /dev/null http://127.0.0.1:19090/health >/dev/null 2>&1 \
    && docker exec aip-cal-diy-qualification-getaip-server-1 wget -q -O /dev/null http://127.0.0.1:18282/health >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 90 ]; then
        $COMPOSE logs --tail 200 getaip-server
        exit 1
    fi
    sleep 2
done

$COMPOSE --profile test run --rm --no-deps -e QUALIFICATION_MODE=verify-restart qualification
$COMPOSE ps
docker volume rm aip-cal-diy-linux-target >/dev/null 2>&1 || true
echo "Qualification evidence: $EXAMPLE/.runtime/evidence/cal-diy-qualification.json"
