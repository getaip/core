#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DEPLOY_DIR=${ROOT}/deploy/connector-fleet
COMPOSE_FILE=${DEPLOY_DIR}/compose.yml
ENV_FILE=${DEPLOY_DIR}/.env.qualification

fail() {
    echo "connector fleet preparation: $*" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || fail "docker is required"
docker info >/dev/null 2>&1 || fail "the Docker daemon is unavailable"
DOCKER_CLIENT_ARCH=$(docker version --format '{{.Client.Arch}}')
case "$DOCKER_CLIENT_ARCH" in
    amd64|arm64) IMAGE_PLATFORM=linux/${DOCKER_CLIENT_ARCH} ;;
    *) fail "unsupported Docker client architecture ${DOCKER_CLIENT_ARCH}" ;;
esac

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
IMAGE_TAG=qualification-$(printf '%s' "$SOURCE_DIGEST" | cut -c 1-16)
SOURCE_REVISION=workspace-sha256:${SOURCE_DIGEST}
CONNECTOR_RELEASE_ID=$(printf '%s' "$SOURCE_DIGEST" | cut -c 1-16)
CONNECTOR_RELEASE_REVISION=$(date +%s)
WA_ARCHIVE_ACCOUNT_ID=${WA_ARCHIVE_ACCOUNT_ID:-}
WA_ARCHIVE_PROVIDER_IMAGE=${WA_ARCHIVE_PROVIDER_IMAGE:-getaip/wa-archive:qualification}
AIP_WA_ARCHIVE_PROVIDER_REQUIRED=${AIP_WA_ARCHIVE_PROVIDER_REQUIRED:-1}

test -n "$WA_ARCHIVE_ACCOUNT_ID" || fail "WA_ARCHIVE_ACCOUNT_ID must be the canonical paired WhatsApp account JID"
case "$WA_ARCHIVE_ACCOUNT_ID" in
    *[!a-zA-Z0-9._:@-]*) fail "WA_ARCHIVE_ACCOUNT_ID contains unsupported characters" ;;
esac
case "$WA_ARCHIVE_PROVIDER_IMAGE" in
    *[!a-zA-Z0-9._/@:-]*) fail "WA_ARCHIVE_PROVIDER_IMAGE contains unsupported characters" ;;
esac
case "$AIP_WA_ARCHIVE_PROVIDER_REQUIRED" in
    0|1) ;;
    *) fail "AIP_WA_ARCHIVE_PROVIDER_REQUIRED must be 0 or 1" ;;
esac

# Re-running an identical source release must regenerate byte-identical
# admission identities instead of creating a spurious catalog revision. A new
# source always advances the durable revision, even if the wall clock stalls.
if test -f "$ENV_FILE"; then
    previous_source_revision=$(sed -n 's/^SOURCE_REVISION=//p' "$ENV_FILE")
    previous_release_id=$(sed -n 's/^AIP_CONNECTOR_RELEASE_ID=//p' "$ENV_FILE")
    previous_release_revision=$(sed -n 's/^AIP_CONNECTOR_RELEASE_REVISION=//p' "$ENV_FILE")
    if test "$previous_source_revision" = "$SOURCE_REVISION" \
        && test -n "$previous_release_id" \
        && test -n "$previous_release_revision"
    then
        CONNECTOR_RELEASE_ID=$previous_release_id
        CONNECTOR_RELEASE_REVISION=$previous_release_revision
    else
        case "$previous_release_revision" in
            ''|*[!0-9]*) ;;
            *)
                if test "$CONNECTOR_RELEASE_REVISION" -le "$previous_release_revision"; then
                    CONNECTOR_RELEASE_REVISION=$((previous_release_revision + 1))
                fi
                ;;
        esac
    fi
fi
case "$CONNECTOR_RELEASE_ID" in
    ''|*[!a-z0-9]*) fail "connector release id must use lowercase ASCII letters or digits" ;;
esac
case "$CONNECTOR_RELEASE_REVISION" in
    ''|0|*[!0-9]*) fail "connector release revision must be a positive integer" ;;
esac

TEMP_ENV=$(mktemp "${DEPLOY_DIR}/.env.qualification.XXXXXX")
trap 'rm -f "$TEMP_ENV"' EXIT HUP INT TERM
chmod 600 "$TEMP_ENV"
{
    printf 'AIP_IMAGE_TAG=%s\n' "$IMAGE_TAG"
    printf 'SOURCE_REVISION=%s\n' "$SOURCE_REVISION"
    printf 'IMAGE_VERSION=%s\n' "$VERSION"
    printf 'AIP_CONNECTOR_RELEASE_ID=%s\n' "$CONNECTOR_RELEASE_ID"
    printf 'AIP_CONNECTOR_RELEASE_REVISION=%s\n' "$CONNECTOR_RELEASE_REVISION"
    printf 'SUPPORT_IMAGE_DIGEST=sha256:%064d\n' 0
    printf 'ENTERPRISE_IMAGE_DIGEST=sha256:%064d\n' 0
    printf 'CAL_IMAGE_DIGEST=sha256:%064d\n' 0
    printf 'HERMES_IMAGE_DIGEST=sha256:%064d\n' 0
    printf 'CHATWOOT_IMAGE_DIGEST=sha256:%064d\n' 0
    printf 'DIFY_IMAGE_DIGEST=sha256:%064d\n' 0
    printf 'CREWAI_IMAGE_DIGEST=sha256:%064d\n' 0
    printf 'TWENTY_IMAGE_DIGEST=sha256:%064d\n' 0
    printf 'WA_ARCHIVE_HOST_IMAGE_DIGEST=sha256:%064d\n' 0
    printf 'WA_ARCHIVE_ACCOUNT_ID=%s\n' "$WA_ARCHIVE_ACCOUNT_ID"
    printf 'WA_ARCHIVE_PROVIDER_IMAGE=%s\n' "$WA_ARCHIVE_PROVIDER_IMAGE"
    printf 'WA_ARCHIVE_PROVIDER_SOURCE_REVISION=unknown\n'
} > "$TEMP_ENV"

DOCKER_DEFAULT_PLATFORM=$IMAGE_PLATFORM \
    docker compose --profile products --profile wa-archive --env-file "$TEMP_ENV" -f "$COMPOSE_FILE" build \
    getaip-cli fleet-fixture edge control-plane getaip-server support-acme-a enterprise-acme-a \
    product-upstream crewai-sidecar cal-acme-a hermes-acme-a chatwoot-acme-a \
    dify-acme-a crewai-acme-a twenty-acme-a wa-archive-acme-a

CLI_IMAGE_ARCH=$(docker image inspect --format '{{.Architecture}}' "getaip/cli:${IMAGE_TAG}")
test "$CLI_IMAGE_ARCH" = "$DOCKER_CLIENT_ARCH" || \
    fail "CLI image architecture ${CLI_IMAGE_ARCH} does not match Docker client architecture ${DOCKER_CLIENT_ARCH}"

SUPPORT_IMAGE_DIGEST=$(
    docker image inspect --format '{{.Id}}' "getaip/aip-host-support-sandbox:${IMAGE_TAG}"
)
ENTERPRISE_IMAGE_DIGEST=$(
    docker image inspect --format '{{.Id}}' "getaip/aip-host-enterprise-sandbox:${IMAGE_TAG}"
)
CAL_IMAGE_DIGEST=$(docker image inspect --format '{{.Id}}' "getaip/aip-host-cal-diy:${IMAGE_TAG}")
HERMES_IMAGE_DIGEST=$(docker image inspect --format '{{.Id}}' "getaip/aip-host-hermes-agent:${IMAGE_TAG}")
CHATWOOT_IMAGE_DIGEST=$(docker image inspect --format '{{.Id}}' "getaip/aip-host-chatwoot:${IMAGE_TAG}")
DIFY_IMAGE_DIGEST=$(docker image inspect --format '{{.Id}}' "getaip/aip-host-dify:${IMAGE_TAG}")
CREWAI_IMAGE_DIGEST=$(docker image inspect --format '{{.Id}}' "getaip/aip-host-crewai:${IMAGE_TAG}")
TWENTY_IMAGE_DIGEST=$(docker image inspect --format '{{.Id}}' "getaip/aip-host-twenty:${IMAGE_TAG}")
WA_ARCHIVE_HOST_IMAGE_DIGEST=$(docker image inspect --format '{{.Id}}' "getaip/aip-host-wa-archive:${IMAGE_TAG}")
WA_ARCHIVE_PROVIDER_IMAGE_DIGEST=$WA_ARCHIVE_PROVIDER_IMAGE
WA_ARCHIVE_PROVIDER_SOURCE_REVISION=not-qualified-in-this-gate
if test "$AIP_WA_ARCHIVE_PROVIDER_REQUIRED" -eq 1; then
    WA_ARCHIVE_PROVIDER_IMAGE_DIGEST=$(docker image inspect --format '{{.Id}}' "$WA_ARCHIVE_PROVIDER_IMAGE") || \
        fail "WA Archive provider image is unavailable; build or pull the separately versioned provider first"
    WA_ARCHIVE_PROVIDER_SOURCE_REVISION=$(
        docker image inspect \
            --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
            "$WA_ARCHIVE_PROVIDER_IMAGE"
    ) || fail "WA Archive provider image metadata is unavailable"
fi
case "$SUPPORT_IMAGE_DIGEST" in
    sha256:????????????????????????????????????????????????????????????????) ;;
    *) fail "support host image did not produce an immutable sha256 image id" ;;
esac
case "$ENTERPRISE_IMAGE_DIGEST" in
    sha256:????????????????????????????????????????????????????????????????) ;;
    *) fail "enterprise host image did not produce an immutable sha256 image id" ;;
esac
for product_digest in \
    "$CAL_IMAGE_DIGEST" \
    "$HERMES_IMAGE_DIGEST" \
    "$CHATWOOT_IMAGE_DIGEST" \
    "$DIFY_IMAGE_DIGEST" \
    "$CREWAI_IMAGE_DIGEST" \
    "$TWENTY_IMAGE_DIGEST" \
    "$WA_ARCHIVE_HOST_IMAGE_DIGEST"
do
    case "$product_digest" in
        sha256:????????????????????????????????????????????????????????????????) ;;
        *) fail "product host image did not produce an immutable sha256 image id" ;;
    esac
done
if test "$AIP_WA_ARCHIVE_PROVIDER_REQUIRED" -eq 1; then
    case "$WA_ARCHIVE_PROVIDER_IMAGE_DIGEST" in
        sha256:????????????????????????????????????????????????????????????????) ;;
        *) fail "WA Archive provider image did not produce an immutable sha256 image id" ;;
    esac
    case "$WA_ARCHIVE_PROVIDER_SOURCE_REVISION" in
        ''|unknown|'<no value>') fail "WA Archive provider image must carry an exact org.opencontainers.image.revision label" ;;
    esac
fi

{
    printf 'AIP_IMAGE_TAG=%s\n' "$IMAGE_TAG"
    printf 'SOURCE_REVISION=%s\n' "$SOURCE_REVISION"
    printf 'IMAGE_VERSION=%s\n' "$VERSION"
    printf 'AIP_CONNECTOR_RELEASE_ID=%s\n' "$CONNECTOR_RELEASE_ID"
    printf 'AIP_CONNECTOR_RELEASE_REVISION=%s\n' "$CONNECTOR_RELEASE_REVISION"
    printf 'SUPPORT_IMAGE_DIGEST=%s\n' "$SUPPORT_IMAGE_DIGEST"
    printf 'ENTERPRISE_IMAGE_DIGEST=%s\n' "$ENTERPRISE_IMAGE_DIGEST"
    printf 'CAL_IMAGE_DIGEST=%s\n' "$CAL_IMAGE_DIGEST"
    printf 'HERMES_IMAGE_DIGEST=%s\n' "$HERMES_IMAGE_DIGEST"
    printf 'CHATWOOT_IMAGE_DIGEST=%s\n' "$CHATWOOT_IMAGE_DIGEST"
    printf 'DIFY_IMAGE_DIGEST=%s\n' "$DIFY_IMAGE_DIGEST"
    printf 'CREWAI_IMAGE_DIGEST=%s\n' "$CREWAI_IMAGE_DIGEST"
    printf 'TWENTY_IMAGE_DIGEST=%s\n' "$TWENTY_IMAGE_DIGEST"
    printf 'WA_ARCHIVE_HOST_IMAGE_DIGEST=%s\n' "$WA_ARCHIVE_HOST_IMAGE_DIGEST"
    printf 'WA_ARCHIVE_ACCOUNT_ID=%s\n' "$WA_ARCHIVE_ACCOUNT_ID"
    printf 'WA_ARCHIVE_PROVIDER_IMAGE=%s\n' "$WA_ARCHIVE_PROVIDER_IMAGE_DIGEST"
    printf 'WA_ARCHIVE_PROVIDER_SOURCE_REVISION=%s\n' "$WA_ARCHIVE_PROVIDER_SOURCE_REVISION"
} > "$TEMP_ENV"
mv -f "$TEMP_ENV" "$ENV_FILE"
trap - EXIT HUP INT TERM
chmod 600 "$ENV_FILE"

docker compose --profile products --profile wa-archive --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config --quiet
printf 'connector fleet preparation: PASS tag=%s source=%s release=%s revision=%s\n' \
    "$IMAGE_TAG" "$SOURCE_REVISION" "$CONNECTOR_RELEASE_ID" "$CONNECTOR_RELEASE_REVISION"
