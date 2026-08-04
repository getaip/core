#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DEPLOY_DIR=${ROOT}/deploy/connector-fleet
COMPOSE_FILE=${DEPLOY_DIR}/compose.yml
ENV_FILE=${DEPLOY_DIR}/.env.qualification
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
EVIDENCE_DIR=${AIP_PRODUCT_FLEET_EVIDENCE_DIR:-${ROOT}/.getaip-product-fleet-qualification/run-${RUN_ID}}
PROJECT=aip-connector-fleet-qualification
EVENTS_PID=

fail() {
    echo "product connector fleet qualification: $*" >&2
    exit 1
}

compose() {
    docker compose --profile products --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

verify_prepared_fleet() {
    current_source_digest=$(
        git ls-files -co --exclude-standard -z |
            LC_ALL=C sort -z |
            xargs -0 shasum -a 256 |
            shasum -a 256 |
            awk '{print $1}'
    )
    test "${#current_source_digest}" -eq 64 || \
        fail "current workspace source digest could not be calculated"
    expected_source_revision="workspace-sha256:${current_source_digest}"
    expected_image_tag="qualification-$(printf '%s' "$current_source_digest" | cut -c 1-16)"
    expected_version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
    test -n "$expected_version" || fail "workspace version is missing"

    # prepare.sh generates metadata only; the file contains no credentials.
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    test "$SOURCE_REVISION" = "$expected_source_revision" || \
        fail "prepared source revision does not match the current workspace"
    test "$AIP_IMAGE_TAG" = "$expected_image_tag" || \
        fail "prepared image tag does not match the current workspace"
    test "$IMAGE_VERSION" = "$expected_version" || \
        fail "prepared image version does not match the workspace version"

    while IFS='|' read -r image expected_image_id; do
        inspection=$(docker image inspect --format \
            '{{.Id}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "org.opencontainers.image.version"}}' \
            "$image") || fail "prepared image is unavailable: ${image}"
        IFS='|' read -r image_id source_revision image_version <<EOF
$inspection
EOF
        test "$image_id" = "$expected_image_id" || \
            fail "prepared image digest changed: ${image}"
        test "$source_revision" = "$SOURCE_REVISION" || \
            fail "prepared image source revision changed: ${image}"
        test "$image_version" = "$IMAGE_VERSION" || \
            fail "prepared image version changed: ${image}"
    done <<EOF
getaip/aip-host-support-sandbox:${AIP_IMAGE_TAG}|${SUPPORT_IMAGE_DIGEST}
getaip/aip-host-enterprise-sandbox:${AIP_IMAGE_TAG}|${ENTERPRISE_IMAGE_DIGEST}
getaip/aip-host-cal-diy:${AIP_IMAGE_TAG}|${CAL_IMAGE_DIGEST}
getaip/aip-host-hermes-agent:${AIP_IMAGE_TAG}|${HERMES_IMAGE_DIGEST}
getaip/aip-host-chatwoot:${AIP_IMAGE_TAG}|${CHATWOOT_IMAGE_DIGEST}
getaip/aip-host-dify:${AIP_IMAGE_TAG}|${DIFY_IMAGE_DIGEST}
getaip/aip-host-crewai:${AIP_IMAGE_TAG}|${CREWAI_IMAGE_DIGEST}
getaip/aip-host-twenty:${AIP_IMAGE_TAG}|${TWENTY_IMAGE_DIGEST}
getaip/aip-host-wa-archive:${AIP_IMAGE_TAG}|${WA_ARCHIVE_HOST_IMAGE_DIGEST}
EOF

    for image in \
        getaip/cli \
        getaip/server \
        getaip/aip-connector-fleet-fixture \
        getaip/aip-connector-fleet-edge \
        getaip/aip-connector-control-plane \
        getaip/aip-product-upstream-fixture \
        getaip/aip-crewai-sidecar
    do
        inspection=$(docker image inspect --format \
            '{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "org.opencontainers.image.version"}}' \
            "${image}:${AIP_IMAGE_TAG}") || \
            fail "prepared auxiliary image is unavailable: ${image}:${AIP_IMAGE_TAG}"
        IFS='|' read -r source_revision image_version <<EOF
$inspection
EOF
        test "$source_revision" = "$SOURCE_REVISION" || \
            fail "prepared auxiliary image source revision changed: ${image}"
        test "$image_version" = "$IMAGE_VERSION" || \
            fail "prepared auxiliary image version changed: ${image}"
    done
}

record() {
    case_name="$1"
    status="$2"
    detail="$3"
    printf '{"case":"%s","status":"%s","detail":"%s","recorded_at":"%s"}\n' \
        "$case_name" "$status" "$detail" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        >> "${EVIDENCE_DIR}/failure-matrix.jsonl"
}

copy_runtime_evidence() {
    mkdir -p "${EVIDENCE_DIR}/runtime-evidence"
    docker run --rm \
        -v "${PROJECT}_qualification_evidence:/source:ro" \
        -v "${EVIDENCE_DIR}/runtime-evidence:/target" \
        alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce \
        sh -c 'cp -a /source/. /target/' >/dev/null 2>&1 || true
}

registry_query() {
    sql="$1"
    compose exec -T postgres sh -eu -c \
        'PGPASSWORD=$(cat /fleet-state/secrets/postgres-bootstrap-password); export PGPASSWORD; exec psql --no-psqlrc --tuples-only --no-align --username aip_bootstrap --dbname aip_registry --set=ON_ERROR_STOP=1 --command "$1"' \
        sh "$sql"
}

database_query() {
    database="$1"
    sql="$2"
    case "$database" in
        cal_acme_runtime|hermes_acme_runtime|chatwoot_acme_runtime|dify_acme_runtime|crewai_acme_runtime|twenty_acme_runtime) ;;
        *) fail "unsupported product runtime database ${database}" ;;
    esac
    compose exec -T postgres sh -eu -c \
        'PGPASSWORD=$(cat /fleet-state/secrets/postgres-bootstrap-password); export PGPASSWORD; exec psql --no-psqlrc --tuples-only --no-align --username aip_bootstrap --dbname "$1" --set=ON_ERROR_STOP=1 --command "$2"' \
        sh "$database" "$sql"
}

capture_registry_state() {
    output="$1"
    registry_query "
        SELECT json_build_object(
            'observed_at_ms', (extract(epoch FROM clock_timestamp()) * 1000)::bigint,
            'product_replicas', COALESCE((
                SELECT json_agg(json_build_object(
                    'replica_id', replica_id,
                    'instance_id', instance_id,
                    'version_id', version_id,
                    'status', status,
                    'lease_expires_at_ms', lease_expires_at_ms,
                    'lease_remaining_ms', lease_expires_at_ms -
                        (extract(epoch FROM clock_timestamp()) * 1000)::bigint,
                    'health_revision', health_revision,
                    'consecutive_failures', consecutive_failures,
                    'region', region,
                    'zone', zone,
                    'capacity_class', capacity_class
                ) ORDER BY replica_id)
                FROM aip_connector_replicas
                WHERE replica_id IN (
                    '${CAL_REPLICA_ID}',
                    '${HERMES_REPLICA_ID}',
                    '${CHATWOOT_REPLICA_ID}',
                    '${DIFY_REPLICA_ID}',
                    '${CREWAI_REPLICA_ID}',
                    '${TWENTY_REPLICA_ID}'
                )
            ), '[]'::json),
            'product_versions', COALESCE((
                SELECT json_agg(json_build_object(
                    'version_id', version_id,
                    'status', status,
                    'artifact_digest', artifact_digest,
                    'manifest_digest', manifest_digest,
                    'supply_chain_qualified', supply_chain_qualified
                ) ORDER BY version_id)
                FROM aip_connector_versions
                WHERE version_id IN (
                    '${CAL_VERSION_ID}',
                    '${HERMES_VERSION_ID}',
                    '${CHATWOOT_VERSION_ID}',
                    '${DIFY_VERSION_ID}',
                    '${CREWAI_VERSION_ID}',
                    '${TWENTY_VERSION_ID}'
                )
            ), '[]'::json)
        );
    " > "$output" 2> "${output}.stderr"
}

capture_database_state() {
    output="$1"
    compose exec -T postgres sh -eu -c '
        PGPASSWORD=$(cat /fleet-state/secrets/postgres-bootstrap-password)
        export PGPASSWORD
        exec psql --no-psqlrc --tuples-only --no-align --username aip_bootstrap --dbname postgres --set=ON_ERROR_STOP=1 --command "
            SELECT json_agg(json_build_object(
                '\''database'\'', datname,
                '\''owner'\'', pg_get_userbyid(datdba)
            ) ORDER BY datname)
            FROM pg_database
            WHERE datname IN (
                '\''cal_acme_runtime'\'',
                '\''hermes_acme_runtime'\'',
                '\''chatwoot_acme_runtime'\'',
                '\''dify_acme_runtime'\'',
                '\''crewai_acme_runtime'\'',
                '\''twenty_acme_runtime'\''
            );
        "
    ' > "$output" 2> "${output}.stderr"
}

capture_images() {
    output="$1"
    # The generated environment contains only source/image metadata and no
    # credentials. It is safe to load for deterministic image-name expansion.
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
    docker image inspect \
        "getaip/server:${AIP_IMAGE_TAG}" \
        "getaip/aip-host-cal-diy:${AIP_IMAGE_TAG}" \
        "getaip/aip-host-hermes-agent:${AIP_IMAGE_TAG}" \
        "getaip/aip-host-chatwoot:${AIP_IMAGE_TAG}" \
        "getaip/aip-host-dify:${AIP_IMAGE_TAG}" \
        "getaip/aip-host-crewai:${AIP_IMAGE_TAG}" \
        "getaip/aip-host-twenty:${AIP_IMAGE_TAG}" \
        "getaip/aip-crewai-sidecar:${AIP_IMAGE_TAG}" \
        "getaip/aip-product-upstream-fixture:${AIP_IMAGE_TAG}" \
        > "$output"
}

capture_diagnostics() {
    exit_code=$?
    trap - EXIT HUP INT TERM
    if [ -n "$EVENTS_PID" ]; then
        kill "$EVENTS_PID" >/dev/null 2>&1 || true
        wait "$EVENTS_PID" >/dev/null 2>&1 || true
    fi
    capture_registry_state "${EVIDENCE_DIR}/registry-final-state.json" || true
    capture_database_state "${EVIDENCE_DIR}/database-final-state.json" || true
    capture_images "${EVIDENCE_DIR}/images.json" 2> "${EVIDENCE_DIR}/images.stderr" || true
    compose ps --all --format json > "${EVIDENCE_DIR}/compose-ps.jsonl" 2>/dev/null || true
    compose logs --no-color --timestamps > "${EVIDENCE_DIR}/compose.log" 2>&1 || true
    copy_runtime_evidence
    compose down --volumes --remove-orphans --timeout 30 > "${EVIDENCE_DIR}/compose-down.log" 2>&1 || true
    if [ "$exit_code" -eq 0 ]; then
        printf '{"status":"passed","run_id":"%s","completed_at":"%s"}\n' \
            "$RUN_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${EVIDENCE_DIR}/summary.json"
    else
        printf '{"status":"failed","run_id":"%s","exit_code":%s,"completed_at":"%s"}\n' \
            "$RUN_ID" "$exit_code" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            > "${EVIDENCE_DIR}/summary.json"
    fi
    exit "$exit_code"
}

wait_healthy() {
    service="$1"
    timeout_seconds="${2:-180}"
    deadline=$(( $(date +%s) + timeout_seconds ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        container_id=$(compose ps -q "$service" 2>/dev/null || true)
        if [ -n "$container_id" ]; then
            health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing-healthcheck{{end}}' "$container_id" 2>/dev/null || true)
            if [ "$health" = healthy ]; then
                return 0
            fi
        fi
        sleep 2
    done
    fail "service ${service} did not become healthy within ${timeout_seconds}s"
}

wait_completed() {
    service="$1"
    timeout_seconds="${2:-900}"
    deadline=$(( $(date +%s) + timeout_seconds ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        container_id=$(compose ps -q --all "$service" 2>/dev/null || true)
        if [ -n "$container_id" ]; then
            state=$(docker inspect --format '{{.State.Status}}' "$container_id" 2>/dev/null || true)
            if [ "$state" = exited ]; then
                code=$(docker inspect --format '{{.State.ExitCode}}' "$container_id")
                test "$code" -eq 0 || fail "service ${service} exited with ${code}"
                return 0
            fi
        fi
        sleep 2
    done
    fail "service ${service} did not complete within ${timeout_seconds}s"
}

wait_registry_status() {
    replica="$1"
    wanted="$2"
    timeout_seconds="${3:-60}"
    deadline=$(( $(date +%s) + timeout_seconds ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        status=$(registry_query "SELECT status FROM aip_connector_replicas WHERE replica_id = '${replica}';" 2>/dev/null || true)
        if [ "$status" = "$wanted" ]; then
            return 0
        fi
        sleep 2
    done
    fail "replica ${replica} did not reach registry status ${wanted}"
}

probe() {
    gateway="$1"
    capability="$2"
    input="$3"
    output="$4"
    compose run --rm --no-deps \
        --entrypoint /usr/local/bin/getaip \
        -e GETAIP_NATIVE_PRINCIPAL_ID=service:getaip:cli:qualification-acme \
        -e GETAIP_NATIVE_TRUST_DOMAIN=fleet.test \
        -e GETAIP_NATIVE_SIGNING_SEED_FILE=/fleet-state/secrets/client-acme-signing-seed.hex \
        -e GETAIP_NATIVE_PEER_DID_FILE=/fleet-state/public/gateway.did \
        -e GETAIP_NATIVE_TLS_CA_FILE=/caddy-data/caddy/pki/authorities/local/root.crt \
        qualification action call "$gateway" "$capability" --input "$input" \
        > "$output" 2> "${output}.stderr"
}

expect_completed() {
    case_name="$1"
    gateway="$2"
    capability="$3"
    input="$4"
    output="${EVIDENCE_DIR}/${case_name}.json"
    probe "$gateway" "$capability" "$input" "$output" || fail "${case_name} transport failed"
    grep -q '"status": "completed"' "$output" || fail "${case_name} did not complete"
    record "$case_name" passed completed
}

expect_failed_closed() {
    case_name="$1"
    gateway="$2"
    capability="$3"
    input="$4"
    output="${EVIDENCE_DIR}/${case_name}.json"
    if probe "$gateway" "$capability" "$input" "$output"; then
        if grep -q '"status": "completed"' "$output"; then
            fail "${case_name} unexpectedly completed"
        fi
    fi
    record "$case_name" passed failed_closed
}

service_replica() {
    case "$1" in
        cal-acme-a) echo "$CAL_REPLICA_ID" ;;
        hermes-acme-a) echo "$HERMES_REPLICA_ID" ;;
        chatwoot-acme-a) echo "$CHATWOOT_REPLICA_ID" ;;
        dify-acme-a) echo "$DIFY_REPLICA_ID" ;;
        crewai-acme-a) echo "$CREWAI_REPLICA_ID" ;;
        twenty-acme-a) echo "$TWENTY_REPLICA_ID" ;;
        *) fail "unknown product host $1" ;;
    esac
}

service_capability() {
    case "$1" in
        cal-acme-a) echo cap:cal_diy:profile.get ;;
        hermes-acme-a) echo cap:hermes_agent:qualification:models ;;
        chatwoot-acme-a) echo cap:chatwoot:account.get ;;
        dify-acme-a) echo cap:dify:qualification-app:parameters.get ;;
        crewai-acme-a) echo cap:crewai:support-qualification:status ;;
        twenty-acme-a) echo cap:twenty:metadata.list ;;
        *) fail "unknown product host $1" ;;
    esac
}

service_input() {
    case "$1" in
        crewai-acme-a) printf '%s\n' '{"run_action_id":"act_crewai_qualification_seed"}' ;;
        twenty-acme-a) printf '%s\n' '{"resource":"objects","query":{"limit":1}}' ;;
        cal-acme-a|hermes-acme-a|chatwoot-acme-a|dify-acme-a) printf '%s\n' '{}' ;;
        *) fail "unknown product host $1" ;;
    esac
}

cd "$ROOT"
command -v docker >/dev/null 2>&1 || fail "docker is required"
docker info >/dev/null 2>&1 || fail "the Docker daemon is unavailable"
if [ "${AIP_PRODUCT_FLEET_SKIP_PREPARE:-0}" != 1 ]; then
    "${DEPLOY_DIR}/prepare.sh"
else
    test -s "$ENV_FILE" || fail "qualification environment is missing"
    verify_prepared_fleet
fi
test -s "$ENV_FILE" || fail "qualification environment is missing"
CONNECTOR_RELEASE_ID=$(sed -n 's/^AIP_CONNECTOR_RELEASE_ID=//p' "$ENV_FILE")
case "$CONNECTOR_RELEASE_ID" in
    ''|*[!a-z0-9]*) fail "qualification environment has an invalid connector release id" ;;
esac
CAL_REPLICA_ID=crepl_cal_diy_acme_a_${CONNECTOR_RELEASE_ID}
HERMES_REPLICA_ID=crepl_hermes_agent_acme_a_${CONNECTOR_RELEASE_ID}
CHATWOOT_REPLICA_ID=crepl_chatwoot_acme_a_${CONNECTOR_RELEASE_ID}
DIFY_REPLICA_ID=crepl_dify_acme_a_${CONNECTOR_RELEASE_ID}
CREWAI_REPLICA_ID=crepl_crewai_acme_a_${CONNECTOR_RELEASE_ID}
TWENTY_REPLICA_ID=crepl_twenty_acme_a_${CONNECTOR_RELEASE_ID}
CAL_VERSION_ID=cver_cal_diy_1_0_0_${CONNECTOR_RELEASE_ID}
HERMES_VERSION_ID=cver_hermes_agent_1_0_0_${CONNECTOR_RELEASE_ID}
CHATWOOT_VERSION_ID=cver_chatwoot_1_0_0_${CONNECTOR_RELEASE_ID}
DIFY_VERSION_ID=cver_dify_1_0_0_${CONNECTOR_RELEASE_ID}
CREWAI_VERSION_ID=cver_crewai_1_0_0_${CONNECTOR_RELEASE_ID}
TWENTY_VERSION_ID=cver_twenty_1_0_0_${CONNECTOR_RELEASE_ID}
if [ -e "$EVIDENCE_DIR" ]; then
    fail "evidence directory already exists: ${EVIDENCE_DIR}"
fi
mkdir -p "$EVIDENCE_DIR"
chmod 700 "$EVIDENCE_DIR"
: > "${EVIDENCE_DIR}/failure-matrix.jsonl"
trap capture_diagnostics EXIT HUP INT TERM

compose down --volumes --remove-orphans --timeout 30 >/dev/null 2>&1 || true
docker events \
    --filter "label=com.docker.compose.project=${PROJECT}" \
    --format '{{json .}}' > "${EVIDENCE_DIR}/docker-events.jsonl" 2>&1 &
EVENTS_PID=$!

compose up --detach product-qualification
wait_completed product-qualification 900
copy_runtime_evidence
grep -q '"status":"passed"' \
    "${EVIDENCE_DIR}/runtime-evidence/products/summary.json" || \
    fail "baseline product qualification summary is not PASS"
record baseline_product_qualification passed thirty_one_native_messages

ready_count=$(registry_query "
    SELECT COUNT(*)
    FROM aip_connector_replicas
    WHERE replica_id IN (
        '${CAL_REPLICA_ID}',
        '${HERMES_REPLICA_ID}',
        '${CHATWOOT_REPLICA_ID}',
        '${DIFY_REPLICA_ID}',
        '${CREWAI_REPLICA_ID}',
        '${TWENTY_REPLICA_ID}'
    )
      AND status = 'ready'
      AND lease_expires_at_ms > (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
")
test "$ready_count" -eq 6 || fail "expected six ready product replicas, found ${ready_count}"

capability_counts=$(registry_query "
    SELECT string_agg(version_id || ':' || capability_count, ',' ORDER BY version_id)
    FROM (
        SELECT version_id, COUNT(*)::text AS capability_count
        FROM aip_connector_version_capabilities
        WHERE version_id IN (
            '${CAL_VERSION_ID}',
            '${HERMES_VERSION_ID}',
            '${CHATWOOT_VERSION_ID}',
            '${DIFY_VERSION_ID}',
            '${CREWAI_VERSION_ID}',
            '${TWENTY_VERSION_ID}'
        )
        GROUP BY version_id
    ) counts;
")
expected_counts="${CAL_VERSION_ID}:81,${CHATWOOT_VERSION_ID}:338,${CREWAI_VERSION_ID}:10,${DIFY_VERSION_ID}:74,${HERMES_VERSION_ID}:35,${TWENTY_VERSION_ID}:22"
test "$capability_counts" = "$expected_counts" || \
    fail "unexpected admitted product capability counts: ${capability_counts}"
record product_registry_topology passed six_replicas_560_capabilities

database_count=$(compose exec -T postgres sh -eu -c '
    PGPASSWORD=$(cat /fleet-state/secrets/postgres-bootstrap-password)
    export PGPASSWORD
    exec psql --no-psqlrc --tuples-only --no-align --username aip_bootstrap --dbname postgres --set=ON_ERROR_STOP=1 --command "
        SELECT COUNT(*)::text || '\''|'\'' || COUNT(DISTINCT datdba)::text
        FROM pg_database
        WHERE datname IN (
            '\''cal_acme_runtime'\'',
            '\''hermes_acme_runtime'\'',
            '\''chatwoot_acme_runtime'\'',
            '\''dify_acme_runtime'\'',
            '\''crewai_acme_runtime'\'',
            '\''twenty_acme_runtime'\''
        );
    "
')
test "$database_count" = '6|6' || fail "product runtime databases are not independently owned: ${database_count}"
for database in \
    cal_acme_runtime \
    hermes_acme_runtime \
    chatwoot_acme_runtime \
    dify_acme_runtime \
    crewai_acme_runtime \
    twenty_acme_runtime
do
    table_count=$(database_query "$database" "
        SELECT COUNT(*)
        FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename IN ('aip_schema_migrations', 'aip_idempotency', 'aip_kv', 'aip_queue', 'aip_transactions');
    ")
    test "$table_count" -eq 5 || fail "runtime database ${database} is not fully migrated"
done
record product_runtime_database_isolation passed six_databases_six_owners

capture_registry_state "${EVIDENCE_DIR}/registry-baseline.json"
capture_database_state "${EVIDENCE_DIR}/database-baseline.json"
capture_images "${EVIDENCE_DIR}/images-baseline.json"

for service in cal-acme-a hermes-acme-a chatwoot-acme-a dify-acme-a crewai-acme-a twenty-acme-a
do
    replica=$(service_replica "$service")
    capability=$(service_capability "$service")
    input=$(service_input "$service")
    compose stop --timeout 20 "$service" >/dev/null
    wait_registry_status "$replica" offline 60
    compose start "$service" >/dev/null
    wait_healthy "$service" 180
    expect_completed "graceful_restart_${service}" \
        https://getaip-server.fleet.test:8443 "$capability" "$input"
done
record graceful_product_host_restarts passed six_hosts

for service in cal-acme-a hermes-acme-a chatwoot-acme-a dify-acme-a crewai-acme-a twenty-acme-a
do
    capability=$(service_capability "$service")
    input=$(service_input "$service")
    container_id=$(compose ps -q "$service")
    test -n "$container_id" || fail "container for ${service} is missing"
    docker update --restart=no "$container_id" >/dev/null
    docker kill --signal KILL "$container_id" >/dev/null
    sleep 18
    expect_failed_closed "expired_lease_${service}" \
        https://getaip-server-b.fleet.test:8443 "$capability" "$input"
    docker update --restart=unless-stopped "$container_id" >/dev/null
    compose start "$service" >/dev/null
    wait_healthy "$service" 180
    expect_completed "sigkill_recovery_${service}" \
        https://getaip-server.fleet.test:8443 "$capability" "$input"
done
record product_host_sigkill_matrix passed six_fail_closed_recoveries

compose restart --timeout 20 crewai-sidecar >/dev/null
wait_healthy crewai-sidecar 240
wait_healthy crewai-acme-a 240
wait_registry_status "$CREWAI_REPLICA_ID" ready 60
expect_completed crewai_durable_status_after_restart \
    https://getaip-server-b.fleet.test:8443 \
    cap:crewai:support-qualification:status \
    '{"run_action_id":"act_qualification_crewai_real_run_v1"}'
grep -q 'act_qualification_crewai_real_run_v1' \
    "${EVIDENCE_DIR}/crewai_durable_status_after_restart.json" || \
    fail "CrewAI durable status did not retain the real run identity"
expect_completed crewai_durable_events_after_restart \
    https://getaip-server.fleet.test:8443 \
    cap:crewai:support-qualification:events \
    '{"run_action_id":"act_qualification_crewai_real_run_v1","cursor":0}'
record crewai_durable_sidecar_restart passed real_crew_state_and_events_retained

crewai_sidecar_id=$(compose ps -q crewai-sidecar)
docker update --restart=no "$crewai_sidecar_id" >/dev/null
docker kill --signal KILL "$crewai_sidecar_id" >/dev/null
wait_registry_status "$CREWAI_REPLICA_ID" offline 60
expect_failed_closed crewai_sidecar_outage \
    https://getaip-server-b.fleet.test:8443 \
    cap:crewai:support-qualification:status \
    '{"run_action_id":"act_qualification_crewai_real_run_v1"}'
docker update --restart=unless-stopped "$crewai_sidecar_id" >/dev/null
compose start crewai-sidecar >/dev/null
wait_healthy crewai-sidecar 240
wait_healthy crewai-acme-a 240
wait_registry_status "$CREWAI_REPLICA_ID" ready 60
expect_completed crewai_sidecar_sigkill_recovery \
    https://getaip-server.fleet.test:8443 \
    cap:crewai:support-qualification:status \
    '{"run_action_id":"act_qualification_crewai_real_run_v1"}'

compose stop --timeout 20 getaip-server >/dev/null
expect_completed primary_gateway_outage_secondary_serves \
    https://getaip-server-b.fleet.test:8443 cap:cal_diy:profile.get '{}'
compose start getaip-server >/dev/null
wait_healthy getaip-server 180
compose stop --timeout 20 getaip-server-b >/dev/null
expect_completed secondary_gateway_outage_primary_serves \
    https://getaip-server.fleet.test:8443 cap:chatwoot:account.get '{}'
compose start getaip-server-b >/dev/null
wait_healthy getaip-server-b 180
record dual_gateway_failover passed both_directions

compose stop --timeout 20 postgres >/dev/null
sleep 3
for service in cal-acme-a hermes-acme-a chatwoot-acme-a dify-acme-a crewai-acme-a twenty-acme-a
do
    expect_failed_closed "database_outage_${service}" \
        https://getaip-server.fleet.test:8443 \
        "$(service_capability "$service")" \
        "$(service_input "$service")"
done
compose start postgres >/dev/null
wait_healthy postgres 180
wait_healthy control-plane 240
wait_healthy getaip-server 240
wait_healthy getaip-server-b 240
for service in cal-acme-a hermes-acme-a chatwoot-acme-a dify-acme-a crewai-acme-a twenty-acme-a
do
    wait_healthy "$service" 240
    wait_registry_status "$(service_replica "$service")" ready 60
    expect_completed "database_recovery_${service}" \
        https://getaip-server-b.fleet.test:8443 \
        "$(service_capability "$service")" \
        "$(service_input "$service")"
done
record shared_postgres_outage passed six_fail_closed_six_recovered

final_ready_count=$(registry_query "
    SELECT COUNT(*)
    FROM aip_connector_replicas
    WHERE replica_id IN (
        '${CAL_REPLICA_ID}',
        '${HERMES_REPLICA_ID}',
        '${CHATWOOT_REPLICA_ID}',
        '${DIFY_REPLICA_ID}',
        '${CREWAI_REPLICA_ID}',
        '${TWENTY_REPLICA_ID}'
    )
      AND status = 'ready'
      AND lease_expires_at_ms > (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
")
test "$final_ready_count" -eq 6 || fail "final product topology has ${final_ready_count} ready replicas"
record complete passed product_fleet_failure_matrix
printf 'product connector fleet qualification: PASS evidence=%s\n' "$EVIDENCE_DIR"
