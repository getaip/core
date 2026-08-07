#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DEPLOY_DIR=${ROOT}/deploy/connector-fleet
COMPOSE_FILE=${DEPLOY_DIR}/compose.yml
ENV_FILE=${DEPLOY_DIR}/.env.qualification
EVIDENCE_DIR=${AIP_FLEET_EVIDENCE_DIR:-${ROOT}/.getaip-fleet-qualification}
PROJECT=aip-connector-fleet-qualification
EVENTS_PID=

fail() {
    echo "connector fleet failure matrix: $*" >&2
    exit 1
}

compose() {
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
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
    target_uid=$(id -u)
    target_gid=$(id -g)
    mkdir -p "${EVIDENCE_DIR}/qualification"
    docker run --rm \
        -e "TARGET_UID=${target_uid}" \
        -e "TARGET_GID=${target_gid}" \
        -v "${PROJECT}_qualification_evidence:/source:ro" \
        -v "${EVIDENCE_DIR}/qualification:/target" \
        alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce \
        sh -eu -c '
            cp -a /source/. /target/
            chown -R "${TARGET_UID}:${TARGET_GID}" /target
            chmod -R u+rwX,go-rwx /target
        ' >/dev/null 2>&1 || true
}

capture_diagnostics() {
    exit_code=$?
    trap - EXIT HUP INT TERM
    if [ -n "$EVENTS_PID" ]; then
        kill "$EVENTS_PID" >/dev/null 2>&1 || true
        wait "$EVENTS_PID" >/dev/null 2>&1 || true
    fi
    capture_registry_state "${EVIDENCE_DIR}/registry-final-state.json" || true
    compose ps --all --format json > "${EVIDENCE_DIR}/compose-ps.jsonl" 2>/dev/null || true
    compose logs --no-color --timestamps > "${EVIDENCE_DIR}/compose.log" 2>&1 || true
    copy_runtime_evidence
    compose down --volumes --remove-orphans --timeout 30 > "${EVIDENCE_DIR}/compose-down.log" 2>&1 || true
    if [ "$exit_code" -eq 0 ]; then
        printf '{"status":"passed","completed_at":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            > "${EVIDENCE_DIR}/summary.json"
    else
        printf '{"status":"failed","exit_code":%s,"completed_at":"%s"}\n' \
            "$exit_code" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            > "${EVIDENCE_DIR}/summary.json"
    fi
    exit "$exit_code"
}

capture_registry_state() {
    registry_state_output="$1"
    registry_query "
        SELECT json_build_object(
            'observed_at_ms', (extract(epoch FROM clock_timestamp()) * 1000)::bigint,
            'replicas', COALESCE((
                SELECT json_agg(json_build_object(
                    'replica_id', replica_id,
                    'instance_id', instance_id,
                    'status', status,
                    'lease_expires_at_ms', lease_expires_at_ms,
                    'lease_remaining_ms', lease_expires_at_ms -
                        (extract(epoch FROM clock_timestamp()) * 1000)::bigint,
                    'capacity', capacity,
                    'active_assignments', active_assignments,
                    'health_revision', health_revision,
                    'consecutive_failures', consecutive_failures,
                    'circuit_open_until_ms', circuit_open_until_ms,
                    'circuit_remaining_ms', circuit_open_until_ms -
                        (extract(epoch FROM clock_timestamp()) * 1000)::bigint
                ) ORDER BY replica_id)
                FROM aip_connector_replicas
            ), '[]'::json),
            'routes', COALESCE((
                SELECT json_agg(json_build_object(
                    'action_id', action_id,
                    'instance_id', instance_id,
                    'replica_id', replica_id,
                    'reserved', reserved,
                    'last_settlement', last_settlement,
                    'assigned_at_ms', assigned_at_ms,
                    'updated_at_ms', updated_at_ms
                ) ORDER BY assigned_at_ms, action_id)
                FROM aip_route_assignments
            ), '[]'::json),
            'admission_counters', COALESCE((
                SELECT json_agg(json_build_object(
                    'scope_kind', scope_kind,
                    'active', active
                ) ORDER BY scope_kind, scope_key)
                FROM aip_connector_admission_counters
            ), '[]'::json)
        );
    " > "$registry_state_output" 2> "${registry_state_output}.stderr"
}

capture_action_route_state() {
    route_state_action_id="$1"
    route_state_output="$2"
    case "$route_state_action_id" in
        *[!A-Za-z0-9:_-]*|'') fail "unsafe action id in diagnostic snapshot" ;;
    esac
    registry_query "
        SELECT json_build_object(
            'observed_at_ms', (extract(epoch FROM clock_timestamp()) * 1000)::bigint,
            'route', (
                SELECT json_build_object(
                    'action_id', a.action_id,
                    'instance_id', a.instance_id,
                    'replica_id', a.replica_id,
                    'reserved', a.reserved,
                    'last_settlement', a.last_settlement,
                    'assigned_at_ms', a.assigned_at_ms,
                    'updated_at_ms', a.updated_at_ms
                )
                FROM aip_route_assignments a
                WHERE a.action_id = '${route_state_action_id}'
            ),
            'replica', (
                SELECT json_build_object(
                    'replica_id', r.replica_id,
                    'status', r.status,
                    'lease_expires_at_ms', r.lease_expires_at_ms,
                    'lease_remaining_ms', r.lease_expires_at_ms -
                        (extract(epoch FROM clock_timestamp()) * 1000)::bigint,
                    'capacity', r.capacity,
                    'active_assignments', r.active_assignments,
                    'health_revision', r.health_revision,
                    'consecutive_failures', r.consecutive_failures,
                    'circuit_open_until_ms', r.circuit_open_until_ms,
                    'circuit_remaining_ms', r.circuit_open_until_ms -
                        (extract(epoch FROM clock_timestamp()) * 1000)::bigint
                )
                FROM aip_connector_replicas r
                JOIN aip_route_assignments a ON a.replica_id = r.replica_id
                WHERE a.action_id = '${route_state_action_id}'
            )
        );
    " > "$route_state_output" 2> "${route_state_output}.stderr"
}

wait_healthy() {
    service="$1"
    timeout_seconds="${2:-120}"
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
    timeout_seconds="${2:-300}"
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

probe() {
    principal="$1"
    seed_file="$2"
    gateway="$3"
    capability="$4"
    input="$5"
    output="$6"
    compose run --rm --no-deps \
        --entrypoint /usr/local/bin/getaip \
        -e "GETAIP_NATIVE_PRINCIPAL_ID=${principal}" \
        -e GETAIP_NATIVE_TRUST_DOMAIN=fleet.test \
        -e "GETAIP_NATIVE_SIGNING_SEED_FILE=${seed_file}" \
        -e GETAIP_NATIVE_PEER_DID_FILE=/fleet-state/public/gateway.did \
        -e GETAIP_NATIVE_TLS_CA_FILE=/caddy-data/caddy/pki/authorities/local/root.crt \
        qualification action call "$gateway" "$capability" --input "$input" \
        > "$output" 2> "${output}.stderr"
}

probe_idempotent() {
    principal="$1"
    seed_file="$2"
    gateway="$3"
    capability="$4"
    input="$5"
    idempotency_key="$6"
    output="$7"
    compose run --rm --no-deps \
        --entrypoint /usr/local/bin/getaip \
        -e "GETAIP_NATIVE_PRINCIPAL_ID=${principal}" \
        -e GETAIP_NATIVE_TRUST_DOMAIN=fleet.test \
        -e "GETAIP_NATIVE_SIGNING_SEED_FILE=${seed_file}" \
        -e GETAIP_NATIVE_PEER_DID_FILE=/fleet-state/public/gateway.did \
        -e GETAIP_NATIVE_TLS_CA_FILE=/caddy-data/caddy/pki/authorities/local/root.crt \
        qualification action call "$gateway" "$capability" --input "$input" \
        --idempotency-key "$idempotency_key" \
        > "$output" 2> "${output}.stderr"
}

probe_idempotent_action() {
    principal="$1"
    seed_file="$2"
    gateway="$3"
    capability="$4"
    input="$5"
    idempotency_key="$6"
    action_id="$7"
    transaction_id="$8"
    output="$9"
    compose run --rm --no-deps \
        --entrypoint /usr/local/bin/getaip \
        -e "GETAIP_NATIVE_PRINCIPAL_ID=${principal}" \
        -e GETAIP_NATIVE_TRUST_DOMAIN=fleet.test \
        -e "GETAIP_NATIVE_SIGNING_SEED_FILE=${seed_file}" \
        -e GETAIP_NATIVE_PEER_DID_FILE=/fleet-state/public/gateway.did \
        -e GETAIP_NATIVE_TLS_CA_FILE=/caddy-data/caddy/pki/authorities/local/root.crt \
        qualification action call "$gateway" "$capability" --input "$input" \
        --action-id "$action_id" \
        --idempotency-key "$idempotency_key" \
        --transaction-mode execute \
        --transaction-id "$transaction_id" \
        > "$output" 2> "${output}.stderr"
}

expect_completed() {
    case_name="$1"
    principal="$2"
    seed_file="$3"
    gateway="$4"
    capability="$5"
    input="$6"
    output="${EVIDENCE_DIR}/${case_name}.json"
    probe "$principal" "$seed_file" "$gateway" "$capability" "$input" "$output" || \
        fail "${case_name} transport failed"
    grep -q '"status": "completed"' "$output" || fail "${case_name} did not complete"
    record "$case_name" passed completed
}

expect_failed_closed() {
    case_name="$1"
    principal="$2"
    seed_file="$3"
    gateway="$4"
    capability="$5"
    input="$6"
    output="${EVIDENCE_DIR}/${case_name}.json"
    if probe "$principal" "$seed_file" "$gateway" "$capability" "$input" "$output"; then
        if grep -q '"status": "completed"' "$output"; then
            fail "${case_name} unexpectedly completed"
        fi
    fi
    record "$case_name" passed failed_closed
}

registry_query() {
    sql="$1"
    compose exec -T postgres sh -eu -c \
        'PGPASSWORD=$(cat /fleet-state/secrets/postgres-bootstrap-password); export PGPASSWORD; exec psql --no-psqlrc --tuples-only --no-align --username aip_bootstrap --dbname aip_registry --set=ON_ERROR_STOP=1 --command "$1"' \
        sh "$sql"
}

provider_support_acme_query() {
    sql="$1"
    compose exec -T postgres sh -eu -c \
        'PGPASSWORD=$(cat /fleet-state/secrets/provider-support-acme-password); export PGPASSWORD; exec psql --no-psqlrc --tuples-only --no-align --username provider_support_acme --dbname provider_support_acme --set=ON_ERROR_STOP=1 --command "$1"' \
        sh "$sql"
}

runtime_support_acme_query() {
    sql="$1"
    compose exec -T postgres sh -eu -c \
        'PGPASSWORD=$(cat /fleet-state/secrets/postgres-bootstrap-password); export PGPASSWORD; exec psql --no-psqlrc --tuples-only --no-align --username aip_bootstrap --dbname support_acme_runtime --set=ON_ERROR_STOP=1 --command "$1"' \
        sh "$sql"
}

checkpoint_volume() {
    docker run --rm \
        -v "${PROJECT}_qualification_checkpoints:/qualification-checkpoints" \
        alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce \
        "$@"
}

set_checkpoint_control() {
    armed="$1"
    generation="$2"
    action_id="$3"
    stage="$4"
    checkpoint_volume sh -eu -c '
        temporary=/qualification-checkpoints/control.json.tmp.$$
        printf "{\"schema_version\":\"aip.execution-crash-control/v1\",\"armed\":%s,\"generation\":\"%s\",\"action_id\":\"%s\",\"stage\":\"%s\"}\n" "$1" "$2" "$3" "$4" > "$temporary"
        chmod 0600 "$temporary"
        chown 10001:10001 "$temporary"
        mv "$temporary" /qualification-checkpoints/control.json
        rm -f /qualification-checkpoints/observed.json
    ' sh "$armed" "$generation" "$action_id" "$stage"
}

wait_for_checkpoint() {
    generation="$1"
    stage="$2"
    output="$3"
    deadline=$(( $(date +%s) + 30 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if checkpoint_volume sh -c 'test -s /qualification-checkpoints/observed.json'; then
            checkpoint_volume cat /qualification-checkpoints/observed.json > "$output"
            grep -q "\"generation\":\"${generation}\"" "$output" || \
                fail "crash checkpoint observation has the wrong generation"
            grep -q "\"stage\":\"${stage}\"" "$output" || \
                fail "crash checkpoint observation has the wrong stage"
            return 0
        fi
        sleep 1
    done
    return 1
}

retry_checkpointed_action() {
    retry_action_id="$1"
    retry_transaction_id="$2"
    retry_idempotency_key="$3"
    retry_input="$4"
    retry_output="$5"
    retry_attempt_log="${retry_output}.attempts.jsonl"
    : > "$retry_attempt_log"
    # A crashed owner can leave a reservation valid for the action timeout plus
    # its fencing grace period. Docker Desktop may also defer auto-removing a
    # completed one-off probe for up to 90 seconds. Keep enough wall-clock
    # budget for that cleanup delay and at least one post-expiry retry.
    retry_deadline=$(( $(date +%s) + 240 ))
    retry_attempt=0
    while [ "$(date +%s)" -lt "$retry_deadline" ]; do
        retry_attempt=$((retry_attempt + 1))
        retry_attempt_output="${retry_output}.attempt-${retry_attempt}.json"
        retry_attempt_state="${retry_output}.attempt-${retry_attempt}.route.json"
        if probe_idempotent_action \
            service:getaip:cli:qualification-acme \
            /fleet-state/secrets/client-acme-signing-seed.hex \
            https://getaip-server.fleet.test:8443 \
            cap:support_sandbox:refund.plan \
            "$retry_input" \
            "$retry_idempotency_key" \
            "$retry_action_id" \
            "$retry_transaction_id" \
            "$retry_attempt_output" && grep -q '"status": "completed"' "$retry_attempt_output"; then
            cp "$retry_attempt_output" "$retry_output"
            cp "${retry_attempt_output}.stderr" "${retry_output}.stderr"
            capture_action_route_state "$retry_action_id" "$retry_attempt_state" || true
            printf '{"attempt":%s,"status":"completed","recorded_at":"%s"}\n' \
                "$retry_attempt" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$retry_attempt_log"
            printf '%s\n' "$retry_attempt" > "${retry_output}.attempts"
            return 0
        fi
        cp "$retry_attempt_output" "$retry_output"
        cp "${retry_attempt_output}.stderr" "${retry_output}.stderr"
        capture_action_route_state "$retry_action_id" "$retry_attempt_state" || true
        printf '{"attempt":%s,"status":"retryable_failure","recorded_at":"%s","response_bytes":%s,"stderr_bytes":%s}\n' \
            "$retry_attempt" \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            "$(wc -c < "$retry_attempt_output" | tr -d ' ')" \
            "$(wc -c < "${retry_attempt_output}.stderr" | tr -d ' ')" \
            >> "$retry_attempt_log"
        sleep 2
    done
    return 1
}

run_crash_window_case() {
    stage="$1"
    suffix="$2"
    generation="crash-${suffix}-v1"
    action_id="act_qualification_crash_${suffix}_v1"
    transaction_id="txn_qualification_crash_${suffix}_v1"
    idempotency_key="qualification-crash-${suffix}-v1"
    refund_id="rf_qualification_crash_${suffix}_v1"
    approval_id="appr_qualification_crash_${suffix}_v1"
    input=$(printf '{"case_id":"case_1001","charge_id":"ch_1001_b","reason":"duplicate_charge","refund_id":"%s","approval_request_id":"%s","approval_ttl_seconds":900}' "$refund_id" "$approval_id")
    interrupted_output="${EVIDENCE_DIR}/crash-window-${suffix}-interrupted.json"
    observed_output="${EVIDENCE_DIR}/crash-window-${suffix}-checkpoint.json"
    recovered_output="${EVIDENCE_DIR}/crash-window-${suffix}-recovered.json"

    set_checkpoint_control true "$generation" "$action_id" "$stage"
    probe_idempotent_action \
        service:getaip:cli:qualification-acme \
        /fleet-state/secrets/client-acme-signing-seed.hex \
        https://getaip-server.fleet.test:8443 \
        cap:support_sandbox:refund.plan \
        "$input" \
        "$idempotency_key" \
        "$action_id" \
        "$transaction_id" \
        "$interrupted_output" &
    probe_pid=$!
    if ! wait_for_checkpoint "$generation" "$stage" "$observed_output"; then
        kill "$probe_pid" >/dev/null 2>&1 || true
        wait "$probe_pid" >/dev/null 2>&1 || true
        fail "host did not reach crash checkpoint ${stage}"
    fi

    support_b_id=$(compose ps -q support-acme-b)
    test -n "$support_b_id" || fail "support-acme-b disappeared during crash checkpoint ${stage}"
    docker update --restart=no "$support_b_id" >/dev/null
    docker kill --signal KILL "$support_b_id" >/dev/null
    interrupted_exit=0
    if wait "$probe_pid" >/dev/null 2>&1; then
        :
    else
        interrupted_exit=$?
    fi
    if grep -q '"status": "completed"' "$interrupted_output"; then
        fail "interrupted request unexpectedly completed at crash checkpoint ${stage}"
    fi
    if [ "$interrupted_exit" -eq 0 ] && \
        ! grep -q '"status": "failed"' "$interrupted_output"; then
        fail "interrupted request returned neither a transport failure nor a failed AIP result at crash checkpoint ${stage}"
    fi
    printf '{"stage":"%s","probe_exit":%s,"aip_failed_result":%s,"recorded_at":"%s"}\n' \
        "$stage" \
        "$interrupted_exit" \
        "$(if grep -q '"status": "failed"' "$interrupted_output"; then printf true; else printf false; fi)" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        > "${interrupted_output}.outcome.json"
    set_checkpoint_control false "disarmed-${generation}" "$action_id" "$stage"
    docker update --restart=unless-stopped "$support_b_id" >/dev/null
    compose start support-acme-b >/dev/null
    wait_healthy support-acme-b 120
    capture_action_route_state \
        "$action_id" \
        "${EVIDENCE_DIR}/crash-window-${suffix}-route-after-restart.json"

    retry_checkpointed_action \
        "$action_id" "$transaction_id" "$idempotency_key" "$input" "$recovered_output" || \
        fail "action did not recover after crash checkpoint ${stage}"

    refund_count=$(provider_support_acme_query "SELECT COUNT(*) FROM billing.refunds WHERE idempotency_key = '${idempotency_key}' AND refund_id = '${refund_id}';")
    approval_count=$(provider_support_acme_query "SELECT COUNT(*) FROM approval.approval_requests WHERE approval_request_id = '${approval_id}';")
    created_event_count=$(provider_support_acme_query "SELECT COUNT(*) FROM audit.events WHERE event_type = 'refund.plan.created' AND payload->>'idempotency_key' = '${idempotency_key}';")
    settlement_count=$(runtime_support_acme_query "SELECT COUNT(*) FROM aip_idempotency WHERE owner_action_id = '${action_id}' AND status = 'settled' AND value->>'action_id' = '${action_id}';")
    result_count=$(runtime_support_acme_query "SELECT COUNT(*) FROM aip_kv WHERE bucket = 'action_results' AND key = '${action_id}' AND value->>'action_id' = '${action_id}';")
    receipt_count=$(runtime_support_acme_query "SELECT COUNT(*) FROM aip_kv WHERE bucket = 'receipt_chains' AND key = 'transaction:${transaction_id}' AND jsonb_array_length(value->'receipts') >= 1;")
    test "$refund_count" -eq 1 || fail "checkpoint ${stage} produced ${refund_count} refund rows"
    test "$approval_count" -eq 1 || fail "checkpoint ${stage} produced ${approval_count} approval rows"
    test "$created_event_count" -eq 1 || fail "checkpoint ${stage} produced ${created_event_count} creation audit events"
    test "$settlement_count" -eq 1 || fail "checkpoint ${stage} produced ${settlement_count} idempotency settlements"
    test "$result_count" -eq 1 || fail "checkpoint ${stage} produced ${result_count} terminal results"
    test "$receipt_count" -eq 1 || fail "checkpoint ${stage} did not retain one receipt chain"
    record "crash_window_${stage}" passed one_effect_one_result_one_receipt_chain
}

set_credential_policy() {
    instance="$1"
    current_revision="$2"
    revoked_revision="${3:-}"
    case "$instance" in
        support-acme|support-beta|enterprise-acme) ;;
        *) fail "unsupported credential policy instance ${instance}" ;;
    esac
    case "$current_revision" in
        credential-v1|credential-v2) ;;
        *) fail "unsupported current credential revision ${current_revision}" ;;
    esac
    case "$revoked_revision" in
        "") revoked_json='[]' ;;
        credential-v1|credential-v2) revoked_json="[\"${revoked_revision}\"]" ;;
        *) fail "unsupported revoked credential revision ${revoked_revision}" ;;
    esac
    compose run --rm --no-deps --user 10001:10001 --entrypoint /bin/sh secrets-init \
        -eu -c '
            path="/fleet-state/public/$1-credential-policy.json"
            temporary="${path}.tmp.$$"
            printf "{\"current_revision_ref\":\"%s\",\"accepted_previous_revisions\":[],\"revoked_revisions\":%s}\n" "$2" "$3" > "$temporary"
            chmod 0600 "$temporary"
            mv "$temporary" "$path"
        ' sh "$instance" "$current_revision" "$revoked_json" >/dev/null
}

cd "$ROOT"
"${DEPLOY_DIR}/prepare.sh"
CONNECTOR_RELEASE_ID=$(sed -n 's/^AIP_CONNECTOR_RELEASE_ID=//p' "$ENV_FILE")
case "$CONNECTOR_RELEASE_ID" in
    ''|*[!a-z0-9]*) fail "qualification environment has an invalid connector release id" ;;
esac
CONNECTOR_RELEASE_REVISION=$(sed -n 's/^AIP_CONNECTOR_RELEASE_REVISION=//p' "$ENV_FILE")
case "$CONNECTOR_RELEASE_REVISION" in
    ''|0|*[!0-9]*) fail "qualification environment has an invalid connector release revision" ;;
esac
SUPPORT_ACME_A_REPLICA_ID=crepl_support_acme_a_${CONNECTOR_RELEASE_ID}
rm -rf "$EVIDENCE_DIR"
mkdir -p "$EVIDENCE_DIR"
: > "${EVIDENCE_DIR}/failure-matrix.jsonl"
chmod 700 "$EVIDENCE_DIR"
trap capture_diagnostics EXIT HUP INT TERM

compose down --volumes --remove-orphans --timeout 30 >/dev/null 2>&1 || true
docker events \
    --filter "label=com.docker.compose.project=${PROJECT}" \
    --format '{{json .}}' > "${EVIDENCE_DIR}/docker-events.jsonl" 2>&1 &
EVENTS_PID=$!

compose up --detach qualification
wait_completed qualification 300
record baseline_qualification passed four_calls_and_signed_orchestration

ready_count=$(registry_query "SELECT COUNT(*) FROM aip_connector_replicas WHERE status = 'ready' AND lease_expires_at_ms > (extract(epoch FROM clock_timestamp()) * 1000)::bigint;")
test "$ready_count" -eq 4 || fail "expected four ready connector replicas, found ${ready_count}"
record registry_topology passed four_ready_replicas

set_credential_policy support-acme credential-v2 credential-v1
expect_failed_closed credential_revision_revocation \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    https://getaip-server.fleet.test:8443 \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1001"}'
if ! grep -q 'credential_revision_denied' \
    "${EVIDENCE_DIR}/credential_revision_revocation.json" \
    "${EVIDENCE_DIR}/credential_revision_revocation.json.stderr"; then
    fail "credential revision revocation did not return the expected fail-closed code"
fi
set_credential_policy support-acme credential-v1
expect_completed credential_revision_atomic_restore \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    https://getaip-server.fleet.test:8443 \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1001"}'

expect_completed secondary_gateway_baseline \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    https://getaip-server-b.fleet.test:8443 \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1001"}'

expect_failed_closed tenant_provider_isolation \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    https://getaip-server.fleet.test:8443 \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1002"}'

compose stop --timeout 20 getaip-server
expect_completed gateway_replica_failover \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    https://getaip-server-b.fleet.test:8443 \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1001"}'
compose start getaip-server
wait_healthy getaip-server 120

compose stop --timeout 20 support-acme-a
status_a=$(registry_query "SELECT status FROM aip_connector_replicas WHERE replica_id = '${SUPPORT_ACME_A_REPLICA_ID}';")
test "$status_a" = offline || fail "graceful host shutdown did not record offline status: ${status_a}"
expect_completed zonal_connector_failover \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    https://getaip-server.fleet.test:8443 \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1001"}'

support_b_id=$(compose ps -q support-acme-b)
test -n "$support_b_id" || fail "support-acme-b container is missing"
# Disable the container-level restart policy before the hard kill. Otherwise
# Docker would immediately replace the process and the test would never expose
# the lease-expiry window it claims to qualify.
docker update --restart=no "$support_b_id" >/dev/null
docker kill --signal KILL "$support_b_id" >/dev/null
sleep 18
expect_failed_closed expired_lease_blocks_routing \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    https://getaip-server-b.fleet.test:8443 \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1001"}'

docker update --restart=unless-stopped "$support_b_id" >/dev/null
compose start support-acme-b
wait_healthy support-acme-b 120
expect_completed host_recovery_after_sigkill \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    https://getaip-server.fleet.test:8443 \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1001"}'
compose start support-acme-a
wait_healthy support-acme-a 120

# Prove the financial side-effect boundary, not merely HTTP availability. The
# first mutation is forced through replica B, which is then killed without a
# graceful lifecycle transition. Replaying the same AIP idempotency key after
# process replacement must return successfully while the provider system of
# record still contains exactly one refund and one approval request.
compose stop --timeout 20 support-acme-a
IDEMPOTENCY_KEY=qualification-refund-plan-restart-v1
REFUND_ID=rf_qualification_restart_v1
APPROVAL_ID=appr_qualification_restart_v1
REFUND_INPUT=$(printf '{"case_id":"case_1001","charge_id":"ch_1001_b","reason":"duplicate_charge","refund_id":"%s","approval_request_id":"%s","approval_ttl_seconds":900}' "$REFUND_ID" "$APPROVAL_ID")
FIRST_REFUND_OUTPUT="${EVIDENCE_DIR}/idempotent_refund_before_sigkill.json"
probe_idempotent \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    https://getaip-server.fleet.test:8443 \
    cap:support_sandbox:refund.plan \
    "$REFUND_INPUT" \
    "$IDEMPOTENCY_KEY" \
    "$FIRST_REFUND_OUTPUT" || fail "financial mutation before SIGKILL failed"
grep -q '"status": "completed"' "$FIRST_REFUND_OUTPUT" || \
    fail "financial mutation before SIGKILL did not complete"

support_b_id=$(compose ps -q support-acme-b)
test -n "$support_b_id" || fail "support-acme-b container is missing before replay test"
docker update --restart=no "$support_b_id" >/dev/null
docker kill --signal KILL "$support_b_id" >/dev/null
docker update --restart=unless-stopped "$support_b_id" >/dev/null
compose start support-acme-b
wait_healthy support-acme-b 120

SECOND_REFUND_OUTPUT="${EVIDENCE_DIR}/idempotent_refund_after_sigkill.json"
probe_idempotent \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    https://getaip-server-b.fleet.test:8443 \
    cap:support_sandbox:refund.plan \
    "$REFUND_INPUT" \
    "$IDEMPOTENCY_KEY" \
    "$SECOND_REFUND_OUTPUT" || fail "financial mutation replay after SIGKILL failed"
grep -q '"status": "completed"' "$SECOND_REFUND_OUTPUT" || \
    fail "financial mutation replay after SIGKILL did not complete"

refund_count=$(provider_support_acme_query "SELECT COUNT(*) FROM billing.refunds WHERE idempotency_key = '${IDEMPOTENCY_KEY}' AND refund_id = '${REFUND_ID}';")
approval_count=$(provider_support_acme_query "SELECT COUNT(*) FROM approval.approval_requests WHERE approval_request_id = '${APPROVAL_ID}';")
created_event_count=$(provider_support_acme_query "SELECT COUNT(*) FROM audit.events WHERE event_type = 'refund.plan.created' AND payload->>'idempotency_key' = '${IDEMPOTENCY_KEY}';")
test "$refund_count" -eq 1 || fail "idempotent replay created ${refund_count} refund rows"
test "$approval_count" -eq 1 || fail "idempotent replay created ${approval_count} approval rows"
test "$created_event_count" -eq 1 || fail "idempotent replay created ${created_event_count} creation audit events"
record financial_idempotency_after_sigkill passed one_refund_one_approval_one_creation_event
compose start support-acme-a
wait_healthy support-acme-a 120

# Exercise every synchronous provider crash boundary with one stable ActionId,
# transaction id, idempotency key, instance, and replica. The observer writes a
# durable marker only after the selected boundary is reached; the controller
# then sends SIGKILL and retries through the replacement process. Runtime and
# provider databases are queried independently after recovery.
compose stop --timeout 20 support-acme-a
run_crash_window_case before_intent_persistence before_intent
run_crash_window_case intent_persisted after_intent
run_crash_window_case provider_effect_committed after_effect
run_crash_window_case provider_response_received after_provider_response
run_crash_window_case result_persisted after_result
compose start support-acme-a
wait_healthy support-acme-a 120

compose stop --timeout 20 postgres
expect_failed_closed registry_and_runtime_database_outage \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    https://getaip-server.fleet.test:8443 \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1001"}'
compose start postgres
wait_healthy postgres 120
wait_healthy control-plane 120
wait_healthy getaip-server 180
wait_healthy getaip-server-b 180
wait_healthy support-acme-a 180
wait_healthy support-acme-b 180
expect_completed database_recovery_without_process_replacement \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    https://getaip-server.fleet.test:8443 \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1001"}'

compose run --rm --no-deps --entrypoint /usr/local/bin/getaip qualification \
    connector registry status \
    --package-id qualification-support-sandbox \
    --revision "$CONNECTOR_RELEASE_REVISION" \
    --database-url-file /fleet-state/secrets/registry-admin.url \
    > "${EVIDENCE_DIR}/admission-status-before-revoke.json"
compose run --rm --no-deps --entrypoint /usr/local/bin/getaip qualification \
    connector registry revoke \
    --package-id qualification-support-sandbox \
    --revision "$CONNECTOR_RELEASE_REVISION" \
    --reason qualification_failure_matrix_complete \
    --database-url-file /fleet-state/secrets/registry-admin.url \
    > "${EVIDENCE_DIR}/admission-revoke.json"
expect_failed_closed cryptographic_admission_revocation \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    https://getaip-server-b.fleet.test:8443 \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1001"}'

record complete passed all_failure_cases
printf 'connector fleet failure matrix: PASS evidence=%s\n' "$EVIDENCE_DIR"
