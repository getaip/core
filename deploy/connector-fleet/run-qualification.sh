#!/bin/sh
set -eu

base_url=https://getaip-server.fleet.test:8443
evidence=/qualification-evidence
mkdir -p "${evidence}"
: > "${evidence}/operations.jsonl"

run_call() {
    name="$1"
    tenant="$2"
    principal="$3"
    seed_file="$4"
    capability="$5"
    input="$6"
    gateway_url="${7:-${base_url}}"
    output="${evidence}/${name}.json"
    started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    attempt=1
    max_attempts=3
    while [ "${attempt}" -le "${max_attempts}" ]; do
        attempt_output="${output}.attempt-${attempt}"
        call_exit=0
        GETAIP_NATIVE_PRINCIPAL_ID="${principal}" \
        GETAIP_NATIVE_TRUST_DOMAIN=fleet.test \
        GETAIP_NATIVE_SIGNING_SEED_FILE="${seed_file}" \
        GETAIP_NATIVE_PEER_DID_FILE=/fleet-state/public/gateway.did \
        GETAIP_NATIVE_TLS_CA_FILE=/caddy-data/caddy/pki/authorities/local/root.crt \
            getaip action call "${gateway_url}" "${capability}" --input "${input}" \
            > "${attempt_output}" 2> "${attempt_output}.stderr" || call_exit=$?
        cp "${attempt_output}" "${output}"
        cp "${attempt_output}.stderr" "${output}.stderr"
        if [ "${call_exit}" -eq 0 ] && grep -q '"status": "completed"' "${output}"; then
            printf '{"name":"%s","tenant":"%s","gateway":"%s","started_at":"%s","completed_at":"%s","status":"passed","attempts":%s,"response":"%s"}\n' \
                "${name}" "${tenant}" "${gateway_url}" "${started_at}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${attempt}" "${name}.json" \
                >> "${evidence}/operations.jsonl"
            printf '%s %s PASS attempts=%s\n' "${name}" "${tenant}" "${attempt}"
            return 0
        fi
        if [ "${attempt}" -ge "${max_attempts}" ] || \
            { [ -s "${output}" ] && ! grep -q '"retryable": true' "${output}"; }; then
            printf '{"name":"%s","tenant":"%s","gateway":"%s","started_at":"%s","completed_at":"%s","status":"failed","attempts":%s,"response":"%s"}\n' \
                "${name}" "${tenant}" "${gateway_url}" "${started_at}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${attempt}" "${name}.json" \
                >> "${evidence}/operations.jsonl"
            return 1
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
}

run_call \
    support-acme-read \
    tenant-acme \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1001"}'

run_call \
    support-beta-read \
    tenant-beta \
    service:getaip:cli:qualification-beta \
    /fleet-state/secrets/client-beta-signing-seed.hex \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1002"}'

run_call \
    enterprise-acme-read \
    tenant-acme \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    cap:enterprise_sandbox:incident.get \
    '{"workflow_id":"inc_5001"}'

run_call \
    support-acme-read-secondary-gateway \
    tenant-acme \
    service:getaip:cli:qualification-acme \
    /fleet-state/secrets/client-acme-signing-seed.hex \
    cap:support_sandbox:support.case.get \
    '{"case_id":"case_1001"}' \
    https://getaip-server-b.fleet.test:8443

catalog_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
GETAIP_NATIVE_BEARER_TOKEN_FILE=/fleet-state/secrets/native-bearer-token \
GETAIP_NATIVE_TLS_CA_FILE=/caddy-data/caddy/pki/authorities/local/root.crt \
    getaip capability list "${base_url}" \
    --capability-id cap:support_sandbox:support.case.get \
    --limit 10 > "${evidence}/tenant-capability-catalog.json"
grep -q '"id": "cap:support_sandbox:support.case.get"' \
    "${evidence}/tenant-capability-catalog.json"
printf '{"name":"tenant-capability-catalog","tenant":"tenant-acme","started_at":"%s","completed_at":"%s","status":"passed","response":"tenant-capability-catalog.json"}\n' \
    "${catalog_started_at}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >> "${evidence}/operations.jsonl"

signed_catalog_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
GETAIP_NATIVE_PRINCIPAL_ID=service:getaip:cli:qualification-acme \
GETAIP_NATIVE_TRUST_DOMAIN=fleet.test \
GETAIP_NATIVE_SIGNING_SEED_FILE=/fleet-state/secrets/client-acme-signing-seed.hex \
GETAIP_NATIVE_PEER_DID_FILE=/fleet-state/public/gateway.did \
GETAIP_NATIVE_TLS_CA_FILE=/caddy-data/caddy/pki/authorities/local/root.crt \
    getaip capability list "${base_url}" --signed-native \
    --capability-id cap:enterprise_sandbox:incident.get --limit 10 \
    > "${evidence}/signed-capability-catalog-acme.json"
grep -q '"id": "cap:enterprise_sandbox:incident.get"' \
    "${evidence}/signed-capability-catalog-acme.json"
printf '{"name":"signed-capability-catalog-acme","tenant":"tenant-acme","started_at":"%s","completed_at":"%s","status":"passed","response":"signed-capability-catalog-acme.json"}\n' \
    "${signed_catalog_started_at}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >> "${evidence}/operations.jsonl"

signed_catalog_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
GETAIP_NATIVE_PRINCIPAL_ID=service:getaip:cli:qualification-beta \
GETAIP_NATIVE_TRUST_DOMAIN=fleet.test \
GETAIP_NATIVE_SIGNING_SEED_FILE=/fleet-state/secrets/client-beta-signing-seed.hex \
GETAIP_NATIVE_PEER_DID_FILE=/fleet-state/public/gateway.did \
GETAIP_NATIVE_TLS_CA_FILE=/caddy-data/caddy/pki/authorities/local/root.crt \
    getaip capability list "${base_url}" --signed-native \
    --capability-id cap:enterprise_sandbox:incident.get --limit 10 \
    > "${evidence}/signed-capability-catalog-beta.json"
grep -q '"total": 0' "${evidence}/signed-capability-catalog-beta.json"
printf '{"name":"signed-capability-catalog-beta-isolation","tenant":"tenant-beta","started_at":"%s","completed_at":"%s","status":"passed","response":"signed-capability-catalog-beta.json"}\n' \
    "${signed_catalog_started_at}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >> "${evidence}/operations.jsonl"

orchestration_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
getaip connector orchestration sign \
    --package /fleet-state/public/support-admission.json \
    --admission-trust-policy /fleet-state/public/admission-policy.json \
    --intent /fleet-state/public/support-acme-intent.json \
    --observed /fleet-state/public/support-acme-observed.json \
    --orchestration-policy /fleet-state/public/orchestration-policy.json \
    --signing-seed-file /fleet-state/secrets/orchestration-signing-seed.hex \
    --signer-identity service:aip-qualification-orchestrator \
    > "${evidence}/support-acme-orchestration-plan.json"
getaip connector orchestration verify \
    --plan "${evidence}/support-acme-orchestration-plan.json" \
    --current-observed /fleet-state/public/support-acme-observed.json \
    --orchestration-policy /fleet-state/public/orchestration-policy.json \
    > "${evidence}/support-acme-orchestration-verified.json"
grep -q '"status": "verified"' "${evidence}/support-acme-orchestration-verified.json"
grep -q '"snapshot_fenced": true' "${evidence}/support-acme-orchestration-verified.json"
printf '{"name":"support-acme-orchestration","tenant":"tenant-acme","started_at":"%s","completed_at":"%s","status":"passed","response":"support-acme-orchestration-verified.json"}\n' \
    "${orchestration_started_at}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >> "${evidence}/operations.jsonl"

printf '{"status":"passed","cases":8,"gateways":2,"connector_instances":3,"connector_replicas":4,"orchestration_plans":1,"catalog_queries":3,"signed_catalog_queries":2}\n' > "${evidence}/summary.json"
