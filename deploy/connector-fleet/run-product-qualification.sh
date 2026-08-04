#!/bin/sh
set -eu

base_url=https://getaip-server.fleet.test:8443
evidence=/qualification-evidence/products
mkdir -p "${evidence}"
: > "${evidence}/operations.jsonl"

native_env() {
    identity="${1:-acme}"
    case "${identity}" in
        acme)
            principal=service:getaip:cli:qualification-acme
            signing_seed=/fleet-state/secrets/client-acme-signing-seed.hex
            ;;
        cal)
            principal=service:getaip:cli:qualification-cal
            signing_seed=/fleet-state/secrets/client-cal-acme-signing-seed.hex
            ;;
        chatwoot)
            principal=service:getaip:cli:qualification-chatwoot
            signing_seed=/fleet-state/secrets/client-chatwoot-acme-signing-seed.hex
            ;;
        twenty)
            principal=service:getaip:cli:qualification-twenty
            signing_seed=/fleet-state/secrets/client-twenty-acme-signing-seed.hex
            ;;
        approver)
            principal=human:qualification-approver
            signing_seed=/fleet-state/secrets/approval-acme-signing-seed.hex
            ;;
        *)
            echo "product qualification: unknown native identity ${identity}" >&2
            return 64
            ;;
    esac
    export GETAIP_NATIVE_PRINCIPAL_ID="${principal}"
    export GETAIP_NATIVE_TRUST_DOMAIN=fleet.test
    export GETAIP_NATIVE_SIGNING_SEED_FILE="${signing_seed}"
    export GETAIP_NATIVE_PEER_DID_FILE=/fleet-state/public/gateway.did
    export GETAIP_NATIVE_TLS_CA_FILE=/caddy-data/caddy/pki/authorities/local/root.crt
    unset GETAIP_NATIVE_BEARER_TOKEN_FILE
}

record_operation() {
    rec_name="$1"
    rec_capability="$2"
    rec_started_at="$3"
    rec_status="$4"
    rec_response="$5"
    printf '{"name":"%s","capability":"%s","started_at":"%s","completed_at":"%s","status":"%s","response":"%s"}\n' \
        "${rec_name}" "${rec_capability}" "${rec_started_at}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "${rec_status}" "${rec_response}" >> "${evidence}/operations.jsonl"
}

run_call() {
    call_name="$1"
    call_capability="$2"
    call_input="$3"
    call_output="${evidence}/${call_name}.json"
    call_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    native_env acme
    if ! getaip action call "${base_url}" "${call_capability}" --input "${call_input}" \
        > "${call_output}" 2> "${call_output}.stderr"; then
        record_operation "${call_name}" "${call_capability}" "${call_started_at}" failed \
            "${call_name}.json"
        return 1
    fi
    grep -q '"status": "completed"' "${call_output}"
    record_operation "${call_name}" "${call_capability}" "${call_started_at}" passed \
        "${call_name}.json"
}

run_governed_mutation() {
    mutation_name="$1"
    mutation_capability="$2"
    mutation_input="$3"
    mutation_idempotency_key="$4"
    mutation_action_id="$5"
    mutation_caller_identity="${6:-acme}"
    mutation_pending_output="${evidence}/${mutation_name}-pending-approval.json"
    mutation_decision_output="${evidence}/${mutation_name}-approval-decision.json"
    mutation_output="${evidence}/${mutation_name}.json"
    mutation_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    native_env "${mutation_caller_identity}"
    if ! getaip action call "${base_url}" "${mutation_capability}" --input "${mutation_input}" \
        --idempotency-key "${mutation_idempotency_key}" --action-id "${mutation_action_id}" \
        > "${mutation_pending_output}" 2> "${mutation_pending_output}.stderr"; then
        record_operation "${mutation_name}.request" "${mutation_capability}" \
            "${mutation_started_at}" failed "${mutation_name}-pending-approval.json"
        return 1
    fi
    if ! grep -q '"status": "pending_approval"' "${mutation_pending_output}"; then
        record_operation "${mutation_name}.request" "${mutation_capability}" \
            "${mutation_started_at}" failed "${mutation_name}-pending-approval.json"
        return 1
    fi
    approval_id=$(sed -n 's/^[[:space:]]*"approval_id": "\([^"]*\)",\{0,1\}$/\1/p' \
        "${mutation_pending_output}" | head -n 1)
    policy_hash=$(sed -n 's/^[[:space:]]*"policy_hash": "\([^"]*\)",\{0,1\}$/\1/p' \
        "${mutation_pending_output}" | head -n 1)
    case "${approval_id}" in
        appr_[A-Za-z0-9_]*) ;;
        *) echo "product qualification: invalid approval id for ${mutation_name}" >&2; return 1 ;;
    esac
    if [ "${#policy_hash}" -ne 64 ] || ! printf '%s' "${policy_hash}" | grep -Eq '^[0-9a-f]{64}$'; then
        echo "product qualification: invalid approval policy hash for ${mutation_name}" >&2
        return 1
    fi
    record_operation "${mutation_name}.request" "${mutation_capability}" \
        "${mutation_started_at}" passed "${mutation_name}-pending-approval.json"

    mutation_decision_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    decided_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    decision=$(printf '{"approval_id":"%s","decision":"approved","approver":{"id":"human:qualification-approver","kind":"human"},"decided_at":"%s","reason":"Approved by the isolated product-fleet qualification authority","constraints":[],"evidence":[],"decision_id":"decision:%s:approved","policy_hash":"%s","authority_path":[]}' \
        "${approval_id}" "${decided_at}" "${approval_id}" "${policy_hash}")
    native_env approver
    if ! getaip approval decide "${base_url}" "${decision}" \
        > "${mutation_decision_output}" 2> "${mutation_decision_output}.stderr"; then
        record_operation "${mutation_name}.approval" "${mutation_capability}" \
            "${mutation_decision_started_at}" failed "${mutation_name}-approval-decision.json"
        return 1
    fi
    if ! grep -q '"kind": "aip.approval.granted"' "${mutation_decision_output}" || \
        ! grep -q '"kind": "aip.action.resumed_result"' "${mutation_decision_output}"; then
        record_operation "${mutation_name}.approval" "${mutation_capability}" \
            "${mutation_decision_started_at}" failed "${mutation_name}-approval-decision.json"
        return 1
    fi
    record_operation "${mutation_name}.approval" "${mutation_capability}" \
        "${mutation_decision_started_at}" passed "${mutation_name}-approval-decision.json"

    mutation_result_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    native_env "${mutation_caller_identity}"
    if ! getaip action call "${base_url}" "${mutation_capability}" \
        --input "${mutation_input}" --idempotency-key "${mutation_idempotency_key}" \
        --action-id "${mutation_action_id}" \
        > "${mutation_output}" 2> "${mutation_output}.stderr"; then
        record_operation "${mutation_name}.result" "${mutation_capability}" \
            "${mutation_result_started_at}" failed "${mutation_name}.json"
        return 1
    fi
    if ! grep -q '"status": "completed"' "${mutation_output}"; then
        record_operation "${mutation_name}.result" "${mutation_capability}" \
            "${mutation_result_started_at}" failed "${mutation_name}.json"
        return 1
    fi
    record_operation "${mutation_name}.result" "${mutation_capability}" \
        "${mutation_result_started_at}" passed "${mutation_name}.json"
}

run_call cal-profile cap:cal_diy:profile.get '{}'
run_call hermes-models cap:hermes_agent:qualification:models '{}'
run_call hermes-jobs cap:hermes_agent:qualification:jobs_list '{"include_disabled":true}'
run_call chatwoot-account cap:chatwoot:account.get '{}'
run_call chatwoot-agents cap:chatwoot:agent.list '{}'
run_call dify-parameters cap:dify:qualification-app:parameters.get '{}'
run_call dify-datasets cap:dify:knowledge:qualification-kb:dataset.list '{"query":{"limit":1}}'
run_call crewai-durable-status cap:crewai:support-qualification:status \
    '{"run_action_id":"act_crewai_qualification_seed"}'
run_call twenty-records cap:twenty:record.list \
    '{"object":"people","query":{"limit":1}}'
run_call twenty-metadata cap:twenty:metadata.list \
    '{"resource":"objects","query":{"limit":1}}'

run_governed_mutation cal-profile-update cap:cal_diy:profile.update \
    '{"name":"Qualification Operator"}' \
    qualification-cal-profile-update-v1 act_qualification_cal_profile_update_v1 cal
run_governed_mutation hermes-job-create cap:hermes_agent:qualification:job_create \
    '{"name":"Qualification Job","schedule":"0 * * * *","prompt":"Verify the connector fleet"}' \
    qualification-hermes-job-create-v1 act_qualification_hermes_job_create_v1
run_governed_mutation chatwoot-conversation-create cap:chatwoot:conversation.create \
    '{"body":{"source_id":"qualification-source","inbox_id":1,"contact_id":1}}' \
    qualification-chatwoot-conversation-create-v1 act_qualification_chatwoot_conversation_create_v1 chatwoot
run_governed_mutation dify-dataset-create cap:dify:knowledge:qualification-kb:dataset.create \
    '{"body":{"name":"Qualification Dataset"}}' \
    qualification-dify-dataset-create-v1 act_qualification_dify_dataset_create_v1
run_governed_mutation crewai-real-run cap:crewai:support-qualification \
    '{"case_id":"AIP-PRODUCT-QUALIFICATION"}' \
    qualification-crewai-real-run-v1 act_qualification_crewai_real_run_v1
run_governed_mutation twenty-person-create cap:twenty:record.create \
    '{"object":"people","body":{"name":{"firstName":"AIP","lastName":"Qualification"},"emails":{"primaryEmail":"aip-qualification@example.invalid"}}}' \
    qualification-twenty-person-create-v1 act_qualification_twenty_person_create_v1 twenty
run_call crewai-real-status cap:crewai:support-qualification:status \
    '{"run_action_id":"act_qualification_crewai_real_run_v1"}'
run_call crewai-real-events cap:crewai:support-qualification:events \
    '{"run_action_id":"act_qualification_crewai_real_run_v1","cursor":0}'

native_env acme
GETAIP_NATIVE_PRINCIPAL_ID=service:getaip:cli:qualification-beta \
GETAIP_NATIVE_SIGNING_SEED_FILE=/fleet-state/secrets/client-beta-signing-seed.hex \
    getaip capability list "${base_url}" --signed-native \
    --capability-id cap:chatwoot:account.get --limit 10 \
    > "${evidence}/tenant-beta-product-isolation.json" \
    2> "${evidence}/tenant-beta-product-isolation.json.stderr"
grep -q '"total": 0' "${evidence}/tenant-beta-product-isolation.json"
printf '%s\n' '{"name":"tenant-beta-product-isolation","capability":"cap:chatwoot:account.get","status":"passed","response":"tenant-beta-product-isolation.json"}' \
    >> "${evidence}/operations.jsonl"

if SSL_CERT_FILE=/caddy-data/caddy/pki/authorities/local/root.crt wget -q \
    --header='Authorization: Bearer deliberately-wrong-token' \
    -O "${evidence}/negative-provider-auth.json" \
    https://cal-provider.fleet.test:8443/v2/me \
    2> "${evidence}/negative-provider-auth.json.stderr"; then
    echo "product qualification: invalid provider credential was accepted" >&2
    exit 1
fi
grep -q '401 Unauthorized' "${evidence}/negative-provider-auth.json.stderr"
printf '%s\n' '{"name":"negative-provider-auth","capability":"direct-provider-boundary","status":"passed","response":"negative-provider-auth.json"}' \
    >> "${evidence}/operations.jsonl"

wget -q -O "${evidence}/upstream-audit.json" \
    http://product-upstream:8095/__fixture/audit
for expected in \
    '"product":"cal-diy","method":"GET","path_and_query":"/v2/me"' \
    '"product":"hermes","method":"GET","path_and_query":"/v1/models"' \
    '"product":"hermes","method":"GET","path_and_query":"/api/jobs?include_disabled=true"' \
    '"product":"chatwoot","method":"GET","path_and_query":"/api/v1/accounts/42"' \
    '"product":"dify","method":"GET","path_and_query":"/v1/parameters"' \
    '"product":"twenty","method":"GET","path_and_query":"/rest/people?limit=1"' \
    '"product":"twenty","method":"GET","path_and_query":"/rest/metadata/objects?limit=1"' \
    '"product":"cal-diy","method":"PATCH","path_and_query":"/v2/me"' \
    '"product":"hermes","method":"POST","path_and_query":"/api/jobs"' \
    '"product":"chatwoot","method":"POST","path_and_query":"/api/v1/accounts/42/conversations"' \
    '"product":"dify","method":"POST","path_and_query":"/v1/datasets"' \
    '"product":"twenty","method":"POST","path_and_query":"/rest/people?upsert=true"' \
    '"idempotency_key_present":true' \
    '"authorization_present":true'
do
    grep -Fq "${expected}" "${evidence}/upstream-audit.json"
done

printf '%s\n' '{"status":"passed","native_messages":31,"action_invocations":24,"idempotent_result_replays":6,"approval_decisions":6,"catalog_queries":1,"read_cases":10,"mutation_cases":6,"durable_replay_cases":2,"product_hosts":6,"product_upstreams":6,"negative_cases":2,"tenant_isolation_cases":1,"durable_sidecars":1}' \
    > "${evidence}/summary.json"
printf 'product connector fleet qualification: PASS\n'
