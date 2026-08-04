#!/bin/sh
set -eu

base_url=https://getaip-server.fleet.test:8443
provider_url=https://wa-archive-provider.fleet.test:8443
evidence=/qualification-evidence/wa-archive
mkdir -p "${evidence}"
: > "${evidence}/operations.jsonl"

export GETAIP_NATIVE_PRINCIPAL_ID=service:getaip:cli:qualification-acme
export GETAIP_NATIVE_TRUST_DOMAIN=fleet.test
export GETAIP_NATIVE_SIGNING_SEED_FILE=/fleet-state/secrets/client-acme-signing-seed.hex
export GETAIP_NATIVE_PEER_DID_FILE=/fleet-state/public/gateway.did
export GETAIP_NATIVE_TLS_CA_FILE=/caddy-data/caddy/pki/authorities/local/root.crt
export SSL_CERT_FILE=/caddy-data/caddy/pki/authorities/local/root.crt

record() {
    name=$1
    status=$2
    artifact=$3
    printf '{"name":"%s","status":"%s","artifact":"%s","completed_at":"%s"}\n' \
        "${name}" "${status}" "${artifact}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        >> "${evidence}/operations.jsonl"
}

call_read() {
    name=$1
    capability=$2
    input=$3
    output="${evidence}/${name}.json"
    if ! getaip action call "${base_url}" "${capability}" --input "${input}" \
        > "${output}" 2> "${output}.stderr"; then
        record "${name}" failed "${name}.json"
        return 1
    fi
    grep -q '"status": "completed"' "${output}"
    record "${name}" passed "${name}.json"
}

call_read account-binding cap:wa_archive:query:archive.account.get '{}'
grep -Fq "${WA_ARCHIVE_ACCOUNT_ID}" "${evidence}/account-binding.json"
call_read message-page cap:wa_archive:query:archive.message.list '{"limit":1}'
call_read outbox-page cap:wa_archive:query:archive.outbox.list '{"limit":1}'

dry_run_output="${evidence}/send-message-dry-run.json"
if ! getaip action call "${base_url}" cap:wa_archive:send_message \
    --input '{"to_phone":"971500000001","operation":{"kind":"send_message"},"body":"AIP qualification dry run","max_attempts":1}' \
    --transaction-mode dry-run \
    --action-id act_wa_archive_qualification_dry_run \
    --idempotency-key wa-archive-qualification-dry-run-v1 \
    > "${dry_run_output}" 2> "${dry_run_output}.stderr"; then
    record send-message-dry-run failed send-message-dry-run.json
    exit 1
fi
grep -q '"status": "completed"' "${dry_run_output}"
grep -q '"side_effect_committed": false' "${dry_run_output}"
record send-message-dry-run passed send-message-dry-run.json

catalog_output="${evidence}/catalog.json"
getaip capability list "${base_url}" --signed-native \
    --capability-id cap:wa_archive:query:archive.account.get --limit 10 \
    > "${catalog_output}" 2> "${catalog_output}.stderr"
grep -q '"id": "cap:wa_archive:query:archive.account.get"' "${catalog_output}"
record catalog passed catalog.json

control_catalog_output="${evidence}/control-catalog.json"
getaip capability list "${base_url}" --signed-native \
    --capability-id cap:wa_archive:archive.ambiguity.resolve --limit 10 \
    > "${control_catalog_output}" 2> "${control_catalog_output}.stderr"
grep -q '"id": "cap:wa_archive:archive.ambiguity.resolve"' "${control_catalog_output}"
grep -q '"requires_human_approval": true' "${control_catalog_output}"
record control-catalog passed control-catalog.json

beta_output="${evidence}/tenant-beta-isolation.json"
GETAIP_NATIVE_PRINCIPAL_ID=service:getaip:cli:qualification-beta \
GETAIP_NATIVE_SIGNING_SEED_FILE=/fleet-state/secrets/client-beta-signing-seed.hex \
    getaip capability list "${base_url}" --signed-native \
    --capability-id cap:wa_archive:query:archive.account.get --limit 10 \
    > "${beta_output}" 2> "${beta_output}.stderr"
grep -q '"total": 0' "${beta_output}"
record tenant-beta-isolation passed tenant-beta-isolation.json

connector_token=$(cat /fleet-state/secrets/wa-archive-connector-token)
capabilities_output="${evidence}/provider-capabilities.json"
wget -q \
    --header="Authorization: Bearer ${connector_token}" \
    --header="x-aip-external-account-id: ${WA_ARCHIVE_ACCOUNT_ID}" \
    --header="x-request-id: qualification-provider-capabilities" \
    -O "${capabilities_output}" \
    "${provider_url}/v1/capabilities"
grep -Fq "${WA_ARCHIVE_PROVIDER_SOURCE_REVISION}" "${capabilities_output}"
grep -Fq 'wa-archive-aip-connector/v1' "${capabilities_output}"
record provider-capabilities passed provider-capabilities.json

feed_output="${evidence}/provider-change-feed.json"
wget -q \
    --header="Authorization: Bearer ${connector_token}" \
    --header="x-aip-external-account-id: ${WA_ARCHIVE_ACCOUNT_ID}" \
    --header="x-request-id: qualification-provider-change-feed" \
    -O "${feed_output}" \
    "${provider_url}/v1/change-feed?afterSequence=0&limit=10&waitMs=0"
grep -q '"nextCursor"' "${feed_output}"
grep -q '"oldestCursor"' "${feed_output}"
grep -q '"latestCursor"' "${feed_output}"
if grep -Eq '"(mediaPath|sessionPath|filesystemPath)"' "${feed_output}"; then
    record provider-change-feed failed provider-change-feed.json
    exit 1
fi
record provider-change-feed passed provider-change-feed.json

negative_output="${evidence}/provider-invalid-auth.json"
if wget -q \
    --header='Authorization: Bearer deliberately-invalid-qualification-token' \
    -O "${negative_output}" \
    "${provider_url}/v1/account" \
    2> "${negative_output}.stderr"; then
    record provider-invalid-auth failed provider-invalid-auth.json
    exit 1
fi
grep -q '401 Unauthorized' "${negative_output}.stderr"
record provider-invalid-auth passed provider-invalid-auth.json

printf '%s\n' '{"status":"passed","cases":10,"aip_read_cases":3,"aip_dry_run_cases":1,"catalog_cases":2,"tenant_isolation_cases":1,"provider_contract_cases":2,"negative_auth_cases":1,"external_side_effects":0}' \
    > "${evidence}/summary.json"
printf 'WA Archive connector qualification: PASS\n'
