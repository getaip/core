#!/bin/sh
set -eu

umask 077
root=/fleet-state
secrets="${root}/secrets"
public="${root}/public"
evidence=/qualification-evidence
checkpoints=/qualification-checkpoints
crewai_state=/crewai-sidecar-state
wa_archive_secrets=/wa-archive-secrets
mkdir -p \
    "${secrets}" \
    "${public}" \
    "${evidence}" \
    "${crewai_state}/home" \
    "${crewai_state}/crewai" \
    "${wa_archive_secrets}"
chown 10001:10001 "${public}"
# Multiple isolated service identities need to traverse to their exact
# owner-only file, while directory enumeration must remain unavailable.
chmod 0711 "${secrets}"
chmod 0700 "${public}"
chown 10001:10001 "${evidence}"
chmod 0700 "${evidence}"
chown 10001:10001 "${checkpoints}"
chmod 0700 "${checkpoints}"
chown -R 10001:10001 "${crewai_state}"
chmod 0700 "${crewai_state}" "${crewai_state}/home" "${crewai_state}/crewai"
chown 10001:10001 "${wa_archive_secrets}"
chmod 0700 "${wa_archive_secrets}"

checkpoint_control="${checkpoints}/control.json"
checkpoint_temporary="${checkpoint_control}.tmp.$$"
printf '%s\n' '{"schema_version":"aip.execution-crash-control/v1","armed":false,"generation":"initial","action_id":"act_disabled","stage":"before_intent_persistence"}' > "${checkpoint_temporary}"
chmod 0600 "${checkpoint_temporary}"
chown 10001:10001 "${checkpoint_temporary}"
mv "${checkpoint_temporary}" "${checkpoint_control}"
rm -f "${checkpoints}/observed.json"

random_hex() {
    bytes="$1"
    head -c "${bytes}" /dev/urandom | od -An -tx1 | tr -d ' \n'
}

write_once() {
    path="$1"
    owner="$2"
    value="$3"
    if [ -e "${path}" ]; then
        test -s "${path}"
        chmod 0600 "${path}"
        chown "${owner}" "${path}"
        return
    fi
    temporary="${path}.tmp.$$"
    (umask 077; printf '%s\n' "${value}" > "${temporary}")
    chmod 0600 "${temporary}"
    chown "${owner}" "${temporary}"
    mv "${temporary}" "${path}"
}

for name in \
    release-signing \
    evidence-oci-signature \
    evidence-sbom \
    evidence-provenance \
    evidence-conformance \
    evidence-vulnerability \
    evidence-license \
    evidence-revocation \
    control-signing \
    gateway-signing \
    orchestration-signing \
    client-acme-signing \
    client-beta-signing \
    client-cal-acme-signing \
    client-chatwoot-acme-signing \
    client-twenty-acme-signing \
    approval-acme-signing \
    support-acme-a-signing \
    support-acme-b-signing \
    support-beta-a-signing \
    enterprise-acme-a-signing \
    cal-acme-a-signing \
    hermes-acme-a-signing \
    chatwoot-acme-a-signing \
    dify-acme-a-signing \
    crewai-acme-a-signing \
    twenty-acme-a-signing \
    wa-archive-acme-a-signing
do
    write_once "${secrets}/${name}-seed.hex" 10001:10001 "$(random_hex 32)"
done

write_once "${secrets}/native-bearer-token" 10001:10001 "$(random_hex 32)"

for role in \
    postgres-bootstrap \
    registry-admin \
    registry-data \
    registry-lifecycle \
    getaip-server-runtime \
    support-acme-runtime \
    support-beta-runtime \
    enterprise-acme-runtime \
    cal-acme-runtime \
    hermes-acme-runtime \
    chatwoot-acme-runtime \
    dify-acme-runtime \
    crewai-acme-runtime \
    twenty-acme-runtime \
    wa-archive-acme-runtime \
    provider-support-acme \
    provider-support-beta \
    provider-enterprise-acme \
    provider-wa-archive-acme
do
    write_once "${secrets}/${role}-password" 70:70 "$(random_hex 32)"
done

write_once "${secrets}/cal-api-token" 10001:10001 "qualification-cal-token"
write_once "${secrets}/hermes-api-token" 10001:10001 "qualification-hermes-token"
write_once "${secrets}/chatwoot-api-token" 10001:10001 "qualification-chatwoot-token"
write_once "${secrets}/chatwoot-webhook-secret" 10001:10001 "qualification-chatwoot-webhook"
write_once "${secrets}/dify-app-api-token" 10001:10001 "qualification-dify-app-token"
write_once "${secrets}/dify-knowledge-api-token" 10001:10001 "qualification-dify-knowledge-token"
write_once "${secrets}/crewai-sidecar-token" 10001:10001 "qualification-crewai-sidecar-token"
write_once "${secrets}/twenty-api-token" 10001:10001 "qualification-twenty-token"
write_once "${secrets}/twenty-webhook-secret" 10001:10001 "qualification-twenty-webhook"
write_once "${wa_archive_secrets}/operator-token" 10001:10001 "$(random_hex 32)"
if [ -s "${secrets}/wa-archive-connector-token" ]; then
    connector_token="$(cat "${secrets}/wa-archive-connector-token")"
elif [ -s "${wa_archive_secrets}/connector-token" ]; then
    connector_token="$(cat "${wa_archive_secrets}/connector-token")"
else
    connector_token="$(random_hex 32)"
fi
write_once "${secrets}/wa-archive-connector-token" 10001:10001 "${connector_token}"
write_once "${wa_archive_secrets}/connector-token" 10001:10001 "${connector_token}"
cmp -s \
    "${secrets}/wa-archive-connector-token" \
    "${wa_archive_secrets}/connector-token" || {
    echo "WA Archive connector-token copies disagree; rotate them explicitly" >&2
    exit 1
}

write_once "${secrets}/issued-at.txt" 10001:10001 "$(date +%s)"

for instance in \
    support-acme \
    support-beta \
    enterprise-acme \
    cal-acme \
    hermes-acme \
    chatwoot-acme \
    dify-acme \
    crewai-acme \
    twenty-acme \
    wa-archive-acme
do
    write_once \
        "${public}/${instance}-credential-policy.json" \
        10001:10001 \
        '{"current_revision_ref":"credential-v1","accepted_previous_revisions":[],"revoked_revisions":[]}'
done

write_once \
    "${public}/hermes-endpoints.json" \
    10001:10001 \
    '[{"id":"qualification","base_url":"https://hermes-provider.fleet.test:8443","api_key_file":"/fleet-state/secrets/hermes-api-token","display_name":"Qualification Hermes","tenant_id":"tenant-acme"}]'
write_once \
    "${public}/dify-apps.json" \
    10001:10001 \
    '[{"id":"qualification-app","name":"Qualification App","mode":"chat","description":"Pinned product-fleet qualification app","api_key_file":"/fleet-state/secrets/dify-app-api-token"}]'
write_once \
    "${public}/dify-knowledge.json" \
    10001:10001 \
    '[{"id":"qualification-kb","name":"Qualification Knowledge","description":"Pinned product-fleet qualification knowledge base","api_key_file":"/fleet-state/secrets/dify-knowledge-api-token"}]'
write_once \
    "${public}/crewai-crews.json" \
    10001:10001 \
    '[{"id":"support-qualification","name":"Support qualification crew","description":"Pinned real-CrewAI product-fleet qualification crew","allowed_operations":["run","status","events","cancel","batch_run","replay","train","test","knowledge_query","memory_reset"]}]'
write_once \
    "${crewai_state}/runs.json" \
    10001:10001 \
    '[{"action_id":"act_crewai_qualification_seed","crew_id":"support-qualification","operation":"run","input_hash":"qualification-seed","status":"completed","events":[{"event":"completed","sequence":0,"data":{"status":"completed"}}],"output":{"status":"completed","result":{"classification":"qualification-seed"}}}]'

database_url() {
    secret_name="$1"
    database_role="$2"
    database="$3"
    password="$(cat "${secrets}/${secret_name}-password")"
    printf 'postgresql://%s:%s@postgres:5432/%s' "${database_role}" "${password}" "${database}"
}

write_once "${secrets}/registry-admin.url" 10001:10001 "$(database_url registry-admin aip_registry_admin aip_registry)"
write_once "${secrets}/registry-data.url" 10001:10001 "$(database_url registry-data aip_registry_data aip_registry)"
write_once "${secrets}/registry-lifecycle.url" 10001:10001 "$(database_url registry-lifecycle aip_registry_lifecycle aip_registry)"
write_once "${secrets}/getaip-server-runtime.url" 10001:10001 "$(database_url getaip-server-runtime getaip_server_runtime getaip_server_runtime)"
write_once "${secrets}/support-acme-runtime.url" 10001:10001 "$(database_url support-acme-runtime support_acme_runtime support_acme_runtime)"
write_once "${secrets}/support-beta-runtime.url" 10001:10001 "$(database_url support-beta-runtime support_beta_runtime support_beta_runtime)"
write_once "${secrets}/enterprise-acme-runtime.url" 10001:10001 "$(database_url enterprise-acme-runtime enterprise_acme_runtime enterprise_acme_runtime)"
write_once "${secrets}/cal-acme-runtime.url" 10001:10001 "$(database_url cal-acme-runtime cal_acme_runtime cal_acme_runtime)"
write_once "${secrets}/hermes-acme-runtime.url" 10001:10001 "$(database_url hermes-acme-runtime hermes_acme_runtime hermes_acme_runtime)"
write_once "${secrets}/chatwoot-acme-runtime.url" 10001:10001 "$(database_url chatwoot-acme-runtime chatwoot_acme_runtime chatwoot_acme_runtime)"
write_once "${secrets}/dify-acme-runtime.url" 10001:10001 "$(database_url dify-acme-runtime dify_acme_runtime dify_acme_runtime)"
write_once "${secrets}/crewai-acme-runtime.url" 10001:10001 "$(database_url crewai-acme-runtime crewai_acme_runtime crewai_acme_runtime)"
write_once "${secrets}/twenty-acme-runtime.url" 10001:10001 "$(database_url twenty-acme-runtime twenty_acme_runtime twenty_acme_runtime)"
write_once "${secrets}/wa-archive-acme-runtime.url" 10001:10001 "$(database_url wa-archive-acme-runtime wa_archive_acme_runtime wa_archive_acme_runtime)"
write_once "${secrets}/provider-support-acme.url" 10001:10001 "$(database_url provider-support-acme provider_support_acme provider_support_acme)"
write_once "${secrets}/provider-support-beta.url" 10001:10001 "$(database_url provider-support-beta provider_support_beta provider_support_beta)"
write_once "${secrets}/provider-enterprise-acme.url" 10001:10001 "$(database_url provider-enterprise-acme provider_enterprise_acme provider_enterprise_acme)"
write_once "${wa_archive_secrets}/database.url" 10001:10001 "$(database_url provider-wa-archive-acme provider_wa_archive_acme provider_wa_archive_acme)"

write_once "${root}/secrets-ready" 10001:10001 "ready"
