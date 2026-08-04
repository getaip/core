#!/bin/sh
set -eu

secrets=/fleet-state/secrets

create_role_and_database() {
    secret_name="$1"
    role="$2"
    database="$3"
    password="$(cat "${secrets}/${secret_name}-password")"
    psql --username "${POSTGRES_USER}" --dbname postgres \
        --set=ON_ERROR_STOP=1 \
        --set=role_name="${role}" \
        --set=role_password="${password}" <<'SQL'
CREATE ROLE :"role_name"
    LOGIN PASSWORD :'role_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
SQL
    createdb --username "${POSTGRES_USER}" --owner "${role}" "${database}"
    psql --username "${POSTGRES_USER}" --dbname postgres --set=ON_ERROR_STOP=1 \
        --command "REVOKE CONNECT ON DATABASE \"${database}\" FROM PUBLIC"
    psql --username "${POSTGRES_USER}" --dbname postgres --set=ON_ERROR_STOP=1 \
        --command "GRANT CONNECT ON DATABASE \"${database}\" TO \"${role}\""
}

create_role() {
    secret_name="$1"
    role="$2"
    password="$(cat "${secrets}/${secret_name}-password")"
    psql --username "${POSTGRES_USER}" --dbname postgres \
        --set=ON_ERROR_STOP=1 \
        --set=role_name="${role}" \
        --set=role_password="${password}" <<'SQL'
CREATE ROLE :"role_name"
    LOGIN PASSWORD :'role_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
SQL
}

create_role_and_database registry-admin aip_registry_admin aip_registry
create_role registry-data aip_registry_data
create_role registry-lifecycle aip_registry_lifecycle
psql --username "${POSTGRES_USER}" --dbname postgres --set=ON_ERROR_STOP=1 \
    --command 'GRANT CONNECT ON DATABASE aip_registry TO aip_registry_data, aip_registry_lifecycle'

create_role_and_database getaip-server-runtime getaip_server_runtime getaip_server_runtime
create_role_and_database support-acme-runtime support_acme_runtime support_acme_runtime
create_role_and_database support-beta-runtime support_beta_runtime support_beta_runtime
create_role_and_database enterprise-acme-runtime enterprise_acme_runtime enterprise_acme_runtime
create_role_and_database cal-acme-runtime cal_acme_runtime cal_acme_runtime
create_role_and_database hermes-acme-runtime hermes_acme_runtime hermes_acme_runtime
create_role_and_database chatwoot-acme-runtime chatwoot_acme_runtime chatwoot_acme_runtime
create_role_and_database dify-acme-runtime dify_acme_runtime dify_acme_runtime
create_role_and_database crewai-acme-runtime crewai_acme_runtime crewai_acme_runtime
create_role_and_database twenty-acme-runtime twenty_acme_runtime twenty_acme_runtime
create_role_and_database wa-archive-acme-runtime wa_archive_acme_runtime wa_archive_acme_runtime
create_role_and_database provider-support-acme provider_support_acme provider_support_acme
create_role_and_database provider-support-beta provider_support_beta provider_support_beta
create_role_and_database provider-enterprise-acme provider_enterprise_acme provider_enterprise_acme
create_role_and_database provider-wa-archive-acme provider_wa_archive_acme provider_wa_archive_acme

psql --username "${POSTGRES_USER}" --dbname provider_support_acme --set=ON_ERROR_STOP=1 <<'SQL'
SET ROLE provider_support_acme;
\i /qualification-schema/001_schema.sql
DELETE FROM audit.events WHERE subject_ref = 'case:case_1002';
DELETE FROM support.messages WHERE case_id = 'case_1002';
DELETE FROM support.cases WHERE case_id = 'case_1002';
DELETE FROM billing.charges WHERE customer_id = 'cust_002';
DELETE FROM billing.orders WHERE customer_id = 'cust_002';
DELETE FROM support.customers WHERE customer_id = 'cust_002';
SQL

psql --username "${POSTGRES_USER}" --dbname provider_support_beta --set=ON_ERROR_STOP=1 <<'SQL'
SET ROLE provider_support_beta;
\i /qualification-schema/001_schema.sql
DELETE FROM audit.events WHERE subject_ref = 'case:case_1001';
DELETE FROM billing.refunds WHERE case_id = 'case_1001';
DELETE FROM approval.approval_requests WHERE case_id = 'case_1001';
DELETE FROM support.messages WHERE case_id = 'case_1001';
DELETE FROM support.cases WHERE case_id = 'case_1001';
DELETE FROM billing.charges WHERE customer_id = 'cust_001';
DELETE FROM billing.orders WHERE customer_id = 'cust_001';
DELETE FROM support.customers WHERE customer_id = 'cust_001';
SQL

psql --username "${POSTGRES_USER}" --dbname provider_enterprise_acme --set=ON_ERROR_STOP=1 <<'SQL'
SET ROLE provider_enterprise_acme;
\i /qualification-schema/002_enterprise_scenarios.sql
SQL

# The PostgreSQL server accepts connections before the entrypoint has finished
# running this bootstrap script. Publish an explicit completion marker so
# dependent qualification services cannot race the final schema setup.
touch /var/lib/postgresql/data/.getaip-qualification-initialized
