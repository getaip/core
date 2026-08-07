#!/bin/sh
set -eu

secrets=/fleet-state/secrets
bootstrap_password=$(cat "${secrets}/postgres-bootstrap-password")
export PGPASSWORD=${bootstrap_password}

ensure_role_and_database() {
    secret_name=$1
    role_name=$2
    database_name=$3
    role_password=$(cat "${secrets}/${secret_name}-password")

    psql \
        --host postgres \
        --username aip_bootstrap \
        --dbname postgres \
        --set=ON_ERROR_STOP=1 \
        --set=role_name="${role_name}" \
        --set=role_password="${role_password}" \
        --set=database_name="${database_name}" <<'SQL'
SELECT format(
    'CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION',
    :'role_name',
    :'role_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role_name')
\gexec

SELECT format('ALTER ROLE %I PASSWORD %L', :'role_name', :'role_password')
\gexec

SELECT format('CREATE DATABASE %I OWNER %I', :'database_name', :'role_name')
WHERE NOT EXISTS (
    SELECT 1 FROM pg_database WHERE datname = :'database_name'
)
\gexec

SELECT format('REVOKE CONNECT ON DATABASE %I FROM PUBLIC', :'database_name')
\gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'database_name', :'role_name')
\gexec
SQL
}

ensure_role_and_database \
    wa-archive-acme-runtime \
    wa_archive_acme_runtime \
    wa_archive_acme_runtime
ensure_role_and_database \
    provider-wa-archive-acme \
    provider_wa_archive_acme \
    provider_wa_archive_acme
