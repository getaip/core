#!/bin/sh
set -eu

database_url="$(cat /fleet-state/secrets/registry-admin.url)"
psql "${database_url}" --set=ON_ERROR_STOP=1 --file=/qualification/grant-registry.sql

# Fail before any network service starts if the deployed least-privilege
# policy cannot support lifecycle replay fencing or accidentally grants catalog
# administration to either runtime role.
verified="$({
    psql "${database_url}" --set=ON_ERROR_STOP=1 --tuples-only --no-align <<'SQL'
SELECT
    has_table_privilege('aip_registry_lifecycle', 'aip_connector_control_replay', 'SELECT')
    AND has_table_privilege('aip_registry_lifecycle', 'aip_connector_control_replay', 'INSERT')
    AND has_table_privilege('aip_registry_lifecycle', 'aip_connector_control_replay', 'UPDATE')
    AND has_table_privilege('aip_registry_lifecycle', 'aip_connector_control_replay', 'DELETE')
    AND has_table_privilege('aip_registry_lifecycle', 'aip_connector_replicas', 'INSERT')
    AND has_table_privilege('aip_registry_lifecycle', 'aip_connector_replicas', 'UPDATE')
    AND has_table_privilege('aip_registry_data', 'aip_connector_replicas', 'SELECT')
    AND has_table_privilege('aip_registry_data', 'aip_connector_replicas', 'UPDATE')
    AND NOT has_table_privilege('aip_registry_lifecycle', 'aip_connector_types', 'INSERT')
    AND NOT has_table_privilege('aip_registry_data', 'aip_connector_types', 'INSERT');
SQL
} | tr -d '[:space:]')"

if [ "${verified}" != "t" ]; then
    echo "connector registry least-privilege verification failed" >&2
    exit 1
fi

echo "connector registry least-privilege verification: PASS"
