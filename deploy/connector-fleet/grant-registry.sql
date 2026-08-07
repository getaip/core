\set ON_ERROR_STOP on

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO aip_registry_data, aip_registry_lifecycle;

-- Reconcile the named application roles to this complete policy on every
-- deployment. Without the explicit revoke, removing a grant from this file
-- would leave stale authority behind on an already provisioned database.
REVOKE ALL ON ALL TABLES IN SCHEMA public
FROM aip_registry_data, aip_registry_lifecycle;

GRANT SELECT ON
    aip_connector_registry_migrations,
    aip_connector_catalog_revision,
    aip_connector_types,
    aip_connector_versions,
    aip_capability_definitions,
    aip_connector_version_capabilities,
    aip_connector_version_profiles,
    aip_connector_instances,
    aip_connector_replicas,
    aip_tenant_capability_bindings,
    aip_connector_admission_policies,
    aip_connector_admission_counters,
    aip_route_assignments
TO aip_registry_data;

GRANT INSERT, UPDATE, DELETE ON
    aip_connector_admission_counters,
    aip_route_assignments
TO aip_registry_data;

GRANT UPDATE ON aip_connector_replicas TO aip_registry_data;

GRANT SELECT ON
    aip_connector_registry_migrations,
    aip_connector_catalog_revision,
    aip_connector_versions,
    aip_connector_instances,
    aip_connector_replicas,
    aip_connector_control_replay
TO aip_registry_lifecycle;

GRANT INSERT, UPDATE ON aip_connector_replicas TO aip_registry_lifecycle;
GRANT UPDATE ON aip_connector_catalog_revision TO aip_registry_lifecycle;
GRANT INSERT, UPDATE, DELETE ON aip_connector_control_replay TO aip_registry_lifecycle;

ALTER DEFAULT PRIVILEGES FOR ROLE aip_registry_admin IN SCHEMA public
    GRANT SELECT ON TABLES TO aip_registry_data;
ALTER DEFAULT PRIVILEGES FOR ROLE aip_registry_admin IN SCHEMA public
    GRANT SELECT ON TABLES TO aip_registry_lifecycle;
