//! Normalized PostgreSQL control-plane storage for connector fleets.
//!
//! The registry stores connector types, immutable versions, shared capability
//! definitions, tenant bindings, live replica leases, and durable action route
//! assignments as indexed rows. It never materializes the fleet as one JSON
//! document and never stores provider credentials.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use aip_connector_admission::{
    AdmissionError, AdmissionJournal, AdmissionOperation, AdmissionOperationClaim,
    AdmissionOperationState,
};
use aip_connector_registry::{
    ActionTargetResolver, AdmissionPolicy, AdmissionReservation, AdmissionScopeKind,
    AdmissionScopeReservation, CapabilityBinding, CapabilityCatalogProvider,
    CapabilityCatalogQuery, CapabilityDefinition, CapabilityPage, CatalogReadContext,
    CatalogRevision, ConnectorFleetStatusProvider, ConnectorInstance, ConnectorInstanceId,
    ConnectorInstanceStatus, ConnectorRegistryAdmin, ConnectorRegistryPoolSnapshot,
    ConnectorRegistryReader, ConnectorReplica, ConnectorReplicaStatus, ConnectorType,
    ConnectorTypeId, ConnectorVersion, ConnectorVersionId, ConnectorVersionStatus,
    FleetStatusSummary, RegistryError, RegistryLimits, ResolvedCapabilityDefinition,
    RouteAssignment, RouteResolutionRequest, RouteSettlement, attempt_admission_scopes,
    build_admission_reservation, capability_definition_size, validate_admission_policy,
    validate_connector_replica, validate_connector_version, validate_registry_limits,
};
use aip_core::{ActionId, CapabilityId, ProfileId};
use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx_core::{query::query, row::Row, transaction::Transaction};
use sqlx_postgres::{PgPool, PgPoolOptions, PgRow, Postgres};
use std::time::Duration as StdDuration;
use time::OffsetDateTime;
use uuid::Uuid;

/// Latest connector-registry schema version required by this crate.
pub const CONNECTOR_REGISTRY_SCHEMA_VERSION: i64 = 7;

// The second half of a database-scoped PostgreSQL advisory-lock key ("AIPC").
// Readers hold the shared form while materializing a catalog view; catalog
// publishers hold the exclusive form before taking the revision row lock.
const CATALOG_REVISION_ADVISORY_LOCK: i32 = 0x4149_5043;

/// Independent connection limits for connector control and data planes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryPoolLimits {
    /// Maximum catalog-administration and schema connections.
    pub control_max_connections: u32,
    /// Maximum routing, lease, admission, and catalog-read connections.
    pub data_max_connections: u32,
    /// Maximum time either pool waits for a connection.
    pub acquire_timeout: StdDuration,
}

impl Default for RegistryPoolLimits {
    fn default() -> Self {
        Self {
            control_max_connections: 4,
            data_max_connections: 32,
            acquire_timeout: StdDuration::from_secs(5),
        }
    }
}

impl RegistryPoolLimits {
    fn validate(&self) -> Result<(), RegistryError> {
        if self.control_max_connections == 0
            || self.data_max_connections == 0
            || self.acquire_timeout.is_zero()
            || self.acquire_timeout > StdDuration::from_secs(60)
        {
            return Err(RegistryError::Invalid(
                "connector registry pool limits must be non-zero and acquire timeout must not exceed 60 seconds"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// PostgreSQL-backed connector fleet registry.
#[derive(Clone, Debug)]
pub struct PostgresConnectorRegistry {
    control_pool: Option<PgPool>,
    data_pool: PgPool,
    pool_limits: RegistryPoolLimits,
    limits: RegistryLimits,
}

impl PostgresConnectorRegistry {
    /// Creates a registry from one backward-compatible shared pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            control_pool: Some(pool.clone()),
            data_pool: pool,
            pool_limits: RegistryPoolLimits::default(),
            limits: RegistryLimits::default(),
        }
    }

    /// Creates a registry from independently permissioned pools.
    #[must_use]
    pub fn with_pools(
        control_pool: PgPool,
        data_pool: PgPool,
        pool_limits: RegistryPoolLimits,
    ) -> Self {
        Self {
            control_pool: Some(control_pool),
            data_pool,
            pool_limits,
            limits: RegistryLimits::default(),
        }
    }

    /// Opens separate pools against one URL and installs the registry schema.
    pub async fn connect(database_url: &str) -> Result<Self, RegistryError> {
        Self::connect_with_urls(database_url, database_url, RegistryPoolLimits::default()).await
    }

    /// Opens independently bounded control/data pools and installs the schema
    /// through the control-plane credentials.
    pub async fn connect_with_urls(
        control_database_url: &str,
        data_database_url: &str,
        pool_limits: RegistryPoolLimits,
    ) -> Result<Self, RegistryError> {
        pool_limits.validate()?;
        let control_pool = PgPoolOptions::new()
            .max_connections(pool_limits.control_max_connections)
            .acquire_timeout(pool_limits.acquire_timeout)
            .connect(control_database_url)
            .await
            .map_err(storage_error)?;
        let data_pool = PgPoolOptions::new()
            .max_connections(pool_limits.data_max_connections)
            .acquire_timeout(pool_limits.acquire_timeout)
            .connect(data_database_url)
            .await
            .map_err(storage_error)?;
        let registry = Self::with_pools(control_pool, data_pool, pool_limits);
        registry.install_schema().await?;
        Ok(registry)
    }

    /// Opens only the routing/catalog-read pool and verifies that an external
    /// control plane already installed the required schema.
    pub async fn connect_data_plane(
        data_database_url: &str,
        mut pool_limits: RegistryPoolLimits,
    ) -> Result<Self, RegistryError> {
        pool_limits.validate()?;
        let data_pool = PgPoolOptions::new()
            .max_connections(pool_limits.data_max_connections)
            .acquire_timeout(pool_limits.acquire_timeout)
            .connect(data_database_url)
            .await
            .map_err(storage_error)?;
        let row = query::<Postgres>(
            "SELECT COALESCE(MAX(version), 0) AS version FROM aip_connector_registry_migrations",
        )
        .fetch_one(&data_pool)
        .await
        .map_err(storage_error)?;
        let version: i64 = row.try_get("version").map_err(storage_error)?;
        if version != CONNECTOR_REGISTRY_SCHEMA_VERSION {
            return Err(RegistryError::Storage(format!(
                "connector registry schema version {version} does not match required version {CONNECTOR_REGISTRY_SCHEMA_VERSION}"
            )));
        }
        pool_limits.control_max_connections = 0;
        Ok(Self {
            control_pool: None,
            data_pool,
            pool_limits,
            limits: RegistryLimits::default(),
        })
    }

    /// Drops control-plane credentials after an optional startup migration.
    #[must_use]
    pub fn into_data_plane(mut self) -> Self {
        self.control_pool = None;
        self.pool_limits.control_max_connections = 0;
        self
    }

    /// Applies explicit admission and page bounds.
    #[must_use]
    pub fn with_limits(mut self, limits: RegistryLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Returns the control-plane pool for administrative tooling.
    ///
    /// New data-plane integrations should use [`Self::data_pool`].
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        self.control_pool.as_ref().unwrap_or(&self.data_pool)
    }

    /// Returns the control-plane pool when this process is authorized to mutate the catalog.
    #[must_use]
    pub fn control_pool(&self) -> Option<&PgPool> {
        self.control_pool.as_ref()
    }

    /// Returns the routing and catalog-read pool.
    #[must_use]
    pub fn data_pool(&self) -> &PgPool {
        &self.data_pool
    }

    /// Returns fixed-cardinality pool telemetry without database identities.
    #[must_use]
    pub fn pool_snapshot(&self) -> ConnectorRegistryPoolSnapshot {
        let (control_size, control_idle) = self.control_pool.as_ref().map_or((0, 0), |pool| {
            (
                pool.size(),
                u32::try_from(pool.num_idle()).unwrap_or(u32::MAX),
            )
        });
        ConnectorRegistryPoolSnapshot {
            control_size,
            control_idle,
            control_max: self.pool_limits.control_max_connections,
            data_size: self.data_pool.size(),
            data_idle: u32::try_from(self.data_pool.num_idle()).unwrap_or(u32::MAX),
            data_max: self.pool_limits.data_max_connections,
        }
    }

    /// Returns the highest immutable migration installed in the registry.
    pub async fn installed_schema_version(&self) -> Result<i64, RegistryError> {
        let row = query::<Postgres>(
            "SELECT COALESCE(MAX(version), 0) AS version FROM aip_connector_registry_migrations",
        )
        .fetch_one(self.control_pool.as_ref().unwrap_or(&self.data_pool))
        .await
        .map_err(storage_error)?;
        row.try_get("version").map_err(storage_error)
    }

    /// Atomically claims one signed connector lifecycle request until expiry.
    ///
    /// This operation is available through the restricted lifecycle/data pool;
    /// it does not require catalog-administration credentials.
    pub async fn claim_control_request(
        &self,
        request_id: &str,
        expires_at: OffsetDateTime,
    ) -> Result<bool, RegistryError> {
        if request_id.trim().is_empty() || request_id.len() > 256 {
            return Err(RegistryError::Invalid(
                "connector control request id must contain 1 to 256 bytes".to_owned(),
            ));
        }
        let expires_at_ms = datetime_ms(expires_at)?;
        let claimed_at_ms = now_ms();
        let acquired = query::<Postgres>(
            r#"
            INSERT INTO aip_connector_control_replay
                (request_id, expires_at_ms, claimed_at_ms)
            VALUES ($1, $2, $3)
            ON CONFLICT (request_id) DO UPDATE
            SET expires_at_ms = EXCLUDED.expires_at_ms,
                claimed_at_ms = EXCLUDED.claimed_at_ms
            WHERE aip_connector_control_replay.expires_at_ms <= $3
            "#,
        )
        .bind(request_id)
        .bind(expires_at_ms)
        .bind(claimed_at_ms)
        .execute(&self.data_pool)
        .await
        .map_err(storage_error)?
        .rows_affected()
            == 1;
        if acquired {
            query::<Postgres>(
                r#"
                WITH expired AS (
                    SELECT request_id
                    FROM aip_connector_control_replay
                    WHERE expires_at_ms <= $1 AND request_id <> $2
                    ORDER BY expires_at_ms, request_id
                    LIMIT 256
                )
                DELETE FROM aip_connector_control_replay AS replay
                USING expired
                WHERE replay.request_id = expired.request_id
                "#,
            )
            .bind(claimed_at_ms)
            .bind(request_id)
            .execute(&self.data_pool)
            .await
            .map_err(storage_error)?;
        }
        Ok(acquired)
    }

    /// Installs the normalized registry schema through an immutable migration.
    pub async fn install_schema(&self) -> Result<(), RegistryError> {
        const MIGRATION_LOCK: i64 = 0x4149_505f_4352_4547;
        let schema = r#"
            CREATE TABLE IF NOT EXISTS aip_connector_catalog_revision (
                singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
                revision BIGINT NOT NULL CHECK (revision >= 0),
                published_at_ms BIGINT NOT NULL
            );

            INSERT INTO aip_connector_catalog_revision (singleton, revision, published_at_ms)
            VALUES (TRUE, 0, 0)
            ON CONFLICT (singleton) DO NOTHING;

            CREATE TABLE IF NOT EXISTS aip_connector_types (
                type_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                owner TEXT NOT NULL,
                enabled BOOLEAN NOT NULL,
                record JSONB NOT NULL,
                updated_at_ms BIGINT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS aip_connector_versions (
                version_id TEXT PRIMARY KEY,
                type_id TEXT NOT NULL REFERENCES aip_connector_types(type_id),
                version TEXT NOT NULL,
                status TEXT NOT NULL,
                artifact_digest TEXT NOT NULL UNIQUE,
                manifest_digest TEXT NOT NULL,
                record JSONB NOT NULL,
                admitted_at_ms BIGINT NOT NULL,
                UNIQUE (type_id, version)
            );

            CREATE INDEX IF NOT EXISTS aip_connector_versions_routing_idx
                ON aip_connector_versions (type_id, status, version_id);

            CREATE TABLE IF NOT EXISTS aip_capability_definitions (
                capability_id TEXT PRIMARY KEY,
                contract_digest TEXT NOT NULL,
                schema_digest TEXT NOT NULL,
                record JSONB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS aip_connector_version_capabilities (
                version_id TEXT NOT NULL REFERENCES aip_connector_versions(version_id),
                capability_id TEXT NOT NULL REFERENCES aip_capability_definitions(capability_id),
                contract_digest TEXT NOT NULL,
                PRIMARY KEY (version_id, capability_id)
            );

            CREATE INDEX IF NOT EXISTS aip_connector_version_capability_lookup_idx
                ON aip_connector_version_capabilities (capability_id, version_id);

            CREATE TABLE IF NOT EXISTS aip_connector_version_profiles (
                version_id TEXT NOT NULL REFERENCES aip_connector_versions(version_id),
                profile_id TEXT NOT NULL,
                PRIMARY KEY (version_id, profile_id)
            );

            CREATE INDEX IF NOT EXISTS aip_connector_version_profile_lookup_idx
                ON aip_connector_version_profiles (profile_id, version_id);

            CREATE TABLE IF NOT EXISTS aip_connector_instances (
                instance_id TEXT PRIMARY KEY,
                type_id TEXT NOT NULL REFERENCES aip_connector_types(type_id),
                version_id TEXT NOT NULL REFERENCES aip_connector_versions(version_id),
                tenant_id TEXT NOT NULL,
                config_revision BIGINT NOT NULL CHECK (config_revision >= 0),
                secret_provider_ref TEXT NOT NULL,
                status TEXT NOT NULL,
                record JSONB NOT NULL,
                updated_at_ms BIGINT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS aip_connector_instances_tenant_idx
                ON aip_connector_instances (tenant_id, status, instance_id);

            CREATE TABLE IF NOT EXISTS aip_connector_replicas (
                replica_id TEXT PRIMARY KEY,
                instance_id TEXT NOT NULL REFERENCES aip_connector_instances(instance_id),
                version_id TEXT NOT NULL REFERENCES aip_connector_versions(version_id),
                endpoint TEXT NOT NULL,
                status TEXT NOT NULL,
                lease_expires_at_ms BIGINT NOT NULL,
                capacity BIGINT NOT NULL CHECK (capacity > 0),
                active_assignments BIGINT NOT NULL DEFAULT 0 CHECK (active_assignments >= 0),
                health_revision BIGINT NOT NULL CHECK (health_revision >= 0),
                record JSONB NOT NULL,
                updated_at_ms BIGINT NOT NULL,
                CHECK (active_assignments <= capacity)
            );

            CREATE INDEX IF NOT EXISTS aip_connector_replicas_routing_idx
                ON aip_connector_replicas
                (instance_id, version_id, status, lease_expires_at_ms, active_assignments, replica_id);

            CREATE TABLE IF NOT EXISTS aip_tenant_capability_bindings (
                tenant_id TEXT NOT NULL,
                capability_id TEXT NOT NULL REFERENCES aip_capability_definitions(capability_id),
                instance_id TEXT NOT NULL REFERENCES aip_connector_instances(instance_id),
                priority BIGINT NOT NULL CHECK (priority >= 0),
                policy_revision BIGINT NOT NULL CHECK (policy_revision >= 0),
                credential_revision_ref TEXT,
                quota_policy_ref TEXT,
                enabled BOOLEAN NOT NULL,
                record JSONB NOT NULL,
                updated_at_ms BIGINT NOT NULL,
                PRIMARY KEY (tenant_id, capability_id, instance_id)
            );

            CREATE INDEX IF NOT EXISTS aip_tenant_capability_bindings_routing_idx
                ON aip_tenant_capability_bindings
                (tenant_id, capability_id, enabled, priority, instance_id);

            CREATE TABLE IF NOT EXISTS aip_route_assignments (
                action_id TEXT PRIMARY KEY,
                capability_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                instance_id TEXT NOT NULL REFERENCES aip_connector_instances(instance_id),
                replica_id TEXT NOT NULL REFERENCES aip_connector_replicas(replica_id),
                version_id TEXT NOT NULL REFERENCES aip_connector_versions(version_id),
                fence_token TEXT NOT NULL UNIQUE,
                reserved BOOLEAN NOT NULL,
                last_settlement TEXT,
                record JSONB NOT NULL,
                assigned_at_ms BIGINT NOT NULL,
                updated_at_ms BIGINT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS aip_route_assignments_replica_reserved_idx
                ON aip_route_assignments (replica_id, reserved, assigned_at_ms);
        "#;
        let lifecycle_indexes = r#"
            CREATE INDEX IF NOT EXISTS aip_connector_instances_type_fk_idx
                ON aip_connector_instances (type_id, instance_id);

            CREATE INDEX IF NOT EXISTS aip_connector_instances_version_fk_idx
                ON aip_connector_instances (version_id, instance_id);

            CREATE INDEX IF NOT EXISTS aip_connector_replicas_version_fk_idx
                ON aip_connector_replicas (version_id, replica_id);

            CREATE INDEX IF NOT EXISTS aip_tenant_capability_bindings_capability_fk_idx
                ON aip_tenant_capability_bindings (capability_id, tenant_id, instance_id);

            CREATE INDEX IF NOT EXISTS aip_tenant_capability_bindings_instance_fk_idx
                ON aip_tenant_capability_bindings (instance_id, tenant_id, capability_id);

            CREATE INDEX IF NOT EXISTS aip_route_assignments_instance_fk_idx
                ON aip_route_assignments (instance_id, assigned_at_ms);

            CREATE INDEX IF NOT EXISTS aip_route_assignments_version_fk_idx
                ON aip_route_assignments (version_id, assigned_at_ms);
        "#;
        let admission_schema = r#"
            CREATE TABLE IF NOT EXISTS aip_connector_admission_policies (
                policy_ref TEXT PRIMARY KEY,
                revision BIGINT NOT NULL CHECK (revision > 0),
                enabled BOOLEAN NOT NULL,
                record JSONB NOT NULL,
                updated_at_ms BIGINT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS aip_connector_admission_counters (
                scope_kind TEXT NOT NULL,
                scope_key TEXT NOT NULL,
                active BIGINT NOT NULL DEFAULT 0 CHECK (active >= 0),
                updated_at_ms BIGINT NOT NULL,
                PRIMARY KEY (scope_kind, scope_key)
            );

            ALTER TABLE aip_route_assignments
                ADD COLUMN IF NOT EXISTS reservation_scopes JSONB NOT NULL DEFAULT '[]'::jsonb;

            ALTER TABLE aip_connector_replicas
                ADD COLUMN IF NOT EXISTS consecutive_failures BIGINT NOT NULL DEFAULT 0
                    CHECK (consecutive_failures >= 0);

            ALTER TABLE aip_connector_replicas
                ADD COLUMN IF NOT EXISTS circuit_open_until_ms BIGINT NOT NULL DEFAULT 0;

            CREATE INDEX IF NOT EXISTS aip_connector_replicas_circuit_routing_idx
                ON aip_connector_replicas
                (instance_id, status, circuit_open_until_ms, lease_expires_at_ms,
                 active_assignments, replica_id);
        "#;
        let supply_chain_schema = r#"
            ALTER TABLE aip_connector_versions
                ADD COLUMN IF NOT EXISTS supply_chain_qualified BOOLEAN NOT NULL DEFAULT FALSE;

            CREATE INDEX IF NOT EXISTS aip_connector_versions_qualified_routing_idx
                ON aip_connector_versions
                (type_id, status, supply_chain_qualified, version_id);
        "#;
        let control_replay_schema = r#"
            CREATE TABLE IF NOT EXISTS aip_connector_control_replay (
                request_id TEXT PRIMARY KEY,
                expires_at_ms BIGINT NOT NULL,
                claimed_at_ms BIGINT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS aip_connector_control_replay_expiry_idx
                ON aip_connector_control_replay (expires_at_ms);
        "#;
        let topology_schema = r#"
            ALTER TABLE aip_connector_replicas
                ADD COLUMN IF NOT EXISTS region TEXT NOT NULL DEFAULT 'global';

            ALTER TABLE aip_connector_replicas
                ADD COLUMN IF NOT EXISTS zone TEXT NOT NULL DEFAULT 'default';

            ALTER TABLE aip_connector_replicas
                ADD COLUMN IF NOT EXISTS capacity_class TEXT NOT NULL DEFAULT 'standard';

            CREATE INDEX IF NOT EXISTS aip_connector_replicas_topology_routing_idx
                ON aip_connector_replicas
                (instance_id, status, capacity_class, region, zone,
                 lease_expires_at_ms, active_assignments, replica_id);
        "#;
        let operator_journal_schema = r#"
            CREATE TABLE IF NOT EXISTS aip_connector_admission_operations (
                package_id TEXT NOT NULL,
                revision BIGINT NOT NULL CHECK (revision > 0),
                package_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                record JSONB NOT NULL,
                updated_at_ms BIGINT NOT NULL,
                PRIMARY KEY (package_id, revision)
            );

            CREATE INDEX IF NOT EXISTS aip_connector_admission_operations_status_idx
                ON aip_connector_admission_operations (state, updated_at_ms, package_id, revision);
        "#;
        let mut transaction = self
            .require_control_pool()?
            .begin()
            .await
            .map_err(storage_error)?;
        query::<Postgres>("SELECT pg_advisory_xact_lock($1)")
            .bind(MIGRATION_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        query::<Postgres>(
            r#"
            CREATE TABLE IF NOT EXISTS aip_connector_registry_migrations (
                version BIGINT PRIMARY KEY,
                name TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at_ms BIGINT NOT NULL
            )
            "#,
        )
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        let checksum = format!("{:x}", Sha256::digest(schema.as_bytes()));
        let applied = query::<Postgres>(
            "SELECT checksum FROM aip_connector_registry_migrations WHERE version = 1 FOR UPDATE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = applied {
            let recorded: String = row.try_get("checksum").map_err(storage_error)?;
            if recorded != checksum {
                return Err(RegistryError::Storage(
                    "connector registry migration 1 checksum changed".to_owned(),
                ));
            }
        } else {
            for statement in schema
                .split(';')
                .map(str::trim)
                .filter(|statement| !statement.is_empty())
            {
                query::<Postgres>(statement)
                    .execute(&mut *transaction)
                    .await
                    .map_err(storage_error)?;
            }
            query::<Postgres>(
                r#"
                INSERT INTO aip_connector_registry_migrations
                    (version, name, checksum, applied_at_ms)
                VALUES (1, 'normalized_connector_registry', $1, $2)
                "#,
            )
            .bind(checksum)
            .bind(now_ms())
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        let lifecycle_checksum = format!("{:x}", Sha256::digest(lifecycle_indexes.as_bytes()));
        let lifecycle_applied = query::<Postgres>(
            "SELECT checksum FROM aip_connector_registry_migrations WHERE version = 2 FOR UPDATE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = lifecycle_applied {
            let recorded: String = row.try_get("checksum").map_err(storage_error)?;
            if recorded != lifecycle_checksum {
                return Err(RegistryError::Storage(
                    "connector registry migration 2 checksum changed".to_owned(),
                ));
            }
        } else {
            for statement in lifecycle_indexes
                .split(';')
                .map(str::trim)
                .filter(|statement| !statement.is_empty())
            {
                query::<Postgres>(statement)
                    .execute(&mut *transaction)
                    .await
                    .map_err(storage_error)?;
            }
            query::<Postgres>(
                r#"
                INSERT INTO aip_connector_registry_migrations
                    (version, name, checksum, applied_at_ms)
                VALUES (2, 'connector_lifecycle_foreign_key_indexes', $1, $2)
                "#,
            )
            .bind(lifecycle_checksum)
            .bind(now_ms())
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        let admission_checksum = format!("{:x}", Sha256::digest(admission_schema.as_bytes()));
        let admission_applied = query::<Postgres>(
            "SELECT checksum FROM aip_connector_registry_migrations WHERE version = 3 FOR UPDATE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = admission_applied {
            let recorded: String = row.try_get("checksum").map_err(storage_error)?;
            if recorded != admission_checksum {
                return Err(RegistryError::Storage(
                    "connector registry migration 3 checksum changed".to_owned(),
                ));
            }
        } else {
            for statement in admission_schema
                .split(';')
                .map(str::trim)
                .filter(|statement| !statement.is_empty())
            {
                query::<Postgres>(statement)
                    .execute(&mut *transaction)
                    .await
                    .map_err(storage_error)?;
            }
            query::<Postgres>(
                r#"
                INSERT INTO aip_connector_registry_migrations
                    (version, name, checksum, applied_at_ms)
                VALUES (3, 'connector_admission_and_circuit_state', $1, $2)
                "#,
            )
            .bind(admission_checksum)
            .bind(now_ms())
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        let supply_chain_checksum = format!("{:x}", Sha256::digest(supply_chain_schema.as_bytes()));
        let supply_chain_applied = query::<Postgres>(
            "SELECT checksum FROM aip_connector_registry_migrations WHERE version = 4 FOR UPDATE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = supply_chain_applied {
            let recorded: String = row.try_get("checksum").map_err(storage_error)?;
            if recorded != supply_chain_checksum {
                return Err(RegistryError::Storage(
                    "connector registry migration 4 checksum changed".to_owned(),
                ));
            }
        } else {
            for statement in supply_chain_schema
                .split(';')
                .map(str::trim)
                .filter(|statement| !statement.is_empty())
            {
                query::<Postgres>(statement)
                    .execute(&mut *transaction)
                    .await
                    .map_err(storage_error)?;
            }
            query::<Postgres>(
                r#"
                INSERT INTO aip_connector_registry_migrations
                    (version, name, checksum, applied_at_ms)
                VALUES (4, 'connector_supply_chain_qualification', $1, $2)
                "#,
            )
            .bind(supply_chain_checksum)
            .bind(now_ms())
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        let control_replay_checksum =
            format!("{:x}", Sha256::digest(control_replay_schema.as_bytes()));
        let control_replay_applied = query::<Postgres>(
            "SELECT checksum FROM aip_connector_registry_migrations WHERE version = 5 FOR UPDATE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = control_replay_applied {
            let recorded: String = row.try_get("checksum").map_err(storage_error)?;
            if recorded != control_replay_checksum {
                return Err(RegistryError::Storage(
                    "connector registry migration 5 checksum changed".to_owned(),
                ));
            }
        } else {
            for statement in control_replay_schema
                .split(';')
                .map(str::trim)
                .filter(|statement| !statement.is_empty())
            {
                query::<Postgres>(statement)
                    .execute(&mut *transaction)
                    .await
                    .map_err(storage_error)?;
            }
            query::<Postgres>(
                r#"
                INSERT INTO aip_connector_registry_migrations
                    (version, name, checksum, applied_at_ms)
                VALUES (5, 'connector_control_replay', $1, $2)
                "#,
            )
            .bind(control_replay_checksum)
            .bind(now_ms())
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        let topology_checksum = format!("{:x}", Sha256::digest(topology_schema.as_bytes()));
        let topology_applied = query::<Postgres>(
            "SELECT checksum FROM aip_connector_registry_migrations WHERE version = 6 FOR UPDATE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = topology_applied {
            let recorded: String = row.try_get("checksum").map_err(storage_error)?;
            if recorded != topology_checksum {
                return Err(RegistryError::Storage(
                    "connector registry migration 6 checksum changed".to_owned(),
                ));
            }
        } else {
            for statement in topology_schema
                .split(';')
                .map(str::trim)
                .filter(|statement| !statement.is_empty())
            {
                query::<Postgres>(statement)
                    .execute(&mut *transaction)
                    .await
                    .map_err(storage_error)?;
            }
            query::<Postgres>(
                r#"
                INSERT INTO aip_connector_registry_migrations
                    (version, name, checksum, applied_at_ms)
                VALUES (6, 'connector_replica_topology', $1, $2)
                "#,
            )
            .bind(topology_checksum)
            .bind(now_ms())
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        let operator_journal_checksum =
            format!("{:x}", Sha256::digest(operator_journal_schema.as_bytes()));
        let operator_journal_applied = query::<Postgres>(
            "SELECT checksum FROM aip_connector_registry_migrations WHERE version = 7 FOR UPDATE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = operator_journal_applied {
            let recorded: String = row.try_get("checksum").map_err(storage_error)?;
            if recorded != operator_journal_checksum {
                return Err(RegistryError::Storage(
                    "connector registry migration 7 checksum changed".to_owned(),
                ));
            }
        } else {
            for statement in operator_journal_schema
                .split(';')
                .map(str::trim)
                .filter(|statement| !statement.is_empty())
            {
                query::<Postgres>(statement)
                    .execute(&mut *transaction)
                    .await
                    .map_err(storage_error)?;
            }
            query::<Postgres>(
                r#"
                INSERT INTO aip_connector_registry_migrations
                    (version, name, checksum, applied_at_ms)
                VALUES (7, 'connector_admission_operator_journal', $1, $2)
                "#,
            )
            .bind(operator_journal_checksum)
            .bind(now_ms())
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        transaction.commit().await.map_err(storage_error)
    }

    fn require_control_pool(&self) -> Result<&PgPool, RegistryError> {
        self.control_pool.as_ref().ok_or_else(|| {
            RegistryError::Storage(
                "connector registry control-plane credentials are not configured in this process"
                    .to_owned(),
            )
        })
    }

    /// Returns the current catalog revision.
    pub async fn revision(&self) -> Result<CatalogRevision, RegistryError> {
        let row = query::<Postgres>(
            "SELECT revision FROM aip_connector_catalog_revision WHERE singleton = TRUE",
        )
        .fetch_one(&self.data_pool)
        .await
        .map_err(storage_error)?;
        revision_from_row(&row)
    }
}

#[async_trait]
impl ConnectorRegistryReader for PostgresConnectorRegistry {
    async fn connector_version(
        &self,
        version_id: &ConnectorVersionId,
    ) -> Result<Option<ConnectorVersion>, RegistryError> {
        query::<Postgres>("SELECT record FROM aip_connector_versions WHERE version_id = $1")
            .bind(version_id.as_str())
            .fetch_optional(&self.data_pool)
            .await
            .map_err(storage_error)?
            .map(|row| record(&row))
            .transpose()
    }

    async fn connector_instance(
        &self,
        instance_id: &ConnectorInstanceId,
    ) -> Result<Option<ConnectorInstance>, RegistryError> {
        query::<Postgres>("SELECT record FROM aip_connector_instances WHERE instance_id = $1")
            .bind(instance_id.as_str())
            .fetch_optional(&self.data_pool)
            .await
            .map_err(storage_error)?
            .map(|row| record(&row))
            .transpose()
    }

    async fn connector_replica(
        &self,
        replica_id: &aip_connector_registry::ConnectorReplicaId,
    ) -> Result<Option<ConnectorReplica>, RegistryError> {
        query::<Postgres>(
            r#"
            SELECT record, status, lease_expires_at_ms, capacity,
                   active_assignments, health_revision
            FROM aip_connector_replicas WHERE replica_id = $1
            "#,
        )
        .bind(replica_id.as_str())
        .fetch_optional(&self.data_pool)
        .await
        .map_err(storage_error)?
        .map(|row| {
            let mut replica: ConnectorReplica = record(&row)?;
            let status: String = row.try_get("status").map_err(storage_error)?;
            replica.status = replica_status_from_label(&status)?;
            replica.lease_expires_at =
                datetime_from_ms(row.try_get("lease_expires_at_ms").map_err(storage_error)?)?;
            replica.capacity = row_u32(&row, "capacity")?;
            replica.active_assignments = row_u32(&row, "active_assignments")?;
            replica.health_revision = row_u64(&row, "health_revision")?;
            Ok(replica)
        })
        .transpose()
    }
}

#[async_trait]
impl ConnectorRegistryAdmin for PostgresConnectorRegistry {
    async fn put_admission_policy(&self, policy: AdmissionPolicy) -> Result<(), RegistryError> {
        validate_admission_policy(&policy)?;
        let revision = u64_i64(policy.revision, "admission policy revision")?;
        let mut transaction = self
            .require_control_pool()?
            .begin()
            .await
            .map_err(storage_error)?;
        lock_catalog_revision(&mut transaction).await?;
        let existing = query::<Postgres>(
            "SELECT record FROM aip_connector_admission_policies WHERE policy_ref = $1 FOR UPDATE",
        )
        .bind(&policy.policy_ref)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = existing {
            let existing: AdmissionPolicy = record(&row)?;
            if existing == policy {
                transaction.commit().await.map_err(storage_error)?;
                return Ok(());
            }
            if policy.revision <= existing.revision {
                return Err(RegistryError::Conflict(format!(
                    "admission policy `{}` requires a newer revision",
                    policy.policy_ref
                )));
            }
        }
        query::<Postgres>(
            r#"
            INSERT INTO aip_connector_admission_policies
                (policy_ref, revision, enabled, record, updated_at_ms)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (policy_ref) DO UPDATE SET
                revision = EXCLUDED.revision,
                enabled = EXCLUDED.enabled,
                record = EXCLUDED.record,
                updated_at_ms = EXCLUDED.updated_at_ms
            "#,
        )
        .bind(&policy.policy_ref)
        .bind(revision)
        .bind(policy.enabled)
        .bind(to_json(&policy)?)
        .bind(now_ms())
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        advance_catalog_revision(&mut transaction).await?;
        transaction.commit().await.map_err(storage_error)
    }

    async fn put_connector_type(&self, connector_type: ConnectorType) -> Result<(), RegistryError> {
        require_nonempty("connector type name", &connector_type.name)?;
        require_nonempty("connector type owner", &connector_type.owner)?;
        let mut transaction = self
            .require_control_pool()?
            .begin()
            .await
            .map_err(storage_error)?;
        lock_catalog_revision(&mut transaction).await?;
        let existing = query::<Postgres>(
            "SELECT record FROM aip_connector_types WHERE type_id = $1 FOR UPDATE",
        )
        .bind(connector_type.id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = existing {
            let existing: ConnectorType = record(&row)?;
            if existing == connector_type {
                transaction.commit().await.map_err(storage_error)?;
                return Ok(());
            }
            return Err(RegistryError::Conflict(format!(
                "connector type `{}` already exists with another definition",
                connector_type.id
            )));
        }
        query::<Postgres>(
            r#"
            INSERT INTO aip_connector_types
                (type_id, name, owner, enabled, record, updated_at_ms)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(connector_type.id.as_str())
        .bind(&connector_type.name)
        .bind(&connector_type.owner)
        .bind(connector_type.enabled)
        .bind(to_json(&connector_type)?)
        .bind(now_ms())
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        advance_catalog_revision(&mut transaction).await?;
        transaction.commit().await.map_err(storage_error)
    }

    async fn set_connector_type_enabled(
        &self,
        connector_type_id: &ConnectorTypeId,
        enabled: bool,
    ) -> Result<(), RegistryError> {
        let mut transaction = self
            .require_control_pool()?
            .begin()
            .await
            .map_err(storage_error)?;
        lock_catalog_revision(&mut transaction).await?;
        let row = query::<Postgres>(
            "SELECT record FROM aip_connector_types WHERE type_id = $1 FOR UPDATE",
        )
        .bind(connector_type_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| RegistryError::NotFound(connector_type_id.to_string()))?;
        let mut connector_type: ConnectorType = record(&row)?;
        if connector_type.enabled == enabled {
            transaction.commit().await.map_err(storage_error)?;
            return Ok(());
        }
        connector_type.enabled = enabled;
        query::<Postgres>(
            "UPDATE aip_connector_types SET enabled = $2, record = $3, updated_at_ms = $4 WHERE type_id = $1",
        )
        .bind(connector_type_id.as_str())
        .bind(enabled)
        .bind(to_json(&connector_type)?)
        .bind(now_ms())
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        advance_catalog_revision(&mut transaction).await?;
        transaction.commit().await.map_err(storage_error)
    }

    async fn admit_version(&self, version: ConnectorVersion) -> Result<(), RegistryError> {
        let definitions = validate_connector_version(&version, &self.limits)?;
        let mut transaction = self
            .require_control_pool()?
            .begin()
            .await
            .map_err(storage_error)?;
        lock_catalog_revision(&mut transaction).await?;
        let type_row = query::<Postgres>(
            "SELECT record FROM aip_connector_types WHERE type_id = $1 FOR UPDATE",
        )
        .bind(version.connector_type_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| RegistryError::NotFound(version.connector_type_id.to_string()))?;
        let connector_type: ConnectorType = record(&type_row)?;
        if !connector_type.enabled {
            return Err(RegistryError::Admission(format!(
                "connector type `{}` is disabled",
                connector_type.id
            )));
        }
        if version.attestation.owner != connector_type.owner {
            return Err(RegistryError::Admission(format!(
                "artifact owner `{}` does not match connector type owner `{}`",
                version.attestation.owner, connector_type.owner
            )));
        }
        let existing = query::<Postgres>(
            "SELECT record FROM aip_connector_versions WHERE version_id = $1 FOR UPDATE",
        )
        .bind(version.id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = existing {
            let existing: ConnectorVersion = record(&row)?;
            if existing == version {
                transaction.commit().await.map_err(storage_error)?;
                return Ok(());
            }
            return Err(RegistryError::Conflict(format!(
                "connector version `{}` is immutable",
                version.id
            )));
        }
        for definition in &definitions {
            let existing = query::<Postgres>(
                "SELECT record FROM aip_capability_definitions WHERE capability_id = $1 FOR UPDATE",
            )
            .bind(definition.capability.id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?;
            if let Some(row) = existing {
                let existing: CapabilityDefinition = record(&row)?;
                if existing != *definition {
                    return Err(RegistryError::Conflict(format!(
                        "capability `{}` has another admitted contract digest",
                        definition.capability.id
                    )));
                }
            }
        }
        query::<Postgres>(
            r#"
            INSERT INTO aip_connector_versions
                (version_id, type_id, version, status, artifact_digest, manifest_digest,
                 supply_chain_qualified, record, admitted_at_ms)
            VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7, $8)
            "#,
        )
        .bind(version.id.as_str())
        .bind(version.connector_type_id.as_str())
        .bind(&version.version)
        .bind(version_status_label(version.status))
        .bind(&version.attestation.artifact_digest)
        .bind(&version.manifest_digest)
        .bind(to_json(&version)?)
        .bind(datetime_ms(version.admitted_at)?)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        for definition in definitions {
            query::<Postgres>(
                r#"
                INSERT INTO aip_capability_definitions
                    (capability_id, contract_digest, schema_digest, record)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (capability_id) DO NOTHING
                "#,
            )
            .bind(definition.capability.id.as_str())
            .bind(&definition.contract_digest)
            .bind(&definition.schema_digest)
            .bind(to_json(&definition)?)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
            query::<Postgres>(
                r#"
                INSERT INTO aip_connector_version_capabilities
                    (version_id, capability_id, contract_digest)
                VALUES ($1, $2, $3)
                "#,
            )
            .bind(version.id.as_str())
            .bind(definition.capability.id.as_str())
            .bind(&definition.contract_digest)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        for profile in &version.manifest.profiles {
            query::<Postgres>(
                "INSERT INTO aip_connector_version_profiles (version_id, profile_id) VALUES ($1, $2)",
            )
            .bind(version.id.as_str())
            .bind(profile.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        advance_catalog_revision(&mut transaction).await?;
        transaction.commit().await.map_err(storage_error)
    }

    async fn set_version_status(
        &self,
        version_id: &ConnectorVersionId,
        status: ConnectorVersionStatus,
    ) -> Result<(), RegistryError> {
        if status == ConnectorVersionStatus::Candidate {
            return Err(RegistryError::Invalid(
                "an admitted version cannot return to candidate status".to_owned(),
            ));
        }
        let mut transaction = self
            .require_control_pool()?
            .begin()
            .await
            .map_err(storage_error)?;
        lock_catalog_revision(&mut transaction).await?;
        let row = query::<Postgres>(
            "SELECT record FROM aip_connector_versions WHERE version_id = $1 FOR UPDATE",
        )
        .bind(version_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| RegistryError::NotFound(version_id.to_string()))?;
        let mut version: ConnectorVersion = record(&row)?;
        if version.status == status {
            transaction.commit().await.map_err(storage_error)?;
            return Ok(());
        }
        if version.status == ConnectorVersionStatus::Revoked {
            return Err(RegistryError::Conflict(format!(
                "revoked connector version `{version_id}` cannot be reactivated"
            )));
        }
        if status == ConnectorVersionStatus::Active {
            aip_connector_registry::validate_artifact_attestation(
                &version.attestation,
                &version.manifest,
            )?;
        }
        version.status = status;
        query::<Postgres>(
            "UPDATE aip_connector_versions SET status = $2, record = $3 WHERE version_id = $1",
        )
        .bind(version_id.as_str())
        .bind(version_status_label(status))
        .bind(to_json(&version)?)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        advance_catalog_revision(&mut transaction).await?;
        transaction.commit().await.map_err(storage_error)
    }

    async fn put_instance(&self, instance: ConnectorInstance) -> Result<(), RegistryError> {
        require_nonempty("tenant id", &instance.tenant_id)?;
        require_nonempty("secret provider reference", &instance.secret_provider_ref)?;
        let config_revision = u64_i64(instance.config_revision, "instance config revision")?;
        let mut transaction = self
            .require_control_pool()?
            .begin()
            .await
            .map_err(storage_error)?;
        lock_catalog_revision(&mut transaction).await?;
        let version_row =
            query::<Postgres>("SELECT record FROM aip_connector_versions WHERE version_id = $1")
                .bind(instance.version_id.as_str())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(storage_error)?
                .ok_or_else(|| RegistryError::NotFound(instance.version_id.to_string()))?;
        let version: ConnectorVersion = record(&version_row)?;
        if version.connector_type_id != instance.connector_type_id {
            return Err(RegistryError::Invalid(
                "instance connector type does not match its version".to_owned(),
            ));
        }
        let existing = query::<Postgres>(
            "SELECT record FROM aip_connector_instances WHERE instance_id = $1 FOR UPDATE",
        )
        .bind(instance.id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = existing {
            let existing: ConnectorInstance = record(&row)?;
            if existing == instance {
                transaction.commit().await.map_err(storage_error)?;
                return Ok(());
            }
            if existing.connector_type_id != instance.connector_type_id
                || existing.tenant_id != instance.tenant_id
            {
                return Err(RegistryError::Conflict(format!(
                    "connector instance `{}` cannot change type or tenant",
                    instance.id
                )));
            }
            if instance.config_revision <= existing.config_revision {
                return Err(RegistryError::Conflict(format!(
                    "connector instance `{}` requires a newer config revision",
                    instance.id
                )));
            }
        }
        let incompatible = query::<Postgres>(
            r#"
            SELECT b.capability_id
            FROM aip_tenant_capability_bindings b
            WHERE b.instance_id = $1 AND b.enabled = TRUE
              AND NOT EXISTS (
                SELECT 1 FROM aip_connector_version_capabilities vc
                WHERE vc.version_id = $2 AND vc.capability_id = b.capability_id
              )
            LIMIT 1
            "#,
        )
        .bind(instance.id.as_str())
        .bind(instance.version_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = incompatible {
            let capability_id: String = row.try_get("capability_id").map_err(storage_error)?;
            return Err(RegistryError::Conflict(format!(
                "instance rollout version `{}` does not implement bound capability `{capability_id}`",
                instance.version_id
            )));
        }
        query::<Postgres>(
            r#"
            INSERT INTO aip_connector_instances
                (instance_id, type_id, version_id, tenant_id, config_revision,
                 secret_provider_ref, status, record, updated_at_ms)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (instance_id) DO UPDATE SET
                version_id = EXCLUDED.version_id,
                config_revision = EXCLUDED.config_revision,
                secret_provider_ref = EXCLUDED.secret_provider_ref,
                status = EXCLUDED.status,
                record = EXCLUDED.record,
                updated_at_ms = EXCLUDED.updated_at_ms
            "#,
        )
        .bind(instance.id.as_str())
        .bind(instance.connector_type_id.as_str())
        .bind(instance.version_id.as_str())
        .bind(&instance.tenant_id)
        .bind(config_revision)
        .bind(&instance.secret_provider_ref)
        .bind(instance_status_label(instance.status))
        .bind(to_json(&instance)?)
        .bind(now_ms())
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        advance_catalog_revision(&mut transaction).await?;
        transaction.commit().await.map_err(storage_error)
    }

    async fn put_replica(&self, replica: ConnectorReplica) -> Result<(), RegistryError> {
        validate_connector_replica(&replica)?;
        let capacity = u64_i64(u64::from(replica.capacity), "replica capacity")?;
        let health_revision = u64_i64(replica.health_revision, "replica health revision")?;
        let lease_expires_at_ms = datetime_ms(replica.lease_expires_at)?;
        let mut transaction = self.data_pool.begin().await.map_err(storage_error)?;
        let instance_row =
            query::<Postgres>("SELECT record FROM aip_connector_instances WHERE instance_id = $1")
                .bind(replica.instance_id.as_str())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(storage_error)?
                .ok_or_else(|| RegistryError::NotFound(replica.instance_id.to_string()))?;
        let instance: ConnectorInstance = record(&instance_row)?;
        if instance.version_id != replica.version_id {
            return Err(RegistryError::Invalid(
                "replica version does not match the instance rollout version".to_owned(),
            ));
        }
        let existing = query::<Postgres>(
            "SELECT record, active_assignments FROM aip_connector_replicas WHERE replica_id = $1 FOR UPDATE",
        )
        .bind(replica.id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = existing {
            let mut existing: ConnectorReplica = record(&row)?;
            existing.active_assignments = row_u32(&row, "active_assignments")?;
            if existing == replica {
                transaction.commit().await.map_err(storage_error)?;
                return Ok(());
            }
            if !same_replica_identity(&existing, &replica) {
                return Err(RegistryError::Conflict(format!(
                    "connector replica `{}` cannot change immutable identity or endpoint",
                    replica.id
                )));
            }
            if replica.health_revision <= existing.health_revision {
                return Err(RegistryError::Conflict(format!(
                    "replica `{}` requires a newer health revision",
                    replica.id
                )));
            }
            if replica.active_assignments != existing.active_assignments {
                return Err(RegistryError::Conflict(format!(
                    "replica `{}` active assignments are registry-owned",
                    replica.id
                )));
            }
        } else if replica.active_assignments != 0 {
            return Err(RegistryError::Invalid(
                "a new replica must start with zero active assignments".to_owned(),
            ));
        }
        query::<Postgres>(
            r#"
            INSERT INTO aip_connector_replicas
                (replica_id, instance_id, version_id, endpoint, status, lease_expires_at_ms,
                 capacity, active_assignments, health_revision, region, zone, capacity_class,
                 record, updated_at_ms)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ON CONFLICT (replica_id) DO UPDATE SET
                status = EXCLUDED.status,
                lease_expires_at_ms = EXCLUDED.lease_expires_at_ms,
                capacity = EXCLUDED.capacity,
                health_revision = EXCLUDED.health_revision,
                region = EXCLUDED.region,
                zone = EXCLUDED.zone,
                capacity_class = EXCLUDED.capacity_class,
                record = EXCLUDED.record,
                updated_at_ms = EXCLUDED.updated_at_ms
            "#,
        )
        .bind(replica.id.as_str())
        .bind(replica.instance_id.as_str())
        .bind(replica.version_id.as_str())
        .bind(&replica.endpoint)
        .bind(replica_status_label(replica.status))
        .bind(lease_expires_at_ms)
        .bind(capacity)
        .bind(i64::from(replica.active_assignments))
        .bind(health_revision)
        .bind(&replica.topology.region)
        .bind(&replica.topology.zone)
        .bind(&replica.topology.capacity_class)
        .bind(to_json(&replica)?)
        .bind(now_ms())
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)
    }

    async fn put_binding(&self, binding: CapabilityBinding) -> Result<(), RegistryError> {
        require_nonempty("tenant id", &binding.tenant_id)?;
        let priority = u64_i64(u64::from(binding.priority), "binding priority")?;
        let policy_revision = u64_i64(binding.policy_revision, "binding policy revision")?;
        let mut transaction = self
            .require_control_pool()?
            .begin()
            .await
            .map_err(storage_error)?;
        lock_catalog_revision(&mut transaction).await?;
        if let Some(policy_ref) = binding.quota_policy_ref.as_deref() {
            let exists = query::<Postgres>(
                "SELECT 1 FROM aip_connector_admission_policies WHERE policy_ref = $1",
            )
            .bind(policy_ref)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?
            .is_some();
            if !exists {
                return Err(RegistryError::NotFound(format!(
                    "admission policy `{policy_ref}`"
                )));
            }
        }
        let instance_row =
            query::<Postgres>("SELECT record FROM aip_connector_instances WHERE instance_id = $1")
                .bind(binding.instance_id.as_str())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(storage_error)?
                .ok_or_else(|| RegistryError::NotFound(binding.instance_id.to_string()))?;
        let instance: ConnectorInstance = record(&instance_row)?;
        if instance.tenant_id != binding.tenant_id {
            return Err(RegistryError::Invalid(
                "binding tenant does not own the connector instance".to_owned(),
            ));
        }
        let supported = query::<Postgres>(
            r#"
            SELECT 1 FROM aip_connector_version_capabilities
            WHERE version_id = $1 AND capability_id = $2
            "#,
        )
        .bind(instance.version_id.as_str())
        .bind(binding.capability_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?
        .is_some();
        if !supported {
            return Err(RegistryError::Invalid(format!(
                "version `{}` does not implement `{}`",
                instance.version_id, binding.capability_id
            )));
        }
        let existing = query::<Postgres>(
            r#"
            SELECT record FROM aip_tenant_capability_bindings
            WHERE tenant_id = $1 AND capability_id = $2 AND instance_id = $3
            FOR UPDATE
            "#,
        )
        .bind(&binding.tenant_id)
        .bind(binding.capability_id.as_str())
        .bind(binding.instance_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = existing {
            let existing: CapabilityBinding = record(&row)?;
            if existing == binding {
                transaction.commit().await.map_err(storage_error)?;
                return Ok(());
            }
            if binding.policy_revision <= existing.policy_revision {
                return Err(RegistryError::Conflict(format!(
                    "binding for `{}` and `{}` requires a newer policy revision",
                    binding.tenant_id, binding.capability_id
                )));
            }
        }
        query::<Postgres>(
            r#"
            INSERT INTO aip_tenant_capability_bindings
                (tenant_id, capability_id, instance_id, priority, policy_revision,
                 credential_revision_ref, quota_policy_ref, enabled, record, updated_at_ms)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (tenant_id, capability_id, instance_id) DO UPDATE SET
                priority = EXCLUDED.priority,
                policy_revision = EXCLUDED.policy_revision,
                credential_revision_ref = EXCLUDED.credential_revision_ref,
                quota_policy_ref = EXCLUDED.quota_policy_ref,
                enabled = EXCLUDED.enabled,
                record = EXCLUDED.record,
                updated_at_ms = EXCLUDED.updated_at_ms
            "#,
        )
        .bind(&binding.tenant_id)
        .bind(binding.capability_id.as_str())
        .bind(binding.instance_id.as_str())
        .bind(priority)
        .bind(policy_revision)
        .bind(&binding.credential_revision_ref)
        .bind(&binding.quota_policy_ref)
        .bind(binding.enabled)
        .bind(to_json(&binding)?)
        .bind(now_ms())
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        advance_catalog_revision(&mut transaction).await?;
        transaction.commit().await.map_err(storage_error)
    }
}

#[async_trait]
impl AdmissionJournal for PostgresConnectorRegistry {
    async fn claim_admission_operation(
        &self,
        mut operation: AdmissionOperation,
    ) -> Result<AdmissionOperationClaim, AdmissionError> {
        validate_admission_operation(&operation)?;
        operation.state = AdmissionOperationState::Applying;
        operation.last_error = None;
        operation.updated_at = OffsetDateTime::now_utc();
        let revision = i64::try_from(operation.revision).map_err(|_| {
            AdmissionError::Invalid("admission operation revision exceeds i64".to_owned())
        })?;
        let mut transaction = self
            .require_control_pool()
            .map_err(admission_journal_error)?
            .begin()
            .await
            .map_err(|error| AdmissionError::Journal(error.to_string()))?;
        // Serialize every revision of one package. A row lock on the exact
        // `(package_id, revision)` cannot fence two concurrent first inserts.
        query::<Postgres>("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&operation.package_id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| AdmissionError::Journal(error.to_string()))?;
        let latest = query::<Postgres>(
            r#"
            SELECT record FROM aip_connector_admission_operations
            WHERE package_id = $1
            ORDER BY revision DESC
            LIMIT 1
            FOR UPDATE
            "#,
        )
        .bind(&operation.package_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| AdmissionError::Journal(error.to_string()))?;
        if let Some(row) = latest {
            let mut existing: AdmissionOperation = record(&row).map_err(admission_journal_error)?;
            if existing.revision > operation.revision {
                return Err(AdmissionError::Conflict(format!(
                    "package `{}` revision {} is stale; revision {} is already durable",
                    operation.package_id, operation.revision, existing.revision
                )));
            }
            if existing.revision < operation.revision {
                if matches!(
                    existing.state,
                    AdmissionOperationState::Applying | AdmissionOperationState::Failed
                ) {
                    return Err(AdmissionError::Conflict(format!(
                        "package `{}` revision {} must be completed before revision {} can be claimed",
                        operation.package_id, existing.revision, operation.revision
                    )));
                }
            } else {
                if existing.package_digest != operation.package_digest
                    || existing.connector_type_id != operation.connector_type_id
                    || existing.version_id != operation.version_id
                {
                    return Err(AdmissionError::Conflict(format!(
                        "package `{}` revision {} was already claimed with different content",
                        operation.package_id, operation.revision
                    )));
                }
                match existing.state {
                    AdmissionOperationState::Applied => {
                        transaction
                            .commit()
                            .await
                            .map_err(|error| AdmissionError::Journal(error.to_string()))?;
                        return Ok(AdmissionOperationClaim::AlreadyApplied);
                    }
                    AdmissionOperationState::Abandoned | AdmissionOperationState::Revoked => {
                        return Err(AdmissionError::Conflict(
                            "a terminal admission operation cannot be resumed".to_owned(),
                        ));
                    }
                    AdmissionOperationState::Applying
                        if existing.claim_expires_at > OffsetDateTime::now_utc()
                            && existing.claim_id != operation.claim_id =>
                    {
                        return Err(AdmissionError::Conflict(format!(
                            "package `{}` revision {} is owned by another live admission claim",
                            operation.package_id, operation.revision
                        )));
                    }
                    AdmissionOperationState::Applying | AdmissionOperationState::Failed => {
                        existing.state = AdmissionOperationState::Applying;
                        existing.claim_id = operation.claim_id;
                        existing.claim_expires_at = operation.claim_expires_at;
                        existing.last_error = None;
                        existing.updated_at = OffsetDateTime::now_utc();
                        query::<Postgres>(
                            r#"
                        UPDATE aip_connector_admission_operations
                        SET state = 'applying', record = $3, updated_at_ms = $4
                        WHERE package_id = $1 AND revision = $2
                        "#,
                        )
                        .bind(&existing.package_id)
                        .bind(revision)
                        .bind(to_json(&existing).map_err(admission_journal_error)?)
                        .bind(datetime_ms(existing.updated_at).map_err(admission_journal_error)?)
                        .execute(&mut *transaction)
                        .await
                        .map_err(|error| AdmissionError::Journal(error.to_string()))?;
                        transaction
                            .commit()
                            .await
                            .map_err(|error| AdmissionError::Journal(error.to_string()))?;
                        return Ok(AdmissionOperationClaim::Resume);
                    }
                }
            }
        }
        query::<Postgres>(
            r#"
            INSERT INTO aip_connector_admission_operations
                (package_id, revision, package_digest, state, record, updated_at_ms)
            VALUES ($1, $2, $3, 'applying', $4, $5)
            "#,
        )
        .bind(&operation.package_id)
        .bind(revision)
        .bind(&operation.package_digest)
        .bind(to_json(&operation).map_err(admission_journal_error)?)
        .bind(datetime_ms(operation.updated_at).map_err(admission_journal_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| AdmissionError::Journal(error.to_string()))?;
        transaction
            .commit()
            .await
            .map_err(|error| AdmissionError::Journal(error.to_string()))?;
        Ok(AdmissionOperationClaim::New)
    }

    async fn renew_admission_operation(
        &self,
        package_id: &str,
        revision: u64,
        package_digest: &str,
        claim_id: &str,
        claim_expires_at: OffsetDateTime,
    ) -> Result<(), AdmissionError> {
        let revision = i64::try_from(revision).map_err(|_| {
            AdmissionError::Invalid("admission operation revision exceeds i64".to_owned())
        })?;
        if claim_expires_at <= OffsetDateTime::now_utc() {
            return Err(AdmissionError::Invalid(
                "admission claim renewal must expire in the future".to_owned(),
            ));
        }
        let mut transaction = self
            .require_control_pool()
            .map_err(admission_journal_error)?
            .begin()
            .await
            .map_err(|error| AdmissionError::Journal(error.to_string()))?;
        let row = query::<Postgres>(
            r#"
            SELECT record FROM aip_connector_admission_operations
            WHERE package_id = $1 AND revision = $2 AND package_digest = $3
            FOR UPDATE
            "#,
        )
        .bind(package_id)
        .bind(revision)
        .bind(package_digest)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| AdmissionError::Journal(error.to_string()))?
        .ok_or_else(|| AdmissionError::Conflict("admission claim is missing".to_owned()))?;
        let mut operation: AdmissionOperation = record(&row).map_err(admission_journal_error)?;
        if operation.state != AdmissionOperationState::Applying
            || operation.claim_id != claim_id
            || operation.claim_expires_at <= OffsetDateTime::now_utc()
        {
            return Err(AdmissionError::Conflict(
                "admission claim was superseded, expired, or is no longer active".to_owned(),
            ));
        }
        operation.claim_expires_at = claim_expires_at;
        operation.updated_at = OffsetDateTime::now_utc();
        query::<Postgres>(
            r#"
            UPDATE aip_connector_admission_operations
            SET record = $4, updated_at_ms = $5
            WHERE package_id = $1 AND revision = $2 AND package_digest = $3
            "#,
        )
        .bind(package_id)
        .bind(revision)
        .bind(package_digest)
        .bind(to_json(&operation).map_err(admission_journal_error)?)
        .bind(datetime_ms(operation.updated_at).map_err(admission_journal_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| AdmissionError::Journal(error.to_string()))?;
        transaction
            .commit()
            .await
            .map_err(|error| AdmissionError::Journal(error.to_string()))
    }

    async fn complete_admission_operation(
        &self,
        package_id: &str,
        revision: u64,
        package_digest: &str,
        claim_id: &str,
    ) -> Result<(), AdmissionError> {
        self.update_admission_operation_state(
            package_id,
            revision,
            package_digest,
            Some(claim_id),
            AdmissionOperationState::Applied,
            None,
        )
        .await
    }

    async fn fail_admission_operation(
        &self,
        package_id: &str,
        revision: u64,
        package_digest: &str,
        claim_id: &str,
        error: &str,
    ) -> Result<(), AdmissionError> {
        let mut error = error.to_owned();
        error.truncate(1_024);
        self.update_admission_operation_state(
            package_id,
            revision,
            package_digest,
            Some(claim_id),
            AdmissionOperationState::Failed,
            Some(error),
        )
        .await
    }

    async fn admission_operation(
        &self,
        package_id: &str,
        revision: Option<u64>,
    ) -> Result<Option<AdmissionOperation>, AdmissionError> {
        if package_id.trim().is_empty() || package_id.len() > 256 {
            return Err(AdmissionError::Invalid(
                "package id must contain 1 to 256 bytes".to_owned(),
            ));
        }
        let row = if let Some(revision) = revision {
            let revision = i64::try_from(revision).map_err(|_| {
                AdmissionError::Invalid("admission operation revision exceeds i64".to_owned())
            })?;
            query::<Postgres>(
                r#"
                SELECT record FROM aip_connector_admission_operations
                WHERE package_id = $1 AND revision = $2
                "#,
            )
            .bind(package_id)
            .bind(revision)
            .fetch_optional(
                self.require_control_pool()
                    .map_err(admission_journal_error)?,
            )
            .await
            .map_err(|error| AdmissionError::Journal(error.to_string()))?
        } else {
            query::<Postgres>(
                r#"
                SELECT record FROM aip_connector_admission_operations
                WHERE package_id = $1
                ORDER BY revision DESC
                LIMIT 1
                "#,
            )
            .bind(package_id)
            .fetch_optional(
                self.require_control_pool()
                    .map_err(admission_journal_error)?,
            )
            .await
            .map_err(|error| AdmissionError::Journal(error.to_string()))?
        };
        row.map(|row| record(&row).map_err(admission_journal_error))
            .transpose()
    }

    async fn revoke_admission_operation(
        &self,
        package_id: &str,
        revision: u64,
        reason: &str,
    ) -> Result<(), AdmissionError> {
        let operation = self
            .admission_operation(package_id, Some(revision))
            .await?
            .ok_or_else(|| {
                AdmissionError::Conflict("admission operation was not found".to_owned())
            })?;
        if operation.state == AdmissionOperationState::Revoked {
            return Ok(());
        }
        if operation.state != AdmissionOperationState::Applied {
            return Err(AdmissionError::Conflict(
                "only an applied operation can be revoked".to_owned(),
            ));
        }
        let mut reason = reason.to_owned();
        reason.truncate(1_024);
        self.update_admission_operation_state(
            package_id,
            revision,
            &operation.package_digest,
            None,
            AdmissionOperationState::Revoked,
            Some(reason),
        )
        .await
    }

    async fn abandon_admission_operation(
        &self,
        package_id: &str,
        revision: u64,
        reason: &str,
    ) -> Result<(), AdmissionError> {
        let operation = self
            .admission_operation(package_id, Some(revision))
            .await?
            .ok_or_else(|| {
                AdmissionError::Conflict("admission operation was not found".to_owned())
            })?;
        if operation.state == AdmissionOperationState::Abandoned {
            return Ok(());
        }
        if operation.state != AdmissionOperationState::Failed {
            return Err(AdmissionError::Conflict(
                "only a failed operation can be abandoned".to_owned(),
            ));
        }
        let mut reason = reason.to_owned();
        reason.truncate(1_024);
        self.update_admission_operation_state(
            package_id,
            revision,
            &operation.package_digest,
            None,
            AdmissionOperationState::Abandoned,
            Some(reason),
        )
        .await
    }
}

impl PostgresConnectorRegistry {
    async fn update_admission_operation_state(
        &self,
        package_id: &str,
        revision: u64,
        package_digest: &str,
        claim_id: Option<&str>,
        state: AdmissionOperationState,
        detail: Option<String>,
    ) -> Result<(), AdmissionError> {
        let revision = i64::try_from(revision).map_err(|_| {
            AdmissionError::Invalid("admission operation revision exceeds i64".to_owned())
        })?;
        let pool = self
            .require_control_pool()
            .map_err(admission_journal_error)?;
        let mut transaction = pool
            .begin()
            .await
            .map_err(|error| AdmissionError::Journal(error.to_string()))?;
        let row = query::<Postgres>(
            r#"
            SELECT record FROM aip_connector_admission_operations
            WHERE package_id = $1 AND revision = $2 AND package_digest = $3
            FOR UPDATE
            "#,
        )
        .bind(package_id)
        .bind(revision)
        .bind(package_digest)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| AdmissionError::Journal(error.to_string()))?
        .ok_or_else(|| {
            AdmissionError::Conflict(
                "admission operation digest does not match the durable claim".to_owned(),
            )
        })?;
        let mut operation: AdmissionOperation = record(&row).map_err(admission_journal_error)?;
        if claim_id.is_some_and(|claim_id| operation.claim_id != claim_id) {
            return Err(AdmissionError::Conflict(
                "admission claim was superseded".to_owned(),
            ));
        }
        let allowed = matches!(
            (operation.state, state),
            (
                AdmissionOperationState::Applying,
                AdmissionOperationState::Applied
            ) | (
                AdmissionOperationState::Applying,
                AdmissionOperationState::Failed
            ) | (
                AdmissionOperationState::Applied,
                AdmissionOperationState::Applied
            ) | (
                AdmissionOperationState::Failed,
                AdmissionOperationState::Failed
            ) | (
                AdmissionOperationState::Failed,
                AdmissionOperationState::Abandoned
            ) | (
                AdmissionOperationState::Abandoned,
                AdmissionOperationState::Abandoned
            ) | (
                AdmissionOperationState::Applied,
                AdmissionOperationState::Revoked
            ) | (
                AdmissionOperationState::Revoked,
                AdmissionOperationState::Revoked
            )
        );
        if !allowed {
            return Err(AdmissionError::Conflict(
                "admission operation state transition is invalid".to_owned(),
            ));
        }
        operation.state = state;
        operation.last_error = detail;
        operation.updated_at = OffsetDateTime::now_utc();
        operation.claim_expires_at = operation.updated_at;
        let updated = query::<Postgres>(
            r#"
            UPDATE aip_connector_admission_operations
            SET state = $4, record = $5, updated_at_ms = $6
            WHERE package_id = $1 AND revision = $2 AND package_digest = $3
            "#,
        )
        .bind(package_id)
        .bind(revision)
        .bind(package_digest)
        .bind(admission_operation_state_label(state))
        .bind(to_json(&operation).map_err(admission_journal_error)?)
        .bind(datetime_ms(operation.updated_at).map_err(admission_journal_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| AdmissionError::Journal(error.to_string()))?;
        if updated.rows_affected() != 1 {
            return Err(AdmissionError::Conflict(
                "admission operation lost its durable claim".to_owned(),
            ));
        }
        transaction
            .commit()
            .await
            .map_err(|error| AdmissionError::Journal(error.to_string()))
    }
}

#[async_trait]
impl ConnectorFleetStatusProvider for PostgresConnectorRegistry {
    async fn expire_stale_replicas(
        &self,
        now: OffsetDateTime,
        limit: usize,
    ) -> Result<usize, RegistryError> {
        if limit == 0 {
            return Err(RegistryError::Invalid(
                "replica expiry batch limit must be greater than zero".to_owned(),
            ));
        }
        let limit = i64::try_from(limit)
            .map_err(|_| RegistryError::Invalid("replica expiry batch exceeds i64".to_owned()))?;
        let now_ms = datetime_ms(now)?;
        let mut transaction = self.data_pool.begin().await.map_err(storage_error)?;
        let expired = query::<Postgres>(
            r#"
            SELECT replica_id
            FROM aip_connector_replicas
            WHERE status <> 'offline' AND lease_expires_at_ms <= $1
            ORDER BY lease_expires_at_ms, replica_id
            FOR UPDATE SKIP LOCKED
            LIMIT $2
            "#,
        )
        .bind(now_ms)
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(storage_error)?;
        for expired_replica in &expired {
            let replica_id: String = expired_replica
                .try_get("replica_id")
                .map_err(storage_error)?;
            let reservations = query::<Postgres>(
                r#"
                SELECT action_id, reservation_scopes
                FROM aip_route_assignments
                WHERE replica_id = $1 AND reserved = TRUE
                ORDER BY action_id
                FOR UPDATE SKIP LOCKED
                "#,
            )
            .bind(&replica_id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(storage_error)?;
            for reservation in &reservations {
                let scopes: Vec<AdmissionScopeReservation> =
                    named_record(reservation, "reservation_scopes")?;
                release_admission_scopes(&mut transaction, &scopes).await?;
                let action_id: String = reservation.try_get("action_id").map_err(storage_error)?;
                query::<Postgres>(
                    r#"
                    UPDATE aip_route_assignments
                    SET reserved = FALSE,
                        last_settlement = 'lease_expired',
                        reservation_scopes = '[]'::jsonb,
                        updated_at_ms = $2
                    WHERE action_id = $1 AND reserved = TRUE
                    "#,
                )
                .bind(action_id)
                .bind(now_ms)
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
            }
            query::<Postgres>(
                r#"
                UPDATE aip_connector_replicas
                SET status = 'offline',
                    lease_expires_at_ms = LEAST(lease_expires_at_ms, $2),
                    active_assignments = 0,
                    health_revision = health_revision + 1,
                    record = (
                        jsonb_set(
                            jsonb_set(
                                jsonb_set(record, '{status}', '"offline"'::jsonb),
                                '{active_assignments}', '0'::jsonb
                            ),
                            '{health_revision}', to_jsonb(health_revision + 1)
                        ) - 'last_control_request_id' - 'last_control_request_digest'
                    ),
                    updated_at_ms = $2
                WHERE replica_id = $1
                "#,
            )
            .bind(replica_id)
            .bind(now_ms)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        transaction.commit().await.map_err(storage_error)?;
        Ok(expired.len())
    }

    async fn fleet_status(
        &self,
        observed_at: OffsetDateTime,
    ) -> Result<FleetStatusSummary, RegistryError> {
        let observed_at_ms = datetime_ms(observed_at)?;
        let row = query::<Postgres>(
            r#"
            SELECT
                revision.revision,
                (SELECT COUNT(*) FROM aip_connector_types)::BIGINT AS connector_types,
                (SELECT COUNT(*) FROM aip_connector_versions
                    WHERE status = 'active' AND supply_chain_qualified = TRUE)::BIGINT
                    AS active_versions,
                (SELECT COUNT(*) FROM aip_connector_instances
                    WHERE status = 'enabled')::BIGINT AS enabled_instances,
                (SELECT COUNT(*) FROM aip_connector_replicas)::BIGINT AS replicas,
                (SELECT COUNT(*) FROM aip_connector_replicas
                    WHERE status = 'ready' AND lease_expires_at_ms > $1)::BIGINT
                    AS ready_replicas,
                (SELECT COUNT(*) FROM aip_connector_replicas
                    WHERE status = 'draining' AND lease_expires_at_ms > $1)::BIGINT
                    AS draining_replicas,
                (SELECT COUNT(*) FROM aip_connector_replicas
                    WHERE status = 'offline')::BIGINT AS offline_replicas,
                (SELECT COUNT(*) FROM aip_connector_replicas
                    WHERE lease_expires_at_ms <= $1)::BIGINT AS expired_leases,
                (SELECT COALESCE(SUM(capacity), 0) FROM aip_connector_replicas
                    WHERE status = 'ready' AND lease_expires_at_ms > $1)::BIGINT
                    AS ready_capacity,
                (SELECT COALESCE(SUM(active_assignments), 0)
                    FROM aip_connector_replicas)::BIGINT AS active_assignments
            FROM aip_connector_catalog_revision AS revision
            WHERE revision.singleton = TRUE
            "#,
        )
        .bind(observed_at_ms)
        .fetch_one(&self.data_pool)
        .await
        .map_err(storage_error)?;
        Ok(FleetStatusSummary {
            catalog_revision: revision_from_row(&row)?,
            connector_types: row_u64(&row, "connector_types")?,
            active_versions: row_u64(&row, "active_versions")?,
            enabled_instances: row_u64(&row, "enabled_instances")?,
            replicas: row_u64(&row, "replicas")?,
            ready_replicas: row_u64(&row, "ready_replicas")?,
            draining_replicas: row_u64(&row, "draining_replicas")?,
            offline_replicas: row_u64(&row, "offline_replicas")?,
            expired_leases: row_u64(&row, "expired_leases")?,
            ready_capacity: row_u64(&row, "ready_capacity")?,
            active_assignments: row_u64(&row, "active_assignments")?,
            observed_at,
        })
    }

    fn pool_snapshot(&self) -> Option<ConnectorRegistryPoolSnapshot> {
        Some(PostgresConnectorRegistry::pool_snapshot(self))
    }
}

#[async_trait]
impl CapabilityCatalogProvider for PostgresConnectorRegistry {
    async fn get(
        &self,
        capability_id: &CapabilityId,
        context: &CatalogReadContext,
    ) -> Result<Option<ResolvedCapabilityDefinition>, RegistryError> {
        let mut transaction = self.data_pool.begin().await.map_err(storage_error)?;
        let revision = read_catalog_revision(&mut transaction).await?;
        let row = if let Some(tenant_id) = context.tenant_id.as_deref() {
            query::<Postgres>(
                r#"
                SELECT d.record
                FROM aip_capability_definitions d
                WHERE d.capability_id = $1
                  AND EXISTS (
                    SELECT 1
                    FROM aip_tenant_capability_bindings b
                    JOIN aip_connector_instances i ON i.instance_id = b.instance_id
                    JOIN aip_connector_versions v ON v.version_id = i.version_id
                    JOIN aip_connector_types t ON t.type_id = i.type_id
                    JOIN aip_connector_version_capabilities vc
                      ON vc.version_id = v.version_id
                     AND vc.capability_id = b.capability_id
                    WHERE b.tenant_id = $2
                      AND b.capability_id = d.capability_id
                      AND b.enabled = TRUE
                      AND i.tenant_id = b.tenant_id
                      AND i.status = 'enabled'
                      AND v.status = 'active'
                      AND v.supply_chain_qualified = TRUE
                      AND t.enabled = TRUE
                  )
                "#,
            )
            .bind(capability_id.as_str())
            .bind(tenant_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?
        } else if context.allow_unbound {
            query::<Postgres>(
                r#"
                SELECT d.record
                FROM aip_capability_definitions d
                WHERE d.capability_id = $1
                  AND EXISTS (
                    SELECT 1
                    FROM aip_connector_version_capabilities vc
                    JOIN aip_connector_versions v ON v.version_id = vc.version_id
                    JOIN aip_connector_types t ON t.type_id = v.type_id
                    WHERE vc.capability_id = d.capability_id
                      AND v.status = 'active'
                      AND v.supply_chain_qualified = TRUE
                      AND t.enabled = TRUE
                  )
                "#,
            )
            .bind(capability_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?
        } else {
            None
        };
        transaction.commit().await.map_err(storage_error)?;
        row.map(|row| {
            Ok(ResolvedCapabilityDefinition {
                definition: record(&row)?,
                catalog_revision: revision,
            })
        })
        .transpose()
    }

    async fn query(
        &self,
        request: CapabilityCatalogQuery,
        context: &CatalogReadContext,
    ) -> Result<CapabilityPage, RegistryError> {
        validate_registry_limits(&self.limits)?;
        let mut transaction = self.data_pool.begin().await.map_err(storage_error)?;
        let revision = read_catalog_revision(&mut transaction).await?;
        let after = parse_catalog_cursor(request.cursor.as_deref(), revision)?;
        let exact = request.capability_id.as_ref().map(CapabilityId::as_str);
        let text = request
            .text
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| format!("%{}%", value.to_ascii_lowercase()));
        let profile = request.profile.as_ref().map(ProfileId::as_str);
        let limit = request.limit.max(1).min(self.limits.max_page_size);
        let total = if let Some(tenant_id) = context.tenant_id.as_deref() {
            let total_row = query::<Postgres>(TENANT_CATALOG_COUNT_SQL)
                .bind(exact)
                .bind(text.as_deref())
                .bind(tenant_id)
                .bind(profile)
                .fetch_one(&mut *transaction)
                .await
                .map_err(storage_error)?;
            row_u64(&total_row, "total")?
        } else if context.allow_unbound {
            let total_row = query::<Postgres>(INTERNAL_CATALOG_COUNT_SQL)
                .bind(exact)
                .bind(text.as_deref())
                .bind(profile)
                .fetch_one(&mut *transaction)
                .await
                .map_err(storage_error)?;
            row_u64(&total_row, "total")?
        } else {
            0
        };

        let transfer_ceiling =
            self.limits
                .max_capability_bytes
                .checked_mul(2)
                .ok_or_else(|| {
                    RegistryError::Invalid("catalog capability byte limit overflowed".to_owned())
                })?;
        let transfer_ceiling_i64 = i64::try_from(transfer_ceiling).map_err(|_| {
            RegistryError::Invalid("catalog capability byte limit is too large".to_owned())
        })?;
        let transfer_ceiling_u64 = u64::try_from(transfer_ceiling).map_err(|_| {
            RegistryError::Invalid("catalog capability byte limit is too large".to_owned())
        })?;
        let fetch_batch_size = self
            .limits
            .max_page_bytes
            .checked_div(transfer_ceiling)
            .unwrap_or(0)
            .max(1)
            .min(limit.saturating_add(1));
        let mut scan_after = after;
        let mut capabilities = Vec::with_capacity(limit);
        let mut page_bytes = 0_usize;
        let mut has_more = false;

        if total > 0 {
            loop {
                let remaining = limit.saturating_sub(capabilities.len());
                let fetch_limit_usize = remaining.saturating_add(1).min(fetch_batch_size).max(1);
                let fetch_limit = i64::try_from(fetch_limit_usize).map_err(|_| {
                    RegistryError::Invalid("catalog page limit is too large".to_owned())
                })?;
                let rows = if let Some(tenant_id) = context.tenant_id.as_deref() {
                    query::<Postgres>(TENANT_CATALOG_PAGE_SQL)
                        .bind(exact)
                        .bind(text.as_deref())
                        .bind(tenant_id)
                        .bind(profile)
                        .bind(scan_after.as_ref().map(CapabilityId::as_str))
                        .bind(fetch_limit)
                        .bind(transfer_ceiling_i64)
                        .fetch_all(&mut *transaction)
                        .await
                        .map_err(storage_error)?
                } else if context.allow_unbound {
                    query::<Postgres>(INTERNAL_CATALOG_PAGE_SQL)
                        .bind(exact)
                        .bind(text.as_deref())
                        .bind(profile)
                        .bind(scan_after.as_ref().map(CapabilityId::as_str))
                        .bind(fetch_limit)
                        .bind(transfer_ceiling_i64)
                        .fetch_all(&mut *transaction)
                        .await
                        .map_err(storage_error)?
                } else {
                    Vec::new()
                };
                let fetched = rows.len();
                if fetched == 0 {
                    break;
                }
                for row in &rows {
                    if capabilities.len() == limit {
                        has_more = true;
                        break;
                    }
                    let capability_id: String =
                        row.try_get("capability_id").map_err(storage_error)?;
                    let stored_bytes = row_u64(row, "record_bytes")?;
                    if stored_bytes > transfer_ceiling_u64 {
                        return Err(RegistryError::Storage(format!(
                            "stored capability `{capability_id}` exceeds the bounded transfer limit"
                        )));
                    }
                    let definition = record::<CapabilityDefinition>(row)?;
                    let definition_bytes = capability_definition_size(&definition)?;
                    if definition_bytes > self.limits.max_capability_bytes {
                        return Err(RegistryError::Storage(format!(
                            "stored capability `{}` exceeds the configured {} byte definition limit",
                            definition.capability.id, self.limits.max_capability_bytes
                        )));
                    }
                    if page_bytes.saturating_add(definition_bytes) > self.limits.max_page_bytes {
                        has_more = true;
                        break;
                    }
                    page_bytes = page_bytes.saturating_add(definition_bytes);
                    scan_after = Some(definition.capability.id.clone());
                    capabilities.push(definition);
                }
                if has_more || fetched < fetch_limit_usize {
                    break;
                }
            }
        }
        transaction.commit().await.map_err(storage_error)?;
        let next_cursor = if has_more {
            let definition = capabilities.last().ok_or_else(|| {
                RegistryError::Invalid(
                    "catalog byte limits cannot fit one admitted capability".to_owned(),
                )
            })?;
            Some(format!("{}:{}", revision.0, definition.capability.id))
        } else {
            None
        };
        Ok(CapabilityPage {
            catalog_revision: revision,
            capabilities,
            next_cursor,
            total,
        })
    }
}

const TENANT_CATALOG_COUNT_SQL: &str = r#"
    SELECT COUNT(*)::BIGINT AS total
    FROM aip_capability_definitions d
    WHERE ($1::TEXT IS NULL OR d.capability_id = $1)
      AND ($2::TEXT IS NULL OR
           LOWER(d.capability_id || ' ' || COALESCE(d.record->'capability'->>'name', '') || ' ' ||
                 COALESCE(d.record->'capability'->>'description', '')) LIKE $2)
      AND EXISTS (
        SELECT 1
        FROM aip_tenant_capability_bindings b
        JOIN aip_connector_instances i ON i.instance_id = b.instance_id
        JOIN aip_connector_versions v ON v.version_id = i.version_id
        JOIN aip_connector_types t ON t.type_id = i.type_id
        JOIN aip_connector_version_capabilities vc
          ON vc.version_id = v.version_id AND vc.capability_id = b.capability_id
        WHERE b.tenant_id = $3 AND b.capability_id = d.capability_id
          AND b.enabled = TRUE AND i.tenant_id = b.tenant_id
          AND i.status = 'enabled' AND v.status = 'active'
          AND v.supply_chain_qualified = TRUE AND t.enabled = TRUE
          AND ($4::TEXT IS NULL OR EXISTS (
              SELECT 1 FROM aip_connector_version_profiles vp
              WHERE vp.version_id = v.version_id AND vp.profile_id = $4
          ))
      )
"#;

const TENANT_CATALOG_PAGE_SQL: &str = r#"
    SELECT d.capability_id,
           octet_length(d.record::TEXT)::BIGINT AS record_bytes,
           CASE WHEN octet_length(d.record::TEXT) <= $7 THEN d.record ELSE NULL END AS record
    FROM aip_capability_definitions d
    WHERE ($1::TEXT IS NULL OR d.capability_id = $1)
      AND ($2::TEXT IS NULL OR
           LOWER(d.capability_id || ' ' || COALESCE(d.record->'capability'->>'name', '') || ' ' ||
                 COALESCE(d.record->'capability'->>'description', '')) LIKE $2)
      AND EXISTS (
        SELECT 1
        FROM aip_tenant_capability_bindings b
        JOIN aip_connector_instances i ON i.instance_id = b.instance_id
        JOIN aip_connector_versions v ON v.version_id = i.version_id
        JOIN aip_connector_types t ON t.type_id = i.type_id
        JOIN aip_connector_version_capabilities vc
          ON vc.version_id = v.version_id AND vc.capability_id = b.capability_id
        WHERE b.tenant_id = $3 AND b.capability_id = d.capability_id
          AND b.enabled = TRUE AND i.tenant_id = b.tenant_id
          AND i.status = 'enabled' AND v.status = 'active'
          AND v.supply_chain_qualified = TRUE AND t.enabled = TRUE
          AND ($4::TEXT IS NULL OR EXISTS (
              SELECT 1 FROM aip_connector_version_profiles vp
              WHERE vp.version_id = v.version_id AND vp.profile_id = $4
          ))
      )
      AND ($5::TEXT IS NULL OR d.capability_id > $5)
    ORDER BY d.capability_id
    LIMIT $6
"#;

const INTERNAL_CATALOG_COUNT_SQL: &str = r#"
    SELECT COUNT(*)::BIGINT AS total
    FROM aip_capability_definitions d
    WHERE ($1::TEXT IS NULL OR d.capability_id = $1)
      AND ($2::TEXT IS NULL OR
           LOWER(d.capability_id || ' ' || COALESCE(d.record->'capability'->>'name', '') || ' ' ||
                 COALESCE(d.record->'capability'->>'description', '')) LIKE $2)
      AND EXISTS (
        SELECT 1
        FROM aip_connector_version_capabilities vc
        JOIN aip_connector_versions v ON v.version_id = vc.version_id
        JOIN aip_connector_types t ON t.type_id = v.type_id
        WHERE vc.capability_id = d.capability_id
          AND v.status = 'active' AND v.supply_chain_qualified = TRUE AND t.enabled = TRUE
          AND ($3::TEXT IS NULL OR EXISTS (
              SELECT 1 FROM aip_connector_version_profiles vp
              WHERE vp.version_id = v.version_id AND vp.profile_id = $3
          ))
      )
"#;

const INTERNAL_CATALOG_PAGE_SQL: &str = r#"
    SELECT d.capability_id,
           octet_length(d.record::TEXT)::BIGINT AS record_bytes,
           CASE WHEN octet_length(d.record::TEXT) <= $6 THEN d.record ELSE NULL END AS record
    FROM aip_capability_definitions d
    WHERE ($1::TEXT IS NULL OR d.capability_id = $1)
      AND ($2::TEXT IS NULL OR
           LOWER(d.capability_id || ' ' || COALESCE(d.record->'capability'->>'name', '') || ' ' ||
                 COALESCE(d.record->'capability'->>'description', '')) LIKE $2)
      AND EXISTS (
        SELECT 1
        FROM aip_connector_version_capabilities vc
        JOIN aip_connector_versions v ON v.version_id = vc.version_id
        JOIN aip_connector_types t ON t.type_id = v.type_id
        WHERE vc.capability_id = d.capability_id
          AND v.status = 'active' AND v.supply_chain_qualified = TRUE AND t.enabled = TRUE
          AND ($3::TEXT IS NULL OR EXISTS (
              SELECT 1 FROM aip_connector_version_profiles vp
              WHERE vp.version_id = v.version_id AND vp.profile_id = $3
          ))
      )
      AND ($4::TEXT IS NULL OR d.capability_id > $4)
    ORDER BY d.capability_id
    LIMIT $5
"#;

#[async_trait]
impl ActionTargetResolver for PostgresConnectorRegistry {
    async fn resolve(
        &self,
        request: RouteResolutionRequest,
    ) -> Result<RouteAssignment, RegistryError> {
        require_nonempty("route tenant id", &request.tenant_id)?;
        let mut transaction = self.data_pool.begin().await.map_err(storage_error)?;
        lock_action(&mut transaction, &request.action_id).await?;
        let existing = query::<Postgres>(
            "SELECT record, reserved FROM aip_route_assignments WHERE action_id = $1 FOR UPDATE",
        )
        .bind(request.action_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if let Some(row) = existing {
            let assignment: RouteAssignment = record(&row)?;
            if assignment.capability_id != request.capability_id
                || assignment.tenant_id != request.tenant_id
            {
                return Err(RegistryError::Conflict(format!(
                    "action `{}` already has a different route contract",
                    request.action_id
                )));
            }
            let reserved: bool = row.try_get("reserved").map_err(storage_error)?;
            if !reserved {
                let now = now_ms();
                let reservation_scopes = attempt_admission_scopes(&assignment.admission, true);
                reserve_admission_scopes(&mut transaction, &reservation_scopes).await?;
                let updated = query::<Postgres>(
                    r#"
                    UPDATE aip_connector_replicas
                    SET active_assignments = active_assignments + 1,
                        updated_at_ms = $2
                    WHERE replica_id = $1
                      AND status IN ('ready', 'draining')
                      AND lease_expires_at_ms > $2
                      AND active_assignments < capacity
                      AND circuit_open_until_ms <= $2
                      AND EXISTS (
                          SELECT 1
                          FROM aip_connector_instances i
                          JOIN aip_connector_versions v ON v.version_id = i.version_id
                          JOIN aip_connector_types t ON t.type_id = i.type_id
                          WHERE i.instance_id = aip_connector_replicas.instance_id
                            AND i.status = 'enabled'
                            AND v.version_id = $3
                            AND v.status = 'active'
                            AND v.supply_chain_qualified = TRUE
                            AND t.enabled = TRUE
                      )
                    "#,
                )
                .bind(assignment.replica_id.as_str())
                .bind(now)
                .bind(assignment.version_id.as_str())
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
                if updated.rows_affected() != 1 {
                    return Err(RegistryError::ReplicaUnavailable(assignment.instance_id));
                }
                query::<Postgres>(
                    r#"
                    UPDATE aip_route_assignments
                    SET reserved = TRUE,
                        last_settlement = NULL,
                        reservation_scopes = $2,
                        updated_at_ms = $3
                    WHERE action_id = $1
                    "#,
                )
                .bind(request.action_id.as_str())
                .bind(to_json(&reservation_scopes)?)
                .bind(now)
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
            }
            transaction.commit().await.map_err(storage_error)?;
            return Ok(assignment);
        }

        // Freeze the catalog view while selecting a new binding. Replica
        // heartbeats remain independent and are locked only for the selected row.
        let catalog_revision = read_catalog_revision(&mut transaction).await?;
        let first_binding = query::<Postgres>(
            r#"
            SELECT b.instance_id
            FROM aip_tenant_capability_bindings b
            JOIN aip_connector_instances i ON i.instance_id = b.instance_id
            JOIN aip_connector_versions v ON v.version_id = i.version_id
            JOIN aip_connector_types t ON t.type_id = i.type_id
            JOIN aip_connector_version_capabilities vc
              ON vc.version_id = v.version_id AND vc.capability_id = b.capability_id
            WHERE b.tenant_id = $1 AND b.capability_id = $2
              AND b.enabled = TRUE AND i.tenant_id = b.tenant_id
              AND i.status = 'enabled' AND v.status = 'active'
              AND v.supply_chain_qualified = TRUE AND t.enabled = TRUE
            ORDER BY b.priority, b.instance_id
            LIMIT 1
            "#,
        )
        .bind(&request.tenant_id)
        .bind(request.capability_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| RegistryError::BindingUnavailable {
            tenant_id: request.tenant_id.clone(),
            capability_id: request.capability_id.clone(),
        })?;
        let first_instance: String = first_binding
            .try_get("instance_id")
            .map_err(storage_error)?;
        let selected_at_ms = now_ms();
        let mut selected = None;
        for attempt in 0..=self.limits.max_route_lock_retries {
            selected = query::<Postgres>(
                r#"
            SELECT b.record AS binding_record,
                   i.record AS instance_record,
                   v.record AS version_record,
                   r.record AS replica_record,
                   r.active_assignments
            FROM aip_tenant_capability_bindings b
            JOIN aip_connector_instances i ON i.instance_id = b.instance_id
            JOIN aip_connector_versions v ON v.version_id = i.version_id
            JOIN aip_connector_types t ON t.type_id = i.type_id
            JOIN aip_connector_version_capabilities vc
              ON vc.version_id = v.version_id AND vc.capability_id = b.capability_id
            JOIN aip_connector_replicas r
              ON r.instance_id = i.instance_id AND r.version_id = v.version_id
            WHERE b.tenant_id = $1 AND b.capability_id = $2
              AND b.enabled = TRUE AND i.tenant_id = b.tenant_id
              AND i.status = 'enabled' AND v.status = 'active'
              AND v.supply_chain_qualified = TRUE AND t.enabled = TRUE
              AND r.status = 'ready' AND r.lease_expires_at_ms > $3
              AND r.active_assignments < r.capacity
              AND r.circuit_open_until_ms <= $3
              AND ($5::TEXT IS NULL OR r.capacity_class = $5)
              AND ($6::BOOLEAN = TRUE OR $7::TEXT IS NULL OR r.region = $7)
            ORDER BY b.priority,
                     CASE WHEN $7::TEXT IS NULL OR r.region = $7 THEN 0 ELSE 1 END,
                     CASE WHEN $8::TEXT IS NULL OR r.zone = $8 THEN 0 ELSE 1 END,
                     r.active_assignments,
                     hashtextextended(r.replica_id || $4, 0),
                     b.instance_id,
                     r.replica_id
            FOR UPDATE OF r SKIP LOCKED
            LIMIT 1
            "#,
            )
            .bind(&request.tenant_id)
            .bind(request.capability_id.as_str())
            .bind(selected_at_ms)
            .bind(request.action_id.as_str())
            .bind(request.topology.capacity_class.as_deref())
            .bind(request.topology.allow_cross_region)
            .bind(request.topology.region.as_deref())
            .bind(request.topology.zone.as_deref())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?;
            if selected.is_some() || attempt == self.limits.max_route_lock_retries {
                break;
            }
            if self.limits.route_lock_retry_ms == 0 {
                tokio::task::yield_now().await;
            } else {
                tokio::time::sleep(StdDuration::from_millis(self.limits.route_lock_retry_ms)).await;
            }
        }
        let selected = selected.ok_or_else(|| {
            RegistryError::ReplicaUnavailable(ConnectorInstanceId::trusted(first_instance))
        })?;
        let binding: CapabilityBinding = named_record(&selected, "binding_record")?;
        let instance: ConnectorInstance = named_record(&selected, "instance_record")?;
        let version: ConnectorVersion = named_record(&selected, "version_record")?;
        let mut replica: ConnectorReplica = named_record(&selected, "replica_record")?;
        replica.active_assignments = row_u32(&selected, "active_assignments")?;
        let admission =
            admission_for_route(&mut transaction, &binding, &instance, &version).await?;
        let reservation_scopes = attempt_admission_scopes(&admission, false);
        reserve_admission_scopes(&mut transaction, &reservation_scopes).await?;
        query::<Postgres>(
            r#"
            UPDATE aip_connector_replicas
            SET active_assignments = active_assignments + 1, updated_at_ms = $2
            WHERE replica_id = $1
            "#,
        )
        .bind(replica.id.as_str())
        .bind(selected_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        let assigned_at = OffsetDateTime::now_utc();
        let assignment = RouteAssignment {
            action_id: request.action_id,
            capability_id: request.capability_id,
            tenant_id: request.tenant_id,
            instance_id: instance.id,
            replica_id: replica.id,
            endpoint: replica.endpoint,
            peer_principal_id: replica.peer_principal_id,
            peer_principal_kind: replica.peer_principal_kind,
            peer_did: replica.peer_did,
            trust_domain: replica.trust_domain,
            transport_profile: replica.transport_profile,
            topology: replica.topology,
            version_id: version.id,
            manifest_digest: version.manifest_digest,
            catalog_revision,
            binding_policy_revision: binding.policy_revision,
            credential_revision_ref: binding.credential_revision_ref,
            quota_policy_ref: binding.quota_policy_ref,
            replica_health_revision: replica.health_revision,
            fence_token: format!("route_{}", Uuid::now_v7().simple()),
            assigned_at,
            admission,
        };
        let assignment_json = to_json(&assignment)?;
        let assigned_at_ms = datetime_ms(assigned_at)?;
        query::<Postgres>(
            r#"
            INSERT INTO aip_route_assignments
                (action_id, capability_id, tenant_id, instance_id, replica_id, version_id,
                 fence_token, reserved, last_settlement, reservation_scopes, record,
                 assigned_at_ms, updated_at_ms)
            VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, NULL, $8, $9, $10, $10)
            "#,
        )
        .bind(assignment.action_id.as_str())
        .bind(assignment.capability_id.as_str())
        .bind(&assignment.tenant_id)
        .bind(assignment.instance_id.as_str())
        .bind(assignment.replica_id.as_str())
        .bind(assignment.version_id.as_str())
        .bind(&assignment.fence_token)
        .bind(to_json(&reservation_scopes)?)
        .bind(assignment_json)
        .bind(assigned_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(assignment)
    }

    async fn assignment(
        &self,
        action_id: &ActionId,
    ) -> Result<Option<RouteAssignment>, RegistryError> {
        let row =
            query::<Postgres>("SELECT record FROM aip_route_assignments WHERE action_id = $1")
                .bind(action_id.as_str())
                .fetch_optional(&self.data_pool)
                .await
                .map_err(storage_error)?;
        row.map(|row| record(&row)).transpose()
    }

    async fn settle(
        &self,
        assignment: &RouteAssignment,
        settlement: RouteSettlement,
    ) -> Result<(), RegistryError> {
        let mut transaction = self.data_pool.begin().await.map_err(storage_error)?;
        lock_action(&mut transaction, &assignment.action_id).await?;
        let row = query::<Postgres>(
            r#"
            SELECT record, reserved, reservation_scopes FROM aip_route_assignments
            WHERE action_id = $1 FOR UPDATE
            "#,
        )
        .bind(assignment.action_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| RegistryError::NotFound(assignment.action_id.to_string()))?;
        let existing: RouteAssignment = record(&row)?;
        if existing != *assignment {
            return Err(RegistryError::FenceLost);
        }
        let reserved: bool = row.try_get("reserved").map_err(storage_error)?;
        if !reserved {
            transaction.commit().await.map_err(storage_error)?;
            return Ok(());
        }
        let reservation_scopes: Vec<AdmissionScopeReservation> =
            named_record(&row, "reservation_scopes")?;
        release_admission_scopes(&mut transaction, &reservation_scopes).await?;
        let now = now_ms();
        let route_update = query::<Postgres>(
            r#"
            UPDATE aip_route_assignments
            SET reserved = FALSE,
                last_settlement = $3,
                reservation_scopes = '[]'::jsonb,
                updated_at_ms = $4
            WHERE action_id = $1 AND fence_token = $2
            "#,
        )
        .bind(assignment.action_id.as_str())
        .bind(&assignment.fence_token)
        .bind(settlement_label(settlement))
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if route_update.rows_affected() != 1 {
            return Err(RegistryError::FenceLost);
        }
        let threshold = i64::from(assignment.admission.circuit_failure_threshold);
        let open_ms = u64_i64(
            assignment.admission.circuit_open_ms,
            "circuit open duration",
        )?;
        let replica_update = query::<Postgres>(
            r#"
            UPDATE aip_connector_replicas
            SET active_assignments = GREATEST(active_assignments - 1, 0),
                consecutive_failures = CASE
                    WHEN $3 = 'completed' THEN 0
                    WHEN $3 = 'outcome_unknown' AND $4 > 0
                        THEN consecutive_failures + 1
                    ELSE consecutive_failures
                END,
                circuit_open_until_ms = CASE
                    WHEN $3 = 'completed' THEN 0
                    WHEN $3 = 'outcome_unknown' AND $4 > 0
                         AND consecutive_failures + 1 >= $4
                        THEN GREATEST(circuit_open_until_ms, $2 + $5)
                    ELSE circuit_open_until_ms
                END,
                updated_at_ms = $2
            WHERE replica_id = $1
            "#,
        )
        .bind(assignment.replica_id.as_str())
        .bind(now)
        .bind(settlement_label(settlement))
        .bind(threshold)
        .bind(open_ms)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if replica_update.rows_affected() != 1 {
            return Err(RegistryError::FenceLost);
        }
        transaction.commit().await.map_err(storage_error)
    }
}

async fn lock_catalog_revision(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<CatalogRevision, RegistryError> {
    query::<Postgres>("SELECT pg_advisory_xact_lock(hashtext(current_database()), $1)")
        .bind(CATALOG_REVISION_ADVISORY_LOCK)
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)?;
    let row = query::<Postgres>(
        "SELECT revision FROM aip_connector_catalog_revision WHERE singleton = TRUE FOR UPDATE",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage_error)?;
    revision_from_row(&row)
}

async fn read_catalog_revision(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<CatalogRevision, RegistryError> {
    query::<Postgres>("SELECT pg_advisory_xact_lock_shared(hashtext(current_database()), $1)")
        .bind(CATALOG_REVISION_ADVISORY_LOCK)
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)?;
    let row = query::<Postgres>(
        "SELECT revision FROM aip_connector_catalog_revision WHERE singleton = TRUE",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage_error)?;
    revision_from_row(&row)
}

async fn advance_catalog_revision(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<CatalogRevision, RegistryError> {
    let row = query::<Postgres>(
        r#"
        UPDATE aip_connector_catalog_revision
        SET revision = revision + 1, published_at_ms = $1
        WHERE singleton = TRUE
        RETURNING revision
        "#,
    )
    .bind(now_ms())
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage_error)?;
    revision_from_row(&row)
}

async fn lock_action(
    transaction: &mut Transaction<'_, Postgres>,
    action_id: &ActionId,
) -> Result<(), RegistryError> {
    query::<Postgres>("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(action_id.as_str())
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    Ok(())
}

async fn admission_for_route(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &CapabilityBinding,
    instance: &ConnectorInstance,
    version: &ConnectorVersion,
) -> Result<AdmissionReservation, RegistryError> {
    let policy = match binding.quota_policy_ref.as_deref() {
        Some(policy_ref) => {
            let row = query::<Postgres>(
                "SELECT record FROM aip_connector_admission_policies WHERE policy_ref = $1",
            )
            .bind(policy_ref)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| RegistryError::NotFound(format!("admission policy `{policy_ref}`")))?;
            record(&row)?
        }
        None => AdmissionPolicy::fleet("quota:implicit-default"),
    };
    build_admission_reservation(
        binding.quota_policy_ref.clone(),
        &policy,
        binding,
        instance,
        version,
    )
}

async fn reserve_admission_scopes(
    transaction: &mut Transaction<'_, Postgres>,
    scopes: &[AdmissionScopeReservation],
) -> Result<(), RegistryError> {
    for scope in scopes {
        let limit = i64::from(scope.limit);
        query::<Postgres>(
            r#"
            INSERT INTO aip_connector_admission_counters
                (scope_kind, scope_key, active, updated_at_ms)
            VALUES ($1, $2, 0, $3)
            ON CONFLICT (scope_kind, scope_key) DO NOTHING
            "#,
        )
        .bind(admission_scope_label(scope.kind))
        .bind(&scope.key)
        .bind(now_ms())
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
        let reserved = query::<Postgres>(
            r#"
            UPDATE aip_connector_admission_counters
            SET active = active + 1, updated_at_ms = $4
            WHERE scope_kind = $1 AND scope_key = $2 AND active < $3
            RETURNING active
            "#,
        )
        .bind(admission_scope_label(scope.kind))
        .bind(&scope.key)
        .bind(limit)
        .bind(now_ms())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage_error)?;
        if reserved.is_none() {
            return Err(RegistryError::CapacityExceeded {
                scope: scope.kind,
                retry_after_ms: 100,
            });
        }
    }
    Ok(())
}

async fn release_admission_scopes(
    transaction: &mut Transaction<'_, Postgres>,
    scopes: &[AdmissionScopeReservation],
) -> Result<(), RegistryError> {
    for scope in scopes {
        let released = query::<Postgres>(
            r#"
            UPDATE aip_connector_admission_counters
            SET active = active - 1, updated_at_ms = $3
            WHERE scope_kind = $1 AND scope_key = $2 AND active > 0
            RETURNING active
            "#,
        )
        .bind(admission_scope_label(scope.kind))
        .bind(&scope.key)
        .bind(now_ms())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage_error)?;
        if released.is_none() {
            return Err(RegistryError::FenceLost);
        }
    }
    Ok(())
}

fn revision_from_row(row: &PgRow) -> Result<CatalogRevision, RegistryError> {
    let revision: i64 = row.try_get("revision").map_err(storage_error)?;
    let revision = u64::try_from(revision)
        .map_err(|_| RegistryError::Storage("catalog revision is negative".to_owned()))?;
    Ok(CatalogRevision(revision))
}

fn parse_catalog_cursor(
    cursor: Option<&str>,
    revision: CatalogRevision,
) -> Result<Option<CapabilityId>, RegistryError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let (cursor_revision, capability_id) = cursor
        .split_once(':')
        .ok_or_else(|| RegistryError::Invalid("invalid capability cursor".to_owned()))?;
    let cursor_revision = cursor_revision
        .parse::<u64>()
        .map_err(|_| RegistryError::Invalid("invalid capability cursor revision".to_owned()))?;
    if cursor_revision != revision.0 {
        return Err(RegistryError::StaleCursor);
    }
    CapabilityId::parse(capability_id)
        .map(Some)
        .map_err(|error| RegistryError::Invalid(error.to_string()))
}

fn record<T>(row: &PgRow) -> Result<T, RegistryError>
where
    T: DeserializeOwned,
{
    named_record(row, "record")
}

fn named_record<T>(row: &PgRow, column: &str) -> Result<T, RegistryError>
where
    T: DeserializeOwned,
{
    let value: Value = row.try_get(column).map_err(storage_error)?;
    serde_json::from_value(value)
        .map_err(|error| RegistryError::Storage(format!("invalid stored registry record: {error}")))
}

fn to_json(value: &impl Serialize) -> Result<Value, RegistryError> {
    serde_json::to_value(value)
        .map_err(|error| RegistryError::Invalid(format!("registry record is not JSON: {error}")))
}

fn row_u64(row: &PgRow, column: &str) -> Result<u64, RegistryError> {
    let value: i64 = row.try_get(column).map_err(storage_error)?;
    u64::try_from(value)
        .map_err(|_| RegistryError::Storage(format!("stored `{column}` is negative")))
}

fn row_u32(row: &PgRow, column: &str) -> Result<u32, RegistryError> {
    let value = row_u64(row, column)?;
    u32::try_from(value)
        .map_err(|_| RegistryError::Storage(format!("stored `{column}` exceeds u32")))
}

fn u64_i64(value: u64, label: &str) -> Result<i64, RegistryError> {
    i64::try_from(value).map_err(|_| RegistryError::Invalid(format!("{label} exceeds i64")))
}

fn datetime_ms(value: OffsetDateTime) -> Result<i64, RegistryError> {
    let milliseconds = value.unix_timestamp_nanos() / 1_000_000;
    i64::try_from(milliseconds)
        .map_err(|_| RegistryError::Invalid("timestamp exceeds i64 milliseconds".to_owned()))
}

fn datetime_from_ms(value: i64) -> Result<OffsetDateTime, RegistryError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(value).saturating_mul(1_000_000))
        .map_err(|error| RegistryError::Storage(format!("stored timestamp is invalid: {error}")))
}

fn now_ms() -> i64 {
    let milliseconds = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    i64::try_from(milliseconds).unwrap_or(i64::MAX)
}

fn same_replica_identity(left: &ConnectorReplica, right: &ConnectorReplica) -> bool {
    left.instance_id == right.instance_id
        && left.version_id == right.version_id
        && left.endpoint == right.endpoint
        && left.peer_principal_id == right.peer_principal_id
        && left.peer_principal_kind == right.peer_principal_kind
        && left.peer_did == right.peer_did
        && left.trust_domain == right.trust_domain
        && left.transport_profile == right.transport_profile
        && left.topology == right.topology
}

fn validate_admission_operation(operation: &AdmissionOperation) -> Result<(), AdmissionError> {
    if operation.package_id.trim().is_empty()
        || operation.package_id.len() > 256
        || operation.revision == 0
        || operation.signer_identity.trim().is_empty()
        || operation.signer_identity.len() > 512
        || !operation.package_digest.starts_with("sha256:")
        || operation.package_digest.len() != 71
        || !operation.package_digest[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || operation.claim_id.trim().is_empty()
        || operation.claim_id.len() > 256
        || operation.claim_expires_at <= operation.updated_at
    {
        return Err(AdmissionError::Invalid(
            "admission operation identifiers, revision, signer, or digest are invalid".to_owned(),
        ));
    }
    Ok(())
}

fn admission_journal_error(error: RegistryError) -> AdmissionError {
    AdmissionError::Journal(error.to_string())
}

fn admission_operation_state_label(state: AdmissionOperationState) -> &'static str {
    match state {
        AdmissionOperationState::Applying => "applying",
        AdmissionOperationState::Applied => "applied",
        AdmissionOperationState::Failed => "failed",
        AdmissionOperationState::Abandoned => "abandoned",
        AdmissionOperationState::Revoked => "revoked",
    }
}

fn require_nonempty(label: &str, value: &str) -> Result<(), RegistryError> {
    if value.trim().is_empty() {
        Err(RegistryError::Invalid(format!("{label} must be non-empty")))
    } else {
        Ok(())
    }
}

fn version_status_label(status: ConnectorVersionStatus) -> &'static str {
    match status {
        ConnectorVersionStatus::Candidate => "candidate",
        ConnectorVersionStatus::Admitted => "admitted",
        ConnectorVersionStatus::Active => "active",
        ConnectorVersionStatus::Revoked => "revoked",
    }
}

fn instance_status_label(status: ConnectorInstanceStatus) -> &'static str {
    match status {
        ConnectorInstanceStatus::Enabled => "enabled",
        ConnectorInstanceStatus::Disabled => "disabled",
    }
}

fn replica_status_label(status: ConnectorReplicaStatus) -> &'static str {
    match status {
        ConnectorReplicaStatus::Ready => "ready",
        ConnectorReplicaStatus::Draining => "draining",
        ConnectorReplicaStatus::Offline => "offline",
    }
}

fn replica_status_from_label(value: &str) -> Result<ConnectorReplicaStatus, RegistryError> {
    match value {
        "ready" => Ok(ConnectorReplicaStatus::Ready),
        "draining" => Ok(ConnectorReplicaStatus::Draining),
        "offline" => Ok(ConnectorReplicaStatus::Offline),
        _ => Err(RegistryError::Storage(format!(
            "stored connector replica status `{value}` is invalid"
        ))),
    }
}

fn admission_scope_label(scope: AdmissionScopeKind) -> &'static str {
    match scope {
        AdmissionScopeKind::Global => "global",
        AdmissionScopeKind::Tenant => "tenant",
        AdmissionScopeKind::ConnectorType => "connector_type",
        AdmissionScopeKind::Instance => "instance",
        AdmissionScopeKind::Binding => "binding",
        AdmissionScopeKind::TenantRetry => "tenant_retry",
    }
}

fn settlement_label(settlement: RouteSettlement) -> &'static str {
    match settlement {
        RouteSettlement::Completed => "completed",
        RouteSettlement::OutcomeUnknown => "outcome_unknown",
        RouteSettlement::Cancelled => "cancelled",
        RouteSettlement::LeaseExpired => "lease_expired",
    }
}

fn storage_error(error: impl std::fmt::Display) -> RegistryError {
    RegistryError::Storage(error.to_string())
}
