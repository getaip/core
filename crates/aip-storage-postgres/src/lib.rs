//! PostgreSQL runtime storage backend for production AIP gateways.
//!
//! The backend implements the runtime persistence traits with atomic queue
//! leasing, durable approvals, transaction records, idempotency cache, event
//! replay, lifecycle state, and delegation graph state. The schema intentionally
//! stores AIP domain records as JSONB so the wire model can evolve without
//! coupling migrations to every semantic-field addition.

#![forbid(unsafe_code)]

use aip_core::{
    ActionId, ActionResult, ActionResultStatus, ApprovalId, AuditEvent, BatchSettlement,
    CallbackDeliveryStatus, Conversation, DelegationId, DelegationRecord, DelegationStatus,
    ErrorCategory, Escalation, EscalationResolution, Event, EventStream, EventStreamRequest,
    ProtocolError, ReceiptChain, SessionId, SessionState, StreamChunk, TransactionId,
};
use aip_mcp_session::{
    CorrelationDirection, McpCorrelationRecord, McpCorrelationStore, McpSessionError,
};
use aip_runtime::{
    ActionLease, ActionQueue, ActionQueueBackend, ApprovalBackend, ApprovalDecisionApply,
    ApprovalRecord, ApprovalStatus, ApprovalStore, ApprovalTransitionLease,
    CallbackDeliveryBackend, CallbackDeliveryStateRecord, CallbackDeliveryStore, DeadLetterRecord,
    DelegationBackend, DelegationStore, EventAppendOutcome, EventLog, EventStore,
    IdempotencyBackend, IdempotencyRecord, IdempotencyReservation, IdempotencyReservationOutcome,
    IdempotencyStore, LifecycleBackend, LifecycleStore, MAX_EVENT_PAGE_BYTES, MAX_EVENT_PAGE_ROWS,
    MAX_EVENT_RECORD_BYTES, ProfileStateBackend, ProfileStateCasOutcome, ProfileStateEntry,
    ProfileStateStore, QueueAttemptOutcome, QueueCompletion, QueuedActionRecord,
    QueuedActionStatus, ReplayBackend, ReplayStore, RuntimeError, RuntimeMaintenanceBackend,
    RuntimeMaintenanceStore, RuntimeResult, RuntimeRetentionPolicy, RuntimeRetentionReport,
    RuntimeStoreDurability, RuntimeStores, SessionManager, SessionRecord, SessionStore,
    StorageHealthBackend, StorageHealthStore, StreamChunkRecordOutcome, TransactionBackend,
    TransactionRecord, TransactionStore, TransactionTransition, VerifiedApprovalDecision,
    classify_stream_chunk_record, validate_event_record_size, validate_queued_action_replacement,
};
use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx_core::{Error as SqlxError, query::query, row::Row, transaction::Transaction};
use sqlx_postgres::{PgPool, PgPoolOptions, PgRow, Postgres};
use std::sync::Arc;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// Error returned by PostgreSQL storage setup and explicit maintenance calls.
#[derive(Debug, Error)]
pub enum PostgresStorageError {
    /// SQLx reported a database error.
    #[error("postgres storage failed: {0}")]
    Sql(#[from] SqlxError),
    /// A stored JSON value could not be serialized or deserialized.
    #[error("postgres storage JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    /// A recorded migration does not match the immutable migration source.
    #[error("postgres schema migration failed: {0}")]
    Migration(String),
}

/// Result alias for PostgreSQL storage operations.
pub type PostgresStorageResult<T> = Result<T, PostgresStorageError>;

/// PostgreSQL implementation of all runtime storage traits.
#[derive(Clone, Debug)]
pub struct PostgresRuntimeStore {
    pool: PgPool,
}

#[derive(Clone, Copy)]
enum EventPageScope<'a> {
    Global,
    Tenant(&'a str),
    Action(&'a ActionId),
}

impl PostgresRuntimeStore {
    /// Creates a storage backend from an existing connection pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Opens a PostgreSQL pool and installs the AIP runtime schema.
    pub async fn connect(database_url: &str) -> PostgresStorageResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;
        let store = Self::new(pool);
        store.install_schema().await?;
        Ok(store)
    }

    /// Returns the underlying SQLx pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Installs or upgrades the runtime schema through immutable migrations.
    pub async fn install_schema(&self) -> PostgresStorageResult<()> {
        let schema = r#"
            CREATE TABLE IF NOT EXISTS aip_kv (
                bucket TEXT NOT NULL,
                key TEXT NOT NULL,
                value JSONB NOT NULL,
                updated_at_ms BIGINT NOT NULL,
                PRIMARY KEY (bucket, key)
            );

            CREATE TABLE IF NOT EXISTS aip_events (
                seq BIGSERIAL PRIMARY KEY,
                kind TEXT NOT NULL,
                event JSONB NOT NULL,
                occurred_at_ms BIGINT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS aip_idempotency (
                key TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                owner_action_id TEXT NOT NULL,
                reservation_id TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                reservation_expires_at_ms BIGINT,
                value JSONB,
                updated_at_ms BIGINT NOT NULL
            );

            ALTER TABLE aip_idempotency
                ADD COLUMN IF NOT EXISTS reservation_id TEXT NOT NULL DEFAULT '';

            ALTER TABLE aip_idempotency
                ADD COLUMN IF NOT EXISTS input_hash TEXT NOT NULL DEFAULT '';

            CREATE INDEX IF NOT EXISTS aip_idempotency_expiry_idx
                ON aip_idempotency (status, reservation_expires_at_ms);

            CREATE TABLE IF NOT EXISTS aip_replay_registry (
                message_id TEXT PRIMARY KEY,
                expires_at_ms BIGINT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS aip_replay_registry_expiry_idx
                ON aip_replay_registry (expires_at_ms);

            CREATE INDEX IF NOT EXISTS aip_events_kind_seq_idx
                ON aip_events (kind, seq);

            CREATE TABLE IF NOT EXISTS aip_queue (
                action_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                lease_expires_at_ms BIGINT,
                created_at_ms BIGINT NOT NULL,
                updated_at_ms BIGINT NOT NULL,
                record JSONB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS aip_queue_claim_idx
                ON aip_queue (status, lease_expires_at_ms, created_at_ms);

            CREATE INDEX IF NOT EXISTS aip_queue_tenant_idx
                ON aip_queue ((record #>> '{action,identity,tenant,id}'));

            CREATE INDEX IF NOT EXISTS aip_queue_external_account_idx
                ON aip_queue ((record #>> '{action,identity,external_account,id}'));

            CREATE TABLE IF NOT EXISTS aip_dead_letters (
                seq BIGSERIAL PRIMARY KEY,
                action_id TEXT NOT NULL,
                record JSONB NOT NULL,
                failed_at_ms BIGINT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS aip_kv_idempotency_tenant_idx
                ON aip_kv ((value #>> '{tenant_id}'))
                WHERE bucket = 'idempotency';

            CREATE INDEX IF NOT EXISTS aip_kv_idempotency_external_account_idx
                ON aip_kv ((value #>> '{external_account_id}'))
                WHERE bucket = 'idempotency';

            CREATE INDEX IF NOT EXISTS aip_kv_approval_tenant_idx
                ON aip_kv ((value #>> '{request,identity,tenant,id}'))
                WHERE bucket = 'approvals';

            CREATE INDEX IF NOT EXISTS aip_kv_approval_external_account_idx
                ON aip_kv ((value #>> '{request,identity,external_account,id}'))
                WHERE bucket = 'approvals';

            CREATE INDEX IF NOT EXISTS aip_kv_transaction_status_idx
                ON aip_kv ((value #>> '{status}'))
                WHERE bucket = 'transactions';

            CREATE INDEX IF NOT EXISTS aip_kv_transaction_tenant_idx
                ON aip_kv ((value #>> '{identity,tenant,id}'))
                WHERE bucket = 'transactions';

            CREATE INDEX IF NOT EXISTS aip_kv_transaction_external_account_idx
                ON aip_kv ((value #>> '{identity,external_account,id}'))
                WHERE bucket = 'transactions';

            CREATE INDEX IF NOT EXISTS aip_kv_callback_delivery_status_idx
                ON aip_kv ((value #>> '{view,status}'))
                WHERE bucket = 'callback_deliveries';

            CREATE INDEX IF NOT EXISTS aip_kv_callback_delivery_tenant_idx
                ON aip_kv ((value #>> '{view,tenant_id}'))
                WHERE bucket = 'callback_deliveries';

            CREATE INDEX IF NOT EXISTS aip_kv_callback_delivery_action_idx
                ON aip_kv ((value #>> '{view,action_id}'))
                WHERE bucket = 'callback_deliveries';
            "#;

        let production_read_models = r#"
            CREATE TABLE IF NOT EXISTS aip_approvals (
                approval_id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                status TEXT NOT NULL,
                tenant_id TEXT,
                external_account_id TEXT,
                expires_at_ms BIGINT,
                created_at_ms BIGINT NOT NULL,
                updated_at_ms BIGINT NOT NULL,
                record JSONB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS aip_approvals_pending_expiry_idx
                ON aip_approvals (status, expires_at_ms)
                WHERE status = 'pending';
            CREATE INDEX IF NOT EXISTS aip_approvals_action_idx
                ON aip_approvals (action_id);
            CREATE INDEX IF NOT EXISTS aip_approvals_tenant_idx
                ON aip_approvals (tenant_id, created_at_ms);

            CREATE TABLE IF NOT EXISTS aip_transactions (
                transaction_id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                plan_id TEXT,
                status TEXT NOT NULL,
                tenant_id TEXT,
                external_account_id TEXT,
                created_at_ms BIGINT NOT NULL,
                updated_at_ms BIGINT NOT NULL,
                record JSONB NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS aip_transactions_plan_id_idx
                ON aip_transactions (plan_id)
                WHERE plan_id IS NOT NULL;
            CREATE INDEX IF NOT EXISTS aip_transactions_action_idx
                ON aip_transactions (action_id, created_at_ms);
            CREATE INDEX IF NOT EXISTS aip_transactions_recovery_idx
                ON aip_transactions (status, updated_at_ms);
            CREATE INDEX IF NOT EXISTS aip_transactions_tenant_idx
                ON aip_transactions (tenant_id, created_at_ms);

            CREATE TABLE IF NOT EXISTS aip_callback_deliveries (
                delivery_id TEXT PRIMARY KEY,
                action_id TEXT,
                status TEXT NOT NULL,
                profile TEXT NOT NULL,
                target TEXT NOT NULL,
                tenant_id TEXT,
                next_attempt_at_ms BIGINT,
                lease_expires_at_ms BIGINT,
                updated_at_ms BIGINT NOT NULL,
                record JSONB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS aip_callback_delivery_recovery_idx
                ON aip_callback_deliveries (status, next_attempt_at_ms, lease_expires_at_ms);
            CREATE INDEX IF NOT EXISTS aip_callback_delivery_action_idx
                ON aip_callback_deliveries (action_id, updated_at_ms);
            CREATE INDEX IF NOT EXISTS aip_callback_delivery_tenant_idx
                ON aip_callback_deliveries (tenant_id, updated_at_ms);

            CREATE TABLE IF NOT EXISTS aip_events_v2 (
                seq BIGINT GENERATED BY DEFAULT AS IDENTITY,
                kind TEXT NOT NULL,
                action_id TEXT,
                tenant_id TEXT,
                event JSONB NOT NULL,
                occurred_at_ms BIGINT NOT NULL,
                PRIMARY KEY (seq)
            ) PARTITION BY HASH (seq);

            CREATE TABLE IF NOT EXISTS aip_events_v2_p0 PARTITION OF aip_events_v2
                FOR VALUES WITH (MODULUS 8, REMAINDER 0);
            CREATE TABLE IF NOT EXISTS aip_events_v2_p1 PARTITION OF aip_events_v2
                FOR VALUES WITH (MODULUS 8, REMAINDER 1);
            CREATE TABLE IF NOT EXISTS aip_events_v2_p2 PARTITION OF aip_events_v2
                FOR VALUES WITH (MODULUS 8, REMAINDER 2);
            CREATE TABLE IF NOT EXISTS aip_events_v2_p3 PARTITION OF aip_events_v2
                FOR VALUES WITH (MODULUS 8, REMAINDER 3);
            CREATE TABLE IF NOT EXISTS aip_events_v2_p4 PARTITION OF aip_events_v2
                FOR VALUES WITH (MODULUS 8, REMAINDER 4);
            CREATE TABLE IF NOT EXISTS aip_events_v2_p5 PARTITION OF aip_events_v2
                FOR VALUES WITH (MODULUS 8, REMAINDER 5);
            CREATE TABLE IF NOT EXISTS aip_events_v2_p6 PARTITION OF aip_events_v2
                FOR VALUES WITH (MODULUS 8, REMAINDER 6);
            CREATE TABLE IF NOT EXISTS aip_events_v2_p7 PARTITION OF aip_events_v2
                FOR VALUES WITH (MODULUS 8, REMAINDER 7);

            CREATE INDEX IF NOT EXISTS aip_events_v2_kind_seq_idx
                ON aip_events_v2 (kind, seq);
            CREATE INDEX IF NOT EXISTS aip_events_v2_action_seq_idx
                ON aip_events_v2 (action_id, seq)
                WHERE action_id IS NOT NULL;
            CREATE INDEX IF NOT EXISTS aip_events_v2_tenant_seq_idx
                ON aip_events_v2 (tenant_id, seq)
                WHERE tenant_id IS NOT NULL;
            CREATE INDEX IF NOT EXISTS aip_events_v2_occurred_idx
                ON aip_events_v2 (occurred_at_ms);

            INSERT INTO aip_events_v2 (seq, kind, action_id, tenant_id, event, occurred_at_ms)
            SELECT seq, kind, event ->> 'action_id',
                   event #>> '{data,identity,tenant,id}', event, occurred_at_ms
            FROM aip_events
            ON CONFLICT (seq) DO NOTHING;

            CREATE TABLE IF NOT EXISTS aip_outbox (
                outbox_id TEXT PRIMARY KEY,
                aggregate_type TEXT NOT NULL,
                aggregate_id TEXT NOT NULL,
                event_kind TEXT NOT NULL,
                payload JSONB NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                available_at_ms BIGINT NOT NULL,
                lease_id TEXT,
                lease_expires_at_ms BIGINT,
                created_at_ms BIGINT NOT NULL,
                published_at_ms BIGINT,
                last_error TEXT
            );

            CREATE INDEX IF NOT EXISTS aip_outbox_claim_idx
                ON aip_outbox (status, available_at_ms, lease_expires_at_ms, created_at_ms);
            CREATE INDEX IF NOT EXISTS aip_outbox_aggregate_idx
                ON aip_outbox (aggregate_type, aggregate_id, created_at_ms);

            CREATE TABLE IF NOT EXISTS aip_runtime_retention_policy (
                policy_id SMALLINT PRIMARY KEY CHECK (policy_id = 1),
                event_retention_ms BIGINT NOT NULL,
                dead_letter_retention_ms BIGINT NOT NULL,
                callback_retention_ms BIGINT NOT NULL,
                replay_retention_ms BIGINT NOT NULL,
                updated_at_ms BIGINT NOT NULL
            );

            INSERT INTO aip_runtime_retention_policy (
                policy_id, event_retention_ms, dead_letter_retention_ms,
                callback_retention_ms, replay_retention_ms, updated_at_ms
            ) VALUES (1, 2592000000, 7776000000, 2592000000, 86400000, 0)
            ON CONFLICT (policy_id) DO NOTHING;

            INSERT INTO aip_approvals (
                approval_id, action_id, capability_id, status, tenant_id,
                external_account_id, expires_at_ms, created_at_ms, updated_at_ms, record
            )
            SELECT key, value #>> '{request,action_id}', value #>> '{request,capability_id}',
                   value #>> '{status}', value #>> '{request,identity,tenant,id}',
                   value #>> '{request,identity,external_account,id}', NULL,
                   updated_at_ms, updated_at_ms, value
            FROM aip_kv WHERE bucket = 'approvals'
            ON CONFLICT (approval_id) DO NOTHING;

            INSERT INTO aip_transactions (
                transaction_id, action_id, capability_id, plan_id, status, tenant_id,
                external_account_id, created_at_ms, updated_at_ms, record
            )
            SELECT key, value #>> '{action_id}', value #>> '{capability_id}',
                   COALESCE(value #>> '{plan,plan_id}', value #>> '{transaction,plan_id}'),
                   value #>> '{status}', value #>> '{identity,tenant,id}',
                   value #>> '{identity,external_account,id}', updated_at_ms, updated_at_ms, value
            FROM aip_kv WHERE bucket = 'transactions'
            ON CONFLICT (transaction_id) DO NOTHING;

            INSERT INTO aip_callback_deliveries (
                delivery_id, action_id, status, profile, target, tenant_id,
                next_attempt_at_ms, lease_expires_at_ms, updated_at_ms, record
            )
            SELECT key, value #>> '{view,action_id}', value #>> '{view,status}',
                   value #>> '{view,profile}', value #>> '{view,target}',
                   value #>> '{view,tenant_id}', NULL, NULL, updated_at_ms, value
            FROM aip_kv WHERE bucket = 'callback_deliveries'
            ON CONFLICT (delivery_id) DO NOTHING;
            "#;

        let operational_hardening = r#"
            ALTER TABLE aip_events_v2 ADD COLUMN IF NOT EXISTS event_id TEXT;
            UPDATE aip_events_v2 SET event_id = event ->> 'id' WHERE event_id IS NULL;
            ALTER TABLE aip_events_v2 ALTER COLUMN event_id SET NOT NULL;
            CREATE INDEX IF NOT EXISTS aip_events_v2_event_id_idx
                ON aip_events_v2 (event_id);

            CREATE TABLE IF NOT EXISTS aip_event_registry (
                event_id TEXT PRIMARY KEY,
                seq BIGINT NOT NULL,
                created_at_ms BIGINT NOT NULL
            );

            INSERT INTO aip_event_registry (event_id, seq, created_at_ms)
            SELECT event_id, seq, occurred_at_ms FROM aip_events_v2
            ON CONFLICT (event_id) DO NOTHING;
            "#;

        let compatibility_profile_state = r#"
            CREATE TABLE IF NOT EXISTS aip_profile_state (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                revision BIGINT NOT NULL CHECK (revision > 0),
                value JSONB NOT NULL,
                updated_at_ms BIGINT NOT NULL,
                PRIMARY KEY (namespace, key)
            );

            CREATE INDEX IF NOT EXISTS aip_profile_state_namespace_key_idx
                ON aip_profile_state (namespace, key);
            CREATE INDEX IF NOT EXISTS aip_profile_state_updated_idx
                ON aip_profile_state (updated_at_ms);
            "#;

        let mcp_correlations = r#"
            CREATE TABLE IF NOT EXISTS aip_mcp_correlations (
                session_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                request_id TEXT NOT NULL,
                expires_at_ms BIGINT NOT NULL,
                terminal BOOLEAN NOT NULL DEFAULT FALSE,
                revision BIGINT NOT NULL CHECK (revision >= 0),
                record JSONB NOT NULL,
                updated_at_ms BIGINT NOT NULL,
                PRIMARY KEY (session_id, direction, request_id),
                CHECK (direction IN ('inbound', 'outbound'))
            );

            CREATE INDEX IF NOT EXISTS aip_mcp_correlations_expiry_idx
                ON aip_mcp_correlations (terminal, expires_at_ms);
            "#;

        let event_sequence_reconciliation = r#"
            LOCK TABLE aip_events_v2 IN ACCESS EXCLUSIVE MODE;

            SELECT setval(
                pg_get_serial_sequence('aip_events_v2', 'seq'),
                GREATEST(
                    COALESCE((SELECT MAX(seq) FROM aip_events_v2), 0),
                    nextval(pg_get_serial_sequence('aip_events_v2', 'seq'))
                ),
                true
            )
            "#;

        // Serialize schema installation across every gateway that shares this
        // database. PostgreSQL's `IF NOT EXISTS` is not sufficient when two
        // sessions concurrently create a table because both can race while
        // creating the table's implicit composite type. A transaction-scoped
        // advisory lock is automatically released on commit or rollback, so a
        // failed migration cannot leak a session lock back into the pool.
        const AIP_SCHEMA_MIGRATION_LOCK: i64 = 0x4149_505f_4d49_4752;
        let mut transaction = self.pool.begin().await?;
        query::<Postgres>("SELECT pg_advisory_xact_lock($1)")
            .bind(AIP_SCHEMA_MIGRATION_LOCK)
            .execute(&mut *transaction)
            .await?;

        query::<Postgres>(
            r#"
            CREATE TABLE IF NOT EXISTS aip_schema_migrations (
                version BIGINT PRIMARY KEY,
                name TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at_ms BIGINT NOT NULL
            )
            "#,
        )
        .execute(&mut *transaction)
        .await?;

        for (version, name, sql) in [
            (1_i64, "initial_runtime_schema", schema),
            (2_i64, "production_read_models", production_read_models),
            (3_i64, "operational_hardening", operational_hardening),
            (
                4_i64,
                "compatibility_profile_state",
                compatibility_profile_state,
            ),
            (5_i64, "mcp_correlations", mcp_correlations),
            (
                6_i64,
                "event_sequence_reconciliation",
                event_sequence_reconciliation,
            ),
        ] {
            let checksum = format!("{:x}", Sha256::digest(sql.as_bytes()));
            let applied = query::<Postgres>(
                "SELECT checksum FROM aip_schema_migrations WHERE version = $1 FOR UPDATE",
            )
            .bind(version)
            .fetch_optional(&mut *transaction)
            .await?;
            if let Some(row) = applied {
                let recorded: String = row.try_get("checksum")?;
                if recorded != checksum {
                    return Err(PostgresStorageError::Migration(format!(
                        "migration {version} ({name}) checksum changed"
                    )));
                }
                continue;
            }
            for statement in sql
                .split(';')
                .map(str::trim)
                .filter(|statement| !statement.is_empty())
            {
                query::<Postgres>(statement)
                    .execute(&mut *transaction)
                    .await?;
            }
            query::<Postgres>(
                r#"
                INSERT INTO aip_schema_migrations (version, name, checksum, applied_at_ms)
                VALUES ($1, $2, $3, $4)
                "#,
            )
            .bind(version)
            .bind(name)
            .bind(checksum)
            .bind(now_ms())
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Builds a complete [`RuntimeStores`] value backed by this PostgreSQL pool.
    #[must_use]
    pub fn runtime_stores(self) -> RuntimeStores {
        let store = Arc::new(self);
        RuntimeStores {
            durability: RuntimeStoreDurability::DurableShared,
            storage_health: StorageHealthStore::new(store.clone()),
            maintenance: RuntimeMaintenanceStore::new(store.clone()),
            replay: ReplayStore::new(store.clone()),
            profile_state: ProfileStateStore::new(store.clone()),
            sessions: SessionManager::new(store.clone()),
            idempotency: IdempotencyStore::new(store.clone()),
            events: EventLog::new(store.clone()),
            lifecycle: LifecycleStore::new(store.clone()),
            delegations: DelegationStore::new(store.clone()),
            approvals: ApprovalStore::new(store.clone()),
            transactions: TransactionStore::new(store.clone()),
            action_queue: ActionQueue::new(store.clone()),
            callback_deliveries: CallbackDeliveryStore::new(store),
        }
    }

    async fn upsert_value<T>(&self, bucket: &str, key: &str, value: &T) -> PostgresStorageResult<()>
    where
        T: Serialize + Sync,
    {
        query::<Postgres>(
            r#"
            INSERT INTO aip_kv (bucket, key, value, updated_at_ms)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (bucket, key)
            DO UPDATE SET value = EXCLUDED.value, updated_at_ms = EXCLUDED.updated_at_ms
            "#,
        )
        .bind(bucket)
        .bind(key)
        .bind(serde_json::to_value(value)?)
        .bind(now_ms())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_value<T>(&self, bucket: &str, key: &str) -> PostgresStorageResult<Option<T>>
    where
        T: DeserializeOwned,
    {
        let row = query::<Postgres>(
            r#"
            SELECT value
            FROM aip_kv
            WHERE bucket = $1 AND key = $2
            "#,
        )
        .bind(bucket)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| decode_value(row.try_get("value")?))
            .transpose()
    }

    async fn values<T>(&self, bucket: &str) -> PostgresStorageResult<Vec<T>>
    where
        T: DeserializeOwned,
    {
        let rows = query::<Postgres>(
            r#"
            SELECT value
            FROM aip_kv
            WHERE bucket = $1
            ORDER BY key
            "#,
        )
        .bind(bucket)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| decode_value(row.try_get("value")?))
            .collect()
    }

    async fn enqueue_approval_transition(
        transaction: &mut Transaction<'_, Postgres>,
        record: &ApprovalRecord,
    ) -> RuntimeResult<()> {
        let outbox_id = approval_outbox_id(&record.request.id);
        query::<Postgres>(
            r#"
            INSERT INTO aip_outbox (
                outbox_id, aggregate_type, aggregate_id, event_kind, payload,
                status, attempts, available_at_ms, created_at_ms
            ) VALUES ($1, 'approval', $2, 'aip.approval.transition', $3,
                      'pending', 0, $4, $4)
            ON CONFLICT (outbox_id) DO NOTHING
            "#,
        )
        .bind(outbox_id)
        .bind(record.request.id.as_str())
        .bind(serde_json::to_value(record).map_err(postgres_runtime_error)?)
        .bind(now_ms())
        .execute(&mut **transaction)
        .await
        .map_err(postgres_runtime_error)?;
        Ok(())
    }
}

#[async_trait]
impl McpCorrelationStore for PostgresRuntimeStore {
    async fn create(&self, record: McpCorrelationRecord) -> Result<(), McpSessionError> {
        let direction = correlation_direction_label(record.direction);
        let result = query::<Postgres>(
            r#"
            INSERT INTO aip_mcp_correlations (
                session_id, direction, request_id, expires_at_ms, terminal,
                revision, record, updated_at_ms
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (session_id, direction, request_id)
            DO UPDATE SET
                expires_at_ms = EXCLUDED.expires_at_ms,
                terminal = EXCLUDED.terminal,
                revision = EXCLUDED.revision,
                record = EXCLUDED.record,
                updated_at_ms = EXCLUDED.updated_at_ms
            WHERE aip_mcp_correlations.terminal
               OR aip_mcp_correlations.expires_at_ms <= $8
            "#,
        )
        .bind(&record.session_id)
        .bind(direction)
        .bind(&record.request_id)
        .bind(timestamp_ms(record.expires_at))
        .bind(record.response.is_some())
        .bind(i64::try_from(record.revision).unwrap_or(i64::MAX))
        .bind(
            serde_json::to_value(&record)
                .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?,
        )
        .bind(now_ms())
        .execute(&self.pool)
        .await
        .map_err(mcp_storage_error)?;
        if result.rows_affected() != 1 {
            return Err(McpSessionError::DuplicateRequestId(record.request_id));
        }
        Ok(())
    }

    async fn settle(
        &self,
        session_id: &str,
        request_id: &str,
        direction: CorrelationDirection,
        response: aip_profile_mcp::JsonRpcResponse,
    ) -> Result<(), McpSessionError> {
        let mut transaction = self.pool.begin().await.map_err(mcp_storage_error)?;
        let row = query::<Postgres>(
            r#"
            SELECT record
            FROM aip_mcp_correlations
            WHERE session_id = $1 AND direction = $2 AND request_id = $3
            FOR UPDATE
            "#,
        )
        .bind(session_id)
        .bind(correlation_direction_label(direction))
        .bind(request_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(mcp_storage_error)?
        .ok_or_else(|| {
            McpSessionError::Dispatcher(format!("response for unknown request id `{request_id}`"))
        })?;
        let mut record: McpCorrelationRecord =
            serde_json::from_value(row.try_get("record").map_err(mcp_storage_error)?)
                .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
        if record.response.is_some() {
            return Err(McpSessionError::DuplicateRequestId(request_id.to_owned()));
        }
        record.response = Some(response);
        record.revision = record.revision.saturating_add(1);
        query::<Postgres>(
            r#"
            UPDATE aip_mcp_correlations
            SET terminal = TRUE, revision = $4, record = $5, updated_at_ms = $6
            WHERE session_id = $1 AND direction = $2 AND request_id = $3
            "#,
        )
        .bind(session_id)
        .bind(correlation_direction_label(direction))
        .bind(request_id)
        .bind(i64::try_from(record.revision).unwrap_or(i64::MAX))
        .bind(
            serde_json::to_value(&record)
                .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?,
        )
        .bind(now_ms())
        .execute(&mut *transaction)
        .await
        .map_err(mcp_storage_error)?;
        transaction.commit().await.map_err(mcp_storage_error)
    }

    async fn get(
        &self,
        session_id: &str,
        request_id: &str,
        direction: CorrelationDirection,
    ) -> Result<Option<McpCorrelationRecord>, McpSessionError> {
        let row = query::<Postgres>(
            r#"
            SELECT record
            FROM aip_mcp_correlations
            WHERE session_id = $1 AND direction = $2 AND request_id = $3
            "#,
        )
        .bind(session_id)
        .bind(correlation_direction_label(direction))
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(mcp_storage_error)?;
        row.map(|row| {
            let value: Value = row.try_get("record").map_err(mcp_storage_error)?;
            serde_json::from_value(value)
                .map_err(|error| McpSessionError::Dispatcher(error.to_string()))
        })
        .transpose()
    }

    async fn prune(&self, now: OffsetDateTime) -> Result<u64, McpSessionError> {
        let result = query::<Postgres>(
            r#"
            DELETE FROM aip_mcp_correlations
            WHERE terminal AND expires_at_ms <= $1
            "#,
        )
        .bind(timestamp_ms(now))
        .execute(&self.pool)
        .await
        .map_err(mcp_storage_error)?;
        Ok(result.rows_affected())
    }
}

const fn correlation_direction_label(direction: CorrelationDirection) -> &'static str {
    match direction {
        CorrelationDirection::Outbound => "outbound",
        CorrelationDirection::Inbound => "inbound",
    }
}

fn mcp_storage_error(error: SqlxError) -> McpSessionError {
    McpSessionError::Dispatcher(format!(
        "PostgreSQL MCP correlation storage failed: {error}"
    ))
}

#[async_trait]
impl ReplayBackend for PostgresRuntimeStore {
    async fn claim(&self, message_id: &str, expires_at: OffsetDateTime) -> RuntimeResult<bool> {
        let acquired = query::<Postgres>(
            r#"
            INSERT INTO aip_replay_registry (message_id, expires_at_ms)
            VALUES ($1, $2)
            ON CONFLICT (message_id) DO UPDATE
            SET expires_at_ms = EXCLUDED.expires_at_ms
            WHERE aip_replay_registry.expires_at_ms <= $3
            "#,
        )
        .bind(message_id)
        .bind(timestamp_ms(expires_at))
        .bind(now_ms())
        .execute(&self.pool)
        .await
        .map_err(postgres_runtime_error)?
        .rows_affected()
            == 1;
        if acquired {
            query::<Postgres>(
                "DELETE FROM aip_replay_registry WHERE expires_at_ms <= $1 AND message_id <> $2",
            )
            .bind(now_ms())
            .bind(message_id)
            .execute(&self.pool)
            .await
            .map_err(postgres_runtime_error)?;
        }
        Ok(acquired)
    }
}

#[async_trait]
impl ProfileStateBackend for PostgresRuntimeStore {
    async fn compare_and_set(
        &self,
        namespace: &str,
        key: &str,
        expected_revision: Option<u64>,
        value: Value,
    ) -> RuntimeResult<ProfileStateCasOutcome> {
        let expected_revision_i64 = expected_revision
            .map(i64::try_from)
            .transpose()
            .map_err(|_| RuntimeError::Storage("profile state revision exceeds i64".to_owned()))?;
        let next_revision = expected_revision_i64.unwrap_or(0).saturating_add(1);
        let updated_at_ms = now_ms();
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let applied = if let Some(expected_revision) = expected_revision_i64 {
            query::<Postgres>(
                r#"
                UPDATE aip_profile_state
                SET revision = $4, value = $5, updated_at_ms = $6
                WHERE namespace = $1 AND key = $2 AND revision = $3
                RETURNING namespace, key, revision, value, updated_at_ms
                "#,
            )
            .bind(namespace)
            .bind(key)
            .bind(expected_revision)
            .bind(next_revision)
            .bind(value)
            .bind(updated_at_ms)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(postgres_runtime_error)?
        } else {
            query::<Postgres>(
                r#"
                INSERT INTO aip_profile_state (namespace, key, revision, value, updated_at_ms)
                VALUES ($1, $2, 1, $3, $4)
                ON CONFLICT (namespace, key) DO NOTHING
                RETURNING namespace, key, revision, value, updated_at_ms
                "#,
            )
            .bind(namespace)
            .bind(key)
            .bind(value)
            .bind(updated_at_ms)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(postgres_runtime_error)?
        };
        if let Some(row) = applied {
            let entry = profile_state_entry_from_row(&row)?;
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(ProfileStateCasOutcome::Applied(entry));
        }
        let current = query::<Postgres>(
            r#"
            SELECT namespace, key, revision, value, updated_at_ms
            FROM aip_profile_state
            WHERE namespace = $1 AND key = $2
            "#,
        )
        .bind(namespace)
        .bind(key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?
        .map(|row| profile_state_entry_from_row(&row))
        .transpose()?;
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(ProfileStateCasOutcome::Conflict(current))
    }

    async fn get(&self, namespace: &str, key: &str) -> RuntimeResult<Option<ProfileStateEntry>> {
        query::<Postgres>(
            r#"
            SELECT namespace, key, revision, value, updated_at_ms
            FROM aip_profile_state
            WHERE namespace = $1 AND key = $2
            "#,
        )
        .bind(namespace)
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(postgres_runtime_error)?
        .map(|row| profile_state_entry_from_row(&row))
        .transpose()
    }

    async fn list(
        &self,
        namespace: &str,
        key_prefix: Option<&str>,
    ) -> RuntimeResult<Vec<ProfileStateEntry>> {
        let rows = query::<Postgres>(
            r#"
            SELECT namespace, key, revision, value, updated_at_ms
            FROM aip_profile_state
            WHERE namespace = $1
            ORDER BY key ASC
            "#,
        )
        .bind(namespace)
        .fetch_all(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        rows.iter()
            .map(profile_state_entry_from_row)
            .filter(|entry| {
                entry.as_ref().map_or(true, |entry| {
                    key_prefix.is_none_or(|prefix| entry.key.starts_with(prefix))
                })
            })
            .collect()
    }

    async fn delete(
        &self,
        namespace: &str,
        key: &str,
        expected_revision: u64,
    ) -> RuntimeResult<bool> {
        let expected_revision = i64::try_from(expected_revision)
            .map_err(|_| RuntimeError::Storage("profile state revision exceeds i64".to_owned()))?;
        let deleted = query::<Postgres>(
            r#"
            DELETE FROM aip_profile_state
            WHERE namespace = $1 AND key = $2 AND revision = $3
            "#,
        )
        .bind(namespace)
        .bind(key)
        .bind(expected_revision)
        .execute(&self.pool)
        .await
        .map_err(postgres_runtime_error)?
        .rows_affected();
        Ok(deleted == 1)
    }
}

#[async_trait]
impl StorageHealthBackend for PostgresRuntimeStore {
    async fn check(&self) -> RuntimeResult<()> {
        query::<Postgres>("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(postgres_runtime_error)?;
        Ok(())
    }
}

#[async_trait]
impl RuntimeMaintenanceBackend for PostgresRuntimeStore {
    async fn apply_retention(
        &self,
        policy: RuntimeRetentionPolicy,
        now: OffsetDateTime,
    ) -> RuntimeResult<RuntimeRetentionReport> {
        let now_ms = timestamp_ms(now);
        let cutoff =
            |retention_ms: u64| now_ms.saturating_sub(retention_ms.min(i64::MAX as u64) as i64);
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        query::<Postgres>(
            r#"
            UPDATE aip_runtime_retention_policy
            SET event_retention_ms = $1,
                dead_letter_retention_ms = $2,
                callback_retention_ms = $3,
                replay_retention_ms = $4,
                updated_at_ms = $5
            WHERE policy_id = 1
            "#,
        )
        .bind(policy.event_retention_ms.min(i64::MAX as u64) as i64)
        .bind(policy.dead_letter_retention_ms.min(i64::MAX as u64) as i64)
        .bind(policy.callback_retention_ms.min(i64::MAX as u64) as i64)
        .bind(policy.outbox_retention_ms.min(i64::MAX as u64) as i64)
        .bind(now_ms)
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;

        let events_deleted =
            query::<Postgres>("DELETE FROM aip_events_v2 WHERE occurred_at_ms < $1")
                .bind(cutoff(policy.event_retention_ms))
                .execute(&mut *transaction)
                .await
                .map_err(postgres_runtime_error)?
                .rows_affected();
        query::<Postgres>(
            r#"
            DELETE FROM aip_event_registry registry
            WHERE NOT EXISTS (
                SELECT 1 FROM aip_events_v2 events WHERE events.event_id = registry.event_id
            )
            "#,
        )
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        let replay_claims_deleted =
            query::<Postgres>("DELETE FROM aip_replay_registry WHERE expires_at_ms <= $1")
                .bind(now_ms)
                .execute(&mut *transaction)
                .await
                .map_err(postgres_runtime_error)?
                .rows_affected();
        let dead_letters_deleted =
            query::<Postgres>("DELETE FROM aip_dead_letters WHERE failed_at_ms < $1")
                .bind(cutoff(policy.dead_letter_retention_ms))
                .execute(&mut *transaction)
                .await
                .map_err(postgres_runtime_error)?
                .rows_affected();
        let callback_deliveries_deleted = query::<Postgres>(
            r#"
            DELETE FROM aip_callback_deliveries
            WHERE status IN ('delivered', 'dead_lettered') AND updated_at_ms < $1
            "#,
        )
        .bind(cutoff(policy.callback_retention_ms))
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?
        .rows_affected();
        let outbox_records_deleted = query::<Postgres>(
            r#"
            DELETE FROM aip_outbox
            WHERE status = 'published' AND published_at_ms < $1
            "#,
        )
        .bind(cutoff(policy.outbox_retention_ms))
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?
        .rows_affected();
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(RuntimeRetentionReport {
            events_deleted,
            replay_claims_deleted,
            dead_letters_deleted,
            callback_deliveries_deleted,
            outbox_records_deleted,
        })
    }
}

#[async_trait]
impl SessionStore for PostgresRuntimeStore {
    async fn insert(&self, record: SessionRecord) -> RuntimeResult<()> {
        let inserted = query::<Postgres>(
            r#"
            INSERT INTO aip_kv (bucket, key, value, updated_at_ms)
            VALUES ('sessions', $1, $2, $3)
            ON CONFLICT (bucket, key) DO NOTHING
            "#,
        )
        .bind(record.session.id.as_str())
        .bind(serde_json::to_value(&record).map_err(postgres_runtime_error)?)
        .bind(now_ms())
        .execute(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        if inserted.rows_affected() != 1 {
            return Err(RuntimeError::Storage(format!(
                "session `{}` already exists",
                record.session.id
            )));
        }
        Ok(())
    }

    async fn get(&self, id: &SessionId) -> RuntimeResult<Option<SessionRecord>> {
        self.get_value("sessions", id.as_str())
            .await
            .map_err(|error| RuntimeError::Storage(error.to_string()))
    }

    async fn list(&self) -> RuntimeResult<Vec<SessionRecord>> {
        self.values("sessions")
            .await
            .map_err(|error| RuntimeError::Storage(error.to_string()))
    }

    async fn transition(&self, id: &SessionId, next: SessionState) -> RuntimeResult<SessionRecord> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| RuntimeError::Handler(error.to_string()))?;
        let row = query::<Postgres>(
            r#"
            SELECT value
            FROM aip_kv
            WHERE bucket = 'sessions' AND key = $1
            FOR UPDATE
            "#,
        )
        .bind(id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| RuntimeError::Handler(error.to_string()))?;
        let Some(row) = row else {
            return Err(RuntimeError::SessionNotFound(id.to_string()));
        };
        let mut record: SessionRecord = decode_value(
            row.try_get("value")
                .map_err(|error| RuntimeError::Handler(error.to_string()))?,
        )
        .map_err(|error| RuntimeError::Handler(error.to_string()))?;
        if !record.session.state.can_transition_to(next) {
            return Err(RuntimeError::Handler(format!(
                "invalid transition from {} to {}",
                record.session.state.as_str(),
                next.as_str()
            )));
        }
        record.session.state = next;
        record.updated_at = OffsetDateTime::now_utc();
        query::<Postgres>(
            r#"
            UPDATE aip_kv
            SET value = $2, updated_at_ms = $3
            WHERE bucket = 'sessions' AND key = $1
            "#,
        )
        .bind(id.as_str())
        .bind(
            serde_json::to_value(&record)
                .map_err(|error| RuntimeError::Handler(error.to_string()))?,
        )
        .bind(now_ms())
        .execute(&mut *transaction)
        .await
        .map_err(|error| RuntimeError::Handler(error.to_string()))?;
        transaction
            .commit()
            .await
            .map_err(|error| RuntimeError::Handler(error.to_string()))?;
        Ok(record)
    }

    async fn rotate_resume_token(
        &self,
        id: &SessionId,
        owner: &aip_core::PrincipalId,
        presented_hash: &str,
        replacement_hash: String,
        replacement_expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> RuntimeResult<SessionRecord> {
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let row = query::<Postgres>(
            "SELECT value FROM aip_kv WHERE bucket = 'sessions' AND key = $1 FOR UPDATE",
        )
        .bind(id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?
        .ok_or_else(|| RuntimeError::SessionNotFound(id.to_string()))?;
        let mut record: SessionRecord =
            decode_value(row.try_get("value").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)?;
        record.validate_resume(owner, presented_hash, now)?;
        let previous_revision = record.token_revision;
        record.resume_token_hash = replacement_hash;
        record.resume_token_expires_at = replacement_expires_at;
        record.token_revision = record.token_revision.saturating_add(1);
        record.updated_at = now;
        let updated = query::<Postgres>(
            r#"
            UPDATE aip_kv SET value = $2, updated_at_ms = $3
            WHERE bucket = 'sessions' AND key = $1
              AND COALESCE((value->>'token_revision')::bigint, 0) = $4
            "#,
        )
        .bind(id.as_str())
        .bind(serde_json::to_value(&record).map_err(postgres_runtime_error)?)
        .bind(timestamp_ms(now))
        .bind(i64::try_from(previous_revision).unwrap_or(i64::MAX))
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        if updated.rows_affected() != 1 {
            return Err(RuntimeError::Storage(format!(
                "session `{id}` lost resume-token rotation fence"
            )));
        }
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(record)
    }

    async fn revoke_resume_token(
        &self,
        id: &SessionId,
        owner: &aip_core::PrincipalId,
    ) -> RuntimeResult<SessionRecord> {
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let row = query::<Postgres>(
            "SELECT value FROM aip_kv WHERE bucket = 'sessions' AND key = $1 FOR UPDATE",
        )
        .bind(id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?
        .ok_or_else(|| RuntimeError::SessionNotFound(id.to_string()))?;
        let mut record: SessionRecord =
            decode_value(row.try_get("value").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)?;
        if &record.owner != owner {
            return Err(RuntimeError::Authorization(
                "session owner does not match authenticated principal".to_owned(),
            ));
        }
        record.resume_revoked = true;
        record.token_revision = record.token_revision.saturating_add(1);
        record.updated_at = OffsetDateTime::now_utc();
        query::<Postgres>(
            "UPDATE aip_kv SET value = $2, updated_at_ms = $3 WHERE bucket = 'sessions' AND key = $1",
        )
        .bind(id.as_str())
        .bind(serde_json::to_value(&record).map_err(postgres_runtime_error)?)
        .bind(timestamp_ms(record.updated_at))
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(record)
    }
}

#[async_trait]
impl IdempotencyBackend for PostgresRuntimeStore {
    async fn get_record(&self, key: &str) -> RuntimeResult<Option<IdempotencyRecord>> {
        let row = query::<Postgres>(
            "SELECT value FROM aip_idempotency WHERE key = $1 AND status = 'settled'",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        row.map(|row| {
            decode_value(
                row.try_get::<Value, _>("value")
                    .map_err(postgres_runtime_error)?,
            )
            .map_err(|error| RuntimeError::Storage(error.to_string()))
        })
        .transpose()
    }

    async fn insert_record(&self, record: IdempotencyRecord) -> RuntimeResult<()> {
        query::<Postgres>(
            r#"
            INSERT INTO aip_idempotency (
                key, status, owner_action_id, reservation_id, input_hash,
                reservation_expires_at_ms, value, updated_at_ms
            ) VALUES ($1, 'settled', $2, '', $3, NULL, $4, $5)
            ON CONFLICT (key) DO UPDATE SET
                status = 'settled',
                owner_action_id = EXCLUDED.owner_action_id,
                reservation_id = '',
                input_hash = EXCLUDED.input_hash,
                reservation_expires_at_ms = NULL,
                value = EXCLUDED.value,
                updated_at_ms = EXCLUDED.updated_at_ms
            "#,
        )
        .bind(&record.key)
        .bind(record.action_id.as_str())
        .bind(&record.input_hash)
        .bind(
            serde_json::to_value(&record)
                .map_err(|error| RuntimeError::Storage(error.to_string()))?,
        )
        .bind(now_ms())
        .execute(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        Ok(())
    }

    async fn reserve(
        &self,
        reservation: IdempotencyReservation,
    ) -> RuntimeResult<IdempotencyReservationOutcome> {
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let inserted = query::<Postgres>(
            r#"
            INSERT INTO aip_idempotency (
                key, status, owner_action_id, reservation_id, input_hash,
                reservation_expires_at_ms, value, updated_at_ms
            ) VALUES ($1, 'in_progress', $2, $3, $4, $5, NULL, $6)
            ON CONFLICT (key) DO NOTHING
            "#,
        )
        .bind(&reservation.key)
        .bind(reservation.action_id.as_str())
        .bind(&reservation.reservation_id)
        .bind(&reservation.input_hash)
        .bind(timestamp_ms(reservation.expires_at))
        .bind(now_ms())
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        if inserted.rows_affected() == 1 {
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(IdempotencyReservationOutcome::Acquired);
        }
        let row = query::<Postgres>(
            "SELECT status, owner_action_id, reservation_id, input_hash, reservation_expires_at_ms, value FROM aip_idempotency WHERE key = $1 FOR UPDATE",
        )
        .bind(&reservation.key)
        .fetch_one(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        let status: String = row.try_get("status").map_err(postgres_runtime_error)?;
        if status == "settled" {
            let record = decode_value::<IdempotencyRecord>(
                row.try_get("value").map_err(postgres_runtime_error)?,
            )
            .map_err(|error| RuntimeError::Storage(error.to_string()))?;
            if reservation.resume_pending
                && reservation.action_id == record.action_id
                && reservation.input_hash == record.input_hash
                && matches!(
                    record.result.status,
                    ActionResultStatus::PendingApproval | ActionResultStatus::RequiresHuman
                )
            {
                query::<Postgres>(
                    r#"
                    UPDATE aip_idempotency
                    SET status = 'in_progress', owner_action_id = $2, reservation_id = $3,
                        input_hash = $4, reservation_expires_at_ms = $5,
                        value = NULL, updated_at_ms = $6
                    WHERE key = $1
                    "#,
                )
                .bind(&reservation.key)
                .bind(reservation.action_id.as_str())
                .bind(&reservation.reservation_id)
                .bind(&reservation.input_hash)
                .bind(timestamp_ms(reservation.expires_at))
                .bind(now_ms())
                .execute(&mut *transaction)
                .await
                .map_err(postgres_runtime_error)?;
                transaction.commit().await.map_err(postgres_runtime_error)?;
                return Ok(IdempotencyReservationOutcome::Acquired);
            }
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(IdempotencyReservationOutcome::Settled(Box::new(record)));
        }
        let expires_at_ms = row
            .try_get::<Option<i64>, _>("reservation_expires_at_ms")
            .map_err(postgres_runtime_error)?
            .unwrap_or_default();
        if expires_at_ms <= now_ms() {
            query::<Postgres>(
                "UPDATE aip_idempotency SET owner_action_id = $2, reservation_id = $3, input_hash = $4, reservation_expires_at_ms = $5, updated_at_ms = $6 WHERE key = $1",
            )
            .bind(&reservation.key)
            .bind(reservation.action_id.as_str())
            .bind(&reservation.reservation_id)
            .bind(&reservation.input_hash)
            .bind(timestamp_ms(reservation.expires_at))
            .bind(now_ms())
            .execute(&mut *transaction)
            .await
            .map_err(postgres_runtime_error)?;
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(IdempotencyReservationOutcome::Acquired);
        }
        let owner_action_id: String = row
            .try_get("owner_action_id")
            .map_err(postgres_runtime_error)?;
        let existing = IdempotencyReservation {
            key: reservation.key,
            reservation_id: row
                .try_get("reservation_id")
                .map_err(postgres_runtime_error)?,
            action_id: ActionId::parse(owner_action_id)
                .map_err(|error| RuntimeError::Storage(error.to_string()))?,
            input_hash: row.try_get("input_hash").map_err(postgres_runtime_error)?,
            resume_pending: false,
            expires_at: OffsetDateTime::from_unix_timestamp_nanos(
                i128::from(expires_at_ms) * 1_000_000,
            )
            .map_err(postgres_runtime_error)?,
        };
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(IdempotencyReservationOutcome::InProgress(existing))
    }

    async fn settle_reservation(
        &self,
        reservation: &IdempotencyReservation,
        record: IdempotencyRecord,
    ) -> RuntimeResult<()> {
        let result = query::<Postgres>(
            r#"
            UPDATE aip_idempotency
            SET status = 'settled', value = $4, reservation_expires_at_ms = NULL, updated_at_ms = $5
            WHERE key = $1 AND status = 'in_progress' AND owner_action_id = $2
                AND reservation_id = $3
            "#,
        )
        .bind(&reservation.key)
        .bind(reservation.action_id.as_str())
        .bind(&reservation.reservation_id)
        .bind(
            serde_json::to_value(record)
                .map_err(|error| RuntimeError::Storage(error.to_string()))?,
        )
        .bind(now_ms())
        .execute(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        if result.rows_affected() != 1 {
            return Err(RuntimeError::Storage(format!(
                "idempotency reservation `{}` is no longer owned by action `{}`",
                reservation.key, reservation.action_id
            )));
        }
        Ok(())
    }

    async fn renew_reservation(
        &self,
        reservation: &IdempotencyReservation,
        expires_at: OffsetDateTime,
    ) -> RuntimeResult<bool> {
        let updated = query::<Postgres>(
            r#"
            UPDATE aip_idempotency
            SET reservation_expires_at_ms = $4, updated_at_ms = $5
            WHERE key = $1
              AND status = 'in_progress'
              AND owner_action_id = $2
              AND reservation_id = $3
            "#,
        )
        .bind(&reservation.key)
        .bind(reservation.action_id.as_str())
        .bind(&reservation.reservation_id)
        .bind(timestamp_ms(expires_at))
        .bind(now_ms())
        .execute(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        Ok(updated.rows_affected() == 1)
    }

    async fn release_reservation(&self, reservation: &IdempotencyReservation) -> RuntimeResult<()> {
        query::<Postgres>(
            "DELETE FROM aip_idempotency WHERE key = $1 AND status = 'in_progress' AND owner_action_id = $2 AND reservation_id = $3",
        )
        .bind(&reservation.key)
        .bind(reservation.action_id.as_str())
        .bind(&reservation.reservation_id)
        .execute(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        Ok(())
    }
}

impl PostgresRuntimeStore {
    async fn stream_event_page(
        &self,
        cursor: i64,
        request: &EventStreamRequest,
        scope: EventPageScope<'_>,
    ) -> RuntimeResult<EventStream> {
        let requested_limit = usize::try_from(
            request
                .limit
                .unwrap_or(100)
                .clamp(1, MAX_EVENT_PAGE_ROWS as u32),
        )
        .map_err(postgres_runtime_error)?;
        let transfer_ceiling = MAX_EVENT_RECORD_BYTES.checked_mul(2).ok_or_else(|| {
            RuntimeError::Storage("event transfer byte limit overflowed".to_owned())
        })?;
        let transfer_ceiling_i64 = i64::try_from(transfer_ceiling).map_err(|_| {
            RuntimeError::Storage("event transfer byte limit exceeds i64".to_owned())
        })?;
        let transfer_ceiling_u64 = u64::try_from(transfer_ceiling).map_err(|_| {
            RuntimeError::Storage("event transfer byte limit exceeds u64".to_owned())
        })?;
        let fetch_batch_size = MAX_EVENT_PAGE_BYTES
            .checked_div(transfer_ceiling)
            .unwrap_or(0)
            .max(1);
        let mut events = Vec::with_capacity(requested_limit.min(fetch_batch_size));
        let mut page_bytes = 0_usize;
        let mut last_seq = cursor;
        let mut byte_limit_reached = false;

        loop {
            let remaining = requested_limit.saturating_sub(events.len());
            if remaining == 0 {
                break;
            }
            let fetch_limit_usize = remaining.min(fetch_batch_size);
            let fetch_limit = i64::try_from(fetch_limit_usize).map_err(|_| {
                RuntimeError::Storage("event page row limit exceeds i64".to_owned())
            })?;
            let rows = match scope {
                EventPageScope::Global => {
                    query::<Postgres>(
                        r#"
                    SELECT seq,
                           octet_length(event::TEXT)::BIGINT AS event_bytes,
                           CASE WHEN octet_length(event::TEXT) <= $4
                                THEN event ELSE NULL END AS event
                    FROM aip_events_v2
                    WHERE seq > $1
                      AND (COALESCE(cardinality($2::TEXT[]), 0) = 0 OR kind = ANY($2))
                    ORDER BY seq
                    LIMIT $3
                    "#,
                    )
                    .bind(last_seq)
                    .bind(&request.kinds)
                    .bind(fetch_limit)
                    .bind(transfer_ceiling_i64)
                    .fetch_all(&self.pool)
                    .await
                }
                EventPageScope::Tenant(tenant_id) => {
                    query::<Postgres>(
                        r#"
                    SELECT seq,
                           octet_length(event::TEXT)::BIGINT AS event_bytes,
                           CASE WHEN octet_length(event::TEXT) <= $5
                                THEN event ELSE NULL END AS event
                    FROM aip_events_v2
                    WHERE seq > $1 AND tenant_id = $2
                      AND (COALESCE(cardinality($3::TEXT[]), 0) = 0 OR kind = ANY($3))
                    ORDER BY seq
                    LIMIT $4
                    "#,
                    )
                    .bind(last_seq)
                    .bind(tenant_id)
                    .bind(&request.kinds)
                    .bind(fetch_limit)
                    .bind(transfer_ceiling_i64)
                    .fetch_all(&self.pool)
                    .await
                }
                EventPageScope::Action(action_id) => {
                    query::<Postgres>(
                        r#"
                    SELECT seq,
                           octet_length(event::TEXT)::BIGINT AS event_bytes,
                           CASE WHEN octet_length(event::TEXT) <= $5
                                THEN event ELSE NULL END AS event
                    FROM aip_events_v2
                    WHERE seq > $1 AND action_id = $2
                      AND (COALESCE(cardinality($3::TEXT[]), 0) = 0 OR kind = ANY($3))
                    ORDER BY seq
                    LIMIT $4
                    "#,
                    )
                    .bind(last_seq)
                    .bind(action_id.as_str())
                    .bind(&request.kinds)
                    .bind(fetch_limit)
                    .bind(transfer_ceiling_i64)
                    .fetch_all(&self.pool)
                    .await
                }
            }
            .map_err(postgres_runtime_error)?;
            let fetched = rows.len();
            if fetched == 0 {
                break;
            }
            for row in rows {
                let seq: i64 = row.try_get("seq").map_err(postgres_runtime_error)?;
                let stored_bytes: i64 =
                    row.try_get("event_bytes").map_err(postgres_runtime_error)?;
                let stored_bytes = u64::try_from(stored_bytes).map_err(|_| {
                    RuntimeError::Storage("stored event byte size is negative".to_owned())
                })?;
                if stored_bytes > transfer_ceiling_u64 {
                    return Err(RuntimeError::Storage(format!(
                        "stored event at sequence {seq} exceeds the bounded transfer limit"
                    )));
                }
                let value: Option<Value> = row.try_get("event").map_err(postgres_runtime_error)?;
                let value = value.ok_or_else(|| {
                    RuntimeError::Storage(format!(
                        "stored event at sequence {seq} is unavailable within its transfer bound"
                    ))
                })?;
                let event = decode_value::<Event>(value).map_err(postgres_runtime_error)?;
                let event_bytes = validate_event_record_size(&event)?;
                if page_bytes.saturating_add(event_bytes) > MAX_EVENT_PAGE_BYTES {
                    byte_limit_reached = true;
                    break;
                }
                page_bytes = page_bytes.saturating_add(event_bytes);
                last_seq = seq;
                events.push(event);
            }
            if byte_limit_reached || fetched < fetch_limit_usize {
                break;
            }
        }

        Ok(EventStream {
            events,
            next_cursor: Some(format_event_cursor(last_seq)),
        })
    }
}

#[async_trait]
impl EventStore for PostgresRuntimeStore {
    async fn append(&self, event: Event) -> RuntimeResult<Event> {
        self.append_with_outcome(event)
            .await
            .map(EventAppendOutcome::into_event)
    }

    async fn append_with_outcome(&self, event: Event) -> RuntimeResult<EventAppendOutcome> {
        validate_event_record_size(&event)?;
        let value = serde_json::to_value(&event).map_err(postgres_runtime_error)?;
        let tenant_id = event
            .data
            .as_ref()
            .and_then(|data| data.pointer("/identity/tenant/id"))
            .and_then(Value::as_str);
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let claimed = query::<Postgres>(
            r#"
            INSERT INTO aip_event_registry (event_id, seq, created_at_ms)
            VALUES ($1, 0, $2)
            ON CONFLICT (event_id) DO NOTHING
            "#,
        )
        .bind(event.id.as_str())
        .bind(timestamp_ms(event.occurred_at))
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        if claimed.rows_affected() == 0 {
            let row = query::<Postgres>(
                "SELECT event FROM aip_events_v2 WHERE event_id = $1 ORDER BY seq LIMIT 1",
            )
            .bind(event.id.as_str())
            .fetch_one(&mut *transaction)
            .await
            .map_err(postgres_runtime_error)?;
            let existing = decode_value(row.try_get("event").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)?;
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(EventAppendOutcome::Replayed(existing));
        }
        let inserted = query::<Postgres>(
            r#"
            INSERT INTO aip_events_v2 (
                event_id, kind, action_id, tenant_id, event, occurred_at_ms
            ) VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING seq
            "#,
        )
        .bind(event.id.as_str())
        .bind(&event.kind)
        .bind(event.action_id.as_ref().map(ActionId::as_str))
        .bind(tenant_id)
        .bind(value)
        .bind(timestamp_ms(event.occurred_at))
        .fetch_one(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        let seq: i64 = inserted.try_get("seq").map_err(postgres_runtime_error)?;
        query::<Postgres>("UPDATE aip_event_registry SET seq = $2 WHERE event_id = $1 AND seq = 0")
            .bind(event.id.as_str())
            .bind(seq)
            .execute(&mut *transaction)
            .await
            .map_err(postgres_runtime_error)?;
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(EventAppendOutcome::Inserted(event))
    }

    async fn stream(&self, request: &EventStreamRequest) -> RuntimeResult<EventStream> {
        let cursor = request
            .cursor
            .as_deref()
            .and_then(parse_event_cursor)
            .unwrap_or(0);
        self.stream_event_page(cursor, request, EventPageScope::Global)
            .await
    }

    async fn stream_checked(&self, request: &EventStreamRequest) -> RuntimeResult<EventStream> {
        let cursor = match request.cursor.as_deref() {
            Some(cursor) => parse_event_cursor_checked(cursor)
                .map_err(|error| RuntimeError::Protocol(*error))?,
            None => 0,
        };
        let max_seq =
            query::<Postgres>("SELECT COALESCE(MAX(seq), 0) AS max_seq FROM aip_events_v2")
                .fetch_one(&self.pool)
                .await
                .map_err(postgres_runtime_error)?
                .try_get::<i64, _>("max_seq")
                .map_err(postgres_runtime_error)?;
        if cursor > max_seq {
            return Err(RuntimeError::Protocol(ProtocolError {
                code: "stream.cursor_expired".to_owned(),
                message: format!(
                    "event cursor `{}` is outside the retained replay window",
                    request.cursor.as_deref().unwrap_or_default()
                ),
                category: ErrorCategory::Permanent,
                retryable: Some(false),
                retry_after_ms: None,
                details: Some(Box::new(json!({
                    "cursor": request.cursor.clone(),
                    "max_seq": max_seq
                }))),
                source: Some(Box::new(json!({ "component": "aip-storage-postgres" }))),
            }));
        }
        self.stream_event_page(cursor, request, EventPageScope::Global)
            .await
    }

    async fn stream_tenant_checked(
        &self,
        tenant_id: &str,
        request: &EventStreamRequest,
    ) -> RuntimeResult<EventStream> {
        let cursor = match request.cursor.as_deref() {
            Some(cursor) => parse_event_cursor_checked(cursor)
                .map_err(|error| RuntimeError::Protocol(*error))?,
            None => 0,
        };
        let max_seq =
            query::<Postgres>("SELECT COALESCE(MAX(seq), 0) AS max_seq FROM aip_events_v2")
                .fetch_one(&self.pool)
                .await
                .map_err(postgres_runtime_error)?
                .try_get::<i64, _>("max_seq")
                .map_err(postgres_runtime_error)?;
        if cursor > max_seq {
            return Err(RuntimeError::Protocol(ProtocolError {
                code: "stream.cursor_expired".to_owned(),
                message: format!(
                    "event cursor `{}` is outside the retained replay window",
                    request.cursor.as_deref().unwrap_or_default()
                ),
                category: ErrorCategory::Permanent,
                retryable: Some(false),
                retry_after_ms: None,
                details: Some(Box::new(json!({
                    "cursor": request.cursor.clone(),
                    "max_seq": max_seq
                }))),
                source: Some(Box::new(json!({ "component": "aip-storage-postgres" }))),
            }));
        }
        self.stream_event_page(cursor, request, EventPageScope::Tenant(tenant_id))
            .await
    }

    async fn stream_action_checked(
        &self,
        action_id: &ActionId,
        request: &EventStreamRequest,
    ) -> RuntimeResult<EventStream> {
        let cursor = match request.cursor.as_deref() {
            Some(cursor) => parse_event_cursor_checked(cursor)
                .map_err(|error| RuntimeError::Protocol(*error))?,
            None => 0,
        };
        let max_seq =
            query::<Postgres>("SELECT COALESCE(MAX(seq), 0) AS max_seq FROM aip_events_v2")
                .fetch_one(&self.pool)
                .await
                .map_err(postgres_runtime_error)?
                .try_get::<i64, _>("max_seq")
                .map_err(postgres_runtime_error)?;
        if cursor > max_seq {
            return Err(RuntimeError::Protocol(ProtocolError {
                code: "stream.cursor_expired".to_owned(),
                message: format!(
                    "event cursor `{}` is outside the retained replay window",
                    request.cursor.as_deref().unwrap_or_default()
                ),
                category: ErrorCategory::Permanent,
                retryable: Some(false),
                retry_after_ms: None,
                details: Some(Box::new(json!({
                    "cursor": request.cursor.clone(),
                    "max_seq": max_seq
                }))),
                source: Some(Box::new(json!({ "component": "aip-storage-postgres" }))),
            }));
        }
        self.stream_event_page(cursor, request, EventPageScope::Action(action_id))
            .await
    }
}

#[async_trait]
impl LifecycleBackend for PostgresRuntimeStore {
    async fn action_result(&self, action_id: &ActionId) -> RuntimeResult<Option<ActionResult>> {
        self.get_value("action_results", action_id.as_str())
            .await
            .map_err(postgres_runtime_error)
    }

    async fn action_results(&self) -> RuntimeResult<Vec<ActionResult>> {
        self.values("action_results")
            .await
            .map_err(postgres_runtime_error)
    }

    async fn stream_chunks(&self, action_id: &ActionId) -> RuntimeResult<Vec<StreamChunk>> {
        Ok(self
            .get_value("stream_chunks", action_id.as_str())
            .await
            .map_err(postgres_runtime_error)?
            .unwrap_or_default())
    }

    async fn cancel_action(
        &self,
        action_id: ActionId,
        reason: Option<String>,
    ) -> RuntimeResult<()> {
        self.upsert_value("cancelled_actions", action_id.as_str(), &reason)
            .await
            .map_err(postgres_runtime_error)
    }

    async fn record_stream_chunk(
        &self,
        chunk: StreamChunk,
    ) -> RuntimeResult<StreamChunkRecordOutcome> {
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        query::<Postgres>(
            r#"
            INSERT INTO aip_kv (bucket, key, value, updated_at_ms)
            VALUES ('stream_chunks', $1, '[]'::JSONB, $2)
            ON CONFLICT (bucket, key) DO NOTHING
            "#,
        )
        .bind(chunk.action_id.as_str())
        .bind(now_ms())
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        let row = query::<Postgres>(
            "SELECT value FROM aip_kv WHERE bucket = 'stream_chunks' AND key = $1 FOR UPDATE",
        )
        .bind(chunk.action_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        let row = row.ok_or_else(|| {
            RuntimeError::Storage(format!(
                "stream chunk log `{}` disappeared while it was locked",
                chunk.action_id
            ))
        })?;
        let mut chunks: Vec<StreamChunk> = row
            .try_get("value")
            .map_err(PostgresStorageError::from)
            .and_then(decode_value)
            .map_err(postgres_runtime_error)?;
        let outcome = classify_stream_chunk_record(&chunks, &chunk)?;
        if outcome == StreamChunkRecordOutcome::Inserted {
            let action_id = chunk.action_id.clone();
            chunks.push(chunk);
            let value = serde_json::to_value(chunks).map_err(postgres_runtime_error)?;
            query::<Postgres>(
                r#"
                UPDATE aip_kv
                SET value = $2, updated_at_ms = $3
                WHERE bucket = 'stream_chunks' AND key = $1
                "#,
            )
            .bind(action_id.as_str())
            .bind(value)
            .bind(now_ms())
            .execute(&mut *transaction)
            .await
            .map_err(postgres_runtime_error)?;
        }
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(outcome)
    }

    async fn record_action_result(&self, result: ActionResult) -> RuntimeResult<()> {
        self.upsert_value("action_results", result.action_id.as_str(), &result)
            .await
            .map_err(postgres_runtime_error)
    }

    async fn record_escalation(&self, escalation: Escalation) -> RuntimeResult<()> {
        let key = storage_key("escalation", now_ms());
        self.upsert_value("escalations", &key, &escalation)
            .await
            .map_err(postgres_runtime_error)
    }

    async fn record_escalation_resolution(
        &self,
        resolution: EscalationResolution,
    ) -> RuntimeResult<()> {
        let key = storage_key("escalation_resolution", now_ms());
        self.upsert_value("escalation_resolutions", &key, &resolution)
            .await
            .map_err(postgres_runtime_error)
    }

    async fn record_conversation(&self, conversation: Conversation) -> RuntimeResult<()> {
        self.upsert_value("conversations", conversation.id.as_str(), &conversation)
            .await
            .map_err(postgres_runtime_error)
    }

    async fn record_receipt_chain(&self, chain: ReceiptChain) -> RuntimeResult<()> {
        self.upsert_value("receipt_chains", &chain.chain_id, &chain)
            .await
            .map_err(postgres_runtime_error)
    }

    async fn receipt_chain(&self, chain_id: &str) -> RuntimeResult<Option<ReceiptChain>> {
        self.get_value("receipt_chains", chain_id)
            .await
            .map_err(postgres_runtime_error)
    }

    async fn receipt_chains(&self) -> RuntimeResult<Vec<ReceiptChain>> {
        self.values("receipt_chains")
            .await
            .map_err(postgres_runtime_error)
    }

    async fn record_audit_event(&self, audit: AuditEvent) -> RuntimeResult<()> {
        self.upsert_value("audit_events", &audit.id, &audit)
            .await
            .map_err(postgres_runtime_error)
    }

    async fn audit_event(&self, audit_id: &str) -> RuntimeResult<Option<AuditEvent>> {
        self.get_value("audit_events", audit_id)
            .await
            .map_err(postgres_runtime_error)
    }

    async fn audit_events(&self) -> RuntimeResult<Vec<AuditEvent>> {
        self.values("audit_events")
            .await
            .map_err(postgres_runtime_error)
    }

    async fn record_settlement(&self, settlement: BatchSettlement) -> RuntimeResult<()> {
        self.upsert_value("settlements", &settlement.id, &settlement)
            .await
            .map_err(postgres_runtime_error)
    }
}

#[async_trait]
impl DelegationBackend for PostgresRuntimeStore {
    async fn upsert(&self, record: DelegationRecord) -> RuntimeResult<()> {
        self.upsert_value(
            "delegations",
            record.request.delegation_id.as_str(),
            &record,
        )
        .await
        .map_err(postgres_runtime_error)
    }

    async fn get(&self, delegation_id: &DelegationId) -> RuntimeResult<Option<DelegationRecord>> {
        self.get_value("delegations", delegation_id.as_str())
            .await
            .map_err(postgres_runtime_error)
    }

    async fn children(&self, parent_action_id: &ActionId) -> RuntimeResult<Vec<DelegationRecord>> {
        Ok(self
            .values::<DelegationRecord>("delegations")
            .await
            .map_err(postgres_runtime_error)?
            .into_iter()
            .filter(|record| record.request.parent_action_id == *parent_action_id)
            .collect())
    }

    async fn by_child_action(
        &self,
        child_action_id: &ActionId,
    ) -> RuntimeResult<Option<DelegationRecord>> {
        Ok(self
            .values::<DelegationRecord>("delegations")
            .await
            .map_err(postgres_runtime_error)?
            .into_iter()
            .find(|record| record.request.child_action.id == *child_action_id))
    }

    async fn running(&self) -> RuntimeResult<Vec<DelegationRecord>> {
        Ok(self
            .values::<DelegationRecord>("delegations")
            .await
            .map_err(postgres_runtime_error)?
            .into_iter()
            .filter(|record| {
                matches!(
                    record.status,
                    DelegationStatus::Accepted | DelegationStatus::Running
                )
            })
            .collect())
    }
}

impl PostgresRuntimeStore {
    async fn insert_approval_record_if_absent(
        &self,
        record: &ApprovalRecord,
    ) -> RuntimeResult<bool> {
        let tenant_id = record
            .request
            .identity
            .as_ref()
            .and_then(|identity| identity.tenant.as_ref())
            .map(|tenant| tenant.id.as_str());
        let external_account_id = record
            .request
            .identity
            .as_ref()
            .and_then(|identity| identity.external_account.as_ref())
            .map(|account| account.id.as_str());
        let inserted = query::<Postgres>(
            r#"
            INSERT INTO aip_approvals (
                approval_id, action_id, capability_id, status, tenant_id,
                external_account_id, expires_at_ms, created_at_ms, updated_at_ms, record
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (approval_id) DO NOTHING
            "#,
        )
        .bind(record.request.id.as_str())
        .bind(record.request.action_id.as_str())
        .bind(record.request.capability_id.as_str())
        .bind(approval_status_label(record.status))
        .bind(tenant_id)
        .bind(external_account_id)
        .bind(record.request.expires_at.map(timestamp_ms))
        .bind(timestamp_ms(record.created_at))
        .bind(timestamp_ms(record.updated_at))
        .bind(serde_json::to_value(record).map_err(postgres_runtime_error)?)
        .execute(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        Ok(inserted.rows_affected() == 1)
    }
}

#[async_trait]
impl ApprovalBackend for PostgresRuntimeStore {
    async fn upsert_request(&self, record: ApprovalRecord) -> RuntimeResult<()> {
        if !self.insert_approval_record_if_absent(&record).await? {
            let existing = <Self as ApprovalBackend>::get(self, &record.request.id)
                .await?
                .ok_or_else(|| {
                    RuntimeError::Storage(format!(
                        "approval `{}` conflicted but could not be read",
                        record.request.id
                    ))
                })?;
            if existing.request == record.request
                && existing.status == ApprovalStatus::Pending
                && existing.decision.is_none()
            {
                return Ok(());
            }
            return Err(RuntimeError::Authorization(format!(
                "approval `{}` already exists and cannot be replaced",
                record.request.id
            )));
        }
        Ok(())
    }

    async fn import_terminal_authorization(&self, record: ApprovalRecord) -> RuntimeResult<()> {
        record.validate_importable_authorization()?;
        if !self.insert_approval_record_if_absent(&record).await? {
            let existing = <Self as ApprovalBackend>::get(self, &record.request.id)
                .await?
                .ok_or_else(|| {
                    RuntimeError::Storage(format!(
                        "approval `{}` conflicted but could not be read",
                        record.request.id
                    ))
                })?;
            if existing == record {
                return Ok(());
            }
            return Err(RuntimeError::Authorization(format!(
                "approval `{}` conflicts with an existing authorization record",
                record.request.id
            )));
        }
        Ok(())
    }

    async fn record_verified_decision(
        &self,
        verified: VerifiedApprovalDecision,
    ) -> RuntimeResult<ApprovalRecord> {
        let decision = &verified.decision;
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let row =
            query::<Postgres>("SELECT record FROM aip_approvals WHERE approval_id = $1 FOR UPDATE")
                .bind(decision.approval_id.as_str())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(postgres_runtime_error)?
                .ok_or_else(|| {
                    RuntimeError::Handler(format!(
                        "approval `{}` was not found",
                        decision.approval_id
                    ))
                })?;
        let mut record: ApprovalRecord =
            decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                .map_err(|error| RuntimeError::Storage(error.to_string()))?;
        let apply = record.apply_verified_decision(verified)?;
        if apply == ApprovalDecisionApply::Replayed {
            if record.status != ApprovalStatus::Pending {
                Self::enqueue_approval_transition(&mut transaction, &record).await?;
            }
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(record);
        }
        let updated = query::<Postgres>(
            r#"
            UPDATE aip_approvals
            SET status = $2, record = $3, updated_at_ms = $4
            WHERE approval_id = $1 AND status = 'pending'
            "#,
        )
        .bind(record.request.id.as_str())
        .bind(approval_status_label(record.status))
        .bind(
            serde_json::to_value(&record)
                .map_err(|error| RuntimeError::Storage(error.to_string()))?,
        )
        .bind(now_ms())
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        if updated.rows_affected() != 1 {
            return Err(RuntimeError::Storage(format!(
                "approval `{}` lost its compare-and-set transition",
                record.request.id
            )));
        }
        if apply == ApprovalDecisionApply::Terminal {
            Self::enqueue_approval_transition(&mut transaction, &record).await?;
        }
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(record)
    }

    async fn get(&self, approval_id: &ApprovalId) -> RuntimeResult<Option<ApprovalRecord>> {
        let row = query::<Postgres>("SELECT record FROM aip_approvals WHERE approval_id = $1")
            .bind(approval_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(postgres_runtime_error)?;
        row.map(|row| {
            decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)
        })
        .transpose()
    }

    async fn pending(&self) -> RuntimeResult<Vec<ApprovalRecord>> {
        let rows = query::<Postgres>(
            "SELECT record FROM aip_approvals WHERE status = 'pending' ORDER BY created_at_ms",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        rows.into_iter()
            .map(|row| {
                decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                    .map_err(postgres_runtime_error)
            })
            .collect()
    }

    async fn list(&self) -> RuntimeResult<Vec<ApprovalRecord>> {
        let rows = query::<Postgres>("SELECT record FROM aip_approvals ORDER BY created_at_ms")
            .fetch_all(&self.pool)
            .await
            .map_err(postgres_runtime_error)?;
        rows.into_iter()
            .map(|row| {
                decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                    .map_err(postgres_runtime_error)
            })
            .collect()
    }

    async fn claim_decision_transition(
        &self,
        approval_id: &ApprovalId,
        worker_id: &str,
        lease_ttl_ms: u64,
        now: OffsetDateTime,
    ) -> RuntimeResult<Option<ApprovalTransitionLease>> {
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let row = query::<Postgres>(
            r#"
            SELECT outbox.payload
            FROM aip_outbox outbox
            WHERE outbox.outbox_id = $1
              AND outbox.status IN ('pending', 'processing')
              AND (outbox.lease_expires_at_ms IS NULL OR outbox.lease_expires_at_ms <= $2)
            FOR UPDATE
            "#,
        )
        .bind(approval_outbox_id(approval_id))
        .bind(timestamp_ms(now))
        .fetch_optional(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(None);
        };
        let record: ApprovalRecord =
            decode_value(row.try_get("payload").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)?;
        let lease_id = Uuid::now_v7().to_string();
        let expires_at =
            now + time::Duration::milliseconds(lease_ttl_ms.max(1).min(i64::MAX as u64) as i64);
        query::<Postgres>(
            r#"
            UPDATE aip_outbox
            SET status = 'processing', attempts = attempts + 1,
                lease_id = $2, lease_expires_at_ms = $3
            WHERE outbox_id = $1
            "#,
        )
        .bind(approval_outbox_id(approval_id))
        .bind(&lease_id)
        .bind(timestamp_ms(expires_at))
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(Some(ApprovalTransitionLease {
            record,
            worker_id: worker_id.to_owned(),
            lease_id,
            expires_at,
        }))
    }

    async fn claim_pending_decision_transitions(
        &self,
        worker_id: &str,
        lease_ttl_ms: u64,
        now: OffsetDateTime,
    ) -> RuntimeResult<Vec<ApprovalTransitionLease>> {
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let rows = query::<Postgres>(
            r#"
            SELECT outbox_id, payload
            FROM aip_outbox
            WHERE aggregate_type = 'approval'
              AND status IN ('pending', 'processing')
              AND available_at_ms <= $1
              AND (lease_expires_at_ms IS NULL OR lease_expires_at_ms <= $1)
            ORDER BY created_at_ms
            FOR UPDATE SKIP LOCKED
            LIMIT 100
            "#,
        )
        .bind(timestamp_ms(now))
        .fetch_all(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        let expires_at =
            now + time::Duration::milliseconds(lease_ttl_ms.max(1).min(i64::MAX as u64) as i64);
        let mut claimed = Vec::with_capacity(rows.len());
        for row in rows {
            let outbox_id: String = row.try_get("outbox_id").map_err(postgres_runtime_error)?;
            let record: ApprovalRecord =
                decode_value(row.try_get("payload").map_err(postgres_runtime_error)?)
                    .map_err(postgres_runtime_error)?;
            let lease_id = Uuid::now_v7().to_string();
            query::<Postgres>(
                r#"
                UPDATE aip_outbox
                SET status = 'processing', attempts = attempts + 1,
                    lease_id = $2, lease_expires_at_ms = $3
                WHERE outbox_id = $1
                "#,
            )
            .bind(outbox_id)
            .bind(&lease_id)
            .bind(timestamp_ms(expires_at))
            .execute(&mut *transaction)
            .await
            .map_err(postgres_runtime_error)?;
            claimed.push(ApprovalTransitionLease {
                record,
                worker_id: worker_id.to_owned(),
                lease_id,
                expires_at,
            });
        }
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(claimed)
    }

    async fn complete_decision_transition(
        &self,
        approval_id: &ApprovalId,
        lease_id: &str,
    ) -> RuntimeResult<bool> {
        let updated = query::<Postgres>(
            r#"
            UPDATE aip_outbox
            SET status = 'published', published_at_ms = $3,
                lease_id = NULL, lease_expires_at_ms = NULL, last_error = NULL
            WHERE outbox_id = $1 AND status = 'processing' AND lease_id = $2
            "#,
        )
        .bind(approval_outbox_id(approval_id))
        .bind(lease_id)
        .bind(now_ms())
        .execute(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        Ok(updated.rows_affected() == 1)
    }
}

#[async_trait]
impl TransactionBackend for PostgresRuntimeStore {
    async fn upsert(&self, record: TransactionRecord) -> RuntimeResult<()> {
        let tenant_id = record
            .identity
            .as_ref()
            .and_then(|identity| identity.tenant.as_ref())
            .map(|tenant| tenant.id.as_str());
        let external_account_id = record
            .identity
            .as_ref()
            .and_then(|identity| identity.external_account.as_ref())
            .map(|account| account.id.as_str());
        query::<Postgres>(
            r#"
            INSERT INTO aip_transactions (
                transaction_id, action_id, capability_id, plan_id, status,
                tenant_id, external_account_id, created_at_ms, updated_at_ms, record
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (transaction_id) DO UPDATE SET
                action_id = EXCLUDED.action_id,
                capability_id = EXCLUDED.capability_id,
                plan_id = EXCLUDED.plan_id,
                status = EXCLUDED.status,
                tenant_id = EXCLUDED.tenant_id,
                external_account_id = EXCLUDED.external_account_id,
                updated_at_ms = EXCLUDED.updated_at_ms,
                record = EXCLUDED.record
            "#,
        )
        .bind(record.transaction_id.as_str())
        .bind(record.action_id.as_str())
        .bind(record.capability_id.as_str())
        .bind(transaction_plan_id(&record))
        .bind(transaction_status_label(record.status))
        .bind(tenant_id)
        .bind(external_account_id)
        .bind(timestamp_ms(record.created_at))
        .bind(timestamp_ms(record.updated_at))
        .bind(serde_json::to_value(&record).map_err(postgres_runtime_error)?)
        .execute(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        Ok(())
    }

    async fn get(
        &self,
        transaction_id: &TransactionId,
    ) -> RuntimeResult<Option<TransactionRecord>> {
        let row =
            query::<Postgres>("SELECT record FROM aip_transactions WHERE transaction_id = $1")
                .bind(transaction_id.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(postgres_runtime_error)?;
        row.map(|row| {
            decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)
        })
        .transpose()
    }

    async fn by_plan_id(&self, plan_id: &str) -> RuntimeResult<Option<TransactionRecord>> {
        let row = query::<Postgres>("SELECT record FROM aip_transactions WHERE plan_id = $1")
            .bind(plan_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(postgres_runtime_error)?;
        row.map(|row| {
            decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)
        })
        .transpose()
    }

    async fn claim_plan(
        &self,
        plan_id: &str,
        commit_action_id: &ActionId,
    ) -> RuntimeResult<TransactionRecord> {
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let row = query::<Postgres>(
            r#"
            SELECT transaction_id, record
            FROM aip_transactions
            WHERE plan_id = $1
            FOR UPDATE
            "#,
        )
        .bind(plan_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?
        .ok_or_else(|| RuntimeError::Storage(format!("transaction plan `{plan_id}` not found")))?;
        let transaction_id: String = row
            .try_get("transaction_id")
            .map_err(postgres_runtime_error)?;
        let mut record: TransactionRecord =
            decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                .map_err(|error| RuntimeError::Storage(error.to_string()))?;
        if record.status != aip_runtime::TransactionStatus::Planned {
            return Err(RuntimeError::Authorization(format!(
                "transaction plan `{plan_id}` is already in state `{:?}`",
                record.status
            )));
        }
        record.status = aip_runtime::TransactionStatus::Committing;
        record.action_id = commit_action_id.clone();
        record.revision = record.revision.saturating_add(1);
        record.updated_at = OffsetDateTime::now_utc();
        let updated = query::<Postgres>(
            r#"
            UPDATE aip_transactions
            SET action_id = $2, status = 'committing', record = $3, updated_at_ms = $4
            WHERE transaction_id = $1 AND status = 'planned'
            "#,
        )
        .bind(&transaction_id)
        .bind(commit_action_id.as_str())
        .bind(
            serde_json::to_value(&record)
                .map_err(|error| RuntimeError::Storage(error.to_string()))?,
        )
        .bind(now_ms())
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        if updated.rows_affected() != 1 {
            return Err(RuntimeError::Storage(format!(
                "transaction plan `{plan_id}` lost its compare-and-set transition"
            )));
        }
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(record)
    }

    async fn claim_direct_commit(
        &self,
        record: TransactionRecord,
    ) -> RuntimeResult<TransactionRecord> {
        if record.status != aip_runtime::TransactionStatus::Committing
            || record.transaction.plan_id.is_some()
        {
            return Err(RuntimeError::Authorization(
                "direct commit claim requires an unplanned committing record".to_owned(),
            ));
        }
        let tenant_id = record
            .identity
            .as_ref()
            .and_then(|identity| identity.tenant.as_ref())
            .map(|tenant| tenant.id.as_str());
        let external_account_id = record
            .identity
            .as_ref()
            .and_then(|identity| identity.external_account.as_ref())
            .map(|account| account.id.as_str());
        let inserted = query::<Postgres>(
            r#"
            INSERT INTO aip_transactions (
                transaction_id, action_id, capability_id, plan_id, status,
                tenant_id, external_account_id, created_at_ms, updated_at_ms, record
            ) VALUES ($1, $2, $3, NULL, 'committing', $4, $5, $6, $7, $8)
            ON CONFLICT (transaction_id) DO NOTHING
            "#,
        )
        .bind(record.transaction_id.as_str())
        .bind(record.action_id.as_str())
        .bind(record.capability_id.as_str())
        .bind(tenant_id)
        .bind(external_account_id)
        .bind(timestamp_ms(record.created_at))
        .bind(timestamp_ms(record.updated_at))
        .bind(serde_json::to_value(&record).map_err(postgres_runtime_error)?)
        .execute(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        if inserted.rows_affected() != 1 {
            let existing = <Self as TransactionBackend>::get(self, &record.transaction_id)
                .await?
                .ok_or_else(|| {
                    RuntimeError::Storage(format!(
                        "transaction `{}` conflicted but could not be read",
                        record.transaction_id
                    ))
                })?;
            return Err(RuntimeError::Authorization(format!(
                "transaction `{}` is already in state `{:?}`",
                record.transaction_id, existing.status
            )));
        }
        Ok(record)
    }

    async fn by_action(&self, action_id: &ActionId) -> RuntimeResult<Vec<TransactionRecord>> {
        let rows = query::<Postgres>(
            "SELECT record FROM aip_transactions WHERE action_id = $1 ORDER BY created_at_ms",
        )
        .bind(action_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        rows.into_iter()
            .map(|row| {
                decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                    .map_err(postgres_runtime_error)
            })
            .collect()
    }

    async fn recoverable(&self) -> RuntimeResult<Vec<TransactionRecord>> {
        let rows = query::<Postgres>(
            r#"
            SELECT record FROM aip_transactions
            WHERE status IN ('planned', 'prepared', 'committing', 'outcome_unknown', 'reconciling')
            ORDER BY updated_at_ms
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        rows.into_iter()
            .map(|row| {
                decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                    .map_err(postgres_runtime_error)
            })
            .collect()
    }

    async fn transition(
        &self,
        transaction_id: &TransactionId,
        expected_revision: u64,
        transition: TransactionTransition,
    ) -> RuntimeResult<TransactionRecord> {
        let mut database = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let row = query::<Postgres>(
            "SELECT status, record FROM aip_transactions WHERE transaction_id = $1 FOR UPDATE",
        )
        .bind(transaction_id.as_str())
        .fetch_optional(&mut *database)
        .await
        .map_err(postgres_runtime_error)?
        .ok_or_else(|| {
            RuntimeError::Storage(format!("transaction `{transaction_id}` was not found"))
        })?;
        let old_status: String = row.try_get("status").map_err(postgres_runtime_error)?;
        let mut record: TransactionRecord =
            decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)?;
        if record.revision != expected_revision {
            return Err(RuntimeError::Storage(format!(
                "transaction `{transaction_id}` lost revision fence `{expected_revision}`"
            )));
        }
        record.apply_transition(transition)?;
        let updated = query::<Postgres>(
            r#"
            UPDATE aip_transactions
            SET status = $2, updated_at_ms = $3, record = $4
            WHERE transaction_id = $1
              AND status = $5
              AND COALESCE((record->>'revision')::bigint, 0) = $6
            "#,
        )
        .bind(transaction_id.as_str())
        .bind(transaction_status_label(record.status))
        .bind(timestamp_ms(record.updated_at))
        .bind(serde_json::to_value(&record).map_err(postgres_runtime_error)?)
        .bind(old_status)
        .bind(i64::try_from(expected_revision).unwrap_or(i64::MAX))
        .execute(&mut *database)
        .await
        .map_err(postgres_runtime_error)?;
        if updated.rows_affected() != 1 {
            return Err(RuntimeError::Storage(format!(
                "transaction `{transaction_id}` lost compare-and-set transition"
            )));
        }
        database.commit().await.map_err(postgres_runtime_error)?;
        Ok(record)
    }
}

#[async_trait]
impl ActionQueueBackend for PostgresRuntimeStore {
    async fn enqueue(&self, record: QueuedActionRecord) -> RuntimeResult<()> {
        self.upsert_queue_record(&record).await
    }

    async fn mark_running(&self, action_id: &ActionId) -> RuntimeResult<()> {
        self.mutate_queue_record(action_id, |record| {
            record.status = QueuedActionStatus::Running;
            record.updated_at = OffsetDateTime::now_utc();
            (true, ())
        })
        .await?;
        Ok(())
    }

    async fn lease_next(
        &self,
        worker_id: &str,
        lease_ttl_ms: u64,
        now: OffsetDateTime,
    ) -> RuntimeResult<Option<QueuedActionRecord>> {
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let rows = query::<Postgres>(
            r#"
            SELECT action_id, record
            FROM aip_queue
            WHERE status IN ('queued', 'running')
              AND (lease_expires_at_ms IS NULL OR lease_expires_at_ms <= $1)
            ORDER BY created_at_ms ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 64
            "#,
        )
        .bind(timestamp_ms(now))
        .fetch_all(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        let mut record = None;
        for row in rows {
            let decoded: QueuedActionRecord =
                decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                    .map_err(postgres_runtime_error)?;
            if action_is_leaseable(&decoded, now) {
                record = Some(decoded);
                break;
            }
        }
        let Some(mut record) = record else {
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(None);
        };
        apply_lease(&mut record, worker_id, lease_ttl_ms, now);
        let updated = query::<Postgres>(
            r#"
            UPDATE aip_queue
            SET status = $2,
                lease_expires_at_ms = $3,
                updated_at_ms = $4,
                record = $5
            WHERE action_id = $1
            "#,
        )
        .bind(record.action.id.as_str())
        .bind(status_label(record.status))
        .bind(
            record
                .lease
                .as_ref()
                .map(|lease| timestamp_ms(lease.expires_at)),
        )
        .bind(timestamp_ms(record.updated_at))
        .bind(serde_json::to_value(&record).map_err(postgres_runtime_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        if updated.rows_affected() != 1 {
            return Err(RuntimeError::Storage(format!(
                "queue action `{}` lost its lease claim update",
                record.action.id
            )));
        }
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(Some(record))
    }

    async fn lease_action(
        &self,
        action_id: &ActionId,
        worker_id: &str,
        lease_ttl_ms: u64,
        now: OffsetDateTime,
    ) -> RuntimeResult<Option<QueuedActionRecord>> {
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let row = query::<Postgres>(
            r#"
            SELECT record
            FROM aip_queue
            WHERE action_id = $1
            FOR UPDATE
            "#,
        )
        .bind(action_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(None);
        };
        let mut record: QueuedActionRecord =
            decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)?;
        if !action_is_leaseable(&record, now) {
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(None);
        }
        apply_lease(&mut record, worker_id, lease_ttl_ms, now);
        let updated = query::<Postgres>(
            r#"
            UPDATE aip_queue
            SET status = $2,
                lease_expires_at_ms = $3,
                updated_at_ms = $4,
                record = $5
            WHERE action_id = $1
            "#,
        )
        .bind(record.action.id.as_str())
        .bind(status_label(record.status))
        .bind(
            record
                .lease
                .as_ref()
                .map(|lease| timestamp_ms(lease.expires_at)),
        )
        .bind(timestamp_ms(record.updated_at))
        .bind(serde_json::to_value(&record).map_err(postgres_runtime_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        if updated.rows_affected() != 1 {
            return Err(RuntimeError::Storage(format!(
                "queue action `{}` lost its explicit lease claim update",
                record.action.id
            )));
        }
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(Some(record))
    }

    async fn lease_approval_action(
        &self,
        action_id: &ActionId,
        worker_id: &str,
        lease_ttl_ms: u64,
        now: OffsetDateTime,
    ) -> RuntimeResult<Option<QueuedActionRecord>> {
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let row = query::<Postgres>("SELECT record FROM aip_queue WHERE action_id = $1 FOR UPDATE")
            .bind(action_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(postgres_runtime_error)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(None);
        };
        let mut record: QueuedActionRecord =
            decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)?;
        if record.status != QueuedActionStatus::RequiresHuman || record.lease.is_some() {
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(None);
        }
        apply_lease(&mut record, worker_id, lease_ttl_ms, now);
        let value = serde_json::to_value(&record).map_err(postgres_runtime_error)?;
        let updated = query::<Postgres>(
            r#"
            UPDATE aip_queue
            SET status = $2, lease_expires_at_ms = $3, updated_at_ms = $4, record = $5
            WHERE action_id = $1
            "#,
        )
        .bind(action_id.as_str())
        .bind(status_label(record.status))
        .bind(
            record
                .lease
                .as_ref()
                .map(|lease| timestamp_ms(lease.expires_at)),
        )
        .bind(timestamp_ms(record.updated_at))
        .bind(value)
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        if updated.rows_affected() != 1 {
            return Err(RuntimeError::Storage(format!(
                "approval action `{action_id}` lost its resume lease update"
            )));
        }
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(Some(record))
    }

    async fn renew_lease(
        &self,
        action_id: &ActionId,
        worker_id: &str,
        lease_id: &str,
        lease_ttl_ms: u64,
        now: OffsetDateTime,
    ) -> RuntimeResult<Option<QueuedActionRecord>> {
        let Some(mut record) = self
            .queue_record(action_id)
            .await
            .map_err(postgres_runtime_error)?
        else {
            return Ok(None);
        };
        if record
            .lease
            .as_ref()
            .is_none_or(|lease| lease.worker_id != worker_id || lease.lease_id != lease_id)
        {
            return Ok(None);
        }
        extend_lease(&mut record, lease_ttl_ms, now);
        let value = serde_json::to_value(&record).map_err(postgres_runtime_error)?;
        let updated = query::<Postgres>(
            r#"
            UPDATE aip_queue
            SET lease_expires_at_ms = $2, updated_at_ms = $3, record = $4
            WHERE action_id = $1
              AND status = 'running'
              AND record #>> '{lease,lease_id}' = $5
            "#,
        )
        .bind(action_id.as_str())
        .bind(
            record
                .lease
                .as_ref()
                .map(|lease| timestamp_ms(lease.expires_at)),
        )
        .bind(timestamp_ms(record.updated_at))
        .bind(value)
        .bind(lease_id)
        .execute(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        Ok((updated.rows_affected() == 1).then_some(record))
    }

    async fn release_lease(
        &self,
        action_id: &ActionId,
        worker_id: &str,
        lease_id: &str,
    ) -> RuntimeResult<()> {
        self.mutate_queue_record(action_id, |record| {
            let owns_lease = record
                .lease
                .as_ref()
                .is_some_and(|lease| lease.worker_id == worker_id && lease.lease_id == lease_id);
            if owns_lease {
                record.lease = None;
                record.status = QueuedActionStatus::Queued;
                record.updated_at = OffsetDateTime::now_utc();
            }
            (owns_lease, ())
        })
        .await?;
        Ok(())
    }

    async fn complete_attempt(
        &self,
        action_id: &ActionId,
        lease_id: &str,
        outcome: QueueAttemptOutcome,
    ) -> RuntimeResult<QueueCompletion> {
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let row = query::<Postgres>("SELECT record FROM aip_queue WHERE action_id = $1 FOR UPDATE")
            .bind(action_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(postgres_runtime_error)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(QueueCompletion::LeaseLost);
        };
        let mut record: QueuedActionRecord =
            decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                .map_err(|error| RuntimeError::Storage(error.to_string()))?;
        if record.status == QueuedActionStatus::Cancelled {
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(QueueCompletion::Cancelled);
        }
        if record
            .lease
            .as_ref()
            .is_none_or(|lease| lease.lease_id != lease_id)
        {
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(QueueCompletion::LeaseLost);
        }
        let mut dead_letter = None;
        match outcome {
            QueueAttemptOutcome::Retry(mut scheduled) => {
                scheduled.lease = None;
                record = scheduled;
            }
            QueueAttemptOutcome::Settle(result) => {
                let error = result.error.clone();
                record.status = queued_status_from_result(result.status);
                record.result = Some(result);
                record.next_attempt_at = None;
                record.last_error = error;
                record.lease = None;
                record.updated_at = OffsetDateTime::now_utc();
            }
            QueueAttemptOutcome::DeadLetter(value) => {
                record.status = QueuedActionStatus::Failed;
                record.dead_letter_reason = Some(value.error.message.clone());
                record.last_error = Some(value.error.clone());
                record.next_attempt_at = None;
                record.lease = None;
                record.updated_at = OffsetDateTime::now_utc();
                dead_letter = Some(value);
            }
        }
        query::<Postgres>(
            r#"
            UPDATE aip_queue
            SET status = $2, lease_expires_at_ms = NULL, updated_at_ms = $3, record = $4
            WHERE action_id = $1
            "#,
        )
        .bind(action_id.as_str())
        .bind(status_label(record.status))
        .bind(timestamp_ms(record.updated_at))
        .bind(
            serde_json::to_value(&record)
                .map_err(|error| RuntimeError::Storage(error.to_string()))?,
        )
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        if let Some(dead_letter) = dead_letter {
            query::<Postgres>(
                "INSERT INTO aip_dead_letters (action_id, record, failed_at_ms) VALUES ($1, $2, $3)",
            )
            .bind(action_id.as_str())
            .bind(serde_json::to_value(&dead_letter).map_err(|error| {
                RuntimeError::Storage(error.to_string())
            })?)
            .bind(timestamp_ms(dead_letter.failed_at))
            .execute(&mut *transaction)
            .await
            .map_err(postgres_runtime_error)?;
        }
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(QueueCompletion::Applied)
    }

    async fn settle(&self, result: ActionResult) -> RuntimeResult<()> {
        let action_id = result.action_id.clone();
        self.mutate_queue_record(&action_id, |record| {
            let error = result.error.clone();
            record.status = queued_status_from_result(result.status);
            record.result = Some(result);
            record.next_attempt_at = None;
            record.last_error = error;
            record.lease = None;
            record.updated_at = OffsetDateTime::now_utc();
            (true, ())
        })
        .await?;
        Ok(())
    }

    async fn expire(&self, result: ActionResult) -> RuntimeResult<()> {
        let action_id = result.action_id.clone();
        self.mutate_queue_record(&action_id, |record| {
            let error = result.error.clone();
            record.status = QueuedActionStatus::Expired;
            record.result = Some(result);
            record.next_attempt_at = None;
            record.last_error = error;
            record.lease = None;
            record.updated_at = OffsetDateTime::now_utc();
            (true, ())
        })
        .await?;
        Ok(())
    }

    async fn cancel(&self, action_id: &ActionId, reason: Option<String>) -> RuntimeResult<()> {
        self.mutate_queue_record(action_id, |record| {
            record.status = QueuedActionStatus::Cancelled;
            record.cancellation_reason = reason;
            record.next_attempt_at = None;
            record.lease = None;
            record.updated_at = OffsetDateTime::now_utc();
            (true, ())
        })
        .await?;
        Ok(())
    }

    async fn increment_attempts(
        &self,
        action_id: &ActionId,
    ) -> RuntimeResult<Option<QueuedActionRecord>> {
        self.mutate_queue_record(action_id, |record| {
            let now = OffsetDateTime::now_utc();
            record.attempts = record.attempts.saturating_add(1);
            record.first_attempted_at.get_or_insert(now);
            record.last_attempted_at = Some(now);
            record.next_attempt_at = None;
            record.last_error = None;
            record.updated_at = now;
            (true, record.clone())
        })
        .await
    }

    async fn dead_letter(&self, dead_letter: DeadLetterRecord) -> RuntimeResult<()> {
        let action_id = dead_letter.record.action.id.clone();
        let mut queued = dead_letter.record.clone();
        queued.status = QueuedActionStatus::Failed;
        queued.dead_letter_reason = Some(dead_letter.error.message.clone());
        queued.last_error = Some(dead_letter.error.clone());
        queued.next_attempt_at = None;
        queued.lease = None;
        queued.updated_at = OffsetDateTime::now_utc();
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        query::<Postgres>(
            r#"
            UPDATE aip_queue
            SET status = 'failed', lease_expires_at_ms = NULL,
                updated_at_ms = $2, record = $3
            WHERE action_id = $1
            "#,
        )
        .bind(action_id.as_str())
        .bind(timestamp_ms(queued.updated_at))
        .bind(serde_json::to_value(&queued).map_err(postgres_runtime_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        query::<Postgres>(
            "INSERT INTO aip_dead_letters (action_id, record, failed_at_ms) VALUES ($1, $2, $3)",
        )
        .bind(action_id.as_str())
        .bind(serde_json::to_value(&dead_letter).map_err(postgres_runtime_error)?)
        .bind(timestamp_ms(dead_letter.failed_at))
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        transaction.commit().await.map_err(postgres_runtime_error)
    }

    async fn dead_letters(&self) -> RuntimeResult<Vec<DeadLetterRecord>> {
        let rows = query::<Postgres>(
            r#"
            SELECT record
            FROM aip_dead_letters
            ORDER BY seq
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        rows.into_iter()
            .map(|row| {
                let value = row.try_get("record").map_err(postgres_runtime_error)?;
                decode_value(value).map_err(postgres_runtime_error)
            })
            .collect()
    }

    async fn recoverable(&self) -> RuntimeResult<Vec<QueuedActionRecord>> {
        let rows = query::<Postgres>(
            r#"
            SELECT record
            FROM aip_queue
            WHERE status IN ('queued', 'running')
            ORDER BY created_at_ms
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let record = decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)?;
            if action_is_leaseable(&record, OffsetDateTime::now_utc()) {
                records.push(record);
            }
        }
        Ok(records)
    }

    async fn get(&self, action_id: &ActionId) -> RuntimeResult<Option<QueuedActionRecord>> {
        self.queue_record(action_id)
            .await
            .map_err(postgres_runtime_error)
    }

    async fn list(&self) -> RuntimeResult<Vec<QueuedActionRecord>> {
        let rows = query::<Postgres>(
            r#"
            SELECT record
            FROM aip_queue
            ORDER BY created_at_ms
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        rows.into_iter()
            .map(|row| {
                let value = row.try_get("record").map_err(postgres_runtime_error)?;
                decode_value(value).map_err(postgres_runtime_error)
            })
            .collect()
    }
}

#[async_trait]
impl CallbackDeliveryBackend for PostgresRuntimeStore {
    async fn upsert(&self, record: CallbackDeliveryStateRecord) -> RuntimeResult<()> {
        query::<Postgres>(
            r#"
            INSERT INTO aip_callback_deliveries (
                delivery_id, action_id, status, profile, target, tenant_id,
                next_attempt_at_ms, lease_expires_at_ms, updated_at_ms, record
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (delivery_id) DO UPDATE SET
                action_id = EXCLUDED.action_id,
                status = EXCLUDED.status,
                profile = EXCLUDED.profile,
                target = EXCLUDED.target,
                tenant_id = EXCLUDED.tenant_id,
                next_attempt_at_ms = EXCLUDED.next_attempt_at_ms,
                lease_expires_at_ms = EXCLUDED.lease_expires_at_ms,
                updated_at_ms = EXCLUDED.updated_at_ms,
                record = EXCLUDED.record
            "#,
        )
        .bind(&record.view.delivery_id)
        .bind(record.view.action_id.as_ref().map(ActionId::as_str))
        .bind(callback_status_label(record.view.status))
        .bind(record.view.policy.target.profile.as_str())
        .bind(&record.view.policy.target.target)
        .bind(record.view.tenant_id.as_deref())
        .bind(record.view.next_attempt_at.map(timestamp_ms))
        .bind(record.view.lease_expires_at.map(timestamp_ms))
        .bind(timestamp_ms(record.view.updated_at))
        .bind(serde_json::to_value(&record).map_err(postgres_runtime_error)?)
        .execute(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        Ok(())
    }

    async fn get(&self, delivery_id: &str) -> RuntimeResult<Option<CallbackDeliveryStateRecord>> {
        let row =
            query::<Postgres>("SELECT record FROM aip_callback_deliveries WHERE delivery_id = $1")
                .bind(delivery_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(postgres_runtime_error)?;
        row.map(|row| {
            decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)
        })
        .transpose()
    }

    async fn list(&self) -> RuntimeResult<Vec<CallbackDeliveryStateRecord>> {
        let rows =
            query::<Postgres>("SELECT record FROM aip_callback_deliveries ORDER BY updated_at_ms")
                .fetch_all(&self.pool)
                .await
                .map_err(postgres_runtime_error)?;
        rows.into_iter()
            .map(|row| {
                decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                    .map_err(postgres_runtime_error)
            })
            .collect()
    }

    async fn recoverable(
        &self,
        now: OffsetDateTime,
    ) -> RuntimeResult<Vec<CallbackDeliveryStateRecord>> {
        let rows = query::<Postgres>(
            r#"
            SELECT record FROM aip_callback_deliveries
            WHERE status NOT IN ('delivered', 'dead_lettered')
              AND (next_attempt_at_ms IS NULL OR next_attempt_at_ms <= $1)
              AND (lease_expires_at_ms IS NULL OR lease_expires_at_ms <= $1)
            ORDER BY updated_at_ms
            "#,
        )
        .bind(timestamp_ms(now))
        .fetch_all(&self.pool)
        .await
        .map_err(postgres_runtime_error)?;
        Ok(rows
            .into_iter()
            .map(|row| {
                decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                    .map_err(postgres_runtime_error)
            })
            .collect::<RuntimeResult<Vec<CallbackDeliveryStateRecord>>>()?
            .into_iter()
            .filter(|record| callback_delivery_is_recoverable(record, now))
            .collect())
    }

    async fn claim_recoverable(
        &self,
        worker_id: &str,
        lease_ttl_ms: u64,
        now: OffsetDateTime,
        limit: usize,
    ) -> RuntimeResult<Vec<CallbackDeliveryStateRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            RuntimeError::Storage("callback recovery batch exceeds PostgreSQL i64".to_owned())
        })?;
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let rows = query::<Postgres>(
            r#"
            SELECT delivery_id, record
            FROM aip_callback_deliveries
            WHERE status NOT IN ('delivered', 'dead_lettered')
              AND (next_attempt_at_ms IS NULL OR next_attempt_at_ms <= $1)
              AND (lease_expires_at_ms IS NULL OR lease_expires_at_ms <= $1)
            ORDER BY updated_at_ms
            FOR UPDATE SKIP LOCKED
            LIMIT $2
            "#,
        )
        .bind(timestamp_ms(now))
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        let mut claimed = Vec::new();
        for row in rows {
            let delivery_id: String = row.try_get("delivery_id").map_err(postgres_runtime_error)?;
            let value: Value = row.try_get("record").map_err(postgres_runtime_error)?;
            let mut record: CallbackDeliveryStateRecord =
                decode_value(value).map_err(postgres_runtime_error)?;
            if !callback_delivery_is_recoverable(&record, now) {
                continue;
            }
            lease_callback_delivery(&mut record, worker_id, lease_ttl_ms, now);
            query::<Postgres>(
                r#"
                UPDATE aip_callback_deliveries
                SET status = $2, lease_expires_at_ms = $3,
                    record = $4, updated_at_ms = $5
                WHERE delivery_id = $1
                "#,
            )
            .bind(&delivery_id)
            .bind(callback_status_label(record.view.status))
            .bind(record.view.lease_expires_at.map(timestamp_ms))
            .bind(serde_json::to_value(&record).map_err(postgres_runtime_error)?)
            .bind(now_ms())
            .execute(&mut *transaction)
            .await
            .map_err(postgres_runtime_error)?;
            claimed.push(record);
        }
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(claimed)
    }
}

impl PostgresRuntimeStore {
    async fn mutate_queue_record<T, F>(
        &self,
        action_id: &ActionId,
        mutate: F,
    ) -> RuntimeResult<Option<T>>
    where
        T: Send,
        F: FnOnce(&mut QueuedActionRecord) -> (bool, T) + Send,
    {
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let row = query::<Postgres>("SELECT record FROM aip_queue WHERE action_id = $1 FOR UPDATE")
            .bind(action_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(postgres_runtime_error)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(None);
        };
        let mut record: QueuedActionRecord =
            decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)?;
        let (changed, output) = mutate(&mut record);
        if changed {
            query::<Postgres>(
                r#"
                UPDATE aip_queue
                SET status = $2,
                    lease_expires_at_ms = $3,
                    updated_at_ms = $4,
                    record = $5
                WHERE action_id = $1
                "#,
            )
            .bind(action_id.as_str())
            .bind(status_label(record.status))
            .bind(
                record
                    .lease
                    .as_ref()
                    .map(|lease| timestamp_ms(lease.expires_at)),
            )
            .bind(timestamp_ms(record.updated_at))
            .bind(serde_json::to_value(&record).map_err(postgres_runtime_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(postgres_runtime_error)?;
        }
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(Some(output))
    }

    async fn queue_record(
        &self,
        action_id: &ActionId,
    ) -> PostgresStorageResult<Option<QueuedActionRecord>> {
        let row = query::<Postgres>(
            r#"
            SELECT record
            FROM aip_queue
            WHERE action_id = $1
            "#,
        )
        .bind(action_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| decode_value(row.try_get("record")?))
            .transpose()
    }

    async fn upsert_queue_record(&self, record: &QueuedActionRecord) -> RuntimeResult<()> {
        let mut transaction = self.pool.begin().await.map_err(postgres_runtime_error)?;
        let inserted = query::<Postgres>(
            r#"
            INSERT INTO aip_queue (
                action_id,
                status,
                lease_expires_at_ms,
                created_at_ms,
                updated_at_ms,
                record
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (action_id)
            DO NOTHING
            "#,
        )
        .bind(record.action.id.as_str())
        .bind(status_label(record.status))
        .bind(
            record
                .lease
                .as_ref()
                .map(|lease| timestamp_ms(lease.expires_at)),
        )
        .bind(timestamp_ms(record.created_at))
        .bind(timestamp_ms(record.updated_at))
        .bind(serde_json::to_value(record).map_err(postgres_runtime_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        if inserted.rows_affected() == 1 {
            transaction.commit().await.map_err(postgres_runtime_error)?;
            return Ok(());
        }

        let row = query::<Postgres>(
            r#"
            SELECT record
            FROM aip_queue
            WHERE action_id = $1
            FOR UPDATE
            "#,
        )
        .bind(record.action.id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        let existing: QueuedActionRecord =
            decode_value(row.try_get("record").map_err(postgres_runtime_error)?)
                .map_err(postgres_runtime_error)?;
        validate_queued_action_replacement(&existing, record)?;

        query::<Postgres>(
            r#"
            UPDATE aip_queue
            SET status = $2,
                lease_expires_at_ms = $3,
                updated_at_ms = $4,
                record = $5
            WHERE action_id = $1
            "#,
        )
        .bind(record.action.id.as_str())
        .bind(status_label(record.status))
        .bind(
            record
                .lease
                .as_ref()
                .map(|lease| timestamp_ms(lease.expires_at)),
        )
        .bind(timestamp_ms(record.updated_at))
        .bind(serde_json::to_value(record).map_err(postgres_runtime_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(postgres_runtime_error)?;
        transaction.commit().await.map_err(postgres_runtime_error)?;
        Ok(())
    }
}

fn decode_value<T>(value: Value) -> PostgresStorageResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_value(value).map_err(PostgresStorageError::Json)
}

fn profile_state_entry_from_row(row: &PgRow) -> RuntimeResult<ProfileStateEntry> {
    let revision: i64 = row.try_get("revision").map_err(postgres_runtime_error)?;
    let revision = u64::try_from(revision).map_err(|_| {
        RuntimeError::Storage("stored profile state revision is negative".to_owned())
    })?;
    let updated_at_ms: i64 = row
        .try_get("updated_at_ms")
        .map_err(postgres_runtime_error)?;
    let updated_at = OffsetDateTime::from_unix_timestamp_nanos(
        i128::from(updated_at_ms).saturating_mul(1_000_000),
    )
    .map_err(postgres_runtime_error)?;
    Ok(ProfileStateEntry {
        namespace: row.try_get("namespace").map_err(postgres_runtime_error)?,
        key: row.try_get("key").map_err(postgres_runtime_error)?,
        value: row.try_get("value").map_err(postgres_runtime_error)?,
        revision,
        updated_at,
    })
}

fn timestamp_ms(timestamp: OffsetDateTime) -> i64 {
    let millis = timestamp.unix_timestamp_nanos() / 1_000_000;
    millis.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn postgres_runtime_error(error: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::Storage(error.to_string())
}

fn now_ms() -> i64 {
    timestamp_ms(OffsetDateTime::now_utc())
}

fn storage_key(prefix: &str, timestamp_ms: i64) -> String {
    format!("{prefix}:{timestamp_ms}")
}

fn parse_event_cursor(cursor: &str) -> Option<i64> {
    cursor
        .strip_prefix("pg_evt_")
        .unwrap_or(cursor)
        .parse::<i64>()
        .ok()
}

fn parse_event_cursor_checked(cursor: &str) -> Result<i64, Box<ProtocolError>> {
    let Some(value) = cursor.strip_prefix("pg_evt_") else {
        return Err(Box::new(ProtocolError {
            code: "query.invalid_cursor".to_owned(),
            message: format!("event cursor `{cursor}` must use `pg_evt_<seq>` format"),
            category: ErrorCategory::Permanent,
            retryable: Some(false),
            retry_after_ms: None,
            details: Some(Box::new(json!({
                "cursor": cursor,
                "expected_prefix": "pg_evt_"
            }))),
            source: Some(Box::new(json!({ "component": "aip-storage-postgres" }))),
        }));
    };
    value.parse::<i64>().map_err(|_| {
        Box::new(ProtocolError {
            code: "query.invalid_cursor".to_owned(),
            message: format!("event cursor `{cursor}` contains a non-numeric sequence"),
            category: ErrorCategory::Permanent,
            retryable: Some(false),
            retry_after_ms: None,
            details: Some(Box::new(json!({ "cursor": cursor }))),
            source: Some(Box::new(json!({ "component": "aip-storage-postgres" }))),
        })
    })
}

fn format_event_cursor(seq: i64) -> String {
    format!("pg_evt_{seq}")
}

fn status_label(status: QueuedActionStatus) -> &'static str {
    match status {
        QueuedActionStatus::Queued => "queued",
        QueuedActionStatus::Running => "running",
        QueuedActionStatus::Completed => "completed",
        QueuedActionStatus::Failed => "failed",
        QueuedActionStatus::Cancelled => "cancelled",
        QueuedActionStatus::RequiresHuman => "requires_human",
        QueuedActionStatus::Expired => "expired",
    }
}

fn queued_status_from_result(status: aip_core::ActionResultStatus) -> QueuedActionStatus {
    match status {
        aip_core::ActionResultStatus::Completed => QueuedActionStatus::Completed,
        aip_core::ActionResultStatus::Failed => QueuedActionStatus::Failed,
        aip_core::ActionResultStatus::Cancelled => QueuedActionStatus::Cancelled,
        aip_core::ActionResultStatus::PendingApproval
        | aip_core::ActionResultStatus::RequiresHuman => QueuedActionStatus::RequiresHuman,
    }
}

fn action_is_leaseable(record: &QueuedActionRecord, now: OffsetDateTime) -> bool {
    matches!(
        record.status,
        QueuedActionStatus::Queued | QueuedActionStatus::Running
    ) && record
        .next_attempt_at
        .is_none_or(|retry_at| retry_at <= now)
        && record
            .lease
            .as_ref()
            .is_none_or(|lease| lease.expires_at <= now)
}

fn callback_delivery_is_recoverable(
    record: &CallbackDeliveryStateRecord,
    now: OffsetDateTime,
) -> bool {
    if matches!(
        record.view.status,
        CallbackDeliveryStatus::Delivered | CallbackDeliveryStatus::DeadLettered
    ) {
        return false;
    }
    if record.view.attempts.len() as u32 >= record.view.policy.max_attempts.max(1) {
        return false;
    }
    if record
        .view
        .lease_expires_at
        .is_some_and(|lease_expires_at| lease_expires_at > now)
    {
        return false;
    }
    record
        .view
        .next_attempt_at
        .is_none_or(|next_attempt_at| next_attempt_at <= now)
}

fn lease_callback_delivery(
    record: &mut CallbackDeliveryStateRecord,
    worker_id: &str,
    lease_ttl_ms: u64,
    now: OffsetDateTime,
) {
    record.view.leased_by = Some(worker_id.to_owned());
    record.view.lease_expires_at =
        Some(now + time::Duration::milliseconds(lease_ttl_ms.max(1) as i64));
    record.view.updated_at = now;
}

fn approval_outbox_id(approval_id: &ApprovalId) -> String {
    format!("approval:{approval_id}:decision")
}

fn approval_status_label(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Pending => "pending",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Denied => "denied",
        ApprovalStatus::Expired => "expired",
        ApprovalStatus::Revoked => "revoked",
    }
}

fn transaction_status_label(status: aip_runtime::TransactionStatus) -> &'static str {
    match status {
        aip_runtime::TransactionStatus::DryRunCompleted => "dry_run_completed",
        aip_runtime::TransactionStatus::Planned => "planned",
        aip_runtime::TransactionStatus::Prepared => "prepared",
        aip_runtime::TransactionStatus::Committing => "committing",
        aip_runtime::TransactionStatus::Committed => "committed",
        aip_runtime::TransactionStatus::Compensating => "compensating",
        aip_runtime::TransactionStatus::Compensated => "compensated",
        aip_runtime::TransactionStatus::Failed => "failed",
        aip_runtime::TransactionStatus::OutcomeUnknown => "outcome_unknown",
        aip_runtime::TransactionStatus::Reconciling => "reconciling",
        aip_runtime::TransactionStatus::Reconciled => "reconciled",
        aip_runtime::TransactionStatus::RollbackNotSupported => "rollback_not_supported",
    }
}

fn callback_status_label(status: CallbackDeliveryStatus) -> &'static str {
    match status {
        CallbackDeliveryStatus::Pending => "pending",
        CallbackDeliveryStatus::Running => "running",
        CallbackDeliveryStatus::Delivered => "delivered",
        CallbackDeliveryStatus::Failed => "failed",
        CallbackDeliveryStatus::DeadLettered => "dead_lettered",
    }
}

fn transaction_plan_id(record: &TransactionRecord) -> Option<String> {
    record
        .plan
        .as_ref()
        .map(|plan| plan.plan_id.clone())
        .or_else(|| record.transaction.plan_id.clone())
}

fn apply_lease(
    record: &mut QueuedActionRecord,
    worker_id: &str,
    lease_ttl_ms: u64,
    now: OffsetDateTime,
) {
    record.status = QueuedActionStatus::Running;
    record.next_attempt_at = None;
    record.updated_at = now;
    record.lease = Some(ActionLease {
        worker_id: worker_id.to_owned(),
        lease_id: format!("lease:{}:{}", worker_id, now.unix_timestamp_nanos()),
        acquired_at: now,
        expires_at: now + time::Duration::milliseconds(lease_ttl_ms.max(1) as i64),
    });
}

fn extend_lease(record: &mut QueuedActionRecord, lease_ttl_ms: u64, now: OffsetDateTime) {
    if let Some(lease) = record.lease.as_mut() {
        lease.expires_at = now + time::Duration::milliseconds(lease_ttl_ms.max(1) as i64);
        record.updated_at = now;
    }
}
