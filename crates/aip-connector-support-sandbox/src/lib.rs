//! Postgres-backed support sandbox connector for production-grade AIP E2E tests.
//!
//! The connector exposes deterministic customer-support and billing operations
//! over AIP. It is intentionally backed by a real PostgreSQL database so agent
//! tests retrieve business facts through capabilities instead of prompt text or
//! model memory. Mutating operations use database transactions, row locks,
//! product-side approval state, audit events, and idempotency keys.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_connector::{
    CapabilityImplementationSupport, CapabilityProviderConnector, Connector, ConnectorContext,
    ConnectorError, ConnectorFailure, ConnectorHealth, ConnectorOperation, ConnectorResult,
    FrozenConnector, OutboundConnector,
};
use aip_core::{
    Action, ActionId, ActionResult, ActionResultStatus, ApprovalDecisionKind, ApprovalPolicy,
    ApproverSelector, Binding, Capability, CapabilityContract, CapabilityId, CapabilityKind,
    CompensationContract, CompensationMode, DataContract, DataSensitivity, DryRunFidelity,
    ErrorCategory, EvidenceRequirement, ExecutionContract, ExpectedCompletionMode,
    IdempotencyCollisionBehavior, IdempotencyContract, IdempotencyKeyScope, IdempotencyRequirement,
    Manifest, MessagePart, Principal, PrincipalId, PrincipalKind, ProfileId, ProtocolError,
    RetrySafety, RiskLevel, ServiceLevelContract, SideEffect, Stability, TransactionContract,
    TransactionMode,
};
use aip_runtime::{ActionExecutionContext, ActionHandler, RuntimeError, RuntimeResult};
use async_trait::async_trait;
use serde_json::{Map, Value, json};
use sqlx_core::{Error as SqlxError, query::query, row::Row};
use sqlx_postgres::{PgPool, PgPoolOptions, Postgres};
use thiserror::Error;

/// Stable connector id.
pub const CONNECTOR_ID: &str = "support-sandbox";

/// AIP profile id for support sandbox-specific capability metadata.
pub const PROFILE_ID: &str = "aip.connector.support_sandbox.v1";

/// Support case lookup capability.
pub const SUPPORT_CASE_GET_CAPABILITY_ID: &str = "cap:support_sandbox:support.case.get";
/// Customer lookup capability.
pub const SUPPORT_CUSTOMER_LOOKUP_CAPABILITY_ID: &str =
    "cap:support_sandbox:support.customer.lookup";
/// Duplicate charge detection capability.
pub const BILLING_DUPLICATE_CHARGE_DETECT_CAPABILITY_ID: &str =
    "cap:support_sandbox:billing.duplicate_charge.detect";
/// Refund policy evaluation capability.
pub const REFUND_POLICY_EVALUATE_CAPABILITY_ID: &str = "cap:support_sandbox:refund.policy.evaluate";
/// Refund planning capability.
pub const REFUND_PLAN_CAPABILITY_ID: &str = "cap:support_sandbox:refund.plan";
/// Approval request creation capability.
pub const APPROVAL_REQUEST_CREATE_CAPABILITY_ID: &str =
    "cap:support_sandbox:approval.request.create";
/// Product-side approval decision recording capability.
pub const APPROVAL_DECISION_RECORD_CAPABILITY_ID: &str =
    "cap:support_sandbox:approval.decision.record";
/// Refund commitment capability.
pub const REFUND_COMMIT_CAPABILITY_ID: &str = "cap:support_sandbox:refund.commit";

const MCP_PROFILE_ID: &str = "aip.mcp.compat.v1";
const NATIVE_HTTP_PROFILE_ID: &str = "aip.native.http.v1";
const DEFAULT_APPROVAL_TTL_MINUTES: i64 = 15;
const MAX_APPROVAL_TTL_SECONDS: i64 = 24 * 60 * 60;

/// Support sandbox connector backed by a PostgreSQL pool.
#[derive(Clone, Debug)]
pub struct SupportSandboxConnector {
    pool: PgPool,
}

impl SupportSandboxConnector {
    /// Opens a PostgreSQL-backed support sandbox connector.
    pub async fn connect(database_url: &str) -> Result<Self, SupportSandboxError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;
        let connector = Self { pool };
        connector.verify_schema().await?;
        Ok(connector)
    }

    /// Creates a connector from an existing PostgreSQL pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns the underlying PostgreSQL pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Verifies that the expected sandbox schema is installed.
    pub async fn verify_schema(&self) -> Result<(), SupportSandboxError> {
        let row = query::<Postgres>(
            r#"
            SELECT
                to_regclass('support.case_triage_context') IS NOT NULL AS has_case_context,
                to_regclass('billing.duplicate_charge_candidates') IS NOT NULL AS has_duplicates,
                to_regclass('billing.refunds') IS NOT NULL AS has_refunds,
                to_regclass('approval.approval_requests') IS NOT NULL AS has_approvals
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        for field in [
            "has_case_context",
            "has_duplicates",
            "has_refunds",
            "has_approvals",
        ] {
            if !row.try_get::<bool, _>(field)? {
                return Err(SupportSandboxError::Schema(format!(
                    "support sandbox schema check failed for `{field}`"
                )));
            }
        }
        Ok(())
    }

    /// Builds the connector manifest.
    pub fn discover_manifest(&self) -> Result<Manifest, SupportSandboxError> {
        support_sandbox_manifest()
    }

    async fn execute(
        &self,
        action: &Action,
        execution: Option<&ActionExecutionContext>,
    ) -> Result<Value, SupportSandboxError> {
        let operation = SupportSandboxOperation::from_capability(&action.capability_id)?;
        match operation {
            SupportSandboxOperation::SupportCaseGet => self.support_case_get(action).await,
            SupportSandboxOperation::SupportCustomerLookup => {
                self.support_customer_lookup(action).await
            }
            SupportSandboxOperation::BillingDuplicateChargeDetect => {
                self.billing_duplicate_charge_detect(action).await
            }
            SupportSandboxOperation::RefundPolicyEvaluate => {
                self.refund_policy_evaluate(action).await
            }
            SupportSandboxOperation::RefundPlan => self.refund_plan(action, execution).await,
            SupportSandboxOperation::ApprovalRequestCreate => {
                self.approval_request_create(action).await
            }
            SupportSandboxOperation::ApprovalDecisionRecord => {
                self.approval_decision_record(action).await
            }
            SupportSandboxOperation::RefundCommit => self.refund_commit(action, execution).await,
        }
    }

    async fn support_case_get(&self, action: &Action) -> Result<Value, SupportSandboxError> {
        let case_id = required_text(&action.input, "case_id")?;
        let row = query::<Postgres>(
            r#"
            SELECT to_jsonb(ctx) AS data
            FROM support.case_triage_context ctx
            WHERE ctx.case_id = $1
            "#,
        )
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Err(protocol_error(
                "support.case.not_found",
                format!("support case `{case_id}` was not found"),
                ErrorCategory::Permanent,
                json!({ "case_id": case_id }),
            ));
        };
        Ok(json!({
            "case": row.try_get::<Value, _>("data")?,
            "source": "support.case_triage_context"
        }))
    }

    async fn support_customer_lookup(&self, action: &Action) -> Result<Value, SupportSandboxError> {
        let customer_id = optional_text(&action.input, "customer_id");
        let email = optional_text(&action.input, "email");
        let external_ref = optional_text(&action.input, "external_ref");
        if customer_id.is_none() && email.is_none() && external_ref.is_none() {
            return Err(protocol_error(
                "support.customer.lookup_key_required",
                "customer lookup requires customer_id, email, or external_ref",
                ErrorCategory::Permanent,
                json!({ "input": action.input }),
            ));
        }
        let row = query::<Postgres>(
            r#"
            SELECT to_jsonb(c) AS data
            FROM support.customers c
            WHERE ($1::text IS NULL OR c.customer_id = $1)
              AND ($2::text IS NULL OR c.email = $2)
              AND ($3::text IS NULL OR c.external_ref = $3)
            ORDER BY c.created_at DESC
            LIMIT 1
            "#,
        )
        .bind(customer_id)
        .bind(email)
        .bind(external_ref)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Err(protocol_error(
                "support.customer.not_found",
                "customer was not found",
                ErrorCategory::Permanent,
                json!({ "input": action.input }),
            ));
        };
        Ok(json!({
            "customer": row.try_get::<Value, _>("data")?
        }))
    }

    async fn billing_duplicate_charge_detect(
        &self,
        action: &Action,
    ) -> Result<Value, SupportSandboxError> {
        let case_id = required_text(&action.input, "case_id")?;
        let row = query::<Postgres>(
            r#"
            WITH case_customer AS (
                SELECT customer_id
                FROM support.cases
                WHERE case_id = $1
            ),
            candidates AS (
                SELECT
                    d.customer_id,
                    d.order_id,
                    d.amount_cents,
                    d.currency,
                    d.successful_charge_count,
                    d.charge_ids,
                    d.charge_ids[array_upper(d.charge_ids, 1)] AS recommended_refund_charge_id,
                    d.first_captured_at,
                    d.last_captured_at
                FROM billing.duplicate_charge_candidates d
                JOIN case_customer cc ON cc.customer_id = d.customer_id
            )
            SELECT coalesce(jsonb_agg(to_jsonb(candidates)), '[]'::jsonb) AS duplicates
            FROM candidates
            "#,
        )
        .bind(case_id)
        .fetch_one(&self.pool)
        .await?;
        let duplicates = row.try_get::<Value, _>("duplicates")?;
        Ok(json!({
            "case_id": case_id,
            "duplicate_charge_candidates": duplicates,
            "duplicate_count": duplicates.as_array().map_or(0, Vec::len)
        }))
    }

    async fn refund_policy_evaluate(&self, action: &Action) -> Result<Value, SupportSandboxError> {
        let case_id = required_text(&action.input, "case_id")?;
        let charge_id = optional_text(&action.input, "charge_id");
        let row = query::<Postgres>(
            r#"
            WITH case_customer AS (
                SELECT case_id, customer_id
                FROM support.cases
                WHERE case_id = $1
            ),
            target_charge AS (
                SELECT ch.*
                FROM billing.charges ch
                JOIN case_customer cc ON cc.customer_id = ch.customer_id
                WHERE ($2::text IS NULL OR ch.charge_id = $2)
                ORDER BY ch.captured_at DESC
                LIMIT 1
            ),
            active_policy AS (
                SELECT *
                FROM policy.refund_policies
                WHERE active
                ORDER BY version DESC
                LIMIT 1
            )
            SELECT jsonb_build_object(
                'case_id', cc.case_id,
                'charge_id', tc.charge_id,
                'customer_id', tc.customer_id,
                'order_id', tc.order_id,
                'amount_cents', tc.amount_cents,
                'currency', tc.currency,
                'charge_status', tc.status,
                'policy_id', ap.policy_id,
                'requires_human_approval', ap.requires_human_approval,
                'rollback_supported', ap.rollback_supported,
                'eligible', tc.status = 'succeeded',
                'reason', CASE
                    WHEN tc.status = 'succeeded' THEN 'duplicate_charge'
                    ELSE 'charge_not_refundable'
                END
            ) AS evaluation
            FROM case_customer cc
            JOIN target_charge tc ON true
            JOIN active_policy ap ON true
            "#,
        )
        .bind(case_id)
        .bind(charge_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Err(protocol_error(
                "refund.policy.no_target",
                "no refundable charge target was found for the case",
                ErrorCategory::Permanent,
                json!({ "case_id": case_id, "charge_id": charge_id }),
            ));
        };
        Ok(row.try_get::<Value, _>("evaluation")?)
    }

    async fn refund_plan(
        &self,
        action: &Action,
        execution: Option<&ActionExecutionContext>,
    ) -> Result<Value, SupportSandboxError> {
        let case_id = required_text(&action.input, "case_id")?;
        let charge_id = required_text(&action.input, "charge_id")?;
        let reason = optional_text(&action.input, "reason").unwrap_or("duplicate_charge");
        let idempotency_key = action_idempotency_key(action)?;
        let refund_id = optional_text(&action.input, "refund_id")
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("rf:{idempotency_key}"));
        let approval_request_id = optional_text(&action.input, "approval_request_id")
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("appr:{idempotency_key}"));
        let approval_ttl_seconds = approval_ttl_seconds(&action.input)?;
        let requested_by = action_principal_label(action, "agent:unknown");
        let mut tx = self.pool.begin().await?;
        let target = query::<Postgres>(
            r#"
            SELECT
                c.case_id,
                c.customer_id,
                ch.charge_id,
                ch.amount_cents,
                ch.currency,
                p.policy_id,
                p.requires_human_approval,
                p.rollback_supported
            FROM support.cases c
            JOIN billing.charges ch ON ch.customer_id = c.customer_id
            JOIN policy.refund_policies p ON p.active
            WHERE c.case_id = $1
              AND ch.charge_id = $2
              AND ch.status = 'succeeded'
            ORDER BY p.version DESC
            LIMIT 1
            "#,
        )
        .bind(case_id)
        .bind(charge_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(target) = target else {
            return Err(protocol_error(
                "refund.plan.invalid_target",
                "refund plan target must be a succeeded charge belonging to the case customer",
                ErrorCategory::Permanent,
                json!({ "case_id": case_id, "charge_id": charge_id }),
            ));
        };
        let customer_id = target.try_get::<String, _>("customer_id")?;
        let amount_cents = target.try_get::<i32, _>("amount_cents")?;
        let currency = target.try_get::<String, _>("currency")?;
        let policy_id = target.try_get::<String, _>("policy_id")?;
        let requires_approval = target.try_get::<bool, _>("requires_human_approval")?;
        let rollback_supported = target.try_get::<bool, _>("rollback_supported")?;

        if let Some(existing) = query::<Postgres>(
            r#"
            SELECT to_jsonb(r) AS refund
            FROM billing.refunds r
            WHERE r.idempotency_key = $1
            FOR UPDATE
            "#,
        )
        .bind(&idempotency_key)
        .fetch_optional(&mut *tx)
        .await?
        {
            let refund = existing.try_get::<Value, _>("refund")?;
            assert_existing_refund_matches(&refund, case_id, charge_id, amount_cents, &currency)?;
            query::<Postgres>(
                r#"
                INSERT INTO audit.events (event_type, actor_principal, subject_ref, payload)
                VALUES (
                    'refund.plan.idempotent_replay',
                    $1,
                    $2,
                    jsonb_build_object('refund_id', $3, 'idempotency_key', $4)
                )
                "#,
            )
            .bind(requested_by)
            .bind(format!("case:{case_id}"))
            .bind(refund.get("refund_id").and_then(Value::as_str))
            .bind(&idempotency_key)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(json!({
                "refund": refund,
                "idempotent_replay": true,
                "policy": {
                    "policy_id": policy_id,
                    "requires_human_approval": requires_approval,
                    "rollback_supported": rollback_supported
                }
            }));
        }

        query::<Postgres>(
            r#"
            INSERT INTO approval.approval_requests (
                approval_request_id,
                case_id,
                requested_by_principal,
                approver_principal,
                action_id,
                status,
                reason,
                evidence,
                expires_at
            ) VALUES (
                $1,
                $2,
                $3,
                'human:billing-manager',
                $4,
                'requested',
                $5,
                jsonb_build_object(
                    'case_id', $2,
                    'charge_id', $6,
                    'amount_cents', $7,
                    'currency', $8,
                    'policy_id', $9,
                    'idempotency_key', $10
                ),
                now() + ($11::bigint * interval '1 second')
            )
            "#,
        )
        .bind(&approval_request_id)
        .bind(case_id)
        .bind(requested_by)
        .bind(action.id.to_string())
        .bind("Duplicate charge refund requires human approval before commitment.")
        .bind(charge_id)
        .bind(amount_cents)
        .bind(&currency)
        .bind(&policy_id)
        .bind(&idempotency_key)
        .bind(approval_ttl_seconds)
        .execute(&mut *tx)
        .await?;
        let refund = query::<Postgres>(
            r#"
            INSERT INTO billing.refunds (
                refund_id,
                charge_id,
                customer_id,
                case_id,
                amount_cents,
                currency,
                status,
                idempotency_key,
                approval_request_id,
                reason,
                metadata
            ) VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                'blocked_for_approval',
                $7,
                $8,
                $9,
                jsonb_build_object('policy_id', $10, 'aip_action_id', $11)
            )
            RETURNING to_jsonb(billing.refunds.*) AS refund
            "#,
        )
        .bind(&refund_id)
        .bind(charge_id)
        .bind(&customer_id)
        .bind(case_id)
        .bind(amount_cents)
        .bind(&currency)
        .bind(&idempotency_key)
        .bind(&approval_request_id)
        .bind(reason)
        .bind(&policy_id)
        .bind(action.id.to_string())
        .fetch_one(&mut *tx)
        .await?
        .try_get::<Value, _>("refund")?;
        query::<Postgres>(
            r#"
            UPDATE support.cases
            SET status = 'pending_approval', updated_at = now()
            WHERE case_id = $1
            "#,
        )
        .bind(case_id)
        .execute(&mut *tx)
        .await?;
        query::<Postgres>(
            r#"
            INSERT INTO audit.events (event_type, actor_principal, subject_ref, payload)
            VALUES (
                'refund.plan.created',
                $1,
                $2,
                jsonb_build_object(
                    'refund_id', $3,
                    'approval_request_id', $4,
                    'charge_id', $5,
                    'amount_cents', $6,
                    'currency', $7,
                    'policy_id', $8,
                    'idempotency_key', $9
                )
            )
            "#,
        )
        .bind(requested_by)
        .bind(format!("case:{case_id}"))
        .bind(&refund_id)
        .bind(&approval_request_id)
        .bind(charge_id)
        .bind(amount_cents)
        .bind(&currency)
        .bind(&policy_id)
        .bind(&idempotency_key)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        if let Some(execution) = execution {
            execution
                .execution_checkpoints
                .provider_effect_committed()
                .await;
        }
        Ok(json!({
            "refund": refund,
            "approval_request": {
                "approval_request_id": approval_request_id,
                "status": "requested",
                "approver_principal": "human:billing-manager",
                "ttl_seconds": approval_ttl_seconds
            },
            "policy": {
                "policy_id": policy_id,
                "requires_human_approval": requires_approval,
                "rollback_supported": rollback_supported
            },
            "idempotent_replay": false
        }))
    }

    async fn approval_request_create(&self, action: &Action) -> Result<Value, SupportSandboxError> {
        let case_id = required_text(&action.input, "case_id")?;
        let approval_request_id = optional_text(&action.input, "approval_request_id")
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("appr:{}", action.id));
        let requested_by = optional_text(&action.input, "requested_by_principal")
            .unwrap_or_else(|| action_principal_label(action, "agent:unknown"));
        let reason = optional_text(&action.input, "reason").unwrap_or("approval requested");
        let approval_ttl_seconds = approval_ttl_seconds(&action.input)?;
        let evidence = action
            .input
            .get("evidence")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let row = query::<Postgres>(
            r#"
            INSERT INTO approval.approval_requests (
                approval_request_id,
                case_id,
                requested_by_principal,
                approver_principal,
                action_id,
                status,
                reason,
                evidence,
                expires_at
            ) VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                'requested',
                $6,
                $7,
                now() + ($8::bigint * interval '1 second')
            )
            ON CONFLICT (approval_request_id)
            DO UPDATE SET approval_request_id = EXCLUDED.approval_request_id
            RETURNING to_jsonb(approval.approval_requests.*) AS approval_request
            "#,
        )
        .bind(&approval_request_id)
        .bind(case_id)
        .bind(requested_by)
        .bind(optional_text(&action.input, "approver_principal").unwrap_or("human:billing-manager"))
        .bind(action.id.to_string())
        .bind(reason)
        .bind(evidence)
        .bind(approval_ttl_seconds)
        .fetch_one(&self.pool)
        .await?;
        Ok(json!({
            "approval_request": row.try_get::<Value, _>("approval_request")?
        }))
    }

    async fn approval_decision_record(
        &self,
        action: &Action,
    ) -> Result<Value, SupportSandboxError> {
        let approval_request_id = required_text(&action.input, "approval_request_id")?;
        let decision = required_text(&action.input, "decision")?;
        let normalized_status = match decision {
            "approved" | "granted" | "approve" | "grant" => "granted",
            "denied" | "deny" => "denied",
            "expired" => "expired",
            other => {
                return Err(protocol_error(
                    "approval.decision.invalid",
                    format!("unsupported approval decision `{other}`"),
                    ErrorCategory::Permanent,
                    json!({ "decision": other }),
                ));
            }
        };
        let approver =
            optional_text(&action.input, "approver_principal").unwrap_or("human:billing-manager");
        let reason = optional_text(&action.input, "reason").unwrap_or("decision recorded");
        let mut tx = self.pool.begin().await?;
        let row = query::<Postgres>(
            r#"
            UPDATE approval.approval_requests
            SET
                status = $2,
                approver_principal = $3,
                decided_at = now()
            WHERE approval_request_id = $1
              AND status IN ('requested', 'granted', 'denied', 'expired')
            RETURNING to_jsonb(approval.approval_requests.*) AS approval_request
            "#,
        )
        .bind(approval_request_id)
        .bind(normalized_status)
        .bind(approver)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Err(protocol_error(
                "approval.request.not_found",
                format!("approval request `{approval_request_id}` was not found"),
                ErrorCategory::Permanent,
                json!({ "approval_request_id": approval_request_id }),
            ));
        };
        if normalized_status == "granted" {
            query::<Postgres>(
                r#"
                UPDATE billing.refunds
                SET status = 'approved'
                WHERE approval_request_id = $1
                  AND status = 'blocked_for_approval'
                "#,
            )
            .bind(approval_request_id)
            .execute(&mut *tx)
            .await?;
        }
        query::<Postgres>(
            r#"
            INSERT INTO audit.events (event_type, actor_principal, subject_ref, payload)
            VALUES (
                'approval.decision.recorded',
                $1,
                $2,
                jsonb_build_object(
                    'approval_request_id', $3,
                    'decision', $4,
                    'reason', $5,
                    'aip_action_id', $6
                )
            )
            "#,
        )
        .bind(approver)
        .bind(format!("approval:{approval_request_id}"))
        .bind(approval_request_id)
        .bind(normalized_status)
        .bind(reason)
        .bind(action.id.to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(json!({
            "approval_request": row.try_get::<Value, _>("approval_request")?,
            "decision": normalized_status
        }))
    }

    async fn refund_commit(
        &self,
        action: &Action,
        execution: Option<&ActionExecutionContext>,
    ) -> Result<Value, SupportSandboxError> {
        let approval = action.approval.as_ref().ok_or_else(|| {
            protocol_error(
                "refund.commit.aip_approval_required",
                "refund commitment requires approved AIP approval metadata",
                ErrorCategory::Policy,
                json!({ "capability_id": action.capability_id }),
            )
        })?;
        if approval.decision != ApprovalDecisionKind::Approved {
            return Err(protocol_error(
                "refund.commit.aip_approval_not_approved",
                "refund commitment requires an approved AIP approval decision",
                ErrorCategory::Policy,
                json!({ "decision": approval.decision }),
            ));
        }
        let idempotency_key = action_idempotency_key(action)?;
        let refund_id = optional_text(&action.input, "refund_id");
        let mut tx = self.pool.begin().await?;
        let refund_row = query::<Postgres>(
            r#"
            SELECT
                r.refund_id,
                r.charge_id,
                r.customer_id,
                r.case_id,
                r.amount_cents,
                r.currency,
                r.status,
                r.idempotency_key,
                r.approval_request_id,
                to_jsonb(r) AS refund
            FROM billing.refunds r
            WHERE ($1::text IS NULL OR r.refund_id = $1)
              AND r.idempotency_key = $2
            FOR UPDATE
            "#,
        )
        .bind(refund_id)
        .bind(&idempotency_key)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(refund_row) = refund_row else {
            return Err(protocol_error(
                "refund.commit.plan_not_found",
                "refund commit requires an existing refund plan with the same idempotency key",
                ErrorCategory::Permanent,
                json!({ "refund_id": refund_id, "idempotency_key": idempotency_key }),
            ));
        };
        let status = refund_row.try_get::<String, _>("status")?;
        let refund_id = refund_row.try_get::<String, _>("refund_id")?;
        let charge_id = refund_row.try_get::<String, _>("charge_id")?;
        let case_id = refund_row.try_get::<String, _>("case_id")?;
        let approval_request_id = refund_row.try_get::<String, _>("approval_request_id")?;
        if status == "committed" {
            tx.commit().await?;
            return Ok(json!({
                "refund": refund_row.try_get::<Value, _>("refund")?,
                "idempotent_replay": true,
                "committed": true
            }));
        }
        let approval_row = query::<Postgres>(
            r#"
            SELECT status, expires_at <= now() AS expired
            FROM approval.approval_requests
            WHERE approval_request_id = $1
            FOR UPDATE
            "#,
        )
        .bind(&approval_request_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(approval_row) = approval_row else {
            return Err(protocol_error(
                "refund.commit.product_approval_missing",
                "product-side approval request was not found",
                ErrorCategory::Policy,
                json!({ "approval_request_id": approval_request_id }),
            ));
        };
        let approval_status = approval_row.try_get::<String, _>("status")?;
        let approval_expired = approval_row.try_get::<bool, _>("expired")?;
        if approval_status != "granted" || approval_expired {
            return Err(protocol_error(
                "refund.commit.product_approval_not_granted",
                "product-side approval must be granted and unexpired before refund commitment",
                ErrorCategory::Policy,
                json!({
                    "approval_request_id": approval_request_id,
                    "status": approval_status,
                    "expired": approval_expired
                }),
            ));
        }
        let committed_refund = query::<Postgres>(
            r#"
            UPDATE billing.refunds
            SET status = 'committed', committed_at = now()
            WHERE refund_id = $1
            RETURNING to_jsonb(billing.refunds.*) AS refund
            "#,
        )
        .bind(&refund_id)
        .fetch_one(&mut *tx)
        .await?
        .try_get::<Value, _>("refund")?;
        query::<Postgres>(
            r#"
            UPDATE billing.charges
            SET status = 'refunded'
            WHERE charge_id = $1
            "#,
        )
        .bind(&charge_id)
        .execute(&mut *tx)
        .await?;
        query::<Postgres>(
            r#"
            UPDATE support.cases
            SET status = 'resolved', updated_at = now()
            WHERE case_id = $1
            "#,
        )
        .bind(&case_id)
        .execute(&mut *tx)
        .await?;
        query::<Postgres>(
            r#"
            INSERT INTO audit.events (event_type, actor_principal, subject_ref, payload)
            VALUES (
                'refund.commit.committed',
                $1,
                $2,
                jsonb_build_object(
                    'refund_id', $3,
                    'charge_id', $4,
                    'case_id', $5,
                    'approval_request_id', $6,
                    'aip_approval_id', $7,
                    'idempotency_key', $8,
                    'aip_action_id', $9
                )
            )
            "#,
        )
        .bind(approval.approver.id.to_string())
        .bind(format!("case:{case_id}"))
        .bind(&refund_id)
        .bind(&charge_id)
        .bind(&case_id)
        .bind(&approval_request_id)
        .bind(approval.approval_id.to_string())
        .bind(&idempotency_key)
        .bind(action.id.to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        if let Some(execution) = execution {
            execution
                .execution_checkpoints
                .provider_effect_committed()
                .await;
        }
        Ok(json!({
            "refund": committed_refund,
            "committed": true,
            "idempotent_replay": false,
            "side_effects": ["financial", "write"],
            "rollback_supported": false
        }))
    }
}

/// Support sandbox connector error.
#[derive(Debug, Error)]
pub enum SupportSandboxError {
    /// SQLx reported a database error.
    #[error("support sandbox database failed: {0}")]
    Sql(#[from] SqlxError),
    /// Required schema is missing.
    #[error("support sandbox schema is not ready: {0}")]
    Schema(String),
    /// A principal, capability, or profile id was invalid.
    #[error("invalid AIP id: {0}")]
    InvalidId(aip_core::IdParseError),
    /// Capability is not owned by this connector.
    #[error("unsupported support sandbox capability `{0}`")]
    UnsupportedCapability(String),
    /// Structured action input is invalid.
    #[error("invalid support sandbox input: {0}")]
    InvalidInput(String),
    /// Product policy returned a protocol error.
    #[error("protocol error: {0:?}")]
    Protocol(Box<ProtocolError>),
}

#[async_trait]
impl Connector for SupportSandboxConnector {
    fn id(&self) -> &str {
        CONNECTOR_ID
    }

    async fn discover(&self, _context: &ConnectorContext) -> ConnectorResult<Manifest> {
        self.discover_manifest()
            .map_err(|error| ConnectorError::Discovery(error.to_string()))
    }

    fn map_error(&self, error: &ConnectorError) -> ProtocolError {
        ProtocolError {
            code: "connector.support_sandbox.error".to_owned(),
            message: error.to_string(),
            category: ErrorCategory::Connector,
            retryable: Some(false),
            retry_after_ms: None,
            details: None,
            source: Some(Box::new(json!({ "connector": CONNECTOR_ID }))),
        }
    }

    async fn health(&self, _context: &ConnectorContext) -> ConnectorResult<ConnectorHealth> {
        self.verify_schema()
            .await
            .map_err(|error| ConnectorError::Discovery(error.to_string()))?;
        Ok(ConnectorHealth {
            ready: true,
            detail: "support sandbox database schema is available".to_owned(),
        })
    }
}

#[async_trait]
impl CapabilityProviderConnector for SupportSandboxConnector {
    async fn capabilities(&self, _context: &ConnectorContext) -> ConnectorResult<Vec<Capability>> {
        Ok(support_sandbox_capabilities())
    }
}

#[async_trait]
impl OutboundConnector for SupportSandboxConnector {
    async fn invoke(
        &self,
        _context: &ConnectorContext,
        action: Action,
    ) -> ConnectorResult<ActionResult> {
        match self.execute(&action, None).await {
            Ok(output) => Ok(completed_result(action, output)),
            Err(SupportSandboxError::Protocol(error)) => Ok(failed_result(action.id, *error)),
            Err(error) => Err(ConnectorError::Invoke(error.to_string())),
        }
    }

    async fn emit(
        &self,
        _context: &ConnectorContext,
        _result: ActionResult,
    ) -> ConnectorResult<()> {
        Ok(())
    }
}

#[async_trait]
impl ActionHandler for SupportSandboxConnector {
    async fn handle(&self, action: Action) -> RuntimeResult<ActionResult> {
        self.invoke(&ConnectorContext::default(), action)
            .await
            .map_err(|error| RuntimeError::Handler(error.to_string()))
    }

    async fn handle_with_context(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> RuntimeResult<ActionResult> {
        match self.execute(&action, Some(&context)).await {
            Ok(output) => Ok(completed_result(action, output)),
            Err(SupportSandboxError::Protocol(error)) => Ok(failed_result(action.id, *error)),
            Err(error) => Err(RuntimeError::Handler(error.to_string())),
        }
    }
}

#[async_trait]
impl FrozenConnector for SupportSandboxConnector {
    fn implementation_support(&self, capability: &Capability) -> CapabilityImplementationSupport {
        support_sandbox_implementation_support(capability)
    }

    async fn invoke_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        <Self as ActionHandler>::handle_with_context(self, action, context)
            .await
            .map_err(|error| {
                ConnectorFailure::from_runtime_error(
                    error,
                    ConnectorOperation::Invocation,
                    self.id(),
                )
            })
    }

    async fn plan_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        if SupportSandboxOperation::from_capability(&action.capability_id).ok()
            != Some(SupportSandboxOperation::RefundPlan)
        {
            return Err(ConnectorFailure::unsupported(
                ConnectorOperation::TransactionPlan,
                self.id(),
            ));
        }
        if action
            .transaction
            .as_ref()
            .map(|transaction| transaction.mode)
            == Some(TransactionMode::DryRun)
        {
            return Ok(completed_result(
                action,
                json!({
                    "transaction": "dry_run",
                    "validated": true,
                    "fidelity": "policy_and_schema",
                    "external_side_effects": false
                }),
            ));
        }
        <Self as ActionHandler>::handle_with_context(self, action, context)
            .await
            .map_err(|error| {
                ConnectorFailure::from_runtime_error(
                    error,
                    ConnectorOperation::TransactionPlan,
                    self.id(),
                )
            })
    }

    async fn commit_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        if SupportSandboxOperation::from_capability(&action.capability_id).ok()
            != Some(SupportSandboxOperation::RefundCommit)
        {
            return Err(ConnectorFailure::unsupported(
                ConnectorOperation::TransactionCommit,
                self.id(),
            ));
        }
        <Self as ActionHandler>::handle_with_context(self, action, context)
            .await
            .map_err(|error| {
                ConnectorFailure::from_runtime_error(
                    error,
                    ConnectorOperation::TransactionCommit,
                    self.id(),
                )
            })
    }
}

/// Returns the exact runtime-support declaration used to qualify this release.
///
/// Keeping this calculation independent from a database connection lets the
/// release pipeline bind conformance evidence to the same claims that the
/// running connector host publishes.
#[must_use]
pub fn support_sandbox_implementation_support(
    capability: &Capability,
) -> CapabilityImplementationSupport {
    let operation = SupportSandboxOperation::from_capability(&capability.id).ok();
    let transactional = matches!(
        operation,
        Some(SupportSandboxOperation::RefundPlan | SupportSandboxOperation::RefundCommit)
    );
    CapabilityImplementationSupport {
        invocation: operation.is_some(),
        cancellation: false,
        streaming: false,
        retry: operation.is_some(),
        transaction: transactional,
        reconciliation: false,
        compensation: false,
        approval: operation == Some(SupportSandboxOperation::RefundCommit),
        credentials: false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SupportSandboxOperation {
    SupportCaseGet,
    SupportCustomerLookup,
    BillingDuplicateChargeDetect,
    RefundPolicyEvaluate,
    RefundPlan,
    ApprovalRequestCreate,
    ApprovalDecisionRecord,
    RefundCommit,
}

impl SupportSandboxOperation {
    fn from_capability(id: &CapabilityId) -> Result<Self, SupportSandboxError> {
        match id.as_str() {
            SUPPORT_CASE_GET_CAPABILITY_ID => Ok(Self::SupportCaseGet),
            SUPPORT_CUSTOMER_LOOKUP_CAPABILITY_ID => Ok(Self::SupportCustomerLookup),
            BILLING_DUPLICATE_CHARGE_DETECT_CAPABILITY_ID => Ok(Self::BillingDuplicateChargeDetect),
            REFUND_POLICY_EVALUATE_CAPABILITY_ID => Ok(Self::RefundPolicyEvaluate),
            REFUND_PLAN_CAPABILITY_ID => Ok(Self::RefundPlan),
            APPROVAL_REQUEST_CREATE_CAPABILITY_ID => Ok(Self::ApprovalRequestCreate),
            APPROVAL_DECISION_RECORD_CAPABILITY_ID => Ok(Self::ApprovalDecisionRecord),
            REFUND_COMMIT_CAPABILITY_ID => Ok(Self::RefundCommit),
            other => Err(SupportSandboxError::UnsupportedCapability(other.to_owned())),
        }
    }
}

/// Returns all capabilities exposed by the support sandbox connector.
#[must_use]
pub fn support_sandbox_capabilities() -> Vec<Capability> {
    vec![
        capability(CapabilitySpec {
            id: SUPPORT_CASE_GET_CAPABILITY_ID,
            name: "Support case get",
            description: "Retrieves case, customer, order, and charge context for triage.",
            input_schema: json_schema_object(&["case_id"], [("case_id", "string")]),
            side_effects: vec![SideEffect::Read],
            risk: RiskLevel::Low,
            contract: read_contract(DataSensitivity::Confidential, true),
            mcp_name: "support_sandbox_support_case_get",
        }),
        capability(CapabilitySpec {
            id: SUPPORT_CUSTOMER_LOOKUP_CAPABILITY_ID,
            name: "Support customer lookup",
            description: "Looks up a customer by customer id, email, or external reference.",
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "customer_id": { "type": "string" },
                    "email": { "type": "string" },
                    "external_ref": { "type": "string" }
                },
                "anyOf": [
                    { "required": ["customer_id"] },
                    { "required": ["email"] },
                    { "required": ["external_ref"] }
                ]
            }),
            side_effects: vec![SideEffect::Read],
            risk: RiskLevel::Low,
            contract: read_contract(DataSensitivity::Confidential, true),
            mcp_name: "support_sandbox_customer_lookup",
        }),
        capability(CapabilitySpec {
            id: BILLING_DUPLICATE_CHARGE_DETECT_CAPABILITY_ID,
            name: "Billing duplicate charge detect",
            description: "Detects duplicate succeeded charges for the case customer.",
            input_schema: json_schema_object(&["case_id"], [("case_id", "string")]),
            side_effects: vec![SideEffect::Read, SideEffect::Financial],
            risk: RiskLevel::Medium,
            contract: read_contract(DataSensitivity::Regulated, true),
            mcp_name: "support_sandbox_billing_duplicate_charge_detect",
        }),
        capability(CapabilitySpec {
            id: REFUND_POLICY_EVALUATE_CAPABILITY_ID,
            name: "Refund policy evaluate",
            description: "Evaluates refund eligibility, approval requirement, and rollback policy.",
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["case_id"],
                "properties": {
                    "case_id": { "type": "string" },
                    "charge_id": { "type": "string" }
                }
            }),
            side_effects: vec![SideEffect::Read, SideEffect::Financial, SideEffect::Legal],
            risk: RiskLevel::Medium,
            contract: read_contract(DataSensitivity::Regulated, true),
            mcp_name: "support_sandbox_refund_policy_evaluate",
        }),
        capability(CapabilitySpec {
            id: REFUND_PLAN_CAPABILITY_ID,
            name: "Refund plan",
            description: "Creates an idempotent blocked refund plan and product-side approval request.",
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["case_id", "charge_id"],
                "properties": {
                    "case_id": { "type": "string" },
                    "charge_id": { "type": "string" },
                    "reason": { "type": "string" },
                    "refund_id": { "type": "string" },
                    "approval_request_id": { "type": "string" },
                    "idempotency_key": { "type": "string" },
                    "approval_ttl_seconds": { "type": "integer", "minimum": 1 },
                    "approval_ttl_minutes": { "type": "integer", "minimum": 1 }
                }
            }),
            side_effects: vec![SideEffect::Read, SideEffect::Write, SideEffect::Financial],
            risk: RiskLevel::Medium,
            contract: financial_plan_contract(false),
            mcp_name: "support_sandbox_refund_plan",
        }),
        capability(CapabilitySpec {
            id: APPROVAL_REQUEST_CREATE_CAPABILITY_ID,
            name: "Approval request create",
            description: "Creates or replays a product-side approval request.",
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["case_id", "reason"],
                "properties": {
                    "case_id": { "type": "string" },
                    "approval_request_id": { "type": "string" },
                    "requested_by_principal": { "type": "string" },
                    "approver_principal": { "type": "string" },
                    "reason": { "type": "string" },
                    "evidence": { "type": "object" },
                    "idempotency_key": { "type": "string" },
                    "approval_ttl_seconds": { "type": "integer", "minimum": 1 },
                    "approval_ttl_minutes": { "type": "integer", "minimum": 1 }
                }
            }),
            side_effects: vec![SideEffect::Read, SideEffect::Write],
            risk: RiskLevel::Medium,
            contract: write_contract(DataSensitivity::Restricted, true, false),
            mcp_name: "support_sandbox_approval_request_create",
        }),
        capability(CapabilitySpec {
            id: APPROVAL_DECISION_RECORD_CAPABILITY_ID,
            name: "Approval decision record",
            description: "Records a product-side approval decision and updates blocked refunds.",
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["approval_request_id", "decision"],
                "properties": {
                    "approval_request_id": { "type": "string" },
                    "decision": { "type": "string", "enum": ["granted", "approved", "denied", "expired"] },
                    "approver_principal": { "type": "string" },
                    "reason": { "type": "string" },
                    "idempotency_key": { "type": "string" }
                }
            }),
            side_effects: vec![SideEffect::Read, SideEffect::Write, SideEffect::Legal],
            risk: RiskLevel::Medium,
            contract: write_contract(DataSensitivity::Restricted, true, false),
            mcp_name: "support_sandbox_approval_decision_record",
        }),
        capability(CapabilitySpec {
            id: REFUND_COMMIT_CAPABILITY_ID,
            name: "Refund commit",
            description: "Commits an approved refund exactly once and marks the duplicate charge refunded.",
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "refund_id": { "type": "string" },
                    "idempotency_key": { "type": "string" }
                }
            }),
            side_effects: vec![SideEffect::Read, SideEffect::Write, SideEffect::Financial],
            risk: RiskLevel::Critical,
            contract: financial_commit_contract(),
            mcp_name: "support_sandbox_refund_commit",
        }),
    ]
}

/// Builds the support sandbox manifest without opening a database connection.
///
/// The manifest is pure connector metadata. Runtime methods still require a
/// PostgreSQL-backed [`SupportSandboxConnector`], but conformance suites can use
/// this function to verify RFC 0003 adapter/profile boundary rules without
/// depending on product data availability.
pub fn support_sandbox_manifest() -> Result<Manifest, SupportSandboxError> {
    Ok(Manifest {
        manifest_version: "aip-manifest/v1".to_owned(),
        agent: Principal::new(
            PrincipalId::parse("agent:support_sandbox:connector")
                .map_err(SupportSandboxError::InvalidId)?,
            PrincipalKind::Agent,
        ),
        capabilities: support_sandbox_capabilities(),
        profiles: vec![
            ProfileId::from(NATIVE_HTTP_PROFILE_ID),
            ProfileId::from(MCP_PROFILE_ID),
            ProfileId::from(PROFILE_ID),
        ],
        resources: Vec::new(),
        channels: Vec::new(),
        security: Some(json!({
            "database": "postgres",
            "secrets": "database credentials are process configuration and never exposed in manifests",
            "idempotency": "financial mutations require Action.idempotency_key",
            "approval": "refund commits require AIP approval metadata plus product-side granted approval rows"
        })),
        governance: Some(json!({
            "scenario": "sierra_like_customer_support_triage",
            "data_classes": ["customer_pii", "billing", "financial", "approval", "audit"],
            "rollback_policy": "refund rollback is not supported after commitment"
        })),
        limits: Some(json!({
            "max_approval_ttl_minutes": DEFAULT_APPROVAL_TTL_MINUTES,
            "transaction_boundary": "single PostgreSQL transaction per mutating product operation"
        })),
        compatibility: Some(json!({
            "system": "support-sandbox-postgres",
            "connector": CONNECTOR_ID,
            "capabilities": support_sandbox_capabilities()
                .iter()
                .map(|capability| capability.id.as_str())
                .collect::<Vec<_>>()
        })),
        extensions: None,
    })
}

struct CapabilitySpec {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    input_schema: Value,
    side_effects: Vec<SideEffect>,
    risk: RiskLevel,
    contract: CapabilityContract,
    mcp_name: &'static str,
}

fn capability(spec: CapabilitySpec) -> Capability {
    let mut contract = spec.contract;
    contract.side_effects = spec.side_effects;
    Capability {
        id: CapabilityId::trusted(spec.id),
        name: spec.name.to_owned(),
        kind: CapabilityKind::Tool,
        input_schema: spec.input_schema,
        output_schema: Some(json!({ "type": "object" })),
        description: Some(spec.description.to_owned()),
        risk: Some(spec.risk),
        stability: Some(Stability::Stable),
        cost: None,
        auth: None,
        bindings: vec![
            Binding {
                profile: ProfileId::from(NATIVE_HTTP_PROFILE_ID),
                metadata: [
                    ("method".to_owned(), json!("POST")),
                    ("path".to_owned(), json!("/aip/v1/messages")),
                    ("message_type".to_owned(), json!("aip.core.v1.action")),
                ]
                .into_iter()
                .collect(),
            },
            Binding {
                profile: ProfileId::from(MCP_PROFILE_ID),
                metadata: [
                    ("name".to_owned(), json!(spec.mcp_name)),
                    ("taskSupport".to_owned(), json!("forbidden")),
                ]
                .into_iter()
                .collect(),
            },
            Binding {
                profile: ProfileId::from(PROFILE_ID),
                metadata: [
                    ("system".to_owned(), json!("support-sandbox-postgres")),
                    ("connector".to_owned(), json!(CONNECTOR_ID)),
                    ("operation".to_owned(), json!(spec.mcp_name)),
                ]
                .into_iter()
                .collect(),
            },
        ],
        requires_human_approval: contract.approval.as_ref().map(|approval| approval.required),
        contract: Some(contract),
    }
}

fn read_contract(sensitivity: DataSensitivity, contains_pii: bool) -> CapabilityContract {
    CapabilityContract {
        side_effects: vec![SideEffect::Read],
        idempotency: IdempotencyContract {
            requirement: IdempotencyRequirement::Optional,
            collision_behavior: IdempotencyCollisionBehavior::ReturnOriginalResult,
            key_scope: IdempotencyKeyScope::Capability,
            ttl_ms: None,
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: false,
            supports_streaming: false,
            supports_cancel: false,
            supports_retry: true,
            expected_completion: ExpectedCompletionMode::Sync,
            retry_safety: RetrySafety::Safe,
        },
        data: DataContract {
            sensitivity,
            contains_pii,
            redaction_required: contains_pii,
            residency: None,
            retention: None,
        },
        credentials: None,
        approval: None,
        sla: Some(ServiceLevelContract {
            expected_latency_ms: Some(100),
            timeout_ms: Some(2_000),
            async_expected: false,
            max_queue_delay_ms: Some(100),
            availability_target: Some("99.9%".to_owned()),
        }),
        transaction: None,
        compensation: Some(CompensationContract {
            mode: CompensationMode::NotRequired,
            compensation_capability_id: None,
            compensation_window_ms: None,
            requires_approval: false,
        }),
    }
}

fn write_contract(
    sensitivity: DataSensitivity,
    contains_pii: bool,
    approval_required: bool,
) -> CapabilityContract {
    CapabilityContract {
        side_effects: vec![SideEffect::Read, SideEffect::Write],
        idempotency: IdempotencyContract {
            requirement: IdempotencyRequirement::Required,
            collision_behavior: IdempotencyCollisionBehavior::RevalidateInputHash,
            key_scope: IdempotencyKeyScope::Capability,
            ttl_ms: Some(86_400_000),
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: false,
            supports_streaming: false,
            supports_cancel: false,
            supports_retry: true,
            expected_completion: ExpectedCompletionMode::Sync,
            retry_safety: RetrySafety::SafeWithIdempotencyKey,
        },
        data: DataContract {
            sensitivity,
            contains_pii,
            redaction_required: contains_pii,
            residency: None,
            retention: None,
        },
        credentials: None,
        approval: approval_required.then(|| {
            approval_policy(
                "mutating approval workflow operations require explicit tenant approval",
            )
        }),
        sla: Some(ServiceLevelContract {
            expected_latency_ms: Some(250),
            timeout_ms: Some(5_000),
            async_expected: false,
            max_queue_delay_ms: Some(500),
            availability_target: Some("99.9%".to_owned()),
        }),
        transaction: None,
        compensation: Some(CompensationContract {
            mode: CompensationMode::RollbackNotSupported,
            compensation_capability_id: None,
            compensation_window_ms: None,
            requires_approval: false,
        }),
    }
}

fn financial_plan_contract(approval_required: bool) -> CapabilityContract {
    let mut contract = write_contract(DataSensitivity::Regulated, true, approval_required);
    contract.transaction = Some(TransactionContract {
        supported_modes: vec![
            TransactionMode::Execute,
            TransactionMode::DryRun,
            TransactionMode::Plan,
        ],
        requires_plan_before_commit: false,
        dry_run_fidelity: DryRunFidelity::PolicyAndSchema,
    });
    contract.compensation = Some(CompensationContract {
        mode: CompensationMode::RollbackNotSupported,
        compensation_capability_id: None,
        compensation_window_ms: None,
        requires_approval: false,
    });
    contract
}

fn financial_commit_contract() -> CapabilityContract {
    let mut contract = write_contract(DataSensitivity::Regulated, true, true);
    contract.transaction = Some(TransactionContract {
        supported_modes: vec![TransactionMode::Execute, TransactionMode::Commit],
        requires_plan_before_commit: false,
        dry_run_fidelity: DryRunFidelity::PolicyAndSchema,
    });
    contract.compensation = Some(CompensationContract {
        mode: CompensationMode::RollbackNotSupported,
        compensation_capability_id: None,
        compensation_window_ms: None,
        requires_approval: false,
    });
    contract
}

fn approval_policy(reason: &str) -> ApprovalPolicy {
    ApprovalPolicy {
        required: true,
        reason: Some(reason.to_owned()),
        approver_selector: ApproverSelector::TenantPolicy,
        ttl_ms: Some((DEFAULT_APPROVAL_TTL_MINUTES * 60_000) as u64),
        evidence_requirements: vec![
            EvidenceRequirement::Reason,
            EvidenceRequirement::InputSnapshot,
            EvidenceRequirement::PolicyDecision,
            EvidenceRequirement::ExternalTicket,
        ],
        delegated_authority: None,
        ..ApprovalPolicy::default()
    }
}

fn json_schema_object<const N: usize>(required: &[&str], fields: [(&str, &str); N]) -> Value {
    let mut properties = Map::new();
    for (name, field_type) in fields {
        properties.insert(name.to_owned(), json!({ "type": field_type }));
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    })
}

fn required_text<'a>(input: &'a Value, key: &'static str) -> Result<&'a str, SupportSandboxError> {
    optional_text(input, key).ok_or_else(|| {
        SupportSandboxError::InvalidInput(format!("missing required string `{key}`"))
    })
}

fn optional_text<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    input
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn approval_ttl_seconds(input: &Value) -> Result<i64, SupportSandboxError> {
    let seconds = optional_integer(input, "approval_ttl_seconds")?;
    let minutes = optional_integer(input, "approval_ttl_minutes")?;
    if seconds.is_some() && minutes.is_some() {
        return Err(protocol_error(
            "approval.ttl.ambiguous",
            "approval_ttl_seconds and approval_ttl_minutes are mutually exclusive",
            ErrorCategory::Permanent,
            json!({
                "approval_ttl_seconds": seconds,
                "approval_ttl_minutes": minutes
            }),
        ));
    }
    let ttl_seconds = match (seconds, minutes) {
        (Some(seconds), None) => seconds,
        (None, Some(minutes)) => minutes.checked_mul(60).ok_or_else(|| {
            protocol_error(
                "approval.ttl.overflow",
                "approval_ttl_minutes is too large",
                ErrorCategory::Permanent,
                json!({ "approval_ttl_minutes": minutes }),
            )
        })?,
        (None, None) => DEFAULT_APPROVAL_TTL_MINUTES * 60,
        (Some(_), Some(_)) => unreachable!("ambiguous TTL is rejected above"),
    };
    if !(1..=MAX_APPROVAL_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(protocol_error(
            "approval.ttl.invalid",
            "approval TTL must be between 1 second and 24 hours",
            ErrorCategory::Permanent,
            json!({
                "approval_ttl_seconds": ttl_seconds,
                "max_approval_ttl_seconds": MAX_APPROVAL_TTL_SECONDS
            }),
        ));
    }
    Ok(ttl_seconds)
}

fn optional_integer(input: &Value, key: &'static str) -> Result<Option<i64>, SupportSandboxError> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    value.as_i64().map(Some).ok_or_else(|| {
        protocol_error(
            "approval.ttl.invalid_type",
            format!("{key} must be an integer"),
            ErrorCategory::Permanent,
            json!({ key: value }),
        )
    })
}

fn action_idempotency_key(action: &Action) -> Result<String, SupportSandboxError> {
    action
        .idempotency_key
        .as_deref()
        .or_else(|| optional_text(&action.input, "idempotency_key"))
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            protocol_error(
                "idempotency.key_required",
                "financial support sandbox operation requires an AIP idempotency key",
                ErrorCategory::Policy,
                json!({ "capability_id": action.capability_id }),
            )
        })
}

fn action_principal_label<'a>(action: &'a Action, fallback: &'a str) -> &'a str {
    action
        .identity
        .as_ref()
        .and_then(|identity| identity.service_account.as_ref())
        .map(|principal| principal.id.as_str())
        .unwrap_or(fallback)
}

fn assert_existing_refund_matches(
    refund: &Value,
    case_id: &str,
    charge_id: &str,
    amount_cents: i32,
    currency: &str,
) -> Result<(), SupportSandboxError> {
    let matches = refund
        .get("case_id")
        .and_then(Value::as_str)
        .is_some_and(|value| value == case_id)
        && refund
            .get("charge_id")
            .and_then(Value::as_str)
            .is_some_and(|value| value == charge_id)
        && refund
            .get("amount_cents")
            .and_then(Value::as_i64)
            .is_some_and(|value| value == i64::from(amount_cents))
        && refund
            .get("currency")
            .and_then(Value::as_str)
            .is_some_and(|value| value == currency);
    if matches {
        Ok(())
    } else {
        Err(protocol_error(
            "idempotency.collision",
            "refund idempotency key already exists for different refund inputs",
            ErrorCategory::Policy,
            json!({
                "existing_refund": refund,
                "requested": {
                    "case_id": case_id,
                    "charge_id": charge_id,
                    "amount_cents": amount_cents,
                    "currency": currency
                }
            }),
        ))
    }
}

fn completed_result(action: Action, output: Value) -> ActionResult {
    ActionResult {
        action_id: action.id,
        status: ActionResultStatus::Completed,
        output: Some(output),
        message: Vec::new(),
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    }
}

fn failed_result(action_id: ActionId, error: ProtocolError) -> ActionResult {
    ActionResult {
        action_id,
        status: ActionResultStatus::Failed,
        output: None,
        message: vec![MessagePart::text(error.message.clone())],
        memory_update: None,
        usage: None,
        receipt: None,
        error: Some(error),
    }
}

fn protocol_error(
    code: impl Into<String>,
    message: impl Into<String>,
    category: ErrorCategory,
    details: Value,
) -> SupportSandboxError {
    SupportSandboxError::Protocol(Box::new(ProtocolError {
        code: code.into(),
        message: message.into(),
        category,
        retryable: Some(false),
        retry_after_ms: None,
        details: Some(Box::new(details)),
        source: Some(Box::new(json!({ "connector": CONNECTOR_ID }))),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_declares_enterprise_financial_contracts() {
        let capabilities = support_sandbox_capabilities();
        let commit = capabilities
            .iter()
            .find(|capability| capability.id.as_str() == REFUND_COMMIT_CAPABILITY_ID)
            .expect("commit capability");
        let contract = commit.contract.as_ref().expect("contract");
        assert_eq!(
            contract.idempotency.requirement,
            IdempotencyRequirement::Required
        );
        assert!(
            contract
                .approval
                .as_ref()
                .is_some_and(|approval| approval.required)
        );
        assert!(contract.side_effects.contains(&SideEffect::Financial));
        assert!(contract.compensation.as_ref().is_some_and(
            |compensation| compensation.mode == CompensationMode::RollbackNotSupported
        ));
    }

    #[test]
    fn all_capabilities_have_mcp_bindings() {
        for capability in support_sandbox_capabilities() {
            assert!(
                capability
                    .bindings
                    .iter()
                    .any(|binding| binding.profile.as_str() == MCP_PROFILE_ID),
                "{} missing MCP binding",
                capability.id
            );
        }
    }

    #[test]
    fn approval_ttl_seconds_defaults_to_contract_window() {
        assert_eq!(
            approval_ttl_seconds(&json!({})).expect("default ttl"),
            DEFAULT_APPROVAL_TTL_MINUTES * 60
        );
    }

    #[test]
    fn approval_ttl_seconds_accepts_short_mcp_test_window() {
        assert_eq!(
            approval_ttl_seconds(&json!({ "approval_ttl_seconds": 1 })).expect("ttl"),
            1
        );
        assert_eq!(
            approval_ttl_seconds(&json!({ "approval_ttl_minutes": 1 })).expect("ttl"),
            60
        );
    }

    #[test]
    fn approval_ttl_seconds_rejects_ambiguous_or_invalid_values() {
        assert!(approval_ttl_seconds(&json!({ "approval_ttl_seconds": 0 })).is_err());
        assert!(
            approval_ttl_seconds(&json!({ "approval_ttl_seconds": MAX_APPROVAL_TTL_SECONDS + 1 }))
                .is_err()
        );
        assert!(
            approval_ttl_seconds(&json!({ "approval_ttl_seconds": 1, "approval_ttl_minutes": 1 }))
                .is_err()
        );
        assert!(approval_ttl_seconds(&json!({ "approval_ttl_seconds": "1" })).is_err());
    }

    #[test]
    fn mutating_mcp_schemas_expose_ttl_and_idempotency_controls() {
        let capabilities = support_sandbox_capabilities();
        let refund_plan = capabilities
            .iter()
            .find(|capability| capability.id.as_str() == REFUND_PLAN_CAPABILITY_ID)
            .expect("refund plan capability");
        assert!(
            refund_plan
                .contract
                .as_ref()
                .and_then(|contract| contract.transaction.as_ref())
                .is_some_and(|transaction| transaction
                    .supported_modes
                    .contains(&TransactionMode::Plan))
        );
        assert!(
            refund_plan
                .input_schema
                .pointer("/properties/idempotency_key")
                .is_some()
        );
        assert!(
            refund_plan
                .input_schema
                .pointer("/properties/approval_ttl_seconds")
                .is_some()
        );
        assert!(
            refund_plan
                .input_schema
                .pointer("/properties/approval_ttl_minutes")
                .is_some()
        );

        let approval_request = capabilities
            .iter()
            .find(|capability| capability.id.as_str() == APPROVAL_REQUEST_CREATE_CAPABILITY_ID)
            .expect("approval request capability");
        assert!(
            approval_request
                .input_schema
                .pointer("/properties/approval_ttl_seconds")
                .is_some()
        );

        let approval_decision = capabilities
            .iter()
            .find(|capability| capability.id.as_str() == APPROVAL_DECISION_RECORD_CAPABILITY_ID)
            .expect("approval decision capability");
        assert!(
            approval_decision
                .input_schema
                .pointer("/properties/idempotency_key")
                .is_some()
        );
    }
}
