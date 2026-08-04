//! PostgreSQL-backed enterprise workflow connector used by AIP system tests.
//!
//! The connector exposes deterministic incident response, procurement,
//! privileged-access, and travel-rebooking systems of record. Every mutation
//! is transactional, idempotent, tenant-bound, auditable, and paired with an
//! explicit compensation capability. It exists to test AIP semantics against
//! durable business state rather than prompt fixtures or in-memory mocks.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_connector::{
    CapabilityImplementationSupport, CapabilityProviderConnector, Connector, ConnectorContext,
    ConnectorError, ConnectorFailure, ConnectorHealth, ConnectorOperation, ConnectorResult,
    FrozenConnector, OutboundConnector,
};
use aip_core::{
    Action, ActionId, ActionResult, ActionResultStatus, ApprovalPolicy, ApproverSelector, Binding,
    Capability, CapabilityContract, CapabilityId, CapabilityKind, CompensationContract,
    CompensationMode, DataContract, DataSensitivity, DryRunFidelity, ErrorCategory,
    EvidenceRequirement, ExecutionContract, ExpectedCompletionMode, IdempotencyCollisionBehavior,
    IdempotencyContract, IdempotencyKeyScope, IdempotencyRequirement, Manifest, MessagePart,
    Principal, PrincipalId, PrincipalKind, ProfileId, ProtocolError, RetrySafety, RiskLevel,
    ServiceLevelContract, SideEffect, Stability, TransactionContract, TransactionMode,
};
use aip_runtime::{ActionExecutionContext, ActionHandler, RuntimeError, RuntimeResult};
use async_trait::async_trait;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx_core::{Error as SqlxError, query::query, row::Row};
use sqlx_postgres::{PgPool, PgPoolOptions, Postgres};
use thiserror::Error;

/// Stable connector id.
pub const CONNECTOR_ID: &str = "enterprise-sandbox";
/// Connector-specific profile id.
pub const PROFILE_ID: &str = "aip.connector.enterprise_sandbox.v1";

/// Incident system-of-record read capability.
pub const INCIDENT_GET: &str = "cap:enterprise_sandbox:incident.get";
/// Incident mitigation planning capability.
pub const INCIDENT_PLAN: &str = "cap:enterprise_sandbox:incident.mitigation.plan";
/// Incident mitigation commit capability.
pub const INCIDENT_COMMIT: &str = "cap:enterprise_sandbox:incident.mitigation.commit";
/// Incident mitigation compensation capability.
pub const INCIDENT_COMPENSATE: &str = "cap:enterprise_sandbox:incident.mitigation.compensate";
/// Procurement request read capability.
pub const PROCUREMENT_GET: &str = "cap:enterprise_sandbox:procurement.request.get";
/// Purchase planning capability.
pub const PROCUREMENT_PLAN: &str = "cap:enterprise_sandbox:procurement.purchase.plan";
/// Purchase commit capability.
pub const PROCUREMENT_COMMIT: &str = "cap:enterprise_sandbox:procurement.purchase.commit";
/// Purchase compensation capability.
pub const PROCUREMENT_COMPENSATE: &str = "cap:enterprise_sandbox:procurement.purchase.compensate";
/// Privileged-access request read capability.
pub const ACCESS_GET: &str = "cap:enterprise_sandbox:access.request.get";
/// Privileged-access grant planning capability.
pub const ACCESS_PLAN: &str = "cap:enterprise_sandbox:access.grant.plan";
/// Privileged-access grant commit capability.
pub const ACCESS_COMMIT: &str = "cap:enterprise_sandbox:access.grant.commit";
/// Privileged-access revocation capability.
pub const ACCESS_COMPENSATE: &str = "cap:enterprise_sandbox:access.grant.revoke";
/// Travel disruption read capability.
pub const TRAVEL_GET: &str = "cap:enterprise_sandbox:travel.disruption.get";
/// Travel rebooking planning capability.
pub const TRAVEL_PLAN: &str = "cap:enterprise_sandbox:travel.rebooking.plan";
/// Travel rebooking commit capability.
pub const TRAVEL_COMMIT: &str = "cap:enterprise_sandbox:travel.rebooking.commit";
/// Travel rebooking compensation capability.
pub const TRAVEL_COMPENSATE: &str = "cap:enterprise_sandbox:travel.rebooking.compensate";

const MCP_PROFILE: &str = "aip.mcp.compat.v1";
const NATIVE_HTTP_PROFILE: &str = "aip.native.http.v1";

/// Durable enterprise sandbox connector.
#[derive(Clone, Debug)]
pub struct EnterpriseSandboxConnector {
    pool: PgPool,
}

impl EnterpriseSandboxConnector {
    /// Connects to a database containing the enterprise fixture schema.
    pub async fn connect(database_url: &str) -> Result<Self, EnterpriseSandboxError> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(database_url)
            .await?;
        let connector = Self { pool };
        connector.verify_schema().await?;
        Ok(connector)
    }

    /// Verifies the complete persistent schema before accepting traffic.
    pub async fn verify_schema(&self) -> Result<(), EnterpriseSandboxError> {
        let row = query::<Postgres>(
            "SELECT to_regclass('enterprise.workflows') IS NOT NULL AS workflows, \
                    to_regclass('enterprise.plans') IS NOT NULL AS plans, \
                    to_regclass('enterprise.audit_events') IS NOT NULL AS audit",
        )
        .fetch_one(&self.pool)
        .await?;
        for field in ["workflows", "plans", "audit"] {
            if !row.try_get::<bool, _>(field)? {
                return Err(EnterpriseSandboxError::Schema(format!(
                    "required relation `{field}` is missing"
                )));
            }
        }
        Ok(())
    }

    /// Returns connector discovery metadata.
    pub fn discover_manifest(&self) -> Result<Manifest, EnterpriseSandboxError> {
        enterprise_sandbox_manifest()
    }

    async fn execute(&self, action: &Action) -> Result<Value, EnterpriseSandboxError> {
        let operation = Operation::parse(&action.capability_id)?;
        match operation.phase {
            Phase::Get => self.get_workflow(action, operation.domain).await,
            Phase::Plan => self.plan(action, operation.domain).await,
            Phase::Commit => self.commit(action, operation.domain).await,
            Phase::Compensate => self.compensate(action, operation.domain).await,
        }
    }

    async fn get_workflow(
        &self,
        action: &Action,
        domain: Domain,
    ) -> Result<Value, EnterpriseSandboxError> {
        let workflow_id = required_text(&action.input, "workflow_id")?;
        let tenant_id = required_tenant(action)?;
        let row = query::<Postgres>(
            "SELECT workflow_id, domain, tenant_id, state, version, facts, updated_at::text AS updated_at \
             FROM enterprise.workflows \
             WHERE workflow_id = $1 AND domain = $2 AND tenant_id = $3",
        )
        .bind(workflow_id)
        .bind(domain.as_str())
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        let row = row.ok_or_else(|| {
            policy_error(
                "enterprise.workflow.not_found_or_forbidden",
                "workflow does not exist in the authenticated tenant",
                json!({ "workflow_id": workflow_id, "tenant_id": tenant_id }),
            )
        })?;
        workflow_json(&row)
    }

    async fn plan(&self, action: &Action, domain: Domain) -> Result<Value, EnterpriseSandboxError> {
        let workflow_id = required_text(&action.input, "workflow_id")?;
        let tenant_id = required_tenant(action)?;
        let idempotency_key = required_idempotency_key(action)?;
        let input_hash = input_hash(&action.input)?;
        let plan_id = optional_text(&action.input, "plan_id")
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("plan:{}:{idempotency_key}", domain.as_str()));
        let actor = actor_label(action);
        let mut tx = self.pool.begin().await?;
        let workflow = query::<Postgres>(
            "SELECT workflow_id, domain, tenant_id, state, version, facts, updated_at::text AS updated_at \
             FROM enterprise.workflows \
             WHERE workflow_id = $1 AND domain = $2 AND tenant_id = $3 FOR UPDATE",
        )
        .bind(workflow_id)
        .bind(domain.as_str())
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| policy_error(
            "enterprise.workflow.not_found_or_forbidden",
            "workflow does not exist in the authenticated tenant",
            json!({ "workflow_id": workflow_id, "tenant_id": tenant_id }),
        ))?;
        let facts = workflow.try_get::<Value, _>("facts")?;
        validate_plan(domain, &facts, &action.input)?;
        if let Some(existing) = query::<Postgres>(
            "SELECT plan_id, workflow_id, input_hash, status, plan, commit_result \
             FROM enterprise.plans WHERE capability_id = $1 AND idempotency_key = $2",
        )
        .bind(action.capability_id.as_str())
        .bind(idempotency_key)
        .fetch_optional(&mut *tx)
        .await?
        {
            if existing.try_get::<String, _>("input_hash")? != input_hash {
                return Err(policy_error(
                    "enterprise.idempotency.collision",
                    "idempotency key was previously used with different input",
                    json!({ "idempotency_key": idempotency_key }),
                ));
            }
            tx.commit().await?;
            return Ok(json!({
                "plan_id": existing.try_get::<String, _>("plan_id")?,
                "workflow_id": existing.try_get::<String, _>("workflow_id")?,
                "status": existing.try_get::<String, _>("status")?,
                "plan": existing.try_get::<Value, _>("plan")?,
                "commit_result": existing.try_get::<Option<Value>, _>("commit_result")?,
                "idempotent_replay": true
            }));
        }
        let plan = build_plan(domain, workflow_id, tenant_id, &facts, &action.input)?;
        query::<Postgres>(
            "INSERT INTO enterprise.plans \
             (plan_id, workflow_id, capability_id, idempotency_key, input_hash, status, plan) \
             VALUES ($1, $2, $3, $4, $5, 'planned', $6)",
        )
        .bind(&plan_id)
        .bind(workflow_id)
        .bind(action.capability_id.as_str())
        .bind(idempotency_key)
        .bind(&input_hash)
        .bind(&plan)
        .execute(&mut *tx)
        .await?;
        insert_audit(
            &mut tx,
            workflow_id,
            Some(&plan_id),
            "plan.created",
            actor,
            tenant_id,
            &plan,
        )
        .await?;
        tx.commit().await?;
        Ok(json!({
            "plan_id": plan_id,
            "workflow_id": workflow_id,
            "status": "planned",
            "plan": plan,
            "idempotent_replay": false
        }))
    }

    async fn simulate_plan(
        &self,
        action: &Action,
        domain: Domain,
    ) -> Result<Value, EnterpriseSandboxError> {
        let workflow_id = required_text(&action.input, "workflow_id")?;
        let tenant_id = required_tenant(action)?;
        let idempotency_key = required_idempotency_key(action)?;
        let workflow = query::<Postgres>(
            "SELECT facts FROM enterprise.workflows \
             WHERE workflow_id = $1 AND domain = $2 AND tenant_id = $3",
        )
        .bind(workflow_id)
        .bind(domain.as_str())
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| {
            policy_error(
                "enterprise.workflow.not_found_or_forbidden",
                "workflow does not exist in the authenticated tenant",
                json!({ "workflow_id": workflow_id, "tenant_id": tenant_id }),
            )
        })?;
        let facts = workflow.try_get::<Value, _>("facts")?;
        validate_plan(domain, &facts, &action.input)?;
        let plan = build_plan(domain, workflow_id, tenant_id, &facts, &action.input)?;
        Ok(json!({
            "transaction": "dry_run",
            "status": "simulated",
            "idempotency_key": idempotency_key,
            "plan": plan,
            "external_side_effects": false
        }))
    }

    async fn commit(
        &self,
        action: &Action,
        domain: Domain,
    ) -> Result<Value, EnterpriseSandboxError> {
        let plan_id = required_text(&action.input, "plan_id")?;
        let tenant_id = required_tenant(action)?;
        let idempotency_key = required_idempotency_key(action)?;
        let approval = action.approval.as_ref().ok_or_else(|| {
            policy_error(
                "enterprise.commit.approval_required",
                "commit requires a runtime-authenticated AIP approval decision",
                json!({ "plan_id": plan_id }),
            )
        })?;
        let actor = actor_label(action);
        let mut tx = self.pool.begin().await?;
        let plan_row = query::<Postgres>(
            "SELECT p.workflow_id, p.status, p.plan, p.commit_result, w.tenant_id, w.domain, \
                    w.state, w.version, w.facts \
             FROM enterprise.plans p JOIN enterprise.workflows w USING (workflow_id) \
             WHERE p.plan_id = $1 FOR UPDATE OF p, w",
        )
        .bind(plan_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            permanent_error(
                "enterprise.plan.not_found",
                "plan does not exist",
                json!({ "plan_id": plan_id }),
            )
        })?;
        let row_tenant = plan_row.try_get::<String, _>("tenant_id")?;
        if row_tenant != tenant_id || plan_row.try_get::<String, _>("domain")? != domain.as_str() {
            return Err(policy_error(
                "enterprise.commit.tenant_or_domain_mismatch",
                "plan is outside the authenticated tenant or capability domain",
                json!({ "plan_id": plan_id, "tenant_id": tenant_id }),
            ));
        }
        let status = plan_row.try_get::<String, _>("status")?;
        if status == "committed" {
            tx.commit().await?;
            return Ok(json!({
                "plan_id": plan_id,
                "status": "committed",
                "result": plan_row.try_get::<Option<Value>, _>("commit_result")?,
                "idempotent_replay": true
            }));
        }
        if status != "planned" {
            return Err(policy_error(
                "enterprise.plan.not_committable",
                format!("plan in state `{status}` cannot be committed"),
                json!({ "plan_id": plan_id, "status": status }),
            ));
        }
        let workflow_id = plan_row.try_get::<String, _>("workflow_id")?;
        let mut facts = plan_row.try_get::<Value, _>("facts")?;
        let result = apply_commit(domain, &workflow_id, plan_id, &mut facts, &action.input)?;
        let next_state = committed_state(domain);
        query::<Postgres>(
            "UPDATE enterprise.workflows SET state = $2, version = version + 1, facts = $3, \
             updated_at = clock_timestamp() WHERE workflow_id = $1",
        )
        .bind(&workflow_id)
        .bind(next_state)
        .bind(&facts)
        .execute(&mut *tx)
        .await?;
        let injected_failure = domain == Domain::Travel
            && action
                .input
                .get("inject_failure_after_reservation")
                .and_then(Value::as_bool)
                == Some(true);
        let plan_status = if injected_failure {
            "failed"
        } else {
            "committed"
        };
        query::<Postgres>(
            "UPDATE enterprise.plans SET status = $2, commit_result = $3, updated_at = clock_timestamp() \
             WHERE plan_id = $1",
        )
        .bind(plan_id)
        .bind(plan_status)
        .bind(&result)
        .execute(&mut *tx)
        .await?;
        insert_audit(
            &mut tx,
            &workflow_id,
            Some(plan_id),
            if injected_failure {
                "commit.partial_failure"
            } else {
                "commit.completed"
            },
            actor,
            tenant_id,
            &json!({
                "result": result,
                "approval_id": approval.approval_id,
                "approver": approval.approver.id,
                "idempotency_key": idempotency_key
            }),
        )
        .await?;
        tx.commit().await?;
        if injected_failure {
            return Err(permanent_error(
                "travel.rebooking.ticket_issue_failed",
                "seat reservation succeeded but ticket issuance failed; compensation is required",
                json!({
                    "plan_id": plan_id,
                    "workflow_id": workflow_id,
                    "reservation": result,
                    "side_effects_committed": true,
                    "compensation_required": true
                }),
            ));
        }
        Ok(json!({
            "plan_id": plan_id,
            "workflow_id": workflow_id,
            "status": "committed",
            "result": result,
            "idempotent_replay": false
        }))
    }

    async fn compensate(
        &self,
        action: &Action,
        domain: Domain,
    ) -> Result<Value, EnterpriseSandboxError> {
        let plan_id = required_text(&action.input, "plan_id")?;
        let tenant_id = required_tenant(action)?;
        let _idempotency_key = required_idempotency_key(action)?;
        let actor = actor_label(action);
        let mut tx = self.pool.begin().await?;
        let row = query::<Postgres>(
            "SELECT p.workflow_id, p.status, p.commit_result, w.tenant_id, w.domain, w.facts \
             FROM enterprise.plans p JOIN enterprise.workflows w USING (workflow_id) \
             WHERE p.plan_id = $1 FOR UPDATE OF p, w",
        )
        .bind(plan_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            permanent_error(
                "enterprise.plan.not_found",
                "plan does not exist",
                json!({ "plan_id": plan_id }),
            )
        })?;
        if row.try_get::<String, _>("tenant_id")? != tenant_id
            || row.try_get::<String, _>("domain")? != domain.as_str()
        {
            return Err(policy_error(
                "enterprise.compensation.tenant_or_domain_mismatch",
                "plan is outside the authenticated tenant or capability domain",
                json!({ "plan_id": plan_id, "tenant_id": tenant_id }),
            ));
        }
        let status = row.try_get::<String, _>("status")?;
        if status == "compensated" {
            tx.commit().await?;
            return Ok(
                json!({ "plan_id": plan_id, "status": "compensated", "idempotent_replay": true }),
            );
        }
        if status != "committed" && status != "failed" {
            return Err(policy_error(
                "enterprise.plan.not_compensatable",
                format!("plan in state `{status}` cannot be compensated"),
                json!({ "plan_id": plan_id, "status": status }),
            ));
        }
        let workflow_id = row.try_get::<String, _>("workflow_id")?;
        let mut facts = row.try_get::<Value, _>("facts")?;
        apply_compensation(domain, &mut facts)?;
        query::<Postgres>(
            "UPDATE enterprise.workflows SET state = $2, version = version + 1, facts = $3, \
             updated_at = clock_timestamp() WHERE workflow_id = $1",
        )
        .bind(&workflow_id)
        .bind(initial_state(domain))
        .bind(&facts)
        .execute(&mut *tx)
        .await?;
        query::<Postgres>(
            "UPDATE enterprise.plans SET status = 'compensated', updated_at = clock_timestamp() \
             WHERE plan_id = $1",
        )
        .bind(plan_id)
        .execute(&mut *tx)
        .await?;
        insert_audit(
            &mut tx,
            &workflow_id,
            Some(plan_id),
            "compensation.completed",
            actor,
            tenant_id,
            &json!({ "prior_status": status }),
        )
        .await?;
        tx.commit().await?;
        Ok(json!({
            "plan_id": plan_id,
            "workflow_id": workflow_id,
            "status": "compensated",
            "idempotent_replay": false
        }))
    }
}

/// Enterprise connector failure.
#[derive(Debug, Error)]
pub enum EnterpriseSandboxError {
    /// PostgreSQL operation failed.
    #[error("enterprise sandbox database failed: {0}")]
    Sql(#[from] SqlxError),
    /// Required schema is absent.
    #[error("enterprise sandbox schema is not ready: {0}")]
    Schema(String),
    /// AIP id is invalid.
    #[error("invalid AIP id: {0}")]
    InvalidId(aip_core::IdParseError),
    /// Capability is not owned by the connector.
    #[error("unsupported enterprise sandbox capability `{0}`")]
    UnsupportedCapability(String),
    /// Action input is malformed.
    #[error("invalid enterprise sandbox input: {0}")]
    InvalidInput(String),
    /// Business policy rejected the operation.
    #[error("protocol error: {0:?}")]
    Protocol(Box<ProtocolError>),
    /// Canonical JSON encoding failed.
    #[error("enterprise sandbox JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[async_trait]
impl Connector for EnterpriseSandboxConnector {
    fn id(&self) -> &str {
        CONNECTOR_ID
    }

    async fn discover(&self, _context: &ConnectorContext) -> ConnectorResult<Manifest> {
        self.discover_manifest()
            .map_err(|error| ConnectorError::Discovery(error.to_string()))
    }

    fn map_error(&self, error: &ConnectorError) -> ProtocolError {
        ProtocolError {
            code: "connector.enterprise_sandbox.error".to_owned(),
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
            detail: "enterprise sandbox schema is available".to_owned(),
        })
    }
}

#[async_trait]
impl CapabilityProviderConnector for EnterpriseSandboxConnector {
    async fn capabilities(&self, _context: &ConnectorContext) -> ConnectorResult<Vec<Capability>> {
        Ok(enterprise_sandbox_capabilities())
    }
}

#[async_trait]
impl OutboundConnector for EnterpriseSandboxConnector {
    async fn invoke(
        &self,
        _context: &ConnectorContext,
        action: Action,
    ) -> ConnectorResult<ActionResult> {
        match self.execute(&action).await {
            Ok(output) => Ok(completed_result(action, output)),
            Err(EnterpriseSandboxError::Protocol(error)) => Ok(failed_result(action.id, *error)),
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
impl ActionHandler for EnterpriseSandboxConnector {
    async fn handle(&self, action: Action) -> RuntimeResult<ActionResult> {
        self.invoke(&ConnectorContext::default(), action)
            .await
            .map_err(|error| RuntimeError::Handler(error.to_string()))
    }
}

#[async_trait]
impl FrozenConnector for EnterpriseSandboxConnector {
    fn implementation_support(&self, capability: &Capability) -> CapabilityImplementationSupport {
        enterprise_sandbox_implementation_support(capability)
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
        let operation = Operation::parse(&action.capability_id).map_err(|error| {
            ConnectorFailure::from_runtime_error(
                RuntimeError::Handler(error.to_string()),
                ConnectorOperation::TransactionPlan,
                self.id(),
            )
        })?;
        if operation.phase != Phase::Plan {
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
            return self
                .simulate_plan(&action, operation.domain)
                .await
                .map(|output| completed_result(action, output))
                .map_err(|error| {
                    ConnectorFailure::from_runtime_error(
                        RuntimeError::Handler(error.to_string()),
                        ConnectorOperation::TransactionPlan,
                        self.id(),
                    )
                });
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
        if Operation::parse(&action.capability_id)
            .ok()
            .is_none_or(|operation| operation.phase != Phase::Commit)
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

    async fn compensate_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        if Operation::parse(&action.capability_id)
            .ok()
            .is_none_or(|operation| operation.phase != Phase::Compensate)
        {
            return Err(ConnectorFailure::unsupported(
                ConnectorOperation::Compensation,
                self.id(),
            ));
        }
        <Self as ActionHandler>::handle_with_context(self, action, context)
            .await
            .map_err(|error| {
                ConnectorFailure::from_runtime_error(
                    error,
                    ConnectorOperation::Compensation,
                    self.id(),
                )
            })
    }
}

/// Returns the exact runtime-support declaration used to qualify this release.
///
/// The release pipeline calls this pure function so its signed implementation
/// claims cannot drift from the behavior advertised by a live connector host.
#[must_use]
pub fn enterprise_sandbox_implementation_support(
    capability: &Capability,
) -> CapabilityImplementationSupport {
    let operation = Operation::parse(&capability.id).ok();
    CapabilityImplementationSupport {
        invocation: operation.is_some(),
        cancellation: false,
        streaming: false,
        retry: operation.is_some(),
        transaction: operation.is_some_and(|operation| operation.phase != Phase::Get),
        reconciliation: false,
        compensation: operation.is_some_and(|operation| operation.phase == Phase::Commit),
        approval: operation.is_some_and(|operation| operation.phase == Phase::Commit),
        credentials: false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Domain {
    Incident,
    Procurement,
    Access,
    Travel,
}

impl Domain {
    fn as_str(self) -> &'static str {
        match self {
            Self::Incident => "incident",
            Self::Procurement => "procurement",
            Self::Access => "access",
            Self::Travel => "travel",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Get,
    Plan,
    Commit,
    Compensate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Operation {
    domain: Domain,
    phase: Phase,
}

impl Operation {
    fn parse(id: &CapabilityId) -> Result<Self, EnterpriseSandboxError> {
        let operation = match id.as_str() {
            INCIDENT_GET => Self {
                domain: Domain::Incident,
                phase: Phase::Get,
            },
            INCIDENT_PLAN => Self {
                domain: Domain::Incident,
                phase: Phase::Plan,
            },
            INCIDENT_COMMIT => Self {
                domain: Domain::Incident,
                phase: Phase::Commit,
            },
            INCIDENT_COMPENSATE => Self {
                domain: Domain::Incident,
                phase: Phase::Compensate,
            },
            PROCUREMENT_GET => Self {
                domain: Domain::Procurement,
                phase: Phase::Get,
            },
            PROCUREMENT_PLAN => Self {
                domain: Domain::Procurement,
                phase: Phase::Plan,
            },
            PROCUREMENT_COMMIT => Self {
                domain: Domain::Procurement,
                phase: Phase::Commit,
            },
            PROCUREMENT_COMPENSATE => Self {
                domain: Domain::Procurement,
                phase: Phase::Compensate,
            },
            ACCESS_GET => Self {
                domain: Domain::Access,
                phase: Phase::Get,
            },
            ACCESS_PLAN => Self {
                domain: Domain::Access,
                phase: Phase::Plan,
            },
            ACCESS_COMMIT => Self {
                domain: Domain::Access,
                phase: Phase::Commit,
            },
            ACCESS_COMPENSATE => Self {
                domain: Domain::Access,
                phase: Phase::Compensate,
            },
            TRAVEL_GET => Self {
                domain: Domain::Travel,
                phase: Phase::Get,
            },
            TRAVEL_PLAN => Self {
                domain: Domain::Travel,
                phase: Phase::Plan,
            },
            TRAVEL_COMMIT => Self {
                domain: Domain::Travel,
                phase: Phase::Commit,
            },
            TRAVEL_COMPENSATE => Self {
                domain: Domain::Travel,
                phase: Phase::Compensate,
            },
            other => {
                return Err(EnterpriseSandboxError::UnsupportedCapability(
                    other.to_owned(),
                ));
            }
        };
        Ok(operation)
    }
}

/// Returns all enterprise sandbox capabilities.
#[must_use]
pub fn enterprise_sandbox_capabilities() -> Vec<Capability> {
    [
        (Domain::Incident, INCIDENT_GET, Phase::Get, "Incident get"),
        (
            Domain::Incident,
            INCIDENT_PLAN,
            Phase::Plan,
            "Incident mitigation plan",
        ),
        (
            Domain::Incident,
            INCIDENT_COMMIT,
            Phase::Commit,
            "Incident mitigation commit",
        ),
        (
            Domain::Incident,
            INCIDENT_COMPENSATE,
            Phase::Compensate,
            "Incident mitigation compensate",
        ),
        (
            Domain::Procurement,
            PROCUREMENT_GET,
            Phase::Get,
            "Procurement request get",
        ),
        (
            Domain::Procurement,
            PROCUREMENT_PLAN,
            Phase::Plan,
            "Procurement purchase plan",
        ),
        (
            Domain::Procurement,
            PROCUREMENT_COMMIT,
            Phase::Commit,
            "Procurement purchase commit",
        ),
        (
            Domain::Procurement,
            PROCUREMENT_COMPENSATE,
            Phase::Compensate,
            "Procurement purchase compensate",
        ),
        (Domain::Access, ACCESS_GET, Phase::Get, "Access request get"),
        (
            Domain::Access,
            ACCESS_PLAN,
            Phase::Plan,
            "Access grant plan",
        ),
        (
            Domain::Access,
            ACCESS_COMMIT,
            Phase::Commit,
            "Access grant commit",
        ),
        (
            Domain::Access,
            ACCESS_COMPENSATE,
            Phase::Compensate,
            "Access grant revoke",
        ),
        (
            Domain::Travel,
            TRAVEL_GET,
            Phase::Get,
            "Travel disruption get",
        ),
        (
            Domain::Travel,
            TRAVEL_PLAN,
            Phase::Plan,
            "Travel rebooking plan",
        ),
        (
            Domain::Travel,
            TRAVEL_COMMIT,
            Phase::Commit,
            "Travel rebooking commit",
        ),
        (
            Domain::Travel,
            TRAVEL_COMPENSATE,
            Phase::Compensate,
            "Travel rebooking compensate",
        ),
    ]
    .into_iter()
    .map(|(domain, id, phase, name)| capability(domain, id, phase, name))
    .collect()
}

/// Builds the connector manifest without opening a database connection.
pub fn enterprise_sandbox_manifest() -> Result<Manifest, EnterpriseSandboxError> {
    Ok(Manifest {
        manifest_version: "aip-manifest/v1".to_owned(),
        agent: Principal::new(
            PrincipalId::parse("agent:enterprise_sandbox:connector")
                .map_err(EnterpriseSandboxError::InvalidId)?,
            PrincipalKind::Agent,
        ),
        capabilities: enterprise_sandbox_capabilities(),
        profiles: vec![
            ProfileId::from(NATIVE_HTTP_PROFILE),
            ProfileId::from(MCP_PROFILE),
            ProfileId::from(PROFILE_ID),
        ],
        resources: Vec::new(),
        channels: Vec::new(),
        security: Some(json!({
            "tenant_source": "Action.identity.tenant",
            "approval_source": "runtime-authenticated ApprovalDecision",
            "idempotency": "required for plan, commit, and compensate",
            "secrets": "database credentials remain process configuration"
        })),
        governance: Some(json!({
            "domains": ["incident", "procurement", "access", "travel"],
            "audit": "immutable PostgreSQL event log",
            "saga": "every commit has an explicit compensation capability"
        })),
        limits: Some(json!({ "transaction_boundary": "one PostgreSQL transaction per operation" })),
        compatibility: Some(
            json!({ "system": "enterprise-sandbox-postgres", "connector": CONNECTOR_ID }),
        ),
        extensions: None,
    })
}

fn capability(domain: Domain, id: &'static str, phase: Phase, name: &'static str) -> Capability {
    let compensation_id = match domain {
        Domain::Incident => INCIDENT_COMPENSATE,
        Domain::Procurement => PROCUREMENT_COMPENSATE,
        Domain::Access => ACCESS_COMPENSATE,
        Domain::Travel => TRAVEL_COMPENSATE,
    };
    let is_read = phase == Phase::Get;
    let approval_required = phase == Phase::Commit;
    let side_effects = match domain {
        Domain::Incident => vec![SideEffect::Read, SideEffect::Write],
        Domain::Procurement | Domain::Travel => vec![
            SideEffect::Read,
            SideEffect::Write,
            SideEffect::Financial,
            SideEffect::Legal,
        ],
        Domain::Access => vec![SideEffect::Read, SideEffect::Write, SideEffect::Identity],
    };
    let contract = CapabilityContract {
        side_effects: if is_read {
            vec![SideEffect::Read]
        } else {
            side_effects
        },
        idempotency: IdempotencyContract {
            requirement: if is_read {
                IdempotencyRequirement::Optional
            } else {
                IdempotencyRequirement::Required
            },
            collision_behavior: IdempotencyCollisionBehavior::RevalidateInputHash,
            key_scope: IdempotencyKeyScope::Tenant,
            ttl_ms: Some(604_800_000),
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: phase == Phase::Commit,
            supports_streaming: false,
            supports_cancel: false,
            supports_retry: true,
            expected_completion: if phase == Phase::Commit {
                ExpectedCompletionMode::Any
            } else {
                ExpectedCompletionMode::Sync
            },
            retry_safety: if is_read {
                RetrySafety::Safe
            } else {
                RetrySafety::SafeWithIdempotencyKey
            },
        },
        data: DataContract {
            sensitivity: if domain == Domain::Access {
                DataSensitivity::Restricted
            } else {
                DataSensitivity::Confidential
            },
            contains_pii: matches!(domain, Domain::Access | Domain::Travel),
            redaction_required: true,
            residency: None,
            retention: None,
        },
        credentials: None,
        approval: approval_required.then(|| ApprovalPolicy {
            required: true,
            reason: Some(format!(
                "{} commit requires authenticated human approval",
                domain.as_str()
            )),
            approver_selector: ApproverSelector::TenantPolicy,
            ttl_ms: Some(if domain == Domain::Access {
                5_000
            } else {
                900_000
            }),
            evidence_requirements: vec![
                EvidenceRequirement::Reason,
                EvidenceRequirement::InputSnapshot,
                EvidenceRequirement::PolicyDecision,
            ],
            delegated_authority: None,
            ..ApprovalPolicy::default()
        }),
        sla: Some(ServiceLevelContract {
            expected_latency_ms: Some(250),
            timeout_ms: Some(10_000),
            async_expected: phase == Phase::Commit,
            max_queue_delay_ms: Some(2_000),
            availability_target: Some("99.9%".to_owned()),
        }),
        transaction: (!is_read).then(|| TransactionContract {
            supported_modes: match phase {
                Phase::Plan => vec![
                    TransactionMode::Execute,
                    TransactionMode::Plan,
                    TransactionMode::DryRun,
                ],
                Phase::Commit => vec![
                    TransactionMode::Execute,
                    TransactionMode::Commit,
                    TransactionMode::Compensate,
                ],
                Phase::Compensate => vec![TransactionMode::Execute],
                Phase::Get => Vec::new(),
            },
            requires_plan_before_commit: false,
            dry_run_fidelity: DryRunFidelity::DownstreamValidation,
        }),
        compensation: Some(if phase == Phase::Commit {
            CompensationContract {
                mode: CompensationMode::Supported,
                compensation_capability_id: Some(CapabilityId::trusted(compensation_id)),
                compensation_window_ms: Some(86_400_000),
                requires_approval: false,
            }
        } else {
            CompensationContract {
                mode: CompensationMode::NotRequired,
                compensation_capability_id: None,
                compensation_window_ms: None,
                requires_approval: false,
            }
        }),
    };
    let input_schema = if phase == Phase::Get || phase == Phase::Plan {
        object_schema(&["workflow_id"])
    } else {
        object_schema(&["plan_id"])
    };
    Capability {
        id: CapabilityId::trusted(id),
        name: name.to_owned(),
        kind: CapabilityKind::Tool,
        input_schema,
        output_schema: Some(json!({ "type": "object" })),
        description: Some(format!(
            "Durable {} {} operation.",
            domain.as_str(),
            phase_name(phase)
        )),
        risk: Some(if approval_required {
            RiskLevel::Critical
        } else if is_read {
            RiskLevel::Low
        } else {
            RiskLevel::Medium
        }),
        stability: Some(Stability::Stable),
        cost: None,
        auth: None,
        bindings: vec![
            Binding {
                profile: ProfileId::from(NATIVE_HTTP_PROFILE),
                metadata: [
                    ("method".to_owned(), json!("POST")),
                    ("path".to_owned(), json!("/aip/v1/messages")),
                ]
                .into_iter()
                .collect(),
            },
            Binding {
                profile: ProfileId::from(MCP_PROFILE),
                metadata: [(
                    "name".to_owned(),
                    json!(id.trim_start_matches("cap:").replace([':', '.'], "_")),
                )]
                .into_iter()
                .collect(),
            },
            Binding {
                profile: ProfileId::from(PROFILE_ID),
                metadata: [
                    ("connector".to_owned(), json!(CONNECTOR_ID)),
                    ("domain".to_owned(), json!(domain.as_str())),
                    ("phase".to_owned(), json!(phase_name(phase))),
                ]
                .into_iter()
                .collect(),
            },
        ],
        requires_human_approval: Some(approval_required),
        contract: Some(contract),
    }
}

fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::Get => "get",
        Phase::Plan => "plan",
        Phase::Commit => "commit",
        Phase::Compensate => "compensate",
    }
}

fn object_schema(required: &[&str]) -> Value {
    let mut properties = Map::new();
    for name in ["workflow_id", "plan_id", "option_id", "ttl_seconds"] {
        properties.insert(
            name.to_owned(),
            if name == "ttl_seconds" {
                json!({ "type": "integer", "minimum": 1 })
            } else {
                json!({ "type": "string" })
            },
        );
    }
    properties.insert(
        "inject_failure_after_reservation".to_owned(),
        json!({ "type": "boolean" }),
    );
    json!({ "type": "object", "additionalProperties": true, "required": required, "properties": properties })
}

fn required_text<'a>(value: &'a Value, key: &str) -> Result<&'a str, EnterpriseSandboxError> {
    optional_text(value, key).ok_or_else(|| {
        EnterpriseSandboxError::InvalidInput(format!("missing required string `{key}`"))
    })
}

fn optional_text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn required_tenant(action: &Action) -> Result<&str, EnterpriseSandboxError> {
    action
        .identity
        .as_ref()
        .and_then(|identity| identity.tenant.as_ref())
        .map(|tenant| tenant.id.as_str())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            policy_error(
                "enterprise.identity.tenant_required",
                "Action.identity.tenant is required",
                json!({ "action_id": action.id }),
            )
        })
}

fn required_idempotency_key(action: &Action) -> Result<&str, EnterpriseSandboxError> {
    action
        .idempotency_key
        .as_deref()
        .filter(|key| !key.trim().is_empty())
        .ok_or_else(|| {
            policy_error(
                "enterprise.idempotency.required",
                "mutation requires Action.idempotency_key",
                json!({ "action_id": action.id }),
            )
        })
}

fn actor_label(action: &Action) -> &str {
    action
        .identity
        .as_ref()
        .and_then(|identity| {
            identity
                .human_actor
                .as_ref()
                .or(identity.service_account.as_ref())
        })
        .map(|principal| principal.id.as_str())
        .unwrap_or("service:getaip:server:mcp-edge")
}

fn input_hash(input: &Value) -> Result<String, EnterpriseSandboxError> {
    let bytes = serde_json::to_vec(input)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn workflow_json(row: &sqlx_postgres::PgRow) -> Result<Value, EnterpriseSandboxError> {
    Ok(json!({
        "workflow_id": row.try_get::<String, _>("workflow_id")?,
        "domain": row.try_get::<String, _>("domain")?,
        "tenant_id": row.try_get::<String, _>("tenant_id")?,
        "state": row.try_get::<String, _>("state")?,
        "version": row.try_get::<i64, _>("version")?,
        "facts": row.try_get::<Value, _>("facts")?,
        "updated_at": row.try_get::<String, _>("updated_at")?,
        "source": "enterprise.workflows"
    }))
}

fn validate_plan(
    domain: Domain,
    facts: &Value,
    input: &Value,
) -> Result<(), EnterpriseSandboxError> {
    match domain {
        Domain::Incident if facts.get("mitigation").and_then(Value::as_str) != Some("rollback") => {
            Err(policy_error(
                "incident.mitigation.unsupported",
                "fixture requires rollback mitigation",
                facts.clone(),
            ))
        }
        Domain::Procurement
            if facts.get("vendor_status").and_then(Value::as_str) != Some("approved") =>
        {
            Err(policy_error(
                "procurement.vendor.not_approved",
                "vendor is not approved",
                facts.clone(),
            ))
        }
        Domain::Access => {
            let ttl = input
                .get("ttl_seconds")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    EnterpriseSandboxError::InvalidInput(
                        "access plan requires integer `ttl_seconds`".to_owned(),
                    )
                })?;
            let max = facts
                .get("max_ttl_seconds")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            if ttl > max {
                Err(policy_error(
                    "access.ttl.exceeds_policy",
                    "requested access TTL exceeds policy",
                    json!({ "requested": ttl, "maximum": max }),
                ))
            } else {
                Ok(())
            }
        }
        Domain::Travel => {
            let option_id = required_text(input, "option_id")?;
            let exists = facts
                .get("options")
                .and_then(Value::as_array)
                .is_some_and(|options| {
                    options.iter().any(|option| {
                        option.get("option_id").and_then(Value::as_str) == Some(option_id)
                    })
                });
            if exists {
                Ok(())
            } else {
                Err(permanent_error(
                    "travel.option.not_found",
                    "selected rebooking option does not exist",
                    json!({ "option_id": option_id }),
                ))
            }
        }
        _ => Ok(()),
    }
}

fn build_plan(
    domain: Domain,
    workflow_id: &str,
    tenant_id: &str,
    facts: &Value,
    input: &Value,
) -> Result<Value, EnterpriseSandboxError> {
    let operation = match domain {
        Domain::Incident => {
            json!({ "operation": "rollback_deploy", "from": facts.get("deploy_id"), "to": facts.get("previous_deploy_id") })
        }
        Domain::Procurement => {
            json!({ "operation": "reserve_budget_and_create_po", "vendor_id": facts.get("vendor_id"), "amount_cents": facts.get("amount_cents"), "currency": facts.get("currency") })
        }
        Domain::Access => {
            json!({ "operation": "grant_time_limited_role", "subject": facts.get("subject"), "resource": facts.get("resource"), "role": facts.get("role"), "ttl_seconds": input.get("ttl_seconds") })
        }
        Domain::Travel => {
            let option_id = required_text(input, "option_id")?;
            let option = facts
                .get("options")
                .and_then(Value::as_array)
                .and_then(|options| {
                    options.iter().find(|option| {
                        option.get("option_id").and_then(Value::as_str) == Some(option_id)
                    })
                })
                .cloned();
            json!({ "operation": "reserve_and_ticket", "option": option })
        }
    };
    Ok(
        json!({ "workflow_id": workflow_id, "tenant_id": tenant_id, "domain": domain.as_str(), "operation": operation, "facts_version": facts }),
    )
}

fn apply_commit(
    domain: Domain,
    workflow_id: &str,
    plan_id: &str,
    facts: &mut Value,
    input: &Value,
) -> Result<Value, EnterpriseSandboxError> {
    let object = facts.as_object_mut().ok_or_else(|| {
        EnterpriseSandboxError::InvalidInput("workflow facts must be an object".to_owned())
    })?;
    let result = match domain {
        Domain::Incident => {
            let target = object
                .get("previous_deploy_id")
                .cloned()
                .unwrap_or(Value::Null);
            object.insert("rollback_deploy_id".to_owned(), target.clone());
            json!({ "incident_id": workflow_id, "rolled_back_to": target, "health": "recovering" })
        }
        Domain::Procurement => {
            let amount = object
                .get("amount_cents")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let available = object
                .get("budget_available_cents")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            if amount > available {
                return Err(policy_error(
                    "procurement.budget.insufficient",
                    "available budget is insufficient",
                    json!({ "amount_cents": amount, "available_cents": available }),
                ));
            }
            let po_id = format!("po:{plan_id}");
            object.insert(
                "budget_available_cents".to_owned(),
                json!(available - amount),
            );
            object.insert("reserved_cents".to_owned(), json!(amount));
            object.insert("purchase_order_id".to_owned(), json!(po_id));
            json!({ "request_id": workflow_id, "purchase_order_id": po_id, "reserved_cents": amount })
        }
        Domain::Access => {
            let ttl = input
                .get("ttl_seconds")
                .and_then(Value::as_u64)
                .or_else(|| object.get("max_ttl_seconds").and_then(Value::as_u64))
                .unwrap_or(300);
            let grant_id = format!("grant:{plan_id}");
            object.insert("grant_id".to_owned(), json!(grant_id));
            object.insert("granted_ttl_seconds".to_owned(), json!(ttl));
            json!({ "request_id": workflow_id, "grant_id": grant_id, "ttl_seconds": ttl })
        }
        Domain::Travel => {
            let option_id = required_text(input, "option_id")?.to_owned();
            let reservation_id = format!("reservation:{plan_id}");
            object.insert("selected_option".to_owned(), json!(option_id));
            object.insert("reservation_id".to_owned(), json!(reservation_id));
            json!({ "trip_id": workflow_id, "option_id": option_id, "reservation_id": reservation_id, "ticket_issued": input.get("inject_failure_after_reservation").and_then(Value::as_bool) != Some(true) })
        }
    };
    Ok(result)
}

fn apply_compensation(domain: Domain, facts: &mut Value) -> Result<(), EnterpriseSandboxError> {
    let object = facts.as_object_mut().ok_or_else(|| {
        EnterpriseSandboxError::InvalidInput("workflow facts must be an object".to_owned())
    })?;
    match domain {
        Domain::Incident => {
            object.remove("rollback_deploy_id");
            object.remove("resolved_at");
        }
        Domain::Procurement => {
            let reserved = object
                .remove("reserved_cents")
                .and_then(|value| value.as_i64())
                .unwrap_or_default();
            let available = object
                .get("budget_available_cents")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            object.insert(
                "budget_available_cents".to_owned(),
                json!(available + reserved),
            );
            object.remove("purchase_order_id");
        }
        Domain::Access => {
            object.remove("grant_id");
            object.remove("granted_ttl_seconds");
        }
        Domain::Travel => {
            object.insert("selected_option".to_owned(), Value::Null);
            object.insert("reservation_id".to_owned(), Value::Null);
        }
    }
    Ok(())
}

fn committed_state(domain: Domain) -> &'static str {
    match domain {
        Domain::Incident => "mitigated",
        Domain::Procurement => "purchased",
        Domain::Access => "granted",
        Domain::Travel => "reserved",
    }
}

fn initial_state(domain: Domain) -> &'static str {
    match domain {
        Domain::Incident => "open",
        Domain::Procurement => "requested",
        Domain::Access => "requested",
        Domain::Travel => "disrupted",
    }
}

async fn insert_audit(
    tx: &mut sqlx_core::transaction::Transaction<'_, Postgres>,
    workflow_id: &str,
    plan_id: Option<&str>,
    event_type: &str,
    actor: &str,
    tenant_id: &str,
    payload: &Value,
) -> Result<(), EnterpriseSandboxError> {
    query::<Postgres>(
        "INSERT INTO enterprise.audit_events (workflow_id, plan_id, event_type, actor_principal, tenant_id, payload) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(workflow_id).bind(plan_id).bind(event_type).bind(actor).bind(tenant_id).bind(payload)
    .execute(&mut **tx).await?;
    Ok(())
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

fn policy_error(
    code: impl Into<String>,
    message: impl Into<String>,
    details: Value,
) -> EnterpriseSandboxError {
    protocol_error(code, message, ErrorCategory::Policy, false, details)
}

fn permanent_error(
    code: impl Into<String>,
    message: impl Into<String>,
    details: Value,
) -> EnterpriseSandboxError {
    protocol_error(code, message, ErrorCategory::Permanent, false, details)
}

fn protocol_error(
    code: impl Into<String>,
    message: impl Into<String>,
    category: ErrorCategory,
    retryable: bool,
    details: Value,
) -> EnterpriseSandboxError {
    EnterpriseSandboxError::Protocol(Box::new(ProtocolError {
        code: code.into(),
        message: message.into(),
        category,
        retryable: Some(retryable),
        retry_after_ms: retryable.then_some(1_000),
        details: Some(Box::new(details)),
        source: Some(Box::new(json!({ "connector": CONNECTOR_ID }))),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_exposes_complete_saga_contracts() {
        let manifest = enterprise_sandbox_manifest().expect("manifest");
        assert_eq!(manifest.capabilities.len(), 16);
        for capability in manifest.capabilities {
            let contract = capability.contract.expect("contract");
            if capability.id.as_str().ends_with(".commit") {
                assert!(
                    contract
                        .approval
                        .as_ref()
                        .is_some_and(|approval| approval.required)
                );
                assert_eq!(
                    contract.compensation.expect("compensation").mode,
                    CompensationMode::Supported
                );
                assert!(
                    contract
                        .transaction
                        .expect("transaction")
                        .supported_modes
                        .contains(&TransactionMode::Compensate),
                    "{} must accept native compensation requests",
                    capability.id
                );
            } else if capability.id.as_str().ends_with(".compensate")
                || capability.id.as_str().ends_with(".revoke")
            {
                assert_eq!(
                    contract.transaction.expect("transaction").supported_modes,
                    vec![TransactionMode::Execute],
                    "{} is the routed compensation endpoint and must not advertise recursive compensation",
                    capability.id
                );
            }
        }
    }

    #[test]
    fn access_plan_rejects_excessive_ttl() {
        let facts = json!({ "max_ttl_seconds": 900 });
        let error = validate_plan(Domain::Access, &facts, &json!({ "ttl_seconds": 901 }))
            .expect_err("TTL must be rejected");
        assert!(error.to_string().contains("exceeds policy"));
    }

    #[test]
    fn procurement_compensation_restores_budget() {
        let mut facts = json!({ "budget_available_cents": 100, "reserved_cents": 25, "purchase_order_id": "po:1" });
        apply_compensation(Domain::Procurement, &mut facts).expect("compensation");
        assert_eq!(facts["budget_available_cents"], 125);
        assert!(facts.get("purchase_order_id").is_none());
    }
}
