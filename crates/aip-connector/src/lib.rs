//! Connector traits for translating external systems into AIP semantics.

#![forbid(unsafe_code)]

use aip_core::{
    Action, ActionResult, Capability, Envelope, ErrorCategory, Escalation, Manifest, ProtocolError,
    ProviderOperationRef, TransactionId, TransactionMode,
};
use aip_runtime::{
    ActionExecutionContext, ActionHandler, CancellationToken, RuntimeError, RuntimeResult,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, str::Utf8Error, sync::Arc};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use aip_discovery::CapabilityImplementationSupport;

/// In-memory connector credential material with redacted diagnostics and
/// zeroization on drop.
///
/// The type is intentionally not serializable. Configuration loaders must
/// construct it at the process boundary and must never place it in manifests,
/// action metadata, protocol errors, or audit records.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ConnectorSecret(Vec<u8>);

impl ConnectorSecret {
    /// Copies secret bytes into protected connector-owned storage.
    #[must_use]
    pub fn new(value: impl AsRef<[u8]>) -> Self {
        Self(value.as_ref().to_vec())
    }

    /// Exposes secret bytes only at the downstream request boundary.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Exposes UTF-8 credential material at the downstream request boundary.
    pub fn expose_str(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(&self.0)
    }

    /// Returns whether the configured credential is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for ConnectorSecret {
    fn from(value: String) -> Self {
        Self(value.into_bytes())
    }
}

impl From<Vec<u8>> for ConnectorSecret {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl fmt::Debug for ConnectorSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectorSecret([REDACTED])")
    }
}

impl PartialEq for ConnectorSecret {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq::constant_time_eq(&self.0, &other.0)
    }
}

impl Eq for ConnectorSecret {}

/// Typed operation at the connector boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorOperation {
    /// Discover a provider manifest.
    Discovery,
    /// Validate and admit a provider manifest.
    Admission,
    /// Invoke a normal capability action.
    Invocation,
    /// Cancel a remote action.
    Cancellation,
    /// Publish or consume incremental output.
    Streaming,
    /// Probe provider readiness.
    Health,
    /// Prepare or simulate a transaction.
    TransactionPlan,
    /// Commit a prepared transaction.
    TransactionCommit,
    /// Reconcile an operation whose outcome is unknown.
    Reconciliation,
    /// Execute a governed compensation action.
    Compensation,
    /// Emit a result or event to the provider.
    Emission,
    /// Ingest a provider event.
    Ingestion,
}

/// Complete typed connector failure retained in action state and protocol errors.
#[derive(Clone, Debug, Error, PartialEq, Serialize, Deserialize)]
#[error("{code}: {message}")]
pub struct ConnectorFailure {
    /// Stable namespaced failure code.
    pub code: String,
    /// Human-readable redacted summary.
    pub message: String,
    /// AIP error category.
    pub category: ErrorCategory,
    /// Whether retry is safe under the capability idempotency contract.
    pub retryable: bool,
    /// Provider-suggested retry delay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    /// Provider request or trace id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_request_id: Option<String>,
    /// Durable provider operation reference for outcome reconciliation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_operation: Option<ProviderOperationRef>,
    /// Remote protocol status, normally an HTTP status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_status: Option<u16>,
    /// Whether an external side effect may have happened despite the failure.
    #[serde(default)]
    pub uncertain_outcome: bool,
    /// Redacted structured details safe for durable audit storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_details: Option<Value>,
    /// Connector and provider component that produced the failure.
    #[serde(rename = "source")]
    pub source_component: String,
    /// Operation that failed.
    pub operation: ConnectorOperation,
}

impl ConnectorFailure {
    /// Creates an explicit unsupported-operation failure.
    #[must_use]
    pub fn unsupported(operation: ConnectorOperation, source: impl Into<String>) -> Self {
        Self {
            code: "connector.operation_unsupported".to_owned(),
            message: format!("connector does not implement {operation:?}"),
            category: ErrorCategory::Permanent,
            retryable: false,
            retry_after_ms: None,
            provider_request_id: None,
            provider_operation: None,
            remote_status: None,
            uncertain_outcome: false,
            redacted_details: None,
            source_component: source.into(),
            operation,
        }
    }

    /// Converts the complete connector failure to an AIP protocol error.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        ProtocolError {
            code: self.code.clone(),
            message: self.message.clone(),
            category: self.category,
            retryable: Some(self.retryable),
            retry_after_ms: self.retry_after_ms,
            details: Some(Box::new(serde_json::json!({
                "operation": self.operation,
                "provider_request_id": self.provider_request_id,
                "provider_operation": self.provider_operation,
                "remote_status": self.remote_status,
                "uncertain_outcome": self.uncertain_outcome,
                "details": self.redacted_details
            }))),
            source: Some(Box::new(serde_json::json!({
                "component": self.source_component
            }))),
        }
    }

    /// Preserves a protocol failure when crossing into the typed connector
    /// boundary.
    #[must_use]
    pub fn from_protocol_error(
        error: ProtocolError,
        operation: ConnectorOperation,
        source: impl Into<String>,
    ) -> Self {
        let details = error.details.as_deref();
        Self {
            code: error.code,
            message: error.message,
            category: error.category,
            retryable: error.retryable.unwrap_or(false),
            retry_after_ms: error.retry_after_ms,
            provider_request_id: details
                .and_then(|value| value.get("provider_request_id"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            provider_operation: details
                .and_then(|value| value.get("provider_operation"))
                .and_then(|value| serde_json::from_value(value.clone()).ok()),
            remote_status: details
                .and_then(|value| value.get("remote_status"))
                .and_then(Value::as_u64)
                .and_then(|status| u16::try_from(status).ok()),
            uncertain_outcome: details
                .and_then(|value| value.get("uncertain_outcome"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            redacted_details: error.details.map(|details| *details),
            source_component: source.into(),
            operation,
        }
    }

    /// Converts a runtime failure without discarding an embedded protocol
    /// error.
    #[must_use]
    pub fn from_runtime_error(
        error: RuntimeError,
        operation: ConnectorOperation,
        source: impl Into<String>,
    ) -> Self {
        let source = source.into();
        match error {
            RuntimeError::Protocol(error) => Self::from_protocol_error(error, operation, source),
            other => Self {
                code: "connector.runtime_failure".to_owned(),
                message: other.to_string(),
                category: ErrorCategory::Connector,
                retryable: false,
                retry_after_ms: None,
                provider_request_id: None,
                provider_operation: None,
                remote_status: None,
                uncertain_outcome: false,
                redacted_details: None,
                source_component: source,
                operation,
            },
        }
    }

    /// Converts a legacy connector error while retaining an already-typed
    /// failure unchanged.
    #[must_use]
    pub fn from_connector_error(
        error: ConnectorError,
        operation: ConnectorOperation,
        source: impl Into<String>,
    ) -> Self {
        match error {
            ConnectorError::Failure(failure) => failure,
            other => Self {
                code: "connector.operation_failed".to_owned(),
                message: other.to_string(),
                category: ErrorCategory::Connector,
                retryable: false,
                retry_after_ms: None,
                provider_request_id: None,
                provider_operation: None,
                remote_status: None,
                uncertain_outcome: false,
                redacted_details: None,
                source_component: source.into(),
                operation,
            },
        }
    }
}

/// Durable provider reference used to reconcile uncertain outcomes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReconciliationRequest {
    /// AIP transaction id.
    pub transaction_id: TransactionId,
    /// Provider operation id captured before or during commit.
    pub provider_operation_id: String,
    /// Opaque provider cursor from the previous reconciliation attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Typed reconciliation result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReconciliationResult {
    /// Whether the provider reports a terminal outcome.
    pub terminal: bool,
    /// Whether the original commit completed successfully.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed: Option<bool>,
    /// Updated provider cursor for another attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Redacted provider evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Value>,
}

/// Connector execution context.
#[derive(Clone, Debug, Default)]
pub struct ConnectorContext {
    /// Tenant or account id.
    pub tenant_id: Option<String>,
    /// Request metadata.
    pub metadata: BTreeMap<String, String>,
}

impl ConnectorContext {
    /// Projects trusted, non-secret execution metadata for legacy connector
    /// operations during migration to the frozen SDK.
    #[must_use]
    pub fn from_execution(context: &ActionExecutionContext) -> Self {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "authenticated_principal_id".to_owned(),
            context.actor.principal.id.to_string(),
        );
        metadata.insert(
            "authentication_issuer".to_owned(),
            context.actor.issuer.clone(),
        );
        if let Some(trace_id) = context.trace.trace_id.clone() {
            metadata.insert("trace_id".to_owned(), trace_id);
        }
        Self {
            tenant_id: context
                .tenant
                .as_ref()
                .map(|tenant| tenant.tenant.id.clone()),
            metadata,
        }
    }
}

/// Connector error.
// Boxing the frozen `Failure` variant would break direct construction in the
// published connector SDK. Keep source compatibility until the next major API.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Error)]
pub enum ConnectorError {
    /// Frozen SDK failure carrying complete execution semantics.
    #[error(transparent)]
    Failure(#[from] ConnectorFailure),
    /// Discovery failed.
    #[error("discovery failed: {0}")]
    Discovery(String),
    /// Inbound mapping failed.
    #[error("ingest failed: {0}")]
    Ingest(String),
    /// Invocation failed.
    #[error("invoke failed: {0}")]
    Invoke(String),
    /// Emission failed.
    #[error("emit failed: {0}")]
    Emit(String),
    /// Verification failed.
    #[error("verification failed: {0}")]
    Verify(String),
}

/// Result alias for connector operations.
pub type ConnectorResult<T> = Result<T, ConnectorError>;

/// Connector readiness result exposed to gateway health checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorHealth {
    /// Whether the connector can currently serve traffic.
    pub ready: bool,
    /// Operator-facing detail without credentials or payload data.
    pub detail: String,
}

/// Base connector contract.
#[async_trait]
pub trait Connector: Send + Sync {
    /// Stable connector id.
    fn id(&self) -> &str;

    /// Returns the connector manifest.
    async fn discover(&self, context: &ConnectorContext) -> ConnectorResult<Manifest>;

    /// Maps a connector error to an AIP protocol error.
    fn map_error(&self, error: &ConnectorError) -> ProtocolError;

    /// Checks whether the connector can currently discover and serve traffic.
    async fn health(&self, context: &ConnectorContext) -> ConnectorResult<ConnectorHealth> {
        self.discover(context).await.map(|_| ConnectorHealth {
            ready: true,
            detail: "connector discovery succeeded".to_owned(),
        })
    }
}

/// Connector that advertises executable AIP capabilities.
///
/// Capability provider connectors are used by gateways during manifest
/// composition and by conformance harnesses when validating that product
/// integrations expose stable capability contracts independently from
/// transport-specific ingress.
#[async_trait]
pub trait CapabilityProviderConnector: Connector {
    /// Returns the executable capabilities currently exposed by the connector.
    async fn capabilities(&self, context: &ConnectorContext) -> ConnectorResult<Vec<Capability>>;
}

/// Connector that ingests external events.
#[async_trait]
pub trait InboundConnector: Connector {
    /// Converts an external event payload to one or more AIP envelopes.
    async fn ingest(
        &self,
        context: &ConnectorContext,
        payload: Value,
    ) -> ConnectorResult<Vec<Envelope>>;
}

/// Connector that maps external channel events and channel replies.
///
/// Channel connectors are intentionally separate from [`OutboundConnector`]:
/// they usually represent conversation surfaces such as support inboxes,
/// chats, and ticketing systems rather than callable tools.
#[async_trait]
pub trait ChannelConnector: Connector {
    /// Converts an external channel event payload to one or more AIP envelopes.
    async fn ingest_channel_event(
        &self,
        context: &ConnectorContext,
        payload: Value,
    ) -> ConnectorResult<Vec<Envelope>>;

    /// Emits an AIP action result back to the channel surface.
    async fn emit_channel_result(
        &self,
        context: &ConnectorContext,
        result: ActionResult,
    ) -> ConnectorResult<()>;
}

/// Connector that invokes an external system from an AIP action.
#[async_trait]
pub trait OutboundConnector: Connector {
    /// Executes an AIP action in the external system.
    async fn invoke(
        &self,
        context: &ConnectorContext,
        action: Action,
    ) -> ConnectorResult<ActionResult>;

    /// Executes an action while observing runtime cancellation.
    ///
    /// The default implementation drops the in-flight invocation future when
    /// cancellation wins. Connectors with a remote cancellation endpoint should
    /// additionally implement [`OutboundConnector::cancel`].
    async fn invoke_with_cancellation(
        &self,
        context: &ConnectorContext,
        action: Action,
        cancellation: CancellationToken,
    ) -> ConnectorResult<ActionResult> {
        tokio::select! {
            result = self.invoke(context, action) => result,
            () = cancellation.cancelled() => Err(ConnectorError::Invoke(
                "operation cancelled by the AIP runtime".to_owned(),
            )),
        }
    }

    /// Requests cancellation from the remote system when it supports it.
    async fn cancel(&self, _context: &ConnectorContext, _action: &Action) -> ConnectorResult<()> {
        Err(ConnectorFailure::unsupported(ConnectorOperation::Cancellation, self.id()).into())
    }

    /// Emits an AIP result back to the external system.
    async fn emit(&self, context: &ConnectorContext, result: ActionResult) -> ConnectorResult<()>;
}

/// Production connector contract consumed by the frozen AIP runtime boundary.
///
/// The execution context is transport-authenticated and never reconstructed
/// from action payload metadata. Incremental output is published through its
/// stream publisher. Every default operation fails explicitly.
#[async_trait]
pub trait FrozenConnector: Connector {
    /// Returns implementation support for one admitted capability.
    fn implementation_support(
        &self,
        capability: &Capability,
    ) -> aip_discovery::CapabilityImplementationSupport;

    /// Executes one action under a bounded trusted context.
    async fn invoke_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure>;

    /// Plans or dry-runs one governed mutation.
    async fn plan_typed(
        &self,
        _action: Action,
        _context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        Err(ConnectorFailure::unsupported(
            ConnectorOperation::TransactionPlan,
            self.id(),
        ))
    }

    /// Commits one prepared mutation.
    async fn commit_typed(
        &self,
        _action: Action,
        _context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        Err(ConnectorFailure::unsupported(
            ConnectorOperation::TransactionCommit,
            self.id(),
        ))
    }

    /// Executes one separately governed compensation action.
    async fn compensate_typed(
        &self,
        _action: Action,
        _context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        Err(ConnectorFailure::unsupported(
            ConnectorOperation::Compensation,
            self.id(),
        ))
    }

    /// Cancels a previously submitted downstream operation.
    async fn cancel_typed(
        &self,
        _action: &Action,
        _context: ActionExecutionContext,
    ) -> Result<(), ConnectorFailure> {
        Err(ConnectorFailure::unsupported(
            ConnectorOperation::Cancellation,
            self.id(),
        ))
    }

    /// Reconciles an uncertain provider outcome.
    async fn reconcile_typed(
        &self,
        _request: ReconciliationRequest,
        _context: ActionExecutionContext,
    ) -> Result<ReconciliationResult, ConnectorFailure> {
        Err(ConnectorFailure::unsupported(
            ConnectorOperation::Reconciliation,
            self.id(),
        ))
    }

    /// Emits a terminal result or provider event.
    async fn emit_typed(
        &self,
        _result: ActionResult,
        _context: ActionExecutionContext,
    ) -> Result<(), ConnectorFailure> {
        Err(ConnectorFailure::unsupported(
            ConnectorOperation::Emission,
            self.id(),
        ))
    }

    /// Ingests one provider event under a trusted execution boundary.
    async fn ingest_typed(
        &self,
        _payload: Value,
        _context: ActionExecutionContext,
    ) -> Result<Vec<Envelope>, ConnectorFailure> {
        Err(ConnectorFailure::unsupported(
            ConnectorOperation::Ingestion,
            self.id(),
        ))
    }
}

/// Runtime adapter for one frozen connector capability.
pub struct FrozenConnectorHandler<C> {
    connector: Arc<C>,
    capability: Capability,
}

impl<C> FrozenConnectorHandler<C> {
    /// Binds a connector implementation to one admitted capability.
    #[must_use]
    pub fn new(connector: Arc<C>, capability: Capability) -> Self {
        Self {
            connector,
            capability,
        }
    }
}

#[async_trait]
impl<C> ActionHandler for FrozenConnectorHandler<C>
where
    C: FrozenConnector + 'static,
{
    fn implementation_support(&self) -> aip_discovery::CapabilityImplementationSupport {
        self.connector.implementation_support(&self.capability)
    }

    async fn handle(&self, _action: Action) -> RuntimeResult<ActionResult> {
        Err(RuntimeError::Authorization(
            "frozen connectors require a trusted execution context".to_owned(),
        ))
    }

    async fn handle_with_context(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> RuntimeResult<ActionResult> {
        if action.capability_id != self.capability.id {
            return Err(RuntimeError::Handler(format!(
                "connector handler for `{}` received `{}`",
                self.capability.id, action.capability_id
            )));
        }
        let transaction_mode = action
            .transaction
            .as_ref()
            .map(|transaction| transaction.mode);
        let result = match transaction_mode {
            Some(TransactionMode::DryRun | TransactionMode::Plan) => {
                self.connector.plan_typed(action, context).await
            }
            Some(TransactionMode::Commit) => self.connector.commit_typed(action, context).await,
            Some(TransactionMode::Compensate) => {
                self.connector.compensate_typed(action, context).await
            }
            Some(TransactionMode::Reconcile) => {
                let transaction = context.transaction.as_ref().ok_or_else(|| {
                    RuntimeError::Handler(
                        "reconciliation requires transaction execution context".to_owned(),
                    )
                })?;
                let provider_operation_id =
                    transaction.provider_operation_id.clone().ok_or_else(|| {
                        RuntimeError::Handler(
                            "reconciliation requires a durable provider operation id".to_owned(),
                        )
                    })?;
                let reconciliation = self
                    .connector
                    .reconcile_typed(
                        ReconciliationRequest {
                            transaction_id: transaction.transaction_id.clone(),
                            provider_operation_id,
                            cursor: transaction.reconciliation_cursor.clone(),
                        },
                        context,
                    )
                    .await;
                return reconciliation
                    .map(|reconciliation| reconciliation_action_result(action.id, reconciliation))
                    .map_err(|failure| RuntimeError::Protocol(failure.to_protocol_error()));
            }
            Some(TransactionMode::Execute | TransactionMode::RollbackNotSupported) | None => {
                self.connector.invoke_typed(action, context).await
            }
        };
        result.map_err(|failure| RuntimeError::Protocol(failure.to_protocol_error()))
    }

    async fn cancel(&self, action: &Action) -> RuntimeResult<()> {
        let _ = action;
        Err(RuntimeError::Protocol(
            ConnectorFailure::unsupported(ConnectorOperation::Cancellation, self.connector.id())
                .to_protocol_error(),
        ))
    }

    async fn cancel_with_context(
        &self,
        action: &Action,
        context: &ActionExecutionContext,
    ) -> RuntimeResult<()> {
        self.connector
            .cancel_typed(action, context.clone())
            .await
            .map_err(|failure| RuntimeError::Protocol(failure.to_protocol_error()))
    }
}

fn reconciliation_action_result(
    action_id: aip_core::ActionId,
    result: ReconciliationResult,
) -> ActionResult {
    if result.terminal {
        ActionResult {
            action_id,
            status: aip_core::ActionResultStatus::Completed,
            output: Some(serde_json::json!({
                "reconciliation": {
                    "terminal": true,
                    "committed": result.committed,
                    "cursor": result.cursor,
                    "evidence": result.evidence
                }
            })),
            message: Vec::new(),
            memory_update: None,
            usage: None,
            receipt: None,
            error: None,
        }
    } else {
        ActionResult {
            action_id,
            status: aip_core::ActionResultStatus::Failed,
            output: None,
            message: Vec::new(),
            memory_update: None,
            usage: None,
            receipt: None,
            error: Some(ProtocolError {
                code: "transaction.reconciliation_pending".to_owned(),
                message: "provider outcome is still pending reconciliation".to_owned(),
                category: ErrorCategory::Temporary,
                retryable: Some(true),
                retry_after_ms: Some(5_000),
                details: Some(Box::new(serde_json::json!({
                    "reconciliation_cursor": result.cursor,
                    "evidence": result.evidence
                }))),
                source: Some(Box::new(serde_json::json!({
                    "component": "aip-connector"
                }))),
            }),
        }
    }
}

/// Selects the typed connector operation implied by an AIP transaction mode.
#[must_use]
pub const fn operation_for_transaction(mode: TransactionMode) -> ConnectorOperation {
    match mode {
        TransactionMode::DryRun | TransactionMode::Plan => ConnectorOperation::TransactionPlan,
        TransactionMode::Commit => ConnectorOperation::TransactionCommit,
        TransactionMode::Execute => ConnectorOperation::Invocation,
        TransactionMode::Compensate => ConnectorOperation::Compensation,
        TransactionMode::Reconcile => ConnectorOperation::Reconciliation,
        TransactionMode::RollbackNotSupported => ConnectorOperation::Invocation,
    }
}

/// Connector that can map human escalation to a product workflow.
#[async_trait]
pub trait EscalationConnector: Connector {
    /// Sends an escalation to the product.
    async fn escalate(
        &self,
        context: &ConnectorContext,
        escalation: Escalation,
    ) -> ConnectorResult<()>;
}

#[cfg(test)]
mod tests {
    use super::{ConnectorOperation, operation_for_transaction};
    use aip_core::TransactionMode;

    #[test]
    fn execute_is_normal_invocation_not_transaction_commit() {
        assert_eq!(
            operation_for_transaction(TransactionMode::Execute),
            ConnectorOperation::Invocation
        );
        assert_eq!(
            operation_for_transaction(TransactionMode::Commit),
            ConnectorOperation::TransactionCommit
        );
    }
}
