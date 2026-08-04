//! Native AIP message payloads.

use crate::{
    Action, ActionId, ActionTransaction, ApprovalDecision, ApprovalId, ApprovalPolicy,
    ApprovalRequest, Callback, Capability, CapabilityId, CompensationContract, Conversation,
    CorrelationId, DelegationId, DryRunFidelity, Event, IdentityContext, MessageId, MessagePart,
    Principal, PrincipalId, ProfileId, ReceiptId, Resource, RiskLevel, SessionId, SessionState,
    SideEffect, TransactionId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use time::OffsetDateTime;

/// Handshake request for session negotiation.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Handshake {
    /// Caller identity.
    pub client: Principal,
    /// Intended session purpose.
    pub purpose: String,
    /// Requested capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_capabilities: Vec<CapabilityId>,
    /// Profiles supported by the caller.
    pub profiles: Vec<ProfileId>,
    /// Authentication proof or token metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Value>,
    /// Required compliance regimes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compliance_required: Vec<String>,
    /// Requested heartbeat settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<Value>,
    /// Session encryption request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Value>,
    /// Billing/settlement preference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing: Option<Value>,
}

/// Handshake response status.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeStatus {
    /// Session accepted.
    Accepted,
    /// Session rejected.
    Rejected,
    /// Caller should use another endpoint or participant.
    Redirect,
}

/// Handshake negotiation response.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Negotiation status.
    pub status: HandshakeStatus,
    /// Created session id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Initial single-use opaque resume token for the created session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_token: Option<String>,
    /// Responder identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<Principal>,
    /// Selected profiles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agreed_profiles: Vec<ProfileId>,
    /// Accepted capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agreed_capabilities: Vec<CapabilityId>,
    /// Agreed heartbeat settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<Value>,
    /// Session encryption metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Value>,
    /// Billing/settlement metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing: Option<Value>,
    /// Redirect target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<Value>,
    /// Rejection details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<ProtocolError>,
}

/// Action acknowledgement state.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckStatus {
    /// Action accepted for processing.
    Accepted,
    /// Action rejected before processing.
    Rejected,
    /// Action queued.
    Queued,
    /// Action accepted and stream will follow.
    Streaming,
    /// Idempotent replay returned cached result.
    Cached,
}

/// Acknowledgement for an action.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ack {
    /// Acknowledged action.
    pub action_id: ActionId,
    /// Acknowledgement state.
    pub status: AckStatus,
    /// Machine/human reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Retry hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    /// Queue metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<Value>,
}

/// Stream chunk kind.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamChunkKind {
    /// Partial user-visible output.
    Data,
    /// Progress update.
    Progress,
    /// Tool call update.
    Tool,
    /// Optional reasoning/progress event.
    Thought,
    /// Preview artifact.
    Preview,
    /// Human approval is pending.
    PendingApproval,
    /// Stream-level error.
    Error,
    /// Stream completed.
    Done,
}

/// Partial output, progress, tool event, or terminal stream marker.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StreamChunk {
    /// Source action.
    pub action_id: ActionId,
    /// Monotonic chunk sequence.
    pub sequence: u64,
    /// Chunk kind.
    pub kind: StreamChunkKind,
    /// Structured chunk data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// Optional rich message part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part: Option<MessagePart>,
}

/// Final action status.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionResultStatus {
    /// Action completed.
    Completed,
    /// Action failed.
    Failed,
    /// Action was cancelled.
    Cancelled,
    /// Action is blocked on a durable approval request.
    PendingApproval,
    /// Action requires human input or approval.
    RequiresHuman,
}

/// Usage and cost metadata.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Usage {
    /// Token usage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Value>,
    /// Tool usage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Value>,
    /// End-to-end latency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// Cost metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<Value>,
}

/// Reference to a signed receipt.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReceiptRef {
    /// Receipt id.
    pub id: ReceiptId,
    /// Receipt hash.
    pub hash: String,
}

/// Final action result.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionResult {
    /// Source action.
    pub action_id: ActionId,
    /// Result status.
    pub status: ActionResultStatus,
    /// Structured output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    /// User-facing message parts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub message: Vec<MessagePart>,
    /// Memory/state update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_update: Option<Value>,
    /// Usage/cost metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    /// Signed receipt reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ReceiptRef>,
    /// Error details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

/// Request for the durable lifecycle view of one action.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionStatusRequest {
    /// Action to inspect.
    pub action_id: ActionId,
    /// Optional tenant boundary expected by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Include the final result when available.
    #[serde(default)]
    pub include_result: bool,
    /// Include the receipt chain when available.
    #[serde(default)]
    pub include_receipts: bool,
    /// Include durable stream chunks for the action.
    #[serde(default)]
    pub include_chunks: bool,
    /// Optional bounded wait preference in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
}

/// Stable native action lifecycle state exposed by AIP query APIs.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionLifecycleState {
    /// The action id is unknown to the current runtime.
    Unknown,
    /// The action was accepted but has not entered a queue.
    Accepted,
    /// The action is queued for execution.
    Queued,
    /// The action is currently running.
    Running,
    /// The action is emitting a stream.
    Streaming,
    /// The action is blocked on a human approval.
    PendingApproval,
    /// The action is being cancelled.
    Cancelling,
    /// The action was cancelled.
    Cancelled,
    /// The action completed successfully.
    Completed,
    /// The action failed.
    Failed,
    /// The action state expired by retention policy.
    Expired,
    /// The action is parked in the dead-letter queue.
    DeadLettered,
}

/// Durable native action lifecycle view.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionStatus {
    /// Action id.
    pub action_id: ActionId,
    /// Capability invoked by the action, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<CapabilityId>,
    /// Session bound to the action, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Correlation id bound to the action, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,
    /// Stable lifecycle state.
    pub state: ActionLifecycleState,
    /// Backend queue state label, when a queue record exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued_state: Option<String>,
    /// Terminal result status, when a result exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_status: Option<ActionResultStatus>,
    /// Approval id blocking the action, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
    /// Transaction id associated with the action, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<TransactionId>,
    /// Delegation id associated with the action, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<DelegationId>,
    /// Time when the action started execution.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub started_at: Option<OffsetDateTime>,
    /// Last durable state update time.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub updated_at: OffsetDateTime,
    /// Terminal completion time, when known.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub completed_at: Option<OffsetDateTime>,
    /// Retry metadata safe for operational readers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<Value>,
    /// Lease metadata safe for operational readers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<Value>,
    /// Final result when requested and available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ActionResult>,
    /// Receipt chain when requested and available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_chain: Option<ReceiptChain>,
    /// Durable stream chunks when requested.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<StreamChunk>,
    /// Typed links exposed by HTTP and SDK bindings.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<String, String>,
}

/// Request for one final action result.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionResultRequest {
    /// Action to inspect.
    pub action_id: ActionId,
    /// Optional tenant boundary expected by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Optional bounded wait preference in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
    /// Include receipt metadata when available.
    #[serde(default)]
    pub include_receipt: bool,
    /// Include terminal event hints when available.
    #[serde(default)]
    pub include_terminal_events: bool,
}

/// Request for a filtered durable action list.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionListRequest {
    /// Lifecycle state filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<ActionLifecycleState>,
    /// Capability filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<CapabilityId>,
    /// Session filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Requesting principal filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<PrincipalId>,
    /// Approval id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
    /// Transaction id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<TransactionId>,
    /// Tenant id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Opaque page cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Maximum number of actions to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Include results when available.
    #[serde(default)]
    pub include_results: bool,
    /// Include receipt chains when available.
    #[serde(default)]
    pub include_receipts: bool,
}

/// Filtered durable action list.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionList {
    /// Action views visible to the caller.
    pub actions: Vec<ActionStatus>,
    /// Number of matching actions before pagination.
    pub total_size: u64,
    /// Cursor for the next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Request for events and chunks scoped to one action.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionEventsRequest {
    /// Action to inspect.
    pub action_id: ActionId,
    /// Optional tenant boundary expected by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Opaque event cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Maximum number of events to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Event kind filter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<String>,
    /// Include durable stream chunks.
    #[serde(default)]
    pub include_chunks: bool,
    /// Caller preference for streaming/following bindings.
    #[serde(default)]
    pub follow: bool,
}

/// Events and chunks scoped to one action.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionEvents {
    /// Source action.
    pub action_id: ActionId,
    /// Ordered action-scoped events.
    pub events: Vec<Event>,
    /// Ordered action-scoped stream chunks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<StreamChunk>,
    /// Cursor for the next event page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Whether the action is in a terminal lifecycle state.
    pub terminal: bool,
}

/// Transaction lifecycle state exposed on the AIP wire.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionProtocolStatus {
    /// Dry-run validation or simulation completed.
    DryRunCompleted,
    /// A durable plan was created.
    Planned,
    /// A provider accepted and prepared the operation without committing it.
    Prepared,
    /// One commit action atomically owns execution of the plan.
    Committing,
    /// A previously planned or direct operation was committed.
    Committed,
    /// A compensating action is executing.
    Compensating,
    /// A compensating operation completed.
    Compensated,
    /// The transaction is waiting for human approval or input.
    RequiresHuman,
    /// The transaction was cancelled.
    Cancelled,
    /// The operation explicitly does not support rollback.
    RollbackNotSupported,
    /// The transaction failed before reaching a committed terminal state.
    Failed,
    /// The provider may have committed, but no definitive result is available.
    OutcomeUnknown,
    /// Provider state is being reconciled before retry or compensation.
    Reconciling,
    /// Reconciliation established the durable provider outcome.
    Reconciled,
}

/// Durable reference to an operation accepted by an external provider.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderOperationRef {
    /// Provider or connector id.
    pub provider: String,
    /// Provider-local operation id.
    pub operation_id: String,
    /// Optional provider request or trace id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Durable execution plan produced by a transactional `Plan` action.
///
/// The plan is protocol-visible evidence for a later `Commit`. It captures the
/// exact action input hash, capability binding, relevant enterprise policy
/// metadata, and identity snapshot so runtimes can reject commits that no
/// longer match the planned operation.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionPlan {
    /// Stable plan id referenced by commit requests.
    pub plan_id: String,
    /// Stable transaction id for the plan.
    pub transaction_id: TransactionId,
    /// Action that created the plan.
    pub action_id: ActionId,
    /// Capability the plan was produced for.
    pub capability_id: CapabilityId,
    /// Planned transaction context.
    pub transaction: ActionTransaction,
    /// Principal that requested the plan.
    pub planned_by: Principal,
    /// Canonical SHA-256 hash of the planned action input.
    pub input_hash: String,
    /// Optional redacted or raw input snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_snapshot: Option<Value>,
    /// Expected side effects declared by the capability contract.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub predicted_side_effects: Vec<SideEffect>,
    /// Whether committing the plan requires approval.
    pub approval_required: bool,
    /// Approval policy evaluated during planning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_policy: Option<ApprovalPolicy>,
    /// Compensation contract available for the planned operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensation: Option<CompensationContract>,
    /// Dry-run fidelity advertised by the capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run_fidelity: Option<DryRunFidelity>,
    /// Identity snapshot captured during planning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityContext>,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub created_at: OffsetDateTime,
    /// Optional plan expiration.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub expires_at: Option<OffsetDateTime>,
    /// Additional runtime metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// First-class request to execute a transactional AIP action.
///
/// `Action.transaction` remains the canonical semantic context for the
/// operation. This wrapper makes transaction workflows explicit on the wire so
/// gateways and runtimes can route, audit, and validate plan/commit/compensate
/// flows without embedding transaction commands inside adapter-specific JSON.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionRequest {
    /// Stable transaction id for correlation across plan, commit, and compensation.
    pub transaction_id: TransactionId,
    /// Action carrying the transactional operation.
    pub action: Action,
    /// Principal requesting the transactional operation.
    pub requested_by: Principal,
    /// Human-readable reason for policy, approval, and audit systems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional request metadata for scheduling, audit, or transport bindings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// Durable provider operation reference for reconciliation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_operation: Option<ProviderOperationRef>,
    /// Opaque cursor from the preceding reconciliation attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation_cursor: Option<String>,
}

/// Result of a first-class transactional AIP action.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionResult {
    /// Stable transaction id from the request or action context.
    pub transaction_id: TransactionId,
    /// Action associated with this transaction.
    pub action_id: ActionId,
    /// Capability associated with the transaction.
    pub capability_id: CapabilityId,
    /// Transaction context that was evaluated.
    pub transaction: ActionTransaction,
    /// Wire-visible transaction status.
    pub status: TransactionProtocolStatus,
    /// Execution plan, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<TransactionPlan>,
    /// Final action result when execution reached a handler.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ActionResult>,
    /// Protocol-level failure when no valid action result exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
    /// Receipt chain proving the transaction decision or terminal state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_chain: Option<ReceiptChain>,
    /// Durable provider operation reference used for reconciliation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_operation: Option<ProviderOperationRef>,
    /// Opaque provider cursor used to continue reconciliation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation_cursor: Option<String>,
    /// Earliest time at which reconciliation should be retried.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub reconcile_after: Option<OffsetDateTime>,
}

/// Delegation lifecycle status.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationStatus {
    /// Delegation was accepted but has not started.
    Accepted,
    /// Delegated child action is running.
    Running,
    /// Delegated child action completed.
    Completed,
    /// Delegated child action failed.
    Failed,
    /// Delegated child action was cancelled.
    Cancelled,
    /// Delegated child action is waiting for human input or approval.
    RequiresHuman,
}

/// First-class request to delegate an action to another AIP participant.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationRequest {
    /// Stable delegation id for the parent-child graph edge.
    pub delegation_id: DelegationId,
    /// Parent action that created this delegation.
    pub parent_action_id: ActionId,
    /// Child action to execute on the delegate.
    pub child_action: Action,
    /// Principal creating the delegation.
    pub requested_by: Principal,
    /// Principal expected to execute the child action.
    pub delegate: Principal,
    /// Delegated authorization scope.
    pub scope: String,
    /// Optional callback target for the final delegation result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback: Option<Callback>,
    /// Routing, scheduling, or product-specific delegation metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Result of a first-class delegation request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationResult {
    /// Delegation id from the original request.
    pub delegation_id: DelegationId,
    /// Parent action that created this delegation.
    pub parent_action_id: ActionId,
    /// Child action executed for this delegation.
    pub child_action_id: ActionId,
    /// Final delegation status.
    pub status: DelegationStatus,
    /// Final child action result when execution reached the child handler.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ActionResult>,
    /// Protocol-level error when scheduling or execution failed before a child result existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
    /// Receipt chain proving the delegation was made and observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_chain: Option<ReceiptChain>,
    /// Dispatcher metadata for callback delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback: Option<Value>,
}

/// Durable parent-child delegation graph record.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationRecord {
    /// Original delegation request.
    pub request: DelegationRequest,
    /// Current delegation status.
    pub status: DelegationStatus,
    /// Final result, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<DelegationResult>,
    /// Creation timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub created_at: OffsetDateTime,
    /// Last update timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub updated_at: OffsetDateTime,
}

/// Protocol error category.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    /// Temporary failure.
    Temporary,
    /// Permanent failure.
    Permanent,
    /// Authentication or authorization failure.
    Auth,
    /// Policy failure.
    Policy,
    /// Economic/settlement failure.
    Economic,
    /// Connector failure.
    Connector,
    /// Transport failure.
    Transport,
}

/// Machine-readable protocol or action error.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtocolError {
    /// Stable machine code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Error category.
    pub category: ErrorCategory,
    /// Whether retry is safe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
    /// Suggested retry delay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    /// Structured details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Box<Value>>,
    /// Connector/profile/source metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Box<Value>>,
}

impl ProtocolError {
    /// Creates a permanent validation error.
    #[must_use]
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self {
            code: "action.invalid_input".to_owned(),
            message: message.into(),
            category: ErrorCategory::Permanent,
            retryable: Some(false),
            retry_after_ms: None,
            details: None,
            source: None,
        }
    }
}

/// Error message body.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Error details.
    pub error: ProtocolError,
}

/// Cancellation target.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelTarget {
    /// Cancel an action.
    Action(ActionId),
    /// Cancel a session.
    Session(SessionId),
}

/// Cancellation request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Cancel {
    /// Target to cancel.
    pub target: CancelTarget,
    /// Optional cancellation reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Liveness/progress signal.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Heartbeat sequence.
    pub sequence: u64,
    /// Status text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Progress percentage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<f32>,
}

/// Heartbeat acknowledgement.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HeartbeatAck {
    /// Acknowledged heartbeat sequence.
    pub sequence: u64,
    /// Receiver timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub received_at: OffsetDateTime,
}

/// Human escalation category.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationKind {
    /// Human approval request.
    Approval,
    /// Human input request.
    Input,
    /// Human handoff request.
    Handoff,
    /// Policy exception review.
    PolicyException,
}

/// Human decision options.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationDecision {
    /// Approve work.
    Approve,
    /// Reject work.
    Reject,
    /// Modify work.
    Modify,
    /// Hand off work.
    Handoff,
    /// Cancel work.
    Cancel,
}

/// Human-in-the-loop escalation request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Escalation {
    /// Escalation category.
    pub kind: EscalationKind,
    /// Human-readable reason.
    pub reason: String,
    /// Requesting actor.
    pub requested_by: Principal,
    /// Human input form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form: Option<Value>,
    /// Risk level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<RiskLevel>,
    /// Escalation timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Allowed decisions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_decisions: Vec<EscalationDecision>,
    /// Channel context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<Conversation>,
}

/// Escalation resolution status.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationResolutionStatus {
    /// Human approved.
    Approved,
    /// Human rejected.
    Rejected,
    /// Human modified the input/action.
    Modified,
    /// Human took over.
    HandoffCompleted,
    /// Escalation expired.
    Expired,
    /// Escalation was cancelled.
    Cancelled,
}

/// Escalation resolution.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EscalationResolution {
    /// Resolution status.
    pub status: EscalationResolutionStatus,
    /// Resolving actor.
    pub resolved_by: Principal,
    /// Resolution timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub resolved_at: OffsetDateTime,
    /// Modified payload or result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}

/// Request for a participant manifest.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManifestRequest {
    /// Requested profiles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<ProfileId>,
    /// Optional native discovery filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<ManifestFilter>,
}

/// AIP participant manifest.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest schema version.
    pub manifest_version: String,
    /// Provider identity.
    pub agent: Principal,
    /// Exposed capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
    /// Supported profiles.
    pub profiles: Vec<ProfileId>,
    /// Readable resources.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<Resource>,
    /// Supported channel operations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<Value>,
    /// Auth/signature requirements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<Value>,
    /// Audit/compliance metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance: Option<Value>,
    /// Limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Value>,
    /// Profile compatibility metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility: Option<Value>,
    /// Vendor extensions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

/// Event stream request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventStreamRequest {
    /// Starting cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Maximum events to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Event kind filter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<String>,
}

/// Event stream response.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventStream {
    /// Events.
    pub events: Vec<Event>,
    /// Next cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Filter for native manifest and capability discovery requests.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFilter {
    /// Capability ids to include.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_ids: Vec<CapabilityId>,
    /// Resource kind labels to include.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_kinds: Vec<String>,
    /// Profile ids to include.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<ProfileId>,
    /// Risk levels to include.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk: Vec<RiskLevel>,
    /// Required side-effect categories.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub side_effects: Vec<SideEffect>,
    /// Filter by approval requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,
    /// Filter capabilities that support streaming.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_streaming: Option<bool>,
    /// Filter capabilities that support transaction semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_transactions: Option<bool>,
}

/// Request for one durable session view.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRequest {
    /// Session to inspect.
    pub session_id: SessionId,
}

/// Request for filtered durable session views.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionListRequest {
    /// Principal filter matching initiator or responder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<PrincipalId>,
    /// Session lifecycle state filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<SessionState>,
    /// Opaque page cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Maximum number of sessions to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Durable session read-model view.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionView {
    /// Stable session id.
    pub session_id: SessionId,
    /// Current lifecycle state.
    pub status: SessionState,
    /// Session initiator.
    pub principal: Principal,
    /// Session responder.
    pub peer: Principal,
    /// Creation timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub created_at: OffsetDateTime,
    /// Last known state update timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub updated_at: OffsetDateTime,
    /// Optional expiration timestamp.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub expires_at: Option<OffsetDateTime>,
    /// Number of non-terminal actions bound to this session.
    pub active_action_count: u64,
    /// Operational links for HTTP and SDK bindings.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<String, String>,
}

/// Filtered session list.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionList {
    /// Sessions visible to the caller.
    pub sessions: Vec<SessionView>,
    /// Cursor for the next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Request to close one session.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCloseRequest {
    /// Session to close.
    pub session_id: SessionId,
    /// Optional operator-visible reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Request to resume one session after reconnect.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResumeRequest {
    /// Session to resume.
    pub session_id: SessionId,
    /// Optional bearer or opaque resume token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_token: Option<String>,
    /// Last event cursor observed by the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_cursor: Option<String>,
}

/// Session resume response.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionResume {
    /// Resumed session view.
    pub session: SessionView,
    /// Events replayed after the supplied cursor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replayed_events: Vec<Event>,
    /// Next cursor for subsequent reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Rotated single-use resume token. The previous token is invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_token: Option<String>,
}

/// Request for one approval record.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalQueryRequest {
    /// Approval id to inspect.
    pub approval_id: ApprovalId,
    /// Optional tenant boundary expected by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Include linked action status when available.
    #[serde(default)]
    pub include_action_status: bool,
    /// Include receipt chain when available.
    #[serde(default)]
    pub include_receipts: bool,
    /// Export the immutable governed action payload used for approval.
    ///
    /// This field contains potentially sensitive action input and is available
    /// only to an approval-visible actor authorized for both `approval:export`
    /// and `approval:sensitive`.
    #[serde(default)]
    pub include_evidence_payload: bool,
}

/// Request for filtered approval records.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalListRequest {
    /// Approval status label such as `pending`, `approved`, or `denied`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Approver principal filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<PrincipalId>,
    /// Requester principal filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<PrincipalId>,
    /// Tenant id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Opaque page cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Maximum number of records to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Include linked action status when available.
    #[serde(default)]
    pub include_action_status: bool,
    /// Include receipt chains when available.
    #[serde(default)]
    pub include_receipts: bool,
}

/// Durable approval read-model view.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRecordView {
    /// Original approval request.
    pub request: ApprovalRequest,
    /// Final decision, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<ApprovalDecision>,
    /// Stable lifecycle status label.
    pub status: String,
    /// Linked action status, when requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_status: Option<ActionStatus>,
    /// Receipt chain, when requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_chain: Option<ReceiptChain>,
    /// Sensitive immutable action evidence, when explicitly exported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_payload: Option<ApprovalEvidencePayload>,
    /// Creation timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub created_at: OffsetDateTime,
    /// Last update timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub updated_at: OffsetDateTime,
}

/// Immutable governed action payload exported for an approval decision.
///
/// Runtimes derive this view from the durable queued action. It is never copied
/// into the approval request, receipts, audit events, callbacks, or ordinary
/// read responses. `input_hash` uses the same canonical hash represented by an
/// approval request's `input_snapshot` evidence artifact.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalEvidencePayload {
    /// Action protected by the approval.
    pub action_id: ActionId,
    /// Capability protected by the approval.
    pub capability_id: CapabilityId,
    /// Canonical SHA-256 hash covering capability, input, and transaction.
    pub input_hash: String,
    /// Exact action input supplied to the governed capability.
    pub input: Value,
    /// Transaction context, including plan binding, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<ActionTransaction>,
    /// Trusted identity context resolved for the governed action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityContext>,
}

/// Filtered approval list.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalList {
    /// Approval records visible to the caller.
    pub approvals: Vec<ApprovalRecordView>,
    /// Cursor for the next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Request for one transaction view.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionQueryRequest {
    /// Transaction id selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<TransactionId>,
    /// Plan id selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
    /// Action id selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<ActionId>,
    /// Optional tenant boundary expected by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Include terminal action result when available.
    #[serde(default)]
    pub include_result: bool,
    /// Include receipt chain when available.
    #[serde(default)]
    pub include_receipts: bool,
}

/// Durable transaction read-model view.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionView {
    /// Transaction id.
    pub transaction_id: TransactionId,
    /// Associated action id.
    pub action_id: ActionId,
    /// Associated capability id.
    pub capability_id: CapabilityId,
    /// Transaction context.
    pub transaction: ActionTransaction,
    /// Stable transaction status label.
    pub status: String,
    /// Durable execution plan, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<TransactionPlan>,
    /// Final result when requested and available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ActionResult>,
    /// Receipt chain when requested and available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_chain: Option<ReceiptChain>,
    /// Creation timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub created_at: OffsetDateTime,
    /// Last update timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub updated_at: OffsetDateTime,
}

/// Request for one receipt chain.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptQueryRequest {
    /// Receipt chain id selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    /// Individual receipt id selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<ReceiptId>,
}

/// Request for filtered audit event records.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQueryRequest {
    /// Action id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<ActionId>,
    /// Session id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Principal id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<PrincipalId>,
    /// Transaction id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<TransactionId>,
    /// Tenant id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Inclusive lower timestamp bound.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub from: Option<OffsetDateTime>,
    /// Inclusive upper timestamp bound.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub to: Option<OffsetDateTime>,
    /// Opaque page cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Maximum number of records to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Include related receipt chains.
    #[serde(default)]
    pub include_receipts: bool,
    /// Treat the query as an evidence export requiring export authority.
    ///
    /// Export mode is intentionally explicit so normal audit browsing can use
    /// `audit:read`, while evidence packages that may leave the runtime trust
    /// boundary require `audit:export`.
    #[serde(default)]
    pub export: bool,
}

/// Filtered audit query result.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditQueryResult {
    /// Audit events visible to the caller.
    pub events: Vec<AuditEvent>,
    /// Receipt chains linked to returned events.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipt_chains: Vec<ReceiptChain>,
    /// Cursor for the next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Native resource list request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceListRequest {
    /// Capability id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<CapabilityId>,
    /// Resource kind label filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Tenant id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Opaque page cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Maximum number of resources to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Native resource list result.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceList {
    /// Resources visible to the caller.
    pub resources: Vec<Resource>,
    /// Cursor for the next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Native resource read request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceReadRequest {
    /// Resource id to read.
    pub resource_id: String,
    /// Optional tenant boundary expected by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Optional resource version selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Acceptable MIME types or profile labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accept: Vec<String>,
}

/// Native resource read result.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceReadResult {
    /// Resource metadata.
    pub resource: Resource,
    /// Optional resource content.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content: Vec<MessagePart>,
    /// Optional entity tag for cache validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// Optional expiration timestamp.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub expires_at: Option<OffsetDateTime>,
}

/// Transport-independent callback delivery policy.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallbackDeliveryPolicy {
    /// Stable delivery id used for deduplication and audit.
    pub delivery_id: String,
    /// Callback target.
    pub target: Callback,
    /// Maximum delivery attempts.
    pub max_attempts: u32,
    /// Per-attempt timeout.
    pub timeout_ms: u64,
    /// Retry backoff schedule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retry_backoff_ms: Vec<u64>,
    /// Idempotency key propagated to delivery targets.
    pub idempotency_key: String,
    /// Whether the transport should sign payloads when supported.
    pub sign_payload: bool,
    /// Whether only terminal lifecycle states should be delivered.
    pub terminal_only: bool,
}

/// Stable callback delivery lifecycle state.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackDeliveryStatus {
    /// Delivery is accepted and waiting for an attempt window.
    Pending,
    /// A delivery attempt is currently in progress.
    Running,
    /// The callback target acknowledged the envelope.
    Delivered,
    /// The delivery exhausted its retry budget.
    Failed,
    /// The delivery is parked in the dead-letter queue after terminal failure.
    DeadLettered,
}

/// Durable view of one callback delivery attempt.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallbackDeliveryAttempt {
    /// One-based attempt number.
    pub attempt: u32,
    /// Attempt start timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub started_at: OffsetDateTime,
    /// Attempt finish timestamp.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub finished_at: Option<OffsetDateTime>,
    /// Attempt error, when the target rejected the envelope or timed out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Durable native view of callback delivery state.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallbackDeliveryRecord {
    /// Stable delivery id.
    pub delivery_id: String,
    /// Delivery policy used by the runtime.
    pub policy: CallbackDeliveryPolicy,
    /// Envelope message id being delivered.
    pub message_id: MessageId,
    /// Envelope message type being delivered.
    pub message_type: String,
    /// Action associated with the delivered message, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<ActionId>,
    /// Session associated with the delivered message, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Correlation id associated with the delivered message, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,
    /// Tenant associated with the delivery, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Stable delivery status.
    pub status: CallbackDeliveryStatus,
    /// Recorded attempts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attempts: Vec<CallbackDeliveryAttempt>,
    /// Earliest retry time after a failed attempt.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub next_attempt_at: Option<OffsetDateTime>,
    /// Worker currently holding the delivery lease, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leased_by: Option<String>,
    /// Lease expiration time after which another worker may recover the delivery.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub lease_expires_at: Option<OffsetDateTime>,
    /// Last delivery error, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Dead-letter reason when the delivery can no longer be retried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead_letter_reason: Option<String>,
    /// Receipt chain, when requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_chain: Option<ReceiptChain>,
    /// Creation timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub created_at: OffsetDateTime,
    /// Last update timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub updated_at: OffsetDateTime,
    /// Terminal timestamp when delivery completed or failed.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub completed_at: Option<OffsetDateTime>,
}

/// Request for one callback delivery record.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackDeliveryQueryRequest {
    /// Stable delivery id.
    pub delivery_id: String,
    /// Optional tenant boundary expected by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Include receipt chain when available.
    #[serde(default)]
    pub include_receipts: bool,
}

/// Request for filtered callback delivery records.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackDeliveryListRequest {
    /// Action id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<ActionId>,
    /// Delivery status filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<CallbackDeliveryStatus>,
    /// Callback profile filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileId>,
    /// Callback target filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Tenant id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Opaque page cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Maximum number of records to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Include receipt chains when available.
    #[serde(default)]
    pub include_receipts: bool,
}

/// Filtered callback delivery list.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallbackDeliveryList {
    /// Delivery records visible to the caller.
    pub deliveries: Vec<CallbackDeliveryRecord>,
    /// Cursor for the next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// External channel message.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChannelMessage {
    /// Conversation/thread.
    pub conversation: Conversation,
    /// Identity context used by policy, audit, and credential mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityContext>,
    /// Message metadata.
    pub message: Value,
    /// Sender.
    pub sender: Principal,
    /// Message parts.
    pub parts: Vec<MessagePart>,
    /// Delivery/idempotency metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<Value>,
    /// Original product payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_payload: Option<Value>,
}

/// Conversation update payload.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConversationUpdated {
    /// Updated conversation.
    pub conversation: Conversation,
    /// Identity context used by policy and audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityContext>,
    /// Changed field names.
    pub changed_fields: Vec<String>,
}

/// Receipt type.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptType {
    /// Request received.
    RequestReceived,
    /// Action accepted.
    ActionAccepted,
    /// Policy engine decision recorded.
    PolicyDecision,
    /// Approval request created.
    ApprovalRequested,
    /// Approval was granted.
    ApprovalGranted,
    /// Approval was denied.
    ApprovalDenied,
    /// Approval expired before a decision.
    ApprovalExpired,
    /// Approval was revoked.
    ApprovalRevoked,
    /// Tool executed.
    ToolExecuted,
    /// Delegation made.
    DelegationMade,
    /// Human approved.
    HumanApproved,
    /// Result returned.
    ResultReturned,
    /// Settlement recorded.
    SettlementRecorded,
    /// Transaction plan created.
    TransactionPlanned,
    /// A commit action atomically acquired the transaction plan.
    TransactionCommitStarted,
    /// Transaction committed.
    TransactionCommitted,
    /// Compensating transaction executed.
    TransactionCompensated,
    /// Dry-run validation or simulation completed.
    TransactionDryRunCompleted,
    /// Transaction was blocked because rollback is unsupported.
    TransactionRollbackUnsupported,
    /// Transaction failed.
    TransactionFailed,
    /// Callback delivery attempt started.
    CallbackDeliveryAttempted,
    /// Callback delivery completed.
    CallbackDelivered,
    /// Callback delivery failed.
    CallbackDeliveryFailed,
}

/// Receipt event.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    /// Receipt id.
    pub id: ReceiptId,
    /// Receipt type.
    pub receipt_type: ReceiptType,
    /// Actor.
    pub actor: Principal,
    /// Timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub occurred_at: OffsetDateTime,
    /// Correlation id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,
    /// Structured receipt data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// Previous hash in the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    /// Receipt hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Hash-linked receipt chain.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReceiptChain {
    /// Chain id.
    pub chain_id: String,
    /// Receipts in order.
    pub receipts: Vec<Receipt>,
    /// Merkle root or equivalent aggregate hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_hash: Option<String>,
}

/// Audit event payload.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event id.
    pub id: String,
    /// Actor.
    pub actor: Principal,
    /// Identity context used by policy, tenant, and credential audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityContext>,
    /// Audit action.
    pub action: String,
    /// Timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub occurred_at: OffsetDateTime,
    /// Structured audit data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Optional economic settlement batch.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BatchSettlement {
    /// Batch id.
    pub id: String,
    /// Settlement model.
    pub model: String,
    /// Settlement records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<Value>,
}

/// Reference to another message.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageReference {
    /// Message id.
    Message(MessageId),
    /// Correlation id.
    Correlation(CorrelationId),
}
