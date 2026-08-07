//! Canonical semantic object model shared by all AIP profiles.

use crate::{
    ActionId, ApprovalId, CapabilityId, ConversationId, CorrelationId, EventId, PrincipalId,
    ProfileId, SessionId, TransactionId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

/// Product-specific identity reference preserved by connectors.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRef {
    /// Source system name, for example `chatwoot` or `dify`.
    pub system: String,
    /// Source-local entity type.
    #[serde(rename = "type")]
    pub ref_type: String,
    /// Source-local entity id.
    pub id: String,
}

/// Entity category for a protocol principal.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// A human user or operator.
    Human,
    /// An autonomous or semi-autonomous agent.
    Agent,
    /// A service account or machine identity.
    Service,
    /// A tenant/account boundary.
    Tenant,
    /// A customer identity.
    Customer,
    /// A contact identity in a channel product.
    Contact,
    /// A system-level actor.
    System,
}

/// Scoped authority delegated to this principal for another principal's work.
///
/// Delegated authority is part of the native AIP identity model. It lets a
/// runtime distinguish "can read or operate on my own work" from "can read or
/// operate on work owned by a specific principal" without granting broad
/// `*:any` scopes. Compatibility profiles may project this from their own
/// auth systems, but the resulting grant is evaluated by AIP core/runtime
/// semantics.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedAuthorityGrant {
    /// Principal whose work is covered by the grant.
    pub principal_id: PrincipalId,
    /// Granted scope labels. `*` grants all scopes for this principal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Expiration timestamp. Expired grants MUST be ignored by runtimes.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub expires_at: Option<OffsetDateTime>,
    /// Optional reason or authority reference retained for audit/debugging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Actor or authorizing entity in AIP.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Principal {
    /// Stable AIP principal id.
    pub id: PrincipalId,
    /// Principal category.
    pub kind: PrincipalKind,
    /// Human-readable display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Trust domain that owns this principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    /// DID identity, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    /// Product-specific identities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_refs: Vec<ExternalRef>,
    /// Scoped delegated authority granted to this principal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegated_authority: Vec<DelegatedAuthorityGrant>,
    /// Authentication metadata supplied by a profile or gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_context: Option<Value>,
}

impl Principal {
    /// Creates a minimal principal.
    #[must_use]
    pub fn new(id: PrincipalId, kind: PrincipalKind) -> Self {
        Self {
            id,
            kind,
            display_name: None,
            trust_domain: None,
            did: None,
            external_refs: Vec::new(),
            delegated_authority: Vec::new(),
            auth_context: None,
        }
    }
}

/// Lifecycle state of an AIP session.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Session is being negotiated.
    New,
    /// Session is ready for actions.
    Active,
    /// Work is accepted but not started.
    Queued,
    /// Work is running.
    Processing,
    /// Work is streaming output.
    Streaming,
    /// Work is blocked on human input or approval.
    WaitingForHuman,
    /// Work completed successfully.
    Completed,
    /// Work was cancelled.
    Cancelled,
    /// Work reached terminal failure.
    Failed,
    /// Settlement/audit closeout is complete.
    Settled,
}

impl SessionState {
    /// Returns the stable wire label for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Active => "active",
            Self::Queued => "queued",
            Self::Processing => "processing",
            Self::Streaming => "streaming",
            Self::WaitingForHuman => "waiting_for_human",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Settled => "settled",
        }
    }

    /// Checks whether a transition is legal.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::New, Self::Active)
                | (
                    Self::Active,
                    Self::Queued | Self::Processing | Self::Cancelled
                )
                | (
                    Self::Queued,
                    Self::Processing | Self::Cancelled | Self::Failed
                )
                | (
                    Self::Processing,
                    Self::Streaming
                        | Self::WaitingForHuman
                        | Self::Completed
                        | Self::Failed
                        | Self::Cancelled
                )
                | (
                    Self::Streaming,
                    Self::Completed | Self::Failed | Self::Cancelled | Self::WaitingForHuman
                )
                | (
                    Self::WaitingForHuman,
                    Self::Processing | Self::Completed | Self::Cancelled | Self::Failed
                )
                | (Self::Completed, Self::Settled)
                | (Self::Failed, Self::Settled)
                | (Self::Cancelled, Self::Settled)
        )
    }
}

/// Session metadata shared across related protocol messages.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Session {
    /// Stable session id.
    pub id: SessionId,
    /// Current lifecycle state.
    pub state: SessionState,
    /// Creation timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub created_at: OffsetDateTime,
    /// Caller or originator.
    pub initiator: Principal,
    /// Callee or handler.
    pub responder: Principal,
}

/// Capability category.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    /// Agent-level capability.
    Agent,
    /// Tool/function capability.
    Tool,
    /// Workflow capability.
    Workflow,
    /// Channel-facing operation.
    Channel,
    /// Readable resource.
    Resource,
    /// Human task.
    HumanTask,
}

/// Operational risk classification.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Low-risk capability.
    Low,
    /// Medium-risk capability.
    Medium,
    /// High-risk capability.
    High,
    /// Critical-risk capability.
    Critical,
}

/// Stability state for a published capability.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stability {
    /// Stable public behavior.
    Stable,
    /// Experimental behavior.
    Experimental,
    /// Deprecated behavior.
    Deprecated,
}

/// Profile-specific binding metadata for a capability.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Binding {
    /// Profile id that owns this binding.
    pub profile: ProfileId,
    /// Additional binding-specific fields.
    #[serde(flatten)]
    pub metadata: Map<String, Value>,
}

/// Side effect category for an enterprise capability.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffect {
    /// Read data without intended mutation.
    Read,
    /// Mutate existing state or create new state.
    Write,
    /// Delete or destroy state.
    Delete,
    /// Send a user-visible or external message.
    SendMessage,
    /// Move money, create financial obligations, or change billing state.
    Financial,
    /// Change identity, account, access, or credential state.
    Identity,
    /// Touch medical or health-related records.
    Medical,
    /// Touch legal, contractual, or compliance-sensitive records.
    Legal,
    /// Call an external network service.
    ExternalNetwork,
    /// Execute code or scripts supplied at runtime.
    CodeExecution,
}

/// Whether an idempotency key is required for a capability invocation.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyRequirement {
    /// Runtime must reject invocations without an idempotency key.
    Required,
    /// Runtime may accept invocations without an idempotency key.
    Optional,
    /// Downstream operation cannot provide idempotent behavior.
    Unsupported,
}

/// Behavior when a duplicate idempotency key is observed.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyCollisionBehavior {
    /// Return the originally stored result for the key.
    ReturnOriginalResult,
    /// Reject duplicate keys as conflicts.
    RejectConflict,
    /// Return the original result only when an input hash matches.
    RevalidateInputHash,
}

/// Scope used when evaluating an idempotency key.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyKeyScope {
    /// Key is unique per action id.
    Action,
    /// Key is unique per capability.
    Capability,
    /// Key is unique per principal.
    Principal,
    /// Key is unique per tenant.
    Tenant,
    /// Key is unique per external account.
    ExternalAccount,
}

/// Idempotency requirements declared by a capability.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyContract {
    /// Requirement level.
    pub requirement: IdempotencyRequirement,
    /// Duplicate key behavior.
    pub collision_behavior: IdempotencyCollisionBehavior,
    /// Namespace used to evaluate key uniqueness.
    pub key_scope: IdempotencyKeyScope,
    /// Optional retention period for stored keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_ms: Option<u64>,
}

/// Expected completion style for an invocation.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedCompletionMode {
    /// Caller should expect a synchronous final result.
    Sync,
    /// Caller should expect asynchronous completion.
    Async,
    /// Caller should expect streamed progress or output.
    Streaming,
    /// Runtime may choose any supported completion mode.
    Any,
}

/// Retry safety declared by a capability.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrySafety {
    /// Retry is safe without additional idempotency constraints.
    Safe,
    /// Retry is safe only when an idempotency key is present.
    SafeWithIdempotencyKey,
    /// Retry is unsafe and should not be automatic.
    Unsafe,
    /// Retry safety is unknown and must be treated conservatively.
    Unknown,
}

/// Execution behavior declared by a capability.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionContract {
    /// Whether synchronous invocation is supported.
    pub supports_sync: bool,
    /// Whether asynchronous invocation is supported.
    pub supports_async: bool,
    /// Whether streaming invocation is supported.
    pub supports_streaming: bool,
    /// Whether cancellation is supported.
    pub supports_cancel: bool,
    /// Whether retry is supported by the connector/downstream operation.
    pub supports_retry: bool,
    /// Expected completion behavior.
    pub expected_completion: ExpectedCompletionMode,
    /// Retry safety classification.
    pub retry_safety: RetrySafety,
}

/// Data sensitivity classification.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSensitivity {
    /// Public data.
    Public,
    /// Internal operational data.
    Internal,
    /// Confidential business data.
    Confidential,
    /// Restricted data requiring strong access controls.
    Restricted,
    /// Regulated data such as medical, legal, or financial records.
    Regulated,
    /// Data sensitivity was not declared by the provider.
    Unknown,
}

/// Data residency restrictions.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataResidency {
    /// Regions where processing is allowed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_regions: Vec<String>,
    /// Regions where processing is prohibited.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prohibited_regions: Vec<String>,
}

/// Data retention declaration.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Minimum retention period.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_for_ms: Option<u64>,
    /// Maximum retention period.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_after_ms: Option<u64>,
    /// Whether legal hold can override deletion.
    pub legal_hold_allowed: bool,
}

/// Data handling contract for a capability.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataContract {
    /// Sensitivity classification.
    pub sensitivity: DataSensitivity,
    /// Whether personally identifiable information may be present.
    pub contains_pii: bool,
    /// Whether redaction is required before logging or cross-domain delegation.
    pub redaction_required: bool,
    /// Data residency restrictions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residency: Option<DataResidency>,
    /// Data retention policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<RetentionPolicy>,
}

/// Service-level declaration for scheduling and operations.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceLevelContract {
    /// Expected end-to-end latency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_latency_ms: Option<u64>,
    /// Runtime timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Whether the provider expects async execution for this capability.
    pub async_expected: bool,
    /// Maximum acceptable queue delay before escalation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_queue_delay_ms: Option<u64>,
    /// Human-readable availability target, for example `99.9%`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability_target: Option<String>,
}

/// Transactional action mode.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionMode {
    /// Execute the action normally.
    Execute,
    /// Validate without committing side effects.
    DryRun,
    /// Produce a durable execution plan.
    Plan,
    /// Commit a previously planned operation.
    Commit,
    /// Execute a declared compensating operation.
    Compensate,
    /// Reconcile a provider operation whose commit outcome is unknown.
    Reconcile,
    /// Explicit state for operations that cannot roll back.
    RollbackNotSupported,
}

/// Dry-run fidelity declared by a capability.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DryRunFidelity {
    /// Only schema validation is performed.
    SchemaOnly,
    /// Schema and policy validation are performed.
    PolicyAndSchema,
    /// Downstream validation is performed without commit.
    DownstreamValidation,
    /// Provider can simulate the full operation.
    FullSimulation,
}

/// Transaction modes supported by a capability.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionContract {
    /// Supported modes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_modes: Vec<TransactionMode>,
    /// Whether commit must reference a previously produced plan.
    pub requires_plan_before_commit: bool,
    /// Dry-run fidelity.
    pub dry_run_fidelity: DryRunFidelity,
}

/// Compensation support declared by a capability.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompensationMode {
    /// No compensation is required for successful execution.
    NotRequired,
    /// A compensating capability is supported.
    Supported,
    /// Compensation is attempted but cannot be guaranteed.
    BestEffort,
    /// Rollback or compensation is not supported.
    RollbackNotSupported,
}

/// Compensation behavior declared by a capability.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompensationContract {
    /// Compensation mode.
    pub mode: CompensationMode,
    /// Capability used to compensate this operation, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensation_capability_id: Option<CapabilityId>,
    /// Maximum window for compensation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensation_window_ms: Option<u64>,
    /// Whether compensation itself requires approval.
    pub requires_approval: bool,
}

/// Credential requirements declared by a capability contract.
///
/// This policy never carries raw credential material. It only describes the
/// credential reference, issuer, and scope requirements that a runtime must
/// verify before dispatching an action to a connector or downstream system.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialPolicy {
    /// Whether an external credential reference or OAuth state is required.
    pub required: bool,
    /// Accepted credential issuers. An empty list means any issuer is accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_issuers: Vec<String>,
    /// Required downstream scopes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_scopes: Vec<String>,
    /// Whether an expired OAuth state can proceed when refresh is available.
    pub allow_oauth_refresh: bool,
}

/// Principal, role, group, policy, or external system that can approve work.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApproverSelector {
    /// Specific approving principal.
    Principal {
        /// Principal id.
        id: PrincipalId,
    },
    /// Role name.
    Role {
        /// Role identifier.
        name: String,
    },
    /// Group name.
    Group {
        /// Group identifier.
        name: String,
    },
    /// Tenant-owned approval policy.
    TenantPolicy,
    /// External approval system.
    ExternalSystem {
        /// External system identifier.
        system: String,
    },
}

/// Evidence required before approval can be decided.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRequirement {
    /// Human-readable reason.
    Reason,
    /// Snapshot of the action input.
    InputSnapshot,
    /// Policy engine decision.
    PolicyDecision,
    /// External ticket or case.
    ExternalTicket,
    /// Attachment or artifact.
    Attachment,
}

/// Delegated approval authority.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedApprovalAuthority {
    /// Principal receiving delegated approval authority.
    pub principal: PrincipalId,
    /// Delegated scope labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    /// Expiration timestamp.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub expires_at: Option<OffsetDateTime>,
}

/// Composable approval authority expression.
///
/// Leaf predicates are evaluated only against authority memberships returned
/// by a trusted resolver. Values carried in an action or decision payload are
/// never sufficient to satisfy a predicate.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operator", rename_all = "snake_case")]
pub enum ApprovalRule {
    /// Every child expression must be satisfied.
    All {
        /// Child expressions.
        rules: Vec<ApprovalRule>,
        /// Explicitly permits one verified decision to satisfy more than one child.
        #[serde(default)]
        allow_decision_reuse: bool,
    },
    /// At least one child expression must be satisfied.
    Any {
        /// Child expressions.
        rules: Vec<ApprovalRule>,
    },
    /// At least `required` distinct matching decisions must be present.
    Quorum {
        /// Required number of decisions.
        required: u32,
        /// Expressions that can contribute to the quorum.
        rules: Vec<ApprovalRule>,
        /// Whether one principal may contribute at most one vote.
        #[serde(default = "default_true")]
        distinct_principals: bool,
    },
    /// A specific principal must approve.
    Principal {
        /// Required principal id.
        id: PrincipalId,
    },
    /// A member of a trusted role must approve.
    Role {
        /// Required role name.
        name: String,
    },
    /// A member of a trusted group must approve.
    Group {
        /// Required group name.
        name: String,
    },
    /// A member authorized by a tenant policy must approve.
    TenantPolicy {
        /// Stable tenant policy id.
        policy_id: String,
    },
    /// A verified external approval system must approve.
    ExternalSystem {
        /// External system id.
        system: String,
    },
    /// A non-revoked delegated authority grant must match the operation.
    DelegatedAuthority {
        /// Required delegated scope.
        scope: String,
        /// Maximum accepted risk for this grant.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_risk: Option<RiskLevel>,
        /// Maximum governed numeric value for this grant.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_value: Option<u64>,
    },
}

/// Separation-of-duties requirements for an approval workflow.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeparationOfDuties {
    /// The requester cannot approve the request.
    #[serde(default)]
    pub requester_must_differ: bool,
    /// The action operator cannot approve the request.
    #[serde(default)]
    pub operator_must_differ: bool,
    /// Explicitly permits self-approval when no stricter rule prohibits it.
    #[serde(default)]
    pub allow_self_approval: bool,
}

/// Approval policy declared by a capability.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    /// Whether approval is required before execution.
    pub required: bool,
    /// Reason shown to an approver or audit trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Approver selection rule.
    pub approver_selector: ApproverSelector,
    /// Time-to-live for approval requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_ms: Option<u64>,
    /// Required evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_requirements: Vec<EvidenceRequirement>,
    /// Delegated approval authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_authority: Option<DelegatedApprovalAuthority>,
    /// Composable authority expression. When absent, the legacy
    /// `approver_selector` is interpreted as one leaf predicate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<ApprovalRule>,
    /// Minimum number of distinct approving principals for the workflow.
    #[serde(default = "default_one_u32")]
    pub minimum_distinct_principals: u32,
    /// Separation-of-duties requirements.
    #[serde(default)]
    pub separation_of_duties: SeparationOfDuties,
    /// Stable policy version retained in approval evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self {
            required: false,
            reason: None,
            approver_selector: ApproverSelector::TenantPolicy,
            ttl_ms: None,
            evidence_requirements: Vec::new(),
            delegated_authority: None,
            rule: None,
            minimum_distinct_principals: 1,
            separation_of_duties: SeparationOfDuties::default(),
            policy_version: None,
        }
    }
}

/// Versioned enterprise contract for a capability.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityContract {
    /// Side effects a caller must assume.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub side_effects: Vec<SideEffect>,
    /// Idempotency requirements.
    pub idempotency: IdempotencyContract,
    /// Execution support matrix.
    pub execution: ExecutionContract,
    /// Data handling policy.
    pub data: DataContract,
    /// Credential reference and scope requirements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<CredentialPolicy>,
    /// Approval policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalPolicy>,
    /// Service-level scheduling hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sla: Option<ServiceLevelContract>,
    /// Transactional behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<TransactionContract>,
    /// Compensation behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensation: Option<CompensationContract>,
}

/// Callable operation exposed by a participant.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Capability {
    /// Stable capability id.
    pub id: CapabilityId,
    /// Human-readable operation name.
    pub name: String,
    /// Capability category.
    pub kind: CapabilityKind,
    /// JSON Schema describing accepted input.
    pub input_schema: Value,
    /// JSON Schema describing output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Operational risk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<RiskLevel>,
    /// Stability classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stability: Option<Stability>,
    /// Pricing or metering hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<Value>,
    /// Required auth/scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Value>,
    /// Supported profile bindings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<Binding>,
    /// Whether a human approval is required before invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_human_approval: Option<bool>,
    /// Enterprise-grade capability contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<CapabilityContract>,
}

/// Readable resource advertised by a manifest.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    /// Stable resource id.
    pub id: String,
    /// Resource name.
    pub name: String,
    /// Native resource kind used by discovery and operational filters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Capability that owns or exposes this resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<CapabilityId>,
    /// Resource description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Resource MIME type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Tenant boundary that owns or can read the resource, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Native read policy for this resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<ResourceAccessPolicy>,
    /// Resource expiration timestamp, when known.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub expires_at: Option<OffsetDateTime>,
}

/// Native resource read policy used by discovery and operational read APIs.
///
/// The policy is intentionally generic: product-specific ACL objects remain in
/// adapters, while AIP resources publish the minimal principal/scope/tenant
/// requirements needed by gateways and runtimes to avoid leaking resource
/// metadata across trust boundaries.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceAccessPolicy {
    /// Whether any authenticated principal can read the resource.
    #[serde(default)]
    pub public: bool,
    /// Principals explicitly allowed to read the resource.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_principals: Vec<PrincipalId>,
    /// Any one of these scopes authorizes the read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_scopes: Vec<String>,
    /// Whether a matching tenant boundary is required when `tenant_id` exists.
    #[serde(default)]
    pub tenant_required: bool,
}

/// Conversation state in a user-facing channel.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationStatus {
    /// Conversation is open.
    Open,
    /// Conversation is pending.
    Pending,
    /// Conversation is resolved.
    Resolved,
    /// Conversation is snoozed.
    Snoozed,
    /// Conversation is archived.
    Archived,
}

/// Conversation priority.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    /// Low priority.
    Low,
    /// Medium priority.
    Medium,
    /// High priority.
    High,
    /// Urgent priority.
    Urgent,
}

/// Customer or user-facing conversation thread.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Conversation {
    /// Stable AIP conversation id.
    pub id: ConversationId,
    /// Channel metadata.
    pub channel: Value,
    /// Conversation status.
    pub status: ConversationStatus,
    /// Product-specific ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_refs: Vec<ExternalRef>,
    /// Customer/contact principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<Principal>,
    /// Human or bot assignee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<Principal>,
    /// Priority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
    /// Labels/tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// Extension metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Rich content part carried by a message, result, or channel event.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessagePart {
    /// Text content.
    Text {
        /// Text body.
        text: String,
        /// Optional text format, for example `plain` or `markdown`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        format: Option<String>,
    },
    /// Image content.
    Image {
        /// Remote URL.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        /// Inline data.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<String>,
        /// MIME type.
        mime_type: String,
        /// Accessibility alt text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alt: Option<String>,
    },
    /// File content.
    File {
        /// Remote URL.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        /// Inline data.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<String>,
        /// MIME type.
        mime_type: String,
        /// File name.
        filename: String,
        /// File size in bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size_bytes: Option<u64>,
    },
    /// Audio content.
    Audio {
        /// Remote URL.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        /// Inline data.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<String>,
        /// MIME type.
        mime_type: String,
        /// Optional transcript.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transcript: Option<String>,
    },
    /// Interactive form.
    Form {
        /// Form fields.
        fields: Vec<Value>,
        /// Form actions.
        actions: Vec<Value>,
    },
    /// Rich card.
    Card {
        /// Card title.
        title: String,
        /// Card body.
        body: String,
        /// Card actions.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        actions: Vec<Value>,
        /// Card media.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media: Option<Value>,
    },
    /// Structured JSON payload.
    Json {
        /// JSON data.
        data: Value,
        /// Optional JSON Schema.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema: Option<Value>,
    },
    /// Tool result payload.
    ToolResult {
        /// Tool call id.
        tool_call_id: String,
        /// Result data.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<Value>,
        /// Error data.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<Value>,
    },
}

impl MessagePart {
    /// Creates a plain text message part.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text {
            text: text.into(),
            format: Some("plain".to_owned()),
        }
    }
}

/// Action invocation mode.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionMode {
    /// Request/response action.
    Sync,
    /// Asynchronous action.
    Async,
    /// Streaming action.
    Streaming,
}

/// Delegation chain entry used for multi-agent authorization.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationEntry {
    /// Delegating principal.
    pub from: Principal,
    /// Delegate principal.
    pub to: Principal,
    /// Delegated scope.
    pub scope: String,
    /// Delegation timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub delegated_at: OffsetDateTime,
}

/// Cross-domain routing context.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationContext {
    /// Current trust domain.
    pub trust_domain: String,
    /// Domains already traversed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hops: Vec<String>,
}

/// Async callback target.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Callback {
    /// Callback profile id.
    pub profile: ProfileId,
    /// Callback target URI or subject.
    pub target: String,
    /// Profile-specific delivery configuration such as authentication or tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Trace/span metadata.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObservabilityContext {
    /// Trace id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Span id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    /// Free-form fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Value>,
}

/// Policy/compliance metadata.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComplianceContext {
    /// Required compliance regimes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regimes: Vec<String>,
    /// Data classification label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_classification: Option<String>,
    /// Additional policy metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Tenant reference used for policy and credential partitioning.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRef {
    /// AIP or external tenant id.
    pub id: String,
    /// Source system that owns the tenant id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
}

/// External account reference used by product connectors.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalAccountRef {
    /// Account id in the source system.
    pub id: String,
    /// Source system name.
    pub system: String,
}

/// External user reference used by product connectors.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalUserRef {
    /// User id in the source system.
    pub id: String,
    /// Source system name.
    pub system: String,
}

/// Reference to credential material stored outside protocol envelopes.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRef {
    /// Credential id or vault reference.
    pub id: String,
    /// Credential issuer or storage boundary.
    pub issuer: String,
    /// Granted scope labels known to the runtime.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

/// OAuth credential lifecycle state without raw token material.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthCredentialState {
    /// Authorization server or provider id.
    pub issuer: String,
    /// OAuth client id or service identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Granted scope labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Token expiration timestamp, when known.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub expires_at: Option<OffsetDateTime>,
    /// Whether refresh is available without human reauthorization.
    pub refresh_available: bool,
}

/// Identity, tenant, and credential mapping context for enterprise actions.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityContext {
    /// Tenant boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<TenantRef>,
    /// External account boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_account: Option<ExternalAccountRef>,
    /// External user associated with the invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_user: Option<ExternalUserRef>,
    /// Human actor that initiated or owns the work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_actor: Option<Principal>,
    /// Service account executing the operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<Principal>,
    /// Principal on whose behalf the operation is performed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acted_on_behalf_of: Option<Principal>,
    /// Reference to external credential material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<CredentialRef>,
    /// OAuth lifecycle state without token material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthCredentialState>,
}

/// Evidence artifact used by approval and audit workflows.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    /// Stable artifact id.
    pub id: String,
    /// Evidence kind.
    pub kind: String,
    /// URI for retrievable evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Integrity hash for the artifact or redacted view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Whether the artifact has been redacted.
    pub redacted: bool,
}

/// First-class approval request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Stable approval workflow id.
    pub id: ApprovalId,
    /// Action requiring approval.
    pub action_id: ActionId,
    /// Capability requiring approval.
    pub capability_id: CapabilityId,
    /// Principal requesting approval.
    pub requester: Principal,
    /// Principal whose work is being approved.
    pub subject: Principal,
    /// Approver selector.
    pub approver_selector: ApproverSelector,
    /// Human-readable reason.
    pub reason: String,
    /// Evidence artifacts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceArtifact>,
    /// Expiration timestamp.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub expires_at: Option<OffsetDateTime>,
    /// External or internal policy decision id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_decision_id: Option<String>,
    /// Identity context used by policy and audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityContext>,
    /// Immutable approval policy snapshot evaluated for this request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_snapshot: Option<ApprovalPolicy>,
    /// SHA-256 hash of the canonical policy snapshot and governed subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// Principal operating the action, when distinct from the requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<Principal>,
    /// Risk evaluated for delegated-authority limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<RiskLevel>,
    /// Governed numeric value evaluated for delegated-authority limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_value: Option<u64>,
}

/// Approval decision outcome.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionKind {
    /// Approval was granted.
    Approved,
    /// Approval was denied.
    Denied,
    /// Approval expired.
    Expired,
    /// Approval was revoked after being granted.
    Revoked,
}

/// Restriction attached to an approval decision.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalConstraint {
    /// Field or path being constrained.
    pub field: String,
    /// Operator name, for example `lte`, `eq`, or `matches`.
    pub operator: String,
    /// Constraint value.
    pub value: Value,
}

/// First-class approval decision.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalDecision {
    /// Approval workflow id.
    pub approval_id: ApprovalId,
    /// Decision kind.
    pub decision: ApprovalDecisionKind,
    /// Approver principal.
    pub approver: Principal,
    /// Decision timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub decided_at: OffsetDateTime,
    /// Human-readable reason or comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Constraints attached to the approval.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<ApprovalConstraint>,
    /// Decision evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceArtifact>,
    /// Stable id for idempotent decision replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    /// Policy hash the approver evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// Resolver-produced authority path retained as audit evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_path: Vec<String>,
    /// Prior decision being revoked, when `decision` is `revoked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_decision_id: Option<String>,
}

/// Transaction context for an action.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionTransaction {
    /// Transaction mode.
    pub mode: TransactionMode,
    /// Stable transaction id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<TransactionId>,
    /// Plan id produced by a previous planning action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
    /// Action being compensated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensation_for: Option<ActionId>,
}

/// Capability invocation.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Action {
    /// Stable action id.
    pub id: ActionId,
    /// Target capability.
    pub capability_id: CapabilityId,
    /// Structured input payload.
    pub input: Value,
    /// Invocation mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ActionMode>,
    /// Replay-safe dedupe key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Caller timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Conversation context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<Conversation>,
    /// Shared memory/context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_context: Option<Value>,
    /// Delegation authorization chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_chain: Vec<DelegationEntry>,
    /// Federation routing context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation: Option<FederationContext>,
    /// Async callback target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback: Option<Callback>,
    /// Trace/span/log metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<ObservabilityContext>,
    /// Policy/compliance context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<ComplianceContext>,
    /// Identity, tenant, and credential mapping context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityContext>,
    /// Approval decision authorizing this invocation, if one has been granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalDecision>,
    /// Transactional execution context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<ActionTransaction>,
}

impl Action {
    /// Creates a new action with structured JSON input.
    #[must_use]
    pub fn new(capability_id: CapabilityId, input: Value) -> Self {
        Self {
            id: ActionId::new(),
            capability_id,
            input,
            mode: None,
            idempotency_key: None,
            timeout_ms: None,
            conversation: None,
            memory_context: None,
            delegation_chain: Vec::new(),
            federation: None,
            callback: None,
            observability: None,
            compliance: None,
            identity: None,
            approval: None,
            transaction: None,
        }
    }
}

/// Lifecycle, channel, tool, audit, or system event.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Stable event id.
    pub id: EventId,
    /// Event kind.
    pub kind: String,
    /// Event timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub occurred_at: OffsetDateTime,
    /// Associated session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Associated action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<ActionId>,
    /// Request correlation id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,
    /// Actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Principal>,
    /// Structured event data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl Event {
    /// Creates an event with the current timestamp.
    #[must_use]
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            id: EventId::new(),
            kind: kind.into(),
            occurred_at: OffsetDateTime::now_utc(),
            session_id: None,
            action_id: None,
            correlation_id: None,
            actor: None,
            data: None,
        }
    }
}

const fn default_true() -> bool {
    true
}

const fn default_one_u32() -> u32 {
    1
}
