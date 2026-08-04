//! Test utilities and deterministic fixtures for AIP.

#![forbid(unsafe_code)]

use aip_connector::{
    Connector, ConnectorContext, ConnectorError, ConnectorResult, OutboundConnector,
};
use aip_core::{
    Action, ActionLifecycleState, ActionResult, ActionResultStatus, ActionStatus, ApprovalPolicy,
    ApproverSelector, Capability, CapabilityContract, CapabilityId, CapabilityKind,
    CompensationContract, CompensationMode, CredentialPolicy, CredentialRef, DataContract,
    DataSensitivity, DryRunFidelity, Envelope, ErrorCategory, EvidenceRequirement,
    ExecutionContract, ExpectedCompletionMode, Handshake, IdempotencyCollisionBehavior,
    IdempotencyContract, IdempotencyKeyScope, IdempotencyRequirement, IdentityContext, Manifest,
    MessageBody, MessagePart, Principal, PrincipalId, PrincipalKind, ProfileId, ProtocolError,
    RetrySafety, ServiceLevelContract, SideEffect, TenantRef, TransactionContract, TransactionMode,
};
use aip_runtime::{ActionHandler, RuntimeResult};
use aip_transport::{RequestReplyTransport, Transport, TransportMessage, TransportResult};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::Mutex;

/// Creates a deterministic test principal.
pub fn principal(id: &str, kind: PrincipalKind) -> Principal {
    Principal::new(PrincipalId::trusted(id), kind)
}

/// Creates a deterministic tool capability.
pub fn capability(id: &str, name: &str) -> Capability {
    Capability {
        id: CapabilityId::trusted(id),
        name: name.to_owned(),
        kind: CapabilityKind::Tool,
        input_schema: json!({ "type": "object" }),
        output_schema: None,
        description: Some(format!("Test capability {name}")),
        risk: None,
        stability: None,
        cost: None,
        auth: None,
        bindings: Vec::new(),
        requires_human_approval: None,
        contract: None,
    }
}

/// Creates a deterministic enterprise capability contract for protocol tests.
///
/// The fixture is intentionally conservative: it declares both read and write
/// side effects by default, requires idempotency, supports sync and async
/// execution, allows retry only with an idempotency key, and exposes dry-run and
/// planning semantics. Tests can mutate the returned contract to model narrower
/// connector behavior.
#[must_use]
pub fn capability_contract(side_effects: Vec<SideEffect>) -> CapabilityContract {
    CapabilityContract {
        side_effects,
        idempotency: IdempotencyContract {
            requirement: IdempotencyRequirement::Required,
            collision_behavior: IdempotencyCollisionBehavior::ReturnOriginalResult,
            key_scope: IdempotencyKeyScope::Capability,
            ttl_ms: Some(86_400_000),
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: true,
            supports_streaming: false,
            supports_cancel: true,
            supports_retry: true,
            expected_completion: ExpectedCompletionMode::Any,
            retry_safety: RetrySafety::SafeWithIdempotencyKey,
        },
        data: DataContract {
            sensitivity: DataSensitivity::Confidential,
            contains_pii: false,
            redaction_required: true,
            residency: None,
            retention: None,
        },
        credentials: None,
        approval: None,
        sla: Some(ServiceLevelContract {
            expected_latency_ms: Some(2_000),
            timeout_ms: Some(30_000),
            async_expected: false,
            max_queue_delay_ms: Some(5_000),
            availability_target: Some("99.9%".to_owned()),
        }),
        transaction: Some(TransactionContract {
            supported_modes: vec![
                TransactionMode::Execute,
                TransactionMode::DryRun,
                TransactionMode::Plan,
                TransactionMode::Commit,
                TransactionMode::RollbackNotSupported,
            ],
            requires_plan_before_commit: true,
            dry_run_fidelity: DryRunFidelity::PolicyAndSchema,
        }),
        compensation: Some(CompensationContract {
            mode: CompensationMode::RollbackNotSupported,
            compensation_capability_id: None,
            compensation_window_ms: None,
            requires_approval: false,
        }),
    }
}

/// Creates a deterministic tool capability with an enterprise contract.
#[must_use]
pub fn enterprise_capability(id: &str, name: &str) -> Capability {
    let mut capability = capability(id, name);
    capability.contract = Some(capability_contract(vec![
        SideEffect::Read,
        SideEffect::Write,
    ]));
    capability
}

/// Creates a deterministic identity context with an external credential ref.
#[must_use]
pub fn credential_identity(tenant_id: &str, issuer: &str, scopes: &[&str]) -> IdentityContext {
    IdentityContext {
        tenant: Some(TenantRef {
            id: tenant_id.to_owned(),
            system: Some("aip-testkit".to_owned()),
        }),
        external_account: None,
        external_user: None,
        human_actor: None,
        service_account: None,
        acted_on_behalf_of: None,
        credential_ref: Some(CredentialRef {
            id: format!("credential:{tenant_id}"),
            issuer: issuer.to_owned(),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        }),
        oauth: None,
    }
}

/// Creates a governed financial capability that exercises RFC 0002 semantics.
#[must_use]
pub fn governed_financial_capability(
    id: &str,
    name: &str,
    compensation_capability_id: CapabilityId,
) -> Capability {
    let mut capability = capability(id, name);
    let mut contract = capability_contract(vec![SideEffect::Financial, SideEffect::Write]);
    contract.idempotency.key_scope = IdempotencyKeyScope::Tenant;
    contract.data.sensitivity = DataSensitivity::Restricted;
    contract.data.contains_pii = true;
    contract.credentials = Some(CredentialPolicy {
        required: true,
        accepted_issuers: vec!["vault:primary".to_owned()],
        required_scopes: vec!["financial:write".to_owned()],
        allow_oauth_refresh: false,
    });
    contract.approval = Some(ApprovalPolicy {
        required: true,
        reason: Some("financial mutation requires approval".to_owned()),
        approver_selector: ApproverSelector::TenantPolicy,
        ttl_ms: Some(900_000),
        evidence_requirements: vec![
            EvidenceRequirement::Reason,
            EvidenceRequirement::InputSnapshot,
            EvidenceRequirement::PolicyDecision,
        ],
        delegated_authority: None,
        ..ApprovalPolicy::default()
    });
    contract.transaction = Some(TransactionContract {
        supported_modes: vec![
            TransactionMode::Execute,
            TransactionMode::DryRun,
            TransactionMode::Plan,
            TransactionMode::Commit,
            TransactionMode::Compensate,
        ],
        requires_plan_before_commit: true,
        dry_run_fidelity: DryRunFidelity::PolicyAndSchema,
    });
    contract.compensation = Some(CompensationContract {
        mode: CompensationMode::Supported,
        compensation_capability_id: Some(compensation_capability_id),
        compensation_window_ms: Some(86_400_000),
        requires_approval: true,
    });
    capability.contract = Some(contract);
    capability
}

/// Creates a manifest with one tool capability.
pub fn manifest() -> Manifest {
    Manifest {
        manifest_version: "aip-manifest/v1".to_owned(),
        agent: principal("agent:test", PrincipalKind::Agent),
        capabilities: vec![capability("cap:test:echo", "echo")],
        profiles: vec![ProfileId::from("aip.native.http.v1")],
        resources: Vec::new(),
        channels: Vec::new(),
        security: None,
        governance: None,
        limits: None,
        compatibility: None,
        extensions: None,
    }
}

/// Creates a test action.
pub fn action(input: Value) -> Action {
    Action::new(CapabilityId::trusted("cap:test:echo"), input)
}

/// Creates deterministic RFC 0003 lifecycle fixtures for conformance suites.
///
/// The returned vector covers queued, running, pending approval, completed,
/// failed, dead-lettered, and expired states without requiring a runtime store.
#[must_use]
pub fn lifecycle_action_status_fixtures() -> Vec<ActionStatus> {
    let capability_id = CapabilityId::trusted("cap:test:lifecycle");
    [
        ActionLifecycleState::Queued,
        ActionLifecycleState::Running,
        ActionLifecycleState::PendingApproval,
        ActionLifecycleState::Completed,
        ActionLifecycleState::Failed,
        ActionLifecycleState::DeadLettered,
        ActionLifecycleState::Expired,
    ]
    .into_iter()
    .map(|state| action_status_fixture(capability_id.clone(), state))
    .collect()
}

fn action_status_fixture(capability_id: CapabilityId, state: ActionLifecycleState) -> ActionStatus {
    let action_id = aip_core::ActionId::new();
    let result_status = match state {
        ActionLifecycleState::Completed => Some(ActionResultStatus::Completed),
        ActionLifecycleState::Failed => Some(ActionResultStatus::Failed),
        _ => None,
    };
    let result = result_status.map(|status| ActionResult {
        action_id: action_id.clone(),
        status,
        output: Some(json!({ "fixture": format!("{state:?}") })),
        message: vec![MessagePart::text("fixture")],
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    });
    ActionStatus {
        action_id,
        capability_id: Some(capability_id),
        session_id: None,
        correlation_id: None,
        state,
        queued_state: Some(format!("{state:?}").to_lowercase()),
        result_status,
        approval_id: None,
        transaction_id: None,
        delegation_id: None,
        started_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        completed_at: matches!(
            state,
            ActionLifecycleState::Completed
                | ActionLifecycleState::Failed
                | ActionLifecycleState::Cancelled
                | ActionLifecycleState::DeadLettered
                | ActionLifecycleState::Expired
        )
        .then_some(OffsetDateTime::UNIX_EPOCH),
        retry: None,
        lease: None,
        result,
        receipt_chain: None,
        chunks: Vec::new(),
        links: BTreeMap::new(),
    }
}

/// Creates a body for a manifest request.
#[must_use]
pub fn manifest_request_body() -> MessageBody {
    MessageBody::ManifestRequest(aip_core::ManifestRequest {
        profiles: vec![ProfileId::from("aip.native.http.v1")],
        filter: None,
    })
}

/// Creates a deterministic handshake envelope for integration tests.
pub fn handshake_envelope(requested_capabilities: Vec<CapabilityId>) -> Envelope {
    let client = principal("agent:test-client", PrincipalKind::Agent);
    let mut envelope = Envelope::new(MessageBody::Handshake(Handshake {
        client: client.clone(),
        purpose: "test handshake".to_owned(),
        requested_capabilities,
        profiles: vec![ProfileId::from("aip.native.http.v1")],
        auth: None,
        compliance_required: Vec::new(),
        heartbeat: None,
        encryption: None,
        billing: None,
    }));
    envelope.from = Some(client);
    envelope
}

/// Deterministic connector that maps every action to a JSON echo result.
#[derive(Clone, Debug)]
pub struct FakeConnector {
    id: String,
    manifest: Manifest,
}

impl FakeConnector {
    /// Creates a fake connector with a deterministic manifest.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            manifest: manifest(),
        }
    }
}

#[async_trait]
impl Connector for FakeConnector {
    fn id(&self) -> &str {
        &self.id
    }

    async fn discover(&self, _context: &ConnectorContext) -> ConnectorResult<Manifest> {
        Ok(self.manifest.clone())
    }

    fn map_error(&self, error: &ConnectorError) -> ProtocolError {
        ProtocolError {
            code: "test.connector".to_owned(),
            message: error.to_string(),
            category: ErrorCategory::Connector,
            retryable: Some(false),
            retry_after_ms: None,
            details: None,
            source: Some(Box::new(json!({ "connector": self.id }))),
        }
    }
}

#[async_trait]
impl OutboundConnector for FakeConnector {
    async fn invoke(
        &self,
        _context: &ConnectorContext,
        action: Action,
    ) -> ConnectorResult<ActionResult> {
        Ok(echo_result(action))
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
impl ActionHandler for FakeConnector {
    async fn handle(&self, action: Action) -> RuntimeResult<ActionResult> {
        Ok(echo_result(action))
    }
}

/// In-memory request/reply transport for deterministic tests.
#[derive(Clone, Debug, Default)]
pub struct InMemoryTransport {
    published: Arc<Mutex<Vec<TransportMessage>>>,
    replies: Arc<Mutex<Vec<TransportMessage>>>,
}

impl InMemoryTransport {
    /// Creates an empty transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues a response that will be returned by the next request.
    pub async fn push_reply(&self, message: TransportMessage) {
        self.replies.lock().await.push(message);
    }

    /// Returns all published messages.
    pub async fn published(&self) -> Vec<TransportMessage> {
        self.published.lock().await.clone()
    }
}

#[async_trait]
impl Transport for InMemoryTransport {
    async fn publish(&self, message: TransportMessage) -> TransportResult<()> {
        self.published.lock().await.push(message);
        Ok(())
    }
}

#[async_trait]
impl RequestReplyTransport for InMemoryTransport {
    async fn request(&self, message: TransportMessage) -> TransportResult<TransportMessage> {
        self.publish(message).await?;
        self.replies
            .lock()
            .await
            .pop()
            .ok_or(aip_transport::TransportError::Timeout)
    }
}

fn echo_result(action: Action) -> ActionResult {
    ActionResult {
        action_id: action.id,
        status: ActionResultStatus::Completed,
        output: Some(json!({ "echo": action.input })),
        message: vec![MessagePart::text("ok")],
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::lifecycle_action_status_fixtures;
    use aip_core::ActionLifecycleState;

    #[test]
    fn lifecycle_fixtures_cover_required_rfc0003_states() {
        let states = lifecycle_action_status_fixtures()
            .into_iter()
            .map(|status| status.state)
            .collect::<Vec<_>>();
        for required in [
            ActionLifecycleState::Queued,
            ActionLifecycleState::Running,
            ActionLifecycleState::PendingApproval,
            ActionLifecycleState::Completed,
            ActionLifecycleState::Failed,
            ActionLifecycleState::DeadLettered,
            ActionLifecycleState::Expired,
        ] {
            assert!(states.contains(&required), "{required:?}");
        }
    }
}
