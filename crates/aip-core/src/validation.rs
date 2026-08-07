//! Pure validation rules for native AIP envelopes.

use crate::{
    AIP_VERSION, Action, ActionResultStatus, AipError, AipResult, ApprovalDecision,
    ApprovalDecisionKind, ApprovalRequest, Capability, CompensationMode, Envelope, Manifest,
    MessageBody, TransactionMode, TransactionProtocolStatus,
};
use std::collections::HashSet;

/// A non-fatal validation issue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationIssue {
    /// Field or path associated with the issue.
    pub path: String,
    /// Human-readable issue description.
    pub message: String,
}

/// Validates invariant rules that cannot be expressed by serde alone.
pub fn validate_envelope(envelope: &Envelope) -> AipResult<()> {
    if envelope.aip_version != AIP_VERSION {
        return Err(AipError::UnsupportedVersion(envelope.aip_version.clone()));
    }
    let body_type = envelope.body.message_type();
    if envelope.message_type != body_type {
        return Err(AipError::MessageTypeMismatch(
            envelope.message_type.as_str().to_owned(),
        ));
    }
    if envelope.message_id.as_str().is_empty() {
        return Err(AipError::MissingField("message_id"));
    }
    if envelope
        .idempotency_key
        .as_deref()
        .is_some_and(str::is_empty)
    {
        return Err(AipError::Validation(
            "envelope idempotency_key must not be empty".to_owned(),
        ));
    }
    validate_body(&envelope.body)?;
    Ok(())
}

fn validate_body(body: &MessageBody) -> AipResult<()> {
    match body {
        MessageBody::Handshake(handshake) => {
            if handshake.purpose.trim().is_empty() {
                return Err(AipError::MissingField("handshake.purpose"));
            }
        }
        MessageBody::Action(action) => validate_action(action)?,
        MessageBody::DelegationRequest(request) => {
            if request.scope.trim().is_empty() {
                return Err(AipError::MissingField("delegation_request.scope"));
            }
            if request.parent_action_id == request.child_action.id {
                return Err(AipError::Validation(
                    "delegation_request parent and child action ids must differ".to_owned(),
                ));
            }
            validate_action(&request.child_action)?;
        }
        MessageBody::DelegationResult(result) => {
            let is_terminal = matches!(
                result.status,
                crate::DelegationStatus::Completed
                    | crate::DelegationStatus::Failed
                    | crate::DelegationStatus::Cancelled
                    | crate::DelegationStatus::RequiresHuman
            );
            if is_terminal && result.result.is_none() && result.error.is_none() {
                return Err(AipError::Validation(
                    "terminal delegation_result must include result or error".to_owned(),
                ));
            }
        }
        MessageBody::TransactionRequest(request) => {
            let Some(transaction) = request.action.transaction.as_ref() else {
                return Err(AipError::MissingField(
                    "transaction_request.action.transaction",
                ));
            };
            if let Some(transaction_id) = transaction.transaction_id.as_ref()
                && transaction_id != &request.transaction_id
            {
                return Err(AipError::Validation(
                    "transaction_request transaction_id must match action.transaction.transaction_id"
                        .to_owned(),
                ));
            }
            validate_action(&request.action)?;
        }
        MessageBody::TransactionResult(result) => {
            if result.transaction.transaction_id.as_ref() != Some(&result.transaction_id) {
                return Err(AipError::Validation(
                    "transaction_result transaction_id must match transaction.transaction_id"
                        .to_owned(),
                ));
            }
            if result.status == TransactionProtocolStatus::Failed
                && result.error.is_none()
                && !result.result.as_ref().is_some_and(|action_result| {
                    action_result.status == ActionResultStatus::Failed
                        && action_result.error.is_some()
                })
            {
                return Err(AipError::Validation(
                    "failed transaction_result must include error or failed action_result"
                        .to_owned(),
                ));
            }
            if result.status == TransactionProtocolStatus::Planned {
                let Some(plan) = result.plan.as_ref() else {
                    return Err(AipError::MissingField("transaction_result.plan"));
                };
                if plan.transaction_id != result.transaction_id {
                    return Err(AipError::Validation(
                        "transaction_result plan transaction_id must match result transaction_id"
                            .to_owned(),
                    ));
                }
                if plan.action_id != result.action_id {
                    return Err(AipError::Validation(
                        "transaction_result plan action_id must match result action_id".to_owned(),
                    ));
                }
                if plan.capability_id != result.capability_id {
                    return Err(AipError::Validation(
                        "transaction_result plan capability_id must match result capability_id"
                            .to_owned(),
                    ));
                }
            }
        }
        MessageBody::ApprovalRequest(request) => validate_approval_request(request)?,
        MessageBody::ApprovalDecision(decision) => validate_approval_decision(decision)?,
        MessageBody::ChannelMessage(message) => {
            if let Some(identity) = &message.identity {
                validate_identity_context(identity, "channel_message.identity")?;
            }
        }
        MessageBody::Conversation(update) => {
            if let Some(identity) = &update.identity {
                validate_identity_context(identity, "conversation_updated.identity")?;
            }
        }
        MessageBody::AuditEvent(audit) => {
            if audit.action.trim().is_empty() {
                return Err(AipError::MissingField("audit_event.action"));
            }
            if let Some(identity) = &audit.identity {
                validate_identity_context(identity, "audit_event.identity")?;
            }
        }
        MessageBody::ActionResult(result) => {
            if result.status == ActionResultStatus::Failed && result.error.is_none() {
                return Err(AipError::Validation(
                    "failed action_result must include error".to_owned(),
                ));
            }
        }
        MessageBody::ActionStatusRequest(request) => {
            validate_optional_string(
                request.tenant_id.as_deref(),
                "action_status_request.tenant_id",
            )?;
            validate_wait_ms(request.wait_ms, "action_status_request.wait_ms")?;
        }
        MessageBody::ActionStatus(status) => {
            if status.state == crate::ActionLifecycleState::Failed
                && status.result_status.is_none()
                && status
                    .result
                    .as_ref()
                    .is_none_or(|result| result.error.is_none())
            {
                return Err(AipError::Validation(
                    "failed action_status must include result_status or result error".to_owned(),
                ));
            }
        }
        MessageBody::ActionResultRequest(request) => {
            validate_optional_string(
                request.tenant_id.as_deref(),
                "action_result_request.tenant_id",
            )?;
            validate_wait_ms(request.wait_ms, "action_result_request.wait_ms")?;
        }
        MessageBody::ActionListRequest(request) => {
            validate_optional_string(
                request.tenant_id.as_deref(),
                "action_list_request.tenant_id",
            )?;
            validate_limit(request.limit, "action_list_request.limit")?;
        }
        MessageBody::ActionList(list) => {
            if list.actions.len() > 1000 {
                return Err(AipError::Validation(
                    "action_list.actions must not exceed 1000 items".to_owned(),
                ));
            }
        }
        MessageBody::ActionEventsRequest(request) => {
            validate_optional_string(
                request.tenant_id.as_deref(),
                "action_events_request.tenant_id",
            )?;
            validate_string_list(&request.kinds, "action_events_request.kinds")?;
            validate_limit(request.limit, "action_events_request.limit")?;
        }
        MessageBody::ActionEvents(events) => {
            if events
                .events
                .iter()
                .any(|event| event.action_id.as_ref() != Some(&events.action_id))
            {
                return Err(AipError::Validation(
                    "action_events events must be scoped to action_id".to_owned(),
                ));
            }
            if events
                .chunks
                .iter()
                .any(|chunk| chunk.action_id != events.action_id)
            {
                return Err(AipError::Validation(
                    "action_events chunks must be scoped to action_id".to_owned(),
                ));
            }
        }
        MessageBody::SessionListRequest(request) => {
            validate_limit(request.limit, "session_list_request.limit")?;
        }
        MessageBody::SessionCloseRequest(request) => {
            if request
                .reason
                .as_deref()
                .is_some_and(|reason| reason.trim().is_empty())
            {
                return Err(AipError::Validation(
                    "session_close_request.reason must not be empty".to_owned(),
                ));
            }
        }
        MessageBody::SessionResumeRequest(request) => {
            if request
                .resume_token
                .as_deref()
                .is_some_and(|token| token.trim().is_empty())
            {
                return Err(AipError::Validation(
                    "session_resume_request.resume_token must not be empty".to_owned(),
                ));
            }
        }
        MessageBody::ApprovalQueryRequest(request) => {
            validate_optional_string(
                request.tenant_id.as_deref(),
                "approval_query_request.tenant_id",
            )?;
        }
        MessageBody::ApprovalListRequest(request) => {
            validate_limit(request.limit, "approval_list_request.limit")?;
            if request
                .status
                .as_deref()
                .is_some_and(|status| status.trim().is_empty())
            {
                return Err(AipError::Validation(
                    "approval_list_request.status must not be empty".to_owned(),
                ));
            }
            if request
                .tenant_id
                .as_deref()
                .is_some_and(|tenant_id| tenant_id.trim().is_empty())
            {
                return Err(AipError::Validation(
                    "approval_list_request.tenant_id must not be empty".to_owned(),
                ));
            }
        }
        MessageBody::ApprovalRecordView(view) => {
            validate_approval_request(&view.request)?;
            if let Some(decision) = &view.decision {
                validate_approval_decision(decision)?;
                if decision.approval_id != view.request.id {
                    return Err(AipError::Validation(
                        "approval_record_view decision approval_id must match request id"
                            .to_owned(),
                    ));
                }
            }
            if view.status.trim().is_empty() {
                return Err(AipError::MissingField("approval_record_view.status"));
            }
        }
        MessageBody::ApprovalList(list) => {
            if list.approvals.len() > 1000 {
                return Err(AipError::Validation(
                    "approval_list.approvals must not exceed 1000 items".to_owned(),
                ));
            }
        }
        MessageBody::CallbackDeliveryQueryRequest(request) => {
            if request.delivery_id.trim().is_empty() {
                return Err(AipError::MissingField(
                    "callback_delivery_query_request.delivery_id",
                ));
            }
            validate_optional_string(
                request.tenant_id.as_deref(),
                "callback_delivery_query_request.tenant_id",
            )?;
        }
        MessageBody::CallbackDeliveryListRequest(request) => {
            validate_optional_string(
                request.tenant_id.as_deref(),
                "callback_delivery_list_request.tenant_id",
            )?;
            validate_limit(request.limit, "callback_delivery_list_request.limit")?;
            if request
                .target
                .as_deref()
                .is_some_and(|target| target.trim().is_empty())
            {
                return Err(AipError::Validation(
                    "callback_delivery_list_request.target must not be empty".to_owned(),
                ));
            }
        }
        MessageBody::CallbackDeliveryRecord(record) => {
            if record.delivery_id.trim().is_empty() {
                return Err(AipError::MissingField(
                    "callback_delivery_record.delivery_id",
                ));
            }
            if record.message_type.trim().is_empty() {
                return Err(AipError::MissingField(
                    "callback_delivery_record.message_type",
                ));
            }
            if record.policy.delivery_id != record.delivery_id {
                return Err(AipError::Validation(
                    "callback_delivery_record policy delivery_id must match record delivery_id"
                        .to_owned(),
                ));
            }
        }
        MessageBody::CallbackDeliveryList(list) => {
            if list.deliveries.len() > 1000 {
                return Err(AipError::Validation(
                    "callback_delivery_list.deliveries must not exceed 1000 items".to_owned(),
                ));
            }
        }
        MessageBody::TransactionQueryRequest(request) => {
            let selector_count = usize::from(request.transaction_id.is_some())
                + usize::from(request.plan_id.is_some())
                + usize::from(request.action_id.is_some());
            if selector_count != 1 {
                return Err(AipError::Validation(
                    "transaction_query_request must supply exactly one selector".to_owned(),
                ));
            }
            if request
                .plan_id
                .as_deref()
                .is_some_and(|plan_id| plan_id.trim().is_empty())
            {
                return Err(AipError::Validation(
                    "transaction_query_request.plan_id must not be empty".to_owned(),
                ));
            }
            validate_optional_string(
                request.tenant_id.as_deref(),
                "transaction_query_request.tenant_id",
            )?;
        }
        MessageBody::TransactionView(view) => {
            if view.transaction.transaction_id.as_ref() != Some(&view.transaction_id) {
                return Err(AipError::Validation(
                    "transaction_view transaction_id must match transaction.transaction_id"
                        .to_owned(),
                ));
            }
            if view.status.trim().is_empty() {
                return Err(AipError::MissingField("transaction_view.status"));
            }
        }
        MessageBody::Manifest(manifest) => validate_manifest(manifest)?,
        MessageBody::ManifestRequest(request) => {
            validate_manifest_filter(request.filter.as_ref())?;
        }
        MessageBody::EventStreamRequest(request) => {
            validate_limit(request.limit, "event_stream_request.limit")?;
        }
        MessageBody::ReceiptQueryRequest(request) => {
            let selector_count =
                usize::from(request.chain_id.is_some()) + usize::from(request.receipt_id.is_some());
            if selector_count != 1 {
                return Err(AipError::Validation(
                    "receipt_query_request must supply exactly one selector".to_owned(),
                ));
            }
            if request
                .chain_id
                .as_deref()
                .is_some_and(|chain_id| chain_id.trim().is_empty())
            {
                return Err(AipError::Validation(
                    "receipt_query_request.chain_id must not be empty".to_owned(),
                ));
            }
        }
        MessageBody::ReceiptChain(chain) => {
            if !chain.receipts.is_empty()
                && chain
                    .root_hash
                    .as_deref()
                    .is_none_or(|root_hash| root_hash.trim().is_empty())
            {
                return Err(AipError::MissingField("receipt_chain.root_hash"));
            }
        }
        MessageBody::AuditQueryRequest(request) => {
            validate_optional_string(
                request.tenant_id.as_deref(),
                "audit_query_request.tenant_id",
            )?;
            validate_limit(request.limit, "audit_query_request.limit")?;
            if let (Some(from), Some(to)) = (request.from, request.to)
                && from > to
            {
                return Err(AipError::Validation(
                    "audit_query_request.from must be before or equal to to".to_owned(),
                ));
            }
        }
        MessageBody::AuditQueryResult(result) => {
            if result.events.len() > 1000 {
                return Err(AipError::Validation(
                    "audit_query_result.events must not exceed 1000 items".to_owned(),
                ));
            }
        }
        MessageBody::ResourceListRequest(request) => {
            validate_optional_string(
                request.tenant_id.as_deref(),
                "resource_list_request.tenant_id",
            )?;
            validate_limit(request.limit, "resource_list_request.limit")?;
            if request
                .kind
                .as_deref()
                .is_some_and(|kind| kind.trim().is_empty())
            {
                return Err(AipError::Validation(
                    "resource_list_request.kind must not be empty".to_owned(),
                ));
            }
        }
        MessageBody::ResourceReadRequest(request) => {
            if request.resource_id.trim().is_empty() {
                return Err(AipError::MissingField("resource_read_request.resource_id"));
            }
            validate_optional_string(
                request.tenant_id.as_deref(),
                "resource_read_request.tenant_id",
            )?;
            if request
                .version
                .as_deref()
                .is_some_and(|version| version.trim().is_empty())
            {
                return Err(AipError::Validation(
                    "resource_read_request.version must not be empty".to_owned(),
                ));
            }
        }
        MessageBody::ResourceReadResult(result) if result.resource.id.trim().is_empty() => {
            return Err(AipError::MissingField("resource_read_result.resource.id"));
        }
        _ => {}
    }
    Ok(())
}

fn validate_manifest_filter(filter: Option<&crate::ManifestFilter>) -> AipResult<()> {
    let Some(filter) = filter else {
        return Ok(());
    };
    if filter
        .resource_kinds
        .iter()
        .any(|kind| kind.trim().is_empty())
    {
        return Err(AipError::Validation(
            "manifest_request.filter.resource_kinds must not contain empty values".to_owned(),
        ));
    }
    Ok(())
}

fn validate_wait_ms(wait_ms: Option<u64>, path: &'static str) -> AipResult<()> {
    if wait_ms.is_some_and(|wait| wait > 30_000) {
        return Err(AipError::Validation(format!(
            "{path} must not exceed 30000"
        )));
    }
    Ok(())
}

fn validate_limit(limit: Option<u32>, path: &'static str) -> AipResult<()> {
    if limit.is_some_and(|limit| limit == 0 || limit > 1000) {
        return Err(AipError::Validation(format!(
            "{path} must be between 1 and 1000"
        )));
    }
    Ok(())
}

fn validate_optional_string(value: Option<&str>, path: &'static str) -> AipResult<()> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        return Err(AipError::Validation(format!("{path} must not be empty")));
    }
    Ok(())
}

fn validate_string_list(values: &[String], path: &'static str) -> AipResult<()> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(AipError::Validation(format!(
            "{path} must not contain empty values"
        )));
    }
    Ok(())
}

fn validate_action(action: &Action) -> AipResult<()> {
    if action.input.is_null() {
        return Err(AipError::Validation(
            "action.input must not be null".to_owned(),
        ));
    }
    if action.idempotency_key.as_deref().is_some_and(str::is_empty) {
        return Err(AipError::Validation(
            "action.idempotency_key must not be empty".to_owned(),
        ));
    }
    if action.timeout_ms.is_some_and(|timeout| timeout == 0) {
        return Err(AipError::Validation(
            "action.timeout_ms must be greater than zero".to_owned(),
        ));
    }
    if action.delegation_chain.len() > 10 {
        return Err(AipError::Validation(
            "action.delegation_chain must not exceed 10 hops".to_owned(),
        ));
    }
    if let Some(identity) = &action.identity {
        validate_identity_context(identity, "action.identity")?;
    }
    if let Some(approval) = &action.approval {
        validate_approval_decision(approval)?;
        if approval.decision != ApprovalDecisionKind::Approved {
            return Err(AipError::Validation(
                "action.approval must contain an approved decision".to_owned(),
            ));
        }
    }
    if let Some(transaction) = &action.transaction {
        if transaction.mode == TransactionMode::Commit && transaction.plan_id.as_deref().is_none() {
            return Err(AipError::Validation(
                "action.transaction.plan_id is required for commit mode".to_owned(),
            ));
        }
        if transaction.mode == TransactionMode::Compensate && transaction.compensation_for.is_none()
        {
            return Err(AipError::Validation(
                "action.transaction.compensation_for is required for compensate mode".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_manifest(manifest: &Manifest) -> AipResult<()> {
    if manifest.manifest_version.trim().is_empty() {
        return Err(AipError::MissingField("manifest.manifest_version"));
    }
    if manifest.profiles.is_empty() {
        return Err(AipError::MissingField("manifest.profiles"));
    }
    let mut capability_ids = HashSet::new();
    for capability in &manifest.capabilities {
        validate_capability(capability)?;
        if !capability_ids.insert(capability.id.as_str()) {
            return Err(AipError::Validation(format!(
                "duplicate capability id `{}`",
                capability.id
            )));
        }
    }
    Ok(())
}

fn validate_capability(capability: &Capability) -> AipResult<()> {
    if capability.name.trim().is_empty() {
        return Err(AipError::MissingField("capability.name"));
    }
    if !capability.input_schema.is_object() {
        return Err(AipError::Validation(format!(
            "capability `{}` input_schema must be a JSON object",
            capability.id
        )));
    }
    if let Some(contract) = &capability.contract {
        if contract.side_effects.is_empty() {
            return Err(AipError::Validation(format!(
                "capability `{}` contract.side_effects must not be empty",
                capability.id
            )));
        }
        if contract.idempotency.ttl_ms.is_some_and(|ttl| ttl == 0) {
            return Err(AipError::Validation(format!(
                "capability `{}` contract.idempotency.ttl_ms must be greater than zero",
                capability.id
            )));
        }
        if !contract.execution.supports_sync
            && !contract.execution.supports_async
            && !contract.execution.supports_streaming
        {
            return Err(AipError::Validation(format!(
                "capability `{}` contract.execution must support at least one mode",
                capability.id
            )));
        }
        if let Some(sla) = &contract.sla
            && (sla.expected_latency_ms.is_some_and(|latency| latency == 0)
                || sla.timeout_ms.is_some_and(|timeout| timeout == 0)
                || sla.max_queue_delay_ms.is_some_and(|delay| delay == 0))
        {
            return Err(AipError::Validation(format!(
                "capability `{}` contract.sla durations must be greater than zero",
                capability.id
            )));
        }
        if let Some(credentials) = &contract.credentials {
            for issuer in &credentials.accepted_issuers {
                if issuer.trim().is_empty() {
                    return Err(AipError::Validation(format!(
                        "capability `{}` contract.credentials.accepted_issuers must not contain empty values",
                        capability.id
                    )));
                }
            }
            for scope in &credentials.required_scopes {
                if scope.trim().is_empty() {
                    return Err(AipError::Validation(format!(
                        "capability `{}` contract.credentials.required_scopes must not contain empty values",
                        capability.id
                    )));
                }
            }
        }
        if let Some(transaction) = &contract.transaction
            && transaction.supported_modes.is_empty()
        {
            return Err(AipError::Validation(format!(
                "capability `{}` contract.transaction.supported_modes must not be empty",
                capability.id
            )));
        }
        if let Some(compensation) = &contract.compensation
            && compensation.mode == CompensationMode::Supported
            && compensation.compensation_capability_id.is_none()
        {
            return Err(AipError::Validation(format!(
                "capability `{}` contract.compensation_capability_id is required when compensation is supported",
                capability.id
            )));
        }
    }
    Ok(())
}

fn validate_approval_request(request: &ApprovalRequest) -> AipResult<()> {
    if request.reason.trim().is_empty() {
        return Err(AipError::MissingField("approval_request.reason"));
    }
    if let Some(identity) = &request.identity {
        validate_identity_context(identity, "approval_request.identity")?;
    }
    for evidence in &request.evidence {
        if evidence.id.trim().is_empty() {
            return Err(AipError::MissingField("approval_request.evidence.id"));
        }
        if evidence.kind.trim().is_empty() {
            return Err(AipError::MissingField("approval_request.evidence.kind"));
        }
    }
    Ok(())
}

fn validate_approval_decision(decision: &ApprovalDecision) -> AipResult<()> {
    if let Some(reason) = &decision.reason
        && reason.trim().is_empty()
    {
        return Err(AipError::Validation(
            "approval_decision.reason must not be empty".to_owned(),
        ));
    }
    for constraint in &decision.constraints {
        if constraint.field.trim().is_empty() {
            return Err(AipError::MissingField(
                "approval_decision.constraints.field",
            ));
        }
        if constraint.operator.trim().is_empty() {
            return Err(AipError::MissingField(
                "approval_decision.constraints.operator",
            ));
        }
    }
    for evidence in &decision.evidence {
        if evidence.id.trim().is_empty() {
            return Err(AipError::MissingField("approval_decision.evidence.id"));
        }
        if evidence.kind.trim().is_empty() {
            return Err(AipError::MissingField("approval_decision.evidence.kind"));
        }
    }
    Ok(())
}

fn validate_identity_context(
    identity: &crate::IdentityContext,
    path: &'static str,
) -> AipResult<()> {
    if let Some(tenant) = &identity.tenant
        && tenant.id.trim().is_empty()
    {
        return Err(AipError::MissingField(path));
    }
    if let Some(account) = &identity.external_account {
        if account.id.trim().is_empty() {
            return Err(AipError::MissingField(path));
        }
        if account.system.trim().is_empty() {
            return Err(AipError::MissingField(path));
        }
    }
    if let Some(user) = &identity.external_user {
        if user.id.trim().is_empty() {
            return Err(AipError::MissingField(path));
        }
        if user.system.trim().is_empty() {
            return Err(AipError::MissingField(path));
        }
    }
    if let Some(credential) = &identity.credential_ref {
        if credential.id.trim().is_empty() {
            return Err(AipError::MissingField(path));
        }
        if credential.issuer.trim().is_empty() {
            return Err(AipError::MissingField(path));
        }
        if credential
            .scopes
            .iter()
            .any(|scope| scope.trim().is_empty())
        {
            return Err(AipError::Validation(format!(
                "{path}.credential_ref.scopes must not contain empty values"
            )));
        }
    }
    if let Some(oauth) = &identity.oauth {
        if oauth.issuer.trim().is_empty() {
            return Err(AipError::MissingField(path));
        }
        if oauth.scopes.iter().any(|scope| scope.trim().is_empty()) {
            return Err(AipError::Validation(format!(
                "{path}.oauth.scopes must not contain empty values"
            )));
        }
        if oauth.client_id.as_deref().is_some_and(str::is_empty) {
            return Err(AipError::Validation(format!(
                "{path}.oauth.client_id must not be empty"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_envelope;
    use crate::{
        Capability, CapabilityId, CapabilityKind, Envelope, Manifest, ManifestRequest, MessageBody,
        Principal, PrincipalId, PrincipalKind, ProfileId,
    };
    use serde_json::json;

    #[test]
    fn generated_envelope_is_valid() {
        let envelope = Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
            profiles: Vec::new(),
            filter: None,
        }));
        assert!(validate_envelope(&envelope).is_ok());
    }

    #[test]
    fn duplicate_manifest_capability_is_invalid() {
        let capability = Capability {
            id: CapabilityId::trusted("cap:test"),
            name: "test".to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: json!({ "type": "object" }),
            output_schema: None,
            description: None,
            risk: None,
            stability: None,
            cost: None,
            auth: None,
            bindings: Vec::new(),
            requires_human_approval: None,
            contract: None,
        };
        let envelope = Envelope::new(MessageBody::Manifest(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(PrincipalId::trusted("agent:test"), PrincipalKind::Agent),
            capabilities: vec![capability.clone(), capability],
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        }));

        assert!(validate_envelope(&envelope).is_err());
    }
}
