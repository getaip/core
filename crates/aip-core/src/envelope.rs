//! AIP native envelope and message type registry.

use crate::{
    Ack, Action, ActionEvents, ActionEventsRequest, ActionList, ActionListRequest, ActionResult,
    ActionResultRequest, ActionStatus, ActionStatusRequest, ApprovalDecision, ApprovalList,
    ApprovalListRequest, ApprovalQueryRequest, ApprovalRecordView, ApprovalRequest, AuditEvent,
    AuditQueryRequest, AuditQueryResult, BatchSettlement, CallbackDeliveryList,
    CallbackDeliveryListRequest, CallbackDeliveryQueryRequest, CallbackDeliveryRecord, Cancel,
    ChannelMessage, ConversationUpdated, CorrelationId, DelegationRequest, DelegationResult,
    ErrorBody, Escalation, EscalationResolution, EventStream, EventStreamRequest, Handshake,
    HandshakeResponse, Heartbeat, HeartbeatAck, Manifest, ManifestRequest, MessageId,
    MessageReference, Principal, ReceiptChain, ReceiptQueryRequest, ResourceList,
    ResourceListRequest, ResourceReadRequest, ResourceReadResult, SessionCloseRequest, SessionId,
    SessionList, SessionListRequest, SessionRequest, SessionResume, SessionResumeRequest,
    SessionView, StreamChunk, TransactionQueryRequest, TransactionRequest, TransactionResult,
    TransactionView,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

/// Current AIP protocol version.
pub const AIP_VERSION: &str = "1.0";

/// Native AIP message type registry.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageType {
    /// Session negotiation request.
    #[serde(rename = "aip.core.v1.handshake")]
    Handshake,
    /// Session negotiation response.
    #[serde(rename = "aip.core.v1.handshake_response")]
    HandshakeResponse,
    /// Capability invocation.
    #[serde(rename = "aip.core.v1.action")]
    Action,
    /// Action acknowledgement.
    #[serde(rename = "aip.core.v1.ack")]
    Ack,
    /// Partial stream chunk.
    #[serde(rename = "aip.core.v1.stream_chunk")]
    StreamChunk,
    /// Final action result.
    #[serde(rename = "aip.core.v1.action_result")]
    ActionResult,
    /// Action lifecycle status request.
    #[serde(rename = "aip.lifecycle.v1.action_status_request")]
    ActionStatusRequest,
    /// Action lifecycle status response.
    #[serde(rename = "aip.lifecycle.v1.action_status")]
    ActionStatus,
    /// Action result lookup request.
    #[serde(rename = "aip.lifecycle.v1.action_result_request")]
    ActionResultRequest,
    /// Action list request.
    #[serde(rename = "aip.lifecycle.v1.action_list_request")]
    ActionListRequest,
    /// Action list response.
    #[serde(rename = "aip.lifecycle.v1.action_list")]
    ActionList,
    /// Action-scoped event request.
    #[serde(rename = "aip.lifecycle.v1.action_events_request")]
    ActionEventsRequest,
    /// Action-scoped event response.
    #[serde(rename = "aip.lifecycle.v1.action_events")]
    ActionEvents,
    /// Human approval request.
    #[serde(rename = "aip.policy.v1.approval_request")]
    ApprovalRequest,
    /// Human approval decision.
    #[serde(rename = "aip.policy.v1.approval_decision")]
    ApprovalDecision,
    /// Approval query request.
    #[serde(rename = "aip.policy.v1.approval_query_request")]
    ApprovalQueryRequest,
    /// Approval list request.
    #[serde(rename = "aip.policy.v1.approval_list_request")]
    ApprovalListRequest,
    /// Approval record view.
    #[serde(rename = "aip.policy.v1.approval_record_view")]
    ApprovalRecordView,
    /// Approval list response.
    #[serde(rename = "aip.policy.v1.approval_list")]
    ApprovalList,
    /// Callback delivery query request.
    #[serde(rename = "aip.callback.v1.delivery_query_request")]
    CallbackDeliveryQueryRequest,
    /// Callback delivery list request.
    #[serde(rename = "aip.callback.v1.delivery_list_request")]
    CallbackDeliveryListRequest,
    /// Callback delivery record response.
    #[serde(rename = "aip.callback.v1.delivery_record")]
    CallbackDeliveryRecord,
    /// Callback delivery list response.
    #[serde(rename = "aip.callback.v1.delivery_list")]
    CallbackDeliveryList,
    /// Session query request.
    #[serde(rename = "aip.session.v1.session_request")]
    SessionRequest,
    /// Session view response.
    #[serde(rename = "aip.session.v1.session_view")]
    SessionView,
    /// Session list request.
    #[serde(rename = "aip.session.v1.session_list_request")]
    SessionListRequest,
    /// Session list response.
    #[serde(rename = "aip.session.v1.session_list")]
    SessionList,
    /// Session close request.
    #[serde(rename = "aip.session.v1.session_close_request")]
    SessionCloseRequest,
    /// Session resume request.
    #[serde(rename = "aip.session.v1.session_resume_request")]
    SessionResumeRequest,
    /// Session resume response.
    #[serde(rename = "aip.session.v1.session_resume")]
    SessionResume,
    /// Agent-to-agent delegation request.
    #[serde(rename = "aip.agent.v1.delegation_request")]
    DelegationRequest,
    /// Agent-to-agent delegation result.
    #[serde(rename = "aip.agent.v1.delegation_result")]
    DelegationResult,
    /// First-class transaction request.
    #[serde(rename = "aip.transaction.v1.request")]
    TransactionRequest,
    /// First-class transaction result.
    #[serde(rename = "aip.transaction.v1.result")]
    TransactionResult,
    /// Transaction query request.
    #[serde(rename = "aip.transaction.v1.query_request")]
    TransactionQueryRequest,
    /// Transaction view response.
    #[serde(rename = "aip.transaction.v1.view")]
    TransactionView,
    /// Protocol/action error.
    #[serde(rename = "aip.core.v1.error")]
    Error,
    /// Cancellation request.
    #[serde(rename = "aip.core.v1.cancel")]
    Cancel,
    /// Heartbeat.
    #[serde(rename = "aip.core.v1.heartbeat")]
    Heartbeat,
    /// Heartbeat acknowledgement.
    #[serde(rename = "aip.core.v1.heartbeat_ack")]
    HeartbeatAck,
    /// Human escalation request.
    #[serde(rename = "aip.core.v1.escalation")]
    Escalation,
    /// Human escalation resolution.
    #[serde(rename = "aip.core.v1.escalation_resolution")]
    EscalationResolution,
    /// Manifest request.
    #[serde(rename = "aip.discovery.v1.manifest_request")]
    ManifestRequest,
    /// Manifest response.
    #[serde(rename = "aip.discovery.v1.manifest_response")]
    ManifestResponse,
    /// Event stream request.
    #[serde(rename = "aip.discovery.v1.event_stream_request")]
    EventStreamRequest,
    /// Event stream response.
    #[serde(rename = "aip.discovery.v1.event_stream_response")]
    EventStreamResponse,
    /// Channel message created.
    #[serde(rename = "aip.channel.v1.message_created")]
    ChannelMessageCreated,
    /// Conversation updated.
    #[serde(rename = "aip.channel.v1.conversation_updated")]
    ConversationUpdated,
    /// Receipt chain.
    #[serde(rename = "aip.audit.v1.receipt_chain")]
    ReceiptChain,
    /// Receipt query request.
    #[serde(rename = "aip.audit.v1.receipt_query_request")]
    ReceiptQueryRequest,
    /// Audit event.
    #[serde(rename = "aip.audit.v1.audit_event")]
    AuditEvent,
    /// Audit query request.
    #[serde(rename = "aip.audit.v1.audit_query_request")]
    AuditQueryRequest,
    /// Audit query response.
    #[serde(rename = "aip.audit.v1.audit_query_result")]
    AuditQueryResult,
    /// Resource list request.
    #[serde(rename = "aip.resource.v1.resource_list_request")]
    ResourceListRequest,
    /// Resource list response.
    #[serde(rename = "aip.resource.v1.resource_list")]
    ResourceList,
    /// Resource read request.
    #[serde(rename = "aip.resource.v1.resource_read_request")]
    ResourceReadRequest,
    /// Resource read response.
    #[serde(rename = "aip.resource.v1.resource_read_result")]
    ResourceReadResult,
    /// Optional economic settlement batch.
    #[serde(rename = "aip.economic.v1.batch_settlement")]
    BatchSettlement,
}

impl MessageType {
    /// Returns the stable wire identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Handshake => "aip.core.v1.handshake",
            Self::HandshakeResponse => "aip.core.v1.handshake_response",
            Self::Action => "aip.core.v1.action",
            Self::Ack => "aip.core.v1.ack",
            Self::StreamChunk => "aip.core.v1.stream_chunk",
            Self::ActionResult => "aip.core.v1.action_result",
            Self::ActionStatusRequest => "aip.lifecycle.v1.action_status_request",
            Self::ActionStatus => "aip.lifecycle.v1.action_status",
            Self::ActionResultRequest => "aip.lifecycle.v1.action_result_request",
            Self::ActionListRequest => "aip.lifecycle.v1.action_list_request",
            Self::ActionList => "aip.lifecycle.v1.action_list",
            Self::ActionEventsRequest => "aip.lifecycle.v1.action_events_request",
            Self::ActionEvents => "aip.lifecycle.v1.action_events",
            Self::ApprovalRequest => "aip.policy.v1.approval_request",
            Self::ApprovalDecision => "aip.policy.v1.approval_decision",
            Self::ApprovalQueryRequest => "aip.policy.v1.approval_query_request",
            Self::ApprovalListRequest => "aip.policy.v1.approval_list_request",
            Self::ApprovalRecordView => "aip.policy.v1.approval_record_view",
            Self::ApprovalList => "aip.policy.v1.approval_list",
            Self::CallbackDeliveryQueryRequest => "aip.callback.v1.delivery_query_request",
            Self::CallbackDeliveryListRequest => "aip.callback.v1.delivery_list_request",
            Self::CallbackDeliveryRecord => "aip.callback.v1.delivery_record",
            Self::CallbackDeliveryList => "aip.callback.v1.delivery_list",
            Self::SessionRequest => "aip.session.v1.session_request",
            Self::SessionView => "aip.session.v1.session_view",
            Self::SessionListRequest => "aip.session.v1.session_list_request",
            Self::SessionList => "aip.session.v1.session_list",
            Self::SessionCloseRequest => "aip.session.v1.session_close_request",
            Self::SessionResumeRequest => "aip.session.v1.session_resume_request",
            Self::SessionResume => "aip.session.v1.session_resume",
            Self::DelegationRequest => "aip.agent.v1.delegation_request",
            Self::DelegationResult => "aip.agent.v1.delegation_result",
            Self::TransactionRequest => "aip.transaction.v1.request",
            Self::TransactionResult => "aip.transaction.v1.result",
            Self::TransactionQueryRequest => "aip.transaction.v1.query_request",
            Self::TransactionView => "aip.transaction.v1.view",
            Self::Error => "aip.core.v1.error",
            Self::Cancel => "aip.core.v1.cancel",
            Self::Heartbeat => "aip.core.v1.heartbeat",
            Self::HeartbeatAck => "aip.core.v1.heartbeat_ack",
            Self::Escalation => "aip.core.v1.escalation",
            Self::EscalationResolution => "aip.core.v1.escalation_resolution",
            Self::ManifestRequest => "aip.discovery.v1.manifest_request",
            Self::ManifestResponse => "aip.discovery.v1.manifest_response",
            Self::EventStreamRequest => "aip.discovery.v1.event_stream_request",
            Self::EventStreamResponse => "aip.discovery.v1.event_stream_response",
            Self::ChannelMessageCreated => "aip.channel.v1.message_created",
            Self::ConversationUpdated => "aip.channel.v1.conversation_updated",
            Self::ReceiptChain => "aip.audit.v1.receipt_chain",
            Self::ReceiptQueryRequest => "aip.audit.v1.receipt_query_request",
            Self::AuditEvent => "aip.audit.v1.audit_event",
            Self::AuditQueryRequest => "aip.audit.v1.audit_query_request",
            Self::AuditQueryResult => "aip.audit.v1.audit_query_result",
            Self::ResourceListRequest => "aip.resource.v1.resource_list_request",
            Self::ResourceList => "aip.resource.v1.resource_list",
            Self::ResourceReadRequest => "aip.resource.v1.resource_read_request",
            Self::ResourceReadResult => "aip.resource.v1.resource_read_result",
            Self::BatchSettlement => "aip.economic.v1.batch_settlement",
        }
    }
}

/// Message body keyed by the required body object name from the specification.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageBody {
    /// Session negotiation request.
    Handshake(Handshake),
    /// Session negotiation response.
    HandshakeResponse(Box<HandshakeResponse>),
    /// Capability invocation.
    Action(Box<Action>),
    /// Action acknowledgement.
    Ack(Ack),
    /// Stream chunk.
    StreamChunk(StreamChunk),
    /// Action result.
    ActionResult(ActionResult),
    /// Action status query.
    ActionStatusRequest(ActionStatusRequest),
    /// Action status response.
    ActionStatus(Box<ActionStatus>),
    /// Action result query.
    ActionResultRequest(ActionResultRequest),
    /// Action list query.
    ActionListRequest(ActionListRequest),
    /// Action list response.
    ActionList(Box<ActionList>),
    /// Action-scoped events query.
    ActionEventsRequest(ActionEventsRequest),
    /// Action-scoped events response.
    ActionEvents(ActionEvents),
    /// Approval request.
    ApprovalRequest(Box<ApprovalRequest>),
    /// Approval decision.
    ApprovalDecision(Box<ApprovalDecision>),
    /// Approval query request.
    ApprovalQueryRequest(ApprovalQueryRequest),
    /// Approval list request.
    ApprovalListRequest(ApprovalListRequest),
    /// Approval record view.
    ApprovalRecordView(Box<ApprovalRecordView>),
    /// Approval list response.
    ApprovalList(Box<ApprovalList>),
    /// Callback delivery query request.
    CallbackDeliveryQueryRequest(CallbackDeliveryQueryRequest),
    /// Callback delivery list request.
    CallbackDeliveryListRequest(CallbackDeliveryListRequest),
    /// Callback delivery record response.
    CallbackDeliveryRecord(Box<CallbackDeliveryRecord>),
    /// Callback delivery list response.
    CallbackDeliveryList(Box<CallbackDeliveryList>),
    /// Session query request.
    SessionRequest(SessionRequest),
    /// Session view response.
    SessionView(Box<SessionView>),
    /// Session list request.
    SessionListRequest(SessionListRequest),
    /// Session list response.
    SessionList(Box<SessionList>),
    /// Session close request.
    SessionCloseRequest(SessionCloseRequest),
    /// Session resume request.
    SessionResumeRequest(SessionResumeRequest),
    /// Session resume response.
    SessionResume(Box<SessionResume>),
    /// Agent-to-agent delegation request.
    DelegationRequest(Box<DelegationRequest>),
    /// Agent-to-agent delegation result.
    DelegationResult(Box<DelegationResult>),
    /// First-class transaction request.
    TransactionRequest(Box<TransactionRequest>),
    /// First-class transaction result.
    TransactionResult(Box<TransactionResult>),
    /// Transaction query request.
    TransactionQueryRequest(TransactionQueryRequest),
    /// Transaction view response.
    TransactionView(Box<TransactionView>),
    /// Error body.
    Error(ErrorBody),
    /// Cancel body.
    Cancel(Cancel),
    /// Heartbeat body.
    Heartbeat(Heartbeat),
    /// Heartbeat acknowledgement body.
    HeartbeatAck(HeartbeatAck),
    /// Escalation body.
    Escalation(Box<Escalation>),
    /// Escalation resolution body.
    EscalationResolution(EscalationResolution),
    /// Manifest request body.
    ManifestRequest(ManifestRequest),
    /// Manifest response body.
    Manifest(Manifest),
    /// Event stream request body.
    EventStreamRequest(EventStreamRequest),
    /// Event stream body.
    EventStream(EventStream),
    /// Channel message body.
    ChannelMessage(Box<ChannelMessage>),
    /// Conversation update body.
    Conversation(Box<ConversationUpdated>),
    /// Receipt chain body.
    ReceiptChain(ReceiptChain),
    /// Receipt query request.
    ReceiptQueryRequest(ReceiptQueryRequest),
    /// Audit event body.
    AuditEvent(Box<AuditEvent>),
    /// Audit query request.
    AuditQueryRequest(AuditQueryRequest),
    /// Audit query response.
    AuditQueryResult(AuditQueryResult),
    /// Native resource list request.
    ResourceListRequest(ResourceListRequest),
    /// Native resource list response.
    ResourceList(ResourceList),
    /// Native resource read request.
    ResourceReadRequest(ResourceReadRequest),
    /// Native resource read response.
    ResourceReadResult(ResourceReadResult),
    /// Batch settlement body.
    BatchSettlement(BatchSettlement),
}

impl MessageBody {
    /// Returns the message type implied by this body.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::Handshake(_) => MessageType::Handshake,
            Self::HandshakeResponse(_) => MessageType::HandshakeResponse,
            Self::Action(_) => MessageType::Action,
            Self::Ack(_) => MessageType::Ack,
            Self::StreamChunk(_) => MessageType::StreamChunk,
            Self::ActionResult(_) => MessageType::ActionResult,
            Self::ActionStatusRequest(_) => MessageType::ActionStatusRequest,
            Self::ActionStatus(_) => MessageType::ActionStatus,
            Self::ActionResultRequest(_) => MessageType::ActionResultRequest,
            Self::ActionListRequest(_) => MessageType::ActionListRequest,
            Self::ActionList(_) => MessageType::ActionList,
            Self::ActionEventsRequest(_) => MessageType::ActionEventsRequest,
            Self::ActionEvents(_) => MessageType::ActionEvents,
            Self::ApprovalRequest(_) => MessageType::ApprovalRequest,
            Self::ApprovalDecision(_) => MessageType::ApprovalDecision,
            Self::ApprovalQueryRequest(_) => MessageType::ApprovalQueryRequest,
            Self::ApprovalListRequest(_) => MessageType::ApprovalListRequest,
            Self::ApprovalRecordView(_) => MessageType::ApprovalRecordView,
            Self::ApprovalList(_) => MessageType::ApprovalList,
            Self::CallbackDeliveryQueryRequest(_) => MessageType::CallbackDeliveryQueryRequest,
            Self::CallbackDeliveryListRequest(_) => MessageType::CallbackDeliveryListRequest,
            Self::CallbackDeliveryRecord(_) => MessageType::CallbackDeliveryRecord,
            Self::CallbackDeliveryList(_) => MessageType::CallbackDeliveryList,
            Self::SessionRequest(_) => MessageType::SessionRequest,
            Self::SessionView(_) => MessageType::SessionView,
            Self::SessionListRequest(_) => MessageType::SessionListRequest,
            Self::SessionList(_) => MessageType::SessionList,
            Self::SessionCloseRequest(_) => MessageType::SessionCloseRequest,
            Self::SessionResumeRequest(_) => MessageType::SessionResumeRequest,
            Self::SessionResume(_) => MessageType::SessionResume,
            Self::DelegationRequest(_) => MessageType::DelegationRequest,
            Self::DelegationResult(_) => MessageType::DelegationResult,
            Self::TransactionRequest(_) => MessageType::TransactionRequest,
            Self::TransactionResult(_) => MessageType::TransactionResult,
            Self::TransactionQueryRequest(_) => MessageType::TransactionQueryRequest,
            Self::TransactionView(_) => MessageType::TransactionView,
            Self::Error(_) => MessageType::Error,
            Self::Cancel(_) => MessageType::Cancel,
            Self::Heartbeat(_) => MessageType::Heartbeat,
            Self::HeartbeatAck(_) => MessageType::HeartbeatAck,
            Self::Escalation(_) => MessageType::Escalation,
            Self::EscalationResolution(_) => MessageType::EscalationResolution,
            Self::ManifestRequest(_) => MessageType::ManifestRequest,
            Self::Manifest(_) => MessageType::ManifestResponse,
            Self::EventStreamRequest(_) => MessageType::EventStreamRequest,
            Self::EventStream(_) => MessageType::EventStreamResponse,
            Self::ChannelMessage(_) => MessageType::ChannelMessageCreated,
            Self::Conversation(_) => MessageType::ConversationUpdated,
            Self::ReceiptChain(_) => MessageType::ReceiptChain,
            Self::ReceiptQueryRequest(_) => MessageType::ReceiptQueryRequest,
            Self::AuditEvent(_) => MessageType::AuditEvent,
            Self::AuditQueryRequest(_) => MessageType::AuditQueryRequest,
            Self::AuditQueryResult(_) => MessageType::AuditQueryResult,
            Self::ResourceListRequest(_) => MessageType::ResourceListRequest,
            Self::ResourceList(_) => MessageType::ResourceList,
            Self::ResourceReadRequest(_) => MessageType::ResourceReadRequest,
            Self::ResourceReadResult(_) => MessageType::ResourceReadResult,
            Self::BatchSettlement(_) => MessageType::BatchSettlement,
        }
    }
}

/// Native AIP envelope.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version. Must be `1.0` for this draft.
    pub aip_version: String,
    /// Fully qualified message type.
    pub message_type: MessageType,
    /// Unique message id.
    pub message_id: MessageId,
    /// Send timestamp.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub sent_at: OffsetDateTime,
    /// Message payload.
    pub body: MessageBody,
    /// Active session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Request correlation id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,
    /// Referenced message or correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_response_to: Option<MessageReference>,
    /// Replay-safe dedupe key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Principal>,
    /// Recipient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Principal>,
    /// Trace metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<Value>,
    /// Signature/auth metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<Value>,
    /// Vendor/profile extensions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

impl Envelope {
    /// Creates an envelope with a generated id and current timestamp.
    #[must_use]
    pub fn new(body: MessageBody) -> Self {
        let message_type = body.message_type();
        Self {
            aip_version: AIP_VERSION.to_owned(),
            message_type,
            message_id: MessageId::new(),
            sent_at: OffsetDateTime::now_utc(),
            body,
            session_id: None,
            correlation_id: None,
            in_response_to: None,
            idempotency_key: None,
            from: None,
            to: None,
            trace: None,
            security: None,
            extensions: None,
        }
    }

    /// Adds a session id to the envelope.
    #[must_use]
    pub fn with_session(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Adds a correlation id to the envelope.
    #[must_use]
    pub fn with_correlation(mut self, correlation_id: CorrelationId) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{Envelope, MessageBody, MessageType};
    use crate::{Action, CapabilityId};
    use serde_json::json;

    #[test]
    fn envelope_message_type_matches_body() {
        let action = Action::new(
            CapabilityId::parse("cap:test").expect("valid id"),
            json!({}),
        );
        let envelope = Envelope::new(MessageBody::Action(Box::new(action)));
        assert_eq!(envelope.message_type, MessageType::Action);
    }
}
