//! JSON Schema registry and validation helpers for AIP.
//!
//! The crate owns protocol-level schema documents and validation utilities. It
//! deliberately keeps schema generation outside `aip-core` so semantic types can
//! remain transport- and tooling-independent.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_core::{
    Ack, Action, ActionEvents, ActionEventsRequest, ActionList, ActionListRequest, ActionResult,
    ActionResultRequest, ActionStatus, ActionStatusRequest, ApprovalDecision, ApprovalList,
    ApprovalListRequest, ApprovalQueryRequest, ApprovalRecordView, ApprovalRequest,
    AuditQueryRequest, AuditQueryResult, CallbackDeliveryList, CallbackDeliveryListRequest,
    CallbackDeliveryPolicy, CallbackDeliveryQueryRequest, CallbackDeliveryRecord,
    CapabilityContract, ChannelMessage, DelegationRequest, DelegationResult, Envelope, Escalation,
    Event, EventStream, IdentityContext, Manifest, ManifestFilter, ReceiptQueryRequest,
    ResourceList, ResourceListRequest, ResourceReadRequest, ResourceReadResult,
    SessionCloseRequest, SessionList, SessionListRequest, SessionRequest, SessionResume,
    SessionResumeRequest, SessionView, StreamChunk, TransactionPlan, TransactionQueryRequest,
    TransactionRequest, TransactionResult, TransactionView, validate_envelope,
};
use schemars::schema_for;
use serde_json::{Value, json};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{OnceLock, mpsc},
    thread,
};
use thiserror::Error;

/// Maximum nesting accepted for a schema compiled by AIP.
pub const MAX_JSON_SCHEMA_DEPTH: usize = 128;
/// Maximum object, array, and scalar nodes accepted in one schema.
pub const MAX_JSON_SCHEMA_NODES: usize = 100_000;
/// Maximum aggregate UTF-8 bytes in schema property names and string values.
pub const MAX_JSON_SCHEMA_TEXT_BYTES: usize = 8 * 1024 * 1024;

const JSON_SCHEMA_COMPILER_STACK_BYTES: usize = 32 * 1024 * 1024;
const JSON_SCHEMA_COMPILER_QUEUE_DEPTH: usize = 64;
const MAX_VALIDATION_ERRORS: usize = 1_024;

/// Error returned by schema compilation or validation.
#[derive(Debug, Error)]
pub enum SchemaError {
    /// The schema itself could not be compiled.
    #[error("schema compile error: {0}")]
    Compile(String),
    /// The instance failed validation.
    #[error("schema validation failed: {0}")]
    Validate(String),
    /// The instance is not a valid AIP envelope.
    #[error("core validation failed: {0}")]
    Core(#[from] aip_core::AipError),
    /// JSON serialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Result alias for schema operations.
pub type SchemaResult<T> = Result<T, SchemaError>;

struct SchemaCompilerRequest {
    schema: Value,
    instance: Option<Value>,
    error_limit: usize,
    response: mpsc::SyncSender<SchemaResult<Vec<String>>>,
}

enum SchemaCompilerState {
    Available(mpsc::SyncSender<SchemaCompilerRequest>),
    Unavailable(String),
}

static SCHEMA_COMPILER: OnceLock<SchemaCompilerState> = OnceLock::new();

/// Compiles one JSON Schema as Draft 2020-12 on AIP's isolated compiler.
///
/// The compiler has a bounded request queue and a dedicated stack. This keeps
/// recursive meta-schema initialization and untrusted schema compilation off
/// async runtime worker stacks while providing deterministic backpressure.
pub fn compile_draft202012(schema: &Value) -> SchemaResult<()> {
    validation_errors_draft202012(schema, None, 0).map(|_| ())
}

/// Returns bounded Draft 2020-12 validation diagnostics for one instance.
///
/// A successful result containing an empty vector means that the instance is
/// valid. Schema compilation failures are returned as [`SchemaError::Compile`].
pub fn validation_errors_draft202012(
    schema: &Value,
    instance: Option<&Value>,
    error_limit: usize,
) -> SchemaResult<Vec<String>> {
    validate_schema_complexity(schema)?;
    let compiler = match schema_compiler() {
        SchemaCompilerState::Available(compiler) => compiler,
        SchemaCompilerState::Unavailable(message) => {
            return Err(SchemaError::Compile(message.clone()));
        }
    };
    let (response, receiver) = mpsc::sync_channel(1);
    compiler
        .send(SchemaCompilerRequest {
            schema: schema.clone(),
            instance: instance.cloned(),
            error_limit: error_limit.min(MAX_VALIDATION_ERRORS),
            response,
        })
        .map_err(|_| SchemaError::Compile("JSON Schema compiler stopped".to_owned()))?;
    receiver
        .recv()
        .map_err(|_| SchemaError::Compile("JSON Schema compiler did not respond".to_owned()))?
}

/// Validates one instance against a Draft 2020-12 schema.
pub fn validate_draft202012(schema: &Value, instance: &Value) -> SchemaResult<()> {
    let errors = validation_errors_draft202012(schema, Some(instance), MAX_VALIDATION_ERRORS)?;
    if errors.is_empty() {
        Ok(())
    } else {
        Err(SchemaError::Validate(errors.join("; ")))
    }
}

fn schema_compiler() -> &'static SchemaCompilerState {
    SCHEMA_COMPILER.get_or_init(|| {
        let (sender, receiver) =
            mpsc::sync_channel::<SchemaCompilerRequest>(JSON_SCHEMA_COMPILER_QUEUE_DEPTH);
        match thread::Builder::new()
            .name("aip-json-schema-compiler".to_owned())
            .stack_size(JSON_SCHEMA_COMPILER_STACK_BYTES)
            .spawn(move || schema_compiler_loop(&receiver))
        {
            Ok(_) => SchemaCompilerState::Available(sender),
            Err(error) => SchemaCompilerState::Unavailable(format!(
                "could not start isolated JSON Schema compiler: {error}"
            )),
        }
    })
}

fn schema_compiler_loop(receiver: &mpsc::Receiver<SchemaCompilerRequest>) {
    while let Ok(request) = receiver.recv() {
        let result = catch_unwind(AssertUnwindSafe(|| compile_and_validate(&request)))
            .unwrap_or_else(|_| {
                Err(SchemaError::Compile(
                    "JSON Schema compiler panicked while processing a schema".to_owned(),
                ))
            });
        let _ = request.response.send(result);
    }
}

fn compile_and_validate(request: &SchemaCompilerRequest) -> SchemaResult<Vec<String>> {
    let validator = jsonschema::draft202012::new(&request.schema)
        .map_err(|error| SchemaError::Compile(error.to_string()))?;
    let Some(instance) = request.instance.as_ref() else {
        return Ok(Vec::new());
    };
    Ok(validator
        .iter_errors(instance)
        .take(request.error_limit)
        .map(|error| error.to_string())
        .collect())
}

fn validate_schema_complexity(schema: &Value) -> SchemaResult<()> {
    let mut pending = vec![(schema, 0_usize)];
    let mut nodes = 0_usize;
    let mut text_bytes = 0_usize;
    while let Some((value, depth)) = pending.pop() {
        nodes = nodes.saturating_add(1);
        if nodes > MAX_JSON_SCHEMA_NODES {
            return Err(SchemaError::Compile(format!(
                "schema exceeds the {MAX_JSON_SCHEMA_NODES}-node safety limit"
            )));
        }
        if depth > MAX_JSON_SCHEMA_DEPTH {
            return Err(SchemaError::Compile(format!(
                "schema exceeds the {MAX_JSON_SCHEMA_DEPTH}-level nesting limit"
            )));
        }
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    text_bytes = text_bytes.saturating_add(key.len());
                    pending.push((child, depth.saturating_add(1)));
                }
            }
            Value::Array(values) => {
                pending.extend(values.iter().map(|child| (child, depth.saturating_add(1))));
            }
            Value::String(value) => text_bytes = text_bytes.saturating_add(value.len()),
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
        if text_bytes > MAX_JSON_SCHEMA_TEXT_BYTES {
            return Err(SchemaError::Compile(format!(
                "schema exceeds the {MAX_JSON_SCHEMA_TEXT_BYTES}-byte text safety limit"
            )));
        }
    }
    Ok(())
}

/// Stable names for schemas maintained by this registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchemaName {
    /// Native envelope schema.
    Envelope,
    /// Manifest schema.
    Manifest,
    /// Action schema.
    Action,
    /// Enterprise capability contract schema.
    CapabilityContract,
    /// Ack schema.
    Ack,
    /// Stream chunk schema.
    StreamChunk,
    /// Action result schema.
    ActionResult,
    /// Action status request schema.
    ActionStatusRequest,
    /// Action status schema.
    ActionStatus,
    /// Action result request schema.
    ActionResultRequest,
    /// Action list request schema.
    ActionListRequest,
    /// Action list schema.
    ActionList,
    /// Action events request schema.
    ActionEventsRequest,
    /// Action events schema.
    ActionEvents,
    /// Approval request schema.
    ApprovalRequest,
    /// Approval decision schema.
    ApprovalDecision,
    /// Approval query request schema.
    ApprovalQueryRequest,
    /// Approval record view schema.
    ApprovalRecordView,
    /// Approval list request schema.
    ApprovalListRequest,
    /// Approval list schema.
    ApprovalList,
    /// Native manifest filter schema.
    ManifestFilter,
    /// Session request schema.
    SessionRequest,
    /// Session view schema.
    SessionView,
    /// Session list request schema.
    SessionListRequest,
    /// Session list schema.
    SessionList,
    /// Session close request schema.
    SessionCloseRequest,
    /// Session resume request schema.
    SessionResumeRequest,
    /// Session resume schema.
    SessionResume,
    /// Identity context schema.
    IdentityContext,
    /// Action transaction context schema.
    TransactionPlan,
    /// First-class transaction request schema.
    TransactionRequest,
    /// First-class transaction result schema.
    TransactionResult,
    /// Transaction query request schema.
    TransactionQueryRequest,
    /// Transaction view schema.
    TransactionView,
    /// Receipt query request schema.
    ReceiptQueryRequest,
    /// Audit query request schema.
    AuditQueryRequest,
    /// Audit query result schema.
    AuditQueryResult,
    /// Resource list request schema.
    ResourceListRequest,
    /// Resource list schema.
    ResourceList,
    /// Resource read request schema.
    ResourceReadRequest,
    /// Resource read result schema.
    ResourceReadResult,
    /// Callback delivery policy schema.
    CallbackDeliveryPolicy,
    /// Callback delivery query request schema.
    CallbackDeliveryQueryRequest,
    /// Callback delivery list request schema.
    CallbackDeliveryListRequest,
    /// Callback delivery record schema.
    CallbackDeliveryRecord,
    /// Callback delivery list schema.
    CallbackDeliveryList,
    /// Delegation request schema.
    DelegationRequest,
    /// Delegation result schema.
    DelegationResult,
    /// Escalation schema.
    Escalation,
    /// Event schema.
    Event,
    /// Global event stream schema.
    EventStream,
    /// Channel message schema.
    ChannelMessage,
}

impl SchemaName {
    /// Returns the canonical file name for this schema.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Envelope => "envelope.schema.json",
            Self::Manifest => "manifest.schema.json",
            Self::Action => "action.schema.json",
            Self::CapabilityContract => "capability_contract.schema.json",
            Self::Ack => "ack.schema.json",
            Self::StreamChunk => "stream_chunk.schema.json",
            Self::ActionResult => "action_result.schema.json",
            Self::ActionStatusRequest => "action_status_request.schema.json",
            Self::ActionStatus => "action_status.schema.json",
            Self::ActionResultRequest => "action_result_request.schema.json",
            Self::ActionListRequest => "action_list_request.schema.json",
            Self::ActionList => "action_list.schema.json",
            Self::ActionEventsRequest => "action_events_request.schema.json",
            Self::ActionEvents => "action_events.schema.json",
            Self::ApprovalRequest => "approval_request.schema.json",
            Self::ApprovalDecision => "approval_decision.schema.json",
            Self::ApprovalQueryRequest => "approval_query_request.schema.json",
            Self::ApprovalRecordView => "approval_record_view.schema.json",
            Self::ApprovalListRequest => "approval_list_request.schema.json",
            Self::ApprovalList => "approval_list.schema.json",
            Self::ManifestFilter => "manifest_filter.schema.json",
            Self::SessionRequest => "session_request.schema.json",
            Self::SessionView => "session_view.schema.json",
            Self::SessionListRequest => "session_list_request.schema.json",
            Self::SessionList => "session_list.schema.json",
            Self::SessionCloseRequest => "session_close_request.schema.json",
            Self::SessionResumeRequest => "session_resume_request.schema.json",
            Self::SessionResume => "session_resume.schema.json",
            Self::IdentityContext => "identity_context.schema.json",
            Self::TransactionPlan => "transaction_plan.schema.json",
            Self::TransactionRequest => "transaction_request.schema.json",
            Self::TransactionResult => "transaction_result.schema.json",
            Self::TransactionQueryRequest => "transaction_query_request.schema.json",
            Self::TransactionView => "transaction_view.schema.json",
            Self::ReceiptQueryRequest => "receipt_query_request.schema.json",
            Self::AuditQueryRequest => "audit_query_request.schema.json",
            Self::AuditQueryResult => "audit_query_result.schema.json",
            Self::ResourceListRequest => "resource_list_request.schema.json",
            Self::ResourceList => "resource_list.schema.json",
            Self::ResourceReadRequest => "resource_read_request.schema.json",
            Self::ResourceReadResult => "resource_read_result.schema.json",
            Self::CallbackDeliveryPolicy => "callback_delivery_policy.schema.json",
            Self::CallbackDeliveryQueryRequest => "callback_delivery_query_request.schema.json",
            Self::CallbackDeliveryListRequest => "callback_delivery_list_request.schema.json",
            Self::CallbackDeliveryRecord => "callback_delivery_record.schema.json",
            Self::CallbackDeliveryList => "callback_delivery_list.schema.json",
            Self::DelegationRequest => "delegation_request.schema.json",
            Self::DelegationResult => "delegation_result.schema.json",
            Self::Escalation => "escalation.schema.json",
            Self::Event => "event.schema.json",
            Self::EventStream => "event_stream.schema.json",
            Self::ChannelMessage => "channel_message.schema.json",
        }
    }
}

/// In-memory registry for AIP JSON Schemas.
#[derive(Clone, Debug, Default)]
pub struct SchemaRegistry;

impl SchemaRegistry {
    /// Creates a registry with the built-in schema set.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns a JSON Schema document by name.
    #[must_use]
    pub fn schema(&self, name: SchemaName) -> Value {
        let generated = match name {
            SchemaName::Envelope => serde_json::to_value(schema_for!(Envelope)),
            SchemaName::Manifest => serde_json::to_value(schema_for!(Manifest)),
            SchemaName::Action => serde_json::to_value(schema_for!(Action)),
            SchemaName::CapabilityContract => serde_json::to_value(schema_for!(CapabilityContract)),
            SchemaName::Ack => serde_json::to_value(schema_for!(Ack)),
            SchemaName::StreamChunk => serde_json::to_value(schema_for!(StreamChunk)),
            SchemaName::ActionResult => serde_json::to_value(schema_for!(ActionResult)),
            SchemaName::ActionStatusRequest => {
                serde_json::to_value(schema_for!(ActionStatusRequest))
            }
            SchemaName::ActionStatus => serde_json::to_value(schema_for!(ActionStatus)),
            SchemaName::ActionResultRequest => {
                serde_json::to_value(schema_for!(ActionResultRequest))
            }
            SchemaName::ActionListRequest => serde_json::to_value(schema_for!(ActionListRequest)),
            SchemaName::ActionList => serde_json::to_value(schema_for!(ActionList)),
            SchemaName::ActionEventsRequest => {
                serde_json::to_value(schema_for!(ActionEventsRequest))
            }
            SchemaName::ActionEvents => serde_json::to_value(schema_for!(ActionEvents)),
            SchemaName::ApprovalRequest => serde_json::to_value(schema_for!(ApprovalRequest)),
            SchemaName::ApprovalDecision => serde_json::to_value(schema_for!(ApprovalDecision)),
            SchemaName::ApprovalQueryRequest => {
                serde_json::to_value(schema_for!(ApprovalQueryRequest))
            }
            SchemaName::ApprovalRecordView => serde_json::to_value(schema_for!(ApprovalRecordView)),
            SchemaName::ApprovalListRequest => {
                serde_json::to_value(schema_for!(ApprovalListRequest))
            }
            SchemaName::ApprovalList => serde_json::to_value(schema_for!(ApprovalList)),
            SchemaName::ManifestFilter => serde_json::to_value(schema_for!(ManifestFilter)),
            SchemaName::SessionRequest => serde_json::to_value(schema_for!(SessionRequest)),
            SchemaName::SessionView => serde_json::to_value(schema_for!(SessionView)),
            SchemaName::SessionListRequest => serde_json::to_value(schema_for!(SessionListRequest)),
            SchemaName::SessionList => serde_json::to_value(schema_for!(SessionList)),
            SchemaName::SessionCloseRequest => {
                serde_json::to_value(schema_for!(SessionCloseRequest))
            }
            SchemaName::SessionResumeRequest => {
                serde_json::to_value(schema_for!(SessionResumeRequest))
            }
            SchemaName::SessionResume => serde_json::to_value(schema_for!(SessionResume)),
            SchemaName::IdentityContext => serde_json::to_value(schema_for!(IdentityContext)),
            SchemaName::TransactionPlan => serde_json::to_value(schema_for!(TransactionPlan)),
            SchemaName::TransactionRequest => serde_json::to_value(schema_for!(TransactionRequest)),
            SchemaName::TransactionResult => serde_json::to_value(schema_for!(TransactionResult)),
            SchemaName::TransactionQueryRequest => {
                serde_json::to_value(schema_for!(TransactionQueryRequest))
            }
            SchemaName::TransactionView => serde_json::to_value(schema_for!(TransactionView)),
            SchemaName::ReceiptQueryRequest => {
                serde_json::to_value(schema_for!(ReceiptQueryRequest))
            }
            SchemaName::AuditQueryRequest => serde_json::to_value(schema_for!(AuditQueryRequest)),
            SchemaName::AuditQueryResult => serde_json::to_value(schema_for!(AuditQueryResult)),
            SchemaName::ResourceListRequest => {
                serde_json::to_value(schema_for!(ResourceListRequest))
            }
            SchemaName::ResourceList => serde_json::to_value(schema_for!(ResourceList)),
            SchemaName::ResourceReadRequest => {
                serde_json::to_value(schema_for!(ResourceReadRequest))
            }
            SchemaName::ResourceReadResult => serde_json::to_value(schema_for!(ResourceReadResult)),
            SchemaName::CallbackDeliveryPolicy => {
                serde_json::to_value(schema_for!(CallbackDeliveryPolicy))
            }
            SchemaName::CallbackDeliveryQueryRequest => {
                serde_json::to_value(schema_for!(CallbackDeliveryQueryRequest))
            }
            SchemaName::CallbackDeliveryListRequest => {
                serde_json::to_value(schema_for!(CallbackDeliveryListRequest))
            }
            SchemaName::CallbackDeliveryRecord => {
                serde_json::to_value(schema_for!(CallbackDeliveryRecord))
            }
            SchemaName::CallbackDeliveryList => {
                serde_json::to_value(schema_for!(CallbackDeliveryList))
            }
            SchemaName::DelegationRequest => serde_json::to_value(schema_for!(DelegationRequest)),
            SchemaName::DelegationResult => serde_json::to_value(schema_for!(DelegationResult)),
            SchemaName::Escalation => serde_json::to_value(schema_for!(Escalation)),
            SchemaName::Event => serde_json::to_value(schema_for!(Event)),
            SchemaName::EventStream => serde_json::to_value(schema_for!(EventStream)),
            SchemaName::ChannelMessage => serde_json::to_value(schema_for!(ChannelMessage)),
        };
        let mut schema = match generated {
            Ok(schema) => schema,
            Err(error) => json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$comment": format!("schema generation failed: {error}"),
                "not": {}
            }),
        };
        annotate_schema(name, &mut schema);
        harden_object_schemas(&mut schema);
        schema
    }

    /// Returns all built-in schemas as `(file_name, schema)` pairs.
    #[must_use]
    pub fn all(&self) -> Vec<(&'static str, Value)> {
        [
            SchemaName::Envelope,
            SchemaName::Manifest,
            SchemaName::Action,
            SchemaName::CapabilityContract,
            SchemaName::Ack,
            SchemaName::StreamChunk,
            SchemaName::ActionResult,
            SchemaName::ActionStatusRequest,
            SchemaName::ActionStatus,
            SchemaName::ActionResultRequest,
            SchemaName::ActionListRequest,
            SchemaName::ActionList,
            SchemaName::ActionEventsRequest,
            SchemaName::ActionEvents,
            SchemaName::ApprovalRequest,
            SchemaName::ApprovalDecision,
            SchemaName::ApprovalQueryRequest,
            SchemaName::ApprovalRecordView,
            SchemaName::ApprovalListRequest,
            SchemaName::ApprovalList,
            SchemaName::ManifestFilter,
            SchemaName::SessionRequest,
            SchemaName::SessionView,
            SchemaName::SessionListRequest,
            SchemaName::SessionList,
            SchemaName::SessionCloseRequest,
            SchemaName::SessionResumeRequest,
            SchemaName::SessionResume,
            SchemaName::IdentityContext,
            SchemaName::TransactionPlan,
            SchemaName::TransactionRequest,
            SchemaName::TransactionResult,
            SchemaName::TransactionQueryRequest,
            SchemaName::TransactionView,
            SchemaName::ReceiptQueryRequest,
            SchemaName::AuditQueryRequest,
            SchemaName::AuditQueryResult,
            SchemaName::ResourceListRequest,
            SchemaName::ResourceList,
            SchemaName::ResourceReadRequest,
            SchemaName::ResourceReadResult,
            SchemaName::CallbackDeliveryPolicy,
            SchemaName::CallbackDeliveryQueryRequest,
            SchemaName::CallbackDeliveryListRequest,
            SchemaName::CallbackDeliveryRecord,
            SchemaName::CallbackDeliveryList,
            SchemaName::DelegationRequest,
            SchemaName::DelegationResult,
            SchemaName::Escalation,
            SchemaName::Event,
            SchemaName::EventStream,
            SchemaName::ChannelMessage,
        ]
        .into_iter()
        .map(|name| (name.file_name(), self.schema(name)))
        .collect()
    }

    /// Validates arbitrary JSON against a named schema.
    pub fn validate_json(&self, name: SchemaName, value: &Value) -> SchemaResult<()> {
        let schema = self.schema(name);
        validate_draft202012(&schema, value)
    }

    /// Validates a typed envelope using both core invariants and JSON Schema.
    pub fn validate_envelope(&self, envelope: &Envelope) -> SchemaResult<()> {
        validate_envelope(envelope)?;
        let value = serde_json::to_value(envelope)?;
        self.validate_json(SchemaName::Envelope, &value)
    }
}

fn annotate_schema(name: SchemaName, schema: &mut Value) {
    if let Some(object) = schema.as_object_mut() {
        object.insert(
            "$id".to_owned(),
            Value::String(format!(
                "https://getaip.org/schemas/aip/{}",
                name.file_name()
            )),
        );
        if matches!(name, SchemaName::Envelope)
            && let Some(properties) = object
                .get_mut("properties")
                .and_then(serde_json::Value::as_object_mut)
            && let Some(version) = properties
                .get_mut("aip_version")
                .and_then(serde_json::Value::as_object_mut)
        {
            version.insert(
                "const".to_owned(),
                Value::String(aip_core::AIP_VERSION.to_owned()),
            );
        }
    }
}

fn harden_object_schemas(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let is_typed_object = object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "object")
                && object.contains_key("properties");
            if is_typed_object && !object.contains_key("additionalProperties") {
                object.insert("additionalProperties".to_owned(), Value::Bool(false));
            }
            for child in object.values_mut() {
                harden_object_schemas(child);
            }
        }
        Value::Array(items) => {
            for child in items {
                harden_object_schemas(child);
            }
        }
        _ => {}
    }
}

/// A canonical schema fixture used by conformance tests and release checks.
#[derive(Clone, Debug, PartialEq)]
pub struct SchemaFixture {
    /// Schema that should validate this fixture.
    pub schema: SchemaName,
    /// Stable fixture label.
    pub name: &'static str,
    /// Fixture JSON value.
    pub value: Value,
}

/// Returns canonical valid fixtures for the native AIP core schema set.
#[must_use]
pub fn golden_fixtures() -> Vec<SchemaFixture> {
    vec![
        SchemaFixture {
            schema: SchemaName::ActionStatusRequest,
            name: "rfc0003_action_status_request",
            value: json!({
                "action_id": "action:rfc0003-status",
                "tenant_id": "tenant-1",
                "include_result": true,
                "include_receipts": true,
                "include_chunks": true,
                "wait_ms": 1000
            }),
        },
        SchemaFixture {
            schema: SchemaName::ActionStatus,
            name: "rfc0003_action_status_running",
            value: json!({
                "action_id": "action:rfc0003-status",
                "capability_id": "cap:rfc0003:triage",
                "session_id": "session:rfc0003",
                "state": "running",
                "queued_state": "running",
                "updated_at": "2026-07-09T00:00:00Z",
                "chunks": [],
                "links": {
                    "events": "/aip/v1/actions/action:rfc0003-status/events"
                }
            }),
        },
        SchemaFixture {
            schema: SchemaName::ActionResultRequest,
            name: "rfc0003_action_result_request",
            value: json!({
                "action_id": "action:rfc0003-status",
                "tenant_id": "tenant-1",
                "wait_ms": 1000,
                "include_receipt": true,
                "include_terminal_events": true
            }),
        },
        SchemaFixture {
            schema: SchemaName::ActionListRequest,
            name: "rfc0003_action_list_request",
            value: json!({
                "state": "running",
                "capability_id": "cap:rfc0003:triage",
                "session_id": "session:rfc0003",
                "principal_id": "agent:rfc0003",
                "tenant_id": "tenant-1",
                "cursor": "offset:0",
                "limit": 50,
                "include_results": false,
                "include_receipts": false
            }),
        },
        SchemaFixture {
            schema: SchemaName::ActionList,
            name: "rfc0003_action_list",
            value: json!({
                "actions": [],
                "total_size": 0,
                "cursor": "offset:50"
            }),
        },
        SchemaFixture {
            schema: SchemaName::ActionEventsRequest,
            name: "rfc0003_action_events_request",
            value: json!({
                "action_id": "action:rfc0003-status",
                "tenant_id": "tenant-1",
                "cursor": "evt_cursor_1",
                "limit": 100,
                "kinds": ["aip.action.result", "aip.stream.chunk"],
                "include_chunks": true,
                "follow": true
            }),
        },
        SchemaFixture {
            schema: SchemaName::ActionEvents,
            name: "rfc0003_action_events",
            value: json!({
                "action_id": "action:rfc0003-status",
                "events": [],
                "chunks": [],
                "cursor": "evt_cursor_2",
                "terminal": false
            }),
        },
        SchemaFixture {
            schema: SchemaName::EventStream,
            name: "rfc0003_event_stream",
            value: json!({
                "events": [{
                    "id": "event:rfc0003-1",
                    "kind": "aip.discovery.capability_registered",
                    "occurred_at": "2026-07-09T00:00:00Z",
                    "session_id": "session:rfc0003",
                    "action_id": "action:rfc0003-status",
                    "actor": { "id": "agent:rfc0003", "kind": "agent" },
                    "data": { "capability_id": "cap:rfc0003:triage" }
                }],
                "next_cursor": "evt_cursor_2"
            }),
        },
        SchemaFixture {
            schema: SchemaName::SessionRequest,
            name: "rfc0003_session_request",
            value: json!({ "session_id": "session:rfc0003" }),
        },
        SchemaFixture {
            schema: SchemaName::SessionListRequest,
            name: "rfc0003_session_list_request",
            value: json!({
                "principal_id": "agent:rfc0003",
                "status": "active",
                "cursor": "offset:0",
                "limit": 25
            }),
        },
        SchemaFixture {
            schema: SchemaName::SessionCloseRequest,
            name: "rfc0003_session_close_request",
            value: json!({
                "session_id": "session:rfc0003",
                "reason": "operator requested close"
            }),
        },
        SchemaFixture {
            schema: SchemaName::SessionResumeRequest,
            name: "rfc0003_session_resume_request",
            value: json!({
                "session_id": "session:rfc0003",
                "resume_token": "resume-token",
                "last_event_cursor": "evt_cursor_1"
            }),
        },
        SchemaFixture {
            schema: SchemaName::ApprovalQueryRequest,
            name: "rfc0003_approval_query_request",
            value: json!({
                "approval_id": "approval:rfc0003",
                "tenant_id": "tenant-1",
                "include_action_status": true,
                "include_receipts": true
            }),
        },
        SchemaFixture {
            schema: SchemaName::TransactionQueryRequest,
            name: "rfc0003_transaction_query_request",
            value: json!({
                "action_id": "action:rfc0003-status",
                "tenant_id": "tenant-1",
                "include_result": true,
                "include_receipts": true
            }),
        },
        SchemaFixture {
            schema: SchemaName::ReceiptQueryRequest,
            name: "rfc0003_receipt_query_request",
            value: json!({ "chain_id": "receipt-chain:rfc0003" }),
        },
        SchemaFixture {
            schema: SchemaName::AuditQueryRequest,
            name: "rfc0003_audit_query_request",
            value: json!({
                "action_id": "action:rfc0003-status",
                "session_id": "session:rfc0003",
                "principal_id": "agent:rfc0003",
                "tenant_id": "tenant-1",
                "from": "2026-07-09T00:00:00Z",
                "to": "2026-07-09T01:00:00Z",
                "cursor": "offset:0",
                "limit": 100,
                "include_receipts": true,
                "export": true
            }),
        },
        SchemaFixture {
            schema: SchemaName::AuditQueryResult,
            name: "rfc0003_audit_query_result",
            value: json!({
                "events": [],
                "receipt_chains": [],
                "cursor": "offset:100"
            }),
        },
        SchemaFixture {
            schema: SchemaName::ResourceListRequest,
            name: "rfc0003_resource_list_request",
            value: json!({
                "capability_id": "cap:rfc0003:triage",
                "kind": "case",
                "tenant_id": "tenant-1",
                "cursor": "offset:0",
                "limit": 50
            }),
        },
        SchemaFixture {
            schema: SchemaName::ResourceList,
            name: "rfc0003_resource_list",
            value: json!({
                "resources": [{
                    "id": "resource:rfc0003-case",
                    "name": "Case C-1001",
                    "kind": "case",
                    "capability_id": "cap:rfc0003:triage",
                    "mime_type": "application/json",
                    "tenant_id": "tenant-1",
                    "expires_at": "2026-07-10T00:00:00Z"
                }],
                "cursor": "offset:1"
            }),
        },
        SchemaFixture {
            schema: SchemaName::ResourceReadRequest,
            name: "rfc0003_resource_read_request",
            value: json!({
                "resource_id": "resource:rfc0003-case",
                "tenant_id": "tenant-1",
                "version": "v1",
                "accept": ["application/json"]
            }),
        },
        SchemaFixture {
            schema: SchemaName::ResourceReadResult,
            name: "rfc0003_resource_read_result",
            value: json!({
                "resource": {
                    "id": "resource:rfc0003-case",
                    "name": "Case C-1001",
                    "kind": "case",
                    "capability_id": "cap:rfc0003:triage",
                    "mime_type": "application/json",
                    "tenant_id": "tenant-1"
                },
                "content": [],
                "etag": "W/\"rfc0003\"",
                "expires_at": "2026-07-10T00:00:00Z"
            }),
        },
        SchemaFixture {
            schema: SchemaName::CallbackDeliveryQueryRequest,
            name: "rfc0003_callback_delivery_query_request",
            value: json!({
                "delivery_id": "cb:rfc0003",
                "tenant_id": "tenant-1",
                "include_receipts": true
            }),
        },
        SchemaFixture {
            schema: SchemaName::CallbackDeliveryListRequest,
            name: "rfc0003_callback_delivery_list_request",
            value: json!({
                "action_id": "action:rfc0003-status",
                "status": "pending",
                "profile": "aip.callback.http",
                "target": "https://callback.example/aip/v1/messages",
                "tenant_id": "tenant-1",
                "cursor": "offset:0",
                "limit": 50,
                "include_receipts": true
            }),
        },
        SchemaFixture {
            schema: SchemaName::CallbackDeliveryRecord,
            name: "rfc0003_callback_delivery_record",
            value: json!({
                "delivery_id": "cb:rfc0003",
                "policy": {
                    "delivery_id": "cb:rfc0003",
                    "target": {
                        "profile": "aip.callback.http",
                        "target": "https://callback.example/aip/v1/messages"
                    },
                    "max_attempts": 3,
                    "timeout_ms": 5000,
                    "retry_backoff_ms": [250, 1000],
                    "idempotency_key": "callback:cb:rfc0003",
                    "sign_payload": false,
                    "terminal_only": true
                },
                "message_id": "msg:rfc0003-callback",
                "message_type": "aip.core.v1.action_result",
                "action_id": "action:rfc0003-status",
                "session_id": "session:rfc0003",
                "tenant_id": "tenant-1",
                "status": "pending",
                "attempts": [{
                    "attempt": 1,
                    "started_at": "2026-07-09T00:00:00Z",
                    "finished_at": "2026-07-09T00:00:01Z",
                    "error": "temporary network failure"
                }],
                "next_attempt_at": "2026-07-09T00:00:02Z",
                "last_error": "temporary network failure",
                "created_at": "2026-07-09T00:00:00Z",
                "updated_at": "2026-07-09T00:00:01Z"
            }),
        },
        SchemaFixture {
            schema: SchemaName::CallbackDeliveryList,
            name: "rfc0003_callback_delivery_list",
            value: json!({
                "deliveries": [],
                "cursor": "offset:1"
            }),
        },
        SchemaFixture {
            schema: SchemaName::CapabilityContract,
            name: "enterprise_capability_contract",
            value: json!({
                "side_effects": ["financial", "write"],
                "idempotency": {
                    "requirement": "required",
                    "collision_behavior": "revalidate_input_hash",
                    "key_scope": "tenant",
                    "ttl_ms": 86400000
                },
                "execution": {
                    "supports_sync": true,
                    "supports_async": true,
                    "supports_streaming": false,
                    "supports_cancel": true,
                    "supports_retry": true,
                    "expected_completion": "any",
                    "retry_safety": "safe_with_idempotency_key"
                },
                "data": {
                    "sensitivity": "restricted",
                    "contains_pii": true,
                    "redaction_required": true
                },
                "credentials": {
                    "required": true,
                    "accepted_issuers": ["vault:primary"],
                    "required_scopes": ["refund:write"],
                    "allow_oauth_refresh": false
                },
                "approval": {
                    "required": true,
                    "approver_selector": { "type": "tenant_policy" },
                    "evidence_requirements": ["reason", "input_snapshot", "policy_decision"]
                },
                "transaction": {
                    "supported_modes": ["execute", "plan", "commit", "compensate"],
                    "requires_plan_before_commit": true,
                    "dry_run_fidelity": "policy_and_schema"
                },
                "compensation": {
                    "mode": "supported",
                    "compensation_capability_id": "cap:refund-compensate",
                    "compensation_window_ms": 86400000,
                    "requires_approval": true
                }
            }),
        },
        SchemaFixture {
            schema: SchemaName::IdentityContext,
            name: "tenant_credential_identity",
            value: json!({
                "tenant": { "id": "tenant-1", "system": "aip" },
                "external_account": { "id": "account-1", "system": "salesforce" },
                "credential_ref": {
                    "id": "credential-1",
                    "issuer": "vault:primary",
                    "scopes": ["refund:write"]
                },
                "oauth": {
                    "issuer": "https://auth.example",
                    "client_id": "aip-client",
                    "scopes": ["refund:write"],
                    "refresh_available": true
                }
            }),
        },
        SchemaFixture {
            schema: SchemaName::TransactionPlan,
            name: "case_update_transaction_plan",
            value: json!({
                "plan_id": "plan:case-update:C-1",
                "transaction_id": "txn:plan-1",
                "action_id": "action:plan-1",
                "capability_id": "cap:case-update",
                "transaction": {
                    "mode": "plan",
                    "transaction_id": "txn:plan-1",
                    "plan_id": "plan:case-update:C-1"
                },
                "planned_by": { "id": "agent:planner", "kind": "agent" },
                "input_hash": "sha256:fixture",
                "input_snapshot": {
                    "redacted": false,
                    "hash": "sha256:fixture",
                    "value": { "case_id": "C-1", "status": "resolved" }
                },
                "predicted_side_effects": ["write"],
                "approval_required": false,
                "dry_run_fidelity": "policy_and_schema",
                "created_at": "2026-07-09T00:00:00Z"
            }),
        },
        SchemaFixture {
            schema: SchemaName::TransactionRequest,
            name: "transaction_request_plan",
            value: json!({
                "transaction_id": "txn:plan-1",
                "action": {
                    "id": "action:plan-1",
                    "capability_id": "cap:case-update",
                    "input": { "case_id": "C-1", "status": "resolved" },
                    "idempotency_key": "tenant-1:case-update:C-1",
                    "transaction": {
                        "mode": "plan",
                        "transaction_id": "txn:plan-1"
                    }
                },
                "requested_by": { "id": "agent:planner", "kind": "agent" },
                "reason": "plan before commit"
            }),
        },
        SchemaFixture {
            schema: SchemaName::TransactionResult,
            name: "transaction_result_planned",
            value: json!({
                "transaction_id": "txn:plan-1",
                "action_id": "action:plan-1",
                "capability_id": "cap:case-update",
                "transaction": {
                    "mode": "plan",
                    "transaction_id": "txn:plan-1",
                    "plan_id": "plan:case-update:C-1"
                },
                "status": "planned",
                "plan": {
                    "plan_id": "plan:case-update:C-1",
                    "transaction_id": "txn:plan-1",
                    "action_id": "action:plan-1",
                    "capability_id": "cap:case-update",
                    "transaction": {
                        "mode": "plan",
                        "transaction_id": "txn:plan-1",
                        "plan_id": "plan:case-update:C-1"
                    },
                    "planned_by": { "id": "agent:planner", "kind": "agent" },
                    "input_hash": "sha256:fixture",
                    "input_snapshot": {
                        "redacted": false,
                        "hash": "sha256:fixture",
                        "value": { "case_id": "C-1", "status": "resolved" }
                    },
                    "predicted_side_effects": ["write"],
                    "approval_required": false,
                    "dry_run_fidelity": "policy_and_schema",
                    "created_at": "2026-07-09T00:00:00Z"
                },
                "result": {
                    "action_id": "action:plan-1",
                    "status": "completed",
                    "output": { "transaction": "plan" }
                }
            }),
        },
        SchemaFixture {
            schema: SchemaName::ChannelMessage,
            name: "channel_message_with_identity",
            value: json!({
                "conversation": {
                    "id": "conv:test-1",
                    "channel": { "system": "chat" },
                    "status": "open"
                },
                "identity": {
                    "tenant": { "id": "tenant-1" },
                    "credential_ref": {
                        "id": "credential-1",
                        "issuer": "vault:primary"
                    }
                },
                "message": { "id": "message-1" },
                "sender": { "id": "contact:test", "kind": "contact" },
                "parts": [{ "type": "text", "text": "hello" }]
            }),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_JSON_SCHEMA_DEPTH, SchemaName, SchemaRegistry, compile_draft202012, golden_fixtures,
        validation_errors_draft202012,
    };
    use aip_core::{Envelope, ManifestRequest, MessageBody};
    use serde_json::json;

    #[test]
    fn validates_generated_envelope() {
        let registry = SchemaRegistry::new();
        let envelope = Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
            profiles: Vec::new(),
            filter: None,
        }));
        registry
            .validate_envelope(&envelope)
            .expect("valid envelope");
    }

    #[test]
    fn exposes_all_schema_documents() {
        let registry = SchemaRegistry::new();
        assert_eq!(registry.all().len(), 52);
        assert_eq!(SchemaName::Envelope.file_name(), "envelope.schema.json");
        assert_eq!(
            SchemaName::ActionStatusRequest.file_name(),
            "action_status_request.schema.json"
        );
    }

    #[test]
    fn validates_enterprise_golden_fixtures() {
        let registry = SchemaRegistry::new();
        for fixture in golden_fixtures() {
            registry
                .validate_json(fixture.schema, &fixture.value)
                .unwrap_or_else(|error| panic!("{} failed validation: {error}", fixture.name));
        }
    }

    #[test]
    fn isolated_compiler_is_safe_from_a_small_caller_stack() {
        std::thread::Builder::new()
            .name("small-schema-caller".to_owned())
            .stack_size(256 * 1024)
            .spawn(|| {
                let schema = json!({
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "required": ["id"],
                    "properties": { "id": { "type": "string" } }
                });
                compile_draft202012(&schema).expect("schema compilation");
                let errors = validation_errors_draft202012(&schema, Some(&json!({ "id": 42 })), 16)
                    .expect("instance validation");
                assert_eq!(errors.len(), 1);
            })
            .expect("small caller thread")
            .join()
            .expect("small caller must not overflow");
    }

    #[test]
    fn compiler_rejects_schema_beyond_protocol_complexity_limit() {
        let mut schema = json!({ "type": "string" });
        for _ in 0..=MAX_JSON_SCHEMA_DEPTH {
            schema = json!({ "anyOf": [schema] });
        }
        let error = compile_draft202012(&schema).expect_err("excessive nesting must fail closed");
        assert!(error.to_string().contains("nesting limit"));
    }
}
