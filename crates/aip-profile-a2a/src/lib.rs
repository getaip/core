//! A2A compatibility profile for AIP.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_core::{
    Action, ActionId, ActionLifecycleState, ActionMode, ActionResult, ActionResultStatus,
    ActionStatus, Capability, CapabilityId, CapabilityKind, Manifest, MessagePart, Principal,
    PrincipalId, PrincipalKind, ProfileId, StreamChunk,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use thiserror::Error;

/// A2A compatibility profile id.
pub const PROFILE_ID: &str = "aip.a2a.compat.v1";

/// Current A2A JSON-RPC operation names plus accepted v0.3 aliases.
pub const CURRENT_METHODS: &[&str] = &[
    "SendMessage",
    "SendStreamingMessage",
    "GetTask",
    "ListTasks",
    "CancelTask",
    "SubscribeToTask",
    "CreateTaskPushNotificationConfig",
    "GetTaskPushNotificationConfig",
    "ListTaskPushNotificationConfigs",
    "DeleteTaskPushNotificationConfig",
    "GetExtendedAgentCard",
];

fn default_agent_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// A2A 1.0 Agent Card representation with compatibility-only legacy fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentCard {
    /// Agent id.
    #[serde(skip_serializing, default)]
    pub id: String,
    /// Agent name.
    pub name: String,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional service-provider information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<A2aAgentProvider>,
    /// Optional public documentation URL.
    #[serde(
        rename = "documentationUrl",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub documentation_url: Option<String>,
    /// Optional public icon URL.
    #[serde(rename = "iconUrl", default, skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    /// Advertised skills.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<A2aSkill>,
    /// Endpoint URL.
    #[serde(skip_serializing, default)]
    pub url: Option<String>,
    /// Ordered A2A v1 interfaces; the first interface is preferred.
    #[serde(
        rename = "supportedInterfaces",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub supported_interfaces: Vec<A2aAgentInterface>,
    /// Agent implementation version.
    #[serde(default = "default_agent_version")]
    pub version: String,
    /// Optional A2A feature declarations.
    #[serde(default)]
    pub capabilities: A2aAgentCapabilities,
    /// Supported input MIME modes.
    #[serde(
        rename = "defaultInputModes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub default_input_modes: Vec<String>,
    /// Supported output MIME modes.
    #[serde(
        rename = "defaultOutputModes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub default_output_modes: Vec<String>,
    /// Named security schemes.
    #[serde(
        rename = "securitySchemes",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub security_schemes: BTreeMap<String, A2aSecurityScheme>,
    /// Security requirements.
    #[serde(
        rename = "securityRequirements",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub security: Vec<Value>,
    /// JWS signatures over the Agent Card.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<A2aAgentCardSignature>,
    /// Whether authenticated clients can fetch an extended card.
    #[serde(skip_serializing, default)]
    pub supports_authenticated_extended_card: bool,
}

/// One A2A v1 transport interface advertised by an Agent Card.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aAgentInterface {
    /// Absolute endpoint URL.
    pub url: String,
    /// Protocol binding such as `JSONRPC`, `GRPC`, or `HTTP+JSON`.
    #[serde(rename = "protocolBinding")]
    pub protocol_binding: String,
    /// Optional tenant routing value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// A2A protocol version exposed by this interface.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
}

/// A2A Agent Card provider metadata.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aAgentProvider {
    /// Provider website or documentation URL.
    pub url: String,
    /// Provider organization name.
    pub organization: String,
}

/// Optional A2A v1 feature declarations.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct A2aAgentCapabilities {
    /// Streaming message and task subscription support.
    #[serde(default)]
    pub streaming: bool,
    /// Push notification configuration support.
    #[serde(rename = "pushNotifications", default)]
    pub push_notifications: bool,
    /// Authenticated extended Agent Card support.
    #[serde(rename = "extendedAgentCard", default)]
    pub extended_agent_card: bool,
    /// Declared protocol extensions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<A2aAgentExtension>,
}

/// Declared A2A protocol extension.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aAgentExtension {
    /// Globally unique extension URI.
    pub uri: String,
    /// Human-readable usage description.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Whether clients must understand the extension before invoking the agent.
    #[serde(default)]
    pub required: bool,
    /// Extension-specific parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// JWS signature fields defined by the A2A Agent Card model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aAgentCardSignature {
    /// Base64url protected JWS header.
    pub protected: String,
    /// Base64url signature bytes.
    pub signature: String,
    /// Optional unprotected JWS header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Value>,
}

/// A2A skill representation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aSkill {
    /// Skill id.
    pub id: String,
    /// Skill name.
    pub name: String,
    /// Skill description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Search and routing tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Example user prompts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,
    /// Skill-specific input media types.
    #[serde(rename = "inputModes", default, skip_serializing_if = "Vec::is_empty")]
    pub input_modes: Vec<String>,
    /// Skill-specific output media types.
    #[serde(rename = "outputModes", default, skip_serializing_if = "Vec::is_empty")]
    pub output_modes: Vec<String>,
    /// Security requirements that override the Agent Card defaults.
    #[serde(
        rename = "securityRequirements",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub security_requirements: Vec<Value>,
    /// AIP-only schema retained when converting back from an AIP manifest.
    #[serde(skip_serializing, default)]
    pub input_schema: Option<Value>,
}

/// A2A v1 security-scheme union using its ProtoJSON representation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum A2aSecurityScheme {
    /// HTTP authentication such as Bearer.
    Http {
        /// HTTP authentication descriptor.
        #[serde(rename = "httpAuthSecurityScheme")]
        http_auth_security_scheme: A2aHttpAuthSecurityScheme,
    },
    /// API-key authentication.
    ApiKey {
        /// API-key descriptor.
        #[serde(rename = "apiKeySecurityScheme")]
        api_key_security_scheme: A2aApiKeySecurityScheme,
    },
    /// OAuth 2.0 authentication.
    OAuth2 {
        /// OAuth 2.0 descriptor.
        #[serde(rename = "oauth2SecurityScheme")]
        oauth2_security_scheme: A2aOAuth2SecurityScheme,
    },
    /// OpenID Connect authentication.
    OpenIdConnect {
        /// OpenID Connect descriptor.
        #[serde(rename = "openIdConnectSecurityScheme")]
        open_id_connect_security_scheme: A2aOpenIdConnectSecurityScheme,
    },
    /// Mutual TLS authentication.
    MutualTls {
        /// Mutual TLS descriptor.
        #[serde(rename = "mtlsSecurityScheme")]
        mtls_security_scheme: A2aMutualTlsSecurityScheme,
    },
    /// Extension security scheme retained without interpretation.
    Other(Value),
}

/// A2A HTTP authentication scheme.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aHttpAuthSecurityScheme {
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// IANA HTTP authentication scheme, for example `Bearer`.
    pub scheme: String,
    /// Optional token-format hint.
    #[serde(
        rename = "bearerFormat",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub bearer_format: Option<String>,
}

/// A2A API-key security scheme.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aApiKeySecurityScheme {
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Key location: `header`, `query`, or `cookie`.
    pub location: String,
    /// Header, query, or cookie parameter name.
    pub name: String,
}

/// A2A OAuth 2.0 security scheme.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aOAuth2SecurityScheme {
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// One supported OAuth flow in ProtoJSON form.
    pub flows: Value,
    /// RFC 8414 authorization-server metadata URL.
    #[serde(
        rename = "oauth2MetadataUrl",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub oauth2_metadata_url: Option<String>,
}

/// A2A OpenID Connect security scheme.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aOpenIdConnectSecurityScheme {
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// OpenID Connect discovery URL.
    #[serde(rename = "openIdConnectUrl")]
    pub open_id_connect_url: String,
}

/// A2A mutual-TLS security scheme.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aMutualTlsSecurityScheme {
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A2A task representation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aTask {
    /// Task id.
    pub id: String,
    /// Context containing this task.
    #[serde(rename = "contextId", default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Target skill id.
    #[serde(skip_serializing, default)]
    pub skill_id: String,
    /// Task input.
    #[serde(skip_serializing, default)]
    pub input: Value,
    /// Current task state.
    pub status: A2aTaskStatus,
    /// Produced artifacts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<A2aArtifact>,
    /// Durable task history projected from native AIP action events or chunks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<A2aMessage>,
    /// Vendor/profile metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// A2A task state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum A2aTaskState {
    /// Task state is not known.
    #[serde(rename = "TASK_STATE_UNSPECIFIED", alias = "unspecified")]
    Unspecified,
    /// Task submitted.
    #[serde(rename = "TASK_STATE_SUBMITTED", alias = "submitted")]
    Submitted,
    /// Task is running.
    #[serde(rename = "TASK_STATE_WORKING", alias = "working")]
    Working,
    /// Task requires input.
    #[serde(rename = "TASK_STATE_INPUT_REQUIRED", alias = "input_required")]
    InputRequired,
    /// Task completed.
    #[serde(rename = "TASK_STATE_COMPLETED", alias = "completed")]
    Completed,
    /// Task failed.
    #[serde(rename = "TASK_STATE_FAILED", alias = "failed")]
    Failed,
    /// Task cancelled.
    #[serde(
        rename = "TASK_STATE_CANCELED",
        alias = "cancelled",
        alias = "canceled"
    )]
    Cancelled,
    /// Agent rejected the task.
    #[serde(rename = "TASK_STATE_REJECTED", alias = "rejected")]
    Rejected,
    /// Authentication is required before work can continue.
    #[serde(rename = "TASK_STATE_AUTH_REQUIRED", alias = "auth_required")]
    AuthRequired,
}

/// A2A task status wrapper.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aTaskStatus {
    /// Task state.
    pub state: A2aTaskState,
    /// Optional status message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<A2aMessage>,
    /// RFC 3339 status timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// A2A streaming task-status update.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aTaskStatusUpdateEvent {
    /// Task id.
    #[serde(rename = "taskId")]
    pub task_id: String,
    /// Context id.
    #[serde(rename = "contextId")]
    pub context_id: String,
    /// New task status.
    pub status: A2aTaskStatus,
    /// Optional event metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// A2A streaming artifact update.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aTaskArtifactUpdateEvent {
    /// Task id.
    #[serde(rename = "taskId")]
    pub task_id: String,
    /// Context id.
    #[serde(rename = "contextId")]
    pub context_id: String,
    /// Artifact delta.
    pub artifact: A2aArtifact,
    /// Append to an artifact with the same id.
    #[serde(default)]
    pub append: bool,
    /// This is the last artifact chunk.
    #[serde(rename = "lastChunk", default)]
    pub last_chunk: bool,
    /// Optional event metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// A2A message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aMessage {
    /// Sender-generated message id.
    #[serde(rename = "messageId")]
    pub message_id: String,
    /// Conversation context id.
    #[serde(rename = "contextId", default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Associated task id.
    #[serde(rename = "taskId", default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// Message role.
    pub role: A2aRole,
    /// Message parts.
    pub parts: Vec<A2aPart>,
    /// Message metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// Extension URIs present in this message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    /// Referenced task ids.
    #[serde(
        rename = "referenceTaskIds",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub reference_task_ids: Vec<String>,
}

/// A2A message role using the canonical ProtoJSON enum representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum A2aRole {
    /// Role was not specified.
    #[serde(rename = "ROLE_UNSPECIFIED", alias = "unspecified")]
    Unspecified,
    /// Message originated from the calling client.
    #[serde(rename = "ROLE_USER", alias = "user")]
    User,
    /// Message originated from the serving agent.
    #[serde(rename = "ROLE_AGENT", alias = "agent")]
    Agent,
}

/// A2A content part.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aPart {
    /// Exactly one ProtoJSON content field.
    #[serde(flatten)]
    pub content: A2aPartContent,
    /// Optional part metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// Optional file name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// MIME media type for the content.
    #[serde(rename = "mediaType", default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

/// A2A part content union.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum A2aPartContent {
    /// Text content.
    Text {
        /// Unicode text value.
        text: String,
    },
    /// Base64-encoded raw bytes.
    Raw {
        /// Base64-encoded byte sequence.
        raw: String,
    },
    /// URL-referenced file content.
    Url {
        /// Absolute or application-defined content URL.
        url: String,
    },
    /// Structured JSON content.
    Data {
        /// Arbitrary ProtoJSON value.
        data: Value,
    },
}

impl A2aPart {
    /// Creates a text part.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: A2aPartContent::Text { text: text.into() },
            metadata: None,
            filename: None,
            media_type: Some("text/plain".to_owned()),
        }
    }

    /// Creates a structured-data part.
    #[must_use]
    pub fn data(data: Value) -> Self {
        Self {
            content: A2aPartContent::Data { data },
            metadata: None,
            filename: None,
            media_type: Some("application/json".to_owned()),
        }
    }
}

/// A2A artifact.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aArtifact {
    /// Artifact id.
    pub artifact_id: String,
    /// Artifact name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional artifact description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Artifact parts.
    pub parts: Vec<A2aPart>,
    /// Artifact metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// Extension URIs present in this artifact.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
}

/// Current A2A `message/send` and `message/stream` configuration.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct A2aSendMessageConfiguration {
    /// Accepted response media types.
    #[serde(
        rename = "acceptedOutputModes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub accepted_output_modes: Vec<String>,
    /// Optional push configuration requested with the message.
    #[serde(
        rename = "taskPushNotificationConfig",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub task_push_notification_config: Option<A2aTaskPushConfig>,
    /// Maximum history messages requested in the response.
    #[serde(
        rename = "historyLength",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub history_length: Option<usize>,
    /// Return after task creation rather than waiting for completion.
    #[serde(rename = "returnImmediately", default)]
    pub return_immediately: bool,
}

/// Current A2A `message/send` or `message/stream` parameters.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aSendMessageParams {
    /// Optional interface tenant routing value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Message to deliver.
    pub message: A2aMessage,
    /// Send behavior.
    #[serde(default)]
    pub configuration: A2aSendMessageConfiguration,
    /// Extension/profile metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Legacy v0.3 task-send parameters accepted as input compatibility aliases.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aTaskSendParams {
    /// Optional client supplied task id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Target skill id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_id: Option<String>,
    /// Target AIP capability id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    /// User message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<A2aMessage>,
    /// Direct JSON input for non-message callers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
    /// Metadata preserved by the AIP profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// A2A task id parameter used by get/cancel/config methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aTaskIdParams {
    /// Task id.
    pub id: String,
    /// Optional maximum number of history messages to return.
    #[serde(
        default,
        rename = "historyLength",
        alias = "history_length",
        skip_serializing_if = "Option::is_none"
    )]
    pub history_length: Option<usize>,
}

/// Current A2A task-list filters and pagination parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aTaskListParams {
    /// Optional interface tenant routing value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Conversation context filter.
    #[serde(rename = "contextId", default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Task-state filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<A2aTaskState>,
    /// Page size in the inclusive range 1 through 100.
    #[serde(rename = "pageSize", default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<usize>,
    /// Opaque continuation token returned by the preceding page.
    #[serde(rename = "pageToken", default, skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
    /// Maximum history messages included per task.
    #[serde(
        rename = "historyLength",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub history_length: Option<usize>,
    /// RFC 3339 lower bound for the status update timestamp.
    #[serde(
        rename = "statusTimestampAfter",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub status_timestamp_after: Option<String>,
    /// Include task artifacts in list entries.
    #[serde(rename = "includeArtifacts", default)]
    pub include_artifacts: bool,
}

/// Current A2A paginated task-list response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aTaskListResponse {
    /// Tasks in this page.
    pub tasks: Vec<A2aTask>,
    /// Opaque next-page token, or an empty string at the end.
    #[serde(rename = "nextPageToken")]
    pub next_page_token: String,
    /// Effective page size.
    #[serde(rename = "pageSize")]
    pub page_size: usize,
    /// Number of matching tasks before pagination.
    #[serde(rename = "totalSize")]
    pub total_size: usize,
}

/// A2A push notification config.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aPushNotificationConfig {
    /// Callback URL.
    pub url: String,
    /// Optional authentication descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<A2aAuthenticationInfo>,
    /// Optional opaque token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// A2A task push-notification config wrapper.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aTaskPushNotificationConfig {
    /// Task id.
    pub id: String,
    /// Push notification configuration.
    pub push_notification_config: A2aPushNotificationConfig,
}

/// Current A2A task push-notification resource.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aTaskPushConfig {
    /// Optional interface tenant routing value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Stable configuration id.
    pub id: String,
    /// Parent task id.
    #[serde(rename = "taskId")]
    pub task_id: String,
    /// HTTPS callback URL.
    pub url: String,
    /// Optional opaque verification token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Optional HTTP authentication descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<A2aAuthenticationInfo>,
}

/// Authentication information used by an A2A push-notification callback.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aAuthenticationInfo {
    /// IANA HTTP authentication scheme, such as `Bearer` or `Basic`.
    pub scheme: String,
    /// Credentials rendered after the scheme in the `Authorization` header.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credentials: String,
}

/// Selector used by push-config get and delete operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aPushConfigSelector {
    /// Optional interface tenant routing value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Parent task id.
    #[serde(rename = "taskId")]
    pub task_id: String,
    /// Configuration id.
    pub id: String,
}

/// Parameters for listing task push-notification resources.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aPushConfigListParams {
    /// Optional interface tenant routing value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Parent task id.
    #[serde(rename = "taskId")]
    pub task_id: String,
    /// Page size, capped by the server.
    #[serde(rename = "pageSize", default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<usize>,
    /// Opaque continuation token.
    #[serde(rename = "pageToken", default, skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
}

/// Current A2A paginated push-notification configuration response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aPushConfigListResponse {
    /// Configurations in this page.
    pub configs: Vec<A2aTaskPushConfig>,
    /// Opaque next-page token, or an empty string at the end.
    #[serde(rename = "nextPageToken")]
    pub next_page_token: String,
}

/// A2A JSON-RPC request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aJsonRpcRequest {
    /// JSON-RPC version.
    pub jsonrpc: String,
    /// Request id.
    pub id: Value,
    /// Method name.
    pub method: String,
    /// Method params.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A2A JSON-RPC response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aJsonRpcResponse {
    /// JSON-RPC version.
    pub jsonrpc: String,
    /// Request id.
    pub id: Value,
    /// Result payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<A2aJsonRpcError>,
}

/// A2A JSON-RPC error.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct A2aJsonRpcError {
    /// Error code.
    pub code: i64,
    /// Error message.
    pub message: String,
    /// Error data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A2A mapping error.
#[derive(Debug, Error)]
pub enum A2aProfileError {
    /// Identifier mapping failed.
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    /// Required params are missing.
    #[error("missing params")]
    MissingParams,
    /// Required field is missing.
    #[error("missing field `{0}`")]
    MissingField(&'static str),
    /// Unsupported method.
    #[error("unsupported A2A method `{0}`")]
    UnsupportedMethod(String),
    /// Durable profile-state operation failed.
    #[error("A2A profile storage failed: {0}")]
    Storage(String),
    /// A2A semantic validation failed.
    #[error("invalid A2A message: {0}")]
    InvalidMessage(String),
}

/// Maps an A2A Agent Card into an AIP manifest.
pub fn manifest_from_agent_card(card: AgentCard) -> Result<Manifest, A2aProfileError> {
    validate_agent_card(&card)?;
    let capabilities = card
        .skills
        .into_iter()
        .map(capability_from_skill)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Manifest {
        manifest_version: "aip-manifest/v1".to_owned(),
        agent: Principal::new(
            PrincipalId::parse(format!(
                "agent:a2a:{}",
                if card.id.is_empty() {
                    &card.name
                } else {
                    &card.id
                }
            ))
            .map_err(|error| A2aProfileError::InvalidIdentifier(error.to_string()))?,
            PrincipalKind::Agent,
        ),
        capabilities,
        profiles: vec![ProfileId::from(PROFILE_ID)],
        resources: Vec::new(),
        channels: Vec::new(),
        security: None,
        governance: None,
        limits: None,
        compatibility: Some(json!({
            "a2a": {
                "url": card.url,
                "methods": CURRENT_METHODS,
                "supported_interfaces": card.supported_interfaces,
                "capabilities": card.capabilities,
                "security_schemes": card.security_schemes,
                "default_input_modes": card.default_input_modes,
                "default_output_modes": card.default_output_modes
            }
        })),
        extensions: None,
    })
}

/// Validates required A2A 1.0 Agent Card invariants.
pub fn validate_agent_card(card: &AgentCard) -> Result<(), A2aProfileError> {
    if card.name.trim().is_empty() {
        return Err(A2aProfileError::InvalidMessage(
            "AgentCard.name must not be empty".to_owned(),
        ));
    }
    if card.description.as_deref().is_none_or(str::is_empty) {
        return Err(A2aProfileError::InvalidMessage(
            "AgentCard.description must not be empty".to_owned(),
        ));
    }
    if card.supported_interfaces.is_empty() {
        return Err(A2aProfileError::InvalidMessage(
            "AgentCard.supportedInterfaces must not be empty".to_owned(),
        ));
    }
    for interface in &card.supported_interfaces {
        let url = url::Url::parse(&interface.url).map_err(|error| {
            A2aProfileError::InvalidMessage(format!("AgentInterface.url must be absolute: {error}"))
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(A2aProfileError::InvalidMessage(
                "AgentInterface.url must use HTTP or HTTPS".to_owned(),
            ));
        }
        if interface.protocol_binding.trim().is_empty()
            || interface.protocol_version.trim().is_empty()
        {
            return Err(A2aProfileError::InvalidMessage(
                "AgentInterface binding and protocolVersion are required".to_owned(),
            ));
        }
    }
    if card.default_input_modes.is_empty() || card.default_output_modes.is_empty() {
        return Err(A2aProfileError::InvalidMessage(
            "AgentCard default input and output modes are required".to_owned(),
        ));
    }
    for skill in &card.skills {
        if skill.id.trim().is_empty()
            || skill.name.trim().is_empty()
            || skill.description.as_deref().is_none_or(str::is_empty)
            || skill.tags.is_empty()
        {
            return Err(A2aProfileError::InvalidMessage(
                "every AgentSkill requires id, name, description, and tags".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Maps an A2A skill into an AIP capability.
pub fn capability_from_skill(skill: A2aSkill) -> Result<Capability, A2aProfileError> {
    Ok(Capability {
        id: CapabilityId::parse(format!("cap:a2a:{}", skill.id))
            .map_err(|error| A2aProfileError::InvalidIdentifier(error.to_string()))?,
        name: skill.name,
        kind: CapabilityKind::Agent,
        input_schema: skill
            .input_schema
            .unwrap_or_else(|| json!({"type": "object"})),
        output_schema: None,
        description: skill.description,
        risk: None,
        stability: None,
        cost: None,
        auth: None,
        bindings: Vec::new(),
        requires_human_approval: None,
        contract: None,
    })
}

/// Maps an AIP manifest into an A2A Agent Card.
#[must_use]
pub fn agent_card_from_manifest(manifest: &Manifest, url: Option<String>) -> AgentCard {
    let supported_interfaces = url
        .as_ref()
        .map(|url| A2aAgentInterface {
            url: url.clone(),
            protocol_binding: "JSONRPC".to_owned(),
            tenant: None,
            protocol_version: "1.0".to_owned(),
        })
        .into_iter()
        .collect();
    AgentCard {
        id: String::new(),
        name: manifest
            .agent
            .display_name
            .clone()
            .unwrap_or_else(|| manifest.agent.id.to_string()),
        description: Some(format!(
            "Agent Interoperability Protocol endpoint for {}",
            manifest.agent.id
        )),
        provider: None,
        documentation_url: None,
        icon_url: None,
        skills: manifest
            .capabilities
            .iter()
            .map(skill_from_capability)
            .collect(),
        url,
        supported_interfaces,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        capabilities: A2aAgentCapabilities {
            streaming: true,
            push_notifications: true,
            extended_agent_card: manifest.security.is_some(),
            extensions: Vec::new(),
        },
        default_input_modes: vec!["application/json".to_owned(), "text/plain".to_owned()],
        default_output_modes: vec!["application/json".to_owned(), "text/plain".to_owned()],
        security_schemes: BTreeMap::new(),
        security: Vec::new(),
        signatures: Vec::new(),
        supports_authenticated_extended_card: manifest.security.is_some(),
    }
}

/// Maps an AIP capability into an A2A skill.
#[must_use]
pub fn skill_from_capability(capability: &Capability) -> A2aSkill {
    A2aSkill {
        id: capability
            .id
            .as_str()
            .strip_prefix("cap:a2a:")
            .unwrap_or_else(|| capability.id.as_str())
            .to_owned(),
        name: capability.name.clone(),
        description: Some(
            capability
                .description
                .clone()
                .unwrap_or_else(|| format!("AIP capability {}", capability.id)),
        ),
        tags: vec![
            "aip".to_owned(),
            format!("{:?}", capability.kind).to_ascii_lowercase(),
        ],
        examples: Vec::new(),
        input_modes: vec!["application/json".to_owned()],
        output_modes: vec!["application/json".to_owned()],
        security_requirements: Vec::new(),
        input_schema: Some(capability.input_schema.clone()),
    }
}

/// Maps an A2A task into an AIP action.
pub fn action_from_task(task: A2aTask) -> Result<Action, A2aProfileError> {
    Ok(Action::new(
        CapabilityId::parse(format!("cap:a2a:{}", task.skill_id))
            .map_err(|error| A2aProfileError::InvalidIdentifier(error.to_string()))?,
        task.input,
    ))
}

/// Maps A2A `tasks/send` parameters into an AIP action.
pub fn action_from_task_send(params: A2aTaskSendParams) -> Result<Action, A2aProfileError> {
    let capability_id = params
        .capability_id
        .or_else(|| {
            params
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.pointer("/aip/capability_id"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .map_or_else(
            || {
                params
                    .skill_id
                    .clone()
                    .map(|skill| {
                        if skill.starts_with("cap:") {
                            skill
                        } else {
                            format!("cap:a2a:{skill}")
                        }
                    })
                    .ok_or(A2aProfileError::MissingField("skill_id"))
            },
            Ok,
        )?;
    let input = params.input.unwrap_or_else(|| {
        params
            .message
            .as_ref()
            .map(message_to_input)
            .unwrap_or_else(|| json!({}))
    });
    let mut action = Action::new(
        CapabilityId::parse(capability_id)
            .map_err(|error| A2aProfileError::InvalidIdentifier(error.to_string()))?,
        input,
    );
    if let Some(task_id) = params.id {
        action.memory_context = Some(json!({ "a2a": { "task_id": task_id } }));
    }
    Ok(action)
}

/// Current A2A operation normalized across JSON-RPC naming revisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum A2aOperation {
    /// Send one message and wait according to configuration.
    SendMessage,
    /// Send one message and stream task updates.
    StreamMessage,
    /// Get one task.
    GetTask,
    /// List tasks.
    ListTasks,
    /// Cancel one task.
    CancelTask,
    /// Resume a task event subscription.
    SubscribeTask,
    /// Create a push-notification configuration.
    CreatePushConfig,
    /// Read a push-notification configuration.
    GetPushConfig,
    /// List push-notification configurations.
    ListPushConfigs,
    /// Delete a push-notification configuration.
    DeletePushConfig,
    /// Fetch the authenticated extended Agent Card.
    GetExtendedAgentCard,
}

/// Parses current A2A method names and explicit v0.3 compatibility aliases.
pub fn operation_from_method(method: &str) -> Result<A2aOperation, A2aProfileError> {
    match method {
        "SendMessage" | "message/send" | "tasks/send" => Ok(A2aOperation::SendMessage),
        "SendStreamingMessage" | "message/stream" | "tasks/sendSubscribe" => {
            Ok(A2aOperation::StreamMessage)
        }
        "GetTask" | "tasks/get" => Ok(A2aOperation::GetTask),
        "ListTasks" | "tasks/list" => Ok(A2aOperation::ListTasks),
        "CancelTask" | "tasks/cancel" => Ok(A2aOperation::CancelTask),
        "SubscribeToTask" | "tasks/resubscribe" => Ok(A2aOperation::SubscribeTask),
        "CreateTaskPushNotificationConfig"
        | "tasks/pushNotificationConfig/create"
        | "tasks/pushNotificationConfig/set" => Ok(A2aOperation::CreatePushConfig),
        "GetTaskPushNotificationConfig" | "tasks/pushNotificationConfig/get" => {
            Ok(A2aOperation::GetPushConfig)
        }
        "ListTaskPushNotificationConfigs" | "tasks/pushNotificationConfig/list" => {
            Ok(A2aOperation::ListPushConfigs)
        }
        "DeleteTaskPushNotificationConfig" | "tasks/pushNotificationConfig/delete" => {
            Ok(A2aOperation::DeletePushConfig)
        }
        "GetExtendedAgentCard" | "agent/getExtendedCard" => Ok(A2aOperation::GetExtendedAgentCard),
        other => Err(A2aProfileError::UnsupportedMethod(other.to_owned())),
    }
}

/// Maps current A2A `message/send` parameters into a native AIP action.
pub fn action_from_send_message(params: A2aSendMessageParams) -> Result<Action, A2aProfileError> {
    let message_id = params.message.message_id.clone();
    let capability_id = params
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.pointer("/aip/capability_id"))
        .or_else(|| {
            params
                .message
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.pointer("/aip/capability_id"))
        })
        .and_then(Value::as_str)
        .ok_or(A2aProfileError::MissingField("metadata.aip.capability_id"))?;
    let input = params
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.pointer("/aip/input"))
        .cloned()
        .unwrap_or_else(|| message_to_input(&params.message));
    let mut action = Action::new(
        CapabilityId::parse(capability_id.to_owned())
            .map_err(|error| A2aProfileError::InvalidIdentifier(error.to_string()))?,
        input,
    );
    action.idempotency_key = Some(format!("a2a-message:{message_id}"));
    if params.configuration.return_immediately {
        action.mode = Some(ActionMode::Async);
    }
    // Push credentials are intentionally not copied into the native action.
    // The authenticated A2A edge must encrypt and persist them in its profile
    // state before attaching an opaque callback descriptor.
    action.callback = None;
    let push_config = params
        .configuration
        .task_push_notification_config
        .as_ref()
        .map(|config| {
            json!({
                "id": config.id,
                "taskId": config.task_id,
                "tenant": config.tenant,
                "url": config.url,
                "authenticationScheme": config.authentication.as_ref().map(|auth| &auth.scheme),
                "hasToken": config.token.is_some(),
                "hasCredentials": config
                    .authentication
                    .as_ref()
                    .is_some_and(|auth| !auth.credentials.is_empty())
            })
        });
    action.memory_context = Some(json!({
        "a2a": {
            "message_id": params.message.message_id,
            "task_id": params.message.task_id,
            "context_id": params.message.context_id,
            "tenant": params.tenant,
            "accepted_output_modes": params.configuration.accepted_output_modes,
            "history_length": params.configuration.history_length,
            "push_notification_config": push_config
        }
    }));
    Ok(action)
}

/// Parses current A2A send parameters from a JSON-RPC request.
pub fn send_message_params(
    request: &A2aJsonRpcRequest,
) -> Result<A2aSendMessageParams, A2aProfileError> {
    let params = serde_json::from_value(
        request
            .params
            .clone()
            .ok_or(A2aProfileError::MissingParams)?,
    )
    .map_err(|error| A2aProfileError::InvalidIdentifier(error.to_string()))?;
    validate_send_message_params(&params)?;
    Ok(params)
}

/// Validates required fields and role/content invariants for an inbound send request.
pub fn validate_send_message_params(params: &A2aSendMessageParams) -> Result<(), A2aProfileError> {
    if params.message.message_id.trim().is_empty() {
        return Err(A2aProfileError::InvalidMessage(
            "message.messageId must not be empty".to_owned(),
        ));
    }
    if params.message.role != A2aRole::User {
        return Err(A2aProfileError::InvalidMessage(
            "inbound SendMessage role must be ROLE_USER".to_owned(),
        ));
    }
    if params.message.parts.is_empty() {
        return Err(A2aProfileError::InvalidMessage(
            "message.parts must contain at least one part".to_owned(),
        ));
    }
    if params.message.parts.iter().any(|part| {
        part.media_type
            .as_deref()
            .is_some_and(|media_type| media_type.trim().is_empty())
    }) {
        return Err(A2aProfileError::InvalidMessage(
            "part.mediaType must not be empty when present".to_owned(),
        ));
    }
    Ok(())
}

/// Maps an AIP action result into an A2A state and artifacts.
#[must_use]
pub fn task_state_from_result(result: &ActionResult) -> (A2aTaskState, Vec<Value>) {
    let state = match result.status {
        ActionResultStatus::Completed => A2aTaskState::Completed,
        ActionResultStatus::Failed => A2aTaskState::Failed,
        ActionResultStatus::Cancelled => A2aTaskState::Cancelled,
        ActionResultStatus::PendingApproval | ActionResultStatus::RequiresHuman => {
            A2aTaskState::InputRequired
        }
    };
    let artifacts = result
        .message
        .iter()
        .map(|part| match part {
            MessagePart::Text { text, .. } => json!({ "kind": "text", "text": text }),
            _ => json!({ "kind": "json", "value": part }),
        })
        .collect();
    (state, artifacts)
}

/// Maps an AIP action result into a full A2A task representation.
#[must_use]
pub fn task_from_result(task_id: String, skill_id: String, result: &ActionResult) -> A2aTask {
    let state = match result.status {
        ActionResultStatus::Completed => A2aTaskState::Completed,
        ActionResultStatus::Failed => A2aTaskState::Failed,
        ActionResultStatus::Cancelled => A2aTaskState::Cancelled,
        ActionResultStatus::PendingApproval | ActionResultStatus::RequiresHuman => {
            A2aTaskState::InputRequired
        }
    };
    A2aTask {
        id: task_id.clone(),
        context_id: Some(task_id.clone()),
        skill_id,
        input: json!({}),
        status: A2aTaskStatus {
            state,
            message: result.error.as_ref().map(|error| A2aMessage {
                message_id: format!("message-{}-error", result.action_id),
                context_id: None,
                task_id: Some(task_id.clone()),
                role: A2aRole::Agent,
                parts: vec![A2aPart::data(json!({ "error": error }))],
                metadata: None,
                extensions: Vec::new(),
                reference_task_ids: Vec::new(),
            }),
            timestamp: None,
        },
        artifacts: artifacts_from_result(result),
        history: Vec::new(),
        metadata: Some(json!({
            "aip": {
                "action_id": result.action_id,
                "status": result.status
            }
        })),
    }
}

/// Maps a native AIP action status into a durable A2A task projection.
#[must_use]
pub fn task_from_action_status(
    task_id: String,
    skill_id: String,
    status: &ActionStatus,
) -> A2aTask {
    if let Some(result) = status.result.as_ref() {
        let mut task = task_from_result(task_id, skill_id, result);
        task.history = history_from_stream_chunks(&status.chunks);
        return task;
    }
    let state = match status.state {
        ActionLifecycleState::Unknown => A2aTaskState::Failed,
        ActionLifecycleState::Accepted | ActionLifecycleState::Queued => A2aTaskState::Submitted,
        ActionLifecycleState::Running | ActionLifecycleState::Streaming => A2aTaskState::Working,
        ActionLifecycleState::PendingApproval => A2aTaskState::InputRequired,
        ActionLifecycleState::Cancelling | ActionLifecycleState::Cancelled => {
            A2aTaskState::Cancelled
        }
        ActionLifecycleState::Completed => A2aTaskState::Completed,
        ActionLifecycleState::Failed
        | ActionLifecycleState::Expired
        | ActionLifecycleState::DeadLettered => A2aTaskState::Failed,
    };
    A2aTask {
        id: task_id.clone(),
        context_id: Some(task_id),
        skill_id,
        input: json!({}),
        status: A2aTaskStatus {
            state,
            message: None,
            timestamp: None,
        },
        artifacts: Vec::new(),
        history: history_from_stream_chunks(&status.chunks),
        metadata: Some(json!({
            "aip": {
                "action_id": status.action_id,
                "state": status.state,
                "result_status": status.result_status
            }
        })),
    }
}

/// Maps a native action status into an A2A task and applies `historyLength`.
///
/// A2A callers expect `historyLength` to return the most recent task history
/// entries, while AIP stores the durable native stream in ascending sequence
/// order. The projection therefore trims from the front and preserves the
/// original order of the retained messages.
#[must_use]
pub fn task_from_action_status_with_history_limit(
    task_id: String,
    skill_id: String,
    status: &ActionStatus,
    history_length: Option<usize>,
) -> A2aTask {
    let mut task = task_from_action_status(task_id, skill_id, status);
    apply_history_limit(&mut task, history_length);
    task
}

/// Applies A2A `historyLength` semantics to an existing task projection.
pub fn apply_history_limit(task: &mut A2aTask, history_length: Option<usize>) {
    let Some(history_length) = history_length else {
        return;
    };
    if history_length >= task.history.len() {
        return;
    }
    let start = task.history.len().saturating_sub(history_length);
    task.history = task.history[start..].to_vec();
}

/// Maps native AIP stream chunks into A2A task history messages.
#[must_use]
pub fn history_from_stream_chunks(chunks: &[StreamChunk]) -> Vec<A2aMessage> {
    chunks
        .iter()
        .map(|chunk| {
            let parts = match chunk.part.as_ref() {
                Some(part) => vec![part_from_message_part(part)],
                None => vec![A2aPart::data(
                    chunk.data.clone().unwrap_or_else(|| json!({})),
                )],
            };
            A2aMessage {
                message_id: format!("message-{}-{}", chunk.action_id, chunk.sequence),
                context_id: None,
                task_id: Some(chunk.action_id.to_string()),
                role: A2aRole::Agent,
                parts,
                metadata: Some(json!({
                    "aip": {
                        "action_id": chunk.action_id,
                        "sequence": chunk.sequence,
                        "kind": chunk.kind
                    }
                })),
                extensions: Vec::new(),
                reference_task_ids: Vec::new(),
            }
        })
        .collect()
}

/// Maps one native AIP stream chunk into a current A2A artifact update.
#[must_use]
pub fn artifact_update_from_stream_chunk(
    task_id: String,
    context_id: String,
    chunk: &StreamChunk,
) -> A2aTaskArtifactUpdateEvent {
    let parts = match chunk.part.as_ref() {
        Some(part) => vec![part_from_message_part(part)],
        None => vec![A2aPart::data(
            chunk.data.clone().unwrap_or_else(|| json!({})),
        )],
    };
    A2aTaskArtifactUpdateEvent {
        task_id,
        context_id,
        artifact: A2aArtifact {
            artifact_id: format!("artifact-{}-stream", chunk.action_id),
            name: Some("stream".to_owned()),
            description: Some("Incremental AIP action output".to_owned()),
            parts,
            metadata: Some(json!({
                "aip": {
                    "actionId": chunk.action_id,
                    "sequence": chunk.sequence,
                    "kind": chunk.kind
                }
            })),
            extensions: Vec::new(),
        },
        append: chunk.sequence > 0,
        last_chunk: matches!(chunk.kind, aip_core::StreamChunkKind::Done),
        metadata: None,
    }
}

/// Maps an AIP action result into A2A artifacts.
#[must_use]
pub fn artifacts_from_result(result: &ActionResult) -> Vec<A2aArtifact> {
    let mut artifacts = result
        .message
        .iter()
        .enumerate()
        .map(|(index, part)| A2aArtifact {
            artifact_id: format!("artifact-{}-{index}", result.action_id),
            name: None,
            description: None,
            parts: vec![part_from_message_part(part)],
            metadata: None,
            extensions: Vec::new(),
        })
        .collect::<Vec<_>>();
    if artifacts.is_empty()
        && let Some(output) = &result.output
    {
        artifacts.push(A2aArtifact {
            artifact_id: format!("artifact-{}-output", result.action_id),
            name: Some("output".to_owned()),
            description: None,
            parts: vec![A2aPart::data(output.clone())],
            metadata: None,
            extensions: Vec::new(),
        });
    }
    artifacts
}

/// Parses task id params from a JSON-RPC request.
pub fn task_id_params(request: &A2aJsonRpcRequest) -> Result<A2aTaskIdParams, A2aProfileError> {
    serde_json::from_value(
        request
            .params
            .clone()
            .ok_or(A2aProfileError::MissingParams)?,
    )
    .map_err(|error| A2aProfileError::InvalidIdentifier(error.to_string()))
}

/// Parses current task-list parameters from a JSON-RPC request.
pub fn task_list_params(request: &A2aJsonRpcRequest) -> Result<A2aTaskListParams, A2aProfileError> {
    serde_json::from_value(request.params.clone().unwrap_or_else(|| json!({})))
        .map_err(|error| A2aProfileError::InvalidIdentifier(error.to_string()))
}

/// Parses a current push-notification configuration resource.
pub fn push_config(request: &A2aJsonRpcRequest) -> Result<A2aTaskPushConfig, A2aProfileError> {
    serde_json::from_value(
        request
            .params
            .clone()
            .ok_or(A2aProfileError::MissingParams)?,
    )
    .map_err(|error| A2aProfileError::InvalidIdentifier(error.to_string()))
}

/// Parses a push-notification configuration selector.
pub fn push_config_selector(
    request: &A2aJsonRpcRequest,
) -> Result<A2aPushConfigSelector, A2aProfileError> {
    serde_json::from_value(
        request
            .params
            .clone()
            .ok_or(A2aProfileError::MissingParams)?,
    )
    .map_err(|error| A2aProfileError::InvalidIdentifier(error.to_string()))
}

/// Parses push-notification configuration list parameters.
pub fn push_config_list_params(
    request: &A2aJsonRpcRequest,
) -> Result<A2aPushConfigListParams, A2aProfileError> {
    serde_json::from_value(
        request
            .params
            .clone()
            .ok_or(A2aProfileError::MissingParams)?,
    )
    .map_err(|error| A2aProfileError::InvalidIdentifier(error.to_string()))
}

/// Parses send params from a JSON-RPC request.
pub fn task_send_params(request: &A2aJsonRpcRequest) -> Result<A2aTaskSendParams, A2aProfileError> {
    serde_json::from_value(
        request
            .params
            .clone()
            .ok_or(A2aProfileError::MissingParams)?,
    )
    .map_err(|error| A2aProfileError::InvalidIdentifier(error.to_string()))
}

/// Creates an A2A JSON-RPC success response.
#[must_use]
pub fn success_response(id: Value, result: Value) -> A2aJsonRpcResponse {
    A2aJsonRpcResponse {
        jsonrpc: "2.0".to_owned(),
        id,
        result: Some(result),
        error: None,
    }
}

/// Creates an A2A JSON-RPC error response.
#[must_use]
pub fn error_response(id: Value, code: i64, message: impl Into<String>) -> A2aJsonRpcResponse {
    let reason = match code {
        -32001 => "TASK_NOT_FOUND",
        -32002 => "TASK_NOT_CANCELABLE",
        -32003 => "PUSH_NOTIFICATION_NOT_SUPPORTED",
        -32004 => "UNSUPPORTED_OPERATION",
        -32005 => "CONTENT_TYPE_NOT_SUPPORTED",
        -32006 => "INVALID_AGENT_RESPONSE",
        -32007 => "EXTENDED_AGENT_CARD_NOT_CONFIGURED",
        -32008 => "EXTENSION_SUPPORT_REQUIRED",
        -32009 => "VERSION_NOT_SUPPORTED",
        -32600 => "INVALID_REQUEST",
        -32601 => "METHOD_NOT_FOUND",
        -32602 => "INVALID_PARAMS",
        -32603 => "INTERNAL_ERROR",
        _ => "AIP_A2A_PROFILE_ERROR",
    };
    A2aJsonRpcResponse {
        jsonrpc: "2.0".to_owned(),
        id,
        result: None,
        error: Some(A2aJsonRpcError {
            code,
            message: message.into(),
            data: Some(json!([{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": reason,
                "domain": "getaip.org",
                "metadata": { "profile": PROFILE_ID }
            }])),
        }),
    }
}

/// Returns the A2A task id associated with an action.
#[must_use]
pub fn task_id_for_action(action: &Action) -> String {
    action
        .memory_context
        .as_ref()
        .and_then(|metadata| metadata.pointer("/a2a/task_id"))
        .and_then(Value::as_str)
        .map_or_else(|| action.id.to_string(), ToOwned::to_owned)
}

/// Returns the A2A skill id associated with an action.
#[must_use]
pub fn skill_id_for_action(action: &Action) -> String {
    action
        .capability_id
        .as_str()
        .strip_prefix("cap:a2a:")
        .unwrap_or_else(|| action.capability_id.as_str())
        .to_owned()
}

/// Parses an A2A task id as an AIP action id when possible.
pub fn action_id_from_task_id(task_id: &str) -> Result<ActionId, A2aProfileError> {
    ActionId::parse(task_id).map_err(|error| A2aProfileError::InvalidIdentifier(error.to_string()))
}

fn message_to_input(message: &A2aMessage) -> Value {
    json!({
        "message": message,
        "text": message.parts.iter().find_map(|part| match &part.content {
            A2aPartContent::Text { text } => Some(text.as_str()),
            _ => None,
        })
    })
}

fn part_from_message_part(part: &MessagePart) -> A2aPart {
    match part {
        MessagePart::Text { text, .. } => A2aPart::text(text.clone()),
        MessagePart::Image {
            url,
            data,
            mime_type,
            alt,
        } => A2aPart {
            content: url.as_ref().map_or_else(
                || A2aPartContent::Raw {
                    raw: data.clone().unwrap_or_default(),
                },
                |url| A2aPartContent::Url { url: url.clone() },
            ),
            metadata: alt.as_ref().map(|alt| json!({ "alt": alt })),
            filename: None,
            media_type: Some(mime_type.clone()),
        },
        MessagePart::File {
            url,
            data,
            mime_type,
            filename,
            size_bytes,
        } => A2aPart {
            content: url.as_ref().map_or_else(
                || A2aPartContent::Raw {
                    raw: data.clone().unwrap_or_default(),
                },
                |url| A2aPartContent::Url { url: url.clone() },
            ),
            metadata: size_bytes.map(|size_bytes| json!({ "sizeBytes": size_bytes })),
            filename: Some(filename.clone()),
            media_type: Some(mime_type.clone()),
        },
        MessagePart::Json { data, .. }
        | MessagePart::ToolResult {
            data: Some(data), ..
        } => A2aPart::data(data.clone()),
        other => A2aPart::data(serde_json::to_value(other).unwrap_or_else(|_| json!({}))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        A2aAgentCapabilities, A2aAgentInterface, A2aHttpAuthSecurityScheme, A2aJsonRpcRequest,
        A2aMessage, A2aPart, A2aPartContent, A2aRole, A2aSecurityScheme, A2aSendMessageParams,
        A2aSkill, A2aTaskSendParams, AgentCard, action_from_task_send, artifacts_from_result,
        error_response, history_from_stream_chunks, send_message_params,
        task_from_action_status_with_history_limit, task_id_params, validate_agent_card,
    };
    use aip_core::{
        ActionLifecycleState, ActionResult, ActionResultStatus, ActionStatus, MessagePart,
        StreamChunk, StreamChunkKind,
    };

    #[test]
    fn maps_task_send_to_action() {
        let action = action_from_task_send(A2aTaskSendParams {
            id: Some("task-1".to_owned()),
            skill_id: Some("research".to_owned()),
            capability_id: None,
            message: Some(A2aMessage {
                message_id: "message-1".to_owned(),
                context_id: None,
                task_id: Some("task-1".to_owned()),
                role: A2aRole::User,
                parts: vec![A2aPart::text("hello")],
                metadata: None,
                extensions: Vec::new(),
                reference_task_ids: Vec::new(),
            }),
            input: None,
            metadata: None,
        })
        .expect("action");

        assert_eq!(action.capability_id.as_str(), "cap:a2a:research");
        assert_eq!(
            action
                .memory_context
                .as_ref()
                .and_then(|value| value.pointer("/a2a/task_id"))
                .and_then(serde_json::Value::as_str),
            Some("task-1")
        );
        assert_eq!(
            action
                .input
                .pointer("/text")
                .and_then(serde_json::Value::as_str),
            Some("hello")
        );
    }

    #[test]
    fn parses_a2a_task_history_length_param() {
        let params = task_id_params(&A2aJsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: serde_json::json!(1),
            method: "tasks/get".to_owned(),
            params: Some(serde_json::json!({
                "id": "task-1",
                "historyLength": 3
            })),
        })
        .expect("params");

        assert_eq!(params.id, "task-1");
        assert_eq!(params.history_length, Some(3));
    }

    #[test]
    fn maps_result_message_parts_to_artifacts() {
        let result = ActionResult {
            action_id: aip_core::ActionId::new(),
            status: ActionResultStatus::Completed,
            output: None,
            message: vec![MessagePart::text("done")],
            memory_update: None,
            usage: None,
            receipt: None,
            error: None,
        };

        let artifacts = artifacts_from_result(&result);
        assert_eq!(artifacts.len(), 1);
        assert!(matches!(
            artifacts[0].parts[0].content,
            A2aPartContent::Text { .. }
        ));
    }

    #[test]
    fn maps_native_stream_chunks_to_task_history() {
        let action_id = aip_core::ActionId::new();
        let history = history_from_stream_chunks(&[
            StreamChunk {
                action_id: action_id.clone(),
                sequence: 1,
                kind: StreamChunkKind::Data,
                data: None,
                part: Some(MessagePart::text("working")),
            },
            StreamChunk {
                action_id,
                sequence: 2,
                kind: StreamChunkKind::Progress,
                data: Some(serde_json::json!({ "percent": 50 })),
                part: None,
            },
        ]);
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[0].parts[0],
            A2aPart {
                content: A2aPartContent::Text {
                    text: "working".into()
                },
                metadata: None,
                filename: None,
                media_type: Some("text/plain".to_owned())
            }
        );
        assert_eq!(
            history[1]
                .metadata
                .as_ref()
                .and_then(|value| value.pointer("/aip/sequence")),
            Some(&serde_json::json!(2))
        );
    }

    #[test]
    fn applies_a2a_history_length_to_native_task_projection() {
        let action_id = aip_core::ActionId::new();
        let status = ActionStatus {
            action_id: action_id.clone(),
            capability_id: None,
            session_id: None,
            correlation_id: None,
            state: ActionLifecycleState::Streaming,
            queued_state: None,
            result_status: None,
            approval_id: None,
            transaction_id: None,
            delegation_id: None,
            started_at: None,
            updated_at: time::OffsetDateTime::now_utc(),
            completed_at: None,
            retry: None,
            lease: None,
            result: None,
            receipt_chain: None,
            chunks: vec![
                StreamChunk {
                    action_id: action_id.clone(),
                    sequence: 1,
                    kind: StreamChunkKind::Data,
                    data: Some(serde_json::json!({ "step": 1 })),
                    part: None,
                },
                StreamChunk {
                    action_id: action_id.clone(),
                    sequence: 2,
                    kind: StreamChunkKind::Data,
                    data: Some(serde_json::json!({ "step": 2 })),
                    part: None,
                },
                StreamChunk {
                    action_id,
                    sequence: 3,
                    kind: StreamChunkKind::Data,
                    data: Some(serde_json::json!({ "step": 3 })),
                    part: None,
                },
            ],
            links: Default::default(),
        };

        let task = task_from_action_status_with_history_limit(
            "task-1".to_owned(),
            "skill".to_owned(),
            &status,
            Some(2),
        );

        assert_eq!(task.history.len(), 2);
        assert_eq!(
            task.history[0]
                .metadata
                .as_ref()
                .and_then(|value| value.pointer("/aip/sequence")),
            Some(&serde_json::json!(2))
        );
        assert_eq!(
            task.history[1]
                .metadata
                .as_ref()
                .and_then(|value| value.pointer("/aip/sequence")),
            Some(&serde_json::json!(3))
        );
    }

    #[test]
    fn current_send_message_protojson_is_validated() {
        let request = A2aJsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: serde_json::json!(1),
            method: "SendMessage".to_owned(),
            params: Some(serde_json::json!({
                "message": {
                    "messageId": "message-1",
                    "role": "ROLE_USER",
                    "parts": [{
                        "text": "hello",
                        "mediaType": "text/plain"
                    }]
                },
                "metadata": {
                    "aip": {
                        "capability_id": "cap:test:echo",
                        "input": { "text": "hello" }
                    }
                }
            })),
        };

        let params: A2aSendMessageParams = send_message_params(&request).expect("send params");
        assert_eq!(params.message.role, A2aRole::User);
        assert!(matches!(
            params.message.parts[0].content,
            A2aPartContent::Text { .. }
        ));
    }

    #[test]
    fn send_message_rejects_missing_parts_and_wrong_role() {
        for message in [
            serde_json::json!({
                "messageId": "message-1",
                "role": "ROLE_USER",
                "parts": []
            }),
            serde_json::json!({
                "messageId": "message-1",
                "role": "ROLE_AGENT",
                "parts": [{ "text": "not an inbound user message" }]
            }),
        ] {
            let request = A2aJsonRpcRequest {
                jsonrpc: "2.0".to_owned(),
                id: serde_json::json!(1),
                method: "SendMessage".to_owned(),
                params: Some(serde_json::json!({ "message": message })),
            };
            assert!(send_message_params(&request).is_err());
        }
    }

    #[test]
    fn current_agent_card_omits_legacy_fields_and_roundtrips_security() {
        let mut security_schemes = std::collections::BTreeMap::new();
        security_schemes.insert(
            "bearer".to_owned(),
            A2aSecurityScheme::Http {
                http_auth_security_scheme: A2aHttpAuthSecurityScheme {
                    description: Some("Access token".to_owned()),
                    scheme: "Bearer".to_owned(),
                    bearer_format: Some("JWT".to_owned()),
                },
            },
        );
        let card = AgentCard {
            id: "legacy-id".to_owned(),
            name: "AIP Agent".to_owned(),
            description: Some("A current A2A 1.0 endpoint".to_owned()),
            provider: None,
            documentation_url: None,
            icon_url: None,
            skills: vec![A2aSkill {
                id: "echo".to_owned(),
                name: "Echo".to_owned(),
                description: Some("Returns input".to_owned()),
                tags: vec!["echo".to_owned()],
                examples: Vec::new(),
                input_modes: vec!["text/plain".to_owned()],
                output_modes: vec!["text/plain".to_owned()],
                security_requirements: Vec::new(),
                input_schema: Some(serde_json::json!({ "type": "object" })),
            }],
            url: Some("https://legacy.invalid/a2a".to_owned()),
            supported_interfaces: vec![A2aAgentInterface {
                url: "https://agent.example/a2a/v1".to_owned(),
                protocol_binding: "JSONRPC".to_owned(),
                tenant: None,
                protocol_version: "1.0".to_owned(),
            }],
            version: "1.0.0".to_owned(),
            capabilities: A2aAgentCapabilities {
                streaming: true,
                push_notifications: true,
                extended_agent_card: true,
                extensions: Vec::new(),
            },
            default_input_modes: vec!["text/plain".to_owned()],
            default_output_modes: vec!["text/plain".to_owned()],
            security_schemes,
            security: vec![serde_json::json!({
                "schemes": { "bearer": { "list": [] } }
            })],
            signatures: Vec::new(),
            supports_authenticated_extended_card: true,
        };
        validate_agent_card(&card).expect("valid card");
        let value = serde_json::to_value(card).expect("card JSON");
        assert!(value.get("id").is_none());
        assert!(value.get("url").is_none());
        assert!(value.pointer("/skills/0/input_schema").is_none());
        assert_eq!(
            value.pointer("/supportedInterfaces/0/protocolVersion"),
            Some(&serde_json::json!("1.0"))
        );
        assert_eq!(
            value.pointer("/securitySchemes/bearer/httpAuthSecurityScheme/scheme"),
            Some(&serde_json::json!("Bearer"))
        );
    }

    #[test]
    fn a2a_specific_error_contains_typed_error_info() {
        let response = error_response(serde_json::json!(1), -32001, "task not found");
        assert_eq!(
            response
                .error
                .as_ref()
                .and_then(|error| error.data.as_ref())
                .and_then(|data| data.pointer("/0/reason")),
            Some(&serde_json::json!("TASK_NOT_FOUND"))
        );
    }
}
