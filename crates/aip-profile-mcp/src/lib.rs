//! MCP compatibility profile for AIP.
//!
//! This crate owns Model Context Protocol DTOs and deterministic mappings
//! between MCP 2025-11-25 concepts and the AIP semantic model. It deliberately
//! avoids runtime, subprocess, or HTTP server state; those concerns live in the
//! MCP server/client and transport crates.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_core::{
    Action, ActionId, ActionLifecycleState, ActionMode, ActionResult, ActionResultStatus,
    ActionStatus, Cancel, CancelTarget, Capability, CapabilityId, CapabilityKind, ErrorCategory,
    Manifest, MessagePart, ObservabilityContext, ProtocolError, Resource, StreamChunk,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, fmt, str::FromStr};
use thiserror::Error;

/// MCP compatibility profile id.
pub const PROFILE_ID: &str = "aip.mcp.compat.v1";

/// Latest stable MCP protocol version implemented by this profile.
pub const LATEST_STABLE_PROTOCOL_VERSION: &str = "2025-11-25";

/// MCP protocol versions intentionally supported by the AIP compatibility layer.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// MCP namespace used for AIP extension metadata inside `_meta`.
pub const AIP_META_KEY: &str = "org.getaip/aip";

/// MCP namespace used for protocol metadata inside `_meta`.
pub const MCP_PROTOCOL_VERSION_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";

/// MCP progress token key inside request `_meta`.
pub const MCP_PROGRESS_TOKEN_META_KEY: &str = "progressToken";

/// JSON-RPC version required by MCP.
pub const JSONRPC_VERSION: &str = "2.0";

/// JSON-RPC request id.
pub type JsonRpcId = Value;

/// MCP profile error.
#[derive(Debug, Error)]
pub enum McpProfileError {
    /// JSON-RPC version is not `2.0`.
    #[error("invalid JSON-RPC version `{0}`")]
    InvalidJsonRpcVersion(String),
    /// Required request id is missing.
    #[error("missing JSON-RPC request id")]
    MissingRequestId,
    /// Required params are missing.
    #[error("missing params")]
    MissingParams,
    /// Required tool name is missing.
    #[error("missing tool name")]
    MissingToolName,
    /// Required resource URI is missing.
    #[error("missing resource URI")]
    MissingResourceUri,
    /// Required prompt name is missing.
    #[error("missing prompt name")]
    MissingPromptName,
    /// Required task id is missing.
    #[error("missing task id")]
    MissingTaskId,
    /// Capability id is invalid.
    #[error("invalid capability id: {0}")]
    InvalidCapability(String),
    /// Action id is invalid or cannot be correlated.
    #[error("invalid action id: {0}")]
    InvalidActionId(String),
    /// Method is not known to the selected MCP version.
    #[error("unsupported MCP method `{0}`")]
    UnsupportedMethod(String),
    /// Protocol version is not supported.
    #[error("unsupported MCP protocol version `{0}`")]
    UnsupportedProtocolVersion(String),
    /// Generic mapping error.
    #[error("{0}")]
    Mapping(String),
}

impl McpProfileError {
    /// Converts this profile error to a JSON-RPC error object.
    #[must_use]
    pub fn to_json_rpc_error(&self) -> JsonRpcError {
        let code = match self {
            Self::InvalidJsonRpcVersion(_)
            | Self::MissingRequestId
            | Self::MissingParams
            | Self::MissingToolName
            | Self::MissingResourceUri
            | Self::MissingPromptName
            | Self::MissingTaskId
            | Self::InvalidCapability(_)
            | Self::InvalidActionId(_) => -32602,
            Self::UnsupportedMethod(_) => -32601,
            Self::UnsupportedProtocolVersion(_) => -32000,
            Self::Mapping(_) => -32603,
        };
        JsonRpcError {
            code,
            message: self.to_string(),
            data: Some(json!({ "profile": PROFILE_ID })),
        }
    }
}

/// Versioned MCP method known to the AIP profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum McpMethod {
    /// `initialize`
    Initialize,
    /// `notifications/initialized`
    Initialized,
    /// `ping`
    Ping,
    /// `notifications/cancelled`
    Cancelled,
    /// `notifications/progress`
    Progress,
    /// `tools/list`
    ToolsList,
    /// `tools/call`
    ToolsCall,
    /// `notifications/tools/list_changed`
    ToolsListChanged,
    /// `resources/list`
    ResourcesList,
    /// `resources/read`
    ResourcesRead,
    /// `resources/templates/list`
    ResourcesTemplatesList,
    /// `resources/subscribe`
    ResourcesSubscribe,
    /// `resources/unsubscribe`
    ResourcesUnsubscribe,
    /// `notifications/resources/list_changed`
    ResourcesListChanged,
    /// `notifications/resources/updated`
    ResourcesUpdated,
    /// `prompts/list`
    PromptsList,
    /// `prompts/get`
    PromptsGet,
    /// `notifications/prompts/list_changed`
    PromptsListChanged,
    /// `completion/complete`
    CompletionComplete,
    /// `logging/setLevel`
    LoggingSetLevel,
    /// `notifications/message`
    LoggingMessage,
    /// `roots/list`
    RootsList,
    /// `notifications/roots/list_changed`
    RootsListChanged,
    /// `sampling/createMessage`
    SamplingCreateMessage,
    /// `elicitation/create`
    ElicitationCreate,
    /// `notifications/elicitation/complete`
    ElicitationComplete,
    /// `tasks/list`
    TasksList,
    /// `tasks/get`
    TasksGet,
    /// `tasks/result`
    TasksResult,
    /// `tasks/cancel`
    TasksCancel,
    /// `notifications/tasks/status`
    TasksStatus,
    /// Draft `server/discover`.
    ServerDiscover,
    /// Draft `subscriptions/listen`.
    SubscriptionsListen,
    /// Draft `notifications/subscriptions/acknowledged`.
    SubscriptionsAcknowledged,
}

impl McpMethod {
    /// Returns the wire method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::Initialized => "notifications/initialized",
            Self::Ping => "ping",
            Self::Cancelled => "notifications/cancelled",
            Self::Progress => "notifications/progress",
            Self::ToolsList => "tools/list",
            Self::ToolsCall => "tools/call",
            Self::ToolsListChanged => "notifications/tools/list_changed",
            Self::ResourcesList => "resources/list",
            Self::ResourcesRead => "resources/read",
            Self::ResourcesTemplatesList => "resources/templates/list",
            Self::ResourcesSubscribe => "resources/subscribe",
            Self::ResourcesUnsubscribe => "resources/unsubscribe",
            Self::ResourcesListChanged => "notifications/resources/list_changed",
            Self::ResourcesUpdated => "notifications/resources/updated",
            Self::PromptsList => "prompts/list",
            Self::PromptsGet => "prompts/get",
            Self::PromptsListChanged => "notifications/prompts/list_changed",
            Self::CompletionComplete => "completion/complete",
            Self::LoggingSetLevel => "logging/setLevel",
            Self::LoggingMessage => "notifications/message",
            Self::RootsList => "roots/list",
            Self::RootsListChanged => "notifications/roots/list_changed",
            Self::SamplingCreateMessage => "sampling/createMessage",
            Self::ElicitationCreate => "elicitation/create",
            Self::ElicitationComplete => "notifications/elicitation/complete",
            Self::TasksList => "tasks/list",
            Self::TasksGet => "tasks/get",
            Self::TasksResult => "tasks/result",
            Self::TasksCancel => "tasks/cancel",
            Self::TasksStatus => "notifications/tasks/status",
            Self::ServerDiscover => "server/discover",
            Self::SubscriptionsListen => "subscriptions/listen",
            Self::SubscriptionsAcknowledged => "notifications/subscriptions/acknowledged",
        }
    }

    /// Returns true for methods that are part of the 2025-11-25 stable schema.
    #[must_use]
    pub const fn is_stable_2025_11_25(self) -> bool {
        !matches!(
            self,
            Self::ServerDiscover | Self::SubscriptionsListen | Self::SubscriptionsAcknowledged
        )
    }
}

impl fmt::Display for McpMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for McpMethod {
    type Err = McpProfileError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "initialize" => Self::Initialize,
            "notifications/initialized" => Self::Initialized,
            "ping" => Self::Ping,
            "notifications/cancelled" => Self::Cancelled,
            "notifications/progress" => Self::Progress,
            "tools/list" => Self::ToolsList,
            "tools/call" => Self::ToolsCall,
            "notifications/tools/list_changed" => Self::ToolsListChanged,
            "resources/list" => Self::ResourcesList,
            "resources/read" => Self::ResourcesRead,
            "resources/templates/list" => Self::ResourcesTemplatesList,
            "resources/subscribe" => Self::ResourcesSubscribe,
            "resources/unsubscribe" => Self::ResourcesUnsubscribe,
            "notifications/resources/list_changed" => Self::ResourcesListChanged,
            "notifications/resources/updated" => Self::ResourcesUpdated,
            "prompts/list" => Self::PromptsList,
            "prompts/get" => Self::PromptsGet,
            "notifications/prompts/list_changed" => Self::PromptsListChanged,
            "completion/complete" => Self::CompletionComplete,
            "logging/setLevel" => Self::LoggingSetLevel,
            "notifications/message" => Self::LoggingMessage,
            "roots/list" => Self::RootsList,
            "notifications/roots/list_changed" => Self::RootsListChanged,
            "sampling/createMessage" => Self::SamplingCreateMessage,
            "elicitation/create" => Self::ElicitationCreate,
            "notifications/elicitation/complete" => Self::ElicitationComplete,
            "tasks/list" => Self::TasksList,
            "tasks/get" => Self::TasksGet,
            "tasks/result" => Self::TasksResult,
            "tasks/cancel" => Self::TasksCancel,
            "notifications/tasks/status" => Self::TasksStatus,
            "server/discover" => Self::ServerDiscover,
            "subscriptions/listen" => Self::SubscriptionsListen,
            "notifications/subscriptions/acknowledged" => Self::SubscriptionsAcknowledged,
            method => return Err(McpProfileError::UnsupportedMethod(method.to_owned())),
        })
    }
}

/// JSON-RPC request used by MCP.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC version.
    pub jsonrpc: String,
    /// Request id.
    pub id: JsonRpcId,
    /// Method name.
    pub method: String,
    /// Method params.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// Creates a valid JSON-RPC 2.0 request.
    #[must_use]
    pub fn new(id: JsonRpcId, method: McpMethod, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id,
            method: method.as_str().to_owned(),
            params,
        }
    }

    /// Parses the method into a typed enum.
    pub fn method_kind(&self) -> Result<McpMethod, McpProfileError> {
        self.method.parse()
    }

    /// Validates JSON-RPC basics.
    pub fn validate(&self) -> Result<(), McpProfileError> {
        if self.jsonrpc != JSONRPC_VERSION {
            return Err(McpProfileError::InvalidJsonRpcVersion(self.jsonrpc.clone()));
        }
        Ok(())
    }
}

/// JSON-RPC notification used by MCP.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    /// JSON-RPC version.
    pub jsonrpc: String,
    /// Method name.
    pub method: String,
    /// Method params.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    /// Creates a valid JSON-RPC 2.0 notification.
    #[must_use]
    pub fn new(method: McpMethod, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            method: method.as_str().to_owned(),
            params,
        }
    }
}

/// JSON-RPC response used by MCP.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC version.
    pub jsonrpc: String,
    /// Request id.
    pub id: JsonRpcId,
    /// Result object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// Creates a success response.
    #[must_use]
    pub fn success(id: JsonRpcId, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Creates an error response.
    #[must_use]
    pub fn error(id: JsonRpcId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// JSON-RPC error object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code.
    pub code: i64,
    /// Error message.
    pub message: String,
    /// Error data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// MCP implementation metadata.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImplementationInfo {
    /// Programmatic implementation name.
    pub name: String,
    /// Human-readable title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Semantic or build version.
    pub version: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional icon descriptors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icons: Vec<McpIcon>,
    /// Optional website URL.
    #[serde(
        rename = "websiteUrl",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub website_url: Option<String>,
}

/// MCP icon descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpIcon {
    /// Icon source URL.
    pub src: String,
    /// MIME type.
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Image sizes descriptor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sizes: Vec<String>,
}

/// MCP initialization request params.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InitializeParams {
    /// Requested protocol version.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Client capabilities.
    #[serde(default)]
    pub capabilities: ClientCapabilities,
    /// Client implementation metadata.
    #[serde(rename = "clientInfo")]
    pub client_info: ImplementationInfo,
}

/// MCP initialization result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InitializeResult {
    /// Negotiated protocol version.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Server capabilities.
    pub capabilities: ServerCapabilities,
    /// Server implementation metadata.
    #[serde(rename = "serverInfo")]
    pub server_info: ImplementationInfo,
    /// Optional server instructions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// Extension metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// MCP client capabilities.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ClientCapabilities {
    /// Filesystem roots support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roots: Option<ListChangedCapability>,
    /// LLM sampling support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling: Option<Value>,
    /// User elicitation support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elicitation: Option<Value>,
    /// MCP task support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks: Option<Value>,
    /// Experimental capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,
}

/// MCP server capabilities.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// Tool support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<ListChangedCapability>,
    /// Resource support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceCapability>,
    /// Prompt support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompts: Option<ListChangedCapability>,
    /// Logging support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<Value>,
    /// Completion support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completions: Option<Value>,
    /// MCP task support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks: Option<Value>,
    /// Experimental capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,
}

/// Capability with `listChanged`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListChangedCapability {
    /// Whether list change notifications may be emitted.
    #[serde(rename = "listChanged", default, skip_serializing_if = "is_false")]
    pub list_changed: bool,
}

/// Resource capability.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCapability {
    /// Whether individual resource subscriptions are supported.
    #[serde(default, skip_serializing_if = "is_false")]
    pub subscribe: bool,
    /// Whether list change notifications may be emitted.
    #[serde(rename = "listChanged", default, skip_serializing_if = "is_false")]
    pub list_changed: bool,
}

/// MCP pagination params.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaginationParams {
    /// Cursor from a previous list result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// MCP pagination result fields.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaginationResult {
    /// Cursor for the next page.
    #[serde(
        rename = "nextCursor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}

/// MCP annotations shared by content, resources, and prompts.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Annotations {
    /// Intended audience, usually `user` and/or `assistant`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,
    /// Priority from 0.0 to 1.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<f64>,
    /// Last modified timestamp.
    #[serde(
        rename = "lastModified",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_modified: Option<String>,
}

/// MCP content block.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Text content.
    Text {
        /// Text body.
        text: String,
        /// Optional annotations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
        /// Extension metadata.
        #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
        meta: Option<Value>,
    },
    /// Inline image content.
    Image {
        /// Base64-encoded image data.
        data: String,
        /// MIME type.
        #[serde(rename = "mimeType")]
        mime_type: String,
        /// Optional annotations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
        /// Extension metadata.
        #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
        meta: Option<Value>,
    },
    /// Inline audio content.
    Audio {
        /// Base64-encoded audio data.
        data: String,
        /// MIME type.
        #[serde(rename = "mimeType")]
        mime_type: String,
        /// Optional annotations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
        /// Extension metadata.
        #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
        meta: Option<Value>,
    },
    /// Link to a server-side resource.
    ResourceLink {
        /// Resource URI.
        uri: String,
        /// Resource name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Resource description.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// MIME type.
        #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        /// Optional annotations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
        /// Extension metadata.
        #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
        meta: Option<Value>,
    },
    /// Embedded resource content.
    Resource {
        /// Embedded resource.
        resource: ResourceContents,
        /// Optional annotations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
        /// Extension metadata.
        #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
        meta: Option<Value>,
    },
    /// Tool-use block used by sampling flows.
    ToolUse {
        /// Tool call id.
        id: String,
        /// Tool name.
        name: String,
        /// Tool input.
        input: Value,
    },
    /// Tool-result block used by sampling flows.
    ToolResult {
        /// Tool call id.
        #[serde(rename = "toolCallId")]
        tool_call_id: String,
        /// Tool result content.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        content: Vec<ContentBlock>,
        /// Error marker.
        #[serde(default, skip_serializing_if = "is_false")]
        is_error: bool,
    },
}

/// MCP resource contents.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourceContents {
    /// Text resource.
    Text {
        /// Resource URI.
        uri: String,
        /// MIME type.
        #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        /// Text content.
        text: String,
    },
    /// Binary resource.
    Blob {
        /// Resource URI.
        uri: String,
        /// MIME type.
        #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        /// Base64-encoded resource bytes.
        blob: String,
    },
}

/// MCP tool definition.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpTool {
    /// Tool name.
    pub name: String,
    /// Human-readable title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Tool description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional icons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icons: Vec<McpIcon>,
    /// Input JSON Schema.
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    /// Output JSON Schema.
    #[serde(
        rename = "outputSchema",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_schema: Option<Value>,
    /// Optional annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
    /// Execution metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ToolExecution>,
    /// AIP metadata carried for clients that preserve MCP `_meta`.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// MCP tool execution metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolExecution {
    /// Task support policy.
    #[serde(rename = "taskSupport")]
    pub task_support: TaskSupport,
}

/// MCP task support policy for tool execution.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskSupport {
    /// Task augmentation is forbidden.
    #[default]
    Forbidden,
    /// Task augmentation is optional.
    Optional,
    /// Task augmentation is required.
    Required,
}

/// MCP resource descriptor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpResource {
    /// Resource URI.
    pub uri: String,
    /// Resource name.
    pub name: String,
    /// Human-readable title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Resource description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type.
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Optional icons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icons: Vec<McpIcon>,
    /// Optional size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Optional annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
    /// Extension metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// MCP resource template descriptor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceTemplate {
    /// URI template.
    #[serde(rename = "uriTemplate")]
    pub uri_template: String,
    /// Template name.
    pub name: String,
    /// Human-readable title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Template description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type.
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Optional icons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icons: Vec<McpIcon>,
    /// Optional annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
    /// Extension metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// MCP prompt descriptor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Prompt {
    /// Prompt name.
    pub name: String,
    /// Human-readable title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Prompt description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Prompt arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
    /// Optional icons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icons: Vec<McpIcon>,
    /// Extension metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// MCP prompt argument descriptor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PromptArgument {
    /// Argument name.
    pub name: String,
    /// Argument description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the argument is required.
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
}

/// MCP prompt message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PromptMessage {
    /// Message role.
    pub role: String,
    /// Message content.
    pub content: ContentBlock,
}

/// MCP task status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Work is queued.
    Pending,
    /// Work is running.
    Working,
    /// Work requires input.
    InputRequired,
    /// Work completed.
    Completed,
    /// Work failed.
    Failed,
    /// Work was cancelled.
    Cancelled,
}

/// MCP task view.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Task {
    /// MCP task id.
    #[serde(rename = "taskId")]
    pub task_id: String,
    /// Current status.
    pub status: TaskStatus,
    /// Status message.
    #[serde(
        rename = "statusMessage",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub status_message: Option<String>,
    /// Creation timestamp.
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last update timestamp.
    #[serde(
        rename = "lastUpdatedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_updated_at: Option<String>,
    /// Time-to-live in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    /// Recommended polling interval.
    #[serde(
        rename = "pollInterval",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub poll_interval: Option<u64>,
    /// Extension metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// MCP root descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Root {
    /// Root URI.
    pub uri: String,
    /// Optional root name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Builds MCP server info from an AIP manifest.
#[must_use]
pub fn server_info_from_manifest(manifest: &Manifest) -> ImplementationInfo {
    ImplementationInfo {
        name: manifest
            .agent
            .display_name
            .clone()
            .unwrap_or_else(|| manifest.agent.id.as_str().replace(':', "-")),
        title: manifest.agent.display_name.clone(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        description: Some(format!("AIP gateway for {}", manifest.agent.id.as_str())),
        icons: Vec::new(),
        website_url: None,
    }
}

/// Negotiates an MCP protocol version against the AIP supported matrix.
#[must_use]
pub fn negotiate_protocol_version(requested: Option<&str>) -> String {
    requested
        .filter(|version| SUPPORTED_PROTOCOL_VERSIONS.contains(version))
        .unwrap_or(LATEST_STABLE_PROTOCOL_VERSION)
        .to_owned()
}

/// Returns true when a protocol version is supported.
#[must_use]
pub fn is_supported_protocol_version(version: &str) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

/// Maps an AIP manifest to an MCP `initialize` result.
#[must_use]
pub fn initialize_result(manifest: &Manifest) -> Value {
    initialize_result_for(manifest, None, None)
}

/// Maps an AIP manifest to an MCP `initialize` result with negotiated options.
#[must_use]
pub fn initialize_result_for(
    manifest: &Manifest,
    requested_version: Option<&str>,
    client_capabilities: Option<&ClientCapabilities>,
) -> Value {
    initialize_result_with_capabilities(
        manifest,
        requested_version,
        server_capabilities_from_manifest(manifest, client_capabilities),
    )
}

/// Creates an initialize result from capabilities proven by the active MCP
/// server composition.
///
/// Profile hosts should prefer this function when providers are configured at
/// runtime. It prevents a manifest-only projection from advertising methods
/// for which no provider or durable implementation is installed.
#[must_use]
pub fn initialize_result_with_capabilities(
    manifest: &Manifest,
    requested_version: Option<&str>,
    capabilities: ServerCapabilities,
) -> Value {
    let result = InitializeResult {
        protocol_version: negotiate_protocol_version(requested_version),
        capabilities,
        server_info: server_info_from_manifest(manifest),
        instructions: manifest
            .compatibility
            .as_ref()
            .and_then(|value| value.pointer("/mcp/instructions"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        meta: Some(aip_meta(manifest)),
    };
    serde_json::to_value(result).unwrap_or_else(|error| {
        json!({
            "protocolVersion": LATEST_STABLE_PROTOCOL_VERSION,
            "capabilities": {},
            "serverInfo": { "name": "aip", "version": env!("CARGO_PKG_VERSION") },
            "_meta": aip_extension_meta(json!({ "serialization_error": error.to_string() }))
        })
    })
}

/// Maps an AIP manifest to MCP server capabilities.
#[must_use]
pub fn server_capabilities_from_manifest(
    manifest: &Manifest,
    _client_capabilities: Option<&ClientCapabilities>,
) -> ServerCapabilities {
    ServerCapabilities {
        tools: manifest
            .capabilities
            .iter()
            .any(is_mcp_tool_capability)
            .then_some(ListChangedCapability {
                list_changed: false,
            }),
        resources: (!manifest.resources.is_empty()).then_some(ResourceCapability {
            subscribe: false,
            list_changed: false,
        }),
        prompts: manifest
            .compatibility
            .as_ref()
            .and_then(|value| value.pointer("/mcp/prompts"))
            .is_some()
            .then_some(ListChangedCapability {
                list_changed: false,
            }),
        logging: Some(json!({})),
        completions: Some(json!({})),
        tasks: Some(json!({
            "list": {},
            "cancel": {},
            "requests": {
                "tools": {
                    "call": {}
                }
            }
        })),
        experimental: None,
    }
}

/// Maps an AIP manifest to an MCP `tools/list` result.
#[must_use]
pub fn tools_list_result(manifest: &Manifest) -> Value {
    tools_list_result_with_options(manifest, None, None)
}

/// Maps an AIP manifest to an MCP paginated `tools/list` result.
#[must_use]
pub fn tools_list_result_with_options(
    manifest: &Manifest,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> Value {
    tools_list_result_from_tools(tools_from_manifest(manifest), cursor, limit)
}

/// Maps an AIP manifest to the complete MCP tool list before pagination.
#[must_use]
pub fn tools_from_manifest(manifest: &Manifest) -> Vec<McpTool> {
    manifest
        .capabilities
        .iter()
        .filter(|capability| is_mcp_tool_capability(capability))
        .map(tool_from_capability)
        .collect()
}

/// Maps a precomputed MCP tool list into a paginated `tools/list` result.
#[must_use]
pub fn tools_list_result_from_tools(
    tools: Vec<McpTool>,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> Value {
    let (page, next_cursor) = paginate(tools, cursor, limit);
    let mut result = json!({ "tools": page });
    if let Some(next_cursor) = next_cursor {
        result["nextCursor"] = Value::String(next_cursor);
    }
    result
}

/// Maps an AIP capability to an MCP tool.
#[must_use]
pub fn tool_from_capability(capability: &Capability) -> McpTool {
    let task_support = capability
        .bindings
        .iter()
        .find(|binding| binding.profile.as_str() == PROFILE_ID)
        .and_then(|binding| binding.metadata.get("taskSupport"))
        .and_then(Value::as_str)
        .and_then(|value| match value {
            "optional" => Some(TaskSupport::Optional),
            "required" => Some(TaskSupport::Required),
            "forbidden" => Some(TaskSupport::Forbidden),
            _ => None,
        })
        .unwrap_or_else(|| {
            if capability.requires_human_approval.unwrap_or(false) {
                TaskSupport::Optional
            } else {
                TaskSupport::Forbidden
            }
        });
    McpTool {
        name: tool_name_for_capability(capability),
        title: Some(capability.name.clone()),
        description: capability.description.clone(),
        icons: Vec::new(),
        input_schema: capability.input_schema.clone(),
        output_schema: capability.output_schema.clone(),
        annotations: capability.risk.map(|risk| {
            json!({
                "aipRisk": risk,
                "requiresHumanApproval": capability.requires_human_approval.unwrap_or(false)
            })
        }),
        execution: Some(ToolExecution { task_support }),
        meta: Some(aip_extension_meta(json!({
            "capability_id": capability.id,
            "kind": capability.kind,
            "profile": PROFILE_ID,
            "contract": capability.contract.as_ref()
        }))),
    }
}

/// Maps an MCP `tools/call` request to an AIP action.
pub fn action_from_tools_call(request: &JsonRpcRequest) -> Result<Action, McpProfileError> {
    let params = request
        .params
        .as_ref()
        .ok_or(McpProfileError::MissingParams)?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or(McpProfileError::MissingToolName)?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let capability_id = CapabilityId::parse(format!("cap:mcp:{name}"))
        .map_err(|error| McpProfileError::InvalidCapability(error.to_string()))?;
    Ok(action_from_tool_parts(capability_id, arguments, params))
}

/// Maps an MCP `tools/call` request to an AIP action using manifest metadata.
pub fn action_from_tools_call_with_manifest(
    request: &JsonRpcRequest,
    manifest: &Manifest,
) -> Result<Action, McpProfileError> {
    let params = request
        .params
        .as_ref()
        .ok_or(McpProfileError::MissingParams)?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or(McpProfileError::MissingToolName)?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let capability = manifest
        .capabilities
        .iter()
        .find(|capability| {
            capability.name == name
                || capability.id.as_str() == name
                || tool_name_for_capability(capability) == name
        })
        .ok_or_else(|| McpProfileError::InvalidCapability(name.to_owned()))?;
    Ok(action_from_tool_parts(
        capability.id.clone(),
        arguments,
        params,
    ))
}

/// Maps manifest resources into an MCP `resources/list` result.
#[must_use]
pub fn resources_list_result(manifest: &Manifest) -> Value {
    resources_list_result_with_options(manifest, None, None)
}

/// Maps manifest resources into a paginated MCP `resources/list` result.
#[must_use]
pub fn resources_list_result_with_options(
    manifest: &Manifest,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> Value {
    let resources = manifest
        .resources
        .iter()
        .map(resource_from_aip)
        .collect::<Vec<_>>();
    let (page, next_cursor) = paginate(resources, cursor, limit);
    let mut result = json!({ "resources": page });
    if let Some(next_cursor) = next_cursor {
        result["nextCursor"] = Value::String(next_cursor);
    }
    result
}

/// Maps AIP resource metadata to MCP resource metadata.
#[must_use]
pub fn resource_from_aip(resource: &Resource) -> McpResource {
    let mut meta = serde_json::Map::new();
    meta.insert("resource_id".to_owned(), json!(resource.id));
    if let Some(tenant_id) = resource.tenant_id.as_ref() {
        meta.insert("tenant_id".to_owned(), json!(tenant_id));
    }
    if let Some(expires_at) = resource.expires_at {
        meta.insert("expires_at".to_owned(), json!(expires_at));
    }
    McpResource {
        uri: resource.id.clone(),
        name: resource.name.clone(),
        title: Some(resource.name.clone()),
        description: resource.description.clone(),
        mime_type: resource.mime_type.clone(),
        icons: Vec::new(),
        size: None,
        annotations: None,
        meta: Some(aip_extension_meta(Value::Object(meta))),
    }
}

/// Creates a `resources/read` result.
#[must_use]
pub fn resources_read_result(contents: Vec<ResourceContents>) -> Value {
    json!({ "contents": contents })
}

/// Creates a `resources/templates/list` result.
#[must_use]
pub fn resource_templates_list_result(templates: Vec<ResourceTemplate>) -> Value {
    json!({ "resourceTemplates": templates })
}

/// Creates a `prompts/list` result.
#[must_use]
pub fn prompts_list_result(prompts: Vec<Prompt>, next_cursor: Option<String>) -> Value {
    let mut result = json!({ "prompts": prompts });
    if let Some(next_cursor) = next_cursor {
        result["nextCursor"] = Value::String(next_cursor);
    }
    result
}

/// Creates a `prompts/get` result.
#[must_use]
pub fn prompt_get_result(
    description: Option<String>,
    messages: Vec<PromptMessage>,
    meta: Option<Value>,
) -> Value {
    let mut result = json!({ "messages": messages });
    if let Some(description) = description {
        result["description"] = Value::String(description);
    }
    if let Some(meta) = meta {
        result["_meta"] = meta;
    }
    result
}

/// Creates a `completion/complete` result.
#[must_use]
pub fn completion_result(values: Vec<String>, total: Option<u64>, has_more: bool) -> Value {
    let mut result = json!({
        "completion": {
            "values": values,
            "hasMore": has_more
        }
    });
    if let Some(total) = total {
        result["completion"]["total"] = json!(total);
    }
    result
}

/// Maps an AIP action result into MCP `CallToolResult`.
#[must_use]
pub fn call_tool_result(result: &ActionResult) -> Value {
    let mut content = result
        .message
        .iter()
        .map(message_part_to_mcp_content)
        .collect::<Vec<_>>();
    if content.is_empty()
        && let Some(output) = &result.output
    {
        content.push(ContentBlock::Text {
            text: output.to_string(),
            annotations: None,
            meta: None,
        });
    }
    let mut mapped = json!({
        "content": content,
        "isError": result.error.is_some() || result.status != ActionResultStatus::Completed
    });
    if let Some(output) = &result.output {
        mapped["structuredContent"] = output.clone();
    }
    if let Some(error) = &result.error {
        mapped["_meta"] = aip_extension_meta(json!({
            "error": error
        }));
    }
    mapped
}

/// Creates an MCP task view from an AIP action result.
#[must_use]
pub fn task_from_action_result(task_id: String, result: &ActionResult) -> Task {
    Task {
        task_id,
        status: match result.status {
            ActionResultStatus::Completed => TaskStatus::Completed,
            ActionResultStatus::Failed => TaskStatus::Failed,
            ActionResultStatus::Cancelled => TaskStatus::Cancelled,
            ActionResultStatus::PendingApproval | ActionResultStatus::RequiresHuman => {
                TaskStatus::InputRequired
            }
        },
        status_message: result.error.as_ref().map(|error| error.message.clone()),
        created_at: None,
        last_updated_at: None,
        ttl: None,
        poll_interval: Some(1_000),
        meta: Some(aip_extension_meta(json!({
            "action_id": result.action_id
        }))),
    }
}

/// Creates an MCP task view from a native AIP action status.
#[must_use]
pub fn task_from_action_status(task_id: String, status: &ActionStatus) -> Task {
    if let Some(result) = status.result.as_ref() {
        return task_from_action_result(task_id, result);
    }
    Task {
        task_id,
        status: match status.state {
            ActionLifecycleState::Unknown => TaskStatus::Failed,
            ActionLifecycleState::Accepted | ActionLifecycleState::Queued => TaskStatus::Pending,
            ActionLifecycleState::Running | ActionLifecycleState::Streaming => TaskStatus::Working,
            ActionLifecycleState::PendingApproval => TaskStatus::InputRequired,
            ActionLifecycleState::Cancelling | ActionLifecycleState::Cancelled => {
                TaskStatus::Cancelled
            }
            ActionLifecycleState::Completed => TaskStatus::Completed,
            ActionLifecycleState::Failed
            | ActionLifecycleState::Expired
            | ActionLifecycleState::DeadLettered => TaskStatus::Failed,
        },
        status_message: status.queued_state.clone(),
        created_at: status.started_at.map(|value| value.to_string()),
        last_updated_at: Some(status.updated_at.to_string()),
        ttl: None,
        poll_interval: Some(1_000),
        meta: Some(aip_extension_meta(json!({
            "action_id": status.action_id,
            "state": status.state,
            "result_status": status.result_status
        }))),
    }
}

/// Maps an MCP cancellation notification to AIP cancel when correlation is possible.
pub fn cancel_from_notification(
    notification: &JsonRpcNotification,
    action_by_request_id: &BTreeMap<String, ActionId>,
) -> Result<Option<Cancel>, McpProfileError> {
    let params = notification
        .params
        .as_ref()
        .ok_or(McpProfileError::MissingParams)?;
    let request_id = params
        .get("requestId")
        .ok_or(McpProfileError::MissingRequestId)?;
    let reason = params
        .get("reason")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let key = request_id_to_key(request_id);
    Ok(action_by_request_id
        .get(&key)
        .cloned()
        .map(|action_id| Cancel {
            target: CancelTarget::Action(action_id),
            reason,
        }))
}

/// Creates an MCP progress notification from an AIP stream chunk.
#[must_use]
pub fn progress_notification_from_stream_chunk(
    progress_token: Value,
    chunk: &StreamChunk,
) -> JsonRpcNotification {
    let progress = chunk
        .data
        .as_ref()
        .and_then(|data| data.get("progress"))
        .and_then(Value::as_f64)
        .unwrap_or(chunk.sequence as f64);
    let total = chunk
        .data
        .as_ref()
        .and_then(|data| data.get("total"))
        .and_then(Value::as_f64);
    let message = chunk
        .data
        .as_ref()
        .and_then(|data| data.get("message"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let mut params = json!({
        "progressToken": progress_token,
        "progress": progress,
        "_meta": aip_extension_meta(json!({
            "action_id": chunk.action_id,
            "kind": chunk.kind
        }))
    });
    if let Some(total) = total {
        params["total"] = json!(total);
    }
    if let Some(message) = message {
        params["message"] = Value::String(message);
    }
    JsonRpcNotification::new(McpMethod::Progress, Some(params))
}

/// Creates a logging notification.
#[must_use]
pub fn logging_notification(level: &str, logger: Option<&str>, data: Value) -> JsonRpcNotification {
    let mut params = json!({ "level": level, "data": data });
    if let Some(logger) = logger {
        params["logger"] = Value::String(logger.to_owned());
    }
    JsonRpcNotification::new(McpMethod::LoggingMessage, Some(params))
}

/// Maps an AIP error to a JSON-RPC error.
#[must_use]
pub fn json_rpc_error(error: &ProtocolError) -> JsonRpcError {
    let code = match error.category {
        ErrorCategory::Auth => -32001,
        ErrorCategory::Policy => -32003,
        ErrorCategory::Temporary | ErrorCategory::Transport => -32010,
        ErrorCategory::Connector => -32020,
        ErrorCategory::Economic => -32030,
        ErrorCategory::Permanent => -32602,
    };
    JsonRpcError {
        code,
        message: error.message.clone(),
        data: error.details.as_deref().cloned().or_else(|| {
            Some(aip_extension_meta(json!({
                "code": error.code,
                "category": error.category,
                "retryable": error.retryable,
                "retry_after_ms": error.retry_after_ms,
                "source": error.source
            })))
        }),
    }
}

/// Converts profile errors into AIP protocol errors.
#[must_use]
pub fn protocol_error_from_profile(error: &McpProfileError) -> ProtocolError {
    ProtocolError {
        code: "mcp.profile".to_owned(),
        message: error.to_string(),
        category: match error {
            McpProfileError::UnsupportedProtocolVersion(_) => ErrorCategory::Permanent,
            McpProfileError::UnsupportedMethod(_) => ErrorCategory::Permanent,
            _ => ErrorCategory::Permanent,
        },
        retryable: Some(false),
        retry_after_ms: None,
        details: Some(Box::new(json!({ "profile": PROFILE_ID }))),
        source: Some(Box::new(json!({ "component": "aip-profile-mcp" }))),
    }
}

/// Serializes a JSON-RPC success response.
#[must_use]
pub fn success_response(id: JsonRpcId, result: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, result)
}

/// Serializes a JSON-RPC error response.
#[must_use]
pub fn error_response(id: JsonRpcId, error: JsonRpcError) -> JsonRpcResponse {
    JsonRpcResponse::error(id, error)
}

/// Returns the stable method set for the selected protocol version.
pub fn methods_for_version(version: &str) -> Result<Vec<McpMethod>, McpProfileError> {
    if !is_supported_protocol_version(version) {
        return Err(McpProfileError::UnsupportedProtocolVersion(
            version.to_owned(),
        ));
    }
    let mut methods = vec![
        McpMethod::Initialize,
        McpMethod::Initialized,
        McpMethod::Ping,
        McpMethod::Cancelled,
        McpMethod::Progress,
        McpMethod::ToolsList,
        McpMethod::ToolsCall,
        McpMethod::ToolsListChanged,
        McpMethod::ResourcesList,
        McpMethod::ResourcesRead,
        McpMethod::ResourcesTemplatesList,
        McpMethod::ResourcesSubscribe,
        McpMethod::ResourcesUnsubscribe,
        McpMethod::ResourcesListChanged,
        McpMethod::ResourcesUpdated,
        McpMethod::PromptsList,
        McpMethod::PromptsGet,
        McpMethod::PromptsListChanged,
        McpMethod::CompletionComplete,
        McpMethod::LoggingSetLevel,
        McpMethod::LoggingMessage,
        McpMethod::RootsList,
        McpMethod::RootsListChanged,
        McpMethod::SamplingCreateMessage,
    ];
    if matches!(version, "2025-11-25" | "2025-06-18") {
        methods.push(McpMethod::ElicitationCreate);
    }
    if version == "2025-11-25" {
        methods.push(McpMethod::ElicitationComplete);
    }
    if version == "2025-11-25" {
        methods.extend([
            McpMethod::TasksList,
            McpMethod::TasksGet,
            McpMethod::TasksResult,
            McpMethod::TasksCancel,
            McpMethod::TasksStatus,
        ]);
    }
    Ok(methods)
}

fn action_from_tool_parts(capability_id: CapabilityId, arguments: Value, params: &Value) -> Action {
    let mut action = Action::new(capability_id, arguments);
    if let Some(idempotency_key) = action
        .input
        .get("idempotency_key")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            params
                .get("_meta")
                .and_then(|meta| meta.get("idempotency_key"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
    {
        action.idempotency_key = Some(idempotency_key.to_owned());
    }
    if params.get("task").is_some() {
        action.mode = Some(ActionMode::Async);
    }
    if let Some(meta) = params.get("_meta") {
        if let Some(progress_token) = meta.get(MCP_PROGRESS_TOKEN_META_KEY) {
            action.observability = Some(ObservabilityContext {
                trace_id: None,
                span_id: None,
                fields: Some(json!({
                    "mcp": {
                        "progress_token": progress_token
                    }
                })),
            });
        }
        action.memory_context = Some(json!({
            "_mcp": {
                "meta": meta
            }
        }));
    }
    action
}

fn is_mcp_tool_capability(capability: &Capability) -> bool {
    matches!(
        capability.kind,
        CapabilityKind::Tool | CapabilityKind::Workflow | CapabilityKind::Agent
    )
}

fn tool_name_for_capability(capability: &Capability) -> String {
    let raw_name = capability
        .bindings
        .iter()
        .find(|binding| binding.profile.as_str() == PROFILE_ID)
        .and_then(|binding| binding.metadata.get("name"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            capability
                .id
                .as_str()
                .strip_prefix("cap:")
                .unwrap_or_else(|| capability.id.as_str())
                .to_owned()
        });
    stable_mcp_tool_name(&raw_name)
}

fn stable_mcp_tool_name(raw_name: &str) -> String {
    let mut normalized = String::with_capacity(raw_name.len());
    let mut previous_separator = false;
    for character in raw_name.chars() {
        let next = if character.is_ascii_alphanumeric() || character == '-' {
            previous_separator = false;
            Some(character.to_ascii_lowercase())
        } else if character == '_' || character == ':' || character == '.' || character == '/' {
            if previous_separator {
                None
            } else {
                previous_separator = true;
                Some('_')
            }
        } else if previous_separator {
            None
        } else {
            previous_separator = true;
            Some('_')
        };
        if let Some(character) = next {
            normalized.push(character);
        }
    }

    let normalized = normalized.trim_matches('_');
    let mut normalized = if normalized.is_empty() {
        "tool".to_owned()
    } else if normalized
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        normalized.to_owned()
    } else {
        format!("tool_{normalized}")
    };

    const MAX_TOOL_NAME_BYTES: usize = 64;
    if normalized.len() > MAX_TOOL_NAME_BYTES {
        let hash = stable_name_hash(raw_name);
        normalized.truncate(MAX_TOOL_NAME_BYTES - 9);
        normalized = normalized.trim_end_matches(['_', '-']).to_owned();
        normalized.push('_');
        normalized.push_str(&format!("{hash:08x}"));
    }

    normalized
}

fn stable_name_hash(value: &str) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    for byte in value.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn message_part_to_mcp_content(part: &MessagePart) -> ContentBlock {
    match part {
        MessagePart::Text { text, .. } => ContentBlock::Text {
            text: text.clone(),
            annotations: None,
            meta: None,
        },
        MessagePart::Image {
            data, mime_type, ..
        } => ContentBlock::Image {
            data: data.clone().unwrap_or_default(),
            mime_type: mime_type.clone(),
            annotations: None,
            meta: None,
        },
        MessagePart::Audio {
            data, mime_type, ..
        } => ContentBlock::Audio {
            data: data.clone().unwrap_or_default(),
            mime_type: mime_type.clone(),
            annotations: None,
            meta: None,
        },
        MessagePart::File {
            url,
            filename,
            mime_type,
            ..
        } => ContentBlock::ResourceLink {
            uri: url.clone().unwrap_or_else(|| format!("file:///{filename}")),
            name: Some(filename.clone()),
            description: None,
            mime_type: Some(mime_type.clone()),
            annotations: None,
            meta: None,
        },
        MessagePart::Json { data, .. } => ContentBlock::Text {
            text: data.to_string(),
            annotations: None,
            meta: None,
        },
        MessagePart::ToolResult {
            tool_call_id,
            data,
            error,
        } => ContentBlock::ToolResult {
            tool_call_id: tool_call_id.clone(),
            content: data
                .as_ref()
                .map(|value| {
                    vec![ContentBlock::Text {
                        text: value.to_string(),
                        annotations: None,
                        meta: None,
                    }]
                })
                .unwrap_or_default(),
            is_error: error.is_some(),
        },
        MessagePart::Form { fields, actions } => ContentBlock::Text {
            text: json!({ "form": { "fields": fields, "actions": actions } }).to_string(),
            annotations: None,
            meta: None,
        },
        MessagePart::Card {
            title,
            body,
            actions,
            media,
        } => ContentBlock::Text {
            text: json!({
                "title": title,
                "body": body,
                "actions": actions,
                "media": media
            })
            .to_string(),
            annotations: None,
            meta: None,
        },
    }
}

fn aip_meta(manifest: &Manifest) -> Value {
    aip_extension_meta(json!({
        "manifest_version": manifest.manifest_version,
        "agent_id": manifest.agent.id,
        "profiles": manifest.profiles
    }))
}

/// Wraps profile-specific metadata under the canonical AIP MCP namespace.
#[must_use]
pub fn aip_extension_meta(payload: Value) -> Value {
    let mut object = Map::new();
    object.insert(AIP_META_KEY.to_owned(), payload);
    Value::Object(object)
}

fn paginate<T: Clone>(
    items: Vec<T>,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> (Vec<T>, Option<String>) {
    let start = cursor
        .and_then(|value| value.strip_prefix("offset:"))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let page_limit = limit.unwrap_or(items.len()).max(1);
    let end = start.saturating_add(page_limit).min(items.len());
    let next_cursor = (end < items.len()).then(|| format!("offset:{end}"));
    (items[start.min(items.len())..end].to_vec(), next_cursor)
}

/// Converts a JSON-RPC request id to a stable map key.
#[must_use]
pub fn request_id_to_key(id: &Value) -> String {
    match id {
        Value::String(value) => value.clone(),
        _ => id.to_string(),
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Extracts params into a typed value.
pub fn typed_params<T>(request: &JsonRpcRequest) -> Result<T, McpProfileError>
where
    T: for<'de> Deserialize<'de>,
{
    let params = request
        .params
        .clone()
        .ok_or(McpProfileError::MissingParams)?;
    serde_json::from_value(params).map_err(|error| McpProfileError::Mapping(error.to_string()))
}

/// Returns a mutable `_meta` object on a params value.
#[must_use]
pub fn meta_object(value: &Value) -> Option<&Map<String, Value>> {
    value.get("_meta").and_then(Value::as_object)
}

#[cfg(test)]
mod tests {
    use super::{
        JsonRpcRequest, LATEST_STABLE_PROTOCOL_VERSION, McpMethod, TaskSupport,
        action_from_tools_call, action_from_tools_call_with_manifest, call_tool_result,
        initialize_result, methods_for_version, negotiate_protocol_version, tool_from_capability,
        tools_list_result,
    };
    use aip_core::{
        ActionResult, ActionResultStatus, Capability, CapabilityId, CapabilityKind, Manifest,
        MessagePart, Principal, PrincipalId, PrincipalKind, ProfileId,
    };
    use serde_json::json;

    #[test]
    fn maps_tool_call_to_action() {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: json!(1),
            method: "tools/call".to_owned(),
            params: Some(json!({"name": "search", "arguments": {"q": "aip"}})),
        };
        let action = action_from_tools_call(&request).expect("action");
        assert_eq!(action.capability_id.to_string(), "cap:mcp:search");
    }

    #[test]
    fn negotiates_latest_supported_version() {
        assert_eq!(negotiate_protocol_version(Some("2025-11-25")), "2025-11-25");
        assert_eq!(
            negotiate_protocol_version(Some("1900-01-01")),
            LATEST_STABLE_PROTOCOL_VERSION
        );
    }

    #[test]
    fn method_matrix_contains_stable_tasks() {
        let methods = methods_for_version("2025-11-25").expect("methods");
        assert!(methods.contains(&McpMethod::TasksResult));
        assert!(methods.contains(&McpMethod::ElicitationCreate));
    }

    #[test]
    fn manifest_projects_tools_with_metadata() {
        let manifest = manifest();
        let tools = tools_list_result(&manifest);
        assert_eq!(tools["tools"][0]["name"], "test_echo");
        assert_eq!(tools["tools"][0]["title"], "echo");
        assert_eq!(
            tools["tools"][0]["execution"]["taskSupport"],
            json!(TaskSupport::Forbidden)
        );
        assert!(tools["tools"][0]["_meta"]["org.getaip/aip"].is_object());
    }

    #[test]
    fn tool_name_uses_stable_identifier_and_title_uses_display_name() {
        let mut manifest = manifest();
        manifest.capabilities[0].id = CapabilityId::trusted("cap:hermes_agent:hermes-1:health");
        manifest.capabilities[0].name = "Hermes Agent health (hermes-1)".to_owned();

        let tool = tool_from_capability(&manifest.capabilities[0]);

        assert_eq!(tool.name, "hermes_agent_hermes-1_health");
        assert_eq!(
            tool.title.as_deref(),
            Some("Hermes Agent health (hermes-1)")
        );
    }

    #[test]
    fn initialize_uses_latest_stable_version() {
        let init = initialize_result(&manifest());
        assert_eq!(init["protocolVersion"], LATEST_STABLE_PROTOCOL_VERSION);
        assert!(init["capabilities"]["tools"].is_object());
    }

    #[test]
    fn manifest_lookup_uses_capability_id_or_name() {
        let manifest = manifest();
        let request = JsonRpcRequest::new(
            json!(1),
            McpMethod::ToolsCall,
            Some(json!({"name": "cap:test:echo", "arguments": {"x": 1}})),
        );
        let action = action_from_tools_call_with_manifest(&request, &manifest).expect("action");
        assert_eq!(action.capability_id.as_str(), "cap:test:echo");
    }

    #[test]
    fn manifest_lookup_uses_generated_tool_name() {
        let manifest = manifest();
        let request = JsonRpcRequest::new(
            json!(1),
            McpMethod::ToolsCall,
            Some(json!({"name": "test_echo", "arguments": {"x": 1}})),
        );
        let action = action_from_tools_call_with_manifest(&request, &manifest).expect("action");
        assert_eq!(action.capability_id.as_str(), "cap:test:echo");
    }

    #[test]
    fn result_maps_text_and_structured_content() {
        let result = ActionResult {
            action_id: aip_core::ActionId::new(),
            status: ActionResultStatus::Completed,
            output: Some(json!({"ok": true})),
            message: vec![MessagePart::text("done")],
            memory_update: None,
            usage: None,
            receipt: None,
            error: None,
        };
        let mapped = call_tool_result(&result);
        assert_eq!(mapped["content"][0]["text"], "done");
        assert_eq!(mapped["structuredContent"]["ok"], true);
    }

    fn manifest() -> Manifest {
        let principal = Principal::new(PrincipalId::trusted("agent:test"), PrincipalKind::Agent);
        Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: principal,
            capabilities: vec![Capability {
                id: CapabilityId::trusted("cap:test:echo"),
                name: "echo".to_owned(),
                kind: CapabilityKind::Tool,
                input_schema: json!({"type": "object"}),
                output_schema: Some(json!({"type": "object"})),
                description: Some("Echo input".to_owned()),
                risk: None,
                stability: None,
                cost: None,
                auth: None,
                bindings: Vec::new(),
                requires_human_approval: None,
                contract: None,
            }],
            profiles: vec![ProfileId::from(super::PROFILE_ID)],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        }
    }
}
