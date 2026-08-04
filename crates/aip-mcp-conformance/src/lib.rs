//! MCP compatibility conformance checks for AIP.
//!
//! The checks in this crate are deterministic and embeddable. They validate the
//! profile mapping, JSON-RPC transport codecs, and the AIP-backed MCP server
//! lifecycle without requiring a network listener.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_core::Manifest;
use aip_mcp_client::McpClient;
use aip_mcp_server::McpServer;
use aip_mcp_session::{McpTransportKind, VersionTransportMatrix};
use aip_profile_mcp::{
    AIP_META_KEY, JSONRPC_VERSION, JsonRpcNotification, JsonRpcRequest,
    LATEST_STABLE_PROTOCOL_VERSION, McpMethod, SUPPORTED_PROTOCOL_VERSIONS, call_tool_result,
    initialize_result, methods_for_version, tools_list_result,
};
use aip_transport_mcp_stdio::{McpStdioFrame, decode_frame, encode_frame};
use aip_transport_mcp_streamable_http::{
    McpHttpMessage, McpHttpRequest, McpStreamableHttpError, classify_request, decode_sse_event,
    encode_sse_event,
};
use http::{HeaderMap, HeaderValue, Method};
use jsonschema::Draft;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::future::Future;
use thiserror::Error;

/// MCP conformance failure.
#[derive(Debug, Error)]
#[error("MCP conformance failed: {0}")]
pub struct McpConformanceError(String);

/// Result alias for MCP conformance checks.
pub type McpConformanceResult<T> = Result<T, McpConformanceError>;

/// Status of one MCP conformance check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpConformanceStatus {
    /// Check passed.
    Passed,
    /// Check failed.
    Failed,
}

/// One MCP conformance check result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpConformanceCheck {
    /// Stable check id.
    pub id: String,
    /// Human-readable check name.
    pub name: String,
    /// Check status.
    pub status: McpConformanceStatus,
    /// Optional detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// MCP conformance report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpConformanceReport {
    /// Executed checks.
    pub checks: Vec<McpConformanceCheck>,
}

/// Deterministic MCP fixture used by conformance checks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpGoldenFixture {
    /// Stable fixture id.
    pub id: String,
    /// MCP protocol version covered by the fixture.
    pub protocol_version: String,
    /// JSON-RPC method covered by the fixture.
    pub method: String,
    /// Request payload.
    pub request: Value,
    /// Expected result shape.
    pub expected_result: Value,
}

impl McpConformanceReport {
    /// Adds a passed check.
    pub fn pass(&mut self, id: impl Into<String>, name: impl Into<String>) {
        self.checks.push(McpConformanceCheck {
            id: id.into(),
            name: name.into(),
            status: McpConformanceStatus::Passed,
            detail: None,
        });
    }

    /// Adds a failed check.
    pub fn fail(
        &mut self,
        id: impl Into<String>,
        name: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.checks.push(McpConformanceCheck {
            id: id.into(),
            name: name.into(),
            status: McpConformanceStatus::Failed,
            detail: Some(detail.into()),
        });
    }

    /// Returns true when every check passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.status == McpConformanceStatus::Passed)
    }

    /// Returns the number of failed checks.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == McpConformanceStatus::Failed)
            .count()
    }

    /// Converts the report into an error if any check failed.
    pub fn ensure_success(&self) -> McpConformanceResult<()> {
        if self.is_success() {
            return Ok(());
        }
        let detail = self
            .checks
            .iter()
            .filter(|check| check.status == McpConformanceStatus::Failed)
            .map(|check| {
                format!(
                    "{}: {}",
                    check.id,
                    check.detail.as_deref().unwrap_or("failed")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        Err(McpConformanceError(detail))
    }
}

/// Returns deterministic golden fixtures for every stable MCP version tracked
/// by AIP.
#[must_use]
pub fn golden_fixtures() -> Vec<McpGoldenFixture> {
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .flat_map(|version| {
            methods_for_version(version)
                .unwrap_or_default()
                .into_iter()
                .enumerate()
                .map(|(index, method)| McpGoldenFixture {
                    id: format!(
                        "mcp.golden.{version}.{}",
                        method.as_str().replace(['/', '_'], ".")
                    ),
                    protocol_version: (*version).to_owned(),
                    method: method.as_str().to_owned(),
                    request: fixture_request(version, method, index as u64 + 1),
                    expected_result: fixture_result(version, method),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn fixture_result(version: &str, method: McpMethod) -> Value {
    match method {
        McpMethod::Initialize => json!({
            "protocolVersion": version,
            "capabilities": {},
            "serverInfo": { "name": "aip-golden", "version": env!("CARGO_PKG_VERSION") }
        }),
        McpMethod::Ping
        | McpMethod::ResourcesSubscribe
        | McpMethod::ResourcesUnsubscribe
        | McpMethod::LoggingSetLevel => json!({}),
        McpMethod::ToolsList => json!({ "tools": [] }),
        McpMethod::ToolsCall => json!({
            "content": [{ "type": "text", "text": "ok" }],
            "isError": false
        }),
        McpMethod::ResourcesList => json!({ "resources": [] }),
        McpMethod::ResourcesRead => json!({ "contents": [] }),
        McpMethod::ResourcesTemplatesList => json!({ "resourceTemplates": [] }),
        McpMethod::PromptsList => json!({ "prompts": [] }),
        McpMethod::PromptsGet => json!({ "messages": [] }),
        McpMethod::CompletionComplete => json!({
            "completion": { "values": [], "hasMore": false }
        }),
        McpMethod::RootsList => json!({ "roots": [] }),
        McpMethod::SamplingCreateMessage => json!({
            "role": "assistant",
            "content": { "type": "text", "text": "ok" },
            "model": "aip-golden"
        }),
        McpMethod::ElicitationCreate => json!({ "action": "decline" }),
        McpMethod::TasksList => json!({ "tasks": [] }),
        McpMethod::TasksGet | McpMethod::TasksCancel => fixture_task(),
        McpMethod::TasksResult => json!({
            "content": [{ "type": "text", "text": "done" }],
            "isError": false
        }),
        McpMethod::Initialized
        | McpMethod::Cancelled
        | McpMethod::Progress
        | McpMethod::ToolsListChanged
        | McpMethod::ResourcesListChanged
        | McpMethod::ResourcesUpdated
        | McpMethod::PromptsListChanged
        | McpMethod::LoggingMessage
        | McpMethod::RootsListChanged
        | McpMethod::ElicitationComplete
        | McpMethod::TasksStatus => Value::Null,
        McpMethod::ServerDiscover
        | McpMethod::SubscriptionsListen
        | McpMethod::SubscriptionsAcknowledged => {
            unreachable!("draft methods are not stable fixtures")
        }
    }
}

fn fixture_task() -> Value {
    json!({
        "taskId": "task-1",
        "status": "working",
        "createdAt": "2026-01-01T00:00:00Z",
        "lastUpdatedAt": "2026-01-01T00:00:01Z",
        "ttl": null
    })
}

fn fixture_request(version: &str, method: McpMethod, id: u64) -> Value {
    let base_request = |params: Option<Value>| {
        let mut request = json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": id,
            "method": method.as_str()
        });
        if let Some(params) = params {
            request["params"] = params;
        }
        request
    };
    let notification = |params: Option<Value>| {
        let mut request = json!({
            "jsonrpc": JSONRPC_VERSION,
            "method": method.as_str()
        });
        if let Some(params) = params {
            request["params"] = params;
        }
        request
    };
    match method {
        McpMethod::Initialize => base_request(Some(json!({
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {
                "name": "aip-golden",
                "version": env!("CARGO_PKG_VERSION")
            }
        }))),
        McpMethod::Initialized
        | McpMethod::ToolsListChanged
        | McpMethod::ResourcesListChanged
        | McpMethod::PromptsListChanged
        | McpMethod::RootsListChanged => notification(None),
        McpMethod::Ping
        | McpMethod::ToolsList
        | McpMethod::ResourcesList
        | McpMethod::ResourcesTemplatesList
        | McpMethod::PromptsList
        | McpMethod::RootsList
        | McpMethod::TasksList => base_request(None),
        McpMethod::Cancelled => notification(Some(json!({
            "requestId": id,
            "reason": "conformance cancellation"
        }))),
        McpMethod::Progress => notification(Some(json!({
            "progressToken": "progress-1",
            "progress": 1,
            "total": 2
        }))),
        McpMethod::ToolsCall => base_request(Some(json!({
            "name": "echo",
            "arguments": { "text": "hello" }
        }))),
        McpMethod::ResourcesRead => base_request(Some(json!({ "uri": "aip://example/resource" }))),
        McpMethod::ResourcesSubscribe | McpMethod::ResourcesUnsubscribe => {
            base_request(Some(json!({ "uri": "aip://example/resource" })))
        }
        McpMethod::ResourcesUpdated => notification(Some(json!({
            "uri": "aip://example/resource"
        }))),
        McpMethod::PromptsGet => base_request(Some(json!({
            "name": "example",
            "arguments": {}
        }))),
        McpMethod::CompletionComplete => base_request(Some(json!({
            "ref": { "type": "ref/prompt", "name": "example" },
            "argument": { "name": "topic", "value": "ai" }
        }))),
        McpMethod::LoggingSetLevel => base_request(Some(json!({ "level": "info" }))),
        McpMethod::LoggingMessage => notification(Some(json!({
            "level": "info",
            "logger": "aip-conformance",
            "data": { "message": "hello" }
        }))),
        McpMethod::SamplingCreateMessage => base_request(Some(json!({
            "messages": [{
                "role": "user",
                "content": { "type": "text", "text": "hello" }
            }],
            "maxTokens": 16
        }))),
        McpMethod::ElicitationCreate => base_request(Some(json!({
            "message": "Provide a value",
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "value": { "type": "string" }
                }
            }
        }))),
        McpMethod::ElicitationComplete => notification(Some(json!({
            "elicitationId": "elicitation-1"
        }))),
        McpMethod::TasksGet | McpMethod::TasksResult | McpMethod::TasksCancel => {
            base_request(Some(json!({ "taskId": "task-1" })))
        }
        McpMethod::TasksStatus => notification(Some(json!({
            "taskId": "task-1",
            "status": "working",
            "createdAt": "2026-01-01T00:00:00Z",
            "lastUpdatedAt": "2026-01-01T00:00:01Z",
            "ttl": null
        }))),
        McpMethod::ServerDiscover
        | McpMethod::SubscriptionsListen
        | McpMethod::SubscriptionsAcknowledged => {
            unreachable!("draft methods are not stable fixtures")
        }
    }
}

/// Runs deterministic golden fixture checks for stable MCP protocol versions.
#[must_use]
pub fn run_golden_fixture_conformance() -> McpConformanceReport {
    let mut report = McpConformanceReport::default();
    for fixture in golden_fixtures() {
        check(
            &mut report,
            &fixture.id,
            &format!(
                "{} golden fixture for {}",
                fixture.method, fixture.protocol_version
            ),
            || {
                let method = if fixture.request.get("id").is_some() {
                    let request = serde_json::from_value::<JsonRpcRequest>(fixture.request.clone())
                        .map_err(|error| error.to_string())?;
                    request.validate().map_err(|error| error.to_string())?;
                    request.method_kind().map_err(|error| error.to_string())?
                } else {
                    let notification =
                        serde_json::from_value::<JsonRpcNotification>(fixture.request.clone())
                            .map_err(|error| error.to_string())?;
                    require(
                        notification.jsonrpc == JSONRPC_VERSION,
                        "notification JSON-RPC version is invalid",
                    )?;
                    notification
                        .method
                        .parse::<McpMethod>()
                        .map_err(|error| error.to_string())?
                };
                let methods = methods_for_version(&fixture.protocol_version)
                    .map_err(|error| error.to_string())?;
                require(
                    methods.contains(&method),
                    "fixture method is not present in the selected version matrix",
                )?;
                validate_against_official_schema(
                    &fixture.protocol_version,
                    definition_for_method(&fixture.method)?,
                    &fixture.request,
                )?;
                match result_definition_for_method(&fixture.method) {
                    Some(definition) => {
                        require(
                            fixture.expected_result.is_object(),
                            "request fixture expected result must be a JSON object",
                        )?;
                        validate_against_official_schema(
                            &fixture.protocol_version,
                            definition,
                            &fixture.expected_result,
                        )
                    }
                    None => require(
                        fixture.expected_result.is_null(),
                        "notification fixture must not declare a response result",
                    ),
                }
            },
        );
    }
    report
}

fn result_definition_for_method(method: &str) -> Option<&'static str> {
    match method {
        "initialize" => Some("InitializeResult"),
        "ping" | "resources/subscribe" | "resources/unsubscribe" | "logging/setLevel" => {
            Some("EmptyResult")
        }
        "tools/list" => Some("ListToolsResult"),
        "tools/call" => Some("CallToolResult"),
        "resources/list" => Some("ListResourcesResult"),
        "resources/read" => Some("ReadResourceResult"),
        "resources/templates/list" => Some("ListResourceTemplatesResult"),
        "prompts/list" => Some("ListPromptsResult"),
        "prompts/get" => Some("GetPromptResult"),
        "completion/complete" => Some("CompleteResult"),
        "roots/list" => Some("ListRootsResult"),
        "sampling/createMessage" => Some("CreateMessageResult"),
        "elicitation/create" => Some("ElicitResult"),
        "tasks/list" => Some("ListTasksResult"),
        "tasks/get" => Some("GetTaskResult"),
        "tasks/result" => Some("GetTaskPayloadResult"),
        "tasks/cancel" => Some("CancelTaskResult"),
        _ => None,
    }
}

/// Runs negative MCP conformance checks for malformed profile and transport
/// inputs.
#[must_use]
pub fn run_negative_conformance() -> McpConformanceReport {
    let mut report = McpConformanceReport::default();
    check(
        &mut report,
        "mcp.negative.schema_matrix",
        "official schemas reject malformed requests for every supported version",
        || {
            for version in SUPPORTED_PROTOCOL_VERSIONS {
                let malformed = json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {}
                });
                require(
                    validate_against_official_schema(version, "InitializeRequest", &malformed)
                        .is_err(),
                    &format!("MCP {version} accepted malformed initialize params"),
                )?;
            }
            Ok(())
        },
    );
    for fixture in golden_fixtures() {
        let check_id = format!("mcp.negative.{}.schema", fixture.id);
        let check_name = format!(
            "{} rejects method and parameter mutations for {}",
            fixture.method, fixture.protocol_version
        );
        check(&mut report, &check_id, &check_name, || {
            let definition = definition_for_method(&fixture.method)?;
            let mut wrong_method = fixture.request.clone();
            wrong_method["method"] = json!("invalid/method");
            require(
                validate_against_official_schema(
                    &fixture.protocol_version,
                    definition,
                    &wrong_method,
                )
                .is_err(),
                "official schema accepted a mutated method constant",
            )?;
            let mut wrong_params = fixture.request.clone();
            wrong_params["params"] = json!("not-an-object");
            require(
                validate_against_official_schema(
                    &fixture.protocol_version,
                    definition,
                    &wrong_params,
                )
                .is_err(),
                "official schema accepted string params",
            )
        });
    }
    check(
        &mut report,
        "mcp.negative.jsonrpc_version",
        "invalid JSON-RPC version is rejected",
        || {
            let request = JsonRpcRequest {
                jsonrpc: "1.0".to_owned(),
                id: json!(1),
                method: "tools/list".to_owned(),
                params: Some(json!({})),
            };
            require(
                request.validate().is_err(),
                "invalid JSON-RPC version was accepted",
            )
        },
    );
    check(
        &mut report,
        "mcp.negative.unsupported_method",
        "unsupported method is rejected",
        || {
            require(
                "unknown/method".parse::<McpMethod>().is_err(),
                "unsupported method parsed successfully",
            )
        },
    );
    check(
        &mut report,
        "mcp.negative.unsupported_version",
        "unsupported protocol version is rejected",
        || {
            require(
                methods_for_version("1900-01-01").is_err(),
                "unsupported protocol version returned a method matrix",
            )
        },
    );
    check(
        &mut report,
        "mcp.negative.streamable_http_missing_body",
        "Streamable HTTP POST without body is rejected",
        || {
            let result = classify_request(&Method::POST, &HeaderMap::new(), None);
            require(
                matches!(result, Err(McpStreamableHttpError::MissingBody)),
                "missing POST body was not rejected",
            )
        },
    );
    check(
        &mut report,
        "mcp.negative.stdio_invalid_json",
        "stdio invalid JSON is rejected",
        || {
            require(
                decode_frame(b"{not-json}\n").is_err(),
                "invalid stdio JSON frame was accepted",
            )
        },
    );
    report
}

fn definition_for_method(method: &str) -> Result<&'static str, String> {
    match method {
        "initialize" => Ok("InitializeRequest"),
        "notifications/initialized" => Ok("InitializedNotification"),
        "ping" => Ok("PingRequest"),
        "notifications/cancelled" => Ok("CancelledNotification"),
        "notifications/progress" => Ok("ProgressNotification"),
        "tools/list" => Ok("ListToolsRequest"),
        "tools/call" => Ok("CallToolRequest"),
        "notifications/tools/list_changed" => Ok("ToolListChangedNotification"),
        "resources/list" => Ok("ListResourcesRequest"),
        "resources/read" => Ok("ReadResourceRequest"),
        "resources/templates/list" => Ok("ListResourceTemplatesRequest"),
        "resources/subscribe" => Ok("SubscribeRequest"),
        "resources/unsubscribe" => Ok("UnsubscribeRequest"),
        "notifications/resources/list_changed" => Ok("ResourceListChangedNotification"),
        "notifications/resources/updated" => Ok("ResourceUpdatedNotification"),
        "prompts/list" => Ok("ListPromptsRequest"),
        "prompts/get" => Ok("GetPromptRequest"),
        "notifications/prompts/list_changed" => Ok("PromptListChangedNotification"),
        "completion/complete" => Ok("CompleteRequest"),
        "logging/setLevel" => Ok("SetLevelRequest"),
        "notifications/message" => Ok("LoggingMessageNotification"),
        "roots/list" => Ok("ListRootsRequest"),
        "notifications/roots/list_changed" => Ok("RootsListChangedNotification"),
        "sampling/createMessage" => Ok("CreateMessageRequest"),
        "elicitation/create" => Ok("ElicitRequest"),
        "notifications/elicitation/complete" => Ok("ElicitationCompleteNotification"),
        "tasks/list" => Ok("ListTasksRequest"),
        "tasks/get" => Ok("GetTaskRequest"),
        "tasks/result" => Ok("GetTaskPayloadRequest"),
        "tasks/cancel" => Ok("CancelTaskRequest"),
        "notifications/tasks/status" => Ok("TaskStatusNotification"),
        other => Err(format!(
            "no official schema definition is registered for `{other}`"
        )),
    }
}

fn validate_against_official_schema(
    version: &str,
    definition: &str,
    instance: &Value,
) -> Result<(), String> {
    let (mut schema, draft, definitions_key) = official_schema(version)?;
    let schema_object = schema
        .as_object_mut()
        .ok_or_else(|| format!("MCP {version} schema root is not an object"))?;
    schema_object.insert(
        "$ref".to_owned(),
        Value::String(format!("#/{definitions_key}/{definition}")),
    );
    let validator = jsonschema::options()
        .with_draft(draft)
        .build(&schema)
        .map_err(|error| format!("MCP {version} schema compilation failed: {error}"))?;
    let errors = validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "MCP {version} {definition} validation failed: {}",
            errors.join("; ")
        ))
    }
}

fn official_schema(version: &str) -> Result<(Value, Draft, &'static str), String> {
    let (source, draft, definitions_key) = match version {
        "2024-11-05" => (
            include_str!("../../../schemas/mcp/2024-11-05/schema.json"),
            Draft::Draft7,
            "definitions",
        ),
        "2025-03-26" => (
            include_str!("../../../schemas/mcp/2025-03-26/schema.json"),
            Draft::Draft7,
            "definitions",
        ),
        "2025-06-18" => (
            include_str!("../../../schemas/mcp/2025-06-18/schema.json"),
            Draft::Draft7,
            "definitions",
        ),
        "2025-11-25" => (
            include_str!("../../../schemas/mcp/2025-11-25/schema.json"),
            Draft::Draft202012,
            "$defs",
        ),
        other => return Err(format!("no official MCP schema snapshot for `{other}`")),
    };
    serde_json::from_str(source)
        .map(|schema| (schema, draft, definitions_key))
        .map_err(|error| format!("MCP {version} schema JSON is invalid: {error}"))
}

/// Runs profile-only MCP compatibility checks for an AIP manifest.
#[must_use]
pub fn run_profile_conformance(manifest: &Manifest) -> McpConformanceReport {
    let mut report = McpConformanceReport::default();
    check(
        &mut report,
        "mcp.profile.version_matrix",
        "stable MCP method matrix",
        || {
            let methods = methods_for_version(LATEST_STABLE_PROTOCOL_VERSION)
                .map_err(|error| error.to_string())?;
            require(
                methods.contains(&McpMethod::Initialize)
                    && methods.contains(&McpMethod::ToolsCall)
                    && methods.contains(&McpMethod::TasksCancel),
                "latest stable method matrix is incomplete",
            )
        },
    );
    for version in SUPPORTED_PROTOCOL_VERSIONS {
        let check_id = format!("mcp.profile.version_matrix.{version}");
        let check_name = format!("MCP {version} method matrix");
        check(&mut report, &check_id, &check_name, || {
            let methods = methods_for_version(version).map_err(|error| error.to_string())?;
            require(
                methods.contains(&McpMethod::Initialize)
                    && methods.contains(&McpMethod::ToolsList)
                    && methods.contains(&McpMethod::ToolsCall)
                    && methods.contains(&McpMethod::ResourcesRead)
                    && methods.contains(&McpMethod::PromptsGet),
                "required lifecycle, tool, resource, or prompt method is missing",
            )?;
            if *version == "2024-11-05" {
                require(
                    methods.contains(&McpMethod::ResourcesSubscribe)
                        && !methods.contains(&McpMethod::TasksResult),
                    "2024-11-05 matrix omitted resource subscriptions or exposed task methods",
                )?;
            }
            if *version == "2025-06-18" {
                require(
                    methods.contains(&McpMethod::ElicitationCreate)
                        && !methods.contains(&McpMethod::ElicitationComplete),
                    "2025-06-18 elicitation matrix does not match its official schema",
                )?;
            }
            if *version == LATEST_STABLE_PROTOCOL_VERSION {
                require(
                    methods.contains(&McpMethod::TasksCancel)
                        && methods.contains(&McpMethod::ElicitationCreate),
                    "latest stable matrix did not expose task and elicitation methods",
                )?;
            }
            Ok(())
        });
    }
    check(
        &mut report,
        "mcp.profile.initialize",
        "initialize result projection",
        || {
            let result = initialize_result(manifest);
            require(
                result["protocolVersion"] == LATEST_STABLE_PROTOCOL_VERSION,
                "initialize selected the wrong protocol version",
            )?;
            require(
                result["_meta"][AIP_META_KEY].is_object(),
                "initialize did not include AIP metadata namespace",
            )
        },
    );
    check(
        &mut report,
        "mcp.profile.tools_list",
        "tools/list projection",
        || {
            let result = tools_list_result(manifest);
            require(
                result["tools"].is_array(),
                "tools/list did not return an array",
            )
        },
    );
    check(
        &mut report,
        "mcp.profile.call_tool_result",
        "CallToolResult projection",
        || {
            let result = aip_core::ActionResult {
                action_id: aip_core::ActionId::new(),
                status: aip_core::ActionResultStatus::Completed,
                output: Some(json!({"ok": true})),
                message: vec![aip_core::MessagePart::text("ok")],
                memory_update: None,
                usage: None,
                receipt: None,
                error: None,
            };
            let mapped = call_tool_result(&result);
            require(
                mapped["content"][0]["type"] == "text" && mapped["structuredContent"]["ok"] == true,
                "CallToolResult did not preserve content and structured output",
            )
        },
    );
    report
}

/// Runs client bridge checks against an external MCP peer.
///
/// This validates the outbound AIP-to-MCP path: initialize, initialized
/// notification, tool discovery, optional resource discovery, and projection of
/// the peer into an AIP manifest.
pub async fn run_client_conformance(client: &McpClient) -> McpConformanceReport {
    let mut report = McpConformanceReport::default();
    check_async(
        &mut report,
        "mcp.client.initialize",
        "client initialize lifecycle",
        async { client.initialize().await.map_err(|error| error.to_string()) },
    )
    .await;
    check_async(
        &mut report,
        "mcp.client.tools_list",
        "client tools/list discovery",
        async {
            let tools = client
                .list_tools()
                .await
                .map_err(|error| error.to_string())?;
            for tool in tools {
                require(!tool.name.is_empty(), "tool name must not be empty")?;
                require(
                    tool.input_schema.is_object(),
                    "tool inputSchema must be a JSON object",
                )?;
            }
            Ok(())
        },
    )
    .await;
    check_async(
        &mut report,
        "mcp.client.resources_list_optional",
        "client resources/list optional discovery",
        async {
            let _ = client.list_resources().await.unwrap_or_default();
            Ok(())
        },
    )
    .await;
    check_async(
        &mut report,
        "mcp.client.manifest_projection",
        "external MCP peer projects as AIP manifest",
        async {
            let manifest = client
                .refresh_manifest()
                .await
                .map_err(|error| error.to_string())?;
            require(
                manifest
                    .profiles
                    .iter()
                    .any(|profile| profile.as_str() == aip_profile_mcp::PROFILE_ID),
                "manifest did not advertise the MCP compatibility profile",
            )?;
            require(
                manifest
                    .compatibility
                    .as_ref()
                    .and_then(|value| value.pointer("/mcp/client_bridge"))
                    .and_then(serde_json::Value::as_bool)
                    == Some(true),
                "manifest did not mark the MCP client bridge",
            )
        },
    )
    .await;
    report
}

/// Runs transport codec checks for MCP stdio and streamable HTTP.
#[must_use]
pub fn run_transport_conformance() -> McpConformanceReport {
    let mut report = McpConformanceReport::default();
    check(
        &mut report,
        "mcp.transport.stdio_jsonrpc",
        "stdio JSON-RPC framing",
        || {
            let frame = McpStdioFrame::Request(JsonRpcRequest::new(
                json!(1),
                McpMethod::ToolsList,
                Some(json!({})),
            ));
            let encoded = encode_frame(&frame).map_err(|error| error.to_string())?;
            let decoded = decode_frame(&encoded).map_err(|error| error.to_string())?;
            require(decoded == frame, "stdio frame did not round-trip")
        },
    );
    check(
        &mut report,
        "mcp.transport.streamable_http_post",
        "streamable HTTP POST classification",
        || {
            let mut headers = HeaderMap::new();
            headers.insert("mcp-session-id", HeaderValue::from_static("s1"));
            let request = classify_request(
                &Method::POST,
                &headers,
                Some(json!({
                    "jsonrpc": JSONRPC_VERSION,
                    "id": 1,
                    "method": "tools/list"
                })),
            )
            .map_err(|error| error.to_string())?;
            match request {
                McpHttpRequest::ClientMessage {
                    message,
                    session_id,
                    ..
                } => match *message {
                    McpHttpMessage::Request(request) => {
                        require(request.method == "tools/list", "wrong JSON-RPC method")?;
                        require(session_id.as_deref() == Some("s1"), "missing session id")
                    }
                    _ => Err("wrong JSON-RPC message type".to_owned()),
                },
                _ => Err("wrong streamable HTTP classification".to_owned()),
            }
        },
    );
    check(
        &mut report,
        "mcp.transport.sse",
        "SSE event framing",
        || {
            let event = aip_transport_mcp_streamable_http::McpSseEvent {
                id: Some("1".to_owned()),
                event: Some("message".to_owned()),
                data: "{\"jsonrpc\":\"2.0\"}".to_owned(),
            };
            let decoded =
                decode_sse_event(&encode_sse_event(&event)).map_err(|error| error.to_string())?;
            require(decoded == event, "SSE event did not round-trip")
        },
    );
    report
}

/// Runs server lifecycle checks against an AIP-backed MCP server.
pub async fn run_server_conformance(server: &McpServer) -> McpConformanceReport {
    let mut report = McpConformanceReport::default();
    check_async(
        &mut report,
        "mcp.server.initialize",
        "initialize lifecycle",
        async {
            let response = server
                .handle_request(
                    "conformance",
                    JsonRpcRequest::new(
                        json!(1),
                        McpMethod::Initialize,
                        Some(json!({
                            "protocolVersion": LATEST_STABLE_PROTOCOL_VERSION,
                            "capabilities": {},
                            "clientInfo": { "name": "aip-mcp-conformance", "version": env!("CARGO_PKG_VERSION") }
                        })),
                    ),
                )
                .await;
            require(
                response.error.is_none()
                    && response.result.as_ref().is_some_and(|result| {
                        result["protocolVersion"] == LATEST_STABLE_PROTOCOL_VERSION
                    }),
                "initialize did not return the negotiated protocol version",
            )
        },
    )
    .await;
    check_async(
        &mut report,
        "mcp.server.initialized_notification",
        "initialized notification",
        async {
            server
                .handle_notification(
                    "conformance",
                    JsonRpcNotification::new(McpMethod::Initialized, None),
                )
                .await
                .map_err(|error| error.to_string())
        },
    )
    .await;
    check_async(
        &mut report,
        "mcp.server.tools_list",
        "tools/list lifecycle",
        async {
            let response = server
                .handle_request(
                    "conformance",
                    JsonRpcRequest::new(json!(2), McpMethod::ToolsList, Some(json!({}))),
                )
                .await;
            require(
                response.error.is_none()
                    && response
                        .result
                        .as_ref()
                        .is_some_and(|result| result["tools"].is_array()),
                "tools/list did not return tools array",
            )
        },
    )
    .await;
    check_async(
        &mut report,
        "mcp.server.negative_unknown_method",
        "unknown JSON-RPC method returns an error",
        async {
            let response = server
                .handle_request(
                    "conformance",
                    JsonRpcRequest {
                        jsonrpc: JSONRPC_VERSION.to_owned(),
                        id: json!(99),
                        method: "unknown/method".to_owned(),
                        params: Some(json!({})),
                    },
                )
                .await;
            require(
                response
                    .error
                    .as_ref()
                    .is_some_and(|error| error.code == -32601),
                "unknown method did not return JSON-RPC method-not-found",
            )
        },
    )
    .await;
    check_async(
        &mut report,
        "mcp.server.negative_missing_tool_params",
        "tools/call without params returns an error",
        async {
            let response = server
                .handle_request(
                    "conformance",
                    JsonRpcRequest::new(json!(100), McpMethod::ToolsCall, None),
                )
                .await;
            require(
                response.error.is_some(),
                "tools/call without params succeeded",
            )
        },
    )
    .await;
    report.checks.extend(
        run_server_version_transport_conformance(server)
            .await
            .checks,
    );
    report
}

/// Executes the authoritative MCP server state machine over every supported
/// stable version and transport pair.
///
/// Each row uses a fresh session and proves pre-initialize denial, exact
/// version selection, duplicate-initialize rejection, the initialized
/// transition, normal method authorization, and terminal session cleanup.
pub async fn run_server_version_transport_conformance(server: &McpServer) -> McpConformanceReport {
    let matrix = VersionTransportMatrix::default();
    let mut report = McpConformanceReport::default();
    let transports = [
        McpTransportKind::Stdio,
        McpTransportKind::LegacyHttpSse,
        McpTransportKind::StreamableHttp,
    ];
    for transport in transports {
        for version in SUPPORTED_PROTOCOL_VERSIONS {
            if !matrix.supports(version, transport) {
                continue;
            }
            let transport_label = match transport {
                McpTransportKind::Stdio => "stdio",
                McpTransportKind::LegacyHttpSse => "legacy_http_sse",
                McpTransportKind::StreamableHttp => "streamable_http",
            };
            let session_id = format!("conformance-{transport_label}-{version}");
            let prefix = format!("mcp.server.matrix.{transport_label}.{version}");

            let pre_initialize = server
                .handle_request_on_transport(
                    &session_id,
                    transport,
                    JsonRpcRequest::new(json!(1), McpMethod::ToolsList, Some(json!({}))),
                )
                .await;
            if pre_initialize
                .error
                .as_ref()
                .is_some_and(|error| error.code == -32002)
            {
                report.pass(
                    format!("{prefix}.pre_initialize"),
                    "normal methods are denied before initialize",
                );
            } else {
                report.fail(
                    format!("{prefix}.pre_initialize"),
                    "normal methods are denied before initialize",
                    format!("unexpected response: {pre_initialize:?}"),
                );
            }

            let initialize = server
                .handle_request_on_transport(
                    &session_id,
                    transport,
                    JsonRpcRequest::new(
                        json!(2),
                        McpMethod::Initialize,
                        Some(json!({
                            "protocolVersion": version,
                            "capabilities": {
                                "roots": { "listChanged": true },
                                "sampling": {},
                                "elicitation": {},
                                "tasks": {}
                            },
                            "clientInfo": {
                                "name": "aip-mcp-conformance",
                                "version": env!("CARGO_PKG_VERSION")
                            }
                        })),
                    ),
                )
                .await;
            if initialize.error.is_none()
                && initialize.result.as_ref().is_some_and(|result| {
                    result.get("protocolVersion").and_then(Value::as_str) == Some(*version)
                })
            {
                report.pass(
                    format!("{prefix}.initialize"),
                    "exact version and transport pair negotiates",
                );
            } else {
                report.fail(
                    format!("{prefix}.initialize"),
                    "exact version and transport pair negotiates",
                    format!("unexpected response: {initialize:?}"),
                );
                let _ = server.delete_session(&session_id).await;
                continue;
            }

            let duplicate = server
                .handle_request_on_transport(
                    &session_id,
                    transport,
                    JsonRpcRequest::new(
                        json!(3),
                        McpMethod::Initialize,
                        Some(json!({
                            "protocolVersion": version,
                            "capabilities": {},
                            "clientInfo": { "name": "duplicate", "version": "1.0.0" }
                        })),
                    ),
                )
                .await;
            if duplicate
                .error
                .as_ref()
                .is_some_and(|error| error.code == -32002)
            {
                report.pass(
                    format!("{prefix}.duplicate_initialize"),
                    "duplicate initialize is rejected",
                );
            } else {
                report.fail(
                    format!("{prefix}.duplicate_initialize"),
                    "duplicate initialize is rejected",
                    format!("unexpected response: {duplicate:?}"),
                );
            }

            match server
                .handle_notification_on_transport(
                    &session_id,
                    transport,
                    JsonRpcNotification::new(McpMethod::Initialized, None),
                )
                .await
            {
                Ok(()) => report.pass(
                    format!("{prefix}.initialized"),
                    "initialized notification activates the session",
                ),
                Err(error) => report.fail(
                    format!("{prefix}.initialized"),
                    "initialized notification activates the session",
                    error.to_string(),
                ),
            }

            let tools = server
                .handle_request_on_transport(
                    &session_id,
                    transport,
                    JsonRpcRequest::new(json!(4), McpMethod::ToolsList, Some(json!({}))),
                )
                .await;
            if tools.error.is_none()
                && tools
                    .result
                    .as_ref()
                    .is_some_and(|result| result.get("tools").is_some_and(Value::is_array))
            {
                report.pass(
                    format!("{prefix}.tools_list"),
                    "initialized session executes negotiated tools/list",
                );
            } else {
                report.fail(
                    format!("{prefix}.tools_list"),
                    "initialized session executes negotiated tools/list",
                    format!("unexpected response: {tools:?}"),
                );
            }

            let state_matches = server
                .session_state(&session_id)
                .await
                .is_some_and(|state| {
                    state.transport == transport
                        && state.protocol_version.as_deref() == Some(*version)
                        && state.lifecycle == aip_mcp_session::McpLifecycle::Initialized
                });
            if state_matches {
                report.pass(
                    format!("{prefix}.state"),
                    "session retains negotiated version and transport",
                );
            } else {
                report.fail(
                    format!("{prefix}.state"),
                    "session retains negotiated version and transport",
                    "server session state did not match the negotiated pair",
                );
            }

            match server.delete_session(&session_id).await {
                Ok(true) if server.session_state(&session_id).await.is_none() => report.pass(
                    format!("{prefix}.close"),
                    "session cleanup removes negotiated state",
                ),
                Ok(value) => report.fail(
                    format!("{prefix}.close"),
                    "session cleanup removes negotiated state",
                    format!("unexpected delete result `{value}`"),
                ),
                Err(error) => report.fail(
                    format!("{prefix}.close"),
                    "session cleanup removes negotiated state",
                    error.to_string(),
                ),
            }
        }
    }
    report
}

fn check<F>(report: &mut McpConformanceReport, id: &str, name: &str, f: F)
where
    F: FnOnce() -> Result<(), String>,
{
    match f() {
        Ok(()) => report.pass(id, name),
        Err(error) => report.fail(id, name, error),
    }
}

async fn check_async<F>(report: &mut McpConformanceReport, id: &str, name: &str, future: F)
where
    F: Future<Output = Result<(), String>>,
{
    match future.await {
        Ok(()) => report.pass(id, name),
        Err(error) => report.fail(id, name, error),
    }
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        run_client_conformance, run_golden_fixture_conformance, run_negative_conformance,
        run_profile_conformance, run_server_conformance, run_transport_conformance,
    };
    use aip_core::{Manifest, Principal, PrincipalId, PrincipalKind, ProfileId};
    use aip_gateway::Gateway;
    use aip_mcp_client::{InMemoryMcpTransport, McpClient, McpClientConfig};
    use aip_mcp_server::{McpServer, McpServerConfig};
    use aip_profile_mcp::McpMethod;
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn profile_and_transport_conformance_pass() {
        let manifest = Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(PrincipalId::trusted("agent:test"), PrincipalKind::Agent),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from(aip_profile_mcp::PROFILE_ID)],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        };
        let profile = run_profile_conformance(&manifest);
        assert!(profile.is_success(), "{profile:?}");
        let transport = run_transport_conformance();
        assert!(transport.is_success(), "{transport:?}");
        let golden = run_golden_fixture_conformance();
        assert!(golden.is_success(), "{golden:?}");
        let negative = run_negative_conformance();
        assert!(negative.is_success(), "{negative:?}");
    }

    #[tokio::test]
    async fn client_conformance_passes_against_in_memory_peer() {
        let transport = InMemoryMcpTransport::default();
        transport
            .register_result(
                McpMethod::Initialize,
                json!({
                    "protocolVersion": aip_profile_mcp::LATEST_STABLE_PROTOCOL_VERSION,
                    "capabilities": { "tools": {}, "resources": {} },
                    "serverInfo": { "name": "mock-mcp", "version": "1.0.0" }
                }),
            )
            .await;
        transport
            .register_result(
                McpMethod::ToolsList,
                json!({
                    "tools": [{
                        "name": "echo",
                        "description": "Echo input",
                        "inputSchema": { "type": "object" }
                    }]
                }),
            )
            .await;
        transport
            .register_result(McpMethod::ResourcesList, json!({ "resources": [] }))
            .await;
        let client = McpClient::new(McpClientConfig::new("mock"), Arc::new(transport));
        let report = run_client_conformance(&client).await;
        assert!(report.is_success(), "{report:?}");
    }

    #[tokio::test]
    async fn server_conformance_covers_every_stable_transport_pair() {
        let manifest = Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(
                PrincipalId::trusted("agent:mcp-conformance"),
                PrincipalKind::Agent,
            ),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from(aip_profile_mcp::PROFILE_ID)],
            resources: Vec::new(),
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        };
        let gateway = Gateway::local_development(manifest.clone())
            .await
            .expect("gateway");
        let server = McpServer::new(McpServerConfig::new(manifest, gateway));
        let report = run_server_conformance(&server).await;
        assert!(report.is_success(), "{report:#?}");
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.id.contains("legacy_http_sse.2024-11-05"))
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.id.contains("streamable_http.2025-11-25"))
        );
    }
}
