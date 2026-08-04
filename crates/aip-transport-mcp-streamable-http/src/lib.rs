//! MCP Streamable HTTP transport helpers.
//!
//! This crate implements the HTTP-level classification and SSE framing rules
//! used by the AIP MCP compatibility server. It is intentionally framework
//! neutral: Axum, Hyper, Tower, and embedded hosts can all adapt their request
//! and response types into these DTOs.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_profile_mcp::{JSONRPC_VERSION, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

/// MCP protocol-version request header.
pub const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
/// MCP session-id response/request header.
pub const MCP_SESSION_ID_HEADER: &str = "mcp-session-id";
/// SSE cursor header used for resuming streamable HTTP streams.
pub const LAST_EVENT_ID_HEADER: &str = "last-event-id";
/// HTTP content type for JSON-RPC bodies.
pub const APPLICATION_JSON: &str = "application/json";
/// HTTP content type for MCP streamable responses.
pub const TEXT_EVENT_STREAM: &str = "text/event-stream";
/// HTTP authorization header.
pub const AUTHORIZATION_HEADER: &str = "authorization";
/// HTTP `WWW-Authenticate` response header.
pub const WWW_AUTHENTICATE_HEADER: &str = "www-authenticate";

/// Streamable HTTP transport error.
#[derive(Debug, Error)]
pub enum McpStreamableHttpError {
    /// HTTP method is not part of the MCP streamable HTTP binding.
    #[error("unsupported MCP streamable HTTP method `{0}`")]
    UnsupportedMethod(String),
    /// Request did not contain a required JSON body.
    #[error("missing JSON-RPC body")]
    MissingBody,
    /// JSON body is not a JSON-RPC 2.0 request, notification, or response.
    #[error("body is not an MCP JSON-RPC message")]
    NotJsonRpc,
    /// JSON-RPC version was invalid.
    #[error("invalid JSON-RPC version `{0}`")]
    InvalidJsonRpcVersion(String),
    /// Header value could not be interpreted as text.
    #[error("invalid header `{name}`: {reason}")]
    InvalidHeader {
        /// Header name.
        name: &'static str,
        /// Reason.
        reason: String,
    },
    /// Origin policy rejected the request.
    #[error("origin `{0}` is not allowed")]
    OriginRejected(String),
    /// SSE frame is malformed.
    #[error("malformed SSE frame: {0}")]
    MalformedSse(String),
    /// Replay log could not be read or written.
    #[error("SSE replay log error: {0}")]
    ReplayLog(String),
}

/// Result alias for MCP streamable HTTP helpers.
pub type McpStreamableHttpResult<T> = Result<T, McpStreamableHttpError>;

/// Decoded JSON-RPC message carried over MCP streamable HTTP.
#[derive(Clone, Debug, PartialEq)]
pub enum McpHttpMessage {
    /// JSON-RPC request.
    Request(JsonRpcRequest),
    /// JSON-RPC notification.
    Notification(JsonRpcNotification),
    /// JSON-RPC response.
    Response(JsonRpcResponse),
}

/// Classified MCP streamable HTTP operation.
#[derive(Clone, Debug, PartialEq)]
pub enum McpHttpRequest {
    /// Client POST containing one JSON-RPC message.
    ClientMessage {
        /// Decoded message.
        message: Box<McpHttpMessage>,
        /// Optional protocol version header.
        protocol_version: Option<String>,
        /// Optional session id header.
        session_id: Option<String>,
    },
    /// Client GET opening or resuming the server-to-client SSE stream.
    Listen {
        /// Optional session id header.
        session_id: Option<String>,
        /// Optional SSE cursor.
        last_event_id: Option<String>,
    },
    /// Client DELETE requesting session termination.
    DeleteSession {
        /// Optional session id header.
        session_id: Option<String>,
    },
}

/// Framework-neutral HTTP response descriptor for MCP streamable HTTP.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpHttpResponse {
    /// Numeric HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: BTreeMap<String, String>,
    /// Optional JSON body or SSE payload encoded as a string value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

impl McpHttpResponse {
    /// Creates a JSON response descriptor.
    #[must_use]
    pub fn json(status: StatusCode, body: Value) -> Self {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_owned(), APPLICATION_JSON.to_owned());
        Self {
            status: status.as_u16(),
            headers,
            body: Some(body),
        }
    }

    /// Creates an empty accepted response descriptor for notifications.
    #[must_use]
    pub fn accepted() -> Self {
        Self {
            status: StatusCode::ACCEPTED.as_u16(),
            headers: BTreeMap::new(),
            body: None,
        }
    }

    /// Creates an SSE response descriptor.
    #[must_use]
    pub fn sse(session_id: Option<&str>, body: String) -> Self {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_owned(), TEXT_EVENT_STREAM.to_owned());
        headers.insert("cache-control".to_owned(), "no-cache".to_owned());
        if let Some(session_id) = session_id {
            headers.insert(MCP_SESSION_ID_HEADER.to_owned(), session_id.to_owned());
        }
        Self {
            status: StatusCode::OK.as_u16(),
            headers,
            body: Some(Value::String(body)),
        }
    }
}

/// OAuth protected-resource metadata for MCP HTTP deployments.
///
/// The shape follows OAuth protected-resource metadata conventions while
/// keeping fields optional enough for deployments that terminate OAuth outside
/// the AIP process.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    /// Protected resource identifier.
    pub resource: String,
    /// Authorization server issuers accepted by this resource.
    #[serde(
        rename = "authorization_servers",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub authorization_servers: Vec<String>,
    /// Bearer token presentation methods supported by this resource.
    #[serde(
        rename = "bearer_methods_supported",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub bearer_methods_supported: Vec<String>,
    /// Scopes understood by this resource.
    #[serde(
        rename = "scopes_supported",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub scopes_supported: Vec<String>,
    /// Optional human-readable documentation URL.
    #[serde(
        rename = "resource_documentation",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resource_documentation: Option<String>,
}

impl ProtectedResourceMetadata {
    /// Creates metadata with the standard bearer-header method enabled.
    #[must_use]
    pub fn bearer(resource: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            authorization_servers: Vec::new(),
            bearer_methods_supported: vec!["header".to_owned()],
            scopes_supported: Vec::new(),
            resource_documentation: None,
        }
    }
}

/// OAuth bearer challenge used for `WWW-Authenticate`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BearerChallenge {
    /// Optional realm.
    pub realm: Option<String>,
    /// Optional protected-resource metadata URL.
    pub resource_metadata_url: Option<String>,
    /// Optional required scope string.
    pub scope: Option<String>,
    /// Optional OAuth error code.
    pub error: Option<String>,
    /// Optional OAuth error description.
    pub error_description: Option<String>,
}

impl BearerChallenge {
    /// Serializes this challenge into a `WWW-Authenticate` header value.
    #[must_use]
    pub fn to_header_value(&self) -> String {
        let mut parts = Vec::new();
        if let Some(realm) = &self.realm {
            parts.push(format!("realm={}", quoted_header_value(realm)));
        }
        if let Some(resource_metadata_url) = &self.resource_metadata_url {
            parts.push(format!(
                "resource_metadata={}",
                quoted_header_value(resource_metadata_url)
            ));
        }
        if let Some(scope) = &self.scope {
            parts.push(format!("scope={}", quoted_header_value(scope)));
        }
        if let Some(error) = &self.error {
            parts.push(format!("error={}", quoted_header_value(error)));
        }
        if let Some(error_description) = &self.error_description {
            parts.push(format!(
                "error_description={}",
                quoted_header_value(error_description)
            ));
        }
        if parts.is_empty() {
            "Bearer".to_owned()
        } else {
            format!("Bearer {}", parts.join(", "))
        }
    }
}

/// Server-sent event used by streamable HTTP.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpSseEvent {
    /// Optional event id for resume cursors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Optional event type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    /// JSON-serialized data payload.
    pub data: String,
}

/// Bounded replay window for MCP Streamable HTTP SSE events.
///
/// Hosts append events before sending them to clients and use `Last-Event-ID`
/// to replay the available suffix after reconnect. The buffer is deterministic
/// and framework-neutral; deployments that need restart recovery should wrap it
/// with [`McpSseReplayFileLog`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpSseReplayBuffer {
    max_events: usize,
    next_sequence: u64,
    events: VecDeque<McpSseEvent>,
}

impl McpSseReplayBuffer {
    /// Creates an empty replay window.
    #[must_use]
    pub fn new(max_events: usize) -> Self {
        Self {
            max_events,
            next_sequence: 0,
            events: VecDeque::new(),
        }
    }

    /// Appends an event and returns the stored event with a stable id.
    pub fn append(&mut self, event: McpSseEvent) -> McpSseEvent {
        let stored = self.normalize_event(event);
        self.events.push_back(stored.clone());
        self.trim();
        stored
    }

    /// Returns events after the supplied cursor.
    ///
    /// A stale or unknown cursor replays the currently retained window. A zero
    /// limit means "no caller-imposed limit".
    #[must_use]
    pub fn replay_after(&self, last_event_id: Option<&str>, limit: usize) -> Vec<McpSseEvent> {
        let start = last_event_id
            .and_then(|cursor| {
                self.events
                    .iter()
                    .position(|event| event.id.as_deref() == Some(cursor))
            })
            .map_or(0, |position| position + 1);
        let events = self.events.iter().skip(start).cloned();
        if limit == 0 {
            events.collect()
        } else {
            events.take(limit).collect()
        }
    }

    /// Returns the number of retained events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns true when the replay window is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    fn normalize_event(&mut self, mut event: McpSseEvent) -> McpSseEvent {
        let id = event.id.take().unwrap_or_else(|| {
            let id = self.next_sequence.to_string();
            self.next_sequence = self.next_sequence.saturating_add(1);
            id
        });
        if let Ok(sequence) = id.parse::<u64>() {
            self.next_sequence = self.next_sequence.max(sequence.saturating_add(1));
        }
        event.id = Some(id);
        event
    }

    fn trim(&mut self) {
        if self.max_events == 0 {
            self.events.clear();
            return;
        }
        while self.events.len() > self.max_events {
            self.events.pop_front();
        }
    }
}

/// Durable JSONL replay log for MCP Streamable HTTP SSE events.
#[derive(Clone, Debug)]
pub struct McpSseReplayFileLog {
    path: PathBuf,
    buffer: McpSseReplayBuffer,
}

impl McpSseReplayFileLog {
    /// Opens or creates a replay log at `path`.
    pub fn open(path: impl AsRef<Path>, max_events: usize) -> McpStreamableHttpResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(replay_log_error)?;
        }
        let mut buffer = McpSseReplayBuffer::new(max_events);
        match File::open(&path) {
            Ok(file) => {
                for line in BufReader::new(file).lines() {
                    let line = line.map_err(replay_log_error)?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let event =
                        serde_json::from_str::<McpSseEvent>(&line).map_err(replay_log_error)?;
                    buffer.append(event);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                File::create(&path).map_err(replay_log_error)?;
            }
            Err(error) => return Err(replay_log_error(error)),
        }
        Ok(Self { path, buffer })
    }

    /// Appends an event to the durable log and returns the stored event.
    pub fn append(&mut self, event: McpSseEvent) -> McpStreamableHttpResult<McpSseEvent> {
        let stored = self.buffer.append(event);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(replay_log_error)?;
        serde_json::to_writer(&mut file, &stored).map_err(replay_log_error)?;
        file.write_all(b"\n").map_err(replay_log_error)?;
        file.flush().map_err(replay_log_error)?;
        Ok(stored)
    }

    /// Returns events after the supplied cursor.
    #[must_use]
    pub fn replay_after(&self, last_event_id: Option<&str>, limit: usize) -> Vec<McpSseEvent> {
        self.buffer.replay_after(last_event_id, limit)
    }

    /// Returns the log path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Classifies an HTTP request into one of the MCP streamable HTTP operations.
pub fn classify_request(
    method: &Method,
    headers: &HeaderMap,
    body: Option<Value>,
) -> McpStreamableHttpResult<McpHttpRequest> {
    match *method {
        Method::POST => Ok(McpHttpRequest::ClientMessage {
            message: Box::new(decode_json_rpc_value(
                body.ok_or(McpStreamableHttpError::MissingBody)?,
            )?),
            protocol_version: protocol_version(headers)?,
            session_id: session_id(headers)?,
        }),
        Method::GET => Ok(McpHttpRequest::Listen {
            session_id: session_id(headers)?,
            last_event_id: last_event_id(headers)?,
        }),
        Method::DELETE => Ok(McpHttpRequest::DeleteSession {
            session_id: session_id(headers)?,
        }),
        _ => Err(McpStreamableHttpError::UnsupportedMethod(
            method.as_str().to_owned(),
        )),
    }
}

/// Decodes a JSON value into an MCP JSON-RPC message.
pub fn decode_json_rpc_value(value: Value) -> McpStreamableHttpResult<McpHttpMessage> {
    let object = value
        .as_object()
        .ok_or(McpStreamableHttpError::NotJsonRpc)?;
    let jsonrpc = object
        .get("jsonrpc")
        .and_then(Value::as_str)
        .ok_or(McpStreamableHttpError::NotJsonRpc)?;
    if jsonrpc != JSONRPC_VERSION {
        return Err(McpStreamableHttpError::InvalidJsonRpcVersion(
            jsonrpc.to_owned(),
        ));
    }
    if object.get("method").is_some() && object.get("id").is_some() {
        return serde_json::from_value::<JsonRpcRequest>(Value::Object(object.clone()))
            .map(McpHttpMessage::Request)
            .map_err(|_| McpStreamableHttpError::NotJsonRpc);
    }
    if object.get("method").is_some() {
        return serde_json::from_value::<JsonRpcNotification>(Value::Object(object.clone()))
            .map(McpHttpMessage::Notification)
            .map_err(|_| McpStreamableHttpError::NotJsonRpc);
    }
    if object.get("result").is_some() || object.get("error").is_some() {
        return serde_json::from_value::<JsonRpcResponse>(Value::Object(object.clone()))
            .map(McpHttpMessage::Response)
            .map_err(|_| McpStreamableHttpError::NotJsonRpc);
    }
    Err(McpStreamableHttpError::NotJsonRpc)
}

/// Returns the MCP protocol version header.
pub fn protocol_version(headers: &HeaderMap) -> McpStreamableHttpResult<Option<String>> {
    text_header(headers, MCP_PROTOCOL_VERSION_HEADER)
}

/// Returns the MCP session id header.
pub fn session_id(headers: &HeaderMap) -> McpStreamableHttpResult<Option<String>> {
    text_header(headers, MCP_SESSION_ID_HEADER)
}

/// Returns the SSE resume cursor header.
pub fn last_event_id(headers: &HeaderMap) -> McpStreamableHttpResult<Option<String>> {
    text_header(headers, LAST_EVENT_ID_HEADER)
}

/// Extracts a bearer token from the `Authorization` header.
pub fn bearer_token(headers: &HeaderMap) -> McpStreamableHttpResult<Option<String>> {
    let Some(value) = text_header(headers, AUTHORIZATION_HEADER)? else {
        return Ok(None);
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return Ok(None);
    };
    let token = token.trim();
    Ok((!token.is_empty()).then(|| token.to_owned()))
}

/// Creates a framework-neutral 401 response with a bearer challenge.
#[must_use]
pub fn bearer_unauthorized_response(challenge: &BearerChallenge) -> McpHttpResponse {
    let mut response = McpHttpResponse {
        status: StatusCode::UNAUTHORIZED.as_u16(),
        headers: BTreeMap::new(),
        body: None,
    };
    response.headers.insert(
        WWW_AUTHENTICATE_HEADER.to_owned(),
        challenge.to_header_value(),
    );
    response
}

/// Validates a request origin against an allowlist.
pub fn validate_origin(
    origin: Option<&str>,
    allowed_origins: &[String],
    local_only: bool,
) -> McpStreamableHttpResult<()> {
    let Some(origin) = origin else {
        return Ok(());
    };
    if allowed_origins.iter().any(|allowed| allowed == origin) {
        return Ok(());
    }
    if local_only
        && (origin.starts_with("http://127.0.0.1")
            || origin.starts_with("http://localhost")
            || origin.starts_with("http://[::1]"))
    {
        return Ok(());
    }
    Err(McpStreamableHttpError::OriginRejected(origin.to_owned()))
}

/// Encodes a JSON-RPC message as one SSE event.
pub fn encode_json_rpc_sse_event(
    id: Option<&str>,
    event: Option<&str>,
    value: &Value,
) -> McpStreamableHttpResult<String> {
    let data = serde_json::to_string(value)
        .map_err(|error| McpStreamableHttpError::MalformedSse(error.to_string()))?;
    Ok(encode_sse_event(&McpSseEvent {
        id: id.map(ToOwned::to_owned),
        event: event.map(ToOwned::to_owned),
        data,
    }))
}

/// Encodes a server-sent event.
#[must_use]
pub fn encode_sse_event(event: &McpSseEvent) -> String {
    let mut rendered = String::new();
    if let Some(id) = &event.id {
        rendered.push_str("id: ");
        rendered.push_str(id);
        rendered.push('\n');
    }
    if let Some(event_type) = &event.event {
        rendered.push_str("event: ");
        rendered.push_str(event_type);
        rendered.push('\n');
    }
    for line in event.data.lines() {
        rendered.push_str("data: ");
        rendered.push_str(line);
        rendered.push('\n');
    }
    rendered.push('\n');
    rendered
}

/// Decodes a single server-sent event frame.
pub fn decode_sse_event(frame: &str) -> McpStreamableHttpResult<McpSseEvent> {
    let mut event = McpSseEvent::default();
    let mut data = Vec::new();
    for line in frame.lines() {
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(McpStreamableHttpError::MalformedSse(line.to_owned()));
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match name {
            "id" => event.id = Some(value.to_owned()),
            "event" => event.event = Some(value.to_owned()),
            "data" => data.push(value.to_owned()),
            _ => {}
        }
    }
    event.data = data.join("\n");
    Ok(event)
}

fn text_header(headers: &HeaderMap, name: &'static str) -> McpStreamableHttpResult<Option<String>> {
    headers
        .get(name)
        .map(HeaderValue::to_str)
        .transpose()
        .map(|value| value.map(ToOwned::to_owned))
        .map_err(|error| McpStreamableHttpError::InvalidHeader {
            name,
            reason: error.to_string(),
        })
}

fn replay_log_error(error: impl std::fmt::Display) -> McpStreamableHttpError {
    McpStreamableHttpError::ReplayLog(error.to_string())
}

fn quoted_header_value(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::{
        BearerChallenge, McpHttpMessage, McpHttpRequest, McpSseEvent, McpSseReplayBuffer,
        McpSseReplayFileLog, bearer_token, bearer_unauthorized_response, classify_request,
        decode_sse_event, encode_sse_event,
    };
    use http::{HeaderMap, HeaderValue, Method};
    use serde_json::json;

    #[test]
    fn classifies_post_request() {
        let mut headers = HeaderMap::new();
        headers.insert("mcp-session-id", HeaderValue::from_static("s1"));
        let classified = classify_request(
            &Method::POST,
            &headers,
            Some(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list"
            })),
        )
        .expect("classified");
        match classified {
            McpHttpRequest::ClientMessage {
                message,
                session_id,
                ..
            } => match *message {
                McpHttpMessage::Request(request) => {
                    assert_eq!(request.method, "tools/list");
                    assert_eq!(session_id.as_deref(), Some("s1"));
                }
                other => panic!("unexpected message: {other:?}"),
            },
            other => panic!("unexpected classification: {other:?}"),
        }
    }

    #[test]
    fn sse_event_round_trips() {
        let encoded = encode_sse_event(&McpSseEvent {
            id: Some("1".to_owned()),
            event: Some("message".to_owned()),
            data: "{\"jsonrpc\":\"2.0\"}".to_owned(),
        });
        let decoded = decode_sse_event(&encoded).expect("decoded");
        assert_eq!(decoded.id.as_deref(), Some("1"));
        assert_eq!(decoded.event.as_deref(), Some("message"));
        assert_eq!(decoded.data, "{\"jsonrpc\":\"2.0\"}");
    }

    #[test]
    fn bearer_auth_helpers_parse_and_challenge() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer token-123"),
        );
        assert_eq!(
            bearer_token(&headers).expect("token").as_deref(),
            Some("token-123")
        );
        let response = bearer_unauthorized_response(&BearerChallenge {
            realm: Some("aip".to_owned()),
            scope: Some("tools:call".to_owned()),
            error: Some("insufficient_scope".to_owned()),
            ..BearerChallenge::default()
        });
        assert_eq!(response.status, 401);
        assert!(response.headers["www-authenticate"].contains("Bearer"));
        assert!(response.headers["www-authenticate"].contains("scope=\"tools:call\""));
    }

    #[test]
    fn sse_replay_buffer_replays_after_cursor() {
        let mut replay = McpSseReplayBuffer::new(3);
        let first = replay.append(McpSseEvent {
            id: None,
            event: Some("message".to_owned()),
            data: "one".to_owned(),
        });
        replay.append(McpSseEvent {
            id: None,
            event: Some("message".to_owned()),
            data: "two".to_owned(),
        });
        replay.append(McpSseEvent {
            id: None,
            event: Some("message".to_owned()),
            data: "three".to_owned(),
        });

        let replayed = replay.replay_after(first.id.as_deref(), 0);
        assert_eq!(replayed.len(), 2);
        assert_eq!(replayed[0].data, "two");
        assert_eq!(replayed[1].data, "three");
    }

    #[test]
    fn sse_file_replay_log_survives_reopen() {
        let path = std::env::temp_dir().join(format!(
            "aip-mcp-sse-replay-{}-{}.jsonl",
            std::process::id(),
            time_suffix()
        ));
        {
            let mut log = McpSseReplayFileLog::open(&path, 16).expect("open log");
            log.append(McpSseEvent {
                id: None,
                event: Some("message".to_owned()),
                data: "persisted".to_owned(),
            })
            .expect("append");
        }
        let log = McpSseReplayFileLog::open(&path, 16).expect("reopen log");
        let replayed = log.replay_after(None, 0);
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].data, "persisted");
        let _ = std::fs::remove_file(path);
    }

    fn time_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    }
}
