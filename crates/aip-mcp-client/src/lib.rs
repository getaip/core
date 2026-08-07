//! MCP client bridge for AIP.
//!
//! This crate lets AIP consume external MCP servers as capability providers.
//! It owns MCP client lifecycle behavior and exposes discovered tools/resources
//! as an AIP connector without embedding MCP transport details in `aip-core`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

mod oauth;

pub use oauth::{
    AuthorizationLaunch, AuthorizationServerMetadata, InMemoryMcpOAuthCredentialStore,
    McpAccessTokenProvider, McpOAuthClientConfig, McpOAuthCredentialStore, McpOAuthTokenManager,
    OAuthTokenSet, SecretBearerToken,
};

use aip_connector::{
    CapabilityProviderConnector, Connector, ConnectorContext, ConnectorError, ConnectorResult,
    OutboundConnector,
};
use aip_core::{
    Action, ActionResult, ActionResultStatus, Capability, CapabilityContract, CapabilityId,
    CapabilityKind, CompensationContract, CompensationMode, DataContract, DataSensitivity,
    ExecutionContract, ExpectedCompletionMode, IdempotencyCollisionBehavior, IdempotencyContract,
    IdempotencyKeyScope, IdempotencyRequirement, Manifest, MessagePart, Principal, PrincipalId,
    PrincipalKind, ProfileId, ProtocolError, Resource, RetrySafety, SideEffect,
};
use aip_mcp_session::{
    InMemoryMcpCorrelationStore, McpDispatcher, McpDuplexTransport, McpFrame, McpLifecycle,
    McpRole, McpSessionError, McpSessionState, McpTransportKind, VersionTransportMatrix,
};
use aip_profile_mcp::{
    ClientCapabilities, ContentBlock, ImplementationInfo, InitializeParams, InitializeResult,
    JsonRpcError, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
    LATEST_STABLE_PROTOCOL_VERSION, McpMethod, McpProfileError, McpTool, Prompt, ResourceContents,
    ResourceTemplate, Root, SUPPORTED_PROTOCOL_VERSIONS, ServerCapabilities, Task,
};
use aip_runtime::{ActionExecutionContext, ActionHandler, CancellationToken, RuntimeResult};
use aip_schema::validation_errors_draft202012;
use aip_transport_mcp_legacy_http_sse::{
    ENDPOINT_EVENT as LEGACY_ENDPOINT_EVENT, MESSAGE_EVENT as LEGACY_MESSAGE_EVENT,
};
use aip_transport_mcp_stdio::{McpStdioFrame, decode_frame, encode_frame};
use aip_transport_mcp_streamable_http::{
    LAST_EVENT_ID_HEADER, MCP_PROTOCOL_VERSION_HEADER, MCP_SESSION_ID_HEADER, McpSseEvent,
    TEXT_EVENT_STREAM, decode_sse_event,
};
use async_trait::async_trait;
use futures_util::StreamExt;
use rand_core::{OsRng, RngCore};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    io::Write,
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{Mutex, RwLock, broadcast, mpsc},
};

const SSE_INITIAL_RECONNECT_DELAY: Duration = Duration::from_millis(100);
const SSE_MAX_RECONNECT_DELAY: Duration = Duration::from_secs(5);
const SSE_MAX_CONSECUTIVE_FAILURES: u8 = 8;
const MCP_CANCELLATION_GRACE: Duration = Duration::from_secs(2);
const MCP_HTTP_BODY_MAX_BYTES: usize = 8 * 1024 * 1024;
const MCP_CLIENT_SNAPSHOT_VERSION: u32 = 1;
const MCP_CLIENT_SNAPSHOT_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// MCP client bridge error.
#[derive(Debug, Error)]
pub enum McpClientError {
    /// MCP profile mapping failed.
    #[error("MCP profile error: {0}")]
    Profile(#[from] McpProfileError),
    /// Transport failed.
    #[error("transport error: {0}")]
    Transport(String),
    /// Peer returned a JSON-RPC error.
    #[error("peer error {code}: {message}")]
    Peer {
        /// JSON-RPC error code.
        code: i64,
        /// JSON-RPC error message.
        message: String,
        /// JSON-RPC error data.
        data: Option<Value>,
    },
    /// Peer returned an unexpected shape.
    #[error("unexpected peer response: {0}")]
    Unexpected(String),
    /// The local caller cancelled an in-flight MCP request.
    #[error("MCP request cancelled: {0}")]
    Cancelled(String),
    /// Durable host state could not be loaded or persisted safely.
    #[error("MCP client state error: {0}")]
    State(String),
}

/// Result alias for MCP client operations.
pub type McpClientResult<T> = Result<T, McpClientError>;

/// Transport-owned state required to resume one MCP session after restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpTransportResumeState {
    /// Transport that created the state.
    pub transport: McpTransportKind,
    /// Exact configured endpoint. State is rejected for a different endpoint.
    pub endpoint: String,
    /// Server-issued MCP session id.
    pub session_id: String,
    /// Negotiated stable MCP protocol version, when carried by the transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    /// Last durable SSE event id accepted by the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<String>,
}

/// Versioned durable state for one outbound MCP host connection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpClientSnapshot {
    /// Snapshot schema version.
    pub snapshot_version: u32,
    /// Configured client id that owns the snapshot.
    pub client_id: String,
    /// Last allocated JSON-RPC request sequence.
    pub request_sequence: u64,
    /// Transport-neutral negotiated session state.
    pub session: McpSessionState,
    /// Full negotiated protocol version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    /// Remote implementation metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_info: Option<ImplementationInfo>,
    /// Remote capability declaration.
    pub server_capabilities: ServerCapabilities,
    /// Last complete tool catalog.
    #[serde(default)]
    pub tools: Vec<McpTool>,
    /// Stable AIP capability-to-MCP-tool projection.
    #[serde(default)]
    pub capability_to_tool: BTreeMap<CapabilityId, String>,
    /// Last complete resource catalog.
    #[serde(default)]
    pub resources: Vec<aip_profile_mcp::McpResource>,
    /// Last complete prompt catalog.
    #[serde(default)]
    pub prompts: Vec<Prompt>,
    /// Last complete resource-template catalog.
    #[serde(default)]
    pub resource_templates: Vec<ResourceTemplate>,
    /// Durable task views received from list/get/cancel/status operations.
    #[serde(default)]
    pub tasks: Vec<Task>,
    /// Catalog invalidation generation.
    pub catalog_generation: u64,
    /// Session-owned resource subscriptions restored after a new initialize.
    #[serde(default)]
    pub resource_subscriptions: BTreeSet<String>,
    /// Transport-specific resumable session and cursor state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_resume: Option<McpTransportResumeState>,
    /// UTC persistence timestamp for operator diagnostics.
    pub persisted_at: String,
}

/// Durable backend for outbound MCP host snapshots.
#[async_trait]
pub trait McpClientStateStore: Send + Sync {
    /// Loads the snapshot owned by `client_id`.
    async fn load(&self, client_id: &str) -> McpClientResult<Option<McpClientSnapshot>>;
    /// Atomically stores the latest snapshot.
    async fn save(&self, snapshot: &McpClientSnapshot) -> McpClientResult<()>;
    /// Removes terminal session state.
    async fn delete(&self, client_id: &str) -> McpClientResult<()>;
}

/// In-memory host-state backend for embedded deployments and deterministic tests.
#[derive(Clone, Debug, Default)]
pub struct InMemoryMcpClientStateStore {
    snapshots: Arc<RwLock<BTreeMap<String, McpClientSnapshot>>>,
}

#[async_trait]
impl McpClientStateStore for InMemoryMcpClientStateStore {
    async fn load(&self, client_id: &str) -> McpClientResult<Option<McpClientSnapshot>> {
        Ok(self.snapshots.read().await.get(client_id).cloned())
    }

    async fn save(&self, snapshot: &McpClientSnapshot) -> McpClientResult<()> {
        self.snapshots
            .write()
            .await
            .insert(snapshot.client_id.clone(), snapshot.clone());
        Ok(())
    }

    async fn delete(&self, client_id: &str) -> McpClientResult<()> {
        self.snapshots.write().await.remove(client_id);
        Ok(())
    }
}

/// Single-host atomic file backend for outbound MCP host snapshots.
#[derive(Clone, Debug)]
pub struct FileMcpClientStateStore {
    path: PathBuf,
    io_lock: Arc<Mutex<()>>,
}

impl FileMcpClientStateStore {
    /// Creates a store bound to one exact state file.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            io_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Returns the configured snapshot path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait]
impl McpClientStateStore for FileMcpClientStateStore {
    async fn load(&self, client_id: &str) -> McpClientResult<Option<McpClientSnapshot>> {
        let _guard = self.io_lock.lock().await;
        let path = self.path.clone();
        let expected_client_id = client_id.to_owned();
        tokio::task::spawn_blocking(move || load_mcp_client_snapshot(&path, &expected_client_id))
            .await
            .map_err(|error| McpClientError::State(format!("snapshot reader failed: {error}")))?
    }

    async fn save(&self, snapshot: &McpClientSnapshot) -> McpClientResult<()> {
        let _guard = self.io_lock.lock().await;
        let path = self.path.clone();
        let snapshot = snapshot.clone();
        tokio::task::spawn_blocking(move || persist_mcp_client_snapshot(&path, &snapshot))
            .await
            .map_err(|error| McpClientError::State(format!("snapshot writer failed: {error}")))?
    }

    async fn delete(&self, _client_id: &str) -> McpClientResult<()> {
        let _guard = self.io_lock.lock().await;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || delete_mcp_client_snapshot(&path))
            .await
            .map_err(|error| McpClientError::State(format!("snapshot deletion failed: {error}")))?
    }
}

/// One server notification accepted by the negotiated host state machine.
#[derive(Clone, Debug, PartialEq)]
pub struct McpClientEvent {
    /// Notification method.
    pub method: McpMethod,
    /// Notification parameters.
    pub params: Option<Value>,
    /// Local receive timestamp.
    pub received_at: time::OffsetDateTime,
}

/// Operator-controlled handlers for MCP server-to-client requests.
#[async_trait]
pub trait McpHostRequestHandler: Send + Sync {
    /// Returns the roots exposed to the server.
    async fn list_roots(&self) -> McpClientResult<Vec<Root>>;
    /// Executes one sampling request under host policy.
    async fn create_message(&self, params: Value) -> McpClientResult<Value>;
    /// Executes one elicitation request under host policy.
    async fn elicit(&self, params: Value) -> McpClientResult<Value>;
}

#[derive(Clone, Debug, Default)]
struct DenyMcpHostRequestHandler;

#[async_trait]
impl McpHostRequestHandler for DenyMcpHostRequestHandler {
    async fn list_roots(&self) -> McpClientResult<Vec<Root>> {
        Err(McpClientError::Unexpected(
            "no MCP roots handler is configured".to_owned(),
        ))
    }

    async fn create_message(&self, _params: Value) -> McpClientResult<Value> {
        Err(McpClientError::Unexpected(
            "no MCP sampling handler is configured".to_owned(),
        ))
    }

    async fn elicit(&self, _params: Value) -> McpClientResult<Value> {
        Err(McpClientError::Unexpected(
            "no MCP elicitation handler is configured".to_owned(),
        ))
    }
}

/// Transport used by the MCP client bridge.
#[async_trait]
pub trait McpClientTransport: Send + Sync {
    /// Concrete MCP transport binding used for version negotiation.
    fn transport_kind(&self) -> McpTransportKind;
    /// Sends one MCP request and returns one JSON-RPC response.
    async fn request(&self, request: JsonRpcRequest) -> McpClientResult<JsonRpcResponse>;
    /// Sends one MCP notification.
    async fn notify(
        &self,
        notification: aip_profile_mcp::JsonRpcNotification,
    ) -> McpClientResult<()>;
    /// Starts any transport-owned receive pump.
    async fn start(&self) -> McpClientResult<()> {
        Ok(())
    }
    /// Returns whether the transport can receive server-initiated frames.
    fn supports_bidirectional(&self) -> bool {
        false
    }
    /// Receives one server-initiated request or notification.
    async fn next_incoming(&self) -> McpClientResult<Option<McpFrame>> {
        Ok(None)
    }
    /// Sends a response for a server-initiated request.
    async fn respond(&self, _response: JsonRpcResponse) -> McpClientResult<()> {
        Err(McpClientError::Transport(
            "transport does not support server-initiated requests".to_owned(),
        ))
    }
    /// Terminates transport-owned sessions, receive pumps, and subprocesses.
    async fn terminate(&self) -> McpClientResult<()> {
        Ok(())
    }
    /// Exports resumable transport state after an accepted frame.
    async fn export_resume_state(&self) -> McpClientResult<Option<McpTransportResumeState>> {
        Ok(None)
    }
    /// Restores transport state. Returns `false` when this binding is not resumable.
    async fn import_resume_state(&self, _state: &McpTransportResumeState) -> McpClientResult<bool> {
        Ok(false)
    }
    /// Clears imported session state before a clean initialize fallback.
    async fn clear_resume_state(&self) -> McpClientResult<()> {
        Ok(())
    }
}

/// Streamable HTTP transport for outbound MCP client bridges.
///
/// The transport owns MCP session id propagation and accepts either direct JSON
/// responses or one-message SSE responses from streamable HTTP endpoints.
#[derive(Clone)]
pub struct McpHttpClientTransport {
    client: reqwest::Client,
    endpoint: Url,
    session_id: Arc<RwLock<Option<String>>>,
    protocol_version: Arc<RwLock<Option<String>>>,
    bearer_token: Option<String>,
    token_provider: Option<Arc<dyn McpAccessTokenProvider>>,
    origin: Option<String>,
    incoming_tx: mpsc::Sender<McpClientResult<McpFrame>>,
    incoming_rx: Arc<Mutex<mpsc::Receiver<McpClientResult<McpFrame>>>>,
    listener_started: Arc<AtomicBool>,
    listener_closed: Arc<AtomicBool>,
    listener_cancellation: CancellationToken,
    last_event_id: Arc<RwLock<Option<String>>>,
}

impl McpHttpClientTransport {
    /// Creates an HTTP transport for a concrete MCP endpoint, for example
    /// `http://127.0.0.1:18080/mcp`.
    pub fn new(endpoint: impl AsRef<str>) -> McpClientResult<Self> {
        let endpoint = Url::parse(endpoint.as_ref())
            .map_err(|error| McpClientError::Transport(error.to_string()))?;
        let (incoming_tx, incoming_rx) = mpsc::channel(1_024);
        Ok(Self {
            client: reqwest::Client::new(),
            endpoint,
            session_id: Arc::default(),
            protocol_version: Arc::default(),
            bearer_token: None,
            token_provider: None,
            origin: None,
            incoming_tx,
            incoming_rx: Arc::new(Mutex::new(incoming_rx)),
            listener_started: Arc::new(AtomicBool::new(false)),
            listener_closed: Arc::new(AtomicBool::new(false)),
            listener_cancellation: CancellationToken::default(),
            last_event_id: Arc::default(),
        })
    }

    /// Adds a bearer token to all outbound Streamable HTTP requests.
    #[must_use]
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    /// Installs a production OAuth token source with refresh support.
    #[must_use]
    pub fn with_access_token_provider<P>(mut self, provider: P) -> Self
    where
        P: McpAccessTokenProvider + 'static,
    {
        self.token_provider = Some(Arc::new(provider));
        self
    }

    /// Adds an explicit Origin header accepted by the server policy.
    #[must_use]
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }

    /// Returns the currently negotiated MCP session id, if the server issued one.
    pub async fn session_id(&self) -> Option<String> {
        self.session_id.read().await.clone()
    }

    async fn post_json(&self, value: &Value) -> McpClientResult<Option<JsonRpcResponse>> {
        let mut response = self.post_json_attempt(value, false).await?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED && self.token_provider.is_some() {
            response = self.post_json_attempt(value, true).await?;
        }
        self.decode_post_response(response).await
    }

    async fn post_json_attempt(
        &self,
        value: &Value,
        force_refresh: bool,
    ) -> McpClientResult<reqwest::Response> {
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .header("accept", format!("application/json, {TEXT_EVENT_STREAM}"))
            .json(value);
        if let Some(provider) = &self.token_provider {
            let token = if force_refresh {
                provider.force_refresh().await?
            } else {
                provider.access_token().await?
            };
            request = request.bearer_auth(token.expose());
        } else if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        if let Some(origin) = &self.origin {
            request = request.header("origin", origin);
        }
        if let Some(session_id) = self.session_id.read().await.clone() {
            request = request.header(MCP_SESSION_ID_HEADER, session_id);
        }
        if let Some(protocol_version) = self.protocol_version.read().await.clone() {
            request = request.header(MCP_PROTOCOL_VERSION_HEADER, protocol_version);
        }
        request
            .send()
            .await
            .map_err(|error| McpClientError::Transport(error.to_string()))
    }

    async fn decode_post_response(
        &self,
        response: reqwest::Response,
    ) -> McpClientResult<Option<JsonRpcResponse>> {
        if let Some(session_id) = response
            .headers()
            .get(MCP_SESSION_ID_HEADER)
            .and_then(|value| value.to_str().ok())
        {
            *self.session_id.write().await = Some(session_id.to_owned());
        }
        if let Some(protocol_version) = response
            .headers()
            .get(MCP_PROTOCOL_VERSION_HEADER)
            .and_then(|value| value.to_str().ok())
        {
            *self.protocol_version.write().await = Some(protocol_version.to_owned());
        }
        let status = response.status();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let body = read_bounded_http_body(response).await?;
        if !status.is_success() {
            return Err(McpClientError::Transport(format!(
                "MCP HTTP request failed with HTTP {status}: {body}"
            )));
        }
        if body.trim().is_empty() {
            return Ok(None);
        }
        decode_http_response(content_type.as_deref(), &body).map(Some)
    }

    async fn ensure_listener(&self) -> McpClientResult<()> {
        if self.listener_started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        if self.session_id.read().await.is_none() {
            self.listener_started.store(false, Ordering::Release);
            return Err(McpClientError::Transport(
                "Streamable HTTP receive stream requires an initialized MCP session".to_owned(),
            ));
        }
        let transport = self.clone();
        tokio::spawn(async move {
            transport.run_sse_listener().await;
        });
        Ok(())
    }

    async fn run_sse_listener(self) {
        let mut reconnect_delay = SSE_INITIAL_RECONNECT_DELAY;
        let mut consecutive_failures = 0_u8;
        while !self.listener_closed.load(Ordering::Acquire) {
            let connection = tokio::select! {
                () = self.listener_cancellation.cancelled() => return,
                result = self.consume_sse_connection() => result,
            };
            match connection {
                Ok(()) => {
                    reconnect_delay = SSE_INITIAL_RECONNECT_DELAY;
                    consecutive_failures = 0;
                }
                Err(error) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    if consecutive_failures < SSE_MAX_CONSECUTIVE_FAILURES {
                        tokio::select! {
                            () = self.listener_cancellation.cancelled() => return,
                            () = tokio::time::sleep(reconnect_delay) => {}
                        }
                        reconnect_delay = (reconnect_delay * 2).min(SSE_MAX_RECONNECT_DELAY);
                        continue;
                    }
                    self.listener_closed.store(true, Ordering::Release);
                    if self.incoming_tx.send(Err(error)).await.is_err() {
                        return;
                    }
                    return;
                }
            }
            if self.listener_closed.load(Ordering::Acquire) {
                return;
            }
            tokio::select! {
                () = self.listener_cancellation.cancelled() => return,
                () = tokio::time::sleep(reconnect_delay) => {}
            }
            reconnect_delay = (reconnect_delay * 2).min(SSE_MAX_RECONNECT_DELAY);
        }
    }

    async fn consume_sse_connection(&self) -> McpClientResult<()> {
        let session_id =
            self.session_id.read().await.clone().ok_or_else(|| {
                McpClientError::Transport("MCP session id is unavailable".to_owned())
            })?;
        let protocol_version = self.protocol_version.read().await.clone().ok_or_else(|| {
            McpClientError::Transport("MCP protocol version is unavailable".to_owned())
        })?;
        let mut request = self
            .client
            .get(self.endpoint.clone())
            .header("accept", TEXT_EVENT_STREAM)
            .header(MCP_SESSION_ID_HEADER, session_id)
            .header(MCP_PROTOCOL_VERSION_HEADER, protocol_version);
        if let Some(provider) = &self.token_provider {
            let token = provider.access_token().await?;
            request = request.bearer_auth(token.expose());
        } else if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        if let Some(origin) = &self.origin {
            request = request.header("origin", origin);
        }
        if let Some(last_event_id) = self.last_event_id.read().await.clone() {
            request = request.header(LAST_EVENT_ID_HEADER, last_event_id);
        }
        let response = request
            .send()
            .await
            .map_err(|error| McpClientError::Transport(error.to_string()))?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            && let Some(provider) = &self.token_provider
        {
            let _ = provider.force_refresh().await?;
            return Err(McpClientError::Transport(
                "MCP receive stream authorization was refreshed; reconnecting".to_owned(),
            ));
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = read_bounded_http_body(response)
                .await
                .unwrap_or_else(|error| format!("<response body unavailable: {error}>"));
            return Err(McpClientError::Transport(format!(
                "MCP receive stream failed with HTTP {status}: {body}"
            )));
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !content_type.starts_with(TEXT_EVENT_STREAM) {
            return Err(McpClientError::Transport(format!(
                "MCP receive stream returned unsupported content type `{content_type}`"
            )));
        }
        let mut stream = response.bytes_stream();
        let mut buffer = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| McpClientError::Transport(error.to_string()))?;
            buffer.extend_from_slice(&chunk);
            if buffer.len() > 8 * 1024 * 1024 {
                return Err(McpClientError::Transport(
                    "MCP SSE frame exceeded the 8 MiB receive bound".to_owned(),
                ));
            }
            while let Some(frame) = take_sse_frame(&mut buffer) {
                let frame = String::from_utf8(frame)
                    .map_err(|error| McpClientError::Transport(error.to_string()))?;
                let event = decode_sse_event(&frame)
                    .map_err(|error| McpClientError::Transport(error.to_string()))?;
                if let Some(id) = event.id {
                    *self.last_event_id.write().await = Some(id);
                }
                let value: Value = serde_json::from_str(&event.data)
                    .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
                let frame = mcp_frame_from_value(value)?;
                if self.incoming_tx.send(Ok(frame)).await.is_err() {
                    self.listener_closed.store(true, Ordering::Release);
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl McpClientTransport for McpHttpClientTransport {
    fn transport_kind(&self) -> McpTransportKind {
        McpTransportKind::StreamableHttp
    }
    async fn request(&self, request: JsonRpcRequest) -> McpClientResult<JsonRpcResponse> {
        let value = serde_json::to_value(request)
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        self.post_json(&value).await?.ok_or_else(|| {
            McpClientError::Unexpected("MCP HTTP request returned no response".to_owned())
        })
    }

    async fn notify(
        &self,
        notification: aip_profile_mcp::JsonRpcNotification,
    ) -> McpClientResult<()> {
        let value = serde_json::to_value(notification)
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        let _ = self.post_json(&value).await?;
        Ok(())
    }

    fn supports_bidirectional(&self) -> bool {
        true
    }

    async fn next_incoming(&self) -> McpClientResult<Option<McpFrame>> {
        self.ensure_listener().await?;
        let mut incoming = self.incoming_rx.lock().await;
        tokio::select! {
            () = self.listener_cancellation.cancelled() => Ok(None),
            frame = incoming.recv() => match frame {
                Some(frame) => frame.map(Some),
                None => Ok(None),
            }
        }
    }

    async fn respond(&self, response: JsonRpcResponse) -> McpClientResult<()> {
        let value = serde_json::to_value(response)
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        let _ = self.post_json(&value).await?;
        Ok(())
    }

    async fn terminate(&self) -> McpClientResult<()> {
        self.listener_closed.store(true, Ordering::Release);
        self.listener_cancellation.cancel();
        let Some(session_id) = self.session_id.read().await.clone() else {
            return Ok(());
        };
        let mut request = self
            .client
            .delete(self.endpoint.clone())
            .header(MCP_SESSION_ID_HEADER, &session_id);
        if let Some(protocol_version) = self.protocol_version.read().await.clone() {
            request = request.header(MCP_PROTOCOL_VERSION_HEADER, protocol_version);
        }
        if let Some(provider) = &self.token_provider {
            request = request.bearer_auth(provider.access_token().await?.expose());
        } else if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        if let Some(origin) = &self.origin {
            request = request.header("origin", origin);
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| McpClientError::Transport(error.to_string()))?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            && let Some(provider) = &self.token_provider
        {
            let token = provider.force_refresh().await?;
            let mut retry = self
                .client
                .delete(self.endpoint.clone())
                .header(MCP_SESSION_ID_HEADER, &session_id)
                .bearer_auth(token.expose());
            if let Some(protocol_version) = self.protocol_version.read().await.clone() {
                retry = retry.header(MCP_PROTOCOL_VERSION_HEADER, protocol_version);
            }
            if let Some(origin) = &self.origin {
                retry = retry.header("origin", origin);
            }
            response = retry
                .send()
                .await
                .map_err(|error| McpClientError::Transport(error.to_string()))?;
        }
        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            let status = response.status();
            let body = read_bounded_http_body(response)
                .await
                .unwrap_or_else(|error| format!("<response body unavailable: {error}>"));
            return Err(McpClientError::Transport(format!(
                "MCP session termination failed with HTTP {status}: {body}"
            )));
        }
        *self.session_id.write().await = None;
        *self.protocol_version.write().await = None;
        Ok(())
    }

    async fn export_resume_state(&self) -> McpClientResult<Option<McpTransportResumeState>> {
        let Some(session_id) = self.session_id.read().await.clone() else {
            return Ok(None);
        };
        Ok(Some(McpTransportResumeState {
            transport: McpTransportKind::StreamableHttp,
            endpoint: self.endpoint.to_string(),
            session_id,
            protocol_version: self.protocol_version.read().await.clone(),
            last_event_id: self.last_event_id.read().await.clone(),
        }))
    }

    async fn import_resume_state(&self, state: &McpTransportResumeState) -> McpClientResult<bool> {
        if state.transport != McpTransportKind::StreamableHttp {
            return Ok(false);
        }
        validate_resume_state(state, &self.endpoint)?;
        let protocol_version = state.protocol_version.clone().ok_or_else(|| {
            McpClientError::State(
                "Streamable HTTP resume state omitted the negotiated version".to_owned(),
            )
        })?;
        *self.session_id.write().await = Some(state.session_id.clone());
        *self.protocol_version.write().await = Some(protocol_version);
        *self.last_event_id.write().await = state.last_event_id.clone();
        self.listener_closed.store(false, Ordering::Release);
        Ok(true)
    }

    async fn clear_resume_state(&self) -> McpClientResult<()> {
        *self.session_id.write().await = None;
        *self.protocol_version.write().await = None;
        *self.last_event_id.write().await = None;
        self.listener_started.store(false, Ordering::Release);
        self.listener_closed.store(false, Ordering::Release);
        Ok(())
    }
}

type LegacyByteStream =
    Pin<Box<dyn futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send>>;

#[derive(Default)]
struct LegacyReceiveState {
    stream: Option<LegacyByteStream>,
    buffer: Vec<u8>,
    pending: VecDeque<McpFrame>,
    consecutive_failures: u8,
}

struct McpLegacyHttpSseDuplex {
    client: reqwest::Client,
    sse_endpoint: Url,
    message_endpoint: RwLock<Option<Url>>,
    bearer_token: StdMutex<Option<String>>,
    token_provider: StdMutex<Option<Arc<dyn McpAccessTokenProvider>>>,
    origin: StdMutex<Option<String>>,
    state: Mutex<LegacyReceiveState>,
    last_event_id: RwLock<Option<String>>,
    connected: AtomicBool,
    closed: AtomicBool,
}

impl McpLegacyHttpSseDuplex {
    async fn ensure_connected(&self) -> McpClientResult<()> {
        if self.connected.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut state = self.state.lock().await;
        if self.connected.load(Ordering::Acquire) {
            return Ok(());
        }
        self.open_stream(&mut state, true, false).await?;
        self.connected.store(true, Ordering::Release);
        Ok(())
    }

    async fn open_stream(
        &self,
        state: &mut LegacyReceiveState,
        require_endpoint: bool,
        force_refresh: bool,
    ) -> McpClientResult<()> {
        let mut endpoint = self.sse_endpoint.clone();
        if !require_endpoint
            && let Some(message_endpoint) = self.message_endpoint.read().await.as_ref()
            && let Some(session_id) = message_endpoint
                .query_pairs()
                .find(|(key, _value)| key == "sessionId")
                .map(|(_key, value)| value.into_owned())
        {
            endpoint
                .query_pairs_mut()
                .clear()
                .append_pair("sessionId", &session_id);
        }
        let mut request = self
            .client
            .get(endpoint)
            .header("accept", TEXT_EVENT_STREAM);
        let token_provider = lock_std(&self.token_provider).clone();
        let bearer_token = lock_std(&self.bearer_token).clone();
        let origin = lock_std(&self.origin).clone();
        if let Some(provider) = &token_provider {
            let token = if force_refresh {
                provider.force_refresh().await?
            } else {
                provider.access_token().await?
            };
            request = request.bearer_auth(token.expose());
        } else if let Some(token) = &bearer_token {
            request = request.bearer_auth(token);
        }
        if let Some(origin) = &origin {
            request = request.header("origin", origin);
        }
        if !require_endpoint && let Some(last_event_id) = self.last_event_id.read().await.as_ref() {
            request = request.header(LAST_EVENT_ID_HEADER, last_event_id);
        }
        let response = request
            .send()
            .await
            .map_err(|error| McpClientError::Transport(error.to_string()))?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            && token_provider.is_some()
            && !force_refresh
        {
            return Box::pin(self.open_stream(state, require_endpoint, true)).await;
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = read_bounded_http_body(response)
                .await
                .unwrap_or_else(|error| format!("<response body unavailable: {error}>"));
            return Err(McpClientError::Transport(format!(
                "legacy MCP SSE open failed with HTTP {status}: {body}"
            )));
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !content_type.starts_with(TEXT_EVENT_STREAM) {
            return Err(McpClientError::Transport(format!(
                "legacy MCP SSE endpoint returned `{content_type}`"
            )));
        }
        state.stream = Some(Box::pin(response.bytes_stream()));
        state.buffer.clear();
        if require_endpoint {
            loop {
                let event = self.next_event(state).await?.ok_or_else(|| {
                    McpClientError::Transport(
                        "legacy MCP SSE closed before the endpoint event".to_owned(),
                    )
                })?;
                if event.name == LEGACY_ENDPOINT_EVENT {
                    let endpoint = Url::parse(&event.data)
                        .map_err(|error| McpClientError::Transport(error.to_string()))?;
                    if endpoint.scheme() != self.sse_endpoint.scheme()
                        || endpoint.host_str() != self.sse_endpoint.host_str()
                        || endpoint.port_or_known_default()
                            != self.sse_endpoint.port_or_known_default()
                    {
                        return Err(McpClientError::Transport(
                            "legacy MCP message endpoint changed origin".to_owned(),
                        ));
                    }
                    if endpoint
                        .query_pairs()
                        .all(|(key, value)| key != "sessionId" || value.is_empty())
                    {
                        return Err(McpClientError::Transport(
                            "legacy MCP endpoint event omitted sessionId".to_owned(),
                        ));
                    }
                    *self.message_endpoint.write().await = Some(endpoint);
                    break;
                }
                if event.name == LEGACY_MESSAGE_EVENT {
                    state.pending.push_back(mcp_frame_from_json(&event.data)?);
                }
            }
        }
        Ok(())
    }

    async fn next_event(
        &self,
        state: &mut LegacyReceiveState,
    ) -> McpClientResult<Option<ParsedLegacySseEvent>> {
        loop {
            if let Some(frame) = take_sse_frame(&mut state.buffer) {
                let frame = String::from_utf8(frame)
                    .map_err(|error| McpClientError::Transport(error.to_string()))?;
                if let Some(event) = parse_legacy_sse_event(&frame)? {
                    if let Some(id) = event.id.as_ref() {
                        *self.last_event_id.write().await = Some(id.clone());
                    }
                    return Ok(Some(event));
                }
            }
            let Some(stream) = state.stream.as_mut() else {
                return Ok(None);
            };
            match stream.next().await {
                Some(Ok(chunk)) => {
                    state.buffer.extend_from_slice(&chunk);
                    if state.buffer.len() > 8 * 1024 * 1024 {
                        return Err(McpClientError::Transport(
                            "legacy MCP SSE frame exceeded 8 MiB".to_owned(),
                        ));
                    }
                }
                Some(Err(error)) => return Err(McpClientError::Transport(error.to_string())),
                None => return Ok(None),
            }
        }
    }

    async fn send_frame(&self, frame: McpFrame) -> McpClientResult<()> {
        self.ensure_connected().await?;
        let endpoint = self.message_endpoint.read().await.clone().ok_or_else(|| {
            McpClientError::Transport("legacy MCP message endpoint is unavailable".to_owned())
        })?;
        let value = match frame {
            McpFrame::Request(request) => serde_json::to_value(request),
            McpFrame::Notification(notification) => serde_json::to_value(notification),
            McpFrame::Response(response) => serde_json::to_value(response),
        }
        .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        let mut request = self.client.post(endpoint).json(&value);
        let token_provider = lock_std(&self.token_provider).clone();
        let bearer_token = lock_std(&self.bearer_token).clone();
        let origin = lock_std(&self.origin).clone();
        if let Some(provider) = &token_provider {
            request = request.bearer_auth(provider.access_token().await?.expose());
        } else if let Some(token) = &bearer_token {
            request = request.bearer_auth(token);
        }
        if let Some(origin) = &origin {
            request = request.header("origin", origin);
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| McpClientError::Transport(error.to_string()))?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            && let Some(provider) = &token_provider
        {
            let token = provider.force_refresh().await?;
            let mut retry =
                self.client
                    .post(self.message_endpoint.read().await.clone().ok_or_else(|| {
                        McpClientError::Transport(
                            "legacy MCP message endpoint is unavailable".to_owned(),
                        )
                    })?);
            retry = retry.bearer_auth(token.expose()).json(&value);
            if let Some(origin) = &origin {
                retry = retry.header("origin", origin);
            }
            response = retry
                .send()
                .await
                .map_err(|error| McpClientError::Transport(error.to_string()))?;
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = read_bounded_http_body(response)
                .await
                .unwrap_or_else(|error| format!("<response body unavailable: {error}>"));
            return Err(McpClientError::Transport(format!(
                "legacy MCP message POST failed with HTTP {status}: {body}"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl McpDuplexTransport for McpLegacyHttpSseDuplex {
    async fn send(&self, frame: McpFrame) -> Result<(), McpSessionError> {
        self.send_frame(frame)
            .await
            .map_err(|error| McpSessionError::Dispatcher(error.to_string()))
    }

    async fn receive(&self) -> Result<Option<McpFrame>, McpSessionError> {
        self.ensure_connected()
            .await
            .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
        let mut reconnect_delay = SSE_INITIAL_RECONNECT_DELAY;
        loop {
            if self.closed.load(Ordering::Acquire) {
                return Ok(None);
            }
            let mut state = self.state.lock().await;
            if let Some(frame) = state.pending.pop_front() {
                state.consecutive_failures = 0;
                return Ok(Some(frame));
            }
            match self.next_event(&mut state).await {
                Ok(Some(event)) if event.name == LEGACY_MESSAGE_EVENT => {
                    state.consecutive_failures = 0;
                    return mcp_frame_from_json(&event.data)
                        .map(Some)
                        .map_err(|error| McpSessionError::Dispatcher(error.to_string()));
                }
                Ok(Some(_)) => continue,
                Ok(None) | Err(_) => {
                    state.stream = None;
                    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                    if state.consecutive_failures >= SSE_MAX_CONSECUTIVE_FAILURES {
                        return Err(McpSessionError::Dispatcher(
                            "legacy MCP SSE reconnect budget exhausted".to_owned(),
                        ));
                    }
                    drop(state);
                    tokio::time::sleep(reconnect_delay).await;
                    reconnect_delay = (reconnect_delay * 2).min(SSE_MAX_RECONNECT_DELAY);
                    let mut state = self.state.lock().await;
                    if let Err(error) = self.open_stream(&mut state, false, false).await {
                        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                        if state.consecutive_failures >= SSE_MAX_CONSECUTIVE_FAILURES {
                            return Err(McpSessionError::Dispatcher(error.to_string()));
                        }
                    }
                }
            }
        }
    }
}

/// Legacy MCP `2024-11-05` HTTP+SSE client transport.
///
/// The initial GET waits for the mandatory endpoint event before any JSON-RPC
/// frame is posted. A shared dispatcher correlates concurrent requests while
/// preserving server-to-client requests and notifications. Reconnects reuse
/// the server-issued session id and `Last-Event-ID` cursor.
#[derive(Clone)]
pub struct McpLegacyHttpSseClientTransport {
    duplex: Arc<McpLegacyHttpSseDuplex>,
    dispatcher: Arc<McpDispatcher<McpLegacyHttpSseDuplex, InMemoryMcpCorrelationStore>>,
    pump_started: Arc<AtomicBool>,
    request_timeout: Duration,
}

impl McpLegacyHttpSseClientTransport {
    /// Creates a legacy transport. Network I/O begins in [`McpClientTransport::start`].
    pub fn new(sse_endpoint: impl AsRef<str>) -> McpClientResult<Self> {
        let sse_endpoint = Url::parse(sse_endpoint.as_ref())
            .map_err(|error| McpClientError::Transport(error.to_string()))?;
        let duplex = Arc::new(McpLegacyHttpSseDuplex {
            client: reqwest::Client::new(),
            sse_endpoint,
            message_endpoint: RwLock::new(None),
            bearer_token: StdMutex::new(None),
            token_provider: StdMutex::new(None),
            origin: StdMutex::new(None),
            state: Mutex::new(LegacyReceiveState::default()),
            last_event_id: RwLock::new(None),
            connected: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        });
        let dispatcher = McpDispatcher::new(
            format!(
                "mcp-legacy-http-sse:{}",
                sse_endpoint_host(&duplex.sse_endpoint)
            ),
            duplex.clone(),
            Arc::new(InMemoryMcpCorrelationStore::default()),
            1_024,
        );
        Ok(Self {
            duplex,
            dispatcher,
            pump_started: Arc::new(AtomicBool::new(false)),
            request_timeout: Duration::from_secs(30),
        })
    }

    /// Adds a local-development static bearer token.
    #[must_use]
    pub fn with_bearer_token(self, token: impl Into<String>) -> Self {
        *lock_std(&self.duplex.bearer_token) = Some(token.into());
        self
    }

    /// Installs the production OAuth token source.
    #[must_use]
    pub fn with_access_token_provider<P>(self, provider: P) -> Self
    where
        P: McpAccessTokenProvider + 'static,
    {
        *lock_std(&self.duplex.token_provider) = Some(Arc::new(provider));
        self
    }

    /// Adds the browser Origin enforced by the server.
    #[must_use]
    pub fn with_origin(self, origin: impl Into<String>) -> Self {
        *lock_std(&self.duplex.origin) = Some(origin.into());
        self
    }

    /// Replaces the correlated request timeout.
    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    async fn ensure_pump(&self) -> McpClientResult<()> {
        self.duplex.ensure_connected().await?;
        if !self.pump_started.swap(true, Ordering::AcqRel) {
            let dispatcher = self.dispatcher.clone();
            tokio::spawn(async move {
                let _ = dispatcher.run().await;
            });
        }
        Ok(())
    }
}

#[async_trait]
impl McpClientTransport for McpLegacyHttpSseClientTransport {
    fn transport_kind(&self) -> McpTransportKind {
        McpTransportKind::LegacyHttpSse
    }

    async fn start(&self) -> McpClientResult<()> {
        self.ensure_pump().await
    }

    async fn request(&self, request: JsonRpcRequest) -> McpClientResult<JsonRpcResponse> {
        self.ensure_pump().await?;
        self.dispatcher
            .request(request, self.request_timeout)
            .await
            .map_err(|error| McpClientError::Transport(error.to_string()))
    }

    async fn notify(&self, notification: JsonRpcNotification) -> McpClientResult<()> {
        self.ensure_pump().await?;
        self.dispatcher
            .notify(notification)
            .await
            .map_err(|error| McpClientError::Transport(error.to_string()))
    }

    fn supports_bidirectional(&self) -> bool {
        true
    }

    async fn next_incoming(&self) -> McpClientResult<Option<McpFrame>> {
        self.ensure_pump().await?;
        Ok(self.dispatcher.next_incoming().await)
    }

    async fn respond(&self, response: JsonRpcResponse) -> McpClientResult<()> {
        self.ensure_pump().await?;
        self.dispatcher
            .respond(response)
            .await
            .map_err(|error| McpClientError::Transport(error.to_string()))
    }

    async fn terminate(&self) -> McpClientResult<()> {
        self.duplex.closed.store(true, Ordering::Release);
        Ok(())
    }
}

struct ParsedLegacySseEvent {
    id: Option<String>,
    name: String,
    data: String,
}

fn parse_legacy_sse_event(frame: &str) -> McpClientResult<Option<ParsedLegacySseEvent>> {
    let normalized = frame.replace("\r\n", "\n");
    let mut id = None;
    let mut name = None;
    let mut data = Vec::new();
    for line in normalized.lines() {
        if line.starts_with(':') || line.is_empty() {
            continue;
        }
        let (field, value) = line
            .split_once(':')
            .map_or((line, ""), |(field, value)| (field, value.trim_start()));
        match field {
            "id" => id = Some(value.to_owned()),
            "event" => name = Some(value.to_owned()),
            "data" => data.push(value),
            _ => {}
        }
    }
    let Some(name) = name else {
        return Ok(None);
    };
    Ok(Some(ParsedLegacySseEvent {
        id,
        name,
        data: data.join("\n"),
    }))
}

fn mcp_frame_from_json(data: &str) -> McpClientResult<McpFrame> {
    let value = serde_json::from_str(data)
        .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
    mcp_frame_from_value(value)
}

fn sse_endpoint_host(endpoint: &Url) -> String {
    endpoint
        .host_str()
        .map_or_else(|| "unknown".to_owned(), ToOwned::to_owned)
}

fn lock_std<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Stdio subprocess transport for outbound MCP client bridges.
///
/// One receive pump feeds a shared bidirectional dispatcher, allowing
/// concurrent request ids and server-initiated requests without consuming or
/// discarding unrelated frames.
pub struct McpStdioClientTransport {
    child: Arc<Mutex<Child>>,
    dispatcher: Arc<McpDispatcher<McpStdioDuplex, InMemoryMcpCorrelationStore>>,
    pump_started: AtomicBool,
    poisoned: Arc<AtomicBool>,
    termination_started: Arc<AtomicBool>,
    process_group_id: Option<u32>,
    request_timeout: Duration,
}

struct McpStdioDuplex {
    stdin: Mutex<ChildStdin>,
    stdout: Mutex<BufReader<ChildStdout>>,
    poisoned: Arc<AtomicBool>,
}

#[async_trait]
impl McpDuplexTransport for McpStdioDuplex {
    async fn send(&self, frame: McpFrame) -> Result<(), McpSessionError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(McpSessionError::Dispatcher(
                "MCP stdio subprocess is no longer usable".to_owned(),
            ));
        }
        let frame = match frame {
            McpFrame::Request(request) => McpStdioFrame::Request(request),
            McpFrame::Notification(notification) => McpStdioFrame::Notification(notification),
            McpFrame::Response(response) => McpStdioFrame::Response(response),
        };
        let bytes =
            encode_frame(&frame).map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
        let mut stdin = self.stdin.lock().await;
        stdin
            .write_all(&bytes)
            .await
            .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
        stdin
            .flush()
            .await
            .map_err(|error| McpSessionError::Dispatcher(error.to_string()))
    }

    async fn receive(&self) -> Result<Option<McpFrame>, McpSessionError> {
        let mut stdout = self.stdout.lock().await;
        let mut line = String::new();
        let bytes_read = stdout
            .read_line(&mut line)
            .await
            .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
        if bytes_read == 0 {
            return Ok(None);
        }
        let frame = decode_frame(line.as_bytes())
            .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
        Ok(Some(match frame {
            McpStdioFrame::Request(request) => McpFrame::Request(request),
            McpStdioFrame::Notification(notification) => McpFrame::Notification(notification),
            McpStdioFrame::Response(response) => McpFrame::Response(response),
        }))
    }
}

struct StdioRequestGuard {
    child: Arc<Mutex<Child>>,
    poisoned: Arc<AtomicBool>,
    termination_started: Arc<AtomicBool>,
    process_group_id: Option<u32>,
    armed: bool,
}

impl StdioRequestGuard {
    fn new(
        child: Arc<Mutex<Child>>,
        poisoned: Arc<AtomicBool>,
        termination_started: Arc<AtomicBool>,
        process_group_id: Option<u32>,
    ) -> Self {
        Self {
            child,
            poisoned,
            termination_started,
            process_group_id,
            armed: true,
        }
    }

    fn complete(&mut self) {
        self.armed = false;
    }

    async fn abort(&mut self) -> McpClientResult<()> {
        self.poisoned.store(true, Ordering::Release);
        let result = terminate_stdio_subprocess(
            &self.child,
            &self.termination_started,
            self.process_group_id,
        )
        .await;
        self.armed = false;
        result
    }
}

impl Drop for StdioRequestGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.poisoned.store(true, Ordering::Release);
        schedule_stdio_termination(
            self.child.clone(),
            self.termination_started.clone(),
            self.process_group_id,
        );
    }
}

impl Drop for McpStdioClientTransport {
    fn drop(&mut self) {
        self.poisoned.store(true, Ordering::Release);
        schedule_stdio_termination(
            self.child.clone(),
            self.termination_started.clone(),
            self.process_group_id,
        );
    }
}

impl McpStdioClientTransport {
    /// Spawns an MCP stdio server process.
    pub fn spawn(command: &str, args: &[String]) -> McpClientResult<Self> {
        let mut command_builder = Command::new(command);
        command_builder
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        #[cfg(unix)]
        command_builder.process_group(0);
        let mut child = command_builder
            .spawn()
            .map_err(|error| McpClientError::Transport(error.to_string()))?;
        #[cfg(unix)]
        let process_group_id = child.id();
        #[cfg(not(unix))]
        let process_group_id = None;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| McpClientError::Transport("child stdin was not piped".to_owned()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| McpClientError::Transport("child stdout was not piped".to_owned()))?;
        let poisoned = Arc::new(AtomicBool::new(false));
        let duplex = Arc::new(McpStdioDuplex {
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
            poisoned: poisoned.clone(),
        });
        let dispatcher = McpDispatcher::new(
            format!("mcp-stdio:{}", child.id().unwrap_or_default()),
            duplex.clone(),
            Arc::new(InMemoryMcpCorrelationStore::default()),
            1_024,
        );
        Ok(Self {
            child: Arc::new(Mutex::new(child)),
            dispatcher,
            pump_started: AtomicBool::new(false),
            poisoned,
            termination_started: Arc::new(AtomicBool::new(false)),
            process_group_id,
            request_timeout: Duration::from_secs(30),
        })
    }

    /// Replaces the request timeout used while waiting for response frames.
    #[must_use]
    pub fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    /// Terminates the MCP subprocess and all descendants that it spawned.
    ///
    /// The operation is idempotent. On Unix, the child is isolated in its own
    /// process group so cancellation cannot leave helper processes running.
    pub async fn shutdown(&self) -> McpClientResult<()> {
        self.poisoned.store(true, Ordering::Release);
        terminate_stdio_subprocess(
            &self.child,
            &self.termination_started,
            self.process_group_id,
        )
        .await
    }

    fn ensure_pump(&self) -> McpClientResult<()> {
        if self.pump_started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let dispatcher = self.dispatcher.clone();
        let poisoned = self.poisoned.clone();
        tokio::runtime::Handle::try_current()
            .map_err(|_| {
                McpClientError::Transport(
                    "MCP stdio transport requires an active Tokio runtime".to_owned(),
                )
            })?
            .spawn(async move {
                if dispatcher.run().await.is_err() {
                    poisoned.store(true, Ordering::Release);
                }
            });
        Ok(())
    }
}

#[async_trait]
impl McpClientTransport for McpStdioClientTransport {
    fn transport_kind(&self) -> McpTransportKind {
        McpTransportKind::Stdio
    }
    async fn request(&self, request: JsonRpcRequest) -> McpClientResult<JsonRpcResponse> {
        self.ensure_pump()?;
        if self.poisoned.load(Ordering::Acquire) {
            return Err(McpClientError::Transport(
                "MCP stdio subprocess is no longer usable".to_owned(),
            ));
        }
        let mut lifecycle_guard = StdioRequestGuard::new(
            self.child.clone(),
            self.poisoned.clone(),
            self.termination_started.clone(),
            self.process_group_id,
        );
        match self.dispatcher.request(request, self.request_timeout).await {
            Ok(response) => {
                lifecycle_guard.complete();
                Ok(response)
            }
            Err(error) => {
                let transport_error = McpClientError::Transport(error.to_string());
                let termination = lifecycle_guard.abort().await;
                Err(with_stdio_termination_error(transport_error, termination))
            }
        }
    }

    async fn notify(
        &self,
        notification: aip_profile_mcp::JsonRpcNotification,
    ) -> McpClientResult<()> {
        self.ensure_pump()?;
        if let Err(error) = self.dispatcher.notify(notification).await {
            self.poisoned.store(true, Ordering::Release);
            let termination = terminate_stdio_subprocess(
                &self.child,
                &self.termination_started,
                self.process_group_id,
            )
            .await;
            return Err(with_stdio_termination_error(
                McpClientError::Transport(error.to_string()),
                termination,
            ));
        }
        Ok(())
    }

    async fn start(&self) -> McpClientResult<()> {
        self.ensure_pump()
    }

    fn supports_bidirectional(&self) -> bool {
        true
    }

    async fn next_incoming(&self) -> McpClientResult<Option<McpFrame>> {
        self.ensure_pump()?;
        Ok(self.dispatcher.next_incoming().await)
    }

    async fn respond(&self, response: JsonRpcResponse) -> McpClientResult<()> {
        self.ensure_pump()?;
        self.dispatcher
            .respond(response)
            .await
            .map_err(|error| McpClientError::Transport(error.to_string()))
    }

    async fn terminate(&self) -> McpClientResult<()> {
        self.shutdown().await
    }
}

fn schedule_stdio_termination(
    child: Arc<Mutex<Child>>,
    termination_started: Arc<AtomicBool>,
    process_group_id: Option<u32>,
) {
    if termination_started.swap(true, Ordering::AcqRel) {
        return;
    }
    let _ = signal_stdio_process_group(process_group_id);
    if process_group_id.is_some() {
        std::thread::sleep(Duration::from_millis(10));
        let _ = signal_stdio_process_group(process_group_id);
    }
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(async move {
            let _ = terminate_stdio_leader(&child).await;
        });
    }
}

async fn terminate_stdio_subprocess(
    child: &Arc<Mutex<Child>>,
    termination_started: &Arc<AtomicBool>,
    process_group_id: Option<u32>,
) -> McpClientResult<()> {
    let owns_termination = !termination_started.swap(true, Ordering::AcqRel);
    let group_error = if owns_termination && process_group_id.is_some() {
        let first_error = signal_stdio_process_group(process_group_id).err();
        tokio::time::sleep(Duration::from_millis(10)).await;
        signal_stdio_process_group(process_group_id)
            .err()
            .or(first_error)
    } else {
        None
    };
    let leader_result = terminate_stdio_leader(child).await;
    if let Some(error) = group_error {
        return Err(McpClientError::Transport(format!(
            "failed to terminate MCP stdio process group: {error}"
        )));
    }
    leader_result.map_err(|error| {
        McpClientError::Transport(format!("failed to reap MCP stdio subprocess: {error}"))
    })
}

async fn terminate_stdio_leader(child: &Arc<Mutex<Child>>) -> std::io::Result<()> {
    let mut child = child.lock().await;
    match child.try_wait() {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {}
        Err(error) => return Err(error),
    }
    if let Err(error) = child.start_kill()
        && error.kind() != std::io::ErrorKind::InvalidInput
    {
        return Err(error);
    }
    child.wait().await.map(|_| ())
}

fn with_stdio_termination_error(
    original: McpClientError,
    termination: McpClientResult<()>,
) -> McpClientError {
    match termination {
        Ok(()) => original,
        Err(termination_error) => McpClientError::Transport(format!(
            "{original}; subprocess termination also failed: {termination_error}"
        )),
    }
}

#[cfg(unix)]
fn signal_stdio_process_group(process_group_id: Option<u32>) -> std::io::Result<()> {
    use nix::{errno::Errno, sys::signal::Signal, unistd::Pid};

    let Some(process_group_id) = process_group_id else {
        return Ok(());
    };
    let process_group_id = i32::try_from(process_group_id).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "MCP stdio process group id exceeds the platform PID range",
        )
    })?;
    match nix::sys::signal::killpg(Pid::from_raw(process_group_id), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(std::io::Error::from_raw_os_error(error as i32)),
    }
}

#[cfg(not(unix))]
fn signal_stdio_process_group(_process_group_id: Option<u32>) -> std::io::Result<()> {
    Ok(())
}

/// MCP client configuration.
#[derive(Clone, Debug)]
pub struct McpClientConfig {
    /// Connector id.
    pub id: String,
    /// AIP principal id exposed for this MCP server.
    pub principal_id: PrincipalId,
    /// Requested MCP protocol version.
    pub protocol_version: String,
    /// Client implementation metadata.
    pub client_info: ImplementationInfo,
    /// Stable versions accepted from the server.
    pub supported_versions: Vec<String>,
    /// Host capabilities available for server-to-client operations.
    pub capabilities: ClientCapabilities,
}

impl McpClientConfig {
    /// Creates a default config for an MCP peer.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            principal_id: PrincipalId::trusted(format!("agent:mcp:{id}")),
            id,
            protocol_version: LATEST_STABLE_PROTOCOL_VERSION.to_owned(),
            client_info: ImplementationInfo {
                name: "aip-mcp-client".to_owned(),
                title: Some("AIP MCP Client".to_owned()),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                description: Some("AIP bridge client for external MCP servers".to_owned()),
                icons: Vec::new(),
                website_url: None,
            },
            supported_versions: SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .map(|version| (*version).to_owned())
                .collect(),
            capabilities: ClientCapabilities::default(),
        }
    }
}

/// MCP client bridge.
#[derive(Clone)]
pub struct McpClient {
    config: McpClientConfig,
    transport: Arc<dyn McpClientTransport>,
    sequence: Arc<AtomicU64>,
    state: Arc<RwLock<McpClientState>>,
    host_handler: Arc<dyn McpHostRequestHandler>,
    incoming_started: Arc<AtomicBool>,
    events: broadcast::Sender<McpClientEvent>,
    state_store: Option<Arc<dyn McpClientStateStore>>,
    state_loaded: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
struct McpClientState {
    session: McpSessionState,
    protocol_version: Option<String>,
    server_info: Option<ImplementationInfo>,
    server_capabilities: ServerCapabilities,
    tools: BTreeMap<String, McpTool>,
    capability_to_tool: BTreeMap<CapabilityId, String>,
    resources: BTreeMap<String, aip_profile_mcp::McpResource>,
    prompts: BTreeMap<String, Prompt>,
    resource_templates: BTreeMap<String, ResourceTemplate>,
    tasks: BTreeMap<String, Task>,
    catalog_generation: u64,
    resource_subscriptions: BTreeSet<String>,
}

impl McpClient {
    /// Creates an MCP client over the supplied transport.
    #[must_use]
    pub fn new(config: McpClientConfig, transport: Arc<dyn McpClientTransport>) -> Self {
        let session = McpSessionState::new(
            format!("mcp-client:{}", config.id),
            McpRole::Client,
            transport.transport_kind(),
        );
        let (events, _receiver) = broadcast::channel(1_024);
        Self {
            config,
            transport,
            sequence: Arc::default(),
            state: Arc::new(RwLock::new(McpClientState {
                session,
                protocol_version: None,
                server_info: None,
                server_capabilities: ServerCapabilities::default(),
                tools: BTreeMap::new(),
                capability_to_tool: BTreeMap::new(),
                resources: BTreeMap::new(),
                prompts: BTreeMap::new(),
                resource_templates: BTreeMap::new(),
                tasks: BTreeMap::new(),
                catalog_generation: 0,
                resource_subscriptions: BTreeSet::new(),
            })),
            host_handler: Arc::new(DenyMcpHostRequestHandler),
            incoming_started: Arc::new(AtomicBool::new(false)),
            events,
            state_store: None,
            state_loaded: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Installs a durable host-state backend used for restart-safe tasks,
    /// catalogs, subscriptions, request ids, and Streamable HTTP cursors.
    #[must_use]
    pub fn with_state_store<S>(mut self, store: S) -> Self
    where
        S: McpClientStateStore + 'static,
    {
        self.state_store = Some(Arc::new(store));
        self
    }

    /// Installs operator-controlled roots, sampling, and elicitation handlers.
    #[must_use]
    pub fn with_host_handler<H>(mut self, handler: H) -> Self
    where
        H: McpHostRequestHandler + 'static,
    {
        self.host_handler = Arc::new(handler);
        self
    }

    /// Subscribes to negotiated MCP notifications.
    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<McpClientEvent> {
        self.events.subscribe()
    }

    /// Returns the local catalog invalidation generation.
    pub async fn catalog_generation(&self) -> u64 {
        self.state.read().await.catalog_generation
    }

    /// Returns the connector id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.config.id
    }

    /// Initializes the MCP peer.
    pub async fn initialize(&self) -> McpClientResult<()> {
        if self.restore_snapshot_and_resume().await? {
            return Ok(());
        }
        let result = self.initialize_inner().await;
        if let Err(error) = result {
            return match self.close().await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(McpClientError::Transport(format!(
                    "MCP initialization failed: {error}; transport cleanup failed: {cleanup}"
                ))),
            };
        }
        Ok(())
    }

    async fn restore_snapshot_and_resume(&self) -> McpClientResult<bool> {
        let Some(store) = self.state_store.as_ref() else {
            return Ok(false);
        };
        if self.state_loaded.swap(true, Ordering::AcqRel) {
            return Ok(false);
        }
        let Some(snapshot) = store.load(&self.config.id).await? else {
            return Ok(false);
        };
        validate_client_snapshot(&snapshot, &self.config, self.transport.transport_kind())?;
        self.sequence
            .fetch_max(snapshot.request_sequence, Ordering::AcqRel);
        let resumable = snapshot.session.lifecycle == McpLifecycle::Initialized
            && snapshot.transport_resume.is_some();
        self.apply_snapshot(&snapshot, resumable).await;
        if !resumable {
            return Ok(false);
        }
        let resume = snapshot.transport_resume.as_ref().ok_or_else(|| {
            McpClientError::State("resumable snapshot omitted transport state".to_owned())
        })?;
        if !self.transport.import_resume_state(resume).await? {
            self.reset_session_for_initialize().await;
            return Ok(false);
        }
        let probe = async {
            self.transport.start().await?;
            let response = self.send(McpMethod::Ping, None).await?;
            expect_result(response)?;
            Ok::<(), McpClientError>(())
        }
        .await;
        if probe.is_ok() {
            self.start_incoming_loop();
            self.persist_state().await?;
            return Ok(true);
        }
        self.transport.clear_resume_state().await?;
        self.reset_session_for_initialize().await;
        Ok(false)
    }

    async fn apply_snapshot(&self, snapshot: &McpClientSnapshot, restore_session: bool) {
        let session = if restore_session {
            snapshot.session.clone()
        } else {
            McpSessionState::new(
                format!("mcp-client:{}", self.config.id),
                McpRole::Client,
                self.transport.transport_kind(),
            )
        };
        let mut state = self.state.write().await;
        state.session = session;
        state.protocol_version = snapshot.protocol_version.clone();
        state.server_info = snapshot.server_info.clone();
        state.server_capabilities = snapshot.server_capabilities.clone();
        state.tools = snapshot
            .tools
            .iter()
            .cloned()
            .map(|tool| (tool.name.clone(), tool))
            .collect();
        state.capability_to_tool = snapshot.capability_to_tool.clone();
        state.resources = snapshot
            .resources
            .iter()
            .cloned()
            .map(|resource| (resource.uri.clone(), resource))
            .collect();
        state.prompts = snapshot
            .prompts
            .iter()
            .cloned()
            .map(|prompt| (prompt.name.clone(), prompt))
            .collect();
        state.resource_templates = snapshot
            .resource_templates
            .iter()
            .cloned()
            .map(|template| (template.uri_template.clone(), template))
            .collect();
        state.tasks = snapshot
            .tasks
            .iter()
            .cloned()
            .map(|task| (task.task_id.clone(), task))
            .collect();
        state.catalog_generation = snapshot.catalog_generation;
        state.resource_subscriptions = snapshot.resource_subscriptions.clone();
    }

    async fn reset_session_for_initialize(&self) {
        let mut state = self.state.write().await;
        state.session = McpSessionState::new(
            format!("mcp-client:{}", self.config.id),
            McpRole::Client,
            self.transport.transport_kind(),
        );
        state.protocol_version = None;
        state.server_info = None;
        state.server_capabilities = ServerCapabilities::default();
    }

    async fn persist_state(&self) -> McpClientResult<()> {
        let Some(store) = self.state_store.as_ref() else {
            return Ok(());
        };
        let resume = self.transport.export_resume_state().await?;
        let state = self.state.read().await.clone();
        let persisted_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| McpClientError::State(error.to_string()))?;
        let snapshot = McpClientSnapshot {
            snapshot_version: MCP_CLIENT_SNAPSHOT_VERSION,
            client_id: self.config.id.clone(),
            request_sequence: self.sequence.load(Ordering::Acquire),
            session: state.session,
            protocol_version: state.protocol_version,
            server_info: state.server_info,
            server_capabilities: state.server_capabilities,
            tools: state.tools.into_values().collect(),
            capability_to_tool: state.capability_to_tool,
            resources: state.resources.into_values().collect(),
            prompts: state.prompts.into_values().collect(),
            resource_templates: state.resource_templates.into_values().collect(),
            tasks: state.tasks.into_values().collect(),
            catalog_generation: state.catalog_generation,
            resource_subscriptions: state.resource_subscriptions,
            transport_resume: resume,
            persisted_at,
        };
        validate_client_snapshot(&snapshot, &self.config, self.transport.transport_kind())?;
        store.save(&snapshot).await
    }

    async fn initialize_inner(&self) -> McpClientResult<()> {
        self.transport.start().await?;
        let params = serde_json::to_value(InitializeParams {
            protocol_version: self.config.protocol_version.clone(),
            capabilities: self.config.capabilities.clone(),
            client_info: self.config.client_info.clone(),
        })
        .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        {
            let mut state = self.state.write().await;
            state
                .session
                .authorize_outbound_request(McpMethod::Initialize)
                .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
            state
                .session
                .begin_initialize_with_supported(
                    &self.config.protocol_version,
                    &VersionTransportMatrix::default(),
                    &self.config.supported_versions,
                )
                .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        }
        let id = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let response = self
            .transport
            .request(JsonRpcRequest::new(
                json!(id),
                McpMethod::Initialize,
                Some(params),
            ))
            .await?;
        if let Some(error) = response.error {
            return Err(McpClientError::Peer {
                code: error.code,
                message: error.message,
                data: error.data,
            });
        }
        let result = response.result.ok_or_else(|| {
            McpClientError::Unexpected("initialize response did not contain result".to_owned())
        })?;
        let initialized: InitializeResult = serde_json::from_value(result)
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        {
            let mut state = self.state.write().await;
            state
                .session
                .accept_negotiated_version(
                    &initialized.protocol_version,
                    &VersionTransportMatrix::default(),
                    &self.config.supported_versions,
                )
                .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
            state
                .session
                .set_capabilities(&self.config.capabilities, &initialized.capabilities);
            state.protocol_version = Some(initialized.protocol_version);
            state.server_info = Some(initialized.server_info);
            state.server_capabilities = initialized.capabilities;
        }
        self.transport
            .notify(aip_profile_mcp::JsonRpcNotification::new(
                McpMethod::Initialized,
                None,
            ))
            .await?;
        self.state
            .write()
            .await
            .session
            .mark_initialized()
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        self.start_incoming_loop();
        let subscriptions = self
            .state
            .read()
            .await
            .resource_subscriptions
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        for uri in subscriptions {
            expect_result(
                self.send(McpMethod::ResourcesSubscribe, Some(json!({ "uri": uri })))
                    .await?,
            )?;
        }
        self.persist_state().await?;
        Ok(())
    }

    /// Closes the negotiated MCP session and all transport-owned resources.
    ///
    /// Streamable HTTP sends the normative DELETE request, stdio terminates the
    /// complete subprocess group, and legacy HTTP+SSE stops its receive pump.
    /// The operation is idempotent and can also clean up a failed initialize.
    pub async fn close(&self) -> McpClientResult<()> {
        {
            let mut state = self.state.write().await;
            match state.session.lifecycle {
                McpLifecycle::Closed => return Ok(()),
                McpLifecycle::Closing => {}
                _ => state
                    .session
                    .begin_close()
                    .map_err(|error| McpClientError::Unexpected(error.to_string()))?,
            }
        }
        self.transport.terminate().await?;
        let mut state = self.state.write().await;
        if state.session.lifecycle == McpLifecycle::Closing {
            state
                .session
                .finish_close()
                .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        }
        drop(state);
        if let Some(store) = self.state_store.as_ref() {
            store.delete(&self.config.id).await?;
        }
        Ok(())
    }

    fn start_incoming_loop(&self) {
        if !self.transport.supports_bidirectional()
            || self.incoming_started.swap(true, Ordering::AcqRel)
        {
            return;
        }
        let client = self.clone();
        tokio::spawn(async move {
            let _ = client.run_incoming_loop().await;
        });
    }

    async fn run_incoming_loop(&self) -> McpClientResult<()> {
        while let Some(frame) = self.transport.next_incoming().await? {
            match frame {
                McpFrame::Request(request) => self.handle_server_request(request).await?,
                McpFrame::Notification(notification) => {
                    self.handle_server_notification(notification).await?;
                }
                McpFrame::Response(response) => {
                    return Err(McpClientError::Unexpected(format!(
                        "received an unclaimed MCP response with id {}",
                        response.id
                    )));
                }
            }
            self.persist_state().await?;
        }
        Ok(())
    }

    async fn handle_server_request(&self, request: JsonRpcRequest) -> McpClientResult<()> {
        let method = request.method_kind()?;
        let authorization = self.state.read().await.session.authorize_request(method);
        let result = match authorization {
            Ok(()) => self.execute_server_request(method, request.params).await,
            Err(error) => Err(JsonRpcError {
                code: error.json_rpc_code(),
                message: error.to_string(),
                data: Some(json!({ "session": "aip-mcp-client" })),
            }),
        };
        let response = match result {
            Ok(result) => JsonRpcResponse::success(request.id, result),
            Err(error) => JsonRpcResponse::error(request.id, error),
        };
        self.transport.respond(response).await
    }

    async fn execute_server_request(
        &self,
        method: McpMethod,
        params: Option<Value>,
    ) -> Result<Value, JsonRpcError> {
        let operation = match method {
            McpMethod::RootsList => self.host_handler.list_roots().await.and_then(|roots| {
                serde_json::to_value(json!({ "roots": roots }))
                    .map_err(|error| McpClientError::Unexpected(error.to_string()))
            }),
            McpMethod::SamplingCreateMessage => {
                self.host_handler
                    .create_message(params.unwrap_or_else(|| json!({})))
                    .await
            }
            McpMethod::ElicitationCreate => {
                self.host_handler
                    .elicit(params.unwrap_or_else(|| json!({})))
                    .await
            }
            _ => Err(McpClientError::Unexpected(format!(
                "unsupported server-to-client method `{method}`"
            ))),
        };
        operation.map_err(|error| JsonRpcError {
            code: -32603,
            message: error.to_string(),
            data: Some(json!({ "method": method.as_str() })),
        })
    }

    async fn handle_server_notification(
        &self,
        notification: JsonRpcNotification,
    ) -> McpClientResult<()> {
        let method: McpMethod = notification.method.parse()?;
        self.state
            .read()
            .await
            .session
            .authorize_notification(method)
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        {
            let mut state = self.state.write().await;
            match method {
                McpMethod::ToolsListChanged => {
                    state.tools.clear();
                    state.capability_to_tool.clear();
                    state.catalog_generation = state.catalog_generation.saturating_add(1);
                }
                McpMethod::ResourcesListChanged => {
                    state.resources.clear();
                    state.resource_templates.clear();
                    state.catalog_generation = state.catalog_generation.saturating_add(1);
                }
                McpMethod::PromptsListChanged => {
                    state.prompts.clear();
                    state.catalog_generation = state.catalog_generation.saturating_add(1);
                }
                McpMethod::TasksStatus => {
                    if let Some(task) = notification
                        .params
                        .as_ref()
                        .and_then(|params| {
                            params.get("task").cloned().or_else(|| Some(params.clone()))
                        })
                        .and_then(|value| serde_json::from_value::<Task>(value).ok())
                    {
                        state.tasks.insert(task.task_id.clone(), task);
                    }
                }
                _ => {}
            }
        }
        let _ = self.events.send(McpClientEvent {
            method,
            params: notification.params,
            received_at: time::OffsetDateTime::now_utc(),
        });
        Ok(())
    }

    /// Refreshes tools and resources from the MCP peer.
    pub async fn refresh_manifest(&self) -> McpClientResult<Manifest> {
        let tools = self.list_tools().await?;
        let resources = self.list_resources().await.unwrap_or_default();
        let agent = Principal::new(self.config.principal_id.clone(), PrincipalKind::Agent);
        let mut capabilities = Vec::with_capacity(tools.len());
        let mut capability_to_tool = BTreeMap::new();
        for tool in tools {
            let capability_id = CapabilityId::trusted(format!(
                "cap:mcp:{}:{}",
                self.config.id,
                sanitize_tool_name(&tool.name)
            ));
            capability_to_tool.insert(capability_id.clone(), tool.name.clone());
            capabilities.push(capability_from_tool(capability_id, &tool));
        }
        let resources = resources
            .into_iter()
            .map(|resource| Resource {
                id: resource.uri,
                name: resource.name,
                kind: Some("mcp.resource".to_owned()),
                capability_id: None,
                description: resource.description,
                mime_type: resource.mime_type,
                tenant_id: None,
                access: None,
                expires_at: None,
            })
            .collect::<Vec<_>>();
        {
            let mut state = self.state.write().await;
            state.capability_to_tool = capability_to_tool;
        }
        self.persist_state().await?;
        let protocol_version = self.state.read().await.protocol_version.clone();
        Ok(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent,
            capabilities,
            profiles: vec![ProfileId::from(aip_profile_mcp::PROFILE_ID)],
            resources,
            channels: Vec::new(),
            security: None,
            governance: None,
            limits: None,
            compatibility: Some(json!({
                "mcp": {
                    "client_bridge": true,
                    "protocol_version": protocol_version
                }
            })),
            extensions: None,
        })
    }

    /// Lists tools from the MCP peer.
    pub async fn list_tools(&self) -> McpClientResult<Vec<McpTool>> {
        let values = self
            .collect_paginated(McpMethod::ToolsList, "tools")
            .await?;
        let parsed = serde_json::from_value::<Vec<McpTool>>(Value::Array(values))
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        let mut state = self.state.write().await;
        state.tools = parsed
            .iter()
            .map(|tool| (tool.name.clone(), tool.clone()))
            .collect();
        drop(state);
        self.persist_state().await?;
        Ok(parsed)
    }

    /// Lists resources from the MCP peer.
    pub async fn list_resources(&self) -> McpClientResult<Vec<aip_profile_mcp::McpResource>> {
        let values = self
            .collect_paginated(McpMethod::ResourcesList, "resources")
            .await?;
        let parsed =
            serde_json::from_value::<Vec<aip_profile_mcp::McpResource>>(Value::Array(values))
                .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        let mut state = self.state.write().await;
        state.resources = parsed
            .iter()
            .map(|resource| (resource.uri.clone(), resource.clone()))
            .collect();
        drop(state);
        self.persist_state().await?;
        Ok(parsed)
    }

    /// Reads one resource from the MCP peer.
    pub async fn read_resource(&self, uri: &str) -> McpClientResult<Vec<ResourceContents>> {
        let response = self
            .send(McpMethod::ResourcesRead, Some(json!({ "uri": uri })))
            .await?;
        let result = expect_result(response)?;
        serde_json::from_value(result.get("contents").cloned().unwrap_or_else(|| json!([])))
            .map_err(|error| McpClientError::Unexpected(error.to_string()))
    }

    /// Lists every resource template across all pages.
    pub async fn list_resource_templates(&self) -> McpClientResult<Vec<ResourceTemplate>> {
        let values = self
            .collect_paginated(McpMethod::ResourcesTemplatesList, "resourceTemplates")
            .await?;
        let templates = serde_json::from_value::<Vec<ResourceTemplate>>(Value::Array(values))
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        self.state.write().await.resource_templates = templates
            .iter()
            .map(|template| (template.uri_template.clone(), template.clone()))
            .collect();
        self.persist_state().await?;
        Ok(templates)
    }

    /// Subscribes to updates for one resource URI.
    pub async fn subscribe_resource(&self, uri: &str) -> McpClientResult<()> {
        expect_result(
            self.send(McpMethod::ResourcesSubscribe, Some(json!({ "uri": uri })))
                .await?,
        )?;
        self.state
            .write()
            .await
            .resource_subscriptions
            .insert(uri.to_owned());
        self.persist_state().await?;
        Ok(())
    }

    /// Removes one resource subscription.
    pub async fn unsubscribe_resource(&self, uri: &str) -> McpClientResult<()> {
        expect_result(
            self.send(McpMethod::ResourcesUnsubscribe, Some(json!({ "uri": uri })))
                .await?,
        )?;
        self.state.write().await.resource_subscriptions.remove(uri);
        self.persist_state().await?;
        Ok(())
    }

    /// Lists every prompt across all pages.
    pub async fn list_prompts(&self) -> McpClientResult<Vec<Prompt>> {
        let values = self
            .collect_paginated(McpMethod::PromptsList, "prompts")
            .await?;
        let prompts = serde_json::from_value::<Vec<Prompt>>(Value::Array(values))
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        self.state.write().await.prompts = prompts
            .iter()
            .map(|prompt| (prompt.name.clone(), prompt.clone()))
            .collect();
        self.persist_state().await?;
        Ok(prompts)
    }

    /// Renders one prompt with string arguments.
    pub async fn get_prompt(
        &self,
        name: &str,
        arguments: BTreeMap<String, String>,
    ) -> McpClientResult<Value> {
        expect_result(
            self.send(
                McpMethod::PromptsGet,
                Some(json!({ "name": name, "arguments": arguments })),
            )
            .await?,
        )
    }

    /// Completes one prompt or resource argument.
    pub async fn complete(&self, reference: Value, argument: Value) -> McpClientResult<Value> {
        expect_result(
            self.send(
                McpMethod::CompletionComplete,
                Some(json!({ "ref": reference, "argument": argument })),
            )
            .await?,
        )
    }

    /// Lists all server tasks across pages.
    pub async fn list_tasks(&self) -> McpClientResult<Vec<Task>> {
        let values = self
            .collect_paginated(McpMethod::TasksList, "tasks")
            .await?;
        let tasks: Vec<Task> = serde_json::from_value(Value::Array(values))
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        self.state.write().await.tasks = tasks
            .iter()
            .cloned()
            .map(|task| (task.task_id.clone(), task))
            .collect();
        self.persist_state().await?;
        Ok(tasks)
    }

    /// Gets one task view.
    pub async fn get_task(&self, task_id: &str) -> McpClientResult<Task> {
        let result = expect_result(
            self.send(McpMethod::TasksGet, Some(json!({ "taskId": task_id })))
                .await?,
        )?;
        let task: Task = serde_json::from_value(result.get("task").cloned().unwrap_or(result))
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        self.state
            .write()
            .await
            .tasks
            .insert(task.task_id.clone(), task.clone());
        self.persist_state().await?;
        Ok(task)
    }

    /// Polls the terminal result for one task.
    pub async fn task_result(&self, task_id: &str) -> McpClientResult<Value> {
        expect_result(
            self.send(McpMethod::TasksResult, Some(json!({ "taskId": task_id })))
                .await?,
        )
    }

    /// Cancels one server task.
    pub async fn cancel_task(&self, task_id: &str) -> McpClientResult<Task> {
        let result = expect_result(
            self.send(McpMethod::TasksCancel, Some(json!({ "taskId": task_id })))
                .await?,
        )?;
        let task: Task = serde_json::from_value(result.get("task").cloned().unwrap_or(result))
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        self.state
            .write()
            .await
            .tasks
            .insert(task.task_id.clone(), task.clone());
        self.persist_state().await?;
        Ok(task)
    }

    /// Calls an MCP tool.
    pub async fn call_tool(&self, name: &str, arguments: Value) -> McpClientResult<Value> {
        let response = self
            .send(
                McpMethod::ToolsCall,
                Some(json!({
                    "name": name,
                    "arguments": arguments
                })),
            )
            .await?;
        let result = expect_result(response)?;
        self.validate_tool_result(name, result).await
    }

    /// Calls an MCP tool and propagates cooperative AIP cancellation to the
    /// peer through `notifications/cancelled` using the exact request id.
    ///
    /// The transport request runs in an owned task so cancellation still
    /// reaches the peer when an outer runtime timeout drops the connector
    /// future. The client consumes a prompt terminal response during a bounded
    /// grace period; an unresponsive stdio peer is then terminated by its
    /// transport lifecycle guard instead of being orphaned.
    pub async fn call_tool_with_cancellation(
        &self,
        name: &str,
        arguments: Value,
        cancellation: CancellationToken,
    ) -> McpClientResult<Value> {
        let response = self
            .send_with_cancellation(
                McpMethod::ToolsCall,
                Some(json!({
                    "name": name,
                    "arguments": arguments
                })),
                cancellation,
            )
            .await?;
        let result = expect_result(response)?;
        self.validate_tool_result(name, result).await
    }

    async fn validate_tool_result(&self, name: &str, result: Value) -> McpClientResult<Value> {
        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !is_error
            && let Some(schema) = self
                .state
                .read()
                .await
                .tools
                .get(name)
                .and_then(|tool| tool.output_schema.as_ref())
        {
            let structured = result
                .get("structuredContent")
                .or_else(|| result.get("structured_content"))
                .unwrap_or(&Value::Null);
            let errors = validation_errors_draft202012(schema, Some(structured), 1_024).map_err(
                |error| McpClientError::Unexpected(format!("invalid tool output schema: {error}")),
            )?;
            if !errors.is_empty() {
                return Err(McpClientError::Unexpected(format!(
                    "tool `{name}` result violates outputSchema: {}",
                    errors.join("; ")
                )));
            }
        }
        if let Some(task) = result
            .get("task")
            .cloned()
            .and_then(|value| serde_json::from_value::<Task>(value).ok())
        {
            self.state
                .write()
                .await
                .tasks
                .insert(task.task_id.clone(), task);
            self.persist_state().await?;
        }
        Ok(result)
    }

    async fn collect_paginated(
        &self,
        method: McpMethod,
        field: &str,
    ) -> McpClientResult<Vec<Value>> {
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..10_000 {
            let params = cursor
                .as_ref()
                .map_or_else(|| json!({}), |cursor| json!({ "cursor": cursor }));
            let result = expect_result(self.send(method, Some(params)).await?)?;
            let page = result.get(field).and_then(Value::as_array).ok_or_else(|| {
                McpClientError::Unexpected(format!("{method} response is missing array `{field}`"))
            })?;
            items.extend(page.iter().cloned());
            let next = result
                .get("nextCursor")
                .or_else(|| result.get("next_cursor"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let Some(next) = next else {
                return Ok(items);
            };
            if !seen.insert(next.clone()) {
                return Err(McpClientError::Unexpected(format!(
                    "{method} repeated pagination cursor `{next}`"
                )));
            }
            cursor = Some(next);
        }
        Err(McpClientError::Unexpected(format!(
            "{method} exceeded the 10000-page safety bound"
        )))
    }

    async fn send(
        &self,
        method: McpMethod,
        params: Option<Value>,
    ) -> McpClientResult<JsonRpcResponse> {
        self.state
            .read()
            .await
            .session
            .authorize_outbound_request(method)
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        let id = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let response = self
            .transport
            .request(JsonRpcRequest::new(json!(id), method, params))
            .await?;
        if let Some(error) = response.error {
            return Err(McpClientError::Peer {
                code: error.code,
                message: error.message,
                data: error.data,
            });
        }
        Ok(response)
    }

    async fn send_with_cancellation(
        &self,
        method: McpMethod,
        params: Option<Value>,
        cancellation: CancellationToken,
    ) -> McpClientResult<JsonRpcResponse> {
        self.state
            .read()
            .await
            .session
            .authorize_outbound_request(method)
            .map_err(|error| McpClientError::Unexpected(error.to_string()))?;
        let id = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let request_id = json!(id);
        let request = JsonRpcRequest::new(request_id.clone(), method, params);
        let transport = self.transport.clone();
        let operation = tokio::spawn(async move {
            let request_future = transport.request(request);
            tokio::pin!(request_future);
            tokio::select! {
                response = &mut request_future => response,
                () = cancellation.cancelled() => {
                    transport
                        .notify(JsonRpcNotification::new(
                            McpMethod::Cancelled,
                            Some(json!({
                                "requestId": request_id,
                                "reason": "AIP action cancellation requested"
                            })),
                        ))
                        .await?;
                    let _ = tokio::time::timeout(
                        MCP_CANCELLATION_GRACE,
                        &mut request_future,
                    )
                    .await;
                    Err(McpClientError::Cancelled(
                        "AIP action cancellation requested".to_owned(),
                    ))
                }
            }
        });
        let response = operation.await.map_err(|error| {
            McpClientError::Transport(format!("MCP request task failed: {error}"))
        })??;
        if let Some(error) = response.error {
            return Err(McpClientError::Peer {
                code: error.code,
                message: error.message,
                data: error.data,
            });
        }
        Ok(response)
    }
}

/// MCP client connector that exposes an external MCP server as AIP capabilities.
#[derive(Clone)]
pub struct McpClientConnector {
    client: McpClient,
    manifest: Arc<RwLock<Option<Manifest>>>,
}

impl McpClientConnector {
    /// Creates a connector from an initialized or lazy MCP client.
    #[must_use]
    pub fn new(client: McpClient) -> Self {
        Self {
            client,
            manifest: Arc::default(),
        }
    }

    async fn tool_name(&self, capability_id: &CapabilityId) -> ConnectorResult<String> {
        self.client
            .state
            .read()
            .await
            .capability_to_tool
            .get(capability_id)
            .cloned()
            .ok_or_else(|| {
                ConnectorError::Invoke(format!(
                    "capability `{capability_id}` is not mapped to an MCP tool"
                ))
            })
    }

    /// Refreshes and stores the current connector manifest.
    pub async fn refresh(&self) -> ConnectorResult<Manifest> {
        let manifest = self
            .client
            .refresh_manifest()
            .await
            .map_err(|error| ConnectorError::Discovery(error.to_string()))?;
        *self.manifest.write().await = Some(manifest.clone());
        Ok(manifest)
    }
}

#[async_trait]
impl Connector for McpClientConnector {
    fn id(&self) -> &str {
        self.client.id()
    }

    async fn discover(&self, _context: &ConnectorContext) -> ConnectorResult<Manifest> {
        if let Some(manifest) = self.manifest.read().await.clone() {
            return Ok(manifest);
        }
        self.refresh().await
    }

    fn map_error(&self, error: &ConnectorError) -> ProtocolError {
        ProtocolError {
            code: "mcp.connector".to_owned(),
            message: error.to_string(),
            category: aip_core::ErrorCategory::Connector,
            retryable: Some(false),
            retry_after_ms: None,
            details: None,
            source: Some(Box::new(json!({ "connector": self.id() }))),
        }
    }
}

#[async_trait]
impl CapabilityProviderConnector for McpClientConnector {
    async fn capabilities(&self, context: &ConnectorContext) -> ConnectorResult<Vec<Capability>> {
        Ok(self.discover(context).await?.capabilities)
    }
}

#[async_trait]
impl OutboundConnector for McpClientConnector {
    async fn invoke(
        &self,
        _context: &ConnectorContext,
        action: Action,
    ) -> ConnectorResult<ActionResult> {
        let tool_name = self.tool_name(&action.capability_id).await?;
        let result = self
            .client
            .call_tool(&tool_name, action.input)
            .await
            .map_err(|error| ConnectorError::Invoke(error.to_string()))?;
        Ok(action_result_from_mcp(action.id, result))
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
impl ActionHandler for McpClientConnector {
    fn implementation_support(&self) -> aip_discovery::CapabilityImplementationSupport {
        aip_discovery::CapabilityImplementationSupport {
            invocation: true,
            cancellation: true,
            ..aip_discovery::CapabilityImplementationSupport::default()
        }
    }

    async fn handle(&self, action: Action) -> RuntimeResult<ActionResult> {
        self.invoke(&ConnectorContext::default(), action)
            .await
            .map_err(|error| aip_runtime::RuntimeError::Handler(error.to_string()))
    }

    async fn handle_with_context(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> RuntimeResult<ActionResult> {
        let tool_name = self
            .tool_name(&action.capability_id)
            .await
            .map_err(|error| aip_runtime::RuntimeError::Handler(error.to_string()))?;
        match self
            .client
            .call_tool_with_cancellation(&tool_name, action.input, context.cancellation)
            .await
        {
            Ok(result) => Ok(action_result_from_mcp(action.id, result)),
            Err(McpClientError::Cancelled(reason)) => Ok(ActionResult {
                action_id: action.id,
                status: ActionResultStatus::Cancelled,
                output: Some(json!({ "cancelled": true, "reason": reason })),
                message: Vec::new(),
                memory_update: None,
                usage: None,
                receipt: None,
                error: None,
            }),
            Err(error) => Err(aip_runtime::RuntimeError::Handler(error.to_string())),
        }
    }
}

/// In-memory transport useful for tests and embedded deterministic bridges.
#[derive(Clone, Debug, Default)]
pub struct InMemoryMcpTransport {
    responses: Arc<RwLock<BTreeMap<String, Value>>>,
    notifications: Arc<RwLock<Vec<aip_profile_mcp::JsonRpcNotification>>>,
}

impl InMemoryMcpTransport {
    /// Registers a result for a method.
    pub async fn register_result(&self, method: McpMethod, result: Value) {
        self.responses
            .write()
            .await
            .insert(method.as_str().to_owned(), result);
    }

    /// Returns captured notifications.
    pub async fn notifications(&self) -> Vec<aip_profile_mcp::JsonRpcNotification> {
        self.notifications.read().await.clone()
    }
}

#[async_trait]
impl McpClientTransport for InMemoryMcpTransport {
    fn transport_kind(&self) -> McpTransportKind {
        McpTransportKind::Stdio
    }
    async fn request(&self, request: JsonRpcRequest) -> McpClientResult<JsonRpcResponse> {
        let result = self
            .responses
            .read()
            .await
            .get(&request.method)
            .cloned()
            .ok_or_else(|| {
                McpClientError::Unexpected(format!("no response for {}", request.method))
            })?;
        Ok(JsonRpcResponse::success(request.id, result))
    }

    async fn notify(
        &self,
        notification: aip_profile_mcp::JsonRpcNotification,
    ) -> McpClientResult<()> {
        self.notifications.write().await.push(notification);
        Ok(())
    }
}

fn expect_result(response: JsonRpcResponse) -> McpClientResult<Value> {
    response
        .result
        .ok_or_else(|| McpClientError::Unexpected("response did not include result".to_owned()))
}

async fn read_bounded_http_body(response: reqwest::Response) -> McpClientResult<String> {
    let body = read_bounded_http_bytes(response, MCP_HTTP_BODY_MAX_BYTES).await?;
    String::from_utf8(body).map_err(|error| McpClientError::Unexpected(error.to_string()))
}

pub(crate) async fn read_bounded_http_bytes(
    response: reqwest::Response,
    max_bytes: usize,
) -> McpClientResult<Vec<u8>> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| McpClientError::Transport(error.to_string()))?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(McpClientError::Transport(format!(
                "MCP HTTP body exceeded the {max_bytes}-byte receive bound"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn decode_http_response(
    content_type: Option<&str>,
    body: &str,
) -> McpClientResult<JsonRpcResponse> {
    if content_type.is_some_and(|value| value.starts_with(TEXT_EVENT_STREAM)) {
        let event: McpSseEvent =
            decode_sse_event(body).map_err(|error| McpClientError::Transport(error.to_string()))?;
        return serde_json::from_str::<JsonRpcResponse>(&event.data)
            .map_err(|error| McpClientError::Unexpected(error.to_string()));
    }
    serde_json::from_str::<JsonRpcResponse>(body)
        .map_err(|error| McpClientError::Unexpected(error.to_string()))
}

fn take_sse_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    let delimiter = buffer
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|index| (index, 2))
        .or_else(|| {
            buffer
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| (index, 4))
        })?;
    let end = delimiter.0 + delimiter.1;
    let frame = buffer.drain(..end).collect::<Vec<_>>();
    Some(frame)
}

fn mcp_frame_from_value(value: Value) -> McpClientResult<McpFrame> {
    let object = value.as_object().ok_or_else(|| {
        McpClientError::Unexpected("MCP transport received a non-object JSON-RPC frame".to_owned())
    })?;
    let has_method = object.contains_key("method");
    let has_id = object.contains_key("id");
    match (has_method, has_id) {
        (true, true) => serde_json::from_value(value)
            .map(McpFrame::Request)
            .map_err(|error| McpClientError::Unexpected(error.to_string())),
        (true, false) => serde_json::from_value(value)
            .map(McpFrame::Notification)
            .map_err(|error| McpClientError::Unexpected(error.to_string())),
        (false, true) => serde_json::from_value(value)
            .map(McpFrame::Response)
            .map_err(|error| McpClientError::Unexpected(error.to_string())),
        (false, false) => Err(McpClientError::Unexpected(
            "MCP transport received an unclassifiable JSON-RPC frame".to_owned(),
        )),
    }
}

fn capability_from_tool(capability_id: CapabilityId, tool: &McpTool) -> Capability {
    Capability {
        id: capability_id,
        name: tool.name.clone(),
        kind: CapabilityKind::Tool,
        input_schema: tool.input_schema.clone(),
        output_schema: tool.output_schema.clone(),
        description: tool.description.clone(),
        risk: None,
        stability: None,
        cost: None,
        auth: None,
        bindings: Vec::new(),
        requires_human_approval: None,
        contract: Some(minimal_mcp_tool_contract()),
    }
}

fn minimal_mcp_tool_contract() -> CapabilityContract {
    CapabilityContract {
        side_effects: vec![
            SideEffect::Read,
            SideEffect::Write,
            SideEffect::ExternalNetwork,
        ],
        idempotency: IdempotencyContract {
            requirement: IdempotencyRequirement::Optional,
            collision_behavior: IdempotencyCollisionBehavior::ReturnOriginalResult,
            key_scope: IdempotencyKeyScope::Capability,
            ttl_ms: None,
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: false,
            supports_streaming: false,
            supports_cancel: true,
            supports_retry: false,
            expected_completion: ExpectedCompletionMode::Sync,
            retry_safety: RetrySafety::Unknown,
        },
        data: DataContract {
            sensitivity: DataSensitivity::Unknown,
            contains_pii: false,
            redaction_required: false,
            residency: None,
            retention: None,
        },
        credentials: None,
        approval: None,
        sla: None,
        transaction: None,
        compensation: Some(CompensationContract {
            mode: CompensationMode::RollbackNotSupported,
            compensation_capability_id: None,
            compensation_window_ms: None,
            requires_approval: false,
        }),
    }
}

fn action_result_from_mcp(action_id: aip_core::ActionId, result: Value) -> ActionResult {
    let is_error = result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let message = result
        .get("content")
        .and_then(Value::as_array)
        .map(|content| content.iter().map(message_part_from_content).collect())
        .unwrap_or_else(|| vec![MessagePart::text(result.to_string())]);
    let output = result
        .get("structuredContent")
        .cloned()
        .unwrap_or_else(|| result.clone());
    ActionResult {
        action_id,
        status: if is_error {
            ActionResultStatus::Failed
        } else {
            ActionResultStatus::Completed
        },
        output: Some(output),
        message,
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    }
}

fn message_part_from_content(content: &Value) -> MessagePart {
    match serde_json::from_value::<ContentBlock>(content.clone()) {
        Ok(ContentBlock::Text { text, .. }) => MessagePart::text(text),
        Ok(ContentBlock::Image {
            data, mime_type, ..
        }) => MessagePart::Image {
            url: None,
            data: Some(data),
            mime_type,
            alt: None,
        },
        Ok(ContentBlock::Audio {
            data, mime_type, ..
        }) => MessagePart::Audio {
            url: None,
            data: Some(data),
            mime_type,
            transcript: None,
        },
        Ok(ContentBlock::ResourceLink {
            uri,
            name,
            mime_type,
            ..
        }) => MessagePart::File {
            url: Some(uri),
            data: None,
            mime_type: mime_type.unwrap_or_else(|| "application/octet-stream".to_owned()),
            filename: name.unwrap_or_else(|| "resource".to_owned()),
            size_bytes: None,
        },
        Ok(ContentBlock::Resource { resource, .. }) => match resource {
            ResourceContents::Text {
                uri,
                mime_type,
                text,
            } => MessagePart::File {
                url: Some(uri),
                data: Some(text),
                mime_type: mime_type.unwrap_or_else(|| "text/plain".to_owned()),
                filename: "resource".to_owned(),
                size_bytes: None,
            },
            ResourceContents::Blob {
                uri,
                mime_type,
                blob,
            } => MessagePart::File {
                url: Some(uri),
                data: Some(blob),
                mime_type: mime_type.unwrap_or_else(|| "application/octet-stream".to_owned()),
                filename: "resource".to_owned(),
                size_bytes: None,
            },
        },
        Ok(ContentBlock::ToolResult {
            tool_call_id,
            content,
            is_error,
        }) => MessagePart::ToolResult {
            tool_call_id,
            data: Some(json!(content)),
            error: is_error.then(|| json!({ "isError": true })),
        },
        Ok(ContentBlock::ToolUse { id, name, input }) => MessagePart::Json {
            data: json!({ "tool_use": { "id": id, "name": name, "input": input } }),
            schema: None,
        },
        Err(_) => MessagePart::text(content.to_string()),
    }
}

fn sanitize_tool_name(name: &str) -> String {
    name.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn validate_resume_state(state: &McpTransportResumeState, endpoint: &Url) -> McpClientResult<()> {
    if state.endpoint != endpoint.to_string() {
        return Err(McpClientError::State(
            "MCP resume state belongs to a different endpoint".to_owned(),
        ));
    }
    validate_header_state("session id", &state.session_id, 4 * 1024)?;
    if let Some(version) = state.protocol_version.as_deref() {
        validate_header_state("protocol version", version, 128)?;
    }
    if let Some(cursor) = state.last_event_id.as_deref() {
        validate_header_state("SSE cursor", cursor, 8 * 1024)?;
    }
    Ok(())
}

fn validate_header_state(name: &str, value: &str, max_bytes: usize) -> McpClientResult<()> {
    if value.is_empty() || value.len() > max_bytes || value.contains(['\r', '\n']) {
        return Err(McpClientError::State(format!(
            "persisted MCP {name} is empty, oversized, or contains a line break"
        )));
    }
    Ok(())
}

fn validate_client_snapshot(
    snapshot: &McpClientSnapshot,
    config: &McpClientConfig,
    transport: McpTransportKind,
) -> McpClientResult<()> {
    if snapshot.snapshot_version != MCP_CLIENT_SNAPSHOT_VERSION {
        return Err(McpClientError::State(format!(
            "unsupported MCP client snapshot version {}",
            snapshot.snapshot_version
        )));
    }
    if snapshot.client_id != config.id {
        return Err(McpClientError::State(
            "MCP client snapshot owner does not match the configured client id".to_owned(),
        ));
    }
    if snapshot.session.role != McpRole::Client || snapshot.session.transport != transport {
        return Err(McpClientError::State(
            "MCP client snapshot role or transport does not match this host".to_owned(),
        ));
    }
    if snapshot.session.session_id != format!("mcp-client:{}", config.id) {
        return Err(McpClientError::State(
            "MCP client snapshot has an unexpected logical session id".to_owned(),
        ));
    }
    if snapshot.protocol_version != snapshot.session.protocol_version {
        return Err(McpClientError::State(
            "MCP client snapshot contains inconsistent negotiated versions".to_owned(),
        ));
    }
    let total_items = snapshot
        .tools
        .len()
        .saturating_add(snapshot.resources.len())
        .saturating_add(snapshot.prompts.len())
        .saturating_add(snapshot.resource_templates.len())
        .saturating_add(snapshot.tasks.len())
        .saturating_add(snapshot.capability_to_tool.len())
        .saturating_add(snapshot.resource_subscriptions.len());
    if total_items > 100_000 {
        return Err(McpClientError::State(
            "MCP client snapshot exceeds the 100000-item safety bound".to_owned(),
        ));
    }
    let tool_names = snapshot
        .tools
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<BTreeSet<_>>();
    if tool_names.len() != snapshot.tools.len()
        || snapshot
            .capability_to_tool
            .values()
            .any(|tool| !tool_names.contains(tool.as_str()))
    {
        return Err(McpClientError::State(
            "MCP client snapshot contains duplicate tools or an invalid capability projection"
                .to_owned(),
        ));
    }
    if snapshot
        .transport_resume
        .as_ref()
        .is_some_and(|resume| resume.transport != transport)
    {
        return Err(McpClientError::State(
            "MCP client snapshot resume transport does not match the active transport".to_owned(),
        ));
    }
    if snapshot.persisted_at.trim().is_empty() {
        return Err(McpClientError::State(
            "MCP client snapshot omitted its persistence timestamp".to_owned(),
        ));
    }
    Ok(())
}

fn load_mcp_client_snapshot(
    path: &Path,
    expected_client_id: &str,
) -> McpClientResult<Option<McpClientSnapshot>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(McpClientError::State(error.to_string())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(McpClientError::State(
            "MCP client snapshot path must be a regular non-symlink file".to_owned(),
        ));
    }
    if metadata.len() > MCP_CLIENT_SNAPSHOT_MAX_BYTES {
        return Err(McpClientError::State(format!(
            "MCP client snapshot exceeds the {}-byte bound",
            MCP_CLIENT_SNAPSHOT_MAX_BYTES
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(McpClientError::State(
                "MCP client snapshot permissions must not grant group or other access".to_owned(),
            ));
        }
    }
    let bytes = fs::read(path).map_err(|error| McpClientError::State(error.to_string()))?;
    let snapshot: McpClientSnapshot = serde_json::from_slice(&bytes)
        .map_err(|error| McpClientError::State(format!("invalid snapshot JSON: {error}")))?;
    if snapshot.client_id != expected_client_id {
        return Err(McpClientError::State(
            "MCP client snapshot belongs to a different client id".to_owned(),
        ));
    }
    Ok(Some(snapshot))
}

fn persist_mcp_client_snapshot(path: &Path, snapshot: &McpClientSnapshot) -> McpClientResult<()> {
    let bytes = serde_json::to_vec_pretty(snapshot)
        .map_err(|error| McpClientError::State(error.to_string()))?;
    if bytes.len() as u64 > MCP_CLIENT_SNAPSHOT_MAX_BYTES {
        return Err(McpClientError::State(format!(
            "MCP client snapshot exceeds the {}-byte bound",
            MCP_CLIENT_SNAPSHOT_MAX_BYTES
        )));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| McpClientError::State(error.to_string()))?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|error| McpClientError::State(error.to_string()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(McpClientError::State(
            "MCP client snapshot parent must be a regular directory".to_owned(),
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(McpClientError::State(
            "MCP client snapshot destination must be a regular non-symlink file".to_owned(),
        ));
    }
    let mut random = [0_u8; 16];
    OsRng.fill_bytes(&mut random);
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("mcp-client-state");
    let temporary = parent.join(format!(".{file_name}.{suffix}.tmp"));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write_result = (|| -> std::io::Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(McpClientError::State(error.to_string()));
    }
    Ok(())
}

fn delete_mcp_client_snapshot(path: &Path) -> McpClientResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(McpClientError::State(
                "refusing to delete a non-regular MCP client snapshot path".to_owned(),
            ))
        }
        Ok(_) => fs::remove_file(path).map_err(|error| McpClientError::State(error.to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(McpClientError::State(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FileMcpClientStateStore, InMemoryMcpClientStateStore, InMemoryMcpTransport, McpClient,
        McpClientConfig, McpClientError, McpClientResult, McpClientStateStore, McpClientTransport,
        McpHostRequestHandler, McpHttpClientTransport, McpLegacyHttpSseClientTransport,
        McpStdioClientTransport, decode_http_response,
    };
    use aip_mcp_session::{McpFrame, McpTransportKind};
    use aip_profile_mcp::{
        JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, ListChangedCapability, McpMethod,
        Root, TaskStatus,
    };
    use aip_runtime::CancellationToken;
    use axum::{
        Json, Router,
        extract::{Query, State},
        http::{HeaderMap, HeaderValue, StatusCode},
        response::sse::{Event as AxumSseEvent, Sse},
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use serde_json::{Value, json};
    use std::{
        collections::HashMap,
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::sync::{Mutex, Notify, broadcast, mpsc};

    type RecordedRequests = Arc<Mutex<Vec<(String, Option<Value>)>>>;

    #[derive(Clone)]
    struct LegacyMockState {
        message_endpoint: String,
        sender: broadcast::Sender<(u64, String)>,
        sequence: Arc<std::sync::atomic::AtomicU64>,
        host_response: Arc<Mutex<Option<Value>>>,
        host_response_ready: Arc<Notify>,
    }

    #[derive(Clone, Debug, Default)]
    struct HttpLifecycleState {
        deletes: Arc<AtomicUsize>,
    }

    #[derive(Clone, Debug, Default)]
    struct ResumeHttpState {
        initializes: Arc<AtomicUsize>,
        pings: Arc<AtomicUsize>,
    }

    async fn lifecycle_http_post(Json(request): Json<Value>) -> Response {
        if request.get("method") == Some(&json!("initialize")) {
            let mut response = Json(json!({
                "jsonrpc": "2.0",
                "id": request.get("id").cloned().unwrap_or(Value::Null),
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "lifecycle-mock", "version": "1.0.0" }
                }
            }))
            .into_response();
            response.headers_mut().insert(
                aip_transport_mcp_streamable_http::MCP_SESSION_ID_HEADER,
                HeaderValue::from_static("session-lifecycle-test"),
            );
            response.headers_mut().insert(
                aip_transport_mcp_streamable_http::MCP_PROTOCOL_VERSION_HEADER,
                HeaderValue::from_static("2025-11-25"),
            );
            response
        } else {
            StatusCode::ACCEPTED.into_response()
        }
    }

    async fn lifecycle_http_get()
    -> Sse<impl futures_util::Stream<Item = Result<AxumSseEvent, Infallible>>> {
        Sse::new(futures_util::stream::pending())
    }

    async fn lifecycle_http_delete(
        State(state): State<HttpLifecycleState>,
        headers: HeaderMap,
    ) -> StatusCode {
        assert_eq!(
            headers
                .get(aip_transport_mcp_streamable_http::MCP_SESSION_ID_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("session-lifecycle-test")
        );
        state.deletes.fetch_add(1, Ordering::SeqCst);
        StatusCode::NO_CONTENT
    }

    async fn resumable_http_post(
        State(state): State<ResumeHttpState>,
        headers: HeaderMap,
        Json(request): Json<Value>,
    ) -> Response {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request.get("method").and_then(Value::as_str);
        if method != Some("initialize") {
            assert_eq!(
                headers
                    .get(aip_transport_mcp_streamable_http::MCP_SESSION_ID_HEADER)
                    .and_then(|value| value.to_str().ok()),
                Some("durable-session-1")
            );
        }
        let result = match method {
            Some("initialize") => {
                state.initializes.fetch_add(1, Ordering::SeqCst);
                json!({
                    "protocolVersion": "2025-11-25",
                    "capabilities": {
                        "tools": {},
                        "resources": { "subscribe": true },
                        "tasks": {}
                    },
                    "serverInfo": { "name": "durable-host", "version": "1.0.0" }
                })
            }
            Some("ping") => {
                state.pings.fetch_add(1, Ordering::SeqCst);
                json!({})
            }
            Some("tools/list") => json!({
                "tools": [{
                    "name": "durable_search",
                    "inputSchema": { "type": "object" }
                }]
            }),
            Some("resources/list") => json!({ "resources": [] }),
            Some("resources/subscribe") => json!({}),
            Some("tasks/get") => json!({
                "task": { "taskId": "durable-task-1", "status": "working" }
            }),
            Some("notifications/initialized") => return StatusCode::ACCEPTED.into_response(),
            _ if request.get("id").is_none() => return StatusCode::ACCEPTED.into_response(),
            _ => json!({}),
        };
        let mut response = Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        }))
        .into_response();
        response.headers_mut().insert(
            aip_transport_mcp_streamable_http::MCP_SESSION_ID_HEADER,
            HeaderValue::from_static("durable-session-1"),
        );
        response.headers_mut().insert(
            aip_transport_mcp_streamable_http::MCP_PROTOCOL_VERSION_HEADER,
            HeaderValue::from_static("2025-11-25"),
        );
        response
    }

    async fn resumable_http_delete() -> StatusCode {
        StatusCode::NO_CONTENT
    }

    impl LegacyMockState {
        fn publish(&self, value: Value) {
            let sequence = self
                .sequence
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            let _ = self.sender.send((sequence, value.to_string()));
        }
    }

    #[derive(Clone, Debug)]
    struct LegacyHostHandler;

    #[derive(Clone, Debug, Default)]
    struct CancellableMockTransport {
        request_started: Arc<Notify>,
        cancellation_received: Arc<Notify>,
        notifications: Arc<Mutex<Vec<JsonRpcNotification>>>,
    }

    #[derive(Clone, Debug)]
    struct HostMatrixTransport {
        incoming_tx: mpsc::UnboundedSender<McpFrame>,
        incoming_rx: Arc<Mutex<mpsc::UnboundedReceiver<McpFrame>>>,
        requests: RecordedRequests,
        responses: Arc<Mutex<Vec<JsonRpcResponse>>>,
        response_ready: Arc<Notify>,
        closed: CancellationToken,
    }

    impl HostMatrixTransport {
        fn new() -> Self {
            let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
            Self {
                incoming_tx,
                incoming_rx: Arc::new(Mutex::new(incoming_rx)),
                requests: Arc::default(),
                responses: Arc::default(),
                response_ready: Arc::default(),
                closed: CancellationToken::default(),
            }
        }

        fn push(&self, frame: McpFrame) {
            self.incoming_tx.send(frame).expect("host incoming frame");
        }
    }

    #[async_trait::async_trait]
    impl McpClientTransport for HostMatrixTransport {
        fn transport_kind(&self) -> McpTransportKind {
            McpTransportKind::Stdio
        }

        async fn request(&self, request: JsonRpcRequest) -> McpClientResult<JsonRpcResponse> {
            let method = request.method_kind()?;
            self.requests
                .lock()
                .await
                .push((request.method.clone(), request.params.clone()));
            let cursor = request
                .params
                .as_ref()
                .and_then(|params| params.get("cursor"))
                .and_then(Value::as_str);
            let force_tool_error = request
                .params
                .as_ref()
                .and_then(|params| params.pointer("/arguments/force_error"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let result = match method {
                McpMethod::Initialize => json!({
                    "protocolVersion": "2025-11-25",
                    "capabilities": {
                        "tools": { "listChanged": true },
                        "resources": { "subscribe": true, "listChanged": true },
                        "prompts": { "listChanged": true },
                        "completions": {},
                        "tasks": { "list": {}, "cancel": {} }
                    },
                    "serverInfo": { "name": "host-matrix", "version": "1.0.0" }
                }),
                McpMethod::ToolsList if cursor.is_none() => json!({
                    "tools": [{
                        "name": "first",
                        "inputSchema": { "type": "object" },
                        "outputSchema": {
                            "type": "object",
                            "required": ["ok"],
                            "properties": { "ok": { "type": "boolean" } }
                        }
                    }],
                    "nextCursor": "tools:2"
                }),
                McpMethod::ToolsList => json!({
                    "tools": [{ "name": "second", "inputSchema": { "type": "object" } }]
                }),
                McpMethod::ToolsCall if force_tool_error => json!({
                    "content": [{ "type": "text", "text": "expected failure" }],
                    "isError": true
                }),
                McpMethod::ToolsCall => json!({
                    "content": [{ "type": "text", "text": "ok" }],
                    "structuredContent": { "ok": true }
                }),
                McpMethod::ResourcesList if cursor.is_none() => json!({
                    "resources": [{ "uri": "aip://resource/1", "name": "one" }],
                    "nextCursor": "resources:2"
                }),
                McpMethod::ResourcesList => json!({
                    "resources": [{ "uri": "aip://resource/2", "name": "two" }]
                }),
                McpMethod::ResourcesTemplatesList => json!({
                    "resourceTemplates": [{
                        "uriTemplate": "aip://resource/{id}",
                        "name": "resource"
                    }]
                }),
                McpMethod::ResourcesSubscribe | McpMethod::ResourcesUnsubscribe => json!({}),
                McpMethod::PromptsList => json!({
                    "prompts": [{ "name": "triage", "arguments": [] }]
                }),
                McpMethod::TasksList if cursor.is_none() => json!({
                    "tasks": [{ "taskId": "task-1", "status": "working" }],
                    "nextCursor": "tasks:2"
                }),
                McpMethod::TasksList => json!({
                    "tasks": [{ "taskId": "task-2", "status": "completed" }]
                }),
                McpMethod::TasksGet => {
                    json!({ "task": { "taskId": "task-1", "status": "working" } })
                }
                McpMethod::TasksResult => {
                    json!({ "content": [{ "type": "text", "text": "done" }] })
                }
                McpMethod::TasksCancel => {
                    json!({ "task": { "taskId": "task-1", "status": "cancelled" } })
                }
                other => {
                    return Err(McpClientError::Unexpected(format!(
                        "host matrix has no response for {other}"
                    )));
                }
            };
            Ok(JsonRpcResponse::success(request.id, result))
        }

        async fn notify(&self, _notification: JsonRpcNotification) -> McpClientResult<()> {
            Ok(())
        }

        fn supports_bidirectional(&self) -> bool {
            true
        }

        async fn next_incoming(&self) -> McpClientResult<Option<McpFrame>> {
            let mut incoming = self.incoming_rx.lock().await;
            tokio::select! {
                () = self.closed.cancelled() => Ok(None),
                frame = incoming.recv() => Ok(frame),
            }
        }

        async fn respond(&self, response: JsonRpcResponse) -> McpClientResult<()> {
            self.responses.lock().await.push(response);
            self.response_ready.notify_waiters();
            Ok(())
        }

        async fn terminate(&self) -> McpClientResult<()> {
            self.closed.cancel();
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl McpClientTransport for CancellableMockTransport {
        fn transport_kind(&self) -> aip_mcp_session::McpTransportKind {
            aip_mcp_session::McpTransportKind::Stdio
        }

        async fn request(&self, request: JsonRpcRequest) -> McpClientResult<JsonRpcResponse> {
            match request.method_kind()? {
                McpMethod::Initialize => Ok(JsonRpcResponse::success(
                    request.id,
                    json!({
                        "protocolVersion": "2025-11-25",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "cancellable-mock", "version": "1.0.0" }
                    }),
                )),
                McpMethod::ToolsCall => {
                    self.request_started.notify_waiters();
                    self.cancellation_received.notified().await;
                    Ok(JsonRpcResponse::success(
                        request.id,
                        json!({ "content": [], "isError": true }),
                    ))
                }
                method => Err(McpClientError::Unexpected(format!(
                    "unexpected mock request `{method}`"
                ))),
            }
        }

        async fn notify(&self, notification: JsonRpcNotification) -> McpClientResult<()> {
            if notification.method == McpMethod::Cancelled.as_str() {
                self.cancellation_received.notify_waiters();
            }
            self.notifications.lock().await.push(notification);
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl McpHostRequestHandler for LegacyHostHandler {
        async fn list_roots(&self) -> McpClientResult<Vec<Root>> {
            Ok(vec![Root {
                uri: "file:///workspace".to_owned(),
                name: Some("workspace".to_owned()),
            }])
        }

        async fn create_message(&self, _params: Value) -> McpClientResult<Value> {
            Ok(json!({ "role": "assistant", "content": { "type": "text", "text": "ok" } }))
        }

        async fn elicit(&self, _params: Value) -> McpClientResult<Value> {
            Ok(json!({ "action": "decline" }))
        }
    }

    async fn legacy_mock_sse(
        State(state): State<LegacyMockState>,
        Query(_query): Query<HashMap<String, String>>,
    ) -> Sse<impl futures_util::Stream<Item = Result<AxumSseEvent, Infallible>>> {
        let receiver = state.sender.subscribe();
        let endpoint = state.message_endpoint;
        let stream = futures_util::stream::unfold(
            (Some(endpoint), receiver),
            |(mut endpoint, mut receiver)| async move {
                if let Some(endpoint) = endpoint.take() {
                    return Some((
                        Ok(AxumSseEvent::default().event("endpoint").data(endpoint)),
                        (None, receiver),
                    ));
                }
                loop {
                    match receiver.recv().await {
                        Ok((sequence, data)) => {
                            return Some((
                                Ok(AxumSseEvent::default()
                                    .id(sequence.to_string())
                                    .event("message")
                                    .data(data)),
                                (None, receiver),
                            ));
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                }
            },
        );
        Sse::new(stream)
    }

    async fn legacy_mock_message(
        State(state): State<LegacyMockState>,
        Query(query): Query<HashMap<String, String>>,
        Json(value): Json<Value>,
    ) -> StatusCode {
        if query.get("sessionId").map(String::as_str) != Some("legacy-test-session") {
            return StatusCode::NOT_FOUND;
        }
        if value.get("method") == Some(&json!("initialize")) {
            state.publish(json!({
                "jsonrpc": "2.0",
                "id": value.get("id").cloned().unwrap_or(Value::Null),
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "legacy-mock", "version": "1.0.0" }
                }
            }));
        } else if value.get("method") == Some(&json!("notifications/initialized")) {
            state.publish(json!({
                "jsonrpc": "2.0",
                "id": 900,
                "method": "roots/list",
                "params": {}
            }));
        } else if value.get("method") == Some(&json!("tools/list")) {
            state.publish(json!({
                "jsonrpc": "2.0",
                "id": value.get("id").cloned().unwrap_or(Value::Null),
                "result": {
                    "tools": [{
                        "name": "legacy_search",
                        "inputSchema": { "type": "object" }
                    }]
                }
            }));
        } else if value.get("id") == Some(&json!(900)) {
            *state.host_response.lock().await = Some(value);
            state.host_response_ready.notify_waiters();
        }
        StatusCode::ACCEPTED
    }

    #[tokio::test]
    async fn client_discovers_tools_as_aip_capabilities() {
        let transport = InMemoryMcpTransport::default();
        transport
            .register_result(
                McpMethod::Initialize,
                json!({
                    "protocolVersion": "2025-11-25",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "mock", "version": "1.0.0" }
                }),
            )
            .await;
        transport
            .register_result(
                McpMethod::ToolsList,
                json!({
                    "tools": [{
                        "name": "search",
                        "inputSchema": { "type": "object" }
                    }]
                }),
            )
            .await;
        transport
            .register_result(McpMethod::ResourcesList, json!({ "resources": [] }))
            .await;
        let client = McpClient::new(McpClientConfig::new("mock"), Arc::new(transport));
        client.initialize().await.expect("initialize");
        let manifest = client.refresh_manifest().await.expect("manifest");
        assert_eq!(manifest.capabilities[0].name, "search");
        assert_eq!(manifest.capabilities[0].id.as_str(), "cap:mcp:mock:search");
    }

    #[tokio::test]
    async fn streamable_http_close_deletes_session_and_stops_receive_lifecycle() {
        let state = HttpLifecycleState::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("lifecycle listener");
        let address = listener.local_addr().expect("lifecycle address");
        let app = Router::new()
            .route(
                "/mcp",
                get(lifecycle_http_get)
                    .post(lifecycle_http_post)
                    .delete(lifecycle_http_delete),
            )
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("lifecycle mock server");
        });
        let transport = Arc::new(
            McpHttpClientTransport::new(format!("http://{address}/mcp")).expect("HTTP transport"),
        );
        let client = McpClient::new(McpClientConfig::new("http-lifecycle"), transport.clone());

        client.initialize().await.expect("initialize HTTP client");
        assert_eq!(
            transport.session_id().await.as_deref(),
            Some("session-lifecycle-test")
        );
        client.close().await.expect("terminate HTTP session");
        client.close().await.expect("idempotent close");
        assert_eq!(state.deletes.load(Ordering::SeqCst), 1);
        assert!(transport.session_id().await.is_none());
        assert_eq!(
            client.state.read().await.session.lifecycle,
            aip_mcp_session::McpLifecycle::Closed
        );
        server.abort();
    }

    #[tokio::test]
    async fn streamable_http_host_resumes_tasks_catalog_subscriptions_and_cursor() {
        let state = ResumeHttpState::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("resume listener");
        let address = listener.local_addr().expect("resume address");
        let app = Router::new()
            .route(
                "/mcp",
                get(lifecycle_http_get)
                    .post(resumable_http_post)
                    .delete(resumable_http_delete),
            )
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("resumable MCP server");
        });
        let endpoint = format!("http://{address}/mcp");
        let store = InMemoryMcpClientStateStore::default();
        let mut config = McpClientConfig::new("durable-host");
        config.capabilities.tasks = Some(json!({}));

        let first_transport = Arc::new(
            McpHttpClientTransport::new(&endpoint).expect("first resumable HTTP transport"),
        );
        let first =
            McpClient::new(config.clone(), first_transport.clone()).with_state_store(store.clone());
        first.initialize().await.expect("first initialize");
        let manifest = first.refresh_manifest().await.expect("durable manifest");
        assert_eq!(manifest.capabilities[0].name, "durable_search");
        first
            .subscribe_resource("file:///durable")
            .await
            .expect("durable subscription");
        let task = first
            .get_task("durable-task-1")
            .await
            .expect("durable task");
        assert_eq!(task.status, TaskStatus::Working);
        *first_transport.last_event_id.write().await = Some("event-42".to_owned());
        first.persist_state().await.expect("persist SSE cursor");
        let prior_sequence = first.sequence.load(Ordering::Acquire);

        first_transport.listener_cancellation.cancel();
        tokio::task::yield_now().await;
        drop(first);

        let second_transport = Arc::new(
            McpHttpClientTransport::new(&endpoint).expect("second resumable HTTP transport"),
        );
        let second =
            McpClient::new(config, second_transport.clone()).with_state_store(store.clone());
        second.initialize().await.expect("resume durable session");

        assert_eq!(state.initializes.load(Ordering::SeqCst), 1);
        assert_eq!(state.pings.load(Ordering::SeqCst), 1);
        assert!(second.sequence.load(Ordering::Acquire) > prior_sequence);
        assert_eq!(
            second_transport.last_event_id.read().await.as_deref(),
            Some("event-42")
        );
        let restored = second.state.read().await;
        assert!(restored.tools.contains_key("durable_search"));
        assert!(restored.tasks.contains_key("durable-task-1"));
        assert!(restored.resource_subscriptions.contains("file:///durable"));
        drop(restored);

        second.close().await.expect("close resumed session");
        assert!(
            store
                .load("durable-host")
                .await
                .expect("load deleted snapshot")
                .is_none()
        );
        server.abort();
    }

    #[tokio::test]
    async fn file_host_state_is_atomic_private_and_owner_bound() {
        let root = std::env::temp_dir().join(format!(
            "aip-mcp-client-state-{}",
            aip_core::ActionId::new()
        ));
        let path = root.join("host.json");
        let store = FileMcpClientStateStore::new(&path);
        let transport = InMemoryMcpTransport::default();
        transport
            .register_result(
                McpMethod::Initialize,
                json!({
                    "protocolVersion": "2025-11-25",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "file-state", "version": "1.0.0" }
                }),
            )
            .await;
        transport
            .register_result(
                McpMethod::ToolsList,
                json!({
                    "tools": [{
                        "name": "persisted_tool",
                        "inputSchema": { "type": "object" }
                    }]
                }),
            )
            .await;
        let client = McpClient::new(McpClientConfig::new("file-state"), Arc::new(transport))
            .with_state_store(store.clone());
        client.initialize().await.expect("initialize file state");
        client.list_tools().await.expect("persist tool catalog");

        let snapshot = store
            .load("file-state")
            .await
            .expect("load private snapshot")
            .expect("snapshot");
        assert_eq!(snapshot.tools[0].name, "persisted_tool");
        assert!(store.load("different-owner").await.is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            assert_eq!(
                std::fs::metadata(&path).expect("snapshot metadata").mode() & 0o077,
                0
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                .expect("weaken snapshot permissions");
            assert!(store.load("file-state").await.is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("restore snapshot permissions");
        }
        store.delete("file-state").await.expect("delete snapshot");
        std::fs::remove_dir_all(root).expect("remove state directory");
    }

    #[tokio::test]
    async fn outbound_host_covers_pagination_notifications_tasks_and_bidirectional_requests() {
        let transport = Arc::new(HostMatrixTransport::new());
        let mut config = McpClientConfig::new("host-matrix");
        config.capabilities.roots = Some(ListChangedCapability { list_changed: true });
        config.capabilities.sampling = Some(json!({}));
        config.capabilities.elicitation = Some(json!({}));
        config.capabilities.tasks = Some(json!({}));
        let client = McpClient::new(config, transport.clone()).with_host_handler(LegacyHostHandler);
        let mut events = client.subscribe_events();
        client.initialize().await.expect("initialize host matrix");

        let tools = client.list_tools().await.expect("paginated tools");
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        let call = client
            .call_tool("first", json!({}))
            .await
            .expect("schema-validated tool call");
        assert_eq!(call.pointer("/structuredContent/ok"), Some(&json!(true)));
        let failed_call = client
            .call_tool("first", json!({ "force_error": true }))
            .await
            .expect("error tool result must bypass success output schema validation");
        assert_eq!(failed_call.get("isError"), Some(&json!(true)));
        assert!(failed_call.get("structuredContent").is_none());
        assert_eq!(client.list_resources().await.expect("resources").len(), 2);
        assert_eq!(
            client
                .list_resource_templates()
                .await
                .expect("resource templates")
                .len(),
            1
        );
        client
            .subscribe_resource("aip://resource/1")
            .await
            .expect("resource subscribe");
        client
            .unsubscribe_resource("aip://resource/1")
            .await
            .expect("resource unsubscribe");
        assert_eq!(client.list_prompts().await.expect("prompts").len(), 1);

        let tasks = client.list_tasks().await.expect("paginated tasks");
        assert_eq!(tasks.len(), 2);
        assert_eq!(
            client.get_task("task-1").await.expect("task").task_id,
            "task-1"
        );
        assert_eq!(
            client
                .cancel_task("task-1")
                .await
                .expect("cancel task")
                .status,
            aip_profile_mcp::TaskStatus::Cancelled
        );
        assert!(client.task_result("task-1").await.is_ok());

        transport.push(McpFrame::Notification(JsonRpcNotification::new(
            McpMethod::ToolsListChanged,
            None,
        )));
        let list_change = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("list change event timeout")
            .expect("list change event");
        assert_eq!(list_change.method, McpMethod::ToolsListChanged);
        assert_eq!(client.catalog_generation().await, 1);

        transport.push(McpFrame::Notification(JsonRpcNotification::new(
            McpMethod::TasksStatus,
            Some(json!({
                "task": { "taskId": "task-1", "status": "completed" }
            })),
        )));
        let task_event = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("task event timeout")
            .expect("task event");
        assert_eq!(task_event.method, McpMethod::TasksStatus);
        assert_eq!(
            client
                .state
                .read()
                .await
                .tasks
                .get("task-1")
                .expect("cached task")
                .status,
            aip_profile_mcp::TaskStatus::Completed
        );

        for (id, method, expected_pointer, expected) in [
            (
                900,
                McpMethod::RootsList,
                "/roots/0/uri",
                json!("file:///workspace"),
            ),
            (
                901,
                McpMethod::SamplingCreateMessage,
                "/content/text",
                json!("ok"),
            ),
            (
                902,
                McpMethod::ElicitationCreate,
                "/action",
                json!("decline"),
            ),
        ] {
            let response_ready = transport.response_ready.notified();
            transport.push(McpFrame::Request(JsonRpcRequest::new(
                json!(id),
                method,
                Some(json!({})),
            )));
            tokio::time::timeout(Duration::from_secs(1), response_ready)
                .await
                .expect("server-to-client response timeout");
            let response = transport
                .responses
                .lock()
                .await
                .iter()
                .find(|response| response.id == json!(id))
                .cloned()
                .expect("correlated host response");
            assert!(response.error.is_none(), "{response:?}");
            assert_eq!(
                response
                    .result
                    .as_ref()
                    .and_then(|result| result.pointer(expected_pointer)),
                Some(&expected)
            );
        }

        let requests = transport.requests.lock().await;
        assert!(requests.iter().any(|(method, params)| {
            method == McpMethod::ToolsList.as_str()
                && params.as_ref().and_then(|value| value.get("cursor")) == Some(&json!("tools:2"))
        }));
        assert!(requests.iter().any(|(method, params)| {
            method == McpMethod::TasksList.as_str()
                && params.as_ref().and_then(|value| value.get("cursor")) == Some(&json!("tasks:2"))
        }));
        drop(requests);
        client.close().await.expect("close host matrix");
    }

    #[tokio::test]
    async fn tool_call_propagates_exact_request_cancellation() {
        let transport = Arc::new(CancellableMockTransport::default());
        let client = McpClient::new(McpClientConfig::new("cancellable"), transport.clone());
        client.initialize().await.expect("initialize");

        let cancellation = CancellationToken::default();
        let request_started = transport.request_started.notified();
        let call = {
            let client = client.clone();
            let cancellation = cancellation.clone();
            tokio::spawn(async move {
                client
                    .call_tool_with_cancellation("slow_tool", json!({}), cancellation)
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(1), request_started)
            .await
            .expect("tool request start");
        cancellation.cancel();

        let error = call
            .await
            .expect("tool call task")
            .expect_err("cancelled tool call");
        assert!(matches!(error, McpClientError::Cancelled(_)));
        let notifications = transport.notifications.lock().await;
        let cancelled = notifications
            .iter()
            .find(|notification| notification.method == McpMethod::Cancelled.as_str())
            .expect("cancelled notification");
        assert_eq!(
            cancelled
                .params
                .as_ref()
                .and_then(|params| params.get("requestId")),
            Some(&json!(2))
        );
    }

    #[tokio::test]
    async fn legacy_http_sse_host_initializes_calls_tools_and_answers_client_requests() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("legacy mock listener");
        let address = listener.local_addr().expect("legacy mock address");
        let (sender, _receiver) = broadcast::channel(64);
        let state = LegacyMockState {
            message_endpoint: format!("http://{address}/messages?sessionId=legacy-test-session"),
            sender,
            sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            host_response: Arc::new(Mutex::new(None)),
            host_response_ready: Arc::new(Notify::new()),
        };
        let app = Router::new()
            .route("/sse", get(legacy_mock_sse))
            .route("/messages", post(legacy_mock_message))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("legacy mock server");
        });
        let transport = McpLegacyHttpSseClientTransport::new(format!("http://{address}/sse"))
            .expect("legacy transport");
        let mut config = McpClientConfig::new("legacy-mock");
        config.protocol_version = "2024-11-05".to_owned();
        config.supported_versions = vec!["2024-11-05".to_owned()];
        config.capabilities.roots = Some(ListChangedCapability { list_changed: true });
        let client =
            McpClient::new(config, Arc::new(transport)).with_host_handler(LegacyHostHandler);

        let host_response_ready = state.host_response_ready.notified();
        client.initialize().await.expect("legacy initialize");
        let tools = client.list_tools().await.expect("legacy tools/list");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "legacy_search");

        tokio::time::timeout(Duration::from_secs(2), host_response_ready)
            .await
            .expect("roots response timeout");
        let response = state
            .host_response
            .lock()
            .await
            .clone()
            .expect("roots response");
        assert_eq!(response.get("id"), Some(&json!(900)));
        assert_eq!(
            response.pointer("/result/roots/0/uri"),
            Some(&json!("file:///workspace"))
        );
        server.abort();
    }

    #[test]
    fn http_transport_decodes_one_message_sse_response() {
        let body = "id: 1\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n";
        let response = decode_http_response(Some("text/event-stream"), body).expect("response");
        assert_eq!(
            response,
            JsonRpcResponse::success(json!(1), json!({ "ok": true }))
        );
    }

    #[tokio::test]
    async fn stdio_transport_multiplexes_concurrent_requests() {
        let script = r#"
            while IFS= read -r line; do
                id=$(printf '%s\n' "$line" | sed -E 's/.*"id":([^,}]+).*/\1/')
                printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "$id"
            done
        "#;
        let transport = Arc::new(
            McpStdioClientTransport::spawn("sh", &["-c".to_owned(), script.to_owned()])
                .expect("spawn stdio peer"),
        );
        let first = {
            let transport = transport.clone();
            tokio::spawn(async move {
                transport
                    .request(JsonRpcRequest::new(json!(1), McpMethod::Ping, None))
                    .await
            })
        };
        let second = {
            let transport = transport.clone();
            tokio::spawn(async move {
                transport
                    .request(JsonRpcRequest::new(json!(2), McpMethod::Ping, None))
                    .await
            })
        };

        let first = first
            .await
            .expect("first request task")
            .expect("first response");
        let second = second
            .await
            .expect("second request task")
            .expect("second response");
        assert_eq!(first.id, json!(1));
        assert_eq!(second.id, json!(2));
    }

    #[tokio::test]
    async fn stdio_transport_rejects_mismatched_response_id_and_poisoned_reuse() {
        let script = r#"
            IFS= read -r _line
            printf '{"jsonrpc":"2.0","id":999,"result":{}}\n'
            sleep 30
        "#;
        let transport = McpStdioClientTransport::spawn("sh", &["-c".to_owned(), script.to_owned()])
            .expect("spawn stdio peer");
        let error = transport
            .request(JsonRpcRequest::new(json!(1), McpMethod::Ping, None))
            .await
            .expect_err("mismatched response id must fail");
        assert!(error.to_string().contains("999"));

        let reuse_error = transport
            .request(JsonRpcRequest::new(json!(2), McpMethod::Ping, None))
            .await
            .expect_err("poisoned subprocess must not be reused");
        assert!(reuse_error.to_string().contains("no longer usable"));
        assert_child_exits(&transport).await;
    }

    #[tokio::test]
    async fn stdio_transport_deadline_kills_unresponsive_subprocess() {
        let script = "IFS= read -r _line; sleep 30";
        let transport = McpStdioClientTransport::spawn("sh", &["-c".to_owned(), script.to_owned()])
            .expect("spawn stdio peer")
            .with_request_timeout(Duration::from_millis(50));
        let error = transport
            .request(JsonRpcRequest::new(json!(1), McpMethod::Ping, None))
            .await
            .expect_err("unresponsive subprocess must time out");
        assert!(error.to_string().contains("timed out"));
        assert_child_exits(&transport).await;
    }

    #[tokio::test]
    async fn dropping_stdio_request_future_kills_subprocess() {
        let script = "IFS= read -r _line; sleep 30";
        let transport = Arc::new(
            McpStdioClientTransport::spawn("sh", &["-c".to_owned(), script.to_owned()])
                .expect("spawn stdio peer"),
        );
        let request = {
            let transport = transport.clone();
            tokio::spawn(async move {
                transport
                    .request(JsonRpcRequest::new(json!(1), McpMethod::Ping, None))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        request.abort();
        request.await.expect_err("request task must be aborted");
        assert_child_exits(&transport).await;
        let error = transport
            .request(JsonRpcRequest::new(json!(2), McpMethod::Ping, None))
            .await
            .expect_err("aborted request must poison the subprocess");
        assert!(error.to_string().contains("no longer usable"));
    }

    async fn assert_child_exits(transport: &McpStdioClientTransport) {
        for _ in 0..100 {
            if transport
                .child
                .lock()
                .await
                .try_wait()
                .expect("query child status")
                .is_some()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("MCP stdio child did not exit after transport failure");
    }
}
