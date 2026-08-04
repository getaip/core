//! MCP lifecycle, negotiated capability, correlation, and duplex dispatch.
//!
//! This crate is transport-neutral. Stdio, legacy HTTP+SSE, and Streamable HTTP
//! use the same state machine and dispatcher so protocol ordering and
//! bidirectional request correlation cannot drift between bindings.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_profile_mcp::{
    ClientCapabilities, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, McpMethod,
    ServerCapabilities, methods_for_version, request_id_to_key,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};

/// MCP peer role for method-direction validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpRole {
    /// Host/client role.
    Client,
    /// Provider/server role.
    Server,
}

/// MCP session lifecycle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpLifecycle {
    /// No initialize request has been accepted.
    #[default]
    New,
    /// Initialize request/response completed; initialized notification pending.
    Initializing,
    /// Normal method traffic is permitted.
    Initialized,
    /// Session termination has started.
    Closing,
    /// Session is terminal.
    Closed,
}

/// Concrete MCP transport binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransportKind {
    /// Newline-delimited JSON-RPC over stdio.
    Stdio,
    /// Legacy 2024 HTTP POST plus server SSE endpoint binding.
    LegacyHttpSse,
    /// 2025 Streamable HTTP binding.
    StreamableHttp,
}

/// MCP session/state-machine error with a stable JSON-RPC code.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum McpSessionError {
    /// Version/transport pair is not executable.
    #[error("MCP version `{version}` is not supported over `{transport:?}`")]
    UnsupportedVersionTransport {
        /// Requested stable version.
        version: String,
        /// Active transport.
        transport: McpTransportKind,
    },
    /// Method is invalid in the current lifecycle state.
    #[error("MCP method `{method}` is invalid while session is `{state:?}`")]
    InvalidState {
        /// Method name.
        method: String,
        /// Current lifecycle.
        state: McpLifecycle,
    },
    /// Method is absent from the negotiated stable version.
    #[error("MCP method `{method}` is unavailable in version `{version}`")]
    MethodUnavailable {
        /// Method name.
        method: String,
        /// Negotiated version.
        version: String,
    },
    /// Required peer capability was not negotiated.
    #[error("MCP method `{method}` requires peer capability `{capability}`")]
    CapabilityNotNegotiated {
        /// Method name.
        method: String,
        /// Missing capability family.
        capability: String,
    },
    /// Method direction does not match this peer role.
    #[error("MCP method `{method}` is not accepted by role `{role:?}`")]
    RoleViolation {
        /// Method name.
        method: String,
        /// Local role.
        role: McpRole,
    },
    /// Duplicate initialize or terminal transition.
    #[error("invalid MCP lifecycle transition from `{from:?}` to `{to:?}`")]
    InvalidTransition {
        /// Existing state.
        from: McpLifecycle,
        /// Requested state.
        to: McpLifecycle,
    },
    /// Correlation id is already active.
    #[error("MCP request id `{0}` is already active")]
    DuplicateRequestId(String),
    /// Dispatcher timed out waiting for a response.
    #[error("MCP request id `{0}` timed out")]
    RequestTimeout(String),
    /// Transport or correlation storage failed.
    #[error("MCP dispatcher failed: {0}")]
    Dispatcher(String),
}

impl McpSessionError {
    /// Stable JSON-RPC error code.
    #[must_use]
    pub const fn json_rpc_code(&self) -> i64 {
        match self {
            Self::MethodUnavailable { .. } | Self::RoleViolation { .. } => -32601,
            Self::CapabilityNotNegotiated { .. } => -32003,
            Self::InvalidState { .. } | Self::InvalidTransition { .. } => -32002,
            Self::UnsupportedVersionTransport { .. } => -32001,
            Self::DuplicateRequestId(_) => -32600,
            Self::RequestTimeout(_) | Self::Dispatcher(_) => -32603,
        }
    }
}

/// Executable stable version/transport matrix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionTransportMatrix {
    pairs: BTreeSet<(String, McpTransportKind)>,
}

impl Default for VersionTransportMatrix {
    fn default() -> Self {
        let mut pairs = BTreeSet::new();
        for version in ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"] {
            pairs.insert((version.to_owned(), McpTransportKind::Stdio));
        }
        pairs.insert(("2024-11-05".to_owned(), McpTransportKind::LegacyHttpSse));
        for version in ["2025-03-26", "2025-06-18", "2025-11-25"] {
            pairs.insert((version.to_owned(), McpTransportKind::StreamableHttp));
        }
        Self { pairs }
    }
}

impl VersionTransportMatrix {
    /// Returns whether the exact pair is implemented.
    #[must_use]
    pub fn supports(&self, version: &str, transport: McpTransportKind) -> bool {
        self.pairs.contains(&(version.to_owned(), transport))
    }

    /// Returns stable versions executable over one transport, newest first.
    #[must_use]
    pub fn versions_for(&self, transport: McpTransportKind) -> Vec<String> {
        let mut versions = self
            .pairs
            .iter()
            .filter(|(_version, candidate)| *candidate == transport)
            .map(|(version, _transport)| version.clone())
            .collect::<Vec<_>>();
        versions.sort_by(|left, right| right.cmp(left));
        versions
    }
}

/// Normalized negotiated MCP capability families.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiatedCapabilities {
    /// Server tools.
    pub tools: bool,
    /// Server resources.
    pub resources: bool,
    /// Resource subscription support.
    pub resource_subscriptions: bool,
    /// Server prompts.
    pub prompts: bool,
    /// Server logging.
    pub logging: bool,
    /// Server completion.
    pub completion: bool,
    /// Task lifecycle.
    pub tasks: bool,
    /// Client roots.
    pub roots: bool,
    /// Client sampling.
    pub sampling: bool,
    /// Client elicitation.
    pub elicitation: bool,
}

impl NegotiatedCapabilities {
    /// Combines server and client initialize capabilities.
    #[must_use]
    pub fn from_initialize(client: &ClientCapabilities, server: &ServerCapabilities) -> Self {
        Self {
            tools: server.tools.is_some(),
            resources: server.resources.is_some(),
            resource_subscriptions: server
                .resources
                .as_ref()
                .is_some_and(|resources| resources.subscribe),
            prompts: server.prompts.is_some(),
            logging: server.logging.is_some(),
            completion: server.completions.is_some(),
            tasks: server.tasks.is_some() && client.tasks.is_some(),
            roots: client.roots.is_some(),
            sampling: client.sampling.is_some(),
            elicitation: client.elicitation.is_some(),
        }
    }
}

/// Transport-neutral MCP session state machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpSessionState {
    /// Stable transport session id.
    pub session_id: String,
    /// Local role.
    pub role: McpRole,
    /// Active transport.
    pub transport: McpTransportKind,
    /// Lifecycle state.
    pub lifecycle: McpLifecycle,
    /// Negotiated stable protocol version.
    pub protocol_version: Option<String>,
    /// Negotiated capability families.
    pub capabilities: NegotiatedCapabilities,
}

impl McpSessionState {
    /// Creates a new state machine.
    #[must_use]
    pub fn new(session_id: impl Into<String>, role: McpRole, transport: McpTransportKind) -> Self {
        Self {
            session_id: session_id.into(),
            role,
            transport,
            lifecycle: McpLifecycle::New,
            protocol_version: None,
            capabilities: NegotiatedCapabilities::default(),
        }
    }

    /// Accepts initialize and selects an executable version.
    pub fn begin_initialize(
        &mut self,
        requested_version: &str,
        matrix: &VersionTransportMatrix,
    ) -> Result<String, McpSessionError> {
        self.begin_initialize_with_supported(requested_version, matrix, &[])
    }

    /// Accepts initialize while applying a deployment-supported version list.
    pub fn begin_initialize_with_supported(
        &mut self,
        requested_version: &str,
        matrix: &VersionTransportMatrix,
        supported_versions: &[String],
    ) -> Result<String, McpSessionError> {
        if self.lifecycle != McpLifecycle::New {
            return Err(McpSessionError::InvalidTransition {
                from: self.lifecycle,
                to: McpLifecycle::Initializing,
            });
        }
        let deployment_supports = |version: &str| {
            supported_versions.is_empty()
                || supported_versions
                    .iter()
                    .any(|candidate| candidate == version)
        };
        let selected = if deployment_supports(requested_version)
            && matrix.supports(requested_version, self.transport)
        {
            requested_version.to_owned()
        } else {
            matrix
                .versions_for(self.transport)
                .into_iter()
                .find(|version| deployment_supports(version))
                .ok_or_else(|| McpSessionError::UnsupportedVersionTransport {
                    version: requested_version.to_owned(),
                    transport: self.transport,
                })?
        };
        methods_for_version(&selected).map_err(|_| {
            McpSessionError::UnsupportedVersionTransport {
                version: selected.clone(),
                transport: self.transport,
            }
        })?;
        self.protocol_version = Some(selected.clone());
        self.lifecycle = McpLifecycle::Initializing;
        Ok(selected)
    }

    /// Authorizes an incoming notification before state mutation.
    pub fn authorize_notification(&self, method: McpMethod) -> Result<(), McpSessionError> {
        self.authorize_notification_direction(method, true)
    }

    /// Authorizes a locally emitted notification.
    pub fn authorize_outbound_notification(
        &self,
        method: McpMethod,
    ) -> Result<(), McpSessionError> {
        self.authorize_notification_direction(method, false)
    }

    fn authorize_notification_direction(
        &self,
        method: McpMethod,
        incoming: bool,
    ) -> Result<(), McpSessionError> {
        if method == McpMethod::Initialized {
            let valid_role = (incoming && self.role == McpRole::Server)
                || (!incoming && self.role == McpRole::Client);
            return (self.lifecycle == McpLifecycle::Initializing && valid_role)
                .then_some(())
                .ok_or_else(|| McpSessionError::InvalidState {
                    method: method.to_string(),
                    state: self.lifecycle,
                });
        }
        if self.lifecycle != McpLifecycle::Initialized {
            return Err(McpSessionError::InvalidState {
                method: method.to_string(),
                state: self.lifecycle,
            });
        }
        let version =
            self.protocol_version
                .as_deref()
                .ok_or_else(|| McpSessionError::InvalidState {
                    method: method.to_string(),
                    state: self.lifecycle,
                })?;
        if !methods_for_version(version)
            .map_err(|_| McpSessionError::MethodUnavailable {
                method: method.to_string(),
                version: version.to_owned(),
            })?
            .contains(&method)
        {
            return Err(McpSessionError::MethodUnavailable {
                method: method.to_string(),
                version: version.to_owned(),
            });
        }
        let server_to_client = matches!(
            method,
            McpMethod::ToolsListChanged
                | McpMethod::ResourcesListChanged
                | McpMethod::ResourcesUpdated
                | McpMethod::PromptsListChanged
                | McpMethod::LoggingMessage
                | McpMethod::Progress
                | McpMethod::TasksStatus
        );
        let client_to_server = matches!(method, McpMethod::RootsListChanged);
        let role_violation = if incoming {
            (self.role == McpRole::Server && server_to_client)
                || (self.role == McpRole::Client && client_to_server)
        } else {
            (self.role == McpRole::Server && client_to_server)
                || (self.role == McpRole::Client && server_to_client)
        };
        if role_violation {
            return Err(McpSessionError::RoleViolation {
                method: method.to_string(),
                role: self.role,
            });
        }
        self.authorize_capability(method)
    }

    /// Stores both peers' capability negotiation.
    pub fn set_capabilities(&mut self, client: &ClientCapabilities, server: &ServerCapabilities) {
        self.capabilities = NegotiatedCapabilities::from_initialize(client, server);
    }

    /// Validates and accepts the version selected by the remote server.
    pub fn accept_negotiated_version(
        &mut self,
        version: &str,
        matrix: &VersionTransportMatrix,
        supported_versions: &[String],
    ) -> Result<(), McpSessionError> {
        if self.lifecycle != McpLifecycle::Initializing
            || !matrix.supports(version, self.transport)
            || (!supported_versions.is_empty()
                && !supported_versions
                    .iter()
                    .any(|candidate| candidate == version))
        {
            return Err(McpSessionError::UnsupportedVersionTransport {
                version: version.to_owned(),
                transport: self.transport,
            });
        }
        methods_for_version(version).map_err(|_| McpSessionError::UnsupportedVersionTransport {
            version: version.to_owned(),
            transport: self.transport,
        })?;
        self.protocol_version = Some(version.to_owned());
        Ok(())
    }

    /// Accepts `notifications/initialized`.
    pub fn mark_initialized(&mut self) -> Result<(), McpSessionError> {
        if self.lifecycle != McpLifecycle::Initializing {
            return Err(McpSessionError::InvalidTransition {
                from: self.lifecycle,
                to: McpLifecycle::Initialized,
            });
        }
        self.lifecycle = McpLifecycle::Initialized;
        Ok(())
    }

    /// Starts termination.
    pub fn begin_close(&mut self) -> Result<(), McpSessionError> {
        if matches!(self.lifecycle, McpLifecycle::Closing | McpLifecycle::Closed) {
            return Err(McpSessionError::InvalidTransition {
                from: self.lifecycle,
                to: McpLifecycle::Closing,
            });
        }
        self.lifecycle = McpLifecycle::Closing;
        Ok(())
    }

    /// Completes termination.
    pub fn finish_close(&mut self) -> Result<(), McpSessionError> {
        if self.lifecycle != McpLifecycle::Closing {
            return Err(McpSessionError::InvalidTransition {
                from: self.lifecycle,
                to: McpLifecycle::Closed,
            });
        }
        self.lifecycle = McpLifecycle::Closed;
        Ok(())
    }

    /// Authorizes an incoming request before provider code runs.
    pub fn authorize_request(&self, method: McpMethod) -> Result<(), McpSessionError> {
        self.authorize_method(method, true)
    }

    /// Authorizes a locally initiated request before transport dispatch.
    pub fn authorize_outbound_request(&self, method: McpMethod) -> Result<(), McpSessionError> {
        self.authorize_method(method, false)
    }

    fn authorize_method(&self, method: McpMethod, incoming: bool) -> Result<(), McpSessionError> {
        if method == McpMethod::Initialize {
            return (self.lifecycle == McpLifecycle::New)
                .then_some(())
                .ok_or_else(|| McpSessionError::InvalidState {
                    method: method.to_string(),
                    state: self.lifecycle,
                });
        }
        if method == McpMethod::Ping
            && matches!(
                self.lifecycle,
                McpLifecycle::Initializing | McpLifecycle::Initialized
            )
        {
            return Ok(());
        }
        if self.lifecycle != McpLifecycle::Initialized {
            return Err(McpSessionError::InvalidState {
                method: method.to_string(),
                state: self.lifecycle,
            });
        }
        let version =
            self.protocol_version
                .as_deref()
                .ok_or_else(|| McpSessionError::InvalidState {
                    method: method.to_string(),
                    state: self.lifecycle,
                })?;
        if !methods_for_version(version)
            .map_err(|_| McpSessionError::MethodUnavailable {
                method: method.to_string(),
                version: version.to_owned(),
            })?
            .contains(&method)
        {
            return Err(McpSessionError::MethodUnavailable {
                method: method.to_string(),
                version: version.to_owned(),
            });
        }
        self.authorize_role(method, incoming)?;
        self.authorize_capability(method)
    }

    fn authorize_role(&self, method: McpMethod, incoming: bool) -> Result<(), McpSessionError> {
        let client_facing = matches!(
            method,
            McpMethod::RootsList | McpMethod::SamplingCreateMessage | McpMethod::ElicitationCreate
        );
        let role_violation = if incoming {
            (self.role == McpRole::Server && client_facing)
                || (self.role == McpRole::Client && !client_facing)
        } else {
            (self.role == McpRole::Server && !client_facing)
                || (self.role == McpRole::Client && client_facing)
        };
        if role_violation {
            return Err(McpSessionError::RoleViolation {
                method: method.to_string(),
                role: self.role,
            });
        }
        Ok(())
    }

    fn authorize_capability(&self, method: McpMethod) -> Result<(), McpSessionError> {
        let requirement = match method {
            McpMethod::ToolsList | McpMethod::ToolsCall | McpMethod::ToolsListChanged => {
                Some((self.capabilities.tools, "tools"))
            }
            McpMethod::ResourcesList
            | McpMethod::ResourcesRead
            | McpMethod::ResourcesTemplatesList
            | McpMethod::ResourcesListChanged
            | McpMethod::ResourcesUpdated => Some((self.capabilities.resources, "resources")),
            McpMethod::ResourcesSubscribe | McpMethod::ResourcesUnsubscribe => Some((
                self.capabilities.resource_subscriptions,
                "resources.subscribe",
            )),
            McpMethod::PromptsList | McpMethod::PromptsGet | McpMethod::PromptsListChanged => {
                Some((self.capabilities.prompts, "prompts"))
            }
            McpMethod::CompletionComplete => Some((self.capabilities.completion, "completion")),
            McpMethod::LoggingSetLevel | McpMethod::LoggingMessage => {
                Some((self.capabilities.logging, "logging"))
            }
            McpMethod::TasksList
            | McpMethod::TasksGet
            | McpMethod::TasksResult
            | McpMethod::TasksCancel
            | McpMethod::TasksStatus => Some((self.capabilities.tasks, "tasks")),
            McpMethod::RootsList | McpMethod::RootsListChanged => {
                Some((self.capabilities.roots, "roots"))
            }
            McpMethod::SamplingCreateMessage => Some((self.capabilities.sampling, "sampling")),
            McpMethod::ElicitationCreate => Some((self.capabilities.elicitation, "elicitation")),
            _ => None,
        };
        if let Some((false, capability)) = requirement {
            return Err(McpSessionError::CapabilityNotNegotiated {
                method: method.to_string(),
                capability: capability.to_owned(),
            });
        }
        Ok(())
    }
}

/// JSON-RPC frame accepted by every MCP transport binding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "message", rename_all = "snake_case")]
pub enum McpFrame {
    /// Request requiring a correlated response.
    Request(JsonRpcRequest),
    /// Notification.
    Notification(JsonRpcNotification),
    /// Success or error response.
    Response(JsonRpcResponse),
}

/// Correlation direction relative to the local peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationDirection {
    /// Local peer sent the request.
    Outbound,
    /// Remote peer sent the request.
    Inbound,
}

/// Durable correlation record for long-running MCP requests.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpCorrelationRecord {
    /// Session id.
    pub session_id: String,
    /// Stable JSON-RPC id key.
    pub request_id: String,
    /// Method name.
    pub method: String,
    /// Request direction.
    pub direction: CorrelationDirection,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Deadline.
    pub expires_at: OffsetDateTime,
    /// Terminal response, when received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<JsonRpcResponse>,
    /// Monotonic update revision.
    pub revision: u64,
}

type CorrelationKey = (String, CorrelationDirection, String);
type CorrelationRecords = BTreeMap<CorrelationKey, McpCorrelationRecord>;
type SharedCorrelationRecords = Arc<RwLock<CorrelationRecords>>;

/// Durable MCP correlation store.
#[async_trait]
pub trait McpCorrelationStore: Send + Sync {
    /// Creates a correlation if the id is not active.
    async fn create(&self, record: McpCorrelationRecord) -> Result<(), McpSessionError>;
    /// Stores one terminal response with revision fencing.
    async fn settle(
        &self,
        session_id: &str,
        request_id: &str,
        direction: CorrelationDirection,
        response: JsonRpcResponse,
    ) -> Result<(), McpSessionError>;
    /// Reads one correlation.
    async fn get(
        &self,
        session_id: &str,
        request_id: &str,
        direction: CorrelationDirection,
    ) -> Result<Option<McpCorrelationRecord>, McpSessionError>;
    /// Removes expired terminal records.
    async fn prune(&self, now: OffsetDateTime) -> Result<u64, McpSessionError>;
}

/// In-memory correlation store for embedded and conformance use.
#[derive(Clone, Debug, Default)]
pub struct InMemoryMcpCorrelationStore {
    records: SharedCorrelationRecords,
}

/// Crash-safe single-node correlation store.
///
/// Every mutation replaces one canonical JSON snapshot using `fsync` and an
/// atomic rename. Clustered deployments must use a backend with database CAS
/// semantics; this store deliberately targets the file-backed daemon profile.
#[derive(Clone, Debug)]
pub struct FileMcpCorrelationStore {
    path: PathBuf,
    records: SharedCorrelationRecords,
}

impl FileMcpCorrelationStore {
    /// Opens or creates a durable correlation snapshot.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, McpSessionError> {
        let path = path.into();
        let records = if path.exists() {
            let bytes =
                fs::read(&path).map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
            let values = serde_json::from_slice::<Vec<McpCorrelationRecord>>(&bytes)
                .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
            values
                .into_iter()
                .map(|record| {
                    (
                        (
                            record.session_id.clone(),
                            record.direction,
                            record.request_id.clone(),
                        ),
                        record,
                    )
                })
                .collect()
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path,
            records: Arc::new(RwLock::new(records)),
        })
    }

    fn persist(&self, records: &CorrelationRecords) -> Result<(), McpSessionError> {
        let values = records.values().collect::<Vec<_>>();
        let bytes = serde_json::to_vec_pretty(&values)
            .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
        persist_atomic_file(&self.path, &bytes)
    }
}

#[async_trait]
impl McpCorrelationStore for FileMcpCorrelationStore {
    async fn create(&self, record: McpCorrelationRecord) -> Result<(), McpSessionError> {
        let key = (
            record.session_id.clone(),
            record.direction,
            record.request_id.clone(),
        );
        let mut records = self.records.write().await;
        if records.get(&key).is_some_and(|existing| {
            existing.response.is_none() && existing.expires_at > OffsetDateTime::now_utc()
        }) {
            return Err(McpSessionError::DuplicateRequestId(record.request_id));
        }
        records.insert(key, record);
        self.persist(&records)
    }

    async fn settle(
        &self,
        session_id: &str,
        request_id: &str,
        direction: CorrelationDirection,
        response: JsonRpcResponse,
    ) -> Result<(), McpSessionError> {
        let mut records = self.records.write().await;
        let record = records
            .get_mut(&(session_id.to_owned(), direction, request_id.to_owned()))
            .ok_or_else(|| {
                McpSessionError::Dispatcher(format!(
                    "response for unknown request id `{request_id}`"
                ))
            })?;
        if record.response.is_some() {
            return Err(McpSessionError::DuplicateRequestId(request_id.to_owned()));
        }
        record.response = Some(response);
        record.revision = record.revision.saturating_add(1);
        self.persist(&records)
    }

    async fn get(
        &self,
        session_id: &str,
        request_id: &str,
        direction: CorrelationDirection,
    ) -> Result<Option<McpCorrelationRecord>, McpSessionError> {
        Ok(self
            .records
            .read()
            .await
            .get(&(session_id.to_owned(), direction, request_id.to_owned()))
            .cloned())
    }

    async fn prune(&self, now: OffsetDateTime) -> Result<u64, McpSessionError> {
        let mut records = self.records.write().await;
        let before = records.len();
        records.retain(|_key, record| record.expires_at > now || record.response.is_none());
        let removed = before.saturating_sub(records.len()) as u64;
        if removed > 0 {
            self.persist(&records)?;
        }
        Ok(removed)
    }
}

fn persist_atomic_file(path: &Path, bytes: &[u8]) -> Result<(), McpSessionError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
    fs::rename(&temporary, path).map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
    }
    Ok(())
}

#[async_trait]
impl McpCorrelationStore for InMemoryMcpCorrelationStore {
    async fn create(&self, record: McpCorrelationRecord) -> Result<(), McpSessionError> {
        let key = (
            record.session_id.clone(),
            record.direction,
            record.request_id.clone(),
        );
        let mut records = self.records.write().await;
        if records.get(&key).is_some_and(|existing| {
            existing.response.is_none() && existing.expires_at > OffsetDateTime::now_utc()
        }) {
            return Err(McpSessionError::DuplicateRequestId(record.request_id));
        }
        records.insert(key, record);
        Ok(())
    }

    async fn settle(
        &self,
        session_id: &str,
        request_id: &str,
        direction: CorrelationDirection,
        response: JsonRpcResponse,
    ) -> Result<(), McpSessionError> {
        let mut records = self.records.write().await;
        let record = records
            .get_mut(&(session_id.to_owned(), direction, request_id.to_owned()))
            .ok_or_else(|| {
                McpSessionError::Dispatcher(format!(
                    "response for unknown request id `{request_id}`"
                ))
            })?;
        if record.response.is_some() {
            return Err(McpSessionError::DuplicateRequestId(request_id.to_owned()));
        }
        record.response = Some(response);
        record.revision = record.revision.saturating_add(1);
        Ok(())
    }

    async fn get(
        &self,
        session_id: &str,
        request_id: &str,
        direction: CorrelationDirection,
    ) -> Result<Option<McpCorrelationRecord>, McpSessionError> {
        Ok(self
            .records
            .read()
            .await
            .get(&(session_id.to_owned(), direction, request_id.to_owned()))
            .cloned())
    }

    async fn prune(&self, now: OffsetDateTime) -> Result<u64, McpSessionError> {
        let mut records = self.records.write().await;
        let before = records.len();
        records.retain(|_key, record| record.expires_at > now || record.response.is_none());
        Ok((before.saturating_sub(records.len())) as u64)
    }
}

/// Bidirectional frame transport consumed by [`McpDispatcher`].
#[async_trait]
pub trait McpDuplexTransport: Send + Sync {
    /// Sends one frame.
    async fn send(&self, frame: McpFrame) -> Result<(), McpSessionError>;
    /// Receives the next frame, or `None` when the transport closes cleanly.
    async fn receive(&self) -> Result<Option<McpFrame>, McpSessionError>;
}

type PendingResponse = Result<JsonRpcResponse, McpSessionError>;
type PendingResponseSender = oneshot::Sender<PendingResponse>;
type PendingRequests = Arc<StdMutex<HashMap<String, PendingResponseSender>>>;

/// Concurrent bidirectional JSON-RPC dispatcher.
pub struct McpDispatcher<T, S> {
    session_id: String,
    transport: Arc<T>,
    correlations: Arc<S>,
    pending: PendingRequests,
    incoming_tx: mpsc::Sender<McpFrame>,
    incoming_rx: Mutex<mpsc::Receiver<McpFrame>>,
}

impl<T, S> McpDispatcher<T, S>
where
    T: McpDuplexTransport + 'static,
    S: McpCorrelationStore + 'static,
{
    /// Creates a dispatcher with bounded unrelated-frame buffering.
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        transport: Arc<T>,
        correlations: Arc<S>,
        capacity: usize,
    ) -> Arc<Self> {
        let (incoming_tx, incoming_rx) = mpsc::channel(capacity.max(1));
        Arc::new(Self {
            session_id: session_id.into(),
            transport,
            correlations,
            pending: Arc::new(StdMutex::new(HashMap::new())),
            incoming_tx,
            incoming_rx: Mutex::new(incoming_rx),
        })
    }

    /// Runs the receive pump until the transport closes.
    pub async fn run(self: Arc<Self>) -> Result<(), McpSessionError> {
        let result = self.receive_loop().await;
        let terminal_error = result
            .as_ref()
            .err()
            .cloned()
            .unwrap_or_else(|| McpSessionError::Dispatcher("MCP transport closed".to_owned()));
        let waiters = {
            let mut pending = lock_pending(&self.pending);
            pending
                .drain()
                .map(|(_key, waiter)| waiter)
                .collect::<Vec<_>>()
        };
        for waiter in waiters {
            let _ = waiter.send(Err(terminal_error.clone()));
        }
        result
    }

    async fn receive_loop(&self) -> Result<(), McpSessionError> {
        while let Some(frame) = self.transport.receive().await? {
            match &frame {
                McpFrame::Response(response) => {
                    let key = request_id_to_key(&response.id);
                    self.correlations
                        .settle(
                            &self.session_id,
                            &key,
                            CorrelationDirection::Outbound,
                            response.clone(),
                        )
                        .await?;
                    if let Some(waiter) = lock_pending(&self.pending).remove(&key) {
                        let _ = waiter.send(Ok(response.clone()));
                        continue;
                    }
                }
                McpFrame::Request(request) => {
                    let now = OffsetDateTime::now_utc();
                    self.correlations
                        .create(McpCorrelationRecord {
                            session_id: self.session_id.clone(),
                            request_id: request_id_to_key(&request.id),
                            method: request.method.clone(),
                            direction: CorrelationDirection::Inbound,
                            created_at: now,
                            expires_at: now + time::Duration::minutes(5),
                            response: None,
                            revision: 0,
                        })
                        .await?;
                }
                McpFrame::Notification(_) => {}
            }
            self.incoming_tx.send(frame).await.map_err(|_| {
                McpSessionError::Dispatcher("incoming frame queue closed".to_owned())
            })?;
        }
        Ok(())
    }

    /// Sends a concurrent request and waits only for its correlated response.
    pub async fn request(
        &self,
        request: JsonRpcRequest,
        deadline: Duration,
    ) -> Result<JsonRpcResponse, McpSessionError> {
        let key = request_id_to_key(&request.id);
        let (sender, receiver) = oneshot::channel();
        if lock_pending(&self.pending)
            .insert(key.clone(), sender)
            .is_some()
        {
            return Err(McpSessionError::DuplicateRequestId(key));
        }
        let mut guard = PendingRequestGuard::new(
            key.clone(),
            request.id.clone(),
            self.pending.clone(),
            self.transport.clone(),
        );
        let now = OffsetDateTime::now_utc();
        if let Err(error) = self
            .correlations
            .create(McpCorrelationRecord {
                session_id: self.session_id.clone(),
                request_id: key.clone(),
                method: request.method.clone(),
                direction: CorrelationDirection::Outbound,
                created_at: now,
                expires_at: now
                    + time::Duration::milliseconds(
                        deadline.as_millis().min(i64::MAX as u128) as i64
                    ),
                response: None,
                revision: 0,
            })
            .await
        {
            lock_pending(&self.pending).remove(&key);
            guard.disarm();
            return Err(error);
        }
        if let Err(error) = self.transport.send(McpFrame::Request(request)).await {
            lock_pending(&self.pending).remove(&key);
            guard.disarm();
            return Err(error);
        }
        match tokio::time::timeout(deadline, receiver).await {
            Ok(Ok(Ok(response))) => {
                guard.disarm();
                Ok(response)
            }
            Ok(Ok(Err(error))) => {
                guard.disarm();
                Err(error)
            }
            Ok(Err(_)) => Err(McpSessionError::Dispatcher(format!(
                "response waiter for `{key}` closed"
            ))),
            Err(_) => {
                lock_pending(&self.pending).remove(&key);
                guard.disarm();
                let _ = self
                    .transport
                    .send(McpFrame::Notification(JsonRpcNotification::new(
                        McpMethod::Cancelled,
                        Some(serde_json::json!({
                            "requestId": guard.request_id,
                            "reason": "request deadline exceeded"
                        })),
                    )))
                    .await;
                Err(McpSessionError::RequestTimeout(key))
            }
        }
    }

    /// Sends one notification.
    pub async fn notify(&self, notification: JsonRpcNotification) -> Result<(), McpSessionError> {
        self.transport
            .send(McpFrame::Notification(notification))
            .await
    }

    /// Sends a response for one previously received request and settles its
    /// inbound durable correlation.
    pub async fn respond(&self, response: JsonRpcResponse) -> Result<(), McpSessionError> {
        let key = request_id_to_key(&response.id);
        let correlation = self
            .correlations
            .get(&self.session_id, &key, CorrelationDirection::Inbound)
            .await?
            .ok_or_else(|| {
                McpSessionError::Dispatcher(format!(
                    "response for unknown inbound request id `{key}`"
                ))
            })?;
        if correlation.response.is_some() {
            return Err(McpSessionError::DuplicateRequestId(key));
        }
        self.transport
            .send(McpFrame::Response(response.clone()))
            .await?;
        self.correlations
            .settle(
                &self.session_id,
                &key,
                CorrelationDirection::Inbound,
                response,
            )
            .await
    }

    /// Returns the next unrelated request, notification, or response.
    pub async fn next_incoming(&self) -> Option<McpFrame> {
        self.incoming_rx.lock().await.recv().await
    }
}

fn lock_pending<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct PendingRequestGuard<T>
where
    T: McpDuplexTransport + 'static,
{
    key: String,
    request_id: serde_json::Value,
    pending: PendingRequests,
    transport: Arc<T>,
    armed: bool,
}

impl<T> PendingRequestGuard<T>
where
    T: McpDuplexTransport + 'static,
{
    fn new(
        key: String,
        request_id: serde_json::Value,
        pending: PendingRequests,
        transport: Arc<T>,
    ) -> Self {
        Self {
            key,
            request_id,
            pending,
            transport,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<T> Drop for PendingRequestGuard<T>
where
    T: McpDuplexTransport + 'static,
{
    fn drop(&mut self) {
        if !self.armed || lock_pending(&self.pending).remove(&self.key).is_none() {
            return;
        }
        let transport = self.transport.clone();
        let request_id = self.request_id.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = transport
                    .send(McpFrame::Notification(JsonRpcNotification::new(
                        McpMethod::Cancelled,
                        Some(serde_json::json!({
                            "requestId": request_id,
                            "reason": "local request future was cancelled"
                        })),
                    )))
                    .await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InMemoryMcpCorrelationStore, McpDispatcher, McpDuplexTransport, McpFrame, McpLifecycle,
        McpRole, McpSessionError, McpSessionState, McpTransportKind, VersionTransportMatrix,
    };
    use aip_profile_mcp::{
        ClientCapabilities, JsonRpcRequest, JsonRpcResponse, McpMethod, ServerCapabilities,
    };
    use async_trait::async_trait;
    use serde_json::json;
    use std::{collections::VecDeque, sync::Arc, time::Duration};
    use tokio::sync::Mutex;

    #[test]
    fn state_machine_rejects_pre_initialize_and_transport_mismatch() {
        let matrix = VersionTransportMatrix::default();
        let mut state =
            McpSessionState::new("s", McpRole::Server, McpTransportKind::StreamableHttp);
        assert!(matches!(
            state.authorize_request(McpMethod::ToolsList),
            Err(McpSessionError::InvalidState { .. })
        ));
        let selected = state
            .begin_initialize("2024-11-05", &matrix)
            .expect("fallback version");
        assert_ne!(selected, "2024-11-05");
        state.set_capabilities(
            &ClientCapabilities::default(),
            &ServerCapabilities {
                tools: Some(Default::default()),
                ..ServerCapabilities::default()
            },
        );
        state.mark_initialized().expect("initialized");
        assert_eq!(state.lifecycle, McpLifecycle::Initialized);
        state
            .authorize_request(McpMethod::ToolsList)
            .expect("tools");
    }

    #[derive(Default)]
    struct Loopback {
        incoming: Mutex<VecDeque<McpFrame>>,
    }

    #[async_trait]
    impl McpDuplexTransport for Loopback {
        async fn send(&self, frame: McpFrame) -> Result<(), McpSessionError> {
            if let McpFrame::Request(request) = frame {
                self.incoming.lock().await.push_back(McpFrame::Notification(
                    aip_profile_mcp::JsonRpcNotification::new(
                        McpMethod::Progress,
                        Some(json!({ "progress": 1 })),
                    ),
                ));
                self.incoming
                    .lock()
                    .await
                    .push_back(McpFrame::Response(JsonRpcResponse::success(
                        request.id,
                        json!({ "ok": true }),
                    )));
            }
            Ok(())
        }

        async fn receive(&self) -> Result<Option<McpFrame>, McpSessionError> {
            loop {
                if let Some(frame) = self.incoming.lock().await.pop_front() {
                    return Ok(Some(frame));
                }
                tokio::task::yield_now().await;
            }
        }
    }

    #[tokio::test]
    async fn dispatcher_preserves_unrelated_frames_while_correlating_response() {
        let transport = Arc::new(Loopback::default());
        let dispatcher = McpDispatcher::new(
            "s",
            transport,
            Arc::new(InMemoryMcpCorrelationStore::default()),
            8,
        );
        let pump = tokio::spawn(dispatcher.clone().run());
        let response = dispatcher
            .request(
                JsonRpcRequest::new(json!(1), McpMethod::RootsList, Some(json!({}))),
                Duration::from_secs(1),
            )
            .await
            .expect("response");
        assert_eq!(response.result, Some(json!({ "ok": true })));
        assert!(matches!(
            dispatcher.next_incoming().await,
            Some(McpFrame::Notification(_))
        ));
        pump.abort();
    }
}
