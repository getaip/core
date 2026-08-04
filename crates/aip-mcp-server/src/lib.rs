//! AIP-backed MCP server runtime.
//!
//! This crate exposes an AIP gateway as a Model Context Protocol server while
//! keeping MCP lifecycle, sessions, request correlation, resources, prompts,
//! completions, and task views outside of `aip-core`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_auth::{AuthScheme, AuthenticatedPrincipal, VerifiedTenant};
use aip_connector_registry::{
    CapabilityCatalogProvider, CapabilityCatalogQuery, CatalogReadContext, RegistryError,
};
use aip_core::{
    Action, ActionEventsRequest, ActionId, ActionListRequest, ActionMode, ActionResultRequest,
    ActionStatusRequest, ActionTransaction, ApprovalDecision, ApprovalDecisionKind, ApprovalId,
    ApprovalListRequest, ApprovalQueryRequest, AuditQueryRequest, Callback,
    CallbackDeliveryListRequest, CallbackDeliveryQueryRequest, CallbackDeliveryStatus, Cancel,
    CancelTarget, Capability, CapabilityId, ComplianceContext, Conversation, DelegationEntry,
    DelegationId, DelegationRequest, Envelope, EventStreamRequest, EvidenceArtifact,
    FederationContext, IdentityContext, Manifest, MessageBody, ObservabilityContext, Principal,
    PrincipalId, PrincipalKind, ProfileId, ProtocolError, ReceiptId, ReceiptQueryRequest, Resource,
    ResourceListRequest, ResourceReadRequest, SessionCloseRequest, SessionListRequest,
    SessionRequest, SessionResumeRequest, TransactionId, TransactionQueryRequest,
};
use aip_gateway::{Gateway, GatewayError};
use aip_mcp_session::{
    McpRole, McpSessionError, McpSessionState, McpTransportKind, VersionTransportMatrix,
};
use aip_profile_mcp::{
    ClientCapabilities, ImplementationInfo, InitializeParams, JsonRpcError, JsonRpcNotification,
    JsonRpcRequest, JsonRpcResponse, ListChangedCapability, McpMethod, McpProfileError, McpTool,
    Prompt, PromptMessage, ResourceCapability, ResourceContents, ResourceTemplate, Root,
    ServerCapabilities, Task, TaskStatus, TaskSupport, ToolExecution,
    action_from_tools_call_with_manifest, aip_extension_meta, call_tool_result, completion_result,
    error_response, initialize_result_with_capabilities, json_rpc_error, methods_for_version,
    progress_notification_from_stream_chunk, prompts_list_result, protocol_error_from_profile,
    request_id_to_key, resource_from_aip, resource_templates_list_result, resources_read_result,
    server_info_from_manifest, success_response, tools_from_manifest, tools_list_result_from_tools,
};
use aip_schema::validation_errors_draft202012;
use async_trait::async_trait;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock};

#[derive(Clone, Debug)]
struct McpRequestIdentity {
    actor: AuthenticatedPrincipal,
    tenant: Option<VerifiedTenant>,
}

tokio::task_local! {
    static MCP_REQUEST_IDENTITY: McpRequestIdentity;
}

/// MCP server error.
#[derive(Debug, Error)]
pub enum McpServerError {
    /// MCP lifecycle, role, version, or capability gate failed.
    #[error("MCP session error: {0}")]
    Session(#[from] McpSessionError),
    /// MCP profile mapping failed.
    #[error("MCP profile error: {0}")]
    Profile(#[from] McpProfileError),
    /// AIP gateway failed.
    #[error("AIP gateway error: {0}")]
    Gateway(#[from] GatewayError),
    /// Provider failed.
    #[error("provider error: {0}")]
    Provider(String),
}

/// Result alias for MCP server operations.
pub type McpServerResult<T> = Result<T, McpServerError>;

const AIP_CAPABILITIES_TOOL: &str = "aip_capabilities";
const AIP_CALL_TOOL: &str = "aip_call";
const AIP_EVENTS_TOOL: &str = "aip_events";
const AIP_ACTION_STATUS_TOOL: &str = "aip_action_status";
const AIP_ACTION_RESULT_TOOL: &str = "aip_action_result";
const AIP_ACTION_LIST_TOOL: &str = "aip_action_list";
const AIP_ACTION_EVENTS_TOOL: &str = "aip_action_events";
const AIP_ACTION_CANCEL_TOOL: &str = "aip_action_cancel";
const AIP_SESSION_GET_TOOL: &str = "aip_session_get";
const AIP_SESSION_LIST_TOOL: &str = "aip_session_list";
const AIP_SESSION_CLOSE_TOOL: &str = "aip_session_close";
const AIP_SESSION_RESUME_TOOL: &str = "aip_session_resume";
const AIP_APPROVAL_GET_TOOL: &str = "aip_approval_get";
const AIP_APPROVAL_LIST_TOOL: &str = "aip_approval_list";
const AIP_APPROVAL_DECIDE_TOOL: &str = "aip_approval_decide";
const AIP_CALLBACK_DELIVERY_GET_TOOL: &str = "aip_callback_delivery_get";
const AIP_CALLBACK_DELIVERY_LIST_TOOL: &str = "aip_callback_delivery_list";
const AIP_TRANSACTION_GET_TOOL: &str = "aip_transaction_get";
const AIP_RECEIPT_GET_TOOL: &str = "aip_receipt_get";
const AIP_AUDIT_EVENTS_TOOL: &str = "aip_audit_events";
const AIP_RESOURCE_LIST_TOOL: &str = "aip_resource_list";
const AIP_RESOURCE_READ_TOOL: &str = "aip_resource_read";
const AIP_SCENARIO_RUN_TOOL: &str = "aip_scenario_run";
const AIP_DELEGATE_TOOL: &str = "aip_delegate";

/// Resource provider for MCP `resources/*`.
#[async_trait]
pub trait ResourceProvider: Send + Sync {
    /// Returns the resource capability this provider can execute.
    fn advertised_capability(&self) -> Option<ResourceCapability>;

    /// Lists resources.
    async fn list(
        &self,
        cursor: Option<String>,
    ) -> McpServerResult<(Vec<aip_profile_mcp::McpResource>, Option<String>)>;
    /// Lists resource templates.
    async fn templates(&self) -> McpServerResult<Vec<ResourceTemplate>>;
    /// Reads a resource by URI.
    async fn read(&self, uri: &str) -> McpServerResult<Vec<ResourceContents>>;
    /// Subscribes to a resource URI.
    async fn subscribe(&self, _uri: &str) -> McpServerResult<()> {
        Err(McpServerError::Provider(
            "resource subscriptions are not supported by this provider".to_owned(),
        ))
    }
    /// Unsubscribes from a resource URI.
    async fn unsubscribe(&self, _uri: &str) -> McpServerResult<()> {
        Err(McpServerError::Provider(
            "resource subscriptions are not supported by this provider".to_owned(),
        ))
    }
}

/// Prompt provider for MCP `prompts/*`.
#[async_trait]
pub trait PromptProvider: Send + Sync {
    /// Returns whether this provider has a real prompt catalog.
    fn is_available(&self) -> bool;

    /// Lists prompts.
    async fn list(&self, cursor: Option<String>) -> McpServerResult<(Vec<Prompt>, Option<String>)>;
    /// Gets a prompt by name.
    async fn get(
        &self,
        name: &str,
        arguments: BTreeMap<String, String>,
    ) -> McpServerResult<(Option<String>, Vec<PromptMessage>, Option<Value>)>;
}

/// Completion provider for MCP `completion/complete`.
#[async_trait]
pub trait CompletionProvider: Send + Sync {
    /// Returns whether this provider implements completion.
    fn is_available(&self) -> bool;

    /// Completes a prompt or resource argument.
    async fn complete(
        &self,
        reference: Value,
        argument: Value,
    ) -> McpServerResult<(Vec<String>, Option<u64>, bool)>;
}

/// Client callback provider for MCP server-to-client requests.
#[async_trait]
pub trait ClientRequestProvider: Send + Sync {
    /// Returns workspace roots exposed by the client.
    async fn roots(&self) -> McpServerResult<Vec<Root>>;
    /// Performs client-side sampling.
    async fn sample(&self, params: Value) -> McpServerResult<Value>;
    /// Performs client-side elicitation.
    async fn elicit(&self, params: Value) -> McpServerResult<Value>;
}

/// Transport boundary for real server-to-client MCP requests.
#[async_trait]
pub trait McpPeerTransport: Send + Sync {
    /// Sends one request to the client bound to `session_id` and waits for its
    /// correlated response.
    async fn request(
        &self,
        session_id: &str,
        request: JsonRpcRequest,
        timeout: Duration,
    ) -> McpServerResult<JsonRpcResponse>;
    /// Sends one server notification to the bound client.
    async fn notify(
        &self,
        session_id: &str,
        notification: JsonRpcNotification,
    ) -> McpServerResult<()>;
}

#[derive(Clone, Debug, Default)]
struct UnavailableMcpPeerTransport;

#[async_trait]
impl McpPeerTransport for UnavailableMcpPeerTransport {
    async fn request(
        &self,
        _session_id: &str,
        _request: JsonRpcRequest,
        _timeout: Duration,
    ) -> McpServerResult<JsonRpcResponse> {
        Err(McpServerError::Provider(
            "no bidirectional MCP peer transport is configured".to_owned(),
        ))
    }

    async fn notify(
        &self,
        _session_id: &str,
        _notification: JsonRpcNotification,
    ) -> McpServerResult<()> {
        Err(McpServerError::Provider(
            "no bidirectional MCP peer transport is configured".to_owned(),
        ))
    }
}

/// Empty resource provider.
#[derive(Clone, Debug, Default)]
pub struct EmptyResourceProvider;

#[async_trait]
impl ResourceProvider for EmptyResourceProvider {
    fn advertised_capability(&self) -> Option<ResourceCapability> {
        None
    }

    async fn list(
        &self,
        _cursor: Option<String>,
    ) -> McpServerResult<(Vec<aip_profile_mcp::McpResource>, Option<String>)> {
        Ok((Vec::new(), None))
    }

    async fn templates(&self) -> McpServerResult<Vec<ResourceTemplate>> {
        Ok(Vec::new())
    }

    async fn read(&self, uri: &str) -> McpServerResult<Vec<ResourceContents>> {
        Err(McpServerError::Provider(format!(
            "resource `{uri}` was not found"
        )))
    }
}

/// Resource provider backed by static resource metadata from an AIP manifest.
#[derive(Clone, Debug)]
pub struct ManifestResourceProvider {
    resources: Vec<Resource>,
}

impl ManifestResourceProvider {
    /// Creates a provider from manifest resources.
    #[must_use]
    pub fn new(resources: Vec<Resource>) -> Self {
        Self { resources }
    }
}

#[async_trait]
impl ResourceProvider for ManifestResourceProvider {
    fn advertised_capability(&self) -> Option<ResourceCapability> {
        (!self.resources.is_empty()).then_some(ResourceCapability {
            subscribe: false,
            list_changed: false,
        })
    }

    async fn list(
        &self,
        cursor: Option<String>,
    ) -> McpServerResult<(Vec<aip_profile_mcp::McpResource>, Option<String>)> {
        let resources = self
            .resources
            .iter()
            .map(resource_from_aip)
            .collect::<Vec<_>>();
        let start = cursor
            .as_deref()
            .and_then(|value| value.strip_prefix("offset:"))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let end = resources.len();
        let page = resources[start.min(end)..end].to_vec();
        Ok((page, None))
    }

    async fn templates(&self) -> McpServerResult<Vec<ResourceTemplate>> {
        Ok(Vec::new())
    }

    async fn read(&self, uri: &str) -> McpServerResult<Vec<ResourceContents>> {
        if self.resources.iter().any(|resource| resource.id == uri) {
            return Err(McpServerError::Provider(format!(
                "resource `{uri}` is declared in the manifest but no content provider is configured"
            )));
        }
        Err(McpServerError::Provider(format!(
            "resource `{uri}` was not found"
        )))
    }
}

/// Empty prompt provider.
#[derive(Clone, Debug, Default)]
pub struct EmptyPromptProvider;

#[async_trait]
impl PromptProvider for EmptyPromptProvider {
    fn is_available(&self) -> bool {
        false
    }

    async fn list(
        &self,
        _cursor: Option<String>,
    ) -> McpServerResult<(Vec<Prompt>, Option<String>)> {
        Ok((Vec::new(), None))
    }

    async fn get(
        &self,
        name: &str,
        _arguments: BTreeMap<String, String>,
    ) -> McpServerResult<(Option<String>, Vec<PromptMessage>, Option<Value>)> {
        Err(McpServerError::Provider(format!(
            "prompt `{name}` was not found"
        )))
    }
}

/// Empty completion provider.
#[derive(Clone, Debug, Default)]
pub struct EmptyCompletionProvider;

#[async_trait]
impl CompletionProvider for EmptyCompletionProvider {
    fn is_available(&self) -> bool {
        false
    }

    async fn complete(
        &self,
        _reference: Value,
        _argument: Value,
    ) -> McpServerResult<(Vec<String>, Option<u64>, bool)> {
        Ok((Vec::new(), Some(0), false))
    }
}

/// Empty client request provider.
#[derive(Clone, Debug, Default)]
pub struct EmptyClientRequestProvider;

#[async_trait]
impl ClientRequestProvider for EmptyClientRequestProvider {
    async fn roots(&self) -> McpServerResult<Vec<Root>> {
        Ok(Vec::new())
    }

    async fn sample(&self, _params: Value) -> McpServerResult<Value> {
        Err(McpServerError::Provider(
            "sampling is not configured for this MCP server".to_owned(),
        ))
    }

    async fn elicit(&self, _params: Value) -> McpServerResult<Value> {
        Err(McpServerError::Provider(
            "elicitation is not configured for this MCP server".to_owned(),
        ))
    }
}

/// MCP server configuration.
#[derive(Clone)]
pub struct McpServerConfig {
    /// Local AIP manifest.
    pub manifest: Manifest,
    /// AIP gateway used for tool calls.
    pub gateway: Gateway,
    /// Optional tenant-scoped fleet catalog used by the stable facade only.
    pub capability_catalog: Option<Arc<dyn CapabilityCatalogProvider>>,
    /// Server implementation metadata.
    pub server_info: ImplementationInfo,
    /// Supported MCP protocol versions.
    pub supported_versions: Vec<String>,
    /// Principal used for MCP-originated AIP calls.
    pub mcp_principal: Principal,
    /// Resource provider.
    pub resources: Arc<dyn ResourceProvider>,
    /// Prompt provider.
    pub prompts: Arc<dyn PromptProvider>,
    /// Completion provider.
    pub completions: Arc<dyn CompletionProvider>,
    /// Client request provider.
    pub client_requests: Arc<dyn ClientRequestProvider>,
    /// Real wire transport for server-to-client requests and notifications.
    pub peer_transport: Arc<dyn McpPeerTransport>,
    /// Whether MCP `tools/call` validates `structuredContent` against the
    /// matched tool `outputSchema` before returning a JSON-RPC result.
    pub enforce_output_schema: bool,
    /// Whether stable AIP facade tools are exposed alongside generated tools.
    pub expose_stable_facade_tools: bool,
    /// Whether each manifest capability is exposed as a generated MCP tool.
    pub expose_generated_capability_tools: bool,
    /// Whether this server accepts MCP logging-level control.
    pub logging_enabled: bool,
    /// Whether native AIP action state is projected as MCP tasks when the
    /// negotiated MCP version supports tasks.
    pub tasks_enabled: bool,
    /// Whether a durable event projector emits dynamic MCP notifications.
    pub dynamic_notifications_enabled: bool,
}

impl McpServerConfig {
    /// Builds a server config for an AIP gateway.
    #[must_use]
    pub fn new(manifest: Manifest, gateway: Gateway) -> Self {
        let resources = Arc::new(ManifestResourceProvider::new(manifest.resources.clone()));
        Self {
            server_info: server_info_from_manifest(&manifest),
            manifest,
            gateway,
            capability_catalog: None,
            supported_versions: aip_profile_mcp::SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .map(|version| (*version).to_owned())
                .collect(),
            mcp_principal: Principal::new(
                PrincipalId::trusted("agent:mcp:client"),
                PrincipalKind::Agent,
            ),
            resources,
            prompts: Arc::new(EmptyPromptProvider),
            completions: Arc::new(EmptyCompletionProvider),
            client_requests: Arc::new(EmptyClientRequestProvider),
            peer_transport: Arc::new(UnavailableMcpPeerTransport),
            enforce_output_schema: true,
            expose_stable_facade_tools: true,
            expose_generated_capability_tools: true,
            logging_enabled: true,
            tasks_enabled: true,
            dynamic_notifications_enabled: false,
        }
    }

    /// Sets the authenticated principal represented by this MCP transport edge.
    ///
    /// The principal must be derived from the spawning host, OAuth token, mTLS
    /// identity, or another authenticated transport credential. Request payloads
    /// must never be allowed to select this principal.
    #[must_use]
    pub fn with_mcp_principal(mut self, principal: Principal) -> Self {
        self.mcp_principal = principal;
        self
    }

    /// Enables or disables MCP logging methods and advertisement.
    #[must_use]
    pub fn with_logging(mut self, enabled: bool) -> Self {
        self.logging_enabled = enabled;
        self
    }

    /// Enables or disables the MCP task projection.
    #[must_use]
    pub fn with_tasks(mut self, enabled: bool) -> Self {
        self.tasks_enabled = enabled;
        self
    }

    /// Declares that a durable dynamic-notification projector is installed.
    #[must_use]
    pub fn with_dynamic_notifications(mut self, enabled: bool) -> Self {
        self.dynamic_notifications_enabled = enabled;
        self
    }

    /// Replaces the resource provider.
    #[must_use]
    pub fn with_resource_provider<P>(mut self, provider: P) -> Self
    where
        P: ResourceProvider + 'static,
    {
        self.resources = Arc::new(provider);
        self
    }

    /// Replaces the prompt provider.
    #[must_use]
    pub fn with_prompt_provider<P>(mut self, provider: P) -> Self
    where
        P: PromptProvider + 'static,
    {
        self.prompts = Arc::new(provider);
        self
    }

    /// Replaces the completion provider.
    #[must_use]
    pub fn with_completion_provider<P>(mut self, provider: P) -> Self
    where
        P: CompletionProvider + 'static,
    {
        self.completions = Arc::new(provider);
        self
    }

    /// Replaces the client request provider.
    #[must_use]
    pub fn with_client_request_provider<P>(mut self, provider: P) -> Self
    where
        P: ClientRequestProvider + 'static,
    {
        self.client_requests = Arc::new(provider);
        self
    }

    /// Installs the real bidirectional transport used for requests to MCP
    /// clients. The transport is session-aware and must preserve request ids.
    #[must_use]
    pub fn with_peer_transport<P>(mut self, transport: P) -> Self
    where
        P: McpPeerTransport + 'static,
    {
        self.peer_transport = Arc::new(transport);
        self
    }

    /// Enables or disables MCP output schema enforcement.
    ///
    /// Enforcement is enabled by default because MCP clients rely on
    /// `structuredContent` matching the advertised tool `outputSchema`. Test
    /// harnesses can disable it when intentionally exercising invalid peers.
    #[must_use]
    pub fn with_output_schema_enforcement(mut self, enforce: bool) -> Self {
        self.enforce_output_schema = enforce;
        self
    }

    /// Enables or disables the stable AIP facade tools.
    ///
    /// The facade tools keep the MCP surface stable while the underlying AIP
    /// manifest evolves. Disabling them is useful only for compatibility tests
    /// that need to observe the generated MCP mapping in isolation.
    #[must_use]
    pub fn with_stable_facade_tools(mut self, expose: bool) -> Self {
        self.expose_stable_facade_tools = expose;
        self
    }

    /// Enables or disables generated per-capability MCP tools.
    ///
    /// Production AIP clients should prefer the stable facade; generated tools
    /// remain useful for legacy MCP clients that expect one typed tool per
    /// capability.
    #[must_use]
    pub fn with_generated_capability_tools(mut self, expose: bool) -> Self {
        self.expose_generated_capability_tools = expose;
        self
    }

    /// Installs a tenant-scoped fleet catalog for `aip_capabilities`.
    ///
    /// Generated per-capability tools are disabled because a fleet catalog is
    /// intentionally not projected into a global in-memory MCP tool list. A
    /// deployment may explicitly re-enable the bounded local manifest tools
    /// after calling this builder.
    #[must_use]
    pub fn with_capability_catalog<C>(mut self, catalog: C) -> Self
    where
        C: CapabilityCatalogProvider + 'static,
    {
        self.capability_catalog = Some(Arc::new(catalog));
        self.expose_generated_capability_tools = false;
        self
    }

    /// Installs a shared fleet catalog trait object.
    #[must_use]
    pub fn with_capability_catalog_arc(
        mut self,
        catalog: Arc<dyn CapabilityCatalogProvider>,
    ) -> Self {
        self.capability_catalog = Some(catalog);
        self.expose_generated_capability_tools = false;
        self
    }
}

/// MCP session state.
#[derive(Clone, Debug)]
pub struct McpSession {
    /// Session id assigned by the transport.
    pub id: String,
    /// Authoritative MCP lifecycle and negotiation state.
    pub state: McpSessionState,
    /// Client capabilities.
    pub client_capabilities: ClientCapabilities,
    /// Client implementation metadata.
    pub client_info: Option<ImplementationInfo>,
    /// JSON-RPC request id to AIP action id correlation.
    pub action_by_request_id: BTreeMap<String, aip_core::ActionId>,
    /// Task views by MCP task id.
    pub tasks: BTreeMap<String, StoredTask>,
    /// Current logging level.
    pub logging_level: String,
    /// Resource URIs subscribed by this negotiated client session.
    pub resource_subscriptions: BTreeSet<String>,
    /// Transport-established identity bound to this session.
    identity: McpRequestIdentity,
}

impl McpSession {
    /// Creates a new MCP session.
    #[must_use]
    fn new(
        id: impl Into<String>,
        transport: McpTransportKind,
        identity: McpRequestIdentity,
    ) -> Self {
        let id = id.into();
        Self {
            id: id.clone(),
            state: McpSessionState::new(id, McpRole::Server, transport),
            client_capabilities: ClientCapabilities::default(),
            client_info: None,
            action_by_request_id: BTreeMap::new(),
            tasks: BTreeMap::new(),
            logging_level: "info".to_owned(),
            resource_subscriptions: BTreeSet::new(),
            identity,
        }
    }
}

/// Stored task and optional terminal result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredTask {
    /// MCP task view.
    pub task: Task,
    /// Terminal JSON result when available.
    pub result: Option<Value>,
}

/// Durable snapshot of one MCP server session.
///
/// Pending duplex requests are deliberately excluded: a process crash makes
/// their transport response channel unreachable. Negotiation, request/action
/// correlation, task views, logging state, and transport-bound identity are
/// retained so a resumable HTTP stream can continue after restart.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpServerSessionSnapshot {
    /// Authoritative lifecycle and negotiated capabilities.
    pub state: McpSessionState,
    /// Client-advertised capabilities.
    pub client_capabilities: ClientCapabilities,
    /// Client implementation metadata.
    pub client_info: Option<ImplementationInfo>,
    /// JSON-RPC request to native action correlation.
    pub action_by_request_id: BTreeMap<String, aip_core::ActionId>,
    /// Session-local task projections.
    pub tasks: BTreeMap<String, StoredTask>,
    /// Current logging level.
    pub logging_level: String,
    /// Resource subscriptions owned by this session.
    pub resource_subscriptions: BTreeSet<String>,
    /// Transport-authenticated actor bound to the session.
    pub actor: AuthenticatedPrincipal,
    /// Verified tenant membership bound to the session.
    pub tenant: Option<VerifiedTenant>,
}

/// AIP-backed MCP server.
#[derive(Clone)]
pub struct McpServer {
    config: Arc<McpServerConfig>,
    sessions: Arc<RwLock<BTreeMap<String, McpSession>>>,
    subscription_lock: Arc<Mutex<()>>,
}

impl McpServer {
    /// Creates an MCP server from config.
    #[must_use]
    pub fn new(config: McpServerConfig) -> Self {
        Self {
            config: Arc::new(config),
            sessions: Arc::default(),
            subscription_lock: Arc::default(),
        }
    }

    /// Returns the local manifest.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.config.manifest
    }

    /// Creates or returns a mutable session.
    async fn session(&self, session_id: &str, transport: McpTransportKind) -> McpSession {
        let identity = self.default_request_identity();
        let mut sessions = self.sessions.write().await;
        sessions
            .entry(session_id.to_owned())
            .or_insert_with(|| McpSession::new(session_id, transport, identity))
            .clone()
    }

    fn default_request_identity(&self) -> McpRequestIdentity {
        McpRequestIdentity {
            actor: AuthenticatedPrincipal {
                principal: self.config.mcp_principal.clone(),
                scheme: AuthScheme::DidProof,
                issuer: "aip-mcp:host".to_owned(),
                audience: Some("aip".to_owned()),
                scopes: principal_scopes(&self.config.mcp_principal),
                authenticated_at: OffsetDateTime::now_utc(),
                expires_at: None,
                credential_fingerprint: None,
            },
            tenant: None,
        }
    }

    /// Binds a transport-authenticated identity to an MCP session.
    pub async fn bind_session_identity(
        &self,
        session_id: &str,
        transport: McpTransportKind,
        actor: AuthenticatedPrincipal,
        tenant: Option<VerifiedTenant>,
    ) -> McpServerResult<()> {
        actor
            .validate(&BTreeSet::new())
            .map_err(|error| McpServerError::Provider(error.to_string()))?;
        let mut sessions = self.sessions.write().await;
        match sessions.get_mut(session_id) {
            Some(session) => {
                if session.identity.actor.principal.id != actor.principal.id
                    || session.identity.actor.issuer != actor.issuer
                {
                    return Err(McpServerError::Provider(
                        "MCP session is already bound to another identity".to_owned(),
                    ));
                }
                session.identity = McpRequestIdentity { actor, tenant };
            }
            None => {
                sessions.insert(
                    session_id.to_owned(),
                    McpSession::new(session_id, transport, McpRequestIdentity { actor, tenant }),
                );
            }
        }
        Ok(())
    }

    async fn replace_session(&self, session: McpSession) {
        self.sessions
            .write()
            .await
            .insert(session.id.clone(), session);
    }

    async fn insert_action_correlation(
        &self,
        session_id: &str,
        request_id: String,
        action_id: ActionId,
    ) -> McpServerResult<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(session_id).ok_or_else(|| {
            McpServerError::Provider(format!("MCP session `{session_id}` is not active"))
        })?;
        session.action_by_request_id.insert(request_id, action_id);
        Ok(())
    }

    async fn remove_action_correlation(&self, session_id: &str, request_id: &str) {
        if let Some(session) = self.sessions.write().await.get_mut(session_id) {
            session.action_by_request_id.remove(request_id);
        }
    }

    async fn store_task(
        &self,
        session_id: &str,
        task_id: String,
        task: StoredTask,
    ) -> McpServerResult<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(session_id).ok_or_else(|| {
            McpServerError::Provider(format!("MCP session `{session_id}` is not active"))
        })?;
        session.tasks.insert(task_id, task);
        Ok(())
    }

    /// Handles an MCP JSON-RPC request.
    pub async fn handle_request(
        &self,
        session_id: &str,
        request: JsonRpcRequest,
    ) -> JsonRpcResponse {
        self.handle_request_on_transport(session_id, McpTransportKind::Stdio, request)
            .await
    }

    /// Handles a request over an explicit versioned transport binding.
    pub async fn handle_request_on_transport(
        &self,
        session_id: &str,
        transport: McpTransportKind,
        request: JsonRpcRequest,
    ) -> JsonRpcResponse {
        let id = request.id.clone();
        let identity = self.session(session_id, transport).await.identity;
        let result = MCP_REQUEST_IDENTITY
            .scope(
                identity,
                self.handle_request_inner(session_id, transport, request),
            )
            .await;
        match result {
            Ok(result) => success_response(id, result),
            Err(error) => error_response(id, json_rpc_error_for_server(error)),
        }
    }

    /// Handles an MCP JSON-RPC notification.
    pub async fn handle_notification(
        &self,
        session_id: &str,
        notification: JsonRpcNotification,
    ) -> McpServerResult<()> {
        self.handle_notification_on_transport(session_id, McpTransportKind::Stdio, notification)
            .await
    }

    /// Handles a notification over an explicit transport binding.
    pub async fn handle_notification_on_transport(
        &self,
        session_id: &str,
        transport: McpTransportKind,
        notification: JsonRpcNotification,
    ) -> McpServerResult<()> {
        let mut session = self.session(session_id, transport).await;
        let identity = session.identity.clone();
        let authenticated_principal = identity.actor.principal.clone();
        MCP_REQUEST_IDENTITY
            .scope(identity, async move {
                let method = notification.method.parse::<McpMethod>()?;
                session.state.authorize_notification(method)?;
                match method {
                    McpMethod::Initialized => {
                        session.state.mark_initialized()?;
                        self.replace_session(session).await;
                        Ok(())
                    }
                    McpMethod::Cancelled => {
                        let cancel = aip_profile_mcp::cancel_from_notification(
                            &notification,
                            &session.action_by_request_id,
                        )?;
                        if let Some(cancel) = cancel {
                            let mut envelope = Envelope::new(MessageBody::Cancel(cancel));
                            envelope.from = Some(authenticated_principal);
                            self.dispatch_envelope(envelope).await?;
                        }
                        Ok(())
                    }
                    McpMethod::ElicitationComplete
                    | McpMethod::Progress
                    | McpMethod::RootsListChanged
                    | McpMethod::ToolsListChanged
                    | McpMethod::ResourcesListChanged
                    | McpMethod::ResourcesUpdated
                    | McpMethod::PromptsListChanged
                    | McpMethod::TasksStatus
                    | McpMethod::LoggingMessage
                    | McpMethod::SubscriptionsAcknowledged => Ok(()),
                    method => Err(McpProfileError::UnsupportedMethod(method.to_string()).into()),
                }
            })
            .await
    }

    /// Deletes an MCP session and releases provider subscriptions that are no
    /// longer referenced by another active session.
    pub async fn delete_session(&self, session_id: &str) -> McpServerResult<bool> {
        let _subscription_guard = self.subscription_lock.lock().await;
        let subscriptions = self
            .sessions
            .read()
            .await
            .get(session_id)
            .map(|session| session.resource_subscriptions.clone());
        let Some(subscriptions) = subscriptions else {
            return Ok(false);
        };
        for uri in &subscriptions {
            let referenced_elsewhere = self.sessions.read().await.iter().any(|(id, session)| {
                id != session_id && session.resource_subscriptions.contains(uri)
            });
            if !referenced_elsewhere {
                self.config.resources.unsubscribe(uri).await?;
            }
        }
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            let _ = session.state.begin_close();
            let _ = session.state.finish_close();
        }
        Ok(sessions.remove(session_id).is_some())
    }

    /// Returns a snapshot of one active session state machine.
    pub async fn session_state(&self, session_id: &str) -> Option<McpSessionState> {
        self.sessions
            .read()
            .await
            .get(session_id)
            .map(|session| session.state.clone())
    }

    /// Returns the number of active MCP sessions.
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Returns stable snapshots of every MCP session state machine.
    pub async fn session_states(&self) -> Vec<(String, McpSessionState)> {
        self.sessions
            .read()
            .await
            .iter()
            .map(|(id, session)| (id.clone(), session.state.clone()))
            .collect()
    }

    /// Returns a durable snapshot of one active session.
    pub async fn session_snapshot(&self, session_id: &str) -> Option<McpServerSessionSnapshot> {
        self.sessions
            .read()
            .await
            .get(session_id)
            .map(|session| McpServerSessionSnapshot {
                state: session.state.clone(),
                client_capabilities: session.client_capabilities.clone(),
                client_info: session.client_info.clone(),
                action_by_request_id: session.action_by_request_id.clone(),
                tasks: session.tasks.clone(),
                logging_level: session.logging_level.clone(),
                resource_subscriptions: session.resource_subscriptions.clone(),
                actor: session.identity.actor.clone(),
                tenant: session.identity.tenant.clone(),
            })
    }

    /// Restores a previously persisted server session after process restart.
    pub async fn restore_session(&self, snapshot: McpServerSessionSnapshot) -> McpServerResult<()> {
        snapshot
            .actor
            .validate(&BTreeSet::new())
            .map_err(|error| McpServerError::Provider(error.to_string()))?;
        if snapshot.state.role != aip_mcp_session::McpRole::Server {
            return Err(McpServerError::Provider(
                "cannot restore a client-role snapshot into an MCP server".to_owned(),
            ));
        }
        if matches!(
            snapshot.state.lifecycle,
            aip_mcp_session::McpLifecycle::New
                | aip_mcp_session::McpLifecycle::Closing
                | aip_mcp_session::McpLifecycle::Closed
        ) {
            return Err(McpServerError::Provider(
                "only negotiated active MCP sessions can be restored".to_owned(),
            ));
        }
        let session_id = snapshot.state.session_id.clone();
        let _subscription_guard = self.subscription_lock.lock().await;
        let mut activated: Vec<String> = Vec::new();
        for uri in &snapshot.resource_subscriptions {
            let already_active = self
                .sessions
                .read()
                .await
                .values()
                .any(|session| session.resource_subscriptions.contains(uri));
            if !already_active {
                if let Err(error) = self.config.resources.subscribe(uri).await {
                    for activated_uri in activated.iter().rev() {
                        let _ = self.config.resources.unsubscribe(activated_uri).await;
                    }
                    return Err(error);
                }
                activated.push(uri.clone());
            }
        }
        self.sessions.write().await.insert(
            session_id.clone(),
            McpSession {
                id: session_id,
                state: snapshot.state,
                client_capabilities: snapshot.client_capabilities,
                client_info: snapshot.client_info,
                action_by_request_id: snapshot.action_by_request_id,
                tasks: snapshot.tasks,
                logging_level: snapshot.logging_level,
                resource_subscriptions: snapshot.resource_subscriptions,
                identity: McpRequestIdentity {
                    actor: snapshot.actor,
                    tenant: snapshot.tenant,
                },
            },
        );
        Ok(())
    }

    /// Returns whether one active session owns a subscription for a resource URI.
    pub async fn session_has_resource_subscription(&self, session_id: &str, uri: &str) -> bool {
        self.sessions
            .read()
            .await
            .get(session_id)
            .is_some_and(|session| session.resource_subscriptions.contains(uri))
    }

    /// Sends one negotiated server-to-client request over the bound transport.
    pub async fn request_client(
        &self,
        session_id: &str,
        method: McpMethod,
        params: Option<Value>,
        timeout: Duration,
    ) -> McpServerResult<Value> {
        if !matches!(
            method,
            McpMethod::RootsList | McpMethod::SamplingCreateMessage | McpMethod::ElicitationCreate
        ) {
            return Err(McpServerError::Provider(format!(
                "`{method}` is not a server-to-client request"
            )));
        }
        let session = self
            .sessions
            .read()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| {
                McpServerError::Provider(format!("MCP session `{session_id}` was not found"))
            })?;
        session.state.authorize_outbound_request(method)?;
        let request =
            JsonRpcRequest::new(json!(format!("server:{}", ActionId::new())), method, params);
        let response = self
            .config
            .peer_transport
            .request(session_id, request.clone(), timeout)
            .await?;
        if response.id != request.id {
            return Err(McpServerError::Provider(format!(
                "MCP peer returned response id {} for request id {}",
                response.id, request.id
            )));
        }
        if let Some(error) = response.error {
            return Err(McpServerError::Provider(format!(
                "MCP peer error {}: {}",
                error.code, error.message
            )));
        }
        response.result.ok_or_else(|| {
            McpServerError::Provider(
                "MCP peer response contained neither result nor error".to_owned(),
            )
        })
    }

    /// Sends one negotiated server notification to a client session.
    pub async fn notify_client(
        &self,
        session_id: &str,
        notification: JsonRpcNotification,
    ) -> McpServerResult<()> {
        let method = notification.method.parse::<McpMethod>()?;
        let session = self
            .sessions
            .read()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| {
                McpServerError::Provider(format!("MCP session `{session_id}` was not found"))
            })?;
        session.state.authorize_outbound_notification(method)?;
        self.config
            .peer_transport
            .notify(session_id, notification)
            .await
    }

    /// Requests roots from a negotiated MCP client.
    pub async fn request_client_roots(
        &self,
        session_id: &str,
        timeout: Duration,
    ) -> McpServerResult<Vec<Root>> {
        let result = self
            .request_client(session_id, McpMethod::RootsList, Some(json!({})), timeout)
            .await?;
        serde_json::from_value(result.get("roots").cloned().unwrap_or_else(|| json!([])))
            .map_err(|error| McpServerError::Provider(error.to_string()))
    }

    /// Requests model sampling from a negotiated MCP client.
    pub async fn request_client_sampling(
        &self,
        session_id: &str,
        params: Value,
        timeout: Duration,
    ) -> McpServerResult<Value> {
        self.request_client(
            session_id,
            McpMethod::SamplingCreateMessage,
            Some(params),
            timeout,
        )
        .await
    }

    /// Requests user elicitation from a negotiated MCP client.
    pub async fn request_client_elicitation(
        &self,
        session_id: &str,
        params: Value,
        timeout: Duration,
    ) -> McpServerResult<Value> {
        self.request_client(
            session_id,
            McpMethod::ElicitationCreate,
            Some(params),
            timeout,
        )
        .await
    }

    /// Returns a server discovery payload for draft-aware clients.
    pub fn discover_result(&self) -> Value {
        let version = self
            .config
            .supported_versions
            .last()
            .map(String::as_str)
            .unwrap_or(aip_profile_mcp::LATEST_STABLE_PROTOCOL_VERSION);
        json!({
            "resultType": "complete",
            "supportedVersions": self.config.supported_versions,
            "capabilities": self.server_capabilities_for(version),
            "serverInfo": self.config.server_info,
            "ttlMs": 3_600_000,
            "cacheScope": "public"
        })
    }

    fn server_capabilities_for(&self, version: &str) -> ServerCapabilities {
        let methods = methods_for_version(version).unwrap_or_default();
        let has_method = |method| methods.contains(&method);
        let has_tools = self.config.expose_stable_facade_tools
            || (self.config.expose_generated_capability_tools
                && !tools_from_manifest(&self.config.manifest).is_empty());
        ServerCapabilities {
            tools: (has_tools && has_method(McpMethod::ToolsList)).then_some(
                ListChangedCapability {
                    list_changed: self.config.dynamic_notifications_enabled,
                },
            ),
            resources: self
                .config
                .resources
                .advertised_capability()
                .and_then(|mut capability| {
                    has_method(McpMethod::ResourcesList).then(|| {
                        capability.list_changed = self.config.dynamic_notifications_enabled;
                        capability
                    })
                }),
            prompts: (self.config.prompts.is_available() && has_method(McpMethod::PromptsList))
                .then_some(ListChangedCapability {
                    list_changed: self.config.dynamic_notifications_enabled,
                }),
            logging: (self.config.logging_enabled && has_method(McpMethod::LoggingSetLevel))
                .then(|| json!({})),
            completions: (self.config.completions.is_available()
                && has_method(McpMethod::CompletionComplete))
            .then(|| json!({})),
            tasks: (self.config.tasks_enabled && has_method(McpMethod::TasksList)).then(|| {
                json!({
                    "list": {},
                    "cancel": {},
                    "requests": { "tools": { "call": {} } }
                })
            }),
            experimental: None,
        }
    }

    async fn handle_request_inner(
        &self,
        session_id: &str,
        transport: McpTransportKind,
        request: JsonRpcRequest,
    ) -> McpServerResult<Value> {
        request.validate()?;
        let method = request.method.parse::<McpMethod>()?;
        let session = self.session(session_id, transport).await;
        session.state.authorize_request(method)?;
        match method {
            McpMethod::Initialize => Box::pin(self.initialize(session, request)).await,
            McpMethod::ServerDiscover => Ok(self.discover_result()),
            McpMethod::Ping => Ok(json!({})),
            McpMethod::ToolsList => Box::pin(self.tools_list(request)).await,
            McpMethod::ToolsCall => Box::pin(self.tools_call(session, request)).await,
            McpMethod::ResourcesList => Box::pin(self.resources_list(request)).await,
            McpMethod::ResourcesRead => Box::pin(self.resources_read(request)).await,
            McpMethod::ResourcesTemplatesList => Box::pin(self.resource_templates()).await,
            McpMethod::ResourcesSubscribe => {
                Box::pin(self.resources_subscribe(session, request)).await
            }
            McpMethod::ResourcesUnsubscribe => {
                Box::pin(self.resources_unsubscribe(session, request)).await
            }
            McpMethod::PromptsList => Box::pin(self.prompts_list(request)).await,
            McpMethod::PromptsGet => Box::pin(self.prompts_get(request)).await,
            McpMethod::CompletionComplete => Box::pin(self.completion_complete(request)).await,
            McpMethod::LoggingSetLevel => Box::pin(self.set_logging_level(session, request)).await,
            McpMethod::RootsList => Box::pin(self.roots_list()).await,
            McpMethod::SamplingCreateMessage => Box::pin(self.sample(request)).await,
            McpMethod::ElicitationCreate => Box::pin(self.elicit(request)).await,
            McpMethod::TasksList => Box::pin(self.tasks_list(&session)).await,
            McpMethod::TasksGet => Box::pin(self.tasks_get(&session, request)).await,
            McpMethod::TasksResult => Box::pin(self.tasks_result(&session, request)).await,
            McpMethod::TasksCancel => Box::pin(self.tasks_cancel(session, request)).await,
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
            | McpMethod::TasksStatus
            | McpMethod::SubscriptionsListen
            | McpMethod::SubscriptionsAcknowledged => {
                Err(McpProfileError::UnsupportedMethod(method.to_string()).into())
            }
        }
    }

    async fn initialize(
        &self,
        mut session: McpSession,
        request: JsonRpcRequest,
    ) -> McpServerResult<Value> {
        let params = request
            .params
            .clone()
            .map(serde_json::from_value::<InitializeParams>)
            .transpose()
            .map_err(|error| McpProfileError::Mapping(error.to_string()))?;
        if let Some(params) = params {
            let requested_version = params.protocol_version.clone();
            let selected = session.state.begin_initialize_with_supported(
                &requested_version,
                &VersionTransportMatrix::default(),
                &self.config.supported_versions,
            )?;
            let server_capabilities = self.server_capabilities_for(&selected);
            session
                .state
                .set_capabilities(&params.capabilities, &server_capabilities);
            session.client_capabilities = params.capabilities;
            session.client_info = Some(params.client_info);
            self.replace_session(session).await;
            Ok(initialize_result_with_capabilities(
                &self.config.manifest,
                Some(&selected),
                server_capabilities,
            ))
        } else {
            Err(McpProfileError::MissingParams.into())
        }
    }

    async fn tools_call(
        &self,
        session: McpSession,
        request: JsonRpcRequest,
    ) -> McpServerResult<Value> {
        if self.config.expose_stable_facade_tools
            && let Some(result) = self.try_stable_facade_tool(&session, &request).await?
        {
            return Ok(result);
        }
        let action = action_from_tools_call_with_manifest(&request, &self.config.manifest)?;
        let action_id = action.id.clone();
        let capability = self
            .config
            .manifest
            .capabilities
            .iter()
            .find(|capability| capability.id == action.capability_id)
            .cloned();
        let request_id = request_id_to_key(&request.id);
        self.insert_action_correlation(&session.id, request_id.clone(), action_id.clone())
            .await?;
        let task_requested = request
            .params
            .as_ref()
            .and_then(|params| params.get("task"))
            .is_some();
        let mut envelope = Envelope::new(MessageBody::Action(Box::new(action)));
        envelope.from = Some(self.current_request_identity().actor.principal);
        let response = self.dispatch_envelope(envelope).await;
        self.remove_action_correlation(&session.id, &request_id)
            .await;
        let response = response?;
        match response.body {
            MessageBody::ActionResult(result) => {
                // A capability output schema describes a successful business result.
                // Failed, cancelled, and input-required lifecycle results may omit
                // `structuredContent` or carry an AIP error/approval projection instead.
                // Validating those projections against the success schema would turn a
                // legitimate protocol outcome into an unrelated JSON-RPC -32602 error.
                if result.status == aip_core::ActionResultStatus::Completed
                    && self.config.enforce_output_schema
                    && let Some(capability) = capability.as_ref()
                {
                    validate_output_schema(capability, &result)?;
                }
                let mapped = call_tool_result(&result);
                if task_requested {
                    let task_id = action_id.to_string();
                    self.store_task(
                        &session.id,
                        task_id.clone(),
                        StoredTask {
                            task: aip_profile_mcp::task_from_action_result(task_id, &result),
                            result: Some(mapped.clone()),
                        },
                    )
                    .await?;
                }
                Ok(mapped)
            }
            MessageBody::Ack(ack) => {
                let task_id = action_id.to_string();
                let task = Task {
                    task_id: task_id.clone(),
                    status: TaskStatus::Working,
                    status_message: ack.reason,
                    created_at: Some(OffsetDateTime::now_utc().to_string()),
                    last_updated_at: Some(OffsetDateTime::now_utc().to_string()),
                    ttl: request
                        .params
                        .as_ref()
                        .and_then(|params| params.pointer("/task/ttl"))
                        .and_then(Value::as_u64),
                    poll_interval: Some(1_000),
                    meta: Some(json!({
                        "org.getaip/aip": {
                            "action_id": action_id,
                            "ack_status": ack.status
                        }
                    })),
                };
                self.store_task(
                    &session.id,
                    task_id,
                    StoredTask {
                        task: task.clone(),
                        result: None,
                    },
                )
                .await?;
                Ok(json!({ "task": task }))
            }
            MessageBody::Error(error) => Err(McpServerError::Provider(error.error.message)),
            other => Err(McpServerError::Provider(format!(
                "unexpected AIP response `{}`",
                other.message_type().as_str()
            ))),
        }
    }

    async fn tools_list(&self, request: JsonRpcRequest) -> McpServerResult<Value> {
        let cursor = request
            .params
            .as_ref()
            .and_then(|params| params.get("cursor"))
            .and_then(Value::as_str);
        let limit = request
            .params
            .as_ref()
            .and_then(|params| params.get("limit"))
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok());
        let mut tools = Vec::new();
        if self.config.expose_stable_facade_tools {
            tools.extend(stable_facade_tools());
        }
        if self.config.expose_generated_capability_tools {
            tools.extend(tools_from_manifest(&self.config.manifest));
        }
        Ok(tools_list_result_from_tools(tools, cursor, limit))
    }

    async fn try_stable_facade_tool(
        &self,
        session: &McpSession,
        request: &JsonRpcRequest,
    ) -> McpServerResult<Option<Value>> {
        let Some(name) = request
            .params
            .as_ref()
            .and_then(|params| params.get("name"))
            .and_then(Value::as_str)
        else {
            return Ok(None);
        };
        match stable_facade_tool(name) {
            Some(StableFacadeTool::Capabilities) => {
                Ok(Some(self.facade_capabilities(session, request).await?))
            }
            Some(StableFacadeTool::Call) => Ok(Some(self.facade_call(session, request).await?)),
            Some(StableFacadeTool::Events) => Ok(Some(self.facade_events(request).await?)),
            Some(StableFacadeTool::ActionStatus) => {
                Ok(Some(self.facade_action_status(request).await?))
            }
            Some(StableFacadeTool::ActionResult) => {
                Ok(Some(self.facade_action_result(request).await?))
            }
            Some(StableFacadeTool::ActionList) => Ok(Some(self.facade_action_list(request).await?)),
            Some(StableFacadeTool::ActionEvents) => {
                Ok(Some(self.facade_action_events(request).await?))
            }
            Some(StableFacadeTool::ActionCancel) => {
                Ok(Some(self.facade_action_cancel(request).await?))
            }
            Some(StableFacadeTool::SessionGet) => Ok(Some(self.facade_session_get(request).await?)),
            Some(StableFacadeTool::SessionList) => {
                Ok(Some(self.facade_session_list(request).await?))
            }
            Some(StableFacadeTool::SessionClose) => {
                Ok(Some(self.facade_session_close(request).await?))
            }
            Some(StableFacadeTool::SessionResume) => {
                Ok(Some(self.facade_session_resume(request).await?))
            }
            Some(StableFacadeTool::ApprovalGet) => {
                Ok(Some(self.facade_approval_get(request).await?))
            }
            Some(StableFacadeTool::ApprovalList) => {
                Ok(Some(self.facade_approval_list(request).await?))
            }
            Some(StableFacadeTool::ApprovalDecide) => {
                Ok(Some(self.facade_approval_decide(request).await?))
            }
            Some(StableFacadeTool::CallbackDeliveryGet) => {
                Ok(Some(self.facade_callback_delivery_get(request).await?))
            }
            Some(StableFacadeTool::CallbackDeliveryList) => {
                Ok(Some(self.facade_callback_delivery_list(request).await?))
            }
            Some(StableFacadeTool::TransactionGet) => {
                Ok(Some(self.facade_transaction_get(request).await?))
            }
            Some(StableFacadeTool::ReceiptGet) => Ok(Some(self.facade_receipt_get(request).await?)),
            Some(StableFacadeTool::AuditEvents) => {
                Ok(Some(self.facade_audit_events(request).await?))
            }
            Some(StableFacadeTool::ResourceList) => {
                Ok(Some(self.facade_resource_list(request).await?))
            }
            Some(StableFacadeTool::ResourceRead) => {
                Ok(Some(self.facade_resource_read(request).await?))
            }
            Some(StableFacadeTool::ScenarioRun) => {
                Ok(Some(self.facade_scenario_run(request).await?))
            }
            Some(StableFacadeTool::Delegate) => Ok(Some(self.facade_delegate(request).await?)),
            None => Ok(None),
        }
    }

    async fn facade_capabilities(
        &self,
        session: &McpSession,
        request: &JsonRpcRequest,
    ) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let capability_id = optional_string(&arguments, "capability_id");
        let profile = optional_string(&arguments, "profile");
        let query = optional_string(&arguments, "query").map(str::to_ascii_lowercase);
        let include_schemas = optional_bool(&arguments, "include_schemas").unwrap_or(true);
        let include_contracts = optional_bool(&arguments, "include_contracts").unwrap_or(true);
        let include_bindings = optional_bool(&arguments, "include_bindings").unwrap_or(true);
        let limit = optional_usize(&arguments, "limit")?.unwrap_or(100);
        if !(1..=1_000).contains(&limit) {
            return Err(McpServerError::Provider(
                "aip_capabilities limit must be between 1 and 1000".to_owned(),
            ));
        }
        let cursor = optional_string(&arguments, "cursor");
        let mut local_capabilities = Vec::new();
        for capability in &self.config.manifest.capabilities {
            if let Some(capability_id) = capability_id
                && capability.id.as_str() != capability_id
            {
                continue;
            }
            if let Some(profile) = profile
                && !capability
                    .bindings
                    .iter()
                    .any(|binding| binding.profile.as_str() == profile)
            {
                continue;
            }
            if let Some(query) = query.as_ref() {
                let searchable = format!(
                    "{} {} {}",
                    capability.id.as_str(),
                    capability.name,
                    capability.description.as_deref().unwrap_or_default()
                )
                .to_ascii_lowercase();
                if !searchable.contains(query) {
                    continue;
                }
            }
            local_capabilities.push(capability_facade_value(
                capability,
                include_schemas,
                include_contracts,
                include_bindings,
            )?);
        }

        let Some(catalog) = self.config.capability_catalog.as_ref() else {
            let cursor = cursor.map(parse_cursor).transpose()?.unwrap_or(0);
            let total = local_capabilities.len();
            let start = cursor.min(total);
            let end = start.saturating_add(limit).min(total);
            let next_cursor = (end < total).then(|| end.to_string());
            return Ok(mcp_tool_result(
                json!({
                    "manifest_version": self.config.manifest.manifest_version,
                    "agent": self.config.manifest.agent,
                    "profiles": self.config.manifest.profiles,
                    "total": total,
                    "capabilities": local_capabilities[start..end].to_vec(),
                    "next_cursor": next_cursor
                }),
                false,
            ));
        };

        let capability_id = capability_id
            .map(CapabilityId::parse)
            .transpose()
            .map_err(|error| McpServerError::Provider(error.to_string()))?;
        let profile = profile
            .map(ProfileId::parse)
            .transpose()
            .map_err(|error| McpServerError::Provider(error.to_string()))?;
        let catalog_context = session
            .identity
            .tenant
            .as_ref()
            .map(|tenant| CatalogReadContext::for_tenant(tenant.tenant.id.clone()))
            .unwrap_or_default();
        let (local_offset, remote_cursor) = parse_fleet_capability_cursor(cursor)?;
        let mut capabilities = Vec::new();
        let local_total = local_capabilities.len();
        let (catalog_page, next_cursor) = if let Some(remote_cursor) = remote_cursor {
            let page = catalog
                .query(
                    CapabilityCatalogQuery {
                        capability_id,
                        text: query.clone(),
                        profile,
                        cursor: remote_cursor,
                        limit,
                    },
                    &catalog_context,
                )
                .await
                .map_err(catalog_mcp_error)?;
            for definition in &page.capabilities {
                capabilities.push(capability_facade_value(
                    &definition.capability,
                    include_schemas,
                    include_contracts,
                    include_bindings,
                )?);
            }
            let next = page
                .next_cursor
                .as_ref()
                .map(|cursor| format!("remote:{cursor}"));
            (page, next)
        } else {
            let start = local_offset.min(local_total);
            let end = start.saturating_add(limit).min(local_total);
            capabilities.extend_from_slice(&local_capabilities[start..end]);
            let remaining = limit.saturating_sub(capabilities.len());
            let page = catalog
                .query(
                    CapabilityCatalogQuery {
                        capability_id,
                        text: query,
                        profile,
                        cursor: None,
                        limit: remaining.max(1),
                    },
                    &catalog_context,
                )
                .await
                .map_err(catalog_mcp_error)?;
            if end == local_total && remaining > 0 {
                for definition in page.capabilities.iter().take(remaining) {
                    capabilities.push(capability_facade_value(
                        &definition.capability,
                        include_schemas,
                        include_contracts,
                        include_bindings,
                    )?);
                }
            }
            let next = if end < local_total {
                Some(format!("local:{end}"))
            } else if remaining == 0 && page.total > 0 {
                Some("remote:".to_owned())
            } else {
                page.next_cursor
                    .as_ref()
                    .map(|cursor| format!("remote:{cursor}"))
            };
            (page, next)
        };
        let total = (local_total as u64).saturating_add(catalog_page.total);
        Ok(mcp_tool_result(
            json!({
                "manifest_version": self.config.manifest.manifest_version,
                "agent": self.config.manifest.agent,
                "profiles": self.config.manifest.profiles,
                "catalog_revision": catalog_page.catalog_revision,
                "total": total,
                "capabilities": capabilities,
                "next_cursor": next_cursor
            }),
            false,
        ))
    }

    async fn facade_call(
        &self,
        session: &McpSession,
        request: &JsonRpcRequest,
    ) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let action = action_from_facade_arguments(&arguments, request.params.as_ref())?;
        let action_id = action.id.clone();
        let request_id = request_id_to_key(&request.id);
        self.insert_action_correlation(&session.id, request_id.clone(), action_id.clone())
            .await?;
        let body = self
            .dispatch_body(MessageBody::Action(Box::new(action)))
            .await;
        self.remove_action_correlation(&session.id, &request_id)
            .await;
        let body = body?;
        mcp_result_from_action_body(action_id, body)
    }

    async fn facade_events(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let kinds = string_array(&arguments, "kinds")?;
        let cursor = optional_string(&arguments, "cursor").map(ToOwned::to_owned);
        let limit = optional_u32(&arguments, "limit")?;
        let body = self
            .dispatch_body(MessageBody::EventStreamRequest(EventStreamRequest {
                cursor,
                limit,
                kinds,
            }))
            .await?;
        match body {
            MessageBody::EventStream(stream) => Ok(mcp_tool_result(
                serde_json::to_value(stream)
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                false,
            )),
            MessageBody::Error(error) => Err(McpServerError::Provider(error.error.message)),
            other => Err(McpServerError::Provider(format!(
                "unexpected AIP response `{}`",
                other.message_type().as_str()
            ))),
        }
    }

    async fn facade_action_status(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let action_id = action_id_from_arguments(&arguments)?;
        let body = self
            .dispatch_body(MessageBody::ActionStatusRequest(ActionStatusRequest {
                action_id,
                tenant_id: optional_string(&arguments, "tenant_id").map(ToOwned::to_owned),
                include_result: optional_bool(&arguments, "include_result").unwrap_or(false),
                include_receipts: optional_bool(&arguments, "include_receipts").unwrap_or(false),
                include_chunks: optional_bool(&arguments, "include_chunks").unwrap_or(false),
                wait_ms: optional_u64(&arguments, "wait_ms")?,
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_action_result(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let action_id = action_id_from_arguments(&arguments)?;
        let body = self
            .dispatch_body(MessageBody::ActionResultRequest(ActionResultRequest {
                action_id,
                tenant_id: optional_string(&arguments, "tenant_id").map(ToOwned::to_owned),
                wait_ms: optional_u64(&arguments, "wait_ms")?,
                include_receipt: optional_bool(&arguments, "include_receipt").unwrap_or(false),
                include_terminal_events: optional_bool(&arguments, "include_terminal_events")
                    .unwrap_or(false),
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_action_list(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let body = self
            .dispatch_body(MessageBody::ActionListRequest(ActionListRequest {
                state: deserialize_field(&arguments, "state")?,
                capability_id: optional_string(&arguments, "capability_id")
                    .map(CapabilityId::parse)
                    .transpose()
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                session_id: optional_string(&arguments, "session_id")
                    .map(aip_core::SessionId::parse)
                    .transpose()
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                principal_id: optional_string(&arguments, "principal_id")
                    .map(PrincipalId::parse)
                    .transpose()
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                tenant_id: optional_string(&arguments, "tenant_id").map(ToOwned::to_owned),
                approval_id: optional_string(&arguments, "approval_id")
                    .map(ApprovalId::parse)
                    .transpose()
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                transaction_id: optional_string(&arguments, "transaction_id")
                    .map(aip_core::TransactionId::parse)
                    .transpose()
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                cursor: optional_string(&arguments, "cursor").map(ToOwned::to_owned),
                limit: optional_u32(&arguments, "limit")?,
                include_results: optional_bool(&arguments, "include_results").unwrap_or(false),
                include_receipts: optional_bool(&arguments, "include_receipts").unwrap_or(false),
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_action_events(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let action_id = action_id_from_arguments(&arguments)?;
        let mut kinds = string_array(&arguments, "kinds")?;
        if let Some(kind) = optional_string(&arguments, "kind") {
            kinds.push(kind.to_owned());
        }
        kinds.sort();
        kinds.dedup();
        let body = self
            .dispatch_body(MessageBody::ActionEventsRequest(ActionEventsRequest {
                action_id,
                tenant_id: optional_string(&arguments, "tenant_id").map(ToOwned::to_owned),
                cursor: optional_string(&arguments, "cursor").map(ToOwned::to_owned),
                limit: optional_u32(&arguments, "limit")?,
                kinds,
                include_chunks: optional_bool(&arguments, "include_chunks").unwrap_or(false),
                follow: optional_bool(&arguments, "follow").unwrap_or(false),
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_action_cancel(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let action_id = action_id_from_arguments(&arguments)?;
        let body = self
            .dispatch_body(MessageBody::Cancel(Cancel {
                target: CancelTarget::Action(action_id),
                reason: optional_string(&arguments, "reason").map(ToOwned::to_owned),
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_session_get(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let session_id = aip_core::SessionId::parse(required_string(&arguments, "session_id")?)
            .map_err(|error| McpServerError::Provider(error.to_string()))?;
        let body = self
            .dispatch_body(MessageBody::SessionRequest(SessionRequest { session_id }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_session_list(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let body = self
            .dispatch_body(MessageBody::SessionListRequest(SessionListRequest {
                principal_id: optional_string(&arguments, "principal_id")
                    .map(PrincipalId::parse)
                    .transpose()
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                status: deserialize_field(&arguments, "status")?,
                cursor: optional_string(&arguments, "cursor").map(ToOwned::to_owned),
                limit: optional_u32(&arguments, "limit")?,
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_session_close(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let session_id = aip_core::SessionId::parse(required_string(&arguments, "session_id")?)
            .map_err(|error| McpServerError::Provider(error.to_string()))?;
        let body = self
            .dispatch_body(MessageBody::SessionCloseRequest(SessionCloseRequest {
                session_id,
                reason: optional_string(&arguments, "reason").map(ToOwned::to_owned),
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_session_resume(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let session_id = aip_core::SessionId::parse(required_string(&arguments, "session_id")?)
            .map_err(|error| McpServerError::Provider(error.to_string()))?;
        let body = self
            .dispatch_body(MessageBody::SessionResumeRequest(SessionResumeRequest {
                session_id,
                resume_token: optional_string(&arguments, "resume_token").map(ToOwned::to_owned),
                last_event_cursor: optional_string(&arguments, "last_event_cursor")
                    .map(ToOwned::to_owned),
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_approval_get(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let approval_id = ApprovalId::parse(required_string(&arguments, "approval_id")?)
            .map_err(|error| McpServerError::Provider(error.to_string()))?;
        let body = self
            .dispatch_body(MessageBody::ApprovalQueryRequest(ApprovalQueryRequest {
                approval_id,
                tenant_id: optional_string(&arguments, "tenant_id").map(ToOwned::to_owned),
                include_action_status: optional_bool(&arguments, "include_action_status")
                    .unwrap_or(false),
                include_receipts: optional_bool(&arguments, "include_receipts").unwrap_or(false),
                include_evidence_payload: optional_bool(&arguments, "include_evidence_payload")
                    .unwrap_or(false),
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_approval_list(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let body = self
            .dispatch_body(MessageBody::ApprovalListRequest(ApprovalListRequest {
                status: optional_string(&arguments, "status").map(ToOwned::to_owned),
                approver: optional_string(&arguments, "approver")
                    .map(PrincipalId::parse)
                    .transpose()
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                requester: optional_string(&arguments, "requester")
                    .map(PrincipalId::parse)
                    .transpose()
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                tenant_id: optional_string(&arguments, "tenant_id").map(ToOwned::to_owned),
                cursor: optional_string(&arguments, "cursor").map(ToOwned::to_owned),
                limit: optional_u32(&arguments, "limit")?,
                include_action_status: optional_bool(&arguments, "include_action_status")
                    .unwrap_or(false),
                include_receipts: optional_bool(&arguments, "include_receipts").unwrap_or(false),
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_callback_delivery_get(
        &self,
        request: &JsonRpcRequest,
    ) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let body = self
            .dispatch_body(MessageBody::CallbackDeliveryQueryRequest(
                CallbackDeliveryQueryRequest {
                    delivery_id: required_string(&arguments, "delivery_id")?.to_owned(),
                    tenant_id: optional_string(&arguments, "tenant_id").map(ToOwned::to_owned),
                    include_receipts: optional_bool(&arguments, "include_receipts")
                        .unwrap_or(false),
                },
            ))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_callback_delivery_list(
        &self,
        request: &JsonRpcRequest,
    ) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let body = self
            .dispatch_body(MessageBody::CallbackDeliveryListRequest(
                CallbackDeliveryListRequest {
                    action_id: optional_string(&arguments, "action_id")
                        .map(ActionId::parse)
                        .transpose()
                        .map_err(|error| McpServerError::Provider(error.to_string()))?,
                    status: optional_string(&arguments, "status")
                        .map(callback_delivery_status)
                        .transpose()?,
                    profile: optional_string(&arguments, "profile")
                        .map(ProfileId::parse)
                        .transpose()
                        .map_err(|error| McpServerError::Provider(error.to_string()))?,
                    target: optional_string(&arguments, "target").map(ToOwned::to_owned),
                    tenant_id: optional_string(&arguments, "tenant_id").map(ToOwned::to_owned),
                    cursor: optional_string(&arguments, "cursor").map(ToOwned::to_owned),
                    limit: optional_u32(&arguments, "limit")?,
                    include_receipts: optional_bool(&arguments, "include_receipts")
                        .unwrap_or(false),
                },
            ))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_transaction_get(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let transaction_id = optional_string(&arguments, "transaction_id")
            .map(TransactionId::parse)
            .transpose()
            .map_err(|error| McpServerError::Provider(error.to_string()))?;
        let action_id = optional_string(&arguments, "action_id")
            .map(ActionId::parse)
            .transpose()
            .map_err(|error| McpServerError::Provider(error.to_string()))?;
        let body = self
            .dispatch_body(MessageBody::TransactionQueryRequest(
                TransactionQueryRequest {
                    transaction_id,
                    plan_id: optional_string(&arguments, "plan_id").map(ToOwned::to_owned),
                    action_id,
                    tenant_id: optional_string(&arguments, "tenant_id").map(ToOwned::to_owned),
                    include_result: optional_bool(&arguments, "include_result").unwrap_or(false),
                    include_receipts: optional_bool(&arguments, "include_receipts")
                        .unwrap_or(false),
                },
            ))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_receipt_get(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let receipt_id = optional_string(&arguments, "receipt_id")
            .map(ReceiptId::parse)
            .transpose()
            .map_err(|error| McpServerError::Provider(error.to_string()))?;
        let body = self
            .dispatch_body(MessageBody::ReceiptQueryRequest(ReceiptQueryRequest {
                chain_id: optional_string(&arguments, "chain_id").map(ToOwned::to_owned),
                receipt_id,
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_audit_events(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let body = self
            .dispatch_body(MessageBody::AuditQueryRequest(AuditQueryRequest {
                action_id: optional_string(&arguments, "action_id")
                    .map(ActionId::parse)
                    .transpose()
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                session_id: optional_string(&arguments, "session_id")
                    .map(aip_core::SessionId::parse)
                    .transpose()
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                principal_id: optional_string(&arguments, "principal_id")
                    .map(PrincipalId::parse)
                    .transpose()
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                tenant_id: optional_string(&arguments, "tenant_id").map(ToOwned::to_owned),
                transaction_id: optional_string(&arguments, "transaction_id")
                    .map(TransactionId::parse)
                    .transpose()
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                from: deserialize_field(&arguments, "from")?,
                to: deserialize_field(&arguments, "to")?,
                cursor: optional_string(&arguments, "cursor").map(ToOwned::to_owned),
                limit: optional_u32(&arguments, "limit")?,
                include_receipts: optional_bool(&arguments, "include_receipts").unwrap_or(false),
                export: optional_bool(&arguments, "export").unwrap_or(false),
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_resource_list(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let body = self
            .dispatch_body(MessageBody::ResourceListRequest(ResourceListRequest {
                capability_id: optional_string(&arguments, "capability_id")
                    .map(CapabilityId::parse)
                    .transpose()
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                kind: optional_string(&arguments, "kind").map(ToOwned::to_owned),
                tenant_id: optional_string(&arguments, "tenant_id").map(ToOwned::to_owned),
                cursor: optional_string(&arguments, "cursor").map(ToOwned::to_owned),
                limit: optional_u32(&arguments, "limit")?,
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_resource_read(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let body = self
            .dispatch_body(MessageBody::ResourceReadRequest(ResourceReadRequest {
                resource_id: required_string(&arguments, "resource_id")?.to_owned(),
                tenant_id: optional_string(&arguments, "tenant_id").map(ToOwned::to_owned),
                version: optional_string(&arguments, "version").map(ToOwned::to_owned),
                accept: string_or_array(&arguments, "accept")?,
            }))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn facade_approval_decide(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let identity = self.current_request_identity();
        require_mcp_scope(&identity.actor, "approval:decide")?;
        let approval_id = ApprovalId::parse(required_string(&arguments, "approval_id")?)
            .map_err(|error| McpServerError::Provider(error.to_string()))?;
        if let Some(claimed) = optional_string(&arguments, "approver_principal")
            && claimed != identity.actor.principal.id.as_str()
        {
            return Err(McpServerError::Provider(
                "approver_principal must match the principal authenticated by the MCP transport"
                    .to_owned(),
            ));
        }
        let approver = identity.actor.principal.clone();
        let evidence = evidence_from_arguments(&arguments)?;
        let decision = ApprovalDecision {
            approval_id,
            decision: decision_kind_from_arguments(&arguments)?,
            approver: approver.clone(),
            decided_at: OffsetDateTime::now_utc(),
            reason: optional_string(&arguments, "reason").map(ToOwned::to_owned),
            constraints: deserialize_field(&arguments, "constraints")?.unwrap_or_default(),
            evidence,
            decision_id: optional_string(&arguments, "decision_id")
                .map(ToOwned::to_owned)
                .or_else(|| {
                    Some(format!(
                        "mcp:{}:{}",
                        identity.actor.principal.id, request.id
                    ))
                }),
            policy_hash: optional_string(&arguments, "policy_hash").map(ToOwned::to_owned),
            authority_path: vec![format!("mcp_transport:{}", identity.actor.principal.id)],
            target_decision_id: optional_string(&arguments, "target_decision_id")
                .map(ToOwned::to_owned),
        };
        let mut envelope = Envelope::new(MessageBody::ApprovalDecision(Box::new(decision)));
        envelope.from = Some(approver);
        let body = self.dispatch_envelope(envelope).await?.body;
        match body {
            MessageBody::EventStream(stream) => Ok(mcp_tool_result(
                serde_json::to_value(stream)
                    .map_err(|error| McpServerError::Provider(error.to_string()))?,
                false,
            )),
            MessageBody::Error(error) => Err(McpServerError::Provider(error.error.message)),
            other => Err(McpServerError::Provider(format!(
                "unexpected AIP response `{}`",
                other.message_type().as_str()
            ))),
        }
    }

    async fn facade_scenario_run(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let scenario_id = required_string(&arguments, "scenario_id")?;
        let continue_on_error = optional_bool(&arguments, "continue_on_error").unwrap_or(false);
        let steps = arguments
            .get("steps")
            .and_then(Value::as_array)
            .ok_or_else(|| McpServerError::Provider("steps must be an array".to_owned()))?;
        let mut failed = false;
        let mut results = Vec::with_capacity(steps.len());
        for (index, step) in steps.iter().enumerate() {
            let name = optional_string(step, "name")
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| format!("step_{}", index + 1));
            let action = match action_from_facade_arguments(step, request.params.as_ref()) {
                Ok(action) => action,
                Err(error) => {
                    failed = true;
                    results.push(json!({
                        "name": name,
                        "index": index,
                        "status": "failed",
                        "error": error.to_string()
                    }));
                    if !continue_on_error {
                        break;
                    }
                    continue;
                }
            };
            let action_id = action.id.clone();
            let capability_id = action.capability_id.clone();
            match self
                .dispatch_body(MessageBody::Action(Box::new(action)))
                .await
            {
                Ok(body) => {
                    let (step_failed, result) =
                        scenario_step_result(name, index, action_id, capability_id, body)?;
                    failed |= step_failed;
                    results.push(result);
                    if step_failed && !continue_on_error {
                        break;
                    }
                }
                Err(error) => {
                    failed = true;
                    results.push(json!({
                        "name": name,
                        "index": index,
                        "action_id": action_id,
                        "capability_id": capability_id,
                        "status": "failed",
                        "error": error.to_string()
                    }));
                    if !continue_on_error {
                        break;
                    }
                }
            }
        }
        Ok(mcp_tool_result(
            json!({
                "scenario_id": scenario_id,
                "status": if failed { "failed" } else { "completed" },
                "step_count": steps.len(),
                "steps": results
            }),
            failed,
        ))
    }

    async fn facade_delegate(&self, request: &JsonRpcRequest) -> McpServerResult<Value> {
        let arguments = tool_arguments(request)?;
        let identity = self.current_request_identity();
        require_mcp_scope(&identity.actor, "delegation:create")?;
        let child_action = action_from_facade_arguments(&arguments, request.params.as_ref())?;
        let parent_action_id = optional_string(&arguments, "parent_action_id")
            .map(ActionId::parse)
            .transpose()
            .map_err(|error| McpServerError::Provider(error.to_string()))?
            .unwrap_or_else(ActionId::new);
        let delegate = Principal::new(
            PrincipalId::parse(required_string(&arguments, "delegate_id")?)
                .map_err(|error| McpServerError::Provider(error.to_string()))?,
            PrincipalKind::Agent,
        );
        let delegation_id = optional_string(&arguments, "delegation_id")
            .map(DelegationId::parse)
            .transpose()
            .map_err(|error| McpServerError::Provider(error.to_string()))?
            .unwrap_or_else(DelegationId::new);
        let callback = deserialize_field::<Callback>(&arguments, "callback")?;
        let delegation = DelegationRequest {
            delegation_id,
            parent_action_id,
            child_action,
            requested_by: identity.actor.principal,
            delegate,
            scope: required_string(&arguments, "scope")?.to_owned(),
            callback,
            metadata: arguments.get("metadata").cloned(),
        };
        let body = self
            .dispatch_body(MessageBody::DelegationRequest(Box::new(delegation)))
            .await?;
        mcp_result_from_read_body(body)
    }

    async fn dispatch_body(&self, body: MessageBody) -> McpServerResult<MessageBody> {
        let mut envelope = Envelope::new(body);
        envelope.from = Some(self.current_request_identity().actor.principal);
        Ok(self.dispatch_envelope(envelope).await?.body)
    }

    async fn dispatch_envelope(&self, mut envelope: Envelope) -> McpServerResult<Envelope> {
        let gateway = self.config.gateway.clone();
        let identity = self.current_request_identity();
        // The authenticated session identity is authoritative. Never forward a
        // caller-supplied or static facade principal across the gateway boundary.
        envelope.from = Some(identity.actor.principal.clone());
        tokio::spawn(async move {
            gateway
                .handle_verified_envelope(envelope, identity.actor, identity.tenant, None)
                .await
        })
        .await
        .map_err(|error| McpServerError::Provider(format!("gateway task failed: {error}")))?
        .map_err(McpServerError::Gateway)
    }

    fn current_request_identity(&self) -> McpRequestIdentity {
        MCP_REQUEST_IDENTITY
            .try_with(Clone::clone)
            .unwrap_or_else(|_| self.default_request_identity())
    }

    async fn resources_list(&self, request: JsonRpcRequest) -> McpServerResult<Value> {
        let cursor = request
            .params
            .as_ref()
            .and_then(|params| params.get("cursor"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let (resources, next_cursor) = self.config.resources.list(cursor).await?;
        let mut result = json!({ "resources": resources });
        if let Some(next_cursor) = next_cursor {
            result["nextCursor"] = Value::String(next_cursor);
        }
        Ok(result)
    }

    async fn resources_read(&self, request: JsonRpcRequest) -> McpServerResult<Value> {
        let uri = request
            .params
            .as_ref()
            .and_then(|params| params.get("uri"))
            .and_then(Value::as_str)
            .ok_or(McpProfileError::MissingResourceUri)?;
        Ok(resources_read_result(
            self.config.resources.read(uri).await?,
        ))
    }

    async fn resource_templates(&self) -> McpServerResult<Value> {
        Ok(resource_templates_list_result(
            self.config.resources.templates().await?,
        ))
    }

    async fn resources_subscribe(
        &self,
        session: McpSession,
        request: JsonRpcRequest,
    ) -> McpServerResult<Value> {
        let uri = request
            .params
            .as_ref()
            .and_then(|params| params.get("uri"))
            .and_then(Value::as_str)
            .ok_or(McpProfileError::MissingResourceUri)?;
        let _subscription_guard = self.subscription_lock.lock().await;
        if session.resource_subscriptions.contains(uri) {
            return Ok(json!({}));
        }
        let provider_already_active = self
            .sessions
            .read()
            .await
            .values()
            .any(|active| active.resource_subscriptions.contains(uri));
        if !provider_already_active {
            self.config.resources.subscribe(uri).await?;
        }
        let mut sessions = self.sessions.write().await;
        let active = sessions.get_mut(&session.id).ok_or_else(|| {
            McpServerError::Provider(format!(
                "MCP session `{}` closed while subscribing to resource `{uri}`",
                session.id
            ))
        })?;
        active.resource_subscriptions.insert(uri.to_owned());
        Ok(json!({}))
    }

    async fn resources_unsubscribe(
        &self,
        session: McpSession,
        request: JsonRpcRequest,
    ) -> McpServerResult<Value> {
        let uri = request
            .params
            .as_ref()
            .and_then(|params| params.get("uri"))
            .and_then(Value::as_str)
            .ok_or(McpProfileError::MissingResourceUri)?;
        let _subscription_guard = self.subscription_lock.lock().await;
        if !session.resource_subscriptions.contains(uri) {
            return Ok(json!({}));
        }
        let referenced_elsewhere =
            self.sessions.read().await.iter().any(|(id, active)| {
                id != &session.id && active.resource_subscriptions.contains(uri)
            });
        if !referenced_elsewhere {
            self.config.resources.unsubscribe(uri).await?;
        }
        let mut sessions = self.sessions.write().await;
        let active = sessions.get_mut(&session.id).ok_or_else(|| {
            McpServerError::Provider(format!(
                "MCP session `{}` closed while unsubscribing from resource `{uri}`",
                session.id
            ))
        })?;
        active.resource_subscriptions.remove(uri);
        Ok(json!({}))
    }

    async fn prompts_list(&self, request: JsonRpcRequest) -> McpServerResult<Value> {
        let cursor = request
            .params
            .as_ref()
            .and_then(|params| params.get("cursor"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let (prompts, next_cursor) = self.config.prompts.list(cursor).await?;
        Ok(prompts_list_result(prompts, next_cursor))
    }

    async fn prompts_get(&self, request: JsonRpcRequest) -> McpServerResult<Value> {
        let params = request
            .params
            .as_ref()
            .ok_or(McpProfileError::MissingParams)?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or(McpProfileError::MissingPromptName)?;
        let arguments = params
            .get("arguments")
            .and_then(Value::as_object)
            .map(|object| {
                object
                    .iter()
                    .map(|(key, value)| {
                        (
                            key.clone(),
                            value
                                .as_str()
                                .map(ToOwned::to_owned)
                                .unwrap_or_else(|| value.to_string()),
                        )
                    })
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let (description, messages, meta) = self.config.prompts.get(name, arguments).await?;
        Ok(aip_profile_mcp::prompt_get_result(
            description,
            messages,
            meta,
        ))
    }

    async fn completion_complete(&self, request: JsonRpcRequest) -> McpServerResult<Value> {
        let params = request
            .params
            .as_ref()
            .ok_or(McpProfileError::MissingParams)?;
        let reference = params.get("ref").cloned().unwrap_or_else(|| json!({}));
        let argument = params.get("argument").cloned().unwrap_or_else(|| json!({}));
        let (values, total, has_more) = self
            .config
            .completions
            .complete(reference, argument)
            .await?;
        Ok(completion_result(values, total, has_more))
    }

    async fn set_logging_level(
        &self,
        session: McpSession,
        request: JsonRpcRequest,
    ) -> McpServerResult<Value> {
        let level = request
            .params
            .as_ref()
            .and_then(|params| params.get("level"))
            .and_then(Value::as_str)
            .unwrap_or("info")
            .to_owned();
        let mut sessions = self.sessions.write().await;
        let active = sessions.get_mut(&session.id).ok_or_else(|| {
            McpServerError::Provider(format!("MCP session `{}` is not active", session.id))
        })?;
        active.logging_level = level;
        Ok(json!({}))
    }

    async fn roots_list(&self) -> McpServerResult<Value> {
        Ok(json!({ "roots": self.config.client_requests.roots().await? }))
    }

    async fn sample(&self, request: JsonRpcRequest) -> McpServerResult<Value> {
        self.config
            .client_requests
            .sample(request.params.unwrap_or_else(|| json!({})))
            .await
    }

    async fn elicit(&self, request: JsonRpcRequest) -> McpServerResult<Value> {
        self.config
            .client_requests
            .elicit(request.params.unwrap_or_else(|| json!({})))
            .await
    }

    async fn tasks_list(&self, session: &McpSession) -> McpServerResult<Value> {
        Ok(json!({
            "tasks": session.tasks.values().map(|stored| stored.task.clone()).collect::<Vec<_>>()
        }))
    }

    async fn task_from_native_status(&self, task_id: &str) -> McpServerResult<Option<StoredTask>> {
        let Ok(action_id) = ActionId::parse(task_id) else {
            return Ok(None);
        };
        let body = self
            .dispatch_body(MessageBody::ActionStatusRequest(ActionStatusRequest {
                action_id,
                tenant_id: None,
                include_result: true,
                include_receipts: false,
                include_chunks: false,
                wait_ms: None,
            }))
            .await?;
        match body {
            MessageBody::ActionStatus(status) => {
                if matches!(status.state, aip_core::ActionLifecycleState::Unknown) {
                    return Ok(None);
                }
                let result = status.result.as_ref().map(call_tool_result);
                Ok(Some(StoredTask {
                    task: aip_profile_mcp::task_from_action_status(task_id.to_owned(), &status),
                    result,
                }))
            }
            MessageBody::Error(error) if error.error.code == "action.not_found" => Ok(None),
            MessageBody::Error(error) => Err(McpServerError::Provider(format!(
                "{}: {}",
                error.error.code, error.error.message
            ))),
            other => Err(McpServerError::Provider(format!(
                "unexpected AIP response `{}`",
                other.message_type().as_str()
            ))),
        }
    }

    async fn tasks_get(
        &self,
        session: &McpSession,
        request: JsonRpcRequest,
    ) -> McpServerResult<Value> {
        let task_id = task_id_from_request(&request)?;
        let stored = match session.tasks.get(&task_id).cloned() {
            Some(stored) => stored,
            None => self
                .task_from_native_status(&task_id)
                .await?
                .ok_or_else(|| {
                    McpServerError::Provider(format!("task `{task_id}` was not found"))
                })?,
        };
        serde_json::to_value(&stored.task)
            .map_err(|error| McpServerError::Provider(error.to_string()))
    }

    async fn tasks_result(
        &self,
        session: &McpSession,
        request: JsonRpcRequest,
    ) -> McpServerResult<Value> {
        let task_id = task_id_from_request(&request)?;
        let stored = match session.tasks.get(&task_id).cloned() {
            Some(stored) => stored,
            None => self
                .task_from_native_status(&task_id)
                .await?
                .ok_or_else(|| {
                    McpServerError::Provider(format!("task `{task_id}` was not found"))
                })?,
        };
        stored.result.clone().ok_or_else(|| {
            McpServerError::Provider(format!("task `{task_id}` has no terminal result yet"))
        })
    }

    async fn tasks_cancel(
        &self,
        session: McpSession,
        request: JsonRpcRequest,
    ) -> McpServerResult<Value> {
        let task_id = task_id_from_request(&request)?;
        if let Some(mut stored) = session.tasks.get(&task_id).cloned() {
            stored.task.status = TaskStatus::Cancelled;
            stored.task.last_updated_at = Some(OffsetDateTime::now_utc().to_string());
            if let Ok(action_id) = aip_core::ActionId::parse(&task_id) {
                let mut envelope = Envelope::new(MessageBody::Cancel(aip_core::Cancel {
                    target: CancelTarget::Action(action_id),
                    reason: Some("cancelled through MCP tasks/cancel".to_owned()),
                }));
                envelope.from = Some(self.current_request_identity().actor.principal);
                let _ = self.dispatch_envelope(envelope).await;
            }
            let task = stored.task.clone();
            self.store_task(&session.id, task_id, stored).await?;
            serde_json::to_value(task).map_err(|error| McpServerError::Provider(error.to_string()))
        } else if let Ok(action_id) = aip_core::ActionId::parse(&task_id) {
            let body = self
                .dispatch_body(MessageBody::Cancel(aip_core::Cancel {
                    target: CancelTarget::Action(action_id),
                    reason: Some("cancelled through MCP tasks/cancel".to_owned()),
                }))
                .await?;
            match body {
                MessageBody::ActionResult(result) => {
                    let task = aip_profile_mcp::task_from_action_result(task_id, &result);
                    serde_json::to_value(task)
                        .map_err(|error| McpServerError::Provider(error.to_string()))
                }
                MessageBody::Error(error) => Err(McpServerError::Provider(format!(
                    "{}: {}",
                    error.error.code, error.error.message
                ))),
                other => Err(McpServerError::Provider(format!(
                    "unexpected AIP response `{}`",
                    other.message_type().as_str()
                ))),
            }
        } else {
            Err(McpServerError::Provider(format!(
                "task `{task_id}` was not found"
            )))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StableFacadeTool {
    Capabilities,
    Call,
    Events,
    ActionStatus,
    ActionResult,
    ActionList,
    ActionEvents,
    ActionCancel,
    SessionGet,
    SessionList,
    SessionClose,
    SessionResume,
    ApprovalGet,
    ApprovalList,
    ApprovalDecide,
    CallbackDeliveryGet,
    CallbackDeliveryList,
    TransactionGet,
    ReceiptGet,
    AuditEvents,
    ResourceList,
    ResourceRead,
    ScenarioRun,
    Delegate,
}

fn stable_facade_tool(name: &str) -> Option<StableFacadeTool> {
    match name {
        AIP_CAPABILITIES_TOOL | "aip.capabilities" => Some(StableFacadeTool::Capabilities),
        AIP_CALL_TOOL | "aip.call" => Some(StableFacadeTool::Call),
        AIP_EVENTS_TOOL | "aip.events" => Some(StableFacadeTool::Events),
        AIP_ACTION_STATUS_TOOL | "aip.action.status" => Some(StableFacadeTool::ActionStatus),
        AIP_ACTION_RESULT_TOOL | "aip.action.result" => Some(StableFacadeTool::ActionResult),
        AIP_ACTION_LIST_TOOL | "aip.action.list" => Some(StableFacadeTool::ActionList),
        AIP_ACTION_EVENTS_TOOL | "aip.action.events" => Some(StableFacadeTool::ActionEvents),
        AIP_ACTION_CANCEL_TOOL | "aip.action.cancel" => Some(StableFacadeTool::ActionCancel),
        AIP_SESSION_GET_TOOL | "aip.session.get" => Some(StableFacadeTool::SessionGet),
        AIP_SESSION_LIST_TOOL | "aip.session.list" => Some(StableFacadeTool::SessionList),
        AIP_SESSION_CLOSE_TOOL | "aip.session.close" => Some(StableFacadeTool::SessionClose),
        AIP_SESSION_RESUME_TOOL | "aip.session.resume" => Some(StableFacadeTool::SessionResume),
        AIP_APPROVAL_GET_TOOL | "aip.approval.get" => Some(StableFacadeTool::ApprovalGet),
        AIP_APPROVAL_LIST_TOOL | "aip.approval.list" => Some(StableFacadeTool::ApprovalList),
        AIP_APPROVAL_DECIDE_TOOL | "aip.approval.decide" => Some(StableFacadeTool::ApprovalDecide),
        AIP_CALLBACK_DELIVERY_GET_TOOL | "aip.callback.delivery.get" => {
            Some(StableFacadeTool::CallbackDeliveryGet)
        }
        AIP_CALLBACK_DELIVERY_LIST_TOOL | "aip.callback.delivery.list" => {
            Some(StableFacadeTool::CallbackDeliveryList)
        }
        AIP_TRANSACTION_GET_TOOL | "aip.transaction.get" => Some(StableFacadeTool::TransactionGet),
        AIP_RECEIPT_GET_TOOL | "aip.receipt.get" => Some(StableFacadeTool::ReceiptGet),
        AIP_AUDIT_EVENTS_TOOL | "aip.audit.events" => Some(StableFacadeTool::AuditEvents),
        AIP_RESOURCE_LIST_TOOL | "aip.resource.list" => Some(StableFacadeTool::ResourceList),
        AIP_RESOURCE_READ_TOOL | "aip.resource.read" => Some(StableFacadeTool::ResourceRead),
        AIP_SCENARIO_RUN_TOOL | "aip.scenario.run" => Some(StableFacadeTool::ScenarioRun),
        AIP_DELEGATE_TOOL | "aip.delegate" => Some(StableFacadeTool::Delegate),
        _ => None,
    }
}

fn stable_facade_tools() -> Vec<McpTool> {
    vec![
        stable_tool(
            AIP_CAPABILITIES_TOOL,
            "aip.capabilities",
            "Lists live AIP capabilities and contracts without requiring generated MCP tool refresh.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "properties": {
                    "capability_id": { "type": "string" },
                    "profile": { "type": "string" },
                    "query": { "type": "string" },
                    "include_schemas": { "type": "boolean", "default": true },
                    "include_contracts": { "type": "boolean", "default": true },
                    "include_bindings": { "type": "boolean", "default": true },
                    "cursor": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1 }
                }
            }),
        ),
        stable_tool(
            AIP_CALL_TOOL,
            "aip.call",
            "Calls any AIP capability by capability_id through the native gateway/runtime path.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["capability_id"],
                "properties": {
                    "capability_id": { "type": "string" },
                    "input": { "type": ["object", "array", "string", "number", "boolean", "null"] },
                    "action_id": { "type": "string" },
                    "mode": { "type": "string", "enum": ["sync", "async", "streaming"] },
                    "idempotency_key": { "type": "string" },
                    "timeout_ms": { "type": "integer", "minimum": 1 },
                    "conversation": { "type": "object", "additionalProperties": true },
                    "memory_context": {},
                    "delegation_chain": {
                        "type": "array",
                        "items": { "type": "object", "additionalProperties": true }
                    },
                    "federation": { "type": "object", "additionalProperties": true },
                    "callback": { "type": "object", "additionalProperties": true },
                    "observability": { "type": "object", "additionalProperties": true },
                    "compliance": { "type": "object", "additionalProperties": true },
                    "approval": { "type": "object", "additionalProperties": true },
                    "transaction": { "type": "object", "additionalProperties": true },
                    "context": { "type": "object", "additionalProperties": true }
                }
            }),
        ),
        stable_tool(
            AIP_EVENTS_TOOL,
            "aip.events",
            "Reads the native AIP event stream with cursor, limit, and kind filters.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "properties": {
                    "cursor": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1 },
                    "kinds": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "kind": { "type": "string" }
                }
            }),
        ),
        stable_tool(
            AIP_ACTION_STATUS_TOOL,
            "aip.action.status",
            "Reads native AIP durable lifecycle status for one action.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["action_id"],
                "properties": {
                    "action_id": { "type": "string" },
                    "include_result": { "type": "boolean", "default": false },
                    "include_receipts": { "type": "boolean", "default": false },
                    "include_chunks": { "type": "boolean", "default": false },
                    "wait_ms": { "type": "integer", "minimum": 0, "maximum": 30000 }
                }
            }),
        ),
        stable_tool(
            AIP_ACTION_RESULT_TOOL,
            "aip.action.result",
            "Fetches the final native AIP result for one action.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["action_id"],
                "properties": {
                    "action_id": { "type": "string" },
                    "wait_ms": { "type": "integer", "minimum": 0, "maximum": 30000 },
                    "include_receipt": { "type": "boolean", "default": false },
                    "include_terminal_events": { "type": "boolean", "default": false }
                }
            }),
        ),
        stable_tool(
            AIP_ACTION_LIST_TOOL,
            "aip.action.list",
            "Lists native AIP durable action lifecycle views with filters and cursor pagination.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "properties": {
                    "state": {
                        "type": "string",
                        "enum": [
                            "unknown",
                            "accepted",
                            "queued",
                            "running",
                            "streaming",
                            "pending_approval",
                            "cancelling",
                            "cancelled",
                            "completed",
                            "failed",
                            "expired",
                            "dead_lettered"
                        ]
                    },
                    "capability_id": { "type": "string" },
                    "session_id": { "type": "string" },
                    "principal_id": { "type": "string" },
                    "approval_id": { "type": "string" },
                    "transaction_id": { "type": "string" },
                    "cursor": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "include_results": { "type": "boolean", "default": false },
                    "include_receipts": { "type": "boolean", "default": false }
                }
            }),
        ),
        stable_tool(
            AIP_ACTION_EVENTS_TOOL,
            "aip.action.events",
            "Reads native AIP events and chunks scoped to one action.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["action_id"],
                "properties": {
                    "action_id": { "type": "string" },
                    "cursor": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "kinds": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "kind": { "type": "string" },
                    "include_chunks": { "type": "boolean", "default": false },
                    "follow": { "type": "boolean", "default": false }
                }
            }),
        ),
        stable_tool(
            AIP_ACTION_CANCEL_TOOL,
            "aip.action.cancel",
            "Cancels one native AIP action through the protocol lifecycle path.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["action_id"],
                "properties": {
                    "action_id": { "type": "string" },
                    "reason": { "type": "string" }
                }
            }),
        ),
        stable_tool(
            AIP_SESSION_GET_TOOL,
            "aip.session.get",
            "Reads one native AIP session view.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["session_id"],
                "properties": {
                    "session_id": { "type": "string" }
                }
            }),
        ),
        stable_tool(
            AIP_SESSION_LIST_TOOL,
            "aip.session.list",
            "Lists native AIP sessions with principal, state, and cursor filters.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "properties": {
                    "principal_id": { "type": "string" },
                    "status": { "type": "string" },
                    "cursor": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 }
                }
            }),
        ),
        stable_tool(
            AIP_SESSION_CLOSE_TOOL,
            "aip.session.close",
            "Closes one native AIP session through lifecycle semantics.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["session_id"],
                "properties": {
                    "session_id": { "type": "string" },
                    "reason": { "type": "string" }
                }
            }),
        ),
        stable_tool(
            AIP_SESSION_RESUME_TOOL,
            "aip.session.resume",
            "Resumes one native AIP session and replays events after a cursor.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["session_id"],
                "properties": {
                    "session_id": { "type": "string" },
                    "resume_token": { "type": "string" },
                    "last_event_cursor": { "type": "string" }
                }
            }),
        ),
        stable_tool(
            AIP_APPROVAL_GET_TOOL,
            "aip.approval.get",
            "Reads one native AIP approval record with optional linked action and receipts.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["approval_id"],
                "properties": {
                    "approval_id": { "type": "string" },
                    "include_action_status": { "type": "boolean", "default": false },
                    "include_receipts": { "type": "boolean", "default": false },
                    "include_evidence_payload": {
                        "type": "boolean",
                        "default": false,
                        "description": "Exports sensitive immutable action evidence; requires approval:export and approval:sensitive."
                    }
                }
            }),
        ),
        stable_tool(
            AIP_APPROVAL_LIST_TOOL,
            "aip.approval.list",
            "Lists native AIP approval records for HITL queues and audit consoles.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "properties": {
                    "status": { "type": "string" },
                    "approver": { "type": "string" },
                    "requester": { "type": "string" },
                    "tenant_id": { "type": "string" },
                    "cursor": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "include_action_status": { "type": "boolean", "default": false },
                    "include_receipts": { "type": "boolean", "default": false }
                }
            }),
        ),
        stable_tool(
            AIP_APPROVAL_DECIDE_TOOL,
            "aip.approval.decide",
            "Records a native AIP approval decision. When the approval request exposes a policy_hash, the decision must repeat that exact value.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["approval_id", "decision"],
                "properties": {
                    "approval_id": { "type": "string" },
                    "decision": {
                        "type": "string",
                        "enum": ["approved", "granted", "approve", "grant", "denied", "deny", "expired", "revoked", "revoke"]
                    },
                    "approver_principal": { "type": "string" },
                    "reason": { "type": "string" },
                    "decision_id": {
                        "type": "string",
                        "description": "Optional caller-stable identifier used to make decision submission idempotent."
                    },
                    "policy_hash": {
                        "type": "string",
                        "description": "Exact immutable policy_hash returned by aip_approval_get. Required whenever that approval request contains a policy_hash; do not place this value only in evidence."
                    },
                    "target_decision_id": {
                        "type": "string",
                        "description": "Existing decision identifier targeted by a revocation decision."
                    },
                    "constraints": { "type": "array" },
                    "evidence": {
                        "type": "array",
                        "items": {
                            "oneOf": [
                                { "type": "string" },
                                {
                                    "type": "object",
                                    "required": ["id", "kind", "redacted"],
                                    "properties": {
                                        "id": { "type": "string" },
                                        "kind": { "type": "string" },
                                        "uri": { "type": "string" },
                                        "hash": { "type": "string" },
                                        "redacted": { "type": "boolean" }
                                    }
                                }
                            ]
                        }
                    },
                    "external_ticket_uri": { "type": "string" },
                    "attachment_uri": { "type": "string" }
                }
            }),
        ),
        stable_tool(
            AIP_CALLBACK_DELIVERY_GET_TOOL,
            "aip.callback.delivery.get",
            "Reads one native AIP callback delivery record by delivery_id.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["delivery_id"],
                "properties": {
                    "delivery_id": { "type": "string" },
                    "tenant_id": { "type": "string" },
                    "include_receipts": { "type": "boolean", "default": false }
                }
            }),
        ),
        stable_tool(
            AIP_CALLBACK_DELIVERY_LIST_TOOL,
            "aip.callback.delivery.list",
            "Lists native AIP callback delivery records by action, status, profile, target, or tenant.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "properties": {
                    "action_id": { "type": "string" },
                    "status": { "type": "string", "enum": ["pending", "running", "delivered", "failed"] },
                    "profile": { "type": "string" },
                    "target": { "type": "string" },
                    "tenant_id": { "type": "string" },
                    "cursor": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "include_receipts": { "type": "boolean", "default": false },
                    "export": { "type": "boolean", "default": false }
                }
            }),
        ),
        stable_tool(
            AIP_TRANSACTION_GET_TOOL,
            "aip.transaction.get",
            "Reads one native AIP transaction by transaction_id, plan_id, or action_id.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "properties": {
                    "transaction_id": { "type": "string" },
                    "plan_id": { "type": "string" },
                    "action_id": { "type": "string" },
                    "include_result": { "type": "boolean", "default": false },
                    "include_receipts": { "type": "boolean", "default": false }
                }
            }),
        ),
        stable_tool(
            AIP_RECEIPT_GET_TOOL,
            "aip.receipt.get",
            "Reads a native AIP receipt chain by chain_id or receipt_id.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "properties": {
                    "chain_id": { "type": "string" },
                    "receipt_id": { "type": "string" }
                }
            }),
        ),
        stable_tool(
            AIP_AUDIT_EVENTS_TOOL,
            "aip.audit.events",
            "Queries native AIP audit events and optional receipt chains.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "properties": {
                    "action_id": { "type": "string" },
                    "session_id": { "type": "string" },
                    "principal_id": { "type": "string" },
                    "transaction_id": { "type": "string" },
                    "from": { "type": "string", "format": "date-time" },
                    "to": { "type": "string", "format": "date-time" },
                    "cursor": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "include_receipts": { "type": "boolean", "default": false }
                }
            }),
        ),
        stable_tool(
            AIP_RESOURCE_LIST_TOOL,
            "aip.resource.list",
            "Lists native AIP resources without depending on the MCP resource projection.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "properties": {
                    "capability_id": { "type": "string" },
                    "kind": { "type": "string" },
                    "cursor": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 }
                }
            }),
        ),
        stable_tool(
            AIP_RESOURCE_READ_TOOL,
            "aip.resource.read",
            "Reads one native AIP resource by resource_id.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["resource_id"],
                "properties": {
                    "resource_id": { "type": "string" },
                    "version": { "type": "string" },
                    "accept": {
                        "oneOf": [
                            { "type": "string" },
                            {
                                "type": "array",
                                "items": { "type": "string" }
                            }
                        ]
                    }
                }
            }),
        ),
        stable_tool(
            AIP_SCENARIO_RUN_TOOL,
            "aip.scenario.run",
            "Runs a deterministic sequence of real AIP capability calls through the gateway.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["scenario_id", "steps"],
                "properties": {
                    "scenario_id": { "type": "string" },
                    "continue_on_error": { "type": "boolean", "default": false },
                    "steps": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": true,
                            "required": ["capability_id"],
                            "properties": {
                                "name": { "type": "string" },
                                "capability_id": { "type": "string" },
                                "input": { "type": ["object", "array", "string", "number", "boolean", "null"] },
                                "idempotency_key": { "type": "string" },
                                "mode": { "type": "string", "enum": ["sync", "async", "streaming"] },
                                "transaction": { "type": "object", "additionalProperties": true },
                                "context": { "type": "object", "additionalProperties": true }
                            }
                        }
                    }
                }
            }),
        ),
        stable_tool(
            AIP_DELEGATE_TOOL,
            "aip.delegate",
            "Creates a first-class AIP parent-child delegation and returns its durable result.",
            json!({
                "type": "object",
                "additionalProperties": true,
                "required": ["delegate_id", "scope", "capability_id"],
                "properties": {
                    "delegation_id": { "type": "string" },
                    "parent_action_id": { "type": "string" },
                    "delegate_id": { "type": "string" },
                    "scope": { "type": "string" },
                    "capability_id": { "type": "string" },
                    "input": {},
                    "action_id": { "type": "string" },
                    "idempotency_key": { "type": "string" },
                    "mode": { "type": "string", "enum": ["sync", "async", "streaming"] },
                    "timeout_ms": { "type": "integer", "minimum": 1 },
                    "approval": { "type": "object", "additionalProperties": true },
                    "transaction": { "type": "object" },
                    "identity": { "type": "object" },
                    "callback": { "type": "object" },
                    "metadata": { "type": "object" }
                }
            }),
        ),
    ]
}

fn stable_tool(
    name: &str,
    canonical_name: &str,
    description: &str,
    input_schema: Value,
) -> McpTool {
    McpTool {
        name: name.to_owned(),
        title: Some(canonical_name.to_owned()),
        description: Some(description.to_owned()),
        icons: Vec::new(),
        input_schema,
        output_schema: Some(json!({
            "type": "object",
            "additionalProperties": true
        })),
        annotations: Some(json!({
            "aipStableFacade": true,
            "readOnlyHint": matches!(
                name,
                AIP_CAPABILITIES_TOOL
                    | AIP_EVENTS_TOOL
                    | AIP_ACTION_STATUS_TOOL
                    | AIP_ACTION_RESULT_TOOL
                    | AIP_ACTION_LIST_TOOL
                    | AIP_ACTION_EVENTS_TOOL
                    | AIP_SESSION_GET_TOOL
                    | AIP_SESSION_LIST_TOOL
                    | AIP_APPROVAL_GET_TOOL
                    | AIP_APPROVAL_LIST_TOOL
                    | AIP_CALLBACK_DELIVERY_GET_TOOL
                    | AIP_CALLBACK_DELIVERY_LIST_TOOL
                    | AIP_TRANSACTION_GET_TOOL
                    | AIP_RECEIPT_GET_TOOL
                    | AIP_AUDIT_EVENTS_TOOL
                    | AIP_RESOURCE_LIST_TOOL
                    | AIP_RESOURCE_READ_TOOL
            )
        })),
        execution: Some(ToolExecution {
            task_support: TaskSupport::Forbidden,
        }),
        meta: Some(aip_extension_meta(json!({
            "facade": "stable",
            "canonical_name": canonical_name,
            "generated_tools_may_change": false
        }))),
    }
}

fn tool_arguments(request: &JsonRpcRequest) -> McpServerResult<Value> {
    let params = request
        .params
        .as_ref()
        .ok_or(McpProfileError::MissingParams)?;
    Ok(params
        .get("arguments")
        .cloned()
        .filter(|value| !value.is_null())
        .unwrap_or_else(|| json!({})))
}

fn action_id_from_arguments(arguments: &Value) -> McpServerResult<ActionId> {
    ActionId::parse(required_string(arguments, "action_id")?)
        .map_err(|error| McpServerError::Provider(error.to_string()))
}

fn action_from_facade_arguments(
    arguments: &Value,
    request_params: Option<&Value>,
) -> McpServerResult<Action> {
    let capability_id = CapabilityId::parse(required_string(arguments, "capability_id")?)
        .map_err(|error| McpServerError::Provider(error.to_string()))?;
    let input = arguments.get("input").cloned().unwrap_or_else(|| json!({}));
    let mut action = Action::new(capability_id, input);
    if let Some(action_id) = optional_action_string(arguments, "action_id") {
        action.id = ActionId::parse(action_id)
            .map_err(|error| McpServerError::Provider(error.to_string()))?;
    }
    if let Some(mode) = optional_action_string(arguments, "mode") {
        action.mode = Some(action_mode(mode)?);
    } else if request_params
        .and_then(|params| params.get("task"))
        .is_some()
    {
        action.mode = Some(ActionMode::Async);
    }
    if let Some(idempotency_key) = optional_action_string(arguments, "idempotency_key") {
        action.idempotency_key = Some(idempotency_key.to_owned());
    }
    if let Some(timeout_ms) = optional_action_u64(arguments, "timeout_ms")? {
        action.timeout_ms = Some(timeout_ms);
    }
    action.conversation = deserialize_action_field::<Conversation>(arguments, "conversation")?;
    action.memory_context = action_field(arguments, "memory_context").cloned();
    action.delegation_chain =
        deserialize_action_field::<Vec<DelegationEntry>>(arguments, "delegation_chain")?
            .unwrap_or_default();
    action.federation = deserialize_action_field::<FederationContext>(arguments, "federation")?;
    action.callback = deserialize_action_field::<Callback>(arguments, "callback")?;
    action.observability =
        deserialize_action_field::<ObservabilityContext>(arguments, "observability")?;
    action.compliance = deserialize_action_field::<ComplianceContext>(arguments, "compliance")?;
    action.identity = deserialize_action_field::<IdentityContext>(arguments, "identity")?;
    action.approval = deserialize_action_field::<ApprovalDecision>(arguments, "approval")?;
    action.transaction = deserialize_action_field::<ActionTransaction>(arguments, "transaction")?;
    Ok(action)
}

fn mcp_result_from_action_body(action_id: ActionId, body: MessageBody) -> McpServerResult<Value> {
    match body {
        MessageBody::ActionResult(result) => Ok(call_tool_result(&result)),
        MessageBody::Ack(ack) => Ok(mcp_tool_result(
            json!({
                "action_id": action_id,
                "ack": ack
            }),
            false,
        )),
        MessageBody::EventStream(stream) => Ok(mcp_tool_result(
            serde_json::to_value(stream)
                .map_err(|error| McpServerError::Provider(error.to_string()))?,
            false,
        )),
        MessageBody::Error(error) => Err(McpServerError::Provider(error.error.message)),
        other => Ok(mcp_tool_result(
            json!({
                "action_id": action_id,
                "message_type": other.message_type().as_str(),
                "body": serde_json::to_value(other)
                    .map_err(|error| McpServerError::Provider(error.to_string()))?
            }),
            false,
        )),
    }
}

fn mcp_result_from_read_body(body: MessageBody) -> McpServerResult<Value> {
    match body {
        MessageBody::Error(error) => Err(McpServerError::Provider(format!(
            "{}: {}",
            error.error.code, error.error.message
        ))),
        body => {
            let message_type = body.message_type().as_str().to_owned();
            let body = mcp_read_body_value(body)?;
            Ok(mcp_tool_result(
                json!({
                    "message_type": message_type,
                    "body": body
                }),
                false,
            ))
        }
    }
}

fn mcp_read_body_value(body: MessageBody) -> McpServerResult<Value> {
    let value = match body {
        MessageBody::ActionStatus(status) => json!({ "action_status": status }),
        MessageBody::ActionResult(result) => json!({ "action_result": result }),
        MessageBody::ActionList(list) => json!({ "action_list": list }),
        MessageBody::ActionEvents(events) => json!({ "action_events": events }),
        MessageBody::EventStream(stream) => json!({ "event_stream": stream }),
        MessageBody::SessionView(view) => json!({ "session_view": view }),
        MessageBody::SessionList(list) => json!({ "session_list": list }),
        MessageBody::SessionResume(resume) => json!({ "session_resume": resume }),
        MessageBody::ApprovalRecordView(view) => json!({ "approval_record_view": view }),
        MessageBody::ApprovalList(list) => json!({ "approval_list": list }),
        MessageBody::CallbackDeliveryRecord(record) => {
            json!({ "callback_delivery_record": record })
        }
        MessageBody::CallbackDeliveryList(list) => json!({ "callback_delivery_list": list }),
        MessageBody::TransactionView(view) => json!({ "transaction_view": view }),
        MessageBody::ReceiptChain(chain) => json!({ "receipt_chain": chain }),
        MessageBody::AuditQueryResult(result) => json!({ "audit_query_result": result }),
        MessageBody::ResourceList(list) => json!({ "resource_list": list }),
        MessageBody::ResourceReadResult(result) => json!({ "resource_read_result": result }),
        MessageBody::Ack(ack) => json!({ "ack": ack }),
        other => serde_json::to_value(other)
            .map_err(|error| McpServerError::Provider(error.to_string()))?,
    };
    Ok(value)
}

fn scenario_step_result(
    name: String,
    index: usize,
    action_id: ActionId,
    capability_id: CapabilityId,
    body: MessageBody,
) -> McpServerResult<(bool, Value)> {
    match body {
        MessageBody::ActionResult(result) => {
            let failed =
                result.error.is_some() || result.status != aip_core::ActionResultStatus::Completed;
            Ok((
                failed,
                json!({
                    "name": name,
                    "index": index,
                    "action_id": result.action_id,
                    "capability_id": capability_id,
                    "status": result.status,
                    "output": result.output,
                    "error": result.error
                }),
            ))
        }
        MessageBody::Ack(ack) => Ok((
            false,
            json!({
                "name": name,
                "index": index,
                "action_id": action_id,
                "capability_id": capability_id,
                "status": "accepted",
                "ack": ack
            }),
        )),
        MessageBody::Error(error) => Ok((
            true,
            json!({
                "name": name,
                "index": index,
                "action_id": action_id,
                "capability_id": capability_id,
                "status": "failed",
                "error": error.error
            }),
        )),
        other => Ok((
            false,
            json!({
                "name": name,
                "index": index,
                "action_id": action_id,
                "capability_id": capability_id,
                "status": "completed",
                "message_type": other.message_type().as_str(),
                "body": serde_json::to_value(other)
                    .map_err(|error| McpServerError::Provider(error.to_string()))?
            }),
        )),
    }
}

fn mcp_tool_result(structured_content: Value, is_error: bool) -> Value {
    let text = mcp_tool_result_text(&structured_content, is_error);
    json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "structuredContent": structured_content,
        "isError": is_error
    })
}

fn mcp_tool_result_text(structured_content: &Value, is_error: bool) -> String {
    if let Some(message_type) = structured_content
        .get("message_type")
        .and_then(Value::as_str)
    {
        return format!("AIP {message_type}");
    }
    if let Some(status) = structured_content.get("status").and_then(Value::as_str) {
        return format!("AIP result: {status}");
    }
    if let Some(scenario_id) = structured_content
        .get("scenario_id")
        .and_then(Value::as_str)
    {
        let status = structured_content
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return format!("AIP scenario {scenario_id}: {status}");
    }
    if is_error {
        "AIP tool error".to_owned()
    } else {
        "AIP tool result".to_owned()
    }
}

fn action_mode(value: &str) -> McpServerResult<ActionMode> {
    match value {
        "sync" => Ok(ActionMode::Sync),
        "async" => Ok(ActionMode::Async),
        "streaming" => Ok(ActionMode::Streaming),
        other => Err(McpServerError::Provider(format!(
            "unsupported action mode `{other}`"
        ))),
    }
}

fn decision_kind_from_arguments(arguments: &Value) -> McpServerResult<ApprovalDecisionKind> {
    match required_string(arguments, "decision")? {
        "approved" | "granted" | "approve" | "grant" => Ok(ApprovalDecisionKind::Approved),
        "denied" | "deny" => Ok(ApprovalDecisionKind::Denied),
        "expired" => Ok(ApprovalDecisionKind::Expired),
        "revoked" | "revoke" => Ok(ApprovalDecisionKind::Revoked),
        other => Err(McpServerError::Provider(format!(
            "unsupported approval decision `{other}`"
        ))),
    }
}

fn callback_delivery_status(value: &str) -> McpServerResult<CallbackDeliveryStatus> {
    serde_json::from_value(json!(value))
        .map_err(|error| McpServerError::Provider(error.to_string()))
}

fn evidence_from_arguments(arguments: &Value) -> McpServerResult<Vec<EvidenceArtifact>> {
    let mut evidence = match arguments.get("evidence") {
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(index, item)| evidence_artifact_from_value(index, item))
            .collect::<McpServerResult<Vec<_>>>()?,
        Some(_) => {
            return Err(McpServerError::Provider(
                "evidence must be an array of evidence objects or URI strings".to_owned(),
            ));
        }
        None => Vec::new(),
    };
    if let Some(uri) = optional_string(arguments, "external_ticket_uri") {
        evidence.push(EvidenceArtifact {
            id: format!("evidence:ticket:{}", evidence.len() + 1),
            kind: "external_ticket".to_owned(),
            uri: Some(uri.to_owned()),
            hash: None,
            redacted: true,
        });
    }
    if let Some(uri) = optional_string(arguments, "attachment_uri") {
        evidence.push(EvidenceArtifact {
            id: format!("evidence:attachment:{}", evidence.len() + 1),
            kind: "attachment".to_owned(),
            uri: Some(uri.to_owned()),
            hash: None,
            redacted: true,
        });
    }
    Ok(evidence)
}

fn evidence_artifact_from_value(index: usize, item: &Value) -> McpServerResult<EvidenceArtifact> {
    match item {
        Value::String(uri) => Ok(EvidenceArtifact {
            id: format!("evidence:uri:{}", index + 1),
            kind: "uri".to_owned(),
            uri: Some(uri.clone()),
            hash: None,
            redacted: true,
        }),
        Value::Object(_) => serde_json::from_value::<EvidenceArtifact>(item.clone())
            .map_err(|error| McpServerError::Provider(format!("invalid evidence item: {error}"))),
        _ => Err(McpServerError::Provider(
            "evidence items must be evidence objects or URI strings".to_owned(),
        )),
    }
}

fn principal_scopes(principal: &Principal) -> BTreeSet<String> {
    principal
        .auth_context
        .as_ref()
        .and_then(|context| context.get("scopes"))
        .map_or_else(BTreeSet::new, |scopes| match scopes {
            Value::Array(values) => values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect(),
            Value::String(scope) => BTreeSet::from([scope.clone()]),
            _ => BTreeSet::new(),
        })
}

fn require_mcp_scope(
    authenticated: &AuthenticatedPrincipal,
    required: &str,
) -> McpServerResult<()> {
    authenticated
        .validate(&BTreeSet::from([required.to_owned()]))
        .map_err(|_| {
            McpServerError::Provider(format!(
                "authenticated MCP principal lacks required scope `{required}`"
            ))
        })?;
    if authenticated.scopes.contains(required) || authenticated.scopes.contains("*") {
        Ok(())
    } else {
        Err(McpServerError::Provider(format!(
            "authenticated MCP principal lacks required scope `{required}`"
        )))
    }
}

fn string_array(arguments: &Value, field: &str) -> McpServerResult<Vec<String>> {
    if let Some(single) = optional_string(arguments, "kind") {
        return Ok(vec![single.to_owned()]);
    }
    let Some(value) = arguments.get(field) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| McpServerError::Provider(format!("{field} must be an array")))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| McpServerError::Provider(format!("{field} entries must be strings")))
        })
        .collect()
}

fn string_or_array(arguments: &Value, field: &str) -> McpServerResult<Vec<String>> {
    let Some(value) = arguments.get(field) else {
        return Ok(Vec::new());
    };
    match value {
        Value::String(value) => Ok(value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect()),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                    McpServerError::Provider(format!("{field} entries must be strings"))
                })
            })
            .collect(),
        _ => Err(McpServerError::Provider(format!(
            "{field} must be a string or an array of strings"
        ))),
    }
}

fn deserialize_field<T>(arguments: &Value, field: &str) -> McpServerResult<Option<T>>
where
    T: DeserializeOwned,
{
    let Some(value) = arguments.get(field) else {
        return Ok(None);
    };
    serde_json::from_value(value.clone())
        .map(Some)
        .map_err(|error| McpServerError::Provider(format!("invalid {field}: {error}")))
}

fn deserialize_action_field<T>(arguments: &Value, field: &str) -> McpServerResult<Option<T>>
where
    T: DeserializeOwned,
{
    let Some(value) = action_field(arguments, field) else {
        return Ok(None);
    };
    serde_json::from_value(value.clone())
        .map(Some)
        .map_err(|error| McpServerError::Provider(format!("invalid {field}: {error}")))
}

fn required_string<'a>(arguments: &'a Value, field: &str) -> McpServerResult<&'a str> {
    optional_string(arguments, field)
        .ok_or_else(|| McpServerError::Provider(format!("missing required string `{field}`")))
}

fn optional_string<'a>(arguments: &'a Value, field: &str) -> Option<&'a str> {
    arguments
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn optional_action_string<'a>(arguments: &'a Value, field: &str) -> Option<&'a str> {
    action_field(arguments, field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn optional_bool(arguments: &Value, field: &str) -> Option<bool> {
    arguments.get(field).and_then(Value::as_bool)
}

fn optional_u32(arguments: &Value, field: &str) -> McpServerResult<Option<u32>> {
    optional_usize(arguments, field).map(|value| value.map(|value| value as u32))
}

fn optional_u64(arguments: &Value, field: &str) -> McpServerResult<Option<u64>> {
    let Some(value) = arguments.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| McpServerError::Provider(format!("{field} must be an integer")))
}

fn optional_usize(arguments: &Value, field: &str) -> McpServerResult<Option<usize>> {
    let Some(value) = arguments.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(McpServerError::Provider(format!(
            "{field} must be an integer"
        )));
    };
    usize::try_from(value)
        .map(Some)
        .map_err(|error| McpServerError::Provider(format!("invalid {field}: {error}")))
}

fn optional_action_u64(arguments: &Value, field: &str) -> McpServerResult<Option<u64>> {
    let Some(value) = action_field(arguments, field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| McpServerError::Provider(format!("{field} must be an integer")))
}

fn action_field<'a>(arguments: &'a Value, field: &str) -> Option<&'a Value> {
    arguments.get(field).or_else(|| {
        arguments
            .get("context")
            .and_then(|context| context.get(field))
    })
}

fn capability_facade_value(
    capability: &Capability,
    include_schemas: bool,
    include_contracts: bool,
    include_bindings: bool,
) -> McpServerResult<Value> {
    let mut value = serde_json::to_value(capability)
        .map_err(|error| McpServerError::Provider(error.to_string()))?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "mcp_tool_name".to_owned(),
            json!(aip_profile_mcp::tool_from_capability(capability).name),
        );
        if !include_schemas {
            object.remove("input_schema");
            object.remove("output_schema");
        }
        if !include_contracts {
            object.remove("contract");
        }
        if !include_bindings {
            object.remove("bindings");
        }
    }
    Ok(value)
}

fn parse_fleet_capability_cursor(
    cursor: Option<&str>,
) -> McpServerResult<(usize, Option<Option<String>>)> {
    let Some(cursor) = cursor else {
        return Ok((0, None));
    };
    if let Some(offset) = cursor.strip_prefix("local:") {
        return parse_cursor(offset).map(|offset| (offset, None));
    }
    if let Some(cursor) = cursor.strip_prefix("remote:") {
        let cursor = (!cursor.is_empty()).then(|| cursor.to_owned());
        return Ok((0, Some(cursor)));
    }
    parse_cursor(cursor).map(|offset| (offset, None))
}

fn catalog_mcp_error(error: RegistryError) -> McpServerError {
    McpServerError::Provider(format!("capability catalog query failed: {error}"))
}

fn parse_cursor(cursor: &str) -> McpServerResult<usize> {
    cursor
        .parse::<usize>()
        .map_err(|error| McpServerError::Provider(format!("invalid cursor: {error}")))
}

fn task_id_from_request(request: &JsonRpcRequest) -> Result<String, McpProfileError> {
    request
        .params
        .as_ref()
        .and_then(|params| params.get("taskId"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(McpProfileError::MissingTaskId)
}

fn json_rpc_error_for_server(error: McpServerError) -> JsonRpcError {
    match error {
        McpServerError::Session(error) => JsonRpcError {
            code: error.json_rpc_code(),
            message: error.to_string(),
            data: Some(json!({ "component": "aip-mcp-session" })),
        },
        McpServerError::Profile(error) => error.to_json_rpc_error(),
        McpServerError::Gateway(error) => {
            let protocol = match Gateway::error_envelope(&error).body {
                MessageBody::Error(body) => body.error,
                _ => ProtocolError::invalid_input(error.to_string()),
            };
            json_rpc_error(&protocol)
        }
        McpServerError::Provider(message) => json_rpc_error(&protocol_error_from_profile(
            &McpProfileError::Mapping(message),
        )),
    }
}

fn validate_output_schema(
    capability: &Capability,
    result: &aip_core::ActionResult,
) -> McpServerResult<()> {
    let Some(schema) = capability.output_schema.as_ref() else {
        return Ok(());
    };
    let output = result.output.as_ref().unwrap_or(&Value::Null);
    let errors = validation_errors_draft202012(schema, Some(output), 1_024)
        .map_err(|error| McpServerError::Provider(format!("invalid output schema: {error}")))?;
    if errors.is_empty() {
        Ok(())
    } else {
        Err(McpServerError::Provider(format!(
            "tool `{}` returned structuredContent that does not match outputSchema: {}",
            capability.name,
            errors.join("; ")
        )))
    }
}

/// Converts an AIP stream chunk into an MCP progress notification when possible.
#[must_use]
pub fn progress_notification(
    progress_token: Value,
    chunk: &aip_core::StreamChunk,
) -> JsonRpcNotification {
    progress_notification_from_stream_chunk(progress_token, chunk)
}

/// Creates an MCP notification for a resource update.
#[must_use]
pub fn resource_updated_notification(uri: impl Into<String>) -> JsonRpcNotification {
    JsonRpcNotification::new(
        McpMethod::ResourcesUpdated,
        Some(json!({ "uri": uri.into() })),
    )
}

/// Creates an MCP notification for a changed tool list.
#[must_use]
pub fn tools_changed_notification() -> JsonRpcNotification {
    JsonRpcNotification::new(McpMethod::ToolsListChanged, None)
}

/// Creates an MCP notification for a changed resource list.
#[must_use]
pub fn resources_changed_notification() -> JsonRpcNotification {
    JsonRpcNotification::new(McpMethod::ResourcesListChanged, None)
}

/// Creates an MCP notification for a changed prompt list.
#[must_use]
pub fn prompts_changed_notification() -> JsonRpcNotification {
    JsonRpcNotification::new(McpMethod::PromptsListChanged, None)
}

#[cfg(test)]
mod tests {
    use super::{
        AIP_ACTION_CANCEL_TOOL, AIP_ACTION_EVENTS_TOOL, AIP_ACTION_LIST_TOOL,
        AIP_ACTION_RESULT_TOOL, AIP_ACTION_STATUS_TOOL, AIP_APPROVAL_DECIDE_TOOL,
        AIP_APPROVAL_GET_TOOL, AIP_APPROVAL_LIST_TOOL, AIP_AUDIT_EVENTS_TOOL, AIP_CALL_TOOL,
        AIP_CALLBACK_DELIVERY_GET_TOOL, AIP_CALLBACK_DELIVERY_LIST_TOOL, AIP_CAPABILITIES_TOOL,
        AIP_EVENTS_TOOL, AIP_RECEIPT_GET_TOOL, AIP_RESOURCE_LIST_TOOL, AIP_RESOURCE_READ_TOOL,
        AIP_SCENARIO_RUN_TOOL, AIP_SESSION_CLOSE_TOOL, AIP_SESSION_GET_TOOL, AIP_SESSION_LIST_TOOL,
        AIP_SESSION_RESUME_TOOL, AIP_TRANSACTION_GET_TOOL, McpServer, McpServerConfig,
        McpServerResult, ResourceProvider, evidence_from_arguments,
    };
    use aip_auth::{
        AuthScheme, AuthenticatedPrincipal, StaticTrustedIdentityResolver, TrustedIdentityBinding,
        VerifiedTenant,
    };
    use aip_connector_registry::{
        CapabilityCatalogProvider, CapabilityCatalogQuery, CapabilityDefinition, CapabilityPage,
        CatalogReadContext, CatalogRevision, RegistryError, ResolvedCapabilityDefinition,
    };
    use aip_core::{
        ActionId, ActionResult, ActionResultStatus, Capability, CapabilityId, CapabilityKind,
        Manifest, MessagePart, Principal, PrincipalId, PrincipalKind, ProfileId, TenantRef,
    };
    use aip_gateway::{Gateway, GatewayCallbackDispatcher, GatewayPolicy};
    use aip_mcp_session::McpTransportKind;
    use aip_profile_mcp::{McpResource, ResourceCapability, ResourceContents, ResourceTemplate};
    use aip_runtime::{ActionHandler, Runtime, RuntimeResult};
    use serde_json::{Value, json};
    use std::{
        collections::{BTreeSet, HashMap},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use time::OffsetDateTime;
    use tokio::sync::{Mutex, Notify};

    #[derive(Clone)]
    struct Echo;

    #[derive(Clone, Debug)]
    struct TestFleetCatalog {
        tenant_id: String,
        definition: CapabilityDefinition,
    }

    #[async_trait::async_trait]
    impl CapabilityCatalogProvider for TestFleetCatalog {
        async fn get(
            &self,
            capability_id: &CapabilityId,
            context: &CatalogReadContext,
        ) -> Result<Option<ResolvedCapabilityDefinition>, RegistryError> {
            if capability_id == &self.definition.capability.id
                && context.tenant_id.as_deref() == Some(self.tenant_id.as_str())
            {
                Ok(Some(ResolvedCapabilityDefinition {
                    definition: self.definition.clone(),
                    catalog_revision: CatalogRevision(7),
                }))
            } else {
                Ok(None)
            }
        }

        async fn query(
            &self,
            request: CapabilityCatalogQuery,
            context: &CatalogReadContext,
        ) -> Result<CapabilityPage, RegistryError> {
            let visible = context.tenant_id.as_deref() == Some(self.tenant_id.as_str())
                && request
                    .capability_id
                    .as_ref()
                    .is_none_or(|id| id == &self.definition.capability.id)
                && request.text.as_ref().is_none_or(|text| {
                    self.definition
                        .capability
                        .name
                        .to_ascii_lowercase()
                        .contains(&text.to_ascii_lowercase())
                });
            Ok(CapabilityPage {
                catalog_revision: CatalogRevision(7),
                capabilities: visible
                    .then(|| self.definition.clone())
                    .into_iter()
                    .collect(),
                next_cursor: None,
                total: u64::from(visible),
            })
        }
    }

    #[async_trait::async_trait]
    impl ActionHandler for Echo {
        async fn handle(&self, action: aip_core::Action) -> RuntimeResult<ActionResult> {
            Ok(ActionResult {
                action_id: action.id,
                status: ActionResultStatus::Completed,
                output: Some(json!({ "echo": action.input })),
                message: vec![MessagePart::text("done")],
                memory_update: None,
                usage: None,
                receipt: None,
                error: None,
            })
        }
    }

    #[derive(Clone)]
    struct BadOutput;

    #[derive(Clone)]
    struct FailedWithoutOutput;

    #[derive(Clone, Debug, Default)]
    struct CancellableHandler {
        started: Arc<Notify>,
    }

    #[async_trait::async_trait]
    impl ActionHandler for CancellableHandler {
        fn implementation_support(&self) -> aip_discovery::CapabilityImplementationSupport {
            aip_discovery::CapabilityImplementationSupport {
                invocation: true,
                cancellation: true,
                ..aip_discovery::CapabilityImplementationSupport::default()
            }
        }

        async fn handle(&self, action: aip_core::Action) -> RuntimeResult<ActionResult> {
            Ok(ActionResult {
                action_id: action.id,
                status: ActionResultStatus::Completed,
                output: None,
                message: Vec::new(),
                memory_update: None,
                usage: None,
                receipt: None,
                error: None,
            })
        }

        async fn handle_with_context(
            &self,
            action: aip_core::Action,
            context: aip_runtime::ActionExecutionContext,
        ) -> RuntimeResult<ActionResult> {
            self.started.notify_waiters();
            context.cancellation.cancelled().await;
            Ok(ActionResult {
                action_id: action.id,
                status: ActionResultStatus::Cancelled,
                output: Some(json!({ "cancelled": true })),
                message: Vec::new(),
                memory_update: None,
                usage: None,
                receipt: None,
                error: None,
            })
        }
    }

    #[derive(Clone, Debug, Default)]
    struct SubscriptionResourceProvider {
        active: Arc<Mutex<BTreeSet<String>>>,
        subscribe_calls: Arc<AtomicUsize>,
        unsubscribe_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ResourceProvider for SubscriptionResourceProvider {
        fn advertised_capability(&self) -> Option<ResourceCapability> {
            Some(ResourceCapability {
                subscribe: true,
                list_changed: true,
            })
        }

        async fn list(
            &self,
            _cursor: Option<String>,
        ) -> McpServerResult<(Vec<McpResource>, Option<String>)> {
            Ok((Vec::new(), None))
        }

        async fn templates(&self) -> McpServerResult<Vec<ResourceTemplate>> {
            Ok(Vec::new())
        }

        async fn read(&self, uri: &str) -> McpServerResult<Vec<ResourceContents>> {
            Ok(vec![ResourceContents::Text {
                uri: uri.to_owned(),
                mime_type: Some("text/plain".to_owned()),
                text: "current".to_owned(),
            }])
        }

        async fn subscribe(&self, uri: &str) -> McpServerResult<()> {
            self.subscribe_calls.fetch_add(1, Ordering::SeqCst);
            self.active.lock().await.insert(uri.to_owned());
            Ok(())
        }

        async fn unsubscribe(&self, uri: &str) -> McpServerResult<()> {
            self.unsubscribe_calls.fetch_add(1, Ordering::SeqCst);
            self.active.lock().await.remove(uri);
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl ActionHandler for BadOutput {
        async fn handle(&self, action: aip_core::Action) -> RuntimeResult<ActionResult> {
            Ok(ActionResult {
                action_id: action.id,
                status: ActionResultStatus::Completed,
                output: Some(json!({ "wrong": true })),
                message: vec![MessagePart::text("invalid")],
                memory_update: None,
                usage: None,
                receipt: None,
                error: None,
            })
        }
    }

    #[async_trait::async_trait]
    impl ActionHandler for FailedWithoutOutput {
        async fn handle(&self, action: aip_core::Action) -> RuntimeResult<ActionResult> {
            Ok(ActionResult {
                action_id: action.id,
                status: ActionResultStatus::Failed,
                output: None,
                message: vec![MessagePart::text("provider failed")],
                memory_update: None,
                usage: None,
                receipt: None,
                error: Some(aip_core::ProtocolError::invalid_input(
                    "provider execution failed",
                )),
            })
        }
    }

    async fn gateway_with_handler<H>(
        manifest: &Manifest,
        capability_id: CapabilityId,
        handler: H,
    ) -> Gateway
    where
        H: ActionHandler + 'static,
    {
        let handlers =
            HashMap::from([(capability_id, Arc::new(handler) as Arc<dyn ActionHandler>)]);
        Gateway::with_policy_runtime_callback_and_handlers(
            manifest.clone(),
            GatewayPolicy {
                require_signed_envelopes: false,
                allow_unverified_payload_identity: true,
                ..GatewayPolicy::default()
            },
            Runtime::new(),
            GatewayCallbackDispatcher::default(),
            handlers,
        )
        .await
        .expect("atomically admitted gateway")
        .with_identity_resolver(Arc::new(StaticTrustedIdentityResolver::new([
            TrustedIdentityBinding {
                principal_id: PrincipalId::trusted("agent:mcp:test"),
                tenant: None,
                credential: None,
                identity: None,
                revision: 1,
                revoked: false,
                expires_at: None,
            },
        ])))
    }

    async fn gateway_with_echo(manifest: &Manifest) -> Gateway {
        gateway_with_handler(manifest, CapabilityId::trusted("cap:test:echo"), Echo).await
    }

    async fn initialize_session(
        server: &McpServer,
        session_id: &str,
    ) -> aip_profile_mcp::JsonRpcResponse {
        let response = server
            .handle_request(
                session_id,
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(1),
                    aip_profile_mcp::McpMethod::Initialize,
                    Some(json!({
                        "protocolVersion": "2025-11-25",
                        "capabilities": {
                            "roots": { "listChanged": true },
                            "sampling": {},
                            "elicitation": {},
                            "tasks": {}
                        },
                        "clientInfo": { "name": "test", "version": "0.0.0" }
                    })),
                ),
            )
            .await;
        assert!(response.error.is_none(), "initialize failed: {response:?}");
        server
            .handle_notification(
                session_id,
                aip_profile_mcp::JsonRpcNotification::new(
                    aip_profile_mcp::McpMethod::Initialized,
                    None,
                ),
            )
            .await
            .expect("initialized notification");
        response
    }

    #[tokio::test]
    async fn mcp_server_initializes_and_calls_tool() {
        let manifest = manifest();
        let gateway = gateway_with_echo(&manifest).await;
        let server = McpServer::new(
            McpServerConfig::new(manifest, gateway)
                .with_mcp_principal(principal_with_scopes(&["action:write"])),
        );
        let init = initialize_session(&server, "test").await;
        assert_eq!(init.result.expect("init")["protocolVersion"], "2025-11-25");

        let response = server
            .handle_request(
                "test",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(2),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": "echo",
                        "arguments": { "x": 1 }
                    })),
                ),
            )
            .await;
        assert_eq!(
            response.result.expect("result")["content"][0]["text"],
            "done"
        );
    }

    #[tokio::test]
    async fn cancelled_notification_reaches_the_exact_in_flight_action() {
        let manifest = manifest();
        let handler = CancellableHandler::default();
        let started = handler.started.clone();
        let gateway =
            gateway_with_handler(&manifest, CapabilityId::trusted("cap:test:echo"), handler).await;
        let server = McpServer::new(
            McpServerConfig::new(manifest, gateway)
                .with_mcp_principal(principal_with_scopes(&["action:write"])),
        );
        initialize_session(&server, "cancel-session").await;

        let request_started = started.notified();
        let call = {
            let server = server.clone();
            tokio::spawn(async move {
                server
                    .handle_request(
                        "cancel-session",
                        aip_profile_mcp::JsonRpcRequest::new(
                            json!(7),
                            aip_profile_mcp::McpMethod::ToolsCall,
                            Some(json!({
                                "name": "echo",
                                "arguments": { "slow": true }
                            })),
                        ),
                    )
                    .await
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), request_started)
            .await
            .expect("action start");
        server
            .handle_notification(
                "cancel-session",
                aip_profile_mcp::JsonRpcNotification::new(
                    aip_profile_mcp::McpMethod::Cancelled,
                    Some(json!({
                        "requestId": 7,
                        "reason": "client disconnected"
                    })),
                ),
            )
            .await
            .expect("cancel notification");
        let response = call.await.expect("tool call task");
        assert!(response.error.is_none(), "{response:?}");
        assert_eq!(
            response
                .result
                .as_ref()
                .and_then(|result| result.pointer("/structuredContent/cancelled")),
            Some(&json!(true))
        );
        assert!(
            server
                .session_snapshot("cancel-session")
                .await
                .expect("session snapshot")
                .action_by_request_id
                .is_empty(),
            "terminal requests must release request/action correlation state"
        );
    }

    #[tokio::test]
    async fn stable_aip_call_correlates_exact_request_cancellation() {
        let manifest = manifest();
        let handler = CancellableHandler::default();
        let started = handler.started.clone();
        let gateway =
            gateway_with_handler(&manifest, CapabilityId::trusted("cap:test:echo"), handler).await;
        let server = McpServer::new(
            McpServerConfig::new(manifest, gateway)
                .with_mcp_principal(principal_with_scopes(&["action:write"])),
        );
        initialize_session(&server, "stable-cancel-session").await;

        let request_started = started.notified();
        let call = {
            let server = server.clone();
            tokio::spawn(async move {
                server
                    .handle_request(
                        "stable-cancel-session",
                        aip_profile_mcp::JsonRpcRequest::new(
                            json!(8),
                            aip_profile_mcp::McpMethod::ToolsCall,
                            Some(json!({
                                "name": AIP_CALL_TOOL,
                                "arguments": {
                                    "capability_id": "cap:test:echo",
                                    "input": { "slow": true }
                                }
                            })),
                        ),
                    )
                    .await
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), request_started)
            .await
            .expect("stable facade action start");
        server
            .handle_notification(
                "stable-cancel-session",
                aip_profile_mcp::JsonRpcNotification::new(
                    aip_profile_mcp::McpMethod::Cancelled,
                    Some(json!({
                        "requestId": 8,
                        "reason": "client disconnected"
                    })),
                ),
            )
            .await
            .expect("stable facade cancel notification");

        let response = call.await.expect("stable facade tool call task");
        assert!(response.error.is_none(), "{response:?}");
        assert_eq!(
            response
                .result
                .as_ref()
                .and_then(|result| result.pointer("/structuredContent/cancelled")),
            Some(&json!(true))
        );
        assert!(
            server
                .session_snapshot("stable-cancel-session")
                .await
                .expect("stable facade session snapshot")
                .action_by_request_id
                .is_empty(),
            "terminal stable facade requests must release correlation state"
        );
    }

    #[tokio::test]
    async fn mcp_server_lists_stable_facade_tools() {
        let manifest = manifest();
        let gateway = gateway_with_echo(&manifest).await;
        let server = McpServer::new(McpServerConfig::new(manifest, gateway));
        initialize_session(&server, "test").await;
        let response = server
            .handle_request(
                "test",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(1),
                    aip_profile_mcp::McpMethod::ToolsList,
                    Some(json!({})),
                ),
            )
            .await;
        let result = response.result.expect("tools list");
        let approval_get = result["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .find(|tool| tool.get("name") == Some(&json!(AIP_APPROVAL_GET_TOOL)))
            .expect("approval get tool");
        assert_eq!(
            approval_get.pointer("/inputSchema/properties/include_evidence_payload/description"),
            Some(&json!(
                "Exports sensitive immutable action evidence; requires approval:export and approval:sensitive."
            ))
        );
        let approval_decide = result["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .find(|tool| tool.get("name") == Some(&json!(AIP_APPROVAL_DECIDE_TOOL)))
            .expect("approval decide tool");
        assert_eq!(
            approval_decide.pointer("/inputSchema/properties/policy_hash/type"),
            Some(&json!("string"))
        );
        assert_eq!(
            approval_decide.pointer("/inputSchema/properties/decision_id/type"),
            Some(&json!("string"))
        );
        assert_eq!(
            approval_decide.pointer("/inputSchema/properties/target_decision_id/type"),
            Some(&json!("string"))
        );
        let names = result["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .filter_map(|tool| tool.get("name").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>();
        assert!(names.contains(&AIP_CAPABILITIES_TOOL));
        assert!(names.contains(&AIP_CALL_TOOL));
        assert!(names.contains(&AIP_EVENTS_TOOL));
        assert!(names.contains(&AIP_ACTION_STATUS_TOOL));
        assert!(names.contains(&AIP_ACTION_RESULT_TOOL));
        assert!(names.contains(&AIP_ACTION_LIST_TOOL));
        assert!(names.contains(&AIP_ACTION_EVENTS_TOOL));
        assert!(names.contains(&AIP_ACTION_CANCEL_TOOL));
        assert!(names.contains(&AIP_SESSION_GET_TOOL));
        assert!(names.contains(&AIP_SESSION_LIST_TOOL));
        assert!(names.contains(&AIP_SESSION_CLOSE_TOOL));
        assert!(names.contains(&AIP_SESSION_RESUME_TOOL));
        assert!(names.contains(&AIP_APPROVAL_GET_TOOL));
        assert!(names.contains(&AIP_APPROVAL_LIST_TOOL));
        assert!(names.contains(&AIP_APPROVAL_DECIDE_TOOL));
        assert!(names.contains(&AIP_CALLBACK_DELIVERY_GET_TOOL));
        assert!(names.contains(&AIP_CALLBACK_DELIVERY_LIST_TOOL));
        assert!(names.contains(&AIP_TRANSACTION_GET_TOOL));
        assert!(names.contains(&AIP_RECEIPT_GET_TOOL));
        assert!(names.contains(&AIP_AUDIT_EVENTS_TOOL));
        assert!(names.contains(&AIP_RESOURCE_LIST_TOOL));
        assert!(names.contains(&AIP_RESOURCE_READ_TOOL));
        assert!(names.contains(&AIP_SCENARIO_RUN_TOOL));
        assert!(names.contains(&"test_echo"));
    }

    #[tokio::test]
    async fn server_advertises_only_versioned_and_implemented_capabilities() {
        let manifest = manifest();
        let gateway = gateway_with_echo(&manifest).await;
        let server = McpServer::new(McpServerConfig::new(manifest.clone(), gateway));
        let legacy = server.server_capabilities_for("2024-11-05");
        assert!(legacy.tools.is_some());
        assert!(!legacy.tools.expect("tools").list_changed);
        assert!(legacy.resources.is_none());
        assert!(legacy.prompts.is_none());
        assert!(legacy.completions.is_none());
        assert!(legacy.tasks.is_none());

        let gateway = gateway_with_echo(&manifest).await;
        let server = McpServer::new(
            McpServerConfig::new(manifest, gateway).with_dynamic_notifications(true),
        );
        let current = server.server_capabilities_for("2025-11-25");
        assert!(current.tools.expect("tools").list_changed);
        assert!(current.tasks.is_some());
        assert!(current.resources.is_none());
        assert!(current.prompts.is_none());
        assert!(current.completions.is_none());
    }

    #[tokio::test]
    async fn resource_subscriptions_are_session_owned_ref_counted_and_restorable() {
        let manifest = manifest();
        let gateway = gateway_with_echo(&manifest).await;
        let provider = SubscriptionResourceProvider::default();
        let server = McpServer::new(
            McpServerConfig::new(manifest, gateway).with_resource_provider(provider.clone()),
        );
        initialize_session(&server, "subscriber-a").await;
        initialize_session(&server, "subscriber-b").await;
        let uri = "aip://resource/customer-42";

        for (request_id, session_id) in [(2, "subscriber-a"), (3, "subscriber-b")] {
            let response = server
                .handle_request(
                    session_id,
                    aip_profile_mcp::JsonRpcRequest::new(
                        json!(request_id),
                        aip_profile_mcp::McpMethod::ResourcesSubscribe,
                        Some(json!({ "uri": uri })),
                    ),
                )
                .await;
            assert!(response.error.is_none(), "subscribe failed: {response:?}");
        }
        assert_eq!(provider.subscribe_calls.load(Ordering::SeqCst), 1);
        assert!(
            server
                .session_has_resource_subscription("subscriber-a", uri)
                .await
        );
        let snapshot = server
            .session_snapshot("subscriber-a")
            .await
            .expect("subscription snapshot");
        assert!(snapshot.resource_subscriptions.contains(uri));

        server
            .delete_session("subscriber-a")
            .await
            .expect("delete first subscriber");
        assert_eq!(provider.unsubscribe_calls.load(Ordering::SeqCst), 0);
        server
            .delete_session("subscriber-b")
            .await
            .expect("delete final subscriber");
        assert_eq!(provider.unsubscribe_calls.load(Ordering::SeqCst), 1);

        server
            .restore_session(snapshot)
            .await
            .expect("restore subscription snapshot");
        assert_eq!(provider.subscribe_calls.load(Ordering::SeqCst), 2);
        assert!(
            server
                .session_has_resource_subscription("subscriber-a", uri)
                .await
        );
        server
            .delete_session("subscriber-a")
            .await
            .expect("delete restored subscriber");
        assert_eq!(provider.unsubscribe_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn stable_approval_decide_accepts_uri_string_evidence() {
        let evidence = evidence_from_arguments(&json!({
            "evidence": [
                "support-sandbox://refund/rf:test",
                {
                    "id": "evidence:product-approval",
                    "kind": "product_approval",
                    "uri": "support-sandbox://approval/appr:test",
                    "redacted": false
                }
            ],
            "external_ticket_uri": "support-sandbox://case/case_1001"
        }))
        .expect("evidence");

        assert_eq!(evidence.len(), 3);
        assert_eq!(evidence[0].kind, "uri");
        assert_eq!(
            evidence[0].uri.as_deref(),
            Some("support-sandbox://refund/rf:test")
        );
        assert_eq!(evidence[1].kind, "product_approval");
        assert_eq!(evidence[2].kind, "external_ticket");
    }

    #[tokio::test]
    async fn mcp_server_stable_aip_call_uses_gateway_runtime() {
        let manifest = manifest();
        let gateway = gateway_with_echo(&manifest).await;
        let server = McpServer::new(
            McpServerConfig::new(manifest, gateway)
                .with_mcp_principal(principal_with_scopes(&["action:read"])),
        );
        initialize_session(&server, "test").await;
        let response = server
            .handle_request(
                "test",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(1),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": AIP_CALL_TOOL,
                        "arguments": {
                            "capability_id": "cap:test:echo",
                            "input": { "x": 1 },
                            "idempotency_key": "stable-call-test"
                        }
                    })),
                ),
            )
            .await;
        let result = response.result.expect("result");
        assert_eq!(
            result.pointer("/structuredContent/echo/x"),
            Some(&serde_json::Value::Number(1.into()))
        );
    }

    #[tokio::test]
    async fn mcp_server_stable_action_status_uses_native_read_model() {
        let manifest = manifest();
        let gateway = gateway_with_echo(&manifest).await;
        let server = McpServer::new(
            McpServerConfig::new(manifest, gateway)
                .with_mcp_principal(principal_with_scopes(&["action:read"])),
        );
        initialize_session(&server, "test").await;
        let action_id = ActionId::new();
        let action_id_string = action_id.to_string();
        let call_request = aip_profile_mcp::JsonRpcRequest::new(
            json!(1),
            aip_profile_mcp::McpMethod::ToolsCall,
            Some(json!({
                "name": AIP_CALL_TOOL,
                "arguments": {
                    "action_id": action_id_string,
                    "capability_id": "cap:test:echo",
                    "input": { "x": 1 }
                }
            })),
        );
        let call = server.handle_request("test", call_request).await;
        assert!(call.error.is_none());

        let status = server
            .handle_request(
                "test",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(2),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": AIP_ACTION_STATUS_TOOL,
                        "arguments": {
                            "action_id": action_id.to_string(),
                            "include_result": true
                        }
                    })),
                ),
            )
            .await;
        let result = status.result.expect("status result");
        assert_eq!(
            result.pointer("/structuredContent/body/action_status/state"),
            Some(&serde_json::Value::String("completed".to_owned()))
        );
        assert_eq!(
            result.pointer("/structuredContent/body/action_status/result/output/echo/x"),
            Some(&serde_json::Value::Number(1.into()))
        );
    }

    #[tokio::test]
    async fn mcp_tasks_get_and_result_project_from_native_read_model() {
        let manifest = manifest();
        let gateway = gateway_with_echo(&manifest).await;
        let server = McpServer::new(
            McpServerConfig::new(manifest, gateway)
                .with_mcp_principal(principal_with_scopes(&["action:read"])),
        );
        initialize_session(&server, "producer-session").await;
        initialize_session(&server, "consumer-session").await;
        let action_id = ActionId::new();
        let action_id_string = action_id.to_string();
        let call = server
            .handle_request(
                "producer-session",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(1),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": AIP_CALL_TOOL,
                        "arguments": {
                            "action_id": action_id_string,
                            "capability_id": "cap:test:echo",
                            "input": { "x": 7 }
                        }
                    })),
                ),
            )
            .await;
        assert!(call.error.is_none());

        let task = server
            .handle_request(
                "consumer-session",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(2),
                    aip_profile_mcp::McpMethod::TasksGet,
                    Some(json!({ "taskId": action_id.to_string() })),
                ),
            )
            .await;
        let task_result = task.result.expect("task result");
        assert_eq!(
            task_result.pointer("/status"),
            Some(&serde_json::Value::String("completed".to_owned()))
        );
        assert_eq!(
            task_result.pointer("/taskId"),
            Some(&serde_json::Value::String(action_id.to_string()))
        );

        let result = server
            .handle_request(
                "consumer-session",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(3),
                    aip_profile_mcp::McpMethod::TasksResult,
                    Some(json!({ "taskId": action_id.to_string() })),
                ),
            )
            .await;
        assert_eq!(
            result
                .result
                .expect("terminal result")
                .pointer("/structuredContent/echo/x"),
            Some(&serde_json::Value::Number(7.into()))
        );
    }

    #[tokio::test]
    async fn mcp_server_stable_capabilities_lists_live_manifest() {
        let manifest = manifest();
        let gateway = gateway_with_echo(&manifest).await;
        let server = McpServer::new(McpServerConfig::new(manifest, gateway));
        initialize_session(&server, "test").await;
        let response = server
            .handle_request(
                "test",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(1),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": AIP_CAPABILITIES_TOOL,
                        "arguments": {
                            "capability_id": "cap:test:echo",
                            "include_schemas": false
                        }
                    })),
                ),
            )
            .await;
        let result = response.result.expect("result");
        assert_eq!(
            result.pointer("/structuredContent/capabilities/0/id"),
            Some(&serde_json::Value::String("cap:test:echo".to_owned()))
        );
        assert!(
            result
                .pointer("/structuredContent/capabilities/0/input_schema")
                .is_none()
        );
    }

    #[tokio::test]
    async fn stable_capabilities_pages_tenant_fleet_without_expanding_tools_list() {
        let manifest = manifest();
        let gateway = gateway_with_echo(&manifest).await;
        let mut remote_capability = manifest.capabilities[0].clone();
        remote_capability.id = CapabilityId::trusted("cap:test:fleet-remote");
        remote_capability.name = "fleet remote".to_owned();
        let actor = Principal::new(
            PrincipalId::trusted("agent:mcp:fleet-client"),
            PrincipalKind::Agent,
        );
        let server = McpServer::new(
            McpServerConfig::new(manifest, gateway)
                .with_mcp_principal(actor.clone())
                .with_capability_catalog(TestFleetCatalog {
                    tenant_id: "tenant-acme".to_owned(),
                    definition: CapabilityDefinition {
                        capability: remote_capability,
                        contract_digest: format!("sha256:{}", "1".repeat(64)),
                        schema_digest: format!("sha256:{}", "2".repeat(64)),
                    },
                }),
        );
        let authenticated = AuthenticatedPrincipal {
            principal: actor,
            scheme: AuthScheme::DidProof,
            issuer: "mcp-fleet-test".to_owned(),
            audience: Some("aip".to_owned()),
            scopes: BTreeSet::from(["*".to_owned()]),
            authenticated_at: OffsetDateTime::now_utc(),
            expires_at: None,
            credential_fingerprint: None,
        };
        server
            .bind_session_identity(
                "fleet-acme",
                McpTransportKind::Stdio,
                authenticated.clone(),
                Some(VerifiedTenant {
                    tenant: TenantRef {
                        id: "tenant-acme".to_owned(),
                        system: Some("mcp-test".to_owned()),
                    },
                    membership_id: "membership-acme".to_owned(),
                    roles: BTreeSet::new(),
                    groups: BTreeSet::new(),
                    verified_at: OffsetDateTime::now_utc(),
                    expires_at: None,
                }),
            )
            .await
            .expect("bind tenant session");
        initialize_session(&server, "fleet-acme").await;

        let first = server
            .handle_request(
                "fleet-acme",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(11),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": AIP_CAPABILITIES_TOOL,
                        "arguments": { "limit": 1 }
                    })),
                ),
            )
            .await
            .result
            .expect("first capability page");
        assert_eq!(first.pointer("/structuredContent/total"), Some(&json!(2)));
        assert_eq!(
            first.pointer("/structuredContent/next_cursor"),
            Some(&json!("remote:"))
        );
        let second = server
            .handle_request(
                "fleet-acme",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(12),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": AIP_CAPABILITIES_TOOL,
                        "arguments": { "limit": 1, "cursor": "remote:" }
                    })),
                ),
            )
            .await
            .result
            .expect("remote capability page");
        assert_eq!(
            second.pointer("/structuredContent/capabilities/0/id"),
            Some(&json!("cap:test:fleet-remote"))
        );

        server
            .bind_session_identity(
                "fleet-other",
                McpTransportKind::Stdio,
                authenticated,
                Some(VerifiedTenant {
                    tenant: TenantRef {
                        id: "tenant-other".to_owned(),
                        system: Some("mcp-test".to_owned()),
                    },
                    membership_id: "membership-other".to_owned(),
                    roles: BTreeSet::new(),
                    groups: BTreeSet::new(),
                    verified_at: OffsetDateTime::now_utc(),
                    expires_at: None,
                }),
            )
            .await
            .expect("bind other tenant session");
        initialize_session(&server, "fleet-other").await;
        let other = server
            .handle_request(
                "fleet-other",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(13),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": AIP_CAPABILITIES_TOOL,
                        "arguments": { "limit": 10 }
                    })),
                ),
            )
            .await
            .result
            .expect("other tenant capability page");
        assert_eq!(other.pointer("/structuredContent/total"), Some(&json!(1)));
    }

    #[tokio::test]
    async fn mcp_server_stable_scenario_run_dispatches_real_steps() {
        let manifest = manifest();
        let gateway = gateway_with_echo(&manifest).await;
        let server = McpServer::new(McpServerConfig::new(manifest, gateway));
        initialize_session(&server, "test").await;
        let response = server
            .handle_request(
                "test",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(1),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": AIP_SCENARIO_RUN_TOOL,
                        "arguments": {
                            "scenario_id": "stable-facade-smoke",
                            "steps": [{
                                "name": "echo",
                                "capability_id": "cap:test:echo",
                                "input": { "x": 1 }
                            }]
                        }
                    })),
                ),
            )
            .await;
        let result = response.result.expect("result");
        assert_eq!(
            result.pointer("/structuredContent/status"),
            Some(&serde_json::Value::String("completed".to_owned()))
        );
        assert_eq!(
            result.pointer("/structuredContent/steps/0/output/echo/x"),
            Some(&serde_json::Value::Number(1.into()))
        );
    }

    #[tokio::test]
    async fn mcp_server_returns_output_schema_violation_as_tool_error() {
        let manifest = manifest_with_output_schema(
            "bad",
            CapabilityId::trusted("cap:test:bad"),
            json!({
                "type": "object",
                "required": ["ok"],
                "properties": { "ok": { "type": "boolean" } },
                "additionalProperties": false
            }),
        );
        let gateway =
            gateway_with_handler(&manifest, CapabilityId::trusted("cap:test:bad"), BadOutput).await;
        let server = McpServer::new(McpServerConfig::new(manifest, gateway));
        initialize_session(&server, "test").await;
        let response = server
            .handle_request(
                "test",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(1),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": "bad",
                        "arguments": {}
                    })),
                ),
            )
            .await;
        assert!(
            response.error.is_none(),
            "capability execution failures must remain MCP tool results"
        );
        let result = response.result.expect("schema violation tool result");
        assert_eq!(result.get("isError").and_then(Value::as_bool), Some(true));
        assert!(result.get("structuredContent").is_none());
    }

    #[tokio::test]
    async fn mcp_server_does_not_apply_success_output_schema_to_failed_result() {
        let capability_id = CapabilityId::trusted("cap:test:failed");
        let manifest = manifest_with_output_schema(
            "failed",
            capability_id.clone(),
            json!({
                "type": "object",
                "required": ["ok"],
                "properties": { "ok": { "type": "boolean" } },
                "additionalProperties": false
            }),
        );
        let gateway = gateway_with_handler(&manifest, capability_id, FailedWithoutOutput).await;
        let server = McpServer::new(McpServerConfig::new(manifest, gateway));
        initialize_session(&server, "failed-output").await;

        let response = server
            .handle_request(
                "failed-output",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(1),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": "failed",
                        "arguments": {}
                    })),
                ),
            )
            .await;

        assert!(
            response.error.is_none(),
            "failed result must remain a tool result"
        );
        let result = response.result.expect("failed tool result");
        assert_eq!(result.get("isError").and_then(Value::as_bool), Some(true));
        assert!(result.get("structuredContent").is_none());
    }

    #[tokio::test]
    async fn mcp_server_preserves_pending_approval_outside_success_output_schema() {
        let capability_id = CapabilityId::trusted("cap:test:approval");
        let mut manifest = manifest_with_output_schema(
            "approval",
            capability_id.clone(),
            json!({
                "type": "object",
                "required": ["ok"],
                "properties": { "ok": { "type": "boolean" } },
                "additionalProperties": false
            }),
        );
        manifest.capabilities[0].requires_human_approval = Some(true);
        let gateway = gateway_with_handler(&manifest, capability_id, Echo).await;
        let server = McpServer::new(McpServerConfig::new(manifest, gateway));
        initialize_session(&server, "pending-approval").await;

        let response = server
            .handle_request(
                "pending-approval",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(1),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": "approval",
                        "arguments": {}
                    })),
                ),
            )
            .await;

        assert!(
            response.error.is_none(),
            "input-required lifecycle state must remain an MCP tool result"
        );
        let result = response.result.expect("pending approval tool result");
        assert_eq!(result.get("isError").and_then(Value::as_bool), Some(true));
        assert!(
            result
                .pointer("/structuredContent/approval_id")
                .and_then(Value::as_str)
                .is_some()
        );
    }

    #[tokio::test]
    async fn privileged_facades_use_only_the_transport_bound_identity() {
        let manifest = manifest();
        let gateway = gateway_with_echo(&manifest).await;
        let server = McpServer::new(McpServerConfig::new(manifest, gateway));

        initialize_session(&server, "unscoped").await;
        let denied = server
            .handle_request(
                "unscoped",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(1),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": AIP_APPROVAL_DECIDE_TOOL,
                        "arguments": {
                            "approval_id": aip_core::ApprovalId::new().to_string(),
                            "decision": "approved",
                            "approver_principal": "agent:payload-forgery"
                        }
                    })),
                ),
            )
            .await;
        assert!(
            denied
                .error
                .expect("missing scope must be rejected")
                .message
                .contains("approval:decide")
        );

        let actor = principal_with_scopes(&["approval:decide", "delegation:create"]);
        server
            .bind_session_identity(
                "verified",
                aip_mcp_session::McpTransportKind::Stdio,
                aip_auth::AuthenticatedPrincipal {
                    principal: actor.clone(),
                    scheme: aip_auth::AuthScheme::DidProof,
                    issuer: "test-transport".to_owned(),
                    audience: Some("aip".to_owned()),
                    scopes: ["approval:decide".to_owned(), "delegation:create".to_owned()]
                        .into_iter()
                        .collect(),
                    authenticated_at: time::OffsetDateTime::now_utc(),
                    expires_at: None,
                    credential_fingerprint: None,
                },
                None,
            )
            .await
            .expect("bind verified identity");
        initialize_session(&server, "verified").await;
        let forged = server
            .handle_request(
                "verified",
                aip_profile_mcp::JsonRpcRequest::new(
                    json!(2),
                    aip_profile_mcp::McpMethod::ToolsCall,
                    Some(json!({
                        "name": AIP_APPROVAL_DECIDE_TOOL,
                        "arguments": {
                            "approval_id": aip_core::ApprovalId::new().to_string(),
                            "decision": "approved",
                            "approver_principal": "agent:payload-forgery"
                        }
                    })),
                ),
            )
            .await;
        assert!(
            forged
                .error
                .expect("payload approver must be rejected")
                .message
                .contains("must match the principal authenticated by the MCP transport")
        );
    }

    fn manifest() -> Manifest {
        manifest_with_output_schema(
            "echo",
            CapabilityId::trusted("cap:test:echo"),
            json!({
                "type": "object",
                "required": ["echo"],
                "properties": { "echo": { "type": "object" } }
            }),
        )
    }

    fn principal_with_scopes(scopes: &[&str]) -> Principal {
        let mut principal =
            Principal::new(PrincipalId::trusted("agent:mcp:test"), PrincipalKind::Agent);
        principal.auth_context = Some(json!({ "scopes": scopes }));
        principal
    }

    fn manifest_with_output_schema(
        name: &str,
        capability_id: CapabilityId,
        output_schema: serde_json::Value,
    ) -> Manifest {
        Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(PrincipalId::trusted("agent:test"), PrincipalKind::Agent),
            capabilities: vec![Capability {
                id: capability_id,
                name: name.to_owned(),
                kind: CapabilityKind::Tool,
                input_schema: json!({"type": "object"}),
                output_schema: Some(output_schema),
                description: None,
                risk: None,
                stability: None,
                cost: None,
                auth: None,
                bindings: Vec::new(),
                requires_human_approval: None,
                contract: None,
            }],
            profiles: vec![ProfileId::from(aip_profile_mcp::PROFILE_ID)],
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
