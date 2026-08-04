//! HTTP daemon for the Agent Interoperability Protocol gateway.
//!
//! `getaip-server` is intentionally thin: protocol semantics live in `aip-core`,
//! runtime behavior lives in `aip-runtime`, and routing lives in `aip-gateway`.
//! This crate owns process configuration, HTTP listener wiring, health checks,
//! and the minimal built-in capability needed to verify a standalone AIP
//! deployment.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

pub mod cli;
pub mod module;

pub use module::{
    DaemonHttpMount, DaemonHttpRoute, DaemonModuleError, DaemonModuleFactory, DaemonServices,
    LocalModuleDescriptor, LocalModuleId, PreparedDaemonModule,
};

use aip_auth::{
    ApprovalAuthorityResolver, AuthScheme, AuthenticatedPrincipal, BearerToken,
    DenyAllApprovalAuthorityResolver, DenyAllTrustedIdentityResolver, TokenVerificationRequest,
    TokenVerifier, TrustedIdentityResolver, VerifiedTenant,
};
use aip_connector_registry::{
    ActionTargetResolver, CapabilityCatalogProvider, CapabilityCatalogQuery, CatalogReadContext,
    ConnectorFleetStatusProvider, ConnectorRegistryReader, FleetStatusSummary,
};
use aip_connector_remote::{
    ConnectorEventIngress, ConnectorEventIngressLimits, FairAdmissionScheduler,
};
use aip_core::{
    Action, ActionEventsRequest, ActionId, ActionLifecycleState, ActionListRequest, ActionResult,
    ActionResultRequest, ActionResultStatus, ActionStatus, ActionStatusRequest, ApprovalId,
    ApprovalListRequest, ApprovalQueryRequest, AuditQueryRequest, Binding, Callback,
    CallbackDeliveryListRequest, CallbackDeliveryQueryRequest, CallbackDeliveryStatus, Cancel,
    CancelTarget, Capability, CapabilityContract, CapabilityId, CapabilityKind,
    CompensationContract, CompensationMode, DataContract, DataSensitivity, Envelope, ErrorBody,
    ErrorCategory, Event, EventStreamRequest, ExecutionContract, ExpectedCompletionMode,
    IdempotencyCollisionBehavior, IdempotencyContract, IdempotencyKeyScope, IdempotencyRequirement,
    Manifest, ManifestFilter, MessageBody, MessagePart, MessageReference, Principal, PrincipalId,
    PrincipalKind, ProfileId, ProtocolError, ReceiptQueryRequest, ResourceListRequest,
    ResourceReadRequest, RetrySafety, RiskLevel, ServiceLevelContract, SessionCloseRequest,
    SessionId, SessionListRequest, SessionRequest, SessionResumeRequest, SessionState, SideEffect,
    Stability, TransactionQueryRequest,
};
use aip_gateway::{
    A2aCallbackCredentials, DelegationRoute, DelegationRouteBinding,
    EncryptedA2aCallbackCredentials, Gateway, GatewayCallbackDispatcher, GatewayCallbackPolicy,
    GatewayError, GatewayPolicy, sign_native_envelope,
};
use aip_mcp_server::{
    ClientRequestProvider, CompletionProvider, McpPeerTransport, McpServer, McpServerConfig,
    McpServerError, McpServerResult, McpServerSessionSnapshot, PromptProvider, ResourceProvider,
    progress_notification, resource_updated_notification, resources_changed_notification,
    tools_changed_notification,
};
use aip_mcp_session::{
    CorrelationDirection, FileMcpCorrelationStore, InMemoryMcpCorrelationStore,
    McpCorrelationRecord, McpCorrelationStore, McpDispatcher, McpDuplexTransport, McpFrame,
    McpLifecycle, McpSessionError, McpTransportKind,
};
use aip_profile_a2a::{A2aJsonRpcRequest, A2aJsonRpcResponse};
use aip_profile_mcp::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, McpMethod};
use aip_runtime::{
    ActionExecutionContext, ActionHandler, ProfileStateCasOutcome, ProfileStateStore,
    QueueWorkerConfig, Runtime, RuntimeError, RuntimeResult, RuntimeRetentionPolicy, RuntimeStores,
    RuntimeWorkBudgets,
};
use aip_schema::{SchemaName, SchemaRegistry};
use aip_storage_postgres::PostgresRuntimeStore;
use aip_transport::{TransportError, TransportMessage};
use aip_transport_http::status_for_error;
use aip_transport_mcp_legacy_http_sse::{
    LegacyHttpSseError, LegacySessionRegistry, LegacySseEvent,
};
use aip_transport_mcp_streamable_http::{
    BearerChallenge, McpHttpMessage, McpHttpRequest, McpHttpResponse, McpSseEvent,
    McpSseReplayBuffer, McpSseReplayFileLog, ProtectedResourceMetadata, bearer_token,
    bearer_unauthorized_response, classify_request, validate_origin,
};
use aip_transport_nats::{
    NatsAuthentication, NatsSubject, NatsTransport, NatsTransportConfig,
    PROFILE_ID as NATS_PROFILE_ID, service_wildcard_subject, transport_message_from_nats,
};
use aip_transport_websocket::{WebSocketFrame, decode_ws, encode_ws};
use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Extension, Path as AxumPath, Query, State,
        ws::{Message as AxumWsMessage, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event as AxumSseEvent, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures_util::{SinkExt, StreamExt};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    convert::Infallible,
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex, OnceLock},
    time::{Duration, Instant},
};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, Semaphore, broadcast, mpsc, watch};
use tracing::warn;
use url::{Host, Url};

/// Stable profile id for the native HTTP binding.
pub const NATIVE_HTTP_PROFILE: &str = "aip.native.http.v1";
const FLEET_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);
const FLEET_MAINTENANCE_MAX_BACKOFF: Duration = Duration::from_secs(30);
const FLEET_EXPIRY_BATCH_SIZE: usize = 500;
const FLEET_EXPIRY_MAX_BATCHES_PER_CYCLE: usize = 8;
const NATIVE_WS_OUTBOUND_CAPACITY: usize = 8;
const NATIVE_WS_MAX_SUBSCRIPTIONS: usize = 16;

/// Built-in health capability exposed by standalone `getaip-server`.
pub const HEALTH_CAPABILITY_ID: &str = "cap:aip:server:health";

/// Stable signed native AIP action for tenant-scoped fleet discovery.
pub const CAPABILITY_CATALOG_QUERY_ID: &str = "cap:aip:server:connector-capabilities-query";

/// Default NATS service subject segment for `getaip-server`.
pub const DEFAULT_NATS_SERVICE: &str = "getaip-server";

/// Default NATS service version segment for the native binding.
pub const DEFAULT_NATS_VERSION: &str = "v1";

const A2A_TASKS_NAMESPACE: &str = "aip.a2a.tasks.v1";
const A2A_PUSH_CONFIGS_NAMESPACE: &str = "aip.a2a.push-configs.v1";
const A2A_PUSH_CURSORS_NAMESPACE: &str = "aip.a2a.push-cursors.v1";
const MCP_HTTP_SESSIONS_NAMESPACE: &str = "aip.mcp.http-sessions.v1";
const MCP_NOTIFICATION_DELIVERIES_NAMESPACE: &str = "aip.mcp.notification-deliveries.v1";
const MCP_NOTIFICATION_CURSORS_NAMESPACE: &str = "aip.mcp.notification-cursors.v1";
const MCP_HTTP_SESSION_TTL_MS: i64 = 86_400_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DurableMcpHttpSession {
    owner: String,
    snapshot: McpServerSessionSnapshot,
    updated_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum McpNotificationDeliveryStatus {
    Pending,
    Leased,
    Delivered,
    DeadLettered,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct McpNotificationDelivery {
    event_id: String,
    session_id: String,
    method: String,
    status: McpNotificationDeliveryStatus,
    attempts: u32,
    lease_owner: Option<String>,
    lease_id: Option<String>,
    lease_expires_at: Option<OffsetDateTime>,
    next_attempt_at: OffsetDateTime,
    last_error: Option<String>,
    updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct StoredA2aPushConfig {
    config: aip_profile_a2a::A2aTaskPushConfig,
    credential_aad: String,
    encrypted_credentials: Option<EncryptedA2aCallbackCredentials>,
    owner: PrincipalId,
    created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct A2aPushCursor {
    task_id: String,
    config_id: String,
    last_state: Option<ActionLifecycleState>,
    last_chunk_sequence: Option<u64>,
    lease_owner: Option<String>,
    lease_expires_at: Option<OffsetDateTime>,
    fencing_token: u64,
}

impl A2aPushCursor {
    fn new(config: &StoredA2aPushConfig) -> Self {
        Self {
            task_id: config.config.task_id.clone(),
            config_id: config.config.id.clone(),
            last_state: None,
            last_chunk_sequence: None,
            lease_owner: None,
            lease_expires_at: None,
            fencing_token: 0,
        }
    }
}

const MCP_SSE_REPLAY_LIMIT: usize = 1_024;
static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
static PROMETHEUS_INIT_LOCK: StdMutex<()> = StdMutex::new(());

/// Runtime configuration for `getaip-server`.
#[derive(Clone, Debug, PartialEq)]
pub struct AipDaemonConfig {
    /// Socket address for the HTTP listener.
    pub bind: SocketAddr,
    /// Deployment-owned external origin advertised to A2A and discovery clients.
    pub public_base_url: Option<String>,
    /// Stable service principal id for the daemon.
    pub service_id: PrincipalId,
    /// Optional trust domain reported in the manifest principal.
    pub trust_domain: Option<String>,
    /// Require Ed25519 signatures on incoming envelopes.
    pub require_signed_envelopes: bool,
    /// Trusted DID-to-principal bindings accepted by the native AIP edge.
    pub trusted_signers: Vec<(String, Principal)>,
    /// Optional bearer-authenticated principal for ergonomic native HTTP routes.
    pub native_http_auth: Option<NativeHttpAuthConfig>,
    /// Explicitly permits unauthenticated loopback-only development traffic.
    pub allow_insecure_development: bool,
    /// Callback destination allowlist, network policy, and signer.
    pub callback_policy: GatewayCallbackPolicy,
    /// Optional durable runtime storage directory.
    pub storage_dir: Option<PathBuf>,
    /// Optional native NATS listener configuration.
    pub nats: Option<AipDaemonNatsConfig>,
    /// Remote peer routes used for first-class AIP delegation.
    pub delegation_routes: Vec<DelegationRoute>,
    /// Optional protected-resource policy for MCP Streamable HTTP endpoints.
    pub mcp_protected_resource: Option<McpProtectedResourceConfig>,
    /// Principal established by the MCP stdio or authenticated HTTP edge.
    pub mcp_principal: Principal,
}

impl Default for AipDaemonConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            public_base_url: None,
            service_id: PrincipalId::trusted("agent:getaip:server:local"),
            trust_domain: None,
            require_signed_envelopes: true,
            trusted_signers: Vec::new(),
            native_http_auth: None,
            allow_insecure_development: false,
            callback_policy: GatewayCallbackPolicy::default(),
            storage_dir: None,
            nats: None,
            delegation_routes: Vec::new(),
            mcp_protected_resource: None,
            mcp_principal: Principal::new(
                PrincipalId::trusted("service:getaip:server:mcp-edge"),
                PrincipalKind::Service,
            ),
        }
    }
}

/// Static bearer identity accepted by the native HTTP edge.
#[derive(Clone, PartialEq)]
pub struct NativeHttpAuthConfig {
    /// Secret bearer token compared in constant time.
    pub bearer_token: String,
    /// Server-owned principal injected after successful authentication.
    pub principal: Principal,
    /// Tenant bound to this static credential for tenant-scoped discovery.
    pub tenant_id: Option<String>,
}

impl fmt::Debug for NativeHttpAuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeHttpAuthConfig")
            .field("bearer_token", &"<redacted>")
            .field("principal", &self.principal)
            .field("tenant_id", &self.tenant_id)
            .finish()
    }
}

impl NativeHttpAuthConfig {
    /// Creates a native HTTP bearer identity.
    #[must_use]
    pub fn bearer(token: impl Into<String>, principal: Principal) -> Self {
        Self {
            bearer_token: token.into(),
            principal,
            tenant_id: None,
        }
    }

    /// Binds this static credential to one verified tenant boundary.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }
}

fn validate_daemon_security_config(config: &AipDaemonConfig) -> Result<(), GatewayError> {
    if config.allow_insecure_development && !config.bind.ip().is_loopback() {
        return Err(GatewayError::Runtime(RuntimeError::Authorization(
            "insecure development mode is restricted to a loopback listener".to_owned(),
        )));
    }
    if config
        .native_http_auth
        .as_ref()
        .is_some_and(|auth| auth.bearer_token.trim().is_empty())
    {
        return Err(GatewayError::Runtime(RuntimeError::Authorization(
            "native HTTP bearer token must not be empty".to_owned(),
        )));
    }
    if config.native_http_auth.as_ref().is_some_and(|auth| {
        auth.tenant_id
            .as_ref()
            .is_some_and(|tenant| tenant.trim().is_empty() || tenant.len() > 512)
    }) {
        return Err(GatewayError::Runtime(RuntimeError::Authorization(
            "native HTTP tenant id must contain 1 to 512 bytes".to_owned(),
        )));
    }
    match config.public_base_url.as_deref() {
        Some(public_base_url) => {
            validate_public_base_url(
                public_base_url,
                config.allow_insecure_development,
                config.bind,
            )?;
        }
        None if !config.bind.ip().is_loopback() && !config.allow_insecure_development => {
            return Err(GatewayError::Runtime(RuntimeError::Authorization(
                "a public HTTPS origin is required for a non-loopback listener".to_owned(),
            )));
        }
        None => {}
    }
    if !config.require_signed_envelopes
        && config.native_http_auth.is_none()
        && !config.allow_insecure_development
    {
        return Err(GatewayError::Runtime(RuntimeError::Authorization(
            "unsigned native envelopes require bearer authentication or explicit loopback-only insecure development mode"
                .to_owned(),
        )));
    }
    Ok(())
}

fn validate_public_base_url(
    value: &str,
    allow_insecure_development: bool,
    bind: SocketAddr,
) -> Result<Url, GatewayError> {
    let mut url = Url::parse(value).map_err(|error| {
        GatewayError::Runtime(RuntimeError::Authorization(format!(
            "public base URL is invalid: {error}"
        )))
    })?;
    if url.cannot_be_a_base()
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(GatewayError::Runtime(RuntimeError::Authorization(
            "public base URL must be an origin without credentials, path, query, or fragment"
                .to_owned(),
        )));
    }
    let secure = url.scheme() == "https";
    let public_host_is_loopback = match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    let loopback_development = url.scheme() == "http"
        && allow_insecure_development
        && bind.ip().is_loopback()
        && public_host_is_loopback;
    if !secure && !loopback_development {
        return Err(GatewayError::Runtime(RuntimeError::Authorization(
            "public base URL must use HTTPS outside explicit loopback development".to_owned(),
        )));
    }
    url.set_path("/");
    Ok(url)
}

fn initialize_prometheus() -> Result<PrometheusHandle, GatewayError> {
    if let Some(handle) = PROMETHEUS_HANDLE.get() {
        return Ok(handle.clone());
    }
    let _guard = PROMETHEUS_INIT_LOCK.lock().map_err(|_| {
        GatewayError::Runtime(RuntimeError::Handler(
            "Prometheus recorder initialization lock was poisoned".to_owned(),
        ))
    })?;
    if let Some(handle) = PROMETHEUS_HANDLE.get() {
        return Ok(handle.clone());
    }
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|error| {
            GatewayError::Runtime(RuntimeError::Handler(format!(
                "Prometheus recorder installation failed: {error}"
            )))
        })?;
    PROMETHEUS_HANDLE.set(handle.clone()).map_err(|_| {
        GatewayError::Runtime(RuntimeError::Handler(
            "Prometheus recorder initialization raced".to_owned(),
        ))
    })?;
    Ok(handle)
}

/// MCP Streamable HTTP protected-resource policy.
///
/// This policy intentionally lives at the daemon boundary. MCP stdio remains
/// governed by the spawning host, while HTTP MCP endpoints can either publish
/// OAuth protected-resource metadata only or also enforce a local bearer token
/// for standalone deployments.
#[derive(Clone, PartialEq, Eq)]
pub struct McpProtectedResourceConfig {
    /// Public OAuth protected-resource metadata.
    pub metadata: ProtectedResourceMetadata,
    /// Optional local bearer token enforced by `getaip-server`.
    pub bearer_token: Option<String>,
    /// Optional realm rendered in `WWW-Authenticate`.
    pub realm: Option<String>,
    /// Optional required scope rendered in `WWW-Authenticate`.
    pub required_scope: Option<String>,
    /// Metadata URL rendered in `WWW-Authenticate`.
    pub metadata_url: Option<String>,
    /// Browser origins permitted to call the MCP HTTP endpoint.
    pub allowed_origins: Vec<String>,
    /// Permit loopback origins in addition to the explicit allowlist.
    pub allow_loopback_origins: bool,
}

impl fmt::Debug for McpProtectedResourceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpProtectedResourceConfig")
            .field("metadata", &self.metadata)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .field("realm", &self.realm)
            .field("required_scope", &self.required_scope)
            .field("metadata_url", &self.metadata_url)
            .field("allowed_origins", &self.allowed_origins)
            .field("allow_loopback_origins", &self.allow_loopback_origins)
            .finish()
    }
}

impl McpProtectedResourceConfig {
    /// Creates a policy that publishes bearer protected-resource metadata and
    /// enforces the supplied local token on MCP HTTP operations.
    #[must_use]
    pub fn bearer(resource: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            metadata: ProtectedResourceMetadata::bearer(resource),
            bearer_token: Some(token.into()),
            realm: Some("aip.server.mcp".to_owned()),
            required_scope: None,
            metadata_url: Some("/.well-known/oauth-protected-resource".to_owned()),
            allowed_origins: Vec::new(),
            allow_loopback_origins: true,
        }
    }

    fn challenge(&self, error: Option<&str>, description: Option<String>) -> BearerChallenge {
        BearerChallenge {
            realm: self.realm.clone(),
            resource_metadata_url: self.metadata_url.clone(),
            scope: self.required_scope.clone(),
            error: error.map(ToOwned::to_owned),
            error_description: description,
        }
    }
}

/// Native NATS listener configuration for `getaip-server`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AipDaemonNatsConfig {
    /// NATS server URL.
    pub server_url: String,
    /// Runtime-only NATS authentication.
    pub authentication: Option<NatsAuthentication>,
    /// Trust-domain subject segment.
    pub trust_domain: String,
    /// Service subject segment.
    pub service: String,
    /// Service version subject segment.
    pub version: String,
    /// Optional NATS queue group for horizontally scaled daemon instances.
    pub queue_group: Option<String>,
    /// Request timeout in milliseconds for outbound request/reply operations.
    pub request_timeout_ms: u64,
}

impl AipDaemonNatsConfig {
    /// Creates a NATS listener config using canonical AIP daemon defaults.
    #[must_use]
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            authentication: None,
            trust_domain: "local".to_owned(),
            service: DEFAULT_NATS_SERVICE.to_owned(),
            version: DEFAULT_NATS_VERSION.to_owned(),
            queue_group: None,
            request_timeout_ms: 30_000,
        }
    }

    /// Returns the daemon subscription subject.
    #[must_use]
    pub fn subscription_subject(&self) -> String {
        service_wildcard_subject(&self.trust_domain, &self.service, &self.version)
    }

    fn transport_config(&self) -> NatsTransportConfig {
        let mut config = NatsTransportConfig::new(
            self.server_url.clone(),
            NatsSubject {
                trust_domain: self.trust_domain.clone(),
                service: self.service.clone(),
                version: self.version.clone(),
                message_type: aip_core::MessageType::ManifestRequest,
            },
        );
        config.authentication = self.authentication.clone();
        config.queue_group.clone_from(&self.queue_group);
        config.request_timeout_ms = self.request_timeout_ms;
        config
    }
}

/// Long-running AIP daemon.
#[derive(Clone)]
pub struct AipDaemon {
    gateway: Gateway,
    manifest: Manifest,
    mcp_server: McpServer,
    started_at: Instant,
    nats: Option<AipDaemonNatsConfig>,
    native_http_auth: Option<NativeHttpAuthConfig>,
    allow_insecure_development: bool,
    callback_policy: GatewayCallbackPolicy,
    mcp_protected_resource: Option<McpProtectedResourceConfig>,
    mcp_sse_replay: SharedMcpSseReplay,
    mcp_http_session_owners: Arc<RwLock<BTreeMap<String, String>>>,
    mcp_legacy_sessions: LegacySessionRegistry,
    mcp_peer_transport: DaemonMcpPeerTransport,
    mcp_token_verifier: Option<Arc<dyn TokenVerifier>>,
    mcp_principal: Principal,
    profile_state: ProfileStateStore,
    a2a_interface_url: String,
    supervisor: DaemonSupervisorState,
    prometheus: PrometheusHandle,
    module_http_mounts: Vec<DaemonHttpMount>,
    module_statuses: BTreeMap<String, LocalModuleStatus>,
    fleet_status_provider: Option<Arc<dyn ConnectorFleetStatusProvider>>,
    fleet_supervisor: Option<DaemonFleetSupervisorState>,
    remote_admission: Option<FairAdmissionScheduler>,
    connector_event_ingress: Option<ConnectorEventIngress>,
    capability_catalog: Option<Arc<dyn CapabilityCatalogProvider>>,
    capability_discovery_url: String,
}

#[derive(Clone, Debug, Serialize)]
struct LocalModuleStatus {
    required: bool,
    ready: bool,
    detail: String,
}

/// Deployment-owned MCP providers installed before daemon startup.
///
/// `None` retains the server's conservative default for that provider family:
/// static manifest resources and unavailable prompts, completions, sampling,
/// elicitation, and roots. Provider instances are shared across all sessions
/// and therefore must implement their own bounded caches and external-client
/// lifecycle where applicable.
#[derive(Clone, Default)]
pub struct DaemonMcpProviders {
    /// Dynamic resource catalog, reads, templates, and subscriptions.
    pub resources: Option<Arc<dyn ResourceProvider>>,
    /// Prompt catalog and rendering provider.
    pub prompts: Option<Arc<dyn PromptProvider>>,
    /// Prompt/resource argument completion provider.
    pub completions: Option<Arc<dyn CompletionProvider>>,
    /// Roots, sampling, and elicitation policy provider.
    pub client_requests: Option<Arc<dyn ClientRequestProvider>>,
}

/// Product-neutral connector-fleet services installed before runtime admission.
///
/// The catalog and catch-all handler are supplied as one inseparable pair so a
/// daemon cannot advertise a remote capability that it has no execution path
/// for. Product connector implementations are not part of this composition.
#[derive(Clone)]
pub struct DaemonFleetServices {
    capability_catalog: Arc<dyn CapabilityCatalogProvider>,
    remote_handler: Arc<dyn ActionHandler>,
    status_provider: Option<Arc<dyn ConnectorFleetStatusProvider>>,
    remote_admission: Option<FairAdmissionScheduler>,
    event_ingress: Option<DaemonConnectorEventIngress>,
}

#[derive(Clone)]
struct DaemonConnectorEventIngress {
    registry: Arc<dyn ConnectorRegistryReader>,
    resolver: Arc<dyn ActionTargetResolver>,
    signer: aip_gateway::CallbackSigner,
    limits: ConnectorEventIngressLimits,
}

impl DaemonFleetServices {
    /// Creates one complete fleet data-plane composition.
    #[must_use]
    pub fn new(
        capability_catalog: Arc<dyn CapabilityCatalogProvider>,
        remote_handler: Arc<dyn ActionHandler>,
    ) -> Self {
        Self {
            capability_catalog,
            remote_handler,
            status_provider: None,
            remote_admission: None,
            event_ingress: None,
        }
    }

    /// Installs bounded lease maintenance and aggregate fleet status.
    #[must_use]
    pub fn with_status_provider<P>(mut self, provider: Arc<P>) -> Self
    where
        P: ConnectorFleetStatusProvider + 'static,
    {
        self.status_provider = Some(provider);
        self
    }

    /// Installs fixed-cardinality telemetry for the shared remote scheduler.
    #[must_use]
    pub fn with_remote_admission(mut self, admission: FairAdmissionScheduler) -> Self {
        self.remote_admission = Some(admission);
        self
    }

    /// Installs the shared signed AIP event ingress for all connector hosts.
    #[must_use]
    pub fn with_event_ingress<P>(
        mut self,
        registry: Arc<P>,
        signer: aip_gateway::CallbackSigner,
        limits: ConnectorEventIngressLimits,
    ) -> Self
    where
        P: ConnectorRegistryReader + ActionTargetResolver + 'static,
    {
        self.event_ingress = Some(DaemonConnectorEventIngress {
            registry: registry.clone(),
            resolver: registry,
            signer,
            limits,
        });
        self
    }
}

/// Complete production composition supplied to [`AipDaemon::new_with_deployment`].
#[derive(Clone)]
pub struct AipDaemonDeployment {
    postgres_url: Option<String>,
    runtime_work_budgets: RuntimeWorkBudgets,
    trust_resolvers: DaemonTrustResolvers,
    mcp_providers: DaemonMcpProviders,
    fleet_services: Option<DaemonFleetServices>,
    module_factories: Vec<Arc<dyn DaemonModuleFactory>>,
}

impl Default for AipDaemonDeployment {
    fn default() -> Self {
        Self {
            postgres_url: None,
            runtime_work_budgets: RuntimeWorkBudgets::default(),
            trust_resolvers: DaemonTrustResolvers::deny_all(),
            mcp_providers: DaemonMcpProviders::default(),
            fleet_services: None,
            module_factories: Vec::new(),
        }
    }
}

impl AipDaemonDeployment {
    /// Selects the reference clustered PostgreSQL runtime backend.
    #[must_use]
    pub fn with_postgres_url(mut self, postgres_url: impl Into<String>) -> Self {
        self.postgres_url = Some(postgres_url.into());
        self
    }

    /// Installs independent callback and reconciliation capacity budgets.
    #[must_use]
    pub fn with_runtime_work_budgets(mut self, budgets: RuntimeWorkBudgets) -> Self {
        self.runtime_work_budgets = budgets;
        self
    }

    /// Installs deployment-owned identity and approval trust resolvers.
    #[must_use]
    pub fn with_trust_resolvers(mut self, resolvers: DaemonTrustResolvers) -> Self {
        self.trust_resolvers = resolvers;
        self
    }

    /// Installs the concrete MCP provider composition.
    #[must_use]
    pub fn with_mcp_providers(mut self, providers: DaemonMcpProviders) -> Self {
        self.mcp_providers = providers;
        self
    }

    /// Installs the tenant-scoped catalog and native remote execution handler.
    #[must_use]
    pub fn with_fleet_services(mut self, services: DaemonFleetServices) -> Self {
        self.fleet_services = Some(services);
        self
    }

    /// Adds one trusted local module factory to the frozen startup
    /// composition. Long-tail connectors must use the remote fleet path.
    #[must_use]
    pub fn with_module_factory<F>(mut self, factory: F) -> Self
    where
        F: DaemonModuleFactory + 'static,
    {
        self.module_factories.push(Arc::new(factory));
        self
    }

    /// Adds one already type-erased trusted local module factory.
    #[must_use]
    pub fn with_module_factory_arc(mut self, factory: Arc<dyn DaemonModuleFactory>) -> Self {
        self.module_factories.push(factory);
        self
    }
}

type SharedMcpSseReplay = Arc<McpSseHub>;

#[derive(Clone, Debug, Default, Serialize)]
struct DaemonSupervisorSnapshot {
    runtime_worker_running: bool,
    nats_listener_running: bool,
    nats_required: bool,
    worker_cycles: u64,
    last_worker_error: Option<String>,
    last_worker_success_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Default)]
struct DaemonSupervisorState {
    inner: Arc<RwLock<DaemonSupervisorSnapshot>>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct DaemonFleetSnapshot {
    worker_running: bool,
    consecutive_failures: u64,
    expired_last_cycle: u64,
    last_error: Option<String>,
    last_success_at: Option<OffsetDateTime>,
    summary: Option<FleetStatusSummary>,
}

#[derive(Clone, Debug, Default)]
struct DaemonFleetSupervisorState {
    inner: Arc<RwLock<DaemonFleetSnapshot>>,
}

impl DaemonFleetSupervisorState {
    async fn snapshot(&self) -> DaemonFleetSnapshot {
        self.inner.read().await.clone()
    }
}

impl DaemonSupervisorState {
    async fn snapshot(&self) -> DaemonSupervisorSnapshot {
        self.inner.read().await.clone()
    }
}

#[derive(Debug)]
enum McpSseReplayStore {
    Memory(McpSseReplayBuffer),
    File(McpSseReplayFileLog),
}

impl McpSseReplayStore {
    fn new(
        storage_dir: Option<&Path>,
        session_id: &str,
    ) -> Result<Self, aip_transport_mcp_streamable_http::McpStreamableHttpError> {
        match storage_dir {
            Some(directory) => Ok(Self::File(McpSseReplayFileLog::open(
                directory.join(format!(
                    "mcp/sse/{}.jsonl",
                    hex::encode(Sha256::digest(session_id.as_bytes()))
                )),
                MCP_SSE_REPLAY_LIMIT,
            )?)),
            None => Ok(Self::Memory(McpSseReplayBuffer::new(MCP_SSE_REPLAY_LIMIT))),
        }
    }

    fn append(
        &mut self,
        event: McpSseEvent,
    ) -> aip_transport_mcp_streamable_http::McpStreamableHttpResult<McpSseEvent> {
        match self {
            Self::Memory(buffer) => Ok(buffer.append(event)),
            Self::File(log) => log.append(event),
        }
    }

    fn replay_after(&self, last_event_id: Option<&str>, limit: usize) -> Vec<McpSseEvent> {
        match self {
            Self::Memory(buffer) => buffer.replay_after(last_event_id, limit),
            Self::File(log) => log.replay_after(last_event_id, limit),
        }
    }
}

#[derive(Debug)]
struct McpSseSessionHub {
    store: McpSseReplayStore,
    sender: broadcast::Sender<McpSseEvent>,
}

#[derive(Debug)]
struct McpSseHub {
    storage_dir: Option<PathBuf>,
    sessions: RwLock<BTreeMap<String, McpSseSessionHub>>,
}

impl McpSseHub {
    fn new(storage_dir: Option<PathBuf>) -> Self {
        Self {
            storage_dir,
            sessions: RwLock::new(BTreeMap::new()),
        }
    }

    fn ensure_session<'a>(
        &'a self,
        sessions: &'a mut BTreeMap<String, McpSseSessionHub>,
        session_id: &str,
    ) -> aip_transport_mcp_streamable_http::McpStreamableHttpResult<&'a mut McpSseSessionHub> {
        if !sessions.contains_key(session_id) {
            let (sender, _) = broadcast::channel(MCP_SSE_REPLAY_LIMIT);
            sessions.insert(
                session_id.to_owned(),
                McpSseSessionHub {
                    store: McpSseReplayStore::new(self.storage_dir.as_deref(), session_id)?,
                    sender,
                },
            );
        }
        sessions.get_mut(session_id).ok_or_else(|| {
            aip_transport_mcp_streamable_http::McpStreamableHttpError::ReplayLog(
                "MCP SSE session initialization failed".to_owned(),
            )
        })
    }

    async fn subscribe(
        &self,
        session_id: &str,
    ) -> aip_transport_mcp_streamable_http::McpStreamableHttpResult<broadcast::Receiver<McpSseEvent>>
    {
        let mut sessions = self.sessions.write().await;
        Ok(self
            .ensure_session(&mut sessions, session_id)?
            .sender
            .subscribe())
    }

    async fn publish(
        &self,
        session_id: &str,
        event: McpSseEvent,
    ) -> aip_transport_mcp_streamable_http::McpStreamableHttpResult<McpSseEvent> {
        let mut sessions = self.sessions.write().await;
        let session = self.ensure_session(&mut sessions, session_id)?;
        let event = session.store.append(event)?;
        // A disconnected stream is not a publication failure: the durable log
        // remains authoritative and the next listener can resume by cursor.
        let _ = session.sender.send(event.clone());
        Ok(event)
    }

    async fn replay_after(
        &self,
        session_id: &str,
        last_event_id: Option<&str>,
    ) -> aip_transport_mcp_streamable_http::McpStreamableHttpResult<Vec<McpSseEvent>> {
        let mut sessions = self.sessions.write().await;
        Ok(self
            .ensure_session(&mut sessions, session_id)?
            .store
            .replay_after(last_event_id, MCP_SSE_REPLAY_LIMIT))
    }

    async fn close(&self, session_id: &str) {
        self.sessions.write().await.remove(session_id);
    }
}

struct McpSseConnection {
    hub: SharedMcpSseReplay,
    session_id: String,
    receiver: broadcast::Receiver<McpSseEvent>,
    pending: VecDeque<McpSseEvent>,
    last_event_id: Option<String>,
}

#[derive(Clone)]
struct DaemonMcpPeerTransport {
    streamable_hub: SharedMcpSseReplay,
    legacy_sessions: LegacySessionRegistry,
    correlations: DaemonMcpCorrelationStore,
    sessions: Arc<RwLock<BTreeMap<String, Arc<DaemonMcpPeerSession>>>>,
}

#[derive(Clone, Debug)]
enum DaemonMcpCorrelationStore {
    Memory(InMemoryMcpCorrelationStore),
    File(FileMcpCorrelationStore),
    Postgres(PostgresRuntimeStore),
}

#[async_trait::async_trait]
impl McpCorrelationStore for DaemonMcpCorrelationStore {
    async fn create(&self, record: McpCorrelationRecord) -> Result<(), McpSessionError> {
        match self {
            Self::Memory(store) => store.create(record).await,
            Self::File(store) => store.create(record).await,
            Self::Postgres(store) => store.create(record).await,
        }
    }

    async fn settle(
        &self,
        session_id: &str,
        request_id: &str,
        direction: CorrelationDirection,
        response: JsonRpcResponse,
    ) -> Result<(), McpSessionError> {
        match self {
            Self::Memory(store) => {
                store
                    .settle(session_id, request_id, direction, response)
                    .await
            }
            Self::File(store) => {
                store
                    .settle(session_id, request_id, direction, response)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .settle(session_id, request_id, direction, response)
                    .await
            }
        }
    }

    async fn get(
        &self,
        session_id: &str,
        request_id: &str,
        direction: CorrelationDirection,
    ) -> Result<Option<McpCorrelationRecord>, McpSessionError> {
        match self {
            Self::Memory(store) => store.get(session_id, request_id, direction).await,
            Self::File(store) => store.get(session_id, request_id, direction).await,
            Self::Postgres(store) => store.get(session_id, request_id, direction).await,
        }
    }

    async fn prune(&self, now: OffsetDateTime) -> Result<u64, McpSessionError> {
        match self {
            Self::Memory(store) => store.prune(now).await,
            Self::File(store) => store.prune(now).await,
            Self::Postgres(store) => store.prune(now).await,
        }
    }
}

struct DaemonMcpPeerSession {
    owner: String,
    transport: McpTransportKind,
    incoming: mpsc::Sender<McpFrame>,
    dispatcher: Arc<McpDispatcher<DaemonMcpDuplex, DaemonMcpCorrelationStore>>,
}

struct DaemonMcpDuplex {
    session_id: String,
    owner: String,
    transport: McpTransportKind,
    streamable_hub: SharedMcpSseReplay,
    legacy_sessions: LegacySessionRegistry,
    stdio_outgoing: Option<mpsc::Sender<McpFrame>>,
    incoming: tokio::sync::Mutex<mpsc::Receiver<McpFrame>>,
}

impl DaemonMcpPeerTransport {
    fn new(
        streamable_hub: SharedMcpSseReplay,
        legacy_sessions: LegacySessionRegistry,
        correlations: DaemonMcpCorrelationStore,
    ) -> Self {
        Self {
            streamable_hub,
            legacy_sessions,
            correlations,
            sessions: Arc::default(),
        }
    }

    async fn register_session(
        &self,
        session_id: &str,
        owner: &str,
        transport: McpTransportKind,
    ) -> McpServerResult<()> {
        self.register_session_with_stdio(session_id, owner, transport, None)
            .await
    }

    async fn register_stdio_session(
        &self,
        session_id: &str,
        owner: &str,
    ) -> McpServerResult<mpsc::Receiver<McpFrame>> {
        let (outgoing, receiver) = mpsc::channel(1_024);
        self.register_session_with_stdio(
            session_id,
            owner,
            McpTransportKind::Stdio,
            Some(outgoing),
        )
        .await?;
        Ok(receiver)
    }

    async fn register_session_with_stdio(
        &self,
        session_id: &str,
        owner: &str,
        transport: McpTransportKind,
        stdio_outgoing: Option<mpsc::Sender<McpFrame>>,
    ) -> McpServerResult<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(existing) = sessions.get(session_id) {
            if existing.owner != owner || existing.transport != transport {
                return Err(McpServerError::Provider(
                    "MCP peer session binding mismatch".to_owned(),
                ));
            }
            return Ok(());
        }
        let (incoming, receiver) = mpsc::channel(1_024);
        let duplex = Arc::new(DaemonMcpDuplex {
            session_id: session_id.to_owned(),
            owner: owner.to_owned(),
            transport,
            streamable_hub: self.streamable_hub.clone(),
            legacy_sessions: self.legacy_sessions.clone(),
            stdio_outgoing,
            incoming: tokio::sync::Mutex::new(receiver),
        });
        let dispatcher = McpDispatcher::new(
            session_id,
            duplex,
            Arc::new(self.correlations.clone()),
            1_024,
        );
        let pump = dispatcher.clone();
        tokio::spawn(async move {
            let _ = pump.run().await;
        });
        sessions.insert(
            session_id.to_owned(),
            Arc::new(DaemonMcpPeerSession {
                owner: owner.to_owned(),
                transport,
                incoming,
                dispatcher,
            }),
        );
        Ok(())
    }

    async fn accept_response(
        &self,
        session_id: &str,
        owner: &str,
        response: JsonRpcResponse,
    ) -> McpServerResult<()> {
        let session = self.session(session_id, owner).await?;
        session
            .incoming
            .send(McpFrame::Response(response))
            .await
            .map_err(|_| McpServerError::Provider("MCP peer receive pump closed".to_owned()))
    }

    async fn close_session(&self, session_id: &str) {
        self.sessions.write().await.remove(session_id);
    }

    async fn session(
        &self,
        session_id: &str,
        owner: &str,
    ) -> McpServerResult<Arc<DaemonMcpPeerSession>> {
        let session = self
            .sessions
            .read()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| {
                McpServerError::Provider(format!("MCP peer session `{session_id}` was not found"))
            })?;
        if session.owner != owner {
            return Err(McpServerError::Provider(
                "MCP peer session owner mismatch".to_owned(),
            ));
        }
        Ok(session)
    }
}

#[async_trait::async_trait]
impl McpDuplexTransport for DaemonMcpDuplex {
    async fn send(&self, frame: McpFrame) -> Result<(), McpSessionError> {
        match self.transport {
            McpTransportKind::StreamableHttp => {
                let data = mcp_frame_json(&frame)?;
                self.streamable_hub
                    .publish(
                        &self.session_id,
                        McpSseEvent {
                            id: None,
                            event: Some("message".to_owned()),
                            data,
                        },
                    )
                    .await
                    .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
            }
            McpTransportKind::LegacyHttpSse => {
                self.legacy_sessions
                    .publish_server_frame(&self.session_id, &self.owner, &frame)
                    .await
                    .map_err(|error| McpSessionError::Dispatcher(error.to_string()))?;
            }
            McpTransportKind::Stdio => {
                self.stdio_outgoing
                    .as_ref()
                    .ok_or_else(|| {
                        McpSessionError::Dispatcher(
                            "getaip-server stdio peer has no outbound frame queue".to_owned(),
                        )
                    })?
                    .send(frame)
                    .await
                    .map_err(|_| {
                        McpSessionError::Dispatcher(
                            "getaip-server stdio outbound frame queue closed".to_owned(),
                        )
                    })?;
            }
        }
        Ok(())
    }

    async fn receive(&self) -> Result<Option<McpFrame>, McpSessionError> {
        Ok(self.incoming.lock().await.recv().await)
    }
}

#[async_trait::async_trait]
impl McpPeerTransport for DaemonMcpPeerTransport {
    async fn request(
        &self,
        session_id: &str,
        request: JsonRpcRequest,
        timeout: Duration,
    ) -> McpServerResult<JsonRpcResponse> {
        let session = self
            .sessions
            .read()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| {
                McpServerError::Provider(format!("MCP peer session `{session_id}` was not found"))
            })?;
        session
            .dispatcher
            .request(request, timeout)
            .await
            .map_err(McpServerError::Session)
    }

    async fn notify(
        &self,
        session_id: &str,
        notification: JsonRpcNotification,
    ) -> McpServerResult<()> {
        let session = self
            .sessions
            .read()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| {
                McpServerError::Provider(format!("MCP peer session `{session_id}` was not found"))
            })?;
        session
            .dispatcher
            .notify(notification)
            .await
            .map_err(McpServerError::Session)
    }
}

fn mcp_frame_json(frame: &McpFrame) -> Result<String, McpSessionError> {
    match frame {
        McpFrame::Request(value) => serde_json::to_string(value),
        McpFrame::Notification(value) => serde_json::to_string(value),
        McpFrame::Response(value) => serde_json::to_string(value),
    }
    .map_err(|error| McpSessionError::Dispatcher(error.to_string()))
}

/// Deployment-owned trust resolvers installed before the daemon accepts
/// protocol traffic.
///
/// The bundle deliberately contains trait objects rather than wire
/// configuration. Deployments can compose an IdP, tenant directory,
/// credential broker, and approval authority without serializing secrets or
/// trusted memberships into AIP messages.
#[derive(Clone)]
pub struct DaemonTrustResolvers {
    identity: Arc<dyn TrustedIdentityResolver>,
    approval_authority: Arc<dyn ApprovalAuthorityResolver>,
}

impl DaemonTrustResolvers {
    /// Creates a trust bundle from independently administered resolvers.
    #[must_use]
    pub fn new(
        identity: Arc<dyn TrustedIdentityResolver>,
        approval_authority: Arc<dyn ApprovalAuthorityResolver>,
    ) -> Self {
        Self {
            identity,
            approval_authority,
        }
    }

    /// Creates the fail-closed default used when no trust providers are
    /// configured.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::new(
            Arc::new(DenyAllTrustedIdentityResolver),
            Arc::new(DenyAllApprovalAuthorityResolver),
        )
    }
}

fn runtime_stores_for_modules(runtime: &Runtime) -> RuntimeStores {
    RuntimeStores {
        durability: runtime.store_durability(),
        storage_health: runtime.storage_health.clone(),
        maintenance: runtime.maintenance.clone(),
        replay: runtime.replay.clone(),
        profile_state: runtime.profile_state.clone(),
        sessions: runtime.sessions.clone(),
        idempotency: runtime.idempotency.clone(),
        events: runtime.events.clone(),
        lifecycle: runtime.lifecycle.clone(),
        delegations: runtime.delegations.clone(),
        approvals: runtime.approvals.clone(),
        transactions: runtime.transactions.clone(),
        action_queue: runtime.action_queue.clone(),
        callback_deliveries: runtime.callback_deliveries.clone(),
    }
}

fn module_gateway_error(error: DaemonModuleError) -> GatewayError {
    GatewayError::Runtime(RuntimeError::Handler(error.to_string()))
}

async fn prepare_local_modules(
    mut factories: Vec<Arc<dyn DaemonModuleFactory>>,
    runtime: &Runtime,
    service_id: &PrincipalId,
    base_manifest: &Manifest,
) -> Result<
    (
        Vec<PreparedDaemonModule>,
        BTreeMap<String, LocalModuleStatus>,
    ),
    GatewayError,
> {
    if factories.len() > module::MAX_LOCAL_MODULES {
        return Err(module_gateway_error(DaemonModuleError::new(
            "aip.server.module.count_limit",
            format!(
                "daemon received {} local modules; maximum is {}",
                factories.len(),
                module::MAX_LOCAL_MODULES
            ),
        )));
    }
    for factory in &factories {
        let descriptor = factory.descriptor();
        LocalModuleId::parse(descriptor.id.as_str()).map_err(module_gateway_error)?;
        if descriptor.startup_timeout_ms == 0 || descriptor.startup_timeout_ms > 300_000 {
            return Err(module_gateway_error(DaemonModuleError::new(
                "aip.server.module.invalid_timeout",
                format!(
                    "module `{}` startup timeout must be between 1 and 300000 milliseconds",
                    descriptor.id
                ),
            )));
        }
    }
    factories.sort_by_key(|factory| factory.descriptor().id);
    let mut descriptor_ids = BTreeSet::new();
    for factory in &factories {
        let descriptor = factory.descriptor();
        if !descriptor_ids.insert(descriptor.id.clone()) {
            return Err(module_gateway_error(DaemonModuleError::new(
                "aip.server.module.duplicate_id",
                format!("duplicate local module id `{}`", descriptor.id),
            )));
        }
    }

    let services = DaemonServices::new(service_id.clone(), runtime_stores_for_modules(runtime));
    let mut prepared = Vec::with_capacity(factories.len());
    let mut statuses = BTreeMap::new();
    for factory in factories {
        let descriptor = factory.descriptor();
        let result = tokio::time::timeout(
            Duration::from_millis(descriptor.startup_timeout_ms),
            factory.prepare(&services),
        )
        .await;
        let module = match result {
            Ok(Ok(module)) => module,
            Ok(Err(error)) if !descriptor.required => {
                statuses.insert(
                    descriptor.id.to_string(),
                    LocalModuleStatus {
                        required: false,
                        ready: false,
                        detail: error.to_string(),
                    },
                );
                continue;
            }
            Ok(Err(error)) => return Err(module_gateway_error(error)),
            Err(_) if !descriptor.required => {
                statuses.insert(
                    descriptor.id.to_string(),
                    LocalModuleStatus {
                        required: false,
                        ready: false,
                        detail: format!(
                            "aip.server.module.startup_timeout: preparation exceeded {} milliseconds",
                            descriptor.startup_timeout_ms
                        ),
                    },
                );
                continue;
            }
            Err(_) => {
                return Err(module_gateway_error(DaemonModuleError::new(
                    "aip.server.module.startup_timeout",
                    format!(
                        "required module `{}` exceeded {} milliseconds",
                        descriptor.id, descriptor.startup_timeout_ms
                    ),
                )));
            }
        };
        if module.descriptor != descriptor {
            return Err(module_gateway_error(DaemonModuleError::new(
                "aip.server.module.descriptor_changed",
                format!(
                    "module factory `{}` returned a different descriptor",
                    descriptor.id
                ),
            )));
        }
        validate_prepared_module(&module)?;
        statuses.insert(
            descriptor.id.to_string(),
            LocalModuleStatus {
                required: descriptor.required,
                ready: true,
                detail: "module prepared and admitted".to_owned(),
            },
        );
        prepared.push(module);
    }

    let mut capability_owners = base_manifest
        .capabilities
        .iter()
        .map(|capability| (capability.id.clone(), "getaip-server-core".to_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut connector_owners = BTreeMap::<String, String>::new();
    let mut route_owners = BTreeMap::<String, String>::new();
    for module in &prepared {
        let owner = module.descriptor.id.to_string();
        for capability in &module.manifest.capabilities {
            if let Some(existing) = capability_owners.insert(capability.id.clone(), owner.clone()) {
                return Err(module_gateway_error(DaemonModuleError::new(
                    "aip.server.module.capability_conflict",
                    format!(
                        "capability `{}` is owned by both `{existing}` and `{owner}`",
                        capability.id
                    ),
                )));
            }
        }
        for connector in module.connectors() {
            let connector_id = connector.id().to_owned();
            if connector_id.trim().is_empty() {
                return Err(module_gateway_error(DaemonModuleError::new(
                    "aip.server.module.empty_connector_id",
                    format!("module `{owner}` returned an empty connector id"),
                )));
            }
            if let Some(existing) = connector_owners.insert(connector_id.clone(), owner.clone()) {
                return Err(module_gateway_error(DaemonModuleError::new(
                    "aip.server.module.connector_conflict",
                    format!(
                        "connector `{connector_id}` is owned by both `{existing}` and `{owner}`"
                    ),
                )));
            }
        }
        for mount in module.http_mounts() {
            for route in mount.routes() {
                if !route
                    .path
                    .starts_with(module::LOCAL_MODULE_HTTP_ROUTE_PREFIX)
                {
                    return Err(module_gateway_error(DaemonModuleError::new(
                        "aip.server.module.reserved_http_route",
                        format!(
                            "module `{owner}` route `{}` must remain under {}",
                            route.path,
                            module::LOCAL_MODULE_HTTP_ROUTE_PREFIX
                        ),
                    )));
                }
                let key = route.conflict_key();
                if let Some(existing) = route_owners.insert(key.clone(), owner.clone()) {
                    return Err(module_gateway_error(DaemonModuleError::new(
                        "aip.server.module.http_route_conflict",
                        format!("route `{key}` is owned by both `{existing}` and `{owner}`"),
                    )));
                }
            }
        }
    }
    Ok((prepared, statuses))
}

fn validate_prepared_module(module: &PreparedDaemonModule) -> Result<(), GatewayError> {
    let manifest_size = serde_json::to_vec(&module.manifest)
        .map_err(|error| {
            module_gateway_error(DaemonModuleError::new(
                "aip.server.module.manifest_serialization",
                error.to_string(),
            ))
        })?
        .len();
    if manifest_size > module::MAX_MODULE_MANIFEST_BYTES {
        return Err(module_gateway_error(DaemonModuleError::new(
            "aip.server.module.manifest_limit",
            format!(
                "module `{}` manifest is {manifest_size} bytes; maximum is {}",
                module.descriptor.id,
                module::MAX_MODULE_MANIFEST_BYTES
            ),
        )));
    }
    let mut manifest_ids = BTreeSet::new();
    let mut executable_ids = BTreeSet::new();
    for capability in &module.manifest.capabilities {
        if !manifest_ids.insert(capability.id.clone()) {
            return Err(module_gateway_error(DaemonModuleError::new(
                "aip.server.module.duplicate_capability",
                format!(
                    "module `{}` repeats capability `{}`",
                    module.descriptor.id, capability.id
                ),
            )));
        }
        if capability.kind != CapabilityKind::Resource {
            executable_ids.insert(capability.id.clone());
        }
    }
    let handler_ids = module.handlers().keys().cloned().collect::<BTreeSet<_>>();
    if executable_ids != handler_ids {
        let missing = executable_ids.difference(&handler_ids).next();
        let undeclared = handler_ids.difference(&executable_ids).next();
        return Err(module_gateway_error(DaemonModuleError::new(
            "aip.server.module.handler_manifest_mismatch",
            match (missing, undeclared) {
                (Some(capability), _) => format!(
                    "module `{}` capability `{capability}` has no handler",
                    module.descriptor.id
                ),
                (_, Some(capability)) => format!(
                    "module `{}` handler `{capability}` has no manifest capability",
                    module.descriptor.id
                ),
                _ => format!(
                    "module `{}` handler set is inconsistent",
                    module.descriptor.id
                ),
            },
        )));
    }
    Ok(())
}

impl AipDaemon {
    /// Creates a daemon and registers built-in protocol capabilities.
    pub async fn new(config: AipDaemonConfig) -> Result<Self, GatewayError> {
        Box::pin(Self::new_with_optional_postgres_url(
            config,
            None,
            DaemonTrustResolvers::deny_all(),
        ))
        .await
    }

    /// Creates a daemon from one explicit production deployment composition.
    ///
    /// This is the preferred constructor for embedders because storage, trust,
    /// and MCP provider boundaries are frozen before any manifest is admitted
    /// or any protocol capability is advertised.
    pub async fn new_with_deployment(
        config: AipDaemonConfig,
        deployment: AipDaemonDeployment,
    ) -> Result<Self, GatewayError> {
        Box::pin(Self::new_with_optional_postgres_url_and_providers(
            config,
            deployment.postgres_url,
            deployment.runtime_work_budgets,
            deployment.trust_resolvers,
            deployment.mcp_providers,
            deployment.fleet_services,
            deployment.module_factories,
        ))
        .await
    }

    /// Creates a daemon with a deployment-owned trusted identity resolver.
    pub async fn new_with_identity_resolver(
        config: AipDaemonConfig,
        resolver: Arc<dyn TrustedIdentityResolver>,
    ) -> Result<Self, GatewayError> {
        Box::pin(Self::new_with_optional_postgres_url(
            config,
            None,
            DaemonTrustResolvers::new(resolver, Arc::new(DenyAllApprovalAuthorityResolver)),
        ))
        .await
    }

    /// Creates a daemon with all deployment-owned identity and approval trust
    /// providers installed before manifest admission.
    pub async fn new_with_trust_resolvers(
        config: AipDaemonConfig,
        resolvers: DaemonTrustResolvers,
    ) -> Result<Self, GatewayError> {
        Box::pin(Self::new_with_optional_postgres_url(
            config, None, resolvers,
        ))
        .await
    }

    /// Creates a daemon backed by PostgreSQL runtime storage.
    pub async fn new_with_postgres_url(
        config: AipDaemonConfig,
        postgres_url: impl Into<String>,
    ) -> Result<Self, GatewayError> {
        Box::pin(Self::new_with_optional_postgres_url(
            config,
            Some(postgres_url.into()),
            DaemonTrustResolvers::deny_all(),
        ))
        .await
    }

    /// Creates a PostgreSQL-backed daemon with a deployment-owned identity
    /// resolver.
    pub async fn new_with_postgres_url_and_identity_resolver(
        config: AipDaemonConfig,
        postgres_url: impl Into<String>,
        resolver: Arc<dyn TrustedIdentityResolver>,
    ) -> Result<Self, GatewayError> {
        Box::pin(Self::new_with_optional_postgres_url(
            config,
            Some(postgres_url.into()),
            DaemonTrustResolvers::new(resolver, Arc::new(DenyAllApprovalAuthorityResolver)),
        ))
        .await
    }

    /// Creates a PostgreSQL-backed daemon with all deployment-owned identity
    /// and approval trust providers installed before manifest admission.
    pub async fn new_with_postgres_url_and_trust_resolvers(
        config: AipDaemonConfig,
        postgres_url: impl Into<String>,
        resolvers: DaemonTrustResolvers,
    ) -> Result<Self, GatewayError> {
        Box::pin(Self::new_with_optional_postgres_url(
            config,
            Some(postgres_url.into()),
            resolvers,
        ))
        .await
    }

    async fn new_with_optional_postgres_url(
        config: AipDaemonConfig,
        postgres_url: Option<String>,
        trust_resolvers: DaemonTrustResolvers,
    ) -> Result<Self, GatewayError> {
        // Keep the full initialization state machine off caller-owned Tokio
        // worker stacks. Connector composition and durable recovery retain
        // several large futures across await points.
        Box::pin(Self::new_with_optional_postgres_url_and_providers(
            config,
            postgres_url,
            RuntimeWorkBudgets::default(),
            trust_resolvers,
            DaemonMcpProviders::default(),
            None,
            Vec::new(),
        ))
        .await
    }

    async fn new_with_optional_postgres_url_and_providers(
        config: AipDaemonConfig,
        postgres_url: Option<String>,
        runtime_work_budgets: RuntimeWorkBudgets,
        trust_resolvers: DaemonTrustResolvers,
        mcp_providers: DaemonMcpProviders,
        fleet_services: Option<DaemonFleetServices>,
        module_factories: Vec<Arc<dyn DaemonModuleFactory>>,
    ) -> Result<Self, GatewayError> {
        validate_daemon_security_config(&config)?;
        let prometheus = initialize_prometheus()?;
        let started_at = Instant::now();
        let mut manifest = manifest_from_config_with_runtime_storage(
            &config,
            runtime_storage_label(&config, postgres_url.as_deref()),
        );
        if fleet_services.is_some() {
            manifest
                .capabilities
                .push(capability_catalog_query_capability());
        }
        let postgres_store = if let Some(postgres_url) = postgres_url.as_deref() {
            Some(
                PostgresRuntimeStore::connect(postgres_url)
                    .await
                    .map_err(runtime_error)?,
            )
        } else {
            None
        };
        let runtime = if let Some(store) = postgres_store.clone() {
            Runtime::with_stores(store.runtime_stores())
        } else if let Some(storage_dir) = &config.storage_dir {
            Runtime::durable_local(storage_dir.clone())
                .await
                .map_err(runtime_error)?
        } else {
            Runtime::new()
        };
        let mut runtime = runtime
            .with_work_budgets(runtime_work_budgets)
            .map_err(runtime_error)?
            .with_approval_authority_arc(trust_resolvers.approval_authority.clone());
        if let Some(services) = fleet_services.as_ref() {
            runtime = runtime
                .with_capability_catalog_arc(services.capability_catalog.clone())
                .with_remote_handler_arc(services.remote_handler.clone());
        }
        let (prepared_modules, module_statuses) =
            prepare_local_modules(module_factories, &runtime, &config.service_id, &manifest)
                .await?;
        for module in &prepared_modules {
            merge_connector_manifest(
                &mut manifest,
                module.descriptor.id.as_str(),
                &module.manifest,
            );
        }
        let callback_dispatcher = GatewayCallbackDispatcher::with_policy(
            aip_transport_sse::SseTransport::new(),
            config.callback_policy.clone(),
        );
        let mut handlers: HashMap<CapabilityId, Arc<dyn ActionHandler>> = HashMap::new();
        handlers.insert(
            CapabilityId::trusted(HEALTH_CAPABILITY_ID),
            Arc::new(BuiltInHealthHandler { started_at }),
        );
        if let Some(services) = fleet_services.as_ref() {
            handlers.insert(
                CapabilityId::trusted(CAPABILITY_CATALOG_QUERY_ID),
                Arc::new(CapabilityCatalogQueryHandler {
                    catalog: services.capability_catalog.clone(),
                }),
            );
        }
        for module in &prepared_modules {
            for (capability_id, handler) in module.handlers() {
                if handlers
                    .insert(capability_id.clone(), handler.clone())
                    .is_some()
                {
                    return Err(module_gateway_error(DaemonModuleError::new(
                        "aip.server.module.handler_conflict",
                        format!("duplicate handler for capability `{capability_id}`"),
                    )));
                }
            }
        }
        let gateway = Gateway::with_policy_runtime_callback_and_handlers(
            manifest.clone(),
            GatewayPolicy {
                require_signed_envelopes: config.require_signed_envelopes,
                allow_unverified_payload_identity: config.allow_insecure_development,
                resolve_identity_for_unknown_actions: fleet_services.is_some(),
                identity_required_capabilities: fleet_services
                    .as_ref()
                    .map_or_else(BTreeSet::new, |_| {
                        BTreeSet::from([CapabilityId::trusted(CAPABILITY_CATALOG_QUERY_ID)])
                    }),
                ..GatewayPolicy::default()
            },
            runtime,
            callback_dispatcher,
            handlers,
        )
        .await?
        .with_identity_resolver(trust_resolvers.identity);
        for (did, principal) in &config.trusted_signers {
            gateway
                .register_trusted_signer(did.clone(), principal.clone())
                .await;
        }
        for route in config.delegation_routes {
            gateway.register_delegation_route(route).await;
        }
        for module in &prepared_modules {
            for connector in module.connectors() {
                gateway.register_connector_arc(connector.clone()).await;
            }
            for router in module.delegation_routers() {
                gateway.register_delegation_router_arc(router.clone()).await;
            }
        }
        for recovery in gateway.runtime().recover_queued_actions().await? {
            if let Err(error) = recovery {
                warn!(error = %error, "failed to recover persisted AIP async action");
            }
        }
        for recovery in gateway
            .runtime()
            .recover_running_delegations(aip_runtime::MessageContext {
                session_id: None,
                correlation_id: None,
                actor: Some(manifest.agent.clone()),
                ..aip_runtime::MessageContext::default()
            })
            .await?
        {
            if let Err(error) = recovery {
                warn!(error = %error, "failed to recover persisted AIP delegation");
            }
        }
        let mcp_sse_replay = Arc::new(McpSseHub::new(config.storage_dir.clone()));
        let mcp_legacy_sessions = LegacySessionRegistry::default();
        let mcp_correlations = if let Some(store) = postgres_store {
            DaemonMcpCorrelationStore::Postgres(store)
        } else if let Some(storage_dir) = config.storage_dir.as_deref() {
            DaemonMcpCorrelationStore::File(
                FileMcpCorrelationStore::open(storage_dir.join("mcp/correlations.json"))
                    .map_err(runtime_error)?,
            )
        } else {
            DaemonMcpCorrelationStore::Memory(InMemoryMcpCorrelationStore::default())
        };
        let mcp_peer_transport = DaemonMcpPeerTransport::new(
            mcp_sse_replay.clone(),
            mcp_legacy_sessions.clone(),
            mcp_correlations,
        );
        let mut mcp_server_config = McpServerConfig::new(manifest.clone(), gateway.clone())
            .with_mcp_principal(config.mcp_principal.clone())
            .with_dynamic_notifications(true)
            .with_peer_transport(mcp_peer_transport.clone());
        if let Some(services) = fleet_services.as_ref() {
            mcp_server_config =
                mcp_server_config.with_capability_catalog_arc(services.capability_catalog.clone());
        }
        if let Some(provider) = mcp_providers.resources {
            mcp_server_config.resources = provider;
        }
        if let Some(provider) = mcp_providers.prompts {
            mcp_server_config.prompts = provider;
        }
        if let Some(provider) = mcp_providers.completions {
            mcp_server_config.completions = provider;
        }
        if let Some(provider) = mcp_providers.client_requests {
            mcp_server_config.client_requests = provider;
        }
        let mcp_server = McpServer::new(mcp_server_config);
        let mcp_principal = config.mcp_principal.clone();
        let supervisor = DaemonSupervisorState::default();
        supervisor.inner.write().await.nats_required = config.nats.is_some();
        let profile_state = gateway.runtime().profile_state.clone();
        let advertised_address = if config.bind.ip().is_unspecified() {
            SocketAddr::new(
                if config.bind.is_ipv4() {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                } else {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                },
                config.bind.port(),
            )
        } else {
            config.bind
        };
        let public_base_url = match config.public_base_url.as_deref() {
            Some(value) => {
                validate_public_base_url(value, config.allow_insecure_development, config.bind)?
            }
            None => Url::parse(&format!("http://{advertised_address}/")).map_err(|error| {
                GatewayError::Runtime(RuntimeError::Authorization(format!(
                    "derived public base URL is invalid: {error}"
                )))
            })?,
        };
        let a2a_interface_url = public_base_url
            .join("a2a/v1")
            .map_err(|error| GatewayError::Runtime(RuntimeError::Authorization(error.to_string())))?
            .to_string();
        let capability_discovery_url = public_base_url
            .join("aip/v1/capabilities")
            .map_err(|error| GatewayError::Runtime(RuntimeError::Authorization(error.to_string())))?
            .to_string();
        let module_http_mounts = prepared_modules
            .iter()
            .flat_map(|module| module.http_mounts().iter().cloned())
            .collect();
        let connector_event_ingress = if let Some(event_ingress) = fleet_services
            .as_ref()
            .and_then(|services| services.event_ingress.as_ref())
        {
            if event_ingress.signer.principal.id != manifest.agent.id
                || event_ingress.signer.principal.kind != manifest.agent.kind
            {
                return Err(GatewayError::Runtime(RuntimeError::Authorization(
                    "connector event ingress signer must match the daemon manifest principal"
                        .to_owned(),
                )));
            }
            Some(
                ConnectorEventIngress::new(
                    event_ingress.registry.clone(),
                    gateway.runtime().events.clone(),
                    event_ingress.signer.clone(),
                    event_ingress.limits.clone(),
                )
                .map_err(|error| GatewayError::Runtime(RuntimeError::Handler(error.to_string())))?
                .with_stream_callbacks(
                    event_ingress.resolver.clone(),
                    Arc::new(gateway.runtime().clone()),
                ),
            )
        } else {
            None
        };
        let fleet_status_provider = fleet_services
            .as_ref()
            .and_then(|services| services.status_provider.clone());
        let remote_admission = fleet_services
            .as_ref()
            .and_then(|services| services.remote_admission.clone());
        let fleet_supervisor = fleet_status_provider
            .as_ref()
            .map(|_| DaemonFleetSupervisorState::default());
        let capability_catalog = fleet_services
            .as_ref()
            .map(|services| services.capability_catalog.clone());
        Ok(Self {
            gateway,
            manifest,
            mcp_server,
            started_at,
            nats: config.nats,
            native_http_auth: config.native_http_auth,
            allow_insecure_development: config.allow_insecure_development,
            callback_policy: config.callback_policy,
            mcp_protected_resource: config.mcp_protected_resource,
            mcp_sse_replay,
            mcp_http_session_owners: Arc::default(),
            mcp_legacy_sessions,
            mcp_peer_transport,
            mcp_token_verifier: None,
            mcp_principal,
            profile_state,
            a2a_interface_url,
            supervisor,
            prometheus,
            module_http_mounts,
            module_statuses,
            fleet_status_provider,
            fleet_supervisor,
            remote_admission,
            connector_event_ingress,
            capability_catalog,
            capability_discovery_url,
        })
    }

    /// Returns the daemon manifest.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Publishes a server-initiated MCP Streamable HTTP event.
    ///
    /// Publication is durable when `storage_dir` is configured. Connected GET
    /// streams receive the event immediately, while reconnecting clients can
    /// resume from its assigned event id with `Last-Event-ID`.
    pub async fn publish_mcp_sse_event(
        &self,
        session_id: &str,
        event: McpSseEvent,
    ) -> Result<McpSseEvent, GatewayError> {
        self.mcp_sse_replay
            .publish(session_id, event)
            .await
            .map_err(runtime_error)
    }

    /// Returns the AIP-backed MCP server runtime.
    #[must_use]
    pub fn mcp_server(&self) -> &McpServer {
        &self.mcp_server
    }

    /// Opens the bidirectional stdio peer queue for one MCP session.
    ///
    /// The caller must forward every returned frame to stdout and feed client
    /// responses back through [`Self::accept_mcp_stdio_response`].
    pub async fn open_mcp_stdio_peer(
        &self,
        session_id: &str,
    ) -> McpServerResult<mpsc::Receiver<McpFrame>> {
        self.mcp_peer_transport
            .register_stdio_session(session_id, self.mcp_principal.id.as_str())
            .await
    }

    /// Settles one server-to-client stdio request with the client's correlated
    /// JSON-RPC response.
    pub async fn accept_mcp_stdio_response(
        &self,
        session_id: &str,
        response: JsonRpcResponse,
    ) -> McpServerResult<()> {
        self.mcp_peer_transport
            .accept_response(session_id, self.mcp_principal.id.as_str(), response)
            .await
    }

    /// Installs the production OAuth token verifier for MCP Streamable HTTP.
    #[must_use]
    pub fn with_mcp_token_verifier<V>(mut self, verifier: V) -> Self
    where
        V: TokenVerifier + 'static,
    {
        self.mcp_token_verifier = Some(Arc::new(verifier));
        self
    }

    /// Builds the HTTP router for embedding and tests.
    pub fn router(&self) -> Router {
        let state = AppState {
            gateway: self.gateway.clone(),
            manifest: self.manifest.clone(),
            mcp_server: self.mcp_server.clone(),
            started_at: self.started_at,
            native_http_auth: self.native_http_auth.clone(),
            allow_insecure_development: self.allow_insecure_development,
            callback_policy: self.callback_policy.clone(),
            mcp_protected_resource: self.mcp_protected_resource.clone(),
            mcp_sse_replay: self.mcp_sse_replay.clone(),
            mcp_http_session_owners: self.mcp_http_session_owners.clone(),
            mcp_legacy_sessions: self.mcp_legacy_sessions.clone(),
            mcp_peer_transport: self.mcp_peer_transport.clone(),
            mcp_token_verifier: self.mcp_token_verifier.clone(),
            mcp_principal: self.mcp_principal.clone(),
            profile_state: self.profile_state.clone(),
            a2a_interface_url: self.a2a_interface_url.clone(),
            supervisor: self.supervisor.clone(),
            prometheus: self.prometheus.clone(),
            module_statuses: self.module_statuses.clone(),
            fleet_supervisor: self.fleet_supervisor.clone(),
            remote_admission: self.remote_admission.clone(),
            connector_event_ingress: self.connector_event_ingress.clone(),
            capability_catalog: self.capability_catalog.clone(),
            capability_discovery_url: self.capability_discovery_url.clone(),
        };
        let connector_event_max_bytes = self
            .connector_event_ingress
            .as_ref()
            .map_or(4 * 1024 * 1024, ConnectorEventIngress::max_envelope_bytes);
        let native_routes = Router::new()
            .route("/aip/v1/actions", get(action_list).post(handle_envelope))
            .route("/aip/v1/actions/{action_id}", get(action_status))
            .route("/aip/v1/actions/{action_id}/result", get(action_result))
            .route("/aip/v1/actions/{action_id}/events", get(action_events))
            .route("/aip/v1/actions/{action_id}/chunks", get(action_chunks))
            .route("/aip/v1/actions/{action_id}/cancel", post(action_cancel))
            .route("/aip/v1/events", get(global_events))
            .route("/aip/v1/sessions", get(session_list))
            .route(
                "/aip/v1/sessions/{session_selector}",
                get(session_get).post(session_operation),
            )
            .route("/aip/v1/sessions/{session_id}/close", post(session_close))
            .route("/aip/v1/sessions/{session_id}/resume", post(session_resume))
            .route("/aip/v1/approvals", get(approval_list))
            .route("/aip/v1/approvals/{approval_id}", get(approval_get))
            .route("/aip/v1/callback-deliveries", get(callback_delivery_list))
            .route(
                "/aip/v1/callback-deliveries/{delivery_id}",
                get(callback_delivery_get),
            )
            .route(
                "/aip/v1/transactions/{transaction_id}",
                get(transaction_get),
            )
            .route(
                "/aip/v1/transactions/by-plan/{plan_id}",
                get(transaction_get_by_plan),
            )
            .route(
                "/aip/v1/transactions/by-action/{action_id}",
                get(transaction_get_by_action),
            )
            .route("/aip/v1/receipts/{chain_id}", get(receipt_get))
            .route(
                "/aip/v1/receipts/by-receipt/{receipt_id}",
                get(receipt_get_by_receipt),
            )
            .route("/aip/v1/audit/events", get(audit_events))
            .route("/aip/v1/resources", get(resource_list))
            .route("/aip/v1/resources/{resource_id}", get(resource_read))
            .route("/aip/v1/capabilities", get(capability_discovery))
            .route("/aip/v1/ws", get(native_websocket))
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_native_http_auth,
            ));
        let mut router = Router::new()
            .route("/", get(health))
            .route("/health", get(health))
            .route("/ready", get(ready))
            .route("/metrics", get(metrics))
            .route("/aip/v1/health", get(health))
            .route("/aip/v1/manifest", get(manifest))
            .route("/aip/v1/messages", post(handle_envelope))
            .route(
                "/aip/v1/connector-events",
                post(handle_connector_events)
                    .layer(DefaultBodyLimit::max(connector_event_max_bytes)),
            )
            .route(
                "/aip/v1/connector-callbacks",
                post(handle_connector_events)
                    .layer(DefaultBodyLimit::max(connector_event_max_bytes)),
            )
            .merge(native_routes)
            .route(
                "/.well-known/oauth-protected-resource",
                get(mcp_protected_resource_metadata),
            )
            .route(
                "/.well-known/oauth-protected-resource/mcp",
                get(mcp_protected_resource_metadata),
            )
            .route(
                "/mcp",
                get(handle_mcp_stream)
                    .post(handle_mcp_jsonrpc)
                    .delete(handle_mcp_session_delete),
            )
            .route(
                "/mcp/v1",
                get(handle_mcp_stream)
                    .post(handle_mcp_jsonrpc)
                    .delete(handle_mcp_session_delete),
            )
            .route(
                "/aip/v1/mcp",
                get(handle_mcp_stream)
                    .post(handle_mcp_jsonrpc)
                    .delete(handle_mcp_session_delete),
            )
            .route("/mcp/legacy/sse", get(handle_legacy_mcp_sse))
            .route("/mcp/legacy/messages", post(handle_legacy_mcp_message))
            .route("/.well-known/agent-card.json", get(a2a_agent_card))
            .route("/.well-known/agent.json", get(a2a_agent_card))
            .route("/a2a/agent-card", get(a2a_agent_card))
            .route("/a2a", post(handle_a2a_jsonrpc))
            .route("/a2a/v1", post(handle_a2a_jsonrpc))
            .route("/aip/v1/a2a", post(handle_a2a_jsonrpc))
            .with_state(state);
        for mount in &self.module_http_mounts {
            router = router.merge(mount.router());
        }
        router
    }

    /// Runs the HTTP listener until the server future exits.
    pub async fn serve(self, bind: SocketAddr) -> std::io::Result<()> {
        let listener = TcpListener::bind(bind).await?;
        let router = self.router();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut fleet_task = match (
            self.fleet_status_provider.clone(),
            self.fleet_supervisor.clone(),
        ) {
            (Some(provider), Some(supervisor)) => {
                let fleet_shutdown = shutdown_rx.clone();
                Some(tokio::spawn(supervise_fleet_status(
                    provider,
                    supervisor,
                    fleet_shutdown,
                )))
            }
            _ => None,
        };
        let worker_id = runtime_worker_id(&self.manifest.agent.id);
        let mut worker_task = tokio::spawn(supervise_runtime_worker(
            self.gateway.runtime(),
            self.mcp_server.clone(),
            self.supervisor.clone(),
            worker_id,
            self.manifest.agent.clone(),
            shutdown_rx.clone(),
        ));
        if let Some(nats) = self.nats.clone() {
            let gateway = self.gateway.clone();
            let supervisor = self.supervisor.clone();
            let mut nats_task = tokio::spawn(async move {
                run_nats_listener(gateway, nats, supervisor, shutdown_rx).await
            });
            let (result, worker_completed, nats_completed) = tokio::select! {
                http_result = axum::serve(listener, router)
                    .with_graceful_shutdown(shutdown_signal()) => (http_result, false, false),
                worker_result = &mut worker_task => (match worker_result {
                    Ok(Ok(())) => Err(std::io::Error::other("runtime worker stopped unexpectedly")),
                    Ok(Err(error)) => Err(std::io::Error::other(error.to_string())),
                    Err(error) => Err(std::io::Error::other(error.to_string())),
                }, true, false),
                nats_result = &mut nats_task => (match nats_result {
                    Ok(Ok(())) => Err(std::io::Error::other("NATS listener stopped unexpectedly")),
                    Ok(Err(error)) => Err(std::io::Error::other(error.to_string())),
                    Err(error) => Err(std::io::Error::other(error.to_string())),
                }, false, true),
            };
            let _ = shutdown_tx.send(true);
            if !worker_completed {
                let _ = tokio::time::timeout(Duration::from_secs(10), worker_task).await;
            }
            if !nats_completed {
                let _ = tokio::time::timeout(Duration::from_secs(10), nats_task).await;
            }
            wait_for_fleet_task(&mut fleet_task).await;
            result
        } else {
            let (result, worker_completed) = tokio::select! {
                http_result = axum::serve(listener, router)
                    .with_graceful_shutdown(shutdown_signal()) => (http_result, false),
                worker_result = &mut worker_task => (match worker_result {
                    Ok(Ok(())) => Err(std::io::Error::other("runtime worker stopped unexpectedly")),
                    Ok(Err(error)) => Err(std::io::Error::other(error.to_string())),
                    Err(error) => Err(std::io::Error::other(error.to_string())),
                }, true),
            };
            let _ = shutdown_tx.send(true);
            if !worker_completed {
                let _ = tokio::time::timeout(Duration::from_secs(10), worker_task).await;
            }
            wait_for_fleet_task(&mut fleet_task).await;
            result
        }
    }
}

async fn wait_for_fleet_task(task: &mut Option<tokio::task::JoinHandle<()>>) {
    if let Some(task) = task {
        let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
    }
}

async fn supervise_fleet_status(
    provider: Arc<dyn ConnectorFleetStatusProvider>,
    supervisor: DaemonFleetSupervisorState,
    mut shutdown: watch::Receiver<bool>,
) {
    supervisor.inner.write().await.worker_running = true;
    let mut backoff = FLEET_MAINTENANCE_INTERVAL;
    loop {
        if *shutdown.borrow() {
            break;
        }
        let observed_at = OffsetDateTime::now_utc();
        let mut expired = 0_usize;
        let mut cycle_error = None;
        for _ in 0..FLEET_EXPIRY_MAX_BATCHES_PER_CYCLE {
            match provider
                .expire_stale_replicas(observed_at, FLEET_EXPIRY_BATCH_SIZE)
                .await
            {
                Ok(count) => {
                    expired = expired.saturating_add(count);
                    if count < FLEET_EXPIRY_BATCH_SIZE {
                        break;
                    }
                }
                Err(error) => {
                    cycle_error = Some(error.to_string());
                    break;
                }
            }
        }
        let summary = if cycle_error.is_none() {
            match provider.fleet_status(observed_at).await {
                Ok(summary) => Some(summary),
                Err(error) => {
                    cycle_error = Some(error.to_string());
                    None
                }
            }
        } else {
            None
        };
        let delay = match (cycle_error, summary) {
            (Some(error), _) => {
                record_fleet_maintenance_failure(&supervisor, &mut backoff, error).await
            }
            (None, Some(summary)) => {
                metrics::gauge!("aip_connector_fleet_ready_replicas")
                    .set(summary.ready_replicas as f64);
                metrics::gauge!("aip_connector_fleet_active_assignments")
                    .set(summary.active_assignments as f64);
                metrics::counter!("aip_connector_fleet_expired_replicas_total")
                    .increment(expired as u64);
                if let Some(pools) = provider.pool_snapshot() {
                    metrics::gauge!("aip_connector_registry_control_pool_connections")
                        .set(f64::from(pools.control_size));
                    metrics::gauge!("aip_connector_registry_control_pool_idle_connections")
                        .set(f64::from(pools.control_idle));
                    metrics::gauge!("aip_connector_registry_control_pool_max_connections")
                        .set(f64::from(pools.control_max));
                    metrics::gauge!("aip_connector_registry_data_pool_connections")
                        .set(f64::from(pools.data_size));
                    metrics::gauge!("aip_connector_registry_data_pool_idle_connections")
                        .set(f64::from(pools.data_idle));
                    metrics::gauge!("aip_connector_registry_data_pool_max_connections")
                        .set(f64::from(pools.data_max));
                }
                let mut state = supervisor.inner.write().await;
                state.consecutive_failures = 0;
                state.expired_last_cycle = expired as u64;
                state.last_error = None;
                state.last_success_at = Some(OffsetDateTime::now_utc());
                state.summary = Some(summary);
                backoff = FLEET_MAINTENANCE_INTERVAL;
                FLEET_MAINTENANCE_INTERVAL
            }
            (None, None) => {
                record_fleet_maintenance_failure(
                    &supervisor,
                    &mut backoff,
                    "fleet maintenance completed without an aggregate summary".to_owned(),
                )
                .await
            }
        };
        let delay = jittered_fleet_delay(delay);
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            () = tokio::time::sleep(delay) => {}
        }
    }
    supervisor.inner.write().await.worker_running = false;
}

fn jittered_fleet_delay(base: Duration) -> Duration {
    let sample = OsRng.next_u64();
    jittered_fleet_delay_with_sample(base, sample)
}

fn jittered_fleet_delay_with_sample(base: Duration, sample: u64) -> Duration {
    // Full-width deterministic sampling across +/-20% avoids synchronized
    // maintenance storms while retaining a bounded upper delay for readiness.
    let base_ms = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
    let spread = base_ms.saturating_div(5).max(1);
    let width = spread.saturating_mul(2).saturating_add(1);
    let offset = sample % width;
    Duration::from_millis(base_ms.saturating_sub(spread).saturating_add(offset))
}

async fn record_fleet_maintenance_failure(
    supervisor: &DaemonFleetSupervisorState,
    backoff: &mut Duration,
    error: String,
) -> Duration {
    warn!(error = %error, "connector fleet maintenance cycle failed");
    let mut state = supervisor.inner.write().await;
    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    state.last_error = Some(bounded_operational_detail(error));
    metrics::counter!("aip_connector_fleet_maintenance_failures_total").increment(1);
    let delay = *backoff;
    *backoff = backoff.saturating_mul(2).min(FLEET_MAINTENANCE_MAX_BACKOFF);
    delay
}

fn bounded_operational_detail(mut detail: String) -> String {
    detail.truncate(1_024);
    detail
}

fn runtime_worker_id(service_id: &PrincipalId) -> String {
    // A service principal identifies the logical daemon deployment, not one
    // process incarnation. Lease owners must change on every boot so a
    // restarted process can never renew or settle work fenced to its
    // predecessor, including when both processes share the same service id.
    format!("getaip-server:{service_id}:{}", uuid::Uuid::now_v7())
}

/// NATS listener error.
#[derive(Debug)]
pub enum NatsListenerError {
    /// Transport failed.
    Transport(TransportError),
}

impl fmt::Display for NatsListenerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for NatsListenerError {}

impl From<TransportError> for NatsListenerError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

async fn run_nats_listener(
    gateway: Gateway,
    config: AipDaemonNatsConfig,
    supervisor: DaemonSupervisorState,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), NatsListenerError> {
    let transport = NatsTransport::connect(config.transport_config()).await?;
    let mut subscriber = if let Some(queue_group) = &config.queue_group {
        transport
            .queue_subscribe_service(queue_group.clone())
            .await?
    } else {
        transport.subscribe_service().await?
    };
    supervisor.inner.write().await.nats_listener_running = true;
    metrics::gauge!("aip_nats_listener_up").set(1.0);
    loop {
        let message = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            message = subscriber.next() => message,
        };
        let Some(message) = message else {
            break;
        };
        let reply = message.reply.clone();
        let response = match transport_message_from_nats(message).await {
            Ok(message) => match handle_gateway_envelope(&gateway, message.envelope).await {
                Ok(response) => response,
                Err(error) => Gateway::error_envelope(&error),
            },
            Err(error) => transport_error_envelope(error),
        };
        if let Some(reply) = reply {
            transport
                .respond_to(reply, TransportMessage::new(response))
                .await?;
        }
    }
    supervisor.inner.write().await.nats_listener_running = false;
    metrics::gauge!("aip_nats_listener_up").set(0.0);
    Ok(())
}

async fn supervise_runtime_worker(
    runtime: Runtime,
    mcp_server: McpServer,
    supervisor: DaemonSupervisorState,
    worker_id: String,
    worker_principal: Principal,
    mut shutdown: watch::Receiver<bool>,
) -> RuntimeResult<()> {
    loop {
        if *shutdown.borrow() {
            supervisor.inner.write().await.runtime_worker_running = false;
            return Ok(());
        }
        let child = tokio::spawn(runtime_worker_loop(
            runtime.clone(),
            mcp_server.clone(),
            supervisor.clone(),
            worker_id.clone(),
            worker_principal.clone(),
            shutdown.clone(),
        ));
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    supervisor.inner.write().await.runtime_worker_running = false;
                    return Ok(());
                }
            }
            result = child => {
                let error = match result {
                    Ok(Ok(())) => "runtime worker exited before shutdown".to_owned(),
                    Ok(Err(error)) => error.to_string(),
                    Err(error) => format!("runtime worker task failed: {error}"),
                };
                {
                    let mut state = supervisor.inner.write().await;
                    state.runtime_worker_running = false;
                    state.last_worker_error = Some(error);
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

async fn runtime_worker_loop(
    runtime: Runtime,
    mcp_server: McpServer,
    supervisor: DaemonSupervisorState,
    worker_id: String,
    worker_principal: Principal,
    mut shutdown: watch::Receiver<bool>,
) -> RuntimeResult<()> {
    supervisor.inner.write().await.runtime_worker_running = true;
    metrics::gauge!("aip_runtime_worker_up").set(1.0);
    let mut next_maintenance_at = OffsetDateTime::now_utc();
    loop {
        if *shutdown.borrow() {
            supervisor.inner.write().await.runtime_worker_running = false;
            metrics::gauge!("aip_runtime_worker_up").set(0.0);
            return Ok(());
        }
        let report = runtime
            .run_queue_worker_until_idle(QueueWorkerConfig {
                worker_id: worker_id.clone(),
                lease_ttl_ms: 30_000,
                idle_sleep_ms: 0,
                max_idle_polls: 1,
                max_claims: Some(64),
            })
            .await?;
        let mut last_error = report.last_error;
        for expiration in runtime.expire_pending_approvals().await? {
            if let Err(error) = expiration {
                last_error = Some(error.to_string());
            }
        }
        for transition in runtime
            .recover_approval_transitions(&format!("{worker_id}:approval-outbox"), 30_000)
            .await?
        {
            if let Err(error) = transition {
                last_error = Some(error.to_string());
            }
        }
        runtime.recover_callback_deliveries().await?;
        let work_budgets = runtime.work_budget_snapshot();
        metrics::gauge!("aip_runtime_callback_capacity")
            .set(work_budgets.callback_max_in_flight as f64);
        metrics::gauge!("aip_runtime_callback_available")
            .set(work_budgets.callback_available as f64);
        metrics::gauge!("aip_runtime_reconciliation_capacity")
            .set(work_budgets.reconciliation_max_in_flight as f64);
        metrics::gauge!("aip_runtime_reconciliation_available")
            .set(work_budgets.reconciliation_available as f64);
        if let Err(error) = dispatch_a2a_push_updates(&runtime, &worker_id, &worker_principal).await
        {
            last_error = Some(error.to_string());
        }
        if let Err(error) = project_mcp_notifications_once(&runtime, &mcp_server, &worker_id).await
        {
            last_error = Some(error.to_string());
        }
        let now = OffsetDateTime::now_utc();
        if now >= next_maintenance_at {
            let retention = runtime
                .maintenance
                .apply_retention(RuntimeRetentionPolicy::default(), now)
                .await?;
            metrics::counter!("aip_retention_events_deleted_total")
                .increment(retention.events_deleted);
            metrics::counter!("aip_retention_replay_claims_deleted_total")
                .increment(retention.replay_claims_deleted);
            metrics::counter!("aip_retention_dead_letters_deleted_total")
                .increment(retention.dead_letters_deleted);
            metrics::counter!("aip_retention_callback_deliveries_deleted_total")
                .increment(retention.callback_deliveries_deleted);
            metrics::counter!("aip_retention_outbox_records_deleted_total")
                .increment(retention.outbox_records_deleted);
            next_maintenance_at = now + time::Duration::hours(1);
        }
        metrics::counter!("aip_runtime_worker_cycles_total").increment(1);
        metrics::counter!("aip_runtime_worker_claimed_actions_total")
            .increment(u64::from(report.claimed));
        {
            let mut state = supervisor.inner.write().await;
            state.runtime_worker_running = true;
            state.worker_cycles = state.worker_cycles.saturating_add(1);
            state.last_worker_success_at = Some(OffsetDateTime::now_utc());
            state.last_worker_error = last_error;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    supervisor.inner.write().await.runtime_worker_running = false;
                    return Ok(());
                }
            }
        }
    }
}

#[derive(Clone)]
struct McpNotificationClaim {
    key: String,
    record: McpNotificationDelivery,
    revision: u64,
    lease_id: String,
}

fn mcp_projection_error(error: impl fmt::Display) -> RuntimeError {
    RuntimeError::Storage(format!("MCP notification projection failed: {error}"))
}

async fn project_mcp_notifications_once(
    runtime: &Runtime,
    server: &McpServer,
    worker_id: &str,
) -> RuntimeResult<()> {
    let cursor_key = format!("worker:{worker_id}");
    let cursor = runtime
        .profile_state
        .get(MCP_NOTIFICATION_CURSORS_NAMESPACE, &cursor_key)
        .await?
        .and_then(|entry| {
            entry
                .value
                .get("cursor")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let stream = runtime
        .events
        .stream(&EventStreamRequest {
            cursor,
            limit: Some(100),
            kinds: Vec::new(),
        })
        .await?;
    let sessions = server.session_states().await;
    for event in &stream.events {
        let notifications = mcp_notifications_from_event(runtime, event).await?;
        if notifications.is_empty() {
            continue;
        }
        for notification in notifications {
            let method = notification.method.parse::<McpMethod>().map_err(|error| {
                RuntimeError::Handler(format!("MCP projection method failed: {error}"))
            })?;
            let resource_uri = (method == McpMethod::ResourcesUpdated)
                .then(|| {
                    notification
                        .params
                        .as_ref()
                        .and_then(|params| params.get("uri"))
                        .and_then(Value::as_str)
                })
                .flatten();
            for (session_id, state) in &sessions {
                if state.authorize_outbound_notification(method).is_err() {
                    continue;
                }
                if let Some(uri) = resource_uri
                    && !server
                        .session_has_resource_subscription(session_id, uri)
                        .await
                {
                    continue;
                }
                let Some(claim) = claim_mcp_notification_delivery(
                    runtime,
                    event,
                    session_id,
                    &notification.method,
                    worker_id,
                )
                .await?
                else {
                    let delivery =
                        mcp_notification_delivery(runtime, event, session_id, &notification.method)
                            .await?;
                    if delivery.is_some_and(|delivery| {
                        delivery.status == McpNotificationDeliveryStatus::Leased
                            && delivery
                                .lease_expires_at
                                .is_some_and(|expires_at| expires_at > OffsetDateTime::now_utc())
                    }) {
                        return Err(RuntimeError::Storage(format!(
                            "MCP notification {} is leased by another worker",
                            event.id
                        )));
                    }
                    continue;
                };
                match server.notify_client(session_id, notification.clone()).await {
                    Ok(()) => settle_mcp_notification_delivery(runtime, claim, None).await?,
                    Err(error) => {
                        settle_mcp_notification_delivery(runtime, claim, Some(error.to_string()))
                            .await?;
                        return Err(RuntimeError::Handler(format!(
                            "MCP notification delivery failed: {error}"
                        )));
                    }
                }
            }
        }
    }
    if let Some(cursor) = stream.next_cursor {
        runtime
            .profile_state
            .put(
                MCP_NOTIFICATION_CURSORS_NAMESPACE,
                &cursor_key,
                json!({ "cursor": cursor, "updated_at": OffsetDateTime::now_utc() }),
            )
            .await?;
    }
    Ok(())
}

async fn mcp_notifications_from_event(
    runtime: &Runtime,
    event: &Event,
) -> RuntimeResult<Vec<JsonRpcNotification>> {
    match event.kind.as_str() {
        "aip.stream.chunk" => {
            let Some(action_id) = event.action_id.as_ref() else {
                return Ok(Vec::new());
            };
            let sequence = event
                .data
                .as_ref()
                .and_then(|data| data.get("sequence"))
                .and_then(Value::as_u64);
            let chunks = runtime.lifecycle.stream_chunks(action_id).await?;
            Ok(chunks
                .into_iter()
                .find(|chunk| sequence.is_none_or(|sequence| chunk.sequence == sequence))
                .map(|chunk| vec![progress_notification(json!(action_id), &chunk)])
                .unwrap_or_default())
        }
        "aip.action.result" => {
            let Some(action_id) = event.action_id.as_ref() else {
                return Ok(Vec::new());
            };
            Ok(runtime
                .lifecycle
                .action_result(action_id)
                .await?
                .map(|result| {
                    vec![JsonRpcNotification::new(
                        McpMethod::TasksStatus,
                        Some(
                            serde_json::to_value(aip_profile_mcp::task_from_action_result(
                                action_id.to_string(),
                                &result,
                            ))
                            .unwrap_or_else(|_| json!({ "taskId": action_id })),
                        ),
                    )]
                })
                .unwrap_or_default())
        }
        "aip.discovery.manifest_admitted" => {
            let data = event.data.as_ref();
            let capability_changed = data.is_some_and(|data| {
                json_array_is_non_empty(data, "added_capability_ids")
                    || json_array_is_non_empty(data, "removed_capability_ids")
            });
            let resource_changed = data.is_some_and(|data| {
                json_array_is_non_empty(data, "added_resource_ids")
                    || json_array_is_non_empty(data, "removed_resource_ids")
            });
            let mut notifications = Vec::new();
            if capability_changed {
                notifications.push(tools_changed_notification());
            }
            if resource_changed {
                notifications.push(resources_changed_notification());
            }
            Ok(notifications)
        }
        "aip.discovery.manifest_registered"
        | "aip.discovery.capability_registered"
        | "aip.discovery.capability_removed" => Ok(vec![tools_changed_notification()]),
        "aip.discovery.resource_registered" | "aip.discovery.resource_removed" => {
            Ok(vec![resources_changed_notification()])
        }
        "aip.resource.updated" => Ok(event
            .data
            .as_ref()
            .and_then(|data| data.get("uri"))
            .and_then(Value::as_str)
            .map(resource_updated_notification)
            .into_iter()
            .collect()),
        _ => Ok(Vec::new()),
    }
}

fn json_array_is_non_empty(value: &Value, field: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty())
}

fn mcp_notification_delivery_key(event: &Event, session_id: &str, method: &str) -> String {
    hex::encode(Sha256::digest(
        format!("{}\u{1f}{session_id}\u{1f}{method}", event.id).as_bytes(),
    ))
}

async fn mcp_notification_delivery(
    runtime: &Runtime,
    event: &Event,
    session_id: &str,
    method: &str,
) -> RuntimeResult<Option<McpNotificationDelivery>> {
    runtime
        .profile_state
        .get(
            MCP_NOTIFICATION_DELIVERIES_NAMESPACE,
            &mcp_notification_delivery_key(event, session_id, method),
        )
        .await?
        .map(|entry| {
            serde_json::from_value(entry.value).map_err(|error| {
                RuntimeError::Storage(format!("MCP delivery state decode failed: {error}"))
            })
        })
        .transpose()
}

async fn claim_mcp_notification_delivery(
    runtime: &Runtime,
    event: &Event,
    session_id: &str,
    method: &str,
    worker_id: &str,
) -> RuntimeResult<Option<McpNotificationClaim>> {
    let key = mcp_notification_delivery_key(event, session_id, method);
    let now = OffsetDateTime::now_utc();
    let initial = McpNotificationDelivery {
        event_id: event.id.to_string(),
        session_id: session_id.to_owned(),
        method: method.to_owned(),
        status: McpNotificationDeliveryStatus::Pending,
        attempts: 0,
        lease_owner: None,
        lease_id: None,
        lease_expires_at: None,
        next_attempt_at: now,
        last_error: None,
        updated_at: now,
    };
    let _ = runtime
        .profile_state
        .create(
            MCP_NOTIFICATION_DELIVERIES_NAMESPACE,
            &key,
            serde_json::to_value(&initial).map_err(mcp_projection_error)?,
        )
        .await?;
    for _ in 0..32 {
        let Some(entry) = runtime
            .profile_state
            .get(MCP_NOTIFICATION_DELIVERIES_NAMESPACE, &key)
            .await?
        else {
            return Err(RuntimeError::Storage(
                "MCP notification delivery disappeared".to_owned(),
            ));
        };
        let mut record = serde_json::from_value::<McpNotificationDelivery>(entry.value)
            .map_err(mcp_projection_error)?;
        let now = OffsetDateTime::now_utc();
        let eligible = match record.status {
            McpNotificationDeliveryStatus::Pending => record.next_attempt_at <= now,
            McpNotificationDeliveryStatus::Leased => record
                .lease_expires_at
                .is_none_or(|expires_at| expires_at <= now),
            McpNotificationDeliveryStatus::Delivered
            | McpNotificationDeliveryStatus::DeadLettered => false,
        };
        if !eligible {
            return Ok(None);
        }
        let lease_id = format!("mcp-notification:{}", ActionId::new());
        record.status = McpNotificationDeliveryStatus::Leased;
        record.attempts = record.attempts.saturating_add(1);
        record.lease_owner = Some(worker_id.to_owned());
        record.lease_id = Some(lease_id.clone());
        record.lease_expires_at = Some(now + time::Duration::seconds(30));
        record.updated_at = now;
        match runtime
            .profile_state
            .compare_and_set(
                MCP_NOTIFICATION_DELIVERIES_NAMESPACE,
                &key,
                Some(entry.revision),
                serde_json::to_value(&record).map_err(mcp_projection_error)?,
            )
            .await?
        {
            ProfileStateCasOutcome::Applied(applied) => {
                return Ok(Some(McpNotificationClaim {
                    key,
                    record,
                    revision: applied.revision,
                    lease_id,
                }));
            }
            ProfileStateCasOutcome::Conflict(_) => tokio::task::yield_now().await,
        }
    }
    Err(RuntimeError::Storage(
        "MCP notification delivery remained contended".to_owned(),
    ))
}

async fn settle_mcp_notification_delivery(
    runtime: &Runtime,
    claim: McpNotificationClaim,
    error: Option<String>,
) -> RuntimeResult<()> {
    let mut record = claim.record;
    if record.lease_id.as_deref() != Some(&claim.lease_id) {
        return Err(RuntimeError::Storage(
            "MCP notification lease token changed".to_owned(),
        ));
    }
    let now = OffsetDateTime::now_utc();
    record.status = if error.is_none() {
        McpNotificationDeliveryStatus::Delivered
    } else if record.attempts >= 5 {
        McpNotificationDeliveryStatus::DeadLettered
    } else {
        McpNotificationDeliveryStatus::Pending
    };
    record.next_attempt_at = now
        + time::Duration::milliseconds(
            250_i64.saturating_mul(1_i64 << record.attempts.saturating_sub(1).min(7)),
        );
    record.last_error = error;
    record.lease_owner = None;
    record.lease_id = None;
    record.lease_expires_at = None;
    record.updated_at = now;
    match runtime
        .profile_state
        .compare_and_set(
            MCP_NOTIFICATION_DELIVERIES_NAMESPACE,
            &claim.key,
            Some(claim.revision),
            serde_json::to_value(record).map_err(mcp_projection_error)?,
        )
        .await?
    {
        ProfileStateCasOutcome::Applied(_) => Ok(()),
        ProfileStateCasOutcome::Conflict(_) => Err(RuntimeError::Storage(
            "MCP notification lease was lost before settlement".to_owned(),
        )),
    }
}

async fn dispatch_a2a_push_updates(
    runtime: &Runtime,
    worker_id: &str,
    worker_principal: &Principal,
) -> RuntimeResult<()> {
    let configs = runtime
        .profile_state
        .list(A2A_PUSH_CONFIGS_NAMESPACE, None)
        .await?;
    let mut last_error = None;
    for entry in configs {
        let stored = match serde_json::from_value::<StoredA2aPushConfig>(entry.value) {
            Ok(stored) => stored,
            Err(error) => {
                last_error = Some(RuntimeError::Storage(format!(
                    "stored A2A push config `{}` is invalid: {error}",
                    entry.key
                )));
                continue;
            }
        };
        let Some((mut cursor, mut revision)) =
            claim_a2a_push_cursor(runtime, &stored, worker_id).await?
        else {
            continue;
        };
        if let Err(error) = dispatch_one_a2a_push_config(
            runtime,
            &stored,
            &mut cursor,
            &mut revision,
            worker_id,
            worker_principal,
        )
        .await
        {
            last_error = Some(error);
        }
    }
    match last_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn claim_a2a_push_cursor(
    runtime: &Runtime,
    config: &StoredA2aPushConfig,
    worker_id: &str,
) -> RuntimeResult<Option<(A2aPushCursor, u64)>> {
    let key = a2a_push_config_key(&config.config.task_id, &config.config.id);
    for _ in 0..32 {
        let current = runtime
            .profile_state
            .get(A2A_PUSH_CURSORS_NAMESPACE, &key)
            .await?;
        let expected_revision = current.as_ref().map(|entry| entry.revision);
        let mut cursor = current
            .as_ref()
            .map(|entry| serde_json::from_value::<A2aPushCursor>(entry.value.clone()))
            .transpose()
            .map_err(|error| {
                RuntimeError::Storage(format!("stored A2A push cursor is invalid: {error}"))
            })?
            .unwrap_or_else(|| A2aPushCursor::new(config));
        let now = OffsetDateTime::now_utc();
        if cursor
            .lease_owner
            .as_deref()
            .is_some_and(|owner| owner != worker_id)
            && cursor
                .lease_expires_at
                .is_some_and(|expires_at| expires_at > now)
        {
            return Ok(None);
        }
        cursor.lease_owner = Some(worker_id.to_owned());
        cursor.lease_expires_at = Some(now + time::Duration::seconds(30));
        cursor.fencing_token = cursor.fencing_token.saturating_add(1);
        let value = serde_json::to_value(&cursor).map_err(|error| {
            RuntimeError::Storage(format!("A2A push cursor encode failed: {error}"))
        })?;
        match runtime
            .profile_state
            .compare_and_set(A2A_PUSH_CURSORS_NAMESPACE, &key, expected_revision, value)
            .await?
        {
            ProfileStateCasOutcome::Applied(entry) => {
                return Ok(Some((cursor, entry.revision)));
            }
            ProfileStateCasOutcome::Conflict(_) => tokio::task::yield_now().await,
        }
    }
    Err(RuntimeError::Storage(format!(
        "A2A push cursor `{key}` remained contended during lease claim"
    )))
}

async fn dispatch_one_a2a_push_config(
    runtime: &Runtime,
    config: &StoredA2aPushConfig,
    cursor: &mut A2aPushCursor,
    revision: &mut u64,
    worker_id: &str,
    worker_principal: &Principal,
) -> RuntimeResult<()> {
    let task = runtime
        .profile_state
        .get(A2A_TASKS_NAMESPACE, &config.config.task_id)
        .await?;
    let Some(action_id) = task
        .as_ref()
        .and_then(|entry| entry.value.pointer("/metadata/aip/action_id"))
        .and_then(Value::as_str)
    else {
        release_a2a_push_cursor(runtime, config, cursor, revision, worker_id).await?;
        return Ok(());
    };
    let action_id = ActionId::parse(action_id.to_owned())
        .map_err(|error| RuntimeError::Storage(format!("invalid A2A task action id: {error}")))?;
    let status = runtime
        .profile_action_status_projection(ActionStatusRequest {
            action_id: action_id.clone(),
            tenant_id: config.config.tenant.clone(),
            include_result: true,
            include_receipts: false,
            include_chunks: true,
            wait_ms: None,
        })
        .await?;
    let skill_id = skill_id_from_action_status(&status);
    let context_id = task
        .as_ref()
        .and_then(|entry| entry.value.get("contextId"))
        .and_then(Value::as_str)
        .unwrap_or(&config.config.task_id)
        .to_owned();
    let mut chunks = status
        .chunks
        .iter()
        .filter(|chunk| {
            cursor
                .last_chunk_sequence
                .is_none_or(|sequence| chunk.sequence > sequence)
        })
        .cloned()
        .collect::<Vec<_>>();
    chunks.sort_by_key(|chunk| chunk.sequence);
    for chunk in chunks {
        let payload = json!({
            "artifactUpdate": aip_profile_a2a::artifact_update_from_stream_chunk(
                config.config.task_id.clone(),
                context_id.clone(),
                &chunk,
            )
        });
        dispatch_a2a_push_payload(
            runtime,
            config,
            &status,
            payload,
            &format!("chunk-{}", chunk.sequence),
            worker_principal,
        )
        .await?;
        cursor.last_chunk_sequence = Some(chunk.sequence);
        renew_a2a_push_cursor(runtime, config, cursor, revision, worker_id, false).await?;
    }
    if cursor.last_state != Some(status.state) {
        let task = aip_profile_a2a::task_from_action_status(
            config.config.task_id.clone(),
            skill_id,
            &status,
        );
        let payload = json!({
            "statusUpdate": {
                "taskId": config.config.task_id,
                "contextId": context_id,
                "status": task.status,
                "metadata": {
                    "aip": {
                        "actionId": action_id,
                        "fencingToken": cursor.fencing_token
                    }
                }
            }
        });
        dispatch_a2a_push_payload(
            runtime,
            config,
            &status,
            payload,
            &format!("state-{:?}", status.state).to_ascii_lowercase(),
            worker_principal,
        )
        .await?;
        cursor.last_state = Some(status.state);
        renew_a2a_push_cursor(runtime, config, cursor, revision, worker_id, false).await?;
    }
    release_a2a_push_cursor(runtime, config, cursor, revision, worker_id).await
}

async fn dispatch_a2a_push_payload(
    runtime: &Runtime,
    config: &StoredA2aPushConfig,
    status: &ActionStatus,
    payload: Value,
    discriminator: &str,
    worker_principal: &Principal,
) -> RuntimeResult<()> {
    let mut callback = a2a_callback_from_stored_config(config, None);
    if let Some(a2a) = callback
        .metadata
        .as_mut()
        .and_then(|metadata| metadata.get_mut("a2a"))
        .and_then(Value::as_object_mut)
    {
        a2a.insert("payload".to_owned(), payload);
    }
    let mut envelope = Envelope::new(MessageBody::ActionStatus(Box::new(status.clone())));
    let message_id = format!(
        "msg_a2a_{}_{}_{}",
        hex::encode(config.config.task_id.as_bytes()),
        hex::encode(config.config.id.as_bytes()),
        discriminator.replace(|character: char| !character.is_ascii_alphanumeric(), "_")
    );
    envelope.message_id = aip_core::MessageId::parse(message_id).map_err(|error| {
        RuntimeError::Handler(format!("A2A callback message id failed: {error}"))
    })?;
    envelope.idempotency_key = Some(format!(
        "a2a-push:{}:{}:{discriminator}",
        config.config.task_id, config.config.id
    ));
    envelope.from = Some(worker_principal.clone());
    let delivery = runtime
        .dispatch_profile_callback(
            &callback,
            envelope,
            aip_runtime::MessageContext {
                session_id: status.session_id.clone(),
                correlation_id: status.correlation_id.clone(),
                actor: Some(worker_principal.clone()),
                ..aip_runtime::MessageContext::default()
            },
        )
        .await?;
    if delivery.status == CallbackDeliveryStatus::DeadLettered {
        return Err(RuntimeError::Handler(format!(
            "A2A push delivery `{}` was dead-lettered",
            delivery.delivery_id
        )));
    }
    if delivery.status != CallbackDeliveryStatus::Delivered {
        return Err(RuntimeError::Handler(format!(
            "A2A push delivery `{}` did not reach a terminal success state",
            delivery.delivery_id
        )));
    }
    Ok(())
}

async fn renew_a2a_push_cursor(
    runtime: &Runtime,
    config: &StoredA2aPushConfig,
    cursor: &mut A2aPushCursor,
    revision: &mut u64,
    worker_id: &str,
    release: bool,
) -> RuntimeResult<()> {
    if cursor.lease_owner.as_deref() != Some(worker_id) {
        return Err(RuntimeError::Storage(
            "A2A push cursor fencing owner changed during delivery".to_owned(),
        ));
    }
    if release {
        cursor.lease_owner = None;
        cursor.lease_expires_at = None;
    } else {
        cursor.lease_expires_at = Some(OffsetDateTime::now_utc() + time::Duration::seconds(30));
    }
    let key = a2a_push_config_key(&config.config.task_id, &config.config.id);
    let value = serde_json::to_value(&*cursor).map_err(|error| {
        RuntimeError::Storage(format!("A2A push cursor encode failed: {error}"))
    })?;
    match runtime
        .profile_state
        .compare_and_set(A2A_PUSH_CURSORS_NAMESPACE, &key, Some(*revision), value)
        .await?
    {
        ProfileStateCasOutcome::Applied(entry) => {
            *revision = entry.revision;
            Ok(())
        }
        ProfileStateCasOutcome::Conflict(_) => Err(RuntimeError::Storage(format!(
            "A2A push cursor `{key}` lost its fencing revision"
        ))),
    }
}

async fn release_a2a_push_cursor(
    runtime: &Runtime,
    config: &StoredA2aPushConfig,
    cursor: &mut A2aPushCursor,
    revision: &mut u64,
    worker_id: &str,
) -> RuntimeResult<()> {
    renew_a2a_push_cursor(runtime, config, cursor, revision, worker_id, true).await
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        if let Ok(mut terminate) = terminate {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[derive(Clone)]
struct AppState {
    gateway: Gateway,
    manifest: Manifest,
    mcp_server: McpServer,
    started_at: Instant,
    native_http_auth: Option<NativeHttpAuthConfig>,
    allow_insecure_development: bool,
    callback_policy: GatewayCallbackPolicy,
    mcp_protected_resource: Option<McpProtectedResourceConfig>,
    mcp_sse_replay: SharedMcpSseReplay,
    mcp_http_session_owners: Arc<RwLock<BTreeMap<String, String>>>,
    mcp_legacy_sessions: LegacySessionRegistry,
    mcp_peer_transport: DaemonMcpPeerTransport,
    mcp_token_verifier: Option<Arc<dyn TokenVerifier>>,
    mcp_principal: Principal,
    profile_state: ProfileStateStore,
    a2a_interface_url: String,
    supervisor: DaemonSupervisorState,
    prometheus: PrometheusHandle,
    module_statuses: BTreeMap<String, LocalModuleStatus>,
    fleet_supervisor: Option<DaemonFleetSupervisorState>,
    remote_admission: Option<FairAdmissionScheduler>,
    connector_event_ingress: Option<ConnectorEventIngress>,
    capability_catalog: Option<Arc<dyn CapabilityCatalogProvider>>,
    capability_discovery_url: String,
}

#[derive(Clone, Debug)]
struct NativeRequestIdentity {
    principal: Principal,
    tenant_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CapabilityDiscoveryQuery {
    capability_id: Option<String>,
    text: Option<String>,
    profile: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn require_native_http_auth(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    match native_bearer_actor(&state, request.headers()) {
        Ok(Some(principal)) => {
            let tenant_id = state
                .native_http_auth
                .as_ref()
                .and_then(|auth| auth.tenant_id.clone());
            request.extensions_mut().insert(NativeRequestIdentity {
                principal,
                tenant_id,
            });
            next.run(request).await
        }
        Ok(None) => native_unauthorized_response("missing bearer token"),
        Err(error) => error.into_response(),
    }
}

async fn capability_discovery(
    State(state): State<AppState>,
    Extension(identity): Extension<NativeRequestIdentity>,
    Query(query): Query<CapabilityDiscoveryQuery>,
) -> Response {
    let Some(catalog) = state.capability_catalog.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "connector_catalog.disabled" } })),
        )
            .into_response();
    };
    let Some(tenant_id) = identity.tenant_id.as_ref() else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": {
                    "code": "connector_catalog.tenant_required",
                    "principal_id": identity.principal.id,
                }
            })),
        )
            .into_response();
    };
    let capability_id = match query.capability_id.as_deref().map(CapabilityId::parse) {
        Some(Ok(value)) => Some(value),
        Some(Err(error)) => {
            return catalog_error_response(
                StatusCode::BAD_REQUEST,
                "connector_catalog.invalid_query",
                error.to_string(),
            );
        }
        None => None,
    };
    let profile = match query.profile.as_deref().map(ProfileId::parse) {
        Some(Ok(value)) => Some(value),
        Some(Err(error)) => {
            return catalog_error_response(
                StatusCode::BAD_REQUEST,
                "connector_catalog.invalid_query",
                error.to_string(),
            );
        }
        None => None,
    };
    let request = CapabilityCatalogQuery {
        capability_id,
        text: query.text,
        profile,
        cursor: query.cursor,
        limit: query.limit.unwrap_or(100),
    };
    match catalog
        .query(request, &CatalogReadContext::for_tenant(tenant_id.clone()))
        .await
    {
        Ok(page) => Json(page).into_response(),
        Err(aip_connector_registry::RegistryError::StaleCursor) => catalog_error_response(
            StatusCode::CONFLICT,
            "connector_catalog.stale_cursor",
            "catalog changed; restart pagination from the first page".to_owned(),
        ),
        Err(aip_connector_registry::RegistryError::Invalid(message)) => catalog_error_response(
            StatusCode::BAD_REQUEST,
            "connector_catalog.invalid_query",
            message,
        ),
        Err(error) => {
            warn!(error = %error, "tenant capability discovery failed");
            catalog_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "connector_catalog.unavailable",
                "connector capability catalog is temporarily unavailable".to_owned(),
            )
        }
    }
}

fn catalog_error_response(status: StatusCode, code: &'static str, message: String) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message } })),
    )
        .into_response()
}

#[derive(Debug)]
struct NativeAuthError {
    message: String,
}

impl NativeAuthError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn into_response(self) -> Response {
        native_unauthorized_response(self.message)
    }
}

fn native_bearer_actor(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<Principal>, NativeAuthError> {
    let presented = bearer_token(headers)
        .map_err(|error| NativeAuthError::new(format!("invalid authorization header: {error}")))?;
    if let Some(auth) = &state.native_http_auth {
        return match presented {
            Some(token)
                if constant_time_eq::constant_time_eq(
                    auth.bearer_token.as_bytes(),
                    token.as_bytes(),
                ) =>
            {
                Ok(Some(auth.principal.clone()))
            }
            Some(_) => Err(NativeAuthError::new("invalid bearer token")),
            None if state.allow_insecure_development => Ok(Some(state.manifest.agent.clone())),
            None => Ok(None),
        };
    }
    if presented.is_some() {
        return Err(NativeAuthError::new(
            "native bearer authentication is not configured",
        ));
    }
    Ok(state
        .allow_insecure_development
        .then(|| state.manifest.agent.clone()))
}

fn native_edge_actor(state: &AppState) -> Result<Principal, NativeAuthError> {
    state
        .native_http_auth
        .as_ref()
        .map(|auth| auth.principal.clone())
        .or_else(|| {
            state
                .allow_insecure_development
                .then(|| state.manifest.agent.clone())
        })
        .ok_or_else(|| NativeAuthError::new("native HTTP authentication is required"))
}

fn native_unauthorized_response(message: impl Into<String>) -> Response {
    protocol_error_response(
        StatusCode::UNAUTHORIZED,
        ProtocolError {
            code: "auth.native_http_unauthorized".to_owned(),
            message: message.into(),
            category: ErrorCategory::Auth,
            retryable: Some(false),
            retry_after_ms: None,
            details: None,
            source: Some(Box::new(json!({ "component": "aip.server.native_http" }))),
        },
    )
}

#[derive(Clone)]
struct BuiltInHealthHandler {
    started_at: Instant,
}

#[async_trait::async_trait]
impl ActionHandler for BuiltInHealthHandler {
    fn implementation_support(&self) -> aip_discovery::CapabilityImplementationSupport {
        aip_discovery::CapabilityImplementationSupport {
            invocation: true,
            retry: true,
            ..aip_discovery::CapabilityImplementationSupport::default()
        }
    }

    async fn handle(&self, action: Action) -> RuntimeResult<ActionResult> {
        Ok(ActionResult {
            action_id: action.id,
            status: ActionResultStatus::Completed,
            output: Some(health_payload(self.started_at)),
            message: vec![MessagePart::text("getaip-server is healthy")],
            memory_update: None,
            usage: None,
            receipt: None,
            error: None,
        })
    }
}

#[derive(Clone)]
struct CapabilityCatalogQueryHandler {
    catalog: Arc<dyn CapabilityCatalogProvider>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityCatalogActionInput {
    capability_id: Option<String>,
    text: Option<String>,
    profile: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}

#[async_trait::async_trait]
impl ActionHandler for CapabilityCatalogQueryHandler {
    fn implementation_support(&self) -> aip_discovery::CapabilityImplementationSupport {
        aip_discovery::CapabilityImplementationSupport {
            invocation: true,
            retry: true,
            ..aip_discovery::CapabilityImplementationSupport::default()
        }
    }

    async fn handle(&self, _action: Action) -> RuntimeResult<ActionResult> {
        Err(RuntimeError::Authorization(
            "connector capability discovery requires a verified tenant execution context"
                .to_owned(),
        ))
    }

    async fn handle_with_context(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> RuntimeResult<ActionResult> {
        let tenant = context.tenant.as_ref().ok_or_else(|| {
            RuntimeError::Authorization(
                "connector capability discovery requires a verified tenant".to_owned(),
            )
        })?;
        let input: CapabilityCatalogActionInput = serde_json::from_value(action.input.clone())
            .map_err(|error| {
                RuntimeError::Handler(format!(
                    "connector capability discovery input is invalid: {error}"
                ))
            })?;
        validate_catalog_action_input(&input)?;
        let capability_id = input
            .capability_id
            .map(CapabilityId::parse)
            .transpose()
            .map_err(|error| RuntimeError::Handler(error.to_string()))?;
        let profile = input
            .profile
            .map(ProfileId::parse)
            .transpose()
            .map_err(|error| RuntimeError::Handler(error.to_string()))?;
        let query = CapabilityCatalogQuery {
            capability_id,
            text: input.text,
            profile,
            cursor: input.cursor,
            limit: input.limit.unwrap_or(100),
        };
        let page = self
            .catalog
            .query(
                query,
                &CatalogReadContext::for_tenant(tenant.tenant.id.clone()),
            )
            .await
            .map_err(|error| match error {
                aip_connector_registry::RegistryError::StaleCursor => RuntimeError::Handler(
                    "connector capability catalog changed; restart pagination".to_owned(),
                ),
                aip_connector_registry::RegistryError::Invalid(message) => RuntimeError::Handler(
                    format!("connector capability discovery query is invalid: {message}"),
                ),
                other => {
                    warn!(error = %other, "signed tenant capability discovery failed");
                    RuntimeError::Handler(
                        "connector capability catalog is temporarily unavailable".to_owned(),
                    )
                }
            })?;
        let count = page.capabilities.len();
        let output = serde_json::to_value(page).map_err(|error| {
            RuntimeError::Handler(format!(
                "connector capability discovery response encoding failed: {error}"
            ))
        })?;
        Ok(ActionResult {
            action_id: action.id,
            status: ActionResultStatus::Completed,
            output: Some(output),
            message: vec![MessagePart::text(format!(
                "Returned {count} tenant-visible connector capabilities"
            ))],
            memory_update: None,
            usage: None,
            receipt: None,
            error: None,
        })
    }
}

fn validate_catalog_action_input(input: &CapabilityCatalogActionInput) -> RuntimeResult<()> {
    for (name, value, max_bytes) in [
        ("capability_id", input.capability_id.as_deref(), 512_usize),
        ("text", input.text.as_deref(), 512_usize),
        ("profile", input.profile.as_deref(), 512_usize),
        ("cursor", input.cursor.as_deref(), 2_048_usize),
    ] {
        if value.is_some_and(|value| value.is_empty() || value.len() > max_bytes) {
            return Err(RuntimeError::Handler(format!(
                "connector capability discovery `{name}` must contain 1 to {max_bytes} bytes"
            )));
        }
    }
    if input.limit.is_some_and(|limit| !(1..=200).contains(&limit)) {
        return Err(RuntimeError::Handler(
            "connector capability discovery limit must be between 1 and 200".to_owned(),
        ));
    }
    Ok(())
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(health_payload(state.started_at))
}

async fn ready(State(state): State<AppState>) -> Response {
    let gateway = state.gateway.readiness().await;
    let supervisor = state.supervisor.snapshot().await;
    let required_modules_ready = state
        .module_statuses
        .values()
        .filter(|module| module.required)
        .all(|module| module.ready);
    let ready = gateway.ready
        && supervisor.runtime_worker_running
        && (!supervisor.nats_required || supervisor.nats_listener_running)
        && required_modules_ready;
    metrics::gauge!("aip_daemon_ready").set(if ready { 1.0 } else { 0.0 });
    metrics::gauge!("aip_runtime_worker_up").set(if supervisor.runtime_worker_running {
        1.0
    } else {
        0.0
    });
    metrics::gauge!("aip_nats_listener_up").set(if supervisor.nats_listener_running {
        1.0
    } else {
        0.0
    });
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let mut body = json!({
        "status": if ready { "ready" } else { "not_ready" },
        "gateway": gateway,
        "supervisor": supervisor,
        "modules": state.module_statuses
    });
    if let Some(fleet) = &state.fleet_supervisor {
        body["fleet"] = serde_json::to_value(fleet.snapshot().await)
            .unwrap_or_else(|_| json!({ "worker_running": false }));
    }
    (status, Json(body)).into_response()
}

async fn metrics(State(state): State<AppState>) -> Response {
    if let Some(admission) = &state.remote_admission {
        let snapshot = admission.snapshot();
        metrics::gauge!("aip_connector_remote_active").set(snapshot.active as f64);
        metrics::gauge!("aip_connector_remote_queued").set(snapshot.queued as f64);
        metrics::gauge!("aip_connector_remote_queued_bytes").set(snapshot.queued_bytes as f64);
        metrics::gauge!("aip_connector_remote_active_tenants").set(snapshot.active_tenants as f64);
        metrics::gauge!("aip_connector_remote_queued_tenants").set(snapshot.queued_tenants as f64);
    }
    if let Some(ingress) = &state.connector_event_ingress {
        let snapshot = ingress.snapshot();
        metrics::gauge!("aip_connector_event_ingress_capacity").set(snapshot.max_in_flight as f64);
        metrics::gauge!("aip_connector_event_ingress_available").set(snapshot.available as f64);
    }
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        state.prometheus.render(),
    )
        .into_response()
}

async fn manifest(State(state): State<AppState>, Query(query): Query<ManifestQuery>) -> Response {
    let filter = match manifest_filter_from_query(query) {
        Ok(filter) => filter,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    Json(Runtime::filter_manifest(&state.manifest, filter.as_ref())).into_response()
}

#[derive(Debug, Default, Deserialize)]
struct ManifestQuery {
    capability_id: Option<String>,
    resource_kind: Option<String>,
    profile: Option<String>,
    risk: Option<String>,
    side_effect: Option<String>,
    requires_approval: Option<bool>,
    supports_streaming: Option<bool>,
    supports_transactions: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct ActionListQuery {
    state: Option<String>,
    capability_id: Option<String>,
    session_id: Option<String>,
    principal_id: Option<String>,
    tenant_id: Option<String>,
    approval_id: Option<String>,
    transaction_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
    include_results: Option<bool>,
    include_receipts: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct ActionStatusQuery {
    tenant_id: Option<String>,
    include_result: Option<bool>,
    include_receipts: Option<bool>,
    include_chunks: Option<bool>,
    wait_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct ActionResultQuery {
    tenant_id: Option<String>,
    wait_ms: Option<u64>,
    include_receipt: Option<bool>,
    include_terminal_events: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct ActionEventsQuery {
    tenant_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
    kinds: Option<String>,
    kind: Option<String>,
    include_chunks: Option<bool>,
    follow: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct CancelBody {
    reason: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SessionListQuery {
    principal_id: Option<String>,
    status: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct SessionOperationBody {
    reason: Option<String>,
    resume_token: Option<String>,
    last_event_cursor: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ApprovalListQuery {
    status: Option<String>,
    approver: Option<String>,
    requester: Option<String>,
    tenant_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
    include_action_status: Option<bool>,
    include_receipts: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct ApprovalQuery {
    tenant_id: Option<String>,
    include_action_status: Option<bool>,
    include_receipts: Option<bool>,
    include_evidence_payload: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct CallbackDeliveryListQuery {
    action_id: Option<String>,
    status: Option<String>,
    profile: Option<String>,
    target: Option<String>,
    tenant_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
    include_receipts: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct CallbackDeliveryQuery {
    tenant_id: Option<String>,
    include_receipts: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct TransactionQuery {
    tenant_id: Option<String>,
    include_result: Option<bool>,
    include_receipts: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct AuditEventsQuery {
    action_id: Option<String>,
    session_id: Option<String>,
    principal_id: Option<String>,
    tenant_id: Option<String>,
    transaction_id: Option<String>,
    from: Option<String>,
    to: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
    include_receipts: Option<bool>,
    export: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct ResourceListQuery {
    capability_id: Option<String>,
    kind: Option<String>,
    tenant_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct ResourceReadQuery {
    tenant_id: Option<String>,
    version: Option<String>,
    accept: Option<String>,
}

async fn action_list(
    State(state): State<AppState>,
    Query(query): Query<ActionListQuery>,
) -> Response {
    let request = match action_list_request_from_query(query) {
        Ok(request) => request,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    dispatch_native_response(&state, MessageBody::ActionListRequest(request)).await
}

async fn action_status(
    State(state): State<AppState>,
    AxumPath(action_id): AxumPath<String>,
    Query(query): Query<ActionStatusQuery>,
) -> Response {
    let action_id = match parse_action_id(&action_id) {
        Ok(action_id) => action_id,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    dispatch_native_response(
        &state,
        MessageBody::ActionStatusRequest(ActionStatusRequest {
            action_id,
            tenant_id: query.tenant_id,
            include_result: query.include_result.unwrap_or(false),
            include_receipts: query.include_receipts.unwrap_or(false),
            include_chunks: query.include_chunks.unwrap_or(false),
            wait_ms: query.wait_ms,
        }),
    )
    .await
}

async fn action_result(
    State(state): State<AppState>,
    AxumPath(action_id): AxumPath<String>,
    Query(query): Query<ActionResultQuery>,
) -> Response {
    let action_id = match parse_action_id(&action_id) {
        Ok(action_id) => action_id,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    dispatch_native_response(
        &state,
        MessageBody::ActionResultRequest(ActionResultRequest {
            action_id,
            tenant_id: query.tenant_id,
            wait_ms: query.wait_ms,
            include_receipt: query.include_receipt.unwrap_or(false),
            include_terminal_events: query.include_terminal_events.unwrap_or(false),
        }),
    )
    .await
}

async fn action_events(
    State(state): State<AppState>,
    AxumPath(action_id): AxumPath<String>,
    headers: HeaderMap,
    Query(query): Query<ActionEventsQuery>,
) -> Response {
    let action_id = match parse_action_id(&action_id) {
        Ok(action_id) => action_id,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    let follow = query.follow.unwrap_or(false);
    let request = ActionEventsRequest {
        action_id,
        tenant_id: query.tenant_id,
        cursor: cursor_from_http(&headers, query.cursor),
        limit: query.limit,
        kinds: event_kinds_from_query(query.kinds, query.kind),
        include_chunks: query.include_chunks.unwrap_or(false),
        follow,
    };
    if follow {
        dispatch_native_sse_response(&state, MessageBody::ActionEventsRequest(request), true).await
    } else {
        dispatch_native_response(&state, MessageBody::ActionEventsRequest(request)).await
    }
}

async fn action_chunks(
    State(state): State<AppState>,
    AxumPath(action_id): AxumPath<String>,
    headers: HeaderMap,
    Query(query): Query<ActionEventsQuery>,
) -> Response {
    let action_id = match parse_action_id(&action_id) {
        Ok(action_id) => action_id,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    let follow = query.follow.unwrap_or(false);
    let request = ActionEventsRequest {
        action_id,
        tenant_id: query.tenant_id,
        cursor: cursor_from_http(&headers, query.cursor),
        limit: query.limit,
        kinds: vec!["aip.stream.chunk".to_owned()],
        include_chunks: true,
        follow,
    };
    if follow {
        dispatch_native_sse_response(&state, MessageBody::ActionEventsRequest(request), true).await
    } else {
        dispatch_native_response(&state, MessageBody::ActionEventsRequest(request)).await
    }
}

async fn action_cancel(
    State(state): State<AppState>,
    AxumPath(action_id): AxumPath<String>,
    body: Option<Json<CancelBody>>,
) -> Response {
    let action_id = match parse_action_id(&action_id) {
        Ok(action_id) => action_id,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    dispatch_native_response(
        &state,
        MessageBody::Cancel(Cancel {
            target: CancelTarget::Action(action_id),
            reason: body.and_then(|body| body.reason.clone()),
        }),
    )
    .await
}

async fn global_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ActionEventsQuery>,
) -> Response {
    let follow = query.follow.unwrap_or(false);
    let request = EventStreamRequest {
        cursor: cursor_from_http(&headers, query.cursor),
        limit: query.limit,
        kinds: event_kinds_from_query(query.kinds, query.kind),
    };
    if follow {
        dispatch_native_sse_response(&state, MessageBody::EventStreamRequest(request), true).await
    } else {
        dispatch_native_response(&state, MessageBody::EventStreamRequest(request)).await
    }
}

async fn session_list(
    State(state): State<AppState>,
    Query(query): Query<SessionListQuery>,
) -> Response {
    let request = match session_list_request_from_query(query) {
        Ok(request) => request,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    dispatch_native_response(&state, MessageBody::SessionListRequest(request)).await
}

async fn session_get(
    State(state): State<AppState>,
    AxumPath(session_selector): AxumPath<String>,
) -> Response {
    if session_selector.contains(':') {
        return protocol_error_response(
            StatusCode::BAD_REQUEST,
            invalid_query_error("session operation suffix is only valid for POST"),
        );
    }
    let session_id = match parse_session_id(&session_selector) {
        Ok(session_id) => session_id,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    dispatch_native_response(
        &state,
        MessageBody::SessionRequest(SessionRequest { session_id }),
    )
    .await
}

async fn session_operation(
    State(state): State<AppState>,
    AxumPath(session_selector): AxumPath<String>,
    body: Option<Json<SessionOperationBody>>,
) -> Response {
    let Some((session_id, operation)) = session_selector.rsplit_once(':') else {
        return protocol_error_response(
            StatusCode::BAD_REQUEST,
            invalid_query_error(
                "session operation must be formatted as `{session_id}:close` or `{session_id}:resume`",
            ),
        );
    };
    match operation {
        "close" => close_session_response(&state, session_id, body).await,
        "resume" => resume_session_response(&state, session_id, body).await,
        other => protocol_error_response(
            StatusCode::BAD_REQUEST,
            invalid_query_error(format!("unsupported session operation `{other}`")),
        ),
    }
}

async fn session_close(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    body: Option<Json<SessionOperationBody>>,
) -> Response {
    close_session_response(&state, &session_id, body).await
}

async fn session_resume(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    body: Option<Json<SessionOperationBody>>,
) -> Response {
    resume_session_response(&state, &session_id, body).await
}

async fn approval_list(
    State(state): State<AppState>,
    Query(query): Query<ApprovalListQuery>,
) -> Response {
    let request = match approval_list_request_from_query(query) {
        Ok(request) => request,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    dispatch_native_response(&state, MessageBody::ApprovalListRequest(request)).await
}

async fn approval_get(
    State(state): State<AppState>,
    AxumPath(approval_id): AxumPath<String>,
    Query(query): Query<ApprovalQuery>,
) -> Response {
    let approval_id = match ApprovalId::parse(&approval_id) {
        Ok(approval_id) => approval_id,
        Err(error) => {
            return protocol_error_response(StatusCode::BAD_REQUEST, invalid_query_error(error));
        }
    };
    dispatch_native_response(
        &state,
        MessageBody::ApprovalQueryRequest(ApprovalQueryRequest {
            approval_id,
            tenant_id: query.tenant_id,
            include_action_status: query.include_action_status.unwrap_or(false),
            include_receipts: query.include_receipts.unwrap_or(false),
            include_evidence_payload: query.include_evidence_payload.unwrap_or(false),
        }),
    )
    .await
}

async fn callback_delivery_list(
    State(state): State<AppState>,
    Query(query): Query<CallbackDeliveryListQuery>,
) -> Response {
    let request = match callback_delivery_list_request_from_query(query) {
        Ok(request) => request,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    dispatch_native_response(&state, MessageBody::CallbackDeliveryListRequest(request)).await
}

async fn callback_delivery_get(
    State(state): State<AppState>,
    AxumPath(delivery_id): AxumPath<String>,
    Query(query): Query<CallbackDeliveryQuery>,
) -> Response {
    dispatch_native_response(
        &state,
        MessageBody::CallbackDeliveryQueryRequest(CallbackDeliveryQueryRequest {
            delivery_id,
            tenant_id: query.tenant_id,
            include_receipts: query.include_receipts.unwrap_or(false),
        }),
    )
    .await
}

async fn transaction_get(
    State(state): State<AppState>,
    AxumPath(transaction_id): AxumPath<String>,
    Query(query): Query<TransactionQuery>,
) -> Response {
    let transaction_id = match aip_core::TransactionId::parse(&transaction_id) {
        Ok(transaction_id) => transaction_id,
        Err(error) => {
            return protocol_error_response(StatusCode::BAD_REQUEST, invalid_query_error(error));
        }
    };
    dispatch_native_response(
        &state,
        MessageBody::TransactionQueryRequest(TransactionQueryRequest {
            transaction_id: Some(transaction_id),
            plan_id: None,
            action_id: None,
            tenant_id: query.tenant_id,
            include_result: query.include_result.unwrap_or(false),
            include_receipts: query.include_receipts.unwrap_or(false),
        }),
    )
    .await
}

async fn transaction_get_by_plan(
    State(state): State<AppState>,
    AxumPath(plan_id): AxumPath<String>,
    Query(query): Query<TransactionQuery>,
) -> Response {
    dispatch_native_response(
        &state,
        MessageBody::TransactionQueryRequest(TransactionQueryRequest {
            transaction_id: None,
            plan_id: Some(plan_id),
            action_id: None,
            tenant_id: query.tenant_id,
            include_result: query.include_result.unwrap_or(false),
            include_receipts: query.include_receipts.unwrap_or(false),
        }),
    )
    .await
}

async fn transaction_get_by_action(
    State(state): State<AppState>,
    AxumPath(action_id): AxumPath<String>,
    Query(query): Query<TransactionQuery>,
) -> Response {
    let action_id = match parse_action_id(&action_id) {
        Ok(action_id) => action_id,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    dispatch_native_response(
        &state,
        MessageBody::TransactionQueryRequest(TransactionQueryRequest {
            transaction_id: None,
            plan_id: None,
            action_id: Some(action_id),
            tenant_id: query.tenant_id,
            include_result: query.include_result.unwrap_or(false),
            include_receipts: query.include_receipts.unwrap_or(false),
        }),
    )
    .await
}

async fn receipt_get(
    State(state): State<AppState>,
    AxumPath(chain_id): AxumPath<String>,
) -> Response {
    dispatch_native_response(
        &state,
        MessageBody::ReceiptQueryRequest(ReceiptQueryRequest {
            chain_id: Some(chain_id),
            receipt_id: None,
        }),
    )
    .await
}

async fn receipt_get_by_receipt(
    State(state): State<AppState>,
    AxumPath(receipt_id): AxumPath<String>,
) -> Response {
    let receipt_id = match aip_core::ReceiptId::parse(&receipt_id) {
        Ok(receipt_id) => receipt_id,
        Err(error) => {
            return protocol_error_response(StatusCode::BAD_REQUEST, invalid_query_error(error));
        }
    };
    dispatch_native_response(
        &state,
        MessageBody::ReceiptQueryRequest(ReceiptQueryRequest {
            chain_id: None,
            receipt_id: Some(receipt_id),
        }),
    )
    .await
}

async fn audit_events(
    State(state): State<AppState>,
    Query(query): Query<AuditEventsQuery>,
) -> Response {
    let request = match audit_query_request_from_query(query) {
        Ok(request) => request,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    dispatch_native_response(&state, MessageBody::AuditQueryRequest(request)).await
}

async fn resource_list(
    State(state): State<AppState>,
    Query(query): Query<ResourceListQuery>,
) -> Response {
    let request = match resource_list_request_from_query(query) {
        Ok(request) => request,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    dispatch_native_response(&state, MessageBody::ResourceListRequest(request)).await
}

async fn resource_read(
    State(state): State<AppState>,
    AxumPath(resource_id): AxumPath<String>,
    Query(query): Query<ResourceReadQuery>,
) -> Response {
    dispatch_native_response(
        &state,
        MessageBody::ResourceReadRequest(ResourceReadRequest {
            resource_id,
            tenant_id: query.tenant_id,
            version: query.version,
            accept: comma_list(query.accept),
        }),
    )
    .await
}

async fn native_websocket(State(state): State<AppState>, websocket: WebSocketUpgrade) -> Response {
    websocket.on_upgrade(move |socket| handle_native_websocket(state, socket))
}

async fn dispatch_native_response(state: &AppState, body: MessageBody) -> Response {
    let actor = match native_edge_actor(state) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let envelope = Envelope::new(body);
    match handle_authenticated_gateway_envelope(&state.gateway, envelope, actor).await {
        Ok(response) => native_body_response(response.body),
        Err(error) => error_response(error),
    }
}

async fn dispatch_native_sse_response(
    state: &AppState,
    body: MessageBody,
    follow: bool,
) -> Response {
    if follow {
        return native_sse_follow_response(state.clone(), body);
    }
    let actor = match native_edge_actor(state) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let envelope = Envelope::new(body);
    match handle_authenticated_gateway_envelope(&state.gateway, envelope, actor).await {
        Ok(response) => native_sse_body_response(response.body),
        Err(error) => error_response(error),
    }
}

fn native_sse_follow_response(state: AppState, body: MessageBody) -> Response {
    let stream = futures_util::stream::unfold(
        NativeSseFollowState {
            state,
            body,
            pending: VecDeque::new(),
            terminal: false,
        },
        |mut follow| async move {
            loop {
                if let Some(event) = follow.pending.pop_front() {
                    return Some((Ok::<_, Infallible>(event), follow));
                }
                if follow.terminal {
                    return None;
                }
                let response =
                    dispatch_native_sse_iteration(&follow.state, follow.body.clone()).await;
                match response {
                    Ok((events, next_cursor, terminal)) => {
                        follow.pending = events.into();
                        if let Some(cursor) = next_cursor {
                            update_follow_cursor(&mut follow.body, cursor);
                        }
                        follow.terminal = terminal;
                    }
                    Err(error) => {
                        follow.pending.push_back(protocol_error_sse_event(error));
                        follow.terminal = true;
                    }
                }
                if follow.pending.is_empty() && !follow.terminal {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        },
    );
    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response()
}

#[derive(Clone)]
struct NativeSseFollowState {
    state: AppState,
    body: MessageBody,
    pending: VecDeque<AxumSseEvent>,
    terminal: bool,
}

async fn dispatch_native_sse_iteration(
    state: &AppState,
    body: MessageBody,
) -> Result<(Vec<AxumSseEvent>, Option<String>, bool), ProtocolError> {
    let actor = native_edge_actor(state).map_err(|_| ProtocolError {
        code: "auth.native_http_unauthorized".to_owned(),
        message: "native HTTP authentication is required".to_owned(),
        category: ErrorCategory::Auth,
        retryable: Some(false),
        retry_after_ms: None,
        details: None,
        source: Some(Box::new(json!({ "component": "aip.server.native_http" }))),
    })?;
    let envelope = Envelope::new(body);
    let response = handle_authenticated_gateway_envelope(&state.gateway, envelope, actor)
        .await
        .map_err(gateway_error_protocol)?;
    let (next_cursor, terminal) = sse_response_cursor_and_terminal(&response.body);
    let events = native_axum_sse_events_from_body(response.body)?;
    Ok((events, next_cursor, terminal))
}

async fn handle_gateway_envelope(
    gateway: &Gateway,
    envelope: Envelope,
) -> Result<Envelope, GatewayError> {
    let gateway = gateway.clone();
    tokio::spawn(async move { gateway.handle_envelope(envelope).await })
        .await
        .map_err(|error| {
            GatewayError::Runtime(RuntimeError::Handler(format!(
                "gateway task failed: {error}"
            )))
        })?
}

async fn handle_authenticated_gateway_envelope(
    gateway: &Gateway,
    envelope: Envelope,
    actor: Principal,
) -> Result<Envelope, GatewayError> {
    let authenticated = AuthenticatedPrincipal {
        scopes: principal_scopes(&actor),
        principal: actor,
        scheme: AuthScheme::Bearer,
        issuer: "getaip-server:native-http".to_owned(),
        audience: Some("getaip-server".to_owned()),
        authenticated_at: OffsetDateTime::now_utc(),
        expires_at: None,
        credential_fingerprint: None,
    };
    let gateway = gateway.clone();
    tokio::spawn(async move {
        gateway
            .handle_verified_envelope(envelope, authenticated, None, None)
            .await
    })
    .await
    .map_err(|error| {
        GatewayError::Runtime(RuntimeError::Handler(format!(
            "authenticated gateway task failed: {error}"
        )))
    })?
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

fn native_body_response(body: MessageBody) -> Response {
    match body {
        MessageBody::Error(error) => {
            protocol_error_response(status_for_error(&error.error), error.error)
        }
        body => (StatusCode::OK, Json(body)).into_response(),
    }
}

fn native_sse_body_response(body: MessageBody) -> Response {
    match body {
        MessageBody::Error(error) => {
            protocol_error_response(status_for_error(&error.error), error.error)
        }
        body => {
            let rendered = match native_sse_events_from_body(body) {
                Ok(events) => events,
                Err(error) => {
                    return protocol_error_response(StatusCode::INTERNAL_SERVER_ERROR, error);
                }
            };
            (
                [
                    (header::CONTENT_TYPE, "text/event-stream"),
                    (header::CACHE_CONTROL, "no-cache"),
                ],
                rendered,
            )
                .into_response()
        }
    }
}

fn native_sse_events_from_body(body: MessageBody) -> Result<String, ProtocolError> {
    let mut output = String::new();
    match body {
        MessageBody::ActionEvents(events) => {
            let mut emitted_data = false;
            for event in events.events {
                output.push_str(&render_sse_event(
                    Some(event.id.to_string()),
                    &event.kind,
                    &json!({ "event": event }),
                )?);
                emitted_data = true;
            }
            for chunk in events.chunks {
                output.push_str(&render_sse_event(
                    Some(format!("chunk:{}", chunk.sequence)),
                    "aip.stream.chunk",
                    &json!({ "chunk": chunk }),
                )?);
                emitted_data = true;
            }
            if emitted_data && let Some(cursor) = events.cursor.clone() {
                output.push_str(&render_sse_event(
                    Some(cursor.clone()),
                    "aip.stream.cursor",
                    &json!({ "next_cursor": cursor }),
                )?);
            }
            if events.terminal {
                output.push_str(&render_sse_event(
                    events.cursor,
                    "aip.stream.terminal",
                    &json!({ "terminal": true, "action_id": events.action_id }),
                )?);
            }
        }
        MessageBody::EventStream(stream) => {
            for event in stream.events {
                output.push_str(&render_sse_event(
                    Some(event.id.to_string()),
                    &event.kind,
                    &json!({ "event": event }),
                )?);
            }
            if let Some(cursor) = stream.next_cursor {
                output.push_str(&render_sse_event(
                    Some(cursor.clone()),
                    "aip.stream.cursor",
                    &json!({ "next_cursor": cursor }),
                )?);
            }
        }
        body => {
            output.push_str(&render_sse_event(
                None,
                body.message_type().as_str(),
                &json!({ "body": body }),
            )?);
        }
    }
    Ok(output)
}

fn native_axum_sse_events_from_body(body: MessageBody) -> Result<Vec<AxumSseEvent>, ProtocolError> {
    let mut output = Vec::new();
    match body {
        MessageBody::ActionEvents(events) => {
            let mut emitted_data = false;
            for event in events.events {
                output.push(axum_sse_event(
                    Some(event.id.to_string()),
                    &event.kind,
                    &json!({ "event": event }),
                )?);
                emitted_data = true;
            }
            for chunk in events.chunks {
                output.push(axum_sse_event(
                    Some(format!("chunk:{}", chunk.sequence)),
                    "aip.stream.chunk",
                    &json!({ "chunk": chunk }),
                )?);
                emitted_data = true;
            }
            if emitted_data && let Some(cursor) = events.cursor.clone() {
                output.push(axum_sse_event(
                    Some(cursor.clone()),
                    "aip.stream.cursor",
                    &json!({ "next_cursor": cursor }),
                )?);
            }
            if events.terminal {
                output.push(axum_sse_event(
                    events.cursor,
                    "aip.stream.terminal",
                    &json!({ "terminal": true, "action_id": events.action_id }),
                )?);
            }
        }
        MessageBody::EventStream(stream) => {
            let mut emitted_data = false;
            for event in stream.events {
                output.push(axum_sse_event(
                    Some(event.id.to_string()),
                    &event.kind,
                    &json!({ "event": event }),
                )?);
                emitted_data = true;
            }
            if emitted_data && let Some(cursor) = stream.next_cursor {
                output.push(axum_sse_event(
                    Some(cursor.clone()),
                    "aip.stream.cursor",
                    &json!({ "next_cursor": cursor }),
                )?);
            }
        }
        MessageBody::Error(error) => output.push(protocol_error_sse_event(error.error)),
        body => output.push(axum_sse_event(
            None,
            body.message_type().as_str(),
            &json!({ "body": body }),
        )?),
    }
    Ok(output)
}

fn axum_sse_event(
    id: Option<String>,
    event: &str,
    data: &Value,
) -> Result<AxumSseEvent, ProtocolError> {
    let data = serde_json::to_string(data).map_err(|error| ProtocolError {
        code: "stream.encode_failed".to_owned(),
        message: error.to_string(),
        category: ErrorCategory::Transport,
        retryable: Some(false),
        retry_after_ms: None,
        details: None,
        source: Some(Box::new(json!({ "component": "aip.server.sse" }))),
    })?;
    let event = AxumSseEvent::default().event(event).data(data);
    Ok(match id {
        Some(id) => event.id(id),
        None => event,
    })
}

fn protocol_error_sse_event(error: ProtocolError) -> AxumSseEvent {
    axum_sse_event(
        None,
        "aip.error",
        &json!({
            "error": error
        }),
    )
    .unwrap_or_else(|_| {
        AxumSseEvent::default()
            .event("aip.error")
            .data("stream error")
    })
}

fn gateway_error_protocol(error: GatewayError) -> ProtocolError {
    let envelope = Gateway::error_envelope(&error);
    match envelope.body {
        MessageBody::Error(error) => error.error,
        _ => ProtocolError {
            code: "gateway.error".to_owned(),
            message: error.to_string(),
            category: ErrorCategory::Permanent,
            retryable: Some(false),
            retry_after_ms: None,
            details: None,
            source: Some(Box::new(json!({ "component": "aip.server.sse" }))),
        },
    }
}

fn update_follow_cursor(body: &mut MessageBody, cursor: String) {
    match body {
        MessageBody::ActionEventsRequest(request) => request.cursor = Some(cursor),
        MessageBody::EventStreamRequest(request) => request.cursor = Some(cursor),
        _ => {}
    }
}

fn sse_response_cursor_and_terminal(body: &MessageBody) -> (Option<String>, bool) {
    match body {
        MessageBody::ActionEvents(events) => (events.cursor.clone(), events.terminal),
        MessageBody::EventStream(stream) => (stream.next_cursor.clone(), false),
        MessageBody::ActionResult(_) | MessageBody::Error(_) => (None, true),
        _ => (None, false),
    }
}

fn render_sse_event(
    id: Option<String>,
    event: &str,
    data: &Value,
) -> Result<String, ProtocolError> {
    let data = serde_json::to_string(data).map_err(|error| ProtocolError {
        code: "stream.encode_failed".to_owned(),
        message: error.to_string(),
        category: ErrorCategory::Transport,
        retryable: Some(false),
        retry_after_ms: None,
        details: None,
        source: Some(Box::new(json!({ "component": "aip.server.sse" }))),
    })?;
    let mut output = String::new();
    if let Some(id) = id {
        output.push_str("id: ");
        output.push_str(&id);
        output.push('\n');
    }
    output.push_str("event: ");
    output.push_str(event);
    output.push('\n');
    output.push_str("data: ");
    output.push_str(&data);
    output.push_str("\n\n");
    Ok(output)
}

#[derive(Clone, Debug, Default, Deserialize)]
struct NativeWebSocketSubscribe {
    #[serde(default)]
    r#type: String,
    subscription_id: Option<String>,
    action_id: Option<String>,
    session_id: Option<String>,
    tenant_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
    kinds: Option<Vec<String>>,
    kind: Option<String>,
    include_chunks: Option<bool>,
    follow: Option<bool>,
}

async fn handle_native_websocket(state: AppState, socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();
    let (outbound, mut inbound) = mpsc::channel::<AxumWsMessage>(NATIVE_WS_OUTBOUND_CAPACITY);
    let subscription_capacity = Arc::new(Semaphore::new(NATIVE_WS_MAX_SUBSCRIPTIONS));
    let writer = tokio::spawn(async move {
        while let Some(message) = inbound.recv().await {
            if sender.send(message).await.is_err() {
                break;
            }
        }
    });
    while let Some(message) = receiver.next().await {
        let Ok(message) = message else {
            break;
        };
        match message {
            AxumWsMessage::Text(text) => {
                if !handle_native_websocket_text(
                    state.clone(),
                    outbound.clone(),
                    subscription_capacity.clone(),
                    text.to_string(),
                )
                .await
                {
                    break;
                }
            }
            AxumWsMessage::Ping(payload) => {
                if outbound.try_send(AxumWsMessage::Pong(payload)).is_err() {
                    break;
                }
            }
            AxumWsMessage::Close(reason) => {
                let _ = outbound.try_send(AxumWsMessage::Close(reason));
                break;
            }
            AxumWsMessage::Binary(_) | AxumWsMessage::Pong(_) => {}
        }
    }
    drop(outbound);
    let _ = writer.await;
}

async fn handle_native_websocket_text(
    state: AppState,
    outbound: mpsc::Sender<AxumWsMessage>,
    subscription_capacity: Arc<Semaphore>,
    text: String,
) -> bool {
    if let Ok(envelope) = decode_ws(&WebSocketFrame::Text(text.clone())) {
        let response = match native_edge_actor(&state) {
            Ok(actor) => {
                match handle_authenticated_gateway_envelope(&state.gateway, envelope, actor).await {
                    Ok(response) => response,
                    Err(error) => Gateway::error_envelope(&error),
                }
            }
            Err(_) => Gateway::error_envelope(&GatewayError::Runtime(RuntimeError::Authorization(
                "native websocket authentication is required".to_owned(),
            ))),
        };
        return send_native_websocket_envelope(&outbound, response);
    }
    match serde_json::from_str::<NativeWebSocketSubscribe>(&text) {
        Ok(subscription) if subscription.r#type == "subscribe" => {
            let Ok(permit) = subscription_capacity.try_acquire_owned() else {
                return send_native_websocket_error(
                    &outbound,
                    "ws.subscription_capacity",
                    "native websocket subscription capacity is exhausted",
                );
            };
            tokio::spawn(async move {
                let _permit = permit;
                native_websocket_subscription_loop(state, outbound, subscription).await;
            });
            true
        }
        Ok(_) => send_native_websocket_error(
            &outbound,
            "ws.invalid_message",
            "unsupported websocket message type",
        ),
        Err(error) => send_native_websocket_error(
            &outbound,
            "ws.decode_failed",
            format!("failed to decode websocket text frame: {error}"),
        ),
    }
}

async fn native_websocket_subscription_loop(
    state: AppState,
    outbound: mpsc::Sender<AxumWsMessage>,
    mut subscription: NativeWebSocketSubscribe,
) {
    let follow = subscription.follow.unwrap_or(false);
    loop {
        let body = match websocket_subscription_body(&subscription) {
            Ok(body) => body,
            Err(error) => {
                let _ = send_native_websocket_envelope(
                    &outbound,
                    Envelope::new(MessageBody::Error(ErrorBody { error })),
                );
                return;
            }
        };
        let mut envelope = Envelope::new(body);
        envelope.from = Some(state.manifest.agent.clone());
        envelope.session_id = match subscription.session_id.as_deref() {
            Some(session_id) => match aip_core::SessionId::parse(session_id) {
                Ok(session_id) => Some(session_id),
                Err(error) => {
                    send_native_websocket_error(
                        &outbound,
                        "ws.invalid_session_id",
                        error.to_string(),
                    );
                    return;
                }
            },
            None => None,
        };
        envelope.trace = Some(json!({
            "transport": "websocket",
            "subscription_id": subscription.subscription_id
        }));
        let mut response = match native_edge_actor(&state) {
            Ok(actor) => {
                match handle_authenticated_gateway_envelope(&state.gateway, envelope, actor).await {
                    Ok(response) => response,
                    Err(error) => Gateway::error_envelope(&error),
                }
            }
            Err(_) => Gateway::error_envelope(&GatewayError::Runtime(RuntimeError::Authorization(
                "native websocket authentication is required".to_owned(),
            ))),
        };
        let (next_cursor, terminal) = websocket_response_cursor_and_terminal(&response.body);
        annotate_websocket_subscription_response(
            &mut response,
            &subscription,
            next_cursor.as_deref(),
            terminal,
        );
        if !send_native_websocket_envelope(&outbound, response) {
            return;
        }
        update_websocket_subscription_cursor(&mut subscription, next_cursor);
        if !follow || terminal {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn update_websocket_subscription_cursor(
    subscription: &mut NativeWebSocketSubscribe,
    next_cursor: Option<String>,
) {
    if let Some(cursor) = next_cursor {
        subscription.cursor = Some(cursor);
    }
}

fn annotate_websocket_subscription_response(
    envelope: &mut Envelope,
    subscription: &NativeWebSocketSubscribe,
    next_cursor: Option<&str>,
    terminal: bool,
) {
    let mut trace = envelope.trace.take().unwrap_or_else(|| json!({}));
    if !trace.is_object() {
        trace = json!({ "previous": trace });
    }
    if let Some(object) = trace.as_object_mut() {
        object.insert(
            "websocket".to_owned(),
            json!({
                "subscription_id": subscription.subscription_id,
                "action_id": subscription.action_id,
                "session_id": subscription.session_id,
                "tenant_id": subscription.tenant_id,
                "cursor": subscription.cursor,
                "next_cursor": next_cursor,
                "terminal": terminal,
                "follow": subscription.follow.unwrap_or(false)
            }),
        );
    }
    envelope.trace = Some(trace);
}

fn websocket_subscription_body(
    subscription: &NativeWebSocketSubscribe,
) -> Result<MessageBody, ProtocolError> {
    let mut kinds = subscription.kinds.clone().unwrap_or_default();
    if let Some(kind) = subscription.kind.as_ref() {
        kinds.push(kind.clone());
    }
    kinds.sort();
    kinds.dedup();
    if let Some(action_id) = subscription.action_id.as_deref() {
        return Ok(MessageBody::ActionEventsRequest(ActionEventsRequest {
            action_id: ActionId::parse(action_id).map_err(invalid_query_error)?,
            tenant_id: subscription.tenant_id.clone(),
            cursor: subscription.cursor.clone(),
            limit: subscription.limit,
            kinds,
            include_chunks: subscription.include_chunks.unwrap_or(false),
            follow: subscription.follow.unwrap_or(false),
        }));
    }
    Ok(MessageBody::EventStreamRequest(EventStreamRequest {
        cursor: subscription.cursor.clone(),
        limit: subscription.limit,
        kinds,
    }))
}

fn websocket_response_cursor_and_terminal(body: &MessageBody) -> (Option<String>, bool) {
    match body {
        MessageBody::ActionEvents(events) => (events.cursor.clone(), events.terminal),
        MessageBody::EventStream(stream) => (stream.next_cursor.clone(), false),
        MessageBody::ActionResult(_) | MessageBody::Error(_) => (None, true),
        _ => (None, false),
    }
}

fn send_native_websocket_envelope(
    outbound: &mpsc::Sender<AxumWsMessage>,
    envelope: Envelope,
) -> bool {
    match encode_ws(&envelope) {
        Ok(WebSocketFrame::Text(text)) => {
            outbound.try_send(AxumWsMessage::Text(text.into())).is_ok()
        }
        Ok(_) => true,
        Err(error) => send_native_websocket_error(outbound, "ws.encode_failed", error.to_string()),
    }
}

fn send_native_websocket_error(
    outbound: &mpsc::Sender<AxumWsMessage>,
    code: &str,
    message: impl Into<String>,
) -> bool {
    let envelope = Envelope::new(MessageBody::Error(ErrorBody {
        error: ProtocolError {
            code: code.to_owned(),
            message: message.into(),
            category: ErrorCategory::Transport,
            retryable: Some(false),
            retry_after_ms: None,
            details: None,
            source: Some(Box::new(json!({ "component": "aip.server.websocket" }))),
        },
    }));
    if let Ok(WebSocketFrame::Text(text)) = encode_ws(&envelope) {
        return outbound.try_send(AxumWsMessage::Text(text.into())).is_ok();
    }
    false
}

fn action_list_request_from_query(
    query: ActionListQuery,
) -> Result<ActionListRequest, ProtocolError> {
    Ok(ActionListRequest {
        state: query
            .state
            .as_deref()
            .map(parse_action_lifecycle_state)
            .transpose()?,
        capability_id: query
            .capability_id
            .map(CapabilityId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        session_id: query
            .session_id
            .map(aip_core::SessionId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        principal_id: query
            .principal_id
            .map(PrincipalId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        tenant_id: query.tenant_id,
        approval_id: query
            .approval_id
            .map(ApprovalId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        transaction_id: query
            .transaction_id
            .map(aip_core::TransactionId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        cursor: query.cursor,
        limit: query.limit,
        include_results: query.include_results.unwrap_or(false),
        include_receipts: query.include_receipts.unwrap_or(false),
    })
}

fn manifest_filter_from_query(
    query: ManifestQuery,
) -> Result<Option<ManifestFilter>, ProtocolError> {
    let filter = ManifestFilter {
        capability_ids: comma_list(query.capability_id)
            .into_iter()
            .map(CapabilityId::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid_query_error)?,
        resource_kinds: comma_list(query.resource_kind),
        profiles: comma_list(query.profile)
            .into_iter()
            .map(|value| ProfileId::from(value.as_str()))
            .collect(),
        risk: comma_list(query.risk)
            .into_iter()
            .map(|value| serde_json::from_value(json!(value)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid_query_error)?,
        side_effects: comma_list(query.side_effect)
            .into_iter()
            .map(|value| serde_json::from_value(json!(value)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid_query_error)?,
        requires_approval: query.requires_approval,
        supports_streaming: query.supports_streaming,
        supports_transactions: query.supports_transactions,
    };
    let is_empty = filter.capability_ids.is_empty()
        && filter.resource_kinds.is_empty()
        && filter.profiles.is_empty()
        && filter.risk.is_empty()
        && filter.side_effects.is_empty()
        && filter.requires_approval.is_none()
        && filter.supports_streaming.is_none()
        && filter.supports_transactions.is_none();
    Ok((!is_empty).then_some(filter))
}

fn session_list_request_from_query(
    query: SessionListQuery,
) -> Result<SessionListRequest, ProtocolError> {
    Ok(SessionListRequest {
        principal_id: query
            .principal_id
            .map(PrincipalId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        status: query
            .status
            .as_deref()
            .map(parse_session_state)
            .transpose()?,
        cursor: query.cursor,
        limit: query.limit,
    })
}

fn approval_list_request_from_query(
    query: ApprovalListQuery,
) -> Result<ApprovalListRequest, ProtocolError> {
    Ok(ApprovalListRequest {
        status: query.status,
        approver: query
            .approver
            .map(PrincipalId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        requester: query
            .requester
            .map(PrincipalId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        tenant_id: query.tenant_id,
        cursor: query.cursor,
        limit: query.limit,
        include_action_status: query.include_action_status.unwrap_or(false),
        include_receipts: query.include_receipts.unwrap_or(false),
    })
}

fn callback_delivery_list_request_from_query(
    query: CallbackDeliveryListQuery,
) -> Result<CallbackDeliveryListRequest, ProtocolError> {
    Ok(CallbackDeliveryListRequest {
        action_id: query
            .action_id
            .map(ActionId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        status: query
            .status
            .as_deref()
            .map(parse_callback_delivery_status)
            .transpose()?,
        profile: query
            .profile
            .map(ProfileId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        target: query.target,
        tenant_id: query.tenant_id,
        cursor: query.cursor,
        limit: query.limit,
        include_receipts: query.include_receipts.unwrap_or(false),
    })
}

fn audit_query_request_from_query(
    query: AuditEventsQuery,
) -> Result<AuditQueryRequest, ProtocolError> {
    Ok(AuditQueryRequest {
        action_id: query
            .action_id
            .map(ActionId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        session_id: query
            .session_id
            .map(aip_core::SessionId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        principal_id: query
            .principal_id
            .map(PrincipalId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        tenant_id: query.tenant_id,
        transaction_id: query
            .transaction_id
            .map(aip_core::TransactionId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        from: query.from.as_deref().map(parse_rfc3339_time).transpose()?,
        to: query.to.as_deref().map(parse_rfc3339_time).transpose()?,
        cursor: query.cursor,
        limit: query.limit,
        include_receipts: query.include_receipts.unwrap_or(false),
        export: query.export.unwrap_or(false),
    })
}

fn resource_list_request_from_query(
    query: ResourceListQuery,
) -> Result<ResourceListRequest, ProtocolError> {
    Ok(ResourceListRequest {
        capability_id: query
            .capability_id
            .map(CapabilityId::parse)
            .transpose()
            .map_err(invalid_query_error)?,
        kind: query.kind,
        tenant_id: query.tenant_id,
        cursor: query.cursor,
        limit: query.limit,
    })
}

async fn close_session_response(
    state: &AppState,
    raw_session_id: &str,
    body: Option<Json<SessionOperationBody>>,
) -> Response {
    let session_id = match parse_session_id(raw_session_id) {
        Ok(session_id) => session_id,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    dispatch_native_response(
        state,
        MessageBody::SessionCloseRequest(SessionCloseRequest {
            session_id,
            reason: body.and_then(|body| body.reason.clone()),
        }),
    )
    .await
}

async fn resume_session_response(
    state: &AppState,
    raw_session_id: &str,
    body: Option<Json<SessionOperationBody>>,
) -> Response {
    let session_id = match parse_session_id(raw_session_id) {
        Ok(session_id) => session_id,
        Err(error) => return protocol_error_response(StatusCode::BAD_REQUEST, error),
    };
    let body = body.map(|body| body.0).unwrap_or_default();
    dispatch_native_response(
        state,
        MessageBody::SessionResumeRequest(SessionResumeRequest {
            session_id,
            resume_token: body.resume_token,
            last_event_cursor: body.last_event_cursor,
        }),
    )
    .await
}

fn parse_action_lifecycle_state(value: &str) -> Result<ActionLifecycleState, ProtocolError> {
    serde_json::from_value(json!(value)).map_err(invalid_query_error)
}

fn parse_session_state(value: &str) -> Result<SessionState, ProtocolError> {
    serde_json::from_value(json!(value)).map_err(invalid_query_error)
}

fn parse_callback_delivery_status(value: &str) -> Result<CallbackDeliveryStatus, ProtocolError> {
    serde_json::from_value(json!(value)).map_err(invalid_query_error)
}

fn parse_action_id(value: &str) -> Result<ActionId, ProtocolError> {
    ActionId::parse(value).map_err(invalid_query_error)
}

fn parse_session_id(value: &str) -> Result<aip_core::SessionId, ProtocolError> {
    aip_core::SessionId::parse(value).map_err(invalid_query_error)
}

fn parse_rfc3339_time(value: &str) -> Result<OffsetDateTime, ProtocolError> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(invalid_query_error)
}

fn invalid_query_error(error: impl fmt::Display) -> ProtocolError {
    ProtocolError {
        code: "query.invalid".to_owned(),
        message: error.to_string(),
        category: ErrorCategory::Permanent,
        retryable: Some(false),
        retry_after_ms: None,
        details: None,
        source: Some(Box::new(json!({ "component": "aip.server.http" }))),
    }
}

fn event_kinds_from_query(kinds: Option<String>, kind: Option<String>) -> Vec<String> {
    let mut output = Vec::new();
    if let Some(kind) = kind {
        output.push(kind);
    }
    if let Some(kinds) = kinds {
        output.extend(
            kinds
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
    }
    output.sort();
    output.dedup();
    output
}

fn cursor_from_http(headers: &HeaderMap, query_cursor: Option<String>) -> Option<String> {
    query_cursor.or_else(|| {
        headers
            .get(header::HeaderName::from_static("last-event-id"))
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn comma_list(value: Option<String>) -> Vec<String> {
    value
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

async fn mcp_protected_resource_metadata(State(state): State<AppState>) -> Response {
    match state.mcp_protected_resource {
        Some(policy) => (StatusCode::OK, Json(policy.metadata)).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct LegacyMcpQuery {
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
}

struct LegacySseConnection {
    registry: LegacySessionRegistry,
    session_id: String,
    owner: String,
    receiver: broadcast::Receiver<LegacySseEvent>,
    pending: VecDeque<LegacySseEvent>,
    last_event_id: Option<String>,
}

async fn handle_legacy_mcp_sse(
    State(state): State<AppState>,
    Query(query): Query<LegacyMcpQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = reject_mcp_origin(&state, &headers) {
        return response;
    }
    let identity = match authorize_mcp_http(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let last_event_id = headers
        .get(header::HeaderName::from_static("last-event-id"))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let (session_id, receiver, pending) = if let Some(session_id) = query.session_id {
        let subscription = match state
            .mcp_legacy_sessions
            .subscribe(&session_id, &identity.owner, last_event_id.as_deref())
            .await
        {
            Ok(subscription) => subscription,
            Err(error) => return legacy_mcp_error_response(error),
        };
        (
            session_id,
            subscription.receiver,
            subscription.replay.into(),
        )
    } else {
        let endpoint = match legacy_mcp_message_endpoint(&state, &headers) {
            Ok(endpoint) => endpoint,
            Err(error) => return legacy_mcp_error_response(error),
        };
        let opened = match state
            .mcp_legacy_sessions
            .open_session(identity.owner.clone(), &endpoint)
            .await
        {
            Ok(opened) => opened,
            Err(error) => return legacy_mcp_error_response(error),
        };
        if let Err(error) = state
            .mcp_peer_transport
            .register_session(
                &opened.session_id,
                &identity.owner,
                McpTransportKind::LegacyHttpSse,
            )
            .await
        {
            let _ = state
                .mcp_legacy_sessions
                .close_session(&opened.session_id, &identity.owner)
                .await;
            return mcp_jsonrpc_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                -32603,
                &error.to_string(),
            );
        }
        if let Err(error) = state
            .mcp_server
            .bind_session_identity(
                &opened.session_id,
                McpTransportKind::LegacyHttpSse,
                identity.actor,
                identity.tenant,
            )
            .await
        {
            let _ = state
                .mcp_legacy_sessions
                .close_session(&opened.session_id, &identity.owner)
                .await;
            return mcp_jsonrpc_error_response(
                StatusCode::UNAUTHORIZED,
                -32003,
                &error.to_string(),
            );
        }
        let mut pending = VecDeque::new();
        pending.push_back(opened.endpoint_event);
        (opened.session_id, opened.receiver, pending)
    };
    let stream = futures_util::stream::unfold(
        LegacySseConnection {
            registry: state.mcp_legacy_sessions.clone(),
            session_id,
            owner: identity.owner,
            receiver,
            pending,
            last_event_id,
        },
        |mut connection| async move {
            loop {
                if let Some(event) = connection.pending.pop_front() {
                    if event.id.is_some() && event.id == connection.last_event_id {
                        continue;
                    }
                    if event.id.is_some() {
                        connection.last_event_id.clone_from(&event.id);
                    }
                    return Some((
                        Ok::<_, Infallible>(legacy_axum_sse_event(event)),
                        connection,
                    ));
                }
                match connection.receiver.recv().await {
                    Ok(event) => connection.pending.push_back(event),
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        match connection
                            .registry
                            .subscribe(
                                &connection.session_id,
                                &connection.owner,
                                connection.last_event_id.as_deref(),
                            )
                            .await
                        {
                            Ok(subscription) => {
                                connection.pending = subscription.replay.into();
                                connection.receiver = subscription.receiver;
                            }
                            Err(_) => return None,
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        },
    );
    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response()
}

async fn handle_legacy_mcp_message(
    State(state): State<AppState>,
    Query(query): Query<LegacyMcpQuery>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Some(response) = reject_mcp_origin(&state, &headers) {
        return response;
    }
    let identity = match authorize_mcp_http(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let Some(session_id) = query.session_id else {
        return mcp_jsonrpc_error_response(
            StatusCode::BAD_REQUEST,
            -32600,
            "legacy MCP message endpoint requires sessionId",
        );
    };
    let frame = match state
        .mcp_legacy_sessions
        .accept_client_frame(&session_id, &identity.owner, &body)
        .await
    {
        Ok(frame) => frame,
        Err(error) => return legacy_mcp_error_response(error),
    };
    match frame {
        aip_mcp_session::McpFrame::Request(request) => {
            let response = state
                .mcp_server
                .handle_request_on_transport(&session_id, McpTransportKind::LegacyHttpSse, request)
                .await;
            if let Err(error) = state
                .mcp_legacy_sessions
                .publish_server_frame(
                    &session_id,
                    &identity.owner,
                    &aip_mcp_session::McpFrame::Response(response),
                )
                .await
            {
                return legacy_mcp_error_response(error);
            }
        }
        aip_mcp_session::McpFrame::Notification(notification) => {
            if let Err(error) = state
                .mcp_server
                .handle_notification_on_transport(
                    &session_id,
                    McpTransportKind::LegacyHttpSse,
                    notification,
                )
                .await
            {
                return mcp_jsonrpc_error_response(
                    StatusCode::BAD_REQUEST,
                    -32600,
                    &error.to_string(),
                );
            }
        }
        aip_mcp_session::McpFrame::Response(response) => {
            if let Err(error) = state
                .mcp_peer_transport
                .accept_response(&session_id, &identity.owner, response)
                .await
            {
                return mcp_jsonrpc_error_response(
                    StatusCode::BAD_REQUEST,
                    -32600,
                    &error.to_string(),
                );
            }
        }
    }
    StatusCode::ACCEPTED.into_response()
}

fn legacy_mcp_message_endpoint(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, LegacyHttpSseError> {
    if let Some(policy) = &state.mcp_protected_resource {
        let mut endpoint = Url::parse(&policy.metadata.resource)
            .map_err(|error| LegacyHttpSseError::Endpoint(error.to_string()))?;
        endpoint.set_path("/mcp/legacy/messages");
        endpoint.set_query(None);
        return Ok(endpoint.to_string());
    }
    let authority = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| LegacyHttpSseError::Endpoint("Host header is required".to_owned()))?;
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|value| matches!(*value, "http" | "https"))
        .unwrap_or("http");
    let endpoint = Url::parse(&format!("{scheme}://{authority}/mcp/legacy/messages"))
        .map_err(|error| LegacyHttpSseError::Endpoint(error.to_string()))?;
    Ok(endpoint.to_string())
}

fn legacy_axum_sse_event(event: LegacySseEvent) -> AxumSseEvent {
    let mut output = AxumSseEvent::default().event(event.event).data(event.data);
    if let Some(id) = event.id {
        output = output.id(id);
    }
    output
}

fn legacy_mcp_error_response(error: LegacyHttpSseError) -> Response {
    let status = match error {
        LegacyHttpSseError::SessionNotFound(_) | LegacyHttpSseError::OwnerMismatch => {
            StatusCode::NOT_FOUND
        }
        LegacyHttpSseError::CursorGone(_) => StatusCode::GONE,
        LegacyHttpSseError::Endpoint(_) | LegacyHttpSseError::Frame(_) => StatusCode::BAD_REQUEST,
    };
    mcp_jsonrpc_error_response(status, -32600, &error.to_string())
}

async fn handle_envelope(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    if let Err(error) = SchemaRegistry::new().validate_json(SchemaName::Envelope, &payload) {
        return protocol_error_response(
            StatusCode::BAD_REQUEST,
            ProtocolError {
                code: "schema.envelope.invalid".to_owned(),
                message: error.to_string(),
                category: ErrorCategory::Permanent,
                retryable: Some(false),
                retry_after_ms: None,
                details: Some(Box::new(
                    json!({ "schema": SchemaName::Envelope.file_name() }),
                )),
                source: Some(Box::new(json!({ "component": "aip.server.http" }))),
            },
        );
    }
    let envelope = match serde_json::from_value::<Envelope>(payload) {
        Ok(envelope) => envelope,
        Err(error) => {
            return protocol_error_response(
                StatusCode::BAD_REQUEST,
                ProtocolError {
                    code: "envelope.decode.invalid".to_owned(),
                    message: error.to_string(),
                    category: ErrorCategory::Permanent,
                    retryable: Some(false),
                    retry_after_ms: None,
                    details: None,
                    source: Some(Box::new(json!({ "component": "aip.server.http" }))),
                },
            );
        }
    };
    let actor = match native_bearer_actor(&state, &headers) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let response_session_id = envelope.session_id.clone();
    let response_correlation_id = envelope.correlation_id.clone();
    let response_message_id = envelope.message_id.clone();
    let response_recipient = envelope.from.clone();
    let response = match actor {
        Some(actor) => handle_authenticated_gateway_envelope(&state.gateway, envelope, actor).await,
        None => handle_gateway_envelope(&state.gateway, envelope).await,
    };
    match response {
        Ok(mut response) => {
            response.session_id = response_session_id;
            response.correlation_id = response_correlation_id;
            response.in_response_to = Some(MessageReference::Message(response_message_id));
            response.to = response_recipient;
            let response = match state.callback_policy.signer.as_ref() {
                Some(signer) => match sign_native_envelope(response, signer) {
                    Ok(response) => response,
                    Err(error) => return error_response(GatewayError::Runtime(error)),
                },
                None => response,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(error) => {
            let protocol = gateway_error_protocol(error);
            let status = status_for_error(&protocol);
            let Some(signer) = state.callback_policy.signer.as_ref() else {
                return protocol_error_response(status, protocol);
            };
            let mut response = Envelope::new(MessageBody::Error(ErrorBody { error: protocol }));
            response.session_id = response_session_id;
            response.correlation_id = response_correlation_id;
            response.in_response_to = Some(MessageReference::Message(response_message_id));
            response.to = response_recipient;
            match sign_native_envelope(response, signer) {
                Ok(response) => (status, Json(response)).into_response(),
                Err(error) => error_response(GatewayError::Runtime(error)),
            }
        }
    }
}

async fn handle_connector_events(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> Response {
    metrics::counter!("aip_connector_event_ingress_received_total").increment(1);
    let Some(ingress) = state.connector_event_ingress.as_ref() else {
        metrics::counter!("aip_connector_event_ingress_rejected_total").increment(1);
        return protocol_error_response(
            StatusCode::NOT_FOUND,
            ProtocolError {
                code: "connector_event.not_configured".to_owned(),
                message: "connector event ingress is not configured".to_owned(),
                category: ErrorCategory::Permanent,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: Some(Box::new(json!({ "component": "aip.server.http" }))),
            },
        );
    };
    if let Err(error) = SchemaRegistry::new().validate_json(SchemaName::Envelope, &payload) {
        metrics::counter!("aip_connector_event_ingress_rejected_total").increment(1);
        return protocol_error_response(
            StatusCode::BAD_REQUEST,
            ProtocolError {
                code: "schema.envelope.invalid".to_owned(),
                message: error.to_string(),
                category: ErrorCategory::Permanent,
                retryable: Some(false),
                retry_after_ms: None,
                details: Some(Box::new(
                    json!({ "schema": SchemaName::Envelope.file_name() }),
                )),
                source: Some(Box::new(json!({ "component": "aip.server.http" }))),
            },
        );
    }
    let envelope = match serde_json::from_value::<Envelope>(payload) {
        Ok(envelope) => envelope,
        Err(error) => {
            metrics::counter!("aip_connector_event_ingress_rejected_total").increment(1);
            return protocol_error_response(
                StatusCode::BAD_REQUEST,
                ProtocolError {
                    code: "envelope.decode.invalid".to_owned(),
                    message: error.to_string(),
                    category: ErrorCategory::Permanent,
                    retryable: Some(false),
                    retry_after_ms: None,
                    details: None,
                    source: Some(Box::new(json!({ "component": "aip.server.http" }))),
                },
            );
        }
    };
    match ingress.handle(&envelope).await {
        Ok(response) => {
            metrics::counter!("aip_connector_event_ingress_accepted_total").increment(1);
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(error) => {
            metrics::counter!("aip_connector_event_ingress_rejected_total").increment(1);
            let status = status_for_error(&error);
            match ingress.signed_error(&envelope, error.clone()) {
                Ok(response) => (status, Json(response)).into_response(),
                Err(_) => protocol_error_response(status, error),
            }
        }
    }
}

async fn handle_mcp_jsonrpc(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    if let Some(response) = reject_mcp_origin(&state, &headers) {
        return response;
    }
    let identity = match authorize_mcp_http(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let classified = match classify_request(&Method::POST, &headers, Some(payload)) {
        Ok(classified) => classified,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(aip_profile_mcp::JsonRpcResponse::error(
                    Value::Null,
                    aip_profile_mcp::JsonRpcError {
                        code: -32600,
                        message: error.to_string(),
                        data: Some(json!({ "profile": aip_profile_mcp::PROFILE_ID })),
                    },
                )),
            )
                .into_response();
        }
    };
    let McpHttpRequest::ClientMessage {
        message,
        protocol_version,
        session_id,
    } = classified
    else {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    };
    let initializes = matches!(
        message.as_ref(),
        McpHttpMessage::Request(request)
            if request.method == McpMethod::Initialize.to_string()
    );
    let session_owner = identity.owner.clone();
    let session_id = if initializes {
        session_id.unwrap_or_else(|| SessionId::new().to_string())
    } else {
        let Some(session_id) = session_id else {
            return mcp_jsonrpc_error_response(
                StatusCode::BAD_REQUEST,
                -32002,
                "MCP-Session-Id is required after initialization",
            );
        };
        session_id
    };
    if !initializes
        && !state
            .mcp_http_session_owners
            .read()
            .await
            .contains_key(&session_id)
    {
        match restore_durable_mcp_http_session(&state, &session_id, &session_owner).await {
            Ok(_) => {}
            Err(error) => {
                return mcp_jsonrpc_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    -32603,
                    &error.to_string(),
                );
            }
        }
    }
    {
        let mut owners = state.mcp_http_session_owners.write().await;
        match owners.get(&session_id) {
            Some(existing) if existing != &identity.owner => {
                return mcp_jsonrpc_error_response(
                    StatusCode::NOT_FOUND,
                    -32002,
                    "MCP session was not found",
                );
            }
            Some(_) => {}
            None if initializes => {
                owners.insert(session_id.clone(), identity.owner.clone());
            }
            None => {
                return mcp_jsonrpc_error_response(
                    StatusCode::NOT_FOUND,
                    -32002,
                    "MCP session was not found",
                );
            }
        }
    }
    if let Err(error) = state
        .mcp_peer_transport
        .register_session(
            &session_id,
            &identity.owner,
            McpTransportKind::StreamableHttp,
        )
        .await
    {
        return mcp_jsonrpc_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            -32603,
            &error.to_string(),
        );
    }
    if let Err(error) = state
        .mcp_server
        .bind_session_identity(
            &session_id,
            McpTransportKind::StreamableHttp,
            identity.actor,
            identity.tenant,
        )
        .await
    {
        return mcp_jsonrpc_error_response(StatusCode::UNAUTHORIZED, -32003, &error.to_string());
    }
    if !initializes {
        let Some(state_machine) = state.mcp_server.session_state(&session_id).await else {
            return mcp_jsonrpc_error_response(
                StatusCode::NOT_FOUND,
                -32002,
                "MCP session was not found",
            );
        };
        if protocol_version.as_deref() != state_machine.protocol_version.as_deref() {
            return mcp_jsonrpc_error_response(
                StatusCode::BAD_REQUEST,
                -32001,
                "MCP-Protocol-Version does not match the negotiated session version",
            );
        }
    }
    let negotiated_version = state
        .mcp_server
        .session_state(&session_id)
        .await
        .and_then(|session| session.protocol_version);
    let mut response = match *message {
        McpHttpMessage::Request(request) => {
            let response = state
                .mcp_server
                .handle_request_on_transport(&session_id, McpTransportKind::StreamableHttp, request)
                .await;
            (StatusCode::OK, Json(response)).into_response()
        }
        McpHttpMessage::Notification(notification) => match state
            .mcp_server
            .handle_notification_on_transport(
                &session_id,
                McpTransportKind::StreamableHttp,
                notification,
            )
            .await
        {
            Ok(()) => StatusCode::ACCEPTED.into_response(),
            Err(error) => (
                StatusCode::BAD_REQUEST,
                Json(aip_profile_mcp::JsonRpcResponse::error(
                    Value::Null,
                    aip_profile_mcp::JsonRpcError {
                        code: -32600,
                        message: error.to_string(),
                        data: Some(json!({ "profile": aip_profile_mcp::PROFILE_ID })),
                    },
                )),
            )
                .into_response(),
        },
        McpHttpMessage::Response(response) => match state
            .mcp_peer_transport
            .accept_response(&session_id, &identity.owner, response)
            .await
        {
            Ok(()) => StatusCode::ACCEPTED.into_response(),
            Err(error) => {
                mcp_jsonrpc_error_response(StatusCode::BAD_REQUEST, -32600, &error.to_string())
            }
        },
    };
    let state_machine = state.mcp_server.session_state(&session_id).await;
    if state_machine.as_ref().is_some_and(|session| {
        matches!(
            session.lifecycle,
            McpLifecycle::Initializing | McpLifecycle::Initialized
        )
    }) {
        if let Err(error) = persist_mcp_http_session(&state, &session_id, &session_owner).await {
            return mcp_jsonrpc_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                -32603,
                &error.to_string(),
            );
        }
    } else if initializes {
        state
            .mcp_http_session_owners
            .write()
            .await
            .remove(&session_id);
        if let Err(error) = state.mcp_server.delete_session(&session_id).await {
            return mcp_jsonrpc_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                -32603,
                &error.to_string(),
            );
        }
        state.mcp_peer_transport.close_session(&session_id).await;
    }
    if let Ok(value) = HeaderValue::from_str(&session_id) {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("mcp-session-id"), value);
    }
    let version = if initializes {
        state
            .mcp_server
            .session_state(&session_id)
            .await
            .and_then(|session| session.protocol_version)
    } else {
        negotiated_version
    };
    if let Some(version) = version
        && let Ok(value) = HeaderValue::from_str(&version)
    {
        response.headers_mut().insert(
            header::HeaderName::from_static("mcp-protocol-version"),
            value,
        );
    }
    response
}

async fn handle_mcp_stream(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (session_id, _version) = match authorize_existing_mcp_session(&state, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let last_event_id = aip_transport_mcp_streamable_http::last_event_id(&headers)
        .ok()
        .flatten();
    // Subscribe before loading replay state. Events published during the read
    // are either in the replay page or buffered by this receiver; duplicate
    // ids are suppressed by the connection cursor below.
    let receiver = match state.mcp_sse_replay.subscribe(&session_id).await {
        Ok(receiver) => receiver,
        Err(error) => {
            return mcp_jsonrpc_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                -32603,
                &error.to_string(),
            );
        }
    };
    let replayed = if last_event_id.is_some() {
        match state
            .mcp_sse_replay
            .replay_after(&session_id, last_event_id.as_deref())
            .await
        {
            Ok(events) => events,
            Err(error) => {
                return mcp_jsonrpc_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    -32603,
                    &error.to_string(),
                );
            }
        }
    } else {
        Vec::new()
    };
    let stream = futures_util::stream::unfold(
        McpSseConnection {
            hub: state.mcp_sse_replay.clone(),
            session_id: session_id.clone(),
            receiver,
            pending: replayed.into(),
            last_event_id,
        },
        |mut connection| async move {
            loop {
                if let Some(event) = connection.pending.pop_front() {
                    if event.id == connection.last_event_id {
                        continue;
                    }
                    connection.last_event_id.clone_from(&event.id);
                    return Some((Ok::<_, Infallible>(mcp_axum_sse_event(event)), connection));
                }
                match connection.receiver.recv().await {
                    Ok(event) => connection.pending.push_back(event),
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        connection.pending = connection
                            .hub
                            .replay_after(
                                &connection.session_id,
                                connection.last_event_id.as_deref(),
                            )
                            .await
                            .unwrap_or_default()
                            .into();
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        },
    );
    let mut response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-transform"),
    );
    if let Ok(session_id) = HeaderValue::from_str(&session_id) {
        response.headers_mut().insert(
            header::HeaderName::from_static("mcp-session-id"),
            session_id,
        );
    }
    response
}

fn mcp_axum_sse_event(event: McpSseEvent) -> AxumSseEvent {
    let mut output = AxumSseEvent::default().data(event.data);
    if let Some(id) = event.id {
        output = output.id(id);
    }
    if let Some(kind) = event.event {
        output = output.event(kind);
    }
    output
}

async fn handle_mcp_session_delete(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (session_id, _version) = match authorize_existing_mcp_session(&state, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let snapshot = state.mcp_server.session_snapshot(&session_id).await;
    if let Err(error) = state.mcp_server.delete_session(&session_id).await {
        return mcp_jsonrpc_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            -32603,
            &error.to_string(),
        );
    }
    if let Err(error) = delete_durable_mcp_http_session(&state, &session_id).await {
        let restoration = match snapshot {
            Some(snapshot) => state.mcp_server.restore_session(snapshot).await,
            None => Ok(()),
        };
        let message = restoration.map_or_else(
            |restore_error| {
                format!(
                    "{error}; additionally failed to restore the in-memory MCP session: {restore_error}"
                )
            },
            |()| error.to_string(),
        );
        return mcp_jsonrpc_error_response(StatusCode::INTERNAL_SERVER_ERROR, -32603, &message);
    }
    state
        .mcp_http_session_owners
        .write()
        .await
        .remove(&session_id);
    state.mcp_sse_replay.close(&session_id).await;
    state.mcp_peer_transport.close_session(&session_id).await;
    StatusCode::NO_CONTENT.into_response()
}

async fn authorize_existing_mcp_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, String), Response> {
    if let Some(response) = reject_mcp_origin(state, headers) {
        return Err(response);
    }
    let identity = authorize_mcp_http(state, headers).await?;
    let session_id = aip_transport_mcp_streamable_http::session_id(headers)
        .map_err(|error| {
            mcp_jsonrpc_error_response(StatusCode::BAD_REQUEST, -32600, &error.to_string())
        })?
        .ok_or_else(|| {
            mcp_jsonrpc_error_response(
                StatusCode::BAD_REQUEST,
                -32002,
                "MCP-Session-Id is required",
            )
        })?;
    if !state
        .mcp_http_session_owners
        .read()
        .await
        .contains_key(&session_id)
    {
        restore_durable_mcp_http_session(state, &session_id, &identity.owner)
            .await
            .map_err(|error| {
                mcp_jsonrpc_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    -32603,
                    &error.to_string(),
                )
            })?;
    }
    if state
        .mcp_http_session_owners
        .read()
        .await
        .get(&session_id)
        .is_none_or(|expected| expected != &identity.owner)
    {
        return Err(mcp_jsonrpc_error_response(
            StatusCode::NOT_FOUND,
            -32002,
            "MCP session was not found",
        ));
    }
    let session = state
        .mcp_server
        .session_state(&session_id)
        .await
        .ok_or_else(|| {
            mcp_jsonrpc_error_response(StatusCode::NOT_FOUND, -32002, "MCP session was not found")
        })?;
    state
        .mcp_server
        .bind_session_identity(
            &session_id,
            McpTransportKind::StreamableHttp,
            identity.actor,
            identity.tenant,
        )
        .await
        .map_err(|error| {
            mcp_jsonrpc_error_response(StatusCode::UNAUTHORIZED, -32003, &error.to_string())
        })?;
    let version = session.protocol_version.ok_or_else(|| {
        mcp_jsonrpc_error_response(
            StatusCode::BAD_REQUEST,
            -32002,
            "MCP session initialization is incomplete",
        )
    })?;
    let presented =
        aip_transport_mcp_streamable_http::protocol_version(headers).map_err(|error| {
            mcp_jsonrpc_error_response(StatusCode::BAD_REQUEST, -32600, &error.to_string())
        })?;
    if presented.as_deref() != Some(version.as_str()) {
        return Err(mcp_jsonrpc_error_response(
            StatusCode::BAD_REQUEST,
            -32001,
            "MCP-Protocol-Version does not match the negotiated session version",
        ));
    }
    Ok((session_id, version))
}

async fn persist_mcp_http_session(
    state: &AppState,
    session_id: &str,
    owner: &str,
) -> RuntimeResult<()> {
    let snapshot = state
        .mcp_server
        .session_snapshot(session_id)
        .await
        .ok_or_else(|| {
            RuntimeError::Storage(format!(
                "MCP session `{session_id}` disappeared before durable checkpoint"
            ))
        })?;
    let now = OffsetDateTime::now_utc();
    let record = DurableMcpHttpSession {
        owner: owner.to_owned(),
        snapshot,
        updated_at: now,
        expires_at: now + time::Duration::milliseconds(MCP_HTTP_SESSION_TTL_MS),
    };
    state
        .profile_state
        .put(
            MCP_HTTP_SESSIONS_NAMESPACE,
            session_id,
            serde_json::to_value(record)
                .map_err(|error| RuntimeError::Storage(error.to_string()))?,
        )
        .await?;
    Ok(())
}

async fn restore_durable_mcp_http_session(
    state: &AppState,
    session_id: &str,
    owner: &str,
) -> RuntimeResult<bool> {
    let Some(entry) = state
        .profile_state
        .get(MCP_HTTP_SESSIONS_NAMESPACE, session_id)
        .await?
    else {
        return Ok(false);
    };
    let record = serde_json::from_value::<DurableMcpHttpSession>(entry.value.clone())
        .map_err(|error| RuntimeError::Storage(error.to_string()))?;
    if record.expires_at <= OffsetDateTime::now_utc() {
        let _ = state
            .profile_state
            .delete(MCP_HTTP_SESSIONS_NAMESPACE, session_id, entry.revision)
            .await?;
        return Ok(false);
    }
    if record.owner != owner {
        return Ok(false);
    }
    if record.snapshot.state.transport != McpTransportKind::StreamableHttp
        || !matches!(
            record.snapshot.state.lifecycle,
            McpLifecycle::Initializing | McpLifecycle::Initialized
        )
    {
        return Err(RuntimeError::Storage(format!(
            "durable MCP session `{session_id}` is not an initialized Streamable HTTP session"
        )));
    }
    state
        .mcp_server
        .restore_session(record.snapshot)
        .await
        .map_err(|error| RuntimeError::Storage(error.to_string()))?;
    state
        .mcp_peer_transport
        .register_session(session_id, owner, McpTransportKind::StreamableHttp)
        .await
        .map_err(|error| RuntimeError::Storage(error.to_string()))?;
    state
        .mcp_http_session_owners
        .write()
        .await
        .insert(session_id.to_owned(), owner.to_owned());
    Ok(true)
}

async fn delete_durable_mcp_http_session(state: &AppState, session_id: &str) -> RuntimeResult<()> {
    for _ in 0..32 {
        let Some(entry) = state
            .profile_state
            .get(MCP_HTTP_SESSIONS_NAMESPACE, session_id)
            .await?
        else {
            return Ok(());
        };
        if state
            .profile_state
            .delete(MCP_HTTP_SESSIONS_NAMESPACE, session_id, entry.revision)
            .await?
        {
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
    Err(RuntimeError::Storage(format!(
        "MCP session `{session_id}` remained contended during deletion"
    )))
}

#[derive(Clone)]
struct McpHttpIdentity {
    owner: String,
    actor: AuthenticatedPrincipal,
    tenant: Option<VerifiedTenant>,
}

async fn authorize_mcp_http(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<McpHttpIdentity, Response> {
    let Some(policy) = state.mcp_protected_resource.as_ref() else {
        if !state.allow_insecure_development {
            return Err(mcp_jsonrpc_error_response(
                StatusCode::UNAUTHORIZED,
                -32003,
                "MCP HTTP authentication is not configured",
            ));
        }
        return Ok(McpHttpIdentity {
            owner: "local-development".to_owned(),
            actor: AuthenticatedPrincipal {
                principal: state.mcp_principal.clone(),
                scheme: AuthScheme::DidProof,
                issuer: "getaip-server:local-development".to_owned(),
                audience: Some("aip".to_owned()),
                scopes: BTreeSet::from(["*".to_owned()]),
                authenticated_at: OffsetDateTime::now_utc(),
                expires_at: None,
                credential_fingerprint: None,
            },
            tenant: None,
        });
    };
    let token = match bearer_token(headers) {
        Ok(Some(token)) => token,
        Ok(None) => {
            return Err(mcp_http_response_to_axum(bearer_unauthorized_response(
                &policy.challenge(
                    Some("invalid_token"),
                    Some("bearer token is required".to_owned()),
                ),
            )));
        }
        Err(error) => {
            return Err(mcp_http_response_to_axum(bearer_unauthorized_response(
                &policy.challenge(Some("invalid_request"), Some(error.to_string())),
            )));
        }
    };
    if let Some(verifier) = state.mcp_token_verifier.as_ref() {
        let verified = verifier
            .verify(
                &BearerToken::new(token.as_bytes().to_vec()).map_err(|error| {
                    mcp_http_response_to_axum(bearer_unauthorized_response(
                        &policy.challenge(Some("invalid_token"), Some(error.to_string())),
                    ))
                })?,
                &TokenVerificationRequest {
                    accepted_issuers: policy
                        .metadata
                        .authorization_servers
                        .iter()
                        .cloned()
                        .collect(),
                    audience: policy.metadata.resource.clone(),
                    required_scopes: policy
                        .required_scope
                        .as_deref()
                        .map(|scopes| scopes.split_whitespace().map(ToOwned::to_owned).collect())
                        .unwrap_or_default(),
                    now: OffsetDateTime::now_utc(),
                },
            )
            .await
            .map_err(|error| {
                mcp_http_response_to_axum(bearer_unauthorized_response(
                    &policy.challenge(Some("invalid_token"), Some(error.to_string())),
                ))
            })?;
        let principal_id = PrincipalId::parse(&verified.subject).map_err(|_| {
            mcp_http_response_to_axum(bearer_unauthorized_response(&policy.challenge(
                Some("invalid_token"),
                Some("token subject is not a canonical AIP principal id".to_owned()),
            )))
        })?;
        let principal = Principal::new(principal_id, principal_kind_for_id(&verified.subject));
        let tenant = verified.tenant_id.as_ref().map(|tenant_id| VerifiedTenant {
            tenant: aip_core::TenantRef {
                id: tenant_id.clone(),
                system: Some(verified.issuer.clone()),
            },
            membership_id: format!("oauth:{}:{}", verified.issuer, verified.subject),
            roles: BTreeSet::new(),
            groups: BTreeSet::new(),
            verified_at: OffsetDateTime::now_utc(),
            expires_at: Some(verified.expires_at),
        });
        return Ok(McpHttpIdentity {
            owner: format!(
                "{}:{}:{}",
                verified.issuer,
                verified.subject,
                verified.tenant_id.as_deref().unwrap_or("-")
            ),
            actor: AuthenticatedPrincipal {
                principal,
                scheme: AuthScheme::Oauth2,
                issuer: verified.issuer,
                audience: Some(policy.metadata.resource.clone()),
                scopes: verified.scopes,
                authenticated_at: OffsetDateTime::now_utc(),
                expires_at: Some(verified.expires_at),
                credential_fingerprint: Some(verified.token_fingerprint),
            },
            tenant,
        });
    }
    let Some(expected) = policy.bearer_token.as_ref() else {
        return Err(mcp_http_response_to_axum(bearer_unauthorized_response(
            &policy.challenge(
                Some("invalid_token"),
                Some("production token verifier is not configured".to_owned()),
            ),
        )));
    };
    if !state.allow_insecure_development {
        return Err(mcp_http_response_to_axum(bearer_unauthorized_response(
            &policy.challenge(
                Some("invalid_token"),
                Some("static bearer tokens are restricted to local development".to_owned()),
            ),
        )));
    }
    if constant_time_eq::constant_time_eq(expected.as_bytes(), token.as_bytes()) {
        Ok(McpHttpIdentity {
            owner: format!("sha256:{}", hex::encode(Sha256::digest(token.as_bytes()))),
            actor: AuthenticatedPrincipal {
                principal: state.mcp_principal.clone(),
                scheme: AuthScheme::Bearer,
                issuer: "getaip-server:static-development-token".to_owned(),
                audience: Some(policy.metadata.resource.clone()),
                scopes: BTreeSet::from(["*".to_owned()]),
                authenticated_at: OffsetDateTime::now_utc(),
                expires_at: None,
                credential_fingerprint: Some(format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(token.as_bytes()))
                )),
            },
            tenant: None,
        })
    } else {
        Err(mcp_http_response_to_axum(bearer_unauthorized_response(
            &policy.challenge(
                Some("invalid_token"),
                Some("missing or invalid bearer token".to_owned()),
            ),
        )))
    }
}

fn principal_kind_for_id(id: &str) -> PrincipalKind {
    if id.starts_with("user:") || id.starts_with("human:") {
        PrincipalKind::Human
    } else if id.starts_with("service:") {
        PrincipalKind::Service
    } else if id.starts_with("system:") {
        PrincipalKind::System
    } else if id.starts_with("tenant:") {
        PrincipalKind::Tenant
    } else {
        PrincipalKind::Agent
    }
}

fn reject_mcp_origin(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let origin = match headers.get(header::ORIGIN) {
        Some(value) => match value.to_str() {
            Ok(value) => Some(value),
            Err(_) => {
                return Some(mcp_jsonrpc_error_response(
                    StatusCode::BAD_REQUEST,
                    -32600,
                    "Origin header is not valid text",
                ));
            }
        },
        None => None,
    };
    let (allowed, local_only) = state.mcp_protected_resource.as_ref().map_or_else(
        || (&[][..], true),
        |policy| {
            (
                policy.allowed_origins.as_slice(),
                policy.allow_loopback_origins,
            )
        },
    );
    validate_origin(origin, allowed, local_only)
        .err()
        .map(|error| mcp_jsonrpc_error_response(StatusCode::FORBIDDEN, -32003, &error.to_string()))
}

fn mcp_jsonrpc_error_response(status: StatusCode, code: i64, message: &str) -> Response {
    (
        status,
        Json(aip_profile_mcp::JsonRpcResponse::error(
            Value::Null,
            aip_profile_mcp::JsonRpcError {
                code,
                message: message.to_owned(),
                data: Some(json!({ "component": "aip.server.mcp_http" })),
            },
        )),
    )
        .into_response()
}

fn mcp_http_response_to_axum(response: McpHttpResponse) -> Response {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut output = match response.body {
        Some(Value::String(body)) => (status, body).into_response(),
        Some(body) => (status, Json(body)).into_response(),
        None => status.into_response(),
    };
    for (name, value) in response.headers {
        if let (Ok(name), Ok(value)) = (
            header::HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            output.headers_mut().insert(name, value);
        }
    }
    output
}

async fn a2a_agent_card(State(state): State<AppState>) -> Json<aip_profile_a2a::AgentCard> {
    Json(a2a_agent_card_for_state(&state))
}

fn a2a_agent_card_for_state(state: &AppState) -> aip_profile_a2a::AgentCard {
    let mut card = aip_profile_a2a::agent_card_from_manifest(
        &state.manifest,
        Some(state.a2a_interface_url.clone()),
    );
    card.capabilities.push_notifications = state.callback_policy.signer.is_some()
        && state.callback_policy.a2a_credential_key.is_some();
    if state.native_http_auth.is_some() {
        card.security_schemes.insert(
            "aipBearer".to_owned(),
            aip_profile_a2a::A2aSecurityScheme::Http {
                http_auth_security_scheme: aip_profile_a2a::A2aHttpAuthSecurityScheme {
                    description: Some(
                        "Bearer identity bound by the AIP daemon to a trusted principal".to_owned(),
                    ),
                    scheme: "Bearer".to_owned(),
                    bearer_format: None,
                },
            },
        );
        card.security = vec![json!({ "schemes": { "aipBearer": { "list": [] } } })];
        card.capabilities.extended_agent_card = true;
        card.supports_authenticated_extended_card = true;
    }
    if state.capability_catalog.is_some() {
        card.capabilities
            .extensions
            .push(aip_profile_a2a::A2aAgentExtension {
            uri: "urn:getaip:a2a:extension:tenant-capability-discovery:v1".to_owned(),
            description:
                "Tenant-scoped, cursor-paginated discovery for remote AIP connector capabilities"
                    .to_owned(),
            required: false,
            params: Some(json!({
                "endpoint": state.capability_discovery_url,
                "authentication": "bearer",
                "native_action_capability_id": CAPABILITY_CATALOG_QUERY_ID,
                "native_action_authentication": "signed_aip_envelope_with_verified_tenant",
                "pagination": "catalog_revision_cursor",
                "agent_card_materializes_fleet": false,
            })),
        });
    }
    card
}

async fn handle_a2a_jsonrpc(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<A2aJsonRpcRequest>,
) -> Response {
    if request.jsonrpc != "2.0" {
        return a2a_json_response(
            StatusCode::BAD_REQUEST,
            aip_profile_a2a::error_response(
                request.id,
                -32600,
                "A2A JSON-RPC requests must use jsonrpc 2.0",
            ),
        );
    }
    if let Some(version) = headers.get("a2a-version") {
        let Ok(version) = version.to_str() else {
            return a2a_json_response(
                StatusCode::BAD_REQUEST,
                aip_profile_a2a::error_response(
                    request.id,
                    -32009,
                    "A2A-Version header is not valid ASCII",
                ),
            );
        };
        if version != "1.0" {
            return a2a_json_response(
                StatusCode::OK,
                aip_profile_a2a::error_response(
                    request.id,
                    -32009,
                    format!("A2A protocol version `{version}` is not supported"),
                ),
            );
        }
    }
    let actor = match a2a_authenticated_actor(&state, &headers) {
        Ok(actor) => actor,
        Err(message) => {
            return a2a_json_response(
                StatusCode::UNAUTHORIZED,
                aip_profile_a2a::error_response(request.id, -32000, message),
            );
        }
    };
    let operation = match aip_profile_a2a::operation_from_method(&request.method) {
        Ok(operation) => operation,
        Err(error) => {
            return a2a_json_response(
                StatusCode::OK,
                aip_profile_a2a::error_response(request.id, -32601, error.to_string()),
            );
        }
    };
    use aip_profile_a2a::A2aOperation;
    match operation {
        A2aOperation::SendMessage => a2a_json_response(
            StatusCode::OK,
            Box::pin(handle_a2a_task_send(&state, &request, &actor)).await,
        ),
        A2aOperation::StreamMessage => {
            Box::pin(handle_a2a_stream_message(state, request, actor)).await
        }
        A2aOperation::GetTask => a2a_json_response(
            StatusCode::OK,
            Box::pin(handle_a2a_task_get(&state, &request, &actor)).await,
        ),
        A2aOperation::ListTasks => a2a_json_response(
            StatusCode::OK,
            Box::pin(handle_a2a_task_list(&state, &request, &actor)).await,
        ),
        A2aOperation::CancelTask => a2a_json_response(
            StatusCode::OK,
            Box::pin(handle_a2a_task_cancel(&state, &request, &actor)).await,
        ),
        A2aOperation::SubscribeTask => {
            Box::pin(handle_a2a_task_subscribe(state, request, actor)).await
        }
        A2aOperation::CreatePushConfig => a2a_json_response(
            StatusCode::OK,
            Box::pin(handle_a2a_push_config_create(&state, &request, &actor)).await,
        ),
        A2aOperation::GetPushConfig => a2a_json_response(
            StatusCode::OK,
            Box::pin(handle_a2a_push_config_get(&state, &request, &actor)).await,
        ),
        A2aOperation::ListPushConfigs => a2a_json_response(
            StatusCode::OK,
            Box::pin(handle_a2a_push_config_list(&state, &request, &actor)).await,
        ),
        A2aOperation::DeletePushConfig => a2a_json_response(
            StatusCode::OK,
            Box::pin(handle_a2a_push_config_delete(&state, &request, &actor)).await,
        ),
        A2aOperation::GetExtendedAgentCard => a2a_json_response(
            StatusCode::OK,
            aip_profile_a2a::success_response(
                request.id,
                serde_json::to_value(a2a_agent_card_for_state(&state))
                    .unwrap_or_else(|_| json!({})),
            ),
        ),
    }
}

fn a2a_authenticated_actor(state: &AppState, headers: &HeaderMap) -> Result<Principal, String> {
    native_bearer_actor(state, headers)
        .map_err(|_| "invalid A2A bearer credentials".to_owned())?
        .ok_or_else(|| "A2A bearer authentication is required".to_owned())
}

fn a2a_json_response(status: StatusCode, response: A2aJsonRpcResponse) -> Response {
    (status, Json(response)).into_response()
}

async fn a2a_action_from_send_request(
    state: &AppState,
    request: &A2aJsonRpcRequest,
    actor: &Principal,
) -> Result<Action, (i64, String)> {
    if matches!(
        request.method.as_str(),
        "tasks/send" | "tasks/sendSubscribe"
    ) {
        aip_profile_a2a::task_send_params(request)
            .and_then(aip_profile_a2a::action_from_task_send)
            .map_err(|error| (-32602, error.to_string()))
    } else {
        let params = aip_profile_a2a::send_message_params(request)
            .map_err(|error| (-32602, error.to_string()))?;
        let push_config = params.configuration.task_push_notification_config.clone();
        let message_id = params.message.message_id.clone();
        let tenant = params.tenant.clone();
        let action = aip_profile_a2a::action_from_send_message(params)
            .map_err(|error| (-32602, error.to_string()))?;
        if let Some(mut config) = push_config {
            if !a2a_push_notifications_enabled(state) {
                return Err((
                    -32003,
                    "A2A push notifications are not enabled on this endpoint".to_owned(),
                ));
            }
            let task_id = aip_profile_a2a::task_id_for_action(&action);
            if !config.task_id.is_empty() && config.task_id != task_id {
                return Err((
                    -32602,
                    "taskPushNotificationConfig.taskId must be empty for a new task or match message.taskId"
                        .to_owned(),
                ));
            }
            config.task_id = task_id;
            if config.id.trim().is_empty() {
                config.id = format!("push-{message_id}");
            }
            if config.tenant.is_none() {
                config.tenant = tenant;
            }
            persist_a2a_push_config(state, config, actor, true)
                .await
                .map_err(|error| (-32603, error.to_string()))?;
        }
        Ok(action)
    }
}

async fn handle_a2a_stream_message(
    state: AppState,
    request: A2aJsonRpcRequest,
    actor: Principal,
) -> Response {
    let mut action = match a2a_action_from_send_request(&state, &request, &actor).await {
        Ok(action) => action,
        Err((code, message)) => {
            return a2a_json_response(
                StatusCode::OK,
                aip_profile_a2a::error_response(request.id, code, message),
            );
        }
    };
    action.mode = Some(aip_core::ActionMode::Async);
    let action_id = action.id.clone();
    let task_id = aip_profile_a2a::task_id_for_action(&action);
    let skill_id = aip_profile_a2a::skill_id_for_action(&action);
    let context_id = action
        .memory_context
        .as_ref()
        .and_then(|value| value.pointer("/a2a/context_id"))
        .and_then(Value::as_str)
        .unwrap_or(&task_id)
        .to_owned();
    let initial_history = a2a_request_message_value(&request)
        .into_iter()
        .collect::<Vec<_>>();
    let mut envelope = Envelope::new(MessageBody::Action(Box::new(action)));
    envelope.trace = Some(json!({
        "profile": aip_profile_a2a::PROFILE_ID,
        "jsonrpc_id": request.id
    }));
    let response = match handle_authenticated_gateway_envelope(
        &state.gateway,
        envelope,
        actor.clone(),
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            return a2a_json_response(
                StatusCode::OK,
                aip_profile_a2a::error_response(request.id, -32603, error.to_string()),
            );
        }
    };
    if let MessageBody::Error(error) = response.body {
        return a2a_json_response(
            StatusCode::OK,
            aip_profile_a2a::error_response(request.id, -32000, error.error.message),
        );
    }
    let request_id = request.id.clone();
    let initial_task = json!({
        "id": task_id.clone(),
        "contextId": context_id.clone(),
        "status": { "state": "TASK_STATE_SUBMITTED" },
        "artifacts": [],
        "history": initial_history,
        "metadata": { "aip": { "action_id": action_id.clone() } }
    });
    if let Err(error) = state
        .profile_state
        .put(A2A_TASKS_NAMESPACE, &task_id, initial_task.clone())
        .await
    {
        return a2a_json_response(
            StatusCode::OK,
            aip_profile_a2a::error_response(request.id, -32603, error.to_string()),
        );
    }
    a2a_task_stream_response(A2aTaskStreamState {
        state,
        actor,
        request_id: request_id.clone(),
        action_id,
        task_id,
        context_id,
        skill_id,
        pending: VecDeque::from([a2a_stream_event(
            request_id,
            json!({ "task": initial_task }),
        )]),
        last_state: None,
        last_chunk_sequence: None,
        terminal: false,
    })
}

async fn handle_a2a_task_subscribe(
    state: AppState,
    request: A2aJsonRpcRequest,
    actor: Principal,
) -> Response {
    let params = match aip_profile_a2a::task_id_params(&request) {
        Ok(params) => params,
        Err(error) => {
            return a2a_json_response(
                StatusCode::OK,
                aip_profile_a2a::error_response(request.id, -32602, error.to_string()),
            );
        }
    };
    let action_id = match action_id_for_a2a_task(&state, &params.id).await {
        Ok(action_id) => action_id,
        Err(error) => {
            return a2a_json_response(
                StatusCode::OK,
                aip_profile_a2a::error_response(request.id, -32001, error.to_string()),
            );
        }
    };
    let status = match a2a_native_action_status(&state, &action_id, &actor).await {
        Ok(Some(status)) => status,
        Ok(None) => {
            return a2a_json_response(
                StatusCode::OK,
                aip_profile_a2a::error_response(request.id, -32001, "task not found"),
            );
        }
        Err(error) => {
            return a2a_json_response(
                StatusCode::OK,
                aip_profile_a2a::error_response(request.id, -32603, error),
            );
        }
    };
    if is_terminal_action_state(status.state) {
        return a2a_json_response(
            StatusCode::OK,
            aip_profile_a2a::error_response(
                request.id,
                -32004,
                "cannot subscribe to a terminal A2A task",
            ),
        );
    }
    let skill_id = skill_id_from_action_status(&status);
    let context_id = status
        .session_id
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| params.id.clone());
    a2a_task_stream_response(A2aTaskStreamState {
        state,
        actor,
        request_id: request.id,
        action_id,
        task_id: params.id,
        context_id,
        skill_id,
        pending: VecDeque::new(),
        last_state: None,
        last_chunk_sequence: None,
        terminal: false,
    })
}

struct A2aTaskStreamState {
    state: AppState,
    actor: Principal,
    request_id: Value,
    action_id: ActionId,
    task_id: String,
    context_id: String,
    skill_id: String,
    pending: VecDeque<AxumSseEvent>,
    last_state: Option<ActionLifecycleState>,
    last_chunk_sequence: Option<u64>,
    terminal: bool,
}

fn a2a_task_stream_response(initial: A2aTaskStreamState) -> Response {
    let stream = futures_util::stream::unfold(initial, |mut stream| async move {
        loop {
            if let Some(event) = stream.pending.pop_front() {
                return Some((Ok::<_, Infallible>(event), stream));
            }
            if stream.terminal {
                return None;
            }
            match a2a_native_action_status(&stream.state, &stream.action_id, &stream.actor).await {
                Ok(Some(status)) => {
                    let task = aip_profile_a2a::task_from_action_status(
                        stream.task_id.clone(),
                        stream.skill_id.clone(),
                        &status,
                    );
                    if stream.last_state != Some(status.state) {
                        stream.pending.push_back(a2a_stream_event(
                            stream.request_id.clone(),
                            json!({
                                "statusUpdate": {
                                    "taskId": stream.task_id,
                                    "contextId": stream.context_id,
                                    "status": task.status,
                                    "metadata": { "aip": { "actionState": status.state } }
                                }
                            }),
                        ));
                        stream.last_state = Some(status.state);
                    }
                    let new_chunks = status
                        .chunks
                        .iter()
                        .filter(|chunk| {
                            stream
                                .last_chunk_sequence
                                .is_none_or(|sequence| chunk.sequence > sequence)
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    for chunk in &new_chunks {
                        let update = aip_profile_a2a::artifact_update_from_stream_chunk(
                            stream.task_id.clone(),
                            stream.context_id.clone(),
                            chunk,
                        );
                        stream.pending.push_back(a2a_stream_event(
                            stream.request_id.clone(),
                            json!({ "artifactUpdate": update }),
                        ));
                        stream.last_chunk_sequence = Some(chunk.sequence);
                    }
                    stream.terminal = is_terminal_action_state(status.state);
                }
                Ok(None) => {
                    stream.pending.push_back(a2a_stream_event(
                        stream.request_id.clone(),
                        serde_json::to_value(aip_profile_a2a::error_response(
                            stream.request_id.clone(),
                            -32001,
                            "task not found",
                        ))
                        .unwrap_or_else(|_| json!({})),
                    ));
                    stream.terminal = true;
                }
                Err(error) => {
                    stream.pending.push_back(a2a_stream_event(
                        stream.request_id.clone(),
                        serde_json::to_value(aip_profile_a2a::error_response(
                            stream.request_id.clone(),
                            -32603,
                            error,
                        ))
                        .unwrap_or_else(|_| json!({})),
                    ));
                    stream.terminal = true;
                }
            }
            if stream.pending.is_empty() && !stream.terminal {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    });
    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response()
}

fn a2a_stream_event(request_id: Value, result: Value) -> AxumSseEvent {
    AxumSseEvent::default()
        .data(json!({ "jsonrpc": "2.0", "id": request_id, "result": result }).to_string())
}

fn is_terminal_action_state(state: ActionLifecycleState) -> bool {
    matches!(
        state,
        ActionLifecycleState::Cancelled
            | ActionLifecycleState::Completed
            | ActionLifecycleState::Failed
            | ActionLifecycleState::Expired
            | ActionLifecycleState::DeadLettered
    )
}

async fn handle_a2a_task_send(
    state: &AppState,
    request: &A2aJsonRpcRequest,
    actor: &Principal,
) -> A2aJsonRpcResponse {
    let action = match a2a_action_from_send_request(state, request, actor).await {
        Ok(action) => action,
        Err((code, message)) => {
            return aip_profile_a2a::error_response(request.id.clone(), code, message);
        }
    };
    let task_id = aip_profile_a2a::task_id_for_action(&action);
    let skill_id = aip_profile_a2a::skill_id_for_action(&action);
    let context_id = action
        .memory_context
        .as_ref()
        .and_then(|value| value.pointer("/a2a/context_id"))
        .and_then(Value::as_str)
        .unwrap_or(&task_id)
        .to_owned();
    let mut envelope = Envelope::new(MessageBody::Action(Box::new(action)));
    envelope.trace = Some(json!({
        "profile": aip_profile_a2a::PROFILE_ID,
        "jsonrpc_id": request.id
    }));
    let mut task_value = match handle_authenticated_gateway_envelope(
        &state.gateway,
        envelope,
        actor.clone(),
    )
    .await
    {
        Ok(response) => match response.body {
            MessageBody::ActionResult(result) => {
                let task = aip_profile_a2a::task_from_result(task_id.clone(), skill_id, &result);
                match serde_json::to_value(task) {
                    Ok(value) => value,
                    Err(error) => {
                        return aip_profile_a2a::error_response(
                            request.id.clone(),
                            -32603,
                            error.to_string(),
                        );
                    }
                }
            }
            MessageBody::Ack(ack) => json!({
                "id": task_id.clone(),
                "contextId": task_id.clone(),
                "status": { "state": "TASK_STATE_SUBMITTED" },
                "artifacts": [],
                "history": [],
                "metadata": {
                    "aip": {
                        "action_id": ack.action_id,
                        "ack_status": ack.status,
                        "reason": ack.reason
                    }
                }
            }),
            MessageBody::ActionStatus(status) => {
                let task =
                    aip_profile_a2a::task_from_action_status(task_id.clone(), skill_id, &status);
                serde_json::to_value(task).unwrap_or_else(|_| json!({ "id": task_id }))
            }
            MessageBody::Error(body) => {
                return aip_profile_a2a::error_response(
                    request.id.clone(),
                    -32000,
                    body.error.message,
                );
            }
            body => {
                return aip_profile_a2a::error_response(
                    request.id.clone(),
                    -32603,
                    format!("unexpected AIP response `{}`", body.message_type().as_str()),
                );
            }
        },
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32000, error.to_string());
        }
    };
    if let Some(object) = task_value.as_object_mut() {
        object.insert("contextId".to_owned(), json!(context_id));
        if let Some(message) = a2a_request_message_value(request) {
            object.insert("history".to_owned(), json!([message]));
        }
    }
    if let Err(error) = state
        .profile_state
        .put(A2A_TASKS_NAMESPACE, &task_id, task_value.clone())
        .await
    {
        return aip_profile_a2a::error_response(request.id.clone(), -32603, error.to_string());
    }
    let result = if request.method == "SendMessage" {
        json!({ "task": task_value })
    } else {
        task_value
    };
    aip_profile_a2a::success_response(request.id.clone(), result)
}

fn a2a_request_message_value(request: &A2aJsonRpcRequest) -> Option<Value> {
    request
        .params
        .as_ref()
        .and_then(|params| params.get("message"))
        .cloned()
}

async fn handle_a2a_task_get(
    state: &AppState,
    request: &A2aJsonRpcRequest,
    actor: &Principal,
) -> A2aJsonRpcResponse {
    let params = match aip_profile_a2a::task_id_params(request) {
        Ok(params) => params,
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32602, error.to_string());
        }
    };
    match a2a_task_from_native_status(state, &params.id, params.history_length, actor).await {
        Ok(Some(task)) => aip_profile_a2a::success_response(request.id.clone(), task),
        Ok(None) => {
            match state
                .profile_state
                .get(A2A_TASKS_NAMESPACE, &params.id)
                .await
            {
                Ok(Some(entry)) => {
                    let mut task = entry.value;
                    apply_a2a_history_length_to_value(&mut task, params.history_length);
                    return aip_profile_a2a::success_response(request.id.clone(), task);
                }
                Ok(None) => {}
                Err(error) => {
                    return aip_profile_a2a::error_response(
                        request.id.clone(),
                        -32603,
                        error.to_string(),
                    );
                }
            }
            aip_profile_a2a::error_response(
                request.id.clone(),
                -32001,
                format!("A2A task `{}` was not found", params.id),
            )
        }
        Err(error) => aip_profile_a2a::error_response(request.id.clone(), -32000, error),
    }
}

async fn handle_a2a_task_list(
    state: &AppState,
    request: &A2aJsonRpcRequest,
    actor: &Principal,
) -> A2aJsonRpcResponse {
    let params = match aip_profile_a2a::task_list_params(request) {
        Ok(params) => params,
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32602, error.to_string());
        }
    };
    let page_size = params.page_size.unwrap_or(50);
    if !(1..=100).contains(&page_size) {
        return aip_profile_a2a::error_response(
            request.id.clone(),
            -32602,
            "pageSize must be between 1 and 100",
        );
    }
    let page_start = match decode_a2a_offset(params.page_token.as_deref()) {
        Ok(offset) => offset,
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32602, error);
        }
    };
    let status_after = match params.status_timestamp_after.as_deref() {
        Some(value) => {
            match OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339) {
                Ok(value) => Some(value),
                Err(error) => {
                    return aip_profile_a2a::error_response(
                        request.id.clone(),
                        -32602,
                        format!("invalid statusTimestampAfter: {error}"),
                    );
                }
            }
        }
        None => None,
    };

    let mut cursor = None;
    let mut statuses = Vec::new();
    loop {
        let mut envelope = Envelope::new(MessageBody::ActionListRequest(ActionListRequest {
            state: None,
            capability_id: None,
            session_id: None,
            principal_id: None,
            approval_id: None,
            transaction_id: None,
            tenant_id: params.tenant.clone(),
            cursor: cursor.clone(),
            limit: Some(1_000),
            include_results: params.include_artifacts,
            include_receipts: false,
        }));
        envelope.trace = Some(json!({ "profile": aip_profile_a2a::PROFILE_ID }));
        let response =
            match handle_authenticated_gateway_envelope(&state.gateway, envelope, actor.clone())
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    return aip_profile_a2a::error_response(
                        request.id.clone(),
                        -32603,
                        error.to_string(),
                    );
                }
            };
        let MessageBody::ActionList(page) = response.body else {
            return aip_profile_a2a::error_response(
                request.id.clone(),
                -32603,
                "native action list returned an unexpected response",
            );
        };
        statuses.extend(page.actions);
        cursor = page.cursor;
        if cursor.is_none() {
            break;
        }
    }

    let bindings = match state.profile_state.list(A2A_TASKS_NAMESPACE, None).await {
        Ok(bindings) => bindings,
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32603, error.to_string());
        }
    };
    let bindings_by_action = bindings
        .into_iter()
        .filter_map(|entry| {
            let action_id = entry
                .value
                .pointer("/metadata/aip/action_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            action_id.map(|action_id| (action_id, (entry.key, entry.value)))
        })
        .collect::<HashMap<_, _>>();
    let mut tasks = Vec::new();
    for status in statuses {
        if status_after.is_some_and(|after| status.updated_at < after) {
            continue;
        }
        let binding = bindings_by_action.get(status.action_id.as_str());
        let Some(binding) = binding else {
            continue;
        };
        let task_id = binding.0.clone();
        let skill_id = skill_id_from_action_status(&status);
        let mut task = aip_profile_a2a::task_from_action_status(task_id, skill_id, &status);
        {
            let value = &binding.1;
            if let Some(context_id) = value.get("contextId").and_then(Value::as_str) {
                task.context_id = Some(context_id.to_owned());
            }
            let stored_history = value
                .get("history")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(serde_json::from_value::<aip_profile_a2a::A2aMessage>)
                .collect::<Result<Vec<_>, _>>();
            match stored_history {
                Ok(mut history) => {
                    history.append(&mut task.history);
                    task.history = history;
                }
                Err(error) => {
                    return aip_profile_a2a::error_response(
                        request.id.clone(),
                        -32603,
                        format!("stored A2A task history is invalid: {error}"),
                    );
                }
            }
        }
        aip_profile_a2a::apply_history_limit(&mut task, params.history_length);
        if !params.include_artifacts {
            task.artifacts.clear();
        }
        if let Some(context_id) = params.context_id.as_deref()
            && task.context_id.as_deref() != Some(context_id)
            && status
                .session_id
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
                != Some(context_id)
        {
            continue;
        }
        if let Some(expected_state) = params.status
            && task.status.state != expected_state
        {
            continue;
        }
        tasks.push(task);
    }
    let total_size = tasks.len();
    let start = page_start.min(total_size);
    let end = start.saturating_add(page_size).min(total_size);
    let next_page_token = if end < total_size {
        encode_a2a_offset(end)
    } else {
        String::new()
    };
    let page = aip_profile_a2a::A2aTaskListResponse {
        tasks: tasks[start..end].to_vec(),
        next_page_token,
        page_size,
        total_size,
    };
    match serde_json::to_value(page) {
        Ok(value) => aip_profile_a2a::success_response(request.id.clone(), value),
        Err(error) => {
            aip_profile_a2a::error_response(request.id.clone(), -32603, error.to_string())
        }
    }
}

fn encode_a2a_offset(offset: usize) -> String {
    format!("a2a-offset:{offset}")
}

fn decode_a2a_offset(token: Option<&str>) -> Result<usize, String> {
    let Some(token) = token else {
        return Ok(0);
    };
    token
        .strip_prefix("a2a-offset:")
        .ok_or_else(|| "invalid A2A page token".to_owned())?
        .parse::<usize>()
        .map_err(|_| "invalid A2A page token".to_owned())
}

async fn a2a_task_from_native_status(
    state: &AppState,
    task_id: &str,
    history_length: Option<usize>,
    actor: &Principal,
) -> Result<Option<Value>, String> {
    let action_id = match action_id_for_a2a_task(state, task_id).await {
        Ok(action_id) => action_id,
        Err(_) => return Ok(None),
    };
    let Some(status) = a2a_native_action_status(state, &action_id, actor).await? else {
        return Ok(None);
    };
    let skill_id = skill_id_from_action_status(&status);
    let task = aip_profile_a2a::task_from_action_status(task_id.to_owned(), skill_id, &status);
    let mut task = serde_json::to_value(task).map_err(|error| error.to_string())?;
    let stored = state
        .profile_state
        .get(A2A_TASKS_NAMESPACE, task_id)
        .await
        .map_err(|error| error.to_string())?;
    if let Some(stored) = stored {
        if let Some(context_id) = stored.value.get("contextId").cloned() {
            task["contextId"] = context_id;
        }
        let mut history = stored
            .value
            .get("history")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        history.extend(
            task.get("history")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        );
        task["history"] = Value::Array(history);
    }
    apply_a2a_history_length_to_value(&mut task, history_length);
    Ok(Some(task))
}

async fn a2a_native_action_status(
    state: &AppState,
    action_id: &ActionId,
    actor: &Principal,
) -> Result<Option<ActionStatus>, String> {
    let mut envelope = Envelope::new(MessageBody::ActionStatusRequest(ActionStatusRequest {
        action_id: action_id.clone(),
        tenant_id: None,
        include_result: true,
        include_receipts: false,
        include_chunks: true,
        wait_ms: None,
    }));
    envelope.trace = Some(json!({ "profile": aip_profile_a2a::PROFILE_ID }));
    let response = handle_authenticated_gateway_envelope(&state.gateway, envelope, actor.clone())
        .await
        .map_err(|error| error.to_string())?;
    match response.body {
        MessageBody::ActionStatus(status) => {
            if matches!(status.state, ActionLifecycleState::Unknown) {
                return Ok(None);
            }
            Ok(Some(*status))
        }
        MessageBody::Error(error) if error.error.code == "action.not_found" => Ok(None),
        MessageBody::Error(error) => Err(format!("{}: {}", error.error.code, error.error.message)),
        body => Err(format!(
            "unexpected AIP response `{}`",
            body.message_type().as_str()
        )),
    }
}

fn apply_a2a_history_length_to_value(task: &mut Value, history_length: Option<usize>) {
    let Some(history_length) = history_length else {
        return;
    };
    let Some(history) = task.get_mut("history").and_then(Value::as_array_mut) else {
        return;
    };
    if history_length >= history.len() {
        return;
    }
    let remove_count = history.len().saturating_sub(history_length);
    history.drain(0..remove_count);
}

fn skill_id_from_action_status(status: &ActionStatus) -> String {
    status
        .capability_id
        .as_ref()
        .map(|capability_id| {
            capability_id
                .as_str()
                .strip_prefix("cap:a2a:")
                .unwrap_or_else(|| capability_id.as_str())
                .to_owned()
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

async fn handle_a2a_task_cancel(
    state: &AppState,
    request: &A2aJsonRpcRequest,
    actor: &Principal,
) -> A2aJsonRpcResponse {
    let params = match aip_profile_a2a::task_id_params(request) {
        Ok(params) => params,
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32602, error.to_string());
        }
    };
    let action_id = match action_id_for_a2a_task(state, &params.id).await {
        Ok(action_id) => action_id,
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32001, error.to_string());
        }
    };
    match a2a_native_action_status(state, &action_id, actor).await {
        Ok(Some(status)) if is_terminal_action_state(status.state) => {
            return aip_profile_a2a::error_response(
                request.id.clone(),
                -32002,
                "A2A task is already in a terminal state",
            );
        }
        Ok(Some(_)) => {}
        Ok(None) => {
            return aip_profile_a2a::error_response(
                request.id.clone(),
                -32001,
                "A2A task was not found",
            );
        }
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32603, error);
        }
    }
    let mut envelope = Envelope::new(MessageBody::Cancel(Cancel {
        target: CancelTarget::Action(action_id.clone()),
        reason: Some("cancelled through A2A tasks/cancel".to_owned()),
    }));
    envelope.trace = Some(json!({
        "profile": aip_profile_a2a::PROFILE_ID,
        "jsonrpc_id": request.id
    }));
    let task_value = match handle_authenticated_gateway_envelope(
        &state.gateway,
        envelope,
        actor.clone(),
    )
    .await
    {
        Ok(response) => match response.body {
            MessageBody::ActionResult(result) => {
                let task = aip_profile_a2a::task_from_result(
                    params.id.clone(),
                    "cancel".to_owned(),
                    &result,
                );
                serde_json::to_value(task).unwrap_or_else(|_| json!({ "id": params.id }))
            }
            MessageBody::Error(body) => {
                return aip_profile_a2a::error_response(
                    request.id.clone(),
                    -32000,
                    body.error.message,
                );
            }
            body => {
                return aip_profile_a2a::error_response(
                    request.id.clone(),
                    -32603,
                    format!("unexpected AIP response `{}`", body.message_type().as_str()),
                );
            }
        },
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32000, error.to_string());
        }
    };
    if let Err(error) = state
        .profile_state
        .put(A2A_TASKS_NAMESPACE, &params.id, task_value.clone())
        .await
    {
        return aip_profile_a2a::error_response(request.id.clone(), -32603, error.to_string());
    }
    aip_profile_a2a::success_response(request.id.clone(), task_value)
}

async fn handle_a2a_push_config_create(
    state: &AppState,
    request: &A2aJsonRpcRequest,
    actor: &Principal,
) -> A2aJsonRpcResponse {
    if !a2a_push_notifications_enabled(state) {
        return aip_profile_a2a::error_response(
            request.id.clone(),
            -32003,
            "A2A push notifications are not enabled on this endpoint",
        );
    }
    let parsed = match aip_profile_a2a::push_config(request).or_else(|_| {
        let legacy = serde_json::from_value::<aip_profile_a2a::A2aTaskPushNotificationConfig>(
            request
                .params
                .clone()
                .ok_or(aip_profile_a2a::A2aProfileError::MissingParams)?,
        )
        .map_err(|error| aip_profile_a2a::A2aProfileError::InvalidIdentifier(error.to_string()))?;
        Ok::<_, aip_profile_a2a::A2aProfileError>(aip_profile_a2a::A2aTaskPushConfig {
            tenant: None,
            id: "default".to_owned(),
            task_id: legacy.id,
            url: legacy.push_notification_config.url,
            token: legacy.push_notification_config.token,
            authentication: legacy.push_notification_config.authentication,
        })
    }) {
        Ok(parsed) => parsed,
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32602, error.to_string());
        }
    };
    if parsed.id.trim().is_empty() || parsed.task_id.trim().is_empty() {
        return aip_profile_a2a::error_response(
            request.id.clone(),
            -32602,
            "push configuration id and taskId must not be empty",
        );
    }
    if let Err(error) = authorize_a2a_task_access(state, &parsed.task_id, actor).await {
        return aip_profile_a2a::error_response(request.id.clone(), -32001, error);
    }
    match persist_a2a_push_config(state, parsed.clone(), actor, true).await {
        Ok(_) => match serde_json::to_value(parsed) {
            Ok(value) => aip_profile_a2a::success_response(request.id.clone(), value),
            Err(error) => {
                aip_profile_a2a::error_response(request.id.clone(), -32603, error.to_string())
            }
        },
        Err(RuntimeError::Protocol(error)) if error.code == "a2a.push.config_conflict" => {
            aip_profile_a2a::error_response(request.id.clone(), -32602, error.message)
        }
        Err(RuntimeError::Authorization(_)) => aip_profile_a2a::error_response(
            request.id.clone(),
            -32001,
            "A2A push configuration is not accessible",
        ),
        Err(error) => {
            aip_profile_a2a::error_response(request.id.clone(), -32603, error.to_string())
        }
    }
}

fn a2a_push_notifications_enabled(state: &AppState) -> bool {
    state.callback_policy.signer.is_some() && state.callback_policy.a2a_credential_key.is_some()
}

async fn persist_a2a_push_config(
    state: &AppState,
    config: aip_profile_a2a::A2aTaskPushConfig,
    actor: &Principal,
    create_only: bool,
) -> RuntimeResult<StoredA2aPushConfig> {
    if config.id.trim().is_empty() || config.task_id.trim().is_empty() {
        return Err(RuntimeError::Protocol(ProtocolError {
            code: "a2a.push.invalid_config".to_owned(),
            message: "push configuration id and taskId must not be empty".to_owned(),
            category: ErrorCategory::Permanent,
            retryable: Some(false),
            retry_after_ms: None,
            details: None,
            source: Some(Box::new(json!({ "component": "aip.server.a2a" }))),
        }));
    }
    state
        .callback_policy
        .validate_destination(&config.url)
        .await?;
    let key = state
        .callback_policy
        .a2a_credential_key
        .as_ref()
        .ok_or_else(|| {
            RuntimeError::Authorization(
                "A2A push credentials require a configured encryption key".to_owned(),
            )
        })?;
    let credentials = A2aCallbackCredentials {
        token: config.token.clone(),
        authentication_scheme: config
            .authentication
            .as_ref()
            .map(|authentication| authentication.scheme.clone()),
        authentication_credentials: config
            .authentication
            .as_ref()
            .map(|authentication| authentication.credentials.clone()),
    };
    if let Some(scheme) = credentials.authentication_scheme.as_deref()
        && (scheme.trim().is_empty() || scheme.contains(['\r', '\n']))
    {
        return Err(RuntimeError::Authorization(
            "invalid A2A push authentication scheme".to_owned(),
        ));
    }
    for value in [
        credentials.token.as_deref(),
        credentials.authentication_credentials.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if value.contains(['\r', '\n']) {
            return Err(RuntimeError::Authorization(
                "A2A push credentials contain forbidden control characters".to_owned(),
            ));
        }
    }
    let credential_aad = format!(
        "aip.a2a.push.v1|{}|{}|{}",
        config.task_id, config.id, config.url
    );
    let encrypted_credentials = (credentials != A2aCallbackCredentials::default())
        .then(|| key.seal(&credential_aad, &credentials))
        .transpose()?;
    let mut sanitized = config.clone();
    sanitized.token = None;
    if let Some(authentication) = sanitized.authentication.as_mut() {
        authentication.credentials.clear();
    }
    let stored = StoredA2aPushConfig {
        config: sanitized,
        credential_aad,
        encrypted_credentials,
        owner: actor.id.clone(),
        created_at: OffsetDateTime::now_utc(),
    };
    let value = serde_json::to_value(&stored).map_err(|error| {
        RuntimeError::Storage(format!("A2A push config encode failed: {error}"))
    })?;
    let storage_key = a2a_push_config_key(&config.task_id, &config.id);
    if !create_only {
        state
            .profile_state
            .put(A2A_PUSH_CONFIGS_NAMESPACE, &storage_key, value)
            .await?;
        return Ok(stored);
    }
    match state
        .profile_state
        .create(A2A_PUSH_CONFIGS_NAMESPACE, &storage_key, value)
        .await?
    {
        ProfileStateCasOutcome::Applied(_) => Ok(stored),
        ProfileStateCasOutcome::Conflict(Some(existing)) => {
            let existing =
                serde_json::from_value::<StoredA2aPushConfig>(existing.value).map_err(|error| {
                    RuntimeError::Storage(format!("stored A2A push config is invalid: {error}"))
                })?;
            if existing.owner != actor.id {
                return Err(RuntimeError::Authorization(
                    "A2A push configuration is not accessible".to_owned(),
                ));
            }
            let existing_public = restore_a2a_push_config(state, &existing)?;
            if existing_public == config {
                Ok(existing)
            } else {
                Err(RuntimeError::Protocol(ProtocolError {
                    code: "a2a.push.config_conflict".to_owned(),
                    message: "push configuration id already exists with different content"
                        .to_owned(),
                    category: ErrorCategory::Permanent,
                    retryable: Some(false),
                    retry_after_ms: None,
                    details: None,
                    source: Some(Box::new(json!({ "component": "aip.server.a2a" }))),
                }))
            }
        }
        ProfileStateCasOutcome::Conflict(None) => Err(RuntimeError::Storage(
            "A2A push config create lost an atomic storage race".to_owned(),
        )),
    }
}

fn restore_a2a_push_config(
    state: &AppState,
    stored: &StoredA2aPushConfig,
) -> RuntimeResult<aip_profile_a2a::A2aTaskPushConfig> {
    let mut config = stored.config.clone();
    let Some(encrypted) = stored.encrypted_credentials.as_ref() else {
        return Ok(config);
    };
    let credentials = state
        .callback_policy
        .a2a_credential_key
        .as_ref()
        .ok_or_else(|| {
            RuntimeError::Authorization(
                "A2A push credential decryption key is unavailable".to_owned(),
            )
        })?
        .open(&stored.credential_aad, encrypted)?;
    config.token = credentials.token;
    match (
        config.authentication.as_mut(),
        credentials.authentication_scheme,
        credentials.authentication_credentials,
    ) {
        (Some(authentication), Some(scheme), Some(credentials)) => {
            authentication.scheme = scheme;
            authentication.credentials = credentials;
        }
        (None, None, None) => {}
        _ => {
            return Err(RuntimeError::Storage(
                "encrypted A2A push authentication does not match public metadata".to_owned(),
            ));
        }
    }
    Ok(config)
}

fn a2a_callback_from_stored_config(
    stored: &StoredA2aPushConfig,
    skill_id: Option<&str>,
) -> Callback {
    Callback {
        profile: ProfileId::from(aip_profile_a2a::PROFILE_ID),
        target: stored.config.url.clone(),
        metadata: Some(json!({
            "a2a": {
                "configId": stored.config.id,
                "taskId": stored.config.task_id,
                "contextId": stored.config.task_id,
                "skillId": skill_id,
                "credentialAad": stored.credential_aad,
                "encryptedCredentials": stored.encrypted_credentials
            }
        })),
    }
}

async fn handle_a2a_push_config_get(
    state: &AppState,
    request: &A2aJsonRpcRequest,
    actor: &Principal,
) -> A2aJsonRpcResponse {
    if !a2a_push_notifications_enabled(state) {
        return aip_profile_a2a::error_response(
            request.id.clone(),
            -32003,
            "A2A push notifications are not enabled on this endpoint",
        );
    }
    let params = match aip_profile_a2a::push_config_selector(request) {
        Ok(params) => params,
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32602, error.to_string());
        }
    };
    if let Err(error) = authorize_a2a_task_access(state, &params.task_id, actor).await {
        return aip_profile_a2a::error_response(request.id.clone(), -32001, error);
    }
    let key = a2a_push_config_key(&params.task_id, &params.id);
    match state
        .profile_state
        .get(A2A_PUSH_CONFIGS_NAMESPACE, &key)
        .await
    {
        Ok(Some(config)) => {
            let stored = match serde_json::from_value::<StoredA2aPushConfig>(config.value) {
                Ok(stored) if stored.owner == actor.id => stored,
                Ok(_) => {
                    return aip_profile_a2a::error_response(
                        request.id.clone(),
                        -32001,
                        "push notification config was not found",
                    );
                }
                Err(error) => {
                    return aip_profile_a2a::error_response(
                        request.id.clone(),
                        -32603,
                        format!("stored A2A push config is invalid: {error}"),
                    );
                }
            };
            match restore_a2a_push_config(state, &stored) {
                Ok(config) => match serde_json::to_value(config) {
                    Ok(value) => aip_profile_a2a::success_response(request.id.clone(), value),
                    Err(error) => aip_profile_a2a::error_response(
                        request.id.clone(),
                        -32603,
                        error.to_string(),
                    ),
                },
                Err(error) => {
                    aip_profile_a2a::error_response(request.id.clone(), -32603, error.to_string())
                }
            }
        }
        Ok(None) => aip_profile_a2a::error_response(
            request.id.clone(),
            -32001,
            format!(
                "push notification config `{}` for task `{}` was not found",
                params.id, params.task_id
            ),
        ),
        Err(error) => {
            aip_profile_a2a::error_response(request.id.clone(), -32603, error.to_string())
        }
    }
}

async fn handle_a2a_push_config_list(
    state: &AppState,
    request: &A2aJsonRpcRequest,
    actor: &Principal,
) -> A2aJsonRpcResponse {
    if !a2a_push_notifications_enabled(state) {
        return aip_profile_a2a::error_response(
            request.id.clone(),
            -32003,
            "A2A push notifications are not enabled on this endpoint",
        );
    }
    let params = match aip_profile_a2a::push_config_list_params(request) {
        Ok(params) => params,
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32602, error.to_string());
        }
    };
    if let Err(error) = authorize_a2a_task_access(state, &params.task_id, actor).await {
        return aip_profile_a2a::error_response(request.id.clone(), -32001, error);
    }
    let page_size = params.page_size.unwrap_or(50);
    if !(1..=100).contains(&page_size) {
        return aip_profile_a2a::error_response(
            request.id.clone(),
            -32602,
            "pageSize must be between 1 and 100",
        );
    }
    let start = match decode_a2a_offset(params.page_token.as_deref()) {
        Ok(offset) => offset,
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32602, error);
        }
    };
    let prefix = a2a_push_config_prefix(&params.task_id);
    let configs = match state
        .profile_state
        .list(A2A_PUSH_CONFIGS_NAMESPACE, Some(&prefix))
        .await
    {
        Ok(entries) => {
            let mut configs = Vec::new();
            for entry in entries {
                let stored = match serde_json::from_value::<StoredA2aPushConfig>(entry.value) {
                    Ok(stored) => stored,
                    Err(error) => {
                        return aip_profile_a2a::error_response(
                            request.id.clone(),
                            -32603,
                            format!("stored A2A push config is invalid: {error}"),
                        );
                    }
                };
                if stored.owner != actor.id {
                    continue;
                }
                match restore_a2a_push_config(state, &stored) {
                    Ok(config) => configs.push(config),
                    Err(error) => {
                        return aip_profile_a2a::error_response(
                            request.id.clone(),
                            -32603,
                            error.to_string(),
                        );
                    }
                }
            }
            configs
        }
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32603, error.to_string());
        }
    };
    let start = start.min(configs.len());
    let end = start.saturating_add(page_size).min(configs.len());
    let response = aip_profile_a2a::A2aPushConfigListResponse {
        configs: configs[start..end].to_vec(),
        next_page_token: if end < configs.len() {
            encode_a2a_offset(end)
        } else {
            String::new()
        },
    };
    match serde_json::to_value(response) {
        Ok(value) => aip_profile_a2a::success_response(request.id.clone(), value),
        Err(error) => {
            aip_profile_a2a::error_response(request.id.clone(), -32603, error.to_string())
        }
    }
}

async fn handle_a2a_push_config_delete(
    state: &AppState,
    request: &A2aJsonRpcRequest,
    actor: &Principal,
) -> A2aJsonRpcResponse {
    if !a2a_push_notifications_enabled(state) {
        return aip_profile_a2a::error_response(
            request.id.clone(),
            -32003,
            "A2A push notifications are not enabled on this endpoint",
        );
    }
    let params = match aip_profile_a2a::push_config_selector(request) {
        Ok(params) => params,
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32602, error.to_string());
        }
    };
    if let Err(error) = authorize_a2a_task_access(state, &params.task_id, actor).await {
        return aip_profile_a2a::error_response(request.id.clone(), -32001, error);
    }
    let key = a2a_push_config_key(&params.task_id, &params.id);
    match state
        .profile_state
        .get(A2A_PUSH_CONFIGS_NAMESPACE, &key)
        .await
    {
        Ok(Some(entry)) => match serde_json::from_value::<StoredA2aPushConfig>(entry.value) {
            Ok(stored) if stored.owner == actor.id => {}
            Ok(_) => {
                return aip_profile_a2a::error_response(
                    request.id.clone(),
                    -32001,
                    "push notification config was not found",
                );
            }
            Err(error) => {
                return aip_profile_a2a::error_response(
                    request.id.clone(),
                    -32603,
                    format!("stored A2A push config is invalid: {error}"),
                );
            }
        },
        Ok(None) => {
            return aip_profile_a2a::success_response(request.id.clone(), json!({}));
        }
        Err(error) => {
            return aip_profile_a2a::error_response(request.id.clone(), -32603, error.to_string());
        }
    }
    match delete_profile_state_record(&state.profile_state, A2A_PUSH_CONFIGS_NAMESPACE, &key).await
    {
        Ok(()) => aip_profile_a2a::success_response(request.id.clone(), json!({})),
        Err(error) => {
            aip_profile_a2a::error_response(request.id.clone(), -32603, error.to_string())
        }
    }
}

fn a2a_push_config_key(task_id: &str, config_id: &str) -> String {
    format!("{}:{}", hex::encode(task_id), hex::encode(config_id))
}

fn a2a_push_config_prefix(task_id: &str) -> String {
    format!("{}:", hex::encode(task_id))
}

async fn delete_profile_state_record(
    store: &ProfileStateStore,
    namespace: &str,
    key: &str,
) -> RuntimeResult<()> {
    for _ in 0..32 {
        let Some(entry) = store.get(namespace, key).await? else {
            return Ok(());
        };
        if store.delete(namespace, key, entry.revision).await? {
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
    Err(RuntimeError::Storage(format!(
        "profile state `{namespace}/{key}` remained contended during delete"
    )))
}

async fn authorize_a2a_task_access(
    state: &AppState,
    task_id: &str,
    actor: &Principal,
) -> Result<(), String> {
    let action_id = action_id_for_a2a_task(state, task_id)
        .await
        .map_err(|_| format!("A2A task `{task_id}` was not found"))?;
    match a2a_native_action_status(state, &action_id, actor).await? {
        Some(_) => Ok(()),
        None => Err(format!("A2A task `{task_id}` was not found")),
    }
}

async fn action_id_for_a2a_task(
    state: &AppState,
    task_id: &str,
) -> Result<ActionId, aip_profile_a2a::A2aProfileError> {
    if let Some(entry) = state
        .profile_state
        .get(A2A_TASKS_NAMESPACE, task_id)
        .await
        .map_err(|error| aip_profile_a2a::A2aProfileError::Storage(error.to_string()))?
        && let Some(action_id) = entry
            .value
            .pointer("/metadata/aip/action_id")
            .and_then(Value::as_str)
    {
        return aip_profile_a2a::action_id_from_task_id(action_id);
    }
    aip_profile_a2a::action_id_from_task_id(task_id)
}

fn error_response(error: GatewayError) -> Response {
    let envelope = Gateway::error_envelope(&error);
    let status = match &envelope.body {
        MessageBody::Error(body) => status_for_error(&body.error),
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(envelope)).into_response()
}

fn protocol_error_response(status: StatusCode, error: ProtocolError) -> Response {
    (
        status,
        Json(Envelope::new(MessageBody::Error(ErrorBody { error }))),
    )
        .into_response()
}

fn manifest_from_config_with_runtime_storage(
    config: &AipDaemonConfig,
    runtime_storage: &'static str,
) -> Manifest {
    let mut agent = Principal::new(
        config.service_id.clone(),
        principal_kind_for_id(config.service_id.as_str()),
    );
    agent.display_name = Some("AIP Daemon".to_owned());
    agent.trust_domain.clone_from(&config.trust_domain);
    let mut profiles = vec![
        ProfileId::from(NATIVE_HTTP_PROFILE),
        ProfileId::from(aip_profile_a2a::PROFILE_ID),
        ProfileId::from(aip_profile_mcp::PROFILE_ID),
    ];
    if config.nats.is_some() {
        profiles.push(ProfileId::from(NATS_PROFILE_ID));
    }
    let mut compatibility = json!({
        "native_http": {
            "messages": "/aip/v1/messages",
            "actions": "/aip/v1/actions",
            "manifest": "/aip/v1/manifest"
        },
        "mcp": {
            "jsonrpc": "/mcp",
            "versioned_jsonrpc": "/mcp/v1",
            "profile": aip_profile_mcp::PROFILE_ID,
            "methods": ["initialize", "tools/list", "tools/call", "resources/list"]
        },
        "a2a": {
            "agent_card": "/.well-known/agent.json",
            "jsonrpc": "/a2a",
            "versioned_jsonrpc": "/a2a/v1",
            "profile": aip_profile_a2a::PROFILE_ID,
            "methods": [
                "tasks/send",
                "tasks/sendSubscribe",
                "tasks/get",
                "tasks/cancel",
                "tasks/pushNotificationConfig/set",
                "tasks/pushNotificationConfig/get"
            ]
        }
    });
    if let Some(nats) = &config.nats {
        compatibility["native_nats"] = json!({
            "server_url": nats.server_url,
            "subject": nats.subscription_subject(),
            "queue_group": nats.queue_group,
            "profile": NATS_PROFILE_ID
        });
    }
    if !config.delegation_routes.is_empty() {
        compatibility["delegation_routes"] = json!(
            config
                .delegation_routes
                .iter()
                .map(delegation_route_summary)
                .collect::<Vec<_>>()
        );
    }
    if let Some(policy) = &config.mcp_protected_resource {
        compatibility["mcp"]["protected_resource"] = json!({
            "metadata": policy.metadata_url,
            "enforced_by_getaip_server": policy.bearer_token.is_some(),
            "bearer_methods_supported": &policy.metadata.bearer_methods_supported,
            "scopes_supported": &policy.metadata.scopes_supported
        });
    }
    Manifest {
        manifest_version: "aip-manifest/v1".to_owned(),
        agent,
        capabilities: vec![health_capability()],
        profiles,
        resources: Vec::new(),
        channels: Vec::new(),
        security: Some(json!({
            "transport": "http",
            "status": "pre_stable_production_oriented",
            "envelope_schema_validation": "required",
            "sender_principal": "required_for_actions",
            "signed_envelopes": if config.require_signed_envelopes { "required" } else { "supported" },
            "mcp_http_auth": config
                .mcp_protected_resource
                .as_ref()
                .map(|policy| if policy.bearer_token.is_some() { "bearer_required" } else { "protected_resource_metadata_only" })
                .unwrap_or("none"),
            "runtime_storage": runtime_storage,
            "idempotency": "required_for_replay_sensitive_actions"
        })),
        governance: None,
        limits: Some(json!({
            "max_request_bytes": 1048576
        })),
        compatibility: Some(compatibility),
        extensions: None,
    }
}

fn delegation_route_summary(route: &DelegationRoute) -> Value {
    let mut summary = json!({
        "delegate_id": route.delegate_id.as_ref().map(|id| id.as_str()),
        "capability_id": route.capability_id.as_ref().map(|id| id.as_str())
    });
    match &route.binding {
        DelegationRouteBinding::NativeHttp { endpoint, security } => {
            summary["profile"] = json!(aip_gateway::NATIVE_HTTP_PROFILE);
            summary["transport"] = json!("http");
            summary["endpoint"] = json!(endpoint);
            summary["trust_domain"] = json!(security.trust_domain);
            summary["expected_peer"] = json!(security.expected_peer.id);
            summary["expected_peer_did"] = json!(security.expected_peer_did);
            summary["retry_budget"] = json!(security.retry_budget);
        }
        DelegationRouteBinding::NativeNats {
            server_url,
            subject,
            timeout_ms,
            security,
        } => {
            summary["profile"] = json!(aip_gateway::NATIVE_NATS_PROFILE);
            summary["transport"] = json!("nats");
            summary["server_url"] = json!(server_url);
            summary["subject"] = json!(subject);
            summary["timeout_ms"] = json!(timeout_ms);
            summary["trust_domain"] = json!(security.trust_domain);
            summary["expected_peer"] = json!(security.expected_peer.id);
            summary["expected_peer_did"] = json!(security.expected_peer_did);
            summary["retry_budget"] = json!(security.retry_budget);
        }
    }
    summary
}

fn runtime_storage_label(config: &AipDaemonConfig, postgres_url: Option<&str>) -> &'static str {
    if postgres_url.is_some() {
        "postgres"
    } else if config.storage_dir.is_some() {
        "durable_file"
    } else {
        "memory"
    }
}

fn transport_error_envelope(error: TransportError) -> Envelope {
    Envelope::new(MessageBody::Error(ErrorBody {
        error: ProtocolError {
            code: "transport.nats.decode".to_owned(),
            message: error.to_string(),
            category: ErrorCategory::Transport,
            retryable: Some(false),
            retry_after_ms: None,
            details: None,
            source: Some(Box::new(json!({ "component": "aip.server.nats" }))),
        },
    }))
}

fn merge_connector_manifest(local: &mut Manifest, connector_id: &str, connector: &Manifest) {
    local.capabilities.extend(connector.capabilities.clone());
    for profile in &connector.profiles {
        if !local.profiles.contains(profile) {
            local.profiles.push(profile.clone());
        }
    }
    if !connector.resources.is_empty() {
        local.resources.extend(connector.resources.clone());
    }
    if !connector.channels.is_empty() {
        local.channels.extend(connector.channels.clone());
    }
    let mut extensions = local
        .extensions
        .take()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    let mut connectors = extensions
        .remove("connectors")
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    connectors.insert(
        connector_id.to_owned(),
        json!({
            "agent": connector.agent,
            "capability_count": connector.capabilities.len(),
            "profiles": connector.profiles,
            "compatibility": connector.compatibility
        }),
    );
    extensions.insert("connectors".to_owned(), Value::Object(connectors));
    local.extensions = Some(Value::Object(extensions));
}

fn runtime_error(error: impl std::fmt::Display) -> GatewayError {
    GatewayError::Runtime(RuntimeError::Handler(error.to_string()))
}

fn health_capability() -> Capability {
    Capability {
        id: CapabilityId::trusted(HEALTH_CAPABILITY_ID),
        name: "AIP daemon health".to_owned(),
        kind: CapabilityKind::Tool,
        input_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }),
        output_schema: Some(json!({
            "type": "object",
            "required": ["status", "protocol", "version", "service", "uptime_ms"],
            "properties": {
                "status": { "type": "string" },
                "protocol": { "type": "string" },
                "version": { "type": "string" },
                "service": { "type": "string" },
                "uptime_ms": { "type": "integer" }
            }
        })),
        description: Some("Reports standalone AIP daemon readiness.".to_owned()),
        risk: Some(RiskLevel::Low),
        stability: Some(Stability::Stable),
        cost: None,
        auth: None,
        bindings: vec![
            Binding {
                profile: ProfileId::from(NATIVE_HTTP_PROFILE),
                metadata: [
                    ("method".to_owned(), json!("POST")),
                    ("path".to_owned(), json!("/aip/v1/messages")),
                    ("message_type".to_owned(), json!("aip.core.v1.action")),
                ]
                .into_iter()
                .collect(),
            },
            Binding {
                profile: ProfileId::from(aip_profile_mcp::PROFILE_ID),
                metadata: [
                    ("name".to_owned(), json!("getaip_server_health")),
                    ("taskSupport".to_owned(), json!("forbidden")),
                ]
                .into_iter()
                .collect(),
            },
        ],
        requires_human_approval: Some(false),
        contract: Some(health_capability_contract()),
    }
}

fn capability_catalog_query_capability() -> Capability {
    Capability {
        id: CapabilityId::trusted(CAPABILITY_CATALOG_QUERY_ID),
        name: "Query tenant connector capabilities".to_owned(),
        kind: CapabilityKind::Tool,
        input_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "capability_id": { "type": "string", "minLength": 1, "maxLength": 512 },
                "text": { "type": "string", "minLength": 1, "maxLength": 512 },
                "profile": { "type": "string", "minLength": 1, "maxLength": 512 },
                "cursor": { "type": "string", "minLength": 1, "maxLength": 2048 },
                "limit": { "type": "integer", "minimum": 1, "maximum": 200 }
            }
        }),
        output_schema: Some(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["catalog_revision", "capabilities", "total"],
            "properties": {
                "catalog_revision": { "type": "integer", "minimum": 0 },
                "capabilities": { "type": "array", "maxItems": 200, "items": { "type": "object" } },
                "next_cursor": { "type": ["string", "null"] },
                "total": { "type": "integer", "minimum": 0 }
            }
        })),
        description: Some(
            "Returns one bounded, revision-fenced page of connector capabilities visible to the verified tenant."
                .to_owned(),
        ),
        risk: Some(RiskLevel::Low),
        stability: Some(Stability::Stable),
        cost: None,
        auth: None,
        bindings: vec![Binding {
            profile: ProfileId::from(NATIVE_HTTP_PROFILE),
            metadata: [
                ("method".to_owned(), json!("POST")),
                ("path".to_owned(), json!("/aip/v1/messages")),
                ("message_type".to_owned(), json!("aip.core.v1.action")),
            ]
            .into_iter()
            .collect(),
        }],
        requires_human_approval: Some(false),
        contract: Some(capability_catalog_query_contract()),
    }
}

fn capability_catalog_query_contract() -> CapabilityContract {
    CapabilityContract {
        side_effects: vec![SideEffect::Read],
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
            supports_cancel: false,
            supports_retry: true,
            expected_completion: ExpectedCompletionMode::Sync,
            retry_safety: RetrySafety::Safe,
        },
        data: DataContract {
            sensitivity: DataSensitivity::Internal,
            contains_pii: false,
            redaction_required: false,
            residency: None,
            retention: None,
        },
        credentials: None,
        approval: None,
        sla: Some(ServiceLevelContract {
            expected_latency_ms: Some(250),
            timeout_ms: Some(2_000),
            async_expected: false,
            max_queue_delay_ms: Some(100),
            availability_target: Some("99.9%".to_owned()),
        }),
        transaction: None,
        compensation: Some(CompensationContract {
            mode: CompensationMode::NotRequired,
            compensation_capability_id: None,
            compensation_window_ms: None,
            requires_approval: false,
        }),
    }
}

fn health_capability_contract() -> CapabilityContract {
    CapabilityContract {
        side_effects: vec![SideEffect::Read],
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
            supports_cancel: false,
            supports_retry: true,
            expected_completion: ExpectedCompletionMode::Sync,
            retry_safety: RetrySafety::Safe,
        },
        data: DataContract {
            sensitivity: DataSensitivity::Internal,
            contains_pii: false,
            redaction_required: false,
            residency: None,
            retention: None,
        },
        credentials: None,
        approval: None,
        sla: Some(ServiceLevelContract {
            expected_latency_ms: Some(100),
            timeout_ms: Some(1_000),
            async_expected: false,
            max_queue_delay_ms: Some(100),
            availability_target: Some("99.9%".to_owned()),
        }),
        transaction: None,
        compensation: Some(CompensationContract {
            mode: CompensationMode::NotRequired,
            compensation_capability_id: None,
            compensation_window_ms: None,
            requires_approval: false,
        }),
    }
}

fn health_payload(started_at: Instant) -> Value {
    json!({
        "status": "ok",
        "protocol": "AIP",
        "version": aip_core::AIP_VERSION,
        "service": "getaip-server",
        "uptime_ms": started_at.elapsed().as_millis()
    })
}

/// Serializable startup failure for embedding callers.
#[derive(Debug, Serialize)]
pub struct StartupError {
    /// Stable error code.
    pub code: &'static str,
    /// Human-readable message.
    pub message: String,
}

impl StartupError {
    /// Converts an I/O error into a structured startup error.
    #[must_use]
    pub fn io(error: std::io::Error) -> Self {
        Self {
            code: "aip.server.io",
            message: error.to_string(),
        }
    }

    /// Converts a protocol gateway error into a structured startup error.
    #[must_use]
    pub fn gateway(error: GatewayError) -> Self {
        let protocol = Gateway::error_envelope(&error);
        let message = match protocol.body {
            MessageBody::Error(body) => body.error.message,
            _ => error.to_string(),
        };
        Self {
            code: "aip.server.gateway",
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AipDaemon, AipDaemonConfig, AipDaemonDeployment, AipDaemonNatsConfig,
        CAPABILITY_CATALOG_QUERY_ID, DaemonFleetServices, DaemonFleetSupervisorState,
        DaemonMcpProviders, DaemonTrustResolvers, HEALTH_CAPABILITY_ID, McpProtectedResourceConfig,
        NativeHttpAuthConfig, dispatch_a2a_push_updates, health_capability,
        jittered_fleet_delay_with_sample, runtime_worker_id, supervise_fleet_status,
        validate_public_base_url,
    };
    use aip_auth::{
        AuthError, AuthScheme, AuthenticatedPrincipal, BearerToken,
        DenyAllApprovalAuthorityResolver, IntrospectionTokenVerifier,
        StaticTrustedIdentityResolver, TokenIntrospection, TokenIntrospector,
        TrustedIdentityBinding, VerifiedTenant,
    };
    use aip_connector_registry::{
        ArtifactAttestation, ArtifactCheckStatus, CapabilityCatalogProvider,
        CapabilityCatalogQuery, CapabilityDefinition, CapabilityPage, CatalogReadContext,
        CatalogRevision, ConnectorFleetStatusProvider, ConnectorInstance, ConnectorInstanceId,
        ConnectorInstanceStatus, ConnectorRegistryAdmin, ConnectorReplica, ConnectorReplicaId,
        ConnectorReplicaStatus, ConnectorType, ConnectorTypeId, ConnectorVersion,
        ConnectorVersionId, ConnectorVersionStatus, EmptyCapabilityCatalog, FleetStatusSummary,
        InMemoryConnectorRegistry, RegistryError, ResolvedCapabilityDefinition, digest_json,
        schema_bundle_digest,
    };
    use aip_connector_remote::ConnectorEventIngressLimits;
    use aip_core::{
        Action, ActionEvents, ActionId, ActionResult, ActionResultStatus, Capability, CapabilityId,
        CapabilityKind, CorrelationId, Envelope, Event, EventStream, EventStreamRequest, Handshake,
        Manifest, ManifestRequest, MessageBody, MessageReference, Principal, PrincipalId,
        PrincipalKind, ProfileId, SessionId, TenantRef,
    };
    use aip_discovery::CapabilityImplementationSupport;
    use aip_gateway::{
        A2aCallbackCredentialKey, CallbackSigner, DelegationPeerSecurity, DelegationRoute,
        GatewayCallbackPolicy, sign_native_envelope, verify_native_envelope_signature,
    };
    use aip_mcp_client::{McpClient, McpClientConfig, McpLegacyHttpSseClientTransport};
    use aip_mcp_server::{McpServerResult, ResourceProvider};
    use aip_mcp_session::{McpFrame, McpTransportKind};
    use aip_profile_mcp::{
        JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, McpMethod, McpResource,
        ResourceCapability, ResourceContents, ResourceTemplate,
    };
    use axum::{
        Json, Router,
        body::{Body, to_bytes},
        extract::State,
        http::{HeaderMap, HeaderValue, Request, StatusCode, header},
        routing::post,
    };
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use std::{
        collections::{BTreeMap, BTreeSet, HashSet},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use time::OffsetDateTime;
    use tokio::{
        net::TcpListener,
        sync::{Mutex, watch},
        time::timeout,
    };
    use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;
    use tower::util::ServiceExt;

    #[derive(Clone, Default)]
    struct PushCapture(Arc<Mutex<Vec<(HeaderMap, Value)>>>);

    #[derive(Clone, Debug, Default)]
    struct MatrixTokenIntrospector;

    #[derive(Clone, Debug, Default)]
    struct DynamicTestResourceProvider;

    #[derive(Clone)]
    struct DynamicFleetCatalog {
        tenant_id: String,
        definition: CapabilityDefinition,
    }

    #[async_trait::async_trait]
    impl CapabilityCatalogProvider for DynamicFleetCatalog {
        async fn get(
            &self,
            capability_id: &CapabilityId,
            context: &CatalogReadContext,
        ) -> Result<Option<ResolvedCapabilityDefinition>, RegistryError> {
            Ok(
                (context.tenant_id.as_deref() == Some(self.tenant_id.as_str())
                    && capability_id == &self.definition.capability.id)
                    .then(|| ResolvedCapabilityDefinition {
                        definition: self.definition.clone(),
                        catalog_revision: CatalogRevision(41),
                    }),
            )
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
                    .is_none_or(|capability_id| capability_id == &self.definition.capability.id)
                && request.profile.as_ref().is_none_or(|profile| {
                    self.definition
                        .capability
                        .bindings
                        .iter()
                        .any(|binding| &binding.profile == profile)
                })
                && request.text.as_ref().is_none_or(|text| {
                    format!(
                        "{} {} {}",
                        self.definition.capability.id,
                        self.definition.capability.name,
                        self.definition
                            .capability
                            .description
                            .as_deref()
                            .unwrap_or_default()
                    )
                    .to_ascii_lowercase()
                    .contains(&text.to_ascii_lowercase())
                });
            Ok(CapabilityPage {
                catalog_revision: CatalogRevision(41),
                capabilities: if visible && request.cursor.is_none() && request.limit > 0 {
                    vec![self.definition.clone()]
                } else {
                    Vec::new()
                },
                next_cursor: None,
                total: u64::from(visible),
            })
        }
    }

    #[derive(Clone, Default)]
    struct DynamicFleetHandler {
        invocations: Arc<AtomicUsize>,
    }

    #[derive(Default)]
    struct CountingFleetStatusProvider {
        expiry_calls: AtomicUsize,
        summary_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ConnectorFleetStatusProvider for CountingFleetStatusProvider {
        async fn expire_stale_replicas(
            &self,
            _now: OffsetDateTime,
            _limit: usize,
        ) -> Result<usize, RegistryError> {
            self.expiry_calls.fetch_add(1, Ordering::SeqCst);
            Ok(0)
        }

        async fn fleet_status(
            &self,
            observed_at: OffsetDateTime,
        ) -> Result<FleetStatusSummary, RegistryError> {
            self.summary_calls.fetch_add(1, Ordering::SeqCst);
            Ok(FleetStatusSummary {
                ready_replicas: 7,
                ready_capacity: 70,
                observed_at,
                ..FleetStatusSummary::default()
            })
        }
    }

    #[async_trait::async_trait]
    impl aip_runtime::ActionHandler for DynamicFleetHandler {
        fn implementation_support(&self) -> CapabilityImplementationSupport {
            CapabilityImplementationSupport {
                invocation: true,
                ..CapabilityImplementationSupport::default()
            }
        }

        async fn handle(&self, action: Action) -> aip_runtime::RuntimeResult<ActionResult> {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            Ok(ActionResult {
                action_id: action.id,
                status: ActionResultStatus::Completed,
                output: Some(json!({ "fleet": true, "input": action.input })),
                message: Vec::new(),
                memory_update: None,
                usage: None,
                receipt: None,
                error: None,
            })
        }
    }

    #[async_trait::async_trait]
    impl ResourceProvider for DynamicTestResourceProvider {
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
            Ok((
                vec![McpResource {
                    uri: "aip://dynamic/customer-42".to_owned(),
                    name: "Customer 42".to_owned(),
                    title: Some("Customer 42".to_owned()),
                    description: Some("Dynamic customer record".to_owned()),
                    mime_type: Some("application/json".to_owned()),
                    size: None,
                    icons: Vec::new(),
                    annotations: None,
                    meta: None,
                }],
                None,
            ))
        }

        async fn templates(&self) -> McpServerResult<Vec<ResourceTemplate>> {
            Ok(Vec::new())
        }

        async fn read(&self, uri: &str) -> McpServerResult<Vec<ResourceContents>> {
            Ok(vec![ResourceContents::Text {
                uri: uri.to_owned(),
                mime_type: Some("application/json".to_owned()),
                text: json!({ "customer_id": 42 }).to_string(),
            }])
        }

        async fn subscribe(&self, _uri: &str) -> McpServerResult<()> {
            Ok(())
        }

        async fn unsubscribe(&self, _uri: &str) -> McpServerResult<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl TokenIntrospector for MatrixTokenIntrospector {
        async fn introspect(&self, token: &BearerToken) -> Result<TokenIntrospection, AuthError> {
            let label = std::str::from_utf8(token.expose())
                .map_err(|_| AuthError::Token("test token is not UTF-8".to_owned()))?;
            let now = time::OffsetDateTime::now_utc();
            let mut claims = TokenIntrospection {
                active: true,
                subject: Some("service:test:mcp-oauth-client".to_owned()),
                issuer: Some("https://issuer.example".to_owned()),
                audiences: BTreeSet::from(["https://aip.example/mcp".to_owned()]),
                scopes: BTreeSet::from(["mcp:invoke".to_owned()]),
                expires_at: Some(now + time::Duration::minutes(5)),
                tenant_id: Some("tenant:test".to_owned()),
                token_fingerprint: format!("sha256:{label}"),
            };
            match label {
                "wrong-issuer" => claims.issuer = Some("https://attacker.example".to_owned()),
                "wrong-audience" => {
                    claims.audiences = BTreeSet::from(["https://other.example".to_owned()]);
                }
                "missing-scope" => claims.scopes.clear(),
                "expired" => claims.expires_at = Some(now - time::Duration::seconds(1)),
                "revoked" => claims.active = false,
                "good" => {}
                _ => claims.active = false,
            }
            Ok(claims)
        }
    }

    async fn capture_push(
        State(capture): State<PushCapture>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> StatusCode {
        capture.0.lock().await.push((headers, body));
        StatusCode::NO_CONTENT
    }

    fn insecure_loopback_test_config() -> AipDaemonConfig {
        let mut principal = Principal::new(
            PrincipalId::trusted("agent:getaip:server:local"),
            PrincipalKind::Agent,
        );
        principal.auth_context = Some(json!({ "scopes": ["*"] }));
        AipDaemonConfig {
            require_signed_envelopes: false,
            native_http_auth: Some(NativeHttpAuthConfig::bearer(
                "insecure-loopback-test-token",
                principal,
            )),
            allow_insecure_development: true,
            ..AipDaemonConfig::default()
        }
    }

    #[test]
    fn daemon_boots_have_distinct_runtime_lease_owners() {
        let service_id = PrincipalId::trusted("agent:getaip:server:cluster");
        let first = runtime_worker_id(&service_id);
        let second = runtime_worker_id(&service_id);

        assert_ne!(first, second);
        assert!(first.starts_with("getaip-server:agent:getaip:server:cluster:"));
        assert!(second.starts_with("getaip-server:agent:getaip:server:cluster:"));
    }

    #[test]
    fn fleet_maintenance_jitter_is_bounded_and_diversifies_replicas() {
        let base = std::time::Duration::from_secs(10);
        let samples = (0_u64..64)
            .map(|sample| jittered_fleet_delay_with_sample(base, sample * 7919))
            .collect::<BTreeSet<_>>();
        assert!(
            samples.len() > 32,
            "samples must not collapse into one timer"
        );
        assert!(
            samples
                .iter()
                .all(|delay| *delay >= std::time::Duration::from_secs(8)
                    && *delay <= std::time::Duration::from_secs(12))
        );
    }

    #[test]
    fn public_base_url_requires_a_secure_origin_outside_loopback_development() {
        let bind = "0.0.0.0:8080".parse().expect("bind address");
        assert!(validate_public_base_url("https://aip.example", false, bind).is_ok());
        assert!(validate_public_base_url("http://aip.example", false, bind).is_err());
        assert!(validate_public_base_url("https://aip.example/prefix", false, bind).is_err());
        assert!(validate_public_base_url("https://user@aip.example", false, bind).is_err());

        let loopback = "127.0.0.1:8080".parse().expect("loopback address");
        let normalized = validate_public_base_url("http://127.0.0.1:18080", true, loopback)
            .expect("explicit loopback development origin");
        assert_eq!(normalized.as_str(), "http://127.0.0.1:18080/");
    }

    #[tokio::test]
    async fn fleet_worker_refreshes_one_bounded_snapshot_and_stops_cleanly() {
        let provider = Arc::new(CountingFleetStatusProvider::default());
        let supervisor = DaemonFleetSupervisorState::default();
        let (shutdown, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(supervise_fleet_status(
            provider.clone(),
            supervisor.clone(),
            shutdown_rx,
        ));
        timeout(std::time::Duration::from_secs(2), async {
            loop {
                if provider.summary_calls.load(Ordering::SeqCst) > 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("fleet worker first summary");
        shutdown.send(true).expect("stop fleet worker");
        task.await.expect("fleet worker task");
        let snapshot = supervisor.snapshot().await;
        assert!(!snapshot.worker_running);
        assert_eq!(snapshot.consecutive_failures, 0);
        assert_eq!(
            snapshot
                .summary
                .as_ref()
                .map(|summary| summary.ready_replicas),
            Some(7)
        );
        assert!(provider.expiry_calls.load(Ordering::SeqCst) > 0);
    }

    #[tokio::test]
    async fn ready_reads_the_cached_fleet_summary_without_calling_the_registry() {
        let provider = Arc::new(CountingFleetStatusProvider::default());
        let handler = Arc::new(DynamicFleetHandler::default());
        let daemon = AipDaemon::new_with_deployment(
            insecure_loopback_test_config(),
            AipDaemonDeployment::default().with_fleet_services(
                DaemonFleetServices::new(Arc::new(EmptyCapabilityCatalog), handler)
                    .with_status_provider(provider.clone()),
            ),
        )
        .await
        .expect("daemon with fleet status");
        daemon.supervisor.inner.write().await.runtime_worker_running = true;
        let fleet = daemon.fleet_supervisor.as_ref().expect("fleet supervisor");
        {
            let mut snapshot = fleet.inner.write().await;
            snapshot.worker_running = true;
            snapshot.last_success_at = Some(OffsetDateTime::now_utc());
            snapshot.summary = Some(FleetStatusSummary {
                ready_replicas: 11,
                ready_capacity: 110,
                observed_at: OffsetDateTime::now_utc(),
                ..FleetStatusSummary::default()
            });
        }
        let response = daemon
            .router()
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .expect("readiness request"),
            )
            .await
            .expect("readiness response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("readiness body");
        let body: Value = serde_json::from_slice(&body).expect("readiness JSON");
        assert_eq!(
            body.pointer("/fleet/summary/ready_replicas"),
            Some(&json!(11))
        );
        assert_eq!(provider.expiry_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.summary_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn connector_event_http_route_authenticates_enriches_and_stores_aip_events() {
        let registry = Arc::new(InMemoryConnectorRegistry::default());
        let connector_type_id = ConnectorTypeId::trusted("ctype_daemon_event_test");
        let version_id = ConnectorVersionId::trusted("cver_daemon_event_test_v1");
        let instance_id = ConnectorInstanceId::trusted("cinst_daemon_event_test_acme");
        let replica_id = ConnectorReplicaId::trusted("crepl_daemon_event_test_one");
        registry
            .put_connector_type(ConnectorType {
                id: connector_type_id.clone(),
                name: "Daemon event fixture".to_owned(),
                owner: "AIP conformance".to_owned(),
                enabled: true,
            })
            .await
            .expect("connector type");

        let host_key = Arc::new(aip_crypto::signing_key_from_seed([81_u8; 32]));
        let mut host_principal = Principal::new(
            PrincipalId::trusted("service:connector:daemon-event-test"),
            PrincipalKind::Service,
        );
        host_principal.trust_domain = Some("connectors.test".to_owned());
        let host_signer = CallbackSigner {
            principal: host_principal.clone(),
            signing_key: host_key.clone(),
        };
        let connector_manifest = Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: host_principal.clone(),
            capabilities: Vec::new(),
            profiles: vec![ProfileId::from("aip.native.http.v1")],
            resources: Vec::new(),
            channels: vec![json!({ "id": "orders.updated" })],
            security: None,
            governance: None,
            limits: None,
            compatibility: None,
            extensions: None,
        };
        let manifest_digest = digest_json(
            &serde_json::to_value(&connector_manifest).expect("connector manifest value"),
        )
        .expect("connector manifest digest");
        registry
            .admit_version(ConnectorVersion {
                id: version_id.clone(),
                connector_type_id: connector_type_id.clone(),
                version: "1.0.0".to_owned(),
                status: ConnectorVersionStatus::Active,
                manifest: connector_manifest.clone(),
                manifest_digest: manifest_digest.clone(),
                attestation: ArtifactAttestation {
                    artifact_digest: format!("sha256:{}", "1".repeat(64)),
                    schema_bundle_digest: schema_bundle_digest(&connector_manifest)
                        .expect("schema bundle digest"),
                    sbom_digest: format!("sha256:{}", "2".repeat(64)),
                    provenance_digest: format!("sha256:{}", "3".repeat(64)),
                    conformance_report_digest: format!("sha256:{}", "4".repeat(64)),
                    vulnerability_report_digest: format!("sha256:{}", "5".repeat(64)),
                    license_report_digest: format!("sha256:{}", "6".repeat(64)),
                    signature_ref: "sigstore:daemon-event-test".to_owned(),
                    signer_identity: "https://fulcio.example/identity/daemon-event-test".to_owned(),
                    owner: "AIP conformance".to_owned(),
                    supported_aip_versions: BTreeSet::from([aip_core::AIP_VERSION.to_owned()]),
                    sdk_version_requirement: format!("^{}", env!("CARGO_PKG_VERSION")),
                    conformance_status: ArtifactCheckStatus::Passed,
                    vulnerability_policy_status: ArtifactCheckStatus::Passed,
                    license_policy_status: ArtifactCheckStatus::Passed,
                    revocation_status: ArtifactCheckStatus::Passed,
                },
                implementation_support: BTreeMap::new(),
                admitted_at: OffsetDateTime::now_utc(),
            })
            .await
            .expect("connector version");
        registry
            .put_instance(ConnectorInstance {
                id: instance_id.clone(),
                connector_type_id,
                version_id: version_id.clone(),
                tenant_id: "tenant-acme".to_owned(),
                config_revision: 1,
                secret_provider_ref: "vault://tenant-acme/daemon-event-test".to_owned(),
                status: ConnectorInstanceStatus::Enabled,
            })
            .await
            .expect("connector instance");
        registry
            .put_replica(ConnectorReplica {
                id: replica_id.clone(),
                instance_id: instance_id.clone(),
                version_id: version_id.clone(),
                endpoint: "https://daemon-event-test.invalid/aip/v1/messages".to_owned(),
                peer_principal_id: host_principal.id.clone(),
                peer_principal_kind: host_principal.kind,
                peer_did: aip_crypto::did_key_from_verifying_key(&host_key.verifying_key()),
                trust_domain: "connectors.test".to_owned(),
                transport_profile: ProfileId::from("aip.native.http.v1"),
                topology: Default::default(),
                status: ConnectorReplicaStatus::Ready,
                lease_expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(5),
                capacity: 4,
                active_assignments: 0,
                health_revision: 1,
                last_control_request_id: None,
                last_control_request_digest: None,
            })
            .await
            .expect("connector replica");

        let daemon_signer = CallbackSigner {
            principal: Principal::new(
                PrincipalId::trusted("agent:getaip:server:local"),
                PrincipalKind::Agent,
            ),
            signing_key: Arc::new(aip_crypto::signing_key_from_seed([82_u8; 32])),
        };
        let daemon = AipDaemon::new_with_deployment(
            insecure_loopback_test_config(),
            AipDaemonDeployment::default().with_fleet_services(
                DaemonFleetServices::new(
                    Arc::new(EmptyCapabilityCatalog),
                    Arc::new(DynamicFleetHandler::default()),
                )
                .with_event_ingress(
                    registry,
                    daemon_signer.clone(),
                    ConnectorEventIngressLimits::default(),
                ),
            ),
        )
        .await
        .expect("daemon with connector event ingress");

        let mut event = Event::new("orders.updated");
        event.data = Some(json!({ "provider_order_id": "order-17" }));
        let mut envelope = Envelope::new(MessageBody::EventStream(EventStream {
            events: vec![event],
            next_cursor: None,
        }));
        envelope.to = Some(daemon_signer.principal.clone());
        envelope.security = Some(json!({
            "connector_event": {
                "tenant_id": "tenant-acme",
                "instance_id": instance_id,
                "replica_id": replica_id,
                "version_id": version_id,
                "manifest_digest": manifest_digest,
                "lease_sequence": 1,
                "channel_id": "orders.updated"
            }
        }));
        let envelope = sign_native_envelope(envelope, &host_signer).expect("signed event");
        let response = daemon
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/aip/v1/connector-events")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&envelope).expect("event envelope JSON"),
                    ))
                    .expect("connector event request"),
            )
            .await
            .expect("connector event response");
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("connector event response body");
        let response: Envelope =
            serde_json::from_slice(&response_body).expect("connector event response envelope");
        verify_native_envelope_signature(&response).expect("daemon response signature");

        let stored = daemon
            .gateway
            .runtime()
            .events
            .stream(&EventStreamRequest {
                cursor: None,
                limit: Some(10),
                kinds: vec!["orders.updated".to_owned()],
            })
            .await
            .expect("stored connector events");
        assert_eq!(stored.events.len(), 1);
        assert_eq!(
            stored.events[0]
                .data
                .as_ref()
                .and_then(|data| data.pointer("/identity/tenant/id"))
                .and_then(Value::as_str),
            Some("tenant-acme")
        );
    }

    #[tokio::test]
    async fn daemon_fleet_composition_keeps_manifest_bounded_and_executes_by_tenant() {
        let capability_id = CapabilityId::trusted("cap:test:daemon-fleet");
        let capability = Capability {
            id: capability_id.clone(),
            name: "Daemon fleet capability".to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: json!({ "type": "object" }),
            output_schema: Some(json!({ "type": "object" })),
            description: Some("Tenant-scoped remote fleet fixture".to_owned()),
            risk: None,
            stability: None,
            cost: None,
            auth: None,
            bindings: Vec::new(),
            requires_human_approval: None,
            contract: None,
        };
        let catalog = Arc::new(DynamicFleetCatalog {
            tenant_id: "tenant-fleet".to_owned(),
            definition: CapabilityDefinition {
                capability,
                contract_digest: format!("sha256:{}", "1".repeat(64)),
                schema_digest: format!("sha256:{}", "2".repeat(64)),
            },
        });
        let handler = Arc::new(DynamicFleetHandler::default());
        let native_principal_id = PrincipalId::trusted("service:test-native-catalog-client");
        let native_tenant = VerifiedTenant {
            tenant: TenantRef {
                id: "tenant-fleet".to_owned(),
                system: Some("daemon-test".to_owned()),
            },
            membership_id: "membership-native-daemon-fleet".to_owned(),
            roles: BTreeSet::new(),
            groups: BTreeSet::new(),
            verified_at: OffsetDateTime::now_utc(),
            expires_at: None,
        };
        let identity_resolver = StaticTrustedIdentityResolver::new([TrustedIdentityBinding {
            principal_id: native_principal_id.clone(),
            tenant: Some(native_tenant),
            credential: None,
            identity: None,
            revision: 1,
            revoked: false,
            expires_at: None,
        }]);
        let mut config = insecure_loopback_test_config();
        config.public_base_url = Some("https://aip.example".to_owned());
        config.native_http_auth = config
            .native_http_auth
            .map(|auth| auth.with_tenant("tenant-fleet"));
        let daemon = AipDaemon::new_with_deployment(
            config,
            AipDaemonDeployment::default()
                .with_trust_resolvers(DaemonTrustResolvers::new(
                    Arc::new(identity_resolver),
                    Arc::new(DenyAllApprovalAuthorityResolver),
                ))
                .with_fleet_services(DaemonFleetServices::new(catalog, handler.clone())),
        )
        .await
        .expect("daemon with fleet services");
        assert!(
            daemon
                .manifest()
                .capabilities
                .iter()
                .all(|candidate| candidate.id != capability_id),
            "remote fleet definitions must not expand the local manifest"
        );

        let session_id = "stdio-daemon-fleet";
        let actor = Principal::new(
            PrincipalId::trusted("service:test-daemon-fleet-client"),
            PrincipalKind::Service,
        );
        daemon
            .mcp_server
            .bind_session_identity(
                session_id,
                McpTransportKind::Stdio,
                AuthenticatedPrincipal {
                    principal: actor,
                    scheme: AuthScheme::DidProof,
                    issuer: "daemon-fleet-test".to_owned(),
                    audience: Some("aip".to_owned()),
                    scopes: BTreeSet::from(["*".to_owned()]),
                    authenticated_at: time::OffsetDateTime::now_utc(),
                    expires_at: None,
                    credential_fingerprint: None,
                },
                Some(VerifiedTenant {
                    tenant: TenantRef {
                        id: "tenant-fleet".to_owned(),
                        system: Some("daemon-test".to_owned()),
                    },
                    membership_id: "membership-daemon-fleet".to_owned(),
                    roles: BTreeSet::new(),
                    groups: BTreeSet::new(),
                    verified_at: time::OffsetDateTime::now_utc(),
                    expires_at: None,
                }),
            )
            .await
            .expect("bind fleet tenant");
        initialize_mcp_peer(&daemon, session_id, McpTransportKind::Stdio, "2025-11-25").await;
        let listed = daemon
            .mcp_server
            .handle_request_on_transport(
                session_id,
                McpTransportKind::Stdio,
                JsonRpcRequest::new(json!(2), McpMethod::ToolsList, None),
            )
            .await
            .result
            .expect("bounded tools list");
        assert!(
            listed
                .get("tools")
                .and_then(Value::as_array)
                .is_some_and(|tools| tools.iter().all(|tool| {
                    tool.get("name").and_then(Value::as_str) != Some(capability_id.as_str())
                })),
            "remote capabilities must not become generated MCP tools"
        );

        let router = daemon.router();
        let card_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/agent-card.json")
                    .body(Body::empty())
                    .expect("Agent Card request"),
            )
            .await
            .expect("Agent Card response");
        assert_eq!(card_response.status(), StatusCode::OK);
        let card: Value = serde_json::from_slice(
            &to_bytes(card_response.into_body(), 1024 * 1024)
                .await
                .expect("Agent Card body"),
        )
        .expect("Agent Card JSON");
        assert_eq!(
            card.pointer("/supportedInterfaces/0/url"),
            Some(&json!("https://aip.example/a2a/v1"))
        );
        assert_eq!(
            card.pointer("/capabilities/extensions/0/params/endpoint"),
            Some(&json!("https://aip.example/aip/v1/capabilities"))
        );
        assert_eq!(
            card.pointer("/capabilities/extensions/0/params/native_action_capability_id"),
            Some(&json!(CAPABILITY_CATALOG_QUERY_ID))
        );

        let discovery_response = router
            .oneshot(
                Request::builder()
                    .uri("/aip/v1/capabilities?capability_id=cap:test:daemon-fleet&limit=10")
                    .header(header::AUTHORIZATION, "Bearer insecure-loopback-test-token")
                    .body(Body::empty())
                    .expect("capability discovery request"),
            )
            .await
            .expect("capability discovery response");
        assert_eq!(discovery_response.status(), StatusCode::OK);
        let discovery: Value = serde_json::from_slice(
            &to_bytes(discovery_response.into_body(), 1024 * 1024)
                .await
                .expect("capability discovery body"),
        )
        .expect("capability discovery JSON");
        assert_eq!(
            discovery.pointer("/capabilities/0/capability/id"),
            Some(&json!("cap:test:daemon-fleet"))
        );
        let native_actor = AuthenticatedPrincipal {
            principal: Principal::new(native_principal_id, PrincipalKind::Service),
            scheme: AuthScheme::DidProof,
            issuer: "daemon-fleet-test".to_owned(),
            audience: Some("aip".to_owned()),
            scopes: BTreeSet::from(["*".to_owned()]),
            authenticated_at: OffsetDateTime::now_utc(),
            expires_at: None,
            credential_fingerprint: None,
        };
        let native_discovery = daemon
            .gateway
            .handle_verified_envelope(
                Envelope::new(MessageBody::Action(Box::new(Action::new(
                    CapabilityId::trusted(CAPABILITY_CATALOG_QUERY_ID),
                    json!({ "capability_id": "cap:test:daemon-fleet", "limit": 10 }),
                )))),
                native_actor.clone(),
                None,
                None,
            )
            .await
            .expect("signed native tenant discovery");
        let MessageBody::ActionResult(native_discovery) = native_discovery.body else {
            panic!("expected native discovery action result");
        };
        assert_eq!(
            native_discovery
                .output
                .as_ref()
                .and_then(|value| value.pointer("/capabilities/0/capability/id")),
            Some(&json!("cap:test:daemon-fleet"))
        );
        let native_execution = daemon
            .gateway
            .handle_verified_envelope(
                Envelope::new(MessageBody::Action(Box::new(Action::new(
                    capability_id.clone(),
                    json!({ "source": "resolved-fleet-identity" }),
                )))),
                native_actor,
                None,
                None,
            )
            .await
            .expect("dynamic fleet execution with resolved tenant");
        let MessageBody::ActionResult(native_execution) = native_execution.body else {
            panic!("expected native fleet action result");
        };
        assert_eq!(native_execution.status, ActionResultStatus::Completed);
        assert_eq!(handler.invocations.load(Ordering::SeqCst), 1);
        let capabilities = daemon
            .mcp_server
            .handle_request_on_transport(
                session_id,
                McpTransportKind::Stdio,
                JsonRpcRequest::new(
                    json!(3),
                    McpMethod::ToolsCall,
                    Some(json!({
                        "name": "aip_capabilities",
                        "arguments": { "capability_id": capability_id }
                    })),
                ),
            )
            .await
            .result
            .expect("fleet capability lookup");
        assert_eq!(
            capabilities.pointer("/structuredContent/capabilities/0/id"),
            Some(&json!("cap:test:daemon-fleet"))
        );
        let called = daemon
            .mcp_server
            .handle_request_on_transport(
                session_id,
                McpTransportKind::Stdio,
                JsonRpcRequest::new(
                    json!(4),
                    McpMethod::ToolsCall,
                    Some(json!({
                        "name": "aip_call",
                        "arguments": {
                            "capability_id": "cap:test:daemon-fleet",
                            "input": { "value": 42 }
                        }
                    })),
                ),
            )
            .await
            .result
            .expect("fleet invocation");
        assert_eq!(
            called.pointer("/structuredContent/fleet"),
            Some(&json!(true))
        );
        assert_eq!(handler.invocations.load(Ordering::SeqCst), 2);
    }

    #[derive(Clone, Debug)]
    struct TestMcpHttpSession {
        id: String,
        version: String,
    }

    async fn initialize_mcp_http(
        router: &Router,
        authorization: Option<&str>,
    ) -> TestMcpHttpSession {
        let mut request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json");
        if let Some(authorization) = authorization {
            request = request.header("authorization", authorization);
        }
        let response = router
            .clone()
            .oneshot(
                request
                    .body(Body::from(
                        json!({
                            "jsonrpc": "2.0",
                            "id": "initialize-test-session",
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2025-11-25",
                                "capabilities": { "tasks": {} },
                                "clientInfo": {
                                    "name": "getaip-server-http-test-client",
                                    "version": "1.0.0"
                                }
                            }
                        })
                        .to_string(),
                    ))
                    .expect("initialize request"),
            )
            .await
            .expect("initialize response");
        let status = response.status();
        let session_id = response
            .headers()
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let version = response
            .headers()
            .get("mcp-protocol-version")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("initialize response body");
        assert_eq!(
            status,
            StatusCode::OK,
            "MCP initialize failed: {}",
            String::from_utf8_lossy(&body)
        );
        let session = TestMcpHttpSession {
            id: session_id.expect("MCP-Session-Id response header"),
            version: version.expect("MCP-Protocol-Version response header"),
        };

        let mut initialized = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("mcp-session-id", &session.id)
            .header("mcp-protocol-version", &session.version);
        if let Some(authorization) = authorization {
            initialized = initialized.header("authorization", authorization);
        }
        let response = router
            .clone()
            .oneshot(
                initialized
                    .body(Body::from(
                        json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/initialized"
                        })
                        .to_string(),
                    ))
                    .expect("initialized notification"),
            )
            .await
            .expect("initialized response");
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        session
    }

    #[test]
    fn health_capability_uses_stable_id() {
        assert_eq!(health_capability().id.as_str(), HEALTH_CAPABILITY_ID);
    }

    #[test]
    fn daemon_manifest_preserves_the_service_identity_kind() {
        let config = AipDaemonConfig {
            service_id: PrincipalId::trusted("service:getaip:server:fleet"),
            ..AipDaemonConfig::default()
        };

        let manifest = super::manifest_from_config_with_runtime_storage(&config, "test");

        assert_eq!(manifest.agent.id, config.service_id);
        assert_eq!(manifest.agent.kind, PrincipalKind::Service);
    }

    #[tokio::test]
    async fn daemon_accepts_native_handshake() {
        let daemon = AipDaemon::new(insecure_loopback_test_config())
            .await
            .expect("daemon");
        let principal = Principal::new(
            PrincipalId::parse("agent:test-client").expect("principal"),
            PrincipalKind::Agent,
        );
        let mut request = Envelope::new(MessageBody::Handshake(Handshake {
            client: principal.clone(),
            purpose: "unit test".to_owned(),
            requested_capabilities: Vec::new(),
            profiles: vec![ProfileId::from(super::NATIVE_HTTP_PROFILE)],
            auth: None,
            compliance_required: Vec::new(),
            heartbeat: None,
            encryption: None,
            billing: None,
        }));
        request.from = Some(principal);
        let response = daemon
            .gateway
            .handle_envelope(request)
            .await
            .expect("handshake response");

        assert!(matches!(response.body, MessageBody::HandshakeResponse(_)));
    }

    #[tokio::test]
    async fn daemon_exposes_native_action_status_endpoint() {
        let daemon = AipDaemon::new(insecure_loopback_test_config())
            .await
            .expect("daemon");
        let action_id = ActionId::new();
        let response = daemon
            .router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/aip/v1/actions/{action_id}?include_result=true"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let value: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            value
                .pointer("/action_status/state")
                .and_then(Value::as_str),
            Some("unknown")
        );
    }

    #[tokio::test]
    async fn daemon_exposes_rfc0003_operational_endpoints() {
        let daemon = AipDaemon::new(insecure_loopback_test_config())
            .await
            .expect("daemon");
        for uri in [
            "/aip/v1/sessions",
            "/aip/v1/approvals",
            "/aip/v1/audit/events",
            "/aip/v1/resources",
        ] {
            let response = daemon
                .router()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(uri)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
        }
    }

    #[tokio::test]
    async fn daemon_exposes_canonical_session_operation_colon_routes() {
        let daemon = AipDaemon::new(insecure_loopback_test_config())
            .await
            .expect("daemon");
        for operation in ["close", "resume"] {
            let session_id = SessionId::new();
            let response = daemon
                .router()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/aip/v1/sessions/{session_id}:{operation}"))
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("request"),
                )
                .await
                .expect("response");
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .expect("body");
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "{operation}: {}",
                String::from_utf8_lossy(&body)
            );
            let value: Value = serde_json::from_slice(&body).expect("json");
            assert!(
                value.pointer("/body/error/error/code")
                    == Some(&Value::String("session.not_found".to_owned()))
                    || value.pointer("/body/error/error/code")
                        == Some(&Value::String("session.resume_rejected".to_owned()))
                    || value.pointer("/session/session_id").is_some(),
                "{operation}: {value}"
            );
        }
    }

    #[test]
    fn daemon_websocket_subscription_maps_native_action_selectors() {
        let action_id = ActionId::new();
        let body = super::websocket_subscription_body(&super::NativeWebSocketSubscribe {
            r#type: "subscribe".to_owned(),
            subscription_id: Some("sub-1".to_owned()),
            action_id: Some(action_id.to_string()),
            session_id: Some(SessionId::new().to_string()),
            tenant_id: Some("tenant-a".to_owned()),
            cursor: Some("evt_cursor_7".to_owned()),
            limit: Some(25),
            kinds: Some(vec!["aip.action.result".to_owned()]),
            kind: Some("aip.stream.chunk".to_owned()),
            include_chunks: Some(true),
            follow: Some(true),
        })
        .expect("subscription body");
        let MessageBody::ActionEventsRequest(request) = body else {
            panic!("expected action events request");
        };
        assert_eq!(request.action_id, action_id);
        assert_eq!(request.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(request.cursor.as_deref(), Some("evt_cursor_7"));
        assert_eq!(request.limit, Some(25));
        assert_eq!(
            request.kinds,
            vec![
                "aip.action.result".to_owned(),
                "aip.stream.chunk".to_owned()
            ]
        );
        assert!(request.include_chunks);
        assert!(request.follow);
    }

    #[test]
    fn daemon_annotates_websocket_subscription_responses_for_resume() {
        let mut envelope = Envelope::new(MessageBody::EventStream(aip_core::EventStream {
            events: Vec::new(),
            next_cursor: Some("evt_cursor_9".to_owned()),
        }));
        let subscription = super::NativeWebSocketSubscribe {
            r#type: "subscribe".to_owned(),
            subscription_id: Some("sub-1".to_owned()),
            action_id: Some("act_01K00000000000000000000000".to_owned()),
            session_id: Some(SessionId::new().to_string()),
            tenant_id: Some("tenant-a".to_owned()),
            cursor: Some("evt_cursor_7".to_owned()),
            limit: Some(10),
            kinds: None,
            kind: None,
            include_chunks: None,
            follow: Some(true),
        };

        super::annotate_websocket_subscription_response(
            &mut envelope,
            &subscription,
            Some("evt_cursor_9"),
            false,
        );

        let trace = envelope.trace.as_ref().expect("trace");
        assert_eq!(
            trace.pointer("/websocket/subscription_id"),
            Some(&json!("sub-1"))
        );
        assert_eq!(
            trace.pointer("/websocket/cursor"),
            Some(&json!("evt_cursor_7"))
        );
        assert_eq!(
            trace.pointer("/websocket/next_cursor"),
            Some(&json!("evt_cursor_9"))
        );
        assert_eq!(trace.pointer("/websocket/terminal"), Some(&json!(false)));
    }

    #[test]
    fn daemon_advances_websocket_subscription_cursor_for_follow_resume() {
        let mut subscription = super::NativeWebSocketSubscribe {
            r#type: "subscribe".to_owned(),
            subscription_id: Some("sub-1".to_owned()),
            action_id: None,
            session_id: Some(SessionId::new().to_string()),
            tenant_id: Some("tenant-a".to_owned()),
            cursor: Some("evt_cursor_7".to_owned()),
            limit: Some(10),
            kinds: None,
            kind: None,
            include_chunks: None,
            follow: Some(true),
        };

        super::update_websocket_subscription_cursor(
            &mut subscription,
            Some("evt_cursor_9".to_owned()),
        );
        assert_eq!(subscription.cursor.as_deref(), Some("evt_cursor_9"));

        super::update_websocket_subscription_cursor(&mut subscription, None);
        assert_eq!(
            subscription.cursor.as_deref(),
            Some("evt_cursor_9"),
            "a missing next cursor must not discard the last resumable cursor"
        );
    }

    #[test]
    fn daemon_bounds_native_websocket_output_for_a_slow_consumer() {
        let (outbound, _inbound) = tokio::sync::mpsc::channel(super::NATIVE_WS_OUTBOUND_CAPACITY);
        for sequence in 0..super::NATIVE_WS_OUTBOUND_CAPACITY {
            let envelope = Envelope::new(MessageBody::EventStream(EventStream {
                events: vec![Event::new(format!("aip.test.websocket.{sequence}"))],
                next_cursor: Some(format!("evt_cursor_{}", sequence + 1)),
            }));
            assert!(super::send_native_websocket_envelope(&outbound, envelope));
        }

        let overflow = Envelope::new(MessageBody::EventStream(EventStream {
            events: vec![Event::new("aip.test.websocket.overflow")],
            next_cursor: Some("evt_cursor_overflow".to_owned()),
        }));
        assert!(
            !super::send_native_websocket_envelope(&outbound, overflow),
            "a slow websocket consumer must not grow an unbounded output queue"
        );
    }

    async fn next_websocket_envelope(
        websocket: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> Envelope {
        let message = websocket
            .next()
            .await
            .expect("websocket message")
            .expect("valid websocket message");
        let text = match message {
            TungsteniteMessage::Text(text) => text.to_string(),
            other => panic!("expected text websocket message, got {other:?}"),
        };
        aip_transport_websocket::decode_ws(&aip_transport_websocket::WebSocketFrame::Text(text))
            .expect("decode AIP websocket envelope")
    }

    #[tokio::test]
    async fn daemon_native_websocket_round_trips_over_tcp_listener() {
        let daemon = AipDaemon::new(insecure_loopback_test_config())
            .await
            .expect("daemon");
        let sender = daemon.manifest().agent.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, daemon.router())
                .await
                .expect("getaip-server websocket server");
        });

        let (mut websocket, _) =
            tokio_tungstenite::connect_async(format!("ws://{address}/aip/v1/ws"))
                .await
                .expect("websocket connect");
        let mut request = Envelope::new(MessageBody::EventStreamRequest(EventStreamRequest {
            cursor: None,
            limit: Some(1),
            kinds: Vec::new(),
        }));
        request.from = Some(sender);
        let aip_transport_websocket::WebSocketFrame::Text(text) =
            aip_transport_websocket::encode_ws(&request).expect("encode request")
        else {
            panic!("native envelope encodes to text");
        };
        websocket
            .send(TungsteniteMessage::Text(text.into()))
            .await
            .expect("send envelope");
        let response = next_websocket_envelope(&mut websocket).await;
        assert!(matches!(response.body, MessageBody::EventStream(_)));

        websocket
            .send(TungsteniteMessage::Text(
                json!({
                    "type": "subscribe",
                    "subscription_id": "sub-tcp",
                    "limit": 1
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("send subscription");
        let subscription_response = next_websocket_envelope(&mut websocket).await;
        assert_eq!(
            subscription_response
                .trace
                .as_ref()
                .and_then(|trace| trace.pointer("/websocket/subscription_id"))
                .and_then(Value::as_str),
            Some("sub-tcp")
        );
        assert!(matches!(
            subscription_response.body,
            MessageBody::EventStream(_)
        ));

        websocket.close(None).await.expect("close websocket");
        server.abort();
    }

    #[test]
    fn daemon_uses_last_event_id_for_native_sse_reconnect() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("last-event-id"),
            HeaderValue::from_static("  evt_cursor_7  "),
        );

        assert_eq!(
            super::cursor_from_http(&headers, None).as_deref(),
            Some("evt_cursor_7")
        );
        assert_eq!(
            super::cursor_from_http(&headers, Some("evt_cursor_query".to_owned())).as_deref(),
            Some("evt_cursor_query"),
            "explicit query cursors have precedence over Last-Event-ID"
        );
    }

    #[test]
    fn daemon_renders_action_events_sse_cursor_for_resume() {
        let action_id = ActionId::new();
        let mut event = Event::new("aip.action.updated");
        event.action_id = Some(action_id.clone());
        let rendered =
            super::native_sse_events_from_body(MessageBody::ActionEvents(ActionEvents {
                action_id,
                events: vec![event],
                chunks: Vec::new(),
                cursor: Some("evt_cursor_10".to_owned()),
                terminal: false,
            }))
            .expect("rendered SSE");

        assert!(rendered.contains("event: aip.action.updated"));
        assert!(rendered.contains("event: aip.stream.cursor"));
        assert!(rendered.contains("id: evt_cursor_10"));
        assert!(rendered.contains(r#""next_cursor":"evt_cursor_10""#));
    }

    #[test]
    fn daemon_renders_global_event_stream_sse_cursor_for_resume() {
        let rendered = super::native_sse_events_from_body(MessageBody::EventStream(EventStream {
            events: vec![Event::new("aip.event")],
            next_cursor: Some("evt_cursor_11".to_owned()),
        }))
        .expect("rendered SSE");

        assert!(rendered.contains("event: aip.event"));
        assert!(rendered.contains("event: aip.stream.cursor"));
        assert!(rendered.contains("id: evt_cursor_11"));
    }

    #[test]
    fn daemon_applies_a2a_history_length_to_cached_task_value() {
        let mut task = json!({
            "id": "task-1",
            "skill_id": "support",
            "input": {},
            "history": [
                { "role": "agent", "parts": [{ "kind": "data", "data": { "step": 1 }}]},
                { "role": "agent", "parts": [{ "kind": "data", "data": { "step": 2 }}]},
                { "role": "agent", "parts": [{ "kind": "data", "data": { "step": 3 }}]}
            ]
        });

        super::apply_a2a_history_length_to_value(&mut task, Some(2));

        let history = task
            .get("history")
            .and_then(Value::as_array)
            .expect("history");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].pointer("/parts/0/data/step"), Some(&json!(2)));
        assert_eq!(history[1].pointer("/parts/0/data/step"), Some(&json!(3)));
    }

    #[tokio::test]
    async fn daemon_exposes_native_sse_follow_binding() {
        let daemon = AipDaemon::new(insecure_loopback_test_config())
            .await
            .expect("daemon");
        let response = daemon
            .router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/aip/v1/events?follow=true")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );
    }

    #[tokio::test]
    async fn daemon_manifest_exposes_native_nats_when_configured() {
        let config = AipDaemonConfig {
            nats: Some(AipDaemonNatsConfig {
                server_url: "nats://127.0.0.1:4222".to_owned(),
                authentication: None,
                trust_domain: "local.test".to_owned(),
                service: "gateway".to_owned(),
                version: "v1".to_owned(),
                queue_group: Some("getaip-server-workers".to_owned()),
                request_timeout_ms: 1_000,
            }),
            ..AipDaemonConfig::default()
        };
        let daemon = AipDaemon::new(config).await.expect("daemon");
        assert!(
            daemon
                .manifest()
                .profiles
                .iter()
                .any(|profile| profile.as_str() == aip_transport_nats::PROFILE_ID)
        );
        assert_eq!(
            daemon
                .manifest()
                .compatibility
                .as_ref()
                .and_then(|value| value.pointer("/native_nats/subject"))
                .and_then(serde_json::Value::as_str),
            Some("aip.v1.local_test.gateway.v1.>")
        );
    }

    #[tokio::test]
    async fn daemon_registers_configured_delegation_routes() {
        let delegate_id = PrincipalId::trusted("agent:delegate");
        let local_signer = CallbackSigner {
            principal: Principal::new(
                PrincipalId::trusted("service:test-delegation-signer"),
                PrincipalKind::Service,
            ),
            signing_key: Arc::new(aip_crypto::signing_key_from_seed([31_u8; 32])),
        };
        let remote_key = aip_crypto::signing_key_from_seed([32_u8; 32]);
        let mut endpoint_policy = GatewayCallbackPolicy::default();
        endpoint_policy.allowed_hosts.insert("127.0.0.1".to_owned());
        endpoint_policy.allow_http = true;
        endpoint_policy.allow_private_networks = true;
        let security = DelegationPeerSecurity::new(
            "test.local",
            local_signer,
            Principal::new(delegate_id.clone(), PrincipalKind::Agent),
            aip_crypto::did_key_from_verifying_key(&remote_key.verifying_key()),
            endpoint_policy,
        )
        .expect("peer security");
        let config = AipDaemonConfig {
            delegation_routes: vec![DelegationRoute::native_http_for_delegate(
                delegate_id.clone(),
                "http://127.0.0.1:18080/aip/v1/messages",
                security,
            )],
            ..AipDaemonConfig::default()
        };
        let daemon = AipDaemon::new(config).await.expect("daemon");

        let routes = daemon.gateway.delegation_routes().await;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].delegate_id, Some(delegate_id));
        assert_eq!(
            daemon
                .manifest()
                .compatibility
                .as_ref()
                .and_then(|value| value.pointer("/delegation_routes/0/transport"))
                .and_then(serde_json::Value::as_str),
            Some("http")
        );
    }

    #[tokio::test]
    async fn daemon_mcp_tools_call_uses_gateway_runtime() {
        let daemon = AipDaemon::new(insecure_loopback_test_config())
            .await
            .expect("daemon");
        let router = daemon.router();
        let session = initialize_mcp_http(&router, None).await;
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("mcp-session-id", session.id)
                    .header("mcp-protocol-version", session.version)
                    .body(Body::from(
                        json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {
                                "name": HEALTH_CAPABILITY_ID,
                                "arguments": {}
                            }
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let payload = serde_json::from_slice::<Value>(&body).expect("json");
        assert_eq!(
            payload.pointer("/result/isError"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            payload.pointer("/result/structuredContent/status"),
            Some(&Value::String("ok".to_owned()))
        );
        assert!(
            payload
                .pointer("/result/content/0/text")
                .and_then(Value::as_str)
                .is_some_and(|text| text.contains("healthy"))
        );
    }

    async fn initialize_mcp_peer(
        daemon: &AipDaemon,
        session_id: &str,
        transport: McpTransportKind,
        version: &str,
    ) {
        let initialized = daemon
            .mcp_server
            .handle_request_on_transport(
                session_id,
                transport,
                JsonRpcRequest::new(
                    json!(1),
                    McpMethod::Initialize,
                    Some(json!({
                        "protocolVersion": version,
                        "capabilities": {
                            "roots": { "listChanged": true },
                            "sampling": {},
                            "elicitation": {},
                            "tasks": {}
                        },
                        "clientInfo": { "name": "getaip-server-duplex-test", "version": "1.0.0" }
                    })),
                ),
            )
            .await;
        assert!(initialized.error.is_none(), "{initialized:?}");
        daemon
            .mcp_server
            .handle_notification_on_transport(
                session_id,
                transport,
                JsonRpcNotification::new(McpMethod::Initialized, None),
            )
            .await
            .expect("mark MCP peer initialized");
    }

    #[tokio::test]
    async fn daemon_mcp_stdio_completes_server_to_client_request() {
        let daemon = AipDaemon::new(AipDaemonConfig::default())
            .await
            .expect("daemon");
        let session_id = "stdio-duplex-test";
        let mut outgoing = daemon
            .open_mcp_stdio_peer(session_id)
            .await
            .expect("open stdio peer");
        initialize_mcp_peer(&daemon, session_id, McpTransportKind::Stdio, "2025-11-25").await;

        let server = daemon.mcp_server.clone();
        let request = tokio::spawn(async move {
            server
                .request_client_roots(session_id, std::time::Duration::from_secs(1))
                .await
        });
        let frame = timeout(std::time::Duration::from_secs(1), outgoing.recv())
            .await
            .expect("stdio request timeout")
            .expect("stdio request frame");
        let McpFrame::Request(frame) = frame else {
            panic!("expected server-to-client stdio request");
        };
        assert_eq!(frame.method, McpMethod::RootsList.to_string());
        daemon
            .accept_mcp_stdio_response(
                session_id,
                JsonRpcResponse::success(
                    frame.id,
                    json!({ "roots": [{ "uri": "file:///workspace", "name": "workspace" }] }),
                ),
            )
            .await
            .expect("accept stdio response");
        let roots = request
            .await
            .expect("stdio request task")
            .expect("stdio roots response");
        assert_eq!(
            roots.first().map(|root| root.uri.as_str()),
            Some("file:///workspace")
        );

        let server = daemon.mcp_server.clone();
        let sampling = tokio::spawn(async move {
            server
                .request_client_sampling(
                    session_id,
                    json!({
                        "messages": [{
                            "role": "user",
                            "content": { "type": "text", "text": "summarize" }
                        }],
                        "maxTokens": 16
                    }),
                    std::time::Duration::from_secs(1),
                )
                .await
        });
        let frame = timeout(std::time::Duration::from_secs(1), outgoing.recv())
            .await
            .expect("stdio sampling timeout")
            .expect("stdio sampling frame");
        let McpFrame::Request(frame) = frame else {
            panic!("expected sampling request");
        };
        assert_eq!(frame.method, McpMethod::SamplingCreateMessage.to_string());
        daemon
            .accept_mcp_stdio_response(
                session_id,
                JsonRpcResponse::success(
                    frame.id,
                    json!({
                        "role": "assistant",
                        "content": { "type": "text", "text": "summary" },
                        "model": "test-model"
                    }),
                ),
            )
            .await
            .expect("accept sampling response");
        assert_eq!(
            sampling
                .await
                .expect("sampling request task")
                .expect("sampling response")
                .pointer("/content/text"),
            Some(&json!("summary"))
        );

        let server = daemon.mcp_server.clone();
        let elicitation = tokio::spawn(async move {
            server
                .request_client_elicitation(
                    session_id,
                    json!({
                        "message": "Confirm operation",
                        "requestedSchema": {
                            "type": "object",
                            "properties": { "confirmed": { "type": "boolean" } }
                        }
                    }),
                    std::time::Duration::from_secs(1),
                )
                .await
        });
        let frame = timeout(std::time::Duration::from_secs(1), outgoing.recv())
            .await
            .expect("stdio elicitation timeout")
            .expect("stdio elicitation frame");
        let McpFrame::Request(frame) = frame else {
            panic!("expected elicitation request");
        };
        assert_eq!(frame.method, McpMethod::ElicitationCreate.to_string());
        daemon
            .accept_mcp_stdio_response(
                session_id,
                JsonRpcResponse::success(
                    frame.id,
                    json!({ "action": "accept", "content": { "confirmed": true } }),
                ),
            )
            .await
            .expect("accept elicitation response");
        assert_eq!(
            elicitation
                .await
                .expect("elicitation request task")
                .expect("elicitation response")
                .get("action"),
            Some(&json!("accept"))
        );
    }

    #[tokio::test]
    async fn daemon_projects_native_events_to_durable_mcp_notifications_once() {
        let daemon = AipDaemon::new(insecure_loopback_test_config())
            .await
            .expect("daemon");
        let session_id = "stdio-projection-test";
        let mut outgoing = daemon
            .open_mcp_stdio_peer(session_id)
            .await
            .expect("open stdio peer");
        initialize_mcp_peer(&daemon, session_id, McpTransportKind::Stdio, "2025-11-25").await;
        let action_id = ActionId::new();
        daemon
            .gateway
            .runtime()
            .record_action_result(
                ActionResult {
                    action_id: action_id.clone(),
                    status: ActionResultStatus::Completed,
                    output: Some(json!({ "ok": true })),
                    message: Vec::new(),
                    memory_update: None,
                    usage: None,
                    receipt: None,
                    error: None,
                },
                aip_runtime::MessageContext::default(),
            )
            .await
            .expect("record native action result");

        super::project_mcp_notifications_once(
            &daemon.gateway.runtime(),
            &daemon.mcp_server,
            "projection-test-worker",
        )
        .await
        .expect("project MCP notifications");
        let mut methods = Vec::new();
        while let Ok(Some(frame)) =
            timeout(std::time::Duration::from_millis(25), outgoing.recv()).await
        {
            if let McpFrame::Notification(notification) = frame {
                methods.push(notification.method);
            }
        }
        assert!(methods.contains(&McpMethod::ToolsListChanged.to_string()));
        assert!(methods.contains(&McpMethod::TasksStatus.to_string()));

        super::project_mcp_notifications_once(
            &daemon.gateway.runtime(),
            &daemon.mcp_server,
            "projection-test-worker",
        )
        .await
        .expect("idempotent second projection");
        assert!(
            timeout(std::time::Duration::from_millis(25), outgoing.recv())
                .await
                .is_err(),
            "durable cursor and delivery records must suppress duplicates"
        );
    }

    #[tokio::test]
    async fn daemon_composes_dynamic_resources_and_targets_updates_to_subscribers() {
        let providers = DaemonMcpProviders {
            resources: Some(Arc::new(DynamicTestResourceProvider)),
            ..DaemonMcpProviders::default()
        };
        let daemon = AipDaemon::new_with_deployment(
            insecure_loopback_test_config(),
            AipDaemonDeployment::default().with_mcp_providers(providers),
        )
        .await
        .expect("daemon with MCP providers");
        let subscribed_session = "stdio-resource-subscriber";
        let other_session = "stdio-resource-observer";
        let mut subscribed_outgoing = daemon
            .open_mcp_stdio_peer(subscribed_session)
            .await
            .expect("open subscribed stdio peer");
        let mut other_outgoing = daemon
            .open_mcp_stdio_peer(other_session)
            .await
            .expect("open observer stdio peer");
        initialize_mcp_peer(
            &daemon,
            subscribed_session,
            McpTransportKind::Stdio,
            "2025-11-25",
        )
        .await;
        initialize_mcp_peer(
            &daemon,
            other_session,
            McpTransportKind::Stdio,
            "2025-11-25",
        )
        .await;

        let listed = daemon
            .mcp_server
            .handle_request_on_transport(
                subscribed_session,
                McpTransportKind::Stdio,
                JsonRpcRequest::new(json!(2), McpMethod::ResourcesList, Some(json!({}))),
            )
            .await;
        assert_eq!(
            listed
                .result
                .as_ref()
                .and_then(|result| result.pointer("/resources/0/uri")),
            Some(&json!("aip://dynamic/customer-42"))
        );
        let subscribed = daemon
            .mcp_server
            .handle_request_on_transport(
                subscribed_session,
                McpTransportKind::Stdio,
                JsonRpcRequest::new(
                    json!(3),
                    McpMethod::ResourcesSubscribe,
                    Some(json!({ "uri": "aip://dynamic/customer-42" })),
                ),
            )
            .await;
        assert!(subscribed.error.is_none(), "{subscribed:?}");

        super::project_mcp_notifications_once(
            &daemon.gateway.runtime(),
            &daemon.mcp_server,
            "resource-projection-worker",
        )
        .await
        .expect("project startup notifications");
        while timeout(
            std::time::Duration::from_millis(10),
            subscribed_outgoing.recv(),
        )
        .await
        .is_ok()
        {}
        while timeout(std::time::Duration::from_millis(10), other_outgoing.recv())
            .await
            .is_ok()
        {}

        daemon
            .gateway
            .runtime()
            .record_resource_updated(
                "aip://dynamic/customer-42",
                aip_runtime::MessageContext::default(),
            )
            .await
            .expect("record resource update");
        super::project_mcp_notifications_once(
            &daemon.gateway.runtime(),
            &daemon.mcp_server,
            "resource-projection-worker",
        )
        .await
        .expect("project resource update");

        let frame = timeout(
            std::time::Duration::from_secs(1),
            subscribed_outgoing.recv(),
        )
        .await
        .expect("subscribed notification timeout")
        .expect("subscribed notification");
        let McpFrame::Notification(notification) = frame else {
            panic!("expected resource update notification");
        };
        assert_eq!(notification.method, McpMethod::ResourcesUpdated.as_str());
        assert_eq!(
            notification
                .params
                .as_ref()
                .and_then(|params| params.get("uri")),
            Some(&json!("aip://dynamic/customer-42"))
        );
        assert!(
            timeout(std::time::Duration::from_millis(50), other_outgoing.recv())
                .await
                .is_err(),
            "non-subscribed session must not receive resources/updated"
        );
    }

    #[tokio::test]
    async fn daemon_mcp_streamable_http_completes_server_to_client_request() {
        let daemon = AipDaemon::new(AipDaemonConfig::default())
            .await
            .expect("daemon");
        let session_id = "streamable-duplex-test";
        let owner = daemon.mcp_principal.id.to_string();
        daemon
            .mcp_peer_transport
            .register_session(session_id, &owner, McpTransportKind::StreamableHttp)
            .await
            .expect("register streamable peer");
        initialize_mcp_peer(
            &daemon,
            session_id,
            McpTransportKind::StreamableHttp,
            "2025-11-25",
        )
        .await;

        let server = daemon.mcp_server.clone();
        let request = tokio::spawn(async move {
            server
                .request_client_roots(session_id, std::time::Duration::from_secs(1))
                .await
        });
        let frame = timeout(std::time::Duration::from_secs(1), async {
            loop {
                let events = daemon
                    .mcp_sse_replay
                    .replay_after(session_id, None)
                    .await
                    .expect("read SSE replay");
                if let Some(event) = events.last() {
                    break serde_json::from_str::<JsonRpcRequest>(&event.data)
                        .expect("server request JSON");
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("streamable roots request timeout");
        assert_eq!(frame.method, McpMethod::RootsList.to_string());
        daemon
            .mcp_peer_transport
            .accept_response(
                session_id,
                &owner,
                JsonRpcResponse::success(
                    frame.id,
                    json!({ "roots": [{ "uri": "file:///workspace", "name": "workspace" }] }),
                ),
            )
            .await
            .expect("accept streamable response");
        let roots = request
            .await
            .expect("streamable request task")
            .expect("streamable roots response");
        assert_eq!(
            roots.first().map(|root| root.uri.as_str()),
            Some("file:///workspace")
        );

        let server = daemon.mcp_server.clone();
        let sampling = tokio::spawn(async move {
            server
                .request_client_sampling(
                    session_id,
                    json!({
                        "messages": [{
                            "role": "user",
                            "content": { "type": "text", "text": "summarize" }
                        }],
                        "maxTokens": 16
                    }),
                    std::time::Duration::from_secs(1),
                )
                .await
        });
        let sampling_frame = timeout(std::time::Duration::from_secs(1), async {
            loop {
                let events = daemon
                    .mcp_sse_replay
                    .replay_after(session_id, None)
                    .await
                    .expect("read sampling SSE replay");
                if let Some(request) = events.iter().rev().find_map(|event| {
                    serde_json::from_str::<JsonRpcRequest>(&event.data)
                        .ok()
                        .filter(|request| {
                            request.method == McpMethod::SamplingCreateMessage.as_str()
                        })
                }) {
                    break request;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("streamable sampling request timeout");
        daemon
            .mcp_peer_transport
            .accept_response(
                session_id,
                &owner,
                JsonRpcResponse::success(
                    sampling_frame.id,
                    json!({
                        "role": "assistant",
                        "content": { "type": "text", "text": "summary" },
                        "model": "test-model"
                    }),
                ),
            )
            .await
            .expect("accept streamable sampling response");
        assert_eq!(
            sampling
                .await
                .expect("streamable sampling task")
                .expect("streamable sampling response")
                .pointer("/content/text"),
            Some(&json!("summary"))
        );

        let server = daemon.mcp_server.clone();
        let elicitation = tokio::spawn(async move {
            server
                .request_client_elicitation(
                    session_id,
                    json!({
                        "message": "Confirm operation",
                        "requestedSchema": {
                            "type": "object",
                            "properties": { "confirmed": { "type": "boolean" } }
                        }
                    }),
                    std::time::Duration::from_secs(1),
                )
                .await
        });
        let elicitation_frame = timeout(std::time::Duration::from_secs(1), async {
            loop {
                let events = daemon
                    .mcp_sse_replay
                    .replay_after(session_id, None)
                    .await
                    .expect("read elicitation SSE replay");
                if let Some(request) = events.iter().rev().find_map(|event| {
                    serde_json::from_str::<JsonRpcRequest>(&event.data)
                        .ok()
                        .filter(|request| request.method == McpMethod::ElicitationCreate.as_str())
                }) {
                    break request;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("streamable elicitation request timeout");
        daemon
            .mcp_peer_transport
            .accept_response(
                session_id,
                &owner,
                JsonRpcResponse::success(
                    elicitation_frame.id,
                    json!({ "action": "accept", "content": { "confirmed": true } }),
                ),
            )
            .await
            .expect("accept streamable elicitation response");
        assert_eq!(
            elicitation
                .await
                .expect("streamable elicitation task")
                .expect("streamable elicitation response")
                .get("action"),
            Some(&json!("accept"))
        );
    }

    #[tokio::test]
    async fn daemon_legacy_http_sse_interoperates_with_the_outbound_host() {
        let daemon = AipDaemon::new(insecure_loopback_test_config())
            .await
            .expect("daemon");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("legacy listener");
        let address = listener.local_addr().expect("legacy address");
        let server = tokio::spawn(async move {
            axum::serve(listener, daemon.router())
                .await
                .expect("legacy getaip-server");
        });
        let transport =
            McpLegacyHttpSseClientTransport::new(format!("http://{address}/mcp/legacy/sse"))
                .expect("legacy transport");
        let mut config = McpClientConfig::new("getaip-server-legacy");
        config.protocol_version = "2024-11-05".to_owned();
        config.supported_versions = vec!["2024-11-05".to_owned()];
        let client = McpClient::new(config, Arc::new(transport));

        client.initialize().await.expect("legacy initialize");
        let tools = client.list_tools().await.expect("legacy tools/list");
        assert!(tools.iter().any(|tool| {
            tool.name.contains("health")
                || tool.title.as_deref().is_some_and(|title| title == "health")
        }));
        server.abort();
    }

    #[tokio::test]
    async fn daemon_mcp_http_enforces_configured_bearer_policy() {
        let daemon = AipDaemon::new(AipDaemonConfig {
            mcp_protected_resource: Some(McpProtectedResourceConfig::bearer(
                "https://aip.example/mcp",
                "unit-secret",
            )),
            allow_insecure_development: true,
            ..AipDaemonConfig::default()
        })
        .await
        .expect("daemon");
        let router = daemon.router();

        let metadata_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(metadata_response.status(), StatusCode::OK);
        let metadata_body = axum::body::to_bytes(metadata_response.into_body(), 64 * 1024)
            .await
            .expect("metadata body");
        let metadata = serde_json::from_slice::<Value>(&metadata_body).expect("metadata json");
        assert_eq!(
            metadata.pointer("/resource"),
            Some(&Value::String("https://aip.example/mcp".to_owned()))
        );

        let unauthorized = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/list"
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert!(
            unauthorized
                .headers()
                .get("www-authenticate")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("Bearer"))
        );

        let session = initialize_mcp_http(&router, Some("Bearer unit-secret")).await;
        let authorized = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer unit-secret")
                    .header("mcp-session-id", session.id)
                    .header("mcp-protocol-version", session.version)
                    .body(Body::from(
                        json!({
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/list"
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(authorized.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn daemon_mcp_oauth_rejects_invalid_claims_before_session_creation() {
        let mut policy = McpProtectedResourceConfig::bearer(
            "https://aip.example/mcp",
            "development-token-must-not-be-used",
        );
        policy.metadata.authorization_servers = vec!["https://issuer.example".to_owned()];
        policy.required_scope = Some("mcp:invoke".to_owned());
        policy.allowed_origins = vec!["https://console.example".to_owned()];
        policy.allow_loopback_origins = false;
        let daemon = AipDaemon::new(AipDaemonConfig {
            mcp_protected_resource: Some(policy),
            ..AipDaemonConfig::default()
        })
        .await
        .expect("daemon")
        .with_mcp_token_verifier(IntrospectionTokenVerifier::new(MatrixTokenIntrospector));
        let router = daemon.router();
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "oauth-test", "version": "1.0.0" }
            }
        })
        .to_string();

        let wrong_origin = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("origin", "https://attacker.example")
                    .header("authorization", "Bearer good")
                    .body(Body::from(initialize.clone()))
                    .expect("request"),
            )
            .await
            .expect("wrong-origin response");
        assert_eq!(wrong_origin.status(), StatusCode::FORBIDDEN);
        assert!(daemon.mcp_server.session_states().await.is_empty());

        for token in [
            "wrong-issuer",
            "wrong-audience",
            "missing-scope",
            "expired",
            "revoked",
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("origin", "https://console.example")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::from(initialize.clone()))
                        .expect("request"),
                )
                .await
                .expect("OAuth rejection response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "token={token}");
            assert!(
                daemon.mcp_server.session_states().await.is_empty(),
                "token={token} created a session before authorization"
            );
        }

        let accepted = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("origin", "https://console.example")
                    .header("authorization", "Bearer good")
                    .body(Body::from(initialize))
                    .expect("request"),
            )
            .await
            .expect("accepted OAuth response");
        assert_eq!(accepted.status(), StatusCode::OK);
        assert_eq!(daemon.mcp_server.session_states().await.len(), 1);
    }

    #[tokio::test]
    async fn daemon_signs_correlated_native_error_envelopes() {
        let client = Principal::new(
            PrincipalId::trusted("service:test:native-client"),
            PrincipalKind::Service,
        );
        let signer = CallbackSigner {
            principal: Principal::new(
                PrincipalId::trusted("service:test:native-server"),
                PrincipalKind::Service,
            ),
            signing_key: Arc::new(aip_crypto::signing_key_from_seed([73_u8; 32])),
        };
        let daemon = AipDaemon::new(AipDaemonConfig {
            native_http_auth: Some(NativeHttpAuthConfig::bearer(
                "native-client-secret",
                client.clone(),
            )),
            callback_policy: GatewayCallbackPolicy {
                signer: Some(signer.clone()),
                ..GatewayCallbackPolicy::default()
            },
            ..AipDaemonConfig::default()
        })
        .await
        .expect("daemon");
        let mut request = Envelope::new(MessageBody::Action(Box::new(Action::new(
            CapabilityId::trusted("cap:test:not-admitted"),
            json!({}),
        ))));
        request.from = Some(client.clone());
        request.session_id = Some(SessionId::new());
        request.correlation_id = Some(CorrelationId::new());
        let request_id = request.message_id.clone();
        let request_session = request.session_id.clone();
        let request_correlation = request.correlation_id.clone();
        let response = daemon
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/aip/v1/messages")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer native-client-secret")
                    .body(Body::from(
                        serde_json::to_vec(&request).expect("serialize request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_ne!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .expect("response body");
        let envelope = serde_json::from_slice::<Envelope>(&body).expect("error envelope");
        assert!(matches!(envelope.body, MessageBody::Error(_)));
        assert_eq!(
            envelope.in_response_to,
            Some(MessageReference::Message(request_id))
        );
        assert_eq!(envelope.session_id, request_session);
        assert_eq!(envelope.correlation_id, request_correlation);
        assert_eq!(envelope.to, Some(client));
        let verified_did =
            verify_native_envelope_signature(&envelope).expect("verify signed error envelope");
        assert_eq!(
            verified_did,
            aip_crypto::did_key_from_verifying_key(&signer.signing_key.verifying_key())
        );
    }

    #[tokio::test]
    async fn daemon_signs_correlated_native_success_envelopes() {
        let client = Principal::new(
            PrincipalId::trusted("service:test:native-success-client"),
            PrincipalKind::Service,
        );
        let signer = CallbackSigner {
            principal: Principal::new(
                PrincipalId::trusted("service:test:native-success-server"),
                PrincipalKind::Service,
            ),
            signing_key: Arc::new(aip_crypto::signing_key_from_seed([74_u8; 32])),
        };
        let daemon = AipDaemon::new(AipDaemonConfig {
            native_http_auth: Some(NativeHttpAuthConfig::bearer(
                "native-success-secret",
                client.clone(),
            )),
            callback_policy: GatewayCallbackPolicy {
                signer: Some(signer.clone()),
                ..GatewayCallbackPolicy::default()
            },
            ..AipDaemonConfig::default()
        })
        .await
        .expect("daemon");
        let mut request = Envelope::new(MessageBody::ManifestRequest(ManifestRequest {
            profiles: Vec::new(),
            filter: None,
        }));
        request.from = Some(client.clone());
        request.session_id = Some(SessionId::new());
        request.correlation_id = Some(CorrelationId::new());
        let request_id = request.message_id.clone();
        let request_session = request.session_id.clone();
        let request_correlation = request.correlation_id.clone();
        let response = daemon
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/aip/v1/messages")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer native-success-secret")
                    .body(Body::from(
                        serde_json::to_vec(&request).expect("serialize request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .expect("response body");
        let envelope = serde_json::from_slice::<Envelope>(&body).expect("success envelope");
        assert!(matches!(envelope.body, MessageBody::Manifest(_)));
        assert_eq!(
            envelope.in_response_to,
            Some(MessageReference::Message(request_id))
        );
        assert_eq!(envelope.session_id, request_session);
        assert_eq!(envelope.correlation_id, request_correlation);
        assert_eq!(envelope.to, Some(client));
        let verified_did =
            verify_native_envelope_signature(&envelope).expect("verify signed success envelope");
        assert_eq!(
            envelope.from.as_ref().and_then(|from| from.did.as_deref()),
            Some(verified_did.as_str())
        );
    }

    #[tokio::test]
    async fn daemon_mcp_sse_replays_events_from_durable_storage() {
        let storage_dir = std::env::temp_dir().join(format!(
            "getaip-server-mcp-sse-replay-{}-{}",
            std::process::id(),
            time_suffix()
        ));
        let first = AipDaemon::new(AipDaemonConfig {
            storage_dir: Some(storage_dir.clone()),
            allow_insecure_development: true,
            ..AipDaemonConfig::default()
        })
        .await
        .expect("first daemon");
        let first_router = first.router();
        let session = initialize_mcp_http(&first_router, None).await;
        let first_event = first
            .publish_mcp_sse_event(&session.id, crate::McpSseEvent {
                id: None,
                event: Some("message".to_owned()),
                data: json!({ "jsonrpc": "2.0", "method": "notifications/progress", "params": { "progressToken": "one", "progress": 1 } }).to_string(),
            })
            .await
            .expect("first event");
        assert_eq!(first_event.id.as_deref(), Some("0"));
        let second_event = first
            .publish_mcp_sse_event(&session.id, crate::McpSseEvent {
                id: None,
                event: Some("message".to_owned()),
                data: json!({ "jsonrpc": "2.0", "method": "notifications/progress", "params": { "progressToken": "two", "progress": 2 } }).to_string(),
            })
            .await
            .expect("second event");
        assert_eq!(second_event.id.as_deref(), Some("1"));
        drop(first);

        let second = AipDaemon::new(AipDaemonConfig {
            storage_dir: Some(storage_dir.clone()),
            allow_insecure_development: true,
            ..AipDaemonConfig::default()
        })
        .await
        .expect("second daemon");
        let replay_response = second
            .router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/mcp")
                    .header("last-event-id", "0")
                    .header("mcp-session-id", session.id)
                    .header("mcp-protocol-version", session.version)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("replay response");
        assert_eq!(replay_response.status(), StatusCode::OK);
        let mut replay_stream = replay_response.into_body().into_data_stream();
        let replay_body =
            tokio::time::timeout(std::time::Duration::from_secs(1), replay_stream.next())
                .await
                .expect("replay frame timeout")
                .expect("replay frame")
                .expect("replay body");
        let replay_text = String::from_utf8(replay_body.to_vec()).expect("utf8");
        assert!(replay_text.contains("id: 1"));
        assert!(replay_text.contains("progressToken"));
        assert!(!replay_text.contains("server/discover"));
        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[tokio::test]
    async fn daemon_a2a_v1_send_and_get_use_authenticated_gateway_runtime() {
        let mut actor = Principal::new(
            PrincipalId::trusted("service:test:a2a-client"),
            PrincipalKind::Service,
        );
        actor.auth_context = Some(json!({ "scopes": ["action:read", "action:write"] }));
        let daemon = AipDaemon::new(AipDaemonConfig {
            native_http_auth: Some(NativeHttpAuthConfig::bearer("a2a-secret", actor)),
            ..AipDaemonConfig::default()
        })
        .await
        .expect("daemon");
        let router = daemon.router();
        let unauthorized = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/a2a/v1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "jsonrpc": "2.0",
                            "id": 0,
                            "method": "GetTask",
                            "params": { "id": "missing" }
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("unauthorized response");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let send_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/a2a/v1")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer a2a-secret")
                    .body(Body::from(
                        json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "SendMessage",
                            "params": {
                                "message": {
                                    "messageId": "message-health",
                                    "taskId": "task-health",
                                    "contextId": "context-health",
                                    "role": "ROLE_USER",
                                    "parts": [{ "data": {} }],
                                    "metadata": {
                                        "aip": { "capability_id": HEALTH_CAPABILITY_ID }
                                    }
                                },
                                "metadata": {
                                    "aip": {
                                        "capability_id": HEALTH_CAPABILITY_ID,
                                        "input": {}
                                    }
                                }
                            }
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("send response");
        assert_eq!(send_response.status(), StatusCode::OK);
        let send_body = axum::body::to_bytes(send_response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let send_payload = serde_json::from_slice::<Value>(&send_body).expect("json");
        assert_eq!(
            send_payload
                .pointer("/result/task/status/state")
                .and_then(Value::as_str),
            Some("TASK_STATE_COMPLETED"),
            "{send_payload}"
        );

        let get_response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/a2a/v1")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer a2a-secret")
                    .body(Body::from(
                        json!({
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "GetTask",
                            "params": { "id": "task-health" }
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("get response");
        assert_eq!(get_response.status(), StatusCode::OK);
        let get_body = axum::body::to_bytes(get_response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let get_payload = serde_json::from_slice::<Value>(&get_body).expect("json");
        assert_eq!(
            get_payload.pointer("/result/id").and_then(Value::as_str),
            Some("task-health")
        );
    }

    #[tokio::test]
    async fn a2a_push_config_survives_restart_and_delivers_once_without_plaintext_secrets() {
        let capture = PushCapture::default();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("push listener");
        let address = listener.local_addr().expect("push address");
        let app = Router::new()
            .route("/push", post(capture_push))
            .with_state(capture.clone());
        let receiver = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("push receiver");
        });
        let actor = Principal::new(
            PrincipalId::trusted("service:test:a2a-push-client"),
            PrincipalKind::Service,
        );
        let mut allowed_hosts = HashSet::new();
        allowed_hosts.insert("127.0.0.1".to_owned());
        let callback_policy = GatewayCallbackPolicy {
            allowed_hosts,
            allow_http: true,
            allow_private_networks: true,
            tls_ca_certificate_pem: None,
            request_timeout_ms: 2_000,
            max_response_bytes: 4 * 1024 * 1024,
            signer: Some(CallbackSigner {
                principal: Principal::new(
                    PrincipalId::trusted("service:test:a2a-push-signer"),
                    PrincipalKind::Service,
                ),
                signing_key: Arc::new(aip_crypto::signing_key_from_seed([31_u8; 32])),
            }),
            a2a_credential_key: Some(A2aCallbackCredentialKey::new([47_u8; 32])),
        };
        let storage_dir = std::env::temp_dir().join(format!(
            "getaip-server-a2a-push-{}-{}",
            std::process::id(),
            time_suffix()
        ));
        let config = AipDaemonConfig {
            native_http_auth: Some(NativeHttpAuthConfig::bearer(
                "a2a-push-secret",
                actor.clone(),
            )),
            callback_policy,
            storage_dir: Some(storage_dir.clone()),
            ..AipDaemonConfig::default()
        };
        let first = AipDaemon::new(config.clone()).await.expect("first daemon");
        let response = first
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/a2a/v1")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer a2a-push-secret")
                    .header("a2a-version", "1.0")
                    .body(Body::from(
                        json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "SendMessage",
                            "params": {
                                "message": {
                                    "messageId": "message-push-health",
                                    "taskId": "task-push-health",
                                    "contextId": "context-push-health",
                                    "role": "ROLE_USER",
                                    "parts": [{ "data": {} }]
                                },
                                "configuration": {
                                    "taskPushNotificationConfig": {
                                        "id": "push-config-1",
                                        "taskId": "",
                                        "url": format!("http://{address}/push"),
                                        "token": "plain-verification-token",
                                        "authentication": {
                                            "scheme": "Bearer",
                                            "credentials": "plain-auth-secret"
                                        }
                                    }
                                },
                                "metadata": {
                                    "aip": {
                                        "capability_id": HEALTH_CAPABILITY_ID,
                                        "input": {}
                                    }
                                }
                            }
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("send response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("send body");
        let payload: Value = serde_json::from_slice(&body).expect("send JSON");
        assert_eq!(
            payload.pointer("/result/task/status/state"),
            Some(&json!("TASK_STATE_COMPLETED")),
            "{payload}"
        );
        let persisted = std::fs::read_to_string(storage_dir.join("profile_state.json"))
            .expect("durable profile state");
        assert!(!persisted.contains("plain-verification-token"));
        assert!(!persisted.contains("plain-auth-secret"));
        drop(first);

        let second = AipDaemon::new(config).await.expect("restarted daemon");
        dispatch_a2a_push_updates(
            &second.gateway.runtime(),
            "getaip-server-test-worker",
            &second.manifest.agent,
        )
        .await
        .expect("push delivery after restart");
        dispatch_a2a_push_updates(
            &second.gateway.runtime(),
            "getaip-server-test-worker",
            &second.manifest.agent,
        )
        .await
        .expect("idempotent second worker pass");
        let deliveries = capture.0.lock().await.clone();
        assert_eq!(deliveries.len(), 1, "cursor must suppress duplicate pushes");
        let (headers, payload) = &deliveries[0];
        assert_eq!(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer plain-auth-secret")
        );
        assert_eq!(
            payload.pointer("/statusUpdate/status/state"),
            Some(&json!("TASK_STATE_COMPLETED"))
        );
        receiver.abort();
        let _ = std::fs::remove_dir_all(storage_dir);
    }

    fn time_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    }
}
