//! Hermes Agent connector for Agent Interoperability Protocol.
//!
//! The connector treats each Hermes API server instance as an AIP participant
//! endpoint and publishes one AIP capability for each stable Hermes API
//! operation. The implementation is intentionally HTTP-native because Hermes'
//! API server already exposes an OpenAI-compatible control surface plus
//! Hermes-specific session and run lifecycle routes.
//!
//! Supported Hermes routes include:
//!
//! - readiness and detailed health checks;
//! - model, capability, skill, and toolset discovery;
//! - OpenAI-compatible Chat Completions and Responses APIs;
//! - Hermes structured runs, run events, stop, and approval resolution;
//! - persisted session resources and session-scoped chat operations.
//! - governed operator runs and connector-owned AIP delegation routing.
//!
//! The connector implements outbound invocation, inbound AIP envelope mapping,
//! result emission into Hermes sessions, and escalation prompts. Runtime-injected
//! AIP context is forwarded through `X-AIP-Session-Id`,
//! `X-AIP-Correlation-Id`, and `X-AIP-Delegation-Chain` headers for deployments
//! that run Hermes as an AIP peer or sidecar. Operator routing is disabled by
//! default and requires explicit allowlists plus durable AIP approval
//! verification unless deployment policy deliberately disables that check.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

mod operator;

pub use operator::{
    HERMES_OPERATOR_STATE_NAMESPACE, HermesDelegatedResultExpectation,
    HermesDelegatedResultResolver, HermesOperatorApprovalCommand, HermesOperatorCommandStatus,
    HermesOperatorPolicy, HermesOperatorRunBinding, HermesOperatorRunStatus,
    HermesOperatorStartClaim, RuntimeHermesDelegatedResultResolver,
};

use aip_connector::{
    CapabilityImplementationSupport, CapabilityProviderConnector, ChannelConnector, Connector,
    ConnectorContext, ConnectorError, ConnectorFailure, ConnectorHealth, ConnectorOperation,
    ConnectorResult, ConnectorSecret, EscalationConnector, FrozenConnector, InboundConnector,
    OutboundConnector,
};
use aip_core::{
    Action, ActionId, ActionResult, ActionResultStatus, ApprovalPolicy, ApproverSelector, Binding,
    Capability, CapabilityContract, CapabilityId, CapabilityKind, CompensationContract,
    CompensationMode, DataContract, DataSensitivity, DelegationRequest, Envelope, ErrorCategory,
    Escalation, EvidenceRequirement, ExecutionContract, ExpectedCompletionMode,
    IdempotencyCollisionBehavior, IdempotencyContract, IdempotencyKeyScope, IdempotencyRequirement,
    Manifest, MessageBody, MessagePart, Principal, PrincipalId, PrincipalKind, ProfileId,
    ProtocolError, RetrySafety, RiskLevel, ServiceLevelContract, SideEffect, Stability,
    StreamChunk, StreamChunkKind,
};
use aip_runtime::{
    ActionExecutionContext, ActionHandler, ActionStream, ApprovalStatus, ApprovalStore,
    ProfileStateStore, RuntimeError, RuntimeResult,
};
use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, sync::Arc};
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;

/// Stable connector id used by registries and gateways.
pub const CONNECTOR_ID: &str = "hermes-agent";

/// AIP profile id for Hermes Agent-specific binding metadata.
pub const PROFILE_ID: &str = "aip.connector.hermes_agent.v1";
/// Exact Hermes Agent revision used to freeze the native API-server matrix.
pub const UPSTREAM_REVISION: &str = "7426c09beee73bdff94d916015bac71384f6bc92";

const CAPABILITY_PREFIX: &str = "cap:hermes_agent:";
const DEFAULT_CHAT_MODEL: &str = "hermes-agent";
const DEFAULT_SSE_EVENT_LIMIT: usize = 4096;
const MAX_SSE_EVENT_LIMIT: usize = 100_000;
const DEFAULT_MAX_JSON_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_STREAM_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_SSE_FRAME_BYTES: usize = 1024 * 1024;
const MAX_CONFIGURED_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUEST_URL_BYTES: usize = 128 * 1024;
const MAX_OUTBOUND_HEADER_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
struct StreamPublication {
    action_id: ActionId,
    stream: ActionStream,
}

struct SseExecutionOptions<'a> {
    headers: Option<StandardHeaders>,
    max_events: Option<usize>,
    publication: Option<&'a StreamPublication>,
}

#[derive(Clone, Copy, Debug)]
struct SseResponseLimits {
    stream_bytes: usize,
    frame_bytes: usize,
}

const HERMES_ACTION_KINDS: &[HermesActionKind] = &[
    HermesActionKind::Health,
    HermesActionKind::HealthDetailed,
    HermesActionKind::Models,
    HermesActionKind::ApiCapabilities,
    HermesActionKind::Skills,
    HermesActionKind::Toolsets,
    HermesActionKind::Chat,
    HermesActionKind::ChatStream,
    HermesActionKind::Responses,
    HermesActionKind::ResponsesStream,
    HermesActionKind::ResponseGet,
    HermesActionKind::ResponseDelete,
    HermesActionKind::RunStart,
    HermesActionKind::RunStatus,
    HermesActionKind::RunEvents,
    HermesActionKind::RunApproval,
    HermesActionKind::RunStop,
    HermesActionKind::Operator,
    HermesActionKind::SessionsList,
    HermesActionKind::SessionCreate,
    HermesActionKind::SessionGet,
    HermesActionKind::SessionPatch,
    HermesActionKind::SessionDelete,
    HermesActionKind::SessionMessages,
    HermesActionKind::SessionFork,
    HermesActionKind::SessionChat,
    HermesActionKind::SessionChatStream,
    HermesActionKind::JobsList,
    HermesActionKind::JobCreate,
    HermesActionKind::JobGet,
    HermesActionKind::JobUpdate,
    HermesActionKind::JobDelete,
    HermesActionKind::JobPause,
    HermesActionKind::JobResume,
    HermesActionKind::JobRun,
];

/// Hermes API server endpoint registered with the connector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HermesAgentEndpoint {
    /// Stable endpoint id used in generated capability ids.
    pub id: String,
    /// Base URL of the Hermes API server, for example `http://hermes-a:8642`.
    pub base_url: Url,
    /// Bearer token configured as `API_SERVER_KEY` on the Hermes side.
    #[serde(
        default,
        skip_serializing,
        deserialize_with = "deserialize_optional_secret"
    )]
    pub api_key: Option<ConnectorSecret>,
    /// Human-readable endpoint label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Verified AIP tenant that owns this Hermes endpoint.
    ///
    /// When configured, frozen connector invocations fail closed unless the
    /// runtime supplies a matching `VerifiedTenant`. This binds a
    /// provider account to the same tenant partition used by AIP policy and
    /// prevents a capability-routing mistake from crossing provider accounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

impl HermesAgentEndpoint {
    /// Creates an endpoint descriptor from user-supplied configuration.
    pub fn new(
        id: impl Into<String>,
        base_url: impl AsRef<str>,
        api_key: Option<String>,
    ) -> Result<Self, HermesAgentError> {
        let id = normalize_endpoint_id(id.into())?;
        let base_url = Url::parse(base_url.as_ref()).map_err(HermesAgentError::InvalidUrl)?;
        validate_endpoint_base_url(&base_url)?;
        let endpoint = Self {
            id,
            base_url,
            api_key: None,
            display_name: None,
            tenant_id: None,
        };
        match api_key {
            Some(api_key) => endpoint.with_api_key_secret(ConnectorSecret::from(api_key)),
            None => Ok(endpoint),
        }
    }

    /// Sets a human-readable endpoint label.
    #[must_use]
    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    /// Sets a protected endpoint API key after applying the same validation as
    /// constructor-supplied credentials.
    pub fn with_api_key_secret(
        mut self,
        api_key: ConnectorSecret,
    ) -> Result<Self, HermesAgentError> {
        validate_hermes_api_key(&api_key, &self.id)?;
        self.api_key = Some(api_key);
        Ok(self)
    }

    /// Binds this provider endpoint to one verified AIP tenant.
    pub fn with_tenant_id(
        mut self,
        tenant_id: impl Into<String>,
    ) -> Result<Self, HermesAgentError> {
        let tenant_id = tenant_id.into();
        validate_tenant_id(&tenant_id)?;
        self.tenant_id = Some(tenant_id);
        Ok(self)
    }

    /// Returns the AIP capability id for a Hermes operation.
    pub fn capability_id(&self, kind: HermesActionKind) -> Result<CapabilityId, HermesAgentError> {
        capability_id(&self.id, kind.operation())
    }

    /// Returns the AIP capability id for the endpoint health check.
    pub fn health_capability_id(&self) -> Result<CapabilityId, HermesAgentError> {
        self.capability_id(HermesActionKind::Health)
    }

    /// Returns the AIP capability id for the endpoint chat operation.
    pub fn chat_capability_id(&self) -> Result<CapabilityId, HermesAgentError> {
        self.capability_id(HermesActionKind::Chat)
    }

    /// Returns the AIP capability id for the endpoint streaming chat operation.
    pub fn chat_stream_capability_id(&self) -> Result<CapabilityId, HermesAgentError> {
        self.capability_id(HermesActionKind::ChatStream)
    }
}

fn deserialize_optional_secret<'de, D>(deserializer: D) -> Result<Option<ConnectorSecret>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.map(ConnectorSecret::from))
}

/// Connector implementation for one or more Hermes Agent API servers.
#[derive(Clone)]
pub struct HermesAgentConnector {
    endpoints: BTreeMap<String, HermesAgentEndpoint>,
    client: reqwest::Client,
    operator_policy: HermesOperatorPolicy,
    operator_state: ProfileStateStore,
    operator_approvals: Option<ApprovalStore>,
    operator_result_resolver: Option<Arc<dyn HermesDelegatedResultResolver>>,
    operator_instance_id: String,
    max_json_response_bytes: usize,
    max_stream_response_bytes: usize,
    max_sse_frame_bytes: usize,
}

impl std::fmt::Debug for HermesAgentConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HermesAgentConnector")
            .field("endpoints", &self.endpoints)
            .field("operator_policy", &self.operator_policy)
            .field("operator_state", &"ProfileStateStore(..)")
            .field("operator_approvals", &self.operator_approvals.is_some())
            .field(
                "operator_result_resolver",
                &self.operator_result_resolver.is_some(),
            )
            .field("operator_instance_id", &"redacted")
            .field("max_json_response_bytes", &self.max_json_response_bytes)
            .field("max_stream_response_bytes", &self.max_stream_response_bytes)
            .field("max_sse_frame_bytes", &self.max_sse_frame_bytes)
            .finish_non_exhaustive()
    }
}

impl HermesAgentConnector {
    /// Creates a connector with the default HTTP client.
    pub fn new(endpoints: Vec<HermesAgentEndpoint>) -> Result<Self, HermesAgentError> {
        let client = reqwest::Client::builder()
            .user_agent(concat!(
                "aip-connector-hermes-agent/",
                env!("CARGO_PKG_VERSION")
            ))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(900))
            .build()
            .map_err(HermesAgentError::HttpClient)?;
        Self::with_client(endpoints, client)
    }

    /// Creates a connector with an injected HTTP client.
    pub fn with_client(
        endpoints: Vec<HermesAgentEndpoint>,
        client: reqwest::Client,
    ) -> Result<Self, HermesAgentError> {
        let mut by_id = BTreeMap::new();
        for endpoint in endpoints {
            validate_endpoint_descriptor(&endpoint)?;
            if by_id.insert(endpoint.id.clone(), endpoint).is_some() {
                return Err(HermesAgentError::DuplicateEndpoint);
            }
        }
        if by_id.is_empty() {
            return Err(HermesAgentError::NoEndpoints);
        }
        Ok(Self {
            endpoints: by_id,
            client,
            operator_policy: HermesOperatorPolicy::default(),
            operator_state: ProfileStateStore::default(),
            operator_approvals: None,
            operator_result_resolver: None,
            operator_instance_id: uuid::Uuid::now_v7().to_string(),
            max_json_response_bytes: DEFAULT_MAX_JSON_RESPONSE_BYTES,
            max_stream_response_bytes: DEFAULT_MAX_STREAM_RESPONSE_BYTES,
            max_sse_frame_bytes: DEFAULT_MAX_SSE_FRAME_BYTES,
        })
    }

    /// Overrides the bounded response limits used for JSON bodies, complete
    /// streams, and individual SSE frames.
    pub fn with_response_limits(
        mut self,
        max_json_response_bytes: usize,
        max_stream_response_bytes: usize,
        max_sse_frame_bytes: usize,
    ) -> Result<Self, HermesAgentError> {
        if !(1..=MAX_CONFIGURED_RESPONSE_BYTES).contains(&max_json_response_bytes) {
            return Err(HermesAgentError::InvalidResponseLimits(
                "JSON response limit is outside the supported range".to_owned(),
            ));
        }
        if !(1..=MAX_CONFIGURED_RESPONSE_BYTES).contains(&max_stream_response_bytes) {
            return Err(HermesAgentError::InvalidResponseLimits(
                "stream response limit is outside the supported range".to_owned(),
            ));
        }
        if !(1..=max_stream_response_bytes).contains(&max_sse_frame_bytes) {
            return Err(HermesAgentError::InvalidResponseLimits(
                "SSE frame limit must not exceed the stream response limit".to_owned(),
            ));
        }
        self.max_json_response_bytes = max_json_response_bytes;
        self.max_stream_response_bytes = max_stream_response_bytes;
        self.max_sse_frame_bytes = max_sse_frame_bytes;
        Ok(self)
    }

    /// Replaces the validated policy used by Hermes operator capabilities and
    /// AIP delegation routing.
    pub fn with_operator_policy(
        mut self,
        policy: HermesOperatorPolicy,
    ) -> Result<Self, HermesAgentError> {
        policy.validate()?;
        self.operator_policy = policy;
        Ok(self)
    }

    /// Uses the runtime-owned profile state backend for durable Hermes run
    /// correlation. In production this should be the same Postgres-backed
    /// store used by the AIP runtime and delegation outbox.
    #[must_use]
    pub fn with_profile_state_store(mut self, store: ProfileStateStore) -> Self {
        self.operator_state = store;
        self
    }

    /// Uses the runtime-owned approval backend to verify delegated operator
    /// authority. This is required when operator delegation approval is enabled.
    #[must_use]
    pub fn with_approval_store(mut self, store: ApprovalStore) -> Self {
        self.operator_approvals = Some(store);
        self
    }

    /// Uses an authoritative native AIP result resolver for first-class Hermes
    /// delegation. Production delegation routing requires this boundary; model
    /// final text is never accepted as a delegated business result.
    #[must_use]
    pub fn with_delegated_result_resolver<R>(mut self, resolver: R) -> Self
    where
        R: HermesDelegatedResultResolver + 'static,
    {
        self.operator_result_resolver = Some(Arc::new(resolver));
        self
    }

    /// Returns configured endpoints keyed by endpoint id.
    #[must_use]
    pub fn endpoints(&self) -> &BTreeMap<String, HermesAgentEndpoint> {
        &self.endpoints
    }

    /// Builds an AIP manifest exposing every configured Hermes endpoint.
    pub fn discover_manifest(&self) -> Result<Manifest, HermesAgentError> {
        let mut capabilities = Vec::with_capacity(self.endpoints.len() * HERMES_ACTION_KINDS.len());
        for endpoint in self.endpoints.values() {
            for kind in HERMES_ACTION_KINDS {
                capabilities.push(capability(endpoint, *kind)?);
            }
        }
        Ok(Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(
                PrincipalId::parse("agent:hermes_agent:connector")
                    .map_err(HermesAgentError::InvalidId)?,
                PrincipalKind::Agent,
            ),
            capabilities,
            profiles: vec![
                ProfileId::from("aip.native.http.v1"),
                ProfileId::from("aip.native.sse.v1"),
                ProfileId::from(PROFILE_ID),
            ],
            resources: Vec::new(),
            channels: Vec::new(),
            security: Some(json!({
                "transport": "http",
                "auth": "per-endpoint bearer token for protected Hermes routes",
                "tenant_binding": "optional verified AIP tenant per endpoint",
                "session_continuity_header": "X-Hermes-Session-Id",
                "session_key_header": "X-Hermes-Session-Key"
            })),
            governance: None,
            limits: Some(json!({
                "default_sse_event_limit": DEFAULT_SSE_EVENT_LIMIT,
                "maximum_sse_event_limit": MAX_SSE_EVENT_LIMIT,
                "max_json_response_bytes": self.max_json_response_bytes,
                "max_stream_response_bytes": self.max_stream_response_bytes,
                "max_sse_frame_bytes": self.max_sse_frame_bytes,
                "max_request_body_bytes": MAX_REQUEST_BODY_BYTES,
                "max_request_url_bytes": MAX_REQUEST_URL_BYTES
            })),
            compatibility: Some(json!({
                "system": "hermes-agent",
                "upstream_revision": UPSTREAM_REVISION,
                "api": "openai-compatible plus hermes session/run lifecycle",
                "endpoints": self.endpoints.keys().collect::<Vec<_>>(),
                "tenant_bound_endpoints": self.endpoints.values().filter_map(|endpoint| {
                    endpoint.tenant_id.as_ref().map(|tenant_id| json!({
                        "endpoint_id": endpoint.id,
                        "tenant_id": tenant_id
                    }))
                }).collect::<Vec<_>>(),
                "operations": HERMES_ACTION_KINDS
                    .iter()
                    .map(|kind| kind.operation())
                    .collect::<Vec<_>>(),
                "operator_principals": self.endpoints.keys().map(|endpoint_id| {
                    operator::operator_principal_id(endpoint_id).to_string()
                }).collect::<Vec<_>>(),
                "operator_delegation_enabled": self.operator_policy.delegation_enabled
            })),
            extensions: None,
        })
    }

    /// Resolves an AIP capability id to a Hermes endpoint and action kind.
    #[must_use]
    pub fn endpoint_for_capability(
        &self,
        capability_id: &CapabilityId,
    ) -> Option<(&HermesAgentEndpoint, HermesActionKind)> {
        let raw = capability_id.as_str().strip_prefix(CAPABILITY_PREFIX)?;
        let (endpoint_id, operation) = raw.rsplit_once(':')?;
        let kind = HermesActionKind::from_operation(operation)?;
        self.endpoints
            .get(endpoint_id)
            .map(|endpoint| (endpoint, kind))
    }

    /// Calls `GET /health` for the selected Hermes endpoint.
    pub async fn health(&self, endpoint_id: &str) -> Result<HermesHealth, HermesAgentError> {
        let endpoint = self.endpoint(endpoint_id)?;
        let url = endpoint_url(endpoint, "/health")?;
        let response = self
            .client
            .get(url)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|source| HermesAgentError::HttpRequest {
                endpoint_id: endpoint.id.clone(),
                source,
            })?;
        let http_status = response.status();
        let raw = response_body_value(response, &endpoint.id, self.max_json_response_bytes).await?;
        if !http_status.is_success() {
            return Err(HermesAgentError::UnexpectedStatus {
                endpoint_id: endpoint.id.clone(),
                status: http_status.as_u16(),
                body: raw,
            });
        }
        Ok(HermesHealth {
            endpoint_id: endpoint.id.clone(),
            status: json_string(&raw, "status").unwrap_or_else(|| "unknown".to_owned()),
            platform: json_string(&raw, "platform"),
            version: json_string(&raw, "version"),
            http_status: http_status.as_u16(),
            raw,
        })
    }

    /// Calls `GET /health/detailed` for the selected Hermes endpoint.
    pub async fn health_detailed(&self, endpoint_id: &str) -> Result<Value, HermesAgentError> {
        self.execute_json(
            endpoint_id,
            HermesActionKind::HealthDetailed,
            json!({}),
            None,
        )
        .await
    }

    /// Calls `GET /v1/models` for the selected Hermes endpoint.
    pub async fn models(&self, endpoint_id: &str) -> Result<Value, HermesAgentError> {
        self.execute_json(endpoint_id, HermesActionKind::Models, json!({}), None)
            .await
    }

    /// Calls Hermes' OpenAI-compatible chat completions endpoint.
    pub async fn chat(
        &self,
        endpoint_id: &str,
        request: HermesChatRequest,
    ) -> Result<Value, HermesAgentError> {
        let payload = build_chat_payload(&request, false)?;
        let path_input = payload.clone();
        self.execute_json_with_body(
            endpoint_id,
            HermesActionKind::Chat,
            &path_input,
            payload,
            Some(StandardHeaders::from_chat_request(&request)),
        )
        .await
    }

    /// Calls Hermes' streaming chat completions endpoint and aggregates SSE events.
    pub async fn chat_stream(
        &self,
        endpoint_id: &str,
        request: HermesChatRequest,
        max_events: Option<usize>,
    ) -> Result<HermesStreamResult, HermesAgentError> {
        let payload = build_chat_payload(&request, true)?;
        let path_input = payload.clone();
        self.execute_sse_with_body(
            endpoint_id,
            HermesActionKind::ChatStream,
            &path_input,
            payload,
            SseExecutionOptions {
                headers: Some(StandardHeaders::from_chat_request(&request)),
                max_events,
                publication: None,
            },
        )
        .await
    }

    async fn invoke_operation(
        &self,
        endpoint_id: &str,
        kind: HermesActionKind,
        input: Value,
        action: Option<&Action>,
        execution: Option<&ActionExecutionContext>,
        publication: Option<&StreamPublication>,
    ) -> Result<ActionOutput, HermesAgentError> {
        let aip_context = action
            .and_then(|action| action.memory_context.as_ref())
            .and_then(aip_context_from_memory);
        let trusted_headers = |mut headers: StandardHeaders| {
            if let (Some(action), Some(execution)) = (action, execution) {
                headers.apply_execution(action, execution);
            }
            headers
        };
        match kind {
            HermesActionKind::Operator => Err(HermesAgentError::InvalidInput(
                "operator actions require the governed operator lifecycle".to_owned(),
            )),
            HermesActionKind::Health => self.health(endpoint_id).await.map(ActionOutput::Health),
            HermesActionKind::Chat => {
                let request = chat_request_from_input(input)?;
                let payload = build_chat_payload(&request, false)?;
                let path_input = payload.clone();
                self.execute_json_with_body(
                    endpoint_id,
                    HermesActionKind::Chat,
                    &path_input,
                    payload,
                    Some(trusted_headers(
                        StandardHeaders::from_chat_request_with_aip(&request, aip_context),
                    )),
                )
                .await
                .map(ActionOutput::Json)
            }
            HermesActionKind::ChatStream => {
                let max_events = max_events_from_input(&input)?;
                let request = chat_request_from_input(input)?;
                let payload = build_chat_payload(&request, true)?;
                let path_input = payload.clone();
                self.execute_sse_with_body(
                    endpoint_id,
                    HermesActionKind::ChatStream,
                    &path_input,
                    payload,
                    SseExecutionOptions {
                        headers: Some(trusted_headers(
                            StandardHeaders::from_chat_request_with_aip(&request, aip_context),
                        )),
                        max_events,
                        publication,
                    },
                )
                .await
                .map(|stream| ActionOutput::Stream(Box::new(stream)))
            }
            HermesActionKind::ResponsesStream
            | HermesActionKind::RunEvents
            | HermesActionKind::SessionChatStream => {
                let max_events = max_events_from_input(&input)?;
                let headers = Some(trusted_headers(StandardHeaders::from_input_with_aip(
                    &input,
                    aip_context,
                )));
                self.execute_sse(endpoint_id, kind, input, headers, max_events, publication)
                    .await
                    .map(|stream| ActionOutput::Stream(Box::new(stream)))
            }
            other => {
                let headers = Some(trusted_headers(StandardHeaders::from_input_with_aip(
                    &input,
                    aip_context,
                )));
                self.execute_json(endpoint_id, other, input, headers)
                    .await
                    .map(ActionOutput::Json)
            }
        }
    }

    async fn invoke_action_with_execution(
        &self,
        action: Action,
        execution: ActionExecutionContext,
    ) -> Result<ActionResult, HermesAgentError> {
        let Some((endpoint, kind)) = self.endpoint_for_capability(&action.capability_id) else {
            return Err(HermesAgentError::UnsupportedCapability(
                action.capability_id.to_string(),
            ));
        };
        validate_execution_boundary(endpoint, &execution)?;
        let remaining = execution.deadline.remaining(OffsetDateTime::now_utc());
        if remaining.is_zero() {
            return Err(HermesAgentError::DeadlineExceeded);
        }
        if kind == HermesActionKind::Operator {
            return tokio::select! {
                biased;
                () = execution.cancellation.cancelled() => Err(HermesAgentError::Cancelled),
                () = tokio::time::sleep(remaining) => Err(HermesAgentError::DeadlineExceeded),
                result = self.invoke_operator_action(&endpoint.id, action, Some(&execution)) => result,
            };
        }
        let publication = kind_streams(kind).then(|| StreamPublication {
            action_id: action.id.clone(),
            stream: execution.stream.clone(),
        });
        let input = action_input_with_transport_metadata(&action);
        let invocation = self.invoke_operation(
            &endpoint.id,
            kind,
            input,
            Some(&action),
            Some(&execution),
            publication.as_ref(),
        );
        let output = tokio::select! {
            biased;
            () = execution.cancellation.cancelled() => {
                return Err(HermesAgentError::Cancelled);
            }
            () = tokio::time::sleep(remaining) => {
                return Err(HermesAgentError::DeadlineExceeded);
            }
            result = invocation => result,
        }?;
        Ok(action_output_result(action, output))
    }

    async fn execute_json(
        &self,
        endpoint_id: &str,
        kind: HermesActionKind,
        input: Value,
        headers: Option<StandardHeaders>,
    ) -> Result<Value, HermesAgentError> {
        let body = body_for_kind(kind, &input)?;
        self.execute_json_with_body(endpoint_id, kind, &input, body, headers)
            .await
    }

    async fn execute_json_with_body(
        &self,
        endpoint_id: &str,
        kind: HermesActionKind,
        path_input: &Value,
        body: Value,
        headers: Option<StandardHeaders>,
    ) -> Result<Value, HermesAgentError> {
        let endpoint = self.endpoint(endpoint_id)?;
        let path = path_for_kind(kind, path_input)?;
        let url =
            endpoint_url_with_query(endpoint, &path, query_pairs_for_kind(kind, path_input)?)?;
        let mut builder = self.client.request(kind.method(), url);
        builder = builder.timeout(json_request_timeout(kind));
        builder = apply_auth(builder, endpoint, kind.auth_required())?;
        builder = apply_standard_headers(builder, headers.unwrap_or_default())?;
        if kind.sends_body() {
            let body = http_body_for_kind(kind, body);
            ensure_hermes_request_size(&body)?;
            builder = builder.json(&body);
        }
        let response = builder
            .send()
            .await
            .map_err(|source| HermesAgentError::HttpRequest {
                endpoint_id: endpoint.id.clone(),
                source,
            })?;
        let http_status = response.status();
        let response_body =
            response_body_value(response, &endpoint.id, self.max_json_response_bytes).await?;
        if !http_status.is_success() {
            return Err(HermesAgentError::UnexpectedStatus {
                endpoint_id: endpoint.id.clone(),
                status: http_status.as_u16(),
                body: response_body,
            });
        }
        Ok(response_body)
    }

    async fn execute_sse(
        &self,
        endpoint_id: &str,
        kind: HermesActionKind,
        input: Value,
        headers: Option<StandardHeaders>,
        max_events: Option<usize>,
        publication: Option<&StreamPublication>,
    ) -> Result<HermesStreamResult, HermesAgentError> {
        let body = body_for_kind(kind, &input)?;
        self.execute_sse_with_body(
            endpoint_id,
            kind,
            &input,
            body,
            SseExecutionOptions {
                headers,
                max_events,
                publication,
            },
        )
        .await
    }

    async fn execute_sse_with_body(
        &self,
        endpoint_id: &str,
        kind: HermesActionKind,
        path_input: &Value,
        body: Value,
        options: SseExecutionOptions<'_>,
    ) -> Result<HermesStreamResult, HermesAgentError> {
        let endpoint = self.endpoint(endpoint_id)?;
        let path = path_for_kind(kind, path_input)?;
        let url =
            endpoint_url_with_query(endpoint, &path, query_pairs_for_kind(kind, path_input)?)?;
        let mut builder = self.client.request(kind.method(), url);
        builder = apply_auth(builder, endpoint, kind.auth_required())?;
        builder = apply_standard_headers(builder, options.headers.unwrap_or_default())?;
        builder = builder.header("Accept", "text/event-stream");
        if kind.sends_body() {
            let body = http_body_for_kind(kind, body);
            ensure_hermes_request_size(&body)?;
            builder = builder.json(&body);
        }
        let response = builder
            .send()
            .await
            .map_err(|source| HermesAgentError::HttpRequest {
                endpoint_id: endpoint.id.clone(),
                source,
            })?;
        let http_status = response.status();
        if !http_status.is_success() {
            let response_body =
                response_body_value(response, &endpoint.id, self.max_json_response_bytes).await?;
            return Err(HermesAgentError::UnexpectedStatus {
                endpoint_id: endpoint.id.clone(),
                status: http_status.as_u16(),
                body: response_body,
            });
        }
        read_sse_response(
            endpoint,
            kind,
            http_status,
            response,
            options.max_events,
            options.publication,
            SseResponseLimits {
                stream_bytes: self.max_stream_response_bytes,
                frame_bytes: self.max_sse_frame_bytes,
            },
        )
        .await
    }

    fn endpoint(&self, endpoint_id: &str) -> Result<&HermesAgentEndpoint, HermesAgentError> {
        self.endpoints
            .get(endpoint_id)
            .ok_or_else(|| HermesAgentError::EndpointNotFound(endpoint_id.to_owned()))
    }

    fn endpoint_id_from_context(&self, context: &ConnectorContext) -> Result<String, String> {
        if let Some(endpoint_id) = context.metadata.get("endpoint_id") {
            if self.endpoints.contains_key(endpoint_id) {
                return Ok(endpoint_id.clone());
            }
            return Err(format!("unknown Hermes endpoint `{endpoint_id}`"));
        }
        if self.endpoints.len() == 1
            && let Some(endpoint_id) = self.endpoints.keys().next()
        {
            return Ok(endpoint_id.clone());
        }
        Err(
            "metadata `endpoint_id` is required when multiple Hermes endpoints are configured"
                .to_owned(),
        )
    }
}

/// Hermes action kind represented by generated AIP capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HermesActionKind {
    /// Deterministic `GET /health` readiness check.
    Health,
    /// Authenticated detailed gateway health check.
    HealthDetailed,
    /// Authenticated OpenAI-compatible model listing.
    Models,
    /// Hermes API server capability document.
    ApiCapabilities,
    /// Installed Hermes skill listing.
    Skills,
    /// Resolved Hermes toolset listing.
    Toolsets,
    /// OpenAI-compatible non-streaming chat completion.
    Chat,
    /// OpenAI-compatible streaming chat completion.
    ChatStream,
    /// OpenAI-compatible non-streaming Responses API call.
    Responses,
    /// OpenAI-compatible streaming Responses API call.
    ResponsesStream,
    /// Retrieve a stored Responses API response.
    ResponseGet,
    /// Delete a stored Responses API response.
    ResponseDelete,
    /// Start a structured Hermes run.
    RunStart,
    /// Retrieve structured Hermes run status.
    RunStatus,
    /// Consume structured Hermes run events as SSE.
    RunEvents,
    /// Resolve a pending run approval.
    RunApproval,
    /// Stop a running structured Hermes run.
    RunStop,
    /// Execute or resume a governed Hermes router/operator run.
    Operator,
    /// List persisted Hermes sessions.
    SessionsList,
    /// Create a persisted Hermes session.
    SessionCreate,
    /// Retrieve a persisted Hermes session.
    SessionGet,
    /// Update safe Hermes session metadata.
    SessionPatch,
    /// Delete a persisted Hermes session.
    SessionDelete,
    /// List persisted messages for a Hermes session.
    SessionMessages,
    /// Fork a persisted Hermes session.
    SessionFork,
    /// Run one synchronous turn against a persisted Hermes session.
    SessionChat,
    /// Run one streaming turn against a persisted Hermes session.
    SessionChatStream,
    /// List durable Hermes cron jobs.
    JobsList,
    /// Create a durable Hermes cron job.
    JobCreate,
    /// Read one durable Hermes cron job.
    JobGet,
    /// Update one durable Hermes cron job.
    JobUpdate,
    /// Delete one durable Hermes cron job.
    JobDelete,
    /// Pause one durable Hermes cron job.
    JobPause,
    /// Resume one durable Hermes cron job.
    JobResume,
    /// Trigger immediate execution of one Hermes cron job.
    JobRun,
}

impl HermesActionKind {
    /// Returns the stable operation name used in capability ids.
    #[must_use]
    pub const fn operation(self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::HealthDetailed => "health_detailed",
            Self::Models => "models",
            Self::ApiCapabilities => "capabilities",
            Self::Skills => "skills",
            Self::Toolsets => "toolsets",
            Self::Chat => "chat",
            Self::ChatStream => "chat_stream",
            Self::Responses => "responses",
            Self::ResponsesStream => "responses_stream",
            Self::ResponseGet => "response_get",
            Self::ResponseDelete => "response_delete",
            Self::RunStart => "run_start",
            Self::RunStatus => "run_status",
            Self::RunEvents => "run_events",
            Self::RunApproval => "run_approval",
            Self::RunStop => "run_stop",
            Self::Operator => "operator",
            Self::SessionsList => "sessions_list",
            Self::SessionCreate => "session_create",
            Self::SessionGet => "session_get",
            Self::SessionPatch => "session_patch",
            Self::SessionDelete => "session_delete",
            Self::SessionMessages => "session_messages",
            Self::SessionFork => "session_fork",
            Self::SessionChat => "session_chat",
            Self::SessionChatStream => "session_chat_stream",
            Self::JobsList => "jobs_list",
            Self::JobCreate => "job_create",
            Self::JobGet => "job_get",
            Self::JobUpdate => "job_update",
            Self::JobDelete => "job_delete",
            Self::JobPause => "job_pause",
            Self::JobResume => "job_resume",
            Self::JobRun => "job_run",
        }
    }

    /// Parses a stable operation name.
    #[must_use]
    pub fn from_operation(operation: &str) -> Option<Self> {
        HERMES_ACTION_KINDS
            .iter()
            .copied()
            .find(|kind| kind.operation() == operation)
    }

    fn path_template(self) -> &'static str {
        match self {
            Self::Health => "/health",
            Self::HealthDetailed => "/health/detailed",
            Self::Models => "/v1/models",
            Self::ApiCapabilities => "/v1/capabilities",
            Self::Skills => "/v1/skills",
            Self::Toolsets => "/v1/toolsets",
            Self::Chat | Self::ChatStream => "/v1/chat/completions",
            Self::Responses | Self::ResponsesStream => "/v1/responses",
            Self::ResponseGet | Self::ResponseDelete => "/v1/responses/{response_id}",
            Self::RunStart | Self::Operator => "/v1/runs",
            Self::RunStatus => "/v1/runs/{run_id}",
            Self::RunEvents => "/v1/runs/{run_id}/events",
            Self::RunApproval => "/v1/runs/{run_id}/approval",
            Self::RunStop => "/v1/runs/{run_id}/stop",
            Self::SessionsList | Self::SessionCreate => "/api/sessions",
            Self::SessionGet | Self::SessionPatch | Self::SessionDelete => {
                "/api/sessions/{session_id}"
            }
            Self::SessionMessages => "/api/sessions/{session_id}/messages",
            Self::SessionFork => "/api/sessions/{session_id}/fork",
            Self::SessionChat => "/api/sessions/{session_id}/chat",
            Self::SessionChatStream => "/api/sessions/{session_id}/chat/stream",
            Self::JobsList | Self::JobCreate => "/api/jobs",
            Self::JobGet | Self::JobUpdate | Self::JobDelete => "/api/jobs/{job_id}",
            Self::JobPause => "/api/jobs/{job_id}/pause",
            Self::JobResume => "/api/jobs/{job_id}/resume",
            Self::JobRun => "/api/jobs/{job_id}/run",
        }
    }

    fn method(self) -> Method {
        match self {
            Self::Health
            | Self::HealthDetailed
            | Self::Models
            | Self::ApiCapabilities
            | Self::Skills
            | Self::Toolsets
            | Self::ResponseGet
            | Self::RunStatus
            | Self::RunEvents
            | Self::SessionsList
            | Self::SessionGet
            | Self::SessionMessages
            | Self::JobsList
            | Self::JobGet => Method::GET,
            Self::ResponseDelete | Self::SessionDelete | Self::JobDelete => Method::DELETE,
            Self::SessionPatch | Self::JobUpdate => Method::PATCH,
            Self::Chat
            | Self::ChatStream
            | Self::Responses
            | Self::ResponsesStream
            | Self::RunStart
            | Self::Operator
            | Self::RunApproval
            | Self::RunStop
            | Self::SessionCreate
            | Self::SessionFork
            | Self::SessionChat
            | Self::SessionChatStream
            | Self::JobCreate
            | Self::JobPause
            | Self::JobResume
            | Self::JobRun => Method::POST,
        }
    }

    fn auth_required(self) -> bool {
        !matches!(self, Self::Health)
    }

    fn sends_body(self) -> bool {
        matches!(
            self.method(),
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) && !matches!(
            self,
            Self::ResponseDelete
                | Self::SessionDelete
                | Self::RunStop
                | Self::JobDelete
                | Self::JobPause
                | Self::JobResume
                | Self::JobRun
        )
    }

    fn capability_kind(self) -> CapabilityKind {
        match self {
            Self::Health
            | Self::HealthDetailed
            | Self::Models
            | Self::ApiCapabilities
            | Self::Skills
            | Self::Toolsets => CapabilityKind::Tool,
            // These provider endpoints operate on Hermes resources, but they
            // are executable AIP operations rather than entries in the native
            // AIP resource-read catalog. `CapabilityKind::Resource` is reserved
            // for values exposed through ResourceList/ResourceRead and is not
            // routed through Action handlers.
            Self::SessionsList
            | Self::SessionCreate
            | Self::SessionGet
            | Self::SessionPatch
            | Self::SessionDelete
            | Self::SessionMessages
            | Self::SessionFork
            | Self::JobsList
            | Self::JobCreate
            | Self::JobGet
            | Self::JobUpdate
            | Self::JobDelete
            | Self::JobPause
            | Self::JobResume => CapabilityKind::Tool,
            Self::RunStart
            | Self::RunStatus
            | Self::RunEvents
            | Self::RunApproval
            | Self::RunStop => CapabilityKind::Workflow,
            Self::Operator | Self::JobRun => CapabilityKind::Agent,
            Self::Chat
            | Self::ChatStream
            | Self::Responses
            | Self::ResponsesStream
            | Self::ResponseGet
            | Self::ResponseDelete
            | Self::SessionChat
            | Self::SessionChatStream => CapabilityKind::Agent,
        }
    }

    fn risk(self) -> RiskLevel {
        match self {
            Self::Health
            | Self::HealthDetailed
            | Self::Models
            | Self::ApiCapabilities
            | Self::Skills
            | Self::Toolsets
            | Self::SessionsList
            | Self::SessionGet
            | Self::SessionMessages
            | Self::ResponseGet
            | Self::RunStatus
            | Self::RunEvents => RiskLevel::Low,
            Self::JobsList | Self::JobGet => RiskLevel::Low,
            Self::Operator => RiskLevel::High,
            Self::Chat
            | Self::ChatStream
            | Self::Responses
            | Self::ResponsesStream
            | Self::RunStart
            | Self::RunApproval
            | Self::RunStop
            | Self::SessionCreate
            | Self::SessionPatch
            | Self::SessionFork
            | Self::SessionChat
            | Self::SessionChatStream
            | Self::JobCreate
            | Self::JobUpdate
            | Self::JobPause
            | Self::JobResume => RiskLevel::Medium,
            Self::ResponseDelete | Self::SessionDelete | Self::JobDelete | Self::JobRun => {
                RiskLevel::High
            }
        }
    }

    fn stability(self) -> Stability {
        match self {
            Self::Health
            | Self::HealthDetailed
            | Self::Models
            | Self::ApiCapabilities
            | Self::Chat
            | Self::ChatStream
            | Self::Responses
            | Self::ResponsesStream
            | Self::RunStart
            | Self::Operator
            | Self::RunStatus
            | Self::RunEvents
            | Self::RunApproval
            | Self::RunStop
            | Self::SessionsList
            | Self::SessionCreate
            | Self::SessionGet
            | Self::SessionPatch
            | Self::SessionDelete
            | Self::SessionMessages
            | Self::SessionFork
            | Self::SessionChat
            | Self::SessionChatStream
            | Self::JobsList
            | Self::JobCreate
            | Self::JobGet
            | Self::JobUpdate
            | Self::JobDelete
            | Self::JobPause
            | Self::JobResume
            | Self::JobRun => Stability::Stable,
            Self::Skills | Self::Toolsets | Self::ResponseGet | Self::ResponseDelete => {
                Stability::Experimental
            }
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::HealthDetailed => "detailed health",
            Self::Models => "models",
            Self::ApiCapabilities => "API capabilities",
            Self::Skills => "skills",
            Self::Toolsets => "toolsets",
            Self::Chat => "chat completion",
            Self::ChatStream => "streaming chat completion",
            Self::Responses => "response",
            Self::ResponsesStream => "streaming response",
            Self::ResponseGet => "response retrieval",
            Self::ResponseDelete => "response deletion",
            Self::RunStart => "run start",
            Self::RunStatus => "run status",
            Self::RunEvents => "run events",
            Self::RunApproval => "run approval",
            Self::RunStop => "run stop",
            Self::Operator => "router/operator run",
            Self::SessionsList => "session listing",
            Self::SessionCreate => "session creation",
            Self::SessionGet => "session retrieval",
            Self::SessionPatch => "session update",
            Self::SessionDelete => "session deletion",
            Self::SessionMessages => "session messages",
            Self::SessionFork => "session fork",
            Self::SessionChat => "session chat",
            Self::SessionChatStream => "streaming session chat",
            Self::JobsList => "job listing",
            Self::JobCreate => "job creation",
            Self::JobGet => "job retrieval",
            Self::JobUpdate => "job update",
            Self::JobDelete => "job deletion",
            Self::JobPause => "job pause",
            Self::JobResume => "job resume",
            Self::JobRun => "immediate job execution",
        }
    }

    fn description(self) -> String {
        format!(
            "Maps AIP action `{}` to Hermes Agent {} {}.",
            self.operation(),
            self.method(),
            self.path_template()
        )
    }

    fn input_schema(self) -> Value {
        match self {
            Self::Health
            | Self::HealthDetailed
            | Self::Models
            | Self::ApiCapabilities
            | Self::Skills
            | Self::Toolsets => empty_object_schema(),
            Self::Chat | Self::ChatStream => chat_input_schema(self == Self::ChatStream),
            Self::Responses | Self::ResponsesStream => raw_body_schema(
                "OpenAI Responses API JSON body. A top-level `body` object may also be supplied.",
                self == Self::ResponsesStream,
            ),
            Self::ResponseGet | Self::ResponseDelete => id_input_schema("response_id"),
            Self::RunStart => raw_body_schema("Hermes /v1/runs JSON body.", false),
            Self::Operator => operator::operator_input_schema(),
            Self::RunStatus | Self::RunEvents | Self::RunStop => id_input_schema("run_id"),
            Self::RunApproval => json!({
                "type": "object",
                "required": ["run_id", "choice"],
                "properties": {
                    "run_id": { "type": "string", "minLength": 1 },
                    "choice": { "type": "string", "enum": ["once", "session", "always", "deny", "approve", "allow"] },
                    "all": { "type": "boolean" },
                    "resolve_all": { "type": "boolean" },
                    "body": { "type": "object" }
                }
            }),
            Self::SessionsList => json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 0, "maximum": 200 },
                    "offset": { "type": "integer", "minimum": 0 },
                    "source": { "type": "string" },
                    "include_children": { "type": "boolean" },
                    "query": { "type": "object" }
                }
            }),
            Self::SessionCreate => raw_body_schema("Hermes session create JSON body.", false),
            Self::SessionGet | Self::SessionDelete | Self::SessionMessages => {
                id_input_schema("session_id")
            }
            Self::SessionPatch => json!({
                "type": "object",
                "required": ["session_id"],
                "properties": {
                    "session_id": { "type": "string", "minLength": 1 },
                    "title": { "type": ["string", "null"] },
                    "end_reason": { "type": "string" },
                    "body": { "type": "object" }
                }
            }),
            Self::SessionFork => json!({
                "type": "object",
                "required": ["session_id"],
                "properties": {
                    "session_id": { "type": "string", "minLength": 1 },
                    "id": { "type": "string" },
                    "title": { "type": "string" },
                    "body": { "type": "object" }
                }
            }),
            Self::SessionChat | Self::SessionChatStream => json!({
                "type": "object",
                "required": ["session_id"],
                "properties": {
                    "session_id": { "type": "string", "minLength": 1 },
                    "message": {},
                    "input": {},
                    "prompt": { "type": "string" },
                    "query": { "type": "string" },
                    "system_message": { "type": "string" },
                    "instructions": { "type": "string" },
                    "session_key": { "type": "string" },
                    "body": { "type": "object" },
                    "max_events": { "type": "integer", "minimum": 1, "maximum": MAX_SSE_EVENT_LIMIT }
                }
            }),
            Self::JobsList => json!({
                "type": "object",
                "properties": {
                    "include_disabled": { "type": "boolean" },
                    "query": { "type": "object" }
                },
                "additionalProperties": false
            }),
            Self::JobCreate => json!({
                "type": "object",
                "required": ["name", "schedule"],
                "properties": {
                    "name": { "type": "string", "minLength": 1, "maxLength": 200 },
                    "schedule": { "type": "string", "minLength": 1, "maxLength": 512 },
                    "prompt": { "type": "string", "maxLength": 5000 },
                    "deliver": { "type": "string", "maxLength": 256 },
                    "skills": { "type": "array", "maxItems": 256, "items": { "type": "string", "maxLength": 256 } },
                    "repeat": { "type": "integer", "minimum": 1 },
                    "body": { "type": "object" }
                },
                "additionalProperties": false
            }),
            Self::JobGet | Self::JobDelete | Self::JobPause | Self::JobResume | Self::JobRun => {
                job_id_input_schema()
            }
            Self::JobUpdate => json!({
                "type": "object",
                "required": ["job_id"],
                "properties": {
                    "job_id": { "type": "string", "pattern": "^[a-f0-9]{12}$" },
                    "name": { "type": "string", "minLength": 1, "maxLength": 200 },
                    "schedule": { "type": "string", "minLength": 1, "maxLength": 512 },
                    "prompt": { "type": "string", "maxLength": 5000 },
                    "deliver": { "type": "string", "maxLength": 256 },
                    "skills": { "type": "array", "maxItems": 256, "items": { "type": "string", "maxLength": 256 } },
                    "skill": { "type": "string", "maxLength": 256 },
                    "repeat": { "type": "integer", "minimum": 1 },
                    "enabled": { "type": "boolean" },
                    "body": { "type": "object" }
                },
                "additionalProperties": false
            }),
        }
    }

    fn output_schema(self) -> Value {
        match self {
            Self::Health => json!({
                "type": "object",
                "required": ["endpoint_id", "status", "http_status", "raw"],
                "properties": {
                    "endpoint_id": { "type": "string" },
                    "status": { "type": "string" },
                    "platform": { "type": "string" },
                    "version": { "type": "string" },
                    "http_status": { "type": "integer" },
                    "raw": { "type": "object" }
                }
            }),
            Self::Operator => operator::operator_output_schema(),
            Self::Chat
            | Self::Responses
            | Self::ResponseGet
            | Self::RunStart
            | Self::RunStatus
            | Self::RunApproval
            | Self::RunStop
            | Self::SessionsList
            | Self::SessionCreate
            | Self::SessionGet
            | Self::SessionPatch
            | Self::SessionDelete
            | Self::SessionMessages
            | Self::SessionFork
            | Self::SessionChat
            | Self::ResponseDelete
            | Self::HealthDetailed
            | Self::Models
            | Self::ApiCapabilities
            | Self::Skills
            | Self::Toolsets => json!({ "type": "object" }),
            Self::JobsList
            | Self::JobCreate
            | Self::JobGet
            | Self::JobUpdate
            | Self::JobDelete
            | Self::JobPause
            | Self::JobResume
            | Self::JobRun => json!({ "type": "object" }),
            Self::ChatStream
            | Self::ResponsesStream
            | Self::RunEvents
            | Self::SessionChatStream => json!({
                "type": "object",
                "required": ["endpoint_id", "operation", "http_status", "events", "text", "terminal"],
                "properties": {
                    "endpoint_id": { "type": "string" },
                    "operation": { "type": "string" },
                    "http_status": { "type": "integer" },
                    "events": { "type": "array" },
                    "text": { "type": "string" },
                    "terminal": { "type": "boolean" },
                    "truncated": { "type": "boolean" }
                }
            }),
        }
    }

    fn requires_human_approval(self) -> bool {
        matches!(
            self,
            Self::ResponseDelete
                | Self::RunApproval
                | Self::RunStop
                | Self::Operator
                | Self::SessionDelete
                | Self::JobCreate
                | Self::JobUpdate
                | Self::JobDelete
                | Self::JobPause
                | Self::JobResume
                | Self::JobRun
        )
    }

    fn is_streaming(self) -> bool {
        kind_streams(self)
    }

    fn is_read_only(self) -> bool {
        matches!(
            self,
            Self::Health
                | Self::HealthDetailed
                | Self::Models
                | Self::ApiCapabilities
                | Self::Skills
                | Self::Toolsets
                | Self::ResponseGet
                | Self::RunStatus
                | Self::RunEvents
                | Self::SessionsList
                | Self::SessionGet
                | Self::SessionMessages
                | Self::JobsList
                | Self::JobGet
        )
    }

    fn is_destructive(self) -> bool {
        matches!(
            self,
            Self::ResponseDelete | Self::SessionDelete | Self::JobDelete
        )
    }

    fn declares_transaction_support(self) -> bool {
        matches!(
            self,
            Self::ResponseDelete
                | Self::RunStart
                | Self::RunApproval
                | Self::RunStop
                | Self::SessionCreate
                | Self::SessionPatch
                | Self::SessionDelete
                | Self::SessionFork
                | Self::JobCreate
                | Self::JobUpdate
                | Self::JobDelete
                | Self::JobPause
                | Self::JobResume
                | Self::JobRun
        )
    }

    fn contract(self) -> CapabilityContract {
        let idempotency_requirement = if self.is_destructive()
            || self.declares_transaction_support()
            || self == Self::Operator
        {
            IdempotencyRequirement::Required
        } else {
            IdempotencyRequirement::Optional
        };
        CapabilityContract {
            side_effects: self.side_effects(),
            idempotency: IdempotencyContract {
                requirement: idempotency_requirement,
                collision_behavior: IdempotencyCollisionBehavior::ReturnOriginalResult,
                key_scope: IdempotencyKeyScope::Capability,
                ttl_ms: match idempotency_requirement {
                    IdempotencyRequirement::Required => Some(86_400_000),
                    IdempotencyRequirement::Optional | IdempotencyRequirement::Unsupported => None,
                },
            },
            execution: ExecutionContract {
                supports_sync: true,
                supports_async: matches!(
                    self,
                    Self::RunStart
                        | Self::RunEvents
                        | Self::Operator
                        | Self::ChatStream
                        | Self::ResponsesStream
                ),
                supports_streaming: self.is_streaming() || self == Self::Operator,
                supports_cancel: self.is_streaming() || self == Self::Operator,
                supports_retry: self.is_read_only(),
                expected_completion: if self.is_streaming() || self == Self::Operator {
                    ExpectedCompletionMode::Streaming
                } else {
                    ExpectedCompletionMode::Sync
                },
                retry_safety: if self.is_read_only() {
                    RetrySafety::Safe
                } else {
                    RetrySafety::Unsafe
                },
            },
            data: DataContract {
                sensitivity: self.data_sensitivity(),
                contains_pii: !self.is_read_only(),
                redaction_required: !matches!(
                    self,
                    Self::Health
                        | Self::HealthDetailed
                        | Self::Models
                        | Self::ApiCapabilities
                        | Self::Skills
                        | Self::Toolsets
                ),
                residency: None,
                retention: None,
            },
            credentials: None,
            approval: self.requires_human_approval().then(|| ApprovalPolicy {
                required: true,
                reason: Some(format!(
                    "Hermes Agent `{}` changes protected or destructive state.",
                    self.operation()
                )),
                approver_selector: ApproverSelector::TenantPolicy,
                ttl_ms: Some(900_000),
                evidence_requirements: vec![
                    EvidenceRequirement::Reason,
                    EvidenceRequirement::InputSnapshot,
                    EvidenceRequirement::PolicyDecision,
                ],
                delegated_authority: None,
                ..ApprovalPolicy::default()
            }),
            sla: Some(ServiceLevelContract {
                expected_latency_ms: Some(if self.is_streaming() || self == Self::Operator {
                    30_000
                } else {
                    5_000
                }),
                timeout_ms: Some(if self == Self::Operator {
                    900_000
                } else if self.is_streaming() {
                    300_000
                } else {
                    60_000
                }),
                async_expected: matches!(self, Self::RunStart | Self::RunEvents | Self::Operator),
                max_queue_delay_ms: Some(10_000),
                availability_target: Some("99.9%".to_owned()),
            }),
            transaction: None,
            compensation: Some(CompensationContract {
                mode: CompensationMode::RollbackNotSupported,
                compensation_capability_id: None,
                compensation_window_ms: None,
                requires_approval: self.requires_human_approval(),
            }),
        }
    }

    fn side_effects(self) -> Vec<SideEffect> {
        if self.is_destructive() {
            return vec![
                SideEffect::Read,
                SideEffect::Delete,
                SideEffect::ExternalNetwork,
            ];
        }
        if self.is_read_only() {
            return vec![SideEffect::Read, SideEffect::ExternalNetwork];
        }
        match self {
            Self::Chat
            | Self::ChatStream
            | Self::Responses
            | Self::ResponsesStream
            | Self::SessionChat
            | Self::SessionChatStream => vec![
                SideEffect::Read,
                SideEffect::Write,
                SideEffect::SendMessage,
                SideEffect::ExternalNetwork,
            ],
            Self::Operator => vec![
                SideEffect::Read,
                SideEffect::Write,
                SideEffect::SendMessage,
                SideEffect::ExternalNetwork,
                SideEffect::CodeExecution,
            ],
            Self::RunApproval | Self::RunStop => vec![
                SideEffect::Read,
                SideEffect::Write,
                SideEffect::ExternalNetwork,
            ],
            _ => vec![
                SideEffect::Read,
                SideEffect::Write,
                SideEffect::ExternalNetwork,
            ],
        }
    }

    fn data_sensitivity(self) -> DataSensitivity {
        match self {
            Self::Health | Self::HealthDetailed | Self::Models | Self::ApiCapabilities => {
                DataSensitivity::Internal
            }
            Self::ResponseDelete
            | Self::SessionDelete
            | Self::RunApproval
            | Self::RunStop
            | Self::JobDelete => DataSensitivity::Restricted,
            Self::Chat
            | Self::ChatStream
            | Self::Responses
            | Self::ResponsesStream
            | Self::RunStart
            | Self::Operator
            | Self::RunEvents
            | Self::SessionCreate
            | Self::SessionPatch
            | Self::SessionFork
            | Self::SessionChat
            | Self::SessionChatStream
            | Self::JobCreate
            | Self::JobUpdate
            | Self::JobRun => DataSensitivity::Confidential,
            _ => DataSensitivity::Internal,
        }
    }
}

/// Normalized health response returned by Hermes Agent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HermesHealth {
    /// Connector endpoint id.
    pub endpoint_id: String,
    /// Health status returned by Hermes.
    pub status: String,
    /// Platform string returned by Hermes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Hermes version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// HTTP status code returned by the endpoint.
    pub http_status: u16,
    /// Full raw JSON health payload.
    pub raw: Value,
}

/// AIP chat input accepted by Hermes chat capabilities.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HermesChatRequest {
    /// Convenience user prompt. Mutually optional with `messages`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Alias for `prompt` used by several connector harnesses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// OpenAI-compatible message array. Takes precedence over `prompt`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<Value>,
    /// Optional model override. Defaults to `hermes-agent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Optional Hermes session id for continuity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Optional Hermes memory/session key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
    /// Optional sampling temperature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Optional nucleus sampling value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    /// Optional maximum output token count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    /// Optional OpenAI-compatible stop setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<Value>,
    /// Optional OpenAI-compatible tools array.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Value>,
    /// Optional OpenAI-compatible tool choice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    /// Optional OpenAI-compatible response format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_format: Option<Value>,
    /// Optional OpenAI-compatible user identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Optional application metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// Forward-compatible OpenAI-compatible fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Parsed Server-Sent Event frame returned by a Hermes streaming route.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HermesSseEvent {
    /// Optional SSE event name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    /// Optional SSE event id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Parsed JSON data, or a JSON string if the data is not JSON.
    pub data: Value,
    /// Raw data lines joined with `\n`.
    pub raw_data: String,
    /// True when this frame is a terminal OpenAI `[DONE]` marker.
    pub terminal: bool,
}

/// Aggregated result returned by a Hermes streaming route.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HermesStreamResult {
    /// Connector endpoint id.
    pub endpoint_id: String,
    /// Hermes operation name.
    pub operation: String,
    /// HTTP status code returned by the endpoint.
    pub http_status: u16,
    /// Parsed SSE events in delivery order.
    pub events: Vec<HermesSseEvent>,
    /// Best-effort assistant text aggregated from known Hermes/OpenAI frames.
    pub text: String,
    /// True only when an explicit protocol terminal event was observed.
    pub terminal: bool,
    /// True when `max_events` stopped stream consumption before terminal close.
    pub truncated: bool,
}

/// Error returned by the Hermes connector.
#[derive(Debug, Error)]
pub enum HermesAgentError {
    /// No endpoints were configured.
    #[error("at least one Hermes endpoint is required")]
    NoEndpoints,
    /// The same endpoint id appeared more than once.
    #[error("duplicate Hermes endpoint id")]
    DuplicateEndpoint,
    /// Endpoint id is empty or contains unsupported characters.
    #[error("invalid Hermes endpoint id `{0}`")]
    InvalidEndpointId(String),
    /// A provider-account tenant binding is empty or exceeds its safe bound.
    #[error("invalid Hermes tenant id `{0}`")]
    InvalidTenantId(String),
    /// Endpoint display metadata is empty, oversized, or contains control characters.
    #[error("invalid display name for Hermes endpoint `{0}`")]
    InvalidDisplayName(String),
    /// Endpoint URL failed to parse.
    #[error("invalid Hermes endpoint URL: {0}")]
    InvalidUrl(url::ParseError),
    /// Endpoint URL used a scheme other than HTTP or HTTPS.
    #[error("unsupported Hermes endpoint URL scheme `{0}`")]
    InvalidUrlScheme(String),
    /// Endpoint URL is not a credential-free HTTP(S) origin.
    #[error("invalid Hermes endpoint base URL: {0}")]
    InvalidBaseUrl(String),
    /// Endpoint API key is empty, oversized, or contains control characters.
    #[error("invalid API key for Hermes endpoint `{0}`")]
    InvalidApiKey(String),
    /// Configured provider response bounds are invalid.
    #[error("invalid Hermes response limits: {0}")]
    InvalidResponseLimits(String),
    /// The secure default HTTP client could not be constructed.
    #[error("failed to construct Hermes HTTP client: {0}")]
    HttpClient(reqwest::Error),
    /// A typed AIP id failed validation.
    #[error("invalid AIP identifier: {0}")]
    InvalidId(aip_core::IdParseError),
    /// Endpoint id was not registered.
    #[error("Hermes endpoint `{0}` is not registered")]
    EndpointNotFound(String),
    /// Capability id did not match a Hermes operation.
    #[error("unsupported Hermes capability `{0}`")]
    UnsupportedCapability(String),
    /// A protected Hermes route was invoked without an API key.
    #[error("Hermes endpoint `{0}` has no API key for protected route")]
    MissingApiKey(String),
    /// Action input could not be mapped to a Hermes request.
    #[error("invalid Hermes action input: {0}")]
    InvalidInput(String),
    /// HTTP request failed before a response was received.
    #[error("Hermes endpoint `{endpoint_id}` request failed: {source}")]
    HttpRequest {
        /// Endpoint id.
        endpoint_id: String,
        /// Underlying HTTP error.
        source: reqwest::Error,
    },
    /// HTTP response body could not be read.
    #[error("Hermes endpoint `{endpoint_id}` response decode failed: {source}")]
    ResponseDecode {
        /// Endpoint id.
        endpoint_id: String,
        /// Underlying HTTP decode error.
        source: reqwest::Error,
    },
    /// Streaming response could not be read.
    #[error("Hermes endpoint `{endpoint_id}` stream decode failed: {source}")]
    StreamDecode {
        /// Endpoint id.
        endpoint_id: String,
        /// Underlying HTTP streaming error.
        source: reqwest::Error,
    },
    /// Streaming response violates UTF-8, framing, or memory bounds.
    #[error("Hermes endpoint `{endpoint_id}` returned an invalid stream: {message}")]
    InvalidStream {
        /// Endpoint id.
        endpoint_id: String,
        /// Sanitized validation failure.
        message: String,
    },
    /// Provider response exceeded its configured bound.
    #[error("Hermes endpoint `{endpoint_id}` response exceeded the configured {limit}-byte bound")]
    ResponseTooLarge {
        /// Endpoint id.
        endpoint_id: String,
        /// Active response limit.
        limit: usize,
    },
    /// A parsed Hermes stream frame could not be published through AIP lifecycle storage.
    #[error("Hermes endpoint `{endpoint_id}` AIP stream publication failed: {message}")]
    StreamPublish {
        /// Endpoint id.
        endpoint_id: String,
        /// Runtime publication error without payload content.
        message: String,
    },
    /// Hermes returned a non-success HTTP status.
    #[error("Hermes endpoint `{endpoint_id}` returned HTTP {status}")]
    UnexpectedStatus {
        /// Endpoint id.
        endpoint_id: String,
        /// HTTP status code.
        status: u16,
        /// Response body.
        body: Value,
    },
    /// Hermes operator policy is invalid or denied the requested route.
    #[error("Hermes operator policy rejected the request: {0}")]
    OperatorPolicy(String),
    /// Durable Hermes operator state could not be read or fenced.
    #[error("Hermes operator state failed: {0}")]
    OperatorState(String),
    /// An action id was reused with a different operator request.
    #[error("Hermes operator action `{0}` was reused with different input")]
    OperatorIdempotencyCollision(ActionId),
    /// A durable operator binding was not found.
    #[error("Hermes operator binding for action `{0}` was not found")]
    OperatorBindingNotFound(ActionId),
    /// Hermes may have accepted a run before its run id could be persisted.
    #[error("Hermes operator action `{0}` has an unknown external outcome")]
    OperatorOutcomeUnknown(ActionId),
    /// Hermes did not reach a terminal state before the governed deadline.
    #[error("Hermes operator action `{0}` exceeded its deadline")]
    OperatorTimeout(ActionId),
    /// Runtime cancelled an in-flight Hermes invocation.
    #[error("Hermes operation was cancelled by the AIP runtime")]
    Cancelled,
    /// The trusted runtime deadline elapsed before Hermes settled the request.
    #[error("Hermes operation exceeded the trusted AIP execution deadline")]
    DeadlineExceeded,
    /// The trusted runtime tenant does not own the selected provider endpoint.
    #[error("Hermes endpoint `{endpoint_id}` is not available to AIP tenant `{actual_tenant}`")]
    TenantMismatch {
        /// Selected endpoint id.
        endpoint_id: String,
        /// Verified tenant id, or `none` when no tenant was resolved.
        actual_tenant: String,
    },
}

#[async_trait]
impl Connector for HermesAgentConnector {
    fn id(&self) -> &str {
        CONNECTOR_ID
    }

    async fn discover(&self, _context: &ConnectorContext) -> ConnectorResult<Manifest> {
        self.discover_manifest()
            .map_err(|error| ConnectorError::Discovery(error.to_string()))
    }

    fn map_error(&self, error: &ConnectorError) -> ProtocolError {
        protocol_error("connector.hermes_agent.error", error.to_string(), None)
    }

    async fn health(&self, _context: &ConnectorContext) -> ConnectorResult<ConnectorHealth> {
        for endpoint_id in self.endpoints.keys() {
            self.health(endpoint_id)
                .await
                .map_err(|error| ConnectorError::Discovery(error.to_string()))?;
        }
        Ok(ConnectorHealth {
            ready: true,
            detail: format!("{} Hermes endpoint(s) are reachable", self.endpoints.len()),
        })
    }
}

#[async_trait]
impl CapabilityProviderConnector for HermesAgentConnector {
    async fn capabilities(&self, _context: &ConnectorContext) -> ConnectorResult<Vec<Capability>> {
        self.discover_manifest()
            .map(|manifest| manifest.capabilities)
            .map_err(|error| ConnectorError::Discovery(error.to_string()))
    }
}

#[async_trait]
impl OutboundConnector for HermesAgentConnector {
    async fn invoke(
        &self,
        _context: &ConnectorContext,
        action: Action,
    ) -> ConnectorResult<ActionResult> {
        let Some((endpoint, kind)) = self.endpoint_for_capability(&action.capability_id) else {
            return Err(ConnectorError::Failure(hermes_failure(
                HermesAgentError::UnsupportedCapability(action.capability_id.to_string()),
                ConnectorOperation::Invocation,
            )));
        };
        if kind == HermesActionKind::Operator {
            return self
                .invoke_operator_action(&endpoint.id, action, None)
                .await
                .map_err(|error| {
                    ConnectorError::Failure(hermes_failure(error, ConnectorOperation::Invocation))
                });
        }
        let input = action_input_with_transport_metadata(&action);
        self.invoke_operation(&endpoint.id, kind, input, Some(&action), None, None)
            .await
            .map(|output| action_output_result(action, output))
            .map_err(|error| {
                ConnectorError::Failure(hermes_failure_with_retry_safety(
                    error,
                    ConnectorOperation::Invocation,
                    kind.is_read_only(),
                ))
            })
    }

    async fn emit(&self, context: &ConnectorContext, result: ActionResult) -> ConnectorResult<()> {
        let endpoint_id = self
            .endpoint_id_from_context(context)
            .map_err(ConnectorError::Emit)?;
        let session_id = context
            .metadata
            .get("session_id")
            .cloned()
            .ok_or_else(|| ConnectorError::Emit("missing metadata `session_id`".to_owned()))?;
        let mut input = json!({
            "session_id": session_id,
            "message": action_result_text(&result)
        });
        if let Some(session_key) = context.metadata.get("session_key")
            && let Some(object) = input.as_object_mut()
        {
            object.insert("session_key".to_owned(), json!(session_key));
        }
        self.execute_json(&endpoint_id, HermesActionKind::SessionChat, input, None)
            .await
            .map_err(|error| ConnectorError::Emit(error.to_string()))?;
        Ok(())
    }

    async fn cancel(&self, _context: &ConnectorContext, action: &Action) -> ConnectorResult<()> {
        self.cancel_hermes(action).await.map_err(|error| {
            ConnectorError::Failure(hermes_failure(error, ConnectorOperation::Cancellation))
        })
    }
}

impl HermesAgentConnector {
    async fn cancel_hermes(&self, action: &Action) -> Result<(), HermesAgentError> {
        let Some((endpoint, kind)) = self.endpoint_for_capability(&action.capability_id) else {
            return Err(HermesAgentError::UnsupportedCapability(
                action.capability_id.to_string(),
            ));
        };
        if kind == HermesActionKind::Operator {
            return self.cancel_operator_action(action).await;
        }
        let Some(run_id) = action.input.get("run_id").and_then(Value::as_str) else {
            return Ok(());
        };
        self.invoke_operation(
            &endpoint.id,
            HermesActionKind::RunStop,
            json!({
                "run_id": run_id,
                "reason": "cancelled by AIP runtime"
            }),
            Some(action),
            None,
            None,
        )
        .await?;
        Ok(())
    }
}

#[async_trait]
impl InboundConnector for HermesAgentConnector {
    async fn ingest(
        &self,
        _context: &ConnectorContext,
        payload: Value,
    ) -> ConnectorResult<Vec<Envelope>> {
        if payload.get("aip_version").is_some() && payload.get("message_type").is_some() {
            let envelope = serde_json::from_value::<Envelope>(payload)
                .map_err(|error| ConnectorError::Ingest(error.to_string()))?;
            return Ok(vec![envelope]);
        }
        if let Some(value) = payload.get("delegation_request") {
            let request = serde_json::from_value::<DelegationRequest>(value.clone())
                .map_err(|error| ConnectorError::Ingest(error.to_string()))?;
            return Ok(vec![Envelope::new(MessageBody::DelegationRequest(
                Box::new(request),
            ))]);
        }
        if let Some(value) = payload.get("action") {
            let action = serde_json::from_value::<Action>(value.clone())
                .map_err(|error| ConnectorError::Ingest(error.to_string()))?;
            return Ok(vec![Envelope::new(MessageBody::Action(Box::new(action)))]);
        }
        if let Some(value) = payload.get("action_result") {
            let result = serde_json::from_value::<ActionResult>(value.clone())
                .map_err(|error| ConnectorError::Ingest(error.to_string()))?;
            return Ok(vec![Envelope::new(MessageBody::ActionResult(result))]);
        }
        Err(ConnectorError::Ingest(
            "Hermes inbound payload must contain an AIP envelope, delegation_request, action, or action_result".to_owned(),
        ))
    }
}

#[async_trait]
impl ChannelConnector for HermesAgentConnector {
    async fn ingest_channel_event(
        &self,
        context: &ConnectorContext,
        payload: Value,
    ) -> ConnectorResult<Vec<Envelope>> {
        InboundConnector::ingest(self, context, payload).await
    }

    async fn emit_channel_result(
        &self,
        context: &ConnectorContext,
        result: ActionResult,
    ) -> ConnectorResult<()> {
        OutboundConnector::emit(self, context, result).await
    }
}

#[async_trait]
impl EscalationConnector for HermesAgentConnector {
    async fn escalate(
        &self,
        context: &ConnectorContext,
        escalation: Escalation,
    ) -> ConnectorResult<()> {
        let endpoint_id = self
            .endpoint_id_from_context(context)
            .map_err(ConnectorError::Emit)?;
        let request = HermesChatRequest {
            prompt: Some(format!(
                "AIP escalation requested.\nKind: {:?}\nReason: {}\nRequested by: {}",
                escalation.kind, escalation.reason, escalation.requested_by.id
            )),
            session_id: context.metadata.get("session_id").cloned(),
            session_key: context.metadata.get("session_key").cloned(),
            ..HermesChatRequest::default()
        };
        self.chat(&endpoint_id, request)
            .await
            .map_err(|error| ConnectorError::Emit(error.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl ActionHandler for HermesAgentConnector {
    async fn handle(&self, action: Action) -> RuntimeResult<ActionResult> {
        self.invoke(&ConnectorContext::default(), action)
            .await
            .map_err(|error| RuntimeError::Handler(error.to_string()))
    }

    async fn handle_with_context(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> RuntimeResult<ActionResult> {
        let retry_safe = self
            .endpoint_for_capability(&action.capability_id)
            .is_some_and(|(_, kind)| kind.is_read_only());
        self.invoke_action_with_execution(action, context)
            .await
            .map_err(|error| {
                RuntimeError::Protocol(
                    hermes_failure_with_retry_safety(
                        error,
                        ConnectorOperation::Invocation,
                        retry_safe,
                    )
                    .to_protocol_error(),
                )
            })
    }

    async fn cancel(&self, action: &Action) -> RuntimeResult<()> {
        OutboundConnector::cancel(self, &ConnectorContext::default(), action)
            .await
            .map_err(|error| RuntimeError::Handler(error.to_string()))
    }

    async fn cancel_with_context(
        &self,
        action: &Action,
        context: &ActionExecutionContext,
    ) -> RuntimeResult<()> {
        FrozenConnector::cancel_typed(self, action, context.clone())
            .await
            .map_err(|failure| RuntimeError::Protocol(failure.to_protocol_error()))
    }
}

#[async_trait]
impl FrozenConnector for HermesAgentConnector {
    fn implementation_support(&self, capability: &Capability) -> CapabilityImplementationSupport {
        let kind = self
            .endpoint_for_capability(&capability.id)
            .map(|(_, kind)| kind);
        CapabilityImplementationSupport {
            invocation: kind.is_some(),
            cancellation: kind
                .is_some_and(|kind| kind_streams(kind) || kind == HermesActionKind::Operator),
            streaming: kind
                .is_some_and(|kind| kind_streams(kind) || kind == HermesActionKind::Operator),
            retry: kind.is_some_and(HermesActionKind::is_read_only),
            transaction: false,
            reconciliation: false,
            compensation: false,
            approval: kind.is_some_and(HermesActionKind::requires_human_approval),
            credentials: false,
        }
    }

    async fn invoke_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        let retry_safe = self
            .endpoint_for_capability(&action.capability_id)
            .is_some_and(|(_, kind)| kind.is_read_only());
        self.invoke_action_with_execution(action, context)
            .await
            .map_err(|error| {
                hermes_failure_with_retry_safety(error, ConnectorOperation::Invocation, retry_safe)
            })
    }

    async fn cancel_typed(
        &self,
        action: &Action,
        _context: ActionExecutionContext,
    ) -> Result<(), ConnectorFailure> {
        self.cancel_hermes(action)
            .await
            .map_err(|error| hermes_failure(error, ConnectorOperation::Cancellation))
    }
}

enum ActionOutput {
    Health(HermesHealth),
    Json(Value),
    Stream(Box<HermesStreamResult>),
}

fn action_input_with_transport_metadata(action: &Action) -> Value {
    let mut input = action.input.clone();
    if let Some(idempotency_key) = action.idempotency_key.as_ref()
        && let Some(object) = input.as_object_mut()
    {
        object
            .entry("idempotency_key".to_owned())
            .or_insert_with(|| Value::String(idempotency_key.clone()));
    }
    input
}

#[derive(Clone, Debug, Default)]
struct StandardHeaders {
    session_id: Option<String>,
    session_key: Option<String>,
    idempotency_key: Option<String>,
    aip_session_id: Option<String>,
    aip_correlation_id: Option<String>,
    aip_delegation_chain: Option<String>,
    aip_principal_id: Option<String>,
    aip_tenant_id: Option<String>,
    aip_authentication_issuer: Option<String>,
    aip_trace_id: Option<String>,
    aip_deadline_unix_ms: Option<String>,
}

impl StandardHeaders {
    fn from_chat_request(request: &HermesChatRequest) -> Self {
        Self::from_chat_request_with_aip(request, None)
    }

    fn from_chat_request_with_aip(
        request: &HermesChatRequest,
        aip_context: Option<&Value>,
    ) -> Self {
        let aip = aip_context.or_else(|| request.extra.get("_aip"));
        Self {
            session_id: request.session_id.clone(),
            session_key: request.session_key.clone(),
            idempotency_key: string_field(&request.extra, "idempotency_key"),
            aip_session_id: aip.and_then(|value| string_field_from_value(value, "session_id")),
            aip_correlation_id: aip
                .and_then(|value| string_field_from_value(value, "correlation_id")),
            aip_delegation_chain: aip
                .and_then(|value| value.get("delegation_chain"))
                .and_then(json_header_value),
            ..Self::default()
        }
    }

    fn from_input_with_aip(input: &Value, aip_context: Option<&Value>) -> Self {
        let aip = aip_context.or_else(|| input.get("_aip"));
        Self {
            session_id: input
                .get("session_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            session_key: input
                .get("session_key")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            idempotency_key: input
                .get("idempotency_key")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            aip_session_id: aip.and_then(|value| string_field_from_value(value, "session_id")),
            aip_correlation_id: aip
                .and_then(|value| string_field_from_value(value, "correlation_id")),
            aip_delegation_chain: aip
                .and_then(|value| value.get("delegation_chain"))
                .and_then(json_header_value),
            ..Self::default()
        }
    }

    fn apply_execution(&mut self, action: &Action, execution: &ActionExecutionContext) {
        self.idempotency_key.clone_from(&action.idempotency_key);
        self.aip_principal_id = Some(execution.actor.principal.id.to_string());
        self.aip_tenant_id = execution
            .tenant
            .as_ref()
            .map(|tenant| tenant.tenant.id.clone());
        self.aip_authentication_issuer = Some(execution.actor.issuer.clone());
        self.aip_trace_id.clone_from(&execution.trace.trace_id);
        if self.aip_trace_id.is_some() {
            self.aip_correlation_id.clone_from(&self.aip_trace_id);
        }
        if !action.delegation_chain.is_empty() {
            self.aip_delegation_chain = json_header_value(&json!(action.delegation_chain));
        }
        self.aip_deadline_unix_ms =
            Some((execution.deadline.expires_at.unix_timestamp_nanos() / 1_000_000).to_string());
    }

    fn apply_message_context(&mut self, context: &aip_runtime::MessageContext) {
        self.aip_session_id = context.session_id.as_ref().map(ToString::to_string);
        self.aip_correlation_id = context.correlation_id.as_ref().map(ToString::to_string);
        if let Some(authenticated) = context.authenticated.as_ref() {
            self.aip_principal_id = Some(authenticated.principal.id.to_string());
            self.aip_authentication_issuer = Some(authenticated.issuer.clone());
        }
        self.aip_tenant_id = context
            .tenant
            .as_ref()
            .map(|tenant| tenant.tenant.id.clone());
    }
}

fn validate_execution_boundary(
    endpoint: &HermesAgentEndpoint,
    execution: &ActionExecutionContext,
) -> Result<(), HermesAgentError> {
    if execution.deadline.is_expired(OffsetDateTime::now_utc()) {
        return Err(HermesAgentError::DeadlineExceeded);
    }
    if let Some(tenant) = execution.tenant.as_ref() {
        tenant
            .validate()
            .map_err(|error| HermesAgentError::InvalidInput(error.to_string()))?;
    }
    if let Some(expected_tenant) = endpoint.tenant_id.as_deref() {
        let actual_tenant = execution
            .tenant
            .as_ref()
            .map(|tenant| tenant.tenant.id.as_str());
        if actual_tenant != Some(expected_tenant) {
            return Err(HermesAgentError::TenantMismatch {
                endpoint_id: endpoint.id.clone(),
                actual_tenant: actual_tenant.unwrap_or("none").to_owned(),
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_message_context_boundary(
    endpoint: &HermesAgentEndpoint,
    context: &aip_runtime::MessageContext,
) -> Result<(), HermesAgentError> {
    if let Some(tenant) = context.tenant.as_ref() {
        tenant
            .validate()
            .map_err(|error| HermesAgentError::InvalidInput(error.to_string()))?;
    }
    if let Some(expected_tenant) = endpoint.tenant_id.as_deref() {
        let actual_tenant = context
            .tenant
            .as_ref()
            .map(|tenant| tenant.tenant.id.as_str());
        if actual_tenant != Some(expected_tenant) {
            return Err(HermesAgentError::TenantMismatch {
                endpoint_id: endpoint.id.clone(),
                actual_tenant: actual_tenant.unwrap_or("none").to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_endpoint_descriptor(endpoint: &HermesAgentEndpoint) -> Result<(), HermesAgentError> {
    let normalized_id = normalize_endpoint_id(endpoint.id.clone())?;
    if normalized_id != endpoint.id {
        return Err(HermesAgentError::InvalidEndpointId(endpoint.id.clone()));
    }
    validate_endpoint_base_url(&endpoint.base_url)?;
    if let Some(api_key) = endpoint.api_key.as_ref() {
        validate_hermes_api_key(api_key, &endpoint.id)?;
    }
    if let Some(display_name) = endpoint.display_name.as_ref()
        && (display_name.trim().is_empty()
            || display_name.trim() != display_name
            || display_name.len() > 256
            || display_name.chars().any(char::is_control))
    {
        return Err(HermesAgentError::InvalidDisplayName(endpoint.id.clone()));
    }
    if let Some(tenant_id) = endpoint.tenant_id.as_ref() {
        validate_tenant_id(tenant_id)?;
    }
    Ok(())
}

fn validate_endpoint_base_url(base_url: &Url) -> Result<(), HermesAgentError> {
    if base_url.scheme() != "http" && base_url.scheme() != "https" {
        return Err(HermesAgentError::InvalidUrlScheme(
            base_url.scheme().to_owned(),
        ));
    }
    if !base_url.username().is_empty()
        || base_url.password().is_some()
        || base_url.query().is_some()
        || base_url.fragment().is_some()
        || base_url.path() != "/"
        || base_url.host_str().is_none()
    {
        return Err(HermesAgentError::InvalidBaseUrl(
            "endpoint URL must be an HTTP(S) origin without credentials, path, query, or fragment"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_tenant_id(tenant_id: &str) -> Result<(), HermesAgentError> {
    if tenant_id.trim().is_empty()
        || tenant_id.trim() != tenant_id
        || tenant_id.len() > 512
        || tenant_id.chars().any(char::is_control)
    {
        return Err(HermesAgentError::InvalidTenantId(tenant_id.to_owned()));
    }
    Ok(())
}

fn normalize_endpoint_id(raw: String) -> Result<String, HermesAgentError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 128
        || !trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(HermesAgentError::InvalidEndpointId(raw));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn validate_hermes_api_key(
    api_key: &ConnectorSecret,
    endpoint_id: &str,
) -> Result<(), HermesAgentError> {
    let api_key = api_key
        .expose_str()
        .map_err(|_| HermesAgentError::InvalidApiKey(endpoint_id.to_owned()))?;
    if api_key.trim().is_empty()
        || api_key.len() > 16 * 1024
        || api_key.bytes().any(|byte| byte.is_ascii_whitespace())
        || api_key.chars().any(char::is_control)
    {
        return Err(HermesAgentError::InvalidApiKey(endpoint_id.to_owned()));
    }
    Ok(())
}

fn capability_id(endpoint_id: &str, operation: &str) -> Result<CapabilityId, HermesAgentError> {
    CapabilityId::parse(format!("{CAPABILITY_PREFIX}{endpoint_id}:{operation}"))
        .map_err(HermesAgentError::InvalidId)
}

fn endpoint_url(endpoint: &HermesAgentEndpoint, path: &str) -> Result<Url, HermesAgentError> {
    endpoint
        .base_url
        .join(path)
        .map_err(HermesAgentError::InvalidUrl)
}

fn endpoint_url_with_query(
    endpoint: &HermesAgentEndpoint,
    path: &str,
    query_pairs: Vec<(String, String)>,
) -> Result<Url, HermesAgentError> {
    let mut url = endpoint_url(endpoint, path)?;
    if !query_pairs.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in query_pairs {
            pairs.append_pair(&key, &value);
        }
    }
    if url.as_str().len() > MAX_REQUEST_URL_BYTES {
        return Err(HermesAgentError::InvalidInput(format!(
            "encoded Hermes request URL exceeds {MAX_REQUEST_URL_BYTES} bytes"
        )));
    }
    Ok(url)
}

fn capability(
    endpoint: &HermesAgentEndpoint,
    kind: HermesActionKind,
) -> Result<Capability, HermesAgentError> {
    Ok(Capability {
        id: endpoint.capability_id(kind)?,
        name: format!("Hermes Agent {} ({})", kind.display_name(), endpoint.id),
        kind: kind.capability_kind(),
        input_schema: kind.input_schema(),
        output_schema: Some(kind.output_schema()),
        description: Some(kind.description()),
        risk: Some(kind.risk()),
        stability: Some(kind.stability()),
        cost: None,
        auth: if kind.auth_required() {
            Some(json!({ "scheme": "bearer", "source": "endpoint.api_key" }))
        } else {
            None
        },
        bindings: vec![binding(endpoint, kind)],
        requires_human_approval: Some(kind.requires_human_approval()),
        contract: Some(kind.contract()),
    })
}

fn binding(endpoint: &HermesAgentEndpoint, kind: HermesActionKind) -> Binding {
    let mut metadata = Map::new();
    metadata.insert("system".to_owned(), json!("hermes-agent"));
    metadata.insert("endpoint_id".to_owned(), json!(endpoint.id));
    metadata.insert("operation".to_owned(), json!(kind.operation()));
    metadata.insert("base_url".to_owned(), json!(endpoint.base_url.as_str()));
    metadata.insert("method".to_owned(), json!(kind.method().as_str()));
    metadata.insert("path".to_owned(), json!(kind.path_template()));
    metadata.insert("streaming".to_owned(), json!(kind_streams(kind)));
    Binding {
        profile: ProfileId::from(PROFILE_ID),
        metadata,
    }
}

fn apply_auth(
    builder: reqwest::RequestBuilder,
    endpoint: &HermesAgentEndpoint,
    required: bool,
) -> Result<reqwest::RequestBuilder, HermesAgentError> {
    if !required {
        return Ok(builder);
    }
    let api_key = endpoint
        .api_key
        .as_ref()
        .ok_or_else(|| HermesAgentError::MissingApiKey(endpoint.id.clone()))?;
    let api_key = api_key
        .expose_str()
        .map_err(|_| HermesAgentError::MissingApiKey(endpoint.id.clone()))?;
    Ok(builder.bearer_auth(api_key))
}

fn apply_standard_headers(
    mut builder: reqwest::RequestBuilder,
    headers: StandardHeaders,
) -> Result<reqwest::RequestBuilder, HermesAgentError> {
    let values = [
        ("X-Hermes-Session-Id", headers.session_id),
        ("X-Hermes-Session-Key", headers.session_key),
        ("Idempotency-Key", headers.idempotency_key),
        ("X-AIP-Session-Id", headers.aip_session_id),
        ("X-AIP-Correlation-Id", headers.aip_correlation_id),
        ("X-AIP-Delegation-Chain", headers.aip_delegation_chain),
        ("X-AIP-Principal-Id", headers.aip_principal_id),
        ("X-AIP-Tenant-Id", headers.aip_tenant_id),
        (
            "X-AIP-Authentication-Issuer",
            headers.aip_authentication_issuer,
        ),
        ("X-AIP-Trace-Id", headers.aip_trace_id),
        ("X-AIP-Deadline-Unix-Ms", headers.aip_deadline_unix_ms),
    ];
    for (name, value) in values {
        let Some(value) = value else {
            continue;
        };
        if value.is_empty()
            || value.len() > MAX_OUTBOUND_HEADER_BYTES
            || reqwest::header::HeaderValue::from_str(&value).is_err()
        {
            return Err(HermesAgentError::InvalidInput(format!(
                "outbound header `{name}` is empty, oversized, or invalid"
            )));
        }
        builder = builder.header(name, value);
    }
    Ok(builder)
}

fn ensure_hermes_request_size(body: &Value) -> Result<(), HermesAgentError> {
    let encoded = serde_json::to_vec(body)
        .map_err(|error| HermesAgentError::InvalidInput(error.to_string()))?;
    if encoded.len() > MAX_REQUEST_BODY_BYTES {
        return Err(HermesAgentError::InvalidInput(format!(
            "Hermes request body exceeds {MAX_REQUEST_BODY_BYTES} bytes"
        )));
    }
    Ok(())
}

async fn response_body_value(
    response: reqwest::Response,
    endpoint_id: &str,
    maximum: usize,
) -> Result<Value, HermesAgentError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(HermesAgentError::ResponseTooLarge {
            endpoint_id: endpoint_id.to_owned(),
            limit: maximum,
        });
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|source| HermesAgentError::ResponseDecode {
            endpoint_id: endpoint_id.to_owned(),
            source,
        })?;
        if bytes.len().saturating_add(chunk.len()) > maximum {
            return Err(HermesAgentError::ResponseTooLarge {
                endpoint_id: endpoint_id.to_owned(),
                limit: maximum,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_slice::<Value>(&bytes).unwrap_or_else(|_| {
        json!({
            "text": String::from_utf8_lossy(&bytes)
        })
    }))
}

fn json_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn string_field(map: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn string_field_from_value(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn json_header_value(value: &Value) -> Option<String> {
    serde_json::to_string(value)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn aip_context_from_memory(memory_context: &Value) -> Option<&Value> {
    memory_context
        .get("_aip")
        .or_else(|| {
            memory_context
                .get("delegation_chain")
                .map(|_| memory_context)
        })
        .or_else(|| memory_context.get("session_id").map(|_| memory_context))
        .or_else(|| memory_context.get("correlation_id").map(|_| memory_context))
}

fn chat_request_from_input(input: Value) -> Result<HermesChatRequest, HermesAgentError> {
    let request = serde_json::from_value::<HermesChatRequest>(input)
        .map_err(|error| HermesAgentError::InvalidInput(error.to_string()))?;
    validate_chat_request(&request)?;
    Ok(request)
}

fn validate_chat_request(request: &HermesChatRequest) -> Result<(), HermesAgentError> {
    if !request.messages.is_empty() {
        return Ok(());
    }
    if request
        .prompt
        .as_deref()
        .or(request.query.as_deref())
        .is_some_and(|text| !text.trim().is_empty())
    {
        return Ok(());
    }
    Err(HermesAgentError::InvalidInput(
        "expected non-empty `messages`, `prompt`, or `query`".to_owned(),
    ))
}

fn build_chat_payload(
    request: &HermesChatRequest,
    stream: bool,
) -> Result<Value, HermesAgentError> {
    validate_chat_request(request)?;
    let mut payload = Map::new();
    for (key, value) in &request.extra {
        if key != "session_id" && key != "session_key" && key != "idempotency_key" {
            payload.insert(key.clone(), value.clone());
        }
    }
    payload.insert(
        "model".to_owned(),
        json!(
            request
                .model
                .clone()
                .unwrap_or_else(|| DEFAULT_CHAT_MODEL.to_owned())
        ),
    );
    payload.insert("messages".to_owned(), chat_messages(request)?);
    insert_optional_f64(&mut payload, "temperature", request.temperature);
    insert_optional_f64(&mut payload, "top_p", request.top_p);
    insert_optional_u64(&mut payload, "max_tokens", request.max_tokens);
    insert_optional_value(&mut payload, "stop", request.stop.clone());
    insert_optional_value(&mut payload, "tools", request.tools.clone());
    insert_optional_value(&mut payload, "tool_choice", request.tool_choice.clone());
    insert_optional_value(
        &mut payload,
        "response_format",
        request.response_format.clone(),
    );
    insert_optional_string(&mut payload, "user", request.user.clone());
    insert_optional_value(&mut payload, "metadata", request.metadata.clone());
    payload.insert("stream".to_owned(), json!(stream));
    Ok(Value::Object(payload))
}

fn chat_messages(request: &HermesChatRequest) -> Result<Value, HermesAgentError> {
    if !request.messages.is_empty() {
        return Ok(Value::Array(request.messages.clone()));
    }
    let prompt = request
        .prompt
        .as_deref()
        .or(request.query.as_deref())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            HermesAgentError::InvalidInput(
                "expected non-empty `messages`, `prompt`, or `query`".to_owned(),
            )
        })?;
    Ok(json!([
        {
            "role": "user",
            "content": prompt
        }
    ]))
}

fn insert_optional_f64(payload: &mut Map<String, Value>, key: &str, value: Option<f64>) {
    if let Some(value) = value {
        payload.insert(key.to_owned(), json!(value));
    }
}

fn insert_optional_u64(payload: &mut Map<String, Value>, key: &str, value: Option<u64>) {
    if let Some(value) = value {
        payload.insert(key.to_owned(), json!(value));
    }
}

fn insert_optional_string(payload: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value {
        payload.insert(key.to_owned(), json!(value));
    }
}

fn insert_optional_value(payload: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        payload.insert(key.to_owned(), value);
    }
}

fn body_for_kind(kind: HermesActionKind, input: &Value) -> Result<Value, HermesAgentError> {
    match kind {
        HermesActionKind::Health
        | HermesActionKind::HealthDetailed
        | HermesActionKind::Models
        | HermesActionKind::ApiCapabilities
        | HermesActionKind::Skills
        | HermesActionKind::Toolsets
        | HermesActionKind::RunStatus
        | HermesActionKind::RunEvents
        | HermesActionKind::RunStop
        | HermesActionKind::ResponseGet
        | HermesActionKind::ResponseDelete
        | HermesActionKind::SessionsList
        | HermesActionKind::SessionGet
        | HermesActionKind::SessionDelete
        | HermesActionKind::SessionMessages
        | HermesActionKind::JobsList
        | HermesActionKind::JobGet
        | HermesActionKind::JobDelete
        | HermesActionKind::JobPause
        | HermesActionKind::JobResume
        | HermesActionKind::JobRun => Ok(input.clone()),
        HermesActionKind::Responses | HermesActionKind::ResponsesStream => {
            let mut body = body_value(input);
            if !body.is_object() {
                body = json!({ "input": body });
            }
            if let Some(object) = body.as_object_mut() {
                object.insert(
                    "stream".to_owned(),
                    json!(kind == HermesActionKind::ResponsesStream),
                );
            }
            Ok(body)
        }
        HermesActionKind::RunStart | HermesActionKind::Operator => {
            let mut body = body_value(input);
            if !body.is_object() {
                body = json!({ "input": body });
            }
            Ok(body)
        }
        HermesActionKind::RunApproval => {
            let body = body_value(input);
            if body.get("choice").is_some() {
                Ok(body)
            } else if let Some(choice) = input.get("choice") {
                let mut object = Map::new();
                object.insert("choice".to_owned(), choice.clone());
                insert_if_present(&mut object, input, "all");
                insert_if_present(&mut object, input, "resolve_all");
                Ok(Value::Object(object))
            } else {
                Err(HermesAgentError::InvalidInput(
                    "run_approval requires `choice`".to_owned(),
                ))
            }
        }
        HermesActionKind::SessionCreate | HermesActionKind::JobCreate => Ok(body_value(input)),
        HermesActionKind::SessionPatch | HermesActionKind::JobUpdate => {
            let body = body_value(input);
            let path_id = if kind == HermesActionKind::JobUpdate {
                "job_id"
            } else {
                "session_id"
            };
            if body.get(path_id).is_some() {
                object_without_keys(body, &[path_id, "session_key", "idempotency_key"])
            } else {
                Ok(body)
            }
        }
        HermesActionKind::SessionFork => {
            let body = body_value(input);
            if body.get("session_id").is_some() {
                object_without_keys(body, &["session_id", "session_key", "idempotency_key"])
            } else {
                Ok(body)
            }
        }
        HermesActionKind::SessionChat | HermesActionKind::SessionChatStream => {
            let mut body = body_value(input);
            if body.get("message").is_none()
                && body.get("input").is_none()
                && let Some(message) = input
                    .get("prompt")
                    .or_else(|| input.get("query"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
            {
                let mut object = body.as_object().cloned().unwrap_or_default();
                object.insert("message".to_owned(), json!(message));
                body = Value::Object(object);
            }
            object_without_keys(
                body,
                &[
                    "session_id",
                    "session_key",
                    "idempotency_key",
                    "max_events",
                    "prompt",
                    "query",
                ],
            )
        }
        HermesActionKind::Chat | HermesActionKind::ChatStream => unreachable!("chat is typed"),
    }
}

fn http_body_for_kind(kind: HermesActionKind, body: Value) -> Value {
    if matches!(
        kind,
        HermesActionKind::SessionPatch
            | HermesActionKind::SessionFork
            | HermesActionKind::SessionChat
            | HermesActionKind::SessionChatStream
            | HermesActionKind::RunApproval
    ) {
        return body;
    }
    if let Some(inner) = body.get("body") {
        inner.clone()
    } else {
        body
    }
}

fn body_value(input: &Value) -> Value {
    input.get("body").cloned().unwrap_or_else(|| input.clone())
}

fn object_without_keys(mut value: Value, keys: &[&str]) -> Result<Value, HermesAgentError> {
    let object = value.as_object_mut().ok_or_else(|| {
        HermesAgentError::InvalidInput("expected request body to be a JSON object".to_owned())
    })?;
    for key in keys {
        object.remove(*key);
    }
    Ok(value)
}

fn insert_if_present(object: &mut Map<String, Value>, input: &Value, key: &str) {
    if let Some(value) = input.get(key) {
        object.insert(key.to_owned(), value.clone());
    }
}

fn path_for_kind(kind: HermesActionKind, input: &Value) -> Result<String, HermesAgentError> {
    let template = kind.path_template();
    let path = match kind {
        HermesActionKind::ResponseGet | HermesActionKind::ResponseDelete => template.replace(
            "{response_id}",
            &required_path_segment(input, "response_id")?,
        ),
        HermesActionKind::RunStatus
        | HermesActionKind::RunEvents
        | HermesActionKind::RunApproval
        | HermesActionKind::RunStop => {
            template.replace("{run_id}", &required_path_segment(input, "run_id")?)
        }
        HermesActionKind::SessionGet
        | HermesActionKind::SessionPatch
        | HermesActionKind::SessionDelete
        | HermesActionKind::SessionMessages
        | HermesActionKind::SessionFork
        | HermesActionKind::SessionChat
        | HermesActionKind::SessionChatStream => {
            template.replace("{session_id}", &required_path_segment(input, "session_id")?)
        }
        HermesActionKind::JobGet
        | HermesActionKind::JobUpdate
        | HermesActionKind::JobDelete
        | HermesActionKind::JobPause
        | HermesActionKind::JobResume
        | HermesActionKind::JobRun => template.replace("{job_id}", &required_job_id(input)?),
        _ => template.to_owned(),
    };
    Ok(path)
}

fn required_path_segment(input: &Value, key: &str) -> Result<String, HermesAgentError> {
    let value = input
        .get(key)
        .or_else(|| input.get("body").and_then(|body| body.get(key)))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| HermesAgentError::InvalidInput(format!("missing `{key}`")))?;
    if value.len() > 512 || value.chars().any(char::is_control) {
        return Err(HermesAgentError::InvalidInput(format!(
            "`{key}` must contain at most 512 bytes without control characters"
        )));
    }
    Ok(encode_path_segment(value))
}

fn required_job_id(input: &Value) -> Result<String, HermesAgentError> {
    let value = input
        .get("job_id")
        .or_else(|| input.get("body").and_then(|body| body.get("job_id")))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| HermesAgentError::InvalidInput("missing `job_id`".to_owned()))?;
    if value.len() != 12
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HermesAgentError::InvalidInput(
            "`job_id` must match ^[a-f0-9]{12}$".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn encode_path_segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn query_pairs_for_kind(
    kind: HermesActionKind,
    input: &Value,
) -> Result<Vec<(String, String)>, HermesAgentError> {
    if !matches!(
        kind,
        HermesActionKind::SessionsList | HermesActionKind::JobsList
    ) {
        return Ok(Vec::new());
    }
    let keys: &[&str] = if kind == HermesActionKind::JobsList {
        &["include_disabled"]
    } else {
        &["limit", "offset", "source", "include_children"]
    };
    let mut pairs = BTreeMap::new();
    if let Some(query) = input.get("query") {
        let object = query.as_object().ok_or_else(|| {
            HermesAgentError::InvalidInput("`query` must be a JSON object".to_owned())
        })?;
        if object.len() > keys.len() {
            return Err(HermesAgentError::InvalidInput(
                "`query` contains too many Hermes parameters".to_owned(),
            ));
        }
        for (key, value) in object {
            if !keys.contains(&key.as_str()) {
                return Err(HermesAgentError::InvalidInput(format!(
                    "unsupported Hermes query parameter `{key}`"
                )));
            }
            let value = query_value_to_string(value).ok_or_else(|| {
                HermesAgentError::InvalidInput(format!(
                    "Hermes query parameter `{key}` must be a scalar"
                ))
            })?;
            validate_query_value(key, &value)?;
            pairs.insert(key.clone(), value);
        }
    }
    for key in keys {
        if let Some(value) = input.get(key).and_then(query_value_to_string) {
            validate_query_value(key, &value)?;
            if pairs.get(*key).is_some_and(|existing| existing != &value) {
                return Err(HermesAgentError::InvalidInput(format!(
                    "Hermes query parameter `{key}` was supplied with conflicting values"
                )));
            }
            pairs.insert((*key).to_owned(), value);
        }
    }
    Ok(pairs.into_iter().collect())
}

fn validate_query_value(key: &str, value: &str) -> Result<(), HermesAgentError> {
    if value.len() > 4_096 || value.chars().any(char::is_control) {
        return Err(HermesAgentError::InvalidInput(format!(
            "Hermes query parameter `{key}` exceeds its safe bound"
        )));
    }
    Ok(())
}

fn query_value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn max_events_from_input(input: &Value) -> Result<Option<usize>, HermesAgentError> {
    let Some(value) = input.get("max_events") else {
        return Ok(None);
    };
    let value = value
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| (1..=MAX_SSE_EVENT_LIMIT).contains(value))
        .ok_or_else(|| {
            HermesAgentError::InvalidInput(format!(
                "`max_events` must be between 1 and {MAX_SSE_EVENT_LIMIT}"
            ))
        })?;
    Ok(Some(value))
}

async fn read_sse_response(
    endpoint: &HermesAgentEndpoint,
    kind: HermesActionKind,
    http_status: StatusCode,
    response: reqwest::Response,
    max_events: Option<usize>,
    publication: Option<&StreamPublication>,
    limits: SseResponseLimits,
) -> Result<HermesStreamResult, HermesAgentError> {
    let event_limit = max_events.unwrap_or(DEFAULT_SSE_EVENT_LIMIT);
    let mut buffer = Vec::new();
    let mut events = Vec::new();
    let mut text = String::new();
    let mut terminal = false;
    let mut truncated = false;
    let mut response_bytes = 0_usize;
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|source| HermesAgentError::StreamDecode {
            endpoint_id: endpoint.id.clone(),
            source,
        })?;
        response_bytes = response_bytes.checked_add(chunk.len()).ok_or_else(|| {
            HermesAgentError::ResponseTooLarge {
                endpoint_id: endpoint.id.clone(),
                limit: limits.stream_bytes,
            }
        })?;
        if response_bytes > limits.stream_bytes {
            return Err(HermesAgentError::ResponseTooLarge {
                endpoint_id: endpoint.id.clone(),
                limit: limits.stream_bytes,
            });
        }
        buffer.extend_from_slice(&chunk);
        while let Some(frame) = take_sse_frame(&mut buffer, limits.frame_bytes, &endpoint.id)? {
            if let Some(event) = parse_sse_frame_bytes(&frame, &endpoint.id)? {
                terminal |= event.terminal;
                append_event_text(&mut text, &event);
                publish_stream_event(endpoint, publication, events.len() as u64, &event).await?;
                events.push(event);
                if events.len() >= event_limit {
                    truncated = true;
                    terminal = false;
                    return Ok(HermesStreamResult {
                        endpoint_id: endpoint.id.clone(),
                        operation: kind.operation().to_owned(),
                        http_status: http_status.as_u16(),
                        events,
                        text,
                        terminal,
                        truncated,
                    });
                }
                if terminal {
                    return Ok(HermesStreamResult {
                        endpoint_id: endpoint.id.clone(),
                        operation: kind.operation().to_owned(),
                        http_status: http_status.as_u16(),
                        events,
                        text,
                        terminal,
                        truncated,
                    });
                }
            }
        }
        if buffer.len() > limits.frame_bytes {
            return Err(HermesAgentError::InvalidStream {
                endpoint_id: endpoint.id.clone(),
                message: format!("SSE frame exceeded {} bytes", limits.frame_bytes),
            });
        }
    }

    if !buffer.iter().all(u8::is_ascii_whitespace)
        && let Some(event) = parse_sse_frame_bytes(&buffer, &endpoint.id)?
    {
        terminal |= event.terminal;
        append_event_text(&mut text, &event);
        publish_stream_event(endpoint, publication, events.len() as u64, &event).await?;
        events.push(event);
    }
    if !truncated
        && !terminal
        && let Some(publication) = publication
    {
        publication
            .stream
            .emit(StreamChunk {
                action_id: publication.action_id.clone(),
                sequence: events.len() as u64,
                kind: StreamChunkKind::Error,
                data: Some(json!({
                    "operation": kind.operation(),
                    "reason": "upstream_stream_closed_without_terminal_event"
                })),
                part: None,
            })
            .await
            .map_err(|error| HermesAgentError::StreamPublish {
                endpoint_id: endpoint.id.clone(),
                message: error.to_string(),
            })?;
    }

    Ok(HermesStreamResult {
        endpoint_id: endpoint.id.clone(),
        operation: kind.operation().to_owned(),
        http_status: http_status.as_u16(),
        events,
        text,
        terminal,
        truncated,
    })
}

async fn publish_stream_event(
    endpoint: &HermesAgentEndpoint,
    publication: Option<&StreamPublication>,
    sequence: u64,
    event: &HermesSseEvent,
) -> Result<(), HermesAgentError> {
    let Some(publication) = publication else {
        return Ok(());
    };
    publication
        .stream
        .emit(StreamChunk {
            action_id: publication.action_id.clone(),
            sequence,
            kind: stream_chunk_kind(event),
            data: Some(json!({ "hermes_sse": event })),
            part: stream_event_text(event).map(MessagePart::text),
        })
        .await
        .map_err(|error| HermesAgentError::StreamPublish {
            endpoint_id: endpoint.id.clone(),
            message: error.to_string(),
        })
}

fn take_sse_frame(
    buffer: &mut Vec<u8>,
    maximum: usize,
    endpoint_id: &str,
) -> Result<Option<Vec<u8>>, HermesAgentError> {
    let lf = buffer.windows(2).position(|window| window == b"\n\n");
    let crlf = buffer.windows(4).position(|window| window == b"\r\n\r\n");
    let (position, delimiter_len) = match (lf, crlf) {
        (Some(lf), Some(crlf)) if lf <= crlf => (lf, 2),
        (Some(_), Some(crlf)) => (crlf, 4),
        (Some(lf), None) => (lf, 2),
        (None, Some(crlf)) => (crlf, 4),
        (None, None) => return Ok(None),
    };
    if position > maximum {
        return Err(HermesAgentError::InvalidStream {
            endpoint_id: endpoint_id.to_owned(),
            message: format!("SSE frame exceeded {maximum} bytes"),
        });
    }
    let frame = buffer[..position].to_vec();
    buffer.drain(..position + delimiter_len);
    Ok(Some(frame))
}

fn parse_sse_frame_bytes(
    frame: &[u8],
    endpoint_id: &str,
) -> Result<Option<HermesSseEvent>, HermesAgentError> {
    let frame = std::str::from_utf8(frame).map_err(|_| HermesAgentError::InvalidStream {
        endpoint_id: endpoint_id.to_owned(),
        message: "SSE frame is not valid UTF-8".to_owned(),
    })?;
    Ok(parse_sse_frame(frame))
}

fn parse_sse_frame(frame: &str) -> Option<HermesSseEvent> {
    let mut event = None;
    let mut id = None;
    let mut data_lines = Vec::new();

    for raw_line in frame.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (field, value) = line.split_once(':').map_or((line, ""), |(field, value)| {
            (field, value.strip_prefix(' ').unwrap_or(value))
        });
        match field {
            "event" => event = Some(value.to_owned()),
            "id" => id = Some(value.to_owned()),
            "data" => data_lines.push(value.to_owned()),
            _ => {}
        }
    }

    if data_lines.is_empty() && event.is_none() && id.is_none() {
        return None;
    }

    let raw_data = data_lines.join("\n");
    let parsed_name = parsed_event_name(&raw_data);
    let terminal = raw_data.trim() == "[DONE]"
        || event.as_deref().is_some_and(is_terminal_event_name)
        || parsed_name.as_deref().is_some_and(is_terminal_event_name);
    let data = if raw_data.trim().is_empty() {
        Value::Null
    } else if terminal && raw_data.trim() == "[DONE]" {
        Value::String("[DONE]".to_owned())
    } else {
        serde_json::from_str::<Value>(&raw_data).unwrap_or_else(|_| Value::String(raw_data.clone()))
    };
    Some(HermesSseEvent {
        event,
        id,
        data,
        raw_data,
        terminal,
    })
}

fn parsed_event_name(raw_data: &str) -> Option<String> {
    serde_json::from_str::<Value>(raw_data)
        .ok()
        .and_then(|data| {
            data.get("event")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
}

fn hermes_event_name(event: &HermesSseEvent) -> Option<&str> {
    event.event.as_deref().or_else(|| {
        event
            .data
            .get("event")
            .or_else(|| event.data.get("type"))
            .and_then(Value::as_str)
    })
}

fn is_terminal_event_name(name: &str) -> bool {
    matches!(
        name,
        "done"
            | "run.completed"
            | "run.failed"
            | "run.cancelled"
            | "response.completed"
            | "response.failed"
            | "response.incomplete"
            | "error"
    )
}

fn stream_chunk_kind(event: &HermesSseEvent) -> StreamChunkKind {
    match hermes_event_name(event) {
        Some("run.failed" | "response.failed" | "response.incomplete" | "error") => {
            StreamChunkKind::Error
        }
        Some("done" | "run.completed" | "run.cancelled" | "response.completed")
            if event.terminal =>
        {
            StreamChunkKind::Done
        }
        Some("tool.started" | "tool.completed" | "tool.failed") => StreamChunkKind::Tool,
        Some("approval.request") => StreamChunkKind::PendingApproval,
        Some("reasoning.available") => StreamChunkKind::Thought,
        _ if event.terminal => StreamChunkKind::Done,
        _ => StreamChunkKind::Data,
    }
}

fn stream_event_text(event: &HermesSseEvent) -> Option<&str> {
    event
        .data
        .get("delta")
        .or_else(|| event.data.get("text"))
        .or_else(|| event.data.get("output"))
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

fn append_event_text(text: &mut String, event: &HermesSseEvent) {
    if let Some(delta) = event
        .data
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("delta"))
        .and_then(|delta| delta.get("content"))
        .and_then(Value::as_str)
    {
        text.push_str(delta);
        return;
    }
    if let Some(delta) = event.data.get("delta").and_then(Value::as_str) {
        text.push_str(delta);
        return;
    }
    if let Some(delta) = event.data.get("text").and_then(Value::as_str)
        && event.event.as_deref() == Some("response.output_text.delta")
    {
        text.push_str(delta);
        return;
    }
    if text.is_empty()
        && let Some(content) = event
            .data
            .get("content")
            .or_else(|| event.data.get("output"))
            .and_then(Value::as_str)
    {
        text.push_str(content);
    }
}

fn action_output_result(action: Action, output: ActionOutput) -> ActionResult {
    match output {
        ActionOutput::Health(health) => health_result(action, health),
        ActionOutput::Json(output) => completed_result(action, output),
        ActionOutput::Stream(stream) => stream_result(action, *stream),
    }
}

fn health_result(action: Action, health: HermesHealth) -> ActionResult {
    let output = json!(health);
    ActionResult {
        action_id: action.id,
        status: if health_status_ok(&output) {
            ActionResultStatus::Completed
        } else {
            ActionResultStatus::Failed
        },
        output: Some(output.clone()),
        message: vec![MessagePart::text(format!(
            "Hermes endpoint health: {}",
            output
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        ))],
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    }
}

fn completed_result(action: Action, output: Value) -> ActionResult {
    let mut message = Vec::new();
    if let Some(text) = assistant_text_from_json(&output) {
        message.push(MessagePart::text(text));
    }
    message.push(MessagePart::Json {
        data: output.clone(),
        schema: None,
    });
    ActionResult {
        action_id: action.id,
        status: ActionResultStatus::Completed,
        output: Some(output),
        message,
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    }
}

fn stream_result(action: Action, stream: HermesStreamResult) -> ActionResult {
    let outcome = stream_outcome(&stream);
    let output = json!(stream);
    let mut message = Vec::new();
    if let Some(text) = output
        .get("text")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        message.push(MessagePart::text(text.to_owned()));
    }
    message.push(MessagePart::Json {
        data: output.clone(),
        schema: None,
    });
    ActionResult {
        action_id: action.id,
        status: outcome.status,
        output: Some(output),
        message,
        memory_update: None,
        usage: None,
        receipt: None,
        error: outcome.error,
    }
}

struct StreamOutcome {
    status: ActionResultStatus,
    error: Option<ProtocolError>,
}

fn stream_outcome(stream: &HermesStreamResult) -> StreamOutcome {
    let terminal_name = stream.events.iter().rev().find_map(hermes_event_name);
    if stream.truncated {
        return StreamOutcome {
            status: ActionResultStatus::Failed,
            error: Some(protocol_error(
                "connector.hermes_agent.stream_truncated",
                "Hermes stream exceeded its configured event limit".to_owned(),
                Some(json!({ "operation": stream.operation })),
            )),
        };
    }
    if !stream.terminal {
        return StreamOutcome {
            status: ActionResultStatus::Failed,
            error: Some(protocol_error(
                "connector.hermes_agent.stream_incomplete",
                "Hermes stream closed without an explicit terminal event".to_owned(),
                Some(json!({ "operation": stream.operation })),
            )),
        };
    }
    match terminal_name {
        Some("run.cancelled") => StreamOutcome {
            status: ActionResultStatus::Cancelled,
            error: None,
        },
        Some("run.failed" | "response.failed" | "response.incomplete" | "error") => {
            let provider = stream.events.last().map(|event| event.data.clone());
            StreamOutcome {
                status: ActionResultStatus::Failed,
                error: Some(protocol_error(
                    "connector.hermes_agent.stream_failed",
                    "Hermes reported a terminal stream failure".to_owned(),
                    provider,
                )),
            }
        }
        _ => StreamOutcome {
            status: ActionResultStatus::Completed,
            error: None,
        },
    }
}

fn assistant_text_from_json(output: &Value) -> Option<String> {
    output
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .filter(|content| !content.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            output
                .get("message")
                .and_then(|message| message.get("content"))
                .and_then(Value::as_str)
                .filter(|content| !content.trim().is_empty())
                .map(ToOwned::to_owned)
        })
}

fn action_result_text(result: &ActionResult) -> String {
    let mut text = result
        .message
        .iter()
        .filter_map(|part| match part {
            MessagePart::Text { text, .. } => Some(text.as_str()),
            MessagePart::Card { body, .. } => Some(body.as_str()),
            _ => None,
        })
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if text.trim().is_empty()
        && let Some(output) = &result.output
    {
        text = assistant_text_from_json(output)
            .or_else(|| serde_json::to_string_pretty(output).ok())
            .unwrap_or_else(|| format!("AIP action {} completed", result.action_id));
    }
    if text.trim().is_empty()
        && let Some(error) = &result.error
    {
        text = format!("AIP action {} failed: {}", result.action_id, error.message);
    }
    if text.trim().is_empty() {
        text = format!(
            "AIP action {} finished with {:?}",
            result.action_id, result.status
        );
    }
    text
}

fn health_status_ok(output: &Value) -> bool {
    output
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status == "ok")
        && output
            .get("http_status")
            .and_then(Value::as_u64)
            .is_some_and(|status| {
                StatusCode::from_u16(status as u16).is_ok_and(|status| status.is_success())
            })
}

fn protocol_error(code: &str, message: String, details: Option<Value>) -> ProtocolError {
    ProtocolError {
        code: code.to_owned(),
        message,
        category: ErrorCategory::Connector,
        retryable: Some(false),
        retry_after_ms: None,
        details: details.map(Box::new),
        source: Some(Box::new(json!({ "connector": CONNECTOR_ID }))),
    }
}

fn hermes_failure(error: HermesAgentError, operation: ConnectorOperation) -> ConnectorFailure {
    hermes_failure_with_retry_safety(error, operation, false)
}

fn hermes_failure_with_retry_safety(
    error: HermesAgentError,
    operation: ConnectorOperation,
    retry_safe: bool,
) -> ConnectorFailure {
    let (code, category, remote_status, uncertain_outcome) = match &error {
        HermesAgentError::UnexpectedStatus { status, .. } if matches!(*status, 401 | 403) => (
            "connector.hermes_agent.authentication",
            ErrorCategory::Auth,
            Some(*status),
            false,
        ),
        HermesAgentError::UnexpectedStatus { status, .. } if *status == 429 || *status >= 500 => (
            "connector.hermes_agent.remote_temporary",
            ErrorCategory::Temporary,
            Some(*status),
            operation == ConnectorOperation::Invocation && !retry_safe,
        ),
        HermesAgentError::UnexpectedStatus { status, .. } => (
            "connector.hermes_agent.remote_rejected",
            ErrorCategory::Permanent,
            Some(*status),
            false,
        ),
        HermesAgentError::HttpRequest { .. }
        | HermesAgentError::ResponseDecode { .. }
        | HermesAgentError::StreamDecode { .. } => (
            "connector.hermes_agent.transport",
            ErrorCategory::Transport,
            None,
            operation == ConnectorOperation::Invocation && !retry_safe,
        ),
        HermesAgentError::InvalidStream { .. } | HermesAgentError::ResponseTooLarge { .. } => (
            "connector.hermes_agent.invalid_response",
            ErrorCategory::Connector,
            None,
            operation == ConnectorOperation::Invocation && !retry_safe,
        ),
        HermesAgentError::StreamPublish { .. } => (
            "connector.hermes_agent.stream_publication",
            ErrorCategory::Connector,
            None,
            true,
        ),
        HermesAgentError::MissingApiKey(_) => (
            "connector.hermes_agent.missing_credential",
            ErrorCategory::Auth,
            None,
            false,
        ),
        HermesAgentError::Cancelled => (
            "connector.hermes_agent.cancelled",
            ErrorCategory::Temporary,
            None,
            operation == ConnectorOperation::Invocation && !retry_safe,
        ),
        HermesAgentError::DeadlineExceeded => (
            "connector.hermes_agent.deadline_exceeded",
            ErrorCategory::Temporary,
            None,
            operation == ConnectorOperation::Invocation && !retry_safe,
        ),
        HermesAgentError::TenantMismatch { .. } => (
            "connector.hermes_agent.tenant_mismatch",
            ErrorCategory::Auth,
            None,
            false,
        ),
        HermesAgentError::OperatorOutcomeUnknown(_) | HermesAgentError::OperatorTimeout(_) => (
            "connector.hermes_agent.operator_outcome_unknown",
            ErrorCategory::Temporary,
            None,
            true,
        ),
        HermesAgentError::OperatorState(_) => (
            "connector.hermes_agent.operator_state",
            ErrorCategory::Temporary,
            None,
            false,
        ),
        HermesAgentError::OperatorPolicy(_)
        | HermesAgentError::OperatorIdempotencyCollision(_)
        | HermesAgentError::OperatorBindingNotFound(_) => (
            "connector.hermes_agent.operator_policy",
            ErrorCategory::Permanent,
            None,
            false,
        ),
        HermesAgentError::NoEndpoints
        | HermesAgentError::DuplicateEndpoint
        | HermesAgentError::InvalidEndpointId(_)
        | HermesAgentError::InvalidTenantId(_)
        | HermesAgentError::InvalidDisplayName(_)
        | HermesAgentError::InvalidUrl(_)
        | HermesAgentError::InvalidUrlScheme(_)
        | HermesAgentError::InvalidBaseUrl(_)
        | HermesAgentError::InvalidApiKey(_)
        | HermesAgentError::InvalidResponseLimits(_)
        | HermesAgentError::HttpClient(_)
        | HermesAgentError::InvalidId(_)
        | HermesAgentError::EndpointNotFound(_)
        | HermesAgentError::UnsupportedCapability(_)
        | HermesAgentError::InvalidInput(_) => (
            "connector.hermes_agent.configuration_or_input",
            ErrorCategory::Permanent,
            None,
            false,
        ),
    };
    let retryable = retry_safe
        && operation == ConnectorOperation::Invocation
        && !uncertain_outcome
        && !matches!(
            error,
            HermesAgentError::Cancelled | HermesAgentError::DeadlineExceeded
        )
        && matches!(
            category,
            ErrorCategory::Temporary | ErrorCategory::Transport
        );
    ConnectorFailure {
        code: code.to_owned(),
        message: error.to_string(),
        category,
        retryable,
        retry_after_ms: None,
        provider_request_id: None,
        provider_operation: None,
        remote_status,
        uncertain_outcome,
        redacted_details: None,
        source_component: CONNECTOR_ID.to_owned(),
        operation,
    }
}

fn kind_streams(kind: HermesActionKind) -> bool {
    matches!(
        kind,
        HermesActionKind::ChatStream
            | HermesActionKind::ResponsesStream
            | HermesActionKind::RunEvents
            | HermesActionKind::SessionChatStream
    )
}

fn json_request_timeout(kind: HermesActionKind) -> std::time::Duration {
    let seconds = match kind {
        HermesActionKind::Chat | HermesActionKind::Responses | HermesActionKind::SessionChat => 300,
        HermesActionKind::RunStart | HermesActionKind::Operator => 60,
        _ => 30,
    };
    std::time::Duration::from_secs(seconds)
}

fn empty_object_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {}
    })
}

fn id_input_schema(id_name: &str) -> Value {
    json!({
        "type": "object",
        "required": [id_name],
        "properties": {
            id_name: { "type": "string", "minLength": 1 },
            "session_key": { "type": "string" },
            "max_events": { "type": "integer", "minimum": 1, "maximum": MAX_SSE_EVENT_LIMIT }
        }
    })
}

fn job_id_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["job_id"],
        "properties": {
            "job_id": { "type": "string", "pattern": "^[a-f0-9]{12}$" }
        },
        "additionalProperties": false
    })
}

fn raw_body_schema(description: &str, streaming: bool) -> Value {
    let mut schema = json!({
        "type": "object",
        "description": description,
        "properties": {
            "body": { "type": "object" },
            "input": {},
            "model": { "type": "string" },
            "instructions": { "type": "string" },
            "conversation_history": { "type": "array" },
            "session_key": { "type": "string" },
            "idempotency_key": { "type": "string" }
        }
    });
    if streaming
        && let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut)
    {
        properties.insert(
            "max_events".to_owned(),
            json!({ "type": "integer", "minimum": 1, "maximum": MAX_SSE_EVENT_LIMIT }),
        );
    }
    schema
}

fn chat_input_schema(streaming: bool) -> Value {
    let mut schema = json!({
        "type": "object",
        "oneOf": [
            { "required": ["prompt"] },
            { "required": ["query"] },
            { "required": ["messages"] }
        ],
        "properties": {
            "prompt": { "type": "string", "minLength": 1 },
            "query": { "type": "string", "minLength": 1 },
            "messages": { "type": "array", "minItems": 1 },
            "model": { "type": "string" },
            "session_id": { "type": "string" },
            "session_key": { "type": "string" },
            "temperature": { "type": "number" },
            "top_p": { "type": "number" },
            "max_tokens": { "type": "integer" },
            "stop": {},
            "tools": {},
            "tool_choice": {},
            "response_format": {},
            "user": { "type": "string" },
            "metadata": { "type": "object" },
            "idempotency_key": { "type": "string" }
        }
    });
    if streaming
        && let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut)
    {
        properties.insert(
            "max_events".to_owned(),
            json!({ "type": "integer", "minimum": 1, "maximum": MAX_SSE_EVENT_LIMIT }),
        );
    }
    schema
}

#[cfg(test)]
mod tests {
    use super::{
        HERMES_ACTION_KINDS, HermesActionKind, HermesAgentConnector, HermesAgentEndpoint,
        HermesAgentError, HermesStreamResult, MAX_REQUEST_BODY_BYTES, MAX_SSE_EVENT_LIMIT,
        StandardHeaders, aip_context_from_memory, append_event_text, apply_standard_headers,
        build_chat_payload, chat_request_from_input, ensure_hermes_request_size,
        hermes_failure_with_retry_safety, max_events_from_input, parse_sse_frame,
        parse_sse_frame_bytes, path_for_kind, query_pairs_for_kind, stream_chunk_kind,
        stream_result, take_sse_frame,
    };
    use aip_auth::{AuthScheme, AuthenticatedPrincipal};
    use aip_connector::{
        ChannelConnector, ConnectorContext, ConnectorOperation, ConnectorSecret,
        FrozenConnectorHandler,
    };
    use aip_core::{
        Action, ActionId, ActionResult, ActionResultStatus, Cancel, CancelTarget, CapabilityId,
        CapabilityKind, DataSensitivity, Envelope, IdempotencyRequirement, MessageBody,
        PrincipalKind,
    };
    use aip_runtime::{ActionHandler, MessageContext, Runtime};
    use axum::{
        Json, Router,
        body::Body,
        extract::State,
        http::{HeaderMap, Response},
        routing::{patch, post},
    };
    use bytes::Bytes;
    use serde_json::{Value, json};
    use std::{
        collections::HashMap,
        convert::Infallible,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
    };
    use url::Url;

    type CapturedJobUpdate = Arc<Mutex<Option<(HeaderMap, Value)>>>;

    async fn mock_incremental_chat_stream() -> Response<Body> {
        let frames = vec![
            "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n".to_owned(),
            "data: [DONE]\n\n".to_owned(),
        ];
        let stream = futures_util::stream::unfold(
            (frames.into_iter(), false),
            |(mut frames, emitted_first)| async move {
                let frame = frames.next()?;
                if emitted_first {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Some((Ok::<_, Infallible>(Bytes::from(frame)), (frames, true)))
            },
        );
        Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .body(Body::from_stream(stream))
            .expect("mock SSE response")
    }

    async fn capture_session_chat(
        State(captured): State<Arc<Mutex<Option<Value>>>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        *captured.lock().expect("capture lock") = Some(body);
        Json(json!({ "status": "completed" }))
    }

    async fn capture_job_update(
        State(captured): State<CapturedJobUpdate>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        *captured.lock().expect("capture lock") = Some((headers, body));
        Json(json!({ "job": { "id": "abcdef123456", "enabled": false } }))
    }

    struct PendingHermesStream {
        first: bool,
        dropped: Arc<AtomicBool>,
    }

    impl futures_util::Stream for PendingHermesStream {
        type Item = Result<Bytes, Infallible>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            if self.first {
                self.first = false;
                return Poll::Ready(Some(Ok(Bytes::from_static(
                    b"data: {\"choices\":[{\"delta\":{\"content\":\"started\"}}]}\n\n",
                ))));
            }
            Poll::Pending
        }
    }

    impl Drop for PendingHermesStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    async fn mock_cancellable_chat_stream(
        State(dropped): State<Arc<AtomicBool>>,
    ) -> Response<Body> {
        Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .body(Body::from_stream(PendingHermesStream {
                first: true,
                dropped,
            }))
            .expect("mock cancellable SSE response")
    }

    #[test]
    fn manifest_exposes_all_hermes_operations_for_each_endpoint() {
        let endpoint = HermesAgentEndpoint::new(
            "Hermes-A",
            "http://localhost:8642",
            Some("secret".to_owned()),
        )
        .expect("endpoint");
        let connector = HermesAgentConnector::new(vec![endpoint]).expect("connector");
        let manifest = connector.discover_manifest().expect("manifest");

        assert_eq!(manifest.capabilities.len(), HERMES_ACTION_KINDS.len());
        for kind in HERMES_ACTION_KINDS {
            let expected = format!("cap:hermes_agent:hermes-a:{}", kind.operation());
            assert!(
                manifest
                    .capabilities
                    .iter()
                    .any(|capability| capability.id.as_str() == expected),
                "missing capability {expected}"
            );
        }
        assert!(
            manifest
                .capabilities
                .iter()
                .all(|capability| capability.kind != CapabilityKind::Resource),
            "every published Hermes API operation must be action-routable"
        );
    }

    #[test]
    fn pinned_upstream_route_matrix_covers_every_published_operation() {
        let matrix = [
            (
                HermesActionKind::Health,
                reqwest::Method::GET,
                "/health",
                false,
                false,
            ),
            (
                HermesActionKind::HealthDetailed,
                reqwest::Method::GET,
                "/health/detailed",
                true,
                false,
            ),
            (
                HermesActionKind::Models,
                reqwest::Method::GET,
                "/v1/models",
                true,
                false,
            ),
            (
                HermesActionKind::ApiCapabilities,
                reqwest::Method::GET,
                "/v1/capabilities",
                true,
                false,
            ),
            (
                HermesActionKind::Skills,
                reqwest::Method::GET,
                "/v1/skills",
                true,
                false,
            ),
            (
                HermesActionKind::Toolsets,
                reqwest::Method::GET,
                "/v1/toolsets",
                true,
                false,
            ),
            (
                HermesActionKind::Chat,
                reqwest::Method::POST,
                "/v1/chat/completions",
                true,
                true,
            ),
            (
                HermesActionKind::ChatStream,
                reqwest::Method::POST,
                "/v1/chat/completions",
                true,
                true,
            ),
            (
                HermesActionKind::Responses,
                reqwest::Method::POST,
                "/v1/responses",
                true,
                true,
            ),
            (
                HermesActionKind::ResponsesStream,
                reqwest::Method::POST,
                "/v1/responses",
                true,
                true,
            ),
            (
                HermesActionKind::ResponseGet,
                reqwest::Method::GET,
                "/v1/responses/response-1",
                true,
                false,
            ),
            (
                HermesActionKind::ResponseDelete,
                reqwest::Method::DELETE,
                "/v1/responses/response-1",
                true,
                false,
            ),
            (
                HermesActionKind::RunStart,
                reqwest::Method::POST,
                "/v1/runs",
                true,
                true,
            ),
            (
                HermesActionKind::RunStatus,
                reqwest::Method::GET,
                "/v1/runs/run-1",
                true,
                false,
            ),
            (
                HermesActionKind::RunEvents,
                reqwest::Method::GET,
                "/v1/runs/run-1/events",
                true,
                false,
            ),
            (
                HermesActionKind::RunApproval,
                reqwest::Method::POST,
                "/v1/runs/run-1/approval",
                true,
                true,
            ),
            (
                HermesActionKind::RunStop,
                reqwest::Method::POST,
                "/v1/runs/run-1/stop",
                true,
                false,
            ),
            (
                HermesActionKind::Operator,
                reqwest::Method::POST,
                "/v1/runs",
                true,
                true,
            ),
            (
                HermesActionKind::SessionsList,
                reqwest::Method::GET,
                "/api/sessions",
                true,
                false,
            ),
            (
                HermesActionKind::SessionCreate,
                reqwest::Method::POST,
                "/api/sessions",
                true,
                true,
            ),
            (
                HermesActionKind::SessionGet,
                reqwest::Method::GET,
                "/api/sessions/session-1",
                true,
                false,
            ),
            (
                HermesActionKind::SessionPatch,
                reqwest::Method::PATCH,
                "/api/sessions/session-1",
                true,
                true,
            ),
            (
                HermesActionKind::SessionDelete,
                reqwest::Method::DELETE,
                "/api/sessions/session-1",
                true,
                false,
            ),
            (
                HermesActionKind::SessionMessages,
                reqwest::Method::GET,
                "/api/sessions/session-1/messages",
                true,
                false,
            ),
            (
                HermesActionKind::SessionFork,
                reqwest::Method::POST,
                "/api/sessions/session-1/fork",
                true,
                true,
            ),
            (
                HermesActionKind::SessionChat,
                reqwest::Method::POST,
                "/api/sessions/session-1/chat",
                true,
                true,
            ),
            (
                HermesActionKind::SessionChatStream,
                reqwest::Method::POST,
                "/api/sessions/session-1/chat/stream",
                true,
                true,
            ),
            (
                HermesActionKind::JobsList,
                reqwest::Method::GET,
                "/api/jobs",
                true,
                false,
            ),
            (
                HermesActionKind::JobCreate,
                reqwest::Method::POST,
                "/api/jobs",
                true,
                true,
            ),
            (
                HermesActionKind::JobGet,
                reqwest::Method::GET,
                "/api/jobs/abcdef123456",
                true,
                false,
            ),
            (
                HermesActionKind::JobUpdate,
                reqwest::Method::PATCH,
                "/api/jobs/abcdef123456",
                true,
                true,
            ),
            (
                HermesActionKind::JobDelete,
                reqwest::Method::DELETE,
                "/api/jobs/abcdef123456",
                true,
                false,
            ),
            (
                HermesActionKind::JobPause,
                reqwest::Method::POST,
                "/api/jobs/abcdef123456/pause",
                true,
                false,
            ),
            (
                HermesActionKind::JobResume,
                reqwest::Method::POST,
                "/api/jobs/abcdef123456/resume",
                true,
                false,
            ),
            (
                HermesActionKind::JobRun,
                reqwest::Method::POST,
                "/api/jobs/abcdef123456/run",
                true,
                false,
            ),
        ];
        assert_eq!(matrix.len(), 35);
        assert_eq!(matrix.len(), HERMES_ACTION_KINDS.len());
        let input = json!({
            "response_id": "response-1",
            "run_id": "run-1",
            "session_id": "session-1",
            "job_id": "abcdef123456"
        });
        for (index, (kind, method, path, auth_required, sends_body)) in matrix.iter().enumerate() {
            assert_eq!(HERMES_ACTION_KINDS[index], *kind);
            assert_eq!(
                HermesActionKind::from_operation(kind.operation()),
                Some(*kind)
            );
            assert_eq!(kind.method(), *method, "{} method", kind.operation());
            assert_eq!(
                path_for_kind(*kind, &input).expect("pinned route path"),
                *path,
                "{} path",
                kind.operation()
            );
            assert_eq!(
                kind.auth_required(),
                *auth_required,
                "{} auth",
                kind.operation()
            );
            assert_eq!(kind.sends_body(), *sends_body, "{} body", kind.operation());
        }
    }

    #[test]
    fn manifest_exposes_enterprise_contracts_for_hermes_operations() {
        let endpoint = HermesAgentEndpoint::new(
            "Hermes-A",
            "http://localhost:8642",
            Some("secret".to_owned()),
        )
        .expect("endpoint");
        let connector = HermesAgentConnector::new(vec![endpoint]).expect("connector");
        let manifest = connector.discover_manifest().expect("manifest");

        assert!(
            manifest
                .capabilities
                .iter()
                .all(|capability| capability.contract.is_some()),
            "every Hermes capability must publish a CapabilityContract"
        );

        let session_delete = manifest
            .capabilities
            .iter()
            .find(|capability| capability.id.as_str() == "cap:hermes_agent:hermes-a:session_delete")
            .expect("session_delete capability");
        let contract = session_delete.contract.as_ref().expect("contract");

        assert_eq!(session_delete.requires_human_approval, Some(true));
        assert_eq!(
            contract.idempotency.requirement,
            IdempotencyRequirement::Required
        );
        assert_eq!(contract.data.sensitivity, DataSensitivity::Restricted);
        assert!(contract.transaction.is_none());
        assert!(!contract.execution.supports_retry);
        assert!(
            contract
                .approval
                .as_ref()
                .is_some_and(|policy| policy.required)
        );
    }

    #[test]
    fn capability_id_routes_to_endpoint_and_kind() {
        let endpoint =
            HermesAgentEndpoint::new("hermes-b", "http://localhost:8642", None).expect("endpoint");
        let capability_id = endpoint.chat_stream_capability_id().expect("capability id");
        let connector = HermesAgentConnector::new(vec![endpoint]).expect("connector");

        let (resolved, kind) = connector
            .endpoint_for_capability(&capability_id)
            .expect("resolved capability");

        assert_eq!(resolved.id, "hermes-b");
        assert_eq!(kind, HermesActionKind::ChatStream);
    }

    #[test]
    fn endpoint_validation_rejects_bad_url_scheme() {
        let result = HermesAgentEndpoint::new("bad", "ftp://localhost:8642", None);

        assert!(matches!(result, Err(HermesAgentError::InvalidUrlScheme(_))));
    }

    #[test]
    fn endpoint_validation_rejects_credentialed_or_non_origin_urls_and_bad_keys() {
        for url in [
            "https://user:password@hermes.example",
            "https://hermes.example/prefix",
            "https://hermes.example?tenant=other",
            "https://hermes.example#fragment",
        ] {
            assert!(matches!(
                HermesAgentEndpoint::new("bad", url, None),
                Err(HermesAgentError::InvalidBaseUrl(_))
            ));
        }
        assert!(matches!(
            HermesAgentEndpoint::new("bad", "https://hermes.example", Some(" \n".to_owned())),
            Err(HermesAgentError::InvalidApiKey(_))
        ));
        assert!(matches!(
            HermesAgentEndpoint::new("x".repeat(129), "https://hermes.example", None),
            Err(HermesAgentError::InvalidEndpointId(_))
        ));
    }

    #[test]
    fn connector_revalidates_public_endpoint_descriptors() {
        let endpoint = HermesAgentEndpoint {
            id: "Bypassed-Normalization".to_owned(),
            base_url: Url::parse("https://hermes.example").expect("endpoint URL"),
            api_key: Some(ConnectorSecret::new("valid-key")),
            display_name: Some("Hermes".to_owned()),
            tenant_id: Some("tenant-a".to_owned()),
        };
        assert!(matches!(
            HermesAgentConnector::with_client(vec![endpoint], reqwest::Client::new()),
            Err(HermesAgentError::InvalidEndpointId(_))
        ));

        let endpoint = HermesAgentEndpoint::new("valid", "https://hermes.example", None)
            .expect("endpoint")
            .with_display_name("invalid\nlabel");
        assert!(matches!(
            HermesAgentConnector::with_client(vec![endpoint], reqwest::Client::new()),
            Err(HermesAgentError::InvalidDisplayName(_))
        ));
    }

    #[test]
    fn request_body_and_standard_headers_are_bounded_before_dispatch() {
        assert!(
            ensure_hermes_request_size(&json!({
                "body": "x".repeat(MAX_REQUEST_BODY_BYTES + 1)
            }))
            .is_err()
        );
        let request = reqwest::Client::new().get("https://hermes.example/health");
        assert!(
            apply_standard_headers(
                request,
                StandardHeaders {
                    session_id: Some("invalid\nheader".to_owned()),
                    ..StandardHeaders::default()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn response_and_event_limits_fail_closed() {
        let endpoint =
            HermesAgentEndpoint::new("bounded", "http://127.0.0.1:8642", None).expect("endpoint");
        let connector = HermesAgentConnector::new(vec![endpoint]).expect("connector");
        assert!(matches!(
            connector.clone().with_response_limits(0, 1024, 512),
            Err(HermesAgentError::InvalidResponseLimits(_))
        ));
        assert!(matches!(
            connector.with_response_limits(1024, 512, 1024),
            Err(HermesAgentError::InvalidResponseLimits(_))
        ));
        assert!(max_events_from_input(&json!({ "max_events": 1 })).is_ok());
        assert!(max_events_from_input(&json!({ "max_events": 0 })).is_err());
        assert!(max_events_from_input(&json!({ "max_events": MAX_SSE_EVENT_LIMIT + 1 })).is_err());
    }

    #[test]
    fn sse_framing_handles_coalesced_frames_and_split_utf8() {
        let payload = "мир".repeat(1_024);
        let encoded = format!("data: {{\"delta\":\"{payload}\"}}\n\n");
        let frame_count = (super::DEFAULT_MAX_SSE_FRAME_BYTES / encoded.len()) + 2;
        let mut transport_chunk = encoded.repeat(frame_count).into_bytes();
        assert!(transport_chunk.len() > super::DEFAULT_MAX_SSE_FRAME_BYTES);

        let mut drained = 0;
        while let Some(frame) = take_sse_frame(
            &mut transport_chunk,
            super::DEFAULT_MAX_SSE_FRAME_BYTES,
            "bounded",
        )
        .expect("bounded frame")
        {
            let event = parse_sse_frame_bytes(&frame, "bounded")
                .expect("UTF-8 frame")
                .expect("event");
            assert!(event.raw_data.contains("мир"));
            drained += 1;
        }
        assert_eq!(drained, frame_count);
        assert!(transport_chunk.is_empty());

        let invalid_utf8 = [b'd', b'a', b't', b'a', b':', b' ', 0xff];
        assert!(parse_sse_frame_bytes(&invalid_utf8, "bounded").is_err());
    }

    #[test]
    fn endpoint_credentials_are_redacted_and_never_serialized() {
        let endpoint = HermesAgentEndpoint::new(
            "secure",
            "https://hermes.example.test",
            Some("top-secret-hermes-key".to_owned()),
        )
        .expect("endpoint");
        let debug = format!("{endpoint:?}");
        let serialized = serde_json::to_string(&endpoint).expect("serialize endpoint metadata");
        assert!(!debug.contains("top-secret-hermes-key"));
        assert!(!serialized.contains("top-secret-hermes-key"));
        assert!(!serialized.contains("api_key"));
    }

    #[test]
    fn chat_request_supports_prompt_alias_and_openai_messages() {
        let prompt = chat_request_from_input(json!({
            "query": "hello",
            "model": "cohere/north-mini-code:free"
        }))
        .expect("prompt request");
        let prompt_payload = build_chat_payload(&prompt, false).expect("prompt payload");
        assert_eq!(prompt_payload["messages"][0]["content"], "hello");
        assert_eq!(prompt_payload["stream"], false);

        let messages = chat_request_from_input(json!({
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}],
            "temperature": 0.2,
            "tools": [{"type": "function", "function": {"name": "noop"}}]
        }))
        .expect("messages request");
        let messages_payload = build_chat_payload(&messages, true).expect("messages payload");
        assert_eq!(messages_payload["messages"][0]["role"], "user");
        assert_eq!(messages_payload["temperature"], 0.2);
        assert_eq!(messages_payload["stream"], true);
    }

    #[test]
    fn dynamic_paths_are_encoded_from_action_input() {
        let run_path = path_for_kind(
            HermesActionKind::RunEvents,
            &json!({ "run_id": "run_abc123" }),
        )
        .expect("run path");
        let session_path = path_for_kind(
            HermesActionKind::SessionChat,
            &json!({ "session_id": "api/session" }),
        )
        .expect("session path");

        assert_eq!(run_path, "/v1/runs/run_abc123/events");
        assert_eq!(session_path, "/api/sessions/api%2Fsession/chat");
    }

    #[test]
    fn cron_job_ids_and_list_query_match_the_pinned_upstream_contract() {
        let path = path_for_kind(
            HermesActionKind::JobRun,
            &json!({ "job_id": "abcdef123456" }),
        )
        .expect("valid job id");
        assert_eq!(path, "/api/jobs/abcdef123456/run");
        assert!(
            path_for_kind(
                HermesActionKind::JobRun,
                &json!({ "job_id": "ABCDEF123456" })
            )
            .is_err()
        );
        assert!(
            path_for_kind(HermesActionKind::JobRun, &json!({ "job_id": "too-short" })).is_err()
        );

        assert_eq!(
            query_pairs_for_kind(
                HermesActionKind::JobsList,
                &json!({ "include_disabled": true })
            )
            .expect("job list query"),
            vec![("include_disabled".to_owned(), "true".to_owned())]
        );
    }

    #[tokio::test]
    async fn job_update_uses_fixed_route_sanitized_body_auth_and_idempotency() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener");
        let address = listener.local_addr().expect("mock address");
        let captured = Arc::new(Mutex::new(None));
        let server_state = captured.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/api/jobs/abcdef123456", patch(capture_job_update))
                    .with_state(server_state),
            )
            .await
            .expect("mock Hermes server");
        });
        let connector = HermesAgentConnector::new(vec![
            HermesAgentEndpoint::new(
                "mock",
                format!("http://{address}"),
                Some("test-api-key".to_owned()),
            )
            .expect("mock endpoint"),
        ])
        .expect("connector");

        let output = connector
            .execute_json(
                "mock",
                HermesActionKind::JobUpdate,
                json!({
                    "job_id": "abcdef123456",
                    "enabled": false,
                    "name": "Nightly reconciliation",
                    "idempotency_key": "job-update-1"
                }),
                Some(StandardHeaders {
                    idempotency_key: Some("job-update-1".to_owned()),
                    ..StandardHeaders::default()
                }),
            )
            .await
            .expect("job update");
        assert_eq!(output["job"]["id"], "abcdef123456");

        let (headers, body) = captured
            .lock()
            .expect("capture lock")
            .clone()
            .expect("captured job update");
        assert_eq!(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer test-api-key")
        );
        assert_eq!(
            headers
                .get("idempotency-key")
                .and_then(|value| value.to_str().ok()),
            Some("job-update-1")
        );
        assert_eq!(body["enabled"], false);
        assert_eq!(body["name"], "Nightly reconciliation");
        assert!(body.get("job_id").is_none());
        assert!(body.get("idempotency_key").is_none());
        server.abort();
    }

    #[test]
    fn standard_headers_use_aip_memory_context_without_input_pollution() {
        let input = json!({
            "session_id": "hermes-session",
            "idempotency_key": "idem-1"
        });
        let memory_context = json!({
            "_aip": {
                "session_id": "aip-session",
                "correlation_id": "corr-1",
                "delegation_chain": [{"from": {"id": "agent:one"}, "to": {"id": "agent:two"}}]
            }
        });
        let headers =
            StandardHeaders::from_input_with_aip(&input, aip_context_from_memory(&memory_context));

        assert_eq!(headers.session_id.as_deref(), Some("hermes-session"));
        assert_eq!(headers.idempotency_key.as_deref(), Some("idem-1"));
        assert_eq!(headers.aip_session_id.as_deref(), Some("aip-session"));
        assert_eq!(headers.aip_correlation_id.as_deref(), Some("corr-1"));
        assert!(
            headers
                .aip_delegation_chain
                .as_deref()
                .is_some_and(|value| value.contains("agent:two"))
        );
        assert!(input.get("_aip").is_none());
    }

    #[test]
    fn sse_parser_handles_openai_done_and_content_chunks() {
        let role_frame = parse_sse_frame(
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n",
        )
        .expect("role frame");
        let delta_frame = parse_sse_frame(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n",
        )
        .expect("delta frame");
        let done_frame = parse_sse_frame("data: [DONE]\n").expect("done frame");
        let mut text = String::new();

        append_event_text(&mut text, &role_frame);
        append_event_text(&mut text, &delta_frame);

        assert_eq!(text, "hi");
        assert!(done_frame.terminal);
    }

    #[test]
    fn sse_parser_handles_named_hermes_events() {
        let event =
            parse_sse_frame("event: assistant.delta\ndata: {\"delta\":\"hello\",\"seq\":1}\n")
                .expect("event");
        let mut text = String::new();

        append_event_text(&mut text, &event);

        assert_eq!(event.event.as_deref(), Some("assistant.delta"));
        assert_eq!(text, "hello");
    }

    #[test]
    fn run_failure_and_cancellation_events_map_to_native_terminal_states() {
        let failed =
            parse_sse_frame("data: {\"event\":\"run.failed\",\"error\":\"provider failed\"}\n")
                .expect("failed event");
        assert!(failed.terminal);
        assert_eq!(stream_chunk_kind(&failed), aip_core::StreamChunkKind::Error);
        let failed_result = stream_result(
            Action::new(CapabilityId::trusted("cap:test:run-events"), json!({})),
            HermesStreamResult {
                endpoint_id: "mock".to_owned(),
                operation: "run_events".to_owned(),
                http_status: 200,
                events: vec![failed],
                text: String::new(),
                terminal: true,
                truncated: false,
            },
        );
        assert_eq!(failed_result.status, ActionResultStatus::Failed);
        assert!(failed_result.error.is_some());

        let cancelled =
            parse_sse_frame("data: {\"event\":\"run.cancelled\"}\n").expect("cancel event");
        assert!(cancelled.terminal);
        let cancelled_result = stream_result(
            Action::new(CapabilityId::trusted("cap:test:run-events"), json!({})),
            HermesStreamResult {
                endpoint_id: "mock".to_owned(),
                operation: "run_events".to_owned(),
                http_status: 200,
                events: vec![cancelled],
                text: String::new(),
                terminal: true,
                truncated: false,
            },
        );
        assert_eq!(cancelled_result.status, ActionResultStatus::Cancelled);
    }

    #[test]
    fn stream_close_without_terminal_event_is_failed_not_completed() {
        let result = stream_result(
            Action::new(CapabilityId::trusted("cap:test:stream"), json!({})),
            HermesStreamResult {
                endpoint_id: "mock".to_owned(),
                operation: "chat_stream".to_owned(),
                http_status: 200,
                events: Vec::new(),
                text: String::new(),
                terminal: false,
                truncated: false,
            },
        );
        assert_eq!(result.status, ActionResultStatus::Failed);
        assert_eq!(
            result.error.as_ref().map(|error| error.code.as_str()),
            Some("connector.hermes_agent.stream_incomplete")
        );
    }

    #[test]
    fn retryable_failure_matches_read_only_implementation_support() {
        let read_only = hermes_failure_with_retry_safety(
            HermesAgentError::UnexpectedStatus {
                endpoint_id: "mock".to_owned(),
                status: 503,
                body: json!({ "error": "unavailable" }),
            },
            ConnectorOperation::Invocation,
            true,
        );
        assert!(read_only.retryable);
        assert!(!read_only.uncertain_outcome);

        let mutating = hermes_failure_with_retry_safety(
            HermesAgentError::UnexpectedStatus {
                endpoint_id: "mock".to_owned(),
                status: 503,
                body: json!({ "error": "unavailable" }),
            },
            ConnectorOperation::Invocation,
            false,
        );
        assert!(!mutating.retryable);
        assert!(mutating.uncertain_outcome);
    }

    #[test]
    fn cancellation_is_uncertain_only_for_provider_mutations() {
        let read_only = hermes_failure_with_retry_safety(
            HermesAgentError::Cancelled,
            ConnectorOperation::Invocation,
            true,
        );
        assert!(!read_only.retryable);
        assert!(!read_only.uncertain_outcome);

        let mutating = hermes_failure_with_retry_safety(
            HermesAgentError::Cancelled,
            ConnectorOperation::Invocation,
            false,
        );
        assert!(!mutating.retryable);
        assert!(mutating.uncertain_outcome);
    }

    #[test]
    fn invalid_chat_request_is_rejected() {
        let result = chat_request_from_input(json!({ "model": "empty" }));

        assert!(matches!(result, Err(HermesAgentError::InvalidInput(_))));
    }

    #[test]
    fn max_events_schema_is_only_published_for_streaming_chat() {
        let schema = HermesActionKind::Chat.input_schema();
        assert!(
            schema
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|properties| !properties.contains_key("max_events"))
        );

        let stream_schema = HermesActionKind::ChatStream.input_schema();
        let max_events = stream_schema
            .get("properties")
            .and_then(|properties| properties.get("max_events"))
            .expect("max_events property");

        assert_eq!(
            max_events,
            &json!({ "type": "integer", "minimum": 1, "maximum": MAX_SSE_EVENT_LIMIT })
        );
    }

    #[test]
    fn every_published_capability_schema_compiles_as_json_schema_2020_12() {
        for kind in HERMES_ACTION_KINDS {
            for (schema_name, schema) in [
                ("input", kind.input_schema()),
                ("output", kind.output_schema()),
            ] {
                aip_schema::compile_draft202012(&schema).unwrap_or_else(|error| {
                    panic!(
                        "{} {schema_name} schema is invalid: {error}",
                        kind.operation()
                    )
                });
            }
        }
    }

    #[tokio::test]
    async fn channel_connector_maps_ingress_and_emits_results_to_the_owned_session() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener");
        let address = listener.local_addr().expect("mock address");
        let captured = Arc::new(Mutex::new(None));
        let server_state = captured.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/api/sessions/session-1/chat", post(capture_session_chat))
                    .with_state(server_state),
            )
            .await
            .expect("mock Hermes server");
        });
        let connector = HermesAgentConnector::new(vec![
            HermesAgentEndpoint::new(
                "mock",
                format!("http://{address}"),
                Some("test-api-key".to_owned()),
            )
            .expect("mock endpoint"),
        ])
        .expect("connector");
        let action = Action::new(
            CapabilityId::trusted("cap:test:channel-ingress"),
            json!({ "message": "hello" }),
        );
        let envelopes = ChannelConnector::ingest_channel_event(
            &connector,
            &ConnectorContext::default(),
            json!({ "action": action }),
        )
        .await
        .expect("channel ingress");
        assert!(matches!(
            envelopes.as_slice(),
            [Envelope {
                body: MessageBody::Action(_),
                ..
            }]
        ));

        let mut context = ConnectorContext::default();
        context
            .metadata
            .insert("session_id".to_owned(), "session-1".to_owned());
        let result = ActionResult {
            action_id: ActionId::new(),
            status: ActionResultStatus::Completed,
            output: Some(json!({ "answer": "done" })),
            message: Vec::new(),
            memory_update: None,
            usage: None,
            receipt: None,
            error: None,
        };
        ChannelConnector::emit_channel_result(&connector, &context, result)
            .await
            .expect("channel egress");
        let body = captured
            .lock()
            .expect("capture lock")
            .clone()
            .expect("captured session request");
        let emitted: Value = serde_json::from_str(
            body.get("message")
                .and_then(Value::as_str)
                .expect("serialized action result"),
        )
        .expect("structured emitted result");
        assert_eq!(emitted, json!({ "answer": "done" }));
        server.abort();
    }

    #[tokio::test]
    async fn hermes_stream_publishes_native_chunks_before_terminal_result() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener");
        let address = listener.local_addr().expect("mock address");
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/v1/chat/completions", post(mock_incremental_chat_stream)),
            )
            .await
            .expect("mock Hermes server");
        });
        let connector = HermesAgentConnector::new(vec![
            HermesAgentEndpoint::new(
                "mock",
                format!("http://{address}"),
                Some("test-api-key".to_owned()),
            )
            .expect("endpoint"),
        ])
        .expect("connector");
        let manifest = connector.discover_manifest().expect("manifest");
        let principal = aip_core::Principal::new(
            aip_core::PrincipalId::trusted("agent:hermes-stream-test"),
            PrincipalKind::Agent,
        );
        let runtime = Runtime::new();
        let connector = Arc::new(connector);
        let handlers = manifest
            .capabilities
            .iter()
            .filter(|capability| capability.kind != aip_core::CapabilityKind::Resource)
            .map(|capability| {
                (
                    capability.id.clone(),
                    Arc::new(FrozenConnectorHandler::new(
                        connector.clone(),
                        capability.clone(),
                    )) as Arc<dyn ActionHandler>,
                )
            })
            .collect::<HashMap<_, _>>();
        runtime
            .admit_manifest_with_handlers("hermes-stream-test", manifest, handlers)
            .await
            .expect("atomic Hermes manifest admission");
        let capability_id = CapabilityId::trusted("cap:hermes_agent:mock:chat_stream");
        let action = Action::new(capability_id, json!({ "prompt": "hello" }));
        let action_id = action.id.clone();
        let execution_runtime = runtime.clone();
        let execution_principal = principal.clone();
        let execution = tokio::spawn(async move {
            execution_runtime
                .process_action(action, &execution_principal)
                .await
        });

        let first_chunk = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let chunks = runtime
                    .lifecycle
                    .stream_chunks(&action_id)
                    .await
                    .expect("stream chunks");
                if let Some(chunk) = chunks.first().cloned() {
                    break Some(chunk);
                }
                if execution.is_finished() {
                    break None;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("first incremental chunk timeout");
        let Some(first_chunk) = first_chunk else {
            let early_result = execution
                .await
                .expect("early execution task")
                .expect("early action result");
            panic!("Hermes action terminated before its first native chunk: {early_result:?}");
        };
        assert_eq!(first_chunk.sequence, 0);
        assert!(
            !execution.is_finished(),
            "first native chunk must be visible while Hermes SSE is still open"
        );
        let result = execution
            .await
            .expect("execution task")
            .expect("action result");
        assert_eq!(result.status, aip_core::ActionResultStatus::Completed);
        let chunks = runtime
            .lifecycle
            .stream_chunks(&action_id)
            .await
            .expect("terminal chunks");
        assert!(chunks.len() >= 2);
        assert!(matches!(
            chunks.last().map(|chunk| chunk.kind),
            Some(aip_core::StreamChunkKind::Done)
        ));
        server.abort();
    }

    #[tokio::test]
    async fn runtime_cancel_aborts_active_hermes_http_stream() {
        let upstream_dropped = Arc::new(AtomicBool::new(false));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener");
        let address = listener.local_addr().expect("mock address");
        let server_state = upstream_dropped.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/v1/chat/completions", post(mock_cancellable_chat_stream))
                    .with_state(server_state),
            )
            .await
            .expect("mock Hermes server");
        });
        let connector = HermesAgentConnector::new(vec![
            HermesAgentEndpoint::new(
                "mock",
                format!("http://{address}"),
                Some("test-api-key".to_owned()),
            )
            .expect("endpoint"),
        ])
        .expect("connector");
        let manifest = connector.discover_manifest().expect("manifest");
        let principal = aip_core::Principal::new(
            aip_core::PrincipalId::trusted("agent:hermes-cancel-test"),
            PrincipalKind::Agent,
        );
        let runtime = Runtime::new();
        let connector = Arc::new(connector);
        let handlers = manifest
            .capabilities
            .iter()
            .filter(|capability| capability.kind != aip_core::CapabilityKind::Resource)
            .map(|capability| {
                (
                    capability.id.clone(),
                    Arc::new(FrozenConnectorHandler::new(
                        connector.clone(),
                        capability.clone(),
                    )) as Arc<dyn ActionHandler>,
                )
            })
            .collect::<HashMap<_, _>>();
        runtime
            .admit_manifest_with_handlers("hermes-cancel-test", manifest, handlers)
            .await
            .expect("atomic Hermes manifest admission");
        let capability_id = CapabilityId::trusted("cap:hermes_agent:mock:chat_stream");
        let action = Action::new(capability_id, json!({ "prompt": "wait" }));
        let action_id = action.id.clone();
        let execution_runtime = runtime.clone();
        let execution_principal = principal.clone();
        let execution = tokio::spawn(async move {
            execution_runtime
                .process_action(action, &execution_principal)
                .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if !runtime
                    .lifecycle
                    .stream_chunks(&action_id)
                    .await
                    .expect("stream chunks")
                    .is_empty()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("first upstream chunk");

        let cancel = runtime
            .handle_cancel(
                Cancel {
                    target: CancelTarget::Action(action_id.clone()),
                    reason: Some("operator cancelled streaming response".to_owned()),
                },
                MessageContext {
                    actor: Some(principal.clone()),
                    authenticated: Some(AuthenticatedPrincipal {
                        principal,
                        scheme: AuthScheme::DidProof,
                        issuer: "test://hermes-edge".to_owned(),
                        audience: Some("aip-runtime".to_owned()),
                        scopes: ["action:write".to_owned()].into_iter().collect(),
                        authenticated_at: time::OffsetDateTime::now_utc(),
                        expires_at: None,
                        credential_fingerprint: Some("sha256:hermes-test".to_owned()),
                    }),
                    ..MessageContext::default()
                },
            )
            .await
            .expect("cancel action");
        assert!(matches!(
            cancel,
            MessageBody::ActionResult(ref result)
                if result.status == ActionResultStatus::Cancelled
        ));
        let result = execution
            .await
            .expect("execution task")
            .expect("execution result");
        assert_eq!(result.status, ActionResultStatus::Cancelled);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !upstream_dropped.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("upstream HTTP stream was not aborted");
        assert_eq!(
            runtime
                .lifecycle
                .action_result(&action_id)
                .await
                .expect("action result lookup")
                .expect("cancelled result")
                .status,
            ActionResultStatus::Cancelled
        );
        server.abort();
    }
}
