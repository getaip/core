//! CrewAI sidecar connector mappings for AIP.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic))]

mod operations;

pub use operations::{ALL_CREW_OPERATIONS, CrewOperation, UPSTREAM_REVISION};

use aip_connector::{
    CapabilityImplementationSupport, CapabilityProviderConnector, Connector, ConnectorContext,
    ConnectorError, ConnectorFailure, ConnectorHealth, ConnectorOperation, ConnectorResult,
    ConnectorSecret, FrozenConnector, OutboundConnector,
};
use aip_core::{
    Action, ActionResult, ActionResultStatus, ApprovalPolicy, ApproverSelector, Capability,
    CapabilityContract, CapabilityId, CompensationContract, CompensationMode, DataContract,
    DataSensitivity, ErrorCategory, EvidenceRequirement, ExecutionContract, ExpectedCompletionMode,
    IdempotencyCollisionBehavior, IdempotencyContract, IdempotencyKeyScope, IdempotencyRequirement,
    MessagePart, Principal, PrincipalId, PrincipalKind, ProfileId, ProtocolError, RetrySafety,
    ServiceLevelContract, SideEffect, StreamChunk, StreamChunkKind,
};
use aip_runtime::{ActionExecutionContext, ActionHandler, RuntimeError, RuntimeResult};
use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
    str,
    time::Duration,
};
use thiserror::Error;
use url::Url;

/// Stable connector id.
pub const CONNECTOR_ID: &str = "crewai";
/// AIP profile id for CrewAI sidecar-specific binding metadata.
pub const PROFILE_ID: &str = "aip.connector.crewai.v1";
const MAX_SSE_FRAME_BYTES: usize = 1024 * 1024;
const MAX_SSE_EVENTS: usize = 100_000;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
const MAX_CREW_INPUT_BYTES: usize = 1024 * 1024;
const MAX_JSON_REQUEST_BYTES: usize = MAX_CREW_INPUT_BYTES + 64 * 1024;
const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1024;

/// Crew descriptor exposed by a Python sidecar.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CrewDescriptor {
    /// Crew id.
    pub id: String,
    /// Crew name.
    pub name: String,
    /// Crew description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Explicit operation allowlist. Missing legacy configuration receives the
    /// least-privilege run/status/events/cancel policy.
    #[serde(default = "CrewOperation::default_policy")]
    pub allowed_operations: BTreeSet<CrewOperation>,
}

/// Sidecar run request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CrewRunRequest {
    /// Crew id.
    pub crew_id: String,
    /// Action id.
    pub action_id: String,
    /// Fixed CrewAI operation.
    #[serde(default = "default_run_operation")]
    pub operation: CrewOperation,
    /// Operation input.
    pub input: Value,
    /// Timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

const fn default_run_operation() -> CrewOperation {
    CrewOperation::Run
}

/// Sidecar cancellation request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CrewCancelRequest {
    /// Crew id.
    pub crew_id: String,
    /// AIP action id to cancel.
    pub action_id: String,
    /// Optional cancellation reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Sidecar callback event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CrewCallback {
    /// Callback event name.
    pub event: String,
    /// Callback payload.
    pub payload: Value,
}

/// CrewAI HTTP sidecar connector.
#[derive(Clone)]
pub struct CrewAiSidecarConnector {
    base_url: Url,
    crews: BTreeMap<String, CrewDescriptor>,
    client: reqwest::Client,
    bearer_token: Option<ConnectorSecret>,
    max_response_bytes: usize,
}

impl fmt::Debug for CrewAiSidecarConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrewAiSidecarConnector")
            .field("base_url", &self.base_url)
            .field("crews", &self.crews)
            .field("bearer_token_configured", &self.bearer_token.is_some())
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl CrewAiSidecarConnector {
    /// Creates a connector that talks to a CrewAI sidecar service.
    pub fn new(
        base_url: impl AsRef<str>,
        crews: Vec<CrewDescriptor>,
    ) -> Result<Self, CrewAiConnectorError> {
        let base_url = validate_base_url(base_url.as_ref())?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(3_660))
            .build()
            .map_err(|error| CrewAiConnectorError::InvalidClient(error.to_string()))?;
        if crews.is_empty() {
            return Err(CrewAiConnectorError::NoCrews);
        }
        let mut configured_crews = BTreeMap::new();
        for crew in crews {
            if crew.id.trim().is_empty()
                || crew.name.trim().is_empty()
                || crew.id.len() > 256
                || crew.name.len() > 512
                || crew.id.chars().any(char::is_control)
                || crew.name.chars().any(char::is_control)
                || crew.description.as_ref().is_some_and(|description| {
                    description.len() > 16 * 1024 || description.chars().any(char::is_control)
                })
                || crew.allowed_operations.is_empty()
            {
                return Err(CrewAiConnectorError::InvalidCrew(
                    "crew id, name, and operation allowlist must be non-empty".to_owned(),
                ));
            }
            CapabilityId::parse(format!("cap:crewai:{}", crew.id))
                .map_err(|error| CrewAiConnectorError::InvalidCrew(error.to_string()))?;
            for operation in &crew.allowed_operations {
                if *operation != CrewOperation::Run {
                    CapabilityId::parse(format!("cap:crewai:{}:{}", crew.id, operation.suffix()))
                        .map_err(|error| CrewAiConnectorError::InvalidCrew(error.to_string()))?;
                }
            }
            if configured_crews.insert(crew.id.clone(), crew).is_some() {
                return Err(CrewAiConnectorError::InvalidCrew(
                    "crew ids must be unique".to_owned(),
                ));
            }
        }
        Ok(Self {
            base_url,
            crews: configured_crews,
            client,
            bearer_token: None,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        })
    }

    /// Configures the deployment bearer token expected by the sidecar.
    pub fn with_bearer_token(self, token: impl Into<String>) -> Result<Self, CrewAiConnectorError> {
        self.with_bearer_secret(ConnectorSecret::from(token.into()))
    }

    /// Configures protected bearer-token material for a production sidecar.
    pub fn with_bearer_secret(
        mut self,
        token: ConnectorSecret,
    ) -> Result<Self, CrewAiConnectorError> {
        validate_bearer_token(&token)?;
        self.bearer_token = Some(token);
        Ok(self)
    }

    /// Sets the maximum accepted blocking response or complete event stream.
    pub fn with_max_response_bytes(
        mut self,
        max_response_bytes: usize,
    ) -> Result<Self, CrewAiConnectorError> {
        if !(1..=MAX_RESPONSE_BYTES).contains(&max_response_bytes) {
            return Err(CrewAiConnectorError::InvalidCrew(format!(
                "max_response_bytes must be between 1 and {MAX_RESPONSE_BYTES}"
            )));
        }
        self.max_response_bytes = max_response_bytes;
        Ok(self)
    }

    fn authenticated(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, CrewAiConnectorError> {
        match &self.bearer_token {
            Some(token) => {
                validate_bearer_token(token)?;
                let token = token
                    .expose_str()
                    .map_err(|_| CrewAiConnectorError::InvalidCredential)?;
                Ok(request.bearer_auth(token))
            }
            None => Ok(request),
        }
    }
}

fn validate_bearer_token(token: &ConnectorSecret) -> Result<(), CrewAiConnectorError> {
    let value = token
        .expose_str()
        .map_err(|_| CrewAiConnectorError::InvalidCredential)?;
    if value.trim().is_empty()
        || value.len() > MAX_BEARER_TOKEN_BYTES
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || value.chars().any(char::is_control)
    {
        return Err(CrewAiConnectorError::InvalidCredential);
    }
    Ok(())
}

fn validate_base_url(value: &str) -> Result<Url, CrewAiConnectorError> {
    let url = Url::parse(value).map_err(CrewAiConnectorError::InvalidUrl)?;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
        || url.host_str().is_none()
    {
        return Err(CrewAiConnectorError::InvalidBaseUrl(
            "base URL must be an origin without credentials, path prefix, query, or fragment"
                .to_owned(),
        ));
    }
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(CrewAiConnectorError::InvalidBaseUrl(
            "CrewAI sidecar requires HTTPS except for an explicit loopback deployment".to_owned(),
        ));
    }
    Ok(url)
}

#[async_trait]
impl ActionHandler for CrewAiSidecarConnector {
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
        let safety = self.action_safety(&action);
        self.invoke_sidecar_streaming(action, context)
            .await
            .map_err(|error| {
                RuntimeError::Protocol(
                    crewai_failure(error, ConnectorOperation::Invocation, safety)
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
impl FrozenConnector for CrewAiSidecarConnector {
    fn implementation_support(&self, capability: &Capability) -> CapabilityImplementationSupport {
        let operation = configured_crew_operation(&self.crews, capability.id.as_str())
            .map(|(_, operation)| operation);
        let configured = operation.is_some();
        CapabilityImplementationSupport {
            invocation: configured,
            cancellation: operation.is_some_and(CrewOperation::supports_cancel),
            streaming: operation.is_some_and(CrewOperation::supports_streaming),
            retry: operation.is_some_and(|operation| !operation.is_mutation()),
            transaction: false,
            reconciliation: false,
            compensation: false,
            approval: configured,
            credentials: false,
        }
    }

    async fn invoke_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        let safety = self.action_safety(&action);
        self.invoke_sidecar_streaming(action, context)
            .await
            .map_err(|error| crewai_failure(error, ConnectorOperation::Invocation, safety))
    }

    async fn cancel_typed(
        &self,
        action: &Action,
        _context: ActionExecutionContext,
    ) -> Result<(), ConnectorFailure> {
        let safety = self.action_safety(action);
        self.cancel_sidecar(action)
            .await
            .map_err(|error| crewai_failure(error, ConnectorOperation::Cancellation, safety))
    }
}

/// CrewAI connector error.
#[derive(Debug, Error)]
pub enum CrewAiConnectorError {
    /// No crews were configured.
    #[error("at least one CrewAI crew is required")]
    NoCrews,
    /// A crew descriptor is invalid.
    #[error("invalid CrewAI crew descriptor: {0}")]
    InvalidCrew(String),
    /// Base URL failed to parse.
    #[error("invalid CrewAI sidecar URL: {0}")]
    InvalidUrl(url::ParseError),
    /// Parsed base URL violates the sidecar transport policy.
    #[error("invalid CrewAI sidecar base URL: {0}")]
    InvalidBaseUrl(String),
    /// The hardened sidecar HTTP client could not be constructed.
    #[error("invalid CrewAI sidecar HTTP client: {0}")]
    InvalidClient(String),
    /// Capability id does not match a configured crew.
    #[error("CrewAI capability `{0}` is not configured")]
    CapabilityNotFound(String),
    /// Operation is valid but not enabled for this crew or execution path.
    #[error("CrewAI operation `{0}` is not enabled for this execution path")]
    UnsupportedOperation(String),
    /// Action input is invalid for the selected operation.
    #[error("invalid CrewAI action input: {0}")]
    InvalidInput(String),
    /// HTTP request failed.
    #[error("CrewAI sidecar request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// Sidecar returned a non-success HTTP status.
    #[error("CrewAI sidecar returned HTTP {status}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// Response body.
        body: Value,
    },
    /// Sidecar emitted an invalid or unbounded SSE stream.
    #[error("invalid CrewAI sidecar event stream: {0}")]
    Stream(String),
    /// Sidecar response exceeded the configured memory bound.
    #[error("CrewAI sidecar response exceeded the configured {limit}-byte bound")]
    ResponseTooLarge {
        /// Active response-size limit.
        limit: usize,
    },
    /// Runtime cancellation raced with sidecar admission before a confirmed stop.
    #[error("CrewAI invocation was cancelled before the sidecar confirmed a stop")]
    CancelledUnconfirmed,
    /// An idempotency key required by the published contract is absent.
    #[error("CrewAI invocation requires an idempotency key")]
    MissingIdempotencyKey,
    /// Configured sidecar credential is not valid UTF-8.
    #[error("configured CrewAI sidecar credential is not valid UTF-8")]
    InvalidCredential,
}

/// Creates a manifest for CrewAI crews.
pub fn manifest_from_crews(
    crews: Vec<CrewDescriptor>,
    namespace: &str,
) -> Result<aip_core::Manifest, aip_core::IdParseError> {
    let capabilities = crews
        .into_iter()
        .map(|crew| capabilities_from_crew(&crew))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    Ok(aip_core::Manifest {
        manifest_version: "aip-manifest/v1".to_owned(),
        agent: Principal::new(
            PrincipalId::parse(format!("agent:crewai:{namespace}"))?,
            PrincipalKind::Agent,
        ),
        capabilities,
        profiles: vec![
            ProfileId::from("aip.native.http.v1"),
            ProfileId::from(PROFILE_ID),
        ],
        resources: Vec::new(),
        channels: Vec::new(),
        security: None,
        governance: None,
        limits: None,
        compatibility: Some(json!({
            "system": "crewai",
            "connector": CONNECTOR_ID,
            "sidecar": true,
            "upstream_revision": UPSTREAM_REVISION,
            "operation_catalog_size": ALL_CREW_OPERATIONS.len()
        })),
        extensions: None,
    })
}

#[async_trait]
impl Connector for CrewAiSidecarConnector {
    fn id(&self) -> &str {
        CONNECTOR_ID
    }

    async fn discover(&self, context: &ConnectorContext) -> ConnectorResult<aip_core::Manifest> {
        manifest_from_crews(
            self.crews.values().cloned().collect(),
            context.tenant_id.as_deref().unwrap_or("default"),
        )
        .map_err(|error| ConnectorError::Discovery(error.to_string()))
    }

    fn map_error(&self, error: &ConnectorError) -> ProtocolError {
        ProtocolError {
            code: "connector.crewai".to_owned(),
            message: error.to_string(),
            category: ErrorCategory::Connector,
            retryable: Some(false),
            retry_after_ms: None,
            details: None,
            source: Some(Box::new(json!({ "connector": CONNECTOR_ID }))),
        }
    }

    async fn health(&self, _context: &ConnectorContext) -> ConnectorResult<ConnectorHealth> {
        let url = self
            .base_url
            .join("/health")
            .map_err(|error| ConnectorError::Discovery(error.to_string()))?;
        let response = self
            .authenticated(self.client.get(url))
            .map_err(|error| ConnectorError::Discovery(error.to_string()))?
            .send()
            .await
            .map_err(|error| ConnectorError::Discovery(error.to_string()))?;
        let health = ensure_sidecar_success(response, self.max_response_bytes)
            .await
            .map_err(|error| ConnectorError::Discovery(error.to_string()))?;
        if health.get("status").and_then(Value::as_str) != Some("ready")
            || health.get("durable_journal").and_then(Value::as_bool) != Some(true)
        {
            return Err(ConnectorError::Discovery(
                "CrewAI sidecar is not ready with a durable journal".to_owned(),
            ));
        }
        let reported_crews = health
            .get("crews")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        if !self
            .crews
            .keys()
            .all(|crew_id| reported_crews.contains(crew_id.as_str()))
        {
            return Err(ConnectorError::Discovery(
                "CrewAI sidecar does not expose every configured crew".to_owned(),
            ));
        }
        let reported_operations = health
            .get("operations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        if !self.crews.values().all(|crew| {
            crew.allowed_operations
                .iter()
                .all(|operation| reported_operations.contains(operation.suffix()))
        }) {
            return Err(ConnectorError::Discovery(
                "CrewAI sidecar operation policy is narrower than the admitted AIP manifest"
                    .to_owned(),
            ));
        }
        Ok(ConnectorHealth {
            ready: true,
            detail: format!(
                "CrewAI sidecar is durable and exposes {} configured crew(s)",
                self.crews.len()
            ),
        })
    }
}

#[async_trait]
impl CapabilityProviderConnector for CrewAiSidecarConnector {
    async fn capabilities(&self, _context: &ConnectorContext) -> ConnectorResult<Vec<Capability>> {
        self.crews
            .values()
            .map(capabilities_from_crew)
            .collect::<Result<Vec<_>, _>>()
            .map(|capabilities| capabilities.into_iter().flatten().collect())
            .map_err(|error| ConnectorError::Discovery(error.to_string()))
    }
}

#[async_trait]
impl OutboundConnector for CrewAiSidecarConnector {
    async fn invoke(
        &self,
        _context: &ConnectorContext,
        action: Action,
    ) -> ConnectorResult<ActionResult> {
        let safety = self.action_safety(&action);
        self.invoke_sidecar(action).await.map_err(|error| {
            ConnectorError::Failure(crewai_failure(
                error,
                ConnectorOperation::Invocation,
                safety,
            ))
        })
    }

    async fn emit(
        &self,
        _context: &ConnectorContext,
        _result: ActionResult,
    ) -> ConnectorResult<()> {
        Err(ConnectorFailure::unsupported(ConnectorOperation::Emission, self.id()).into())
    }

    async fn cancel(&self, _context: &ConnectorContext, action: &Action) -> ConnectorResult<()> {
        let safety = self.action_safety(action);
        self.cancel_sidecar(action).await.map_err(|error| {
            ConnectorError::Failure(crewai_failure(
                error,
                ConnectorOperation::Cancellation,
                safety,
            ))
        })
    }
}

impl CrewAiSidecarConnector {
    fn action_safety(&self, action: &Action) -> CrewAiOperationSafety {
        configured_crew_operation(&self.crews, action.capability_id.as_str())
            .map(|(_, operation)| CrewAiOperationSafety {
                retry_safe: !operation.is_mutation(),
                mutation: operation.is_mutation(),
            })
            .unwrap_or(CrewAiOperationSafety::MUTATION_UNSAFE)
    }

    async fn cancel_sidecar(&self, action: &Action) -> Result<(), CrewAiConnectorError> {
        let (crew_id, operation) = configured_crew_action(&self.crews, action)?;
        if !operation.supports_cancel() {
            return Err(CrewAiConnectorError::UnsupportedOperation(
                operation.suffix().to_owned(),
            ));
        }
        self.cancel_job(
            &crew_id,
            &action.id.to_string(),
            Some("cancelled by AIP runtime".to_owned()),
        )
        .await
    }

    async fn cancel_job(
        &self,
        crew_id: &str,
        action_id: &str,
        reason: Option<String>,
    ) -> Result<(), CrewAiConnectorError> {
        let url = self
            .base_url
            .join(&format!("/jobs/{action_id}/cancel"))
            .map_err(CrewAiConnectorError::InvalidUrl)?;
        let request = CrewCancelRequest {
            crew_id: crew_id.to_owned(),
            action_id: action_id.to_owned(),
            reason,
        };
        ensure_crewai_request_size(&request)?;
        let response = self
            .authenticated(self.client.post(url))?
            .json(&request)
            .send()
            .await?;
        ensure_sidecar_success(response, self.max_response_bytes)
            .await
            .map(|_| ())
    }
}

impl CrewAiSidecarConnector {
    async fn stream_failure_after_admission(
        &self,
        crew_id: &str,
        action: &Action,
        operation: CrewOperation,
        error: CrewAiConnectorError,
    ) -> CrewAiConnectorError {
        if operation.supports_cancel()
            && self
                .cancel_job(
                    crew_id,
                    &action.id.to_string(),
                    Some("AIP connector rejected the sidecar event stream".to_owned()),
                )
                .await
                .is_err()
        {
            return CrewAiConnectorError::CancelledUnconfirmed;
        }
        error
    }

    async fn invoke_sidecar(&self, action: Action) -> Result<ActionResult, CrewAiConnectorError> {
        let (crew_id, operation) = configured_crew_action(&self.crews, &action)?;
        let idempotency_key = operation
            .requires_idempotency()
            .then(|| required_crewai_idempotency_key(&action))
            .transpose()?;
        let response = match operation {
            CrewOperation::Status => {
                let target = required_run_action_id(&action)?;
                let url = self
                    .base_url
                    .join(&format!("/jobs/{target}"))
                    .map_err(CrewAiConnectorError::InvalidUrl)?;
                self.authenticated(self.client.get(url))?.send().await?
            }
            CrewOperation::Events => {
                let target = required_run_action_id(&action)?;
                let mut url = self
                    .base_url
                    .join(&format!("/jobs/{target}/events"))
                    .map_err(CrewAiConnectorError::InvalidUrl)?;
                if let Some(cursor) = action.input.get("cursor").and_then(Value::as_u64) {
                    url.query_pairs_mut()
                        .append_pair("cursor", &cursor.to_string());
                }
                self.authenticated(self.client.get(url))?.send().await?
            }
            CrewOperation::Cancel => {
                let target = required_run_action_id(&action)?;
                let url = self
                    .base_url
                    .join(&format!("/jobs/{target}/cancel"))
                    .map_err(CrewAiConnectorError::InvalidUrl)?;
                let request = CrewCancelRequest {
                    crew_id,
                    action_id: target.to_owned(),
                    reason: optional_cancel_reason(&action.input)?,
                };
                ensure_crewai_request_size(&request)?;
                self.authenticated(self.client.post(url))?
                    .header("Idempotency-Key", idempotency_key.unwrap_or_default())
                    .header("X-AIP-Action-ID", action.id.to_string())
                    .json(&request)
                    .send()
                    .await?
            }
            operation => {
                let request = run_request_from_action(crew_id, operation, &action);
                ensure_crewai_run_request_size(&request)?;
                let url = self
                    .base_url
                    .join("/jobs")
                    .map_err(CrewAiConnectorError::InvalidUrl)?;
                self.authenticated(self.client.post(url))?
                    .header("Idempotency-Key", idempotency_key.unwrap_or_default())
                    .header("X-AIP-Action-ID", action.id.to_string())
                    .json(&request)
                    .send()
                    .await?
            }
        };
        let body = ensure_sidecar_success(response, self.max_response_bytes).await?;
        Ok(result_from_output(&action, body))
    }

    async fn invoke_sidecar_streaming(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, CrewAiConnectorError> {
        let (crew_id, operation) = configured_crew_action(&self.crews, &action)?;
        if !operation.supports_streaming() {
            let cancelled_action = action.clone();
            let invocation = self.invoke_sidecar(action);
            return tokio::select! {
                result = invocation => result,
                () = context.cancellation.cancelled() => {
                    if operation.is_mutation() {
                        Err(CrewAiConnectorError::CancelledUnconfirmed)
                    } else {
                        Ok(cancelled_result(
                            &cancelled_action,
                            json!({
                                "remote_stop_confirmed": false,
                                "provider_effect": "read_only",
                                "completion_unobserved": true
                            }),
                        ))
                    }
                },
            };
        }
        let request_builder = if operation == CrewOperation::Events {
            let target = required_run_action_id(&action)?;
            let mut url = self
                .base_url
                .join(&format!("/jobs/{target}/events"))
                .map_err(CrewAiConnectorError::InvalidUrl)?;
            if let Some(cursor) = action.input.get("cursor").and_then(Value::as_u64) {
                url.query_pairs_mut()
                    .append_pair("cursor", &cursor.to_string());
            }
            self.authenticated(
                self.client
                    .get(url)
                    .header(reqwest::header::ACCEPT, "text/event-stream"),
            )?
        } else {
            let key = required_crewai_idempotency_key(&action)?;
            let url = self
                .base_url
                .join("/jobs/stream")
                .map_err(CrewAiConnectorError::InvalidUrl)?;
            let request = run_request_from_action(crew_id.clone(), operation, &action);
            ensure_crewai_run_request_size(&request)?;
            self.authenticated(self.client.post(url))?
                .header("Idempotency-Key", key)
                .header("X-AIP-Action-ID", action.id.to_string())
                .json(&request)
        };
        let send = request_builder.send();
        let response = tokio::select! {
            response = send => response?,
            () = context.cancellation.cancelled() => {
                if operation.is_mutation() {
                    return Err(CrewAiConnectorError::CancelledUnconfirmed);
                }
                return Ok(cancelled_result(
                    &action,
                    json!({
                        "remote_stop_confirmed": false,
                        "provider_effect": "read_only",
                        "completion_unobserved": true
                    }),
                ));
            }
        };
        if !response.status().is_success() {
            return Err(sidecar_status_error(response, self.max_response_bytes).await);
        }

        let mut upstream = response.bytes_stream();
        let mut buffer = Vec::new();
        let initial_sequence = if operation == CrewOperation::Events {
            action
                .input
                .get("cursor")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        } else {
            0
        };
        let mut expected_sequence = initial_sequence;
        let mut response_bytes = 0_usize;
        let mut terminal_output = None;
        let mut terminal = false;
        loop {
            let next = tokio::select! {
                chunk = upstream.next() => chunk,
                () = context.cancellation.cancelled() => {
                    if operation == CrewOperation::Events {
                        return Ok(cancelled_result(
                            &action,
                            json!({
                                "remote_stop_confirmed": false,
                                "provider_effect": "read_only",
                                "stream_detached": true
                            }),
                        ));
                    }
                    if !operation.supports_cancel() {
                        return Err(CrewAiConnectorError::CancelledUnconfirmed);
                    }
                    self.cancel_job(
                        &crew_id,
                        &action.id.to_string(),
                        Some("cancelled by AIP runtime".to_owned()),
                    )
                    .await
                    .map_err(|_| CrewAiConnectorError::CancelledUnconfirmed)?;
                    return Ok(cancelled_result(
                        &action,
                        json!({ "remote_stop_confirmed": true }),
                    ));
                }
            };
            let Some(chunk) = next else {
                break;
            };
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    let error = self
                        .stream_failure_after_admission(
                            &crew_id,
                            &action,
                            operation,
                            CrewAiConnectorError::Http(error),
                        )
                        .await;
                    return Err(error);
                }
            };
            response_bytes = match response_bytes.checked_add(chunk.len()) {
                Some(response_bytes) => response_bytes,
                None => {
                    let error = self
                        .stream_failure_after_admission(
                            &crew_id,
                            &action,
                            operation,
                            CrewAiConnectorError::ResponseTooLarge {
                                limit: self.max_response_bytes,
                            },
                        )
                        .await;
                    return Err(error);
                }
            };
            if response_bytes > self.max_response_bytes {
                let error = self
                    .stream_failure_after_admission(
                        &crew_id,
                        &action,
                        operation,
                        CrewAiConnectorError::ResponseTooLarge {
                            limit: self.max_response_bytes,
                        },
                    )
                    .await;
                return Err(error);
            }
            buffer.extend_from_slice(&chunk);
            while let Some(frame) = match take_sse_frame(&mut buffer) {
                Ok(frame) => frame,
                Err(error) => {
                    let error = self
                        .stream_failure_after_admission(&crew_id, &action, operation, error)
                        .await;
                    return Err(error);
                }
            } {
                let event = match parse_sidecar_sse_frame(&frame) {
                    Ok(event) => event,
                    Err(error) => {
                        let error = self
                            .stream_failure_after_admission(&crew_id, &action, operation, error)
                            .await;
                        return Err(error);
                    }
                };
                let Some(mut event) = event else {
                    continue;
                };
                if event.sequence != expected_sequence {
                    let error = self
                        .stream_failure_after_admission(
                            &crew_id,
                            &action,
                            operation,
                            CrewAiConnectorError::Stream(format!(
                                "expected sequence {expected_sequence}, received {}",
                                event.sequence
                            )),
                        )
                        .await;
                    return Err(error);
                }
                let provider_sequence = event.sequence;
                event.sequence = provider_sequence.saturating_sub(initial_sequence);
                if event.sequence as usize >= MAX_SSE_EVENTS {
                    let error = self
                        .stream_failure_after_admission(
                            &crew_id,
                            &action,
                            operation,
                            CrewAiConnectorError::Stream(format!(
                                "SSE stream exceeded {MAX_SSE_EVENTS} events"
                            )),
                        )
                        .await;
                    return Err(error);
                }
                if let Err(error) = context
                    .stream
                    .emit(stream_chunk_from_sidecar(&action, &event))
                    .await
                {
                    let error = self
                        .stream_failure_after_admission(
                            &crew_id,
                            &action,
                            operation,
                            CrewAiConnectorError::Stream(error.to_string()),
                        )
                        .await;
                    return Err(error);
                }
                expected_sequence = provider_sequence.saturating_add(1);
                match event.event.as_str() {
                    "completed" => {
                        terminal_output = Some(event.data);
                        terminal = true;
                        break;
                    }
                    "cancelled" => {
                        return Ok(cancelled_result(&action, event.data));
                    }
                    "failed" => {
                        return Ok(failed_result(&action, event.data));
                    }
                    _ => {}
                }
            }
            // HTTP transports may coalesce many bounded SSE frames into one
            // chunk. Only an unterminated frame is subject to the frame bound.
            if buffer.len() > MAX_SSE_FRAME_BYTES {
                let error = self
                    .stream_failure_after_admission(
                        &crew_id,
                        &action,
                        operation,
                        CrewAiConnectorError::Stream(format!(
                            "SSE frame exceeded {MAX_SSE_FRAME_BYTES} bytes"
                        )),
                    )
                    .await;
                return Err(error);
            }
            if terminal {
                break;
            }
        }
        if !terminal {
            let error = self
                .stream_failure_after_admission(
                    &crew_id,
                    &action,
                    operation,
                    CrewAiConnectorError::Stream(
                        "sidecar closed before a terminal event".to_owned(),
                    ),
                )
                .await;
            return Err(error);
        }
        Ok(result_from_output(
            &action,
            terminal_output.unwrap_or(Value::Null),
        ))
    }
}

#[derive(Debug)]
struct CrewSidecarEvent {
    event: String,
    sequence: u64,
    data: Value,
}

fn required_run_action_id(action: &Action) -> Result<&str, CrewAiConnectorError> {
    let value = action
        .input
        .get("run_action_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CrewAiConnectorError::InvalidInput("missing input `run_action_id`".to_owned())
        })?;
    if value.len() > 256 || value.chars().any(char::is_control) || value.contains('/') {
        return Err(CrewAiConnectorError::InvalidInput(
            "run_action_id must be a bounded path-safe identifier".to_owned(),
        ));
    }
    Ok(value)
}

fn required_crewai_idempotency_key(action: &Action) -> Result<&str, CrewAiConnectorError> {
    action
        .idempotency_key
        .as_deref()
        .filter(|key| {
            !key.trim().is_empty() && key.len() <= 512 && !key.chars().any(char::is_control)
        })
        .ok_or(CrewAiConnectorError::MissingIdempotencyKey)
}

fn ensure_crewai_request_size<T: Serialize>(value: &T) -> Result<(), CrewAiConnectorError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| CrewAiConnectorError::InvalidInput(error.to_string()))?;
    if encoded.len() > MAX_JSON_REQUEST_BYTES {
        return Err(CrewAiConnectorError::InvalidInput(format!(
            "CrewAI sidecar request exceeds {MAX_JSON_REQUEST_BYTES} bytes"
        )));
    }
    Ok(())
}

fn ensure_crewai_run_request_size(request: &CrewRunRequest) -> Result<(), CrewAiConnectorError> {
    let input = serde_json::to_vec(&request.input)
        .map_err(|error| CrewAiConnectorError::InvalidInput(error.to_string()))?;
    if input.len() > MAX_CREW_INPUT_BYTES {
        return Err(CrewAiConnectorError::InvalidInput(format!(
            "CrewAI input exceeds {MAX_CREW_INPUT_BYTES} bytes"
        )));
    }
    ensure_crewai_request_size(request)
}

fn optional_cancel_reason(input: &Value) -> Result<Option<String>, CrewAiConnectorError> {
    let Some(reason) = input.get("reason") else {
        return Ok(None);
    };
    let reason = reason.as_str().ok_or_else(|| {
        CrewAiConnectorError::InvalidInput("cancel reason must be a string".to_owned())
    })?;
    if reason.len() > 2_048 || reason.chars().any(char::is_control) {
        return Err(CrewAiConnectorError::InvalidInput(
            "cancel reason must contain at most 2048 bytes without control characters".to_owned(),
        ));
    }
    Ok(Some(reason.to_owned()))
}

fn configured_crew_operation<'a>(
    crews: &'a BTreeMap<String, CrewDescriptor>,
    capability_id: &str,
) -> Option<(&'a CrewDescriptor, CrewOperation)> {
    let raw = capability_id.strip_prefix("cap:crewai:")?;
    if let Some(crew) = crews.get(raw)
        && crew.allowed_operations.contains(&CrewOperation::Run)
    {
        return Some((crew, CrewOperation::Run));
    }
    crews
        .iter()
        .filter_map(|(crew_id, crew)| {
            let suffix = raw.strip_prefix(crew_id)?.strip_prefix(':')?;
            let operation = CrewOperation::from_suffix(suffix)?;
            crew.allowed_operations
                .contains(&operation)
                .then_some((crew_id.len(), crew, operation))
        })
        .max_by_key(|(length, _, _)| *length)
        .map(|(_, crew, operation)| (crew, operation))
}

fn configured_crew_action(
    crews: &BTreeMap<String, CrewDescriptor>,
    action: &Action,
) -> Result<(String, CrewOperation), CrewAiConnectorError> {
    configured_crew_operation(crews, action.capability_id.as_str())
        .map(|(crew, operation)| (crew.id.clone(), operation))
        .ok_or_else(|| CrewAiConnectorError::CapabilityNotFound(action.capability_id.to_string()))
}

async fn ensure_sidecar_success(
    response: reqwest::Response,
    maximum: usize,
) -> Result<Value, CrewAiConnectorError> {
    if !response.status().is_success() {
        return Err(sidecar_status_error(response, maximum).await);
    }
    let body = bounded_sidecar_body(response, maximum).await?;
    if body.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&body).map_err(|error| {
        CrewAiConnectorError::Stream(format!("sidecar response is not valid JSON: {error}"))
    })
}

async fn sidecar_status_error(response: reqwest::Response, maximum: usize) -> CrewAiConnectorError {
    let status = response.status().as_u16();
    let body = match bounded_sidecar_body(response, maximum).await {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "error": "non_json_sidecar_error" })),
        Err(CrewAiConnectorError::ResponseTooLarge { .. }) => {
            json!({ "error": "sidecar_error_response_too_large" })
        }
        Err(_) => json!({ "error": "unreadable_sidecar_error" }),
    };
    CrewAiConnectorError::Status { status, body }
}

async fn bounded_sidecar_body(
    response: reqwest::Response,
    maximum: usize,
) -> Result<Vec<u8>, CrewAiConnectorError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(CrewAiConnectorError::ResponseTooLarge { limit: maximum });
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let next = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(CrewAiConnectorError::ResponseTooLarge { limit: maximum })?;
        if next > maximum {
            return Err(CrewAiConnectorError::ResponseTooLarge { limit: maximum });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn take_sse_frame(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>, CrewAiConnectorError> {
    let lf = buffer.windows(2).position(|window| window == b"\n\n");
    let crlf = buffer.windows(4).position(|window| window == b"\r\n\r\n");
    let (position, delimiter_len) = match (lf, crlf) {
        (Some(lf), Some(crlf)) if lf <= crlf => (lf, 2),
        (Some(_), Some(crlf)) => (crlf, 4),
        (Some(lf), None) => (lf, 2),
        (None, Some(crlf)) => (crlf, 4),
        (None, None) => return Ok(None),
    };
    if position > MAX_SSE_FRAME_BYTES {
        return Err(CrewAiConnectorError::Stream(format!(
            "SSE frame exceeded {MAX_SSE_FRAME_BYTES} bytes"
        )));
    }
    let frame = buffer[..position].to_vec();
    buffer.drain(..position + delimiter_len);
    Ok(Some(frame))
}

fn parse_sidecar_sse_frame(frame: &[u8]) -> Result<Option<CrewSidecarEvent>, CrewAiConnectorError> {
    let frame = str::from_utf8(frame)
        .map_err(|error| CrewAiConnectorError::Stream(format!("SSE is not UTF-8: {error}")))?;
    let mut event_name = None;
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
            "event" => event_name = Some(value.to_owned()),
            "data" => data_lines.push(value),
            _ => {}
        }
    }
    if data_lines.is_empty() {
        return Ok(None);
    }
    let value = serde_json::from_str::<Value>(&data_lines.join("\n")).map_err(|error| {
        CrewAiConnectorError::Stream(format!("SSE data is not valid JSON: {error}"))
    })?;
    let event = event_name
        .or_else(|| {
            value
                .get("event")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .ok_or_else(|| CrewAiConnectorError::Stream("SSE event name is missing".to_owned()))?;
    let sequence = value
        .get("sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| CrewAiConnectorError::Stream("SSE sequence is missing".to_owned()))?;
    let data = value.get("data").cloned().unwrap_or(Value::Null);
    Ok(Some(CrewSidecarEvent {
        event,
        sequence,
        data,
    }))
}

fn stream_chunk_from_sidecar(action: &Action, event: &CrewSidecarEvent) -> StreamChunk {
    let kind = match event.event.as_str() {
        "chunk" => match event.data.get("channel").and_then(Value::as_str) {
            Some("tools") => StreamChunkKind::Tool,
            Some("llm") | Some("messages") => StreamChunkKind::Data,
            _ => StreamChunkKind::Progress,
        },
        "completed" | "cancelled" => StreamChunkKind::Done,
        "failed" => StreamChunkKind::Error,
        _ => StreamChunkKind::Progress,
    };
    let part = event
        .data
        .get("content")
        .or_else(|| event.data.pointer("/data/chunk"))
        .and_then(Value::as_str)
        .filter(|content| !content.is_empty())
        .map(MessagePart::text);
    StreamChunk {
        action_id: action.id.clone(),
        sequence: event.sequence,
        kind,
        data: Some(event.data.clone()),
        part,
    }
}

fn cancelled_result(action: &Action, output: Value) -> ActionResult {
    ActionResult {
        action_id: action.id.clone(),
        status: ActionResultStatus::Cancelled,
        output: Some(output),
        message: Vec::new(),
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    }
}

fn failed_result(action: &Action, details: Value) -> ActionResult {
    ActionResult {
        action_id: action.id.clone(),
        status: ActionResultStatus::Failed,
        output: None,
        message: Vec::new(),
        memory_update: None,
        usage: None,
        receipt: None,
        error: Some(ProtocolError {
            code: "connector.crewai.execution_failed".to_owned(),
            message: "CrewAI sidecar reported a terminal execution failure".to_owned(),
            category: ErrorCategory::Connector,
            retryable: Some(false),
            retry_after_ms: None,
            details: Some(Box::new(details)),
            source: Some(Box::new(json!({ "connector": CONNECTOR_ID }))),
        }),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CrewAiOperationSafety {
    retry_safe: bool,
    mutation: bool,
}

impl CrewAiOperationSafety {
    const MUTATION_UNSAFE: Self = Self {
        retry_safe: false,
        mutation: true,
    };
}

fn crewai_failure(
    error: CrewAiConnectorError,
    operation: ConnectorOperation,
    safety: CrewAiOperationSafety,
) -> ConnectorFailure {
    let may_have_changed_remote_state = safety.mutation
        && matches!(
            operation,
            ConnectorOperation::Invocation | ConnectorOperation::Cancellation
        );
    let (code, category, retryable, remote_status, uncertain_outcome) = match &error {
        CrewAiConnectorError::Status { status, .. } if matches!(*status, 401 | 403) => (
            "connector.crewai.authentication",
            ErrorCategory::Auth,
            false,
            Some(*status),
            false,
        ),
        CrewAiConnectorError::Status { status, .. } if *status == 429 || *status >= 500 => (
            "connector.crewai.remote_temporary",
            ErrorCategory::Temporary,
            operation == ConnectorOperation::Invocation && safety.retry_safe,
            Some(*status),
            may_have_changed_remote_state,
        ),
        CrewAiConnectorError::Status { status, .. } => (
            "connector.crewai.remote_rejected",
            ErrorCategory::Permanent,
            false,
            Some(*status),
            false,
        ),
        CrewAiConnectorError::Http(error) => (
            "connector.crewai.transport",
            ErrorCategory::Transport,
            operation == ConnectorOperation::Invocation && safety.retry_safe,
            None,
            may_have_changed_remote_state && !error.is_connect(),
        ),
        CrewAiConnectorError::Stream(_) => (
            "connector.crewai.invalid_stream",
            ErrorCategory::Connector,
            operation == ConnectorOperation::Invocation && safety.retry_safe,
            None,
            may_have_changed_remote_state,
        ),
        CrewAiConnectorError::ResponseTooLarge { .. } => (
            "connector.crewai.response_too_large",
            ErrorCategory::Connector,
            false,
            None,
            may_have_changed_remote_state,
        ),
        CrewAiConnectorError::CancelledUnconfirmed => (
            "connector.crewai.cancelled_unconfirmed",
            ErrorCategory::Temporary,
            false,
            None,
            may_have_changed_remote_state,
        ),
        CrewAiConnectorError::InvalidCredential => (
            "connector.crewai.invalid_credential",
            ErrorCategory::Auth,
            false,
            None,
            false,
        ),
        CrewAiConnectorError::NoCrews
        | CrewAiConnectorError::InvalidCrew(_)
        | CrewAiConnectorError::InvalidUrl(_)
        | CrewAiConnectorError::InvalidBaseUrl(_)
        | CrewAiConnectorError::InvalidClient(_)
        | CrewAiConnectorError::CapabilityNotFound(_)
        | CrewAiConnectorError::UnsupportedOperation(_)
        | CrewAiConnectorError::InvalidInput(_)
        | CrewAiConnectorError::MissingIdempotencyKey => (
            "connector.crewai.configuration_or_input",
            ErrorCategory::Permanent,
            false,
            None,
            false,
        ),
    };
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

/// Maps a Crew descriptor to an AIP capability.
pub fn capability_from_crew(crew: CrewDescriptor) -> Result<Capability, aip_core::IdParseError> {
    crew_operation_capability(&crew, CrewOperation::Run)
}

/// Maps every explicitly allowed crew operation into a callable AIP capability.
pub fn capabilities_from_crew(
    crew: &CrewDescriptor,
) -> Result<Vec<Capability>, aip_core::IdParseError> {
    crew.allowed_operations
        .iter()
        .copied()
        .map(|operation| crew_operation_capability(crew, operation))
        .collect()
}

fn crew_operation_capability(
    crew: &CrewDescriptor,
    operation: CrewOperation,
) -> Result<Capability, aip_core::IdParseError> {
    let id = if operation == CrewOperation::Run {
        CapabilityId::parse(format!("cap:crewai:{}", crew.id))?
    } else {
        CapabilityId::parse(format!("cap:crewai:{}:{}", crew.id, operation.suffix()))?
    };
    Ok(Capability {
        id,
        name: format!("CrewAI {}: {}", crew.name, operation.display_name()),
        kind: operation.capability_kind(),
        input_schema: crew_operation_input_schema(operation),
        output_schema: Some(crew_operation_output_schema(operation)),
        description: Some(format!(
            "{} Maps to CrewAI {} at upstream revision {}.",
            crew.description.as_deref().unwrap_or("Configured CrewAI crew."),
            operation.display_name(),
            UPSTREAM_REVISION
        )),
        risk: Some(operation.risk()),
        stability: None,
        cost: None,
        auth: None,
        bindings: vec![
            aip_core::Binding {
                profile: ProfileId::from("aip.native.http.v1"),
                metadata: json!({
                    "method": "POST",
                    "sidecar_method": operation.method(),
                    "sidecar_path_template": operation.path_template(),
                    "sidecar_stream_path": operation.supports_streaming().then_some("/jobs/stream"),
                    "sidecar_cancel_path_template": operation.supports_cancel().then_some("/jobs/{action_id}/cancel"),
                    "message_type": "aip.core.v1.action"
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            },
            aip_core::Binding {
                profile: ProfileId::from(PROFILE_ID),
                metadata: json!({
                    "system": "crewai",
                    "connector": CONNECTOR_ID,
                    "crew_id": crew.id,
                    "operation": operation.suffix(),
                    "upstream_revision": UPSTREAM_REVISION
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            },
        ],
        requires_human_approval: Some(operation.is_mutation()),
        contract: Some(crewai_contract(operation)),
    })
}

fn crew_operation_input_schema(operation: CrewOperation) -> Value {
    match operation {
        CrewOperation::Run => json!({
            "type": "object",
            "description": "Inputs passed to CrewAI Crew.akickoff",
            "maxProperties": 512,
            "additionalProperties": true
        }),
        CrewOperation::Status => json!({
            "type": "object",
            "required": ["run_action_id"],
            "properties": {
                "run_action_id": { "type": "string", "minLength": 1, "maxLength": 256 }
            },
            "additionalProperties": false
        }),
        CrewOperation::Cancel => json!({
            "type": "object",
            "required": ["run_action_id"],
            "properties": {
                "run_action_id": { "type": "string", "minLength": 1, "maxLength": 256 },
                "reason": { "type": "string", "maxLength": 2048 }
            },
            "additionalProperties": false
        }),
        CrewOperation::Events => json!({
            "type": "object",
            "required": ["run_action_id"],
            "properties": {
                "run_action_id": { "type": "string", "minLength": 1, "maxLength": 256 },
                "cursor": { "type": "integer", "minimum": 0, "maximum": 100000 }
            },
            "additionalProperties": false
        }),
        CrewOperation::BatchRun => json!({
            "type": "object",
            "required": ["inputs"],
            "properties": {
                "inputs": { "type": "array", "minItems": 1, "maxItems": 100, "items": { "type": "object", "maxProperties": 512 } }
            },
            "additionalProperties": false
        }),
        CrewOperation::Replay => json!({
            "type": "object",
            "required": ["task_id"],
            "properties": {
                "task_id": { "type": "string", "minLength": 1, "maxLength": 256 },
                "inputs": { "type": "object", "maxProperties": 512 }
            },
            "additionalProperties": false
        }),
        CrewOperation::Train => json!({
            "type": "object",
            "required": ["n_iterations", "artifact_name"],
            "properties": {
                "n_iterations": { "type": "integer", "minimum": 1, "maximum": 100 },
                "artifact_name": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" },
                "inputs": { "type": "object", "maxProperties": 512 }
            },
            "additionalProperties": false
        }),
        CrewOperation::Test => json!({
            "type": "object",
            "required": ["n_iterations", "eval_llm"],
            "properties": {
                "n_iterations": { "type": "integer", "minimum": 1, "maximum": 100 },
                "eval_llm": { "type": "string", "minLength": 1, "maxLength": 256 },
                "inputs": { "type": "object", "maxProperties": 512 }
            },
            "additionalProperties": false
        }),
        CrewOperation::KnowledgeQuery => json!({
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": { "type": "array", "minItems": 1, "maxItems": 100, "items": { "type": "string", "minLength": 1, "maxLength": 4096 } },
                "results_limit": { "type": "integer", "minimum": 1, "maximum": 100 },
                "score_threshold": { "type": "number", "minimum": 0, "maximum": 1 }
            },
            "additionalProperties": false
        }),
        CrewOperation::MemoryReset => json!({
            "type": "object",
            "required": ["command_type"],
            "properties": {
                "command_type": { "type": "string", "enum": ["memory", "knowledge", "agent_knowledge", "kickoff_outputs", "all"] }
            },
            "additionalProperties": false
        }),
    }
}

fn crew_operation_output_schema(operation: CrewOperation) -> Value {
    if operation == CrewOperation::Run {
        json!({
            "type": "object",
            "required": ["raw", "token_usage"],
            "properties": {
                "raw": { "type": "string" },
                "json_dict": { "type": ["object", "null"] },
                "pydantic": { "type": ["object", "null"] },
                "tasks_output": { "type": "array" },
                "token_usage": { "type": "object" }
            },
            "additionalProperties": true
        })
    } else {
        json!({ "type": "object", "additionalProperties": true })
    }
}

fn crewai_contract(operation: CrewOperation) -> CapabilityContract {
    let mutation = operation.is_mutation();
    CapabilityContract {
        side_effects: if mutation {
            vec![
                SideEffect::Read,
                SideEffect::Write,
                SideEffect::ExternalNetwork,
                SideEffect::CodeExecution,
            ]
        } else {
            vec![SideEffect::Read, SideEffect::ExternalNetwork]
        },
        idempotency: IdempotencyContract {
            requirement: if operation.requires_idempotency() {
                IdempotencyRequirement::Required
            } else {
                IdempotencyRequirement::Optional
            },
            collision_behavior: IdempotencyCollisionBehavior::RevalidateInputHash,
            key_scope: IdempotencyKeyScope::Tenant,
            ttl_ms: Some(86_400_000),
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: operation.supports_streaming(),
            supports_streaming: operation.supports_streaming(),
            supports_cancel: operation.supports_cancel(),
            supports_retry: !mutation,
            expected_completion: if operation.supports_streaming() {
                ExpectedCompletionMode::Any
            } else {
                ExpectedCompletionMode::Sync
            },
            retry_safety: if mutation {
                RetrySafety::Unsafe
            } else {
                RetrySafety::Safe
            },
        },
        data: DataContract {
            sensitivity: DataSensitivity::Confidential,
            contains_pii: true,
            redaction_required: true,
            residency: None,
            retention: None,
        },
        credentials: None,
        approval: mutation.then(|| ApprovalPolicy {
            required: true,
            reason: Some("CrewAI crews may coordinate multiple agents, call external tools, or run code through a sidecar.".to_owned()),
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
            expected_latency_ms: Some(30_000),
            timeout_ms: Some(600_000),
            async_expected: operation.supports_streaming(),
            max_queue_delay_ms: Some(10_000),
            availability_target: Some("99.5%".to_owned()),
        }),
        transaction: None,
        compensation: mutation.then_some(CompensationContract {
            mode: CompensationMode::RollbackNotSupported,
            compensation_capability_id: None,
            compensation_window_ms: None,
            requires_approval: true,
        }),
    }
}

/// Converts an AIP action into a sidecar request.
#[must_use]
pub fn run_request_from_action(
    crew_id: String,
    operation: CrewOperation,
    action: &Action,
) -> CrewRunRequest {
    CrewRunRequest {
        crew_id,
        action_id: action.id.to_string(),
        operation,
        input: action.input.clone(),
        timeout_ms: action.timeout_ms,
    }
}

/// Converts an AIP cancellation into a CrewAI sidecar cancellation request.
#[must_use]
pub fn cancel_request_from_action(
    crew_id: String,
    action_id: aip_core::ActionId,
    reason: Option<String>,
) -> CrewCancelRequest {
    CrewCancelRequest {
        crew_id,
        action_id: action_id.to_string(),
        reason,
    }
}

/// Converts a Crew callback into an AIP stream chunk.
#[must_use]
pub fn stream_chunk_from_callback(
    action_id: aip_core::ActionId,
    sequence: u64,
    callback: CrewCallback,
) -> StreamChunk {
    let kind = match callback.event.as_str() {
        "agent_action" => StreamChunkKind::Tool,
        "agent_finish" => StreamChunkKind::Done,
        "error" => StreamChunkKind::Error,
        _ => StreamChunkKind::Progress,
    };
    StreamChunk {
        action_id,
        sequence,
        kind,
        data: Some(callback.payload),
        part: None,
    }
}

/// Converts a sidecar output into an AIP action result.
#[must_use]
pub fn result_from_output(action: &Action, output: Value) -> ActionResult {
    ActionResult {
        action_id: action.id.clone(),
        status: ActionResultStatus::Completed,
        output: Some(output.clone()),
        message: vec![MessagePart::Json {
            data: output,
            schema: None,
        }],
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ALL_CREW_OPERATIONS, CrewAiSidecarConnector, CrewDescriptor, CrewOperation,
        MAX_CREW_INPUT_BYTES, cancel_request_from_action, capabilities_from_crew,
        capability_from_crew, ensure_crewai_run_request_size, parse_sidecar_sse_frame,
        run_request_from_action, take_sse_frame,
    };
    use aip_connector::{Connector, ConnectorContext, ConnectorOperation, OutboundConnector};
    use aip_core::{Action, ActionResultStatus, CapabilityId, IdempotencyRequirement};
    use axum::{
        Json, Router,
        extract::{Path, State},
        http::HeaderMap,
        routing::{get, post},
    };
    use serde_json::{Value, json};
    use std::{collections::BTreeSet, env, sync::Arc};
    use tokio::{net::TcpListener, sync::Mutex};

    #[derive(Clone, Default)]
    struct SidecarState {
        requests: Arc<Mutex<Vec<(String, Value)>>>,
    }

    #[test]
    fn sidecar_configuration_and_request_payloads_are_bounded() {
        assert!(
            CrewAiSidecarConnector::new(
                "https://crewai.example/prefix",
                vec![CrewDescriptor {
                    id: "support".to_owned(),
                    name: "Support".to_owned(),
                    description: None,
                    allowed_operations: CrewOperation::default_policy(),
                }]
            )
            .is_err()
        );
        let connector = CrewAiSidecarConnector::new(
            "https://crewai.example",
            vec![CrewDescriptor {
                id: "support".to_owned(),
                name: "Support".to_owned(),
                description: None,
                allowed_operations: CrewOperation::default_policy(),
            }],
        )
        .expect("connector");
        assert!(connector.with_bearer_token("invalid\ncredential").is_err());
        let action = Action::new(
            CapabilityId::trusted("cap:crewai:support"),
            json!({ "payload": "x".repeat(MAX_CREW_INPUT_BYTES + 1) }),
        );
        let request = run_request_from_action("support".to_owned(), CrewOperation::Run, &action);
        assert!(ensure_crewai_run_request_size(&request).is_err());
    }

    #[tokio::test]
    async fn sidecar_run_and_cancel_use_stable_aip_action_identity() {
        let state = SidecarState::default();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock sidecar");
        let address = listener.local_addr().expect("sidecar address");
        let app = Router::new()
            .route("/jobs", post(run))
            .route("/jobs/{action_id}/cancel", post(cancel))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve sidecar");
        });
        let connector = CrewAiSidecarConnector::new(
            format!("http://{address}"),
            vec![CrewDescriptor {
                id: "support".to_owned(),
                name: "Support".to_owned(),
                description: None,
                allowed_operations: CrewOperation::default_policy(),
            }],
        )
        .expect("connector")
        .with_bearer_token("sidecar-secret")
        .expect("valid sidecar credential");
        assert!(!format!("{connector:?}").contains("sidecar-secret"));
        let mut action = Action::new(
            CapabilityId::trusted("cap:crewai:support"),
            json!({ "case_id": "case-1" }),
        );
        action.idempotency_key = Some("case-1-run".to_owned());
        let result = connector
            .invoke(&ConnectorContext::default(), action.clone())
            .await
            .expect("run crew");
        assert_eq!(result.status, ActionResultStatus::Completed);
        assert_eq!(result.output, Some(json!({ "decision": "approved" })));
        connector
            .cancel(&ConnectorContext::default(), &action)
            .await
            .expect("cancel crew");

        let requests = state.requests.lock().await;
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].0, "run");
        assert_eq!(requests[0].1.get("action_id"), Some(&json!(action.id)));
        assert_eq!(requests[1].0, "cancel");
        assert_eq!(requests[1].1.get("action_id"), Some(&json!(action.id)));
        server.abort();
    }

    #[tokio::test]
    async fn every_job_operation_uses_the_frozen_route_and_replay_headers() {
        let state = SidecarState::default();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock sidecar");
        let address = listener.local_addr().expect("sidecar address");
        let app = Router::new()
            .route("/jobs", post(run))
            .route("/health", get(health))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve sidecar");
        });
        let all_operations = ALL_CREW_OPERATIONS.iter().copied().collect();
        let connector = CrewAiSidecarConnector::new(
            format!("http://{address}"),
            vec![CrewDescriptor {
                id: "operations".to_owned(),
                name: "Operations".to_owned(),
                description: None,
                allowed_operations: all_operations,
            }],
        )
        .expect("connector")
        .with_bearer_token("sidecar-secret")
        .expect("valid sidecar credential");

        Connector::health(&connector, &ConnectorContext::default())
            .await
            .expect("sidecar health");
        let inputs = [
            (CrewOperation::Run, json!({ "case_id": "case-1" })),
            (
                CrewOperation::BatchRun,
                json!({ "inputs": [{ "case_id": "case-1" }] }),
            ),
            (
                CrewOperation::Replay,
                json!({ "task_id": "task-1", "inputs": {} }),
            ),
            (
                CrewOperation::Train,
                json!({ "n_iterations": 1, "artifact_name": "training.json" }),
            ),
            (
                CrewOperation::Test,
                json!({ "n_iterations": 1, "eval_llm": "test-model" }),
            ),
            (
                CrewOperation::KnowledgeQuery,
                json!({ "query": ["policy"] }),
            ),
            (
                CrewOperation::MemoryReset,
                json!({ "command_type": "kickoff_outputs" }),
            ),
        ];
        for (index, (operation, input)) in inputs.into_iter().enumerate() {
            let capability = if operation == CrewOperation::Run {
                "cap:crewai:operations".to_owned()
            } else {
                format!("cap:crewai:operations:{}", operation.suffix())
            };
            let mut action = Action::new(CapabilityId::trusted(capability), input);
            action.idempotency_key = Some(format!("operation-{index}"));
            let result = connector
                .invoke(&ConnectorContext::default(), action)
                .await
                .expect("invoke job operation");
            assert_eq!(result.status, ActionResultStatus::Completed);
        }

        let requests = state.requests.lock().await;
        assert_eq!(requests.len(), 7);
        assert_eq!(
            requests
                .iter()
                .map(|(_, request)| request["operation"].as_str().expect("operation"))
                .collect::<BTreeSet<_>>(),
            [
                "run",
                "batch_run",
                "replay",
                "train",
                "test",
                "knowledge_query",
                "memory_reset",
            ]
            .into_iter()
            .collect()
        );
        server.abort();
    }

    #[tokio::test]
    #[ignore = "requires the exact-upstream CrewAI qualification sidecar"]
    async fn exact_upstream_sidecar_executes_a_real_crewai_crew() {
        let base_url = env::var("AIP_E2E_CREWAI_URL")
            .expect("AIP_E2E_CREWAI_URL must identify the qualification sidecar");
        let crew_id = env::var("AIP_E2E_CREWAI_CREW_ID")
            .expect("AIP_E2E_CREWAI_CREW_ID must identify a registered CrewAI crew");
        let mut connector = CrewAiSidecarConnector::new(
            base_url,
            vec![CrewDescriptor {
                id: crew_id.clone(),
                name: "Exact upstream CrewAI qualification".to_owned(),
                description: Some(
                    "Real CrewAI Agent, Task, Crew, streaming output, and terminal result"
                        .to_owned(),
                ),
                allowed_operations: CrewOperation::default_policy(),
            }],
        )
        .expect("qualification connector");
        if let Ok(token) = env::var("AIP_E2E_CREWAI_BEARER_TOKEN") {
            connector = connector
                .with_bearer_token(token)
                .expect("valid CrewAI qualification credential");
        }
        let mut action = Action::new(
            CapabilityId::trusted(format!("cap:crewai:{crew_id}")),
            json!({ "case_id": "AIP-QUALIFICATION" }),
        );
        action.idempotency_key = Some("aip-crewai-exact-upstream-v1".to_owned());
        let result = connector
            .invoke(&ConnectorContext::default(), action)
            .await
            .expect("real CrewAI execution through the Rust connector");
        assert_eq!(result.status, ActionResultStatus::Completed);
        let output = result.output.expect("CrewAI terminal output");
        assert_eq!(output.get("raw"), Some(&json!("case triaged")));
        assert_eq!(output.pointer("/token_usage/total_tokens"), Some(&json!(5)));
    }

    #[test]
    fn capability_advertises_native_sidecar_streaming() {
        let capability = capability_from_crew(CrewDescriptor {
            id: "support".to_owned(),
            name: "Support".to_owned(),
            description: None,
            allowed_operations: CrewOperation::default_policy(),
        })
        .expect("capability");
        assert!(
            capability
                .contract
                .expect("contract")
                .execution
                .supports_streaming
        );
    }

    #[test]
    fn full_operation_catalog_is_unique_and_matches_idempotency_contracts() {
        let operations = ALL_CREW_OPERATIONS.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(operations.len(), 10);
        let capabilities = capabilities_from_crew(&CrewDescriptor {
            id: "full".to_owned(),
            name: "Full".to_owned(),
            description: None,
            allowed_operations: operations,
        })
        .expect("capabilities");
        assert_eq!(capabilities.len(), 10);
        assert_eq!(
            capabilities
                .iter()
                .map(|capability| capability.id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            10
        );
        for capability in capabilities {
            let operation = if capability.id.as_str() == "cap:crewai:full" {
                CrewOperation::Run
            } else {
                CrewOperation::from_suffix(
                    capability
                        .id
                        .as_str()
                        .strip_prefix("cap:crewai:full:")
                        .expect("operation suffix"),
                )
                .expect("known operation")
            };
            let contract = capability.contract.expect("contract");
            let requirement = contract.idempotency.requirement;
            assert_eq!(
                requirement,
                if operation.requires_idempotency() {
                    IdempotencyRequirement::Required
                } else {
                    IdempotencyRequirement::Optional
                }
            );
            assert_eq!(
                contract.execution.supports_cancel,
                matches!(operation, CrewOperation::Run | CrewOperation::BatchRun)
            );
        }
    }

    #[test]
    fn runtime_failures_match_the_published_retry_and_uncertainty_contract() {
        let connector = CrewAiSidecarConnector::new(
            "http://127.0.0.1:9",
            vec![CrewDescriptor {
                id: "support".to_owned(),
                name: "Support".to_owned(),
                description: None,
                allowed_operations: ALL_CREW_OPERATIONS.iter().copied().collect(),
            }],
        )
        .expect("connector");

        let status = Action::new(
            CapabilityId::trusted("cap:crewai:support:status"),
            json!({ "run_action_id": "action-1" }),
        );
        let read_failure = super::crewai_failure(
            super::CrewAiConnectorError::Status {
                status: 503,
                body: json!({ "error": "unavailable" }),
            },
            ConnectorOperation::Invocation,
            connector.action_safety(&status),
        );
        assert!(read_failure.retryable);
        assert!(!read_failure.uncertain_outcome);

        let run = Action::new(
            CapabilityId::trusted("cap:crewai:support"),
            json!({ "case_id": "case-1" }),
        );
        let mutation_failure = super::crewai_failure(
            super::CrewAiConnectorError::CancelledUnconfirmed,
            ConnectorOperation::Invocation,
            connector.action_safety(&run),
        );
        assert!(!mutation_failure.retryable);
        assert!(mutation_failure.uncertain_outcome);
    }

    #[test]
    fn sidecar_sse_parser_requires_ordering_metadata() {
        let event = parse_sidecar_sse_frame(
            b"event: chunk\ndata: {\"event\":\"chunk\",\"sequence\":7,\"data\":{\"content\":\"hello\"}}\n",
        )
        .expect("parse sidecar event")
        .expect("sidecar event");
        assert_eq!(event.event, "chunk");
        assert_eq!(event.sequence, 7);
        assert_eq!(event.data.get("content"), Some(&json!("hello")));
        assert!(parse_sidecar_sse_frame(b"data: {\"event\":\"chunk\"}\n").is_err());
    }

    #[test]
    fn sidecar_sse_framing_accepts_coalesced_bounded_frames() {
        let payload = "x".repeat(4_096);
        let encoded = format!(
            "event: chunk\ndata: {{\"event\":\"chunk\",\"sequence\":0,\"data\":{{\"content\":\"{payload}\"}}}}\n\n"
        );
        let frame_count = (super::MAX_SSE_FRAME_BYTES / encoded.len()) + 2;
        let mut transport_chunk = encoded.repeat(frame_count).into_bytes();
        assert!(transport_chunk.len() > super::MAX_SSE_FRAME_BYTES);

        let mut drained = 0;
        while let Some(frame) = take_sse_frame(&mut transport_chunk).expect("bounded frame") {
            assert!(frame.len() <= super::MAX_SSE_FRAME_BYTES);
            drained += 1;
        }
        assert_eq!(drained, frame_count);
        assert!(transport_chunk.is_empty());

        let mut oversized = vec![b'x'; super::MAX_SSE_FRAME_BYTES + 1];
        oversized.extend_from_slice(b"\n\n");
        assert!(take_sse_frame(&mut oversized).is_err());
    }

    async fn run(
        State(state): State<SidecarState>,
        headers: HeaderMap,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer sidecar-secret")
        );
        assert!(
            headers
                .get("idempotency-key")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| !value.is_empty())
        );
        assert!(
            headers
                .get("x-aip-action-id")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| !value.is_empty())
        );
        state
            .requests
            .lock()
            .await
            .push(("run".to_owned(), request));
        Json(json!({ "decision": "approved" }))
    }

    async fn health(headers: HeaderMap) -> Json<Value> {
        assert_eq!(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer sidecar-secret")
        );
        Json(json!({
            "status": "ready",
            "durable_journal": true,
            "crews": ["operations"],
            "operations": ALL_CREW_OPERATIONS
                .iter()
                .map(|operation| operation.suffix())
                .collect::<Vec<_>>()
        }))
    }

    async fn cancel(
        State(state): State<SidecarState>,
        Path(action_id): Path<String>,
        headers: HeaderMap,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer sidecar-secret")
        );
        assert_eq!(request.get("action_id"), Some(&json!(action_id)));
        state
            .requests
            .lock()
            .await
            .push(("cancel".to_owned(), request));
        Json(json!({ "cancelled": true }))
    }

    #[test]
    fn cancellation_request_preserves_reason() {
        let action = Action::new(CapabilityId::trusted("cap:crewai:support"), json!({}));
        let request = cancel_request_from_action(
            "support".to_owned(),
            action.id,
            Some("operator request".to_owned()),
        );
        assert_eq!(request.reason.as_deref(), Some("operator request"));
    }
}
