//! Production connector between native AIP and the WA Archive linked-device service.
//!
//! The connector never opens the provider PostgreSQL database, reads its
//! cryptographic SQLite session, accepts provider filesystem paths, or starts a
//! second WhatsApp client. All external effects cross the authenticated,
//! version-pinned WA Archive HTTP contract and its ambiguity-safe outbox.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic))]

mod operations;

pub use operations::{
    ALL_WA_ARCHIVE_CONTROL_OPERATIONS, ALL_WA_ARCHIVE_OPERATIONS, ALL_WA_ARCHIVE_QUERY_OPERATIONS,
    CONNECTOR_FEED_VERSION, OPERATION_CONTRACT_SHA256, OPERATION_CONTRACT_VERSION,
    OPERATION_SCHEMA_CONTRACT_SHA256, OPERATION_SCHEMA_DOCUMENT_VERSION,
    PROVIDER_CONNECTOR_CONTRACT, PROVIDER_REVISION, WaArchiveControlOperation, WaArchiveOperation,
    WaArchiveQueryOperation, WaArchiveSafetyClass,
};

use aip_connector::{
    CapabilityImplementationSupport, CapabilityProviderConnector, Connector, ConnectorContext,
    ConnectorError, ConnectorFailure, ConnectorHealth, ConnectorOperation, ConnectorResult,
    ConnectorSecret, FrozenConnector, OutboundConnector, ReconciliationRequest,
    ReconciliationResult,
};
use aip_connector_host::ConnectorHostEventPublisher;
use aip_core::{
    Action, ActionResult, ActionResultStatus, ApprovalPolicy, ApproverSelector, Binding,
    Capability, CapabilityContract, CapabilityId, CapabilityKind, CompensationContract,
    CompensationMode, CredentialPolicy, DataContract, DataSensitivity, DryRunFidelity,
    ErrorCategory, Event, EventId, EvidenceRequirement, ExecutionContract, ExpectedCompletionMode,
    IdempotencyCollisionBehavior, IdempotencyContract, IdempotencyKeyScope, IdempotencyRequirement,
    MessagePart, Principal, PrincipalId, PrincipalKind, ProfileId, ProtocolError,
    ProviderOperationRef, RetrySafety, RiskLevel, ServiceLevelContract, SideEffect,
    TransactionContract, TransactionMode,
};
use aip_runtime::{
    ActionExecutionContext, ActionHandler, ProfileStateCasOutcome, ProfileStateStore, RuntimeError,
    RuntimeResult,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use constant_time_eq::constant_time_eq;
use futures_util::StreamExt;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{Mutex, watch};
use url::Url;
use uuid::Uuid;

/// Stable connector id used by fleet admission and provider checkpoints.
pub const CONNECTOR_ID: &str = "wa-archive";
/// AIP profile carrying WA Archive binding metadata.
pub const PROFILE_ID: &str = "aip.connector.wa_archive.v1";
/// Capability prefix for provider operations and archive reads.
pub const CAPABILITY_PREFIX: &str = "cap:wa_archive:";
/// Capability prefix for invocable archive queries.
///
/// The first WA Archive contract incorrectly published archive queries as
/// passive AIP resources under [`CAPABILITY_PREFIX`]. Capability contracts are
/// immutable after admission, so the callable form uses a distinct namespace
/// instead of mutating those historical capability ids in place.
pub const QUERY_CAPABILITY_PREFIX: &str = "cap:wa_archive:query:";
/// Channel used for provider change-feed publication.
pub const CHANGE_FEED_CHANNEL_ID: &str = "wa-archive-changes";

const DEFAULT_MAX_JSON_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_MEDIA_BYTES: usize = 32 * 1024 * 1024;
const MAX_MEDIA_BYTES: usize = 64 * 1024 * 1024;
const MAX_INLINE_MEDIA_BYTES: usize = 2 * 1024 * 1024;
const MAX_OPERATION_JSON_BYTES: usize = 256 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_REQUEST_BYTES: usize = 96 * 1024 * 1024;
const MAX_API_TOKEN_BYTES: usize = 16 * 1024;
const CONTRACT_CACHE_TTL: Duration = Duration::from_secs(60);
const OUTBOX_LONG_POLL_MS: u64 = 25_000;
const CHANGE_FEED_LONG_POLL_MS: u64 = 25_000;
const CHANGE_FEED_STALE_AFTER: Duration = Duration::from_secs(90);
// Five maximum-size provider rows remain below the default bounded HTTP
// response and AIP event-page limits.
const CHANGE_FEED_BATCH_SIZE: u32 = 5;
const CURSOR_NAMESPACE: &str = "aip.connector.wa_archive.change_feed.v1";
const EXTERNAL_ACCOUNT_ID_HEADER: &str = "x-aip-external-account-id";

type QueryParameters = Vec<(&'static str, String)>;

/// Connector construction or provider-operation failure.
#[derive(Debug, Error)]
pub enum WaArchiveConnectorError {
    /// Deployment configuration is invalid.
    #[error("invalid WA Archive connector configuration: {0}")]
    Configuration(String),
    /// AIP action input is invalid or does not match its capability.
    #[error("invalid WA Archive action: {0}")]
    InvalidAction(String),
    /// Provider authentication material is invalid.
    #[error("WA Archive credential is not valid UTF-8")]
    InvalidCredential,
    /// Provider HTTP transport failed.
    #[error("WA Archive transport failed: {0}")]
    Transport(String),
    /// Provider returned a non-success status.
    #[error("WA Archive returned HTTP {status}: {message}")]
    Remote {
        /// HTTP status.
        status: u16,
        /// Redacted provider diagnostic.
        message: String,
        /// Provider request id, when supplied.
        request_id: Option<String>,
        /// Retry delay from the provider.
        retry_after_ms: Option<u64>,
    },
    /// Provider response exceeded its configured bound.
    #[error("WA Archive response exceeded the configured {limit}-byte bound")]
    ResponseTooLarge {
        /// Active response-size limit.
        limit: usize,
    },
    /// The live provider contract differs from the qualified source contract.
    #[error("WA Archive contract mismatch: {0}")]
    ContractMismatch(String),
    /// A referenced provider operation was not found.
    #[error("WA Archive provider operation was not found")]
    OperationNotFound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AllowedMediaOrigin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl AllowedMediaOrigin {
    fn parse(value: &str) -> Result<Self, WaArchiveConnectorError> {
        let url = Url::parse(value)
            .map_err(|error| WaArchiveConnectorError::Configuration(error.to_string()))?;
        if url.scheme() != "https"
            || url.username() != ""
            || url.password().is_some()
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err(WaArchiveConnectorError::Configuration(
                "media origins must be bare HTTPS origins without credentials, path, query, or fragment"
                    .to_owned(),
            ));
        }
        Ok(Self {
            scheme: url.scheme().to_owned(),
            host: url.host_str().unwrap_or_default().to_ascii_lowercase(),
            port: url.port_or_known_default(),
        })
    }

    fn matches(&self, url: &Url) -> bool {
        self.scheme == url.scheme()
            && url
                .host_str()
                .is_some_and(|host| self.host == host.to_ascii_lowercase())
            && self.port == url.port_or_known_default()
    }
}

#[derive(Debug, Default)]
struct ContractState {
    verified_at: Option<tokio::time::Instant>,
    operation_schema_document: Option<Arc<ProviderOperationSchemaDocument>>,
}

#[derive(Debug, Default)]
struct ChangeFeedHealthState {
    required: bool,
    running: bool,
    last_success: Option<tokio::time::Instant>,
    consecutive_failures: u32,
    last_error: Option<String>,
}

/// Authenticated connector for one isolated WA Archive account instance.
#[derive(Clone)]
pub struct WaArchiveConnector {
    base_url: Url,
    external_account_id: String,
    api_token: ConnectorSecret,
    client: reqwest::Client,
    media_client: reqwest::Client,
    allowed_operations: BTreeSet<WaArchiveOperation>,
    allowed_query_operations: BTreeSet<WaArchiveQueryOperation>,
    allowed_control_operations: BTreeSet<WaArchiveControlOperation>,
    allowed_media_origins: Vec<AllowedMediaOrigin>,
    max_json_response_bytes: usize,
    max_media_bytes: usize,
    contract_state: Arc<Mutex<ContractState>>,
    change_feed_health: Arc<Mutex<ChangeFeedHealthState>>,
    change_feed_enabled: Arc<AtomicBool>,
}

impl fmt::Debug for WaArchiveConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WaArchiveConnector")
            .field("base_url", &self.base_url)
            .field("external_account_id", &self.external_account_id)
            .field("api_token", &self.api_token)
            .field("allowed_operations", &self.allowed_operations.len())
            .field(
                "allowed_query_operations",
                &self.allowed_query_operations.len(),
            )
            .field(
                "allowed_control_operations",
                &self.allowed_control_operations.len(),
            )
            .field("allowed_media_origins", &self.allowed_media_origins.len())
            .field("provider_source_revision", &PROVIDER_REVISION)
            .field("max_json_response_bytes", &self.max_json_response_bytes)
            .field("max_media_bytes", &self.max_media_bytes)
            .field("change_feed_health", &"shared")
            .field(
                "change_feed_enabled",
                &self.change_feed_enabled.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl WaArchiveConnector {
    /// Creates a connector for one provider process and external account.
    pub fn new(
        base_url: &str,
        external_account_id: &str,
        api_token: ConnectorSecret,
    ) -> Result<Self, WaArchiveConnectorError> {
        let mut base_url = Url::parse(base_url)
            .map_err(|error| WaArchiveConnectorError::Configuration(error.to_string()))?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || base_url.username() != ""
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(WaArchiveConnectorError::Configuration(
                "provider base URL must be an HTTP(S) origin without credentials, query, or fragment"
                    .to_owned(),
            ));
        }
        if base_url.scheme() == "http"
            && !base_url.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            })
        {
            return Err(WaArchiveConnectorError::Configuration(
                "provider HTTP is permitted only on a loopback origin; use HTTPS for network transport"
                    .to_owned(),
            ));
        }
        if !matches!(base_url.path(), "" | "/") {
            return Err(WaArchiveConnectorError::Configuration(
                "provider base URL must not contain a path prefix".to_owned(),
            ));
        }
        base_url.set_path("/");
        let external_account_id = external_account_id.trim();
        if external_account_id.is_empty()
            || external_account_id.len() > 512
            || external_account_id.chars().any(char::is_control)
        {
            return Err(WaArchiveConnectorError::Configuration(
                "external account id must contain 1 to 512 bytes without control characters"
                    .to_owned(),
            ));
        }
        let token = api_token.expose_str().map_err(|_| {
            WaArchiveConnectorError::Configuration(
                "provider API token must contain UTF-8 header material".to_owned(),
            )
        })?;
        if token.trim().is_empty()
            || token.len() > MAX_API_TOKEN_BYTES
            || reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).is_err()
        {
            return Err(WaArchiveConnectorError::Configuration(
                "provider API token is empty, oversized, or invalid for an HTTP header".to_owned(),
            ));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(35))
            .build()
            .map_err(|error| WaArchiveConnectorError::Configuration(error.to_string()))?;
        let media_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|error| WaArchiveConnectorError::Configuration(error.to_string()))?;
        Ok(Self {
            base_url,
            external_account_id: external_account_id.to_owned(),
            api_token,
            client,
            media_client,
            allowed_operations: ALL_WA_ARCHIVE_OPERATIONS.iter().copied().collect(),
            allowed_query_operations: ALL_WA_ARCHIVE_QUERY_OPERATIONS.iter().copied().collect(),
            allowed_control_operations: ALL_WA_ARCHIVE_CONTROL_OPERATIONS.iter().copied().collect(),
            allowed_media_origins: Vec::new(),
            max_json_response_bytes: DEFAULT_MAX_JSON_RESPONSE_BYTES,
            max_media_bytes: DEFAULT_MAX_MEDIA_BYTES,
            contract_state: Arc::new(Mutex::new(ContractState::default())),
            change_feed_health: Arc::new(Mutex::new(ChangeFeedHealthState::default())),
            change_feed_enabled: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Restricts the provider operation catalogue for one deployment instance.
    pub fn with_allowed_operations(
        mut self,
        operations: impl IntoIterator<Item = WaArchiveOperation>,
    ) -> Result<Self, WaArchiveConnectorError> {
        let operations = operations.into_iter().collect::<BTreeSet<_>>();
        if operations.is_empty() {
            return Err(WaArchiveConnectorError::Configuration(
                "at least one WA Archive operation must be admitted".to_owned(),
            ));
        }
        self.allowed_operations = operations;
        Ok(self)
    }

    /// Restricts archive/read capabilities for one deployment instance.
    pub fn with_allowed_query_operations(
        mut self,
        operations: impl IntoIterator<Item = WaArchiveQueryOperation>,
    ) -> Result<Self, WaArchiveConnectorError> {
        self.allowed_query_operations = operations.into_iter().collect();
        Ok(self)
    }

    /// Restricts operator-only ambiguity controls for one deployment instance.
    pub fn with_allowed_control_operations(
        mut self,
        operations: impl IntoIterator<Item = WaArchiveControlOperation>,
    ) -> Result<Self, WaArchiveConnectorError> {
        self.allowed_control_operations = operations.into_iter().collect();
        Ok(self)
    }

    /// Pins the exact provider source revision compiled into the remote binary.
    pub fn with_expected_provider_source_revision(
        self,
        revision: impl Into<String>,
    ) -> Result<Self, WaArchiveConnectorError> {
        let revision = revision.into();
        let revision = revision.trim();
        if revision != PROVIDER_REVISION {
            return Err(WaArchiveConnectorError::Configuration(format!(
                "provider source revision must equal the qualified immutable revision `{PROVIDER_REVISION}`"
            )));
        }
        Ok(self)
    }

    /// Requires the durable provider change-feed worker for connector readiness.
    pub async fn require_change_feed(&self, required: bool) {
        self.change_feed_enabled.store(required, Ordering::Release);
        let mut health = self.change_feed_health.lock().await;
        health.required = required;
        if !required {
            health.running = false;
            health.last_success = None;
            health.consecutive_failures = 0;
            health.last_error = None;
        }
    }

    /// Configures exact HTTPS origins from which media may be fetched.
    pub fn with_allowed_media_origins(
        mut self,
        origins: impl IntoIterator<Item = String>,
    ) -> Result<Self, WaArchiveConnectorError> {
        self.allowed_media_origins = origins
            .into_iter()
            .map(|origin| AllowedMediaOrigin::parse(&origin))
            .collect::<Result<Vec<_>, _>>()?;
        self.allowed_media_origins.sort_by(|left, right| {
            (&left.scheme, &left.host, left.port).cmp(&(&right.scheme, &right.host, right.port))
        });
        self.allowed_media_origins.dedup();
        Ok(self)
    }

    /// Overrides the bounded JSON response size.
    pub fn with_max_json_response_bytes(
        mut self,
        limit: usize,
    ) -> Result<Self, WaArchiveConnectorError> {
        if !(1024..=MAX_JSON_RESPONSE_BYTES).contains(&limit) {
            return Err(WaArchiveConnectorError::Configuration(format!(
                "JSON response limit must be between 1024 and {MAX_JSON_RESPONSE_BYTES} bytes"
            )));
        }
        self.max_json_response_bytes = limit;
        Ok(self)
    }

    /// Overrides the bounded remote-media download size.
    pub fn with_max_media_bytes(mut self, limit: usize) -> Result<Self, WaArchiveConnectorError> {
        if !(1024..=MAX_MEDIA_BYTES).contains(&limit) {
            return Err(WaArchiveConnectorError::Configuration(format!(
                "media limit must be between 1024 and {MAX_MEDIA_BYTES} bytes"
            )));
        }
        self.max_media_bytes = limit;
        Ok(self)
    }

    fn token(&self) -> Result<&str, WaArchiveConnectorError> {
        self.api_token
            .expose_str()
            .map_err(|_| WaArchiveConnectorError::InvalidCredential)
    }

    fn endpoint(&self, path: &str) -> Result<Url, WaArchiveConnectorError> {
        self.base_url
            .join(path)
            .map_err(|error| WaArchiveConnectorError::Configuration(error.to_string()))
    }

    fn provider_operation_ref(key: &str) -> ProviderOperationRef {
        ProviderOperationRef {
            provider: CONNECTOR_ID.to_owned(),
            operation_id: key.to_owned(),
            request_id: None,
        }
    }

    /// Builds the frozen admission manifest from the checked-in provider
    /// schema artifact without contacting a live WhatsApp account.
    ///
    /// Runtime discovery still performs live contract and account admission;
    /// this method exists only for signed release-package construction.
    pub fn qualified_manifest(&self) -> Result<aip_core::Manifest, WaArchiveConnectorError> {
        let document = checked_in_operation_schema_document()?;
        self.manifest_from_schema(&document)
    }

    fn manifest_from_schema(
        &self,
        operation_schema_document: &ProviderOperationSchemaDocument,
    ) -> Result<aip_core::Manifest, WaArchiveConnectorError> {
        let account_digest =
            hex::encode(&Sha256::digest(self.external_account_id.as_bytes())[..16]);
        let change_feed_enabled = self.change_feed_enabled.load(Ordering::Acquire);
        let channels = if change_feed_enabled {
            vec![json!({
                "id": CHANGE_FEED_CHANNEL_ID,
                "system": "wa_archive",
                "external_account_digest": account_digest.clone(),
                "delivery": "durable_monotonic_feed"
            })]
        } else {
            Vec::new()
        };
        Ok(aip_core::Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(
                PrincipalId::parse(format!("agent:wa_archive:{account_digest}"))
                    .map_err(|error| WaArchiveConnectorError::Configuration(error.to_string()))?,
                PrincipalKind::Agent,
            ),
            capabilities: wa_archive_capabilities(
                &self.allowed_operations,
                &self.allowed_query_operations,
                &self.allowed_control_operations,
                operation_schema_document,
            ),
            profiles: vec![
                ProfileId::from("aip.native.http.v1"),
                ProfileId::from(PROFILE_ID),
            ],
            resources: Vec::new(),
            channels,
            security: Some(json!({
                "provider_authentication": "account_scoped_bearer_token_from_owner_only_file",
                "request_identity": "x-request-id",
                "media_origins_allowlisted": !self.allowed_media_origins.is_empty(),
                "database_access": false,
                "session_access": false,
                "change_feed_enabled": change_feed_enabled
            })),
            governance: Some(json!({
                "sensitive_and_destructive_operations_require_verified_approval": true,
                "sensitive_and_destructive_operations_require_plan_commit": true,
                "ambiguous_provider_outcomes_require_reconciliation": true,
                "ambiguous_provider_outcomes_require_evidenced_manual_resolution_before_retry": true
            })),
            limits: Some(json!({
                "max_json_response_bytes": self.max_json_response_bytes,
                "max_media_bytes": self.max_media_bytes,
                "max_inline_media_bytes": MAX_INLINE_MEDIA_BYTES
            })),
            compatibility: Some(json!({
                "system": "wa_archive",
                "connector": CONNECTOR_ID,
                "provider_revision": PROVIDER_REVISION,
                "operation_contract_version": OPERATION_CONTRACT_VERSION,
                "operation_contract_sha256": OPERATION_CONTRACT_SHA256,
                "connector_feed_version": CONNECTOR_FEED_VERSION,
                "provider_connector_contract": PROVIDER_CONNECTOR_CONTRACT,
                "catalog_operations_supported": ALL_WA_ARCHIVE_OPERATIONS.len(),
                "catalog_operations_admitted": self.allowed_operations.len(),
                "archive_query_operations_supported": ALL_WA_ARCHIVE_QUERY_OPERATIONS.len(),
                "archive_query_operations_admitted": self.allowed_query_operations.len(),
                "operator_control_operations_supported": ALL_WA_ARCHIVE_CONTROL_OPERATIONS.len(),
                "operator_control_operations_admitted": self.allowed_control_operations.len(),
                "provider_source_revision": PROVIDER_REVISION,
                "operation_schema_contract_sha256": OPERATION_SCHEMA_CONTRACT_SHA256
            })),
            extensions: None,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderCapabilities {
    operation_contract_version: u32,
    operation_contract_sha256: String,
    connector_feed_version: u32,
    aip_connector_contract: String,
    provider_source_revision: String,
    operation_schema_document_version: String,
    operation_schema_contract_sha256: String,
    operation_schema_document: ProviderOperationSchemaDocument,
    operation_kinds: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderOperationSchemaDocument {
    schema_version: String,
    operation_contract_version: u32,
    operation_contract_sha256: String,
    schema_dialect: String,
    definitions: BTreeMap<String, Value>,
    operation_schemas: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderAccount {
    paired: bool,
    account_id: Option<String>,
    phone_jid: Option<String>,
    lid_jid: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderJob {
    id: i64,
    status: String,
    attempts: Option<i32>,
    ack: Option<i32>,
    whatsapp_message_id: Option<String>,
    failure_class: Option<String>,
    idempotency_key: String,
    operation_kind: String,
    operation_version: i32,
    safety_class: String,
    result: Option<Value>,
    completed_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProviderJobEnvelope {
    job: ProviderJob,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderValidation {
    operation_kind: String,
    operation_version: u32,
    safety_class: String,
    requires_confirmation: bool,
    normalized_target: Option<String>,
    has_media: bool,
}

#[derive(Debug, Deserialize)]
struct ProviderValidationEnvelope {
    valid: bool,
    operation: ProviderValidation,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderAmbiguityResolution {
    id: i64,
    outbox_id: i64,
    created: bool,
    idempotency_key: String,
    resolution: String,
    actor: String,
    reason: String,
    evidence: Value,
    whatsapp_message_id: Option<String>,
    result: Option<Value>,
    resolved_at: String,
}

#[derive(Debug, Deserialize)]
struct ProviderAmbiguityResolutionEnvelope {
    resolution: ProviderAmbiguityResolution,
}

#[derive(Debug, Deserialize)]
struct ProviderAmbiguityResolutionListEnvelope {
    items: Vec<ProviderAmbiguityResolution>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AmbiguityResolutionActionInput {
    provider_operation_id: String,
    resolution: String,
    reason: String,
    evidence: Value,
    #[serde(default)]
    whatsapp_message_id: Option<String>,
    #[serde(default)]
    result: Option<Value>,
}

/// One item returned by the monotonic provider change feed.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WaArchiveChange {
    /// Strictly increasing provider cursor.
    pub sequence: i64,
    /// Provider source family.
    pub source_kind: String,
    /// Stable source identifier.
    pub source_id: String,
    /// Path-free event kind.
    pub event_kind: String,
    /// RFC 3339 event time.
    pub occurred_at: String,
    /// Bounded event data.
    pub payload: Value,
    /// RFC 3339 append time.
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeFeedEnvelope {
    items: Vec<WaArchiveChange>,
    next_cursor: i64,
    has_more: bool,
    oldest_cursor: Option<i64>,
    latest_cursor: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationActionInput {
    #[serde(default)]
    to_phone: Option<String>,
    #[serde(default)]
    to_chat_id: Option<String>,
    operation: Value,
    #[serde(default)]
    body: String,
    #[serde(default = "default_max_attempts")]
    max_attempts: i32,
    #[serde(default)]
    media: Option<MediaInput>,
    #[serde(default)]
    send_as_voice: bool,
    #[serde(default)]
    quoted_message_id: Option<String>,
}

const fn default_max_attempts() -> i32 {
    3
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MediaInput {
    #[serde(default)]
    content_base64: Option<String>,
    #[serde(default)]
    url: Option<String>,
    filename: String,
    sha256: String,
}

struct PreparedOperationInput {
    validation_body: Value,
    enqueue_body: Value,
    provider_key: String,
    input_hash: String,
}

struct ProviderResponse {
    status: StatusCode,
    request_id: Option<String>,
    retry_after_ms: Option<u64>,
    body: Vec<u8>,
}

impl ProviderResponse {
    fn json<T: for<'de> Deserialize<'de>>(&self) -> Result<T, WaArchiveConnectorError> {
        serde_json::from_slice(&self.body).map_err(|error| {
            WaArchiveConnectorError::Transport(format!("invalid provider JSON response: {error}"))
        })
    }
}

impl WaArchiveConnector {
    async fn execute_request(
        &self,
        method: Method,
        url: Url,
        body: Option<&Value>,
    ) -> Result<ProviderResponse, WaArchiveConnectorError> {
        let request_id = new_request_id();
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(self.token()?)
            .header("Accept", "application/json")
            .header(EXTERNAL_ACCOUNT_ID_HEADER, &self.external_account_id)
            .header("x-request-id", &request_id);
        if let Some(body) = body {
            let encoded = serde_json::to_vec(body)
                .map_err(|error| WaArchiveConnectorError::InvalidAction(error.to_string()))?;
            if encoded.len() > MAX_PROVIDER_REQUEST_BYTES {
                return Err(WaArchiveConnectorError::InvalidAction(format!(
                    "provider request exceeds {MAX_PROVIDER_REQUEST_BYTES} bytes"
                )));
            }
            request = request.json(body);
        }
        let response = request.send().await.map_err(|_| {
            WaArchiveConnectorError::Transport("provider HTTP request failed".to_owned())
        })?;
        let status = response.status();
        let provider_request_id = provider_request_id(&response).ok_or_else(|| {
            WaArchiveConnectorError::ContractMismatch(
                "provider response omitted the required request id".to_owned(),
            )
        })?;
        if provider_request_id != request_id {
            return Err(WaArchiveConnectorError::ContractMismatch(
                "provider returned a request id different from the dispatched request".to_owned(),
            ));
        }
        let retry_after_ms = retry_after_millis(&response);
        let body = read_bounded_response(response, self.max_json_response_bytes).await?;
        let result = ProviderResponse {
            status,
            request_id: Some(provider_request_id),
            retry_after_ms,
            body,
        };
        if result.status.is_success() {
            return Ok(result);
        }
        if result.status == StatusCode::NOT_FOUND {
            return Err(WaArchiveConnectorError::OperationNotFound);
        }
        let message = provider_error_message(&result.body);
        Err(WaArchiveConnectorError::Remote {
            status: result.status.as_u16(),
            message,
            request_id: result.request_id,
            retry_after_ms: result.retry_after_ms,
        })
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T, WaArchiveConnectorError> {
        let mut url = self.endpoint(path)?;
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(key, value)| (*key, value)));
        }
        self.execute_request(Method::GET, url, None).await?.json()
    }

    async fn post_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<T, WaArchiveConnectorError> {
        self.execute_request(Method::POST, self.endpoint(path)?, Some(body))
            .await?
            .json()
    }

    async fn get_media(&self, message_id: &str) -> Result<Value, WaArchiveConnectorError> {
        if message_id.is_empty()
            || message_id.len() > 512
            || message_id.chars().any(char::is_control)
        {
            return Err(WaArchiveConnectorError::InvalidAction(
                "message_id must contain 1 to 512 bytes without controls".to_owned(),
            ));
        }
        let mut url = self.endpoint("/v1/media/")?;
        url.path_segments_mut()
            .map_err(|()| {
                WaArchiveConnectorError::Configuration(
                    "provider media endpoint cannot accept path segments".to_owned(),
                )
            })?
            .pop_if_empty()
            .push(message_id);
        let request_id = new_request_id();
        let response = self
            .client
            .get(url)
            .bearer_auth(self.token()?)
            .header("Accept", "application/octet-stream")
            .header(EXTERNAL_ACCOUNT_ID_HEADER, &self.external_account_id)
            .header("x-request-id", &request_id)
            .send()
            .await
            .map_err(|_| {
                WaArchiveConnectorError::Transport("provider media request failed".to_owned())
            })?;
        let status = response.status();
        let provider_request_id = provider_request_id(&response).ok_or_else(|| {
            WaArchiveConnectorError::ContractMismatch(
                "provider media response omitted the required request id".to_owned(),
            )
        })?;
        if provider_request_id != request_id {
            return Err(WaArchiveConnectorError::ContractMismatch(
                "provider returned a request id different from the media request".to_owned(),
            ));
        }
        let retry_after_ms = retry_after_millis(&response);
        if !status.is_success() {
            let body = read_bounded_response(response, self.max_json_response_bytes).await?;
            if status == StatusCode::NOT_FOUND {
                return Err(WaArchiveConnectorError::OperationNotFound);
            }
            return Err(WaArchiveConnectorError::Remote {
                status: status.as_u16(),
                message: provider_error_message(&body),
                request_id: Some(provider_request_id),
                retry_after_ms,
            });
        }
        let content_type = bounded_response_header(&response, "content-type", 255)
            .unwrap_or_else(|| "application/octet-stream".to_owned());
        let filename = bounded_response_header(&response, "content-disposition", 1_024)
            .and_then(|value| content_disposition_filename(&value))
            .unwrap_or_else(|| "media.bin".to_owned());
        let bytes = read_bounded_response(response, self.max_media_bytes).await?;
        Ok(json!({
            "message_id": message_id,
            "filename": filename,
            "content_type": content_type,
            "size_bytes": bytes.len(),
            "sha256": hex::encode(Sha256::digest(&bytes)),
            "content_base64": BASE64_STANDARD.encode(bytes)
        }))
    }

    async fn ensure_contract(
        &self,
        force: bool,
    ) -> Result<Arc<ProviderOperationSchemaDocument>, WaArchiveConnectorError> {
        let mut state = self.contract_state.lock().await;
        if !force
            && state
                .verified_at
                .is_some_and(|verified| verified.elapsed() < CONTRACT_CACHE_TTL)
            && let Some(document) = state.operation_schema_document.as_ref()
        {
            return Ok(Arc::clone(document));
        }
        let capabilities = self
            .get_json::<ProviderCapabilities>("/v1/capabilities", &[])
            .await?;
        verify_provider_capabilities(&capabilities, PROVIDER_REVISION)?;
        let document = Arc::new(capabilities.operation_schema_document);
        state.verified_at = Some(tokio::time::Instant::now());
        state.operation_schema_document = Some(Arc::clone(&document));
        Ok(document)
    }

    async fn prepare_operation_input(
        &self,
        operation: WaArchiveOperation,
        action: &Action,
        fetch_remote_media: bool,
        confirmed: bool,
    ) -> Result<PreparedOperationInput, WaArchiveConnectorError> {
        let input = serde_json::from_value::<OperationActionInput>(action.input.clone())
            .map_err(|error| WaArchiveConnectorError::InvalidAction(error.to_string()))?;
        if input.body.len() > MAX_BODY_BYTES {
            return Err(WaArchiveConnectorError::InvalidAction(format!(
                "body exceeds {MAX_BODY_BYTES} bytes"
            )));
        }
        if !(1..=100).contains(&input.max_attempts) {
            return Err(WaArchiveConnectorError::InvalidAction(
                "max_attempts must be between 1 and 100".to_owned(),
            ));
        }
        let operation_bytes = serde_json::to_vec(&input.operation)
            .map_err(|error| WaArchiveConnectorError::InvalidAction(error.to_string()))?;
        if operation_bytes.len() > MAX_OPERATION_JSON_BYTES {
            return Err(WaArchiveConnectorError::InvalidAction(format!(
                "operation payload exceeds {MAX_OPERATION_JSON_BYTES} bytes"
            )));
        }
        if input.media.is_some() && !operation.accepts_media() {
            return Err(WaArchiveConnectorError::InvalidAction(format!(
                "operation `{}` does not accept media",
                operation.suffix()
            )));
        }
        if operation.requires_media() && input.media.is_none() {
            return Err(WaArchiveConnectorError::InvalidAction(format!(
                "operation `{}` requires media",
                operation.suffix()
            )));
        }
        let provider_key = provider_idempotency_key(&self.external_account_id, action)?;
        let has_media = input.media.is_some();
        let media_filename = input.media.as_ref().map(|media| media.filename.clone());
        let validation_body = json!({
            "toPhone": input.to_phone,
            "toChatId": input.to_chat_id,
            "operation": input.operation,
            "body": input.body,
            "maxAttempts": input.max_attempts,
            "idempotencyKey": provider_key,
            "hasMedia": has_media,
            "mediaFilename": media_filename,
            "sendAsVoice": input.send_as_voice,
            "quotedMessageId": input.quoted_message_id
        });
        let input_hash_material = json!({
            "capability": action.capability_id.as_str(),
            "validation": validation_body,
            "mediaSha256": input.media.as_ref().map(|media| media.sha256.as_str()),
            "mediaUrl": input.media.as_ref().and_then(|media| media.url.as_deref())
        });
        let enqueue_body = if let Some(media) = input.media.as_ref() {
            validate_media_metadata(media)?;
            let bytes = if fetch_remote_media {
                self.resolve_media(media).await?
            } else {
                self.validate_media_without_fetch(media)?;
                Vec::new()
            };
            json!({
                "toPhone": input.to_phone,
                "toChatId": input.to_chat_id,
                "operation": input.operation,
                "body": input.body,
                "maxAttempts": input.max_attempts,
                "idempotencyKey": provider_key,
                "filename": media.filename,
                "sha256": media.sha256,
                "dataBase64": if fetch_remote_media { BASE64_STANDARD.encode(bytes) } else { String::new() },
                "sendAsVoice": input.send_as_voice,
                "quotedMessageId": input.quoted_message_id,
                "confirmed": confirmed
            })
        } else {
            json!({
                "toPhone": input.to_phone,
                "toChatId": input.to_chat_id,
                "operation": input.operation,
                "body": input.body,
                "maxAttempts": input.max_attempts,
                "idempotencyKey": provider_key,
                "mediaPath": null,
                "mediaFilename": null,
                "mediaOwned": false,
                "sendAsVoice": input.send_as_voice,
                "quotedMessageId": input.quoted_message_id,
                "confirmed": confirmed
            })
        };
        let input_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input_hash_material)
                .map_err(|error| WaArchiveConnectorError::InvalidAction(error.to_string()))?,
        ));
        Ok(PreparedOperationInput {
            validation_body,
            enqueue_body,
            provider_key,
            input_hash,
        })
    }

    async fn resolve_media(&self, media: &MediaInput) -> Result<Vec<u8>, WaArchiveConnectorError> {
        let bytes = match (&media.content_base64, &media.url) {
            (Some(encoded), None) => decode_inline_media(encoded)?,
            (None, Some(value)) => {
                let url = self.validated_media_url(value)?;
                let response = self
                    .media_client
                    .get(url)
                    .header("Accept", "application/octet-stream")
                    .send()
                    .await
                    .map_err(|_| {
                        WaArchiveConnectorError::Transport(
                            "allowlisted media origin request failed".to_owned(),
                        )
                    })?;
                if !response.status().is_success() {
                    return Err(WaArchiveConnectorError::Remote {
                        status: response.status().as_u16(),
                        message: "allowlisted media origin rejected the download".to_owned(),
                        request_id: provider_request_id(&response),
                        retry_after_ms: retry_after_millis(&response),
                    });
                }
                read_bounded_response(response, self.max_media_bytes).await?
            }
            _ => {
                return Err(WaArchiveConnectorError::InvalidAction(
                    "media must contain exactly one of content_base64 or url".to_owned(),
                ));
            }
        };
        verify_media_digest(&bytes, &media.sha256)?;
        Ok(bytes)
    }

    fn validate_media_without_fetch(
        &self,
        media: &MediaInput,
    ) -> Result<(), WaArchiveConnectorError> {
        match (&media.content_base64, &media.url) {
            (Some(encoded), None) => {
                let bytes = decode_inline_media(encoded)?;
                verify_media_digest(&bytes, &media.sha256)
            }
            (None, Some(value)) => self.validated_media_url(value).map(|_| ()),
            _ => Err(WaArchiveConnectorError::InvalidAction(
                "media must contain exactly one of content_base64 or url".to_owned(),
            )),
        }
    }

    fn validated_media_url(&self, value: &str) -> Result<Url, WaArchiveConnectorError> {
        let url = Url::parse(value).map_err(|_| {
            WaArchiveConnectorError::InvalidAction("media.url is not a valid URL".to_owned())
        })?;
        if url.scheme() != "https"
            || url.username() != ""
            || url.password().is_some()
            || url.fragment().is_some()
            || !self
                .allowed_media_origins
                .iter()
                .any(|origin| origin.matches(&url))
        {
            return Err(WaArchiveConnectorError::InvalidAction(
                "media URL is not covered by an exact configured HTTPS origin".to_owned(),
            ));
        }
        Ok(url)
    }

    async fn validate_provider_operation(
        &self,
        operation: WaArchiveOperation,
        prepared: &PreparedOperationInput,
    ) -> Result<ProviderValidation, WaArchiveConnectorError> {
        let response = self
            .post_json::<ProviderValidationEnvelope>(
                "/v1/operations/validate",
                &prepared.validation_body,
            )
            .await?;
        if !response.valid {
            return Err(WaArchiveConnectorError::ContractMismatch(
                "provider returned a non-validating success response".to_owned(),
            ));
        }
        let validation = response.operation;
        if validation.operation_kind != operation.suffix()
            || validation.operation_version != OPERATION_CONTRACT_VERSION
            || validation.safety_class != operation.safety_class().as_str()
            || validation.requires_confirmation != operation.safety_class().requires_approval()
            || validation.has_media
                != prepared
                    .validation_body
                    .get("hasMedia")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
        {
            return Err(WaArchiveConnectorError::ContractMismatch(format!(
                "provider validation does not match capability `{}`",
                operation.suffix()
            )));
        }
        Ok(validation)
    }
}

fn validate_media_metadata(media: &MediaInput) -> Result<(), WaArchiveConnectorError> {
    if media.filename.is_empty()
        || media.filename.len() > 255
        || media.filename.chars().any(char::is_control)
        || media.filename.contains('/')
        || media.filename.contains('\\')
    {
        return Err(WaArchiveConnectorError::InvalidAction(
            "media.filename must be a 1 to 255 byte basename without control characters".to_owned(),
        ));
    }
    if media.sha256.len() != 64
        || !media
            .sha256
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err(WaArchiveConnectorError::InvalidAction(
            "media.sha256 must be 64 lowercase hexadecimal characters".to_owned(),
        ));
    }
    if (media.content_base64.is_some()) == (media.url.is_some()) {
        return Err(WaArchiveConnectorError::InvalidAction(
            "media must contain exactly one of content_base64 or url".to_owned(),
        ));
    }
    Ok(())
}

fn decode_inline_media(encoded: &str) -> Result<Vec<u8>, WaArchiveConnectorError> {
    let bytes = BASE64_STANDARD.decode(encoded).map_err(|_| {
        WaArchiveConnectorError::InvalidAction(
            "media.content_base64 is not valid standard base64".to_owned(),
        )
    })?;
    if bytes.len() > MAX_INLINE_MEDIA_BYTES {
        return Err(WaArchiveConnectorError::InvalidAction(format!(
            "inline media exceeds {MAX_INLINE_MEDIA_BYTES} decoded bytes; use an allowlisted HTTPS URL"
        )));
    }
    Ok(bytes)
}

fn verify_media_digest(bytes: &[u8], expected_hex: &str) -> Result<(), WaArchiveConnectorError> {
    let expected = hex::decode(expected_hex).map_err(|_| {
        WaArchiveConnectorError::InvalidAction(
            "media.sha256 must be 64 lowercase hexadecimal characters".to_owned(),
        )
    })?;
    let actual = Sha256::digest(bytes);
    if expected.len() != actual.len() || !constant_time_eq(&expected, actual.as_slice()) {
        return Err(WaArchiveConnectorError::InvalidAction(
            "media SHA-256 digest does not match the supplied content".to_owned(),
        ));
    }
    Ok(())
}

fn verify_provider_capabilities(
    capabilities: &ProviderCapabilities,
    expected_provider_source_revision: &str,
) -> Result<(), WaArchiveConnectorError> {
    if capabilities.operation_contract_version != OPERATION_CONTRACT_VERSION {
        return Err(WaArchiveConnectorError::ContractMismatch(format!(
            "operation contract version {} is not {}",
            capabilities.operation_contract_version, OPERATION_CONTRACT_VERSION
        )));
    }
    if capabilities.operation_contract_sha256 != OPERATION_CONTRACT_SHA256 {
        return Err(WaArchiveConnectorError::ContractMismatch(
            "operation source digest differs from the qualified provider source".to_owned(),
        ));
    }
    if capabilities.connector_feed_version != CONNECTOR_FEED_VERSION {
        return Err(WaArchiveConnectorError::ContractMismatch(format!(
            "connector feed version {} is not {}",
            capabilities.connector_feed_version, CONNECTOR_FEED_VERSION
        )));
    }
    if capabilities.aip_connector_contract != PROVIDER_CONNECTOR_CONTRACT {
        return Err(WaArchiveConnectorError::ContractMismatch(format!(
            "provider connector contract `{}` is not `{PROVIDER_CONNECTOR_CONTRACT}`",
            capabilities.aip_connector_contract
        )));
    }
    if capabilities.provider_source_revision.is_empty()
        || capabilities.provider_source_revision.len() > 128
        || capabilities
            .provider_source_revision
            .chars()
            .any(char::is_control)
        || capabilities.provider_source_revision == "unknown"
    {
        return Err(WaArchiveConnectorError::ContractMismatch(
            "provider source revision is missing or is not immutable".to_owned(),
        ));
    }
    if capabilities.provider_source_revision != expected_provider_source_revision {
        return Err(WaArchiveConnectorError::ContractMismatch(format!(
            "provider source revision `{}` does not match the configured immutable revision",
            capabilities.provider_source_revision
        )));
    }
    if capabilities.operation_schema_document_version != OPERATION_SCHEMA_DOCUMENT_VERSION
        || capabilities.operation_schema_document.schema_version
            != OPERATION_SCHEMA_DOCUMENT_VERSION
    {
        return Err(WaArchiveConnectorError::ContractMismatch(
            "provider operation-schema document version is not supported".to_owned(),
        ));
    }
    if capabilities
        .operation_schema_document
        .operation_contract_version
        != OPERATION_CONTRACT_VERSION
        || capabilities
            .operation_schema_document
            .operation_contract_sha256
            != OPERATION_CONTRACT_SHA256
    {
        return Err(WaArchiveConnectorError::ContractMismatch(
            "provider operation-schema document targets a different operation contract".to_owned(),
        ));
    }
    if capabilities.operation_schema_document.schema_dialect
        != "https://json-schema.org/draft/2020-12/schema"
    {
        return Err(WaArchiveConnectorError::ContractMismatch(
            "provider operation schemas use an unsupported JSON Schema dialect".to_owned(),
        ));
    }
    let schema_document_bytes = serde_json::to_vec(&capabilities.operation_schema_document)
        .map_err(|error| WaArchiveConnectorError::ContractMismatch(error.to_string()))?;
    let schema_document_digest = hex::encode(Sha256::digest(schema_document_bytes));
    if schema_document_digest != OPERATION_SCHEMA_CONTRACT_SHA256
        || capabilities.operation_schema_contract_sha256 != OPERATION_SCHEMA_CONTRACT_SHA256
    {
        return Err(WaArchiveConnectorError::ContractMismatch(
            "provider operation-schema contract digest differs from the qualified document"
                .to_owned(),
        ));
    }
    let expected = ALL_WA_ARCHIVE_OPERATIONS
        .iter()
        .map(|operation| operation.suffix())
        .collect::<BTreeSet<_>>();
    let actual = capabilities
        .operation_kinds
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual != expected || capabilities.operation_kinds.len() != expected.len() {
        return Err(WaArchiveConnectorError::ContractMismatch(format!(
            "provider operation catalogue contains {} entries instead of the qualified {}",
            capabilities.operation_kinds.len(),
            expected.len()
        )));
    }
    let schema_kinds = capabilities
        .operation_schema_document
        .operation_schemas
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if schema_kinds != expected
        || capabilities
            .operation_schema_document
            .operation_schemas
            .values()
            .any(|schema| !schema.is_object())
    {
        return Err(WaArchiveConnectorError::ContractMismatch(
            "provider operation-schema catalogue is incomplete or malformed".to_owned(),
        ));
    }
    Ok(())
}

fn checked_in_operation_schema_document()
-> Result<ProviderOperationSchemaDocument, WaArchiveConnectorError> {
    let document = serde_json::from_slice::<ProviderOperationSchemaDocument>(include_bytes!(
        "../contracts/provider-operation-schemas.json"
    ))
    .map_err(|error| WaArchiveConnectorError::ContractMismatch(error.to_string()))?;
    if document.schema_version != OPERATION_SCHEMA_DOCUMENT_VERSION
        || document.operation_contract_version != OPERATION_CONTRACT_VERSION
        || document.operation_contract_sha256 != OPERATION_CONTRACT_SHA256
        || document.schema_dialect != "https://json-schema.org/draft/2020-12/schema"
    {
        return Err(WaArchiveConnectorError::ContractMismatch(
            "checked-in provider operation schemas target a different contract".to_owned(),
        ));
    }
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&document)
            .map_err(|error| WaArchiveConnectorError::ContractMismatch(error.to_string()))?,
    ));
    let expected = ALL_WA_ARCHIVE_OPERATIONS
        .iter()
        .map(|operation| operation.suffix())
        .collect::<BTreeSet<_>>();
    let actual = document
        .operation_schemas
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if digest != OPERATION_SCHEMA_CONTRACT_SHA256 || actual != expected {
        return Err(WaArchiveConnectorError::ContractMismatch(
            "checked-in provider operation-schema artifact failed its digest or catalogue check"
                .to_owned(),
        ));
    }
    Ok(document)
}

fn parse_ambiguity_resolution_input(
    action: &Action,
) -> Result<AmbiguityResolutionActionInput, WaArchiveConnectorError> {
    let input = serde_json::from_value::<AmbiguityResolutionActionInput>(action.input.clone())
        .map_err(|error| WaArchiveConnectorError::InvalidAction(error.to_string()))?;
    outbox_lookup_path(&input.provider_operation_id)?;
    if !matches!(input.resolution.as_str(), "committed" | "not_committed") {
        return Err(WaArchiveConnectorError::InvalidAction(
            "resolution must be `committed` or `not_committed`".to_owned(),
        ));
    }
    if input.reason.trim().is_empty()
        || input.reason.len() > 2_000
        || input.reason.chars().any(char::is_control)
    {
        return Err(WaArchiveConnectorError::InvalidAction(
            "resolution reason must contain 1 to 2000 bytes without controls".to_owned(),
        ));
    }
    let evidence = input
        .evidence
        .as_object()
        .filter(|object| !object.is_empty())
        .ok_or_else(|| {
            WaArchiveConnectorError::InvalidAction(
                "resolution evidence must be a non-empty object".to_owned(),
            )
        })?;
    if serde_json::to_vec(evidence).is_ok_and(|bytes| bytes.len() > 65_536) {
        return Err(WaArchiveConnectorError::InvalidAction(
            "resolution evidence exceeds 65536 bytes".to_owned(),
        ));
    }
    if input.whatsapp_message_id.as_ref().is_some_and(|value| {
        value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control)
    }) {
        return Err(WaArchiveConnectorError::InvalidAction(
            "resolution WhatsApp message id is invalid".to_owned(),
        ));
    }
    if input.result.as_ref().is_some_and(|value| {
        serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > MAX_OPERATION_JSON_BYTES)
    }) {
        return Err(WaArchiveConnectorError::InvalidAction(
            "resolution result exceeds the connector bound".to_owned(),
        ));
    }
    if input.resolution == "not_committed"
        && (input.whatsapp_message_id.is_some() || input.result.is_some())
    {
        return Err(WaArchiveConnectorError::InvalidAction(
            "not_committed resolution cannot include a message id or provider result".to_owned(),
        ));
    }
    Ok(input)
}

fn ambiguity_resolution_idempotency_key(
    external_account_id: &str,
    action: &Action,
) -> Result<String, WaArchiveConnectorError> {
    let key = action
        .idempotency_key
        .as_deref()
        .filter(|value| {
            !value.trim().is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            WaArchiveConnectorError::InvalidAction(
                "ambiguity resolution requires a bounded AIP idempotency key".to_owned(),
            )
        })?;
    let mut digest = Sha256::new();
    digest.update(b"aip-wa-ambiguity-resolution-v1\0");
    digest.update(external_account_id.as_bytes());
    digest.update(b"\0");
    digest.update(key.as_bytes());
    Ok(format!(
        "aip-wa-resolution-v1-{}",
        hex::encode(digest.finalize())
    ))
}

fn validate_provider_ambiguity_resolution(
    resolution: &ProviderAmbiguityResolution,
    expected_outbox_id: i64,
    expected_idempotency_key: Option<&str>,
    expected_actor: Option<&str>,
) -> Result<(), WaArchiveConnectorError> {
    let evidence_invalid = resolution
        .evidence
        .as_object()
        .filter(|object| !object.is_empty())
        .is_none_or(|evidence| {
            serde_json::to_vec(evidence).map_or(true, |bytes| bytes.len() > 65_536)
        });
    let result_invalid = resolution.result.as_ref().is_some_and(|value| {
        serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > MAX_OPERATION_JSON_BYTES)
    });
    if resolution.id < 1
        || resolution.outbox_id != expected_outbox_id
        || resolution.idempotency_key.trim().is_empty()
        || resolution.idempotency_key.len() > 200
        || resolution.idempotency_key.chars().any(char::is_control)
        || !matches!(
            resolution.resolution.as_str(),
            "committed" | "not_committed"
        )
        || resolution.actor.trim().is_empty()
        || resolution.actor.len() > 200
        || resolution.actor.chars().any(char::is_control)
        || resolution.reason.trim().is_empty()
        || resolution.reason.len() > 2_000
        || resolution.reason.chars().any(char::is_control)
        || evidence_invalid
        || resolution
            .whatsapp_message_id
            .as_ref()
            .is_some_and(|value| {
                value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control)
            })
        || result_invalid
        || (resolution.resolution == "not_committed"
            && (resolution.whatsapp_message_id.is_some() || resolution.result.is_some()))
        || OffsetDateTime::parse(&resolution.resolved_at, &Rfc3339).is_err()
        || expected_idempotency_key.is_some_and(|expected| resolution.idempotency_key != expected)
        || expected_actor.is_some_and(|expected| resolution.actor != expected)
    {
        return Err(WaArchiveConnectorError::ContractMismatch(
            "provider returned invalid ambiguity-resolution metadata".to_owned(),
        ));
    }
    Ok(())
}

fn provider_idempotency_key(
    external_account_id: &str,
    action: &Action,
) -> Result<String, WaArchiveConnectorError> {
    let key = action
        .idempotency_key
        .as_deref()
        .filter(|value| {
            !value.trim().is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            WaArchiveConnectorError::InvalidAction(
                "provider operations require a bounded AIP idempotency key".to_owned(),
            )
        })?;
    let mut digest = Sha256::new();
    digest.update(b"aip-wa-archive-v1\0");
    digest.update(external_account_id.as_bytes());
    digest.update(b"\0");
    digest.update(key.as_bytes());
    Ok(format!("aip-wa-v1-{}", hex::encode(digest.finalize())))
}

async fn read_bounded_response(
    response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, WaArchiveConnectorError> {
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(limit).unwrap_or(u64::MAX))
    {
        return Err(WaArchiveConnectorError::ResponseTooLarge { limit });
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| {
            WaArchiveConnectorError::Transport("provider HTTP response stream failed".to_owned())
        })?;
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(WaArchiveConnectorError::ResponseTooLarge { limit });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn provider_request_id(response: &reqwest::Response) -> Option<String> {
    ["x-request-id", "x-correlation-id", "traceparent"]
        .iter()
        .find_map(|name| response.headers().get(*name)?.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .map(ToOwned::to_owned)
}

fn new_request_id() -> String {
    format!("aip-wa-{}", Uuid::now_v7().simple())
}

fn bounded_response_header(
    response: &reqwest::Response,
    name: &str,
    maximum: usize,
) -> Option<String> {
    response
        .headers()
        .get(name)?
        .to_str()
        .ok()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= maximum
                && !value
                    .chars()
                    .any(|character| character.is_control() && !matches!(character, '\t'))
        })
        .map(ToOwned::to_owned)
}

fn content_disposition_filename(value: &str) -> Option<String> {
    let raw = value
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("filename="))?
        .trim_matches('"');
    let filename = raw
        .rsplit(['/', '\\'])
        .next()
        .filter(|value| !value.is_empty() && value.len() <= 255)?;
    if filename.chars().any(char::is_control) {
        return None;
    }
    Some(filename.to_owned())
}

fn retry_after_millis(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1_000))
}

fn provider_error_message(bytes: &[u8]) -> String {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .filter(|value| !value.is_empty())
        .map_or_else(
            || "provider rejected the request".to_owned(),
            |value| value.chars().take(1_000).collect(),
        )
}

#[async_trait]
impl Connector for WaArchiveConnector {
    fn id(&self) -> &str {
        CONNECTOR_ID
    }

    async fn discover(&self, _context: &ConnectorContext) -> ConnectorResult<aip_core::Manifest> {
        let operation_schema_document = self.ensure_contract(false).await.map_err(|error| {
            ConnectorError::Failure(connector_failure(
                error,
                ConnectorOperation::Discovery,
                None,
                false,
            ))
        })?;
        self.manifest_from_schema(&operation_schema_document)
            .map_err(|error| ConnectorError::Discovery(error.to_string()))
    }

    fn map_error(&self, error: &ConnectorError) -> ProtocolError {
        match error {
            ConnectorError::Failure(failure) => failure.to_protocol_error(),
            other => ProtocolError {
                code: "connector.wa_archive".to_owned(),
                message: other.to_string(),
                category: ErrorCategory::Connector,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: Some(Box::new(json!({ "component": CONNECTOR_ID }))),
            },
        }
    }

    async fn health(&self, _context: &ConnectorContext) -> ConnectorResult<ConnectorHealth> {
        self.ensure_contract(true).await.map_err(|error| {
            ConnectorError::Failure(connector_failure(
                error,
                ConnectorOperation::Health,
                None,
                false,
            ))
        })?;
        self.execute_request(
            Method::GET,
            self.endpoint("/ready").map_err(|error| {
                ConnectorError::Failure(connector_failure(
                    error,
                    ConnectorOperation::Health,
                    None,
                    false,
                ))
            })?,
            None,
        )
        .await
        .map_err(|error| {
            ConnectorError::Failure(connector_failure(
                error,
                ConnectorOperation::Health,
                None,
                false,
            ))
        })?;
        let account = self
            .get_json::<ProviderAccount>("/v1/account", &[])
            .await
            .map_err(|error| {
                ConnectorError::Failure(connector_failure(
                    error,
                    ConnectorOperation::Health,
                    None,
                    false,
                ))
            })?;
        if !account.paired {
            return Ok(ConnectorHealth {
                ready: false,
                detail: "WA Archive has no durable linked-account binding".to_owned(),
            });
        }
        if account.account_id.as_deref() != Some(self.external_account_id.as_str())
            || account.phone_jid.as_deref() != account.account_id.as_deref()
            || account.lid_jid.as_deref().is_none_or(str::is_empty)
        {
            return Ok(ConnectorHealth {
                ready: false,
                detail: "WA Archive linked-account identity does not match the configured external account"
                    .to_owned(),
            });
        }
        let feed = self.change_feed_health.lock().await;
        if feed.required
            && (!feed.running
                || feed
                    .last_success
                    .is_none_or(|last| last.elapsed() > CHANGE_FEED_STALE_AFTER)
                || feed.consecutive_failures >= 5)
        {
            let detail = feed.last_error.as_deref().map_or_else(
                || "WA Archive change-feed worker is not healthy".to_owned(),
                |error| format!("WA Archive change-feed worker is not healthy: {error}"),
            );
            return Ok(ConnectorHealth {
                ready: false,
                detail,
            });
        }
        Ok(ConnectorHealth {
            ready: true,
            detail: "WA Archive is ready, paired, authenticated, and contract-compatible"
                .to_owned(),
        })
    }
}

#[async_trait]
impl CapabilityProviderConnector for WaArchiveConnector {
    async fn capabilities(&self, _context: &ConnectorContext) -> ConnectorResult<Vec<Capability>> {
        let operation_schema_document = self.ensure_contract(false).await.map_err(|error| {
            ConnectorError::Failure(connector_failure(
                error,
                ConnectorOperation::Discovery,
                None,
                false,
            ))
        })?;
        Ok(wa_archive_capabilities(
            &self.allowed_operations,
            &self.allowed_query_operations,
            &self.allowed_control_operations,
            &operation_schema_document,
        ))
    }
}

/// Builds the complete admitted capability set for one connector instance.
#[must_use]
fn wa_archive_capabilities(
    allowed_operations: &BTreeSet<WaArchiveOperation>,
    allowed_query_operations: &BTreeSet<WaArchiveQueryOperation>,
    allowed_control_operations: &BTreeSet<WaArchiveControlOperation>,
    operation_schema_document: &ProviderOperationSchemaDocument,
) -> Vec<Capability> {
    let mut capabilities = allowed_operations
        .iter()
        .copied()
        .map(|operation| operation_capability(operation, operation_schema_document))
        .collect::<Vec<_>>();
    capabilities.extend(
        allowed_query_operations
            .iter()
            .copied()
            .map(legacy_query_resource_capability),
    );
    capabilities.extend(
        allowed_query_operations
            .iter()
            .copied()
            .map(query_capability),
    );
    capabilities.extend(
        allowed_control_operations
            .iter()
            .copied()
            .map(control_capability),
    );
    capabilities
}

fn operation_capability(
    operation: WaArchiveOperation,
    operation_schema_document: &ProviderOperationSchemaDocument,
) -> Capability {
    let safety = operation.safety_class();
    Capability {
        id: CapabilityId::trusted(format!("{CAPABILITY_PREFIX}{}", operation.suffix())),
        name: format!("WA Archive {}", operation.display_name()),
        kind: CapabilityKind::Tool,
        input_schema: operation_input_schema(operation, operation_schema_document),
        output_schema: Some(provider_job_output_schema()),
        description: Some(format!(
            "Executes the pinned WA Archive `{}` operation through its ambiguity-safe transactional outbox.",
            operation.suffix()
        )),
        risk: Some(match safety {
            WaArchiveSafetyClass::ReadOnly => RiskLevel::Low,
            WaArchiveSafetyClass::Standard => RiskLevel::Medium,
            WaArchiveSafetyClass::Sensitive => RiskLevel::High,
            WaArchiveSafetyClass::Destructive => RiskLevel::Critical,
        }),
        stability: None,
        cost: None,
        auth: Some(json!({ "type": "wa_archive_bearer_token" })),
        bindings: capability_bindings(operation.suffix(), safety.as_str()),
        requires_human_approval: Some(safety.requires_approval()),
        contract: Some(operation_contract(operation)),
    }
}

fn legacy_query_resource_capability(operation: WaArchiveQueryOperation) -> Capability {
    let mut capability = query_capability(operation);
    capability.id = CapabilityId::trusted(format!("{CAPABILITY_PREFIX}{}", operation.suffix()));
    capability.kind = CapabilityKind::Resource;
    capability
}

fn query_capability(operation: WaArchiveQueryOperation) -> Capability {
    Capability {
        id: CapabilityId::trusted(format!("{QUERY_CAPABILITY_PREFIX}{}", operation.suffix())),
        name: format!("WA Archive {}", operation.display_name()),
        // Archive queries accept typed pagination and filter input and are
        // executed by the connector. AIP Resource capabilities are passive
        // manifest resources and are deliberately excluded from the action
        // handler registry, so these invocable read operations are Tools.
        kind: CapabilityKind::Tool,
        input_schema: query_input_schema(operation),
        output_schema: Some(query_output_schema(operation)),
        description: Some(format!(
            "Reads the account-isolated WA Archive `{}` surface with bounded results.",
            operation.suffix()
        )),
        risk: Some(RiskLevel::Low),
        stability: None,
        cost: None,
        auth: Some(json!({ "type": "wa_archive_bearer_token" })),
        bindings: capability_bindings(operation.suffix(), "read_only"),
        requires_human_approval: Some(false),
        contract: Some(query_contract()),
    }
}

fn control_capability(operation: WaArchiveControlOperation) -> Capability {
    Capability {
        id: CapabilityId::trusted(format!("{CAPABILITY_PREFIX}{}", operation.suffix())),
        name: format!("WA Archive {}", operation.display_name()),
        kind: CapabilityKind::Tool,
        input_schema: ambiguity_resolution_input_schema(),
        output_schema: Some(ambiguity_resolution_output_schema()),
        description: Some(
            "Records an independently evidenced, human-approved resolution of an unknown provider outcome."
                .to_owned(),
        ),
        risk: Some(RiskLevel::Critical),
        stability: None,
        cost: None,
        auth: Some(json!({ "type": "wa_archive_bearer_token" })),
        bindings: capability_bindings(operation.suffix(), "operator_control"),
        requires_human_approval: Some(true),
        contract: Some(ambiguity_resolution_contract()),
    }
}

fn capability_bindings(operation: &str, safety_class: &str) -> Vec<Binding> {
    ["aip.native.http.v1", PROFILE_ID]
        .into_iter()
        .map(|profile| Binding {
            profile: ProfileId::from(profile),
            metadata: json!({
                "system": "wa_archive",
                "connector": CONNECTOR_ID,
                "operation": operation,
                "safety_class": safety_class,
                "operation_contract_version": OPERATION_CONTRACT_VERSION,
                "operation_contract_sha256": OPERATION_CONTRACT_SHA256
            })
            .as_object()
            .cloned()
            .unwrap_or_default(),
        })
        .collect()
}

fn operation_input_schema(
    operation: WaArchiveOperation,
    operation_schema_document: &ProviderOperationSchemaDocument,
) -> Value {
    let media_schema = json!({
        "type": "object",
        "required": ["filename", "sha256"],
        "properties": {
            "content_base64": { "type": "string" },
            "url": { "type": "string", "format": "uri", "pattern": "^https://" },
            "filename": { "type": "string", "minLength": 1, "maxLength": 255 },
            "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
        },
        "oneOf": [
            { "required": ["content_base64"], "not": { "required": ["url"] } },
            { "required": ["url"], "not": { "required": ["content_base64"] } }
        ],
        "additionalProperties": false
    });
    let mut properties = Map::from_iter([
        (
            "to_phone".to_owned(),
            json!({ "type": "string", "pattern": "^[0-9]{7,15}$" }),
        ),
        (
            "to_chat_id".to_owned(),
            json!({ "type": "string", "minLength": 1, "maxLength": 512 }),
        ),
        (
            "operation".to_owned(),
            provider_operation_schema(operation, operation_schema_document),
        ),
        (
            "body".to_owned(),
            json!({ "type": "string", "maxLength": MAX_BODY_BYTES }),
        ),
        (
            "max_attempts".to_owned(),
            json!({ "type": "integer", "minimum": 1, "maximum": 100, "default": 3 }),
        ),
        ("send_as_voice".to_owned(), json!({ "type": "boolean" })),
        (
            "quoted_message_id".to_owned(),
            json!({ "type": "string", "minLength": 1, "maxLength": 512 }),
        ),
    ]);
    if operation.accepts_media() {
        properties.insert("media".to_owned(), media_schema);
    }
    let mut required = vec![Value::String("operation".to_owned())];
    if operation.requires_media() {
        required.push(Value::String("media".to_owned()));
    }
    let mut schema = Map::from_iter([
        ("type".to_owned(), Value::String("object".to_owned())),
        ("required".to_owned(), Value::Array(required)),
        ("properties".to_owned(), Value::Object(properties)),
        ("additionalProperties".to_owned(), Value::Bool(false)),
    ]);
    schema.insert(
        "$schema".to_owned(),
        Value::String(operation_schema_document.schema_dialect.clone()),
    );
    if !operation_schema_document.definitions.is_empty() {
        schema.insert(
            "$defs".to_owned(),
            Value::Object(
                operation_schema_document
                    .definitions
                    .clone()
                    .into_iter()
                    .collect(),
            ),
        );
    }
    Value::Object(schema)
}

fn provider_operation_schema(
    operation: WaArchiveOperation,
    document: &ProviderOperationSchemaDocument,
) -> Value {
    let Some(mut schema) = document
        .operation_schemas
        .get(operation.suffix())
        .cloned()
        .and_then(|value| value.as_object().cloned())
    else {
        // Contract verification rejects this state before discovery. The
        // fail-closed schema keeps a malformed provider from advertising an
        // unconstrained operation if a future caller bypasses discovery.
        return json!({ "not": {} });
    };
    schema.insert(
        "$schema".to_owned(),
        Value::String(document.schema_dialect.clone()),
    );
    if !document.definitions.is_empty() {
        schema.insert(
            "$defs".to_owned(),
            Value::Object(document.definitions.clone().into_iter().collect()),
        );
    }
    Value::Object(schema)
}

fn provider_job_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "provider_operation_id", "provider_job_id", "status", "operation_kind",
            "operation_version", "safety_class", "whatsapp_message_id", "ack", "result",
            "completed_at"
        ],
        "properties": {
            "provider_operation_id": { "type": "string" },
            "provider_job_id": { "type": "integer" },
            "status": { "enum": ["sent", "delivered", "read", "played", "succeeded"] },
            "operation_kind": { "type": "string" },
            "operation_version": { "type": "integer", "minimum": 1 },
            "safety_class": { "type": "string" },
            "whatsapp_message_id": { "type": ["string", "null"] },
            "ack": { "type": ["integer", "null"] },
            "result": {},
            "completed_at": { "type": ["string", "null"] }
        },
        "additionalProperties": false
    })
}

fn query_input_schema(operation: WaArchiveQueryOperation) -> Value {
    let properties = match operation {
        WaArchiveQueryOperation::MessageList => json!({
            "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
            "cursor": { "type": "string" },
            "chat_id": { "type": "string" },
            "query": { "type": "string" },
            "direction": { "type": "string", "enum": ["incoming", "outgoing"] },
            "message_type": { "type": "string" },
            "from": { "type": "string", "format": "date-time" },
            "to": { "type": "string", "format": "date-time" },
            "has_media": { "type": "boolean" }
        }),
        WaArchiveQueryOperation::ChatList => json!({
            "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
            "cursor": { "type": "string", "minLength": 1, "maxLength": 2048 }
        }),
        WaArchiveQueryOperation::ContactSearch => json!({
            "query": { "type": "string" },
            "limit": { "type": "integer", "minimum": 1, "maximum": 200 }
        }),
        WaArchiveQueryOperation::MessageEventList => json!({
            "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
            "message_id": { "type": "string" },
            "event_type": { "type": "string", "enum": ["edit", "revoke", "reaction"] }
        }),
        WaArchiveQueryOperation::ProtocolEventList => json!({
            "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
            "chat_id": { "type": "string" },
            "event_type": { "type": "string" }
        }),
        WaArchiveQueryOperation::ConversationExport => json!({
            "chat_id": { "type": "string", "minLength": 1, "maxLength": 512 }
        }),
        WaArchiveQueryOperation::MediaGet => json!({
            "message_id": { "type": "string", "minLength": 1, "maxLength": 512 }
        }),
        WaArchiveQueryOperation::OutboxList => json!({
            "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
            "cursor": { "type": "integer", "minimum": 1 }
        }),
        WaArchiveQueryOperation::OutboxGet => json!({
            "provider_operation_id": { "type": "string", "minLength": 1, "maxLength": 200 }
        }),
        WaArchiveQueryOperation::AccountGet => json!({}),
        WaArchiveQueryOperation::AmbiguityResolutionList => json!({
            "provider_operation_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "limit": { "type": "integer", "minimum": 1, "maximum": 100 }
        }),
    };
    let required = match operation {
        WaArchiveQueryOperation::ConversationExport => vec!["chat_id"],
        WaArchiveQueryOperation::MediaGet => vec!["message_id"],
        WaArchiveQueryOperation::OutboxGet => vec!["provider_operation_id"],
        WaArchiveQueryOperation::AmbiguityResolutionList => vec!["provider_operation_id"],
        _ => Vec::new(),
    };
    json!({
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": false
    })
}

fn query_output_schema(operation: WaArchiveQueryOperation) -> Value {
    let nullable_string = || json!({ "type": ["string", "null"] });
    let message = json!({
        "type": "object",
        "required": [
            "messageId", "direction", "sentAt", "chatId", "canonicalChatId", "sender",
            "chat", "messageType", "body", "editedAt", "revokedAt", "quote"
        ],
        "properties": {
            "messageId": { "type": "string" },
            "direction": { "enum": ["incoming", "outgoing"] },
            "sentAt": { "type": "string", "format": "date-time" },
            "chatId": { "type": "string" },
            "canonicalChatId": { "type": "string" },
            "sender": { "type": "string" },
            "chat": { "type": "string" },
            "messageType": { "type": "string" },
            "body": nullable_string(),
            "editedAt": { "type": ["string", "null"], "format": "date-time" },
            "revokedAt": { "type": ["string", "null"], "format": "date-time" },
            "quote": {
                "type": "object",
                "required": ["messageId", "senderId", "body", "messageType"],
                "properties": {
                    "messageId": nullable_string(),
                    "senderId": nullable_string(),
                    "body": nullable_string(),
                    "messageType": nullable_string()
                },
                "additionalProperties": false
            }
        },
        "additionalProperties": false
    });
    let outbox = json!({
        "type": "object",
        "required": [
            "id", "createdAt", "toPhone", "toChatId", "status", "attempts", "ack",
            "whatsappMessageId", "body", "failureClass", "lastError", "idempotencyKey",
            "sendAsVoice", "quotedMessageId", "operationKind", "operationVersion",
            "operationPayload", "safetyClass", "confirmedAt", "result", "completedAt",
            "ambiguityResolution", "ambiguityResolvedAt", "ambiguityResolvedBy"
        ],
        "properties": {
            "id": { "type": "integer", "minimum": 1 },
            "createdAt": { "type": "string", "format": "date-time" },
            "toPhone": nullable_string(),
            "toChatId": nullable_string(),
            "status": { "type": "string" },
            "attempts": { "type": "integer", "minimum": 0 },
            "ack": { "type": ["integer", "null"] },
            "whatsappMessageId": nullable_string(),
            "body": { "type": "string" },
            "failureClass": nullable_string(),
            "lastError": nullable_string(),
            "idempotencyKey": nullable_string(),
            "sendAsVoice": { "type": "boolean" },
            "quotedMessageId": nullable_string(),
            "operationKind": { "type": "string" },
            "operationVersion": { "type": "integer", "minimum": 1 },
            "operationPayload": { "type": "object" },
            "safetyClass": { "enum": ["read_only", "standard", "sensitive", "destructive"] },
            "confirmedAt": { "type": ["string", "null"], "format": "date-time" },
            "result": {},
            "completedAt": { "type": ["string", "null"], "format": "date-time" },
            "ambiguityResolution": {
                "type": ["string", "null"],
                "enum": ["committed", "not_committed", null]
            },
            "ambiguityResolvedAt": { "type": ["string", "null"], "format": "date-time" },
            "ambiguityResolvedBy": nullable_string()
        },
        "additionalProperties": false
    });
    match operation {
        WaArchiveQueryOperation::MessageList => paged_query_output(message, true),
        WaArchiveQueryOperation::ChatList => paged_query_output(
            json!({
                "type": "object",
                "required": [
                    "chatId", "chatName", "isGroup", "lastMessageAt", "messageCount",
                    "liveChatIds", "historyStatus"
                ],
                "properties": {
                    "chatId": { "type": "string" },
                    "chatName": nullable_string(),
                    "isGroup": { "type": "boolean" },
                    "lastMessageAt": { "type": ["string", "null"], "format": "date-time" },
                    "messageCount": { "type": "integer", "minimum": 0 },
                    "liveChatIds": { "type": "array", "items": { "type": "string" } },
                    "historyStatus": nullable_string()
                },
                "additionalProperties": false
            }),
            true,
        ),
        WaArchiveQueryOperation::ContactSearch => paged_query_output(
            json!({
                "type": "object",
                "required": [
                    "canonicalId", "phone", "contactId", "lidId", "name", "pushName",
                    "isMyContact", "isWaContact", "isBlocked", "aliases"
                ],
                "properties": {
                    "canonicalId": { "type": "string" },
                    "phone": nullable_string(),
                    "contactId": nullable_string(),
                    "lidId": nullable_string(),
                    "name": nullable_string(),
                    "pushName": nullable_string(),
                    "isMyContact": { "type": "boolean" },
                    "isWaContact": { "type": "boolean" },
                    "isBlocked": { "type": "boolean" },
                    "aliases": { "type": "array", "items": { "type": "string" } }
                },
                "additionalProperties": false
            }),
            false,
        ),
        WaArchiveQueryOperation::MessageEventList => {
            paged_query_output(event_output_schema(false), false)
        }
        WaArchiveQueryOperation::ProtocolEventList => {
            paged_query_output(event_output_schema(true), false)
        }
        WaArchiveQueryOperation::ConversationExport => json!({
            "type": "object",
            "required": ["chatId", "messages"],
            "properties": {
                "chatId": { "type": "string" },
                "messages": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": [
                            "eventId", "direction", "chatId", "peerId", "body", "messageType",
                            "deliveryStatus", "eventAt", "liveChatId", "quotedMessageId",
                            "quotedSenderId", "quotedBody", "quotedMessageType"
                        ],
                        "properties": {
                            "eventId": { "type": "string" },
                            "direction": { "enum": ["incoming", "outgoing"] },
                            "chatId": { "type": "string" },
                            "peerId": { "type": "string" },
                            "body": nullable_string(),
                            "messageType": { "type": "string" },
                            "deliveryStatus": nullable_string(),
                            "eventAt": { "type": "string", "format": "date-time" },
                            "liveChatId": { "type": "string" },
                            "quotedMessageId": nullable_string(),
                            "quotedSenderId": nullable_string(),
                            "quotedBody": nullable_string(),
                            "quotedMessageType": nullable_string()
                        },
                        "additionalProperties": false
                    }
                }
            },
            "additionalProperties": false
        }),
        WaArchiveQueryOperation::MediaGet => json!({
            "type": "object",
            "required": [
                "message_id", "filename", "content_type", "size_bytes", "sha256",
                "content_base64"
            ],
            "properties": {
                "message_id": { "type": "string" },
                "filename": { "type": "string", "minLength": 1, "maxLength": 255 },
                "content_type": { "type": "string", "minLength": 1, "maxLength": 255 },
                "size_bytes": { "type": "integer", "minimum": 0, "maximum": MAX_MEDIA_BYTES },
                "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                "content_base64": {
                    "type": "string",
                    "maxLength": MAX_MEDIA_BYTES.div_ceil(3) * 4
                }
            },
            "additionalProperties": false
        }),
        WaArchiveQueryOperation::OutboxList => paged_query_output(outbox.clone(), true),
        WaArchiveQueryOperation::OutboxGet => json!({
            "type": "object",
            "required": ["job"],
            "properties": { "job": outbox },
            "additionalProperties": false
        }),
        WaArchiveQueryOperation::AccountGet => json!({
            "type": "object",
            "required": [
                "paired", "accountId", "phoneJid", "lidJid", "businessName", "platform",
                "pairedAt", "observedAt"
            ],
            "properties": {
                "paired": { "type": "boolean" },
                "accountId": nullable_string(),
                "phoneJid": nullable_string(),
                "lidJid": nullable_string(),
                "businessName": nullable_string(),
                "platform": nullable_string(),
                "pairedAt": { "type": ["string", "null"], "format": "date-time" },
                "observedAt": { "type": ["string", "null"], "format": "date-time" }
            },
            "additionalProperties": false
        }),
        WaArchiveQueryOperation::AmbiguityResolutionList => {
            paged_query_output(provider_ambiguity_resolution_item_schema(), false)
        }
    }
}

fn ambiguity_resolution_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["provider_operation_id", "resolution", "reason", "evidence"],
        "properties": {
            "provider_operation_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "resolution": { "enum": ["committed", "not_committed"] },
            "reason": { "type": "string", "minLength": 1, "maxLength": 2000 },
            "evidence": { "type": "object", "minProperties": 1 },
            "whatsapp_message_id": { "type": "string", "minLength": 1, "maxLength": 512 },
            "result": {}
        },
        "additionalProperties": false
    })
}

fn ambiguity_resolution_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["provider_operation_id", "resolution"],
        "properties": {
            "provider_operation_id": { "type": "string" },
            "resolution": provider_ambiguity_resolution_item_schema()
        },
        "additionalProperties": false
    })
}

fn provider_ambiguity_resolution_item_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "id", "outboxId", "created", "idempotencyKey", "resolution", "actor",
            "reason", "evidence", "whatsappMessageId", "result", "resolvedAt"
        ],
        "properties": {
            "id": { "type": "integer", "minimum": 1 },
            "outboxId": { "type": "integer", "minimum": 1 },
            "created": { "type": "boolean" },
            "idempotencyKey": { "type": "string", "minLength": 1, "maxLength": 200 },
            "resolution": { "enum": ["committed", "not_committed"] },
            "actor": { "type": "string", "minLength": 1, "maxLength": 200 },
            "reason": { "type": "string", "minLength": 1, "maxLength": 2000 },
            "evidence": { "type": "object", "minProperties": 1 },
            "whatsappMessageId": { "type": ["string", "null"] },
            "result": {},
            "resolvedAt": { "type": "string", "format": "date-time" }
        },
        "additionalProperties": false
    })
}

fn paged_query_output(item: Value, has_cursor: bool) -> Value {
    let mut properties = Map::from_iter([(
        "items".to_owned(),
        json!({ "type": "array", "items": item }),
    )]);
    let mut required = vec![Value::String("items".to_owned())];
    if has_cursor {
        properties.insert(
            "nextCursor".to_owned(),
            json!({ "type": ["string", "integer", "null"] }),
        );
        required.push(Value::String("nextCursor".to_owned()));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": false
    })
}

fn event_output_schema(protocol: bool) -> Value {
    let (required, properties) = if protocol {
        (
            json!([
                "eventKey",
                "eventType",
                "chatId",
                "actorId",
                "payload",
                "occurredAt"
            ]),
            json!({
                "eventKey": { "type": "string" },
                "eventType": { "type": "string" },
                "chatId": { "type": ["string", "null"] },
                "actorId": { "type": ["string", "null"] },
                "payload": { "type": "object" },
                "occurredAt": { "type": "string", "format": "date-time" }
            }),
        )
    } else {
        (
            json!([
                "eventKey",
                "messageId",
                "eventType",
                "actorId",
                "payload",
                "occurredAt"
            ]),
            json!({
                "eventKey": { "type": "string" },
                "messageId": { "type": "string" },
                "eventType": { "enum": ["edit", "revoke", "reaction"] },
                "actorId": { "type": ["string", "null"] },
                "payload": { "type": "object" },
                "occurredAt": { "type": "string", "format": "date-time" }
            }),
        )
    };
    json!({
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": false
    })
}

fn operation_contract(operation: WaArchiveOperation) -> CapabilityContract {
    let safety = operation.safety_class();
    let read_only = safety == WaArchiveSafetyClass::ReadOnly;
    let requires_approval = safety.requires_approval();
    let mut side_effects = if read_only {
        vec![SideEffect::Read, SideEffect::ExternalNetwork]
    } else if safety == WaArchiveSafetyClass::Destructive {
        vec![
            SideEffect::Delete,
            SideEffect::Write,
            SideEffect::ExternalNetwork,
        ]
    } else {
        vec![SideEffect::Write, SideEffect::ExternalNetwork]
    };
    if operation.suffix().starts_with("send_")
        || operation.suffix().starts_with("status_")
        || operation.suffix().starts_with("call_")
        || matches!(
            operation.suffix(),
            "edit_message"
                | "edit_message_encrypted"
                | "revoke_message"
                | "read_receipt"
                | "played_receipt"
                | "event_create"
                | "event_respond"
        )
    {
        side_effects.push(SideEffect::SendMessage);
    }
    if operation.suffix().starts_with("profile_")
        || operation.suffix().starts_with("privacy_")
        || operation.suffix().starts_with("blocklist_")
        || operation.suffix().starts_with("group_")
        || operation.suffix().starts_with("community_")
    {
        side_effects.push(SideEffect::Identity);
    }
    CapabilityContract {
        side_effects,
        idempotency: IdempotencyContract {
            requirement: IdempotencyRequirement::Required,
            collision_behavior: IdempotencyCollisionBehavior::RevalidateInputHash,
            key_scope: IdempotencyKeyScope::ExternalAccount,
            ttl_ms: None,
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: false,
            supports_streaming: false,
            supports_cancel: true,
            supports_retry: true,
            expected_completion: ExpectedCompletionMode::Sync,
            retry_safety: RetrySafety::SafeWithIdempotencyKey,
        },
        data: DataContract {
            sensitivity: DataSensitivity::Restricted,
            contains_pii: true,
            redaction_required: true,
            residency: None,
            retention: None,
        },
        credentials: None::<CredentialPolicy>,
        approval: requires_approval.then(|| ApprovalPolicy {
            required: true,
            reason: Some(format!(
                "WA Archive classifies `{}` as a {} account operation.",
                operation.suffix(),
                safety.as_str()
            )),
            approver_selector: ApproverSelector::TenantPolicy,
            ttl_ms: Some(900_000),
            evidence_requirements: vec![
                EvidenceRequirement::Reason,
                EvidenceRequirement::InputSnapshot,
                EvidenceRequirement::PolicyDecision,
            ],
            policy_version: Some("wa-archive-production-operation-v1".to_owned()),
            ..ApprovalPolicy::default()
        }),
        sla: Some(ServiceLevelContract {
            expected_latency_ms: Some(if read_only { 5_000 } else { 15_000 }),
            timeout_ms: Some(120_000),
            async_expected: false,
            max_queue_delay_ms: Some(30_000),
            availability_target: Some("99.9%".to_owned()),
        }),
        transaction: (!read_only).then(|| TransactionContract {
            supported_modes: vec![
                TransactionMode::DryRun,
                TransactionMode::Plan,
                TransactionMode::Commit,
                TransactionMode::Reconcile,
            ],
            requires_plan_before_commit: requires_approval,
            dry_run_fidelity: DryRunFidelity::DownstreamValidation,
        }),
        compensation: Some(if read_only {
            CompensationContract {
                mode: CompensationMode::NotRequired,
                compensation_capability_id: None,
                compensation_window_ms: None,
                requires_approval: false,
            }
        } else {
            CompensationContract {
                mode: CompensationMode::RollbackNotSupported,
                compensation_capability_id: None,
                compensation_window_ms: None,
                requires_approval: true,
            }
        }),
    }
}

fn query_contract() -> CapabilityContract {
    CapabilityContract {
        side_effects: vec![SideEffect::Read, SideEffect::ExternalNetwork],
        idempotency: IdempotencyContract {
            requirement: IdempotencyRequirement::Optional,
            collision_behavior: IdempotencyCollisionBehavior::ReturnOriginalResult,
            key_scope: IdempotencyKeyScope::Action,
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
            sensitivity: DataSensitivity::Restricted,
            contains_pii: true,
            redaction_required: true,
            residency: None,
            retention: None,
        },
        credentials: None,
        approval: None,
        sla: Some(ServiceLevelContract {
            expected_latency_ms: Some(2_000),
            timeout_ms: Some(30_000),
            async_expected: false,
            max_queue_delay_ms: Some(5_000),
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

fn ambiguity_resolution_contract() -> CapabilityContract {
    CapabilityContract {
        side_effects: vec![
            SideEffect::Write,
            SideEffect::Legal,
            SideEffect::ExternalNetwork,
        ],
        idempotency: IdempotencyContract {
            requirement: IdempotencyRequirement::Required,
            collision_behavior: IdempotencyCollisionBehavior::RevalidateInputHash,
            key_scope: IdempotencyKeyScope::ExternalAccount,
            ttl_ms: None,
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: false,
            supports_streaming: false,
            supports_cancel: false,
            supports_retry: true,
            expected_completion: ExpectedCompletionMode::Sync,
            retry_safety: RetrySafety::SafeWithIdempotencyKey,
        },
        data: DataContract {
            sensitivity: DataSensitivity::Restricted,
            contains_pii: true,
            redaction_required: true,
            residency: None,
            retention: None,
        },
        credentials: None,
        approval: Some(ApprovalPolicy {
            required: true,
            reason: Some(
                "Resolving an unknown provider outcome changes durable execution truth and retry eligibility."
                    .to_owned(),
            ),
            approver_selector: ApproverSelector::TenantPolicy,
            ttl_ms: Some(900_000),
            evidence_requirements: vec![
                EvidenceRequirement::Reason,
                EvidenceRequirement::InputSnapshot,
                EvidenceRequirement::PolicyDecision,
            ],
            policy_version: Some("wa-archive-ambiguity-resolution-v1".to_owned()),
            ..ApprovalPolicy::default()
        }),
        sla: Some(ServiceLevelContract {
            expected_latency_ms: Some(5_000),
            timeout_ms: Some(30_000),
            async_expected: false,
            max_queue_delay_ms: Some(5_000),
            availability_target: Some("99.9%".to_owned()),
        }),
        transaction: Some(TransactionContract {
            supported_modes: vec![
                TransactionMode::DryRun,
                TransactionMode::Plan,
                TransactionMode::Commit,
            ],
            requires_plan_before_commit: true,
            dry_run_fidelity: DryRunFidelity::DownstreamValidation,
        }),
        compensation: Some(CompensationContract {
            mode: CompensationMode::RollbackNotSupported,
            compensation_capability_id: None,
            compensation_window_ms: None,
            requires_approval: true,
        }),
    }
}

#[derive(Clone, Copy)]
enum CapabilityRoute {
    Provider(WaArchiveOperation),
    Query(WaArchiveQueryOperation),
    Control(WaArchiveControlOperation),
}

fn capability_route(id: &CapabilityId) -> Option<CapabilityRoute> {
    if let Some(suffix) = id.as_str().strip_prefix(QUERY_CAPABILITY_PREFIX) {
        return WaArchiveQueryOperation::from_suffix(suffix).map(CapabilityRoute::Query);
    }
    let suffix = id.as_str().strip_prefix(CAPABILITY_PREFIX)?;
    WaArchiveOperation::from_suffix(suffix)
        .map(CapabilityRoute::Provider)
        .or_else(|| WaArchiveControlOperation::from_suffix(suffix).map(CapabilityRoute::Control))
}

fn legacy_query_operation(id: &CapabilityId) -> Option<WaArchiveQueryOperation> {
    let suffix = id.as_str().strip_prefix(CAPABILITY_PREFIX)?;
    WaArchiveQueryOperation::from_suffix(suffix)
}

impl WaArchiveConnector {
    async fn invoke_action(
        &self,
        action: Action,
        context: Option<&ActionExecutionContext>,
    ) -> Result<ActionResult, ConnectorFailure> {
        let route = capability_route(&action.capability_id).ok_or_else(|| {
            invalid_failure(
                "unsupported WA Archive capability",
                ConnectorOperation::Invocation,
            )
        })?;
        self.await_provider(
            self.ensure_contract(false),
            context,
            ConnectorOperation::Invocation,
            None,
            false,
        )
        .await?;
        match route {
            CapabilityRoute::Query(operation) => {
                if !self.allowed_query_operations.contains(&operation) {
                    return Err(invalid_failure(
                        "WA Archive query capability is not admitted for this connector instance",
                        ConnectorOperation::Invocation,
                    ));
                }
                self.execute_query(operation, action, context).await
            }
            CapabilityRoute::Provider(operation) => {
                if !self.allowed_operations.contains(&operation) {
                    return Err(invalid_failure(
                        "WA Archive capability is not admitted for this connector instance",
                        ConnectorOperation::Invocation,
                    ));
                }
                if operation.safety_class().requires_approval() {
                    return Err(ConnectorFailure {
                        code: "connector.wa_archive.transaction_required".to_owned(),
                        message: "sensitive and destructive WA Archive operations require AIP Plan and Commit"
                            .to_owned(),
                        category: ErrorCategory::Policy,
                        retryable: false,
                        retry_after_ms: None,
                        provider_request_id: None,
                        provider_operation: None,
                        remote_status: None,
                        uncertain_outcome: false,
                        redacted_details: None,
                        source_component: CONNECTOR_ID.to_owned(),
                        operation: ConnectorOperation::Invocation,
                    });
                }
                self.execute_provider_operation(
                    operation,
                    action,
                    context,
                    ConnectorOperation::Invocation,
                )
                .await
            }
            CapabilityRoute::Control(operation) => {
                if !self.allowed_control_operations.contains(&operation) {
                    return Err(invalid_failure(
                        "WA Archive control capability is not admitted for this connector instance",
                        ConnectorOperation::Invocation,
                    ));
                }
                Err(ConnectorFailure {
                    code: "connector.wa_archive.transaction_required".to_owned(),
                    message: "ambiguity resolution requires AIP Plan, verified human approval, and Commit"
                        .to_owned(),
                    category: ErrorCategory::Policy,
                    retryable: false,
                    retry_after_ms: None,
                    provider_request_id: None,
                    provider_operation: None,
                    remote_status: None,
                    uncertain_outcome: false,
                    redacted_details: None,
                    source_component: CONNECTOR_ID.to_owned(),
                    operation: ConnectorOperation::Invocation,
                })
            }
        }
    }

    async fn execute_provider_operation(
        &self,
        operation: WaArchiveOperation,
        action: Action,
        context: Option<&ActionExecutionContext>,
        connector_operation: ConnectorOperation,
    ) -> Result<ActionResult, ConnectorFailure> {
        let requires_approval = operation.safety_class().requires_approval();
        if requires_approval
            && context
                .and_then(|value| value.transaction.as_ref())
                .is_none()
        {
            return Err(ConnectorFailure {
                code: "connector.wa_archive.transaction_required".to_owned(),
                message: "sensitive and destructive WA Archive operations require a verified AIP transaction context"
                    .to_owned(),
                category: ErrorCategory::Policy,
                retryable: false,
                retry_after_ms: None,
                provider_request_id: None,
                provider_operation: None,
                remote_status: None,
                uncertain_outcome: false,
                redacted_details: None,
                source_component: CONNECTOR_ID.to_owned(),
                operation: connector_operation,
            });
        }
        if requires_approval && context.and_then(|value| value.approval.as_ref()).is_none() {
            return Err(ConnectorFailure {
                code: "connector.wa_archive.approval_required".to_owned(),
                message: "verified AIP approval is required for this WA Archive operation"
                    .to_owned(),
                category: ErrorCategory::Policy,
                retryable: false,
                retry_after_ms: None,
                provider_request_id: None,
                provider_operation: None,
                remote_status: None,
                uncertain_outcome: false,
                redacted_details: None,
                source_component: CONNECTOR_ID.to_owned(),
                operation: connector_operation,
            });
        }
        let prepared = self
            .await_provider(
                self.prepare_operation_input(operation, &action, true, requires_approval),
                context,
                connector_operation,
                None,
                false,
            )
            .await?;
        let provider_operation = Self::provider_operation_ref(&prepared.provider_key);
        self.await_provider(
            self.validate_provider_operation(operation, &prepared),
            context,
            connector_operation,
            Some(provider_operation.clone()),
            false,
        )
        .await?;
        if let Some(context) = context.filter(|context| context.transaction.is_some()) {
            context
                .transaction_checkpoint
                .checkpoint(provider_operation.clone(), None)
                .await
                .map_err(|error| {
                    ConnectorFailure::from_runtime_error(error, connector_operation, CONNECTOR_ID)
                })?;
        }
        let path = if prepared.enqueue_body.get("dataBase64").is_some() {
            "/v1/operations/media"
        } else {
            "/v1/operations"
        };
        let submitted = self
            .await_provider(
                self.post_json::<ProviderJobEnvelope>(path, &prepared.enqueue_body),
                context,
                connector_operation,
                Some(provider_operation.clone()),
                true,
            )
            .await?;
        validate_provider_job(&submitted.job, operation, &prepared.provider_key).map_err(
            |error| {
                connector_failure(
                    error,
                    connector_operation,
                    Some(Self::provider_operation_ref(&prepared.provider_key)),
                    true,
                )
            },
        )?;
        self.wait_for_terminal_job(
            operation,
            action,
            submitted.job,
            &prepared.provider_key,
            context,
            connector_operation,
        )
        .await
    }

    async fn plan_ambiguity_resolution(
        &self,
        action: Action,
        context: &ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        let input = parse_ambiguity_resolution_input(&action).map_err(|error| {
            connector_failure(error, ConnectorOperation::TransactionPlan, None, false)
        })?;
        let job = self
            .lookup_provider_job(
                &input.provider_operation_id,
                ConnectorOperation::TransactionPlan,
                Some(context),
            )
            .await?
            .ok_or_else(|| {
                connector_failure(
                    WaArchiveConnectorError::OperationNotFound,
                    ConnectorOperation::TransactionPlan,
                    Some(Self::provider_operation_ref(&input.provider_operation_id)),
                    false,
                )
            })?;
        if job.status != "ambiguous" {
            return Err(invalid_failure(
                "only a currently ambiguous WA Archive operation can be resolved",
                ConnectorOperation::TransactionPlan,
            ));
        }
        let resolution_key =
            ambiguity_resolution_idempotency_key(&self.external_account_id, &action).map_err(
                |error| {
                    connector_failure(
                        error,
                        ConnectorOperation::TransactionPlan,
                        Some(Self::provider_operation_ref(&input.provider_operation_id)),
                        false,
                    )
                },
            )?;
        let evidence_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&input.evidence).map_err(|error| {
                connector_failure(
                    WaArchiveConnectorError::InvalidAction(error.to_string()),
                    ConnectorOperation::TransactionPlan,
                    Some(Self::provider_operation_ref(&input.provider_operation_id)),
                    false,
                )
            })?,
        ));
        Ok(completed_result(
            action,
            json!({
                "planned": true,
                "provider_operation_id": input.provider_operation_id,
                "provider_job_id": job.id,
                "current_status": job.status,
                "resolution": input.resolution,
                "resolution_request_id": resolution_key,
                "actor": context.actor.principal.id.as_str(),
                "evidence_sha256": evidence_digest,
                "validation": "provider_ambiguity_state_and_evidence_contract",
                "side_effect_committed": false
            }),
        ))
    }

    async fn commit_ambiguity_resolution(
        &self,
        action: Action,
        context: &ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        if context.transaction.is_none() {
            return Err(invalid_failure(
                "ambiguity resolution requires a verified AIP transaction context",
                ConnectorOperation::TransactionCommit,
            ));
        }
        if context.approval.is_none() {
            return Err(ConnectorFailure {
                code: "connector.wa_archive.approval_required".to_owned(),
                message: "verified human approval is required to resolve an ambiguous outcome"
                    .to_owned(),
                category: ErrorCategory::Policy,
                retryable: false,
                retry_after_ms: None,
                provider_request_id: None,
                provider_operation: None,
                remote_status: None,
                uncertain_outcome: false,
                redacted_details: None,
                source_component: CONNECTOR_ID.to_owned(),
                operation: ConnectorOperation::TransactionCommit,
            });
        }
        let input = parse_ambiguity_resolution_input(&action).map_err(|error| {
            connector_failure(error, ConnectorOperation::TransactionCommit, None, false)
        })?;
        let job = self
            .lookup_provider_job(
                &input.provider_operation_id,
                ConnectorOperation::TransactionCommit,
                Some(context),
            )
            .await?
            .ok_or_else(|| {
                connector_failure(
                    WaArchiveConnectorError::OperationNotFound,
                    ConnectorOperation::TransactionCommit,
                    Some(Self::provider_operation_ref(&input.provider_operation_id)),
                    false,
                )
            })?;
        let resolution_key =
            ambiguity_resolution_idempotency_key(&self.external_account_id, &action).map_err(
                |error| {
                    connector_failure(
                        error,
                        ConnectorOperation::TransactionCommit,
                        Some(Self::provider_operation_ref(&input.provider_operation_id)),
                        false,
                    )
                },
            )?;
        let actor = context.actor.principal.id.as_str();
        let body = json!({
            "idempotencyKey": resolution_key,
            "resolution": input.resolution,
            "actor": actor,
            "reason": input.reason,
            "evidence": input.evidence,
            "whatsappMessageId": input.whatsapp_message_id,
            "result": input.result
        });
        let path = format!("/v1/outbox/{}/resolve-ambiguity", job.id);
        let response = self
            .await_provider(
                self.post_json::<ProviderAmbiguityResolutionEnvelope>(&path, &body),
                Some(context),
                ConnectorOperation::TransactionCommit,
                Some(Self::provider_operation_ref(&input.provider_operation_id)),
                false,
            )
            .await?;
        validate_provider_ambiguity_resolution(
            &response.resolution,
            job.id,
            Some(&resolution_key),
            Some(actor),
        )
        .map_err(|error| {
            connector_failure(
                error,
                ConnectorOperation::TransactionCommit,
                Some(Self::provider_operation_ref(&input.provider_operation_id)),
                false,
            )
        })?;
        if response.resolution.resolution != input.resolution
            || response.resolution.reason != input.reason
            || response.resolution.evidence != input.evidence
            || response.resolution.whatsapp_message_id != input.whatsapp_message_id
            || response.resolution.result != input.result
        {
            return Err(connector_failure(
                WaArchiveConnectorError::ContractMismatch(
                    "provider ambiguity resolution differs from the approved request".to_owned(),
                ),
                ConnectorOperation::TransactionCommit,
                Some(Self::provider_operation_ref(&input.provider_operation_id)),
                false,
            ));
        }
        let resolution = serde_json::to_value(response.resolution).map_err(|error| {
            connector_failure(
                WaArchiveConnectorError::ContractMismatch(error.to_string()),
                ConnectorOperation::TransactionCommit,
                Some(Self::provider_operation_ref(&input.provider_operation_id)),
                false,
            )
        })?;
        Ok(completed_result(
            action,
            json!({
                "provider_operation_id": input.provider_operation_id,
                "resolution": redact_provider_paths(resolution)
            }),
        ))
    }

    async fn wait_for_terminal_job(
        &self,
        operation: WaArchiveOperation,
        action: Action,
        mut job: ProviderJob,
        provider_key: &str,
        context: Option<&ActionExecutionContext>,
        connector_operation: ConnectorOperation,
    ) -> Result<ActionResult, ConnectorFailure> {
        loop {
            match job.status.as_str() {
                "sent" | "delivered" | "read" | "played" | "succeeded" => {
                    return Ok(completed_result(
                        action,
                        safe_job_output(&job, operation, provider_key),
                    ));
                }
                "failed" | "cancelled" => {
                    return Err(ConnectorFailure {
                        code: format!("connector.wa_archive.{}", job.status),
                        message: format!("WA Archive operation ended in `{}`", job.status),
                        category: ErrorCategory::Permanent,
                        retryable: false,
                        retry_after_ms: None,
                        provider_request_id: None,
                        provider_operation: Some(Self::provider_operation_ref(provider_key)),
                        remote_status: None,
                        uncertain_outcome: false,
                        redacted_details: Some(json!({
                            "status": job.status,
                            "failure_class": job.failure_class,
                            "attempts": job.attempts
                        })),
                        source_component: CONNECTOR_ID.to_owned(),
                        operation: connector_operation,
                    });
                }
                "ambiguous" => {
                    return Err(ConnectorFailure {
                        code: "connector.wa_archive.outcome_ambiguous".to_owned(),
                        message: "WA Archive crossed the send boundary without a definitive outcome; automatic retry is forbidden"
                            .to_owned(),
                        category: ErrorCategory::Temporary,
                        retryable: false,
                        retry_after_ms: None,
                        provider_request_id: None,
                        provider_operation: Some(Self::provider_operation_ref(provider_key)),
                        remote_status: None,
                        uncertain_outcome: true,
                        redacted_details: Some(json!({
                            "status": job.status,
                            "failure_class": job.failure_class,
                            "attempts": job.attempts
                        })),
                        source_component: CONNECTOR_ID.to_owned(),
                        operation: connector_operation,
                    });
                }
                "pending" | "processing" | "retry_wait" | "sending" => {}
                status => {
                    return Err(connector_failure(
                        WaArchiveConnectorError::ContractMismatch(format!(
                            "unknown provider outbox status `{status}`"
                        )),
                        connector_operation,
                        Some(Self::provider_operation_ref(provider_key)),
                        status == "sending",
                    ));
                }
            }
            let path = outbox_lookup_path(provider_key).map_err(|error| {
                connector_failure(
                    error,
                    connector_operation,
                    Some(Self::provider_operation_ref(provider_key)),
                    job.status == "sending",
                )
            })?;
            let query = vec![
                ("knownStatus", job.status.clone()),
                ("waitMs", OUTBOX_LONG_POLL_MS.to_string()),
            ];
            let current_status_is_uncertain = job.status == "sending";
            let response = self
                .await_provider(
                    self.get_json::<ProviderJobEnvelope>(&path, &query),
                    context,
                    connector_operation,
                    Some(Self::provider_operation_ref(provider_key)),
                    current_status_is_uncertain,
                )
                .await?;
            validate_provider_job(&response.job, operation, provider_key).map_err(|error| {
                connector_failure(
                    error,
                    connector_operation,
                    Some(Self::provider_operation_ref(provider_key)),
                    true,
                )
            })?;
            job = response.job;
        }
    }

    async fn await_provider<T, F>(
        &self,
        future: F,
        context: Option<&ActionExecutionContext>,
        operation: ConnectorOperation,
        provider_operation: Option<ProviderOperationRef>,
        dispatched_or_sending: bool,
    ) -> Result<T, ConnectorFailure>
    where
        F: Future<Output = Result<T, WaArchiveConnectorError>>,
    {
        let Some(context) = context else {
            return future.await.map_err(|error| {
                connector_failure(error, operation, provider_operation, dispatched_or_sending)
            });
        };
        let remaining = context.deadline.remaining(OffsetDateTime::now_utc());
        if remaining.is_zero() {
            return Err(timeout_failure(
                operation,
                provider_operation,
                dispatched_or_sending,
            ));
        }
        tokio::select! {
            result = future => result.map_err(|error| connector_failure(
                error,
                operation,
                provider_operation,
                dispatched_or_sending,
            )),
            () = context.cancellation.cancelled() => Err(cancelled_failure(
                operation,
                provider_operation,
                dispatched_or_sending,
            )),
            () = tokio::time::sleep(remaining) => Err(timeout_failure(
                operation,
                provider_operation,
                dispatched_or_sending,
            )),
        }
    }

    async fn execute_query(
        &self,
        operation: WaArchiveQueryOperation,
        action: Action,
        context: Option<&ActionExecutionContext>,
    ) -> Result<ActionResult, ConnectorFailure> {
        if operation == WaArchiveQueryOperation::MediaGet {
            let object = action.input.as_object().ok_or_else(|| {
                invalid_failure(
                    "WA Archive media query input must be an object",
                    ConnectorOperation::Invocation,
                )
            })?;
            if object.len() != 1 {
                return Err(invalid_failure(
                    "archive.media.get accepts only message_id",
                    ConnectorOperation::Invocation,
                ));
            }
            let message_id = required_query_string(object, "message_id").map_err(|error| {
                connector_failure(error, ConnectorOperation::Invocation, None, false)
            })?;
            let value = self
                .await_provider(
                    self.get_media(message_id),
                    context,
                    ConnectorOperation::Invocation,
                    None,
                    false,
                )
                .await?;
            return Ok(completed_result(action, value));
        }
        if operation == WaArchiveQueryOperation::AmbiguityResolutionList {
            let object = action.input.as_object().ok_or_else(|| {
                invalid_failure(
                    "WA Archive ambiguity-resolution query input must be an object",
                    ConnectorOperation::Invocation,
                )
            })?;
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "provider_operation_id" | "limit"))
            {
                return Err(invalid_failure(
                    "archive.ambiguity_resolution.list contains an unknown property",
                    ConnectorOperation::Invocation,
                ));
            }
            let provider_key =
                required_query_string(object, "provider_operation_id").map_err(|error| {
                    connector_failure(error, ConnectorOperation::Invocation, None, false)
                })?;
            outbox_lookup_path(provider_key).map_err(|error| {
                connector_failure(error, ConnectorOperation::Invocation, None, false)
            })?;
            let limit = object.get("limit").map_or(20, |value| {
                value
                    .as_u64()
                    .filter(|limit| (1..=100).contains(limit))
                    .unwrap_or(0)
            });
            if limit == 0 {
                return Err(invalid_failure(
                    "ambiguity-resolution history limit must be between 1 and 100",
                    ConnectorOperation::Invocation,
                ));
            }
            let job = self
                .lookup_provider_job(provider_key, ConnectorOperation::Invocation, context)
                .await?
                .ok_or_else(|| {
                    connector_failure(
                        WaArchiveConnectorError::OperationNotFound,
                        ConnectorOperation::Invocation,
                        Some(Self::provider_operation_ref(provider_key)),
                        false,
                    )
                })?;
            let path = format!("/v1/outbox/{}/ambiguity-resolutions", job.id);
            let response = self
                .await_provider(
                    self.get_json::<ProviderAmbiguityResolutionListEnvelope>(
                        &path,
                        &[("limit", limit.to_string())],
                    ),
                    context,
                    ConnectorOperation::Invocation,
                    Some(Self::provider_operation_ref(provider_key)),
                    false,
                )
                .await?;
            for resolution in &response.items {
                validate_provider_ambiguity_resolution(resolution, job.id, None, None).map_err(
                    |error| {
                        connector_failure(
                            error,
                            ConnectorOperation::Invocation,
                            Some(Self::provider_operation_ref(provider_key)),
                            false,
                        )
                    },
                )?;
            }
            let value = serde_json::to_value(response.items).map_err(|error| {
                connector_failure(
                    WaArchiveConnectorError::ContractMismatch(error.to_string()),
                    ConnectorOperation::Invocation,
                    Some(Self::provider_operation_ref(provider_key)),
                    false,
                )
            })?;
            return Ok(completed_result(
                action,
                json!({ "items": redact_provider_paths(value) }),
            ));
        }
        let (path, query) = query_request(operation, &action.input).map_err(|error| {
            connector_failure(error, ConnectorOperation::Invocation, None, false)
        })?;
        let value = self
            .await_provider(
                self.get_json::<Value>(&path, &query),
                context,
                ConnectorOperation::Invocation,
                None,
                false,
            )
            .await?;
        let value = normalize_query_output(operation, value).map_err(|error| {
            connector_failure(error, ConnectorOperation::Invocation, None, false)
        })?;
        Ok(completed_result(action, redact_provider_paths(value)))
    }

    async fn lookup_provider_job(
        &self,
        provider_key: &str,
        operation: ConnectorOperation,
        context: Option<&ActionExecutionContext>,
    ) -> Result<Option<ProviderJob>, ConnectorFailure> {
        let path = outbox_lookup_path(provider_key)
            .map_err(|error| connector_failure(error, operation, None, false))?;
        match self
            .await_provider(
                self.get_json::<ProviderJobEnvelope>(&path, &[]),
                context,
                operation,
                Some(Self::provider_operation_ref(provider_key)),
                false,
            )
            .await
        {
            Ok(response) if response.job.id > 0 && response.job.idempotency_key == provider_key => {
                Ok(Some(response.job))
            }
            Ok(_) => Err(connector_failure(
                WaArchiveConnectorError::ContractMismatch(
                    "provider outbox lookup returned mismatched metadata".to_owned(),
                ),
                operation,
                Some(Self::provider_operation_ref(provider_key)),
                false,
            )),
            Err(failure) if failure.code == "connector.wa_archive.operation_not_found" => Ok(None),
            Err(failure) => Err(failure),
        }
    }
}

#[async_trait]
impl OutboundConnector for WaArchiveConnector {
    async fn invoke(
        &self,
        _context: &ConnectorContext,
        action: Action,
    ) -> ConnectorResult<ActionResult> {
        self.invoke_action(action, None)
            .await
            .map_err(ConnectorError::Failure)
    }

    async fn cancel(&self, _context: &ConnectorContext, action: &Action) -> ConnectorResult<()> {
        self.cancel_action(action, None)
            .await
            .map_err(ConnectorError::Failure)
    }

    async fn emit(
        &self,
        _context: &ConnectorContext,
        _result: ActionResult,
    ) -> ConnectorResult<()> {
        Err(ConnectorFailure::unsupported(ConnectorOperation::Emission, CONNECTOR_ID).into())
    }
}

#[async_trait]
impl FrozenConnector for WaArchiveConnector {
    fn implementation_support(&self, capability: &Capability) -> CapabilityImplementationSupport {
        match capability_route(&capability.id) {
            Some(CapabilityRoute::Provider(operation))
                if self.allowed_operations.contains(&operation) =>
            {
                let read_only = operation.safety_class() == WaArchiveSafetyClass::ReadOnly;
                CapabilityImplementationSupport {
                    invocation: true,
                    cancellation: true,
                    streaming: false,
                    retry: true,
                    transaction: !read_only,
                    reconciliation: true,
                    compensation: false,
                    approval: operation.safety_class().requires_approval(),
                    credentials: false,
                }
            }
            Some(CapabilityRoute::Query(operation))
                if self.allowed_query_operations.contains(&operation) =>
            {
                CapabilityImplementationSupport {
                    invocation: true,
                    cancellation: false,
                    streaming: false,
                    retry: true,
                    transaction: false,
                    reconciliation: false,
                    compensation: false,
                    approval: false,
                    credentials: false,
                }
            }
            Some(CapabilityRoute::Control(operation))
                if self.allowed_control_operations.contains(&operation) =>
            {
                CapabilityImplementationSupport {
                    invocation: true,
                    cancellation: false,
                    streaming: false,
                    retry: true,
                    transaction: true,
                    reconciliation: false,
                    compensation: false,
                    approval: true,
                    credentials: false,
                }
            }
            None if capability.kind == CapabilityKind::Resource
                && legacy_query_operation(&capability.id).is_some_and(|operation| {
                    self.allowed_query_operations.contains(&operation)
                }) =>
            {
                CapabilityImplementationSupport {
                    invocation: false,
                    cancellation: false,
                    streaming: false,
                    // The immutable historical Resource contract declares a
                    // safe retry policy. It remains passive and is never
                    // entered into the ActionHandler registry.
                    retry: true,
                    transaction: false,
                    reconciliation: false,
                    compensation: false,
                    approval: false,
                    credentials: false,
                }
            }
            _ => CapabilityImplementationSupport::default(),
        }
    }

    async fn invoke_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        self.invoke_action(action, Some(&context)).await
    }

    async fn plan_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        let route = capability_route(&action.capability_id).ok_or_else(|| {
            invalid_failure(
                "unsupported WA Archive capability",
                ConnectorOperation::TransactionPlan,
            )
        })?;
        self.await_provider(
            self.ensure_contract(false),
            Some(&context),
            ConnectorOperation::TransactionPlan,
            None,
            false,
        )
        .await?;
        if let CapabilityRoute::Control(operation) = route {
            if !self.allowed_control_operations.contains(&operation) {
                return Err(invalid_failure(
                    "WA Archive control capability is not admitted for this connector instance",
                    ConnectorOperation::TransactionPlan,
                ));
            }
            return self.plan_ambiguity_resolution(action, &context).await;
        }
        let CapabilityRoute::Provider(operation) = route else {
            return Err(ConnectorFailure::unsupported(
                ConnectorOperation::TransactionPlan,
                CONNECTOR_ID,
            ));
        };
        if operation.safety_class() == WaArchiveSafetyClass::ReadOnly {
            return Err(ConnectorFailure::unsupported(
                ConnectorOperation::TransactionPlan,
                CONNECTOR_ID,
            ));
        }
        if !self.allowed_operations.contains(&operation) {
            return Err(invalid_failure(
                "WA Archive capability is not admitted for this connector instance",
                ConnectorOperation::TransactionPlan,
            ));
        }
        let prepared = self
            .await_provider(
                self.prepare_operation_input(operation, &action, false, false),
                Some(&context),
                ConnectorOperation::TransactionPlan,
                None,
                false,
            )
            .await?;
        let validation = self
            .await_provider(
                self.validate_provider_operation(operation, &prepared),
                Some(&context),
                ConnectorOperation::TransactionPlan,
                Some(Self::provider_operation_ref(&prepared.provider_key)),
                false,
            )
            .await?;
        let output = json!({
            "planned": true,
            "operation_kind": validation.operation_kind,
            "operation_version": validation.operation_version,
            "safety_class": validation.safety_class,
            "requires_confirmation": validation.requires_confirmation,
            "normalized_target": validation.normalized_target,
            "has_media": validation.has_media,
            "provider_operation_id": prepared.provider_key,
            "input_hash": prepared.input_hash,
            "validation": "downstream_schema_destination_and_policy",
            "side_effect_committed": false
        });
        Ok(completed_result(action, output))
    }

    async fn commit_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        let route = capability_route(&action.capability_id).ok_or_else(|| {
            invalid_failure(
                "unsupported WA Archive capability",
                ConnectorOperation::TransactionCommit,
            )
        })?;
        if let CapabilityRoute::Control(operation) = route {
            if !self.allowed_control_operations.contains(&operation) {
                return Err(invalid_failure(
                    "WA Archive control capability is not admitted for this connector instance",
                    ConnectorOperation::TransactionCommit,
                ));
            }
            self.await_provider(
                self.ensure_contract(false),
                Some(&context),
                ConnectorOperation::TransactionCommit,
                None,
                false,
            )
            .await?;
            return self.commit_ambiguity_resolution(action, &context).await;
        }
        let CapabilityRoute::Provider(operation) = route else {
            return Err(ConnectorFailure::unsupported(
                ConnectorOperation::TransactionCommit,
                CONNECTOR_ID,
            ));
        };
        if operation.safety_class() == WaArchiveSafetyClass::ReadOnly {
            return Err(ConnectorFailure::unsupported(
                ConnectorOperation::TransactionCommit,
                CONNECTOR_ID,
            ));
        }
        if !self.allowed_operations.contains(&operation) {
            return Err(invalid_failure(
                "WA Archive capability is not admitted for this connector instance",
                ConnectorOperation::TransactionCommit,
            ));
        }
        self.execute_provider_operation(
            operation,
            action,
            Some(&context),
            ConnectorOperation::TransactionCommit,
        )
        .await
    }

    async fn cancel_typed(
        &self,
        action: &Action,
        context: ActionExecutionContext,
    ) -> Result<(), ConnectorFailure> {
        self.cancel_action(action, Some(&context)).await
    }

    async fn reconcile_typed(
        &self,
        request: ReconciliationRequest,
        context: ActionExecutionContext,
    ) -> Result<ReconciliationResult, ConnectorFailure> {
        if request.provider_operation_id.is_empty()
            || request.provider_operation_id.len() > 200
            || request.provider_operation_id.chars().any(char::is_control)
        {
            return Err(invalid_failure(
                "invalid WA Archive provider operation id",
                ConnectorOperation::Reconciliation,
            ));
        }
        let job = self
            .lookup_provider_job(
                &request.provider_operation_id,
                ConnectorOperation::Reconciliation,
                Some(&context),
            )
            .await?;
        Ok(reconciliation_result(job, &request.provider_operation_id))
    }
}

impl WaArchiveConnector {
    async fn cancel_action(
        &self,
        action: &Action,
        context: Option<&ActionExecutionContext>,
    ) -> Result<(), ConnectorFailure> {
        let CapabilityRoute::Provider(operation) = capability_route(&action.capability_id)
            .ok_or_else(|| {
                invalid_failure(
                    "unsupported WA Archive capability",
                    ConnectorOperation::Cancellation,
                )
            })?
        else {
            return Err(ConnectorFailure::unsupported(
                ConnectorOperation::Cancellation,
                CONNECTOR_ID,
            ));
        };
        if !self.allowed_operations.contains(&operation) {
            return Err(invalid_failure(
                "WA Archive capability is not admitted for this connector instance",
                ConnectorOperation::Cancellation,
            ));
        }
        let provider_key =
            provider_idempotency_key(&self.external_account_id, action).map_err(|error| {
                connector_failure(error, ConnectorOperation::Cancellation, None, false)
            })?;
        let Some(job) = self
            .lookup_provider_job(&provider_key, ConnectorOperation::Cancellation, context)
            .await?
        else {
            return Ok(());
        };
        if job.status == "cancelled" {
            return Ok(());
        }
        if matches!(
            job.status.as_str(),
            "sent" | "delivered" | "read" | "played" | "succeeded" | "sending" | "ambiguous"
        ) {
            return Err(ConnectorFailure {
                code: "connector.wa_archive.cancellation_too_late".to_owned(),
                message: "WA Archive operation already crossed its cancellation boundary"
                    .to_owned(),
                category: ErrorCategory::Policy,
                retryable: false,
                retry_after_ms: None,
                provider_request_id: None,
                provider_operation: Some(Self::provider_operation_ref(&provider_key)),
                remote_status: None,
                uncertain_outcome: matches!(job.status.as_str(), "sending" | "ambiguous"),
                redacted_details: Some(json!({ "status": job.status })),
                source_component: CONNECTOR_ID.to_owned(),
                operation: ConnectorOperation::Cancellation,
            });
        }
        let path = format!("/v1/outbox/{}/cancel", job.id);
        self.await_provider(
            self.post_json::<Value>(&path, &json!({})),
            context,
            ConnectorOperation::Cancellation,
            Some(Self::provider_operation_ref(&provider_key)),
            false,
        )
        .await?;
        Ok(())
    }
}

#[async_trait]
impl ActionHandler for WaArchiveConnector {
    async fn handle(&self, action: Action) -> RuntimeResult<ActionResult> {
        self.invoke_action(action, None)
            .await
            .map_err(|failure| RuntimeError::Protocol(failure.to_protocol_error()))
    }

    async fn handle_with_context(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> RuntimeResult<ActionResult> {
        self.invoke_typed(action, context)
            .await
            .map_err(|failure| RuntimeError::Protocol(failure.to_protocol_error()))
    }

    async fn cancel(&self, action: &Action) -> RuntimeResult<()> {
        self.cancel_action(action, None)
            .await
            .map_err(|failure| RuntimeError::Protocol(failure.to_protocol_error()))
    }

    async fn cancel_with_context(
        &self,
        action: &Action,
        context: &ActionExecutionContext,
    ) -> RuntimeResult<()> {
        self.cancel_action(action, Some(context))
            .await
            .map_err(|failure| RuntimeError::Protocol(failure.to_protocol_error()))
    }
}

fn validate_provider_job(
    job: &ProviderJob,
    operation: WaArchiveOperation,
    provider_key: &str,
) -> Result<(), WaArchiveConnectorError> {
    if job.id < 1
        || job.idempotency_key != provider_key
        || job.operation_kind != operation.suffix()
        || job.operation_version != OPERATION_CONTRACT_VERSION as i32
        || job.safety_class != operation.safety_class().as_str()
    {
        return Err(WaArchiveConnectorError::ContractMismatch(format!(
            "outbox response does not match operation `{}` or its idempotency key",
            operation.suffix()
        )));
    }
    Ok(())
}

fn safe_job_output(job: &ProviderJob, operation: WaArchiveOperation, provider_key: &str) -> Value {
    json!({
        "provider_operation_id": provider_key,
        "provider_job_id": job.id,
        "status": job.status,
        "operation_kind": operation.suffix(),
        "operation_version": job.operation_version,
        "safety_class": operation.safety_class().as_str(),
        "whatsapp_message_id": job.whatsapp_message_id,
        "ack": job.ack,
        "result": job.result.clone().map(redact_provider_paths),
        "completed_at": job.completed_at
    })
}

fn completed_result(action: Action, output: Value) -> ActionResult {
    ActionResult {
        action_id: action.id,
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

fn outbox_lookup_path(provider_key: &str) -> Result<String, WaArchiveConnectorError> {
    let Some(digest) = provider_key.strip_prefix("aip-wa-v1-") else {
        return Err(WaArchiveConnectorError::InvalidAction(
            "provider operation id has an invalid namespace".to_owned(),
        ));
    };
    if digest.len() != 64 || !digest.bytes().all(|value| value.is_ascii_hexdigit()) {
        return Err(WaArchiveConnectorError::InvalidAction(
            "provider operation id has an invalid digest".to_owned(),
        ));
    }
    Ok(format!("/v1/outbox/by-idempotency/{provider_key}"))
}

fn query_request(
    operation: WaArchiveQueryOperation,
    input: &Value,
) -> Result<(String, QueryParameters), WaArchiveConnectorError> {
    let object = input.as_object().ok_or_else(|| {
        WaArchiveConnectorError::InvalidAction("query input must be an object".to_owned())
    })?;
    let (path, parameters): (&str, &[(&str, &str)]) = match operation {
        WaArchiveQueryOperation::MessageList => (
            "/v1/messages",
            &[
                ("limit", "limit"),
                ("cursor", "cursor"),
                ("chat_id", "chatId"),
                ("query", "query"),
                ("direction", "direction"),
                ("message_type", "messageType"),
                ("from", "from"),
                ("to", "to"),
                ("has_media", "hasMedia"),
            ],
        ),
        WaArchiveQueryOperation::ChatList => {
            ("/v1/chats", &[("limit", "limit"), ("cursor", "cursor")])
        }
        WaArchiveQueryOperation::ContactSearch => {
            ("/v1/contacts", &[("query", "query"), ("limit", "limit")])
        }
        WaArchiveQueryOperation::MessageEventList => (
            "/v1/events",
            &[
                ("limit", "limit"),
                ("message_id", "messageId"),
                ("event_type", "eventType"),
            ],
        ),
        WaArchiveQueryOperation::ProtocolEventList => (
            "/v1/protocol-events",
            &[
                ("limit", "limit"),
                ("chat_id", "chatId"),
                ("event_type", "eventType"),
            ],
        ),
        WaArchiveQueryOperation::ConversationExport => ("/v1/export", &[("chat_id", "chatId")]),
        WaArchiveQueryOperation::MediaGet => {
            return Err(WaArchiveConnectorError::InvalidAction(
                "archive.media.get uses the bounded binary resource path".to_owned(),
            ));
        }
        WaArchiveQueryOperation::OutboxList => {
            ("/v1/outbox", &[("limit", "limit"), ("cursor", "cursor")])
        }
        WaArchiveQueryOperation::AccountGet => ("/v1/account", &[]),
        WaArchiveQueryOperation::OutboxGet => {
            if object.len() != 1 {
                return Err(WaArchiveConnectorError::InvalidAction(
                    "archive.outbox.get accepts only provider_operation_id".to_owned(),
                ));
            }
            let key = required_query_string(object, "provider_operation_id")?;
            return Ok((outbox_lookup_path(key)?, Vec::new()));
        }
        WaArchiveQueryOperation::AmbiguityResolutionList => {
            return Err(WaArchiveConnectorError::InvalidAction(
                "archive.ambiguity_resolution.list uses the validated outbox resolution path"
                    .to_owned(),
            ));
        }
    };
    if object
        .keys()
        .any(|key| !parameters.iter().any(|(input_name, _)| key == input_name))
    {
        return Err(WaArchiveConnectorError::InvalidAction(format!(
            "query `{}` contains an unknown property",
            operation.suffix()
        )));
    }
    let mut query = Vec::new();
    for (input_name, provider_name) in parameters {
        if let Some(value) = object.get(*input_name) {
            query.push((*provider_name, query_scalar(value)?));
        }
    }
    Ok((path.to_owned(), query))
}

fn required_query_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, WaArchiveConnectorError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            WaArchiveConnectorError::InvalidAction(format!(
                "query field `{key}` is missing or invalid"
            ))
        })
}

fn query_scalar(value: &Value) -> Result<String, WaArchiveConnectorError> {
    let encoded = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        _ => {
            return Err(WaArchiveConnectorError::InvalidAction(
                "query values must be strings, numbers, or booleans".to_owned(),
            ));
        }
    };
    if encoded.len() > 2_048 || encoded.chars().any(char::is_control) {
        return Err(WaArchiveConnectorError::InvalidAction(
            "query value exceeds its bound or contains control characters".to_owned(),
        ));
    }
    Ok(encoded)
}

/// Converts provider-specific query response fields into the immutable AIP
/// capability contract admitted for this connector release.
///
/// WA-Rust historically exposed `isWAContact`, `shortName`, and
/// `verifiedName`. Those provider fields are deliberately not part of AIP's
/// stable contact projection. Normalizing here keeps provider evolution behind
/// the connector boundary without weakening the published output schema.
fn normalize_query_output(
    operation: WaArchiveQueryOperation,
    value: Value,
) -> Result<Value, WaArchiveConnectorError> {
    match operation {
        WaArchiveQueryOperation::ContactSearch => normalize_contact_search_output(value),
        _ => Ok(value),
    }
}

fn normalize_contact_search_output(value: Value) -> Result<Value, WaArchiveConnectorError> {
    const CONTACT_FIELDS: [&str; 10] = [
        "canonicalId",
        "phone",
        "contactId",
        "lidId",
        "name",
        "pushName",
        "isMyContact",
        "isWaContact",
        "isBlocked",
        "aliases",
    ];

    let mut envelope = match value {
        Value::Object(envelope) => envelope,
        _ => {
            return Err(WaArchiveConnectorError::ContractMismatch(
                "contact search response must be an object".to_owned(),
            ));
        }
    };
    let items = match envelope.remove("items") {
        Some(Value::Array(items)) => items,
        Some(_) => {
            return Err(WaArchiveConnectorError::ContractMismatch(
                "contact search response `items` must be an array".to_owned(),
            ));
        }
        None => {
            return Err(WaArchiveConnectorError::ContractMismatch(
                "contact search response is missing `items`".to_owned(),
            ));
        }
    };

    let normalized = items
        .into_iter()
        .enumerate()
        .map(|(index, item)| {
            let mut contact = match item {
                Value::Object(contact) => contact,
                _ => {
                    return Err(WaArchiveConnectorError::ContractMismatch(format!(
                        "contact search item {index} must be an object"
                    )));
                }
            };
            if !contact.contains_key("isWaContact")
                && let Some(value) = contact.remove("isWAContact")
            {
                contact.insert("isWaContact".to_owned(), value);
            }

            let mut projected = Map::new();
            for field in CONTACT_FIELDS {
                let value = contact.remove(field).ok_or_else(|| {
                    WaArchiveConnectorError::ContractMismatch(format!(
                        "contact search item {index} is missing `{field}`"
                    ))
                })?;
                projected.insert(field.to_owned(), value);
            }
            Ok(Value::Object(projected))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(json!({ "items": normalized }))
}

fn redact_provider_paths(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter(|(key, _)| {
                    !matches!(
                        key.as_str(),
                        "path"
                            | "mediaPath"
                            | "media_path"
                            | "raw"
                            | "token"
                            | "accessToken"
                            | "access_token"
                            | "session"
                    )
                })
                .map(|(key, value)| (key, redact_provider_paths(value)))
                .collect(),
        ),
        Value::Array(values) => {
            Value::Array(values.into_iter().map(redact_provider_paths).collect())
        }
        value => value,
    }
}

fn reconciliation_result(job: Option<ProviderJob>, provider_key: &str) -> ReconciliationResult {
    let Some(job) = job else {
        return ReconciliationResult {
            terminal: true,
            committed: Some(false),
            cursor: None,
            evidence: Some(json!({
                "source": "wa_archive_outbox",
                "provider_operation_id": provider_key,
                "status": "not_found"
            })),
        };
    };
    let evidence = Some(json!({
        "source": "wa_archive_outbox",
        "provider_operation_id": provider_key,
        "provider_job_id": job.id,
        "status": job.status,
        "attempts": job.attempts,
        "failure_class": job.failure_class,
        "whatsapp_message_id": job.whatsapp_message_id,
        "ack": job.ack,
        "result": job.result.map(redact_provider_paths),
        "completed_at": job.completed_at
    }));
    match job.status.as_str() {
        "sent" | "delivered" | "read" | "played" | "succeeded" => ReconciliationResult {
            terminal: true,
            committed: Some(true),
            cursor: None,
            evidence,
        },
        "failed" | "cancelled" => ReconciliationResult {
            terminal: true,
            committed: Some(false),
            cursor: None,
            evidence,
        },
        "pending" | "processing" | "retry_wait" | "sending" | "ambiguous" => ReconciliationResult {
            terminal: false,
            committed: None,
            cursor: Some(format!("wa_archive.outbox.v1:{}", job.status)),
            evidence,
        },
        _ => ReconciliationResult {
            terminal: false,
            committed: None,
            cursor: Some("wa_archive.outbox.v1:unknown".to_owned()),
            evidence,
        },
    }
}

/// Maps one path-free provider feed row into a deterministic AIP event.
pub fn event_from_change(
    external_account_id: &str,
    change: WaArchiveChange,
) -> Result<Event, WaArchiveConnectorError> {
    if change.sequence < 1
        || change.source_kind.is_empty()
        || change.source_kind.len() > 64
        || change.source_id.is_empty()
        || change.source_id.len() > 512
        || change.event_kind.is_empty()
        || change.event_kind.len() > 128
        || change.event_kind.chars().any(|value| {
            !(value.is_ascii_lowercase() || value.is_ascii_digit() || matches!(value, '.' | '_'))
        })
    {
        return Err(WaArchiveConnectorError::ContractMismatch(
            "provider change-feed item has invalid identity fields".to_owned(),
        ));
    }
    let occurred_at = OffsetDateTime::parse(&change.occurred_at, &Rfc3339).map_err(|error| {
        WaArchiveConnectorError::ContractMismatch(format!(
            "provider change-feed timestamp is invalid: {error}"
        ))
    })?;
    OffsetDateTime::parse(&change.created_at, &Rfc3339).map_err(|error| {
        WaArchiveConnectorError::ContractMismatch(format!(
            "provider change-feed append timestamp is invalid: {error}"
        ))
    })?;
    let mut digest = Sha256::new();
    digest.update(b"aip-wa-archive-event-v1\0");
    digest.update(external_account_id.as_bytes());
    digest.update(b"\0");
    digest.update(change.sequence.to_be_bytes());
    let mut event = Event::new(format!("wa_archive.{}", change.event_kind));
    event.id = EventId::parse(format!(
        "evt_wa_archive_{}",
        hex::encode(&digest.finalize()[..16])
    ))
    .map_err(|error| WaArchiveConnectorError::ContractMismatch(error.to_string()))?;
    event.occurred_at = occurred_at;
    event.data = Some(json!({
        "sequence": change.sequence,
        "source_kind": change.source_kind,
        "source_id": change.source_id,
        "payload": redact_provider_paths(change.payload),
        "provider_created_at": change.created_at
    }));
    Ok(event)
}

fn invalid_failure(message: &str, operation: ConnectorOperation) -> ConnectorFailure {
    ConnectorFailure {
        code: "connector.wa_archive.invalid_action".to_owned(),
        message: message.chars().take(1_000).collect(),
        category: ErrorCategory::Permanent,
        retryable: false,
        retry_after_ms: None,
        provider_request_id: None,
        provider_operation: None,
        remote_status: None,
        uncertain_outcome: false,
        redacted_details: None,
        source_component: CONNECTOR_ID.to_owned(),
        operation,
    }
}

fn connector_failure(
    error: WaArchiveConnectorError,
    operation: ConnectorOperation,
    provider_operation: Option<ProviderOperationRef>,
    dispatched_or_sending: bool,
) -> ConnectorFailure {
    let (code, category, retryable, retry_after_ms, request_id, remote_status, uncertain) =
        match &error {
            WaArchiveConnectorError::Configuration(_) => (
                "connector.wa_archive.configuration",
                ErrorCategory::Permanent,
                false,
                None,
                None,
                None,
                false,
            ),
            WaArchiveConnectorError::InvalidAction(_) => (
                "connector.wa_archive.invalid_action",
                ErrorCategory::Permanent,
                false,
                None,
                None,
                None,
                false,
            ),
            WaArchiveConnectorError::InvalidCredential => (
                "connector.wa_archive.authentication",
                ErrorCategory::Auth,
                false,
                None,
                None,
                None,
                false,
            ),
            WaArchiveConnectorError::Transport(_) => (
                "connector.wa_archive.transport",
                ErrorCategory::Transport,
                !dispatched_or_sending,
                None,
                None,
                None,
                dispatched_or_sending,
            ),
            WaArchiveConnectorError::Remote {
                status,
                request_id,
                retry_after_ms,
                ..
            } => {
                let authentication = matches!(*status, 401 | 403);
                let temporary = *status == 408 || *status == 429 || *status >= 500;
                let uncertain = dispatched_or_sending && *status >= 500;
                (
                    if authentication {
                        "connector.wa_archive.authentication"
                    } else {
                        "connector.wa_archive.remote"
                    },
                    if authentication {
                        ErrorCategory::Auth
                    } else if temporary {
                        ErrorCategory::Temporary
                    } else {
                        ErrorCategory::Permanent
                    },
                    temporary && !uncertain,
                    *retry_after_ms,
                    request_id.clone(),
                    Some(*status),
                    uncertain,
                )
            }
            WaArchiveConnectorError::ResponseTooLarge { .. } => (
                "connector.wa_archive.response_too_large",
                ErrorCategory::Connector,
                false,
                None,
                None,
                None,
                dispatched_or_sending,
            ),
            WaArchiveConnectorError::ContractMismatch(_) => (
                "connector.wa_archive.contract_mismatch",
                ErrorCategory::Permanent,
                false,
                None,
                None,
                None,
                dispatched_or_sending,
            ),
            WaArchiveConnectorError::OperationNotFound => (
                "connector.wa_archive.operation_not_found",
                ErrorCategory::Permanent,
                false,
                None,
                None,
                Some(404),
                dispatched_or_sending,
            ),
        };
    ConnectorFailure {
        code: code.to_owned(),
        message: error.to_string().chars().take(1_000).collect(),
        category,
        retryable,
        retry_after_ms,
        provider_request_id: request_id,
        provider_operation,
        remote_status,
        uncertain_outcome: uncertain,
        redacted_details: None,
        source_component: CONNECTOR_ID.to_owned(),
        operation,
    }
}

fn cancelled_failure(
    operation: ConnectorOperation,
    provider_operation: Option<ProviderOperationRef>,
    uncertain: bool,
) -> ConnectorFailure {
    ConnectorFailure {
        code: "connector.wa_archive.cancelled".to_owned(),
        message: "WA Archive connector operation was cancelled".to_owned(),
        category: ErrorCategory::Temporary,
        retryable: false,
        retry_after_ms: None,
        provider_request_id: None,
        provider_operation,
        remote_status: None,
        uncertain_outcome: uncertain,
        redacted_details: None,
        source_component: CONNECTOR_ID.to_owned(),
        operation,
    }
}

fn timeout_failure(
    operation: ConnectorOperation,
    provider_operation: Option<ProviderOperationRef>,
    uncertain: bool,
) -> ConnectorFailure {
    ConnectorFailure {
        code: "connector.wa_archive.deadline_exceeded".to_owned(),
        message: "WA Archive connector operation exceeded the AIP deadline".to_owned(),
        category: ErrorCategory::Temporary,
        retryable: !uncertain,
        retry_after_ms: Some(1_000),
        provider_request_id: None,
        provider_operation,
        remote_status: None,
        uncertain_outcome: uncertain,
        redacted_details: None,
        source_component: CONNECTOR_ID.to_owned(),
        operation,
    }
}

/// Durable provider change-feed consumer for one connector host replica.
#[derive(Clone)]
pub struct WaArchiveChangeFeedWorker {
    connector: Arc<WaArchiveConnector>,
    state: ProfileStateStore,
    cursor_key: String,
}

impl fmt::Debug for WaArchiveChangeFeedWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WaArchiveChangeFeedWorker")
            .field("connector", &self.connector)
            .field("cursor_key", &self.cursor_key)
            .finish_non_exhaustive()
    }
}

impl WaArchiveChangeFeedWorker {
    /// Binds a feed worker to the shared durable host profile-state store.
    #[must_use]
    pub fn new(connector: Arc<WaArchiveConnector>, state: ProfileStateStore) -> Self {
        let digest = hex::encode(&Sha256::digest(connector.external_account_id.as_bytes())[..16]);
        Self {
            connector,
            state,
            cursor_key: format!("account:{digest}"),
        }
    }

    /// Polls, durably publishes, and checkpoints provider events until shutdown.
    ///
    /// Multiple replicas may run this loop concurrently. Stable event ids make
    /// publication idempotent, and compare-and-set cursor advancement can never
    /// move the shared cursor backwards.
    pub async fn run(
        self,
        publisher: ConnectorHostEventPublisher,
        shutdown: watch::Receiver<bool>,
    ) {
        self.mark_started().await;
        self.run_loop(&publisher, shutdown).await;
        self.mark_stopped().await;
    }

    async fn run_loop(
        &self,
        publisher: &ConnectorHostEventPublisher,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut backoff = Duration::from_millis(250);
        loop {
            if *shutdown.borrow() {
                return;
            }
            match self.publish_next_batch(publisher).await {
                Ok(has_more) => {
                    self.mark_success().await;
                    backoff = Duration::from_millis(250);
                    if has_more {
                        continue;
                    }
                }
                Err(error) => {
                    self.mark_failure(&error).await;
                    tracing::warn!(
                        error = %error,
                        cursor_key = %self.cursor_key,
                        "WA Archive change-feed iteration failed"
                    );
                    let delay = backoff;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    tokio::select! {
                        result = shutdown.changed() => {
                            if result.is_err() || *shutdown.borrow() {
                                return;
                            }
                        }
                        () = tokio::time::sleep(delay) => {}
                    }
                    continue;
                }
            }
            tokio::select! {
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                () = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
        }
    }

    async fn mark_started(&self) {
        let mut health = self.connector.change_feed_health.lock().await;
        health.running = true;
        health.last_success = Some(tokio::time::Instant::now());
        health.consecutive_failures = 0;
        health.last_error = None;
    }

    async fn mark_success(&self) {
        let mut health = self.connector.change_feed_health.lock().await;
        health.running = true;
        health.last_success = Some(tokio::time::Instant::now());
        health.consecutive_failures = 0;
        health.last_error = None;
    }

    async fn mark_failure(&self, error: &str) {
        let mut health = self.connector.change_feed_health.lock().await;
        health.consecutive_failures = health.consecutive_failures.saturating_add(1);
        health.last_error = Some(error.chars().take(512).collect());
    }

    async fn mark_stopped(&self) {
        let mut health = self.connector.change_feed_health.lock().await;
        health.running = false;
    }

    async fn publish_next_batch(
        &self,
        publisher: &ConnectorHostEventPublisher,
    ) -> Result<bool, String> {
        self.connector
            .ensure_contract(false)
            .await
            .map_err(|error| error.to_string())?;
        let cursor = self.cursor().await?;
        let query = vec![
            ("afterSequence", cursor.to_string()),
            ("limit", CHANGE_FEED_BATCH_SIZE.to_string()),
            ("waitMs", CHANGE_FEED_LONG_POLL_MS.to_string()),
        ];
        let response = self
            .connector
            .get_json::<ChangeFeedEnvelope>("/v1/change-feed", &query)
            .await
            .map_err(|error| error.to_string())?;
        if cursor > 0
            && response
                .oldest_cursor
                .is_some_and(|oldest| cursor < oldest.saturating_sub(1))
        {
            return Err("durable WA Archive change-feed cursor expired".to_owned());
        }
        if response
            .latest_cursor
            .is_some_and(|latest| latest < response.next_cursor)
        {
            return Err("provider change-feed latest cursor precedes its page cursor".to_owned());
        }
        if response.items.is_empty() {
            if response.next_cursor != cursor || response.has_more {
                return Err("empty provider feed response advanced its cursor".to_owned());
            }
            return Ok(false);
        }
        let mut expected = cursor;
        let mut events = Vec::with_capacity(response.items.len());
        for change in response.items {
            if change.sequence <= expected {
                return Err("provider change-feed sequence is not strictly increasing".to_owned());
            }
            expected = change.sequence;
            events.push(
                event_from_change(&self.connector.external_account_id, change)
                    .map_err(|error| error.to_string())?,
            );
        }
        if response.next_cursor != expected {
            return Err(
                "provider change-feed next cursor does not match its final item".to_owned(),
            );
        }
        publisher
            .enqueue(CHANGE_FEED_CHANNEL_ID, events)
            .await
            .map_err(|error| error.to_string())?;
        self.advance_cursor(expected).await?;
        Ok(response.has_more)
    }

    async fn cursor(&self) -> Result<i64, String> {
        let entry = self
            .state
            .get(CURSOR_NAMESPACE, &self.cursor_key)
            .await
            .map_err(|error| error.to_string())?;
        let cursor = entry
            .as_ref()
            .and_then(|entry| entry.value.get("sequence"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if cursor < 0 {
            return Err("durable WA Archive change-feed cursor is negative".to_owned());
        }
        Ok(cursor)
    }

    async fn advance_cursor(&self, sequence: i64) -> Result<(), String> {
        for _ in 0..32 {
            let current = self
                .state
                .get(CURSOR_NAMESPACE, &self.cursor_key)
                .await
                .map_err(|error| error.to_string())?;
            let current_sequence = current
                .as_ref()
                .and_then(|entry| entry.value.get("sequence"))
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if current_sequence >= sequence {
                return Ok(());
            }
            match self
                .state
                .compare_and_set(
                    CURSOR_NAMESPACE,
                    &self.cursor_key,
                    current.as_ref().map(|entry| entry.revision),
                    json!({ "sequence": sequence }),
                )
                .await
                .map_err(|error| error.to_string())?
            {
                ProfileStateCasOutcome::Applied(_) => return Ok(()),
                ProfileStateCasOutcome::Conflict(_) => tokio::task::yield_now().await,
            }
        }
        Err("WA Archive change-feed cursor remained contended after 32 attempts".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_auth::{AuthScheme, AuthenticatedPrincipal};
    use aip_core::{
        ActionId, ApprovalDecision, ApprovalDecisionKind, ApprovalId, ApprovalRequest,
        TransactionId,
    };
    use aip_runtime::{
        ActionStream, ApprovalRecord, ApprovalStatus, CancellationToken, Deadline,
        ExecutionCheckpointPublisher, RedactionPolicy, TraceContext,
        TransactionCheckpointPublisher, TransactionExecutionContext, VerifiedApprovalSet,
    };
    use axum::{
        Json, Router,
        body::Body,
        extract::{Path, State},
        http::{HeaderMap, Response, StatusCode, header},
        routing::{get, post},
    };
    use std::sync::{Arc as StdArc, Mutex as StdMutex};

    const MOCK_TOKEN: &str = "qualified-provider-token";
    const MOCK_ACCOUNT_ID: &str = "whatsapp-account-1";
    const MOCK_AMBIGUOUS_PROVIDER_KEY: &str =
        "aip-wa-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn qualified_schema_document() -> ProviderOperationSchemaDocument {
        serde_json::from_slice(include_bytes!(
            "../contracts/provider-operation-schemas.json"
        ))
        .expect("checked-in qualified provider operation schemas")
    }

    #[derive(Clone, Default)]
    struct MockProviderState {
        submissions: StdArc<StdMutex<Vec<Value>>>,
        resolutions: StdArc<StdMutex<Vec<Value>>>,
    }

    fn authorize(headers: &HeaderMap) -> Result<(), StatusCode> {
        match headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
        {
            Some(value) if value == format!("Bearer {MOCK_TOKEN}") => {}
            _ => return Err(StatusCode::UNAUTHORIZED),
        }
        match headers
            .get(EXTERNAL_ACCOUNT_ID_HEADER)
            .and_then(|value| value.to_str().ok())
        {
            Some(MOCK_ACCOUNT_ID) => Ok(()),
            _ => Err(StatusCode::FORBIDDEN),
        }
    }

    async fn echo_request_id(
        request: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        let request_id = request.headers().get("x-request-id").cloned();
        let mut response = next.run(request).await;
        if let Some(request_id) = request_id {
            response.headers_mut().insert("x-request-id", request_id);
        }
        response
    }

    async fn mock_capabilities(headers: HeaderMap) -> Result<Json<Value>, StatusCode> {
        authorize(&headers)?;
        let operation_schema_document = qualified_schema_document();
        Ok(Json(json!({
            "operationContractVersion": OPERATION_CONTRACT_VERSION,
            "operationContractSha256": OPERATION_CONTRACT_SHA256,
            "connectorFeedVersion": CONNECTOR_FEED_VERSION,
            "aipConnectorContract": PROVIDER_CONNECTOR_CONTRACT,
            "providerSourceRevision": PROVIDER_REVISION,
            "operationSchemaDocumentVersion": OPERATION_SCHEMA_DOCUMENT_VERSION,
            "operationSchemaContractSha256": OPERATION_SCHEMA_CONTRACT_SHA256,
            "operationSchemaDocument": operation_schema_document,
            "operationKinds": ALL_WA_ARCHIVE_OPERATIONS
                .iter()
                .map(|operation| operation.suffix())
                .collect::<Vec<_>>()
        })))
    }

    async fn mock_account(headers: HeaderMap) -> Result<Json<Value>, StatusCode> {
        authorize(&headers)?;
        Ok(Json(json!({
            "paired": true,
            "accountId": MOCK_ACCOUNT_ID,
            "phoneJid": MOCK_ACCOUNT_ID,
            "lidJid": "100000000001@lid"
        })))
    }

    async fn mock_validate(
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Result<Json<Value>, StatusCode> {
        authorize(&headers)?;
        if body.get("confirmed").is_some() {
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
        Ok(Json(json!({
            "valid": true,
            "operation": {
                "operationKind": "send_message",
                "operationVersion": OPERATION_CONTRACT_VERSION,
                "safetyClass": "standard",
                "requiresConfirmation": false,
                "normalizedTarget": body.get("toChatId").cloned().unwrap_or(Value::Null),
                "hasMedia": false
            }
        })))
    }

    async fn mock_submit(
        State(state): State<MockProviderState>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Result<Json<Value>, StatusCode> {
        authorize(&headers)?;
        let provider_key = body
            .get("idempotencyKey")
            .and_then(Value::as_str)
            .ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
        if body.get("confirmed") != Some(&Value::Bool(false)) {
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
        state
            .submissions
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .push(body.clone());
        Ok(Json(mock_job(provider_key)))
    }

    async fn mock_lookup(
        State(state): State<MockProviderState>,
        Path(provider_key): Path<String>,
        headers: HeaderMap,
    ) -> Result<Json<Value>, StatusCode> {
        authorize(&headers)?;
        if provider_key == MOCK_AMBIGUOUS_PROVIDER_KEY {
            return Ok(Json(mock_ambiguous_job(&provider_key)));
        }
        let exists = state
            .submissions
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .iter()
            .any(|body| body.get("idempotencyKey").and_then(Value::as_str) == Some(&provider_key));
        if !exists {
            return Err(StatusCode::NOT_FOUND);
        }
        Ok(Json(mock_job(&provider_key)))
    }

    async fn mock_resolve_ambiguity(
        State(state): State<MockProviderState>,
        Path(outbox_id): Path<i64>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Result<(StatusCode, Json<Value>), StatusCode> {
        authorize(&headers)?;
        if outbox_id != 77 {
            return Err(StatusCode::NOT_FOUND);
        }
        let mut resolutions = state
            .resolutions
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if let Some(existing) = resolutions.first() {
            for (request_name, response_name) in [
                ("idempotencyKey", "idempotencyKey"),
                ("resolution", "resolution"),
                ("actor", "actor"),
                ("reason", "reason"),
                ("evidence", "evidence"),
                ("whatsappMessageId", "whatsappMessageId"),
                ("result", "result"),
            ] {
                if body.get(request_name) != existing.get(response_name) {
                    return Err(StatusCode::CONFLICT);
                }
            }
            let mut replay = existing.clone();
            replay["created"] = Value::Bool(false);
            return Ok((StatusCode::OK, Json(json!({ "resolution": replay }))));
        }
        let resolution = json!({
            "id": 901,
            "outboxId": outbox_id,
            "created": true,
            "idempotencyKey": body.get("idempotencyKey").cloned().unwrap_or(Value::Null),
            "resolution": body.get("resolution").cloned().unwrap_or(Value::Null),
            "actor": body.get("actor").cloned().unwrap_or(Value::Null),
            "reason": body.get("reason").cloned().unwrap_or(Value::Null),
            "evidence": body.get("evidence").cloned().unwrap_or(Value::Null),
            "whatsappMessageId": body.get("whatsappMessageId").cloned().unwrap_or(Value::Null),
            "result": body.get("result").cloned().unwrap_or(Value::Null),
            "resolvedAt": "2026-07-26T01:02:03Z"
        });
        resolutions.push(resolution.clone());
        Ok((
            StatusCode::CREATED,
            Json(json!({ "resolution": resolution })),
        ))
    }

    async fn mock_ambiguity_resolutions(
        State(state): State<MockProviderState>,
        Path(outbox_id): Path<i64>,
        headers: HeaderMap,
    ) -> Result<Json<Value>, StatusCode> {
        authorize(&headers)?;
        if outbox_id != 77 {
            return Err(StatusCode::NOT_FOUND);
        }
        let resolutions = state
            .resolutions
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .clone();
        Ok(Json(json!({ "items": resolutions })))
    }

    async fn mock_media(
        Path(message_id): Path<String>,
        headers: HeaderMap,
    ) -> Result<Response<Body>, StatusCode> {
        authorize(&headers)?;
        if message_id != "message-with-media" {
            return Err(StatusCode::NOT_FOUND);
        }
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain")
            .header(
                header::CONTENT_DISPOSITION,
                "attachment; filename=archive-note.txt",
            )
            .body(Body::from("verified archive media"))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn mock_job(provider_key: &str) -> Value {
        json!({
            "job": {
                "id": 41,
                "status": "succeeded",
                "attempts": 1,
                "ack": 2,
                "whatsappMessageId": "provider-message-41",
                "failureClass": null,
                "idempotencyKey": provider_key,
                "operationKind": "send_message",
                "operationVersion": OPERATION_CONTRACT_VERSION,
                "safetyClass": "standard",
                "result": { "messageId": "provider-message-41", "mediaPath": "/private/provider/file" },
                "completedAt": "2026-07-26T00:00:00Z"
            }
        })
    }

    fn mock_ambiguous_job(provider_key: &str) -> Value {
        json!({
            "job": {
                "id": 77,
                "status": "ambiguous",
                "attempts": 1,
                "ack": null,
                "whatsappMessageId": null,
                "failureClass": "transport_unknown",
                "idempotencyKey": provider_key,
                "operationKind": "send_message",
                "operationVersion": OPERATION_CONTRACT_VERSION,
                "safetyClass": "standard",
                "result": null,
                "completedAt": null
            }
        })
    }

    async fn mock_provider() -> (String, MockProviderState, tokio::task::JoinHandle<()>) {
        let state = MockProviderState::default();
        let app = Router::new()
            .route("/v1/capabilities", get(mock_capabilities))
            .route("/v1/account", get(mock_account))
            .route("/v1/operations/validate", post(mock_validate))
            .route("/v1/operations", post(mock_submit))
            .route("/v1/outbox/by-idempotency/{provider_key}", get(mock_lookup))
            .route(
                "/v1/outbox/{outbox_id}/resolve-ambiguity",
                post(mock_resolve_ambiguity),
            )
            .route(
                "/v1/outbox/{outbox_id}/ambiguity-resolutions",
                get(mock_ambiguity_resolutions),
            )
            .route("/v1/media/{message_id}", get(mock_media))
            .layer(axum::middleware::from_fn(echo_request_id))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock provider");
        let address = listener.local_addr().expect("mock provider address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock provider");
        });
        (format!("http://{address}"), state, task)
    }

    fn operator_execution_context(
        with_approval: bool,
        with_transaction: bool,
    ) -> ActionExecutionContext {
        let now = OffsetDateTime::now_utc();
        let principal = Principal::new(
            PrincipalId::trusted("human:wa-archive-operator"),
            PrincipalKind::Human,
        );
        let actor = AuthenticatedPrincipal {
            principal: principal.clone(),
            scheme: AuthScheme::DidProof,
            issuer: "wa-archive-connector-test".to_owned(),
            audience: Some("aip".to_owned()),
            scopes: BTreeSet::from(["wa_archive:resolve_ambiguity".to_owned()]),
            authenticated_at: now,
            expires_at: Some(now + time::Duration::minutes(5)),
            credential_fingerprint: None,
        };
        let approval = with_approval.then(|| {
            let approval_id = ApprovalId::new();
            let request = ApprovalRequest {
                id: approval_id.clone(),
                action_id: ActionId::new(),
                capability_id: CapabilityId::trusted("cap:wa_archive:archive.ambiguity.resolve"),
                requester: principal.clone(),
                subject: principal.clone(),
                approver_selector: ApproverSelector::TenantPolicy,
                reason: "independent evidence review".to_owned(),
                evidence: Vec::new(),
                expires_at: Some(now + time::Duration::minutes(5)),
                policy_decision_id: Some("policy:wa-archive-ambiguity-v1".to_owned()),
                identity: None,
                policy_snapshot: Some(ApprovalPolicy {
                    required: true,
                    ..ApprovalPolicy::default()
                }),
                policy_hash: Some("sha256:wa-archive-ambiguity-test".to_owned()),
                operator: Some(principal.clone()),
                risk: Some(RiskLevel::Critical),
                governed_value: None,
            };
            let decision = ApprovalDecision {
                approval_id: approval_id.clone(),
                decision: ApprovalDecisionKind::Approved,
                approver: principal.clone(),
                decided_at: now,
                reason: Some("evidence independently verified".to_owned()),
                constraints: Vec::new(),
                evidence: Vec::new(),
                decision_id: Some("decision:wa-archive-ambiguity-test".to_owned()),
                policy_hash: request.policy_hash.clone(),
                authority_path: vec!["tenant:wa-archive-test".to_owned()],
                target_decision_id: None,
            };
            VerifiedApprovalSet {
                approval_ids: BTreeSet::from([approval_id]),
                decision_ids: BTreeSet::from(["decision:wa-archive-ambiguity-test".to_owned()]),
                policy_hashes: BTreeSet::from(["sha256:wa-archive-ambiguity-test".to_owned()]),
                authorization: ApprovalRecord {
                    request,
                    status: ApprovalStatus::Approved,
                    decision: Some(decision),
                    decisions: Vec::new(),
                    created_at: now,
                    updated_at: now,
                },
            }
        });
        ActionExecutionContext {
            actor,
            tenant: None,
            credential: None,
            deadline: Deadline::after(now, 30_000),
            cancellation: CancellationToken::default(),
            idempotency: None,
            approval,
            transaction: with_transaction.then(|| TransactionExecutionContext {
                transaction_id: TransactionId::new(),
                provider_operation_id: None,
                reconciliation_cursor: None,
            }),
            transaction_checkpoint: TransactionCheckpointPublisher::default(),
            execution_checkpoints: ExecutionCheckpointPublisher::default(),
            stream: ActionStream::default(),
            trace: TraceContext::default(),
            redaction: RedactionPolicy::default(),
        }
    }

    #[test]
    fn operation_capabilities_cover_exact_admitted_catalogue() {
        let admitted = ALL_WA_ARCHIVE_OPERATIONS.iter().copied().collect();
        let admitted_queries = ALL_WA_ARCHIVE_QUERY_OPERATIONS.iter().copied().collect();
        let admitted_controls = ALL_WA_ARCHIVE_CONTROL_OPERATIONS.iter().copied().collect();
        let schema_document = qualified_schema_document();
        let capabilities = wa_archive_capabilities(
            &admitted,
            &admitted_queries,
            &admitted_controls,
            &schema_document,
        );
        assert_eq!(
            capabilities.len(),
            ALL_WA_ARCHIVE_OPERATIONS.len()
                + (ALL_WA_ARCHIVE_QUERY_OPERATIONS.len() * 2)
                + ALL_WA_ARCHIVE_CONTROL_OPERATIONS.len()
        );
        let ids = capabilities
            .iter()
            .map(|capability| capability.id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), capabilities.len());
        for capability in &capabilities {
            jsonschema::draft202012::new(&capability.input_schema).unwrap_or_else(|error| {
                panic!("{} input schema failed to compile: {error}", capability.id)
            });
            if let Some(output_schema) = capability.output_schema.as_ref() {
                jsonschema::draft202012::new(output_schema).unwrap_or_else(|error| {
                    panic!("{} output schema failed to compile: {error}", capability.id)
                });
            }
        }
        for operation in ALL_WA_ARCHIVE_OPERATIONS {
            let contract = operation_capability(*operation, &schema_document)
                .contract
                .expect("provider operation contract");
            assert_eq!(
                contract.execution.retry_safety,
                RetrySafety::SafeWithIdempotencyKey
            );
        }
        for operation in ALL_WA_ARCHIVE_QUERY_OPERATIONS {
            let contract = query_capability(*operation)
                .contract
                .expect("archive query contract");
            assert_eq!(contract.execution.retry_safety, RetrySafety::Safe);
        }
        for operation in ALL_WA_ARCHIVE_CONTROL_OPERATIONS {
            let contract = control_capability(*operation)
                .contract
                .expect("ambiguity control contract");
            assert_eq!(
                contract.execution.retry_safety,
                RetrySafety::SafeWithIdempotencyKey
            );
        }
    }

    #[test]
    fn chat_inventory_cursor_is_exposed_and_forwarded_by_native_aip() {
        let legacy = legacy_query_resource_capability(WaArchiveQueryOperation::ChatList);
        assert_eq!(legacy.id.as_str(), "cap:wa_archive:archive.chat.list");
        assert_eq!(legacy.kind, CapabilityKind::Resource);

        let query = query_capability(WaArchiveQueryOperation::ChatList);
        assert_eq!(query.id.as_str(), "cap:wa_archive:query:archive.chat.list");
        assert_eq!(query.kind, CapabilityKind::Tool);
        assert_eq!(legacy.input_schema, query.input_schema);
        assert_eq!(legacy.output_schema, query.output_schema);
        assert_eq!(legacy.contract, query.contract);
        let connector = WaArchiveConnector::new(
            "http://127.0.0.1:1",
            "15550000000@c.us",
            ConnectorSecret::new(b"test-token"),
        )
        .expect("connector");
        let legacy_support = FrozenConnector::implementation_support(&connector, &legacy);
        assert!(!legacy_support.invocation);
        assert!(legacy_support.retry);
        assert!(capability_route(&legacy.id).is_none());
        let input = query_input_schema(WaArchiveQueryOperation::ChatList);
        assert_eq!(
            input.pointer("/properties/cursor/maxLength"),
            Some(&Value::from(2_048))
        );
        let output = query_output_schema(WaArchiveQueryOperation::ChatList);
        assert!(
            output
                .get("required")
                .and_then(Value::as_array)
                .is_some_and(|required| required.iter().any(|name| name == "nextCursor"))
        );

        let (path, parameters) = query_request(
            WaArchiveQueryOperation::ChatList,
            &json!({ "limit": 200, "cursor": "opaque-page-2" }),
        )
        .expect("valid chat inventory query");
        assert_eq!(path, "/v1/chats");
        assert_eq!(
            parameters,
            vec![
                ("limit", "200".to_owned()),
                ("cursor", "opaque-page-2".to_owned())
            ]
        );
    }

    #[test]
    fn deployment_can_disable_all_archive_queries_and_operator_controls() {
        let connector = WaArchiveConnector::new(
            "http://127.0.0.1:3210",
            MOCK_ACCOUNT_ID,
            ConnectorSecret::new(MOCK_TOKEN),
        )
        .expect("connector")
        .with_allowed_query_operations([])
        .expect("empty query allowlist")
        .with_allowed_control_operations([])
        .expect("empty control allowlist");
        let manifest = connector.qualified_manifest().expect("qualified manifest");
        assert_eq!(manifest.capabilities.len(), ALL_WA_ARCHIVE_OPERATIONS.len());
        assert!(manifest.capabilities.iter().all(|capability| {
            WaArchiveOperation::from_suffix(
                capability
                    .id
                    .as_str()
                    .strip_prefix(CAPABILITY_PREFIX)
                    .expect("WA Archive capability prefix"),
            )
            .is_some()
        }));
    }

    #[tokio::test]
    async fn disabled_change_feed_is_not_advertised_during_admission() {
        let connector = WaArchiveConnector::new(
            "http://127.0.0.1:3210",
            MOCK_ACCOUNT_ID,
            ConnectorSecret::new(MOCK_TOKEN),
        )
        .expect("connector");
        let enabled = connector.qualified_manifest().expect("enabled manifest");
        assert_eq!(enabled.channels.len(), 1);
        assert_eq!(
            enabled
                .security
                .as_ref()
                .and_then(|security| security.get("change_feed_enabled"))
                .and_then(Value::as_bool),
            Some(true)
        );

        connector.require_change_feed(false).await;
        let disabled = connector.qualified_manifest().expect("disabled manifest");
        assert!(disabled.channels.is_empty());
        assert_eq!(
            disabled
                .security
                .as_ref()
                .and_then(|security| security.get("change_feed_enabled"))
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn provider_revision_pin_is_mandatory_and_cannot_be_overridden() {
        let connector = WaArchiveConnector::new(
            "http://127.0.0.1:3210",
            MOCK_ACCOUNT_ID,
            ConnectorSecret::new(MOCK_TOKEN),
        )
        .expect("connector");
        let manifest = connector.qualified_manifest().expect("qualified manifest");
        assert_eq!(
            manifest
                .compatibility
                .as_ref()
                .and_then(|compatibility| compatibility.get("provider_source_revision"))
                .and_then(Value::as_str),
            Some(PROVIDER_REVISION)
        );
        assert!(
            connector
                .with_expected_provider_source_revision("0000000000000000000000000000000000000000")
                .is_err()
        );

        let mut capabilities = ProviderCapabilities {
            operation_contract_version: OPERATION_CONTRACT_VERSION,
            operation_contract_sha256: OPERATION_CONTRACT_SHA256.to_owned(),
            connector_feed_version: CONNECTOR_FEED_VERSION,
            aip_connector_contract: PROVIDER_CONNECTOR_CONTRACT.to_owned(),
            provider_source_revision: PROVIDER_REVISION.to_owned(),
            operation_schema_document_version: OPERATION_SCHEMA_DOCUMENT_VERSION.to_owned(),
            operation_schema_contract_sha256: OPERATION_SCHEMA_CONTRACT_SHA256.to_owned(),
            operation_schema_document: qualified_schema_document(),
            operation_kinds: ALL_WA_ARCHIVE_OPERATIONS
                .iter()
                .map(|operation| operation.suffix().to_owned())
                .collect(),
        };
        assert!(verify_provider_capabilities(&capabilities, PROVIDER_REVISION).is_ok());
        capabilities.provider_source_revision =
            "0000000000000000000000000000000000000000".to_owned();
        assert!(matches!(
            verify_provider_capabilities(&capabilities, PROVIDER_REVISION),
            Err(WaArchiveConnectorError::ContractMismatch(_))
        ));
    }

    #[test]
    fn sensitive_and_destructive_capabilities_require_plan_and_approval() {
        let schema_document = qualified_schema_document();
        for operation in ALL_WA_ARCHIVE_OPERATIONS {
            let capability = operation_capability(*operation, &schema_document);
            let contract = capability.contract.as_ref().expect("contract");
            let guarded = operation.safety_class().requires_approval();
            assert_eq!(capability.requires_human_approval, Some(guarded));
            assert_eq!(contract.approval.is_some(), guarded);
            if guarded {
                assert!(
                    contract
                        .transaction
                        .as_ref()
                        .expect("mutation transaction")
                        .requires_plan_before_commit
                );
            }
        }
    }

    #[test]
    fn ambiguity_resolution_is_an_approved_transactional_control() {
        let capability = control_capability(WaArchiveControlOperation::ResolveAmbiguity);
        assert_eq!(capability.risk, Some(RiskLevel::Critical));
        assert_eq!(capability.requires_human_approval, Some(true));
        let contract = capability.contract.expect("control contract");
        assert!(contract.approval.is_some());
        let transaction = contract.transaction.expect("control transaction");
        assert!(transaction.requires_plan_before_commit);
        assert!(transaction.supported_modes.contains(&TransactionMode::Plan));
        assert!(
            transaction
                .supported_modes
                .contains(&TransactionMode::Commit)
        );
        assert!(
            !transaction
                .supported_modes
                .contains(&TransactionMode::Reconcile)
        );
    }

    #[test]
    fn ambiguity_resolution_input_requires_independent_consistent_evidence() {
        let mut action = Action::new(
            CapabilityId::trusted("cap:wa_archive:archive.ambiguity.resolve"),
            json!({
                "provider_operation_id": format!("aip-wa-v1-{}", "a".repeat(64)),
                "resolution": "not_committed",
                "reason": "provider history proves rejection before dispatch",
                "evidence": { "source": "provider_audit", "dispatchObserved": false }
            }),
        );
        action.idempotency_key = Some("resolution-case-1".to_owned());
        let parsed = parse_ambiguity_resolution_input(&action).expect("valid resolution input");
        assert_eq!(parsed.resolution, "not_committed");
        action.input["whatsapp_message_id"] = Value::String("must-not-exist".to_owned());
        assert!(parse_ambiguity_resolution_input(&action).is_err());
    }

    #[tokio::test]
    async fn ambiguity_resolution_requires_approval_and_is_idempotently_auditable() {
        let (base_url, state, server) = mock_provider().await;
        let connector =
            WaArchiveConnector::new(&base_url, MOCK_ACCOUNT_ID, ConnectorSecret::new(MOCK_TOKEN))
                .expect("connector")
                .with_expected_provider_source_revision(PROVIDER_REVISION)
                .expect("qualified provider revision");
        let mut action = Action::new(
            CapabilityId::trusted("cap:wa_archive:archive.ambiguity.resolve"),
            json!({
                "provider_operation_id": MOCK_AMBIGUOUS_PROVIDER_KEY,
                "resolution": "committed",
                "reason": "provider delivery receipt and recipient archive agree",
                "evidence": {
                    "providerReceipt": "receipt-77",
                    "archiveMessageId": "provider-message-77"
                },
                "whatsapp_message_id": "provider-message-77",
                "result": { "messageId": "provider-message-77" }
            }),
        );
        action.idempotency_key = Some("ambiguity-resolution-business-case-77".to_owned());

        let direct = connector
            .invoke_typed(action.clone(), operator_execution_context(true, true))
            .await
            .expect_err("direct control invocation must be rejected");
        assert_eq!(direct.code, "connector.wa_archive.transaction_required");

        let plan = connector
            .plan_typed(action.clone(), operator_execution_context(false, false))
            .await
            .expect("side-effect-free ambiguity resolution plan");
        assert_eq!(
            plan.output
                .as_ref()
                .and_then(|output| output.get("current_status"))
                .and_then(Value::as_str),
            Some("ambiguous")
        );
        assert_eq!(
            plan.output
                .as_ref()
                .and_then(|output| output.get("side_effect_committed"))
                .and_then(Value::as_bool),
            Some(false)
        );

        let unapproved = connector
            .commit_typed(action.clone(), operator_execution_context(false, true))
            .await
            .expect_err("unapproved ambiguity resolution must be rejected");
        assert_eq!(unapproved.code, "connector.wa_archive.approval_required");
        assert!(
            state
                .resolutions
                .lock()
                .expect("resolution state")
                .is_empty()
        );

        let committed = connector
            .commit_typed(action.clone(), operator_execution_context(true, true))
            .await
            .expect("approved ambiguity resolution commit");
        assert_eq!(committed.status, ActionResultStatus::Completed);
        assert_eq!(
            committed
                .output
                .as_ref()
                .and_then(|output| output.pointer("/resolution/created"))
                .and_then(Value::as_bool),
            Some(true)
        );
        let replay = connector
            .commit_typed(action, operator_execution_context(true, true))
            .await
            .expect("idempotent ambiguity resolution replay");
        assert_eq!(
            replay
                .output
                .as_ref()
                .and_then(|output| output.pointer("/resolution/created"))
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(state.resolutions.lock().expect("resolution state").len(), 1);

        let history = connector
            .invoke_typed(
                Action::new(
                    CapabilityId::trusted("cap:wa_archive:query:archive.ambiguity_resolution.list"),
                    json!({
                        "provider_operation_id": MOCK_AMBIGUOUS_PROVIDER_KEY,
                        "limit": 10
                    }),
                ),
                operator_execution_context(false, false),
            )
            .await
            .expect("append-only ambiguity resolution history");
        assert_eq!(
            history
                .output
                .as_ref()
                .and_then(|output| output.pointer("/items/0/actor"))
                .and_then(Value::as_str),
            Some("human:wa-archive-operator")
        );
        server.abort();
    }

    #[tokio::test]
    async fn provider_response_without_request_identity_is_rejected() {
        let state = MockProviderState::default();
        let app = Router::new()
            .route("/v1/capabilities", get(mock_capabilities))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind uncorrelated provider");
        let address = listener.local_addr().expect("provider address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve uncorrelated provider");
        });
        let connector = WaArchiveConnector::new(
            &format!("http://{address}"),
            MOCK_ACCOUNT_ID,
            ConnectorSecret::new(MOCK_TOKEN),
        )
        .expect("connector");
        let error = connector
            .ensure_contract(false)
            .await
            .expect_err("missing response request id must fail closed");
        assert!(matches!(
            error,
            WaArchiveConnectorError::ContractMismatch(_)
        ));
        server.abort();
    }

    #[test]
    fn every_qualified_provider_operation_schema_is_valid_draft_2020_12() {
        let document = qualified_schema_document();
        let encoded = serde_json::to_vec(&document).expect("serialize qualified schema document");
        assert_eq!(
            hex::encode(Sha256::digest(encoded)),
            OPERATION_SCHEMA_CONTRACT_SHA256
        );
        assert_eq!(
            document.operation_schemas.len(),
            ALL_WA_ARCHIVE_OPERATIONS.len()
        );
        for operation in ALL_WA_ARCHIVE_OPERATIONS {
            let schema = provider_operation_schema(*operation, &document);
            jsonschema::draft202012::new(&schema).unwrap_or_else(|error| {
                panic!("{} schema failed to compile: {error}", operation.suffix())
            });
        }
    }

    #[test]
    fn provider_key_is_account_scoped_and_deterministic() {
        let mut action = Action::new(
            CapabilityId::trusted("cap:wa_archive:send_message"),
            json!({}),
        );
        action.idempotency_key = Some("business-operation-42".to_owned());
        let first = provider_idempotency_key("account-a", &action).expect("provider key");
        let repeated = provider_idempotency_key("account-a", &action).expect("provider key");
        let other = provider_idempotency_key("account-b", &action).expect("provider key");
        assert_eq!(first, repeated);
        assert_ne!(first, other);
        assert_eq!(first.len(), 74);
    }

    #[test]
    fn change_feed_event_id_is_stable_and_account_scoped() {
        let change = WaArchiveChange {
            sequence: 7,
            source_kind: "message".to_owned(),
            source_id: "message-1".to_owned(),
            event_kind: "message.archived".to_owned(),
            occurred_at: "2026-07-26T00:00:00Z".to_owned(),
            payload: json!({
                "messageId": "message-1",
                "mediaPath": "/private/provider/media"
            }),
            created_at: "2026-07-26T00:00:01Z".to_owned(),
        };
        let first = event_from_change("account-a", change.clone()).expect("event");
        let repeated = event_from_change("account-a", change.clone()).expect("event");
        let other = event_from_change("account-b", change).expect("event");
        assert_eq!(first.id, repeated.id);
        assert_ne!(first.id, other.id);
        assert!(
            first
                .data
                .as_ref()
                .and_then(|data| data.pointer("/payload/mediaPath"))
                .is_none()
        );
    }

    #[test]
    fn provider_outputs_drop_filesystem_and_secret_fields_recursively() {
        let redacted = redact_provider_paths(json!({
            "mediaPath": "/private/archive/file",
            "nested": { "path": "/private/other", "token": "secret", "safe": true },
            "items": [{ "media_path": "/private/third", "id": 1 }]
        }));
        assert!(redacted.get("mediaPath").is_none());
        assert_eq!(redacted.pointer("/nested/safe"), Some(&Value::Bool(true)));
        assert!(redacted.pointer("/nested/path").is_none());
        assert!(redacted.pointer("/nested/token").is_none());
        assert!(redacted.pointer("/items/0/media_path").is_none());
    }

    #[test]
    fn contact_search_normalizes_provider_fields_to_the_admitted_aip_contract() {
        let normalized = normalize_query_output(
            WaArchiveQueryOperation::ContactSearch,
            json!({
                "items": [{
                    "canonicalId": "971501234567@c.us",
                    "phone": "+971501234567",
                    "contactId": "971501234567@c.us",
                    "lidId": null,
                    "name": "Alice Example",
                    "pushName": "Alice",
                    "shortName": "Ali",
                    "verifiedName": null,
                    "isMyContact": true,
                    "isWAContact": true,
                    "isBlocked": false,
                    "aliases": ["971501234567@c.us"]
                }]
            }),
        )
        .expect("provider contact projection");

        assert_eq!(
            normalized.pointer("/items/0/isWaContact"),
            Some(&Value::Bool(true))
        );
        assert!(normalized.pointer("/items/0/isWAContact").is_none());
        assert!(normalized.pointer("/items/0/shortName").is_none());
        assert!(normalized.pointer("/items/0/verifiedName").is_none());

        let schema = query_output_schema(WaArchiveQueryOperation::ContactSearch);
        jsonschema::draft202012::new(&schema)
            .expect("contact output schema")
            .validate(&normalized)
            .expect("normalized provider response must satisfy the admitted contract");
    }

    #[test]
    fn contact_search_fails_closed_when_a_stable_field_is_missing() {
        let error = normalize_query_output(
            WaArchiveQueryOperation::ContactSearch,
            json!({ "items": [{ "canonicalId": "971501234567@c.us" }] }),
        )
        .expect_err("partial provider contacts cannot cross the AIP boundary");
        assert!(matches!(
            error,
            WaArchiveConnectorError::ContractMismatch(_)
        ));
    }

    #[tokio::test]
    async fn native_aip_invocation_validates_submits_and_reconciles_by_provider_key() {
        let (base_url, state, server) = mock_provider().await;
        let connector = WaArchiveConnector::new(
            &base_url,
            "whatsapp-account-1",
            ConnectorSecret::new(MOCK_TOKEN),
        )
        .expect("connector");
        let mut action = Action::new(
            CapabilityId::trusted("cap:wa_archive:send_message"),
            json!({
                "to_chat_id": "971501234567@c.us",
                "operation": { "kind": "send_message" },
                "body": "AIP connector contract test"
            }),
        );
        action.idempotency_key = Some("business-message-41".to_owned());
        let provider_key = provider_idempotency_key("whatsapp-account-1", &action)
            .expect("provider operation key");

        let result = connector
            .invoke(&ConnectorContext::default(), action)
            .await
            .expect("native AIP invocation");
        assert_eq!(result.status, ActionResultStatus::Completed);
        assert_eq!(
            result
                .output
                .as_ref()
                .and_then(|output| output.get("provider_operation_id"))
                .and_then(Value::as_str),
            Some(provider_key.as_str())
        );
        assert!(
            result
                .output
                .as_ref()
                .and_then(|output| output.pointer("/result/mediaPath"))
                .is_none()
        );

        let stored = connector
            .lookup_provider_job(&provider_key, ConnectorOperation::Reconciliation, None)
            .await
            .expect("provider reconciliation lookup");
        let reconciled = reconciliation_result(stored, &provider_key);
        assert!(reconciled.terminal);
        assert_eq!(reconciled.committed, Some(true));
        assert_eq!(
            state.submissions.lock().expect("submissions").len(),
            1,
            "the connector must dispatch exactly once"
        );
        server.abort();
    }

    #[tokio::test]
    async fn media_resource_is_bounded_hashed_and_path_free() {
        let (base_url, _state, server) = mock_provider().await;
        let connector = WaArchiveConnector::new(
            &base_url,
            "whatsapp-account-1",
            ConnectorSecret::new(MOCK_TOKEN),
        )
        .expect("connector");
        let action = Action::new(
            CapabilityId::trusted("cap:wa_archive:query:archive.media.get"),
            json!({ "message_id": "message-with-media" }),
        );
        let result = connector
            .invoke(&ConnectorContext::default(), action)
            .await
            .expect("media query");
        let output = result.output.expect("media output");
        assert_eq!(output["filename"], "archive-note.txt");
        assert_eq!(output["content_type"], "text/plain");
        assert_eq!(output["size_bytes"], 22);
        assert_eq!(
            output["sha256"],
            hex::encode(Sha256::digest(b"verified archive media"))
        );
        assert_eq!(
            output["content_base64"],
            BASE64_STANDARD.encode(b"verified archive media")
        );
        assert!(output.get("path").is_none());
        server.abort();
    }

    #[tokio::test]
    async fn sensitive_invocation_is_rejected_before_provider_dispatch() {
        let (base_url, state, server) = mock_provider().await;
        let connector = WaArchiveConnector::new(
            &base_url,
            "whatsapp-account-1",
            ConnectorSecret::new(MOCK_TOKEN),
        )
        .expect("connector");
        let mut action = Action::new(
            CapabilityId::trusted("cap:wa_archive:profile_set_about"),
            json!({
                "operation": {
                    "kind": "profile",
                    "operation": { "action": "set_about", "text": "Production" }
                }
            }),
        );
        action.idempotency_key = Some("business-delete-1".to_owned());

        let failure = connector
            .invoke(&ConnectorContext::default(), action)
            .await
            .expect_err("sensitive operation must require a transaction");
        assert!(matches!(failure, ConnectorError::Failure(_)));
        assert!(state.submissions.lock().expect("submissions").is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn plan_validation_verifies_inline_media_digest_without_provider_side_effects() {
        let connector = WaArchiveConnector::new(
            "http://127.0.0.1:9",
            "whatsapp-account-1",
            ConnectorSecret::new(MOCK_TOKEN),
        )
        .expect("connector");
        let operation = WaArchiveOperation::from_suffix("send_message").expect("operation");
        let mut action = Action::new(
            CapabilityId::trusted("cap:wa_archive:send_message"),
            json!({
                "to_chat_id": "971501234567@c.us",
                "operation": { "kind": "send_message" },
                "body": "media",
                "media": {
                    "content_base64": "aGVsbG8=",
                    "filename": "note.txt",
                    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                }
            }),
        );
        action.idempotency_key = Some("media-plan-1".to_owned());
        connector
            .prepare_operation_input(operation, &action, false, false)
            .await
            .expect("valid inline media plan");

        action.input["media"]["sha256"] = Value::String("0".repeat(64));
        let invalid = connector
            .prepare_operation_input(operation, &action, false, false)
            .await;
        let Err(error) = invalid else {
            panic!("invalid media digest was accepted");
        };
        assert!(error.to_string().contains("does not match"));
    }
}
