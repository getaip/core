//! Production connector for Twenty's workspace-aware REST APIs.
//!
//! The connector deliberately maps the documented core-record, metadata, and
//! OpenAPI surfaces to fixed AIP capabilities. It is not an arbitrary HTTP or
//! GraphQL proxy: provider paths are assembled from validated object/resource
//! identifiers, authentication is header-only, and redirects are disabled.
//! Mutations require AIP approval by default. A deployment may explicitly
//! admit a narrow, field-allowlisted idempotent-ingest policy for deterministic
//! `record.ingest` and `record.ingest_many` automation; all other mutations
//! remain approval-gated.

#![forbid(unsafe_code)]

use aip_connector::{
    CapabilityImplementationSupport, CapabilityProviderConnector, Connector, ConnectorContext,
    ConnectorError, ConnectorFailure, ConnectorHealth, ConnectorOperation, ConnectorResult,
    ConnectorSecret, FrozenConnector, OutboundConnector,
};
use aip_core::{
    Action, ActionResult, ActionResultStatus, ApprovalPolicy, ApproverSelector, Binding,
    Capability, CapabilityContract, CapabilityId, CapabilityKind, CompensationContract,
    CompensationMode, DataContract, DataSensitivity, ErrorCategory, Event, EventId,
    EvidenceRequirement, ExecutionContract, ExpectedCompletionMode, IdempotencyCollisionBehavior,
    IdempotencyContract, IdempotencyKeyScope, IdempotencyRequirement, Manifest, MessagePart,
    Principal, PrincipalId, PrincipalKind, ProfileId, ProtocolError, RetrySafety, RiskLevel,
    ServiceLevelContract, SideEffect, Stability,
};
use aip_discovery::CapabilityImplementationSupport as ImplementationSupport;
use aip_runtime::{
    ActionExecutionContext, ActionHandler, ProfileStateCasOutcome, ProfileStateStore, RuntimeError,
    RuntimeResult,
};
use async_trait::async_trait;
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::{Method, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

/// Stable connector id.
pub const CONNECTOR_ID: &str = "twenty";
/// AIP binding profile for Twenty REST semantics.
pub const PROFILE_ID: &str = "aip.connector.twenty.v1";
/// Exact official Twenty revision used to derive this mapping.
pub const UPSTREAM_REVISION: &str = "96a24563674313a3071d359bfccaf33d5e130ab8";

const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_WEBHOOK_BODY_BYTES: usize = 4 * 1024 * 1024;
const WEBHOOK_MAX_SKEW_MILLIS: i128 = 300_000;
const WEBHOOK_REPLAY_CAPACITY: usize = 100_000;
/// Exact configuration contract for bounded automatic record ingestion.
pub const IDEMPOTENT_INGEST_POLICY_VERSION: &str = "aip.twenty.idempotent-ingest-policy/v1";
const MAX_INGEST_POLICY_OBJECTS: usize = 128;
const MAX_INGEST_POLICY_FIELDS: usize = 2_048;

/// Per-object boundary for deterministic, idempotent record ingestion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwentyIngestObjectPolicy {
    /// Exact Twenty record fields that an ingest action may write.
    pub fields: BTreeSet<String>,
    /// Maximum records accepted in one `record.ingest_many` action.
    #[serde(default = "default_ingest_batch_records")]
    pub max_batch_records: usize,
}

/// Deployment-owned allowlist for unattended, idempotent record ingestion.
///
/// Installing this policy enables only `record.ingest` and
/// `record.ingest_many`: these dedicated, stable-contract capabilities are
/// medium-risk and do not require per-action approval. The connector rejects
/// every object or field not listed here before sending an HTTP request to
/// Twenty. The normal `record.create*` capabilities retain their approval
/// contract and are never changed by deployment policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwentyIdempotentIngestPolicy {
    /// Must equal [`IDEMPOTENT_INGEST_POLICY_VERSION`].
    pub version: String,
    /// Allowed Twenty plural object name to its exact writable boundary.
    pub objects: BTreeMap<String, TwentyIngestObjectPolicy>,
}

const fn default_ingest_batch_records() -> usize {
    200
}

/// Complete stable operation catalogue exposed by the connector.
pub const ALL_TWENTY_OPERATIONS: [TwentyOperation; 24] = [
    TwentyOperation::RecordList,
    TwentyOperation::RecordGet,
    TwentyOperation::RecordFindDuplicates,
    TwentyOperation::RecordGroupBy,
    TwentyOperation::RecordCreate,
    TwentyOperation::RecordCreateMany,
    TwentyOperation::RecordIngest,
    TwentyOperation::RecordIngestMany,
    TwentyOperation::RecordUpdate,
    TwentyOperation::RecordUpdateMany,
    TwentyOperation::RecordSoftDelete,
    TwentyOperation::RecordSoftDeleteMany,
    TwentyOperation::RecordDestroy,
    TwentyOperation::RecordDestroyMany,
    TwentyOperation::RecordRestore,
    TwentyOperation::RecordRestoreMany,
    TwentyOperation::RecordMerge,
    TwentyOperation::MetadataList,
    TwentyOperation::MetadataGet,
    TwentyOperation::MetadataCreate,
    TwentyOperation::MetadataUpdate,
    TwentyOperation::MetadataDelete,
    TwentyOperation::OpenApiCore,
    TwentyOperation::OpenApiMetadata,
];

const METADATA_RESOURCES: [&str; 12] = [
    "objects",
    "fields",
    "views",
    "viewFields",
    "viewFilters",
    "viewGroups",
    "viewSorts",
    "viewFilterGroups",
    "pageLayouts",
    "pageLayoutTabs",
    "pageLayoutWidgets",
    "webhooks",
];

/// Provider surfaces intentionally excluded from the AIP business connector.
///
/// These endpoints are not missing REST coverage. They are deployment,
/// credential, arbitrary-query, code-execution, or UI-extension boundaries
/// whose admission and data contracts cannot be represented safely by the
/// fixed record and metadata capabilities below.
pub const INTENTIONALLY_EXCLUDED_SURFACES: &[(&str, &str)] = &[
    (
        "workspace GraphQL and metadata GraphQL",
        "arbitrary query documents bypass the fixed operation, path, and field contracts",
    ),
    (
        "admin, authentication, billing, and workspace-management APIs",
        "operator-owned deployment and credential lifecycle",
    ),
    (
        "REST AI generation",
        "model execution requires a separately governed model connector contract",
    ),
    (
        "REST front-component delivery",
        "executable UI extension content is outside the CRM data boundary",
    ),
    (
        "route triggers and workflow code execution",
        "dynamic executable routes require a dedicated workflow connector",
    ),
    (
        "Twenty MCP server",
        "protocol translation is handled by AIP profiles rather than provider MCP passthrough",
    ),
];

/// One fixed Twenty provider operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TwentyOperation {
    /// List records of a standard or custom object.
    RecordList,
    /// Read one record by UUID.
    RecordGet,
    /// Find duplicate records from provider-native matching rules.
    RecordFindDuplicates,
    /// Aggregate records with provider-native group-by semantics.
    RecordGroupBy,
    /// Create or idempotently upsert one record.
    RecordCreate,
    /// Create or idempotently upsert multiple records.
    RecordCreateMany,
    /// Policy-scoped idempotent ingest of one deterministic record.
    RecordIngest,
    /// Policy-scoped idempotent ingest of deterministic records.
    RecordIngestMany,
    /// Update one record by UUID.
    RecordUpdate,
    /// Update records selected by an explicit filter.
    RecordUpdateMany,
    /// Soft-delete one record.
    RecordSoftDelete,
    /// Soft-delete records selected by an explicit filter.
    RecordSoftDeleteMany,
    /// Permanently destroy one record.
    RecordDestroy,
    /// Permanently destroy records selected by an explicit filter.
    RecordDestroyMany,
    /// Restore one soft-deleted record.
    RecordRestore,
    /// Restore soft-deleted records selected by an explicit filter.
    RecordRestoreMany,
    /// Merge multiple records using Twenty conflict priority rules.
    RecordMerge,
    /// List one supported metadata resource.
    MetadataList,
    /// Read one metadata resource by UUID.
    MetadataGet,
    /// Create one metadata resource.
    MetadataCreate,
    /// Update one metadata resource by UUID.
    MetadataUpdate,
    /// Delete one metadata resource by UUID.
    MetadataDelete,
    /// Read the workspace-specific core OpenAPI document.
    OpenApiCore,
    /// Read the workspace-specific metadata OpenAPI document.
    OpenApiMetadata,
}

impl TwentyOperation {
    /// Parses one exact capability suffix.
    #[must_use]
    pub fn from_suffix(value: &str) -> Option<Self> {
        ALL_TWENTY_OPERATIONS
            .into_iter()
            .find(|operation| operation.suffix() == value)
    }

    /// Returns the stable capability suffix.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::RecordList => "record.list",
            Self::RecordGet => "record.get",
            Self::RecordFindDuplicates => "record.find_duplicates",
            Self::RecordGroupBy => "record.group_by",
            Self::RecordCreate => "record.create",
            Self::RecordCreateMany => "record.create_many",
            Self::RecordIngest => "record.ingest",
            Self::RecordIngestMany => "record.ingest_many",
            Self::RecordUpdate => "record.update",
            Self::RecordUpdateMany => "record.update_many",
            Self::RecordSoftDelete => "record.soft_delete",
            Self::RecordSoftDeleteMany => "record.soft_delete_many",
            Self::RecordDestroy => "record.destroy",
            Self::RecordDestroyMany => "record.destroy_many",
            Self::RecordRestore => "record.restore",
            Self::RecordRestoreMany => "record.restore_many",
            Self::RecordMerge => "record.merge",
            Self::MetadataList => "metadata.list",
            Self::MetadataGet => "metadata.get",
            Self::MetadataCreate => "metadata.create",
            Self::MetadataUpdate => "metadata.update",
            Self::MetadataDelete => "metadata.delete",
            Self::OpenApiCore => "openapi.core",
            Self::OpenApiMetadata => "openapi.metadata",
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::RecordList => "List records",
            Self::RecordGet => "Get record",
            Self::RecordFindDuplicates => "Find duplicate records",
            Self::RecordGroupBy => "Group records",
            Self::RecordCreate => "Create record",
            Self::RecordCreateMany => "Create records",
            Self::RecordIngest => "Ingest record",
            Self::RecordIngestMany => "Ingest records",
            Self::RecordUpdate => "Update record",
            Self::RecordUpdateMany => "Update records",
            Self::RecordSoftDelete => "Soft-delete record",
            Self::RecordSoftDeleteMany => "Soft-delete records",
            Self::RecordDestroy => "Permanently destroy record",
            Self::RecordDestroyMany => "Permanently destroy records",
            Self::RecordRestore => "Restore record",
            Self::RecordRestoreMany => "Restore records",
            Self::RecordMerge => "Merge records",
            Self::MetadataList => "List metadata",
            Self::MetadataGet => "Get metadata",
            Self::MetadataCreate => "Create metadata",
            Self::MetadataUpdate => "Update metadata",
            Self::MetadataDelete => "Delete metadata",
            Self::OpenApiCore => "Read core OpenAPI",
            Self::OpenApiMetadata => "Read metadata OpenAPI",
        }
    }

    /// Returns whether this operation changes provider state.
    #[must_use]
    pub const fn is_mutation(self) -> bool {
        !matches!(
            self,
            Self::RecordList
                | Self::RecordGet
                | Self::RecordFindDuplicates
                | Self::RecordGroupBy
                | Self::MetadataList
                | Self::MetadataGet
                | Self::OpenApiCore
                | Self::OpenApiMetadata
        )
    }

    const fn is_delete(self) -> bool {
        matches!(
            self,
            Self::RecordSoftDelete
                | Self::RecordSoftDeleteMany
                | Self::RecordDestroy
                | Self::RecordDestroyMany
                | Self::MetadataDelete
        )
    }

    const fn is_critical(self) -> bool {
        matches!(
            self,
            Self::RecordDestroy
                | Self::RecordDestroyMany
                | Self::MetadataCreate
                | Self::MetadataUpdate
                | Self::MetadataDelete
        )
    }

    const fn retry_safe(self) -> bool {
        !self.is_mutation()
            || matches!(
                self,
                Self::RecordCreate
                    | Self::RecordCreateMany
                    | Self::RecordIngest
                    | Self::RecordIngestMany
                    | Self::RecordUpdate
            )
    }

    const fn is_policy_ingest(self) -> bool {
        matches!(self, Self::RecordIngest | Self::RecordIngestMany)
    }
}

/// Exact signed webhook delivery received from Twenty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwentyWebhookDelivery {
    /// Millisecond timestamp from `X-Twenty-Webhook-Timestamp`.
    pub timestamp: String,
    /// Hex HMAC from `X-Twenty-Webhook-Signature`.
    pub signature: String,
    /// Random delivery nonce from `X-Twenty-Webhook-Nonce`.
    pub nonce: String,
    /// Original request body, byte-for-byte as received.
    pub raw_body: Vec<u8>,
}

/// Atomic replay fence for Twenty webhook nonces.
#[async_trait]
pub trait TwentyWebhookReplayStore: Send + Sync {
    /// Admits a verified nonce once inside a bounded replay window.
    async fn admit(
        &self,
        nonce: &str,
        timestamp_millis: i128,
        cutoff_millis: i128,
        capacity: usize,
    ) -> Result<bool, String>;
}

/// Process-local replay store for tests and single-process development.
#[derive(Debug, Default)]
pub struct InMemoryTwentyWebhookReplayStore {
    nonces: Mutex<BTreeMap<String, i128>>,
}

/// Cluster-safe webhook replay store backed by AIP profile state.
#[derive(Clone)]
pub struct ProfileStateTwentyWebhookReplayStore {
    state: ProfileStateStore,
    scope: String,
}

impl fmt::Debug for ProfileStateTwentyWebhookReplayStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileStateTwentyWebhookReplayStore")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl ProfileStateTwentyWebhookReplayStore {
    /// Creates a shared replay fence for one logical connector instance.
    pub fn new(state: ProfileStateStore, scope: impl Into<String>) -> Result<Self, String> {
        let scope = scope.into();
        if scope.trim().is_empty() || scope.len() > 1_024 || scope.contains('\0') {
            return Err(
                "Twenty webhook replay scope must contain 1..=1024 bytes without NUL".to_owned(),
            );
        }
        Ok(Self { state, scope })
    }
}

#[async_trait]
impl TwentyWebhookReplayStore for InMemoryTwentyWebhookReplayStore {
    async fn admit(
        &self,
        nonce: &str,
        timestamp_millis: i128,
        cutoff_millis: i128,
        capacity: usize,
    ) -> Result<bool, String> {
        let mut nonces = self.nonces.lock().await;
        admit_nonce(
            &mut nonces,
            nonce,
            timestamp_millis,
            cutoff_millis,
            capacity,
        )
    }
}

#[async_trait]
impl TwentyWebhookReplayStore for ProfileStateTwentyWebhookReplayStore {
    async fn admit(
        &self,
        nonce: &str,
        timestamp_millis: i128,
        cutoff_millis: i128,
        capacity: usize,
    ) -> Result<bool, String> {
        const NAMESPACE: &str = "aip.connector.twenty.webhook_replay.v1";
        for _ in 0..32 {
            let current = self
                .state
                .get(NAMESPACE, &self.scope)
                .await
                .map_err(|error| error.to_string())?;
            let mut nonces = current
                .as_ref()
                .map(|entry| serde_json::from_value::<BTreeMap<String, i128>>(entry.value.clone()))
                .transpose()
                .map_err(|error| format!("decode Twenty replay state: {error}"))?
                .unwrap_or_default();
            if nonces.contains_key(nonce) {
                return Ok(false);
            }
            if !admit_nonce(
                &mut nonces,
                nonce,
                timestamp_millis,
                cutoff_millis,
                capacity,
            )? {
                return Ok(false);
            }
            let value = serde_json::to_value(nonces)
                .map_err(|error| format!("encode Twenty replay state: {error}"))?;
            match self
                .state
                .compare_and_set(
                    NAMESPACE,
                    &self.scope,
                    current.as_ref().map(|entry| entry.revision),
                    value,
                )
                .await
                .map_err(|error| error.to_string())?
            {
                ProfileStateCasOutcome::Applied(_) => return Ok(true),
                ProfileStateCasOutcome::Conflict(_) => tokio::task::yield_now().await,
            }
        }
        Err("Twenty webhook replay state remained contended after 32 attempts".to_owned())
    }
}

fn admit_nonce(
    nonces: &mut BTreeMap<String, i128>,
    nonce: &str,
    timestamp_millis: i128,
    cutoff_millis: i128,
    capacity: usize,
) -> Result<bool, String> {
    nonces.retain(|_, timestamp| *timestamp >= cutoff_millis);
    if nonces.contains_key(nonce) {
        return Ok(false);
    }
    if nonces.len() >= capacity {
        return Err(format!(
            "Twenty webhook replay window reached its {capacity}-nonce capacity"
        ));
    }
    nonces.insert(nonce.to_owned(), timestamp_millis);
    Ok(true)
}

/// Hardened Twenty REST connector.
#[derive(Clone)]
pub struct TwentyConnector {
    base_url: Url,
    workspace_id: String,
    api_token: ConnectorSecret,
    webhook_secret: Option<ConnectorSecret>,
    webhook_replays: Arc<dyn TwentyWebhookReplayStore>,
    client: reqwest::Client,
    max_response_bytes: usize,
    allowed_operations: BTreeSet<TwentyOperation>,
    idempotent_ingest_policy: Option<TwentyIdempotentIngestPolicy>,
}

impl fmt::Debug for TwentyConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TwentyConnector")
            .field("base_url", &self.base_url)
            .field("workspace_id", &self.workspace_id)
            .field("api_token", &self.api_token)
            .field("webhook_secret_configured", &self.webhook_secret.is_some())
            .field("max_response_bytes", &self.max_response_bytes)
            .field("allowed_operation_count", &self.allowed_operations.len())
            .field(
                "idempotent_ingest_policy_configured",
                &self.idempotent_ingest_policy.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl TwentyConnector {
    /// Creates a connector with a protected API token.
    ///
    /// Plain HTTP is accepted only for loopback origins unless
    /// `allow_insecure_http` is explicitly enabled for a trusted private Docker
    /// network. Redirects remain disabled in either mode.
    pub fn with_api_token(
        base_url: impl AsRef<str>,
        workspace_id: impl Into<String>,
        api_token: ConnectorSecret,
        allow_insecure_http: bool,
    ) -> Result<Self, TwentyConnectorError> {
        let base_url = validate_base_url(base_url.as_ref(), allow_insecure_http)?;
        let workspace_id = workspace_id.into();
        if !is_twenty_uuid(&workspace_id) {
            return Err(TwentyConnectorError::InvalidConfiguration(
                "workspace id must be an RFC 4122 UUID version 1 through 5".to_owned(),
            ));
        }
        validate_bearer_secret(&api_token)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|error| TwentyConnectorError::InvalidConfiguration(error.to_string()))?;
        Ok(Self {
            base_url,
            workspace_id,
            api_token,
            webhook_secret: None,
            webhook_replays: Arc::new(InMemoryTwentyWebhookReplayStore::default()),
            client,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            allowed_operations: ALL_TWENTY_OPERATIONS
                .into_iter()
                .filter(|operation| !operation.is_policy_ingest())
                .collect(),
            idempotent_ingest_policy: None,
        })
    }

    /// Restricts the executable catalogue for one deployment/account policy.
    pub fn with_allowed_operations(
        mut self,
        operations: impl IntoIterator<Item = TwentyOperation>,
    ) -> Result<Self, TwentyConnectorError> {
        let operations = operations.into_iter().collect::<BTreeSet<_>>();
        if operations.is_empty() {
            return Err(TwentyConnectorError::InvalidConfiguration(
                "at least one Twenty operation must be enabled".to_owned(),
            ));
        }
        self.allowed_operations = operations;
        Ok(self)
    }

    /// Enables a fail-closed, object-and-field-scoped idempotent ingest path.
    ///
    /// This is intended for deterministic importers that use stable record IDs
    /// and AIP idempotency keys. It never enables update, delete, metadata, or
    /// arbitrary provider operations. Installing the policy restricts every
    /// admitted `record.ingest` and `record.ingest_many` action to the declared
    /// objects and fields. The deployment operation allowlist must enable those
    /// dedicated capabilities explicitly.
    pub fn with_idempotent_ingest_policy(
        mut self,
        policy: TwentyIdempotentIngestPolicy,
    ) -> Result<Self, TwentyConnectorError> {
        validate_ingest_policy(&policy)?;
        self.idempotent_ingest_policy = Some(policy);
        Ok(self)
    }

    /// Sets the maximum accepted provider response size.
    pub fn with_max_response_bytes(
        mut self,
        max_response_bytes: usize,
    ) -> Result<Self, TwentyConnectorError> {
        if !(1..=MAX_RESPONSE_BYTES).contains(&max_response_bytes) {
            return Err(TwentyConnectorError::InvalidConfiguration(format!(
                "max_response_bytes must be between 1 and {MAX_RESPONSE_BYTES}"
            )));
        }
        self.max_response_bytes = max_response_bytes;
        Ok(self)
    }

    /// Enables exact HMAC verification and shared nonce replay fencing.
    pub fn with_webhook_security(
        mut self,
        secret: ConnectorSecret,
        replay_store: Arc<dyn TwentyWebhookReplayStore>,
    ) -> Result<Self, TwentyConnectorError> {
        validate_secret(&secret, "webhook secret")?;
        self.webhook_secret = Some(secret);
        self.webhook_replays = replay_store;
        Ok(self)
    }

    fn token(&self) -> Result<&str, TwentyConnectorError> {
        self.api_token
            .expose_str()
            .map_err(|_| TwentyConnectorError::InvalidCredential)
    }

    /// Verifies one exact Twenty delivery and maps it to a deterministic AIP event.
    pub async fn ingest_webhook_delivery(
        &self,
        delivery: TwentyWebhookDelivery,
    ) -> Result<Event, TwentyConnectorError> {
        let secret = self
            .webhook_secret
            .as_ref()
            .ok_or(TwentyConnectorError::WebhookNotConfigured)?;
        if delivery.raw_body.is_empty() || delivery.raw_body.len() > MAX_WEBHOOK_BODY_BYTES {
            return Err(TwentyConnectorError::InvalidWebhook(format!(
                "body must contain 1..={MAX_WEBHOOK_BODY_BYTES} bytes"
            )));
        }
        validate_hex("webhook nonce", &delivery.nonce, 32)?;
        validate_hex("webhook signature", &delivery.signature, 64)?;
        if delivery.timestamp.is_empty()
            || delivery.timestamp.len() > 32
            || !delivery.timestamp.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(TwentyConnectorError::InvalidWebhook(
                "timestamp must be a decimal Unix millisecond value".to_owned(),
            ));
        }
        let timestamp_millis = delivery
            .timestamp
            .parse::<i128>()
            .map_err(|_| TwentyConnectorError::InvalidWebhook("invalid timestamp".to_owned()))?;
        let now_millis = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let skew_millis = now_millis
            .checked_sub(timestamp_millis)
            .and_then(i128::checked_abs)
            .ok_or_else(|| TwentyConnectorError::InvalidWebhook("timestamp overflow".to_owned()))?;
        if skew_millis > WEBHOOK_MAX_SKEW_MILLIS {
            return Err(TwentyConnectorError::InvalidWebhook(
                "timestamp is outside the five-minute acceptance window".to_owned(),
            ));
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.expose_bytes())
            .map_err(|_| TwentyConnectorError::InvalidCredential)?;
        mac.update(delivery.timestamp.as_bytes());
        mac.update(b":");
        mac.update(&delivery.raw_body);
        let supplied = hex::decode(&delivery.signature)
            .map_err(|_| TwentyConnectorError::InvalidWebhook("invalid signature".to_owned()))?;
        mac.verify_slice(&supplied).map_err(|_| {
            TwentyConnectorError::InvalidWebhook("signature verification failed".to_owned())
        })?;
        // Twenty's pinned upstream contract signs `timestamp:raw-body`; its
        // nonce header is intentionally not part of that HMAC. Fence the
        // authenticated delivery rather than trusting an attacker-mutable
        // nonce as the replay identity. A provider retry may legitimately use
        // a new timestamp and nonce, so the stable AIP event id below is
        // derived independently from the business payload.
        let delivery_fingerprint = Sha256::digest(
            [
                delivery.timestamp.as_bytes(),
                b":",
                delivery.signature.as_bytes(),
                b":",
                delivery.raw_body.as_slice(),
            ]
            .concat(),
        );
        let replay_key = hex::encode(delivery_fingerprint);
        let admitted = self
            .webhook_replays
            .admit(
                &replay_key,
                timestamp_millis,
                now_millis - WEBHOOK_MAX_SKEW_MILLIS,
                WEBHOOK_REPLAY_CAPACITY,
            )
            .await
            .map_err(TwentyConnectorError::ReplayStore)?;
        if !admitted {
            return Err(TwentyConnectorError::InvalidWebhook(
                "signed webhook delivery was already admitted".to_owned(),
            ));
        }
        let payload: Value = serde_json::from_slice(&delivery.raw_body)
            .map_err(|error| TwentyConnectorError::InvalidWebhook(error.to_string()))?;
        let object = payload.as_object().ok_or_else(|| {
            TwentyConnectorError::InvalidWebhook("payload must be a JSON object".to_owned())
        })?;
        let event_name = required_string(object, "eventName")?;
        validate_event_name(event_name)?;
        let workspace_id = required_string(object, "workspaceId")?;
        if workspace_id != self.workspace_id {
            return Err(TwentyConnectorError::InvalidWebhook(
                "payload workspaceId does not match the configured workspace".to_owned(),
            ));
        }
        let webhook_id = required_string(object, "webhookId")?;
        validate_uuid("webhookId", webhook_id)?;
        let event_date = required_string(object, "eventDate")?;
        let occurred_at = OffsetDateTime::parse(event_date, &Rfc3339).map_err(|error| {
            TwentyConnectorError::InvalidWebhook(format!("invalid eventDate: {error}"))
        })?;
        let digest = Sha256::digest(
            [
                self.workspace_id.as_bytes(),
                b":",
                webhook_id.as_bytes(),
                b":",
                delivery.raw_body.as_slice(),
            ]
            .concat(),
        );
        let mut event = Event::new(format!("twenty.{event_name}"));
        event.id = EventId::parse(format!("evt_{}", hex::encode(&digest[..16])))
            .map_err(|error| TwentyConnectorError::InvalidWebhook(error.to_string()))?;
        event.occurred_at = occurred_at;
        event.data = Some(payload);
        Ok(event)
    }

    async fn invoke_operation(
        &self,
        operation: TwentyOperation,
        action: Action,
        execution: Option<&ActionExecutionContext>,
    ) -> Result<ActionResult, TwentyConnectorError> {
        if !self.allowed_operations.contains(&operation) {
            return Err(TwentyConnectorError::OperationNotAllowed(
                operation.suffix().to_owned(),
            ));
        }
        if operation.is_policy_ingest() {
            let policy = self.idempotent_ingest_policy.as_ref().ok_or_else(|| {
                TwentyConnectorError::OperationNotAllowed(format!(
                    "{} requires an admitted idempotent-ingest policy",
                    operation.suffix()
                ))
            })?;
            validate_idempotent_ingest_action(policy, operation, &action.input)?;
        }
        let idempotency_key = if operation.is_mutation() {
            Some(required_idempotency_key(&action)?)
        } else {
            action.idempotency_key.as_deref()
        };
        let request_spec = self.request_spec(operation, &action, idempotency_key)?;
        let mut request = self
            .client
            .request(request_spec.method, request_spec.url)
            .bearer_auth(self.token()?)
            .header("X-AIP-Action-ID", action.id.to_string());
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        if let Some(body) = request_spec.body {
            ensure_request_size(&body)?;
            request = request.json(&body);
        }
        let response = request.send().await?;
        let status = response.status();
        let request_id = provider_request_id(&response);
        let retry_after_ms = retry_after_millis(&response);
        let body = response_body(response, self.max_response_bytes).await?;
        if !status.is_success() {
            return Err(TwentyConnectorError::Status {
                status: status.as_u16(),
                request_id,
                retry_after_ms,
                details: provider_error_details(&body),
            });
        }
        let body = redact_provider_response(operation, &action.input, body);
        if operation.is_mutation()
            && let Some(execution) = execution
        {
            execution
                .execution_checkpoints
                .provider_effect_committed()
                .await;
        }
        Ok(completed_result(
            action,
            json!({
                "http_status": status.as_u16(),
                "provider_request_id": request_id,
                "body": body
            }),
        ))
    }

    fn metadata_mutation_body(
        &self,
        operation: TwentyOperation,
        resource: &str,
        input: &Value,
    ) -> Result<Value, TwentyConnectorError> {
        let mut body = input_body(input, true)?;
        if resource != "webhooks" {
            return Ok(body);
        }
        let object = body
            .as_object_mut()
            .ok_or_else(|| invalid_input("webhook metadata body must be a JSON object"))?;
        if object.remove("secret").is_some() {
            return Err(invalid_input(
                "webhook secrets must come from AIP_TWENTY_WEBHOOK_SECRET_FILE, not Action input",
            ));
        }
        let rotate = object.remove("rotateConfiguredSecret");
        let inject = match operation {
            TwentyOperation::MetadataCreate => {
                if rotate.is_some() {
                    return Err(invalid_input(
                        "rotateConfiguredSecret is valid only for webhook updates",
                    ));
                }
                true
            }
            TwentyOperation::MetadataUpdate => match rotate {
                None => false,
                Some(Value::Bool(true)) => true,
                Some(_) => {
                    return Err(invalid_input(
                        "rotateConfiguredSecret must be the boolean true",
                    ));
                }
            },
            _ => false,
        };
        if inject {
            let secret = self
                .webhook_secret
                .as_ref()
                .ok_or(TwentyConnectorError::WebhookNotConfigured)?
                .expose_str()
                .map_err(|_| TwentyConnectorError::InvalidCredential)?;
            object.insert("secret".to_owned(), Value::String(secret.to_owned()));
        }
        Ok(body)
    }

    fn request_spec(
        &self,
        operation: TwentyOperation,
        action: &Action,
        idempotency_key: Option<&str>,
    ) -> Result<RequestSpec, TwentyConnectorError> {
        let object = || input_object_name(&action.input);
        let id = || input_uuid(&action.input, "id");
        let resource = || input_metadata_resource(&action.input);
        let (method, path, body) = match operation {
            TwentyOperation::RecordList => (Method::GET, format!("/rest/{}", object()?), None),
            TwentyOperation::RecordGet => {
                (Method::GET, format!("/rest/{}/{}", object()?, id()?), None)
            }
            TwentyOperation::RecordFindDuplicates => (
                Method::POST,
                format!("/rest/{}/duplicates", object()?),
                Some(input_find_duplicates_body(&action.input)?),
            ),
            TwentyOperation::RecordGroupBy => {
                (Method::GET, format!("/rest/{}/groupBy", object()?), None)
            }
            TwentyOperation::RecordCreate | TwentyOperation::RecordIngest => {
                let key = idempotency_key.ok_or(TwentyConnectorError::MissingIdempotencyKey)?;
                let body =
                    inject_record_id(input_body(&action.input, true)?, &self.workspace_id, key, 0)?;
                (Method::POST, format!("/rest/{}", object()?), Some(body))
            }
            TwentyOperation::RecordCreateMany | TwentyOperation::RecordIngestMany => {
                let key = idempotency_key.ok_or(TwentyConnectorError::MissingIdempotencyKey)?;
                let values = input_body(&action.input, false)?
                    .as_array()
                    .cloned()
                    .ok_or_else(|| invalid_input("body must be a non-empty array"))?;
                if values.is_empty() || values.len() > 200 {
                    return Err(invalid_input("body must contain 1..=200 records"));
                }
                let values = values
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| inject_record_id(value, &self.workspace_id, key, index))
                    .collect::<Result<Vec<_>, _>>()?;
                (
                    Method::POST,
                    format!("/rest/batch/{}", object()?),
                    Some(Value::Array(values)),
                )
            }
            TwentyOperation::RecordUpdate => (
                Method::PATCH,
                format!("/rest/{}/{}", object()?, id()?),
                Some(input_body(&action.input, true)?),
            ),
            TwentyOperation::RecordUpdateMany => (
                Method::PATCH,
                format!("/rest/{}", object()?),
                Some(input_body(&action.input, true)?),
            ),
            TwentyOperation::RecordSoftDelete => (
                Method::DELETE,
                format!("/rest/{}/{}", object()?, id()?),
                None,
            ),
            TwentyOperation::RecordSoftDeleteMany => {
                (Method::DELETE, format!("/rest/{}", object()?), None)
            }
            TwentyOperation::RecordDestroy => (
                Method::DELETE,
                format!("/rest/{}/{}", object()?, id()?),
                None,
            ),
            TwentyOperation::RecordDestroyMany => {
                (Method::DELETE, format!("/rest/{}", object()?), None)
            }
            TwentyOperation::RecordRestore => {
                // Twenty 96a2456 declares the single-record route, but its
                // parseCorePath guard rejects every three-segment restore path.
                // The filtered collection route has the same durable effect.
                id()?;
                (Method::PATCH, format!("/rest/restore/{}", object()?), None)
            }
            TwentyOperation::RecordRestoreMany => {
                (Method::PATCH, format!("/rest/restore/{}", object()?), None)
            }
            TwentyOperation::RecordMerge => (
                Method::PATCH,
                format!("/rest/{}/merge", object()?),
                Some(input_merge_body(&action.input)?),
            ),
            TwentyOperation::MetadataList => {
                (Method::GET, format!("/rest/metadata/{}", resource()?), None)
            }
            TwentyOperation::MetadataGet => (
                Method::GET,
                format!("/rest/metadata/{}/{}", resource()?, id()?),
                None,
            ),
            TwentyOperation::MetadataCreate => {
                let resource = resource()?;
                let body = self.metadata_mutation_body(operation, &resource, &action.input)?;
                (
                    Method::POST,
                    format!("/rest/metadata/{resource}"),
                    Some(body),
                )
            }
            TwentyOperation::MetadataUpdate => {
                let resource = resource()?;
                let body = self.metadata_mutation_body(operation, &resource, &action.input)?;
                (
                    Method::PATCH,
                    format!("/rest/metadata/{resource}/{}", id()?),
                    Some(body),
                )
            }
            TwentyOperation::MetadataDelete => (
                Method::DELETE,
                format!("/rest/metadata/{}/{}", resource()?, id()?),
                None,
            ),
            TwentyOperation::OpenApiCore => (Method::GET, "/rest/open-api/core".to_owned(), None),
            TwentyOperation::OpenApiMetadata => {
                (Method::GET, "/rest/open-api/metadata".to_owned(), None)
            }
        };
        let mut url = self
            .base_url
            .join(&path)
            .map_err(TwentyConnectorError::InvalidUrl)?;
        if operation.suffix().starts_with("record.") {
            append_query(
                &mut url,
                action.input.get("query"),
                record_query_keys(operation),
            )?;
            if matches!(
                operation,
                TwentyOperation::RecordUpdateMany
                    | TwentyOperation::RecordSoftDeleteMany
                    | TwentyOperation::RecordDestroyMany
                    | TwentyOperation::RecordRestoreMany
            ) {
                require_bulk_filter(&url)?;
            }
            match operation {
                TwentyOperation::RecordCreate
                | TwentyOperation::RecordCreateMany
                | TwentyOperation::RecordIngest
                | TwentyOperation::RecordIngestMany => {
                    replace_query(&mut url, "upsert", "true");
                }
                TwentyOperation::RecordSoftDelete | TwentyOperation::RecordSoftDeleteMany => {
                    replace_query(&mut url, "soft_delete", "true");
                }
                TwentyOperation::RecordDestroy | TwentyOperation::RecordDestroyMany => {
                    replace_query(&mut url, "soft_delete", "false");
                }
                TwentyOperation::RecordRestore => {
                    replace_query(&mut url, "filter", &format!("id[eq]:{}", id()?));
                }
                _ => {}
            }
        } else if matches!(operation, TwentyOperation::MetadataList) {
            let resource = resource()?;
            append_query(
                &mut url,
                action.input.get("query"),
                metadata_list_query_keys(&resource),
            )?;
            validate_metadata_list_query(&resource, &url)?;
        } else if action.input.get("query").is_some() {
            return Err(invalid_input("query is not accepted by this operation"));
        }
        Ok(RequestSpec { method, url, body })
    }
}

struct RequestSpec {
    method: Method,
    url: Url,
    body: Option<Value>,
}

#[async_trait]
impl Connector for TwentyConnector {
    fn id(&self) -> &str {
        CONNECTOR_ID
    }

    async fn discover(&self, context: &ConnectorContext) -> ConnectorResult<Manifest> {
        let namespace = context.tenant_id.as_deref().unwrap_or(&self.workspace_id);
        manifest(
            namespace,
            &self.allowed_operations,
            self.max_response_bytes,
            self.webhook_secret.is_some(),
            self.idempotent_ingest_policy.as_ref(),
        )
        .map_err(|error| ConnectorError::Discovery(error.to_string()))
    }

    fn map_error(&self, error: &ConnectorError) -> ProtocolError {
        match error {
            ConnectorError::Failure(failure) => failure.to_protocol_error(),
            _ => ProtocolError {
                code: "connector.twenty".to_owned(),
                message: error.to_string(),
                category: ErrorCategory::Connector,
                retryable: Some(false),
                retry_after_ms: None,
                details: None,
                source: Some(Box::new(json!({ "connector": CONNECTOR_ID }))),
            },
        }
    }

    async fn health(&self, _context: &ConnectorContext) -> ConnectorResult<ConnectorHealth> {
        let url = self
            .base_url
            .join("/rest/open-api/core")
            .map_err(|error| ConnectorError::Discovery(error.to_string()))?;
        let response = self
            .client
            // Twenty exposes the authenticated OpenAPI route to HEAD requests.
            // A GET here would stream the complete workspace schema on every
            // connector-host readiness probe. Apart from unnecessary provider
            // load, dropping that large response after inspecting only its
            // status makes reverse proxies report a misleading broken pipe.
            .head(url)
            .bearer_auth(
                self.token()
                    .map_err(|error| ConnectorError::Discovery(error.to_string()))?,
            )
            .send()
            .await
            .map_err(|error| ConnectorError::Discovery(error.to_string()))?;
        if !response.status().is_success() {
            return Err(ConnectorError::Discovery(format!(
                "Twenty authenticated OpenAPI probe returned HTTP {}",
                response.status().as_u16()
            )));
        }
        Ok(ConnectorHealth {
            ready: true,
            detail: "Twenty authenticated workspace API is reachable".to_owned(),
        })
    }
}

#[async_trait]
impl CapabilityProviderConnector for TwentyConnector {
    async fn capabilities(&self, _context: &ConnectorContext) -> ConnectorResult<Vec<Capability>> {
        Ok(self
            .allowed_operations
            .iter()
            .copied()
            .map(|operation| {
                capability_for_policy(operation, self.idempotent_ingest_policy.as_ref())
            })
            .collect())
    }
}

#[async_trait]
impl OutboundConnector for TwentyConnector {
    async fn invoke(
        &self,
        _context: &ConnectorContext,
        action: Action,
    ) -> ConnectorResult<ActionResult> {
        let operation = operation_from_capability(&action.capability_id).ok_or_else(|| {
            ConnectorError::Invoke(format!(
                "unsupported Twenty capability `{}`",
                action.capability_id
            ))
        })?;
        self.invoke_operation(operation, action, None)
            .await
            .map_err(|error| ConnectorError::Failure(failure(error, operation)))
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
impl ActionHandler for TwentyConnector {
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
        FrozenConnector::invoke_typed(self, action, context)
            .await
            .map_err(|error| RuntimeError::Protocol(error.to_protocol_error()))
    }
}

#[async_trait]
impl FrozenConnector for TwentyConnector {
    fn implementation_support(&self, capability: &Capability) -> CapabilityImplementationSupport {
        let operation = operation_from_capability(&capability.id)
            .filter(|operation| self.allowed_operations.contains(operation));
        ImplementationSupport {
            invocation: operation.is_some(),
            cancellation: false,
            streaming: false,
            retry: operation.is_some_and(TwentyOperation::retry_safe),
            transaction: false,
            reconciliation: false,
            compensation: false,
            approval: operation
                .is_some_and(|operation| operation.is_mutation() && !operation.is_policy_ingest()),
            credentials: false,
        }
    }

    async fn invoke_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        let operation = operation_from_capability(&action.capability_id).ok_or_else(|| {
            failure(
                TwentyConnectorError::OperationNotAllowed(action.capability_id.to_string()),
                TwentyOperation::RecordGet,
            )
        })?;
        tokio::select! {
            result = self.invoke_operation(operation, action, Some(&context)) => {
                result.map_err(|error| failure(error, operation))
            }
            () = context.cancellation.cancelled() => Err(ConnectorFailure {
                code: "connector.twenty.cancelled".to_owned(),
                message: "Twenty invocation was cancelled before completion".to_owned(),
                category: ErrorCategory::Temporary,
                retryable: false,
                retry_after_ms: None,
                provider_request_id: None,
                provider_operation: None,
                remote_status: None,
                uncertain_outcome: operation.is_mutation(),
                redacted_details: None,
                source_component: CONNECTOR_ID.to_owned(),
                operation: ConnectorOperation::Invocation,
            }),
        }
    }
}

/// Connector configuration, validation, transport, or provider error.
#[derive(Debug, Error)]
pub enum TwentyConnectorError {
    /// Connector configuration is invalid.
    #[error("invalid Twenty connector configuration: {0}")]
    InvalidConfiguration(String),
    /// Provider base URL is invalid.
    #[error("invalid Twenty URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    /// Action input is invalid.
    #[error("invalid Twenty action input: {0}")]
    InvalidInput(String),
    /// Operation is not admitted by deployment policy.
    #[error("Twenty operation `{0}` is not enabled")]
    OperationNotAllowed(String),
    /// A required mutation idempotency key is absent.
    #[error("Twenty mutation requires Action.idempotency_key")]
    MissingIdempotencyKey,
    /// Configured credential is invalid.
    #[error("configured Twenty credential is invalid")]
    InvalidCredential,
    /// HTTP request failed.
    #[error("Twenty request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// Provider returned a non-success status.
    #[error("Twenty returned HTTP {status}")]
    Status {
        /// HTTP status.
        status: u16,
        /// Redaction-safe provider request id.
        request_id: Option<String>,
        /// Provider retry delay.
        retry_after_ms: Option<u64>,
        /// Bounded allowlisted provider error fields.
        details: Option<Value>,
    },
    /// Provider response exceeded the configured memory bound.
    #[error("Twenty response exceeded the configured {limit}-byte bound")]
    ResponseTooLarge {
        /// Active response size limit.
        limit: usize,
    },
    /// Provider returned a response outside the Twenty JSON contract.
    #[error("Twenty returned an invalid response: {0}")]
    InvalidResponse(String),
    /// Webhook HMAC verification is not configured.
    #[error("Twenty webhook verification is not configured")]
    WebhookNotConfigured,
    /// Webhook delivery is invalid.
    #[error("invalid Twenty webhook: {0}")]
    InvalidWebhook(String),
    /// Durable replay fencing failed.
    #[error("Twenty webhook replay store failed: {0}")]
    ReplayStore(String),
}

fn validate_base_url(value: &str, allow_insecure_http: bool) -> Result<Url, TwentyConnectorError> {
    let url = Url::parse(value)?;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(TwentyConnectorError::InvalidConfiguration(
            "base URL must be an origin without credentials, path, query, or fragment".to_owned(),
        ));
    }
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && (loopback || allow_insecure_http)) {
        return Err(TwentyConnectorError::InvalidConfiguration(
            "HTTPS is required unless private-network HTTP is explicitly enabled".to_owned(),
        ));
    }
    if url.host_str().is_none() {
        return Err(TwentyConnectorError::InvalidConfiguration(
            "base URL must include a host".to_owned(),
        ));
    }
    Ok(url)
}

fn validate_secret(secret: &ConnectorSecret, name: &str) -> Result<(), TwentyConnectorError> {
    let bytes = secret.expose_bytes();
    if bytes.is_empty() || bytes.len() > 16 * 1024 || bytes.contains(&0) {
        return Err(TwentyConnectorError::InvalidConfiguration(format!(
            "{name} must contain 1..=16384 bytes without NUL"
        )));
    }
    Ok(())
}

fn validate_bearer_secret(secret: &ConnectorSecret) -> Result<(), TwentyConnectorError> {
    validate_secret(secret, "API token")?;
    let value = secret.expose_str().map_err(|_| {
        TwentyConnectorError::InvalidConfiguration("API token must be UTF-8".to_owned())
    })?;
    if value
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte == 0x7f)
    {
        return Err(TwentyConnectorError::InvalidConfiguration(
            "API token must not contain whitespace or DEL".to_owned(),
        ));
    }
    Ok(())
}

fn validate_hex(name: &str, value: &str, length: usize) -> Result<(), TwentyConnectorError> {
    if value.len() != length || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(TwentyConnectorError::InvalidWebhook(format!(
            "{name} must contain exactly {length} hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_event_name(value: &str) -> Result<(), TwentyConnectorError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(TwentyConnectorError::InvalidWebhook(
            "eventName must contain 1..=256 ASCII identifier characters".to_owned(),
        ));
    }
    Ok(())
}

fn is_twenty_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok()
        && value.len() == 36
        && matches!(value.as_bytes().get(14), Some(b'1'..=b'5'))
        && matches!(
            value.as_bytes().get(19).map(u8::to_ascii_lowercase),
            Some(b'8' | b'9' | b'a' | b'b')
        )
}

fn validate_uuid(name: &str, value: &str) -> Result<(), TwentyConnectorError> {
    if is_twenty_uuid(value) {
        Ok(())
    } else {
        Err(invalid_input(format!(
            "{name} must be an RFC 4122 UUID version 1 through 5 accepted by Twenty"
        )))
    }
}

fn invalid_input(message: impl Into<String>) -> TwentyConnectorError {
    TwentyConnectorError::InvalidInput(message.into())
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, TwentyConnectorError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TwentyConnectorError::InvalidWebhook(format!("missing `{key}`")))
}

fn input_map(input: &Value) -> Result<&Map<String, Value>, TwentyConnectorError> {
    input
        .as_object()
        .ok_or_else(|| invalid_input("input must be a JSON object"))
}

fn valid_twenty_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_alphanumeric() || (index > 0 && byte == b'_'))
}

fn validate_ingest_policy(
    policy: &TwentyIdempotentIngestPolicy,
) -> Result<(), TwentyConnectorError> {
    if policy.version != IDEMPOTENT_INGEST_POLICY_VERSION {
        return Err(TwentyConnectorError::InvalidConfiguration(format!(
            "idempotent ingest policy version must be `{IDEMPOTENT_INGEST_POLICY_VERSION}`"
        )));
    }
    if policy.objects.is_empty() || policy.objects.len() > MAX_INGEST_POLICY_OBJECTS {
        return Err(TwentyConnectorError::InvalidConfiguration(format!(
            "idempotent ingest policy must contain 1..={MAX_INGEST_POLICY_OBJECTS} objects"
        )));
    }
    for (object, object_policy) in &policy.objects {
        if !valid_twenty_identifier(object) {
            return Err(TwentyConnectorError::InvalidConfiguration(format!(
                "idempotent ingest object `{object}` must match ^[A-Za-z][A-Za-z0-9_]{{0,127}}$"
            )));
        }
        if object_policy.fields.is_empty() || object_policy.fields.len() > MAX_INGEST_POLICY_FIELDS
        {
            return Err(TwentyConnectorError::InvalidConfiguration(format!(
                "idempotent ingest object `{object}` must allow 1..={MAX_INGEST_POLICY_FIELDS} fields"
            )));
        }
        if !(1..=200).contains(&object_policy.max_batch_records) {
            return Err(TwentyConnectorError::InvalidConfiguration(format!(
                "idempotent ingest object `{object}` maxBatchRecords must be between 1 and 200"
            )));
        }
        if let Some(field) = object_policy
            .fields
            .iter()
            .find(|field| !valid_twenty_identifier(field))
        {
            return Err(TwentyConnectorError::InvalidConfiguration(format!(
                "idempotent ingest field `{object}.{field}` must match ^[A-Za-z][A-Za-z0-9_]{{0,127}}$"
            )));
        }
    }
    Ok(())
}

fn ingest_policy_digest(
    policy: &TwentyIdempotentIngestPolicy,
) -> Result<String, TwentyConnectorError> {
    let encoded = serde_json::to_vec(policy).map_err(|error| {
        TwentyConnectorError::InvalidConfiguration(format!(
            "idempotent ingest policy cannot be canonicalized: {error}"
        ))
    })?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn validate_ingest_record(
    object: &str,
    object_policy: &TwentyIngestObjectPolicy,
    record: &Value,
) -> Result<(), TwentyConnectorError> {
    let record = record.as_object().ok_or_else(|| {
        invalid_input(format!(
            "idempotent ingest body for `{object}` must contain JSON objects"
        ))
    })?;
    if let Some(field) = record
        .keys()
        .find(|field| !object_policy.fields.contains(*field))
    {
        return Err(invalid_input(format!(
            "idempotent ingest policy does not allow field `{object}.{field}`"
        )));
    }
    Ok(())
}

fn validate_idempotent_ingest_action(
    policy: &TwentyIdempotentIngestPolicy,
    operation: TwentyOperation,
    input: &Value,
) -> Result<(), TwentyConnectorError> {
    if !matches!(
        operation,
        TwentyOperation::RecordIngest | TwentyOperation::RecordIngestMany
    ) {
        return Ok(());
    }
    let object = input_object_name(input)?;
    let object_policy = policy.objects.get(&object).ok_or_else(|| {
        invalid_input(format!(
            "idempotent ingest policy does not allow object `{object}`"
        ))
    })?;
    let body = input_map(input)?
        .get("body")
        .ok_or_else(|| invalid_input("body is required"))?;
    match operation {
        TwentyOperation::RecordIngest => validate_ingest_record(&object, object_policy, body),
        TwentyOperation::RecordIngestMany => {
            let records = body
                .as_array()
                .ok_or_else(|| invalid_input("idempotent ingest body must be an array"))?;
            if records.is_empty() || records.len() > object_policy.max_batch_records {
                return Err(invalid_input(format!(
                    "idempotent ingest object `{object}` accepts 1..={} records per batch",
                    object_policy.max_batch_records
                )));
            }
            for record in records {
                validate_ingest_record(&object, object_policy, record)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn input_object_name(input: &Value) -> Result<String, TwentyConnectorError> {
    let value = input_map(input)?
        .get("object")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("object must be a string"))?;
    if !valid_twenty_identifier(value) {
        return Err(invalid_input(
            "object must match ^[A-Za-z][A-Za-z0-9_]{0,127}$",
        ));
    }
    Ok(value.to_owned())
}

fn input_uuid(input: &Value, key: &str) -> Result<String, TwentyConnectorError> {
    let value = input_map(input)?
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input(format!("{key} must be a UUID string")))?;
    validate_uuid(key, value)?;
    Ok(value.to_owned())
}

fn input_metadata_resource(input: &Value) -> Result<String, TwentyConnectorError> {
    let value = input_map(input)?
        .get("resource")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("resource must be a string"))?;
    if !METADATA_RESOURCES.contains(&value) {
        return Err(invalid_input(format!(
            "unsupported metadata resource `{value}`"
        )));
    }
    Ok(value.to_owned())
}

fn input_body(input: &Value, require_object: bool) -> Result<Value, TwentyConnectorError> {
    let body = input_map(input)?
        .get("body")
        .cloned()
        .ok_or_else(|| invalid_input("body is required"))?;
    if require_object && !body.is_object() {
        return Err(invalid_input("body must be a JSON object"));
    }
    Ok(body)
}

fn input_find_duplicates_body(input: &Value) -> Result<Value, TwentyConnectorError> {
    let body = input_body(input, true)?;
    let object = body
        .as_object()
        .ok_or_else(|| invalid_input("find-duplicates body must be a JSON object"))?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "data" | "ids"))
    {
        return Err(invalid_input(
            "find-duplicates body accepts only `data` or `ids`",
        ));
    }
    match (object.get("data"), object.get("ids")) {
        (Some(_), Some(_)) => Err(invalid_input(
            "find-duplicates body must not contain both `data` and `ids`",
        )),
        (None, None) => Err(invalid_input(
            "find-duplicates body requires either `data` or `ids`",
        )),
        (Some(Value::Array(records)), None) if (1..=200).contains(&records.len()) => {
            if records.iter().any(|record| !record.is_object()) {
                return Err(invalid_input(
                    "find-duplicates `data` must contain JSON objects",
                ));
            }
            Ok(body)
        }
        (Some(_), None) => Err(invalid_input(
            "find-duplicates `data` must contain 1..=200 objects",
        )),
        (None, Some(Value::Array(ids))) if (1..=200).contains(&ids.len()) => {
            for id in ids {
                let id = id.as_str().ok_or_else(|| {
                    invalid_input("find-duplicates `ids` must contain UUID strings")
                })?;
                validate_uuid("find-duplicates id", id)?;
            }
            Ok(body)
        }
        (None, Some(_)) => Err(invalid_input(
            "find-duplicates `ids` must contain 1..=200 UUID strings",
        )),
    }
}

fn input_merge_body(input: &Value) -> Result<Value, TwentyConnectorError> {
    let body = input_body(input, true)?;
    let object = body
        .as_object()
        .ok_or_else(|| invalid_input("merge body must be a JSON object"))?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "ids" | "conflictPriorityIndex" | "dryRun"))
    {
        return Err(invalid_input(
            "merge body accepts only `ids`, `conflictPriorityIndex`, and `dryRun`",
        ));
    }
    let ids = object
        .get("ids")
        .and_then(Value::as_array)
        .filter(|ids| (2..=9).contains(&ids.len()))
        .ok_or_else(|| invalid_input("merge `ids` must contain 2..=9 UUID strings"))?;
    let mut unique = BTreeSet::new();
    for id in ids {
        let id = id
            .as_str()
            .ok_or_else(|| invalid_input("merge `ids` must contain UUID strings"))?;
        validate_uuid("merge id", id)?;
        if !unique.insert(id) {
            return Err(invalid_input("merge `ids` must be unique"));
        }
    }
    let priority = object
        .get("conflictPriorityIndex")
        .and_then(Value::as_u64)
        .filter(|priority| (*priority as usize) < ids.len())
        .ok_or_else(|| invalid_input("merge conflictPriorityIndex is out of range"))?;
    let _ = priority;
    if object
        .get("dryRun")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(invalid_input("merge dryRun must be a boolean"));
    }
    Ok(body)
}

fn required_idempotency_key(action: &Action) -> Result<&str, TwentyConnectorError> {
    let key = action
        .idempotency_key
        .as_deref()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 1_024
                && value.bytes().all(|byte| byte.is_ascii_graphic())
        })
        .ok_or(TwentyConnectorError::MissingIdempotencyKey)?;
    Ok(key)
}

fn deterministic_record_uuid(workspace: &str, key: &str, index: usize) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("aip:twenty:{workspace}:{key}:{index}").as_bytes(),
    )
}

fn inject_record_id(
    value: Value,
    workspace: &str,
    key: &str,
    index: usize,
) -> Result<Value, TwentyConnectorError> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_input("each record body must be an object"))?;
    if let Some(existing) = object.get("id") {
        let existing = existing
            .as_str()
            .ok_or_else(|| invalid_input("record id must be a UUID string"))?;
        validate_uuid("record id", existing)?;
    } else {
        object.insert(
            "id".to_owned(),
            Value::String(deterministic_record_uuid(workspace, key, index).to_string()),
        );
    }
    Ok(Value::Object(object))
}

fn append_query(
    url: &mut Url,
    query: Option<&Value>,
    allowed: &[&str],
) -> Result<(), TwentyConnectorError> {
    let Some(query) = query else {
        return Ok(());
    };
    let query = query
        .as_object()
        .ok_or_else(|| invalid_input("query must be a JSON object"))?;
    if query.len() > 64 {
        return Err(invalid_input("query contains too many entries"));
    }
    let mut pairs = url.query_pairs_mut();
    for (key, value) in query {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid_input(format!(
                "unsupported query parameter `{key}`"
            )));
        }
        let encoded = match value {
            Value::String(value) => value.clone(),
            Value::Bool(value) => value.to_string(),
            Value::Number(value) => value.to_string(),
            Value::Array(_) | Value::Object(_) => serde_json::to_string(value)
                .map_err(|error| invalid_input(format!("invalid query value: {error}")))?,
            Value::Null => return Err(invalid_input(format!("query `{key}` must not be null"))),
        };
        if encoded.len() > 32 * 1024 || encoded.chars().any(|character| character == '\0') {
            return Err(invalid_input(format!(
                "query `{key}` is too large or invalid"
            )));
        }
        pairs.append_pair(key, &encoded);
    }
    drop(pairs);
    if url.as_str().len() > 128 * 1024 {
        return Err(invalid_input("encoded request URL is too large"));
    }
    Ok(())
}

fn replace_query(url: &mut Url, key: &str, value: &str) {
    let existing = url
        .query_pairs()
        .filter(|(candidate, _)| candidate != key)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    url.set_query(None);
    let mut pairs = url.query_pairs_mut();
    for (key, value) in existing {
        pairs.append_pair(&key, &value);
    }
    pairs.append_pair(key, value);
}

fn require_bulk_filter(url: &Url) -> Result<(), TwentyConnectorError> {
    let valid = url
        .query_pairs()
        .find(|(key, _)| key == "filter")
        .is_some_and(|(_, value)| !value.trim().is_empty() && value != "{}" && value != "null");
    if !valid {
        return Err(invalid_input(
            "bulk mutation requires a non-empty Twenty `filter` query",
        ));
    }
    Ok(())
}

fn metadata_list_query_keys(resource: &str) -> &'static [&'static str] {
    match resource {
        "objects" | "fields" => &["limit", "starting_after", "ending_before"],
        "views" => &["objectMetadataId"],
        "viewFields" | "viewFilters" | "viewGroups" | "viewSorts" | "viewFilterGroups" => {
            &["viewId"]
        }
        "pageLayouts" => &["objectMetadataId", "pageLayoutType"],
        "pageLayoutTabs" => &["pageLayoutId"],
        "pageLayoutWidgets" => &["pageLayoutTabId"],
        "webhooks" => &[],
        _ => &[],
    }
}

fn record_query_keys(operation: TwentyOperation) -> &'static [&'static str] {
    match operation {
        TwentyOperation::RecordList => &[
            "limit",
            "order_by",
            "depth",
            "filter",
            "starting_after",
            "ending_before",
        ],
        TwentyOperation::RecordGet
        | TwentyOperation::RecordFindDuplicates
        | TwentyOperation::RecordCreate
        | TwentyOperation::RecordCreateMany
        | TwentyOperation::RecordIngest
        | TwentyOperation::RecordIngestMany
        | TwentyOperation::RecordUpdate
        | TwentyOperation::RecordRestore
        | TwentyOperation::RecordMerge => &["depth"],
        TwentyOperation::RecordGroupBy => &[
            "limit",
            "order_by",
            "filter",
            "group_by",
            "include_records_sample",
            "order_by_for_records",
            "aggregate",
            "viewId",
        ],
        TwentyOperation::RecordUpdateMany | TwentyOperation::RecordRestoreMany => {
            &["filter", "depth"]
        }
        TwentyOperation::RecordSoftDeleteMany | TwentyOperation::RecordDestroyMany => &["filter"],
        TwentyOperation::RecordSoftDelete | TwentyOperation::RecordDestroy => &[],
        _ => &[],
    }
}

fn validate_metadata_list_query(resource: &str, url: &Url) -> Result<(), TwentyConnectorError> {
    let value = |key: &str| {
        url.query_pairs()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value.into_owned())
    };
    let uuid = |key: &str, required: bool| -> Result<(), TwentyConnectorError> {
        match value(key) {
            Some(value) => validate_uuid(key, &value),
            None if required => Err(invalid_input(format!(
                "metadata resource `{resource}` requires query `{key}`"
            ))),
            None => Ok(()),
        }
    };
    match resource {
        "objects" | "fields" => {
            uuid("starting_after", false)?;
            uuid("ending_before", false)?;
        }
        "views" => uuid("objectMetadataId", false)?,
        "viewFields" | "viewFilters" | "viewGroups" | "viewSorts" | "viewFilterGroups" => {
            uuid("viewId", false)?
        }
        "pageLayouts" => {
            uuid("objectMetadataId", false)?;
            if let Some(layout_type) = value("pageLayoutType") {
                if value("objectMetadataId").is_none() {
                    return Err(invalid_input(
                        "pageLayoutType requires objectMetadataId because Twenty otherwise ignores it",
                    ));
                }
                if !matches!(
                    layout_type.as_str(),
                    "RECORD_INDEX" | "RECORD_PAGE" | "DASHBOARD" | "STANDALONE_PAGE"
                ) {
                    return Err(invalid_input(
                        "pageLayoutType is not a Twenty PageLayoutType",
                    ));
                }
            }
        }
        "pageLayoutTabs" => uuid("pageLayoutId", true)?,
        "pageLayoutWidgets" => uuid("pageLayoutTabId", true)?,
        _ => {}
    }
    Ok(())
}

fn ensure_request_size(body: &Value) -> Result<(), TwentyConnectorError> {
    let size = serde_json::to_vec(body)
        .map_err(|error| invalid_input(format!("body is not JSON serializable: {error}")))?
        .len();
    if size > MAX_REQUEST_BYTES {
        return Err(invalid_input(format!(
            "body exceeds the {MAX_REQUEST_BYTES}-byte request limit"
        )));
    }
    Ok(())
}

async fn response_body(
    response: Response,
    max_response_bytes: usize,
) -> Result<Value, TwentyConnectorError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        return Err(TwentyConnectorError::ResponseTooLarge {
            limit: max_response_bytes,
        });
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len().saturating_add(chunk.len()) > max_response_bytes {
            return Err(TwentyConnectorError::ResponseTooLarge {
                limit: max_response_bytes,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| TwentyConnectorError::InvalidResponse(error.to_string()))
}

fn provider_request_id(response: &Response) -> Option<String> {
    response
        .headers()
        .get("x-request-id")
        .or_else(|| response.headers().get("traceparent"))
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 512 && !value.chars().any(char::is_control))
        .map(ToOwned::to_owned)
}

fn provider_error_details(body: &Value) -> Option<Value> {
    let object = body.as_object()?;
    let mut details = Map::new();
    for key in ["statusCode", "error", "message", "messages", "code"] {
        let Some(value) = object.get(key) else {
            continue;
        };
        let safe = match value {
            Value::String(value) => Some(Value::String(bounded_error_text(value))),
            Value::Number(_) | Value::Bool(_) => Some(value.clone()),
            Value::Array(values) => Some(Value::Array(
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .take(16)
                    .map(|value| Value::String(bounded_error_text(value)))
                    .collect(),
            )),
            _ => None,
        };
        if let Some(safe) = safe {
            details.insert(key.to_owned(), safe);
        }
    }
    (!details.is_empty()).then_some(Value::Object(details))
}

fn redact_provider_response(operation: TwentyOperation, input: &Value, mut body: Value) -> Value {
    if operation.suffix().starts_with("metadata.")
        && input.get("resource").and_then(Value::as_str) == Some("webhooks")
    {
        remove_json_key(&mut body, "secret");
    }
    body
}

fn remove_json_key(value: &mut Value, key: &str) {
    match value {
        Value::Object(object) => {
            object.remove(key);
            for value in object.values_mut() {
                remove_json_key(value, key);
            }
        }
        Value::Array(values) => {
            for value in values {
                remove_json_key(value, key);
            }
        }
        _ => {}
    }
}

fn bounded_error_text(value: &str) -> String {
    value
        .chars()
        .take(2_048)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn retry_after_millis(response: &Response) -> Option<u64> {
    response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1_000))
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

fn operation_from_capability(id: &CapabilityId) -> Option<TwentyOperation> {
    id.as_str()
        .strip_prefix("cap:twenty:")
        .and_then(TwentyOperation::from_suffix)
}

#[cfg(test)]
fn capability(operation: TwentyOperation) -> Capability {
    capability_for_policy(operation, None)
}

fn capability_for_policy(
    operation: TwentyOperation,
    _ingest_policy: Option<&TwentyIdempotentIngestPolicy>,
) -> Capability {
    let mutation = operation.is_mutation();
    // A capability contract is catalog-global and immutable for one ID. A
    // deployment-owned field allowlist therefore must not rewrite its schema,
    // risk, or approval requirements. Dedicated ingest IDs keep that contract
    // stable while runtime policy narrows each instance's writable boundary.
    let unattended_ingest = operation.is_policy_ingest();
    let method = match operation {
        TwentyOperation::RecordList
        | TwentyOperation::RecordGet
        | TwentyOperation::RecordGroupBy
        | TwentyOperation::MetadataList
        | TwentyOperation::MetadataGet
        | TwentyOperation::OpenApiCore
        | TwentyOperation::OpenApiMetadata => "GET",
        TwentyOperation::RecordFindDuplicates
        | TwentyOperation::RecordCreate
        | TwentyOperation::RecordCreateMany
        | TwentyOperation::RecordIngest
        | TwentyOperation::RecordIngestMany
        | TwentyOperation::MetadataCreate => "POST",
        TwentyOperation::RecordUpdate
        | TwentyOperation::RecordUpdateMany
        | TwentyOperation::RecordRestore
        | TwentyOperation::RecordRestoreMany
        | TwentyOperation::RecordMerge
        | TwentyOperation::MetadataUpdate => "PATCH",
        TwentyOperation::RecordSoftDelete
        | TwentyOperation::RecordSoftDeleteMany
        | TwentyOperation::RecordDestroy
        | TwentyOperation::RecordDestroyMany
        | TwentyOperation::MetadataDelete => "DELETE",
    };
    Capability {
        id: CapabilityId::trusted(format!("cap:twenty:{}", operation.suffix())),
        name: format!("Twenty: {}", operation.title()),
        kind: if matches!(
            operation,
            TwentyOperation::OpenApiCore | TwentyOperation::OpenApiMetadata
        ) {
            CapabilityKind::Resource
        } else {
            CapabilityKind::Tool
        },
        input_schema: input_schema(operation),
        output_schema: Some(json!({ "type": "object", "additionalProperties": true })),
        description: Some(format!(
            "{} through Twenty REST at upstream revision {}.",
            operation.title(),
            UPSTREAM_REVISION
        )),
        risk: Some(if operation.is_critical() {
            RiskLevel::Critical
        } else if mutation && !unattended_ingest {
            RiskLevel::High
        } else {
            if unattended_ingest {
                RiskLevel::Medium
            } else {
                RiskLevel::Low
            }
        }),
        stability: Some(Stability::Stable),
        cost: None,
        auth: None,
        bindings: vec![
            Binding {
                profile: ProfileId::from("aip.native.http.v1"),
                metadata: json!({
                    "method": "POST",
                    "message_type": "aip.core.v1.action"
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            },
            Binding {
                profile: ProfileId::from(PROFILE_ID),
                metadata: json!({
                    "provider_method": method,
                    "operation": operation.suffix(),
                    "upstream_revision": UPSTREAM_REVISION,
                    "auth": "bearer_header"
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            },
        ],
        requires_human_approval: Some(mutation && !unattended_ingest),
        contract: Some(capability_contract(operation, unattended_ingest)),
    }
}

fn query_schema(keys: &[&str]) -> Value {
    let uuid = json!({
        "type": "string",
        "pattern": "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89AaBb][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
    });
    let mut properties = Map::new();
    for key in keys {
        let schema = match *key {
            "limit" => json!({ "type": "integer", "minimum": 0, "maximum": 200 }),
            "depth" => json!({ "type": "integer", "enum": [0, 1] }),
            "include_records_sample" => json!({ "type": "boolean" }),
            "starting_after" | "ending_before" | "viewId" | "objectMetadataId" | "pageLayoutId"
            | "pageLayoutTabId" => uuid.clone(),
            "pageLayoutType" => json!({
                "type": "string",
                "enum": ["RECORD_INDEX", "RECORD_PAGE", "DASHBOARD", "STANDALONE_PAGE"]
            }),
            _ => json!({ "type": ["string", "array", "object"] }),
        };
        properties.insert((*key).to_owned(), schema);
    }
    json!({
        "type": "object",
        "maxProperties": keys.len(),
        "properties": properties,
        "additionalProperties": false
    })
}

fn input_schema(operation: TwentyOperation) -> Value {
    let object = json!({
        "type": "string",
        "pattern": "^[A-Za-z][A-Za-z0-9_]{0,127}$"
    });
    let id = json!({
        "type": "string",
        "format": "uuid",
        "pattern": "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89AaBb][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
    });
    let resource = json!({ "type": "string", "enum": METADATA_RESOURCES });
    let mut properties = Map::new();
    let mut required = Vec::<Value>::new();
    if operation.suffix().starts_with("record.") {
        properties.insert("object".to_owned(), object);
        required.push(Value::String("object".to_owned()));
    }
    if operation.suffix().starts_with("metadata.") {
        properties.insert("resource".to_owned(), resource);
        required.push(Value::String("resource".to_owned()));
    }
    if matches!(
        operation,
        TwentyOperation::RecordGet
            | TwentyOperation::RecordUpdate
            | TwentyOperation::RecordSoftDelete
            | TwentyOperation::RecordDestroy
            | TwentyOperation::RecordRestore
            | TwentyOperation::MetadataGet
            | TwentyOperation::MetadataUpdate
            | TwentyOperation::MetadataDelete
    ) {
        properties.insert("id".to_owned(), id.clone());
        required.push(Value::String("id".to_owned()));
    }
    if matches!(
        operation,
        TwentyOperation::RecordCreate
            | TwentyOperation::RecordIngest
            | TwentyOperation::RecordUpdate
            | TwentyOperation::RecordUpdateMany
            | TwentyOperation::MetadataCreate
            | TwentyOperation::MetadataUpdate
    ) {
        properties.insert(
            "body".to_owned(),
            json!({ "type": "object", "maxProperties": 2048, "additionalProperties": true }),
        );
        required.push(Value::String("body".to_owned()));
    } else if matches!(
        operation,
        TwentyOperation::RecordCreateMany | TwentyOperation::RecordIngestMany
    ) {
        properties.insert(
            "body".to_owned(),
            json!({
                "type": "array",
                "minItems": 1,
                "maxItems": 200,
                "items": { "type": "object", "maxProperties": 2048, "additionalProperties": true }
            }),
        );
        required.push(Value::String("body".to_owned()));
    } else if operation == TwentyOperation::RecordFindDuplicates {
        properties.insert(
            "body".to_owned(),
            json!({
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["data"],
                        "properties": {
                            "data": {
                                "type": "array", "minItems": 1, "maxItems": 200,
                                "items": { "type": "object" }
                            }
                        },
                        "additionalProperties": false
                    },
                    {
                        "type": "object",
                        "required": ["ids"],
                        "properties": {
                            "ids": {
                                "type": "array", "minItems": 1, "maxItems": 200,
                                "items": id.clone()
                            }
                        },
                        "additionalProperties": false
                    }
                ]
            }),
        );
        required.push(Value::String("body".to_owned()));
    } else if operation == TwentyOperation::RecordMerge {
        properties.insert(
            "body".to_owned(),
            json!({
                "type": "object",
                "required": ["ids", "conflictPriorityIndex"],
                "properties": {
                    "ids": {
                        "type": "array", "minItems": 2, "maxItems": 9,
                        "uniqueItems": true, "items": id.clone()
                    },
                    "conflictPriorityIndex": { "type": "integer", "minimum": 0, "maximum": 8 },
                    "dryRun": { "type": "boolean" }
                },
                "additionalProperties": false
            }),
        );
        required.push(Value::String("body".to_owned()));
    }
    if operation.suffix().starts_with("record.") && !record_query_keys(operation).is_empty() {
        properties.insert(
            "query".to_owned(),
            query_schema(record_query_keys(operation)),
        );
    } else if operation == TwentyOperation::MetadataList {
        properties.insert(
            "query".to_owned(),
            query_schema(&[
                "limit",
                "starting_after",
                "ending_before",
                "objectMetadataId",
                "viewId",
                "pageLayoutType",
                "pageLayoutId",
                "pageLayoutTabId",
            ]),
        );
    }
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": false
    });
    if operation == TwentyOperation::MetadataList {
        schema["allOf"] = json!([
            {
                "if": { "properties": { "resource": { "const": "pageLayoutTabs" } } },
                "then": {
                    "required": ["query"],
                    "properties": { "query": { "required": ["pageLayoutId"] } }
                }
            },
            {
                "if": { "properties": { "resource": { "const": "pageLayoutWidgets" } } },
                "then": {
                    "required": ["query"],
                    "properties": { "query": { "required": ["pageLayoutTabId"] } }
                }
            }
        ]);
    }
    schema
}

fn capability_contract(operation: TwentyOperation, unattended_ingest: bool) -> CapabilityContract {
    let mutation = operation.is_mutation();
    let mut side_effects = vec![SideEffect::ExternalNetwork];
    side_effects.push(if operation.is_delete() {
        SideEffect::Delete
    } else if mutation {
        SideEffect::Write
    } else {
        SideEffect::Read
    });
    CapabilityContract {
        side_effects,
        idempotency: IdempotencyContract {
            requirement: if mutation {
                IdempotencyRequirement::Required
            } else {
                IdempotencyRequirement::Optional
            },
            collision_behavior: IdempotencyCollisionBehavior::RevalidateInputHash,
            key_scope: IdempotencyKeyScope::ExternalAccount,
            ttl_ms: Some(7 * 86_400_000),
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: false,
            supports_streaming: false,
            supports_cancel: false,
            supports_retry: operation.retry_safe(),
            expected_completion: ExpectedCompletionMode::Sync,
            retry_safety: if operation.retry_safe() {
                if mutation {
                    RetrySafety::SafeWithIdempotencyKey
                } else {
                    RetrySafety::Safe
                }
            } else {
                RetrySafety::Unsafe
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
        approval: (mutation && !unattended_ingest).then(|| ApprovalPolicy {
            required: true,
            reason: Some(
                "Twenty mutations change CRM records, schema, layouts, or webhook delivery policy."
                    .to_owned(),
            ),
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
            expected_latency_ms: Some(2_000),
            timeout_ms: Some(120_000),
            async_expected: false,
            max_queue_delay_ms: Some(10_000),
            availability_target: Some("99.9%".to_owned()),
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

fn manifest(
    namespace: &str,
    operations: &BTreeSet<TwentyOperation>,
    max_response_bytes: usize,
    webhook_ingress_enabled: bool,
    ingest_policy: Option<&TwentyIdempotentIngestPolicy>,
) -> Result<Manifest, TwentyConnectorError> {
    if operations
        .iter()
        .any(|operation| operation.is_policy_ingest())
        && ingest_policy.is_none()
    {
        return Err(TwentyConnectorError::InvalidConfiguration(
            "record.ingest capabilities require an idempotent-ingest policy".to_owned(),
        ));
    }
    let mut profiles = vec![
        ProfileId::from("aip.native.http.v1"),
        ProfileId::from(PROFILE_ID),
    ];
    let channels = if webhook_ingress_enabled {
        profiles.push(ProfileId::from(aip_profile_webhook::PROFILE_ID));
        vec![json!({
            "id": "twenty-webhooks",
            "name": "Twenty signed workspace events",
            "system": "twenty",
            "workspace_scope": namespace,
            "kind": "signed_record_events",
            "signature": "hmac-sha256(timestamp:raw-body)"
        })]
    } else {
        Vec::new()
    };
    let ingest_policy_governance = ingest_policy
        .map(|policy| {
            Ok::<Value, TwentyConnectorError>(json!({
                "version": policy.version,
                "sha256": ingest_policy_digest(policy)?,
                "objects": policy.objects.keys().collect::<Vec<_>>(),
                "operations": ["record.ingest", "record.ingest_many"]
            }))
        })
        .transpose()?;
    Ok(Manifest {
        manifest_version: "aip-manifest/v1".to_owned(),
        agent: Principal::new(
            PrincipalId::parse(format!("agent:twenty:{namespace}")).map_err(|error| {
                TwentyConnectorError::InvalidConfiguration(format!(
                    "workspace namespace is not a valid AIP principal component: {error}"
                ))
            })?,
            PrincipalKind::Agent,
        ),
        capabilities: operations
            .iter()
            .copied()
            .map(|operation| capability_for_policy(operation, ingest_policy))
            .collect(),
        profiles,
        resources: Vec::new(),
        channels,
        security: Some(json!({
            "api_auth": "bearer_header",
            "credential_material_in_protocol": false,
            "provider_redirects": false,
            "webhook_hmac": "sha256_hex_timestamp_colon_exact_raw_body",
            "webhook_ingress_enabled": webhook_ingress_enabled,
            "webhook_replay_fence": "durable_authenticated_delivery_fingerprint_compare_and_swap",
            "webhook_event_deduplication": "workspace_webhook_and_exact_payload_digest",
            "webhook_nonce_trust": "validated_but_not_used_as_authenticated_identity",
            "metadata_webhook_secrets": "host_injected_and_result_redacted"
        })),
        governance: Some(json!({
            "mutation_approval_policy": if ingest_policy.is_some() {
                "required_except_field_scoped_idempotent_ingest"
            } else {
                "required_for_all_mutations"
            },
            "mutations_require_idempotency": true,
            "idempotent_ingest_policy": ingest_policy_governance,
            "automatic_reconciliation": false,
            "uncertain_mutation_disposition": "operator_reconciliation_required",
            "arbitrary_provider_paths": false,
            "arbitrary_graphql": false,
            "intentionally_excluded_surfaces": INTENTIONALLY_EXCLUDED_SURFACES
        })),
        limits: Some(json!({
            "provider_request_max_bytes": MAX_REQUEST_BYTES,
            "provider_response_max_bytes": max_response_bytes,
            "webhook_max_body_bytes": MAX_WEBHOOK_BODY_BYTES,
            "webhook_replay_capacity": WEBHOOK_REPLAY_CAPACITY,
            "webhook_max_clock_skew_ms": WEBHOOK_MAX_SKEW_MILLIS,
            "bulk_operation_max_records": 200
        })),
        compatibility: Some(json!({
            "system": "twenty",
            "connector": CONNECTOR_ID,
            "upstream_revision": UPSTREAM_REVISION,
            "catalog_operations_supported": ALL_TWENTY_OPERATIONS.len(),
            "catalog_operations_admitted": operations.len(),
            "record_surface": "standard_and_custom_objects",
            "metadata_resources": METADATA_RESOURCES,
            "webhook_signature": "hmac-sha256(timestamp:raw-body)"
        })),
        extensions: None,
    })
}

fn failure(error: TwentyConnectorError, operation: TwentyOperation) -> ConnectorFailure {
    let (code, category, retryable, retry_after_ms, request_id, remote_status, uncertain) =
        match &error {
            TwentyConnectorError::Status {
                status,
                request_id,
                retry_after_ms,
                ..
            } if matches!(*status, 401 | 403) => (
                "connector.twenty.authentication",
                ErrorCategory::Auth,
                false,
                *retry_after_ms,
                request_id.clone(),
                Some(*status),
                false,
            ),
            TwentyConnectorError::Status {
                status,
                request_id,
                retry_after_ms,
                ..
            } if *status == 429 || *status >= 500 => (
                "connector.twenty.remote_temporary",
                ErrorCategory::Temporary,
                operation.retry_safe(),
                *retry_after_ms,
                request_id.clone(),
                Some(*status),
                operation.is_mutation(),
            ),
            TwentyConnectorError::Status {
                status,
                request_id,
                retry_after_ms,
                ..
            } => (
                "connector.twenty.remote_rejected",
                ErrorCategory::Permanent,
                false,
                *retry_after_ms,
                request_id.clone(),
                Some(*status),
                false,
            ),
            TwentyConnectorError::Http(error) => (
                "connector.twenty.transport",
                ErrorCategory::Temporary,
                operation.retry_safe() && (error.is_connect() || !operation.is_mutation()),
                None,
                None,
                error.status().map(|status| status.as_u16()),
                operation.is_mutation() && !error.is_connect(),
            ),
            TwentyConnectorError::InvalidCredential => (
                "connector.twenty.authentication",
                ErrorCategory::Auth,
                false,
                None,
                None,
                None,
                false,
            ),
            TwentyConnectorError::ReplayStore(_) => (
                "connector.twenty.storage",
                ErrorCategory::Temporary,
                true,
                None,
                None,
                None,
                false,
            ),
            TwentyConnectorError::ResponseTooLarge { .. }
            | TwentyConnectorError::InvalidResponse(_) => (
                "connector.twenty.invalid_response",
                ErrorCategory::Connector,
                false,
                None,
                None,
                None,
                operation.is_mutation(),
            ),
            _ => (
                "connector.twenty.invalid_request",
                ErrorCategory::Permanent,
                false,
                None,
                None,
                None,
                false,
            ),
        };
    let redacted_details = match &error {
        TwentyConnectorError::Status {
            details: Some(details),
            ..
        } => json!({
            "twenty_operation": operation.suffix(),
            "provider_error": details
        }),
        _ => json!({ "twenty_operation": operation.suffix() }),
    };
    ConnectorFailure {
        code: code.to_owned(),
        message: error.to_string(),
        category,
        retryable,
        retry_after_ms,
        provider_request_id: request_id,
        provider_operation: None,
        remote_status,
        uncertain_outcome: uncertain,
        redacted_details: Some(redacted_details),
        source_component: CONNECTOR_ID.to_owned(),
        operation: ConnectorOperation::Invocation,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use axum::{
        Json, Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode, Uri},
        response::{IntoResponse, Response as AxumResponse},
    };
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use tokio::{net::TcpListener, task::JoinHandle};

    const WORKSPACE_ID: &str = "b61e197a-0cb8-4035-acbc-3e9cf4fe8a0a";
    const RECORD_ID: &str = "11111111-1111-4111-8111-111111111111";

    fn connector() -> TwentyConnector {
        TwentyConnector::with_api_token(
            "http://127.0.0.1:3000",
            WORKSPACE_ID,
            ConnectorSecret::new("qualification-token"),
            false,
        )
        .expect("test connector")
    }

    fn ingest_policy() -> TwentyIdempotentIngestPolicy {
        TwentyIdempotentIngestPolicy {
            version: IDEMPOTENT_INGEST_POLICY_VERSION.to_owned(),
            objects: BTreeMap::from([
                (
                    "notes".to_owned(),
                    TwentyIngestObjectPolicy {
                        fields: BTreeSet::from([
                            "bodyV2".to_owned(),
                            "id".to_owned(),
                            "title".to_owned(),
                        ]),
                        max_batch_records: 50,
                    },
                ),
                (
                    "opportunities".to_owned(),
                    TwentyIngestObjectPolicy {
                        fields: BTreeSet::from(["id".to_owned(), "name".to_owned()]),
                        max_batch_records: 10,
                    },
                ),
            ]),
        }
    }

    fn action(operation: TwentyOperation, input: Value, idempotency_key: Option<&str>) -> Action {
        let mut action = Action::new(
            CapabilityId::trusted(format!("cap:twenty:{}", operation.suffix())),
            input,
        );
        action.idempotency_key = idempotency_key.map(ToOwned::to_owned);
        action
    }

    #[test]
    fn catalogue_is_complete_unique_and_governed() {
        assert_eq!(ALL_TWENTY_OPERATIONS.len(), 24);
        let mut suffixes = BTreeSet::new();
        let mut capability_ids = BTreeSet::new();
        for operation in ALL_TWENTY_OPERATIONS {
            assert!(suffixes.insert(operation.suffix()));
            assert_eq!(
                TwentyOperation::from_suffix(operation.suffix()),
                Some(operation)
            );
            let capability = capability(operation);
            assert!(capability_ids.insert(capability.id.to_string()));
            let contract = capability.contract.expect("capability contract");
            assert_eq!(
                contract.idempotency.requirement,
                if operation.is_mutation() {
                    IdempotencyRequirement::Required
                } else {
                    IdempotencyRequirement::Optional
                }
            );
            assert_eq!(
                contract
                    .approval
                    .as_ref()
                    .is_some_and(|approval| approval.required),
                operation.is_mutation() && !operation.is_policy_ingest()
            );
            assert_eq!(
                capability.requires_human_approval,
                Some(operation.is_mutation() && !operation.is_policy_ingest())
            );
        }
        assert_eq!(suffixes.len(), ALL_TWENTY_OPERATIONS.len());
        assert_eq!(capability_ids.len(), ALL_TWENTY_OPERATIONS.len());
        assert_eq!(TwentyOperation::from_suffix("graphql.proxy"), None);
        assert_eq!(INTENTIONALLY_EXCLUDED_SURFACES.len(), 6);
        assert!(
            INTENTIONALLY_EXCLUDED_SURFACES
                .iter()
                .all(|(surface, reason)| !surface.trim().is_empty() && !reason.trim().is_empty())
        );
    }

    #[test]
    fn idempotent_ingest_policy_is_narrow_visible_and_fail_closed() {
        let policy = ingest_policy();
        let connector = connector()
            .with_idempotent_ingest_policy(policy.clone())
            .expect("valid ingest policy");

        let create_without_policy = capability_for_policy(TwentyOperation::RecordCreate, None);
        let create = capability_for_policy(TwentyOperation::RecordCreate, Some(&policy));
        assert_eq!(create, create_without_policy);
        assert_eq!(create.risk, Some(RiskLevel::High));
        assert_eq!(create.requires_human_approval, Some(true));
        assert!(
            create
                .contract
                .as_ref()
                .and_then(|contract| contract.approval.as_ref())
                .is_some_and(|approval| approval.required)
        );
        let ingest_without_policy = capability_for_policy(TwentyOperation::RecordIngest, None);
        let ingest = capability_for_policy(TwentyOperation::RecordIngest, Some(&policy));
        assert_eq!(ingest, ingest_without_policy);
        assert_eq!(ingest.risk, Some(RiskLevel::Medium));
        assert_eq!(ingest.requires_human_approval, Some(false));
        assert!(
            ingest
                .contract
                .as_ref()
                .is_some_and(|contract| contract.approval.is_none())
        );
        assert!(
            ingest
                .input_schema
                .pointer("/properties/object/pattern")
                .is_some()
        );
        jsonschema::draft202012::new(&ingest.input_schema)
            .expect("stable ingest input schema must compile");

        let destroy = capability_for_policy(TwentyOperation::RecordDestroy, Some(&policy));
        assert_eq!(destroy.risk, Some(RiskLevel::Critical));
        assert_eq!(destroy.requires_human_approval, Some(true));
        assert!(
            destroy
                .contract
                .as_ref()
                .and_then(|contract| contract.approval.as_ref())
                .is_some_and(|approval| approval.required)
        );

        validate_idempotent_ingest_action(
            connector
                .idempotent_ingest_policy
                .as_ref()
                .expect("installed policy"),
            TwentyOperation::RecordIngest,
            &json!({
                "object": "opportunities",
                "body": { "id": RECORD_ID, "name": "WhatsApp conversation" }
            }),
        )
        .expect("allowlisted object and fields");
        let unexpected_field = validate_idempotent_ingest_action(
            &policy,
            TwentyOperation::RecordIngest,
            &json!({
                "object": "opportunities",
                "body": { "id": RECORD_ID, "name": "Allowed", "stage": "CUSTOMER" }
            }),
        )
        .expect_err("unlisted stage mutation must fail before provider I/O");
        assert!(unexpected_field.to_string().contains("opportunities.stage"));
        let unexpected_object = validate_idempotent_ingest_action(
            &policy,
            TwentyOperation::RecordIngest,
            &json!({ "object": "people", "body": { "id": RECORD_ID } }),
        )
        .expect_err("unlisted object must fail before provider I/O");
        assert!(unexpected_object.to_string().contains("object `people`"));
    }

    #[test]
    fn ingest_policy_rejects_unknown_versions_and_oversized_batches() {
        let mut policy = ingest_policy();
        policy.version = "aip.twenty.idempotent-ingest-policy/v0".to_owned();
        assert!(connector().with_idempotent_ingest_policy(policy).is_err());

        let policy = ingest_policy();
        let records = (0..51)
            .map(|index| json!({ "title": format!("message-{index}") }))
            .collect::<Vec<_>>();
        let error = validate_idempotent_ingest_action(
            &policy,
            TwentyOperation::RecordIngestMany,
            &json!({ "object": "notes", "body": records }),
        )
        .expect_err("per-object batch bound must be enforced");
        assert!(error.to_string().contains("1..=50"));
    }

    #[tokio::test]
    async fn webhook_channel_is_advertised_only_after_security_is_installed() {
        let outbound = connector()
            .discover(&ConnectorContext::default())
            .await
            .expect("outbound manifest");
        assert!(outbound.channels.is_empty());
        assert!(
            !outbound
                .profiles
                .iter()
                .any(|profile| profile.as_str() == aip_profile_webhook::PROFILE_ID)
        );

        let secured = connector()
            .with_webhook_security(
                ConnectorSecret::new("webhook-secret"),
                Arc::new(InMemoryTwentyWebhookReplayStore::default()),
            )
            .expect("webhook security");
        let inbound = secured
            .discover(&ConnectorContext::default())
            .await
            .expect("inbound manifest");
        assert_eq!(inbound.channels.len(), 1);
        assert!(
            inbound
                .profiles
                .iter()
                .any(|profile| profile.as_str() == aip_profile_webhook::PROFILE_ID)
        );
    }

    #[derive(Clone, Debug)]
    struct ObservedRequest {
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Value,
    }

    type ObservedRequests = StdArc<StdMutex<Vec<ObservedRequest>>>;

    async fn mock_twenty_provider(
        State(observed): State<ObservedRequests>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> AxumResponse {
        let body = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).expect("connector sends JSON")
        };
        observed
            .lock()
            .expect("observed request lock")
            .push(ObservedRequest {
                method: method.clone(),
                uri: uri.clone(),
                headers,
                body: body.clone(),
            });
        let response = match (method, uri.path()) {
            (Method::POST, "/rest/people") => json!({ "data": body }),
            (Method::GET, "/rest/metadata/objects") => {
                json!({ "data": [{ "id": RECORD_ID, "nameSingular": "person" }] })
            }
            (Method::GET | Method::HEAD, "/rest/open-api/core") => {
                json!({ "openapi": "3.0.0", "padding": "x".repeat(1024) })
            }
            _ => {
                return (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" })))
                    .into_response();
            }
        };
        (StatusCode::OK, Json(response)).into_response()
    }

    async fn spawn_mock_twenty_provider() -> (String, ObservedRequests, JoinHandle<()>) {
        let observed = StdArc::new(StdMutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind Twenty mock");
        let address = listener.local_addr().expect("Twenty mock address");
        let app = Router::new()
            .fallback(mock_twenty_provider)
            .with_state(observed.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve Twenty mock");
        });
        (format!("http://{address}"), observed, server)
    }

    #[tokio::test]
    async fn real_http_client_enforces_auth_idempotency_and_route_contracts() {
        let (base_url, observed, server) = spawn_mock_twenty_provider().await;
        let connector = TwentyConnector::with_api_token(
            base_url,
            WORKSPACE_ID,
            ConnectorSecret::new("qualification-token"),
            false,
        )
        .expect("HTTP test connector");

        let create = action(
            TwentyOperation::RecordCreate,
            json!({ "object": "people", "body": { "name": "Amira" } }),
            Some("tenant:case:http-create"),
        );
        let create_id = create.id.to_string();
        let result = connector
            .invoke(&ConnectorContext::default(), create)
            .await
            .expect("record create over HTTP");
        assert_eq!(result.status, ActionResultStatus::Completed);
        let created_id = result
            .output
            .as_ref()
            .and_then(|output| output.pointer("/body/data/id"))
            .and_then(Value::as_str)
            .expect("deterministic provider record id");
        assert!(is_twenty_uuid(created_id));

        let metadata = action(
            TwentyOperation::MetadataList,
            json!({ "resource": "objects", "query": { "limit": 10 } }),
            None,
        );
        connector
            .invoke(&ConnectorContext::default(), metadata)
            .await
            .expect("metadata list over HTTP");

        let requests = observed.lock().expect("observed requests");
        assert_eq!(requests.len(), 2);
        let create = &requests[0];
        assert_eq!(create.method, Method::POST);
        assert_eq!(create.uri.path(), "/rest/people");
        assert_eq!(create.uri.query(), Some("upsert=true"));
        assert_eq!(
            create
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer qualification-token")
        );
        assert_eq!(
            create
                .headers
                .get("idempotency-key")
                .and_then(|value| value.to_str().ok()),
            Some("tenant:case:http-create")
        );
        assert_eq!(
            create
                .headers
                .get("x-aip-action-id")
                .and_then(|value| value.to_str().ok()),
            Some(create_id.as_str())
        );
        assert_eq!(
            create.body.get("id").and_then(Value::as_str),
            Some(created_id)
        );

        let metadata = &requests[1];
        assert_eq!(metadata.method, Method::GET);
        assert_eq!(metadata.uri.path(), "/rest/metadata/objects");
        assert_eq!(metadata.uri.query(), Some("limit=10"));
        assert_eq!(metadata.body, Value::Null);
        assert!(!metadata.headers.contains_key("idempotency-key"));
        drop(requests);
        server.abort();
    }

    #[tokio::test]
    async fn health_probe_uses_an_authenticated_head_request() {
        let (base_url, observed, server) = spawn_mock_twenty_provider().await;
        let connector = TwentyConnector::with_api_token(
            base_url,
            WORKSPACE_ID,
            ConnectorSecret::new("qualification-token"),
            false,
        )
        .expect("HTTP test connector");

        let health = connector
            .health(&ConnectorContext::default())
            .await
            .expect("authenticated health probe");
        assert!(health.ready);

        let requests = observed.lock().expect("observed requests");
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, Method::HEAD);
        assert_eq!(request.uri.path(), "/rest/open-api/core");
        assert_eq!(request.body, Value::Null);
        assert_eq!(
            request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer qualification-token")
        );
        drop(requests);
        server.abort();
    }

    #[tokio::test]
    async fn provider_response_limit_is_enforced_on_the_actual_http_path() {
        let (base_url, _observed, server) = spawn_mock_twenty_provider().await;
        let connector = TwentyConnector::with_api_token(
            base_url,
            WORKSPACE_ID,
            ConnectorSecret::new("qualification-token"),
            false,
        )
        .expect("HTTP test connector")
        .with_max_response_bytes(64)
        .expect("small response limit");
        let error = connector
            .invoke(
                &ConnectorContext::default(),
                action(TwentyOperation::OpenApiCore, json!({}), None),
            )
            .await
            .expect_err("oversized provider response must fail");
        assert!(error.to_string().contains("response exceeded"));
        server.abort();
    }

    #[test]
    fn configuration_and_provider_identifiers_reject_unsafe_values() {
        assert!(validate_base_url("https://twenty.example", false).is_ok());
        assert!(validate_base_url("http://localhost:3000", false).is_ok());
        assert!(validate_base_url("http://10.0.0.8:3000", false).is_err());
        assert!(validate_base_url("http://10.0.0.8:3000", true).is_ok());
        for unsafe_origin in [
            "https://user:password@twenty.example",
            "https://twenty.example/rest",
            "https://twenty.example?token=value",
            "file:///etc/passwd",
        ] {
            assert!(validate_base_url(unsafe_origin, false).is_err());
        }
        for unsafe_object in ["../people", "people/1", "_private", "people-name", ""] {
            assert!(input_object_name(&json!({ "object": unsafe_object })).is_err());
        }
        assert!(input_object_name(&json!({ "object": "customObjects1" })).is_ok());
        assert!(
            TwentyConnector::with_api_token(
                "https://twenty.example",
                WORKSPACE_ID,
                ConnectorSecret::new("token\nheader-injection"),
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn record_create_is_deterministic_and_provider_upsert_is_forced() {
        let connector = connector();
        let input = json!({ "object": "people", "body": { "name": "Amira" } });
        let first_action = action(
            TwentyOperation::RecordCreate,
            input.clone(),
            Some("tenant:case:create"),
        );
        let first = connector
            .request_spec(
                TwentyOperation::RecordCreate,
                &first_action,
                first_action.idempotency_key.as_deref(),
            )
            .expect("first create request");
        let second_action = action(
            TwentyOperation::RecordCreate,
            input,
            Some("tenant:case:create"),
        );
        let second = connector
            .request_spec(
                TwentyOperation::RecordCreate,
                &second_action,
                second_action.idempotency_key.as_deref(),
            )
            .expect("second create request");

        assert_eq!(first.method, Method::POST);
        assert_eq!(first.url.path(), "/rest/people");
        assert_eq!(
            first
                .url
                .query_pairs()
                .find(|(key, _)| key == "upsert")
                .map(|(_, value)| value.into_owned()),
            Some("true".to_owned())
        );
        let first_id = first.body.as_ref().and_then(|body| body.get("id"));
        let second_id = second.body.as_ref().and_then(|body| body.get("id"));
        assert_eq!(first_id, second_id);
        assert!(first_id.and_then(Value::as_str).is_some_and(is_twenty_uuid));

        let explicit_action = action(
            TwentyOperation::RecordCreate,
            json!({
                "object": "people",
                "body": { "id": RECORD_ID, "name": "Amira" }
            }),
            Some("tenant:case:explicit"),
        );
        let explicit = connector
            .request_spec(
                TwentyOperation::RecordCreate,
                &explicit_action,
                explicit_action.idempotency_key.as_deref(),
            )
            .expect("explicit create request");
        assert_eq!(
            explicit.body.as_ref().and_then(|body| body.get("id")),
            Some(&json!(RECORD_ID))
        );
    }

    #[test]
    fn bulk_mutations_require_a_nonempty_filter_and_explicit_delete_mode() {
        let connector = connector();
        for filter in [None, Some(""), Some("{}"), Some("null")] {
            let mut query = Map::new();
            if let Some(filter) = filter {
                query.insert("filter".to_owned(), Value::String(filter.to_owned()));
            }
            let update = action(
                TwentyOperation::RecordUpdateMany,
                json!({
                    "object": "people",
                    "query": Value::Object(query),
                    "body": { "city": "Dubai" }
                }),
                Some("tenant:case:update-many"),
            );
            assert!(
                connector
                    .request_spec(
                        TwentyOperation::RecordUpdateMany,
                        &update,
                        update.idempotency_key.as_deref(),
                    )
                    .is_err()
            );
        }

        let destroy = action(
            TwentyOperation::RecordDestroyMany,
            json!({
                "object": "people",
                "query": { "filter": "city[eq]:Dubai" }
            }),
            Some("tenant:case:destroy-many"),
        );
        let request = connector
            .request_spec(
                TwentyOperation::RecordDestroyMany,
                &destroy,
                destroy.idempotency_key.as_deref(),
            )
            .expect("filtered destroy request");
        assert_eq!(request.method, Method::DELETE);
        assert_eq!(request.url.path(), "/rest/people");
        let query = request.url.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(
            query.get("filter").map(|value| value.as_ref()),
            Some("city[eq]:Dubai")
        );
        assert_eq!(
            query.get("soft_delete").map(|value| value.as_ref()),
            Some("false")
        );
    }

    #[test]
    fn webhook_metadata_secret_is_host_owned_and_recursively_redacted() {
        let connector = connector()
            .with_webhook_security(
                ConnectorSecret::new("host-owned-webhook-secret"),
                Arc::new(InMemoryTwentyWebhookReplayStore::default()),
            )
            .expect("webhook-secured connector");
        let supplied = connector.metadata_mutation_body(
            TwentyOperation::MetadataCreate,
            "webhooks",
            &json!({ "body": { "targetUrl": "https://example.test", "secret": "wire" } }),
        );
        assert!(matches!(
            supplied,
            Err(TwentyConnectorError::InvalidInput(_))
        ));

        let injected = connector
            .metadata_mutation_body(
                TwentyOperation::MetadataCreate,
                "webhooks",
                &json!({ "body": { "targetUrl": "https://example.test" } }),
            )
            .expect("host-injected webhook secret");
        assert_eq!(
            injected.get("secret"),
            Some(&json!("host-owned-webhook-secret"))
        );

        let redacted = redact_provider_response(
            TwentyOperation::MetadataGet,
            &json!({ "resource": "webhooks" }),
            json!({
                "data": {
                    "secret": "top-level",
                    "nested": [{ "secret": "nested", "id": RECORD_ID }]
                }
            }),
        );
        assert!(nested_json_key(&redacted, "secret").is_none());
        assert_eq!(
            redacted.pointer("/data/nested/0/id"),
            Some(&json!(RECORD_ID))
        );
    }

    #[tokio::test]
    async fn signed_webhook_replay_is_fenced_and_provider_retry_keeps_one_event_identity() {
        let webhook_secret = ConnectorSecret::new("webhook-signing-secret");
        let connector = connector()
            .with_webhook_security(
                ConnectorSecret::new("webhook-signing-secret"),
                Arc::new(InMemoryTwentyWebhookReplayStore::default()),
            )
            .expect("webhook-secured connector");
        let now = OffsetDateTime::now_utc();
        let timestamp_millis = now.unix_timestamp_nanos() / 1_000_000;
        let timestamp = timestamp_millis.to_string();
        let raw_body = serde_json::to_vec(&json!({
            "eventName": "record.created",
            "workspaceId": WORKSPACE_ID,
            "webhookId": RECORD_ID,
            "eventDate": now.format(&Rfc3339).expect("RFC3339 timestamp"),
            "record": { "id": RECORD_ID }
        }))
        .expect("webhook JSON");
        let delivery = |timestamp: String, nonce: String| {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(webhook_secret.expose_bytes()).expect("HMAC key");
            mac.update(timestamp.as_bytes());
            mac.update(b":");
            mac.update(&raw_body);
            TwentyWebhookDelivery {
                timestamp,
                signature: hex::encode(mac.finalize().into_bytes()),
                nonce,
                raw_body: raw_body.clone(),
            }
        };
        let first_delivery = delivery(timestamp, "ab".repeat(16));

        let event = connector
            .ingest_webhook_delivery(first_delivery.clone())
            .await
            .expect("first webhook delivery");
        assert_eq!(event.kind, "twenty.record.created");
        assert_eq!(
            event.data.as_ref().and_then(|data| data.get("workspaceId")),
            Some(&json!(WORKSPACE_ID))
        );
        let replay_with_changed_unsigned_nonce = TwentyWebhookDelivery {
            nonce: "cd".repeat(16),
            ..first_delivery
        };
        assert!(matches!(
            connector
                .ingest_webhook_delivery(replay_with_changed_unsigned_nonce)
                .await,
            Err(TwentyConnectorError::InvalidWebhook(message))
                if message.contains("already admitted")
        ));

        let provider_retry = connector
            .ingest_webhook_delivery(delivery(
                (timestamp_millis + 1).to_string(),
                "ef".repeat(16),
            ))
            .await
            .expect("provider retry with a fresh signed timestamp");
        assert_eq!(provider_retry.id, event.id);
    }

    #[tokio::test]
    async fn replay_store_prunes_expired_nonces_and_enforces_capacity() {
        let store = InMemoryTwentyWebhookReplayStore::default();
        assert!(store.admit("old", 10, 0, 2).await.expect("first nonce"));
        assert!(store.admit("new", 20, 0, 2).await.expect("second nonce"));
        assert!(!store.admit("new", 20, 0, 2).await.expect("duplicate nonce"));
        assert!(store.admit("overflow", 30, 0, 2).await.is_err());
        assert!(
            store
                .admit("after-prune", 40, 15, 2)
                .await
                .expect("pruned nonce")
        );
    }

    #[test]
    fn temporary_provider_failures_preserve_mutation_uncertainty() {
        let create = failure(
            TwentyConnectorError::Status {
                status: 503,
                request_id: Some("request-1".to_owned()),
                retry_after_ms: Some(2_000),
                details: None,
            },
            TwentyOperation::RecordCreate,
        );
        assert!(create.retryable);
        assert!(create.uncertain_outcome);
        assert_eq!(create.retry_after_ms, Some(2_000));

        let destroy = failure(
            TwentyConnectorError::Status {
                status: 503,
                request_id: None,
                retry_after_ms: None,
                details: None,
            },
            TwentyOperation::RecordDestroy,
        );
        assert!(!destroy.retryable);
        assert!(destroy.uncertain_outcome);
    }

    fn nested_json_key<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
        match value {
            Value::Object(object) => object.get(key).or_else(|| {
                object
                    .values()
                    .find_map(|value| nested_json_key(value, key))
            }),
            Value::Array(values) => values.iter().find_map(|value| nested_json_key(value, key)),
            _ => None,
        }
    }
}
