//! Chatwoot connector mappings for AIP.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic))]

mod operations;

pub use operations::{
    ALL_CHATWOOT_OPERATIONS, ChatwootHttpMethod, ChatwootOperation, OPERATOR_ONLY_EXCLUDED_ROUTES,
    UPSTREAM_REVISION,
};

use aip_connector::{
    CapabilityImplementationSupport, CapabilityProviderConnector, ChannelConnector, Connector,
    ConnectorContext, ConnectorError, ConnectorFailure, ConnectorHealth, ConnectorOperation,
    ConnectorResult, ConnectorSecret, FrozenConnector, InboundConnector, OutboundConnector,
};
use aip_core::{
    Action, ActionResult, ActionResultStatus, ApprovalPolicy, ApproverSelector, Capability,
    CapabilityContract, CapabilityId, CapabilityKind, ChannelMessage, CompensationContract,
    CompensationMode, Conversation, ConversationId, ConversationStatus, DataContract,
    DataSensitivity, Envelope, ErrorCategory, Event, EventId, EvidenceRequirement,
    ExecutionContract, ExpectedCompletionMode, ExternalRef, IdempotencyCollisionBehavior,
    IdempotencyContract, IdempotencyKeyScope, IdempotencyRequirement, MessageBody, MessagePart,
    Principal, PrincipalId, PrincipalKind, ProfileId, ProtocolError, RetrySafety, RiskLevel,
    ServiceLevelContract, SideEffect,
};
use aip_profile_webhook::WebhookHeaders;
use aip_runtime::{
    ActionExecutionContext, ActionHandler, ProfileStateCasOutcome, ProfileStateStore, RuntimeError,
    RuntimeResult,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use url::Url;

type HmacSha256 = Hmac<Sha256>;

/// Stable connector id.
pub const CONNECTOR_ID: &str = "chatwoot";
/// AIP profile id for Chatwoot-specific binding metadata.
pub const PROFILE_ID: &str = "aip.connector.chatwoot.v1";
const SEND_MESSAGE_CAPABILITY_ID: &str = "cap:chatwoot:message:create";
const STATUS_CAPABILITY_ID: &str = "cap:chatwoot:conversation:status";
const HANDOFF_CAPABILITY_ID: &str = "cap:chatwoot:conversation:handoff";
const WEBHOOK_MAX_SKEW_SECONDS: i64 = 300;
const WEBHOOK_REPLAY_CAPACITY: usize = 10_000;
/// Maximum exact raw body accepted by the signed webhook boundary.
pub const MAX_WEBHOOK_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_WEBHOOK_SECRET_BYTES: usize = 16 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 128 * 1024 * 1024;
const MAX_JSON_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_QUERY_VALUE_BYTES: usize = 32 * 1024;
const MAX_REQUEST_URL_BYTES: usize = 128 * 1024;
const MAX_MULTIPART_FILES: usize = 20;
const MAX_MULTIPART_FILE_BYTES: usize = 25 * 1024 * 1024;
const MAX_MULTIPART_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_MULTIPART_FIELD_BYTES: usize = 1024 * 1024;

/// Chatwoot webhook payload subset used by the connector.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChatwootWebhook {
    /// Event name.
    pub event: String,
    /// Account id.
    pub account: Value,
    /// Conversation object.
    pub conversation: Value,
    /// Message object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Value>,
    /// Contact object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<Value>,
}

/// Exact Chatwoot webhook delivery accepted by the frozen ingestion boundary.
///
/// Signature verification always uses `raw_body`; parsing and re-serializing
/// JSON before verification is forbidden because it changes the signed bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatwootWebhookDelivery {
    /// Value of `X-Chatwoot-Delivery`.
    pub delivery_id: String,
    /// Value of `X-Chatwoot-Timestamp`.
    pub timestamp: i64,
    /// Value of `X-Chatwoot-Signature`.
    pub signature: String,
    /// Original UTF-8 request body, byte-for-byte as received.
    pub raw_body: String,
}

/// Atomic replay-fencing boundary for accepted Chatwoot webhook deliveries.
#[async_trait]
pub trait ChatwootReplayStore: Send + Sync {
    /// Admits a delivery exactly once after removing entries older than the
    /// supplied cutoff. Returns `false` for a duplicate delivery.
    async fn admit(
        &self,
        delivery_id: &str,
        delivery_timestamp: i64,
        cutoff_timestamp: i64,
        capacity: usize,
    ) -> Result<bool, String>;
}

/// Process-local replay store for tests and ephemeral deployments.
#[derive(Debug, Default)]
pub struct InMemoryChatwootReplayStore {
    deliveries: Mutex<BTreeMap<String, i64>>,
}

/// Cluster-safe Chatwoot webhook replay store backed by runtime profile state.
#[derive(Clone)]
pub struct ProfileStateChatwootReplayStore {
    state: ProfileStateStore,
    scope: String,
}

impl std::fmt::Debug for ProfileStateChatwootReplayStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProfileStateChatwootReplayStore")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl ProfileStateChatwootReplayStore {
    /// Creates a shared replay fence for one logical connector instance.
    pub fn new(state: ProfileStateStore, scope: impl Into<String>) -> Result<Self, String> {
        let scope = scope.into();
        if scope.trim().is_empty() || scope.len() > 1_024 || scope.contains('\0') {
            return Err(
                "Chatwoot webhook replay scope must contain 1 to 1024 bytes without NUL".to_owned(),
            );
        }
        Ok(Self { state, scope })
    }
}

#[async_trait]
impl ChatwootReplayStore for ProfileStateChatwootReplayStore {
    async fn admit(
        &self,
        delivery_id: &str,
        delivery_timestamp: i64,
        cutoff_timestamp: i64,
        capacity: usize,
    ) -> Result<bool, String> {
        const NAMESPACE: &str = "aip.connector.chatwoot.webhook_replay.v1";
        for _ in 0..32 {
            let current = self
                .state
                .get(NAMESPACE, &self.scope)
                .await
                .map_err(|error| error.to_string())?;
            let mut deliveries = current
                .as_ref()
                .map(|entry| serde_json::from_value::<BTreeMap<String, i64>>(entry.value.clone()))
                .transpose()
                .map_err(|error| format!("decode Chatwoot webhook replay state: {error}"))?
                .unwrap_or_default();
            if deliveries.contains_key(delivery_id) {
                return Ok(false);
            }
            if !admit_delivery_to_map(
                &mut deliveries,
                delivery_id,
                delivery_timestamp,
                cutoff_timestamp,
                capacity,
            ) {
                return Ok(false);
            }
            match self
                .state
                .compare_and_set(
                    NAMESPACE,
                    &self.scope,
                    current.as_ref().map(|entry| entry.revision),
                    serde_json::to_value(deliveries).map_err(|error| {
                        format!("encode Chatwoot webhook replay state: {error}")
                    })?,
                )
                .await
                .map_err(|error| error.to_string())?
            {
                ProfileStateCasOutcome::Applied(_) => return Ok(true),
                ProfileStateCasOutcome::Conflict(_) => tokio::task::yield_now().await,
            }
        }
        Err("Chatwoot webhook replay state remained contended after 32 attempts".to_owned())
    }
}

#[async_trait]
impl ChatwootReplayStore for InMemoryChatwootReplayStore {
    async fn admit(
        &self,
        delivery_id: &str,
        delivery_timestamp: i64,
        cutoff_timestamp: i64,
        capacity: usize,
    ) -> Result<bool, String> {
        let mut deliveries = self.deliveries.lock().await;
        Ok(admit_delivery_to_map(
            &mut deliveries,
            delivery_id,
            delivery_timestamp,
            cutoff_timestamp,
            capacity,
        ))
    }
}

/// Durable single-host replay store using atomic file replacement.
///
/// Multiple daemon processes must use a database-backed implementation with an
/// atomic unique constraint instead of sharing this file backend.
#[derive(Debug)]
pub struct FileChatwootReplayStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileChatwootReplayStore {
    /// Creates a replay store at the supplied durable state path.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    /// Returns the durable state path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait]
impl ChatwootReplayStore for FileChatwootReplayStore {
    async fn admit(
        &self,
        delivery_id: &str,
        delivery_timestamp: i64,
        cutoff_timestamp: i64,
        capacity: usize,
    ) -> Result<bool, String> {
        let _guard = self.lock.lock().await;
        let mut deliveries = match tokio::fs::read(&self.path).await {
            Ok(bytes) => serde_json::from_slice::<BTreeMap<String, i64>>(&bytes)
                .map_err(|error| format!("decode replay store: {error}"))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(format!("read replay store: {error}")),
        };
        if !admit_delivery_to_map(
            &mut deliveries,
            delivery_id,
            delivery_timestamp,
            cutoff_timestamp,
            capacity,
        ) {
            return Ok(false);
        }
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|error| format!("create replay store directory: {error}"))?;
        }
        let temporary = self.path.with_extension("tmp");
        let encoded = serde_json::to_vec(&deliveries)
            .map_err(|error| format!("encode replay store: {error}"))?;
        tokio::fs::write(&temporary, encoded)
            .await
            .map_err(|error| format!("write replay store: {error}"))?;
        tokio::fs::rename(&temporary, &self.path)
            .await
            .map_err(|error| format!("replace replay store: {error}"))?;
        Ok(true)
    }
}

/// Chatwoot outgoing message request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChatwootOutgoingMessage {
    /// Conversation id.
    pub conversation_id: String,
    /// Message content.
    pub content: String,
    /// Whether the message is private.
    pub private: bool,
    /// AIP action id recorded in Chatwoot content attributes for audit and deduplication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aip_action_id: Option<String>,
}

/// Chatwoot conversation status command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatwootConversationCommand {
    /// Mark the conversation open.
    Open,
    /// Mark the conversation resolved.
    Resolve,
    /// Put the conversation back in pending state.
    Pending,
}

/// Chatwoot handoff request payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatwootHandoff {
    /// Conversation id.
    pub conversation_id: String,
    /// Optional assignee id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee_id: Option<String>,
    /// Private note added during handoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Chatwoot HTTP connector.
#[derive(Clone)]
pub struct ChatwootConnector {
    base_url: Url,
    account_id: String,
    api_token: ConnectorSecret,
    webhook_secret: Option<ConnectorSecret>,
    client: reqwest::Client,
    webhook_replays: Arc<dyn ChatwootReplayStore>,
    max_response_bytes: usize,
    allowed_operations: BTreeSet<ChatwootOperation>,
}

impl fmt::Debug for ChatwootConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatwootConnector")
            .field("base_url", &self.base_url)
            .field("account_id", &self.account_id)
            .field("api_token", &self.api_token)
            .field("webhook_secret_configured", &self.webhook_secret.is_some())
            .field("max_response_bytes", &self.max_response_bytes)
            .field("allowed_operation_count", &self.allowed_operations.len())
            .finish_non_exhaustive()
    }
}

impl ChatwootConnector {
    /// Creates a Chatwoot connector.
    pub fn new(
        base_url: impl AsRef<str>,
        account_id: impl Into<String>,
        api_token: impl Into<String>,
    ) -> Result<Self, ChatwootConnectorError> {
        Self::with_api_token(
            base_url,
            account_id,
            ConnectorSecret::from(api_token.into()),
        )
    }

    /// Creates a Chatwoot connector without materializing the API token as a
    /// general-purpose `String` in the host process.
    pub fn with_api_token(
        base_url: impl AsRef<str>,
        account_id: impl Into<String>,
        api_token: ConnectorSecret,
    ) -> Result<Self, ChatwootConnectorError> {
        let base_url = validate_base_url(base_url.as_ref())?;
        let account_id = account_id.into();
        if account_id.trim().is_empty()
            || account_id.len() > 256
            || account_id.chars().any(char::is_control)
        {
            return Err(ChatwootConnectorError::InvalidConfiguration(
                "account id must contain 1 to 256 bytes without control characters".to_owned(),
            ));
        }
        validate_api_token(&api_token)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|error| ChatwootConnectorError::InvalidClient(error.to_string()))?;
        Ok(Self {
            base_url,
            account_id,
            api_token,
            webhook_secret: None,
            client,
            webhook_replays: Arc::new(InMemoryChatwootReplayStore::default()),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            allowed_operations: ALL_CHATWOOT_OPERATIONS.iter().copied().collect(),
        })
    }

    /// Restricts the advertised and executable catalogue to operations admitted
    /// for this Chatwoot edition and account policy.
    pub fn with_allowed_operations(
        mut self,
        operations: impl IntoIterator<Item = ChatwootOperation>,
    ) -> Result<Self, ChatwootConnectorError> {
        let operations = operations.into_iter().collect::<BTreeSet<_>>();
        if operations.is_empty() {
            return Err(ChatwootConnectorError::InvalidConfiguration(
                "at least one Chatwoot catalogue operation must be enabled".to_owned(),
            ));
        }
        self.allowed_operations = operations;
        Ok(self)
    }

    /// Sets the maximum accepted provider response size.
    pub fn with_max_response_bytes(
        mut self,
        max_response_bytes: usize,
    ) -> Result<Self, ChatwootConnectorError> {
        if !(1..=MAX_RESPONSE_BYTES).contains(&max_response_bytes) {
            return Err(ChatwootConnectorError::InvalidConfiguration(format!(
                "max_response_bytes must be between 1 and {MAX_RESPONSE_BYTES}"
            )));
        }
        self.max_response_bytes = max_response_bytes;
        Ok(self)
    }

    /// Sets the webhook HMAC secret used for inbound verification.
    #[must_use]
    pub fn with_webhook_secret(mut self, secret: impl Into<Vec<u8>>) -> Self {
        self.webhook_secret = Some(ConnectorSecret::from(secret.into()));
        self
    }

    /// Sets webhook verification and an atomic replay-fencing backend.
    #[must_use]
    pub fn with_webhook_security(
        mut self,
        secret: impl Into<Vec<u8>>,
        replay_store: Arc<dyn ChatwootReplayStore>,
    ) -> Self {
        self.webhook_secret = Some(ConnectorSecret::from(secret.into()));
        self.webhook_replays = replay_store;
        self
    }

    fn api_token(&self) -> Result<&str, ChatwootConnectorError> {
        self.api_token
            .expose_str()
            .map_err(|_| ChatwootConnectorError::InvalidCredential)
    }

    /// Verifies and ingests one exact Chatwoot webhook delivery.
    ///
    /// The delivery id is observed atomically in a bounded replay window only
    /// after timestamp and HMAC verification succeed. A duplicate intentionally
    /// returns the same deterministic message projection so the caller can
    /// repair a crash between replay observation and event persistence.
    pub async fn ingest_webhook_delivery(
        &self,
        delivery: ChatwootWebhookDelivery,
    ) -> Result<Vec<Envelope>, ChatwootConnectorError> {
        let secret = self
            .webhook_secret
            .as_ref()
            .ok_or(ChatwootConnectorError::WebhookNotConfigured)?;
        validate_webhook_secret(secret)?;
        if delivery.delivery_id.trim().is_empty()
            || delivery.delivery_id.len() > 512
            || delivery.delivery_id.chars().any(char::is_control)
        {
            return Err(ChatwootConnectorError::InvalidWebhook(
                "delivery id must contain 1 to 512 bytes without control characters".to_owned(),
            ));
        }
        if delivery.signature.len() > 512 || delivery.signature.chars().any(char::is_control) {
            return Err(ChatwootConnectorError::InvalidWebhook(
                "signature exceeds its transport bound".to_owned(),
            ));
        }
        if delivery.raw_body.is_empty() || delivery.raw_body.len() > MAX_WEBHOOK_BODY_BYTES {
            return Err(ChatwootConnectorError::InvalidWebhook(format!(
                "raw body must contain 1 to {MAX_WEBHOOK_BODY_BYTES} bytes"
            )));
        }
        let headers = WebhookHeaders {
            delivery: delivery.delivery_id.clone(),
            timestamp: delivery.timestamp,
            signature: delivery.signature,
            source_system: "chatwoot".to_owned(),
            event_type: "unknown".to_owned(),
        };
        verify_webhook(
            secret.expose_bytes(),
            &headers,
            delivery.raw_body.as_bytes(),
        )
        .map_err(|error| ChatwootConnectorError::InvalidWebhook(error.to_string()))?;
        self.observe_delivery(&delivery.delivery_id, delivery.timestamp)
            .await?;
        let webhook = serde_json::from_slice::<ChatwootWebhook>(delivery.raw_body.as_bytes())
            .map_err(|error| ChatwootConnectorError::InvalidWebhook(error.to_string()))?;
        if is_loop_prevention_webhook(&webhook) {
            return Ok(Vec::new());
        }
        let channel = channel_message_from_webhook(webhook, delivery.delivery_id)
            .map_err(|error| ChatwootConnectorError::InvalidWebhook(error.to_string()))?;
        Ok(vec![Envelope::new(MessageBody::ChannelMessage(Box::new(
            channel,
        )))])
    }

    async fn observe_delivery(
        &self,
        delivery_id: &str,
        timestamp: i64,
    ) -> Result<(), ChatwootConnectorError> {
        let cutoff = OffsetDateTime::now_utc().unix_timestamp() - WEBHOOK_MAX_SKEW_SECONDS;
        let _new_delivery = self
            .webhook_replays
            .admit(delivery_id, timestamp, cutoff, WEBHOOK_REPLAY_CAPACITY)
            .await
            .map_err(ChatwootConnectorError::ReplayStore)?;
        Ok(())
    }
}

fn validate_base_url(value: &str) -> Result<Url, ChatwootConnectorError> {
    let url = Url::parse(value).map_err(ChatwootConnectorError::InvalidUrl)?;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ChatwootConnectorError::InvalidBaseUrl(
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
        return Err(ChatwootConnectorError::InvalidBaseUrl(
            "Chatwoot requires HTTPS except for an explicit loopback deployment".to_owned(),
        ));
    }
    Ok(url)
}

fn validate_api_token(token: &ConnectorSecret) -> Result<(), ChatwootConnectorError> {
    let token = token
        .expose_str()
        .map_err(|_| ChatwootConnectorError::InvalidCredential)?;
    if token.trim().is_empty() || token.len() > 16 * 1024 || token.chars().any(char::is_control) {
        return Err(ChatwootConnectorError::InvalidCredential);
    }
    Ok(())
}

fn validate_webhook_secret(secret: &ConnectorSecret) -> Result<(), ChatwootConnectorError> {
    let bytes = secret.expose_bytes();
    if bytes.is_empty() || bytes.len() > MAX_WEBHOOK_SECRET_BYTES {
        return Err(ChatwootConnectorError::InvalidConfiguration(format!(
            "webhook secret must contain 1 to {MAX_WEBHOOK_SECRET_BYTES} bytes"
        )));
    }
    Ok(())
}

fn admit_delivery_to_map(
    deliveries: &mut BTreeMap<String, i64>,
    delivery_id: &str,
    delivery_timestamp: i64,
    cutoff_timestamp: i64,
    capacity: usize,
) -> bool {
    deliveries.retain(|_, accepted_at| *accepted_at >= cutoff_timestamp);
    if deliveries.contains_key(delivery_id) {
        return false;
    }
    while deliveries.len() >= capacity {
        let Some(oldest) = deliveries
            .iter()
            .min_by_key(|(_, accepted_at)| **accepted_at)
            .map(|(delivery, _)| delivery.clone())
        else {
            break;
        };
        deliveries.remove(&oldest);
    }
    deliveries.insert(delivery_id.to_owned(), delivery_timestamp);
    true
}

/// Chatwoot connector error.
#[derive(Debug, Error)]
pub enum ChatwootConnectorError {
    /// Base URL failed to parse.
    #[error("invalid Chatwoot URL: {0}")]
    InvalidUrl(url::ParseError),
    /// Parsed base URL violates the provider transport policy.
    #[error("invalid Chatwoot base URL: {0}")]
    InvalidBaseUrl(String),
    /// The hardened provider HTTP client could not be constructed.
    #[error("invalid Chatwoot HTTP client: {0}")]
    InvalidClient(String),
    /// Static connector configuration is invalid.
    #[error("invalid Chatwoot connector configuration: {0}")]
    InvalidConfiguration(String),
    /// Required metadata is missing.
    #[error("missing metadata `{0}`")]
    MissingMetadata(&'static str),
    /// HTTP request failed.
    #[error("Chatwoot request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// Chatwoot returned a non-success HTTP status.
    #[error("Chatwoot returned HTTP {status}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// Response body.
        body: Value,
    },
    /// Configured credential material is not valid UTF-8.
    #[error("configured Chatwoot credential is not valid UTF-8")]
    InvalidCredential,
    /// A signed webhook delivery id was already accepted.
    #[error("Chatwoot webhook delivery `{0}` is a replay")]
    WebhookReplay(String),
    /// Replay store could not durably fence a delivery.
    #[error("Chatwoot webhook replay store failed: {0}")]
    ReplayStore(String),
    /// Webhook payload is not valid JSON.
    #[error("invalid Chatwoot webhook payload: {0}")]
    InvalidWebhook(String),
    /// Inbound webhook verification was not configured.
    #[error("Chatwoot webhook verification is not configured")]
    WebhookNotConfigured,
    /// Action input does not satisfy the Chatwoot operation contract.
    #[error("invalid Chatwoot action input: {0}")]
    InvalidAction(String),
    /// Provider response exceeded the configured memory bound.
    #[error("Chatwoot response exceeded the configured {limit}-byte bound")]
    ResponseTooLarge {
        /// Active response-size limit.
        limit: usize,
    },
    /// A state-changing operation omitted its mandatory idempotency key.
    #[error("Chatwoot mutation requires an AIP idempotency key")]
    MissingIdempotencyKey,
}

/// Verifies Chatwoot webhook HMAC using normalized AIP webhook headers.
pub fn verify_webhook(
    secret: &[u8],
    headers: &WebhookHeaders,
    payload: &[u8],
) -> Result<(), aip_profile_webhook::WebhookError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if (now - headers.timestamp).abs() > WEBHOOK_MAX_SKEW_SECONDS {
        return Err(aip_profile_webhook::WebhookError::TimestampSkew);
    }
    let supplied = headers.signature.strip_prefix("sha256=").ok_or_else(|| {
        aip_profile_webhook::WebhookError::InvalidEncoding(
            "Chatwoot signature must use the sha256=<hex> format".to_owned(),
        )
    })?;
    let supplied = hex::decode(supplied)
        .map_err(|error| aip_profile_webhook::WebhookError::InvalidEncoding(error.to_string()))?;
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| aip_profile_webhook::WebhookError::InvalidKey)?;
    mac.update(headers.timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    let expected = mac.finalize().into_bytes();
    if expected.len() != supplied.len()
        || !constant_time_eq::constant_time_eq(expected.as_slice(), &supplied)
    {
        return Err(aip_profile_webhook::WebhookError::InvalidSignature);
    }
    Ok(())
}

#[async_trait]
impl Connector for ChatwootConnector {
    fn id(&self) -> &str {
        CONNECTOR_ID
    }

    async fn discover(&self, _context: &ConnectorContext) -> ConnectorResult<aip_core::Manifest> {
        if let Some(secret) = &self.webhook_secret {
            validate_webhook_secret(secret)
                .map_err(|error| ConnectorError::Discovery(error.to_string()))?;
        }
        let mut profiles = vec![
            aip_core::ProfileId::from("aip.native.http.v1"),
            aip_core::ProfileId::from(PROFILE_ID),
        ];
        let channels = if self.webhook_secret.is_some() {
            profiles.push(aip_core::ProfileId::from(aip_profile_webhook::PROFILE_ID));
            vec![json!({
                "id": "chatwoot-webhooks",
                "system": "chatwoot",
                "account_id": self.account_id
            })]
        } else {
            Vec::new()
        };
        Ok(aip_core::Manifest {
            manifest_version: "aip-manifest/v1".to_owned(),
            agent: Principal::new(
                PrincipalId::parse(format!("agent:chatwoot:{}", self.account_id))
                    .map_err(|error| ConnectorError::Discovery(error.to_string()))?,
                PrincipalKind::Agent,
            ),
            capabilities: chatwoot_capabilities_for(&self.allowed_operations),
            profiles,
            resources: Vec::new(),
            channels,
            security: Some(json!({
                "webhook_ingress_enabled": self.webhook_secret.is_some(),
                "webhook_hmac_required": true,
                "webhook_max_body_bytes": MAX_WEBHOOK_BODY_BYTES
            })),
            governance: None,
            limits: None,
            compatibility: Some(json!({
                "system": "chatwoot",
                "connector": CONNECTOR_ID,
                "upstream_revision": UPSTREAM_REVISION,
                "catalog_operations_supported": ALL_CHATWOOT_OPERATIONS.len(),
                "catalog_operations_admitted": self.allowed_operations.len(),
                "composite_operations": 3
            })),
            extensions: None,
        })
    }

    fn map_error(&self, error: &ConnectorError) -> ProtocolError {
        ProtocolError {
            code: "connector.chatwoot".to_owned(),
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
            .join(&format!("/api/v1/accounts/{}", self.account_id))
            .map_err(|error| ConnectorError::Discovery(error.to_string()))?;
        self.client
            .get(url)
            .header(
                "api_access_token",
                self.api_token()
                    .map_err(|error| ConnectorError::Discovery(error.to_string()))?,
            )
            .send()
            .await
            .map_err(|error| ConnectorError::Discovery(error.to_string()))?
            .error_for_status()
            .map_err(|error| ConnectorError::Discovery(error.to_string()))?;
        Ok(ConnectorHealth {
            ready: true,
            detail: "Chatwoot account API is reachable".to_owned(),
        })
    }
}

#[async_trait]
impl CapabilityProviderConnector for ChatwootConnector {
    async fn capabilities(&self, _context: &ConnectorContext) -> ConnectorResult<Vec<Capability>> {
        Ok(chatwoot_capabilities_for(&self.allowed_operations))
    }
}

#[async_trait]
impl InboundConnector for ChatwootConnector {
    async fn ingest(
        &self,
        context: &ConnectorContext,
        payload: Value,
    ) -> ConnectorResult<Vec<Envelope>> {
        let headers = webhook_headers_from_context(context).map_err(ConnectorError::Verify)?;
        let raw_body = required_metadata(context, "raw_body").map_err(ConnectorError::Verify)?;
        if raw_body.len() > MAX_WEBHOOK_BODY_BYTES {
            return Err(ConnectorError::Verify(format!(
                "raw Chatwoot webhook body exceeds {MAX_WEBHOOK_BODY_BYTES} bytes"
            )));
        }
        let parsed = serde_json::from_str::<Value>(&raw_body)
            .map_err(|error| ConnectorError::Verify(error.to_string()))?;
        if parsed != payload {
            return Err(ConnectorError::Verify(
                "raw Chatwoot webhook body does not match the supplied parsed payload".to_owned(),
            ));
        }
        self.ingest_webhook_delivery(ChatwootWebhookDelivery {
            delivery_id: headers.delivery,
            timestamp: headers.timestamp,
            signature: headers.signature,
            raw_body,
        })
        .await
        .map_err(|error| ConnectorError::Verify(error.to_string()))
    }
}

#[async_trait]
impl ChannelConnector for ChatwootConnector {
    async fn ingest_channel_event(
        &self,
        context: &ConnectorContext,
        payload: Value,
    ) -> ConnectorResult<Vec<Envelope>> {
        self.ingest(context, payload).await
    }

    async fn emit_channel_result(
        &self,
        context: &ConnectorContext,
        result: ActionResult,
    ) -> ConnectorResult<()> {
        self.emit(context, result).await
    }
}

fn webhook_headers_from_context(context: &ConnectorContext) -> Result<WebhookHeaders, String> {
    let delivery = required_metadata(context, "delivery_id")?;
    let signature = required_metadata(context, "signature")?;
    let timestamp = required_metadata(context, "timestamp")?
        .parse::<i64>()
        .map_err(|error| format!("invalid timestamp: {error}"))?;
    Ok(WebhookHeaders {
        delivery,
        timestamp,
        signature,
        source_system: context
            .metadata
            .get("source_system")
            .cloned()
            .unwrap_or_else(|| "chatwoot".to_owned()),
        event_type: context
            .metadata
            .get("event_type")
            .cloned()
            .unwrap_or_else(|| "message_created".to_owned()),
    })
}

fn required_metadata(context: &ConnectorContext, key: &'static str) -> Result<String, String> {
    context
        .metadata
        .get(key)
        .cloned()
        .ok_or_else(|| format!("missing metadata `{key}`"))
}

#[async_trait]
impl OutboundConnector for ChatwootConnector {
    async fn invoke(
        &self,
        _context: &ConnectorContext,
        action: Action,
    ) -> ConnectorResult<ActionResult> {
        let safety = chatwoot_action_safety(&action);
        self.invoke_chatwoot(action).await.map_err(|error| {
            ConnectorError::Failure(connector_failure(
                error,
                ConnectorOperation::Invocation,
                safety,
            ))
        })
    }

    async fn emit(&self, context: &ConnectorContext, result: ActionResult) -> ConnectorResult<()> {
        let conversation_id = context
            .metadata
            .get("conversation_id")
            .ok_or(ChatwootConnectorError::MissingMetadata("conversation_id"))
            .map_err(|error| ConnectorError::Emit(error.to_string()))?
            .clone();
        let message = outgoing_message(conversation_id, &result.message);
        let message = ChatwootOutgoingMessage {
            aip_action_id: Some(result.action_id.to_string()),
            ..message
        };
        self.send_outgoing_message(&message).await.map_err(|error| {
            ConnectorError::Failure(connector_failure(
                error,
                ConnectorOperation::Emission,
                ChatwootOperationSafety::MUTATION_UNSAFE,
            ))
        })
    }
}

impl ChatwootConnector {
    async fn invoke_chatwoot(
        &self,
        action: Action,
    ) -> Result<ActionResult, ChatwootConnectorError> {
        match action.capability_id.as_str() {
            SEND_MESSAGE_CAPABILITY_ID => {
                let mut message =
                    serde_json::from_value::<ChatwootOutgoingMessage>(action.input.clone())
                        .map_err(|error| {
                            ChatwootConnectorError::InvalidAction(error.to_string())
                        })?;
                message.aip_action_id = Some(action.id.to_string());
                self.send_outgoing_message(&message).await?;
                Ok(completed_result(
                    action,
                    json!({ "conversation_id": message.conversation_id, "sent": true }),
                ))
            }
            STATUS_CAPABILITY_ID => {
                let conversation_id = required_action_string(&action.input, "conversation_id")?;
                let status = required_action_string(&action.input, "status")?;
                if !matches!(status.as_str(), "open" | "resolved" | "pending") {
                    return Err(ChatwootConnectorError::InvalidAction(
                        "status must be one of open, resolved, or pending".to_owned(),
                    ));
                }
                self.update_conversation_status(&conversation_id, &status)
                    .await?;
                Ok(completed_result(
                    action,
                    json!({ "conversation_id": conversation_id, "status": status }),
                ))
            }
            HANDOFF_CAPABILITY_ID => {
                let handoff = serde_json::from_value::<ChatwootHandoff>(action.input.clone())
                    .map_err(|error| ChatwootConnectorError::InvalidAction(error.to_string()))?;
                self.handoff_conversation(&handoff, &action.id).await?;
                Ok(completed_result(
                    action,
                    json!({ "conversation_id": handoff.conversation_id, "handoff": true }),
                ))
            }
            capability_id => {
                let suffix = capability_id.strip_prefix("cap:chatwoot:").ok_or_else(|| {
                    ChatwootConnectorError::InvalidAction(format!(
                        "unsupported Chatwoot capability `{}`",
                        action.capability_id
                    ))
                })?;
                let operation = ChatwootOperation::from_suffix(suffix).ok_or_else(|| {
                    ChatwootConnectorError::InvalidAction(format!(
                        "unsupported Chatwoot capability `{}`",
                        action.capability_id
                    ))
                })?;
                if !self.allowed_operations.contains(&operation) {
                    return Err(ChatwootConnectorError::InvalidAction(format!(
                        "Chatwoot capability `{}` is not admitted for this connector instance",
                        action.capability_id
                    )));
                }
                self.invoke_catalog_operation(operation, action).await
            }
        }
    }
}

#[async_trait]
impl ActionHandler for ChatwootConnector {
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
            .map_err(|failure| RuntimeError::Protocol(failure.to_protocol_error()))
    }

    async fn cancel(&self, action: &Action) -> RuntimeResult<()> {
        OutboundConnector::cancel(self, &ConnectorContext::default(), action)
            .await
            .map_err(|error| RuntimeError::Handler(error.to_string()))
    }
}

#[async_trait]
impl FrozenConnector for ChatwootConnector {
    fn implementation_support(&self, capability: &Capability) -> CapabilityImplementationSupport {
        let legacy_operation = match capability.id.as_str() {
            SEND_MESSAGE_CAPABILITY_ID => Some(ChatwootLegacyOperation::SendMessage),
            STATUS_CAPABILITY_ID => Some(ChatwootLegacyOperation::ConversationStatus),
            HANDOFF_CAPABILITY_ID => Some(ChatwootLegacyOperation::Handoff),
            _ => None,
        };
        let catalog_operation = capability
            .id
            .as_str()
            .strip_prefix("cap:chatwoot:")
            .and_then(ChatwootOperation::from_suffix);
        let catalog_operation =
            catalog_operation.filter(|operation| self.allowed_operations.contains(operation));
        let configured = legacy_operation.is_some() || catalog_operation.is_some();
        CapabilityImplementationSupport {
            invocation: configured,
            cancellation: false,
            streaming: false,
            retry: legacy_operation == Some(ChatwootLegacyOperation::ConversationStatus)
                || catalog_operation.is_some_and(ChatwootOperation::retry_safe),
            transaction: false,
            reconciliation: false,
            compensation: false,
            approval: legacy_operation.is_some()
                || catalog_operation.is_some_and(ChatwootOperation::is_mutation),
            credentials: false,
        }
    }

    async fn invoke_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        let safety = chatwoot_action_safety(&action);
        tokio::select! {
            result = self.invoke_chatwoot(action) => result.map_err(|error| {
                connector_failure(error, ConnectorOperation::Invocation, safety)
            }),
            () = context.cancellation.cancelled() => Err(ConnectorFailure {
                code: "connector.chatwoot.cancelled".to_owned(),
                message: "Chatwoot invocation was cancelled before completion".to_owned(),
                category: ErrorCategory::Temporary,
                retryable: false,
                retry_after_ms: None,
                provider_request_id: None,
                provider_operation: None,
                remote_status: None,
                uncertain_outcome: safety.mutation,
                redacted_details: None,
                source_component: CONNECTOR_ID.to_owned(),
                operation: ConnectorOperation::Invocation,
            }),
        }
    }

    async fn ingest_typed(
        &self,
        payload: Value,
        _context: ActionExecutionContext,
    ) -> Result<Vec<Envelope>, ConnectorFailure> {
        let delivery =
            serde_json::from_value::<ChatwootWebhookDelivery>(payload).map_err(|error| {
                ConnectorFailure {
                    code: "connector.chatwoot.invalid_webhook_delivery".to_owned(),
                    message: error.to_string(),
                    category: ErrorCategory::Permanent,
                    retryable: false,
                    retry_after_ms: None,
                    provider_request_id: None,
                    provider_operation: None,
                    remote_status: None,
                    uncertain_outcome: false,
                    redacted_details: None,
                    source_component: CONNECTOR_ID.to_owned(),
                    operation: ConnectorOperation::Ingestion,
                }
            })?;
        self.ingest_webhook_delivery(delivery)
            .await
            .map_err(|error| {
                connector_failure(
                    error,
                    ConnectorOperation::Ingestion,
                    ChatwootOperationSafety::READ_ONLY,
                )
            })
    }
}

impl ChatwootConnector {
    async fn invoke_catalog_operation(
        &self,
        operation: ChatwootOperation,
        action: Action,
    ) -> Result<ActionResult, ChatwootConnectorError> {
        let idempotency_key = if operation.is_mutation() {
            Some(required_idempotency_key(&action)?)
        } else {
            action.idempotency_key.as_deref()
        };
        let mut url =
            chatwoot_operation_url(&self.base_url, &self.account_id, operation, &action.input)?;
        append_chatwoot_query(&mut url, action.input.get("query"))?;
        let method = match operation.method() {
            ChatwootHttpMethod::Get => reqwest::Method::GET,
            ChatwootHttpMethod::Post => reqwest::Method::POST,
            ChatwootHttpMethod::Patch => reqwest::Method::PATCH,
            ChatwootHttpMethod::Put => reqwest::Method::PUT,
            ChatwootHttpMethod::Delete => reqwest::Method::DELETE,
        };
        let mut request = self
            .client
            .request(method, url)
            .header("api_access_token", self.api_token()?)
            .header("X-AIP-Action-ID", action.id.to_string());
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        if action.input.get("body").is_some() && action.input.get("multipart").is_some() {
            return Err(ChatwootConnectorError::InvalidAction(
                "input must not contain both `body` and `multipart`".to_owned(),
            ));
        }
        if matches!(operation.method(), ChatwootHttpMethod::Get)
            && (action.input.get("body").is_some() || action.input.get("multipart").is_some())
        {
            return Err(ChatwootConnectorError::InvalidAction(
                "Chatwoot GET operations do not accept a request body".to_owned(),
            ));
        }
        if action.input.get("multipart").is_some() && !operation.supports_multipart() {
            return Err(ChatwootConnectorError::InvalidAction(format!(
                "Chatwoot operation `{}` does not accept multipart input",
                operation.suffix()
            )));
        }
        if let Some(body) = action.input.get("body") {
            let object = body.as_object().ok_or_else(|| {
                ChatwootConnectorError::InvalidAction("input `body` must be an object".to_owned())
            })?;
            let encoded = serde_json::to_vec(object).map_err(|error| {
                ChatwootConnectorError::InvalidAction(format!(
                    "input `body` is not JSON serializable: {error}"
                ))
            })?;
            if encoded.len() > MAX_JSON_REQUEST_BYTES {
                return Err(ChatwootConnectorError::InvalidAction(format!(
                    "input `body` exceeds {MAX_JSON_REQUEST_BYTES} bytes"
                )));
            }
            request = request.json(object);
        } else if let Some(multipart) = action.input.get("multipart") {
            request = request.multipart(chatwoot_multipart_form(multipart)?);
        }
        let response = request.send().await?;
        let status = response.status();
        let provider_request_id = response
            .headers()
            .get("x-request-id")
            .or_else(|| response.headers().get("x-runtime"))
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let body = chatwoot_response_body(response, self.max_response_bytes).await?;
        if !status.is_success() {
            return Err(ChatwootConnectorError::Status {
                status: status.as_u16(),
                body,
            });
        }
        Ok(completed_result(
            action,
            json!({
                "http_status": status.as_u16(),
                "body": body,
                "provider_request_id": provider_request_id
            }),
        ))
    }

    async fn send_outgoing_message(
        &self,
        message: &ChatwootOutgoingMessage,
    ) -> Result<(), ChatwootConnectorError> {
        let url = self
            .base_url
            .join(&format!(
                "/api/v1/accounts/{}/conversations/{}/messages",
                self.account_id, message.conversation_id
            ))
            .map_err(ChatwootConnectorError::InvalidUrl)?;
        let response = self
            .client
            .post(url)
            .header("api_access_token", self.api_token()?)
            .json(&json!({
                "content": message.content,
                "private": message.private,
                "content_attributes": {
                    "aip": {
                        "connector_id": CONNECTOR_ID,
                        "loop_prevention": true,
                        "action_id": message.aip_action_id
                    }
                }
            }))
            .send()
            .await?;
        let status = response.status();
        let body = chatwoot_response_body(response, self.max_response_bytes).await?;
        if !status.is_success() {
            return Err(ChatwootConnectorError::Status {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    async fn update_conversation_status(
        &self,
        conversation_id: &str,
        status: &str,
    ) -> Result<(), ChatwootConnectorError> {
        let url = self
            .base_url
            .join(&format!(
                "/api/v1/accounts/{}/conversations/{conversation_id}/toggle_status",
                self.account_id
            ))
            .map_err(ChatwootConnectorError::InvalidUrl)?;
        let response = self
            .client
            .post(url)
            .header("api_access_token", self.api_token()?)
            .json(&json!({ "status": chatwoot_status(status) }))
            .send()
            .await?;
        ensure_success(response, self.max_response_bytes).await
    }

    async fn handoff_conversation(
        &self,
        handoff: &ChatwootHandoff,
        action_id: &aip_core::ActionId,
    ) -> Result<(), ChatwootConnectorError> {
        if let Some(assignee_id) = &handoff.assignee_id {
            let url = self
                .base_url
                .join(&format!(
                    "/api/v1/accounts/{}/conversations/{}/assignments",
                    self.account_id, handoff.conversation_id
                ))
                .map_err(ChatwootConnectorError::InvalidUrl)?;
            let response = self
                .client
                .post(url)
                .header("api_access_token", self.api_token()?)
                .json(&json!({ "assignee_id": assignee_id }))
                .send()
                .await?;
            ensure_success(response, self.max_response_bytes).await?;
        }
        if let Some(note) = &handoff.note {
            self.send_outgoing_message(&ChatwootOutgoingMessage {
                conversation_id: handoff.conversation_id.clone(),
                content: note.clone(),
                private: true,
                aip_action_id: Some(action_id.to_string()),
            })
            .await?;
        }
        Ok(())
    }
}

async fn ensure_success(
    response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<(), ChatwootConnectorError> {
    let status = response.status();
    let body = chatwoot_response_body(response, max_response_bytes).await?;
    if !status.is_success() {
        return Err(ChatwootConnectorError::Status {
            status: status.as_u16(),
            body,
        });
    }
    Ok(())
}

async fn chatwoot_response_body(
    response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<Value, ChatwootConnectorError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        return Err(ChatwootConnectorError::ResponseTooLarge {
            limit: max_response_bytes,
        });
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len().saturating_add(chunk.len()) > max_response_bytes {
            return Err(ChatwootConnectorError::ResponseTooLarge {
                limit: max_response_bytes,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    match serde_json::from_slice(&bytes) {
        Ok(value) => Ok(redact_chatwoot_provider_value(value)),
        Err(_) => Ok(json!({ "text": String::from_utf8_lossy(&bytes) })),
    }
}

/// Removes credential material exposed by administrator-authorized Chatwoot
/// serializers before a provider response can enter an AIP result, receipt,
/// audit record, or error detail.
///
/// Chatwoot intentionally includes several channel and bot credentials in
/// otherwise ordinary account API representations when the caller is an
/// administrator. The connector itself commonly uses such a token, so it must
/// treat every provider response as privileged regardless of the AIP caller's
/// role. Public identifiers such as `website_token` remain available because
/// they are required to embed the Chatwoot widget and are not credentials.
fn redact_chatwoot_provider_value(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter(|(key, _)| !is_chatwoot_secret_key(key))
                .map(|(key, value)| (key, redact_chatwoot_provider_value(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(redact_chatwoot_provider_value)
                .collect(),
        ),
        scalar => scalar,
    }
}

fn is_chatwoot_secret_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "access_token"
            | "api_access_token"
            | "api_key"
            | "api_key_secret"
            | "api_token"
            | "auth_token"
            | "bearer_token"
            | "bot_token"
            | "client_secret"
            | "hmac_token"
            | "imap_password"
            | "line_channel_secret"
            | "line_channel_token"
            | "page_access_token"
            | "password"
            | "password_confirmation"
            | "private_key"
            | "pubsub_token"
            | "refresh_token"
            | "secret"
            | "smtp_password"
            | "twitter_access_token"
            | "twitter_access_token_secret"
            | "user_access_token"
            | "webhook_verify_token"
    )
}

fn chatwoot_capabilities_for(allowed_operations: &BTreeSet<ChatwootOperation>) -> Vec<Capability> {
    let mut capabilities = vec![
        Capability {
            id: CapabilityId::trusted(SEND_MESSAGE_CAPABILITY_ID),
            name: "Chatwoot send message".to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: json!({
                "type": "object",
                "required": ["conversation_id", "content"],
                "properties": {
                    "conversation_id": { "type": "string" },
                    "content": { "type": "string" },
                    "private": { "type": "boolean", "default": false }
                },
                "additionalProperties": false
            }),
            output_schema: Some(json!({
                "type": "object",
                "required": ["conversation_id", "sent"],
                "properties": {
                    "conversation_id": { "type": "string" },
                    "sent": { "const": true }
                },
                "additionalProperties": false
            })),
            description: Some(
                "Sends a public reply or private note to a Chatwoot conversation.".to_owned(),
            ),
            risk: Some(RiskLevel::Medium),
            stability: None,
            cost: None,
            auth: Some(json!({ "type": "chatwoot_api_access_token" })),
            bindings: vec![
                aip_core::Binding {
                    profile: ProfileId::from("aip.native.http.v1"),
                    metadata: json!({ "connector": CONNECTOR_ID, "operation": "send_message" })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                },
                aip_core::Binding {
                    profile: ProfileId::from(PROFILE_ID),
                    metadata: json!({
                        "system": "chatwoot",
                        "connector": CONNECTOR_ID,
                        "operation": "send_message"
                    })
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
                },
            ],
            requires_human_approval: Some(true),
            contract: Some(chatwoot_contract(ChatwootLegacyOperation::SendMessage)),
        },
        Capability {
            id: CapabilityId::trusted(STATUS_CAPABILITY_ID),
            name: "Chatwoot update conversation status".to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: json!({
                "type": "object",
                "required": ["conversation_id", "status"],
                "properties": {
                    "conversation_id": { "type": "string" },
                    "status": { "type": "string", "enum": ["open", "resolved", "pending"] }
                },
                "additionalProperties": false
            }),
            output_schema: Some(json!({
                "type": "object",
                "required": ["conversation_id", "status"],
                "properties": {
                    "conversation_id": { "type": "string" },
                    "status": { "type": "string", "enum": ["open", "resolved", "pending"] }
                },
                "additionalProperties": false
            })),
            description: Some(
                "Opens, resolves, or marks a Chatwoot conversation pending.".to_owned(),
            ),
            risk: Some(RiskLevel::Medium),
            stability: None,
            cost: None,
            auth: Some(json!({ "type": "chatwoot_api_access_token" })),
            bindings: vec![
                aip_core::Binding {
                    profile: ProfileId::from("aip.native.http.v1"),
                    metadata:
                        json!({ "connector": CONNECTOR_ID, "operation": "conversation_status" })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                },
                aip_core::Binding {
                    profile: ProfileId::from(PROFILE_ID),
                    metadata: json!({
                        "system": "chatwoot",
                        "connector": CONNECTOR_ID,
                        "operation": "conversation_status"
                    })
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
                },
            ],
            requires_human_approval: Some(true),
            contract: Some(chatwoot_contract(
                ChatwootLegacyOperation::ConversationStatus,
            )),
        },
        Capability {
            id: CapabilityId::trusted(HANDOFF_CAPABILITY_ID),
            name: "Chatwoot handoff conversation".to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: json!({
                "type": "object",
                "required": ["conversation_id"],
                "properties": {
                    "conversation_id": { "type": "string" },
                    "assignee_id": { "type": "string" },
                    "note": { "type": "string" }
                },
                "additionalProperties": false
            }),
            output_schema: Some(json!({
                "type": "object",
                "required": ["conversation_id", "handoff"],
                "properties": {
                    "conversation_id": { "type": "string" },
                    "handoff": { "const": true }
                },
                "additionalProperties": false
            })),
            description: Some(
                "Assigns a Chatwoot conversation and optionally adds a private handoff note."
                    .to_owned(),
            ),
            risk: Some(RiskLevel::High),
            stability: None,
            cost: None,
            auth: Some(json!({ "type": "chatwoot_api_access_token" })),
            bindings: vec![
                aip_core::Binding {
                    profile: ProfileId::from("aip.native.http.v1"),
                    metadata: json!({ "connector": CONNECTOR_ID, "operation": "handoff" })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                },
                aip_core::Binding {
                    profile: ProfileId::from(PROFILE_ID),
                    metadata: json!({
                        "system": "chatwoot",
                        "connector": CONNECTOR_ID,
                        "operation": "handoff"
                    })
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
                },
            ],
            requires_human_approval: Some(true),
            contract: Some(chatwoot_contract(ChatwootLegacyOperation::Handoff)),
        },
    ];
    capabilities.extend(
        allowed_operations
            .iter()
            .copied()
            .map(chatwoot_catalog_capability),
    );
    capabilities
}

fn chatwoot_catalog_capability(operation: ChatwootOperation) -> Capability {
    let suffix = operation.suffix();
    Capability {
        id: CapabilityId::trusted(format!("cap:chatwoot:{suffix}")),
        name: format!("Chatwoot {}", operation.display_name()),
        kind: operation.capability_kind(),
        input_schema: chatwoot_catalog_input_schema(operation),
        output_schema: Some(json!({
            "type": "object",
            "required": ["http_status", "body"],
            "properties": {
                "http_status": { "type": "integer", "minimum": 100, "maximum": 599 },
                "body": {},
                "provider_request_id": { "type": ["string", "null"] }
            },
            "additionalProperties": false
        })),
        description: Some(format!(
            "Maps a frozen AIP capability to Chatwoot {} {} at upstream revision {}.",
            chatwoot_method_name(operation.method()),
            operation.path_template(),
            UPSTREAM_REVISION
        )),
        risk: Some(operation.risk()),
        stability: None,
        cost: None,
        auth: Some(json!({ "type": "chatwoot_api_access_token" })),
        bindings: vec![
            aip_core::Binding {
                profile: ProfileId::from("aip.native.http.v1"),
                metadata: json!({
                    "connector": CONNECTOR_ID,
                    "operation": suffix,
                    "method": chatwoot_method_name(operation.method()),
                    "path_template": operation.path_template(),
                    "upstream_revision": UPSTREAM_REVISION,
                    "requires_enterprise_edition": operation.requires_enterprise_edition()
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            },
            aip_core::Binding {
                profile: ProfileId::from(PROFILE_ID),
                metadata: json!({
                    "system": "chatwoot",
                    "connector": CONNECTOR_ID,
                    "operation": suffix,
                    "upstream_revision": UPSTREAM_REVISION,
                    "requires_enterprise_edition": operation.requires_enterprise_edition()
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            },
        ],
        requires_human_approval: Some(operation.is_mutation()),
        contract: Some(chatwoot_catalog_contract(operation)),
    }
}

fn chatwoot_catalog_input_schema(operation: ChatwootOperation) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for parameter in chatwoot_path_parameters(operation.path_template()) {
        if parameter == "account_id" {
            continue;
        }
        properties.insert(
            parameter.to_owned(),
            json!({ "type": "string", "minLength": 1, "maxLength": 512 }),
        );
        required.push(Value::String(parameter.to_owned()));
    }
    properties.insert(
        "query".to_owned(),
        json!({
            "type": "object",
            "maxProperties": 128,
            "additionalProperties": {
                "oneOf": [
                    { "type": ["string", "number", "integer", "boolean", "null"] },
                    { "type": "array", "maxItems": 256, "items": { "type": ["string", "number", "integer", "boolean", "null"] } }
                ]
            }
        }),
    );
    if !matches!(operation.method(), ChatwootHttpMethod::Get) {
        properties.insert(
            "body".to_owned(),
            json!({ "type": "object", "maxProperties": 512 }),
        );
    }
    if operation.supports_multipart() {
        properties.insert(
            "multipart".to_owned(),
            json!({
                "type": "object",
                "properties": {
                    "fields": {
                        "type": "object",
                        "maxProperties": 512,
                        "additionalProperties": { "type": ["string", "number", "integer", "boolean", "null", "object", "array"] }
                    },
                    "files": {
                        "type": "array",
                        "maxItems": MAX_MULTIPART_FILES,
                        "items": {
                            "type": "object",
                            "required": ["field_name", "filename", "content_type", "content_base64"],
                            "properties": {
                                "field_name": { "type": "string", "minLength": 1, "maxLength": 128 },
                                "filename": { "type": "string", "minLength": 1, "maxLength": 255 },
                                "content_type": { "type": "string", "minLength": 1, "maxLength": 255 },
                                "content_base64": { "type": "string" }
                            },
                            "additionalProperties": false
                        }
                    }
                },
                "additionalProperties": false
            }),
        );
    }
    json!({
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": false
    })
}

fn chatwoot_catalog_contract(operation: ChatwootOperation) -> CapabilityContract {
    let mutation = operation.is_mutation();
    CapabilityContract {
        side_effects: if mutation {
            vec![SideEffect::Write, SideEffect::ExternalNetwork]
        } else {
            vec![SideEffect::Read, SideEffect::ExternalNetwork]
        },
        idempotency: IdempotencyContract {
            requirement: if mutation {
                IdempotencyRequirement::Required
            } else {
                IdempotencyRequirement::Optional
            },
            collision_behavior: IdempotencyCollisionBehavior::RevalidateInputHash,
            key_scope: IdempotencyKeyScope::ExternalAccount,
            ttl_ms: Some(86_400_000),
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: false,
            supports_streaming: false,
            supports_cancel: false,
            supports_retry: operation.retry_safe(),
            expected_completion: ExpectedCompletionMode::Sync,
            retry_safety: if operation.retry_safe() {
                RetrySafety::Safe
            } else {
                RetrySafety::Unsafe
            },
        },
        data: DataContract {
            sensitivity: DataSensitivity::Restricted,
            contains_pii: true,
            redaction_required: true,
            residency: None,
            retention: None,
        },
        credentials: None,
        approval: mutation.then(|| ApprovalPolicy {
            required: true,
            reason: Some("Chatwoot mutations change customer-service production state.".to_owned()),
            approver_selector: ApproverSelector::TenantPolicy,
            ttl_ms: Some(900_000),
            evidence_requirements: vec![
                EvidenceRequirement::Reason,
                EvidenceRequirement::InputSnapshot,
                EvidenceRequirement::PolicyDecision,
            ],
            policy_version: Some("chatwoot-production-mutation-v1".to_owned()),
            ..ApprovalPolicy::default()
        }),
        sla: Some(ServiceLevelContract {
            expected_latency_ms: Some(5_000),
            timeout_ms: Some(120_000),
            async_expected: false,
            max_queue_delay_ms: Some(30_000),
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

const fn chatwoot_method_name(method: ChatwootHttpMethod) -> &'static str {
    match method {
        ChatwootHttpMethod::Get => "GET",
        ChatwootHttpMethod::Post => "POST",
        ChatwootHttpMethod::Patch => "PATCH",
        ChatwootHttpMethod::Put => "PUT",
        ChatwootHttpMethod::Delete => "DELETE",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChatwootLegacyOperation {
    SendMessage,
    ConversationStatus,
    Handoff,
}

fn chatwoot_contract(operation: ChatwootLegacyOperation) -> CapabilityContract {
    let side_effects = match operation {
        ChatwootLegacyOperation::SendMessage => {
            vec![
                SideEffect::SendMessage,
                SideEffect::Write,
                SideEffect::ExternalNetwork,
            ]
        }
        ChatwootLegacyOperation::ConversationStatus => {
            vec![SideEffect::Write, SideEffect::ExternalNetwork]
        }
        ChatwootLegacyOperation::Handoff => vec![
            SideEffect::Write,
            SideEffect::SendMessage,
            SideEffect::Identity,
            SideEffect::ExternalNetwork,
        ],
    };
    CapabilityContract {
        side_effects,
        idempotency: IdempotencyContract {
            requirement: IdempotencyRequirement::Required,
            collision_behavior: IdempotencyCollisionBehavior::RevalidateInputHash,
            key_scope: IdempotencyKeyScope::ExternalAccount,
            ttl_ms: Some(86_400_000),
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: false,
            supports_streaming: false,
            supports_cancel: false,
            supports_retry: operation == ChatwootLegacyOperation::ConversationStatus,
            expected_completion: ExpectedCompletionMode::Sync,
            retry_safety: if operation == ChatwootLegacyOperation::ConversationStatus {
                RetrySafety::Safe
            } else {
                RetrySafety::Unsafe
            },
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
                "Chatwoot operations can send customer-visible messages or change case ownership."
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
            expected_latency_ms: Some(3_000),
            timeout_ms: Some(30_000),
            async_expected: false,
            max_queue_delay_ms: Some(5_000),
            availability_target: Some("99.9%".to_owned()),
        }),
        transaction: None,
        compensation: Some(CompensationContract {
            mode: CompensationMode::RollbackNotSupported,
            compensation_capability_id: None,
            compensation_window_ms: None,
            requires_approval: true,
        }),
    }
}

fn required_action_string(input: &Value, field: &str) -> Result<String, ChatwootConnectorError> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| ChatwootConnectorError::InvalidAction(format!("missing input `{field}`")))
}

fn required_idempotency_key(action: &Action) -> Result<&str, ChatwootConnectorError> {
    action
        .idempotency_key
        .as_deref()
        .filter(|key| {
            !key.trim().is_empty() && key.len() <= 512 && !key.chars().any(char::is_control)
        })
        .ok_or(ChatwootConnectorError::MissingIdempotencyKey)
}

fn chatwoot_path_parameters(template: &str) -> Vec<&str> {
    template
        .split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .collect()
}

fn chatwoot_operation_url(
    base_url: &Url,
    account_id: &str,
    operation: ChatwootOperation,
    input: &Value,
) -> Result<Url, ChatwootConnectorError> {
    let mut url = base_url.clone();
    url.set_path("");
    let mut rendered = Vec::new();
    for segment in operation
        .path_template()
        .split('/')
        .filter(|value| !value.is_empty())
    {
        let value = match segment
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
        {
            Some("account_id") => account_id.to_owned(),
            Some(parameter) => required_action_string(input, parameter)?,
            None => segment.to_owned(),
        };
        if value.len() > 512 || value.chars().any(char::is_control) {
            return Err(ChatwootConnectorError::InvalidAction(format!(
                "invalid path parameter in operation `{}`",
                operation.suffix()
            )));
        }
        rendered.push(value);
    }
    {
        let mut segments = url.path_segments_mut().map_err(|()| {
            ChatwootConnectorError::InvalidAction(
                "Chatwoot base URL cannot accept path segments".to_owned(),
            )
        })?;
        segments.clear();
        for segment in &rendered {
            segments.push(segment);
        }
    }
    Ok(url)
}

fn chatwoot_multipart_form(
    multipart: &Value,
) -> Result<reqwest::multipart::Form, ChatwootConnectorError> {
    let multipart = multipart.as_object().ok_or_else(|| {
        ChatwootConnectorError::InvalidAction("input `multipart` must be an object".to_owned())
    })?;
    if multipart
        .keys()
        .any(|key| !matches!(key.as_str(), "fields" | "files"))
    {
        return Err(ChatwootConnectorError::InvalidAction(
            "input `multipart` contains an unknown property".to_owned(),
        ));
    }
    let fields = match multipart.get("fields") {
        Some(value) => Some(value.as_object().ok_or_else(|| {
            ChatwootConnectorError::InvalidAction(
                "input `multipart.fields` must be an object".to_owned(),
            )
        })?),
        None => None,
    };
    let files = match multipart.get("files") {
        Some(value) => Some(value.as_array().ok_or_else(|| {
            ChatwootConnectorError::InvalidAction(
                "input `multipart.files` must be an array".to_owned(),
            )
        })?),
        None => None,
    };
    if fields.is_none_or(serde_json::Map::is_empty) && files.is_none_or(Vec::is_empty) {
        return Err(ChatwootConnectorError::InvalidAction(
            "input `multipart` must contain at least one field or file".to_owned(),
        ));
    }
    if fields.is_some_and(|fields| fields.len() > 512) {
        return Err(ChatwootConnectorError::InvalidAction(
            "input `multipart.fields` exceeds 512 entries".to_owned(),
        ));
    }
    if files.is_some_and(|files| files.len() > MAX_MULTIPART_FILES) {
        return Err(ChatwootConnectorError::InvalidAction(format!(
            "input `multipart.files` exceeds {MAX_MULTIPART_FILES} entries"
        )));
    }

    let mut total = 0_usize;
    let mut form = reqwest::multipart::Form::new();
    if let Some(fields) = fields {
        for (name, value) in fields {
            validate_multipart_name(name, "field name")?;
            let value = match value {
                Value::String(value) => value.clone(),
                value => serde_json::to_string(value).map_err(|error| {
                    ChatwootConnectorError::InvalidAction(format!(
                        "multipart field `{name}` is not JSON serializable: {error}"
                    ))
                })?,
            };
            if value.len() > MAX_MULTIPART_FIELD_BYTES {
                return Err(ChatwootConnectorError::InvalidAction(format!(
                    "multipart field `{name}` exceeds {MAX_MULTIPART_FIELD_BYTES} bytes"
                )));
            }
            total = total.checked_add(value.len()).ok_or_else(|| {
                ChatwootConnectorError::InvalidAction(
                    "multipart request size overflowed".to_owned(),
                )
            })?;
            form = form.text(name.clone(), value);
        }
    }
    if let Some(files) = files {
        for file in files {
            let file = file.as_object().ok_or_else(|| {
                ChatwootConnectorError::InvalidAction(
                    "every multipart file must be an object".to_owned(),
                )
            })?;
            if file.len() != 4
                || file.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "field_name" | "filename" | "content_type" | "content_base64"
                    )
                })
            {
                return Err(ChatwootConnectorError::InvalidAction(
                    "multipart file properties must exactly match the published schema".to_owned(),
                ));
            }
            let field_name = required_multipart_string(file, "field_name", 128)?;
            validate_multipart_name(field_name, "file field name")?;
            let filename = required_multipart_string(file, "filename", 255)?;
            if filename.contains('/') || filename.contains('\\') {
                return Err(ChatwootConnectorError::InvalidAction(
                    "multipart filename must be a basename".to_owned(),
                ));
            }
            let content_type = required_multipart_string(file, "content_type", 255)?;
            let encoded = required_multipart_string(
                file,
                "content_base64",
                MAX_MULTIPART_FILE_BYTES.saturating_mul(2),
            )?;
            let bytes = BASE64_STANDARD.decode(encoded).map_err(|_| {
                ChatwootConnectorError::InvalidAction(
                    "multipart file content is not valid standard base64".to_owned(),
                )
            })?;
            if bytes.len() > MAX_MULTIPART_FILE_BYTES {
                return Err(ChatwootConnectorError::InvalidAction(format!(
                    "multipart file exceeds {MAX_MULTIPART_FILE_BYTES} decoded bytes"
                )));
            }
            total = total.checked_add(bytes.len()).ok_or_else(|| {
                ChatwootConnectorError::InvalidAction(
                    "multipart request size overflowed".to_owned(),
                )
            })?;
            let part = reqwest::multipart::Part::bytes(bytes)
                .file_name(filename.to_owned())
                .mime_str(content_type)?;
            form = form.part(field_name.to_owned(), part);
        }
    }
    if total > MAX_MULTIPART_TOTAL_BYTES {
        return Err(ChatwootConnectorError::InvalidAction(format!(
            "multipart request exceeds {MAX_MULTIPART_TOTAL_BYTES} decoded bytes"
        )));
    }
    Ok(form)
}

fn validate_multipart_name(value: &str, label: &str) -> Result<(), ChatwootConnectorError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(ChatwootConnectorError::InvalidAction(format!(
            "multipart {label} must contain 1 to 128 bytes without control characters"
        )));
    }
    Ok(())
}

fn required_multipart_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<&'a str, ChatwootConnectorError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            ChatwootConnectorError::InvalidAction(format!(
                "multipart `{key}` is missing or exceeds its bound"
            ))
        })
}

fn append_chatwoot_query(
    url: &mut Url,
    query: Option<&Value>,
) -> Result<(), ChatwootConnectorError> {
    let Some(query) = query else {
        return Ok(());
    };
    let query = query.as_object().ok_or_else(|| {
        ChatwootConnectorError::InvalidAction("input `query` must be an object".to_owned())
    })?;
    if query.len() > 128 {
        return Err(ChatwootConnectorError::InvalidAction(
            "input `query` exceeds 128 keys".to_owned(),
        ));
    }
    let mut pairs = url.query_pairs_mut();
    for (key, value) in query {
        if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
            return Err(ChatwootConnectorError::InvalidAction(
                "query names must contain 1 to 256 bytes without control characters".to_owned(),
            ));
        }
        match value {
            Value::Null => {}
            Value::Array(values) if values.len() <= 256 => {
                for value in values {
                    pairs.append_pair(key, &chatwoot_query_scalar(value)?);
                }
            }
            Value::Array(_) => {
                return Err(ChatwootConnectorError::InvalidAction(format!(
                    "query `{key}` exceeds 256 values"
                )));
            }
            value => {
                pairs.append_pair(key, &chatwoot_query_scalar(value)?);
            }
        }
    }
    drop(pairs);
    if url.as_str().len() > MAX_REQUEST_URL_BYTES {
        return Err(ChatwootConnectorError::InvalidAction(format!(
            "encoded request URL exceeds {MAX_REQUEST_URL_BYTES} bytes"
        )));
    }
    Ok(())
}

fn chatwoot_query_scalar(value: &Value) -> Result<String, ChatwootConnectorError> {
    let value = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => String::new(),
        Value::Array(_) | Value::Object(_) => Err(ChatwootConnectorError::InvalidAction(
            "query values must be scalar or arrays of scalars".to_owned(),
        ))?,
    };
    if value.len() > MAX_QUERY_VALUE_BYTES || value.chars().any(char::is_control) {
        return Err(ChatwootConnectorError::InvalidAction(format!(
            "query value exceeds {MAX_QUERY_VALUE_BYTES} bytes or contains control characters"
        )));
    }
    Ok(value)
}

fn chatwoot_status(status: &str) -> &'static str {
    match status {
        "open" => "open",
        "pending" => "pending",
        _ => "resolved",
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChatwootOperationSafety {
    retry_safe: bool,
    mutation: bool,
}

impl ChatwootOperationSafety {
    const READ_ONLY: Self = Self {
        retry_safe: true,
        mutation: false,
    };
    const MUTATION_SAFE: Self = Self {
        retry_safe: true,
        mutation: true,
    };
    const MUTATION_UNSAFE: Self = Self {
        retry_safe: false,
        mutation: true,
    };
}

fn chatwoot_action_safety(action: &Action) -> ChatwootOperationSafety {
    match action.capability_id.as_str() {
        STATUS_CAPABILITY_ID => ChatwootOperationSafety::MUTATION_SAFE,
        SEND_MESSAGE_CAPABILITY_ID | HANDOFF_CAPABILITY_ID => {
            ChatwootOperationSafety::MUTATION_UNSAFE
        }
        capability_id => capability_id
            .strip_prefix("cap:chatwoot:")
            .and_then(ChatwootOperation::from_suffix)
            .map_or(ChatwootOperationSafety::MUTATION_UNSAFE, |operation| {
                ChatwootOperationSafety {
                    retry_safe: operation.retry_safe(),
                    mutation: operation.is_mutation(),
                }
            }),
    }
}

fn connector_failure(
    error: ChatwootConnectorError,
    operation: ConnectorOperation,
    safety: ChatwootOperationSafety,
) -> ConnectorFailure {
    let (code, category, retryable, remote_status, uncertain_outcome) = match &error {
        ChatwootConnectorError::Status { status, .. } if matches!(*status, 401 | 403) => (
            "connector.chatwoot.authentication",
            ErrorCategory::Auth,
            false,
            Some(*status),
            false,
        ),
        ChatwootConnectorError::Status { status, .. } if *status == 429 || *status >= 500 => (
            "connector.chatwoot.remote_temporary",
            ErrorCategory::Temporary,
            safety.retry_safe,
            Some(*status),
            operation == ConnectorOperation::Invocation && safety.mutation,
        ),
        ChatwootConnectorError::Status { status, .. } => (
            "connector.chatwoot.remote_rejected",
            ErrorCategory::Permanent,
            false,
            Some(*status),
            false,
        ),
        ChatwootConnectorError::Http(error) => (
            "connector.chatwoot.transport",
            ErrorCategory::Transport,
            safety.retry_safe,
            None,
            operation == ConnectorOperation::Invocation && safety.mutation && !error.is_connect(),
        ),
        ChatwootConnectorError::WebhookReplay(_) => (
            "connector.chatwoot.webhook_replay",
            ErrorCategory::Policy,
            false,
            None,
            false,
        ),
        ChatwootConnectorError::ReplayStore(_) => (
            "connector.chatwoot.replay_store",
            ErrorCategory::Temporary,
            false,
            None,
            false,
        ),
        ChatwootConnectorError::InvalidWebhook(_) => (
            "connector.chatwoot.invalid_webhook",
            ErrorCategory::Permanent,
            false,
            None,
            false,
        ),
        ChatwootConnectorError::WebhookNotConfigured => (
            "connector.chatwoot.webhook_not_configured",
            ErrorCategory::Policy,
            false,
            None,
            false,
        ),
        ChatwootConnectorError::InvalidAction(_) => (
            "connector.chatwoot.invalid_action",
            ErrorCategory::Permanent,
            false,
            None,
            false,
        ),
        ChatwootConnectorError::InvalidCredential => (
            "connector.chatwoot.invalid_credential",
            ErrorCategory::Auth,
            false,
            None,
            false,
        ),
        ChatwootConnectorError::ResponseTooLarge { .. } => (
            "connector.chatwoot.response_too_large",
            ErrorCategory::Permanent,
            safety.retry_safe,
            None,
            operation == ConnectorOperation::Invocation && safety.mutation,
        ),
        ChatwootConnectorError::MissingIdempotencyKey => (
            "connector.chatwoot.missing_idempotency_key",
            ErrorCategory::Policy,
            false,
            None,
            false,
        ),
        ChatwootConnectorError::InvalidUrl(_)
        | ChatwootConnectorError::InvalidBaseUrl(_)
        | ChatwootConnectorError::InvalidClient(_)
        | ChatwootConnectorError::InvalidConfiguration(_)
        | ChatwootConnectorError::MissingMetadata(_) => (
            "connector.chatwoot.configuration",
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

fn is_loop_prevention_webhook(webhook: &ChatwootWebhook) -> bool {
    webhook.message.as_ref().is_some_and(|message| {
        message
            .pointer("/content_attributes/aip/loop_prevention")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || message
                .pointer("/content_attributes/aip/connector_id")
                .and_then(Value::as_str)
                .is_some_and(|connector| connector == CONNECTOR_ID)
    })
}

/// Maps a Chatwoot webhook to an AIP channel message.
pub fn channel_message_from_webhook(
    webhook: ChatwootWebhook,
    delivery_id: String,
) -> Result<ChannelMessage, aip_core::IdParseError> {
    let account_id = webhook
        .account
        .get("id")
        .and_then(Value::as_i64)
        .map_or_else(|| "unknown".to_owned(), |id| id.to_string());
    let conversation_id = webhook
        .conversation
        .get("id")
        .and_then(Value::as_i64)
        .map_or_else(|| "unknown".to_owned(), |id| id.to_string());
    let contact_id = webhook
        .contact
        .as_ref()
        .and_then(|contact| contact.get("id"))
        .and_then(Value::as_i64)
        .map_or_else(|| "unknown".to_owned(), |id| id.to_string());
    let text = webhook
        .message
        .as_ref()
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();

    let contact = Principal::new(
        PrincipalId::parse(format!(
            "principal:chatwoot:account-{account_id}:contact-{contact_id}"
        ))?,
        PrincipalKind::Contact,
    );
    Ok(ChannelMessage {
        conversation: Conversation {
            id: ConversationId::new(),
            channel: json!({ "system": "chatwoot", "account_id": account_id }),
            status: ConversationStatus::Open,
            external_refs: vec![ExternalRef {
                system: "chatwoot".to_owned(),
                ref_type: "conversation".to_owned(),
                id: conversation_id,
            }],
            contact: Some(contact.clone()),
            assignee: None,
            priority: None,
            labels: Vec::new(),
            metadata: None,
        },
        identity: None,
        message: webhook.message.unwrap_or_else(|| json!({})),
        sender: contact,
        parts: vec![MessagePart::text(text)],
        delivery: Some(json!({ "delivery_id": delivery_id })),
        raw_payload: Some(json!({ "event": webhook.event })),
    })
}

/// Converts a verified Chatwoot channel message into one deterministic event.
///
/// The event id is derived from the authenticated provider delivery id. This
/// lets a durable event store return the first stored event after any process
/// crash instead of dropping the provider retry or creating a second event.
pub fn event_from_channel_message(
    message: ChannelMessage,
) -> Result<Event, ChatwootConnectorError> {
    let delivery_id = message
        .delivery
        .as_ref()
        .and_then(|delivery| delivery.get("delivery_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(ChatwootConnectorError::MissingMetadata("delivery_id"))?;
    let digest = hex::encode(Sha256::digest(delivery_id.as_bytes()));
    let mut event = Event::new("chatwoot.channel_message");
    event.id = EventId::parse(format!("evt_chatwoot_{digest}"))
        .map_err(|error| ChatwootConnectorError::InvalidWebhook(error.to_string()))?;
    event.actor = Some(message.sender.clone());
    event.data = serde_json::to_value(message)
        .ok()
        .map(|channel_message| json!({ "channel_message": channel_message }));
    Ok(event)
}

/// Maps an AIP message part list to a Chatwoot outgoing message.
#[must_use]
pub fn outgoing_message(conversation_id: String, parts: &[MessagePart]) -> ChatwootOutgoingMessage {
    let content = parts
        .iter()
        .filter_map(|part| match part {
            MessagePart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    ChatwootOutgoingMessage {
        conversation_id,
        content,
        private: false,
        aip_action_id: None,
    }
}

/// Returns true when the webhook message was produced by the configured bot.
#[must_use]
pub fn is_loopback_bot_message(webhook: &ChatwootWebhook, bot_sender_id: &str) -> bool {
    webhook
        .message
        .as_ref()
        .and_then(|message| message.get("sender"))
        .and_then(|sender| sender.get("id"))
        .and_then(Value::as_i64)
        .is_some_and(|id| id.to_string() == bot_sender_id)
}

/// Maps an AIP conversation status to a Chatwoot status command payload.
#[must_use]
pub fn status_command_payload(
    conversation_id: String,
    command: ChatwootConversationCommand,
) -> Value {
    let status = match command {
        ChatwootConversationCommand::Open => "open",
        ChatwootConversationCommand::Resolve => "resolved",
        ChatwootConversationCommand::Pending => "pending",
    };
    json!({
        "conversation_id": conversation_id,
        "status": status
    })
}

/// Maps an AIP handoff to Chatwoot assignment and private-note payloads.
#[must_use]
pub fn handoff_payload(handoff: ChatwootHandoff) -> Value {
    json!({
        "conversation_id": handoff.conversation_id,
        "assignee_id": handoff.assignee_id,
        "private_note": handoff.note
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ALL_CHATWOOT_OPERATIONS, ChatwootConnector, ChatwootConnectorError, ChatwootHttpMethod,
        ChatwootLegacyOperation, ChatwootOperation, ChatwootWebhookDelivery,
        FileChatwootReplayStore, OPERATOR_ONLY_EXCLUDED_ROUTES, SEND_MESSAGE_CAPABILITY_ID,
        STATUS_CAPABILITY_ID, chatwoot_action_safety, chatwoot_catalog_capability,
        chatwoot_contract, connector_failure, event_from_channel_message,
        redact_chatwoot_provider_value,
    };
    use aip_connector::{
        CapabilityProviderConnector, Connector, ConnectorContext, ConnectorOperation,
        OutboundConnector,
    };
    use aip_core::{
        Action, ActionResultStatus, CapabilityId, CapabilityKind, MessageBody, RetrySafety,
    };
    use axum::{
        Json, Router,
        body::Bytes,
        extract::{Path as AxumPath, State},
        http::HeaderMap,
        routing::{patch, post},
    };
    use hmac::{Hmac, Mac};
    use serde_json::{Value, json};
    use sha2::Sha256;
    use std::{collections::BTreeSet, sync::Arc};
    use time::OffsetDateTime;
    use tokio::{net::TcpListener, sync::Mutex};

    #[derive(Clone, Default)]
    struct ChatwootState {
        messages: Arc<Mutex<Vec<Value>>>,
    }

    #[tokio::test]
    async fn outbound_message_records_action_identity_and_authenticates_to_chatwoot() {
        let state = ChatwootState::default();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock Chatwoot");
        let address = listener.local_addr().expect("Chatwoot address");
        let app = Router::new()
            .route(
                "/api/v1/accounts/{account}/conversations/{conversation}/messages",
                post(record_message),
            )
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve Chatwoot");
        });
        let connector = ChatwootConnector::new(format!("http://{address}"), "account-1", "token-1")
            .expect("connector");
        let action = Action::new(
            CapabilityId::trusted(SEND_MESSAGE_CAPABILITY_ID),
            json!({
                "conversation_id": "conversation-1",
                "content": "Refund approved",
                "private": false
            }),
        );
        let result = connector
            .invoke(&ConnectorContext::default(), action.clone())
            .await
            .expect("send message");
        assert_eq!(result.status, ActionResultStatus::Completed);
        let messages = state.messages.lock().await;
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].pointer("/content_attributes/aip/action_id"),
            Some(&json!(action.id))
        );
        assert_eq!(
            messages[0].pointer("/content_attributes/aip/loop_prevention"),
            Some(&json!(true))
        );
        server.abort();
    }

    #[tokio::test]
    async fn inbound_webhook_requires_valid_signature_and_drops_looped_messages() {
        let secret = b"chatwoot-webhook-secret";
        let connector = ChatwootConnector::new("http://127.0.0.1", "account-1", "token")
            .expect("connector")
            .with_webhook_secret(secret.to_vec());
        let payload = json!({
            "event": "message_created",
            "account": { "id": 1 },
            "conversation": { "id": 2 },
            "message": {
                "id": 3,
                "content": "loop",
                "content_attributes": {
                    "aip": { "connector_id": "chatwoot", "loop_prevention": true }
                }
            },
            "contact": { "id": 4 }
        });
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();
        let raw_body = serde_json::to_string(&payload).expect("serialize payload");
        let signature = chatwoot_signature(secret, timestamp, raw_body.as_bytes());
        let delivery = ChatwootWebhookDelivery {
            delivery_id: "delivery-1".to_owned(),
            timestamp,
            signature,
            raw_body: raw_body.clone(),
        };
        assert!(
            connector
                .ingest_webhook_delivery(delivery.clone())
                .await
                .expect("ingest")
                .is_empty()
        );
        assert!(
            connector
                .ingest_webhook_delivery(delivery)
                .await
                .expect("idempotent duplicate")
                .is_empty()
        );

        let invalid = ChatwootWebhookDelivery {
            delivery_id: "delivery-2".to_owned(),
            timestamp,
            signature: "sha256=00".to_owned(),
            raw_body,
        };
        assert!(connector.ingest_webhook_delivery(invalid).await.is_err());
    }

    #[tokio::test]
    async fn webhook_ingress_is_not_advertised_or_accepted_without_security() {
        let connector =
            ChatwootConnector::new("http://127.0.0.1", "account-1", "token").expect("connector");
        let manifest = connector
            .discover(&ConnectorContext::default())
            .await
            .expect("outbound-only manifest");
        assert!(manifest.channels.is_empty());
        assert!(
            !manifest
                .profiles
                .iter()
                .any(|profile| profile.as_str() == aip_profile_webhook::PROFILE_ID)
        );
        let error = connector
            .ingest_webhook_delivery(ChatwootWebhookDelivery {
                delivery_id: "delivery-unsigned".to_owned(),
                timestamp: OffsetDateTime::now_utc().unix_timestamp(),
                signature: "sha256=00".to_owned(),
                raw_body: "{}".to_owned(),
            })
            .await
            .expect_err("unsigned ingress must fail closed");
        assert!(matches!(
            error,
            ChatwootConnectorError::WebhookNotConfigured
        ));
    }

    #[tokio::test]
    async fn invalid_webhook_secret_prevents_manifest_admission() {
        let connector = ChatwootConnector::new("http://127.0.0.1", "account-1", "token")
            .expect("connector")
            .with_webhook_secret(Vec::new());
        assert!(
            connector
                .discover(&ConnectorContext::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn durable_replay_store_replays_deterministic_event_after_connector_restart() {
        let secret = b"durable-webhook-secret";
        let path = std::env::temp_dir().join(format!(
            "aip-chatwoot-replay-{}.json",
            aip_core::ActionId::new()
        ));
        let payload = json!({
            "event": "message_created",
            "account": { "id": 1 },
            "conversation": { "id": 2 },
            "message": { "id": 3, "content": "hello" },
            "contact": { "id": 4 }
        });
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();
        let raw_body = serde_json::to_string(&payload).expect("serialize payload");
        let delivery = ChatwootWebhookDelivery {
            delivery_id: "durable-delivery-1".to_owned(),
            timestamp,
            signature: chatwoot_signature(secret, timestamp, raw_body.as_bytes()),
            raw_body,
        };
        let first = ChatwootConnector::new("http://127.0.0.1", "account-1", "token")
            .expect("first connector")
            .with_webhook_security(
                secret.to_vec(),
                Arc::new(FileChatwootReplayStore::new(&path)),
            );
        let first_envelopes = first
            .ingest_webhook_delivery(delivery.clone())
            .await
            .expect("first delivery");
        let MessageBody::ChannelMessage(first_message) = first_envelopes[0].body.clone() else {
            panic!("channel message");
        };
        let first_event = event_from_channel_message(*first_message).expect("first event");
        drop(first);

        let restarted = ChatwootConnector::new("http://127.0.0.1", "account-1", "token")
            .expect("restarted connector")
            .with_webhook_security(
                secret.to_vec(),
                Arc::new(FileChatwootReplayStore::new(&path)),
            );
        let replayed = restarted
            .ingest_webhook_delivery(delivery)
            .await
            .expect("replayed delivery");
        let MessageBody::ChannelMessage(replayed_message) = replayed[0].body.clone() else {
            panic!("channel message");
        };
        let replayed_event = event_from_channel_message(*replayed_message).expect("replayed event");
        assert_eq!(first_event.id, replayed_event.id);
        tokio::fs::remove_file(path)
            .await
            .expect("remove replay fixture");
    }

    #[test]
    fn retry_contract_is_conservative_for_non_idempotent_chatwoot_mutations() {
        let send = chatwoot_contract(ChatwootLegacyOperation::SendMessage);
        assert!(!send.execution.supports_retry);
        assert_eq!(send.execution.retry_safety, RetrySafety::Unsafe);
        let status = chatwoot_contract(ChatwootLegacyOperation::ConversationStatus);
        assert!(status.execution.supports_retry);
        assert_eq!(status.execution.retry_safety, RetrySafety::Safe);
    }

    #[test]
    fn runtime_failures_match_the_published_retry_and_uncertainty_contract() {
        let read = Action::new(CapabilityId::trusted("cap:chatwoot:account.get"), json!({}));
        let read_failure = connector_failure(
            ChatwootConnectorError::Status {
                status: 503,
                body: json!({ "error": "unavailable" }),
            },
            ConnectorOperation::Invocation,
            chatwoot_action_safety(&read),
        );
        assert!(read_failure.retryable);
        assert!(!read_failure.uncertain_outcome);

        let mutation = Action::new(
            CapabilityId::trusted("cap:chatwoot:agent.create"),
            json!({ "body": { "name": "Support" } }),
        );
        let mutation_failure = connector_failure(
            ChatwootConnectorError::Status {
                status: 503,
                body: json!({ "error": "unavailable" }),
            },
            ConnectorOperation::Invocation,
            chatwoot_action_safety(&mutation),
        );
        assert!(!mutation_failure.retryable);
        assert!(mutation_failure.uncertain_outcome);

        let status = Action::new(CapabilityId::trusted(STATUS_CAPABILITY_ID), json!({}));
        let status_failure = connector_failure(
            ChatwootConnectorError::Status {
                status: 503,
                body: json!({ "error": "unavailable" }),
            },
            ConnectorOperation::Invocation,
            chatwoot_action_safety(&status),
        );
        assert!(status_failure.retryable);
        assert!(status_failure.uncertain_outcome);
    }

    #[test]
    fn frozen_catalog_is_unique_complete_and_governed() {
        assert_eq!(ALL_CHATWOOT_OPERATIONS.len(), 335);
        let mut ids = BTreeSet::new();
        for operation in ALL_CHATWOOT_OPERATIONS {
            assert!(ids.insert(operation.suffix()));
            assert!(
                operation
                    .path_template()
                    .starts_with("/api/v1/accounts/{account_id}")
                    || operation
                        .path_template()
                        .starts_with("/api/v2/accounts/{account_id}")
            );
            let capability = chatwoot_catalog_capability(*operation);
            assert_eq!(
                capability.id.as_str(),
                format!("cap:chatwoot:{}", operation.suffix())
            );
            assert_ne!(
                capability.kind,
                CapabilityKind::Resource,
                "Chatwoot provider operation {} must be action-routable",
                operation.suffix()
            );
            let contract = capability.contract.expect("catalog contract");
            let properties = capability
                .input_schema
                .get("properties")
                .and_then(Value::as_object)
                .expect("catalog input properties");
            assert_eq!(
                properties.contains_key("multipart"),
                operation.supports_multipart(),
                "multipart contract drift for {}",
                operation.suffix()
            );
            if matches!(operation.method(), ChatwootHttpMethod::Get) {
                assert!(!properties.contains_key("body"));
                assert!(!properties.contains_key("multipart"));
            }
            if operation.is_mutation() {
                assert!(capability.requires_human_approval.unwrap_or(false));
                assert_eq!(
                    contract.idempotency.requirement,
                    aip_core::IdempotencyRequirement::Required
                );
                assert_eq!(contract.execution.retry_safety, RetrySafety::Unsafe);
            } else {
                assert!(!capability.requires_human_approval.unwrap_or(true));
                assert!(contract.execution.supports_retry);
                assert_eq!(contract.execution.retry_safety, RetrySafety::Safe);
            }
        }
        for (method, path) in OPERATOR_ONLY_EXCLUDED_ROUTES {
            assert!(
                !ALL_CHATWOOT_OPERATIONS.iter().any(|operation| {
                    operation.method() == *method && operation.path_template() == *path
                }),
                "operator-only route leaked into the product catalogue: {path}"
            );
        }
    }

    #[tokio::test]
    async fn manifest_declares_every_capability_binding_profile() {
        let connector =
            ChatwootConnector::new("http://127.0.0.1", "account-1", "token").expect("connector");
        let manifest = connector
            .discover(&ConnectorContext::default())
            .await
            .expect("manifest");
        assert_eq!(manifest.capabilities.len(), 338);

        for capability in &manifest.capabilities {
            for binding in &capability.bindings {
                assert!(
                    manifest.profiles.contains(&binding.profile),
                    "capability {} uses undeclared profile {}",
                    capability.id,
                    binding.profile
                );
            }
        }
    }

    #[tokio::test]
    async fn catalog_mutation_uses_frozen_path_auth_body_and_idempotency() {
        let state = ChatwootState::default();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind catalog mock");
        let address = listener.local_addr().expect("catalog address");
        let app = Router::new()
            .route(
                "/api/v1/accounts/{account}/agents/{agent}",
                patch(record_agent_update),
            )
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve catalog mock");
        });
        let connector = ChatwootConnector::new(format!("http://{address}"), "account-1", "token-1")
            .expect("connector");
        let mut action = Action::new(
            CapabilityId::trusted("cap:chatwoot:agent.update"),
            json!({ "agent_id": "42", "body": { "name": "Operations" } }),
        );
        action.idempotency_key = Some("agent-update-42-v1".to_owned());
        let result = connector
            .invoke(&ConnectorContext::default(), action)
            .await
            .expect("catalog invocation");
        assert_eq!(result.status, ActionResultStatus::Completed);
        assert_eq!(
            result
                .output
                .as_ref()
                .and_then(|value| value.pointer("/body/id")),
            Some(&json!(42))
        );
        assert_eq!(
            state.messages.lock().await.as_slice(),
            &[json!({ "name": "Operations" })]
        );
        server.abort();
    }

    #[tokio::test]
    async fn admitted_message_upload_uses_bounded_multipart_and_hides_other_operations() {
        let state = ChatwootState::default();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind multipart mock");
        let address = listener.local_addr().expect("multipart address");
        let app = Router::new()
            .route(
                "/api/v1/accounts/{account}/conversations/{conversation}/messages",
                post(record_multipart_message),
            )
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve multipart mock");
        });
        let connector = ChatwootConnector::new(format!("http://{address}"), "account-1", "token-1")
            .expect("connector")
            .with_allowed_operations([ChatwootOperation::MessageCreate])
            .expect("operation policy");
        let capabilities = connector
            .capabilities(&ConnectorContext::default())
            .await
            .expect("capabilities");
        assert!(
            capabilities
                .iter()
                .any(|capability| capability.id.as_str() == "cap:chatwoot:message.create")
        );
        assert!(
            capabilities
                .iter()
                .all(|capability| capability.id.as_str() != "cap:chatwoot:agent.list")
        );

        let mut action = Action::new(
            CapabilityId::trusted("cap:chatwoot:message.create"),
            json!({
                "conversation_id": "conversation-1",
                "multipart": {
                    "fields": { "content": "Evidence attached", "private": false },
                    "files": [{
                        "field_name": "attachments[]",
                        "filename": "evidence.txt",
                        "content_type": "text/plain",
                        "content_base64": "aGVsbG8="
                    }]
                }
            }),
        );
        action.idempotency_key = Some("message-upload-1".to_owned());
        connector
            .invoke(&ConnectorContext::default(), action)
            .await
            .expect("multipart invocation");
        assert_eq!(state.messages.lock().await.len(), 1);
        server.abort();
    }

    async fn record_message(
        State(state): State<ChatwootState>,
        headers: HeaderMap,
        Json(payload): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(
            headers
                .get("api_access_token")
                .and_then(|value| value.to_str().ok()),
            Some("token-1")
        );
        state.messages.lock().await.push(payload);
        Json(json!({ "id": 10 }))
    }

    async fn record_agent_update(
        State(state): State<ChatwootState>,
        AxumPath((account, agent)): AxumPath<(String, String)>,
        headers: HeaderMap,
        Json(payload): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(account, "account-1");
        assert_eq!(agent, "42");
        assert_eq!(
            headers
                .get("api_access_token")
                .and_then(|value| value.to_str().ok()),
            Some("token-1")
        );
        assert_eq!(
            headers
                .get("idempotency-key")
                .and_then(|value| value.to_str().ok()),
            Some("agent-update-42-v1")
        );
        state.messages.lock().await.push(payload);
        Json(json!({ "id": 42 }))
    }

    async fn record_multipart_message(
        State(state): State<ChatwootState>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Json<Value> {
        assert_eq!(
            headers
                .get("api_access_token")
                .and_then(|value| value.to_str().ok()),
            Some("token-1")
        );
        assert_eq!(
            headers
                .get("idempotency-key")
                .and_then(|value| value.to_str().ok()),
            Some("message-upload-1")
        );
        assert!(
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("multipart/form-data; boundary="))
        );
        let body = String::from_utf8(body.to_vec()).expect("multipart fixture is UTF-8");
        assert!(body.contains("Evidence attached"));
        assert!(body.contains("filename=\"evidence.txt\""));
        assert!(body.contains("hello"));
        state
            .messages
            .lock()
            .await
            .push(json!({ "multipart": true }));
        Json(json!({ "id": 11 }))
    }

    fn chatwoot_signature(secret: &[u8], timestamp: i64, payload: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("valid HMAC key");
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn connector_debug_never_exposes_credentials() {
        let connector = ChatwootConnector::new("http://127.0.0.1", "account-1", "top-secret-token")
            .expect("connector")
            .with_webhook_secret(b"top-secret-webhook".to_vec());
        let debug = format!("{connector:?}");
        assert!(!debug.contains("top-secret-token"));
        assert!(!debug.contains("top-secret-webhook"));
    }

    #[test]
    fn provider_credentials_are_recursively_removed_from_results() {
        let redacted = redact_chatwoot_provider_value(json!({
            "id": 7,
            "website_token": "public-widget-identifier",
            "access_token": "bot-credential",
            "secret": "webhook-credential",
            "channel": {
                "provider_config": {
                    "phone_number_id": "1234",
                    "api_key": "provider-credential",
                    "webhook_verify_token": "verify-credential"
                },
                "smtp_password": "mail-credential",
                "safe": true
            },
            "nested": [{
                "hmac_token": "hmac-credential",
                "reference_id": "ref-1"
            }]
        }));

        assert_eq!(redacted.get("id"), Some(&json!(7)));
        assert_eq!(
            redacted.get("website_token"),
            Some(&json!("public-widget-identifier"))
        );
        assert_eq!(
            redacted.pointer("/channel/provider_config/phone_number_id"),
            Some(&json!("1234"))
        );
        assert_eq!(redacted.pointer("/channel/safe"), Some(&json!(true)));
        assert_eq!(
            redacted.pointer("/nested/0/reference_id"),
            Some(&json!("ref-1"))
        );
        for secret_pointer in [
            "/access_token",
            "/secret",
            "/channel/provider_config/api_key",
            "/channel/provider_config/webhook_verify_token",
            "/channel/smtp_password",
            "/nested/0/hmac_token",
        ] {
            assert!(
                redacted.pointer(secret_pointer).is_none(),
                "credential field survived at {secret_pointer}"
            );
        }
    }
}
